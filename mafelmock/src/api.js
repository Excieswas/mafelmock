const enc = new TextEncoder();
const J = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json' } });
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
async function hmac(secret, data) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u(await crypto.subtle.sign('HMAC', k, enc.encode(data)));
}
async function sign(env, p) { const b = btoa(JSON.stringify(p)); return b + '.' + await hmac(SEC, b); }
async function verify(env, t) {
  if (!t) return null; const [b, s] = t.split('.');
  if (!s || s !== await hmac(SEC, b)) return null;
  try { const p = JSON.parse(atob(b)); return p.exp > Date.now() ? p : null; } catch { return null; }
}
async function hashPw(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, k, 256);
  return b64u(bits);
}
const slug = (s) => s.toLowerCase().replace(/ç/g, 'c').replace(/ğ/g, 'g').replace(/ı/g, 'i').replace(/ö/g, 'o').replace(/ş/g, 's').replace(/ü/g, 'u')
  .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'komite';
let SEC, ready;
const getS = async (db, k) => (await db.prepare('SELECT v FROM settings WHERE k=?').bind(k).first())?.v;
const setS = (db, k, v) => db.prepare('INSERT OR REPLACE INTO settings VALUES(?,?)').bind(k, v).run();
async function init(db) {
  if (!ready) {
    await db.batch([
      db.prepare("CREATE TABLE IF NOT EXISTS committees(id TEXT PRIMARY KEY, name TEXT NOT NULL, abbr TEXT DEFAULT '', seats INTEGER DEFAULT 20, visible INTEGER DEFAULT 1, description TEXT DEFAULT '', agenda TEXT DEFAULT '', details TEXT DEFAULT '', usg TEXT DEFAULT '', matrix TEXT DEFAULT '[]', has_guide INTEGER DEFAULT 0, salt TEXT, pass_hash TEXT, created_at INTEGER)"),
      db.prepare('CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT)'),
      db.prepare('CREATE TABLE IF NOT EXISTS guides(id TEXT, part INTEGER, data TEXT, PRIMARY KEY(id, part))')]);
    ready = 1;
  }
  let v = await getS(db, 'secret');
  if (!v) { await db.prepare("INSERT OR IGNORE INTO settings VALUES('secret',?)").bind(crypto.randomUUID() + crypto.randomUUID()).run(); v = await getS(db, 'secret'); }
  SEC = v;
}
const toB64 = (u) => { let s = ''; for (let i = 0; i < u.length; i += 8192) s += String.fromCharCode(...u.subarray(i, i + 8192)); return btoa(s); };
const unB64 = (parts) => { const bin = parts.map((x) => atob(x)).join(''); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; };
const str = (v, n) => String(v ?? '').slice(0, n);
const pub = (r) => ({ id: r.id, name: r.name, abbr: r.abbr, seats: r.seats, visible: !!r.visible, description: r.description,
  agenda: r.agenda, details: r.details, usg: r.usg, matrix: JSON.parse(r.matrix || '[]'), hasGuide: !!r.has_guide });

export async function onRequest({ request, env, params }) {
  const p = params.path || [], m = request.method, db = env.DB;
  if (!db) return J({ error: 'D1 veritabanı bağlı değil (README adım 3)' }, 500);
  await init(db);
  const a = await verify(env, (request.headers.get('authorization') || '').replace('Bearer ', ''));
  const body = async () => { try { return await request.json(); } catch { return {}; } };
  try {
    if (p[0] === 'committees' && m === 'GET') {
      if (p[1]) {
        const r = await db.prepare('SELECT * FROM committees WHERE id=? AND visible=1').bind(p[1]).first();
        return r ? J(pub(r)) : J({ error: 'Bulunamadı' }, 404);
      }
      const { results } = await db.prepare('SELECT * FROM committees WHERE visible=1 ORDER BY created_at').all();
      return J(results.map(pub));
    }
    if (p[0] === 'guide' && m === 'GET') {
      const r = await db.prepare('SELECT name FROM committees WHERE id=? AND visible=1 AND has_guide=1').bind(p[1]).first();
      const ch = r ? (await db.prepare('SELECT data FROM guides WHERE id=? ORDER BY part').bind(p[1]).all()).results : [];
      const o = ch.length ? { body: unB64(ch.map((x) => x.data)) } : null;
      if (!o) return J({ error: 'Study guide yok' }, 404);
      return new Response(o.body, { headers: { 'content-type': 'application/pdf', 'content-disposition': `inline; filename="${p[1]}-study-guide.pdf"` } });
    }
    if (p[0] === 'status') return J({ adminSet: !!(await getS(db, 'admin_hash')) });
    if (p[0] === 'login' && m === 'POST') {
      const b = await body(); const exp = Date.now() + 12 * 3600e3;
      if (b.role === 'admin') {
        const pw = str(b.password, 200), hs = await getS(db, 'admin_hash');
        if (!hs) {
          if (pw.length < 6) return J({ error: 'En az 6 karakter' }, 400);
          const sl = crypto.randomUUID(); await setS(db, 'admin_salt', sl); await setS(db, 'admin_hash', await hashPw(pw, sl));
          return J({ token: await sign(env, { role: 'admin', exp }) });
        }
        if (await hashPw(pw, await getS(db, 'admin_salt')) === hs) return J({ token: await sign(env, { role: 'admin', exp }) });
      } else {
        const r = await db.prepare('SELECT * FROM committees WHERE id=?').bind(str(b.id, 60)).first();
        if (r && r.pass_hash && await hashPw(str(b.password, 200), r.salt) === r.pass_hash)
          return J({ token: await sign(env, { role: 'usg', id: r.id, exp }) });
      }
      return J({ error: 'Hatalı giriş' }, 401);
    }
    if (p[0] === 'admin') {
      if (a?.role !== 'admin') return J({ error: 'Yetkisiz' }, 401);
      if (p[1] === 'committees' && m === 'GET') {
        const { results } = await db.prepare('SELECT * FROM committees ORDER BY created_at').all();
        return J(results.map(pub));
      }
      if (p[1] === 'committees' && m === 'POST') {
        const b = await body(); if (!b.name || !b.password) return J({ error: 'İsim ve şifre gerekli' }, 400);
        let id = slug(b.name);
        if (await db.prepare('SELECT 1 FROM committees WHERE id=?').bind(id).first()) id += '-' + Math.random().toString(36).slice(2, 5);
        const salt = crypto.randomUUID();
        await db.prepare('INSERT INTO committees(id,name,abbr,seats,usg,salt,pass_hash,created_at) VALUES(?,?,?,?,?,?,?,?)')
          .bind(id, str(b.name, 100), str(b.abbr, 12), Math.min(Math.max(+b.seats || 20, 1), 300), str(b.usg, 100), salt, await hashPw(str(b.password, 200), salt), Date.now()).run();
        return J({ id });
      }
      if (p[1] === 'committees' && p[2] && m === 'PUT') {
        const b = await body();
        await db.prepare('UPDATE committees SET name=?,abbr=?,seats=?,visible=?,usg=? WHERE id=?')
          .bind(str(b.name, 100), str(b.abbr, 12), Math.min(Math.max(+b.seats || 20, 1), 300), b.visible ? 1 : 0, str(b.usg, 100), p[2]).run();
        if (b.password) { const salt = crypto.randomUUID();
          await db.prepare('UPDATE committees SET salt=?,pass_hash=? WHERE id=?').bind(salt, await hashPw(str(b.password, 200), salt), p[2]).run(); }
        return J({ ok: true });
      }
      if (p[1] === 'committees' && p[2] && m === 'DELETE') {
        await db.prepare('DELETE FROM committees WHERE id=?').bind(p[2]).run();
        await db.prepare('DELETE FROM guides WHERE id=?').bind(p[2]).run(); return J({ ok: true });
      }
    }
    if (p[0] === 'usg') {
      if (a?.role !== 'usg') return J({ error: 'Yetkisiz' }, 401);
      if (p[1] === 'committee' && m === 'GET') {
        const r = await db.prepare('SELECT * FROM committees WHERE id=?').bind(a.id).first(); return J(pub(r));
      }
      if (p[1] === 'committee' && m === 'PUT') {
        const b = await body(); const seats = Math.min(Math.max(+b.seats || 1, 1), 300);
        const matrix = (Array.isArray(b.matrix) ? b.matrix : []).slice(0, seats)
          .map((x) => ({ country: str(x.country, 80), delegate: str(x.delegate, 80), school: str(x.school, 80) }));
        await db.prepare('UPDATE committees SET description=?,agenda=?,details=?,seats=?,matrix=? WHERE id=?')
          .bind(str(b.description, 3000), str(b.agenda, 1000), str(b.details, 6000), seats, JSON.stringify(matrix), a.id).run();
        return J({ ok: true });
      }
      if (p[1] === 'guide' && m === 'POST') {
        const f = (await request.formData()).get('file');
        if (!f || f.type !== 'application/pdf' || f.size > 8e6) return J({ error: 'En fazla 8MB PDF yükleyin' }, 400);
        const u = new Uint8Array(await f.arrayBuffer()), st = [db.prepare('DELETE FROM guides WHERE id=?').bind(a.id)];
        for (let i = 0, n = 0; i < u.length; i += 600000, n++) st.push(db.prepare('INSERT INTO guides VALUES(?,?,?)').bind(a.id, n, toB64(u.subarray(i, i + 600000))));
        await db.batch(st);
        await db.prepare('UPDATE committees SET has_guide=1 WHERE id=?').bind(a.id).run(); return J({ ok: true });
      }
    }
    return J({ error: 'Bulunamadı' }, 404);
  } catch (e) { return J({ error: 'Sunucu hatası' }, 500); }
}
