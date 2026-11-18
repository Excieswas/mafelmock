# MAFELMOCK
Cloudflare Pages + Functions + D1. Tablolar, oturum anahtarı ve study guide depolama otomatik; env değişkeni yok, R2 yok.

## Kurulum (3 adım)
1. Repoyu GitHub'a yükle → Cloudflare > Workers & Pages > Create > Pages > Connect to Git. Build command boş, Output directory: `public`.
2. Cloudflare > Storage & Databases > D1 > Create database (adı: mafelmock).
3. Pages projesi > Settings > Bindings > Add > D1 database: Variable name `DB`, database `mafelmock`. Sonra Deployments > Retry/Redeploy.

İlk `/admin.html` ziyaretinde admin şifresini sen belirlersin (hemen yap).
USG girişi: `/usg.html` — komite kodu (admin panelde görünür) + senin koyduğun şifre.
