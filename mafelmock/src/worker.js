import { onRequest } from './api.js';
export default {
  async fetch(request, env) {
    const u = new URL(request.url);
    if (u.pathname.startsWith('/api/')) {
      const path = u.pathname.slice(5).split('/').filter(Boolean).map(decodeURIComponent);
      return onRequest({ request, env, params: { path } });
    }
    return env.ASSETS.fetch(request);
  },
};
