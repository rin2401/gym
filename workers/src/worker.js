// opengym on Cloudflare Workers — one Worker, one Durable Object, static frontend.
//
// /api/* is forwarded whole into the Db durable object (src/db.js), which holds every
// route, the db document and the per-profile state documents — the same single-instance
// shape the Node server has. Everything else falls through to the static asset handler,
// which serves the built frontend (../frontend/dist). The app routes client-side behind
// a hash router, so no SPA fallback is needed: an asset path that matches is served, one
// that does not is a genuine 404.
import { Db } from './db.js';

export { Db };

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (pathname === '/api' || pathname.startsWith('/api/')) {
      return env.DB.get(env.DB.idFromName('global')).fetch(request);
    }
    return env.ASSETS.fetch(request);
  }
};
