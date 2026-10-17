/* HTTP surface for the Coach on the Worker — the port of api/coach/routes.js.
 *
 * Same routes, same shapes, same words (the client cannot tell them apart); only the
 * plumbing differs: the Node server's Express-style (req, res) handlers become the DO's
 * (request) → Response handlers, and the helpers they close over come from the Db
 * instance (readSession, isAdmin) instead of server.js's closures.
 *
 * Every one of these is inert while the feature is unconfigured — the admin dashboard
 * (Settings → Coach) is how this deployment is meant to be switched on, exactly as on
 * the Node server: pick the provider, paste the base URL and the key, choose a model.
 */
import * as jobs from './jobs.js';
import { computeCohort, setShare } from './cohort.js';
import { adapterFor } from './adapters.js';
import { PROVIDERS, SHARED_ACCOUNT_REFUSAL, MAX_MESSAGE_LEN_FLOOR, MAX_MESSAGE_LEN_CEILING, MAX_OUTPUT_TOKENS_FLOOR, MAX_OUTPUT_TOKENS_CEILING } from './store.js';
import { DATA_CATEGORIES } from './core/payload.js';
import { validateBaseUrl, validateHeaders, baseUrlFor } from './core/providers.js';

// Job failures the user sees, in the app's own voice. The raw provider detail never reaches
// them — it goes to the admin card, which is where someone can act on it (FR-47).
const USER_ERROR = {
  off: 'the Coach is not set up on this instance',
  busy: 'the Coach is already thinking about your training',
  cap: 'the Coach is taking a rest day, try again tomorrow',
  consent: 'the Coach needs your go-ahead first',
  // Verbatim, because it tells the user the one thing that resolves it and names who resolves
  // it. A vaguer message here turns into a support question for the person running the box.
  shared: SHARED_ACCOUNT_REFUSAL,
  unprivileged: 'the Coach is switched off on this instance for safety reasons'
};
const HTTP_FOR = { off: 503, busy: 409, cap: 429, consent: 403, shared: 409, unprivileged: 503 };

const MAX_BODY = 5 * 1024 * 1024;

/* The same response/body helpers db.js uses, duplicated here rather than exported from it:
 * a route module importing its own dispatcher is a cycle, and these are ten lines. */
function json(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: [['Content-Type', 'application/json'], ['Cache-Control', 'no-store']]
  });
}
async function readBody(request) {
  const buf = await request.arrayBuffer();
  if (buf.byteLength > MAX_BODY) return json(413, { error: 'body too large' });
  if (!buf.byteLength) return {};
  try {
    const body = JSON.parse(new TextDecoder().decode(buf));
    if (!body || typeof body !== 'object' || Array.isArray(body)) return json(400, { error: 'invalid json' });
    return body;
  } catch { return json(400, { error: 'invalid json' }); }
}

export function coachRoutes(db) {
  const C = db.coach;

  /** Every user route starts the same way: signed in, feature on, feature reachable. The class
   *  goes beside the words, as enqueue's refusal sends it: the app shows its own translated line
   *  for the class, and these English words only where it has none. */
  const guard = async request => {
    const user = db.readSession(request);
    if (!user) return { answer: json(401, { error: 'not signed in' }) };
    if (!C.isEnabled() || !(await C.isConnected())) return { answer: json(503, { error: USER_ERROR.off, code: 'off' }) };
    return { user };
  };
  const failEnqueue = e => {
    if (e instanceof jobs.CoachError) return json(HTTP_FOR[e.code] || 400, { error: USER_ERROR[e.code] || e.message, code: e.code });
    throw e;
  };
  // The admin gate (server.js requireAdmin): a 401 is any unauthenticated bot poking
  // /api/admin/*, a 403 is a real user without the flag.
  const requireAdmin = request => {
    const user = db.readSession(request);
    if (!user) return { answer: json(401, { error: 'not signed in' }) };
    if (!db.isAdmin(user)) return { answer: json(403, { error: 'forbidden' }) };
    return { user };
  };

  return {
    /* ------------------------------ user ------------------------------ */

    // What the consent screen has to disclose, straight from the module that builds payloads,
    // so the screen cannot drift from what actually leaves (FR-09). Signed in only: on an
    // invite-only instance which provider this box is wired to is nobody's business who has
    // not been let in.
    'GET /api/coach/disclosure': async function (request) {
      if (!db.readSession(request)) return json(401, { error: 'not signed in' });
      const cfg = C.load();
      return json(200, {
        provider: cfg.provider,
        providerLabel: C.providerMeta(cfg).label,
        categories: DATA_CATEGORIES,
        version: 1
      });
    },

    'GET /api/coach/status': async function (request) {
      const g = await guard(request); if (g.answer) return g.answer;
      // The chat composer's maxLength rides on this poll rather than a one-off fetch, so an
      // admin raising or lowering the limit reaches an open chat within one poll cycle.
      return json(200, { ...jobs.status(C, g.user.id), maxMessageLen: C.load().maxMessageLen });
    },

    'POST /api/coach/plan': async function (request) {
      const g = await guard(request); if (g.answer) return g.answer;
      const body = await readBody(request);
      if (body instanceof Response) return body;
      try {
        // The admin's configured length is the real limit; jobs.enqueue is where it is actually
        // enforced (it is the one place that already loads config for every job). This slice is
        // only a sanity ceiling so an oversized string is not carried further than it has to be.
        const job = await jobs.enqueue(C, g.user.id, {
          kind: 'create',
          intake: body.intake || null,
          lang: body.lang,
          refine: body.refine ? String(body.refine).slice(0, MAX_MESSAGE_LEN_CEILING) : null
        });
        return json(202, { job });
      } catch (e) { return failEnqueue(e); }
    },

    'POST /api/coach/review': async function (request) {
      const g = await guard(request); if (g.answer) return g.answer;
      const body = await readBody(request);
      if (body instanceof Response) return body;
      try {
        const job = await jobs.enqueue(C, g.user.id, {
          kind: 'review',
          lang: body.lang,
          note: body.note ? String(body.note).slice(0, MAX_MESSAGE_LEN_CEILING) : null
        });
        return json(202, { job });
      } catch (e) { return failEnqueue(e); }
    },

    // One workout, read closely. Nothing to apply — the card is kept in the user's log.
    'POST /api/coach/debrief': async function (request) {
      const g = await guard(request); if (g.answer) return g.answer;
      const body = await readBody(request);
      if (body instanceof Response) return body;
      try {
        const job = await jobs.enqueue(C, g.user.id, { kind: 'debrief', lang: body.lang, workoutId: body.workoutId ? String(body.workoutId).slice(0, 40) : null });
        return json(202, { job });
      } catch (e) { return failEnqueue(e); }
    },

    /* How this profile sits against everyone else on the instance who opted in: medians only,
       at least three people, and nothing for a profile that does not share itself. */
    'GET /api/coach/cohort': async function (request) {
      const g = await guard(request); if (g.answer) return g.answer;
      if (!C.load().community) return json(200, { ok: false, enabled: false });
      return json(200, computeCohort(C, g.user.id));
    },
    'POST /api/coach/cohort/share': async function (request) {
      const g = await guard(request); if (g.answer) return g.answer;
      const body = await readBody(request);
      if (body instanceof Response) return body;
      return json(200, { ok: true, sharing: setShare(C, g.user.id, !!body.share) });
    },

    'POST /api/coach/pending/resolve': async function (request) {
      const g = await guard(request); if (g.answer) return g.answer;
      const body = await readBody(request);
      if (body instanceof Response) return body;
      return json(200, jobs.resolvePending(C, g.user.id, {
        accepted: Array.isArray(body.accepted) ? body.accepted : [],
        rejected: Array.isArray(body.rejected) ? body.rejected : [],
        dismissed: !!body.dismissed
      }));
    },

    // Consent withdrawn, or the profile turned the Coach off: drop everything held server-side
    // for them at once, without waiting for a sync to carry the news (D5).
    'POST /api/coach/forget': async function (request) {
      const user = db.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      jobs.clearUser(C, user.id);
      return json(200, { ok: true });
    },

    /* ------------------------------ admin ------------------------------ */

    'GET /api/admin/coach': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      const cfg = C.load();
      const adapter = adapterFor(cfg.provider);
      // For an HTTPS provider this lists the models with the stored key, which is the round
      // trip the card wants anyway (and doubles as the auth check it renders).
      const cred = await C.credentialFor(C.boundUidFor(cfg));
      const check = adapter ? await adapter.check(cfg, C.jobEnv(cred?.ok ? cred : undefined)) : { ok: false, error: 'unknown provider' };
      const log = cfg.log || [];
      const today = C.todayISO();
      const meta = C.providerMeta(cfg);
      const rec = C.authFor(cfg);
      // The one async fact in an otherwise synchronous answer, resolved before it: whether
      // the stored blob still decrypts (a row that outlived the instance secret does not).
      const readable = rec?.data ? !!(await C.decrypt(rec.data)) : null;
      return json(200, {
        disabledByEnv: C.COACH_DISABLED,
        enabled: !!cfg.enabled,
        provider: cfg.provider,
        providers: Object.entries(PROVIDERS).map(([id, p]) => ({
          id, label: p.label, runtime: p.runtime,
          setupToken: !!p.setupToken, deviceLogin: !!p.deviceLogin, apiKey: !!p.apiKeyEnv,
          http: !!p.http, baseUrl: !!p.baseUrl, keyOptional: !!p.keyOptional, keyPlaceholder: p.keyPlaceholder || null,
          defaultModel: p.defaultModel || null,
          // Which providers already hold a key — so switching chips is visibly not a reset.
          connected: !!(C.authFor(cfg, id) && C.authFor(cfg, id).data)
        })),
        model: C.modelFor(cfg),
        models: cfg.models,
        baseUrl: meta.http ? baseUrlFor(cfg.provider, cfg) : null,
        // Extra static headers this endpoint is called with (compatible endpoints only).
        // Values, not just names: the admin wrote them and needs to see them to edit them.
        // Plaintext next to baseUrl — routing aids, not credentials (the key stays encrypted).
        headers: meta.http ? (C.optionsFor(cfg).headers || null) : null,
        knownModels: check.models || null,
        caps: cfg.caps,
        maxMessageLen: cfg.maxMessageLen,
        maxOutputTokens: cfg.maxOutputTokens,
        community: !!cfg.community,
        runtime: { ok: !!check.ok, version: check.version || null, error: check.error || null, needsKey: !!check.needsKey },
        authMode: cfg.authMode,
        boundUid: C.boundUidFor(cfg),
        /* Whether a credential is filed, and whose — never the credential. `unreadable` is its
           own state rather than "not connected" because it has a specific cause and a specific
           fix: the row outlived the instance secret, so the blob is intact and undecryptable,
           and connecting again is the way out. */
        auth: (() => {
          if (!meta.oauthEnv && !meta.apiKeyEnv) return { state: 'not-required' };
          if (!rec || !rec.data) return { state: meta.keyOptional ? 'optional' : 'none' };
          if (readable === false) return { state: 'unreadable' };
          return { state: 'connected', type: rec.type || null, account: rec.account || null, connectedAt: rec.connectedAt || null };
        })(),
        // No child process exists on this deployment, so there is nothing to drop and the card
        // must not show a red banner for it (the Node server's canDropPrivileges question).
        unprivileged: { ok: true, dropped: false, why: 'this provider runs no child process' },
        // Counts and outcomes only — never intake answers, payloads or proposals (FR-12/A4).
        // The same counter the instance cap reads, so the card and the cap cannot disagree.
        jobsToday: cfg.daily?.date === today ? cfg.daily.count : 0,
        lastSuccess: C.lastSuccess(),
        lastError: C.lastError(),
        recent: log.slice(-20).reverse().map(e => ({ at: e.at, kind: e.kind, trigger: e.trigger, outcome: e.outcome, errorClass: e.errorClass, ms: e.ms }))
      });
    },

    'POST /api/admin/coach/config': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      const body = await readBody(request);
      if (body instanceof Response) return body;
      const patch = {};
      if (body.enabled !== undefined) patch.enabled = !!body.enabled;
      const current = C.load();
      if (body.provider !== undefined) {
        if (!PROVIDERS[body.provider]) return json(400, { error: 'unknown provider' });
        // Credentials, model and endpoint are all keyed by provider — switching never drops them.
        patch.provider = body.provider;
      }
      const target = patch.provider || current.provider;
      if (body.model !== undefined) {
        patch.models = { ...current.models };
        if (body.model) patch.models[target] = String(body.model).slice(0, 80); else delete patch.models[target];
      }
      if (body.baseUrl !== undefined) {
        if (!PROVIDERS[target].baseUrl) return json(400, { error: `${target} has a fixed endpoint` });
        const v = validateBaseUrl(body.baseUrl);
        if (!v.ok) return json(400, { error: v.error });
        // An empty value passes the validator on purpose: for a provider with a default it means
        // "back to the default". A provider with none (compatible) would be saved pointing at ''
        // and baseUrlFor() would hand the adapter nothing to call — refused, as on the server.
        if (!v.value && !PROVIDERS[target].defaultBase) return json(400, { error: `${target} has no default endpoint, enter one` });
        patch.providerOptions = { ...current.providerOptions, [target]: { ...(current.providerOptions[target] || {}), baseUrl: v.value } };
      }
      if (body.headers !== undefined) {
        if (!PROVIDERS[target].baseUrl) return json(400, { error: `${target} has a fixed endpoint` });
        const h = validateHeaders(body.headers);
        if (!h.ok) return json(400, { error: h.error });
        // Build on the patch, not on current: a body carrying baseUrl AND headers must keep both.
        const next = { ...((patch.providerOptions && patch.providerOptions[target]) || current.providerOptions[target] || {}) };
        if (h.value) next.headers = h.value; else delete next.headers;
        patch.providerOptions = { ...current.providerOptions, ...(patch.providerOptions || {}), [target]: next };
      }
      if (body.community !== undefined) patch.community = !!body.community;
      if (body.caps) {
        patch.caps = {
          perProfileDaily: Math.max(0, Math.min(200, +body.caps.perProfileDaily || 0)),
          instanceDaily: Math.max(0, Math.min(5000, +body.caps.instanceDaily || 0))
        };
      }
      if (body.maxMessageLen !== undefined) {
        patch.maxMessageLen = Math.max(
          MAX_MESSAGE_LEN_FLOOR,
          Math.min(MAX_MESSAGE_LEN_CEILING, +body.maxMessageLen || current.maxMessageLen)
        );
      }
      if (body.maxOutputTokens !== undefined) {
        patch.maxOutputTokens = Math.max(
          MAX_OUTPUT_TOKENS_FLOOR,
          Math.min(MAX_OUTPUT_TOKENS_CEILING, +body.maxOutputTokens || current.maxOutputTokens)
        );
      }
      C.save(patch);
      return json(200, { ok: true });
    },

    'POST /api/admin/coach/test': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      return json(200, await jobs.testRun(C));
    },

    /* The models the configured endpoint serves, so the card can offer a list rather than a
       text field that goes stale with every model release. HTTPS providers only. */
    'POST /api/admin/coach/models': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      const cfg = C.load();
      const adapter = adapterFor(cfg.provider);
      if (!adapter || typeof adapter.models !== 'function') return json(200, { ok: false, error: 'this provider does not list models', models: [] });
      const cred = await C.credentialFor(C.boundUidFor(cfg));
      return json(200, await adapter.models(cfg, C.jobEnv(cred.ok ? cred : undefined)));
    },

    /* Connect the instance credential. The token is accepted once and never read back: it is
       encrypted here and leaves again only through the job env the adapter reads (store.js
       jobEnv — the same single channel the Node server's child process had). `type` has to
       match a variable the configured provider actually declares, so a key filed under one
       provider cannot silently go nowhere at job time. */
    'POST /api/admin/coach/connect': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      const body = await readBody(request);
      if (body instanceof Response) return body;
      const cfg = C.load();
      // A key may be filed for a provider that is not the active one, so the chips can be
      // prepared ahead of switching; by default it is the active provider's.
      const provider = body.provider !== undefined ? String(body.provider) : cfg.provider;
      if (!PROVIDERS[provider]) return json(400, { error: 'unknown provider' });
      const meta = PROVIDERS[provider];
      const type = String(body.type || '');
      const envVar = (type === 'cli-token' || type === 'oauth') ? meta.oauthEnv
        : type === 'apikey' ? meta.apiKeyEnv : null;
      if (!envVar) {
        return json(400, { error: `${provider} does not take a credential of type "${type}"` });
      }
      const token = String(body.token || '').trim();
      if (!token) return json(400, { error: 'no token supplied' });
      await C.saveAuth(provider, {
        type, account: String(body.account || '').slice(0, 120), data: await C.encrypt({ token }), connectedAt: new Date().toISOString()
      });
      return json(200, { ok: true });
    },

    'POST /api/admin/coach/disconnect': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      const body = await readBody(request);
      if (body instanceof Response) return body;
      const provider = body.provider !== undefined ? String(body.provider) : C.load().provider;
      if (!PROVIDERS[provider]) return json(400, { error: 'unknown provider' });
      await C.saveAuth(provider, null);
      return json(200, { ok: true });
    },

    /* Whose account this profile is about to spend. Its own route because both the Coach screen
       and the admin card must state it, and neither should be inferring it from settings. */
    'GET /api/coach/account': async function (request) {
      const user = db.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      return json(200, await C.accountFor(user.id));
    }
  };
}
