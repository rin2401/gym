/* Provider adapters on the Worker — the port of api/coach/adapters/index.js, minus the
 * runtimes. A Worker cannot spawn a child process, so claude (Agent SDK), codex (CLI) and
 * the fixture CLI are not offered at all; what remains is every plain-HTTPS provider,
 * which is the whole reason this deployment exists: an OpenAI-compatible endpoint.
 *
 * The adapters themselves are shared verbatim with the Node server and the phone
 * (api/coach/core/adapters) — one implementation, three runtimes.
 */
import anthropic from './core/adapters/anthropic.js';
import openai from './core/adapters/openai.js';
import gemini from './core/adapters/gemini.js';
import compatible from './core/adapters/compatible.js';

const ADAPTERS = { anthropic, openai, gemini, compatible };
export const adapterFor = provider => ADAPTERS[provider] || null;
export default ADAPTERS;
