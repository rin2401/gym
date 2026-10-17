/* The stable per-profile pseudonym a payload carries instead of the uid: never the uid,
 * never reversible, the same across jobs. Keyed on the instance secret so two instances
 * never mint the same handle for the same uid. Port of api/coach/handle.js — the secret
 * comes from the DO (kv 'secret') instead of ./data/secret, the HMAC is the same one.
 */
import crypto from 'node:crypto';

export const HANDLE_LENGTH = 16;

export const handleFor = (C, uid) =>
  crypto.createHmac('sha256', C.secret).update('coach-handle:' + uid).digest('base64url').slice(0, HANDLE_LENGTH);
