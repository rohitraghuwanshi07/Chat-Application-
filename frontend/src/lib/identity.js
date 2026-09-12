import * as ed from '@noble/ed25519'

/**
 * identity.js
 * ------------
 * Owns the ONE thing that used to live on the server and shouldn't:
 * the Ed25519 PRIVATE signing key. This never leaves the browser and is
 * never sent over the network -- only the derived public key and
 * per-message signatures are.
 *
 * Why this exists: previously the server generated a keypair per
 * username and signed on the user's behalf, which means the server
 * (or anyone who compromised it) could forge a "valid" signature for
 * any user. Generating and holding the private key here instead means
 * a signature actually proves "this browser, holding this key, signed
 * this exact text" -- the server can check that, but never produce it.
 *
 * Fixed known limitation (unchanged from before, left as-is on purpose):
 * there is still no login/account system, so nothing stops a second
 * browser from picking the same display name and registering a
 * DIFFERENT key under it -- the server will trust whichever public key
 * it saw most recently for that name. This module only fixes signature
 * forgery; it does not add real identity/authentication.
 */

// RFC 8410 fixed 12-byte DER prefix for an Ed25519 SubjectPublicKeyInfo.
// Every Ed25519 public key gets wrapped in exactly this prefix -- it's
// not derived from the key, it's a constant "this is an Ed25519 public
// key" header that Python's `cryptography` (and everything else that
// speaks PEM) expects.
const SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
])

function toBase64(bytes) {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary)
}

function fromBase64(b64) {
  const binary = atob(b64)
  return Uint8Array.from(binary, (c) => c.charCodeAt(0))
}

function publicKeyToPem(publicKeyBytes) {
  const spki = new Uint8Array(SPKI_PREFIX.length + publicKeyBytes.length)
  spki.set(SPKI_PREFIX, 0)
  spki.set(publicKeyBytes, SPKI_PREFIX.length)
  const b64 = toBase64(spki)
  const lines = b64.match(/.{1,64}/g).join('\n')
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----\n`
}

function storageKey(username) {
  return `chat_identity:${username}`
}

/**
 * Returns { privateKey, publicKeyPem } for this username, generating
 * and persisting a new keypair the first time this browser sees this
 * name, and reusing the same one on every later visit -- so the
 * "verified" badge stays stable across reconnects/reloads instead of
 * flipping every time a fresh key gets registered.
 */
export async function getOrCreateIdentity(username) {
  const key = storageKey(username)
  const saved = localStorage.getItem(key)

  const privateKey = saved ? fromBase64(saved) : ed.utils.randomPrivateKey()
  if (!saved) localStorage.setItem(key, toBase64(privateKey))

  const publicKeyBytes = await ed.getPublicKeyAsync(privateKey)
  return { privateKey, publicKeyPem: publicKeyToPem(publicKeyBytes) }
}

/** Signs the EXACT plaintext string, returns a base64 signature --
 * same format the server's `crypto_utils.sign_text` used to produce,
 * so nothing downstream (storage, verification) needed to change. */
export async function signText(privateKey, plaintext) {
  const msgBytes = new TextEncoder().encode(plaintext)
  const sig = await ed.signAsync(msgBytes, privateKey)
  return toBase64(sig)
}
