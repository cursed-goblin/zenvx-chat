// ZenvX Chat — zero-dependency crypto primitives.
// Uses only WebCrypto, so this exact file runs in browsers, Node >= 20, and Deno.
// No npm packages. Nothing to audit but this file.

const C = globalThis.crypto
export const subtle = C.subtle

export function randomBytes(n) {
	return C.getRandomValues(new Uint8Array(n))
}

export function concat(...arrs) {
	const total = arrs.reduce((n, a) => n + a.length, 0)
	const out = new Uint8Array(total)
	let o = 0
	for (const a of arrs) {
		out.set(a, o)
		o += a.length
	}
	return out
}

// Constant-time-ish comparison. Used for tag/fingerprint checks.
export function eq(a, b) {
	if (a.length !== b.length) return false
	let d = 0
	for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]
	return d === 0
}

const TE = new TextEncoder()
const TD = new TextDecoder()
export const utf8 = {
	enc: (s) => TE.encode(s),
	dec: (b) => TD.decode(b),
}

export function toB64(u8) {
	let s = ''
	for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i])
	return btoa(s)
}

export function fromB64(str) {
	const s = atob(str)
	const u = new Uint8Array(s.length)
	for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i)
	return u
}

export async function sha256(data) {
	return new Uint8Array(await subtle.digest('SHA-256', data))
}

// ---------------------------------------------------------------- X25519 (DH)

export async function x25519Generate() {
	return subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])
}
export async function x25519ExportPub(key) {
	return new Uint8Array(await subtle.exportKey('raw', key))
}
export async function x25519ImportPub(raw) {
	return subtle.importKey('raw', raw, { name: 'X25519' }, true, [])
}
export async function x25519ExportPriv(key) {
	return new Uint8Array(await subtle.exportKey('pkcs8', key))
}
export async function x25519ImportPriv(raw) {
	return subtle.importKey('pkcs8', raw, { name: 'X25519' }, true, ['deriveBits'])
}

// Raw X25519 shared secret. `pubRaw` is 32 bytes.
export async function dh(priv, pubRaw) {
	const pub = await x25519ImportPub(pubRaw)
	return new Uint8Array(
		await subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256),
	)
}

// -------------------------------------------------------- Ed25519 (signatures)

export async function ed25519Generate() {
	return subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
}
export async function edExportPub(key) {
	return new Uint8Array(await subtle.exportKey('raw', key))
}
export async function edImportPub(raw) {
	return subtle.importKey('raw', raw, { name: 'Ed25519' }, true, ['verify'])
}
export async function edExportPriv(key) {
	return new Uint8Array(await subtle.exportKey('pkcs8', key))
}
export async function edImportPriv(raw) {
	return subtle.importKey('pkcs8', raw, { name: 'Ed25519' }, true, ['sign'])
}
export async function sign(priv, data) {
	return new Uint8Array(await subtle.sign({ name: 'Ed25519' }, priv, data))
}
export async function verify(pubRaw, sig, data) {
	const pub = await edImportPub(pubRaw)
	return subtle.verify({ name: 'Ed25519' }, pub, sig, data)
}

// ------------------------------------------------------------------ KDF / MAC

export async function hkdf(ikm, salt, info, bytes) {
	const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
	const bits = await subtle.deriveBits(
		{ name: 'HKDF', hash: 'SHA-256', salt, info: utf8.enc(info) },
		key,
		bytes * 8,
	)
	return new Uint8Array(bits)
}

export async function hmac(keyBytes, data) {
	const k = await subtle.importKey(
		'raw',
		keyBytes,
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign'],
	)
	return new Uint8Array(await subtle.sign('HMAC', k, data))
}

// ---------------------------------------------------------------------- AEAD
// Message keys are single-use, so the nonce is derived deterministically from
// the message key rather than transmitted. Saves 12 bytes and removes the
// possibility of a nonce-reuse bug at the call site.

async function aeadKeys(mk) {
	const out = await hkdf(mk, new Uint8Array(32), 'ZenvX-AEAD-v1', 44)
	return { key: out.slice(0, 32), iv: out.slice(32, 44) }
}

export async function seal(mk, plaintext, aad) {
	const { key, iv } = await aeadKeys(mk)
	const k = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, [
		'encrypt',
	])
	return new Uint8Array(
		await subtle.encrypt(
			{ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
			k,
			plaintext,
		),
	)
}

export async function open(mk, ct, aad) {
	const { key, iv } = await aeadKeys(mk)
	const k = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, [
		'decrypt',
	])
	return new Uint8Array(
		await subtle.decrypt(
			{ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
			k,
			ct,
		),
	)
}
