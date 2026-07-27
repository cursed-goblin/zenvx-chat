// ZenvX Chat — Double Ratchet (Signal-style symmetric + DH ratchet).
//
// Guarantees:
//   forward secrecy    — compromising today's keys does not decrypt yesterday
//   post-compromise    — a new DH ratchet step heals the session after a leak
//   out-of-order        — skipped message keys are cached (bounded by MAX_SKIP)

import * as P from './primitives.js'

const MAX_SKIP = 256

// Root KDF: (root key, DH output) -> (new root key, new chain key)
async function kdfRk(rk, dhOut) {
	const out = await P.hkdf(dhOut, rk, 'ZenvX-Ratchet-RK-v1', 64)
	return { rk: out.slice(0, 32), ck: out.slice(32, 64) }
}

// Chain KDF: chain key -> (next chain key, message key)
async function kdfCk(ck) {
	const mk = await P.hmac(ck, new Uint8Array([1]))
	const next = await P.hmac(ck, new Uint8Array([2]))
	return { ck: next, mk }
}

// The initiator already knows the responder's signed prekey, so it can send
// immediately without a round trip.
export async function initSender(sk, ad, theirRatchetPubRaw) {
	const dhs = await P.x25519Generate()
	const dhOut = await P.dh(dhs.privateKey, theirRatchetPubRaw)
	const { rk, ck } = await kdfRk(sk, dhOut)
	return {
		dhs,
		dhr: theirRatchetPubRaw,
		rk,
		cks: ck,
		ckr: null,
		ns: 0,
		nr: 0,
		pn: 0,
		skipped: new Map(),
		ad,
	}
}

// The responder's first ratchet key pair IS its signed prekey.
export async function initReceiver(sk, ad, ourRatchetKeyPair) {
	return {
		dhs: ourRatchetKeyPair,
		dhr: null,
		rk: sk,
		cks: null,
		ckr: null,
		ns: 0,
		nr: 0,
		pn: 0,
		skipped: new Map(),
		ad,
	}
}

async function dhRatchet(st, hdr) {
	st.pn = st.ns
	st.ns = 0
	st.nr = 0
	st.dhr = P.fromB64(hdr.dh)

	let r = await kdfRk(st.rk, await P.dh(st.dhs.privateKey, st.dhr))
	st.rk = r.rk
	st.ckr = r.ck

	st.dhs = await P.x25519Generate()
	r = await kdfRk(st.rk, await P.dh(st.dhs.privateKey, st.dhr))
	st.rk = r.rk
	st.cks = r.ck
}

async function skipMessageKeys(st, until) {
	if (st.ckr === null) return
	if (st.nr + MAX_SKIP < until) {
		throw new Error('ratchet: too many skipped messages')
	}
	const prefix = P.toB64(st.dhr)
	while (st.nr < until) {
		const { ck, mk } = await kdfCk(st.ckr)
		st.ckr = ck
		st.skipped.set(prefix + ':' + st.nr, mk)
		st.nr += 1
	}
}

export async function encrypt(st, plaintextBytes) {
	const { ck, mk } = await kdfCk(st.cks)
	st.cks = ck
	const hdr = {
		dh: P.toB64(await P.x25519ExportPub(st.dhs.publicKey)),
		pn: st.pn,
		n: st.ns,
	}
	st.ns += 1
	const aad = P.concat(st.ad, P.utf8.enc(JSON.stringify(hdr)))
	return { hdr, ct: P.toB64(await P.seal(mk, plaintextBytes, aad)) }
}

export async function decrypt(st, msg) {
	const aad = P.concat(st.ad, P.utf8.enc(JSON.stringify(msg.hdr)))
	const ct = P.fromB64(msg.ct)

	// Was this one skipped earlier and cached?
	const cacheKey = msg.hdr.dh + ':' + msg.hdr.n
	if (st.skipped.has(cacheKey)) {
		const mk = st.skipped.get(cacheKey)
		const pt = await P.open(mk, ct, aad)
		st.skipped.delete(cacheKey)
		return pt
	}

	// New sending chain from the peer -> step the DH ratchet.
	if (st.dhr === null || P.toB64(st.dhr) !== msg.hdr.dh) {
		await skipMessageKeys(st, msg.hdr.pn)
		await dhRatchet(st, msg.hdr)
	}

	await skipMessageKeys(st, msg.hdr.n)
	const { ck, mk } = await kdfCk(st.ckr)
	st.ckr = ck
	st.nr += 1
	return P.open(mk, ct, aad)
}

// ------------------------------------------------------- persistence helpers
// Session state must survive app restarts. Private keys are exported as PKCS8
// and are expected to be re-encrypted at rest by the storage layer.

export async function exportState(st) {
	return {
		v: 1,
		dhsPriv: P.toB64(await P.x25519ExportPriv(st.dhs.privateKey)),
		dhsPub: P.toB64(await P.x25519ExportPub(st.dhs.publicKey)),
		dhr: st.dhr ? P.toB64(st.dhr) : null,
		rk: P.toB64(st.rk),
		cks: st.cks ? P.toB64(st.cks) : null,
		ckr: st.ckr ? P.toB64(st.ckr) : null,
		ns: st.ns,
		nr: st.nr,
		pn: st.pn,
		ad: P.toB64(st.ad),
		skipped: [...st.skipped.entries()].map(([k, v]) => [k, P.toB64(v)]),
	}
}

export async function importState(j) {
	const priv = await P.x25519ImportPriv(P.fromB64(j.dhsPriv))
	const pub = await P.x25519ImportPub(P.fromB64(j.dhsPub))
	return {
		dhs: { privateKey: priv, publicKey: pub },
		dhr: j.dhr ? P.fromB64(j.dhr) : null,
		rk: P.fromB64(j.rk),
		cks: j.cks ? P.fromB64(j.cks) : null,
		ckr: j.ckr ? P.fromB64(j.ckr) : null,
		ns: j.ns,
		nr: j.nr,
		pn: j.pn,
		ad: P.fromB64(j.ad),
		skipped: new Map(j.skipped.map(([k, v]) => [k, P.fromB64(v)])),
	}
}
