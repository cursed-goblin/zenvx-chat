// ZenvX Chat — X3DH asynchronous key agreement.
//
// Lets you start an encrypted session with someone who is OFFLINE, using only
// their public prekey bundle from the signed directory. This is the sole reason
// the server holds any crypto material at all — and it is public keys only.

import * as P from './primitives.js'
import * as Ratchet from './ratchet.js'

const OPK_COUNT = 100

// A device identity:
//   idSign — Ed25519, long-term. This IS your identity. Signed by community root.
//   idDh   — X25519, long-term, used in the handshake.
//   spk    — X25519 signed prekey, rotated ~weekly.
//   opks   — X25519 one-time prekeys, consumed on use.
export async function createIdentity(handle) {
	const idSign = await P.ed25519Generate()
	const idDh = await P.x25519Generate()
	const spk = await P.x25519Generate()
	const spkPub = await P.x25519ExportPub(spk.publicKey)
	const spkSig = await P.sign(idSign.privateKey, spkPub)

	const opks = []
	for (let i = 0; i < OPK_COUNT; i++) {
		opks.push({ id: i, kp: await P.x25519Generate() })
	}
	return { handle, idSign, idDh, spk, spkSig, opks }
}

// The public half — this is what gets committed to directory/members.json.
export async function publicBundle(id) {
	return {
		handle: id.handle,
		idSign: P.toB64(await P.edExportPub(id.idSign.publicKey)),
		idDh: P.toB64(await P.x25519ExportPub(id.idDh.publicKey)),
		spk: P.toB64(await P.x25519ExportPub(id.spk.publicKey)),
		spkSig: P.toB64(id.spkSig),
		opks: await Promise.all(
			id.opks.map(async (o) => ({
				id: o.id,
				pub: P.toB64(await P.x25519ExportPub(o.kp.publicKey)),
			})),
		),
	}
}

// Initiator side. Returns a ratchet state plus the prekey message to attach to
// the first ciphertext so the recipient can derive the same secret.
export async function initiate(me, bundle) {
	const theirSign = P.fromB64(bundle.idSign)
	const spkPub = P.fromB64(bundle.spk)

	// Refuse to talk to a bundle whose prekey is not signed by the claimed identity.
	const ok = await P.verify(theirSign, P.fromB64(bundle.spkSig), spkPub)
	if (!ok) throw new Error('x3dh: signed prekey failed verification')

	const ek = await P.x25519Generate()
	const opk = bundle.opks && bundle.opks.length ? bundle.opks[0] : null

	const dh1 = await P.dh(me.idDh.privateKey, spkPub) // IK_a <-> SPK_b
	const dh2 = await P.dh(ek.privateKey, P.fromB64(bundle.idDh)) // EK_a <-> IK_b
	const dh3 = await P.dh(ek.privateKey, spkPub) // EK_a <-> SPK_b
	let ikm = P.concat(dh1, dh2, dh3)
	if (opk) {
		ikm = P.concat(ikm, await P.dh(ek.privateKey, P.fromB64(opk.pub))) // EK_a <-> OPK_b
	}

	const sk = await P.hkdf(ikm, new Uint8Array(32), 'ZenvX-X3DH-v1', 32)
	const mySignPub = await P.edExportPub(me.idSign.publicKey)
	const ad = P.concat(mySignPub, theirSign) // initiator || responder

	const state = await Ratchet.initSender(sk, ad, spkPub)
	const preKeyMsg = {
		type: 'prekey',
		from: me.handle,
		ikSign: P.toB64(mySignPub),
		ikDh: P.toB64(await P.x25519ExportPub(me.idDh.publicKey)),
		ek: P.toB64(await P.x25519ExportPub(ek.publicKey)),
		opkId: opk ? opk.id : null,
	}
	return { state, preKeyMsg }
}

// Responder side. Mirrors the four DH operations with roles swapped.
export async function respond(me, preKeyMsg) {
	const theirSign = P.fromB64(preKeyMsg.ikSign)
	const theirIkDh = P.fromB64(preKeyMsg.ikDh)
	const theirEk = P.fromB64(preKeyMsg.ek)

	const dh1 = await P.dh(me.spk.privateKey, theirIkDh)
	const dh2 = await P.dh(me.idDh.privateKey, theirEk)
	const dh3 = await P.dh(me.spk.privateKey, theirEk)
	let ikm = P.concat(dh1, dh2, dh3)

	if (preKeyMsg.opkId !== null && preKeyMsg.opkId !== undefined) {
		const idx = me.opks.findIndex((o) => o.id === preKeyMsg.opkId)
		if (idx === -1) throw new Error('x3dh: one-time prekey already consumed')
		ikm = P.concat(ikm, await P.dh(me.opks[idx].kp.privateKey, theirEk))
		me.opks.splice(idx, 1) // single use — burn it
	}

	const sk = await P.hkdf(ikm, new Uint8Array(32), 'ZenvX-X3DH-v1', 32)
	const mySignPub = await P.edExportPub(me.idSign.publicKey)
	const ad = P.concat(theirSign, mySignPub) // initiator || responder

	return Ratchet.initReceiver(sk, ad, me.spk)
}

// Persist an identity to disk. Private keys are exported as raw/pkcs8 bytes and
// are only ever written inside the passphrase-encrypted local store.
export async function exportIdentity(id) {
	const pair = async (kp, kind) =>
		kind === 'ed'
			? {
					pub: P.toB64(await P.edExportPub(kp.publicKey)),
					priv: P.toB64(await P.edExportPriv(kp.privateKey)),
				}
			: {
					pub: P.toB64(await P.x25519ExportPub(kp.publicKey)),
					priv: P.toB64(await P.x25519ExportPriv(kp.privateKey)),
				}

	return {
		v: 1,
		handle: id.handle,
		idSign: await pair(id.idSign, 'ed'),
		idDh: await pair(id.idDh, 'dh'),
		spk: await pair(id.spk, 'dh'),
		spkSig: P.toB64(id.spkSig),
		opks: await Promise.all(
			id.opks.map(async (o) => ({ id: o.id, ...(await pair(o.kp, 'dh')) })),
		),
	}
}

export async function importIdentity(j) {
	if (j.v !== 1) throw new Error('x3dh: unsupported identity version')
	const dh = async (o) => ({
		publicKey: await P.x25519ImportPub(P.fromB64(o.pub)),
		privateKey: await P.x25519ImportPriv(P.fromB64(o.priv)),
	})
	return {
		handle: j.handle,
		idSign: {
			publicKey: await P.edImportPub(P.fromB64(j.idSign.pub)),
			privateKey: await P.edImportPriv(P.fromB64(j.idSign.priv)),
		},
		idDh: await dh(j.idDh),
		spk: await dh(j.spk),
		spkSig: P.fromB64(j.spkSig),
		opks: await Promise.all(
			j.opks.map(async (o) => ({ id: o.id, kp: await dh(o) })),
		),
	}
}

// Human-checkable fingerprint. Only needed if you distrust the root key.
export async function safetyNumber(aSignPub, bSignPub) {
	const ordered =
		P.toB64(aSignPub) < P.toB64(bSignPub)
			? P.concat(aSignPub, bSignPub)
			: P.concat(bSignPub, aSignPub)
	const h = await P.sha256(ordered)
	let out = ''
	for (let i = 0; i < 12; i++) {
		out += (((h[i * 2] << 8) | h[i * 2 + 1]) % 100000).toString().padStart(5, '0')
		if (i % 4 === 3 && i !== 11) out += '\n'
		else if (i !== 11) out += ' '
	}
	return out
}
