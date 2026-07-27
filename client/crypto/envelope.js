// ZenvX Chat — sealed sender.
//
// The Double Ratchet hides message CONTENT. It does not hide WHO is talking to
// whom — and the social graph is usually more sensitive than the text.
//
// So we wrap every ciphertext in an ECIES box addressed to the recipient's
// long-term DH key. The relay sees only:
//     { to: "bob", ek: <random 32 bytes>, ct: <opaque> }
// The sender's handle lives INSIDE the box. The relay cannot build a social
// graph even with full disk access and full logs.

import * as P from './primitives.js'

const INFO = 'ZenvX-SealedSender-v1'

// Derive the box key from the ephemeral<->recipient DH, bound to both public
// keys so a captured box cannot be replayed at a different recipient.
async function boxKey(sharedSecret, ekPub, recipientPub) {
	return P.hkdf(
		P.concat(sharedSecret, ekPub, recipientPub),
		new Uint8Array(32),
		INFO,
		32,
	)
}

// Seal a JSON payload to a recipient's long-term X25519 public key (base64).
export async function seal(recipientIdDhB64, payload) {
	const ek = await P.x25519Generate()
	const ekPub = await P.x25519ExportPub(ek.publicKey)
	const recipientPub = P.fromB64(recipientIdDhB64)

	const shared = await P.dh(ek.privateKey, recipientPub)
	const mk = await boxKey(shared, ekPub, recipientPub)
	const ct = await P.seal(mk, P.utf8.enc(JSON.stringify(payload)), ekPub)
	return { v: 1, ek: P.toB64(ekPub), ct: P.toB64(ct) }
}

// Open a sealed box with our own X25519 key pair.
// WebCrypto cannot recover a public key from a private CryptoKey, so we take
// the whole pair rather than pretending otherwise.
export async function openWith(myKeyPair, box) {
	if (box.v !== 1) throw new Error('envelope: unsupported version')
	const myPub = await P.x25519ExportPub(myKeyPair.publicKey)
	const ekPub = P.fromB64(box.ek)
	const shared = await P.dh(myKeyPair.privateKey, ekPub)
	const mk = await boxKey(shared, ekPub, myPub)
	const pt = await P.open(mk, P.fromB64(box.ct), ekPub)
	return JSON.parse(P.utf8.dec(pt))
}
