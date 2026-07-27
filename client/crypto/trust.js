// ZenvX Chat — community trust anchor.
//
// Public messengers make you compare safety numbers by hand because there is no
// shared trust anchor. A closed community HAS one: a root key held offline by
// the community operator, which signs every member's identity key.
//
// The app ships with ROOT_PUBLIC_KEY baked in. A tampered directory — even one
// served from a compromised GitHub repo — cannot forge these signatures.

import * as P from './primitives.js'

// Replace at build time via tools/root-key.mjs init. Base64 raw Ed25519 pubkey.
export const ROOT_PUBLIC_KEY = '__ZENVX_ROOT_PUBLIC_KEY__'

function rootKeyBytes(override) {
	const k = override || ROOT_PUBLIC_KEY
	if (!k || k.startsWith('__ZENVX_ROOT')) {
		throw new Error(
			'trust: no community root key baked in. Run tools/root-key.mjs init.',
		)
	}
	return P.fromB64(k)
}

// Canonical serialisation. Signature is over this exact byte string, so key
// order and separators must never change. Do not "tidy" this function.
export function canonicalMemberBytes(m) {
	return P.utf8.enc(
		[
			'zenvx-member-v1',
			m.handle,
			m.displayName,
			m.idSign,
			m.idDh,
			String(m.enrolledAt),
		].join('\u001f'),
	)
}

// Verify one member entry against the community root.
export async function verifyMember(member, rootPubOverride) {
	if (!member.rootSig) return false
	return P.verify(
		rootKeyBytes(rootPubOverride),
		P.fromB64(member.rootSig),
		canonicalMemberBytes(member),
	)
}

// Verify the whole directory and return only members that pass.
// Anything unsigned or badly signed is dropped, not merely flagged.
export async function verifyDirectory(directory, rootPubOverride) {
	const accepted = []
	const rejected = []
	for (const m of directory.members || []) {
		const ok = await verifyMember(m, rootPubOverride)
		if (ok) accepted.push(m)
		else rejected.push(m.handle)
	}
	return { accepted, rejected, revoked: directory.revoked || [] }
}

// A member's own prekey bundle is self-signed by their identity key, which the
// root vouches for. Two-level chain: root -> identity -> prekeys.
export async function verifyBundle(member, bundle) {
	if (bundle.idSign !== member.idSign) return false
	return P.verify(
		P.fromB64(member.idSign),
		P.fromB64(bundle.spkSig),
		P.fromB64(bundle.spk),
	)
}

// ---------------------------------------------------- whole-directory signing
// Per-member signatures stop key substitution, but not deletion or rollback.
// Signing the directory as a unit, with a monotonic serial, stops both:
// a stale copy can be detected because its serial went backwards.

export function canonicalDirectoryBytes(d) {
	const entries = (d.members || [])
		.map((m) => m.handle + '\u001e' + m.rootSig)
		.join('\u001d')
	const rev = (d.revoked || [])
		.map((r) => (r.handle || r) + '\u001e' + (r.at || ''))
		.join('\u001d')
	return P.utf8.enc(
		[
			'zenvx-directory-v1',
			String(d.serial),
			d.updatedAt,
			entries,
			rev,
		].join('\u001f'),
	)
}

export async function verifyDirectorySignature(d, sigB64, rootPubOverride) {
	if (!sigB64) return false
	try {
		return await P.verify(
			rootKeyBytes(rootPubOverride),
			P.fromB64(sigB64),
			canonicalDirectoryBytes(d),
		)
	} catch {
		return false
	}
}

// Reject a directory whose serial is older than the newest one we have seen.
export function isRollback(candidateSerial, lastKnownSerial) {
	if (lastKnownSerial === null || lastKnownSerial === undefined) return false
	return Number(candidateSerial) < Number(lastKnownSerial)
}
