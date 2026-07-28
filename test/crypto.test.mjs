// Real end-to-end tests. Run: node test/crypto.test.mjs
import * as P from '../client/crypto/primitives.js'
import * as X3DH from '../client/crypto/x3dh.js'
import * as Ratchet from '../client/crypto/ratchet.js'
import * as Trust from '../client/crypto/trust.js'

let pass = 0
let fail = 0
function check(name, cond) {
	if (cond) {
		pass++
		console.log('  ok   ' + name)
	} else {
		fail++
		console.log('  FAIL ' + name)
	}
}
const dec = (b) => P.utf8.dec(b)
const enc = (s) => P.utf8.enc(s)

console.log('\n== primitives ==')
{
	const a = await P.x25519Generate()
	const b = await P.x25519Generate()
	const s1 = await P.dh(a.privateKey, await P.x25519ExportPub(b.publicKey))
	const s2 = await P.dh(b.privateKey, await P.x25519ExportPub(a.publicKey))
	check('x25519 shared secrets agree', P.eq(s1, s2))

	const ed = await P.ed25519Generate()
	const msg = enc('hello')
	const sig = await P.sign(ed.privateKey, msg)
	check('ed25519 verifies', await P.verify(await P.edExportPub(ed.publicKey), sig, msg))
	msg[0] ^= 1
	check(
		'ed25519 rejects tampered',
		!(await P.verify(await P.edExportPub(ed.publicKey), sig, msg)),
	)

	const mk = P.randomBytes(32)
	const aad = enc('aad')
	const ct = await P.seal(mk, enc('secret payload'), aad)
	check('aead roundtrip', dec(await P.open(mk, ct, aad)) === 'secret payload')
	let threw = false
	try {
		await P.open(mk, ct, enc('wrong aad'))
	} catch {
		threw = true
	}
	check('aead rejects wrong aad', threw)

	const b64 = P.toB64(mk)
	check('base64 roundtrip', P.eq(P.fromB64(b64), mk))
}

console.log('\n== x3dh handshake ==')
const alice = await X3DH.createIdentity('alice')
const bob = await X3DH.createIdentity('bob')
const bobBundle = await X3DH.publicBundle(bob)
check('bundle has 100 one-time prekeys', bobBundle.opks.length === 100)

const { state: aState, preKeyMsg } = await X3DH.initiate(alice, bobBundle)
const first = await Ratchet.encrypt(aState, enc('hi bob, offline handshake'))
const bState = await X3DH.respond(bob, preKeyMsg)
check(
	'offline first message decrypts',
	dec(await Ratchet.decrypt(bState, first)) === 'hi bob, offline handshake',
)
check('one-time prekey consumed', bob.opks.length === 99)

{
	let threw = false
	try {
		await X3DH.respond(bob, preKeyMsg)
	} catch {
		threw = true
	}
	check('prekey replay rejected', threw)
}

{
	const forged = { ...bobBundle, spk: P.toB64(P.randomBytes(32)) }
	let threw = false
	try {
		await X3DH.initiate(alice, forged)
	} catch {
		threw = true
	}
	check('forged prekey bundle rejected', threw)
}

console.log('\n== double ratchet ==')
{
	const r1 = await Ratchet.encrypt(bState, enc('hey alice'))
	check('reply decrypts', dec(await Ratchet.decrypt(aState, r1)) === 'hey alice')

	const m2 = await Ratchet.encrypt(aState, enc('m2'))
	const m3 = await Ratchet.encrypt(aState, enc('m3'))
	const m4 = await Ratchet.encrypt(aState, enc('m4'))
	// deliver out of order: 4, 2, 3
	check('out-of-order m4 first', dec(await Ratchet.decrypt(bState, m4)) === 'm4')
	check('skipped m2 recovered', dec(await Ratchet.decrypt(bState, m2)) === 'm2')
	check('skipped m3 recovered', dec(await Ratchet.decrypt(bState, m3)) === 'm3')

	// long alternating conversation forces many DH ratchet steps
	let okAll = true
	for (let i = 0; i < 40; i++) {
		const fromA = await Ratchet.encrypt(aState, enc('a' + i))
		if (dec(await Ratchet.decrypt(bState, fromA)) !== 'a' + i) okAll = false
		const fromB = await Ratchet.encrypt(bState, enc('b' + i))
		if (dec(await Ratchet.decrypt(aState, fromB)) !== 'b' + i) okAll = false
	}
	check('40 alternating rounds (80 DH ratchet steps)', okAll)

	const tampered = await Ratchet.encrypt(aState, enc('tamper me'))
	const raw = P.fromB64(tampered.ct)
	raw[3] ^= 0xff
	tampered.ct = P.toB64(raw)
	let threw = false
	try {
		await Ratchet.decrypt(bState, tampered)
	} catch {
		threw = true
	}
	check('tampered ciphertext rejected', threw)
}

console.log('\n== session persistence ==')
{
	const a2 = await X3DH.createIdentity('carol')
	const b2 = await X3DH.createIdentity('dave')
	const { state: s1, preKeyMsg: pk } = await X3DH.initiate(a2, await X3DH.publicBundle(b2))
	const m = await Ratchet.encrypt(s1, enc('before restart'))
	const s2 = await X3DH.respond(b2, pk)
	await Ratchet.decrypt(s2, m)

	// simulate app restart on both sides
	const reloadedA = await Ratchet.importState(await Ratchet.exportState(s1))
	const reloadedB = await Ratchet.importState(await Ratchet.exportState(s2))
	const after = await Ratchet.encrypt(reloadedA, enc('after restart'))
	check(
		'session survives serialize/deserialize',
		dec(await Ratchet.decrypt(reloadedB, after)) === 'after restart',
	)
}

console.log('\n== community root trust ==')
{
	const root = await P.ed25519Generate()
	const rootPub = P.toB64(await P.edExportPub(root.publicKey))

	const member = {
		handle: 'alice',
		displayName: 'Alice',
		idSign: (await X3DH.publicBundle(alice)).idSign,
		idDh: (await X3DH.publicBundle(alice)).idDh,
		enrolledAt: 1753000000,
	}
	member.rootSig = P.toB64(
		await P.sign(root.privateKey, Trust.canonicalMemberBytes(member)),
	)
	check('root-signed member verifies', await Trust.verifyMember(member, rootPub))

	const impostor = { ...member, idSign: P.toB64(P.randomBytes(32)) }
	check(
		'key substitution rejected',
		!(await Trust.verifyMember(impostor, rootPub)),
	)

	const renamed = { ...member, displayName: 'Alice (admin)' }
	check('display name tampering rejected', !(await Trust.verifyMember(renamed, rootPub)))

	const unsigned = { ...member, rootSig: undefined }
	check('unsigned member rejected', !(await Trust.verifyMember(unsigned, rootPub)))

	const dir = { members: [member, impostor, unsigned] }
	const res = await Trust.verifyDirectory(dir, rootPub)
	check(
		'directory filters to only valid members',
		res.accepted.length === 1 && res.rejected.length === 2,
	)

	check(
		'bundle chains to member identity',
		await Trust.verifyBundle(member, await X3DH.publicBundle(alice)),
	)
}

console.log('\n== safety number ==')
{
	const aPub = await P.edExportPub(alice.idSign.publicKey)
	const bPub = await P.edExportPub(bob.idSign.publicKey)
	const s1 = await X3DH.safetyNumber(aPub, bPub)
	const s2 = await X3DH.safetyNumber(bPub, aPub)
	check('safety number is order-independent', s1 === s2)
	console.log('\n' + s1 + '\n')
}

console.log(`\n${pass} passed, ${fail} failed\n`)
process.exit(fail === 0 ? 0 : 1)
