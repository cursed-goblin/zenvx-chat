// Sealed sender tests. Run: node test/envelope.test.mjs
import * as P from '../client/crypto/primitives.js'
import * as Envelope from '../client/crypto/envelope.js'
import * as X3DH from '../client/crypto/x3dh.js'
import * as Ratchet from '../client/crypto/ratchet.js'

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

console.log('\n== sealed sender ==')
const bob = await X3DH.createIdentity('bob')
const eve = await X3DH.createIdentity('eve')
const bobPub = P.toB64(await P.x25519ExportPub(bob.idDh.publicKey))

const box = await Envelope.seal(bobPub, { from: 'alice', text: 'meet at 6' })
check('recipient can open', (await Envelope.openWith(bob.idDh, box)).from === 'alice')

{
	let threw = false
	try {
		await Envelope.openWith(eve.idDh, box)
	} catch {
		threw = true
	}
	check('non-recipient cannot open', threw)
}

// The crucial property: nothing on the wire names the sender.
{
	const wire = JSON.stringify(box)
	check('wire bytes do not contain sender handle', !wire.includes('alice'))
	check('wire bytes do not contain plaintext', !wire.includes('meet at 6'))
	check('wire exposes only v, ek, ct', Object.keys(box).sort().join(',') === 'ct,ek,v')
}

{
	const tampered = { ...box }
	const raw = P.fromB64(tampered.ct)
	raw[5] ^= 0xff
	tampered.ct = P.toB64(raw)
	let threw = false
	try {
		await Envelope.openWith(bob.idDh, tampered)
	} catch {
		threw = true
	}
	check('tampered box rejected', threw)
}

{
	// Swapping the ephemeral key must not produce a valid box.
	const other = await Envelope.seal(bobPub, { from: 'alice', text: 'other' })
	const mixed = { v: 1, ek: other.ek, ct: box.ct }
	let threw = false
	try {
		await Envelope.openWith(bob.idDh, mixed)
	} catch {
		threw = true
	}
	check('ephemeral key substitution rejected', threw)
}

{
	const a = await Envelope.seal(bobPub, { x: 1 })
	const b = await Envelope.seal(bobPub, { x: 1 })
	check('identical plaintexts produce different ciphertexts', a.ct !== b.ct)
}

console.log('\n== full pipeline: x3dh + ratchet + sealed sender ==')
{
	const alice = await X3DH.createIdentity('alice')
	const { state, preKeyMsg } = await X3DH.initiate(alice, await X3DH.publicBundle(bob))
	const msg = await Ratchet.encrypt(state, P.utf8.enc(JSON.stringify({ text: 'hello' })))

	// What actually crosses the relay:
	const sealed = await Envelope.seal(bobPub, { from: 'alice', prekey: preKeyMsg, msg })
	const onWire = JSON.stringify({ to: 'bob', box: sealed })
	check('relay payload never names the sender', !onWire.includes('alice'))
	check('relay payload never contains plaintext', !onWire.includes('hello'))

	// Bob unwraps both layers.
	const inner = await Envelope.openWith(bob.idDh, JSON.parse(onWire).box)
	const bState = await X3DH.respond(bob, inner.prekey)
	const pt = JSON.parse(P.utf8.dec(await Ratchet.decrypt(bState, inner.msg)))
	check('bob recovers sender identity', inner.from === 'alice')
	check('bob recovers plaintext', pt.text === 'hello')
}

console.log(`\n${pass} passed, ${fail} failed\n`)
process.exit(fail === 0 ? 0 : 1)
