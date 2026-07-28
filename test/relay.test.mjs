// Integration test against the real relay process.
// Proves: membership gate, sealed queue, ACK semantics, WebSocket signalling.
// Run: node test/relay.test.mjs

import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import * as P from '../client/crypto/primitives.js'
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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const PORT = 8099
const BASE = `http://127.0.0.1:${PORT}`
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zenvx-relay-'))

// ---- build a signed directory with two members ----
const root = await P.ed25519Generate()
const rootPub = P.toB64(await P.edExportPub(root.publicKey))

async function makeMember(handle, displayName) {
	const idSign = await P.ed25519Generate()
	const idDh = await P.x25519Generate()
	const m = {
		handle,
		displayName,
		idSign: P.toB64(await P.edExportPub(idSign.publicKey)),
		idDh: P.toB64(await P.x25519ExportPub(idDh.publicKey)),
		enrolledAt: Math.floor(Date.now() / 1000),
	}
	m.rootSig = P.toB64(await P.sign(root.privateKey, Trust.canonicalMemberBytes(m)))
	return { record: m, signKey: idSign.privateKey }
}

const alice = await makeMember('alice', 'Alice')
const bob = await makeMember('bob', 'Bob')
const impostor = await makeMember('mallory', 'Mallory') // never enrolled

const directory = {
	version: 1,
	serial: 1,
	updatedAt: new Date().toISOString(),
	members: [alice.record, bob.record],
	revoked: [],
}
const dirFile = path.join(tmp, 'members.json')
fs.writeFileSync(dirFile, JSON.stringify(directory, null, 2))

// ---- auth helper ----
async function auth(member) {
	const ts = Date.now()
	const sig = await P.sign(
		member.signKey,
		P.utf8.enc(`zenvx-auth-v1|${member.record.handle}|${ts}`),
	)
	return `handle=${member.record.handle}&ts=${ts}&sig=${encodeURIComponent(P.toB64(sig))}`
}

// ---- boot relay ----
const relay = spawn(process.execPath, ['server/relay.mjs'], {
	env: {
		...process.env,
		PORT: String(PORT),
		ZENVX_DATA: tmp,
		ZENVX_DIRECTORY: dirFile,
		ZENVX_ROOT_PUB: rootPub,
	},
	stdio: ['ignore', 'pipe', 'pipe'],
})
relay.stderr.on('data', (d) => process.stderr.write('[relay] ' + d))

let booted = false
for (let i = 0; i < 60; i++) {
	try {
		const r = await fetch(BASE + '/health')
		if (r.ok) {
			const j = await r.json()
			booted = j.members === 2
			break
		}
	} catch {}
	await sleep(100)
}
check('relay boots and loads 2 root-signed members', booted)

console.log('\n== membership gate ==')
{
	const r = await fetch(BASE + '/v1/inbox')
	check('no credentials rejected (401)', r.status === 401)

	const r2 = await fetch(BASE + '/v1/inbox?' + (await auth(impostor)))
	check('non-member with valid self-signature rejected', r2.status === 401)

	const ts = Date.now()
	const forged = P.toB64(P.randomBytes(64))
	const r3 = await fetch(
		`${BASE}/v1/inbox?handle=alice&ts=${ts}&sig=${encodeURIComponent(forged)}`,
	)
	check('forged signature for real member rejected', r3.status === 401)

	const old = Date.now() - 10 * 60 * 1000
	const sig = await P.sign(alice.signKey, P.utf8.enc(`zenvx-auth-v1|alice|${old}`))
	const r4 = await fetch(
		`${BASE}/v1/inbox?handle=alice&ts=${old}&sig=${encodeURIComponent(P.toB64(sig))}`,
	)
	check('stale timestamp rejected (replay window)', r4.status === 401)

	const r5 = await fetch(BASE + '/v1/inbox?' + (await auth(alice)))
	check('valid member accepted', r5.status === 200)
}

console.log('\n== sealed store-and-forward ==')
let envIds = []
{
	const sealed = P.toB64(P.randomBytes(200)) // opaque to the server
	const r = await fetch(`${BASE}/v1/send?to=bob&` + (await auth(alice)), {
		method: 'POST',
		body: sealed,
	})
	check('queue accepts envelope for offline peer (202)', r.status === 202)

	const r2 = await fetch(`${BASE}/v1/send?to=nobody&` + (await auth(alice)), {
		method: 'POST',
		body: sealed,
	})
	check('unknown recipient rejected (404)', r2.status === 404)

	const inbox = await (await fetch(BASE + '/v1/inbox?' + (await auth(bob)))).json()
	check('bob sees exactly 1 envelope', inbox.envelopes.length === 1)
	check('envelope content preserved byte-for-byte', inbox.envelopes[0].envelope === sealed)
	envIds = inbox.envelopes.map((e) => e.id)

	const aliceInbox = await (await fetch(BASE + '/v1/inbox?' + (await auth(alice)))).json()
	check('alice cannot read bob\u2019s queue', aliceInbox.envelopes.length === 0)

	const ackRes = await (
		await fetch(BASE + '/v1/ack?' + (await auth(bob)), {
			method: 'POST',
			body: JSON.stringify({ ids: envIds }),
		})
	).json()
	check('ack drains the queue', ackRes.remaining === 0)

	const after = await (await fetch(BASE + '/v1/inbox?' + (await auth(bob)))).json()
	check('queue empty after ack', after.envelopes.length === 0)

	const big = await fetch(`${BASE}/v1/send?to=bob&` + (await auth(alice)), {
		method: 'POST',
		body: 'x'.repeat(300 * 1024),
	})
	check('oversized envelope rejected (413)', big.status === 413)
}

console.log('\n== websocket signalling ==')
{
	const wsUrl = async (m) =>
		`ws://127.0.0.1:${PORT}/v1/signal?` + (await auth(m))

	const aSock = new WebSocket(await wsUrl(alice))
	const bSock = new WebSocket(await wsUrl(bob))
	const bMsgs = []
	const aMsgs = []
	bSock.onmessage = (e) => bMsgs.push(JSON.parse(e.data))
	aSock.onmessage = (e) => aMsgs.push(JSON.parse(e.data))

	await new Promise((res) => {
		let n = 0
		const done = () => ++n === 2 && res()
		aSock.onopen = done
		bSock.onopen = done
		setTimeout(res, 3000)
	})
	check('both members connect over hand-rolled websocket', aSock.readyState === 1 && bSock.readyState === 1)

	aSock.send(JSON.stringify({ t: 'ping' }))
	await sleep(200)
	check('ping/pong works (frame parsing)', aMsgs.some((m) => m.t === 'pong'))

	// A big SDP-sized blob to exercise the 126-length frame path.
	const sdp = 'v=0\r\n' + 'a=candidate:'.repeat(500)
	aSock.send(JSON.stringify({ t: 'signal', to: 'bob', payload: sdp }))
	await sleep(300)
	const got = bMsgs.find((m) => m.t === 'signal')
	check('signal forwarded to peer', !!got)
	check('signal is attributed to real sender', got && got.from === 'alice')
	check('large SDP payload survives framing', got && got.payload === sdp)

	aSock.send(JSON.stringify({ t: 'signal', to: 'nobody', payload: 'x' }))
	await sleep(200)
	check('signal to non-member silently dropped', !aMsgs.some((m) => m.t === 'offline' && m.who === 'nobody'))

	// Offline notice
	bSock.close()
	await sleep(300)
	aSock.send(JSON.stringify({ t: 'signal', to: 'bob', payload: 'x' }))
	await sleep(300)
	check('sender told peer is offline', aMsgs.some((m) => m.t === 'offline' && m.who === 'bob'))

	// Mail notification on connect
	await fetch(`${BASE}/v1/send?to=bob&` + (await auth(alice)), {
		method: 'POST',
		body: 'sealed-again',
	})
	const bSock2 = new WebSocket(await wsUrl(bob))
	const b2 = []
	bSock2.onmessage = (e) => b2.push(JSON.parse(e.data))
	await new Promise((r) => {
		bSock2.onopen = r
		setTimeout(r, 2000)
	})
	await sleep(400)
	check('waiting mail announced on connect', b2.some((m) => m.t === 'mail'))

	aSock.close()
	bSock2.close()
}

console.log('\n== unauthorized websocket ==')
{
	const bad = new WebSocket(`ws://127.0.0.1:${PORT}/v1/signal?handle=mallory&ts=${Date.now()}&sig=AAAA`)
	const closed = await new Promise((res) => {
		bad.onerror = () => res(true)
		bad.onclose = () => res(true)
		bad.onopen = () => res(false)
		setTimeout(() => res(false), 2000)
	})
	check('non-member websocket refused', closed === true)
}

relay.kill('SIGKILL')
fs.rmSync(tmp, { recursive: true, force: true })
console.log(`\n${pass} passed, ${fail} failed\n`)
process.exit(fail === 0 ? 0 : 1)
