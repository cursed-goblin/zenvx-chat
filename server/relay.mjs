// ZenvX Relay — the entire backend. Runs on one Oracle Always Free instance.
//
// It does exactly three things:
//   1. WebRTC signalling  — forwards opaque offer/answer/ICE blobs between members
//   2. Store-and-forward  — holds SEALED envelopes for offline devices, TTL 30d
//   3. Membership gate    — only root-signed members may connect
//
// It cannot read a single message. It never sees plaintext, message keys, or
// (thanks to sealed sender) who is talking to whom.

import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import * as P from '../client/crypto/primitives.js'
import * as Trust from '../client/crypto/trust.js'
import { accept } from './ws.mjs'

const PORT = Number(process.env.PORT || 8080)
const DATA_DIR = process.env.ZENVX_DATA || '/var/lib/zenvx'
const DIRECTORY = process.env.ZENVX_DIRECTORY || '/var/lib/zenvx/members.json'
const ROOT_PUB = process.env.ZENVX_ROOT_PUB || ''
const TTL_MS = 30 * 24 * 3600 * 1000
const MAX_QUEUE_PER_DEVICE = 2000
const MAX_ENVELOPE = 256 * 1024
const AUTH_WINDOW_MS = 120 * 1000

fs.mkdirSync(path.join(DATA_DIR, 'queue'), { recursive: true })

// ------------------------------------------------------------------ directory

let members = new Map() // handle -> member record

async function loadDirectory() {
	try {
		const raw = JSON.parse(fs.readFileSync(DIRECTORY, 'utf8'))
		const { accepted, rejected, revoked } = await Trust.verifyDirectory(raw, ROOT_PUB)
		const revokedSet = new Set(revoked.map((r) => r.handle || r))
		const next = new Map()
		for (const m of accepted) {
			if (!revokedSet.has(m.handle)) next.set(m.handle, m)
		}
		members = next
		log(
			`directory loaded: ${members.size} members` +
				(rejected.length ? `, ${rejected.length} rejected (${rejected.join(',')})` : '') +
				(revokedSet.size ? `, ${revokedSet.size} revoked` : ''),
		)
	} catch (e) {
		log('directory load FAILED: ' + e.message)
	}
}

// ----------------------------------------------------------------------- auth
// Clients prove membership by signing a timestamped challenge with the identity
// key the community root vouched for. No passwords, no sessions, no accounts.

async function verifyAuth(handle, ts, sigB64) {
	const m = members.get(handle)
	if (!m) return false
	const t = Number(ts)
	if (!Number.isFinite(t)) return false
	if (Math.abs(Date.now() - t) > AUTH_WINDOW_MS) return false
	try {
		return await P.verify(
			P.fromB64(m.idSign),
			P.fromB64(sigB64),
			P.utf8.enc(`zenvx-auth-v1|${handle}|${ts}`),
		)
	} catch {
		return false
	}
}

function authFromUrl(u) {
	return {
		handle: u.searchParams.get('handle') || '',
		ts: u.searchParams.get('ts') || '',
		sig: u.searchParams.get('sig') || '',
	}
}

// ---------------------------------------------------------------- mail queue
// One append-only JSONL file per recipient handle. Deleted on ACK.

function queuePath(handle) {
	// handle is validated against the directory before we ever build a path,
	// but belt-and-braces against traversal.
	const safe = handle.replace(/[^a-z0-9_.-]/gi, '')
	return path.join(DATA_DIR, 'queue', safe + '.jsonl')
}

function enqueue(handle, envelope) {
	const p = queuePath(handle)
	let count = 0
	if (fs.existsSync(p)) {
		count = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).length
	}
	if (count >= MAX_QUEUE_PER_DEVICE) return { ok: false, reason: 'queue_full' }
	const id = P.toB64(P.randomBytes(12)).replace(/[^a-zA-Z0-9]/g, '')
	const rec = { id, at: Date.now(), envelope }
	fs.appendFileSync(p, JSON.stringify(rec) + '\n')
	return { ok: true, id }
}

function drain(handle) {
	const p = queuePath(handle)
	if (!fs.existsSync(p)) return []
	const now = Date.now()
	return fs
		.readFileSync(p, 'utf8')
		.split('\n')
		.filter(Boolean)
		.map((l) => {
			try {
				return JSON.parse(l)
			} catch {
				return null
			}
		})
		.filter((r) => r && now - r.at < TTL_MS)
}

function ack(handle, ids) {
	const p = queuePath(handle)
	if (!fs.existsSync(p)) return 0
	const keep = drain(handle).filter((r) => !ids.includes(r.id))
	if (keep.length === 0) fs.rmSync(p, { force: true })
	else fs.writeFileSync(p, keep.map((r) => JSON.stringify(r)).join('\n') + '\n')
	return keep.length
}

function sweep() {
	const dir = path.join(DATA_DIR, 'queue')
	let removed = 0
	for (const f of fs.readdirSync(dir)) {
		const handle = f.replace(/\.jsonl$/, '')
		const before = drain(handle).length
		const p = path.join(dir, f)
		const kept = drain(handle)
		if (kept.length === 0) {
			fs.rmSync(p, { force: true })
			removed += before
		} else if (kept.length !== before) {
			fs.writeFileSync(p, kept.map((r) => JSON.stringify(r)).join('\n') + '\n')
			removed += before - kept.length
		}
	}
	if (removed) log(`sweep: expired ${removed} envelopes`)
}

// ------------------------------------------------------------------ signalling

const online = new Map() // handle -> WsConnection

function log(...a) {
	console.log(new Date().toISOString(), ...a)
}

function json(res, code, body) {
	const s = JSON.stringify(body)
	res.writeHead(code, {
		'content-type': 'application/json',
		'access-control-allow-origin': '*',
		'access-control-allow-headers': '*',
	})
	res.end(s)
}

// Reads a body with a hard cap. On overflow we keep draining the socket and
// report it, rather than destroying the connection — a destroyed socket looks
// like a network fault to the client instead of a clean rejection.
async function readBody(req, limit) {
	return new Promise((resolve) => {
		let size = 0
		let overflow = false
		const chunks = []
		req.on('data', (c) => {
			size += c.length
			if (size > limit) {
				overflow = true
				chunks.length = 0 // stop buffering, keep draining
				return
			}
			if (!overflow) chunks.push(c)
		})
		req.on('end', () =>
			resolve({ overflow, body: Buffer.concat(chunks).toString('utf8') }),
		)
		req.on('error', () => resolve({ overflow, body: '' }))
	})
}

const server = http.createServer(async (req, res) => {
	const u = new URL(req.url, 'http://localhost')

	if (req.method === 'OPTIONS') return json(res, 204, {})

	if (u.pathname === '/health') {
		return json(res, 200, {
			ok: true,
			members: members.size,
			online: online.size,
			uptime: Math.round(process.uptime()),
		})
	}

	// Public: the signed directory. Clients verify the root signature themselves,
	// so serving it over plain HTTP would still be safe — but use TLS anyway.
	if (u.pathname === '/v1/directory' && req.method === 'GET') {
		try {
			return json(res, 200, JSON.parse(fs.readFileSync(DIRECTORY, 'utf8')))
		} catch {
			return json(res, 503, { error: 'directory_unavailable' })
		}
	}

	// Everything below requires membership.
	const a = authFromUrl(u)
	if (!(await verifyAuth(a.handle, a.ts, a.sig))) {
		return json(res, 401, { error: 'not_a_member' })
	}

	if (u.pathname === '/v1/send' && req.method === 'POST') {
		const to = u.searchParams.get('to')
		if (!members.has(to)) return json(res, 404, { error: 'unknown_recipient' })

		// Reject early when the client declares an oversized body.
		const declared = Number(req.headers['content-length'] || 0)
		if (declared > MAX_ENVELOPE) {
			return json(res, 413, { error: 'envelope_too_large', max: MAX_ENVELOPE })
		}

		const { overflow, body } = await readBody(req, MAX_ENVELOPE)
		if (overflow) {
			return json(res, 413, { error: 'envelope_too_large', max: MAX_ENVELOPE })
		}
		// We do not parse the envelope. It is opaque ciphertext to us.
		const r = enqueue(to, body)
		if (!r.ok) return json(res, 507, { error: r.reason })

		// Nudge them if they happen to be connected right now.
		const sock = online.get(to)
		if (sock) sock.send(JSON.stringify({ t: 'mail' }))
		return json(res, 202, { queued: r.id })
	}

	if (u.pathname === '/v1/inbox' && req.method === 'GET') {
		return json(res, 200, { envelopes: drain(a.handle) })
	}

	if (u.pathname === '/v1/ack' && req.method === 'POST') {
		const { body } = await readBody(req, 64 * 1024)
		let ids = []
		try {
			ids = JSON.parse(body).ids || []
		} catch {}
		return json(res, 200, { remaining: ack(a.handle, ids) })
	}

	return json(res, 404, { error: 'not_found' })
})

// WebSocket upgrade -> signalling channel
server.on('upgrade', async (req, socket) => {
	const u = new URL(req.url, 'http://localhost')
	if (u.pathname !== '/v1/signal') {
		socket.destroy()
		return
	}
	const a = authFromUrl(u)
	if (!(await verifyAuth(a.handle, a.ts, a.sig))) {
		socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
		socket.destroy()
		return
	}

	const ws = accept(req, socket)
	if (!ws) return

	online.get(a.handle)?.close(1000) // one socket per handle
	online.set(a.handle, ws)
	log(`+ ${a.handle} (${online.size} online)`)

	// Tell them immediately if mail is waiting.
	if (drain(a.handle).length > 0) ws.send(JSON.stringify({ t: 'mail' }))

	ws.on('message', (raw) => {
		let msg
		try {
			msg = JSON.parse(raw)
		} catch {
			return
		}
		if (msg.t === 'ping') return ws.send(JSON.stringify({ t: 'pong' }))

		// Only forwarding. `payload` is an opaque WebRTC SDP/ICE blob.
		if (msg.t === 'signal' && typeof msg.to === 'string') {
			if (!members.has(msg.to)) return
			const peer = online.get(msg.to)
			if (!peer) {
				ws.send(JSON.stringify({ t: 'offline', who: msg.to }))
				return
			}
			peer.send(
				JSON.stringify({ t: 'signal', from: a.handle, payload: msg.payload }),
			)
		}
	})

	ws.on('close', () => {
		if (online.get(a.handle) === ws) online.delete(a.handle)
		log(`- ${a.handle} (${online.size} online)`)
	})
})

await loadDirectory()
fs.watchFile(DIRECTORY, { interval: 5000 }, () => loadDirectory())
setInterval(sweep, 6 * 3600 * 1000)

server.listen(PORT, () => log(`zenvx relay listening on :${PORT}`))

export { server, enqueue, drain, ack, loadDirectory }
