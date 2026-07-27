// ZenvX Chat — local store. This IS the database. There is no server copy.
//
// IndexedDB (not SQLite/WASM) because it is built into every browser and needs
// zero dependencies and zero downloads. Rows are encrypted at rest with a key
// derived from the user's passphrase, so a stolen unlocked laptop still needs
// the passphrase to read history.
//
// Structure: an append-only event log. Messages, edits, deletes, and group
// membership changes are all events. Conversation views are derived by folding
// the log, which makes multi-device merge tractable.

import * as P from '../crypto/primitives.js'

const DB_NAME = 'zenvx'
const DB_VERSION = 1
const PBKDF2_ITERS = 600000 // ~0.5s on a mid-range phone

let db = null
let dek = null // data encryption key, held in memory only while unlocked

function req(r) {
	return new Promise((res, rej) => {
		r.onsuccess = () => res(r.result)
		r.onerror = () => rej(r.error)
	})
}

export async function open() {
	if (db) return db
	const r = indexedDB.open(DB_NAME, DB_VERSION)
	r.onupgradeneeded = () => {
		const d = r.result
		if (!d.objectStoreNames.contains('meta')) d.createObjectStore('meta')
		if (!d.objectStoreNames.contains('events')) {
			const s = d.createObjectStore('events', { keyPath: 'id' })
			s.createIndex('conv', 'conv')
			s.createIndex('at', 'at')
		}
		if (!d.objectStoreNames.contains('sessions')) d.createObjectStore('sessions')
		if (!d.objectStoreNames.contains('blobs')) d.createObjectStore('blobs')
		if (!d.objectStoreNames.contains('outbox')) {
			d.createObjectStore('outbox', { keyPath: 'id' })
		}
	}
	db = await req(r)
	return db
}

function tx(store, mode = 'readonly') {
	return db.transaction(store, mode).objectStore(store)
}

async function getMeta(k) {
	await open()
	return req(tx('meta').get(k))
}
async function setMeta(k, v) {
	await open()
	return req(tx('meta', 'readwrite').put(v, k))
}

// ------------------------------------------------------------------ unlocking

async function deriveKek(passphrase, salt) {
	const base = await P.subtle.importKey(
		'raw',
		P.utf8.enc(passphrase),
		'PBKDF2',
		false,
		['deriveBits'],
	)
	const bits = await P.subtle.deriveBits(
		{ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERS },
		base,
		256,
	)
	return new Uint8Array(bits)
}

export async function isInitialised() {
	return !!(await getMeta('wrappedDek'))
}

// First run: generate a random data key and wrap it with the passphrase.
export async function initialise(passphrase) {
	if (await isInitialised()) throw new Error('store: already initialised')
	const salt = P.randomBytes(16)
	const kek = await deriveKek(passphrase, salt)
	const freshDek = P.randomBytes(32)
	const wrapped = await P.seal(kek, freshDek, P.utf8.enc('zenvx-dek-v1'))
	await setMeta('salt', P.toB64(salt))
	await setMeta('wrappedDek', P.toB64(wrapped))
	dek = freshDek
}

export async function unlock(passphrase) {
	const saltB64 = await getMeta('salt')
	const wrappedB64 = await getMeta('wrappedDek')
	if (!saltB64 || !wrappedB64) throw new Error('store: not initialised')
	const kek = await deriveKek(passphrase, P.fromB64(saltB64))
	try {
		dek = await P.open(kek, P.fromB64(wrappedB64), P.utf8.enc('zenvx-dek-v1'))
	} catch {
		throw new Error('Wrong passphrase')
	}
	return true
}

export function lock() {
	dek = null
}
export function isUnlocked() {
	return dek !== null
}
function requireKey() {
	if (!dek) throw new Error('store: locked')
	return dek
}

// -------------------------------------------------------------------- events
// Content is encrypted; only routing metadata (conv, at, seq) stays plaintext
// so we can index it. That metadata never leaves the device.

export async function appendEvent(ev) {
	await open()
	const key = requireKey()
	const id = ev.id || P.toB64(P.randomBytes(16))
	const body = P.utf8.enc(JSON.stringify(ev.body))
	const ct = await P.seal(key, body, P.utf8.enc(id))
	const row = {
		id,
		conv: ev.conv,
		at: ev.at || Date.now(),
		seq: ev.seq || 0,
		author: ev.author,
		kind: ev.kind,
		ct: P.toB64(ct),
	}
	await req(tx('events', 'readwrite').put(row))
	return id
}

async function decryptRow(row) {
	const key = requireKey()
	const pt = await P.open(key, P.fromB64(row.ct), P.utf8.enc(row.id))
	return {
		id: row.id,
		conv: row.conv,
		at: row.at,
		seq: row.seq,
		author: row.author,
		kind: row.kind,
		body: JSON.parse(P.utf8.dec(pt)),
	}
}

export async function listEvents(conv) {
	await open()
	const rows = await req(tx('events').index('conv').getAll(conv))
	rows.sort((a, b) => a.at - b.at || a.seq - b.seq)
	return Promise.all(rows.map(decryptRow))
}

export async function listConversations() {
	await open()
	const rows = await req(tx('events').getAll())
	const byConv = new Map()
	for (const r of rows) {
		const cur = byConv.get(r.conv)
		if (!cur || r.at > cur.at) byConv.set(r.conv, r)
	}
	const out = []
	for (const [conv, row] of byConv) {
		out.push({ conv, at: row.at, last: await decryptRow(row) })
	}
	return out.sort((a, b) => b.at - a.at)
}

export async function hasEvent(id) {
	await open()
	return !!(await req(tx('events').get(id)))
}

// ------------------------------------------------------------------- sessions

export async function saveSession(peer, state) {
	await open()
	const key = requireKey()
	const ct = await P.seal(key, P.utf8.enc(JSON.stringify(state)), P.utf8.enc(peer))
	return req(tx('sessions', 'readwrite').put(P.toB64(ct), peer))
}

export async function loadSession(peer) {
	await open()
	const v = await req(tx('sessions').get(peer))
	if (!v) return null
	const key = requireKey()
	const pt = await P.open(key, P.fromB64(v), P.utf8.enc(peer))
	return JSON.parse(P.utf8.dec(pt))
}

// --------------------------------------------------------------------- outbox
// Messages queued while a peer is unreachable. Retried on reconnect.

export async function queueOutbound(item) {
	await open()
	const id = item.id || P.toB64(P.randomBytes(12))
	await req(tx('outbox', 'readwrite').put({ ...item, id, at: Date.now() }))
	return id
}
export async function listOutbound() {
	await open()
	return req(tx('outbox').getAll())
}
export async function dequeueOutbound(id) {
	await open()
	return req(tx('outbox', 'readwrite').delete(id))
}

// --------------------------------------------------------------------- backup
// The ONLY recovery path. There is no server-side restore, by design.
// Output is a single encrypted blob safe to store in any untrusted cloud.

export async function exportBackup(passphrase) {
	await open()
	requireKey()
	const events = await req(tx('events').getAll())
	const sessionKeys = await req(tx('sessions').getAllKeys())
	const sessions = {}
	for (const k of sessionKeys) sessions[k] = await req(tx('sessions').get(k))

	const payload = P.utf8.enc(
		JSON.stringify({ v: 1, exportedAt: Date.now(), events, sessions }),
	)
	const salt = P.randomBytes(16)
	const kek = await deriveKek(passphrase, salt)
	const ct = await P.seal(kek, payload, P.utf8.enc('zenvx-backup-v1'))
	return {
		format: 'zenvx-backup',
		v: 1,
		salt: P.toB64(salt),
		data: P.toB64(ct),
	}
}

export async function importBackup(passphrase, backup) {
	if (backup.format !== 'zenvx-backup') throw new Error('not a ZenvX backup')
	const kek = await deriveKek(passphrase, P.fromB64(backup.salt))
	let pt
	try {
		pt = await P.open(kek, P.fromB64(backup.data), P.utf8.enc('zenvx-backup-v1'))
	} catch {
		throw new Error('Wrong backup passphrase')
	}
	const parsed = JSON.parse(P.utf8.dec(pt))
	await open()
	// Rows are still encrypted under the ORIGINAL dek, so restoring requires the
	// same identity. Merge is idempotent because event ids are content-derived.
	for (const row of parsed.events) {
		await req(tx('events', 'readwrite').put(row))
	}
	for (const [k, v] of Object.entries(parsed.sessions || {})) {
		await req(tx('sessions', 'readwrite').put(v, k))
	}
	return { events: parsed.events.length }
}

// Storage pressure check. iOS Safari evicts OPFS/IndexedDB under pressure, so
// the UI must nag iOS users to back up.
export async function storageEstimate() {
	if (!navigator.storage?.estimate) return null
	const { usage, quota } = await navigator.storage.estimate()
	const persisted = navigator.storage.persisted
		? await navigator.storage.persisted()
		: false
	return { usage, quota, persisted }
}
