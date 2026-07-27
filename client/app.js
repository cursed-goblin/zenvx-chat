// ZenvX Chat — UI glue. Deliberately thin: all security lives in the modules
// below it, so a bug here cannot leak plaintext or forge identities.

import * as P from './crypto/primitives.js'
import * as X3DH from './crypto/x3dh.js'
import * as Trust from './crypto/trust.js'
import * as Store from './db/store.js'
import { Transport } from './net/transport.js'

const VERSION = '1.0.0'
const DEFAULT_RELAY = 'https://relay.example.org' // set in Settings on first run
const DIRECTORY_URL = './directory/members.json'

const $ = (id) => document.getElementById(id)
const screens = ['s-lock', 's-enroll', 's-list', 's-chat', 's-set']
function show(id) {
	for (const s of screens) $(s).classList.toggle('on', s === id)
}
let toastTimer
function toast(msg) {
	const t = $('toast')
	t.textContent = msg
	t.classList.add('on')
	clearTimeout(toastTimer)
	toastTimer = setTimeout(() => t.classList.remove('on'), 2600)
}
const esc = (s) =>
	String(s).replace(
		/[&<>"']/g,
		(c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
	)
function when(ts) {
	const d = new Date(ts)
	const today = new Date().toDateString() === d.toDateString()
	return today
		? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
		: d.toLocaleDateString([], { day: '2-digit', month: 'short' })
}

const app = {
	identity: null,
	directory: new Map(),
	transport: null,
	peer: null,
	relay: localStorage.getItem('zenvx.relay') || DEFAULT_RELAY,
	ice: [],
}

// --------------------------------------------------------------- boot / unlock

async function boot() {
	$('ver').textContent = VERSION
	if ('serviceWorker' in navigator) {
		navigator.serviceWorker.register('./sw.js').catch(() => {})
	}
	const first = !(await Store.isInitialised())
	if (first) {
		$('lock-sub').textContent = 'Create a passphrase for this device.'
		$('unlock').textContent = 'Create'
		$('pass2wrap').style.display = ''
		$('lock-note').style.display = ''
		$('pass').autocomplete = 'new-password'
	}
	show('s-lock')
	$('pass').focus()
}

$('unlock').onclick = async () => {
	$('lock-err').textContent = ''
	const pw = $('pass').value
	const first = !(await Store.isInitialised())
	if (pw.length < 8) {
		$('lock-err').textContent = 'Use at least 8 characters.'
		return
	}
	$('unlock').disabled = true
	try {
		if (first) {
			if (pw !== $('pass2').value) throw new Error('Passphrases do not match.')
			await Store.initialise(pw)
		} else {
			await Store.unlock(pw)
		}
		$('pass').value = $('pass2').value = ''
		await afterUnlock()
	} catch (e) {
		$('lock-err').textContent = e.message
	} finally {
		$('unlock').disabled = false
	}
}

$('restore').onclick = async () => {
	const inp = document.createElement('input')
	inp.type = 'file'
	inp.accept = '.json,application/json'
	inp.onchange = async () => {
		const pw = $('pass').value
		if (!pw) return toast('Enter the backup passphrase first')
		try {
			const backup = JSON.parse(await inp.files[0].text())
			if (!(await Store.isInitialised())) await Store.initialise(pw)
			else await Store.unlock(pw)
			const r = await Store.importBackup(pw, backup)
			toast(`Restored ${r.events} events`)
			await afterUnlock()
		} catch (e) {
			$('lock-err').textContent = e.message
		}
	}
	inp.click()
}

async function afterUnlock() {
	const saved = localStorage.getItem('zenvx.identity')
	if (!saved) return show('s-enroll')
	try {
		app.identity = await X3DH.importIdentity(JSON.parse(saved))
	} catch {
		return show('s-enroll')
	}
	await loadDirectory()
	await startTransport()
	await renderConversations()
	await fillSettings()
	show('s-list')
}

// ----------------------------------------------------------------- enrolment

$('mkid').onclick = async () => {
	const handle = $('handle').value.trim().toLowerCase()
	const name = $('dname').value.trim() || handle
	if (!/^[a-z0-9_.-]{2,32}$/.test(handle)) {
		return toast('Handle must be 2–32 chars: a–z 0–9 . _ -')
	}
	$('mkid').disabled = true
	try {
		const id = await X3DH.createIdentity(handle)
		app.identity = id
		localStorage.setItem('zenvx.identity', JSON.stringify(await X3DH.exportIdentity(id)))

		// The request is self-signed: it proves the requester holds the private key
		// for the identity they are claiming, so the key holder cannot be tricked
		// into enrolling someone else's key under this handle.
		const idSign = P.toB64(await P.edExportPub(id.idSign.publicKey))
		const idDh = P.toB64(await P.x25519ExportPub(id.idDh.publicKey))
		const sig = P.toB64(
			await P.sign(
				id.idSign.privateKey,
				P.utf8.enc(`zenvx-enroll-v1|${handle}|${idSign}|${idDh}`),
			),
		)
		const request = {
			type: 'zenvx-enrolment-request',
			v: 1,
			handle,
			displayName: name,
			idSign,
			idDh,
			selfSig: sig,
			bundle: await X3DH.publicBundle(id),
		}
		$('req').value = JSON.stringify(request, null, 2)
		$('reqwrap').style.display = ''
	} finally {
		$('mkid').disabled = false
	}
}

$('copyreq').onclick = async () => {
	await navigator.clipboard.writeText($('req').value).catch(() => {})
	toast('Copied — send it to the key holder')
}
$('gotdir').onclick = () => afterUnlock()

// ------------------------------------------------------------------ directory
// Every member record must carry a signature from the community root key that
// is baked into trust.js. An attacker who owns the relay AND the web host still
// cannot inject a fake member.

async function loadDirectory() {
	let dir = null
	try {
		const res = await fetch(DIRECTORY_URL, { cache: 'no-cache' })
		if (res.ok) dir = await res.json()
	} catch {}
	if (!dir) {
		const cached = localStorage.getItem('zenvx.directory')
		if (cached) dir = JSON.parse(cached)
	}
	if (!dir) {
		toast('Could not load member directory')
		return
	}

	// Rollback protection: a stale signed directory is still validly signed, so
	// serial numbers must never go backwards (that would resurrect revoked members).
	const lastSerial = Number(localStorage.getItem('zenvx.dirSerial') || 0)
	if (Trust.isRollback(dir.serial, lastSerial)) {
		toast('Directory rollback detected — ignoring')
		return
	}

	// The directory is signed as a whole, so deletions are detectable too.
	let dirSig = null
	try {
		const r2 = await fetch('./directory/members.sig', { cache: 'no-cache' })
		if (r2.ok) dirSig = (await r2.text()).trim()
	} catch {}
	if (!(await Trust.verifyDirectorySignature(dir, dirSig))) {
		toast('Directory signature invalid — ignoring')
		return
	}

	const { accepted, rejected } = await Trust.verifyDirectory(dir)
	if (rejected.length) toast(`${rejected.length} entries failed signature check`)
	app.directory = new Map()
	const revoked = new Set((dir.revoked || []).map((r) => r.handle || r))
	for (const m of accepted) {
		if (revoked.has(m.handle)) continue
		app.directory.set(m.handle, m)
	}
	localStorage.setItem('zenvx.directory', JSON.stringify(dir))
	localStorage.setItem('zenvx.dirSerial', String(dir.serial))

	if (app.identity && !app.directory.has(app.identity.handle)) {
		toast('You are not in the directory yet')
	}
	if (dir.ice) app.ice = dir.ice
}

// ------------------------------------------------------------------ transport

async function startTransport() {
	app.transport?.stop()
	app.transport = new Transport({
		identity: app.identity,
		relayUrl: app.relay,
		iceServers: app.ice,
		directory: app.directory,
	})
	app.transport.onStatus((s) => {
		if (s === 'online') setNet('relay', 'connected')
		else if (s === 'offline') setNet('off', 'offline — retrying')
		else if (s?.peer === app.peer) {
			$('peerdot').className = 'dot ' + (s.state === 'p2p' ? 'p2p' : 'relay')
			$('peerstate').textContent =
				s.state === 'p2p' ? 'direct · end-to-end encrypted' : 'via relay · encrypted'
		} else if (s?.offline) {
			toast(`${s.offline} is offline — message queued`)
		}
	})
	app.transport.onMessage(async ({ from, body }) => {
		await Store.appendEvent({
			id: body.id,
			conv: from,
			at: body.at || Date.now(),
			author: from,
			kind: 'message',
			body,
		})
		if (app.peer === from) await renderChat(from)
		else {
			toast(`${from}: ${String(body.text).slice(0, 40)}`)
			await renderConversations()
		}
	})
	await app.transport.connect()
}

function setNet(kind, text) {
	$('netdot').className = 'dot ' + kind
	$('netstate').textContent = text
}

// ---------------------------------------------------------------- rendering

async function renderConversations() {
	const convs = await Store.listConversations()
	const el = $('convs')
	if (!convs.length) {
		el.innerHTML =
			'<div class="empty">No conversations yet.<br>Tap <b>New</b> to message a member.</div>'
		return
	}
	el.innerHTML = convs
		.map(
			(c) => `<div class="row" data-peer="${esc(c.conv)}">
			<div class="av">${esc(c.conv[0].toUpperCase())}</div>
			<div class="meta">
				<div>${esc(app.directory.get(c.conv)?.displayName || c.conv)}</div>
				<div class="last">${esc(c.last.body.text || '')}</div>
			</div>
			<div class="when">${when(c.at)}</div>
		</div>`,
		)
		.join('')
	for (const row of el.querySelectorAll('.row')) {
		row.onclick = () => openChat(row.dataset.peer)
	}
}

async function openChat(handle) {
	app.peer = handle
	$('peername').textContent = app.directory.get(handle)?.displayName || handle
	$('peerdot').className = 'dot relay'
	$('peerstate').textContent = 'encrypted'
	show('s-chat')
	await renderChat(handle)
	$('input').focus()
	// Opportunistically try for a direct connection; falls back silently.
	app.transport?.openChannel(handle).catch(() => {})
}

async function renderChat(handle) {
	const events = await Store.listEvents(handle)
	const me = app.identity.handle
	$('msgs').innerHTML = events
		.filter((e) => e.kind === 'message')
		.map(
			(e) =>
				`<div class="bub ${e.author === me ? 'me' : ''}">${esc(e.body.text)}<div class="t">${when(e.at)}</div></div>`,
		)
		.join('')
	$('msgs').scrollTop = $('msgs').scrollHeight
}

// ------------------------------------------------------------------- sending

async function sendCurrent() {
	const text = $('input').value.trim()
	if (!text || !app.peer) return
	$('input').value = ''
	$('input').style.height = 'auto'

	// Content-addressed id makes replay and multi-device merge idempotent.
	const at = Date.now()
	const id = P.toB64(
		await P.sha256(P.utf8.enc(`${app.identity.handle}|${app.peer}|${at}|${text}`)),
	).slice(0, 22)
	const body = { id, text, at }

	await Store.appendEvent({
		id,
		conv: app.peer,
		at,
		author: app.identity.handle,
		kind: 'message',
		body,
	})
	await renderChat(app.peer)

	try {
		const r = await app.transport.send(app.peer, body)
		if (r.path === 'queued') toast('Saved — will send when you are back online')
	} catch (e) {
		toast(e.message)
	}
}

$('go').onclick = sendCurrent
$('input').addEventListener('keydown', (e) => {
	if (e.key === 'Enter' && !e.shiftKey) {
		e.preventDefault()
		sendCurrent()
	}
})
$('input').addEventListener('input', (e) => {
	e.target.style.height = 'auto'
	e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px'
})

// --------------------------------------------------------------- navigation

$('back').onclick = async () => {
	app.peer = null
	await renderConversations()
	show('s-list')
}
$('back2').onclick = () => show('s-list')
$('settings').onclick = async () => {
	await fillSettings()
	show('s-set')
}

$('newchat').onclick = () => {
	const members = [...app.directory.keys()].filter((h) => h !== app.identity.handle)
	if (!members.length) return toast('No other members in the directory yet')
	const who = prompt('Message which member?\n\n' + members.join(', '))
	if (!who) return
	const h = who.trim().toLowerCase()
	if (!app.directory.has(h)) return toast('Not a verified member')
	openChat(h)
}

// Safety numbers let two people confirm out-of-band that no one is in the
// middle. With a signed directory this is a belt-and-braces check.
$('verify').onclick = async () => {
	const peer = app.directory.get(app.peer)
	if (!peer) return
	const mine = P.toB64(await P.edExportPub(app.identity.idSign.publicKey))
	const sn = await X3DH.safetyNumber(mine, peer.idSign)
	alert(
		`Safety number with ${app.peer}\n\n${sn}\n\n` +
			'Read this aloud on a call. If it matches on both devices, nobody is intercepting.',
	)
}

async function fillSettings() {
	$('myhandle').textContent = app.identity?.handle || '—'
	$('relay').value = app.relay
	if (app.identity) {
		const mine = P.toB64(await P.edExportPub(app.identity.idSign.publicKey))
		$('myfp').textContent = await X3DH.safetyNumber(mine, mine)
	}
	const est = await Store.storageEstimate()
	if (est) {
		const mb = (n) => (n / 1048576).toFixed(1) + ' MB'
		$('storage').textContent =
			`${mb(est.usage)} used of ~${mb(est.quota)}` +
			(est.persisted ? ' · persistent' : ' · NOT persistent — back up regularly')
		if (!est.persisted && navigator.storage?.persist) navigator.storage.persist()
	}
}

$('backup').onclick = async () => {
	const pw = prompt('Passphrase to encrypt this backup:')
	if (!pw || pw.length < 8) return toast('Use at least 8 characters')
	const backup = await Store.exportBackup(pw)
	const blob = new Blob([JSON.stringify(backup)], { type: 'application/json' })
	const a = document.createElement('a')
	a.href = URL.createObjectURL(blob)
	a.download = `zenvx-backup-${new Date().toISOString().slice(0, 10)}.json`
	a.click()
	URL.revokeObjectURL(a.href)
	toast('Backup exported')
}

$('lock').onclick = () => {
	Store.lock()
	location.reload()
}

$('saverelay').onclick = async () => {
	app.relay = $('relay').value.trim().replace(/\/$/, '')
	localStorage.setItem('zenvx.relay', app.relay)
	await startTransport()
	toast('Reconnecting…')
	show('s-list')
}

// Check for a newer APK/PWA build. Uses the public releases API — no server.
async function checkUpdate() {
	try {
		const res = await fetch(
			'https://api.github.com/repos/cursed-goblin/zenvx-chat/releases/latest',
		)
		if (!res.ok) return
		const rel = await res.json()
		const tag = (rel.tag_name || '').replace(/^v/, '')
		if (tag && tag !== VERSION) toast(`Update available: v${tag}`)
	} catch {}
}

window.addEventListener('online', () => app.transport?.connect())
document.addEventListener('visibilitychange', () => {
	if (!document.hidden) app.transport?.drainInbox()
})

boot()
setTimeout(checkUpdate, 4000)
