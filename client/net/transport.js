// ZenvX Chat — transport. Decides HOW a sealed envelope reaches a peer.
//
// Preference order:
//   1. WebRTC DataChannel  — direct device-to-device, the relay sees nothing
//   2. TURN-relayed WebRTC — when NAT traversal fails (common on mobile networks)
//   3. Store-and-forward   — peer offline; a sealed envelope waits on the relay
//
// The ciphertext is byte-identical on all three paths, so the transport cannot
// weaken security — only latency.

import * as P from '../crypto/primitives.js'
import * as X3DH from '../crypto/x3dh.js'
import * as Ratchet from '../crypto/ratchet.js'
import * as Envelope from '../crypto/envelope.js'
import * as Store from '../db/store.js'

export class Transport {
	constructor({ identity, relayUrl, iceServers, directory }) {
		this.id = identity
		this.relayUrl = String(relayUrl || '').replace(/\/$/, '')
		this.iceServers = iceServers || []
		this.directory = directory
		this.ws = null
		this.peers = new Map()
		this.sessions = new Map()
		this.listeners = []
		this.statusListeners = []
		this.reconnectDelay = 1000
		this.stopped = false
	}

	onMessage(fn) {
		this.listeners.push(fn)
	}
	onStatus(fn) {
		this.statusListeners.push(fn)
	}
	_status(s) {
		for (const fn of this.statusListeners) fn(s)
	}

	// Membership proof: sign a fresh timestamp with the identity key that the
	// community root vouched for. Query params, not headers — browser WebSocket
	// cannot set headers.
	async authQuery() {
		const ts = Date.now()
		const sig = await P.sign(
			this.id.idSign.privateKey,
			P.utf8.enc(`zenvx-auth-v1|${this.id.handle}|${ts}`),
		)
		return (
			`handle=${encodeURIComponent(this.id.handle)}&ts=${ts}` +
			`&sig=${encodeURIComponent(P.toB64(sig))}`
		)
	}

	// -------------------------------------------------------------- signalling

	async connect() {
		if (this.ws && this.ws.readyState <= 1) return
		this.stopped = false
		const q = await this.authQuery()
		const url = this.relayUrl.replace(/^http/, 'ws') + '/v1/signal?' + q
		this.ws = new WebSocket(url)

		this.ws.onopen = () => {
			this.reconnectDelay = 1000
			this._status('online')
			this.drainInbox()
			this.flushOutbox()
		}
		this.ws.onmessage = (e) => {
			let m
			try {
				m = JSON.parse(e.data)
			} catch {
				return
			}
			if (m.t === 'mail') this.drainInbox()
			else if (m.t === 'signal') this._onSignal(m.from, m.payload)
			else if (m.t === 'offline') this._status({ offline: m.who })
		}
		this.ws.onclose = () => {
			this._status('offline')
			if (this.stopped) return
			// Backoff, capped. Mobile networks flap constantly.
			setTimeout(() => this.connect(), this.reconnectDelay)
			this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30000)
		}
	}

	stop() {
		this.stopped = true
		try {
			this.ws?.close()
		} catch {}
	}

	_signal(to, payload) {
		if (this.ws?.readyState === 1) {
			this.ws.send(JSON.stringify({ t: 'signal', to, payload }))
			return true
		}
		return false
	}

	// ----------------------------------------------------------------- WebRTC
	// Perfect-negotiation-lite: the lexicographically smaller handle is "polite"
	// and yields on an offer collision. Without this, simultaneous offers
	// deadlock both sides.

	_isPolite(peer) {
		return this.id.handle < peer
	}

	async getPeer(handle) {
		let entry = this.peers.get(handle)
		if (entry && entry.pc.connectionState !== 'failed') return entry

		const pc = new RTCPeerConnection({ iceServers: this.iceServers })
		entry = { pc, dc: null, ready: false, makingOffer: false }
		this.peers.set(handle, entry)

		pc.onicecandidate = (e) => {
			if (e.candidate) this._signal(handle, { ice: e.candidate })
		}
		pc.onconnectionstatechange = () => {
			if (['failed', 'closed', 'disconnected'].includes(pc.connectionState)) {
				entry.ready = false
				this._status({ peer: handle, state: pc.connectionState })
			}
		}
		pc.ondatachannel = (e) => this._bindChannel(handle, entry, e.channel)
		return entry
	}

	_bindChannel(handle, entry, dc) {
		entry.dc = dc
		dc.onopen = () => {
			entry.ready = true
			this._status({ peer: handle, state: 'p2p' })
			this.flushOutbox()
		}
		dc.onclose = () => {
			entry.ready = false
		}
		dc.onmessage = (e) => {
			this._onEnvelope(e.data).catch((err) =>
				console.warn('bad p2p envelope', err.message),
			)
		}
	}

	async openChannel(handle) {
		const entry = await this.getPeer(handle)
		if (entry.ready) return entry
		if (!entry.dc) {
			this._bindChannel(handle, entry, entry.pc.createDataChannel('zenvx'))
		}
		try {
			entry.makingOffer = true
			await entry.pc.setLocalDescription(await entry.pc.createOffer())
			this._signal(handle, { sdp: entry.pc.localDescription })
		} finally {
			entry.makingOffer = false
		}
		return entry
	}

	async _onSignal(from, payload) {
		if (!this.directory.has(from)) return // not a verified member — ignore
		const entry = await this.getPeer(from)
		const pc = entry.pc

		if (payload.sdp) {
			const collision =
				payload.sdp.type === 'offer' &&
				(entry.makingOffer || pc.signalingState !== 'stable')
			if (collision && !this._isPolite(from)) return
			if (collision) {
				await pc.setLocalDescription({ type: 'rollback' }).catch(() => {})
			}
			await pc.setRemoteDescription(payload.sdp)
			if (payload.sdp.type === 'offer') {
				await pc.setLocalDescription(await pc.createAnswer())
				this._signal(from, { sdp: pc.localDescription })
			}
		} else if (payload.ice) {
			try {
				await pc.addIceCandidate(payload.ice)
			} catch {}
		}
	}

	// ---------------------------------------------------------------- sessions

	async session(handle) {
		if (this.sessions.has(handle)) return this.sessions.get(handle)
		const saved = await Store.loadSession(handle)
		if (saved) {
			const st = await Ratchet.importState(saved)
			this.sessions.set(handle, st)
			return st
		}
		return null
	}

	async persist(handle) {
		const st = this.sessions.get(handle)
		if (st) await Store.saveSession(handle, await Ratchet.exportState(st))
	}

	// ----------------------------------------------------------------- sending

	async send(handle, body) {
		const member = this.directory.get(handle)
		if (!member) throw new Error('not a verified member: ' + handle)

		let st = await this.session(handle)
		let preKeyMsg = null

		if (!st) {
			// No session yet: run X3DH against their published bundle. This works
			// even while they are offline, which is the entire point of prekeys.
			const r = await X3DH.initiate(this.id, await this.fetchBundle(handle))
			st = r.state
			preKeyMsg = r.preKeyMsg
			this.sessions.set(handle, st)
		}

		const msg = await Ratchet.encrypt(st, P.utf8.enc(JSON.stringify(body)))
		await this.persist(handle)

		// Sealed sender: the relay never learns who sent this.
		const box = await Envelope.seal(member.idDh, {
			from: this.id.handle,
			prekey: preKeyMsg,
			msg,
		})

		// 1. direct P2P
		const entry = this.peers.get(handle)
		if (entry?.ready && entry.dc?.readyState === 'open') {
			entry.dc.send(JSON.stringify({ to: handle, box }))
			return { path: 'p2p' }
		}

		// Warm a channel for next time; failure is not fatal.
		this.openChannel(handle).catch(() => {})

		// 2. relay queue
		try {
			const res = await fetch(
				`${this.relayUrl}/v1/send?to=${encodeURIComponent(handle)}&${await this.authQuery()}`,
				{ method: 'POST', body: JSON.stringify(box) },
			)
			if (res.ok) return { path: 'relay' }
			throw new Error('relay rejected: ' + res.status)
		} catch (e) {
			// 3. hold it locally and retry on reconnect
			await Store.queueOutbound({ to: handle, box })
			return { path: 'queued', error: e.message }
		}
	}

	async flushOutbox() {
		for (const it of await Store.listOutbound()) {
			try {
				const res = await fetch(
					`${this.relayUrl}/v1/send?to=${encodeURIComponent(it.to)}&${await this.authQuery()}`,
					{ method: 'POST', body: JSON.stringify(it.box) },
				)
				if (res.ok) await Store.dequeueOutbound(it.id)
				else if (res.status === 413 || res.status === 403) {
					// Permanently undeliverable — drop it instead of looping forever.
					await Store.dequeueOutbound(it.id)
				}
			} catch {
				break // still offline; try again next reconnect
			}
		}
	}

	// --------------------------------------------------------------- receiving

	async drainInbox() {
		try {
			const res = await fetch(`${this.relayUrl}/v1/inbox?${await this.authQuery()}`)
			if (!res.ok) return
			const { envelopes } = await res.json()
			if (!envelopes?.length) return

			const done = []
			for (const e of envelopes) {
				try {
					await this._onEnvelope(e.envelope)
				} catch (err) {
					// Undecryptable mail must still be acked or it blocks the queue forever.
					console.warn('undecryptable envelope', err.message)
				}
				done.push(e.id)
			}
			await fetch(`${this.relayUrl}/v1/ack?${await this.authQuery()}`, {
				method: 'POST',
				body: JSON.stringify({ ids: done }),
			})
		} catch {}
	}

	async _onEnvelope(raw) {
		const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw
		const box = parsed.box || parsed
		const inner = await Envelope.openWith(this.id.idDh, box)

		const from = inner.from
		if (!this.directory.has(from)) {
			throw new Error('envelope claims unverified sender: ' + from)
		}

		let st = await this.session(from)
		if (!st) {
			if (!inner.prekey) throw new Error('no session and no prekey message')
			st = await X3DH.respond(this.id, inner.prekey)
			this.sessions.set(from, st)
		}

		const pt = await Ratchet.decrypt(st, inner.msg)
		await this.persist(from)
		const body = JSON.parse(P.utf8.dec(pt))
		for (const fn of this.listeners) fn({ from, body })
		return { from, body }
	}

	// Prekey bundles ride along in the root-signed directory next to identity keys.
	async fetchBundle(handle) {
		const member = this.directory.get(handle)
		if (!member?.bundle) {
			throw new Error(
				`${handle} has not published a prekey bundle yet, so no session can be started.`,
			)
		}
		return member.bundle
	}
}
