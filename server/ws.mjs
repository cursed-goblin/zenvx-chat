// Minimal RFC6455 WebSocket server. ~150 lines, zero dependencies.
//
// We only need text frames, ping/pong, and close. Writing this by hand keeps the
// relay dependency-free, which means no supply-chain surface on the one machine
// that sees all our traffic metadata.

import { createHash } from 'node:crypto'

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

export function accept(req, socket) {
	const key = req.headers['sec-websocket-key']
	if (!key) {
		socket.destroy()
		return null
	}
	const hash = createHash('sha1')
		.update(key + GUID)
		.digest('base64')
	socket.write(
		'HTTP/1.1 101 Switching Protocols\r\n' +
			'Upgrade: websocket\r\n' +
			'Connection: Upgrade\r\n' +
			`Sec-WebSocket-Accept: ${hash}\r\n\r\n`,
	)
	return new WsConnection(socket)
}

function encodeFrame(opcode, payload) {
	const len = payload.length
	let header
	if (len < 126) {
		header = Buffer.alloc(2)
		header[1] = len
	} else if (len < 65536) {
		header = Buffer.alloc(4)
		header[1] = 126
		header.writeUInt16BE(len, 2)
	} else {
		header = Buffer.alloc(10)
		header[1] = 127
		header.writeBigUInt64BE(BigInt(len), 2)
	}
	header[0] = 0x80 | opcode // FIN + opcode
	return Buffer.concat([header, payload])
}

export class WsConnection {
	constructor(socket) {
		this.socket = socket
		this.buf = Buffer.alloc(0)
		this.frags = []
		this.fragOpcode = null
		this.closed = false
		this.firedClose = false
		this.handlers = { message: [], close: [] }

		socket.on('data', (d) => this._onData(d))
		socket.on('error', () => this._fireClose())
		socket.on('close', () => this._fireClose())
		socket.setNoDelay(true)
	}

	on(event, fn) {
		this.handlers[event]?.push(fn)
		return this
	}

	send(str) {
		if (this.closed) return false
		try {
			this.socket.write(encodeFrame(0x1, Buffer.from(str, 'utf8')))
			return true
		} catch {
			return false
		}
	}

	close(code = 1000) {
		if (!this.closed) {
			const b = Buffer.alloc(2)
			b.writeUInt16BE(code, 0)
			try {
				this.socket.write(encodeFrame(0x8, b))
			} catch {}
			this.closed = true
			this.socket.end()
		}
		// Must still notify listeners. Guarding this on `closed` was a bug:
		// a peer-initiated close frame set closed=true, so the socket was never
		// removed from the online map and the peer looked permanently online.
		this._fireClose()
	}

	_fireClose() {
		if (this.firedClose) return
		this.firedClose = true
		this.closed = true
		for (const fn of this.handlers.close) fn()
	}

	_onData(chunk) {
		this.buf = Buffer.concat([this.buf, chunk])
		// Hard cap so a hostile peer cannot exhaust memory before we parse.
		if (this.buf.length > 4 * 1024 * 1024) {
			this.close(1009)
			return
		}
		while (true) {
			const frame = this._readFrame()
			if (!frame) break
			this._handleFrame(frame)
			if (this.closed) break
		}
	}

	_readFrame() {
		const b = this.buf
		if (b.length < 2) return null
		const fin = (b[0] & 0x80) !== 0
		const opcode = b[0] & 0x0f
		const masked = (b[1] & 0x80) !== 0
		let len = b[1] & 0x7f
		let off = 2

		if (len === 126) {
			if (b.length < off + 2) return null
			len = b.readUInt16BE(off)
			off += 2
		} else if (len === 127) {
			if (b.length < off + 8) return null
			const big = b.readBigUInt64BE(off)
			if (big > 4194304n) {
				this.close(1009)
				return null
			}
			len = Number(big)
			off += 8
		}

		let mask = null
		if (masked) {
			if (b.length < off + 4) return null
			mask = b.subarray(off, off + 4)
			off += 4
		}
		if (b.length < off + len) return null

		const payload = Buffer.from(b.subarray(off, off + len))
		if (mask) {
			for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3]
		}
		this.buf = b.subarray(off + len)
		return { fin, opcode, payload }
	}

	_handleFrame(f) {
		switch (f.opcode) {
			case 0x0: // continuation
				this.frags.push(f.payload)
				if (f.fin) this._deliver()
				break
			case 0x1: // text
			case 0x2: // binary
				this.fragOpcode = f.opcode
				this.frags = [f.payload]
				if (f.fin) this._deliver()
				break
			case 0x8:
				this.close(1000)
				break
			case 0x9: // ping -> pong
				try {
					this.socket.write(encodeFrame(0xa, f.payload))
				} catch {}
				break
			case 0xa:
				break // pong, ignore
			default:
				this.close(1002)
		}
	}

	_deliver() {
		const payload = Buffer.concat(this.frags)
		this.frags = []
		const str = payload.toString('utf8')
		for (const fn of this.handlers.message) fn(str)
	}
}
