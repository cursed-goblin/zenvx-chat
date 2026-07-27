#!/usr/bin/env node
// ZenvX community root key tool. Runs on the OPERATOR's machine only.
//
//   node tools/root-key.mjs init                 generate the root key, bake pubkey into the client
//   node tools/root-key.mjs enroll req.json      vouch for a new member
//   node tools/root-key.mjs revoke <handle>      remove a member
//   node tools/root-key.mjs seal                 re-sign the directory (bumps serial)
//   node tools/root-key.mjs verify               check the directory end to end
//   node tools/root-key.mjs fingerprint          print the root fingerprint to read aloud
//
// THE PRIVATE KEY MUST NEVER TOUCH AN INTERNET-CONNECTED MACHINE OR THIS REPO.
// Default location is ~/.zenvx-root/root.key (mode 0600), outside the project.

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import * as P from '../client/crypto/primitives.js'
import * as Trust from '../client/crypto/trust.js'

const ROOT_DIR = process.env.ZENVX_ROOT_DIR || path.join(os.homedir(), '.zenvx-root')
const KEY_FILE = path.join(ROOT_DIR, 'root.key')
const PUB_FILE = path.join(ROOT_DIR, 'root.pub')
const REPO = path.resolve(new URL('..', import.meta.url).pathname)
const DIR_FILE = path.join(REPO, 'directory', 'members.json')
const SIG_FILE = path.join(REPO, 'directory', 'members.sig')
const TRUST_FILE = path.join(REPO, 'client', 'crypto', 'trust.js')

const die = (m) => {
	console.error('error: ' + m)
	process.exit(1)
}

function loadDirectory() {
	if (!fs.existsSync(DIR_FILE)) {
		return { version: 1, serial: 0, updatedAt: new Date().toISOString(), members: [], revoked: [] }
	}
	return JSON.parse(fs.readFileSync(DIR_FILE, 'utf8'))
}

function saveDirectory(d) {
	fs.mkdirSync(path.dirname(DIR_FILE), { recursive: true })
	fs.writeFileSync(DIR_FILE, JSON.stringify(d, null, 2) + '\n')
}

async function loadRootPriv() {
	if (!fs.existsSync(KEY_FILE)) die(`no root key at ${KEY_FILE}. Run: init`)
	return P.edImportPriv(P.fromB64(fs.readFileSync(KEY_FILE, 'utf8').trim()))
}

function loadRootPub() {
	if (!fs.existsSync(PUB_FILE)) die(`no root pubkey at ${PUB_FILE}. Run: init`)
	return fs.readFileSync(PUB_FILE, 'utf8').trim()
}

// Short human-readable fingerprint, for reading aloud over a voice call so
// members can confirm the app they installed carries the right root key.
async function fingerprint(pubB64) {
	const h = await P.sha256(P.fromB64(pubB64))
	return [...h.slice(0, 10)]
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('')
		.toUpperCase()
		.match(/.{4}/g)
		.join('-')
}

async function seal(d, priv) {
	d.serial = Number(d.serial || 0) + 1
	d.updatedAt = new Date().toISOString()
	const sig = await P.sign(priv, Trust.canonicalDirectoryBytes(d))
	saveDirectory(d)
	fs.writeFileSync(SIG_FILE, P.toB64(sig) + '\n')
	return d
}

const [cmd, ...args] = process.argv.slice(2)

switch (cmd) {
	case 'init': {
		if (fs.existsSync(KEY_FILE)) {
			die(`root key already exists at ${KEY_FILE}. Refusing to overwrite — that would orphan every enrolled member.`)
		}
		const kp = await P.ed25519Generate()
		const priv = P.toB64(await P.edExportPriv(kp.privateKey))
		const pub = P.toB64(await P.edExportPub(kp.publicKey))

		fs.mkdirSync(ROOT_DIR, { recursive: true, mode: 0o700 })
		fs.writeFileSync(KEY_FILE, priv + '\n', { mode: 0o600 })
		fs.writeFileSync(PUB_FILE, pub + '\n', { mode: 0o644 })

		// Bake the public key into the shipped client.
		const t = fs.readFileSync(TRUST_FILE, 'utf8')
		fs.writeFileSync(
			TRUST_FILE,
			t.replace("'__ZENVX_ROOT_PUBLIC_KEY__'", JSON.stringify(pub)),
		)

		await seal(loadDirectory(), kp.privateKey)

		console.log('\nroot key created.\n')
		console.log('  private : ' + KEY_FILE + '   (mode 0600 — never commit, never copy online)')
		console.log('  public  : ' + pub)
		console.log('  finger  : ' + (await fingerprint(pub)))
		console.log('\nBaked the public key into client/crypto/trust.js.')
		console.log('Back up the private key OFFLINE, in two places, now.')
		console.log('If you lose it you must re-enroll all 1000 members.\n')
		break
	}

	case 'enroll': {
		const reqFile = args[0]
		if (!reqFile) die('usage: enroll <request.json>')
		const req = JSON.parse(fs.readFileSync(reqFile, 'utf8'))
		for (const f of ['handle', 'displayName', 'idSign', 'idDh']) {
			if (!req[f]) die('request missing field: ' + f)
		}
		if (!/^[a-z0-9_.-]{2,32}$/.test(req.handle)) {
			die('handle must be 2-32 chars of a-z 0-9 _ . -')
		}

		// The request is self-signed, proving the requester holds the private key.
		const selfOk = await P.verify(
			P.fromB64(req.idSign),
			P.fromB64(req.selfSig),
			P.utf8.enc(`zenvx-enroll-v1|${req.handle}|${req.idSign}|${req.idDh}`),
		)
		if (!selfOk) die('request self-signature invalid — possibly tampered in transit')

		const d = loadDirectory()
		if (d.members.some((m) => m.handle === req.handle)) {
			die(`handle "${req.handle}" already enrolled. Revoke first to re-key.`)
		}

		const member = {
			handle: req.handle,
			displayName: req.displayName,
			idSign: req.idSign,
			idDh: req.idDh,
			enrolledAt: Math.floor(Date.now() / 1000),
		}
		const priv = await loadRootPriv()
		member.rootSig = P.toB64(await P.sign(priv, Trust.canonicalMemberBytes(member)))
		d.members.push(member)
		await seal(d, priv)

		console.log(`enrolled ${member.handle} (${member.displayName})`)
		console.log(`directory serial now ${d.serial}, ${d.members.length} members`)
		console.log('Commit directory/ and the relay will pick it up within 5s.')
		break
	}

	case 'revoke': {
		const handle = args[0]
		if (!handle) die('usage: revoke <handle>')
		const d = loadDirectory()
		const i = d.members.findIndex((m) => m.handle === handle)
		if (i === -1) die('no such member: ' + handle)
		d.members.splice(i, 1)
		d.revoked = d.revoked || []
		d.revoked.push({ handle, at: new Date().toISOString(), reason: args[1] || 'unspecified' })
		await seal(d, await loadRootPriv())
		console.log(`revoked ${handle}. serial now ${d.serial}`)
		console.log('NOTE: revocation stops new sessions. It cannot delete messages')
		console.log('already on their device. That is inherent to E2EE.')
		break
	}

	case 'seal': {
		const d = await seal(loadDirectory(), await loadRootPriv())
		console.log(`sealed. serial ${d.serial}, ${d.members.length} members`)
		break
	}

	case 'verify': {
		const pub = loadRootPub()
		const d = loadDirectory()
		const sig = fs.existsSync(SIG_FILE) ? fs.readFileSync(SIG_FILE, 'utf8').trim() : null
		const dirOk = await Trust.verifyDirectorySignature(d, sig, pub)
		const { accepted, rejected } = await Trust.verifyDirectory(d, pub)
		console.log(`root        : ${await fingerprint(pub)}`)
		console.log(`serial      : ${d.serial}`)
		console.log(`dir sig     : ${dirOk ? 'VALID' : 'INVALID'}`)
		console.log(`members ok  : ${accepted.length}`)
		console.log(`members bad : ${rejected.length}${rejected.length ? ' (' + rejected.join(', ') + ')' : ''}`)
		console.log(`revoked     : ${(d.revoked || []).length}`)
		process.exit(dirOk && rejected.length === 0 ? 0 : 1)
		break
	}

	case 'fingerprint': {
		console.log(await fingerprint(loadRootPub()))
		break
	}

	default:
		console.log(fs.readFileSync(new URL(import.meta.url), 'utf8')
			.split('\n')
			.filter((l) => l.startsWith('//'))
			.map((l) => l.replace(/^\/\/ ?/, ''))
			.join('\n'))
		process.exit(cmd ? 1 : 0)
}
