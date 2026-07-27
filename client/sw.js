// ZenvX Chat service worker.
//
// Two jobs: make the app work offline, and never cache stale crypto code.
// Strategy: cache-first for the shell, but the shell is versioned — bumping
// VERSION nukes the old cache. A stale ratchet implementation would be a
// correctness bug, not just a UX annoyance.

const VERSION = 'zenvx-v1'
const SHELL = [
	'./',
	'./index.html',
	'./app.js',
	'./manifest.json',
	'./crypto/primitives.js',
	'./crypto/ratchet.js',
	'./crypto/x3dh.js',
	'./crypto/trust.js',
	'./crypto/envelope.js',
	'./db/store.js',
	'./net/transport.js',
]

self.addEventListener('install', (e) => {
	e.waitUntil(
		caches
			.open(VERSION)
			// Individual failures must not abort the whole install.
			.then((c) => Promise.allSettled(SHELL.map((u) => c.add(u))))
			.then(() => self.skipWaiting()),
	)
})

self.addEventListener('activate', (e) => {
	e.waitUntil(
		caches
			.keys()
			.then((keys) =>
				Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))),
			)
			.then(() => self.clients.claim()),
	)
})

self.addEventListener('fetch', (e) => {
	const url = new URL(e.request.url)

	// Never cache relay traffic. Cached inbox responses would silently drop mail.
	if (url.pathname.startsWith('/v1/')) return
	if (e.request.method !== 'GET') return

	e.respondWith(
		caches.match(e.request).then((hit) => {
			if (hit) {
				// Refresh in the background so the next launch is current.
				fetch(e.request)
					.then((res) => {
						if (res.ok) caches.open(VERSION).then((c) => c.put(e.request, res))
					})
					.catch(() => {})
				return hit
			}
			return fetch(e.request).catch(
				() => new Response('offline', { status: 503 }),
			)
		}),
	)
})

// Web Push wake-up. The payload is deliberately contentless — the push service
// (Google/Apple/Mozilla) must learn nothing. It only says "go check your inbox".
self.addEventListener('push', (e) => {
	e.waitUntil(
		self.registration.showNotification('ZenvX', {
			body: 'New message',
			icon: './icon-192.png',
			tag: 'zenvx-mail',
			renotify: true,
			data: { at: Date.now() },
		}),
	)
})

self.addEventListener('notificationclick', (e) => {
	e.notification.close()
	e.waitUntil(
		self.clients.matchAll({ type: 'window' }).then((list) => {
			for (const c of list) if ('focus' in c) return c.focus()
			return self.clients.openWindow('./index.html')
		}),
	)
})
