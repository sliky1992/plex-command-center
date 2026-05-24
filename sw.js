// Service worker: offline-fallback only, never cache the app shell.
//
// Why no caching of index.html: the inline React app is the entire UI, so a cached HTML
// freezes every fix/feature until the SW happens to refresh. We HAD that bug — the user saw
// stale UI after deploys despite Ctrl+F5. Now the SW network-fetches index.html every time
// and only falls back to a cache for genuine offline (no network).
//
// Other assets (manifest, icons) keep cache-first so the PWA still installs cleanly.
const CACHE_NAME = 'pcc-v4.0.13';
const PRECACHE = ['/manifest.json', '/icon-192.png', '/icon-512.png'];
const NEVER_CACHE = ['/', '/index.html', '/sw.js'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(PRECACHE).catch(() => {})));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // API calls: untouched. The browser deals with them directly so auth cookies & live data work.
  if (url.pathname.startsWith('/api/')) return;
  // App shell: always network. Fall through (no respondWith) so the browser fetches normally
  // and honors the no-store Cache-Control header the server sends. We don't even try the
  // cache here — stale UI is worse than a few seconds of "offline" if the network is down.
  if (NEVER_CACHE.includes(url.pathname)) return;
  // Everything else: network-first with cache fallback for offline.
  e.respondWith(
    fetch(e.request).then(r => {
      if (r.ok) {
        const clone = r.clone();
        caches.open(CACHE_NAME).then(c => c.put(e.request, clone)).catch(() => {});
      }
      return r;
    }).catch(() => caches.match(e.request))
  );
});
