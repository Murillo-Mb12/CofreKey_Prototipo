/*
 * CofreKey — service worker
 * Guarda os arquivos do app no aparelho para ele abrir sem internet (RF-36).
 * Não guarda dados do usuário: o cofre fica no localStorage, criptografado.
 */
const CACHE = 'cofrekey-1.0.0';
const FILES = [
  './', 'index.html', 'manifest.webmanifest',
  'css/fonts.css', 'css/app.css',
  'js/totp.js', 'js/vault.js', 'js/passwords.js', 'js/csv.js', 'js/storage.js', 'js/qr.js', 'js/app.js',
  'vendor/qrcode.min.js', 'vendor/jsQR.min.js',
  'fonts/manrope-latin-400-normal.woff2', 'fonts/manrope-latin-500-normal.woff2', 'fonts/manrope-latin-600-normal.woff2',
  'fonts/manrope-latin-700-normal.woff2', 'fonts/manrope-latin-800-normal.woff2',
  'fonts/jetbrains-mono-latin-500-normal.woff2', 'fonts/jetbrains-mono-latin-700-normal.woff2',
  'icons/icon.svg', 'icons/icon-192.png', 'icons/icon-512.png', 'icons/icon-maskable-512.png', 'icons/apple-touch-icon.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('cofrekey-') && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;
  event.respondWith(
    caches.match(req, { ignoreSearch: true }).then((hit) => hit || fetch(req).then((res) => {
      if (res.ok) {
        const copy = res.clone();
        caches.open(CACHE).then((cache) => cache.put(req, copy));
      }
      return res;
    }).catch(() => caches.match('index.html')))
  );
});
