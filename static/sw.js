const CACHE_NAME = 'roxli-account-v1';
const urlsToCache = [
  '/',
  '/static/css/account.css',
  '/static/js/account.js',
  '/static/js/auth-bridge.js',
  '/static/images/logo.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => response || fetch(event.request))
  );
});