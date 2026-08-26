// Koffi PWA Service Worker v1.0
const CACHE_NAME = 'koffi-loyalty-v1';
const OFFLINE_URLS = [
  '/loyalty',
  '/arang-loyalty.html',
  '/buy-me-coffee-icon.svg',
  '/manifest.json'
];

// Install: Pre-cache fail utama
self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(OFFLINE_URLS).catch(() => {});
    })
  );
});

// Activate: Buang cache lama
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// Fetch: Cache-first untuk asset statik, network-first untuk API
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Jangan cache API calls atau Supabase
  if (url.pathname.startsWith('/api/') || url.hostname.includes('supabase')) {
    return;
  }

  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(response => {
        if (response && response.status === 200 && event.request.method === 'GET') {
          const cloned = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, cloned));
        }
        return response;
      }).catch(() => caches.match('/loyalty') || caches.match('/arang-loyalty.html'));
    })
  );
});

// Push Notification Handler
self.addEventListener('push', event => {
  const data = event.data ? event.data.json() : {};
  const title = data.title || 'Koffi Loyalty 🎁';
  const options = {
    body: data.body || 'Ada kemas kini untuk anda!',
    icon: '/buy-me-coffee-icon.svg',
    badge: '/buy-me-coffee-icon.svg',
    vibrate: [200, 100, 200],
    data: { url: data.url || '/loyalty' },
    actions: data.actions || [
      { action: 'open', title: '✅ Buka App' },
      { action: 'close', title: '✖ Tutup' }
    ]
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

// Klik pada notifikasi → buka tab loyalty
self.addEventListener('notificationclick', event => {
  event.notification.close();
  if (event.action === 'close') return;
  const targetUrl = (event.notification.data && event.notification.data.url) || '/loyalty';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      for (const client of clientList) {
        if (client.url.includes('/loyalty') && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(targetUrl);
    })
  );
});
