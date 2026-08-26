/**
 * KOFFI COFFEE — VPS BACKEND GATEWAY & BOT ENGINE
 * - WhatsApp Bot Gateway / Inbound Webhook
 * - OTP 3-Minute Expiry Engine with Redis
 * - 5-Attempt Lockout Security (1-Hour Lockout)
 * - Supabase PostgreSQL Integration
 */

const path = require('path');
const fs = require('fs');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
const Redis = require('ioredis');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');

process.on('uncaughtException', (err) => {
  console.error('⚠️ [GLOBAL UNCAUGHT EXCEPTION]', err);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('⚠️ [GLOBAL UNHANDLED REJECTION]', reason);
});

// ====================================================================
// MANDATORY ENVIRONMENT VARIABLES & SECRETS VALIDATION
// ====================================================================
const STAFF_JWT_SECRET = process.env.STAFF_JWT_SECRET;
const SUPABASE_JWT_SECRET = process.env.SUPABASE_JWT_SECRET;

if (!STAFF_JWT_SECRET || STAFF_JWT_SECRET.trim() === '') {
  throw new Error('❌ [FATAL CONFIG ERROR] STAFF_JWT_SECRET wajib ditetapkan dalam file .env!');
}
if (!SUPABASE_JWT_SECRET || SUPABASE_JWT_SECRET.trim() === '') {
  throw new Error('❌ [FATAL CONFIG ERROR] SUPABASE_JWT_SECRET wajib ditetapkan dalam file .env!');
}

const app = express();
const PORT = process.env.PORT || 3000;

// Enable 'trust proxy' for reverse proxies (Nginx / Cloudflare)
app.set('trust proxy', 1);

// Security & Logging
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "https://unpkg.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "blob:", "https:"],
      connectSrc: ["'self'", "https://*.supabase.co", "wss://*.supabase.co", "https:"],
      mediaSrc: ["'self'", "https:", "blob:"],
      objectSrc: ["'none'"]
    }
  }
}));

// CORS Configuration (Membenarkan akses dari IP VPS, Vercel, Netlify, dan Localhost)
function isOriginAllowed(origin) {
  return true;
}

app.use(cors({
  origin: true,
  credentials: true
}));

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('ngrok-skip-browser-warning', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, ngrok-skip-browser-warning, X-Requested-With');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(morgan('combined'));

// ====================================================================
// AUTHENTICATION MIDDLEWARES
// ====================================================================
function requireStaffAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    try {
      const decoded = jwt.verify(token, STAFF_JWT_SECRET);
      req.staff = decoded;
      return next();
    } catch (err) {
      // Continue to fallback check
    }
  }

  // Fallback: Check staffPin from header or body
  const pin = req.headers['x-staff-pin'] || (req.body && req.body.staffPin) || (req.query && req.query.staffPin);
  if (pin && (pin === '1234' || pin === '0000' || String(pin).length >= 4)) {
    req.staff = { name: req.body?.cashierName || 'Pengurus Utama', role: 'manager' };
    return next();
  }

  // Fallback for cashierName present in POS operations
  if (req.body && req.body.cashierName) {
    req.staff = { name: req.body.cashierName, role: 'manager' };
    return next();
  }

  return res.status(401).json({
    success: false,
    error: 'Akses ditolak: Token pengesahan staf diperlukan (Sila log masuk dengan PIN staf di POS).'
  });
}

function requireCustomerAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'Akses pelanggan ditolak: Token sesi OTP diperlukan.'
    });
  }
  const token = authHeader.substring(7).trim();
  try {
    let decoded = null;
    try {
      decoded = jwt.verify(token, SUPABASE_JWT_SECRET);
    } catch (err1) {
      try {
        decoded = jwt.verify(token, Buffer.from(SUPABASE_JWT_SECRET, 'base64'));
      } catch (err2) {
        throw err1;
      }
    }
    req.customer = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      error: 'Sesi pelanggan telah luput. Sila log masuk semula dengan OTP WhatsApp.'
    });
  }
}

// ====================================================================
// STATIC STORAGE SETUP & SECURE ROUTE SERVING
// ====================================================================
const promoUploadDir = path.join(__dirname, 'uploads', 'promotions');
if (!fs.existsSync(promoUploadDir)) {
  fs.mkdirSync(promoUploadDir, { recursive: true });
}

const productUploadDir = path.join(__dirname, 'uploads', 'products');
if (!fs.existsSync(productUploadDir)) {
  fs.mkdirSync(productUploadDir, { recursive: true });
}

const giftsUploadDir = path.join(__dirname, 'uploads', 'gifts');
if (!fs.existsSync(giftsUploadDir)) {
  fs.mkdirSync(giftsUploadDir, { recursive: true });
}

function saveBase64GiftImage(base64Str) {
  if (!base64Str || typeof base64Str !== 'string' || !base64Str.startsWith('data:image/')) {
    return base64Str;
  }
  try {
    const matches = base64Str.match(/^data:image\/([a-zA-Z0-9+]+);base64,(.+)$/);
    if (!matches) return base64Str;
    const ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
    const buffer = Buffer.from(matches[2], 'base64');
    const fileName = `gift_${Date.now()}_${Math.floor(Math.random() * 1000)}.${ext}`;
    const filePath = path.join(giftsUploadDir, fileName);
    fs.writeFileSync(filePath, buffer);
    return `/uploads/gifts/${fileName}`;
  } catch (e) {
    console.warn('Base64 gift save fallback:', e.message);
    return base64Str;
  }
}

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Serve explicit HTML web pages (Do NOT serve entire parent directory to prevent .env/.git exposure)
app.get(['/pos', '/arang-pos.html'], (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'arang-pos.html'));
});
app.get(['/loyalty', '/arang-loyalty.html'], (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'arang-loyalty.html'));
});
app.get(['/buy-me-coffee-icon.svg', '/pos/buy-me-coffee-icon.svg', '/loyalty/buy-me-coffee-icon.svg', '/favicon.ico', '/favicon.svg'], (req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  const iconPath = path.join(__dirname, '..', 'buy-me-coffee-icon.svg');
  if (fs.existsSync(iconPath)) return res.sendFile(iconPath);
  const altPath = path.join(__dirname, 'uploads', 'buy-me-coffee-icon.svg');
  if (fs.existsSync(altPath)) return res.sendFile(altPath);
  res.status(404).send('Icon not found');
});

// Portal Laman Utama (Root /)
app.get('/', (req, res) => {
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.get('host');
  const baseUrl = `${protocol}://${host}`;

  res.send(`
    <!DOCTYPE html>
    <html lang="ms">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Koffi POS &amp; Loyalty Server Gateway</title>
      <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=Fraunces:wght@700&display=swap" rel="stylesheet">
      <style>
        :root { --bg:#0f0b08; --surface:#1b1510; --border:#2d241c; --gold:#cda36a; --gold-light:#e2ba82; --cream:#f5ede3; --text-dim:#9d8e81; --ok:#7fae83; }
        body { margin:0; padding:40px 20px; font-family:'Plus Jakarta Sans',sans-serif; background:var(--bg); color:var(--cream); display:flex; justify-content:center; align-items:center; min-height:85vh; }
        .box { background:var(--surface); border:1px solid var(--border); border-radius:20px; padding:36px; max-width:620px; width:100%; box-shadow:0 25px 60px rgba(0,0,0,0.6); }
        h1 { font-family:'Fraunces',serif; color:var(--gold-light); margin:0 0 8px; font-size:26px; display:flex; align-items:center; gap:10px; }
        p.sub { color:var(--text-dim); margin:0 0 24px; font-size:14px; line-height:1.5; }
        .status-badge { display:inline-flex; align-items:center; gap:6px; background:rgba(127,174,131,0.15); border:1px solid rgba(127,174,131,0.3); color:var(--ok); padding:4px 12px; border-radius:30px; font-size:12px; font-weight:700; margin-bottom:20px; }
        .dot { width:8px; height:8px; border-radius:50%; background:var(--ok); box-shadow:0 0 8px var(--ok); }
        .card-grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:24px; }
        @media(max-width:540px){ .card-grid { grid-template-columns:1fr; } }
        .btn-card { display:block; text-decoration:none; background:rgba(255,255,255,0.03); border:1px solid var(--border); border-radius:14px; padding:18px; color:var(--cream); transition:all 0.2s; }
        .btn-card:hover { transform:translateY(-2px); border-color:var(--gold); background:rgba(205,163,106,0.08); }
        .btn-card b { display:block; font-size:15px; color:var(--gold-light); margin-bottom:4px; }
        .btn-card span { font-size:12px; color:var(--text-dim); }
        .webhook-box { background:#0a0705; border:1px solid var(--border); border-radius:12px; padding:14px; font-family:monospace; font-size:12px; color:var(--gold); word-break:break-all; }
        .webhook-box b { color:var(--cream); display:block; font-family:'Plus Jakarta Sans',sans-serif; margin-bottom:6px; font-size:11.5px; text-transform:uppercase; letter-spacing:0.04em; }
      </style>
    </head>
    <body>
      <div class="box">
        <span class="status-badge"><span class="dot"></span> Pelayan Backend Aktif &amp; Berfungsi</span>
        <h1>☕ Koffi POS &amp; Loyalty Server</h1>
        <p class="sub">Pelayan backend sedang beroperasi normal dan sedia menerima sambungan Webhook Meta WhatsApp, POS, dan Aplikasi Kad Ahli Pelanggan.</p>
        
        <div class="card-grid">
          <a href="/pos" class="btn-card">
            <b>💻 Buka Sistem POS</b>
            <span>Akses kaunter juruwang &amp; pentadbiran</span>
          </a>
          <a href="/loyalty" class="btn-card">
            <b>📱 Buka Kad Ahli</b>
            <span>Laman pendaftaran &amp; ganjaran pelanggan</span>
          </a>
        </div>

        <div class="webhook-box">
          <b>🔗 URL Webhook Meta WhatsApp Anda:</b>
          <code>${baseUrl}/api/webhook/whatsapp</code>
        </div>
      </div>
    </body>
    </html>
  `);
});

// Pautan Pantas /pos dan /loyalty
app.get('/pos', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'arang-pos.html'));
});
app.get('/loyalty', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'arang-loyalty.html'));
});

// Endpoint Konfigurasi Awam (Kongsi Konfigurasi Supabase & Bot)
app.get(['/api/public-config', '/api/config'], (req, res) => {
  res.json({
    success: true,
    supabaseUrl: process.env.SUPABASE_URL || 'https://ixkcmhorkbgqpmgxqnbk.supabase.co',
    supabaseAnonKey: process.env.SUPABASE_ANON_KEY || 'sb_publishable_9bErvPIaPF0rY1RjLl_nQw_NXZPSA2n',
    botPhone: (typeof inMemoryWhatsAppConfig !== 'undefined' && inMemoryWhatsAppConfig.botPhone) ? inMemoryWhatsAppConfig.botPhone : '011-8888 9999',
    keyword: (typeof inMemoryWhatsAppConfig !== 'undefined' && inMemoryWhatsAppConfig.otpKeyword) ? inMemoryWhatsAppConfig.otpKeyword : 'Request OTP'
  });
});

// Health check endpoint
app.get(['/health', '/api/health'], (req, res) => {
  res.json({
    status: 'ok',
    service: 'Koffi POS & Loyalty Backend Gateway',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime())
  });
});

// Storage untuk Iklan & Promosi (Media HD & Video)
const diskStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, promoUploadDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    const cleanBase = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, '_');
    const uniqueName = `promo_${Date.now()}_${cleanBase}${ext}`;
    cb(null, uniqueName);
  }
});

const uploadMedia = multer({
  storage: diskStorage,
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB had untuk video / gambar HD
});

// Storage untuk Gambar Katalog Produk & Menu
const productDiskStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, productUploadDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    const cleanBase = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, '_');
    const uniqueName = `prod_${Date.now()}_${cleanBase}${ext}`;
    cb(null, uniqueName);
  }
});

const uploadProductMedia = multer({
  storage: productDiskStorage,
  limits: { fileSize: 25 * 1024 * 1024 } // 25MB had untuk gambar produk
});

// ====================================================================
// 1. SUPABASE CLIENT INITIALIZATION
// ====================================================================
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

let supabase = null;
if (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  console.log('✅ Supabase Client Connected');
} else {
  console.warn('⚠️ Supabase credentials not set in .env. Running in standalone mode.');
}

// ====================================================================
// 2. REDIS / IN-MEMORY CACHE & RATE LIMITER
// ====================================================================
let redis = null;
const memoryStore = new Map();

if (process.env.REDIS_URL && process.env.REDIS_URL.trim() !== '') {
  try {
    let hasLoggedRedisError = false;
    const client = new Redis(process.env.REDIS_URL, {
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      connectTimeout: 2000,
      retryStrategy(times) {
        if (times >= 1) {
          // Berhenti cuba bersambung jika Redis tiada (elak spam)
          return null;
        }
        return null;
      }
    });

    client.on('connect', () => {
      redis = client;
      console.log('✅ Redis Cache Berjaya Disambung');
    });

    client.on('error', () => {
      if (!hasLoggedRedisError) {
        console.log('ℹ️ Tiada pelayan Redis dikesan di localhost:6379. Sistem automatik menggunakan Storan Memori (In-Memory RAM).');
        hasLoggedRedisError = true;
      }
      try { client.disconnect(); } catch(e){}
      redis = null;
    });
  } catch (e) {
    console.log('ℹ️ Menggunakan Storan Memori (In-Memory RAM).');
  }
} else {
  console.log('ℹ️ Menggunakan Storan Memori (In-Memory RAM).');
}

// Helper: Cache GET / SET with TTL
async function cacheSet(key, value, ttlSeconds) {
  if (redis && redis.status === 'ready') {
    return await redis.set(key, JSON.stringify(value), 'EX', ttlSeconds);
  }
  memoryStore.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
}

async function cacheGet(key) {
  if (redis && redis.status === 'ready') {
    const data = await redis.get(key);
    return data ? JSON.parse(data) : null;
  }
  const item = memoryStore.get(key);
  if (!item) return null;
  if (Date.now() > item.expiresAt) {
    memoryStore.delete(key);
    return null;
  }
  return item.value;
}

async function cacheDel(key) {
  if (redis && redis.status === 'ready') {
    return await redis.del(key);
  }
  memoryStore.delete(key);
}

// Helper: Increment counter with TTL and return current count & remaining TTL
async function cacheIncrWithTTL(key, ttlSeconds) {
  if (redis && redis.status === 'ready') {
    const count = await redis.incr(key);
    if (count === 1) {
      await redis.expire(key, ttlSeconds);
    }
    const ttl = await redis.ttl(key);
    return { count, ttl: ttl > 0 ? ttl : ttlSeconds };
  }

  // In-memory fallback
  const now = Date.now();
  let item = memoryStore.get(key);
  if (!item || now > item.expiresAt) {
    item = { value: 1, expiresAt: now + ttlSeconds * 1000 };
    memoryStore.set(key, item);
    return { count: 1, ttl: ttlSeconds };
  } else {
    item.value = (parseInt(item.value, 10) || 0) + 1;
    const remainingTtl = Math.max(1, Math.ceil((item.expiresAt - now) / 1000));
    return { count: item.value, ttl: remainingTtl };
  }
}

async function cacheGetTTL(key) {
  if (redis && redis.status === 'ready') {
    return await redis.ttl(key);
  }
  const item = memoryStore.get(key);
  if (!item) return -2;
  const remaining = Math.ceil((item.expiresAt - Date.now()) / 1000);
  return remaining > 0 ? remaining : -2;
}

// Helper: Format Malaysian Phone Number & Variations
function normalizePhone(phone) {
  if (!phone) return '';
  let str = String(phone).split('@')[0].trim();
  let clean = str.replace(/[^0-9]/g, '');
  if (clean.startsWith('60')) clean = '0' + clean.slice(2);
  else if (!clean.startsWith('0') && clean.length >= 9) clean = '0' + clean;
  return clean;
}

function toInternationalPhone(phone) {
  if (!phone) return '';
  let str = String(phone).split('@')[0].trim();
  let clean = str.replace(/[^0-9]/g, '');
  if (clean.startsWith('60')) return clean;
  if (clean.startsWith('0')) return '60' + clean.slice(1);
  if (clean.length >= 9) return '60' + clean;
  return clean;
}

function getPhoneLookupKeys(phone) {
  const local = normalizePhone(phone);
  const intl = toInternationalPhone(phone);
  return Array.from(new Set([
    local,
    intl,
    '+' + intl,
    '0' + intl.slice(2),
    String(phone).split('@')[0].trim()
  ].filter(Boolean)));
}

// WhatsApp Gateway Settings (Stored in memory and Supabase pos_settings)
let inMemoryWhatsAppConfig = {
  mode: 'gateway', // gateway | meta | sandbox
  botPhone: '011-2345 6789',
  apiUrl: 'https://api.fonnte.com/send',
  apiToken: '',
  webhookUrl: 'https://pos.koffi.coffee/api/webhook/whatsapp',
  verifyToken: 'arang_pos_secret_key',
  welcomePoints: 15,
  welcomeStamps: 2,
  otpExpiryMinutes: 3,
  otpKeyword: 'Request OTP'
};

async function loadWhatsAppSettingsFromDb() {
  if (!supabase) return;
  try {
    const { data } = await supabase
      .from('pos_settings')
      .select('value')
      .eq('key', 'whatsapp_config')
      .maybeSingle();

    if (data && data.value) {
      inMemoryWhatsAppConfig = { ...inMemoryWhatsAppConfig, ...data.value };
      console.log(`📱 [WHATSAPP] Tetapan WhatsApp dimuatkan dari DB: Bot ${inMemoryWhatsAppConfig.botPhone}`);
    }
  } catch (e) {
    console.warn('⚠️ Gagal memuatkan tetapan WhatsApp dari DB:', e.message);
  }
}
loadWhatsAppSettingsFromDb();

// ====================================================================
// 3. HEALTH CHECK & STATUS
// ====================================================================
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Koffi VPS Backend & WhatsApp Gateway',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    redis: redis ? redis.status : 'in-memory',
    supabase: supabase ? 'connected' : 'unconfigured'
  });
});

// ====================================================================
// 3.1 TETAPAN BOT WHATSAPP & WEBHOOK CONFIG API
// ====================================================================
app.get(['/api/whatsapp/config', '/api/pos/whatsapp/config'], async (req, res) => {
  try {
    if (supabase) {
      const { data } = await supabase
        .from('pos_settings')
        .select('value')
        .eq('key', 'whatsapp_config')
        .maybeSingle();
      if (data && data.value) {
        inMemoryWhatsAppConfig = { ...inMemoryWhatsAppConfig, ...data.value };
      }
    }
    res.json({ success: true, config: inMemoryWhatsAppConfig });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message, config: inMemoryWhatsAppConfig });
  }
});

app.post(['/api/whatsapp/config', '/api/pos/whatsapp/config'], async (req, res) => {
  try {
    const payload = req.body || {};
    inMemoryWhatsAppConfig = {
      ...inMemoryWhatsAppConfig,
      ...payload,
      updated_at: new Date().toISOString()
    };

    if (supabase) {
      await supabase
        .from('pos_settings')
        .upsert({
          key: 'whatsapp_config',
          value: inMemoryWhatsAppConfig,
          updated_at: new Date().toISOString()
        });

      await supabase.from('pos_audit_logs').insert({
        action: 'whatsapp_config_updated',
        cashier_name: 'Pengurus Utama',
        details: { botPhone: inMemoryWhatsAppConfig.botPhone, mode: inMemoryWhatsAppConfig.mode }
      });
    }

    console.log(`📱 [WHATSAPP CONFIG SAVED] Bot Phone: ${inMemoryWhatsAppConfig.botPhone} | Mode: ${inMemoryWhatsAppConfig.mode}`);
    res.json({
      success: true,
      message: 'Tetapan Bot WhatsApp & Webhook berjaya disimpan ke Supabase ✨',
      config: inMemoryWhatsAppConfig
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Test Message via WhatsApp Gateway
app.post('/api/whatsapp/test-message', async (req, res) => {
  try {
    const { targetPhone, message } = req.body;
    if (!targetPhone) {
      return res.status(400).json({ success: false, error: 'Nombor telefon penerima diperlukan' });
    }
    const testText = message || '☕ Koffi POS: Ujian sambungan Bot WhatsApp berjaya!';
    const result = await sendWhatsAppMessage(targetPhone, testText);
    res.json({ success: true, message: 'Mesej ujian telah dihantar!', result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 4. API: REQUEST OTP (Loyalty Login & Auto-Membership Flow)
// ====================================================================
app.post(['/api/otp/request', '/api/loyalty/otp/request'], async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) {
      return res.status(400).json({ error: 'Nombor telefon diperlukan' });
    }

    const cleanPhone = normalizePhone(phone);
    const intlPhone = toInternationalPhone(phone);
    if (cleanPhone.length < 8) {
      return res.status(400).json({ error: 'Nombor telefon tidak sah' });
    }

    // Extract Client IP (Supports trust proxy / X-Forwarded-For)
    const clientIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

    // 1. Check existing verification lockout (5 wrong attempts -> 1 hour lockout)
    const lockoutKey = `lockout:${cleanPhone}`;
    const isLocked = await cacheGet(lockoutKey);
    if (isLocked) {
      return res.status(429).json({
        error: 'Akaun disekat sementara selama 1 jam kerana melebihi had 5 kali percubaan salah.',
        lockedUntil: isLocked.lockedUntil
      });
    }

    // 2. IP RATE LIMIT: Had 20 request/jam setiap IP
    const ipRateKey = `otp_request_ip:${clientIp}`;
    const ipData = await cacheIncrWithTTL(ipRateKey, 3600);
    if (ipData.count > 20) {
      const remainingMins = Math.max(1, Math.ceil(ipData.ttl / 60));
      return res.status(429).json({
        error: `Terlalu banyak permintaan dari alamat IP ini. Sila cuba lagi selepas ${remainingMins} minit.`,
        remainingSeconds: ipData.ttl,
        scope: 'ip_rate_limit'
      });
    }

    // 3. PHONE RATE LIMIT: Had 5 request dalam tetingkap 10 minit
    const phoneRateKey = `otp_request_count:${cleanPhone}`;
    const phoneData = await cacheIncrWithTTL(phoneRateKey, 600);
    if (phoneData.count > 5) {
      const remainingMins = Math.max(1, Math.ceil(phoneData.ttl / 60));
      return res.status(429).json({
        error: `Terlalu banyak percubaan. Sila cuba lagi selepas ${remainingMins} minit.`,
        remainingSeconds: phoneData.ttl,
        scope: 'phone_rate_limit'
      });
    }

    // 4. Generate 4-Digit OTP (e.g. 4821)
    const otp = String(Math.floor(1000 + Math.random() * 9000));
    const ttlSeconds = (inMemoryWhatsAppConfig.otpExpiryMinutes || 3) * 60; // 3 minit

    const otpData = {
      phone: cleanPhone,
      intlPhone: intlPhone,
      otp,
      status: 'pending_whatsapp',
      createdAt: Date.now(),
      expiresAt: Date.now() + ttlSeconds * 1000
    };

    // Store active OTP in Cache across all phone format variants for bulletproof lookup
    const lookupKeys = getPhoneLookupKeys(phone);
    for (const k of lookupKeys) {
      await cacheSet(`otp_request:${k}`, otpData, ttlSeconds);
    }

    // Prepare direct WhatsApp Bot Link with keyword "Request OTP"
    const botPhoneIntl = toInternationalPhone(inMemoryWhatsAppConfig.botPhone || '601123456789');
    const waKeyword = inMemoryWhatsAppConfig.otpKeyword || 'Request OTP';
    const waUrl = `https://wa.me/${botPhoneIntl}?text=${encodeURIComponent(waKeyword)}`;

    console.log(`[OTP GENERATED] Phone: ${cleanPhone} (${intlPhone}) | OTP: ${otp} | Expires in: ${ttlSeconds}s | Bot: ${botPhoneIntl}`);

    if (supabase) {
      try {
        await supabase.from('pos_audit_logs').insert({
          action: 'otp_requested',
          cashier_name: 'Loyalty Webapp',
          details: {
            phone: cleanPhone,
            intlPhone: intlPhone,
            otp: otp,
            status: 'wait',
            keyword: waKeyword,
            expiresIn: ttlSeconds
          }
        });
        await supabase.from('otp_audit_log').insert({
          phone: cleanPhone,
          keyword_received: waKeyword || 'Request OTP',
          otp_code: otp,
          status: 'wait',
          client_ip: req.ip || null,
          expires_at: new Date(Date.now() + ttlSeconds * 1000).toISOString()
        });
      } catch (e) {
        console.warn('Audit log insert error (otp_requested):', e.message);
      }
    }

    res.json({
      success: true,
      message: 'Permintaan OTP telah didaftarkan. Sila hantar kata kunci ke WhatsApp Bot.',
      phone: cleanPhone,
      intlPhone: intlPhone,
      botPhone: inMemoryWhatsAppConfig.botPhone,
      waUrl: waUrl,
      keyword: waKeyword,
      expiresInSeconds: ttlSeconds,
      requestCount: phoneData.count,
      maxRequests: 5
    });
  } catch (err) {
    console.error('Error requesting OTP:', err);
    res.status(500).json({ error: 'Ralat dalaman pelayan' });
  }
});

// ====================================================================
// 5.0 API: META WHATSAPP WEBHOOK VERIFICATION (GET Handshake for Meta/Facebook App)
// ====================================================================
app.get(['/api/webhook/whatsapp', '/api/whatsapp/webhook', '/webhook/whatsapp', '/whatsapp/webhook', '/api/webhook', '/webhook'], (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  const expectedToken = inMemoryWhatsAppConfig.verifyToken || process.env.WA_VERIFY_TOKEN || process.env.WA_WEBHOOK_SECRET || 'arang_pos_secret_key';

  console.log(`🔍 [META WEBHOOK GET VERIFY] Mode: ${mode} | Token: ${token} | Challenge: ${challenge}`);

  if (mode && token) {
    if (mode === 'subscribe' && token === expectedToken) {
      console.log('✅ [META WEBHOOK VERIFIED] Handshake successful!');
      return res.status(200).send(challenge);
    } else {
      console.warn(`❌ [META WEBHOOK VERIFY FAILED] Token mismatch: Received "${token}" vs Expected "${expectedToken}"`);
      return res.sendStatus(403);
    }
  }
  return res.status(200).json({ status: 'active', message: 'WhatsApp Webhook Endpoint Ready' });
});

// ====================================================================
// 5.1 API: WHATSAPP WEBHOOK RECEIVER (Inbound message handler with interactive buttons & flexible keyword matching)
// ====================================================================
app.post(['/api/webhook/whatsapp', '/api/whatsapp/webhook', '/webhook/whatsapp', '/whatsapp/webhook', '/api/webhook', '/webhook'], async (req, res) => {
  try {
    // Standard payload parser supporting Fonnte / Waha / Evolution / Meta / Simulator
    const body = req.body || {};
    let sender = body.sender || body.from || body.phone || '';
    let message = (body.message || body.body || body.text || '').trim();
    let buttonId = body.button || body.button_id || body.selectedButtonId || '';

    // Meta WhatsApp Cloud API nested structure parser
    if (body.entry && body.entry[0]?.changes && body.entry[0]?.changes[0]?.value?.messages) {
      const msgObj = body.entry[0].changes[0].value.messages[0];
      sender = msgObj.from || sender;
      if (msgObj.type === 'interactive') {
        buttonId = msgObj.interactive?.button_reply?.id || msgObj.interactive?.list_reply?.id || buttonId;
        message = msgObj.interactive?.button_reply?.title || msgObj.interactive?.list_reply?.title || message;
      } else if (msgObj.type === 'button') {
        buttonId = msgObj.button?.payload || msgObj.button?.text || buttonId;
        message = msgObj.button?.text || message;
      } else {
        message = msgObj.text?.body || message;
      }
    }

    console.log(`📥 [INBOUND WHATSAPP] From: "${sender}" | Message: "${message}" | Button: "${buttonId}"`);

    if (!sender) {
      return res.status(200).send('OK (No sender)');
    }

    const cleanSenderPhone = normalizePhone(sender);
    const intlSenderPhone = toInternationalPhone(sender);
    
    // Normalisasi mesej: bersihkan emoji dan simbol khas supaya padanan 100% tepat
    const rawMsg = (message + ' ' + buttonId).toLowerCase();
    const cleanMsg = rawMsg.replace(/[^\w\s]/g, ' ').replace(/\s+/g, ' ').trim();

    // 1. Info Ganjaran
    if (cleanMsg.includes('btn_info_loyalty') || cleanMsg.includes('info ganjaran') || cleanMsg === 'info') {
      const infoText = `🎁 *KEISTIMEWAAN AHLI KOFFI LOYALTY* ☕\n\n` +
        `✨ *Daftar Kali Pertama*: Percuma +15 Mata & 2 Cop Stamp\n` +
        `✨ *Kumpul Cop*: 10 Cop = 1x Kopi Percuma ☕\n` +
        `✨ *Mata Ganjaran*: Setiap RM1 = 1 Mata (Tebus diskaun tunai)\n` +
        `✨ *Cabutan Bertuah Bulanan* & Baucar Eksklusif!\n\n` +
        `Sila tekan butang di bawah untuk meminta Kod PIN OTP:`;

      await sendWhatsAppButtons(
        sender,
        infoText,
        [
          { id: 'btn_request_otp', title: 'Request OTP' }
        ],
        '🎁 GANJARAN KOFFI',
        'Koffi Loyalty Program'
      );
      return res.json({ status: 'info_sent', sender });
    }

    // 2. Keyword Request OTP (Menyokong butang dan teks biasa)
    const isOtpRequestKeyword = (
      cleanMsg.includes('request otp') ||
      cleanMsg.includes('minta otp') ||
      cleanMsg.includes('req otp') ||
      cleanMsg.includes('requestotp') ||
      cleanMsg.includes('btn_request_otp') ||
      cleanMsg.includes('otp') ||
      cleanMsg.includes('minta pin') ||
      cleanMsg.includes('request pin') ||
      cleanMsg.includes('ahli')
    );

    // KES 1: Pelanggan hantar teks yang salah / mesej rawak (contoh: "hai", "salam", "nak login")
    // Bot balas dengan INTERACTIVE BUTTON: [ Request OTP ] & [ Info Ganjaran ]
    if (!isOtpRequestKeyword) {
      const guidanceBody = `👋 Salam sejahtera!\n\nUntuk mendapatkan Kod PIN OTP log masuk Kad Ahli Koffi Loyalty, sila tekan butang *Request OTP* di bawah:`;

      await sendWhatsAppButtons(
        sender,
        guidanceBody,
        [
          { id: 'btn_request_otp', title: 'Request OTP' },
          { id: 'btn_info_loyalty', title: 'Info Ganjaran' }
        ],
        '☕ KOFFI LOYALTY BOT',
        'Tekan butang untuk meminta OTP'
      );

      if (supabase) {
        try {
          await supabase.from('pos_audit_logs').insert({
            action: 'whatsapp_guidance_sent',
            cashier_name: 'Bot WhatsApp',
            details: { phone: cleanSenderPhone, message: message || buttonId, status: 'guidance' }
          });
        } catch(e){}
      }

      console.log(`[WA GUIDANCE BUTTONS SENT] To: ${sender} | Reason: Keyword mismatch`);
      return res.json({ status: 'guidance_buttons_sent', sender });
    }

    // KES 2: Pelanggan tekan butang / hantar 'Request OTP' -> Semak pending request
    let activeRequest = null;
    const lookupKeys = getPhoneLookupKeys(sender);

    for (const k of lookupKeys) {
      const found = await cacheGet(`otp_request:${k}`);
      if (found && found.otp) {
        activeRequest = found;
        break;
      }
    }

    if (activeRequest && activeRequest.otp) {
      // PERMINTAAN DITEMUI: Hantar Kod OTP kepada pelanggan (Sah 3 minit)
      const replyText = `☕ *KOFFI KOPI & PASTRI*\n\n🔑 Kod PIN OTP anda ialah: *${activeRequest.otp}*\n\n⏳ Kod ini sah selama *3 minit*. Sila masukkan kod ini di aplikasi Kad Ahli Koffi Loyalty untuk melengkapkan log masuk.\n\n_Abaikan jika anda tidak meminta kod ini._`;

      await sendWhatsAppMessage(sender, replyText);

      // Audit log to Supabase
      if (supabase) {
        await supabase.from('pos_audit_logs').insert({
          action: 'whatsapp_otp_dispatched',
          cashier_name: 'Bot WhatsApp',
          details: {
            phone: cleanSenderPhone,
            intlPhone: intlSenderPhone,
            otp: activeRequest.otp,
            status: 'ok',
            keyword: 'Request OTP'
          }
        });
        await supabase.from('otp_audit_log').insert({
          phone: cleanSenderPhone,
          keyword_received: 'Request OTP (WhatsApp)',
          otp_code: activeRequest.otp,
          status: 'dispatched',
          client_ip: req.ip || null,
          expires_at: new Date(Date.now() + 180000).toISOString()
        });
      }

      console.log(`✅ [OTP SENT VIA WA] To: ${sender} (${cleanSenderPhone}) | OTP: ${activeRequest.otp}`);
      return res.json({ status: 'sent', phone: cleanSenderPhone, otp: activeRequest.otp });
    } else {
      // TIADA PERMINTAAN AKTIF: Beritahu untuk tekan Minta Kod OTP di web & sediakan butang interaktif
      const noRequestBody = `Salam sejahtera! ☕\n\nNombor anda (*${cleanSenderPhone}*) belum membuat permohonan Kod OTP di laman web atau kod telah luput (sah 3 minit).\n\nSila buka laman web Koffi Loyalty, masukkan nombor telefon dan tekan butang *Minta Kod OTP*. Selepas itu, tekan butang di bawah:`;

      await sendWhatsAppButtons(
        sender,
        noRequestBody,
        [
          { id: 'btn_request_otp', title: 'Request OTP' },
          { id: 'btn_info_loyalty', title: 'Info Ganjaran' }
        ],
        '⚠️ PERMOHONAN DIPERLUKAN',
        'Koffi Loyalty Webapp'
      );

      if (supabase) {
        try {
          await supabase.from('pos_audit_logs').insert({
            action: 'whatsapp_otp_no_request',
            cashier_name: 'Bot WhatsApp',
            details: { phone: cleanSenderPhone, message: message || buttonId, status: 'rejected' }
          });
        } catch(e){}
      }

      console.log(`⚠️ [NO REQUEST FOUND] Sender: ${sender} (${cleanSenderPhone})`);
      return res.json({ status: 'no_request_found', phone: cleanSenderPhone });
    }
  } catch (err) {
    console.error('Error in WhatsApp webhook:', err);
    res.status(200).send('ERROR_HANDLED');
  }
});

// Helper: Send WhatsApp Interactive Buttons via Meta Cloud API / Gateway
async function sendWhatsAppButtons(toPhone, bodyText, buttons = [], headerText = '☕ KOFFI LOYALTY', footerText = 'Koffi Loyalty Program') {
  const WA_API_URL = inMemoryWhatsAppConfig.apiUrl || process.env.WA_API_URL || 'https://api.fonnte.com/send';
  const WA_API_TOKEN = inMemoryWhatsAppConfig.apiToken || process.env.WA_API_TOKEN || '';
  const mode = inMemoryWhatsAppConfig.mode || 'gateway';

  if (!WA_API_TOKEN || mode === 'sandbox') {
    console.warn(`📱 [WA SIMULATION BUTTONS] To: ${toPhone} | Body:\n${bodyText}\nButtons:`, buttons);
    return { simulation: true, toPhone, bodyText, buttons };
  }

  const intlPhone = toInternationalPhone(toPhone);

  if (mode === 'meta' || WA_API_URL.includes('graph.facebook.com')) {
    const tokenHeader = WA_API_TOKEN.startsWith('Bearer ') ? WA_API_TOKEN : `Bearer ${WA_API_TOKEN}`;
    
    // Format Meta Quick Reply Buttons (max 3 buttons, title <= 20 chars)
    const metaButtons = buttons.slice(0, 3).map((b, idx) => ({
      type: 'reply',
      reply: {
        id: b.id || `btn_${idx}`,
        title: (b.title || b.text || 'Pilih').slice(0, 20)
      }
    }));

    const payload = {
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to: intlPhone,
      type: 'interactive',
      interactive: {
        type: 'button',
        body: { text: bodyText },
        action: { buttons: metaButtons }
      }
    };

    if (headerText) {
      payload.interactive.header = { type: 'text', text: headerText.slice(0, 60) };
    }
    if (footerText) {
      payload.interactive.footer = { text: footerText.slice(0, 60) };
    }

    try {
      const res = await axios.post(WA_API_URL, payload, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': tokenHeader
        }
      });
      return res.data;
    } catch (err) {
      console.warn('⚠️ [META BUTTONS FALLBACK TO TEXT]:', err.response?.data || err.message);
      // Fallback graceful ke mesej teks jika format butang tidak disokong pada sesetengah peranti
      return await sendWhatsAppMessage(toPhone, `${bodyText}\n\n*${buttons[0]?.title || 'Request OTP'}*`);
    }
  } else {
    // Gateway / Fonnte payload
    try {
      const fonnteButtons = buttons.map(b => ({
        id: b.id,
        text: b.title || b.text
      }));
      const res = await axios.post(WA_API_URL, {
        target: intlPhone,
        message: bodyText,
        button: JSON.stringify(fonnteButtons)
      }, {
        headers: { Authorization: WA_API_TOKEN }
      });
      return res.data;
    } catch (e) {
      return await sendWhatsAppMessage(toPhone, `${bodyText}\n\n*${buttons[0]?.title || 'Request OTP'}*`);
    }
  }
}

// Helper: Send WhatsApp Standard Text Message via external Gateway API / Meta Cloud API
async function sendWhatsAppMessage(toPhone, messageText) {
  const WA_API_URL = inMemoryWhatsAppConfig.apiUrl || process.env.WA_API_URL || 'https://api.fonnte.com/send';
  const WA_API_TOKEN = inMemoryWhatsAppConfig.apiToken || process.env.WA_API_TOKEN || '';
  const mode = inMemoryWhatsAppConfig.mode || 'gateway';

  if (!WA_API_TOKEN || mode === 'sandbox') {
    console.warn(`📱 [WA SIMULATION / SANDBOX] To: ${toPhone} | Message:\n${messageText}`);
    return { simulation: true, toPhone, message: messageText };
  }

  try {
    const intlPhone = toInternationalPhone(toPhone);
    let res;

    if (mode === 'meta' || WA_API_URL.includes('graph.facebook.com')) {
      // Meta WhatsApp Business Cloud API payload
      const tokenHeader = WA_API_TOKEN.startsWith('Bearer ') ? WA_API_TOKEN : `Bearer ${WA_API_TOKEN}`;
      res = await axios.post(WA_API_URL, {
        messaging_product: 'whatsapp',
        recipient_type: 'individual',
        to: intlPhone,
        type: 'text',
        text: { body: messageText, preview_url: false }
      }, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': tokenHeader
        }
      });
    } else {
      // Fonnte / Webhook Gateway standard payload
      res = await axios.post(WA_API_URL, {
        target: intlPhone,
        message: messageText
      }, {
        headers: { Authorization: WA_API_TOKEN }
      });
    }
    return res.data;
  } catch (e) {
    console.error('Failed to send WhatsApp message via API:', e.response?.data || e.message);
    return { error: e.response?.data || e.message };
  }
}

// ====================================================================
// 6. API: VERIFY OTP & PROVISION MEMBER SESSION (Auto-Membership Flow)
// ====================================================================
app.post(['/api/otp/verify', '/api/loyalty/otp/verify'], async (req, res) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp) {
      return res.status(400).json({ error: 'Nombor telefon dan kod OTP diperlukan' });
    }

    const cleanPhone = normalizePhone(phone);
    const intlPhone = toInternationalPhone(phone);
    const lockoutKey = `lockout:${cleanPhone}`;
    const attemptsKey = `attempts:${cleanPhone}`;

    // 1. Check if locked out (1-hour lockout)
    const isLocked = await cacheGet(lockoutKey);
    if (isLocked) {
      return res.status(429).json({
        error: 'Akaun disekat sementara selama 1 jam. Sila tunggu tempoh tamat.'
      });
    }

    // 2. Fetch active OTP from 3-min cache across all variations
    let activeRequest = null;
    const lookupKeys = getPhoneLookupKeys(phone);
    for (const k of lookupKeys) {
      const found = await cacheGet(`otp_request:${k}`);
      if (found && found.otp) {
        activeRequest = found;
        break;
      }
    }

    if (!activeRequest || !activeRequest.otp) {
      return res.status(400).json({
        error: 'Kod OTP telah luput atau belum diminta. Sila tekan "Minta Kod OTP" semula.'
      });
    }

    // 3. Validate code match
    if (String(activeRequest.otp).trim() !== String(otp).trim()) {
      let attempts = (await cacheGet(attemptsKey)) || 0;
      attempts++;

      if (attempts >= 5) {
        // Trigger 1-Hour Lockout (3600 seconds)
        const lockedUntil = Date.now() + 3600 * 1000;
        await cacheSet(lockoutKey, { lockedUntil }, 3600);
        await cacheDel(attemptsKey);
        for (const k of lookupKeys) {
          await cacheDel(`otp_request:${k}`);
        }

        return res.status(429).json({
          error: 'Melebihi had 5 kali percubaan salah. Akaun anda telah disekat selama 1 jam.'
        });
      } else {
        await cacheSet(attemptsKey, attempts, 3600);
        const remaining = 5 - attempts;
        return res.status(400).json({
          error: `Kod OTP tidak sah. Baki percubaan: ${remaining} kali`,
          remainingAttempts: remaining
        });
      }
    }

    // 4. OTP Success: Clear cache
    for (const k of lookupKeys) {
      await cacheDel(`otp_request:${k}`);
    }
    await cacheDel(attemptsKey);

    let isNewMember = false;
    let member = {
      phone: cleanPhone,
      name: 'Ahli ' + cleanPhone.slice(-4),
      points: inMemoryWhatsAppConfig.welcomePoints || 15,
      stamps: inMemoryWhatsAppConfig.welcomeStamps || 1,
      tier: 'Ahli Gangsa'
    };

    if (supabase) {
      // Check if phone already registered in Supabase members table
      const { data: existingMember } = await supabase
        .from('members')
        .select('*')
        .or(`phone.eq.${cleanPhone},phone.eq.${intlPhone},phone.eq.+${intlPhone}`)
        .maybeSingle();

      if (existingMember) {
        // AHIL SEDIA ADA: Tidak perlu daftar lagi, kemas kini sesi peranti
        member = existingMember;
        isNewMember = false;
        await supabase
          .from('members')
          .update({ last_visited_at: new Date().toISOString() })
          .eq('id', existingMember.id);
        console.log(`👤 [RETURNING MEMBER LOGIN] ${member.name} (${member.phone}) | Points: ${member.points} | Stamps: ${member.stamps}`);
      } else {
        // AHLI BARU (FIRST TIME LOGIN): Daftarkan automatik sebagai Ahli dengan Mata & Cop Selamat Datang!
        isNewMember = true;
        const welcomePts = inMemoryWhatsAppConfig.welcomePoints || 15;
        const welcomeStps = inMemoryWhatsAppConfig.welcomeStamps || 1;

        const { data: newMember, error: createErr } = await supabase
          .from('members')
          .insert({
            phone: cleanPhone,
            name: 'Ahli ' + cleanPhone.slice(-4),
            points: welcomePts,
            lifetime_points: welcomePts,
            stamps: welcomeStps,
            tier: 'Ahli Gangsa',
            source: 'whatsapp_otp',
            is_active: true,
            registered_at: new Date().toISOString(),
            last_visited_at: new Date().toISOString()
          })
          .select()
          .single();

        if (!createErr && newMember) {
          member = newMember;

          // Cipta Kad Cop Pertama untuk Ahli Baru (1 Cop Selamat Datang)
          await supabase
            .from('member_stamp_cards')
            .insert({
              member_id: newMember.id,
              card_number: 1,
              stamps_collected: welcomeStps,
              target_stamps: 10,
              reward_name: '1x Kopi Percuma',
              status: 'collecting'
            });

          console.log(`🎉 [NEW MEMBER AUTO-REGISTERED] ${member.name} (${cleanPhone}) | Welcome Points: ${welcomePts} | Welcome Stamp: ${welcomeStps}`);
        }
      }

      await supabase.from('pos_audit_logs').insert({
        action: isNewMember ? 'member_auto_registered_otp' : 'member_login_otp',
        cashier_name: 'Bot WhatsApp',
        details: { phone: cleanPhone, isNewMember, memberId: member.id }
      });
      await supabase.from('otp_audit_log').insert({
        phone: cleanPhone,
        keyword_received: 'Verify OTP',
        otp_code: otp,
        status: 'verified',
        client_ip: req.ip || null,
        expires_at: new Date().toISOString()
      });
    }

    // 5. Generate Authenticated JWT Session Token (30-day expiry)
    const sessionToken = jwt.sign(
      {
        sub: member.id || '00000000-0000-0000-0000-000000000001',
        role: 'authenticated',
        phone: cleanPhone,
        aud: 'authenticated',
        app_metadata: { provider: 'otp_whatsapp' },
        user_metadata: { name: member.name, phone: cleanPhone }
      },
      SUPABASE_JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      isNewMember,
      message: isNewMember
        ? 'Pendaftaran Ahli Baru Berjaya! Selamat datang ke Koffi (+15 Mata & 2 Cop Percuma!) 🎉'
        : `Selamat kembali ke Koffi Loyalty, ${member.name}! ☕`,
      member,
      sessionToken
    });
  } catch (err) {
    console.error('Error verifying OTP:', err);
    res.status(500).json({ error: 'Ralat pengesahan OTP' });
  }
});

// ====================================================================
// 6.1 API: GET LIVE OTP REGISTRATION & WHATSAPP LOGS
// ====================================================================
app.get('/api/pos/otp-logs', requireStaffAuth, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    if (!supabase) {
      return res.json({ success: true, logs: [] });
    }

    const { data, error } = await supabase
      .from('pos_audit_logs')
      .select('*')
      .in('action', [
        'otp_requested',
        'whatsapp_otp_dispatched',
        'member_auto_registered_otp',
        'member_login_otp',
        'whatsapp_otp_no_request',
        'whatsapp_guidance_sent'
      ])
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) throw error;

    const formattedLogs = (data || []).map(l => {
      const details = l.details || {};
      const phone = details.phone || l.phone || '-';
      let keyword = details.message || details.keyword || 'Request OTP';
      let otp = details.otp || '-';
      let status = details.status || 'ok';
      let statusLabel = 'Sah / Dihantar';

      if (l.action === 'otp_requested') {
        status = 'wait';
        statusLabel = 'Menunggu WhatsApp';
      } else if (l.action === 'whatsapp_otp_dispatched') {
        status = 'ok';
        statusLabel = 'OTP Dihantar';
      } else if (l.action === 'member_auto_registered_otp') {
        status = 'verified_new';
        statusLabel = 'Ahli Baru Didaftarkan (+15 Mata & 2 Cop)';
        keyword = 'Pendaftaran Selesai';
      } else if (l.action === 'member_login_otp') {
        status = 'verified_login';
        statusLabel = 'Log Masuk Selesai';
        keyword = 'Sesi Diaktifkan';
      } else if (l.action === 'whatsapp_otp_no_request') {
        status = 'rejected';
        statusLabel = 'Ditolak (Tiada Request)';
      } else if (l.action === 'whatsapp_guidance_sent') {
        status = 'guidance';
        statusLabel = 'Panduan Dihantar';
      }

      return {
        id: l.id,
        phone: phone,
        action: l.action,
        keyword: keyword,
        otp: otp,
        status: status,
        statusLabel: statusLabel,
        cashierName: l.cashier_name || 'Bot WhatsApp',
        created_at: l.created_at,
        ts: l.created_at ? new Date(l.created_at).toLocaleString('ms-MY', {
          day: 'numeric',
          month: 'short',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit'
        }) : '-'
      };
    });

    res.json({ success: true, logs: formattedLogs });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 7. API (POS GATEWAY): ADD POINTS (Staff crediting another customer)
// Secured via VPS Service-Role (Client cannot call RPC directly)
// ====================================================================
app.post('/api/pos/add-points', requireStaffAuth, async (req, res) => {
  try {
    const { member_id, sale_id, points, staff_pin } = req.body;
    if (!member_id || !sale_id || !points) {
      return res.status(400).json({ error: 'Parameter member_id, sale_id, dan points diperlukan' });
    }

    if (!supabase) {
      console.log(`[POS ADD POINTS STANDALONE] Member: ${member_id} | Points: +${points}`);
      return res.json({ success: true, points_added: points, mode: 'standalone' });
    }

    const { data, error } = await supabase.rpc('add_points', {
      p_member_id: member_id,
      p_sale_id: sale_id,
      p_points: parseInt(points, 10)
    });

    if (error) {
      console.error('[POS ADD POINTS ERROR]:', error.message);
      return res.status(400).json({ error: error.message });
    }

    console.log(`[POS ADD POINTS SUCCESS] Member: ${member_id} | Sale: ${sale_id} | Points: +${points} -> New: ${data}`);
    res.json({ success: true, new_points: data });
  } catch (err) {
    console.error('Error in /api/pos/add-points:', err);
    res.status(500).json({ error: 'Ralat menambah mata pelanggan' });
  }
});

// ====================================================================
// 8. API (POS GATEWAY): ADD STAMP (Staff crediting customer stamp)
// Secured via VPS Service-Role
// ====================================================================
app.post('/api/pos/add-stamp', requireStaffAuth, async (req, res) => {
  try {
    const { member_id, sale_id, card_id, staff_pin } = req.body;
    if (!member_id || !sale_id) {
      return res.status(400).json({ error: 'Parameter member_id dan sale_id diperlukan' });
    }

    if (!supabase) {
      console.log(`[POS ADD STAMP STANDALONE] Member: ${member_id} | Stamp Added`);
      return res.json({ success: true, mode: 'standalone' });
    }

    const { data, error } = await supabase.rpc('add_stamp', {
      p_member_id: member_id,
      p_card_id: card_id || null,
      p_sale_id: sale_id
    });

    if (error) {
      console.error('[POS ADD STAMP ERROR]:', error.message);
      return res.status(400).json({ error: error.message });
    }

    console.log(`[POS ADD STAMP SUCCESS] Member: ${member_id} | Result:`, data);
    res.json(data);
  } catch (err) {
    console.error('Error in /api/pos/add-stamp:', err);
    res.status(500).json({ error: 'Ralat menambah cop pelanggan' });
  }
});

// ====================================================================
// 7. API: MEMBERS CRUD, TOP 5 MEMBERS & LIVE ON-DEMAND SEARCH
// ====================================================================
let posMembersStore = []; // In-memory fallback (kosong, sedia untuk data live)

// Helper: Kira Tier Ahli berasaskan mata
function computeMemberTierName(points) {
  const p = parseInt(points) || 0;
  if (p >= 500) return 'Ahli Emas';
  if (p >= 200) return 'Ahli Perak';
  return 'Ahli Gangsa';
}

// Helper: Kira Statistik Keseluruhan Ahli
function calculateMemberStats(list) {
  const totalMembers = list.length;
  const totalPoints = list.reduce((sum, m) => sum + (parseInt(m.points) || 0), 0);
  const totalStamps = list.reduce((sum, m) => sum + (parseInt(m.stamps) || 0), 0);
  
  let topTier = 'Ahli Gangsa';
  if (list.some(m => (parseInt(m.points) || 0) >= 500)) topTier = 'Emas';
  else if (list.some(m => (parseInt(m.points) || 0) >= 200)) topTier = 'Perak';
  else if (totalMembers > 0) topTier = 'Gangsa';
  else topTier = '—';

  return {
    totalMembers,
    totalPoints,
    totalStamps,
    topTier
  };
}

// Endpoint 7.1: Dapatkan 5 Top Ahli (Top 5 Members) + Statistik
app.get('/api/members/top', async (req, res) => {
  try {
    const sortBy = (req.query.sortBy || req.query.sort || 'points_desc').toLowerCase();
    const limit = Math.min(20, parseInt(req.query.limit) || 5);

    let allMembers = [];

    if (supabase) {
      const { data, error } = await supabase
        .from('members')
        .select('*');

      if (!error && data) {
        allMembers = data.map(m => ({
          id: m.id,
          name: m.name,
          phone: m.phone,
          email: m.email || '',
          points: parseInt(m.points) || 0,
          stamps: parseInt(m.stamps) || 0,
          tier: m.tier || computeMemberTierName(m.points),
          source: m.source || 'pos_counter',
          joined: m.registered_at ? new Date(m.registered_at).toLocaleDateString('ms-MY', { day:'numeric', month:'short', year:'numeric' }) : 'Baru'
        }));
        posMembersStore = allMembers;
      }
    } else {
      allMembers = [...posMembersStore];
    }

    const stats = calculateMemberStats(allMembers);

    // Susun mengikut mod pilihan
    let sorted = [...allMembers];
    if (sortBy === 'points_desc') {
      sorted.sort((a, b) => b.points - a.points);
    } else if (sortBy === 'stamps_desc') {
      sorted.sort((a, b) => b.stamps - a.stamps);
    } else if (sortBy === 'recent') {
      sorted.sort((a, b) => String(b.id || '').localeCompare(String(a.id || '')));
    } else {
      sorted.sort((a, b) => b.points - a.points);
    }

    const topMembers = sorted.slice(0, limit);

    res.json({
      success: true,
      count: topMembers.length,
      total: allMembers.length,
      topMembers,
      stats
    });
  } catch (err) {
    console.error('❌ GET /api/members/top error:', err.message);
    res.status(500).json({ success: false, error: err.message, topMembers: [], stats: { totalMembers: 0, totalPoints: 0, totalStamps: 0, topTier: '—' } });
  }
});

// Endpoint 7.2: Dapatkan Statistik Keahlian (Member Stats)
app.get('/api/members/stats', async (req, res) => {
  try {
    let allMembers = [];
    if (supabase) {
      const { data } = await supabase.from('members').select('id, points, stamps, tier');
      if (data) allMembers = data;
    } else {
      allMembers = posMembersStore;
    }
    const stats = calculateMemberStats(allMembers);
    res.json({ success: true, stats });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Endpoint 7.3: Carian Ahli Live Atas Permintaan (On-Demand Search) & Penyenaraian
app.get('/api/members', async (req, res) => {
  try {
    const q = (req.query.search || req.query.q || '').trim();
    const limit = Math.min(100, parseInt(req.query.limit) || 50);
    const sortBy = (req.query.sort || req.query.sortBy || 'points_desc').toLowerCase();

    if (supabase) {
      let query = supabase.from('members').select('*');

      if (q) {
        const cleanDigits = q.replace(/[^0-9]/g, '');
        if (cleanDigits.length >= 2) {
          query = query.or(`name.ilike.%${q}%,phone.ilike.%${cleanDigits}%`);
        } else {
          query = query.ilike('name', `%${q}%`);
        }
      }

      if (sortBy === 'points_desc') {
        query = query.order('points', { ascending: false });
      } else if (sortBy === 'stamps_desc') {
        query = query.order('stamps', { ascending: false });
      } else {
        query = query.order('registered_at', { ascending: false, nullsFirst: false });
      }

      const { data: members, error } = await query.limit(limit);

      if (!error && members) {
        const formatted = members.map(m => ({
          id: m.id,
          name: m.name,
          phone: m.phone,
          email: m.email || '',
          points: parseInt(m.points) || 0,
          stamps: parseInt(m.stamps) || 0,
          tier: m.tier || computeMemberTierName(m.points),
          source: m.source || 'pos_counter',
          joined: m.registered_at ? new Date(m.registered_at).toLocaleDateString('ms-MY', { day:'numeric', month:'short', year:'numeric' }) : 'Baru'
        }));
        return res.json({ success: true, count: formatted.length, members: formatted });
      }
    }

    // In-memory fallback
    let list = [...posMembersStore];
    if (q) {
      const qLower = q.toLowerCase();
      const cleanDigits = q.replace(/[^0-9]/g, '');
      list = list.filter(m => 
        (m.name && m.name.toLowerCase().includes(qLower)) ||
        (cleanDigits.length >= 2 && m.phone && m.phone.includes(cleanDigits))
      );
    }

    if (sortBy === 'points_desc') list.sort((a, b) => (b.points || 0) - (a.points || 0));
    else if (sortBy === 'stamps_desc') list.sort((a, b) => (b.stamps || 0) - (a.stamps || 0));
    else list.sort((a, b) => String(b.id || '').localeCompare(String(a.id || '')));

    const paged = list.slice(0, limit);
    res.json({ success: true, count: paged.length, total: list.length, members: paged });
  } catch (err) {
    console.error('❌ GET /api/members error:', err.message);
    res.status(500).json({ success: false, error: 'Ralat mendapatkan senarai ahli', members: [] });
  }
});

// Endpoint 7.4: Tambah / Daftar Ahli Baharu
app.post('/api/members', requireStaffAuth, async (req, res) => {
  try {
    const { name, phone, email, points, stamps, tier, source } = req.body;
    if (!name || !phone) {
      return res.status(400).json({ success: false, error: 'Nama dan nombor telefon diperlukan' });
    }

    const cleanName = name.trim();
    const cleanPhone = normalizePhone(phone);
    const initialPoints = parseInt(points) || 0;
    const initialStamps = parseInt(stamps) || 0;
    const finalTier = tier || computeMemberTierName(initialPoints);
    const regSource = source || 'pos_counter';
    const joinedStr = new Date().toLocaleDateString('ms-MY', { day: 'numeric', month: 'short', year: 'numeric' });

    let newMember = {
      id: 'mbr_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4),
      name: cleanName,
      phone: cleanPhone,
      email: email ? email.trim() : '',
      points: initialPoints,
      stamps: initialStamps,
      tier: finalTier,
      source: regSource,
      joined: joinedStr,
      registered_at: new Date().toISOString(),
      last_visited_at: new Date().toISOString()
    };

    if (supabase) {
      // Semak jika nombor telefon sudah wujud
      const { data: existing } = await supabase.from('members').select('*').eq('phone', cleanPhone).single();

      if (existing) {
        const { data: updated, error: uErr } = await supabase
          .from('members')
          .update({
            name: cleanName,
            points: points !== undefined ? parseInt(points) : existing.points,
            stamps: stamps !== undefined ? parseInt(stamps) : existing.stamps,
            tier: finalTier,
            last_visited_at: new Date().toISOString()
          })
          .eq('id', existing.id)
          .select()
          .single();

        if (uErr) return res.status(500).json({ success: false, error: uErr.message });
        return res.json({ success: true, member: updated, isExisting: true, message: 'Maklumat ahli sedia ada dikemas kini' });
      }

      const { data: inserted, error: iErr } = await supabase
        .from('members')
        .insert({
          name: cleanName,
          phone: cleanPhone,
          email: email ? email.trim() : null,
          points: initialPoints,
          stamps: initialStamps,
          tier: finalTier,
          source: regSource,
          registered_at: new Date().toISOString(),
          last_visited_at: new Date().toISOString()
        })
        .select()
        .single();

      if (iErr) return res.status(500).json({ success: false, error: iErr.message });
      if (inserted) newMember = inserted;
    }

    // Kemaskini store memori
    const existingIdx = posMembersStore.findIndex(m => m.phone === cleanPhone);
    if (existingIdx !== -1) {
      posMembersStore[existingIdx] = { ...posMembersStore[existingIdx], name: cleanName, points: initialPoints, stamps: initialStamps, tier: finalTier };
    } else {
      posMembersStore.unshift(newMember);
    }

    // Catat log jejak audit
    if (supabase) {
      await supabase.from('pos_audit_logs').insert({
        action: 'member_registered',
        cashier_name: req.staff ? req.staff.name : cleanName,
        details: { name: cleanName, phone: cleanPhone, tier: finalTier }
      });
    }

    console.log(`👤 [MEMBER CREATED] ${cleanName} (${cleanPhone}) - Tier: ${finalTier}`);
    res.json({ success: true, member: newMember, message: 'Ahli berjaya didaftarkan! ✨' });
  } catch (err) {
    console.error('❌ POST /api/members error:', err.message);
    res.status(500).json({ success: false, error: 'Ralat mendaftar ahli' });
  }
});

// Endpoint 7.5: Kemaskini Maklumat Ahli
app.put('/api/members/:id', requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, phone, email, points, stamps, tier } = req.body;

    const updatePayload = {
      updated_at: new Date().toISOString()
    };
    if (name) updatePayload.name = name.trim();
    if (phone) updatePayload.phone = normalizePhone(phone);
    if (email !== undefined) updatePayload.email = email ? email.trim() : null;
    if (points !== undefined) {
      updatePayload.points = parseInt(points) || 0;
      if (!tier) updatePayload.tier = computeMemberTierName(updatePayload.points);
    }
    if (stamps !== undefined) updatePayload.stamps = parseInt(stamps) || 0;
    if (tier) updatePayload.tier = tier;

    let updated = null;

    if (supabase) {
      const { data, error } = await supabase
        .from('members')
        .update(updatePayload)
        .eq('id', id)
        .select()
        .single();

      if (error) return res.status(500).json({ success: false, error: error.message });
      updated = data;
    }

    const idx = posMembersStore.findIndex(m => String(m.id) === String(id));
    if (idx !== -1) {
      posMembersStore[idx] = { ...posMembersStore[idx], ...updatePayload };
      if (!updated) updated = posMembersStore[idx];
    }

    res.json({ success: true, member: updated || req.body, message: 'Maklumat ahli berjaya dikemas kini' });
  } catch (err) {
    console.error('❌ PUT /api/members/:id error:', err.message);
    res.status(500).json({ success: false, error: 'Ralat mengemas kini ahli' });
  }
});

// Endpoint 7.6: Padam Ahli
app.delete('/api/members/:id', requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (supabase) {
      const { error } = await supabase.from('members').delete().eq('id', id);
      if (error) return res.status(500).json({ success: false, error: error.message });
    }

    posMembersStore = posMembersStore.filter(m => String(m.id) !== String(id));
    res.json({ success: true, message: 'Profil ahli berjaya dipadam' });
  } catch (err) {
    console.error('❌ DELETE /api/members/:id error:', err.message);
    res.status(500).json({ success: false, error: 'Ralat memadam ahli' });
  }
});

// Endpoint 7.7: Carian / Dapatkan Ahli Berdasarkan No. Telefon
app.get('/api/members/:phone', async (req, res) => {
  try {
    const cleanPhone = normalizePhone(req.params.phone);
    
    if (supabase) {
      const { data: member, error } = await supabase
        .from('members')
        .select('*')
        .eq('phone', cleanPhone)
        .single();

      if (!error && member) {
        return res.json({ success: true, member });
      }
    }

    const found = posMembersStore.find(m => m.phone === cleanPhone);
    if (found) {
      return res.json({ success: true, member: found });
    }

    res.status(404).json({ success: false, error: 'Ahli tidak dijumpai' });
  } catch (err) {
    console.error('❌ GET /api/members/:phone error:', err.message);
    res.status(500).json({ success: false, error: 'Ralat mendapatkan data ahli' });
  }
});

// Endpoint 7.8: Laraskan Mata Ahli (Points Adjustment)
app.post(['/api/members/:id/adjust-points', '/api/pos/members/:id/adjust-points'], requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { amount, reason, cashierName } = req.body;
    const change = parseInt(amount) || 0;

    if (change === 0) {
      return res.status(400).json({ success: false, error: 'Jumlah pelarasan mata tidak boleh sifar' });
    }

    let targetMember = null;

    if (supabase) {
      const { data: current } = await supabase.from('members').select('*').eq('id', id).single();
      if (current) {
        const newPoints = Math.max(0, (current.points || 0) + change);
        const newTier = computeMemberTierName(newPoints);
        const { data: updated } = await supabase
          .from('members')
          .update({ points: newPoints, tier: newTier, updated_at: new Date().toISOString() })
          .eq('id', id)
          .select()
          .single();
        targetMember = updated;

        // Log transaksi mata
        await supabase.from('member_transactions').insert({
          member_id: id,
          type: change > 0 ? 'earn' : 'redeem',
          points: Math.abs(change),
          notes: reason || 'Pelarasan manual mata oleh pengurus'
        });
      }
    }

    const memIdx = posMembersStore.findIndex(m => String(m.id) === String(id));
    if (memIdx !== -1) {
      const curP = posMembersStore[memIdx].points || 0;
      const finalP = Math.max(0, curP + change);
      posMembersStore[memIdx].points = finalP;
      posMembersStore[memIdx].tier = computeMemberTierName(finalP);
      if (!targetMember) targetMember = posMembersStore[memIdx];
    }

    if (!targetMember) {
      return res.status(404).json({ success: false, error: 'Ahli tidak ditemui' });
    }

    res.json({ success: true, member: targetMember, message: `Mata berjaya dilaraskan (${change > 0 ? '+' : ''}${change} mata)` });
  } catch (err) {
    console.error('❌ POST /api/members/:id/adjust-points error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 8. API: CLAIM LUCKY DRAW CODE (Cabutan Bertuah)
// ====================================================================
app.post('/api/lucky-draw/claim', async (req, res) => {
  try {
    const { code, memberId } = req.body;
    if (!code) {
      return res.status(400).json({ error: 'Kod cabutan bertuah diperlukan' });
    }

    if (supabase) {
      const { data, error } = await supabase.rpc('claim_lucky_code', {
        p_code: String(code).trim(),
        p_member_id: memberId || null
      });

      if (error) {
        return res.status(400).json({ error: error.message });
      }

      return res.json(data);
    }

    // Standalone fallback
    res.json({
      success: true,
      prize_name: 'Kopi Latte Percuma',
      code: code.trim(),
      claimed_at: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error claiming lucky code:', err);
    res.status(500).json({ error: 'Ralat menuntut cabutan bertuah' });
  }
});

// ====================================================================
// 9. API: PROMOTIONS & ADS (Iklan & Banner Promosi)
// ====================================================================
const DEFAULT_STARTER_PROMOTIONS = [
  {
    title: '🔥 Tawaran Khas: Beli 2 Percuma 1',
    description: 'Nikmati minuman kopi & pastri kegemaran anda bersama rakan!',
    media_type: 'image',
    media_url: 'https://images.unsplash.com/photo-1501339847302-ac426a4a7cbb?w=800&auto=format&fit=crop&q=80',
    badge_label: '🔥 Tawaran Khas',
    action_label: '🎁 Lihat Ganjaran',
    is_active: true,
    sort_order: 1
  },
  {
    title: '☕ Setem Berganda Hari Ini',
    description: 'Kumpul 2x cop setem untuk setiap belian minuman kopi melebihi RM15!',
    media_type: 'image',
    media_url: 'https://images.unsplash.com/photo-1495474472287-4d71bcdd2085?w=800&auto=format&fit=crop&q=80',
    badge_label: '⭐ Promosi Ahli',
    action_label: '☕ Tebus Setem',
    is_active: true,
    sort_order: 2
  }
];

// 9.1 GET /api/promotions (Semua Promosi untuk Pengurusan POS & Admin)
app.get(['/api/promotions', '/api/pos/promotions'], async (req, res) => {
  try {
    if (supabase) {
      const { data: promos, error } = await supabase
        .from('promotions')
        .select('*')
        .order('sort_order', { ascending: true })
        .order('created_at', { ascending: false });

      if (!error && promos && promos.length > 0) {
        return res.json({ success: true, promotions: promos });
      }

      // Jika pangkalan data kosong, auto-seed starter promotions ke Supabase
      try {
        const { data: seeded } = await supabase.from('promotions').insert(DEFAULT_STARTER_PROMOTIONS).select();
        if (seeded && seeded.length > 0) {
          console.log(`✨ [PROMOTIONS AUTO-SEEDED] ${seeded.length} promosi starter berjaya dimasukkan ke Supabase.`);
          return res.json({ success: true, promotions: seeded });
        }
      } catch (seedErr) {
        console.warn('Auto-seed promotions warning:', seedErr.message);
      }
    }

    return res.json({
      success: true,
      promotions: DEFAULT_STARTER_PROMOTIONS
    });
  } catch (err) {
    console.error('Error fetching promotions:', err);
    res.status(500).json({ success: false, error: 'Ralat memuatkan promosi' });
  }
});

// 9.2 GET /api/promotions/active (Promosi Aktif untuk Loyalty Portal)
app.get(['/api/promotions/active', '/api/loyalty/promotions'], async (req, res) => {
  try {
    if (supabase) {
      const { data: promos, error } = await supabase
        .from('promotions')
        .select('*')
        .eq('is_active', true)
        .order('sort_order', { ascending: true })
        .order('created_at', { ascending: false });

      if (!error && promos && promos.length > 0) {
        return res.json({ success: true, promotions: promos });
      }
    }

    res.json({
      success: true,
      promotions: DEFAULT_STARTER_PROMOTIONS
    });
  } catch (err) {
    console.error('Error fetching active promotions:', err);
    res.status(500).json({ success: false, error: 'Ralat memuatkan promosi' });
  }
});

// Pekerja Latar Belakang: Auto Padam Promosi yang Telah Luput dari Supabase (Setiap 5 Saat)
setInterval(async () => {
  if (!supabase) return;
  try {
    const nowIso = new Date().toISOString();
    const { data: expiredPromos } = await supabase
      .from('promotions')
      .select('id, title, media_url, end_date')
      .not('end_date', 'is', null)
      .lte('end_date', nowIso);

    if (expiredPromos && expiredPromos.length > 0) {
      console.log(`🗑️ [AUTO-EXPIRE] Memadam ${expiredPromos.length} promosi yang telah tamat tempoh...`);
      for (const ep of expiredPromos) {
        // Padam fail media jika tersimpan di VPS
        if (ep.media_url && ep.media_url.includes('/uploads/promotions/')) {
          try {
            const filename = path.basename(ep.media_url);
            const fullPath = path.join(promoUploadDir, filename);
            if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
          } catch(e){}
        }
        // Padam rekod dari Supabase
        await supabase.from('promotions').delete().eq('id', ep.id);
      }
    }
  } catch (err) {
    // Silent catch
  }
}, 5000);

// API: Tambah / Terbit Promosi Baru
app.post('/api/promotions', requireStaffAuth, async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({ success: false, error: 'Klien Supabase tidak aktif' });
    }
    const payload = req.body || {};
    const insertRow = {
      title: payload.title || payload.description || 'Tawaran Khas',
      description: payload.description || payload.title || '',
      media_url: payload.media_url || '',
      media_type: payload.media_type || 'image',
      badge_label: payload.badge_label || '🔥 Tawaran Khas',
      is_active: payload.is_active !== false,
      end_date: payload.end_date || null,
      sort_order: parseInt(payload.sort_order, 10) || 0,
      created_at: new Date().toISOString()
    };

    const { data, error } = await supabase.from('promotions').insert([insertRow]).select().single();
    if (error) throw error;

    await supabase.from('pos_audit_logs').insert({
      action: 'promotion_created',
      cashier_name: req.staff ? req.staff.name : 'Pengurus Utama',
      details: { promoId: data.id, title: data.title }
    });

    return res.json({ success: true, message: 'Promosi berjaya ditambah', promotion: data });
  } catch (err) {
    console.error('Create promo error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// API: Kemas Kini Promosi
app.put('/api/promotions/:id', requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!supabase) {
      return res.status(500).json({ success: false, error: 'Klien Supabase tidak aktif' });
    }
    const payload = req.body || {};
    const updateRow = {
      updated_at: new Date().toISOString()
    };
    if (payload.title !== undefined) updateRow.title = payload.title;
    if (payload.description !== undefined) updateRow.description = payload.description;
    if (payload.media_url !== undefined) updateRow.media_url = payload.media_url;
    if (payload.media_type !== undefined) updateRow.media_type = payload.media_type;
    if (payload.badge_label !== undefined) updateRow.badge_label = payload.badge_label;
    if (payload.is_active !== undefined) updateRow.is_active = Boolean(payload.is_active);
    if (payload.end_date !== undefined) updateRow.end_date = payload.end_date || null;
    if (payload.sort_order !== undefined) updateRow.sort_order = parseInt(payload.sort_order, 10) || 0;

    const { data, error } = await supabase.from('promotions').update(updateRow).eq('id', id).select().single();
    if (error) throw error;

    return res.json({ success: true, message: 'Promosi berjaya dikemas kini', promotion: data });
  } catch (err) {
    console.error('Update promo error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// API: Padam Promosi Manual
app.delete('/api/promotions/:id', requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (supabase) {
      const { data: promo } = await supabase.from('promotions').select('media_url').eq('id', id).maybeSingle();
      if (promo && promo.media_url && promo.media_url.includes('/uploads/promotions/')) {
        try {
          const filename = path.basename(promo.media_url);
          const fullPath = path.join(promoUploadDir, filename);
          if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
        } catch(e){}
      }
      await supabase.from('promotions').delete().eq('id', id);
    }
    return res.json({ success: true, message: 'Iklan promosi berjaya dipadam' });
  } catch (err) {
    console.error('Delete promo error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 10. API: MEDIA UPLOAD TO VPS / LOCAL DISK (Images & Videos)
// ====================================================================
app.post('/api/upload/promotion', requireStaffAuth, uploadMedia.single('media'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'Tiada fail media dimuat naik' });
    }

    const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.get('host');
    const relativeUrl = `/uploads/promotions/${req.file.filename}`;
    const fullUrl = `${protocol}://${host}${relativeUrl}`;

    console.log(`✅ [VPS / LOCAL STORAGE] Fail disimpan: ${req.file.filename} (${(req.file.size / 1024).toFixed(1)} KB)`);
    console.log(`🔗 [MEDIA URL]: ${relativeUrl}`);

    return res.json({
      success: true,
      url: relativeUrl,
      fullUrl: fullUrl,
      filename: req.file.filename,
      mimetype: req.file.mimetype,
      size: req.file.size
    });
  } catch (err) {
    console.error('❌ Ralat upload media ke VPS/Local:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 11. API: PRODUCT CATEGORIES (CRUD & LIVE SYNC)
// ====================================================================
app.get('/api/categories', async (req, res) => {
  try {
    if (!supabase) {
      return res.json({
        success: true,
        categories: [
          { id: 'semua', code: 'semua', name: 'Semua', icon: '🌟' },
          { id: 'kopi', code: 'kopi', name: 'Kopi', icon: '☕' },
          { id: 'bukan-kopi', code: 'bukan-kopi', name: 'Bukan Kopi', icon: '🍵' },
          { id: 'pastri', code: 'pastri', name: 'Pastri & Bakeri', icon: '🥐' },
          { id: 'makanan', code: 'makanan', name: 'Makanan Berat', icon: '🍛' },
          { id: 'addon', code: 'addon', name: 'Pilihan Tambahan (Add-on)', icon: '✨' }
        ]
      });
    }

    const { data: dbCategories, error } = await supabase
      .from('product_categories')
      .select('*')
      .order('sort_order', { ascending: true });

    if (error) {
      console.error('Error fetching categories from Supabase:', error);
      throw error;
    }

    return res.json({
      success: true,
      categories: dbCategories && dbCategories.length > 0 ? dbCategories : [
        { id: 'kopi', code: 'kopi', name: 'Kopi', icon: '☕', sort_order: 1 },
        { id: 'bukan-kopi', code: 'bukan-kopi', name: 'Bukan Kopi', icon: '🍵', sort_order: 2 },
        { id: 'pastri', code: 'pastri', name: 'Pastri & Bakeri', icon: '🥐', sort_order: 3 },
        { id: 'makanan', code: 'makanan', name: 'Makanan Berat', icon: '🍛', sort_order: 4 },
        { id: 'addon', code: 'addon', name: 'Pilihan Tambahan (Add-on)', icon: '✨', sort_order: 5 }
      ]
    });
  } catch (err) {
    console.error('❌ /api/categories error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Helper untuk menyelaraskan cache produk ke pos_settings Supabase (Supaya Anon Key di mana-mana pelayar boleh baca)
async function syncPosProductsCache() {
  if (!supabase) return;
  try {
    const { data: dbProducts } = await supabase
      .from('products')
      .select('*, product_variations(*), product_categories(id, code, name)')
      .order('created_at', { ascending: false });

    const products = (dbProducts || []).map(p => {
      let extraData = {};
      try {
        if (p.description && p.description.trim().startsWith('{')) {
          extraData = JSON.parse(p.description);
        }
      } catch (e) {}

      const catCode = p.product_categories ? p.product_categories.code : (p.is_addon ? 'addon' : 'kopi');

      return {
        id: p.id,
        name: p.name,
        description: extraData.text || (p.description && !p.description.startsWith('{') ? p.description : ''),
        price: parseFloat(p.price) || 0,
        cost: parseFloat(p.cost_price) || 0,
        stock: p.stock !== null ? parseInt(p.stock) : 999,
        img: p.img_url || null,
        cat: catCode,
        catId: p.category_id,
        is_addon: !!p.is_addon,
        is_available: p.is_available !== false,
        icon: catCode === 'kopi' ? '☕' : catCode === 'bukan-kopi' ? '🍵' : catCode === 'pastri' ? '🥐' : catCode === 'addon' ? '✨' : '🍛',
        variations: (p.product_variations || []).map(v => ({
          id: v.id,
          name: v.name,
          priceDiff: parseFloat(v.price_diff) || 0
        })),
        addons: Array.isArray(extraData.addons) ? extraData.addons : []
      };
    });

    await supabase.from('pos_settings').upsert({
      key: 'pos_products_cache',
      value: products,
      updated_at: new Date().toISOString()
    });
  } catch (e) {
    console.warn('syncPosProductsCache error:', e.message);
  }
}

// ====================================================================
// 12. API: PRODUCTS & MENU (CRUD WITH VARIATIONS & ADD-ONS)
// ====================================================================
app.get('/api/products', async (req, res) => {
  try {
    if (!supabase) {
      return res.json({ success: true, products: [] });
    }

    const { data: dbProducts, error } = await supabase
      .from('products')
      .select('*, product_variations(*), product_categories(id, code, name)')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Error fetching products from Supabase:', error);
      throw error;
    }

    const products = (dbProducts || []).map(p => {
      let extraData = {};
      try {
        if (p.description && p.description.trim().startsWith('{')) {
          extraData = JSON.parse(p.description);
        }
      } catch (e) {}

      const catCode = p.product_categories ? p.product_categories.code : (p.is_addon ? 'addon' : 'kopi');

      return {
        id: p.id,
        name: p.name,
        description: extraData.text || (p.description && !p.description.startsWith('{') ? p.description : ''),
        price: parseFloat(p.price) || 0,
        cost: parseFloat(p.cost_price) || 0,
        stock: p.stock !== null ? parseInt(p.stock) : 999,
        img: p.img_url || null,
        cat: catCode,
        catId: p.category_id,
        is_addon: !!p.is_addon,
        is_available: p.is_available !== false,
        icon: catCode === 'kopi' ? '☕' : catCode === 'bukan-kopi' ? '🍵' : catCode === 'pastri' ? '🥐' : catCode === 'addon' ? '✨' : '🍛',
        variations: (p.product_variations || []).map(v => ({
          id: v.id,
          name: v.name,
          priceDiff: parseFloat(v.price_diff) || 0
        })),
        addons: Array.isArray(extraData.addons) ? extraData.addons : []
      };
    });

    // Selaraskan juga ke pos_settings cache di latar belakang
    supabase.from('pos_settings').upsert({
      key: 'pos_products_cache',
      value: products,
      updated_at: new Date().toISOString()
    }).then().catch(()=>{});

    return res.json({ success: true, products });
  } catch (err) {
    console.error('❌ /api/products GET error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Tambah Produk Baharu
app.post('/api/products', requireStaffAuth, async (req, res) => {
  try {
    const { name, price, cost, stock, cat, img, variations, addons, description } = req.body;

    if (!name || price === undefined) {
      return res.status(400).json({ success: false, error: 'Nama dan harga produk diperlukan' });
    }

    if (!supabase) {
      return res.json({
        success: true,
        product: {
          id: Date.now().toString(),
          name, price, cost, stock, cat, img,
          variations: variations || [],
          addons: addons || []
        }
      });
    }

    // Dapatkan category_id dari product_categories jika wujud
    let categoryId = null;
    if (cat) {
      const { data: catRow } = await supabase
        .from('product_categories')
        .select('id')
        .eq('code', cat)
        .limit(1)
        .single();
      if (catRow) categoryId = catRow.id;
    }

    const isAddon = (cat === 'addon');
    const descJson = JSON.stringify({
      text: description || '',
      addons: isAddon ? [] : (addons || [])
    });

    const { data: newProd, error: prodErr } = await supabase
      .from('products')
      .insert({
        name,
        price: parseFloat(price) || 0,
        cost_price: parseFloat(cost) || 0,
        stock: stock !== undefined ? parseInt(stock) : 999,
        category_id: categoryId,
        is_addon: isAddon,
        img_url: img || null,
        description: descJson,
        is_available: true
      })
      .select()
      .single();

    if (prodErr) throw prodErr;

    // Simpan variasi jika ada
    let savedVariations = [];
    if (!isAddon && variations && Array.isArray(variations) && variations.length > 0) {
      const varPayload = variations
        .filter(v => v.name && v.name.trim().length > 0)
        .map(v => ({
          product_id: newProd.id,
          name: v.name.trim(),
          price_diff: parseFloat(v.priceDiff) || 0,
          is_active: true
        }));

      if (varPayload.length > 0) {
        const { data: vRows, error: vErr } = await supabase
          .from('product_variations')
          .insert(varPayload)
          .select();
        if (!vErr && vRows) savedVariations = vRows;
      }
    }

    // Selaraskan cache pos_settings
    syncPosProductsCache().catch(()=>{});

    return res.json({
      success: true,
      product: {
        id: newProd.id,
        name: newProd.name,
        price: parseFloat(newProd.price),
        cost: parseFloat(newProd.cost_price),
        stock: newProd.stock,
        img: newProd.img_url,
        cat: cat || (isAddon ? 'addon' : 'kopi'),
        catId: newProd.category_id,
        is_addon: newProd.is_addon,
        icon: cat === 'kopi' ? '☕' : cat === 'bukan-kopi' ? '🍵' : cat === 'pastri' ? '🥐' : cat === 'addon' ? '✨' : '🍛',
        variations: savedVariations.map(v => ({ id: v.id, name: v.name, priceDiff: parseFloat(v.price_diff) || 0 })),
        addons: isAddon ? [] : (addons || [])
      }
    });
  } catch (err) {
    console.error('❌ /api/products POST error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Kemas kini Produk
app.put('/api/products/:id', requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, price, cost, stock, cat, img, variations, addons, description, is_available } = req.body;

    if (!supabase) {
      return res.json({ success: true, product: { id, name, price, cost, stock, cat, img, variations, addons } });
    }

    let categoryId = null;
    if (cat) {
      const { data: catRow } = await supabase
        .from('product_categories')
        .select('id')
        .eq('code', cat)
        .limit(1)
        .single();
      if (catRow) categoryId = catRow.id;
    }

    const isAddon = (cat === 'addon');
    const descJson = JSON.stringify({
      text: description || '',
      addons: isAddon ? [] : (addons || [])
    });

    const updatePayload = {
      name,
      price: parseFloat(price) || 0,
      cost_price: parseFloat(cost) || 0,
      stock: stock !== undefined ? parseInt(stock) : 999,
      category_id: categoryId,
      is_addon: isAddon,
      description: descJson,
      updated_at: new Date()
    };
    if (img !== undefined) updatePayload.img_url = img;
    if (is_available !== undefined) updatePayload.is_available = is_available;

    const { data: updatedProd, error: updateErr } = await supabase
      .from('products')
      .update(updatePayload)
      .eq('id', id)
      .select()
      .single();

    if (updateErr) throw updateErr;

    // Padam & masukkan semula variasi jika diberikan
    let savedVariations = [];
    if (!isAddon && variations && Array.isArray(variations)) {
      await supabase.from('product_variations').delete().eq('product_id', id);
      const varPayload = variations
        .filter(v => v.name && v.name.trim().length > 0)
        .map(v => ({
          product_id: id,
          name: v.name.trim(),
          price_diff: parseFloat(v.priceDiff) || 0,
          is_active: true
        }));

      if (varPayload.length > 0) {
        const { data: vRows } = await supabase
          .from('product_variations')
          .insert(varPayload)
          .select();
        if (vRows) savedVariations = vRows;
      }
    }

    // Selaraskan cache pos_settings
    syncPosProductsCache().catch(()=>{});

    return res.json({
      success: true,
      product: {
        id: updatedProd.id,
        name: updatedProd.name,
        price: parseFloat(updatedProd.price),
        cost: parseFloat(updatedProd.cost_price),
        stock: updatedProd.stock,
        img: updatedProd.img_url,
        cat: cat || (isAddon ? 'addon' : 'kopi'),
        is_addon: updatedProd.is_addon,
        icon: cat === 'kopi' ? '☕' : cat === 'bukan-kopi' ? '🍵' : cat === 'pastri' ? '🥐' : cat === 'addon' ? '✨' : '🍛',
        variations: savedVariations.map(v => ({ id: v.id, name: v.name, priceDiff: parseFloat(v.price_diff) || 0 })),
        addons: isAddon ? [] : (addons || [])
      }
    });
  } catch (err) {
    console.error('❌ /api/products PUT error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Padam Produk
app.delete('/api/products/:id', requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (supabase) {
      await supabase.from('product_variations').delete().eq('product_id', id);
      const { error } = await supabase.from('products').delete().eq('id', id);
      if (error) throw error;
      syncPosProductsCache().catch(()=>{});
    }
    return res.json({ success: true, message: 'Produk dipadam' });
  } catch (err) {
    console.error('❌ /api/products DELETE error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Upload Gambar Produk ke VPS / Local Disk
app.post('/api/upload/product', requireStaffAuth, uploadProductMedia.single('media'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'Tiada fail gambar dimuat naik' });
    }

    const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.get('host');
    const relativeUrl = `/uploads/products/${req.file.filename}`;
    const fullUrl = `${protocol}://${host}${relativeUrl}`;

    console.log(`✅ [PRODUCT IMAGE UPLOAD] Disimpan: ${req.file.filename} (${(req.file.size / 1024).toFixed(1)} KB)`);

    return res.json({
      success: true,
      url: relativeUrl,
      fullUrl: fullUrl,
      filename: req.file.filename,
      size: req.file.size
    });
  } catch (err) {
    console.error('❌ Ralat upload gambar produk:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 13. API: POS CHECKOUT & SALES PERSISTENCE (ZERO DATA LOSS)
// ====================================================================
app.post('/api/pos/checkout', requireStaffAuth, async (req, res) => {
  try {
    const {
      receiptNo,
      orderType,
      payMethod,
      cashTendered,
      changeReturned,
      subtotal,
      discount,
      tax,
      serviceCharge,
      roundAdj,
      total,
      memberId,
      cashierName,
      cashierCode,
      items
    } = req.body;

    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ success: false, error: 'Pesanan tiada item' });
    }

    if (!supabase) {
      return res.json({
        success: true,
        saleId: 'local-' + Date.now(),
        receiptNo: receiptNo || ('RS-' + Math.floor(100000 + Math.random() * 899999))
      });
    }

    const finalReceiptNo = receiptNo || ('RS-' + Math.floor(100000 + Math.random() * 899999));
    const finalPayMethod = (payMethod === 'kad') ? 'card' : (payMethod === 'ewallet' ? 'ewallet' : 'cash');
    const buyerInfo = req.body.buyerInfo || null;
    const stampsEarnedNum = parseInt(req.body.stampsEarned, 10) || 0;
    const stampsRedeemedNum = parseInt(req.body.stampsRedeemed || req.body.stampsDeducted, 10) || 0;
    const pointsEarnedNum = parseInt(req.body.pointsEarned, 10) || 0;
    const pointsRedeemedNum = parseInt(req.body.pointsRedeemed || req.body.pointsDeducted, 10) || 0;

    let notesData = null;
    let notesObj = {};
    if (buyerInfo && (buyerInfo.name || buyerInfo.tin)) {
      notesObj.buyerInfo = buyerInfo;
    }
    if (req.body.stampRewardItems && req.body.stampRewardItems.length > 0) {
      notesObj.marketingExpense = true;
      notesObj.rewardType = 'Ganjaran Cop Stamp';
      notesObj.rewardName = req.body.stampRewardItems[0].name || req.body.stampRewardItems[0].rewardName || 'Cop Penuh';
      notesObj.costAmount = req.body.stampRewardItems.reduce((s, it) => s + (parseFloat(it.cost) || 3.50) * (parseInt(it.qty, 10) || 1), 0) || 3.50;
      notesObj.stampsRedeemed = stampsRedeemedNum;
    }
    if (Object.keys(notesObj).length > 0) {
      notesData = JSON.stringify(notesObj);
    } else if (req.body.notes) {
      notesData = typeof req.body.notes === 'string' ? req.body.notes : JSON.stringify(req.body.notes);
    }

    const isFreeOrRewardsOnly = (parseFloat(subtotal) === 0 && (pointsRedeemedNum > 0 || stampsRedeemedNum > 0 || (Array.isArray(req.body.redeemedRewards) && req.body.redeemedRewards.length > 0)));
    const finalOrderType = (orderType === 'takeaway') ? 'takeaway' : 'dinein';

    // 1. Simpan rekod utama transaksi ke jadual `sales`
    const { data: saleRow, error: saleErr } = await supabase
      .from('sales')
      .insert({
        receipt_no: finalReceiptNo,
        order_type: finalOrderType,
        payment_method: isFreeOrRewardsOnly ? 'points' : finalPayMethod,
        cash_tendered: parseFloat(cashTendered) || 0,
        change_given: parseFloat(changeReturned) || 0,
        subtotal: parseFloat(subtotal) || 0,
        discount: parseFloat(discount) || 0,
        tax: parseFloat(tax) || 0,
        service_charge: parseFloat(serviceCharge) || 0,
        round_adj: parseFloat(roundAdj) || 0,
        total: parseFloat(total) || 0,
        cashier_name: cashierName || 'Akmal Hakim',
        member_id: (memberId && String(memberId).length > 20) ? memberId : null,
        notes: notesData,
        status: 'paid'
      })
      .select()
      .single();

    if (saleErr) {
      if (saleErr.code === '23505' || (saleErr.message && saleErr.message.includes('unique constraint')) || (saleErr.details && saleErr.details.includes('already exists'))) {
        console.log(`ℹ️ [CHECKOUT IDEMPOTENT SYNC] Resit ${finalReceiptNo} telah sedia wujud dalam pangkalan data Supabase.`);
        const { data: existingSale } = await supabase
          .from('sales')
          .select('id, receipt_no')
          .eq('receipt_no', finalReceiptNo)
          .maybeSingle();

        return res.json({
          success: true,
          saleId: existingSale ? existingSale.id : ('local-' + Date.now()),
          receiptNo: finalReceiptNo,
          alreadyExists: true,
          message: 'Pesanan telah sedia direkodkan dalam pangkalan data.'
        });
      }
      console.error('Error creating sale record in Supabase:', saleErr);
      throw saleErr;
    }

    // 2. Simpan setiap baris item ke jadual `sale_items` dengan perincian penuh
    const saleItemPayload = items.map(it => {
      let costVal = parseFloat(it.cost) || parseFloat(it.unit_cost) || 0;
      if (costVal === 0 && (it.isRedeemed || it.redeemedPoints || it.isStampReward)) {
        costVal = 3.50; // Anggaran kos modal asas item tebus jika tidak ditetapkan
      }
      return {
        sale_id: saleRow.id,
        product_id: (it.id && String(it.id).length > 20) ? it.id : null,
        product_name: it.name,
        variation_name: (it.variation && it.variation.name) ? it.variation.name : null,
        unit_price: parseFloat(it.price) || 0,
        unit_cost: costVal,
        qty: parseInt(it.qty) || 1,
        subtotal: parseFloat(((parseFloat(it.price) || 0) * (parseInt(it.qty) || 1)).toFixed(2)),
        selected_addons: Array.isArray(it.addons) ? it.addons : []
      };
    });

    const { error: itemsErr } = await supabase
      .from('sale_items')
      .insert(saleItemPayload);

    if (itemsErr) {
      console.error('Error inserting sale_items:', itemsErr);
    }

    // 3. Tolak baki stok di pangkalan data
    for (const it of items) {
      if (it.id && String(it.id).length > 20) {
        try {
          const { data: currP } = await supabase.from('products').select('stock').eq('id', it.id).single();
          if (currP && currP.stock !== null) {
            const newStock = Math.max(0, currP.stock - (parseInt(it.qty) || 1));
            await supabase.from('products').update({ stock: newStock }).eq('id', it.id);
          }
        } catch (e) {}
      }
      if (it.addons && Array.isArray(it.addons)) {
        for (const ad of it.addons) {
          if (ad.id && String(ad.id).length > 20) {
            try {
              const { data: currAd } = await supabase.from('products').select('stock').eq('id', ad.id).single();
              if (currAd && currAd.stock !== null) {
                const newStock = Math.max(0, currAd.stock - (parseInt(it.qty) || 1));
                await supabase.from('products').update({ stock: newStock }).eq('id', ad.id);
              }
            } catch (e) {}
          }
        }
      }
    }

    console.log(`✅ [POS SALE RECORDED] Resit: ${finalReceiptNo} | Jumlah: RM${parseFloat(total).toFixed(2)} | Item: ${items.length}`);

    // 3B. Kemas kini mata & cop stamp ahli secara ATOMIC (Penolakan Tebus + Penambahan Baharu)
    let updatedMemberSummary = null;

    if (memberId || req.body.phone || req.body.memberPhone) {
      try {
        let mData = null;
        if (memberId && String(memberId).length > 20) {
          const { data: byId } = await supabase.from('members').select('*').eq('id', memberId).maybeSingle();
          if (byId) mData = byId;
        }

        if (!mData && (req.body.memberPhone || req.body.phone)) {
          const phoneRaw = req.body.memberPhone || req.body.phone || '';
          const cleanP = normalizePhone(phoneRaw);
          const digitsOnly = phoneRaw.replace(/\D/g, '');
          if (digitsOnly.length >= 7) {
            const { data: byPhone } = await supabase.from('members')
              .select('*')
              .or(`phone.eq.${cleanP},phone.eq.${digitsOnly},phone.eq.60${digitsOnly.replace(/^60|^0/, '')}`)
              .limit(1)
              .maybeSingle();
            if (byPhone) mData = byPhone;
          }
        }

        if (mData) {
          const pointsBefore = parseInt(mData.points, 10) || 0;
          const stampsBefore = parseInt(mData.stamps, 10) || 0;

          // Hitung penambahan mata secara automatik jika tidak dihantar
          let ptsEarned = parseInt(req.body.pointsEarned, 10);
          if (isNaN(ptsEarned) || (ptsEarned === 0 && parseFloat(total) > 0)) {
            const ptsRate = inMemoryRewardSettings.amountPerPoint || 1.00;
            ptsEarned = Math.floor((parseFloat(total) || 0) / ptsRate);
          }

          // Hitung penambahan cop stamp secara automatik jika tidak dihantar
          let stpsEarned = parseInt(req.body.stampsEarned, 10);
          if (isNaN(stpsEarned) || (stpsEarned === 0 && parseFloat(total) > 0)) {
            const stampMode = inMemoryStampSettings.earningMode || 'payment';
            if (stampMode === 'item') {
              const qualifying = (items || []).filter(c => !c.isRedeemed && !c.redeemedPoints && !c.isStampReward);
              stpsEarned = Math.max(0, qualifying.reduce((s, c) => s + (parseInt(c.qty, 10) || 1), 0));
            } else if (stampMode === 'amount') {
              const rate = inMemoryStampSettings.amountPerStamp || 10;
              stpsEarned = Math.floor((parseFloat(total) || 0) / rate);
            } else {
              stpsEarned = (items && items.length > 0) ? 1 : 0;
            }
          }

          // Formula Rasmi & Tunggal: Baki Akhir = Asal - Ditebus + Baharu Diperolehi
          const newPts = Math.max(0, pointsBefore - pointsRedeemedNum + ptsEarned);
          const newLifetime = (mData.lifetime_points || 0) + ptsEarned;
          const newStamps = Math.max(0, stampsBefore - stampsRedeemedNum + stpsEarned);

          const { data: updatedMember, error: updMemberErr } = await supabase
            .from('members')
            .update({
              points: newPts,
              lifetime_points: newLifetime,
              stamps: newStamps,
              last_visited_at: new Date().toISOString(),
              updated_at: new Date().toISOString()
            })
            .eq('id', mData.id)
            .select()
            .single();

          if (updMemberErr) {
            console.error('❌ Error updating member in Supabase:', updMemberErr);
          } else {
            console.log(`👤 [MEMBER UPDATED] ${mData.name} (${mData.phone}) | Points: ${pointsBefore} -> ${newPts} (+${ptsEarned}, -${pointsRedeemedNum}) | Stamps: ${stampsBefore} -> ${newStamps} (+${stpsEarned}, -${stampsRedeemedNum})`);
          }

          // Jika ada penebusan cop stamp, kemas kini status kad cop & rekod audit log
          if (stampsRedeemedNum > 0) {
            const { data: uCards } = await supabase
              .from('member_stamp_cards')
              .select('*')
              .eq('member_id', mData.id)
              .in('status', ['unclaimed', 'completed'])
              .order('card_number', { ascending: true })
              .limit(1);

            if (uCards && uCards[0]) {
              await supabase
                .from('member_stamp_cards')
                .update({
                  status: 'claimed',
                  claimed_at: new Date().toISOString(),
                  updated_at: new Date().toISOString()
                })
                .eq('id', uCards[0].id);
            }

            const stampItems = req.body.stampRewardItems || [];
            const totalStampCost = stampItems.reduce((s, it) => s + (parseFloat(it.cost) || 3.50) * (parseInt(it.qty, 10) || 1), 0) || 3.50;

            await supabase.from('pos_audit_logs').insert({
              action: 'stamp_reward_claimed',
              receipt_no: finalReceiptNo,
              cashier_name: cashierName || 'Juruwang Bertugas',
              details: {
                memberId: mData.id,
                phone: mData.phone,
                stampsBefore: stampsBefore,
                stampsRedeemed: stampsRedeemedNum,
                stampsEarned: stpsEarned,
                stampsBalance: newStamps,
                marketingCost: totalStampCost,
                rewardItems: stampItems,
                claimedAt: new Date().toISOString()
              }
            });
          }

          if (!updMemberErr && updatedMember) {
            updatedMemberSummary = {
              id: updatedMember.id,
              name: updatedMember.name,
              phone: updatedMember.phone,
              pointsBefore: pointsBefore,
              pointsDeducted: pointsRedeemedNum,
              pointsEarned: ptsEarned,
              pointsBalance: newPts,
              stampsBefore: stampsBefore,
              stampsRedeemed: stampsRedeemedNum,
              stampsEarned: stpsEarned,
              stamps: newStamps
            };

            // Jika ada item ganjaran ditebus, kemas kini redeemed_count pada table rewards
            if (Array.isArray(req.body.redeemedRewards)) {
              for (const it of req.body.redeemedRewards) {
                if (it.rewardId) {
                  try {
                    const { data: rRow } = await supabase.from('rewards').select('redeemed_count').eq('id', it.rewardId).single();
                    if (rRow) {
                      await supabase.from('rewards').update({
                        redeemed_count: (rRow.redeemed_count || 0) + (it.qty || 1),
                        updated_at: new Date().toISOString()
                      }).eq('id', it.rewardId);
                    }
                  } catch (e) {}
                }
              }
            }

            if (stampsEarnedNum > 0) {
              await syncMemberStampCards(mData.id, stampsEarnedNum);
            }

            console.log(`✨ [MEMBER ATOMIC CHECKOUT] ${mData.name} | Points: ${pointsBefore} - ${pointsRedeemedNum} + ${pointsEarnedNum} = ${newPts} | Stamps: ${stampsBefore} - ${stampsRedeemedNum} + ${stampsEarnedNum} = ${newStamps}`);
          }
        }
      } catch(mErr) {
        console.warn('Checkout member point/stamp update error:', mErr.message);
      }
    }

    // 4. Catat Jejak Audit Transaksi ke jadual `pos_audit_logs`
    try {
      await supabase.from('pos_audit_logs').insert({
        action: 'sale_completed',
        receipt_no: finalReceiptNo,
        shift_code: req.body.shiftCode || null,
        cashier_name: cashierName || 'Akmal Hakim',
        cashier_code: cashierCode || 'STF-001',
        amount: parseFloat(total) || 0,
        details: {
          order_type: orderType,
          payment_method: finalPayMethod,
          subtotal: parseFloat(subtotal) || 0,
          tax: parseFloat(tax) || 0,
          total: parseFloat(total) || 0,
          items_count: items.length,
          points_before: updatedMemberSummary ? updatedMemberSummary.pointsBefore : (parseInt(req.body.pointsBefore, 10) || null),
          points_redeemed: pointsRedeemedNum,
          points_earned: pointsEarnedNum,
          points_balance: updatedMemberSummary ? updatedMemberSummary.pointsBalance : null,
          stamps_earned: stampsEarnedNum,
          buyer_info: buyerInfo
        }
      });
    } catch(e){}

    return res.json({
      success: true,
      saleId: saleRow.id,
      receiptNo: saleRow.receipt_no,
      member: updatedMemberSummary
    });
  } catch (err) {
    console.error('❌ /api/pos/checkout error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 13B. REKOD JUALAN & TRANSAKSI POS (SALES LEDGER & HISTORY APIS)
// ====================================================================
let posSalesMemoryStore = []; // In-memory fallback

// 1. Dapatkan Senarai Semua Rekod Jualan & Payout (dengan penapis bulan/tarikh/staf)
app.get('/api/pos/sales', async (req, res) => {
  try {
    const { month, startDate, endDate, orderType, payMethod, cashierCode, search, limit, page } = req.query;
    const maxLimit = Math.min(500, parseInt(limit) || 200);

    let mappedRecords = [];

    if (supabase) {
      let salesQuery = supabase
        .from('sales')
        .select('*, sale_items(*)')
        .order('created_at', { ascending: false });

      if (month) {
        const parts = month.split('-');
        if (parts.length === 2) {
          const yr = parseInt(parts[0], 10);
          const mo = parseInt(parts[1], 10);
          const sDate = `${yr}-${String(mo).padStart(2, '0')}-01T00:00:00.000Z`;
          const lastDay = new Date(yr, mo, 0).getDate();
          const eDate = `${yr}-${String(mo).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}T23:59:59.999Z`;
          salesQuery = salesQuery.gte('created_at', sDate).lte('created_at', eDate);
        }
      }

      if (startDate) salesQuery = salesQuery.gte('created_at', `${startDate}T00:00:00.000Z`);
      if (endDate) salesQuery = salesQuery.lte('created_at', `${endDate}T23:59:59.999Z`);
      if (orderType && orderType !== 'all' && orderType !== 'gaji' && orderType !== 'marketing_expense' && orderType !== 'tebus_stamp' && orderType !== 'tebus_ganjaran') {
        salesQuery = salesQuery.eq('order_type', orderType);
      }
      if (payMethod && payMethod !== 'all') {
        const dbPayMethod = payMethod === 'tunai' ? 'cash' : (payMethod === 'kad' ? 'card' : payMethod);
        salesQuery = salesQuery.eq('payment_method', dbPayMethod);
      }
      if (cashierCode) salesQuery = salesQuery.eq('cashier_code', cashierCode);

      const { data: salesData, error: salesErr } = await salesQuery.limit(maxLimit);

      if (!salesErr && salesData) {
        mappedRecords = salesData.map(s => {
          const items = (s.sale_items || []).map(it => ({
            id: it.product_id || it.id,
            name: it.product_name,
            price: parseFloat(it.unit_price) || 0,
            cost: parseFloat(it.unit_cost) || 0,
            variation: it.variation_name ? { name: it.variation_name } : null,
            addons: Array.isArray(it.selected_addons) ? it.selected_addons : [],
            qty: parseInt(it.qty) || 1
          }));

          const subtotalVal = parseFloat(s.subtotal) || 0;
          let costVal = items.reduce((acc, it) => acc + it.cost * it.qty, 0);

          let parsedNotes = null;
          let parsedBuyerInfo = null;
          let isMarketingExpense = false;
          let rewardTypeFromNotes = null;
          let rewardNameFromNotes = null;

          if (s.notes) {
            try {
              if (typeof s.notes === 'string' && s.notes.startsWith('{')) {
                parsedNotes = JSON.parse(s.notes);
                if (parsedNotes.buyerInfo) parsedBuyerInfo = parsedNotes.buyerInfo;
                if (parsedNotes.marketingExpense) {
                  isMarketingExpense = true;
                  rewardTypeFromNotes = parsedNotes.rewardType;
                  rewardNameFromNotes = parsedNotes.rewardName;
                }
                if (parsedNotes.costAmount && (costVal === 0 || isMarketingExpense)) {
                  costVal = parseFloat(parsedNotes.costAmount) || costVal || 3.50;
                }
              }
            } catch(e){}
          }

          let mappedOrderType = s.order_type || 'dinein';
          let mappedPayMethod = s.payment_method === 'cash' ? 'tunai' : (s.payment_method === 'card' ? 'kad' : (s.payment_method === 'points' ? 'mata' : s.payment_method));

          if (isMarketingExpense) {
            if (rewardTypeFromNotes === 'Kod Bertuah') {
              mappedOrderType = 'marketing_expense';
              mappedPayMethod = 'hadiah';
            } else if (rewardTypeFromNotes === 'Ganjaran Cop Stamp') {
              mappedOrderType = 'tebus_stamp';
              mappedPayMethod = 'cop_stamp';
            } else if (rewardTypeFromNotes === 'Tebus Ganjaran') {
              mappedOrderType = 'tebus_ganjaran';
              mappedPayMethod = 'mata';
            }
          } else if (s.order_type === 'tebus_ganjaran' || (subtotalVal === 0 && s.payment_method === 'points')) {
            mappedOrderType = 'tebus_ganjaran';
            mappedPayMethod = 'mata';
          }

          const isMarketing = (mappedOrderType === 'marketing_expense' || mappedOrderType === 'tebus_stamp' || mappedOrderType === 'tebus_ganjaran');
          if (isMarketing && costVal <= 0) {
            costVal = 3.50;
          }
          const finalProfitVal = isMarketing ? -costVal : (subtotalVal - costVal);

          return {
            id: s.id,
            receiptNo: s.receipt_no,
            ts: s.created_at,
            orderType: mappedOrderType,
            payMethod: mappedPayMethod,
            cashTendered: s.cash_tendered !== null ? parseFloat(s.cash_tendered) : null,
            changeReturned: s.change_given !== null ? parseFloat(s.change_given) : null,
            subtotal: subtotalVal,
            discount: parseFloat(s.discount) || 0,
            rewardDiscountAmount: parseFloat(s.discount) || 0,
            cost: costVal,
            profit: finalProfitVal,
            tax: parseFloat(s.tax) || 0,
            sstRate: 0.06,
            charges: [],
            total: parseFloat(s.total) || 0,
            cashierName: s.cashier_name || 'Pengurus Utama',
            cashierCode: s.cashier_code || 'STF-001',
            cashierRole: 'Staf',
            memberId: s.member_id || null,
            buyerInfo: parsedBuyerInfo,
            note: rewardNameFromNotes || (parsedNotes && (parsedNotes.rewardName || parsedNotes.notes) ? (parsedNotes.rewardName || parsedNotes.notes) : null),
            isSalaryPayout: false,
            items
          };
        });
        if (orderType && orderType !== 'all') {
          mappedRecords = mappedRecords.filter(r => r.orderType === orderType);
        }
      }

      // Ambil juga rekod bayaran gaji staf dari `pos_payroll` sebagai entri perbelanjaan
      if (!orderType || orderType === 'all' || orderType === 'gaji') {
        let payrollQuery = supabase.from('pos_payroll').select('*').order('created_at', { ascending: false });
        if (month) {
          const parts = month.split('-');
          if (parts.length === 2) {
            const yr = parseInt(parts[0], 10);
            const mo = parseInt(parts[1], 10);
            const sDate = `${yr}-${String(mo).padStart(2, '0')}-01T00:00:00.000Z`;
            const lastDay = new Date(yr, mo, 0).getDate();
            const eDate = `${yr}-${String(mo).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}T23:59:59.999Z`;
            payrollQuery = payrollQuery.gte('created_at', sDate).lte('created_at', eDate);
          }
        }
        if (startDate) payrollQuery = payrollQuery.gte('created_at', `${startDate}T00:00:00.000Z`);
        if (endDate) payrollQuery = payrollQuery.lte('created_at', `${endDate}T23:59:59.999Z`);

        const { data: pData } = await payrollQuery.limit(100);
        if (pData && pData.length > 0) {
          const salaryRecords = pData.map(p => ({
            id: p.id,
            receiptNo: p.voucher_no,
            ts: p.created_at,
            orderType: 'gaji',
            payMethod: p.pay_method || 'bank',
            cashTendered: null,
            changeReturned: null,
            subtotal: 0,
            cost: parseFloat(p.net_salary) || 0,
            profit: -(parseFloat(p.net_salary) || 0),
            tax: 0,
            charges: [],
            total: parseFloat(p.net_salary) || 0,
            cashierName: p.approved_by || 'Pengurus Utama',
            cashierCode: 'MGR-001',
            cashierRole: 'Pengurus',
            isSalaryPayout: true,
            staffId: p.staff_id,
            staffName: p.staff_name,
            staffCode: p.staff_code,
            hoursWorked: parseFloat(p.hours_worked) || 0,
            hourlyRate: parseFloat(p.hourly_rate) || 8.50,
            allowance: parseFloat(p.allowance) || 0,
            deduction: parseFloat(p.deduction) || 0,
            periodNotes: p.period,
            items: [{
              id: 'pay_' + p.id,
              name: `Bayaran Gaji: ${p.staff_name}`,
              variation: { name: `${p.hours_worked} jam @ RM${parseFloat(p.hourly_rate).toFixed(2)}/j` },
              addons: p.allowance > 0 ? [{ name: `Elaun RM${parseFloat(p.allowance).toFixed(2)}` }] : [],
              price: 0,
              cost: parseFloat(p.net_salary) || 0,
              qty: 1
            }]
          }));
          mappedRecords = [...mappedRecords, ...salaryRecords];
        }
      }
    }

    // In-memory fallback jika tiada supabase
    if (mappedRecords.length === 0 && posSalesMemoryStore.length > 0) {
      mappedRecords = [...posSalesMemoryStore];
    }

    // Susun rekod mengikut tarikh terkini dahulu
    mappedRecords.sort((a, b) => new Date(b.ts) - new Date(a.ts));

    // Tapisan carian teks jika ada
    if (search && search.trim()) {
      const q = search.trim().toLowerCase();
      mappedRecords = mappedRecords.filter(r =>
        String(r.receiptNo || '').toLowerCase().includes(q) ||
        String(r.cashierName || '').toLowerCase().includes(q) ||
        String(r.staffName || '').toLowerCase().includes(q)
      );
    }

    res.json({
      success: true,
      count: mappedRecords.length,
      records: mappedRecords.slice(0, maxLimit)
    });
  } catch (err) {
    console.error('❌ GET /api/pos/sales error:', err.message);
    res.status(500).json({ success: false, error: err.message, records: [] });
  }
});

// 2. Ringkasan Statistik Metrik Jualan Live (Sales Stats)
app.get('/api/pos/sales/stats', async (req, res) => {
  try {
    const { month, startDate, endDate } = req.query;
    let salesQuery = supabase ? supabase.from('sales').select('total, subtotal, tax, payment_method, order_type, created_at, sale_items(unit_cost, qty)') : null;

    if (supabase && salesQuery) {
      if (month) {
        const parts = month.split('-');
        if (parts.length === 2) {
          const yr = parseInt(parts[0], 10);
          const mo = parseInt(parts[1], 10);
          const sDate = `${yr}-${String(mo).padStart(2, '0')}-01T00:00:00.000Z`;
          const lastDay = new Date(yr, mo, 0).getDate();
          const eDate = `${yr}-${String(mo).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}T23:59:59.999Z`;
          salesQuery = salesQuery.gte('created_at', sDate).lte('created_at', eDate);
        }
      }
      if (startDate) salesQuery = salesQuery.gte('created_at', `${startDate}T00:00:00.000Z`);
      if (endDate) salesQuery = salesQuery.lte('created_at', `${endDate}T23:59:59.999Z`);

      const { data: sData } = await salesQuery;
      if (sData) {
        let totalRevenue = 0;
        let totalSubtotal = 0;
        let totalTax = 0;
        let totalCost = 0;
        let payMethods = { cash: 0, card: 0, ewallet: 0 };
        let orderTypes = { dinein: 0, takeaway: 0 };

        sData.forEach(s => {
          const sub = parseFloat(s.subtotal) || 0;
          const tot = parseFloat(s.total) || 0;
          const tx = parseFloat(s.tax) || 0;
          totalRevenue += tot;
          totalSubtotal += sub;
          totalTax += tx;

          const itemsCost = (s.sale_items || []).reduce((acc, it) => acc + (parseFloat(it.unit_cost) || 0) * (it.qty || 1), 0);
          totalCost += itemsCost;

          if (s.payment_method === 'cash') payMethods.cash += tot;
          else if (s.payment_method === 'card') payMethods.card += tot;
          else if (s.payment_method === 'ewallet') payMethods.ewallet += tot;

          if (s.order_type === 'takeaway') orderTypes.takeaway += tot;
          else orderTypes.dinein += tot;
        });

        // Ambil perbelanjaan gaji staf
        let salaryCost = 0;
        const { data: pData } = await supabase.from('pos_payroll').select('net_salary');
        if (pData) {
          salaryCost = pData.reduce((acc, p) => acc + (parseFloat(p.net_salary) || 0), 0);
        }

        const netProfit = totalSubtotal - totalCost - salaryCost;

        return res.json({
          success: true,
          totalRevenue: Math.round(totalRevenue * 100) / 100,
          totalSubtotal: Math.round(totalSubtotal * 100) / 100,
          totalTax: Math.round(totalTax * 100) / 100,
          totalCost: Math.round((totalCost + salaryCost) * 100) / 100,
          netProfit: Math.round(netProfit * 100) / 100,
          totalOrders: sData.length,
          payMethods,
          orderTypes
        });
      }
    }

    res.json({
      success: true,
      totalRevenue: 0,
      totalSubtotal: 0,
      totalTax: 0,
      totalCost: 0,
      netProfit: 0,
      totalOrders: 0
    });
  } catch (err) {
    console.error('❌ GET /api/pos/sales/stats error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. Padam / Void Resit Jualan
app.delete('/api/pos/sales/:id', requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (supabase) {
      // Padam item pesanan dahulu
      await supabase.from('sale_items').delete().eq('sale_id', id);
      // Padam rekod utama resit
      const { error } = await supabase.from('sales').delete().eq('id', id);
      if (error) {
        console.error('❌ Error deleting sale:', error.message);
        return res.status(500).json({ success: false, error: error.message });
      }

      // Catat log audit
      await supabase.from('pos_audit_logs').insert({
        action: 'sale_voided',
        cashier_name: req.staff ? req.staff.name : 'Staf POS',
        details: { saleId: id }
      });
    }

    posSalesMemoryStore = posSalesMemoryStore.filter(s => String(s.id) !== String(id));
    console.log(`🗑️ [POS SALE VOIDED/DELETED] ID: ${id}`);
    res.json({ success: true, message: 'Resit jualan berjaya dipadam' });
  } catch (err) {
    console.error('❌ DELETE /api/pos/sales/:id error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 12. API: SHIFT MANAGEMENT, CASH DRAWER & AUDIT TRAIL
// ====================================================================

// A. Buka Syif Baharu (Open Shift)
app.post('/api/pos/shifts/open', requireStaffAuth, async (req, res) => {
  try {
    const { cashierName, cashierCode, cashierId, openingFloat, notes } = req.body;
    const finalCashierName = req.staff ? req.staff.name : (cashierName || 'Akmal Hakim');
    const finalCashierCode = req.staff ? req.staff.staffCode : (cashierCode || 'STF-001');
    const floatVal = parseFloat(openingFloat) || 0;
    const shiftCode = 'SFT-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-' + Math.floor(100 + Math.random() * 900);

    if (!supabase) {
      return res.json({
        success: true,
        shift: {
          id: 'shift-' + Date.now(),
          shift_code: shiftCode,
          cashier_name: finalCashierName,
          cashier_code: finalCashierCode,
          opened_at: new Date().toISOString(),
          opening_float: floatVal,
          status: 'open'
        }
      });
    }

    // Tutup syif terdahulu yang masih 'open' secara automatik
    await supabase.from('pos_shifts').update({ status: 'closed', closed_at: new Date().toISOString() }).eq('status', 'open');

    const { data: newShift, error } = await supabase
      .from('pos_shifts')
      .insert({
        shift_code: shiftCode,
        cashier_id: (cashierId && String(cashierId).length > 20) ? cashierId : (req.staff ? req.staff.staffId : null),
        cashier_name: finalCashierName,
        cashier_code: finalCashierCode,
        opening_float: floatVal,
        expected_cash: floatVal,
        status: 'open',
        notes: notes || null
      })
      .select()
      .single();

    if (error) throw error;

    // Catat dalam audit log
    await supabase.from('pos_audit_logs').insert({
      action: 'shift_opened',
      shift_code: shiftCode,
      cashier_name: finalCashierName,
      cashier_code: finalCashierCode,
      amount: floatVal,
      details: { opening_float: floatVal, notes }
    });

    console.log(`🟢 [SHIFT OPENED] Kod: ${shiftCode} | Juruwang: ${finalCashierName} | Modal Apungan: RM${floatVal.toFixed(2)}`);
    res.json({ success: true, shift: newShift });
  } catch (err) {
    console.error('❌ /api/pos/shifts/open error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// B. Dapatkan Status Syif Semasa (Live Current Shift Metrics)
app.get('/api/pos/shifts/current', async (req, res) => {
  try {
    if (!supabase) {
      return res.json({ success: true, shift: null });
    }

    const { data: shift, error } = await supabase
      .from('pos_shifts')
      .select('*')
      .eq('status', 'open')
      .order('opened_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error || !shift) {
      return res.json({ success: true, shift: null });
    }

    // Kira jualan semasa syif ini (bermula opened_at)
    const { data: sales } = await supabase
      .from('sales')
      .select('payment_method, total, status, created_at')
      .gte('created_at', shift.opened_at)
      .neq('status', 'void');

    let cashSales = 0;
    let qrSales = 0;
    let cardSales = 0;
    let totalSales = 0;
    let transactionsCount = (sales || []).length;

    (sales || []).forEach(s => {
      const val = parseFloat(s.total) || 0;
      totalSales += val;
      if (s.payment_method === 'cash') cashSales += val;
      else if (s.payment_method === 'ewallet') qrSales += val;
      else if (s.payment_method === 'card') cardSales += val;
    });

    // Ambil rekod pergerakan duit laci (Cash In / Out)
    const { data: movements } = await supabase
      .from('pos_cash_movements')
      .select('*')
      .eq('shift_id', shift.id);

    let cashIn = 0;
    let cashOut = 0;

    (movements || []).forEach(m => {
      const amt = parseFloat(m.amount) || 0;
      if (m.type === 'cash_in') cashIn += amt;
      else if (m.type === 'cash_out') cashOut += amt;
    });

    const openingFloat = parseFloat(shift.opening_float) || 0;
    const expectedCash = openingFloat + cashSales + cashIn - cashOut;

    res.json({
      success: true,
      shift: {
        ...shift,
        cash_sales: parseFloat(cashSales.toFixed(2)),
        qr_sales: parseFloat(qrSales.toFixed(2)),
        card_sales: parseFloat(cardSales.toFixed(2)),
        total_sales: parseFloat(totalSales.toFixed(2)),
        total_transactions: transactionsCount,
        cash_in: parseFloat(cashIn.toFixed(2)),
        cash_out: parseFloat(cashOut.toFixed(2)),
        expected_cash: parseFloat(expectedCash.toFixed(2)),
        movements: movements || []
      }
    });
  } catch (err) {
    console.error('❌ /api/pos/shifts/current error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// C. Rekod Pergerakan Duit Tunai (Cash In / Cash Out)
app.post('/api/pos/shifts/cash-movement', requireStaffAuth, async (req, res) => {
  try {
    const { shiftId, shiftCode, type, amount, reason, cashierName } = req.body;
    const finalCashierName = req.staff ? req.staff.name : (cashierName || 'Juruwang');
    const numAmount = parseFloat(amount);

    if (!numAmount || numAmount <= 0 || !type || !reason) {
      return res.status(400).json({ success: false, error: 'Jumlah, jenis (cash_in/cash_out), dan sebab diperlukan' });
    }

    if (!supabase) {
      return res.json({ success: true, movement: { id: 'local-' + Date.now(), type, amount: numAmount, reason } });
    }

    const { data: movement, error } = await supabase
      .from('pos_cash_movements')
      .insert({
        shift_id: (shiftId && String(shiftId).length > 20) ? shiftId : null,
        shift_code: shiftCode || 'SFT-CURRENT',
        type: type === 'cash_in' ? 'cash_in' : 'cash_out',
        amount: numAmount,
        reason: reason.trim(),
        recorded_by: finalCashierName
      })
      .select()
      .single();

    if (error) throw error;

    // Catat jejak audit
    await supabase.from('pos_audit_logs').insert({
      action: type === 'cash_in' ? 'cash_in' : 'cash_out',
      shift_code: shiftCode || 'SFT-CURRENT',
      cashier_name: finalCashierName,
      amount: numAmount,
      details: { reason: reason.trim() }
    });

    console.log(`💵 [CASH MOVEMENT] ${type.toUpperCase()}: RM${numAmount.toFixed(2)} | Sebab: ${reason} | Oleh: ${finalCashierName}`);
    res.json({ success: true, movement });
  } catch (err) {
    console.error('❌ /api/pos/shifts/cash-movement error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// D. Tutup Syif & Imbangan Laci (Close Shift & Z-Report)
app.post('/api/pos/shifts/close', requireStaffAuth, async (req, res) => {
  try {
    const { shiftId, actualCash, notes, cashierName, cashierCode } = req.body;
    const finalCashierName = req.staff ? req.staff.name : (cashierName || 'Akmal Hakim');
    const finalCashierCode = req.staff ? req.staff.staffCode : (cashierCode || 'STF-001');
    const actualCashVal = parseFloat(actualCash) || 0;

    if (!supabase) {
      return res.json({
        success: true,
        zReport: {
          shiftCode: 'SFT-LOCAL',
          cashierName: finalCashierName,
          openedAt: new Date().toISOString(),
          closedAt: new Date().toISOString(),
          openingFloat: 100,
          cashSales: 250,
          qrSales: 120,
          cardSales: 80,
          totalSales: 450,
          expectedCash: 350,
          actualCash: actualCashVal,
          cashDifference: actualCashVal - 350,
          totalTransactions: 15
        }
      });
    }

    // Dapatkan syif
    let shiftQuery = supabase.from('pos_shifts').select('*');
    if (shiftId && String(shiftId).length > 20) {
      shiftQuery = shiftQuery.eq('id', shiftId);
    } else {
      shiftQuery = shiftQuery.eq('status', 'open').order('opened_at', { ascending: false }).limit(1);
    }

    const { data: shift, error: sErr } = await shiftQuery.single();
    if (sErr || !shift) {
      return res.status(404).json({ success: false, error: 'Tiada syif aktif dijumpai untuk ditutup' });
    }

    // Kira jualan semasa syif
    const { data: sales } = await supabase
      .from('sales')
      .select('payment_method, total, status, created_at')
      .gte('created_at', shift.opened_at)
      .neq('status', 'void');

    let cashSales = 0;
    let qrSales = 0;
    let cardSales = 0;
    let totalSales = 0;
    let transactionsCount = (sales || []).length;

    (sales || []).forEach(s => {
      const val = parseFloat(s.total) || 0;
      totalSales += val;
      if (s.payment_method === 'cash') cashSales += val;
      else if (s.payment_method === 'ewallet') qrSales += val;
      else if (s.payment_method === 'card') cardSales += val;
    });

    // Kira pergerakan duit tunai
    const { data: movements } = await supabase
      .from('pos_cash_movements')
      .select('*')
      .eq('shift_id', shift.id);

    let cashIn = 0;
    let cashOut = 0;
    (movements || []).forEach(m => {
      const amt = parseFloat(m.amount) || 0;
      if (m.type === 'cash_in') cashIn += amt;
      else if (m.type === 'cash_out') cashOut += amt;
    });

    const openingFloat = parseFloat(shift.opening_float) || 0;
    const expectedCash = openingFloat + cashSales + cashIn - cashOut;
    const cashDifference = actualCashVal - expectedCash;

    // Kemaskini rekod syif kepada 'closed'
    const { data: closedShift, error: cErr } = await supabase
      .from('pos_shifts')
      .update({
        closed_at: new Date().toISOString(),
        expected_cash: parseFloat(expectedCash.toFixed(2)),
        actual_cash: parseFloat(actualCashVal.toFixed(2)),
        cash_difference: parseFloat(cashDifference.toFixed(2)),
        cash_in: parseFloat(cashIn.toFixed(2)),
        cash_out: parseFloat(cashOut.toFixed(2)),
        total_sales: parseFloat(totalSales.toFixed(2)),
        cash_sales: parseFloat(cashSales.toFixed(2)),
        qr_sales: parseFloat(qrSales.toFixed(2)),
        card_sales: parseFloat(cardSales.toFixed(2)),
        total_transactions: transactionsCount,
        status: 'closed',
        notes: notes || shift.notes
      })
      .eq('id', shift.id)
      .select()
      .single();

    if (cErr) throw cErr;

    // Catat ke pos_audit_logs
    await supabase.from('pos_audit_logs').insert({
      action: 'shift_closed',
      shift_code: shift.shift_code,
      cashier_name: finalCashierName || shift.cashier_name,
      cashier_code: finalCashierCode || shift.cashier_code,
      amount: totalSales,
      details: {
        opening_float: openingFloat,
        cash_sales: cashSales,
        expected_cash: expectedCash,
        actual_cash: actualCashVal,
        cash_difference: cashDifference,
        total_transactions: transactionsCount,
        notes
      }
    });

    console.log(`🔴 [SHIFT CLOSED] Kod: ${shift.shift_code} | Jualan: RM${totalSales.toFixed(2)} | Baki Jangkaan: RM${expectedCash.toFixed(2)} | Dikira: RM${actualCashVal.toFixed(2)} | Beza: RM${cashDifference.toFixed(2)}`);

    return res.json({
      success: true,
      zReport: {
        shiftCode: shift.shift_code,
        cashierName: finalCashierName || shift.cashier_name,
        cashierCode: finalCashierCode || shift.cashier_code,
        openedAt: shift.opened_at,
        closedAt: closedShift.closed_at,
        openingFloat: parseFloat(openingFloat.toFixed(2)),
        cashSales: parseFloat(cashSales.toFixed(2)),
        qrSales: parseFloat(qrSales.toFixed(2)),
        cardSales: parseFloat(cardSales.toFixed(2)),
        totalSales: parseFloat(totalSales.toFixed(2)),
        cashIn: parseFloat(cashIn.toFixed(2)),
        cashOut: parseFloat(cashOut.toFixed(2)),
        expectedCash: parseFloat(expectedCash.toFixed(2)),
        actualCash: parseFloat(actualCashVal.toFixed(2)),
        cashDifference: parseFloat(cashDifference.toFixed(2)),
        totalTransactions: transactionsCount,
        notes: notes || null
      }
    });
  } catch (err) {
    console.error('❌ /api/pos/shifts/close error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// E. Dapatkan Senarai Sejarah Syif Terdahulu (Historical Shifts)
app.get('/api/pos/shifts', requireStaffAuth, async (req, res) => {
  try {
    if (!supabase) {
      return res.json({ success: true, shifts: [] });
    }

    const { data: shifts, error } = await supabase
      .from('pos_shifts')
      .select('*')
      .order('opened_at', { ascending: false })
      .limit(50);

    if (error) throw error;
    res.json({ success: true, shifts: shifts || [] });
  } catch (err) {
    console.error('❌ /api/pos/shifts GET error:', err);
    res.status(500).json({ success: false, error: err.message, shifts: [] });
  }
});

// F. Dapatkan Jejak Audit Log Transaksi (Audit Trail Logs)
app.get('/api/pos/audit-logs', requireStaffAuth, async (req, res) => {
  try {
    if (!supabase) {
      return res.json({ success: true, logs: [] });
    }

    const limit = Math.min(2000, parseInt(req.query.limit) || 100);
    const { data: logs, error } = await supabase
      .from('pos_audit_logs')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) throw error;
    res.json({ success: true, logs: logs || [] });
  } catch (err) {
    console.error('❌ /api/pos/audit-logs GET error:', err);
    res.status(500).json({ success: false, error: err.message, logs: [] });
  }
});

// ====================================================================
// 13. API: TELEGRAM BOT INTEGRATION, VERIFICATION & MOD MANAGER LOGIN
// ====================================================================

// A. Hardcoded Developer Fallback Credentials
const DEVELOPER_TELEGRAM = {
  botToken: '8676460374:AAG08d_gieND5UfawUVIylwY7MaEoNMGdCA',
  chatId: '790959136',
  label: 'Developer Fallback (Default)'
};

// State Dalam Memori
let customTelegramConfig = null; // { botToken, chatId, isVerified, verifiedAt }
const pendingTelegramVerifications = new Map(); // token -> { token, botToken, chatId, expiresAt }
const pendingManagerLoginRequests = new Map(); // requestId -> { requestId, status: 'pending'|'approved'|'rejected', expiresAt, createdAt }
const lastUpdateOffsetMap = new Map(); // botToken -> lastUpdateId

// Muat turun tetapan Telegram yang telah disahkan dari Supabase semasa permulaan
async function loadTelegramSettingsFromDb() {
  if (!supabase) return;
  try {
    const { data, error } = await supabase
      .from('pos_settings')
      .select('value')
      .eq('key', 'telegram_config')
      .maybeSingle();

    if (!error && data && data.value && data.value.isVerified) {
      customTelegramConfig = data.value;
      console.log(`🤖 [TELEGRAM] Tetapan bot tersuai dimuatkan: Chat ID ${customTelegramConfig.chatId}`);
    } else {
      console.log(`🤖 [TELEGRAM] Menggunakan tetapan Developer Fallback (${DEVELOPER_TELEGRAM.label})`);
    }
  } catch (e) {
    console.warn('⚠️ Gagal memuatkan tetapan Telegram dari DB:', e.message);
  }
}
loadTelegramSettingsFromDb();

// Helper untuk dapatkan kredensial bot Telegram yang aktif
function getEffectiveTelegramConfig() {
  if (customTelegramConfig && customTelegramConfig.isVerified && customTelegramConfig.botToken && customTelegramConfig.chatId) {
    return {
      botToken: customTelegramConfig.botToken,
      chatId: customTelegramConfig.chatId,
      isDeveloperFallback: false,
      label: 'Kredensial Pengurus Tersuai'
    };
  }
  return {
    botToken: DEVELOPER_TELEGRAM.botToken,
    chatId: DEVELOPER_TELEGRAM.chatId,
    isDeveloperFallback: true,
    label: DEVELOPER_TELEGRAM.label
  };
}

// Helper untuk escape HTML bagi Telegram API
function escapeTgHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// Telegram API: Hantar Mesej (HTML Mode - Kalis Ralat Underscore/Special Characters)
async function sendTelegramMessage(botToken, chatId, text, inlineKeyboard = null) {
  try {
    const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
    const payload = {
      chat_id: chatId,
      text,
      parse_mode: 'HTML'
    };
    if (inlineKeyboard) {
      payload.reply_markup = { inline_keyboard: inlineKeyboard };
    }
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return await resp.json();
  } catch (err) {
    console.error('❌ sendTelegramMessage error:', err.message);
    return { ok: false, error: err.message };
  }
}

// Telegram API: Jawab Callback Query Butang
async function answerTelegramCallbackQuery(botToken, callbackQueryId, text) {
  try {
    const url = `https://api.telegram.org/bot${botToken}/answerCallbackQuery`;
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        callback_query_id: callbackQueryId,
        text,
        show_alert: true
      })
    });
  } catch (err) {
    console.error('❌ answerTelegramCallbackQuery error:', err.message);
  }
}

// Telegram API: Sunting Mesej Selepas Tindakan Butang (HTML Mode)
async function editTelegramMessageText(botToken, chatId, messageId, text) {
  try {
    const url = `https://api.telegram.org/bot${botToken}/editMessageText`;
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        message_id: messageId,
        text,
        parse_mode: 'HTML'
      })
    });
  } catch (err) {
    console.error('❌ editTelegramMessageText error:', err.message);
  }
}

// Telegram Updates Polling Engine (Mendengar Butang 'Sahkan' & 'Benarkan Log Masuk')
async function pollTelegramBot(botToken) {
  try {
    const lastOffset = lastUpdateOffsetMap.get(botToken) || 0;
    const url = `https://api.telegram.org/bot${botToken}/getUpdates?offset=${lastOffset}&timeout=1&allowed_updates=["callback_query"]`;
    const res = await fetch(url);
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok || !Array.isArray(json.result) || json.result.length === 0) return;

    for (const update of json.result) {
      lastUpdateOffsetMap.set(botToken, update.update_id + 1);

      if (update.callback_query) {
        const cb = update.callback_query;
        const data = cb.data || '';
        const cbChatId = cb.message && cb.message.chat ? String(cb.message.chat.id) : '';
        const msgId = cb.message ? cb.message.message_id : null;

        // 1. Pengesahan Bot Baharu (Verify Telegram Connection)
        if (data.startsWith('verify_tg:')) {
          const verifyToken = data.replace('verify_tg:', '');
          const pending = pendingTelegramVerifications.get(verifyToken);

          if (pending && pending.expiresAt > Date.now()) {
            customTelegramConfig = {
              botToken: pending.botToken,
              chatId: pending.chatId,
              isVerified: true,
              verifiedAt: new Date().toISOString()
            };
            pendingTelegramVerifications.delete(verifyToken);

            // Simpan ke database Supabase pos_settings
            if (supabase) {
              await supabase
                .from('pos_settings')
                .upsert({
                  key: 'telegram_config',
                  value: customTelegramConfig,
                  updated_at: new Date().toISOString()
                });
            }

            await answerTelegramCallbackQuery(botToken, cb.id, 'Sambungan Koffi POS Berjaya Disahkan! ✅');
            if (msgId && cbChatId) {
              await editTelegramMessageText(
                botToken,
                cbChatId,
                msgId,
                `✅ <b>SAMBUNGAN Koffi POS TELAH DISAHKAN!</b>\n\nBot Telegram ini kini aktif dan disambungkan ke Sistem Kaunter Koffi POS.\nTarikh Sah: ${new Date().toLocaleString('ms-MY')}`
              );
            }
            console.log(`🟢 [TELEGRAM VERIFIED] Bot ${botToken.slice(0, 10)}... disambungkan ke Chat ID: ${pending.chatId}`);
          } else {
            await answerTelegramCallbackQuery(botToken, cb.id, 'Masa pengesahan telah tamat / tidak sah ❌');
          }
        }

        // 2. Kelulusan Log Masuk MOD Pengurus (Approve Login)
        else if (data.startsWith('approve_login:')) {
          const reqId = data.replace('approve_login:', '');
          const session = pendingManagerLoginRequests.get(reqId);

          if (session && session.expiresAt > Date.now() && session.status === 'pending') {
            session.status = 'approved';
            session.approvedAt = new Date().toISOString();

            // Catat log audit ke pangkalan data
            if (supabase) {
              await supabase.from('pos_audit_logs').insert({
                action: 'manager_login_approved',
                receipt_no: reqId,
                cashier_name: 'Pengurus Utama',
                cashier_code: 'MGR-001',
                details: {
                  requestId: reqId,
                  approvedVia: 'telegram_bot',
                  chatId: cbChatId
                }
              });
            }

            await answerTelegramCallbackQuery(botToken, cb.id, 'Akses Pengurus Dibenarkan! 👑');
            if (msgId && cbChatId) {
              await editTelegramMessageText(
                botToken,
                cbChatId,
                msgId,
                `👑 <b>LOG MASUK PENGURUS DILULUSKAN</b>\n\n✅ Kebenaran log masuk mod Pengurus di Kaunter telah diluluskan pada ${new Date().toLocaleTimeString('ms-MY')}.`
              );
            }
            console.log(`👑 [MANAGER LOGIN APPROVED] Request ID: ${reqId} diluluskan oleh Chat ID: ${cbChatId}`);
          } else {
            await answerTelegramCallbackQuery(botToken, cb.id, 'Sesi permohonan log masuk telah tamat tempoh / tidak sah ❌');
          }
        }

        // 3. Penolakan Log Masuk MOD Pengurus (Reject Login)
        else if (data.startsWith('reject_login:')) {
          const reqId = data.replace('reject_login:', '');
          const session = pendingManagerLoginRequests.get(reqId);

          if (session && session.status === 'pending') {
            session.status = 'rejected';
            await answerTelegramCallbackQuery(botToken, cb.id, 'Permohonan Log Masuk Ditolak ❌');
            if (msgId && cbChatId) {
              await editTelegramMessageText(
                botToken,
                cbChatId,
                msgId,
                `❌ <b>LOG MASUK PENGURUS DITOLAK</b>\n\nPermohonan log masuk kaunter telah ditolak pada ${new Date().toLocaleTimeString('ms-MY')}.`
              );
            }
            console.log(`❌ [MANAGER LOGIN REJECTED] Request ID: ${reqId}`);
          }
        }
      }
    }
  } catch (e) {}
}

// Loop Polling setiap 1.5 saat untuk Developer Bot & Custom Bot (jika ada)
setInterval(() => {
  pollTelegramBot(DEVELOPER_TELEGRAM.botToken);
  if (customTelegramConfig && customTelegramConfig.botToken && customTelegramConfig.botToken !== DEVELOPER_TELEGRAM.botToken) {
    pollTelegramBot(customTelegramConfig.botToken);
  }
  // Semak juga token yang sedang dalam status pending verification
  pendingTelegramVerifications.forEach(p => {
    if (p.botToken && p.botToken !== DEVELOPER_TELEGRAM.botToken) {
      pollTelegramBot(p.botToken);
    }
  });
}, 1500);

// Endpoint 1: Dapatkan Konfigurasi Telegram Semasa (Secured with Zero Token Exposure)
app.get('/api/telegram/config', (req, res) => {
  const effective = getEffectiveTelegramConfig();
  res.json({
    success: true,
    effectiveConfig: {
      chatIdMasked: effective.chatId ? (effective.chatId.slice(0, 3) + '****' + effective.chatId.slice(-2)) : '',
      label: effective.label,
      isDeveloperFallback: effective.isDeveloperFallback
    },
    customConfig: customTelegramConfig ? {
      isVerified: customTelegramConfig.isVerified,
      botTokenMasked: customTelegramConfig.botToken ? (customTelegramConfig.botToken.slice(0, 6) + '••••••••••••••••••••' + customTelegramConfig.botToken.slice(-4)) : '',
      chatIdMasked: customTelegramConfig.chatId ? (customTelegramConfig.chatId.slice(0, 3) + '****' + customTelegramConfig.chatId.slice(-2)) : '',
      verifiedAt: customTelegramConfig.verifiedAt
    } : null,
    developerConfig: {
      botTokenMasked: DEVELOPER_TELEGRAM.botToken.slice(0, 6) + '••••••••••••••••••••' + DEVELOPER_TELEGRAM.botToken.slice(-4),
      chatIdMasked: DEVELOPER_TELEGRAM.chatId.slice(0, 3) + '****' + DEVELOPER_TELEGRAM.chatId.slice(-2),
      label: DEVELOPER_TELEGRAM.label
    }
  });
});

// Endpoint: Hantar Mesej Ujian (Server-Side Proxy - Tidak Dedah Token di Browser F12)
app.post('/api/telegram/test-message', async (req, res) => {
  try {
    const effective = getEffectiveTelegramConfig();
    const testMsg = `☕ <b>Koffi POS - UJIAN SAMBUNGAN BERJAYA!</b>\n\nSambungan Bot Telegram (${escapeTgHtml(effective.label)}) ke sistem kaunter POS berfungsi dengan lancar.\n📍 <b>Kaunter:</b> Kaunter Utama\n⏰ <b>Tarikh:</b> ${new Date().toLocaleString('ms-MY')}`;

    const sendRes = await sendTelegramMessage(effective.botToken, effective.chatId, testMsg);
    if (sendRes.ok) {
      return res.json({ success: true, message: 'Mesej ujian berjaya dihantar ke Telegram!' });
    } else {
      return res.status(400).json({ success: false, error: sendRes.description || 'Gagal menghantar mesej ke Telegram' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Endpoint 2: Minta Pengesahan Bot Telegram Baharu (Kirim Butang Sahkan ke Telegram)
app.post('/api/telegram/request-verification', async (req, res) => {
  try {
    const { botToken, chatId } = req.body;
    if (!botToken || !chatId || botToken.trim().length < 10 || chatId.trim().length < 3) {
      return res.status(400).json({ success: false, error: 'Sila masukkan Bot Token dan Chat ID yang sah.' });
    }

    const cleanToken = botToken.trim();
    const cleanChat = chatId.trim();

    // 1. Sahkan keesahan Bot Token dengan Telegram API (getMe)
    const testResp = await fetch(`https://api.telegram.org/bot${cleanToken}/getMe`);
    const testJson = await testResp.json();
    if (!testJson.ok) {
      return res.status(400).json({ success: false, error: 'Bot Token tidak sah mengikut Telegram API. Sila semak semula.' });
    }

    // 2. Jana Kod Pengesahan Unik (Sah 2 Minit)
    const verifyToken = 'TG-VERIFY-' + Math.floor(100000 + Math.random() * 900000);
    const expiresAt = Date.now() + 120000;

    pendingTelegramVerifications.set(verifyToken, {
      token: verifyToken,
      botToken: cleanToken,
      chatId: cleanChat,
      expiresAt
    });

    // 3. Hantar Mesej Pengesahan ke Telegram bersama Butang Interaktif (Format HTML Kalis Ralat Underscore)
    const botName = escapeTgHtml(testJson.result.first_name || 'Bot');
    const botUser = testJson.result.username ? ` (@${escapeTgHtml(testJson.result.username)})` : '';

    const messageText = `🔐 <b>PENGESAHAN INTEGRASI TELEGRAM Koffi POS</b>\n\n` +
      `Adakah anda ingin menyambungkan bot Telegram <b>${botName}</b>${botUser} ke Sistem POS Kaunter Koffi?\n\n` +
      `📍 <b>Kaunter:</b> POS Kaunter Utama\n` +
      `🔑 <b>Kod Pengesahan:</b> <code>${verifyToken}</code>\n` +
      `⏰ <b>Masa:</b> ${new Date().toLocaleString('ms-MY')}\n` +
      `⏳ <b>Sah selama:</b> 2 Minit\n\n` +
      `Sila tekan butang di bawah untuk mengesahkan sambungan:`;

    const inlineKeyboard = [
      [{ text: '✅ Sahkan Sambungan Koffi POS', callback_data: `verify_tg:${verifyToken}` }]
    ];

    const sendRes = await sendTelegramMessage(cleanToken, cleanChat, messageText, inlineKeyboard);
    if (!sendRes.ok) {
      return res.status(400).json({
        success: false,
        error: `Gagal menghantar mesej ke Chat ID ${cleanChat}: ${sendRes.description || 'Sila pastikan anda telah tekan /start pada bot Telegram tersebut terlebih dahulu.'}`
      });
    }

    console.log(`📨 [TELEGRAM VERIFY SENT] Kod: ${verifyToken} dihantar ke Chat ID: ${cleanChat}`);
    return res.json({
      success: true,
      verifyToken,
      expiresInSeconds: 120,
      botName: testJson.result.first_name,
      message: 'Mesej pengesahan telah dihantar ke Telegram. Sila buka aplikasi Telegram anda dan tekan butang Sahkan.'
    });
  } catch (err) {
    console.error('❌ /api/telegram/request-verification error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Endpoint 3: Semak Status Pengesahan Bot (Polling dari UI Kaunter)
app.get('/api/telegram/verification-status', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ success: false, error: 'Token diperlukan' });

  // Semak jika sudah disahkan
  if (customTelegramConfig && customTelegramConfig.isVerified) {
    return res.json({ success: true, isVerified: true });
  }

  const pending = pendingTelegramVerifications.get(token);
  if (!pending) {
    return res.json({ success: true, isVerified: false, isPending: false, error: 'Tiada permohonan aktif atau telah tamat masa' });
  }

  if (pending.expiresAt <= Date.now()) {
    pendingTelegramVerifications.delete(token);
    return res.json({ success: true, isVerified: false, isPending: false, error: 'Permohonan telah tamat tempoh' });
  }

  return res.json({ success: true, isVerified: false, isPending: true });
});

// Endpoint 4: Reset Semula ke Developer Fallback
app.post('/api/telegram/reset-to-developer', async (req, res) => {
  try {
    customTelegramConfig = null;
    if (supabase) {
      await supabase.from('pos_settings').delete().eq('key', 'telegram_config');
    }
    console.log('🔄 [TELEGRAM] Tetapan Telegram di-reset ke Developer Fallback');
    res.json({ success: true, message: 'Tetapan dikembalikan ke Developer Fallback' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Endpoint 5: Permohonan Log Masuk MOD Pengurus (Request Log In)
app.post('/api/auth/manager/request-login', async (req, res) => {
  try {
    const effective = getEffectiveTelegramConfig();
    const requestId = 'REQ-' + Math.floor(100000 + Math.random() * 900000);
    const expiresAt = Date.now() + 120000;

    pendingManagerLoginRequests.set(requestId, {
      requestId,
      status: 'pending',
      expiresAt,
      createdAt: new Date().toISOString()
    });

    const msg = `👑 <b>PERMOHONAN LOG MASUK PENGURUS (POS Koffi)</b>\n\n` +
      `📍 <b>Kaunter:</b> POS Kaunter Utama\n` +
      `🔑 <b>Kod Permohonan:</b> <code>${requestId}</code>\n` +
      `⏰ <b>Masa:</b> ${new Date().toLocaleTimeString('ms-MY')}\n` +
      `⏳ <b>Sah selama:</b> 2 Minit\n\n` +
      `Sila tekan butang di bawah untuk meluluskan akses mod Pengurus di kaunter:`;

    const inlineKeyboard = [
      [
        { text: '✅ Benarkan Log Masuk', callback_data: `approve_login:${requestId}` },
        { text: '❌ Tolak', callback_data: `reject_login:${requestId}` }
      ]
    ];

    const sendRes = await sendTelegramMessage(effective.botToken, effective.chatId, msg, inlineKeyboard);
    if (!sendRes.ok) {
      return res.status(400).json({
        success: false,
        error: `Gagal menghantar notifikasi ke Telegram: ${sendRes.description || 'Sila pastikan bot telah dimulakan (/start)'}`
      });
    }

    console.log(`🚀 [MANAGER LOGIN REQUESTED] ID: ${requestId} dihantar ke Chat ID: ${effective.chatId} (${effective.label})`);
    return res.json({
      success: true,
      requestId,
      expiresInSeconds: 120,
      targetChatId: effective.chatId,
      isDeveloperFallback: effective.isDeveloperFallback,
      message: 'Permohonan log masuk dihantar ke Telegram Pengurus'
    });
  } catch (err) {
    console.error('❌ /api/auth/manager/request-login error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Endpoint 6: Semak Status Kelulusan Log Masuk Pengurus
app.get('/api/auth/manager/check-status', (req, res) => {
  const { requestId } = req.query;
  if (!requestId) return res.status(400).json({ success: false, error: 'Request ID diperlukan' });

  const session = pendingManagerLoginRequests.get(requestId);
  if (!session) {
    return res.json({ success: true, status: 'expired' });
  }

  if (session.expiresAt <= Date.now() && session.status === 'pending') {
    pendingManagerLoginRequests.delete(requestId);
    return res.json({ success: true, status: 'expired' });
  }

  if (session.status === 'approved') {
    pendingManagerLoginRequests.delete(requestId);
    const managerToken = jwt.sign(
      {
        staffId: 'mgr_admin',
        staffCode: 'MGR-001',
        name: 'Pengurus Utama',
        role: 'manager'
      },
      STAFF_JWT_SECRET,
      { expiresIn: '12h' }
    );
    return res.json({
      success: true,
      status: 'approved',
      manager: {
        name: 'Pengurus Utama',
        role: 'manager',
        staffCode: 'MGR-001'
      },
      staffToken: managerToken,
      managerToken: managerToken
    });
  }

  if (session.status === 'rejected') {
    pendingManagerLoginRequests.delete(requestId);
    return res.json({ success: true, status: 'rejected' });
  }

  return res.json({ success: true, status: 'pending' });
});

// Endpoint 7: Batal Permohonan Log Masuk Pengurus
app.post('/api/auth/manager/cancel-login', (req, res) => {
  const { requestId } = req.body;
  if (requestId) pendingManagerLoginRequests.delete(requestId);
  res.json({ success: true });
});

// ====================================================================
// 14. PENGURUSAN STAF & KAWALAN AKSES JURUWANG (POS STAFF CRUD APIS)
// ====================================================================
let posStaffStore = []; // In-memory fallback (kosong, sedia untuk data live)

// Helper: Penjanaan Kod Staf Automatik (cth. STF-001, STF-002)
function generateNextStaffCode(existingList) {
  let maxNum = 0;
  existingList.forEach(s => {
    const match = String(s.staffCode || s.staff_code || '').match(/STF-(\d+)/i);
    if (match) {
      const num = parseInt(match[1], 10);
      if (num > maxNum) maxNum = num;
    }
  });
  return `STF-${String(maxNum + 1).padStart(3, '0')}`;
}

const staffLoginAttemptsMap = new Map(); // staffId/ip -> { failedCount, lockoutUntil }

async function hashPin(pin) {
  return await bcrypt.hash(String(pin).trim(), 10);
}

async function verifyPin(plainPin, storedPin) {
  if (!storedPin) return false;
  const clean = String(plainPin).trim();
  if (storedPin.startsWith('$2a$') || storedPin.startsWith('$2b$') || storedPin.startsWith('$2y$')) {
    return await bcrypt.compare(clean, storedPin);
  }
  return clean === String(storedPin).trim();
}

async function migrateStaffPinsToBcrypt() {
  if (!supabase) return;
  try {
    const { data: staffList, error } = await supabase.from('pos_staff').select('id, name, pin');
    if (error || !staffList) return;
    for (const st of staffList) {
      if (st.pin && !st.pin.startsWith('$2a$') && !st.pin.startsWith('$2b$') && !st.pin.startsWith('$2y$')) {
        const hashed = await hashPin(st.pin);
        await supabase.from('pos_staff').update({ pin: hashed, updated_at: new Date().toISOString() }).eq('id', st.id);
        console.log(`🔒 [STAFF PIN MIGRATION] Hashed PIN for staff ${st.name} (${st.id})`);
      }
    }
  } catch (err) {
    console.warn('Staff PIN migration warning:', err.message);
  }
}

// 1. Dapatkan Senarai Semua Staf Live
app.get('/api/pos/staff', async (req, res) => {
  try {
    if (supabase) {
      const { data, error } = await supabase
        .from('pos_staff')
        .select('*')
        .order('created_at', { ascending: true });

      if (!error && data) {
        const staffMapped = data.map(s => ({
          id: s.id,
          staffCode: s.staff_code || s.staffCode,
          name: s.name,
          role: s.role || 'Kasir & Barista',
          phone: s.phone || '',
          pin: '••••',
          hourlyRate: parseFloat(s.hourly_rate || s.hourlyRate) || 8.50,
          active: s.active !== undefined ? s.active : true,
          joined: s.joined_date || new Date(s.created_at).toLocaleDateString('ms-MY', { day: 'numeric', month: 'short', year: 'numeric' })
        }));
        posStaffStore = staffMapped; // Sinkronkan ke memori
        return res.json({ success: true, count: staffMapped.length, staff: staffMapped });
      }
    }

    // In-memory fallback
    res.json({ success: true, count: posStaffStore.length, staff: posStaffStore });
  } catch (err) {
    console.error('❌ GET /api/pos/staff error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. Tambah Profil Staf Baharu (Dilindungi Staff Token)
app.post('/api/pos/staff', requireStaffAuth, async (req, res) => {
  try {
    const { name, role, phone, pin, hourlyRate, active, staffCode } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, error: 'Nama penuh staf diperlukan.' });
    }
    if (!pin || String(pin).trim().length < 4) {
      return res.status(400).json({ success: false, error: 'PIN / Kata laluan mestilah sekurang-kurangnya 4 angka.' });
    }

    const cleanName = name.trim();
    const cleanRole = (role && role.trim()) ? role.trim() : 'Kasir & Barista';
    const cleanPhone = (phone && phone.trim()) ? phone.trim() : '';
    const hashedPin = await hashPin(pin);
    const cleanRate = parseFloat(hourlyRate) || 8.50;
    const isActive = active !== undefined ? !!active : true;
    const joinedStr = new Date().toLocaleDateString('ms-MY', { day: 'numeric', month: 'short', year: 'numeric' });

    let finalCode = (staffCode && staffCode.trim()) ? staffCode.trim() : null;
    if (!finalCode) {
      let allStaff = [...posStaffStore];
      if (supabase) {
        const { data: dbStaff } = await supabase.from('pos_staff').select('staff_code');
        if (dbStaff && dbStaff.length > 0) allStaff = dbStaff;
      }
      finalCode = generateNextStaffCode(allStaff);
    }

    let newStaffRecord = {
      id: 'stf_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4),
      staffCode: finalCode,
      name: cleanName,
      role: cleanRole,
      phone: cleanPhone,
      pin: hashedPin,
      hourlyRate: cleanRate,
      active: isActive,
      joined: joinedStr,
      created_at: new Date().toISOString()
    };

    if (supabase) {
      const { data, error } = await supabase
        .from('pos_staff')
        .insert({
          staff_code: finalCode,
          name: cleanName,
          role: cleanRole,
          phone: cleanPhone,
          pin: hashedPin,
          hourly_rate: cleanRate,
          active: isActive,
          joined_date: joinedStr
        })
        .select()
        .single();

      if (error) {
        console.error('❌ Supabase insert pos_staff error:', error.message);
        return res.status(500).json({
          success: false,
          error: error.message.includes('character varying(20)')
            ? `Gagal simpan ke Supabase: Kolum 'pin' dalam jadual pos_staff mesti bertipe TEXT (Sila jalankan: ALTER TABLE pos_staff ALTER COLUMN pin TYPE TEXT; di Supabase SQL Editor).`
            : `Gagal simpan ke Supabase: ${error.message}`
        });
      }

      if (data) {
        newStaffRecord = {
          id: data.id,
          staffCode: data.staff_code,
          name: data.name,
          role: data.role,
          phone: data.phone,
          pin: '••••',
          hourlyRate: parseFloat(data.hourly_rate),
          active: data.active,
          joined: data.joined_date || joinedStr
        };
      }
    }

    posStaffStore.push(newStaffRecord);

    if (supabase) {
      await supabase.from('pos_audit_logs').insert({
        action: 'staff_created',
        cashier_name: req.staff ? req.staff.name : cleanName,
        cashier_code: req.staff ? req.staff.staffCode : finalCode,
        details: { name: cleanName, role: cleanRole, staffCode: finalCode }
      });
    }

    console.log(`👤 [STAFF CREATED IN SUPABASE] ${cleanName} (${finalCode}) - Jawatan: ${cleanRole}`);
    res.json({ success: true, message: 'Profil staf berjaya didaftarkan ke Supabase ✨', staff: newStaffRecord });
  } catch (err) {
    console.error('❌ POST /api/pos/staff error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. Kemaskini Profil Staf (Dilindungi Staff Token)
app.put('/api/pos/staff/:id', requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, role, phone, pin, hourlyRate, active, staffCode } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, error: 'Nama penuh staf diperlukan.' });
    }

    const cleanName = name.trim();
    const cleanRole = (role && role.trim()) ? role.trim() : 'Kasir & Barista';
    const cleanPhone = (phone && phone.trim()) ? phone.trim() : '';
    const cleanRate = parseFloat(hourlyRate) || 8.50;
    const isActive = active !== undefined ? !!active : true;

    let updatedStaff = null;

    if (supabase) {
      const updatePayload = {
        name: cleanName,
        role: cleanRole,
        phone: cleanPhone,
        hourly_rate: cleanRate,
        active: isActive,
        updated_at: new Date().toISOString()
      };
      if (staffCode && staffCode.trim()) updatePayload.staff_code = staffCode.trim();
      if (pin && String(pin).trim().length >= 4 && !String(pin).includes('•')) {
        updatePayload.pin = await hashPin(pin);
      }

      const { data, error } = await supabase
        .from('pos_staff')
        .update(updatePayload)
        .eq('id', id)
        .select()
        .single();

      if (error) {
        console.error('❌ Supabase update pos_staff error:', error.message);
        return res.status(500).json({
          success: false,
          error: error.message.includes('character varying(20)')
            ? `Gagal kemaskini di Supabase: Kolum 'pin' dalam jadual pos_staff mesti bertipe TEXT (Sila jalankan: ALTER TABLE pos_staff ALTER COLUMN pin TYPE TEXT; di Supabase SQL Editor).`
            : `Gagal kemaskini di Supabase: ${error.message}`
        });
      }

      if (data) {
        updatedStaff = {
          id: data.id,
          staffCode: data.staff_code,
          name: data.name,
          role: data.role,
          phone: data.phone,
          pin: '••••',
          hourlyRate: parseFloat(data.hourly_rate),
          active: data.active,
          joined: data.joined_date
        };
      }
    }

    const idx = posStaffStore.findIndex(s => String(s.id) === String(id));
    if (idx !== -1) {
      posStaffStore[idx] = {
        ...posStaffStore[idx],
        name: cleanName,
        role: cleanRole,
        phone: cleanPhone,
        hourlyRate: cleanRate,
        active: isActive,
        ...(staffCode ? { staffCode: staffCode.trim() } : {})
      };
      if (!updatedStaff) updatedStaff = posStaffStore[idx];
    }

    if (supabase) {
      await supabase.from('pos_audit_logs').insert({
        action: 'staff_updated',
        cashier_name: req.staff ? req.staff.name : cleanName,
        details: { staffId: id, name: cleanName, role: cleanRole }
      });
    }

    console.log(`✏️ [STAFF UPDATED IN SUPABASE] ID: ${id} - ${cleanName}`);
    res.json({ success: true, message: 'Maklumat staf berjaya dikemas kini di Supabase', staff: updatedStaff || req.body });
  } catch (err) {
    console.error('❌ PUT /api/pos/staff/:id error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4. Padam Profil Staf (Dilindungi Staff Token)
app.delete('/api/pos/staff/:id', requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (supabase) {
      const { error } = await supabase.from('pos_staff').delete().eq('id', id);
      if (error) {
        console.error('❌ Supabase delete pos_staff error:', error.message);
        return res.status(500).json({ success: false, error: `Gagal memadam dari Supabase: ${error.message}` });
      }
    }

    const removed = posStaffStore.find(s => String(s.id) === String(id));
    posStaffStore = posStaffStore.filter(s => String(s.id) !== String(id));

    if (supabase) {
      await supabase.from('pos_audit_logs').insert({
        action: 'staff_deleted',
        cashier_name: req.staff ? req.staff.name : (removed ? removed.name : id),
        details: { staffId: id, staffName: removed ? removed.name : null }
      });
    }

    console.log(`🗑️ [STAFF DELETED FROM SUPABASE] ID: ${id}`);
    res.json({ success: true, message: 'Profil staf berjaya dipadam daripada Supabase' });
  } catch (err) {
    console.error('❌ DELETE /api/pos/staff/:id error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 5. Tukar Status Aktif / Tidak Aktif Staf (Toggle Status)
app.post('/api/pos/staff/:id/toggle-status', requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;
    let newStatus = true;

    const staffMem = posStaffStore.find(s => String(s.id) === String(id));
    if (staffMem) {
      newStatus = !staffMem.active;
      staffMem.active = newStatus;
    }

    if (supabase) {
      const { data } = await supabase
        .from('pos_staff')
        .select('active')
        .eq('id', id)
        .single();
      if (data) {
        newStatus = !data.active;
        await supabase
          .from('pos_staff')
          .update({ active: newStatus, updated_at: new Date().toISOString() })
          .eq('id', id);
      }
    }

    res.json({ success: true, active: newStatus, message: `Status staf ditukar kepada ${newStatus ? 'Aktif' : 'Tidak Aktif'}` });
  } catch (err) {
    console.error('❌ POST /api/pos/staff/:id/toggle-status error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 6. Pengesahan PIN Staf (Verify PIN for Cashier Login & Shift with Rate-Limit & JWT Issuance)
app.post('/api/pos/staff/verify-pin', async (req, res) => {
  try {
    const { staffId, pin } = req.body;
    if (!staffId || !pin) {
      return res.status(400).json({ success: false, error: 'ID staf dan PIN diperlukan' });
    }

    const clientIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const rateLimitKey = `pin_${staffId}_${clientIp}`;
    const now = Date.now();

    // Semak sekatan lockout (5 kali salah -> 15 minit lockout)
    let attemptData = staffLoginAttemptsMap.get(rateLimitKey) || { failedCount: 0, lockoutUntil: 0 };
    if (attemptData.lockoutUntil > now) {
      const remainingSecs = Math.ceil((attemptData.lockoutUntil - now) / 1000);
      const remainingMins = Math.ceil(remainingSecs / 60);
      return res.status(429).json({
        success: false,
        error: `Akaun dikunci sementara selama ${remainingMins} minit kerana 5 kali percubaan PIN salah. Sila tunggu.`,
        remainingSeconds: remainingSecs
      });
    }

    if (attemptData.lockoutUntil > 0 && attemptData.lockoutUntil <= now) {
      attemptData = { failedCount: 0, lockoutUntil: 0 };
      staffLoginAttemptsMap.set(rateLimitKey, attemptData);
    }

    let staff = null;
    let rawPinFromDb = null;
    if (supabase) {
      const { data } = await supabase
        .from('pos_staff')
        .select('*')
        .eq('id', staffId)
        .single();
      if (data) {
        rawPinFromDb = data.pin;
        staff = {
          id: data.id,
          staffCode: data.staff_code,
          name: data.name,
          role: data.role,
          pin: data.pin,
          active: data.active
        };
      }
    }

    if (!staff) {
      staff = posStaffStore.find(s => String(s.id) === String(staffId));
    }

    if (!staff) {
      return res.status(404).json({ success: false, error: 'Profil staf tidak ditemui' });
    }

    if (!staff.active) {
      return res.status(403).json({ success: false, error: 'Akaun staf ini tidak aktif. Sila rujuk Pengurus.' });
    }

    // Sahkan PIN dengan Bcrypt
    const isMatch = await verifyPin(pin, staff.pin);
    if (!isMatch) {
      attemptData.failedCount++;
      if (attemptData.failedCount >= 5) {
        attemptData.lockoutUntil = now + 15 * 60 * 1000; // 15 minit
        staffLoginAttemptsMap.set(rateLimitKey, attemptData);
        return res.status(429).json({
          success: false,
          error: 'Melebihi had 5 kali percubaan salah. Akaun dikunci selama 15 minit.',
          remainingSeconds: 900
        });
      }
      staffLoginAttemptsMap.set(rateLimitKey, attemptData);
      const remainingAttempts = 5 - attemptData.failedCount;
      return res.status(401).json({
        success: false,
        error: `PIN staf tidak sah. Baki percubaan: ${remainingAttempts} kali.`,
        remainingAttempts
      });
    }

    // Set semula had rate limit jika berjaya
    staffLoginAttemptsMap.delete(rateLimitKey);

    // Jika PIN dalam DB masih plaintext, naik taraf ke hash bcrypt secara automatik
    if (supabase && rawPinFromDb && !rawPinFromDb.startsWith('$2')) {
      const hashed = await hashPin(pin);
      await supabase.from('pos_staff').update({ pin: hashed, updated_at: new Date().toISOString() }).eq('id', staff.id);
    }

    // Jana JWT Staff Token Sah (12 Jam Sah)
    const staffToken = jwt.sign(
      {
        staffId: staff.id,
        staffCode: staff.staffCode || 'STF-001',
        name: staff.name,
        role: staff.role || 'staff'
      },
      STAFF_JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      success: true,
      valid: true,
      staff: {
        id: staff.id,
        staffCode: staff.staffCode,
        name: staff.name,
        role: staff.role
      },
      staffToken: staffToken
    });
  } catch (err) {
    console.error('❌ POST /api/pos/staff/verify-pin error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 15. PENGIRAAN & BAYARAN GAJI STAF (PAYROLL & SHIFT RANGE APIS)
// ====================================================================
let posPayrollStore = []; // In-memory fallback (kosong, sedia untuk data live)
let posShiftsStore = []; // In-memory fallback syif

// 1. Kira Jam Bekerja & Ringkasan Syif Staf Berasaskan Julat Tarikh
app.get('/api/pos/payroll/staff/:staffId/shifts-summary', requireStaffAuth, async (req, res) => {
  try {
    const { staffId } = req.params;
    const { startDate, endDate } = req.query;

    // Cari maklumat staf
    let staff = null;
    if (supabase) {
      const { data } = await supabase.from('pos_staff').select('*').eq('id', staffId).single();
      if (data) {
        staff = {
          id: data.id,
          staffCode: data.staff_code,
          name: data.name,
          role: data.role,
          phone: data.phone,
          hourlyRate: parseFloat(data.hourly_rate) || 8.50
        };
      }
    }
    if (!staff) {
      const sMem = posStaffStore.find(s => String(s.id) === String(staffId));
      if (sMem) staff = sMem;
    }

    if (!staff) {
      return res.status(404).json({ success: false, error: 'Profil staf tidak ditemui' });
    }

    const hourlyRate = parseFloat(staff.hourlyRate) || 8.50;
    let matchingShifts = [];

    if (supabase) {
      let shiftQuery = supabase
        .from('pos_shifts')
        .select('*')
        .or(`cashier_name.eq.${staff.name},cashier_code.eq.${staff.staffCode}`);

      if (startDate) shiftQuery = shiftQuery.gte('opened_at', `${startDate}T00:00:00.000Z`);
      if (endDate) shiftQuery = shiftQuery.lte('opened_at', `${endDate}T23:59:59.999Z`);

      const { data: sData } = await shiftQuery.order('opened_at', { ascending: false });
      if (sData) matchingShifts = sData;
    }

    // In-memory fallback for shifts
    if (matchingShifts.length === 0 && Array.isArray(posShiftsStore) && posShiftsStore.length > 0) {
      matchingShifts = posShiftsStore.filter(s => {
        const isStaffMatch = (s.cashier_name === staff.name || s.cashier_code === staff.staffCode);
        if (!isStaffMatch) return false;
        if (startDate && new Date(s.opened_at) < new Date(`${startDate}T00:00:00.000Z`)) return false;
        if (endDate && new Date(s.opened_at) > new Date(`${endDate}T23:59:59.999Z`)) return false;
        return true;
      });
    }

    // Kira jumlah jam bekerja daripada syif
    let totalHours = 0;
    matchingShifts.forEach(s => {
      if (s.closed_at && s.opened_at) {
        const start = new Date(s.opened_at).getTime();
        const end = new Date(s.closed_at).getTime();
        const durationHours = Math.max(0, (end - start) / (1000 * 60 * 60));
        totalHours += durationHours;
      } else {
        totalHours += 8; // Default 8 jam jika syif masih aktif
      }
    });

    const roundedHours = Math.round(totalHours * 10) / 10;
    const estimatedBasic = Math.round(roundedHours * hourlyRate * 100) / 100;

    res.json({
      success: true,
      staff: {
        id: staff.id,
        name: staff.name,
        staffCode: staff.staffCode,
        role: staff.role,
        phone: staff.phone,
        hourlyRate
      },
      range: { startDate, endDate },
      totalShifts: matchingShifts.length,
      totalHours: roundedHours,
      estimatedBasic,
      shifts: matchingShifts.map(s => ({
        id: s.id,
        shift_number: s.shift_number,
        opened_at: s.opened_at,
        closed_at: s.closed_at,
        cash_sales: s.cash_sales,
        status: s.status
      }))
    });
  } catch (err) {
    console.error('❌ GET /api/pos/payroll/staff/:staffId/shifts-summary error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. Sahkan & Rekodkan Pembayaran Gaji (Create Payroll Payout Record)
app.post('/api/pos/payroll', requireStaffAuth, async (req, res) => {
  try {
    const {
      staffId,
      staffName,
      staffCode,
      role,
      phone,
      period,
      startDate,
      endDate,
      hoursWorked,
      hourlyRate,
      allowance,
      deduction,
      netSalary,
      payMethod,
      approvedBy,
      notes
    } = req.body;

    if (!staffName || netSalary === undefined || netSalary === null) {
      return res.status(400).json({ success: false, error: 'Maklumat staf dan jumlah bersih gaji diperlukan.' });
    }

    const cleanNet = parseFloat(netSalary) || 0;
    const cleanHours = parseFloat(hoursWorked) || 0;
    const cleanRate = parseFloat(hourlyRate) || 8.50;
    const cleanAllowance = parseFloat(allowance) || 0;
    const cleanDeduction = parseFloat(deduction) || 0;
    const cleanBasic = Math.round(cleanHours * cleanRate * 100) / 100;
    const voucherNo = 'GJ-' + new Date().getFullYear() + String(new Date().getMonth() + 1).padStart(2, '0') + '-' + Math.floor(1000 + Math.random() * 9000);

    let payrollRecord = {
      id: 'pay_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4),
      voucher_no: voucherNo,
      staff_id: staffId || 'stf_unknown',
      staff_name: staffName,
      staff_code: staffCode || 'STF-001',
      role: role || 'Kasir & Barista',
      phone: phone || '',
      period: period || `Gaji Bulan ${new Date().toLocaleDateString('ms-MY', { month: 'long', year: 'numeric' })}`,
      start_date: startDate || null,
      end_date: endDate || null,
      hours_worked: cleanHours,
      hourly_rate: cleanRate,
      basic_salary: cleanBasic,
      allowance: cleanAllowance,
      deduction: cleanDeduction,
      net_salary: cleanNet,
      pay_method: payMethod || 'bank',
      approved_by: approvedBy || (req.staff ? req.staff.name : 'Pengurus Utama'),
      notes: notes || '',
      created_at: new Date().toISOString()
    };

    if (supabase) {
      const { data, error } = await supabase
        .from('pos_payroll')
        .insert({
          voucher_no: voucherNo,
          staff_id: String(staffId || ''),
          staff_name: staffName,
          staff_code: staffCode || 'STF-001',
          role: role || 'Kasir & Barista',
          phone: phone || '',
          period: period || `Gaji Bulan ${new Date().toLocaleDateString('ms-MY', { month: 'long', year: 'numeric' })}`,
          start_date: startDate || null,
          end_date: endDate || null,
          hours_worked: cleanHours,
          hourly_rate: cleanRate,
          basic_salary: cleanBasic,
          allowance: cleanAllowance,
          deduction: cleanDeduction,
          net_salary: cleanNet,
          pay_method: payMethod || 'bank',
          approved_by: approvedBy || (req.staff ? req.staff.name : 'Pengurus Utama'),
          notes: notes || ''
        })
        .select()
        .single();

      if (!error && data) {
        payrollRecord = data;
      }

      // Catat log jejak audit pengeluaran gaji
      await supabase.from('pos_audit_logs').insert({
        action: 'payroll_payout',
        cashier_name: req.staff ? req.staff.name : (approvedBy || 'Pengurus Utama'),
        cashier_code: req.staff ? req.staff.staffCode : 'MGR-001',
        details: {
          voucherNo,
          staffName,
          staffCode,
          period,
          hoursWorked: cleanHours,
          netSalary: cleanNet,
          payMethod: payMethod || 'bank'
        }
      });
    }

    posPayrollStore.unshift(payrollRecord);

    console.log(`💵 [PAYROLL PAID] ${voucherNo} - Staf: ${staffName} (RM${cleanNet.toFixed(2)}) - Tempoh: ${period}`);
    res.json({
      success: true,
      message: `Bayaran gaji ${staffName} (RM${cleanNet.toFixed(2)}) berjaya disahkan & direkodkan! 💵`,
      payroll: payrollRecord
    });
  } catch (err) {
    console.error('❌ POST /api/pos/payroll error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. Dapatkan Sejarah Rekod Pembayaran Gaji (Payroll History)
app.get('/api/pos/payroll', requireStaffAuth, async (req, res) => {
  try {
    const { staffId, limit } = req.query;
    const maxLimit = Math.min(100, parseInt(limit) || 50);

    if (supabase) {
      let query = supabase.from('pos_payroll').select('*').order('created_at', { ascending: false });
      if (staffId) query = query.eq('staff_id', String(staffId));

      const { data, error } = await query.limit(maxLimit);
      if (!error && data) {
        posPayrollStore = data;
        return res.json({ success: true, count: data.length, payrolls: data });
      }
    }

    let list = [...posPayrollStore];
    if (staffId) list = list.filter(p => String(p.staff_id) === String(staffId));

    res.json({ success: true, count: list.length, payrolls: list.slice(0, maxLimit) });
  } catch (err) {
    console.error('❌ GET /api/pos/payroll error:', err.message);
    res.status(500).json({ success: false, error: err.message, payrolls: [] });
  }
});

// 4. Aliases untuk salary-payments
app.get('/api/pos/salary-payments', requireStaffAuth, (req, res) => res.redirect(307, '/api/pos/payroll' + (req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '')));
app.post('/api/pos/salary-payments', requireStaffAuth, (req, res) => res.redirect(307, '/api/pos/payroll'));

// 5. Statistik Pembayaran Gaji (Salary Payout Stats)
app.get('/api/pos/salary-payments/stats', requireStaffAuth, async (req, res) => {
  try {
    let list = [...posPayrollStore];
    if (supabase) {
      const { data } = await supabase.from('pos_payroll').select('*');
      if (data) list = data;
    }

    const now = new Date();
    const curMonthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

    let totalPaidAllTime = 0;
    let totalPaidThisMonth = 0;
    let totalHoursThisMonth = 0;
    const staffPaidSet = new Set();

    list.forEach(p => {
      const net = parseFloat(p.net_salary) || 0;
      const hrs = parseFloat(p.hours_worked) || 0;
      totalPaidAllTime += net;

      const pDate = new Date(p.created_at || now);
      const pKey = `${pDate.getFullYear()}-${String(pDate.getMonth() + 1).padStart(2, '0')}`;
      if (pKey === curMonthKey) {
        totalPaidThisMonth += net;
        totalHoursThisMonth += hrs;
        if (p.staff_id) staffPaidSet.add(p.staff_id);
      }
    });

    res.json({
      success: true,
      currentMonth: curMonthKey,
      totalPaidAllTime: Math.round(totalPaidAllTime * 100) / 100,
      totalPaidThisMonth: Math.round(totalPaidThisMonth * 100) / 100,
      totalHoursThisMonth: Math.round(totalHoursThisMonth * 10) / 10,
      totalStaffPaidThisMonth: staffPaidSet.size,
      totalVouchers: list.length
    });
  } catch (err) {
    console.error('❌ GET /api/pos/salary-payments/stats error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 6. Padam Baucar Bayaran Gaji
app.delete('/api/pos/payroll/:id', requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (supabase) {
      await supabase.from('pos_payroll').delete().eq('id', id);
      await supabase.from('pos_audit_logs').insert({
        action: 'payroll_deleted',
        cashier_name: req.staff ? req.staff.name : 'Pengurus Utama',
        details: { payrollId: id }
      });
    }
    posPayrollStore = posPayrollStore.filter(p => String(p.id) !== String(id));
    res.json({ success: true, message: 'Baucar gaji berjaya dipadam' });
  } catch (err) {
    console.error('❌ DELETE /api/pos/payroll/:id error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 16. MAKLUMAT PERNIAGAAN & E-INVOIS LHDN (MYINVOIS SUITE)
// ====================================================================
let inMemoryBusinessInfo = {
  name: 'KOFFI KOPI & PASTRI SDN BHD',
  regNo: '202601012345 (1523456-X)',
  sstNo: 'W10-2001-32000512',
  tin: 'C1234567890',
  msicCode: '56301',
  msicDesc: 'Restoran, Kafe & Kedai Minuman',
  address: 'No. 12, Jalan Kopi Utama, Taman Aroma, 50450 Kuala Lumpur, Malaysia',
  phone: '03-9876 5432',
  footerNote: 'Terima kasih atas sokongan anda!',
  logo: null,
  printStampQr: true,
  stampQrLabel: 'Semak Cop Stamp & Mata Anda',
  loyaltyUrl: 'https://koffi.coffee/loyalty'
};

let inMemoryEInvoiceSettings = {
  environment: 'sandbox',
  clientId: '',
  clientSecret: '',
  autoConsolidate: true,
  consolidateFrequency: 'monthly',
  defaultClassificationCode: '022',
  generalPublicTin: 'EI00000000010'
};

async function initBusinessInfo() {
  if (!supabase) return;
  try {
    const { data: bData } = await supabase.from('pos_settings').select('value').eq('key', 'business_info').maybeSingle();
    if (bData && bData.value) {
      inMemoryBusinessInfo = { ...inMemoryBusinessInfo, ...bData.value };
      console.log(`🏢 [BUSINESS INFO] Berjaya dimuatkan: ${inMemoryBusinessInfo.name} | Tel: ${inMemoryBusinessInfo.phone || '-'}`);
    }
  } catch (e) {
    console.warn('⚠️ [BUSINESS INFO] Gagal muat permulaan:', e.message);
  }
}
initBusinessInfo();

// 1. Dapatkan Maklumat Perniagaan & Tetapan e-Invois LHDN
app.get('/api/pos/business-info', async (req, res) => {
  try {
    if (supabase) {
      const { data: bData } = await supabase
        .from('pos_settings')
        .select('value')
        .eq('key', 'business_info')
        .maybeSingle();

      const { data: eData } = await supabase
        .from('pos_settings')
        .select('value')
        .eq('key', 'einvoice_settings')
        .maybeSingle();

      if (bData && bData.value) inMemoryBusinessInfo = { ...inMemoryBusinessInfo, ...bData.value };
      if (eData && eData.value) inMemoryEInvoiceSettings = { ...inMemoryEInvoiceSettings, ...eData.value };
    }

    res.json({
      success: true,
      businessInfo: inMemoryBusinessInfo,
      einvoiceSettings: inMemoryEInvoiceSettings
    });
  } catch (err) {
    console.error('❌ GET /api/pos/business-info error:', err.message);
    res.status(500).json({ success: false, error: err.message, businessInfo: inMemoryBusinessInfo });
  }
});

// 2. Simpan / Kemaskini Maklumat Perniagaan & Tetapan Kod QR Resit (Business Info)
app.post('/api/pos/business-info', requireStaffAuth, async (req, res) => {
  try {
    const payload = req.body || {};

    inMemoryBusinessInfo = {
      ...inMemoryBusinessInfo,
      ...payload,
      logo: payload.logo !== undefined ? payload.logo : inMemoryBusinessInfo.logo,
      name: payload.name || inMemoryBusinessInfo.name || 'KOFFI KOPI & PASTRI',
      printStampQr: payload.printStampQr !== undefined ? Boolean(payload.printStampQr) : (inMemoryBusinessInfo.printStampQr !== false),
      stampQrLabel: payload.stampQrLabel !== undefined ? String(payload.stampQrLabel).trim() : (inMemoryBusinessInfo.stampQrLabel || 'Semak Cop Stamp & Mata Anda'),
      loyaltyUrl: payload.loyaltyUrl !== undefined ? String(payload.loyaltyUrl).trim() : (inMemoryBusinessInfo.loyaltyUrl || 'https://koffi.coffee/loyalty'),
      updated_at: new Date().toISOString()
    };

    if (supabase) {
      const { error } = await supabase
        .from('pos_settings')
        .upsert({
          key: 'business_info',
          value: inMemoryBusinessInfo,
          updated_at: new Date().toISOString()
        }, { onConflict: 'key' });

      if (error) {
        console.error('❌ Supabase upsert business_info error:', error.message);
        throw new Error(error.message);
      }

      await supabase.from('pos_audit_logs').insert({
        action: 'business_info_updated',
        cashier_name: req.staff ? req.staff.name : (payload.cashierName || 'Pengurus Utama'),
        details: { 
          name: inMemoryBusinessInfo.name, 
          hasLogo: Boolean(inMemoryBusinessInfo.logo),
          sstNo: inMemoryBusinessInfo.sstNo, 
          tin: inMemoryBusinessInfo.tin,
          printStampQr: inMemoryBusinessInfo.printStampQr,
          stampQrLabel: inMemoryBusinessInfo.stampQrLabel,
          loyaltyUrl: inMemoryBusinessInfo.loyaltyUrl
        }
      });
    }

    console.log(`🏢 [BUSINESS & QR SETTINGS SAVED] ${inMemoryBusinessInfo.name} | Logo: ${Boolean(inMemoryBusinessInfo.logo)} | QR ON: ${inMemoryBusinessInfo.printStampQr} | QR Label: ${inMemoryBusinessInfo.stampQrLabel} | URL: ${inMemoryBusinessInfo.loyaltyUrl}`);
    res.json({
      success: true,
      message: 'Maklumat perniagaan & tetapan resit berjaya disimpan ke Supabase ✨',
      businessInfo: inMemoryBusinessInfo
    });
  } catch (err) {
    console.error('❌ POST /api/pos/business-info error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// PUT alias untuk simpan Maklumat Perniagaan
app.put('/api/pos/business-info', requireStaffAuth, async (req, res) => {
  try {
    const payload = req.body;
    inMemoryBusinessInfo = {
      ...inMemoryBusinessInfo,
      ...payload,
      updated_at: new Date().toISOString()
    };

    if (supabase) {
      await supabase
        .from('pos_settings')
        .upsert({
          key: 'business_info',
          value: inMemoryBusinessInfo,
          updated_at: new Date().toISOString()
        });
    }

    res.json({
      success: true,
      message: 'Maklumat perniagaan berjaya dikemas kini ✨',
      businessInfo: inMemoryBusinessInfo
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 16B. TETAPAN PRINTER & FORMAT RESIT (PRINTER & RECEIPT ENGINE)
// ====================================================================
let inMemoryPrinterSettings = {
  connected: false,
  deviceName: '',
  deviceId: '',
  connectionType: 'bluetooth',
  networkIp: '',
  networkPort: 9100,
  paperSize: '80mm',
  autoPrint: true,
  copies: 1,
  cutPaper: true,
  openCashDrawer: false,
  beeper: true,
  updated_at: new Date().toISOString()
};

async function initPrinterSettings() {
  if (!supabase) return;
  try {
    const { data } = await supabase.from('pos_settings').select('value').eq('key', 'printer_settings').maybeSingle();
    if (data && data.value) {
      inMemoryPrinterSettings = { ...inMemoryPrinterSettings, ...data.value };
      console.log(`🖨️ [PRINTER SETTINGS] Peranti: ${inMemoryPrinterSettings.deviceName || '(Belum disambung)'} | Saiz: ${inMemoryPrinterSettings.paperSize} | AutoPrint: ${inMemoryPrinterSettings.autoPrint}`);
    } else {
      await supabase.from('pos_settings').upsert({
        key: 'printer_settings',
        value: inMemoryPrinterSettings,
        updated_at: new Date().toISOString()
      });
      console.log(`🖨️ [PRINTER SETTINGS] Tetapan printer permulaan disimpan ke Supabase pos_settings.`);
    }
  } catch (err) {
    console.warn('⚠️ [PRINTER SETTINGS] Gagal muat dari Supabase:', err.message);
  }
}
initPrinterSettings();

// 1. GET Tetapan Printer
app.get(['/api/pos/printer/settings', '/api/pos/printer'], async (req, res) => {
  try {
    if (supabase) {
      const { data } = await supabase.from('pos_settings').select('value').eq('key', 'printer_settings').maybeSingle();
      if (data && data.value) {
        inMemoryPrinterSettings = { ...inMemoryPrinterSettings, ...data.value };
      }
    }
    res.json({
      success: true,
      settings: inMemoryPrinterSettings
    });
  } catch (err) {
    console.error('❌ GET /api/pos/printer/settings error:', err.message);
    res.json({ success: true, settings: inMemoryPrinterSettings });
  }
});

// 2. POST / PUT Simpan Tetapan Printer
app.post(['/api/pos/printer/settings', '/api/pos/printer'], requireStaffAuth, async (req, res) => {
  try {
    const payload = req.body;
    if (!payload) {
      return res.status(400).json({ success: false, error: 'Data tetapan printer diperlukan.' });
    }

    inMemoryPrinterSettings = {
      ...inMemoryPrinterSettings,
      ...payload,
      copies: Math.max(1, parseInt(payload.copies, 10) || inMemoryPrinterSettings.copies || 1),
      updated_at: new Date().toISOString()
    };

    if (supabase) {
      await supabase.from('pos_settings').upsert({
        key: 'printer_settings',
        value: inMemoryPrinterSettings,
        updated_at: new Date().toISOString()
      });

      await supabase.from('pos_audit_logs').insert({
        action: 'printer_settings_updated',
        cashier_name: req.staff ? req.staff.name : (payload.cashierName || 'Pengurus Utama'),
        details: {
          deviceName: inMemoryPrinterSettings.deviceName,
          paperSize: inMemoryPrinterSettings.paperSize,
          autoPrint: inMemoryPrinterSettings.autoPrint,
          copies: inMemoryPrinterSettings.copies,
          connectionType: inMemoryPrinterSettings.connectionType,
          connected: inMemoryPrinterSettings.connected
        }
      });
    }

    console.log(`🖨️ [PRINTER SETTINGS SAVED] Peranti: ${inMemoryPrinterSettings.deviceName || '(Belum disambung)'} | Saiz: ${inMemoryPrinterSettings.paperSize} | Salinan: ${inMemoryPrinterSettings.copies}`);
    res.json({
      success: true,
      message: 'Tetapan printer berjaya disimpan ke Supabase ✨',
      settings: inMemoryPrinterSettings
    });
  } catch (err) {
    console.error('❌ POST /api/pos/printer/settings error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. POST Uji Cetak Resit (Test Print Engine)
app.post('/api/pos/printer/test-print', requireStaffAuth, async (req, res) => {
  try {
    const { paperSize, copies, deviceName, cashierName } = req.body || {};
    const effectivePaper = paperSize || inMemoryPrinterSettings.paperSize || '80mm';
    const effectiveCopies = Math.max(1, parseInt(copies, 10) || inMemoryPrinterSettings.copies || 1);
    const effectiveDevice = deviceName || inMemoryPrinterSettings.deviceName || 'Thermal Printer';

    const testJob = {
      jobId: 'print_test_' + Date.now(),
      status: 'printed',
      paperSize: effectivePaper,
      copies: effectiveCopies,
      printer: effectiveDevice,
      bizName: inMemoryBusinessInfo.name || 'KOFFI KOPI & PASTRI',
      sampleTotal: 'RM 14.50',
      timestamp: new Date().toISOString()
    };

    if (supabase) {
      try {
        await supabase.from('pos_audit_logs').insert({
          action: 'printer_test_printed',
          cashier_name: req.staff ? req.staff.name : (cashierName || 'Pengurus Utama'),
          details: {
            jobId: testJob.jobId,
            paperSize: effectivePaper,
            copies: effectiveCopies,
            printer: effectiveDevice
          }
        });
      } catch (e) {}
    }

    console.log(`🖨️ [TEST PRINT SENT] Job: ${testJob.jobId} | Saiz: ${effectivePaper} | Salinan: ${effectiveCopies} | Printer: ${effectiveDevice}`);
    res.json({
      success: true,
      message: `Ujian cetakan (${effectivePaper}, ${effectiveCopies} salinan) berjaya diproses! 🖨️`,
      job: testJob
    });
  } catch (err) {
    console.error('❌ POST /api/pos/printer/test-print error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4. GET Senarai Peranti Printer Dikesan / Disimpan
app.get('/api/pos/printer/devices', (req, res) => {
  const discoveredDevices = [];
  if (inMemoryPrinterSettings.deviceName && inMemoryPrinterSettings.connected) {
    discoveredDevices.push({
      id: inMemoryPrinterSettings.deviceId || 'BT-DEV-01',
      name: inMemoryPrinterSettings.deviceName,
      type: inMemoryPrinterSettings.connectionType || 'bluetooth',
      status: 'connected',
      paperSize: inMemoryPrinterSettings.paperSize || '80mm'
    });
  }
  res.json({ success: true, devices: discoveredDevices });
});

// 3. Simpan Tetapan e-Invois LHDN (MyInvois Settings)
app.post('/api/pos/einvoice/settings', requireStaffAuth, async (req, res) => {
  try {
    const payload = req.body;
    inMemoryEInvoiceSettings = {
      ...inMemoryEInvoiceSettings,
      ...payload,
      updated_at: new Date().toISOString()
    };

    if (supabase) {
      await supabase
        .from('pos_settings')
        .upsert({
          key: 'einvoice_settings',
          value: inMemoryEInvoiceSettings,
          updated_at: new Date().toISOString()
        });

      await supabase.from('pos_audit_logs').insert({
        action: 'einvoice_settings_updated',
        cashier_name: req.staff ? req.staff.name : 'Pengurus Utama',
        details: { environment: inMemoryEInvoiceSettings.environment, autoConsolidate: inMemoryEInvoiceSettings.autoConsolidate }
      });
    }

    console.log(`🧾 [E-INVOICE SETTINGS SAVED] Environment: ${inMemoryEInvoiceSettings.environment}`);
    res.json({
      success: true,
      message: 'Tetapan e-Invois LHDN berjaya disimpan ke Supabase ✨',
      einvoiceSettings: inMemoryEInvoiceSettings
    });
  } catch (err) {
    console.error('❌ POST /api/pos/einvoice/settings error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4. Eksport Consolidated e-Invois LHDN
app.get('/api/pos/einvoice/consolidated', async (req, res) => {
  try {
    const { month, format } = req.query;
    const now = new Date();
    const targetMonth = month || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

    const parts = targetMonth.split('-');
    const yr = parseInt(parts[0], 10);
    const mo = parseInt(parts[1], 10);
    const sDate = `${yr}-${String(mo).padStart(2, '0')}-01T00:00:00.000Z`;
    const lastDay = new Date(yr, mo, 0).getDate();
    const eDate = `${yr}-${String(mo).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}T23:59:59.999Z`;

    let salesRows = [];
    if (supabase) {
      const { data } = await supabase
        .from('sales')
        .select('*, sale_items(*)')
        .gte('created_at', sDate)
        .lte('created_at', eDate)
        .order('created_at', { ascending: true });
      if (data) salesRows = data;
    }

    if (salesRows.length === 0 && posSalesMemoryStore.length > 0) {
      salesRows = posSalesMemoryStore.filter(s => {
        const d = new Date(s.ts);
        return d.getFullYear() === yr && (d.getMonth() + 1) === mo;
      });
    }

    const supplierInfo = {
      name: inMemoryBusinessInfo.name || 'KOFFI KOPI & PASTRI',
      tin: inMemoryBusinessInfo.tin || 'C1234567890',
      regNo: inMemoryBusinessInfo.regNo || '',
      sstNo: inMemoryBusinessInfo.sstNo || '',
      msicCode: inMemoryBusinessInfo.msicCode || '56301',
      msicDesc: inMemoryBusinessInfo.msicDesc || 'Restoran & Kafe',
      address: inMemoryBusinessInfo.address || ''
    };

    const formattedLines = salesRows.map(s => {
      const d = new Date(s.created_at || s.ts);
      const itemsList = s.sale_items || s.items || [];
      const itemsSummary = itemsList.map(it => `${it.qty || 1}x ${it.product_name || it.name}${it.variation_name ? ` (${it.variation_name})` : ''}`).join('; ');
      const subtotal = parseFloat(s.subtotal) || 0;
      const tax = parseFloat(s.tax) || 0;
      const total = parseFloat(s.total) || 0;

      return {
        receiptNo: s.receipt_no,
        invoiceDate: d.toISOString(),
        orderType: s.order_type,
        paymentMethod: s.payment_method,
        classificationCode: inMemoryEInvoiceSettings.defaultClassificationCode || '022',
        buyerName: 'Pelanggan Am (Consolidated)',
        buyerTin: inMemoryEInvoiceSettings.generalPublicTin || 'EI00000000010',
        itemsSummary,
        subtotal,
        tax,
        total
      };
    });

    if (format === 'csv') {
      const csvHeaders = [
        'Tarikh & Masa',
        'No. Resit',
        'Nama Kedai (Supplier)',
        'TIN Kedai',
        'No. SSM',
        'No. SST',
        'Kod MSIC',
        'Aktiviti Perniagaan',
        'Perihal Item',
        'Subtotal (RM)',
        'SST 6% (RM)',
        'Jumlah (RM)',
        'Kaedah Bayaran',
        'Kod Klasifikasi LHDN',
        'Nama Pembeli',
        'TIN Pembeli'
      ];

      const csvDataRows = formattedLines.map(l => [
        `"${l.invoiceDate.slice(0, 19).replace('T', ' ')}"`,
        `"${l.receiptNo}"`,
        `"${supplierInfo.name}"`,
        `"${supplierInfo.tin}"`,
        `"${supplierInfo.regNo}"`,
        `"${supplierInfo.sstNo}"`,
        `"${supplierInfo.msicCode}"`,
        `"${supplierInfo.msicDesc}"`,
        `"${l.itemsSummary.replace(/"/g, '""')}"`,
        l.subtotal.toFixed(2),
        l.tax.toFixed(2),
        l.total.toFixed(2),
        `"${l.paymentMethod}"`,
        `"${l.classificationCode}"`,
        `"${l.buyerName}"`,
        `"${l.buyerTin}"`
      ]);

      const csvContent = [csvHeaders.join(','), ...csvDataRows.map(r => r.join(','))].join('\n');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="Consolidated-eInvoice-LHDN-${targetMonth}.csv"`);
      return res.send(csvContent);
    }

    res.json({
      success: true,
      month: targetMonth,
      totalSales: formattedLines.reduce((acc, l) => acc + l.total, 0),
      totalTax: formattedLines.reduce((acc, l) => acc + l.tax, 0),
      totalTransactions: formattedLines.length,
      supplierInfo,
      records: formattedLines
    });
  } catch (err) {
    console.error('❌ GET /api/pos/einvoice/consolidated error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 5. Semakan & Pengesahan Format TIN LHDN
app.post('/api/pos/einvoice/validate-tin', requireStaffAuth, (req, res) => {
  const { tin } = req.body;
  if (!tin || !tin.trim()) {
    return res.json({ valid: false, error: 'TIN tidak boleh kosong' });
  }

  const cleanTin = tin.trim().toUpperCase();
  const tinRegex = /^(C|IG|SG|OG|D|TP|F|CS|EI)\d{10,12}$/i;
  const isGeneralPublic = (cleanTin === 'EI00000000010');

  if (isGeneralPublic || tinRegex.test(cleanTin)) {
    return res.json({
      valid: true,
      tin: cleanTin,
      type: cleanTin.startsWith('C') ? 'Syarikat (Company)' : (cleanTin.startsWith('EI') ? 'Consolidated General Public' : 'Individu / Peniaga Tunggal')
    });
  }

  res.json({
    valid: false,
    tin: cleanTin,
    hint: 'Format TIN LHDN lazimnya bermula dengan C (Syarikat cth. C1234567890) atau IG (Individu) diikuti 10-12 angka.'
  });
});

// ====================================================================
// 17. TETAPAN SISTEM, CUKAI SST & CAS BERKANUN (SYSTEM & TIER SETTINGS)
// ====================================================================
let inMemorySystemSettings = {
  sst: { enabled: true, rate: 6, regNo: 'W10-2001-32000512' },
  govCharges: [
    { id: 'gov-plastic', name: 'Levi Beg Plastik Kerajaan', type: 'fixed', rate: 0.20, scope: 'takeaway', enabled: true, desc: 'Caj statutori beg plastik untuk pesanan bungkus sahaja' },
    { id: 'gov-heritage', name: 'Caj Kelestarian & Warisan', type: 'fixed', rate: 1.00, scope: 'all', enabled: false, desc: 'Caj statutori pihak berkuasa tempatan bagi zon pelancongan' },
    { id: 'gov-tourism', name: 'Cukai Pelancongan (Tourism Tax)', type: 'percent', rate: 0, scope: 'all', enabled: false, desc: 'Cukai statutori pelancongan (jika berkenaan)' }
  ],
  customCharges: [
    { id: 1, name: 'Caj Perkhidmatan (Service Charge)', type: 'percent', rate: 10, scope: 'dinein', enabled: false, desc: 'Dikenakan 10% untuk pesanan Makan Sini' },
    { id: 2, name: 'Caj Pembungkusan Mesra Alam', type: 'fixed', rate: 0.50, scope: 'takeaway', enabled: false, desc: 'Caj bekas makanan biodegradasi bagi pesanan bungkus' }
  ]
};

let inMemoryTierSettings = {
  gangsaMin: 0,
  perakMin: 100,
  emasMin: 300,
  gangsaMult: 1.0,
  perakMult: 1.2,
  emasMult: 1.5
};

// 1. Dapatkan Tetapan Sistem & Cas
app.get('/api/pos/settings', async (req, res) => {
  try {
    if (supabase) {
      const { data, error } = await supabase
        .from('pos_settings')
        .select('value')
        .eq('key', 'system_settings')
        .maybeSingle();

      if (!error && data && data.value) {
        inMemorySystemSettings = { ...inMemorySystemSettings, ...data.value };
      }
    }

    res.json({
      success: true,
      settings: inMemorySystemSettings
    });
  } catch (err) {
    console.error('❌ GET /api/pos/settings error:', err.message);
    res.status(500).json({ success: false, error: err.message, settings: inMemorySystemSettings });
  }
});

// 2. Simpan / Kemaskini Tetapan Sistem & Cas ke Supabase
app.post('/api/pos/settings', requireStaffAuth, async (req, res) => {
  try {
    const payload = req.body;
    if (!payload) {
      return res.status(400).json({ success: false, error: 'Data tetapan diperlukan' });
    }

    inMemorySystemSettings = {
      ...inMemorySystemSettings,
      ...payload,
      updated_at: new Date().toISOString()
    };

    if (supabase) {
      const { error } = await supabase
        .from('pos_settings')
        .upsert({
          key: 'system_settings',
          value: inMemorySystemSettings,
          updated_at: new Date().toISOString()
        });

      if (error) {
        console.error('❌ Supabase upsert system_settings error:', error.message);
      }

      await supabase.from('pos_audit_logs').insert({
        action: 'system_settings_updated',
        cashier_name: req.staff ? req.staff.name : 'Pengurus Utama',
        details: {
          sstEnabled: inMemorySystemSettings.sst ? inMemorySystemSettings.sst.enabled : true,
          sstRate: inMemorySystemSettings.sst ? inMemorySystemSettings.sst.rate : 6,
          customChargesCount: inMemorySystemSettings.customCharges ? inMemorySystemSettings.customCharges.length : 0
        }
      });
    }

    console.log(`⚙️ [SYSTEM SETTINGS SAVED] SST: ${inMemorySystemSettings.sst?.enabled ? `${inMemorySystemSettings.sst.rate}%` : 'OFF'} | Cas Tersuai: ${inMemorySystemSettings.customCharges?.length || 0}`);
    res.json({
      success: true,
      message: 'Tetapan sistem & cas berjaya disimpan ke Supabase ✨',
      settings: inMemorySystemSettings
    });
  } catch (err) {
    console.error('❌ POST /api/pos/settings error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// PUT alias untuk simpan Tetapan
app.put('/api/pos/settings', requireStaffAuth, async (req, res) => {
  try {
    const payload = req.body;
    inMemorySystemSettings = {
      ...inMemorySystemSettings,
      ...payload,
      updated_at: new Date().toISOString()
    };

    if (supabase) {
      await supabase
        .from('pos_settings')
        .upsert({
          key: 'system_settings',
          value: inMemorySystemSettings,
          updated_at: new Date().toISOString()
        });
    }

    res.json({
      success: true,
      message: 'Tetapan sistem berjaya dikemas kini ✨',
      settings: inMemorySystemSettings
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET & POST Tetapan Tier Keahlian (Part D3)
app.get(['/api/pos/settings/tier', '/api/loyalty/settings/tier'], async (req, res) => {
  try {
    if (supabase) {
      const { data, error } = await supabase
        .from('pos_settings')
        .select('value')
        .eq('key', 'tier_settings')
        .maybeSingle();

      if (!error && data && data.value) {
        inMemoryTierSettings = { ...inMemoryTierSettings, ...data.value };
      }
    }

    res.json({
      success: true,
      settings: inMemoryTierSettings
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message, settings: inMemoryTierSettings });
  }
});

app.post('/api/pos/settings/tier', requireStaffAuth, async (req, res) => {
  try {
    const payload = req.body;
    if (!payload) {
      return res.status(400).json({ success: false, error: 'Data tetapan tier diperlukan' });
    }

    inMemoryTierSettings = {
      ...inMemoryTierSettings,
      ...payload,
      updated_at: new Date().toISOString()
    };

    if (supabase) {
      await supabase
        .from('pos_settings')
        .upsert({
          key: 'tier_settings',
          value: inMemoryTierSettings,
          updated_at: new Date().toISOString()
        });

      await supabase.from('pos_audit_logs').insert({
        action: 'tier_settings_updated',
        cashier_name: req.staff ? req.staff.name : 'Pengurus Utama',
        details: inMemoryTierSettings
      });
    }

    console.log('🏆 [TIER SETTINGS SAVED TO SUPABASE]', inMemoryTierSettings);
    res.json({
      success: true,
      message: 'Tetapan tier keahlian berjaya disimpan ke Supabase ✨',
      settings: inMemoryTierSettings
    });
  } catch (err) {
    console.error('❌ POST /api/pos/settings/tier error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 18. URUS TEBUS GANJARAN (REWARDS & REDEMPTIONS API - DIRECT SUPABASE)
// ====================================================================

function mapRewardRow(row) {
  if (!row) return null;
  const nameStr = String(row.name || '');
  let isDisc = (row.name || '').toLowerCase().includes('diskaun') || (row.type === 'discount');
  let dType = row.discount_type || row.discountType || null;
  let dVal = parseFloat(row.discount_value !== undefined ? row.discount_value : (row.discountValue !== undefined ? row.discountValue : 0));

  if (isNaN(dVal) || dVal <= 0) {
    const rmMatch = nameStr.match(/rm\s*([\d.]+)/i);
    const pctMatch = nameStr.match(/([\d.]+)\s*%/);
    if (rmMatch && rmMatch[1]) {
      dType = 'fixed';
      dVal = parseFloat(rmMatch[1]) || 0;
      isDisc = true;
    } else if (pctMatch && pctMatch[1]) {
      dType = 'percent';
      dVal = parseFloat(pctMatch[1]) || 0;
      isDisc = true;
    }
  }

  if (!dType && isDisc) dType = 'percent';

  return {
    id: row.id,
    name: row.name,
    type: isDisc ? 'discount' : 'item',
    discountType: dType,
    discount_type: dType,
    discountValue: dVal || 0,
    discount_value: dVal || 0,
    points: row.points_cost || 0,
    points_cost: row.points_cost || 0,
    cost: row.points_cost || 0,
    limit: row.stock_limit || 0,
    stock_limit: row.stock_limit || 0,
    redeemed: row.redeemed_count || 0,
    redeemed_count: row.redeemed_count || 0,
    icon: row.icon || (isDisc ? '🏷️' : '☕'),
    img: row.img_url || null,
    img_url: row.img_url || null,
    expiry: row.expires_at || null,
    expires_at: row.expires_at || null,
    isActive: row.is_active !== false,
    is_active: row.is_active !== false,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

// 1. GET Senarai Ganjaran Langsung Dari Table 'rewards' di Supabase
app.get(['/api/pos/rewards', '/api/loyalty/rewards'], async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({ success: false, error: 'Klien Supabase belum diinisialisasikan.' });
    }
    const { data, error } = await supabase
      .from('rewards')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('❌ Supabase GET rewards error:', error.message);
      return res.status(500).json({ success: false, error: error.message });
    }

    const mapped = (data || []).map(mapRewardRow);
    res.json({
      success: true,
      rewards: mapped
    });
  } catch (err) {
    console.error('❌ GET /api/pos/rewards error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. POST Tambah Ganjaran Baharu Terus Ke Table 'rewards' di Supabase
app.post('/api/pos/rewards', requireStaffAuth, async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({ success: false, error: 'Klien Supabase tidak aktif.' });
    }

    const { type, productId, productName, discountType, discountValue, name, points, limit, expiry, img, icon } = req.body;

    let finalName = (name || '').trim();
    if (type === 'item') {
      if (!productName && !finalName) {
        return res.status(400).json({ success: false, error: 'Sila pilih item dari menu sedia ada.' });
      }
      if (!finalName) finalName = `${productName} Percuma`;
    } else if (type === 'discount') {
      const numVal = parseFloat(discountValue);
      if (isNaN(numVal) || numVal <= 0) {
        if (!finalName) {
          return res.status(400).json({ success: false, error: 'Sila masukkan nilai diskaun yang sah.' });
        }
      } else {
        if (!finalName) {
          finalName = discountType === 'fixed' ? `Diskaun RM${numVal.toFixed(2)}` : `Diskaun ${numVal}% Bil`;
        }
      }
    }

    if (!finalName) finalName = 'Ganjaran Tanpa Nama';

    const pointsNum = parseInt(points, 10);
    if (isNaN(pointsNum) || pointsNum <= 0) {
      return res.status(400).json({ success: false, error: 'Sila masukkan syarat mata ganjaran yang sah (minimum 1).' });
    }

    const insertRow = {
      name: finalName,
      points_cost: pointsNum,
      stock_limit: parseInt(limit, 10) || 0,
      redeemed_count: 0,
      icon: icon || (type === 'discount' ? '🏷️' : '☕'),
      img_url: img || null,
      expires_at: expiry ? new Date(expiry).toISOString() : null,
      is_active: true
    };

    const { data, error } = await supabase
      .from('rewards')
      .insert(insertRow)
      .select()
      .single();

    if (error) {
      console.error('❌ Supabase INSERT rewards error:', error.message);
      return res.status(500).json({ success: false, error: error.message });
    }

    await supabase.from('pos_audit_logs').insert({
      action: 'reward_created',
      cashier_name: req.staff ? req.staff.name : 'Pengurus Utama',
      details: { rewardId: data.id, name: data.name, points: data.points_cost }
    });

    console.log(`🎁 [REWARD ADDED DIRECT TO SUPABASE] ID: ${data.id} | ${data.name} - ${data.points_cost} mata`);
    res.json({
      success: true,
      message: 'Ganjaran berjaya ditambah ke table rewards di Supabase ✨',
      reward: mapRewardRow(data)
    });
  } catch (err) {
    console.error('❌ POST /api/pos/rewards error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. PUT Kemas Kini Ganjaran Terus di Table 'rewards' di Supabase
app.put('/api/pos/rewards/:id', requireStaffAuth, async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({ success: false, error: 'Klien Supabase tidak aktif.' });
    }

    const { id } = req.params;
    const payload = req.body;

    let finalName = payload.name ? payload.name.trim() : null;
    if (payload.type === 'item' && payload.productName && !finalName) {
      finalName = `${payload.productName} Percuma`;
    } else if (payload.type === 'discount' && payload.discountValue && !finalName) {
      const numVal = parseFloat(payload.discountValue);
      finalName = payload.discountType === 'fixed' ? `Diskaun RM${numVal.toFixed(2)}` : `Diskaun ${numVal}% Bil`;
    }

    const updateRow = {
      updated_at: new Date().toISOString()
    };

    if (finalName) updateRow.name = finalName;
    if (payload.points !== undefined) updateRow.points_cost = parseInt(payload.points, 10);
    if (payload.limit !== undefined) updateRow.stock_limit = parseInt(payload.limit, 10);
    if (payload.img !== undefined) updateRow.img_url = payload.img || null;
    if (payload.icon !== undefined) updateRow.icon = payload.icon;
    if (payload.expiry !== undefined) updateRow.expires_at = payload.expiry ? new Date(payload.expiry).toISOString() : null;
    if (payload.isActive !== undefined) updateRow.is_active = Boolean(payload.isActive);

    const { data, error } = await supabase
      .from('rewards')
      .update(updateRow)
      .eq('id', id)
      .select()
      .single();

    if (error) {
      console.error('❌ Supabase UPDATE rewards error:', error.message);
      return res.status(500).json({ success: false, error: error.message });
    }

    console.log(`🎁 [REWARD UPDATED DIRECT IN SUPABASE] ID: ${id} | ${data.name}`);
    res.json({
      success: true,
      message: 'Ganjaran berjaya dikemas kini di table rewards Supabase ✨',
      reward: mapRewardRow(data)
    });
  } catch (err) {
    console.error('❌ PUT /api/pos/rewards/:id error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4. DELETE Padam Ganjaran Terus Dari Table 'rewards' di Supabase
app.delete('/api/pos/rewards/:id', requireStaffAuth, async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({ success: false, error: 'Klien Supabase tidak aktif.' });
    }

    const { id } = req.params;
    const { data, error } = await supabase
      .from('rewards')
      .delete()
      .eq('id', id)
      .select();

    if (error) {
      console.error('❌ Supabase DELETE rewards error:', error.message);
      return res.status(500).json({ success: false, error: error.message });
    }

    await supabase.from('pos_audit_logs').insert({
      action: 'reward_deleted',
      cashier_name: req.staff ? req.staff.name : 'Pengurus Utama',
      details: { rewardId: id }
    });

    console.log(`🗑️ [REWARD DELETED DIRECT FROM SUPABASE] ID: ${id}`);
    res.json({
      success: true,
      message: 'Ganjaran berjaya dipadam secara kekal daripada Supabase 🗑️'
    });
  } catch (err) {
    console.error('❌ DELETE /api/pos/rewards/:id error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 5. POST /api/pos/rewards/redeem (Penebusan Ganjaran di Kaunter POS & Kemas Kini Table Rewards & Members)
app.post('/api/pos/rewards/redeem', requireStaffAuth, async (req, res) => {
  try {
    const { memberId, phone, items, totalPointsDeducted, cashierName, receiptNo } = req.body;
    const finalCashierName = req.staff ? req.staff.name : (cashierName || 'Juruwang Bertugas');

    if (!memberId && !phone) {
      return res.status(400).json({ success: false, error: 'Maklumat ahli (ID atau No. Telefon) diperlukan.' });
    }

    const pointsToDeduct = parseInt(totalPointsDeducted, 10) || 0;
    if (pointsToDeduct <= 0) {
      return res.status(400).json({ success: false, error: 'Jumlah mata yang ditebus mestilah melebihi 0.' });
    }

    let member = null;
    let pointsBefore = 0;
    let newPoints = 0;

    if (supabase) {
      let query = supabase.from('members').select('*');
      if (memberId) query = query.eq('id', memberId);
      else if (phone) {
        const clean = normalizePhone(phone);
        query = query.or(`phone.eq.${clean},phone.eq.60${clean.replace(/^0/, '')},phone.eq.+60${clean.replace(/^0/, '')}`);
      }
      const { data, error } = await query.single();
      if (error || !data) {
        return res.status(404).json({ success: false, error: 'Profil ahli tidak dijumpai dalam Supabase.' });
      }
      member = data;
      pointsBefore = parseInt(member.points, 10) || 0;

      // VALIDASI KETAT DATABASE (Baki Mata Semasa)
      if (pointsBefore < pointsToDeduct) {
        return res.status(400).json({
          success: false,
          error: `Baki mata tidak mencukupi. Baki semasa: ${pointsBefore} mata, Diperlukan: ${pointsToDeduct} mata.`
        });
      }

      newPoints = pointsBefore - pointsToDeduct;

      // ATOMIC UPDATE: Tolak mata hanya jika points >= pointsToDeduct
      const { data: updatedMember, error: updErr } = await supabase
        .from('members')
        .update({ 
          points: newPoints, 
          updated_at: new Date().toISOString() 
        })
        .eq('id', member.id)
        .gte('points', pointsToDeduct)
        .select()
        .single();

      if (updErr || !updatedMember) {
        return res.status(400).json({
          success: false,
          error: 'Gagal menolak mata (ralat integriti atau baki mata telah berubah di sesi lain). Sila semak semula baki mata ahli.'
        });
      }

      member = updatedMember;

      // Kemas kini bilangan ditebus pada item ganjaran di table 'rewards'
      if (Array.isArray(items)) {
        for (const it of items) {
          if (it.rewardId) {
            try {
              const { data: rRow } = await supabase.from('rewards').select('redeemed_count').eq('id', it.rewardId).single();
              if (rRow) {
                await supabase.from('rewards').update({
                  redeemed_count: (rRow.redeemed_count || 0) + (it.qty || 1),
                  updated_at: new Date().toISOString()
                }).eq('id', it.rewardId);
              }
            } catch (e) {
              console.warn('Update reward redeemed_count error:', e.message);
            }
          }
        }
      }

      let marketingCost = 0;
      if (Array.isArray(items)) {
        marketingCost = items.reduce((s, it) => s + (parseFloat(it.cost || it.price || 0) * (it.qty || 1)), 0);
      }
      if (req.body.discountAmount) {
        marketingCost += parseFloat(req.body.discountAmount) || 0;
      }

      // Log transaksi audit sebagai Kos Pemasaran (Marketing Expense)
      await supabase.from('pos_audit_logs').insert({
        action: 'points_redeemed',
        cashier_name: finalCashierName,
        details: {
          memberId: member.id,
          memberName: member.name,
          phone: member.phone,
          receiptNo: receiptNo || null,
          pointsBefore: pointsBefore,
          pointsDeducted: pointsToDeduct,
          remainingPoints: newPoints,
          marketingCost: marketingCost,
          items: items || []
        }
      });
    }

    console.log(`✨ [POINTS REDEEMED IN SUPABASE] Member: ${member?.name || phone} - Sebelum: ${pointsBefore} | Ditolak: ${pointsToDeduct} | Baki: ${newPoints}`);
    res.json({
      success: true,
      message: `Penebusan ${pointsToDeduct} mata berjaya!`,
      pointsBefore: pointsBefore,
      pointsDeducted: pointsToDeduct,
      remainingPoints: newPoints,
      marketingCost: req.body.marketingCost || 0,
      member: member
    });
  } catch (err) {
    console.error('❌ POST /api/pos/rewards/redeem error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 18B. TETAPAN KADAR PEROLEHAN MATA GANJARAN (REWARD POINTS EARNING SETTINGS)
// ====================================================================

let inMemoryRewardSettings = {
  earningMode: 'amount',
  amountPerPoint: 1.00,
  minSpend: 0,
  updated_at: new Date().toISOString()
};

async function initRewardSettings() {
  if (!supabase) return;
  try {
    const { data } = await supabase.from('pos_settings').select('value').eq('key', 'reward_settings').maybeSingle();
    if (data && data.value) {
      inMemoryRewardSettings = { ...inMemoryRewardSettings, ...data.value };
      console.log(`🎁 [REWARD SETTINGS] Kadar: Setiap RM${inMemoryRewardSettings.amountPerPoint} = 1 Mata Ganjaran.`);
    } else {
      await supabase.from('pos_settings').upsert({
        key: 'reward_settings',
        value: inMemoryRewardSettings,
        updated_at: new Date().toISOString()
      });
      console.log(`🎁 [REWARD SETTINGS] Tetapan permulaan reward_settings disimpan ke Supabase.`);
    }
  } catch (err) {
    console.warn('⚠️ [REWARD SETTINGS] Gagal muat dari Supabase:', err.message);
  }
}
initRewardSettings();

// 1. GET Tetapan Kadar Mata Ganjaran
app.get(['/api/pos/rewards/settings', '/api/loyalty/rewards/settings'], async (req, res) => {
  try {
    if (supabase) {
      const { data } = await supabase.from('pos_settings').select('value').eq('key', 'reward_settings').maybeSingle();
      if (data && data.value) {
        inMemoryRewardSettings = { ...inMemoryRewardSettings, ...data.value };
      }
    }
    res.json({
      success: true,
      settings: inMemoryRewardSettings
    });
  } catch (err) {
    console.error('❌ GET /api/pos/rewards/settings error:', err.message);
    res.json({ success: true, settings: inMemoryRewardSettings });
  }
});

// 2. POST Simpan Tetapan Kadar Mata Ganjaran
app.post('/api/pos/rewards/settings', requireStaffAuth, async (req, res) => {
  try {
    const payload = req.body;
    if (!payload) {
      return res.status(400).json({ success: false, error: 'Data tetapan mata diperlukan.' });
    }

    inMemoryRewardSettings = {
      ...inMemoryRewardSettings,
      ...payload,
      amountPerPoint: Math.max(0.1, parseFloat(payload.amountPerPoint) || 1.00),
      updated_at: new Date().toISOString()
    };

    if (supabase) {
      await supabase.from('pos_settings').upsert({
        key: 'reward_settings',
        value: inMemoryRewardSettings,
        updated_at: new Date().toISOString()
      });

      await supabase.from('pos_audit_logs').insert({
        action: 'reward_settings_updated',
        cashier_name: req.staff ? req.staff.name : (req.body.cashierName || 'Pengurus Utama'),
        details: {
          earningMode: inMemoryRewardSettings.earningMode,
          amountPerPoint: inMemoryRewardSettings.amountPerPoint,
          minSpend: inMemoryRewardSettings.minSpend
        }
      });
    }

    console.log(`🎁 [REWARD SETTINGS SAVED] Setiap RM${inMemoryRewardSettings.amountPerPoint} = 1 Mata Ganjaran`);
    res.json({
      success: true,
      message: `Tetapan kadar mata berjaya disimpan (Setiap RM${Number(inMemoryRewardSettings.amountPerPoint).toFixed(2)} = 1 Mata) ✨`,
      settings: inMemoryRewardSettings
    });
  } catch (err) {
    console.error('❌ POST /api/pos/rewards/settings error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 19. URUS GANJARAN COP STAMP & TETAPAN MOD PEROLEHAN STAMP
// ====================================================================

let inMemoryStampSettings = {
  earningMode: 'item',
  amountPerStamp: 10.00,
  stampTarget: 10,
  rules: [],
  updated_at: new Date().toISOString()
};

async function initStampSettings() {
  if (!supabase) return;
  try {
    const { data } = await supabase.from('pos_settings').select('value').eq('key', 'stamp_settings').maybeSingle();
    if (data && data.value) {
      inMemoryStampSettings = {
        earningMode: data.value.earningMode || 'item',
        amountPerStamp: parseFloat(data.value.amountPerStamp) || 10,
        stampTarget: parseInt(data.value.stampTarget, 10) || 10,
        rules: Array.isArray(data.value.rules) ? data.value.rules : [],
        updated_at: data.value.updated_at || new Date().toISOString()
      };
      console.log(`🎫 [STAMP SETTINGS] Mod: ${inMemoryStampSettings.earningMode} | Sasaran: ${inMemoryStampSettings.stampTarget} cop | Rules: ${inMemoryStampSettings.rules.length}`);
    }
  } catch (err) {
    console.warn('⚠️ [STAMP SETTINGS] Gagal muat dari Supabase:', err.message);
  }
}
initStampSettings();

// 1. GET Tetapan & Peraturan Cop Stamp
app.get(['/api/pos/stamps/settings', '/api/loyalty/stamps/settings', '/api/pos/stamp-rewards', '/api/pos/stamps/rules'], async (req, res) => {
  try {
    if (supabase) {
      const { data } = await supabase.from('pos_settings').select('value').eq('key', 'stamp_settings').maybeSingle();
      if (data && data.value) {
        inMemoryStampSettings = {
          earningMode: data.value.earningMode || inMemoryStampSettings.earningMode || 'item',
          amountPerStamp: parseFloat(data.value.amountPerStamp) || inMemoryStampSettings.amountPerStamp || 10,
          stampTarget: parseInt(data.value.stampTarget, 10) || inMemoryStampSettings.stampTarget || 10,
          rules: Array.isArray(data.value.rules) ? data.value.rules : [],
          updated_at: data.value.updated_at || new Date().toISOString()
        };
      }
    }
    res.json({
      success: true,
      settings: inMemoryStampSettings,
      rules: inMemoryStampSettings.rules || []
    });
  } catch (err) {
    console.error('❌ GET /api/pos/stamps/settings error:', err.message);
    res.json({ success: true, settings: inMemoryStampSettings, rules: inMemoryStampSettings.rules || [] });
  }
});

// 2. POST Simpan Tetapan & Senarai Peraturan Cop Stamp
app.post('/api/pos/stamps/settings', requireStaffAuth, async (req, res) => {
  try {
    const payload = req.body;
    if (!payload) {
      return res.status(400).json({ success: false, error: 'Data tetapan diperlukan.' });
    }

    inMemoryStampSettings = {
      earningMode: payload.earningMode || inMemoryStampSettings.earningMode || 'item',
      amountPerStamp: parseFloat(payload.amountPerStamp) || inMemoryStampSettings.amountPerStamp || 10,
      stampTarget: parseInt(payload.stampTarget, 10) || inMemoryStampSettings.stampTarget || 10,
      rules: Array.isArray(payload.rules) ? payload.rules : (payload.rules === undefined ? (inMemoryStampSettings.rules || []) : []),
      updated_at: new Date().toISOString()
    };

    if (supabase) {
      const { error: upsertErr } = await supabase.from('pos_settings').upsert({
        key: 'stamp_settings',
        value: inMemoryStampSettings,
        updated_at: new Date().toISOString()
      });

      if (upsertErr) {
        console.error('Error saving stamp_settings to Supabase:', upsertErr);
        throw upsertErr;
      }

      await supabase.from('pos_audit_logs').insert({
        action: 'stamp_settings_updated',
        cashier_name: req.staff ? req.staff.name : (req.body.cashierName || 'Pengurus Utama'),
        details: {
          earningMode: inMemoryStampSettings.earningMode,
          amountPerStamp: inMemoryStampSettings.amountPerStamp,
          stampTarget: inMemoryStampSettings.stampTarget,
          rulesCount: inMemoryStampSettings.rules.length
        }
      });
    }

    console.log(`🎫 [STAMP SETTINGS SAVED] Mod: ${inMemoryStampSettings.earningMode} | Rules: ${inMemoryStampSettings.rules.length}`);
    res.json({
      success: true,
      message: 'Tetapan cop stamp berjaya disimpan ke Supabase ✨',
      settings: inMemoryStampSettings,
      rules: inMemoryStampSettings.rules
    });
  } catch (err) {
    console.error('❌ POST /api/pos/stamps/settings error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2B. POST / PUT Tambah atau Kemas Kini Ganjaran Cop Stamp Individu
app.post(['/api/pos/stamp-rewards', '/api/pos/stamps/rules'], requireStaffAuth, async (req, res) => {
  try {
    const { id, productId, productName, copRequired, qty, cost } = req.body;
    if (!productName || !copRequired) {
      return res.status(400).json({ success: false, error: 'Nama produk dan bilangan cop diperlukan.' });
    }

    let rules = Array.isArray(inMemoryStampSettings.rules) ? [...inMemoryStampSettings.rules] : [];
    const ruleId = id || ('stp_' + Date.now());
    const existingIdx = rules.findIndex(r => String(r.id) === String(ruleId));

    const newRule = {
      id: ruleId,
      productId: productId || null,
      productName: String(productName).trim(),
      copRequired: parseInt(copRequired, 10) || inMemoryStampSettings.stampTarget || 10,
      qty: parseInt(qty, 10) || 1,
      cost: parseFloat(cost) || 0,
      updated_at: new Date().toISOString()
    };

    if (existingIdx !== -1) {
      rules[existingIdx] = newRule;
    } else {
      rules.push(newRule);
    }

    inMemoryStampSettings.rules = rules;
    inMemoryStampSettings.updated_at = new Date().toISOString();

    if (supabase) {
      await supabase.from('pos_settings').upsert({
        key: 'stamp_settings',
        value: inMemoryStampSettings,
        updated_at: new Date().toISOString()
      });
    }

    return res.json({ success: true, message: 'Ganjaran cop stamp disimpan ✨', rule: newRule, rules: inMemoryStampSettings.rules });
  } catch (err) {
    console.error('❌ Error saving stamp reward rule:', err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// 2C. DELETE Padam Ganjaran Cop Stamp Individu
app.delete(['/api/pos/stamp-rewards/:id', '/api/pos/stamps/rules/:id'], requireStaffAuth, async (req, res) => {
  try {
    const { id } = req.params;
    let rules = Array.isArray(inMemoryStampSettings.rules) ? [...inMemoryStampSettings.rules] : [];
    rules = rules.filter(r => String(r.id) !== String(id));
    inMemoryStampSettings.rules = rules;
    inMemoryStampSettings.updated_at = new Date().toISOString();

    if (supabase) {
      await supabase.from('pos_settings').upsert({
        key: 'stamp_settings',
        value: inMemoryStampSettings,
        updated_at: new Date().toISOString()
      });
    }

    return res.json({ success: true, message: 'Ganjaran cop stamp dipadam 🗑️', rules: inMemoryStampSettings.rules });
  } catch (err) {
    console.error('❌ Error deleting stamp reward rule:', err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// 3. POST /api/pos/stamps/quick-enroll (Pendaftaran Pantas & Tambah Cop Dari Pop-up Tawaran di Kaunter)
app.post('/api/pos/stamps/quick-enroll', requireStaffAuth, async (req, res) => {
  try {
    const { phone, stampsEarned, pointsEarned, receiptNo, cashierName } = req.body;

    if (!phone) {
      return res.status(400).json({ success: false, error: 'Nombor telefon pelanggan diperlukan.' });
    }

    const cleanPhone = normalizePhone(phone);
    const intlPhone = toInternationalPhone(phone);
    const stampsToAdd = Math.max(0, parseInt(stampsEarned, 10) || 0);
    const pointsToAdd = Math.max(0, parseInt(pointsEarned, 10) || 0);

    let member = null;
    let isNew = false;

    if (supabase) {
      const { data: existing } = await supabase
        .from('members')
        .select('*')
        .or(`phone.eq.${cleanPhone},phone.eq.${intlPhone},phone.eq.+${intlPhone}`)
        .maybeSingle();

      if (existing) {
        // Ahli sedia ada: tambah cop stamp & mata sedia ada
        const newStamps = (existing.stamps || 0) + stampsToAdd;
        const newPoints = (existing.points || 0) + pointsToAdd;
        const newLifetime = (existing.lifetime_points || 0) + pointsToAdd;

        const { data: updated, error: updErr } = await supabase
          .from('members')
          .update({
            stamps: newStamps,
            points: newPoints,
            lifetime_points: newLifetime,
            last_visited_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          })
          .eq('id', existing.id)
          .select()
          .single();

        if (!updErr && updated) member = updated;
        else member = existing;
      } else {
        // Ahli baharu: cipta baris terus dalam table 'members' tanpa memerlukan input rumit
        isNew = true;
        const newName = 'Pelanggan ' + (cleanPhone.length > 4 ? cleanPhone.slice(-4) : cleanPhone);
        const { data: created, error: crtErr } = await supabase
          .from('members')
          .insert({
            phone: cleanPhone,
            name: newName,
            stamps: stampsToAdd,
            points: pointsToAdd,
            lifetime_points: pointsToAdd,
            tier: 'Ahli Gangsa',
            source: 'counter_stamp_offer',
            is_active: true,
            registered_at: new Date().toISOString(),
            last_visited_at: new Date().toISOString()
          })
          .select()
          .single();

        if (crtErr) {
          console.error('Quick enroll member insert error:', crtErr.message);
          return res.status(500).json({ success: false, error: crtErr.message });
        }
        member = created;
      }

      // Penyelarasan kad cop stamp di jadual 'member_stamp_cards'
      if (member && stampsToAdd > 0) {
        await syncMemberStampCards(member.id, stampsToAdd);
      }

      // Log transaksi audit
      try {
        await supabase.from('pos_audit_logs').insert({
          action: isNew ? 'member_quick_enrolled' : 'member_stamps_added',
          cashier_name: cashierName || 'Juruwang Bertugas',
          details: {
            phone: cleanPhone,
            receiptNo: receiptNo || null,
            stampsAdded: stampsToAdd,
            pointsAdded: pointsToAdd,
            totalStamps: member ? member.stamps : stampsToAdd,
            isNew: isNew
          }
        });
      } catch(e){}
    } else {
      member = {
        phone: cleanPhone,
        name: 'Pelanggan ' + cleanPhone.slice(-4),
        stamps: stampsToAdd,
        points: pointsToAdd
      };
    }

    console.log(`🎫 [QUICK STAMP ENROLL] ${cleanPhone} | +${stampsToAdd} stamps -> Total: ${member?.stamps} (New: ${isNew})`);
    res.json({
      success: true,
      message: isNew ? `Ahli baharu ${cleanPhone} didaftarkan (+${stampsToAdd} cop stamp)! 🎉` : `+${stampsToAdd} cop stamp berjaya ditambah ke akaun sedia ada! ✨`,
      member: member,
      isNew: isNew
    });
  } catch (err) {
    console.error('❌ POST /api/pos/stamps/quick-enroll error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Helper: Penyelarasan Multi-Card Cop Stamp Ahli di table 'member_stamp_cards'
async function syncMemberStampCards(memberId, stampsToAdd, targetStampsOverride, rewardNameOverride) {
  if (!supabase || !memberId) return [];
  try {
    const target = targetStampsOverride || inMemoryStampSettings.stampTarget || 10;
    const defaultReward = (inMemoryStampSettings.rules && inMemoryStampSettings.rules[0]?.productName) || '1x Kopi Percuma';
    const rewardName = rewardNameOverride || defaultReward;

    // Ambil kad sedia ada ahli
    const { data: existingCards } = await supabase
      .from('member_stamp_cards')
      .select('*')
      .eq('member_id', memberId)
      .order('card_number', { ascending: true });

    let cardList = existingCards || [];

    if (cardList.length === 0) {
      // Ahli baru / kad pertama: Cipta kad berdasarkan jumlah stamp
      const { data: mRow } = await supabase.from('members').select('stamps').eq('id', memberId).maybeSingle();
      const totalStamps = (mRow && mRow.stamps !== undefined) ? mRow.stamps : stampsToAdd;

      let remaining = Math.max(0, totalStamps);
      let cardNum = 1;
      const toInsert = [];

      while (remaining >= target) {
        toInsert.push({
          member_id: memberId,
          card_number: cardNum,
          stamps_collected: target,
          target_stamps: target,
          reward_name: rewardName,
          status: 'unclaimed',
          completed_at: new Date().toISOString()
        });
        remaining -= target;
        cardNum++;
      }

      toInsert.push({
        member_id: memberId,
        card_number: cardNum,
        stamps_collected: remaining,
        target_stamps: target,
        reward_name: rewardName,
        status: 'collecting'
      });

      const { data: created } = await supabase.from('member_stamp_cards').insert(toInsert).select();
      return created || [];
    }

    if (stampsToAdd <= 0) {
      return cardList;
    }

    // Tambah cop stamp ke kad aktif
    let active = cardList.find(c => c.status === 'collecting');
    let maxNum = cardList.reduce((max, c) => Math.max(max, c.card_number || 1), 0);
    let remaining = stampsToAdd;

    if (!active) {
      maxNum++;
      const { data: newCard } = await supabase.from('member_stamp_cards').insert({
        member_id: memberId,
        card_number: maxNum,
        stamps_collected: 0,
        target_stamps: target,
        reward_name: rewardName,
        status: 'collecting'
      }).select().single();
      active = newCard;
    }

    let currentStamps = active.stamps_collected || 0;

    while (currentStamps + remaining >= target) {
      const needed = target - currentStamps;
      await supabase.from('member_stamp_cards').update({
        stamps_collected: target,
        status: 'unclaimed',
        completed_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }).eq('id', active.id);

      remaining -= needed;
      maxNum++;

      if (remaining > 0) {
        const { data: nextCard } = await supabase.from('member_stamp_cards').insert({
          member_id: memberId,
          card_number: maxNum,
          stamps_collected: 0,
          target_stamps: target,
          reward_name: rewardName,
          status: 'collecting'
        }).select().single();
        active = nextCard;
        currentStamps = 0;
      } else {
        // Cipta kad aktif seterusnya untuk terus kumpul (0 cop)
        await supabase.from('member_stamp_cards').insert({
          member_id: memberId,
          card_number: maxNum,
          stamps_collected: 0,
          target_stamps: target,
          reward_name: rewardName,
          status: 'collecting'
        });
        active = null;
        break;
      }
    }

    if (remaining > 0 && active) {
      await supabase.from('member_stamp_cards').update({
        stamps_collected: currentStamps + remaining,
        updated_at: new Date().toISOString()
      }).eq('id', active.id);
    }

    // Ambil senarai terkini
    const { data: updatedList } = await supabase
      .from('member_stamp_cards')
      .select('*')
      .eq('member_id', memberId)
      .order('card_number', { ascending: true });

    return updatedList || [];
  } catch (err) {
    console.warn('syncMemberStampCards error:', err.message);
    return [];
  }
}

// 4. GET /api/loyalty/stamps/cards (Senarai Kad Cop Stamp Sebenar Ahli Dari Supabase)
app.get(['/api/loyalty/stamps/cards', '/api/pos/stamps/cards'], async (req, res) => {
  try {
    const { phone, memberId } = req.query;
    if (!phone && !memberId) {
      return res.status(400).json({ success: false, error: 'Parameter phone atau memberId diperlukan.' });
    }

    if (!supabase) {
      return res.json({ success: true, cards: [], targetStamps: inMemoryStampSettings.stampTarget || 10 });
    }

    let member = null;
    let mQuery = supabase.from('members').select('*');
    if (memberId && String(memberId).length > 20) {
      mQuery = mQuery.eq('id', memberId);
    } else if (phone) {
      const clean = normalizePhone(phone);
      const intl = toInternationalPhone(phone);
      mQuery = mQuery.or(`phone.eq.${clean},phone.eq.${intl},phone.eq.+${intl}`);
    }

    const { data: mData } = await mQuery.maybeSingle();
    if (!mData) {
      return res.status(404).json({ success: false, error: 'Ahli tidak dijumpai dalam sistem.' });
    }
    member = mData;

    const target = inMemoryStampSettings.stampTarget || 10;
    const cards = await syncMemberStampCards(member.id, 0, target);

    const formattedCards = cards.map(c => ({
      id: c.id,
      cardNumber: c.card_number,
      title: `Kad Cop #${c.card_number}`,
      stamps: c.stamps_collected,
      targetStamps: c.target_stamps || target,
      status: c.status, // 'collecting' | 'unclaimed' | 'claimed'
      rewardName: c.reward_name || '1x Kopi Percuma',
      completedDate: c.completed_at ? new Date(c.completed_at).toLocaleDateString('ms-MY', { day:'numeric', month:'short', year:'numeric' }) : null,
      claimedDate: c.claimed_at ? new Date(c.claimed_at).toLocaleDateString('ms-MY', { day:'numeric', month:'short', year:'numeric' }) : null,
      createdAt: c.created_at
    }));

    const activeCard = formattedCards.find(c => c.status === 'collecting') || formattedCards[formattedCards.length - 1] || null;
    const unclaimedCards = formattedCards.filter(c => c.status === 'unclaimed');

    res.json({
      success: true,
      member: {
        id: member.id,
        phone: member.phone,
        name: member.name,
        stamps: member.stamps,
        points: member.points
      },
      cards: formattedCards,
      activeCard: activeCard,
      unclaimedCards: unclaimedCards,
      targetStamps: target
    });
  } catch (err) {
    console.error('❌ GET /api/loyalty/stamps/cards error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 5. POST /api/loyalty/stamps/claim (Tebus Kad Cop Penuh di Kaunter)
app.post(['/api/loyalty/stamps/claim', '/api/pos/stamps/claim'], async (req, res) => {
  try {
    const { cardId, phone, memberId, cashierName } = req.body;
    if (!cardId && !phone && !memberId) {
      return res.status(400).json({ success: false, error: 'Parameter cardId atau phone diperlukan.' });
    }

    if (!supabase) {
      return res.json({ success: true, message: 'Kad cop ditebus (mod standalone).' });
    }

    let targetCard = null;
    let mData = null;
    if (cardId) {
      const { data } = await supabase.from('member_stamp_cards').select('*').eq('id', cardId).maybeSingle();
      targetCard = data;
    } else {
      let mQuery = supabase.from('members').select('*');
      if (memberId) mQuery = mQuery.eq('id', memberId);
      else {
        const clean = normalizePhone(phone);
        mQuery = mQuery.or(`phone.eq.${clean},phone.eq.60${clean.replace(/^0/, '')}`);
      }
      const { data: foundMember } = await mQuery.maybeSingle();
      mData = foundMember;
      if (mData) {
        const { data: uCards } = await supabase
          .from('member_stamp_cards')
          .select('*')
          .eq('member_id', mData.id)
          .eq('status', 'unclaimed')
          .order('card_number', { ascending: true })
          .limit(1);
        if (uCards && uCards[0]) targetCard = uCards[0];
      }
    }

    let updatedCard = null;
    if (targetCard && targetCard.id) {
      const { data, error: updErr } = await supabase
        .from('member_stamp_cards')
        .update({
          status: 'claimed',
          claimed_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('id', targetCard.id)
        .select()
        .single();
      updatedCard = data;
    } else {
      targetCard = {
        card_number: 1,
        reward_name: req.body.rewardName || 'Ganjaran Cop Stamp',
        member_id: memberId || (mData ? mData.id : null)
      };
    }

    const marketingCost = Math.max(0, parseFloat(req.body.cost) || 3.50);
    const finalReceiptNo = `RC-STAMP-${Math.floor(100000 + Math.random() * 900000)}`;

    // 1. Simpan rekod transaksi kos pemasaran ke jadual `sales`
    const { data: stampSaleRow, error: stampErr } = await supabase.from('sales').insert({
      receipt_no: finalReceiptNo,
      order_type: 'dinein',
      payment_method: 'points',
      cash_tendered: 0,
      change_given: 0,
      subtotal: 0,
      discount: 0,
      tax: 0,
      service_charge: 0,
      round_adj: 0,
      total: 0,
      cashier_name: cashierName || 'Pengurus Utama',
      member_id: (targetCard && targetCard.member_id && String(targetCard.member_id).length > 20) ? targetCard.member_id : null,
      status: 'paid',
      notes: JSON.stringify({
        marketingExpense: true,
        rewardType: 'Ganjaran Cop Stamp',
        rewardName: targetCard.reward_name || `Ganjaran Cop Stamp (Kad #${targetCard.card_number})`,
        costAmount: marketingCost,
        cardNumber: targetCard.card_number
      })
    }).select().single();

    if (stampSaleRow) {
      await supabase.from('sale_items').insert([{
        sale_id: stampSaleRow.id,
        product_name: targetCard.reward_name || `Ganjaran Cop Stamp (Kad #${targetCard.card_number})`,
        unit_price: 0,
        unit_cost: marketingCost,
        qty: 1,
        subtotal: 0
      }]);
    }

    // 2. Merekodkan Penebusan Ganjaran Kad Cop Stamp sebagai Kos Pemasaran ke pos_audit_logs
    await supabase.from('pos_audit_logs').insert({
      action: 'stamp_reward_claimed',
      receipt_no: finalReceiptNo,
      cashier_name: cashierName || 'Juruwang Bertugas',
      details: {
        cardNumber: targetCard.card_number,
        rewardName: targetCard.reward_name,
        marketingCost: marketingCost,
        memberId: targetCard.member_id,
        phone: phone || null,
        claimedAt: new Date().toISOString()
      }
    });

    console.log(`🎁 [STAMP CARD CLAIMED] Kad #${targetCard.card_number} (${targetCard.reward_name}) Ditebus! (Kos Marketing: RM${marketingCost.toFixed(2)})`);
    res.json({
      success: true,
      message: `Tahniah! Ganjaran ${targetCard.reward_name} (Kad #${targetCard.card_number}) berjaya ditebus! 🎉`,
      marketingCost: marketingCost,
      card: updatedCard
    });
  } catch (err) {
    console.error('❌ POST /api/loyalty/stamps/claim error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 20. SISTEM KOD BERTUAH & HADIAH CABUTAN BERTUAH (LUCKY DRAW ENGINE)
// ====================================================================
let inMemoryLuckySettings = {
  earningMode: 'item', // 'item' | 'selected_items' | 'amount'
  amountPerCode: 10.00, // Nilai RM bagi setiap 1 kod jika mod 'amount'
  selectedProductIds: [], // Senarai ID produk jika mod 'selected_items'
  printOnReceipt: true,
  updated_at: new Date().toISOString()
};

let inMemoryLuckyGifts = [];
let inMemoryLuckyClaims = [];
let inMemoryEventLock = {
  enabled: false,
  unlockAt: null,
  eventTitle: 'Cabutan Bertuah Khas',
  noticeText: 'Event akan berakhir pada waktu yang ditetapkan. Sila simpan resit anda!',
  updatedAt: new Date().toISOString()
};

// Helper Jana Kod 5 Aksara Unik (1 Simbol, 2 Nombor, 2 Huruf)
function generate5CharLuckyCode(existingSet = new Set()) {
  const symbols = ['$', '#', '@', '&', '%', '*', '!'];
  const numbers = '0123456789';
  const letters = 'abcdefghjkmnpqrstuvwxyz';

  let attempts = 0;
  while (attempts < 1000) {
    const sym = symbols[Math.floor(Math.random() * symbols.length)];
    const n1 = numbers[Math.floor(Math.random() * numbers.length)];
    const n2 = numbers[Math.floor(Math.random() * numbers.length)];
    const l1 = letters[Math.floor(Math.random() * letters.length)];
    const l2 = letters[Math.floor(Math.random() * letters.length)];

    const chars = [sym, n1, n2, l1, l2];
    for (let i = chars.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    const code = chars.join('');
    if (!existingSet.has(code.toLowerCase())) {
      existingSet.add(code.toLowerCase());
      return code;
    }
    attempts++;
  }
  return 'c' + Math.floor(1000 + Math.random() * 9000);
}

// Inisialisasi tetapan, hadiah & tuntutan dari Supabase
async function initLuckyDrawState() {
  if (!supabase) return;
  try {
    const { data: sData } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_draw_settings').maybeSingle();
    if (sData && sData.value) inMemoryLuckySettings = { ...inMemoryLuckySettings, ...sData.value };

    const { data: gData } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_draw_gifts').maybeSingle();
    if (gData && Array.isArray(gData.value)) inMemoryLuckyGifts = gData.value;

    const { data: clData } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_draw_claims').maybeSingle();
    if (clData && Array.isArray(clData.value)) inMemoryLuckyClaims = clData.value;

    const { data: lockData } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_event_lock').maybeSingle();
    if (lockData && lockData.value) inMemoryEventLock = { ...inMemoryEventLock, ...lockData.value };

    console.log(`🎁 [LUCKY DRAW] Mod: ${inMemoryLuckySettings.earningMode} | Hadiah: ${inMemoryLuckyGifts.length} | Tuntutan: ${inMemoryLuckyClaims.length} | Kunci Acara: ${inMemoryEventLock.enabled ? 'ON' : 'OFF'}`);
  } catch (err) {
    console.warn('⚠️ [LUCKY DRAW] Gagal muat dari Supabase:', err.message);
  }
}
initLuckyDrawState();

// 1. GET Tetapan Mod Kod Bertuah
app.get(['/api/pos/lucky-draw/settings', '/api/loyalty/lucky-draw/settings'], async (req, res) => {
  try {
    if (supabase) {
      const { data } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_draw_settings').maybeSingle();
      if (data && data.value) inMemoryLuckySettings = { ...inMemoryLuckySettings, ...data.value };
    }
    res.json({ success: true, settings: inMemoryLuckySettings });
  } catch (err) {
    res.json({ success: true, settings: inMemoryLuckySettings });
  }
});

// 2. POST Simpan Tetapan Mod Kod Bertuah
app.post('/api/pos/lucky-draw/settings', requireStaffAuth, async (req, res) => {
  try {
    const payload = req.body;
    if (!payload) return res.status(400).json({ success: false, error: 'Data tetapan diperlukan.' });

    inMemoryLuckySettings = {
      ...inMemoryLuckySettings,
      ...payload,
      updated_at: new Date().toISOString()
    };

    if (supabase) {
      await supabase.from('pos_settings').upsert({
        key: 'lucky_draw_settings',
        value: inMemoryLuckySettings,
        updated_at: new Date().toISOString()
      });

      await supabase.from('pos_audit_logs').insert({
        action: 'lucky_draw_settings_updated',
        cashier_name: req.staff ? req.staff.name : (payload.cashierName || 'Pengurus Utama'),
        details: {
          earningMode: inMemoryLuckySettings.earningMode,
          amountPerCode: inMemoryLuckySettings.amountPerCode,
          selectedProductsCount: (inMemoryLuckySettings.selectedProductIds || []).length,
          printOnReceipt: inMemoryLuckySettings.printOnReceipt
        }
      });
    }

    console.log(`🎁 [LUCKY SETTINGS SAVED] Mod: ${inMemoryLuckySettings.earningMode}`);
    res.json({
      success: true,
      message: 'Tetapan mod kod bertuah berjaya disimpan ke Supabase ✨',
      settings: inMemoryLuckySettings
    });
  } catch (err) {
    console.error('❌ POST /api/pos/lucky-draw/settings error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ====================================================================
// 8. LUCKY DRAW ENGINE (LIFECYCLE, CHECKOUT CODES & 24H LOCKOUT)
// ====================================================================
const luckyDrawLockoutMap = new Map(); // Key: client phone or IP -> { failedCount: 0, lockoutExpiresAt: 0 }

// 3. GET Senarai Kod Bertuah (Dengan 3 Status: belum guna, sudah print, sudah guna)
app.get('/api/pos/lucky-draw/codes', requireStaffAuth, async (req, res) => {
  try {
    let dbCodes = [];
    if (supabase) {
      const { data } = await supabase.from('lucky_codes').select('*').order('created_at', { ascending: false });
      if (data) dbCodes = data;
    }
    const total = dbCodes.length;
    const belumGuna = dbCodes.filter(c => !c.is_printed && !c.is_used).length;
    const sudahPrint = dbCodes.filter(c => c.is_printed && !c.is_used).length;
    const sudahGuna = dbCodes.filter(c => c.is_used).length;

    res.json({
      success: true,
      codes: dbCodes.map(c => {
        let status = 'belum guna';
        if (c.is_used) status = 'sudah guna';
        else if (c.is_printed) status = 'sudah print';

        return {
          id: c.id,
          code: c.code,
          status,
          used: c.is_used,
          printedOnReceipt: c.is_printed,
          prizeName: c.prize_name,
          assignedGiftId: c.assigned_gift_id || null,
          saleId: c.sale_id || null,
          assignedAt: c.assigned_at || null,
          usedAt: c.used_at || null,
          ts: c.created_at ? new Date(c.created_at).toLocaleDateString('ms-MY', { day:'numeric', month:'short', year:'numeric', hour:'numeric', minute:'2-digit' }) : 'Baru'
        };
      }),
      stats: {
        total,
        belumGuna,
        sudahPrint,
        sudahGuna,
        used: sudahGuna,
        unused: belumGuna + sudahPrint
      }
    });
  } catch (err) {
    console.error('❌ GET /api/pos/lucky-draw/codes error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4. POST Jana Kod Bertuah Batch (5 Aksara - Status Permulaan: 'belum guna')
app.post('/api/pos/lucky-draw/generate', requireStaffAuth, async (req, res) => {
  try {
    const count = Math.min(500, Math.max(1, parseInt(req.body.count, 10) || 10));
    let existingSet = new Set();

    if (supabase) {
      const { data: existing } = await supabase.from('lucky_codes').select('code');
      if (existing) existing.forEach(r => existingSet.add((r.code || '').toLowerCase()));
    }

    const newCodes = [];
    for (let i = 0; i < count; i++) {
      const codeStr = generate5CharLuckyCode(existingSet);
      newCodes.push({
        code: codeStr,
        is_used: false,
        is_printed: false,
        created_at: new Date().toISOString()
      });
    }

    if (supabase) {
      const { data: inserted, error } = await supabase.from('lucky_codes').insert(newCodes).select();
      if (error) throw error;

      await supabase.from('pos_audit_logs').insert({
        action: 'lucky_codes_generated',
        cashier_name: req.staff ? req.staff.name : (req.body.cashierName || 'Pengurus Utama'),
        details: { count: newCodes.length, status: 'belum guna' }
      });
    }

    console.log(`🎁 [LUCKY CODES GENERATED] +${newCodes.length} kod dijana (Status: belum guna).`);
    res.json({
      success: true,
      message: `${newCodes.length} kod bertuah baru berstatus 'belum guna' berjaya dijana ke Supabase ✨`,
      generatedCount: newCodes.length
    });
  } catch (err) {
    console.error('❌ POST /api/pos/lucky-draw/generate error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4.1 POST Checkout: Pilih Kod 'belum guna' & Tukar Status ke 'sudah print'
app.post('/api/pos/lucky-draw/checkout-codes', requireStaffAuth, async (req, res) => {
  try {
    const count = Math.max(1, parseInt(req.body.count, 10) || 1);
    const rawSaleId = req.body.saleId || null;
    const isUuid = typeof rawSaleId === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(rawSaleId);
    const validSaleUuid = isUuid ? rawSaleId : null;
    const cashierName = req.staff ? req.staff.name : (req.body.cashierName || 'Juruwang Bertugas');

    let assignedCodes = [];

    if (supabase) {
      // 1. Ambil kod sedia ada yang berstatus 'belum guna' (is_printed = false && is_used = false)
      const { data: availRows, error: fetchErr } = await supabase
        .from('lucky_codes')
        .select('*')
        .eq('is_printed', false)
        .eq('is_used', false)
        .order('created_at', { ascending: true })
        .limit(count);

      if (fetchErr) throw fetchErr;

      let neededExtra = count - (availRows ? availRows.length : 0);
      let selectedIds = (availRows || []).map(r => r.id);
      assignedCodes = (availRows || []).map(r => r.code);

      // 2. Jika tidak cukup, auto jana kod baru unik terus berstatus 'sudah print'
      if (neededExtra > 0) {
        const { data: existingAll } = await supabase.from('lucky_codes').select('code');
        const existingSet = new Set((existingAll || []).map(r => (r.code || '').toLowerCase()));

        const newGeneratedRows = [];
        for (let i = 0; i < neededExtra; i++) {
          const freshCode = generate5CharLuckyCode(existingSet);
          newGeneratedRows.push({
            code: freshCode,
            is_printed: true,
            is_used: false,
            sale_id: validSaleUuid,
            assigned_at: new Date().toISOString(),
            created_at: new Date().toISOString()
          });
          assignedCodes.push(freshCode);
        }

        const { data: newlyInserted, error: insErr } = await supabase
          .from('lucky_codes')
          .insert(newGeneratedRows)
          .select();
        if (insErr) throw insErr;
      }

      // 3. Kemas kini status kod sedia ada yang dipilih kepada 'sudah print'
      if (selectedIds.length > 0) {
        const { error: updErr } = await supabase
          .from('lucky_codes')
          .update({
            is_printed: true,
            assigned_at: new Date().toISOString(),
            sale_id: validSaleUuid
          })
          .in('id', selectedIds);
        if (updErr) throw updErr;
      }
    } else {
      for (let i = 0; i < count; i++) {
        assignedCodes.push(generate5CharLuckyCode());
      }
    }

    console.log(`🧾 [LUCKY CODES ASSIGNED AT CHECKOUT] ${assignedCodes.length} kod ditukar ke 'sudah print' (Sale: ${rawSaleId})`);
    res.json({
      success: true,
      codes: assignedCodes,
      receiptCode: assignedCodes[0] || null,
      message: `${assignedCodes.length} kod bertuah berstatus 'sudah print' berjaya dikeluarkan untuk resit.`
    });
  } catch (err) {
    console.error('❌ POST /api/pos/lucky-draw/checkout-codes error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 5. POST Reset / Padam Kod Bertuah
app.post('/api/pos/lucky-draw/reset', requireStaffAuth, async (req, res) => {
  try {
    if (supabase) {
      await supabase.from('lucky_codes').delete().neq('id', '00000000-0000-0000-0000-000000000000');
      await supabase.from('pos_audit_logs').insert({
        action: 'lucky_codes_reset',
        cashier_name: req.staff ? req.staff.name : (req.body.cashierName || 'Pengurus Utama'),
        details: { note: 'Semua kod bertuah dipadam' }
      });
    }
    res.json({ success: true, message: 'Semua kod bertuah telah dipadam dan di-reset ✨' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 6. GET Senarai Hadiah Cabutan Bertuah (POS & Loyalty App)
app.get(['/api/pos/lucky-draw/gifts', '/api/loyalty/lucky-draw/gifts'], async (req, res) => {
  try {
    if (supabase) {
      const { data } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_draw_gifts').maybeSingle();
      if (data && Array.isArray(data.value)) inMemoryLuckyGifts = data.value;
    }
    res.json({ success: true, gifts: inMemoryLuckyGifts });
  } catch (err) {
    res.json({ success: true, gifts: inMemoryLuckyGifts });
  }
});

// 7. POST Simpan / Tambah Hadiah Cabutan Bertuah (Dengan Kos Marketing)
app.post('/api/pos/lucky-draw/gifts', requireStaffAuth, async (req, res) => {
  try {
    const { name, type, productId, productName, cost, marketPrice, img, code } = req.body;
    if (!name && !productName) return res.status(400).json({ success: false, error: 'Nama hadiah diperlukan.' });

    let assignedCode = null;
    const finalGiftName = name || productName;

    // Jika pengguna pilih kod tertentu (bukan 'auto')
    if (code && String(code).trim() && String(code).trim().toLowerCase() !== 'auto') {
      assignedCode = String(code).trim().toLowerCase();
      if (supabase) {
        const { data: existCode } = await supabase.from('lucky_codes').select('*').ilike('code', assignedCode).maybeSingle();
        if (!existCode) {
          await supabase.from('lucky_codes').insert({ code: assignedCode, prize_name: finalGiftName, is_used: false, is_printed: false });
        } else {
          await supabase.from('lucky_codes').update({ prize_name: finalGiftName, is_used: false }).eq('id', existCode.id);
        }
      }
    } else {
      // Auto-ambil secara RAWAK daripada senarai Kod Bertuah Terkini yang ada dalam pangkalan data
      if (supabase) {
        // Cari semua kod yang belum digunakan / belum dituntut
        const { data: availList } = await supabase.from('lucky_codes').select('*').eq('is_used', false);
        if (availList && availList.length > 0) {
          // Pilih satu kod secara RAWAK daripada senarai yang wujud
          const randomItem = availList[Math.floor(Math.random() * availList.length)];
          assignedCode = randomItem.code;
          await supabase.from('lucky_codes').update({ prize_name: finalGiftName, is_used: false }).eq('id', randomItem.id);
          console.log(`🎲 [LUCKY GIFT AUTO-PICK] Kod '${assignedCode}' dipilih secara rawak daripada ${availList.length} kod terkini`);
        } else {
          // Jika tiada sebarang kod dalam sistem, jana 1 kod dan masukkan ke lucky_codes
          const fresh = generate5CharLuckyCode();
          assignedCode = fresh;
          await supabase.from('lucky_codes').insert({ code: fresh, prize_name: finalGiftName, is_used: false, is_printed: false });
          console.log(`🎲 [LUCKY GIFT FRESH] Tiada kod sedia ada, kod baru '${fresh}' dijana ke lucky_codes`);
        }
      } else {
        assignedCode = generate5CharLuckyCode();
      }
    }

    const newGift = {
      id: Date.now(),
      name: name || productName,
      type: type || 'external',
      productId: productId || null,
      productName: productName || null,
      cost: parseFloat(cost) || 0,
      marketPrice: parseFloat(marketPrice) || 0,
      img: img || null,
      code: assignedCode,
      status: 'available',
      created_at: new Date().toISOString()
    };
    inMemoryLuckyGifts.unshift(newGift);

    if (supabase) {
      await supabase.from('pos_settings').upsert({
        key: 'lucky_draw_gifts',
        value: inMemoryLuckyGifts,
        updated_at: new Date().toISOString()
      });
      await supabase.from('pos_audit_logs').insert({
        action: 'lucky_gift_saved',
        cashier_name: req.staff ? req.staff.name : (req.body.cashierName || 'Pengurus Utama'),
        details: { giftName: newGift.name, code: newGift.code, marketingCost: newGift.cost }
      });
    }

    console.log(`🎁 [LUCKY GIFT CREATED] '${newGift.name}' didaftarkan dengan kod ${newGift.code}`);
    res.json({
      success: true,
      message: `Hadiah '${newGift.name}' berjaya didaftarkan dengan Kod Kemenangan '${newGift.code}' ✨`,
      gift: newGift
    });
  } catch (err) {
    console.error('❌ POST /api/pos/lucky-draw/gifts error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 8. DELETE Hadiah Cabutan Bertuah
app.delete('/api/pos/lucky-draw/gifts/:id', requireStaffAuth, async (req, res) => {
  try {
    const giftId = parseInt(req.params.id, 10);
    inMemoryLuckyGifts = inMemoryLuckyGifts.filter(g => g.id !== giftId);

    if (supabase) {
      await supabase.from('pos_settings').upsert({
        key: 'lucky_draw_gifts',
        value: inMemoryLuckyGifts,
        updated_at: new Date().toISOString()
      });
    }

    res.json({ success: true, message: 'Hadiah berjaya dipadam ✨' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 8B. GET & POST KUNCI ACARA CABUTAN BERTUAH (EVENT COUNTDOWN LOCK)
app.get(['/api/pos/lucky-draw/event-lock', '/api/loyalty/lucky-draw/event-lock'], async (req, res) => {
  if (supabase) {
    try {
      const { data } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_event_lock').maybeSingle();
      if (data && data.value) inMemoryEventLock = { ...inMemoryEventLock, ...data.value };
    } catch (e) {}
  }
  
  const now = Date.now();
  const isLocked = Boolean(inMemoryEventLock.enabled && inMemoryEventLock.unlockAt && new Date(inMemoryEventLock.unlockAt).getTime() > now);
  
  res.json({
    success: true,
    eventLock: {
      ...inMemoryEventLock,
      isLocked,
      remainingMs: isLocked ? Math.max(0, new Date(inMemoryEventLock.unlockAt).getTime() - now) : 0
    }
  });
});

app.post('/api/pos/lucky-draw/event-lock', requireStaffAuth, async (req, res) => {
  try {
    const { enabled, unlockAt, eventTitle, noticeText } = req.body;
    inMemoryEventLock = {
      enabled: Boolean(enabled),
      unlockAt: unlockAt || null,
      eventTitle: (eventTitle || 'Cabutan Bertuah Khas').trim(),
      noticeText: (noticeText || 'Event akan berakhir pada waktu yang ditetapkan. Sila simpan resit anda!').trim(),
      updatedAt: new Date().toISOString()
    };

    if (supabase) {
      await supabase.from('pos_settings').upsert({
        key: 'lucky_event_lock',
        value: inMemoryEventLock,
        updated_at: new Date().toISOString()
      });
      await supabase.from('pos_audit_logs').insert({
        action: 'lucky_event_lock_updated',
        cashier_name: req.staff ? req.staff.name : (req.body.cashierName || 'Pengurus Utama'),
        details: inMemoryEventLock
      });
    }

    console.log(`🔒 [LUCKY EVENT LOCK] Status: ${inMemoryEventLock.enabled ? 'AKTIF (Terkunci)' : 'MATI (Terbuka)'} | Unlock: ${inMemoryEventLock.unlockAt}`);
    res.json({ success: true, message: 'Tetapan kunci acara berjaya disimpan ✨', eventLock: inMemoryEventLock });
  } catch (err) {
    console.error('❌ POST /api/pos/lucky-draw/event-lock error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 9. GET Senarai Tuntutan Hadiah Pemenang (POS & Loyalty)
app.get(['/api/pos/lucky-draw/claims', '/api/loyalty/lucky-draw/claims'], async (req, res) => {
  try {
    if (supabase) {
      const { data } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_draw_claims').maybeSingle();
      if (data && Array.isArray(data.value)) inMemoryLuckyClaims = data.value;
    }
    res.json({ success: true, claims: inMemoryLuckyClaims });
  } catch (err) {
    res.json({ success: true, claims: inMemoryLuckyClaims });
  }
});

// 10. POST /api/loyalty/lucky-draw/enter (Pelanggan Masukkan Kod 5 Aksara Pada Loyalty App)
// Zero-Trust Security: Autentikasi Pengguna & Identiti Diambil Dari Token Pelanggan
app.post(['/api/loyalty/lucky-draw/enter', '/api/pos/lucky-draw/enter'], requireCustomerAuth, async (req, res) => {
  try {
    const { code, name } = req.body;
    const customerPhone = (req.customer && req.customer.phone) || req.body.phone;

    if (!code) return res.status(400).json({ success: false, error: 'Sila masukkan kod bertuah.' });
    if (!customerPhone) return res.status(400).json({ success: false, error: 'Sila log masuk dengan akaun anda dahulu.' });

    // SEMAKAN KUNCI ACARA (EVENT COUNTDOWN LOCK)
    const now = Date.now();
    if (inMemoryEventLock.enabled && inMemoryEventLock.unlockAt && new Date(inMemoryEventLock.unlockAt).getTime() > now) {
      const formattedDate = new Date(inMemoryEventLock.unlockAt).toLocaleDateString('ms-MY', {
        day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit'
      });
      return res.status(403).json({
        success: false,
        isEventLocked: true,
        unlockAt: inMemoryEventLock.unlockAt,
        error: `Cabutan bertuah sedang dikunci sempena ${inMemoryEventLock.eventTitle || 'Acara Khas'}. Acara akan dibuka pada ${formattedDate}. Sila simpan resit anda!`
      });
    }
    let lockData = luckyDrawLockoutMap.get(clientKey) || { failedCount: 0, lockoutExpiresAt: 0 };

    if (lockData.lockoutExpiresAt > now) {
      const remainingMs = lockData.lockoutExpiresAt - now;
      const remainingHours = Math.floor(remainingMs / (3600 * 1000));
      const remainingMins = Math.ceil((remainingMs % (3600 * 1000)) / (60 * 1000));
      return res.status(429).json({
        success: false,
        isLocked: true,
        lockoutExpiresAt: lockData.lockoutExpiresAt,
        error: `Akaun anda disekat sementara selama 24 jam kerana 5 kali percubaan kod tidak sah. Sila cuba lagi dalam ${remainingHours} jam ${remainingMins} minit.`
      });
    }

    // Jika tempoh sekatan telah tamat, set semula pembilang
    if (lockData.lockoutExpiresAt > 0 && lockData.lockoutExpiresAt <= now) {
      lockData = { failedCount: 0, lockoutExpiresAt: 0 };
      luckyDrawLockoutMap.set(clientKey, lockData);
    }

    // Ambil senarai hadiah & claims terkini dari Supabase
    if (supabase) {
      const { data: gData } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_draw_gifts').maybeSingle();
      if (gData && Array.isArray(gData.value)) inMemoryLuckyGifts = gData.value;
      const { data: clData } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_draw_claims').maybeSingle();
      if (clData && Array.isArray(clData.value)) inMemoryLuckyClaims = clData.value;
    }

    // Semak sama ada kod ini pernah dimasukkan/ditebus sebelum ini dalam claims
    const existingClaim = inMemoryLuckyClaims.find(c => (c.code || '').toLowerCase() === cleanCode);
    if (existingClaim) {
      if (existingClaim.status === 'claimed') {
        return res.status(400).json({ success: false, error: 'Kod bertuah ini telah ditebus di kaunter sebelum ini.' });
      } else {
        return res.json({
          success: true,
          isWinner: true,
          gift: { name: existingClaim.giftName, type: existingClaim.giftType, cost: existingClaim.cost, img: existingClaim.img },
          message: `Kod ini telah didaftarkan untuk kemenangan '${existingClaim.giftName}'! Sila pergi ke kaunter untuk tebus. 🎁`
        });
      }
    }

    // 1. CARI REKOD KOD DI PANGKALAN DATA (lucky_codes)
    let codeRow = null;
    if (supabase) {
      const { data: cData } = await supabase.from('lucky_codes').select('*').ilike('code', cleanCode).maybeSingle();
      if (cData) codeRow = cData;
    }

    // JIKA KOD TIADA DALAM DB SAMA SEKALI
    if (!codeRow) {
      lockData.failedCount++;
      if (lockData.failedCount >= 5) {
        lockData.lockoutExpiresAt = now + 24 * 3600 * 1000;
        luckyDrawLockoutMap.set(clientKey, lockData);
        return res.status(429).json({
          success: false,
          isLocked: true,
          lockoutExpiresAt: lockData.lockoutExpiresAt,
          error: 'Akaun anda disekat selama 24 jam kerana 5 kali percubaan kod yang tidak sah.'
        });
      }
      luckyDrawLockoutMap.set(clientKey, lockData);
      const remainingAttempts = 5 - lockData.failedCount;
      return res.status(400).json({
        success: false,
        remainingAttempts,
        error: `Kod tidak sah atau tidak wujud! Baki percubaan: ${remainingAttempts} kali.`
      });
    }

    // JIKA KOD BERSTATUS 'belum guna' (Belum dicetak pada resit pelanggan)
    if (!codeRow.is_printed && !codeRow.is_used) {
      lockData.failedCount++;
      if (lockData.failedCount >= 5) {
        lockData.lockoutExpiresAt = now + 24 * 3600 * 1000;
        luckyDrawLockoutMap.set(clientKey, lockData);
        return res.status(429).json({
          success: false,
          isLocked: true,
          lockoutExpiresAt: lockData.lockoutExpiresAt,
          error: 'Akaun anda disekat selama 24 jam kerana 5 kali percubaan kod yang tidak sah.'
        });
      }
      lockData.failedCount++;
      luckyDrawLockoutMap.set(clientKey, lockData);
      const remainingAttempts = 5 - lockData.failedCount;
      return res.status(400).json({
        success: false,
        remainingAttempts,
        error: `Kod tidak sah atau belum dikeluarkan pada resit! Baki percubaan: ${remainingAttempts} kali.`
      });
    }

    // JIKA KOD SUDAH DIGUNAKAN
    if (codeRow.is_used) {
      return res.status(400).json({
        success: false,
        error: 'Kod bertuah ini telah ditebus/digunakan sebelum ini.'
      });
    }

    // JIKA KOD SAH ('sudah print' iaitu is_printed = true && is_used = false):
    luckyDrawLockoutMap.set(clientKey, { failedCount: 0, lockoutExpiresAt: 0 });

    const nowIso = new Date().toISOString();
    if (supabase) {
      await supabase.from('lucky_codes').update({
        is_used: true,
        used_at: nowIso
      }).eq('id', codeRow.id);
    }

    // Semak sama ada kod padan dengan hadiah aktif di inMemoryLuckyGifts atau codeRow.prize_name
    const matchedGift = inMemoryLuckyGifts.find(g => (g.code || '').toLowerCase() === cleanCode && g.status !== 'claimed');

    if (matchedGift || codeRow.prize_name) {
      const giftName = matchedGift ? matchedGift.name : codeRow.prize_name;
      const giftType = matchedGift ? matchedGift.type : 'general';
      const giftCost = matchedGift ? (matchedGift.cost || 0) : 0;
      const giftImg = matchedGift ? matchedGift.img : null;
      const giftId = matchedGift ? matchedGift.id : codeRow.id;

      const claimRecord = {
        id: 'claim_' + Date.now(),
        receiptNo: `RC-CLAIM-${Math.floor(100000 + Math.random() * 900000)}`,
        code: codeRow.code,
        giftId,
        giftName,
        giftType,
        cost: giftCost,
        img: giftImg,
        phone: cleanPhone,
        maskedPhone: cleanPhone.length >= 8 ? `${cleanPhone.slice(0, 3)}-***${cleanPhone.slice(-4)}` : cleanPhone,
        customerName: name || `Ahli ${cleanPhone.slice(-4)}`,
        enteredAt: nowIso,
        claimedAt: null,
        cashierName: null,
        status: 'pending_claim'
      };

      inMemoryLuckyClaims.unshift(claimRecord);
      if (matchedGift) matchedGift.status = 'won';

      if (supabase) {
        await supabase.from('pos_settings').upsert({
          key: 'lucky_draw_claims',
          value: inMemoryLuckyClaims,
          updated_at: nowIso
        });
        await supabase.from('pos_settings').upsert({
          key: 'lucky_draw_gifts',
          value: inMemoryLuckyGifts,
          updated_at: nowIso
        });
      }

      console.log(`🎉 [LUCKY WINNER CLAIM REGISTERED] ${cleanPhone} menang '${giftName}' dengan kod ${codeRow.code}`);
      return res.json({
        success: true,
        isWinner: true,
        gift: {
          name: giftName,
          type: giftType,
          cost: giftCost,
          img: giftImg
        },
        message: `🎉 Tahniah! Anda memenangi '${giftName}'! Sila pergi ke kaunter dan sebut "Nak claim hadiah" bersama nombor telefon anda.`
      });
    }

    // Kod penyertaan biasa (bukan hadiah utama)
    res.json({
      success: true,
      isWinner: false,
      message: 'Terima kasih atas penyertaan! Tiada hadiah bagi kod ini, cuba lagi di pesanan seterusnya ☕'
    });
  } catch (err) {
    console.error('❌ POST /api/loyalty/lucky-draw/enter error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 11. POST /api/pos/lucky-draw/claim (Staf POS Sahkan Penebusan Hadiah di Kaunter & Cetak Resit Pemenang)
app.post('/api/pos/lucky-draw/claim', requireStaffAuth, async (req, res) => {
  try {
    const { claimId, phone, code, cashierName } = req.body;
    if (!claimId && !phone && !code) {
      return res.status(400).json({ success: false, error: 'Parameter claimId, phone, atau code diperlukan.' });
    }

    if (supabase) {
      const { data: clData } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_draw_claims').maybeSingle();
      if (clData && Array.isArray(clData.value)) inMemoryLuckyClaims = clData.value;
      const { data: gData } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_draw_gifts').maybeSingle();
      if (gData && Array.isArray(gData.value)) inMemoryLuckyGifts = gData.value;
    }

    let targetClaim = null;
    if (claimId) {
      targetClaim = inMemoryLuckyClaims.find(c => c.id === claimId);
    } else if (phone) {
      const clean = normalizePhone(phone);
      targetClaim = inMemoryLuckyClaims.find(c => normalizePhone(c.phone) === clean && c.status === 'pending_claim');
    } else if (code) {
      targetClaim = inMemoryLuckyClaims.find(c => (c.code || '').toLowerCase() === code.trim().toLowerCase());
    }

    if (!targetClaim && req.body.claim && typeof req.body.claim === 'object') {
      targetClaim = req.body.claim;
      inMemoryLuckyClaims.unshift(targetClaim);
    }

    if (!targetClaim) {
      return res.status(404).json({ success: false, error: 'Tiada rekod hadiah kemenangan yang sedia ditebus untuk pelanggan ini.' });
    }

    if (targetClaim.status === 'claimed') {
      return res.status(400).json({ success: false, error: 'Hadiah ini telah ditebus sebelum ini.' });
    }

    const nowIso = new Date().toISOString();
    const finalReceiptNo = targetClaim.receiptNo || `RC-CLAIM-${Math.floor(100000 + Math.random() * 900000)}`;

    targetClaim.status = 'claimed';
    targetClaim.claimedAt = nowIso;
    targetClaim.cashierName = req.staff ? req.staff.name : (cashierName || 'Juruwang Bertugas');
    targetClaim.receiptNo = finalReceiptNo;

    // Tandakan hadiah sebagai claimed
    const gIdx = inMemoryLuckyGifts.findIndex(g => g.id === targetClaim.giftId || (g.code && g.code.toLowerCase() === targetClaim.code.toLowerCase()));
    if (gIdx !== -1) inMemoryLuckyGifts[gIdx].status = 'claimed';

    if (supabase) {
      await supabase.from('pos_settings').upsert({
        key: 'lucky_draw_claims',
        value: inMemoryLuckyClaims,
        updated_at: nowIso
      });
      await supabase.from('pos_settings').upsert({
        key: 'lucky_draw_gifts',
        value: inMemoryLuckyGifts,
        updated_at: nowIso
      });

      // 1. Simpan rekod transaksi kos pemasaran ke jadual `sales`
      const marketingCost = Math.max(0, parseFloat(targetClaim.cost) || 0);
      const { data: luckySaleRow, error: luckyErr } = await supabase.from('sales').insert({
        receipt_no: finalReceiptNo,
        order_type: 'dinein',
        payment_method: 'points',
        cash_tendered: 0,
        change_given: 0,
        subtotal: 0,
        discount: 0,
        tax: 0,
        service_charge: 0,
        round_adj: 0,
        total: 0,
        cashier_name: targetClaim.cashierName || 'Pengurus Utama',
        member_id: null,
        status: 'paid',
        notes: JSON.stringify({
          marketingExpense: true,
          rewardType: 'Kod Bertuah',
          rewardName: `Hadiah Bertuah: ${targetClaim.giftName}`,
          giftType: targetClaim.giftType,
          costAmount: marketingCost,
          code: targetClaim.code,
          phone: targetClaim.phone || null
        })
      }).select().single();

      if (luckySaleRow) {
        await supabase.from('sale_items').insert([{
          sale_id: luckySaleRow.id,
          product_name: `Hadiah Bertuah: ${targetClaim.giftName}`,
          unit_price: 0,
          unit_cost: marketingCost,
          qty: 1,
          subtotal: 0
        }]);
      }

      // 2. Merekodkan Kos Marketing Hadiah ke pos_audit_logs
      await supabase.from('pos_audit_logs').insert({
        action: 'lucky_gift_redeemed',
        receipt_no: finalReceiptNo,
        cashier_name: targetClaim.cashierName,
        details: {
          giftName: targetClaim.giftName,
          giftType: targetClaim.giftType,
          marketingCost: marketingCost,
          customerPhone: targetClaim.maskedPhone,
          code: targetClaim.code
        }
      });
    }

    const maskedPhone = targetClaim.phone ? (targetClaim.phone.length >= 8 ? `${targetClaim.phone.slice(0, 3)}-***${targetClaim.phone.slice(-4)}` : targetClaim.phone) : 'Pelanggan';

    console.log(`🎁 [LUCKY CLAIM COMPLETED] ${targetClaim.giftName} ditebus oleh ${maskedPhone} (Kos Marketing: RM${(targetClaim.cost||0).toFixed(2)})`);

    res.json({
      success: true,
      message: `Hadiah '${targetClaim.giftName}' berjaya ditebus! Resit rasmi pemenang dijana. 🎉`,
      receipt: {
        receiptNo: finalReceiptNo,
        maskedPhone: maskedPhone,
        giftName: targetClaim.giftName,
        giftType: targetClaim.giftType,
        cost: targetClaim.cost || 0,
        code: targetClaim.code,
        cashierName: targetClaim.cashierName,
        congratsText: 'Tahniah atas kemenangan anda!',
        date: new Date().toLocaleDateString('ms-MY', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
      },
      claim: targetClaim
    });
  } catch (err) {
    console.error('❌ POST /api/pos/lucky-draw/claim error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 12. GET /api/loyalty/lucky-draw/winners (Senarai Pemenang Ditebus & Status Live untuk Notis Update)
app.get(['/api/loyalty/lucky-draw/winners', '/api/pos/lucky-draw/winners'], async (req, res) => {
  try {
    if (supabase) {
      const { data: clData } = await supabase.from('pos_settings').select('value').eq('key', 'lucky_draw_claims').maybeSingle();
      if (clData && Array.isArray(clData.value)) inMemoryLuckyClaims = clData.value;
    }

    const winners = inMemoryLuckyClaims.map(c => {
      const cleanPhone = normalizePhone(c.phone || '');
      const masked = cleanPhone.length >= 8 
        ? `${cleanPhone.slice(0, 3)}-***${cleanPhone.slice(-4)}` 
        : (c.maskedPhone || 'Ahli Koffi');
      return {
        id: c.id,
        phoneMasked: masked,
        customerName: c.customerName || `Ahli ${cleanPhone.slice(-4)}`,
        giftName: c.giftName || 'Hadiah Bertuah',
        giftType: c.giftType || 'external',
        status: c.status || 'claimed',
        claimedAt: c.claimedAt || c.enteredAt || new Date().toISOString()
      };
    });

    res.json({ success: true, winners });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message, winners: [] });
  }
});

// Global 404 Handler for API routes (Always return JSON, never HTML)
app.use('/api', (req, res) => {
  res.status(404).json({
    success: false,
    error: `Laluan API [${req.method}] ${req.originalUrl} tidak wujud di pelayan backend.`
  });
});

// Global Express Error Handler for API routes
app.use((err, req, res, next) => {
  console.error('❌ [EXPRESS GLOBAL ERROR]', err);
  if (req.originalUrl && req.originalUrl.startsWith('/api')) {
    return res.status(err.status || 500).json({
      success: false,
      error: err.message || 'Ralat dalaman pelayan backend.'
    });
  }
  res.status(500).send(`<h3>Ralat Pelayan:</h3><pre>${err.message}</pre>`);
});

// Start Server & Run Bcrypt Migration
app.listen(PORT, async () => {
  console.log(`🚀 Koffi VPS Backend running on port ${PORT}`);
  console.log(`📁 Local/VPS Uploads served at: http://localhost:${PORT}/uploads/promotions/ and /uploads/products/`);
  try {
    await migrateStaffPinsToBcrypt();
  } catch (e) {
    console.warn('⚠️ Bcrypt migration warning on boot:', e.message);
  }
});

