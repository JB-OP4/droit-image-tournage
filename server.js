const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PIN = String(process.env.ADMIN_PIN || '1234').trim();
const TOKEN_SECRET = process.env.SESSION_SECRET || crypto.createHash('sha256').update('droit-image-' + ADMIN_PIN).digest('hex');

// Détection automatique d'un Volume Railway monté sur /data
const HAS_RAILWAY_VOLUME = fs.existsSync('/data');
const DATA_DIR = process.env.DATA_DIR || (HAS_RAILWAY_VOLUME ? '/data' : path.join(__dirname, 'data'));
const SIGNATURES_DIR = path.join(DATA_DIR, 'signatures');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');

fs.mkdirSync(SIGNATURES_DIR, { recursive: true });

const DEFAULT_SETTINGS = {
  projectName: 'GeoGuessr IRL',
  producer: 'Production Audiovisuelle',
  rgpdEmail: 'contact@exemple.fr',
  location: 'Montpellier, France',
  channels: 'YouTube, réseaux sociaux (Instagram, TikTok, Shorts), site web et supports de promotion du projet',
  duration: '5 ans',
  territory: 'Monde entier'
};

function readSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      const raw = fs.readFileSync(SETTINGS_FILE, 'utf8');
      return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
    }
  } catch (err) {
    console.error('Erreur lecture settings.json:', err.message);
  }
  return { ...DEFAULT_SETTINGS };
}

function writeSettings(data) {
  const clean = {
    projectName: String(data.projectName || DEFAULT_SETTINGS.projectName).slice(0, 120),
    producer: String(data.producer || DEFAULT_SETTINGS.producer).slice(0, 160),
    rgpdEmail: String(data.rgpdEmail || DEFAULT_SETTINGS.rgpdEmail).slice(0, 160),
    location: String(data.location || DEFAULT_SETTINGS.location).slice(0, 160),
    channels: String(data.channels || DEFAULT_SETTINGS.channels).slice(0, 400),
    duration: String(data.duration || DEFAULT_SETTINGS.duration).slice(0, 80),
    territory: String(data.territory || DEFAULT_SETTINGS.territory).slice(0, 120)
  };
  const tmpFile = SETTINGS_FILE + '.tmp';
  fs.writeFileSync(tmpFile, JSON.stringify(clean, null, 2), 'utf8');
  fs.renameSync(tmpFile, SETTINGS_FILE);
  return clean;
}

function generateToken() {
  const exp = Date.now() + 24 * 60 * 60 * 1000; // 24h
  const payload = String(exp);
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return false;
  const [payload, sig] = token.split('.');
  const exp = Number(payload);
  if (!Number.isFinite(exp) || Date.now() > exp) return false;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!verifyToken(token)) {
    return res.status(401).json({ error: 'Accès non autorisé. Veuillez saisir le code PIN.' });
  }
  next();
}

app.set('trust proxy', 1);
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// État du serveur (public)
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    persistentVolume: HAS_RAILWAY_VOLUME || Boolean(process.env.DATA_DIR),
    usingDefaultPin: ADMIN_PIN === '1234'
  });
});

// Authentification Production par PIN
app.post('/api/auth', (req, res) => {
  const pin = String((req.body && req.body.pin) || '').trim();
  const a = Buffer.from(pin);
  const b = Buffer.from(ADMIN_PIN);
  if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
    return res.json({ ok: true, token: generateToken() });
  }
  return res.status(401).json({ error: 'Code PIN incorrect.' });
});

// Lecture des paramètres du tournage (public, nécessaire au formulaire passant)
app.get('/api/settings', (req, res) => {
  res.json(readSettings());
});

// Mise à jour des paramètres du tournage (admin)
app.put('/api/settings', requireAdmin, (req, res) => {
  try {
    const updated = writeSettings(req.body || {});
    res.json(updated);
  } catch (err) {
    console.error('Erreur sauvegarde settings:', err);
    res.status(500).json({ error: 'Impossible de sauvegarder les réglages.' });
  }
});

// Enregistrement d'une autorisation signée (public, envoyé par le passant)
app.post('/api/signatures', (req, res) => {
  try {
    const body = req.body || {};
    const fullName = String(body.fullName || '').trim();
    const signatureDataUrl = String(body.signatureDataUrl || '');
    const isMinor = Boolean(body.isMinor);
    const guardianName = String(body.guardianName || '').trim();
    const guardianRelation = String(body.guardianRelation || '').trim();

    if (!fullName || fullName.length < 2) {
      return res.status(400).json({ error: 'Le nom complet est obligatoire.' });
    }
    if (isMinor && !guardianName) {
      return res.status(400).json({ error: 'Le nom du représentant légal est obligatoire pour un mineur.' });
    }
    if (!signatureDataUrl.startsWith('data:image/png;base64,')) {
      return res.status(400).json({ error: 'La signature manuscrite est obligatoire.' });
    }
    if (!body.accepted) {
      return res.status(400).json({ error: 'Vous devez accepter les conditions.' });
    }

    let photoDataUrl = '';
    if (typeof body.photoDataUrl === 'string' && body.photoDataUrl.startsWith('data:image/')) {
      photoDataUrl = body.photoDataUrl;
    }

    const id = crypto.randomUUID();
    const settingsSnapshot = readSettings();
    const ipHeader = req.headers['x-forwarded-for'];
    const clientIp = Array.isArray(ipHeader)
      ? ipHeader[0]
      : String(ipHeader || req.socket.remoteAddress || '').split(',')[0].trim();

    const record = {
      id,
      signedAt: new Date().toISOString(),
      fullName: fullName.slice(0, 140),
      email: String(body.email || '').trim().slice(0, 160),
      phone: String(body.phone || '').trim().slice(0, 40),
      isMinor,
      guardianName: isMinor ? guardianName.slice(0, 140) : '',
      guardianRelation: isMinor ? guardianRelation.slice(0, 60) : '',
      photoDataUrl,
      signatureDataUrl,
      settingsSnapshot,
      audit: {
        ip: clientIp,
        userAgent: String(req.headers['user-agent'] || '').slice(0, 200)
      }
    };

    const targetPath = path.join(SIGNATURES_DIR, `${id}.json`);
    const tmpPath = targetPath + '.tmp';
    fs.writeFileSync(tmpPath, JSON.stringify(record), 'utf8');
    fs.renameSync(tmpPath, targetPath);

    res.status(201).json({ ok: true, record });
  } catch (err) {
    console.error('Erreur enregistrement signature:', err);
    res.status(500).json({ error: 'Erreur serveur lors de l’enregistrement.' });
  }
});

// Liste de toutes les autorisations (admin)
app.get('/api/signatures', requireAdmin, (req, res) => {
  try {
    const files = fs.readdirSync(SIGNATURES_DIR).filter(f => f.endsWith('.json'));
    const list = [];
    for (const file of files) {
      try {
        const raw = fs.readFileSync(path.join(SIGNATURES_DIR, file), 'utf8');
        list.push(JSON.parse(raw));
      } catch (e) {
        console.error('Fichier illisible:', file, e.message);
      }
    }
    list.sort((a, b) => new Date(b.signedAt) - new Date(a.signedAt));
    res.json(list);
  } catch (err) {
    console.error('Erreur lecture signatures:', err);
    res.status(500).json({ error: 'Impossible de lire les signatures.' });
  }
});

// Suppression d'une autorisation (admin)
app.delete('/api/signatures/:id', requireAdmin, (req, res) => {
  const id = String(req.params.id || '');
  if (!/^[0-9a-fA-F-]{36}$/.test(id)) {
    return res.status(400).json({ error: 'Identifiant invalide.' });
  }
  const targetPath = path.join(SIGNATURES_DIR, `${id}.json`);
  if (!fs.existsSync(targetPath)) {
    return res.status(404).json({ error: 'Autorisation introuvable.' });
  }
  fs.unlinkSync(targetPath);
  res.json({ ok: true });
});

// Fallback SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Serveur Droit à l'Image lancé sur le port ${PORT}`);
  console.log(`Dossier de stockage : ${DATA_DIR} (Volume persistant : ${HAS_RAILWAY_VOLUME || Boolean(process.env.DATA_DIR)})`);
});
