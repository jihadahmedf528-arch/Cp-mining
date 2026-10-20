
const express = require("express");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_KEY = process.env.ADMIN_KEY;
const DATABASE_URL = process.env.FIREBASE_DATABASE_URL;
const SERVICE_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

let db = null;

try {
  if (DATABASE_URL && SERVICE_JSON) {
    const serviceAccount = JSON.parse(SERVICE_JSON);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: DATABASE_URL
    });
    db = admin.database();
  }
} catch (err) {
  console.error("Firebase setup error:", err.message);
}

app.use(express.static("public"));

const defaults = {
  appName: "CP Mining",
  dailyMiningCP: 100,
  referralCP: 10,
  adRewardCP: 1,
  adsPerDay: 20,
  miningEnabled: true,
  adsEnabled: true,
  referralsEnabled: true,
  notice: {
    title: "Welcome to CP Mining",
    message: "Start mining CP today!",
    expiresAt: 0
  }
};

function requireDb(req, res, next) {
  if (!db) {
    return res.status(503).json({
      error: "Firebase is not configured on Render"
    });
  }
  next();
}

async function getSettings() {
  const snap = await db.ref("settings").once("value");
  return { ...defaults, ...(snap.val() || {}) };
}

function requireAdmin(req, res, next) {
  if (!ADMIN_KEY || req.get("x-admin-key") !== ADMIN_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

function verifyTelegram(req, res, next) {
  try {
    if (!BOT_TOKEN) {
      return res.status(503).json({ error: "Bot token not configured" });
    }

    const initData = req.get("x-telegram-init-data");
    if (!initData) {
      return res.status(401).json({ error: "Telegram data required" });
    }

    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    const authDate = Number(params.get("auth_date"));

    if (!hash || !authDate ||
        Math.abs(Date.now() / 1000 - authDate) > 86400) {
      return res.status(401).json({ error: "Invalid or expired session" });
    }

    params.delete("hash");
    params.delete("signature");

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(BOT_TOKEN)
      .digest();

    const calculatedHash = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest();

    const suppliedHash = Buffer.from(hash, "hex");

    if (suppliedHash.length !== calculatedHash.length ||
        !crypto.timingSafeEqual(suppliedHash, calculatedHash)) {
      return res.status(401).json({ error: "Telegram verification failed" });
    }

    const user = JSON.parse(params.get("user") || "null");
    if (!user || !user.id) {
      return res.status(401).json({ error: "Telegram user missing" });
    }

    req.tgUser = user;
    req.startParam = params.get("start_param") || "";
    next();
  } catch {
    res.status(401).json({ error: "Invalid Telegram session" });
  }
}

async function syncMining(uid, settings) {
  const ref = db.ref(`users/${uid}`);
  const snap = await ref.once("value");
  const user = snap.val();
  if (!user || !user.mining || !user.mining.active) return user;

  const now = Date.now();
  const mining = user.mining;
  const endAt = Math.min(now, mining.startedAt + 86400000);
  const lastAt = Math.min(mining.lastAccruedAt || mining.startedAt, endAt);
  const elapsed = Math.max(0, endAt - lastAt);

  if (elapsed > 0) {
    const earned = settings.dailyMiningCP * elapsed / 86400000;
    user.balance = Number(user.balance || 0) + earned;
    mining.lastAccruedAt = endAt;
  }

  if (now >= mining.startedAt + 86400000) {
    mining.active = false;
    mining.completedAt = mining.startedAt + 86400000;
  }

  user.mining = mining;
  await ref.update({
    balance: user.balance,
    mining: mining
  });

  return user;
}

app.get("/api/bootstrap", requireDb, async (req, res) => {
  const s = await getSettings();
  res.json({
    appName: s.appName,
    dailyMiningCP: s.dailyMiningCP,
    referralCP: s.referralCP,
    adRewardCP: s.adRewardCP,
    adsPerDay: s.adsPerDay,
    miningEnabled: s.miningEnabled,
    adsEnabled: s.adsEnabled,
    referralsEnabled: s.referralsEnabled,
    notice: s.notice
  });
});

app.get("/api/me", requireDb, verifyTelegram, async (req, res) => {
  const uid = String(req.tgUser.id);
  const settings = await getSettings();
  let userRef = db.ref(`users/${uid}`);
  let snap = await userRef.once("value");
  let user = snap.val();

  if (!user) {
    user = {
      id: uid,
      firstName: req.tgUser.first_name || "",
      username: req.tgUser.username || "",
      balance: 0,
      referralCount: 0,
      createdAt: Date.now(),
      mining: { active: false }
    };

    const match = req.startParam.match(/^ref_(\d+)$/);
    if (settings.referralsEnabled && match && match[1] !== uid) {
      const referrerId = match[1];
      const referrerRef = db.ref(`users/${referrerId}`);
      const referrerSnap = await referrerRef.once("value");
      const referrer = referrerSnap.val();

      if (referrer) {
        const already = await db.ref(`referrals/${uid}`).once("value");
        if (!already.exists()) {
          user.referredBy = referrerId;
          referrer.balance = Number(referrer.balance || 0) +
            Number(settings.referralCP || 0);
          referrer.referralCount = Number(referrer.referralCount || 0) + 1;
          await referrerRef.update({
            balance: referrer.balance,
            referralCount: referrer.referralCount
          });
          await db.ref(`referrals/${uid}`).set({
            referrerId,
            createdAt: Date.now()
          });
        }
      }
    }

    await userRef.set(user);
  } else {
    await userRef.update({
      firstName: req.tgUser.first_name || user.firstName || "",
      username: req.tgUser.username || user.username || ""
    });
  }

  user = await syncMining(uid, settings) || user;

  res.json({
    id: uid,
    firstName: user.firstName,
    balance: Number(user.balance || 0),
    referralCount: Number(user.referralCount || 0),
    referralLink: `https://t.me/${process.env.BOT_USERNAME || "YOUR_BOT_USERNAME"}?startapp=ref_${uid}`,
    mining: user.mining || { active: false },
    settings: {
      dailyMiningCP: settings.dailyMiningCP,
      miningEnabled: settings.miningEnabled
    }
  });
});

app.post("/api/mining/start", requireDb, verifyTelegram, async (req, res) => {
  const uid = String(req.tgUser.id);
  const settings = await getSettings();

  if (!settings.miningEnabled) {
    return res.status(403).json({ error: "Mining is disabled" });
  }

  const ref = db.ref(`users/${uid}`);
  const snap = await ref.once("value");
  const user = snap.val();

  if (!user) return res.status(404).json({ error: "Open the app again" });

  const synced = await syncMining(uid, settings);
  if (synced && synced.mining && synced.mining.active) {
    return res.status(409).json({ error: "Mining is already active" });
  }

  const now = Date.now();
  const mining = {
    active: true,
    startedAt: now,
    lastAccruedAt: now
  };

  await ref.child("mining").set(mining);
  res.json({ success: true, mining });
});

// Ad rewards stay disabled until real Monetag
// rewarded-ad verification is integrated.
app.post("/api/ads/reward", requireDb, verifyTelegram, (req, res) => {
  res.status(501).json({
    error: "Monetag reward verification is not configured yet"
  });
});

app.get("/api/admin/settings", requireDb, requireAdmin, async (req, res) => {
  res.json(await getSettings());
});

app.post("/api/admin/settings", requireDb, requireAdmin, async (req, res) => {
  const allowed = [
    "appName", "dailyMiningCP", "referralCP", "adRewardCP",
    "adsPerDay", "miningEnabled", "adsEnabled", "referralsEnabled", "notice"
  ];
  const current = await getSettings();
  const next = { ...current };

  for (const key of allowed) {
    if (req.body[key] !== undefined) next[key] = req.body[key];
  }

  for (const key of ["dailyMiningCP", "referralCP", "adRewardCP", "adsPerDay"]) {
    if (!Number.isFinite(Number(next[key])) || Number(next[key]) < 0) {
      return res.status(400).json({ error: `Invalid ${key}` });
    }
    next[key] = Number(next[key]);
  }

  await db.ref("settings").set(next);
  res.json({ success: true });
});

app.get("/api/admin/stats", requireDb, requireAdmin, async (req, res) => {
  const users = await db.ref("users").once("value");
  const all = Object.values(users.val() || {});
  res.json({
    totalUsers: all.length,
    totalCP: all.reduce((sum, u) => sum + Number(u.balance || 0), 0)
  });
});

app.post("/api/admin/broadcast", requireDb, requireAdmin, async (req, res) => {
  if (!BOT_TOKEN) return res.status(503).json({ error: "Bot token missing" });

  const message = String(req.body.message || "").trim();
  if (!message) return res.status(400).json({ error: "Message required" });

  const snap = await db.ref("users").once("value");
  const users = Object.keys(snap.val() || {});
  let sent = 0;
  let failed = 0;

  for (const uid of users) {
    try {
      const response = await fetch(
        `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: uid, text: message })
        }
      );
      if (response.ok) sent++;
      else failed++;
    } catch {
      failed++;
    }
  }

  res.json({ success: true, sent, failed });
});

app.get("/api/admin/users", requireDb, requireAdmin, async (req, res) => {
  const snap = await db.ref("users").once("value");
  res.json(snap.val() || {});
});

app.get("/api/notices", requireDb, async (req, res) => {
  const settings = await getSettings();
  const n = settings.notice || {};
  if (n.expiresAt && Date.now() > n.expiresAt) {
    return res.json({ notice: null });
  }
  res.json({ notice: n });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", firebase: Boolean(db) });
});

app.listen(PORT, () => {
  console.log(`CP Mining server listening on ${PORT}`);
});
            
