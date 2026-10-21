const express = require("express");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_KEY = process.env.ADMIN_KEY;
const MONETAG_POSTBACK_SECRET = process.env.MONETAG_POSTBACK_SECRET || "";
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
  monetagZoneId1: "",
  monetagZoneId2: "",
  miningEnabled: true,
  adsEnabled: true,
  referralsEnabled: true,
  withdrawalEnabled: true,
  minWithdrawalCP: 50000,
  cpPerUSD: 100000,
  notice: {
    title: "Welcome to CP Mining",
    message: "Start mining CP today!",
    expiresAt: 0
  }
};

function requireDb(req, res, next) {
  if (!db) return res.status(503).json({ error: "Firebase is not configured on Render" });
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
      return res.status(503).json({
        error: "Bot token not configured"
      });
    }

    const initData = req.get("x-telegram-init-data");

    if (!initData) {
      return res.status(401).json({
        error: "Telegram data required"
      });
    }

    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    const authDate = Number(params.get("auth_date"));

    if (
      !hash ||
      !/^[a-f0-9]{64}$/i.test(hash) ||
      !Number.isFinite(authDate) ||
      authDate <= 0 ||
      Math.abs(Date.now() / 1000 - authDate) > 86400
    ) {
      return res.status(401).json({
        error: "Invalid or expired session"
      });
    }

    params.delete("hash");
    params.delete("signature");

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
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

    if (
      suppliedHash.length !== calculatedHash.length ||
      !crypto.timingSafeEqual(suppliedHash, calculatedHash)
    ) {
      console.warn("Telegram verification failed: hash mismatch");
      return res.status(401).json({
        error: "Telegram verification failed"
      });
    }

    const user = JSON.parse(params.get("user") || "null");

    if (!user || !user.id) {
      return res.status(401).json({
        error: "Telegram user missing"
      });
    }

    req.tgUser = user;
    req.startParam = params.get("start_param") || "";

    next();
  } catch (err) {
    console.error("Telegram verification error:", err.message);
    return res.status(401).json({
      error: "Invalid Telegram session"
    });
  }
}

async function syncMining(uid, settings) {
  const ref = db.ref(`users/${uid}`);
  const snap = await ref.once("value");
  const user = snap.val();
  if (!user || !user.mining || !user.mining.active) return user;
  const now = Date.now();
  const mining = user.mining;
  const endAt = Math.min(now, Number(mining.startedAt) + 86400000);
  const lastAt = Math.min(Number(mining.lastAccruedAt || mining.startedAt), endAt);
  const elapsed = Math.max(0, endAt - lastAt);
  if (elapsed > 0) {
    user.balance = Number(user.balance || 0) + Number(settings.dailyMiningCP) * elapsed / 86400000;
    mining.lastAccruedAt = endAt;
  }
  if (now >= Number(mining.startedAt) + 86400000) {
    mining.active = false;
    mining.completedAt = Number(mining.startedAt) + 86400000;
  }
  user.mining = mining;
  await ref.update({ balance: user.balance, mining });
  return user;
}

app.get("/api/bootstrap", requireDb, async (req, res) => {
  try {
    const s = await getSettings();
    res.json({
      appName: s.appName, dailyMiningCP: s.dailyMiningCP, referralCP: s.referralCP,
      adRewardCP: s.adRewardCP, adsPerDay: s.adsPerDay,
      monetagZoneId1: String(s.monetagZoneId1 || ""), monetagZoneId2: String(s.monetagZoneId2 || ""),
      miningEnabled: s.miningEnabled,
      adsEnabled: s.adsEnabled, referralsEnabled: s.referralsEnabled,
      withdrawalEnabled: s.withdrawalEnabled !== false,
      minWithdrawalCP: Number(s.minWithdrawalCP ?? defaults.minWithdrawalCP),
      cpPerUSD: Number(s.cpPerUSD ?? defaults.cpPerUSD), notice: s.notice
    });
  } catch (e) { res.status(500).json({ error: "Could not load settings" }); }
});

app.get("/api/me", requireDb, verifyTelegram, async (req, res) => {
  try {
    const uid = String(req.tgUser.id);
    const settings = await getSettings();
    const userRef = db.ref(`users/${uid}`);
    let snap = await userRef.once("value");
    let user = snap.val();
    if (!user) {
      user = {
        id: uid, firstName: req.tgUser.first_name || "", username: req.tgUser.username || "",
        balance: 0, referralCount: 0, createdAt: Date.now(), mining: { active: false }
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
            referrer.balance = Number(referrer.balance || 0) + Number(settings.referralCP || 0);
            referrer.referralCount = Number(referrer.referralCount || 0) + 1;
            await referrerRef.update({ balance: referrer.balance, referralCount: referrer.referralCount });
            await db.ref(`referrals/${uid}`).set({ referrerId, createdAt: Date.now() });
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
      id: uid, firstName: user.firstName, balance: Number(user.balance || 0),
      referralCount: Number(user.referralCount || 0),
      referralLink: `https://t.me/${process.env.BOT_USERNAME || "YOUR_BOT_USERNAME"}?startapp=ref_${uid}`,
      mining: user.mining || { active: false },
      settings: { dailyMiningCP: settings.dailyMiningCP, miningEnabled: settings.miningEnabled }
    });
  } catch (e) { console.error("me error:", e.message); res.status(500).json({ error: "Could not load account" }); }
});

app.post("/api/mining/start", requireDb, verifyTelegram, async (req, res) => {
  try {
    const uid = String(req.tgUser.id);
    const settings = await getSettings();
    if (!settings.miningEnabled) return res.status(403).json({ error: "Mining is disabled" });
    const ref = db.ref(`users/${uid}`);
    const snap = await ref.once("value");
    if (!snap.exists()) return res.status(404).json({ error: "Open the app again" });
    const synced = await syncMining(uid, settings);
    if (synced && synced.mining && synced.mining.active) {
      return res.status(409).json({ error: "Mining is already active" });
    }
    const now = Date.now();
    const mining = { active: true, startedAt: now, lastAccruedAt: now };
    await ref.child("mining").set(mining);
    res.json({ success: true, mining });
  } catch (e) { res.status(500).json({ error: "Could not start mining" }); }
});

// Monetag rewarded ads: client callbacks never credit CP. Only a valid server postback can do that.
function utcDay(ts = Date.now()) { return new Date(ts).toISOString().slice(0, 10); }
function cleanZone(value) { return String(value || "").trim().replace(/[^0-9]/g, "").slice(0, 30); }

app.get("/api/ads/state", requireDb, verifyTelegram, async (req, res) => {
  try {
    const uid = String(req.tgUser.id), settings = await getSettings();
    const userSnap = await db.ref(`users/${uid}`).once("value");
    if (!userSnap.exists()) return res.status(404).json({ error: "Open the main app first" });
    const user = userSnap.val() || {}, day = utcDay();
    const completed = Number((user.adDailyUsage || {})[day] || 0);
    const zones = [cleanZone(settings.monetagZoneId1), cleanZone(settings.monetagZoneId2)].filter(Boolean);
    res.json({ enabled: settings.adsEnabled !== false, configured: zones.length > 0 && Boolean(MONETAG_POSTBACK_SECRET),
      zones, rewardCP: Number(settings.adRewardCP || 0), dailyLimit: Number(settings.adsPerDay || 0),
      completed, remaining: Math.max(0, Number(settings.adsPerDay || 0) - completed),
      balance: Number(user.balance || 0), pending: Boolean(user.pendingAdSession) });
  } catch (e) { res.status(500).json({ error: "Could not load ad status" }); }
});

app.post("/api/ads/start", requireDb, verifyTelegram, async (req, res) => {
  try {
    const uid = String(req.tgUser.id), settings = await getSettings();
    if (settings.adsEnabled === false) return res.status(403).json({ error: "Ads are disabled" });
    if (!MONETAG_POSTBACK_SECRET) return res.status(503).json({ error: "Admin must configure MONETAG_POSTBACK_SECRET in Render" });
    const zones = [cleanZone(settings.monetagZoneId1), cleanZone(settings.monetagZoneId2)].filter(Boolean);
    if (!zones.length) return res.status(503).json({ error: "Admin has not configured a Monetag Zone ID" });
    const day = utcDay(), now = Date.now(), ymid = `cp_${crypto.randomUUID().replace(/-/g, "")}`;
    const userBefore = (await db.ref(`users/${uid}`).once("value")).val();
    if (userBefore && userBefore.pendingAdSession) {
      const pendingRef = db.ref(`adSessions/${String(userBefore.pendingAdSession)}`);
      const pending = (await pendingRef.once("value")).val();
      if (pending && pending.status === "pending" && now - Number(pending.createdAt || now) < 10 * 60 * 1000) {
        return res.status(409).json({ error: "An ad is already pending. Finish it or wait up to 10 minutes before retrying" });
      }
      if (pending && pending.status === "pending") await pendingRef.update({ status: "expired", finishedAt: now });
      await db.ref(`users/${uid}`).transaction(user => { if (user && user.pendingAdSession === userBefore.pendingAdSession) { delete user.pendingAdSession; return user; } return; });
    }
    const sessionRef = db.ref(`adSessions/${ymid}`);
    await sessionRef.set({ ymid, uid, day, zoneId: zones[(Number((await db.ref(`users/${uid}/adDailyUsage/${day}`).once("value")).val() || 0)) % zones.length], status: "pending", createdAt: now });
    let problem = "";
    const userRef = db.ref(`users/${uid}`);
    const result = await userRef.transaction(user => {
      if (!user) { problem = "Open the main app first"; return; }
      const completed = Number((user.adDailyUsage || {})[day] || 0);
      if (completed >= Number(settings.adsPerDay || 0)) { problem = "You have completed all ads for today"; return; }
      if (user.pendingAdSession) { problem = "An ad is already pending. Finish it or wait up to 10 minutes before retrying"; return; }
      user.pendingAdSession = ymid;
      return user;
    }, undefined, false);
    if (!result.committed) {
      await sessionRef.update({ status: "cancelled", finishedAt: Date.now() });
      return res.status(409).json({ error: problem || "Could not start ad session" });
    }
    const session = (await sessionRef.once("value")).val();
    res.json({ success: true, ymid, zoneId: session.zoneId, rewardCP: Number(settings.adRewardCP || 0), dailyLimit: Number(settings.adsPerDay || 0), completed: Number(((result.snapshot.val().adDailyUsage || {})[day]) || 0) });
  } catch (e) { console.error("ad start error:", e.message); res.status(500).json({ error: "Could not start ad" }); }
});

app.get("/api/ads/status", requireDb, verifyTelegram, async (req, res) => {
  try {
    const uid = String(req.tgUser.id), ymid = String(req.query.ymid || "");
    if (!/^cp_[a-f0-9]{32}$/.test(ymid)) return res.status(400).json({ error: "Invalid ad session" });
    const session = (await db.ref(`adSessions/${ymid}`).once("value")).val();
    if (!session || session.uid !== uid) return res.status(404).json({ error: "Ad session not found" });
    const user = (await db.ref(`users/${uid}`).once("value")).val() || {}, settings = await getSettings();
    const completed = Number(((user.adDailyUsage || {})[utcDay()]) || 0);
    res.json({ status: session.status, balance: Number(user.balance || 0), completed, remaining: Math.max(0, Number(settings.adsPerDay || 0) - completed), rewardCP: Number(settings.adRewardCP || 0) });
  } catch (e) { res.status(500).json({ error: "Could not check ad status" }); }
});

app.post("/api/ads/cancel", requireDb, verifyTelegram, async (req, res) => {
  try {
    const uid = String(req.tgUser.id), ymid = String(req.body.ymid || "");
    if (!/^cp_[a-f0-9]{32}$/.test(ymid)) return res.status(400).json({ error: "Invalid ad session" });
    const sessionRef = db.ref(`adSessions/${ymid}`), session = (await sessionRef.once("value")).val();
    if (!session || session.uid !== uid) return res.status(404).json({ error: "Ad session not found" });
    if (session.status === "pending") {
      await sessionRef.transaction(s => { if (s && s.status === "pending") { s.status = "not_valued"; s.finishedAt = Date.now(); return s; } return; });
      await db.ref(`users/${uid}`).transaction(user => { if (user && user.pendingAdSession === ymid) { delete user.pendingAdSession; return user; } return; });
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: "Could not close ad session" }); }
});

// Monetag calls this endpoint directly. Set MONETAG_POSTBACK_SECRET in Render and the matching
// secret in Monetag's postback URL. Duplicate ymid values can never grant CP twice.
app.get("/postback", requireDb, async (req, res) => {
  try {
    if (!MONETAG_POSTBACK_SECRET || !req.query.secret || req.query.secret !== MONETAG_POSTBACK_SECRET) return res.sendStatus(403);
    const ymid = String(req.query.ymid || ""), eventType = String(req.query.event_type || ""), rewardType = String(req.query.reward_event_type || ""), zoneId = cleanZone(req.query.zone_id), telegramId = String(req.query.telegram_id || "");
    if (!/^cp_[a-f0-9]{32}$/.test(ymid)) return res.sendStatus(200);
    const sessionRef = db.ref(`adSessions/${ymid}`), snap = await sessionRef.once("value"), session = snap.val();
    if (!session || session.status !== "pending") return res.sendStatus(200);
    if (eventType !== "impression" || rewardType !== "valued" || zoneId !== cleanZone(session.zoneId)) return res.sendStatus(200);
    if (telegramId && telegramId !== String(session.uid)) return res.sendStatus(200);
    const settings = await getSettings(), uid = String(session.uid), userRef = db.ref(`users/${uid}`);
    let problem = "";
    const credited = await userRef.transaction(user => {
      if (!user) { problem = "user missing"; return; }
      user.rewardedAdIds = user.rewardedAdIds || {};
      if (user.rewardedAdIds[ymid]) { problem = "duplicate"; return; }
      const usage = user.adDailyUsage || {}, count = Number(usage[session.day] || 0);
      if (count >= Number(settings.adsPerDay || 0)) { problem = "daily cap"; return; }
      if (user.pendingAdSession !== ymid) { problem = "session mismatch"; return; }
      user.balance = Number(user.balance || 0) + Number(settings.adRewardCP || 0);
      usage[session.day] = count + 1;
      user.adDailyUsage = usage;
      user.rewardedAdIds[ymid] = Date.now();
      delete user.pendingAdSession;
      return user;
    }, undefined, false);
    if (credited.committed) {
      await sessionRef.update({ status: "rewarded", rewardedAt: Date.now(), creditedCP: Number(settings.adRewardCP || 0) });
    }
    res.sendStatus(200);
  } catch (e) { console.error("Monetag postback error:", e.message); res.sendStatus(500); }
});

// Withdrawal request is stored under the user's record in the same Firebase transaction
// that reserves CP. This makes the balance deduction and request creation atomic.
app.post("/api/withdrawals", requireDb, verifyTelegram, async (req, res) => {
  try {
    const uid = String(req.tgUser.id);
    const settings = await getSettings();
    if (settings.withdrawalEnabled === false) return res.status(403).json({ error: "Withdrawals are currently disabled" });
    const minCP = Number(settings.minWithdrawalCP ?? defaults.minWithdrawalCP);
    const cpPerUSD = Number(settings.cpPerUSD ?? defaults.cpPerUSD);
    const amountCP = Number(req.body.amountCP);
    const walletAddress = String(req.body.walletAddress || "").trim();
    const network = String(req.body.network || "USDT").trim().slice(0, 30);
    if (!Number.isFinite(amountCP) || amountCP <= 0 || !Number.isInteger(amountCP)) {
      return res.status(400).json({ error: "Enter a whole-number CP amount" });
    }
    if (amountCP < minCP) return res.status(400).json({ error: `Minimum withdrawal is ${minCP.toLocaleString()} CP` });
    if (!walletAddress || walletAddress.length < 8 || walletAddress.length > 180) {
      return res.status(400).json({ error: "Enter a valid wallet address (8–180 characters)" });
    }
    if (!["USDT (TRC20)", "USDT (BEP20)", "USDT (ERC20)", "Crypto - Other"].includes(network)) {
      return res.status(400).json({ error: "Select a supported payment network" });
    }
    // Accrue any mining CP earned up to this moment before checking the balance.
    await syncMining(uid, settings);
    const id = db.ref(`users/${uid}/withdrawals`).push().key;
    const now = Date.now();
    let transactionError = null;
    const userRef = db.ref(`users/${uid}`);
    const result = await userRef.transaction(user => {
      if (!user) { transactionError = "Account not found. Reopen the Mini App."; return; }
      const balance = Number(user.balance || 0);
      if (balance < amountCP) { transactionError = "Insufficient CP balance"; return; }
      user.balance = balance - amountCP;
      user.withdrawals = user.withdrawals || {};
      user.withdrawals[id] = {
        id, userId: uid, amountCP, amountUSD: amountCP / cpPerUSD,
        cpPerUSD, walletAddress, network, status: "Pending",
        createdAt: now, updatedAt: now
      };
      return user;
    }, undefined, false);
    if (!result.committed) return res.status(400).json({ error: transactionError || "Withdrawal could not be created; refresh and try again" });
    res.json({ success: true, withdrawal: result.snapshot.val().withdrawals[id], balance: Number(result.snapshot.val().balance || 0) });
  } catch (e) {
    console.error("withdrawal request error:", e.message);
    res.status(500).json({ error: "Could not submit withdrawal request" });
  }
});

app.get("/api/withdrawals", requireDb, verifyTelegram, async (req, res) => {
  try {
    const uid = String(req.tgUser.id);
    const snap = await db.ref(`users/${uid}/withdrawals`).once("value");
    const items = Object.values(snap.val() || {}).sort((a,b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
    const s = await getSettings();
    res.json({
      withdrawals: items,
      balance: Number((await db.ref(`users/${uid}/balance`).once("value")).val() || 0),
      withdrawalEnabled: s.withdrawalEnabled !== false,
      minWithdrawalCP: Number(s.minWithdrawalCP ?? defaults.minWithdrawalCP),
      cpPerUSD: Number(s.cpPerUSD ?? defaults.cpPerUSD)
    });
  } catch (e) { res.status(500).json({ error: "Could not load withdrawal history" }); }
});

app.get("/api/admin/withdrawals", requireDb, requireAdmin, async (req, res) => {
  try {
    const snap = await db.ref("users").once("value");
    const users = snap.val() || {};
    const items = [];
    for (const [uid, user] of Object.entries(users)) {
      for (const w of Object.values(user.withdrawals || {})) {
        items.push({
          ...w, userId: uid, firstName: user.firstName || "",
          username: user.username || ""
        });
      }
    }
    items.sort((a,b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
    res.json({ withdrawals: items });
  } catch (e) { res.status(500).json({ error: "Could not load withdrawal requests" }); }
});

app.post("/api/admin/withdrawals/:userId/:withdrawalId", requireDb, requireAdmin, async (req, res) => {
  try {
    const uid = String(req.params.userId);
    const id = String(req.params.withdrawalId);
    const action = String(req.body.action || "");
    const txHash = String(req.body.txHash || "").trim().slice(0, 200);
    if (!["Approved", "Rejected"].includes(action)) return res.status(400).json({ error: "Action must be Approved or Rejected" });
    let problem = "";
    const ref = db.ref(`users/${uid}`);
    const result = await ref.transaction(user => {
      if (!user || !user.withdrawals || !user.withdrawals[id]) { problem = "Withdrawal request not found"; return; }
      const w = user.withdrawals[id];
      if (w.status !== "Pending") { problem = `Request is already ${w.status}`; return; }
      w.status = action;
      w.updatedAt = Date.now();
      if (action === "Approved") {
        w.reviewedAt = Date.now();
        if (txHash) w.txHash = txHash;
        w.paymentNote = txHash ? "Transaction reference saved; send payment manually if not yet sent." : "Approved by admin; payment must be sent manually.";
      } else {
        user.balance = Number(user.balance || 0) + Number(w.amountCP || 0);
        w.refundedAt = Date.now();
      }
      user.withdrawals[id] = w;
      return user;
    }, undefined, false);
    if (!result.committed) return res.status(400).json({ error: problem || "Could not update request" });
    res.json({ success: true, status: action });
  } catch (e) { res.status(500).json({ error: "Could not update withdrawal request" }); }
});

app.get("/api/admin/settings", requireDb, requireAdmin, async (req, res) => {
  res.json(await getSettings());
});
app.post("/api/admin/settings", requireDb, requireAdmin, async (req, res) => {
  const allowed = [
    "appName", "dailyMiningCP", "referralCP", "adRewardCP", "adsPerDay", "monetagZoneId1", "monetagZoneId2",
    "miningEnabled", "adsEnabled", "referralsEnabled", "notice",
    "withdrawalEnabled", "minWithdrawalCP", "cpPerUSD"
  ];
  const current = await getSettings();
  const next = { ...current };
  for (const key of allowed) if (req.body[key] !== undefined) next[key] = req.body[key];
  for (const key of ["dailyMiningCP", "referralCP", "adRewardCP", "adsPerDay", "minWithdrawalCP", "cpPerUSD"]) {
    if (!Number.isFinite(Number(next[key])) || Number(next[key]) < 0) {
      return res.status(400).json({ error: `Invalid ${key}` });
    }
    next[key] = Number(next[key]);
  }
  next.monetagZoneId1 = cleanZone(next.monetagZoneId1);
  next.monetagZoneId2 = cleanZone(next.monetagZoneId2);
  if (next.adsPerDay < 0 || !Number.isInteger(next.adsPerDay)) return res.status(400).json({ error: "Daily ad limit must be a whole number 0 or greater" });
  if (next.minWithdrawalCP < 1) return res.status(400).json({ error: "Minimum withdrawal CP must be at least 1" });
  if (next.cpPerUSD <= 0) return res.status(400).json({ error: "CP per USD must be greater than 0" });
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
  let sent = 0, failed = 0;
  for (const uid of users) {
    try {
      const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: uid, text: message })
      });
      if (response.ok) sent++; else failed++;
    } catch { failed++; }
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
  if (n.expiresAt && Date.now() > n.expiresAt) return res.json({ notice: null });
  res.json({ notice: n });
});
app.get("/health", (req, res) => res.json({ status: "ok", firebase: Boolean(db) }));
app.listen(PORT, () => console.log(`CP Mining server listening on ${PORT}`));
