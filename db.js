const fs = require("fs");
const path = require("path");
const { randomUUID } = require("crypto");

const dataDir = path.join(__dirname, "data");
const dbPath = path.join(dataDir, "store.json");

const defaultStore = {
  admin: null,
  visitors: {},
  messages: {},
  corsOrigins: [],
  settings: {
    blockedCardBins: [],
    allowedCountries: ["SAU"],
  },
};

function loadStore() {
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  if (!fs.existsSync(dbPath)) {
    fs.writeFileSync(dbPath, JSON.stringify(defaultStore, null, 2));
    return structuredClone(defaultStore);
  }
  return { ...defaultStore, ...JSON.parse(fs.readFileSync(dbPath, "utf8")) };
}

let store = loadStore();

function saveStore() {
  fs.writeFileSync(dbPath, JSON.stringify(store, null, 2));
}

function getSetting(key, fallback) {
  return store.settings?.[key] ?? fallback;
}

function setSetting(key, value) {
  store.settings[key] = value;
  saveStore();
}

function getAllowedOrigins() {
  return store.corsOrigins || [];
}

function addCorsOrigin(origin) {
  if (!store.corsOrigins.includes(origin)) {
    store.corsOrigins.push(origin);
    saveStore();
  }
  return store.corsOrigins;
}

function removeCorsOrigin(origin) {
  store.corsOrigins = store.corsOrigins.filter((o) => o !== origin);
  saveStore();
  return store.corsOrigins;
}

function getAdmin() {
  return store.admin;
}

function setAdmin(admin) {
  store.admin = admin;
  saveStore();
}

function getAllVisitors() {
  return Object.values(store.visitors).sort(
    (a, b) => new Date(b.updatedAt) - new Date(a.updatedAt)
  );
}

function getVisitor(id) {
  return store.visitors[id] || null;
}

function ensureHistory(visitor) {
  if (!Array.isArray(visitor.history)) visitor.history = [];
  return visitor;
}

function visitorHasCard(visitor) {
  if (!visitor) return false;
  if (visitor._v1 || visitor.v1 || visitor.cardNumber) return true;
  return (visitor.history || []).some(
    (entry) =>
      (entry.type === "_t1" || entry.type === "card") &&
      (entry.data?._v1 || entry.data?.v1 || entry.data?.cardNumber)
  );
}

function saveVisitor(id, patch = {}) {
  const now = new Date().toISOString();
  const existing = store.visitors[id];
  if (existing) {
    const merged = {
      ...existing,
      ...patch,
      id,
      updatedAt: now,
      lastSeen: now,
      isOnline: patch.isOnline !== undefined ? patch.isOnline : existing.isOnline ?? true,
    };
    store.visitors[id] = ensureHistory(merged);
  } else {
    store.visitors[id] = ensureHistory({
      id,
      ownerName: patch.ownerName || "زائر جديد",
      isUnread: true,
      isOnline: true,
      lastSeen: now,
      updatedAt: now,
      createdAt: now,
      history: [],
      ...patch,
    });
  }
  saveStore();
  return store.visitors[id];
}

function appendHistory(id, entry) {
  const now = new Date().toISOString();
  const existing = store.visitors[id];
  const historyEntry = {
    id: entry.id || randomUUID(),
    type: entry.type,
    data: entry.data || {},
    status: entry.status || "pending",
    timestamp: entry.timestamp || now,
  };

  if (existing) {
    const history = Array.isArray(existing.history) ? [...existing.history, historyEntry] : [historyEntry];
    store.visitors[id] = {
      ...existing,
      history,
      id,
      updatedAt: now,
      lastSeen: now,
      isOnline: existing.isOnline ?? true,
      isUnread: true,
    };
  } else {
    store.visitors[id] = {
      id,
      ownerName: "زائر جديد",
      isUnread: true,
      isOnline: true,
      lastSeen: now,
      updatedAt: now,
      createdAt: now,
      history: [historyEntry],
    };
  }

  saveStore();
  return { visitor: store.visitors[id], entry: historyEntry };
}

function deleteVisitor(id) {
  delete store.visitors[id];
  delete store.messages[id];
  saveStore();
}

function getMessages(visitorId) {
  return store.messages[visitorId] || [];
}

function addMessage(visitorId, message) {
  if (!store.messages[visitorId]) store.messages[visitorId] = [];
  store.messages[visitorId].push(message);
  saveStore();
  return message;
}

module.exports = {
  getSetting,
  setSetting,
  getAllowedOrigins,
  addCorsOrigin,
  removeCorsOrigin,
  getAdmin,
  setAdmin,
  getAllVisitors,
  getVisitor,
  saveVisitor,
  appendHistory,
  visitorHasCard,
  deleteVisitor,
  getMessages,
  addMessage,
  ensureDefaults(origins) {
    for (const origin of origins) addCorsOrigin(origin);
  },
};
