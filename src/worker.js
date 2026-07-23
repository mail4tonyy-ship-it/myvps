const SESSION_TTL = 12 * 60 * 60 * 1000;
const REPORT_LIMIT = 256 * 1024;
const STALE_AFTER = 90 * 1000;
const OFFLINE_AFTER = 6 * 60 * 1000;
const AGENT_VERSION = "2026.07.23.1";

const json = (body, init = {}) => new Response(JSON.stringify(body), {
  ...init,
  headers: { "Content-Type": "application/json; charset=utf-8", ...(init.headers || {}) },
});

async function sha256(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}

async function passwordHash(password) {
  return `sha256:${await sha256(password)}`;
}

async function passwordMatches(password, stored) {
  if (!stored) return false;
  if (stored.startsWith("sha256:")) return `sha256:${await sha256(password)}` === stored;
  return password === stored;
}

async function readJson(request, limit = 32 * 1024) {
  const declared = Number(request.headers.get("Content-Length") || 0);
  if (declared && declared > limit) throw new Error("Request body too large");
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > limit) throw new Error("Request body too large");
  return text ? JSON.parse(text) : {};
}

function publicOrigin(request) {
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}

function validIp(value) {
  return typeof value === "string" && /^[0-9A-Fa-f:.]{2,64}$/.test(value);
}

async function ensureSchema(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS servers (
      ip TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      group_name TEXT DEFAULT 'default',
      country TEXT DEFAULT 'XX',
      price TEXT DEFAULT '',
      expire_date TEXT DEFAULT '',
      bandwidth TEXT DEFAULT '',
      traffic_limit REAL DEFAULT 0,
      reset_day INTEGER DEFAULT 1,
      hidden INTEGER DEFAULT 0,
      agent_token TEXT,
      cpu REAL DEFAULT 0,
      mem REAL DEFAULT 0,
      disk REAL DEFAULT 0,
      load_avg TEXT DEFAULT '',
      uptime TEXT DEFAULT '',
      os TEXT DEFAULT '',
      cpu_info TEXT DEFAULT '',
      arch TEXT DEFAULT '',
      virt TEXT DEFAULT '',
      boot_time TEXT DEFAULT '',
      ram_total REAL DEFAULT 0,
      ram_used REAL DEFAULT 0,
      swap_total REAL DEFAULT 0,
      swap_used REAL DEFAULT 0,
      disk_total REAL DEFAULT 0,
      disk_used REAL DEFAULT 0,
      processes INTEGER DEFAULT 0,
      tcp_conn INTEGER DEFAULT 0,
      udp_conn INTEGER DEFAULT 0,
      net_rx REAL DEFAULT 0,
      net_tx REAL DEFAULT 0,
      last_rx REAL DEFAULT 0,
      last_tx REAL DEFAULT 0,
      monthly_rx REAL DEFAULT 0,
      monthly_tx REAL DEFAULT 0,
      reset_cycle TEXT DEFAULT '',
      net_in_speed REAL DEFAULT 0,
      net_out_speed REAL DEFAULT 0,
      ping_ct INTEGER DEFAULT 0,
      ping_cu INTEGER DEFAULT 0,
      ping_cm INTEGER DEFAULT 0,
      ping_bd INTEGER DEFAULT 0,
      ping_v4 INTEGER DEFAULT 0,
      ip_v4 TEXT DEFAULT '',
      ip_v6 TEXT DEFAULT '',
      agent_version TEXT DEFAULT '',
      history TEXT DEFAULT '{}',
      last_report INTEGER DEFAULT 0,
      last_report_id TEXT DEFAULT '',
      alert_sent INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT 0
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS report_receipts (
      report_id TEXT PRIMARY KEY,
      ip TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )`),
  ]);

  const upgrades = [
    "ALTER TABLE servers ADD COLUMN ping_v4 INTEGER DEFAULT 0",
    "ALTER TABLE servers ADD COLUMN agent_version TEXT DEFAULT ''",
  ];
  for (const sql of upgrades) {
    try { await db.prepare(sql).run(); } catch {}
  }

  const defaults = {
    site_title: "服务器全景探针",
    is_public: "true",
    report_interval: "15",
    ping_node_ct: "223.5.5.5",
    ping_node_cu: "119.29.29.29",
    ping_node_cm: "120.196.165.24",
    ping_node_bd: "180.76.76.76",
    ping_node_v4: "1.1.1.1",
    theme: "light",
    auto_reset_traffic: "true",
  };
  const now = Date.now();
  await db.batch(Object.entries(defaults).map(([key, value]) =>
    db.prepare("INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)").bind(key, value, now)
  ));
}

async function settingsMap(db) {
  const rows = (await db.prepare("SELECT key, value FROM settings").all()).results || [];
  return Object.fromEntries(rows.map(row => [row.key, row.value]));
}

function clientSettings(settings) {
  const filtered = { ...settings };
  delete filtered.admin_password_hash;
  return filtered;
}

async function newSession(db, username) {
  const raw = crypto.randomUUID() + "." + crypto.randomUUID();
  await db.prepare("INSERT INTO sessions (token_hash, username, expires_at) VALUES (?, ?, ?)")
    .bind(await sha256(raw), username, Date.now() + SESSION_TTL).run();
  return raw;
}

async function currentUser(request, env, db) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return "";
  const row = await db.prepare("SELECT username, expires_at FROM sessions WHERE token_hash = ?").bind(await sha256(token)).first();
  if (!row || Number(row.expires_at) < Date.now()) return "";
  return row.username;
}

async function requireAdmin(request, env, db) {
  const user = await currentUser(request, env, db);
  return user && user === (env.ADMIN_USERNAME || "admin");
}

async function verifyAgent(request, db, ip) {
  if (!validIp(ip)) return false;
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return false;
  const row = await db.prepare("SELECT agent_token FROM servers WHERE ip = ?").bind(ip).first();
  return !!row?.agent_token && row.agent_token === token;
}

function trafficCycle(now, resetDay) {
  const local = new Date(now + 8 * 60 * 60 * 1000);
  let year = local.getUTCFullYear();
  let month = local.getUTCMonth() + 1;
  const day = local.getUTCDate();
  const reset = Math.max(1, Math.min(31, Number(resetDay) || 1));
  const thisReset = Math.min(reset, new Date(Date.UTC(year, month, 0)).getUTCDate());
  if (day >= thisReset) return `${year}-${month}-${thisReset}`;
  month -= 1;
  if (month === 0) { month = 12; year -= 1; }
  return `${year}-${month}-${Math.min(reset, new Date(Date.UTC(year, month, 0)).getUTCDate())}`;
}

function pushHistory(raw, data, now) {
  let history = {};
  try { history = JSON.parse(raw || "{}"); } catch {}
  if (now - Number(history.last_time || 0) < 300000 && Array.isArray(history.time)) return JSON.stringify(history);
  const cap = 288;
  const add = (key, value) => {
    const arr = Array.isArray(history[key]) ? history[key] : [];
    arr.push(value);
    history[key] = arr.slice(-cap);
  };
  const d = new Date(now + 8 * 60 * 60 * 1000);
  add("time", `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`);
  add("cpu", Number(data.cpu || 0));
  add("ram", Number(data.mem || 0));
  add("disk", Number(data.disk || 0));
  add("net_in", Number(data.net_in_speed || 0));
  add("net_out", Number(data.net_out_speed || 0));
  add("tcp", Number(data.tcp_conn || 0));
  add("udp", Number(data.udp_conn || 0));
  add("ping_ct", Number(data.ping_ct || 0));
  add("ping_cu", Number(data.ping_cu || 0));
  add("ping_cm", Number(data.ping_cm || 0));
  add("ping_bd", Number(data.ping_bd || 0));
  add("ping_v4", Number(data.ping_v4 || 0));
  history.last_time = now;
  return JSON.stringify(history);
}

function decorateServer(row, now = Date.now()) {
  const last = Number(row.last_report || 0);
  const state = !last || now - last > OFFLINE_AFTER ? "offline" : now - last > STALE_AFTER ? "stale" : "online";
  return { ...row, state };
}

async function handleReport(request, env, db) {
  const data = await readJson(request, REPORT_LIMIT);
  if (!validIp(data.ip) || !String(data.report_id || "").startsWith(`${data.ip}:`)) return json({ error: "Invalid report" }, { status: 400 });
  if (!(await verifyAgent(request, db, data.ip))) return new Response("Unauthorized", { status: 401 });

  const server = await db.prepare("SELECT * FROM servers WHERE ip = ?").bind(data.ip).first();
  if (!server) return json({ error: "Server removed" }, { status: 403 });
  if (await db.prepare("SELECT report_id FROM report_receipts WHERE report_id = ?").bind(data.report_id).first()) {
    return json({ success: true, duplicate: true });
  }

  const now = Date.now();
  const settings = await settingsMap(db);
  const cycle = trafficCycle(now, server.reset_day);
  let monthlyRx = Number(server.monthly_rx || 0);
  let monthlyTx = Number(server.monthly_tx || 0);
  let lastRx = Number(server.last_rx || 0);
  let lastTx = Number(server.last_tx || 0);
  if (settings.auto_reset_traffic === "true" && server.reset_cycle && server.reset_cycle !== cycle) {
    monthlyRx = 0;
    monthlyTx = 0;
  }
  const currentRx = Number(data.net_rx || 0);
  const currentTx = Number(data.net_tx || 0);
  monthlyRx += currentRx >= lastRx ? currentRx - lastRx : currentRx;
  monthlyTx += currentTx >= lastTx ? currentTx - lastTx : currentTx;
  lastRx = currentRx;
  lastTx = currentTx;
  const history = pushHistory(server.history, data, now);
  const country = request.cf?.country || server.country || "XX";

  await db.batch([
    db.prepare("INSERT INTO report_receipts (report_id, ip, created_at) VALUES (?, ?, ?)").bind(data.report_id, data.ip, now),
    db.prepare(`UPDATE servers SET
      country=?, cpu=?, mem=?, disk=?, load_avg=?, uptime=?, os=?, cpu_info=?, arch=?, virt=?, boot_time=?,
      ram_total=?, ram_used=?, swap_total=?, swap_used=?, disk_total=?, disk_used=?, processes=?, tcp_conn=?, udp_conn=?,
      net_rx=?, net_tx=?, last_rx=?, last_tx=?, monthly_rx=?, monthly_tx=?, reset_cycle=?,
      net_in_speed=?, net_out_speed=?, ping_ct=?, ping_cu=?, ping_cm=?, ping_bd=?, ping_v4=?, ip_v4=?, ip_v6=?,
      agent_version=?,
      history=?, last_report=?, last_report_id=?, alert_sent=0 WHERE ip=?`)
      .bind(country, data.cpu || 0, data.mem || 0, data.disk || 0, data.load || "", data.uptime || "", data.os || "", data.cpu_info || "", data.arch || "", data.virt || "", data.boot_time || "",
        data.ram_total || 0, data.ram_used || 0, data.swap_total || 0, data.swap_used || 0, data.disk_total || 0, data.disk_used || 0, data.processes || 0, data.tcp_conn || 0, data.udp_conn || 0,
        currentRx, currentTx, lastRx, lastTx, monthlyRx, monthlyTx, cycle,
        data.net_in_speed || 0, data.net_out_speed || 0, data.ping_ct || 0, data.ping_cu || 0, data.ping_cm || 0, data.ping_bd || 0, data.ping_v4 || 0, data.ip_v4 || "", data.ip_v6 || "",
        data.agent_version || "", history, now, data.report_id, data.ip),
  ]);

  return json({
    success: true,
    interval: Math.max(10, Math.min(300, Number(settings.report_interval || 15))),
    ping_ct: settings.ping_node_ct,
    ping_cu: settings.ping_node_cu,
    ping_cm: settings.ping_node_cm,
    ping_bd: settings.ping_node_bd,
    ping_v4: settings.ping_node_v4,
  });
}

async function api(request, env, ctx) {
  if (!env.DB) return json({ error: "Missing D1 binding: DB" }, { status: 500 });
  await ensureSchema(env.DB);
  const db = env.DB;
  const url = new URL(request.url);
  const parts = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
  const action = parts[0] || "";

  if (request.method === "OPTIONS") return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Authorization, Content-Type", "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS" } });

  if (action === "login" && request.method === "POST") {
    const body = await readJson(request, 8 * 1024).catch(() => ({}));
    const username = env.ADMIN_USERNAME || "admin";
    const password = String(body.password || "");
    if (String(body.username || "") !== username) return json({ error: "Unauthorized" }, { status: 401 });
    const envPassword = String(env.ADMIN_PASSWORD || "");
    if (envPassword && envPassword !== "change-me-now" && password === envPassword) {
      return json({ success: true, token: await newSession(db, username), role: "admin" });
    }
    const stored = await db.prepare("SELECT value FROM settings WHERE key = 'admin_password_hash'").first();
    if (stored?.value && await passwordMatches(password, stored.value)) {
      return json({ success: true, token: await newSession(db, username), role: "admin" });
    }
    if (!stored?.value && password.length >= 8) {
      await db.prepare("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('admin_password_hash', ?, ?)")
        .bind(await passwordHash(password), Date.now()).run();
      return json({ success: true, token: await newSession(db, username), role: "admin", setup: true });
    }
    return json({ error: stored?.value ? "Unauthorized" : "首次登录请设置至少 8 位密码" }, { status: 401 });
  }

  if (action === "logout" && request.method === "POST") {
    const header = request.headers.get("Authorization") || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (token) await db.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(token)).run();
    return json({ success: true });
  }

  if (action === "public" && request.method === "GET") {
    const settings = await settingsMap(db);
    if (settings.is_public !== "true") return json({ error: "Private dashboard" }, { status: 403 });
    const rows = (await db.prepare("SELECT * FROM servers WHERE hidden = 0 ORDER BY group_name, name").all()).results || [];
    return json({ settings: clientSettings(settings), servers: rows.map(row => decorateServer(row)) });
  }

  if (action === "report" && request.method === "POST") return handleReport(request, env, db);

  if (action === "agent" && parts[1] === "config" && request.method === "GET") {
    const ip = url.searchParams.get("ip") || "";
    if (!(await verifyAgent(request, db, ip))) return new Response("Unauthorized", { status: 401 });
    const settings = await settingsMap(db);
    return json({ settings: clientSettings(settings) });
  }

  if (action === "agent" && parts[1] === "script" && request.method === "GET") {
    if (!env.ASSETS) return json({ error: "Missing ASSETS binding" }, { status: 500 });
    return env.ASSETS.fetch(new URL("/vps/panorama-agent.py", request.url));
  }

  if (!(await requireAdmin(request, env, db))) return json({ error: "Unauthorized" }, { status: 401 });

  if (action === "me") return json({ username: env.ADMIN_USERNAME || "admin", role: "admin" });

  if (action === "password" && request.method === "POST") {
    const body = await readJson(request, 8 * 1024).catch(() => ({}));
    const password = String(body.password || "");
    if (password.length < 8) return json({ error: "密码至少 8 位" }, { status: 400 });
    await db.prepare("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('admin_password_hash', ?, ?)")
      .bind(await passwordHash(password), Date.now()).run();
    return json({ success: true });
  }

  if (action === "data" && request.method === "GET") {
    const settings = await settingsMap(db);
    const rows = (await db.prepare("SELECT * FROM servers ORDER BY group_name, name").all()).results || [];
    return json({ settings: clientSettings(settings), servers: rows.map(row => decorateServer(row)), origin: publicOrigin(request) });
  }

  if (action === "servers" && request.method === "POST") {
    const body = await readJson(request, 16 * 1024);
    if (!validIp(body.ip)) return json({ error: "Invalid IP" }, { status: 400 });
    const token = crypto.randomUUID();
    const now = Date.now();
    await db.prepare(`INSERT INTO servers (ip, name, group_name, agent_token, created_at)
      VALUES (?, ?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET name=excluded.name, group_name=excluded.group_name`)
      .bind(body.ip, String(body.name || body.ip).slice(0, 100), String(body.group_name || "default").slice(0, 80), token, now).run();
    const row = await db.prepare("SELECT * FROM servers WHERE ip = ?").bind(body.ip).first();
    const origin = publicOrigin(request);
    return json({ success: true, server: decorateServer(row), command: installCommand(origin, body.ip, row.agent_token), upgradeCommand: upgradeCommand(origin) });
  }

  if (action === "servers" && request.method === "PUT") {
    const body = await readJson(request, 16 * 1024);
    if (!validIp(body.ip)) return json({ error: "Invalid IP" }, { status: 400 });
    await db.prepare(`UPDATE servers SET name=?, group_name=?, price=?, expire_date=?, bandwidth=?, traffic_limit=?, reset_day=?, hidden=? WHERE ip=?`)
      .bind(String(body.name || body.ip).slice(0, 100), String(body.group_name || "default").slice(0, 80), String(body.price || "").slice(0, 80), String(body.expire_date || "").slice(0, 40),
        String(body.bandwidth || "").slice(0, 80), Number(body.traffic_limit || 0), Math.max(1, Math.min(31, Number(body.reset_day || 1))), body.hidden ? 1 : 0, body.ip).run();
    return json({ success: true });
  }

  if (action === "servers" && request.method === "DELETE") {
    const ip = url.searchParams.get("ip") || "";
    await db.prepare("DELETE FROM servers WHERE ip = ?").bind(ip).run();
    return json({ success: true });
  }

  if (action === "servers" && parts[1] === "token" && request.method === "POST") {
    const ip = url.searchParams.get("ip") || "";
    const token = crypto.randomUUID();
    await db.prepare("UPDATE servers SET agent_token = ? WHERE ip = ?").bind(token, ip).run();
    return json({ success: true, token, command: installCommand(publicOrigin(request), ip, token) });
  }

  if (action === "agent" && parts[1] === "upgrade-command" && request.method === "GET") {
    return json({ success: true, command: upgradeCommand(publicOrigin(request)), version: AGENT_VERSION });
  }

  if (action === "settings" && request.method === "POST") {
    const body = await readJson(request, 32 * 1024);
    const allowed = ["site_title", "is_public", "report_interval", "ping_node_ct", "ping_node_cu", "ping_node_cm", "ping_node_bd", "ping_node_v4", "theme", "auto_reset_traffic"];
    const now = Date.now();
    const statements = allowed.filter(key => body[key] !== undefined).map(key =>
      db.prepare("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)").bind(key, String(body[key]), now)
    );
    if (statements.length) await db.batch(statements);
    return json({ success: true });
  }

  if (action === "cron_check" && request.method === "POST") {
    if (!env.CRON_SECRET || request.headers.get("Authorization") !== `Bearer ${env.CRON_SECRET}`) return new Response("Unauthorized", { status: 401 });
    return json({ success: true, alerted: await checkOffline(env) });
  }

  return json({ error: "Not found" }, { status: 404 });
}

function installCommand(origin, ip, token) {
  return `curl -fsSL ${origin}/vps/install.sh | sh -s -- --api ${origin} --ip ${ip} --token ${token}`;
}

function upgradeCommand(origin) {
  return `curl -fsSL ${origin}/vps/upgrade-agent.sh | sh`;
}

async function checkOffline(env) {
  const cutoff = Date.now() - OFFLINE_AFTER;
  const rows = (await env.DB.prepare("SELECT ip FROM servers WHERE last_report > 0 AND last_report < ? AND alert_sent = 0").bind(cutoff).all()).results || [];
  if (rows.length) await env.DB.batch(rows.map(row => env.DB.prepare("UPDATE servers SET alert_sent = 1 WHERE ip = ?").bind(row.ip)));
  return rows.length;
}

async function serveAsset(request, env) {
  if (!env.ASSETS) return new Response("ASSETS binding is not configured", { status: 500 });
  const response = await env.ASSETS.fetch(request);
  if (response.status !== 404) return response;
  return env.ASSETS.fetch(new URL("/", request.url));
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
      try { return await api(request, env, ctx); }
      catch (error) { return json({ error: error.message || "Internal error" }, { status: 500 }); }
    }
    return serveAsset(request, env);
  },
  async scheduled(controller, env, ctx) {
    ctx.waitUntil((async () => { await ensureSchema(env.DB); await checkOffline(env); })());
  },
};
