import { DurableObject } from "cloudflare:workers";

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_SETTINGS = {
  site_title: "探针全景大盘",
  theme: "theme1",
  is_public: "true",
  show_price: "true",
  show_expire: "true",
  show_bw: "true",
  show_tf: "true",
  report_interval: "60",
  custom_css: "",
  custom_bg: "",
  enable_popup: "false",
  popup_content: ""
};

let schemaReadyPromise = null;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
  });
}

function text(body, status = 200, contentType = "text/plain; charset=utf-8") {
  return new Response(body, { status, headers: { "Content-Type": contentType, "Cache-Control": "no-store" } });
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

async function token() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let raw = "";
  bytes.forEach(byte => raw += String.fromCharCode(byte));
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function validIp(value) {
  return typeof value === "string" && /^[0-9A-Fa-f:.]{2,64}$/.test(value);
}

function clean(value, max = 120) {
  return String(value ?? "").slice(0, max);
}

async function readJson(request, maxBytes = 64 * 1024) {
  const declared = Number(request.headers.get("Content-Length") || 0);
  if (declared && declared > maxBytes) throw new Error("Request body too large");
  const raw = await request.text();
  if (raw.length > maxBytes) throw new Error("Request body too large");
  const parsed = raw ? JSON.parse(raw) : {};
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("JSON object required");
  return parsed;
}

async function ensureDbSchema(db) {
  if (!schemaReadyPromise) {
    schemaReadyPromise = (async () => {
      const statements = [
        `CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL)`,
        `CREATE TABLE IF NOT EXISTS servers (
          ip TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          agent_token TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          last_report INTEGER DEFAULT 0,
          alert_sent INTEGER DEFAULT 0
        )`,
        `CREATE TABLE IF NOT EXISTS probe_settings (key TEXT PRIMARY KEY, value TEXT)`,
        `CREATE TABLE IF NOT EXISTS probe_servers (
          id TEXT PRIMARY KEY,
          name TEXT,
          cpu TEXT DEFAULT '0',
          ram TEXT DEFAULT '0',
          disk TEXT DEFAULT '0',
          load_avg TEXT DEFAULT '',
          uptime TEXT DEFAULT '',
          last_updated INTEGER DEFAULT 0,
          ram_total TEXT DEFAULT '0',
          ram_used TEXT DEFAULT '0',
          swap_total TEXT DEFAULT '0',
          swap_used TEXT DEFAULT '0',
          disk_total TEXT DEFAULT '0',
          disk_used TEXT DEFAULT '0',
          net_rx TEXT DEFAULT '0',
          net_tx TEXT DEFAULT '0',
          net_in_speed TEXT DEFAULT '0',
          net_out_speed TEXT DEFAULT '0',
          os TEXT DEFAULT '',
          cpu_info TEXT DEFAULT '',
          arch TEXT DEFAULT '',
          boot_time TEXT DEFAULT '',
          processes TEXT DEFAULT '0',
          tcp_conn TEXT DEFAULT '0',
          udp_conn TEXT DEFAULT '0',
          country TEXT DEFAULT 'XX',
          ip_v4 TEXT DEFAULT '',
          ip_v6 TEXT DEFAULT '',
          server_group TEXT DEFAULT '默认分组',
          price TEXT DEFAULT '',
          expire_date TEXT DEFAULT '',
          bandwidth TEXT DEFAULT '',
          traffic_limit TEXT DEFAULT '',
          monthly_rx TEXT DEFAULT '0',
          monthly_tx TEXT DEFAULT '0',
          last_rx TEXT DEFAULT '0',
          last_tx TEXT DEFAULT '0',
          history TEXT DEFAULT '{}',
          is_hidden TEXT DEFAULT 'false',
          virt TEXT DEFAULT ''
        )`
      ];
      for (const statement of statements) await db.prepare(statement).run();
      for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) {
        await db.prepare("INSERT OR IGNORE INTO probe_settings (key, value) VALUES (?, ?)").bind(key, value).run();
      }
    })().catch(error => {
      schemaReadyPromise = null;
      throw error;
    });
  }
  return schemaReadyPromise;
}

async function currentUser(request, env) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) return null;
  const sessionHash = await sha256(header.slice(7));
  const row = await env.DB.prepare("SELECT username FROM auth_sessions WHERE token_hash = ? AND expires_at > ?")
    .bind(sessionHash, Date.now()).first();
  return row?.username || null;
}

async function requireAdmin(request, env) {
  const user = await currentUser(request, env);
  if (user !== (env.ADMIN_USERNAME || "admin")) return null;
  return user;
}

async function verifyAgent(request, env, ip) {
  const auth = request.headers.get("Authorization") || "";
  if (!validIp(ip) || !auth) return false;
  const row = await env.DB.prepare("SELECT agent_token FROM servers WHERE ip = ?").bind(ip).first();
  return !!row?.agent_token && row.agent_token === auth;
}

async function settings(db) {
  const out = { ...DEFAULT_SETTINGS };
  const { results } = await db.prepare("SELECT key, value FROM probe_settings").all();
  (results || []).forEach(row => out[row.key] = row.value);
  return out;
}

function hub(env) {
  return env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
}

async function publicSnapshot(env) {
  await ensureDbSchema(env.DB);
  const appSettings = await settings(env.DB);
  const { results } = await env.DB.prepare(
    `SELECT id, name, cpu, ram, disk, load_avg, uptime, last_updated, net_in_speed, net_out_speed,
      os, arch, virt, tcp_conn, udp_conn, country, ip_v4, ip_v6, server_group, price, expire_date,
      bandwidth, traffic_limit, monthly_rx, monthly_tx, net_rx, net_tx, cpu_info, ram_used, ram_total,
      disk_used, disk_total
     FROM probe_servers WHERE is_hidden != 'true' ORDER BY server_group, name`
  ).all();
  return { settings: appSettings, servers: results || [], realtime_url: "" };
}

async function broadcastSnapshot(env) {
  try {
    await hub(env).fetch(new Request("https://hub.internal/broadcast", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(await publicSnapshot(env))
    }));
  } catch {}
}

async function handleApi(request, env, ctx, path) {
  await ensureDbSchema(env.DB);
  const url = new URL(request.url);
  const method = request.method;
  const route = path.join("/");

  if (route === "auth/login" && method === "POST") {
    const body = await readJson(request);
    const username = clean(body.username || "admin", 64);
    const password = String(body.password || "");
    if (username !== (env.ADMIN_USERNAME || "admin") || password !== (env.ADMIN_PASSWORD || "admin")) {
      return json({ error: "用户名或密码错误" }, 401);
    }
    const session = await token();
    await env.DB.prepare("INSERT INTO auth_sessions (token_hash, username, expires_at) VALUES (?, ?, ?)")
      .bind(await sha256(session), username, Date.now() + SESSION_TTL_MS).run();
    return json({ token: session, username });
  }

  if (route === "auth/me" && method === "GET") {
    const user = await currentUser(request, env);
    return user ? json({ username: user }) : json({ error: "Unauthorized" }, 401);
  }

  if (route === "probe/public" && method === "GET") {
    const data = await publicSnapshot(env);
    if (data.settings.is_public !== "true" && !(await currentUser(request, env))) return json({ error: "Private Dashboard" }, 401);
    return json(data, 200, { "Cache-Control": "public, max-age=10, s-maxage=10" });
  }

  if (route === "probe/detail" && method === "GET") {
    const id = url.searchParams.get("id") || "";
    const row = await env.DB.prepare("SELECT * FROM probe_servers WHERE id = ? AND is_hidden != 'true'").bind(id).first();
    if (!row) return json({ error: "Not found" }, 404);
    const appSettings = await settings(env.DB);
    if (appSettings.is_public !== "true" && !(await currentUser(request, env))) return json({ error: "Unauthorized" }, 401);
    return json(row);
  }

  if (route === "settings" && method === "POST") {
    if (!(await requireAdmin(request, env))) return json({ error: "Unauthorized" }, 401);
    const body = await readJson(request);
    const allowed = new Set(Object.keys(DEFAULT_SETTINGS));
    for (const [key, value] of Object.entries(body.settings || {})) {
      if (allowed.has(key)) {
        await env.DB.prepare("INSERT INTO probe_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
          .bind(key, clean(value, key.includes("custom") || key.includes("popup") ? 10000 : 200)).run();
      }
    }
    ctx.waitUntil(broadcastSnapshot(env));
    return json({ success: true });
  }

  if (route === "servers" && method === "GET") {
    if (!(await requireAdmin(request, env))) return json({ error: "Unauthorized" }, 401);
    const { results } = await env.DB.prepare(
      `SELECT s.ip, s.name, s.created_at, s.last_report, p.server_group, p.price, p.expire_date, p.bandwidth, p.traffic_limit, p.is_hidden
       FROM servers s LEFT JOIN probe_servers p ON p.id = s.ip ORDER BY s.created_at DESC`
    ).all();
    return json(results || []);
  }

  if (route === "servers" && method === "POST") {
    if (!(await requireAdmin(request, env))) return json({ error: "Unauthorized" }, 401);
    const body = await readJson(request);
    const ip = clean(body.ip, 64);
    if (!validIp(ip)) return json({ error: "IP 格式不正确" }, 400);
    const name = clean(body.name || ip, 120);
    const group = clean(body.server_group || "默认分组", 120);
    const agentToken = await token();
    const now = Date.now();
    await env.DB.prepare(
      "INSERT INTO servers (ip, name, agent_token, created_at, last_report) VALUES (?, ?, ?, ?, 0) ON CONFLICT(ip) DO UPDATE SET name = excluded.name"
    ).bind(ip, name, agentToken, now).run();
    await env.DB.prepare(
      `INSERT INTO probe_servers (id, name, country, ip_v4, server_group, price, is_hidden)
       VALUES (?, ?, 'XX', ?, ?, '', 'false')
       ON CONFLICT(id) DO UPDATE SET name = excluded.name, server_group = excluded.server_group`
    ).bind(ip, name, ip.includes(":") ? "" : ip, group).run();
    ctx.waitUntil(broadcastSnapshot(env));
    return json({ success: true, ip, token: agentToken, install_command: installCommand(url.origin, ip, agentToken) });
  }

  if (route === "servers" && method === "DELETE") {
    if (!(await requireAdmin(request, env))) return json({ error: "Unauthorized" }, 401);
    const ip = url.searchParams.get("ip") || "";
    await env.DB.prepare("DELETE FROM servers WHERE ip = ?").bind(ip).run();
    await env.DB.prepare("DELETE FROM probe_servers WHERE id = ?").bind(ip).run();
    ctx.waitUntil(broadcastSnapshot(env));
    return json({ success: true });
  }

  if (route === "install-command" && method === "GET") {
    if (!(await requireAdmin(request, env))) return json({ error: "Unauthorized" }, 401);
    const ip = url.searchParams.get("ip") || "";
    const row = await env.DB.prepare("SELECT agent_token FROM servers WHERE ip = ?").bind(ip).first();
    if (!row) return json({ error: "Server not found" }, 404);
    return json({ command: installCommand(url.origin, ip, row.agent_token) });
  }

  if (route === "config" && method === "GET") {
    const ip = url.searchParams.get("ip") || "";
    if (!(await verifyAgent(request, env, ip))) return text("Unauthorized", 401);
    const appSettings = await settings(env.DB);
    return json({ success: true, interval: Math.max(15, Number(appSettings.report_interval) || 60) });
  }

  if (route === "report" && method === "POST") {
    const body = await readJson(request, 256 * 1024);
    const ip = clean(body.ip, 64);
    if (!(await verifyAgent(request, env, ip))) return text("Unauthorized", 401);
    const now = Date.now();
    const existing = await env.DB.prepare("SELECT last_rx, last_tx, monthly_rx, monthly_tx, history FROM probe_servers WHERE id = ?").bind(ip).first();
    const rx = Number(body.net_rx || 0);
    const tx = Number(body.net_tx || 0);
    const lastRx = Number(existing?.last_rx || 0);
    const lastTx = Number(existing?.last_tx || 0);
    const monthlyRx = Number(existing?.monthly_rx || 0) + (rx >= lastRx ? rx - lastRx : rx);
    const monthlyTx = Number(existing?.monthly_tx || 0) + (tx >= lastTx ? tx - lastTx : tx);
    const history = nextHistory(existing?.history, body, now);
    const country = clean(body.country || request.cf?.country || "XX", 8);
    await env.DB.prepare("UPDATE servers SET last_report = ?, alert_sent = 0 WHERE ip = ?").bind(now, ip).run();
    await env.DB.prepare(
      `UPDATE probe_servers SET
        cpu=?, ram=?, disk=?, load_avg=?, uptime=?, last_updated=?, ram_total=?, ram_used=?,
        swap_total=?, swap_used=?, disk_total=?, disk_used=?, net_rx=?, net_tx=?, net_in_speed=?,
        net_out_speed=?, os=?, cpu_info=?, arch=?, boot_time=?, processes=?, tcp_conn=?, udp_conn=?,
        country=?, ip_v4=?, ip_v6=?, monthly_rx=?, monthly_tx=?, last_rx=?, last_tx=?, history=?, virt=?
       WHERE id=?`
    ).bind(
      clean(body.cpu, 20), clean(body.mem, 20), clean(body.disk, 20), clean(body.load, 80), clean(body.uptime, 80), now,
      clean(body.ram_total, 40), clean(body.ram_used, 40), clean(body.swap_total, 40), clean(body.swap_used, 40),
      clean(body.disk_total, 40), clean(body.disk_used, 40), String(rx), String(tx), clean(body.net_in_speed, 40),
      clean(body.net_out_speed, 40), clean(body.os, 120), clean(body.cpu_info, 240), clean(body.arch, 40),
      clean(body.boot_time, 80), clean(body.processes, 40), clean(body.tcp_conn, 40), clean(body.udp_conn, 40),
      country, clean(body.ip_v4, 64), clean(body.ip_v6, 128), String(monthlyRx), String(monthlyTx), String(rx),
      String(tx), JSON.stringify(history), clean(body.virt, 80), ip
    ).run();
    ctx.waitUntil(broadcastSnapshot(env));
    const appSettings = await settings(env.DB);
    return json({ success: true, interval: Math.max(15, Number(appSettings.report_interval) || 60) });
  }

  return json({ error: "Not found" }, 404);
}

function nextHistory(raw, body, now) {
  let history = {};
  try { history = JSON.parse(raw || "{}"); } catch {}
  if (now - Number(history.last_time || 0) < 5 * 60 * 1000 && Array.isArray(history.time)) return history;
  const label = new Date(now + 8 * 60 * 60 * 1000).toISOString().slice(11, 16);
  const push = (key, value) => {
    const arr = Array.isArray(history[key]) ? history[key] : [];
    arr.push(Number(value || 0));
    history[key] = arr.slice(-288);
  };
  push("cpu", body.cpu);
  push("ram", body.mem);
  push("net_in", body.net_in_speed);
  push("net_out", body.net_out_speed);
  push("tcp", body.tcp_conn);
  push("udp", body.udp_conn);
  history.time = [...(Array.isArray(history.time) ? history.time : []), label].slice(-288);
  history.last_time = now;
  return history;
}

function installCommand(origin, ip, agentToken) {
  return `bash <(curl -fsSL ${origin}/vps/install.sh) '${origin}' '${ip}' '${agentToken}'`;
}

async function checkOffline(env) {
  await ensureDbSchema(env.DB);
  const cutoff = Date.now() - 6 * 60 * 1000;
  await env.DB.prepare("UPDATE servers SET alert_sent = 1 WHERE last_report > 0 AND last_report < ?").bind(cutoff).run();
  await broadcastSnapshot(env);
}

function bindingError() {
  return html(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>部署未完成</title><body style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#f8fafc;color:#0f172a"><main style="max-width:640px;padding:32px;line-height:1.7"><h1>探针全景大盘需要完成 Cloudflare 绑定</h1><p>请确认 Worker 已绑定 D1 数据库 <code>DB</code>、Assets <code>ASSETS</code>，以及 Durable Objects <code>VPS_PRESENCE</code> 和 <code>DASHBOARD_HUB</code>。</p></main></body></html>`);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (!env.DB || !env.ASSETS || !env.DASHBOARD_HUB) return bindingError();
    if (url.pathname === "/health") return json({ ok: true, service: "probe-panorama" });
    if (url.pathname === "/public/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return json({ error: "WebSocket required" }, 426);
      return hub(env).fetch(request);
    }
    if (url.pathname === "/agent/ws") {
      return json({ ok: true, message: "HTTP report mode is enabled in the standalone build." });
    }
    if (url.pathname === "/notify") {
      ctx.waitUntil(broadcastSnapshot(env));
      return json({ success: true });
    }
    if (url.pathname === "/public-policy" || url.pathname === "/frequency-policy") {
      return json({ success: true, standalone: true });
    }
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
      return handleApi(request, env, ctx, url.pathname.slice(5).split("/").filter(Boolean));
    }
    return env.ASSETS.fetch(request);
  },

  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(checkOffline(env));
  }
};

export class DashboardHub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.latest = null;
    ctx.blockConcurrencyWhile(async () => {
      this.latest = await ctx.storage.get("latest");
    });
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/broadcast" && request.method === "POST") {
      this.latest = await request.json();
      await this.ctx.storage.put("latest", this.latest);
      this.broadcast({ type: "snapshot", data: this.latest, ts: Date.now() });
      return json({ success: true });
    }
    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.ctx.acceptWebSocket(server);
      if (this.latest) server.send(JSON.stringify({ type: "snapshot", data: this.latest, ts: Date.now() }));
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/snapshot") return json(this.latest || {});
    return json({ error: "Not found" }, 404);
  }

  webSocketMessage(ws, message) {
    if (message === "ping") ws.send("pong");
  }

  broadcast(payload) {
    const raw = JSON.stringify(payload);
    for (const ws of this.ctx.getWebSockets()) {
      try { ws.send(raw); } catch {}
    }
  }
}

export class VpsPresence extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
  }

  async fetch() {
    return json({ ok: true, standalone: true });
  }
}
