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
  cpu_threshold: "85",
  ram_threshold: "85",
  disk_threshold: "90",
  critical_cpu_threshold: "95",
  critical_ram_threshold: "95",
  critical_disk_threshold: "97",
  offline_minutes: "6",
  ping_targets: "1.1.1.1,8.8.8.8,github.com,cloudflare.com",
  ssl_notice_days: "14",
  renew_notice_days: "7",
  traffic_notice_percent: "80",
  public_hide_sensitive: "false",
  public_password_hash: "",
  maintenance_start: "",
  maintenance_end: "",
  recovery_notice: "true",
  mobile_compact: "true",
  webhook_url: "",
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

function cleanUrl(value) {
  const url = clean(value, 500);
  return /^https:\/\//i.test(url) ? url : "";
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
          virt TEXT DEFAULT '',
          silence_until TEXT DEFAULT '0',
          notes TEXT DEFAULT '',
          renew_notice_sent TEXT DEFAULT '',
          is_pinned TEXT DEFAULT 'false',
          sla_log TEXT DEFAULT '[]',
          event_log TEXT DEFAULT '[]',
          agent_version TEXT DEFAULT '',
          traffic_notice_sent TEXT DEFAULT '',
          traffic_month TEXT DEFAULT '',
          node_icon TEXT DEFAULT '',
          node_color TEXT DEFAULT '',
          console_url TEXT DEFAULT '',
          ping_result TEXT DEFAULT '{}',
          port_checks TEXT DEFAULT '',
          port_result TEXT DEFAULT '{}',
          ssl_domains TEXT DEFAULT '',
          ssl_result TEXT DEFAULT '{}',
          ssl_notice_sent TEXT DEFAULT '',
          ssh_user TEXT DEFAULT '',
          ssh_port TEXT DEFAULT '22'
        )`
      ];
      for (const statement of statements) await db.prepare(statement).run();
      const columns = await db.prepare("PRAGMA table_info(probe_servers)").all();
      const existingColumns = new Set((columns.results || []).map(row => row.name));
      const migrations = [
        ["silence_until", "ALTER TABLE probe_servers ADD COLUMN silence_until TEXT DEFAULT '0'"],
        ["notes", "ALTER TABLE probe_servers ADD COLUMN notes TEXT DEFAULT ''"],
        ["renew_notice_sent", "ALTER TABLE probe_servers ADD COLUMN renew_notice_sent TEXT DEFAULT ''"],
        ["is_pinned", "ALTER TABLE probe_servers ADD COLUMN is_pinned TEXT DEFAULT 'false'"],
        ["sla_log", "ALTER TABLE probe_servers ADD COLUMN sla_log TEXT DEFAULT '[]'"],
        ["event_log", "ALTER TABLE probe_servers ADD COLUMN event_log TEXT DEFAULT '[]'"],
        ["agent_version", "ALTER TABLE probe_servers ADD COLUMN agent_version TEXT DEFAULT ''"],
        ["traffic_notice_sent", "ALTER TABLE probe_servers ADD COLUMN traffic_notice_sent TEXT DEFAULT ''"],
        ["traffic_month", "ALTER TABLE probe_servers ADD COLUMN traffic_month TEXT DEFAULT ''"],
        ["node_icon", "ALTER TABLE probe_servers ADD COLUMN node_icon TEXT DEFAULT ''"],
        ["node_color", "ALTER TABLE probe_servers ADD COLUMN node_color TEXT DEFAULT ''"],
        ["console_url", "ALTER TABLE probe_servers ADD COLUMN console_url TEXT DEFAULT ''"],
        ["ping_result", "ALTER TABLE probe_servers ADD COLUMN ping_result TEXT DEFAULT '{}'"],
        ["port_checks", "ALTER TABLE probe_servers ADD COLUMN port_checks TEXT DEFAULT ''"],
        ["port_result", "ALTER TABLE probe_servers ADD COLUMN port_result TEXT DEFAULT '{}'"],
        ["ssl_domains", "ALTER TABLE probe_servers ADD COLUMN ssl_domains TEXT DEFAULT ''"],
        ["ssl_result", "ALTER TABLE probe_servers ADD COLUMN ssl_result TEXT DEFAULT '{}'"],
        ["ssl_notice_sent", "ALTER TABLE probe_servers ADD COLUMN ssl_notice_sent TEXT DEFAULT ''"],
        ["ssh_user", "ALTER TABLE probe_servers ADD COLUMN ssh_user TEXT DEFAULT ''"],
        ["ssh_port", "ALTER TABLE probe_servers ADD COLUMN ssh_port TEXT DEFAULT '22'"]
      ];
      for (const [column, statement] of migrations) {
        if (!existingColumns.has(column)) await db.prepare(statement).run();
      }
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

async function adminPasswordMatches(db, env, password) {
  const passwordHash = await db.prepare("SELECT value FROM probe_settings WHERE key = 'admin_password_hash'").first();
  if (passwordHash?.value) return passwordHash.value === await sha256(password);
  return password === (env.ADMIN_PASSWORD || "admin");
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

function publicSettings(appSettings) {
  const out = { ...appSettings };
  delete out.public_password_hash;
  return out;
}

async function hasPublicAccess(request, env, appSettings) {
  if (!appSettings.public_password_hash) return true;
  if (await currentUser(request, env)) return true;
  const provided = request.headers.get("X-Public-Password") || new URL(request.url).searchParams.get("access") || "";
  return !!provided && await sha256(provided) === appSettings.public_password_hash;
}

function hub(env) {
  return env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
}

async function publicSnapshot(env, includeSensitive = false) {
  await ensureDbSchema(env.DB);
  const appSettings = await settings(env.DB);
  const { results } = await env.DB.prepare(
    `SELECT id, name, cpu, ram, disk, load_avg, uptime, last_updated, net_in_speed, net_out_speed,
      os, arch, virt, tcp_conn, udp_conn, country, ip_v4, ip_v6, server_group, price, expire_date,
      bandwidth, traffic_limit, monthly_rx, monthly_tx, net_rx, net_tx, cpu_info, ram_used, ram_total,
      disk_used, disk_total, silence_until, notes, renew_notice_sent, is_pinned, sla_log, event_log, agent_version, traffic_notice_sent,
      node_icon, node_color, console_url, ping_result, port_checks, port_result, ssl_domains, ssl_result, ssh_user, ssh_port
     FROM probe_servers WHERE is_hidden != 'true' ORDER BY is_pinned DESC, server_group, name`
  ).all();
  const servers = includeSensitive || appSettings.public_hide_sensitive !== "true"
    ? results || []
    : await Promise.all((results || []).map(maskSensitive));
  return { settings: publicSettings(appSettings), servers, realtime_url: "" };
}

async function maskSensitive(server) {
  return {
    ...server,
    id: server.id ? `node-${(await sha256(server.id)).slice(0, 12)}` : "",
    ip_v4: "",
    ip_v6: "",
    price: "",
    notes: "",
    console_url: ""
  };
}

async function publicDetailByMaskedId(db, maskedId) {
  const { results } = await db.prepare("SELECT * FROM probe_servers WHERE is_hidden != 'true'").all();
  for (const row of results || []) {
    if (`node-${(await sha256(row.id)).slice(0, 12)}` === maskedId) return row;
  }
  return null;
}

async function broadcastSnapshot(env) {
  try {
    await hub(env).fetch(new Request("https://hub.internal/broadcast", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(await publicSnapshot(env, false))
    }));
  } catch {}
}

function issueState(server, appSettings, now = Date.now()) {
  if (inMaintenance(appSettings, now)) return [];
  if (Number(server.silence_until || 0) > now) return [];
  const cpuLimit = Number(appSettings.cpu_threshold || 85);
  const ramLimit = Number(appSettings.ram_threshold || 85);
  const diskLimit = Number(appSettings.disk_threshold || 90);
  const criticalCpu = Number(appSettings.critical_cpu_threshold || 95);
  const criticalRam = Number(appSettings.critical_ram_threshold || 95);
  const criticalDisk = Number(appSettings.critical_disk_threshold || 97);
  const offlineMs = Math.max(1, Number(appSettings.offline_minutes || 6)) * 60 * 1000;
  const issues = [];
  if (Number(server.last_updated || server.last_report || 0) && now - Number(server.last_updated || server.last_report || 0) > offlineMs) issues.push("离线");
  if (Number(server.cpu || 0) >= cpuLimit) issues.push(`${Number(server.cpu || 0) >= criticalCpu ? "严重" : "警告"} CPU ${server.cpu}%`);
  const ram = server.ram ?? server.mem ?? 0;
  if (Number(ram || 0) >= ramLimit) issues.push(`${Number(ram || 0) >= criticalRam ? "严重" : "警告"} 内存 ${ram}%`);
  if (Number(server.disk || 0) >= diskLimit) issues.push(`${Number(server.disk || 0) >= criticalDisk ? "严重" : "警告"} 磁盘 ${server.disk}%`);
  return issues;
}

function alertLevel(issues) {
  if (issues.some(issue => issue.includes("严重") || issue.includes("离线"))) return "严重";
  return issues.length ? "警告" : "正常";
}

function inMaintenance(appSettings, now = Date.now()) {
  const start = Date.parse(appSettings.maintenance_start || "");
  const end = Date.parse(appSettings.maintenance_end || "");
  return Number.isFinite(start) && Number.isFinite(end) && start <= now && now <= end;
}

async function sendWebhook(env, title, payload) {
  try {
    const appSettings = await settings(env.DB);
    const target = appSettings.webhook_url || "";
    if (!/^https:\/\//i.test(target)) return;
    await fetch(target, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, ...payload, service: "probe-panorama", ts: Date.now() }),
      signal: AbortSignal.timeout(8000)
    });
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
    if (username !== (env.ADMIN_USERNAME || "admin") || !(await adminPasswordMatches(env.DB, env, password))) {
      return json({ error: "用户名或密码错误" }, 401);
    }
    const session = await token();
    await env.DB.prepare("INSERT INTO auth_sessions (token_hash, username, expires_at) VALUES (?, ?, ?)")
      .bind(await sha256(session), username, Date.now() + SESSION_TTL_MS).run();
    return json({ token: session, username });
  }

  if (route === "auth/password" && method === "POST") {
    if (!(await requireAdmin(request, env))) return json({ error: "Unauthorized" }, 401);
    const body = await readJson(request);
    const currentPassword = String(body.current_password || "");
    const nextPassword = String(body.new_password || "");
    if (!(await adminPasswordMatches(env.DB, env, currentPassword))) return json({ error: "当前密码不正确" }, 400);
    if (nextPassword.length < 8 || nextPassword.length > 128) return json({ error: "新密码长度需要 8-128 位" }, 400);
    await env.DB.prepare("INSERT INTO probe_settings (key, value) VALUES ('admin_password_hash', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .bind(await sha256(nextPassword)).run();
    await env.DB.prepare("DELETE FROM auth_sessions").run();
    return json({ success: true });
  }

  if (route === "auth/me" && method === "GET") {
    const user = await currentUser(request, env);
    return user ? json({ username: user }) : json({ error: "Unauthorized" }, 401);
  }

  if (route === "probe/public" && method === "GET") {
    const isAdmin = !!(await currentUser(request, env));
    const appSettings = await settings(env.DB);
    if (appSettings.is_public !== "true" && !isAdmin) return json({ error: "Private Dashboard" }, 401);
    if (!isAdmin && !(await hasPublicAccess(request, env, appSettings))) return json({ error: "Public password required", requires_public_password: true }, 401);
    const data = await publicSnapshot(env, isAdmin);
    return json(data, 200, { "Cache-Control": "public, max-age=10, s-maxage=10" });
  }

  if (route === "probe/detail" && method === "GET") {
    const id = url.searchParams.get("id") || "";
    const appSettings = await settings(env.DB);
    const isAdmin = !!(await currentUser(request, env));
    let row = isAdmin || appSettings.public_hide_sensitive !== "true"
      ? await env.DB.prepare("SELECT * FROM probe_servers WHERE id = ? AND is_hidden != 'true'").bind(id).first()
      : null;
    if (!row && id.startsWith("node-")) row = await publicDetailByMaskedId(env.DB, id);
    if (!row) return json({ error: "Not found" }, 404);
    if (appSettings.is_public !== "true" && !isAdmin) return json({ error: "Unauthorized" }, 401);
    if (!isAdmin && !(await hasPublicAccess(request, env, appSettings))) return json({ error: "Public password required", requires_public_password: true }, 401);
    return json(isAdmin || appSettings.public_hide_sensitive !== "true" ? row : await maskSensitive(row));
  }

  if (route === "settings" && method === "POST") {
    if (!(await requireAdmin(request, env))) return json({ error: "Unauthorized" }, 401);
    const body = await readJson(request);
    const allowed = new Set(Object.keys(DEFAULT_SETTINGS));
    for (const [key, value] of Object.entries(body.settings || {})) {
      if (key === "public_password") {
        const raw = String(value || "");
        const nextHash = raw ? await sha256(raw) : "";
        await env.DB.prepare("INSERT INTO probe_settings (key, value) VALUES ('public_password_hash', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
          .bind(nextHash).run();
      } else if (allowed.has(key) && key !== "public_password_hash") {
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
      `SELECT s.ip, s.name, s.created_at, s.last_report, p.server_group, p.price, p.expire_date, p.bandwidth, p.traffic_limit, p.is_hidden, p.silence_until, p.notes, p.renew_notice_sent, p.is_pinned, p.agent_version, p.node_icon, p.node_color, p.console_url, p.port_checks, p.ssl_domains, p.ssh_user, p.ssh_port
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

  if (route === "servers/batch" && method === "POST") {
    if (!(await requireAdmin(request, env))) return json({ error: "Unauthorized" }, 401);
    const body = await readJson(request, 64 * 1024);
    const lines = String(body.text || "").split(/\r?\n/).map(line => line.trim()).filter(Boolean).slice(0, 100);
    const created = [];
    for (const line of lines) {
      if (/^ip[,，]/i.test(line)) continue;
      const parts = line.includes(",") || line.includes("，") ? line.split(/[,，]/).map(item => item.trim()) : line.split(/\s+/).filter(Boolean);
      const ip = clean(parts[0] || "", 64);
      if (!validIp(ip)) continue;
      const name = clean(parts[1] || ip, 120);
      const group = clean(parts[2] || "默认分组", 120);
      const price = clean(parts[3] || "", 80);
      const expireDate = clean(parts[4] || "", 80);
      const bandwidth = clean(parts[5] || "", 80);
      const trafficLimit = clean(parts[6] || "", 80);
      const existing = await env.DB.prepare("SELECT agent_token FROM servers WHERE ip = ?").bind(ip).first();
      const agentToken = existing?.agent_token || await token();
      const now = Date.now();
      await env.DB.prepare(
        "INSERT INTO servers (ip, name, agent_token, created_at, last_report) VALUES (?, ?, ?, ?, 0) ON CONFLICT(ip) DO UPDATE SET name = excluded.name"
      ).bind(ip, name, agentToken, now).run();
      await env.DB.prepare(
        `INSERT INTO probe_servers (id, name, country, ip_v4, server_group, price, expire_date, bandwidth, traffic_limit, is_hidden)
         VALUES (?, ?, 'XX', ?, ?, ?, ?, ?, ?, 'false')
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, server_group = excluded.server_group,
           price = excluded.price, expire_date = excluded.expire_date, bandwidth = excluded.bandwidth, traffic_limit = excluded.traffic_limit`
      ).bind(ip, name, ip.includes(":") ? "" : ip, group, price, expireDate, bandwidth, trafficLimit).run();
      created.push({ ip, name, group, install_command: installCommand(url.origin, ip, agentToken) });
    }
    ctx.waitUntil(broadcastSnapshot(env));
    return json({ success: true, created, uninstall_command: uninstallCommand() });
  }

  if (route === "servers/bulk" && method === "POST") {
    if (!(await requireAdmin(request, env))) return json({ error: "Unauthorized" }, 401);
    const body = await readJson(request);
    const ips = Array.isArray(body.ips) ? body.ips.map(ip => clean(ip, 64)).filter(validIp).slice(0, 200) : [];
    if (!ips.length) return json({ error: "请选择节点" }, 400);
    const placeholders = ips.map(() => "?").join(",");
    const action = clean(body.action, 40);
    if (action === "silence") {
      const hours = Math.max(1, Math.min(168, Number(body.hours || 1)));
      await env.DB.prepare(`UPDATE probe_servers SET silence_until = ? WHERE id IN (${placeholders})`)
        .bind(String(Date.now() + hours * 3600000), ...ips).run();
    } else if (action === "unsilence") {
      await env.DB.prepare(`UPDATE probe_servers SET silence_until = '0' WHERE id IN (${placeholders})`).bind(...ips).run();
    } else if (action === "hide") {
      await env.DB.prepare(`UPDATE probe_servers SET is_hidden = 'true' WHERE id IN (${placeholders})`).bind(...ips).run();
    } else if (action === "show") {
      await env.DB.prepare(`UPDATE probe_servers SET is_hidden = 'false' WHERE id IN (${placeholders})`).bind(...ips).run();
    } else if (action === "group") {
      await env.DB.prepare(`UPDATE probe_servers SET server_group = ? WHERE id IN (${placeholders})`)
        .bind(clean(body.server_group || "默认分组", 120), ...ips).run();
    } else {
      return json({ error: "不支持的批量操作" }, 400);
    }
    ctx.waitUntil(broadcastSnapshot(env));
    return json({ success: true, count: ips.length });
  }

  if (route === "servers" && method === "PUT") {
    if (!(await requireAdmin(request, env))) return json({ error: "Unauthorized" }, 401);
    const body = await readJson(request);
    const ip = clean(body.ip, 64);
    if (!validIp(ip)) return json({ error: "IP 格式不正确" }, 400);
    const exists = await env.DB.prepare("SELECT ip FROM servers WHERE ip = ?").bind(ip).first();
    if (!exists) return json({ error: "Server not found" }, 404);
    const name = clean(body.name || ip, 120);
    const requestedSilence = Number(body.silence_until || 0);
    const silenceUntil = Number.isFinite(requestedSilence) ? Math.max(0, requestedSilence) : 0;
    await env.DB.prepare("UPDATE servers SET name = ? WHERE ip = ?").bind(name, ip).run();
    await env.DB.prepare(
      `UPDATE probe_servers SET name=?, server_group=?, price=?, expire_date=?, bandwidth=?, traffic_limit=?, is_hidden=?, silence_until=?, notes=?, is_pinned=?, node_icon=?, node_color=?, console_url=?, port_checks=?, ssl_domains=?, ssh_user=?, ssh_port=? WHERE id=?`
    ).bind(
      name,
      clean(body.server_group || "默认分组", 120),
      clean(body.price || "", 80),
      clean(body.expire_date || "", 80),
      clean(body.bandwidth || "", 80),
      clean(body.traffic_limit || "", 80),
      body.is_hidden === "true" || body.is_hidden === true ? "true" : "false",
      String(silenceUntil),
      clean(body.notes || "", 2000),
      body.is_pinned === "true" || body.is_pinned === true ? "true" : "false",
      clean(body.node_icon || "", 20),
      clean(body.node_color || "", 30),
      cleanUrl(body.console_url || ""),
      clean(body.port_checks || "", 200),
      clean(body.ssl_domains || "", 500),
      clean(body.ssh_user || "", 80),
      clean(body.ssh_port || "22", 12),
      ip
    ).run();
    ctx.waitUntil(broadcastSnapshot(env));
    return json({ success: true });
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
    return json({
      command: installCommand(url.origin, ip, row.agent_token),
      reinstall_command: installCommand(url.origin, ip, row.agent_token),
      upgrade_command: installCommand(url.origin, ip, row.agent_token),
      uninstall_command: uninstallCommand()
    });
  }

  if (route === "webhook/test" && method === "POST") {
    if (!(await requireAdmin(request, env))) return json({ error: "Unauthorized" }, 401);
    await sendWebhook(env, "探针全景大盘测试通知", { name: "Webhook 测试", issues: ["通知通道可用"] });
    return json({ success: true });
  }

  if (route === "config" && method === "GET") {
    const ip = url.searchParams.get("ip") || "";
    if (!(await verifyAgent(request, env, ip))) return text("Unauthorized", 401);
    const appSettings = await settings(env.DB);
    const row = await env.DB.prepare("SELECT port_checks, ssl_domains FROM probe_servers WHERE id = ?").bind(ip).first();
    return json({
      success: true,
      interval: Math.max(15, Number(appSettings.report_interval) || 60),
      ping_targets: appSettings.ping_targets || "",
      port_checks: row?.port_checks || "",
      ssl_domains: row?.ssl_domains || ""
    });
  }

  if (route === "report" && method === "POST") {
    const body = await readJson(request, 256 * 1024);
    const ip = clean(body.ip, 64);
    if (!(await verifyAgent(request, env, ip))) return text("Unauthorized", 401);
    const now = Date.now();
    const existing = await env.DB.prepare("SELECT last_rx, last_tx, monthly_rx, monthly_tx, history, silence_until, sla_log, event_log, traffic_limit, traffic_notice_sent, traffic_month, ssl_notice_sent FROM probe_servers WHERE id = ?").bind(ip).first();
    const rx = Number(body.net_rx || 0);
    const tx = Number(body.net_tx || 0);
    const lastRx = Number(existing?.last_rx || 0);
    const lastTx = Number(existing?.last_tx || 0);
    const monthKey = new Date(now).toISOString().slice(0, 7);
    const baseMonthlyRx = existing?.traffic_month === monthKey ? Number(existing?.monthly_rx || 0) : 0;
    const baseMonthlyTx = existing?.traffic_month === monthKey ? Number(existing?.monthly_tx || 0) : 0;
    const monthlyRx = baseMonthlyRx + (rx >= lastRx ? rx - lastRx : rx);
    const monthlyTx = baseMonthlyTx + (tx >= lastTx ? tx - lastTx : tx);
    const history = nextHistory(existing?.history, body, now);
    const country = clean(body.country || request.cf?.country || "XX", 8);
    const appSettings = await settings(env.DB);
    const previousServer = await env.DB.prepare("SELECT name, alert_sent FROM servers WHERE ip = ?").bind(ip).first();
    const nextProbe = { ...body, last_updated: now, silence_until: existing?.silence_until || "0" };
    const issues = issueState(nextProbe, appSettings, now);
    const slaLog = nextSlaLog(existing?.sla_log, now, !issues.includes("离线"));
    const eventLog = nextEventLog(existing?.event_log, previousServer?.alert_sent, issues, now);
    await env.DB.prepare("UPDATE servers SET last_report = ?, alert_sent = ? WHERE ip = ?")
      .bind(now, issues.length ? 2 : 0, ip).run();
    await env.DB.prepare(
      `UPDATE probe_servers SET
        cpu=?, ram=?, disk=?, load_avg=?, uptime=?, last_updated=?, ram_total=?, ram_used=?,
        swap_total=?, swap_used=?, disk_total=?, disk_used=?, net_rx=?, net_tx=?, net_in_speed=?,
        net_out_speed=?, os=?, cpu_info=?, arch=?, boot_time=?, processes=?, tcp_conn=?, udp_conn=?,
        country=?, ip_v4=?, ip_v6=?, monthly_rx=?, monthly_tx=?, last_rx=?, last_tx=?, history=?, virt=?, sla_log=?, event_log=?, agent_version=?, traffic_month=?, ping_result=?, port_result=?, ssl_result=?
       WHERE id=?`
    ).bind(
      clean(body.cpu, 20), clean(body.mem, 20), clean(body.disk, 20), clean(body.load, 80), clean(body.uptime, 80), now,
      clean(body.ram_total, 40), clean(body.ram_used, 40), clean(body.swap_total, 40), clean(body.swap_used, 40),
      clean(body.disk_total, 40), clean(body.disk_used, 40), String(rx), String(tx), clean(body.net_in_speed, 40),
      clean(body.net_out_speed, 40), clean(body.os, 120), clean(body.cpu_info, 240), clean(body.arch, 40),
      clean(body.boot_time, 80), clean(body.processes, 40), clean(body.tcp_conn, 40), clean(body.udp_conn, 40),
      country, clean(body.ip_v4, 64), clean(body.ip_v6, 128), String(monthlyRx), String(monthlyTx), String(rx),
      String(tx), JSON.stringify(history), clean(body.virt, 80), JSON.stringify(slaLog), JSON.stringify(eventLog),
      clean(body.agent_version || body.version || "", 40), monthKey,
      clean(JSON.stringify(body.ping_result || {}), 5000), clean(JSON.stringify(body.port_result || {}), 5000),
      clean(JSON.stringify(body.ssl_result || {}), 5000), ip
    ).run();
    if (issues.length && Number(previousServer?.alert_sent || 0) !== 2) {
      const level = alertLevel(issues);
      ctx.waitUntil(sendWebhook(env, `探针${level}告警`, { ip, name: previousServer?.name || ip, level, issues }));
    }
    if (!issues.length && Number(previousServer?.alert_sent || 0) > 0 && appSettings.recovery_notice === "true") {
      ctx.waitUntil(sendWebhook(env, "探针恢复通知", { ip, name: previousServer?.name || ip, issues: ["已恢复正常"] }));
    }
    ctx.waitUntil(checkTrafficUsage(env, appSettings, ip, previousServer?.name || ip, existing?.traffic_limit, monthlyRx + monthlyTx, existing?.traffic_notice_sent));
    ctx.waitUntil(checkSslUsage(env, appSettings, ip, previousServer?.name || ip, body.ssl_result || {}, existing?.ssl_notice_sent));
    ctx.waitUntil(broadcastSnapshot(env));
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

function nextSlaLog(raw, now, online) {
  let log = [];
  try { log = JSON.parse(raw || "[]"); } catch {}
  if (Array.isArray(log) && now - Number(log.at(-1)?.t || 0) < 5 * 60 * 1000) return log;
  log = Array.isArray(log) ? log : [];
  log.push({ t: now, on: online ? 1 : 0 });
  return log.filter(item => now - Number(item.t || 0) <= 8 * 24 * 60 * 60 * 1000).slice(-2304);
}

function nextEventLog(raw, previousAlertSent, issues, now) {
  let log = [];
  try { log = JSON.parse(raw || "[]"); } catch {}
  log = Array.isArray(log) ? log : [];
  const hadAlert = Number(previousAlertSent || 0) > 0;
  if (issues.length && !hadAlert) log.push({ t: now, type: "异常", text: issues.join("、") });
  if (!issues.length && hadAlert) log.push({ t: now, type: "恢复", text: "节点恢复正常" });
  return log.slice(-80);
}

function parseBytesLimit(value) {
  const text = String(value || "").trim().toLowerCase();
  const match = text.match(/([\d.]+)\s*(pb|tb|gb|mb|kb|p|t|g|m|k)?/i);
  if (!match) return 0;
  const units = { k: 1024, kb: 1024, m: 1024 ** 2, mb: 1024 ** 2, g: 1024 ** 3, gb: 1024 ** 3, t: 1024 ** 4, tb: 1024 ** 4, p: 1024 ** 5, pb: 1024 ** 5 };
  return Number(match[1] || 0) * (units[match[2] || "gb"] || 1);
}

async function checkTrafficUsage(env, appSettings, ip, name, limitText, usedBytes, noticeSent) {
  const limit = parseBytesLimit(limitText);
  const percent = Math.max(1, Number(appSettings.traffic_notice_percent || 80));
  const monthKey = new Date().toISOString().slice(0, 7);
  if (!limit || usedBytes / limit * 100 < percent || noticeSent === monthKey) return;
  await sendWebhook(env, "VPS 流量预警", {
    ip,
    name,
    limit: limitText,
    used_percent: Math.round(usedBytes / limit * 1000) / 10,
    issues: ["流量接近上限"]
  });
  await env.DB.prepare("UPDATE probe_servers SET traffic_notice_sent = ? WHERE id = ?").bind(monthKey, ip).run();
}

async function checkSslUsage(env, appSettings, ip, name, sslResult, noticeSent) {
  const days = Math.max(0, Number(appSettings.ssl_notice_days || 0));
  if (!days || !sslResult || typeof sslResult !== "object") return;
  const sent = new Set(String(noticeSent || "").split(",").filter(Boolean));
  for (const [domain, info] of Object.entries(sslResult)) {
    if (!info?.ok) continue;
    const left = Number(info.days_left);
    const key = `${domain}:${info.expires_date || left}`;
    if (left >= 0 && left <= days && !sent.has(key)) {
      await sendWebhook(env, "SSL 证书到期提醒", { ip, name, domain, days_left: left, issues: ["证书即将到期"] });
      sent.add(key);
    }
  }
  await env.DB.prepare("UPDATE probe_servers SET ssl_notice_sent = ? WHERE id = ?").bind([...sent].slice(-50).join(","), ip).run();
}

function installCommand(origin, ip, agentToken) {
  return `bash <(curl -fsSL ${origin}/vps/install.sh) '${origin}' '${ip}' '${agentToken}'`;
}

function uninstallCommand() {
  return "systemctl disable --now probe-panorama-agent 2>/dev/null || true; rm -f /etc/systemd/system/probe-panorama-agent.service; systemctl daemon-reload 2>/dev/null || true; rm -rf /opt/probe-panorama";
}

async function checkOffline(env) {
  await ensureDbSchema(env.DB);
  const appSettings = await settings(env.DB);
  const now = Date.now();
  if (inMaintenance(appSettings, now)) {
    await checkRenewals(env, appSettings, now);
    await broadcastSnapshot(env);
    return;
  }
  const cutoff = now - Math.max(1, Number(appSettings.offline_minutes || 6)) * 60 * 1000;
  const { results } = await env.DB.prepare(
    `SELECT s.ip, s.name, p.silence_until, p.sla_log, p.event_log
     FROM servers s LEFT JOIN probe_servers p ON p.id = s.ip
     WHERE s.last_report > 0 AND s.last_report < ? AND s.alert_sent != 1`
  ).bind(cutoff).all();
  for (const server of results || []) {
    if (Number(server.silence_until || 0) > now) continue;
    await sendWebhook(env, "探针离线告警", { ip: server.ip, name: server.name, issues: ["离线"] });
    const slaLog = nextSlaLog(server.sla_log, now, false);
    const eventLog = nextEventLog(server.event_log, 0, ["离线"], now);
    await env.DB.prepare("UPDATE probe_servers SET sla_log = ?, event_log = ? WHERE id = ?")
      .bind(JSON.stringify(slaLog), JSON.stringify(eventLog), server.ip).run();
  }
  await env.DB.prepare(
    `UPDATE servers SET alert_sent = 1
     WHERE last_report > 0 AND last_report < ?
       AND ip IN (SELECT id FROM probe_servers WHERE CAST(silence_until AS INTEGER) <= ? OR silence_until IS NULL)`
  ).bind(cutoff, now).run();
  await checkRenewals(env, appSettings, now);
  await broadcastSnapshot(env);
}

async function checkRenewals(env, appSettings, now) {
  const days = Math.max(0, Number(appSettings.renew_notice_days || 0));
  if (!days) return;
  const limit = now + days * 24 * 60 * 60 * 1000;
  const { results } = await env.DB.prepare(
    "SELECT id, name, expire_date, renew_notice_sent FROM probe_servers WHERE expire_date != '' AND is_hidden != 'true'"
  ).all();
  for (const server of results || []) {
    const expireAt = Date.parse(`${server.expire_date}T00:00:00+08:00`);
    if (!Number.isFinite(expireAt) || expireAt < now || expireAt > limit || server.renew_notice_sent === server.expire_date) continue;
    await sendWebhook(env, "VPS 续费提醒", {
      ip: server.id,
      name: server.name || server.id,
      expire_date: server.expire_date,
      days_left: Math.ceil((expireAt - now) / 86400000),
      issues: ["即将到期"]
    });
    await env.DB.prepare("UPDATE probe_servers SET renew_notice_sent = ? WHERE id = ?").bind(server.expire_date, server.id).run();
  }
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
      await ensureDbSchema(env.DB);
      const appSettings = await settings(env.DB);
      if (appSettings.is_public !== "true" && !(await currentUser(request, env))) return json({ error: "Unauthorized" }, 401);
      if (!(await hasPublicAccess(request, env, appSettings))) return json({ error: "Public password required" }, 401);
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
