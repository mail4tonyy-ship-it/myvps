// ==========================================
// MyVps Server Monitor 后端
// (包含：自动建表升级 + VPS 探针管理 + 实时状态 + 动态云端测速/主题)
// ==========================================

async function sha256(text) {
    const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacHex(secret, message) {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
    return Array.from(new Uint8Array(signature), byte => byte.toString(16).padStart(2, '0')).join('');
}

function bytesEqual(left, right) { if (left.length !== right.length) return false; let diff = 0; for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i]; return diff === 0; }
function base64Bytes(bytes) { let output = ''; for (const byte of bytes) output += String.fromCharCode(byte); return btoa(output); }
function decodeBase64Bytes(value) { const binary = atob(value); return Uint8Array.from(binary, char => char.charCodeAt(0)); }
async function passwordHash(password, salt = crypto.getRandomValues(new Uint8Array(16)), iterations = 210000) { const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']); const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256); return `pbkdf2$${iterations}$${base64Bytes(salt)}$${base64Bytes(new Uint8Array(bits))}`; }
async function passwordMatches(password, stored) { try { if (/^[0-9a-f]{64}$/i.test(stored || '')) return bytesEqual(new TextEncoder().encode(await sha256(password)), new TextEncoder().encode(stored.toLowerCase())); const [kind, rawIterations, rawSalt, rawHash] = String(stored || '').split('$'); if (kind !== 'pbkdf2') return false; const iterations = Number(rawIterations); if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 1000000) return false; const salt = decodeBase64Bytes(rawSalt); const expected = decodeBase64Bytes(rawHash); const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']); const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, expected.byteLength * 8); return bytesEqual(new Uint8Array(bits), expected); } catch { return false; } }
async function sessionToken() { const bytes = crypto.getRandomValues(new Uint8Array(32)); return base64Bytes(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, ''); }

function updateManifest(component, sha, length) { return `v1\n${component}\n${sha}\n${length}\n`; }

const MAX_REPORT_BYTES = 256 * 1024;
const MAX_NODE_DELTA_BYTES = 1024 * 1024 * 1024 * 1024;
const MAX_REPORT_DELTA_BYTES = MAX_NODE_DELTA_BYTES * 10;

async function readJsonBody(request, maxBytes) {
    const declared = Number(request.headers.get('Content-Length') || 0);
    if (declared && (!Number.isSafeInteger(declared) || declared > maxBytes)) throw new Error('Request body too large');
    const reader = request.body?.getReader();
    if (!reader) return {};
    const chunks = []; let size = 0;
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) { await reader.cancel(); throw new Error('Request body too large'); }
        chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('JSON object required');
    return parsed;
}

function validIp(value) { return typeof value === 'string' && /^[0-9A-Fa-f:.]{2,64}$/.test(value); }

function validateTrafficReport(data) {
    if (!validIp(data.ip) || typeof data.report_id !== 'string' || data.report_id.length > 160 || !data.report_id.startsWith(`${data.ip}:`)) throw new Error('Invalid report identity');
    const entries = data.node_traffic === undefined ? [] : data.node_traffic;
    if (!Array.isArray(entries) || entries.length > 200) throw new Error('Invalid traffic entries');
    const ids = new Set(); let total = 0;
    for (const entry of entries) {
        if (!entry || !/^[A-Za-z0-9_-]{1,64}$/.test(entry.id || '') || !Number.isSafeInteger(entry.delta_bytes) || entry.delta_bytes <= 0 || entry.delta_bytes > MAX_NODE_DELTA_BYTES || ids.has(entry.id)) throw new Error('Invalid traffic entry');
        ids.add(entry.id); total += entry.delta_bytes;
        if (!Number.isSafeInteger(total) || total > MAX_REPORT_DELTA_BYTES) throw new Error('Traffic report exceeds limit');
    }
    return { ...data, node_traffic: entries, total_delta: total };
}

async function realtimeAdminHeader(env) {
    if (!env.ADMIN_PASSWORD) return null;
    const username = env.ADMIN_USERNAME || 'admin';
    const timestamp = Date.now().toString();
    const keyHex = await sha256(env.ADMIN_PASSWORD);
    const keyBytes = new Uint8Array(keyHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const nonce = crypto.randomUUID();
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${username}\n${timestamp}\n${nonce}\nPOST\n/api/realtime_auth`));
    const signatureHex = Array.from(new Uint8Array(signature), byte => byte.toString(16).padStart(2, '0')).join('');
    return `${btoa(username)}.${timestamp}.${nonce}.${signatureHex}`;
}

async function notifyRealtimePublicPolicy(env, db, enabled, pagesOrigin = '') {
    const authorization = await realtimeAdminHeader(env);
    if (!authorization) return;
    const configured = env.REALTIME_URL || (await db.prepare("SELECT val FROM sys_config WHERE key = 'realtime_url'").first())?.val;
    if (!configured || !/^https:\/\//i.test(configured)) return;
    await fetch(`${configured.replace(/\/$/, '')}/public-policy`, {
        method: 'POST',
        headers: { Authorization: authorization, 'Content-Type': 'application/json', 'X-MyVps-Pages-Origin': pagesOrigin },
        body: JSON.stringify({ public: enabled }),
    });
}

function realtimeFrequencyPolicy(settings = {}) {
    const admin = Number(settings.realtime_admin_interval || 5);
    const publicInterval = Number(settings.realtime_public_interval || 10);
    const idle = Number(settings.realtime_idle_interval || 30);
    if (!Number.isInteger(admin) || !Number.isInteger(publicInterval) || !Number.isInteger(idle) || admin < 5 || admin > 60 || publicInterval < 10 || publicInterval > 120 || idle < 30 || idle > 600 || publicInterval < admin || idle < publicInterval) return null;
    return { admin, public: publicInterval, idle };
}

async function notifyRealtimeFrequencyPolicy(env, db, settings, pagesOrigin = '') {
    const policy = realtimeFrequencyPolicy(settings);
    const authorization = await realtimeAdminHeader(env);
    const configured = env.REALTIME_URL || (await db.prepare("SELECT val FROM sys_config WHERE key = 'realtime_url'").first())?.val;
    if (!policy || !authorization || !configured || !/^https:\/\//i.test(configured)) return;
    await fetch(`${configured.replace(/\/$/, '')}/frequency-policy`, {
        method: 'POST',
        headers: { Authorization: authorization, 'Content-Type': 'application/json', 'X-MyVps-Pages-Origin': pagesOrigin },
        body: JSON.stringify(policy),
    });
}

async function notifyRealtimeVps(env, db, ip, pagesOrigin = '') {
    const authorization = await realtimeAdminHeader(env);
    const configured = env.REALTIME_URL || (await db.prepare("SELECT val FROM sys_config WHERE key = 'realtime_url'").first())?.val;
    if (!authorization || !configured || !/^https:\/\//i.test(configured)) return;
    await fetch(`${configured.replace(/\/$/, '')}/notify`, { method: 'POST', headers: { Authorization: authorization, 'Content-Type': 'application/json', 'X-MyVps-Pages-Origin': pagesOrigin }, body: JSON.stringify({ ip }) });
}

async function chunkBatch(db, statements, size = 100) {
    for (let i = 0; i < statements.length; i += size) {
        await db.batch(statements.slice(i, i + size));
    }
}

function yamlString(value) {
    return `"${String(value ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\r?\n/g, '\\n')}"`;
}

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

let schemaReadyPromise = null;
let lastReceiptCleanup = 0;

function loginThrottleKey(request) { return `${request.headers.get('CF-Connecting-IP') || 'unknown'}:${String(request.headers.get('Authorization') || '').split('.')[0].slice(0, 128)}`; }

async function loginAllowed(db, request) {
    const row = await db.prepare('SELECT failures, window_started_at, blocked_until FROM login_throttles WHERE key = ?').bind(loginThrottleKey(request)).first();
    return !row || Number(row.blocked_until || 0) <= Date.now();
}

async function recordLoginFailure(db, request) {
    const key = loginThrottleKey(request); const now = Date.now();
    const row = await db.prepare('SELECT failures, window_started_at FROM login_throttles WHERE key = ?').bind(key).first();
    const freshWindow = !row || now - Number(row.window_started_at || 0) > 15 * 60 * 1000;
    const failures = freshWindow ? 1 : Number(row.failures || 0) + 1;
    const blockedUntil = failures >= 8 ? now + 15 * 60 * 1000 : 0;
    await db.prepare('INSERT INTO login_throttles (key, failures, window_started_at, blocked_until) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET failures = excluded.failures, window_started_at = excluded.window_started_at, blocked_until = excluded.blocked_until').bind(key, failures, freshWindow ? now : row.window_started_at, blockedUntil).run();
}

async function initializeDbSchema(db) {
    const initQueries = [
        `CREATE TABLE IF NOT EXISTS servers (ip TEXT PRIMARY KEY, name TEXT NOT NULL, cpu INTEGER DEFAULT 0, mem REAL DEFAULT 0, last_report INTEGER DEFAULT 0, alert_sent INTEGER DEFAULT 0, disk INTEGER DEFAULT 0, load TEXT DEFAULT "", uptime TEXT DEFAULT "", net_in_speed INTEGER DEFAULT 0, net_out_speed INTEGER DEFAULT 0, tcp_conn INTEGER DEFAULT 0, udp_conn INTEGER DEFAULT 0)`,
        `CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL, traffic_limit INTEGER DEFAULT 0, traffic_used INTEGER DEFAULT 0, expire_time INTEGER DEFAULT 0, enable INTEGER DEFAULT 1, sub_token TEXT)`,
                `CREATE TABLE IF NOT EXISTS traffic_stats (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, delta_bytes INTEGER DEFAULT 0, timestamp INTEGER NOT NULL, FOREIGN KEY(ip) REFERENCES servers(ip) ON DELETE CASCADE)`,
        `CREATE INDEX IF NOT EXISTS idx_traffic_ip_time ON traffic_stats(ip, timestamp)`,
        `CREATE TABLE IF NOT EXISTS sys_config (key TEXT PRIMARY KEY, val TEXT, ts INTEGER)`,
                `CREATE TABLE IF NOT EXISTS server_logs (ip TEXT PRIMARY KEY, logs TEXT, updated_at INTEGER)`,
                `CREATE TABLE IF NOT EXISTS report_receipts (report_id TEXT PRIMARY KEY, vps_ip TEXT NOT NULL, created_at INTEGER NOT NULL, applied INTEGER DEFAULT 1)`,
        `CREATE TABLE IF NOT EXISTS auth_replays (nonce TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL)`,
        `CREATE TABLE IF NOT EXISTS login_throttles (key TEXT PRIMARY KEY, failures INTEGER NOT NULL, window_started_at INTEGER NOT NULL, blocked_until INTEGER NOT NULL DEFAULT 0)`,
        `CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL)`
    ];
    for (let query of initQueries) { try { await db.prepare(query).run(); } catch (e) {} }

    const probeQueries = [
        `CREATE TABLE IF NOT EXISTS probe_settings (key TEXT PRIMARY KEY, value TEXT)`,
        `CREATE TABLE IF NOT EXISTS probe_servers (
            id TEXT PRIMARY KEY, name TEXT, cpu TEXT, ram TEXT, disk TEXT, load_avg TEXT, uptime TEXT, last_updated INTEGER,
            ram_total TEXT, net_rx TEXT, net_tx TEXT, net_in_speed TEXT, net_out_speed TEXT,
            os TEXT, cpu_info TEXT, arch TEXT, boot_time TEXT, ram_used TEXT, swap_total TEXT, 
            swap_used TEXT, disk_total TEXT, disk_used TEXT, processes TEXT, tcp_conn TEXT, udp_conn TEXT, 
            country TEXT, ip_v4 TEXT, ip_v6 TEXT, server_group TEXT DEFAULT '默认分组', price TEXT DEFAULT '', 
            expire_date TEXT DEFAULT '', bandwidth TEXT DEFAULT '', traffic_limit TEXT DEFAULT '', agent_os TEXT DEFAULT 'debian',
            ping_ct TEXT DEFAULT '0', ping_cu TEXT DEFAULT '0', ping_cm TEXT DEFAULT '0', ping_bd TEXT DEFAULT '0',
            monthly_rx TEXT DEFAULT '0', monthly_tx TEXT DEFAULT '0', last_rx TEXT DEFAULT '0', last_tx TEXT DEFAULT '0', 
            reset_month TEXT DEFAULT '', history TEXT DEFAULT '{}', is_hidden TEXT DEFAULT 'false', virt TEXT DEFAULT '',             reset_day TEXT DEFAULT '1'
        )`,
        ];
    for (let query of probeQueries) { try { await db.prepare(query).run(); } catch (e) {} }

    try { await db.prepare("SELECT disk FROM servers LIMIT 1").first(); } catch (e) { const newCols = ['disk INTEGER DEFAULT 0', 'load TEXT DEFAULT ""', 'uptime TEXT DEFAULT ""', 'net_in_speed INTEGER DEFAULT 0', 'net_out_speed INTEGER DEFAULT 0', 'tcp_conn INTEGER DEFAULT 0', 'udp_conn INTEGER DEFAULT 0']; for (let col of newCols) { try { await db.prepare(`ALTER TABLE servers ADD COLUMN ${col}`).run(); } catch(err){} } }
    try { await db.prepare("SELECT sub_token FROM users LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE users ADD COLUMN sub_token TEXT").run(); } catch(err){} }
    try {
        const { results: usersWithoutToken } = await db.prepare("SELECT username FROM users WHERE sub_token IS NULL OR sub_token = '' LIMIT 100").all();
        if (usersWithoutToken && usersWithoutToken.length) await db.batch(usersWithoutToken.map(user => db.prepare("UPDATE users SET sub_token = ? WHERE username = ? AND (sub_token IS NULL OR sub_token = '')").bind(crypto.randomUUID(), user.username)));
    } catch (error) {}
    try { await db.prepare("SELECT reset_day FROM probe_servers LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE probe_servers ADD COLUMN reset_day TEXT DEFAULT '1'").run(); } catch(e){} }
    try { await db.prepare("SELECT agent_token FROM servers LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE servers ADD COLUMN agent_token TEXT").run(); } catch(err){} }
    try { await db.prepare("SELECT last_report_id FROM probe_servers LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE probe_servers ADD COLUMN last_report_id TEXT DEFAULT ''").run(); } catch(err){} }
    try { await db.prepare("SELECT applied FROM report_receipts LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE report_receipts ADD COLUMN applied INTEGER DEFAULT 1").run(); } catch(err){} }
    const probeServerColumns = [
        ['cpu', "TEXT DEFAULT '0'"], ['ram', "TEXT DEFAULT '0'"], ['disk', "TEXT DEFAULT '0'"], ['load_avg', "TEXT DEFAULT '0'"], ['uptime', "TEXT DEFAULT ''"], ['last_updated', 'INTEGER DEFAULT 0'],
        ['ram_total', "TEXT DEFAULT '0'"], ['net_rx', "TEXT DEFAULT '0'"], ['net_tx', "TEXT DEFAULT '0'"], ['net_in_speed', "TEXT DEFAULT '0'"], ['net_out_speed', "TEXT DEFAULT '0'"],
        ['os', "TEXT DEFAULT ''"], ['cpu_info', "TEXT DEFAULT ''"], ['arch', "TEXT DEFAULT ''"], ['boot_time', "TEXT DEFAULT ''"], ['ram_used', "TEXT DEFAULT '0'"],
        ['swap_total', "TEXT DEFAULT '0'"], ['swap_used', "TEXT DEFAULT '0'"], ['disk_total', "TEXT DEFAULT '0'"], ['disk_used', "TEXT DEFAULT '0'"], ['processes', "TEXT DEFAULT '0'"],
        ['tcp_conn', "TEXT DEFAULT '0'"], ['udp_conn', "TEXT DEFAULT '0'"], ['country', "TEXT DEFAULT 'XX'"], ['ip_v4', "TEXT DEFAULT '1'"], ['ip_v6', "TEXT DEFAULT '0'"],
        ['server_group', "TEXT DEFAULT '默认分组'"], ['price', "TEXT DEFAULT '免费'"], ['expire_date', "TEXT DEFAULT ''"], ['bandwidth', "TEXT DEFAULT ''"], ['traffic_limit', "TEXT DEFAULT ''"],
        ['agent_os', "TEXT DEFAULT 'debian'"], ['ping_ct', "TEXT DEFAULT '0'"], ['ping_cu', "TEXT DEFAULT '0'"], ['ping_cm', "TEXT DEFAULT '0'"], ['ping_bd', "TEXT DEFAULT '0'"],
        ['monthly_rx', "TEXT DEFAULT '0'"], ['monthly_tx', "TEXT DEFAULT '0'"], ['last_rx', "TEXT DEFAULT '0'"], ['last_tx', "TEXT DEFAULT '0'"], ['reset_month', "TEXT DEFAULT ''"],
        ['history', "TEXT DEFAULT '{}'"], ['is_hidden', "TEXT DEFAULT 'false'"], ['virt', "TEXT DEFAULT ''"], ['reset_day', "TEXT DEFAULT '1'"], ['last_report_id', "TEXT DEFAULT ''"],
    ];
    for (const [name, definition] of probeServerColumns) {
        try { await db.prepare(`SELECT ${name} FROM probe_servers LIMIT 1`).first(); }
        catch (e) { try { await db.prepare(`ALTER TABLE probe_servers ADD COLUMN ${name} ${definition}`).run(); } catch(err){} }
    }

    // 初始化云端测速数据
    const checkNodes = await db.prepare("SELECT value FROM probe_settings WHERE key = 'cached_nodes_data'").first();
    if (!checkNodes) {
        try {
            const res = await fetch('https://raw.githubusercontent.com/a63414262/CF-Server-Monitor-Pro/refs/heads/main/nodes.json');
            if (res.ok) {
                const dataText = await res.text();
                await db.prepare("INSERT INTO probe_settings (key, value) VALUES ('cached_nodes_data', ?)").bind(dataText).run();
            }
        } catch(e) {}
    }
}

async function ensureDbSchema(db) {
    if (!schemaReadyPromise) {
        schemaReadyPromise = initializeDbSchema(db).catch(error => {
            schemaReadyPromise = null;
            throw error;
        });
    }
    return schemaReadyPromise;
}

async function ensureProbePlaceholder(db, ip, name, country = 'XX') {
    const safeName = String(name || ip || 'Unnamed').trim().slice(0, 100) || String(ip);
    const safeCountry = String(country || 'XX').toUpperCase() === 'TW' ? 'CN' : String(country || 'XX').toUpperCase().slice(0, 2);
    await db.prepare(`
        INSERT INTO probe_servers (
            id, name, cpu, ram, disk, load_avg, uptime, last_updated,
            ram_total, net_rx, net_tx, net_in_speed, net_out_speed,
            os, cpu_info, arch, boot_time, ram_used, swap_total, swap_used,
            disk_total, disk_used, processes, tcp_conn, udp_conn,
            country, ip_v4, ip_v6, server_group, price, expire_date,
            bandwidth, traffic_limit, ping_ct, ping_cu, ping_cm, ping_bd,
            monthly_rx, monthly_tx, last_rx, last_tx, reset_month,
            agent_os, history, is_hidden, virt, reset_day
        ) VALUES (
            ?, ?, '0', '0', '0', '0', '等待 Agent 上报', 0,
            '0', '0', '0', '0', '0',
            '待接入', '', '', '', '0', '0', '0',
            '0', '0', '0', '0', '0',
            ?, '1', '0', '默认分组', '免费', '',
            '', '', '0', '0', '0', '0',
            '0', '0', '0', '0', '',
            'debian', '{}', 'false', '', '1'
        )
        ON CONFLICT(id) DO UPDATE SET name = excluded.name
    `).bind(ip, safeName, safeCountry).run();
}

async function verifyAuth(authHeader, request, db, env, context) {
    try {
        if (!authHeader || !env.ADMIN_PASSWORD) return null;
        if (authHeader.startsWith('Bearer ')) {
            const token = authHeader.slice(7);
            if (!/^[A-Za-z0-9_-]{32,128}$/.test(token)) return null;
            const tokenHash = await sha256(token);
            const session = await db.prepare('SELECT username FROM auth_sessions WHERE token_hash = ? AND expires_at > ?').bind(tokenHash, Date.now()).first();
            return session?.username || null;
        }
        const adminUser = env.ADMIN_USERNAME || "admin";
        const adminPass = env.ADMIN_PASSWORD;
        const parts = authHeader.split('.');
        if (parts.length !== 4) return null;
        const [b64User, timestamp, nonce, clientSig] = parts;
        const timestampNumber = Number(timestamp);
        if (!Number.isFinite(timestampNumber) || Math.abs(Date.now() - timestampNumber) > 120000 || !/^[0-9a-f-]{36}$/i.test(nonce)) return null;
        const username = atob(b64User);
        let baseKeyHex;
        if (username === adminUser) baseKeyHex = await sha256(adminPass);
        else return null;
        const keyBytes = new Uint8Array(baseKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const url = new URL(request.url);
        const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${username}\n${timestamp}\n${nonce}\n${request.method}\n${url.pathname}`));
        const expectedSig = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
        if (clientSig !== expectedSig) return null;
        const receipt = await db.prepare('INSERT OR IGNORE INTO auth_replays (nonce, username, expires_at) VALUES (?, ?, ?)').bind(nonce, username, Date.now() + 180000).run();
        if (Number(receipt.meta?.changes || 0) !== 1) return null;
        context?.waitUntil(db.prepare('DELETE FROM auth_replays WHERE expires_at < ?').bind(Date.now()).run().catch(() => {}));
        return username;
    } catch (error) {
        return null;
    }
}

async function verifyAgent(authHeader, ip, db, env) {
    if (!authHeader) return false;
    if (ip) {
        const server = await db.prepare("SELECT agent_token FROM servers WHERE ip = ?").bind(ip).first();
        if (server && server.agent_token && authHeader === server.agent_token) return true;
    }
    return false;
}

// ==============================================
// 探针纯净 API 子系统处理
// ==============================================
async function handleProbeAPI(request, env, context, pathArray) {
    const subPath = pathArray ? pathArray.join('/') : '';
    const url = new URL(request.url);
    const method = request.method;
    const db = env.DB;

    // Telegram Bot 交互回调控制
    if (method === 'POST' && subPath === 'tg_webhook') {
        try {
            const webhookSecret = env.TG_WEBHOOK_SECRET || '';
            if (!webhookSecret || request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== webhookSecret) return new Response('Unauthorized', { status: 401 });
            const body = await request.json();
            const message = body.message; const callback_query = body.callback_query;
            let tgBotToken = ''; let tgChatId = '';
            try { const { results } = await db.prepare("SELECT key, value FROM probe_settings WHERE key IN ('tg_bot_token', 'tg_chat_id')").all(); results.forEach(r => { if(r.key === 'tg_bot_token') tgBotToken = r.value; if(r.key === 'tg_chat_id') tgChatId = r.value; }); } catch(e){}
            
            const tgSend = async (chatId, text, kb=null) => { const p = { chat_id: chatId, text, parse_mode: 'HTML' }; if (kb) p.reply_markup = kb; await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(p)}); };
            const tgEdit = async (chatId, msgId, text, kb=null) => { const p = { chat_id: chatId, message_id: msgId, text, parse_mode: 'HTML' }; if (kb) p.reply_markup = kb; await fetch(`https://api.telegram.org/bot${tgBotToken}/editMessageText`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(p)}); };

            let chatId, text, msgId;
            if (message) { chatId = message.chat.id.toString(); text = message.text || ''; msgId = message.message_id; } 
            else if (callback_query) { chatId = callback_query.message.chat.id.toString(); text = callback_query.data; msgId = callback_query.message.message_id; }
            if (chatId !== tgChatId) return new Response('OK', { status: 200 });

            const mainMenuText = `🖥 <b>MyVps 探针管理</b>\n\n您可以使用命令快速设置系统：\n<code>/set_interval 10</code> - 上报间隔10秒\n<code>/set_sitetitle 新标题</code> - 更改大盘标题\n<code>/menu</code> - 调出本菜单`;
            const mainMenuKb = { inline_keyboard: [ [{text: '📋 服务器列表', callback_data: 'cb_list_nodes'}], [{text: '⚙️ 系统设置快捷开关', callback_data: 'cb_settings'}] ] };
            
            if (callback_query) {
                if (text === 'cb_menu') await tgEdit(chatId, msgId, mainMenuText, mainMenuKb);
                else if (text === 'cb_list_nodes') {
                    const { results } = await db.prepare('SELECT id, name, last_updated FROM probe_servers WHERE is_hidden != "true"').all();
                    let kb = { inline_keyboard: [] };
                    for (const s of results) { kb.inline_keyboard.push([{text: `${s.name}`, callback_data: `cb_node_${s.id}`}]); }
                    kb.inline_keyboard.push([{text: '🔙 返回', callback_data: 'cb_menu'}]);
                    await tgEdit(chatId, msgId, '📋 <b>当前服务器：</b>', kb);
                }
                else if (text.startsWith('cb_node_')) {
                    const id = text.split('_')[2]; const s = await db.prepare('SELECT * FROM probe_servers WHERE id = ?').bind(id).first();
                    if (s) await tgEdit(chatId, msgId, `🖥 <b>探针详情:</b> ${escapeHtml(s.name)}\n\n系统: ${escapeHtml(s.os||'-')}\nIP类型: IPv4:${escapeHtml(s.ip_v4)} / IPv6:${escapeHtml(s.ip_v6)}\n运行时长: ${escapeHtml(s.uptime)}\n分组: ${escapeHtml(s.server_group)}`, {inline_keyboard: [[{text: '🔙 返回列表', callback_data: 'cb_list_nodes'}]]});
                }
                else if (text === 'cb_settings') {
                    let set = { is_public: 'true', show_price: 'true' }; try { const { results } = await db.prepare("SELECT key, value FROM probe_settings").all(); results.forEach(r => set[r.key]=r.value); } catch(e){}
                    const kb = { inline_keyboard: [
                        [{text: `${set.is_public === 'true' ? '✅' : '❌'} 公开大盘`, callback_data: 'cb_tog_is_public'}, {text: `${set.show_price === 'true' ? '✅' : '❌'} 显示价格`, callback_data: 'cb_tog_show_price'}],
                        [{text: '🔙 返回主菜单', callback_data: 'cb_menu'}]
                    ]};
                    await tgEdit(chatId, msgId, '⚙️ <b>点击切换探针前台展示状态</b>', kb);
                }
                else if (text.startsWith('cb_tog_')) {
                    const key = text.replace('cb_tog_', '');
                    let cur = 'true'; try { const r = await db.prepare('SELECT value FROM probe_settings WHERE key=?').bind(key).first(); if(r) cur = r.value; } catch(e){}
                    const next = cur === 'true' ? 'false' : 'true';
                    await db.prepare('INSERT INTO probe_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(key, next).run();
                    if (key === 'is_public') await notifyRealtimePublicPolicy(env, db, next === 'true', url.origin).catch(() => {});
                    await tgSend(chatId, `✅ 属性 ${key} 已成功切换！`);
                }
            }
            if (message) {
                const cmdParts = text.trim().split(/\s+/); const cmd = cmdParts[0].toLowerCase();
                if (cmd === '/start' || cmd === '/menu') await tgSend(chatId, mainMenuText, mainMenuKb);
                else if (cmd === '/set_interval' && cmdParts[1]) { await db.prepare('INSERT INTO probe_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind('report_interval', cmdParts[1]).run(); await tgSend(chatId, `✅ 上报间隔设为 ${cmdParts[1]} 秒`); }
                else if (cmd === '/set_sitetitle') { await db.prepare('INSERT INTO probe_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind('site_title', text.replace(cmdParts[0], '').trim()).run(); await tgSend(chatId, '✅ 大盘标题已更新'); }
            }
            return new Response('OK', { status: 200 });
        } catch(e) { return new Response('Webhook Error', {status:200}); }
    }

    if (method === 'GET' && subPath === 'public') {
        const isAjax = url.searchParams.get('ajax') === '1';
        const authHeader = request.headers.get("Authorization");
        const isLoggedIn = await verifyAuth(authHeader, request, db, env, context);
        const cacheKey = new Request(`${url.origin}/api/probe/public?ajax=${isAjax ? '1' : '0'}`);
        const cached = null;
        if (cached) return cached;
        const settings = { theme: 'theme1', is_public: 'true', site_title: 'MyVps', show_price: 'true', show_expire: 'true', show_bw: 'true', show_tf: 'true', custom_css: '', custom_bg: '', custom_head: '', custom_script: '', report_interval: '5', enable_popup: 'false', popup_content: '', cached_nodes_data: '' };
        try { const { results } = await db.prepare('SELECT * FROM probe_settings').all(); if (results) results.forEach(r => settings[r.key] = r.value); } catch(e){}
        if (settings.site_title === 'Server Monitor Pro') {
            settings.site_title = 'MyVps';
            await db.prepare('INSERT INTO probe_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind('site_title', 'MyVps').run();
        }
        if (settings.is_public !== 'true' && !isLoggedIn) return Response.json({ error: "Private Dashboard" }, { status: 401 });
        const servers = (await db.prepare(`
            SELECT
                s.ip AS id,
                COALESCE(p.name, s.name) AS name,
                COALESCE(p.cpu, s.cpu, '0') AS cpu,
                COALESCE(p.ram, s.mem, '0') AS ram,
                COALESCE(p.disk, s.disk, '0') AS disk,
                COALESCE(p.load_avg, s.load, '0') AS load_avg,
                COALESCE(p.uptime, s.uptime, '等待 Agent 上报') AS uptime,
                COALESCE(p.last_updated, s.last_report, 0) AS last_updated,
                COALESCE(p.net_in_speed, s.net_in_speed, '0') AS net_in_speed,
                COALESCE(p.net_out_speed, s.net_out_speed, '0') AS net_out_speed,
                COALESCE(p.os, '待接入') AS os,
                COALESCE(p.arch, '') AS arch,
                COALESCE(p.virt, '') AS virt,
                COALESCE(p.tcp_conn, s.tcp_conn, '0') AS tcp_conn,
                COALESCE(p.udp_conn, s.udp_conn, '0') AS udp_conn,
                COALESCE(p.country, 'XX') AS country,
                COALESCE(p.ip_v4, '1') AS ip_v4,
                COALESCE(p.ip_v6, '0') AS ip_v6,
                COALESCE(p.server_group, '默认分组') AS server_group,
                COALESCE(p.price, '免费') AS price,
                COALESCE(p.expire_date, '') AS expire_date,
                COALESCE(p.bandwidth, '') AS bandwidth,
                COALESCE(p.traffic_limit, '') AS traffic_limit,
                COALESCE(p.ping_ct, '0') AS ping_ct,
                COALESCE(p.ping_cu, '0') AS ping_cu,
                COALESCE(p.ping_cm, '0') AS ping_cm,
                COALESCE(p.ping_bd, '0') AS ping_bd,
                COALESCE(p.monthly_rx, '0') AS monthly_rx,
                COALESCE(p.monthly_tx, '0') AS monthly_tx,
                COALESCE(p.net_rx, '0') AS net_rx,
                COALESCE(p.net_tx, '0') AS net_tx,
                COALESCE(p.cpu_info, '') AS cpu_info,
                COALESCE(p.boot_time, '') AS boot_time,
                COALESCE(p.ram_used, '0') AS ram_used,
                COALESCE(p.ram_total, '0') AS ram_total,
                COALESCE(p.disk_used, '0') AS disk_used,
                COALESCE(p.disk_total, '0') AS disk_total,
                COALESCE(p.swap_used, '0') AS swap_used,
                COALESCE(p.swap_total, '0') AS swap_total,
                COALESCE(p.processes, '0') AS processes
            FROM servers s
            LEFT JOIN probe_servers p ON p.id = s.ip
            WHERE COALESCE(p.is_hidden, 'false') != 'true'
            ORDER BY s.name COLLATE NOCASE ASC
        `).all()).results;
        const publicKeys = new Set(['theme', 'is_public', 'site_title', 'show_price', 'show_expire', 'show_bw', 'show_tf', 'custom_css', 'custom_bg', 'custom_head', 'custom_script', 'report_interval', 'enable_popup', 'popup_content', 'cached_nodes_data', 'auto_reset_traffic', 'visits_total', 'visits_today', 'visits_date']);
        for (const key of Object.keys(settings)) if (!publicKeys.has(key)) delete settings[key];
        const realtime = env.REALTIME_URL ? null : await db.prepare("SELECT val FROM sys_config WHERE key = 'realtime_url'").first();
        const response = Response.json({ settings, servers, realtime_url: env.REALTIME_URL || realtime?.val || '' }, { headers: { 'Cache-Control': 'no-store' } });
        return response;
    }

    if (method === 'GET' && subPath === 'detail') {
        const id = url.searchParams.get('id');
        let server = await db.prepare('SELECT * FROM probe_servers WHERE id = ?').bind(id).first();
        if (!server) {
            const base = await db.prepare('SELECT * FROM servers WHERE ip = ?').bind(id).first();
            if (base) {
                server = {
                    id: base.ip,
                    name: base.name,
                    cpu: base.cpu || 0,
                    ram: base.mem || 0,
                    disk: base.disk || 0,
                    load_avg: base.load || '0',
                    uptime: base.uptime || '等待 Agent 上报',
                    last_updated: base.last_report || 0,
                    net_in_speed: base.net_in_speed || 0,
                    net_out_speed: base.net_out_speed || 0,
                    tcp_conn: base.tcp_conn || 0,
                    udp_conn: base.udp_conn || 0,
                    net_rx: '0',
                    net_tx: '0',
                    cpu_info: '',
                    boot_time: '',
                    arch: '',
                    os: '待接入',
                    virt: '',
                    ram_used: '0',
                    ram_total: '0',
                    swap_used: '0',
                    swap_total: '0',
                    disk_used: '0',
                    disk_total: '0',
                    processes: '0',
                    country: 'XX',
                    ip_v4: '1',
                    ip_v6: '0',
                    server_group: '默认分组',
                    price: '免费',
                    expire_date: '',
                    bandwidth: '',
                    traffic_limit: '',
                    ping_ct: '0',
                    ping_cu: '0',
                    ping_cm: '0',
                    ping_bd: '0',
                    history: '{}',
                    is_hidden: 'false',
                };
            }
        }
        if (!server || server.is_hidden === 'true') return Response.json({ error: "Not found" }, { status: 404 });
        const publicSetting = await db.prepare("SELECT value FROM probe_settings WHERE key = 'is_public'").first();
        if (publicSetting && publicSetting.value !== 'true' && !(await verifyAuth(request.headers.get('Authorization'), request, db, env, context))) return Response.json({ error: "Unauthorized" }, { status: 401 });
        return Response.json(server);
    }

    const probeUser = await verifyAuth(request.headers.get("Authorization"), request, db, env, context);
    if (!probeUser) return Response.json({error: "Unauthorized"}, {status: 401});
    if (subPath.startsWith('admin/') && probeUser !== (env.ADMIN_USERNAME || 'admin')) return Response.json({error: "Forbidden"}, {status: 403});

    // 🌟 GitHub 云端拉取三网节点库
    if (method === 'POST' && subPath === 'admin/pull_github') {
        try {
            const res = await fetch('https://raw.githubusercontent.com/a63414262/CF-Server-Monitor-Pro/refs/heads/main/nodes.json');
            if (res.ok) {
                const dataText = await res.text();
                await db.prepare("INSERT INTO probe_settings (key, value) VALUES ('cached_nodes_data', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(dataText).run();
                return Response.json({ success: true });
            }
            return Response.json({ error: 'Fetch failed' }, { status: 400 });
        } catch (e) { return Response.json({ error: e.message }, { status: 400 }); }
    }

    if (method === 'GET' && subPath === 'admin/data') {
        const settings = {};
        try { const { results } = await db.prepare('SELECT * FROM probe_settings').all(); if (results) results.forEach(r => settings[r.key] = r.value); } catch(e){}
        if (settings.site_title === 'Server Monitor Pro') {
            settings.site_title = 'MyVps';
            await db.prepare('INSERT INTO probe_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind('site_title', 'MyVps').run();
        }
        const servers = (await db.prepare(`
            SELECT
                s.ip AS id,
                COALESCE(p.name, s.name) AS name,
                COALESCE(p.last_updated, s.last_report, 0) AS last_updated,
                COALESCE(p.server_group, '默认分组') AS server_group,
                COALESCE(p.price, '免费') AS price,
                COALESCE(p.expire_date, '') AS expire_date,
                COALESCE(p.bandwidth, '') AS bandwidth,
                COALESCE(p.traffic_limit, '') AS traffic_limit,
                COALESCE(p.agent_os, 'debian') AS agent_os,
                COALESCE(p.is_hidden, 'false') AS is_hidden,
                COALESCE(p.reset_day, '1') AS reset_day
            FROM servers s
            LEFT JOIN probe_servers p ON p.id = s.ip
            ORDER BY s.name COLLATE NOCASE ASC
        `).all()).results;
        return Response.json({ settings, servers });
    }
    
    if (method === 'POST' && subPath === 'admin/settings') {
        const { settings } = await readJsonBody(request, 64 * 1024);
        if (!settings || typeof settings !== 'object' || Array.isArray(settings) || Object.keys(settings).length > 80) return Response.json({ error: 'Invalid settings' }, { status: 400 });
        const frequencyKeys = ['realtime_admin_interval', 'realtime_public_interval', 'realtime_idle_interval'];
        let frequencySettings = settings;
        if (frequencyKeys.some(key => Object.prototype.hasOwnProperty.call(settings, key))) {
            const { results } = await db.prepare("SELECT key, value FROM probe_settings WHERE key IN ('realtime_admin_interval', 'realtime_public_interval', 'realtime_idle_interval')").all();
            frequencySettings = { ...Object.fromEntries((results || []).map(row => [row.key, row.value])), ...settings };
            if (!realtimeFrequencyPolicy(frequencySettings)) return Response.json({ error: 'Invalid realtime frequency policy' }, { status: 400 });
        }
        for (const [k, v] of Object.entries(settings)) { await db.prepare('INSERT INTO probe_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(k, v).run(); }
        if (Object.prototype.hasOwnProperty.call(settings, 'is_public')) await notifyRealtimePublicPolicy(env, db, settings.is_public === 'true', url.origin).catch(() => {});
        if (frequencyKeys.some(key => Object.prototype.hasOwnProperty.call(settings, key))) await notifyRealtimeFrequencyPolicy(env, db, frequencySettings, url.origin).catch(() => {});
        if (settings.tg_bot_token) {
            try {
               await fetch(`https://api.telegram.org/bot${settings.tg_bot_token}/setWebhook`, {
                  method: 'POST', headers: {'Content-Type': 'application/json'},
                   body: JSON.stringify({ url: `${url.origin}/api/probe/tg_webhook`, ...(env.TG_WEBHOOK_SECRET ? { secret_token: env.TG_WEBHOOK_SECRET } : {}) })
               });
            } catch(e) {}
        }
        return Response.json({ success: true });
    }

    if (method === 'PUT' && subPath === 'admin/server') {
        const data = await readJsonBody(request, 16 * 1024);
        await ensureProbePlaceholder(db, data.id, data.name || data.id, request.cf?.country || 'XX');
        await db.prepare(`UPDATE probe_servers SET name=?, server_group=?, price=?, expire_date=?, bandwidth=?, traffic_limit=?, agent_os=?, is_hidden=?, reset_day=? WHERE id=?`).bind(data.name || 'Unnamed', data.server_group || '默认分组', data.price || '', data.expire_date || '', data.bandwidth || '', data.traffic_limit || '', data.agent_os || 'debian', data.is_hidden || 'false', data.reset_day || '1', data.id).run();
        return Response.json({ success: true });
    }
    
    if (method === 'DELETE' && subPath === 'admin/server') {
        const id = url.searchParams.get('id');
        await db.prepare('DELETE FROM probe_servers WHERE id = ?').bind(id).run();
        return Response.json({ success: true });
    }

    return Response.json({error: "Not Found"}, {status: 404});
}

export async function onRequest(context) {
    const { request, env, params } = context;
    const method = request.method;
    const action = params.path ? params.path[0] : ''; 
    const db = env.DB; 

    // 防御：未绑定 D1 数据库时直接返回清晰错误，避免 Cloudflare 1101 (Worker threw exception)
    if (!env || !env.DB) {
        return new Response(JSON.stringify({ error: "D1 binding 'DB' is not configured in Cloudflare Pages. Please bind a D1 database (variable name DB) and redeploy." }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }

    if (action === "probe") {
        await ensureDbSchema(db);
        return await handleProbeAPI(request, env, context, params.path.slice(1));
    }

    if (action === "ui_ping" && method === "POST") {
        if (!(await verifyAuth(request.headers.get("Authorization"), request, db, env, context))) return new Response("Unauthorized", { status: 401 });
        const now = Date.now();
        const current = await db.prepare("SELECT ts FROM sys_config WHERE key = 'ui_active'").first();
        if (!current || now - current.ts > 45000) await db.prepare("INSERT OR REPLACE INTO sys_config (key, val, ts) VALUES ('ui_active', '1', ?)").bind(now).run();
        return Response.json({ success: true });
    }

    if (action === "cron_check" && method === "POST") {
        if (!env.CRON_SECRET || request.headers.get('Authorization') !== `Bearer ${env.CRON_SECRET}`) return new Response('Unauthorized', { status: 401 });
        await ensureDbSchema(db);
        return Response.json({ success: true, alerted: await checkOfflineServers(env) });
    }

    if (action === "agent_update" && method === "GET") {
        const ip = new URL(request.url).searchParams.get('ip');
        if (!(await verifyAgent(request.headers.get('Authorization'), ip, db, env))) return new Response('Unauthorized', { status: 401 });
        if (!env.ASSETS) return Response.json({ error: 'ASSETS binding is unavailable' }, { status: 503 });
        const component = new URL(request.url).searchParams.get('component') || 'agent';
        const assets = { agent: '/vps/agent.py', 'realtime-client': '/vps/realtime_client.py', 'full-installer': '/vps/myvps.sh' };
        if (!assets[component]) return Response.json({ error: 'Unknown agent component' }, { status: 400 });
        const assetUrl = new URL(assets[component], request.url);
        const asset = await env.ASSETS.fetch(assetUrl);
        if (!asset.ok) return new Response('Agent asset not found', { status: 404 });
        const source = await asset.arrayBuffer();
        const digest = await crypto.subtle.digest('SHA-256', source);
        const sha256 = Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('');
        const server = await db.prepare('SELECT agent_token FROM servers WHERE ip = ?').bind(ip).first();
        if (!server?.agent_token) return new Response('Agent token unavailable', { status: 503 });
        const manifest = updateManifest(component, sha256, source.byteLength);
        const mac = await hmacHex(server.agent_token, manifest);
        const contentType = component.endsWith('installer') ? 'text/x-shellscript; charset=utf-8' : 'text/x-python; charset=utf-8';
        return new Response(source, { headers: { 'Content-Type': contentType, 'Cache-Control': 'no-store', 'X-Agent-SHA256': sha256, 'X-Agent-Manifest-Version': '1', 'X-Agent-Length': String(source.byteLength), 'X-Agent-MAC': mac } });
    }

    // 🌟 Agent 统一探针与管理上报接口 (融入全新的 Reset Day 计算和动态云端测速节点)
    if (action === "report" && method === "POST") {
     try {
        await ensureDbSchema(db);
        const data = validateTrafficReport(await readJsonBody(request, MAX_REPORT_BYTES));
        const nowMs = Date.now();
        const vpsIp = data.ip;
        const authHeader = request.headers.get("Authorization");
        if (!(await verifyAgent(authHeader, vpsIp, db, env))) return new Response("Unauthorized", { status: 401 });
        if (!data.report_id) return Response.json({ error: "report_id is required" }, { status: 400 });
        const duplicateReport = !!(await db.prepare("SELECT report_id FROM report_receipts WHERE report_id = ? AND applied = 1").bind(data.report_id).first());

        const myvpsServer = await db.prepare('SELECT name FROM servers WHERE ip = ?').bind(vpsIp).first();
        if (!myvpsServer) {
            return Response.json({ error: "Server has been removed from MyVps panel." }, { status: 403 });
        }
        const serverName = myvpsServer.name;

        try { 
            await db.prepare("UPDATE servers SET cpu=?, mem=?, disk=?, load=?, uptime=?, net_in_speed=?, net_out_speed=?, tcp_conn=?, udp_conn=?, last_report=?, alert_sent=0 WHERE ip=?")
                    .bind(data.cpu||0, data.mem||0, data.disk||0, data.load||'', data.uptime||'', data.net_in_speed||0, data.net_out_speed||0, data.tcp_conn||0, data.udp_conn||0, nowMs, vpsIp).run(); 
        } catch (e) { 
            await ensureDbSchema(db); 
            await db.prepare("UPDATE servers SET cpu=?, mem=?, disk=?, load=?, uptime=?, net_in_speed=?, net_out_speed=?, tcp_conn=?, udp_conn=?, last_report=?, alert_sent=0 WHERE ip=?")
                    .bind(data.cpu||0, data.mem||0, data.disk||0, data.load||'', data.uptime||'', data.net_in_speed||0, data.net_out_speed||0, data.tcp_conn||0, data.udp_conn||0, nowMs, vpsIp).run(); 
        }

        try {
            let countryCode = request.cf && request.cf.country ? request.cf.country : 'XX'; 
            if (countryCode.toUpperCase() === 'TW') countryCode = 'CN';

            const probeServer = await db.prepare('SELECT * FROM probe_servers WHERE id = ?').bind(vpsIp).first();
            
            // --- 全新核心：基于动态 reset_day 的流量生命周期重置 ---
            const localNow = new Date(nowMs + 8 * 60 * 60000); 
            let y = localNow.getFullYear();
            let m = localNow.getMonth() + 1;
            let d = localNow.getDate();
            
            let resetDayVal = probeServer ? parseInt(probeServer.reset_day) || 1 : 1;
            if (resetDayVal < 1) resetDayVal = 1; if (resetDayVal > 31) resetDayVal = 31;
            
            let maxDaysThisMonth = new Date(y, m, 0).getDate();
            let actualResetDayThisMonth = Math.min(resetDayVal, maxDaysThisMonth);
            
            let currentCycleStr = '';
            if (d < actualResetDayThisMonth) {
                let pm = m - 1; let py = y;
                if (pm === 0) { pm = 12; py -= 1; }
                let maxDaysPrevMonth = new Date(py, pm, 0).getDate();
                let actualResetDayPrevMonth = Math.min(resetDayVal, maxDaysPrevMonth);
                currentCycleStr = `${py}-${pm}-${actualResetDayPrevMonth}`;
            } else {
                currentCycleStr = `${y}-${m}-${actualResetDayThisMonth}`;
            }

            let monthly_rx = 0, monthly_tx = 0, last_rx = 0, last_tx = 0;
            let reset_month = currentCycleStr;
            let history = {};

            if (!probeServer) {
                await db.prepare(`INSERT INTO probe_servers (id, name, cpu, ram, disk, load_avg, uptime, last_updated, ram_total, net_rx, net_tx, net_in_speed, net_out_speed, os, cpu_info, arch, boot_time, ram_used, swap_total, swap_used, disk_total, disk_used, processes, tcp_conn, udp_conn, country, ip_v4, ip_v6, server_group, price, expire_date, bandwidth, traffic_limit, ping_ct, ping_cu, ping_cm, ping_bd, monthly_rx, monthly_tx, last_rx, last_tx, reset_month, agent_os, history, is_hidden, virt, reset_day) VALUES (?, ?, '0', '0', '0', '0', '0', 0, '0', '0', '0', '0', '0', '', '', '', '', '0', '0', '0', '0', '0', '0', '0', '0', ?, '1', '0', '默认分组', '免费', '', '', '', '0', '0', '0', '0', '0', '0', '0', '0', ?, 'debian', '{}', 'false', '', '1')`).bind(vpsIp, serverName, countryCode, currentCycleStr).run();
            } else {
                monthly_rx = parseFloat(probeServer.monthly_rx || '0'); monthly_tx = parseFloat(probeServer.monthly_tx || '0');
                last_rx = parseFloat(probeServer.last_rx || '0'); last_tx = parseFloat(probeServer.last_tx || '0');
                reset_month = probeServer.reset_month || currentCycleStr;
                
                let autoReset = 'false';
                try { const r = await db.prepare("SELECT value FROM probe_settings WHERE key = 'auto_reset_traffic'").first(); if (r) autoReset = r.value; } catch(e){}
                // 周期变动立即清零结算
                if (autoReset === 'true' && currentCycleStr !== reset_month) { monthly_rx = 0; monthly_tx = 0; reset_month = currentCycleStr; }
                try { history = JSON.parse(probeServer.history || '{}'); } catch(e) {}
            }

            const current_rx = parseFloat(data.net_rx || '0'); const current_tx = parseFloat(data.net_tx || '0');
            const probeAlreadyApplied = probeServer && probeServer.last_report_id === data.report_id;
            if (!duplicateReport && !probeAlreadyApplied) {
                if (current_rx >= last_rx) monthly_rx += (current_rx - last_rx); else monthly_rx += current_rx;
                if (current_tx >= last_tx) monthly_tx += (current_tx - last_tx); else monthly_tx += current_tx;
                last_rx = current_rx; last_tx = current_tx;
            }

            const lastHistTime = history.last_time || 0;
            if (nowMs - lastHistTime >= 300000 || !history.time) {
                const maxPoints = 288; 
                const updateArr = (arr, val) => { if (!Array.isArray(arr)) arr = []; arr.push(val); if (arr.length > maxPoints) arr.shift(); return arr; };
                const updateLabels = (arr) => { if (!Array.isArray(arr)) arr = []; const d = new Date(nowMs + 8 * 60 * 60000); arr.push(d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0')); if (arr.length > maxPoints) arr.shift(); return arr; };
                history.cpu = updateArr(history.cpu, parseFloat(data.cpu) || 0); history.ram = updateArr(history.ram, parseFloat(data.mem) || 0); history.proc = updateArr(history.proc, parseInt(data.processes) || 0); 
                history.net_in = updateArr(history.net_in, parseFloat(data.net_in_speed) || 0); history.net_out = updateArr(history.net_out, parseFloat(data.net_out_speed) || 0); 
                history.tcp = updateArr(history.tcp, parseInt(data.tcp_conn) || 0); history.udp = updateArr(history.udp, parseInt(data.udp_conn) || 0); 
                history.ping_ct = updateArr(history.ping_ct, parseInt(data.ping_ct) || 0); history.ping_cu = updateArr(history.ping_cu, parseInt(data.ping_cu) || 0); history.ping_cm = updateArr(history.ping_cm, parseInt(data.ping_cm) || 0); history.ping_bd = updateArr(history.ping_bd, parseInt(data.ping_bd) || 0); 
                history.time = updateLabels(history.time); history.last_time = nowMs;
            }

            await db.prepare(`UPDATE probe_servers SET cpu=?, ram=?, disk=?, load_avg=?, uptime=?, last_updated=?, ram_total=?, net_rx=?, net_tx=?, net_in_speed=?, net_out_speed=?, os=?, cpu_info=?, arch=?, boot_time=?, ram_used=?, swap_total=?, swap_used=?, disk_total=?, disk_used=?, processes=?, tcp_conn=?, udp_conn=?, ping_ct=?, ping_cu=?, ping_cm=?, ping_bd=?, monthly_rx=CASE WHEN last_report_id=? THEN monthly_rx ELSE ? END, monthly_tx=CASE WHEN last_report_id=? THEN monthly_tx ELSE ? END, last_rx=CASE WHEN last_report_id=? THEN last_rx ELSE ? END, last_tx=CASE WHEN last_report_id=? THEN last_tx ELSE ? END, reset_month=?, history=?, virt=?, last_report_id=? WHERE id=?`)
                    .bind(data.cpu||0, data.mem||0, data.disk||0, data.load||'', data.uptime||'', nowMs, data.ram_total||'0', data.net_rx||'0', data.net_tx||'0', data.net_in_speed||0, data.net_out_speed||0, data.os||'', data.cpu_info||'', data.arch||'', data.boot_time||'', data.ram_used||'0', data.swap_total||'0', data.swap_used||'0', data.disk_total||'0', data.disk_used||'0', data.processes||'0', data.tcp_conn||0, data.udp_conn||0, data.ping_ct||'0', data.ping_cu||'0', data.ping_cm||'0', data.ping_bd||'0', data.report_id, monthly_rx.toString(), data.report_id, monthly_tx.toString(), data.report_id, last_rx.toString(), data.report_id, last_tx.toString(), reset_month, JSON.stringify(history), data.virt||'', data.report_id, vpsIp).run();

        } catch (e) { console.error("探针数据同步失败:", e); }

        const stmts = []; let totalDelta = 0;
        if (!duplicateReport) stmts.push(db.prepare("INSERT OR IGNORE INTO report_receipts (report_id, vps_ip, created_at, applied) VALUES (?, ?, ?, 0)").bind(data.report_id, vpsIp, nowMs));
        if (!duplicateReport && totalDelta > 0) stmts.push(db.prepare("INSERT INTO traffic_stats (ip, delta_bytes, timestamp) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM report_receipts WHERE report_id = ? AND applied = 0)").bind(vpsIp, totalDelta, nowMs, data.report_id));
        if (!duplicateReport) stmts.push(db.prepare("UPDATE report_receipts SET applied = 1 WHERE report_id = ? AND applied = 0").bind(data.report_id));
        if (stmts.length > 0) {
            await db.batch(stmts);
        }
        if (nowMs - lastReceiptCleanup > 3600000) {
            lastReceiptCleanup = nowMs;
            context.waitUntil(db.prepare("DELETE FROM report_receipts WHERE created_at < ?").bind(nowMs - 604800000).run().catch(() => {}));
        }
        
        let fastMode = false; try { const uiActive = await db.prepare("SELECT ts FROM sys_config WHERE key = 'ui_active'").first(); if (uiActive && (nowMs - uiActive.ts < 90000)) fastMode = true; } catch(e) {}
        
        let reportInterval = 5; let pingCt = 'default'; let pingCu = 'default'; let pingCm = 'default'; let pingBd = 'default';
        try { 
            const { results } = await db.prepare("SELECT key, value FROM probe_settings WHERE key IN ('report_interval', 'ping_node_ct', 'ping_node_cu', 'ping_node_cm', 'ping_node_bd')").all(); 
            if (results) {
                results.forEach(r => {
                    if (r.key === 'report_interval') reportInterval = parseInt(r.value) || 5;
                    if (r.key === 'ping_node_ct') pingCt = r.value;
                    if (r.key === 'ping_node_cu') pingCu = r.value;
                    if (r.key === 'ping_node_cm') pingCm = r.value;
                    if (r.key === 'ping_node_bd') pingBd = r.value;
                });
            }
        } catch(e) {}
        
        const effectiveInterval = Math.min(300, fastMode ? Math.max(15, reportInterval) : Math.max(90, reportInterval));
        return Response.json({ success: true, fast_mode: fastMode, interval: effectiveInterval, ping_ct: pingCt, ping_cu: pingCu, ping_cm: pingCm, ping_bd: pingBd });
     } catch (err) {
        return Response.json({ error: "REPORT_ERR: " + (err && err.message ? err.message : String(err)) }, { status: 500 });
     }
    }

    if (action === "config" && method === "GET") {
        await ensureDbSchema(db);
        const ip = new URL(request.url).searchParams.get("ip"); const now = Date.now(); const adminUser = env.ADMIN_USERNAME || "admin";
        const authHeader = request.headers.get("Authorization");
        const currentUser = await verifyAuth(authHeader, request, db, env, context);
        const agentAuthenticated = await verifyAgent(authHeader, ip, db, env);
        if (currentUser !== adminUser && !agentAuthenticated) return new Response("Unauthorized", { status: 401 });
        const machineNodes = [];
        const serverAuth = await db.prepare("SELECT agent_token FROM servers WHERE ip = ?").bind(ip).first();
        const realtime = await db.prepare("SELECT val FROM sys_config WHERE key = 'realtime_url'").first();
        const policy = { report_interval: '5', ping_ct: 'default', ping_cu: 'default', ping_cm: 'default', ping_bd: 'default' };
        try {
            const { results } = await db.prepare("SELECT key, value FROM probe_settings WHERE key IN ('report_interval', 'ping_node_ct', 'ping_node_cu', 'ping_node_cm', 'ping_node_bd')").all();
            for (const row of results || []) {
                if (row.key === 'report_interval') policy.report_interval = row.value;
                if (row.key === 'ping_node_ct') policy.ping_ct = row.value;
                if (row.key === 'ping_node_cu') policy.ping_cu = row.value;
                if (row.key === 'ping_node_cm') policy.ping_cm = row.value;
                if (row.key === 'ping_node_bd') policy.ping_bd = row.value;
            }
        } catch(e) {}
        return Response.json({ success: true, configs: machineNodes, agent_token: serverAuth && serverAuth.agent_token || '', realtime_url: env.REALTIME_URL || realtime && realtime.val || '', ...policy });
    }
    if (action === "sub") return new Response("Not Found", { status: 404 });

    if (action === "login" && method === "POST") {
        await ensureDbSchema(db);
        if (!env.ADMIN_PASSWORD) return Response.json({ error: "ADMIN_PASSWORD is not configured" }, { status: 500 });
        if (!(await loginAllowed(db, request))) return Response.json({ error: "Too many attempts" }, { status: 429, headers: { 'Retry-After': '900' } });
        let credentials;
        try { credentials = await readJsonBody(request, 8 * 1024); } catch { credentials = {}; }
        const username = String(credentials.username || '').trim(); const password = String(credentials.password || '');
        let valid = false;
        if (username === (env.ADMIN_USERNAME || 'admin')) valid = password.length > 0 && password === env.ADMIN_PASSWORD;
        else { const user = await db.prepare('SELECT password FROM users WHERE username = ? AND enable = 1').bind(username).first(); valid = !!user && await passwordMatches(password, user.password); if (valid && /^[0-9a-f]{64}$/i.test(user.password || '')) await db.prepare('UPDATE users SET password = ? WHERE username = ?').bind(await passwordHash(password), username).run(); }
        if (valid) { const token = await sessionToken(); await db.prepare('INSERT INTO auth_sessions (token_hash, username, expires_at) VALUES (?, ?, ?)').bind(await sha256(token), username, Date.now() + 12 * 60 * 60 * 1000).run(); context.waitUntil(db.prepare('DELETE FROM auth_sessions WHERE expires_at < ?').bind(Date.now()).run().catch(() => {})); await db.prepare('DELETE FROM login_throttles WHERE key = ?').bind(loginThrottleKey(request)).run(); return Response.json({ success: true, token, role: username === (env.ADMIN_USERNAME || "admin") ? 'admin' : 'user' }); }
        await recordLoginFailure(db, request);
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    if (action === "realtime_auth" && method === "POST") {
        await ensureDbSchema(db);
        const username = await verifyAuth(request.headers.get("Authorization"), request, db, env, context);
        const isAdminUser = username === (env.ADMIN_USERNAME || "admin");
        return Response.json({ success: isAdminUser, admin: isAdminUser }, { status: isAdminUser ? 200 : 403, headers: { "Cache-Control": "no-store" } });
    }

    const currentUser = await verifyAuth(request.headers.get("Authorization"), request, db, env, context);
    const isAdmin = currentUser === (env.ADMIN_USERNAME || "admin");
    if (!currentUser) return Response.json({ error: "Unauthorized" }, { status: 401 });

    try {
        if (action === "data") {
            const rawServers = isAdmin
                ? ((await db.prepare("SELECT * FROM servers ORDER BY name COLLATE NOCASE ASC").all()).results || [])
                : ((await db.prepare("SELECT ip, name, cpu, mem, last_report, disk, load, uptime, net_in_speed, net_out_speed, tcp_conn, udp_conn FROM servers ORDER BY name COLLATE NOCASE ASC").all()).results || []);
            const probeRows = (await db.prepare("SELECT * FROM probe_servers").all()).results || [];
            const probeByIp = new Map(probeRows.map(row => [row.id, row]));
            const servers = rawServers.map(server => {
                const probe = probeByIp.get(server.ip) || {};
                return {
                    ...server,
                    name: probe.name || server.name,
                    cpu: probe.cpu ?? server.cpu ?? 0,
                    mem: probe.ram ?? server.mem ?? 0,
                    disk: probe.disk ?? server.disk ?? 0,
                    load: probe.load_avg ?? server.load ?? '',
                    uptime: probe.uptime ?? server.uptime ?? '',
                    last_report: probe.last_updated ?? server.last_report ?? 0,
                    net_in_speed: probe.net_in_speed ?? server.net_in_speed ?? 0,
                    net_out_speed: probe.net_out_speed ?? server.net_out_speed ?? 0,
                    tcp_conn: probe.tcp_conn ?? server.tcp_conn ?? 0,
                    udp_conn: probe.udp_conn ?? server.udp_conn ?? 0,
                    net_rx: probe.net_rx ?? 0,
                    net_tx: probe.net_tx ?? 0,
                    monthly_rx: probe.monthly_rx ?? 0,
                    monthly_tx: probe.monthly_tx ?? 0,
                    os: probe.os || '待接入',
                    arch: probe.arch || '',
                    virt: probe.virt || '',
                    cpu_info: probe.cpu_info || '',
                    boot_time: probe.boot_time || '',
                    ram_used: probe.ram_used ?? 0,
                    ram_total: probe.ram_total ?? 0,
                    swap_used: probe.swap_used ?? 0,
                    swap_total: probe.swap_total ?? 0,
                    disk_used: probe.disk_used ?? 0,
                    disk_total: probe.disk_total ?? 0,
                    processes: probe.processes ?? 0,
                    country: probe.country || 'XX',
                    ping_ct: probe.ping_ct ?? 0,
                    ping_cu: probe.ping_cu ?? 0,
                    ping_cm: probe.ping_cm ?? 0,
                    ping_bd: probe.ping_bd ?? 0,
                    server_group: probe.server_group || '默认分组',
                    price: probe.price || '免费',
                    expire_date: probe.expire_date || '',
                    bandwidth: probe.bandwidth || '',
                    traffic_limit: probe.traffic_limit || '',
                };
            });
            if (isAdmin) {
                for (const server of servers) {
                    if (!server.agent_token) {
                        server.agent_token = crypto.randomUUID();
                        await db.prepare("UPDATE servers SET agent_token = ? WHERE ip = ? AND agent_token IS NULL").bind(server.agent_token, server.ip).run();
                    }
                    await ensureProbePlaceholder(db, server.ip, server.name, request.cf?.country || 'XX');
                }
            }
            const nodes = [];
            const users = isAdmin ? (await db.prepare("SELECT * FROM users").all()).results : (await db.prepare("SELECT * FROM users WHERE username = ?").bind(currentUser).all()).results;
            let siteTitle = "MyVps"; try { const r = await db.prepare("SELECT val FROM sys_config WHERE key='site_title'").first(); if(r && r.val) siteTitle = r.val; } catch(e){}
            let mySubToken = "";
            const realtime = await db.prepare("SELECT val FROM sys_config WHERE key = 'realtime_url'").first();
            return Response.json({ servers, nodes, users, siteTitle, mySubToken, realtimeUrl: env.REALTIME_URL || realtime && realtime.val || '' });
        }
        
        if (action === "settings" && method === "POST" && isAdmin) {
            const { site_title, realtime_url } = await request.json();
            const statements = [];
            if (typeof site_title === 'string' && site_title.trim()) statements.push(db.prepare("INSERT OR REPLACE INTO sys_config (key, val, ts) VALUES ('site_title', ?, ?)").bind(site_title.trim(), Date.now()));
            if (typeof realtime_url === 'string') {
                const normalized = realtime_url.trim().replace(/\/$/, '');
                if (normalized && !/^https:\/\//i.test(normalized)) return Response.json({ error: 'realtime_url must use https' }, { status: 400 });
                statements.push(db.prepare("INSERT OR REPLACE INTO sys_config (key, val, ts) VALUES ('realtime_url', ?, ?)").bind(normalized, Date.now()));
            }
            if (!statements.length) return Response.json({ error: 'No supported settings supplied' }, { status: 400 });
            await db.batch(statements);
            return Response.json({ success: true });
        }
        if (action === "user" && params.path[1] === "password" && method === "PUT") { const { password } = await readJsonBody(request, 8 * 1024); if (isAdmin) return Response.json({error: "管理员密码受绝对安全保护，仅可通过 Cloudflare Pages 环境变量修改！"}, {status: 400}); if (String(password || '').length < 12) return Response.json({ error: 'Password must be at least 12 characters' }, { status: 400 }); await db.prepare("UPDATE users SET password = ? WHERE username = ?").bind(await passwordHash(password), currentUser).run(); return Response.json({ success: true }); }
        if (action === "user" && params.path[1] === "sub_token") return new Response("Not Found", { status: 404 });
        if (action === "stats" && method === "GET" && isAdmin) { const query = `SELECT strftime('%m-%d', datetime(timestamp / 1000, 'unixepoch', 'localtime')) as day, SUM(delta_bytes) as total_bytes FROM traffic_stats WHERE ip = ? AND timestamp > ? GROUP BY day ORDER BY day ASC`; const { results } = await db.prepare(query).bind(new URL(request.url).searchParams.get("ip"), Date.now() - 604800000).all(); return Response.json(results || []); }
        
        if (action === "users" && isAdmin) {
            if (method === "POST") { const { username, password, traffic_limit, expire_time } = await readJsonBody(request, 16 * 1024); const safeUser = String(username || '').trim(); if (!/^[A-Za-z0-9_.-]{1,64}$/.test(safeUser) || safeUser === (env.ADMIN_USERNAME || 'admin')) return Response.json({ error: 'Invalid or reserved username' }, { status: 400 }); if (String(password || '').length < 12) return Response.json({ error: 'Password must be at least 12 characters' }, { status: 400 }); if (await db.prepare("SELECT username FROM users WHERE username = ?").bind(safeUser).first()) return Response.json({ error: "User already exists" }, { status: 409 }); const hash = await passwordHash(password); const subToken = crypto.randomUUID(); await db.prepare("INSERT INTO users (username, password, traffic_limit, expire_time, sub_token) VALUES (?, ?, ?, ?, ?)").bind(safeUser, hash, Math.max(0, Number(traffic_limit)||0), Math.max(0, Number(expire_time)||0), subToken).run(); return Response.json({ success: true }); }
            if (method === "PUT") { const { username, enable, reset_traffic } = await request.json(); const statements = []; if (reset_traffic) statements.push(db.prepare("UPDATE users SET traffic_used = 0 WHERE username = ?").bind(username)); if (enable !== undefined) statements.push(db.prepare("UPDATE users SET enable = ? WHERE username = ?").bind(enable, username)); if (statements.length) await db.batch(statements); return Response.json({ success: true }); }
            if (method === "DELETE") { const target = new URL(request.url).searchParams.get("username"); await db.prepare("DELETE FROM users WHERE username = ?").bind(target).run(); return Response.json({ success: true }); }
        }
        
        if (action === "vps" && isAdmin) {
            await ensureDbSchema(db);
            if (method === "POST") { const { ip, name } = await request.json(); const safeIp = String(ip || '').trim(); const safeName = String(name || safeIp).trim().slice(0, 100); if (!/^[0-9A-Fa-f:.]{2,64}$/.test(safeIp)) return Response.json({ error: 'Invalid VPS IP' }, { status: 400 }); if (!safeName) return Response.json({ error: 'Server name is required' }, { status: 400 }); const agentToken = crypto.randomUUID(); const inserted = await db.prepare("INSERT INTO servers (ip, name, alert_sent, agent_token) SELECT ?, ?, 0, ? WHERE (SELECT COUNT(*) FROM servers) < 100 ON CONFLICT(ip) DO NOTHING RETURNING ip").bind(safeIp, safeName, agentToken).first(); if (!inserted) { if (await db.prepare('SELECT ip FROM servers WHERE ip = ?').bind(safeIp).first()) return Response.json({ error: 'VPS already exists' }, { status: 409 }); return Response.json({ error: "当前版本最多管理 100 台 VPS" }, { status: 409 }); } await ensureProbePlaceholder(db, safeIp, safeName, request.cf?.country || 'XX'); return Response.json({ success: true }); }
            if (method === "PUT") {
                const { ip, name } = await readJsonBody(request, 8 * 1024);
                const safeIp = String(ip || '').trim();
                const safeName = String(name || '').trim().slice(0, 100);
                if (!/^[0-9A-Fa-f:.]{2,64}$/.test(safeIp)) return Response.json({ error: 'Invalid VPS IP' }, { status: 400 });
                if (!safeName) return Response.json({ error: 'Server name is required' }, { status: 400 });
                const server = await db.prepare("SELECT ip FROM servers WHERE ip = ?").bind(safeIp).first();
                if (!server) return Response.json({ error: 'VPS not found' }, { status: 404 });
                await db.batch([
                    db.prepare("UPDATE servers SET name = ? WHERE ip = ?").bind(safeName, safeIp),
                    db.prepare("UPDATE probe_servers SET name = ? WHERE id = ?").bind(safeName, safeIp),
                ]);
                return Response.json({ success: true });
            }
            if (method === "DELETE") { 
                const ip = new URL(request.url).searchParams.get("ip"); 
                await db.batch([ db.prepare("DELETE FROM traffic_stats WHERE ip = ?").bind(ip), db.prepare("DELETE FROM servers WHERE ip = ?").bind(ip), db.prepare("DELETE FROM probe_servers WHERE id = ?").bind(ip), db.prepare("DELETE FROM server_logs WHERE ip = ?").bind(ip) ]);
                return Response.json({ success: true }); 
            }
        }

        return new Response("Not Found", { status: 404 });
    } catch (err) {
        const msg = (err && err.message) ? err.message : String(err);
        // 兜底捕获，杜绝未处理异常导致的 Cloudflare 1101
        return new Response(JSON.stringify({ error: "SERVER_ERR: " + msg }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
}

export async function onRequestScheduled(context) {
    try { await checkOfflineServers(context.env); } catch (error) { console.error('[cron] offline check failed:', error); throw error; }
}
