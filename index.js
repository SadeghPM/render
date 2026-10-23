// ===== EDIT THIS LINE: put your UUID between the quotes =====
const USER_UUID = '42a4b7d4-50c3-4ef8-a0a6-469711cb3f3e';
// ============================================================
// VLESS over WebSocket + TLS on Render (Node.js web service).
import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns';
import dgram from 'node:dgram';
import { WebSocketServer } from 'ws';

const DEBUG = true;  // true = write connection logs (see Render > Logs)
const log = (...a) => { if (DEBUG) console.log(new Date().toISOString(), ...a); };

// Only for local testing. Leave unset on Render.
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1';

const getUuid = () => (process.env.UUID || USER_UUID).toLowerCase();

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });

  // Secret page: open https://YOUR-SITE.onrender.com/?key=YOUR-UUID to get the link text
  if (url.searchParams.get('key') === getUuid()) {
    const host = String(req.headers['x-forwarded-host'] || req.headers.host || '')
      .split(',')[0]
      .trim();
    res.end(makeLink(getUuid(), host));
    return;
  }
  res.end('Hello world');
});

const wss = new WebSocketServer({ server });
server.on('upgrade', (req) => log('ws upgrade', req.url, 'from=' + (req.headers['x-forwarded-for'] || '-'), 'ua=' + (req.headers['user-agent'] || '-')));
wss.on('connection', (ws) => { log('ws open'); handleVless(ws, getUuid()); });

function makeLink(uuid, host) {
  return (
    `vless://${uuid}@${host}:443` +
    `?encryption=none&security=tls&sni=${host}&fp=chrome` +
    `&type=ws&host=${host}&path=%2Fws#render`
  );
}

function handleVless(ws, uuid) {
  const uuidBytes = Buffer.from(uuid.replace(/-/g, ''), 'hex');
  let remote = null;
  let udp = false;
  let udpTarget = null;
  let responseHeader = null;

  const closeAll = () => {
    try { remote && remote.destroy(); } catch {}
    try { ws.close(); } catch {}
  };

  const sendOut = (chunk) => {
    if (ws.readyState !== 1) return;
    if (responseHeader) {
      ws.send(Buffer.concat([responseHeader, chunk]));
      responseHeader = null;
    } else {
      ws.send(chunk);
    }
  };

  ws.on('message', (data, isBinary) => {
    if (isBinary === false) return;
    try {
      const buf = Buffer.isBuffer(data)
        ? data
        : Array.isArray(data)
          ? Buffer.concat(data)
          : Buffer.from(data);
      onData(buf);
    } catch (e) {
      log('message error:', e.message);
      closeAll();
    }
  });
  ws.on('close', () => {
    log('ws close');
    try { remote && remote.destroy(); } catch {}
  });
  ws.on('error', closeAll);

  function onData(data) {
    // Already connected: just forward data
    if (remote) { remote.write(data); return; }
    if (udp) { udpData(data); return; }

    // First message: read the VLESS header
    if (data.length < 24) throw new Error('header too short');
    if (!data.subarray(1, 17).equals(uuidBytes)) throw new Error('wrong uuid');
    const version = data[0];
    let p = 18 + data[17];
    const cmd = data[p++]; // 1 = TCP, 2 = UDP
    const port = data.readUInt16BE(p);
    p += 2;
    const atype = data[p++];

    let address;
    if (atype === 1) {
      address = Array.from(data.subarray(p, p + 4)).join('.');
      p += 4;
    } else if (atype === 2) {
      const len = data[p++];
      address = data.toString('utf8', p, p + len);
      p += len;
    } else if (atype === 3) {
      const groups = [];
      for (let i = 0; i < 8; i++) groups.push(data.readUInt16BE(p + i * 2).toString(16));
      address = groups.join(':');
      p += 16;
    } else {
      throw new Error('bad address type');
    }

    const payload = data.subarray(p);
    responseHeader = Buffer.from([version, 0]);
    log('vless request', cmd === 1 ? 'tcp' : 'udp', address + ':' + port);

    if (cmd === 1) {
      connectTcp(address, port, payload);
    } else if (cmd === 2 && port === 53) {
      // UDP is only supported for DNS (answered by UDP and DNS-over-HTTPS, first answer wins)
      udp = true;
      udpTarget = { address, port };
      udpData(payload);
    } else {
      throw new Error('unsupported command');
    }
  }

  function connectTcp(address, port, payload) {
    if (net.isIP(address) && isBlocked(address)) throw new Error('blocked address');
    const sock = net.connect({ host: address, port, lookup: safeLookup });
    remote = sock;
    sock.setNoDelay(true);
    if (payload.length) sock.write(payload);

    sock.on('data', (chunk) => {
      sendOut(chunk);
      // Slow down the remote side if the client cannot keep up
      if (ws.bufferedAmount > 1048576 && !sock.isPaused()) {
        sock.pause();
        const timer = setInterval(() => {
          if (ws.readyState !== 1 || ws.bufferedAmount < 262144) {
            clearInterval(timer);
            sock.resume();
          }
        }, 25);
      }
    });
    sock.on('connect', () => log('remote connected', address + ':' + port));
    sock.on('error', (e) => { log('remote error', address + ':' + port, e.message); closeAll(); });
    sock.on('close', closeAll);
  }

  function udpData(data) {
    let i = 0;
    while (i + 2 <= data.length) {
      const len = data.readUInt16BE(i);
      const query = Buffer.from(data.subarray(i + 2, i + 2 + len));
      i += 2 + len;
      resolveDns(query, udpTarget)
        .then((answer) => {
          const head = Buffer.alloc(2);
          head.writeUInt16BE(answer.length);
          sendOut(Buffer.concat([head, answer]));
        })
        .catch((e) => log('dns failed:', e && e.message));
    }
  }
}

const DOH_URLS = [
  'https://1.1.1.1/dns-query',
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/dns-query',
];

// Ask UDP and DNS-over-HTTPS at the same time, use whichever answers first
function resolveDns(query, target) {
  const t0 = Date.now();
  const tries = [
    dohQuery(query).then((r) => { log('dns ok via doh', Date.now() - t0, 'ms'); return r; }),
  ];
  if (target && net.isIP(target.address) && !isBlocked(target.address)) {
    tries.push(
      udpQuery(query, target.address, target.port).then((r) => {
        log('dns ok via udp', Date.now() - t0, 'ms');
        return r;
      })
    );
  }
  return Promise.any(tries).catch((agg) => {
    throw new Error((agg.errors || [agg]).map((e) => e.message).join(' | '));
  });
}

async function dohQuery(query) {
  let lastError;
  for (const url of DOH_URLS) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
        body: query,
        signal: AbortSignal.timeout(4000),
      });
      if (!res.ok) throw new Error('status ' + res.status);
      return Buffer.from(await res.arrayBuffer());
    } catch (e) {
      lastError = e;
      log('doh failed', url, e && (e.cause && e.cause.message ? e.cause.message : e.message));
    }
  }
  throw lastError;
}

function udpQuery(query, host, port) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket(net.isIPv6(host) ? 'udp6' : 'udp4');
    const timer = setTimeout(() => {
      try { sock.close(); } catch {}
      reject(new Error('udp timeout'));
    }, 3000);
    sock.once('message', (m) => {
      clearTimeout(timer);
      try { sock.close(); } catch {}
      resolve(m);
    });
    sock.once('error', (e) => {
      clearTimeout(timer);
      try { sock.close(); } catch {}
      reject(e);
    });
    sock.send(query, port, host, (err) => {
      if (err) { clearTimeout(timer); try { sock.close(); } catch {} reject(err); }
    });
  });
}

// Do not let clients reach private or internal addresses of the server
function safeLookup(hostname, options, cb) {
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return cb(err);
    const list = Array.isArray(address) ? address.map((a) => a.address) : [address];
    if (list.some(isBlocked)) return cb(new Error('blocked address'));
    cb(null, address, family);
  });
}

function isBlocked(ip) {
  if (ALLOW_PRIVATE) return false;
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }
  const x = ip.toLowerCase();
  return (
    x === '::' || x === '::1' ||
    x.startsWith('fc') || x.startsWith('fd') ||
    x.startsWith('fe8') || x.startsWith('fe9') || x.startsWith('fea') || x.startsWith('feb')
  );
}

server.listen(Number(process.env.PORT) || 10000, '0.0.0.0', () => log('server listening'));
