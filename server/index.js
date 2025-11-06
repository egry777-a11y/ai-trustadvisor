// server/index.js
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');
const whois = require('whois-json');
const { fromUrl } = require('tldts');
const axios = require('axios');
const path = require('path');
const fs = require('fs');

// Optional: OpenAI client (will only be used if OPENAI_API_KEY is set)
const { OpenAIApi, Configuration } = require('openai');
const OPENAI_KEY = process.env.OPENAI_API_KEY || null;
const openai = OPENAI_KEY ? new OpenAIApi(new Configuration({ apiKey: OPENAI_KEY })) : null;

const GOOGLE_SAFEBROWSING_KEY = process.env.GOOGLE_SAFEBROWSING_KEY || null;
const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_KEY || null;
const WHOISXMLAPI_KEY = process.env.WHOISXMLAPI_KEY || null;

const app = express();
app.use(helmet());
app.use(bodyParser.json({ limit: '2mb' }));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 60 });
app.use(limiter);

const PORT = process.env.PORT || 4000;

async function safeFetch(url, opts = {}, timeout = 8000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

async function googleSafeBrowsingLookup(url) {
  if (!GOOGLE_SAFEBROWSING_KEY) return { available: false };
  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFEBROWSING_KEY}`;
    const body = {
      client: { clientId: "ai-trustadvisor", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };
    const r = await axios.post(endpoint, body, { timeout: 8000 });
    return { available: true, matches: r.data.matches || null };
  } catch (e) {
    return { available: true, error: String(e) };
  }
}

async function virustotalLookup(url) {
  if (!VIRUSTOTAL_KEY) return { available: false };
  try {
    // VirusTotal v3 requires URL to be analyzed via /urls then /analyses; here we use the /urls endpoint with encoded URL
    const encoded = Buffer.from(url).toString('base64').replace(/=+$/,'');
    const endpoint = `https://www.virustotal.com/api/v3/urls/${encoded}`;
    const r = await axios.get(endpoint, { headers: { 'x-apikey': VIRUSTOTAL_KEY }, timeout: 10000 });
    return { available: true, data: r.data };
  } catch (e) {
    return { available: true, error: String(e) };
  }
}

async function whoisLookup(domain) {
  // Prefer whois-json library (fast) but if WHOISXMLAPI_KEY provided, we attempt their API
  if (WHOISXMLAPI_KEY) {
    try {
      const endpoint = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOISXMLAPI_KEY}&domainName=${encodeURIComponent(domain)}&outputFormat=JSON`;
      const r = await axios.get(endpoint, { timeout: 8000 });
      return { api: 'whoisxmlapi', data: r.data };
    } catch (e) {
      // fall back to whois-json
    }
  }
  try {
    const r = await whois(domain, { follow: 3, timeout: 8000 });
    return { api: 'whois-json', data: r };
  } catch (e) {
    return { error: String(e) };
  }
}

// quickScan with optional integrations
async function quickScan(targetUrl) {
  const parsed = fromUrl(targetUrl);
  const domain = parsed?.domain || parsed?.hostname || targetUrl;
  const host = parsed?.hostname || domain;

  const result = { domain, scanned_at: new Date().toISOString(), results: {}, composite_score: 0 };

  // WHOIS
  try {
    const who = await whoisLookup(host);
    let ageDays = null;
    const raw = who.data || who;
    // attempt to find creation date
    let created = raw?.WhoisRecord?.createdDateNormalized || raw?.created || raw?.CreationDate || raw?.createdDate || null;
    if (!created && raw?.createDate) created = raw.createDate;
    if (created) {
      const d = new Date(created);
      if (!isNaN(d)) ageDays = Math.floor((Date.now() - d.getTime()) / (1000*60*60*24));
    }
    const whoScore = ageDays == null ? 0.5 : (ageDays > 365 ? 0.9 : ageDays > 30 ? 0.6 : 0.2);
    result.results.whois = { age_days: ageDays, registrar: raw?.registrar || raw?.WhoisRecord?.registrarName || 'unknown', raw, score: whoScore };
  } catch (e) {
    result.results.whois = { error: String(e), score: 0.5 };
  }

  // fetch homepage
  try {
    const res = await safeFetch(targetUrl, { method: 'GET' }, 8000);
    const text = await res.text().catch(()=>'');
    result.results.ssl = { ok: res.ok, status: res.status, score: res.ok ? 0.9 : 0.0, details: `HTTP status ${res.status}` };

    const payment = { provider: null, hosted: false, evidence: [] };
    if (/stripe\.com|js\.stripe\.com|stripe-elements/.test(text)) { payment.provider = 'Stripe'; payment.hosted = true; payment.evidence.push('js.stripe.com'); }
    if (/paypal\.com|paypal-js|paypal-buttons/.test(text)) { payment.provider = payment.provider ? payment.provider + ', PayPal' : 'PayPal'; payment.hosted = true; payment.evidence.push('paypal.com'); }
    if (/adyen|checkoutshopper/.test(text)) { payment.provider = payment.provider ? payment.provider + ', Adyen' : 'Adyen'; payment.evidence.push('adyen'); }

    const typoscore = (host.match(/[-0-9]/g) || []).length / Math.max(1, host.length);
    result.results.payment = { provider: payment.provider || 'Unknown', hosted: payment.hosted, evidence: payment.evidence, score: payment.provider ? 0.9 : 0.2 };
    result.results.heuristics = { typosquatting_score: Math.min(1, typoscore), snippet: text.slice(0,1000) };

    // Google Safe Browsing and VirusTotal (best-effort, optional)
    const gs = await googleSafeBrowsingLookup(targetUrl).catch(e=>({ error: String(e) }));
    result.results.safebrowsing = gs;
    const vt = await virustotalLookup(targetUrl).catch(e=>({ error: String(e) }));
    result.results.virustotal = vt;
  } catch (e) {
    result.results.ssl = { ok: false, score: 0.0, raw_error: String(e) };
    result.results.payment = { provider: 'unknown', hosted: false, score: 0.1, raw_error: String(e) };
    result.results.heuristics = { typosquatting_score: 0.5 };
  }

  const weights = { whois: 0.25, ssl: 0.3, safebrowsing: 0.25, payment: 0.2 };
  let score = 0, tot = 0;
  for (const [k,w] of Object.entries(weights)) { const s = result.results[k]?.score ?? 0.5; score += s*w; tot += w; }
  result.composite_score = Math.round((score / Math.max(1, tot)) * 100) / 100;
  return result;
}

app.post('/api/scan', async (req, res) => {
  try {
    const { url } = req.body || {};
    if (!url) return res.status(400).json({ error: 'missing url in body' });
    let normalized;
    try { normalized = new URL(url).href; } catch (e) { return res.status(400).json({ error: 'invalid url' }); }
    const scan = await quickScan(normalized);
    return res.json(scan);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'internal error', details: String(e) });
  }
});

app.get('/api/scan', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'missing url query param' });
  try { const normalized = new URL(url).href; const scan = await quickScan(normalized); return res.json(scan); } catch (e) { console.error(e); return res.status(500).json({ error: 'internal', details: String(e) }); }
});

app.post('/api/ai-assess', async (req, res) => {
  const { scan } = req.body || {};
  if (!scan) return res.status(400).json({ error: 'missing scan in body' });
  try {
    if (openai) {
      const prompt = `You are a security-savvy assistant. Accept a JSON scan result and produce a short summary, actionable advice, and confidence (0..1). Scan JSON: ${JSON.stringify(scan).slice(0,2000)}`;
      const completion = await openai.createChatCompletion({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: prompt }], max_tokens: 400 });
      const reply = completion?.data?.choices?.[0]?.message?.content || 'No reply.';
      return res.json({ summary: reply, advice: reply, confidence: 0.85 });
    }
    const score = scan.composite_score || 0;
    if (score >= 0.8) return res.json({ summary: 'Site appears trustworthy based on domain age, TLS, and detected hosted payment provider.', advice: 'Proceed with caution. Verify checkout domain and use 3D-Secure or virtual card for payments.', confidence: 0.9 });
    if (score < 0.4) return res.json({ summary: 'Site shows multiple high-risk signals (new domain, missing TLS or malicious indicators).', advice: 'Do not enter payment information. Report or block the domain and use alternative vendors.', confidence: 0.95 });
    return res.json({ summary: 'Site looks mixed: some good signals but also warnings. Use extra caution when paying.', advice: 'Use payment provider protections (hosted checkout, 3D-Secure, virtual card) and double-check domain.', confidence: 0.7 });
  } catch (e) { console.error(e); return res.status(500).json({ error: 'ai-assess failed', details: String(e) }); }
});

// serve frontend static
app.use('/', express.static(path.join(__dirname, '..', 'frontend')));
app.get('/health', (req,res)=>res.json({ ok: true, time: new Date().toISOString() }));

app.listen(PORT, () => console.log(`AI TrustAdvisor server listening on ${PORT}`));
