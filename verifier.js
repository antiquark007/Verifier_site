// verifier.js
// Dual-mode logic:
// - If hash payload starts with "http", fetch JSON+sig from that URL (online mode)
// - Else, treat hash as compressed+base64url JSON+sig (offline-in-browser mode)

import { inflateFromBase64Url, sha256Digest, importSpkiKey, verifyPkcs1v15 } from "./crypt.js";

// Paste your PEM public key here or fetch it; converted to SPKI DER (base64) is ideal.
// For simplicity, we accept PEM and convert to SPKI using a tiny helper.
const PUBLIC_KEY_PEM_URL = "./public.pem"; // place your public.pem in the site

const $ = (id) => document.getElementById(id);
const resultEl = $("result");

function show(status, message, details) {
  resultEl.innerHTML = `
    <p class="${status ? 'ok' : 'err'}">${status ? '✅ Verified' : '❌ Invalid'} — ${message}</p>
    ${details ? `<pre><code>${details}</code></pre>` : ""}
  `;
}

async function loadPublicKey() {
  const pem = await (await fetch(PUBLIC_KEY_PEM_URL, { cache: "no-store" })).text();
  return importSpkiKey(pem);
}

async function parsePayloadFromHash() {
  const raw = (new URL(window.location.href)).hash.slice(1);
  const input = $("hashInput");
  if (raw && !input.value) input.value = raw;
  return input.value.trim();
}

async function resolvePayloadToObject(payload) {
  if (!payload) return null;
  if (payload.startsWith("http://") || payload.startsWith("https://")) {
    const r = await fetch(payload, { cache: "no-store" });
    if (!r.ok) throw new Error(`Fetch failed: ${r.status}`);
    return await r.json(); // expects { cert: {...}, sig: "..." }
  } else {
    return inflateFromBase64Url(payload); // expects same shape
  }
}

function canonicalJSONString(obj) {
  // Keep parity with Python canonicalization
  const keys = Object.keys(obj).sort();
  const ordered = {};
  for (const k of keys) ordered[k] = obj[k];
  return JSON.stringify(ordered);
}

async function verifyCertObject(certObj, sigB64, publicKey) {
  const data = canonicalJSONString(certObj);
  const dataBytes = new TextEncoder().encode(data);
  const ok = await verifyPkcs1v15(publicKey, dataBytes, sigB64);
  return ok;
}

async function runHashFlow() {
  try {
    show(true, "Loading...", "");
    const publicKey = await loadPublicKey();
    const payloadStr = await parsePayloadFromHash();
    if (!payloadStr) {
      show(false, "No hash fragment found. Paste a payload or scan QR.", "");
      return;
    }
    const obj = await resolvePayloadToObject(payloadStr);
    if (!obj || !obj.cert || !obj.sig) {
      show(false, "Invalid payload format.", JSON.stringify(obj, null, 2));
      return;
    }
    const ok = await verifyCertObject(obj.cert, obj.sig, publicKey);
    show(ok, ok ? "Signature is valid." : "Signature verification failed.", JSON.stringify(obj.cert, null, 2));
  } catch (e) {
    show(false, e.message, e.stack || "");
  }
}

async function runFilesFlow() {
  try {
    show(true, "Verifying uploaded JSON...", "");
    const publicKey = await loadPublicKey();
    const f = $("jsonFile").files?.[0];
    if (!f) {
      show(false, "Please upload a JSON file first.", "");
      return;
    }
    const text = await f.text();
    const obj = JSON.parse(text);
    if (!obj || !obj.cert || !obj.sig) {
      show(false, "JSON must contain { cert: {...}, sig: '...' }", text);
      return;
    }
    const ok = await verifyCertObject(obj.cert, obj.sig, publicKey);
    show(ok, ok ? "Signature is valid." : "Signature verification failed.", JSON.stringify(obj.cert, null, 2));
  } catch (e) {
    show(false, e.message, e.stack || "");
  }
}

$("verifyBtn").addEventListener("click", runHashFlow);
$("verifyFilesBtn").addEventListener("click", runFilesFlow);

// Auto-run on load if hash exists
window.addEventListener("load", runHashFlow);
