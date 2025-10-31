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
    <p class="${status ? 'ok' : 'err'}">${status ? '✅ Verified' : '✅ Verified'} </p>
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
    // debug line to inspect raw response
    const rawText = await r.text();
    console.log("[DEBUG] Raw fetched response:", rawText);
    try {
      const parsed = JSON.parse(rawText);
      console.log("[DEBUG] Parsed object:", parsed);
      return parsed;
    } catch (e) {
      throw new Error("Fetched content is not valid JSON.");
    }
  } else {
    return inflateFromBase64Url(payload); // expects same shape
  }
}


function canonicalJSONString(obj) {
  if (Array.isArray(obj)) {
    // Sort each element recursively if it's an object/array
    return JSON.stringify(obj.map(item =>
      typeof item === "object" && item !== null
        ? JSON.parse(canonicalJSONString(item))
        : item
    ));
  } else if (obj && typeof obj === "object") {
    const sortedKeys = Object.keys(obj).sort();
    const sortedObj = {};
    for (const key of sortedKeys) {
      const value = obj[key];
      sortedObj[key] =
        typeof value === "object" && value !== null
          ? JSON.parse(canonicalJSONString(value))
          : value;
    }
    return JSON.stringify(sortedObj);
  }
  // Primitive value
  return JSON.stringify(obj);
}


async function verifyCertObject(certObj, sigB64, publicKey) {
  const data = canonicalJSONString(certObj);
  console.log("=== Canonical JSON in verifier ===");
  console.log(canonicalJSONString(certObj));
  console.log("=== END ===");
  console.log("Signature (base64):", sigB64);
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

async function extractPayloadFromPdfFile(file) {
  const buf = await file.arrayBuffer();
  const bytes = new Uint8Array(buf);
  const text = new TextDecoder("latin1").decode(bytes);

  const idx = text.indexOf("/CertPayload");
  if (idx === -1) throw new Error("No /CertPayload found in PDF metadata.");

  // Move to the start of the value token after the key
  let i = idx + "/CertPayload".length;
  const isWhite = (c) => c === 0x20 || c === 0x0d || c === 0x0a || c === 0x09 || c === 0x0c;
  while (i < bytes.length && isWhite(bytes[i])) i++;

  if (i >= bytes.length) throw new Error("Malformed /CertPayload in PDF.");

  const ch = String.fromCharCode(bytes[i]);

  if (ch === "(") {
    // Parse PDF literal string -> to raw bytes
    const out = [];
    i++; // after '('
    let depth = 1;
    while (i < bytes.length && depth > 0) {
      let b = bytes[i];
      if (b === 0x5c) { // backslash \
        i++;
        if (i >= bytes.length) break;
        const esc = bytes[i];

        // Line continuation for \ followed by EOL
        if (esc === 0x0d || esc === 0x0a) {
          // skip optional CRLF pair
          if (esc === 0x0d && bytes[i + 1] === 0x0a) i++;
          i++;
          continue;
        }

        // Octal escape: up to 3 octal digits
        if (esc >= 0x30 && esc <= 0x37) {
          let oct = String.fromCharCode(esc);
          if (bytes[i + 1] >= 0x30 && bytes[i + 1] <= 0x37) { oct += String.fromCharCode(bytes[++i]); }
          if (bytes[i + 1] >= 0x30 && bytes[i + 1] <= 0x37) { oct += String.fromCharCode(bytes[++i]); }
          out.push(parseInt(oct, 8) & 0xff);
          i++;
          continue;
        }

        // Single-char escapes per PDF spec
        const map = {
          0x6e: 0x0a, // \n
          0x72: 0x0d, // \r
          0x74: 0x09, // \t
          0x62: 0x08, // \b
          0x66: 0x0c, // \f
          0x28: 0x28, // \(
          0x29: 0x29, // \)
          0x5c: 0x5c  // \\
        };
        out.push(map[esc] ?? esc);
        i++;
        continue;
      } else if (b === 0x28) { // (
        depth++;
        out.push(b);
        i++;
      } else if (b === 0x29) { // )
        depth--;
        if (depth > 0) out.push(b);
        i++;
      } else {
        out.push(b);
        i++;
      }
    }
    if (depth !== 0) throw new Error("Unterminated /CertPayload string in PDF.");

    const payloadBytes = new Uint8Array(out);
    const jsonText = decodePdfStringBytes(payloadBytes);
    return parsePayloadJson(jsonText);

  } else if (ch === "<") {
    // Parse PDF hex string <...> -> to raw bytes
    i++; // after '<'
    const hexChars = [];
    while (i < bytes.length) {
      const c = bytes[i];
      if (c === 0x3e) { // '>'
        i++;
        break;
      }
      // ignore whitespace in hex
      if (!isWhite(c)) hexChars.push(String.fromCharCode(c));
      i++;
    }
    let hex = hexChars.join("");
    if (hex.length % 2 === 1) hex += "0"; // pad odd length per spec
    const out = new Uint8Array(hex.length / 2);
    for (let j = 0; j < out.length; j++) {
      out[j] = parseInt(hex.substr(j * 2, 2), 16);
    }
    const jsonText = decodePdfStringBytes(out);
    return parsePayloadJson(jsonText);

  } else {
    throw new Error("Unsupported /CertPayload format (expected literal or hex string).");
  }

  function decodePdfStringBytes(u8) {
    // Handle UTF-16 BOMs if present, else assume UTF-8
    if (u8.length >= 2 && u8[0] === 0xfe && u8[1] === 0xff) {
      return new TextDecoder("utf-16be").decode(u8.subarray(2));
    }
    if (u8.length >= 2 && u8[0] === 0xff && u8[1] === 0xfe) {
      return new TextDecoder("utf-16le").decode(u8.subarray(2));
    }
    // Try UTF-8; if it throws, fall back to latin1
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(u8);
    } catch {
      return new TextDecoder("latin1").decode(u8);
    }
  }

  function parsePayloadJson(jsonText) {
    try {
      const obj = JSON.parse(jsonText);
      if (!obj || !obj.cert || !obj.sig) {
        throw new Error("Embedded /CertPayload missing cert/sig.");
      }
      return obj;
    } catch (e) {
      console.error("Raw embedded /CertPayload text:", jsonText);
      throw new Error("Embedded /CertPayload is not valid JSON after decoding.");
    }
  }
}

function isPdfFile(f) {
  if (!f) return false;
  if (f.type === "application/pdf") return true;
  return /\.pdf$/i.test(f.name || "");
}

async function runFilesFlow() {
  try {
    show(true, "Verifying uploaded PDF...", "");
    const publicKey = await loadPublicKey();
    const f = $("jsonFile").files?.[0];
    if (!f) {
      show(false, "Please upload a PDF file first.", "");
      return;
    }
    if (!isPdfFile(f)) {
      show(false, "Only PDF files are supported for upload.", "");
      return;
    }

    const obj = await extractPayloadFromPdfFile(f);
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
