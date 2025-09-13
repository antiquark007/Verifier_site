// webcrypto_utils.js
// Helpers: base64url inflate, RSA verify, PEM -> CryptoKey

export function base64UrlToBytes(b64url) {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function bytesToBase64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export async function inflateFromBase64Url(b64url) {
  // Use Compression Streams API if available; else fallback to fflate
  if ("DecompressionStream" in window) {
    const bytes = base64UrlToBytes(b64url);
    const ds = new DecompressionStream("deflate");
    const stream = new Blob([bytes]).stream().pipeThrough(ds);
    const buf = await new Response(stream).arrayBuffer();
    const text = new TextDecoder().decode(buf);
    return JSON.parse(text);
  } else {
    // Fallback to fflate (optional): add <script src="https://cdn.jsdelivr.net/npm/fflate/umd/index.min.js"></script>
    if (!window.fflate) throw new Error("No DecompressionStream; include fflate for fallback.");
    const bytes = base64UrlToBytes(b64url);
    const out = window.fflate.inflateSync(bytes);
    const text = new TextDecoder().decode(out);
    return JSON.parse(text);
  }
}

export async function importSpkiKey(pemText) {
  // Accept PEM public key and import as SPKI
  const b64 = pemText.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "");
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "spki",
    raw,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

export async function verifyPkcs1v15(publicKey, dataBytes, signatureB64) {
  const sigRaw = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
  return crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    publicKey,
    sigRaw,
    dataBytes
  );
}

export async function sha256Digest(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToBase64(new Uint8Array(buf));
}
