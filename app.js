// VaultOne SecureVault: AES-256-GCM + LSB image steganography, fully client-side.
const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = (id) => document.getElementById(id);

/* ---------- AES (Web Crypto) ---------- */
async function deriveKey(password, salt) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptText(text, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text)));
  const out = new Uint8Array(28 + ct.length); // salt(16) + iv(12) + ciphertext
  out.set(salt, 0);
  out.set(iv, 16);
  out.set(ct, 28);
  return out;
}

async function decryptBytes(bytes, password) {
  const salt = bytes.slice(0, 16);
  const iv = bytes.slice(16, 28);
  const ct = bytes.slice(28);
  const key = await deriveKey(password, salt);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return dec.decode(pt);
}

/* ---------- LSB steganography ---------- */
// Layout: 32-bit payload length, then payload bits. One bit per R/G/B channel (alpha untouched).
function embed(imageData, payload) {
  const d = imageData.data;
  const capacity = (d.length / 4) * 3;
  if (32 + payload.length * 8 > capacity) {
    throw new Error("Image is too small for this message. Use a larger image or a shorter message.");
  }
  let n = 0;
  const setBit = (bit) => {
    const i = Math.floor(n / 3) * 4 + (n % 3);
    d[i] = (d[i] & 0xfe) | bit;
    n++;
  };
  for (let i = 31; i >= 0; i--) setBit((payload.length >>> i) & 1);
  for (const byte of payload) for (let i = 7; i >= 0; i--) setBit((byte >> i) & 1);
}

function extract(imageData) {
  const d = imageData.data;
  const capacity = (d.length / 4) * 3;
  let n = 0;
  const getBit = () => {
    const i = Math.floor(n / 3) * 4 + (n % 3);
    n++;
    return d[i] & 1;
  };
  let len = 0;
  for (let i = 0; i < 32; i++) len = len * 2 + getBit();
  if (len < 29 || 32 + len * 8 > capacity) throw new Error("No hidden message found in this image.");
  const out = new Uint8Array(len);
  for (let b = 0; b < len; b++) {
    let v = 0;
    for (let i = 0; i < 8; i++) v = (v << 1) | getBit();
    out[b] = v;
  }
  return out;
}

/* ---------- helpers ---------- */
function loadImageToCanvas(file, canvas) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      canvas.width = img.naturalWidth;
      canvas.height = img.naturalHeight;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      ctx.fillStyle = "#fff"; // flatten transparency so RGB values are stable
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0);
      URL.revokeObjectURL(url);
      resolve(ctx);
    };
    img.onerror = () => reject(new Error("Could not read that image."));
    img.src = url;
  });
}

function setStatus(el, msg, ok) {
  el.textContent = msg;
  el.className = "status " + (ok === undefined ? "" : ok ? "ok" : "err");
}

/* ---------- tabs ---------- */
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    $("panel-hide").classList.toggle("hidden", tab.dataset.tab !== "hide");
    $("panel-reveal").classList.toggle("hidden", tab.dataset.tab !== "reveal");
  });
});

/* ---------- hide ---------- */
$("hideImg").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    await loadImageToCanvas(file, $("hideCanvas"));
    $("downloadLink").classList.add("hidden");
    setStatus($("hideStatus"), "Image loaded.", true);
  } catch (err) {
    setStatus($("hideStatus"), err.message, false);
  }
});

$("hideBtn").addEventListener("click", async () => {
  const status = $("hideStatus");
  const text = $("secretText").value;
  const pass = $("hidePass").value;
  const canvas = $("hideCanvas");
  if (!$("hideImg").files[0]) return setStatus(status, "Please choose a cover image first.", false);
  if (!text) return setStatus(status, "Enter a message to hide.", false);
  if (pass.length < 6) return setStatus(status, "Use a password of at least 6 characters.", false);
  try {
    setStatus(status, "Encrypting and embedding...");
    await loadImageToCanvas($("hideImg").files[0], canvas); // fresh pixels each time
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const payload = await encryptText(text, pass);
    embed(imageData, payload);
    ctx.putImageData(imageData, 0, 0);
    canvas.toBlob((blob) => {
      const link = $("downloadLink");
      link.href = URL.createObjectURL(blob);
      link.classList.remove("hidden");
      setStatus(status, "Done! Message encrypted and hidden. Download the PNG below.", true);
    }, "image/png");
  } catch (err) {
    setStatus(status, err.message, false);
  }
});

/* ---------- reveal ---------- */
$("revealImg").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    await loadImageToCanvas(file, $("revealCanvas"));
    $("revealOut").classList.add("hidden");
    setStatus($("revealStatus"), "Image loaded.", true);
  } catch (err) {
    setStatus($("revealStatus"), err.message, false);
  }
});

$("revealBtn").addEventListener("click", async () => {
  const status = $("revealStatus");
  const pass = $("revealPass").value;
  const canvas = $("revealCanvas");
  if (!$("revealImg").files[0]) return setStatus(status, "Please choose a secure image first.", false);
  if (!pass) return setStatus(status, "Enter the password.", false);
  try {
    setStatus(status, "Extracting and decrypting...");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const bytes = extract(imageData);
    const message = await decryptBytes(bytes, pass);
    const out = $("revealOut");
    out.textContent = message;
    out.classList.remove("hidden");
    setStatus(status, "Message recovered successfully.", true);
  } catch (err) {
    $("revealOut").classList.add("hidden");
    const wrongPass = err && err.name === "OperationError";
    setStatus(status, wrongPass ? "Wrong password, or the image was altered." : err.message, false);
  }
});
