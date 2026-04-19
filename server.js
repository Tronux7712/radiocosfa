const express = require("express");
const helmet = require("helmet");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const WEB_ROOT = path.resolve(__dirname, "..");
const DATA_DIR = path.join(__dirname, "data");
const STORE_PATH = path.join(DATA_DIR, "messages.enc.json");
const ADMIN_EMAILS = new Set(
    (process.env.ADMIN_EMAILS || "ximebe712@gmail.com")
        .split(",")
        .map((x) => x.trim().toLowerCase())
        .filter(Boolean)
);

const AES_KEY = crypto
    .createHash("sha256")
    .update(process.env.CHAT_ENCRYPTION_SECRET || "change-this-secret-now")
    .digest();

const forbiddenWords = [
    "hpta",
    "hp",
    "gonorrea",
    "malparido",
    "malparida",
    "jueputa",
    "hijueputa",
    "mierda",
    "puta",
    "puto",
    "marica",
    "pendejo",
    "pendeja"
];

const spamState = new Map();

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

function sanitize(value) {
    return String(value || "").trim();
}

function normalizeForModeration(text) {
    return sanitize(text)
        .toLowerCase()
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/[^a-z0-9\s]/g, " ")
        .replace(/\s+/g, " ")
        .trim();
}

function isAllowedHolaSpam(normalizedText) {
    if (!normalizedText) {
        return false;
    }

    return normalizedText.replace(/\s+/g, "") === "hola";
}

function applyProfanityFilter(text) {
    let filtered = text;

    for (const word of forbiddenWords) {
        const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const pattern = new RegExp(`\\b${escaped}\\b`, "gi");
        filtered = filtered.replace(pattern, (match) => "*".repeat(match.length));
    }

    return filtered;
}

function detectSpam(senderKey, normalizedText) {
    const now = Date.now();
    const isHolaSpam = isAllowedHolaSpam(normalizedText);
    const state = spamState.get(senderKey) || { lastText: "", lastAt: 0, repeatCount: 0 };

    if (!isHolaSpam && now - state.lastAt < 900) {
        spamState.set(senderKey, state);
        return "Estas enviando mensajes muy rapido. Espera un segundo.";
    }

    if (!isHolaSpam && normalizedText && normalizedText === state.lastText && now - state.lastAt < 25000) {
        state.repeatCount += 1;
        if (state.repeatCount >= 3) {
            spamState.set(senderKey, state);
            return "Ese mensaje parece spam repetido.";
        }
    } else if (normalizedText !== state.lastText) {
        state.repeatCount = 0;
    }

    if (!isHolaSpam && /(.)\1{9,}/.test(normalizedText)) {
        spamState.set(senderKey, state);
        return "Ese mensaje parece spam por repeticion de caracteres.";
    }

    if (!isHolaSpam && normalizedText.split(" ").length > 45) {
        spamState.set(senderKey, state);
        return "El mensaje es demasiado largo para el chat.";
    }

    state.lastText = normalizedText;
    state.lastAt = now;
    spamState.set(senderKey, state);
    return "";
}

function encryptText(plainText) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", AES_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
        iv: iv.toString("base64"),
        tag: tag.toString("base64"),
        data: encrypted.toString("base64")
    };
}

function decryptText(payload) {
    const iv = Buffer.from(payload.iv, "base64");
    const tag = Buffer.from(payload.tag, "base64");
    const encrypted = Buffer.from(payload.data, "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", AES_KEY, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString("utf8");
}

function readStore() {
    if (!fs.existsSync(STORE_PATH)) {
        return [];
    }

    try {
        const raw = fs.readFileSync(STORE_PATH, "utf8");
        const list = JSON.parse(raw);
        return Array.isArray(list) ? list : [];
    } catch (error) {
        return [];
    }
}

function writeStore(messages) {
    fs.writeFileSync(STORE_PATH, JSON.stringify(messages, null, 2), "utf8");
}

function toPublicMessage(item) {
    let message = "";
    try {
        message = decryptText(item.payload || {});
    } catch (error) {
        message = "[mensaje no disponible]";
    }

    return {
        id: item.id,
        name: item.name,
        email: item.email,
        photo: item.photo,
        timestamp: Number(item.timestamp || 0),
        message
    };
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "300kb" }));

app.get("/api/messages", (req, res) => {
    const list = readStore()
        .map(toPublicMessage)
        .sort((a, b) => Number(a.timestamp || 0) - Number(b.timestamp || 0))
        .slice(-80);

    res.json({ messages: list });
});

app.post("/api/messages", (req, res) => {
    const name = sanitize(req.body?.name) || "Usuario";
    const email = sanitize(req.body?.email).toLowerCase();
    const photo = sanitize(req.body?.photo);
    const rawMessage = sanitize(req.body?.message);
    const normalized = normalizeForModeration(rawMessage);
    const senderKey = email || `anon:${name.toLowerCase()}`;

    if (!rawMessage) {
        res.status(400).json({ error: "No se puede enviar un mensaje vacio." });
        return;
    }

    const spamReason = detectSpam(senderKey, normalized);
    if (spamReason) {
        res.status(429).json({ error: spamReason });
        return;
    }

    const filteredMessage = applyProfanityFilter(rawMessage);
    const encryptedPayload = encryptText(filteredMessage);
    const now = Date.now();

    const record = {
        id: crypto.randomUUID(),
        name,
        email,
        photo,
        timestamp: now,
        payload: encryptedPayload
    };

    const list = readStore();
    list.push(record);
    writeStore(list);

    res.status(201).json({ message: toPublicMessage(record) });
});

app.delete("/api/messages/:id", (req, res) => {
    const actorEmail = sanitize(req.headers["x-user-email"]).toLowerCase();
    const id = sanitize(req.params.id);

    if (!ADMIN_EMAILS.has(actorEmail)) {
        res.status(403).json({ error: "Solo los admins pueden eliminar mensajes." });
        return;
    }

    const list = readStore();
    const next = list.filter((item) => item.id !== id);
    if (next.length === list.length) {
        res.status(404).json({ error: "Mensaje no encontrado." });
        return;
    }

    writeStore(next);
    res.json({ ok: true });
});

app.post("/api/messages/reset", (req, res) => {
    writeStore([]);
    res.json({ ok: true });
});

app.use(express.static(WEB_ROOT));

app.get("*", (req, res) => {
    res.sendFile(path.join(WEB_ROOT, "index.html"));
});

app.listen(PORT, () => {
    console.log(`Cosfa backend listo en http://localhost:${PORT}`);
});
