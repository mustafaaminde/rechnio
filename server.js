"use strict";

// Rechnio: Supabase Auth, benutzerspezifische Cloud-Daten und Rechnungs-E-Mail über Resend.
// Keine Passwörter oder API-Schlüssel im Quellcode hinterlegen.
// Voraussetzung für Cloud-Daten: SQL aus rechnio_supabase_setup.sql in Supabase ausführen.

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const HOST = "0.0.0.0";
const PORT = Number(process.env.PORT || 3000);
const INDEX_PATH = path.join(__dirname, "index.html");

const PUBLIC_SITE_URL = (() => {
  const fallback = "https://rechnio.onrender.com";
  const configured = String(process.env.SITE_URL || "").trim();

  if (!configured) return fallback;

  try {
    const parsed = new URL(configured);
    const localHosts = new Set([
      "localhost",
      "127.0.0.1",
      "0.0.0.0",
      "::1",
    ]);

    if (
      parsed.protocol === "https:" &&
      !localHosts.has(parsed.hostname.toLowerCase())
    ) {
      return parsed.origin;
    }
  } catch {}

  return fallback;
})();

const COOKIE_NAME = "rn_session";
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const DEFAULT_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const REMEMBER_SESSION_TTL_MS = 10 * 365 * 24 * 60 * 60 * 1000;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const MAX_AUTH_ATTEMPTS = 10;
const MAX_EMAILS_PER_WINDOW = 10;
const SESSION_SECRET = String(process.env.SESSION_SECRET || "").trim();
const SESSION_COOKIE_MAX_AGE_SECONDS = Math.floor(
  REMEMBER_SESSION_TTL_MS / 1000
);

const sessions = new Map();
const authAttempts = new Map();
const emailAttempts = new Map();

function supabaseConfig() {
  const url = String(process.env.SUPABASE_URL || "")
    .trim()
    .replace(/\/+$/, "");

  const key = String(process.env.SUPABASE_ANON_KEY || "").trim();

  return url && key ? { url, key } : null;
}

function sendJson(res, statusCode, data, headers = {}) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    ...headers,
  });

  res.end(JSON.stringify(data));
}

function serveIndex(res) {
  fs.readFile(INDEX_PATH, (error, contents) => {
    if (error) {
      console.error("index.html konnte nicht gelesen werden:", error.message);

      sendJson(res, 500, {
        error: "Rechnio konnte nicht geladen werden.",
      });

      return;
    }

    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "same-origin",
    });

    res.end(contents);
  });
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    let size = 0;
    let finished = false;

    req.on("data", (chunk) => {
      size += chunk.length;

      if (size > MAX_BODY_BYTES) {
        if (!finished) {
          finished = true;
          reject(new Error("Die Anfrage ist zu groß."));
        }

        return;
      }

      if (!finished) {
        body += chunk.toString("utf8");
      }
    });

    req.on("end", () => {
      if (finished) return;

      if (!body.trim()) {
        finished = true;
        resolve({});
        return;
      }

      try {
        const value = JSON.parse(body);

        if (
          !value ||
          typeof value !== "object" ||
          Array.isArray(value)
        ) {
          throw new Error("Ungültiges Datenformat.");
        }

        finished = true;
        resolve(value);
      } catch {
        finished = true;
        reject(new Error("Die Anfrage enthält kein gültiges JSON."));
      }
    });

    req.on("error", (error) => {
      if (!finished) {
        finished = true;
        reject(error);
      }
    });
  });
}

async function readResponse(response) {
  const text = await response.text();

  if (!text) return {};

  try {
    return JSON.parse(text);
  } catch {
    return { message: text.slice(0, 500) };
  }
}

async function supabaseRequest(
  endpoint,
  {
    method = "GET",
    body,
    accessToken,
    extraHeaders = {},
  } = {}
) {
  const config = supabaseConfig();

  if (!config) {
    return {
      ok: false,
      status: 503,
      data: {
        message:
          "SUPABASE_URL oder SUPABASE_ANON_KEY fehlt in Render.",
      },
    };
  }

  const headers = {
    apikey: config.key,
    Accept: "application/json",
    ...extraHeaders,
  };

  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }

  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  let response;

  try {
    response = await fetch(`${config.url}${endpoint}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (error) {
    return {
      ok: false,
      status: 502,
      data: {
        message: `Supabase ist nicht erreichbar: ${error.message}`,
      },
    };
  }

  return {
    ok: response.ok,
    status: response.status,
    data: await readResponse(response),
  };
}

function normalizeUser(user) {
  const metadata =
    (user && (user.user_metadata || user.raw_user_meta_data)) || {};

  return {
    id: String(user?.id || ""),
    email: String(user?.email || "").trim().toLowerCase(),
    name: String(metadata.full_name || metadata.name || ""),
  };
}

function safeAuthMessage(result, isSignup = false) {
  const data = result?.data || {};

  const code = String(
    data.code || data.error_code || data.error || ""
  ).toLowerCase();

  const message = String(
    data.msg || data.message || data.error_description || ""
  ).toLowerCase();

  const detail = `${code} ${message}`;

  if (
    /invalid api key|invalid_api_key|api key.*(invalid|missing)|missing.*api key|apikey/.test(
      detail
    )
  ) {
    return "Rechnio kann Supabase nicht authentifizieren. Prüfe in Render unter Environment, ob SUPABASE_URL und SUPABASE_ANON_KEY exakt aus deinem Supabase-Projekt stammen.";
  }

  if (
    /email not confirmed|email_not_confirmed|email.*not.*confirmed/.test(
      detail
    )
  ) {
    return "Dieses Konto ist noch nicht bestätigt. Bestätige das Konto in Supabase → Authentication → Users oder registriere ein neues Konto.";
  }

  if (
    /invalid login credentials|invalid credentials|invalid_credentials|email or password/.test(
      detail
    )
  ) {
    return "Anmeldung fehlgeschlagen.";
  }

  if (
    /already registered|user already exists|already been registered|user_already_exists/.test(
      detail
    )
  ) {
    return "Für diese E-Mail-Adresse existiert bereits ein Konto. Melde dich an, statt ein neues Konto zu erstellen.";
  }

  if (
    /password.*(weak|short|least)|weak_password|password should be/.test(
      detail
    )
  ) {
    return "Das Passwort ist zu schwach. Verwende ein längeres Passwort.";
  }

  if (
    /signup is disabled|signups not allowed|disable_signup/.test(detail)
  ) {
    return "Die Registrierung ist in Supabase deaktiviert. Aktiviere die Registrierung neuer Benutzer.";
  }

  if (
    /rate limit|too many requests|over_request_rate_limit/.test(detail) ||
    result?.status === 429
  ) {
    return "Zu viele Versuche. Bitte warte etwas und versuche es erneut.";
  }

  if (result?.status === 401 || result?.status === 403) {
    return "Supabase hat die Anfrage abgelehnt. Prüfe die Supabase-Schlüssel in Render.";
  }

  if (result?.status >= 500) {
    return "Supabase hat einen Serverfehler zurückgegeben. Bitte versuche es später erneut.";
  }

  if (result?.status === 400 || result?.status === 422) {
    return isSignup
      ? "Das Konto konnte nicht erstellt werden. Prüfe die E-Mail-Adresse, das Passwort und die Supabase-Einstellungen."
      : "Supabase hat die Anmeldung abgelehnt. Prüfe E-Mail und Passwort.";
  }

  return isSignup
    ? "Das Konto konnte nicht erstellt werden. Prüfe die Supabase-Einstellungen in Render."
    : "Die Anmeldung ist fehlgeschlagen. Prüfe die Supabase-Einstellungen in Render.";
}

function requestIp(req) {
  return req.socket.remoteAddress || "unknown";
}

function isRateLimited(map, key, maxCount) {
  const now = Date.now();
  const current = map.get(key);

  if (!current || current.resetAt <= now) {
    map.set(key, {
      count: 1,
      resetAt: now + RATE_WINDOW_MS,
    });

    return false;
  }

  current.count += 1;

  return current.count > maxCount;
}

function parseCookies(req) {
  const result = {};

  for (const part of String(req.headers.cookie || "").split(";")) {
    const index = part.indexOf("=");

    if (index < 0) continue;

    const name = part.slice(0, index).trim();

    try {
      result[name] = decodeURIComponent(part.slice(index + 1).trim());
    } catch {
      result[name] = "";
    }
  }

  return result;
}

function hasPersistentSessionSecret() {
  return SESSION_SECRET.length >= 32;
}

function sessionEncryptionKey() {
  if (!hasPersistentSessionSecret()) return null;

  return crypto
    .createHash("sha256")
    .update(SESSION_SECRET, "utf8")
    .digest();
}

function sealPersistentSession(session) {
  const key = sessionEncryptionKey();

  if (!key) {
    throw new Error("SESSION_SECRET fehlt oder ist zu kurz.");
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(session), "utf8");

  const encrypted = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return `p.${iv.toString("base64url")}.${tag.toString(
    "base64url"
  )}.${encrypted.toString("base64url")}`;
}

function openPersistentSession(value) {
  try {
    const parts = String(value || "").split(".");

    if (parts.length !== 4 || parts[0] !== "p") return null;

    const key = sessionEncryptionKey();

    if (!key) return null;

    const iv = Buffer.from(parts[1], "base64url");
    const tag = Buffer.from(parts[2], "base64url");
    const encrypted = Buffer.from(parts[3], "base64url");

    if (iv.length !== 12 || tag.length !== 16 || !encrypted.length) {
      return null;
    }

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);

    const session = JSON.parse(plaintext.toString("utf8"));

    if (
      !session ||
      !session.user?.id ||
      !session.accessToken ||
      !session.refreshToken ||
      session.remember !== true ||
      !Number.isFinite(Number(session.accessExpiresAt)) ||
      Number(session.cookieExpiresAt) <= Date.now()
    ) {
      return null;
    }

    return session;
  } catch {
    return null;
  }
}

function cookieFlags(req) {
  const secure =
    req.headers["x-forwarded-proto"] === "https" ||
    PUBLIC_SITE_URL.startsWith("https://");

  return `Path=/; HttpOnly; SameSite=Lax${
    secure ? "; Secure" : ""
  }`;
}

function createSessionCookie(req, session, remember, existingId = null) {
  const flags = cookieFlags(req);

  if (remember) {
    if (!hasPersistentSessionSecret()) {
      throw new Error(
        "Angemeldet bleiben benötigt SESSION_SECRET mit mindestens 32 Zeichen in Render → Environment."
      );
    }

    session.remember = true;
    session.cookieExpiresAt = Date.now() + REMEMBER_SESSION_TTL_MS;

    const sealed = sealPersistentSession(session);

    return `${COOKIE_NAME}=${encodeURIComponent(
      sealed
    )}; Max-Age=${SESSION_COOKIE_MAX_AGE_SECONDS}; ${flags}`;
  }

  session.remember = false;
  session.cookieExpiresAt = Date.now() + DEFAULT_SESSION_TTL_MS;

  const id =
    existingId || crypto.randomBytes(32).toString("base64url");

  sessions.set(id, session);

  return `${COOKIE_NAME}=${encodeURIComponent(
    `s.${id}`
  )}; ${flags}`;
}

function clearCookie(req) {
  return `${COOKIE_NAME}=; Max-Age=0; ${cookieFlags(req)}`;
}

function newSessionFromAuth(authData, remember = false) {
  if (
    !authData?.access_token ||
    !authData?.refresh_token ||
    !authData?.user?.id
  ) {
    return null;
  }

  const ttl = remember
    ? REMEMBER_SESSION_TTL_MS
    : DEFAULT_SESSION_TTL_MS;

  const session = {
    user: normalizeUser(authData.user),
    accessToken: authData.access_token,
    refreshToken: authData.refresh_token,
    accessExpiresAt:
      Date.now() +
      Math.max(60, Number(authData.expires_in || 3600)) * 1000,
    cookieExpiresAt: Date.now() + ttl,
    remember: remember === true,
  };

  return {
    session,
    remember: remember === true,
  };
}

async function getSession(req) {
  const cookieValue = parseCookies(req)[COOKIE_NAME];

  if (!cookieValue) return null;

  let token = null;
  let session = null;
  let remember = false;

  if (cookieValue.startsWith("p.")) {
    session = openPersistentSession(cookieValue);
    remember = true;
    token = cookieValue;
  } else if (cookieValue.startsWith("s.")) {
    token = cookieValue.slice(2);
    session = sessions.get(token) || null;
  } else {
    return null;
  }

  if (!session || Number(session.cookieExpiresAt) <= Date.now()) {
    if (!remember && token) sessions.delete(token);
    return null;
  }

  if (session.accessExpiresAt <= Date.now() + 45_000) {
    const result = await supabaseRequest(
      "/auth/v1/token?grant_type=refresh_token",
      {
        method: "POST",
        body: {
          refresh_token: session.refreshToken,
        },
      }
    );

    if (
      !result.ok ||
      !result.data?.access_token ||
      !result.data?.refresh_token
    ) {
      if (!remember && token) sessions.delete(token);
      return null;
    }

    session.accessToken = result.data.access_token;
    session.refreshToken = result.data.refresh_token;

    session.accessExpiresAt =
      Date.now() +
      Math.max(60, Number(result.data.expires_in || 3600)) * 1000;

    if (result.data.user) {
      session.user = normalizeUser(result.data.user);
    }

    if (!remember && token) {
      sessions.set(token, session);
    }
  }

  return {
    token,
    session,
    refreshed: true,
    remember,
  };
}

function authResponse(res, req, status, data, found = null, extraHeaders = {}) {
  const headers = { ...extraHeaders };

  if (found?.remember) {
    headers["Set-Cookie"] = createSessionCookie(
      req,
      found.session,
      true,
      found.token
    );
  }

  sendJson(res, status, data, headers);
}

function h(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[char]);
}

function money(value) {
  return new Intl.NumberFormat("de-DE", {
    style: "currency",
    currency: "EUR",
  }).format(Number(value) || 0);
}

function displayDate(value) {
  const match = String(value || "").match(
    /^(\d{4})-(\d{2})-(\d{2})/
  );

  return match
    ? `${match[3]}.${match[2]}.${match[1]}`
    : h(value || "—");
}

function emailHtml({ invoice, customer, company, rows, net, vat, gross }) {
  const companyName = String(company.name || "Rechnio");

  const issuerAddress = [
    company.street,
    [company.postalCode, company.city].filter(Boolean).join(" "),
  ]
    .filter(Boolean)
    .join(", ");

  const items = rows
    .map(
      (row) => `<tr>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb">${h(row.description)}</td>
        <td style="padding:10px;text-align:right;border-bottom:1px solid #e5e7eb">${h(row.quantity)}</td>
        <td style="padding:10px;text-align:right;border-bottom:1px solid #e5e7eb">${money(row.price)}</td>
        <td style="padding:10px;text-align:right;border-bottom:1px solid #e5e7eb">${h(row.vat)} %</td>
        <td style="padding:10px;text-align:right;border-bottom:1px solid #e5e7eb">${money(row.net)}</td>
      </tr>`
    )
    .join("");

  const taxInfo = [
    company.taxId ? `Steuernummer: ${h(company.taxId)}` : "",
    company.vatNumber ? `USt-IdNr.: ${h(company.vatNumber)}` : "",
  ]
    .filter(Boolean)
    .join(" · ");

  const companyInfo = [
    h(companyName),
    h(issuerAddress),
    h(company.email || ""),
    taxInfo,
  ]
    .filter(Boolean)
    .join("<br>");

  const customerAddress = [
    customer.street,
    [customer.postalCode, customer.city].filter(Boolean).join(" "),
  ]
    .filter(Boolean)
    .map(h)
    .join("<br>");

  const notes = String(invoice.notes || company.footer || "");

  return `<!doctype html>
<html lang="de">
<head><meta charset="utf-8"></head>
<body style="margin:0;background:#f5f7fb;font-family:Arial,Helvetica,sans-serif;color:#172033">
  <div style="max-width:760px;margin:0 auto;padding:28px 14px">
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden">
      <div style="padding:24px 26px;background:#172033;color:#fff">
        <div style="font-size:12px;letter-spacing:2px;text-transform:uppercase;opacity:.8">Rechnung</div>
        <h1 style="font-size:25px;margin:8px 0 0">${h(invoice.number)}</h1>
        <div style="margin-top:8px;color:#dbeafe">${h(companyName)}</div>
      </div>
      <div style="padding:24px 26px">
        <div style="display:flex;flex-wrap:wrap;gap:28px;margin-bottom:24px">
          <div style="flex:1;min-width:220px">
            <strong>Rechnungssteller</strong>
            <p style="font-size:13px;line-height:1.7">${companyInfo || "Angaben zum Rechnungssteller fehlen."}</p>
          </div>
          <div style="flex:1;min-width:220px">
            <strong>Rechnungsempfänger</strong>
            <p style="font-size:13px;line-height:1.7">
              <b>${h(customer.name || "")}</b><br>
              ${customerAddress}
              ${customer.email ? `<br>${h(customer.email)}` : ""}
            </p>
          </div>
        </div>
        <div style="background:#f8fafc;border-radius:8px;padding:14px;display:flex;flex-wrap:wrap;gap:20px;font-size:13px;margin-bottom:22px">
          <div><strong>Rechnungsdatum</strong><br>${displayDate(invoice.issueDate)}</div>
          <div><strong>Fällig am</strong><br>${displayDate(invoice.dueDate)}</div>
          ${
            invoice.serviceDate
              ? `<div><strong>Leistungsdatum</strong><br>${displayDate(invoice.serviceDate)}</div>`
              : invoice.servicePeriod
                ? `<div><strong>Leistungszeitraum</strong><br>${h(invoice.servicePeriod)}</div>`
                : ""
          }
        </div>
        <div style="overflow-x:auto">
          <table style="width:100%;border-collapse:collapse;font-size:13px">
            <thead>
              <tr style="text-align:left;background:#f8fafc">
                <th style="padding:10px">Beschreibung</th>
                <th style="padding:10px;text-align:right">Menge</th>
                <th style="padding:10px;text-align:right">Einzelpreis netto</th>
                <th style="padding:10px;text-align:right">MwSt.</th>
                <th style="padding:10px;text-align:right">Netto</th>
              </tr>
            </thead>
            <tbody>${items}</tbody>
          </table>
        </div>
        <div style="max-width:310px;margin:22px 0 0 auto;font-size:14px">
          <div style="display:flex;justify-content:space-between;padding:5px 0">
            <span>Nettosumme</span><strong>${money(net)}</strong>
          </div>
          <div style="display:flex;justify-content:space-between;padding:5px 0">
            <span>Umsatzsteuer</span><strong>${money(vat)}</strong>
          </div>
          <div style="display:flex;justify-content:space-between;padding:12px 0;border-top:2px solid #172033;font-size:18px">
            <span>Gesamtbetrag</span><strong>${money(gross)}</strong>
          </div>
        </div>
        ${
          company.iban
            ? `<p style="font-size:13px;line-height:1.6;margin-top:24px"><strong>Bankverbindung:</strong> ${h(company.iban)}</p>`
            : ""
        }
        ${
          notes
            ? `<p style="font-size:13px;line-height:1.6;margin-top:18px"><strong>Hinweis:</strong><br>${h(notes).replace(/\n/g, "<br>")}</p>`
            : ""
        }
        <p style="font-size:12px;color:#64748b;border-top:1px solid #e5e7eb;padding-top:16px;margin-top:26px">
          Diese E-Mail wurde über Rechnio versendet. Bitte bewahre die Nachricht für deine Unterlagen auf.
        </p>
      </div>
    </div>
  </div>
</body>
</html>`;
}

function validateInvoicePayload(body) {
  const invoice =
    body.invoice && typeof body.invoice === "object"
      ? body.invoice
      : null;

  const customer =
    body.customer && typeof body.customer === "object"
      ? body.customer
      : null;

  const company =
    body.company && typeof body.company === "object"
      ? body.company
      : {};

  if (!invoice || !customer) {
    return { error: "Rechnungs- oder Kundendaten fehlen." };
  }

  const to = String(customer.email || "").trim().toLowerCase();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
    return {
      error:
        "Beim Rechnungsempfänger ist keine gültige E-Mail-Adresse hinterlegt.",
    };
  }

  const number = String(invoice.number || "").trim().slice(0, 100);

  if (!number) {
    return { error: "Die Rechnungsnummer fehlt." };
  }

  if (
    !Array.isArray(invoice.items) ||
    invoice.items.length < 1 ||
    invoice.items.length > 100
  ) {
    return {
      error: "Die Rechnung muss zwischen 1 und 100 Positionen enthalten.",
    };
  }

  let net = 0;
  let vat = 0;
  const rows = [];

  for (const item of invoice.items) {
    const quantity = Number(item.quantity);
    const price = Number(item.price);
    const rate = Number(item.vat ?? 0);
    const description = String(item.description || "Leistung").slice(
      0,
      300
    );

    if (
      !Number.isFinite(quantity) ||
      quantity <= 0 ||
      !Number.isFinite(price) ||
      price < 0 ||
      !Number.isFinite(rate) ||
      rate < 0 ||
      rate > 100
    ) {
      return {
        error:
          "Eine Rechnungsposition enthält ungültige Mengen, Preise oder Steuersätze.",
      };
    }

    const rowNet = Math.round(quantity * price * 100) / 100;
    const rowVat = Math.round(rowNet * rate) / 100;

    net += rowNet;
    vat += rowVat;

    rows.push({
      description,
      quantity: quantity.toLocaleString("de-DE"),
      price,
      vat: rate,
      net: rowNet,
    });
  }

  net = Math.round(net * 100) / 100;
  vat = Math.round(vat * 100) / 100;

  const safeCompany = {
    name: String(company.name || "").slice(0, 200),
    owner: String(company.owner || "").slice(0, 160),
    email: String(company.email || "").slice(0, 254),
    phone: String(company.phone || "").slice(0, 80),
    street: String(company.street || "").slice(0, 200),
    postalCode: String(company.postalCode || "").slice(0, 40),
    city: String(company.city || "").slice(0, 160),
    taxId: String(company.taxId || "").slice(0, 100),
    vatNumber: String(company.vatNumber || "").slice(0, 100),
    iban: String(company.iban || "").slice(0, 60),
    footer: String(company.footer || "").slice(0, 1000),
  };

  const safeInvoice = {
    number,
    title: String(invoice.title || "").slice(0, 200),
    issueDate: String(invoice.issueDate || "").slice(0, 10),
    serviceDate: String(invoice.serviceDate || "").slice(0, 10),
    servicePeriod: String(invoice.servicePeriod || "").slice(0, 100),
    dueDate: String(invoice.dueDate || "").slice(0, 10),
    notes: String(invoice.notes || "").slice(0, 1000),
  };

  const safeCustomer = {
    name: String(customer.name || "").slice(0, 200),
    email: to,
    street: String(customer.street || "").slice(0, 200),
    postalCode: String(customer.postalCode || "").slice(0, 40),
    city: String(customer.city || "").slice(0, 160),
  };

  return {
    invoice: safeInvoice,
    customer: safeCustomer,
    company: safeCompany,
    rows,
    net,
    vat,
    gross: Math.round((net + vat) * 100) / 100,
  };
}

async function handle(req, res) {
  let url;

  try {
    url = new URL(
      req.url || "/",
      `http://${req.headers.host || "localhost"}`
    );
  } catch {
    sendJson(res, 400, {
      error: "Ungültige Anfrageadresse.",
    });
    return;
  }

  const route = url.pathname;

  if (
    req.method === "GET" &&
    (
      route === "/" ||
      route === "/reset-password" ||
      route === "/auth/confirmed"
    )
  ) {
    serveIndex(res);
    return;
  }

  if (req.method === "GET" && route === "/favicon.ico") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method === "GET" && route === "/api/health") {
    sendJson(res, 200, {
      ok: true,
      service: "Rechnio",
      authConfigured: Boolean(supabaseConfig()),
      cloudConfigured: Boolean(supabaseConfig()),
      emailConfigured: Boolean(
        process.env.RESEND_API_KEY && process.env.EMAIL_FROM
      ),
      persistentLoginConfigured: hasPersistentSessionSecret(),
    });

    return;
  }

  if (
    req.method === "POST" &&
    (
      route === "/api/auth/login" ||
      route === "/api/auth/register"
    )
  ) {
    const signup = route.endsWith("/register");
    const limitKey = `${requestIp(req)}:${signup ? "register" : "login"}`;

    if (isRateLimited(authAttempts, limitKey, MAX_AUTH_ATTEMPTS)) {
      sendJson(res, 429, {
        error:
          "Zu viele Versuche. Bitte warte 15 Minuten und versuche es danach erneut.",
      });
      return;
    }

    if (!supabaseConfig()) {
      sendJson(res, 503, {
        error:
          "Die Anmeldung ist nicht konfiguriert. Prüfe SUPABASE_URL und SUPABASE_ANON_KEY in Render.",
      });
      return;
    }

    let body;

    try {
      body = await readJson(req);
    } catch (error) {
      sendJson(res, 400, { error: error.message });
      return;
    }

    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password ?? "");
    const remember = body.remember === true;

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      sendJson(res, 400, {
        error: "Bitte gib eine gültige E-Mail-Adresse ein.",
      });
      return;
    }

    if (signup && password.length < 8) {
      sendJson(res, 400, {
        error: "Das Passwort muss mindestens 8 Zeichen enthalten.",
      });
      return;
    }

    if (!password || password.length > 256) {
      sendJson(res, 400, {
        error: "Bitte gib ein gültiges Passwort ein.",
      });
      return;
    }

    if (remember && !hasPersistentSessionSecret()) {
      sendJson(res, 503, {
        error:
          "Damit Rechnio dich dauerhaft angemeldet hält, fehlt SESSION_SECRET in Render → Environment. Füge eine geheime Zeichenfolge mit mindestens 32 Zeichen hinzu und deploye erneut.",
      });
      return;
    }

    const confirmationDestination =
      `${PUBLIC_SITE_URL}/auth/confirmed?remember=${remember ? "1" : "0"}`;

    const endpoint = signup
      ? `/auth/v1/signup?redirect_to=${encodeURIComponent(
          confirmationDestination
        )}`
      : "/auth/v1/token?grant_type=password";

    const result = await supabaseRequest(endpoint, {
      method: "POST",
      body: signup
        ? { email, password, data: {} }
        : { email, password },
    });

    if (!result.ok) {
      console.warn("Supabase auth request rejected", {
        action: signup ? "register" : "login",
        status: result.status,
        code: String(
          result.data?.code ||
          result.data?.error_code ||
          result.data?.error ||
          "unknown"
        ).slice(0, 80),
        reason: String(
          result.data?.error_description ||
          result.data?.msg ||
          result.data?.message ||
          ""
        ).slice(0, 160),
      });

      sendJson(
        res,
        result.status === 429
          ? 429
          : result.status >= 500
            ? 502
            : signup
              ? 400
              : 401,
        {
          error: safeAuthMessage(result, signup),
        }
      );

      return;
    }

    if (
      signup &&
      (
        !result.data?.access_token ||
        !result.data?.refresh_token ||
        !result.data?.user?.id
      )
    ) {
      sendJson(res, 202, {
        needsEmailConfirmation: true,
        message:
          "Wir haben dir einen Bestätigungslink per E-Mail geschickt. Öffne die E-Mail und klicke auf den Link. Danach wirst du automatisch zu Rechnio zurückgeleitet und wir fragen dich nach deinem Namen.",
      });

      return;
    }

    const opened = newSessionFromAuth(result.data, remember);

    if (!opened) {
      sendJson(res, 502, {
        error:
          "Supabase hat kein vollständiges Sitzungstoken zurückgegeben. Prüfe die E-Mail-Bestätigungseinstellungen.",
      });

      return;
    }

    let setCookie;

    try {
      setCookie = createSessionCookie(
        req,
        opened.session,
        opened.remember
      );
    } catch (error) {
      sendJson(res, 503, {
        error:
          error.message ||
          "Die Sitzung konnte nicht sicher gespeichert werden.",
      });

      return;
    }

    authAttempts.delete(limitKey);

    sendJson(
      res,
      signup ? 201 : 200,
      { user: opened.session.user },
      { "Set-Cookie": setCookie }
    );

    return;
  }

  if (req.method === "POST" && route === "/api/auth/session") {
    let body;

    try {
      body = await readJson(req);
    } catch (error) {
      sendJson(res, 400, { error: error.message });
      return;
    }

    const accessToken = String(body.accessToken || "").trim();
    const refreshToken = String(body.refreshToken || "").trim();
    const expiresIn = Number(body.expiresIn || 3600);
    const remember = body.remember === true;

    if (
      !accessToken ||
      !refreshToken ||
      accessToken.length > 10000 ||
      refreshToken.length > 10000
    ) {
      sendJson(res, 400, {
        error:
          "Der Bestätigungslink enthält keine gültige Sitzung. Fordere einen neuen Link an.",
      });

      return;
    }

    if (remember && !hasPersistentSessionSecret()) {
      sendJson(res, 503, {
        error:
          "SESSION_SECRET fehlt in Render. Bitte füge sie unter Environment hinzu und öffne danach einen neuen Bestätigungslink.",
      });

      return;
    }

    const verified = await supabaseRequest("/auth/v1/user", {
      accessToken,
    });

    if (
      !verified.ok ||
      !verified.data?.id ||
      !verified.data?.email
    ) {
      sendJson(res, 401, {
        error:
          "Der Bestätigungslink ist ungültig oder abgelaufen. Bitte fordere einen neuen Link an.",
      });

      return;
    }

    const opened = newSessionFromAuth(
      {
        access_token: accessToken,
        refresh_token: refreshToken,
        expires_in:
          Number.isFinite(expiresIn) && expiresIn > 0
            ? expiresIn
            : 3600,
        user: verified.data,
      },
      remember
    );

    if (!opened) {
      sendJson(res, 401, {
        error:
          "Die Bestätigung konnte keine gültige Rechnio-Sitzung erstellen.",
      });

      return;
    }

    try {
      const setCookie = createSessionCookie(
        req,
        opened.session,
        opened.remember
      );

      sendJson(
        res,
        200,
        { ok: true, user: opened.session.user },
        { "Set-Cookie": setCookie }
      );
    } catch (error) {
      sendJson(res, 503, {
        error:
          error.message ||
          "Die Sitzung konnte nicht sicher gespeichert werden.",
      });
    }

    return;
  }

  if (req.method === "GET" && route === "/api/auth/me") {
    const found = await getSession(req);

    if (!found) {
      sendJson(res, 401, {
        error: "Bitte melde dich an.",
      });

      return;
    }

    authResponse(res, req, 200, { user: found.session.user }, found);
    return;
  }

  if (req.method === "POST" && route === "/api/auth/profile") {
    const found = await getSession(req);

    if (!found) {
      sendJson(res, 401, {
        error: "Deine Sitzung ist abgelaufen. Bitte melde dich erneut an.",
      });

      return;
    }

    let body;

    try {
      body = await readJson(req);
    } catch (error) {
      authResponse(res, req, 400, { error: error.message }, found);
      return;
    }

    const name = String(body.name || "").trim().slice(0, 80);

    if (name.length < 2) {
      authResponse(res, req, 400, {
        error: "Bitte gib mindestens zwei Zeichen als Namen ein.",
      }, found);

      return;
    }

    const updated = await supabaseRequest("/auth/v1/user", {
      method: "PUT",
      accessToken: found.session.accessToken,
      body: {
        data: { full_name: name },
      },
    });

    if (!updated.ok) {
      authResponse(res, req, 502, {
        error: "Dein Name konnte nicht im Benutzerkonto gespeichert werden.",
      }, found);

      return;
    }

    found.session.user = normalizeUser(updated.data);

    if (!found.session.user.name) {
      found.session.user.name = name;
    }

    authResponse(res, req, 200, { user: found.session.user }, found);
    return;
  }

  if (req.method === "POST" && route === "/api/auth/logout") {
    const found = await getSession(req);

    if (found) {
      sessions.delete(found.token);

      await supabaseRequest("/auth/v1/logout", {
        method: "POST",
        accessToken: found.session.accessToken,
      }).catch(() => null);
    }

    sendJson(
      res,
      200,
      { ok: true },
      { "Set-Cookie": clearCookie(req) }
    );

    return;
  }

  if (
    route === "/api/state" &&
    (req.method === "GET" || req.method === "PUT")
  ) {
    const found = await getSession(req);

    if (!found) {
      sendJson(res, 401, {
        error: "Bitte melde dich an.",
      });

      return;
    }

    const userId = encodeURIComponent(found.session.user.id);

    if (req.method === "GET") {
      const result = await supabaseRequest(
        `/rest/v1/rechnio_user_state?select=state&user_id=eq.${userId}`,
        {
          accessToken: found.session.accessToken,
        }
      );

      if (!result.ok) {
        const message = String(
          result.data?.message || result.data?.details || ""
        );

        const missingTable =
          result.status === 404 ||
          /rechnio_user_state|schema cache|does not exist/i.test(message);

        authResponse(
          res,
          req,
          missingTable ? 503 : 502,
          {
            error: missingTable
              ? "Die Cloud-Tabelle fehlt noch. Führe die Datei rechnio_supabase_setup.sql im Supabase SQL Editor aus."
              : "Die Cloud-Daten konnten nicht geladen werden. Prüfe Supabase-RLS und den Login.",
          },
          found
        );

        return;
      }

      const row = Array.isArray(result.data)
        ? result.data[0]
        : null;

      authResponse(
        res,
        req,
        200,
        { state: row?.state || null },
        found
      );

      return;
    }

    let body;

    try {
      body = await readJson(req);
    } catch (error) {
      authResponse(res, req, 400, { error: error.message }, found);
      return;
    }

    if (
      !body.state ||
      typeof body.state !== "object" ||
      Array.isArray(body.state)
    ) {
      authResponse(res, req, 400, {
        error: "Der zu speichernde Rechnio-Datenstand ist ungültig.",
      }, found);

      return;
    }

    const result = await supabaseRequest(
      "/rest/v1/rechnio_user_state?on_conflict=user_id",
      {
        method: "POST",
        accessToken: found.session.accessToken,
        extraHeaders: {
          Prefer: "resolution=merge-duplicates,return=minimal",
        },
        body: {
          user_id: found.session.user.id,
          state: body.state,
          updated_at: new Date().toISOString(),
        },
      }
    );

    if (!result.ok) {
      const message = String(
        result.data?.message || result.data?.details || ""
      );

      const missingTable =
        result.status === 404 ||
        /rechnio_user_state|schema cache|does not exist/i.test(message);

      authResponse(
        res,
        req,
        missingTable ? 503 : 502,
        {
          error: missingTable
            ? "Die Cloud-Tabelle fehlt noch. Führe rechnio_supabase_setup.sql im Supabase SQL Editor aus."
            : "Cloud-Speicherung fehlgeschlagen. Prüfe die RLS-Regeln in Supabase.",
        },
        found
      );

      return;
    }

    authResponse(
      res,
      req,
      200,
      {
        ok: true,
        savedAt: new Date().toISOString(),
      },
      found
    );

    return;
  }

  if (req.method === "POST" && route === "/api/send-invoice") {
    const found = await getSession(req);

    if (!found) {
      sendJson(res, 401, {
        error: "Bitte melde dich erneut an.",
      });

      return;
    }

    if (!process.env.RESEND_API_KEY || !process.env.EMAIL_FROM) {
      authResponse(res, req, 503, {
        error:
          "Der E-Mail-Dienst ist nicht vollständig eingerichtet. Prüfe RESEND_API_KEY und EMAIL_FROM in Render.",
      }, found);

      return;
    }

    if (
      isRateLimited(
        emailAttempts,
        found.session.user.id,
        MAX_EMAILS_PER_WINDOW
      )
    ) {
      authResponse(res, req, 429, {
        error:
          "Du hast gerade viele E-Mails gesendet. Bitte versuche es später erneut.",
      }, found);

      return;
    }

    let body;

    try {
      body = await readJson(req);
    } catch (error) {
      authResponse(res, req, 400, { error: error.message }, found);
      return;
    }

    const checked = validateInvoicePayload(body);

    if (checked.error) {
      authResponse(res, req, 400, { error: checked.error }, found);
      return;
    }

    const {
      invoice,
      customer,
      company,
      rows,
      net,
      vat,
      gross,
    } = checked;

    const html = emailHtml(checked);

    const textRows = rows
      .map(
        (row) =>
          `${row.description} | Menge ${row.quantity} | ${money(
            row.price
          )} netto | ${row.vat}% MwSt. | ${money(row.net)} netto`
      )
      .join("\n");

    const plainText = [
      `RECHNUNG ${invoice.number}`,
      `Von: ${company.name || "Rechnio"}`,
      `Rechnung an: ${customer.name} <${customer.email}>`,
      `Rechnungsdatum: ${displayDate(invoice.issueDate)}`,
      `Fällig am: ${displayDate(invoice.dueDate)}`,
      "",
      "Positionen:",
      textRows,
      "",
      `Nettosumme: ${money(net)}`,
      `Umsatzsteuer: ${money(vat)}`,
      `Gesamtbetrag: ${money(gross)}`,
      invoice.notes || company.footer || "",
    ]
      .filter(Boolean)
      .join("\n");

    let resendResponse;

    try {
      resendResponse = await fetch(
        "https://api.resend.com/emails",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({
            from: String(process.env.EMAIL_FROM).trim(),
            to: [customer.email],
            subject: `Rechnung ${invoice.number} von ${
              company.name || "Rechnio"
            }`,
            html,
            text: plainText,
            tags: [
              {
                name: "product",
                value: "rechnio",
              },
            ],
          }),
        }
      );
    } catch (error) {
      console.error("Resend ist nicht erreichbar:", error.message);

      authResponse(res, req, 502, {
        error: "Der E-Mail-Dienst ist nicht erreichbar. Versuche es erneut.",
      }, found);

      return;
    }

    const resendData = await readResponse(resendResponse);

    if (!resendResponse.ok) {
      console.error(
        "Resend hat eine E-Mail abgelehnt:",
        resendResponse.status,
        String(
          resendData.message || resendData.name || ""
        ).slice(0, 300)
      );

      if (resendResponse.status === 401) {
        authResponse(res, req, 502, {
          error:
            "Der Resend-API-Schlüssel ist ungültig. Prüfe RESEND_API_KEY in Render.",
        }, found);

        return;
      }

      if (
        resendResponse.status === 403 ||
        /domain.*(verify|verified)|testing.*email/i.test(
          String(resendData.message || "")
        )
      ) {
        authResponse(res, req, 502, {
          error:
            "Resend lehnt den Absender ab. EMAIL_FROM muss von einer bei Resend verifizierten Domain stammen. Eine Gmail-Adresse allein reicht dafür nicht.",
        }, found);

        return;
      }

      authResponse(res, req, 502, {
        error:
          "Resend konnte die E-Mail nicht senden. Prüfe API-Key, Absender und Empfänger im Resend-Dashboard.",
      }, found);

      return;
    }

    authResponse(res, req, 200, {
      ok: true,
      emailId: resendData.id || null,
    }, found);

    return;
  }

  if (route.startsWith("/api/")) {
    sendJson(res, 404, {
      error: "Diese API-Funktion ist nicht eingerichtet.",
    });

    return;
  }

  sendJson(res, 404, {
    error: "Diese Seite ist nicht verfügbar.",
  });
}

const server = http.createServer((req, res) => {
  Promise.resolve(handle(req, res)).catch((error) => {
    console.error("Rechnio request failed:", error.message);

    if (!res.headersSent) {
      sendJson(res, 500, {
        error: "Ein interner Fehler ist aufgetreten. Bitte versuche es erneut.",
      });
    } else {
      res.end();
    }
  });
});

server.on("error", (error) => {
  console.error("Rechnio server error:", error.message);
  process.exitCode = 1;
});

server.listen(PORT, HOST, () => {
  console.log(`Rechnio läuft auf Port ${PORT}.`);
});
