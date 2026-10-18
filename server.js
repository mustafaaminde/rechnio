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

// Öffentliche Rechnio-Adresse für Bestätigungslinks.
// Verhindert, dass localhost als Produktionsziel verwendet wird.
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
const REMEMBER_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const MAX_AUTH_ATTEMPTS = 10;
const MAX_EMAILS_PER_WINDOW = 10;

// Sitzungen liegen im Arbeitsspeicher des Servers.
// Nach einem Render-Neustart muss man sich gegebenenfalls erneut anmelden.
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
      console.error(
        "index.html konnte nicht gelesen werden:",
        error.message
      );

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
        return resolve({});
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
    Authorization: `Bearer ${accessToken || config.key}`,
    Accept: "application/json",
    ...extraHeaders,
  };

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
  const message = String(
    result?.data?.msg ||
      result?.data?.message ||
      result?.data?.error_description ||
      result?.data?.error ||
      ""
  ).toLowerCase();

  if (
    /invalid login credentials|invalid credentials|email or password/.test(
      message
    )
  ) {
    return "E-Mail oder Passwort stimmt nicht.";
  }

  if (/email not confirmed|email_not_confirmed/.test(message)) {
    return "Bitte bestätige zuerst deine E-Mail-Adresse. Prüfe auch deinen Spam-Ordner.";
  }

  if (
    /already registered|user already exists|already been registered/.test(
      message
    )
  ) {
    return "Für diese E-Mail-Adresse existiert bereits ein Konto. Melde dich an oder verwende die Funktion zum Zurücksetzen des Passworts in Supabase.";
  }

  if (/password.*(weak|short|least)|weak_password/.test(message)) {
    return "Das Passwort ist zu schwach. Verwende ein längeres Passwort.";
  }

  if (/signup is disabled|signups not allowed|disable_signup/.test(message)) {
    return "Die Registrierung ist in Supabase deaktiviert. Aktiviere unter Authentication die Registrierung neuer Benutzer.";
  }

  if (/rate limit|too many requests/.test(message)) {
    return "Zu viele Versuche. Bitte warte etwas und versuche es erneut.";
  }

  if (result?.status === 400 || result?.status === 422) {
    return isSignup
      ? "Das Konto konnte nicht erstellt werden. Prüfe E-Mail, Passwort und die Supabase-Authentifizierungseinstellungen."
      : "E-Mail oder Passwort stimmt nicht.";
  }

  return isSignup
    ? "Das Konto konnte nicht erstellt werden. Prüfe die Supabase-Einstellungen."
    : "Die Anmeldung ist fehlgeschlagen. Bitte versuche es erneut.";
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
      result[name] = decodeURIComponent(
        part.slice(index + 1).trim()
      );
    } catch {
      result[name] = "";
    }
  }

  return result;
}

function cookieHeader(req, token, maxAgeSeconds) {
  const secure =
    req.headers["x-forwarded-proto"] === "https" ||
    PUBLIC_SITE_URL.startsWith("https://");

  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; Max-Age=${Math.max(
    0,
    maxAgeSeconds
  )}; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

function clearCookie(req) {
  const secure =
    req.headers["x-forwarded-proto"] === "https" ||
    PUBLIC_SITE_URL.startsWith("https://");

  return `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${
    secure ? "; Secure" : ""
  }`;
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

  const token = crypto.randomBytes(32).toString("base64url");

  const session = {
    user: normalizeUser(authData.user),
    accessToken: authData.access_token,
    refreshToken: authData.refresh_token,
    accessExpiresAt:
      Date.now() + Number(authData.expires_in || 3600) * 1000,
    cookieExpiresAt: Date.now() + ttl,
  };

  sessions.set(token, session);

  return {
    token,
    session,
    ttlSeconds: Math.floor(ttl / 1000),
  };
}

async function getSession(req) {
  const token = parseCookies(req)[COOKIE_NAME];

  if (!token) return null;

  const session = sessions.get(token);

  if (!session || session.cookieExpiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }

  let refreshed = false;

  if (session.accessExpiresAt <= Date.now() + 45_000) {
    const result = await supabaseRequest(
      "/auth/v1/token?grant_type=refresh_token",
      {
        method: "POST",
        body: { refresh_token: session.refreshToken },
      }
    );

    if (
      !result.ok ||
      !result.data?.access_token ||
      !result.data?.refresh_token
    ) {
      sessions.delete(token);
      return null;
    }

    session.accessToken = result.data.access_token;
    session.refreshToken = result.data.refresh_token;
    session.accessExpiresAt =
      Date.now() + Number(result.data.expires_in || 3600) * 1000;

    if (result.data.user) {
      session.user = normalizeUser(result.data.user);
    }

    refreshed = true;
  }

  return { token, session, refreshed };
}

function authResponse(
  res,
  req,
  status,
  data,
  found = null,
  extraHeaders = {}
) {
  const headers = { ...extraHeaders };

  if (found?.refreshed) {
    headers["Set-Cookie"] = cookieHeader(
      req,
      found.token,
      Math.floor(
        (found.session.cookieExpiresAt - Date.now()) / 1000
      )
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
  const match = String(value || "").match(/^(\d{4})-(\d{2})-(\d{2})/);

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
      (row) =>
        `<tr>
          <td style="padding:10px;border-bottom:1px solid #e5e7eb">${h(
            row.description
          )}</td>
          <td style="padding:10px;text-align:right;border-bottom:1px solid #e5e7eb">${h(
            row.quantity
          )}</td>
          <td style="padding:10px;text-align:right;border-bottom:1px solid #e5e7eb">${money(
            row.price
          )}</td>
          <td style="padding:10px;text-align:right;border-bottom:1px solid #e5e7eb">${h(
            row.vat
          )} %</td>
          <td style="padding:10px;text-align:right;border-bottom:1px solid #e5e7eb">${money(
            row.net
          )}</td>
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
            <p style="font-size:13px;line-height:1.7">${
              companyInfo || "Angaben zum Rechnungssteller fehlen."
            }</p>
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
          <div><strong>Rechnungsdatum</strong><br>${displayDate(
            invoice.issueDate
          )}</div>
          <div><strong>Fällig am</strong><br>${displayDate(
            invoice.dueDate
          )}</div>
          ${
            invoice.serviceDate
              ? `<div><strong>Leistungsdatum</strong><br>${displayDate(
                  invoice.serviceDate
                )}</div>`
              : invoice.servicePeriod
              ? `<div><strong>Leistungszeitraum</strong><br>${h(
                  invoice.servicePeriod
                )}</div>`
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
            ? `<p style="font-size:13px;line-height:1.6;margin-top:24px"><strong>Bankverbindung:</strong> ${h(
                company.iban
              )}</p>`
            : ""
        }

        ${
          notes
            ? `<p style="font-size:13px;line-height:1.6;margin-top:18px"><strong>Hinweis:</strong><br>${h(
                notes
              ).replace(/\n/g, "<br>")}</p>`
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
