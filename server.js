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
const COOKIE_NAME = "rn_session";
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const DEFAULT_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const REMEMBER_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const MAX_AUTH_ATTEMPTS = 10;
const MAX_EMAILS_PER_WINDOW = 10;

// Sitzungen liegen serverseitig im Arbeitsspeicher.
// Nach einem Render-Neustart müssen Benutzer sich erneut anmelden.
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

  if (
    /signup is disabled|signups not allowed|disable_signup/.test(message)
  ) {
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
  const now = Date
