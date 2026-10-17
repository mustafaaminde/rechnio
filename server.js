
"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const HOST = "0.0.0.0";
const PORT = Number(process.env.PORT || 3000);
const INDEX_PATH = path.join(__dirname, "index.html");
const SESSION_COOKIE = "rn_test_session";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

const sessions = new Map();
const loginAttempts = new Map();

function sendJson(response, statusCode, data, extraHeaders = {}) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...extraHeaders
  });

  response.end(JSON.stringify(data));
}

function serveIndex(response) {
  fs.readFile(INDEX_PATH, (error, contents) => {
    if (error) {
      console.error("index.html konnte nicht gelesen werden:", error.message);

      sendJson(response, 500, {
        error: "Rechnio konnte nicht geladen werden."
      });

      return;
    }

    response.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    });

    response.end(contents);
  });
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = "";

    request.on("data", chunk => {
      body += chunk;

      if (body.length > 10000) {
        reject(new Error("Anfrage zu groß."));
        request.destroy();
      }
    });

    request.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Ungültiges JSON."));
      }
    });

    request.on("error", reject);
  });
}

function cookies(request) {
  const result = {};

  for (const part of String(request.headers.cookie || "").split(";")) {
    const index = part.indexOf("=");

    if (index < 0) continue;

    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (name) {
      try {
        result[name] = decodeURIComponent(value);
      } catch {
        result[name] = "";
      }
    }
  }

  return result;
}

function getSession(request) {
  const token = cookies(request)[SESSION_COOKIE];

  if (!token) return null;

  const session = sessions.get(token);

  if (!session) return null;

  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }

  return { token, session };
}

function sessionCookie(token, maxAgeSeconds = 43200) {
  return [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    `Max-Age=${maxAgeSeconds}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ].join("; ");
}

function clearSessionCookie() {
  return [
    `${SESSION_COOKIE}=`,
    "Path=/",
    "Max-Age=0",
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ].join("; ");
}

function clientIp(request) {
  const forwarded = String(
    request.headers["x-forwarded-for"] || ""
  ).split(",")[0].trim();

  return forwarded || request.socket.remoteAddress || "unknown";
}

function isRateLimited(request) {
  const key = clientIp(request);
  const now = Date.now();
  const current = loginAttempts.get(key);

  if (!current || current.resetAt <= now) {
    loginAttempts.set(key, {
      count: 1,
      resetAt: now + 15 * 60 * 1000
    });

    return false;
  }

  current.count += 1;

  return current.count > 8;
}

function userFor(session) {
  return {
    id: session.user.id,
    email: session.user.email,
    name: session.user.name || ""
  };
}

async function handle(request, response) {
  let url;

  try {
    url = new URL(
      request.url || "/",
      `http://${request.headers.host || "localhost"}`
    );
  } catch {
    sendJson(response, 400, {
      error: "Die Anfrageadresse ist ungültig."
    });

    return;
  }

  // Rechnio-Oberfläche
  if (
    request.method === "GET" &&
    (url.pathname === "/" || url.pathname === "/reset-password")
  ) {
    serveIndex(response);
    return;
  }

  // Statusprüfung
  if (request.method === "GET" && url.pathname === "/api/health") {
    sendJson(response, 200, {
      ok: true,
      service: "Rechnio",
      authConfigured: Boolean(
        process.env.RECHNIO_TEST_EMAIL &&
        process.env.RECHNIO_TEST_PASSWORD
      ),
      emailConfigured: Boolean(
        process.env.RESEND_API_KEY &&
        process.env.EMAIL_FROM
      )
    });

    return;
  }

  // Bestehende Sitzung prüfen
  if (
    request.method === "GET" &&
    url.pathname === "/api/auth/me"
  ) {
    const found = getSession(request);

    if (!found) {
      sendJson(response, 401, {
        error: "Bitte melde dich an."
      });

      return;
    }

    sendJson(response, 200, {
      user: userFor(found.session)
    });

    return;
  }

  // Privater Test-Login
  if (
    request.method === "POST" &&
    url.pathname === "/api/auth/login"
  ) {
    if (isRateLimited(request)) {
      sendJson(response, 429, {
        error: "Zu viele Anmeldeversuche. Bitte warte 15 Minuten."
      });

      return;
    }

    const expectedEmail = process.env.RECHNIO_TEST_EMAIL;
    const expectedPassword = process.env.RECHNIO_TEST_PASSWORD;

    if (!expectedEmail || expectedPassword === undefined) {
      sendJson(response, 503, {
        error: "Der private Testzugang ist noch nicht konfiguriert."
      });

      return;
    }

    let body;

    try {
      body = await readJson(request);
    } catch (error) {
      sendJson(response, 400, {
        error: error.message || "Ungültige Anfrage."
      });

      return;
    }

    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password ?? "");
    const correctEmail = String(expectedEmail).trim().toLowerCase();
    const correctPassword = String(expectedPassword);

    // Keine Mindestlänge oder andere Passwortregeln.
    if (email !== correctEmail || password !== correctPassword) {
      sendJson(response, 401, {
        error: "E-Mail oder Passwort stimmt nicht."
      });

      return;
    }

    const token = crypto.randomBytes(32).toString("base64url");

    const session = {
      user: {
        id: "rechnio-private-test",
        email: correctEmail,
        name: "Rechnio Test"
      },
      expiresAt: Date.now() + SESSION_TTL_MS
    };

    sessions.set(token, session);

    sendJson(
      response,
      200,
      { user: userFor(session) },
      { "Set-Cookie": sessionCookie(token) }
    );

    return;
  }

  // Registrierung ist für diesen Testzugang deaktiviert.
  if (
    request.method === "POST" &&
    url.pathname === "/api/auth/register"
  ) {
    sendJson(response, 403, {
      error: "Die Registrierung ist für den privaten Testzugang deaktiviert."
    });

    return;
  }

  // Profilnamen speichern
  if (
    request.method === "POST" &&
    url.pathname === "/api/auth/profile"
  ) {
    const found = getSession(request);

    if (!found) {
      sendJson(response, 401, {
        error: "Bitte melde dich erneut an."
      });

      return;
    }

    let body;

    try {
      body = await readJson(request);
    } catch (error) {
      sendJson(response, 400, {
        error: error.message || "Ungültige Anfrage."
      });

      return;
    }

    const name = String(body.name || "").trim().slice(0, 80);

    if (name.length < 2) {
      sendJson(response, 400, {
        error: "Bitte gib mindestens zwei Zeichen als Namen ein."
      });

      return;
    }

    found.session.user.name = name;

    sendJson(response, 200, {
      user: userFor(found.session)
    });

    return;
  }

  // Abmelden
  if (
    request.method === "POST" &&
    url.pathname === "/api/auth/logout"
  ) {
    const found = getSession(request);

    if (found) {
      sessions.delete(found.token);
    }

    sendJson(
      response,
      200,
      { ok: true },
      { "Set-Cookie": clearSessionCookie() }
    );

    return;
  }

  // E-Mail-Versand ist in diesem Test-Build deaktiviert.
  if (
    request.method === "POST" &&
    url.pathname === "/api/send-invoice"
  ) {
    sendJson(response, 503, {
      error: "Der Rechnungs-E-Mail-Versand ist in diesem Test-Build nicht aktiviert."
    });

    return;
  }

  if (url.pathname.startsWith("/api/auth/")) {
    sendJson(response, 501, {
      error: "Diese Authentifizierungsfunktion ist nicht aktiviert."
    });

    return;
  }

  if (url.pathname.startsWith("/api/")) {
    sendJson(response, 404, {
      error: "Diese API-Funktion ist nicht eingerichtet."
    });

    return;
  }

  if (request.method === "GET" && url.pathname === "/favicon.ico") {
    response.writeHead(204, {
      "Cache-Control": "public, max-age=86400"
    });

    response.end();
    return;
  }

  sendJson(response, 404, {
    error: "Diese Seite ist nicht verfügbar."
  });
}

const server = http.createServer((request, response) => {
  Promise.resolve(handle(request, response)).catch(error => {
    console.error("Rechnio-Anfrage fehlgeschlagen:", error.message);

    if (!response.headersSent) {
      sendJson(response, 500, {
        error: "Interner Fehler. Bitte versuche es erneut."
      });
    } else {
      response.end();
    }
  });
});

server.on("error", error => {
  console.error("Serverfehler:", error.message);
  process.exitCode = 1;
});

server.listen(PORT, HOST, () => {
  console.log(`Rechnio läuft auf Port ${PORT}.`);
});
