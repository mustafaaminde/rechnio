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

// Zugangsdaten ausschließlich serverseitig aus Render lesen.
function getTestCredentials() {
  const email = String(
    process.env.RECHNIO_TEST_EMAIL ?? ""
  ).trim().toLowerCase();

  const password = String(
    process.env.RECHNIO_TEST_PASSWORD ?? ""
  ).trim();

  if (!email || !password) return null;

  return { email, password };
}

function safeEqual(leftValue, rightValue) {
  const left = Buffer.from(String(leftValue), "utf8");
  const right = Buffer.from(String(rightValue), "utf8");

  if (left.length !== right.length) return false;

  return crypto.timingSafeEqual(left, right);
}

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
      console.error(
        "index.html konnte nicht gelesen werden:",
        error.message
      );

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
    let tooLarge = false;

    request.on("data", chunk => {
      body += chunk;

      if (body.length > 10_000 && !tooLarge) {
        tooLarge = true;
        reject(new Error("Anfrage zu groß."));
      }
    });

    request.on("end", () => {
      if (tooLarge) return;
      if (!body) return resolve({});

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

  for (const part of String(
    request.headers.cookie || ""
  ).split(";")) {
    const index = part.indexOf("=");

    if (index < 0) continue;

    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (!name) continue;

    try {
      result[name] = decodeURIComponent(value);
    } catch {
      // Fehlerhafte Cookies ignorieren.
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
  return (
    `${SESSION_COOKIE}=${encodeURIComponent(token)}` +
    `; Path=/; Max-Age=${maxAgeSeconds}` +
    "; HttpOnly; Secure; SameSite=Lax"
  );
}

function clearSessionCookie() {
  return (
    `${SESSION_COOKIE}=; Path=/; Max-Age=0` +
    "; HttpOnly; Secure; SameSite=Lax"
  );
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

  // Hauptseite
  if (
    request.method === "GET" &&
    (url.pathname === "/" || url.pathname === "/reset-password")
  ) {
    serveIndex(response);
    return;
  }

  // Status des Dienstes
  if (
    request.method === "GET" &&
    url.pathname === "/api/health"
  ) {
    sendJson(response, 200, {
      ok: true,
      service: "Rechnio",
      authConfigured: Boolean(getTestCredentials()),
      emailConfigured: Boolean(
        process.env.RESEND_API_KEY &&
        process.env.EMAIL_FROM
      )
    });

    return;
  }

  // Aktuelle Anmeldung prüfen
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

  // Anmeldung
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

    const credentials = getTestCredentials();

    if (!credentials) {
      sendJson(response, 503, {
        error:
          "Der private Testzugang ist nicht vollständig konfiguriert. " +
          "Prüfe RECHNIO_TEST_EMAIL und RECHNIO_TEST_PASSWORD in Render."
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

    const email = String(body.email ?? "")
      .trim()
      .toLowerCase();

    const password = String(body.password ?? "");

    const emailMatches = email === credentials.email;
    const passwordMatches = safeEqual(
      password,
      credentials.password
    );

    if (!emailMatches || !passwordMatches) {
      // Keine Passwörter oder eingegebenen E-Mail-Adressen loggen.
      console.warn(
        "Rechnio-Testlogin abgelehnt:",
        `E-Mail passt: ${emailMatches},`,
        `Passwort passt: ${passwordMatches}`
      );

      sendJson(response, 401, {
        error:
          "E-Mail oder Passwort stimmt nicht. " +
          "Prüfe die Zugangsdaten in Render."
      });

      return;
    }

    loginAttempts.delete(clientIp(request));

    const token = crypto.randomBytes(32).toString("base64url");

    const session = {
      user: {
        id: "rechnio-private-test",
        email: credentials.email,
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

  // Registrierung ist im Test-Build deaktiviert.
  if (
    request.method === "POST" &&
    url.pathname === "/api/auth/register"
  ) {
    sendJson(response, 403, {
      error:
        "Die Registrierung ist für den privaten Testzugang deaktiviert."
    });

    return;
  }

  // Profil aktualisieren
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

    const name = String(body.name || "")
      .trim()
      .slice(0, 80);

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

  // E-Mail-Versand im aktuellen Test-Build deaktiviert.
  if (
    request.method === "POST" &&
    url.pathname === "/api/send-invoice"
  ) {
    sendJson(response, 503, {
      error:
        "Der Rechnungs-E-Mail-Versand ist in diesem Test-Build noch nicht aktiviert."
    });

    return;
  }

  if (url.pathname.startsWith("/api/auth/")) {
    sendJson(response, 501, {
      error:
        "Diese Authentifizierungsfunktion ist in diesem Test-Build nicht aktiviert."
    });

    return;
  }

  if (url.pathname.startsWith("/api/")) {
    sendJson(response, 404, {
      error:
        "Diese API-Funktion ist in diesem Test-Build nicht eingerichtet."
    });

    return;
  }

  if (
    request.method === "GET" &&
    url.pathname === "/favicon.ico"
  ) {
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
    console.error(
      "Rechnio-Anfrage fehlgeschlagen:",
      error.message
    );

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

// Hinweis:
// Test-Sitzungen werden im Arbeitsspeicher gespeichert und laufen
// nach 12 Stunden ab. Bei einem Neustart von Render gehen sie verloren.
// Dieser Test-Build ist nicht für echte Kundenkonten vorgesehen.
