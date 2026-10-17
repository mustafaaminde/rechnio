
"use strict";

const express = require("express");
const path = require("node:path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const INDEX_PATH = path.join(__dirname, "index.html");

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "100kb" }));

// Basis-Sicherheitsheader
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

function emailIsValid(email) {
  return (
    typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

function htmlEscape(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function getSupabaseConfig() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_ANON_KEY;

  if (!url || !key) {
    return null;
  }

  try {
    const parsed = new URL(url);

    if (
      !["https:", "http:"].includes(parsed.protocol) ||
      parsed.username ||
      parsed.password
    ) {
      return null;
    }

    return { url: url.replace(/\/+$/, ""), key };
  } catch {
    return null;
  }
}

function getSiteUrl() {
  try {
    const url = new URL(process.env.SITE_URL || "");

    if (url.protocol !== "https:" && url.hostname !== "localhost") {
      return null;
    }

    return url.origin;
  } catch {
    return null;
  }
}

// Supabase Auth API aufrufen
async function supabaseRequest(endpoint, options = {}) {
  const config = getSupabaseConfig();

  if (!config) {
    return { configured: false };
  }

  const headers = {
    apikey: config.key,
    "Content-Type": "application/json"
  };

  if (options.token) {
    headers.Authorization = `Bearer ${options.token}`;
  }

  const response = await fetch(
    `${config.url}/auth/v1/${endpoint}`,
    {
      method: options.method || "GET",
      headers,
      ...(options.body !== undefined
        ? { body: JSON.stringify(options.body) }
        : {})
    }
  );

  const data = await response.json().catch(() => ({}));

  return {
    configured: true,
    ok: response.ok,
    status: response.status,
    data
  };
}

// HTTP-only Cookies für die Anmeldung
function readCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";

  for (const item of cookieHeader.split(";")) {
    const separator = item.indexOf("=");

    if (separator < 0) continue;

    const key = item.slice(0, separator).trim();

    if (key === name) {
      try {
        return decodeURIComponent(item.slice(separator + 1).trim());
      } catch {
        return null;
      }
    }
  }

  return null;
}

function setSessionCookies(res, session) {
  if (!session.access_token || !session.refresh_token) {
    return;
  }

  const secure =
    process.env.NODE_ENV === "production" ? "; Secure" : "";

  const accessAge = Math.max(
    60,
    Math.min(Number(session.expires_in) || 3600, 86400)
  );

  const refreshAge = 60 * 60 * 24 * 30;

  res.setHeader("Set-Cookie", [
    `rn_access=${encodeURIComponent(session.access_token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${accessAge}${secure}`,
    `rn_refresh=${encodeURIComponent(session.refresh_token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${refreshAge}${secure}`
  ]);
}

function clearSessionCookies(res) {
  const secure =
    process.env.NODE_ENV === "production" ? "; Secure" : "";

  res.setHeader("Set-Cookie", [
    `rn_access=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`,
    `rn_refresh=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`
  ]);
}

// Benutzer ermitteln und abgelaufene Access-Tokens erneuern
async function getCurrentUser(req, res) {
  const accessToken = readCookie(req, "rn_access");
  const refreshToken = readCookie(req, "rn_refresh");

  if (accessToken) {
    const result = await supabaseRequest("user", {
      token: accessToken
    });

    if (result.ok) {
      return {
        user: result.data,
        token: accessToken
      };
    }
  }

  if (!refreshToken) {
    return null;
  }

  const refreshed = await supabaseRequest(
    "token?grant_type=refresh_token",
    {
      method: "POST",
      body: { refresh_token: refreshToken }
    }
  );

  if (!refreshed.ok || !refreshed.data.access_token) {
    clearSessionCookies(res);
    return null;
  }

  setSessionCookies(res, refreshed.data);

  return {
    user: refreshed.data.user,
    token: refreshed.data.access_token
  };
}

// Einfache IP-basierte Begrenzung für sensible Endpunkte
const attempts = new Map();

function rateLimit(maxRequests = 10, windowMs = 15 * 60 * 1000) {
  return (req, res, next) => {
    const key = `${req.path}:${req.ip}`;
    const now = Date.now();
    let entry = attempts.get(key);

    if (!entry || now - entry.start > windowMs) {
      entry = { start: now, count: 0 };
    }

    entry.count += 1;
    attempts.set(key, entry);

    if (entry.count > maxRequests) {
      res.setHeader(
        "Retry-After",
        String(Math.ceil(windowMs / 1000))
      );

      return res.status(429).json({
        error: "Zu viele Anfragen. Bitte versuche es später erneut."
      });
    }

    // Abgelaufene Einträge aufräumen
    for (const [storedKey, value] of attempts) {
      if (now - value.start > windowMs) {
        attempts.delete(storedKey);
      }
    }

    next();
  };
}

function authNotConfigured(res) {
  return res.status(503).json({
    error: "Die Kontoverwaltung ist noch nicht konfiguriert."
  });
}

// Diagnose: zeigt keine API-Schlüssel an
app.get("/api/health", (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  res.json({
    ok: true,
    service: "Rechnio",
    authConfigured: Boolean(getSupabaseConfig()),
    emailConfigured: Boolean(
      process.env.RESEND_API_KEY && process.env.EMAIL_FROM
    )
  });
});

// Startseite und Passwort-Reset-Seite
app.get(["/", "/reset-password"], (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(INDEX_PATH);
});

// Registrierung
app.post(
  "/api/auth/signup",
  rateLimit(),
  async (req, res) => {
    try {
      const { email, password } = req.body || {};

      if (!emailIsValid(email) ||
          typeof password !== "string" ||
          password.length < 10 ||
          password.length > 128) {
        return res.status(400).json({
          error: "Bitte prüfe deine E-Mail und dein Passwort. Das Passwort muss mindestens 10 Zeichen haben."
        });
      }

      const siteUrl = getSiteUrl();

      if (!siteUrl || !getSupabaseConfig()) {
        return authNotConfigured(res);
      }

      const result = await supabaseRequest(
        `signup?redirect_to=${encodeURIComponent(siteUrl)}`,
        {
          method: "POST",
          body: { email: email.trim(), password }
        }
      );

      if (!result.configured) return authNotConfigured(res);

      if (!result.ok) {
        return res.status(400).json({
          error: "Registrierung fehlgeschlagen. Bitte prüfe deine Eingaben."
        });
      }

      if (result.data.access_token) {
        setSessionCookies(res, result.data);
      }

      return res.status(201).json({
        ok: true,
        confirmationRequired: !result.data.access_token,
        message: result.data.access_token
          ? "Konto erstellt."
          : "Bitte prüfe deine E-Mails, um dein Konto zu bestätigen."
      });
    } catch (error) {
      console.error("Signup-Fehler:", error.message);

      return res.status(502).json({
        error: "Der Registrierungsdienst ist momentan nicht erreichbar."
      });
    }
  }
);

// Anmeldung
app.post(
  "/api/auth/login",
  rateLimit(),
  async (req, res) => {
    try {
      const { email, password } = req.body || {};

      if (!emailIsValid(email) ||
          typeof password !== "string" ||
          !password ||
          password.length > 128) {
        return res.status(400).json({
          error: "Bitte prüfe deine Anmeldedaten."
        });
      }

      const result = await supabaseRequest(
        "token?grant_type=password",
        {
          method: "POST",
          body: { email: email.trim(), password }
        }
      );

      if (!result.configured) return authNotConfigured(res);

      if (!result.ok || !result.data.access_token) {
        return res.status(401).json({
          error: "E-Mail oder Passwort ist nicht korrekt."
        });
      }

      setSessionCookies(res, result.data);

      return res.json({
        ok: true,
        user: {
          id: result.data.user.id,
          email: result.data.user.email
        }
      });
    } catch (error) {
      console.error("Login-Fehler:", error.message);

      return res.status(502).json({
        error: "Anmeldung derzeit nicht möglich."
      });
    }
  }
);

// Passwort-Zurücksetzungslink anfordern
app.post(
  "/api/auth/forgot-password",
  rateLimit(5),
  async (req, res) => {
    try {
      const { email } = req.body || {};

      if (!emailIsValid(email)) {
        return res.status(400).json({
          error: "Bitte gib eine gültige E-Mail-Adresse ein."
        });
      }

      const siteUrl = getSiteUrl();

      if (!siteUrl || !getSupabaseConfig()) {
        return authNotConfigured(res);
      }

      const redirectUrl = `${siteUrl}/reset-password`;

      const result = await supabaseRequest(
        `recover?redirect_to=${encodeURIComponent(redirectUrl)}`,
        {
          method: "POST",
          body: { email: email.trim() }
        }
      );

      if (!result.configured) return authNotConfigured(res);

      if (!result.ok) {
        console.error(
          "Passwort-Reset-Anfrage wurde vom Auth-Dienst abgelehnt."
        );

        return res.status(502).json({
          error: "Der Reset-Link konnte momentan nicht angefordert werden."
        });
      }

      return res.json({
        ok: true,
        message: "Falls ein Konto mit dieser E-Mail besteht, erhältst du einen Link zum Zurücksetzen."
      });
    } catch (error) {
      console.error("Passwort-Reset-Fehler:", error.message);

      return res.status(502).json({
        error: "Der Passwort-Reset ist momentan nicht erreichbar."
      });
    }
  }
);

// Neues Passwort setzen.
// accessToken erhält das Frontend aus dem bestätigten Reset-Link.
app.post(
  "/api/auth/reset-password",
  rateLimit(),
  async (req, res) => {
    try {
      const { accessToken, newPassword } = req.body || {};

      if (
        typeof accessToken !== "string" ||
        accessToken.length < 20 ||
        typeof newPassword !== "string" ||
        newPassword.length < 10 ||
        newPassword.length > 128
      ) {
        return res.status(400).json({
          error: "Der Reset-Link oder das neue Passwort ist ungültig."
        });
      }

      const result = await supabaseRequest("user", {
        method: "PUT",
        token: accessToken,
        body: { password: newPassword }
      });

      if (!result.configured) return authNotConfigured(res);

      if (!result.ok) {
        return res.status(400).json({
          error: "Das Passwort konnte nicht geändert werden. Fordere einen neuen Reset-Link an."
        });
      }

      return res.json({
        ok: true,
        message: "Dein Passwort wurde geändert. Melde dich jetzt an."
      });
    } catch (error) {
      console.error("Passwort-Änderungsfehler:", error.message);

      return res.status(502).json({
        error: "Das Passwort konnte momentan nicht geändert werden."
      });
    }
  }
);

// Aktuelles Konto abrufen
app.get("/api/account", async (req, res) => {
  try {
    const session = await getCurrentUser(req, res);

    if (!session) {
      return res.status(401).json({
        error: "Bitte melde dich erneut an."
      });
    }

    return res.json({
      id: session.user.id,
      email: session.user.email,
      emailConfirmed: Boolean(session.user.email_confirmed_at)
    });
  } catch (error) {
    console.error("Kontoabruf fehlgeschlagen:", error.message);

    return res.status(502).json({
      error: "Kontodaten sind momentan nicht verfügbar."
    });
  }
});

// Abmelden
app.post("/api/auth/logout", async (req, res) => {
  try {
    const token = readCookie(req, "rn_access");

    if (token) {
      await supabaseRequest("logout", {
        method: "POST",
        token
      });
    }

    clearSessionCookies(res);

    return res.json({ ok: true });
  } catch (error) {
    clearSessionCookies(res);

    return res.json({ ok: true });
  }
});

// Unbekannte API-Adressen klar beantworten
app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API-Endpunkt nicht gefunden."
  });
});

// Fehlerbehandlung
app.use((error, req, res, next) => {
  console.error("Serverfehler:", error.message);

  if (res.headersSent) return next(error);

  res.status(500).json({
    error: "Ein interner Serverfehler ist aufgetreten."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Rechnio läuft auf Port ${PORT}.`);
});
