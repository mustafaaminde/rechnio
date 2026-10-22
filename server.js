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
const teamInviteAttempts = new Map();

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


// Organisationszugriff für Mitarbeiterkonten. Admin-Schlüssel bleiben ausschließlich auf dem Server.
function supabaseAdminConfig() {
  const base = supabaseConfig();
  const key = String(
    process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || ""
  ).trim();
  return base && key ? { url: base.url, key } : null;
}

async function supabaseAdminRequest(endpoint, { method = "GET", body, extraHeaders = {} } = {}) {
  const config = supabaseAdminConfig();
  if (!config) {
    return { ok: false, status: 503, data: { message: "Der serverseitige Supabase-Schlüssel fehlt." } };
  }
  const headers = {
    apikey: config.key,
    Authorization: `Bearer ${config.key}`,
    Accept: "application/json",
    ...extraHeaders,
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  try {
    const response = await fetch(`${config.url}${endpoint}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { ok: response.ok, status: response.status, data: await readResponse(response) };
  } catch (error) {
    return { ok: false, status: 502, data: { message: `Supabase ist nicht erreichbar: ${error.message}` } };
  }
}

function firstRow(data) {
  return Array.isArray(data) ? (data[0] || null) : (data && typeof data === "object" ? data : null);
}

function restFilter(value) {
  return encodeURIComponent(String(value ?? ""));
}

function isMissingDatabaseObject(result, name) {
  const message = String(result?.data?.message || result?.data?.details || result?.data?.hint || "");
  return result?.status === 404 || new RegExp(`${name}|schema cache|does not exist`, "i").test(message);
}

function readableDatabaseError(result, fallback) {
  const code = String(result?.data?.code || "");
  if (isMissingDatabaseObject(result, "rechnio_organization_state|rechnio_memberships|rechnio_organizations|rechnio_invitations")) {
    return "Die Mitarbeiterkonto-Datenbank ist noch nicht vollständig eingerichtet. Führe das aktualisierte Mitarbeiterkonto-SQL in Supabase aus.";
  }
  if (code === "23505") return "Dieser Eintrag existiert bereits.";
  return fallback;
}

async function getMembershipsForUser(userId) {
  return supabaseAdminRequest(
    `/rest/v1/rechnio_memberships?select=organization_id,user_id,email,role,created_at&user_id=eq.${restFilter(userId)}&order=created_at.asc&limit=20`
  );
}

async function getOrganization(organizationId) {
  const result = await supabaseAdminRequest(
    `/rest/v1/rechnio_organizations?select=id,name&id=eq.${restFilter(organizationId)}&limit=1`
  );
  if (!result.ok) throw new Error(readableDatabaseError(result, "Der Unternehmensbereich konnte nicht geladen werden."));
  return firstRow(result.data);
}

async function getOrganizationState(organizationId) {
  const result = await supabaseAdminRequest(
    `/rest/v1/rechnio_organization_state?select=state,updated_at&organization_id=eq.${restFilter(organizationId)}&limit=1`
  );
  if (!result.ok) throw new Error(readableDatabaseError(result, "Die gemeinsamen Unternehmensdaten konnten nicht geladen werden."));
  return firstRow(result.data);
}

function mergeRecordsWithoutDeleting(previousValues, submittedValues) {
  const previous = Array.isArray(previousValues) ? previousValues : [];
  const submitted = Array.isArray(submittedValues) ? submittedValues : [];
  const map = new Map();
  for (const item of previous) {
    if (item && item.id) map.set(String(item.id), item);
  }
  for (const item of submitted) {
    if (item && item.id) map.set(String(item.id), item);
  }
  return Array.from(map.values());
}

async function upsertOrganizationState(organizationId, userId, stateValue) {
  const result = await supabaseAdminRequest(
    `/rest/v1/rechnio_organization_state?on_conflict=organization_id`,
    {
      method: "POST",
      extraHeaders: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: {
        organization_id: organizationId,
        state: stateValue,
        updated_by: userId,
        updated_at: new Date().toISOString(),
      },
    }
  );
  if (!result.ok) throw new Error(readableDatabaseError(result, "Die gemeinsamen Unternehmensdaten konnten nicht gespeichert werden."));
}

async function ensureOrganizationMembership(user) {
  if (!supabaseAdminConfig()) {
    throw new Error("Mitarbeiterkonten benötigen einen Supabase-Secret-Key in Render. Die bisherige Anmeldung bleibt davon getrennt.");
  }
  const existing = await getMembershipsForUser(user.id);
  if (!existing.ok) throw new Error(readableDatabaseError(existing, "Deine Unternehmenszugehörigkeit konnte nicht geprüft werden."));
  const memberships = Array.isArray(existing.data) ? existing.data : [];
  if (memberships.length) {
    const membership = memberships[0];
    const organization = await getOrganization(membership.organization_id);
    if (!organization) throw new Error("Der zugehörige Unternehmensbereich wurde nicht gefunden. Bitte wende dich an den Rechnio-Administrator.");
    return { membership, organization };
  }

  // Ein entfernter Mitarbeiter darf nicht automatisch einen neuen Inhaberbereich erzeugen und so
  // die zuvor geladenen Unternehmensdaten erneut als eigenen Bereich speichern.
  const acceptedInvite = await supabaseAdminRequest(
    `/rest/v1/rechnio_invitations?select=id&accepted_by=eq.${restFilter(user.id)}&status=eq.accepted&limit=1`
  );
  if (!acceptedInvite.ok) throw new Error(readableDatabaseError(acceptedInvite, "Deine Unternehmenszugehörigkeit konnte nicht geprüft werden."));
  if (Array.isArray(acceptedInvite.data) && acceptedInvite.data.length) {
    const error = new Error("Dein Zugriff auf den bisherigen Unternehmensbereich wurde entfernt. Bitte den Inhaber kontaktieren, falls du wieder Zugang brauchst.");
    error.statusCode = 403;
    throw error;
  }

  const email = String(user.email || "").trim().toLowerCase();
  const displayName = String(user.name || "").trim();
  const organizationName = displayName ? `${displayName}s Unternehmen`.slice(0, 160) : "Mein Unternehmen";
  const createdOrg = await supabaseAdminRequest("/rest/v1/rechnio_organizations", {
    method: "POST",
    extraHeaders: { Prefer: "return=representation" },
    body: { name: organizationName, created_by: user.id },
  });
  if (!createdOrg.ok) throw new Error(readableDatabaseError(createdOrg, "Der Unternehmensbereich konnte nicht erstellt werden."));
  const organization = firstRow(createdOrg.data);
  if (!organization?.id) throw new Error("Supabase hat keinen Unternehmensbereich zurückgegeben.");

  const addedMembership = await supabaseAdminRequest("/rest/v1/rechnio_memberships", {
    method: "POST",
    extraHeaders: { Prefer: "return=representation" },
    body: { organization_id: organization.id, user_id: user.id, email, role: "owner" },
  });
  if (!addedMembership.ok) {
    // Falls zwei Anfragen gleichzeitig erstmals angemeldet wurden, bereits erstellte Mitgliedschaft erneut suchen.
    const retry = await getMembershipsForUser(user.id);
    const retryMembership = firstRow(retry.data);
    if (!retry.ok || !retryMembership) {
      throw new Error(readableDatabaseError(addedMembership, "Die Inhabermitgliedschaft konnte nicht eingerichtet werden."));
    }
    const retryOrganization = await getOrganization(retryMembership.organization_id);
    return { membership: retryMembership, organization: retryOrganization };
  }
  const membership = firstRow(addedMembership.data) || {
    organization_id: organization.id, user_id: user.id, email, role: "owner",
  };

  // Vorhandene persönliche Rechnio-Daten einmalig in den neuen gemeinsamen Bereich übernehmen.
  const legacy = await supabaseAdminRequest(
    `/rest/v1/rechnio_user_state?select=state&user_id=eq.${restFilter(user.id)}&limit=1`
  );
  if (legacy.ok) {
    const legacyState = firstRow(legacy.data)?.state;
    if (legacyState && typeof legacyState === "object" && !Array.isArray(legacyState)) {
      await upsertOrganizationState(organization.id, user.id, legacyState);
    }
  } else if (!isMissingDatabaseObject(legacy, "rechnio_user_state")) {
    console.warn("Rechnio legacy state migration skipped because the old data could not be read.");
  }
  return { membership, organization };
}

async function requireOwnerContext(found) {
  const context = await ensureOrganizationMembership(found.session.user);
  if (context.membership.role !== "owner") {
    const error = new Error("Nur der Inhaber kann Mitarbeiterkonten verwalten.");
    error.statusCode = 403;
    throw error;
  }
  return context;
}

async function findInvitationByToken(token) {
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const result = await supabaseAdminRequest(
    `/rest/v1/rechnio_invitations?select=id,organization_id,invited_by,email,status,expires_at,created_at,accepted_by,accepted_at&token_hash=eq.${restFilter(tokenHash)}&limit=1`
  );
  if (!result.ok) throw new Error(readableDatabaseError(result, "Die Einladung konnte nicht geprüft werden."));
  return firstRow(result.data);
}

function validInviteToken(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{35,100}$/.test(value);
}

function inviteEmailHtml({ email, organizationName, inviteUrl }) {
  return `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#18212f;line-height:1.6"><div style="max-width:560px;margin:24px auto;padding:24px;border:1px solid #e5e7eb;border-radius:14px"><h1 style="font-size:24px;margin:0 0 12px">Du wurdest zu Rechnio eingeladen</h1><p>Du wurdest eingeladen, als Mitarbeiter bei <strong>${h(organizationName)}</strong> mitzuarbeiten.</p><p>Die Einladung gilt für <strong>${h(email)}</strong> und läuft nach sieben Tagen ab.</p><p style="margin:28px 0"><a href="${h(inviteUrl)}" style="background:#192335;color:white;text-decoration:none;padding:12px 18px;border-radius:9px;display:inline-block">Einladung annehmen</a></p><p>Öffne den Link, erstelle bei Bedarf dein Rechnio-Konto und bestätige die Einladung. Teile diesen Link nicht mit anderen.</p></div></body></html>`;
}

async function sendTeamInvitationEmail({ email, organizationName, inviteUrl }) {
  const apiKey = String(process.env.RESEND_API_KEY || "").trim();
  const from = String(process.env.EMAIL_FROM || "").trim();
  if (!apiKey || !from) return { sent: false, reason: "Der E-Mail-Dienst ist noch nicht vollständig eingerichtet." };
  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from,
        to: [email],
        subject: `Einladung zu Rechnio – ${organizationName}`,
        html: inviteEmailHtml({ email, organizationName, inviteUrl }),
      }),
    });
    const payload = await readResponse(response);
    if (!response.ok) {
      console.warn("Rechnio invitation email rejected by provider:", response.status);
      return { sent: false, reason: "Resend konnte die Einladungs-E-Mail nicht senden. Prüfe dort deine verifizierte Absenderadresse." };
    }
    return { sent: true, id: payload.id || null };
  } catch (error) {
    console.warn("Rechnio invitation email failed:", error.message);
    return { sent: false, reason: "Der E-Mail-Dienst ist momentan nicht erreichbar." };
  }
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
      teamConfigured: Boolean(supabaseAdminConfig()),
    });

    return;
  }

  // Öffentliche Einladungsvorschau: Der zufällige Token ist der Nachweis der Einladung.
  if (req.method === "GET" && route === "/api/team/invitation") {
    if (!supabaseAdminConfig()) {
      sendJson(res, 503, { error: "Die Mitarbeiterkonto-Funktion ist noch nicht vollständig eingerichtet." });
      return;
    }
    const token = String(url.searchParams.get("token") || "");
    if (!validInviteToken(token)) {
      sendJson(res, 400, { error: "Der Einladungslink ist ungültig." });
      return;
    }
    try {
      const invitation = await findInvitationByToken(token);
      if (!invitation || invitation.status !== "pending") {
        sendJson(res, 410, { error: "Diese Einladung ist nicht mehr gültig. Bitte den Inhaber um eine neue Einladung." });
        return;
      }
      if (Date.parse(invitation.expires_at) <= Date.now()) {
        await supabaseAdminRequest(
          `/rest/v1/rechnio_invitations?id=eq.${restFilter(invitation.id)}`,
          { method: "PATCH", body: { status: "expired" }, extraHeaders: { Prefer: "return=minimal" } }
        );
        sendJson(res, 410, { error: "Diese Einladung ist abgelaufen. Bitte den Inhaber um eine neue Einladung." });
        return;
      }
      const organization = await getOrganization(invitation.organization_id);
      sendJson(res, 200, { email: invitation.email, organizationName: organization?.name || "Rechnio-Unternehmen", expiresAt: invitation.expires_at });
    } catch (error) {
      sendJson(res, error.statusCode || 503, { error: error.message || "Die Einladung konnte nicht geprüft werden." });
    }
    return;
  }

  if (req.method === "POST" && route === "/api/auth/password-reset") {
    const limitKey = `${requestIp(req)}:password-reset`;
    if (isRateLimited(authAttempts, limitKey, MAX_AUTH_ATTEMPTS)) {
      sendJson(res, 429, { error: "Zu viele Anfragen. Bitte warte 15 Minuten und versuche es erneut." });
      return;
    }
    if (!supabaseConfig()) {
      sendJson(res, 503, { error: "Der Passwort-Dienst ist nicht konfiguriert. Prüfe SUPABASE_URL und SUPABASE_ANON_KEY in Render." });
      return;
    }
    let body;
    try { body = await readJson(req); }
    catch (error) { sendJson(res, 400, { error: error.message }); return; }
    const email = String(body.email || "").trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      sendJson(res, 400, { error: "Bitte gib eine gültige E-Mail-Adresse ein." });
      return;
    }
    const redirectTo = `${PUBLIC_SITE_URL}/reset-password`;
    const result = await supabaseRequest(`/auth/v1/recover?redirect_to=${encodeURIComponent(redirectTo)}`, {
      method: "POST",
      body: { email },
    });
    if (!result.ok) {
      console.warn("Supabase password recovery request rejected", { status: result.status, code: String(result.data?.code || result.data?.error || "unknown").slice(0, 80) });
      sendJson(res, result.status === 429 ? 429 : 502, { error: result.status === 429 ? "Zu viele Anfragen. Bitte warte etwas und versuche es erneut." : "Der Passwort-Link konnte gerade nicht angefordert werden. Prüfe die Supabase-E-Mail-Einstellungen und versuche es erneut." });
      return;
    }
    sendJson(res, 200, { ok: true, message: "Falls ein Konto mit dieser E-Mail-Adresse existiert, erhältst du einen Link zum Zurücksetzen des Passworts." });
    return;
  }

  if (req.method === "POST" && route === "/api/auth/password-recovery-verify") {
    const limitKey = `${requestIp(req)}:password-recovery-verify`;
    if (isRateLimited(authAttempts, limitKey, MAX_AUTH_ATTEMPTS)) {
      sendJson(res, 429, { error: "Zu viele Versuche. Bitte fordere einen neuen Passwort-Link an." });
      return;
    }
    if (!supabaseConfig()) {
      sendJson(res, 503, { error: "Der Passwort-Dienst ist nicht konfiguriert. Prüfe SUPABASE_URL und SUPABASE_ANON_KEY in Render." });
      return;
    }
    let body;
    try { body = await readJson(req); }
    catch (error) { sendJson(res, 400, { error: error.message }); return; }
    const tokenHash = String(body.tokenHash || "").trim();
    if (!/^[A-Za-z0-9_-]{20,200}$/.test(tokenHash)) {
      sendJson(res, 400, { error: "Der Passwort-Link ist ungültig oder abgelaufen. Fordere bitte einen neuen Link an." });
      return;
    }
    const result = await supabaseRequest("/auth/v1/verify", {
      method: "POST",
      body: { token_hash: tokenHash, type: "recovery" },
    });
    if (!result.ok || !result.data?.access_token) {
      console.warn("Supabase recovery token verification rejected", {
        status: result.status,
        code: String(result.data?.code || result.data?.error_code || result.data?.error || "unknown").slice(0, 80),
        reason: String(result.data?.msg || result.data?.message || result.data?.error_description || result.data?.hint || "").replace(/[\r\n]+/g, " ").slice(0, 160),
      });
      sendJson(res, result.status === 429 ? 429 : 400, {
        error: result.status === 429
          ? "Zu viele Versuche. Bitte warte etwas und fordere danach einen neuen Link an."
          : "Der Passwort-Link ist ungültig, wurde bereits verwendet oder ist abgelaufen. Fordere bitte einen neuen Link an.",
      });
      return;
    }
    sendJson(res, 200, { accessToken: result.data.access_token });
    return;
  }

  if (req.method === "POST" && route === "/api/auth/password-update") {
    if (!supabaseConfig()) {
      sendJson(res, 503, { error: "Der Passwort-Dienst ist nicht konfiguriert. Prüfe die Supabase-Einstellungen in Render." });
      return;
    }
    let body;
    try { body = await readJson(req); }
    catch (error) { sendJson(res, 400, { error: error.message }); return; }
    const accessToken = String(body.accessToken || "").trim();
    const password = String(body.password ?? "");
    if (!accessToken || accessToken.length > 10000) {
      sendJson(res, 400, { error: "Der Passwort-Link ist ungültig oder abgelaufen. Fordere bitte einen neuen Link an." });
      return;
    }
    if (password.length < 8 || password.length > 256) {
      sendJson(res, 400, { error: "Das Passwort muss mindestens 8 Zeichen enthalten." });
      return;
    }
    const result = await supabaseRequest("/auth/v1/user", {
      method: "PUT",
      accessToken,
      body: { password },
    });
    if (!result.ok) {
      console.warn("Supabase password update rejected", {
        status: result.status,
        code: String(result.data?.code || result.data?.error_code || result.data?.error || "unknown").slice(0, 80),
        reason: String(result.data?.msg || result.data?.message || result.data?.error_description || result.data?.hint || "").replace(/[\r\n]+/g, " ").slice(0, 160),
      });
      sendJson(res, result.status === 429 ? 429 : 400, { error: result.status === 429 ? "Zu viele Versuche. Bitte warte etwas und versuche es erneut." : "Der Link ist ungültig oder abgelaufen. Fordere bitte einen neuen Passwort-Link an." });
      return;
    }
    sendJson(res, 200, { ok: true });
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
    const rememberRequested = body.remember === true;
    // Persistent cookies need SESSION_SECRET. If it is missing, use a normal session instead
    // of rejecting an otherwise valid login or registration.
    const remember = rememberRequested && hasPersistentSessionSecret();

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

    const inviteToken = signup && validInviteToken(String(body.inviteToken || ""))
      ? String(body.inviteToken)
      : "";
    const inviteRedirectParam = inviteToken ? `&invite=${encodeURIComponent(inviteToken)}` : "";
    const confirmationDestination =
      `${PUBLIC_SITE_URL}/auth/confirmed?remember=${remember ? "1" : "0"}${inviteRedirectParam}`;

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
      { user: opened.session.user, rememberUnavailable: rememberRequested && !remember },
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
    const rememberRequested = body.remember === true;
    const remember = rememberRequested && hasPersistentSessionSecret();

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
        { ok: true, user: opened.session.user, rememberUnavailable: rememberRequested && !remember },
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

  // Mitarbeiter-Einladungen und Rollen werden nur mit einer gültigen Session und serverseitig geprüft.
  if (route.startsWith("/api/team") && route !== "/api/team/invitation") {
    const found = await getSession(req);
    if (!found) {
      sendJson(res, 401, { error: "Bitte melde dich an." });
      return;
    }
    if (!supabaseAdminConfig()) {
      authResponse(res, req, 503, {
        error: "Die Mitarbeiterkonto-Funktion benötigt SUPABASE_SECRET_KEY (oder SUPABASE_SERVICE_ROLE_KEY) in Render sowie das aktualisierte SQL in Supabase."
      }, found);
      return;
    }

    if (req.method === "GET" && route === "/api/team") {
      try {
        const context = await requireOwnerContext(found);
        const orgId = context.organization.id;
        const [membersResult, invitesResult] = await Promise.all([
          supabaseAdminRequest(`/rest/v1/rechnio_memberships?select=user_id,email,role,created_at&organization_id=eq.${restFilter(orgId)}&order=created_at.asc`),
          supabaseAdminRequest(`/rest/v1/rechnio_invitations?select=id,email,status,expires_at,created_at&organization_id=eq.${restFilter(orgId)}&status=eq.pending&order=created_at.desc`),
        ]);
        if (!membersResult.ok) throw new Error(readableDatabaseError(membersResult, "Die Mitarbeiterliste konnte nicht geladen werden."));
        if (!invitesResult.ok) throw new Error(readableDatabaseError(invitesResult, "Die Einladungen konnten nicht geladen werden."));
        authResponse(res, req, 200, {
          membership: { enabled: true, role: context.membership.role, organizationId: orgId, organizationName: context.organization.name },
          members: Array.isArray(membersResult.data) ? membersResult.data : [],
          invitations: Array.isArray(invitesResult.data) ? invitesResult.data : [],
        }, found);
      } catch (error) {
        authResponse(res, req, error.statusCode || 503, { error: error.message || "Die Mitarbeiterverwaltung konnte nicht geladen werden." }, found);
      }
      return;
    }

    if (req.method === "POST" && route === "/api/team/invitations") {
      if (isRateLimited(teamInviteAttempts, found.session.user.id, 10)) {
        authResponse(res, req, 429, { error: "Du hast viele Einladungen erstellt. Bitte warte 15 Minuten." }, found);
        return;
      }
      let body;
      try { body = await readJson(req); }
      catch (error) { authResponse(res, req, 400, { error: error.message }, found); return; }
      const email = String(body.email || "").trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
        authResponse(res, req, 400, { error: "Bitte gib eine gültige E-Mail-Adresse ein." }, found);
        return;
      }
      try {
        const context = await requireOwnerContext(found);
        if (email === String(found.session.user.email || "").toLowerCase()) {
          authResponse(res, req, 400, { error: "Du kannst dich nicht selbst als Mitarbeiter einladen." }, found);
          return;
        }
        const existingMember = await supabaseAdminRequest(
          `/rest/v1/rechnio_memberships?select=user_id,email&organization_id=eq.${restFilter(context.organization.id)}&email=eq.${restFilter(email)}&limit=1`
        );
        if (!existingMember.ok) throw new Error(readableDatabaseError(existingMember, "Die Mitgliedschaft konnte nicht geprüft werden."));
        if (Array.isArray(existingMember.data) && existingMember.data.length) {
          authResponse(res, req, 409, { error: "Diese E-Mail-Adresse gehört bereits zu einem Mitglied dieses Unternehmens." }, found);
          return;
        }
        const existingInvite = await supabaseAdminRequest(
          `/rest/v1/rechnio_invitations?select=id&organization_id=eq.${restFilter(context.organization.id)}&email=eq.${restFilter(email)}&status=eq.pending&limit=1`
        );
        if (!existingInvite.ok) throw new Error(readableDatabaseError(existingInvite, "Vorhandene Einladungen konnten nicht geprüft werden."));
        if (Array.isArray(existingInvite.data) && existingInvite.data.length) {
          authResponse(res, req, 409, { error: "Für diese E-Mail gibt es bereits eine offene Einladung. Widerrufe sie zuerst oder verwende den vorhandenen Link." }, found);
          return;
        }

        const token = crypto.randomBytes(32).toString("base64url");
        const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
        const inserted = await supabaseAdminRequest("/rest/v1/rechnio_invitations", {
          method: "POST",
          extraHeaders: { Prefer: "return=representation" },
          body: {
            organization_id: context.organization.id,
            invited_by: found.session.user.id,
            email,
            token_hash: tokenHash,
            status: "pending",
            expires_at: expiresAt,
          },
        });
        if (!inserted.ok) throw new Error(readableDatabaseError(inserted, "Die Einladung konnte nicht erstellt werden."));
        const inviteUrl = `${PUBLIC_SITE_URL}/?invite=${encodeURIComponent(token)}`;
        const mail = await sendTeamInvitationEmail({ email, organizationName: context.organization.name, inviteUrl });
        authResponse(res, req, 201, {
          ok: true,
          inviteUrl,
          emailSent: mail.sent,
          message: mail.sent ? "Einladung erstellt und per E-Mail versendet." : `Einladung erstellt, E-Mail aber nicht versendet. ${mail.reason || "Teile den Link manuell mit der eingeladenen Person."}`,
        }, found);
      } catch (error) {
        authResponse(res, req, error.statusCode || 503, { error: error.message || "Die Einladung konnte nicht erstellt werden." }, found);
      }
      return;
    }

    if (req.method === "POST" && route === "/api/team/invitations/revoke") {
      let body;
      try { body = await readJson(req); }
      catch (error) { authResponse(res, req, 400, { error: error.message }, found); return; }
      const invitationId = String(body.invitationId || "").trim();
      if (!invitationId) { authResponse(res, req, 400, { error: "Die Einladung fehlt." }, found); return; }
      try {
        const context = await requireOwnerContext(found);
        const updated = await supabaseAdminRequest(
          `/rest/v1/rechnio_invitations?id=eq.${restFilter(invitationId)}&organization_id=eq.${restFilter(context.organization.id)}&status=eq.pending`,
          { method: "PATCH", body: { status: "revoked" }, extraHeaders: { Prefer: "return=representation" } }
        );
        if (!updated.ok) throw new Error(readableDatabaseError(updated, "Die Einladung konnte nicht widerrufen werden."));
        if (!Array.isArray(updated.data) || !updated.data.length) {
          authResponse(res, req, 404, { error: "Die offene Einladung wurde nicht gefunden." }, found);
          return;
        }
        authResponse(res, req, 200, { ok: true }, found);
      } catch (error) {
        authResponse(res, req, error.statusCode || 503, { error: error.message || "Die Einladung konnte nicht widerrufen werden." }, found);
      }
      return;
    }

    if (req.method === "POST" && route === "/api/team/members/remove") {
      let body;
      try { body = await readJson(req); }
      catch (error) { authResponse(res, req, 400, { error: error.message }, found); return; }
      const userId = String(body.userId || "").trim();
      if (!userId || userId === found.session.user.id) {
        authResponse(res, req, 400, { error: "Du kannst dein eigenes Inhaberkonto hier nicht entfernen." }, found);
        return;
      }
      try {
        const context = await requireOwnerContext(found);
        const targetResult = await supabaseAdminRequest(
          `/rest/v1/rechnio_memberships?select=user_id,role&organization_id=eq.${restFilter(context.organization.id)}&user_id=eq.${restFilter(userId)}&limit=1`
        );
        if (!targetResult.ok) throw new Error(readableDatabaseError(targetResult, "Das Mitglied konnte nicht geprüft werden."));
        const target = firstRow(targetResult.data);
        if (!target || target.role !== "employee") {
          authResponse(res, req, 404, { error: "Dieses Mitarbeiterkonto wurde nicht gefunden." }, found);
          return;
        }
        const removed = await supabaseAdminRequest(
          `/rest/v1/rechnio_memberships?organization_id=eq.${restFilter(context.organization.id)}&user_id=eq.${restFilter(userId)}&role=eq.employee`,
          { method: "DELETE", extraHeaders: { Prefer: "return=minimal" } }
        );
        if (!removed.ok) throw new Error(readableDatabaseError(removed, "Der Mitarbeiter konnte nicht entfernt werden."));
        authResponse(res, req, 200, { ok: true }, found);
      } catch (error) {
        authResponse(res, req, error.statusCode || 503, { error: error.message || "Der Mitarbeiter konnte nicht entfernt werden." }, found);
      }
      return;
    }

    if (req.method === "POST" && route === "/api/team/accept") {
      let body;
      try { body = await readJson(req); }
      catch (error) { authResponse(res, req, 400, { error: error.message }, found); return; }
      const token = String(body.token || "");
      if (!validInviteToken(token)) { authResponse(res, req, 400, { error: "Der Einladungslink ist ungültig." }, found); return; }
      try {
        const invitation = await findInvitationByToken(token);
        if (!invitation || invitation.status !== "pending") {
          authResponse(res, req, 410, { error: "Diese Einladung ist nicht mehr gültig. Bitte den Inhaber um eine neue Einladung." }, found);
          return;
        }
        if (Date.parse(invitation.expires_at) <= Date.now()) {
          await supabaseAdminRequest(`/rest/v1/rechnio_invitations?id=eq.${restFilter(invitation.id)}`, {
            method: "PATCH", body: { status: "expired" }, extraHeaders: { Prefer: "return=minimal" },
          });
          authResponse(res, req, 410, { error: "Diese Einladung ist abgelaufen. Bitte den Inhaber um eine neue Einladung." }, found);
          return;
        }
        const user = found.session.user;
        if (String(user.email || "").trim().toLowerCase() !== String(invitation.email || "").trim().toLowerCase()) {
          authResponse(res, req, 403, { error: `Melde dich mit ${invitation.email} an, damit die Einladung dem richtigen Konto zugeordnet wird.` }, found);
          return;
        }
        const membershipsResult = await getMembershipsForUser(user.id);
        if (!membershipsResult.ok) throw new Error(readableDatabaseError(membershipsResult, "Deine bestehende Unternehmenszugehörigkeit konnte nicht geprüft werden."));
        const memberships = Array.isArray(membershipsResult.data) ? membershipsResult.data : [];
        const sameOrg = memberships.find(m => m.organization_id === invitation.organization_id);
        const otherOrg = memberships.find(m => m.organization_id !== invitation.organization_id);
        if (sameOrg) {
          await supabaseAdminRequest(`/rest/v1/rechnio_invitations?id=eq.${restFilter(invitation.id)}`, {
            method: "PATCH", body: { status: "accepted", accepted_by: user.id, accepted_at: new Date().toISOString() }, extraHeaders: { Prefer: "return=minimal" },
          });
          const organization = await getOrganization(invitation.organization_id);
          authResponse(res, req, 200, { ok: true, membership: { enabled: true, role: sameOrg.role, organizationId: invitation.organization_id, organizationName: organization?.name || "" } }, found);
          return;
        }
        if (otherOrg) {
          authResponse(res, req, 409, { error: "Dieses Konto gehört bereits zu einem anderen Rechnio-Unternehmen. Nutze für diese Einladung eine neue E-Mail-Adresse oder verwende ein Konto ohne bestehenden Rechnio-Arbeitsbereich." }, found);
          return;
        }
        const added = await supabaseAdminRequest("/rest/v1/rechnio_memberships", {
          method: "POST", extraHeaders: { Prefer: "return=representation" },
          body: { organization_id: invitation.organization_id, user_id: user.id, email: String(user.email || "").toLowerCase(), role: "employee" },
        });
        if (!added.ok) throw new Error(readableDatabaseError(added, "Dein Mitarbeiterkonto konnte nicht aktiviert werden."));
        const acceptedAt = new Date().toISOString();
        const marked = await supabaseAdminRequest(`/rest/v1/rechnio_invitations?id=eq.${restFilter(invitation.id)}&status=eq.pending`, {
          method: "PATCH", body: { status: "accepted", accepted_by: user.id, accepted_at: acceptedAt }, extraHeaders: { Prefer: "return=minimal" },
        });
        if (!marked.ok) throw new Error(readableDatabaseError(marked, "Die Einladung wurde zugeordnet, ihr Status konnte aber nicht aktualisiert werden."));
        const organization = await getOrganization(invitation.organization_id);
        authResponse(res, req, 200, { ok: true, membership: { enabled: true, role: "employee", organizationId: invitation.organization_id, organizationName: organization?.name || "" } }, found);
      } catch (error) {
        authResponse(res, req, error.statusCode || 503, { error: error.message || "Die Einladung konnte nicht angenommen werden." }, found);
      }
      return;
    }

    sendJson(res, 404, { error: "Diese Mitarbeiterkonto-Funktion ist nicht eingerichtet." });
    return;
  }

  if (
    route === "/api/state" &&
    (req.method === "GET" || req.method === "PUT")
  ) {
    const found = await getSession(req);
    if (!found) {
      sendJson(res, 401, { error: "Bitte melde dich an." });
      return;
    }

    // Neue gemeinsame Organisationsspeicherung. Der alte Benutzer-Speicher bleibt als Rückfall erhalten,
    // bis in Render ein serverseitiger Schlüssel hinterlegt wurde.
    if (supabaseAdminConfig()) {
      try {
        const context = await ensureOrganizationMembership(found.session.user);
        const membershipResponse = {
          enabled: true,
          role: context.membership.role,
          organizationId: context.organization.id,
          organizationName: context.organization.name,
        };
        if (req.method === "GET") {
          const row = await getOrganizationState(context.organization.id);
          authResponse(res, req, 200, { state: row?.state || null, membership: membershipResponse }, found);
          return;
        }
        let body;
        try { body = await readJson(req); }
        catch (error) { authResponse(res, req, 400, { error: error.message }, found); return; }
        if (!body.state || typeof body.state !== "object" || Array.isArray(body.state)) {
          authResponse(res, req, 400, { error: "Der zu speichernde Rechnio-Datenstand ist ungültig." }, found);
          return;
        }
        let stateToSave = body.state;
        const existingRow = await getOrganizationState(context.organization.id);
        if (context.membership.role === "employee" && existingRow?.state && typeof existingRow.state === "object") {
          const previous = existingRow.state;
          const previousCompany = previous.company && typeof previous.company === "object" ? previous.company : {};
          const submittedCompany = body.state.company && typeof body.state.company === "object" ? body.state.company : {};
          const previousNext = Number(previousCompany.nextInvoiceNumber || 1);
          const submittedNext = Number(submittedCompany.nextInvoiceNumber || previousNext);
          stateToSave = {
            ...body.state,
            company: {
              ...previousCompany,
              // Mitarbeiter dürfen keine Firmeneinstellungen ändern, aber die laufende Rechnungsnummer erhöhen.
              nextInvoiceNumber: Math.max(previousNext, Number.isFinite(submittedNext) ? Math.min(submittedNext, 100000000) : previousNext),
            },
            preferences: previous.preferences || body.state.preferences || {},
            expenses: Array.isArray(previous.expenses) ? previous.expenses : (Array.isArray(body.state.expenses) ? body.state.expenses : []),
            // Mitarbeiter dürfen Rechnungen/Kunden anlegen und bearbeiten, aber nicht vorhandene Datensätze löschen.
            customers: mergeRecordsWithoutDeleting(previous.customers, body.state.customers),
            invoices: mergeRecordsWithoutDeleting(previous.invoices, body.state.invoices),
          };
        }
        await upsertOrganizationState(context.organization.id, found.session.user.id, stateToSave);
        authResponse(res, req, 200, { ok: true, savedAt: new Date().toISOString(), membership: membershipResponse }, found);
      } catch (error) {
        // A configured secret key selects team storage. If the team tables have not been
        // installed yet, use the authenticated per-user table so owners can still log in.
        // Team sharing stays unavailable until the employee SQL is installed.
        if (/Mitarbeiterkonto-Datenbank ist noch nicht vollständig eingerichtet/i.test(String(error.message || ""))) {
          console.warn("Rechnio team tables are missing; falling back to per-user cloud storage.");
        } else {
          const status = error.statusCode || 503;
          authResponse(res, req, status, { error: error.message || "Die gemeinsamen Unternehmensdaten konnten nicht verarbeitet werden." }, found);
          return;
        }
      }
      // Any successful organization-state action returns from inside the try block.
      // A missing team-table schema falls through to the legacy personal storage below.
      if (!supabaseAdminConfig()) return;
    }

    // Bisheriges persönliches Speichern für Installationen, die noch nicht für Mitarbeiterkonten konfiguriert sind.
    const userId = encodeURIComponent(found.session.user.id);
    if (req.method === "GET") {
      const result = await supabaseRequest(
        `/rest/v1/rechnio_user_state?select=state&user_id=eq.${userId}`,
        { accessToken: found.session.accessToken }
      );
      if (!result.ok) {
        const missingTable = isMissingDatabaseObject(result, "rechnio_user_state");
        authResponse(res, req, missingTable ? 503 : 502, {
          error: missingTable
            ? "Die Cloud-Tabelle fehlt noch. Führe die Datei rechnio_supabase_setup.sql im Supabase SQL Editor aus."
            : "Die Cloud-Daten konnten nicht geladen werden. Prüfe Supabase-RLS und den Login.",
        }, found);
        return;
      }
      const row = Array.isArray(result.data) ? result.data[0] : null;
      authResponse(res, req, 200, { state: row?.state || null, membership: { enabled: false, role: "owner", organizationName: "" } }, found);
      return;
    }
    let body;
    try { body = await readJson(req); }
    catch (error) { authResponse(res, req, 400, { error: error.message }, found); return; }
    if (!body.state || typeof body.state !== "object" || Array.isArray(body.state)) {
      authResponse(res, req, 400, { error: "Der zu speichernde Rechnio-Datenstand ist ungültig." }, found);
      return;
    }
    const result = await supabaseRequest("/rest/v1/rechnio_user_state?on_conflict=user_id", {
      method: "POST",
      accessToken: found.session.accessToken,
      extraHeaders: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: { user_id: found.session.user.id, state: body.state, updated_at: new Date().toISOString() },
    });
    if (!result.ok) {
      const missingTable = isMissingDatabaseObject(result, "rechnio_user_state");
      authResponse(res, req, missingTable ? 503 : 502, {
        error: missingTable
          ? "Die Cloud-Tabelle fehlt noch. Führe rechnio_supabase_setup.sql im Supabase SQL Editor aus."
          : "Cloud-Speicherung fehlgeschlagen. Prüfe die RLS-Regeln in Supabase.",
      }, found);
      return;
    }
    authResponse(res, req, 200, { ok: true, savedAt: new Date().toISOString(), membership: { enabled: false, role: "owner", organizationName: "" } }, found);
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

    if (supabaseAdminConfig()) {
      try {
        await ensureOrganizationMembership(found.session.user);
      } catch (error) {
        authResponse(res, req, error.statusCode || 403, { error: error.message || "Für dein Konto ist kein aktiver Unternehmenszugriff vorhanden." }, found);
        return;
      }
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
