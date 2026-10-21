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

// Organisationszugriff für Mitarbeiterkonten.
// Admin-Schlüssel bleiben ausschließlich auf dem Server.
function supabaseAdminConfig() {
  const base = supabaseConfig();
  const key = String(
    process.env.SUPABASE_SECRET_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    ""
  ).trim();

  return base && key ? { url: base.url, key } : null;
}

async function supabaseAdminRequest(
  endpoint,
  { method = "GET", body, extraHeaders = {} } = {}
) {
  const config = supabaseAdminConfig();

  if (!config) {
    return {
      ok: false,
      status: 503,
      data: {
        message: "Der serverseitige Supabase-Schlüssel fehlt.",
      },
    };
  }

  const headers = {
    apikey: config.key,
    Authorization: `Bearer ${config.key}`,
    Accept: "application/json",
    ...extraHeaders,
  };

  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  try {
    const response = await fetch(`${config.url}${endpoint}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });

    return {
      ok: response.ok,
      status: response.status,
      data: await readResponse(response),
    };
  } catch (error) {
    return {
      ok: false,
      status: 502,
      data: {
        message: `Supabase ist nicht erreichbar: ${error.message}`,
      },
    };
  }
}

function firstRow(data) {
  return Array.isArray(data)
    ? data[0] || null
    : data && typeof data === "object"
      ? data
      : null;
}

function restFilter(value) {
  return encodeURIComponent(String(value ?? ""));
}

function isMissingDatabaseObject(result, name) {
  const message = String(
    result?.data?.message ||
    result?.data?.details ||
    result?.data?.hint ||
    ""
  );

  return (
    result?.status === 404 ||
    new RegExp(`${name}|schema cache|does not exist`, "i").test(message)
  );
}

function readableDatabaseError(result, fallback) {
  const code = String(result?.data?.code || "");

  if (
    isMissingDatabaseObject(
      result,
      "rechnio_organization_state|rechnio_memberships|rechnio_organizations|rechnio_invitations"
    )
  ) {
    return "Die Mitarbeiterkonto-Datenbank ist noch nicht vollständig eingerichtet. Führe das aktualisierte Mitarbeiterkonto-SQL in Supabase aus.";
  }

  if (code === "23505") {
    return "Dieser Eintrag existiert bereits.";
  }

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

  if (!result.ok) {
    throw new Error(
      readableDatabaseError(
        result,
        "Der Unternehmensbereich konnte nicht geladen werden."
      )
    );
  }

  return firstRow(result.data);
}

async function getOrganizationState(organizationId) {
  const result = await supabaseAdminRequest(
    `/rest/v1/rechnio_organization_state?select=state,updated_at&organization_id=eq.${restFilter(organizationId)}&limit=1`
  );

  if (!result.ok) {
    throw new Error(
      readableDatabaseError(
        result,
        "Die gemeinsamen Unternehmensdaten konnten nicht geladen werden."
      )
    );
  }

  return firstRow(result.data);
}

function mergeRecordsWithoutDeleting(previousValues, submittedValues) {
  const previous = Array.isArray(previousValues) ? previousValues : [];
  const submitted = Array.isArray(submittedValues) ? submittedValues : [];
  const map = new Map();

  for (const item of previous) {
    if (item && item.id) {
      map.set(String(item.id), item);
    }
  }

  for (const item of submitted) {
    if (item && item.id) {
      map.set(String(item.id), item);
    }
  }

  return Array.from(map.values());
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

  // Die restlichen Routen folgen in Teil 3.
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
            email,
            token_hash: tokenHash,
            status: "pending",
            expires_at: expiresAt,
            invited_by: found.session.user.id,
          },
        });

        if (!inserted.ok) {
          throw new Error(readableDatabaseError(inserted, "Die Einladung konnte nicht gespeichert werden."));
        }

        const invitationUrl = `${PUBLIC_SITE_URL}/?team_invite=${encodeURIComponent(token)}`;
        authResponse(res, req, 200, {
          ok: true,
          invitation: {
            email,
            expiresAt,
            url: invitationUrl,
          },
        }, found);
      } catch (error) {
        authResponse(res, req, error.statusCode || 503, {
          error: error.message || "Die Einladung konnte nicht erstellt werden.",
        }, found);
      }
      return;
    }
        if (req.method === "POST" && route === "/api/team/invitations/revoke") {
      let body;
      try { body = await readJson(req); }
      catch (error) { authResponse(res, req, 400, { error: error.message }, found); return; }

      const invitationId = String(body.invitationId || "").trim();
      if (!invitationId) {
        authResponse(res, req, 400, { error: "Die Einladung fehlt." }, found);
        return;
      }

      try {
        const context = await requireOwnerContext(found);
        const updated = await supabaseAdminRequest(
          `/rest/v1/rechnio_invitations?id=eq.${restFilter(invitationId)}&organization_id=eq.${restFilter(context.organization.id)}&status=eq.pending`,
          {
            method: "PATCH",
            body: { status: "revoked" },
            extraHeaders: { Prefer: "return=representation" },
          }
        );

        if (!updated.ok) {
          throw new Error(readableDatabaseError(updated, "Die Einladung konnte nicht widerrufen werden."));
        }

        if (!Array.isArray(updated.data) || !updated.data.length) {
          authResponse(res, req, 404, { error: "Die offene Einladung wurde nicht gefunden." }, found);
          return;
        }

        authResponse(res, req, 200, { ok: true }, found);
      } catch (error) {
        authResponse(res, req, error.statusCode || 503, {
          error: error.message || "Die Einladung konnte nicht widerrufen werden.",
        }, found);
      }

      return;
    }

    if (req.method === "POST" && route === "/api/team/members/remove") {
      let body;
      try { body = await readJson(req); }
      catch (error) { authResponse(res, req, 400, { error: error.message }, found); return; }

      const userId = String(body.userId || "").trim();

      if (!userId || userId === found.session.user.id) {
        authResponse(res, req, 400, {
          error: "Du kannst dein eigenes Inhaberkonto hier nicht entfernen.",
        }, found);
        return;
      }

      try {
        const context = await requireOwnerContext(found);
        const targetResult = await supabaseAdminRequest(
          `/rest/v1/rechnio_memberships?select=user_id,role&organization_id=eq.${restFilter(context.organization.id)}&user_id=eq.${restFilter(userId)}&limit=1`
        );

        if (!targetResult.ok) {
          throw new Error(readableDatabaseError(targetResult, "Das Mitglied konnte nicht geprüft werden."));
        }

        const target = firstRow(targetResult.data);

        if (!target || target.role !== "employee") {
          authResponse(res, req, 404, {
            error: "Dieses Mitarbeiterkonto wurde nicht gefunden.",
          }, found);
          return;
        }

        const removed = await supabaseAdminRequest(
          `/rest/v1/rechnio_memberships?organization_id=eq.${restFilter(context.organization.id)}&user_id=eq.${restFilter(userId)}&role=eq.employee`,
          {
            method: "DELETE",
            extraHeaders: { Prefer: "return=minimal" },
          }
        );

        if (!removed.ok) {
          throw new Error(readableDatabaseError(removed, "Der Mitarbeiter konnte nicht entfernt werden."));
        }

        authResponse(res, req, 200, { ok: true }, found);
      } catch (error) {
        authResponse(res, req, error.statusCode || 503, {
          error: error.message || "Der Mitarbeiter konnte nicht entfernt werden.",
        }, found);
      }

      return;
    }

    if (req.method === "POST" && route === "/api/team/accept") {
      let body;
      try { body = await readJson(req); }
      catch (error) { authResponse(res, req, 400, { error: error.message }, found); return; }

      const token = String(body.token || "");

      if (!validInviteToken(token)) {
        authResponse(res, req, 400, { error: "Der Einladungslink ist ungültig." }, found);
        return;
      }

      try {
        const invitation = await findInvitationByToken(token);

        if (!invitation || invitation.status !== "pending") {
          authResponse(res, req, 410, {
            error: "Diese Einladung ist nicht mehr gültig. Bitte den Inhaber um eine neue Einladung.",
          }, found);
          return;
        }

        if (Date.parse(invitation.expires_at) <= Date.now()) {
          await supabaseAdminRequest(
            `/rest/v1/rechnio_invitations?id=eq.${restFilter(invitation.id)}`,
            {
              method: "PATCH",
              body: { status: "expired" },
              extraHeaders: { Prefer: "return=minimal" },
            }
          );

          authResponse(res, req, 410, {
            error: "Diese Einladung ist abgelaufen. Bitte den Inhaber um eine neue Einladung.",
          }, found);
          return;
        }

        const user = found.session.user;

        if (
          String(user.email || "").trim().toLowerCase() !==
          String(invitation.email || "").trim().toLowerCase()
        ) {
          authResponse(res, req, 403, {
            error: `Melde dich mit ${invitation.email} an, damit die Einladung dem richtigen Konto zugeordnet wird.`,
          }, found);
          return;
        }

        const membershipsResult = await getMembershipsForUser(user.id);

        if (!membershipsResult.ok) {
          throw new Error(readableDatabaseError(
            membershipsResult,
            "Deine bestehende Unternehmenszugehörigkeit konnte nicht geprüft werden."
          ));
        }

        const memberships = Array.isArray(membershipsResult.data)
          ? membershipsResult.data
          : [];

        const sameOrg = memberships.find(
          m => m.organization_id === invitation.organization_id
        );

        const otherOrg = memberships.find(
          m => m.organization_id !== invitation.organization_id
        );

        if (sameOrg) {
          await supabaseAdminRequest(
            `/rest/v1/rechnio_invitations?id=eq.${restFilter(invitation.id)}`,
            {
              method: "PATCH",
              body: {
                status: "accepted",
                accepted_by: user.id,
                accepted_at: new Date().toISOString(),
              },
              extraHeaders: { Prefer: "return=minimal" },
            }
          );

          const organization = await getOrganization(invitation.organization_id);

          authResponse(res, req, 200, {
            ok: true,
            membership: {
              enabled: true,
              role: sameOrg.role,
              organizationId: invitation.organization_id,
              organizationName: organization?.name || "",
            },
          }, found);

          return;
        }

        if (otherOrg) {
          authResponse(res, req, 409, {
            error: "Dieses Konto gehört bereits zu einem anderen Rechnio-Unternehmen. Nutze für diese Einladung eine neue E-Mail-Adresse oder verwende ein Konto ohne bestehenden Rechnio-Arbeitsbereich.",
          }, found);
          return;
        }

        const added = await supabaseAdminRequest("/rest/v1/rechnio_memberships", {
          method: "POST",
          extraHeaders: { Prefer: "return=representation" },
          body: {
            organization_id: invitation.organization_id,
            user_id: user.id,
            email: String(user.email || "").toLowerCase(),
            role: "employee",
          },
        });

        if (!added.ok) {
          throw new Error(readableDatabaseError(added, "Dein Mitarbeiterkonto konnte nicht aktiviert werden."));
        }

        const acceptedAt = new Date().toISOString();

        const marked = await supabaseAdminRequest(
          `/rest/v1/rechnio_invitations?id=eq.${restFilter(invitation.id)}&status=eq.pending`,
          {
            method: "PATCH",
            body: {
              status: "accepted",
              accepted_by: user.id,
              accepted_at: acceptedAt,
            },
            extraHeaders: { Prefer: "return=minimal" },
          }
        );

        if (!marked.ok) {
          throw new Error(readableDatabaseError(marked, "Die Einladung wurde zugeordnet, ihr Status konnte aber nicht aktualisiert werden."));
        }

        const organization = await getOrganization(invitation.organization_id);

        authResponse(res, req, 200, {
          ok: true,
          membership: {
            enabled: true,
            role: "employee",
            organizationId: invitation.organization_id,
            organizationName: organization?.name || "",
          },
        }, found);
      } catch (error) {
        authResponse(res, req, error.statusCode || 503, {
          error: error.message || "Die Einladung konnte nicht angenommen werden.",
        }, found);
      }

      return;
    }

    sendJson(res, 404, {
      error: "Diese Mitarbeiterkonto-Funktion ist nicht eingerichtet.",
    });

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

          authResponse(res, req, 200, {
            state: row?.state || null,
            membership: membershipResponse,
          }, found);

          return;
        }

        let body;

        try { body = await readJson(req); }
        catch (error) {
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

        let stateToSave = body.state;
        const existingRow = await getOrganizationState(context.organization.id);

        if (
          context.membership.role === "employee" &&
          existingRow?.state &&
          typeof existingRow.state === "object"
        ) {
          const previous = existingRow.state;
          const previousCompany =
            previous.company && typeof previous.company === "object"
              ? previous.company
              : {};
          const submittedCompany =
            body.state.company && typeof body.state.company === "object"
              ? body.state.company
              : {};

          const previousNext = Number(previousCompany.nextInvoiceNumber || 1);
          const submittedNext = Number(
            submittedCompany.nextInvoiceNumber || previousNext
          );

          stateToSave = {
            ...body.state,
            company: {
              ...previousCompany,
              nextInvoiceNumber: Math.max(
                previousNext,
                Number.isFinite(submittedNext)
                  ? Math.min(submittedNext, 100000000)
                  : previousNext
              ),
            },
            preferences: previous.preferences || body.state.preferences || {},
            expenses: Array.isArray(previous.expenses)
              ? previous.expenses
              : Array.isArray(body.state.expenses)
                ? body.state.expenses
                : [],
            customers: mergeRecordsWithoutDeleting(
              previous.customers,
              body.state.customers
            ),
            invoices: mergeRecordsWithoutDeleting(
              previous.invoices,
              body.state.invoices
            ),
          };
        }

        await upsertOrganizationState(
          context.organization.id,
          found.session.user.id,
          stateToSave
        );

        authResponse(res, req, 200, {
          ok: true,
          savedAt: new Date().toISOString(),
          membership: membershipResponse,
        }, found);
      } catch (error) {
        authResponse(res, req, error.statusCode || 503, {
          error: error.message || "Die gemeinsamen Unternehmensdaten konnten nicht verarbeitet werden.",
        }, found);
      }

      return;
    }

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

      authResponse(res, req, 200, {
        state: row?.state || null,
        membership: {
          enabled: false,
          role: "owner",
          organizationName: "",
        },
      }, found);

      return;
    }

    let body;

    try { body = await readJson(req); }
    catch (error) {
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

    const result = await supabaseRequest("/rest/v1/rechnio_user_state?on_conflict=user_id", {
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

    authResponse(res, req, 200, {
      ok: true,
      savedAt: new Date().toISOString(),
      membership: {
        enabled: false,
        role: "owner",
        organizationName: "",
      },
    }, found);

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
        authResponse(res, req, error.statusCode || 403, {
          error: error.message || "Für dein Konto ist kein aktiver Unternehmenszugriff vorhanden."
        }, found);
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
