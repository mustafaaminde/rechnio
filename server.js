const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const host = "0.0.0.0";
const port = Number(process.env.PORT || 3000);
const indexPath = path.join(__dirname, "index.html");
const maxRequestBytes = 16 * 1024;

function sendJson(response, statusCode, data) {
    response.writeHead(statusCode, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store"
    });
    response.end(JSON.stringify(data));
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function isValidEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isFiniteNumber(value) {
    return typeof value === "number" && Number.isFinite(value);
}

function validateInvoice(invoice) {
    if (!invoice || typeof invoice !== "object" || Array.isArray(invoice)) {
        return "Ungültige Rechnungsdaten.";
    }

    const requiredStrings = [
        ["customerName", 200],
        ["customerEmail", 320],
        ["invoiceNumber", 100],
        ["service", 1000],
        ["invoiceDate", 30],
        ["dueDate", 30]
    ];

    for (const [field, maxLength] of requiredStrings) {
        if (
            typeof invoice[field] !== "string" ||
            invoice[field].trim().length === 0 ||
            invoice[field].length > maxLength
        ) {
            return "Rechnungsdaten sind unvollständig oder ungültig.";
        }
    }

    if (!isValidEmail(invoice.customerEmail.trim())) {
        return "Die Kunden-E-Mail-Adresse ist ungültig.";
    }

    for (const field of [
        "quantity",
        "unitPrice",
        "taxRate",
        "netAmount",
        "taxAmount",
        "grossAmount"
    ]) {
        if (!isFiniteNumber(invoice[field]) || invoice[field] < 0) {
            return "Rechnungsbeträge sind ungültig.";
        }
    }

    return null;
}

async function readJsonBody(request) {
    let body = "";

    for await (const chunk of request) {
        body += chunk;
        if (Buffer.byteLength(body, "utf8") > maxRequestBytes) {
            throw new Error("request-too-large");
        }
    }

    return JSON.parse(body);
}

function formatCurrency(amount) {
    return new Intl.NumberFormat("de-DE", {
        style: "currency",
        currency: "EUR"
    }).format(amount);
}

async function sendInvoice(request, response) {
    let invoice;

    try {
        invoice = await readJsonBody(request);
    } catch (error) {
        if (error.message === "request-too-large") {
            sendJson(response, 413, {
                error: "Die Anfrage ist zu groß."
            });
            return;
        }

        sendJson(response, 400, {
            error: "Die Rechnungsdaten konnten nicht gelesen werden."
        });
        return;
    }

    const validationError = validateInvoice(invoice);
    if (validationError) {
        sendJson(response, 400, { error: validationError });
        return;
    }

    const apiKey = process.env.RESEND_API_KEY;
    const from = process.env.EMAIL_FROM;

    if (!apiKey || !from) {
        console.error("RESEND_API_KEY oder EMAIL_FROM ist nicht konfiguriert.");
        sendJson(response, 500, {
            error: "Der E-Mail-Service ist auf dem Server nicht konfiguriert."
        });
        return;
    }

    const customerName = escapeHtml(invoice.customerName.trim());
    const invoiceNumber = escapeHtml(invoice.invoiceNumber.trim());
    const service = escapeHtml(invoice.service.trim());
    const invoiceDate = escapeHtml(invoice.invoiceDate);
    const dueDate = escapeHtml(invoice.dueDate);
    const email = invoice.customerEmail.trim();
    const html = `
        <h1>Rechnung ${invoiceNumber}</h1>
        <p>Guten Tag ${customerName},</p>
        <p>hier sind die Details zu Ihrer Rechnung:</p>
        <table>
            <tr><th align="left">Leistung</th><td>${service}</td></tr>
            <tr><th align="left">Menge</th><td>${invoice.quantity}</td></tr>
            <tr><th align="left">Einzelpreis</th><td>${formatCurrency(invoice.unitPrice)}</td></tr>
            <tr><th align="left">Netto</th><td>${formatCurrency(invoice.netAmount)}</td></tr>
            <tr><th align="left">MwSt. (${invoice.taxRate} %)</th><td>${formatCurrency(invoice.taxAmount)}</td></tr>
            <tr><th align="left">Gesamtbetrag</th><td>${formatCurrency(invoice.grossAmount)}</td></tr>
            <tr><th align="left">Rechnungsdatum</th><td>${invoiceDate}</td></tr>
            <tr><th align="left">Fällig am</th><td>${dueDate}</td></tr>
        </table>
    `;

    let providerResponse;
    try {
        providerResponse = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${apiKey}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                from,
                to: [email],
                subject: `Rechnung ${invoiceNumber}`,
                html
            }),
            signal: AbortSignal.timeout(15000)
        });
    } catch (error) {
        console.error("Resend-Anfrage fehlgeschlagen:", error.message);
        sendJson(response, 502, {
            error: "Der E-Mail-Service ist momentan nicht erreichbar."
        });
        return;
    }

    if (!providerResponse.ok) {
        const details = await providerResponse.text();
        console.error(
            `Resend meldete HTTP ${providerResponse.status}:`,
            details
        );
        sendJson(response, 502, {
            error: "Der E-Mail-Service konnte die Rechnung nicht versenden."
        });
        return;
    }

    sendJson(response, 200, {
        message: `Rechnung ${invoice.invoiceNumber} wurde an ${email} gesendet.`
    });
}

const server = http.createServer(async function(request, response) {
 console.log("REQUEST:", request.method, request.url);
    if (request.method === "GET" && request.url.split("?")[0] === "/") {
        fs.readFile(indexPath, function(error, contents) {
            if (error) {
                console.error("index.html konnte nicht gelesen werden:", error);
                response.writeHead(500, {
                    "Content-Type": "text/plain; charset=utf-8"
                });
                response.end("Die Anwendung konnte nicht geladen werden.");
                return;
            }

            response.writeHead(200, {
                "Content-Type": "text/html; charset=utf-8",
                "Cache-Control": "no-store"
            });
            response.end(contents);
        });
        return;
    }

    if (request.method === "POST" && request.url === "/api/send-invoice") {
        await sendInvoice(request, response);
        return;
    }

    sendJson(response, 404, { error: "Endpunkt nicht gefunden." });
});

server.listen(port, host, function() {
    console.log(`Rechnio läuft auf http://${host}:${port}`);
});
