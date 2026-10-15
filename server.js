
"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const HOST = "0.0.0.0";
const PORT = Number(process.env.PORT || 3000);
const INDEX_PATH = path.join(__dirname, "index.html");

function sendJson(response, statusCode, data) {
    response.writeHead(statusCode, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff"
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

const server = http.createServer((request, response) => {
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

    if (request.method === "GET" && url.pathname === "/") {
        serveIndex(response);
        return;
    }

    // Der bisherige Rechnungs-E-Mail-Endpunkt ist deaktiviert.
    if (url.pathname === "/api/send-invoice") {
        sendJson(response, 404, {
            error: "Der E-Mail-Versand ist deaktiviert."
        });

        return;
    }

    sendJson(response, 404, {
        error: "Endpunkt nicht gefunden."
    });
});

server.on("error", (error) => {
    console.error("Serverfehler:", error.message);
    process.exitCode = 1;
});

server.listen(PORT, HOST, () => {
    console.log(`Rechnio läuft auf Port ${PORT}.`);
});
