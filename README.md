# Rechnio

## Rechnungen per E-Mail senden

Der Versand läuft über `index.html` zum lokalen Node.js-Backend und von dort
über Resend an die Kundenadresse. Der Resend-API-Schlüssel bleibt serverseitig.

1. Installiere Node.js 20.6 oder neuer.
2. Lege im Resend-Konto einen API-Schlüssel an und verifiziere die Absenderdomain.
3. Kopiere `.env.example` als `.env` und trage den API-Schlüssel sowie eine
   Absenderadresse dieser verifizierten Domain bei `EMAIL_FROM` ein.
4. Starte die App im Projektordner mit `npm start` und öffne
   `http://127.0.0.1:3000`.

Die E-Mail enthält die Rechnungsdaten als Nachricht, aber derzeit keinen
PDF-Anhang. Das Backend bindet standardmäßig nur an `127.0.0.1`; diese
Demonstrations-App hat noch keine serverseitige Anmeldung oder
Berechtigungsprüfung. Vor einer Veröffentlichung im Internet müssen
Authentifizierung, Berechtigungsprüfung und persistente serverseitige
Rechnungsdaten ergänzt werden.
