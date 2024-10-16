const http = require("node:http");
const https = require("node:https");

const checkPort = (port) =>
    !isNaN(parseFloat(port)) && Math.sign(port) === 1;

const getDaysBetween = (validFrom, validTo) =>
    Math.round(Math.abs(+validFrom - +validTo) / 8.64e7);

const getDaysRemaining = (validFrom, validTo) => {
    if (!validFrom || !validTo) {
        return 0;
    }

    const daysRemaining = getDaysBetween(validFrom, validTo);

    if (new Date(validTo).getTime() < new Date().getTime()) {
        return -daysRemaining;
    }

    return daysRemaining;
};

const DEFAULT_OPTIONS = {
    agent: new https.Agent({
        maxCachedSessions: 0,
    }),
    method: "GET",
    port: 443,
    rejectUnauthorized: false,
    validateSubjectAltName: true,
    headers: {
        "User-Agent": "MeuSSLBot/1.0",
    }
};

// Propriedades Detalhadas
// subject: Um objeto contendo informações sobre o sujeito do certificado.

// CN: Nome comum.
// O: Organização.
// OU: Unidade organizacional.
// L: Localidade.
// ST: Estado ou província.
// C: País.
// issuer: Um objeto contendo informações sobre a entidade emissora do certificado.

// CN: Nome comum.
// O: Organização.
// OU: Unidade organizacional.
// L: Localidade.
// ST: Estado ou província.
// C: País.
// valid_from: Uma string representando a data de início da validade do certificado.

// valid_to: Uma string representando a data de término da validade do certificado.

// fingerprint: Uma string representando a impressão digital do certificado.

// serialNumber: Uma string representando o número de série do certificado.

// raw: Um buffer contendo o certificado em formato binário.

// Essas são algumas das propriedades mais comuns que você pode acessar no objeto retornado por getPeerCertificate.

const sslChecker = (host, options = {}) =>
    new Promise((resolve, reject) => {
        options = Object.assign({}, DEFAULT_OPTIONS, options);

        if (!checkPort(options.port)) {
            reject(new Error("Invalid port: Port must be a positive number"));
            return;
        }

        try {
            const req = https.request(
                {host, ...options},
                (res) => {
                    let {
                        valid_from,
                        valid_to,
                        subjectaltname,
                        issuer,
                        subject,
                        fingerprint256,
                        serialNumber
                    } = res.socket.getPeerCertificate();
                    res.socket.destroy();

                    if (!valid_from || !valid_to || !subjectaltname) {
                        reject(new Error("No certificate: Missing required certificate fields"));
                        return;
                    }

                    const validTo = new Date(valid_to);
                    const validFor = subjectaltname
                        .replace(/DNS:|IP Address:/g, "")
                        .split(", ");

                    const issuerInfo = {
                        commonName: issuer.CN,
                        organization: issuer.O,
                        organizationalUnit: issuer.OU || null,
                        locality: issuer.L  || null,
                        state: issuer.ST || null,
                        country: issuer.C || null,
                    };

                    const sslInfo = {
                        commonName: subject.CN,
                        subject: subject,
                        daysRemaining: getDaysRemaining(new Date(), validTo),
                        valid: res.socket.authorized || false,
                        validFrom: new Date(valid_from).toISOString() || null,
                        validTo: validTo.toISOString() || null,
                        validFor: validFor || [],
                        fingerprint256: fingerprint256 || null,
                        serialNumber: serialNumber || null,
                    };

                    resolve({issuer: issuerInfo, ssl: sslInfo});
                }
            );

            req.on("error", (err) => {
                reject(new Error(`Request error: ${err.message}`));
            });
            req.on("timeout", () => {
                req.destroy();
                reject(new Error("Request timed out"));
            });
            req.end();
        } catch (e) {
            reject(new Error(`Unexpected error: ${e.message}`));
        }
    });

module.exports = sslChecker;