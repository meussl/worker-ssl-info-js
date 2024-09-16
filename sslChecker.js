const http = require("http");
const https = require("https");

const checkPort = (port) =>
    !isNaN(parseFloat(port)) && Math.sign(port) === 1;

const getDaysBetween = (validFrom, validTo) =>
    Math.round(Math.abs(+validFrom - +validTo) / 8.64e7);

const getDaysRemaining = (validFrom, validTo) => {
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
        "User-Agent": "MeuSSL Bot 1.0",
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
            reject(Error("Invalid port"));
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
                        reject(new Error("No certificate"));
                        return;
                    }

                    const validTo = new Date(valid_to);
                    const validFor = subjectaltname
                        .replace(/DNS:|IP Address:/g, "")
                        .split(", ");

                    const issuerInfo = {
                        commonName: issuer.CN,
                        organization: issuer.O,
                        organizationalUnit: issuer.OU,
                        locality: issuer.L,
                        state: issuer.ST,
                        country: issuer.C
                    };

                    const sslInfo = {
                        commonName: issuer.CN,
                        subject: subject,
                        daysRemaining: getDaysRemaining(new Date(), validTo),
                        valid: res.socket.authorized || false,
                        validFrom: new Date(valid_from).toISOString(),
                        validTo: validTo.toISOString(),
                        validFor,
                        fingerprint256: fingerprint256,
                        serialNumber: serialNumber
                    };

                    resolve({issuer: issuerInfo, ssl: sslInfo});
                }
            );

            req.on("error", reject);
            req.on("timeout", () => {
                req.destroy();
                reject(new Error("Timed Out"));
            });
            req.end();
        } catch (e) {
            reject(e);
        }
    });

module.exports = sslChecker;