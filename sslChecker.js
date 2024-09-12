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
  method: "HEAD",
  port: 443,
  rejectUnauthorized: false,
  validateSubjectAltName: false
};

const sslChecker = (host, options = {}) =>
  new Promise((resolve, reject) => {
    options = Object.assign({}, DEFAULT_OPTIONS, options);

    if (!checkPort(options.port)) {
      reject(Error("Invalid port"));
      return;
    }

    try {
      if (options.validateSubjectAltName) {
        const req = https.request(
          { host, ...options },
          (res) => {
            let { valid_from, valid_to, subjectaltname } = res.socket.getPeerCertificate();
            res.socket.destroy();

            if (!valid_from || !valid_to || !subjectaltname) {
              reject(new Error("No certificate"));
              return;
            }

            const validTo = new Date(valid_to);
            const validFor = subjectaltname
              .replace(/DNS:|IP Address:/g, "")
              .split(", ");

            resolve({
              daysRemaining: getDaysRemaining(new Date(), validTo),
              valid: res.socket.authorized || false,
              validFrom: new Date(valid_from).toISOString(),
              validTo: validTo.toISOString(),
              validFor,
            });
          }
        );

        req.on("error", reject);
        req.on("timeout", () => {
          req.destroy();
          reject(new Error("Timed Out"));
        });
        req.end();
      } else {
        const req = https.request(
          { host, ...options },
          (res) => {
            let { valid_from, valid_to } = res.socket.getPeerCertificate();
            res.socket.destroy();

            if (!valid_from || !valid_to) {
              reject(new Error("No certificate"));
              return;
            }

            const validTo = new Date(valid_to);

            resolve({
              daysRemaining: getDaysRemaining(new Date(), validTo),
              valid: res.socket.authorized || false,
              validFrom: new Date(valid_from).toISOString(),
              validTo: validTo.toISOString()
            });
          }
        );
        req.on("error", reject);
        req.on("timeout", () => {
          req.destroy();
          reject(new Error("Timed Out"));
        });
        req.end();
      }
    } catch (e) {
      reject(e);
    }
  });

module.exports = sslChecker;