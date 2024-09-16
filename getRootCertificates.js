const { exec } = require("child_process");
const fs = require("fs");
const { Certificate } = require("@fidm/x509");

function getRootCertificates() {
    return new Promise((resolve, reject) => {
        exec('ls /etc/ssl/certs/*.pem', (err, stdout, stderr) => {
            if (err) {
                return reject(`Error listing certificates: ${stderr}`);
            }

            const certFiles = stdout.split('\n').filter(file => file);
            const certs = [];

            certFiles.forEach(file => {
                const pem = fs.readFileSync(file, 'utf8');
                const cert = Certificate.fromPEM(Buffer.from(pem));

                // Check if the certificate uses RSA
                if (cert.publicKey.algo === 'rsaEncryption') {
                    const sans = cert.subjectAltName ? cert.subjectAltName.map(altName => altName.value) : [];

                    certs.push({
                        // subject: cert.subject,
                        issuer: cert.issuer,
                        valid_from: cert.validFrom,
                        valid_to: cert.validTo,
                        serialNumber: cert.serialNumber,
                        fingerprint: cert.fingerprint,
                        // sans: sans
                    });
                }
            });

            resolve(certs);
        });
    });
}

module.exports = getRootCertificates;