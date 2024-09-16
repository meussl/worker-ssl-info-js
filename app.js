const express = require('express');
const https = require('https');
const sslChecker = require('./sslChecker'); // Correctly import the sslChecker function
const issuers = require('./issuers'); // Import the issuers data
const app = express();
const { exec } = require('child_process');
const fs = require('fs');
const { Certificate } = require('@fidm/x509');


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

app.get('/ssl-info', async (req, res) => { // Make the handler function async
    const domain = req.query.domain;
    if (!domain) {
        return res.status(400).json({ error: 'Domain parameter is required' });
    }

    try {
        const {ssl, issuer} = await sslChecker(domain, {validateSubjectAltName: true}); // Await the sslChecker function
        
        
        res.json({
            domain: domain,
            status: ssl.valid ? 'valid' : 'invalid',
            ssl: ssl,
            issuer: issuer,
            requestTime: new Date().toISOString(),
            requestEpoch: Date.now()
        });
    } catch (error) {
        res.status(500).json({ error: 'Request error', message: error.message });
    }
});

app.get('/issuers', (req, res) => {
    res.set('Cache-Control', 'public, max-age=3600'); // Set cache headers
    res.json(issuers);
});

app.get('/root-certificates', async (req, res) => {
    try {
        const certs = await getRootCertificates();
        res.set('Cache-Control', 'public, max-age=3600'); // Set cache headers
        res.json(certs);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});