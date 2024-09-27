const express = require('express');
const sslChecker = require('./sslChecker'); // Correctly import the sslChecker function
const issuers = require('./issuers'); // Import the issuers data
const app = express();
const getRootCertificates = require("./getRootCertificates");
const dns = require('dns');

app.get('/ssl-info', async (req, res) => { // Make the handler function async
    const domain = req.query.domain;
    if (!domain) {
        return res.status(400).json({error: 'Domain parameter is required'});
    }

    console.log(`Checking SSL for ${domain}`);

    try {
        await dns.promises.resolve(domain);
    } catch (err) {
        return res.status(400).json({error: 'Domain does not properly resolve, this is alive?'});
    }

    try {

        const {ssl, issuer} = await sslChecker(domain, {validateSubjectAltName: true}); // Await the sslChecker function

        let response = {
            domain: domain,
            status: ssl.valid ? 'valid' : 'invalid',
            ssl: ssl,
            issuer: issuer,
            requestTime: new Date().toISOString(),
            requestEpoch: Date.now()
        };

        console.log(response);


        res.json(response);
    } catch (error) {
        res.status(404).json({error: 'Request error', message: error.message});
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
        res.status(500).json({error: error.message});
    }
});

const PORT = process.env.PORT || 8001;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});