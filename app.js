const express = require('express');
const https = require('https');
const app = express();

app.get('/ssl-info', (req, res) => {
    const domain = req.query.domain;
    if (!domain) {
        return res.status(400).json({ error: 'Domain parameter is required' });
    }

    const options = {
        hostname: domain,
        port: 443,
        method: 'GET'
    };

    const req = https.request(options, (response) => {
        const certificate = response.socket.getPeerCertificate();
        if (!certificate || Object.keys(certificate).length === 0) {
            return res.status(500).json({ error: 'No certificate found' });
        }

        res.json({
            domain: domain,
            ssl_info: certificate,
            status: response.statusCode === 200 ? 'valid' : 'invalid'
        });
    });

    req.on('error', (e) => {
        res.status(500).json({ error: 'Request error', details: e.message });
    });

    req.end();
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});