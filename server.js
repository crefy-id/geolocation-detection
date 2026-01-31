// server-advanced.js
const express = require('express');
const geoip = require('geoip-lite');
const app = express();
const port = process.env.PORT || 3000;

app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.ip} - ${req.method} ${req.url}`);
    next();
});

app.get('/', (req, res) => {
    // Get client IP (handle proxies)
    let clientIP = req.headers['x-forwarded-for'] || 
                   req.headers['x-real-ip'] || 
                   req.socket.remoteAddress || 
                   req.connection.remoteAddress;
    
    // Clean IP address (remove IPv6 prefix if present)
    clientIP = clientIP.replace('::ffff:', '');
    
    // Get geolocation data
    const geo = geoip.lookup(clientIP);
    
    // Prepare response data
    const visitorInfo = {
        timestamp: new Date().toISOString(),
        ip: clientIP,
        userAgent: req.headers['user-agent'],
        language: req.headers['accept-language'],
        referer: req.headers['referer'],
        method: req.method,
        url: req.url,
        headers: req.headers,
        geo: geo || { 
            message: 'Location data not available for this IP',
            note: 'For more accurate location, use a service like ipapi.co or ipinfo.io'
        }
    };
    
    // Send JSON or HTML based on Accept header
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
        res.json(visitorInfo);
    } else {
        // Render HTML page
        res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Visitor Information</title>
            <style>
                body { font-family: Arial, sans-serif; padding: 20px; }
                .info { margin: 10px 0; padding: 10px; background: #f5f5f5; }
                .label { font-weight: bold; color: #333; }
                .geo { background: #e3f2fd !important; }
            </style>
        </head>
        <body>
            <h1>Visitor Information</h1>
            <div class="info"><span class="label">IP:</span> ${visitorInfo.ip}</div>
            <div class="info geo">
                <span class="label">Location:</span> 
                ${visitorInfo.geo.country ? 
                    `${visitorInfo.geo.city || 'Unknown City'}, ${visitorInfo.geo.region}, ${visitorInfo.geo.country}` 
                    : 'Unknown'}
            </div>
            <div class="info"><span class="label">Time:</span> ${new Date(visitorInfo.timestamp).toLocaleString()}</div>
            <div class="info"><span class="label">Browser:</span> ${visitorInfo.userAgent}</div>
            <div class="info"><span class="label">Languages:</span> ${visitorInfo.language}</div>
            <div class="info"><span class="label">Full Data:</span> 
                <pre>${JSON.stringify(visitorInfo, null, 2)}</pre>
            </div>
        </body>
        </html>
        `);
    }
});

app.get('/api/visitor-info', (req, res) => {
    let clientIP = req.headers['x-forwarded-for'] || req.ip;
    clientIP = clientIP.replace('::ffff:', '');
    const geo = geoip.lookup(clientIP);
    
    res.json({
        ip: clientIP,
        location: geo,
        timestamp: new Date().toISOString(),
        userAgent: req.headers['user-agent']
    });
});

app.get('/ip', (req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.ip;
    res.send(ip.replace('::ffff:', ''));
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`Local: http://localhost:${port}`);
    console.log(`Network: http://${require('os').networkInterfaces().en0?.[1]?.address || 'localhost'}:${port}`);
});