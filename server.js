// server.js
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const requestIp = require('request-ip');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');
const { RateLimiterMemory } = require('rate-limiter-flexible');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"]
        }
    }
}));

app.use(cors());
app.use(compression());
app.use(express.json());
app.use(requestIp.mw());

// Rate limiting - 100 requests per 15 minutes per IP
const rateLimiter = new RateLimiterMemory({
    points: 100,
    duration: 900, // 15 minutes
    blockDuration: 1800 // Block for 30 minutes if exceeded
});

app.use((req, res, next) => {
    const clientIp = req.clientIp;
    
    // Skip rate limiting for localhost
    if (clientIp === '::1' || clientIp === '127.0.0.1') {
        return next();
    }
    
    rateLimiter.consume(clientIp)
        .then(() => next())
        .catch(() => {
            res.status(429).json({
                error: 'Too many requests',
                message: 'Please try again later'
            });
        });
});

// Check if IP is private
function isPrivateIP(ip) {
    if (!ip) return false;
    const ipv4 = ip.replace('::ffff:', '');
    return /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.)/.test(ipv4);
}

// Get location data
function getLocationData(ip) {
    const cleanIp = ip.replace('::ffff:', '');
    
    if (isPrivateIP(cleanIp)) {
        return {
            type: 'private',
            note: 'Local network address',
            ip: cleanIp
        };
    }
    
    const geo = geoip.lookup(cleanIp);
    if (!geo) {
        return {
            type: 'public',
            ip: cleanIp,
            location: null,
            error: 'Location data not available'
        };
    }
    
    return {
        type: 'public',
        ip: cleanIp,
        location: {
            country: geo.country,
            countryName: geo.country === 'US' ? 'United States' : 
                        geo.country === 'GB' ? 'United Kingdom' :
                        geo.country === 'DE' ? 'Germany' :
                        geo.country === 'FR' ? 'France' :
                        geo.country === 'JP' ? 'Japan' :
                        geo.country === 'CN' ? 'China' : 'Unknown',
            region: geo.region,
            city: geo.city,
            timezone: geo.timezone,
            coordinates: geo.ll,
            metro: geo.metro,
            area: geo.area,
            eu: geo.eu === '1' ? 'Yes' : 'No'
        },
        network: {
            range: geo.range,
            isp: null // geoip-lite doesn't provide ISP
        }
    };
}

// Get device info from user agent
function getDeviceInfo(userAgent) {
    const parser = new UAParser(userAgent);
    const result = parser.getResult();
    
    return {
        browser: result.browser.name + ' ' + result.browser.version,
        engine: result.engine.name,
        os: result.os.name + ' ' + result.os.version,
        device: result.device.type || 'Desktop',
        model: result.device.model || 'Unknown',
        vendor: result.device.vendor || 'Unknown',
        cpu: result.cpu.architecture || 'Unknown'
    };
}

// Main route
app.get('/', (req, res) => {
    const clientIp = req.clientIp;
    const userAgent = req.headers['user-agent'] || '';
    const now = new Date();
    
    const locationData = getLocationData(clientIp);
    const deviceInfo = getDeviceInfo(userAgent);
    
    const visitorInfo = {
        timestamp: {
            iso: now.toISOString(),
            local: now.toLocaleString(),
            utc: now.toUTCString(),
            unix: Math.floor(now.getTime() / 1000)
        },
        network: locationData,
        device: deviceInfo,
        request: {
            ip: clientIp,
            method: req.method,
            url: req.url,
            protocol: req.protocol,
            secure: req.secure,
            host: req.headers['host'],
            userAgent: userAgent,
            languages: req.headers['accept-language'],
            encoding: req.headers['accept-encoding'],
            connection: req.headers['connection'],
            referer: req.headers['referer'] || 'Direct',
            forwardedFor: req.headers['x-forwarded-for'],
            realIp: req.headers['x-real-ip']
        },
        server: {
            hostname: require('os').hostname(),
            uptime: process.uptime(),
            nodeVersion: process.version,
            memory: process.memoryUsage()
        }
    };
    
    // Respond based on Accept header
    const accept = req.headers.accept || '';
    
    if (accept.includes('application/json')) {
        res.json(visitorInfo);
    } else {
        // Render HTML page
        res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Visitor Information - Contabo Server</title>
            <style>
                :root {
                    --primary: #4361ee;
                    --secondary: #3a0ca3;
                    --success: #4cc9f0;
                    --warning: #f72585;
                    --dark: #212529;
                    --light: #f8f9fa;
                }
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 20px;
                    color: var(--dark);
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                }
                header {
                    text-align: center;
                    margin-bottom: 30px;
                    padding: 20px;
                    background: rgba(255, 255, 255, 0.95);
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
                }
                h1 {
                    color: var(--secondary);
                    font-size: 2.5em;
                    margin-bottom: 10px;
                }
                .subtitle {
                    color: #666;
                    font-size: 1.1em;
                }
                .server-ip {
                    display: inline-block;
                    background: var(--primary);
                    color: white;
                    padding: 5px 15px;
                    border-radius: 20px;
                    margin-top: 10px;
                    font-family: 'Courier New', monospace;
                }
                .grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                    gap: 20px;
                    margin-bottom: 20px;
                }
                .card {
                    background: rgba(255, 255, 255, 0.95);
                    border-radius: 15px;
                    padding: 25px;
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
                    transition: transform 0.3s ease;
                }
                .card:hover {
                    transform: translateY(-5px);
                }
                .card-header {
                    display: flex;
                    align-items: center;
                    margin-bottom: 20px;
                    padding-bottom: 15px;
                    border-bottom: 2px solid #eee;
                }
                .icon {
                    font-size: 1.5em;
                    margin-right: 10px;
                    color: var(--primary);
                }
                .card-title {
                    font-size: 1.3em;
                    color: var(--secondary);
                    font-weight: 600;
                }
                .info-row {
                    display: flex;
                    justify-content: space-between;
                    padding: 10px 0;
                    border-bottom: 1px solid #eee;
                }
                .info-row:last-child {
                    border-bottom: none;
                }
                .label {
                    color: #666;
                    font-weight: 500;
                }
                .value {
                    color: var(--dark);
                    font-weight: 600;
                    text-align: right;
                    max-width: 60%;
                    word-break: break-word;
                }
                .ip-display {
                    background: var(--dark);
                    color: white;
                    padding: 15px;
                    border-radius: 10px;
                    font-family: 'Courier New', monospace;
                    font-size: 1.2em;
                    text-align: center;
                    margin: 10px 0;
                }
                .location-badge {
                    display: inline-block;
                    background: var(--success);
                    color: white;
                    padding: 5px 10px;
                    border-radius: 5px;
                    font-size: 0.9em;
                    margin: 2px;
                }
                .controls {
                    text-align: center;
                    margin-top: 30px;
                }
                .btn {
                    display: inline-block;
                    background: var(--primary);
                    color: white;
                    padding: 12px 25px;
                    border-radius: 8px;
                    text-decoration: none;
                    margin: 5px;
                    border: none;
                    cursor: pointer;
                    font-size: 1em;
                    font-weight: 600;
                    transition: all 0.3s ease;
                }
                .btn:hover {
                    background: var(--secondary);
                    transform: translateY(-2px);
                }
                .btn-secondary {
                    background: #6c757d;
                }
                .btn-warning {
                    background: var(--warning);
                }
                .footer {
                    text-align: center;
                    margin-top: 30px;
                    padding: 20px;
                    color: white;
                    opacity: 0.8;
                }
                @media (max-width: 768px) {
                    .grid {
                        grid-template-columns: 1fr;
                    }
                    h1 {
                        font-size: 2em;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>🌐 Visitor Information Dashboard</h1>
                    <div class="subtitle">Running on Contabo VPS</div>
                    <div class="server-ip">Server IP: ${req.headers['host']}</div>
                </header>
                
                <div class="grid">
                    <!-- Network Information -->
                    <div class="card">
                        <div class="card-header">
                            <span class="icon">📡</span>
                            <div class="card-title">Network Information</div>
                        </div>
                        <div class="ip-display">
                            ${visitorInfo.network.ip}
                            ${visitorInfo.network.type === 'private' ? 
                                '<span style="color: #ffcc00;">(Private IP)</span>' : 
                                '<span style="color: #4cd964;">(Public IP)</span>'}
                        </div>
                        ${visitorInfo.network.location ? `
                        <div class="info-row">
                            <span class="label">Location:</span>
                            <span class="value">
                                ${visitorInfo.network.location.city || 'Unknown'}, 
                                ${visitorInfo.network.location.region}, 
                                ${visitorInfo.network.location.countryName}
                            </span>
                        </div>
                        <div class="info-row">
                            <span class="label">Coordinates:</span>
                            <span class="value">
                                ${visitorInfo.network.location.coordinates ? 
                                    visitorInfo.network.location.coordinates.join(', ') : 'Unknown'}
                            </span>
                        </div>
                        <div class="info-row">
                            <span class="label">Timezone:</span>
                            <span class="value">${visitorInfo.network.location.timezone || 'Unknown'}</span>
                        </div>
                        ` : `
                        <div class="info-row">
                            <span class="label">Status:</span>
                            <span class="value" style="color: #ff6b6b;">
                                ${visitorInfo.network.error || 'Location data unavailable'}
                            </span>
                        </div>
                        `}
                        <div class="info-row">
                            <span class="label">Network Type:</span>
                            <span class="value">${visitorInfo.network.type.toUpperCase()}</span>
                        </div>
                    </div>
                    
                    <!-- Device Information -->
                    <div class="card">
                        <div class="card-header">
                            <span class="icon">💻</span>
                            <div class="card-title">Device Information</div>
                        </div>
                        <div class="info-row">
                            <span class="label">Browser:</span>
                            <span class="value">${visitorInfo.device.browser}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Operating System:</span>
                            <span class="value">${visitorInfo.device.os}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Device Type:</span>
                            <span class="value">${visitorInfo.device.device}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Engine:</span>
                            <span class="value">${visitorInfo.device.engine}</span>
                        </div>
                        ${visitorInfo.device.model !== 'Unknown' ? `
                        <div class="info-row">
                            <span class="label">Model:</span>
                            <span class="value">${visitorInfo.device.model}</span>
                        </div>
                        ` : ''}
                    </div>
                    
                    <!-- Request Details -->
                    <div class="card">
                        <div class="card-header">
                            <span class="icon">📋</span>
                            <div class="card-title">Request Details</div>
                        </div>
                        <div class="info-row">
                            <span class="label">Timestamp:</span>
                            <span class="value">${visitorInfo.timestamp.local}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Method:</span>
                            <span class="value">${visitorInfo.request.method}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Protocol:</span>
                            <span class="value">${visitorInfo.request.protocol.toUpperCase()}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Languages:</span>
                            <span class="value">${visitorInfo.request.languages || 'Unknown'}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Referrer:</span>
                            <span class="value">${visitorInfo.request.referer}</span>
                        </div>
                    </div>
                </div>
                
                <div class="controls">
                    <button class="btn" onclick="refreshPage()">🔄 Refresh Data</button>
                    <button class="btn btn-secondary" onclick="copyToClipboard('${visitorInfo.network.ip}')">
                        📋 Copy IP
                    </button>
                    <button class="btn btn-warning" onclick="showJson()">📊 View JSON</button>
                    <button class="btn" onclick="shareLink()">📤 Share This Page</button>
                </div>
                
                <div id="jsonViewer" style="display: none; margin-top: 30px;">
                    <div class="card">
                        <div class="card-header">
                            <span class="icon">📊</span>
                            <div class="card-title">Raw JSON Data</div>
                        </div>
                        <pre style="background: #f8f9fa; padding: 20px; border-radius: 8px; overflow-x: auto; max-height: 500px;">
${JSON.stringify(visitorInfo, null, 2)}
                        </pre>
                    </div>
                </div>
                
                <div class="footer">
                    <p>Server running on Contabo VPS | ${visitorInfo.timestamp.local}</p>
                    <p>Access this page from different networks to see public IP information</p>
                </div>
            </div>
            
            <script>
                // Refresh page
                function refreshPage() {
                    window.location.reload();
                }
                
                // Copy IP to clipboard
                function copyToClipboard(text) {
                    navigator.clipboard.writeText(text).then(() => {
                        alert('IP address copied to clipboard: ' + text);
                    });
                }
                
                // Show JSON data
                function showJson() {
                    const viewer = document.getElementById('jsonViewer');
                    viewer.style.display = viewer.style.display === 'none' ? 'block' : 'none';
                }
                
                // Share page
                function shareLink() {
                    if (navigator.share) {
                        navigator.share({
                            title: 'Visitor Information',
                            text: 'Check out my visitor information server!',
                            url: window.location.href
                        });
                    } else {
                        copyToClipboard(window.location.href);
                        alert('Link copied to clipboard! Share it with others.');
                    }
                }
                
                // Auto-refresh every 2 minutes
                setTimeout(refreshPage, 120000);
            </script>
        </body>
        </html>
        `);
    }
});

// API endpoints
app.get('/api/ip', (req, res) => {
    res.json({ ip: req.clientIp });
});

app.get('/api/info', (req, res) => {
    const info = {
        ip: req.clientIp,
        location: getLocationData(req.clientIp),
        device: getDeviceInfo(req.headers['user-agent']),
        timestamp: new Date().toISOString()
    };
    res.json(info);
});

app.get('/api/headers', (req, res) => {
    res.json(req.headers);
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: `Cannot ${req.method} ${req.url}`,
        availableEndpoints: ['/', '/api/ip', '/api/info', '/api/headers', '/health']
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong!'
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`
    ===================================================
    🚀 Visitor Information Server
    ===================================================
    
    📍 Server running on port: ${PORT}
    🌐 Access URLs:
       - http://localhost:${PORT}
       - http://YOUR_CONTABO_IP:${PORT}
    
    🔧 Features:
       - Real-time visitor tracking
       - IP geolocation
       - Device detection
       - Rate limiting
       - Security headers
    
    📊 API Endpoints:
       - GET /           - HTML dashboard
       - GET /api/ip     - Raw IP address
       - GET /api/info   - JSON info
       - GET /api/headers- Request headers
       - GET /health     - Health check
    
    ⚡ Auto-start with PM2:
       pm2 start server.js --name visitor-server
       pm2 save
       pm2 startup
    
    ===================================================
    `);
});