const http = require('node:http');
const crypto = require('node:crypto');
const next = require('next');

const secret = process.env.GATEWAY_ORIGIN_SECRET || '';
if (secret.length < 32 || !/^[\x20-\x7e]+$/.test(secret)) {
  throw new Error('GATEWAY_ORIGIN_SECRET must contain at least 32 printable ASCII characters');
}
const expected = Buffer.from(secret, 'ascii');
const hostname = '127.0.0.1';
const port = Number(process.env.PORT || 9000);
const app = next({dev: false, dir: __dirname, hostname, port});
const handle = app.getRequestHandler();

app.prepare().then(() => {
  const server = http.createServer(async (req, res) => {
    const values = [];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if (req.rawHeaders[i].toLowerCase() === 'x-gateway-origin-secret') {
        values.push(req.rawHeaders[i + 1]);
      }
    }
    const supplied = Buffer.from(values[0] || '', 'utf8');
    if (values.length !== 1 || supplied.length !== expected.length ||
        !crypto.timingSafeEqual(supplied, expected)) {
      res.writeHead(403, {'Cache-Control': 'no-store', 'Content-Length': '0'});
      res.end();
      return;
    }
    // Strip the secret before Next.js route code can inspect request headers.
    delete req.headers['x-gateway-origin-secret'];
    for (let i = req.rawHeaders.length - 2; i >= 0; i -= 2) {
      if (req.rawHeaders[i].toLowerCase() === 'x-gateway-origin-secret') req.rawHeaders.splice(i, 2);
    }
    try {
      await handle(req, res);
    } catch {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    }
  });
  // No secondary public listener or unguarded WebSocket upgrade path.
  server.on('upgrade', (_req, socket) => socket.destroy());
  server.listen(port, hostname, () => console.log(`ORIGIN_READY ${server.address().port}`));
}).catch(() => {
  console.error('Origin startup failed. Build the Next.js app before starting.');
  process.exit(1);
});
