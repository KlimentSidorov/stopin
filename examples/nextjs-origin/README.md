# Local protected Next.js origin

This is a test fixture, not the customer dashboard or production website.
The custom `server.cjs` checks the gateway secret before calling Next.js for any
route or static asset. It listens only on loopback. Start it with `npm start`;
`next start` / `next dev` do not install the guard.

See [setup, acceptance tests, and deployment scope](../../docs/origin-security.md).
Do not put the origin secret in a NEXT_PUBLIC variable or next.config env output.
