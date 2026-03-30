export default {
  async fetch(request) {
    const DEFAULT_SECURITY_HEADERS = {
      "X-Content-Type-Options": "nosniff",
      "Strict-Transport-Security":
        "max-age=63072000; includeSubDomains; preload",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Cross-Origin-Embedder-Policy": 'require-corp; report-to="default";',
      "Cross-Origin-Opener-Policy": 'same-site; report-to="default";',
      "Cross-Origin-Resource-Policy": "same-site",
      "Content-Security-Policy":
        "default-src 'none'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests; style-src 'nonce-hPbORtHvBUB532MSTnzG47VMdw+4Ei5i'",
    };
    const DEFAULT_MAX_AGE = 63072000;

    const BLOCKED_HEADERS = [
      "Public-Key-Pins",
      "X-Powered-By",
      "X-AspNet-Version",
    ];

    let response = await fetch(request);
    let newHeaders = new Headers(response.headers);

    // Set all default security headers (except CSP if already present).
    // Always force-set HSTS to override zone-level settings.
    Object.entries(DEFAULT_SECURITY_HEADERS).forEach(([name, value]) => {
      if (name === "Content-Security-Policy" && newHeaders.has(name)) return;
      newHeaders.set(name, value);
    });

    // Delete blocked headers.
    BLOCKED_HEADERS.forEach((name) => {
      newHeaders.delete(name);
    });

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  },
};
