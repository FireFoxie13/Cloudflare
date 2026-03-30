export default {
  async fetch(request) {
    const securityHeaders = {
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Cross-Origin-Embedder-Policy": 'require-corp; report-to="default"',
      "Cross-Origin-Opener-Policy": 'same-site; report-to="default"',
      "Cross-Origin-Resource-Policy": "same-site",
      "Content-Security-Policy":
        "default-src 'none'; object-src 'none'; form-action 'self'; manifest-src 'self'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests; block-all-mixed-content; style-src 'nonce-hPbORtHvBUB532MSTnzG47VMdw+4Ei5i'",
    };

    const response = await fetch(request);
    const newHeaders = new Headers(response.headers);

    // Add each security header only if not already present
    for (const [name, value] of Object.entries(securityHeaders)) {
      if (!newHeaders.has(name)) {
        newHeaders.set(name, value);
      }
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  },
};
