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
        "default-src 'none'; object-src 'none'; form-action 'self'; manifest-src 'self'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests; block-all-mixed-content; script-src 'nonce-hPbORtHvBUB532MSTnzG47VMdw+4Ei5i'; style-src 'nonce-hPbORtHvBUB532MSTnzG47VMdw+4Ei5i'",
    };
    const DEFAULT_MAX_AGE = 63072000;

    const BLOCKED_HEADERS = [
      "Public-Key-Pins",
      "X-Powered-By",
      "X-AspNet-Version",
    ];

    let response = await fetch(request);
    let newHeaders = new Headers(response.headers);

    // Handle Strict-Transport-Security header.
    let hstsWasPresent = false;
    let hstsWasOverwritten = false;

    if (newHeaders.has("Strict-Transport-Security")) {
      hstsWasPresent = true;

      const existingHsts =
        newHeaders.get("Strict-Transport-Security") || "";
      const maxAgeMatch = existingHsts.match(/max-age\s*=\s*(\d+)/i);

      if (maxAgeMatch) {
        const currentMaxAge = Number(maxAgeMatch[1]);

        if (
          Number.isSafeInteger(currentMaxAge) &&
          currentMaxAge >= 0 &&
          currentMaxAge < DEFAULT_MAX_AGE
        ) {
          hstsWasOverwritten = true;
          newHeaders.set(
            "Strict-Transport-Security",
            DEFAULT_SECURITY_HEADERS["Strict-Transport-Security"]
          );
        }
      }
    }

    // Set other security headers (except CSP if already present).
    Object.entries(DEFAULT_SECURITY_HEADERS).forEach(([name, value]) => {
      if (
        name === "Strict-Transport-Security" &&
        hstsWasPresent &&
        !hstsWasOverwritten
      )
        return;
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
