# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-ssrf-safe-url -->
### sec-ssrf-safe-url — Validate outbound URLs before fetching

User-supplied URLs go through SafeUrlUtils.toSafeUrl (http/https only, host required, no userinfo, resolved address must be public) and are fetched with redirects disabled. Use it for any new outbound fetch of a user URL.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-aes-gcm -->
### sec-aes-gcm — Encrypt with AES-GCM and verify by decrypting

EncryptionUtils uses AES/GCM/NoPadding with a random 12-byte IV, so output is non-deterministic. Callers must verify by calling decrypt, not by re-encrypting and comparing ciphertext.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-shell-argv -->
### sec-no-shell-argv — Run commands with a fixed argv, no shell

Request values must never be concatenated into a shell command string. Validate the target against a hostname or IP allowlist and pass it as a separate ProcessBuilder argument.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-confinement -->
### sec-path-confinement — Confine file paths to a fixed root

Resolve caller or config supplied paths against a fixed root, normalize, and check startsWith and toRealPath containment before use. Reject escapes with 400 and reserve 404 for a missing file inside the root.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

Request values in this repo go into SQL through ? placeholders and bind arguments, and the JPA criteria query binds a parsed Integer. DDL that cannot bind, such as CREATE USER, must use the escaping helper toSqlStringLiteral.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-html-encode -->
### sec-html-encode — Encode request values before putting them in HTML

Reflected XSS payloads encode every request value with Spring HtmlUtils.htmlEscape and quote attribute placeholders such as src. This applies to intentionally vulnerable demo levels too.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-gha-env-interpolation -->
### sec-gha-env-interpolation — Pass workflow expressions through env

GitHub Actions run steps must not interpolate github or matrix expressions into script text. Put them in step-level env and read them as shell or os.environ variables.
<!-- /harness-remediation -->
