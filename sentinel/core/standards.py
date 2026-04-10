"""
sentinel/core/standards.py

OWASP Standards Mapping Engine.

Maps every finding to:
  - OWASP ASVS (Application Security Verification Standard) section
  - OWASP WSTG (Web Security Testing Guide) section
  - Control family
  - Test intent
  - Remediation verification step
  - What would disprove this finding

Sources:
  ASVS 4.0: https://owasp.org/www-project-application-security-verification-standard/
  WSTG 4.2: https://owasp.org/www-project-web-security-testing-guide/
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ASVSMapping:
    """OWASP Application Security Verification Standard mapping."""
    section:     str   # e.g. "V2.1.1"
    title:       str   # e.g. "Password Security Requirements"
    level:       int   # 1=opportunistic, 2=standard, 3=advanced
    requirement: str   # What the standard requires


@dataclass
class WSTGMapping:
    """OWASP Web Security Testing Guide mapping."""
    section:     str   # e.g. "WSTG-AUTHN-01"
    title:       str   # e.g. "Testing for Credentials Transported over an Encrypted Channel"
    description: str   # What this test covers


@dataclass
class ControlMapping:
    """
    Complete standards mapping for a finding.
    Every confirmed finding must have this.
    """
    control_family:   str              # Authentication|Authorization|Input Validation|etc.
    asvs:             list[ASVSMapping]
    wstg:             list[WSTGMapping]
    test_intent:      str              # What security assumption this probe validates
    remediation_steps: list[str]       # Ordered remediation actions
    verification_test: str             # Exact test to confirm fix worked
    falsification:    str              # What would disprove this finding
    exploitability:   str              # How easy is exploitation
    business_impact:  str              # What happens if exploited

    def format_short(self) -> str:
        asvs_refs = ", ".join(f"ASVS {a.section}" for a in self.asvs[:2])
        wstg_refs = ", ".join(f"{w.section}" for w in self.wstg[:2])
        return f"[{self.control_family}] {asvs_refs} | {wstg_refs}"

    def format_full(self) -> str:
        lines = [
            f"Control Family:   {self.control_family}",
            f"Test Intent:      {self.test_intent}",
            "",
            "ASVS Mappings:",
        ]
        for a in self.asvs:
            lines.append(f"  {a.section} (L{a.level}) — {a.title}")
            lines.append(f"  Requirement: {a.requirement}")
        lines.append("")
        lines.append("WSTG Mappings:")
        for w in self.wstg:
            lines.append(f"  {w.section} — {w.title}")
        lines.append("")
        lines.append("Remediation:")
        for i, step in enumerate(self.remediation_steps, 1):
            lines.append(f"  {i}. {step}")
        lines.append(f"\nVerification test: {self.verification_test}")
        lines.append(f"Falsification:     {self.falsification}")
        lines.append(f"Exploitability:    {self.exploitability}")
        lines.append(f"Business impact:   {self.business_impact}")
        return "\n".join(lines)


# ── Standards database ────────────────────────────────────────────────────────

CONTROL_FAMILIES = {
    "authentication":       "Authentication",
    "authorization":        "Authorization / Access Control",
    "input_validation":     "Input Validation",
    "api_security":         "API Security",
    "cryptography":         "Cryptography",
    "session_management":   "Session Management",
    "error_handling":       "Error Handling / Information Disclosure",
    "configuration":        "Security Configuration",
    "data_protection":      "Sensitive Data Protection",
    "transport_security":   "Transport Layer Security",
    "business_logic":       "Business Logic",
    "client_side":          "Client-Side Security",
}

STANDARDS_DB: dict[str, ControlMapping] = {

    # ── Authentication ────────────────────────────────────────────────────────

    "no_rate_limiting_auth": ControlMapping(
        control_family="Authentication",
        asvs=[
            ASVSMapping("V2.2.1", "Anti-Automation Controls", 1,
                        "Verify that anti-automation controls are effective at mitigating "
                        "breached credential testing, brute force, and account lockout attacks."),
            ASVSMapping("V2.2.2", "Login Throttling", 1,
                        "Verify that the use of weak authenticators cannot be discovered by "
                        "forcing accounts into a lockout state."),
        ],
        wstg=[
            WSTGMapping("WSTG-AUTHN-03", "Testing for Weak Lock Out Mechanism",
                        "Verify the application implements an account lockout or rate limiting "
                        "mechanism to prevent automated credential attacks."),
        ],
        test_intent="Validate that the authentication endpoint implements rate limiting "
                    "to prevent credential stuffing and brute force attacks.",
        remediation_steps=[
            "Implement IP-based rate limiting: max 5 failed attempts per minute",
            "Return HTTP 429 with Retry-After header when threshold exceeded",
            "Implement progressive backoff: 1s, 5s, 30s, 5min after repeated failures",
            "Consider CAPTCHA after 3 consecutive failures",
            "Log failed attempts for anomaly detection",
        ],
        verification_test="Send 6 rapid failed login attempts. "
                          "Verify HTTP 429 is returned on the 6th attempt.",
        falsification="If HTTP 429 is returned before 10 attempts, "
                      "rate limiting is operational.",
        exploitability="Medium — requires automation but no special skill. "
                       "Tools: Hydra, Burp Intruder, custom scripts.",
        business_impact="Account takeover via credential stuffing. "
                        "Enables bulk compromise of reused passwords.",
    ),

    "unauthenticated_api": ControlMapping(
        control_family="Authorization / Access Control",
        asvs=[
            ASVSMapping("V4.1.1", "Access Control Design", 1,
                        "Verify that the application enforces access control rules on a trusted "
                        "service layer, especially if client-side access control is present."),
            ASVSMapping("V4.1.3", "Principle of Least Privilege", 1,
                        "Verify that the principle of least privilege exists: users should only "
                        "be able to access functions, data files, URLs, controllers, services, "
                        "and other resources for which they possess specific authorization."),
        ],
        wstg=[
            WSTGMapping("WSTG-ATHZ-01", "Testing Directory Traversal File Include",
                        "Verify that access controls prevent unauthorized resource access."),
            WSTGMapping("WSTG-ATHZ-02", "Testing for Bypassing Authorization Schema",
                        "Verify that the authorization schema cannot be bypassed."),
        ],
        test_intent="Verify that API endpoints enforce authentication before returning data. "
                    "A GET request without an Authorization header should return 401.",
        remediation_steps=[
            "Apply authentication middleware to all non-public API routes",
            "Return HTTP 401 Unauthorized for unauthenticated requests",
            "Do not rely on client-side access control (Angular guards, etc.)",
            "Implement server-side authorization checks on every request",
            "Audit all API routes using a route map analysis",
        ],
        verification_test="Send GET request to endpoint without Authorization header. "
                          "Verify HTTP 401 is returned.",
        falsification="If endpoint returns 401 without credentials, "
                      "authentication is enforced.",
        exploitability="Critical — zero skill required. Any HTTP client works.",
        business_impact="Complete data exposure. All records accessible to any user.",
    ),

    "unauthenticated_admin": ControlMapping(
        control_family="Authorization / Access Control",
        asvs=[
            ASVSMapping("V4.1.2", "Function Level Access Control", 1,
                        "Verify that sensitive data and APIs are protected against "
                        "Insecure Direct Object Reference attacks."),
            ASVSMapping("V4.2.1", "Operation Level Access Control", 2,
                        "Verify that sensitive data and APIs are protected against "
                        "function level access control bypass."),
        ],
        wstg=[
            WSTGMapping("WSTG-ATHZ-02", "Testing for Bypassing Authorization Schema",
                        "Verify admin functionality requires elevated privileges."),
        ],
        test_intent="Verify that administrative interfaces require authentication "
                    "and cannot be accessed by unauthenticated users.",
        remediation_steps=[
            "Implement server-side authentication check on all admin routes",
            "Do not rely on client-side routing (SPA admin routes are not protected)",
            "Return 401/403 for unauthenticated admin requests",
            "Separate admin functionality into a distinct authenticated context",
        ],
        verification_test="Request admin endpoint without session/token. "
                          "Verify 401 or redirect to login.",
        falsification="Admin endpoint returns 401 or redirects to login "
                      "for unauthenticated requests.",
        exploitability="Critical — if real admin functionality is exposed.",
        business_impact="Full administrative access. User management, "
                        "data manipulation, configuration changes.",
    ),

    "sql_injection_condition": ControlMapping(
        control_family="Input Validation",
        asvs=[
            ASVSMapping("V5.3.4", "Output Encoding and Injection Prevention", 1,
                        "Verify that data selection or database queries use parameterized "
                        "queries, ORMs, entity frameworks, or are otherwise protected from "
                        "SQL injection attacks."),
            ASVSMapping("V5.2.3", "Sanitization and Sandboxing", 1,
                        "Verify that unstructured data is sanitized to enforce safety measures "
                        "such as allowed characters and length."),
        ],
        wstg=[
            WSTGMapping("WSTG-INPV-05", "Testing for SQL Injection",
                        "Verify the application does not construct SQL queries "
                        "using unsanitized user input."),
        ],
        test_intent="Detect whether user-controlled input is incorporated directly "
                    "into SQL queries without parameterization. "
                    "Observed by error response when probe character is sent.",
        remediation_steps=[
            "Replace string concatenation with parameterized queries",
            "Use prepared statements: SELECT * FROM t WHERE id = ?",
            "Use ORM with built-in parameterization (Sequelize, SQLAlchemy, Hibernate)",
            "Implement input validation: reject non-numeric IDs in ID fields",
            "Disable SQL error messages in production responses",
        ],
        verification_test="Send single quote to input. Verify no SQL error in response. "
                          "Verify identical behavior for valid and invalid inputs.",
        falsification="If application returns identical responses for valid input "
                      "and probe input, injection is mitigated.",
        exploitability="High — condition detected. Full exploitation requires "
                       "crafted payloads (not performed here).",
        business_impact="Database read/write access. Authentication bypass. "
                        "Potential for full data extraction.",
    ),

    "missing_https": ControlMapping(
        control_family="Transport Layer Security",
        asvs=[
            ASVSMapping("V9.1.1", "Client Communication Security", 1,
                        "Verify that TLS is used for all client connectivity, and does not "
                        "fall back to insecure or unencrypted communications."),
            ASVSMapping("V9.1.2", "HSTS Implementation", 2,
                        "Verify that HTTP Strict Transport Security headers are included on "
                        "all requests and for all subdomains."),
        ],
        wstg=[
            WSTGMapping("WSTG-CRYP-03", "Testing for Sensitive Information Sent via Unencrypted Channels",
                        "Verify that sensitive data is not transmitted in cleartext."),
        ],
        test_intent="Verify that HTTP traffic is redirected to HTTPS and "
                    "HSTS is configured to prevent protocol downgrade.",
        remediation_steps=[
            "Configure permanent 301 redirect from HTTP to HTTPS",
            "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "Enable HSTS preloading via hstspreload.org",
            "Ensure TLS 1.2+ with strong cipher suites",
        ],
        verification_test="Send HTTP request. Verify 301 redirect to HTTPS. "
                          "Verify HSTS header present on HTTPS response.",
        falsification="If HTTP returns 301 to HTTPS and HSTS header is present, "
                      "transport security is enforced.",
        exploitability="Medium — requires network position (MitM). "
                       "Not trivially exploitable remotely.",
        business_impact="Session hijacking, credential interception on shared networks.",
    ),

    "cors_wildcard": ControlMapping(
        control_family="API Security",
        asvs=[
            ASVSMapping("V14.4.8", "HTTP Security Headers", 1,
                        "Verify that the Cross-Origin Resource Sharing (CORS) "
                        "Access-Control-Allow-Origin header uses an explicit allowlist "
                        "of trusted domains and subdomains to match against."),
        ],
        wstg=[
            WSTGMapping("WSTG-CLNT-07", "Testing Cross Origin Resource Sharing",
                        "Verify CORS policy does not allow arbitrary cross-origin requests."),
        ],
        test_intent="Verify that the CORS policy restricts cross-origin requests "
                    "to explicitly trusted domains.",
        remediation_steps=[
            "Replace Access-Control-Allow-Origin: * with explicit origin allowlist",
            "Implement dynamic origin validation against allowlist",
            "Never combine wildcard CORS with credentials (Access-Control-Allow-Credentials: true)",
            "Restrict CORS to specific trusted domains only",
        ],
        verification_test="Send request with Origin: https://malicious.example.com. "
                          "Verify response does not reflect the malicious origin.",
        falsification="If CORS response does not include the untrusted origin, "
                      "policy is correctly restrictive.",
        exploitability="Medium — requires user to visit attacker-controlled page.",
        business_impact="Cross-origin data theft from authenticated sessions.",
    ),

    "missing_security_header": ControlMapping(
        control_family="Security Configuration",
        asvs=[
            ASVSMapping("V14.4.1", "HTTP Security Headers", 1,
                        "Verify that every HTTP response contains a Content-Type header. "
                        "Also verify that a safe character set is specified "
                        "(e.g., UTF-8, ISO-8859-1) if the content types are text/plain "
                        "or text/html."),
            ASVSMapping("V14.4.3", "Content Security Policy", 2,
                        "Verify that a Content Security Policy response header is in place "
                        "that helps mitigate impact for XSS attacks."),
        ],
        wstg=[
            WSTGMapping("WSTG-CONF-12", "Testing for Content Security Policy",
                        "Verify CSP and security headers are properly configured."),
        ],
        test_intent="Verify that defensive HTTP security headers are configured "
                    "to reduce attack surface for XSS, clickjacking, and MIME sniffing.",
        remediation_steps=[
            "Add Content-Security-Policy: default-src 'self'",
            "Add X-Frame-Options: DENY",
            "Add X-Content-Type-Options: nosniff",
            "Add Referrer-Policy: strict-origin-when-cross-origin",
            "Configure in reverse proxy (nginx/Apache) for consistent application",
        ],
        verification_test="Request any page. Verify all security headers present in response.",
        falsification="If all required security headers are present in response, "
                      "this control is satisfied.",
        exploitability="Low — headers are defense-in-depth, not direct exploit paths.",
        business_impact="Increases impact of other vulnerabilities (XSS, clickjacking). "
                        "Not directly exploitable alone.",
    ),

    "idor": ControlMapping(
        control_family="Authorization / Access Control",
        asvs=[
            ASVSMapping("V4.2.1", "Object Level Access Control", 1,
                        "Verify that sensitive data and APIs are protected against "
                        "Insecure Direct Object Reference (IDOR) attacks."),
            ASVSMapping("V4.1.3", "Principle of Least Privilege", 1,
                        "Verify users can only access resources they are authorized to access."),
        ],
        wstg=[
            WSTGMapping("WSTG-ATHZ-04", "Testing for Insecure Direct Object References",
                        "Verify object references enforce authorization at the object level."),
        ],
        test_intent="Verify that accessing a resource by ID enforces "
                    "ownership check — not just authentication.",
        remediation_steps=[
            "Implement object-level authorization: verify resource.user_id == session.user_id",
            "Use indirect object references (UUIDs instead of sequential integers)",
            "Never trust client-supplied IDs without server-side ownership verification",
            "Implement authorization middleware that checks resource ownership",
        ],
        verification_test="Authenticated as User A, request resource owned by User B. "
                          "Verify HTTP 403 is returned.",
        falsification="If request for another user's resource returns 403, "
                      "object-level authorization is enforced.",
        exploitability="High — trivial with authenticated session and predictable IDs.",
        business_impact="Access to other users' private data, orders, profiles, messages.",
    ),

    "jwt_weakness": ControlMapping(
        control_family="Session Management",
        asvs=[
            ASVSMapping("V3.5.1", "Token Based Session Management", 2,
                        "Verify the application does not treat unsigned or weakly signed "
                        "JWT tokens as trusted. Verify that tokens are validated using "
                        "their signing key or secret."),
            ASVSMapping("V3.5.2", "JWT Expiry", 2,
                        "Verify that tokens have a short expiry (under 1 hour) and "
                        "that refresh tokens implement sliding window expiry."),
        ],
        wstg=[
            WSTGMapping("WSTG-SESS-10", "Testing JSON Web Tokens",
                        "Verify JWT implementation is secure against known attacks."),
        ],
        test_intent="Verify JWT tokens are signed with a strong secret, "
                    "reject the none algorithm, and include appropriate expiry.",
        remediation_steps=[
            "Reject JWTs with alg=none server-side",
            "Use RS256 or ES256 (asymmetric) instead of HS256",
            "Set exp claim: 15-60 minute token lifetime",
            "Implement refresh token rotation",
            "Use a cryptographically random secret (32+ bytes) for HS256",
        ],
        verification_test="Send JWT with alg=none. Verify request is rejected. "
                          "Verify tokens expire within configured window.",
        falsification="If modified tokens are rejected with 401, "
                      "token validation is enforced.",
        exploitability="Critical if none algorithm — trivial token forgery. "
                       "High if weak secret — offline cracking.",
        business_impact="Authentication bypass. Impersonation of any user. "
                        "Potential admin privilege escalation.",
    ),

    "sensitive_data_exposure": ControlMapping(
        control_family="Sensitive Data Protection",
        asvs=[
            ASVSMapping("V6.2.1", "Algorithms", 1,
                        "Verify that all cryptographic modules fail securely and that "
                        "errors are handled in a way that does not enable oracle padding."),
            ASVSMapping("V8.3.1", "Sensitive Private Data", 1,
                        "Verify that sensitive data is sent to the server in the HTTP "
                        "message body or headers, and that query string parameters from "
                        "any HTTP verb do not contain sensitive data."),
        ],
        wstg=[
            WSTGMapping("WSTG-CRYP-04", "Testing for Weak Encryption",
                        "Verify sensitive data is not stored or transmitted in cleartext."),
            WSTGMapping("WSTG-CONF-10", "Testing for Sensitive Information in HTTP Referrer",
                        "Verify sensitive data is not exposed in API responses."),
        ],
        test_intent="Verify that API responses do not include sensitive fields "
                    "(passwords, tokens, PII) that are not required by the client.",
        remediation_steps=[
            "Implement response field allowlisting — explicitly define which fields to return",
            "Never return password hashes in API responses",
            "Remove sensitive fields from serialization layer",
            "Implement separate DTOs for public vs internal representations",
        ],
        verification_test="Request user profile endpoint. Verify response does not "
                          "contain password, passwordHash, totpSecret, or tokens.",
        falsification="If response does not contain sensitive fields, "
                      "data minimization is implemented.",
        exploitability="High — data is directly readable in response.",
        business_impact="Credential exposure, account takeover, PII breach.",
    ),

    "information_disclosure_error": ControlMapping(
        control_family="Error Handling / Information Disclosure",
        asvs=[
            ASVSMapping("V7.4.1", "Error Handling", 1,
                        "Verify that a generic message is shown when an unexpected or "
                        "security sensitive error occurs, potentially with a unique ID "
                        "which support personnel can use to investigate."),
        ],
        wstg=[
            WSTGMapping("WSTG-ERRH-01", "Testing for Improper Error Handling",
                        "Verify error messages do not disclose sensitive information."),
            WSTGMapping("WSTG-ERRH-02", "Testing for Stack Traces",
                        "Verify stack traces are not exposed to users."),
        ],
        test_intent="Verify that error responses do not expose internal implementation "
                    "details, stack traces, database errors, or framework versions.",
        remediation_steps=[
            "Configure error handling to return generic messages in production",
            "Set NODE_ENV=production, DEBUG=false, or equivalent",
            "Log full errors server-side, never expose to client",
            "Return generic error ID that support staff can correlate to logs",
        ],
        verification_test="Trigger an error condition. Verify response contains "
                          "only a generic message, not a stack trace.",
        falsification="If error responses contain only generic messages, "
                      "information disclosure is controlled.",
        exploitability="Low — provides reconnaissance value but not direct exploit.",
        business_impact="Reveals technology stack, internal paths, and query structure "
                        "to aid targeted attacks.",
    ),
}


def map_finding(title: str, description: str) -> Optional[ControlMapping]:
    """
    Map a finding title/description to its standards entry.
    Returns None if no mapping found.
    """
    text = (title + " " + description).lower()

    # Order: most specific first
    if "rate limit" in text and ("auth" in text or "login" in text):
        return STANDARDS_DB["no_rate_limiting_auth"]
    if "sql injection" in text or "sqli" in text:
        return STANDARDS_DB["sql_injection_condition"]
    if "jwt" in text:
        return STANDARDS_DB["jwt_weakness"]
    if "idor" in text or "insecure direct" in text:
        return STANDARDS_DB["idor"]
    if "unauthenticated" in text and "admin" in text:
        return STANDARDS_DB["unauthenticated_admin"]
    if "unauthenticated" in text or "without auth" in text or "no auth" in text:
        return STANDARDS_DB["unauthenticated_api"]
    if "cors" in text and "wildcard" in text:
        return STANDARDS_DB["cors_wildcard"]
    if "https" in text and ("redirect" in text or "missing" in text):
        return STANDARDS_DB["missing_https"]
    if "sensitive" in text and ("data" in text or "field" in text):
        return STANDARDS_DB["sensitive_data_exposure"]
    if "header" in text and ("security" in text or "missing" in text):
        return STANDARDS_DB["missing_security_header"]
    if "stack trace" in text or "error" in text and "disclose" in text:
        return STANDARDS_DB["information_disclosure_error"]

    return None


def enrich_finding_with_standards(finding_title: str,
                                   finding_description: str) -> dict:
    """
    Returns a dict with all standards mappings for a finding.
    """
    mapping = map_finding(finding_title, finding_description)
    if not mapping:
        return {
            "control_family":    "Uncategorized",
            "asvs_refs":         [],
            "wstg_refs":         [],
            "test_intent":       "No standard mapping found",
            "remediation_steps": [],
            "verification_test": "Manual review required",
            "falsification":     "Not defined",
            "exploitability":    "Unknown",
            "business_impact":   "Unknown",
        }
    return {
        "control_family":    mapping.control_family,
        "asvs_refs":         [f"{a.section} — {a.title}" for a in mapping.asvs],
        "wstg_refs":         [f"{w.section} — {w.title}" for w in mapping.wstg],
        "test_intent":       mapping.test_intent,
        "remediation_steps": mapping.remediation_steps,
        "verification_test": mapping.verification_test,
        "falsification":     mapping.falsification,
        "exploitability":    mapping.exploitability,
        "business_impact":   mapping.business_impact,
        "formatted_short":   mapping.format_short(),
    }


# For type hints
from typing import Optional
