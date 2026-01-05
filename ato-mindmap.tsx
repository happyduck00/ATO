import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Shield, Unlock, Key, Users, AlertTriangle, Lock, FileText, TestTube, BookOpen } from 'lucide-react';

const MindMap = () => {
  const [expanded, setExpanded] = useState({});
  const [selected, setSelected] = useState(null);

  const toggleNode = (path) => {
    setExpanded(prev => ({...prev, [path]: !prev[path]}));
  };

  const selectNode = (node) => {
    setSelected(node);
  };

  const data = {
    title: "Account Takeover Testing & Reference",
    icon: AlertTriangle,
    color: "bg-red-500",
    description: "Comprehensive testing methodology with standards and practice resources",
    children: [
      {
        title: "Authentication Mechanisms",
        icon: Key,
        color: "bg-blue-500",
        description: "Identity verification testing procedures",
        children: [
          {
            title: "Password-Based Authentication",
            testingSteps: [
              "Test password policy enforcement (length, complexity, common passwords)",
              "Attempt timing attacks on login to enumerate valid usernames",
              "Test password reset flow for token predictability and expiration",
              "Check for password in cleartext in responses, logs, or error messages",
              "Verify bcrypt/Argon2 usage via response timing (slow = good)",
              "Test account lockout mechanisms and bypass techniques",
              "Check if old passwords are rejected (password history)",
              "Test for SQL injection in authentication fields"
            ],
            standards: [
              "NIST SP 800-63B: Digital Identity Guidelines (Authentication)",
              "OWASP ASVS 2.1: Password Security Requirements",
              "CWE-521: Weak Password Requirements",
              "CWE-916: Use of Password Hash With Insufficient Computational Effort"
            ],
            practiceResources: [
              "PortSwigger: Authentication vulnerabilities (all labs)",
              "HTB: Weak credentials, login brute force boxes",
              "OWASP Juice Shop: Login Admin, Password Strength challenges",
              "TryHackMe: Authentication Bypass room",
              "PentesterLab: From SQL Injection to Shell"
            ],
            realWorldCVEs: [
              "CVE-2019-11510: Pulse Secure - Pre-auth arbitrary file read",
              "CVE-2020-5902: F5 BIG-IP - RCE via authentication bypass",
              "GitLab password reset token vulnerability (2020)"
            ],
            vulnerabilityPatterns: [
              "Timing oracles revealing valid usernames",
              "Weak password hashing (MD5, SHA-1, or low bcrypt cost)",
              "Predictable password reset tokens",
              "No rate limiting on authentication endpoints",
              "Credentials in URL parameters or GET requests"
            ],
            technologies: ["bcrypt (cost 12+)", "Argon2id", "PBKDF2 (100k+ iterations)", "scrypt"],
            gapChecklist: [
              "Can you identify hashing algorithm from response timing?",
              "Do you understand salt vs pepper vs key stretching?",
              "Can you calculate time to crack various hash types?",
              "Do you know how rainbow tables work and when they are effective?"
            ]
          },
          {
            title: "Multi-Factor Authentication (MFA)",
            testingSteps: [
              "Test MFA bypass via direct endpoint access after 1st factor",
              "Attempt replay attacks on TOTP codes",
              "Test for rate limiting on MFA code submission",
              "Check if MFA can be disabled without re-authentication",
              "Test backup codes: enumeration, reuse, expiration",
              "Attempt MFA fatigue attacks (push notification spam)",
              "Test OAuth flow MFA bypass (direct /callback access)",
              "Check if TOTP seed is exposed in responses or JavaScript",
              "Test if MFA is enforced for all authentication paths (API, mobile, etc)"
            ],
            standards: [
              "NIST SP 800-63B Section 5.1.3: Multi-Factor Authenticators",
              "RFC 6238: TOTP Time-Based One-Time Password",
              "RFC 4226: HOTP HMAC-Based One-Time Password",
              "FIDO2/WebAuthn specifications"
            ],
            practiceResources: [
              "PortSwigger: 2FA bypass labs (broken logic, simple bypass)",
              "HTB: Includes boxes with MFA implementation flaws",
              "HackTheBox Academy: Multi-Factor Authentication module",
              "OWASP Juice Shop: Two Factor Authentication challenge"
            ],
            realWorldCVEs: [
              "Cisco Duo - MFA bypass via direct authentication endpoint (2020)",
              "Reddit 2FA SMS interception incident (2018)",
              "Twitter MFA bypass via password reset (2020)"
            ],
            vulnerabilityPatterns: [
              "Direct access to post-authentication endpoints",
              "TOTP secret exposure in API responses",
              "No rate limiting allowing TOTP brute force (1M codes)",
              "Session fixation allowing MFA bypass",
              "MFA enrollment not enforced, can be skipped"
            ],
            technologies: ["Google Authenticator", "Authy", "YubiKey", "Duo Security", "SMS (deprecated)", "WebAuthn/FIDO2"],
            gapChecklist: [
              "Do you understand the TOTP algorithm and time window?",
              "Can you implement a TOTP validator from scratch?",
              "Do you know why SMS 2FA is discouraged?",
              "Can you explain WebAuthn ceremony flow?"
            ]
          },
          {
            title: "OAuth 2.0 / OIDC",
            testingSteps: [
              "Test for missing state parameter (CSRF on callback)",
              "Attempt authorization code interception via referrer",
              "Test redirect_uri validation (open redirect to attacker)",
              "Check for lack of PKCE in public clients",
              "Test implicit flow token leakage in URL fragments",
              "Verify token binding to prevent token theft usage",
              "Test account pre-linking vulnerabilities",
              "Check for client_secret exposure in JavaScript",
              "Test for scope escalation in token exchange"
            ],
            standards: [
              "RFC 6749: OAuth 2.0 Authorization Framework",
              "RFC 7636: PKCE - Proof Key for Code Exchange",
              "RFC 8252: OAuth 2.0 for Native Apps",
              "OpenID Connect Core 1.0 specification"
            ],
            practiceResources: [
              "PortSwigger: OAuth authentication labs (all 6 labs)",
              "HackTheBox: OAuth misconfiguration challenges",
              "Kontra: OAuth Security Training",
              "OAuth.tools: OAuth flow testing tool"
            ],
            realWorldCVEs: [
              "Slack OAuth token theft (2017) - redirect_uri validation",
              "GitHub OAuth Web Application Flow Vulnerability (2014)",
              "Facebook OAuth token leak via Referer header"
            ],
            vulnerabilityPatterns: [
              "Weak redirect_uri validation allowing open redirect",
              "Missing PKCE in mobile apps (authorization code interception)",
              "State parameter not validated (CSRF)",
              "Implicit flow used instead of authorization code flow",
              "Token leakage via browser history or logs"
            ],
            technologies: ["OAuth 2.0", "OpenID Connect", "PKCE", "JWT", "Passport.js", "Spring Security OAuth"],
            gapChecklist: [
              "Can you diagram all OAuth flows (auth code, implicit, client credentials)?",
              "Do you understand why implicit flow is deprecated?",
              "Can you explain PKCE and when it is required?",
              "Do you know the difference between OAuth and OIDC?"
            ]
          }
        ]
      },
      {
        title: "Session Management",
        icon: Unlock,
        color: "bg-green-500",
        description: "Authenticated state maintenance testing",
        children: [
          {
            title: "Cookie-Based Sessions",
            testingSteps: [
              "Check for HttpOnly flag (XSS cookie theft protection)",
              "Verify Secure flag is set (HTTPS-only transmission)",
              "Test SameSite attribute (None/Lax/Strict for CSRF)",
              "Attempt session fixation by setting cookie pre-auth",
              "Test for predictable session IDs",
              "Check session timeout enforcement (idle and absolute)",
              "Test concurrent session handling",
              "Verify session invalidation on logout",
              "Test session after password change",
              "Attempt session hijacking via cookie theft"
            ],
            standards: [
              "RFC 6265: HTTP State Management Mechanism (Cookies)",
              "OWASP Session Management Cheat Sheet",
              "OWASP ASVS 3.2: Session Management",
              "CWE-384: Session Fixation"
            ],
            practiceResources: [
              "PortSwigger: Session vulnerabilities (fixation, hijacking)",
              "OWASP WebGoat: Session Management Flaws",
              "OWASP Juice Shop: Admin Session challenge",
              "HTB: Session-based authentication boxes"
            ],
            realWorldCVEs: [
              "Tomcat Session Fixation (CVE-2008-2370)",
              "Apache Struts2 session management vulnerabilities",
              "Drupal session fixation (SA-CORE-2008-005)"
            ],
            vulnerabilityPatterns: [
              "Session ID in URL (leaks via Referer)",
              "Missing HttpOnly allowing XSS cookie theft",
              "No SameSite allowing CSRF attacks",
              "Sequential or predictable session IDs",
              "Session not regenerated after authentication",
              "No absolute timeout (sessions valid indefinitely)"
            ],
            technologies: ["express-session", "Redis", "Memcached", "connect-redis", "Database session stores"],
            gapChecklist: [
              "Can you calculate session ID entropy?",
              "Do you understand the impact of each cookie attribute?",
              "Can you exploit session fixation in a real app?",
              "Do you know when to use Lax vs Strict SameSite?"
            ]
          },
          {
            title: "JWT-Based Sessions",
            testingSteps: [
              "Test algorithm confusion (change alg to none or HS256 to RS256)",
              "Attempt key confusion attacks",
              "Check for weak signing secrets (JWT_SECRET = secret)",
              "Test for missing signature verification",
              "Verify exp (expiration) claim enforcement",
              "Test for jti (JWT ID) reuse prevention",
              "Check if JWT in localStorage (XSS vulnerable)",
              "Attempt JWT parameter injection (kid, jku headers)",
              "Test for information disclosure in JWT payload",
              "Verify proper audience (aud) and issuer (iss) validation"
            ],
            standards: [
              "RFC 7519: JSON Web Token (JWT)",
              "RFC 7515: JSON Web Signature (JWS)",
              "RFC 7516: JSON Web Encryption (JWE)",
              "OWASP JWT Cheat Sheet"
            ],
            practiceResources: [
              "PortSwigger: JWT attacks (alg confusion, injection, all labs)",
              "PentesterLab: JWT Security badge",
              "jwt.io: Token decoder and verifier",
              "OWASP Juice Shop: Multiple JWT challenges"
            ],
            realWorldCVEs: [
              "Auth0 alg:none vulnerability (2015)",
              "GitLab JWT verification bypass (CVE-2020-10977)",
              "npm jsonwebtoken library vulnerabilities"
            ],
            vulnerabilityPatterns: [
              "Algorithm set to none accepted by server",
              "HS256 key confusion with RS256 public key",
              "Weak signing secret (dictionary attack)",
              "No expiration claim or not enforced",
              "Sensitive data in unencrypted payload",
              "JWTs in URL parameters or localStorage"
            ],
            technologies: ["jsonwebtoken (npm)", "PyJWT", "jose (Java)", "jwt-go (Go)", "Auth0", "Keycloak"],
            gapChecklist: [
              "Can you manually decode and verify a JWT?",
              "Do you understand JWS vs JWE?",
              "Can you exploit algorithm confusion?",
              "Do you know when NOT to use JWT?"
            ]
          }
        ]
      },
      {
        title: "Authorization & Access Control",
        icon: Users,
        color: "bg-purple-500",
        description: "Permission and access control testing",
        children: [
          {
            title: "IDOR (Insecure Direct Object Reference)",
            testingSteps: [
              "Identify sequential or predictable IDs in URLs/APIs",
              "Test accessing other users resources by changing IDs",
              "Try GUID enumeration and prediction",
              "Test for mass assignment vulnerabilities",
              "Check for base64 encoded IDs (decode and modify)",
              "Test POST/PUT/DELETE with other users resource IDs",
              "Verify authorization checks on all HTTP methods",
              "Test nested resources (/users/1/orders/2)"
            ],
            standards: [
              "OWASP Top 10 A01:2021 - Broken Access Control",
              "CWE-639: Insecure Direct Object References",
              "OWASP ASVS 4.1: Access Control"
            ],
            practiceResources: [
              "PortSwigger: Access control vulnerabilities (12+ labs)",
              "OWASP Juice Shop: View Basket, Access Log challenges",
              "HTB: Most boxes include IDOR somewhere",
              "HackTheBox Academy: IDOR module",
              "Bugcrowd University: IDOR lessons"
            ],
            realWorldCVEs: [
              "Instagram IDOR - Delete any photo (2019)",
              "Strava privacy leak via IDOR",
              "Facebook IDOR vulnerabilities (multiple)"
            ],
            vulnerabilityPatterns: [
              "Sequential numeric IDs without auth checks",
              "Authorization bypass by changing user_id parameter",
              "Missing function-level access control",
              "Horizontal privilege escalation",
              "Vertical privilege escalation to admin"
            ],
            technologies: ["Authorization middleware", "ORM access control", "API gateways"],
            gapChecklist: [
              "Can you identify IDOR in both REST and GraphQL?",
              "Do you understand horizontal vs vertical privilege escalation?",
              "Can you bypass GUIDs via enumeration?"
            ]
          }
        ]
      },
      {
        title: "Common Attack Vectors",
        icon: AlertTriangle,
        color: "bg-red-600",
        description: "Exploitation techniques and methodologies",
        children: [
          {
            title: "Credential Stuffing & Brute Force",
            testingSteps: [
              "Test rate limiting on login endpoint",
              "Attempt login with common credentials (admin/admin)",
              "Test for CAPTCHA bypass techniques",
              "Use leaked credential databases for stuffing",
              "Test for account lockout mechanisms",
              "Verify lockout cannot be used for DoS",
              "Test distributed brute force (multiple IPs)",
              "Check for user enumeration via different responses"
            ],
            standards: [
              "OWASP Automated Threats: OAT-008 Credential Stuffing",
              "NIST SP 800-63B Section 5.2.2: Rate Limiting"
            ],
            practiceResources: [
              "PortSwigger: Username enumeration, password brute force labs",
              "TryHackMe: Brute force rooms",
              "OWASP Juice Shop: Login challenges",
              "HackTheBox: Brute force authentication boxes"
            ],
            realWorldCVEs: [
              "Ring camera credential stuffing (2019)",
              "Dunkin Donuts credential stuffing incident"
            ],
            vulnerabilityPatterns: [
              "No rate limiting on authentication",
              "Weak account lockout (time or attempt based)",
              "Username enumeration via timing or response differences",
              "No CAPTCHA or easily bypassed"
            ],
            technologies: ["Hydra", "Burp Intruder", "Medusa", "Custom scripts", "Distributed attack tools"],
            gapChecklist: [
              "Can you implement effective rate limiting?",
              "Do you understand distributed attack evasion?",
              "Can you differentiate stuffing from spraying?"
            ]
          },
          {
            title: "Session Hijacking & Fixation",
            testingSteps: [
              "Intercept session tokens via network sniffing (HTTP)",
              "Steal cookies via XSS payload",
              "Test for session fixation vulnerabilities",
              "Attempt session token prediction",
              "Test cookie theft via subdomain takeover",
              "Verify session binding to IP or user agent",
              "Test for concurrent session killing",
              "Attempt session donation attacks"
            ],
            standards: [
              "OWASP Session Management Cheat Sheet",
              "CWE-384: Session Fixation",
              "CWE-294: Authentication Bypass by Capture-replay"
            ],
            practiceResources: [
              "PortSwigger: Session hijacking labs",
              "OWASP WebGoat: Hijack a Session",
              "HTB: Network-based session capture challenges"
            ],
            realWorldCVEs: [
              "Firesheep - Public WiFi session hijacking tool (2010)",
              "Various XSS leading to session theft"
            ],
            vulnerabilityPatterns: [
              "Session transmitted over HTTP",
              "No HttpOnly flag allowing XSS cookie theft",
              "Predictable session tokens",
              "Session not bound to client characteristics"
            ],
            technologies: ["Wireshark", "Burp Suite", "Browser DevTools", "BeEF XSS Framework"],
            gapChecklist: [
              "Can you perform MitM to steal sessions?",
              "Do you understand session binding techniques?",
              "Can you write XSS to exfiltrate cookies?"
            ]
          },
          {
            title: "CSRF (Cross-Site Request Forgery)",
            testingSteps: [
              "Check for anti-CSRF tokens in state-changing requests",
              "Test if tokens are validated on server",
              "Attempt token reuse across sessions",
              "Test for token in GET requests (link-based CSRF)",
              "Verify SameSite cookie attribute",
              "Test CORS configuration for CSRF protection",
              "Attempt CSRF with XMLHttpRequest or fetch",
              "Test custom header requirement for CSRF protection"
            ],
            standards: [
              "OWASP CSRF Prevention Cheat Sheet",
              "CWE-352: Cross-Site Request Forgery",
              "RFC 6265 SameSite cookies"
            ],
            practiceResources: [
              "PortSwigger: CSRF labs (token bypass, SameSite)",
              "OWASP WebGoat: CSRF challenges",
              "OWASP Juice Shop: CSRF challenge"
            ],
            realWorldCVEs: [
              "YouTube CSRF leading to account takeover",
              "GitLab CSRF vulnerabilities (multiple)"
            ],
            vulnerabilityPatterns: [
              "No CSRF token in state-changing requests",
              "CSRF token not validated or in GET request",
              "SameSite=None without Secure flag",
              "CORS misconfiguration allowing CSRF"
            ],
            technologies: ["CSRF tokens", "SameSite cookies", "Double-submit cookies", "Custom headers"],
            gapChecklist: [
              "Can you explain why SameSite=Lax prevents CSRF?",
              "Do you know when custom headers prevent CSRF?",
              "Can you bypass CSRF protection techniques?"
            ]
          },
          {
            title: "Account Recovery & Password Reset",
            testingSteps: [
              "Test password reset token predictability",
              "Check token expiration enforcement",
              "Test for token reuse after password change",
              "Verify token invalidation after use",
              "Test for user enumeration in reset flow",
              "Check if reset link works after password change",
              "Test for token leakage in Referer header",
              "Attempt host header injection in reset emails",
              "Test for account takeover via email parameter pollution"
            ],
            standards: [
              "OWASP Forgot Password Cheat Sheet",
              "CWE-640: Weak Password Recovery Mechanism",
              "NIST SP 800-63B Section 5.1.1.2: Password Reset"
            ],
            practiceResources: [
              "PortSwigger: Password reset poisoning",
              "OWASP Juice Shop: Reset password challenges",
              "HackTheBox: Password reset vulnerabilities"
            ],
            realWorldCVEs: [
              "Instagram password reset vulnerability (2016)",
              "Uber password reset token reuse (2015)",
              "Multiple platforms - Host header injection in reset"
            ],
            vulnerabilityPatterns: [
              "Predictable reset tokens (timestamp, sequential)",
              "No token expiration or long expiration",
              "Token not invalidated after use",
              "Reset link sent over HTTP",
              "User enumeration via different responses"
            ],
            technologies: ["Secure random token generation", "Time-limited tokens", "One-time use tokens"],
            gapChecklist: [
              "Can you calculate reset token entropy?",
              "Do you understand host header injection?",
              "Can you exploit email parameter pollution?"
            ]
          },
          {
            title: "Social Engineering & Phishing",
            testingSteps: [
              "Test for missing anti-phishing indicators",
              "Check email authentication (SPF, DKIM, DMARC)",
              "Test for lookalike domain detection",
              "Verify MFA prompt shows context (location, device)",
              "Test for push notification fatigue attacks",
              "Check if users can report suspicious activity",
              "Test security questions for weak answers",
              "Verify account recovery methods are secure"
            ],
            standards: [
              "NIST SP 800-63C: Federation and Assertions",
              "Anti-Phishing Working Group best practices",
              "DMARC RFC 7489"
            ],
            practiceResources: [
              "Social-Engineer Toolkit (SET)",
              "Gophish - Phishing campaign simulation",
              "TryHackMe: Social engineering rooms"
            ],
            realWorldCVEs: [
              "Twitter 2020 breach via social engineering",
              "Uber 2022 breach via MFA fatigue",
              "Countless corporate breaches via phishing"
            ],
            vulnerabilityPatterns: [
              "No email authentication enforcement",
              "Weak security questions (mother's maiden name)",
              "No context in MFA prompts",
              "Easy to replicate login pages",
              "No rate limiting on MFA push requests"
            ],
            technologies: ["SPF/DKIM/DMARC", "Browser phishing detection", "Security awareness training platforms"],
            gapChecklist: [
              "Can you craft a convincing phishing email?",
              "Do you understand DMARC policy enforcement?",
              "Can you recognize phishing indicators?"
            ]
          },
          {
            title: "API Authentication Bypass",
            testingSteps: [
              "Test API endpoints without authentication headers",
              "Attempt authentication bypass via HTTP method tampering",
              "Test for API key in URLs or logs",
              "Check for different auth on GraphQL vs REST",
              "Test for JWT validation bypass in APIs",
              "Verify API versioning has consistent auth",
              "Test for authentication on all CRUD operations",
              "Check for mass assignment vulnerabilities in APIs"
            ],
            standards: [
              "OWASP API Security Top 10",
              "REST API Security best practices",
              "GraphQL Security best practices"
            ],
            practiceResources: [
              "PortSwigger: API testing labs",
              "OWASP crAPI - Vulnerable API",
              "HackTheBox: API exploitation challenges",
              "TryHackMe: API hacking rooms"
            ],
            realWorldCVEs: [
              "Peloton API authentication bypass (2021)",
              "Experian API key exposure",
              "T-Mobile API data breach (2021)"
            ],
            vulnerabilityPatterns: [
              "Missing authentication on API endpoints",
              "API keys in client-side code or URLs",
              "Inconsistent auth across API versions",
              "GraphQL introspection enabled in production",
              "No rate limiting on API endpoints"
            ],
            technologies: ["Postman", "Burp Suite", "REST APIs", "GraphQL", "API gateways"],
            gapChecklist: [
              "Can you identify all API endpoints in an application?",
              "Do you understand GraphQL authorization challenges?",
              "Can you exploit mass assignment in APIs?"
            ]
          },
          {
            title: "Token Theft & Manipulation",
            testingSteps: [
              "Test for tokens in localStorage (XSS vulnerable)",
              "Check for tokens in URL parameters",
              "Test for token logging in application logs",
              "Verify tokens transmitted over HTTPS only",
              "Test for token theft via DNS rebinding",
              "Check for tokens in browser history",
              "Test token manipulation (JWT payload tampering)",
              "Verify token expiration is enforced"
            ],
            standards: [
              "OWASP Token Storage Cheat Sheet",
              "RFC 8725: JWT Best Current Practices",
              "NIST Cryptographic Standards"
            ],
            practiceResources: [
              "PortSwigger: JWT manipulation labs",
              "OWASP Juice Shop: JWT challenges",
              "jwt_tool: JWT testing toolkit"
            ],
            realWorldCVEs: [
              "Zoom tokens in logs (2020)",
              "Multiple apps - GitHub token exposure",
              "Auth0 algorithm confusion (2015)"
            ],
            vulnerabilityPatterns: [
              "Tokens stored in localStorage",
              "Tokens in URL query parameters",
              "Weak JWT signing algorithms",
              "No token rotation on refresh",
              "Tokens logged in application logs"
            ],
            technologies: ["JWT", "OAuth tokens", "Browser storage APIs", "Token rotation"],
            gapChecklist: [
              "Do you know all places tokens can leak?",
              "Can you exploit JWT algorithm confusion?",
              "Do you understand token binding?"
            ]
          },
          {
            title: "Username Enumeration",
            testingSteps: [
              "Test for different error messages (invalid user vs invalid password)",
              "Check response timing differences",
              "Test registration endpoint for existing users",
              "Verify password reset reveals valid emails",
              "Test for enumeration via autocomplete",
              "Check login error messages for enumeration",
              "Test for user existence via forgot password",
              "Verify consistent responses regardless of user validity"
            ],
            standards: [
              "OWASP Authentication Cheat Sheet",
              "CWE-204: Observable Response Discrepancy",
              "CWE-203: Observable Discrepancy"
            ],
            practiceResources: [
              "PortSwigger: Username enumeration labs",
              "OWASP WebGoat: Authentication flaws",
              "Custom scripts for timing analysis"
            ],
            realWorldCVEs: [
              "GitHub username enumeration (historical)",
              "Multiple platforms - Registration endpoint leaks"
            ],
            vulnerabilityPatterns: [
              "Different messages for valid/invalid users",
              "Timing differences in authentication",
              "Registration reveals existing usernames",
              "Password reset confirms email existence",
              "Autocomplete leaks valid usernames"
            ],
            technologies: ["Timing attack tools", "Burp Intruder", "Custom scripts"],
            gapChecklist: [
              "Can you perform timing-based enumeration?",
              "Do you understand statistical timing analysis?",
              "Can you enumerate users without obvious indicators?"
            ]
          }
        ]
      },
      {
        title: "Defense Mechanisms",
        icon: Shield,
        color: "bg-teal-500",
        description: "Security controls and their testing",
        children: [
          {
            title: "Rate Limiting & Throttling",
            testingSteps: [
              "Identify rate limit thresholds (requests per time window)",
              "Test rate limit bypass via IP rotation",
              "Attempt distributed attacks to evade limits",
              "Test for rate limit on different endpoints",
              "Check if rate limit is per-IP, per-session, or per-account",
              "Test for race conditions in rate limiting",
              "Verify rate limit response codes and headers",
              "Test rate limit reset timing"
            ],
            standards: [
              "OWASP API Security Top 10: API4:2023 Unrestricted Resource Consumption",
              "NIST SP 800-63B: Throttling and lockout",
              "RFC 6585: Additional HTTP Status Codes (429 Too Many Requests)"
            ],
            practiceResources: [
              "PortSwigger: Rate limiting and race condition labs",
              "HackTheBox: Rate limit bypass challenges",
              "Custom testing scripts"
            ],
            realWorldCVEs: [
              "Cloudflare rate limiting bypass techniques",
              "Various API rate limit bypass vulnerabilities"
            ],
            vulnerabilityPatterns: [
              "No rate limiting on critical endpoints",
              "Rate limit only on IP (easy to bypass)",
              "Race conditions in rate limit counters",
              "Different rate limits for API vs web",
              "Rate limit can be reset prematurely"
            ],
            technologies: ["nginx rate limiting", "Redis rate limiting", "Token bucket algorithm", "Leaky bucket algorithm"],
            gapChecklist: [
              "Can you implement token bucket algorithm?",
              "Do you understand distributed rate limiting?",
              "Can you exploit race conditions in rate limiters?"
            ]
          },
          {
            title: "Web Application Firewall (WAF)",
            testingSteps: [
              "Identify WAF presence (headers, error pages)",
              "Test WAF bypass via encoding (URL, Unicode, hex)",
              "Attempt case manipulation to bypass rules",
              "Test for null byte injection",
              "Try path confusion techniques",
              "Test HTTP parameter pollution",
              "Attempt request smuggling",
              "Test for WAF rule exceptions"
            ],
            standards: [
              "OWASP ModSecurity Core Rule Set",
              "PCI DSS Requirement 6.6: WAF deployment"
            ],
            practiceResources: [
              "PortSwigger: Advanced topics (HTTP request smuggling)",
              "HackTheBox: WAF bypass challenges",
              "TryHackMe: WAF evasion rooms",
              "wafw00f: WAF fingerprinting tool"
            ],
            realWorldCVEs: [
              "Cloudflare WAF bypass techniques",
              "ModSecurity bypass methods",
              "AWS WAF bypass vulnerabilities"
            ],
            vulnerabilityPatterns: [
              "Weak regex patterns in WAF rules",
              "Case sensitivity bypass",
              "Encoding bypass (double encoding, etc)",
              "HTTP parameter pollution",
              "Request smuggling vulnerabilities"
            ],
            technologies: ["ModSecurity", "Cloudflare WAF", "AWS WAF", "Imperva", "F5 ASM"],
            gapChecklist: [
              "Can you fingerprint different WAFs?",
              "Do you understand HTTP request smuggling?",
              "Can you craft payloads to bypass common WAF rules?"
            ]
          },
          {
            title: "Anomaly Detection & Monitoring",
            testingSteps: [
              "Test login from unusual geographic location",
              "Attempt rapid successive logins from different IPs",
              "Test for impossible travel detection",
              "Verify new device detection and notification",
              "Test for behavioral biometrics detection",
              "Check if VPN/proxy is flagged",
              "Test for unusual activity pattern detection",
              "Verify alerts on high-risk activities"
            ],
            standards: [
              "NIST SP 800-53: AU Family (Audit and Accountability)",
              "ISO 27001: A.12.4 Logging and monitoring",
              "PCI DSS 10: Track and monitor access"
            ],
            practiceResources: [
              "Limited public labs - mostly production testing",
              "Set up SIEM tools locally for testing",
              "Splunk/ELK Stack training"
            ],
            realWorldCVEs: [
              "Bypass techniques documented in security research"
            ],
            vulnerabilityPatterns: [
              "Anomaly detection not implemented",
              "Easy to bypass with common VPNs",
              "False positives causing user friction",
              "No alerts on high-risk activities",
              "Insufficient logging for forensics"
            ],
            technologies: ["MaxMind GeoIP", "Splunk", "ELK Stack", "Machine learning models", "SIEM platforms"],
            gapChecklist: [
              "Do you understand impossible travel calculations?",
              "Can you evade behavioral detection?",
              "Do you know ML model evasion techniques?"
            ]
          },
          {
            title: "Bot Detection & CAPTCHA",
            testingSteps: [
              "Test for CAPTCHA on authentication endpoints",
              "Attempt automated CAPTCHA solving",
              "Test for CAPTCHA bypass via API endpoints",
              "Check for different CAPTCHA difficulty levels",
              "Test bot detection via browser fingerprinting",
              "Verify JavaScript challenge implementation",
              "Test for proof-of-work requirements",
              "Check for headless browser detection"
            ],
            standards: [
              "OWASP Automated Threats Handbook",
              "W3C Web Authentication API"
            ],
            practiceResources: [
              "2captcha/anti-captcha services for testing",
              "Selenium with undetected-chromedriver",
              "PortSwigger: CAPTCHA bypass techniques"
            ],
            realWorldCVEs: [
              "reCAPTCHA v2 bypass methods",
              "CAPTCHA farming services"
            ],
            vulnerabilityPatterns: [
              "No CAPTCHA on critical endpoints",
              "CAPTCHA only on login, not registration",
              "Easy CAPTCHA types (simple math)",
              "CAPTCHA can be bypassed via API",
              "No progressive difficulty"
            ],
            technologies: ["reCAPTCHA v3", "hCaptcha", "Cloudflare Turnstile", "PerimeterX", "DataDome"],
            gapChecklist: [
              "Can you bypass reCAPTCHA v2?",
              "Do you understand behavioral bot detection?",
              "Can you evade fingerprinting techniques?"
            ]
          },
          {
            title: "Device Fingerprinting & Trust",
            testingSteps: [
              "Test for device fingerprinting implementation",
              "Attempt fingerprint spoofing",
              "Check for device trust establishment",
              "Test for device binding to accounts",
              "Verify new device notification",
              "Test for device revocation capability",
              "Check if fingerprint survives browser data clearing",
              "Test fingerprint uniqueness and collision rates"
            ],
            standards: [
              "W3C Device Memory API",
              "Privacy considerations in fingerprinting"
            ],
            practiceResources: [
              "amiunique.org: Test your fingerprint uniqueness",
              "FingerprintJS testing",
              "Browser fingerprinting research papers"
            ],
            realWorldCVEs: [
              "Privacy concerns with aggressive fingerprinting",
              "Fingerprint spoofing techniques"
            ],
            vulnerabilityPatterns: [
              "No device fingerprinting implemented",
              "Fingerprint easy to spoof",
              "Privacy-invasive fingerprinting",
              "No user control over trusted devices",
              "Fingerprint not combined with other signals"
            ],
            technologies: ["FingerprintJS", "Client Hints", "Canvas fingerprinting", "WebGL fingerprinting"],
            gapChecklist: [
              "Can you implement basic fingerprinting?",
              "Do you understand privacy vs security tradeoffs?",
              "Can you spoof device fingerprints?"
            ]
          },
          {
            title: "Security Headers & Browser Protections",
            testingSteps: [
              "Check for Content-Security-Policy header",
              "Verify HSTS (Strict-Transport-Security) implementation",
              "Test X-Frame-Options for clickjacking protection",
              "Check X-Content-Type-Options: nosniff",
              "Verify Referrer-Policy configuration",
              "Test Permissions-Policy restrictions",
              "Check SameSite cookie attributes",
              "Verify CORS policy configuration"
            ],
            standards: [
              "OWASP Secure Headers Project",
              "Mozilla Observatory recommendations",
              "W3C CSP specification"
            ],
            practiceResources: [
              "securityheaders.com: Test header configuration",
              "PortSwigger: CORS misconfiguration labs",
              "Mozilla Observatory scanning"
            ],
            realWorldCVEs: [
              "Missing CSP leading to XSS exploitation",
              "CORS misconfiguration data leaks",
              "Clickjacking via missing X-Frame-Options"
            ],
            vulnerabilityPatterns: [
              "Missing or weak CSP",
              "No HSTS header",
              "Overly permissive CORS",
              "Missing X-Frame-Options",
              "Unsafe inline scripts allowed"
            ],
            technologies: ["CSP", "HSTS", "CORS", "Helmet.js", "Content-Security-Policy-Report-Only"],
            gapChecklist: [
              "Can you write a secure CSP policy?",
              "Do you understand CORS preflight requests?",
              "Can you identify missing security headers?"
            ]
          }
        ]
      }
    ]
  };

  const Node = ({ node, path = "0", level = 0 }) => {
    const hasChildren = node.children && node.children.length > 0;
    const isExpanded = expanded[path];
    const isSelected = selected?.title === node.title;
    const Icon = node.icon;

    return (
      <div className="my-1">
        <div 
          className={`flex items-start p-2 rounded cursor-pointer transition-all ${
            isSelected ? 'bg-blue-50 ring-2 ring-blue-400' : 'hover:bg-gray-50'
          }`}
          onClick={() => {
            if (hasChildren) toggleNode(path);
            selectNode(node);
          }}
        >
          {hasChildren && (
            <div className="mr-2 mt-1 flex-shrink-0">
              {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
            </div>
          )}
          {Icon && (
            <div className={`${node.color} p-1.5 rounded mr-2 text-white flex-shrink-0`}>
              <Icon size={16} />
            </div>
          )}
          <div className="flex-1 min-w-0">
            <div className="font-semibold text-sm text-gray-800">{node.title}</div>
          </div>
        </div>

        {isExpanded && hasChildren && (
          <div className="ml-6 mt-1 border-l-2 border-gray-200 pl-3">
            {node.children.map((child, idx) => (
              <Node key={idx} node={child} path={`${path}-${idx}`} level={level + 1} />
            ))}
          </div>
        )}
      </div>
    );
  };

  const DetailPanel = () => {
    if (!selected || !selected.testingSteps) {
      return (
        <div className="flex items-center justify-center h-full text-gray-400">
          <div className="text-center p-6">
            <BookOpen size={48} className="mx-auto mb-4 opacity-50" />
            <p className="text-lg font-semibold mb-2">Select a specific testing topic</p>
            <p className="text-sm">Expand categories and click on detailed nodes to see testing procedures</p>
          </div>
        </div>
      );
    }

    return (
      <div className="h-full overflow-auto">
        <div className="p-6">
          <h2 className="text-2xl font-bold mb-4 text-gray-800 border-b-2 pb-2">{selected.title}</h2>
          
          <div className="mb-6 bg-blue-50 p-4 rounded-lg border border-blue-200">
            <div className="flex items-center mb-2">
              <TestTube className="text-blue-600 mr-2" size={20} />
              <h3 className="font-semibold text-blue-900">Testing Methodology Checklist</h3>
            </div>
            <div className="space-y-3 text-sm">
              {selected.testingSteps.map((step, idx) => (
                <div key={idx} className="flex items-start gap-3 p-2 hover:bg-blue-100 rounded">
                  <span className="text-blue-700 font-semibold min-w-[20px]">{idx + 1}.</span>
                  <div className="flex-1">{step}</div>
                  <div className="flex gap-2 flex-shrink-0">
                    <label className="flex items-center gap-1 cursor-pointer">
                      <input type="checkbox" className="w-4 h-4 text-green-600" />
                      <span className="text-xs text-green-700 font-medium">Pass</span>
                    </label>
                    <label className="flex items-center gap-1 cursor-pointer">
                      <input type="checkbox" className="w-4 h-4 text-red-600" />
                      <span className="text-xs text-red-700 font-medium">Fail</span>
                    </label>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {selected.standards && (
            <div className="mb-6 bg-purple-50 p-4 rounded-lg border border-purple-200">
              <div className="flex items-center mb-2">
                <FileText className="text-purple-600 mr-2" size={20} />
                <h3 className="font-semibold text-purple-900">Standards & References</h3>
              </div>
              <ul className="space-y-1 text-sm">
                {selected.standards.map((std, idx) => (
                  <li key={idx} className="text-gray-700 flex items-start">
                    <span className="text-purple-600 mr-2">•</span>
                    <span>{std}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {selected.practiceResources && (
            <div className="mb-6 bg-green-50 p-4 rounded-lg border border-green-200">
              <div className="flex items-center mb-2">
                <TestTube className="text-green-600 mr-2" size={20} />
                <h3 className="font-semibold text-green-900">Practice Resources</h3>
              </div>
              <ul className="space-y-1 text-sm">
                {selected.practiceResources.map((resource, idx) => (
                  <li key={idx} className="text-gray-700 flex items-start">
                    <span className="text-green-600 mr-2">→</span>
                    <span>{resource}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {selected.realWorldCVEs && (
            <div className="mb-6 bg-red-50 p-4 rounded-lg border border-red-200">
              <div className="flex items-center mb-2">
                <AlertTriangle className="text-red-600 mr-2" size={20} />
                <h3 className="font-semibold text-red-900">Real-World CVEs</h3>
              </div>
              <ul className="space-y-1 text-sm">
                {selected.realWorldCVEs.map((cve, idx) => (
                  <li key={idx} className="text-gray-700 flex items-start">
                    <span className="text-red-600 mr-2">⚠</span>
                    <span>{cve}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {selected.vulnerabilityPatterns && (
            <div className="mb-6 bg-orange-50 p-4 rounded-lg border border-orange-200">
              <div className="flex items-center mb-2">
                <AlertTriangle className="text-orange-600 mr-2" size={20} />
                <h3 className="font-semibold text-orange-900">Common Vulnerability Patterns</h3>
              </div>
              <ul className="space-y-1 text-sm">
                {selected.vulnerabilityPatterns.map((pattern, idx) => (
                  <li key={idx} className="text-gray-700 flex items-start">
                    <span className="text-orange-600 mr-2">!</span>
                    <span>{pattern}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {selected.technologies && (
            <div className="mb-6">
              <h3 className="font-semibold text-gray-700 mb-2 text-sm">Related Technologies</h3>
              <div className="flex flex-wrap gap-2">
                {selected.technologies.map((tech, idx) => (
                  <span key={idx} className="bg-gray-100 text-gray-700 px-3 py-1 rounded-full text-xs border border-gray-300">
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          )}

          {selected.gapChecklist && (
            <div className="bg-yellow-50 p-4 rounded-lg border-2 border-yellow-400">
              <div className="flex items-center mb-2">
                <BookOpen className="text-yellow-700 mr-2" size={20} />
                <h3 className="font-semibold text-yellow-900">Knowledge Gap Checklist</h3>
              </div>
              <p className="text-xs text-yellow-800 mb-3">Can you answer these? If not, this is where to focus your learning:</p>
              <ul className="space-y-2 text-sm">
                {selected.gapChecklist.map((question, idx) => (
                  <li key={idx} className="text-gray-700 flex items-start">
                    <input type="checkbox" className="mt-1 mr-2" />
                    <span className="italic">{question}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="h-screen flex flex-col bg-gray-50">
      <div className="bg-gradient-to-r from-slate-800 to-slate-900 text-white p-4 shadow-lg">
        <h1 className="text-2xl font-bold mb-1">Account Takeover: Testing & Reference Guide</h1>
        <p className="text-sm text-slate-300">Complete methodology with standards, practice labs, CVEs, and gap analysis</p>
      </div>
      
      <div className="flex-1 flex overflow-hidden">
        <div className="w-1/3 overflow-auto p-4 border-r border-gray-300 bg-white">
          <Node node={data} />
        </div>
        
        <div className="w-2/3 bg-gray-50">
          <DetailPanel />
        </div>
      </div>

      <div className="bg-slate-800 text-slate-300 p-3 text-xs space-y-1">
        <p><strong>Usage:</strong> Select topics → Follow testing steps → Practice in labs → Check knowledge gaps → Research unfamiliar concepts</p>
        <p><strong>Workflow:</strong> Test → Document findings → Compare with CVEs → Identify patterns → Build exploitation skills</p>
      </div>
    </div>
  );
};

export default MindMap;