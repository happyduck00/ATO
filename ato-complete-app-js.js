// NOTE: This is a simplified template. 
// You need to copy the FULL component code from both artifacts:
// 1. ato-mindmap artifact (the testing reference map)
// 2. oauth-deepdive artifact (the OAuth security guide)
// 
// Both are React components that should be pasted into this file.

import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Shield, Unlock, Key, Users, AlertTriangle, Lock, FileText, TestTube, BookOpen, Code, Bug, Terminal, CheckCircle, XCircle, Book } from 'lucide-react';

// ============================================================================
// COMPONENT 1: ATO MIND MAP
// Copy the ENTIRE MindMap component from the ato-mindmap artifact here
// It should start with: const MindMap = () => {
// And end with: export default MindMap;
// Remove the "export default" line at the end
// ============================================================================

const ATOMindMap = () => {
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
  // PASTE THE FULL COMPONENT CODE FROM ato-mindmap HERE
  // This includes all the data, Node component, DetailPanel, everything
  // The artifact has the complete working code
  
  return <div>ATO Mind Map Component - Replace this with actual code</div>;
};

// ============================================================================
// COMPONENT 2: OAUTH DEEP DIVE  
// Copy the ENTIRE OAuthDeepDive component from the oauth-deepdive artifact here
// It should start with: const OAuthDeepDive = () => {
// And end with: export default OAuthDeepDive;
// Remove the "export default" line at the end
// ============================================================================

const OAuthDeepDive = () => {
  const OAuthDeepDive = () => {
  const [expanded, setExpanded] = useState({ '0': true });
  const [selected, setSelected] = useState(null);

  const toggleNode = (path) => {
    setExpanded(prev => ({...prev, [path]: !prev[path]}));
  };

  const selectNode = (node) => {
    setSelected(node);
  };

  const data = {
    title: "OAuth 2.0 Security Deep Dive",
    sections: [
      {
        title: "1. OAuth 2.0 Fundamentals",
        icon: Book,
        color: "bg-blue-600",
        topics: [
          {
            title: "What is OAuth 2.0?",
            content: {
              overview: "OAuth 2.0 is an authorization framework that enables applications to obtain limited access to user accounts on an HTTP service. It works by delegating user authentication to the service that hosts the user account and authorizing third-party applications to access that account.",
              keyPoint: "Critical: OAuth 2.0 is for AUTHORIZATION, not AUTHENTICATION. OpenID Connect (OIDC) builds on OAuth for authentication.",
              roles: [
                "Resource Owner: The user who owns the data",
                "Client: The application requesting access (your app)",
                "Authorization Server: Issues tokens after authentication",
                "Resource Server: Hosts the protected resources (API)"
              ],
              diagram: `
[Resource Owner]
      |
      v (1. User clicks "Login with Google")
  [Client App]
      |
      v (2. Redirect to Authorization Server)
[Authorization Server] (Google, GitHub, etc)
      |
      v (3. User authenticates & approves)
      |
      v (4. Authorization code returned)
  [Client App]
      |
      v (5. Exchange code for access token)
[Authorization Server]
      |
      v (6. Access token returned)
  [Client App]
      |
      v (7. Use token to access API)
[Resource Server]
              `,
              standards: ["RFC 6749: OAuth 2.0 Framework", "RFC 6750: Bearer Token Usage"]
            }
          },
          {
            title: "OAuth 2.0 Flows (Grant Types)",
            content: {
              overview: "Different flows for different client types and use cases. Understanding when to use each is critical for security.",
              flows: [
                {
                  name: "Authorization Code Flow",
                  useCase: "Web applications with server-side backend",
                  security: "Most secure - secret never exposed to browser",
                  steps: "User → Auth Server → Redirect with code → Client exchanges code + secret for token",
                  recommended: true
                },
                {
                  name: "Authorization Code + PKCE",
                  useCase: "Mobile apps, SPAs, public clients",
                  security: "Prevents authorization code interception",
                  steps: "Same as above but with code_challenge/code_verifier",
                  recommended: true
                },
                {
                  name: "Implicit Flow",
                  useCase: "DEPRECATED - Previously for SPAs",
                  security: "Insecure - token in URL fragment, no refresh token",
                  steps: "User → Auth Server → Token directly in redirect URL",
                  recommended: false
                },
                {
                  name: "Client Credentials",
                  useCase: "Machine-to-machine (no user involved)",
                  security: "Secure for backend services",
                  steps: "Client → Auth Server with credentials → Access token",
                  recommended: true
                },
                {
                  name: "Resource Owner Password",
                  useCase: "AVOID - only for legacy migration",
                  security: "User gives password to client (defeats OAuth purpose)",
                  steps: "Client collects username/password → Sends to Auth Server",
                  recommended: false
                }
              ],
              keyDecisions: "Use Authorization Code + PKCE for everything except machine-to-machine (use Client Credentials). Never use Implicit or Password flows."
            }
          },
          {
            title: "Key OAuth Components",
            content: {
              tokens: {
                accessToken: {
                  purpose: "Grants access to protected resources",
                  lifetime: "Short-lived (minutes to hours)",
                  storage: "Never in localStorage - use httpOnly cookies or memory",
                  format: "Usually JWT, but can be opaque"
                },
                refreshToken: {
                  purpose: "Obtains new access tokens without re-authentication",
                  lifetime: "Long-lived (days to months)",
                  storage: "Secure backend storage only, never client-side",
                  rotation: "Should rotate on each use (refresh token rotation)"
                },
                idToken: {
                  purpose: "OIDC only - contains user identity information",
                  lifetime: "Short-lived",
                  format: "Always JWT with user claims",
                  validation: "Must validate signature, issuer, audience, expiration"
                }
              },
              parameters: [
                "client_id: Public identifier for the application",
                "client_secret: Secret credential (confidential clients only)",
                "redirect_uri: Where to send user after authorization",
                "state: CSRF protection - random value client generates",
                "scope: Permissions being requested (read, write, etc)",
                "code_challenge: PKCE - SHA256 hash of code_verifier",
                "code_verifier: PKCE - Random cryptographic string"
              ]
            }
          }
        ]
      },
      {
        title: "2. Common Vulnerabilities & Exploits",
        icon: Bug,
        color: "bg-red-600",
        topics: [
          {
            title: "Missing State Parameter (CSRF)",
            content: {
              vulnerability: "Authorization endpoint doesn't use or validate state parameter",
              impact: "Attacker can trick victim into authorizing attacker's account, leading to account linking attacks",
              exploitSteps: [
                "1. Attacker initiates OAuth flow but stops before completing",
                "2. Attacker captures authorization code from redirect",
                "3. Attacker sends victim link with their authorization code",
                "4. Victim completes flow, linking their account to attacker's OAuth account",
                "5. Attacker now has access to victim's data"
              ],
              testingSteps: [
                "Remove state parameter from authorization request",
                "Use same state value across multiple requests",
                "Check if state is validated on callback",
                "Test if state can be predicted or reused"
              ],
              exploitCode: `
// Attacker's malicious link (simplified)
// Victim clicks this and authorizes
https://yourapp.com/oauth/callback?code=ATTACKERS_CODE

// Client doesn't validate state, accepts the code
// Victim's account now linked to attacker's OAuth account
              `,
              mitigation: [
                "Always generate cryptographically random state parameter",
                "Store state in session before redirect",
                "Validate state matches on callback",
                "State should be single-use (delete after validation)"
              ],
              realWorldExample: "Slack OAuth CSRF (2017) - Missing state validation allowed account takeover",
              cvss: "Medium to High (6.5-8.0)",
              cwe: "CWE-352: Cross-Site Request Forgery"
            }
          },
          {
            title: "Weak redirect_uri Validation",
            content: {
              vulnerability: "Authorization server doesn't properly validate redirect_uri parameter",
              impact: "Authorization code or token leaked to attacker-controlled domain",
              exploitSteps: [
                "1. Attacker registers client with legitimate redirect_uri",
                "2. Attacker modifies redirect_uri in authorization request",
                "3. Victims authorize, but code/token sent to attacker's domain",
                "4. Attacker captures authorization code or access token",
                "5. Attacker can now access victim's account"
              ],
              bypassTechniques: [
                "Path traversal: redirect_uri=https://legitimate.com/../attacker.com",
                "Subdomain: redirect_uri=https://attacker.legitimate.com",
                "Open redirect: redirect_uri=https://legitimate.com/redirect?url=https://attacker.com",
                "Localhost: redirect_uri=http://localhost:8080 (if allowed)",
                "Parameter pollution: redirect_uri=https://legit.com&redirect_uri=https://evil.com"
              ],
              testingSteps: [
                "Try changing redirect_uri to attacker-controlled domain",
                "Test with subdomain of registered domain",
                "Test path traversal techniques",
                "Try open redirect on legitimate domain",
                "Test with HTTP instead of HTTPS",
                "Test URL encoding variations",
                "Test with additional parameters"
              ],
              exploitCode: `
// Legitimate registration
redirect_uri=https://yourapp.com/callback

// Attack attempts:
// 1. Subdomain takeover
redirect_uri=https://evil.yourapp.com/callback

// 2. Path traversal
redirect_uri=https://yourapp.com/callback/../../../evil.com

// 3. Open redirect chain
redirect_uri=https://yourapp.com/redirect?url=https://evil.com

// 4. Parameter pollution
redirect_uri=https://yourapp.com/callback&redirect_uri=https://evil.com
              `,
              mitigation: [
                "Use exact string matching for redirect_uri (no wildcards)",
                "Pre-register all valid redirect URIs",
                "Reject any redirect_uri not in whitelist",
                "Validate scheme (https:// only in production)",
                "Validate hostname exactly (no subdomains unless explicitly registered)",
                "Consider using redirect_uri_mismatch error instead of accepting"
              ],
              realWorldExample: "Facebook OAuth redirect_uri bypass (2013) - Allowed token theft via subdomain",
              cvss: "High to Critical (8.0-9.5)",
              cwe: "CWE-601: URL Redirection to Untrusted Site"
            }
          },
          {
            title: "Missing PKCE (Code Interception)",
            content: {
              vulnerability: "Public clients (mobile apps, SPAs) don't implement PKCE",
              impact: "Authorization code can be intercepted and used by attacker",
              exploitSteps: [
                "1. Victim initiates OAuth flow on mobile app",
                "2. Authorization code returned via custom URI scheme (myapp://callback?code=...)",
                "3. Attacker's malicious app registers same URI scheme",
                "4. Attacker intercepts authorization code",
                "5. Attacker exchanges code for access token (no client_secret required for public clients)",
                "6. Attacker gains access to victim's account"
              ],
              pkceExplained: `
PKCE (Proof Key for Code Exchange) prevents this:

1. Client generates random code_verifier (43-128 chars)
2. Client creates code_challenge = SHA256(code_verifier)
3. Client sends code_challenge in authorization request
4. Auth server stores code_challenge with authorization code
5. When exchanging code for token, client sends code_verifier
6. Auth server validates: SHA256(code_verifier) === stored code_challenge
7. If match, issue token; if not, reject

This means even if attacker intercepts code, they can't use it without the code_verifier!
              `,
              testingSteps: [
                "Check if PKCE parameters are present in mobile/SPA flows",
                "Test if code_challenge is required",
                "Test if code_verifier is validated on token exchange",
                "Try exchanging code without code_verifier",
                "Test with mismatched code_verifier",
                "Verify S256 challenge method (not plain)"
              ],
              exploitCode: `
// Without PKCE (vulnerable):
GET /authorize?client_id=app&redirect_uri=myapp://callback&response_type=code

// Attacker intercepts: myapp://callback?code=ABC123

// Attacker exchanges code:
POST /token
client_id=app&code=ABC123&redirect_uri=myapp://callback
// No secret needed for public client - ATTACK SUCCEEDS


// With PKCE (secure):
// 1. Generate verifier
code_verifier = random_string(64) // e.g., "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// 2. Create challenge
code_challenge = base64url(sha256(code_verifier))

// 3. Authorization request
GET /authorize?client_id=app&redirect_uri=myapp://callback
    &response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256

// Attacker intercepts code but doesn't have code_verifier

// 4. Token exchange (attacker fails here)
POST /token
client_id=app&code=ABC123&redirect_uri=myapp://callback
&code_verifier=WRONG_VALUE
// Server validates: SHA256(WRONG_VALUE) != stored challenge
// ATTACK FAILS
              `,
              mitigation: [
                "Always use PKCE for public clients (mobile, SPA)",
                "Require code_challenge in authorization requests",
                "Use S256 challenge method (not plain)",
                "Validate code_verifier on token exchange",
                "Consider requiring PKCE even for confidential clients (defense in depth)"
              ],
              realWorldExample: "Many mobile apps vulnerable to code interception before PKCE became standard",
              cvss: "High (7.5-8.5)",
              cwe: "CWE-294: Authentication Bypass by Capture-replay",
              rfc: "RFC 7636: Proof Key for Code Exchange"
            }
          },
          {
            title: "Authorization Code Reuse",
            content: {
              vulnerability: "Authorization codes can be used multiple times",
              impact: "Stolen or leaked codes can be replayed to obtain tokens",
              exploitSteps: [
                "1. Attacker obtains authorization code (via network sniffing, logs, etc)",
                "2. Legitimate client exchanges code for token",
                "3. Attacker also attempts to exchange same code",
                "4. If not single-use, attacker gets valid access token"
              ],
              testingSteps: [
                "Capture authorization code from callback",
                "Exchange code for access token normally",
                "Attempt to exchange same code again",
                "Check if second exchange succeeds",
                "Test if codes expire (should be short-lived)"
              ],
              exploitCode: `
// Normal flow
POST /token
code=ABC123&client_id=myapp&client_secret=SECRET

// Response: access_token

// Attacker tries replay
POST /token
code=ABC123&client_id=myapp&client_secret=SECRET

// Should fail with "invalid_grant" error
// If succeeds, vulnerability exists
              `,
              mitigation: [
                "Authorization codes must be single-use only",
                "Invalidate code immediately after first use",
                "Codes should expire within 60 seconds",
                "Detect and revoke all tokens if code reuse detected",
                "Log code reuse attempts for security monitoring"
              ],
              realWorldExample: "Common misconfiguration in custom OAuth implementations",
              cvss: "Medium (6.0-7.0)",
              cwe: "CWE-294: Authentication Bypass by Capture-replay"
            }
          },
          {
            title: "Token Leakage via Referer Header",
            content: {
              vulnerability: "Access tokens or authorization codes leaked in Referer header",
              impact: "Third-party sites receive sensitive tokens via HTTP Referer",
              exploitSteps: [
                "1. Application includes token in URL (query parameter or fragment)",
                "2. User clicks external link from authenticated page",
                "3. Referer header sent to third-party includes token",
                "4. Third-party logs Referer and captures token"
              ],
              scenarios: [
                "Implicit flow: Token in URL fragment (#access_token=...)",
                "Authorization code in URL: ?code=ABC123",
                "Access token in URL: ?access_token=xyz789",
                "Any OAuth parameter that ends up in URL"
              ],
              testingSteps: [
                "Check if tokens appear in URL (address bar)",
                "Use browser DevTools Network tab to inspect Referer headers",
                "Click external links and check what's sent in Referer",
                "Test with analytics scripts that might log full URL",
                "Check server logs for token exposure"
              ],
              mitigation: [
                "Never put tokens in URLs (use POST or headers)",
                "Use Authorization: Bearer header for API requests",
                "Set Referrer-Policy: no-referrer or strict-origin",
                "For OAuth callbacks, immediately exchange code server-side",
                "Use httpOnly cookies for token storage when possible"
              ],
              realWorldExample: "Facebook OAuth token leak via Referer (2012)",
              cvss: "Medium to High (6.5-8.0)",
              cwe: "CWE-200: Exposure of Sensitive Information"
            }
          },
          {
            title: "Scope Escalation",
            content: {
              vulnerability: "Client can request or use more permissions than granted",
              impact: "Access to resources beyond user's authorization",
              exploitSteps: [
                "1. Client requests limited scope (e.g., read:profile)",
                "2. User authorizes limited scope",
                "3. Client attempts to use token with elevated scope (e.g., write:profile)",
                "4. If not properly validated, elevated access granted"
              ],
              testingSteps: [
                "Request minimal scope in authorization",
                "After receiving token, attempt API calls with higher privileges",
                "Modify scope in token exchange request",
                "Check if token claims match requested vs granted scope",
                "Test if resource server validates scope on each request"
              ],
              exploitCode: `
// Authorization request (legitimate)
scope=read:profile

// Token received with scope: read:profile

// Attacker tries elevated API call
GET /api/user/profile
Authorization: Bearer <token>
// Modify profile (write operation)

// Resource server should check:
// 1. Token is valid
// 2. Token has 'write:profile' scope
// If missing scope check, attack succeeds
              `,
              mitigation: [
                "Authorization server must include scope in access token",
                "Resource server must validate scope for every request",
                "Use principle of least privilege (request minimal scope)",
                "Document scope requirements for each API endpoint",
                "Audit scope usage regularly"
              ],
              realWorldExample: "GitHub OAuth scope escalation (2014)",
              cvss: "High (7.5-8.5)",
              cwe: "CWE-269: Improper Privilege Management"
            }
          },
          {
            title: "Pre-Account Takeover (Account Linking)",
            content: {
              vulnerability: "Attacker links their OAuth account to victim's application account before victim does",
              impact: "When victim tries to use OAuth login, they get attacker's account or attacker gains access to victim's account",
              exploitSteps: [
                "1. Attacker creates account with victim's email on OAuth provider (e.g., victim@example.com)",
                "2. Attacker initiates OAuth flow with your app using this account",
                "3. Attacker links OAuth account to your app but doesn't complete",
                "4. Victim later tries to login via OAuth",
                "5. App sees email matches, links accounts",
                "6. Now both attacker and victim have access, or victim gets attacker's account"
              ],
              testingSteps: [
                "Create OAuth account with target email",
                "Link to application account",
                "Have another user try to link same OAuth email",
                "Check if email verification is required before linking",
                "Test if existing accounts can be overwritten"
              ],
              mitigation: [
                "Always verify email ownership before account linking",
                "Require email verification for OAuth accounts",
                "Check if application account with same email already exists",
                "If exists, require authentication on that account first",
                "Use OAuth provider's email_verified claim",
                "Don't auto-link accounts based solely on email match"
              ],
              realWorldExample: "Common vulnerability in many OAuth integrations",
              cvss: "High (8.0-9.0)",
              cwe: "CWE-287: Improper Authentication"
            }
          }
        ]
      },
      {
        title: "3. Attack Scenarios & Walkthroughs",
        icon: Terminal,
        color: "bg-orange-600",
        topics: [
          {
            title: "Scenario 1: Steal Access Token via redirect_uri",
            content: {
              setup: "Target app: example.com with OAuth integration. Registered redirect_uri: https://example.com/oauth/callback",
              attackGoal: "Steal victim's access token to access their account",
              walkthrough: [
                "Step 1: Test redirect_uri validation",
                "Try: https://attacker.com → Rejected",
                "Try: https://example.com.attacker.com → Accepted! (Weak validation)",
                "",
                "Step 2: Set up attacker-controlled subdomain",
                "Register example.com.attacker.com pointing to attacker server",
                "",
                "Step 3: Craft malicious OAuth link",
                "https://oauth-provider.com/authorize?client_id=example_app&redirect_uri=https://example.com.attacker.com&response_type=token",
                "",
                "Step 4: Social engineer victim to click link",
                "Phishing email, forum post, etc.",
                "",
                "Step 5: Victim authorizes, token sent to attacker's server",
                "Attacker receives: https://example.com.attacker.com#access_token=VICTIM_TOKEN",
                "",
                "Step 6: Use stolen token",
                "curl -H 'Authorization: Bearer VICTIM_TOKEN' https://api.example.com/user/profile"
              ],
              prevention: "Exact match redirect_uri validation. No subdomain wildcards.",
              labsToTry: ["PortSwigger: OAuth account hijacking via redirect_uri"]
            }
          },
          {
            title: "Scenario 2: Account Takeover via Missing State",
            content: {
              setup: "Target app allows OAuth login but doesn't use state parameter",
              attackGoal: "Link victim's account to attacker's OAuth profile",
              walkthrough: [
                "Step 1: Attacker initiates OAuth flow",
                "Navigate to: example.com/login/oauth",
                "Gets redirected to OAuth provider",
                "",
                "Step 2: Attacker authorizes with their OAuth account",
                "OAuth provider redirects back with code",
                "",
                "Step 3: Attacker captures authorization code from URL",
                "https://example.com/oauth/callback?code=ATTACKERS_CODE",
                "Attacker stops here, doesn't complete",
                "",
                "Step 4: Attacker sends victim crafted link",
                "https://example.com/oauth/callback?code=ATTACKERS_CODE",
                "",
                "Step 5: Victim clicks link (logged into their account)",
                "App processes code, links attacker's OAuth to victim's account",
                "",
                "Step 6: Attacker now logs in with OAuth",
                "Gets access to victim's account on example.com"
              ],
              technicalDetails: `
Without state parameter:
1. App can't verify who initiated OAuth flow
2. Authorization code can come from anyone
3. No binding between user session and OAuth flow
4. CSRF attack succeeds

With state parameter:
1. App generates random state, stores in session
2. State included in OAuth request
3. OAuth provider returns state with code
4. App verifies state matches session
5. Mismatched state = reject the request
              `,
              prevention: "Always use cryptographically random state parameter and validate it",
              labsToTry: ["PortSwigger: Forced OAuth profile linking"]
            }
          },
          {
            title: "Scenario 3: Mobile App Code Interception (No PKCE)",
            content: {
              setup: "Mobile app using custom URI scheme without PKCE",
              attackGoal: "Intercept authorization code and steal access token",
              walkthrough: [
                "Step 1: Attacker installs malicious app on own device",
                "Malicious app registers same custom URI scheme: myapp://",
                "",
                "Step 2: Victim uses legitimate app on same device type",
                "Victim initiates OAuth login",
                "",
                "Step 3: Victim authorizes on OAuth provider",
                "OAuth provider redirects: myapp://callback?code=VICTIMS_CODE",
                "",
                "Step 4: OS ambiguity - both apps can handle myapp://",
                "Malicious app intercepts callback, captures code",
                "",
                "Step 5: Attacker extracts authorization code",
                "Sends to attacker's server",
                "",
                "Step 6: Attacker exchanges code for token",
                "POST /token",
                "client_id=myapp&code=VICTIMS_CODE&redirect_uri=myapp://callback",
                "No client_secret needed (public client)",
                "No PKCE validation",
                "",
                "Step 7: Attacker receives valid access token",
                "Can now access victim's account"
              ],
              technicalDetails: `
Why PKCE prevents this:

1. Legitimate app generates code_verifier (random secret)
2. Creates code_challenge = SHA256(code_verifier)
3. Sends code_challenge in authorization request
4. Even if attacker intercepts code, they don't have code_verifier
5. Token exchange requires code_verifier
6. Attacker's exchange fails validation
7. Only legitimate app with code_verifier can get token
              `,
              prevention: "Always implement PKCE for mobile and SPA applications",
              labsToTry: ["Build test mobile app, simulate interception"]
            }
          }
        ]
      },
      {
        title: "4. Secure Implementation Patterns",
        icon: Shield,
        color: "bg-green-600",
        topics: [
          {
            title: "Authorization Code Flow (Confidential Client)",
            content: {
              description: "Secure server-side implementation with client secret",
              code: `
// 1. Generate state and store in session
const state = crypto.randomBytes(32).toString('hex');
req.session.oauthState = state;

// 2. Redirect to authorization endpoint
const authUrl = new URL('https://oauth-provider.com/authorize');
authUrl.searchParams.set('client_id', 'YOUR_CLIENT_ID');
authUrl.searchParams.set('redirect_uri', 'https://yourapp.com/oauth/callback');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('scope', 'read:user');
authUrl.searchParams.set('state', state);

res.redirect(authUrl.toString());

// 3. Handle callback
app.get('/oauth/callback', async (req, res) => {
  // Validate state
  if (req.query.state !== req.session.oauthState) {
    return res.status(403).send('Invalid state parameter');
  }
  
  // Clear used state
  delete req.session.oauthState;
  
  // Exchange code for token
  const tokenResponse = await fetch('https://oauth-provider.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: req.query.code,
      redirect_uri: 'https://yourapp.com/oauth/callback',
      client_id: 'YOUR_CLIENT_ID',
      client_secret: 'YOUR_CLIENT_SECRET' // Server-side only!
    })
  });
  
  const tokens = await tokenResponse.json();
  
  // Store tokens securely (encrypted in DB, not in cookies/localStorage)
  await storeTokens(req.session.userId, {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_at: Date.now() + (tokens.expires_in * 1000)
  });
  
  res.redirect('/dashboard');
});
              `,
              keyPoints: [
                "State parameter prevents CSRF",
                "Client secret never exposed to browser",
                "Tokens stored server-side only",
                "Redirect URI exactly matches registration",
                "State is single-use (deleted after validation)"
              ]
            }
          },
          {
            title: "Authorization Code + PKCE Flow (Public Client)",
            content: {
              description: "Secure implementation for SPAs and mobile apps without client secret",
              code: `
// 1. Generate PKCE parameters
function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256')
    .update(verifier)
    .digest('base64url');
  
  return { verifier, challenge };
}

// 2. Start OAuth flow (browser/SPA)
const pkce = generatePKCE();
const state = crypto.randomBytes(32).toString('hex');

// Store in sessionStorage (will be needed for token exchange)
sessionStorage.setItem('pkce_verifier', pkce.verifier);
sessionStorage.setItem('oauth_state', state);

const authUrl = new URL('https://oauth-provider.com/authorize');
authUrl.searchParams.set('client_id', 'YOUR_CLIENT_ID');
authUrl.searchParams.set('redirect_uri', 'https://yourapp.com/callback');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('scope', 'read:user');
authUrl.searchParams.set('state', state);
authUrl.searchParams.set('code_challenge', pkce.challenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

window.location.href = authUrl.toString();

// 3. Handle callback
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const returnedState = urlParams.get('state');

// Validate state
const storedState = sessionStorage.getItem('oauth_state');
if (returnedState !== storedState) {
  throw new Error('State mismatch - possible CSRF attack');
}

// Get stored verifier
const codeVerifier = sessionStorage.getItem('pkce_verifier');

// Clean up
sessionStorage.removeItem('oauth_state');
sessionStorage.removeItem('pkce_verifier');

// Exchange code for token
const tokenResponse = await fetch('https://oauth-provider.com/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: 'https://yourapp.com/callback',
    client_id: 'YOUR_CLIENT_ID',
    code_verifier: codeVerifier // PKCE verification
  })
});

const tokens = await tokenResponse.json();

// Store access token in memory (NOT localStorage)
// Use short-lived access tokens and refresh tokens
window.accessToken = tokens.access_token;
              `,
              keyPoints: [
                "PKCE prevents code interception attacks",
                "No client secret needed for public clients",
                "code_verifier stored temporarily in sessionStorage",
                "S256 challenge method (SHA-256 hash)",
                "State parameter still required for CSRF protection"
              ]
            }
          },
          {
            title: "Secure redirect_uri Validation",
            content: {
              description: "Proper validation to prevent redirect_uri bypass attacks",
              code: `
// BAD - Vulnerable to bypass
function validateRedirectUri(requestedUri, registeredUri) {
  return requestedUri.includes(registeredUri); // WRONG!
}

// GOOD - Exact match validation
function validateRedirectUri(requestedUri, registeredUris) {
  // Normalize URIs (remove trailing slashes, etc)
  const normalize = (uri) => new URL(uri).href.replace(/\/$/, '');
  
  const normalizedRequested = normalize(requestedUri);
  
  // Check against all registered URIs
  return registeredUris.some(uri => 
    normalize(uri) === normalizedRequested
  );
}

// Example usage
const registeredUris = [
  'https://yourapp.com/oauth/callback',
  'https://yourapp.com/oauth/callback2'
];

const requestedUri = req.query.redirect_uri;

if (!validateRedirectUri(requestedUri, registeredUris)) {
  return res.status(400).json({
    error: 'invalid_request',
    error_description: 'redirect_uri does not match registered URIs'
  });
}

// Additional security checks
const parsedUri = new URL(requestedUri);

// Enforce HTTPS in production
if (process.env.NODE_ENV === 'production' && parsedUri.protocol !== 'https:') {
  return res.status(400).json({
    error: 'invalid_request',
    error_description: 'redirect_uri must use HTTPS'
  });
}

// No open redirects allowed in path
if (parsedUri.searchParams.has('redirect') || 
    parsedUri.searchParams.has('url') ||
    parsedUri.searchParams.has('next')) {
  return res.status(400).json({
    error: 'invalid_request',
    error_description: 'redirect_uri contains suspicious parameters'
  });
}
              `,
              keyPoints: [
                "Use exact string matching, no wildcards",
                "Normalize URIs before comparison",
                "Pre-register all valid redirect_uris",
                "Validate protocol (HTTPS only in production)",
                "Check for open redirect patterns in path/query"
              ]
            }
          },
          {
            title: "Token Storage Best Practices",
            content: {
              description: "Where and how to store OAuth tokens securely",
              guidelines: {
                "Access Tokens": {
                  "Server-side (Confidential)": "Database (encrypted), Redis (encrypted), Session store",
                  "Browser (Public Client)": "Memory only (JavaScript variable), httpOnly cookie (if backend proxy), NEVER localStorage",
                  "Mobile": "Keychain (iOS), Keystore (Android), Encrypted SharedPreferences"
                },
                "Refresh Tokens": {
                  "Server-side": "Database (encrypted at rest), HSM for high security",
                  "Browser": "NEVER store in browser - use backend proxy pattern",
                  "Mobile": "Secure storage only (Keychain/Keystore)"
                }
              },
              code: `
// WRONG - Never do this
localStorage.setItem('access_token', token); // XSS vulnerable!
localStorage.setItem('refresh_token', refreshToken); // Critical vulnerability!

// CORRECT - Server-side storage
// 1. Store in encrypted database
const crypto = require('crypto');

function encryptToken(token, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString('hex'),
    encrypted: encrypted.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

await db.tokens.insert({
  userId: user.id,
  ...encryptToken(accessToken, process.env.TOKEN_ENCRYPTION_KEY),
  expiresAt: new Date(Date.now() + expiresIn * 1000)
});

// 2. For SPAs: Use backend proxy pattern
// SPA → Your Backend → OAuth Provider → Resource Server
// Tokens never touch browser

// Frontend makes request to your backend
fetch('/api/user/profile', {
  credentials: 'include' // Send httpOnly session cookie
});

// Backend retrieves token and makes request
app.get('/api/user/profile', async (req, res) => {
  const token = await getTokenForUser(req.session.userId);
  
  const response = await fetch('https://api.service.com/user', {
    headers: { 'Authorization': \`Bearer \${token.access_token}\` }
  });
  
  res.json(await response.json());
});
              `,
              keyPoints: [
                "Encrypt tokens at rest",
                "Use httpOnly cookies for session, not tokens",
                "SPAs should use backend proxy pattern",
                "Mobile apps must use platform secure storage",
                "Never log tokens (even in debugging)"
              ]
            }
          },
          {
            title: "Scope Validation in Resource Server",
            content: {
              description: "Properly validate scopes on every API request",
              code: `
// Express middleware for scope validation
function requireScope(...requiredScopes) {
  return async (req, res, next) => {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing or invalid token' });
    }
    
    const token = authHeader.substring(7);
    
    // Verify and decode token (JWT example)
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_PUBLIC_KEY);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    // Check token expiration
    if (decoded.exp < Date.now() / 1000) {
      return res.status(401).json({ error: 'Token expired' });
    }
    
    // Extract scopes from token
    const tokenScopes = decoded.scope ? decoded.scope.split(' ') : [];
    
    // Check if token has ALL required scopes
    const hasAllScopes = requiredScopes.every(scope => 
      tokenScopes.includes(scope)
    );
    
    if (!hasAllScopes) {
      return res.status(403).json({ 
        error: 'Insufficient scope',
        required: requiredScopes,
        provided: tokenScopes
      });
    }
    
    // Attach user info to request
    req.user = {
      id: decoded.sub,
      scopes: tokenScopes
    };
    
    next();
  };
}

// Usage in routes
app.get('/api/user/profile', 
  requireScope('read:profile'),
  async (req, res) => {
    // Handler code - scope already validated
    const profile = await db.users.findById(req.user.id);
    res.json(profile);
  }
);

app.put('/api/user/profile', 
  requireScope('write:profile'),
  async (req, res) => {
    // Handler code
    await db.users.update(req.user.id, req.body);
    res.json({ success: true });
  }
);

app.delete('/api/user/account', 
  requireScope('delete:account'),
  async (req, res) => {
    // Sensitive operation requires specific scope
    await db.users.delete(req.user.id);
    res.json({ success: true });
  }
);
              `,
              keyPoints: [
                "Validate scope on every protected endpoint",
                "Use middleware for consistent validation",
                "Document required scopes for each endpoint",
                "Follow principle of least privilege",
                "Different operations = different scopes"
              ]
            }
          }
        ]
      },
      {
        title: "5. Testing Checklist",
        icon: CheckCircle,
        color: "bg-purple-600",
        topics: [
          {
            title: "Complete OAuth Security Testing Checklist",
            content: {
              categories: [
                {
                  name: "Authorization Endpoint",
                  tests: [
                    { test: "State parameter is required and validated", severity: "Critical" },
                    { test: "redirect_uri uses exact matching (no wildcards)", severity: "Critical" },
                    { test: "redirect_uri requires HTTPS in production", severity: "High" },
                    { test: "PKCE required for public clients", severity: "Critical" },
                    { test: "Scope parameter is validated", severity: "Medium" },
                    { test: "Response type is validated", severity: "Medium" },
                    { test: "Client ID is valid and active", severity: "High" }
                  ]
                },
                {
                  name: "Token Endpoint",
                  tests: [
                    { test: "Authorization codes are single-use only", severity: "Critical" },
                    { test: "Authorization codes expire within 60 seconds", severity: "High" },
                    { test: "PKCE code_verifier validated (public clients)", severity: "Critical" },
                    { test: "Client authentication required (confidential clients)", severity: "Critical" },
                    { test: "redirect_uri matches authorization request", severity: "High" },
                    { test: "Grant type is validated", severity: "Medium" },
                    { test: "Refresh token rotation implemented", severity: "High" }
                  ]
                },
                {
                  name: "Token Security",
                  tests: [
                    { test: "Access tokens are short-lived (< 1 hour)", severity: "High" },
                    { test: "Refresh tokens are long-lived but rotated", severity: "High" },
                    { test: "Tokens never in URL parameters", severity: "Critical" },
                    { test: "Tokens not logged in application logs", severity: "High" },
                    { test: "Token binding implemented where possible", severity: "Medium" },
                    { test: "Tokens stored securely (encrypted at rest)", severity: "High" }
                  ]
                },
                {
                  name: "Resource Server",
                  tests: [
                    { test: "Token signature verified on every request", severity: "Critical" },
                    { test: "Token expiration checked on every request", severity: "Critical" },
                    { test: "Scope validated for each endpoint", severity: "Critical" },
                    { test: "Issuer (iss) claim validated", severity: "High" },
                    { test: "Audience (aud) claim validated", severity: "High" },
                    { test: "Rate limiting on API endpoints", severity: "Medium" }
                  ]
                },
                {
                  name: "Client Security",
                  tests: [
                    { test: "Client secrets never exposed in frontend code", severity: "Critical" },
                    { test: "Public clients use PKCE", severity: "Critical" },
                    { test: "State parameter generated cryptographically", severity: "Critical" },
                    { test: "Tokens not stored in localStorage", severity: "Critical" },
                    { test: "Mobile apps use platform secure storage", severity: "High" },
                    { test: "Referrer-Policy header set appropriately", severity: "Medium" }
                  ]
                }
              ]
            }
          }
        ]
      }
    ]
  };

  const Section = ({ section, sectionIdx }) => {
    const path = `section-${sectionIdx}`;
    const isExpanded = expanded[path];
    const SectionIcon = section.icon;

    return (
      <div className="mb-4">
        <div 
          className={`${section.color} text-white p-4 rounded-lg cursor-pointer hover:opacity-90 transition-all`}
          onClick={() => toggleNode(path)}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <SectionIcon size={24} />
              <h2 className="text-xl font-bold">{section.title}</h2>
            </div>
            {isExpanded ? <ChevronDown size={24} /> : <ChevronRight size={24} />}
          </div>
        </div>

        {isExpanded && (
          <div className="mt-2 ml-4 space-y-2">
            {section.topics.map((topic, topicIdx) => (
              <div 
                key={topicIdx}
                className="bg-white border-l-4 border-gray-300 hover:border-blue-500 p-3 rounded cursor-pointer transition-all hover:shadow-md"
                onClick={() => selectNode(topic)}
              >
                <h3 className="font-semibold text-gray-800">{topic.title}</h3>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  const DetailView = () => {
    if (!selected) {
      return (
        <div className="flex items-center justify-center h-full">
          <div className="text-center text-gray-400">
            <Book size={64} className="mx-auto mb-4 opacity-50" />
            <p className="text-xl font-semibold">Select a topic to view details</p>
            <p className="text-sm mt-2">Click on any topic from the left panel</p>
          </div>
        </div>
      );
    }

    const content = selected.content;

    return (
      <div className="p-6 overflow-auto h-full">
        <h2 className="text-3xl font-bold mb-6 text-gray-800 border-b-2 pb-2">{selected.title}</h2>

        {content.overview && (
          <div className="mb-6 bg-blue-50 p-4 rounded-lg border-l-4 border-blue-500">
            <p className="text-gray-700">{content.overview}</p>
          </div>
        )}

        {content.keyPoint && (
          <div className="mb-6 bg-yellow-50 p-4 rounded-lg border-l-4 border-yellow-500">
            <p className="font-semibold text-yellow-900">⚠️ {content.keyPoint}</p>
          </div>
        )}

        {content.roles && (
          <div className="mb-6">
            <h3 className="font-bold text-lg mb-3">OAuth Roles:</h3>
            <ul className="space-y-2">
              {content.roles.map((role, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-blue-600 mt-1">▸</span>
                  <span>{role}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {content.diagram && (
          <div className="mb-6 bg-gray-50 p-4 rounded-lg border border-gray-300">
            <h3 className="font-bold mb-2">Flow Diagram:</h3>
            <pre className="text-sm text-gray-700 whitespace-pre-wrap font-mono">{content.diagram}</pre>
          </div>
        )}

        {content.flows && (
          <div className="mb-6">
            <h3 className="font-bold text-lg mb-3">Grant Types:</h3>
            {content.flows.map((flow, idx) => (
              <div key={idx} className={`mb-4 p-4 rounded-lg border-l-4 ${flow.recommended ? 'bg-green-50 border-green-500' : 'bg-red-50 border-red-500'}`}>
                <div className="flex items-center gap-2 mb-2">
                  {flow.recommended ? <CheckCircle className="text-green-600" size={20} /> : <XCircle className="text-red-600" size={20} />}
                  <h4 className="font-bold">{flow.name}</h4>
                </div>
                <p className="text-sm mb-1"><strong>Use Case:</strong> {flow.useCase}</p>
                <p className="text-sm mb-1"><strong>Security:</strong> {flow.security}</p>
                <p className="text-sm"><strong>Flow:</strong> {flow.steps}</p>
              </div>
            ))}
            {content.keyDecisions && (
              <div className="mt-4 bg-blue-50 p-4 rounded-lg">
                <p className="font-semibold">💡 {content.keyDecisions}</p>
              </div>
            )}
          </div>
        )}

        {content.tokens && (
          <div className="mb-6">
            <h3 className="font-bold text-lg mb-3">Token Types:</h3>
            {Object.entries(content.tokens).map(([tokenType, tokenInfo]) => (
              <div key={tokenType} className="mb-4 p-4 bg-gray-50 rounded-lg">
                <h4 className="font-bold capitalize mb-2">{tokenType.replace(/([A-Z])/g, ' $1').trim()}</h4>
                <div className="space-y-1 text-sm">
                  <p><strong>Purpose:</strong> {tokenInfo.purpose}</p>
                  <p><strong>Lifetime:</strong> {tokenInfo.lifetime}</p>
                  <p><strong>Storage:</strong> {tokenInfo.storage}</p>
                  {tokenInfo.format && <p><strong>Format:</strong> {tokenInfo.format}</p>}
                  {tokenInfo.rotation && <p><strong>Rotation:</strong> {tokenInfo.rotation}</p>}
                  {tokenInfo.validation && <p><strong>Validation:</strong> {tokenInfo.validation}</p>}
                </div>
              </div>
            ))}
          </div>
        )}

        {content.parameters && (
          <div className="mb-6">
            <h3 className="font-bold text-lg mb-3">Key Parameters:</h3>
            <ul className="space-y-2">
              {content.parameters.map((param, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <Code className="text-purple-600 mt-1 flex-shrink-0" size={16} />
                  <span className="text-sm">{param}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {content.vulnerability && (
          <div className="space-y-6">
            <div className="bg-red-50 p-4 rounded-lg border-l-4 border-red-600">
              <h3 className="font-bold text-red-900 mb-2">Vulnerability:</h3>
              <p className="text-gray-700">{content.vulnerability}</p>
            </div>

            <div className="bg-orange-50 p-4 rounded-lg border-l-4 border-orange-600">
              <h3 className="font-bold text-orange-900 mb-2">Impact:</h3>
              <p className="text-gray-700">{content.impact}</p>
            </div>

            {content.exploitSteps && (
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="font-bold mb-3">Exploitation Steps:</h3>
                <ol className="space-y-2">
                  {content.exploitSteps.map((step, idx) => (
                    <li key={idx} className="flex gap-3">
                      <span className="font-bold text-red-600">{idx + 1}.</span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}

            {content.bypassTechniques && (
              <div className="bg-purple-50 p-4 rounded-lg">
                <h3 className="font-bold mb-3">Bypass Techniques:</h3>
                <ul className="space-y-2">
                  {content.bypassTechniques.map((technique, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <Terminal className="text-purple-600 mt-1 flex-shrink-0" size={16} />
                      <code className="text-sm bg-white px-2 py-1 rounded">{technique}</code>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {content.testingSteps && (
              <div className="bg-blue-50 p-4 rounded-lg">
                <h3 className="font-bold mb-3">Testing Steps:</h3>
                <ul className="space-y-2">
                  {content.testingSteps.map((step, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <CheckCircle className="text-blue-600 mt-1 flex-shrink-0" size={16} />
                      <span className="text-sm">{step}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {content.exploitCode && (
              <div>
                <h3 className="font-bold mb-2">Exploit Code:</h3>
                <pre className="bg-gray-900 text-green-400 p-4 rounded-lg overflow-x-auto text-sm font-mono">{content.exploitCode}</pre>
              </div>
            )}

            {content.pkceExplained && (
              <div className="bg-green-50 p-4 rounded-lg border-l-4 border-green-600">
                <h3 className="font-bold text-green-900 mb-2">How PKCE Prevents This:</h3>
                <pre className="text-sm text-gray-700 whitespace-pre-wrap">{content.pkceExplained}</pre>
              </div>
            )}

            {content.mitigation && (
              <div className="bg-green-50 p-4 rounded-lg border-l-4 border-green-600">
                <h3 className="font-bold text-green-900 mb-3">Mitigation:</h3>
                <ul className="space-y-2">
                  {content.mitigation.map((step, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <Shield className="text-green-600 mt-1 flex-shrink-0" size={16} />
                      <span className="text-sm">{step}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              {content.realWorldExample && (
                <div className="bg-yellow-50 p-3 rounded-lg">
                  <h4 className="font-bold text-sm mb-1">Real-World Example:</h4>
                  <p className="text-sm text-gray-700">{content.realWorldExample}</p>
                </div>
              )}
              {content.cvss && (
                <div className="bg-red-50 p-3 rounded-lg">
                  <h4 className="font-bold text-sm mb-1">CVSS Score:</h4>
                  <p className="text-sm text-gray-700">{content.cvss}</p>
                </div>
              )}
            </div>

            {content.cwe && (
              <div className="text-sm text-gray-600">
                <strong>CWE:</strong> {content.cwe}
              </div>
            )}
          </div>
        )}

        {content.code && (
          <div className="mb-6">
            <h3 className="font-bold mb-2">Implementation:</h3>
            <pre className="bg-gray-900 text-green-400 p-4 rounded-lg overflow-x-auto text-sm font-mono">{content.code}</pre>
            {content.keyPoints && (
              <div className="mt-4 bg-blue-50 p-4 rounded-lg">
                <h4 className="font-bold mb-2">Key Points:</h4>
                <ul className="space-y-1">
                  {content.keyPoints.map((point, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="text-blue-600">✓</span>
                      <span className="text-sm">{point}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {content.walkthrough && (
          <div className="mb-6">
            {content.setup && (
              <div className="mb-4 bg-gray-50 p-4 rounded-lg">
                <h4 className="font-bold mb-2">Setup:</h4>
                <p className="text-sm">{content.setup}</p>
              </div>
            )}
            {content.attackGoal && (
              <div className="mb-4 bg-orange-50 p-4 rounded-lg border-l-4 border-orange-500">
                <h4 className="font-bold mb-2">Attack Goal:</h4>
                <p className="text-sm">{content.attackGoal}</p>
              </div>
            )}
            <div className="bg-gray-900 text-green-400 p-4 rounded-lg">
              <h4 className="font-bold mb-3 text-white">Step-by-Step Walkthrough:</h4>
              <pre className="text-sm whitespace-pre-wrap font-mono">{content.walkthrough.join('\n')}</pre>
            </div>
            {content.technicalDetails && (
              <div className="mt-4 bg-blue-50 p-4 rounded-lg">
                <h4 className="font-bold mb-2">Technical Details:</h4>
                <pre className="text-sm whitespace-pre-wrap">{content.technicalDetails}</pre>
              </div>
            )}
            {content.prevention && (
              <div className="mt-4 bg-green-50 p-4 rounded-lg border-l-4 border-green-600">
                <h4 className="font-bold text-green-900 mb-2">Prevention:</h4>
                <p className="text-sm">{content.prevention}</p>
              </div>
            )}
            {content.labsToTry && (
              <div className="mt-4 bg-purple-50 p-4 rounded-lg">
                <h4 className="font-bold mb-2">Practice Labs:</h4>
                <ul className="space-y-1">
                  {content.labsToTry.map((lab, idx) => (
                    <li key={idx} className="text-sm flex items-center gap-2">
                      <Terminal size={14} className="text-purple-600" />
                      {lab}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {content.guidelines && (
          <div className="mb-6">
            {Object.entries(content.guidelines).map(([category, items]) => (
              <div key={category} className="mb-4">
                <h3 className="font-bold text-lg mb-2">{category}:</h3>
                <div className="bg-gray-50 p-4 rounded-lg space-y-2">
                  {Object.entries(items).map(([platform, guidance]) => (
                    <div key={platform}>
                      <h4 className="font-semibold text-sm">{platform}:</h4>
                      <p className="text-sm text-gray-700 ml-4">{guidance}</p>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {content.categories && (
          <div className="space-y-6">
            {content.categories.map((category, idx) => (
              <div key={idx} className="bg-white border rounded-lg p-4">
                <h3 className="font-bold text-lg mb-4 text-gray-800">{category.name}</h3>
                <div className="space-y-2">
                  {category.tests.map((item, testIdx) => (
                    <div key={testIdx} className="flex items-center justify-between p-3 bg-gray-50 rounded hover:bg-gray-100">
                      <div className="flex items-center gap-3 flex-1">
                        <input type="checkbox" className="w-5 h-5" />
                        <span className="text-sm">{item.test}</span>
                      </div>
                      <span className={`text-xs font-semibold px-3 py-1 rounded-full ${
                        item.severity === 'Critical' ? 'bg-red-100 text-red-800' :
                        item.severity === 'High' ? 'bg-orange-100 text-orange-800' :
                        'bg-yellow-100 text-yellow-800'
                      }`}>
                        {item.severity}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {content.standards && (
          <div className="mt-6 text-sm text-gray-600">
            <strong>Standards:</strong> {content.standards.join(', ')}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="h-screen flex flex-col bg-gray-100">
      <div className="bg-gradient-to-r from-indigo-600 to-purple-600 text-white p-6 shadow-lg">
        <h1 className="text-3xl font-bold mb-2">OAuth 2.0 Security Deep Dive</h1>
        <p className="text-indigo-100">Complete vulnerability analysis, attack scenarios, and secure implementation patterns</p>
      </div>

      <div className="flex-1 flex overflow-hidden">
        <div className="w-1/3 bg-white border-r overflow-auto p-4">
          {data.sections.map((section, idx) => (
            <Section key={idx} section={section} sectionIdx={idx} />
          ))}
        </div>

        <div className="w-2/3 bg-gray-50">
          <DetailView />
        </div>
      </div>

      <div className="bg-gray-800 text-gray-300 p-3 text-sm">
        <strong>Next:</strong> After studying OAuth, practice on PortSwigger OAuth labs, then we'll build the testing scripts artifact!
      </div>
    </div>
  );
};
  // PASTE THE FULL COMPONENT CODE FROM oauth-deepdive HERE
  // This includes all the OAuth data, Section component, DetailView, everything
  // The artifact has the complete working code
  
  return <div>OAuth Deep Dive Component - Replace this with actual code</div>;
};

// ============================================================================
// MAIN APP COMPONENT - Navigation between the two views
// ============================================================================

function App() {
  const [activeView, setActiveView] = useState('ato');

  return (
    <div className="h-screen flex flex-col">
      {/* Navigation Bar */}
      <nav className="bg-gray-900 text-white p-4 shadow-lg">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <h1 className="text-2xl font-bold">ATO Security Testing Guide</h1>
          <div className="flex gap-4">
            <button
              onClick={() => setActiveView('ato')}
              className={`px-6 py-2 rounded-lg font-semibold transition-all ${
                activeView === 'ato' 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              📚 ATO Reference Map
            </button>
            <button
              onClick={() => setActiveView('oauth')}
              className={`px-6 py-2 rounded-lg font-semibold transition-all ${
                activeView === 'oauth' 
                  ? 'bg-purple-600 text-white' 
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              🔐 OAuth 2.0 Deep Dive
            </button>
          </div>
        </div>
      </nav>

      {/* Content Area */}
      <div className="flex-1 overflow-hidden">
        {activeView === 'ato' ? <ATOMindMap /> : <OAuthDeepDive />}
      </div>
    </div>
  );
}

export default App;
