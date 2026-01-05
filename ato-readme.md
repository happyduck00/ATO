# Account Takeover (ATO) Security Testing & Reference Guide

A comprehensive, interactive guide for learning and testing Account Takeover vulnerabilities. This resource includes testing methodologies, real-world CVEs, practice resources, and OAuth 2.0 deep dives.

## Features

- **Interactive Mind Map**: Complete attack surface visualization with expandable nodes
- **Testing Checklists**: Pass/fail checkboxes for each security test
- **OAuth 2.0 Deep Dive**: Comprehensive vulnerability analysis with exploit code
- **Practice Resources**: Mapped to HackTheBox, PortSwigger, OWASP, and more
- **Real CVEs**: Historical vulnerabilities with technical breakdowns
- **Standards References**: NIST, RFC, OWASP, CWE citations

## Quick Start with Docker

### Prerequisites
- Docker installed ([Get Docker](https://docs.docker.com/get-docker/))
- Docker Compose installed (included with Docker Desktop)

### Run Locally

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/ATO.git
   cd ATO
   ```

2. **Build and run with Docker Compose**
   ```bash
   docker-compose up --build
   ```

3. **Access the application**
   Open your browser to: **http://localhost:3000**

4. **Stop the application**
   ```bash
   # Press Ctrl+C in the terminal, then:
   docker-compose down
   ```

## Manual Setup (Without Docker)

If you prefer to run without Docker:

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Start development server**
   ```bash
   npm start
   ```

3. **Access at http://localhost:3000**

4. **Build for production**
   ```bash
   npm run build
   ```

## Project Structure

```
ATO/
├── public/
│   ├── index.html          # HTML entry point
│   └── favicon.ico         # App icon
├── src/
│   ├── App.js              # Main app component with both guides
│   ├── index.js            # React entry point
│   └── index.css           # Tailwind CSS
├── Dockerfile              # Docker build instructions
├── docker-compose.yml      # Docker Compose configuration
├── nginx.conf              # Nginx server configuration
├── package.json            # Node dependencies
└── README.md              # This file
```

## Usage Guide

### Main Reference Map
- Click on major categories to expand
- Select specific topics to see:
  - Step-by-step testing procedures (with pass/fail checkboxes)
  - Standards and RFC references
  - Practice resources (HackTheBox, PortSwigger, etc.)
  - Real-world CVEs
  - Common vulnerability patterns
  - Technologies and tools
  - Knowledge gap checklists

### OAuth 2.0 Deep Dive
- Comprehensive vulnerability analysis
- Attack scenarios with step-by-step walkthroughs
- Exploit code examples
- Secure implementation patterns
- Complete testing checklist

## Learning Path

1. **Start with Fundamentals** (Main Map)
   - Understand authentication mechanisms
   - Learn session management basics
   - Study authorization models

2. **Explore Attack Vectors**
   - Credential stuffing & brute force
   - Session attacks
   - CSRF vulnerabilities
   - OAuth-specific attacks

3. **Study Defense Mechanisms**
   - Rate limiting
   - WAF configuration
   - Bot detection
   - Security headers

4. **Deep Dive: OAuth 2.0**
   - Complete OAuth flows
   - Common vulnerabilities
   - Real attack scenarios
   - Secure implementations

5. **Practice**
   - Use the practice resources listed
   - Complete PortSwigger labs
   - Try HackTheBox challenges
   - Test real applications

## Contributing

Found a vulnerability pattern not covered? Have a better testing methodology? Contributions welcome!

## Resources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)

## License

MIT License - Educational purposes only. Always get permission before testing security on systems you don't own.

## Disclaimer

This tool is for educational and authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.
