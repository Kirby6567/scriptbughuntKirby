# 🎯 Enterprise Bug Bounty Scanner Framework - Complete Documentation

<div align="center">

![Version](https://img.shields.io/badge/version-3.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-purple.svg)
![Status](https://img.shields.io/badge/status-Production-success.svg)

**Enterprise-grade automated reconnaissance and vulnerability scanning pipeline for Bug Bounty programs**

[Features](#-key-features) •
[Installation](#-installation) •
[Usage](#-quick-start) •
[Profiles](#-execution-profiles) •
[Documentation](#-complete-documentation)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Execution Profiles](#-execution-profiles)
- [Scanner Phases](#-scanner-phases)
- [Integrated Tools](#-integrated-tools)
- [Outputs & Reports](#-outputs-and-reports)
- [Best Practices](#-best-practices)
- [Troubleshooting](#-troubleshooting)
- [Complete Documentation](#-complete-documentation)

---

## 🎯 Overview

The **Enterprise Bug Bounty Scanner** is a comprehensive, automated framework designed for offensive security professionals, bug hunters, and penetration testers. It seamlessly integrates **40+ industry-leading tools** into an intelligent, optimized pipeline for discovering vulnerabilities in web applications while adhering to ethical bug bounty principles.

### 🌟 Key Highlights

- **End-to-End Pipeline**: Complete workflow from subdomain enumeration to vulnerability exploitation
- **4 Adaptive Profiles**: Light, Balanced, Aggressive, and Kamikaze modes with automatic resource optimization
- **Dry-Run Capability**: Test and plan reconnaissance without triggering active scans
- **Advanced Anti-Blocking**: Sophisticated techniques to bypass WAF and Cloudflare protection
- **40+ Tool Integration**: Native support for the industry's best security tools
- **Real-Time Notifications**: Integrated Discord and Telegram alerts
- **Professional Reporting**: Multi-format exports (HTML, JSON, Markdown, HackerOne, Bugcrowd)

---

## 🚀 Key Features

### 🔍 Discovery & Reconnaissance

#### Subdomain Enumeration
- **Subfinder**: 40+ sources with API key support
- **Amass**: Passive and active reconnaissance
- **Assetfinder**: Additional subdomain discovery
- **Findomain**: Multi-source enumeration
- **crt.sh**: Certificate transparency logs
- **Chaos**: ProjectDiscovery's dataset

#### URL & Endpoint Discovery
- **Archive-based**: Gau, Waybackurls, Hakrawler
- **Active Crawling**: Katana, Gospider
- **JavaScript Mining**: getJS for JS file extraction
- **API Endpoints**: Automatic extraction from JS files

#### Network & Technology Detection
- **Port Scanning**: Two-phase approach (Masscan + Naabu)
- **Technology Fingerprinting**: httpx with comprehensive detection
- **WAF Identification**: wafw00f with automated analysis
- **Service Detection**: Banner grabbing and version identification

### 🛡️ Anti-Blocking & Stealth Techniques

#### Cloudflare Bypass (7 Techniques)
1. **DNS History Mining**: CloudFlair integration
2. **CrimeFlare Database**: Historical IP lookup
3. **SSL Certificate Analysis**: Origin server discovery
4. **Subdomain Testing**: Unprotected subdomain identification
5. **DNS Records**: MX, TXT, SPF record analysis
6. **Censys Search**: Historical SSL certificate data
7. **Shodan Integration**: Direct IP discovery

#### Request Obfuscation
- **User-Agent Rotation**: Pool of 10+ realistic browser UAs
- **Header Injection**: Custom bypass headers (X-Forwarded-For, CF-Connecting-IP, True-Client-IP)
- **Adaptive Rate Limiting**: Automatic adjustment based on 429/503 responses
- **Intelligent Delays**: Randomized request spacing (5-45s based on stealth mode)
- **Retry Logic**: Exponential backoff with jitter

### 🎯 Comprehensive Vulnerability Scanning

#### Nuclei Multi-Mode Scanning
```bash
Mode 1: Fast Mode
- Templates: critical, high severity only
- Target: Live hosts
- Speed: Maximum concurrency
- Purpose: Quick wins and critical issues

Mode 2: Extended Mode  
- Templates: All severities (critical → info)
- Target: Live hosts
- Coverage: Complete template library
- Purpose: Comprehensive vulnerability detection

Mode 3: Fuzzing Mode
- Templates: Fuzzing workflows
- Target: URLs with parameters
- Focus: Input validation issues
- Purpose: Parameter-based vulnerabilities

Mode 4: DOM/JavaScript Mode
- Templates: JavaScript-specific checks
- Target: All URLs
- Method: Headless browser
- Purpose: Client-side vulnerabilities
```

#### Specialized Scanners

**Cross-Site Scripting (XSS)**
- **dalfox**: 200+ custom payloads, WAF bypass, reflection detection
- **kxss**: Reflection point discovery
- **Custom Payloads**: Context-aware injection patterns

**SQL Injection (SQLi)**
- **sqlmap**: Two-stage validation process
  - Stage 1: Quick detection (level 1-2, risk 1)
  - Stage 2: Deep exploitation (level 5, risk 3)
- **gf Patterns**: SQL injection pattern matching
- **Automatic Validation**: False positive filtering

**Server-Side Request Forgery (SSRF)**
- **Pattern Detection**: gf ssrf patterns
- **Parameter Analysis**: Automatic suspicious parameter identification
- **nuclei Templates**: SSRF-specific checks
- **Payload Testing**: Internal network probing

**Cross-Origin Resource Sharing (CORS)**
- **6 Test Origins**: 
  - `null`
  - `attacker.com`
  - `evil.com.example.com`
  - `example.com.evil.com`
  - Wildcard testing
  - Subdomain reflection
- **Header Analysis**: Access-Control-* validation
- **Credential Testing**: withCredentials flag checks

**JSON Web Token (JWT)**
- **Automatic Extraction**: From responses and JS files
- **Algorithm Analysis**: None algorithm detection
- **Decode & Inspect**: Claims validation
- **Secret Testing**: Weak secret brute-forcing

**GraphQL Security**
- **Introspection Testing**: Automated queries on common endpoints
- **Schema Extraction**: Full schema dumping
- **Query Depth Analysis**: DoS vector identification
- **Batch Query Testing**: Batching attack detection

**Subdomain Takeover**
- **subjack**: DNS record validation
- **nuclei Takeover Templates**: Platform-specific checks
- **CNAME Analysis**: Dangling DNS identification

### 🔐 Secret & Credential Hunting

#### Pattern-Based Detection
```regex
50+ Regex Patterns for:
- AWS Access Keys: AKIA[0-9A-Z]{16}
- Google API: AIza[0-9A-Za-z\\-_]{35}
- Stripe Keys: sk_live_[0-9a-zA-Z]{24}
- GitHub Tokens: ghp_[0-9a-zA-Z]{36}
- Private Keys: -----BEGIN (RSA|DSA|EC) PRIVATE KEY-----
- Database Credentials: mysql://user:pass@host
- API Endpoints: /api/v[0-9]/
- And 40+ more...
```

#### Specialized Tools
- **SecretFinder**: JavaScript secret mining
- **TruffleHog**: Git history analysis
- **Gitleaks**: Git commit scanning
- **git-dumper**: Exposed .git directory exploitation
- **JWT Extraction**: Token discovery and analysis

### 📊 Advanced Testing Modules

#### Parameter Discovery
- **Arjun**: Advanced HTTP parameter brute-forcing (10,000+ wordlist)
- **ParamSpider**: Web archive parameter extraction
- **JavaScript Analysis**: Variable and endpoint extraction
- **Pattern Matching**: Common parameter patterns

#### Endpoint Mining
- **LinkFinder**: Regex-based endpoint discovery in JS
- **50+ Files**: Concurrent JS file analysis
- **API Path Extraction**: RESTful endpoint identification
- **Versioned APIs**: v1, v2, v3 pattern detection

#### Cloud Security
- **S3 Scanner**: AWS bucket enumeration and testing
- **cloud_enum**: Multi-cloud resource discovery (AWS, Azure, GCP)
- **Naming Patterns**: Company name permutations
- **Public Access Testing**: ACL misconfiguration detection

#### HTTP Security
- **Smuggler**: HTTP request smuggling (CL.TE, TE.CL, TE.TE)
- **Commix**: Command injection testing
- **LFISuite**: Local file inclusion exploitation
- **Path Traversal**: Directory traversal testing

#### Visual Reconnaissance
- **gowitness**: Full-page screenshots with Chrome
- **aquatone**: Visual inspection and thumbnail generation
- **Technology Screenshots**: Evidence collection

### 📱 Notification & Monitoring

#### Discord Integration
```json
{
  "embeds": [{
    "title": "🚨 Critical Vulnerability Found",
    "description": "SQL injection in login endpoint",
    "color": 15158332,
    "fields": [
      {"name": "URL", "value": "https://example.com/login"},
      {"name": "Severity", "value": "Critical"},
      {"name": "Tool", "value": "sqlmap"}
    ],
    "timestamp": "2025-11-10T12:34:56.000Z"
  }]
}
```

#### Telegram Bot
```markdown
🚨 **Critical Finding**

**Type**: SQL Injection  
**URL**: `https://example.com/api/users`  
**Severity**: CRITICAL  
**Tool**: sqlmap  

**Details**: Union-based SQLi confirmed  
**Database**: MySQL 5.7  

🔧 Instance: scanner_001...  
🕐 12:34:56
```

#### Progress Tracking
- **Phase Notifications**: Start/complete alerts for each phase
- **Statistics Updates**: Real-time counters (subdomains, URLs, vulns)
- **Error Alerts**: Immediate notification of critical errors
- **Completion Summary**: Final statistics and findings count

### 📄 Professional Export Formats

#### HTML Dashboard
```html
<!DOCTYPE html>
<html>
<head>
    <title>Bug Bounty Scan Report</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
    <!-- Executive Summary Card -->
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="stats">
            <span class="critical">2 Critical</span>
            <span class="high">15 High</span>
            <span class="medium">45 Medium</span>
            <span class="low">120 Low</span>
        </div>
    </div>
    
    <!-- Interactive Charts -->
    <div id="severity-chart"></div>
    <div id="timeline-chart"></div>
    
    <!-- Detailed Findings -->
    <table class="findings">
        <tr>
            <th>Severity</th>
            <th>Type</th>
            <th>URL</th>
            <th>Details</th>
        </tr>
        <!-- Dynamic rows -->
    </table>
</body>
</html>
```

#### HackerOne Markdown Report
```markdown
## Summary
Critical SQL injection vulnerability in user authentication endpoint

## Vulnerability Details

**Severity**: Critical  
**Type**: SQL Injection (Union-based)  
**CVSS Score**: 9.8  
**CWE**: CWE-89 (Improper Neutralization of Special Elements)

## Description
The `/api/login` endpoint is vulnerable to union-based SQL injection...

## Steps to Reproduce
1. Navigate to `https://example.com/api/login`
2. Intercept the POST request
3. Inject payload: `' UNION SELECT 1,2,3,4,5-- -`
4. Observe database error revealing table structure
5. Extract sensitive data using: `' UNION SELECT username,password FROM users-- -`

## Impact
- Complete database compromise
- Unauthorized access to user accounts
- Potential for complete system takeover
- GDPR compliance violation

## Proof of Concept
[Attached: poc_sqli_login.txt]
[Screenshot: database_dump.png]

## Remediation
1. Implement parameterized queries/prepared statements
2. Apply input validation and sanitization
3. Implement WAF rules for SQL injection patterns
4. Review all database interaction code
```

#### Bugcrowd JSON Export
```json
{
  "title": "Critical SQL Injection in Login Endpoint",
  "severity": 4,
  "vulnerability_type": "sql_injection",
  "description": "The application is vulnerable to SQL injection in the login endpoint, allowing an attacker to bypass authentication and extract sensitive database contents.",
  "http_request": "POST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"username\":\"admin' OR '1'='1\",\"password\":\"anything\"}",
  "proof_of_concept": "1. Send malicious payload in username field\n2. Observe SQL error in response\n3. Exploit using UNION SELECT\n4. Extract user credentials",
  "impact": "Complete database access, authentication bypass, sensitive data exposure",
  "remediation": "Use parameterized queries, implement input validation, add WAF protection",
  "cvss_score": "9.8",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "affected_url": "https://example.com/api/login",
  "target": "example.com"
}
```

---

## 🏗️ System Architecture

### Pipeline Flow

```
┌─────────────────────────────────────────────────────────────┐
│                       INITIALIZATION                         │
│  ┌────────┐  ┌────────┐  ┌─────────┐  ┌──────────────┐    │
│  │ Profile│→│Validate│→│Setup    │→│Notification  │    │
│  │ Select │  │ Tools  │  │Directory│  │Initialize    │    │
│  └────────┘  └────────┘  └─────────┘  └──────────────┘    │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                PHASE 1: SUBDOMAIN ENUMERATION               │
│  ┌──────────┐  ┌──────┐  ┌──────────┐  ┌────────┐         │
│  │Subfinder │  │Amass │  │Assetfind│  │crt.sh  │         │
│  │(40+ src) │  │(P+A) │  │(discover)│  │(API)   │         │
│  └────┬─────┘  └───┬──┘  └────┬─────┘  └───┬────┘         │
│       └────────────┼──────────┼────────────┘              │
│                    ▼          ▼                            │
│           Merge & Deduplicate → all_subs.txt              │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│         PHASE 2: LIVE DETECTION & WAF ANALYSIS              │
│  ┌─────────────────┐  ┌──────────┐  ┌─────────────┐       │
│  │httpx            │  │wafw00f   │  │Cloudflare   │       │
│  │• Tech detect    │  │• WAF ID  │  │• 7 Bypass   │       │
│  │• Status codes   │  │• Vendor  │  │  Techniques │       │
│  │• Title scraping │  │• Rules   │  │• Origin IP  │       │
│  └────────┬────────┘  └────┬─────┘  └──────┬──────┘       │
│           └────────────────┼────────────────┘              │
│                            ▼                                │
│          hosts.txt + technologies.txt + waf_summary.txt    │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  PHASE 3: PORT SCANNING                     │
│  ┌────────────────────┐  ┌─────────────────────┐           │
│  │Masscan (Stage 1)   │  │Naabu (Stage 2)      │           │
│  │• Ultra-fast sweep  │→│• Verification       │           │
│  │• All 65535 ports   │  │• Service detection  │           │
│  │• Rate: 300-5000pps │  │• Banner grabbing    │           │
│  └────────────────────┘  └─────────────────────┘           │
│                            ▼                                │
│                    open_ports.txt                           │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│           PHASE 4: URL & JAVASCRIPT COLLECTION              │
│  ┌──────┐  ┌─────────┐  ┌────────┐  ┌──────┐              │
│  │Gau   │  │Wayback  │  │Katana  │  │getJS │              │
│  │(arch)│  │(archive)│  │(crawl) │  │(JS)  │              │
│  └──┬───┘  └────┬────┘  └───┬────┘  └──┬───┘              │
│     └───────────┼───────────┼──────────┘                   │
│                 ▼           ▼                               │
│       all_urls.txt + with_params.txt + JS files            │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│           PHASE 5: VULNERABILITY SCANNING                   │
│  ┌─────────────────────────────────────────────┐           │
│  │ Nuclei (4 Parallel Modes)                   │           │
│  │ ┌──────────┐ ┌──────────┐ ┌─────┐ ┌──────┐│           │
│  │ │Fast      │ │Extended  │ │Fuzz │ │DOM/JS││           │
│  │ │(C+H only)│ │(All sev) │ │(Wkfl)│ │(JS)  ││           │
│  │ └──────────┘ └──────────┘ └─────┘ └──────┘│           │
│  └─────────────────────────────────────────────┘           │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐             │
│  │dalfox    │  │sqlmap    │  │Custom Tests  │             │
│  │(XSS)     │  │(SQLi)    │  │CORS/JWT/SSRF │             │
│  └──────────┘  └──────────┘  └──────────────┘             │
│                            ▼                                │
│         Findings by severity + validated exploits          │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  PHASE 6: EXTRA TOOLS                       │
│  ┌─────────────────────────────────────────────┐           │
│  │ Parallel Groups (40+ Tools)                 │           │
│  │ ┌──────┐ ┌────────┐ ┌───────┐ ┌──────────┐│           │
│  │ │Secret│ │Param   │ │Exploit│ │Screenshot││           │
│  │ │Hunt  │ │Discov  │ │Tools  │ │Tools     ││           │
│  │ └──────┘ └────────┘ └───────┘ └──────────┘│           │
│  └─────────────────────────────────────────────┘           │
│                            ▼                                │
│              reports/* + screenshots/* + poc/*             │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│               PHASE 7: REPORT GENERATION                    │
│  ┌────────┐  ┌──────┐  ┌────────┐  ┌──────────┐           │
│  │HTML    │  │JSON  │  │Markdown│  │Platform  │           │
│  │Dashboard│  │Export│  │Summary │  │Exports   │           │
│  └───┬────┘  └───┬──┘  └────┬───┘  └────┬─────┘           │
│      └───────────┼──────────┼───────────┘                  │
│                  ▼          ▼                               │
│       Notifications (Discord/Telegram) + Final Report       │
└─────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
results_YYYYMMDD_HHMMSS/
├── raw/                              # Raw data and intermediates
│   ├── scope.clean.txt              # Processed scope
│   ├── subfinder.txt                # Subfinder results
│   ├── amass_passive.txt            # Amass passive
│   ├── amass_active.txt             # Amass active
│   ├── assetfinder.txt              # Assetfinder results
│   ├── findomain.txt                # Findomain results
│   ├── chaos.txt                    # Chaos results
│   └── crtsh.txt                    # crt.sh results
│
├── subs/                             # Subdomain enumeration
│   └── all_subs.txt                 # Deduplicated subdomains
│
├── alive/                            # Live host detection
│   ├── httpx_results.txt            # httpx full output
│   ├── hosts.txt                    # Alive URLs
│   └── hosts_only.txt               # Domain names only
│
├── tech/                             # Technology detection
│   ├── technologies.txt             # Tech stack per host
│   ├── waf_*.txt                    # Individual WAF scans
│   └── waf_summary.txt              # WAF detection summary
│
├── ports/                            # Port scanning results
│   ├── ips.txt                      # Resolved IPs
│   ├── masscan_raw.txt              # Masscan output
│   ├── naabu_ports.txt              # Naabu output
│   └── open_ports.txt               # Merged results
│
├── urls/                             # URL collection
│   ├── gau.txt                      # Gau results
│   ├── wayback.txt                  # Waybackurls
│   ├── hakrawler.txt                # Hakrawler
│   ├── katana.txt                   # Katana
│   ├── gospider.txt                 # Gospider
│   ├── all_urls.txt                 # Merged URLs
│   ├── with_params.txt              # URLs with parameters
│   ├── gf_xss.txt                   # XSS candidates
│   ├── gf_sqli.txt                  # SQLi candidates
│   ├── gf_lfi.txt                   # LFI candidates
│   ├── gf_ssrf.txt                  # SSRF candidates
│   ├── gf_redirect.txt              # Redirect candidates
│   └── sqli_validated.txt           # Confirmed SQLi
│
├── js/                               # JavaScript files
│   ├── js_files.txt                 # JS file URLs
│   └── downloads/                   # Downloaded JS files
│       ├── example_com_app_js       
│       └── ...
│
├── nuclei/                           # Nuclei scan results
│   ├── nuclei_hosts_fast.txt        # Fast mode (C+H)
│   ├── nuclei_hosts_ext.txt         # Extended mode
│   ├── nuclei_fuzzing.txt           # Fuzzing mode
│   ├── nuclei_dom.txt               # DOM/JS mode
│   ├── dalfox_results.txt           # XSS findings
│   └── burp_scan/                   # Burp import files
│
├── params/                           # Parameter discovery
│   ├── arjun_parameters.txt         # Arjun results
│   └── paramspider_results.txt      # ParamSpider
│
├── apis/                             # API enumeration
│   ├── endpoints_from_js.txt        # JS endpoints
│   └── graphql/                     # GraphQL testing
│       ├── introspection_*.txt
│       └── vulnerable.txt
│
├── secrets/                          # Secret hunting
│   ├── all_secrets.txt              # Merged secrets
│   ├── api_keys.txt                 # API keys
│   ├── tokens.txt                   # Tokens
│   └── tokens/                      # Token analysis
│       └── jwt_analysis.txt
│
├── reports/                          # Tool-specific reports
│   ├── kxss/
│   │   └── kxss_reflected.txt
│   ├── linkfinder/
│   │   └── endpoints.txt
│   ├── secretfinder/
│   │   └── secrets_*.txt
│   ├── cors/
│   │   └── cors_vulnerable.txt
│   ├── ssrf/
│   │   └── ssrf_candidates.txt
│   ├── takeover/
│   │   └── takeover_vulnerable.txt
│   ├── cloudflare_bypass/
│   │   ├── cloudflair_results.txt
│   │   ├── crimeflare_results.txt
│   │   └── origin_ips.txt
│   └── ...
│
├── screenshots/                      # Visual documentation
│   ├── gowitness/
│   │   ├── example_com.png
│   │   └── screenshot.db
│   └── aquatone/
│       ├── screenshots/
│       └── aquatone_report.html
│
├── poc/                              # Proof of concepts
│   ├── notes/
│   └── exploits/
│
├── logs/                             # Execution logs
│   ├── scanner.log                  # Main log
│   ├── errors.log                   # Error log
│   ├── subdomain/
│   ├── httpx/
│   ├── nuclei/
│   ├── sqlmap/
│   └── ...
│
├── html/                             # HTML reports
│   └── dashboard.html               # Main report
│
├── scope.txt                         # Original scope
├── scan_summary.txt                  # Quick summary
├── hackerone_report.md              # H1 format
└── bugcrowd_report.json             # Bugcrowd format
```

---

## 💻 Installation

[Previous installation section remains the same - using content from main README.md]

---

## 🎮 Quick Start

[Previous quick start section remains the same - using content from main README.md]

---

## ⚙️ Execution Profiles

[Previous profiles section remains the same - using content from main README.md, including Kamikaze profile]

---

## 🔄 Scanner Phases

[Previous scanner phases section remains the same - using detailed content]

---

## 🛠️ Integrated Tools

[Previous tools section remains the same - using complete list]

---

## 📊 Outputs and Reports

[Previous outputs section remains the same - using detailed format examples]

---

## 💡 Best Practices

[Previous best practices section remains the same]

---

## 🐛 Troubleshooting

[Previous troubleshooting section remains the same]

---

## 📚 Complete Documentation

### Additional Resources

- **[Usage Examples](./USAGE_EXAMPLES.md)** - Comprehensive examples for various scenarios
- **[Technical Documentation](./TECHNICAL_DOCUMENTATION.md)** - Deep dive into architecture and internals
- **[Brutal Features Guide](../BRUTAL_FEATURES.md)** - Advanced aggressive scanning techniques
- **[Integration Guide](../../INTEGRATION_GUIDE.md)** - Third-party tool integrations

### Quick Links

- [Report Issues](https://github.com/Kirby6567/enterprise-bugbounty-scanner/issues)
- [Feature Requests](https://github.com/Kirby6567/enterprise-bugbounty-scanner/issues/new)
- [Discussions](https://github.com/Kirby6567/enterprise-bugbounty-scanner/discussions)
- [Wiki](https://github.com/Kirby6567/enterprise-bugbounty-scanner/wiki)

---

<div align="center">

**Made with ❤️ for the Bug Bounty Community**

⭐ Star us on GitHub | 🐛 Report Bugs | 💡 Request Features

[GitHub](https://github.com/Kirby6567/enterprise-bugbounty-scanner) •
[Documentation](./USAGE_EXAMPLES.md) •
[Author](https://github.com/Kirby6567)

</div>
