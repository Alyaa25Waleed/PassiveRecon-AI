# PassiveRecon-AI

Next-Generation Passive Reconnaissance & AI-Driven Threat Intelligence Framework.

PassiveRecon-AI is an automated tool for passive information gathering and pre-engagement target analysis. It relies on zero-contact reconnaissance techniques, followed by AI-powered analysis (OpenAI) to generate comprehensive reports and suggest potential attack vectors.

---

## Key Features

- Passive Subdomain Enumeration: Extract subdomains accurately via SSL/TLS certificates using crt.sh.
- Comprehensive DNS Analysis: Query and analyze essential DNS records (A, MX, NS, TXT) to reveal infrastructure details and associated services.
- Historical URL Discovery: Fetch and reconstruct historical URL trees via the Wayback Machine to identify legacy endpoints or sensitive information leaks.
- AI-Powered Attack Surface Report: Leverage OpenAI models to aggregate and analyze data automatically, generating a preliminary evaluation report that includes:
  - Attack surface summary.
  - Potential architectural and scenario-based vulnerabilities.
  - Suggested attack vectors to guide the active testing phase.

---

## Tech Stack

| Component | Technology |
| :--- | :--- |
| Language | Python 3.9+ |
| Frontend / UI | Streamlit |
| AI Engine | OpenAI API (gpt-4 / gpt-3.5-turbo) |
| Networking & DNS | requests, dnspython |

---

## Getting Started

### Prerequisites

Ensure you have the following prerequisites installed and configured:
- Python 3.9+ installed on your system.
