# Sentinel Threat Intelligence

> **A comprehensive real-time cybersecurity threat intelligence and network monitoring dashboard — powered by live threat feeds, AI-driven analysis, automated attack detection, and a global attack visualisation map.**

[![TypeScript](https://img.shields.io/badge/TypeScript-98.8%25-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-6.x-646CFF?logo=vite&logoColor=white)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-v4-38BDF8?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Google Gemini](https://img.shields.io/badge/Google_Gemini_AI-Integrated-4285F4?logo=google&logoColor=white)](https://ai.google.dev/)
[![Google Maps](https://img.shields.io/badge/Google_Maps-Integrated-34A853?logo=googlemaps&logoColor=white)](https://developers.google.com/maps)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📖 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Live Threat Intelligence Feeds](#live-threat-intelligence-feeds)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Author](#author)

---

## Overview

**Sentinel Threat Intelligence** (repo: `Netscan`) is a full-stack, real-time cybersecurity operations platform. It continuously ingests data from four live threat intelligence sources, runs an automated correlation engine, detects active attacks, and visualises global threat activity on an interactive map — all updating live in the browser.

The platform combines raw threat data from the security community (URLHaus, Feodo Tracker, CIRCL MISP, ThreatFox) with Google Gemini AI for contextual analysis and Google Maps for geographic attack visualisation.

---

## Features

### 🛡️ Real-Time Threat Intelligence
- Ingests live IoCs (Indicators of Compromise) from **four real threat intelligence APIs** every 60 seconds
- Tracks **IPs, Domains, Hashes, and URLs** with reputation scoring (Malicious / Suspicious) and threat tags
- Maintains a rolling database of up to 50 active IoCs, continuously refreshed

### 🗺️ Live Global Attack Map
- Visualises active attack traffic on a **Google Maps-powered world map** using `@vis.gl/react-google-maps`
- Geolocates attacker IPs in real time via `ip-api.com` with caching to avoid redundant lookups
- Displays attack source countries, attack type (DDoS, Malware, Phishing, Exploit), and target locations
- Falls back gracefully to simulated attack data when live geolocation is unavailable

### 🔁 Automated Correlation Engine
Runs every **5 seconds** and identifies three attack patterns automatically:

| Pattern | Trigger | Severity |
|---|---|---|
| **IoC Match** | A known malicious indicator appears in system logs | Critical / High |
| **Brute Force** | 5+ failed authentication log entries in a short window | High |
| **Data Exfiltration** | High-frequency DB queries followed by external connections | Critical |

### 📋 Live System Log Stream
- Generates and streams realistic system logs every **2 seconds** from five simulated sources: `AuthService`, `EdgeFirewall`, `DBProxy`, `APIGateway`, `Kernel`
- Log levels: `INFO`, `WARN`, `ERROR`, `CRITICAL`
- Log volume and severity automatically escalate when an active attack is detected

### 🚨 Automated Attack Detection & Alerting
- Continuously monitors log patterns for brute force and DDoS signatures
- Automatically sets the system into **"Under Attack"** mode when thresholds are breached — tripling network traffic metrics and intensifying log output
- Generates real-time alerts with severity levels: **Critical**, **High**, **Medium**
- Alert types include: Intrusion, Phishing, Malware, Policy Violation, Anomalous Traffic

### 📡 Network Statistics Dashboard
- Live bandwidth monitoring (inbound/outbound, in GB/s) — updates every **3 seconds**
- Real-time packet count tracking (inbound/outbound)
- Protocol distribution breakdown: TCP, UDP, ICMP, Other (rendered via Recharts)
- Top talkers list showing the highest-traffic IPs (internal and external)
- All metrics scale up automatically during active attack simulation

### 🕵️ Threat Actor Intelligence
Built-in profiles for three major nation-state threat actors with full MITRE ATT&CK mapping:

| Actor | Alias | Origin | Motivations |
|---|---|---|---|
| **APT-28** | Fancy Bear, STRONTIUM, Sofacy | 🇷🇺 Russia | Espionage, Political Influence |
| **APT-41** | Double Dragon, Winnti Group, BARIUM | 🇨🇳 China | Espionage, Financial Gain |
| **Lazarus Group** | Hidden Cobra, Guardians of Peace | 🇰🇵 North Korea | Financial Gain, Destruction |

Each profile includes target sectors, known TTPs (Tactics, Techniques, and Procedures) with direct links to the MITRE ATT&CK framework, and last known active date.

### 🤖 AI-Powered Insights
- **Google Gemini AI** integration for natural-language threat analysis and contextual security recommendations
- AI complements quantitative threat data with explainable, actionable insights

---

## Live Threat Intelligence Feeds

Netscan pulls from four real, publicly available threat intelligence sources:

| Source | Data Type | Update Frequency |
|---|---|---|
| **[URLHaus](https://urlhaus.abuse.ch/)** (abuse.ch) | Malicious URLs, active malware distribution sites | Every 60 seconds |
| **[Feodo Tracker](https://feodotracker.abuse.ch/)** (abuse.ch) | Botnet C2 server IPs (Emotet, TrickBot, Dridex, etc.) | Every 60 seconds |
| **[CIRCL MISP Feed](https://misp.circl.lu/)** | Structured threat events with IoCs (IPs, domains, hashes) | Every 60 seconds |
| **[ThreatFox](https://threatfox.abuse.ch/)** (abuse.ch) | Recent IoCs by threat type, with geolocation for attack map | Every 60 seconds |

All feeds include graceful error handling — if an API is unreachable, the system falls back to mock data and continues operating without interruption.

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 19, TypeScript (strict), Vite 6 |
| **Styling** | Tailwind CSS v4, Motion (animations), clsx, tailwind-merge |
| **AI / LLM** | Google Gemini AI (`@google/genai`) |
| **Maps** | Google Maps Platform (`@vis.gl/react-google-maps`) |
| **Charts** | Recharts |
| **Backend** | Express.js (Node.js, 611 lines) |
| **Threat Feeds** | URLHaus, Feodo Tracker, CIRCL MISP, ThreatFox |
| **Geolocation** | ip-api.com (with in-memory caching) |
| **Utilities** | date-fns, lucide-react, dotenv |
| **Tooling** | TypeScript 5.8, tsx, Vite, `tsc --noEmit` |

---

## Architecture

```
Sentinel Threat Intelligence (Netscan)
│
├── Frontend (React 19 SPA)
│   ├── Live dashboard — alerts, logs, network stats
│   ├── IoC management view
│   ├── Global attack map (Google Maps + geolocation)
│   ├── Threat actor intelligence profiles (MITRE ATT&CK)
│   ├── Correlation engine results view
│   └── AI analysis panel (Google Gemini)
│
├── Backend (Express.js — server.ts, 611 lines)
│   ├── /api/health           — system health check
│   ├── /api/iocs             — Indicators of Compromise
│   ├── /api/logs             — live system log stream
│   ├── /api/status           — attack status + latest alert
│   ├── /api/alerts           — security alert feed
│   ├── /api/attack-map       — geolocated attack data
│   ├── /api/correlations     — correlation engine results
│   ├── /api/network-stats    — bandwidth, packets, protocols
│   ├── /api/threat-actors    — APT profiles (MITRE ATT&CK)
│   │
│   ├── Background Jobs (setInterval)
│   │   ├── fetchRealThreatData()     — every 60s (4 live feeds)
│   │   ├── runCorrelationEngine()    — every 5s
│   │   ├── generateLog()            — every 2s
│   │   ├── updateNetworkStats()     — every 3s
│   │   └── simulateIoCRotation()    — every 10s
│   │
│   ├── Vite dev middleware (development / HMR)
│   └── Static SPA serving (production)
│
└── External APIs
    ├── Google Gemini AI      — GEMINI_API_KEY
    ├── Google Maps Platform  — GOOGLE_MAPS_PLATFORM_KEY
    ├── URLHaus API           — public (no key required)
    ├── Feodo Tracker API     — public (no key required)
    ├── CIRCL MISP Feed       — public (no key required)
    ├── ThreatFox API         — public (no key required)
    └── ip-api.com            — public geolocation (with cache)
```

---

## API Reference

All endpoints are served by the Express.js backend at `http://localhost:3000/api/`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | System health check with timestamp |
| `GET` | `/api/iocs` | All current Indicators of Compromise |
| `GET` | `/api/logs` | Last 100 system log entries (newest first) |
| `GET` | `/api/status` | Attack status, alert count, latest alert |
| `GET` | `/api/alerts` | All security alerts (newest first) |
| `GET` | `/api/attack-map` | Geolocated attack data for map rendering |
| `GET` | `/api/correlations` | Last 20 correlation engine findings |
| `GET` | `/api/network-stats` | Bandwidth, packet counts, protocol split, top talkers |
| `GET` | `/api/threat-actors` | APT profiles with MITRE ATT&CK TTPs |

---

## Getting Started

### Prerequisites

- **Node.js** 18+
- A **Google Gemini API key** — free at [aistudio.google.com](https://aistudio.google.com)
- *(Optional)* A **Google Maps Platform API key** for the attack map

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/BhargavA09/Netscan.git
cd Netscan

# 2. Install dependencies
npm install

# 3. Configure environment variables
cp .env.example .env
# Edit .env and add your API keys

# 4. Start the development server
npm run dev
```

Open `http://localhost:3000` — the dashboard will begin loading live threat data immediately.

---

## Environment Variables

```env
# Required — Google Gemini AI
GEMINI_API_KEY=your_gemini_api_key_here

# Optional — Google Maps Platform (enables the global attack map)
GOOGLE_MAPS_PLATFORM_KEY=your_google_maps_key_here
```

> ⚠️ **Never commit `.env` to version control.** It is already excluded in `.gitignore`. Use `.env.example` as the safe template — it contains no real credentials.

The four threat intelligence feeds (URLHaus, Feodo Tracker, CIRCL MISP, ThreatFox) and the IP geolocation service are all **free public APIs** — no keys required.

---

## Usage

### Available Scripts

| Command | Description |
|---|---|
| `npm run dev` | Start dev server with HMR at `localhost:3000` |
| `npm run build` | Build optimised production bundle to `dist/` |
| `npm run preview` | Preview the production build locally |
| `npm run lint` | TypeScript type-check (`tsc --noEmit`) |
| `npm run clean` | Remove the `dist/` build folder |

### What happens on startup

1. The Express backend starts on port 3000
2. Background jobs begin immediately — threat feeds are fetched, logs start streaming, network stats update
3. The React SPA connects to the API and begins rendering live data
4. The correlation engine starts analysing patterns every 5 seconds
5. The attack map populates as IoCs are geolocated

---

## Project Structure

```
Netscan/
├── src/                    # React + TypeScript frontend (SPA)
│   └── main.tsx            # App entry point
├── server.ts               # Express.js backend — 611 lines
│                           # (threat feeds, APIs, correlation engine, logs)
├── index.html              # HTML shell
├── vite.config.ts          # Vite config — React, Tailwind, env vars
├── tsconfig.json           # TypeScript strict configuration
├── package.json            # Dependencies and npm scripts
├── metadata.json           # App metadata (name: Sentinel Threat Intelligence)
├── .env.example            # Env variable template (no real keys)
└── .gitignore              # Excludes .env, dist/, node_modules/
```

---

## Contributing

Contributions, bug reports, and feature requests are welcome.

```bash
git checkout -b feature/your-feature
git commit -m "feat: describe your change"
git push origin feature/your-feature
# Open a Pull Request
```

Please ensure `npm run lint` passes before submitting.

---

## Author

**Bhargav Patel**
- GitHub: [@BhargavA09](https://github.com/BhargavA09)
- LinkedIn: [linkedin.com/in/bhrgavpatel](https://www.linkedin.com/in/bhrgavpatel)
- Email: bhrgavpatel04@gmail.com

---

*Built with React 19, Google Gemini AI, Google Maps, and four live cybersecurity threat intelligence feeds.*
