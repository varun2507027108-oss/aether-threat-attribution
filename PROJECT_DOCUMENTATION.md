# Project AETHER — Threat Actor De-Anonymization System
**Autonomous Engine for Threat Harmonization & Entity Resolution**  
*National Technical Research Organisation (NTRO) | Problem Statement: 26151 | Smart India Hackathon 2026*

---

## 1. Executive Summary & Purpose

### 1.1 Problem Statement
Modern cybercrime cartels, ransomware syndicates, and state-sponsored Advanced Persistent Threats (APTs) conduct illicit operations behind the anonymizing veil of the **Tor network (Onion Services)**, decentralized dark web bulletin boards, encrypted messaging protocols, and privacy coins.

Because breaking the underlying 1024/2048-bit RSA and Curve25519 cryptography of Onion Routing is computationally impossible, traditional investigative techniques fail. Furthermore, threat actors frequently rotate handles, burn compromised infrastructure, and utilize multiple forum personas to sever attribution trails. Manual investigations are fragmented, error-prone, and generate unverified intelligence that is legally inadmissible in courts of law.

### 1.2 The AETHER Paradigm
**Project AETHER** bypasses cryptographic hurdles entirely by exploiting the adversary's **Operational Security (OpSec) blunders, asset reuse, and immutable human behavioral patterns**:

```
+----------------------------------------------------------------------------------------------------+
|                                    PROJECT AETHER CORE PIPELINE                                    |
+----------------------------------------------------------------------------------------------------+
|  [Darknet Target (.onion)]                                                                         |
|            |                                                                                       |
|            +---> 1. Infrastructure Recon  ---> Favicon mmh3 + JARM Hash ---> Shodan/Censys Clearnet|
|            |                                                                                       |
|            +---> 2. Deterministic Keys    ---> PGP Fingerprint + BTC Peel Chain Clustering         |
|            |                                                                                       |
|            +---> 3. Behavioral Biomarkers ---> NLP Stylometry Cosine Sim + Circadian Sleep Trough  |
|            |                                                                                       |
|            v                                                                                       |
|  [Attribution Engine ($C_{attr}$ Calibrated Confidence Scoring with Contradiction Penalty)]        |
|            |                                                                                       |
|            v                                                                                       |
|  [Tamper-Evident SHA-256 Chain of Custody (Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872) Audit Ledger)] |
|            |                                                                                       |
|            +---> Court Dossier PDF (Digital Seal)                                                  |
|            +---> OASIS STIX 2.1 JSON Threat Feed Bundle                                            |
|            +---> RFC 4180 Forensic CSV Audit Matrix                                                |
+----------------------------------------------------------------------------------------------------+
```

1. **Origin Infrastructure Unmasking**: Cross-correlating unique web assets (Favicon MurmurHash3), TLS server configurations (JARM signatures), and server status endpoints against global clearnet sensors (Shodan, Censys) to expose the true backend IP address.
2. **Deterministic Identity Resolution**: Linking disparate aliases through cryptographic proof (40-character PGP public keys) and multi-input Bitcoin transaction clustering (common-input ownership heuristic).
3. **Linguistic & Behavioral Biomarkers**: Using NLP token/character n-gram vectorization and cosine similarity to match forum manifestos, combined with diurnal circadian sleep-trough modeling to triangulate the operator's operational UTC timezone.
4. **Calibrated Confidence Scoring ($C_{attr}$)**: Calculating mathematically rigorous attribution scores that prioritize deterministic cryptographic evidence while penalizing conflicting forensic artifacts.
5. **Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872) Compliance**: Recording all investigative operations in an append-only, SHA-256 cryptographic chain of custody, producing tamper-evident digital seals admissible in judicial proceedings.

---

## 2. Forensic Analysis Modules

### Module 1: Clearnet Origin Discovery
- **Favicon MurmurHash3 (`mmh3`)**: Calculates the 32-bit Murmur3 hash of the target's base64-encoded favicon. Clearnet web servers serving identical icons are discovered via Shodan search queries (`http.favicon.hash:<hash>`).
- **JARM TLS Fingerprinting**: Sends 10 active TLS Client Hello probes to record server response ciphers, extensions, and versions, generating a 62-character cryptographic fingerprint unique to the server's OS, OpenSSL version, and web daemon.
- **Apache `/server-status` & HTTP Leakage**: Probes for misconfigured mod_status or diagnostic endpoints leaking real public IPv4/IPv6 addresses, hostnames, and virtual host mappings.

### Module 2: Deterministic Identity Linking
- **PGP Key Fingerprint Extraction**: Normalizes and matches 160-bit SHA-1 fingerprints across independent dark web posts, marketplace listings, and key servers.
- **Bitcoin Peel-Chain Clustering**: Implements the multi-input ownership heuristic: when a transaction consumes inputs from multiple Bitcoin addresses, all input addresses are inferred to belong to the same wallet cluster, tracking peel chains down to deposit exchanges (KYC choke points).

### Module 3: Behavioral Profiling & Linguistic Intelligence
- **Comparative Stylometry Engine**: Extracts character 3-grams, word unigrams, and punctuation frequency distributions. Generates token embeddings and measures cosine similarity between intercepted threat actor messages and known suspect writing samples:
  $$\text{Cosine Similarity} = \frac{\mathbf{u} \cdot \mathbf{v}}{\|\mathbf{u}\| \|\mathbf{v}\|}$$
- **Circadian Diurnal Modeling**: Ingests timestamped dark web activity logs across 24 hours. Identifies the primary 6–8 hour consecutive inactivity trough (biological sleep cycle) to compute the operator's home timezone offset relative to UTC.

### Module 4: Calibrated Attribution Scoring ($C_{attr}$)
Unlike naive heuristic tools that simply sum indicator scores, AETHER employs an evidentiary weighting algorithm:
- **Deterministic Indicators** (PGP Match, Direct IP Binding): High weight ($30\% - 35\%$).
- **Probabilistic Indicators** (Stylometry similarity $> 0.85$, JARM match, Favicon match): Medium weight ($15\% - 20\%$).
- **Behavioral Indicators** (Circadian UTC overlap): Corroborative weight ($10\% - 15\%$).
- **Contradiction Deduction**: If conflicting evidence is detected (e.g. mutually exclusive server geolocations or disparate cryptographic identities), a penalty deduction is applied to prevent false convictions.

### Module 5: Tamper-Evident Chain of Custody & Judicial Admissibility
To satisfy the strict standards of **Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872)**:
- Every piece of evidence, investigator note, and analytical step is appended to an in-memory and database-backed hash chain.
- Each entry references the previous entry's SHA-256 hash:
  $$H_i = \text{SHA256}(H_{i-1} \parallel \text{Timestamp} \parallel \text{Operator} \parallel \text{Action} \parallel \text{Seq})$$
- The chain starts from a hardcoded `GENESIS_HASH`.
- Verification recalculates the entire ledger from Genesis to the tip. If even a single byte or timestamp is modified, verification fails and pinpoints the exact sequence number (`broken_at_seq`) where tampering occurred.

---

## 3. Technology Stack

### 3.1 Frontend Web Application (`aether-frontend/`)
- **Framework**: **Next.js 16.3.5 (App Router, Turbopack)**
- **UI Library**: **React 19.2.8**
- **Language**: **TypeScript 5**
- **Styling**: **Tailwind CSS v4** (Industrial dark steel color system: `#000000`, `#0f172a`, `#1e293b`, `#e2e8f0`, `#ffffff`)
- **Visual Design Rules**:
  - `border-radius: 0px` strictly enforced across all components
  - 1px crisp borders, monochrome tactical aesthetic
  - High-density Bento Grid layout
- **Visualizations**:
  - **Three.js (^0.186.0)**: Interactive 3D threat entity relationship knowledge graph
  - Custom Canvas/SVG renderers for circadian 24h diurnal clocks and Bitcoin transaction peel chains
- **API Client**: Robust client gateway (`src/lib/api.ts`) featuring:
  - Automatic backend auto-detection (`http://localhost:8000`)
  - Zero-crash offline fallback mechanism with synthetic mock data for field resilience

### 3.2 Backend REST API (`aether-backend/`)
- **Framework**: **FastAPI 0.115.6**
- **ASGI Server**: **Uvicorn 0.34.0 (Standard)**
- **Database & ORM**: **SQLAlchemy 2.0.36**
  - Production: **PostgreSQL 16** via `psycopg2-binary 2.9.10`
  - Development / Zero-Docker: **SQLite 3** (`sqlite:///./aether_dev.db`)
- **Data Validation & Typing**: **Pydantic 2.10.4** & `pydantic-core 2.27.2`
- **Threat Intelligence Standardization**: **stix2 3.0.2** (Official OASIS Cyber Threat Intelligence SDK for STIX 2.1 validation)
- **Security & Middleware**:
  - SSRF Guard: Strictly blocks private RFC 1918, loopback, link-local, and AWS/cloud metadata addresses
  - Sliding-window IP Rate Limiter
  - Request Payload Boundary Guard (2MB cap)
  - Security Headers (nosniff, X-Frame-Options, CSP, XSS-Protection)
  - Formula Injection Sanitizer: Neutralizes CSV spreadsheet formula injection (`=`, `+`, `-`, `@`)

### 3.3 Zero-Dependency Fallback Prototype (`index.html`)
- Standalone single-file HTML5/CSS3/Vanilla JS application (72KB)
- Completely independent of Node.js or Python runtimes
- Provides complete 3-stage tactical demonstration interface for air-gapped forensic environments

### 3.4 DevOps, Testing & Containerization
- **Containerization**: Docker, Docker Compose
- **Test Suite**: **Pytest 8.3.4**, `httpx 0.27.2` (74 comprehensive integration & unit tests)
- **Package Managers**: `npm 11+`, Python `pip` / `venv`

---

## 4. Directory & File Structure

Below is the complete, annotated file tree of the repository:

```
aether-threat-attribution/
├── .env.example                        # Template for global environment variables
├── .gitignore                          # Git ignore rules for node_modules, .venv, logs, etc.
├── docker-compose.yml                  # Multi-container orchestration (FastAPI + PostgreSQL)
├── index.html                          # Zero-dependency, single-file frontend prototype
├── README.md                           # Quick-start documentation and hackathon build status
├── PROJECT_DOCUMENTATION.md            # Comprehensive architectural and reference guide (This file)
│
├── docs/                               # Project documentation and briefs
│   └── project_aether_executive_brief.md # Executive 1-page summary for SIH evaluators
│
├── aether-backend/                     # FastAPI Python Backend
│   ├── .env.example                    # Backend environment template
│   ├── .gitignore                      # Python specific gitignore rules
│   ├── Dockerfile                      # Container definition for FastAPI backend
│   ├── migrate_db.py                   # Automated database schema migration script
│   ├── README.md                       # Backend technical documentation & API spec
│   ├── requirements.txt                # Pinned production Python dependencies
│   ├── requirements-dev.txt            # Development & testing dependencies (pytest, httpx)
│   │
│   ├── app/                            # Application Core Package
│   │   ├── __init__.py                 # Package initializer
│   │   ├── db.py                       # SQLAlchemy engine & session manager (SQLite/Postgres)
│   │   ├── main.py                     # FastAPI application factory, middlewares & life-cycle
│   │   ├── models.py                   # Database models (Case, EvidenceRecord, CustodyRow, AuditLog)
│   │   ├── schemas.py                  # Pydantic v2 schemas for request/response serialization
│   │   ├── security.py                 # SSRF mitigation, rate limiter, API key auth, security headers
│   │   │
│   │   ├── routers/                    # API Route Handlers
│   │   │   ├── __init__.py
│   │   │   ├── analysis.py             # Endpoints for stylometry, diurnal, graph, BTC clustering
│   │   │   ├── cases.py                # CRUD for cases, custody append, verification, full investigation
│   │   │   └── export.py               # STIX 2.1 JSON and forensic CSV export endpoints
│   │   │
│   │   └── services/                   # Business Logic & Forensic Engines
│   │       ├── __init__.py
│   │       ├── custody.py              # SHA-256 chain of custody with Genesis seal verification
│   │       ├── diurnal.py              # Circadian sleep-trough detection & UTC timezone inference
│   │       ├── export.py               # OASIS STIX 2.1 bundle assembler & CSV generator
│   │       ├── graph.py                # Threat actor entity-relationship graph & Neo4j Cypher generator
│   │       ├── intel.py                # OSINT collectors (Favicon mmh3, JARM, Shodan, Censys)
│   │       ├── investigation.py        # Master pipeline orchestrating all 9 forensic modules
│   │       ├── scoring.py              # $C_{attr}$ calibrated confidence score engine
│   │       └── stylometry.py           # NLP character/word n-gram vectorizer & cosine similarity
│   │
│   ├── scripts/                        # Utility & Automation Scripts
│   │   └── smoke_test.sh               # Bash test hitting live endpoints and testing outputs
│   │
│   └── tests/                          # Automated Pytest Suite (74 tests)
│       ├── __init__.py
│       ├── conftest.py                 # Shared fixtures (in-memory SQLite client, test auth headers)
│       ├── test_analysis.py            # Unit tests for stylometry, diurnal, graph & BTC clustering
│       ├── test_api.py                 # HTTP tests for case CRUD & database level tampering checks
│       ├── test_custody.py             # Integrity tests for hash chain, deletion & modification detection
│       ├── test_export.py              # Validates STIX 2.1 parser compliance & CSV formula sanitization
│       ├── test_investigation.py       # Full end-to-end investigation pipeline integration tests
│       └── test_security.py            # Rigorous security tests (SSRF, Rate Limiting, Headers, Auth)
│
└── aether-frontend/                    # Next.js 16 + React 19 Frontend
    ├── package.json                    # Node.js dependencies and scripts (dev, build, start, lint)
    ├── package-lock.json               # Locked dependency tree
    ├── tsconfig.json                   # TypeScript configuration
    ├── next.config.ts                  # Next.js build settings & compiler options
    ├── postcss.config.mjs              # PostCSS plugin configurations
    ├── eslint.config.mjs               # ESLint code style rules
    ├── README.md                       # Frontend quickstart guide
    ├── AGENTS.md                       # Developer & AI agent workflow instructions
    ├── CLAUDE.md                       # Guidance notes for autonomous assistants
    │
    ├── public/                         # Static assets (favicons, SVG icons, badges)
    │
    └── src/                            # Frontend Source Code
        ├── app/                        # Next.js App Router Structure
        │   ├── globals.css             # Industrial dark steel CSS variables & resets
        │   ├── layout.tsx              # Root HTML wrapper, metadata & font providers
        │   └── page.tsx                # Main dashboard page assembling Bento Grid and modals
        │
        ├── components/                 # Reusable React UI Components
        │   ├── BentoGrid.tsx           # Primary forensic monitoring telemetry & overview cards
        │   ├── CustodyLedgerView.tsx   # Interactive SHA-256 custody ledger & Section 63 BSA 2023 (formerly s.65B IEA) validator
        │   ├── DossierModal.tsx        # High-level threat intelligence executive brief
        │   ├── EngineConfigModal.tsx   # Investigator settings (Shodan/Censys keys, proxy config)
        │   ├── EvidenceModal.tsx       # Drill-down viewer for specific forensic artifacts
        │   ├── Header.tsx              # System navigation, active case indicator, export triggers
        │   ├── KnowledgeGraphView.tsx  # Three.js 3D entity relationship graph viewer
        │   ├── NewInvestigationModal.tsx# Wizard for creating a new dark web threat investigation
        │   ├── Sidebar.tsx             # Stage navigation (Recon -> Correlation -> Attribution)
        │   ├── StylometryLabModal.tsx  # Interactive forum text linguistic comparison lab
        │   └── Toast.tsx               # Non-intrusive security alerts and notification banners
        │
        └── lib/                        # Client-side Utilities
            └── api.ts                  # Typed API bridge connecting UI to FastAPI with mock fallbacks
```

---

## 5. System Architecture & Data Flow

```mermaid
sequenceDiagram
    autonumber
    actor Investigator as Law Enforcement Investigator
    participant UI as Next.js 16 Web Dashboard
    participant API as FastAPI Gateway (:8000)
    participant SEC as Security Middlewares (SSRF / RateLimit / Headers)
    participant ORCH as Investigation Pipeline (investigation.py)
    participant INTEL as OSINT & Analysis Engines (Stylometry/Diurnal/BTC)
    participant CHAIN as SHA-256 Custody Ledger
    participant DB as SQLite / PostgreSQL Database
    participant EXPORT as STIX 2.1 & CSV Exporters

    Investigator->>UI: Submit Target (e.g., Dread Market .onion)
    UI->>API: POST /api/cases/investigate
    API->>SEC: Validate Request (SSRF Check, Payload Size, Auth Key)
    SEC-->>API: Authorized & Safe
    API->>ORCH: Trigger Full Investigation

    par Reconnaissance & Analysis
        ORCH->>INTEL: Favicon mmh3 + JARM Hash -> Clearnet IP
        ORCH->>INTEL: NLP Stylometry Cosine Similarity
        ORCH->>INTEL: Circadian Sleep-Trough Timezone Engine
        ORCH->>INTEL: Multi-Input Bitcoin Peel-Chain Clustering
    end

    INTEL-->>ORCH: Consolidated Forensic Telemetry
    ORCH->>ORCH: Compute Calibrated Confidence Score ($C_{attr}$)
    
    ORCH->>CHAIN: Append Sequence Entries to SHA-256 Chain
    CHAIN-->>ORCH: Digital Seal ($H_{final}$)
    
    ORCH->>DB: Persist Case, EvidenceRecords, & CustodyRows
    DB-->>ORCH: Saved (Commit)
    
    ORCH-->>API: InvestigationResultOut
    API-->>UI: Complete Dossier, 3D Graph, & Ledger
    UI-->>Investigator: Interactive Visual Dashboard Display

    opt Court & SOC Exports
        Investigator->>UI: Click "Export STIX 2.1" or "Export CSV"
        UI->>API: GET /api/cases/{id}/export/{stix|csv}
        API->>EXPORT: Generate Spec-Compliant Package
        EXPORT-->>UI: Downloadable Bundle
    end
```

---

## 6. Comprehensive API Reference

All endpoints are hosted at `http://localhost:8000`. Full OpenAPI Interactive Swagger documentation is available at `http://localhost:8000/docs`.

### 6.1 Authentication
Include the investigator credentials in all requests:
- Header: `X-AETHER-KEY: aether-investigator-dev-key-2026`
- Or: `Authorization: Bearer aether-investigator-dev-key-2026`

### 6.2 Primary Endpoints

| Category | Method | Endpoint | Description |
|---|---|---|---|
| **System** | `GET` | `/` | Service identification & Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872) compliance statement |
| **System** | `GET` | `/api/health` | Liveness and health check endpoint |
| **Investigation**| `POST` | `/api/cases/investigate` | **Primary Entrypoint**: Ingests target and runs all 9 forensic modules |
| **Cases** | `GET` | `/api/cases` | Lists all active and historical forensic cases |
| **Cases** | `POST` | `/api/cases` | Manually creates an empty case record |
| **Cases** | `GET` | `/api/cases/{evidence_id}` | Retrieves case details and full custody ledger |
| **Cases** | `GET` | `/api/cases/{evidence_id}/investigation` | Retrieves detailed multi-module analysis results |
| **Custody** | `POST` | `/api/cases/{evidence_id}/custody` | Appends a manual action or evidence acquisition to custody chain |
| **Custody** | `GET` | `/api/cases/{evidence_id}/verify` | Cryptographically recalculates SHA-256 chain from Genesis; detects tampering |
| **Custody** | `GET` | `/api/custody/verify` | Alias to verify the active demonstration case |
| **Audit** | `GET` | `/api/audit-logs` | Retrieves immutable audit log entries for judicial review |
| **Analysis** | `POST` | `/api/analysis/stylometry` | Compares two text samples via character/word n-gram cosine similarity |
| **Analysis** | `POST` | `/api/analysis/diurnal` | Computes circadian sleep trough and inferred UTC timezone from timestamps |
| **Analysis** | `POST` | `/api/analysis/graph` | Generates node-link graph data and Neo4j Cypher statements |
| **Analysis** | `POST` | `/api/analysis/btc-cluster` | Computes Bitcoin multi-input peel-chain wallet clustering |
| **Analysis** | `POST` | `/api/analysis/score` | Calculates calibrated confidence score ($C_{attr}$) with penalty checks |
| **Export** | `GET` | `/api/cases/{evidence_id}/export/stix` | Exports spec-validated OASIS STIX 2.1 Threat Intelligence Bundle (JSON) |
| **Export** | `GET` | `/api/cases/{evidence_id}/export/csv` | Exports RFC 4180 forensic evidence spreadsheet with anti-formula injection |

---

## 7. Installation, Setup & Running Instructions

### 7.1 Prerequisites
- **Node.js**: `v20+` or `v24+`
- **Python**: `3.11+`, `3.12+`, or `3.13+`
- **Git** installed
- Optional: **Docker & Docker Compose**

---

### 7.2 Backend Setup (Python / FastAPI)

1. Navigate to the backend directory:
   ```bash
   cd aether-backend
   ```

2. Create and activate a Python virtual environment:
   - **Windows (PowerShell)**:
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS (Bash)**:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. Install all dependencies:
   ```bash
   pip install --upgrade pip
   pip install -r requirements-dev.txt
   ```

4. Initialize/migrate the SQLite development database:
   ```bash
   python migrate_db.py
   ```

5. Run the automated test suite (verifying 74 tests pass):
   ```bash
   pytest -q
   ```

6. Start the FastAPI development server:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
   *The API will be live on `http://127.0.0.1:8000` with Swagger docs at `http://127.0.0.1:8000/docs`.*

---

### 7.3 Frontend Setup (Next.js 16 + Tailwind CSS)

1. Open a new terminal and navigate to the frontend directory:
   ```bash
   cd aether-frontend
   ```

2. Install Node dependencies:
   ```bash
   npm install
   ```

3. (Optional) Run production build check:
   ```bash
   npm run build
   ```

4. Start the Next.js development server:
   ```bash
   npm run dev
   ```
   *The web application will be live at `http://localhost:3000`.*

---

### 7.4 Running via Docker Compose (Full Stack)

To run the entire system with PostgreSQL:
```bash
docker compose up --build
```
- Web Application: `http://localhost:3000`
- API Backend: `http://localhost:8000`
- PostgreSQL Port: `5432`

---

## 8. Evidentiary Standards & Legal Compliance

### Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872)
Under Indian jurisprudence, electronic records are only admissible if accompanied by a certificate establishing:
1. **Device Integrity**: The computer output was produced during the period over which the computer was used regularly to store or process information.
2. **Operational Continuity**: Throughout the material part of said period, the computer was operating properly.
3. **Chain of Custody**: Cryptographic certainty that evidence was not tampered with, altered, or replaced from the moment of acquisition to trial submission.

**How AETHER Guarantees Admissibility:**
- **Zero In-Place Edits**: Custody records are strictly append-only.
- **Hash Linkage**: Any database tampering breaks the SHA-256 chain verification immediately.
- **Audit Trails**: All operator actions are logged with authenticated principal identity, client IP, action type, and UTC timestamps.
- **Evidentiary Caveats**: Probabilistic AI outputs (stylometry and circadian analysis) are explicitly demarcated as investigative leads rather than singular proof of identity, preventing legal dismissal during trial cross-examination.
