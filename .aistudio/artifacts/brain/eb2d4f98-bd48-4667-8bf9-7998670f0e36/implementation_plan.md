# CyberPilot — SOC Threat Intelligence & Diagnostic Engine

An authoritative, mission-critical threat intelligence platform and diagnostic engine engineered for SOC tier analysts, incident responders, and security researchers.

> [!IMPORTANT]
> **Confirmed Specifications & Choices**:
> - **Primary Workspace View**: Live Threat Investigation and IOC Lookup Console (instant hash, IP, domain, and CVE analysis with multi-engine heuristic scoring).
> - **Core Highlighted Capability**: Multi-engine IOC analysis engine with granular vendor detection breakdowns, behavioral indicators, and reputation scoring.
> - **Language & Terminology**: English with standard cybersecurity / SOC taxonomy (MITRE ATT&CK, YARA, CVE, STIX 2.1).

---

### 1. Overview & Core Concept
- **What It Does**: CyberPilot provides instant, high-density triage of malicious indicators of compromise (IOCs)—including SHA256/MD5 hashes, IPv4/IPv6 addresses, fully-qualified domain names (FQDNs), and CVE vulnerability IDs. It features interactive multi-engine detection simulations, behavioral sandboxing reports, live threat feed triage, an interactive hex/payload viewer with YARA pattern matching, and STIX 2.1 / JSON export capabilities.
- **Target Audience / Persona**: Tier 1-3 SOC Analysts, Threat Hunters, Malware Researchers, and Incident Response Leads requiring swift triage with zero cognitive friction.
- **Key Value**: Low-latency, keyboard-friendly triage with 1-click clipboard copying, granular engine breakdowns, and high-density technical telemetry.

---

### 2. User Experience & Visual Design
- **Color System & Surface Hierarchy**:
  - `Canvas Base`: `#051424` / `#0B1020` (Dark void foundation)
  - `Surface Primary`: `#111827` (Card panels and analytical views)
  - `Surface Secondary`: `#172033` (Sidebar, sub-containers, active row hover)
  - `Structural Border`: `#293548` (Crisp 1px delineation lines)
  - `Accents`: Primary Sky Blue `#38BDF8`, Technical Teal `#2DD4BF`
  - `Semantic Verdicts`: Malicious (`#F87171`), Suspicious (`#FBBF24`), Clean (`#34D399`), Info/Processing (`#60A5FA`)
- **Typography & Font Pairing**:
  - `Plus Jakarta Sans / Inter`: For crisp structural UI, column headers, and navigational rails.
  - `JetBrains Mono`: For SHA256 hashes, IP ranges, CVE IDs, YARA rules, hex dumps, and all numerical metrics with `tabular-nums`.
- **Layout Architecture**:
  - **Global Header (64px)**: Unified IOC quick-search bar with prefix auto-detection (detects MD5, SHA256, IPv4, Domain, or CVE), active tenant switcher (`Global SOC - US-East`), real-time threat alert counter, and manual sample ingest trigger.
  - **Lateral Rail (240px desktop, collapsible)**: Navigation across `Live Investigation`, `IOC Registry & Feed`, `Sandbox & Hex Viewer`, `YARA & Sigma Rules`, and `Incident Triage`.
  - **High-Density Data Grid & Inspectors**: 36-40px compact table rows with hover actions, copy-to-clipboard inline buttons, and expandable side drawers for deep forensic breakdown.

---

### 3. Key Product Decisions & Trade-Offs
- **Decision 1: Client-Side Interactive Diagnostic Engine**:
  - *Chosen Approach*: Comprehensive local diagnostic engine pre-populated with realistic malware samples (e.g. Cobalt Strike Beacon, LockBit 3.0 loader, Emotet staging script, Lumma Stealer payload, Clean DNS resolver, Suspicious C2 IP) with dynamic custom input analysis that computes simulated entropy, engine detections, and heuristic tags in real time.
  - *Why*: Provides instant response (<50ms) without requiring live external API rate limits or exposing analyst data.
- **Decision 2: Integrated Hex & Disassembly Payload Inspector**:
  - *Chosen Approach*: Real interactive hexadecimal viewer with offset addresses, byte columns, ASCII interpretation, string extraction, and live YARA rule execution against loaded buffers.
  - *Why*: Delivers authentic reverse engineering utility matching the design specification.
- **Decision 3: Zero-Pill Typography & Hardware-Grade Verdict Badges**:
  - *Chosen Approach*: Strict compliance with anti-slop guidelines: unboxed quiet metadata for categories/timestamps, combined SVG status icon + uppercase monospace text badges for threat verdicts.

---

### 4. Technical Architecture & Data Strategy

```
┌────────────────────────────────────────────────────────────────────────┐
│                          CYBERPILOT SHELL                              │
├────────────────────────────────┬───────────────────────────────────────┤
│          HEADER (64px)         │ Unified Search Bar (Hash/IP/Domain)   │
│                                │ Tenant Select · Quick Detonate Modal │
├────────────────────────────────┴───────────────────────────────────────┤
│  SIDEBAR (240px)   │                   MAIN WORKSPACE                  │
│  ───────────────   │  ──────────────────────────────────────────────── │
│  [1] Investigation │  • Metric Cards: Total Triage, Malicious, Engines │
│  [2] IOC Registry  │  • Active Target Banner with Heuristic Score Bar  │
│  [3] Hex / Sandbox │  • Multi-Engine Scan Matrix (68 Antivirus Engines)│
│  [4] YARA Matcher  │  • Behavioral Sandbox Telemetry & MITRE ATT&CK    │
│  [5] Incident Feed │  • Interactive Raw Hex Dump & String Extractor    │
│                    │  • Export Drawer: STIX 2.1 & JSON Forensics Dump │
└────────────────────┴───────────────────────────────────────────────────┘
```

- **Core Views & Modules**:
  1. **Live Investigation View**: Primary IOC investigation console with detection gauges (e.g. 58/68 engines flagged), risk severity indicator, vendor engine breakdown (CrowdStrike, Defender, SentinelOne, Kaspersky, VirusTotal-style matrix), network contacts, and MITRE ATT&CK tactic tags.
  2. **IOC Registry & Live Feed**: High-density searchable IOC table with filtering by type (Hash, IP, Domain, URL), verdict chips, first/last seen timestamps, and one-click bulk export.
  3. **Hex & Payload Inspector**: Interactive binary viewer with byte offset addressing, hex representation, ASCII panel, search string finder, and entropy graph.
  4. **YARA & Rule Workbench**: Interactive rule editor with syntax validation, test payload injection, and instant pattern matching matches.
  5. **Incident Triage Queue**: SOC analyst queue with alert prioritization, assigned severity, containment trigger actions, and analyst notes.
- **Data Export**: Complete STIX 2.1 bundle generator and structured JSON report downloader.
