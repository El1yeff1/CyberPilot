/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export type IocType = 'sha256' | 'md5' | 'ipv4' | 'ipv6' | 'domain' | 'cve' | 'url';

export type ThreatVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface VendorDetection {
  engineName: string;
  category: 'malicious' | 'suspicious' | 'clean' | 'undetected';
  signature: string;
  updateTimestamp: string;
  engineVersion: string;
}

export interface MitreTactic {
  id: string; // e.g. T1059.001
  name: string;
  tactic: 'Initial Access' | 'Execution' | 'Persistence' | 'Privilege Escalation' | 'Defense Evasion' | 'Credential Access' | 'Command and Control' | 'Exfiltration' | 'Lateral Movement';
  description: string;
}

export interface BehavioralEvent {
  category: 'network' | 'filesystem' | 'registry' | 'process' | 'mutex';
  action: string;
  target: string;
  severity: SeverityLevel;
  timestamp: string;
}

export interface ThreatIoc {
  id: string;
  value: string;
  type: IocType;
  verdict: ThreatVerdict;
  threatScore: number; // 0 to 100
  detectionRatio: {
    flagged: number;
    total: number;
  };
  threatName: string;
  category: string;
  firstSeen: string;
  lastActive: string;
  fileSize?: string;
  entropy?: number;
  md5?: string;
  sha1?: string;
  sha256?: string;
  ssdeep?: string;
  asn?: string;
  country?: string;
  nameservers?: string[];
  reputationSummary: string;
  vendorDetections: VendorDetection[];
  mitreTactics: MitreTactic[];
  behavioralEvents: BehavioralEvent[];
  tags: string[];
}

export interface SocIncident {
  id: string;
  title: string;
  severity: SeverityLevel;
  status: 'new' | 'investigating' | 'contained' | 'resolved' | 'false_positive';
  assignedTo: string;
  timestamp: string;
  source: string;
  affectedHost: string;
  relatedIocs: string[];
  notes: {
    author: string;
    text: string;
    time: string;
  }[];
  mitreTactic: string;
}

export interface YaraRule {
  id: string;
  name: string;
  author: string;
  description: string;
  severity: SeverityLevel;
  tags: string[];
  ruleContent: string;
  targetKeywords: string[];
}

export interface PayloadSample {
  id: string;
  name: string;
  type: string;
  size: number;
  entropy: number;
  hexBytes: string[];
  rawText: string;
  extractedStrings: string[];
  description: string;
}
