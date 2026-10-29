/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { ThreatIoc, ThreatVerdict } from '../types/threat';
import { VerdictBadge } from './VerdictBadge';
import { 
  Copy, 
  Check, 
  ShieldAlert, 
  Download, 
  RefreshCw, 
  ShieldCheck, 
  ShieldX, 
  Globe, 
  FileText, 
  Hash, 
  AlertTriangle, 
  Network, 
  Terminal, 
  Filter, 
  ExternalLink,
  Cpu
} from 'lucide-react';

interface InvestigationViewProps {
  ioc: ThreatIoc;
  onSelectRelatedIoc?: (iocValue: string) => void;
  onAddToBlocklist: (iocValue: string) => void;
  isBlocklisted: boolean;
  onRescan: (iocValue: string) => void;
}

export const InvestigationView: React.FC<InvestigationViewProps> = ({
  ioc,
  onSelectRelatedIoc,
  onAddToBlocklist,
  isBlocklisted,
  onRescan
}) => {
  const [copiedValue, setCopiedValue] = useState<string | null>(null);
  const [engineFilter, setEngineFilter] = useState<'all' | 'flagged' | 'clean'>('all');
  const [engineSearch, setEngineSearch] = useState('');
  const [activeTab, setActiveTab] = useState<'engines' | 'behavior' | 'mitre' | 'raw'>('engines');
  const [isRescanning, setIsRescanning] = useState(false);
  const [showStixModal, setShowStixModal] = useState(false);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedValue(label);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  const handleTriggerRescan = () => {
    setIsRescanning(true);
    setTimeout(() => {
      onRescan(ioc.value);
      setIsRescanning(false);
    }, 1200);
  };

  // Filter vendor detections
  const filteredEngines = ioc.vendorDetections.filter((engine) => {
    const matchesSearch = engine.engineName.toLowerCase().includes(engineSearch.toLowerCase()) ||
                          engine.signature.toLowerCase().includes(engineSearch.toLowerCase());
    if (!matchesSearch) return false;
    if (engineFilter === 'flagged') return engine.category === 'malicious' || engine.category === 'suspicious';
    if (engineFilter === 'clean') return engine.category === 'clean' || engine.category === 'undetected';
    return true;
  });

  const flaggedCount = ioc.vendorDetections.filter(e => e.category === 'malicious' || e.category === 'suspicious').length;
  const cleanCount = ioc.vendorDetections.length - flaggedCount;

  // Generate STIX 2.1 payload
  const stixBundle = {
    type: "bundle",
    id: `bundle--${Math.random().toString(36).substring(2, 12)}`,
    spec_version: "2.1",
    objects: [
      {
        type: "indicator",
        spec_version: "2.1",
        id: `indicator--${ioc.id}`,
        created: new Date().toISOString(),
        modified: new Date().toISOString(),
        name: ioc.threatName,
        description: ioc.reputationSummary,
        indicator_types: [ioc.category],
        pattern: `[${ioc.type}:value = '${ioc.value}']`,
        pattern_type: "stix",
        valid_from: new Date().toISOString(),
        confidence: ioc.threatScore,
        labels: ioc.tags
      }
    ]
  };

  const downloadStixJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(stixBundle, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `cyberpilot_stix_${ioc.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-4">
      {/* Target Investigation Banner */}
      <div className="bg-[#111827] border border-[#293548] rounded-xl p-4 md:p-5 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-2 flex-1 min-w-0">
            {/* Meta Tags Strip */}
            <div className="flex flex-wrap items-center gap-2 text-xs text-[#94a3b8]">
              <span className="font-mono font-bold px-2 py-0.5 rounded bg-[#172033] border border-[#293548] text-[#38bdf8] uppercase">
                {ioc.type}
              </span>
              <span>·</span>
              <span className="text-[#f1f5f9] font-medium">{ioc.category}</span>
              <span>·</span>
              <span>First Seen: <span className="text-[#f1f5f9] font-mono tabular-nums">{ioc.firstSeen}</span></span>
              <span>·</span>
              <span>Last Active: <span className="text-[#f1f5f9] font-mono tabular-nums">{ioc.lastActive}</span></span>
            </div>

            {/* Indicator Hash / Value with 1-click copy */}
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="font-mono text-base md:text-xl font-bold text-[#f1f5f9] break-all tracking-tight">
                {ioc.value}
              </h1>
              <button
                onClick={() => copyToClipboard(ioc.value, 'ioc')}
                title="Copy Indicator"
                className="p-1.5 rounded-lg bg-[#172033] hover:bg-[#1e293b] border border-[#293548] text-[#94a3b8] hover:text-[#38bdf8] transition-colors shrink-0"
              >
                {copiedValue === 'ioc' ? <Check className="w-3.5 h-3.5 text-[#34d399]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>

            {/* Reputation Description */}
            <p className="text-xs md:text-sm text-[#94a3b8] max-w-4xl leading-relaxed">
              {ioc.reputationSummary}
            </p>

            {/* Threat Tags */}
            <div className="flex flex-wrap gap-1.5 pt-1">
              {ioc.tags.map((t) => (
                <span
                  key={t}
                  className="font-mono text-[11px] px-2 py-0.5 rounded bg-[#0b1020] border border-[#293548] text-[#94a3b8]"
                >
                  #{t}
                </span>
              ))}
            </div>
          </div>

          {/* Right Metrics Strip & Verdict Gauge */}
          <div className="flex items-center lg:flex-col lg:items-end justify-between gap-4 shrink-0 pt-3 lg:pt-0 border-t lg:border-t-0 border-[#293548]">
            <div className="space-y-1.5 text-right">
              <div className="flex items-center gap-2">
                <VerdictBadge 
                  verdict={ioc.verdict} 
                  flaggedRatio={ioc.detectionRatio}
                  size="lg"
                />
              </div>

              {/* Threat Score Bar */}
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-[#94a3b8] font-mono uppercase">Threat Score:</span>
                <span className={`font-mono text-sm font-bold tabular-nums ${
                  ioc.threatScore >= 70 ? 'text-[#f87171]' : ioc.threatScore >= 30 ? 'text-[#fbbf24]' : 'text-[#34d399]'
                }`}>
                  {ioc.threatScore}/100
                </span>
              </div>
              <div className="w-36 h-2 bg-[#0b1020] rounded-full border border-[#293548] overflow-hidden ml-auto">
                <div 
                  className={`h-full transition-all duration-500 ${
                    ioc.threatScore >= 70 ? 'bg-[#f87171]' : ioc.threatScore >= 30 ? 'bg-[#fbbf24]' : 'bg-[#34d399]'
                  }`}
                  style={{ width: `${ioc.threatScore}%` }}
                />
              </div>
            </div>

            {/* Quick Action Buttons */}
            <div className="flex items-center gap-2">
              <button
                onClick={handleTriggerRescan}
                disabled={isRescanning}
                className="h-8 px-2.5 bg-[#172033] hover:bg-[#1e293b] text-[#f1f5f9] text-xs font-medium rounded-lg border border-[#293548] flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 text-[#38bdf8] ${isRescanning ? 'animate-spin' : ''}`} />
                <span>{isRescanning ? 'Scanning...' : 'Re-scan'}</span>
              </button>

              <button
                onClick={() => setShowStixModal(true)}
                className="h-8 px-2.5 bg-[#172033] hover:bg-[#1e293b] text-[#f1f5f9] text-xs font-medium rounded-lg border border-[#293548] flex items-center gap-1.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-[#2dd4bf]" />
                <span>Export STIX</span>
              </button>

              <button
                onClick={() => onAddToBlocklist(ioc.value)}
                className={`h-8 px-2.5 text-xs font-semibold rounded-lg border flex items-center gap-1.5 transition-colors ${
                  isBlocklisted 
                    ? 'bg-[#34d399]/15 text-[#34d399] border-[#34d399]/40' 
                    : 'bg-[#f87171]/15 text-[#f87171] border-[#f87171]/40 hover:bg-[#f87171]/25'
                }`}
              >
                {isBlocklisted ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldX className="w-3.5 h-3.5" />}
                <span>{isBlocklisted ? 'Blocklisted' : 'Blocklist'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Analytical Detail Tabs */}
      <div className="bg-[#111827] border border-[#293548] rounded-xl overflow-hidden">
        {/* Tab Header Strip */}
        <div className="h-12 px-4 border-b border-[#293548] flex items-center justify-between gap-4 bg-[#111827]">
          <div className="flex items-center gap-1">
            <button
              onClick={() => setActiveTab('engines')}
              className={`h-8 px-3 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'engines' 
                  ? 'bg-[#172033] text-[#38bdf8] border border-[#38bdf8]/40 shadow-xs' 
                  : 'text-[#94a3b8] hover:text-[#f1f5f9]'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>Engine Matrix ({ioc.detectionRatio.flagged}/{ioc.detectionRatio.total})</span>
            </button>

            <button
              onClick={() => setActiveTab('behavior')}
              className={`h-8 px-3 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'behavior' 
                  ? 'bg-[#172033] text-[#38bdf8] border border-[#38bdf8]/40 shadow-xs' 
                  : 'text-[#94a3b8] hover:text-[#f1f5f9]'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Sandbox Activity ({ioc.behavioralEvents.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('mitre')}
              className={`h-8 px-3 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'mitre' 
                  ? 'bg-[#172033] text-[#38bdf8] border border-[#38bdf8]/40 shadow-xs' 
                  : 'text-[#94a3b8] hover:text-[#f1f5f9]'
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              <span>MITRE ATT&CK ({ioc.mitreTactics.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('raw')}
              className={`h-8 px-3 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'raw' 
                  ? 'bg-[#172033] text-[#38bdf8] border border-[#38bdf8]/40 shadow-xs' 
                  : 'text-[#94a3b8] hover:text-[#f1f5f9]'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Technical Attributes</span>
            </button>
          </div>
        </div>

        {/* Tab Content Body */}
        <div className="p-4">
          {/* TAB 1: Engine Detection Matrix */}
          {activeTab === 'engines' && (
            <div className="space-y-4">
              {/* Matrix Filter Sub-bar */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0b1020] p-2.5 rounded-lg border border-[#293548]">
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => setEngineFilter('all')}
                    className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                      engineFilter === 'all' 
                        ? 'bg-[#172033] text-[#f1f5f9] border border-[#293548]' 
                        : 'text-[#94a3b8] hover:text-[#f1f5f9]'
                    }`}
                  >
                    All Vendors ({ioc.vendorDetections.length})
                  </button>

                  <button
                    onClick={() => setEngineFilter('flagged')}
                    className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                      engineFilter === 'flagged' 
                        ? 'bg-[#f87171]/20 text-[#f87171] border border-[#f87171]/40' 
                        : 'text-[#94a3b8] hover:text-[#f87171]'
                    }`}
                  >
                    Flagged ({flaggedCount})
                  </button>

                  <button
                    onClick={() => setEngineFilter('clean')}
                    className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                      engineFilter === 'clean' 
                        ? 'bg-[#34d399]/20 text-[#34d399] border border-[#34d399]/40' 
                        : 'text-[#94a3b8] hover:text-[#34d399]'
                    }`}
                  >
                    Clean ({cleanCount})
                  </button>
                </div>

                <div className="relative w-full sm:w-64">
                  <input
                    type="text"
                    value={engineSearch}
                    onChange={(e) => setEngineSearch(e.target.value)}
                    placeholder="Filter vendor or signature..."
                    className="w-full h-8 pl-7 pr-3 bg-[#111827] border border-[#293548] rounded-md text-xs text-[#f1f5f9] placeholder-[#94a3b8]/60 focus:outline-none focus:border-[#38bdf8]"
                  />
                  <Filter className="w-3.5 h-3.5 text-[#94a3b8] absolute left-2 top-2.5 pointer-events-none" />
                </div>
              </div>

              {/* High-Density Engine Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-2">
                {filteredEngines.map((engine, idx) => {
                  const isFlagged = engine.category === 'malicious' || engine.category === 'suspicious';
                  return (
                    <div
                      key={idx}
                      className={`p-2.5 rounded-lg border flex flex-col justify-between transition-colors ${
                        isFlagged 
                          ? 'bg-[#172033]/80 border-[#f87171]/30 hover:border-[#f87171]/60' 
                          : 'bg-[#0b1020]/70 border-[#293548] hover:border-[#3e484f]'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-semibold text-[#f1f5f9] truncate">
                          {engine.engineName}
                        </span>
                        <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                          isFlagged 
                            ? 'bg-[#f87171]/15 text-[#f87171] border border-[#f87171]/40' 
                            : 'bg-[#34d399]/10 text-[#34d399] border border-[#34d399]/20'
                        }`}>
                          {isFlagged ? 'DETECTED' : 'CLEAN'}
                        </span>
                      </div>

                      <div className="mt-1.5 font-mono text-[11px] truncate text-[#94a3b8]">
                        {engine.signature}
                      </div>

                      <div className="mt-1 text-[10px] text-[#94a3b8]/60 flex items-center justify-between font-mono">
                        <span>{engine.engineVersion}</span>
                        <span>{engine.updateTimestamp}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB 2: Sandbox Behavioral Activity */}
          {activeTab === 'behavior' && (
            <div className="space-y-3">
              <div className="text-xs text-[#94a3b8]">
                Heuristic behavioral telemetry captured in isolated sandbox hypervisor during 180-second execution window:
              </div>

              <div className="divide-y divide-[#293548] border border-[#293548] rounded-lg overflow-hidden bg-[#0b1020]">
                {ioc.behavioralEvents.map((event, idx) => (
                  <div key={idx} className="p-3 flex items-start gap-3 hover:bg-[#172033]/40 transition-colors">
                    <span className={`font-mono text-[10px] uppercase font-bold px-2 py-0.5 rounded border shrink-0 mt-0.5 ${
                      event.severity === 'critical' ? 'bg-[#f87171]/15 text-[#f87171] border-[#f87171]/40' :
                      event.severity === 'high' ? 'bg-[#fbbf24]/15 text-[#fbbf24] border-[#fbbf24]/40' :
                      'bg-[#60a5fa]/15 text-[#60a5fa] border-[#60a5fa]/40'
                    }`}>
                      {event.category}
                    </span>

                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold text-[#f1f5f9] flex items-center gap-2">
                        <span>{event.action}</span>
                        <span className="text-[10px] font-mono text-[#94a3b8] tabular-nums">({event.timestamp})</span>
                      </div>
                      <div className="font-mono text-xs text-[#38bdf8] break-all mt-0.5 bg-[#111827] p-1.5 rounded border border-[#293548]">
                        {event.target}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 3: MITRE ATT&CK Matrix */}
          {activeTab === 'mitre' && (
            <div className="space-y-3">
              <div className="text-xs text-[#94a3b8]">
                Observed Tactics, Techniques, and Procedures (TTPs) mapped against the MITRE ATT&CK Enterprise Matrix:
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {ioc.mitreTactics.map((ttp) => (
                  <div key={ttp.id} className="p-3 rounded-lg bg-[#0b1020] border border-[#293548] space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-[#38bdf8] bg-[#38bdf8]/10 px-2 py-0.5 rounded border border-[#38bdf8]/30">
                        {ttp.id}
                      </span>
                      <span className="text-[11px] text-[#94a3b8] uppercase font-mono font-medium">
                        {ttp.tactic}
                      </span>
                    </div>

                    <div className="text-xs font-semibold text-[#f1f5f9]">
                      {ttp.name}
                    </div>

                    <p className="text-[11px] text-[#94a3b8] leading-normal">
                      {ttp.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: Technical Attributes & Hash Manifest */}
          {activeTab === 'raw' && (
            <div className="space-y-4 font-mono text-xs">
              <div className="bg-[#0b1020] p-4 rounded-lg border border-[#293548] space-y-2">
                <div className="text-[11px] uppercase tracking-wider font-bold text-[#94a3b8] pb-1 border-b border-[#293548]">
                  CRYPTOGRAPHIC CHECKSUMS & ARTIFACT METRICS
                </div>

                {ioc.sha256 && (
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 py-1 border-b border-[#293548]/40">
                    <span className="text-[#94a3b8]">SHA-256:</span>
                    <span className="text-[#f1f5f9] select-all break-all">{ioc.sha256}</span>
                  </div>
                )}

                {ioc.md5 && (
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 py-1 border-b border-[#293548]/40">
                    <span className="text-[#94a3b8]">MD-5:</span>
                    <span className="text-[#f1f5f9] select-all break-all">{ioc.md5}</span>
                  </div>
                )}

                {ioc.ssdeep && (
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 py-1 border-b border-[#293548]/40">
                    <span className="text-[#94a3b8]">SSDEEP:</span>
                    <span className="text-[#f1f5f9] select-all break-all">{ioc.ssdeep}</span>
                  </div>
                )}

                {ioc.entropy !== undefined && (
                  <div className="flex items-center justify-between py-1 border-b border-[#293548]/40">
                    <span className="text-[#94a3b8]">Shannon Entropy:</span>
                    <span className="text-[#f1f5f9] font-bold">{ioc.entropy} (High packing threshold: 7.0)</span>
                  </div>
                )}

                {ioc.fileSize && (
                  <div className="flex items-center justify-between py-1 border-b border-[#293548]/40">
                    <span className="text-[#94a3b8]">Calculated File Size:</span>
                    <span className="text-[#f1f5f9]">{ioc.fileSize}</span>
                  </div>
                )}

                {ioc.asn && (
                  <div className="flex items-center justify-between py-1 border-b border-[#293548]/40">
                    <span className="text-[#94a3b8]">Autonomous System:</span>
                    <span className="text-[#f1f5f9]">{ioc.asn}</span>
                  </div>
                )}

                {ioc.country && (
                  <div className="flex items-center justify-between py-1">
                    <span className="text-[#94a3b8]">Geographical Location:</span>
                    <span className="text-[#f1f5f9]">{ioc.country}</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* STIX 2.1 Export Modal */}
      {showStixModal && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-[#111827] border border-[#293548] rounded-xl max-w-2xl w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#293548] pb-3">
              <div className="flex items-center gap-2">
                <Download className="w-4 h-4 text-[#38bdf8]" />
                <h3 className="font-semibold text-sm text-[#f1f5f9]">STIX 2.1 Threat Intelligence Bundle</h3>
              </div>
              <button
                onClick={() => setShowStixModal(false)}
                className="text-[#94a3b8] hover:text-[#f1f5f9] text-sm"
              >
                ✕
              </button>
            </div>

            <div className="font-mono text-xs bg-[#0b1020] p-3 rounded-lg border border-[#293548] text-[#38bdf8] overflow-x-auto max-h-72">
              <pre>{JSON.stringify(stixBundle, null, 2)}</pre>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#293548]">
              <button
                onClick={() => copyToClipboard(JSON.stringify(stixBundle, null, 2), 'stix')}
                className="px-3 py-1.5 text-xs text-[#f1f5f9] bg-[#172033] hover:bg-[#1e293b] rounded-lg border border-[#293548] flex items-center gap-1.5 transition-colors"
              >
                {copiedValue === 'stix' ? <Check className="w-3.5 h-3.5 text-[#34d399]" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy JSON</span>
              </button>
              <button
                onClick={downloadStixJson}
                className="px-3.5 py-1.5 text-xs font-semibold text-[#0b1020] bg-[#38bdf8] hover:bg-[#7dd3fc] rounded-lg transition-colors flex items-center gap-1.5"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download .json</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Internal Activity Icon helper
function Activity(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg 
      {...props} 
      viewBox="0 0 24 24" 
      fill="none" 
      stroke="currentColor" 
      strokeWidth="2" 
      strokeLinecap="round" 
      strokeLinejoin="round"
    >
      <path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.48 12H2" />
    </svg>
  );
}
