/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { ThreatIoc, ThreatVerdict, IocType } from '../types/threat';
import { VerdictBadge } from './VerdictBadge';
import { 
  Search, 
  Filter, 
  Copy, 
  Check, 
  ArrowUpRight, 
  Download, 
  ShieldX, 
  ShieldCheck, 
  Layers,
  Sparkles
} from 'lucide-react';

interface IocRegistryViewProps {
  iocs: ThreatIoc[];
  onSelectIoc: (ioc: ThreatIoc) => void;
  blocklist: string[];
  onToggleBlocklist: (iocValue: string) => void;
}

export const IocRegistryView: React.FC<IocRegistryViewProps> = ({
  iocs,
  onSelectIoc,
  blocklist,
  onToggleBlocklist
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<'all' | IocType>('all');
  const [verdictFilter, setVerdictFilter] = useState<'all' | ThreatVerdict>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const filteredIocs = iocs.filter((ioc) => {
    const matchesSearch = ioc.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          ioc.threatName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          ioc.tags.some(t => t.toLowerCase().includes(searchTerm.toLowerCase()));
    if (!matchesSearch) return false;
    if (typeFilter !== 'all' && ioc.type !== typeFilter) return false;
    if (verdictFilter !== 'all' && ioc.verdict !== verdictFilter) return false;
    return true;
  });

  const exportCsv = () => {
    const headers = ['Value', 'Type', 'Verdict', 'Threat Score', 'Flagged Engines', 'Total Engines', 'Category', 'First Seen'];
    const rows = filteredIocs.map(i => [
      `"${i.value}"`,
      i.type,
      i.verdict,
      i.threatScore,
      i.detectionRatio.flagged,
      i.detectionRatio.total,
      `"${i.category}"`,
      `"${i.firstSeen}"`
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `cyberpilot_ioc_registry_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  return (
    <div className="space-y-4">
      {/* Registry Header and Controls */}
      <div className="bg-[#111827] border border-[#293548] rounded-xl p-4 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-[#f1f5f9] tracking-tight">
              Indicator of Compromise (IOC) Registry
            </h2>
            <p className="text-xs text-[#94a3b8] mt-0.5">
              Authoritative threat intelligence repository indexed by multi-engine heuristics and telemetry sensors.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={exportCsv}
              className="h-8 px-3 text-xs font-medium text-[#f1f5f9] bg-[#172033] hover:bg-[#1e293b] border border-[#293548] rounded-lg transition-colors flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5 text-[#2dd4bf]" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        {/* Filter and Search Bar */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pt-2 border-t border-[#293548]">
          <div className="flex flex-wrap items-center gap-1.5">
            {/* Type Filters */}
            <div className="flex items-center gap-1 bg-[#0b1020] p-1 rounded-lg border border-[#293548]">
              <span className="text-[10px] font-mono text-[#94a3b8] px-1.5 uppercase">Type:</span>
              {(['all', 'sha256', 'ipv4', 'domain', 'cve'] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setTypeFilter(t)}
                  className={`px-2 py-0.5 text-xs font-mono rounded transition-colors ${
                    typeFilter === t 
                      ? 'bg-[#172033] text-[#38bdf8] font-bold border border-[#38bdf8]/40' 
                      : 'text-[#94a3b8] hover:text-[#f1f5f9]'
                  }`}
                >
                  {t.toUpperCase()}
                </button>
              ))}
            </div>

            {/* Verdict Filters */}
            <div className="flex items-center gap-1 bg-[#0b1020] p-1 rounded-lg border border-[#293548]">
              <span className="text-[10px] font-mono text-[#94a3b8] px-1.5 uppercase">Verdict:</span>
              {(['all', 'malicious', 'suspicious', 'clean'] as const).map((v) => (
                <button
                  key={v}
                  onClick={() => setVerdictFilter(v)}
                  className={`px-2 py-0.5 text-xs font-mono rounded transition-colors ${
                    verdictFilter === v 
                      ? 'bg-[#172033] text-[#f1f5f9] font-bold border border-[#293548]' 
                      : 'text-[#94a3b8] hover:text-[#f1f5f9]'
                  }`}
                >
                  {v.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Quick Search */}
          <div className="relative w-full lg:w-72">
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search registry hash, tag, IP..."
              className="w-full h-8 pl-8 pr-3 bg-[#0b1020] border border-[#293548] rounded-lg text-xs font-mono text-[#f1f5f9] placeholder-[#94a3b8]/60 focus:outline-none focus:border-[#38bdf8]"
            />
            <Search className="w-3.5 h-3.5 text-[#94a3b8] absolute left-2.5 top-2.5 pointer-events-none" />
          </div>
        </div>
      </div>

      {/* High-Density Data Table */}
      <div className="bg-[#111827] border border-[#293548] rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="h-10 border-b border-[#293548] bg-[#0b1020]/90 text-[11px] font-mono font-semibold uppercase text-[#94a3b8] tracking-wider">
                <th className="py-2 px-4">Indicator / Hash</th>
                <th className="py-2 px-3 w-24">Type</th>
                <th className="py-2 px-3 w-36">Verdict</th>
                <th className="py-2 px-3 w-28 text-right">Detection</th>
                <th className="py-2 px-4">Category & Threat Signature</th>
                <th className="py-2 px-3 w-36">First Seen</th>
                <th className="py-2 px-4 w-28 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#293548]">
              {filteredIocs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-xs text-[#94a3b8]">
                    No matching IOC indicators found in registry.
                  </td>
                </tr>
              ) : (
                filteredIocs.map((ioc) => {
                  const isBlocked = blocklist.includes(ioc.value);

                  return (
                    <tr
                      key={ioc.id}
                      onClick={() => onSelectIoc(ioc)}
                      className="h-11 hover:bg-[#172033] cursor-pointer transition-colors group text-xs"
                    >
                      {/* Indicator / Hash with Copy on Hover */}
                      <td className="py-2 px-4">
                        <div className="flex items-center gap-2 max-w-md">
                          <span className="font-mono text-xs text-[#f1f5f9] group-hover:text-[#38bdf8] truncate font-medium">
                            {ioc.value}
                          </span>
                          <button
                            onClick={(e) => copyToClipboard(ioc.value, ioc.id, e)}
                            title="Copy to clipboard"
                            className="opacity-0 group-hover:opacity-100 p-1 hover:bg-[#1e293b] rounded text-[#94a3b8] hover:text-[#38bdf8] transition-opacity shrink-0"
                          >
                            {copiedId === ioc.id ? <Check className="w-3 h-3 text-[#34d399]" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                      </td>

                      {/* Type */}
                      <td className="py-2 px-3">
                        <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-[#0b1020] border border-[#293548] text-[#94a3b8] uppercase">
                          {ioc.type}
                        </span>
                      </td>

                      {/* Verdict Badge */}
                      <td className="py-2 px-3">
                        <VerdictBadge verdict={ioc.verdict} size="sm" />
                      </td>

                      {/* Detection Ratio */}
                      <td className="py-2 px-3 text-right">
                        <span className={`font-mono text-xs font-bold tabular-nums ${
                          ioc.detectionRatio.flagged > 0 ? 'text-[#f87171]' : 'text-[#34d399]'
                        }`}>
                          {ioc.detectionRatio.flagged}/{ioc.detectionRatio.total}
                        </span>
                      </td>

                      {/* Threat Name & Category */}
                      <td className="py-2 px-4">
                        <div className="truncate max-w-xs">
                          <div className="font-medium text-[#f1f5f9] truncate">{ioc.threatName}</div>
                          <div className="text-[11px] text-[#94a3b8] font-mono truncate">{ioc.category}</div>
                        </div>
                      </td>

                      {/* First Seen */}
                      <td className="py-2 px-3 font-mono text-[11px] text-[#94a3b8] tabular-nums">
                        {ioc.firstSeen.split(' ')[0]}
                      </td>

                      {/* Actions */}
                      <td className="py-2 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => onSelectIoc(ioc)}
                            title="Open Investigation Console"
                            className="p-1.5 rounded-md hover:bg-[#1e293b] text-[#38bdf8] border border-[#293548] transition-colors"
                          >
                            <ArrowUpRight className="w-3.5 h-3.5" />
                          </button>

                          <button
                            onClick={() => onToggleBlocklist(ioc.value)}
                            title={isBlocked ? "Remove from Blocklist" : "Add to Blocklist"}
                            className={`p-1.5 rounded-md border transition-colors ${
                              isBlocked 
                                ? 'bg-[#34d399]/15 text-[#34d399] border-[#34d399]/40' 
                                : 'hover:bg-[#1e293b] text-[#94a3b8] hover:text-[#f87171] border-[#293548]'
                            }`}
                          >
                            {isBlocked ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldX className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Footer info bar */}
        <div className="h-9 px-4 bg-[#0b1020] border-t border-[#293548] flex items-center justify-between text-[11px] font-mono text-[#94a3b8]">
          <span>Showing {filteredIocs.length} of {iocs.length} indexed indicators</span>
          <span>Blocklist entries: {blocklist.length}</span>
        </div>
      </div>
    </div>
  );
};
