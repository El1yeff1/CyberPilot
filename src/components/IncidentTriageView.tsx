/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { SocIncident, SeverityLevel } from '../types/threat';
import { 
  AlertOctagon, 
  ShieldCheck, 
  ShieldAlert, 
  User, 
  Clock, 
  Send, 
  ExternalLink, 
  Lock, 
  Ban, 
  RotateCcw,
  CheckCircle2,
  Filter
} from 'lucide-react';

interface IncidentTriageViewProps {
  incidents: SocIncident[];
  onSelectIocValue: (iocValue: string) => void;
  onUpdateIncidentStatus: (incidentId: string, status: SocIncident['status']) => void;
  onAddIncidentNote: (incidentId: string, noteText: string) => void;
}

export const IncidentTriageView: React.FC<IncidentTriageViewProps> = ({
  incidents,
  onSelectIocValue,
  onUpdateIncidentStatus,
  onAddIncidentNote
}) => {
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(incidents[0]?.id || '');
  const [statusFilter, setStatusFilter] = useState<'all' | SocIncident['status']>('all');
  const [newNoteText, setNewNoteText] = useState('');
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  const activeIncident = incidents.find(i => i.id === selectedIncidentId) || incidents[0];

  const filteredIncidents = incidents.filter(i => {
    if (statusFilter !== 'all' && i.status !== statusFilter) return false;
    return true;
  });

  const handleAddNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (newNoteText.trim() && activeIncident) {
      onAddIncidentNote(activeIncident.id, newNoteText.trim());
      setNewNoteText('');
    }
  };

  const handleContainmentAction = (actionName: string) => {
    setActionFeedback(`Executed: ${actionName} on host ${activeIncident?.affectedHost}`);
    if (activeIncident && activeIncident.status !== 'contained') {
      onUpdateIncidentStatus(activeIncident.id, 'contained');
    }
    setTimeout(() => setActionFeedback(null), 3000);
  };

  const severityBadge = (sev: SeverityLevel) => {
    const configs = {
      critical: 'bg-[#f87171]/15 text-[#f87171] border-[#f87171]/40',
      high: 'bg-[#fbbf24]/15 text-[#fbbf24] border-[#fbbf24]/40',
      medium: 'bg-[#60a5fa]/15 text-[#60a5fa] border-[#60a5fa]/40',
      low: 'bg-[#34d399]/15 text-[#34d399] border-[#34d399]/40',
      info: 'bg-[#94a3b8]/15 text-[#94a3b8] border-[#94a3b8]/40'
    };
    return (
      <span className={`text-[10px] font-mono font-bold uppercase px-1.5 py-0.5 rounded border ${configs[sev]}`}>
        {sev}
      </span>
    );
  };

  const statusBadge = (status: SocIncident['status']) => {
    const map = {
      new: { label: 'NEW', color: 'bg-[#f87171]/20 text-[#f87171] border-[#f87171]/40' },
      investigating: { label: 'INVESTIGATING', color: 'bg-[#fbbf24]/20 text-[#fbbf24] border-[#fbbf24]/40' },
      contained: { label: 'CONTAINED', color: 'bg-[#38bdf8]/20 text-[#38bdf8] border-[#38bdf8]/40' },
      resolved: { label: 'RESOLVED', color: 'bg-[#34d399]/20 text-[#34d399] border-[#34d399]/40' },
      false_positive: { label: 'FALSE POSITIVE', color: 'bg-[#94a3b8]/20 text-[#94a3b8] border-[#94a3b8]/40' }
    };
    const s = map[status];
    return (
      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${s.color}`}>
        {s.label}
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {/* Header Strip */}
      <div className="bg-[#111827] border border-[#293548] rounded-xl p-4 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <AlertOctagon className="w-4 h-4 text-[#f87171]" />
              <h2 className="text-base font-bold text-[#f1f5f9] tracking-tight">
                Incident Response & Alert Triage Queue
              </h2>
            </div>
            <p className="text-xs text-[#94a3b8] mt-0.5">
              Priority SOC triage pipeline with live EDR host isolation, firewall synchronization, and analyst forensics timeline.
            </p>
          </div>

          {/* Status Filter Tabs */}
          <div className="flex items-center gap-1 bg-[#0b1020] p-1 rounded-lg border border-[#293548]">
            {(['all', 'new', 'investigating', 'contained', 'resolved'] as const).map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 text-xs font-mono rounded transition-colors ${
                  statusFilter === st 
                    ? 'bg-[#172033] text-[#38bdf8] font-bold border border-[#38bdf8]/40' 
                    : 'text-[#94a3b8] hover:text-[#f1f5f9]'
                }`}
              >
                {st.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Layout: Incident Queue on Left, Active Triage Card on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Incident List */}
        <div className="space-y-2 lg:col-span-1">
          {filteredIncidents.map((inc) => {
            const isSelected = selectedIncidentId === inc.id;

            return (
              <div
                key={inc.id}
                onClick={() => setSelectedIncidentId(inc.id)}
                className={`p-3 rounded-xl border cursor-pointer transition-all ${
                  isSelected 
                    ? 'bg-[#172033] border-[#38bdf8]/50 shadow-md' 
                    : 'bg-[#111827] border-[#293548] hover:border-[#3e484f]'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-bold text-[#38bdf8]">
                    {inc.id}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {severityBadge(inc.severity)}
                    {statusBadge(inc.status)}
                  </div>
                </div>

                <div className="text-xs font-semibold text-[#f1f5f9] mt-2 line-clamp-2">
                  {inc.title}
                </div>

                <div className="mt-2 pt-2 border-t border-[#293548] flex items-center justify-between text-[11px] text-[#94a3b8] font-mono">
                  <span>{inc.affectedHost.split('.')[0]}</span>
                  <span className="tabular-nums">{inc.timestamp}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Active Incident Detail Panel */}
        {activeIncident && (
          <div className="lg:col-span-2 bg-[#111827] border border-[#293548] rounded-xl p-5 space-y-4 flex flex-col justify-between">
            <div className="space-y-4">
              {/* Title & Metadata */}
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 border-b border-[#293548] pb-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-[#38bdf8]">
                      {activeIncident.id}
                    </span>
                    {severityBadge(activeIncident.severity)}
                    {statusBadge(activeIncident.status)}
                  </div>
                  <h3 className="text-base font-bold text-[#f1f5f9] mt-1">
                    {activeIncident.title}
                  </h3>
                </div>

                {/* Status Changer */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <span className="text-xs text-[#94a3b8] font-mono">Set:</span>
                  {(['investigating', 'contained', 'resolved'] as const).map((s) => (
                    <button
                      key={s}
                      onClick={() => onUpdateIncidentStatus(activeIncident.id, s)}
                      className={`px-2 py-1 text-[11px] font-mono rounded border transition-colors ${
                        activeIncident.status === s 
                          ? 'bg-[#38bdf8]/20 border-[#38bdf8]/40 text-[#38bdf8] font-bold' 
                          : 'bg-[#0b1020] border-[#293548] text-[#94a3b8] hover:text-[#f1f5f9]'
                      }`}
                    >
                      {s.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>

              {/* Action Feedback Banner */}
              {actionFeedback && (
                <div className="p-2.5 rounded-lg bg-[#34d399]/15 border border-[#34d399]/40 text-[#34d399] text-xs font-mono flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>{actionFeedback}</span>
                </div>
              )}

              {/* Key Attributes Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs bg-[#0b1020] p-3 rounded-lg border border-[#293548]">
                <div>
                  <span className="text-[#94a3b8] font-mono">Affected Endpoint:</span>
                  <div className="font-mono text-[#f1f5f9] font-bold mt-0.5">{activeIncident.affectedHost}</div>
                </div>

                <div>
                  <span className="text-[#94a3b8] font-mono">Assigned Analyst:</span>
                  <div className="font-medium text-[#f1f5f9] mt-0.5">{activeIncident.assignedTo}</div>
                </div>

                <div>
                  <span className="text-[#94a3b8] font-mono">Sensor Source:</span>
                  <div className="text-[#2dd4bf] font-medium mt-0.5">{activeIncident.source}</div>
                </div>

                <div>
                  <span className="text-[#94a3b8] font-mono">Observed TTP:</span>
                  <div className="font-mono text-[#38bdf8] mt-0.5">{activeIncident.mitreTactic}</div>
                </div>
              </div>

              {/* Related IOCs with jump action */}
              <div className="space-y-1.5">
                <span className="text-[11px] font-mono text-[#94a3b8] uppercase font-bold">
                  Associated Indicators of Compromise ({activeIncident.relatedIocs.length}):
                </span>
                <div className="flex flex-wrap gap-2">
                  {activeIncident.relatedIocs.map((iocVal) => (
                    <button
                      key={iocVal}
                      onClick={() => onSelectIocValue(iocVal)}
                      className="px-2.5 py-1 rounded bg-[#0b1020] hover:bg-[#172033] border border-[#293548] hover:border-[#38bdf8]/50 text-xs font-mono text-[#38bdf8] flex items-center gap-1.5 transition-colors group"
                    >
                      <span className="truncate max-w-xs">{iocVal}</span>
                      <ExternalLink className="w-3 h-3 text-[#94a3b8] group-hover:text-[#38bdf8]" />
                    </button>
                  ))}
                </div>
              </div>

              {/* Rapid Containment Actions */}
              <div className="p-3 rounded-lg bg-[#172033] border border-[#293548] space-y-2">
                <span className="text-[11px] font-mono text-[#f87171] uppercase font-bold flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Immediate Containment Controls:</span>
                </span>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => handleContainmentAction('Isolate Network Host')}
                    className="h-8 px-3 text-xs font-semibold text-[#f87171] bg-[#f87171]/15 hover:bg-[#f87171]/25 border border-[#f87171]/40 rounded-lg flex items-center gap-1.5 transition-colors"
                  >
                    <Ban className="w-3.5 h-3.5" />
                    <span>Isolate Endpoint Host</span>
                  </button>

                  <button
                    onClick={() => handleContainmentAction('Push Firewall Block Rules')}
                    className="h-8 px-3 text-xs font-medium text-[#f1f5f9] bg-[#0b1020] hover:bg-[#111827] border border-[#293548] rounded-lg flex items-center gap-1.5 transition-colors"
                  >
                    <Lock className="w-3.5 h-3.5 text-[#38bdf8]" />
                    <span>Push Firewall Block</span>
                  </button>

                  <button
                    onClick={() => handleContainmentAction('Revoke Azure AD Sessions')}
                    className="h-8 px-3 text-xs font-medium text-[#f1f5f9] bg-[#0b1020] hover:bg-[#111827] border border-[#293548] rounded-lg flex items-center gap-1.5 transition-colors"
                  >
                    <RotateCcw className="w-3.5 h-3.5 text-[#2dd4bf]" />
                    <span>Revoke User Tokens</span>
                  </button>
                </div>
              </div>

              {/* SOC Analyst Notes Timeline */}
              <div className="space-y-2">
                <span className="text-[11px] font-mono text-[#94a3b8] uppercase font-bold">
                  Analyst Timeline & Notes ({activeIncident.notes.length}):
                </span>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {activeIncident.notes.map((note, idx) => (
                    <div key={idx} className="p-2.5 bg-[#0b1020] rounded-lg border border-[#293548] text-xs space-y-1">
                      <div className="flex items-center justify-between text-[11px] text-[#94a3b8]">
                        <span className="font-semibold text-[#38bdf8]">{note.author}</span>
                        <span className="font-mono tabular-nums">{note.time}</span>
                      </div>
                      <p className="text-[#f1f5f9] leading-relaxed">{note.text}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Note Input Box */}
            <form onSubmit={handleAddNote} className="mt-4 pt-3 border-t border-[#293548] flex gap-2">
              <input
                type="text"
                value={newNoteText}
                onChange={(e) => setNewNoteText(e.target.value)}
                placeholder="Log forensic observation or remediation step..."
                className="flex-1 h-9 px-3 bg-[#0b1020] border border-[#293548] rounded-lg text-xs text-[#f1f5f9] placeholder-[#94a3b8]/60 focus:outline-none focus:border-[#38bdf8]"
              />
              <button
                type="submit"
                className="h-9 px-3.5 bg-[#38bdf8] text-[#0b1020] text-xs font-semibold rounded-lg hover:bg-[#7dd3fc] transition-colors flex items-center gap-1.5 shrink-0"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Post Note</span>
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  );
};
