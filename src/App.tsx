/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  INITIAL_IOCS, 
  INITIAL_INCIDENTS, 
  INITIAL_YARA_RULES, 
  INITIAL_PAYLOAD_SAMPLES,
  analyzeCustomInput 
} from './data/mockThreatData';
import { ThreatIoc, SocIncident } from './types/threat';
import { Header } from './components/Header';
import { Sidebar, NavView } from './components/Sidebar';
import { InvestigationView } from './components/InvestigationView';
import { IocRegistryView } from './components/IocRegistryView';
import { HexPayloadInspector } from './components/HexPayloadInspector';
import { YaraWorkbench } from './components/YaraWorkbench';
import { IncidentTriageView } from './components/IncidentTriageView';
import { DetonateModal } from './components/DetonateModal';

export default function App() {
  const [currentView, setCurrentView] = useState<NavView>('investigation');
  const [iocs, setIocs] = useState<ThreatIoc[]>(INITIAL_IOCS);
  const [selectedIoc, setSelectedIoc] = useState<ThreatIoc>(INITIAL_IOCS[0]);
  const [incidents, setIncidents] = useState<SocIncident[]>(INITIAL_INCIDENTS);
  const [yaraRules, setYaraRules] = useState(INITIAL_YARA_RULES);
  const [payloadSamples, setPayloadSamples] = useState(INITIAL_PAYLOAD_SAMPLES);
  const [blocklist, setBlocklist] = useState<string[]>([
    '185.220.101.45',
    'auth-security-update-microsoft365.online'
  ]);
  const [isDetonateModalOpen, setIsDetonateModalOpen] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [alertToast, setAlertToast] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setAlertToast(msg);
    setTimeout(() => setAlertToast(null), 3000);
  };

  // Unified Search Handler
  const handleSearch = (query: string) => {
    const trimmed = query.trim().toLowerCase();
    const existing = iocs.find(i => 
      i.value.toLowerCase() === trimmed ||
      i.id.toLowerCase() === trimmed
    );

    if (existing) {
      setSelectedIoc(existing);
      setCurrentView('investigation');
      showToast(`Loaded indicator: ${existing.value.slice(0, 24)}...`);
    } else {
      // Analyze new unknown input dynamically through heuristic engine
      const analyzed = analyzeCustomInput(query);
      setIocs(prev => [analyzed, ...prev]);
      setSelectedIoc(analyzed);
      setCurrentView('investigation');
      showToast(`Detonated & analyzed new indicator: ${analyzed.value.slice(0, 24)}...`);
    }
  };

  // Blocklist toggle
  const handleToggleBlocklist = (iocValue: string) => {
    setBlocklist(prev => {
      const exists = prev.includes(iocValue);
      if (exists) {
        showToast(`Removed from perimeter blocklist: ${iocValue.slice(0, 20)}`);
        return prev.filter(v => v !== iocValue);
      } else {
        showToast(`Added to perimeter blocklist: ${iocValue.slice(0, 20)}`);
        return [...prev, iocValue];
      }
    });
  };

  // Rescan simulation
  const handleRescan = (iocValue: string) => {
    setSelectedIoc(prev => ({
      ...prev,
      lastActive: 'Just now (Re-verified)',
      vendorDetections: prev.vendorDetections.map(v => ({
        ...v,
        updateTimestamp: '2026-10-29'
      }))
    }));
    showToast(`Multi-engine re-scan completed for ${iocValue.slice(0, 20)}`);
  };

  // Incident status update
  const handleUpdateIncidentStatus = (incidentId: string, status: SocIncident['status']) => {
    setIncidents(prev => prev.map(inc => {
      if (inc.id === incidentId) {
        return { ...inc, status };
      }
      return inc;
    }));
    showToast(`Updated incident ${incidentId} status to ${status.toUpperCase()}`);
  };

  // Incident note append
  const handleAddIncidentNote = (incidentId: string, noteText: string) => {
    setIncidents(prev => prev.map(inc => {
      if (inc.id === incidentId) {
        return {
          ...inc,
          notes: [
            ...inc.notes,
            {
              author: 'Nuran R. (Tier 2 SOC)',
              text: noteText,
              time: 'Just now'
            }
          ]
        };
      }
      return inc;
    }));
    showToast(`Forensic note added to ${incidentId}`);
  };

  const activeIncidentsCount = incidents.filter(i => i.status === 'new' || i.status === 'investigating').length;

  return (
    <div className="min-h-screen bg-[#051424] text-[#d4e4fa] font-sans flex flex-col antialiased">
      {/* 64px Fixed Global Header */}
      <Header
        onSearch={handleSearch}
        onOpenDetonateModal={() => setIsDetonateModalOpen(true)}
        activeIncidentsCount={activeIncidentsCount}
        onNavigateToIncidents={() => setCurrentView('incidents')}
        isSidebarOpen={isSidebarOpen}
        onToggleSidebar={() => setIsSidebarOpen(!isSidebarOpen)}
      />

      {/* Main Operational Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* 240px Lateral Navigation Rail */}
        <Sidebar
          currentView={currentView}
          onSelectView={setCurrentView}
          isOpen={isSidebarOpen}
          onCloseMobile={() => setIsSidebarOpen(false)}
          iocCount={iocs.length}
          incidentCount={activeIncidentsCount}
        />

        {/* Dynamic Viewport Container */}
        <main className="flex-1 lg:ml-64 p-4 md:p-6 overflow-y-auto max-w-[1600px] w-full mx-auto">
          {/* Toast Notification */}
          {alertToast && (
            <div className="fixed bottom-5 right-5 z-50 bg-[#172033] border border-[#38bdf8]/40 text-[#f1f5f9] px-4 py-2.5 rounded-lg shadow-xl text-xs font-mono flex items-center gap-2 animate-in fade-in slide-in-from-bottom-2 duration-200">
              <span className="w-2 h-2 rounded-full bg-[#38bdf8]" />
              <span>{alertToast}</span>
            </div>
          )}

          {/* Module Views */}
          {currentView === 'investigation' && (
            <InvestigationView
              ioc={selectedIoc}
              onSelectRelatedIoc={handleSearch}
              onAddToBlocklist={handleToggleBlocklist}
              isBlocklisted={blocklist.includes(selectedIoc.value)}
              onRescan={handleRescan}
            />
          )}

          {currentView === 'registry' && (
            <IocRegistryView
              iocs={iocs}
              onSelectIoc={(ioc) => {
                setSelectedIoc(ioc);
                setCurrentView('investigation');
              }}
              blocklist={blocklist}
              onToggleBlocklist={handleToggleBlocklist}
            />
          )}

          {currentView === 'hex' && (
            <HexPayloadInspector samples={payloadSamples} />
          )}

          {currentView === 'yara' && (
            <YaraWorkbench rules={yaraRules} samples={payloadSamples} />
          )}

          {currentView === 'incidents' && (
            <IncidentTriageView
              incidents={incidents}
              onSelectIocValue={handleSearch}
              onUpdateIncidentStatus={handleUpdateIncidentStatus}
              onAddIncidentNote={handleAddIncidentNote}
            />
          )}
        </main>
      </div>

      {/* Detonate / Ingest Modal */}
      <DetonateModal
        isOpen={isDetonateModalOpen}
        onClose={() => setIsDetonateModalOpen(false)}
        onSubmit={handleSearch}
      />
    </div>
  );
}
