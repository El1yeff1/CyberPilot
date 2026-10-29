/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Terminal, 
  Bell, 
  ChevronDown, 
  PlusCircle, 
  Layers, 
  Check, 
  Menu
} from 'lucide-react';

interface HeaderProps {
  onSearch: (query: string) => void;
  onOpenDetonateModal: () => void;
  activeIncidentsCount: number;
  onNavigateToIncidents: () => void;
  isSidebarOpen: boolean;
  onToggleSidebar: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  onSearch,
  onOpenDetonateModal,
  activeIncidentsCount,
  onNavigateToIncidents,
  isSidebarOpen,
  onToggleSidebar
}) => {
  const [searchInput, setSearchInput] = useState('');
  const [tenantDropdownOpen, setTenantDropdownOpen] = useState(false);
  const [selectedTenant, setSelectedTenant] = useState('Global SOC · US-East Cluster');

  const tenants = [
    'Global SOC · US-East Cluster',
    'EU-Central Incident Response',
    'APAC Perimeter Defense',
    'Air-Gapped Sandbox Node'
  ];

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchInput.trim()) {
      onSearch(searchInput.trim());
    }
  };

  return (
    <header className="h-16 bg-[#111827] border-b border-[#293548] px-4 md:px-6 flex items-center justify-between gap-4 sticky top-0 z-40 shrink-0">
      {/* Brand & Sidebar Toggle */}
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleSidebar}
          aria-label="Toggle navigation rail"
          className="p-1.5 rounded-lg border border-[#293548] text-[#94a3b8] hover:text-[#f1f5f9] hover:bg-[#172033] transition-colors lg:hidden"
        >
          <Menu className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-[#38bdf8]/15 border border-[#38bdf8]/40 flex items-center justify-center text-[#38bdf8]">
            <Terminal className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-bold tracking-tight text-[#f1f5f9] text-base font-sans">
                CYBERPILOT
              </span>
              <span className="text-[10px] font-mono font-bold tracking-wider px-1.5 py-0.2 text-[#2dd4bf] bg-[#2dd4bf]/10 border border-[#2dd4bf]/30 rounded">
                SEC-OPS
              </span>
            </div>
            <div className="text-[11px] text-[#94a3b8] tracking-normal font-mono hidden sm:block">
              DIAGNOSTIC ENGINE
            </div>
          </div>
        </div>
      </div>

      {/* Unified IOC Search Bar */}
      <form onSubmit={handleSearchSubmit} className="flex-1 max-w-xl mx-2">
        <div className="relative group">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#94a3b8] group-focus-within:text-[#38bdf8] transition-colors">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search indicator (SHA256, MD5, IPv4, Domain, CVE-2024-...)"
            className="w-full h-10 pl-9 pr-16 bg-[#0b1020] border border-[#293548] rounded-lg text-sm text-[#f1f5f9] placeholder-[#94a3b8]/60 focus:outline-none focus:border-[#38bdf8] focus:ring-1 focus:ring-[#38bdf8] font-mono text-xs transition-all"
          />
          <div className="absolute inset-y-0 right-0 pr-2.5 flex items-center">
            <kbd className="hidden sm:inline-block text-[10px] font-mono font-medium text-[#94a3b8] bg-[#172033] px-1.5 py-0.5 rounded border border-[#293548]">
              ↵ ENTER
            </kbd>
          </div>
        </div>
      </form>

      {/* Right Controls: Tenant Selector, Alerts, Detonate CTA */}
      <div className="flex items-center gap-2 sm:gap-3">
        {/* Tenant Selector */}
        <div className="relative hidden md:block">
          <button
            onClick={() => setTenantDropdownOpen(!tenantDropdownOpen)}
            className="h-9 px-3 bg-[#172033] border border-[#293548] rounded-lg text-xs font-medium text-[#d4e4fa] hover:border-[#38bdf8]/50 flex items-center gap-2 transition-colors"
          >
            <Layers className="w-3.5 h-3.5 text-[#38bdf8]" />
            <span className="truncate max-w-[150px]">{selectedTenant}</span>
            <ChevronDown className="w-3 h-3 text-[#94a3b8]" />
          </button>

          {tenantDropdownOpen && (
            <div className="absolute right-0 mt-1 w-64 bg-[#1e293b] border border-[#293548] rounded-xl shadow-2xl py-1.5 z-50">
              <div className="px-3 py-1.5 text-[11px] font-semibold text-[#94a3b8] tracking-wider uppercase border-b border-[#293548]">
                Select SOC Cluster
              </div>
              {tenants.map((t) => (
                <button
                  key={t}
                  onClick={() => {
                    setSelectedTenant(t);
                    setTenantDropdownOpen(false);
                  }}
                  className="w-full px-3 py-2 text-left text-xs text-[#f1f5f9] hover:bg-[#172033] flex items-center justify-between transition-colors"
                >
                  <span className="truncate">{t}</span>
                  {selectedTenant === t && <Check className="w-3.5 h-3.5 text-[#38bdf8]" />}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Incident Alerts Button */}
        <button
          onClick={onNavigateToIncidents}
          title="Active Incident Alerts"
          className="h-9 px-2.5 bg-[#172033] border border-[#293548] rounded-lg text-[#94a3b8] hover:text-[#f1f5f9] hover:border-[#38bdf8]/50 flex items-center gap-1.5 transition-colors relative"
        >
          <Bell className="w-4 h-4 text-[#94a3b8]" />
          {activeIncidentsCount > 0 && (
            <span className="font-mono text-xs font-bold text-[#f87171] bg-[#f87171]/15 px-1.5 py-0.2 rounded border border-[#f87171]/40 tabular-nums">
              {activeIncidentsCount}
            </span>
          )}
        </button>

        {/* Detonate / Ingest Button */}
        <button
          onClick={onOpenDetonateModal}
          className="h-9 px-3.5 bg-[#38bdf8] text-[#0b1020] font-semibold text-xs rounded-lg hover:bg-[#7dd3fc] active:bg-[#0284c7] transition-colors flex items-center gap-1.5 shadow-sm"
        >
          <PlusCircle className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Detonate Sample</span>
          <span className="sm:hidden">Detonate</span>
        </button>
      </div>
    </header>
  );
};
