/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { 
  Crosshair, 
  Database, 
  Binary, 
  Code2, 
  AlertOctagon, 
  Activity, 
  Cpu, 
  Radio, 
  UserCheck 
} from 'lucide-react';

export type NavView = 'investigation' | 'registry' | 'hex' | 'yara' | 'incidents';

interface SidebarProps {
  currentView: NavView;
  onSelectView: (view: NavView) => void;
  isOpen: boolean;
  onCloseMobile: () => void;
  iocCount: number;
  incidentCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onSelectView,
  isOpen,
  onCloseMobile,
  iocCount,
  incidentCount
}) => {
  const navItems = [
    {
      id: 'investigation' as NavView,
      label: 'Live Investigation',
      sublabel: 'Multi-engine IOC diagnostics',
      icon: Crosshair,
      badge: null
    },
    {
      id: 'registry' as NavView,
      label: 'IOC Registry & Feed',
      sublabel: 'Threat database & hashes',
      icon: Database,
      badge: `${iocCount}`
    },
    {
      id: 'hex' as NavView,
      label: 'Hex & Payload Viewer',
      sublabel: 'Binary disassembly & entropy',
      icon: Binary,
      badge: null
    },
    {
      id: 'yara' as NavView,
      label: 'YARA & Rule Workbench',
      sublabel: 'Live signature matching',
      icon: Code2,
      badge: null
    },
    {
      id: 'incidents' as NavView,
      label: 'Incident Triage',
      sublabel: 'Queue & containment actions',
      icon: AlertOctagon,
      badge: `${incidentCount}`
    }
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div 
          onClick={onCloseMobile}
          className="fixed inset-0 bg-black/60 backdrop-blur-xs z-40 lg:hidden"
        />
      )}

      <aside className={`
        fixed top-16 bottom-0 left-0 z-40 w-64 bg-[#111827] border-r border-[#293548] flex flex-col justify-between transition-transform duration-200
        ${isOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        {/* Navigation List */}
        <div className="p-3 space-y-1 overflow-y-auto">
          <div className="px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-wider text-[#94a3b8]/70">
            OPERATIONAL MODULES
          </div>

          {navItems.map((item) => {
            const isActive = currentView === item.id;
            const Icon = item.icon;

            return (
              <button
                key={item.id}
                onClick={() => {
                  onSelectView(item.id);
                  onCloseMobile();
                }}
                className={`
                  w-full px-3 py-2.5 rounded-lg text-left flex items-center justify-between transition-colors group relative
                  ${isActive 
                    ? 'bg-[#172033] border border-[#38bdf8]/40 text-[#f1f5f9]' 
                    : 'text-[#94a3b8] hover:text-[#f1f5f9] hover:bg-[#172033]/60 border border-transparent'}
                `}
              >
                <div className="flex items-center gap-2.5">
                  <div className={`p-1.5 rounded-md transition-colors ${
                    isActive 
                      ? 'bg-[#38bdf8]/15 text-[#38bdf8]' 
                      : 'bg-[#0b1020] text-[#94a3b8] group-hover:text-[#f1f5f9]'
                  }`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold leading-tight">{item.label}</div>
                    <div className="text-[11px] text-[#94a3b8]/70 leading-tight">{item.sublabel}</div>
                  </div>
                </div>

                {item.badge && (
                  <span className={`text-[11px] font-mono px-1.5 py-0.5 rounded border tabular-nums ${
                    isActive 
                      ? 'bg-[#38bdf8]/15 text-[#38bdf8] border-[#38bdf8]/30 font-bold' 
                      : 'bg-[#0b1020] text-[#94a3b8] border-[#293548]'
                  }`}>
                    {item.badge}
                  </span>
                )}

                {isActive && (
                  <div className="absolute right-0 top-1/2 -translate-y-1/2 w-1 h-5 bg-[#38bdf8] rounded-l" />
                )}
              </button>
            );
          })}
        </div>

        {/* Bottom Hardware & SOC Status */}
        <div className="p-3 border-t border-[#293548] bg-[#0b1020]/70 space-y-3">
          <div className="space-y-1.5 text-xs">
            <div className="flex items-center justify-between text-[#94a3b8]">
              <span className="flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-[#2dd4bf]" />
                <span className="text-[11px]">Detection Engines</span>
              </span>
              <span className="font-mono text-[11px] text-[#2dd4bf] font-semibold tabular-nums">68/68 Active</span>
            </div>
            
            <div className="flex items-center justify-between text-[#94a3b8]">
              <span className="flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5 text-[#38bdf8]" />
                <span className="text-[11px]">Telemetry Feed</span>
              </span>
              <span className="font-mono text-[11px] text-[#38bdf8] font-semibold">Live (42 ms)</span>
            </div>
          </div>

          {/* Analyst Session Chip */}
          <div className="p-2 rounded-lg bg-[#111827] border border-[#293548] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-[#38bdf8]/10 border border-[#38bdf8]/30 flex items-center justify-center text-[#38bdf8]">
                <UserCheck className="w-3.5 h-3.5" />
              </div>
              <div>
                <div className="text-[11px] font-semibold text-[#f1f5f9] leading-none">Nuran R.</div>
                <div className="text-[10px] text-[#94a3b8] font-mono leading-none mt-0.5">Tier 2 SOC</div>
              </div>
            </div>
            <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-[#34d399]/10 text-[#34d399] border border-[#34d399]/30">
              ACTIVE
            </span>
          </div>
        </div>
      </aside>
    </>
  );
};
