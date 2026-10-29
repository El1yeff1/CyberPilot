/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  PlusCircle, 
  Terminal, 
  ShieldAlert, 
  Cpu, 
  Play, 
  X, 
  Sparkles,
  ArrowRight
} from 'lucide-react';

interface DetonateModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (input: string) => void;
}

export const DetonateModal: React.FC<DetonateModalProps> = ({
  isOpen,
  onClose,
  onSubmit
}) => {
  const [inputValue, setInputValue] = useState('');
  const [executionWindow, setExecutionWindow] = useState('180s');

  if (!isOpen) return null;

  const quickSamples = [
    { label: 'Obfuscated Stager Hash', value: '7b23f81e9d1a3c74900a84e27f9cb811234a9b5f4c8e762d01e4a7b3c9d8112a' },
    { label: 'Credential Harvest Domain', value: 'auth-security-update-microsoft365.online' },
    { label: 'Untrusted Relay IP', value: '185.220.101.45' },
    { label: 'CVE-2024-38077 Flaw', value: 'CVE-2024-38077' }
  ];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputValue.trim()) {
      onSubmit(inputValue.trim());
      onClose();
    }
  };

  const handleSelectQuickSample = (val: string) => {
    setInputValue(val);
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4 z-50">
      <div className="bg-[#111827] border border-[#293548] rounded-xl max-w-xl w-full p-5 space-y-4 shadow-2xl relative">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[#293548] pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-[#38bdf8]/15 border border-[#38bdf8]/40 flex items-center justify-center text-[#38bdf8]">
              <PlusCircle className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-[#f1f5f9]">
                Detonate Artifact / Manual IOC Ingest
              </h3>
              <p className="text-[11px] text-[#94a3b8] font-mono">
                Isolated sandbox dynamic analysis & heuristic indexing
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 text-[#94a3b8] hover:text-[#f1f5f9] rounded-md transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Input Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-mono text-[#94a3b8] flex items-center justify-between">
              <span>INDICATOR STRING OR HASH:</span>
              <span className="text-[#38bdf8]">SHA256 · MD5 · IPv4 · Domain · CVE</span>
            </label>
            <textarea
              rows={3}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Paste SHA-256 hash, suspicious domain, IP address, or CVE identifier..."
              className="w-full bg-[#0b1020] border border-[#293548] rounded-lg p-3 text-xs font-mono text-[#f1f5f9] placeholder-[#94a3b8]/50 focus:outline-none focus:border-[#38bdf8] focus:ring-1 focus:ring-[#38bdf8] resize-none"
              autoFocus
            />
          </div>

          {/* Quick presets */}
          <div className="space-y-1.5">
            <span className="text-[11px] font-mono text-[#94a3b8] uppercase">
              Quick Test Presets:
            </span>
            <div className="flex flex-wrap gap-1.5">
              {quickSamples.map((sample, idx) => (
                <button
                  type="button"
                  key={idx}
                  onClick={() => handleSelectQuickSample(sample.value)}
                  className="px-2 py-1 bg-[#172033] hover:bg-[#1e293b] border border-[#293548] hover:border-[#38bdf8]/40 rounded text-[11px] font-mono text-[#38bdf8] transition-colors"
                >
                  {sample.label}
                </button>
              ))}
            </div>
          </div>

          {/* Sandbox Config */}
          <div className="flex items-center justify-between p-3 rounded-lg bg-[#0b1020] border border-[#293548] text-xs">
            <div className="flex items-center gap-2 text-[#94a3b8]">
              <Cpu className="w-4 h-4 text-[#2dd4bf]" />
              <span>Hypervisor Emulation Timeout:</span>
            </div>
            <div className="flex items-center gap-1 font-mono">
              {(['60s', '180s', '300s'] as const).map((win) => (
                <button
                  type="button"
                  key={win}
                  onClick={() => setExecutionWindow(win)}
                  className={`px-2 py-0.5 rounded text-xs transition-colors ${
                    executionWindow === win 
                      ? 'bg-[#38bdf8]/20 text-[#38bdf8] border border-[#38bdf8]/40 font-bold' 
                      : 'text-[#94a3b8] hover:text-[#f1f5f9]'
                  }`}
                >
                  {win}
                </button>
              ))}
            </div>
          </div>

          {/* Footer Actions */}
          <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#293548]">
            <button
              type="button"
              onClick={onClose}
              className="h-9 px-4 text-xs font-medium text-[#94a3b8] hover:text-[#f1f5f9] hover:bg-[#172033] rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!inputValue.trim()}
              className="h-9 px-4 bg-[#38bdf8] text-[#0b1020] font-semibold text-xs rounded-lg hover:bg-[#7dd3fc] transition-colors flex items-center gap-1.5 disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Execute Detonation</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
