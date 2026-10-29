/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { PayloadSample } from '../types/threat';
import { 
  Binary, 
  Search, 
  Copy, 
  Check, 
  Layers, 
  FileCode, 
  Terminal, 
  Activity, 
  ArrowDownToLine,
  Upload
} from 'lucide-react';

interface HexPayloadInspectorProps {
  samples: PayloadSample[];
}

export const HexPayloadInspector: React.FC<HexPayloadInspectorProps> = ({ samples }) => {
  const [selectedSampleId, setSelectedSampleId] = useState(samples[0]?.id || '');
  const [hoveredByteIndex, setHoveredByteIndex] = useState<number | null>(null);
  const [stringSearch, setStringSearch] = useState('');
  const [copiedText, setCopiedText] = useState(false);
  const [customText, setCustomText] = useState('');
  const [isCustomMode, setIsCustomMode] = useState(false);

  const activeSample = samples.find(s => s.id === selectedSampleId) || samples[0];

  // Convert custom text to hex bytes if in custom mode
  const currentHexBytes = isCustomMode 
    ? Array.from(new TextEncoder().encode(customText || 'Enter custom text to view hex dump')).map(b => b.toString(16).padStart(2, '0').toUpperCase())
    : activeSample.hexBytes;

  const currentEntropy = isCustomMode ? calculateEntropy(customText) : activeSample.entropy;

  function calculateEntropy(str: string): number {
    if (!str) return 0;
    const len = str.length;
    const frequencies: Record<string, number> = {};
    for (const char of str) {
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 100) / 100;
  }

  // Group bytes into 16-byte rows
  const rows: { offset: string; hex: string[]; ascii: string; rawIndices: number[] }[] = [];
  for (let i = 0; i < currentHexBytes.length; i += 16) {
    const chunk = currentHexBytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(8, '0').toUpperCase();
    const ascii = chunk.map(hex => {
      const charCode = parseInt(hex, 16);
      return charCode >= 32 && charCode <= 126 ? String.fromCharCode(charCode) : '.';
    }).join('');
    
    rows.push({
      offset,
      hex: chunk,
      ascii,
      rawIndices: chunk.map((_, idx) => i + idx)
    });
  }

  const copyHexDump = () => {
    const dump = rows.map(r => `${r.offset}  ${r.hex.join(' ').padEnd(48, ' ')}  |${r.ascii}|`).join('\n');
    navigator.clipboard.writeText(dump);
    setCopiedText(true);
    setTimeout(() => setCopiedText(false), 2000);
  };

  // Filter extracted strings
  const extractedStrings = isCustomMode 
    ? customText.split(/\s+/).filter(s => s.length >= 4)
    : activeSample.extractedStrings;

  const filteredStrings = extractedStrings.filter(s => 
    s.toLowerCase().includes(stringSearch.toLowerCase())
  );

  return (
    <div className="space-y-4">
      {/* Header and Controls */}
      <div className="bg-[#111827] border border-[#293548] rounded-xl p-4 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Binary className="w-4 h-4 text-[#38bdf8]" />
              <h2 className="text-base font-bold text-[#f1f5f9] tracking-tight">
                Hex & Payload Disassembly Viewer
              </h2>
            </div>
            <p className="text-xs text-[#94a3b8] mt-0.5">
              Interactive binary forensic inspector with byte offset addressing, real-time Shannon entropy, and ASCII string extraction.
            </p>
          </div>

          {/* Sample Selector & Custom Input Toggle */}
          <div className="flex items-center gap-2">
            <select
              value={isCustomMode ? 'custom' : selectedSampleId}
              onChange={(e) => {
                if (e.target.value === 'custom') {
                  setIsCustomMode(true);
                } else {
                  setIsCustomMode(false);
                  setSelectedSampleId(e.target.value);
                }
              }}
              className="h-8 px-2.5 bg-[#0b1020] border border-[#293548] rounded-lg text-xs font-mono text-[#f1f5f9] focus:outline-none focus:border-[#38bdf8]"
            >
              {samples.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.size} bytes)
                </option>
              ))}
              <option value="custom">+ Paste Raw Custom Payload</option>
            </select>

            <button
              onClick={copyHexDump}
              className="h-8 px-2.5 bg-[#172033] hover:bg-[#1e293b] text-xs font-medium text-[#f1f5f9] border border-[#293548] rounded-lg flex items-center gap-1.5 transition-colors"
            >
              {copiedText ? <Check className="w-3.5 h-3.5 text-[#34d399]" /> : <Copy className="w-3.5 h-3.5 text-[#38bdf8]" />}
              <span>{copiedText ? 'Copied' : 'Copy Dump'}</span>
            </button>
          </div>
        </div>

        {/* Custom Input Field if toggled */}
        {isCustomMode && (
          <div className="pt-2 border-t border-[#293548] space-y-2">
            <label className="text-[11px] font-mono text-[#38bdf8] uppercase font-bold">
              Custom String / Shellcode Ingestion:
            </label>
            <textarea
              rows={2}
              value={customText}
              onChange={(e) => setCustomText(e.target.value)}
              placeholder="Paste ASCII payload, shellcode script, or base64 stream here to inspect in hex viewer..."
              className="w-full bg-[#0b1020] border border-[#293548] rounded-lg p-2 text-xs font-mono text-[#f1f5f9] focus:outline-none focus:border-[#38bdf8]"
            />
          </div>
        )}

        {/* Entropy and Technical Strip */}
        <div className="pt-2 border-t border-[#293548] flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-3">
            <span className="text-[#94a3b8]">Size: <span className="text-[#f1f5f9] font-bold">{currentHexBytes.length} bytes</span></span>
            <span>·</span>
            <span className="text-[#94a3b8]">Format: <span className="text-[#2dd4bf]">{isCustomMode ? 'Raw ASCII / Ingested Buffer' : activeSample.type}</span></span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[#94a3b8]">Shannon Entropy:</span>
            <span className={`font-bold tabular-nums ${currentEntropy >= 7.0 ? 'text-[#f87171]' : 'text-[#34d399]'}`}>
              {currentEntropy} / 8.0
            </span>
            <div className="w-24 h-2 bg-[#0b1020] rounded-full border border-[#293548] overflow-hidden">
              <div 
                className={`h-full ${currentEntropy >= 7.0 ? 'bg-[#f87171]' : currentEntropy >= 5.5 ? 'bg-[#fbbf24]' : 'bg-[#34d399]'}`}
                style={{ width: `${(currentEntropy / 8.0) * 100}%` }}
              />
            </div>
            {currentEntropy >= 7.0 && (
              <span className="text-[10px] text-[#f87171] font-bold">[HIGH PACKING]</span>
            )}
          </div>
        </div>
      </div>

      {/* Main Hex Inspector & String Extractor Columns */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left 2 Columns: Full Hexadecimal Dump */}
        <div className="lg:col-span-2 bg-[#0b1020] border border-[#293548] rounded-xl overflow-hidden flex flex-col">
          {/* Hex View Header Bar */}
          <div className="h-9 px-4 bg-[#111827] border-b border-[#293548] flex items-center justify-between text-[11px] font-mono font-semibold text-[#94a3b8]">
            <div className="flex items-center gap-6">
              <span className="w-20">OFFSET</span>
              <span className="tracking-widest">00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
            </div>
            <span className="w-28 text-right">ASCII DUMP</span>
          </div>

          {/* Hex Body */}
          <div className="p-3 font-mono text-xs overflow-x-auto space-y-1 select-text max-h-[500px] overflow-y-auto">
            {rows.map((row, rIdx) => (
              <div 
                key={rIdx} 
                className="flex items-center justify-between hover:bg-[#172033]/50 py-0.5 px-1 rounded transition-colors group"
              >
                {/* Offset */}
                <span className="text-[#94a3b8]/60 font-semibold w-20 shrink-0 select-none">
                  {row.offset}
                </span>

                {/* Hex Bytes */}
                <div className="flex items-center gap-1.5 flex-1 max-w-[340px] shrink-0 font-medium">
                  {row.hex.map((byte, bIdx) => {
                    const globalIdx = row.rawIndices[bIdx];
                    const isHovered = hoveredByteIndex === globalIdx;

                    return (
                      <span
                        key={bIdx}
                        onMouseEnter={() => setHoveredByteIndex(globalIdx)}
                        onMouseLeave={() => setHoveredByteIndex(null)}
                        className={`cursor-crosshair px-0.5 rounded transition-colors ${
                          isHovered 
                            ? 'bg-[#38bdf8] text-[#0b1020] font-bold' 
                            : byte === '00' 
                            ? 'text-[#94a3b8]/30' 
                            : 'text-[#d4e4fa] hover:text-[#38bdf8]'
                        } ${bIdx === 7 ? 'mr-2' : ''}`}
                      >
                        {byte}
                      </span>
                    );
                  })}
                </div>

                {/* ASCII Panel */}
                <div className="w-28 text-right tracking-widest font-mono text-[#2dd4bf] shrink-0 border-l border-[#293548] pl-3">
                  {row.ascii.split('').map((char, cIdx) => {
                    const globalIdx = row.rawIndices[cIdx];
                    const isHovered = hoveredByteIndex === globalIdx;

                    return (
                      <span
                        key={cIdx}
                        onMouseEnter={() => setHoveredByteIndex(globalIdx)}
                        onMouseLeave={() => setHoveredByteIndex(null)}
                        className={`inline-block ${
                          isHovered 
                            ? 'bg-[#38bdf8] text-[#0b1020] font-bold rounded' 
                            : char === '.' 
                            ? 'text-[#94a3b8]/30' 
                            : 'text-[#2dd4bf]'
                        }`}
                      >
                        {char}
                      </span>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Extracted ASCII Strings & API Call Indicators */}
        <div className="bg-[#111827] border border-[#293548] rounded-xl p-4 flex flex-col justify-between space-y-3">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-[#2dd4bf]" />
                <h3 className="text-xs font-bold text-[#f1f5f9] uppercase tracking-wider font-mono">
                  Extracted Strings
                </h3>
              </div>
              <span className="font-mono text-[10px] text-[#94a3b8] px-1.5 py-0.5 rounded bg-[#0b1020] border border-[#293548]">
                {filteredStrings.length} found
              </span>
            </div>

            {/* Filter Strings */}
            <div className="relative">
              <input
                type="text"
                value={stringSearch}
                onChange={(e) => setStringSearch(e.target.value)}
                placeholder="Search strings & APIs..."
                className="w-full h-8 pl-7 pr-3 bg-[#0b1020] border border-[#293548] rounded-md text-xs font-mono text-[#f1f5f9] placeholder-[#94a3b8]/60 focus:outline-none focus:border-[#38bdf8]"
              />
              <Search className="w-3.5 h-3.5 text-[#94a3b8] absolute left-2 top-2.5 pointer-events-none" />
            </div>

            {/* Strings List */}
            <div className="space-y-1.5 max-h-[380px] overflow-y-auto pr-1">
              {filteredStrings.map((str, idx) => (
                <div
                  key={idx}
                  className="p-2 bg-[#0b1020] hover:bg-[#172033] border border-[#293548] rounded-lg text-xs font-mono text-[#f1f5f9] flex items-center justify-between group transition-colors"
                >
                  <span className="truncate max-w-[220px] text-[#38bdf8] select-all">
                    {str}
                  </span>
                  <button
                    onClick={() => navigator.clipboard.writeText(str)}
                    title="Copy string"
                    className="opacity-0 group-hover:opacity-100 p-1 text-[#94a3b8] hover:text-[#f1f5f9] transition-opacity"
                  >
                    <Copy className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-2 border-t border-[#293548] text-[11px] text-[#94a3b8] font-mono">
            Analyzed with GNU strings emulation (min length 4 characters).
          </div>
        </div>
      </div>
    </div>
  );
};
