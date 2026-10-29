/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { YaraRule, PayloadSample } from '../types/threat';
import { 
  Code2, 
  Play, 
  CheckCircle2, 
  XCircle, 
  Copy, 
  Check, 
  Plus, 
  FileText, 
  ShieldCheck, 
  AlertTriangle 
} from 'lucide-react';

interface YaraWorkbenchProps {
  rules: YaraRule[];
  samples: PayloadSample[];
}

export const YaraWorkbench: React.FC<YaraWorkbenchProps> = ({ rules, samples }) => {
  const [selectedRuleId, setSelectedRuleId] = useState(rules[0]?.id || '');
  const [editorContent, setEditorContent] = useState(rules[0]?.ruleContent || '');
  const [selectedSampleId, setSelectedSampleId] = useState(samples[0]?.id || '');
  const [scanResult, setScanResult] = useState<{
    matched: boolean;
    matchedStrings: string[];
    testedAt: string;
  } | null>(null);
  const [copiedRule, setCopiedRule] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const activeRule = rules.find(r => r.id === selectedRuleId) || rules[0];
  const activeSample = samples.find(s => s.id === selectedSampleId) || samples[0];

  const handleSelectRule = (rule: YaraRule) => {
    setSelectedRuleId(rule.id);
    setEditorContent(rule.ruleContent);
    setScanResult(null);
  };

  const handleRunScan = () => {
    // Check if targetKeywords or substrings from editor exist in sample
    const sampleText = activeSample.rawText + ' ' + activeSample.extractedStrings.join(' ');
    const matches: string[] = [];

    // Parse string patterns from editor content ($variable = "pattern")
    const stringMatches = editorContent.matchAll(/\$([a-zA-Z0-9_]+)\s*=\s*"([^"]+)"/g);
    for (const match of stringMatches) {
      const pattern = match[2];
      if (sampleText.toLowerCase().includes(pattern.toLowerCase())) {
        matches.push(`${match[1]}: "${pattern}"`);
      }
    }

    // Fallback to activeRule target keywords if custom regex didn't extract any
    if (matches.length === 0 && activeRule) {
      for (const kw of activeRule.targetKeywords) {
        if (sampleText.toLowerCase().includes(kw.toLowerCase())) {
          matches.push(`keyword: "${kw}"`);
        }
      }
    }

    setScanResult({
      matched: matches.length > 0,
      matchedStrings: matches,
      testedAt: new Date().toLocaleTimeString()
    });
  };

  const copyRuleToClipboard = () => {
    navigator.clipboard.writeText(editorContent);
    setCopiedRule(true);
    setTimeout(() => setCopiedRule(false), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Header and Controls */}
      <div className="bg-[#111827] border border-[#293548] rounded-xl p-4 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Code2 className="w-4 h-4 text-[#38bdf8]" />
              <h2 className="text-base font-bold text-[#f1f5f9] tracking-tight">
                YARA Rule Workbench & Signature Matcher
              </h2>
            </div>
            <p className="text-xs text-[#94a3b8] mt-0.5">
              Live authoring environment and test runner for YARA malware classification rules against memory dumps and artifacts.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={copyRuleToClipboard}
              className="h-8 px-2.5 bg-[#172033] hover:bg-[#1e293b] text-xs font-medium text-[#f1f5f9] border border-[#293548] rounded-lg flex items-center gap-1.5 transition-colors"
            >
              {copiedRule ? <Check className="w-3.5 h-3.5 text-[#34d399]" /> : <Copy className="w-3.5 h-3.5 text-[#38bdf8]" />}
              <span>{copiedRule ? 'Copied' : 'Copy Rule'}</span>
            </button>
          </div>
        </div>

        {/* Test Target Selector & Run Trigger */}
        <div className="pt-2 border-t border-[#293548] flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-[#94a3b8]">Test Against Sample:</span>
            <select
              value={selectedSampleId}
              onChange={(e) => setSelectedSampleId(e.target.value)}
              className="h-8 px-2.5 bg-[#0b1020] border border-[#293548] rounded-lg text-xs font-mono text-[#f1f5f9] focus:outline-none focus:border-[#38bdf8]"
            >
              {samples.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.size} bytes)
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={handleRunScan}
            className="h-8 px-4 bg-[#38bdf8] text-[#0b1020] font-semibold text-xs rounded-lg hover:bg-[#7dd3fc] transition-colors flex items-center gap-1.5 shadow-sm"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Execute YARA Scan</span>
          </button>
        </div>
      </div>

      {/* Main Grid: Rules List on Left, Editor and Results on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Rules Sidebar */}
        <div className="bg-[#111827] border border-[#293548] rounded-xl p-3 space-y-2 lg:col-span-1">
          <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-[#94a3b8] px-2 py-1">
            STANDARD RULESET ({rules.length})
          </div>

          <div className="space-y-1.5">
            {rules.map((rule) => {
              const isSelected = selectedRuleId === rule.id;
              return (
                <button
                  key={rule.id}
                  onClick={() => handleSelectRule(rule)}
                  className={`w-full p-2.5 rounded-lg text-left border transition-colors ${
                    isSelected 
                      ? 'bg-[#172033] border-[#38bdf8]/40 text-[#f1f5f9]' 
                      : 'bg-[#0b1020]/60 border-[#293548] text-[#94a3b8] hover:text-[#f1f5f9] hover:bg-[#172033]/40'
                  }`}
                >
                  <div className="font-mono text-xs font-bold truncate">
                    {rule.name}
                  </div>
                  <div className="text-[11px] text-[#94a3b8] truncate mt-0.5">
                    {rule.description}
                  </div>
                  <div className="flex items-center gap-1.5 mt-2">
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#0b1020] border border-[#293548] text-[#38bdf8]">
                      {rule.severity.toUpperCase()}
                    </span>
                    <span className="text-[10px] font-mono text-[#94a3b8]/60">
                      {rule.author.split(' ')[0]}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Editor & Scan Results Container */}
        <div className="lg:col-span-3 space-y-4">
          {/* Syntax Editor */}
          <div className="bg-[#0b1020] border border-[#293548] rounded-xl overflow-hidden flex flex-col">
            <div className="h-9 px-4 bg-[#111827] border-b border-[#293548] flex items-center justify-between text-xs font-mono text-[#94a3b8]">
              <div className="flex items-center gap-2">
                <FileText className="w-3.5 h-3.5 text-[#38bdf8]" />
                <span className="text-[#f1f5f9] font-bold">{activeRule.name}.yar</span>
              </div>
              <span>YARA v4.5.1 syntax</span>
            </div>

            <textarea
              rows={14}
              value={editorContent}
              onChange={(e) => setEditorContent(e.target.value)}
              className="w-full bg-[#0b1020] p-4 text-xs font-mono text-[#f1f5f9] leading-relaxed focus:outline-none resize-none selection:bg-[#38bdf8]/30"
              spellCheck={false}
            />
          </div>

          {/* Scan Results Panel */}
          {scanResult && (
            <div className={`p-4 rounded-xl border transition-all ${
              scanResult.matched 
                ? 'bg-[#f87171]/10 border-[#f87171]/40' 
                : 'bg-[#34d399]/10 border-[#34d399]/40'
            }`}>
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  {scanResult.matched ? (
                    <div className="w-7 h-7 rounded-lg bg-[#f87171]/20 border border-[#f87171]/40 flex items-center justify-center text-[#f87171]">
                      <AlertTriangle className="w-4 h-4" />
                    </div>
                  ) : (
                    <div className="w-7 h-7 rounded-lg bg-[#34d399]/20 border border-[#34d399]/40 flex items-center justify-center text-[#34d399]">
                      <CheckCircle2 className="w-4 h-4" />
                    </div>
                  )}

                  <div>
                    <div className={`font-mono text-sm font-bold ${scanResult.matched ? 'text-[#f87171]' : 'text-[#34d399]'}`}>
                      {scanResult.matched ? 'YARA SIGNATURE RULE MATCHED' : 'ZERO SIGNATURE MATCHES DETECTED'}
                    </div>
                    <div className="text-xs text-[#94a3b8] font-mono mt-0.5">
                      Target: {activeSample.name} · Tested at {scanResult.testedAt}
                    </div>
                  </div>
                </div>

                <span className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded border ${
                  scanResult.matched ? 'bg-[#f87171]/20 text-[#f87171] border-[#f87171]/40' : 'bg-[#34d399]/20 text-[#34d399] border-[#34d399]/40'
                }`}>
                  {scanResult.matched ? 'FLAGGED' : 'CLEAN'}
                </span>
              </div>

              {scanResult.matched && scanResult.matchedStrings.length > 0 && (
                <div className="mt-3 pt-3 border-t border-[#f87171]/20 space-y-1.5">
                  <div className="text-[11px] font-mono text-[#f87171] font-bold uppercase">
                    Matched Artifact Patterns:
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {scanResult.matchedStrings.map((ms, idx) => (
                      <span
                        key={idx}
                        className="font-mono text-xs bg-[#0b1020] border border-[#f87171]/30 text-[#f87171] px-2 py-0.5 rounded"
                      >
                        {ms}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
