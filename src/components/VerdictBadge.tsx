/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { ThreatVerdict } from '../types/threat';
import { ShieldAlert, AlertTriangle, CheckCircle2, HelpCircle } from 'lucide-react';

interface VerdictBadgeProps {
  verdict: ThreatVerdict;
  flaggedRatio?: { flagged: number; total: number };
  size?: 'sm' | 'md' | 'lg';
}

export const VerdictBadge: React.FC<VerdictBadgeProps> = ({ 
  verdict, 
  flaggedRatio,
  size = 'md' 
}) => {
  const configs = {
    malicious: {
      bg: 'bg-[#f87171]/15',
      border: 'border-[#f87171]/60',
      text: 'text-[#f87171]',
      label: 'MALICIOUS',
      Icon: ShieldAlert
    },
    suspicious: {
      bg: 'bg-[#fbbf24]/15',
      border: 'border-[#fbbf24]/60',
      text: 'text-[#fbbf24]',
      label: 'SUSPICIOUS',
      Icon: AlertTriangle
    },
    clean: {
      bg: 'bg-[#34d399]/15',
      border: 'border-[#34d399]/60',
      text: 'text-[#34d399]',
      label: 'CLEAN',
      Icon: CheckCircle2
    },
    unknown: {
      bg: 'bg-[#60a5fa]/15',
      border: 'border-[#60a5fa]/60',
      text: 'text-[#60a5fa]',
      label: 'UNKNOWN',
      Icon: HelpCircle
    }
  };

  const config = configs[verdict] || configs.unknown;
  const Icon = config.Icon;

  const sizeClasses = {
    sm: 'text-[10px] py-0.5 px-1.5 gap-1',
    md: 'text-[11px] py-1 px-2.5 gap-1.5',
    lg: 'text-xs py-1.5 px-3 gap-2'
  };

  const iconSizes = {
    sm: 'w-3 h-3',
    md: 'w-3.5 h-3.5',
    lg: 'w-4 h-4'
  };

  return (
    <div className={`
      inline-flex items-center font-mono font-bold tracking-wider rounded-[6px] border ${config.bg} ${config.border} ${config.text} ${sizeClasses[size]}
    `}>
      <Icon className={`${iconSizes[size]} shrink-0`} />
      <span>{config.label}</span>
      {flaggedRatio && (
        <span className="font-mono text-[10px] opacity-80 pl-1 border-l border-current/30 tabular-nums">
          {flaggedRatio.flagged}/{flaggedRatio.total}
        </span>
      )}
    </div>
  );
};
