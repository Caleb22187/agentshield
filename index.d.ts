export interface Threat {
  id: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  pattern: string;
}

export interface ScanResult {
  clean: boolean;
  threats: Threat[];
  count: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | null;
  categories: string[];
  summary: string;
}

export interface ScanOptions {
  categories?: string[];
  minSeverity?: 'critical' | 'high' | 'medium' | 'low';
}

export function scan(text: string, options?: ScanOptions): ScanResult;
export function scanQuick(text: string): boolean;
export function getCategories(): string[];
export function getRuleCount(): number;
