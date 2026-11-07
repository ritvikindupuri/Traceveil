import type { Inventory, Sev, Signal } from './types';

export const threatCategories = [
  { name: 'Tool Steering', rules: ['cross-tool', 'shadowing', 'coercion', 'override', 'hidden-directive', 'concealment'] },
  { name: 'Prompt Injection', rules: ['override', 'hidden-directive', 'concealment', 'encoded', 'invisible'] },
  { name: 'Credential Scraping', rules: ['secret-ref', 'sensitive-path'] },
  { name: 'Exfiltration Risk', rules: ['exfil', 'redirect'] },
];
export const severityLevel: Record<Sev, number> = { low: 1, medium: 2, high: 3, critical: 4 };

export function categoryEvidence(signals: Signal[]) {
  return threatCategories.map(category => {
    const matches = signals.filter(s => category.rules.includes(s.rule));
    const level = Math.max(0, ...matches.map(s => severityLevel[s.severity]));
    return { ...category, matches, level };
  });
}

export function toolEvidence(inventory: Inventory, signals: Signal[]) {
  const names = [...new Set(inventory.tools.map(t => t.name))];
  return names.map(name => ({
    name,
    signals: signals.filter(s => {
      const owner = names.filter(n => s.target === n || s.target.startsWith(`${n}.`)).sort((a,b) => b.length - a.length)[0];
      return owner === name;
    }),
  }));
}

export const referenceTargets = [
  { name: 'Credentials', rules: ['secret-ref'] },
  { name: 'Sensitive files', rules: ['sensitive-path'] },
  { name: 'External destination', rules: ['exfil', 'redirect'] },
];