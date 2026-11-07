import { describe, expect, it } from 'vitest';
import { categoryEvidence, toolEvidence } from './visual-evidence';
import type { Inventory, Signal } from './types';

const signal = (rule: string, target: string): Signal => ({ rule, target, severity: 'high', label: rule, excerpt: 'reference' });
describe('evidence-only audit graphics', () => {
  it('does not fabricate threat scores or matches for empty input', () => {
    expect(categoryEvidence([]).map(c => [c.level, c.matches.length])).toEqual([[0,0],[0,0],[0,0],[0,0]]);
  });
  it('classifies credential and external-reference rules separately', () => {
    const dimensions = categoryEvidence([signal('secret-ref','read'), signal('exfil','send')]);
    expect(dimensions.map(c => c.matches.map(s => s.rule))).toEqual([[],[],['secret-ref'],['exfil']]);
  });
  it('associates exact tools and nested paths without ambiguous prefixes or transcript attribution', () => {
    const inv: Inventory = {mode:'definitions',source:'input',server:null,transcriptChars:0,tools:['read','read.file'].map(name => ({name,params:[],descLength:0}))};
    expect(toolEvidence(inv,[signal('secret-ref','read.file.path'),signal('exfil','reader'),signal('override','segment 1')]).map(t => t.signals.length)).toEqual([0,1]);
  });
});