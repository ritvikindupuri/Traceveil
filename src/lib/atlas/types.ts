export type EntityKind = 'repository' | 'file' | 'workflow' | 'dependency' | 'service' | 'finding';
export type Evidence = { id: string; path: string; line: number; excerpt: string; url: string; collectedAt: string };
export type GraphEntity = { id: string; label: string; kind: EntityKind; evidenceIds: string[]; severity?: 'high' | 'medium' | 'low' };
export type GraphRelation = { id: string; source: string; target: string; label: string; evidenceIds: string[]; provenance: 'declared' | 'inferred'; risky?: boolean };
export type Finding = { id: string; title: string; severity: 'high' | 'medium' | 'low'; evidenceIds: string[]; rule: string; fix: string };
export type AttackGraph = { target: string; commit: string; branch: string; nodes: GraphEntity[]; edges: GraphRelation[]; evidence: Evidence[]; findings: Finding[]; coverage: { inspected: number; total: number; skipped: number; gaps: string[] }; collectedAt: string };
export type ScanRecord = { id: string; target: string; commit_sha: string; graph: AttackGraph; reports: Record<string,string>; created_at: string };
