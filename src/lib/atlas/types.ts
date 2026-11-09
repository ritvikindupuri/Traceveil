export type EntityKind =
  | 'repository'
  | 'file'
  | 'workflow'
  | 'dependency'
  | 'service'
  | 'server'
  | 'internet'
  | 'identity'
  | 'target'
  | 'finding';

export type Evidence = {
  id: string;
  path: string;
  line: number;
  excerpt: string;
  url: string;
  collectedAt: string;
};

export type GraphEntity = {
  id: string;
  label: string;
  kind: EntityKind;
  evidenceIds: string[];
  severity?: 'high' | 'medium' | 'low';
  category?: 'exposure' | 'compute' | 'vulnerability' | 'privilege' | 'target';
  subtitle?: string;
  badge?: string;
  details?: string;
  stepNumber?: number;
};

export type GraphRelation = {
  id: string;
  source: string;
  target: string;
  label: string;
  evidenceIds: string[];
  provenance: 'declared' | 'inferred';
  risky?: boolean;
};

export type Finding = {
  id: string;
  title: string;
  severity: 'high' | 'medium' | 'low';
  evidenceIds: string[];
  rule: string;
  fix: string;
};

export type AttackPathStep = {
  id: string;
  nodeId: string;
  title: string;
  subtitle: string;
  stage: 'internet' | 'server' | 'vulnerability' | 'privilege' | 'target';
  badge: string;
  description: string;
  remediation?: string;
  evidenceIds: string[];
};

export type AttackPath = {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium';
  summary: string;
  steps: AttackPathStep[];
  nodeIds: string[];
  edgeIds: string[];
};

export type AttackGraph = {
  target: string;
  commit: string;
  branch: string;
  nodes: GraphEntity[];
  edges: GraphRelation[];
  evidence: Evidence[];
  findings: Finding[];
  attackPaths?: AttackPath[];
  coverage: { inspected: number; total: number; skipped: number; gaps: string[] };
  collectedAt: string;
};

export type ScanRecord = {
  id: string;
  target: string;
  commit_sha: string;
  graph: AttackGraph;
  reports: Record<string, string>;
  created_at: string;
};
