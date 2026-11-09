import type { AttackGraph, EntityKind, AttackPath, AttackPathStep, GraphEntity, GraphRelation } from './types';
import { redact, validateGraph } from './validation';

export type SourceFile = { path: string; text: string };

export function buildRepositoryGraph(
  target: string,
  commit: string,
  branch: string,
  files: SourceFile[],
  total: number,
  gaps: string[]
): AttackGraph {
  const now = new Date().toISOString();
  const graph: AttackGraph = {
    target,
    commit,
    branch,
    nodes: [],
    edges: [],
    evidence: [],
    findings: [],
    attackPaths: [],
    coverage: { inspected: files.length, total, skipped: Math.max(0, total - files.length), gaps },
    collectedAt: now,
  };

  const evidence = (path: string, line: number, excerpt: string) => {
    const id = `e${graph.evidence.length}`;
    graph.evidence.push({
      id,
      path,
      line,
      excerpt: redact(excerpt).slice(0, 600),
      url: path
        ? `${target}/blob/${commit}/${path.split('/').map(encodeURIComponent).join('/')}#L${line}`
        : `${target}/commit/${commit}`,
      collectedAt: now,
    });
    return id;
  };

  const rootEvidence = evidence('', 1, `Repository snapshot ${commit}`);
  graph.nodes.push({
    id: 'repo',
    label: target.replace('https://github.com/', ''),
    kind: 'repository',
    category: 'compute',
    subtitle: 'Source Code Repository',
    badge: 'Inspected Target',
    evidenceIds: [rootEvidence],
  });

  if (files.length === 0) {
    return validateGraph(graph);
  }

  function addNode(entity: GraphEntity) {
    if (!graph.nodes.some(n => n.id === entity.id)) {
      graph.nodes.push(entity);
    }
  }

  function addEdge(edge: GraphRelation) {
    if (!graph.edges.some(e => e.id === edge.id)) {
      graph.edges.push(edge);
    }
  }

  function addFinding(
    parent: string,
    path: string,
    line: number,
    excerpt: string,
    rule: string,
    title: string,
    fix: string,
    severity: 'high' | 'medium' | 'low' = 'medium'
  ) {
    const e = evidence(path, line, excerpt);
    const id = `f${graph.findings.length}`;
    graph.findings.push({ id, title, severity, evidenceIds: [e], rule, fix });
    addNode({
      id,
      label: title,
      kind: 'finding',
      severity,
      category: 'vulnerability',
      subtitle: `Rule: ${rule}`,
      badge: `${severity.toUpperCase()} SEVERITY`,
      evidenceIds: [e],
    });
    addEdge({
      id: `r${graph.edges.length}`,
      source: parent,
      target: id,
      label: 'has risk',
      evidenceIds: [e],
      provenance: 'declared',
      risky: true,
    });
    return { id, evidenceId: e };
  }

  // Scan files and collect findings
  for (const file of files) {
    const kind: EntityKind = file.path.startsWith('.github/workflows/') ? 'workflow' : 'file';
    const fileId = `file:${file.path}`;
    const e = evidence(file.path, 1, file.text.split('\n')[0] ?? '');
    addNode({
      id: fileId,
      label: file.path,
      kind,
      category: 'compute',
      subtitle: kind === 'workflow' ? 'GitHub Actions CI/CD' : 'Source Manifest',
      badge: kind === 'workflow' ? 'Automation' : 'Config',
      evidenceIds: [e],
    });
    addEdge({
      id: `r${graph.edges.length}`,
      source: 'repo',
      target: fileId,
      label: 'declares',
      evidenceIds: [e],
      provenance: 'declared',
    });

    if (file.path.endsWith('package.json')) {
      try {
        const json = JSON.parse(file.text);
        const deps = { ...json.dependencies, ...json.devDependencies };
        const depNames = Object.keys(deps);
        if (depNames.length > 0) {
          const firstLine = Math.max(1, file.text.split('\n').findIndex(l => l.includes('"dependencies"')) + 1);
          const ev = evidence(file.path, firstLine, `Dependencies: ${depNames.slice(0, 10).join(', ')}... (${depNames.length} total)`);
          addNode({
            id: `dep:summary:${file.path}`,
            label: `Dependencies (${depNames.length} packages)`,
            kind: 'dependency',
            category: 'compute',
            subtitle: `${depNames.length} npm packages declared`,
            badge: 'Supply Chain',
            details: depNames.slice(0, 25).join(', ') + (depNames.length > 25 ? ` and ${depNames.length - 25} more` : ''),
            evidenceIds: [ev],
          });
          addEdge({
            id: `r${graph.edges.length}`,
            source: fileId,
            target: `dep:summary:${file.path}`,
            label: 'depends on',
            evidenceIds: [ev],
            provenance: 'declared',
          });
        }
      } catch {
        graph.coverage.gaps.push(`Unparsed manifest: ${file.path}`);
      }
    }

    const lines = file.text.split('\n');
    lines.forEach((text, i) => {
      if (kind === 'workflow' && /uses:\s*[\w.-]+\/[\w./-]+@/.test(text) && !/@[a-f0-9]{40}\b/i.test(text)) {
        addFinding(fileId, file.path, i + 1, text, 'mutable-action', 'Unpinned workflow action', 'Pin the action to a reviewed full commit SHA.');
      }
      if (kind === 'workflow' && /permissions:\s*write-all\b/.test(text)) {
        addFinding(fileId, file.path, i + 1, text, 'workflow-write', 'Broad workflow write permission', 'Replace write-all with the minimum explicit permissions.', 'high');
      }
      if (/privileged:\s*true\b/.test(text)) {
        addFinding(fileId, file.path, i + 1, text, 'privileged', 'Privileged container declared', 'Disable privileged mode and grant only required capabilities.', 'high');
      }
      if (/(?:0\.0\.0\.0\/0|::\/0)/.test(text)) {
        addFinding(fileId, file.path, i + 1, text, 'public-cidr', 'Unrestricted network range declared', 'Restrict this range to the required callers; verify deployed exposure.');
      }
      if (/^\s*USER\s+root\b/i.test(text) && /Dockerfile/i.test(file.path)) {
        addFinding(fileId, file.path, i + 1, text, 'root-user', 'Root container user declared', 'Use a dedicated non-root user and verify file permissions.');
      }
      if (/-----BEGIN [^-]*PRIVATE KEY-----/.test(text) || /\b(?:ghp_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16})\b/.test(text)) {
        addFinding(fileId, file.path, i + 1, '[REDACTED credential pattern]', 'credential-pattern', 'Potential committed credential', 'Remove the credential, rotate it through its owner, and review history. Never test the credential.', 'high');
      }
    });
  }

  // Synthesize Wiz-Style Attack Paths
  // If there are high or critical findings, construct full 5-stage toxic attack paths
  const attackPaths: AttackPath[] = [];

  const workflowWriteFinding = graph.findings.find(f => f.rule === 'workflow-write');
  const mutableActionFinding = graph.findings.find(f => f.rule === 'mutable-action');
  const credentialFinding = graph.findings.find(f => f.rule === 'credential-pattern');
  const privilegedFinding = graph.findings.find(f => f.rule === 'privileged');
  const publicCidrFinding = graph.findings.find(f => f.rule === 'public-cidr');

  // Attack Path 1: CI/CD Supply Chain Compromise
  if (workflowWriteFinding || mutableActionFinding) {
    const primaryFinding = workflowWriteFinding || mutableActionFinding!;
    const fNode = graph.nodes.find(n => n.id === primaryFinding.id)!;
    const fEvId = primaryFinding.evidenceIds[0] || rootEvidence;

    const internetNode: GraphEntity = {
      id: 'ap:internet:ci',
      label: 'Public Internet',
      kind: 'internet',
      category: 'exposure',
      subtitle: 'External Pull Request / Webhook',
      badge: 'Public Exposure',
      evidenceIds: [fEvId],
    };
    const runnerNode: GraphEntity = {
      id: 'ap:runner:ci',
      label: 'GitHub Actions Runner',
      kind: 'server',
      category: 'compute',
      subtitle: 'CI/CD Automation Environment',
      badge: 'Exposed Server',
      evidenceIds: [fEvId],
    };
    const tokenNode: GraphEntity = {
      id: 'ap:token:write',
      label: 'GITHUB_TOKEN (write-all)',
      kind: 'identity',
      category: 'privilege',
      subtitle: 'Elevated Repository Permissions',
      badge: 'Write Token',
      evidenceIds: [fEvId],
    };
    const releaseNode: GraphEntity = {
      id: 'ap:target:release',
      label: 'Production Release Pipeline',
      kind: 'target',
      category: 'target',
      subtitle: 'Package Registry & Deployed Artifacts',
      badge: 'Crown Jewel',
      evidenceIds: [fEvId],
    };

    addNode(internetNode);
    addNode(runnerNode);
    addNode(tokenNode);
    addNode(releaseNode);

    const edge1: GraphRelation = { id: `ap:e1:${primaryFinding.id}`, source: internetNode.id, target: runnerNode.id, label: 'Inbound Ingress', evidenceIds: [fEvId], provenance: 'inferred', risky: true };
    const edge2: GraphRelation = { id: `ap:e2:${primaryFinding.id}`, source: runnerNode.id, target: fNode.id, label: 'Executes With', evidenceIds: [fEvId], provenance: 'inferred', risky: true };
    const edge3: GraphRelation = { id: `ap:e3:${primaryFinding.id}`, source: fNode.id, target: tokenNode.id, label: 'Grants Access', evidenceIds: [fEvId], provenance: 'inferred', risky: true };
    const edge4: GraphRelation = { id: `ap:e4:${primaryFinding.id}`, source: tokenNode.id, target: releaseNode.id, label: 'Compromises Pipeline', evidenceIds: [fEvId], provenance: 'inferred', risky: true };

    addEdge(edge1);
    addEdge(edge2);
    addEdge(edge3);
    addEdge(edge4);

    const steps: AttackPathStep[] = [
      {
        id: 'step-1',
        nodeId: internetNode.id,
        title: 'Public Internet Exposure',
        subtitle: 'External Attacker Ingress',
        stage: 'internet',
        badge: 'External Exposure',
        description: 'An untrusted external actor submits a malicious pull request or triggers an untrusted webhook payload against the public repository.',
        evidenceIds: [fEvId],
      },
      {
        id: 'step-2',
        nodeId: runnerNode.id,
        title: 'CI/CD Automation Runner',
        subtitle: 'GitHub Actions Compute Context',
        stage: 'server',
        badge: 'Exposed Server',
        description: 'The automated workflow runner spins up and executes build tasks inside the repository context.',
        evidenceIds: [fEvId],
      },
      {
        id: 'step-3',
        nodeId: fNode.id,
        title: primaryFinding.title,
        subtitle: 'Toxic Risk Condition',
        stage: 'vulnerability',
        badge: `${primaryFinding.severity.toUpperCase()} RISK`,
        description: primaryFinding.rule === 'workflow-write'
          ? 'Workflow is configured with global "permissions: write-all", granting write privileges across repository packages, releases, and branches.'
          : 'Workflow action is not pinned to an immutable commit SHA, enabling supply-chain tag mutation or upstream dependency poisoning.',
        remediation: primaryFinding.fix,
        evidenceIds: [fEvId],
      },
      {
        id: 'step-4',
        nodeId: tokenNode.id,
        title: 'Elevated GITHUB_TOKEN',
        subtitle: 'Lateral Movement & Privilege Escalation',
        stage: 'privilege',
        badge: 'Write Access',
        description: 'Attacker leverages the overly permissive runner token to push modified release binaries or create backdoor git tags.',
        evidenceIds: [fEvId],
      },
      {
        id: 'step-5',
        nodeId: releaseNode.id,
        title: 'Production Release & Supply Chain',
        subtitle: 'Crown Jewel Impact',
        stage: 'target',
        badge: 'Crown Jewel',
        description: 'Malicious artifacts enter production deployments and downstream customer consumers.',
        remediation: 'Restrict workflow permissions to minimum read-only scope and require pull request review on sensitive environments.',
        evidenceIds: [fEvId],
      },
    ];

    attackPaths.push({
      id: 'path-supply-chain',
      title: 'Internet ➔ CI Runner ➔ Permissive Token ➔ Release Pipeline',
      severity: 'critical',
      summary: 'External pull request triggers workflow running with write-all permissions, compromising the production release pipeline.',
      steps,
      nodeIds: [internetNode.id, runnerNode.id, fNode.id, tokenNode.id, releaseNode.id],
      edgeIds: [edge1.id, edge2.id, edge3.id, edge4.id],
    });
  }

  // Attack Path 2: Credential Exposure / Secrets in Source
  if (credentialFinding) {
    const fNode = graph.nodes.find(n => n.id === credentialFinding.id)!;
    const fEvId = credentialFinding.evidenceIds[0] || rootEvidence;

    const internetNode: GraphEntity = {
      id: 'ap:internet:cred',
      label: 'Public Internet',
      kind: 'internet',
      category: 'exposure',
      subtitle: 'Public Repository Cloner',
      badge: 'Public Exposure',
      evidenceIds: [fEvId],
    };
    const repoServerNode: GraphEntity = {
      id: 'ap:repo:public',
      label: 'Public Git Repository',
      kind: 'server',
      category: 'compute',
      subtitle: 'Publicly Reachable Commit History',
      badge: 'Exposed Server',
      evidenceIds: [fEvId],
    };
    const identityNode: GraphEntity = {
      id: 'ap:identity:cred',
      label: 'Exposed Production API Key',
      kind: 'identity',
      category: 'privilege',
      subtitle: 'Hardcoded Secret / Private Key',
      badge: 'Extracted Credential',
      evidenceIds: [fEvId],
    };
    const targetNode: GraphEntity = {
      id: 'ap:target:cloud',
      label: 'Cloud Infrastructure & Database',
      kind: 'target',
      category: 'target',
      subtitle: 'Production Data & Cloud APIs',
      badge: 'Crown Jewel',
      evidenceIds: [fEvId],
    };

    addNode(internetNode);
    addNode(repoServerNode);
    addNode(identityNode);
    addNode(targetNode);

    const edge1: GraphRelation = { id: `ap:e1:${credentialFinding.id}`, source: internetNode.id, target: repoServerNode.id, label: 'Public Clone', evidenceIds: [fEvId], provenance: 'inferred', risky: true };
    const edge2: GraphRelation = { id: `ap:e2:${credentialFinding.id}`, source: repoServerNode.id, target: fNode.id, label: 'Contains Secret', evidenceIds: [fEvId], provenance: 'inferred', risky: true };
    const edge3: GraphRelation = { id: `ap:e3:${credentialFinding.id}`, source: fNode.id, target: identityNode.id, label: 'Harvests Token', evidenceIds: [fEvId], provenance: 'inferred', risky: true };
    const edge4: GraphRelation = { id: `ap:e4:${credentialFinding.id}`, source: identityNode.id, target: targetNode.id, label: 'Authenticates To', evidenceIds: [fEvId], provenance: 'inferred', risky: true };

    addEdge(edge1);
    addEdge(edge2);
    addEdge(edge3);
    addEdge(edge4);

    attackPaths.push({
      id: 'path-credential-leak',
      title: 'Internet ➔ Public Git ➔ Hardcoded Secret ➔ Cloud Infrastructure',
      severity: 'critical',
      summary: 'Public clone reveals hardcoded production secret, allowing unauthorized authentication to internal cloud infrastructure.',
      steps: [
        {
          id: 'step-cred-1',
          nodeId: internetNode.id,
          title: 'Public Internet Exposure',
          subtitle: 'External Attacker',
          stage: 'internet',
          badge: 'External Exposure',
          description: 'Any external party on the internet can clone the public repository.',
          evidenceIds: [fEvId],
        },
        {
          id: 'step-cred-2',
          nodeId: repoServerNode.id,
          title: 'Public Git History',
          subtitle: 'Version Control Storage',
          stage: 'server',
          badge: 'Exposed Server',
          description: 'Git history and committed files are publicly indexed and readable.',
          evidenceIds: [fEvId],
        },
        {
          id: 'step-cred-3',
          nodeId: fNode.id,
          title: credentialFinding.title,
          subtitle: 'Toxic Risk Condition',
          stage: 'vulnerability',
          badge: 'CRITICAL RISK',
          description: 'High-entropy secret or private key pattern detected directly in committed repository source.',
          remediation: credentialFinding.fix,
          evidenceIds: [fEvId],
        },
        {
          id: 'step-cred-4',
          nodeId: identityNode.id,
          title: 'Stolen Service Credential',
          subtitle: 'Privilege Escalation',
          stage: 'privilege',
          badge: 'Admin Access',
          description: 'Attacker extracts and validates the exposed token against upstream provider endpoints.',
          evidenceIds: [fEvId],
        },
        {
          id: 'step-cred-5',
          nodeId: targetNode.id,
          title: 'Internal Cloud & Database Target',
          subtitle: 'Crown Jewel Impact',
          stage: 'target',
          badge: 'Crown Jewel',
          description: 'Unauthorized data access, customer data exfiltration, or cloud resource manipulation.',
          remediation: 'Immediately revoke and rotate the credential. Scrub git history using git-filter-repo.',
          evidenceIds: [fEvId],
        },
      ],
      nodeIds: [internetNode.id, repoServerNode.id, fNode.id, identityNode.id, targetNode.id],
      edgeIds: [edge1.id, edge2.id, edge3.id, edge4.id],
    });
  }

  // Attack Path 3: Container / Workload Privilege Escalation
  if (privilegedFinding || publicCidrFinding) {
    const primaryFinding = privilegedFinding || publicCidrFinding!;
    const fNode = graph.nodes.find(n => n.id === primaryFinding.id)!;
    const fEvId = primaryFinding.evidenceIds[0] || rootEvidence;

    const internetNode: GraphEntity = {
      id: 'ap:internet:workload',
      label: 'Public Internet',
      kind: 'internet',
      category: 'exposure',
      subtitle: 'Inbound 0.0.0.0/0 Traffic',
      badge: 'Public Exposure',
      evidenceIds: [fEvId],
    };
    const containerNode: GraphEntity = {
      id: 'ap:server:container',
      label: 'Container Workload',
      kind: 'server',
      category: 'compute',
      subtitle: 'Docker / Kubernetes Pod',
      badge: 'Exposed Server',
      evidenceIds: [fEvId],
    };
    const rootNode: GraphEntity = {
      id: 'ap:identity:root',
      label: 'Host Root Privileges',
      kind: 'identity',
      category: 'privilege',
      subtitle: 'CAP_SYS_ADMIN / Privileged Mode',
      badge: 'Host Escape',
      evidenceIds: [fEvId],
    };
    const hostNode: GraphEntity = {
      id: 'ap:target:host',
      label: 'Host Node & Cluster Kernel',
      kind: 'target',
      category: 'target',
      subtitle: 'Underlying Node & Sensitive Secrets',
      badge: 'Crown Jewel',
      evidenceIds: [fEvId],
    };

    addNode(internetNode);
    addNode(containerNode);
    addNode(rootNode);
    addNode(hostNode);

    const edge1: GraphRelation = { id: `ap:e1:${primaryFinding.id}`, source: internetNode.id, target: containerNode.id, label: 'Inbound Connection', evidenceIds: [fEvId], provenance: 'inferred', risky: true };
    const edge2: GraphRelation = { id: `ap:e2:${primaryFinding.id}`, source: containerNode.id, target: fNode.id, label: 'Misconfigured In', evidenceIds: [fEvId], provenance: 'inferred', risky: true };
    const edge3: GraphRelation = { id: `ap:e3:${primaryFinding.id}`, source: fNode.id, target: rootNode.id, label: 'Container Breakout', evidenceIds: [fEvId], provenance: 'inferred', risky: true };
    const edge4: GraphRelation = { id: `ap:e4:${primaryFinding.id}`, source: rootNode.id, target: hostNode.id, label: 'Host System Takeover', evidenceIds: [fEvId], provenance: 'inferred', risky: true };

    addEdge(edge1);
    addEdge(edge2);
    addEdge(edge3);
    addEdge(edge4);

    attackPaths.push({
      id: 'path-container-escape',
      title: 'Internet ➔ Exposed Container ➔ Privileged Mode ➔ Host Takeover',
      severity: 'high',
      summary: 'Public network exposure combined with privileged container configuration allows container breakout to host kernel.',
      steps: [
        {
          id: 'step-pod-1',
          nodeId: internetNode.id,
          title: 'Public Internet Exposure',
          subtitle: 'Unrestricted Ingress',
          stage: 'internet',
          badge: '0.0.0.0/0',
          description: 'Workload allows inbound traffic from unrestricted public IP space.',
          evidenceIds: [fEvId],
        },
        {
          id: 'step-pod-2',
          nodeId: containerNode.id,
          title: 'Container Workload',
          subtitle: 'Application Container',
          stage: 'server',
          badge: 'Exposed Server',
          description: 'Container executes web services or background workers.',
          evidenceIds: [fEvId],
        },
        {
          id: 'step-pod-3',
          nodeId: fNode.id,
          title: primaryFinding.title,
          subtitle: 'Toxic Risk Condition',
          stage: 'vulnerability',
          badge: 'HIGH RISK',
          description: 'Container is declared with privileged: true or root user permissions, weakening kernel isolation.',
          remediation: primaryFinding.fix,
          evidenceIds: [fEvId],
        },
        {
          id: 'step-pod-4',
          nodeId: rootNode.id,
          title: 'Root Escalation & Escape',
          subtitle: 'Privilege Escalation',
          stage: 'privilege',
          badge: 'Root Access',
          description: 'Attacker leverages container capabilities to access host devices via /dev.',
          evidenceIds: [fEvId],
        },
        {
          id: 'step-pod-5',
          nodeId: hostNode.id,
          title: 'Host Node & Adjacent Containers',
          subtitle: 'Crown Jewel Impact',
          stage: 'target',
          badge: 'Crown Jewel',
          description: 'Full compromise of Kubernetes worker node and co-located tenant workloads.',
          remediation: 'Run as non-root user (USER 10001) and drop all Linux capabilities (cap_drop: ALL).',
          evidenceIds: [fEvId],
        },
      ],
      nodeIds: [internetNode.id, containerNode.id, fNode.id, rootNode.id, hostNode.id],
      edgeIds: [edge1.id, edge2.id, edge3.id, edge4.id],
    });
  }

  // Baseline Exposure Path when no findings exist
  if (attackPaths.length === 0 && files.length > 0) {
    const internetNode: GraphEntity = {
      id: 'ap:internet:baseline',
      label: 'Public Internet',
      kind: 'internet',
      category: 'exposure',
      subtitle: 'Public Repository Access',
      badge: 'Public Exposure',
      evidenceIds: [rootEvidence],
    };
    const appServerNode: GraphEntity = {
      id: 'ap:server:baseline',
      label: 'Application Server / Source',
      kind: 'server',
      category: 'compute',
      subtitle: 'Verified Repository Files',
      badge: 'Healthy Baseline',
      evidenceIds: [rootEvidence],
    };
    const secureTargetNode: GraphEntity = {
      id: 'ap:target:baseline',
      label: 'Secure Production Target',
      kind: 'target',
      category: 'target',
      subtitle: 'No Active Attack Paths Detected',
      badge: 'Verified Clean',
      evidenceIds: [rootEvidence],
    };

    addNode(internetNode);
    addNode(appServerNode);
    addNode(secureTargetNode);

    const edge1: GraphRelation = { id: 'ap:e1:baseline', source: internetNode.id, target: appServerNode.id, label: 'Public Ingress', evidenceIds: [rootEvidence], provenance: 'declared' };
    const edge2: GraphRelation = { id: 'ap:e2:baseline', source: appServerNode.id, target: secureTargetNode.id, label: 'Clean Pipeline', evidenceIds: [rootEvidence], provenance: 'declared' };

    addEdge(edge1);
    addEdge(edge2);

    attackPaths.push({
      id: 'path-baseline',
      title: 'Baseline Ingress · 0 Toxic Attack Paths',
      severity: 'medium',
      summary: 'Public repository exposure verified. Inspected configuration files contain no toxic vulnerability or privilege escalation chains.',
      steps: [
        {
          id: 'step-base-1',
          nodeId: internetNode.id,
          title: 'Public Internet Exposure',
          subtitle: 'External Reachability',
          stage: 'internet',
          badge: 'Public',
          description: 'Repository is publicly accessible over HTTPS.',
          evidenceIds: [rootEvidence],
        },
        {
          id: 'step-base-2',
          nodeId: appServerNode.id,
          title: 'Application Server / Source',
          subtitle: 'Inspected Codebase',
          stage: 'server',
          badge: 'Clean State',
          description: `${files.length} configuration, manifest, and source files inspected.`,
          evidenceIds: [rootEvidence],
        },
        {
          id: 'step-base-3',
          nodeId: secureTargetNode.id,
          title: 'Verified Secure Target',
          subtitle: 'No Attack Paths',
          stage: 'target',
          badge: 'Verified Clean',
          description: 'No unpinned actions, write-all permissions, or exposed secrets detected.',
          evidenceIds: [rootEvidence],
        },
      ],
      nodeIds: [internetNode.id, appServerNode.id, secureTargetNode.id],
      edgeIds: [edge1.id, edge2.id],
    });
  }

  graph.attackPaths = attackPaths;
  return validateGraph(graph);
}
