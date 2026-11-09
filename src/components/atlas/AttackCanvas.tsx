import { useMemo, useEffect, useRef, useState, useCallback } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  BackgroundVariant,
  Handle,
  Position,
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
  type NodeProps,
  type EdgeProps,
  type Node,
  type ReactFlowInstance,
} from '@xyflow/react';
import dagre from '@dagrejs/dagre';
import {
  Globe,
  Server,
  ShieldAlert,
  KeyRound,
  Database,
  Workflow,
  GitBranch,
  FileCode,
  Package,
  Zap,
  ArrowRight,
  ChevronRight,
  ChevronLeft,
  Flame,
  ExternalLink,
  Wrench,
  AlertTriangle,
  Copy,
  Check,
  Minimize2,
  Maximize2,
} from 'lucide-react';
import type { AttackGraph, GraphEntity, AttackPath, AttackPathStep, Evidence } from '@/lib/atlas/types';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';

type CustomNodeData = {
  entity: GraphEntity;
  isActiveStep?: boolean;
  stepNumber?: number;
  totalSteps?: number;
  isAttackPathMode?: boolean;
};

type EntityNode = Node<CustomNodeData, 'wizNode'>;

const stageIcons: Record<string, typeof Globe> = {
  internet: Globe,
  'public-internet': Globe,
  external: Globe,
  ingress: Globe,
  server: Server,
  compute: Server,
  vulnerability: ShieldAlert,
  privilege: KeyRound,
  identity: KeyRound,
  credential: KeyRound,
  target: Database,
  database: Database,
  workflow: Workflow,
  repository: GitBranch,
  file: FileCode,
  dependency: Package,
  service: Server,
  finding: ShieldAlert,
};

function getCategoryColor(kind: string, severity?: string) {
  if (kind === 'internet' || kind === 'public-internet' || kind === 'external' || kind === 'ingress') {
    return {
      border: 'border-sky-500/60 hover:border-sky-400',
      glow: 'shadow-sky-500/15',
      badge: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
      glyph: 'bg-sky-500/20 text-sky-400',
      tag: 'EXTERNAL INGRESS',
    };
  }
  if (kind === 'server' || kind === 'workflow' || kind === 'service') {
    return {
      border: 'border-indigo-500/60 hover:border-indigo-400',
      glow: 'shadow-indigo-500/15',
      badge: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30',
      glyph: 'bg-indigo-500/20 text-indigo-400',
      tag: 'COMPUTE / RUNTIME',
    };
  }
  if (kind === 'finding') {
    const isCritical = severity === 'high';
    return {
      border: isCritical ? 'border-red-500/80 hover:border-red-400' : 'border-amber-500/80 hover:border-amber-400',
      glow: isCritical ? 'shadow-red-500/30' : 'shadow-amber-500/25',
      badge: isCritical ? 'bg-red-500/20 text-red-400 border-red-500/40' : 'bg-amber-500/20 text-amber-400 border-amber-500/40',
      glyph: isCritical ? 'bg-red-500/25 text-red-400' : 'bg-amber-500/25 text-amber-400',
      tag: isCritical ? 'TOXIC FINDING' : 'RISK CONDITION',
    };
  }
  if (kind === 'identity') {
    return {
      border: 'border-amber-500/60 hover:border-amber-400',
      glow: 'shadow-amber-500/15',
      badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
      glyph: 'bg-amber-500/20 text-amber-400',
      tag: 'PRIVILEGE ESCALATION',
    };
  }
  if (kind === 'target') {
    return {
      border: 'border-rose-500/70 hover:border-rose-400',
      glow: 'shadow-rose-500/25',
      badge: 'bg-rose-500/20 text-rose-400 border-rose-500/40',
      glyph: 'bg-rose-500/25 text-rose-400',
      tag: 'CROWN JEWEL TARGET',
    };
  }
  return {
    border: 'border-border hover:border-muted-foreground/50',
    glow: 'shadow-none',
    badge: 'bg-muted text-muted-foreground border-border',
    glyph: 'bg-secondary text-muted-foreground',
    tag: kind.toUpperCase(),
  };
}

function WizNodeComponent({ data, selected }: NodeProps<EntityNode>) {
  const n = data.entity;
  const rawKind = n.kind || 'file';
  const isInternet =
    rawKind === 'internet' ||
    rawKind === 'public-internet' ||
    rawKind === 'external' ||
    n.id === 'public-internet' ||
    /internet|ingress/i.test(n.label);
  const isDatabase =
    rawKind === 'database' ||
    rawKind === 'target' ||
    n.id === 'backend-datastore' ||
    /database|datastore/i.test(n.label);
  const Icon = isInternet ? Globe : isDatabase ? Database : (stageIcons[rawKind] || FileCode);
  const theme = getCategoryColor(isInternet ? 'internet' : isDatabase ? 'target' : rawKind, n.severity);
  const isActive = data.isActiveStep || selected;
  const isAttackPath = data.isAttackPathMode;

  return (
    <div
      className={cn(
        'relative flex flex-col justify-between rounded-xl border bg-card/95 p-3.5 backdrop-blur-md shadow-md transition-all duration-200 cursor-pointer',
        'w-[320px] min-h-[96px]',
        theme.border,
        theme.glow,
        isAttackPath && 'ring-1 ring-destructive/40 shadow-[0_0_15px_rgba(239,68,68,0.2)]',
        isActive && 'ring-2 ring-destructive ring-offset-2 ring-offset-background scale-[1.04] shadow-[0_0_25px_rgba(239,68,68,0.45)]'
      )}
    >
      <Handle type="target" position={Position.Left} className="!w-2.5 !h-2.5 !bg-muted-foreground !border-background" />

      {/* Top Header Pill */}
      <div className="flex items-center justify-between gap-1 pb-1">
        <span className={cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider border', theme.badge)}>
          {isInternet && <Globe className="size-2.5 animate-pulse" />}
          {rawKind === 'finding' && <Zap className="size-2.5" />}
          {isAttackPath && (rawKind === 'target' || rawKind === 'database') && <Database className="size-2.5 text-rose-400" />}
          {theme.tag}
        </span>
        {isAttackPath && data.stepNumber && (
          <span className="font-mono text-[9px] font-bold text-destructive">
            Step {data.stepNumber}/{data.totalSteps || 5}
          </span>
        )}
      </div>

      {/* Body: Glyph + Titles */}
      <div className="flex items-start gap-3 pt-1">
        <div className={cn('flex size-10 shrink-0 items-center justify-center rounded-lg', theme.glyph)}>
          <Icon className="size-5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-semibold text-foreground leading-snug line-clamp-2 break-words" title={n.label}>
            {n.label}
          </div>
          <div className="text-[11px] text-muted-foreground leading-snug line-clamp-2 mt-0.5 break-words" title={n.subtitle || n.kind}>
            {n.subtitle || n.kind}
          </div>
        </div>
      </div>

      {/* Bottom Badge / Attribute */}
      {n.badge && (
        <div className="mt-2 flex items-center justify-between border-t border-border/50 pt-1 text-[9px] text-muted-foreground">
          <span className="line-clamp-1 break-words">{n.badge}</span>
          <ChevronRight className="size-3 text-muted-foreground/60" />
        </div>
      )}

      <Handle type="source" position={Position.Right} className="!w-2.5 !h-2.5 !bg-primary !border-background" />
    </div>
  );
}


type CustomEdgeData = {
  isPathEdge?: boolean;
  label?: string;
};

function WizEdge({
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  markerEnd,
  data,
  label,
}: EdgeProps) {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    borderRadius: 8,
  });

  const edgeData = data as CustomEdgeData | undefined;
  const isPathEdge = Boolean(edgeData?.isPathEdge);
  const displayLabel = (label as string) || edgeData?.label;

  return (
    <>
      <BaseEdge path={edgePath} markerEnd={markerEnd} style={style} />
      {displayLabel && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              pointerEvents: 'all',
            }}
            className={cn(
              'px-2.5 py-1 rounded-md text-[10px] font-medium tracking-tight border shadow-xs select-none backdrop-blur-sm transition-all',
              isPathEdge
                ? 'bg-destructive/10 text-destructive border-destructive/30 font-semibold shadow-destructive/10'
                : 'bg-card/95 text-foreground/80 border-border/80 hover:text-foreground hover:border-border'
            )}
          >
            {displayLabel}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

const edgeTypes = {
  wizEdge: WizEdge,
};

const nodeTypes = {
  wizNode: WizNodeComponent,
};

export function AttackCanvas({
  graph,
  onSelect,
  search,
  riskOnly = false,
}: {
  graph: AttackGraph;
  onSelect: (ids: string[], label: string) => void;
  search: string;
  riskOnly: boolean;
}) {
  const container = useRef<HTMLDivElement | null>(null);
  const [rfInstance, setRfInstance] = useState<ReactFlowInstance | null>(null);

  // Attack path state
  const paths = useMemo(() => graph.attackPaths || [], [graph.attackPaths]);
  const [selectedPathId, setSelectedPathId] = useState<string>('');
  const [activeStepIdx, setActiveStepIdx] = useState<number>(0);

  // Automatically select the first path when riskOnly is clicked
  useEffect(() => {
    if (riskOnly && paths.length > 0 && !selectedPathId) {
      setSelectedPathId(paths[0].id);
      setActiveStepIdx(0);
    }
  }, [riskOnly, paths, selectedPathId]);

  // Active path is STRICTLY enabled when riskOnly is true!
  const activePath: AttackPath | null = useMemo(() => {
    if (!riskOnly) return null;
    return paths.find(p => p.id === selectedPathId) || paths[0] || null;
  }, [riskOnly, paths, selectedPathId]);

  // Normalize steps to support both steps and legacy stages
  const normalizedSteps = useMemo<AttackPathStep[]>(() => {
    if (!activePath) return [];
    if (Array.isArray(activePath.steps) && activePath.steps.length > 0) {
      return activePath.steps;
    }
    const legacyStages = (activePath as any).stages;
    if (Array.isArray(legacyStages) && legacyStages.length > 0) {
      return legacyStages.map((st: any, idx: number) => ({
        id: `step-${st.order || idx + 1}`,
        nodeId: st.entityId || st.nodeId || 'live-app',
        title: st.label || st.title || `Stage ${idx + 1}`,
        subtitle: st.role || 'Stage',
        stage: (st.role === 'actor' ? 'internet' : st.role === 'workload' ? 'server' : st.role === 'finding' ? 'vulnerability' : st.role === 'privilege' ? 'privilege' : 'target') as any,
        badge: st.role ? st.role.toUpperCase() : 'STEP',
        description: st.description || '',
        remediation: undefined,
        evidenceIds: [],
      }));
    }
    if (graph.findings && graph.findings.length > 0) {
      return graph.findings.map((f, idx) => ({
        id: `step-finding-${idx}`,
        nodeId: f.id,
        title: f.title,
        subtitle: f.rule,
        stage: 'vulnerability' as const,
        badge: f.severity.toUpperCase(),
        description: f.fix,
        remediation: f.fix,
        evidenceIds: f.evidenceIds || [],
      }));
    }
    return [];
  }, [activePath, graph.findings]);

  const activeStep: AttackPathStep | null = useMemo(() => {
    if (!activePath || normalizedSteps.length === 0) return null;
    return normalizedSteps[activeStepIdx] || normalizedSteps[0] || null;
  }, [activePath, normalizedSteps, activeStepIdx]);

  const [inspectModalOpen, setInspectModalOpen] = useState(false);
  const [copiedEvidenceId, setCopiedEvidenceId] = useState<string | null>(null);
  const [isCardMinimized, setIsCardMinimized] = useState(false);

  const activeStepEvidence = useMemo<Evidence[]>(() => {
    if (!activeStep || !graph) return [];
    const directMatches = (graph.evidence || []).filter(e => activeStep.evidenceIds?.includes(e.id));
    if (directMatches.length > 0) return directMatches;
    const node = graph.nodes?.find(n => n.id === activeStep.nodeId);
    if (node && node.evidenceIds?.length) {
      const nodeMatches = (graph.evidence || []).filter(e => node.evidenceIds.includes(e.id));
      if (nodeMatches.length > 0) return nodeMatches;
    }
    return (graph.evidence || []).slice(0, 3);
  }, [activeStep, graph]);

  function copyEvidenceText(text: string, id: string) {
    void navigator.clipboard.writeText(text);
    setCopiedEvidenceId(id);
    setTimeout(() => setCopiedEvidenceId(null), 2000);
  }

  const pathNodeIdsList = useMemo<string[]>(() => {
    if (!activePath) return [];
    if (Array.isArray(activePath.nodeIds) && activePath.nodeIds.length > 0) {
      return activePath.nodeIds;
    }
    const fromSteps = normalizedSteps.map(s => s.nodeId).filter(Boolean);
    if (fromSteps.length > 0) return fromSteps;
    return graph.nodes.map(n => n.id);
  }, [activePath, normalizedSteps, graph.nodes]);

  const pathEdgeIdsList = useMemo<string[]>(() => {
    if (!activePath) return [];
    if (Array.isArray(activePath.edgeIds) && activePath.edgeIds.length > 0) {
      return activePath.edgeIds;
    }
    return graph.edges.map(e => e.id);
  }, [activePath, graph.edges]);

  // Center on node when step changes in attack path mode
  useEffect(() => {
    if (!rfInstance || !activeStep || !riskOnly) return;
    const node = rfInstance.getNode(activeStep.nodeId);
    if (node) {
      rfInstance.setCenter(node.position.x + 160, node.position.y + 50, { duration: 350, zoom: 0.95 });
    }
  }, [activeStep, riskOnly, rfInstance]);

  // Auto-dispatch onSelect when entering attack path mode or switching step so evidence opens immediately
  useEffect(() => {
    if (riskOnly && activeStep) {
      const evIds = activeStep.evidenceIds && activeStep.evidenceIds.length > 0
        ? activeStep.evidenceIds
        : graph.findings[0]?.evidenceIds || [];
      if (evIds.length > 0) {
        onSelect(evIds, activeStep.title);
      }
    }
  }, [riskOnly, activeStep?.id, activePath?.id]);

  // Recalibrate and fit view smoothly when riskOnly changes
  useEffect(() => {
    if (!rfInstance) return;
    const timer = setTimeout(() => {
      rfInstance.fitView({ padding: 0.25, duration: 400 });
    }, 50);
    return () => clearTimeout(timer);
  }, [riskOnly, selectedPathId, rfInstance]);

  // Build nodes and edges
  const { nodes, edges } = useMemo(() => {
    let entities: GraphEntity[] = [];
    let relations = graph.edges;

    if (riskOnly && activePath) {
      // Attack Path Mode: isolate ONLY the nodes and edges belonging to the active toxic path!
      const pathNodeIds = new Set(pathNodeIdsList);
      entities = graph.nodes.filter(n => pathNodeIds.has(n.id));

      if (entities.length === 0) {
        entities = graph.nodes.filter(n => !n.id.startsWith('dep:') || n.id.startsWith('dep:summary:'));
      }

      // Sort in stage order
      const orderMap = new Map(pathNodeIdsList.map((id, idx) => [id, idx]));
      entities.sort((a, b) => (orderMap.get(a.id) ?? 999) - (orderMap.get(b.id) ?? 999));

      const pathEdgeIds = new Set(pathEdgeIdsList);
      relations = graph.edges.filter(e => pathEdgeIds.has(e.id) || (pathNodeIds.has(e.source) && pathNodeIds.has(e.target)));
      if (relations.length === 0) {
        const ids = new Set(entities.map(n => n.id));
        relations = graph.edges.filter(e => ids.has(e.source) && ids.has(e.target));
      }
    } else if (riskOnly) {
      // Risk Only fallback if no synthesized multi-step path: highlight just the risky nodes and connections
      const riskyNodeIds = new Set(['repo', ...graph.edges.filter(e => e.risky).flatMap(e => [e.source, e.target]), ...graph.findings.map(f => f.id)]);
      entities = graph.nodes.filter(n => riskyNodeIds.has(n.id));
      const ids = new Set(entities.map(n => n.id));
      relations = graph.edges.filter(e => ids.has(e.source) && ids.has(e.target) && e.risky);
    } else {
      // Standard Overview Mode: show full graph without individual raw package spam
      entities = graph.nodes.filter(n => !n.id.startsWith('dep:') || n.id.startsWith('dep:summary:'));
      if (search) {
        entities = entities.filter(n => n.label.toLowerCase().includes(search.toLowerCase()));
      }
      const ids = new Set(entities.map(n => n.id));
      relations = graph.edges.filter(e => ids.has(e.source) && ids.has(e.target));
    }

    // Horizontal LR Layout with Dagre
    const layout = new dagre.graphlib.Graph();
    layout.setGraph({ rankdir: 'LR', nodesep: 56, ranksep: 260 });
    layout.setDefaultEdgeLabel(() => ({}));

    entities.forEach(n => layout.setNode(n.id, { width: 320, height: 100 }));
    relations.forEach(e => layout.setEdge(e.source, e.target));
    dagre.layout(layout);

    const mappedNodes = entities.map((n, idx) => {
      const pos = layout.node(n.id) || { x: idx * 280, y: 150 };
      const isCurrentStep = activeStep?.nodeId === n.id;
      return {
        id: n.id,
        type: 'wizNode',
        data: {
          entity: n,
          isActiveStep: isCurrentStep,
          stepNumber: riskOnly && activePath ? idx + 1 : undefined,
          totalSteps: riskOnly && activePath ? entities.length : undefined,
          isAttackPathMode: riskOnly,
        },
        position: { x: pos.x - 160, y: pos.y - 50 },
      };
    });

    const mappedEdges = relations.map(e => {
      const isPathEdge = (riskOnly && pathEdgeIdsList.includes(e.id)) || (riskOnly && e.risky);
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        type: 'wizEdge',
        data: {
          isPathEdge,
          label: e.label,
        },
        label: e.label,
        animated: isPathEdge,
        style: {
          stroke: isPathEdge ? '#ef4444' : '#64748b',
          strokeWidth: isPathEdge ? 2.8 : 1.5,
          filter: isPathEdge ? 'drop-shadow(0 0 7px rgba(239, 68, 68, 0.65))' : undefined,
        },
      };
    });

    return { nodes: mappedNodes, edges: mappedEdges };
  }, [graph, riskOnly, activePath, activeStep, search]);

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      const customNode = node as EntityNode;
      const entity = customNode.data.entity;
      onSelect(entity.evidenceIds, entity.label);

      if (riskOnly && activePath) {
        const stepIndex = normalizedSteps.findIndex(s => s.nodeId === entity.id);
        if (stepIndex !== -1) {
          setActiveStepIdx(stepIndex);
        }
      }
    },
    [riskOnly, activePath, normalizedSteps, onSelect]
  );

  return (
    <div ref={container} className="relative flex flex-col h-full w-full overflow-hidden bg-background">
      {/* Top Wiz-Style Header & Stepper: ONLY VISIBLE WHEN RISK ONLY / ATTACK PATHS IS CLICKED */}
      {riskOnly && activePath && (
        <div className="z-10 flex flex-wrap items-center justify-between gap-3 border-b border-destructive/30 bg-destructive/5 px-4 py-3 backdrop-blur-md">
          {/* Left: Path Selector Tabs */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-destructive flex items-center gap-1.5 mr-2">
              <Flame className="size-4 animate-pulse" />
              <span>Attack Paths:</span>
            </span>

            {paths.map((p, idx) => (
              <Button
                key={p.id}
                size="sm"
                variant={selectedPathId === p.id ? 'default' : 'outline'}
                onClick={() => {
                  setSelectedPathId(p.id);
                  setActiveStepIdx(0);
                }}
                className={cn(
                  'h-8 gap-2 text-xs font-medium',
                  selectedPathId === p.id
                    ? 'bg-destructive text-destructive-foreground hover:bg-destructive/90 shadow-sm'
                    : 'border-destructive/40 text-destructive hover:bg-destructive/10'
                )}
              >
                <Flame className="size-3.5" />
                <span>Path {idx + 1}</span>
                <span className="hidden sm:inline font-mono text-[10px] opacity-90">({p.severity.toUpperCase()})</span>
              </Button>
            ))}
          </div>

          {/* Right: Walkthrough Step Controls */}
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-muted-foreground">
              Step {activeStepIdx + 1} of {normalizedSteps.length}
            </span>
            <div className="flex items-center gap-1">
              <Button
                size="icon"
                variant="outline"
                className="size-7"
                disabled={activeStepIdx <= 0}
                onClick={() => {
                  const next = Math.max(0, activeStepIdx - 1);
                  setActiveStepIdx(next);
                  const step = normalizedSteps[next];
                  if (step) onSelect(step.evidenceIds, step.title);
                }}
                title="Previous step"
              >
                <ChevronLeft className="size-4" />
              </Button>
              <Button
                size="icon"
                variant="outline"
                className="size-7"
                disabled={activeStepIdx >= normalizedSteps.length - 1}
                onClick={() => {
                  const next = Math.min(normalizedSteps.length - 1, activeStepIdx + 1);
                  setActiveStepIdx(next);
                  const step = normalizedSteps[next];
                  if (step) onSelect(step.evidenceIds, step.title);
                }}
                title="Next step"
              >
                <ChevronRight className="size-4" />
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Horizontal Step Breadcrumbs: ONLY VISIBLE WHEN RISK ONLY / ATTACK PATHS IS CLICKED */}
      {riskOnly && activePath && (
        <div className="z-10 flex items-center gap-1 overflow-x-auto border-b border-border/60 bg-muted/30 px-4 py-2 text-xs">
          {normalizedSteps.map((s, idx) => {
            const Icon = stageIcons[s.stage as keyof typeof stageIcons] || Globe;
            const isCurrent = activeStepIdx === idx;
            return (
              <div key={s.id} className="flex items-center gap-1 shrink-0">
                <button
                  type="button"
                  onClick={() => {
                    setActiveStepIdx(idx);
                    onSelect(s.evidenceIds, s.title);
                  }}
                  className={cn(
                    'flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors',
                    isCurrent
                      ? 'bg-destructive text-destructive-foreground shadow-sm'
                      : 'text-muted-foreground hover:bg-accent hover:text-foreground'
                  )}
                >
                  <Icon className="size-3.5" />
                  <span>{s.title}</span>
                </button>
                {idx < normalizedSteps.length - 1 && (
                  <ArrowRight className="size-3 text-muted-foreground/40 shrink-0" />
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* React Flow Canvas */}
      <div className="relative flex-1 min-h-0 w-full">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onInit={instance => {
            setRfInstance(instance);
            instance.fitView({ padding: 0.25 });
          }}
          fitView
          minZoom={0.2}
          maxZoom={1.8}
          nodesDraggable={false}
          nodesConnectable={false}
          onNodeClick={onNodeClick}
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={28} size={1.2} />
          <Controls showInteractive={false} className="!left-4 !bottom-4" />
        </ReactFlow>

        {/* Floating Wiz Walkthrough Card: ONLY VISIBLE WHEN RISK ONLY / ATTACK PATHS IS CLICKED */}
        {riskOnly && activePath && activeStep && (
          <div
            className={cn(
              'absolute bottom-3 right-3 z-20 rounded-lg border border-destructive/40 bg-card/95 shadow-xl backdrop-blur-md ring-1 ring-destructive/20 transition-all duration-200 animate-in fade-in',
              isCardMinimized ? 'w-[260px] p-2.5' : 'w-[290px] max-w-[calc(100vw-2rem)] p-3'
            )}
          >
            <div className="flex items-center justify-between gap-1.5 border-b border-border/80 pb-1.5">
              <span className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-destructive">
                <Flame className="size-3 animate-pulse" />
                Step {activeStepIdx + 1}/{normalizedSteps.length} · {activeStep.badge}
              </span>
              <div className="flex items-center gap-1">
                <span className="font-mono text-[9px] text-muted-foreground uppercase">
                  {activeStep.stage}
                </span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-5 h-5 w-5 p-0 text-muted-foreground hover:text-foreground"
                  aria-label={isCardMinimized ? 'Expand walkthrough card' : 'Minimize walkthrough card'}
                  title={isCardMinimized ? 'Expand' : 'Minimize'}
                  onClick={() => setIsCardMinimized(prev => !prev)}
                >
                  {isCardMinimized ? <Maximize2 className="size-3" /> : <Minimize2 className="size-3" />}
                </Button>
              </div>
            </div>

            {!isCardMinimized ? (
              <>
                <div className="pt-2">
                  <h4 className="text-xs font-semibold text-foreground line-clamp-1">
                    {activeStep.title}
                  </h4>
                  <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground line-clamp-2">
                    {activeStep.description}
                  </p>
                </div>

                {activeStep.remediation && (
                  <div className="mt-2 rounded border border-primary/20 bg-primary/5 p-2 text-[10px]">
                    <div className="flex items-center gap-1 font-medium text-primary text-[10px]">
                      <Wrench className="size-3" />
                      <span>Break Path</span>
                    </div>
                    <p className="mt-0.5 text-[10px] text-muted-foreground line-clamp-2">
                      {activeStep.remediation}
                    </p>
                  </div>
                )}

                <div className="mt-2.5 flex items-center justify-between gap-1 pt-1 border-t border-border/50">
                  <Button
                    variant="secondary"
                    size="sm"
                    className="h-6 px-2 text-[11px] gap-1 font-medium"
                    onClick={() => {
                      onSelect(activeStep.evidenceIds, activeStep.title);
                      setInspectModalOpen(true);
                    }}
                  >
                    <ExternalLink className="size-3" />
                    <span>Inspect Evidence</span>
                  </Button>

                  <div className="flex items-center gap-1">
                    {activeStepIdx > 0 && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-6 h-6 w-6 p-0"
                        title="Previous step"
                        onClick={() => {
                          const prev = activeStepIdx - 1;
                          setActiveStepIdx(prev);
                          const step = normalizedSteps[prev];
                          if (step) onSelect(step.evidenceIds, step.title);
                        }}
                      >
                        <ChevronLeft className="size-3" />
                      </Button>
                    )}
                    {activeStepIdx < normalizedSteps.length - 1 ? (
                      <Button
                        size="sm"
                        className="h-6 px-2 text-[11px] gap-1 bg-destructive text-destructive-foreground hover:bg-destructive/90"
                        onClick={() => {
                          const next = activeStepIdx + 1;
                          setActiveStepIdx(next);
                          const step = normalizedSteps[next];
                          if (step) onSelect(step.evidenceIds, step.title);
                        }}
                      >
                        <span>Next</span>
                        <ChevronRight className="size-3" />
                      </Button>
                    ) : (
                      <span className="text-[9px] font-mono text-muted-foreground uppercase">Done</span>
                    )}
                  </div>
                </div>
              </>
            ) : (
              <div className="mt-1 flex items-center justify-between gap-1">
                <span className="truncate text-[11px] font-medium text-foreground">
                  {activeStep.title}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-5 px-1.5 text-[10px] text-destructive hover:text-destructive"
                  onClick={() => {
                    onSelect(activeStep.evidenceIds, activeStep.title);
                    setInspectModalOpen(true);
                  }}
                >
                  <ExternalLink className="mr-0.5 size-2.5" />
                  Inspect
                </Button>
              </div>
            )}
          </div>
        )}

        {/* Interactive Evidence Inspector Dialog */}
        <Dialog open={inspectModalOpen} onOpenChange={setInspectModalOpen}>
          <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <div className="flex items-center gap-2">
                <span className="rounded bg-destructive/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-destructive uppercase">
                  {activeStep?.badge || 'Evidence'}
                </span>
                <span className="font-mono text-[10px] text-muted-foreground uppercase">
                  Stage: {activeStep?.stage}
                </span>
              </div>
              <DialogTitle className="text-base font-semibold mt-1">
                {activeStep?.title || 'Security Evidence Inspector'}
              </DialogTitle>
              <DialogDescription className="text-xs text-muted-foreground">
                {activeStep?.description || 'Collected forensic evidence and code provenance supporting this attack path step.'}
              </DialogDescription>
            </DialogHeader>

            <div className="mt-4 space-y-4">
              {activeStepEvidence.length > 0 ? (
                activeStepEvidence.map((ev, idx) => (
                  <div key={ev.id || idx} className="rounded-lg border border-border bg-card p-3 shadow-xs">
                    <div className="flex items-center justify-between gap-2 border-b border-border/60 pb-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <FileCode className="size-3.5 text-primary shrink-0" />
                        <span className="font-mono text-xs font-medium text-foreground truncate">
                          {ev.path}
                        </span>
                        {ev.line > 0 && (
                          <span className="font-mono text-[10px] text-muted-foreground shrink-0">
                            :L{ev.line}
                          </span>
                        )}
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 px-2 text-[10px] gap-1 text-muted-foreground hover:text-foreground"
                        onClick={() => copyEvidenceText(ev.excerpt, ev.id)}
                      >
                        {copiedEvidenceId === ev.id ? (
                          <>
                            <Check className="size-3 text-primary" />
                            <span className="text-primary">Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="size-3" />
                            <span>Copy snippet</span>
                          </>
                        )}
                      </Button>
                    </div>

                    <div className="mt-2.5">
                      <pre className="overflow-x-auto rounded bg-muted/60 p-2.5 font-mono text-[11px] text-foreground leading-relaxed whitespace-pre-wrap">
                        {ev.excerpt || '// No source snippet recorded for this evidence item'}
                      </pre>
                    </div>

                    <div className="mt-2 flex items-center justify-between text-[10px] text-muted-foreground">
                      <span className="font-mono">ID: {ev.id}</span>
                      {ev.url && (
                        <a
                          href={ev.url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-primary hover:underline"
                        >
                          <span>Open in source</span>
                          <ExternalLink className="size-2.5" />
                        </a>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div className="rounded-lg border border-dashed border-border p-6 text-center">
                  <AlertTriangle className="size-6 mx-auto text-warning mb-2" />
                  <p className="text-xs font-medium text-foreground">
                    Inferred Attack Trajectory
                  </p>
                  <p className="mt-1 text-[11px] text-muted-foreground max-w-sm mx-auto">
                    This step is inferred from surrounding topological connections and graph reachability rules. No direct single-line file excerpt was associated with this node.
                  </p>
                </div>
              )}

              {activeStep?.remediation && (
                <div className="rounded-lg border border-primary/20 bg-primary/5 p-3 text-xs">
                  <div className="flex items-center gap-1.5 font-medium text-primary text-xs">
                    <Wrench className="size-3.5" />
                    <span>Recommended Remediation to Sever This Link</span>
                  </div>
                  <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
                    {activeStep.remediation}
                  </p>
                </div>
              )}
            </div>

            <div className="mt-4 flex items-center justify-end gap-2 border-t border-border pt-3">
              <Button
                variant="outline"
                size="sm"
                className="h-8 text-xs"
                onClick={() => setInspectModalOpen(false)}
              >
                Close Inspector
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}
