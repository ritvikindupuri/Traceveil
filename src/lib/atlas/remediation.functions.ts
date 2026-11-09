import { createServerFn } from '@tanstack/react-start';
import { runRemediationAgent, type RemediationInput } from './remediation.server';

export type LiveRemediationLog = {
  command?: string;
  output: string[];
  type?: 'cmd' | 'info' | 'success' | 'warn' | 'error';
};

export type LiveRemediationResult = {
  ok: boolean;
  isRealPR: boolean;
  prNumber?: number;
  prUrl: string;
  branchName: string;
  commitSha: string;
  logs: LiveRemediationLog[];
  status: 'completed' | 'failed' | 'needs_auth';
  error?: string;
};

export const executeLiveRemediationPR = createServerFn({ method: 'POST' })
  .validator((input: RemediationInput) => input)
  .handler(async ({ data }): Promise<LiveRemediationResult> => {
    return runRemediationAgent(data);
  });
