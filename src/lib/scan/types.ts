export type Recon = {
  name: string;
  version: string;
  previousVersion: string | null;
  publishedAt: string | null;
  previousPublishedAt: string | null;
  totalVersions: number;
  weeklyDownloads: number | null;
  maintainers: string[];
  publisher: string | null;
  previousPublisher: string | null;
  hasProvenance: boolean;
  previousHadProvenance: boolean;
  scripts: Record<string, string>;
  previousScripts: Record<string, string>;
  repository: string | null;
  tarballSize: number;
  fileCount: number;
  addedFiles: string[];
  largestFiles: { path: string; size: number }[];
};

