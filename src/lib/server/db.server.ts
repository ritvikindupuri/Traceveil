import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export interface DbUser {
  id: string;
  email: string;
  password_hash: string;
  created_at: string;
}

export interface DbSession {
  id: string;
  token: string;
  user_id: string;
  expires_at: string;
  created_at: string;
}

export interface StoreData {
  users: DbUser[];
  sessions: DbSession[];
  application_scans: Array<Record<string, unknown>>;
  github_credentials: Array<Record<string, unknown>>;
  guardrail_policies: Array<Record<string, unknown>>;
  mcp_connections: Array<Record<string, unknown>>;
  audit_records: Array<Record<string, unknown>>;
  tool_approvals: Array<Record<string, unknown>>;
  enforcement_events: Array<Record<string, unknown>>;
  tenant_verification_plans: Array<Record<string, unknown>>;
  tenant_verification_runs: Array<Record<string, unknown>>;
}

const DATA_DIR = path.resolve(process.cwd(), 'data');
const STORE_FILE = path.join(DATA_DIR, 'traceveil-store.json');

function initStore(): StoreData {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(STORE_FILE)) {
    const initial: StoreData = {
      users: [],
      sessions: [],
      application_scans: [],
      github_credentials: [],
      guardrail_policies: [],
      mcp_connections: [],
      audit_records: [],
      tool_approvals: [],
      enforcement_events: [],
      tenant_verification_plans: [],
      tenant_verification_runs: [],
    };
    fs.writeFileSync(STORE_FILE, JSON.stringify(initial, null, 2), 'utf-8');
    return initial;
  }
  try {
    const content = fs.readFileSync(STORE_FILE, 'utf-8');
    const parsed = JSON.parse(content);
    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
      application_scans: Array.isArray(parsed.application_scans) ? parsed.application_scans : [],
      github_credentials: Array.isArray(parsed.github_credentials) ? parsed.github_credentials : [],
      guardrail_policies: Array.isArray(parsed.guardrail_policies) ? parsed.guardrail_policies : [],
      mcp_connections: Array.isArray(parsed.mcp_connections) ? parsed.mcp_connections : [],
      audit_records: Array.isArray(parsed.audit_records) ? parsed.audit_records : [],
      tool_approvals: Array.isArray(parsed.tool_approvals) ? parsed.tool_approvals : [],
      enforcement_events: Array.isArray(parsed.enforcement_events) ? parsed.enforcement_events : [],
      tenant_verification_plans: Array.isArray(parsed.tenant_verification_plans) ? parsed.tenant_verification_plans : [],
      tenant_verification_runs: Array.isArray(parsed.tenant_verification_runs) ? parsed.tenant_verification_runs : [],
    };
  } catch {
    return {
      users: [],
      sessions: [],
      application_scans: [],
      github_credentials: [],
      guardrail_policies: [],
      mcp_connections: [],
      audit_records: [],
      tool_approvals: [],
      enforcement_events: [],
      tenant_verification_plans: [],
      tenant_verification_runs: [],
    };
  }
}

let store: StoreData = initStore();

function persistStore() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    const tempFile = `${STORE_FILE}.${Date.now()}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(store, null, 2), 'utf-8');
    fs.renameSync(tempFile, STORE_FILE);
  } catch (err) {
    console.error('[db.server] Failed to persist store:', err);
  }
}

// Password hashing with scrypt
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  try {
    const parts = storedHash.split(':');
    if (parts.length !== 2) return false;
    const [salt, expectedHash] = parts;
    const testHash = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(testHash, 'hex'), Buffer.from(expectedHash, 'hex'));
  } catch {
    return false;
  }
}

// User & Session Management
export function findUserByEmail(email: string): DbUser | null {
  const normalized = email.trim().toLowerCase();
  return store.users.find(u => u.email.toLowerCase() === normalized) || null;
}

export function findUserById(id: string): DbUser | null {
  return store.users.find(u => u.id === id) || null;
}

export function createUser(email: string, password: string): { user: { id: string; email: string }; error: string | null } {
  const normalized = email.trim().toLowerCase();
  if (!normalized.includes('@') || !normalized.includes('.')) {
    return { user: { id: '', email: '' }, error: 'Please enter a valid email address.' };
  }
  if (!password || password.length < 8) {
    return { user: { id: '', email: '' }, error: 'Password must be at least 8 characters long.' };
  }
  if (findUserByEmail(normalized)) {
    return { user: { id: '', email: '' }, error: 'An account with this email already exists. Please sign in.' };
  }
  const id = crypto.randomUUID();
  const password_hash = hashPassword(password);
  const newUser: DbUser = {
    id,
    email: normalized,
    password_hash,
    created_at: new Date().toISOString(),
  };
  store.users.push(newUser);
  persistStore();
  return { user: { id, email: normalized }, error: null };
}

export function createSession(userId: string): DbSession {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date();
  expires.setDate(expires.getDate() + 30);
  const session: DbSession = {
    id: crypto.randomUUID(),
    token,
    user_id: userId,
    expires_at: expires.toISOString(),
    created_at: new Date().toISOString(),
  };
  store.sessions.push(session);
  persistStore();
  return session;
}

export function getSessionByToken(token: string): { session: DbSession; user: { id: string; email: string } } | null {
  if (!token) return null;
  const session = store.sessions.find(s => s.token === token);
  if (!session) return null;
  if (new Date(session.expires_at).getTime() < Date.now()) {
    deleteSession(token);
    return null;
  }
  const user = findUserById(session.user_id);
  if (!user) return null;
  return { session, user: { id: user.id, email: user.email } };
}

export function deleteSession(token: string): void {
  store.sessions = store.sessions.filter(s => s.token !== token);
  persistStore();
}

export function updateUserPassword(userId: string, newPassword: string): boolean {
  if (!newPassword || newPassword.length < 8) return false;
  const user = findUserById(userId);
  if (!user) return false;
  user.password_hash = hashPassword(newPassword);
  persistStore();
  return true;
}

// Fluent Query Builder
class QueryBuilder {
  private tableName: keyof StoreData;
  private filters: Array<(row: Record<string, unknown>) => boolean> = [];
  private orderField: string | null = null;
  private orderAscending = true;
  private limitCount: number | null = null;
  private pendingOp: (() => unknown) | null = null;
  private selectedColumns: string[] | null = null;

  constructor(table: keyof StoreData) {
    this.tableName = table;
  }

  select(columns = '*'): this {
    if (columns !== '*') {
      this.selectedColumns = columns.split(',').map(c => c.trim());
    }
    return this;
  }

  eq(column: string, value: unknown): this {
    this.filters.push(row => row[column] === value);
    return this;
  }

  order(column: string, options: { ascending?: boolean } = {}): this {
    this.orderField = column;
    this.orderAscending = options.ascending ?? true;
    return this;
  }

  limit(count: number): this {
    this.limitCount = count;
    return this;
  }

  insert(values: Record<string, unknown> | Array<Record<string, unknown>>): this {
    this.pendingOp = () => {
      const rows = (Array.isArray(values) ? values : [values]).map(v => {
        const row = { id: crypto.randomUUID(), created_at: new Date().toISOString(), ...v };
        return row;
      });
      const table = (store[this.tableName] || (store[this.tableName] = [])) as Array<Record<string, unknown>>;
      table.push(...rows);
      persistStore();
      return Array.isArray(values) ? rows : rows[0];
    };
    return this;
  }

  update(values: Record<string, unknown>): this {
    this.pendingOp = () => {
      const table = (store[this.tableName] || []) as Array<Record<string, unknown>>;
      const updated: Array<Record<string, unknown>> = [];
      for (const row of table) {
        if (this.filters.every(fn => fn(row))) {
          Object.assign(row, values);
          updated.push(row);
        }
      }
      persistStore();
      return updated.length === 1 ? updated[0] : updated;
    };
    return this;
  }

  delete(): this {
    this.pendingOp = () => {
      const table = (store[this.tableName] || []) as Array<Record<string, unknown>>;
      const initialLen = table.length;
      const remaining = table.filter(row => !this.filters.every(fn => fn(row)));
      (store[this.tableName] as unknown) = remaining;
      persistStore();
      return { count: initialLen - remaining.length };
    };
    return this;
  }

  upsert(values: Record<string, unknown>, options: { onConflict?: string } = {}): this {
    this.pendingOp = () => {
      const conflictKey = options.onConflict || 'user_id';
      const table = (store[this.tableName] || (store[this.tableName] = [])) as Array<Record<string, unknown>>;
      const conflictVal = values[conflictKey];
      const existing = table.find(r => r[conflictKey] === conflictVal);
      if (existing) {
        Object.assign(existing, values);
        persistStore();
        return existing;
      }
      const newRow = { id: crypto.randomUUID(), created_at: new Date().toISOString(), ...values };
      table.push(newRow);
      persistStore();
      return newRow;
    };
    return this;
  }

  private filterCols(row: Record<string, unknown>): Record<string, unknown> {
    if (!this.selectedColumns || !row) return row;
    const res: Record<string, unknown> = {};
    for (const col of this.selectedColumns) {
      if (col in row) res[col] = row[col];
    }
    return res;
  }

  private execute(): unknown {
    if (this.pendingOp) {
      const result = this.pendingOp();
      if (result && typeof result === 'object' && this.selectedColumns) {
        if (Array.isArray(result)) return result.map(r => this.filterCols(r as Record<string, unknown>));
        return this.filterCols(result as Record<string, unknown>);
      }
      return result;
    }

    const table = (store[this.tableName] || []) as Array<Record<string, unknown>>;
    let results = table.filter(row => this.filters.every(fn => fn(row)));

    if (this.orderField) {
      const field = this.orderField;
      const asc = this.orderAscending ? 1 : -1;
      results = results.slice().sort((a, b) => {
        const valA = a[field];
        const valB = b[field];
        if (valA === valB) return 0;
        if (valA === undefined || valA === null) return 1;
        if (valB === undefined || valB === null) return -1;
        return valA > valB ? asc : -asc;
      });
    }

    if (this.limitCount !== null) {
      results = results.slice(0, this.limitCount);
    }

    if (this.selectedColumns) {
      return results.map(r => this.filterCols(r));
    }
    return results;
  }

  async single(): Promise<{ data: Record<string, unknown> | null; error: Error | null }> {
    const res = this.execute();
    if (Array.isArray(res)) {
      if (res.length === 0) return { data: null, error: new Error('Row not found') };
      return { data: res[0] as Record<string, unknown>, error: null };
    }
    return { data: (res as Record<string, unknown>) || null, error: null };
  }

  async maybeSingle(): Promise<{ data: Record<string, unknown> | null; error: null }> {
    const res = this.execute();
    if (Array.isArray(res)) {
      return { data: (res[0] as Record<string, unknown>) || null, error: null };
    }
    return { data: (res as Record<string, unknown>) || null, error: null };
  }

  then<TResult1 = { data: unknown; error: null }, TResult2 = never>(
    onfulfilled?: ((value: { data: unknown; error: null }) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
  ): Promise<TResult1 | TResult2> {
    const data = this.execute();
    return Promise.resolve({ data, error: null }).then(onfulfilled, onrejected);
  }
}

export function createServerDbClient(scopedUserId?: string) {
  return {
    from(tableName: keyof StoreData) {
      const qb = new QueryBuilder(tableName);
      if (scopedUserId && ['application_scans', 'github_credentials', 'audit_records', 'guardrail_policies'].includes(tableName)) {
        qb.eq('user_id', scopedUserId);
      }
      return qb;
    },
    async rpc(funcName: string, _args: Record<string, unknown> = {}) {
      if (funcName === 'consume_audit_quota') {
        return { data: true, error: null };
      }
      return { data: null, error: null };
    },
  };
}
