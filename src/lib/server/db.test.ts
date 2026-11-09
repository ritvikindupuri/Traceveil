import { describe, it, expect } from 'vitest';
import {
  createUser,
  verifyPassword,
  createSession,
  getSessionByToken,
  deleteSession,
  findUserByEmail,
  hashPassword,
} from './db.server';

describe('Secure Local Auth & DB System', () => {
  const testEmail = `test_${Date.now()}@example.com`;
  const testPassword = 'StrongPassword123!';

  it('rejects passwords shorter than 8 characters', () => {
    const res = createUser('short@example.com', 'short');
    expect(res.error).toContain('at least 8 characters');
    expect(res.user.id).toBe('');
  });

  it('rejects invalid email formats', () => {
    const res = createUser('not-an-email', 'ValidPassword123!');
    expect(res.error).toContain('valid email');
  });

  it('creates user with salted scrypt hash', () => {
    const res = createUser(testEmail, testPassword);
    expect(res.error).toBeNull();
    expect(res.user.email).toBe(testEmail.toLowerCase());
    expect(res.user.id).toBeTruthy();

    const storedUser = findUserByEmail(testEmail);
    expect(storedUser).not.toBeNull();
    expect(storedUser?.password_hash).not.toContain(testPassword);
    expect(storedUser?.password_hash).toContain(':'); // salt:hash format
  });

  it('rejects duplicate email registrations', () => {
    const duplicate = createUser(testEmail, 'AnotherPassword123!');
    expect(duplicate.error).toContain('already exists');
  });

  it('verifies valid password and rejects incorrect password', () => {
    const stored = findUserByEmail(testEmail);
    expect(stored).not.toBeNull();
    if (stored) {
      expect(verifyPassword(testPassword, stored.password_hash)).toBe(true);
      expect(verifyPassword('WrongPassword123!', stored.password_hash)).toBe(false);
      expect(verifyPassword('', stored.password_hash)).toBe(false);
    }
  });

  it('creates and retrieves active session with user details', () => {
    const user = findUserByEmail(testEmail);
    expect(user).not.toBeNull();
    if (user) {
      const session = createSession(user.id);
      expect(session.token).toHaveLength(64);

      const active = getSessionByToken(session.token);
      expect(active).not.toBeNull();
      expect(active?.user.email).toBe(testEmail.toLowerCase());
      expect(active?.user.id).toBe(user.id);

      // Deleting session
      deleteSession(session.token);
      expect(getSessionByToken(session.token)).toBeNull();
    }
  });
});
