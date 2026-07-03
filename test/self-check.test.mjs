import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validate, grants, assertAllowed, PolicyError, Mode, registerSecret, redact, ALL_TOOLS } from '../dist/index.js';
import { GlpiClient } from '../dist/glpi.js';

test('schema: rejects unexpected property (anti mass-assignment)', () => {
  const s = { type: 'object', properties: { name: { type: 'string' } }, additionalProperties: false };
  const r = validate(s, { name: 'ok', profiles_id: 4 });
  assert.equal(r.ok, false);
  assert.match(r.errors.join(), /unexpected property/);
});

test('schema: enforces minimum and applies default', () => {
  assert.equal(validate({ type: 'integer', minimum: 1 }, -5).ok, false);
  const r = validate({ type: 'string', default: '0-49' }, undefined);
  assert.equal(r.ok, true);
  assert.equal(r.value, '0-49');
});

test('policy: read-only grants read, denies write/admin', () => {
  assert.equal(grants(Mode.ReadOnly, 'read'), true);
  for (const cap of ['write', 'admin']) assert.equal(grants(Mode.ReadOnly, cap), false);
  assert.throws(() => assertAllowed(Mode.ReadOnly, 'write', 'glpi_create_ticket'), PolicyError);
});

test('no delete power exists anywhere', () => {
  const del = ALL_TOOLS.filter((t) => /delete|purge/i.test(t.name) || t.capability === 'delete');
  assert.deepEqual(del, [], 'no tool may delete or purge');
  assert.equal(typeof GlpiClient.prototype.softDelete, 'undefined', 'client must not expose a delete verb');
});

test('audit: redacts registered secrets and auth headers', () => {
  registerSecret('user-secret-456');
  assert.match(redact('token=user-secret-456'), /«redacted»/);
  assert.doesNotMatch(redact('token=user-secret-456'), /user-secret-456/);
  assert.match(redact('Session-Token: abc123def'), /Session-Token.*«redacted»/);
});
