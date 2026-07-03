#!/usr/bin/env node
/**
 * Zero-dependency, least-privilege MCP server for GLPI over stdio (JSON-RPC 2.0).
 *
 * stdout: JSON-RPC stream ONLY (newline-delimited).  stderr: logs.
 *
 * Everything except the GLPI HTTP client lives here (audit, schema validation,
 * capability policy, config, tools, server). Kept compact on purpose.
 */

import { createInterface } from 'node:readline';
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { GlpiClient, type SearchCriterion } from './glpi.js';

// ============================================================================
// Audit — structured logging with secret redaction. stderr only.
// ============================================================================

const SECRETS = new Set<string>();

export function registerSecret(value: string | undefined): void {
  if (value && value.length >= 4) SECRETS.add(value);
}

const HEADER_RE = /("?(?:Session-Token|Authorization|App-Token)"?\s*[:=]\s*)("?)[^",}\s]+/gi;

export function redact(text: string): string {
  let out = text;
  for (const secret of SECRETS) out = out.split(secret).join('«redacted»');
  return out.replace(HEADER_RE, '$1$2«redacted»');
}

type LogLevel = 'info' | 'warn' | 'error';

function log(level: LogLevel, message: string, fields: Record<string, unknown> = {}): void {
  process.stderr.write(redact(JSON.stringify({ ts: new Date().toISOString(), level, msg: message, ...fields })) + '\n');
}

interface AuditEvent {
  tool: string;
  mode: string;
  capability: string;
  ok: boolean;
  ms: number;
  args: unknown;
  error?: string;
}
function audit(e: AuditEvent): void {
  log(e.ok ? 'info' : 'warn', 'tool_call', e as unknown as Record<string, unknown>);
}

// ============================================================================
// Schema — minimal JSON Schema (draft-07 subset) validator.
// One object is both the advertised inputSchema and the enforced contract.
// ============================================================================

export interface JSONSchema {
  type?: 'object' | 'string' | 'number' | 'integer' | 'boolean' | 'array';
  description?: string;
  properties?: Record<string, JSONSchema>;
  required?: string[];
  additionalProperties?: boolean;
  enum?: ReadonlyArray<string | number>;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  items?: JSONSchema;
  default?: unknown;
}

interface ValidationResult {
  ok: boolean;
  errors: string[];
  value?: unknown;
}

export function validate(schema: JSONSchema, input: unknown): ValidationResult {
  const errors: string[] = [];
  const value = walk(schema, input, '$', errors);
  return errors.length === 0 ? { ok: true, errors, value } : { ok: false, errors };
}

function walk(schema: JSONSchema, input: unknown, path: string, errors: string[]): unknown {
  if (input === undefined) return schema.default !== undefined ? structuredClone(schema.default) : undefined;
  switch (schema.type) {
    case 'object':
      return validateObject(schema, input, path, errors);
    case 'array':
      return validateArray(schema, input, path, errors);
    case 'string':
      return validateString(schema, input, path, errors);
    case 'integer':
    case 'number':
      return validateNumber(schema, input, path, errors);
    case 'boolean':
      if (typeof input !== 'boolean') errors.push(`${path}: expected boolean`);
      return input;
    default:
      return input;
  }
}

function validateObject(schema: JSONSchema, input: unknown, path: string, errors: string[]): unknown {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    errors.push(`${path}: expected object`);
    return input;
  }
  const obj = input as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  const props = schema.properties ?? {};
  const allowExtra = schema.additionalProperties === true;

  if (!allowExtra) {
    for (const key of Object.keys(obj)) {
      if (!(key in props)) errors.push(`${path}.${key}: unexpected property (not allowed)`);
    }
  }
  for (const [key, propSchema] of Object.entries(props)) {
    if (!(key in obj)) {
      if (schema.required?.includes(key)) {
        errors.push(`${path}.${key}: required`);
        continue;
      }
      const def = walk(propSchema, undefined, `${path}.${key}`, errors);
      if (def !== undefined) out[key] = def;
      continue;
    }
    out[key] = walk(propSchema, obj[key], `${path}.${key}`, errors);
  }
  if (allowExtra) for (const key of Object.keys(obj)) if (!(key in props)) out[key] = obj[key];
  return out;
}

function validateArray(schema: JSONSchema, input: unknown, path: string, errors: string[]): unknown {
  if (!Array.isArray(input)) {
    errors.push(`${path}: expected array`);
    return input;
  }
  if (!schema.items) return input;
  return input.map((el, i) => walk(schema.items as JSONSchema, el, `${path}[${i}]`, errors));
}

function validateString(schema: JSONSchema, input: unknown, path: string, errors: string[]): unknown {
  if (typeof input !== 'string') {
    errors.push(`${path}: expected string`);
    return input;
  }
  if (schema.minLength !== undefined && input.length < schema.minLength) errors.push(`${path}: shorter than minLength ${schema.minLength}`);
  if (schema.maxLength !== undefined && input.length > schema.maxLength) errors.push(`${path}: longer than maxLength ${schema.maxLength}`);
  if (schema.enum && !schema.enum.includes(input)) errors.push(`${path}: must be one of ${schema.enum.join(', ')}`);
  if (schema.pattern && !new RegExp(schema.pattern).test(input)) errors.push(`${path}: does not match pattern ${schema.pattern}`);
  return input;
}

function validateNumber(schema: JSONSchema, input: unknown, path: string, errors: string[]): unknown {
  if (typeof input !== 'number' || Number.isNaN(input)) {
    errors.push(`${path}: expected number`);
    return input;
  }
  if (schema.type === 'integer' && !Number.isInteger(input)) errors.push(`${path}: expected integer`);
  if (schema.minimum !== undefined && input < schema.minimum) errors.push(`${path}: below minimum ${schema.minimum}`);
  if (schema.maximum !== undefined && input > schema.maximum) errors.push(`${path}: above maximum ${schema.maximum}`);
  if (schema.enum && !schema.enum.includes(input)) errors.push(`${path}: must be one of ${schema.enum.join(', ')}`);
  return input;
}

// ============================================================================
// Policy — least-privilege capability model. No 'delete' capability by design.
// ============================================================================

export const Mode = { ReadOnly: 'read-only', ReadWrite: 'read-write', Admin: 'admin' } as const;
export type Mode = (typeof Mode)[keyof typeof Mode];
export type Capability = 'read' | 'write' | 'admin';

const GRANTS: Record<Mode, ReadonlySet<Capability>> = {
  [Mode.ReadOnly]: new Set(['read']),
  [Mode.ReadWrite]: new Set(['read', 'write']),
  [Mode.Admin]: new Set(['read', 'write', 'admin']),
};

function isMode(v: string): v is Mode {
  return v === Mode.ReadOnly || v === Mode.ReadWrite || v === Mode.Admin;
}
export function grants(mode: Mode, cap: Capability): boolean {
  return GRANTS[mode].has(cap);
}
export class PolicyError extends Error {
  override readonly name = 'PolicyError';
}
export function assertAllowed(mode: Mode, cap: Capability, toolName: string): void {
  if (!grants(mode, cap)) throw new PolicyError(`Tool '${toolName}' requires capability '${cap}', denied in mode '${mode}'.`);
}

// ============================================================================
// Config — all input from the environment. Secrets via env or *_FILE mounts.
// ============================================================================

export interface Config {
  apiBase: string; // full base incl. any subpath, e.g. https://host/glpi (no trailing slash)
  origin: string; // scheme://host[:port] — the only network destination allowed
  mode: Mode;
  timeoutMs: number;
  allowInsecure: boolean;
  auth:
    | { kind: 'user_token'; appToken?: string; userToken: string }
    | { kind: 'basic'; appToken?: string; username: string; password: string };
}

export class ConfigError extends Error {
  override readonly name = 'ConfigError';
}

function readSecret(name: string, env: NodeJS.ProcessEnv): string | undefined {
  const file = env[`${name}_FILE`];
  const value = (file ? readFileSync(file, 'utf8') : env[name])?.trim() || undefined;
  registerSecret(value);
  return value;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const rawUrl = env.GLPI_URL?.trim();
  if (!rawUrl) throw new ConfigError('GLPI_URL is required.');

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new ConfigError(`GLPI_URL is not a valid URL: ${rawUrl}`);
  }

  const allowInsecure = env.GLPI_ALLOW_INSECURE === '1';
  if (url.protocol !== 'https:' && !allowInsecure)
    throw new ConfigError('GLPI_URL must use https:// (set GLPI_ALLOW_INSECURE=1 only for isolated lab use).');
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new ConfigError(`Unsupported URL scheme: ${url.protocol}`);

  const mode = (env.GLPI_MCP_MODE?.trim() || Mode.ReadOnly).toLowerCase();
  if (!isMode(mode)) throw new ConfigError(`GLPI_MCP_MODE must be read-only | read-write | admin (got '${mode}').`);

  const timeoutMs = Number(env.GLPI_TIMEOUT_MS ?? '15000');
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 120_000)
    throw new ConfigError('GLPI_TIMEOUT_MS must be a positive number <= 120000.');

  const appToken = readSecret('GLPI_APP_TOKEN', env);
  const userToken = readSecret('GLPI_USER_TOKEN', env);
  const username = readSecret('GLPI_USERNAME', env);
  const password = readSecret('GLPI_PASSWORD', env);

  let auth: Config['auth'];
  if (userToken) auth = appToken ? { kind: 'user_token', appToken, userToken } : { kind: 'user_token', userToken };
  else if (username && password)
    auth = appToken ? { kind: 'basic', appToken, username, password } : { kind: 'basic', username, password };
  else throw new ConfigError('No authentication configured. Provide GLPI_USER_TOKEN (recommended) or GLPI_USERNAME + GLPI_PASSWORD.');

  return { apiBase: `${url.origin}${url.pathname}`.replace(/\/+$/, ''), origin: url.origin, mode, timeoutMs, allowInsecure, auth };
}

// ============================================================================
// Tools — read tools table-driven; write/admin declared explicitly.
// No delete tool exists: this server has no destructive power over GLPI.
// ============================================================================

interface Tool {
  name: string;
  description: string;
  capability: Capability;
  inputSchema: JSONSchema;
  handler: (c: GlpiClient, args: Record<string, unknown>) => Promise<unknown>;
}

const obj = (properties: Record<string, JSONSchema>, required: string[] = []): JSONSchema => ({
  type: 'object',
  properties,
  required,
  additionalProperties: false,
});
const str = (max = 255): JSONSchema => ({ type: 'string', minLength: 1, maxLength: max });
const textField = (): JSONSchema => ({ type: 'string', minLength: 1, maxLength: 65535 });
const dateField = (): JSONSchema => ({ type: 'string', maxLength: 25, description: 'YYYY-MM-DD[ HH:MM:SS]' });
const idField = (): JSONSchema => ({ type: 'integer', minimum: 1 });
const fkey = (): JSONSchema => ({ type: 'integer', minimum: 0 });
const nonNeg = (): JSONSchema => ({ type: 'integer', minimum: 0 });
const rank = (): JSONSchema => ({ type: 'integer', minimum: 1, maximum: 5 });

const LIST_SCHEMA = obj({
  range: { type: 'string', pattern: '^\\d+-\\d+$', description: 'e.g. 0-49', default: '0-49' },
  sort: { type: 'integer', minimum: 1 },
  order: { type: 'string', enum: ['ASC', 'DESC'] },
  is_deleted: { type: 'boolean', description: 'include soft-deleted items' },
  expand_dropdowns: { type: 'boolean' },
});
const GET_SCHEMA = obj({ id: idField(), expand_dropdowns: { type: 'boolean' } }, ['id']);

function listQuery(a: Record<string, unknown>): Record<string, string | number | boolean> {
  const q: Record<string, string | number | boolean> = { range: (a.range as string) ?? '0-49' };
  if (a.sort !== undefined) q.sort = a.sort as number;
  if (a.order !== undefined) q.order = a.order as string;
  if (a.is_deleted !== undefined) q.is_deleted = a.is_deleted ? 1 : 0;
  if (a.expand_dropdowns) q.expand_dropdowns = true;
  return q;
}
const asArray = (v: unknown): Array<Record<string, unknown>> => (Array.isArray(v) ? v : []);

// `single` is explicit (not naive de-pluralization) so get-tool names are correct.
const READ_TYPES: Array<{ key: string; single: string; itemtype: string; label: string }> = [
  { key: 'tickets', single: 'ticket', itemtype: 'Ticket', label: 'tickets' },
  { key: 'problems', single: 'problem', itemtype: 'Problem', label: 'problems' },
  { key: 'changes', single: 'change', itemtype: 'Change', label: 'changes' },
  { key: 'users', single: 'user', itemtype: 'User', label: 'users' },
  { key: 'groups', single: 'group', itemtype: 'Group', label: 'groups' },
  { key: 'computers', single: 'computer', itemtype: 'Computer', label: 'computers' },
  { key: 'software', single: 'software', itemtype: 'Software', label: 'software' },
  { key: 'network_equipment', single: 'network_equipment', itemtype: 'NetworkEquipment', label: 'network equipment' },
  { key: 'printers', single: 'printer', itemtype: 'Printer', label: 'printers' },
  { key: 'monitors', single: 'monitor', itemtype: 'Monitor', label: 'monitors' },
  { key: 'phones', single: 'phone', itemtype: 'Phone', label: 'phones' },
  { key: 'knowbase', single: 'knowbase_item', itemtype: 'KnowbaseItem', label: 'knowledge base items' },
  { key: 'contracts', single: 'contract', itemtype: 'Contract', label: 'contracts' },
  { key: 'suppliers', single: 'supplier', itemtype: 'Supplier', label: 'suppliers' },
  { key: 'locations', single: 'location', itemtype: 'Location', label: 'locations' },
  { key: 'entities', single: 'entity', itemtype: 'Entity', label: 'entities' },
  { key: 'projects', single: 'project', itemtype: 'Project', label: 'projects' },
  { key: 'documents', single: 'document', itemtype: 'Document', label: 'documents' },
  { key: 'categories', single: 'category', itemtype: 'ITILCategory', label: 'ITIL categories' },
];

const readTools: Tool[] = READ_TYPES.flatMap(({ key, single, itemtype, label }) => [
  {
    name: `glpi_list_${key}`,
    description: `List ${label} from GLPI.`,
    capability: 'read',
    inputSchema: LIST_SCHEMA,
    handler: (c, a) => c.list(itemtype, listQuery(a)),
  },
  {
    name: `glpi_get_${single}`,
    description: `Get a single ${single.replace(/_/g, ' ')} by id.`,
    capability: 'read',
    inputSchema: GET_SCHEMA,
    handler: (c, a) => c.get(itemtype, a.id as number, a.expand_dropdowns ? { expand_dropdowns: true } : {}),
  },
]);

function createTool(key: string, itemtype: string, props: Record<string, JSONSchema>, required: string[] = ['name'], capability: Capability = 'write'): Tool {
  return {
    name: `glpi_create_${key}`,
    description: `Create a ${key.replace(/_/g, ' ')} in GLPI.`,
    capability,
    inputSchema: obj(props, required),
    handler: (c, a) => c.create(itemtype, a),
  };
}

function updateTool(key: string, itemtype: string, props: Record<string, JSONSchema>, capability: Capability = 'write'): Tool {
  return {
    name: `glpi_update_${key}`,
    description: `Update a ${key.replace(/_/g, ' ')} in GLPI.`,
    capability,
    inputSchema: obj({ id: idField(), ...props }, ['id']),
    handler: (c, a) => {
      const { id: itemId, ...rest } = a;
      return c.update(itemtype, itemId as number, rest);
    },
  };
}

const ITIL_BODY = {
  name: str(),
  content: textField(),
  urgency: rank(),
  impact: rank(),
  priority: rank(),
  itilcategories_id: fkey(),
  entities_id: fkey(),
};

const writeTools: Tool[] = [
  // Tickets
  createTool('ticket', 'Ticket', { ...ITIL_BODY, type: { type: 'integer', enum: [1, 2], description: '1=incident, 2=request' } }),
  updateTool('ticket', 'Ticket', {
    name: str(),
    content: textField(),
    status: { type: 'integer', minimum: 1, maximum: 6 },
    urgency: rank(),
    impact: rank(),
    priority: rank(),
    itilcategories_id: fkey(),
  }),
  {
    name: 'glpi_add_ticket_followup',
    description: 'Add a followup (comment) to a ticket.',
    capability: 'write',
    inputSchema: obj({ ticket_id: idField(), content: textField(), is_private: { type: 'boolean' } }, ['ticket_id', 'content']),
    handler: (c, a) => c.create('ITILFollowup', { itemtype: 'Ticket', items_id: a.ticket_id, content: a.content, is_private: a.is_private ? 1 : 0 }),
  },
  {
    name: 'glpi_add_ticket_task',
    description: 'Add a task to a ticket.',
    capability: 'write',
    inputSchema: obj(
      {
        ticket_id: idField(),
        content: textField(),
        is_private: { type: 'boolean' },
        actiontime: { type: 'integer', minimum: 0, description: 'seconds' },
        state: { type: 'integer', enum: [0, 1, 2], description: '0=none,1=todo,2=done' },
      },
      ['ticket_id', 'content'],
    ),
    handler: (c, a) =>
      c.create('TicketTask', { tickets_id: a.ticket_id, content: a.content, is_private: a.is_private ? 1 : 0, actiontime: a.actiontime ?? 0, state: a.state ?? 1 }),
  },
  {
    name: 'glpi_add_ticket_solution',
    description: 'Add a solution to a ticket.',
    capability: 'write',
    inputSchema: obj({ ticket_id: idField(), content: textField(), solutiontypes_id: fkey() }, ['ticket_id', 'content']),
    handler: (c, a) => c.create('ITILSolution', { itemtype: 'Ticket', items_id: a.ticket_id, content: a.content, solutiontypes_id: a.solutiontypes_id ?? 0 }),
  },
  {
    name: 'glpi_assign_ticket',
    description: 'Assign a user to a ticket (type: 1=requester, 2=assigned, 3=observer).',
    capability: 'write',
    inputSchema: obj({ ticket_id: idField(), users_id: idField(), type: { type: 'integer', enum: [1, 2, 3] } }, ['ticket_id', 'users_id']),
    handler: (c, a) => c.create('Ticket_User', { tickets_id: a.ticket_id, users_id: a.users_id, type: a.type ?? 2 }),
  },
  {
    name: 'glpi_list_ticket_followups',
    description: 'List followups of a ticket.',
    capability: 'read',
    inputSchema: obj({ ticket_id: idField() }, ['ticket_id']),
    handler: (c, a) => c.subList('Ticket', a.ticket_id as number, 'ITILFollowup'),
  },
  {
    name: 'glpi_list_ticket_tasks',
    description: 'List tasks of a ticket.',
    capability: 'read',
    inputSchema: obj({ ticket_id: idField() }, ['ticket_id']),
    handler: (c, a) => c.subList('Ticket', a.ticket_id as number, 'TicketTask'),
  },

  // Problems & Changes
  createTool('problem', 'Problem', ITIL_BODY),
  updateTool('problem', 'Problem', { name: str(), content: textField(), status: { type: 'integer', minimum: 1 } }),
  createTool('change', 'Change', ITIL_BODY),
  updateTool('change', 'Change', { name: str(), content: textField(), status: { type: 'integer', minimum: 1 } }),

  // Assets
  createTool('computer', 'Computer', {
    name: str(),
    serial: str(),
    otherserial: str(),
    comment: textField(),
    locations_id: fkey(),
    states_id: fkey(),
    computertypes_id: fkey(),
    manufacturers_id: fkey(),
    entities_id: fkey(),
  }),
  updateTool('computer', 'Computer', { name: str(), serial: str(), comment: textField(), locations_id: fkey(), states_id: fkey() }),
  createTool('software', 'Software', { name: str(), comment: textField(), softwarecategories_id: fkey(), manufacturers_id: fkey(), locations_id: fkey(), entities_id: fkey() }),
  createTool('network_equipment', 'NetworkEquipment', { name: str(), serial: str(), locations_id: fkey(), networkequipmenttypes_id: fkey(), manufacturers_id: fkey(), entities_id: fkey() }),
  createTool('printer', 'Printer', { name: str(), serial: str(), locations_id: fkey(), printertypes_id: fkey(), manufacturers_id: fkey(), entities_id: fkey() }),

  // Knowledge base
  {
    name: 'glpi_create_knowbase_item',
    description: 'Create a knowledge base article.',
    capability: 'write',
    inputSchema: obj({ name: str(), answer: textField(), is_faq: { type: 'boolean' }, knowbaseitemcategories_id: fkey() }, ['name', 'answer']),
    handler: (c, a) => c.create('KnowbaseItem', { name: a.name, answer: a.answer, is_faq: a.is_faq ? 1 : 0, knowbaseitemcategories_id: a.knowbaseitemcategories_id ?? 0 }),
  },

  // Contracts / Suppliers / Locations
  createTool('contract', 'Contract', { name: str(), num: str(), contracttypes_id: fkey(), begin_date: dateField(), duration: nonNeg(), comment: textField(), entities_id: fkey() }),
  createTool('supplier', 'Supplier', { name: str(), suppliertypes_id: fkey(), address: str(), town: str(), country: str(), email: { type: 'string', maxLength: 255 }, phonenumber: str(50), entities_id: fkey() }),
  createTool('location', 'Location', { name: str(), locations_id: fkey(), address: str(), town: str(), country: str(), building: str(), room: str(), entities_id: fkey() }),

  // Projects
  createTool('project', 'Project', {
    name: str(),
    code: str(),
    content: textField(),
    comment: textField(),
    priority: rank(),
    plan_start_date: dateField(),
    plan_end_date: dateField(),
    projectstates_id: fkey(),
    projecttypes_id: fkey(),
    entities_id: fkey(),
  }),
  updateTool('project', 'Project', { name: str(), content: textField(), percent_done: { type: 'integer', minimum: 0, maximum: 100 }, projectstates_id: fkey() }),

  // Groups
  {
    name: 'glpi_create_group',
    description: 'Create a group.',
    capability: 'write',
    inputSchema: obj({ name: str(), comment: textField(), is_recursive: { type: 'boolean' }, entities_id: fkey() }, ['name']),
    handler: (c, a) => c.create('Group', { name: a.name, comment: a.comment, is_recursive: a.is_recursive ? 1 : 0, entities_id: a.entities_id }),
  },
  {
    name: 'glpi_add_user_to_group',
    description: 'Add a user to a group.',
    capability: 'write',
    inputSchema: obj({ users_id: idField(), groups_id: idField(), is_manager: { type: 'boolean' } }, ['users_id', 'groups_id']),
    handler: (c, a) => c.create('Group_User', { users_id: a.users_id, groups_id: a.groups_id, is_manager: a.is_manager ? 1 : 0 }),
  },

  // Users (admin)
  {
    name: 'glpi_create_user',
    description: 'Create a user account.',
    capability: 'admin',
    inputSchema: obj(
      { name: str(), realname: str(), firstname: str(), email: { type: 'string', maxLength: 255 }, phone: str(50), profiles_id: fkey(), entities_id: fkey(), is_active: { type: 'boolean' } },
      ['name'],
    ),
    handler: (c, a) => {
      const { is_active, ...rest } = a;
      return c.create('User', { ...rest, is_active: is_active === false ? 0 : 1 });
    },
  },
  {
    name: 'glpi_update_user',
    description: 'Update a user account.',
    capability: 'admin',
    inputSchema: obj(
      { id: idField(), realname: str(), firstname: str(), email: { type: 'string', maxLength: 255 }, phone: str(50), profiles_id: fkey(), is_active: { type: 'boolean' } },
      ['id'],
    ),
    handler: (c, a) => {
      const { id: userId, is_active, ...rest } = a;
      const input: Record<string, unknown> = { ...rest };
      if (is_active !== undefined) input.is_active = is_active ? 1 : 0;
      return c.update('User', userId as number, input);
    },
  },

  // Entities (admin — organizational structure)
  createTool(
    'entity',
    'Entity',
    { name: str(), entities_id: fkey(), comment: textField(), address: str(), postcode: str(20), town: str(), state: str(), country: str(), website: str(), phonenumber: str(50), fax: str(50), email: { type: 'string', maxLength: 255 } },
    ['name'],
    'admin',
  ),
  updateTool(
    'entity',
    'Entity',
    { name: str(), comment: textField(), address: str(), postcode: str(20), town: str(), state: str(), country: str(), website: str(), phonenumber: str(50), fax: str(50), email: { type: 'string', maxLength: 255 } },
    'admin',
  ),

  // Search
  {
    name: 'glpi_search',
    description: 'Search any GLPI itemtype with criteria (field id per GLPI search options).',
    capability: 'read',
    inputSchema: obj(
      {
        itemtype: str(64),
        criteria: {
          type: 'array',
          items: obj(
            {
              field: { type: 'integer', minimum: 1 },
              searchtype: { type: 'string', enum: ['contains', 'equals', 'notequals', 'lessthan', 'morethan', 'under', 'notunder'] },
              value: { type: 'string', maxLength: 255 },
              link: { type: 'string', enum: ['AND', 'OR'] },
            },
            ['field', 'searchtype', 'value'],
          ),
        },
      },
      ['itemtype', 'criteria'],
    ),
    handler: (c, a) => c.search(a.itemtype as string, a.criteria as SearchCriterion[]),
  },

  // Statistics
  {
    name: 'glpi_ticket_stats',
    description: 'Ticket counts grouped by status.',
    capability: 'read',
    inputSchema: obj({}),
    handler: async (c) => {
      const arr = asArray(await c.list('Ticket', { range: '0-9999' }));
      const by = (s: number) => arr.filter((t) => t.status === s).length;
      return { total: arr.length, new: by(1), assigned: by(2), planned: by(3), pending: by(4), solved: by(5), closed: by(6) };
    },
  },
  {
    name: 'glpi_asset_stats',
    description: 'Counts of active assets by type.',
    capability: 'read',
    inputSchema: obj({}),
    handler: async (c) => {
      const types: Record<string, string> = { computers: 'Computer', monitors: 'Monitor', printers: 'Printer', network_equipment: 'NetworkEquipment', phones: 'Phone', software: 'Software' };
      const out: Record<string, number> = {};
      await Promise.all(Object.entries(types).map(async ([k, it]) => { out[k] = asArray(await c.list(it, { range: '0-9999', is_deleted: 0 })).length; }));
      return out;
    },
  },

  // Session info
  ...(['getMyProfiles', 'getActiveProfile', 'getMyEntities', 'getFullSession'] as const).map(
    (ep): Tool => ({
      name: `glpi_${ep.replace(/^get/, 'session_').toLowerCase()}`,
      description: `GLPI session info: ${ep}.`,
      capability: 'read',
      inputSchema: obj({}),
      handler: (c) => c.sessionInfo(ep),
    }),
  ),
];

export const ALL_TOOLS: Tool[] = [...readTools, ...writeTools];

// ============================================================================
// Server — JSON-RPC 2.0 over stdio.
// ============================================================================

const PROTOCOL_DEFAULT = '2025-06-18';
const SERVER_INFO = { name: 'mcp-glpi-secure', version: '1.0.0' };

type RpcId = string | number | null;
interface Rpc {
  jsonrpc: '2.0';
  id?: RpcId;
  method?: string;
  params?: Record<string, unknown>;
}

class McpError extends Error {
  constructor(readonly code: number, message: string) {
    super(message);
  }
}

function send(msg: unknown): void {
  process.stdout.write(JSON.stringify(msg) + '\n');
}
function toolError(message: string): unknown {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function main(): void {
  let config: Config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      log('error', 'configuration error', { error: err.message });
      process.exit(78); // EX_CONFIG
    }
    throw err;
  }

  const client = new GlpiClient(config);
  const tools = ALL_TOOLS.filter((t) => grants(config.mode, t.capability));
  const byName = new Map<string, Tool>(tools.map((t) => [t.name, t]));

  log('info', 'starting', { mode: config.mode, origin: config.origin, tools: tools.length, auth: config.auth.kind });

  const rl = createInterface({ input: process.stdin });
  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (trimmed) void handleLine(trimmed);
  });
  rl.on('close', () => shutdown(0));
  process.on('SIGINT', () => shutdown(0));
  process.on('SIGTERM', () => shutdown(0));

  async function shutdown(code: number): Promise<void> {
    await client.killSession();
    process.exit(code);
  }

  async function handleLine(line: string): Promise<void> {
    let req: Rpc;
    try {
      req = JSON.parse(line);
    } catch {
      send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      return;
    }
    const id = req.id ?? null;
    const isNotification = req.id === undefined;
    try {
      const result = await dispatch(req);
      if (!isNotification) send({ jsonrpc: '2.0', id, result });
    } catch (err) {
      const code = err instanceof McpError ? err.code : -32603;
      if (!isNotification) send({ jsonrpc: '2.0', id, error: { code, message: redact(String(err instanceof Error ? err.message : err)) } });
      log('error', 'dispatch failed', { method: req.method, error: String(err) });
    }
  }

  async function dispatch(req: Rpc): Promise<unknown> {
    switch (req.method) {
      case 'initialize': {
        const requested = req.params?.protocolVersion;
        return { protocolVersion: typeof requested === 'string' ? requested : PROTOCOL_DEFAULT, capabilities: { tools: {} }, serverInfo: SERVER_INFO };
      }
      case 'notifications/initialized':
      case 'notifications/cancelled':
      case 'ping':
        return {};
      case 'tools/list':
        return { tools: tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })) };
      case 'tools/call':
        return callTool(req.params ?? {});
      default:
        throw new McpError(-32601, `Method not found: ${req.method}`);
    }
  }

  async function callTool(params: Record<string, unknown>): Promise<unknown> {
    const name = params.name as string;
    const args = (params.arguments as Record<string, unknown>) ?? {};
    const tool = byName.get(name);
    if (!tool) return toolError(`Unknown tool: ${name}`);

    const started = Date.now();
    try {
      assertAllowed(config.mode, tool.capability, tool.name); // defense in depth
      const v = validate(tool.inputSchema, args);
      if (!v.ok) return toolError(`Invalid arguments: ${v.errors.join('; ')}`);
      const data = await tool.handler(client, v.value as Record<string, unknown>);
      audit({ tool: name, mode: config.mode, capability: tool.capability, ok: true, ms: Date.now() - started, args });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    } catch (err) {
      audit({ tool: name, mode: config.mode, capability: tool.capability, ok: false, ms: Date.now() - started, args, error: String(err) });
      return toolError(redact(String(err instanceof Error ? err.message : err)));
    }
  }
}

// Run only when invoked as the entrypoint (not when imported by tests).
function isEntrypoint(): boolean {
  const arg = process.argv[1];
  if (!arg) return false;
  try {
    return realpathSync(arg) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}
if (isEntrypoint()) main();
