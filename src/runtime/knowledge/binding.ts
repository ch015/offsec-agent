import type { KnowledgePin, PostgresKnowledgeStore } from './postgres-knowledge.js';

/** Symbols are copied by host spreads and omitted from serialized model inputs. */
export const KNOWLEDGE_BINDING = Symbol('host-only-knowledge-binding');
export type KnowledgeBinding = { store: PostgresKnowledgeStore; scope: string; documentScope: string; view: string; pin: KnowledgePin };
