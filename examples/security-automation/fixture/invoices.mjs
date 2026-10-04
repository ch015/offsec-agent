// Synthetic accounts and invoice data for this loopback-only demonstration.
export const sessions = new Map([
  ['demo-alice', { id: 'alice', name: '김고객' }],
  ['demo-bob', { id: 'bob', name: '이고객' }],
]);
const invoices = new Map([
  ['INV-A', { id: 'INV-A', owner: 'alice', customer: '김고객', amount: 120000, item: '클라우드 이용료' }],
  ['INV-B', { id: 'INV-B', owner: 'bob', customer: '이고객', amount: 240000, item: '보안 서비스 이용료' }],
]);
export function lookupInvoice(id) { return invoices.get(id); }
