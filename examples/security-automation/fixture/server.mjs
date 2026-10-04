import { sessions, lookupInvoice } from './invoices.mjs';

// The demo host listens on 127.0.0.1. All records and credentials are synthetic.
export function handleInvoice(req, res) {
  const user = sessions.get((req.headers.authorization || '').replace('Bearer ', ''));
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (!user) { res.writeHead(401); res.end('{"error":"로그인이 필요합니다"}'); return; }
  const url = new URL(req.url, 'http://127.0.0.1');
  const invoice = lookupInvoice(url.pathname.split('/').pop());
  if (!invoice) { res.writeHead(404); res.end('{"error":"송장이 없습니다"}'); return; }
  // The /fixed path demonstrates the corrected ownership check.
  if (url.pathname.startsWith('/fixed/') && invoice.owner !== user.id) {
    res.writeHead(403); res.end('{"error":"본인 송장만 조회할 수 있습니다"}'); return;
  }
  // Deliberate demonstration defect: /api returns another customer's invoice.
  res.end(JSON.stringify(invoice));
}
