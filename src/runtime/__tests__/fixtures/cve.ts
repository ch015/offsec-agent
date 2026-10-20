export const cveFixture = (updated = '2026-10-08T00:00:00Z', state = 'PUBLISHED') => JSON.stringify({
  dataType: 'CVE_RECORD', dataVersion: '5.1', cveMetadata: { cveId: 'CVE-2026-123456', state, dateUpdated: updated },
  containers: { cna: { title: state === 'REJECTED' ? 'Withdrawn record' : 'Example component advisory',
    affected: [{ vendor: 'Example', product: 'Sample', versions: [{ version: '1.0', status: 'affected' }] }],
    descriptions: [{ lang: 'en', value: 'Example advisory for a fictional component.' }],
    solutions: [{ lang: 'en', value: 'Apply the vendor maintenance update after checking compatibility.' }],
    references: [{ url: 'https://example.com/advisory' }], providerMetadata: { orgId: 'test-cna' } },
    adp: [{ providerMetadata: { orgId: 'test-adp' }, customFutureField: { original: true } }] },
  futureTopLevel: { preserve: true },
}, null, 2);

