import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSecurityObligations, validateSecurityAssessments, type SecurityObligation } from '../planning/security-obligations.js';
import { validateAnalysisAssessments, validateAssessmentDelivery } from '../planning/analysis-assessments.js';

const roots:string[]=[];
afterEach(()=>roots.splice(0).forEach(root=>rmSync(root,{recursive:true,force:true})));
function fixture(source="router.delete('/feedback/:id', (req,res) => db.destroy(req.params.id));\n") {
  const target=mkdtempSync(join(tmpdir(),'offsec-security-cases-'));roots.push(target);
  writeFileSync(join(target,'app.js'),source);
  const ranges=[{path:'app.js',lineStart:1,lineEnd:source.split(/\r?\n/).length,byteStart:0,byteEnd:Buffer.byteLength(source)}];
  const obligations=createSecurityObligations(target,ranges);
  return {target,ranges,obligations};
}
const rows=(obligations:SecurityObligation[])=>obligations.map(o=>({id:o.id,cases:o.cases.map(name=>({case:name,result:'not-applicable',reason:'Fixture operation has no live consumer in the isolated test.'})),evidence:o.anchors,findingIds:[] as string[],conditions:[]}));
const validate=(f:ReturnType<typeof fixture>,assessments:unknown,findingIds:string[]=[])=>validateSecurityAssessments({target:f.target,obligations:f.obligations,assessments,allowedFiles:['app.js'],findingIds});
describe('explicit security control coverage',()=>{
  it('requires server boundaries and method/owner checks even when a source file was read',()=>{
    const f=fixture();
    expect(f.obligations.map(o=>o.control)).toEqual(expect.arrayContaining(['input-validation','authorization','state-and-session']));
    expect(f.obligations.find(o=>o.control==='input-validation')!.cases).toContain('numeric-and-size-boundaries');
    expect(f.obligations.find(o=>o.control==='authorization')!.cases).toContain('role-and-http-method');
    expect(()=>validateAnalysisAssessments({target:f.target,files:['app.js'],ranges:f.ranges,securityObligations:f.obligations,
      value:{files:[{path:'app.js',status:'analyzed',rationale:'The source file has been read in full for this fixture.',evidence:[{lineStart:1,lineEnd:1,quote:readFileSync(join(f.target,'app.js'),'utf8').trim()}]}],flows:[]}})).toThrow('Missing security obligations');
  });
  it.each(["$id = $_GET['id']; echo $id;", "@app.route('/users', methods=['POST'])\ndef users(): return request.form['name']"])
    ('discovers controls for non-JavaScript input surfaces: %s',source=>{
      const f=fixture(source);expect(f.obligations.map(o=>o.control)).toContain('input-validation');
      expect(f.obligations.map(o=>o.control)).toContain('authorization');
    });
  it('does not change obligation identities for CRLF or final-newline-only changes',()=>{
    const f=fixture(),before=f.obligations.map(o=>o.id);
    const source=readFileSync(join(f.target,'app.js'),'utf8').replace(/\n/g,'\r\n');writeFileSync(join(f.target,'app.js'),source);
    expect(createSecurityObligations(f.target,[{...f.ranges[0]!,byteEnd:Buffer.byteLength(source)}]).map(o=>o.id)).toEqual(before);
    writeFileSync(join(f.target,'app.js'),source.trimEnd());
    expect(createSecurityObligations(f.target,[{...f.ranges[0]!,byteEnd:Buffer.byteLength(source.trimEnd())}]).map(o=>o.id)).toEqual(before);
  });
  it('bounds source hints without silently skipping minified source ranges',()=>{
    const source='const pad="'+ 'x'.repeat(16000)+'"; res.json(req.body);';const f=fixture(source);
    expect(f.obligations.length).toBeGreaterThan(0);
    expect(f.obligations.flatMap(o=>o.anchors).every(a=>a.quote.length<=800 && source.includes(a.quote))).toBe(true);
  });
  it('rejects missing, repeated or invented cases and source references',()=>{
    const f=fixture(),r=rows(f.obligations);r[0]!.cases.pop();expect(()=>validate(f,r)).toThrow('Missing security case');
    const duplicate=rows(f.obligations);duplicate[0]!.cases.push(duplicate[0]!.cases[0]!);expect(()=>validate(f,duplicate)).toThrow('duplicate security case');
    const outside=rows(f.obligations);outside[0]!.evidence=[{path:'../outside',lineStart:1,lineEnd:1,quote:'secret'}];expect(()=>validate(f,outside)).toThrow('outside assigned/context');
    const invented=rows(f.obligations);invented[0]!.evidence=[{path:'app.js',lineStart:1,lineEnd:1,quote:'invented guard'}];expect(()=>validate(f,invented)).toThrow('Invalid security evidence');
  });
  it('retains unresolved checks as incomplete and reports not-applicable separately',()=>{
    const f=fixture(),r=rows(f.obligations);r[0]!.cases[0]!.result='unresolved';
    const result=validate(f,r);expect(result.complete).toBe(false);expect(result.counts.unresolved).toBe(1);expect(result.counts['not-applicable']).toBeGreaterThan(0);
  });
  it('requires a submitted finding for a violated case',()=>{
    const f=fixture(),r=rows(f.obligations);r[0]!.cases[0]!.result='violated';
    expect(()=>validate(f,r)).toThrow('needs a submitted finding');r[0]!.findingIds=['F-existing'];
    expect(()=>validate(f,r)).toThrow('unknown finding');expect(validate(f,r,['F-existing']).complete).toBe(true);
  });
  it('requires independent delivery of cited control evidence, including upstream guards',()=>{
    const f=fixture(),security=validate(f,rows(f.obligations));
    expect(()=>validateAssessmentDelivery({ownedSources:[],contextRanges:[],flowResponsibilities:[],kind:'source'},
      {value:{files:[],flows:[]},security,complete:true},f.target,[])).toThrow('Missing verified source delivery');
  });
});
