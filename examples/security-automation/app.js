const names={code:['code-pentester','코드 구조·8개 진단 영역'],web:['web-pentester','요청 재현·현장 증거'],offsec:['OffSec Agent','분석·검토·평가·보고서'],soc:['SOC Agent','경보 조사·판단 근거']};
const $=s=>document.querySelector(s), esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let selected='web',mode='recording',state={recordings:{},results:{},events:[]};
let renderedResult='';
const metric=(n,t)=>`<div class="metric"><b>${esc(n)}</b><span>${esc(t)}</span></div>`;
function render(){
 $('#projects').innerHTML=Object.entries(names).map(([key,[name,description]])=>`<button class="project ${key===selected?'selected':''}" data-project="${key}"><span>${description}</span><strong>${name}</strong><span>${(mode==='recording'?state.recordings:state.results)[key]?.status==='completed'?'● 실행 완료':'○ 실행 대기'}</span></button>`).join('');
 $('#recording-mode').classList.toggle('active',mode==='recording');$('#live-mode').classList.toggle('active',mode==='live');
 $('#mode-note').textContent=mode==='recording'?'실제 성공 실행의 저장 기록입니다. 재실행은 “지금 실행”에서 선택하세요.':`로컬 샘플을 새로 실행합니다. AI 연결: ${state.aiAvailable?'준비됨':'환경변수 설정 필요'}`;
 $('#target-link').href=state.targetUrl;$('#web-button').hidden=selected!=='web';
 $('#run-button').hidden=mode!=='live';$('#run-button').disabled=!!state.busy||(['soc','offsec'].includes(selected)&&!state.aiAvailable);
 $('#run-button').textContent=state.busy===selected?'실행 중…':selected==='offsec'?'실제 AI 진단 · 최대 $4':selected==='soc'?'실제 AI 조사':'실제 실행';
 const r=(mode==='recording'?state.recordings:state.results)[selected];
 $('#result-title').textContent=r?.title||names[selected][0];
 $('#result-status').textContent=state.busy===selected&&mode==='live'?'실행 중':r?(mode==='recording'?'실제 실행 기록 · ':'')+(r.status==='completed'?'완료':'확인 필요'):'준비됨';
 $('#result-status').className='tag'+(r&&r.status!=='completed'?' warn':'');
 let body='';
 if(!r){body='<div class="empty">이 항목의 실행 기록을 준비하고 있습니다. “지금 실행”에서 샘플을 실행할 수 있습니다.</div>';}
 else{
  body=`<p class="muted">${esc(r.note||'')}</p><p class="muted">실행: ${esc(new Date(r.finished||r.started).toLocaleString('ko-KR'))}</p>`;
  if(r.error||r.reason)body+=`<p class="error">${esc(r.error||r.reason)}</p>`;
  if(selected==='web'&&r.requests)body+=`<table><thead><tr><th>요청자</th><th>요청</th><th>실제 응답</th></tr></thead><tbody>${r.requests.map((q,i)=>`<tr><td>고객 Alice</td><td>${esc(new URL(q.url).pathname)}<small>${['본인 송장 조회','타인 송장 조회 · 취약 경로','타인 송장 조회 · 수정 경로'][i]}</small></td><td><span class="tag ${i===1?'bad':''}">${q.status}</span><small>${esc(q.body.customer||q.body.error)}</small></td></tr>`).join('')}</tbody></table><div class="callout">같은 Alice 계정으로 Bob의 송장을 조회했습니다. 소유권 검사가 없는 경로는 200, 검사를 적용한 경로는 403을 반환합니다.</div>`;
  if(selected==='code')body+=`<div class="flow">인증 · 인가 · 데이터흐름 · 입출력<br>비밀관리 · 의존성 · 에러처리 · 리소스</div><details open><summary>실제 AST 전처리 통계</summary><pre>${esc(JSON.stringify(r.stats,null,2))}</pre></details><details><summary>Codex에서 독립 분석·검증을 실행할 프롬프트</summary><pre>${esc(r.nativePrompt)}</pre><button id="copy-prompt">프롬프트 복사</button></details>`;
  if(selected==='offsec')body+=`<div class="metrics">${metric(r.findings?.length||0,'원장 취약점 기록')}${metric(r.phaseMetrics?.filter(x=>x.validationPassed).length||0,'검증 통과 단계')}${metric(r.publicationStatus||'대기','보고서 발행')}</div>${(r.findings||[]).map(f=>`<article class="finding"><span class="tag ${f.severity==='HIGH'?'bad':'warn'}">${esc(f.severity)}</span><strong>${esc(f.title)}</strong><p>${esc(f.id)} · ${esc((f.evidence||[]).map(e=>e.path+':'+e.lineStart).join(', '))}</p><p>${esc(f.remediation)}</p></article>`).join('')}<details open><summary>실제 생성 보고서</summary><pre>${esc(r.report||'보고서가 아직 없습니다.')}</pre></details><details><summary>단계별 실행 기록</summary><pre>${esc(JSON.stringify(r.attempts,null,2))}</pre></details>`;
  if(selected==='soc'&&r.assessment){const a=r.assessment;body+=`<div class="metrics">${metric(({escalate:'담당자 확인',monitor:'추가 관찰',dismiss:'종결 검토'})[a.decision]||a.decision,'에이전트 권고')}${metric(r.modelCalls,'실제 모델 호출')}${metric(r.calls?.length||0,'실제 도구 조회')}</div><h3>${esc(a.title)}</h3><p>${esc(a.summary)}</p>${a.findings.map(f=>`<article class="finding"><p>${esc(f.description)}</p><span class="tag">근거 ${esc(f.evidence.join(' · '))}</span></article>`).join('')}<h3>대응 권고</h3><p>${esc(a.recommendation.immediate||'')}</p><p>${esc(a.recommendation.shortTerm)}</p><p>${esc(a.recommendation.monitoring)}</p><details><summary>도구 호출과 실제 반환 근거</summary><pre>${esc(JSON.stringify({calls:r.calls,observations:r.observations},null,2))}</pre></details>`;}
 }
 const contentKey=JSON.stringify([selected,mode,r?.finished,r?.status]);
 if(contentKey!==renderedResult){$('#result').innerHTML=body;renderedResult=contentKey;}
 $('#events').innerHTML=state.events.slice(-12).reverse().map(e=>`<div class="event"><time>${esc(new Date(e.at).toLocaleTimeString('ko-KR'))} · ${esc(e.kind)}</time>${esc(e.text)}</div>`).join('')||'<p class="muted">지금 실행을 시작하면 진행 과정이 표시됩니다.</p>';
}
async function update(){try{const r=await fetch('/state');state=await r.json();render();}catch{$('#mode-note').textContent='시연 서버 연결이 끊겼습니다. demo.sh serve로 다시 시작하세요.';}}
document.addEventListener('click',async e=>{
 const tab=e.target.closest('[data-project]');if(tab){selected=tab.dataset.project;render();return;}
 if(e.target.id==='recording-mode'){mode='recording';render();}
 if(e.target.id==='live-mode'){mode='live';render();}
 if(e.target.id==='copy-prompt')await navigator.clipboard.writeText((mode==='recording'?state.recordings:state.results).code.nativePrompt);
 if(['run-button','web-button'].includes(e.target.id)){
  try{const response=await fetch(e.target.id==='web-button'?'/open-web':'/run/'+selected,{method:'POST'});const result=await response.json();if(!response.ok)throw Error(result.error);await update();}catch(error){alert(error.message);}
 }
});
update();setInterval(update,2500);
