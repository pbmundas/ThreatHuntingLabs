import * as duckdb from '@duckdb/duckdb-wasm';
import manifestSnapshot from '../manifest.json';

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
let db, conn, databaseReady, lab = null;
let catalog = [], sources = [], lastRows = [], lastColumns = [];
let language = 'sql', sourceSchemas = {};
let progress = {}, currentUser = null, applicationStarted = false;
const ACCOUNT_KEY='blacksite-accounts-v1',SESSION_KEY='blacksite-session-v1';

const esc = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const ident = (value) => `"${String(value).replaceAll('"','""')}"`;
const str = (value) => `'${String(value).replaceAll("'","''")}'`;
const current = () => progress[lab?.id] ||= {done:[], hints:[], history:[]};
const progressKey = () => `blacksite-progress-v1:${currentUser?.toLowerCase()||'guest'}`;
const save = () => localStorage.setItem(progressKey(), JSON.stringify(progress));
function toast(message){const element=$('#toast');element.textContent=message;element.classList.add('show');clearTimeout(window.toastTimer);window.toastTimer=setTimeout(()=>element.classList.remove('show'),2500)}

const bytesToBase64=(bytes)=>btoa(String.fromCharCode(...bytes));
const base64ToBytes=(value)=>Uint8Array.from(atob(value),(char)=>char.charCodeAt(0));
function accounts(){try{return JSON.parse(localStorage.getItem(ACCOUNT_KEY)||'[]')}catch{return []}}
function sortCatalog(items){const rank={Novice:0,Intermediate:1,Expert:2};return [...items].sort((a,b)=>(rank[a.difficulty_tier]??99)-(rank[b.difficulty_tier]??99)||(a.estimated_minutes??999)-(b.estimated_minutes??999)||a.title.localeCompare(b.title))}
async function passwordVerifier(password,salt){const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:150000,hash:'SHA-256'},material,256);return bytesToBase64(new Uint8Array(bits))}
function loadProgress(){try{progress=JSON.parse(localStorage.getItem(progressKey())||'{}')}catch{progress={}}}
function updateProfile(){if(!currentUser)return;$('#profileName').textContent=`HUNTER · ${currentUser.toUpperCase()}`;$('#profileName').classList.remove('hidden');$('#logoutBtn').classList.remove('hidden');$('#libraryUser').textContent=`LOCAL PROFILE · ${currentUser.toUpperCase()}`}
function showAuth(message=''){currentUser=null;$('#accountGate').classList.remove('hidden');$('#labLibrary').classList.add('hidden');$('#authMessage').textContent=message;$('#engineStatus').textContent='SIGN IN · REQUIRED'}
async function completeAuth(username){currentUser=username;localStorage.setItem(SESSION_KEY,username);loadProgress();updateProfile();$('#accountGate').classList.add('hidden');$('#labLibrary').classList.remove('hidden');renderLibrary();await startApplication()}
function restoreSession(){const requested=localStorage.getItem(SESSION_KEY),match=accounts().find((account)=>account.username.toLowerCase()===requested?.toLowerCase());if(!match)return false;currentUser=match.username;loadProgress();updateProfile();return true}

async function initDatabase(){
  if(location.protocol==='file:')throw new Error('This lab requires a local web server');
  const base=new URL('./',location.href);
  const bundle=await duckdb.selectBundle({
    mvp:{mainModule:new URL('assets/vendor/duckdb-mvp.wasm',base).href,mainWorker:new URL('assets/vendor/duckdb-browser-mvp.worker.js',base).href},
    eh:{mainModule:new URL('assets/vendor/duckdb-eh.wasm',base).href,mainWorker:new URL('assets/vendor/duckdb-browser-eh.worker.js',base).href}
  });
  db=new duckdb.AsyncDuckDB(new duckdb.ConsoleLogger(duckdb.LogLevel.WARNING),new Worker(bundle.mainWorker));
  await db.instantiate(bundle.mainModule);conn=await db.connect();window.db=db;
  $('#engineStatus').textContent='DUCKDB · READY';$('#runBtn').disabled=false;$('#queryInfo').textContent='Select a lab to mount its evidence';
}

async function refreshCatalog(){
  if(location.protocol==='file:')return;
  try{const response=await fetch('manifest.json',{cache:'no-store'});if(!response.ok)return;catalog=sortCatalog((await response.json()).labs?.filter((item)=>item.published!==false)||catalog);renderLibrary()}
  catch(error){console.warn('Using bundled catalog snapshot',error)}
}

async function startApplication(){
  if(applicationStarted)return;applicationStarted=true;refreshCatalog();
  if(location.protocol==='file:'){$('#engineStatus').textContent='START SERVER · REQUIRED';$('#queryInfo').textContent='Run start-lab.cmd, then use http://localhost:8080';$('#labCards').insertAdjacentHTML('afterbegin','<div class="loading-card launch-warning"><b>Local server required</b><br>Double-click <code>start-lab.cmd</code> in the project folder. Opening index.html directly blocks WebAssembly and evidence files.</div>');return}
  databaseReady=initDatabase();
  try{await databaseReady;const requested=new URLSearchParams(location.search).get('lab');if(requested&&catalog.some((item)=>item.id===requested))await launchLab(requested)}
  catch(error){console.error(error);$('#engineStatus').textContent='ENGINE · ERROR';$('#labCards').innerHTML=`<div class="loading-card">${esc(error.message)}. Serve the project over HTTP; WebAssembly cannot start from a file:// URL.</div>`}
}

async function init(){
  catalog=sortCatalog((manifestSnapshot.labs||[]).filter((item)=>item.published!==false));renderQueryGuide();setSidebar(localStorage.getItem('blacksite-sidebar-open')!=='false');
  if(!restoreSession())return showAuth();
  $('#accountGate').classList.add('hidden');$('#labLibrary').classList.remove('hidden');renderLibrary();await startApplication();
}

function renderLibrary(){
  $('#labCards').innerHTML=catalog.length?catalog.map((item)=>{const completed=(progress[item.id]?.done||[]).length,total=item.steps?.length||0,percent=total?completed/total*100:0;return `<article class="lab-card"><div><span class="difficulty ${esc((item.difficulty_tier||'novice').toLowerCase())}">${esc(item.difficulty_tier||'Novice')}</span><span>${esc(item.estimated_minutes||30)} MIN</span></div><h3>${esc(item.title)}</h3><p>${esc(item.hypothesis||item.description||'Investigate the assigned telemetry and prove or disprove the hypothesis.')}</p><div class="lab-sources">${(item.log_sources||[]).slice(0,4).map((source)=>`<span>${esc(source)}</span>`).join('')}</div><div class="lab-tags">${(item.mitre_tags||[]).slice(0,4).map((tag)=>`<span>${esc(tag)}</span>`).join('')}</div><div class="lab-progress"><div><i style="width:${percent}%"></i></div><span>${completed} / ${total} CHALLENGES COMPLETE</span></div><button data-launch="${esc(item.id)}">${completed===total&&total?'REOPEN COMPLETED LAB':'LAUNCH INVESTIGATION'} →</button></article>`}).join(''):'<div class="loading-card"><b>No labs have been published.</b><br>An administrator must add a published entry to manifest.json.</div>';
  $$('[data-launch]').forEach((button)=>button.onclick=()=>launchLab(button.dataset.launch));
}

async function launchLab(id){
  if(location.protocol==='file:')return toast('RUN START-LAB.CMD TO LAUNCH EVIDENCE');
  if(!conn){toast('DATABASE IS STARTING · PLEASE WAIT');try{await databaseReady}catch{return}if(!conn)return}
  lab=catalog.find((item)=>item.id===id);if(!lab)return;$('#labLibrary').classList.add('hidden');
  history.replaceState(null,'',`?lab=${encodeURIComponent(id)}`);$('#caseTitle').textContent=`${lab.id} · ${lab.title}`.toUpperCase();
  $('#caseDescription').innerHTML=lab.hypothesis?`<b>HYPOTHESIS:</b> ${esc(lab.hypothesis)}`:esc(lab.description||'Complete the assigned investigation.');
  $('#mitreTags').innerHTML=(lab.mitre_tags||[]).map((tag)=>`<span class="tag active">${esc(tag)}</span>`).join('')||'<span class="tag">NO TAGS</span>';
  renderObjectives();await mountLabSources();
}

async function mountLabSources(){
  sources=[];sourceSchemas={};$('#engineStatus').textContent='MOUNTING · EVIDENCE';$('#sourceList').innerHTML='<span>Mounting administrator-published evidence…</span>';
  try{
    for(const source of lab.parquet_sources||lab.sources||[]){
      const table=source.table||source.name,url=new URL(source.url,location.href).href,ext=(url.split('?')[0].split('.').pop()||'parquet').toLowerCase(),file=`${table}.${ext}`;
      await db.registerFileURL(file,url,duckdb.DuckDBDataProtocol.HTTP,false);
      const reader=ext==='parquet'?`read_parquet(${str(file)})`:ext==='csv'?`read_csv_auto(${str(file)},normalize_names=true)`: `read_json_auto(${str(file)})`;
      await conn.query(`CREATE OR REPLACE VIEW ${ident(table)} AS SELECT * FROM ${reader}`);sources.push({...source,table,ext});
      sourceSchemas[table]=rowsOf(await conn.query(`DESCRIBE ${ident(table)}`)).map((field)=>({name:field.column_name,type:field.column_type}));
    }
    renderSources();renderQueryGuide();$('#engineStatus').textContent='DUCKDB · READY';
    if(sources.length){setStarterQuery();await runQuery()}else{$('#queryInfo').textContent='This lab has no configured evidence';toast('LAB MANIFEST HAS NO DATA SOURCES')}
  }catch(error){console.error(error);$('#engineStatus').textContent='EVIDENCE · ERROR';$('#sourceList').innerHTML='<span>Evidence could not be mounted. Ask the administrator to verify the URL and CORS range headers.</span>';toast('EVIDENCE MOUNT FAILED')}
}

function renderSources(){
  $('#sourceCount').textContent=`${sources.length} TABLE${sources.length===1?'':'S'}`;
  $('#sourceList').innerHTML=sources.map((source)=>`<button class="source-item" data-table="${esc(source.table)}"><b>${esc(source.table)}</b><span>${esc(source.ext.toUpperCase())} · ADMIN</span></button>`).join('');
  $('#logSourceList').innerHTML=(lab.log_sources||[]).map((source)=>`<span>${esc(source)}</span>`).join('');
  $$('.source-item').forEach((button)=>button.onclick=()=>setStarterQuery(button.dataset.table));
  $('#queryInfo').textContent=`${sources.length} evidence source${sources.length===1?'':'s'} ready`;
}

function activeTable(){return sources[0]?.table||'logs'}
function setStarterQuery(table=activeTable()){$('#queryEditor').value=language==='sql'?`SELECT *\nFROM ${ident(table)}\nLIMIT 100;`:`${table}\n| take 100`}
function schemaFor(table=activeTable()){return sourceSchemas[table]||[]}

function translateKqlExpression(expression){
  let value=expression.trim();
  const literal=(text)=>str(text.slice(1,-1));
  value=value.replace(/([A-Za-z_][\w.]*)\s+!contains\s+("[^"]*"|'[^']*')/gi,(_,field,text)=>`CAST(${field} AS VARCHAR) NOT ILIKE ${str(`%${text.slice(1,-1)}%`)}`);
  value=value.replace(/([A-Za-z_][\w.]*)\s+(contains|has)\s+("[^"]*"|'[^']*')/gi,(_,field,op,text)=>`CAST(${field} AS VARCHAR) ILIKE ${str(`%${text.slice(1,-1)}%`)}`);
  value=value.replace(/([A-Za-z_][\w.]*)\s+startswith\s+("[^"]*"|'[^']*')/gi,(_,field,text)=>`CAST(${field} AS VARCHAR) ILIKE ${str(`${text.slice(1,-1)}%`)}`);
  value=value.replace(/([A-Za-z_][\w.]*)\s+endswith\s+("[^"]*"|'[^']*')/gi,(_,field,text)=>`CAST(${field} AS VARCHAR) ILIKE ${str(`%${text.slice(1,-1)}`)}`);
  value=value.replace(/([A-Za-z_][\w.]*)\s*=~\s+("[^"]*"|'[^']*')/gi,(_,field,text)=>`lower(CAST(${field} AS VARCHAR)) = lower(${literal(text)})`);
  value=value.replace(/"([^"]*)"/g,(_,text)=>str(text)).replace(/==/g,'=').replace(/\bnot\b/gi,'NOT').replace(/\band\b/gi,'AND').replace(/\bor\b/gi,'OR');
  return value;
}

function translateKql(query){
  const pipes=query.split('|').map((part)=>part.trim()).filter(Boolean);if(!pipes.length)throw new Error('KQL must begin with a table name');
  const table=pipes.shift().split(/\s+/)[0],fields=schemaFor(table).map((field)=>field.name);let select='*',where=[],group='',order='',limit='';
  for(const pipe of pipes){
    if(/^where\s+/i.test(pipe))where.push(translateKqlExpression(pipe.replace(/^where\s+/i,'')));
    else if(/^search\s+/i.test(pipe)){const term=pipe.replace(/^search\s+/i,'').trim().replace(/^['"]|['"]$/g,'');if(!fields.length)throw new Error('Search requires a mounted table schema');where.push(`concat_ws(' ',${fields.map((field)=>`COALESCE(CAST(${ident(field)} AS VARCHAR),'')`).join(',')}) ILIKE ${str(`%${term}%`)}`)}
    else if(/^project\s+/i.test(pipe))select=pipe.replace(/^project\s+/i,'').split(',').map((field)=>ident(field.trim())).join(', ');
    else if(/^summarize\s+count\(\)\s+by\s+/i.test(pipe)){const groups=pipe.replace(/^summarize\s+count\(\)\s+by\s+/i,'').split(',').map((field)=>ident(field.trim()));select=`${groups.join(', ')}, count(*) AS event_count`;group=` GROUP BY ${groups.join(', ')}`}
    else if(/^(order|sort)\s+by\s+/i.test(pipe)){const match=pipe.match(/^(?:order|sort)\s+by\s+([\w.]+)(?:\s+(asc|desc))?/i);if(!match)throw new Error('Use order by Field desc');order=` ORDER BY ${ident(match[1])} ${(match[2]||'asc').toUpperCase()}`}
    else if(/^(take|limit)\s+/i.test(pipe)){const count=Number(pipe.split(/\s+/)[1]);if(!Number.isInteger(count)||count<1||count>10000)throw new Error('Take must be between 1 and 10000');limit=` LIMIT ${count}`}
    else throw new Error(`Unsupported KQL operator: ${pipe.split(/\s+/)[0]}`);
  }
  return `SELECT ${select} FROM ${ident(table)}${where.length?` WHERE ${where.join(' AND ')}`:''}${group}${order}${limit}`;
}
function translate(query){return language==='kql'?translateKql(query):query}

async function runQuery(){
  if(!conn)return;const raw=$('#queryEditor').value.trim();let sql;try{sql=translate(raw)}catch(error){return toast(error.message.toUpperCase())}
  $('#runBtn').disabled=true;$('#resultMeta').textContent='RUNNING';const started=performance.now();
  try{const result=await conn.query(sql);lastColumns=result.schema.fields.map((field)=>field.name);lastRows=rowsOf(result);const state=current();state.history.push(raw);state.history=state.history.slice(-50);save();renderGrid();renderAnalytics();renderTimeline();$('#resultMeta').textContent=`${lastRows.length.toLocaleString()} ROWS · ${Math.round(performance.now()-started)} MS`}
  catch(error){console.error(error);$('#resultMeta').textContent='QUERY ERROR';toast(String(error.message).split('\n')[0].slice(0,120))}finally{$('#runBtn').disabled=false}
}

function rowsOf(table){return table.toArray().map((row)=>{const data=typeof row.toJSON==='function'?row.toJSON():row;return Object.fromEntries(Object.entries(data).map(([key,value])=>[key,typeof value==='bigint'?Number(value):value instanceof Date?value.toISOString():value??'']))})}
function rawEvent(row){const explicit=lastColumns.find((column)=>/^(_?raw|raw_event|event_original|original_event)$/i.test(column));if(explicit&&row[explicit])return String(row[explicit]);const message=lastColumns.find((column)=>/^(message|eventmessage|description)$/i.test(column));return message&&row[message]?String(row[message]):JSON.stringify(row)}
function renderedValue(value){return value===''||value===null||value===undefined?'<span class="null-value">null</span>':esc(value)}
function renderGrid(){
  const display=[...lastColumns,'raw_event'];$('#gridHead').innerHTML=lastColumns.length?`<tr><th>EVENT</th>${display.map((column)=>`<th>${esc(column)}</th>`).join('')}</tr>`:'';
  $('#gridBody').innerHTML=lastRows.slice(0,500).map((row,index)=>`<tr><td><button class="event-open" data-event="${index}">VIEW</button></td>${display.map((column)=>{const raw=column==='raw_event',value=raw?rawEvent(row):row[column];return `<td class="${raw?'raw-cell':''}" data-col="${esc(column)}" data-value="${esc(value)}">${renderedValue(value)}</td>`}).join('')}</tr>`).join('');
  $('#emptyState').classList.toggle('hidden',lastRows.length>0);if(!lastRows.length)$('#emptyState').textContent='No events matched this query.';
  $$('.event-open').forEach((button)=>button.onclick=()=>openInspector(Number(button.dataset.event)));
  $$('#gridBody td[data-col]').forEach((cell)=>cell.ondblclick=()=>{if(cell.dataset.col==='raw_event')return;appendFilter(cell.dataset.col,cell.dataset.value);toast('FILTER APPENDED')});
}

function openInspector(index){
  const row=lastRows[index];if(!row)return;$('#inspectorTitle').textContent=`EVENT ${index+1} · ${lastColumns.length} PARSED FIELDS`;
  $('#inspectorBody').innerHTML=`<dl class="inspector-fields">${lastColumns.map((column)=>`<dt>${esc(column)}</dt><dd>${renderedValue(row[column])}</dd>`).join('')}</dl><section class="raw-event"><h3>RAW EVENT</h3><pre>${esc(rawEvent(row))}</pre></section>`;
  $('#eventInspector').classList.remove('hidden');
}

function appendFilter(field,value){
  const editor=$('#queryEditor'),numeric=value!==''&&Number.isFinite(Number(value)),literal=numeric?String(Number(value)):language==='sql'?str(value):`"${String(value).replaceAll('"','\\"')}"`;
  if(language==='kql')editor.value+=`\n| where ${field} == ${literal}`;
  else{const withoutSemi=editor.value.trim().replace(/;$/,'');editor.value=/\bwhere\b/i.test(withoutSemi)?`${withoutSemi}\n  AND ${ident(field)} = ${literal};`:`${withoutSemi.replace(/\s+LIMIT\s+\d+$/i,'')}\nWHERE ${ident(field)} = ${literal}\nLIMIT 100;`}
}

function findField(pattern,excluded=[]){return lastColumns.find((column)=>!excluded.includes(column)&&pattern.test(column))}
function countsFor(field){const counts=new Map;for(const row of lastRows){const value=String(row[field]??'').trim();if(value)counts.set(value,(counts.get(value)||0)+1)}return [...counts].sort((a,b)=>b[1]-a[1]).slice(0,7)}
function distributionPanel(field,title){
  if(!field)return `<section class="chart-panel"><div class="chart-title"><span>${esc(title)}</span><b>NO MATCHING FIELD</b></div><div class="analytics-empty">Select this field in your query to profile it.</div></section>`;
  const counts=countsFor(field),max=counts[0]?.[1]||1;
  return `<section class="chart-panel"><div class="chart-title"><span>${esc(title)}</span><b>${esc(field)}</b></div><div class="top-values">${counts.map(([value,count])=>`<button class="value-bar" data-pivot-field="${esc(field)}" data-pivot-value="${esc(value)}"><i style="width:${Math.max(3,count/max*100)}%"></i><span>${esc(value)}</span><b>${count}</b></button>`).join('')||'<div class="analytics-empty">No populated values</div>'}</div></section>`;
}
function renderAnalytics(){
  if(!lastRows.length){$('#analyticsBody').innerHTML='<div class="analytics-empty">No events available for statistical profiling.</div>';$('#analyticsMeta').textContent='0 EVENTS';return}
  const timeField=findField(/^(timestamp|timecreated|event_time|datetime|@timestamp|date)$/i)||findField(/time|date/i);
  const categoryField=findField(/^(eventid|event_id|eventtype|event_type|action|channel|providername|provider)$/i)||findField(/event|action|channel|provider/i);
  const sourceField=findField(/^(sourcename|source_name|providername|provider_name|channel)$/i)||findField(/source.*name|provider|channel/i);
  const entityField=findField(/^(hostname|computer|host|subjectusername|username|user|processname|image|sourceip|destinationip)$/i,[categoryField])||findField(/host|computer|user|process|image|source.*ip|destination.*ip/i,[categoryField]);
  let histogram='<section class="chart-panel"><div class="chart-title"><span>EVENT VOLUME</span><b>NO TIMESTAMP FIELD</b></div><div class="analytics-empty">Include a timestamp field to build a time histogram.</div></section>';
  if(timeField){const timed=lastRows.map((row)=>new Date(row[timeField]).getTime()).filter(Number.isFinite);if(timed.length){const min=Math.min(...timed),max=Math.max(...timed),bins=18,span=Math.max(1,max-min),values=Array(bins).fill(0);timed.forEach((time)=>values[Math.min(bins-1,Math.floor((time-min)/span*bins))]++);const peak=Math.max(...values,1);histogram=`<section class="chart-panel"><div class="chart-title"><span>EVENT VOLUME · ${timed.length} TIMESTAMPED</span><b>${esc(timeField)}</b></div><div class="histogram" role="img" aria-label="Event count over time">${values.map((count,index)=>`<button class="hist-bar" style="height:${Math.max(2,count/peak*100)}%" aria-label="Time bucket ${index+1}: ${count} events"><span>${count} events</span></button>`).join('')}</div></section>`}}
  $('#analyticsBody').innerHTML=histogram+distributionPanel(categoryField,'TOP EVENT CATEGORY')+distributionPanel(sourceField,'LOG SOURCE MIX')+distributionPanel(entityField,'TOP ENTITY');$('#analyticsMeta').textContent=`PROFILED ${lastRows.length.toLocaleString()} RETURNED EVENTS`;
  $$('[data-pivot-field]').forEach((button)=>button.onclick=()=>{appendFilter(button.dataset.pivotField,button.dataset.pivotValue);runQuery()});
}

function renderTimeline(){
  const timeline=$('#timeline');timeline.innerHTML='<div class="axis"></div>';const timeColumn=findField(/^(timestamp|timecreated|event_time|datetime|@timestamp|date)$/i)||findField(/time|date/i);
  if(!timeColumn){$('#timelineRange').textContent='NO TIMESTAMP COLUMN IN RESULTS';return}const items=lastRows.map((row,index)=>({row,index,time:new Date(row[timeColumn])})).filter((item)=>!Number.isNaN(item.time.getTime())).sort((a,b)=>a.time-b.time);if(!items.length){$('#timelineRange').textContent='NO PARSEABLE TIMESTAMPS';return}
  const min=items[0].time.getTime(),max=items.at(-1).time.getTime(),span=Math.max(1,max-min);$('#timelineRange').textContent=`${items[0].time.toLocaleString()} — ${items.at(-1).time.toLocaleString()}`;
  timeline.insertAdjacentHTML('beforeend',items.slice(0,300).map(({row,index,time},position)=>{const high=/critical|high|malicious|denied|failed|alert|suspicious|powershell|service installed/i.test(Object.values(row).join(' ')),left=2+((time.getTime()-min)/span)*96;return `<button class="event ${high?'high':''}" data-timeline-event="${index}" style="left:${left}%;--height:${15+(position%4)*8}px" aria-label="Inspect event at ${esc(time.toISOString())}"></button>`}).join(''));$$('[data-timeline-event]').forEach((button)=>button.onclick=()=>openInspector(Number(button.dataset.timelineEvent)));
}

function renderQueryGuide(){
  const table=activeTable(),fields=schemaFor(table),fieldNames=fields.map((field)=>field.name),category=fieldNames.find((name)=>/eventid|event_type|action|hostname|user/i.test(name))||fieldNames[0]||'EventID';
  const recipes=language==='sql'?[['Recent events',`SELECT * FROM ${ident(table)} LIMIT 100;`],['Filter a field',`SELECT * FROM ${ident(table)} WHERE ${ident(category)} = ${/id/i.test(category)?'7045':str('value')} LIMIT 100;`],['Count by field',`SELECT ${ident(category)}, count(*) AS event_count FROM ${ident(table)} GROUP BY 1 ORDER BY event_count DESC;`],['Search raw text',`SELECT * FROM ${ident(table)} WHERE CAST(${ident(fieldNames.find((name)=>/message|raw/i.test(name))||category)} AS VARCHAR) ILIKE '%powershell%' LIMIT 100;`]]:[['Recent events',`${table}\n| take 100`],['Filter a field',`${table}\n| where ${category} == ${/id/i.test(category)?'7045':'"value"'}\n| take 100`],['Search every field',`${table}\n| search "powershell"\n| take 100`],['Count by field',`${table}\n| summarize count() by ${category}\n| order by event_count desc`]];
  $('#guideLanguage').textContent=language.toUpperCase();$('#queryRecipes').innerHTML=recipes.map(([label,query])=>`<button class="recipe" data-recipe="${esc(query)}"><span>${esc(label)}</span>${esc(query)}</button>`).join('');
  $('#syntaxHelp').innerHTML=language==='sql'?'<code>WHERE Field = value</code><code>ILIKE \'%text%\' for case-insensitive search</code><code>GROUP BY + count(*) for frequency</code><code>ORDER BY ... DESC · LIMIT 100</code>':'<code>| where Field == value</code><code>| search "text" across every field</code><code>contains · !contains · startswith · endswith</code><code>| project Field1, Field2</code><code>| summarize count() by Field</code><code>| order by event_count desc · | take 100</code>';
  renderFieldList($('#fieldSearch')?.value||'');$$('[data-recipe]').forEach((button)=>button.onclick=()=>{$('#queryEditor').value=button.dataset.recipe;$('#queryGuide').classList.add('hidden');$('#guideBtn').setAttribute('aria-expanded','false')});
}
function renderFieldList(filter=''){const fields=Object.entries(sourceSchemas).flatMap(([table,schema])=>schema.map((field)=>({...field,table}))).filter((field)=>field.name.toLowerCase().includes(filter.toLowerCase()));$('#fieldList').innerHTML=fields.length?fields.map((field)=>`<button class="field-item" data-field="${esc(field.name)}"><span>${esc(field.name)}</span><small>${esc(field.type)}</small></button>`).join(''):'<span>No matching fields.</span>';$$('[data-field]').forEach((button)=>button.onclick=()=>{const editor=$('#queryEditor'),token=language==='sql'?ident(button.dataset.field):button.dataset.field;editor.setRangeText(token,editor.selectionStart,editor.selectionEnd,'end');editor.focus()})}

async function digest(value){const buffer=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value.trim().toLowerCase()));return [...new Uint8Array(buffer)].map((item)=>item.toString(16).padStart(2,'0')).join('')}
async function verify(index,value){
  const step=lab.steps[index],state=current();if(index>0&&!state.done.includes(index-1))return toast('OBJECTIVE LOCKED');
  const answerOk=await digest(value)===String(step.solution_hash).toLowerCase(),queryOk=!step.required_query_token||state.history.some((query)=>query.toLowerCase().includes(step.required_query_token.toLowerCase()));let evidenceOk=true;
  if(answerOk&&step.verification_sql){try{const result=rowsOf(await conn.query(step.verification_sql));evidenceOk=Number(Object.values(result[0]||{})[0])>0}catch{evidenceOk=false}}
  if(answerOk&&queryOk&&evidenceOk){if(!state.done.includes(index))state.done.push(index);save();renderObjectives();toast('EVIDENCE VERIFIED · OBJECTIVE COMPLETE')}else if(answerOk)toast('ANSWER MATCHED · INVESTIGATION NOT VERIFIED');else toast('INCORRECT · CHECK THE EVIDENCE');
}
function renderObjectives(){
  const state=current(),steps=lab.steps||[];$('#progressText').textContent=`${state.done.length} / ${steps.length}`;$('#objectives').className='';
  $('#objectives').innerHTML=steps.map((step,index)=>{const locked=index>0&&!state.done.includes(index-1),done=state.done.includes(index),status=done?'COMPLETE':locked?'LOCKED':'ACTIVE',hint=(step.hints||[])[0]||step.hint;return `<article class="objective ${locked?'locked':''} ${done?'done':''}"><div class="obj-top"><span class="obj-num">${done?'✓':String(index+1).padStart(2,'0')}</span><div><h3>${esc(step.title||`Challenge ${index+1}`)}<span class="obj-status">${status}</span></h3><p>${esc(step.prompt)}</p></div></div><div class="answer-row"><input id="answer${index}" ${locked||done?'disabled':''} placeholder="${done?'Verified':'Enter evidence…'}"><button data-verify="${index}" ${locked||done?'disabled':''}>VERIFY</button></div>${hint?`<button class="hint" data-hint="${index}" ${locked?'disabled':''}>+ REQUEST HINT</button>`:''}${state.hints.includes(index)?`<div class="hint-text">${esc(hint)}</div>`:''}</article>`}).join('')||'<div class="no-objectives">This lab has no configured challenges.</div>';
  $$('[data-verify]').forEach((button)=>button.onclick=()=>verify(Number(button.dataset.verify),$(`#answer${button.dataset.verify}`).value));$$('[data-hint]').forEach((button)=>button.onclick=()=>{const index=Number(button.dataset.hint);if(!state.hints.includes(index))state.hints.push(index);save();renderObjectives()});
}

$('#runBtn').onclick=runQuery;$('#queryEditor').onkeydown=(event)=>{if(event.key==='Enter'&&(event.ctrlKey||event.metaKey)){event.preventDefault();runQuery()}};
$$('.tab').forEach((button)=>button.onclick=()=>{$$('.tab').forEach((item)=>item.classList.remove('active'));button.classList.add('active');language=button.dataset.lang;setStarterQuery();renderQueryGuide()});
$('#guideBtn').onclick=()=>{const opening=$('#queryGuide').classList.contains('hidden');$('#queryGuide').classList.toggle('hidden',!opening);$('#guideBtn').setAttribute('aria-expanded',String(opening));if(opening)renderQueryGuide()};
$('#closeGuide').onclick=()=>{$('#queryGuide').classList.add('hidden');$('#guideBtn').setAttribute('aria-expanded','false')};$('#fieldSearch').oninput=(event)=>renderFieldList(event.target.value);
$('#closeInspector').onclick=()=>$('#eventInspector').classList.add('hidden');
function showLibrary(){renderLibrary();$('#labLibrary').classList.remove('hidden');$('#eventInspector').classList.add('hidden');history.replaceState(null,'',location.pathname)}
$('#changeLab').onclick=showLibrary;$('#libraryBtn').onclick=showLibrary;
$('#resetBtn').onclick=()=>{if(!lab)return toast('LAUNCH A LAB FIRST');if(confirm('Reset progress for this lab?')){delete progress[lab.id];save();renderObjectives();toast('LAB PROGRESS RESET')}};
function setSidebar(open){document.body.classList.toggle('workspace-focus',!open);$('#sidebarToggle').textContent=open?'HIDE CHALLENGES':'SHOW CHALLENGES';$('#sidebarToggle').setAttribute('aria-expanded',String(open));localStorage.setItem('blacksite-sidebar-open',String(open))}
$('#sidebarToggle').onclick=()=>setSidebar(document.body.classList.contains('workspace-focus'));
$$('[data-auth-tab]').forEach((button)=>button.onclick=()=>{$$('[data-auth-tab]').forEach((item)=>item.classList.toggle('active',item===button));$('#loginForm').classList.toggle('hidden',button.dataset.authTab!=='login');$('#registerForm').classList.toggle('hidden',button.dataset.authTab!=='register');$('#authMessage').textContent=''});
$('#registerForm').onsubmit=async(event)=>{event.preventDefault();const username=$('#registerUsername').value.trim(),password=$('#registerPassword').value,confirmPassword=$('#registerConfirm').value;if(!/^[A-Za-z0-9._-]{3,24}$/.test(username))return $('#authMessage').textContent='Use 3–24 letters, numbers, dots, underscores, or hyphens.';if(password.length<8)return $('#authMessage').textContent='Password must contain at least 8 characters.';if(password!==confirmPassword)return $('#authMessage').textContent='Passwords do not match.';const list=accounts();if(list.some((account)=>account.username.toLowerCase()===username.toLowerCase()))return $('#authMessage').textContent='That local username already exists.';$('#authMessage').textContent='Creating local profile…';const salt=crypto.getRandomValues(new Uint8Array(16)),verifier=await passwordVerifier(password,salt);list.push({username,salt:bytesToBase64(salt),verifier,created_at:new Date().toISOString()});localStorage.setItem(ACCOUNT_KEY,JSON.stringify(list));await completeAuth(username)};
$('#loginForm').onsubmit=async(event)=>{event.preventDefault();const username=$('#loginUsername').value.trim(),password=$('#loginPassword').value,account=accounts().find((item)=>item.username.toLowerCase()===username.toLowerCase());if(!account)return $('#authMessage').textContent='Local profile or password is incorrect.';$('#authMessage').textContent='Verifying local profile…';const verifier=await passwordVerifier(password,base64ToBytes(account.salt));if(verifier!==account.verifier)return $('#authMessage').textContent='Local profile or password is incorrect.';await completeAuth(account.username)};
$('#logoutBtn').onclick=()=>{localStorage.removeItem(SESSION_KEY);location.href=location.pathname};
init();
