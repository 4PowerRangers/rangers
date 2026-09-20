const BASE=import.meta.env.VITE_API_URL??'';
const json=async(r:Response)=>{const body=await r.json().catch(()=>({}));if(!r.ok){const detail=body?.detail;const message=typeof detail==='string'?detail:typeof detail?.message==='string'?`${detail.message}${detail.error?`: ${detail.error}`:''}`:`Request failed (${r.status})`;throw new Error(message)}return body};
export const api={
 getScenarios:()=>fetch(`${BASE}/api/meta/scenarios`).then(json),
 getEnvStatus:()=>fetch(`${BASE}/api/env/status`).then(json),
 startEnvironment:()=>fetch(`${BASE}/api/env/start`,{method:'POST'}).then(json),
 getRuns:(scenario?:string)=>fetch(`${BASE}/api/runs${scenario?`?scenario=${encodeURIComponent(scenario)}`:''}`).then(json),
 startBatch:(body:unknown)=>fetch(`${BASE}/api/runs/batch`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(json),
 startPressure:(body:unknown)=>fetch(`${BASE}/api/runs/pressure`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(json),
 getPressure:(scenario:string)=>fetch(`${BASE}/api/runs/${encodeURIComponent(scenario)}/pressure`).then(json),
 getPressureSummary:(params:Record<string,string|undefined>={})=>{const query=new URLSearchParams(Object.entries(params).filter(([,value])=>value).map(([key,value])=>[key,value as string]));const endpoint=`${BASE}/api/pressure/summary${query.toString()?`?${query}`:''}`;return fetch(endpoint).then(async response=>{const body=await response.json().catch(()=>({}));if(!response.ok){const detail=typeof body?.detail==='string'?body.detail:'server aggregation failed';throw new Error(`Pressure summary API ${response.status} (${endpoint}): ${detail}`)}return body})},
 getBatch:(id:string)=>fetch(`${BASE}/api/runs/batch/${id}`).then(json),
 getActiveBatches:()=>fetch(`${BASE}/api/runs/batch`).then(json),
 getDetail:(id:string)=>fetch(`${BASE}/api/runs/${id}`).then(json),
 getCommandTools:(id:string)=>fetch(`${BASE}/api/runs/${id}/command-tools`).then(json),
 getActions:(id:string)=>fetch(`${BASE}/api/runs/${id}/actions`).then(json),
 getArtifacts:(id:string)=>fetch(`${BASE}/api/runs/${id}/artifacts`).then(json),
 getOverlay:(id:string)=>fetch(`${BASE}/api/runs/${id}/overlay`).then(json),
 getTerminal:(id:string)=>fetch(`${BASE}/api/runs/${id}/terminal`).then(json),
 deleteRun:(id:string)=>fetch(`${BASE}/api/runs/${encodeURIComponent(id)}`,{method:'DELETE'}).then(r=>{if(!r.ok)throw new Error('delete failed');return r.json()}),
 stopBatch:(id:string)=>fetch(`${BASE}/api/runs/batch/${id}/stop`,{method:'POST'}),
 stopRun:(id:string)=>fetch(`${BASE}/api/runs/${id}/stop`,{method:'POST'}),
 stream:(id:string,on:(x:any)=>void)=>{const source=new EventSource(`${BASE}/api/runs/${id}/stream`);source.onmessage=e=>on(JSON.parse(e.data));return source},
};
