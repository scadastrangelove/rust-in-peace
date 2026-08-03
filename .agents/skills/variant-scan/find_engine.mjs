// find_engine — the reference orchestration for /variant-scan, for the Workflow tool.
//
// One seed-diverse find pass: N lens-agents (all blind, all threat-model-seeded, or
// all CVE/history-seeded — the caller decides by what prompts it puts in `lenses`) →
// union-of-N dedup with vote-counting → a 3-skeptic adversarial verify panel
// (correctness / reachability / impact) → per-candidate disposition.
//
// Run it ONCE PER SEED SOURCE (blind, tm, cve) and union the three results — see
// SKILL.md. The disposition it emits is a TRIAGE signal, NOT a verdict: a
// "confirmed" candidate still has to survive reading the actual verifier text and an
// independent PoC before it is real (LESSONS L19/L22/L26; the gitoxide tar-slip and
// x509 two-layer over-claims both scored "confirmed" here and were false).
//
// args = { name, src, context, lenses:[{id,p}], verify_context? }
export const meta = {
  name: 'find-engine',
  description: 'Generalized first-pass find: N lens-diverse finders (TM-seeded, blind, or CVE-seeded) + 3-skeptic verify panel',
  phases: [{ title: 'Find' }, { title: 'Verify' }],
}
const A = typeof args === 'string' ? JSON.parse(args) : args
const SRC = A.src

const FIND_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['findings'],
  properties: { findings: { type: 'array', items: {
    type: 'object', additionalProperties: false,
    required: ['bug_class','file','line','symbol','mechanism','reachability_from_entry','poc_sketch','severity','confidence'],
    properties: {
      bug_class:{type:'string'}, file:{type:'string'}, line:{type:'integer'}, symbol:{type:'string'},
      mechanism:{type:'string'}, reachability_from_entry:{type:'string'}, poc_sketch:{type:'string'},
      severity:{type:'string', enum:['CRITICAL','HIGH','MEDIUM','LOW','INFO']},
      confidence:{type:'string', enum:['high','medium','low']},
    } } } },
}
const VERDICT_SCHEMA = {
  type:'object', additionalProperties:false,
  required:['real','reachable','where_checked','severity','reason'],
  properties:{ real:{type:'boolean'}, reachable:{type:'boolean'},
    where_checked:{type:'string'}, severity:{type:'string', enum:['CRITICAL','HIGH','MEDIUM','LOW','INFO']}, reason:{type:'string'} },
}
async function tryAgent(prompt, opts, tries = 3) {
  for (let i=0;i<tries;i++){ const r=await agent(prompt,{...opts,label:`${opts.label}${i?`#r${i}`:''}`}); if(r) return r }
  return null
}

phase('Find')
const findResults = await parallel(A.lenses.map(L => () =>
  tryAgent(`${A.context}\n\n${L.p}`, { schema: FIND_SCHEMA, phase:'Find', label:`find:${A.name}:${L.id}` })
    .then(r => ((r&&r.findings)||[]).map(f => ({...f, lens:L.id})))))
const allF = findResults.filter(Boolean).flat()
const keyOf = f => `${(f.bug_class||'').toLowerCase().split(/[\s(]/)[0]}@${f.file}:${f.symbol}`
const byKey = new Map()
for (const f of allF){ const k=keyOf(f); if(!byKey.has(k)) byKey.set(k,{...f,votes:1,lenses:[f.lens]}); else {const e=byKey.get(k); e.votes++; e.lenses.push(f.lens)} }
const cands=[...byKey.values()].sort((a,b)=>b.votes-a.votes)
log(`[${A.name}] find: ${allF.length} raw → ${cands.length} unique`)

phase('Verify')
const verified = await pipeline(cands,
  c => parallel(['correctness','reachability','impact'].map(vl => () =>
    tryAgent(`You are a SKEPTICAL verifier (lens: ${vl}) trying to REFUTE this "${A.name}" finding. Default to doubt. Source at ${SRC}.
${A.verify_context || ''}
FINDING: ${c.bug_class} at ${c.file}:${c.line} (${c.symbol}); mechanism: ${c.mechanism}; reachability: ${c.reachability_from_entry}; poc: ${c.poc_sketch}
Read the ACTUAL code. Is it real + reachable from a public entry point on crafted/untrusted input? Or already guarded / intended / documented / not attacker-controlled? Give the concrete where_checked (file:line of the guard, or of the unguarded path). Concede only what the code forces.`,
      { schema: VERDICT_SCHEMA, phase:'Verify', label:`verify:${A.name}:${vl}:${c.file}` })))
    .then(vs => {
      const v=vs.filter(Boolean)
      const realVotes=v.filter(x=>x.real&&x.reachable).length
      const disposition=realVotes>=2?'confirmed':realVotes===1?'contested':(v.length?'refuted':'unverified')
      const sev=v.map(x=>x.severity).sort((a,b)=>['INFO','LOW','MEDIUM','HIGH','CRITICAL'].indexOf(b)-['INFO','LOW','MEDIUM','HIGH','CRITICAL'].indexOf(a))[0]||c.severity
      const wc=(v.find(x=>x.where_checked&&x.where_checked.trim())?.where_checked)||''
      // keep every verifier's reasoning — the disposition is triage; the TEXT is what a human reads before trusting it
      const reasons=v.map(x=>`${x.real?'real':'not-real'}/${x.reachable?'reachable':'not-reachable'}: ${x.reason}`)
      return {...c, real_votes:realVotes, disposition, severity:sev, where_checked:wc, verifier_reasons:reasons}
    }))
const out=verified.filter(Boolean)
const pick=d=>out.filter(c=>c.disposition===d).map(c=>({bug_class:c.bug_class,file:c.file,line:c.line,symbol:c.symbol,lenses:c.lenses,votes:c.votes,real_votes:c.real_votes,severity:c.severity,mechanism:c.mechanism,poc_sketch:c.poc_sketch,where_checked:c.where_checked,verifier_reasons:c.verifier_reasons}))
log(`[${A.name}] verify: ${out.filter(c=>c.disposition==='confirmed').length} confirmed, ${out.filter(c=>c.disposition==='contested').length} contested, ${out.filter(c=>c.disposition==='refuted').length} refuted`)
return { name:A.name, n_raw:allF.length, n_candidates:cands.length,
  confirmed:pick('confirmed'), contested:pick('contested'), refuted:pick('refuted'),
  unverified:pick('unverified'), refuted_count:out.filter(c=>c.disposition==='refuted').length,
  all:out.map(c=>({sym:c.symbol,file:c.file,lenses:c.lenses,disp:c.disposition,rv:c.real_votes,sev:c.severity})) }
