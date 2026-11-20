/* Agents: Settings -> Agents (connect a coding assistant) and the security level of a node.  ADR-140, ADR-141, ADR-142, ADR-143.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.

   Two jobs, both without a secret anywhere:
     - The Agents section.  The shell reads the assistants' config files (admin.agentDetect), shows the exact configuration to copy
       (admin.agentSnippet), and - only from the Write button of the change dialog - writes the one `credmgr` entry (admin.agentApply),
       after showing the diff (admin.agentPlan) and keeping a copy of the file.  Claude Code's own state file is never written: its row
       offers the one-line command.  The page never touches the clipboard itself (admin.copyPlainText -> the shell).
     - The node's security level (open / guarded / strict, stored and sent as `sealed`: ADR-152 renamed it for people, because "sealed" also names sealing a node into Orphaned): one broker call, node.policy, through write.setNodePolicy, and a re-read.
       Lowering it widens what an agent may do, so the broker asks for presence (Touch ID); the router shows that if it is refused.
     - Agent tokens (ADR-164).  The list (agent.token_status: metadata only), Revoke (agent.token_revoke), and the Issue dialog
       (agent.token_issue: the shell asks for Touch ID).  The broker answers the new token ONCE, and the page never sees it: like the
       login (ADR-057), the shell takes it off the answer and puts it on the concealed clipboard, cleared after 30 seconds and at lock.
       The dialog says it was copied.  If the clipboard could not take it, the shell revokes it and the dialog says so. */

import { admin, write } from "../../vault/index";

const LEVELS = [
  {id:'open', label:'Open', rank:0, caption:'Agents read and write as their access allows, without asking you.'},
  {id:'guarded', label:'Guarded', rank:1, caption:'Agents read low and medium values freely; a high or critical value waits for your one-tap approval.'},
  {id:'sealed', label:'Strict', rank:2, caption:'Every value waits for your approval. What an agent adds waits in the tray, and it cannot change or remove anything.'},
];
const levelOf = (n) => (n && LEVELS.some((l)=>l.id===n.securityLevel)) ? n.securityLevel : 'guarded';
const CHIPS = {
  connected:{label:'connected',state:'ok'},
  ready:{label:'not connected',state:'warn'},
  other_entry:{label:'different entry',state:'warn'},
  unreadable:{label:'unreadable',state:'danger'},
  not_found:{label:'not found',state:''},
};
const NOTES = {
  connected:'Connected. Restart the assistant after a change.',
  ready:'Found on this Mac, not connected yet.',
  other_entry:'The file already has a credmgr entry that CredMgr did not write. It will not replace it: compare it with the copy.',
  not_found:'Not found on this Mac. You can still copy the configuration.',
};
const errText = (e) => String((e && e.message) || 'The change could not be made.').slice(0, 300);

// ADR-164: what an agent token may carry, and how long it may live (the broker holds the same bounds).
export const TOKEN_CAPS = [
  {id:'list', label:'list names'},
  {id:'read', label:'read metadata'},
  {id:'reveal', label:'reveal values'},
  {id:'create', label:'add entries'},
  {id:'update', label:'change entries'},
];
export const TOKEN_EXPIRIES = [
  {secs:3600, label:'1 hour'},
  {secs:28800, label:'8 hours'},
  {secs:86400, label:'1 day'},
  {secs:604800, label:'7 days'},
];
const TOKEN_DEFAULT_CAPS = {list:true, read:true, reveal:false, create:false, update:false};
/** A time in UTC, to the minute, as the CLI prints it. */
export function utcMinute(secs){
  if(typeof secs!=='number'||!Number.isFinite(secs))return '';
  return new Date(secs*1000).toISOString().slice(0,16).replace('T',' ')+' UTC';
}
/** "in 3 h", "in 2 days", "in 12 min", or "expired". */
export function expiresIn(secs, now){
  const left=secs-now;
  if(left<=0)return 'expired';
  if(left<3600)return 'in '+Math.max(1,Math.round(left/60))+' min';
  if(left<2*86400)return 'in '+Math.round(left/3600)+' h';
  return 'in '+Math.round(left/86400)+' days';
}
const nowSecs = () => Math.floor(Date.now()/1000);

export const agentsMethods = {
  /** Read which assistants are on this Mac.  Called when the Agents section opens; reads files, writes none. */
  loadAgents(){
    this.setState({agentsLoading:true});
    this.loadAgentTokens();
    this.pollSettingRequests(); // the requests from agents listed at the top of this section (ADR-155)
    this.clearRequestNotice();
    admin.agentDetect().then(
      (d)=>this.setState({agents:d,agentsLoading:false,agentsNoShell:!d}),
      (e)=>{ this.setState({agentsLoading:false,agentsNoShell:false}); this.notify('error',errText(e)); },
    );
  },
  /** Copy text through the shell and say so on the button for a moment. */
  agentCopied(key, ok){
    clearTimeout(this._agentCopyT);
    this.setState({agentCopied:{key,ok}});
    this._agentCopyT=setTimeout(()=>this.setState({agentCopied:null}),ok?1500:6000);
    if(!ok)this.notify('error','Could not copy. Nothing was changed.');
  },
  async agentCopy(client){
    try{
      const r=await admin.agentSnippet(client);
      if(!r)throw new Error('no shell');
      await admin.copyPlainText(client==='claude-code'&&r.command?r.command:r.snippet);
      this.agentCopied(client,true);
    }catch(e){ this.agentCopied(client,false); }
  },
  /** The prompt (or the text of CREDMGR.md) for the selected node: its name, the nodes it reaches, its level - never a value. */
  async agentCopyText(format){
    const v=this.vault, s=this.state;
    const sel=s.selected&&s.selected!=='__orphan'?this.node(s.selected):null;
    const start=sel||v.nodes.find((n)=>n.id==='global')||v.nodes[0];
    if(!start){ this.agentCopied(format,false); return; }
    const reach=[]; const seen=new Set();
    for(let n=start; n&&!seen.has(n.id); n=n.parentId?v.nodes.find((x)=>x.id===n.parentId):null){ seen.add(n.id); reach.push(n.id); }
    try{
      const r=await admin.agentPrompt(start.id,reach,levelOf(start),format);
      if(!r)throw new Error('no shell');
      await admin.copyPlainText(r.text);
      this.agentCopied(format,true);
    }catch(e){ this.agentCopied(format,false); }
  },
  /** Draw the change.  Writes nothing. */
  async openAgentPlan(client, action){
    try{
      const plan=await admin.agentPlan(client,action);
      if(!plan)throw new Error('This needs the CredMgr app.');
      this.setState({agentDlg:{client,action,plan,busy:false},dialog:'agent'});
      this.focusLater('[data-agent-cancel]');
    }catch(e){ this.notify('error',errText(e)); }
  },
  /** The Write button.  The shell writes only if the file is still what the diff showed. */
  async agentConfirm(){
    const d=this.state.agentDlg; if(!d||d.busy)return;
    this.setState({agentDlg:{...d,busy:true}});
    try{
      const r=await admin.agentApply(d.client,d.action,d.plan.token);
      this.setState({agentDlg:null,dialog:null});
      if(r&&r.written){
        const backup=r.backup?' A copy of the original is beside it.':'';
        this.notify('success',(d.action==='connect'?d.plan.label+' is connected.':d.plan.label+' is disconnected.')+' Restart it to pick the change up.'+backup);
      }
      this.loadAgents();
    }catch(e){
      this.setState({agentDlg:null,dialog:null});
      this.notify('error',errText(e));
      this.loadAgents();
    }
  },
  agentCancel(){ this.setState({agentDlg:null,dialog:null}); },

  // ── agent tokens (ADR-164) ──
  /** Read the live tokens.  Metadata only; a refusal is said in words on the section, never as an empty list. */
  loadAgentTokens(){
    this.setState({atLoading:true, atError:null});
    return admin.agentTokens().then(
      (r)=>this.setState({atList:r, atLoading:false}),
      (e)=>{
        const code=e&&e.code;
        const text=code==='capability_not_held'?'Only your own login can see agent tokens.'
          :(code==='vault_locked'||code==='session_expired')?'Unlock the vault to see agent tokens.'
          :'The agent tokens could not be read.';
        this.setState({atList:null, atLoading:false, atError:text});
      },
    );
  },
  /** Open the Issue dialog for the selected node (or the first project). */
  openAgentTokenDlg(){
    const s=this.state, v=this.vault;
    const nodes=(v&&v.nodes||[]).filter((n)=>n.kind!=='orphan');
    const sel=s.selected&&s.selected!=='__orphan'?nodes.find((n)=>n.id===s.selected):null;
    // ADR-164 review P2-7: the broker issues no token for Global, so the dialog never starts there.
    const projects=nodes.filter((n)=>n.id!=='global');
    const first=(sel&&sel.id!=='global'?sel:null)||projects[0];
    this.setState({dialog:'agentToken', atForm:{node:first?first.id:'', label:'', caps:{...TOKEN_DEFAULT_CAPS}, expires:86400, busy:false, err:null}, atIssued:null});
    this.focusLater('[data-at-label]');
  },
  /** Close the dialog.  The form and the issued summary leave the page's state here. */
  closeAgentTokenDlg(){
    this.setState({dialog:null, atForm:null, atIssued:null});
  },
  /** The dialog's state must not outlive it: any close (Done, Cancel, Escape, a lock) leaves no form and no summary behind. */
  scheduleAgentTokenWipe(){
    const st=this.state;
    if(this._atWipeQueued||st.dialog==='agentToken'||!(st.atForm||st.atIssued))return;
    this._atWipeQueued=true;
    queueMicrotask(()=>{ this._atWipeQueued=false; if(this.state.dialog!=='agentToken'&&(this.state.atForm||this.state.atIssued))this.setState({atForm:null,atIssued:null}); });
  },
  setAgentTokenForm(patch){
    this.setState((st)=>({atForm:{...(st.atForm||{}), err:null, ...patch}}));
  },
  /** The Issue button: one agent.token_issue.  The shell asks for Touch ID; the broker decides everything. */
  async issueAgentToken(){
    const f=this.state.atForm; if(!f||f.busy)return;
    const label=String(f.label||'').trim();
    const caps=TOKEN_CAPS.filter((c)=>f.caps&&f.caps[c.id]).map((c)=>c.id);
    if(!f.node){ this.setAgentTokenForm({err:'Choose the node the token is for.'}); return; }
    if(!label){ this.setAgentTokenForm({err:'Name the agent that will hold the token.'}); return; }
    if(label.length>64){ this.setAgentTokenForm({err:'The name is at most 64 characters.'}); return; }
    if(!caps.length){ this.setAgentTokenForm({err:'Tick at least one thing the agent may do.'}); return; }
    this.setState({atForm:{...f, busy:true, err:null}});
    try{
      const r=await admin.issueAgentToken(f.node,label,caps,f.expires);
      // The shell kept the token: the answer says only whether it reached the clipboard.
      this.setState({atForm:{...f, busy:false}, atIssued:{id:r.id, label:r.label, node:r.node, capabilities:r.capabilities||[], expiresAt:r.expiresAt,
        copied:r.copied===true, clearAfter:r.clearAfterSeconds||30, revoked:r.revoked===true, revokePending:r.revokePending===true}});
      this.focusLater('[data-at-done]');
      this.loadAgentTokens();
    }catch(e){
      const code=e&&e.code;
      if(code==='malformed_request'){
        this.setState({atForm:{...f, busy:false, err:'The broker refused this token. Check that the node gives agents what you ticked (its agent access), and that fewer than 32 tokens are live.'}});
        return;
      }
      this.setState({atForm:{...f, busy:false}});
      this.routeError(e,{op:'agent.token_issue', node:f.node});
    }
  },
  /** Revoke: one agent.token_revoke, then the list again.  No Touch ID: revoking only takes access away. */
  async revokeAgentToken(id){
    if(this._atRevoking)return;
    this._atRevoking=id; this.setState({atRevoking:id});
    try{
      const r=await admin.revokeAgentToken(id);
      this.notify('success','Revoked “'+(r&&r.label||id)+'”. The next request with it is refused.');
    }catch(e){
      if(e&&e.code==='not_found')this.notify('info','That token had already ended.');
      else this.routeError(e,{op:'agent.token_revoke'});
    }finally{
      this._atRevoking=null; this.setState({atRevoking:null});
      this.loadAgentTokens();
    }
  },

  /** Set the selected node's security level.  One broker call and a re-read; a refusal (presence) goes through the router. */
  async setNodeLevel(id, level){
    if(this._lvlBusy)return;
    this._lvlBusy=true; this.setState({lvlBusy:true});
    try{
      const r=await write.setNodePolicy(this.model,id,'Security level set from the node panel',{securityLevel:level});
      if(this.state.tfUntil){ clearInterval(this._tfI); this.setState({tfUntil:0}); } // node.policy ends every elevation at the broker
      const text='Security level is now '+(LEVELS.find((l)=>l.id===level)||{label:level}).label.toLowerCase()+'.';
      if(r.readbackError)this.savedButNotRefreshed(r.readbackError,text); else this.notify('success',text);
    }catch(e){ this.routeError(e,{op:'node.policy',node:id}); }
    finally{ this._lvlBusy=false; this.setState({lvlBusy:false}); }
  },

  rvAgents(c){
    const {s, sel} = c;
    this.scheduleAgentTokenWipe();
    const a=s.agents, d=s.agentDlg, cp=s.agentCopied;
    const label=(key,idle)=>cp&&cp.key===key?(cp.ok?'copied ✓':'copy failed'):idle;
    const rows=((a&&a.clients)||[]).map((r)=>{
      const chip=CHIPS[r.state]||CHIPS.not_found;
      const note=r.state==='unreadable'?(r.detail||'The file could not be read.'):(r.writable?NOTES[r.state]||'':'Claude Code keeps its settings in a file it rewrites itself, so CredMgr does not edit it. Copy the command and run it in a terminal.');
      return {
        id:r.client, label:r.label, path:r.path, chipLabel:chip.label, chipState:chip.state, chipStyle:chip.state==='danger'?'color:var(--danger-fg)':'', note,
        copyLabel:label(r.client,r.writable?'Copy configuration':'Copy command'),
        copyAria:(r.writable?'copy the configuration for ':'copy the command for ')+r.label,
        copy:()=>this.agentCopy(r.client),
        canConnect:r.writable&&r.state==='ready',
        canDisconnect:r.writable&&r.state==='connected',
        connect:()=>this.openAgentPlan(r.client,'connect'),
        disconnect:()=>this.openAgentPlan(r.client,'disconnect'),
      };
    });
    // the dialog
    const plan=d&&d.plan;
    const diffRows=plan?plan.diff.map((l)=>({
      mark:l.kind==='+'?'+':l.kind==='-'?'-':' ', text:l.text===''?' ':l.text,
      bg:l.kind==='+'?'var(--steel-3)':'transparent',
      fg:l.kind==='-'?'var(--danger-fg)':l.kind==='+'?'var(--bone)':'var(--ash)',
    })):[];
    // agent tokens (ADR-164)
    const at=s.atList, af=s.atForm, ai=s.atIssued, now=nowSecs();
    const atRows=((at&&at.tokens)||[]).map((t)=>{
      const narrowed=(t.effectiveCapabilities||[]).length<(t.capabilities||[]).length;
      return {
        id:t.id, label:t.label, node:t.node,
        caps:(t.effectiveCapabilities||[]).join(', ')||'nothing now',
        narrowed, narrowedText:narrowed?'the node now gives agents less than this token was issued with':'',
        expires:'expires '+expiresIn(t.expiresAt,now)+' · '+utcMinute(t.expiresAt),
        used:t.lastUsedAt?'last used '+utcMinute(t.lastUsedAt):'never used',
        revoke:()=>this.revokeAgentToken(t.id),
        revokeAria:'revoke the agent token '+t.label,
        revokeLabel:s.atRevoking===t.id?'Revoking…':'Revoke',
        revokeDisabled:!!s.atRevoking,
      };
    });
    const atNodes=((this.vault&&this.vault.nodes)||[]).filter((n)=>n.kind!=='orphan'&&n.id!=='global').map((n)=>({id:n.id, label:n.label||n.id}));
    // the node's security level, in the inspector
    const lvl=levelOf(sel);
    const lvlBusy=!!s.lvlBusy;
    return {
      setAgents:s.setSection==='agents',
      agentsLoading:!!s.agentsLoading,
      agentsNoShell:!!s.agentsNoShell,
      agentsNoBinary:!!(a&&a.binaryFound===false),
      agentRows:rows,
      agentCopyGeneric:()=>this.agentCopy('generic'),
      agentGenericLabel:label('generic','Copy JSON'),
      agentCopyPrompt:()=>this.agentCopyText('prompt'),
      agentPromptLabel:label('prompt','Copy prompt'),
      agentCopyMd:()=>this.agentCopyText('md'),
      agentMdLabel:label('md','Copy CREDMGR.md'),
      dlgAgent:s.dialog==='agent'&&!!plan,
      agentCancel:()=>this.agentCancel(),
      agentConfirm:()=>this.agentConfirm(),
      agentBusy:!!(d&&d.busy),
      agentDlgTitle:plan?(plan.action==='connect'?'connect ':'disconnect ')+plan.label:'',
      agentDlgPath:plan?plan.path:'',
      agentDlgNothing:!!plan&&plan.unchanged,
      agentDlgNothingText:plan&&plan.action==='connect'?'Nothing to change: credmgr is already in this file.':'Nothing to change: credmgr is not in this file.',
      agentDlgHasDiff:!!plan&&!plan.unchanged,
      agentDiffRows:diffRows,
      agentDlgBackup:!!plan&&!plan.unchanged&&!!plan.backupName,
      agentDlgBackupName:plan&&plan.backupName?plan.backupName.replace('<time>','the time'):'',
      agentDlgCanWrite:!!plan&&!plan.unchanged,
      agentDlgWriteLabel:d&&d.busy?'Writing…':'Write this change',
      atLoading:!!s.atLoading,
      atErrShow:!!s.atError,
      atErr:s.atError||'',
      atEmpty:!!at&&!s.atLoading&&atRows.length===0,
      atRows,
      atCount:at?atRows.length+' of '+at.max+' live':'',
      openAgentToken:()=>this.openAgentTokenDlg(),
      dlgAgentToken:s.dialog==='agentToken'&&!!af,
      atFormShow:!!af&&!ai,
      atNodes,
      onAtNode:(ev)=>this.setAgentTokenForm({node:ev.target.value}),
      atLabel:af?af.label:'',
      onAtLabel:(ev)=>this.setAgentTokenForm({label:ev.target.value}),
      atCaps:TOKEN_CAPS.map((c)=>({id:c.id, label:c.label, on:!!(af&&af.caps&&af.caps[c.id]), toggle:()=>this.setAgentTokenForm({caps:{...((af&&af.caps)||{}), [c.id]:!(af&&af.caps&&af.caps[c.id])}})})),
      atExpiries:TOKEN_EXPIRIES.map((x)=>({secs:String(x.secs), label:x.label})),
      atNodeVal:af?af.node:'',
      atExpiresVal:af?String(af.expires):'86400',
      onAtExpires:(ev)=>this.setAgentTokenForm({expires:Number(ev.target.value)}),
      atFormErrShow:!!(af&&af.err),
      atFormErr:af&&af.err||'',
      atIssueLabel:af&&af.busy?'Waiting for Touch ID…':'Issue token',
      atIssueDisabled:!!(af&&af.busy),
      issueAgentToken:()=>this.issueAgentToken(),
      closeAgentToken:()=>this.closeAgentTokenDlg(),
      atIssuedShow:!!ai,
      atIssuedWhat:ai?'“'+ai.label+'” on node '+ai.node+': '+(ai.capabilities||[]).join(', ')+'. Expires '+utcMinute(ai.expiresAt)+'.':'',
      atCopiedShow:!!(ai&&ai.copied),
      atCopiedText:ai&&ai.copied?'The token is on the clipboard now, and only there: CredMgr does not show it and keeps only a fingerprint. Paste it into the agent\'s settings as CREDMGR_AGENT_TOKEN within '+ai.clearAfter+' seconds; the clipboard clears itself then, and at lock. If you miss it, revoke this token and issue another.':'',
      atNotCopiedShow:!!(ai&&!ai.copied),
      atNotCopiedText:ai&&!ai.copied?(ai.revoked?'The clipboard could not take the token, so nobody holds it and it has been revoked. Issue another.':ai.revokePending?'The vault locked before the token reached the clipboard, so nobody holds it. CredMgr will revoke “'+ai.label+'” as soon as you unlock; check the list then, and issue another.':'The clipboard could not take the token, and revoking it failed. Revoke “'+ai.label+'” from the list now, then issue another.'):'',
      lvlShow:!!sel,
      lvlOpts:LEVELS.map((l)=>({
        label:l.label, on:lvl===l.id?'true':'false', bg:lvl===l.id?'var(--bone)':'transparent', fg:lvl===l.id?'var(--night)':'var(--bone)',
        title:l.id===lvl?'the current level':(l.rank<LEVELS.find((x)=>x.id===lvl).rank?'lowering it widens what agents may do: it needs Touch ID':l.caption),
        disabled:lvlBusy,
        set:()=>{ if(sel&&l.id!==lvl)this.setNodeLevel(sel.id,l.id); },
      })),
      lvlCaption:LEVELS.find((l)=>l.id===lvl).caption,
    };
  },
};
