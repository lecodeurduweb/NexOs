import {FormEvent, ReactElement, useEffect, useState} from 'react';

type User = {username:string;role:string;failed_attempts:number;locked:boolean};

function api(path: string, init?: RequestInit) {
  const auth = sessionStorage.getItem('nexos_auth') || '';
  return fetch(path, {
    ...init,
    headers: {
      ...(init?.headers || {}),
      ...(auth ? {Authorization: auth} : {}),
      'Cache-Control': 'no-store',
    },
  });
}

export default function App() {
  const [setup, setSetup] = useState<{needs_setup:boolean}|null>(null);
  const [auth, setAuth] = useState(sessionStorage.getItem('nexos_auth') || '');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [setupToken, setSetupToken] = useState('');
  const [setupUser, setSetupUser] = useState('');
  const [setupPassword, setSetupPassword] = useState('');
  const [tab, setTab] = useState('overview');
  const [system, setSystem] = useState<any>(null);
  const [services, setServices] = useState<any[]>([]);
  const [tasks, setTasks] = useState<any[]>([]);
  const [network, setNetwork] = useState<any>(null);
  const [storage, setStorage] = useState<any>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [newUser, setNewUser] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [newUserRole, setNewUserRole] = useState('viewer');
  const [logs, setLogs] = useState('');
  const [agents, setAgents] = useState<any>(null);
  const [aiStatus, setAiStatus] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [memory, setMemory] = useState<any[]>([]);
  const [prompt, setPrompt] = useState('');
  const [answer, setAnswer] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    fetch('/api/v1/setup/status').then(r => r.json()).then(setSetup).catch(() => setError('Cannot reach NexOS API'));
  }, []);

  useEffect(() => {
    if (!auth) return;
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => window.clearInterval(timer);
  }, [auth]);

  async function refresh() {
    try {
      const [s, sv, ta, ne, st, us, lg, ag, ai, hi, me] = await Promise.all([
        api('/api/v1/system'), api('/api/v1/services'), api('/api/v1/tasks'),
        api('/api/v1/network'), api('/api/v1/storage'), api('/api/v1/users'),
        api('/api/logs'), api('/api/v1/ai/agents'), api('/api/v1/ai/status'), api('/api/v1/ai/history'), api('/api/v1/ai/memory'),
      ]);
      if ([s, sv, ta, ne, st, us, lg, ag, ai, hi, me].some(r => r.status === 401)) {
        sessionStorage.removeItem('nexos_auth');
        setAuth('');
        return;
      }
      setSystem(await s.json());
      const svd = await sv.json(); setServices(svd.services || []);
      const tad = await ta.json(); setTasks(tad.tasks || []);
      setNetwork(await ne.json());
      setStorage(await st.json());
      const usd = await us.json(); setUsers(usd.users || []);
      setLogs(await lg.text());
      setAgents(await ag.json());
      setAiStatus(await ai.json());
      const hid = await hi.json(); setHistory(hid.history || []);
      const med = await me.json(); setMemory(med.memory || []);
      setError('');
    } catch (e) {
      setError('Live NexOS API refresh failed');
    }
  }

  async function login(e: FormEvent) {
    e.preventDefault();
    const basic = 'Basic ' + btoa(`${username}:${password}`);
    const r = await api('/api/login', {method:'POST', headers:{Authorization:basic}});
    if (!r.ok) { setError((await r.json()).error || 'Login failed'); return; }
    const data = await r.json();
    sessionStorage.setItem('nexos_auth', 'Bearer ' + data.token);
    setAuth('Bearer ' + data.token);
  }

  async function provision(e: FormEvent) {
    e.preventDefault();
    const r = await fetch('/api/v1/setup', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({token:setupToken, username:setupUser, password:setupPassword}),
    });
    if (!r.ok) { setError((await r.json()).error || 'Setup failed'); return; }
    setSetup({needs_setup:false});
    setError('');
  }

  async function serviceAction(action:string, name:string) {
    await api(`/api/v1/services/${action}?name=${encodeURIComponent(name)}`, {method:'POST'});
    await refresh();
  }

  async function sendPrompt(e:FormEvent) {
    e.preventDefault();
    setAnswer('Analyzing live NexOS state...');
    const r = await api('/api/v1/ai/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({prompt})});
    const data = await r.json();
    setAnswer(r.ok ? `${data.agent}: ${data.observation}` : (data.error || 'AI diagnostic failed'));
  }

  async function createUser(e:FormEvent) {
    e.preventDefault();
    const r = await api(`/api/v1/users?user=${encodeURIComponent(newUser)}&pass=${encodeURIComponent(newUserPassword)}&role=${encodeURIComponent(newUserRole)}`, {method:'POST'});
    if (!r.ok) { setError((await r.json()).error || 'User creation failed'); return; }
    setNewUser(''); setNewUserPassword(''); setError('');
    await refresh();
  }

  async function deleteUser(name:string) {
    const r = await api(`/api/v1/users?user=${encodeURIComponent(name)}`, {method:'DELETE'});
    if (!r.ok) { setError((await r.json()).error || 'User deletion failed'); return; }
    setError('');
    await refresh();
  }

  if (!setup) return <main className="loading">Connecting to NexOS...</main>;

  if (setup.needs_setup) return (
    <main className="auth-shell">
      <form className="auth-card" onSubmit={provision}>
        <div className="brand"><span className="mark">N</span><div><b>NexOS</b><small>Initial provisioning</small></div></div>
        <label>One-time setup token<input value={setupToken} onChange={e=>setSetupToken(e.target.value)} required /></label>
        <label>Admin username<input value={setupUser} onChange={e=>setSetupUser(e.target.value)} required /></label>
        <label>Admin password<input type="password" value={setupPassword} onChange={e=>setSetupPassword(e.target.value)} required minLength={8} /></label>
        {error && <div className="error">{error}</div>}
        <button>Provision NexOS</button>
      </form>
    </main>
  );

  if (!auth) return (
    <main className="auth-shell">
      <form className="auth-card" onSubmit={login}>
        <div className="brand"><span className="mark">N</span><div><b>NexOS</b><small>Administration</small></div></div>
        <label>Username<input value={username} onChange={e=>setUsername(e.target.value)} required /></label>
        <label>Password<input type="password" value={password} onChange={e=>setPassword(e.target.value)} required /></label>
        {error && <div className="error">{error}</div>}
        <button>Sign in</button>
      </form>
    </main>
  );

  const tabs = ['overview','services','processes','network','storage','security','ai','logs'];

  return (
    <main className="app-shell">
      <aside>
        <div className="brand"><span className="mark">N</span><div><b>NexOS</b><small>ARM64 server</small></div></div>
        <nav>{tabs.map(t => <button className={tab===t?'active':''} onClick={()=>setTab(t)} key={t}>{t}</button>)}</nav>
        <button className="signout" onClick={()=>{sessionStorage.removeItem('nexos_auth');setAuth('');}}>Sign out</button>
      </aside>
      <section>
        <header><div><small>Board</small><b>{system?.board || 'NexOS'}</b></div><div className="live"><i /> Live telemetry</div></header>
        {error && <div className="error">{error}</div>}
        {tab==='overview' && <div className="grid">
          <Metric label="RAM free" value={system ? `${system.ram_free_mib} MiB` : '—'} detail={system ? `${system.ram_total_mib} MiB total` : ''}/>
          <Metric label="Tasks" value={system?.tasks_total ?? '—'} detail={`${system?.ctx_switches ?? 0} context switches`}/>
          <Metric label="Services" value={system?.services_total ?? '—'} detail={`${services.filter(s=>s.state==='Running').length} running`}/>
          <Metric label="Temperature" value="N/A" detail="No thermal sensor exposed"/>
          <Metric label="Uptime" value={system ? `${Math.floor(system.uptime_ms/60000)} min` : '—'} detail={`${system?.uptime_ms ?? 0} ms`}/>
          <Metric label="Network" value={network?.ip || 'Unconfigured'} detail={network?.mac || ''}/>
        </div>}
        {tab==='services' && <Table columns={['Service','State','PID','Restarts']} rows={services.map(s=>[s.name,s.state,s.pid ?? '—',s.restarts])} actions={services.map(s=><><button onClick={()=>serviceAction('restart',s.name)}>Restart</button><button onClick={()=>serviceAction('stop',s.name)}>Stop</button></>)}/>}
        {tab==='processes' && <Table columns={['PID','Name','State','EL','CPU','Priority']} rows={tasks.map(t=>[t.id,t.name,t.state,t.el,t.cpu,t.prio])}/>}
        {tab==='network' && <pre>{network ? JSON.stringify(network,null,2):'Loading...'}</pre>}
        {tab==='storage' && <pre>{storage ? JSON.stringify(storage,null,2):'Loading...'}</pre>}
        {tab==='security' && <>
          <h2>Users</h2>
          <Table columns={['Username','Role','Failures','Locked']} rows={users.map(u=>[u.username,u.role,u.failed_attempts,u.locked?'yes':'no'])}/>
          <form className="auth-card" onSubmit={createUser} style={{marginTop:18,width:'100%',maxWidth:520}}>
            <h3>Create user</h3>
            <label>Username<input value={newUser} onChange={e=>setNewUser(e.target.value)} required/></label>
            <label>Password<input type="password" value={newUserPassword} onChange={e=>setNewUserPassword(e.target.value)} required minLength={8}/></label>
            <label>Role<select value={newUserRole} onChange={e=>setNewUserRole(e.target.value)}><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="ai-agent">AI Agent</option><option value="admin">Admin</option></select></label>
            <button>Create</button>
          </form>
        </>}
        {tab==='ai' && <div className="ai-layout">
          <div><h2>AI agents</h2><pre>{agents ? JSON.stringify(agents,null,2):'Loading...'}</pre><h3>Engine</h3><pre>{aiStatus ? JSON.stringify(aiStatus,null,2):'Loading...'}</pre></div>
          <div><h2>Diagnose</h2><form onSubmit={sendPrompt}><textarea value={prompt} onChange={e=>setPrompt(e.target.value)} placeholder="Diagnose network, memory, storage or process problems"/><button>Analyze</button></form><article className="answer">{answer || 'No diagnostic requested.'}</article><h3>Recent interventions</h3><pre>{JSON.stringify(history,null,2)}</pre><h3>Persistent AI memory</h3><pre>{JSON.stringify(memory,null,2)}</pre></div>
        </div>}
        {tab==='logs' && <pre className="logs">{logs || 'No kernel log entries.'}</pre>}
      </section>
    </main>
  );
}

function Metric({label,value,detail}:{label:string,value:string|number,detail:string}) {
  return <article className="metric"><small>{label}</small><b>{value}</b><span>{detail}</span></article>;
}

function Table({columns,rows,actions}: {columns:string[];rows:any[][];actions?:ReactElement[]}) {
  return <div className="table-wrap"><table><thead><tr>{columns.map(c=><th key={c}>{c}</th>)}{actions&&<th>Actions</th>}</tr></thead><tbody>{rows.map((r,i)=><tr key={i}>{r.map((v,j)=><td key={j}>{String(v)}</td>)}{actions&&<td>{actions[i]}</td>}</tr>)}</tbody></table></div>;
}
