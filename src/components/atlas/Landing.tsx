import {useEffect,useState} from 'react';
import {useNavigate,Link} from '@tanstack/react-router';
import {ArrowUpRight,ArrowRight,GitBranch,ScanLine,LockKeyhole,FileCode2,Fingerprint,Network,ShieldCheck} from 'lucide-react';
import {Button} from '@/components/ui/button';
import {Logo} from '@/components/armorix/Logo';
import {AccountDialog} from '@/components/armorix/AccountDialog';
import {supabase} from '@/integrations/supabase/client';
import structure from '@/assets/traceveil-structure.jpg';

export function Landing(){
 const [open,setOpen]=useState(false);
 const navigate=useNavigate();
 useEffect(()=>{
  let active=true;
  void supabase.auth.getUser().then(({data})=>{if(active&&data.user)void navigate({to:'/console'});});
  const {data}=supabase.auth.onAuthStateChange((event,session)=>{if(event==='SIGNED_IN'&&session?.user)void navigate({to:'/console'});});
  return()=>{active=false;data.subscription.unsubscribe();};
 },[navigate]);
 return <div className="tv-landing">
  <header className="flex h-20 items-center justify-between border-b border-border px-6 md:px-12">
   <Link to="/" className="flex items-center gap-3"><Logo className="size-8"/><span className="text-lg font-semibold">Traceveil</span></Link>
   <div className="flex items-center gap-6"><span className="hidden font-mono text-[10px] uppercase tracking-widest text-muted-foreground sm:block">Application security</span><Button variant="outline" onClick={()=>setOpen(true)}>Sign in<ArrowUpRight className="size-4"/></Button></div>
  </header>
  <main>
   <section className="tv-intro relative isolate overflow-hidden border-b border-border">
    <img src={structure} alt="" aria-hidden width={1600} height={1008} className="tv-structure absolute inset-0 -z-10 size-full object-cover"/>
    <div className="tv-intro-content ax-rise px-6 md:px-12">
     <div className="mb-8 flex items-center gap-3 text-primary"><Fingerprint className="size-5"/><span className="font-mono text-[10px] uppercase tracking-widest">Evidence, not assumptions</span></div>
     <h1 className="tv-wordmark font-semibold">Traceveil<span className="text-primary">.</span></h1>
     <p className="mt-5 max-w-sm text-xl leading-relaxed md:text-2xl">Security, traced back<br/>to the source.</p>
     <p className="mt-4 max-w-xs text-sm leading-relaxed text-muted-foreground">Repository evidence. Agent investigations.<br/>Customer-run isolation checks.</p>
     <Button className="mt-8 h-11 gap-5 px-5" onClick={()=>setOpen(true)}>Open workspace<ArrowRight className="size-4"/></Button>
    </div>
    <div className="absolute bottom-6 left-6 right-6 flex items-center justify-between md:left-12 md:right-12"><span className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground"><GitBranch className="size-3.5"/>Built from real repository evidence</span><span className="hidden font-mono text-[10px] text-muted-foreground sm:block">01 / TRACE</span></div>
   </section>
   <section className="grid border-b border-border md:grid-cols-[1fr_2fr]">
    <div className="border-b border-border px-6 py-9 md:border-b-0 md:border-r md:px-12"><span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">The investigation chain</span><h2 className="mt-5 text-2xl font-medium">Follow the evidence.</h2><div className="mt-6 flex items-center gap-3 text-primary"><GitBranch className="size-5"/><ArrowRight className="size-3 text-muted-foreground"/><Network className="size-5"/><ArrowRight className="size-3 text-muted-foreground"/><ShieldCheck className="size-5"/></div></div>
    <div className="grid sm:grid-cols-3">
     {[{icon:GitBranch,title:'Source',detail:'Commit-bound snapshots',tone:'text-primary'},{icon:ScanLine,title:'Investigate',detail:'Evidence-linked findings',tone:'text-entity-dependency'},{icon:LockKeyhole,title:'Verify',detail:'Read-only tenant checks',tone:'text-warning'}].map((item,i)=><div key={item.title} className="border-b border-border p-7 last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0"><div className="flex items-center justify-between"><item.icon className={`size-7 ${item.tone}`} strokeWidth={1.5}/><span className="font-mono text-[10px] text-muted-foreground">0{i+1}</span></div><h3 className="mt-8 text-sm font-semibold">{item.title}</h3><p className="mt-2 text-xs text-muted-foreground">{item.detail}</p></div>)}
    </div>
   </section>
  </main>
  <footer className="flex flex-wrap items-center justify-between gap-5 px-6 py-6 md:px-12"><span className="flex items-center gap-2 text-xs text-muted-foreground"><FileCode2 className="size-4"/>Traceveil · Evidence-first security</span><Link to="/mcp-audits" className="flex items-center gap-2 text-xs text-muted-foreground hover:text-primary">MCP audits<ArrowUpRight className="size-3.5"/></Link></footer>
  <AccountDialog open={open} onOpenChange={setOpen}/>
 </div>;
}