import logo from '@/assets/armorix-logo.png';

export function Logo({ className = "h-7 w-7" }: { className?: string }) {
  return <img src={logo} alt="" aria-hidden width={1024} height={1024} loading="lazy" className={className} />;
}
