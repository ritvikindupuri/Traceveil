export function Logo({ className = "h-6 w-6" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <rect width="32" height="32" rx="8" className="fill-secondary" />
      <path d="M8 9l8 14 8-14" fill="none" className="stroke-primary" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="16" cy="9" r="2" className="fill-primary" />
    </svg>
  );
}
