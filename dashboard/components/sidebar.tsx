"use client";

import {
  ScanSearch,
  FlaskConical,
  ShieldCheck,
  Gauge,
  Activity,
  ClipboardList,
  ExternalLink,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
  { href: "/", icon: ScanSearch, label: "Scan" },
  { href: "/tests", icon: FlaskConical, label: "Tests" },
  { href: "/policies", icon: ShieldCheck, label: "Policies" },
  { href: "/trust-score", icon: Gauge, label: "Trust Score" },
  { href: "/monitor", icon: Activity, label: "Monitor" },
  { href: "/reports", icon: ClipboardList, label: "Reports" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-[260px] flex-col border-r border-border bg-[#0F0F0F]">
      {/* Logo */}
      <div className="flex items-center gap-3 px-6 py-6 border-b border-border">
        <div className="relative flex items-center justify-center w-9 h-9 rounded-lg overflow-hidden">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/guardian-logo.png" alt="MCP Guardian" width="36" height="36" className="rounded-lg" />
          <div className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-guardian-green animate-pulse" />
        </div>
        <div>
          <h1 className="text-sm font-bold tracking-wider text-foreground">
            MCP GUARDIAN
          </h1>
          <p className="text-[10px] tracking-widest text-muted-foreground uppercase">
            Security Auditor
          </p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-all duration-200 ${
                isActive
                  ? "bg-primary/10 text-primary border border-primary/20"
                  : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
              }`}
            >
              <item.icon
                className={`w-4 h-4 transition-colors ${
                  isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                }`}
              />
              <span className="tracking-wide">{item.label}</span>
              {isActive && (
                <div className="ml-auto w-1.5 h-1.5 rounded-full bg-primary animate-pulse-ring" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-4 py-4 border-t border-border">
        <a
          href="http://localhost:3000"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 text-xs text-muted-foreground hover:text-primary transition-colors"
        >
          <ExternalLink className="w-3.5 h-3.5" />
          <span className="tracking-wide">Open Archestra</span>
        </a>
        <p className="mt-2 text-[10px] text-muted-foreground/50 tracking-wider">
          v1.0.0
        </p>
      </div>
    </aside>
  );
}
