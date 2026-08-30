import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import {
  Shield,
  Cookie,
  Bug,
  KeyRound,
  Lock,
  Radar,
  FileCheck2,
  Activity,
  Terminal,
  ArrowRight,
  CheckCircle2,
  Mail,
} from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/landing")({
  head: () => ({
    meta: [
      { title: "NOVAIN Security Lab — Self-hosted web security validation" },
      {
        name: "description",
        content:
          "NSL is a self-hosted penetration testing console for validating the security posture of your own web applications. Scan, validate, and report — end to end.",
      },
      { property: "og:title", content: "NOVAIN Security Lab — Self-hosted web security validation" },
      {
        property: "og:description",
        content:
          "Scan headers, cookies, TLS, auth and session flows. Validate findings with a PoC library. Export executive and technical reports.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
      { name: "twitter:title", content: "NOVAIN Security Lab" },
      {
        name: "twitter:description",
        content: "Self-hosted web security validation for teams that own their targets.",
      },
    ],
  }),
  component: LandingPage,
});

const modules = [
  { icon: Shield, name: "HTTP Security Scanner", tag: "Headers · CSP · HSTS" },
  { icon: Cookie, name: "Cookie Inspector", tag: "Flags · Session cookies" },
  { icon: Bug, name: "XSS Test Suite", tag: "Reflected · Stored probes" },
  { icon: KeyRound, name: "CSRF Validator", tag: "Token reuse · Verb tamper" },
  { icon: Lock, name: "TLS Checker", tag: "Cert · Chain · crt.sh" },
  { icon: Radar, name: "Recon & Discovery", tag: "Restricted link crawler" },
  { icon: FileCheck2, name: "Authentication Audit", tag: "MFA · Reauth probe" },
  { icon: Activity, name: "PoC Validator", tag: "20+ vulnerability classes" },
];

const pocClasses = [
  "SQL Injection",
  "SSRF",
  "Path Traversal",
  "GraphQL Introspection",
  "IDOR Enumeration",
  "NoSQL Injection",
  "Open Redirect",
  "CORS Reflection",
  "Cache-key Injection",
  "HTTP Verb Tampering",
  "JWT alg:none",
  "X-Forwarded-User Trust",
  "X-Original-URL Rewrite",
  "Anonymous Access",
  "Session Fixation",
  "Mixed Content · SRI",
];

function LandingPage() {
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [message, setMessage] = useState("");

  function submitDemo(e: React.FormEvent) {
    e.preventDefault();
    if (!email) {
      toast.error("Enter a work email");
      return;
    }
    toast.success("Demo request queued", {
      description: `We'll reach out to ${email} within one business day.`,
    });
    setEmail("");
    setCompany("");
    setMessage("");
  }

  return (
    <div className="min-h-screen bg-background text-foreground" style={{ fontFamily: '"DM Sans", ui-sans-serif, system-ui, sans-serif' }}>
      <style>{`
        .font-display { font-family: "Space Grotesk", ui-sans-serif, system-ui, sans-serif; letter-spacing: -0.02em; }
        .grid-bg {
          background-image:
            linear-gradient(oklch(0.62 0.19 256 / 0.08) 1px, transparent 1px),
            linear-gradient(90deg, oklch(0.62 0.19 256 / 0.08) 1px, transparent 1px);
          background-size: 48px 48px;
          mask-image: radial-gradient(ellipse at 50% 0%, black 40%, transparent 75%);
        }
      `}</style>

      {/* Nav */}
      <header className="sticky top-0 z-40 border-b border-border/60 bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-7xl items-center gap-6 px-6">
          <Link to="/landing" className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/15 ring-1 ring-primary/40">
              <Shield className="h-4 w-4 text-primary" />
            </div>
            <span className="font-display text-lg font-semibold">NOVAIN Security Lab</span>
          </Link>
          <nav className="ml-auto hidden items-center gap-6 text-sm text-muted-foreground md:flex">
            <a href="#modules" className="hover:text-foreground">Modules</a>
            <a href="#validator" className="hover:text-foreground">Validator</a>
            <a href="#stack" className="hover:text-foreground">Stack</a>
            <a href="#demo" className="hover:text-foreground">Book demo</a>
          </nav>
          <Link
            to="/"
            className="rounded-md border border-border px-3 py-1.5 text-sm text-foreground hover:bg-accent"
          >
            Open console
          </Link>
          <a
            href="#demo"
            className="hidden rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground shadow-[var(--shadow-glow)] hover:opacity-90 md:inline-flex"
          >
            Book a demo
          </a>
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="grid-bg absolute inset-0" />
        <div className="relative mx-auto max-w-7xl px-6 pt-20 pb-16 md:pt-28 md:pb-24">
          <div className="mx-auto max-w-3xl text-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-border bg-card/60 px-3 py-1 font-mono text-xs uppercase tracking-widest text-muted-foreground">
              <span className="h-1.5 w-1.5 rounded-full bg-success" />
              Self-hosted · Authorized targets only
            </div>
            <h1 className="font-display mt-6 text-4xl font-semibold leading-tight md:text-6xl">
              Validate the security posture of your own web apps.
            </h1>
            <p className="mt-5 text-lg text-muted-foreground md:text-xl">
              NSL is a penetration testing console for teams that own their targets — headers,
              cookies, TLS, auth, sessions, and a 20-class PoC library, all wired to executive
              and technical reports.
            </p>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
              <a
                href="#demo"
                className="inline-flex items-center gap-2 rounded-md bg-primary px-5 py-3 font-medium text-primary-foreground shadow-[var(--shadow-glow)] hover:opacity-90"
              >
                Book a demo <ArrowRight className="h-4 w-4" />
              </a>
              <Link
                to="/"
                className="inline-flex items-center gap-2 rounded-md border border-border bg-card/60 px-5 py-3 font-medium text-foreground hover:bg-accent"
              >
                <Terminal className="h-4 w-4" /> Open the console
              </Link>
            </div>
            <div className="mt-10 grid grid-cols-2 gap-4 sm:grid-cols-4">
              {[
                { k: "20+", v: "PoC classes" },
                { k: "9", v: "Modules" },
                { k: "SARIF", v: "+ PDF exports" },
                { k: "Self-host", v: "Docker + Postgres" },
              ].map((s) => (
                <div key={s.v} className="rounded-lg border border-border bg-card/40 p-4 text-left">
                  <div className="font-display text-2xl font-semibold text-primary">{s.k}</div>
                  <div className="mt-1 text-xs uppercase tracking-widest text-muted-foreground">
                    {s.v}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Bento modules */}
      <section id="modules" className="mx-auto max-w-7xl px-6 py-20">
        <div className="mb-10 flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="font-mono text-xs uppercase tracking-widest text-primary">01 · Modules</div>
            <h2 className="font-display mt-2 text-3xl font-semibold md:text-4xl">
              Nine modules, one engagement lifecycle.
            </h2>
          </div>
          <p className="max-w-md text-muted-foreground">
            Scoping, recon, enumeration, validation, and reporting — mapped to a professional
            7-phase methodology.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-4 md:grid-rows-3">
          {/* Feature tile */}
          <div className="relative overflow-hidden rounded-2xl border border-border bg-gradient-to-br from-primary/20 via-card to-card p-6 md:col-span-2 md:row-span-2">
            <div className="grid-bg absolute inset-0 opacity-40" />
            <div className="relative">
              <div className="inline-flex h-10 w-10 items-center justify-center rounded-md bg-primary/20 ring-1 ring-primary/40">
                <Activity className="h-5 w-5 text-primary" />
              </div>
              <h3 className="font-display mt-4 text-2xl font-semibold">PoC Validation Library</h3>
              <p className="mt-2 text-muted-foreground">
                Turn theoretical findings into verified vulnerabilities. Each PoC captures the
                exact request, response evidence, verdict, and a copyable curl command.
              </p>
              <div className="mt-5 flex flex-wrap gap-2">
                {pocClasses.slice(0, 10).map((c) => (
                  <span
                    key={c}
                    className="rounded-md border border-border bg-background/60 px-2 py-1 font-mono text-[11px] text-muted-foreground"
                  >
                    {c}
                  </span>
                ))}
                <span className="rounded-md bg-primary/15 px-2 py-1 font-mono text-[11px] text-primary">
                  +{pocClasses.length - 10} more
                </span>
              </div>
            </div>
          </div>

          {modules.map((m) => (
            <div
              key={m.name}
              className="group rounded-2xl border border-border bg-card/60 p-5 transition hover:border-primary/40 hover:bg-card"
            >
              <div className="inline-flex h-9 w-9 items-center justify-center rounded-md bg-primary/10 ring-1 ring-primary/30">
                <m.icon className="h-4 w-4 text-primary" />
              </div>
              <div className="font-display mt-4 font-semibold">{m.name}</div>
              <div className="mt-1 font-mono text-xs uppercase tracking-widest text-muted-foreground">
                {m.tag}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Validator */}
      <section id="validator" className="border-y border-border bg-card/30">
        <div className="mx-auto grid max-w-7xl gap-10 px-6 py-20 md:grid-cols-2">
          <div>
            <div className="font-mono text-xs uppercase tracking-widest text-primary">02 · Validator</div>
            <h2 className="font-display mt-2 text-3xl font-semibold md:text-4xl">
              Evidence over assumption.
            </h2>
            <p className="mt-4 text-muted-foreground">
              Every PoC records the raw request and response, timestamp, verdict, and CVSS 3.1
              vector. Export to PDF, JSON, or SARIF 2.1.0 for pipeline ingestion. Diff any two
              scans to track drift over time.
            </p>
            <ul className="mt-6 space-y-3">
              {[
                "Authorized active PoCs gated by Rules of Engagement",
                "Restricted-link discovery via crawl + wordlist",
                "Fan-out execution across every discovered endpoint",
                "Executive summary + technical report variants",
              ].map((f) => (
                <li key={f} className="flex items-start gap-3">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" />
                  <span className="text-sm text-foreground">{f}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="rounded-2xl border border-border bg-background p-1 shadow-[var(--shadow-panel)]">
            <div className="flex items-center gap-2 border-b border-border px-4 py-2">
              <div className="flex gap-1.5">
                <span className="h-2.5 w-2.5 rounded-full bg-critical/70" />
                <span className="h-2.5 w-2.5 rounded-full bg-warning/70" />
                <span className="h-2.5 w-2.5 rounded-full bg-success/70" />
              </div>
              <span className="ml-2 font-mono text-xs text-muted-foreground">nsl · validator</span>
            </div>
            <pre className="overflow-x-auto p-5 font-mono text-xs leading-relaxed text-foreground">
{`$ nsl validate https://target.example/login
[+] Discovery         12 restricted paths
[+] Auth Bypass       3 classes · 0 confirmed
[+] Open Redirect     1 confirmed  → ?next=nsl-poc.invalid
[+] Missing headers   6 confirmed  (HSTS, CSP, XFO ...)
[+] IDOR sweep        200 ids · 0 divergences
[+] SQLi (boolean)    0 confirmed
[+] SSRF              0 confirmed
[+] JWT alg:none      0 confirmed

Report: report-2026-07-19.pdf · sarif · json
CVSS avg 6.4 · 7 confirmed / 21 tested`}
            </pre>
          </div>
        </div>
      </section>

      {/* Stack */}
      <section id="stack" className="mx-auto max-w-7xl px-6 py-20">
        <div className="mb-10">
          <div className="font-mono text-xs uppercase tracking-widest text-primary">03 · Stack</div>
          <h2 className="font-display mt-2 text-3xl font-semibold md:text-4xl">
            Runs on infrastructure you already trust.
          </h2>
        </div>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {[
            "React + Vite",
            "Tailwind CSS",
            "Node.js + Express",
            "PostgreSQL",
            "Redis",
            "Nginx",
            "Docker",
            "SARIF 2.1.0",
          ].map((t) => (
            <div
              key={t}
              className="rounded-lg border border-border bg-card/60 px-4 py-5 text-center font-mono text-sm text-foreground"
            >
              {t}
            </div>
          ))}
        </div>
      </section>

      {/* Demo CTA */}
      <section id="demo" className="border-t border-border bg-gradient-to-b from-card/30 to-background">
        <div className="mx-auto grid max-w-6xl gap-10 px-6 py-20 md:grid-cols-2 md:items-center">
          <div>
            <div className="font-mono text-xs uppercase tracking-widest text-primary">04 · Book a demo</div>
            <h2 className="font-display mt-2 text-3xl font-semibold md:text-4xl">
              See NSL against your own staging environment.
            </h2>
            <p className="mt-4 text-muted-foreground">
              30-minute walkthrough. Bring a target you're authorized to test — we'll run a full
              engagement, validate every finding, and export the report live.
            </p>
            <div className="mt-6 flex items-center gap-3 text-sm text-muted-foreground">
              <Mail className="h-4 w-4 text-primary" />
              <span>demo@novain.security</span>
            </div>
          </div>

          <form
            onSubmit={submitDemo}
            className="rounded-2xl border border-border bg-card/80 p-6 shadow-[var(--shadow-panel)]"
          >
            <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Work email
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              className="mb-4 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground outline-none focus:border-primary"
            />
            <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Company
            </label>
            <input
              value={company}
              onChange={(e) => setCompany(e.target.value)}
              placeholder="Acme Security"
              className="mb-4 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground outline-none focus:border-primary"
            />
            <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-muted-foreground">
              What do you want to test?
            </label>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              rows={3}
              placeholder="Staging URL, scope, timeline…"
              className="mb-4 w-full resize-none rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground outline-none focus:border-primary"
            />
            <button
              type="submit"
              className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-primary px-4 py-2.5 font-medium text-primary-foreground shadow-[var(--shadow-glow)] hover:opacity-90"
            >
              Request demo <ArrowRight className="h-4 w-4" />
            </button>
            <p className="mt-3 text-center text-xs text-muted-foreground">
              Rules of Engagement required before any active testing.
            </p>
          </form>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6 py-8 text-sm text-muted-foreground">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <span className="font-display font-semibold text-foreground">NOVAIN Security Lab</span>
            <span>· © {new Date().getFullYear()}</span>
          </div>
          <div className="flex items-center gap-5">
            <Link to="/" className="hover:text-foreground">Console</Link>
            <a href="#modules" className="hover:text-foreground">Modules</a>
            <a href="#demo" className="hover:text-foreground">Contact</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
