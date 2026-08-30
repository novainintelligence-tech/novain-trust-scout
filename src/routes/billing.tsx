import { createFileRoute } from "@tanstack/react-router";
import { Check, CreditCard, ShieldCheck, Sparkles } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

export const Route = createFileRoute("/billing")({ component: BillingPage });

const plans = [
  { code: "starter", name: "Starter", price: "$19", description: "For a focused security baseline.", features: ["10 website scans", "Full scoring report", "Evidence export"] },
  { code: "growth", name: "Growth", price: "$79", description: "For teams tracking risk continuously.", features: ["50 website scans", "Scan history", "CI verification API"], featured: true },
  { code: "scale", name: "Scale", price: "$199", description: "For security programs at speed.", features: ["200 website scans", "Priority processing", "Team-ready reporting"] },
];

function BillingPage() {
  const [loadingPlan, setLoadingPlan] = useState<string | null>(null);

  async function startCheckout(planCode: string) {
    setLoadingPlan(planCode);
    try {
      const apiBase = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
      const apiKey = import.meta.env.VITE_NOVAIN_API_KEY;
      if (!apiKey) throw new Error("VITE_NOVAIN_API_KEY is not configured for the NOVAIN API.");
      const response = await fetch(`${apiBase}/api/public/v1/billing/checkout`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({ plan_code: planCode }),
      });
      const payload = await response.json();
      if (!response.ok || !payload.checkout_url) throw new Error(payload?.error?.message || "Unable to start checkout.");
      window.location.assign(payload.checkout_url);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to start checkout.");
    } finally {
      setLoadingPlan(null);
    }
  }

  return (
    <div className="mx-auto w-full max-w-6xl px-6 py-12 lg:px-10">
      <div className="mx-auto max-w-2xl text-center">
        <div className="mx-auto mb-5 flex h-12 w-12 items-center justify-center rounded-xl border border-primary/30 bg-primary/10 text-primary"><CreditCard className="h-5 w-5" /></div>
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-primary">NOVAIN access</p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight text-foreground">Buy the clarity to fix risk.</h1>
        <p className="mt-4 text-base leading-7 text-muted-foreground">Every plan turns live security evidence into a score your team can act on. Checkout is secured by Stripe and scan credits are applied only after a verified webhook.</p>
      </div>
      <div className="mt-12 grid gap-5 lg:grid-cols-3">
        {plans.map((plan) => (
          <article key={plan.code} className={`relative flex flex-col rounded-2xl border p-6 ${plan.featured ? "border-primary bg-primary/[0.06] shadow-lg shadow-primary/10" : "border-border bg-card"}`}>
            {plan.featured && <div className="absolute -top-3 left-6 inline-flex items-center gap-1 rounded-full bg-primary px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-primary-foreground"><Sparkles className="h-3 w-3" /> Most used</div>}
            <h2 className="text-lg font-semibold text-foreground">{plan.name}</h2>
            <p className="mt-2 min-h-12 text-sm leading-6 text-muted-foreground">{plan.description}</p>
            <p className="mt-6 text-4xl font-semibold tracking-tight text-foreground">{plan.price}<span className="text-sm font-normal text-muted-foreground"> / month</span></p>
            <div className="my-6 h-px bg-border" />
            <ul className="space-y-3 text-sm text-muted-foreground">{plan.features.map((feature) => <li key={feature} className="flex items-center gap-2"><Check className="h-4 w-4 text-primary" />{feature}</li>)}</ul>
            <button type="button" onClick={() => startCheckout(plan.code)} disabled={loadingPlan !== null} className={`mt-8 inline-flex h-11 items-center justify-center gap-2 rounded-lg px-4 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${plan.featured ? "bg-primary text-primary-foreground hover:bg-primary/90" : "border border-border bg-background text-foreground hover:bg-muted"}`}>
              {loadingPlan === plan.code ? "Opening secure checkout…" : <>Choose {plan.name}<ShieldCheck className="h-4 w-4" /></>}
            </button>
          </article>
        ))}
      </div>
      <p className="mt-8 text-center font-mono text-[11px] uppercase tracking-wider text-muted-foreground">Secure payment processing · No card data touches NOVAIN</p>
    </div>
  );
}
