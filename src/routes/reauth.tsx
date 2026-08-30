import { createFileRoute } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { Loader2, ShieldAlert, ShieldCheck, KeyRound, Check, X } from "lucide-react";
import { toast } from "sonner";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RawBlock, formatHeaders, formatJson } from "@/components/raw-block";
import { useSession } from "@/hooks/use-session";
import { EmptyScanState } from "@/components/empty-scan-state";
import { runReauthProbe, type ReauthResult } from "@/lib/reauth.functions";

export const Route = createFileRoute("/reauth")({
  head: () => ({
    meta: [
      { title: "Session Reauthorization Probe · NSL" },
      { name: "description", content: "Verify that session cookies issued at login actually reauthorize on subsequent requests, and that logout invalidates them server-side." },
    ],
  }),
  component: ReauthPage,
});

interface FormState {
  loginUrl: string;
  protectedUrl: string;
  logoutUrl: string;
  usernameField: string;
  passwordField: string;
  username: string;
  password: string;
  loggedInMarker: string;
  loggedOutMarker: string;
}

const DEFAULTS: FormState = {
  loginUrl: "",
  protectedUrl: "",
  logoutUrl: "",
  usernameField: "email",
  passwordField: "password",
  username: "",
  password: "",
  loggedInMarker: "",
  loggedOutMarker: "",
};

function Flag({ on }: { on: boolean }) {
  return on ? <Check className="h-3.5 w-3.5 text-success" /> : <X className="h-3.5 w-3.5 text-critical" />;
}

function ReauthPage() {
  const { session } = useSession();
  const [form, setForm] = useState<FormState>(DEFAULTS);
  const runFn = useServerFn(runReauthProbe);
  const mutation = useMutation({
    mutationFn: (data: FormState) =>
      runFn({
        data: {
          loginUrl: data.loginUrl,
          protectedUrl: data.protectedUrl,
          logoutUrl: data.logoutUrl || undefined,
          usernameField: data.usernameField,
          passwordField: data.passwordField,
          username: data.username,
          password: data.password,
          loggedInMarker: data.loggedInMarker || undefined,
          loggedOutMarker: data.loggedOutMarker || undefined,
        },
      }) as Promise<ReauthResult>,
    onSuccess: () => toast.success("Reauthorization probe complete"),
    onError: (e) => toast.error(e instanceof Error ? e.message : "Probe failed"),
  });

  const onField = (k: keyof FormState) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.loginUrl || !form.protectedUrl || !form.username || !form.password) {
      toast.error("Login URL, protected URL, username and password are required");
      return;
    }
    mutation.mutate(form);
  };

  const result = mutation.data;

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Session Reauthorization"
        title="Reauthorization Probe"
        description="Log in against your own target, capture every Set-Cookie, then replay the jar against a protected URL to confirm the session actually reauthorizes — and that logout invalidates it server-side."
      />

      {!session ? (
        <EmptyScanState context="cookie" />
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <KeyRound className="h-4 w-4 text-primary" />
                Probe configuration
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={submit} className="grid gap-4 md:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="loginUrl">Login form URL (POST target)</Label>
                  <Input id="loginUrl" placeholder="https://app.example.com/login" value={form.loginUrl} onChange={onField("loginUrl")} required />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="protectedUrl">Protected URL (auth-only)</Label>
                  <Input id="protectedUrl" placeholder="https://app.example.com/account" value={form.protectedUrl} onChange={onField("protectedUrl")} required />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="usernameField">Username field name</Label>
                  <Input id="usernameField" value={form.usernameField} onChange={onField("usernameField")} />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="passwordField">Password field name</Label>
                  <Input id="passwordField" value={form.passwordField} onChange={onField("passwordField")} />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="username">Username / email</Label>
                  <Input id="username" autoComplete="off" value={form.username} onChange={onField("username")} required />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="password">Password</Label>
                  <Input id="password" type="password" autoComplete="off" value={form.password} onChange={onField("password")} required />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="loggedInMarker">Logged-in body marker (optional)</Label>
                  <Input id="loggedInMarker" placeholder="Sign out" value={form.loggedInMarker} onChange={onField("loggedInMarker")} />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="loggedOutMarker">Logged-out body marker (optional)</Label>
                  <Input id="loggedOutMarker" placeholder="Please sign in" value={form.loggedOutMarker} onChange={onField("loggedOutMarker")} />
                </div>
                <div className="space-y-1.5 md:col-span-2">
                  <Label htmlFor="logoutUrl">Logout URL (optional — enables server-side invalidation test)</Label>
                  <Input id="logoutUrl" placeholder="https://app.example.com/logout" value={form.logoutUrl} onChange={onField("logoutUrl")} />
                </div>
                <div className="md:col-span-2 flex items-center justify-between rounded-md border border-dashed border-border/60 p-3 text-xs text-muted-foreground">
                  <span>Credentials are used per-run only and never persisted. Only probe targets you own.</span>
                  <Button type="submit" disabled={mutation.isPending}>
                    {mutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Run probe"}
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>

          {result && (
            <>
              <div className="grid gap-3 md:grid-cols-3">
                <SummaryCard
                  label="Reauthorized"
                  ok={result.reauthorized}
                  detail={result.reauthReason}
                  icon={result.reauthorized ? <ShieldCheck className="h-4 w-4 text-success" /> : <ShieldAlert className="h-4 w-4 text-critical" />}
                />
                <SummaryCard
                  label="Session rotated on login"
                  ok={result.sessionRotated === true}
                  neutral={result.sessionRotated === null}
                  detail={result.sessionRotated === null
                    ? "No session-shaped cookie observed both before and after login."
                    : result.sessionRotated
                      ? "Session identifier changed after login — resistant to fixation."
                      : "Same session identifier before and after login — fixation risk."}
                />
                <SummaryCard
                  label="Logout invalidates server-side"
                  ok={result.logoutInvalidatesServerSide === true}
                  neutral={result.logoutInvalidatesServerSide === null}
                  detail={result.logoutReason ?? "Logout URL not provided."}
                />
              </div>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Cookies issued at login</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {result.issuedCookies.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No Set-Cookie headers were returned by the login response.</p>
                  ) : (
                    result.issuedCookies.map((c, i) => (
                      <div key={i} className="rounded-md border border-border/60 p-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-sm font-semibold">{c.name}</span>
                          {result.postLoginSessionCookies.includes(c.name) && (
                            <SeverityBadge severity="info">session-like</SeverityBadge>
                          )}
                          <SeverityBadge severity={c.httpOnly ? "pass" : "fail"}>
                            <Flag on={c.httpOnly} /> HttpOnly
                          </SeverityBadge>
                          <SeverityBadge severity={c.secure ? "pass" : "fail"}>
                            <Flag on={c.secure} /> Secure
                          </SeverityBadge>
                          <SeverityBadge severity={c.sameSite ? "pass" : "warn"}>
                            SameSite: {c.sameSite ?? "—"}
                          </SeverityBadge>
                        </div>
                        <div className="mt-2 grid gap-1 font-mono text-[11px] text-muted-foreground sm:grid-cols-2">
                          <div>domain: {c.domain ?? "—"}</div>
                          <div>path: {c.path ?? "—"}</div>
                          <div>expires: {c.expires ?? "—"}</div>
                          <div>max-age: {c.maxAge ?? "—"}</div>
                          <div className="sm:col-span-2 break-all">value: {c.value || "(empty)"}</div>
                        </div>
                        <RawBlock title="raw set-cookie" className="mt-2" maxHeight={120}>
                          {c.raw}
                        </RawBlock>
                      </div>
                    ))
                  )}
                </CardContent>
              </Card>

              {result.steps.map((s, i) => (
                <Card key={i}>
                  <CardHeader>
                    <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
                      <span className="font-mono text-[10px] text-muted-foreground">Step {i + 1}</span>
                      <span>{s.label}</span>
                      <SeverityBadge severity={s.error ? "fail" : s.status && s.status < 400 ? "pass" : "warn"}>
                        {s.method} · {s.status ?? "ERR"}
                      </SeverityBadge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="font-mono text-[11px] text-muted-foreground break-all">{s.url}</div>
                    {s.error && (
                      <div className="rounded-md border border-critical/40 bg-critical/10 p-2 text-xs text-critical">
                        {s.error}
                      </div>
                    )}
                    <div className="grid gap-3 lg:grid-cols-2">
                      <RawBlock title="request headers">{formatHeaders(s.requestHeaders)}</RawBlock>
                      <RawBlock title="response headers">{formatHeaders(s.responseHeaders)}</RawBlock>
                      <RawBlock title="set-cookie (raw)">{s.setCookies.join("\n")}</RawBlock>
                      <RawBlock title="cookie jar after">{s.cookieJarAfter}</RawBlock>
                    </div>
                    <RawBlock title={`response body (${s.bodyBytes} bytes${s.bodyTruncated ? ", truncated" : ""})`}>
                      {s.bodySnippet}
                    </RawBlock>
                  </CardContent>
                </Card>
              ))}

              <Card>
                <CardHeader><CardTitle className="text-base">Full result (JSON)</CardTitle></CardHeader>
                <CardContent>
                  <RawBlock title="reauth.json" maxHeight={480}>{formatJson(result)}</RawBlock>
                </CardContent>
              </Card>
            </>
          )}
        </>
      )}
    </PageShell>
  );
}

function SummaryCard({
  label, ok, neutral, detail, icon,
}: { label: string; ok: boolean; neutral?: boolean; detail: string; icon?: React.ReactNode }) {
  const severity = neutral ? "info" : ok ? "pass" : "fail";
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-xs font-mono uppercase tracking-widest text-muted-foreground">
          {icon}
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <SeverityBadge severity={severity}>
          {neutral ? "indeterminate" : ok ? "yes" : "no"}
        </SeverityBadge>
        <p className="text-xs text-muted-foreground">{detail}</p>
      </CardContent>
    </Card>
  );
}
