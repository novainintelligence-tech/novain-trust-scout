import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { ShieldCheck, UserCog, Eye, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { PageHeader, PageShell } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useMyRoles } from "@/hooks/use-roles";
import { listUsersWithRoles, setUserRole, type AppRole } from "@/lib/roles.functions";

export const Route = createFileRoute("/admin")({
  head: () => ({
    meta: [
      { title: "Admin · Access Control · NSL" },
      { name: "description", content: "Manage admin, editor, and viewer roles across the NSL workspace." },
    ],
  }),
  component: AdminPage,
});

const ROLES: AppRole[] = ["admin", "editor", "viewer"];
const ROLE_META: Record<AppRole, { label: string; icon: typeof ShieldCheck; hint: string }> = {
  admin: { label: "Admin", icon: ShieldCheck, hint: "Full access; manages users, all scans, and settings" },
  editor: { label: "Editor", icon: UserCog, hint: "Runs scans, edits engagement, exports reports" },
  viewer: { label: "Viewer", icon: Eye, hint: "Read-only access to their own scans and reports" },
};

function AdminPage() {
  const { isAdmin, isLoading: rolesLoading } = useMyRoles();
  const fetchUsers = useServerFn(listUsersWithRoles);
  const mutateRole = useServerFn(setUserRole);
  const qc = useQueryClient();

  const users = useQuery({
    queryKey: ["admin-users"],
    queryFn: () => fetchUsers(),
    enabled: isAdmin,
  });

  const toggle = useMutation({
    mutationFn: (v: { userId: string; role: AppRole; grant: boolean }) => mutateRole({ data: v }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-users"] });
      qc.invalidateQueries({ queryKey: ["my-roles"] });
      toast.success("Role updated");
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to update role"),
  });

  if (rolesLoading) {
    return <PageShell><div className="p-8 flex items-center gap-2 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div></PageShell>;
  }
  if (!isAdmin) {
    return (
      <PageShell>
        <PageHeader eyebrow="Access Control" title="Access Control" description="Admin privileges required to view this page." />
        <Card><CardContent className="py-10 text-center text-muted-foreground">You need the <Badge variant="outline">admin</Badge> role to manage users.</CardContent></Card>
      </PageShell>
    );
  }

  return (
    <PageShell>
      <PageHeader
        eyebrow="Administration"
        title="Access Control"
        description="Grant or revoke admin, editor, and viewer roles. Roles are enforced by database policies."
      />

      <div className="grid gap-4 md:grid-cols-3 mb-6">
        {ROLES.map((r) => {
          const meta = ROLE_META[r];
          const Icon = meta.icon;
          return (
            <Card key={r}>
              <CardHeader className="pb-2"><CardTitle className="flex items-center gap-2 text-base"><Icon className="h-4 w-4" /> {meta.label}</CardTitle></CardHeader>
              <CardContent className="text-sm text-muted-foreground">{meta.hint}</CardContent>
            </Card>
          );
        })}
      </div>

      <Card>
        <CardHeader><CardTitle>Workspace users</CardTitle></CardHeader>
        <CardContent>
          {users.isLoading ? (
            <div className="flex items-center gap-2 text-muted-foreground py-6"><Loader2 className="h-4 w-4 animate-spin" /> Loading users…</div>
          ) : users.error ? (
            <div className="text-destructive text-sm">{(users.error as Error).message}</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email</TableHead>
                  <TableHead>Last sign-in</TableHead>
                  <TableHead>Roles</TableHead>
                  <TableHead className="text-right">Grant / Revoke</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(users.data ?? []).map((u) => (
                  <TableRow key={u.id}>
                    <TableCell className="font-mono text-xs">{u.email || u.id}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{u.lastSignInAt ? new Date(u.lastSignInAt).toLocaleString() : "—"}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {u.roles.length === 0 ? <span className="text-xs text-muted-foreground">no roles</span> :
                          u.roles.map((r) => <Badge key={r} variant={r === "admin" ? "default" : "secondary"}>{r}</Badge>)}
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex flex-wrap gap-1 justify-end">
                        {ROLES.map((r) => {
                          const has = u.roles.includes(r);
                          return (
                            <Button
                              key={r}
                              size="sm"
                              variant={has ? "secondary" : "outline"}
                              disabled={toggle.isPending}
                              onClick={() => toggle.mutate({ userId: u.id, role: r, grant: !has })}
                            >
                              {has ? `Revoke ${r}` : `Grant ${r}`}
                            </Button>
                          );
                        })}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </PageShell>
  );
}
