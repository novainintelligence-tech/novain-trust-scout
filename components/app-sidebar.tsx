import { Link, useRouterState, useNavigate } from "@tanstack/react-router";
import {
  LayoutDashboard,
  Cookie,
  Bug,
  ShieldAlert,
  KeyRound,
  ServerCog,
  LockKeyhole,
  ScrollText,
  ShieldCheck,
  LogIn,
  LogOut,
  Radar,
  Workflow,
  FileText,
  Crosshair,
  Users,
} from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { useMyRoles } from "@/hooks/use-roles";

import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarFooter,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import { useSession } from "@/hooks/use-session";
import { supabase } from "@/integrations/supabase/client";

const overview = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard },
  { title: "Workflow", url: "/methodology", icon: Workflow },
  { title: "Engagement Report", url: "/report", icon: FileText },
  { title: "PoC Validator", url: "/validator", icon: Crosshair },
];

const modules = [
  { title: "Cookie Inspector", url: "/cookies", icon: Cookie },
  { title: "Live Session", url: "/live-session", icon: KeyRound },
  { title: "Reauth Probe", url: "/reauth", icon: LogIn },
  { title: "XSS Test Suite", url: "/xss", icon: Bug },
  { title: "CSRF Validator", url: "/csrf", icon: ShieldAlert },
  { title: "Session Security", url: "/sessions", icon: KeyRound },
  { title: "HTTP Headers", url: "/headers", icon: ServerCog },
  { title: "TLS Checker", url: "/tls", icon: LockKeyhole },
  { title: "Reconnaissance", url: "/recon", icon: Radar },
  { title: "Scan History", url: "/audit", icon: ScrollText },
];

export function AppSidebar() {
  const currentPath = useRouterState({ select: (r) => r.location.pathname });
  const isActive = (path: string) =>
    path === "/" ? currentPath === "/" : currentPath.startsWith(path);
  const { session, user } = useSession();
  const { isAdmin, roles } = useMyRoles();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const signOut = async () => {
    await queryClient.cancelQueries();
    queryClient.clear();
    await supabase.auth.signOut();
    toast.success("Signed out");
    navigate({ to: "/auth", replace: true });
  };

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <div className="flex items-center gap-2 px-2 py-1">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/15 ring-1 ring-primary/40">
            <ShieldCheck className="h-4 w-4 text-primary" />
          </div>
          <div className="flex min-w-0 flex-col leading-tight group-data-[collapsible=icon]:hidden">
            <span className="truncate text-sm font-semibold">NOVAIN</span>
            <span className="truncate font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              Security Lab
            </span>
          </div>
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Overview</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {overview.map((item) => (
                <SidebarMenuItem key={item.url}>
                  <SidebarMenuButton asChild isActive={isActive(item.url)} tooltip={item.title}>
                    <Link to={item.url}>
                      <item.icon />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel>Modules</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {modules.map((item) => (
                <SidebarMenuItem key={item.url}>
                  <SidebarMenuButton asChild isActive={isActive(item.url)} tooltip={item.title}>
                    <Link to={item.url}>
                      <item.icon />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {isAdmin && (
          <SidebarGroup>
            <SidebarGroupLabel>Administration</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton asChild isActive={isActive("/admin")} tooltip="Access Control">
                    <Link to="/admin">
                      <Users />
                      <span>Access Control</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        )}
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          {session ? (
            <>
              <SidebarMenuItem>
                <div className="px-2 py-1 text-xs text-muted-foreground group-data-[collapsible=icon]:hidden">
                  <div className="truncate font-mono">{user?.email}</div>
                  {roles.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {roles.map((r) => (
                        <span
                          key={r}
                          className="rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-primary"
                        >
                          {r}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton onClick={signOut} tooltip="Sign out">
                  <LogOut />
                  <span>Sign out</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </>
          ) : (
            <SidebarMenuItem>
              <SidebarMenuButton asChild isActive={isActive("/auth")} tooltip="Sign in">
                <Link to="/auth">
                  <LogIn />
                  <span>Sign in</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          )}
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  );
}
