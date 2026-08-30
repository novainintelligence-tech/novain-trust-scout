import { useQuery } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";

import { getMyRoles, type AppRole } from "@/lib/roles.functions";
import { useSession } from "@/hooks/use-session";

export function useMyRoles() {
  const { user } = useSession();
  const fetchRoles = useServerFn(getMyRoles);
  const q = useQuery({
    queryKey: ["my-roles", user?.id ?? "anon"],
    queryFn: () => fetchRoles(),
    enabled: !!user,
    staleTime: 30_000,
  });
  const roles = (q.data ?? []) as AppRole[];
  return {
    ...q,
    roles,
    isAdmin: roles.includes("admin"),
    isEditor: roles.includes("editor") || roles.includes("admin"),
    isViewer: roles.length > 0,
    can: (role: AppRole | AppRole[]) => {
      const need = Array.isArray(role) ? role : [role];
      // admin implies editor and viewer
      const effective = new Set<AppRole>(roles);
      if (effective.has("admin")) { effective.add("editor"); effective.add("viewer"); }
      if (effective.has("editor")) { effective.add("viewer"); }
      return need.some((r) => effective.has(r));
    },
  };
}
