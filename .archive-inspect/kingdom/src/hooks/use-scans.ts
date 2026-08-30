import { useQuery } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useMemo } from "react";

import { useTarget } from "@/components/target-selector";
import { useSession } from "@/hooks/use-session";
import { getLatestScanForHost, getScanById, listRecentScans } from "@/lib/scans.functions";

export function useLatestScan() {
  const { target } = useTarget();
  const { session } = useSession();
  const fn = useServerFn(getLatestScanForHost);

  const host = useMemo(() => {
    try { return new URL(target).host; } catch { return ""; }
  }, [target]);

  return useQuery({
    queryKey: ["latest-scan", host, session?.user.id],
    queryFn: () => fn({ data: { host } }),
    enabled: !!session && !!host,
    staleTime: 30_000,
  });
}

export function useRecentScans() {
  const { session } = useSession();
  const fn = useServerFn(listRecentScans);
  return useQuery({
    queryKey: ["scans", session?.user.id],
    queryFn: () => fn(),
    enabled: !!session,
    staleTime: 30_000,
  });
}

export function useScanById(id: string | undefined) {
  const { session } = useSession();
  const fn = useServerFn(getScanById);
  return useQuery({
    queryKey: ["scan", id, session?.user.id],
    queryFn: () => fn({ data: { id: id! } }),
    enabled: !!session && !!id,
    staleTime: 60_000,
  });
}
