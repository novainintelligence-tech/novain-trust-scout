import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { Loader2, Play } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { useTarget } from "@/components/target-selector";
import { runScan } from "@/lib/scanner.functions";
import { useSession } from "@/hooks/use-session";

interface ScanRunnerProps {
  variant?: "default" | "outline";
  size?: "sm" | "default";
  label?: string;
}

export function ScanRunner({ variant = "default", size = "sm", label = "Run scan" }: ScanRunnerProps) {
  const { target } = useTarget();
  const queryClient = useQueryClient();
  const runScanFn = useServerFn(runScan);
  const { session } = useSession();

  const mutation = useMutation({
    mutationFn: () => runScanFn({ data: { url: target } }),
    onSuccess: (scan) => {
      toast.success("Scan complete", {
        description: `${scan.targetHost} · score ${scan.overallScore}/100`,
      });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      queryClient.invalidateQueries({ queryKey: ["latest-scan"] });
    },
    onError: (err) => {
      toast.error("Scan failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    },
  });

  if (!session) {
    return (
      <Button variant="outline" size={size} disabled>
        Sign in to scan
      </Button>
    );
  }

  return (
    <Button variant={variant} size={size} onClick={() => mutation.mutate()} disabled={mutation.isPending}>
      {mutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
      {label}
    </Button>
  );
}
