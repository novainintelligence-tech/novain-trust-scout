import { Link } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useSession } from "@/hooks/use-session";
import { ScanRunner } from "@/components/scan-runner";
import { useLatestScan } from "@/hooks/use-scans";

export function EmptyScanState({ context }: { context: string }) {
  const { session, loading } = useSession();
  const { data, isLoading } = useLatestScan();

  if (loading || isLoading) {
    return (
      <Card>
        <CardContent className="p-8 text-center text-sm text-muted-foreground">
          Loading…
        </CardContent>
      </Card>
    );
  }

  if (!session) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center gap-3 p-8 text-center">
          <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/15 ring-1 ring-primary/40">
            <ShieldAlert className="h-5 w-5 text-primary" />
          </div>
          <div>
            <p className="text-sm font-medium">Sign in to run real scans</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Your {context} results and history are stored per account.
            </p>
          </div>
          <Button asChild size="sm">
            <Link to="/auth">Sign in or create account</Link>
          </Button>
        </CardContent>
      </Card>
    );
  }

  if (!data) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center gap-3 p-8 text-center">
          <p className="text-sm font-medium">No scan yet for this target</p>
          <p className="text-xs text-muted-foreground">
            Pick a target in the header, then run a scan to populate {context}.
          </p>
          <ScanRunner label="Run first scan" />
        </CardContent>
      </Card>
    );
  }

  return null;
}
