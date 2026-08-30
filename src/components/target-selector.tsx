import { useEffect, useState } from "react";
import { Crosshair, Check } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";

const STORAGE_KEY = "nsl:target";
const DEFAULTS = ["https://example.com", "https://github.com", "https://developer.mozilla.org"];

export function useTarget() {
  const [target, setTarget] = useState<string>(DEFAULTS[0]);
  useEffect(() => {
    if (typeof window === "undefined") return;
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored) setTarget(stored);
  }, []);
  const update = (next: string) => {
    setTarget(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // ignore
    }
  };
  return { target, setTarget: update };
}

export function TargetSelector() {
  const { target, setTarget } = useTarget();
  const [draft, setDraft] = useState(target);

  useEffect(() => setDraft(target), [target]);

  const apply = () => {
    try {
      const url = new URL(draft);
      setTarget(url.toString());
      toast.success("Target updated", { description: url.host });
    } catch {
      toast.error("Invalid URL", { description: "Include the protocol, e.g. https://" });
    }
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="gap-2 font-mono">
          <Crosshair className="h-3.5 w-3.5 text-primary" />
          <span className="max-w-[220px] truncate text-xs">{new URL(target).host}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-80">
        <DropdownMenuLabel className="text-xs uppercase tracking-widest text-muted-foreground">
          Scan target
        </DropdownMenuLabel>
        <div className="flex gap-2 px-2 py-2">
          <Input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="https://example.com"
            className="h-8 font-mono text-xs"
            onKeyDown={(e) => e.key === "Enter" && apply()}
          />
          <Button size="sm" className="h-8" onClick={apply}>
            Set
          </Button>
        </div>
        <DropdownMenuSeparator />
        <DropdownMenuLabel className="text-xs uppercase tracking-widest text-muted-foreground">
          Recent
        </DropdownMenuLabel>
        {DEFAULTS.map((d) => (
          <DropdownMenuItem key={d} onSelect={() => setTarget(d)} className="font-mono text-xs">
            {d === target && <Check className="mr-1 h-3.5 w-3.5 text-primary" />}
            {d}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
