import { Copy } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

interface Props {
  title?: string;
  children: string;
  className?: string;
  maxHeight?: number;
}

/** Renders raw captured text (headers/HTML/JSON) verbatim, monospaced, copyable. */
export function RawBlock({ title, children, className, maxHeight = 320 }: Props) {
  const [copied, setCopied] = useState(false);
  const empty = !children || children.length === 0;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(children);
      setCopied(true);
      toast.success("Copied to clipboard");
      setTimeout(() => setCopied(false), 1500);
    } catch { toast.error("Copy failed"); }
  };

  return (
    <div className={cn("rounded-md border border-border/60 bg-background/70", className)}>
      <div className="flex items-center justify-between border-b border-border/60 px-3 py-1.5">
        <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          {title ?? "raw"}
        </span>
        <Button size="sm" variant="ghost" className="h-6 px-2" onClick={copy} disabled={empty}>
          <Copy className="h-3 w-3" />
          <span className="text-[10px]">{copied ? "copied" : "copy"}</span>
        </Button>
      </div>
      <pre
        className="overflow-auto p-3 font-mono text-[11px] leading-relaxed text-foreground/90"
        style={{ maxHeight }}
      >
        {empty ? <span className="italic text-muted-foreground">— no data captured —</span> : children}
      </pre>
    </div>
  );
}

export function formatHeaders(headers: Record<string, string> | null | undefined): string {
  if (!headers) return "";
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}

export function formatJson(value: unknown): string {
  try { return JSON.stringify(value, null, 2); } catch { return String(value); }
}
