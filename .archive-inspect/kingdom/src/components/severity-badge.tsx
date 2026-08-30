import { cn } from "@/lib/utils";

export type Severity = "pass" | "warn" | "fail" | "info";

const styles: Record<Severity, string> = {
  pass: "bg-success/15 text-success ring-success/30",
  warn: "bg-warning/15 text-warning ring-warning/30",
  fail: "bg-critical/15 text-critical ring-critical/30",
  info: "bg-info/15 text-info ring-info/30",
};

const labels: Record<Severity, string> = {
  pass: "Pass",
  warn: "Warn",
  fail: "Fail",
  info: "Info",
};

export function SeverityBadge({
  severity,
  children,
  className,
}: {
  severity: Severity;
  children?: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider ring-1 ring-inset",
        styles[severity],
        className,
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {children ?? labels[severity]}
    </span>
  );
}
