import { FileDown } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { downloadScanPdf } from "@/lib/pdf-export";
import type { ScanResult } from "@/lib/scan-types";

interface Props {
  scan: ScanResult | null | undefined;
  size?: "sm" | "default";
  variant?: "default" | "outline";
  label?: string;
}

export function ExportPdfButton({ scan, size = "sm", variant = "outline", label = "Export PDF" }: Props) {
  const onClick = () => {
    if (!scan) return;
    try {
      downloadScanPdf(scan);
      toast.success("PDF exported");
    } catch (e) {
      toast.error("PDF export failed", {
        description: e instanceof Error ? e.message : "Unknown error",
      });
    }
  };
  return (
    <Button size={size} variant={variant} onClick={onClick} disabled={!scan}>
      <FileDown className="h-4 w-4" />
      {label}
    </Button>
  );
}
