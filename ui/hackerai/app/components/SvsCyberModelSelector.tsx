"use client";

/**
 * SvsCyberModelSelector — SVS-Cyber model selector.
 *
 * Ported from HackerAI ModelSelector.tsx UI patterns:
 * - Same compact pill / dropdown trigger
 * - Same dropdown menu pattern (Radix DropdownMenu)
 * - Same selected state highlighting
 * - Same transitions and hover effects
 *
 * Only changed: HackerAI models → SVS-Cyber models.
 * Changing the model does NOT create a new chat.
 */

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ChevronDown, Cpu, Construction } from "lucide-react";
import { cn } from "@/lib/utils";
import type { SelectedModel } from "@/app/contexts/StaiGlobalState";
import { SVS_MODELS } from "@/app/contexts/StaiGlobalState";

interface SvsCyberModelSelectorProps {
  value: SelectedModel;
  onChange: (model: SelectedModel) => void;
  disabled?: boolean;
}

function modelIcon(_id: SelectedModel) {
  return <Cpu className="size-3 shrink-0" />;
}

export function SvsCyberModelSelector({
  value,
  onChange,
  disabled = false,
}: SvsCyberModelSelectorProps) {
  const current = SVS_MODELS.find((m) => m.id === value) ?? SVS_MODELS[0]!;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild disabled={disabled}>
        {/* Trigger pill — matches HackerAI model selector compact button */}
        <button
          type="button"
          className={cn(
            "flex h-7 items-center gap-1.5 rounded-full px-2.5 text-xs font-medium",
            "bg-transparent text-muted-foreground",
            "border border-transparent",
            "transition-colors duration-150",
            "hover:bg-accent hover:text-accent-foreground hover:border-border/50",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
            "disabled:pointer-events-none disabled:opacity-50",
            "data-[state=open]:bg-accent data-[state=open]:text-accent-foreground",
          )}
          aria-label={`Model: ${current.label}. Click to change.`}
          data-testid="model-selector"
        >
          {modelIcon(current.id)}
          <span className="max-w-[7rem] truncate">{current.label}</span>
          {!current.available && (
            <Construction className="size-3 shrink-0 text-amber-500" aria-label="Under development" />
          )}
          <ChevronDown className="size-3 shrink-0 opacity-60" />
        </button>
      </DropdownMenuTrigger>

      <DropdownMenuContent
        align="start"
        sideOffset={6}
        className="w-64 p-1"
        data-testid="model-selector-menu"
      >
        <DropdownMenuLabel className="px-2 py-1 text-xs font-medium text-muted-foreground">
          SVS-Cyber Models
        </DropdownMenuLabel>
        <DropdownMenuSeparator />

        {SVS_MODELS.filter((model) => model.id === "auto").map((model) => (
          <DropdownMenuItem
            key={model.id}
            disabled={!model.available}
            onSelect={() => onChange(model.id)}
            className={cn(
              "flex flex-col items-start gap-0.5 rounded-md px-2 py-2 text-sm",
              "cursor-pointer focus:bg-accent focus:text-accent-foreground",
              value === model.id && "bg-accent/60 text-foreground",
              !model.available && "opacity-50 cursor-not-allowed",
            )}
            data-testid={`model-option-${model.id}`}
          >
            <div className="flex w-full items-center gap-2">
              {modelIcon(model.id)}
              <span className="font-medium">{model.label}</span>
              {model.badge && (
                <span className="ml-auto rounded-sm bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400">
                  {model.badge}
                </span>
              )}
              {value === model.id && (
                <span className="ml-auto text-[10px] text-muted-foreground">
                  selected
                </span>
              )}
            </div>
            <span className="pl-5 text-xs text-muted-foreground">
              {model.description}
            </span>
          </DropdownMenuItem>
        ))}

        <DropdownMenuSeparator />
        <div className="px-2 py-1.5 text-[10px] text-muted-foreground/70">
          Changing the model keeps your current investigation open.
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
