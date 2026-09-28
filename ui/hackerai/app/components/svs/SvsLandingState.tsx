"use client";

import {
  ArrowUpRight,
  FileSearch,
  LockKeyhole,
  ScanSearch,
  Shield,
  ShieldCheck,
} from "lucide-react";

interface SvsLandingStateProps {
  onSuggestion: (prompt: string) => void;
}

const suggestions = [
  {
    title: "Review an authentication flow",
    detail: "Look for weak session handling and access checks",
    prompt:
      "Review an authentication flow for weak session handling and access control. What should I test first?",
    icon: LockKeyhole,
  },
  {
    title: "Plan a web security review",
    detail: "Turn a target description into a focused checklist",
    prompt:
      "Help me plan a defensive web security review. What information should I gather and what checks should I prioritize?",
    icon: ScanSearch,
  },
  {
    title: "Analyze a security finding",
    detail: "Assess impact and gather reproducible evidence",
    prompt:
      "Help me analyze a security finding, assess its impact, and organize reproducible evidence for a report.",
    icon: FileSearch,
  },
] as const;

export function SvsLandingState({ onSuggestion }: SvsLandingStateProps) {
  return (
    <section
      className="mx-auto flex w-full max-w-[920px] flex-col px-4 pb-8 pt-4 sm:px-6 sm:pt-8"
      aria-labelledby="svs-landing-title"
    >
      <div className="relative isolate overflow-hidden rounded-[28px] border border-cyan-500/20 bg-gradient-to-br from-cyan-500/[0.09] via-card/90 to-card px-6 py-7 shadow-[0_28px_80px_-54px_rgba(6,182,212,0.55)] sm:px-9 sm:py-9 dark:from-cyan-400/[0.10]">
        <div
          className="pointer-events-none absolute -right-24 -top-28 size-72 rounded-full bg-cyan-400/10 blur-3xl"
          aria-hidden="true"
        />
        <div
          className="pointer-events-none absolute inset-y-0 right-0 hidden w-2/5 bg-[linear-gradient(to_right,transparent,rgba(34,211,238,0.035))] sm:block"
          aria-hidden="true"
        />

        <div className="relative z-10 max-w-[620px]">
          <div className="mb-6 flex items-center gap-3">
            <span className="flex size-11 shrink-0 items-center justify-center rounded-2xl border border-cyan-500/25 bg-cyan-500/10 text-cyan-700 shadow-[inset_0_1px_0_rgba(255,255,255,0.12)] dark:text-cyan-300">
              <ShieldCheck
                className="size-5"
                strokeWidth={1.7}
                aria-hidden="true"
              />
            </span>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-cyan-700 dark:text-cyan-300">
                SVS-Cyber
              </p>
              <p className="mt-0.5 text-xs text-muted-foreground">
                Defensive security workspace
              </p>
            </div>
          </div>

          <h2
            id="svs-landing-title"
            className="max-w-[610px] text-balance text-[2rem] leading-[1.12] font-semibold tracking-[-0.045em] text-foreground sm:text-[2.75rem]"
          >
            Start a security investigation
          </h2>
          <p className="mt-4 max-w-[530px] text-pretty text-sm leading-6 text-muted-foreground sm:text-[15px]">
            Bring a question or a finding. Work through the next defensive check
            with a clear record of the conversation and agent activity.
          </p>

          <div className="mt-7 flex flex-wrap gap-x-5 gap-y-2 border-t border-cyan-500/15 pt-4 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-2">
              <span
                className="size-1.5 rounded-full bg-cyan-500"
                aria-hidden="true"
              />
              Define the scope
            </span>
            <span className="inline-flex items-center gap-2">
              <span
                className="size-1.5 rounded-full bg-cyan-500"
                aria-hidden="true"
              />
              Review the evidence
            </span>
            <span className="inline-flex items-center gap-2">
              <span
                className="size-1.5 rounded-full bg-cyan-500"
                aria-hidden="true"
              />
              Decide the next step
            </span>
          </div>
        </div>

        <div
          className="pointer-events-none absolute bottom-8 right-9 hidden size-40 items-center justify-center rounded-[2rem] border border-cyan-500/10 bg-background/20 text-cyan-500/15 shadow-[inset_0_0_0_1px_rgba(34,211,238,0.025)] lg:flex"
          aria-hidden="true"
        >
          <div className="absolute inset-4 rounded-[1.5rem] border border-cyan-500/10" />
          <Shield className="size-16" strokeWidth={0.9} />
        </div>
      </div>

      <div className="mt-7 flex w-full items-end justify-between gap-3 px-1">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-700 dark:text-cyan-300">
            A place to begin
          </p>
          <h3 className="mt-1 text-sm font-medium text-foreground">
            Choose a starting point
          </h3>
        </div>
        <p className="hidden text-xs text-muted-foreground sm:block">
          Or type your own question below
        </p>
      </div>

      <div className="mt-3 grid w-full gap-2.5 text-left sm:grid-cols-3">
        {suggestions.map(({ title, detail, prompt, icon: Icon }, index) => (
          <button
            key={title}
            type="button"
            onClick={() => onSuggestion(prompt)}
            className="group flex min-h-32 flex-col rounded-2xl border border-border bg-card/70 p-4 text-left transition-[background-color,border-color,transform,box-shadow] duration-200 hover:-translate-y-0.5 hover:border-cyan-500/40 hover:bg-card hover:shadow-[0_14px_32px_-24px_rgba(6,182,212,0.55)] focus-visible:outline-2 focus-visible:outline-cyan-500 motion-reduce:transform-none motion-reduce:transition-none"
          >
            <span className="mb-4 flex w-full items-start justify-between">
              <span className="flex size-8 items-center justify-center rounded-lg border border-cyan-500/15 bg-cyan-500/5 text-cyan-700 dark:text-cyan-300">
                <Icon className="size-4" strokeWidth={1.8} aria-hidden="true" />
              </span>
              <span className="text-[10px] font-mono text-muted-foreground/70">
                0{index + 1}
              </span>
            </span>
            <span className="flex w-full items-center justify-between gap-2 text-sm font-medium text-foreground">
              {title}
              <ArrowUpRight
                className="size-3.5 shrink-0 text-muted-foreground transition-colors group-hover:text-cyan-600 group-focus-visible:text-cyan-600 dark:group-hover:text-cyan-300 dark:group-focus-visible:text-cyan-300 motion-reduce:transition-none"
                aria-hidden="true"
              />
            </span>
            <span className="mt-1 text-xs leading-5 text-muted-foreground">
              {detail}
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}
