import React from "react";
import { Shimmer } from "@/components/ai-elements/shimmer";

interface ToolBlockProps {
  icon: React.ReactNode;
  action: string;
  target?: string;
  isShimmer?: boolean;
  isClickable?: boolean;
  onClick?: () => void;
  onKeyDown?: (e: React.KeyboardEvent) => void;
  accessibleLabel?: string;
  renderAs?: "button" | "div";
}

const ToolBlock: React.FC<ToolBlockProps> = ({
  icon,
  action,
  target,
  isShimmer = false,
  isClickable = false,
  onClick,
  onKeyDown,
  accessibleLabel,
  renderAs = "button",
}) => {
  const baseClasses =
    "rounded-[15px] px-[10px] py-[6px] border border-border bg-muted/20 inline-flex max-w-full gap-[4px] items-center relative h-[36px] overflow-hidden";
  const clickableClasses = isClickable
    ? "cursor-pointer hover:bg-muted/40 transition-colors"
    : "";
  const blockContent = (
    <>
      <div className="w-[21px] inline-flex items-center flex-shrink-0 text-foreground [&>svg]:h-4 [&>svg]:w-4">
        {icon}
      </div>
      <div className="max-w-[100%] truncate text-muted-foreground relative top-[-1px]">
        <span className="text-[13px]">
          {isShimmer ? <Shimmer>{action}</Shimmer> : action}
        </span>
        {target && (
          <span className="text-[12px] font-mono ml-[6px] text-muted-foreground/70">
            {target}
          </span>
        )}
      </div>
    </>
  );
  const blockProps = {
    className: `${baseClasses} ${clickableClasses}`,
    onClick: isClickable ? onClick : undefined,
    onKeyDown: isClickable ? onKeyDown : undefined,
    tabIndex: isClickable ? 0 : undefined,
    role: isClickable ? "button" : undefined,
    "aria-label":
      accessibleLabel ??
      (isClickable && target ? `Open ${target} in sidebar` : undefined),
  };

  return (
    <div className="flex-1 min-w-0">
      {renderAs === "button" ? (
        <button type="button" {...blockProps}>
          {blockContent}
        </button>
      ) : (
        <div {...blockProps}>{blockContent}</div>
      )}
    </div>
  );
};

export default ToolBlock;
