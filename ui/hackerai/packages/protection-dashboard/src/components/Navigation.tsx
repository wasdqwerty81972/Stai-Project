import {
  Activity,
  Bot,
  Cpu,
  HardDriveDownload,
  Network,
  LayoutDashboard,
  ListChecks,
  LockKeyhole,
  ScanSearch,
  Settings,
  Shield,
  type LucideIcon,
} from "lucide-react";

export type DashboardPage =
  | "Dashboard"
  | "AI Agent"
  | "Processes"
  | "Network Activity"
  | "System Status"
  | "Driver Diagnostics"
  | "Threat Activity"
  | "Scans"
  | "Quarantine"
  | "Settings";

const pages: { label: DashboardPage; icon: LucideIcon }[] = [
  { label: "Dashboard", icon: LayoutDashboard },
  { label: "AI Agent", icon: Bot },
  { label: "Processes", icon: Cpu },
  { label: "Network Activity", icon: Network },
  { label: "System Status", icon: Activity },
  { label: "Driver Diagnostics", icon: HardDriveDownload },
  { label: "Threat Activity", icon: Shield },
  { label: "Scans", icon: ScanSearch },
  { label: "Quarantine", icon: LockKeyhole },
  { label: "Settings", icon: Settings },
];

export function Navigation({
  page,
  onNavigate,
  onOpenAgent,
}: {
  page: DashboardPage;
  onNavigate: (page: DashboardPage) => void;
  onOpenAgent: () => void;
}) {
  return (
    <aside className="sidebar" aria-label="STAI Protection">
      <div className="brand-lockup">
        <div className="brand-mark" aria-hidden="true">
          <Shield size={21} strokeWidth={2.2} />
          <span />
        </div>
        <div className="brand-copy">
          <span className="brand-name">SVS</span>
          <span className="brand-product">CYBER</span>
        </div>
      </div>

      <div className="sidebar-section-label">DEVICE SECURITY</div>
      <nav className="primary-nav" aria-label="Main navigation">
        {pages.map(({ label, icon: Icon }) => (
          <button
            aria-label={label}
            aria-current={page === label ? "page" : undefined}
            className={`nav-item${page === label ? " is-active" : ""}`}
            key={label}
            onClick={() => label === "AI Agent" ? onOpenAgent() : onNavigate(label)}
            title={label}
            type="button"
          >
            <Icon aria-hidden="true" size={19} strokeWidth={1.8} />
            <span className="nav-label">{label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-spacer" />
      <div className="sidebar-footnote">
        <div className="sidebar-footnote-icon">
          <ListChecks size={17} aria-hidden="true" />
        </div>
        <div className="sidebar-footer-copy">
          <strong>Local protection</strong>
          <span>Device data stays here</span>
        </div>
      </div>
      <div className="sidebar-version">SVS CYBER · WINDOWS</div>
    </aside>
  );
}
