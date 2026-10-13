import {
  Activity,
  Cable,
  Bot,
  Cpu,
  House,
  ListChecks,
  LockKeyhole,
  ScanSearch,
  Settings,
  Shield,
  type LucideIcon,
} from "lucide-react";

export type DashboardPage =
  | "Home"
  | "Antivirus"
  | "AI Agent"
  | "System Status"
  | "Processes"
  | "Network"
  | "Firewall"
  | "Threat Activity"
  | "Scans"
  | "Quarantine"
  | "Settings";

const pages: { label: DashboardPage; icon: LucideIcon }[] = [
  { label: "Home", icon: House },
  { label: "Antivirus", icon: Shield },
  { label: "AI Agent", icon: Bot },
  { label: "System Status", icon: Activity },
  { label: "Processes", icon: Cpu },
  { label: "Network", icon: Cable },
  { label: "Firewall", icon: Shield },
  { label: "Threat Activity", icon: Shield },
  { label: "Scans", icon: ScanSearch },
  { label: "Quarantine", icon: LockKeyhole },
  { label: "Settings", icon: Settings },
];

export function Navigation({
  page,
  onNavigate,
}: {
  page: DashboardPage;
  onNavigate: (page: DashboardPage) => void;
}) {
  return (
    <aside className="sidebar" aria-label="SVS Cyber">
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

      <div className="sidebar-section-label">SVS CYBER</div>
      <nav className="primary-nav" aria-label="Main navigation">
        {pages.map(({ label, icon: Icon }) => (
          <button
            aria-label={label}
            aria-current={page === label ? "page" : undefined}
            className={`nav-item${page === label ? " is-active" : ""}`}
            key={label}
            onClick={() => onNavigate(label)}
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
