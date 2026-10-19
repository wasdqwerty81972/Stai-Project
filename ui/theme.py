"""
cyber_theme.py — design tokens for the CyberAgent workspace.

Direction: this is a terminal-native security tool, not a generic SaaS
dashboard, so the theme leans into that world directly — monospace-first
type, a single phosphor-green signal color (the "everything is nominal"
color on a real SOC monitor), and risk levels read as a left-edge color
bar rather than a colored word buried in a sentence.

Signature element: the chat input renders as a literal shell prompt
("agent@cyberai:~$") with a blinking-block cursor character, and every
tool/finding row carries a 3px risk-colored left border instead of an
inline tag — so severity is scannable from the gutter, the way a real
log viewer works.
"""

# ---- Color palette -------------------------------------------------
COLORS = {
    # base surfaces (near-black, slightly cool — not pure #000)
    "bg_base":       "#0a0c0e",
    "bg_panel":      "#0f1215",
    "bg_elevated":   "#151a1e",
    "bg_hover":      "#1b2126",
    "bg_input":      "#0d1013",

    # borders / dividers
    "border":        "#22282d",
    "border_subtle": "#181d21",

    # text
    "text_primary":  "#e4e9ec",
    "text_secondary":"#9aa5ab",
    "text_muted":    "#5c666c",
    "text_disabled": "#3a4247",

    # signal accent — phosphor green, the SOC "nominal" color
    "accent":        "#3ddc84",
    "accent_dim":    "#2a9c5c",
    "accent_bg":     "#122018",

    # risk / severity ramp
    "critical":      "#ff5c5c",
    "critical_bg":   "#2a1414",
    "high":          "#ffab4a",
    "high_bg":       "#251c10",
    "medium":        "#f0d868",
    "medium_bg":     "#211f10",
    "low":           "#5ac8fa",
    "low_bg":        "#101c24",
    "info":          "#7c9aff",
}

# ---- Type -----------------------------------------------------------
# Mono carries the tool's identity (findings, agent activity, code,
# status). Sans is reserved for section labels / prose only, kept
# deliberately minimal so the interface doesn't read as two competing
# voices.
FONTS = {
    "mono_display": ("JetBrains Mono", 20, "bold"),
    "mono_heading": ("JetBrains Mono", 13, "bold"),
    "mono_body":    ("JetBrains Mono", 12, "normal"),
    "mono_small":   ("JetBrains Mono", 11, "normal"),
    "sans_label":   ("Inter", 11, "normal"),
    "sans_eyebrow": ("Inter", 10, "bold"),
}

SPACING = {
    "xs": 4, "sm": 8, "md": 12, "lg": 16, "xl": 24,
}

RADIUS = {
    "sm": 4, "md": 6, "lg": 10,
}

RISK_COLOR_MAP = {
    "CRITICAL": ("critical", "critical_bg"),
    "HIGH":     ("high", "high_bg"),
    "MEDIUM":   ("medium", "medium_bg"),
    "LOW":      ("low", "low_bg"),
    "INFO":     ("info", "accent_bg"),
}


def risk_colors(level: str):
    """Return (fg_key, bg_key) for a severity level, defaulting to info."""
    key = (level or "").upper()
    return RISK_COLOR_MAP.get(key, RISK_COLOR_MAP["INFO"])


def qt_stylesheet() -> str:
    """Return the native Qt stylesheet built from this theme's tokens."""
    return f"""
        QWidget {{ color: {COLORS['text_primary']}; background: {COLORS['bg_base']}; font-family: "Segoe UI"; font-size: 13px; }}
        #root {{ background: {COLORS['bg_base']}; }}
        #header {{ background: {COLORS['bg_panel']}; border-bottom: 1px solid {COLORS['border']}; }}
        #title {{ color: {COLORS['text_primary']}; font-size: 22px; font-weight: 650; }}
        #subtitle, #navMeta, #navHint {{ color: {COLORS['text_secondary']}; }}
        #subtitle {{ font-size: 12px; }}
        #notification {{ color: {COLORS['accent']}; font-size: 11px; padding: 4px 10px; }}
        #notification[state="active"] {{ color: {COLORS['low']}; }}
        #notification[state="notice"] {{ color: {COLORS['high']}; }}
        #notification[state="error"] {{ color: {COLORS['critical']}; }}
        #navigation, #context {{ background: {COLORS['bg_panel']}; }}
        #navigation {{ border-right: 1px solid {COLORS['border']}; }}
        #context {{ border-left: 1px solid {COLORS['border']}; }}
        #conversation {{ background: {COLORS['bg_base']}; }}
        #eyebrow {{ color: {COLORS['accent']}; font-size: 10px; font-weight: 700; letter-spacing: 1.2px; }}
        #navCurrent {{ color: {COLORS['text_primary']}; background: {COLORS['bg_hover']}; padding: 10px; border-radius: {RADIUS['sm']}px; }}
        #contextText {{ color: {COLORS['text_secondary']}; font-size: 13px; line-height: 1.35; }}
        #timeline {{ background: {COLORS['bg_base']}; border: 1px solid {COLORS['border']}; border-radius: {RADIUS['sm']}px; color: {COLORS['text_secondary']}; padding: 5px; font-size: 11px; outline: none; }}
        #timeline::item {{ padding: 5px 3px; border-bottom: 1px solid {COLORS['border_subtle']}; }}
        #timeline::item:selected {{ background: {COLORS['bg_hover']}; color: {COLORS['text_primary']}; }}
        #messages {{ background: {COLORS['bg_base']}; border: none; padding: 4px; font-size: 13px; }}
        #thread_agent, #thread_status {{ background: {COLORS['bg_panel']}; border-left: 3px solid {COLORS['accent_dim']}; border-radius: {RADIUS['sm']}px; }}
        #thread_user {{ background: {COLORS['accent_bg']}; border-left: 3px solid {COLORS['accent']}; border-radius: {RADIUS['sm']}px; }}
        #thread_tool {{ background: {COLORS['bg_elevated']}; border-left: 3px solid {COLORS['low']}; border-radius: {RADIUS['sm']}px; }}
        #threadHeading {{ color: {COLORS['text_primary']}; font-size: 14px; font-weight: 650; }}
        #threadStatus, #threadTime, #threadToggle {{ color: {COLORS['accent']}; font-size: 11px; }}
        #threadDetails {{ color: {COLORS['text_secondary']}; font-family: "Segoe UI"; font-size: 13px; line-height: 1.35; }}
        #threadToggle {{ border: none; padding: 0; }}
        #stopButton {{ background: {COLORS['critical_bg']}; color: {COLORS['critical']}; border: 1px solid {COLORS['critical']}; border-radius: {RADIUS['sm']}px; padding: 0 16px; }}
        #stopButton:disabled {{ color: {COLORS['text_disabled']}; border-color: {COLORS['border']}; background: {COLORS['bg_panel']}; }}
        #activity, #agentList {{ background: {COLORS['bg_panel']}; border: 1px solid {COLORS['border']}; border-radius: {RADIUS['sm']}px; color: {COLORS['text_secondary']}; padding: 4px; }}
        #activity::item, #agentList::item {{ padding: 7px 4px; }}
        #activity::item:selected, #agentList::item:selected {{ background: {COLORS['bg_hover']}; }}
        QHeaderView::section {{ background: {COLORS['bg_elevated']}; color: {COLORS['text_muted']}; border: none; padding: 5px; }}
        #prompt {{ background: {COLORS['bg_input']}; border: 1px solid {COLORS['border']}; border-radius: {RADIUS['md']}px; padding: 14px; color: {COLORS['text_primary']}; font-size: 14px; selection-background-color: {COLORS['accent_dim']}; }}
        #prompt:focus {{ border: 1px solid {COLORS['accent']}; }}
        QStatusBar {{ background: {COLORS['bg_panel']}; color: {COLORS['text_muted']}; border-top: 1px solid {COLORS['border']}; }}
    """