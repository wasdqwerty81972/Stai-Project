"""Regression tests for the SVS-Cyber launcher defaults."""

import unittest

import cyber_main


class CyberMainLauncherTests(unittest.TestCase):
    def test_agent_startup_allows_cold_next_page_compilation(self) -> None:
        self.assertGreaterEqual(cyber_main.AGENT_SERVER_STARTUP_TIMEOUT_SECONDS, 300)

    def test_backend_port_defaults_to_6764(self) -> None:
        args = cyber_main.build_parser().parse_args([])

        self.assertEqual(args.port, 6764)

    def test_agent_ui_port_defaults_to_3000(self) -> None:
        args = cyber_main.build_parser().parse_args([])

        self.assertEqual(args.agent_port, 3000)

    def test_windows_defaults_to_native_dashboard_and_browser_flag_overrides(self) -> None:
        default_args = cyber_main.build_parser().parse_args([])
        browser_args = cyber_main.build_parser().parse_args(["--browser"])

        self.assertTrue(cyber_main.should_launch_desktop(default_args, "nt"))
        self.assertFalse(cyber_main.should_launch_desktop(browser_args, "nt"))
        self.assertFalse(cyber_main.should_launch_desktop(default_args, "posix"))

    def test_desktop_flag_selects_native_dashboard(self) -> None:
        args = cyber_main.build_parser().parse_args(["--desktop"])

        self.assertTrue(cyber_main.should_launch_desktop(args, "posix"))
