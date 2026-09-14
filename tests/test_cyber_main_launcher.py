"""Regression tests for the SVS-Cyber launcher defaults."""

import unittest

import cyber_main


class CyberMainLauncherTests(unittest.TestCase):
    def test_backend_port_defaults_to_6764(self) -> None:
        args = cyber_main.build_parser().parse_args([])

        self.assertEqual(args.port, 6764)
