import argparse
import socket
import unittest
from types import SimpleNamespace
from unittest import mock

import stealth_scan


class PortParsingTests(unittest.TestCase):
    def test_accepts_unique_ports_within_limit(self):
        self.assertEqual(stealth_scan.parse_ports("22, 443"), [22, 443])

    def test_rejects_malformed_empty_out_of_range_and_duplicate_ports(self):
        for value in ("", "22,,443", "https", "0", "65536", "22,22"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    stealth_scan.parse_ports(value)

    def test_rejects_more_than_maximum_ports(self):
        ports = ",".join(str(port) for port in range(1, stealth_scan.MAX_PORTS + 2))
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "no more than"):
            stealth_scan.parse_ports(ports)


class ScopeTests(unittest.TestCase):
    def test_accepts_target_inside_declared_ipv4_and_ipv6_scopes(self):
        self.assertEqual(
            stealth_scan.validate_scope("192.0.2.10", "192.0.2.0/24"),
            "192.0.2.10",
        )
        self.assertEqual(
            stealth_scan.validate_scope("2001:db8::10", "2001:db8::/64"),
            "2001:db8::10",
        )

    def test_rejects_hostname_invalid_scope_and_target_outside_scope(self):
        for target, scope in (
            ("example.invalid", "192.0.2.0/24"),
            ("192.0.2.10", "not-a-network"),
            ("192.0.3.10", "192.0.2.0/24"),
            ("2001:db8::1", "192.0.2.0/24"),
        ):
            with self.subTest(target=target, scope=scope):
                with self.assertRaises(ValueError):
                    stealth_scan.validate_scope(target, scope)


class ProbeTests(unittest.TestCase):
    @mock.patch("stealth_scan.socket.socket")
    def test_connect_and_banner_read_are_bounded(self, socket_factory):
        fake_socket = mock.Mock()
        fake_socket.connect_ex.return_value = 0
        fake_socket.recv.return_value = b"fixture banner"
        socket_factory.return_value = fake_socket

        result = stealth_scan.probe("127.0.0.1", 80, 1.2)

        self.assertEqual(result, (80, "fixture banner"))
        socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        fake_socket.connect_ex.assert_called_once_with(("127.0.0.1", 80))
        fake_socket.recv.assert_called_once_with(stealth_scan.MAX_BANNER_BYTES)
        self.assertEqual(
            [call.args[0] for call in fake_socket.settimeout.call_args_list],
            [1.2, 0.6],
        )
        fake_socket.close.assert_called_once()

    @mock.patch("stealth_scan.socket.socket")
    def test_returns_none_for_closed_port_and_closes_socket(self, socket_factory):
        fake_socket = mock.Mock()
        fake_socket.connect_ex.return_value = 111
        socket_factory.return_value = fake_socket

        self.assertIsNone(stealth_scan.probe("127.0.0.1", 80, 0.5))
        fake_socket.recv.assert_not_called()
        fake_socket.close.assert_called_once()

    @mock.patch("stealth_scan.socket.socket")
    def test_ipv6_uses_ipv6_socket_address(self, socket_factory):
        fake_socket = mock.Mock()
        fake_socket.connect_ex.return_value = 111
        socket_factory.return_value = fake_socket

        stealth_scan.probe("2001:db8::1", 443, 0.5)

        socket_factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        fake_socket.connect_ex.assert_called_once_with(("2001:db8::1", 443, 0, 0))


class ArgumentBoundTests(unittest.TestCase):
    def test_worker_and_timeout_caps_are_enforced(self):
        self.assertEqual(stealth_scan.parse_workers("32"), 32)
        self.assertEqual(stealth_scan.parse_timeout("3"), 3)
        for parser, value in (
            (stealth_scan.parse_workers, "0"),
            (stealth_scan.parse_workers, "33"),
            (stealth_scan.parse_timeout, "0.09"),
            (stealth_scan.parse_timeout, "3.01"),
        ):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    parser(value)


class RunTests(unittest.TestCase):
    def test_out_of_scope_target_fails_before_creating_executor(self):
        context = SimpleNamespace(
            target="192.0.2.10",
            args=SimpleNamespace(scope="192.0.3.0/24"),
            info=mock.Mock(),
        )
        with mock.patch("stealth_scan.cf.ThreadPoolExecutor") as executor:
            with self.assertRaisesRegex(ValueError, "outside declared scope"):
                stealth_scan.run(context)
        executor.assert_not_called()

    def test_valid_run_uses_bounded_executor_and_reports_observation_as_info(self):
        context = SimpleNamespace(
            target="192.0.2.10",
            args=SimpleNamespace(
                scope="192.0.2.0/24",
                ports=[80],
                max_workers=2,
                timeout=0.5,
            ),
            data={},
            info=mock.Mock(),
            good=mock.Mock(),
            warn=mock.Mock(),
            finding=mock.Mock(),
        )
        with (
            mock.patch("stealth_scan.cf.ThreadPoolExecutor") as executor,
            mock.patch("stealth_scan.probe", return_value=(80, "fixture banner")) as probe,
        ):
            executor.return_value.__enter__.return_value.map.side_effect = (
                lambda function, ports: map(function, ports)
            )
            self.assertEqual(stealth_scan.run(context), 0)

        executor.assert_called_once_with(max_workers=2)
        probe.assert_called_once_with("192.0.2.10", 80, 0.5)
        context.finding.assert_called_once()
        self.assertEqual(context.finding.call_args.args[1], "info")
        self.assertEqual(context.data["open_ports"], [80])


if __name__ == "__main__":
    unittest.main()
