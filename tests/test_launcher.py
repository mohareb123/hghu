import os
import unittest
from unittest.mock import MagicMock, patch

from protohunter.launcher import main


class LauncherTests(unittest.TestCase):
    def test_cli_arguments_are_forwarded(self):
        with patch('protohunter.launcher.cli_main', return_value=7) as cli:
            self.assertEqual(main(['doctor']), 7)
            cli.assert_called_once_with(['doctor'])

    def test_desktop_is_loopback_only_and_closes(self):
        server = MagicMock()
        server.__enter__.return_value = server
        server.server_port = 43210
        server.serve_forever.side_effect = KeyboardInterrupt
        with patch.dict(os.environ, {'PROTOHUNTER_NO_BROWSER':'1','PROTOHUNTER_PORT':'0'}), patch('protohunter.launcher.Server', return_value=server) as factory:
            self.assertEqual(main([]), 0)
            self.assertEqual(factory.call_args.args, (('127.0.0.1', 0),))
            self.assertTrue(factory.call_args.kwargs['desktop_tools'])
            server.__exit__.assert_called_once()

    def test_invalid_port_is_a_clear_error(self):
        with patch.dict(os.environ, {'PROTOHUNTER_PORT':'not-a-port'}):
            self.assertEqual(main([]), 2)
        with patch.dict(os.environ, {'PROTOHUNTER_PORT':'70000'}):
            self.assertEqual(main([]), 2)

    def test_browser_timer_is_cancelled(self):
        server = MagicMock()
        server.__enter__.return_value = server
        server.server_port = 43210
        server.serve_forever.side_effect = KeyboardInterrupt
        timer = MagicMock()
        with patch.dict(os.environ, {'PROTOHUNTER_NO_BROWSER':'0','PROTOHUNTER_PORT':'0'}), patch('protohunter.launcher.Server', return_value=server), patch('protohunter.launcher.threading.Timer', return_value=timer):
            self.assertEqual(main([]), 0)
            timer.start.assert_called_once()
            timer.cancel.assert_called_once()
