import warnings
from struct import pack
from unittest import TestCase, mock

from twisted.internet.error import ConnectionDone

from vncdotool import rfb
from vncdotool.security import base as security_base

MAX_REASON_LENGTH = security_base.MAX_REASON_LENGTH


class TestRFB(TestCase):

    def setUp(self) -> None:
        self.client = rfb.RFBClient()
        self.client.transport = mock.Mock()
        self.client.factory = mock.Mock()

    def test_auth_invalid(self):
        self.client._packet += b"X"
        self.client._handler()
        self.client.transport.loseConnection.assert_called_once()

    def test_invalid_server_response_reports_protocol_error(self):
        self.client.vncProtocolError = mock.Mock()
        self.client._packet += b"X"
        self.client._handler()
        self.client.vncProtocolError.assert_called_once()
        assert self.client._aborted

    def test_unknown_security_types_reports_protocol_error(self):
        self.client.vncProtocolError = mock.Mock()
        self.client._packet += (
            b"RFB 003.007\n"  # header
            b"\x01"  # num-auth-types
            b"\x7f"  # an auth type we do not support
        )
        self.client._handler()
        self.client.vncProtocolError.assert_called_once()
        assert self.client._aborted

    def test_unknown_auth_type_reports_protocol_error(self):
        self.client.vncProtocolError = mock.Mock()
        self.client._packet += (
            b"RFB 003.003\n"  # header
            b"\x00\x00\x00\x7f"  # an auth type we do not support
        )
        self.client._handler()
        self.client.vncProtocolError.assert_called_once()
        assert self.client._aborted

    def test_unknown_message_reports_protocol_error(self):
        self.client.vncProtocolError = mock.Mock()
        self.client._handleConnection(b"\x7f")
        self.client.vncProtocolError.assert_called_once()
        assert self.client._aborted

    def test_connection_refused_reports_protocol_error(self):
        self.client.vncProtocolError = mock.Mock()
        self.client._handleConnMessage(b"nope")
        self.client.vncProtocolError.assert_called_once()
        self.client.transport.loseConnection.assert_called_once()
        assert self.client._aborted

    def _drive_conn_failed(self, declared: int, payload: bytes):
        self.client.vncProtocolError = mock.Mock()
        self.client._handler = self.client._handleExpected
        self.client._handleConnFailed(pack("!I", declared))
        self.client._packet += payload
        self.client._handler()
        return self.client.vncProtocolError.call_args.args[0]

    def test_conn_failed_short_reason_is_kept_intact(self):
        reason = b"Too many security failures"
        message = self._drive_conn_failed(len(reason), reason)
        assert reason.decode() in message
        assert "truncated" not in message
        self.client.transport.loseConnection.assert_called_once()

    def test_conn_failed_empty_reason_is_accepted(self):
        message = self._drive_conn_failed(0, b"")
        assert "Connection refused" in message
        assert "truncated" not in message
        self.client.transport.loseConnection.assert_called_once()

    def test_conn_failed_reason_at_exactly_the_limit_is_not_truncated(self):
        reason = b"a" * MAX_REASON_LENGTH
        message = self._drive_conn_failed(MAX_REASON_LENGTH, reason)
        assert "truncated" not in message

    def test_conn_failed_overlong_reason_is_bounded_and_truncated(self):
        declared = 0xFFFFFFFF
        self.client.vncProtocolError = mock.Mock()
        self.client._handler = self.client._handleExpected
        self.client._handleConnFailed(pack("!I", declared))
        # it must not park on the declared 4 GiB
        assert self.client._expected_len == MAX_REASON_LENGTH
        assert self.client._expected_len < declared
        self.client.transport.loseConnection.assert_not_called()

        self.client._packet += b"b" * MAX_REASON_LENGTH
        self.client._handler()
        message = self.client.vncProtocolError.call_args.args[0]
        assert "truncated" in message
        assert str(declared) in message
        self.client.transport.loseConnection.assert_called_once()
        # no more than the cap is buffered
        assert not self.client._packet

    def test_conn_failed_one_byte_over_the_limit_is_truncated(self):
        message = self._drive_conn_failed(
            MAX_REASON_LENGTH + 1, b"c" * MAX_REASON_LENGTH
        )
        assert "truncated" in message

    def test_conn_failed_invalid_encoding_still_tears_down(self):
        # 0xff is never valid UTF-8; decoding must not raise through the
        # connection teardown.
        message = self._drive_conn_failed(2, b"\xff\xfe")
        assert "Connection refused" in message
        self.client.transport.loseConnection.assert_called_once()

    def test_conn_failed_reason_waiting_when_peer_hangs_up_winds_down(self):
        self.client.vncConnectionLost = mock.Mock()
        self.client._handler = self.client._handleExpected
        # server declares a reason but only sends part of it
        self.client.expect(self.client._handleConnMessage, 10)
        self.client._packet += b"short"
        self.client.connectionLost(ConnectionDone())
        self.client.vncConnectionLost.assert_called_once()
        assert self.client._aborted
        assert not self.client._packet

    def test_data_after_a_lost_connection_is_ignored(self):
        self.client.vncConnectionLost = mock.Mock()
        self.client._handler = self.client._handleExpected
        self.client.expect(self.client._handleConnMessage, 10)
        self.client.connectionLost(ConnectionDone())
        self.client.dataReceived(b"anything")
        self.client.vncConnectionLost.assert_called_once()
        assert not self.client._packet

    def test_security_failure_with_huge_reason_is_truncated_end_to_end(self):
        self.client.vncAuthFailed = mock.Mock()
        declared = MAX_REASON_LENGTH * 2
        payload = b"d" * MAX_REASON_LENGTH
        self.client._packet += (
            b"RFB 003.008\n"
            b"\x01"  # one security type
            b"\x01"  # NONE
            + pack("!I", 1)  # result: failed
            + pack("!I", declared)
            + payload
        )
        self.client._handler()
        reason = self.client.vncAuthFailed.call_args.args[0]
        assert reason.startswith(payload)
        assert reason.endswith(security_base.REASON_TRUNCATED_MARKER)
        self.client.transport.loseConnection.assert_called_once()
        assert not self.client._packet

    def test_security_failure_reason_waiting_when_peer_hangs_up_winds_down(self):
        self.client.vncConnectionLost = mock.Mock()
        # negotiate NONE on 3.8, then the server sends "failed" and stalls
        self.client._packet += b"RFB 003.008\n\x01\x01" + pack("!I", 1)
        self.client._handler()
        # parked waiting for the 4-byte reason length
        assert not self.client._aborted
        self.client.connectionLost(ConnectionDone())
        assert self.client._aborted
        self.client.vncConnectionLost.assert_called_once()

    def test_unknown_encoding_stops_processing_buffered_rectangles(self):
        self.client.vncProtocolError = mock.Mock()
        self.client._handler = self.client._handleExpected
        self.client.rectangles = 3
        self.client.expect(self.client._handleRectangle, 12)
        unknown_encoding = 0x7F
        header = pack("!HHHHi", 0, 0, 1, 1, unknown_encoding)
        self.client._packet += header * 3
        self.client._handler()
        self.client.vncProtocolError.assert_called_once()
        self.client.transport.loseConnection.assert_called_once()
        assert self.client._aborted
        assert not self.client._packet

    def test_auth_incmplete(self):
        self.client._packet += b"RFB 000.000"
        self.client._handler()
        self.client.transport.loseConnection.assert_not_called()

    def test_auth_invalid33(self):
        self.client._packet += (
            b"RFB 003.003\n"  # header
            b"\x00\x00\x00\x00"  # AuthTypes.INVALID
            b"\x00\x00\x00\x1a"  # length
            b"Too many security failures"
        )
        self.client._handler()
        assert self.client._version_server == (3, 3)
        assert self.client._version == (3, 3)
        self.client.transport.loseConnection.assert_called_once()

    def test_auth_none33(self):
        self.client._packet += (
            b"RFB 003.003\n"  # header
            b"\x00\x00\x00\x01"  # AuthTypes.NONE
        )
        self.client.factory.shared = 0
        self.client._handler()
        assert self.client._version_server == (3, 3)
        self.client.transport.write.assert_has_calls([
            mock.call(b"RFB 003.003\n"),
            mock.call(b"\x00"),  # shared
        ])

    def test_auth_none37(self):
        self.client._packet += (
            b"RFB 003.007\n"  # header
            b"\x01"  # num-auth-types
            b"\x01"  # AuthTypes.NONE
        )
        self.client.factory.shared = 0
        self.client._handler()
        assert self.client._version_server == (3, 7)
        self.client.transport.write.assert_has_calls([
            mock.call(b"RFB 003.007\n"),
            mock.call(b"\x01"),  # AuthTypes.NONE
            mock.call(b"\x00"),  # shared
        ])

    def test_server_fence_dispatches_from_handleConnection(self):
        self.client._handleConnection(b"\xf8")  # SERVER_FENCE
        assert self.client._expected_handler == self.client._pump
        assert self.client._expected_len == 8

    def test_clientFence(self):
        self.client.clientFence(rfb.FenceFlags.SYNC_NEXT, b"abc")
        self.client.transport.write.assert_called_once_with(
            b"\xf8\x00\x00\x00\x00\x00\x00\x04\x03abc"
        )

    def test_auth_none38(self):
        self.client._packet += (
            b"RFB 003.008\n"  # header
            b"\x01"  # num-auth-types
            b"\x01"  # AuthTypes.NONE
            b"\x00\x00\x00\x00"  # OK
        )
        self.client.factory.shared = 0
        self.client._handler()
        assert self.client._version_server == (3, 8)
        self.client.transport.write.assert_has_calls([
            mock.call(b"RFB 003.008\n"),
            mock.call(b"\x01"),  # AuthTypes.NONE
            mock.call(b"\x00"),  # shared
        ])

    def test_oversized_server_cut_text_length_is_a_diagnosed_disconnect(self):
        self.client.vncProtocolError = mock.Mock()
        self.client._handler = self.client._handleExpected
        self.client.expect(self.client._handleConnection, 1)
        oversized = self.client.MAX_MESSAGE_PAYLOAD + 1
        self.client._packet += bytes([rfb.MsgS2C.SERVER_CUT_TEXT]) + pack(
            "!xxxI", oversized
        )
        self.client._handler()
        self.client.vncProtocolError.assert_called_once()
        self.client.transport.loseConnection.assert_called_once()
        assert self.client._aborted
        # never grew a buffer waiting for the declared length
        assert not self.client._packet

    def test_auth_vnc38(self):
        challenge = bytes(range(16))
        self.client._packet += (
            b"RFB 003.008\n"  # header
            b"\x01"  # num-auth-types
            b"\x02"  # AuthTypes.VNC_AUTHENTICATION
            + challenge
            + b"\x00\x00\x00\x00"  # OK
        )
        self.client.factory.password = "secret"
        self.client.factory.shared = 0
        self.client._handler()
        self.client.transport.write.assert_has_calls([
            mock.call(b"RFB 003.008\n"),
            mock.call(b"\x02"),  # AuthTypes.VNC_AUTHENTICATION
            mock.call(rfb.des_encrypt(rfb._vnc_des("secret"), challenge)),
            mock.call(b"\x00"),  # shared
        ])

    def test_password_sent_after_the_handshake_still_answers_the_challenge(self):
        challenge = bytes(range(16))
        self.client._packet += (
            b"RFB 003.008\n"  # header
            b"\x01"  # num-auth-types
            b"\x02"  # AuthTypes.VNC_AUTHENTICATION
            + challenge
        )
        self.client.factory.password = None
        self.client._handler()
        self.client.sendPassword("secret")
        self.client.transport.write.assert_called_with(
            rfb.des_encrypt(rfb._vnc_des("secret"), challenge)
        )

    def test_security_type_without_a_handler_reports_protocol_error(self):
        self.client.vncProtocolError = mock.Mock()
        self.client.SUPPORTED_AUTHS = {rfb.AuthTypes.TIGHT}
        self.client._packet += (
            b"RFB 003.008\n"  # header
            b"\x01"  # num-auth-types
            b"\x10"  # AuthTypes.TIGHT
        )
        self.client._handler()
        self.client.vncProtocolError.assert_called_once()
        assert self.client._aborted

    def test_ardRequestCredentials_prompts_when_factory_has_no_username(self):
        self.client.factory = rfb.RFBFactory()
        with (
            mock.patch("builtins.input", return_value="alice") as input_,
            mock.patch("getpass.getpass", return_value="secret") as getpass_,
        ):
            self.client.ardRequestCredentials()
        input_.assert_called_once()
        getpass_.assert_called_once()
        assert self.client.factory.username == "alice"
        assert self.client.factory.password == "secret"


class TestRFBClientSubclassWarning(TestCase):

    def test_overriding_updateRectangle_warns(self):
        with self.assertWarnsRegex(FutureWarning, r"updateRectangle changed in 2\.0.*issues/385"):
            class Sub(rfb.RFBClient):
                def updateRectangle(self, x, y, width, height, data):
                    pass

    def test_overriding_fillRectangle_warns(self):
        with self.assertWarnsRegex(FutureWarning, r"fillRectangle changed in 2\.0.*issues/385"):
            class Sub(rfb.RFBClient):
                def fillRectangle(self, x, y, width, height, color):
                    pass

    def test_overriding_unrelated_method_does_not_warn(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error")

            class Sub(rfb.RFBClient):
                def bell(self):
                    pass

    def test_subclass_not_overriding_changing_hooks_does_not_warn(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error")

            class Sub(rfb.RFBClient):
                pass

    def test_override_from_vncdotool_module_does_not_warn(self):
        def updateRectangle(self, x, y, width, height, data):
            pass

        updateRectangle.__module__ = "vncdotool.client"

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            type("Sub", (rfb.RFBClient,), {"updateRectangle": updateRectangle})


class TestDesEncrypt(TestCase):

    def test_matches_the_published_des_vector(self):
        """The FIPS SP 800-17 single-DES vector, so this checks against
        published DES rather than against whatever this implementation
        happens to produce."""
        key = bytes.fromhex("0123456789ABCDEF")
        plaintext = bytes.fromhex("4E6F772069732074")

        self.assertEqual(
            rfb.des_encrypt(key, plaintext).hex().upper(),
            "3FA40E8A984D4815",
        )

    def test_emits_no_deprecation_warning(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            rfb.des_encrypt(b"12345678", b"87654321")
