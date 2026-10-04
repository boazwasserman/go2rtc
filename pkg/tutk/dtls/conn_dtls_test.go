package dtls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/tutk"
	piondtls "github.com/pion/dtls/v3"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v4/dpipe"
)

func configuredTestConn(options Options, authKey string) *DTLSConn {
	options, psk := normalizeOptions(options, "synthetic-enr", false)
	return &DTLSConn{
		uid:                  "synthetic-uid",
		authKey:              authKey,
		enr:                  "synthetic-enr",
		psk:                  psk,
		pskIdentity:          PSKIdentity(options.AVUsername),
		outerProtocolVersion: options.OuterProtocolVersion,
		sdkVersion:           options.SDKVersion,
		avUsername:           options.AVUsername,
		avPassword:           options.AVPassword,
		avLoginSecurityMode:  options.AVLoginSecurityMode,
		cipherSuites:         options.CipherSuites,
		sid:                  []byte("sid12345"),
	}
}

func TestConfiguredDiscoveryRequest(t *testing.T) {
	c := configuredTestConn(Options{
		OuterProtocolVersion: 29,
		SDKVersion:           [4]byte{0x03, 0x06, 0x03, 0x04},
		AVUsername:           "synthetic-user",
		AVPassword:           "synthetic-password",
		AVLoginSecurityMode:  2,
	}, "")

	packet := c.msgDisco(2)
	if len(packet) != 88 {
		t.Fatalf("discovery packet length = %d, want 88", len(packet))
	}
	if !bytes.Equal(packet[:4], []byte{0x04, 0x02, 0x1d, 0x02}) {
		t.Fatal("discovery marker, protocol version, or mode mismatch")
	}
	if binary.LittleEndian.Uint16(packet[8:]) != cmdDiscoReq {
		t.Fatal("discovery command mismatch")
	}
	if binary.LittleEndian.Uint16(packet[10:]) != 0x0021 {
		t.Fatal("discovery flags mismatch")
	}
	if !bytes.Equal(packet[52:56], []byte{0x03, 0x06, 0x03, 0x04}) {
		t.Fatal("discovery SDK version mismatch")
	}
	if packet[64] != 2 {
		t.Fatalf("discovery stage = %d, want 2", packet[64])
	}
	if !bytes.Equal(packet[74:], make([]byte, 14)) {
		t.Fatal("empty AuthKey field is not zero-filled")
	}
}

func TestDiscoveryAuthKeyField(t *testing.T) {
	c := configuredTestConn(Options{
		OuterProtocolVersion: 29,
		SDKVersion:           [4]byte{0x03, 0x06, 0x03, 0x04},
	}, "synthetic-auth")

	stageOne := c.msgDisco(1)
	if !bytes.Equal(stageOne[74:88], []byte("synthetic-auth")) {
		t.Fatal("non-empty AuthKey was not written to stage-one discovery")
	}

	stageTwo := c.msgDisco(2)
	if !bytes.Equal(stageTwo[74:], make([]byte, 14)) {
		t.Fatal("stage-two discovery unexpectedly contains AuthKey")
	}
}

func TestConfiguredOuterProtocolVersion(t *testing.T) {
	c := configuredTestConn(Options{OuterProtocolVersion: 29}, "")

	session := c.msgSession()
	if len(session) != 52 {
		t.Fatalf("session packet length = %d, want 52", len(session))
	}
	if session[2] != 29 || binary.LittleEndian.Uint16(session[8:]) != cmdSessionReq || binary.LittleEndian.Uint16(session[10:]) != 0x0033 {
		t.Fatal("session packet does not use the configured outer protocol fields")
	}

	data := c.msgTxData([]byte{0x01, 0x02}, 0)
	if data[2] != 29 || binary.LittleEndian.Uint16(data[8:]) != cmdDataTX || binary.LittleEndian.Uint16(data[10:]) != 0x0021 {
		t.Fatal("data packet does not use the configured outer protocol fields")
	}

	keepalive := c.msgKeepalive(nil)
	if keepalive[2] != 29 || binary.LittleEndian.Uint16(keepalive[8:]) != cmdKeepaliveReq || binary.LittleEndian.Uint16(keepalive[10:]) != 0x0021 {
		t.Fatal("keepalive packet does not use the configured outer protocol fields")
	}
}

func TestConfiguredAVLogin(t *testing.T) {
	c := configuredTestConn(Options{
		OuterProtocolVersion: 29,
		AVUsername:           "synthetic-user",
		AVPassword:           "synthetic-password",
		AVLoginSecurityMode:  2,
	}, "")

	packet := c.msgAVLogin(magicAVLogin1, 570, 0x0001, []byte{1, 2, 3, 4})
	if len(packet) != 570 {
		t.Fatalf("AV login packet length = %d, want 570", len(packet))
	}
	if binary.LittleEndian.Uint16(packet) != magicAVLogin1 ||
		binary.LittleEndian.Uint16(packet[16:]) != 546 ||
		binary.LittleEndian.Uint16(packet[18:]) != 0x0001 ||
		!bytes.Equal(packet[20:24], []byte{1, 2, 3, 4}) {
		t.Fatal("AV login header fields mismatch")
	}
	if binary.LittleEndian.Uint16(packet[2:]) != avProtocolVersion {
		t.Fatal("AV login uses the wrong inner protocol version")
	}
	if !bytes.Equal(packet[24:280], paddedTestField("synthetic-user", 256)) {
		t.Fatal("AV login username field mismatch")
	}
	if !bytes.Equal(packet[280:536], paddedTestField("synthetic-password", 256)) {
		t.Fatal("AV login password field mismatch")
	}
	if binary.LittleEndian.Uint32(packet[540:]) != 2 {
		t.Fatal("AV login security mode mismatch")
	}

	packet2 := c.msgAVLogin(magicAVLogin2, 572, 0, []byte{1, 2, 3, 4})
	if len(packet2) != 572 || binary.LittleEndian.Uint16(packet2) != magicAVLogin2 {
		t.Fatal("second AV login request shape mismatch")
	}
}

func TestPSKIdentityAndPassword(t *testing.T) {
	const password = "synthetic-password"

	c := configuredTestConn(Options{
		AVUsername: "synthetic-user",
		AVPassword: password,
	}, "")
	if got := c.pskIdentity; got != "AUTHPWD_synthetic-user" {
		t.Fatal("configured PSK identity mismatch")
	}
	if !bytes.Equal(c.psk, DerivePSK(password)) {
		t.Fatal("configured AV password was not used to derive the DTLS PSK")
	}

	config := buildDTLSConfigWithIdentity(c.psk, c.pskIdentity, false)
	if !bytes.Equal(config.PSKIdentityHint, []byte("AUTHPWD_synthetic-user")) {
		t.Fatal("DTLS config PSK identity mismatch")
	}
	psk, err := config.PSK(nil)
	if err != nil || !bytes.Equal(psk, DerivePSK(password)) {
		t.Fatal("DTLS config PSK mismatch")
	}
}

func TestConfiguredCipherSuites(t *testing.T) {
	c := configuredTestConn(Options{
		CipherSuites: []piondtls.CipherSuiteID{
			piondtls.TLS_PSK_WITH_AES_128_CBC_SHA256,
		},
	}, "")
	if len(c.cipherSuites) != 1 ||
		c.cipherSuites[0] != piondtls.TLS_PSK_WITH_AES_128_CBC_SHA256 {
		t.Fatal("configured DTLS cipher suite mismatch")
	}
}

func TestLegacyDefaultsRemainCompatible(t *testing.T) {
	options, psk := normalizeOptions(Options{}, "synthetic-enr", true)
	if options.OuterProtocolVersion != outerProtocolVersion {
		t.Fatal("legacy outer protocol version changed")
	}
	if options.SDKVersion != defaultSDKVersion {
		t.Fatal("legacy SDK version changed")
	}
	if options.AVLoginSecurityMode != 4 {
		t.Fatal("legacy AV login security mode changed")
	}
	if !bytes.Equal(psk, DerivePSK("synthetic-enr")) {
		t.Fatal("legacy DTLS PSK derivation changed")
	}

	config := buildDTLSConfig(psk, false)
	if !bytes.Equal(config.PSKIdentityHint, []byte(PSKIdentity("admin"))) {
		t.Fatal("legacy DTLS PSK identity changed")
	}
}

func TestAVClientStartRequiresSuccessResultBeforePublishingCapability(t *testing.T) {
	for _, advertisement := range []byte{0, 1} {
		t.Run("success_advertisement_"+string(rune('0'+advertisement)), func(t *testing.T) {
			c, writer, cancel := newLoginTestConn(t)
			err := completeLoginWithResponse(t, c, writer, avLoginResponse(0, advertisement))
			if err != nil {
				t.Fatalf("successful AV result returned an error: %v", err)
			}
			if got := c.HasTwoWayStreaming(); got != (advertisement == 1) {
				t.Fatalf("two-way advertisement = %t, want %t", got, advertisement == 1)
			}
			assertSuccessfulLoginWrites(t, writer)
			if err := c.Close(); err != nil {
				t.Fatalf("Close after successful login failed: %v", err)
			}
			if c.HasTwoWayStreaming() {
				t.Fatal("Close did not clear two-way capability")
			}
			cancel()
		})
	}

	c, writer, cancel := newLoginTestConn(t)
	err := completeLoginWithResponse(t, c, writer, avLoginResponse(3, 1))
	var resultErr *AVLoginResultError
	if !errors.As(err, &resultErr) || resultErr.Result != 3 {
		t.Fatalf("authentication rejection error = %T %v, want numeric result 3", err, err)
	}
	if c.HasTwoWayStreaming() {
		t.Fatal("rejected login published the advertised two-way capability")
	}
	if got := len(writer.snapshot()); got != 2 {
		t.Fatalf("writes after rejected login = %d, want login requests only", got)
	}
	cancel()
}

func TestAVClientStartRejectsEveryNonzeroResult(t *testing.T) {
	for result := 1; result <= 255; result++ {
		c, writer, cancel := newLoginTestConn(t)
		err := completeLoginWithResponse(t, c, writer, avLoginResponse(byte(result), 1))
		var resultErr *AVLoginResultError
		if !errors.As(err, &resultErr) || int(resultErr.Result) != result {
			t.Fatalf("result %d returned %T %v", result, err, err)
		}
		if c.HasTwoWayStreaming() {
			t.Fatalf("result %d published two-way capability", result)
		}
		if got := len(writer.snapshot()); got != 2 {
			t.Fatalf("result %d produced %d writes, want login requests only", result, got)
		}
		cancel()
	}
}

func TestAVClientStartRejectsTruncatedMatchingResponse(t *testing.T) {
	c, writer, cancel := newLoginTestConn(t)
	response := avLoginResponse(0, 1)[:31]
	err := completeLoginWithResponse(t, c, writer, response)
	if err == nil || !strings.Contains(err.Error(), "too short: 31 bytes") {
		t.Fatalf("truncated login response error = %v", err)
	}
	if c.HasTwoWayStreaming() || len(writer.snapshot()) != 2 {
		t.Fatal("truncated response published capability or sent success ACK")
	}
	cancel()
}

func TestAVClientStartIgnoresUnrelatedMagicUntilValidResponse(t *testing.T) {
	c, writer, cancel := newLoginTestConn(t)
	done := startLoginAndWaitForRequests(t, c, writer)
	c.rawCmd <- []byte{0x34, 0x12, 0x00}
	c.rawCmd <- avLoginResponse(0, 1)
	if err := awaitLoginResult(t, done); err != nil {
		t.Fatalf("valid response after unrelated magic failed: %v", err)
	}
	if !c.HasTwoWayStreaming() {
		t.Fatal("valid response was not accepted after unrelated magic")
	}
	assertSuccessfulLoginWrites(t, writer)
	cancel()
}

func TestAVClientStartFailsClosedForTimeoutAndUnavailableInputs(t *testing.T) {
	t.Run("invalid_timeout", func(t *testing.T) {
		c, writer, cancel := newLoginTestConn(t)
		if err := c.AVClientStart(0); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("zero timeout error = %v, want deadline exceeded", err)
		}
		if len(writer.snapshot()) != 0 || c.HasTwoWayStreaming() {
			t.Fatal("invalid timeout wrote packets or published capability")
		}
		cancel()
	})

	t.Run("response_timeout", func(t *testing.T) {
		c, writer, cancel := newLoginTestConn(t)
		err := c.AVClientStart(30 * time.Millisecond)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("response timeout error = %v", err)
		}
		if len(writer.snapshot()) != 2 || c.HasTwoWayStreaming() {
			t.Fatal("timeout sent success ACK or published capability")
		}
		cancel()
	})

	t.Run("nil_context", func(t *testing.T) {
		c, _, cancel := newLoginTestConn(t)
		c.ctx = nil
		if err := c.AVClientStart(time.Second); err == nil {
			t.Fatal("nil context was accepted")
		}
		cancel()
	})

	t.Run("nil_response_queue", func(t *testing.T) {
		c, _, cancel := newLoginTestConn(t)
		c.rawCmd = nil
		if err := c.AVClientStart(time.Second); err == nil {
			t.Fatal("nil response queue was accepted")
		}
		cancel()
	})

	t.Run("nil_writer", func(t *testing.T) {
		c, _, cancel := newLoginTestConn(t)
		c.clientWriter = nil
		if err := c.AVClientStart(time.Second); err == nil {
			t.Fatal("nil client writer was accepted")
		}
		cancel()
	})
}

func TestAVClientStartRejectsWriteErrorsAndShortWrites(t *testing.T) {
	for _, test := range []struct {
		name     string
		outcomes []loginWriteOutcome
	}{
		{name: "first_request_error", outcomes: []loginWriteOutcome{{err: errors.New("synthetic write failure")}}},
		{name: "first_request_short_write", outcomes: []loginWriteOutcome{{short: true}}},
		{name: "second_request_error", outcomes: []loginWriteOutcome{{}, {err: errors.New("synthetic write failure")}}},
		{name: "second_request_short_write", outcomes: []loginWriteOutcome{{}, {short: true}}},
		{name: "ack_short_write", outcomes: []loginWriteOutcome{{}, {}, {short: true}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, writer, cancel := newLoginTestConn(t)
			writer.setOutcomes(test.outcomes)
			if len(test.outcomes) == 3 {
				done := startLoginAndWaitForRequests(t, c, writer)
				c.rawCmd <- avLoginResponse(0, 1)
				if err := awaitLoginResult(t, done); err == nil {
					t.Fatal("short success ACK write was accepted")
				}
			} else {
				if err := c.AVClientStart(time.Second); err == nil {
					t.Fatal("failed or short login request write was accepted")
				}
			}
			if c.HasTwoWayStreaming() {
				t.Fatal("write failure published two-way capability")
			}
			if got := len(writer.snapshot()); got != len(test.outcomes) {
				t.Fatalf("writer calls = %d, want %d", got, len(test.outcomes))
			}
			cancel()
		})
	}
}

func TestAVClientStartDrainsStaleRepliesBeforeLogin(t *testing.T) {
	for _, test := range []struct {
		name     string
		stale    []byte
		response []byte
		wantErr  bool
	}{
		{name: "stale_rejection_does_not_fail_fresh_success", stale: avLoginResponse(3, 1), response: avLoginResponse(0, 1)},
		{name: "stale_success_does_not_accept_fresh_rejection", stale: avLoginResponse(0, 1), response: avLoginResponse(3, 1), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, writer, cancel := newLoginTestConn(t)
			c.rawCmd <- test.stale
			err := completeLoginWithResponse(t, c, writer, test.response)
			if (err != nil) != test.wantErr {
				t.Fatalf("fresh response result = %v, want error %t", err, test.wantErr)
			}
			if (c.HasTwoWayStreaming()) == test.wantErr {
				t.Fatal("stale response affected published login capability")
			}
			cancel()
		})
	}
}

func TestAVClientStartIsSingleAttemptAcrossConcurrentAndRepeatedCalls(t *testing.T) {
	t.Run("pending_then_success", func(t *testing.T) {
		c, writer, cancel := newLoginTestConn(t)
		done := startLoginAndWaitForRequests(t, c, writer)
		if err := c.AVClientStart(time.Second); err == nil || !strings.Contains(err.Error(), "already attempted") {
			t.Fatalf("concurrent login result = %v, want already-attempted error", err)
		}
		c.rawCmd <- avLoginResponse(0, 1)
		if err := awaitLoginResult(t, done); err != nil {
			t.Fatalf("first login failed after concurrent rejection: %v", err)
		}
		if err := c.AVClientStart(time.Second); err == nil {
			t.Fatal("login restart after success was accepted")
		}
		if !c.HasTwoWayStreaming() {
			t.Fatal("rejected duplicate call changed successful login state")
		}
		assertSuccessfulLoginWrites(t, writer)
		cancel()
	})

	t.Run("failure_then_retry", func(t *testing.T) {
		c, writer, cancel := newLoginTestConn(t)
		err := completeLoginWithResponse(t, c, writer, avLoginResponse(3, 1))
		if err == nil {
			t.Fatal("rejected login unexpectedly succeeded")
		}
		if retryErr := c.AVClientStart(time.Second); retryErr == nil || !strings.Contains(retryErr.Error(), "already attempted") {
			t.Fatalf("retry result = %v, want already-attempted error", retryErr)
		}
		if len(writer.snapshot()) != 2 || c.HasTwoWayStreaming() {
			t.Fatal("retry changed failed login state or wrote packets")
		}
		cancel()
	})
}

func TestAVClientStartCancellationAndCloseDoNotAcknowledge(t *testing.T) {
	t.Run("cancel_during_wait", func(t *testing.T) {
		c, writer, cancel := newLoginTestConn(t)
		done := startLoginAndWaitForRequests(t, c, writer)
		cancel()
		if err := awaitLoginResult(t, done); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel result = %v, want context canceled", err)
		}
		if len(writer.snapshot()) != 2 || c.HasTwoWayStreaming() {
			t.Fatal("canceled login sent success ACK or published capability")
		}
	})

	t.Run("close_before_start", func(t *testing.T) {
		c, writer, _ := newLoginTestConn(t)
		if err := c.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
		if err := c.AVClientStart(time.Second); err == nil {
			t.Fatal("login after Close was accepted")
		}
		if len(writer.snapshot()) != 0 || c.HasTwoWayStreaming() {
			t.Fatal("login after Close wrote packets or published capability")
		}
	})

	t.Run("close_during_wait", func(t *testing.T) {
		c, writer, _ := newLoginTestConn(t)
		done := startLoginAndWaitForRequests(t, c, writer)
		if err := c.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
		if err := awaitLoginResult(t, done); !errors.Is(err, context.Canceled) {
			t.Fatalf("login after Close returned %v, want context canceled", err)
		}
		if len(writer.snapshot()) != 2 || c.HasTwoWayStreaming() {
			t.Fatal("closed login sent success ACK or published capability")
		}
	})

	t.Run("close_during_success_ack", func(t *testing.T) {
		c, writer, _ := newLoginTestConn(t)
		writer.blockWrite(2)
		done := startLoginAndWaitForRequests(t, c, writer)
		c.rawCmd <- avLoginResponse(0, 1)
		select {
		case <-writer.blocked:
		case <-time.After(2 * time.Second):
			t.Fatal("success ACK write did not reach test barrier")
		}

		closeDone := make(chan error, 1)
		go func() {
			closeDone <- c.Close()
		}()
		select {
		case <-c.ctx.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not cancel the login context")
		}
		writer.releaseBlockedWrite()
		if err := awaitLoginResult(t, done); !errors.Is(err, context.Canceled) {
			t.Fatalf("login result after Close = %v, want context canceled", err)
		}
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("Close failed: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not return after the ACK write completed")
		}
		if c.HasTwoWayStreaming() || len(writer.snapshot()) != 3 {
			t.Fatal("close during ACK published capability or wrote a ticker ACK")
		}
	})
}

func TestPeriodicAVACKFailureTerminatesSessionAndClearsSpeakerState(t *testing.T) {
	writeErr := errors.New("synthetic periodic ACK failure")
	for _, test := range []struct {
		name    string
		outcome loginWriteOutcome
		wantErr error
	}{
		{name: "writer_error", outcome: loginWriteOutcome{err: writeErr}, wantErr: writeErr},
		{name: "short_write", outcome: loginWriteOutcome{short: true}, wantErr: io.ErrShortWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, writer, cancel := newLoginTestConn(t)
			outcomes := make([]loginWriteOutcome, 5)
			outcomes[4] = test.outcome
			writer.setOutcomes(outcomes)
			done := startLoginAndWaitForRequests(t, c, writer)
			c.rawCmd <- avLoginResponse(0, 1)
			if err := awaitLoginResult(t, done); err != nil {
				t.Fatalf("AV login failed: %v", err)
			}

			if err := c.AVTwoWayStart(1); err != nil {
				t.Fatalf("speaker start failed: %v", err)
			}
			for i := 0; i < 2; i++ {
				select {
				case <-writer.calls:
				case <-time.After(time.Second):
					t.Fatal("timed out waiting for initial ACK and speaker-start writes")
				}
			}
			select {
			case <-writer.calls:
			case <-time.After(2 * time.Second):
				t.Fatal("periodic ACK write did not occur")
			}
			select {
			case <-c.Done():
			case <-time.After(time.Second):
				t.Fatal("periodic ACK failure did not terminate the session")
			}
			c.wg.Wait()

			if err := c.Error(); err == nil || !strings.Contains(err.Error(), "av acknowledgement ticker failed") {
				t.Fatalf("session error = %v, want periodic ACK failure", err)
			}
			if !errors.Is(c.Error(), test.wantErr) {
				t.Fatalf("session error = %v, want %v", c.Error(), test.wantErr)
			}
			if c.HasTwoWayStreaming() || c.twoWayStarted {
				t.Fatal("periodic ACK failure retained two-way or active speaker state")
			}
			if err := c.AVSendAudioDataTwoWay(tutk.CodecPCMU, make([]byte, 640), 0, 16000, 1); err == nil {
				t.Fatal("audio send succeeded after session termination")
			}
			if got := len(writer.snapshot()); got != 5 {
				t.Fatalf("writes after periodic ACK failure = %d, want exactly 5", got)
			}

			c.failAVSession(io.EOF)
			if !errors.Is(c.Error(), test.wantErr) {
				t.Fatalf("secondary error replaced original ACK failure: %v", c.Error())
			}
			cancel()
		})
	}
}

func TestCloseDuringPeriodicAVACKWriteDoesNotRecordShutdownAsFailure(t *testing.T) {
	c, writer, _ := newLoginTestConn(t)
	writer.blockWrite(3)
	done := startLoginAndWaitForRequests(t, c, writer)
	c.rawCmd <- avLoginResponse(0, 1)
	if err := awaitLoginResult(t, done); err != nil {
		t.Fatalf("AV login failed: %v", err)
	}
	select {
	case <-writer.calls:
	case <-time.After(time.Second):
		t.Fatal("initial success ACK was not written")
	}

	select {
	case <-writer.blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("periodic ACK did not reach the writer barrier")
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- c.Close()
	}()
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the session")
	}
	writer.releaseBlockedWrite()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after the ACK writer was released")
	}
	c.wg.Wait()
	if !errors.Is(c.Error(), io.EOF) {
		t.Fatalf("normal close recorded an ACK failure: %v", c.Error())
	}
	if got := len(writer.snapshot()); got != 4 {
		t.Fatalf("writes after close = %d, want only login requests and ACKs", got)
	}
}

func TestUnexpectedClientReadEOFTerminatesSession(t *testing.T) {
	clientConn, peerConn := newMemoryDTLSPair(t)
	c, _, cancel := newLoginTestConn(t)
	c.mu.Lock()
	c.clientConn = clientConn
	c.hasTwoWayStreaming = true
	c.twoWayStarted = true
	c.wg.Add(1)
	c.mu.Unlock()
	go c.worker()

	if err := peerConn.Close(); err != nil {
		t.Fatalf("close in-memory DTLS peer: %v", err)
	}
	select {
	case <-c.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("unexpected client read EOF did not terminate the session")
	}
	c.wg.Wait()
	if err := c.Error(); err == nil || !strings.Contains(err.Error(), "dtls av client read failed") {
		t.Fatalf("session error = %v, want client read failure", err)
	}
	if c.HasTwoWayStreaming() || c.twoWayStarted {
		t.Fatal("client read EOF left AV capability or speaker state active")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	cancel()
}

func TestWriteAndWaitIOCtrlRejectsFailedACKWrites(t *testing.T) {
	writeErr := errors.New("synthetic IOCTRL ACK write failure")
	for _, test := range []struct {
		name    string
		outcome loginWriteOutcome
		wantErr error
		closed  bool
	}{
		{name: "writer_error", outcome: loginWriteOutcome{err: writeErr}, wantErr: writeErr},
		{name: "short_write", outcome: loginWriteOutcome{short: true}, wantErr: io.ErrShortWrite},
		{name: "closed_session", wantErr: context.Canceled, closed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, writer, cancel := newLoginTestConn(t)
			writer.setOutcomes([]loginWriteOutcome{test.outcome})
			c.mu.Lock()
			c.hasTwoWayStreaming = true
			c.twoWayStarted = true
			c.mu.Unlock()
			if test.closed {
				if err := c.Close(); err != nil {
					t.Fatalf("Close failed: %v", err)
				}
			}

			c.rawCmd <- []byte{0x01}
			matched := false
			data, err := c.WriteAndWaitIOCtrl([]byte{0x02}, func([]byte) bool {
				matched = true
				return true
			}, time.Second)
			if !errors.Is(err, test.wantErr) || data != nil || matched {
				t.Fatalf("IOCTRL result = data %v, matched %t, error %v", data, matched, err)
			}
			if c.HasTwoWayStreaming() || c.twoWayStarted {
				t.Fatal("failed acknowledgement left AV capability or speaker state active")
			}
			if !test.closed && !errors.Is(c.Error(), test.wantErr) {
				t.Fatalf("session error = %v, want underlying ACK failure %v", c.Error(), test.wantErr)
			}
			cancel()
		})
	}
}

func TestWorkerTerminatesSessionIfClientPointerMissingWithLiveContext(t *testing.T) {
	c, _, cancel := newLoginTestConn(t)
	c.mu.Lock()
	c.clientConn = nil
	c.hasTwoWayStreaming = true
	c.twoWayStarted = true
	c.mu.Unlock()

	c.wg.Add(1)
	workerDone := make(chan struct{})
	go func() {
		c.worker()
		close(workerDone)
	}()
	select {
	case <-workerDone:
	case <-time.After(time.Second):
		t.Fatal("worker did not handle a cleared client connection")
	}
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("missing client pointer did not terminate the live session")
	}
	if c.Error() == nil || c.Error() == io.EOF {
		t.Fatalf("missing client pointer did not record a terminal error: %v", c.Error())
	}
	if c.HasTwoWayStreaming() || c.twoWayStarted {
		t.Fatal("missing client pointer left AV capability or speaker state active")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	cancel()
}

func TestCloseDuringActualWorkerReadAfterPeriodicACKFailure(t *testing.T) {
	clientConn, peerConn := newMemoryDTLSPair(t)
	c, writer, cancel := newLoginTestConn(t)
	writeErr := errors.New("synthetic periodic ACK failure")
	writer.setOutcomes([]loginWriteOutcome{{}, {}, {}, {err: writeErr}})
	readEntered := make(chan struct{})
	releaseRead := make(chan struct{})
	var releaseOnce sync.Once
	unblockRead := func() { releaseOnce.Do(func() { close(releaseRead) }) }
	t.Cleanup(unblockRead)

	c.mu.Lock()
	c.clientConn = clientConn
	c.cmdAck = func() {
		close(readEntered)
		<-releaseRead
	}
	c.wg.Add(1)
	c.mu.Unlock()
	go c.worker()

	loginDone := startLoginAndWaitForRequests(t, c, writer)
	c.rawCmd <- avLoginResponse(0, 1)
	if err := awaitLoginResult(t, loginDone); err != nil {
		t.Fatalf("AV login failed: %v", err)
	}
	select {
	case <-writer.calls:
	case <-time.After(time.Second):
		t.Fatal("initial login ACK was not written")
	}

	if _, err := peerConn.Write([]byte{byte(magicACK), byte(magicACK >> 8)}); err != nil {
		t.Fatalf("write actual DTLS worker packet: %v", err)
	}
	select {
	case <-readEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("actual worker did not read and dispatch the DTLS packet")
	}
	select {
	case <-writer.calls:
	case <-time.After(2 * time.Second):
		t.Fatal("periodic ACK write did not occur")
	}
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("periodic ACK failure did not terminate the session")
	}
	if !errors.Is(c.Error(), writeErr) {
		t.Fatalf("session error = %v, want original periodic ACK failure", c.Error())
	}
	if c.HasTwoWayStreaming() || c.twoWayStarted {
		t.Fatal("periodic ACK failure left two-way capability or speaker state active")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- c.Close()
	}()
	closeDeadline := time.NewTimer(time.Second)
	defer closeDeadline.Stop()
	closePoll := time.NewTicker(time.Millisecond)
	defer closePoll.Stop()
	for {
		c.mu.RLock()
		closed := c.closed && c.clientConn == nil
		c.mu.RUnlock()
		if closed {
			break
		}
		select {
		case <-closePoll.C:
		case <-closeDeadline.C:
			unblockRead()
			<-closeDone
			t.Fatal("Close did not clear the client connection pointer")
		}
	}

	unblockRead()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not reap the actual worker")
	}
	c.wg.Wait()
	if !errors.Is(c.Error(), writeErr) {
		t.Fatalf("worker or Close replaced the original ACK failure: %v", c.Error())
	}
	if got := len(writer.snapshot()); got != 4 {
		t.Fatalf("writes after worker teardown = %d, want exactly 4", got)
	}
	cancel()
}

func TestAVTwoWaySpeakerControlsUseClientDTLS(t *testing.T) {
	writer := &captureWriter{}
	c := configuredTestConn(Options{}, "")
	c.clientWriter = writer
	c.hasTwoWayStreaming = true

	const channel = uint32(1)
	if err := c.AVTwoWayStart(channel); err != nil {
		t.Fatalf("AVTwoWayStart failed: %v", err)
	}
	if c.serverConn != nil {
		t.Fatal("AVTwoWayStart unexpectedly initialized the separate server connection")
	}
	assertSpeakerControl(t, writer.data[0], speakerStartControl, channel, 0)

	if err := c.AVTwoWayStop(channel); err != nil {
		t.Fatalf("AVTwoWayStop failed: %v", err)
	}
	assertSpeakerControl(t, writer.data[1], speakerStopControl, channel, 1)
	if c.twoWayStarted {
		t.Fatal("two-way state remained active after stop")
	}
	if c.twoWayChannel != 0 || c.twoWayAudioSeq != 0 || c.twoWayAudioFrameNo != 0 {
		t.Fatal("two-way state was not reset after stop")
	}

	if err := c.AVTwoWayStop(channel); err != nil {
		t.Fatalf("second AVTwoWayStop failed: %v", err)
	}
	if len(writer.data) != 2 {
		t.Fatalf("idempotent stop wrote %d frames, want 2", len(writer.data))
	}
}

func TestAVTwoWayStartRequiresNegotiatedSupport(t *testing.T) {
	writer := &captureWriter{}
	c := configuredTestConn(Options{}, "")
	c.clientWriter = writer

	if err := c.AVTwoWayStart(1); err == nil {
		t.Fatal("AVTwoWayStart succeeded without negotiated two-way support")
	}
	if len(writer.data) != 0 {
		t.Fatal("unsupported AVTwoWayStart wrote a control frame")
	}
}

func TestAudioLogsDoNotContainPayload(t *testing.T) {
	const privatePayloadMarker = "private-audio-payload"
	for _, direction := range []string{"SERVER TX", "CLIENT TX"} {
		got := formatAudioLog(direction, 692, tutk.CodecPCMU, 40000)
		if strings.Contains(got, privatePayloadMarker) {
			t.Fatalf("audio log contains payload marker: %q", got)
		}
		if !strings.Contains(got, "["+direction+"]") ||
			!strings.Contains(got, "len=692") ||
			!strings.Contains(got, "codec=0x89") ||
			!strings.Contains(got, "timestamp_us=40000") {
			t.Fatalf("audio log missing safe metadata: %q", got)
		}
	}
}

func TestAVTwoWayPCMUAudioTimestampsMatchCAM720FrameFormat(t *testing.T) {
	writer := &captureWriter{}
	c := configuredTestConn(Options{}, "")
	c.clientWriter = writer
	c.hasTwoWayStreaming = true

	payloads := make([][]byte, 3)
	for frameNo := range payloads {
		payloads[frameNo] = make([]byte, 640)
		for i := range payloads[frameNo] {
			payloads[frameNo][i] = byte(frameNo + i)
		}
	}

	if err := c.AVSendAudioDataTwoWay(tutk.CodecPCMU, payloads[0], 0, 16000, 1); err == nil {
		t.Fatal("AVSendAudioDataTwoWay succeeded before speaker start")
	}
	if len(writer.data) != 0 {
		t.Fatal("audio sent before speaker start")
	}

	if err := c.AVTwoWayStart(1); err != nil {
		t.Fatalf("AVTwoWayStart failed: %v", err)
	}
	for frameNo, payload := range payloads {
		if err := c.AVSendAudioDataTwoWay(tutk.CodecPCMU, payload, uint32(frameNo*40), 16000, 1); err != nil {
			t.Fatalf("AVSendAudioDataTwoWay frame %d failed: %v", frameNo, err)
		}
	}
	if c.serverConn != nil {
		t.Fatal("two-way audio unexpectedly used the separate server connection")
	}

	if len(writer.data) != 4 {
		t.Fatalf("captured frames = %d, want speaker start plus 3 audio frames", len(writer.data))
	}
	for i, payload := range payloads {
		frame := writer.data[i+1]
		if len(frame) != 36+640+16 {
			t.Fatalf("audio frame %d length = %d, want 692", i, len(frame))
		}
		frameNo := uint32(i + 1)
		prevFrame := uint32(i)
		wantOuterFlags := uint32(0x00100001)
		if i == 0 {
			wantOuterFlags = 1
		}
		if frame[0] != tutk.ChannelAudio || frame[1] != tutk.FrameTypeStartAlt ||
			binary.LittleEndian.Uint16(frame[2:]) != avProtocolVersion ||
			binary.LittleEndian.Uint32(frame[4:]) != frameNo ||
			binary.LittleEndian.Uint32(frame[8:]) != uint32(i*40) ||
			binary.LittleEndian.Uint32(frame[12:]) != wantOuterFlags {
			t.Fatalf("audio frame %d outer header mismatch", i)
		}
		if frame[16] != tutk.ChannelAudio || frame[17] != tutk.FrameTypeEndSingle ||
			binary.LittleEndian.Uint16(frame[18:]) != uint16(prevFrame) ||
			binary.LittleEndian.Uint16(frame[20:]) != 1 ||
			binary.LittleEndian.Uint16(frame[22:]) != 0x0010 ||
			binary.LittleEndian.Uint32(frame[24:]) != 656 ||
			binary.LittleEndian.Uint32(frame[28:]) != prevFrame ||
			binary.LittleEndian.Uint32(frame[32:]) != frameNo {
			t.Fatalf("audio frame %d inner header mismatch", i)
		}
		if !bytes.Equal(frame[36:676], payload) {
			t.Fatalf("audio frame %d payload mismatch", i)
		}

		frameInfo := frame[676:]
		if frameInfo[0] != tutk.CodecPCMU ||
			frameInfo[2] != 14 ||
			frameInfo[4] != 1 ||
			binary.LittleEndian.Uint32(frameInfo[12:]) != uint32(i*10) {
			t.Fatalf("audio frame %d frame info timestamp mismatch", i)
		}
	}
}

func TestAVTwoWayNonCAM720PCMUUsesPayloadDuration(t *testing.T) {
	writer := &captureWriter{}
	c := configuredTestConn(Options{}, "")
	c.clientWriter = writer
	c.hasTwoWayStreaming = true
	if err := c.AVTwoWayStart(1); err != nil {
		t.Fatalf("AVTwoWayStart failed: %v", err)
	}

	payload := make([]byte, 320)
	for i := 0; i < 2; i++ {
		if err := c.AVSendAudioDataTwoWay(tutk.CodecPCMU, payload, uint32(i*20), 16000, 1); err != nil {
			t.Fatalf("AVSendAudioDataTwoWay frame %d failed: %v", i, err)
		}
	}
	frame := writer.data[2]
	frameInfoTimestamp := binary.LittleEndian.Uint32(frame[36+len(payload)+12:])
	if frameInfoTimestamp != 20000 {
		t.Fatalf("frame-info timestamp = %d, want original payload duration 20000", frameInfoTimestamp)
	}
}

func TestAVTwoWayCloseClearsState(t *testing.T) {
	writer := &captureWriter{}
	c := configuredTestConn(Options{}, "")
	c.clientWriter = writer
	c.cancel = func() {}
	c.hasTwoWayStreaming = true

	if err := c.AVTwoWayStart(1); err != nil {
		t.Fatalf("AVTwoWayStart failed: %v", err)
	}
	c.twoWayAudioSeq = 4
	c.twoWayAudioFrameNo = 5

	if err := c.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if c.hasTwoWayStreaming || c.twoWayStarted || c.twoWayChannel != 0 ||
		c.twoWayAudioSeq != 0 || c.twoWayAudioFrameNo != 0 {
		t.Fatal("Close did not clear two-way state")
	}
}

func assertSpeakerControl(t *testing.T, frame []byte, control, channel uint32, seq uint16) {
	t.Helper()
	if len(frame) != 52 {
		t.Fatalf("speaker control frame length = %d, want 52", len(frame))
	}
	if binary.LittleEndian.Uint16(frame) != avProtocolVersion ||
		binary.LittleEndian.Uint16(frame[2:]) != avProtocolVersion ||
		binary.LittleEndian.Uint16(frame[16:]) != magicIOCtrl ||
		binary.LittleEndian.Uint16(frame[18:]) != seq ||
		binary.LittleEndian.Uint32(frame[24:]) != 16 {
		t.Fatal("speaker control IOCTRL header mismatch")
	}
	if binary.LittleEndian.Uint32(frame[40:]) != control ||
		binary.LittleEndian.Uint32(frame[44:]) != channel ||
		binary.LittleEndian.Uint32(frame[48:]) != 0 {
		t.Fatalf("speaker control payload = %x", frame[40:])
	}
}

type captureWriter struct {
	data [][]byte
}

func (w *captureWriter) Write(data []byte) (int, error) {
	w.data = append(w.data, append([]byte(nil), data...))
	return len(data), nil
}

type loginWriteOutcome struct {
	err   error
	short bool
}

type loginTestWriter struct {
	mu       sync.Mutex
	writes   [][]byte
	outcomes []loginWriteOutcome
	calls    chan struct{}
	blockAt  int
	blocked  chan struct{}
	release  chan struct{}
}

func (w *loginTestWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	index := len(w.writes)
	w.writes = append(w.writes, append([]byte(nil), data...))
	var outcome loginWriteOutcome
	if index < len(w.outcomes) {
		outcome = w.outcomes[index]
	}
	block := index == w.blockAt
	w.mu.Unlock()

	w.calls <- struct{}{}
	if block {
		w.blocked <- struct{}{}
		<-w.release
	}
	if outcome.err != nil {
		return 0, outcome.err
	}
	if outcome.short {
		return len(data) - 1, nil
	}
	return len(data), nil
}

func (w *loginTestWriter) setOutcomes(outcomes []loginWriteOutcome) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.outcomes = outcomes
}

func (w *loginTestWriter) blockWrite(index int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.blockAt = index
}

func (w *loginTestWriter) releaseBlockedWrite() {
	select {
	case w.release <- struct{}{}:
	default:
	}
}

func (w *loginTestWriter) snapshot() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	writes := make([][]byte, len(w.writes))
	for i, data := range w.writes {
		writes[i] = append([]byte(nil), data...)
	}
	return writes
}

func newLoginTestConn(t *testing.T) (*DTLSConn, *loginTestWriter, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	writer := &loginTestWriter{
		calls:   make(chan struct{}, 8),
		blockAt: -1,
		blocked: make(chan struct{}, 1),
		release: make(chan struct{}, 1),
	}
	c := configuredTestConn(Options{}, "")
	c.ctx = ctx
	c.cancel = cancel
	c.rawCmd = make(chan []byte, 8)
	c.clientWriter = writer
	t.Cleanup(func() {
		cancel()
		writer.releaseBlockedWrite()
		c.wg.Wait()
	})
	return c, writer, cancel
}

func avLoginResponse(result, advertisement byte) []byte {
	response := make([]byte, 32)
	binary.LittleEndian.PutUint16(response, magicAVLoginResp)
	response[24] = result
	response[31] = advertisement
	return response
}

func assertSuccessfulLoginWrites(t *testing.T, writer *loginTestWriter) {
	t.Helper()
	writes := writer.snapshot()
	if len(writes) < 3 {
		t.Fatalf("successful login writes = %d, want two requests and an ACK", len(writes))
	}
	if binary.LittleEndian.Uint16(writes[0]) != magicAVLogin1 ||
		binary.LittleEndian.Uint16(writes[1]) != magicAVLogin2 ||
		binary.LittleEndian.Uint16(writes[2]) != magicACK {
		t.Fatal("successful login did not write both requests followed by an ACK")
	}
}

func newMemoryDTLSPair(t *testing.T) (*piondtls.Conn, *piondtls.Conn) {
	t.Helper()
	clientPipe, serverPipe := dpipe.Pipe()
	var clientConn, serverConn *piondtls.Conn
	t.Cleanup(func() {
		if clientConn != nil {
			_ = clientConn.Close()
		}
		if serverConn != nil {
			_ = serverConn.Close()
		}
		_ = clientPipe.Close()
		_ = serverPipe.Close()
	})

	psk := []byte("worker-test-psk")
	clientConfig := buildDTLSConfigWithIdentity(psk, "worker-test-identity", false)
	clientConfig.CustomCipherSuites = nil
	clientConfig.CipherSuites = []piondtls.CipherSuiteID{piondtls.TLS_PSK_WITH_AES_128_CBC_SHA256}
	clientConn, err := piondtls.Client(
		dtlsnet.PacketConnFromConn(clientPipe),
		clientPipe.RemoteAddr(),
		clientConfig,
	)
	if err != nil {
		t.Fatalf("create in-memory DTLS client: %v", err)
	}
	serverConn, err = piondtls.Server(
		dtlsnet.PacketConnFromConn(serverPipe),
		serverPipe.RemoteAddr(),
		buildDTLSConfigWithIdentity(psk, "worker-test-identity", true),
	)
	if err != nil {
		t.Fatalf("create in-memory DTLS server: %v", err)
	}

	handshakeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverHandshake := make(chan error, 1)
	go func() {
		serverHandshake <- serverConn.HandshakeContext(handshakeCtx)
	}()
	if err = clientConn.HandshakeContext(handshakeCtx); err != nil {
		t.Fatalf("in-memory DTLS client handshake: %v", err)
	}
	select {
	case err = <-serverHandshake:
		if err != nil {
			t.Fatalf("in-memory DTLS server handshake: %v", err)
		}
	case <-handshakeCtx.Done():
		t.Fatal("in-memory DTLS server handshake timed out")
	}
	return clientConn, serverConn
}

func startLoginAndWaitForRequests(t *testing.T, c *DTLSConn, writer *loginTestWriter) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- c.AVClientStart(time.Second)
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-writer.calls:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for AV login write")
		}
	}
	return done
}

func awaitLoginResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for AV login result")
		return nil
	}
}

func completeLoginWithResponse(t *testing.T, c *DTLSConn, writer *loginTestWriter, response []byte) error {
	t.Helper()
	done := startLoginAndWaitForRequests(t, c, writer)
	c.rawCmd <- response
	return awaitLoginResult(t, done)
}

func paddedTestField(value string, size int) []byte {
	field := make([]byte, size)
	copy(field, value)
	return field
}
