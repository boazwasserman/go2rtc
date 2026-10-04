package jooan

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/pion/rtp"
)

type fakeSession struct {
	mu          sync.Mutex
	starts      int
	stops       int
	closes      int
	timestamps  []uint32
	frames      [][]byte
	channels    []uint32
	ready       bool
	startErr    error
	sendErr     error
	stopErr     error
	closeErr    error
	terminalErr error
	done        chan struct{}
	doneOnce    sync.Once
	startCh     chan struct{}
}

func (s *fakeSession) AVClientStart(time.Duration) error { return nil }
func (s *fakeSession) HasTwoWayStreaming() bool          { return s.ready }
func (s *fakeSession) Done() <-chan struct{}             { return s.done }
func (s *fakeSession) Error() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminalErr
}
func (s *fakeSession) AVTwoWayStart(channel uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts++
	s.channels = append(s.channels, channel)
	if s.startCh != nil {
		close(s.startCh)
		s.startCh = nil
	}
	return s.startErr
}
func (s *fakeSession) AVTwoWayStop(channel uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stops++
	s.channels = append(s.channels, channel)
	return s.stopErr
}
func (s *fakeSession) AVSendAudioDataTwoWay(_ byte, payload []byte, timestamp, _ uint32, _ uint8) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timestamps = append(s.timestamps, timestamp)
	s.frames = append(s.frames, append([]byte(nil), payload...))
	return s.sendErr
}
func (s *fakeSession) Close() error {
	s.mu.Lock()
	s.closes++
	err := s.closeErr
	done := s.done
	s.mu.Unlock()
	s.doneOnce.Do(func() { close(done) })
	return err
}

func (s *fakeSession) terminate(err error) {
	s.mu.Lock()
	if s.terminalErr == nil {
		s.terminalErr = err
	}
	done := s.done
	s.mu.Unlock()
	s.doneOnce.Do(func() { close(done) })
}

func testProducer(t *testing.T, session *fakeSession) *Producer {
	t.Helper()
	session.mu.Lock()
	if session.done == nil {
		session.done = make(chan struct{})
	}
	session.mu.Unlock()
	p, err := newProducerWithSession(Config{Host: "192.0.2.10", UID: "synthetic", Username: "admin", Password: "secret"}, session)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProducerFramesExactSizeAndPreservesLeftovers(t *testing.T) {
	session := &fakeSession{ready: true}
	p := testProducer(t, session)
	media := p.Medias[0]
	track := core.NewReceiver(media, media.Codecs[0])
	if err := p.AddTrack(media, media.Codecs[0], track); err != nil {
		t.Fatal(err)
	}

	track.WriteRTP(&rtp.Packet{Payload: make([]byte, 639)})
	track.WriteRTP(&rtp.Packet{Payload: []byte{7, 8}})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		session.mu.Lock()
		ready := len(session.frames) == 1
		session.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(time.Millisecond)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.frames) != 1 || len(session.frames[0]) != AudioFrameBytes {
		t.Fatalf("frames = %d, size = %d", len(session.frames), len(session.frames[0]))
	}
	if session.frames[0][639] != 7 {
		t.Fatalf("first frame did not preserve payload order")
	}
	if len(p.frameBuf) != 1 {
		t.Fatalf("leftover = %d, want 1", len(p.frameBuf))
	}
	if session.timestamps[0] != 0 {
		t.Fatalf("timestamp = %d, want 0", session.timestamps[0])
	}
}

func TestProducerAdvertisesOnlyPCMU16KMonoSendonly(t *testing.T) {
	session := &fakeSession{ready: true}
	p := testProducer(t, session)
	if len(p.Medias) != 1 {
		t.Fatalf("media count = %d, want 1", len(p.Medias))
	}
	media := p.Medias[0]
	if media.Kind != core.KindAudio || media.Direction != core.DirectionSendonly || len(media.Codecs) != 1 {
		t.Fatalf("media = %+v", media)
	}
	codec := media.Codecs[0]
	if codec.Name != core.CodecPCMU || codec.ClockRate != AudioSampleRate || codec.Channels != AudioChannels {
		t.Fatalf("codec = %+v", codec)
	}
}

func TestConfigJSONDoesNotExposeCredentials(t *testing.T) {
	data, err := json.Marshal(Config{
		Host: "192.0.2.10", UID: "synthetic-uid", Username: "synthetic-user", Password: "synthetic-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "synthetic-uid") ||
		strings.Contains(string(data), "synthetic-user") ||
		strings.Contains(string(data), "synthetic-secret") {
		t.Fatalf("config JSON exposed credentials: %s", data)
	}
}

func TestProducerSpeakerLifecycleIsSerializedAndIdempotent(t *testing.T) {
	session := &fakeSession{ready: true}
	p := testProducer(t, session)
	if err := p.AddTrack(p.Medias[0], p.Medias[0].Codecs[0], core.NewReceiver(p.Medias[0], p.Medias[0].Codecs[0])); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.starts != 1 || session.stops != 1 || session.closes != 1 {
		t.Fatalf("lifecycle = starts %d, stops %d, closes %d", session.starts, session.stops, session.closes)
	}
	if len(session.channels) != 2 || session.channels[0] != SpeakerChannel || session.channels[1] != SpeakerChannel {
		t.Fatalf("channels = %v, want [%d %d]", session.channels, SpeakerChannel, SpeakerChannel)
	}
}

func TestProducerRejectsSecondSenderAndIgnoresAudioBeforeStart(t *testing.T) {
	session := &fakeSession{ready: true}
	p := testProducer(t, session)
	p.write(make([]byte, AudioFrameBytes))
	session.mu.Lock()
	if len(session.frames) != 0 {
		t.Fatal("audio was sent before speaker start")
	}
	session.mu.Unlock()

	media := p.Medias[0]
	track := core.NewReceiver(media, media.Codecs[0])
	if err := p.AddTrack(media, media.Codecs[0], track); err != nil {
		t.Fatal(err)
	}
	if err := p.AddTrack(media, media.Codecs[0], core.NewReceiver(media, media.Codecs[0])); err == nil {
		t.Fatal("second sender attachment succeeded")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.starts != 1 {
		t.Fatalf("speaker starts = %d, want 1", session.starts)
	}
}

func TestProducerUsesConfiguredSpeakerChannel(t *testing.T) {
	session := &fakeSession{ready: true, done: make(chan struct{})}
	p, err := newProducerWithSession(Config{
		Host: "192.0.2.10", UID: "synthetic", Username: "admin", Password: "secret",
		SpeakerChannel: 3,
	}, session)
	if err != nil {
		t.Fatal(err)
	}
	media := p.Medias[0]
	if err := p.AddTrack(media, media.Codecs[0], core.NewReceiver(media, media.Codecs[0])); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.channels) != 2 || session.channels[0] != 3 || session.channels[1] != 3 {
		t.Fatalf("channels = %v, want [3 3]", session.channels)
	}
}

func TestProducerSendFailureStopsSpeakerAndTransport(t *testing.T) {
	session := &fakeSession{ready: true, sendErr: errors.New("synthetic send failure")}
	p := testProducer(t, session)
	media := p.Medias[0]
	if err := p.AddTrack(media, media.Codecs[0], core.NewReceiver(media, media.Codecs[0])); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan struct{})
	go func() {
		p.write(make([]byte, AudioFrameBytes))
		close(writeDone)
	}()
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("send failure cleanup deadlocked")
	}
	if err := p.Start(); err == nil || !strings.Contains(err.Error(), "synthetic send failure") {
		t.Fatalf("Start error = %v", err)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.stops != 1 || session.closes != 1 {
		t.Fatalf("cleanup = stops %d, closes %d", session.stops, session.closes)
	}
}

func TestProducerStopsWhenSessionTerminatesWithoutFurtherAudio(t *testing.T) {
	session := &fakeSession{ready: true}
	p := testProducer(t, session)
	startDone := startProducer(p)
	cause := errors.New("synthetic periodic ACK failure")
	session.terminate(cause)

	err := awaitProducerStart(t, startDone)
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "session terminated") {
		t.Fatalf("Start error = %v, want explicit session failure", err)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closes != 1 || session.stops != 0 {
		t.Fatalf("cleanup without active speaker = stops %d, closes %d", session.stops, session.closes)
	}
}

func TestProducerReportsEOFForSessionTerminationWithoutError(t *testing.T) {
	session := &fakeSession{ready: true}
	p := testProducer(t, session)
	startDone := startProducer(p)
	session.terminate(nil)

	if err := awaitProducerStart(t, startDone); !errors.Is(err, io.EOF) {
		t.Fatalf("Start error = %v, want explicit EOF", err)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closes != 1 {
		t.Fatalf("session closes = %d, want 1", session.closes)
	}
}

func TestProducerSessionFailureStopsActiveAudioAndJoinsCleanupErrors(t *testing.T) {
	session := &fakeSession{
		ready:    true,
		stopErr:  errors.New("synthetic speaker stop failure"),
		closeErr: errors.New("synthetic session close failure"),
	}
	p := testProducer(t, session)
	media := p.Medias[0]
	if err := p.AddTrack(media, media.Codecs[0], core.NewReceiver(media, media.Codecs[0])); err != nil {
		t.Fatal(err)
	}

	startDone := startProducer(p)
	cause := errors.New("synthetic periodic ACK failure")
	session.terminate(cause)
	err := awaitProducerStart(t, startDone)
	if !errors.Is(err, cause) || !errors.Is(err, session.stopErr) || !errors.Is(err, session.closeErr) {
		t.Fatalf("Start error = %v, want session and cleanup causes", err)
	}

	p.write(make([]byte, AudioFrameBytes))
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.starts != 1 || session.stops != 1 || session.closes != 1 || len(session.frames) != 0 {
		t.Fatalf("active-session cleanup = starts %d stops %d closes %d frames %d",
			session.starts, session.stops, session.closes, len(session.frames))
	}
}

func TestProducerNormalStopWinsWhenSessionAndProducerAreDone(t *testing.T) {
	p := testProducer(t, &fakeSession{ready: true})
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start after normal Stop = %v, want normal result", err)
	}
}

func TestProducerTimestampsAdvanceMonotonically(t *testing.T) {
	session := &fakeSession{ready: true}
	p := testProducer(t, session)
	media := p.Medias[0]
	if err := p.AddTrack(media, media.Codecs[0], core.NewReceiver(media, media.Codecs[0])); err != nil {
		t.Fatal(err)
	}
	p.write(make([]byte, AudioFrameBytes*3))
	session.mu.Lock()
	defer session.mu.Unlock()
	want := []uint32{0, 40, 80}
	if len(session.timestamps) != len(want) {
		t.Fatalf("timestamps = %v, want %v", session.timestamps, want)
	}
	for i := range want {
		if session.timestamps[i] != want[i] {
			t.Fatalf("timestamps = %v, want %v", session.timestamps, want)
		}
	}
}

func TestProducerRejectsMissingTwoWayCapability(t *testing.T) {
	_, err := newProducerWithSession(Config{}, &fakeSession{})
	if !errors.Is(err, ErrNoTwoWay) {
		t.Fatalf("error = %v, want %v", err, ErrNoTwoWay)
	}
}

func startProducer(p *Producer) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- p.Start()
	}()
	return done
}

func awaitProducerStart(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("Producer.Start did not return after session termination")
		return nil
	}
}
