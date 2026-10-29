// Exercise the real process/IPC boundary with deterministic driver failures. No audio server,
// SoundFont, game data, or real SDL initialization is needed.
#include "host_audio.h"
#include <SDL2/SDL.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/wait.h>
#include <unistd.h>

namespace {
const char* mode;
int midiEvents = 0;
bool Is(const char* name) { return strcmp(mode, name) == 0; }
[[noreturn]] void Hang() { for (;;) pause(); }
void Check(bool ok, const char* why) {
    if (!ok) { fprintf(stderr, "%s\n", why); exit(1); }
}

class Sink final : public hlekit::AudioSink {
public:
    explicit Sink(bool silent) : silent_(silent) {}
    ~Sink() override { if (!silent_ && Is("shutdown-timeout")) Hang(); }
    bool Open(int rate, int channels, int bits) override {
        if (!silent_ && Is("open-timeout")) Hang();
        Check(rate == 44100 && channels == 2 && bits == 16, "sample format lost over IPC");
        return silent_ || !Is("open-failure");
    }
    void Queue(const uint8_t* pcm, size_t bytes) override {
        if (!silent_ && Is("backpressure")) Hang();
        if (!silent_) {
            for (size_t i = 0; i < bytes; ++i) Check(pcm[i] == 42, "PCM payload corrupted");
            bytes_ += bytes;
        }
    }
    double QueuedSeconds() override {
        if (silent_) return 0.25;
        if (Is("query-timeout")) Hang();
        return bytes_ / 176400.0 + midiEvents;
    }
    void Close() override { bytes_ = 0; }
private:
    bool silent_;
    size_t bytes_ = 0;
};

class Midi final : public hlekit::MidiOut {
public:
    void Short(uint8_t status, uint8_t d1, uint8_t d2) override {
        if (Is("worker-crash")) _exit(17);
        Check(status == 0x90 && d1 == 60 && d2 == 100, "MIDI message corrupted");
        ++midiEvents;
    }
    void Sysex(const uint8_t* data, size_t bytes) override {
        Check(bytes == 3 && data[0] == 1 && data[1] == 2 && data[2] == 3, "SysEx payload corrupted");
        ++midiEvents;
    }
    void Reset() override { ++midiEvents; }
};
}  // namespace

extern "C" int SDL_InitSubSystem(Uint32 flags) {
    Check(flags == SDL_INIT_AUDIO, "worker initialized more than audio");
    if (Is("init-timeout")) Hang();
    return Is("init-failure") ? -1 : 0;
}
extern "C" const char* SDL_GetError() { return "injected audio failure"; }
extern "C" void SDL_QuitSubSystem(Uint32) {}

namespace hlekit {
std::unique_ptr<AudioSink> MakeSdlSink() { return std::make_unique<Sink>(false); }
std::unique_ptr<AudioSink> MakeClockSink() { return std::make_unique<Sink>(true); }
std::unique_ptr<MidiOut> MakeFluidSynth(const std::string& soundFont, std::string& err) {
    Check(soundFont == "test.sf2", "SoundFont path lost");
    if (Is("no-midi")) { err = "no test MIDI"; return nullptr; }
    return std::make_unique<Midi>();
}
}  // namespace hlekit

int main(int argc, char** argv) {
    Check(argc == 2, "expected test mode");
    mode = argv[1];
    const auto start = std::chrono::steady_clock::now();
    {
        auto audio = hlekit::MakeHostAudio("test.sf2");
        Check(audio.samples != nullptr, "missing silent fallback");
        const bool failedInit = Is("init-timeout") || Is("init-failure");
        Check(bool(audio.midi) == (!failedInit && !Is("no-midi")), "wrong MIDI availability");
        Check(audio.samples->Open(44100, 2, 16), "silent sample fallback did not open");
        if (failedInit || Is("open-timeout") || Is("open-failure") || Is("query-timeout")) {
            Check(audio.samples->QueuedSeconds() == 0.25, "audio failure did not fall back to clock sink");
        } else if (Is("worker-crash")) {
            audio.midi->Short(0x90, 60, 100);
            Check(audio.samples->QueuedSeconds() == 0.25, "worker crash did not fall back");
            audio.midi->Reset();  // Must be harmless after worker failure.
        } else if (Is("backpressure")) {
            uint8_t pcm[60 * 1024] = {};
            // A stopped consumer must not block the guest once the IPC buffer fills.
            for (int i = 0; i < 128; ++i) audio.samples->Queue(pcm, sizeof(pcm));
            Check(audio.samples->QueuedSeconds() == 0.25, "full worker socket did not fall back");
            Check(std::chrono::steady_clock::now() - start < std::chrono::seconds(1), "PCM send blocked");
        } else {
            // Exceeds a single IPC packet to exercise PCM splitting and ordered MIDI delivery.
            uint8_t pcm[70 * 1024];
            memset(pcm, 42, sizeof(pcm));
            audio.samples->Queue(pcm, sizeof(pcm));
            if (audio.midi) {
                audio.midi->Short(0x90, 60, 100);
                const uint8_t sysex[] = {1, 2, 3};
                audio.midi->Sysex(sysex, sizeof(sysex));
                audio.midi->Reset();
            }
            Check(audio.samples->QueuedSeconds() == sizeof(pcm) / 176400.0 + (audio.midi ? 3 : 0),
                  "PCM queue length or MIDI ordering lost over IPC");
            audio.samples->Close();
        }
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    Check(elapsed < std::chrono::seconds(5), "audio failure or shutdown blocked the runner");
    if (Is("init-timeout") || Is("open-timeout") || Is("query-timeout"))
        Check(elapsed >= std::chrono::seconds(3), "timeout test did not exercise hung driver");
    errno = 0;
    Check(waitpid(-1, nullptr, WNOHANG) == -1 && errno == ECHILD, "audio worker was not reaped");
    return 0;
}
