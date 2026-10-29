#include "host_audio.h"

#include <SDL2/SDL.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

#ifdef __linux__
#include <cerrno>
#include <chrono>
#include <csignal>
#include <mutex>
#include <poll.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace hlekit {

#ifdef __linux__
namespace {

constexpr auto kTimeout = std::chrono::seconds(3);
constexpr size_t kPayload = 60 * 1024;
enum class Op { Ready, Open, Queue, Queued, Close, Short, Sysex, Reset };
struct Message {
    Op op{};
    int a = 0, b = 0, c = 0;
    double seconds = 0;
};

// SOCK_SEQPACKET preserves message boundaries. Nonblocking sends prevent a stuck worker
// from eventually blocking the guest when the socket buffer fills. No SIGPIPE on worker exit.
bool Send(int fd, const Message& msg, const uint8_t* data = nullptr, size_t bytes = 0) {
    if (bytes > kPayload) return false;
    iovec parts[] = {{const_cast<Message*>(&msg), sizeof(msg)}, {const_cast<uint8_t*>(data), bytes}};
    msghdr packet{};
    packet.msg_iov = parts;
    packet.msg_iovlen = bytes ? 2 : 1;
    ssize_t sent;
    do { sent = sendmsg(fd, &packet, MSG_DONTWAIT | MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
    return sent == static_cast<ssize_t>(sizeof(msg) + bytes);
}

void Serve(int fd, const std::string& soundFont) {
    // The guest JIT installs fault handlers before frontend audio startup; the audio child
    // must not inherit handlers that attempt to interpret its faults as guest memory writes.
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    Message ready{Op::Ready};
    if (SDL_InitSubSystem(SDL_INIT_AUDIO) != 0) {
        const char* error = SDL_GetError();
        Send(fd, ready, reinterpret_cast<const uint8_t*>(error), strlen(error));
        return;
    }
    auto samples = MakeSdlSink();
    std::string err;
    auto midi = MakeFluidSynth(soundFont, err);
    if (!midi) fprintf(stderr, "note: no MIDI music (%s)\n", err.c_str());
    ready.a = 1;
    ready.b = midi != nullptr;
    if (!Send(fd, ready)) return;

    alignas(Message) uint8_t packet[sizeof(Message) + kPayload];
    for (;;) {
        ssize_t bytes;
        do { bytes = recv(fd, packet, sizeof(packet), 0); } while (bytes < 0 && errno == EINTR);
        if (bytes < static_cast<ssize_t>(sizeof(Message))) break;
        Message msg;
        memcpy(&msg, packet, sizeof(msg));
        const uint8_t* data = packet + sizeof(msg);
        const size_t size = bytes - sizeof(msg);
        switch (msg.op) {
        case Op::Open:
            samples->Close();
            msg.a = samples->Open(msg.a, msg.b, msg.c);
            if (!msg.a) fprintf(stderr, "note: no sample audio (%s); continuing silently\n", SDL_GetError());
            if (!Send(fd, msg)) return;
            break;
        case Op::Queue: samples->Queue(data, size); break;
        case Op::Queued:
            msg.seconds = samples->QueuedSeconds();
            if (!Send(fd, msg)) return;
            break;
        case Op::Close: samples->Close(); break;
        case Op::Short:
            if (midi) midi->Short(msg.a, msg.b, msg.c);
            break;
        case Op::Sysex:
            if (midi) midi->Sysex(data, size);
            break;
        case Op::Reset:
            if (midi) midi->Reset();
            break;
        default: return;
        }
    }
    // This cleanup may itself block in a broken driver. The parent bounds child shutdown too.
    midi.reset();
    samples.reset();
    SDL_QuitSubSystem(SDL_INIT_AUDIO);
}

class Worker {
public:
    Worker(int fd, pid_t pid) : fd_(fd), pid_(pid) {}
    ~Worker() { Stop(); }

    bool SendMessage(const Message& msg, const uint8_t* data = nullptr, size_t bytes = 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fd_ < 0) return false;
        if (Send(fd_, msg, data, bytes)) return true;
        Fail("audio worker disconnected or stopped accepting data");
        return false;
    }

    bool Request(Message& msg, std::string* error = nullptr, bool startup = false) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fd_ < 0) return false;
        if (!startup && !Send(fd_, msg)) {
            Fail("audio worker disconnected or stopped accepting data");
            return false;
        }
        const auto deadline = std::chrono::steady_clock::now() + kTimeout;
        for (;;) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0) {
                Fail(startup ? "audio initialization timed out after 3 seconds" : "audio device timed out after 3 seconds");
                return false;
            }
            pollfd pfd{fd_, POLLIN, 0};
            const int result = poll(&pfd, 1, static_cast<int>(left));
            if (result < 0 && errno == EINTR) continue;
            if (result < 0) { Fail("cannot wait for audio worker"); return false; }
            if (!result) continue;
            uint8_t packet[sizeof(Message) + kPayload];
            const ssize_t bytes = recv(fd_, packet, sizeof(packet), MSG_DONTWAIT);
            if (bytes < static_cast<ssize_t>(sizeof(Message))) {
                Fail("audio worker exited without a reply");
                return false;
            }
            memcpy(&msg, packet, sizeof(msg));
            if (error) error->assign(reinterpret_cast<const char*>(packet + sizeof(msg)), bytes - sizeof(msg));
            return true;
        }
    }

private:
    void Fail(const char* why) {
        fprintf(stderr, "note: %s; continuing without host audio\n", why);
        Stop();
    }

    void Stop() {
        if (fd_ >= 0) { close(fd_); fd_ = -1; }
        if (pid_ <= 0) return;
        // Allow ordinary device cleanup, but never join a driver that is stuck on shutdown.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
        for (;;) {
            const pid_t result = waitpid(pid_, nullptr, WNOHANG);
            if (result == pid_ || (result < 0 && errno == ECHILD)) break;
            if (std::chrono::steady_clock::now() >= deadline) {
                kill(pid_, SIGKILL);
                // Give SIGKILL time to take effect and reap without an unbounded wait if
                // the kernel keeps a device operation in uninterruptible sleep.
                const auto killedDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
                while (waitpid(pid_, nullptr, WNOHANG) == 0 && std::chrono::steady_clock::now() < killedDeadline)
                    poll(nullptr, 0, 1);
                break;
            }
            poll(nullptr, 0, 5);
        }
        pid_ = -1;
    }

    int fd_;
    pid_t pid_;
    std::mutex mutex_;
};

class WorkerSink final : public AudioSink {
public:
    explicit WorkerSink(std::shared_ptr<Worker> worker) : worker_(std::move(worker)), clock_(MakeClockSink()) {}
    bool Open(int rate, int channels, int bits) override {
        clock_->Open(rate, channels, bits);
        Message msg{Op::Open, rate, channels, bits};
        audible_ = worker_->Request(msg) && msg.a;
        return true;
    }
    void Queue(const uint8_t* pcm, size_t bytes) override {
        clock_->Queue(pcm, bytes);
        while (audible_ && bytes) {
            const size_t n = std::min(bytes, kPayload);
            audible_ = worker_->SendMessage({Op::Queue}, pcm, n);
            pcm += n;
            bytes -= n;
        }
    }
    double QueuedSeconds() override {
        Message msg{Op::Queued};
        if (audible_ && worker_->Request(msg)) return msg.seconds;
        audible_ = false;
        return clock_->QueuedSeconds();
    }
    void Close() override {
        if (audible_) worker_->SendMessage({Op::Close});
        audible_ = false;
        clock_->Close();
    }
private:
    std::shared_ptr<Worker> worker_;
    std::unique_ptr<AudioSink> clock_;
    bool audible_ = false;
};

class WorkerMidi final : public MidiOut {
public:
    explicit WorkerMidi(std::shared_ptr<Worker> worker) : worker_(std::move(worker)) {}
    void Short(uint8_t status, uint8_t d1, uint8_t d2) override { worker_->SendMessage({Op::Short, status, d1, d2}); }
    void Sysex(const uint8_t* data, size_t bytes) override { worker_->SendMessage({Op::Sysex}, data, bytes); }
    void Reset() override { worker_->SendMessage({Op::Reset}); }
private:
    std::shared_ptr<Worker> worker_;
};

}  // namespace
#endif

HostAudio MakeHostAudio(const std::string& soundFont) {
#ifdef __linux__
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) {
        fprintf(stderr, "note: cannot create audio worker socket (%s); continuing without host audio\n", strerror(errno));
        return {MakeClockSink(), nullptr};
    }
    const pid_t parent = getpid();
    const pid_t pid = fork();
    if (pid == 0) {
        // Also stop a hung driver if the runner crashes or is killed before its timeout.
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent) _exit(1);
        close(sockets[0]);
        Serve(sockets[1], soundFont);
        close(sockets[1]);
        _exit(0);
    }
    close(sockets[1]);
    if (pid < 0) {
        close(sockets[0]);
        fprintf(stderr, "note: cannot start audio worker (%s); continuing without host audio\n", strerror(errno));
        return {MakeClockSink(), nullptr};
    }
    auto worker = std::make_shared<Worker>(sockets[0], pid);
    Message ready;
    std::string err;
    if (!worker->Request(ready, &err, true)) return {MakeClockSink(), nullptr};
    if (!ready.a) {
        fprintf(stderr, "note: audio initialization failed (%s); continuing without host audio\n", err.c_str());
        return {MakeClockSink(), nullptr};
    }
    HostAudio out{std::make_unique<WorkerSink>(worker), nullptr};
    if (ready.b) out.midi = std::make_unique<WorkerMidi>(worker);
    return out;
#else
    std::string err;
    auto midi = MakeFluidSynth(soundFont, err);
    if (!midi) fprintf(stderr, "note: no MIDI music (%s)\n", err.c_str());
    return {MakeSdlSink(), std::move(midi)};
#endif
}

}  // namespace hlekit
