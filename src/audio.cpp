#include "hlekit/audio.h"

#include <SDL2/SDL.h>

#include <chrono>
#include <cstdio>
#include <mutex>

namespace hlekit {

namespace {

class SdlSink : public AudioSink {
public:
    ~SdlSink() override { Close(); }
    bool Open(int rate, int channels, int bits) override {
        if (SDL_InitSubSystem(SDL_INIT_AUDIO) != 0) return false;
        SDL_AudioSpec want{}, have{};
        want.freq = rate;
        want.format = bits == 16 ? AUDIO_S16LSB : AUDIO_U8;
        want.channels = (Uint8)channels;
        want.samples = 512;
        dev_ = SDL_OpenAudioDevice(nullptr, 0, &want, &have, 0);   // SDL converts to the device
        if (!dev_) return false;
        bytesPerSecond_ = rate * channels * (bits / 8);
        SDL_PauseAudioDevice(dev_, 0);
        return true;
    }
    void Queue(const uint8_t* pcm, size_t n) override { if (dev_) SDL_QueueAudio(dev_, pcm, (Uint32)n); }
    double QueuedSeconds() override { return dev_ ? (double)SDL_GetQueuedAudioSize(dev_) / bytesPerSecond_ : 0; }
    void Close() override {
        if (dev_) SDL_CloseAudioDevice(dev_);
        dev_ = 0;
    }
private:
    SDL_AudioDeviceID dev_ = 0;
    int bytesPerSecond_ = 1;
};

class ClockSink : public AudioSink {
public:
    bool Open(int rate, int channels, int bits) override {
        bytesPerSecond_ = rate * channels * (bits / 8);
        start_ = Now();
        queued_ = 0;
        return true;
    }
    void Queue(const uint8_t*, size_t n) override {
        std::lock_guard<std::mutex> lock(m_);
        const double played = Now() - start_;
        if (played > queued_) start_ = Now() - queued_;      // underrun: the device idled
        queued_ += (double)n / bytesPerSecond_;
    }
    double QueuedSeconds() override {
        std::lock_guard<std::mutex> lock(m_);
        double left = queued_ - (Now() - start_);
        return left > 0 ? left : 0;
    }
    void Close() override {}
private:
    static double Now() { return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
    std::mutex m_;
    int bytesPerSecond_ = 1;
    double start_ = 0, queued_ = 0;
};

class WavTee : public AudioSink {
public:
    WavTee(std::unique_ptr<AudioSink> inner, std::string path) : inner_(std::move(inner)), path_(std::move(path)) {}
    ~WavTee() override { Close(); }
    bool Open(int rate, int channels, int bits) override {
        rate_ = rate;
        channels_ = channels;
        bits_ = bits;
        f_ = fopen(path_.c_str(), "wb");
        if (f_) fwrite(Header(0).data(), 1, 44, f_);
        return inner_->Open(rate, channels, bits);
    }
    void Queue(const uint8_t* pcm, size_t n) override {
        if (f_) { fwrite(pcm, 1, n, f_); bytes_ += (uint32_t)n; }
        inner_->Queue(pcm, n);
    }
    double QueuedSeconds() override { return inner_->QueuedSeconds(); }
    void Close() override {
        if (f_) {
            fseek(f_, 0, SEEK_SET);
            fwrite(Header(bytes_).data(), 1, 44, f_);
            fclose(f_);
            f_ = nullptr;
        }
        inner_->Close();
    }
private:
    std::string Header(uint32_t n) {
        auto u32 = [](uint32_t v) { return std::string{(char)v, (char)(v >> 8), (char)(v >> 16), (char)(v >> 24)}; };
        auto u16 = [](uint16_t v) { return std::string{(char)v, (char)(v >> 8)}; };
        const uint16_t align = (uint16_t)(channels_ * bits_ / 8);
        return "RIFF" + u32(36 + n) + "WAVEfmt " + u32(16) + u16(1) + u16((uint16_t)channels_) + u32(rate_) +
               u32(rate_ * align) + u16(align) + u16((uint16_t)bits_) + "data" + u32(n);
    }
    std::unique_ptr<AudioSink> inner_;
    std::string path_;
    FILE* f_ = nullptr;
    uint32_t bytes_ = 0;
    int rate_ = 1, channels_ = 1, bits_ = 8;
};

}  // namespace

std::unique_ptr<AudioSink> MakeSdlSink() { return std::make_unique<SdlSink>(); }
std::unique_ptr<AudioSink> MakeClockSink() { return std::make_unique<ClockSink>(); }
std::unique_ptr<AudioSink> MakeWavTee(std::unique_ptr<AudioSink> inner, const std::string& path) {
    return std::make_unique<WavTee>(std::move(inner), path);
}

}  // namespace hlekit
