// Host audio for sound seams: the game's own mixer fills buffers in guest memory; the seam hands
// each one to a sink at the moment the original DMA would have started it.
//
// Formats: 8-bit unsigned or 16-bit signed little endian, mono or interleaved stereo.
#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace hlekit {

class AudioSink {
public:
    virtual ~AudioSink() = default;
    virtual bool Open(int rate, int channels, int bits) = 0;
    virtual void Queue(const uint8_t* pcm, size_t bytes) = 0;
    virtual double QueuedSeconds() = 0;                     // still to be played
    virtual void Close() = 0;
};

std::unique_ptr<AudioSink> MakeSdlSink();                   // the default audio device
std::unique_ptr<AudioSink> MakeClockSink();                 // silent, consumes in real time (headless)

// Tee: everything queued is also written to a WAV file.
std::unique_ptr<AudioSink> MakeWavTee(std::unique_ptr<AudioSink> inner, const std::string& path);

}  // namespace hlekit
