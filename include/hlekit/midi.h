// Host MIDI for music seams: a General MIDI synthesizer (FluidSynth and a SoundFont, rendered in
// its own SDL audio callback) and a Miles XMIDI sequencer that plays a game's .XMI data on host
// time. A game's music driver API (e.g. Miles AIL's XMI_* functions) is answered natively on top
// of these; no sound card, MPU-401 or OPL is involved.
#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace hlekit {

class MidiOut {
public:
    virtual ~MidiOut() = default;
    virtual void Short(uint8_t status, uint8_t d1, uint8_t d2) = 0;   // any channel message
    virtual void Sysex(const uint8_t* data, size_t bytes) = 0;        // without the F0/F7 framing
    virtual void Reset() = 0;                                          // all notes and controllers
};

// FluidSynth on the default audio device; nullptr (and `err`) when unavailable. An empty
// `soundFont` tries HLEKIT_SOUNDFONT, then SOUNDFONT. The kit has no built-in SoundFont path.
std::unique_ptr<MidiOut> MakeFluidSynth(const std::string& soundFont, std::string& err);

// Miles XMIDI: an XMIDI file (FORM XDIR + CAT XMID, or one FORM XMID) holds sequences of
// 120 Hz events with note durations, FOR/NEXT loops (controllers 116/117), branch points
// (RBRN chunk, controller 120) and tempo/time-signature meta events for beat and measure counts.
class XmiPlayer {
public:
    enum Status { kStopped = 0, kPlaying = 1, kDone = 2 };
    explicit XmiPlayer(MidiOut* out) : out_(out) {}
    void SetOut(MidiOut* out) { out_ = out; }

    // The IFF size of an XMIDI file starting at `data` (0 if it is not one); `avail` bounds reads.
    static size_t FileSize(const uint8_t* data, size_t avail);
    int Register(const uint8_t* file, size_t bytes, int sequence);    // a handle, or -1
    void Release(int h);
    void Start(int h);                                                 // from the beginning
    void Stop(int h);                                                  // silence; Resume continues
    void Resume(int h);
    int StatusOf(int h) const;
    void RelativeVolume(int h, int percent, int ms);
    void RelativeTempo(int h, int percent, int ms);
    bool Branch(int h, int marker);                                    // jump to an RBRN point
    int Measure(int h) const;                                          // 1-based measure count
    // Two clocks. Service: play everything due by `nowSeconds` (120 ticks a second at 100%).
    // Serve: one driver interrupt, as Miles counts it - tempo% / 100 ticks per call, whatever the
    // caller's rate (games compensate with the relative tempo). Ramps use `nowSeconds` either way.
    void Service(double nowSeconds);
    void Serve(double nowSeconds);
    void StopAll();

private:
    struct Note { uint8_t channel, key; uint32_t ticksLeft; };
    struct Loop { size_t start; int remaining; };                     // remaining 0 = forever
    struct Ramp {
        double from = 100, to = 100, startAt = 0, ms = 0;
        double At(double now) const { return ms <= 0 || now >= startAt + ms / 1000 ? to : from + (to - from) * (now - startAt) * 1000 / ms; }
    };
    struct Seq {
        bool used = false;
        std::vector<uint8_t> evnt;
        std::map<int, uint32_t> branches;
        int status = kStopped;
        size_t pos = 0;
        uint32_t wait = 0;
        double ticks = 0;                                              // accumulated, not yet run
        std::vector<Note> notes;
        std::vector<Loop> loops;
        uint8_t volume[16];                                            // the sequence's own CC7
        uint16_t channels = 0;                                         // channels it has used
        int sentPercent = 100;
        Ramp vol, tempo;
        uint32_t tempoUs = 500000;
        double tickInBeat = 0;
        int beatsPerBar = 4, beatUnit = 4, beat = 0, measure = 1;
    };
    Seq* Get(int h);
    const Seq* Get(int h) const;
    void Rewind(Seq& s);
    void ReadDelay(Seq& s);
    void Event(Seq& s);
    void Tick(Seq& s);
    void NotesOff(Seq& s);
    void SendVolume(Seq& s, int channel);
    void Advance(double nowSeconds, double ticks100);              // ticks at 100% tempo
    MidiOut* out_;
    std::vector<Seq> seqs_;
    double last_ = -1, now_ = 0;
};

}  // namespace hlekit
