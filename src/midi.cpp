// Host MIDI: FluidSynth output and the Miles XMIDI sequencer (include/hlekit/midi.h).
#include "hlekit/midi.h"

#include <SDL2/SDL.h>

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>

#ifdef HLEKIT_HAVE_FLUIDSYNTH
#include <fluidsynth.h>
#endif

namespace hlekit {

// ---- FluidSynth -------------------------------------------------------------------------------

#ifdef HLEKIT_HAVE_FLUIDSYNTH
namespace {

class FluidOut : public MidiOut {
public:
    ~FluidOut() override {
        if (dev_) SDL_CloseAudioDevice(dev_);
        if (synth_) delete_fluid_synth(synth_);
        if (settings_) delete_fluid_settings(settings_);
    }
    bool Open(const std::string& soundFont, std::string& err) {
        settings_ = new_fluid_settings();
        if (!settings_) return err = "new_fluid_settings failed", false;
        fluid_settings_setnum(settings_, "synth.sample-rate", 44100.0);
        fluid_settings_setnum(settings_, "synth.gain", 0.6);
        fluid_settings_setint(settings_, "synth.polyphony", 256);
        synth_ = new_fluid_synth(settings_);                 // the API is thread-safe by default
        if (!synth_) return err = "new_fluid_synth failed", false;
        if (fluid_synth_sfload(synth_, soundFont.c_str(), 1) == FLUID_FAILED)
            return err = "cannot load SoundFont " + soundFont, false;
        if (SDL_InitSubSystem(SDL_INIT_AUDIO) != 0) return err = SDL_GetError(), false;
        SDL_AudioSpec want{};
        want.freq = 44100;
        want.format = AUDIO_S16SYS;
        want.channels = 2;
        want.samples = 512;
        want.callback = [](void* self, Uint8* stream, int len) {
            fluid_synth_write_s16(static_cast<FluidOut*>(self)->synth_, len / 4, stream, 0, 2, stream, 1, 2);
        };
        want.userdata = this;
        dev_ = SDL_OpenAudioDevice(nullptr, 0, &want, nullptr, 0);
        if (!dev_) return err = SDL_GetError(), false;
        SDL_PauseAudioDevice(dev_, 0);
        return true;
    }
    void Short(uint8_t status, uint8_t d1, uint8_t d2) override {
        const int ch = status & 15;
        switch (status & 0xF0) {
        case 0x80: fluid_synth_noteoff(synth_, ch, d1); break;
        case 0x90: d2 ? fluid_synth_noteon(synth_, ch, d1, d2) : fluid_synth_noteoff(synth_, ch, d1); break;
        case 0xA0: fluid_synth_key_pressure(synth_, ch, d1, d2); break;
        case 0xB0: fluid_synth_cc(synth_, ch, d1, d2); break;
        case 0xC0: fluid_synth_program_change(synth_, ch, d1); break;
        case 0xD0: fluid_synth_channel_pressure(synth_, ch, d1); break;
        case 0xE0: fluid_synth_pitch_bend(synth_, ch, d2 << 7 | d1); break;
        }
    }
    void Sysex(const uint8_t* data, size_t bytes) override {
        if (bytes) fluid_synth_sysex(synth_, (const char*)data, (int)bytes, nullptr, nullptr, nullptr, 0);
    }
    void Reset() override { fluid_synth_system_reset(synth_); }

private:
    fluid_settings_t* settings_ = nullptr;
    fluid_synth_t* synth_ = nullptr;
    SDL_AudioDeviceID dev_ = 0;
};

}  // namespace
#endif

std::unique_ptr<MidiOut> MakeFluidSynth(const std::string& soundFont, std::string& err) {
#ifdef HLEKIT_HAVE_FLUIDSYNTH
    // Resolution order: the explicit path (GameInfo::soundFont or --soundfont), then
    // HLEKIT_SOUNDFONT, then the generic SOUNDFONT. There is deliberately no built-in path:
    // the kit neither bundles nor assumes a SoundFont.
    std::string path = soundFont;
    if (path.empty())
        if (const char* env = getenv("HLEKIT_SOUNDFONT")) path = env;
    if (path.empty())
        if (const char* env = getenv("SOUNDFONT")) path = env;
    if (path.empty()) {
        err = "no SoundFont (use --soundfont FILE, HLEKIT_SOUNDFONT or SOUNDFONT)";
        return nullptr;
    }
    auto out = std::make_unique<FluidOut>();
    if (!out->Open(path, err)) return nullptr;
    return out;
#else
    (void)soundFont;
    err = "built without FluidSynth";
    return nullptr;
#endif
}

// ---- XMIDI ------------------------------------------------------------------------------------

namespace {

uint32_t Be32(const uint8_t* p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }
uint32_t Even(uint32_t n) { return n + (n & 1); }

uint32_t Vlq(const std::vector<uint8_t>& d, size_t& pos) {
    uint32_t v = 0;
    for (int i = 0; i < 4 && pos < d.size(); ++i) {
        const uint8_t b = d[pos++];
        v = v << 7 | (b & 0x7F);
        if (!(b & 0x80)) break;
    }
    return v;
}

// The chunks of one FORM XMID: its EVNT data and RBRN branch points (offsets into EVNT).
bool ReadXmid(const uint8_t* p, size_t n, std::vector<uint8_t>& evnt, std::map<int, uint32_t>& branches) {
    for (size_t at = 0; at + 8 <= n;) {
        const uint32_t len = Be32(p + at + 4);
        if (at + 8 + len > n) return false;
        const uint8_t* c = p + at + 8;
        if (!memcmp(p + at, "EVNT", 4)) evnt.assign(c, c + len);
        else if (!memcmp(p + at, "RBRN", 4) && len >= 2) {
            const uint32_t count = c[0] | c[1] << 8;
            for (uint32_t i = 0; i < count && 2 + 6 * i + 6 <= len; ++i) {
                const uint8_t* e = c + 2 + 6 * i;
                branches[e[0] | e[1] << 8] = e[2] | e[3] << 8 | e[4] << 16 | uint32_t(e[5]) << 24;
            }
        }
        at += 8 + Even(len);
    }
    return !evnt.empty();
}

}  // namespace

size_t XmiPlayer::FileSize(const uint8_t* d, size_t avail) {
    if (avail < 12) return 0;
    if (!memcmp(d, "FORM", 4) && !memcmp(d + 8, "XMID", 4)) return std::min<size_t>(8 + Even(Be32(d + 4)), avail);
    if (memcmp(d, "FORM", 4) || memcmp(d + 8, "XDIR", 4)) return 0;
    size_t n = 8 + Even(Be32(d + 4));
    if (n + 8 <= avail && !memcmp(d + n, "CAT ", 4)) n += 8 + Even(Be32(d + n + 4));
    return std::min(n, avail);
}

int XmiPlayer::Register(const uint8_t* d, size_t n, int sequence) {
    // Find FORM XMID number `sequence`: the only one, or the n-th inside CAT XMID.
    const uint8_t* form = nullptr;
    size_t formLen = 0;
    int index = 0;
    auto scan = [&](const uint8_t* p, size_t len) {
        for (size_t at = 0; at + 12 <= len && !form;) {
            const uint32_t l = Be32(p + at + 4);
            if (!memcmp(p + at, "FORM", 4) && !memcmp(p + at + 8, "XMID", 4) && index++ == sequence) {
                form = p + at + 12;
                formLen = std::min<size_t>(l - 4, len - at - 12);
            }
            at += 8 + Even(l);
        }
    };
    if (n >= 12 && !memcmp(d, "FORM", 4) && !memcmp(d + 8, "XMID", 4)) scan(d, n);
    else if (n >= 12 && !memcmp(d, "FORM", 4)) {
        const size_t cat = 8 + Even(Be32(d + 4));
        if (cat + 12 <= n && !memcmp(d + cat, "CAT ", 4))
            scan(d + cat + 12, std::min<size_t>(Be32(d + cat + 4) - 4, n - cat - 12));
    }
    if (!form) return -1;
    Seq s;
    if (!ReadXmid(form, formLen, s.evnt, s.branches)) return -1;
    s.used = true;
    size_t h = 0;
    while (h < seqs_.size() && seqs_[h].used) ++h;
    if (h == seqs_.size()) seqs_.emplace_back();
    seqs_[h] = std::move(s);
    Rewind(seqs_[h]);
    return (int)h;
}

XmiPlayer::Seq* XmiPlayer::Get(int h) { return h >= 0 && h < (int)seqs_.size() && seqs_[h].used ? &seqs_[h] : nullptr; }
const XmiPlayer::Seq* XmiPlayer::Get(int h) const { return h >= 0 && h < (int)seqs_.size() && seqs_[h].used ? &seqs_[h] : nullptr; }

void XmiPlayer::Release(int h) {
    if (Seq* s = Get(h)) { NotesOff(*s); *s = Seq{}; }
}

void XmiPlayer::Rewind(Seq& s) {
    s.pos = 0;
    s.wait = 0;
    s.ticks = 0;
    s.loops.clear();
    std::fill(std::begin(s.volume), std::end(s.volume), 127);
    s.tempoUs = 500000;
    s.tickInBeat = 0;
    s.beatsPerBar = 4;
    s.beatUnit = 4;
    s.beat = 0;
    s.measure = 1;
    ReadDelay(s);
}

void XmiPlayer::Start(int h) {
    Seq* s = Get(h);
    if (!s) return;
    NotesOff(*s);
    Rewind(*s);
    s->status = kPlaying;
}

void XmiPlayer::Stop(int h) {
    if (Seq* s = Get(h); s && s->status == kPlaying) { NotesOff(*s); s->status = kStopped; }
}

void XmiPlayer::Resume(int h) {
    if (Seq* s = Get(h); s && s->status == kStopped) s->status = kPlaying;
}

int XmiPlayer::StatusOf(int h) const {
    const Seq* s = Get(h);
    return s ? s->status : kStopped;
}

void XmiPlayer::RelativeVolume(int h, int percent, int ms) {
    if (Seq* s = Get(h)) s->vol = Ramp{s->vol.At(now_), (double)std::clamp(percent, 0, 127), now_, (double)std::max(ms, 0)};
}

void XmiPlayer::RelativeTempo(int h, int percent, int ms) {
    if (Seq* s = Get(h)) s->tempo = Ramp{s->tempo.At(now_), (double)std::clamp(percent, 1, 400), now_, (double)std::max(ms, 0)};
}

bool XmiPlayer::Branch(int h, int marker) {
    Seq* s = Get(h);
    if (!s) return false;
    auto it = s->branches.find(marker);
    if (it == s->branches.end() || it->second >= s->evnt.size()) return false;
    s->pos = it->second;
    s->wait = 0;
    ReadDelay(*s);
    return true;
}

int XmiPlayer::Measure(int h) const {
    const Seq* s = Get(h);
    return s ? s->measure : 0;
}

void XmiPlayer::StopAll() {
    for (Seq& s : seqs_) if (s.used) { NotesOff(s); if (s.status == kPlaying) s.status = kStopped; }
    if (out_) out_->Reset();
}

void XmiPlayer::NotesOff(Seq& s) {
    if (out_) for (const Note& n : s.notes) out_->Short(0x80 | n.channel, n.key, 0);
    s.notes.clear();
}

void XmiPlayer::SendVolume(Seq& s, int channel) {
    if (out_) out_->Short(0xB0 | channel, 7, (uint8_t)std::min(127, s.volume[channel] * s.sentPercent / 100));
}

// XMIDI intervals: the bytes below 80h before an event, summed.
void XmiPlayer::ReadDelay(Seq& s) {
    while (s.pos < s.evnt.size() && s.evnt[s.pos] < 0x80) s.wait += s.evnt[s.pos++];
}

void XmiPlayer::Event(Seq& s) {
    const std::vector<uint8_t>& d = s.evnt;
    if (s.pos >= d.size()) { s.status = kDone; NotesOff(s); return; }
    const uint8_t b = d[s.pos++];
    const uint8_t ch = b & 15;
    auto byte = [&]() -> uint8_t { return s.pos < d.size() ? d[s.pos++] : 0; };
    switch (b & 0xF0) {
    case 0x80: {
        const uint8_t key = byte();
        byte();
        if (out_) out_->Short(b, key, 0);
        break;
    }
    case 0x90: {                                            // note, velocity, duration (VLQ)
        const uint8_t key = byte(), vel = byte();
        const uint32_t dur = Vlq(d, s.pos);
        s.channels |= 1 << ch;
        if (out_) out_->Short(b, key, vel);
        if (vel) s.notes.push_back({ch, key, dur ? dur - 1 : 0});
        break;
    }
    case 0xA0: case 0xE0: {
        const uint8_t d1 = byte(), d2 = byte();
        s.channels |= 1 << ch;
        if (out_) out_->Short(b, d1, d2);
        break;
    }
    case 0xC0: case 0xD0: {
        const uint8_t d1 = byte();
        s.channels |= 1 << ch;
        if (out_) out_->Short(b, d1, 0);
        break;
    }
    case 0xB0: {
        const uint8_t c = byte(), v = byte();
        s.channels |= 1 << ch;
        if (c == 7) { s.volume[ch] = v; SendVolume(s, ch); }
        else if (c == 116) s.loops.push_back({s.pos, v});                 // FOR (count, 0 = forever)
        else if (c == 117) {                                               // NEXT (< 64: BREAK)
            if (s.loops.empty()) break;
            Loop& l = s.loops.back();
            if (v < 64) s.loops.pop_back();
            else if (l.remaining == 0 || --l.remaining > 0) s.pos = l.start;
            else s.loops.pop_back();
        } else if (c == 118) { s.beat = 0; s.tickInBeat = 0; s.measure = 1; }   // clear beat/bar
        else if (c >= 110 && c <= 120) {}                                  // AIL locks, banks, callbacks, markers
        else if (out_) out_->Short(b, c, v);
        break;
    }
    default:
        if (b == 0xFF) {
            const uint8_t type = byte();
            const uint32_t len = Vlq(d, s.pos);
            const size_t at = s.pos;
            s.pos = std::min(d.size(), s.pos + len);
            if (type == 0x2F) { s.status = kDone; NotesOff(s); }
            else if (type == 0x51 && len >= 3) s.tempoUs = uint32_t(d[at]) << 16 | d[at + 1] << 8 | d[at + 2];
            else if (type == 0x58 && len >= 2) { s.beatsPerBar = std::max<int>(1, d[at]); s.beatUnit = 1 << std::min<int>(d[at + 1], 6); }
        } else {                                                           // F0 / F7 sysex
            const uint32_t len = Vlq(d, s.pos);
            const size_t at = s.pos;
            s.pos = std::min(d.size(), s.pos + len);
            size_t n = s.pos - at;
            if (n && d[at + n - 1] == 0xF7) --n;
            if (out_ && n) out_->Sysex(d.data() + at, n);
        }
    }
}

void XmiPlayer::Tick(Seq& s) {
    for (size_t i = 0; i < s.notes.size();) {
        if (s.notes[i].ticksLeft == 0) {
            if (out_) out_->Short(0x80 | s.notes[i].channel, s.notes[i].key, 0);
            s.notes.erase(s.notes.begin() + i);
        } else --s.notes[i++].ticksLeft;
    }
    for (int guard = 0; s.status == kPlaying && s.wait == 0 && guard < 4096; ++guard) {
        Event(s);
        ReadDelay(s);
    }
    if (s.wait) --s.wait;
    // Beats from the tempo (microseconds per quarter note) at 120 ticks per second.
    const double beatTicks = s.tempoUs * 120.0 / 1e6 * 4.0 / s.beatUnit;
    if (++s.tickInBeat >= beatTicks) {
        s.tickInBeat -= beatTicks;
        if (++s.beat >= s.beatsPerBar) { s.beat = 0; ++s.measure; }
    }
}

void XmiPlayer::Service(double now) {
    const double dt = last_ < 0 ? 0 : std::clamp(now - last_, 0.0, 0.25);
    last_ = now;
    Advance(now, dt * 120.0);
}

void XmiPlayer::Serve(double now) {
    last_ = now;
    Advance(now, 1.0);
}

void XmiPlayer::Advance(double now, double ticks100) {
    now_ = now;
    for (Seq& s : seqs_) {
        if (!s.used) continue;
        const int percent = (int)std::lround(s.vol.At(now));
        if (percent != s.sentPercent) {
            s.sentPercent = percent;
            for (int c = 0; c < 16; ++c) if (s.channels >> c & 1) SendVolume(s, c);
        }
        if (s.status != kPlaying) continue;
        s.ticks += ticks100 * s.tempo.At(now) / 100.0;
        while (s.ticks >= 1 && s.status == kPlaying) { s.ticks -= 1; Tick(s); }
    }
}

}  // namespace hlekit
