#pragma once

#include "hlekit/audio.h"
#include "hlekit/midi.h"

namespace hlekit {

struct HostAudio {
    std::unique_ptr<AudioSink> samples;
    std::unique_ptr<MidiOut> midi;
};

// Called before starting threads or initializing SDL in the frontend. On Linux, host audio
// lives in a child process so a driver that never returns cannot stall the game or shutdown.
// Failed/timed-out audio uses the silent real-time sink to preserve guest sound timing.
HostAudio MakeHostAudio(const std::string& soundFont);

}  // namespace hlekit
