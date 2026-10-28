// Per-game user options, declared by the port and stored as a plain text file next to the other
// per-user files (the SDL pref path: XDG data home on Linux, %APPDATA% on Windows, Application
// Support on macOS; see paths.h). A port lists its options in GameInfo::options; the kit writes
// a commented config.ini with the defaults on first run, appends options added later, reads it at
// start-up, and lets the command line override it for one run (--config FILE, --set key=value).
// Seams read the result with Machine::Option / Machine::OptionIndex.
//
// File format: "key = value", '#' or ';' starts a comment line, unknown keys are reported and kept.
#pragma once
#include <map>
#include <string>
#include <vector>

namespace hlekit {

struct ConfigOption {
    std::string key;                    // "language"
    std::string def;                    // default value (a member of `choices` when that is non-empty)
    std::string doc;                    // one line, written above the key in the file
    std::vector<std::string> choices;   // allowed values (case-insensitive); empty = free text
};

class Config {
public:
    // Reads `path` (missing is fine), fills in defaults, and writes the file back when it was
    // missing or lacked a declared option. `overrides` (--set) win and are never written.
    void Load(const std::vector<ConfigOption>& options, const std::string& path,
              const std::map<std::string, std::string>& overrides);
    std::string Get(const std::string& key) const;     // "" for an undeclared key
    // Index of the value within the option's choices, 0 if it is free text or undeclared.
    int Index(const std::string& key) const;

private:
    std::vector<ConfigOption> options_;
    std::map<std::string, std::string> values_;
};

}  // namespace hlekit
