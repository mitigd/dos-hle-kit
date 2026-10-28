#include "hlekit/config.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>

namespace hlekit {

namespace {
std::string Lower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}
std::string Trim(const std::string& s) {
    const auto a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}
// The declared spelling of `v` among the option's choices, "" if it is not one.
std::string Canonical(const ConfigOption& o, const std::string& v) {
    if (o.choices.empty()) return v;
    for (const std::string& c : o.choices)
        if (Lower(c) == Lower(v)) return c;
    return "";
}
}  // namespace

void Config::Load(const std::vector<ConfigOption>& options, const std::string& path,
                  const std::map<std::string, std::string>& overrides) {
    options_ = options;
    values_.clear();
    std::map<std::string, std::string> file;
    bool exists = false;
    if (!path.empty()) {
        std::ifstream in(path);
        exists = (bool)in;
        std::string line;
        while (std::getline(in, line)) {
            line = Trim(line);
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;
            const auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            file[Lower(Trim(line.substr(0, eq)))] = Trim(line.substr(eq + 1));
        }
    }
    std::string append;
    for (const ConfigOption& o : options_) {
        const std::string key = Lower(o.key);
        std::string v = o.def;
        if (auto it = file.find(key); it != file.end()) {
            const std::string c = Canonical(o, it->second);
            if (c.empty()) fprintf(stderr, "[config] %s: '%s' is not one of the choices; using %s\n", o.key.c_str(), it->second.c_str(), o.def.c_str());
            else v = c;
        } else {
            append += "\n# " + o.doc + "\n";
            if (!o.choices.empty()) {
                append += "# choices:";
                for (const std::string& c : o.choices) append += " " + c;
                append += "\n";
            }
            append += o.key + " = " + o.def + "\n";
        }
        values_[key] = v;
    }
    for (const auto& [k, v] : file)
        if (!values_.count(k)) fprintf(stderr, "[config] unknown option '%s'\n", k.c_str());
    if (!append.empty() && !path.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
        std::ofstream out(path, std::ios::app);
        if (!exists) out << "# dos-hle-kit port options. Edit and restart; delete a line to restore its default.\n";
        out << append;
    }
    for (const auto& [k, v] : overrides) {
        auto it = std::find_if(options_.begin(), options_.end(), [&](const ConfigOption& o) { return Lower(o.key) == Lower(k); });
        if (it == options_.end()) { fprintf(stderr, "[config] --set: unknown option '%s'\n", k.c_str()); continue; }
        const std::string c = Canonical(*it, v);
        if (c.empty()) fprintf(stderr, "[config] --set %s: '%s' is not one of the choices\n", k.c_str(), v.c_str());
        else values_[Lower(k)] = c;
    }
}

std::string Config::Get(const std::string& key) const {
    auto it = values_.find(Lower(key));
    return it == values_.end() ? "" : it->second;
}

int Config::Index(const std::string& key) const {
    for (const ConfigOption& o : options_) {
        if (Lower(o.key) != Lower(key)) continue;
        for (size_t i = 0; i < o.choices.size(); ++i)
            if (Lower(o.choices[i]) == Lower(Get(key))) return (int)i;
    }
    return 0;
}

}  // namespace hlekit
