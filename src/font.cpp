#include "hlekit/font.h"

#include <cstring>
#include <fstream>
#include <sstream>

namespace hlekit {

namespace embedded {
extern const char* const kFont8x8;
extern const char* const kFont8x16;
}

bool Font::Parse(const std::string& text, Font& out, std::string& err) {
    int height = 0, ch = -1, row = 0;
    auto data = std::make_shared<std::vector<uint8_t>>();
    std::stringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == ';') continue;
        if (line.rfind("height ", 0) == 0) {
            height = atoi(line.c_str() + 7);
            if (height < 1 || height > 32) { err = "bad font height"; return false; }
            data->assign((size_t)256 * height, 0);
        } else if (line.rfind("@ ", 0) == 0 && line.size() >= 3) {
            // "@ A" or, for codes with no printable form, "@ 0x1a"
            ch = line.rfind("@ 0x", 0) == 0 && line.size() > 4 ? (int)strtol(line.c_str() + 4, nullptr, 16) & 0xff
                                                                 : (uint8_t)line[2];
            row = 0;
        } else if (ch >= 0 && height && row < height) {
            uint8_t bits = 0;
            for (size_t x = 0; x < line.size() && x < 8; ++x)
                if (line[x] == '#') bits |= 0x80 >> x;
            (*data)[(size_t)ch * height + row++] = bits;
        }
    }
    if (!height) { err = "font has no 'height' line"; return false; }
    out.own_ = data;
    out.rows_ = data->data();
    out.height_ = height;
    return true;
}

bool Font::Load(const std::string& path, Font& out, std::string& err) {
    std::ifstream f(path);
    if (!f) { err = "cannot open " + path; return false; }
    std::stringstream ss;
    ss << f.rdbuf();
    return Parse(ss.str(), out, err);
}

Font Font::Builtin(int height) {
    static const Font f8 = [] { Font f; std::string e; Font::Parse(embedded::kFont8x8, f, e); return f; }();
    static const Font f16 = [] { Font f; std::string e; Font::Parse(embedded::kFont8x16, f, e); return f; }();
    return height > 12 ? f16 : f8;
}

Font Font::Guest(Machine& m, uint32_t linear, int height) {
    Font f;
    f.rows_ = m.vm.Ptr(linear, (uint32_t)(256 * height));
    f.height_ = height;
    if (!f.rows_) return Builtin(height);
    return f;
}

Font ResolveFont(Machine& m, const FontRequest& req) {
    if (req.guestLinear) {
        Font f = Font::Guest(m, req.guestLinear, req.guestHeight);
        if (f.height() == req.guestHeight) return f;
    }
    if (!req.overrideFile.empty()) {
        Font f;
        std::string err;
        if (Font::Load(req.overrideFile, f, err)) return f;
        fprintf(stderr, "[font] %s\n", err.c_str());
    }
    const bool text = req.videoMode <= 3 || req.videoMode == 7;
    return Font::Builtin(req.height ? req.height : text ? 16 : 8);
}

TextSurface::TextSurface(Machine& m, Font font, uint32_t frameLinear, int width, int height)
    : m_(m), font_(std::move(font)), frame_(frameLinear), width_(width), height_(height) {}

uint8_t* TextSurface::Frame() { return m_.vm.Ptr(frame_, (uint32_t)(width_ * height_)); }

void TextSurface::FillCells(int top, int left, int bottom, int right, uint8_t color) {
    uint8_t* fb = Frame();
    if (!fb) return;
    const int h = font_.height();
    for (int r = std::max(top, 0); r <= bottom && r < rows(); ++r)
        for (int y = r * h; y < r * h + h; ++y)
            for (int c = std::max(left, 0); c <= right && c < cols(); ++c) memset(fb + y * width_ + c * 8, color, 8);
}

void TextSurface::ScrollUp(int top, int left, int bottom, int right, uint8_t fillColor) {
    uint8_t* fb = Frame();
    if (!fb || top < 0 || left < 0 || bottom >= rows() || right >= cols() || top > bottom || left > right) return;
    const int h = font_.height();
    for (int y = top * h; y < bottom * h; ++y)
        memmove(fb + y * width_ + left * 8, fb + (y + h) * width_ + left * 8, (size_t)(right - left + 1) * 8);
    FillCells(bottom, left, bottom, right, fillColor);
}

void TextSurface::DrawGlyph(int row, int col, uint8_t ch, uint8_t fg, int bg) {
    uint8_t* fb = Frame();
    if (!fb || row < 0 || col < 0 || row >= rows() || col >= cols()) return;
    if (bg >= 0) FillCells(row, col, row, col, (uint8_t)bg);
    const uint8_t* glyph = font_.Glyph(ch);
    for (int y = 0; y < font_.height(); ++y)
        for (int x = 0; x < 8; ++x)
            if (glyph[y] & (0x80 >> x)) fb[(row * font_.height() + y) * width_ + col * 8 + x] = fg;
}

}  // namespace hlekit
