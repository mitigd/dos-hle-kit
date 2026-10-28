// Fonts for text the kit draws on behalf of a game, and a surface to draw it on.
//
// A game that prints through the BIOS (int 10h write-character, scroll, set cursor) has no glyphs
// of its own: the ROM supplied them. Its text helpers are replaced by seams, and those need a
// font. Fonts here are data (data/fonts/*.fnt, embedded into the library), not code, and a glyph is
// *resolved*, never assumed:
//
//   1. the game's own font in guest memory (FontRequest::guestLinear), read live - games that ship
//      or copy a font, or point the BIOS at one, need nothing from the kit;
//   2. a project font file (FontRequest::overrideFile, same text format);
//   3. the kit's built-in font for the mode: graphics modes draw 8x8 (as the BIOS does there), text
//      modes the 8x14/8x16 face of the display.
//
// Nothing here models int 10h: there is no cursor, no attribute byte, no page - those are the
// game's logic, kept in the game's seams. The surface only draws cells.
#pragma once
#include "hlekit/machine.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace hlekit {

// 256 glyphs of `height` rows, bit 7 = leftmost pixel. Cheap to copy; may view guest memory.
class Font {
public:
    int height() const { return height_; }
    // Eight bytes' worth of rows for `ch` (height() bytes); blank for glyphs the font lacks.
    const uint8_t* Glyph(uint8_t ch) const { return rows_ + (size_t)ch * height_; }

    // The kit's own faces, from data/fonts: the nearest of 8 and 16 rows to `height`.
    static Font Builtin(int height);
    // Text format of data/fonts/*.fnt ("height N", then "@ c" blocks of '#'/'.' rows).
    static bool Parse(const std::string& text, Font& out, std::string& err);
    static bool Load(const std::string& path, Font& out, std::string& err);
    // `height` bytes per glyph for codes 0..255 at `linear` in guest memory (e.g. the table the
    // BIOS font pointer pointed at, or a font the game copied into its data segment). Not copied.
    static Font Guest(Machine& m, uint32_t linear, int height);

private:
    std::shared_ptr<const std::vector<uint8_t>> own_;   // keeps parsed data alive
    const uint8_t* rows_ = nullptr;
    int height_ = 8;
};

struct FontRequest {
    int videoMode = 0x13;             // picks the built-in face when nothing else applies
    int height = 0;                   // wanted rows; 0 = by mode (8 in graphics modes, 16 in text modes)
    uint32_t guestLinear = 0;         // game font in guest memory (0 = none)
    int guestHeight = 8;
    std::string overrideFile;         // project font file ("" = none)
};

// The order described above. Always returns a usable font.
Font ResolveFont(Machine& m, const FontRequest& req);

// Draws 8-pixel-wide cells on an 8-bit frame in guest memory (default: the VGA window).
class TextSurface {
public:
    TextSurface(Machine& m, Font font, uint32_t frameLinear = 0xA0000, int width = 320, int height = 200);

    int cols() const { return width_ / 8; }
    int rows() const { return height_ / font_.height(); }
    const Font& font() const { return font_; }
    void SetFont(Font f) { font_ = std::move(f); }

    // Cell rectangles are inclusive and clipped to the surface.
    void FillCells(int top, int left, int bottom, int right, uint8_t color);
    void ScrollUp(int top, int left, int bottom, int right, uint8_t fillColor);   // one text row
    // A glyph in `fg`; with bg >= 0 the cell is filled first, otherwise only set pixels are
    // plotted (what the BIOS does in graphics modes).
    void DrawGlyph(int row, int col, uint8_t ch, uint8_t fg, int bg = -1);

private:
    uint8_t* Frame();
    Machine& m_;
    Font font_;
    uint32_t frame_;
    int width_, height_;
};

}  // namespace hlekit
