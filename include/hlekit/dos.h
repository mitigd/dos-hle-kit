// The extender's services: int 21h (DOS, DOS/4GW flavour), int 31h (DPMI 0.9), int 10h (BIOS
// video mode). This is the OS layer the game was linked against, not hardware; the contracts
// were established on Action SuperCross (across-hle docs/02-dos-surface.md).
//
// Files: reads come from the overlay, then the game directory (case-insensitive); creates and
// writes go to the overlay only, so the game directory is never changed.
#pragma once
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

namespace hlekit {

class Machine;

class Dos {
public:
    explicit Dos(Machine& m);
    ~Dos();
    void Int21();
    void Int31();
    void Int10();
    bool Hooked(uint8_t v, uint32_t& off) const;
    bool HookedFar(uint8_t v, uint16_t& sel, uint32_t& off) const;
    uint32_t HeapTop() const { return heap_; }                    // end of DPMI / DOS memory handed out
    // Where the pools start, after the loaded image (Machine::Load); before the first allocation.
    void SetLayout(uint32_t poolStart, uint32_t heapStart) { dosPool_ = poolStart_ = poolStart; heap_ = heapStart_ = heapStart; }
    uint32_t PoolStart() const { return poolStart_; }
    void SetFirstSelector(uint16_t sel) { nextSel_ = sel; }        // segmented programs keep the low ones
    uint32_t HeapStart() const { return heapStart_; }

    // Allocators the extender layers (int 31h, Phar Lap 286 imports) share: linear memory from
    // the heap, conventional memory (paragraphs) and selectors.
    uint32_t Alloc(uint32_t size, uint32_t align);
    bool DosAlloc(uint16_t paras, uint16_t& seg, uint16_t& largest);   // conventional memory
    uint16_t NewSelector(uint32_t base, uint32_t limit, uint8_t access = 0xF3, bool big = true);
    void RealModeInt(uint8_t v, uint32_t rmRegs);                      // int 31h/0300h register image

private:
    struct Found { std::string name; uint32_t size; bool dir; };
    std::string Resolve(const std::string& guest, bool forWrite);
    std::string GuestPath(uint32_t addr);
    uint16_t FreeHandle() const;                                       // lowest free DOS handle, 0 = none
    void Ok();
    void Fail(uint16_t code);
    void FindFill(uint32_t dta);

    Machine& m_;
    std::map<uint16_t, FILE*> files_;
    uint32_t heap_ = 0x100000;                     // DPMI / DOS 48h memory, up to Vm::kRam
    uint32_t dosPool_ = 0x70000;                   // conventional memory for int 31h/0100h
    uint32_t poolStart_ = 0x70000, heapStart_ = 0x100000;
    uint32_t dta_;
    uint16_t dtaSel_;
    uint32_t dtaOff_;
    bool dtaSet_ = false;
    uint16_t nextSel_;
    struct Vector { uint32_t linear; uint16_t sel; uint32_t off; };
    std::map<uint8_t, Vector> vectors_;             // protected-mode handlers the game installed
    std::map<uint32_t, std::pair<uint32_t, uint32_t>> blocks_;   // DPMI handle -> (addr, size)
    std::map<uint32_t, std::pair<std::vector<Found>, size_t>> finds_;   // DTA -> results, next
};

}  // namespace hlekit
