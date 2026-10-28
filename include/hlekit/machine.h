// The runner: the original code on a CPU backend (vcpu.h), the extender's services answered by
// (dos.cpp), and the hardware seams replaced by native code (the game's seam table). No device
// is emulated: any port access that still happens is reported as an unseamed function.
#pragma once
#include "hlekit/audio.h"
#include "hlekit/midi.h"
#include "hlekit/seam.h"
#include "hlekit/vm.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace hlekit {

class Dos;

// Optional function labels from a CSV (addr,name,size,...): guest address -> "name+off".
class Labels {
public:
    bool Load(const std::string& csvPath);
    void Add(uint32_t addr, uint32_t size, const std::string& name);   // then Sort()
    void Sort();
    void Remap(const std::function<uint32_t(uint32_t)>& to);          // decomp -> guest addresses
    std::string Of(uint32_t addr) const;
private:
    struct F { uint32_t addr, size; std::string name; };
    std::vector<F> funcs_;
};

class Machine {
public:
    using Task = std::function<void(Machine&)>;

    Machine();
    ~Machine();

    bool Load(const std::string& path, std::string& err);         // NE/LE executable or AHLEIMG1/2 image
    bool DumpImage(const std::string& path);                      // the loaded objects, AHLEIMG2 (with link bases)
    bool Start(const std::string& programName, std::string& err); // PSP, environment, entry
    void InstallSeams(const std::vector<Seam>& seams, const std::vector<std::string>& disabled);
    void Run();                                                   // the vCPU thread
    void Stop(const std::string& why);                            // any thread

    // Any thread: run `t` on the vCPU thread at the next point where the guest has interrupts
    // enabled - where a hardware IRQ could have arrived. Native ISR bodies go through this.
    void Post(Task t);

    // Run a guest function to completion from inside a seam or task (__watcall: up to four
    // register arguments) and return its EAX. All registers are restored afterwards. This is how
    // native code uses the game's own logic (config parsing, allocation, mixers).
    uint32_t CallGuest(uint32_t fn, std::initializer_list<uint32_t> args);
    // The same for a stack-convention callee (cdecl / Watcom -3s, `push args; call fn`): the
    // arguments are pushed right to left and the caller's stack pointer comes back as it was.
    uint32_t CallGuestCdecl(uint32_t fn, std::initializer_list<uint32_t> args);
    // Watcom register calling (-3r: C++ and NAME_ functions): arguments in EAX, EDX, EBX, ECX, the
    // rest pushed right to left (the callee pops them). Returns EAX; registers restored afterwards.
    uint32_t CallGuestWatcom(uint32_t fn, const std::vector<uint32_t>& args);
    // The original body of a function whose entry is a seam (a partial translation, A/B checks):
    // its first instruction runs from a copy that jumps back into the body. `fn` is the guest entry
    // address; Watcom arguments. A function without a seam is simply called.
    uint32_t CallOriginal(uint32_t fn, const std::vector<uint32_t>& args);
    // Inside a seam of a Watcom-convention function: argument n (EAX, EDX, EBX, ECX, then the
    // stack, [ESP+4+4(n-4)]). Its `ret N` pops 4 * (count - 4) bytes: Seam::pop.
    uint32_t WatcomArg(int n);
    // A far call, as `call fword ptr` (selector:offset); with `interruptFrame` the callee sees
    // EFLAGS, CS, EIP - the `pushfd; call far` idiom of interrupt chains - and returns by iretd.
    void CallGuestFar(uint16_t sel, uint32_t off, bool interruptFrame);
    // NE far function, word arguments (first argument lowest, as `push` right to left leaves it);
    // returns the callee's DX:AX.
    uint32_t CallGuestFar16(uint16_t sel, uint16_t off, uint16_t dataSel = 0,
                            std::initializer_list<uint16_t> args = {});

    // Real-mode (MZ/COM) programs: run a near cdecl function of the current code segment to
    // completion from a seam or task and return its DX:AX. `fn` is the linked address, like a seam's;
    // `args` are pushed right to left (first argument lowest, [bp+4] after `push bp`). All registers
    // and segments are restored afterwards. `dataSeg` != 0 loads DS and ES with it for the call (a task
    // running between instructions has no meaningful DS).
    uint32_t CallGuestNear16(uint32_t fn, std::initializer_list<uint16_t> args = {}, uint16_t dataSeg = 0);

    // A periodic host timer: `t` is posted `hz` times a second. Like a PIC, ticks that arrive
    // while the previous one is still pending are coalesced. hz <= 0 stops it.
    void SetTimer(double hz, Task t);

    // Wait inside a seam the way the original spin loop waited: until `t`, with the replaced
    // IRQs (Post tasks) still delivered whenever the guest has interrupts enabled. Seams that
    // replace a busy-wait (vsync, delays) use this instead of sleeping.
    void WaitUntil(std::chrono::steady_clock::time_point t);

    // Rollback: copy the guest's mutable memory (data objects, DPMI/DOS heap, the BIOS data area)
    // and put it back byte for byte. With HoldTasks(true) no replaced IRQ runs in between, so a
    // speculative computation - e.g. an extra render for widescreen - leaves no trace in the game.
    struct Snapshot { std::vector<std::pair<uint32_t, std::vector<uint8_t>>> ranges; };
    void TakeSnapshot(Snapshot& s);
    void RestoreSnapshot(const Snapshot& s);
    void HoldTasks(bool hold) { holdTasks_ = hold; }

    // A frame composed by a seam (any width, 8-bit indexed with `palette`); once set, the
    // frontend shows it instead of the mode-13h window at A0000h. `aspect`: the picture's display
    // width/height (4:3 for any VGA mode filling the screen); 0 = 320x200-shaped pixels.
    // ClearFrame() goes back to the A0000h window (the game left its planar / tweaked mode).
    void PresentFrame(const uint8_t* pixels, int width, int height, double aspect = 0);
    void ClearFrame();
    struct HostFrame { std::vector<uint8_t> pixels; int width = 0, height = 0; double aspect = 0; uint64_t serial = 0; };
    bool LatestFrame(HostFrame& out);

    // A native function the guest can call (driver tables, callbacks): returns its guest address,
    // a `hlt` stub that dispatches to `seam.fn` and returns like a seam (`ret seam.pop`).
    uint32_t NativeFunction(const Seam& seam);

    // The protected-mode handler the game installed for vector `v` (int 21h/25h, int 31h/0205h).
    bool HookedVector(uint8_t v, uint32_t& off) const;
    void QueueBiosKey(uint8_t scan, uint8_t ascii);       // host keypress for int 16h consumers

    // Host audio for sound seams. `onBufferDue` runs (as a Post task) whenever less than one
    // buffer is left in the host queue - the moment the original DMA would have finished.
    std::unique_ptr<AudioSink> audio;
    // Host General MIDI for music seams (FluidSynth); null when muted, headless or unavailable.
    std::unique_ptr<MidiOut> midi;
    bool StartSound(int rate, int channels, int bits, uint32_t bufferBytes, Task onBufferDue);
    void StopSound();
    void QueueAudio(uint32_t guestAddr, uint32_t bytes);          // one buffer, in the opened format
    std::atomic<float> gain{1.0f};

    // helpers for services and seams (vCPU thread)
    void Count(const std::string& what) { ++counts[what]; }
    void SetFrameFlag(uint32_t bit, bool on);                     // in a software-interrupt frame
    double Seconds() const;
    bool IsCode(uint32_t addr) const;

    // ---- real-mode (MZ/COM) programs (kvm and jit). The image is loaded and relocated at a fixed
    // segment (PSP at kRealPsp, image at PSP:0100h, so analysis addresses are linked addresses);
    // no DOS is emulated: software interrupts that reach a stub are reported as unseamed
    // functions, exactly like port I/O. Seams address code by those linked addresses (Data()).
    static constexpr uint16_t kRealPsp = 0x1000;
    bool realMode = false;
    // Deliver hardware interrupt `v` to the game's handler (IVT) as the PIC would: push FLAGS, CS,
    // IP, clear IF/TF, jump. Call from a Post task (the guest has IF=1 there).
    void InjectInterrupt(uint8_t v);
    uint16_t RealCs() const { return vm.GetSeg(Seg::Cs); }

    // ---- segmented (NE) programs: Phar Lap 286|DOS-Extender, 16-bit protected mode
    bool segmented = false;
    struct NeSeg { uint32_t base, size; uint16_t sel; bool code; };
    std::vector<NeSeg> neSegs;                                    // [n - 1] = segment n
    uint32_t SegOff(uint16_t seg, uint32_t off) const {           // map seg:off -> linear
        return seg >= 1 && seg <= neSegs.size() ? neSegs[seg - 1].base + off : 0;
    }
    uint16_t SegSel(uint16_t seg) const { return seg >= 1 && seg <= neSegs.size() ? neSegs[seg - 1].sel : 0; }
    // Native implementations of imported functions, by "MODULE.ORDINAL" or "MODULE.NAME"
    // (registered before Load). A function import becomes a `hlt` stub that runs `fn` and
    // returns far, popping `pop` bytes (pascal); a value import (`value`) resolves to
    // valueSel:valueOff itself (e.g. DOSCALLS.135 = __AHSHIFT).
    struct ImportImpl {
        std::function<void(Machine&)> fn;
        uint16_t pop = 0;
        bool value = false;
        uint16_t valueSel = 0, valueOff = 0;
    };
    std::map<std::string, ImportImpl> importImpls;
    bool LoadMap(const std::string& mapPath);                     // labels from a linker map
    // The stack as the CPU addresses it (SS base + SP or ESP); 16-bit far stack arguments.
    uint32_t StackAddr(uint32_t n);
    uint16_t ArgW(int n) { return vm.Rd16(StackAddr(4 + 2 * (uint32_t)n)); }    // after a far call
    uint32_t ArgD(int n) { return vm.Rd32(StackAddr(4 + 2 * (uint32_t)n)); }    // two words at n
    void SetSp(uint32_t sp);                                      // keeps ESP's high word on a 16-bit stack
    bool CallerIs16();                                            // in a software-int handler: the interrupted CS
    uint32_t Linear(Seg s, uint32_t off);                         // segment base + offset (16 bits on 16-bit code)
    // Decomp (linked) address -> guest address. Equal unless the loader moved the object out of
    // the A0000h hole (le.h); seams that touch data globals of such a game go through this.
    uint32_t Data(uint32_t linkAddr) const;
    uint32_t Link(uint32_t guestAddr) const;                      // the reverse, for reports
    // Inside a seam: the n-th (0-based) stack argument of a stack-convention (cdecl / Watcom -3s)
    // function - [ESP+4+4n], ESP pointing at the return address. The caller pops them (pop = 0).
    uint32_t Arg(int n) { return vm.Rd32(vm.Get(Reg::Esp) + 4 + 4 * (uint32_t)n); }

    Vm vm;
    Labels labels;
    std::unique_ptr<Dos> dos;
    std::string gameDir, fallbackGameDir, overlayDir;
    std::string commandLine;                                      // guest arguments (after argv[0])
    std::vector<std::string> dosDirAliases;
    bool logServices = false;
    bool loadHigh = false;                                        // LE: all objects above 1 MB (GameInfo::loadHigh)

    // shared with the host thread
    std::atomic<bool> stopping{false};
    std::string stopReason;
    std::mutex paletteMutex;
    uint8_t palette[768] = {};                                    // 6-bit DAC values, set by seams / int 10h
    std::atomic<int> videoMode{3};
    std::atomic<uint64_t> frames{0};                              // games' vsync seams count here

    std::map<std::string, uint64_t> counts;                       // vCPU thread; read after join
    std::deque<uint16_t> biosKeys_;                                // XT scan:ASCII words
    std::chrono::steady_clock::time_point t0;
    uint32_t entry = 0, stack = 0, fixups = 0;
    struct Region { uint32_t base, size, flags, linkBase; };
    std::vector<Region> regions;

private:
    bool Placed(std::string& err);
    bool LoadNe(const std::string& path, std::string& err);
    bool LoadReal(const std::string& path, std::string& err);
    uint16_t realCs_ = 0, realIp_ = 0, realSs_ = 0, realSp_ = 0;
    uint32_t CodeLinear() { return ((segmented || realMode) ? vm.SegBase(Seg::Cs) : 0) + (realMode ? vm.Get(Reg::Eip) & 0xFFFF : vm.Get(Reg::Eip)); }
    std::vector<uint64_t> neDescs_;                               // installed after BuildTables
    std::vector<std::pair<uint16_t, uint64_t>> neExtraDescs_;
    uint16_t neCs_ = 0, neIp_ = 0, neSs_ = 0, neSp_ = 0, neDs_ = 0, neDsSize_ = 0;
    void Step();
    void OnHlt();
    void OnTrap(uint32_t linear, bool atTrap);
    void OnInt(uint8_t v);
    void OnIo();
    void DeliverTasks();
    void Ticker();
    void BiosIrq(uint8_t irq);

    std::mutex taskMutex_;
    std::deque<Task> tasks_;
    std::map<uint32_t, const Seam*> seams_;
    std::map<std::string, bool> reported_;
    std::mutex stopMutex_;
    bool callReturned_ = false;
    uint32_t seamAt_ = 0;          // linear address of the seam whose body is running
    uint32_t nearRet_ = 0;         // linear return trap of a CallGuestNear16 in progress
    std::atomic<bool> soundRunning_{false}, soundDue_{false};
    double soundBufferSeconds_ = 0;
    int soundBytesPerSample_ = 1;
    Task onBufferDue_;
    std::thread ticker_;
    std::mutex timerMutex_;
    double timerHz_ = 0;
    Task timerTask_;
    std::atomic<bool> timerPending_{false};
    std::atomic<uint64_t> timerFired_{0}, timerCoalesced_{0};
    std::chrono::steady_clock::time_point timerNext_;
    bool holdTasks_ = false;
    // HLEKIT_TRACE=addr[,steps]: at each execution of addr, single-step `steps` instructions
    // into a ring buffer; a fault stop prints the last of them (where a wild jump came from).
    uint32_t traceBp_ = 0, traceSteps_ = 0, traceLeft_ = 0;
    uint32_t watchLimit_ = 0xFFFFFFFF;
    bool watchAny_ = false;
    double watchAfter_ = 0;                                       // HLEKIT_WATCH_AFTER: ignore writes before this time                            // HLEKIT_WATCH=addr[,limit]: stop when the dword > limit (signed)
    std::vector<uint32_t> traceRing_;
    size_t traceAt_ = 0;
    void OnDebug();
    bool profile_ = false;                                        // HLEKIT_PROFILE: guest EIP samples per function
    std::map<std::string, uint64_t> profileHits_;
    std::string TraceTail(size_t n) const;
    std::mutex frameMutex_;
    HostFrame frame_;
    bool frameShown_ = false;
    std::map<uint32_t, uint8_t> originalByte_;                    // entry bytes the traps replaced
    std::map<uint32_t, uint32_t> trampolines_;                    // CallOriginal: entry -> copy
    uint32_t nextTrampoline_ = Vm::kTrampolines;
    uint32_t Trampoline(uint32_t fn);
    std::deque<Seam> natives_;                                    // stable addresses for seams_
    uint32_t nextNative_ = Vm::kNative;
};

}  // namespace hlekit
