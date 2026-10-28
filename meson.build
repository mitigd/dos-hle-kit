project('dos-hle-kit', 'cpp', 'c',
  license : 'MIT',
  default_options : ['cpp_std=c++20', 'warning_level=2', 'buildtype=release'])

# The kit is a static library plus a dependency object; a game project uses it as a meson
# subproject (subprojects/dos-hle-kit -> this directory) and only supplies its seam table.
#
# The CPU engine is a backend (include/hlekit/vcpu.h): the kit and the games
# never see KVM/WHPX/JIT. A build links the backends its host can run.
hlekit_src = files(
  'src/vcpu.cpp',
  'src/vcpu_jit.cpp',
  'src/vm.cpp',
  'src/machine.cpp',
  'src/decomp.cpp',
  'src/dos.cpp',
  'src/le.cpp',
  'src/ne.cpp',
  'src/phar286.cpp',
  'src/audio.cpp',
  'src/midi.cpp',
  'src/frontend.cpp',
  'src/font.cpp',
  'src/jit/JitEngine/CompileBlock.cpp',
  'src/jit/JitEngine/Engine.cpp')

# Fonts are data (data/fonts/*.fnt); they are embedded into the library as text.
embedded_fonts = custom_target('embedded_fonts',
  input : ['data/fonts/hlekit-8x8.fnt', 'data/fonts/hlekit-8x16.fnt'],
  output : 'embedded_fonts.cpp',
  command : [find_program('python3'), files('tools/embed_text.py'), '@OUTPUT@',
             'kFont8x8=@INPUT0@', 'kFont8x16=@INPUT1@'])
hlekit_src += embedded_fonts

hlekit_args = ['-DHLEKIT_HAVE_JIT']
hlekit_inc = [include_directories('include', 'src/jit',
                                  'third_party/zydis/include', 'third_party/zydis/src',
                                  'third_party/zydis/dependencies/zycore/include',
                                  'third_party/zydis/dependencies/zycore/src',
                                  'third_party/asmjit/src')]

# ---- vendored CPU dependencies: Zydis decodes, AsmJit emits (MIT / zlib)
zydis_src = files(
  'third_party/zydis/src/Decoder.c',
  'third_party/zydis/src/DecoderData.c',
  'third_party/zydis/src/Disassembler.c',
  'third_party/zydis/src/Formatter.c',
  'third_party/zydis/src/FormatterATT.c',
  'third_party/zydis/src/FormatterBase.c',
  'third_party/zydis/src/FormatterBuffer.c',
  'third_party/zydis/src/FormatterIntel.c',
  'third_party/zydis/src/MetaInfo.c',
  'third_party/zydis/src/Mnemonic.c',
  'third_party/zydis/src/Register.c',
  'third_party/zydis/src/Segment.c',
  'third_party/zydis/src/SharedData.c',
  'third_party/zydis/src/String.c',
  'third_party/zydis/src/Utils.c',
  'third_party/zydis/src/Zydis.c',
  'third_party/zydis/dependencies/zycore/src/Allocator.c',
  'third_party/zydis/dependencies/zycore/src/ArgParse.c',
  'third_party/zydis/dependencies/zycore/src/Bitset.c',
  'third_party/zydis/dependencies/zycore/src/Format.c',
  'third_party/zydis/dependencies/zycore/src/List.c',
  'third_party/zydis/dependencies/zycore/src/String.c',
  'third_party/zydis/dependencies/zycore/src/Vector.c',
  'third_party/zydis/dependencies/zycore/src/Zycore.c')

asmjit_src = files(
  'third_party/asmjit/src/asmjit/core/archtraits.cpp',
  'third_party/asmjit/src/asmjit/core/assembler.cpp',
  'third_party/asmjit/src/asmjit/core/builder.cpp',
  'third_party/asmjit/src/asmjit/core/codeholder.cpp',
  'third_party/asmjit/src/asmjit/core/codewriter.cpp',
  'third_party/asmjit/src/asmjit/core/compiler.cpp',
  'third_party/asmjit/src/asmjit/core/constpool.cpp',
  'third_party/asmjit/src/asmjit/core/cpuinfo.cpp',
  'third_party/asmjit/src/asmjit/core/emithelper.cpp',
  'third_party/asmjit/src/asmjit/core/emitter.cpp',
  'third_party/asmjit/src/asmjit/core/emitterutils.cpp',
  'third_party/asmjit/src/asmjit/core/environment.cpp',
  'third_party/asmjit/src/asmjit/core/errorhandler.cpp',
  'third_party/asmjit/src/asmjit/core/formatter.cpp',
  'third_party/asmjit/src/asmjit/core/func.cpp',
  'third_party/asmjit/src/asmjit/core/funcargscontext.cpp',
  'third_party/asmjit/src/asmjit/core/globals.cpp',
  'third_party/asmjit/src/asmjit/core/inst.cpp',
  'third_party/asmjit/src/asmjit/core/jitallocator.cpp',
  'third_party/asmjit/src/asmjit/core/jitruntime.cpp',
  'third_party/asmjit/src/asmjit/core/logger.cpp',
  'third_party/asmjit/src/asmjit/core/operand.cpp',
  'third_party/asmjit/src/asmjit/core/osutils.cpp',
  'third_party/asmjit/src/asmjit/core/ralocal.cpp',
  'third_party/asmjit/src/asmjit/core/rapass.cpp',
  'third_party/asmjit/src/asmjit/core/rastack.cpp',
  'third_party/asmjit/src/asmjit/core/string.cpp',
  'third_party/asmjit/src/asmjit/core/support.cpp',
  'third_party/asmjit/src/asmjit/core/target.cpp',
  'third_party/asmjit/src/asmjit/core/type.cpp',
  'third_party/asmjit/src/asmjit/core/virtmem.cpp',
  'third_party/asmjit/src/asmjit/core/zone.cpp',
  'third_party/asmjit/src/asmjit/core/zonehash.cpp',
  'third_party/asmjit/src/asmjit/core/zonelist.cpp',
  'third_party/asmjit/src/asmjit/core/zonestack.cpp',
  'third_party/asmjit/src/asmjit/core/zonetree.cpp',
  'third_party/asmjit/src/asmjit/core/zonevector.cpp',
  'third_party/asmjit/src/asmjit/x86/x86assembler.cpp',
  'third_party/asmjit/src/asmjit/x86/x86builder.cpp',
  'third_party/asmjit/src/asmjit/x86/x86compiler.cpp',
  'third_party/asmjit/src/asmjit/x86/x86emithelper.cpp',
  'third_party/asmjit/src/asmjit/x86/x86formatter.cpp',
  'third_party/asmjit/src/asmjit/x86/x86func.cpp',
  'third_party/asmjit/src/asmjit/x86/x86instapi.cpp',
  'third_party/asmjit/src/asmjit/x86/x86instdb.cpp',
  'third_party/asmjit/src/asmjit/x86/x86operand.cpp',
  'third_party/asmjit/src/asmjit/x86/x86rapass.cpp')

cpu_deps_lib = static_library('hlekit_cpu_deps', zydis_src, asmjit_src,
  include_directories : hlekit_inc,
  c_args : ['-std=c11', '-DZYDIS_STATIC_BUILD', '-DZYCORE_STATIC_BUILD'],
  cpp_args : ['-std=c++20', '-DASMJIT_STATIC', '-DASMJIT_NO_AARCH64', '-DASMJIT_NO_ARM'],
  override_options : ['unity=off'])

if host_machine.system() == 'linux'
  hlekit_src += files('src/vcpu_kvm.cpp')
  hlekit_args += '-DHLEKIT_HAVE_KVM'
elif host_machine.system() == 'windows'
  # hlekit_args += '-DHLEKIT_HAVE_WHPX'   # src/vcpu_whpx.cpp: the Windows bring-up
endif

# Music seams synthesize General MIDI with FluidSynth when it is installed.
fluidsynth_dep = dependency('fluidsynth', required : false)
if fluidsynth_dep.found()
  hlekit_args += '-DHLEKIT_HAVE_FLUIDSYNTH'
endif

hlekit_lib = static_library('hlekit', hlekit_src,
  include_directories : hlekit_inc,
  cpp_args : hlekit_args,
  dependencies : [dependency('sdl2'), dependency('zlib'), dependency('threads'), fluidsynth_dep])

hlekit_dep = declare_dependency(
  link_with : [hlekit_lib, cpu_deps_lib],
  include_directories : include_directories('include'),
  compile_args : hlekit_args,
  dependencies : [dependency('sdl2'), dependency('threads'), fluidsynth_dep])
