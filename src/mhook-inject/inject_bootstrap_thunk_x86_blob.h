// inject_bootstrap_thunk_x86_blob.h — machine-code bytes of the x86 bootstrap
// thunk, for embedding into the x64 build (cross-architecture 64-bit -> 32-bit
// injection).  The x64 assembler (ml64) cannot assemble the x86 .asm, so the
// 32-bit thunk is carried as a raw byte blob instead.
//
// SOURCE OF TRUTH: src/mhook-inject/inject_bootstrap_thunk_x86.asm.  This blob is
// a verbatim copy of the assembled InjectBootstrapThunkEntry..InjectBootstrapThunkEnd
// bytes (the trailing sentinel NOP at InjectBootstrapThunkEnd is NOT included, so
// the size equals the same-arch codeSize = End - Entry).  The thunk is fully
// position-independent and contains NO relocations — every call goes indirectly
// through the params block — so the raw bytes are usable as-is at any address.
//
// REGENERATION (when the .asm changes):
//   ml.exe /nologo /c /Fo t.obj inject_bootstrap_thunk_x86.asm
//   dumpbin /SYMBOLS t.obj                     # InjectBootstrapThunkEnd offset = byte count
//   dumpbin "/SECTION:.text$mn" /RAWDATA:BYTES t.obj
//   -> copy the first <End offset> bytes here.
// The x86 static-build unit test (MhookInjectTest.CrossArchThunkBlobMatches)
// memcmp's this blob against the linked InjectBootstrapThunkEntry and FAILS if the
// .asm was changed without regenerating this file.

#pragma once

static const unsigned char kInjectBootstrapThunkX86[] = {
    0x55, 0x8B, 0xEC, 0x53, 0x8B, 0x5D, 0x08, 0x8D, 0x43, 0x0C, 0x50, 0x8D, 0x43, 0x04, 0x50, 0x6A,
    0x00, 0x6A, 0x00, 0xFF, 0x13, 0x89, 0x43, 0x4C, 0x8B, 0x43, 0x14, 0x85, 0xC0, 0x74, 0x0E, 0x8D,
    0x43, 0x24, 0x50, 0x8D, 0x43, 0x1C, 0x50, 0x6A, 0x00, 0x6A, 0x00, 0xFF, 0x13, 0x8B, 0x43, 0x0C,
    0x03, 0x43, 0x10, 0x53, 0xFF, 0xD0, 0x83, 0xC4, 0x04, 0x5B, 0x5D, 0xC2, 0x04, 0x00,
};
