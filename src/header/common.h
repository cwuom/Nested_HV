//
// Created by cwuom on 17 Feb 2026.
//

#pragma once

using u64 = unsigned __int64;
using u32 = unsigned __int32;
using u16 = unsigned __int16;
using u8  = unsigned __int8;

// constants
constexpr u64 HYPERVISOR_MAGIC = 0x13371337;
constexpr u64 VMCALL_UNLOAD    = 0xDEADBEEF;

struct __declspec(align(64)) GuestContext {
    u8 FxArea[4096];

    u64 Rax; u64 Rcx; u64 Rdx; u64 Rbx; u64 Rbp;
    u64 Rsi; u64 Rdi; u64 R8;  u64 R9;  u64 R10;
    u64 R11; u64 R12; u64 R13; u64 R14; u64 R15;

    u64 GuestRip;
    u64 GuestRsp;
    u64 Rflags;
};

struct VcpuContext {
    // physical/virtual pairs for VMX structures
    u64   VmxOnPhys;
    void* VmxOnVirt;

    u64   VmcsPhys;
    void* VmcsVirt;

    u64   MsrBitmapPhys;
    void* MsrBitmapVirt;

    void* HostStack;
    u64   HostStackTop;

    // helper to track state
    bool  IsLaunched;
};