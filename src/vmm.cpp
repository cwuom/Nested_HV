//
// Created by cwuom on 17 Feb 2026.
//

// ==============================================================================
// vmm.cpp
// Hypervisor Implementation
// ==============================================================================

#include "header/common.h"
#include <intrin.h>
#include <ntddk.h>
#include <ntdef.h>

#include "header/vmx.h"

extern "C" void StopHypervisor();

extern "C" {
    NTKERNELAPI VOID KeStackAttachProcess(PRKPROCESS Process, PVOID ApcState);
    NTKERNELAPI VOID KeUnstackDetachProcess(PVOID ApcState);
}

// ==============================================================================
// External Assembly Linking
// ==============================================================================
extern "C" {
    // defined in arch.asm
    u64 HvVmxOn(u64* Phys);
    void HvVmxOff();
    u64 HvVmClear(u64* Phys);
    u64 HvVmPtrLd(u64* Phys);
    u64 HvVmWrite(u64 Field, u64 Value);
    u64  HvVmRead(u64 Field);

    u64 HvLaunchGuest();
    void HvRestoreStateAndReturn(GuestContext* Ctx);
    void GuestStartThunk(); // x64 naked thunk
    void HvCall(u64 Magic, u64 Command, u64 Arg1, u64 Arg2);

    // entry point for vm-exit, used in vmcs setup
    void HvVmExitEntryPoint();

    // register helpers
    u16 GetCs(); u16 GetDs(); u16 GetEs(); u16 GetSs(); u16 GetFs(); u16 GetGs();
    u16 GetTr(); u16 GetLdtr();
    u64 GetGdtBase(); u16 GetGdtLimit(); u64 GetIdtBase(); u16 GetIdtLimit();
    u64 GetRflags();
    u32 HvGetSegmentLimit(u16 Selector);
    u32 HvGetSegmentAr(u16 Selector);
}

// ==============================================================================
// Global State
// ==============================================================================
VcpuContext* g_VcpuData = nullptr;
u32 g_ProcessorCount = 0;
static u64 g_HostCr3 = 0;

// tags for memory allocation (avoid multi-char warnings by using integers)
constexpr u32 TAG_HV00 = 0x30305648; // 'HV00' little endian
constexpr u32 TAG_HVST = 0x54535648; // 'HVST' little endian

static __forceinline bool VmxOk(u64 rflags) {
    return ((rflags & 1ULL) == 0) && ((rflags & (1ULL << 6)) == 0);
}
// ==============================================================================
// Helper Functions
// ==============================================================================

// ensure controls respect the msr fixed bits
u32 AdjustControls(u32 Ctl, u32 Msr) {
    ULARGE_INTEGER msrVal;
    msrVal.QuadPart = __readmsr(Msr);
    Ctl &= msrVal.HighPart; // clear bits that must be 0
    Ctl |= msrVal.LowPart;  // set bits that must be 1
    return Ctl;
}

// ensure cr0/cr4 respect vmx fixed bits
u64 AdjustCr0(u64 Cr0) {
    const u64 fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    const u64 fixed1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    return Cr0 & fixed1 | fixed0;
}

u64 AdjustCr4(u64 Cr4) {
    const u64 fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
    const u64 fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);
    return (Cr4 & fixed1) | fixed0;
}

// passive level memory allocator
// replaced ExAllocatePool2 with ExAllocatePoolWithTag for broader compatibility
void* AllocContiguous(SIZE_T Size, u64* Phys) {
    PHYSICAL_ADDRESS max = {0}; max.QuadPart = -1;
    void* virt = MmAllocateContiguousMemory(Size, max);
    if (virt) {
        RtlZeroMemory(virt, Size);
        *Phys = MmGetPhysicalAddress(virt).QuadPart;
    }
    return virt;
}

// ==============================================================================
// VM-Exit Handling
// ==============================================================================

// handle hypervisor unload requests
void HandleVmCall(GuestContext* Ctx) {
    // calling convention: rcx = magic, rdx = command
    if (Ctx->Rcx == HYPERVISOR_MAGIC && Ctx->Rdx == VMCALL_UNLOAD) {
        // we are unloading

        // advance guest rip manually (skip the vmcall instr)
        const u64 ExitLen = HvVmRead(VM_EXIT_INSTRUCTION_LEN);
        Ctx->GuestRip += ExitLen;

        // actually, we don't need to manually clear cr4.vmxe here
        // HvRestoreStateAndReturn will execute 'vmxoff', which puts the cpu
        // out of vmx root operation.
        // the guest (which is the driver unload thread) will resume execution
        // in StopHvCallback. we can clean up cr4 there

        HvRestoreStateAndReturn(Ctx);
    }
}

void HandleMsrRead(GuestContext* Ctx) {
    // RDMSR: reads the MSR specified by ECX into EDX:EAX
    u32 msrIndex = static_cast<u32>(Ctx->Rcx);
    ULARGE_INTEGER result;

    // protect against GPF if Guest tries to access invalid MSR
    __try {
        result.QuadPart = __readmsr(msrIndex);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // if operation fails, inject GPF to guest
        // for now, just return 0 to prevent Host crash
        result.QuadPart = 0;
    }

    Ctx->Rax = result.LowPart;
    Ctx->Rdx = result.HighPart;
}

void HandleMsrWrite(GuestContext* Ctx) {
    // WRMSR: writes the value in EDX:EAX to the MSR specified by ECX
    u32 msrIndex = static_cast<u32>(Ctx->Rcx);
    ULARGE_INTEGER value;
    value.LowPart  = static_cast<u32>(Ctx->Rax);
    value.HighPart = static_cast<u32>(Ctx->Rdx);

    __try {
        __writemsr(msrIndex, value.QuadPart);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // ignore invalid MSR writes from Guest to prevent Host crash
    }
}

static __forceinline u64 GetGpr(const GuestContext* c, u8 reg) {
    switch (reg) {
        case 0: return c->Rax; case 1: return c->Rcx; case 2: return c->Rdx; case 3: return c->Rbx;
        case 4: return c->GuestRsp; case 5: return c->Rbp; case 6: return c->Rsi; case 7: return c->Rdi;
        case 8: return c->R8;  case 9: return c->R9;  case 10: return c->R10; case 11: return c->R11;
        case 12: return c->R12; case 13: return c->R13; case 14: return c->R14; case 15: return c->R15;
        default: return 0;
    }
}

static __forceinline void SetGpr(GuestContext* c, u8 reg, u64 v) {
    switch (reg) {
        case 0:
            c->Rax = v;
            break;
        case 1:
            c->Rcx = v;
            break;
        case 2:
            c->Rdx = v;
            break;
        case 3:
            c->Rbx = v;
            break;
        case 4:
            c->GuestRsp = v;
            HvVmWrite(GUEST_RSP, v);
            break;
        case 5:
            c->Rbp = v;
            break;
        case 6: c->Rsi = v;
            break;
        case 7:
            c->Rdi = v;
            break;
        case 8:
            c->R8 = v;
            break;
        case 9:
            c->R9 = v;
            break;
        case 10:
            c->R10 = v;
            break;
        case 11:
            c->R11 = v;
            break;
        case 12:
            c->R12 = v;
            break;
        case 13:
            c->R13 = v;
            break;
        case 14: c->R14 = v;
            break;
        case 15:
            c->R15 = v;
            break;
        default:
            break;
    }
}

static void HandleCrAccess(GuestContext* c) {
    const u64 qual = HvVmRead(EXIT_QUALIFICATION);
    const u8 crNum = static_cast<u8>(qual & 0xF);
    const u8 accessType = static_cast<u8>((qual >> 4) & 0x3);
    const u8 gpr = static_cast<u8>((qual >> 8) & 0xF);

    if (accessType == 0) {
        const u64 value = GetGpr(c, gpr);
        if (crNum == 0) {
            const u64 newCr0 = AdjustCr0(value);
            HvVmWrite(GUEST_CR0, newCr0);
            HvVmWrite(CONTROL_CR0_READ_SHADOW, newCr0);
            return;
        }
        if (crNum == 4) {
            const u64 actualCr4 = AdjustCr4(value | CR4_VMXE);
            HvVmWrite(GUEST_CR4, actualCr4);
            HvVmWrite(CONTROL_CR4_READ_SHADOW, (value & ~CR4_VMXE));
            return;
        }
        return;
    }
    if (accessType == 1) {
        if (crNum == 0) { SetGpr(c, gpr, HvVmRead(GUEST_CR0)); return; }
        if (crNum == 4) { SetGpr(c, gpr, HvVmRead(CONTROL_CR4_READ_SHADOW)); return; }
        return;
    }
}

extern "C" void VmExitHandler(GuestContext* Ctx) {
    const u64 ExitReason = HvVmRead(VM_EXIT_REASON) & 0xFFFF;
    const u64 ExitLen    = HvVmRead(VM_EXIT_INSTRUCTION_LEN);

    // synchronize context
    Ctx->GuestRip = HvVmRead(GUEST_RIP);
    Ctx->GuestRsp = HvVmRead(GUEST_RSP);
    Ctx->Rflags   = HvVmRead(GUEST_RFLAGS);

    bool AdvanceRip = true;

    switch (ExitReason) {
        case 10: // CPUID
        {
            if (Ctx->Rax == 0x13371337) {
                DbgPrint("[HV] Magic CPUID Intercepted on Core %d!\n", KeGetCurrentProcessorNumber());
                Ctx->Rax = 0x13371337;
                Ctx->Rbx = 0xDEADC0DE; // dead code
                Ctx->Rcx = 0xC0FFEE;   // coffee
                Ctx->Rdx = 0x48564856;
            }
            else {
                int regs[4] = {};
                __cpuidex(regs, static_cast<int>(Ctx->Rax), static_cast<int>(Ctx->Rcx));

                if (Ctx->Rax == 1) {
                    regs[2] &= ~(1 << 5);
                }

                Ctx->Rax = regs[0];
                Ctx->Rbx = regs[1];
                Ctx->Rcx = regs[2];
                Ctx->Rdx = regs[3];
            }
            break;
        }

        case 18: // VMCALL
            HandleVmCall(Ctx);
            break;

        case 31: // RDMSR
            HandleMsrRead(Ctx);
            break;

        case 32: // WRMSR
            HandleMsrWrite(Ctx);
            break;

        case 28: // control-register access
            HandleCrAccess(Ctx);
            break;

        case 1: // external interrupt
            AdvanceRip = false;
            break;

        default:
            DbgPrint("[HV] Unhandled VMExit Reason: %lld RIP: 0x%llX\n", ExitReason, Ctx->GuestRip);
            KeBugCheckEx(0xDEADDEAD, ExitReason, Ctx->GuestRip, ExitLen, 1);
    }

    if (AdvanceRip) {
        Ctx->GuestRip += ExitLen;
        HvVmWrite(GUEST_RIP, Ctx->GuestRip);
    }
}

// ==============================================================================
// VMCS Setup
// ==============================================================================

// extract the 64-bit base address from a 16-byte tss descriptor
u64 GetTssBase(const u64 GdtBase, const u16 Selector) {
    if ((Selector & 0xFFF8) == 0) return 0;
    auto descriptor = reinterpret_cast<u8*>(GdtBase + (Selector & 0xFFF8));

    u64 base = 0;
    base |= static_cast<u64>(descriptor[2]);
    base |= static_cast<u64>(descriptor[3]) << 8;
    base |= static_cast<u64>(descriptor[4]) << 16;

    base |= static_cast<u64>(static_cast<u32>(descriptor[7])) << 24;
    const u64 high = *reinterpret_cast<u32*>(&descriptor[8]);
    base |= (high << 32);

    return base;
}

// initialize the vmcs for a single virtual cpu
bool SetupVmcs(const VcpuContext* Vcpu, void* GuestSp, void* GuestIp) {
    const u64 gdtBase = GetGdtBase();
    const u16 trSelector = GetTr();
    const u64 tssBase = GetTssBase(gdtBase, trSelector);

    // ==============================================================================
    // Host State Configuration
    // ==============================================================================
    HvVmWrite(HOST_CR0, __readcr0());

    // set host CR3 to system directory table base
    HvVmWrite(HOST_CR3, g_HostCr3);

    HvVmWrite(HOST_CR4, __readcr4());

    // host selectors
    HvVmWrite(HOST_CS_SELECTOR, GetCs() & 0xFFF8);
    HvVmWrite(HOST_SS_SELECTOR, GetSs() & 0xFFF8);
    HvVmWrite(HOST_DS_SELECTOR, GetDs() & 0xFFF8);
    HvVmWrite(HOST_ES_SELECTOR, GetEs() & 0xFFF8);
    HvVmWrite(HOST_FS_SELECTOR, GetFs() & 0xFFF8);
    HvVmWrite(HOST_GS_SELECTOR, GetGs() & 0xFFF8);
    HvVmWrite(HOST_TR_SELECTOR, trSelector & 0xFFF8);

    // host base addresses
    HvVmWrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
    HvVmWrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));
    HvVmWrite(HOST_TR_BASE, tssBase);
    HvVmWrite(HOST_GDTR_BASE, gdtBase);
    HvVmWrite(HOST_IDTR_BASE, GetIdtBase());

    // host sysenter
    HvVmWrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    HvVmWrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    HvVmWrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

    // host RIP/RSP (exit handler)
    HvVmWrite(HOST_RSP, Vcpu->HostStackTop);
    HvVmWrite(HOST_RIP, reinterpret_cast<u64>(HvVmExitEntryPoint));


    // ==============================================================================
    // Guest State Configuration
    // ==============================================================================

    // control registers
    HvVmWrite(GUEST_CR0, AdjustCr0(__readcr0()));
    HvVmWrite(GUEST_CR3, __readcr3());
    HvVmWrite(GUEST_CR4, AdjustCr4(__readcr4()));
    HvVmWrite(GUEST_DR7, 0x400);

    // guest selectors
    HvVmWrite(GUEST_CS_SELECTOR, GetCs());
    HvVmWrite(GUEST_SS_SELECTOR, GetSs());
    HvVmWrite(GUEST_DS_SELECTOR, GetDs());
    HvVmWrite(GUEST_ES_SELECTOR, GetEs());
    HvVmWrite(GUEST_FS_SELECTOR, GetFs());
    HvVmWrite(GUEST_GS_SELECTOR, GetGs());
    HvVmWrite(GUEST_LDTR_SELECTOR, GetLdtr());
    HvVmWrite(GUEST_TR_SELECTOR, trSelector);

    // guest limits
    HvVmWrite(GUEST_CS_LIMIT, HvGetSegmentLimit(GetCs()));
    HvVmWrite(GUEST_SS_LIMIT, HvGetSegmentLimit(GetSs()));
    HvVmWrite(GUEST_DS_LIMIT, HvGetSegmentLimit(GetDs()));
    HvVmWrite(GUEST_ES_LIMIT, HvGetSegmentLimit(GetEs()));
    HvVmWrite(GUEST_FS_LIMIT, HvGetSegmentLimit(GetFs()));
    HvVmWrite(GUEST_GS_LIMIT, HvGetSegmentLimit(GetGs()));
    HvVmWrite(GUEST_LDTR_LIMIT, HvGetSegmentLimit(GetLdtr()));
    HvVmWrite(GUEST_TR_LIMIT, HvGetSegmentLimit(trSelector));
    HvVmWrite(GUEST_GDTR_LIMIT, GetGdtLimit());
    HvVmWrite(GUEST_IDTR_LIMIT, GetIdtLimit());

    // guest access rights
    HvVmWrite(GUEST_CS_AR_BYTES, HvGetSegmentAr(GetCs()));
    HvVmWrite(GUEST_SS_AR_BYTES, HvGetSegmentAr(GetSs()));
    HvVmWrite(GUEST_DS_AR_BYTES, HvGetSegmentAr(GetDs()));
    HvVmWrite(GUEST_ES_AR_BYTES, HvGetSegmentAr(GetEs()));
    HvVmWrite(GUEST_FS_AR_BYTES, HvGetSegmentAr(GetFs()));
    HvVmWrite(GUEST_GS_AR_BYTES, HvGetSegmentAr(GetGs()));
    HvVmWrite(GUEST_LDTR_AR_BYTES, HvGetSegmentAr(GetLdtr()));
    HvVmWrite(GUEST_TR_AR_BYTES, HvGetSegmentAr(trSelector));

    // guest base addresses
    HvVmWrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
    HvVmWrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
    HvVmWrite(GUEST_GDTR_BASE, gdtBase);
    HvVmWrite(GUEST_IDTR_BASE, GetIdtBase());

    // flat model bases
    HvVmWrite(GUEST_CS_BASE, 0);
    HvVmWrite(GUEST_SS_BASE, 0);
    HvVmWrite(GUEST_DS_BASE, 0);
    HvVmWrite(GUEST_ES_BASE, 0);
    HvVmWrite(GUEST_TR_BASE, tssBase);
    HvVmWrite(GUEST_LDTR_BASE, 0);

    // guest MSRs
    HvVmWrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    HvVmWrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    HvVmWrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    HvVmWrite(GUEST_EFER, __readmsr(MSR_IA32_EFER));

    // PAT (Page Attribute Table)
    u64 pat = __readmsr(MSR_IA32_PAT);
    HvVmWrite(GUEST_PAT, pat);
    HvVmWrite(HOST_PAT, pat);

 // guest execution state
    HvVmWrite(GUEST_ACTIVITY_STATE, 0); // 0 = Active
    HvVmWrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    HvVmWrite(GUEST_VMCS_LINK_PTR, ~0ULL); // Must be -1
    HvVmWrite(GUEST_DEBUGCTL, 0);
    HvVmWrite(GUEST_PENDING_DBG_EXCEPTIONS, 0);
    HvVmWrite(GUEST_SM_BASE, 0);

    // guest RIP/RSP
    HvVmWrite(GUEST_RIP, reinterpret_cast<u64>(GuestIp));
    HvVmWrite(GUEST_RSP, reinterpret_cast<u64>(GuestSp));
    HvVmWrite(GUEST_RFLAGS, GetRflags());

    // ==============================================================================
    // VM Execution Controls
    // ==============================================================================

    u32 pinCtl = 0;
    pinCtl = AdjustControls(pinCtl, MSR_IA32_VMX_TRUE_PINBASED_CTLS);
    HvVmWrite(CONTROL_PIN_BASED_VM_EXECUTION_CONTROLS, pinCtl);

    // Bit 28: Use MSR Bitmaps
    // Bit 31: Use Secondary Controls
    u32 procCtl = (1 << 28) | (1 << 31);
    procCtl = AdjustControls(procCtl, MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
    HvVmWrite(CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, procCtl);

    // Bit 3:  Enable RDTSCP
    // Bit 12: Enable INVPCID (if supported by CPU, strictly optional but good practice)
    // Bit 20: Enable XSAVES/XRSTORS
    u32 secCtl = (1 << 3) | (1 << 12) | (1 << 20);
    secCtl = AdjustControls(secCtl, MSR_IA32_VMX_PROCBASED_CTLS2);
    HvVmWrite(CONTROL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, secCtl);

    // MSR Bitmap Address
    HvVmWrite(CONTROL_MSR_BITMAP_ADDRESS, Vcpu->MsrBitmapPhys);

    // Bit 9: Host Address Space Size (Must be 1 for x64 Host)
    u32 exitCtl = (1 << 9);
    exitCtl = AdjustControls(exitCtl, MSR_IA32_VMX_TRUE_EXIT_CTLS);
    HvVmWrite(CONTROL_VM_EXIT_CONTROLS, exitCtl);

    // Bit 9: IA-32e Mode Guest (Must be 1 for x64 Guest)
    u32 entryCtl = (1 << 9);
    entryCtl = AdjustControls(entryCtl, MSR_IA32_VMX_TRUE_ENTRY_CTLS);
    HvVmWrite(CONTROL_VM_ENTRY_CONTROLS, entryCtl);

    // Set CR0/CR4 Guest/Host Masks
    const u64 guestCr0 = AdjustCr0(__readcr0());
    const u64 guestCr4 = AdjustCr4(__readcr4());

    HvVmWrite(GUEST_CR0, guestCr0);
    HvVmWrite(GUEST_CR4, guestCr4);

    HvVmWrite(CONTROL_CR0_GUEST_HOST_MASK, 0ULL);
    HvVmWrite(CONTROL_CR0_READ_SHADOW, guestCr0);

    HvVmWrite(CONTROL_CR4_GUEST_HOST_MASK, CR4_VMXE);
    HvVmWrite(CONTROL_CR4_READ_SHADOW, guestCr4 & ~CR4_VMXE);

    return true;
}
// ==============================================================================
// Launch Logic
// ==============================================================================


// this ipi callback must return ULONG_PTR to satisfy KIPI_BROADCAST_WORKER
ULONG_PTR EnableHvCallback(ULONG_PTR Context) {
    UNREFERENCED_PARAMETER(Context);
    const u32 id = KeGetCurrentProcessorNumber();
    VcpuContext* vcpu = &g_VcpuData[id];

    const u64 cr0 = AdjustCr0(__readcr0());
    __writecr0(cr0);

    const u64 cr4 = AdjustCr4(__readcr4() | CR4_VMXE);
    __writecr4(cr4);

    // vmxon
    if (!VmxOk(HvVmxOn(&vcpu->VmxOnPhys))) {
        DbgPrint("[HV] VMXON failed on core %u\n", id);
        __writecr4(__readcr4() & ~CR4_VMXE);
        return 0;
    }

    if (!VmxOk(HvVmClear(&vcpu->VmcsPhys))) {
        DbgPrint("[HV] VMCLEAR failed on core %u\n", id);
        HvVmxOff();
        __writecr4(__readcr4() & ~CR4_VMXE);
        return 0;
    }

    if (!VmxOk(HvVmPtrLd(&vcpu->VmcsPhys))) {
        DbgPrint("[HV] VMPTRLD failed on core %u\n", id);
        HvVmxOff();
        __writecr4(__readcr4() & ~CR4_VMXE);
        return 0;
    }

    // ensure setup respects the actual hardware state
    if (!SetupVmcs(vcpu, _AddressOfReturnAddress(), reinterpret_cast<void*>(GuestStartThunk))) {
        HvVmxOff();
        __writecr4(__readcr4() & ~CR4_VMXE);
        return 0;
    }

    vcpu->IsLaunched = true;
    // launch and check the returned rflags for failures
    u64 rflags = HvLaunchGuest();
    vcpu->IsLaunched = false;

    // bit 0 (CF) means vmlaunch failed with no error code available
    // bit 6 (ZF) means vmlaunch failed with error code in VM_INSTRUCTION_ERROR
    if (rflags & (1 << 0) || rflags & (1 << 6)) {
        u64 errorCode = HvVmRead(VM_INSTRUCTION_ERROR);
        DbgPrint("[HV] Launch Failed on core %d with error: 0x%llX\n", id, errorCode);
    }

    // unexpected return path
    HvVmxOff();
    __writecr4(__readcr4() & ~CR4_VMXE);
    return 0;
}

// ==============================================================================
// Stop Logic
// ==============================================================================

// this ipi callback must return ULONG_PTR
ULONG_PTR StopHvCallback(ULONG_PTR Context) {
    UNREFERENCED_PARAMETER(Context);

    __try {
        // use the wrapper defined in arch.asm
        HvCall(HYPERVISOR_MAGIC, VMCALL_UNLOAD, 0, 0);

        // resume here after unload.
        // clean up vmxe bit which vmxoff doesn't touch.
        __writecr4(__readcr4() & ~CR4_VMXE);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // failed to vmcall (vmx likely not running)
    }
    return 0;
}

// ==============================================================================
// Public API
// ==============================================================================

extern "C" NTSTATUS StartHypervisor() {
    int regs[4] = {};
    __cpuidex(regs, 0xD, 0);
    u32 xsaveSize = static_cast<u32>(regs[1]);

    if (xsaveSize > sizeof(GuestContext{}.FxArea)) {
        DbgPrint("[HV] XSAVE area too small: need %u bytes, have %zu\n",
                 xsaveSize, sizeof(GuestContext{}.FxArea));
        return STATUS_NOT_SUPPORTED;
    }

    {
        UCHAR apcState[128] = {};

        KeStackAttachProcess(reinterpret_cast<PRKPROCESS>(PsInitialSystemProcess), apcState);
        g_HostCr3 = __readcr3();
        KeUnstackDetachProcess(apcState);
    }

    g_ProcessorCount = KeQueryActiveProcessorCount(nullptr);

    g_VcpuData = static_cast<VcpuContext*>(
        ExAllocatePoolWithTag(NonPagedPool, sizeof(VcpuContext) * g_ProcessorCount, TAG_HV00)
    );

    if (!g_VcpuData) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_VcpuData, sizeof(VcpuContext) * g_ProcessorCount);

    const u64 vmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
    const u32 vmcsRevisionId = static_cast<u32>(vmxBasic);

    for (u32 i = 0; i < g_ProcessorCount; i++) {
        g_VcpuData[i].VmxOnVirt     = AllocContiguous(PAGE_SIZE, &g_VcpuData[i].VmxOnPhys);
        g_VcpuData[i].VmcsVirt      = AllocContiguous(PAGE_SIZE, &g_VcpuData[i].VmcsPhys);
        g_VcpuData[i].MsrBitmapVirt = AllocContiguous(PAGE_SIZE, &g_VcpuData[i].MsrBitmapPhys);
        if (g_VcpuData[i].MsrBitmapVirt) RtlZeroMemory(g_VcpuData[i].MsrBitmapVirt, PAGE_SIZE);

        g_VcpuData[i].HostStack = ExAllocatePoolWithTag(NonPagedPool, 0x8000, TAG_HVST);
        if (g_VcpuData[i].HostStack) {
            RtlZeroMemory(g_VcpuData[i].HostStack, 0x8000);
            g_VcpuData[i].HostStackTop  = reinterpret_cast<u64>(g_VcpuData[i].HostStack) + 0x8000;
            g_VcpuData[i].HostStackTop &= ~0x3FULL;
        }

        if (g_VcpuData[i].VmxOnVirt) {
            *static_cast<u32 *>(g_VcpuData[i].VmxOnVirt) = vmcsRevisionId;
        }

        if (g_VcpuData[i].VmcsVirt) {
            *static_cast<u32 *>(g_VcpuData[i].VmcsVirt) = vmcsRevisionId;
        }

        if (!g_VcpuData[i].VmxOnVirt || !g_VcpuData[i].VmcsVirt ||
            !g_VcpuData[i].MsrBitmapVirt || !g_VcpuData[i].HostStack) {
                StopHypervisor();
                return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    KeIpiGenericCall(EnableHvCallback, 0);

    u32 ok = 0;
    for (u32 i = 0; i < g_ProcessorCount; i++) if (g_VcpuData[i].IsLaunched) ok++;
    DbgPrint("[HV] Launched on %u/%u processors\n", ok, g_ProcessorCount);
    if (ok == 0) { StopHypervisor(); return STATUS_NOT_SUPPORTED; }

    return STATUS_SUCCESS;
}

extern "C" void StopHypervisor() {
    if (g_VcpuData) {
        // broadcast unload signal
        KeIpiGenericCall(StopHvCallback, 0);

        // free memory
        for (u32 i = 0; i < g_ProcessorCount; i++) {
            if (g_VcpuData[i].VmxOnVirt) MmFreeContiguousMemory(g_VcpuData[i].VmxOnVirt);
            if (g_VcpuData[i].VmcsVirt)  MmFreeContiguousMemory(g_VcpuData[i].VmcsVirt);
            if (g_VcpuData[i].MsrBitmapVirt) MmFreeContiguousMemory(g_VcpuData[i].MsrBitmapVirt);
            if (g_VcpuData[i].HostStack) ExFreePoolWithTag(g_VcpuData[i].HostStack, TAG_HVST);
        }
        ExFreePoolWithTag(g_VcpuData, TAG_HV00);
        g_VcpuData = nullptr;
    }
}