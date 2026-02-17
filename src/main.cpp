//
// Created by cwuom on 17 Feb 2026.
//

#include <intrin.h>
#include <ntddk.h>

#include "header/common.h"
#include "header/vmm.h"



// hardware check
bool IsVmxSupported() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 5))) return false; // ECX Bit 5 = VMX

    u64 featureControl = __readmsr(0x3A);
    if (!(featureControl & 1)) return false; // lock a bit missing
    if (!(featureControl & 4)) return false; // VMX outside SMX missing

    return true;
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[HV] Unloading...\n");
    StopHypervisor();
    DbgPrint("[HV] Stopped.\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[HV] Driver Entry.\n");

    if (!IsVmxSupported()) {
        DbgPrint("[HV] VMX not supported or disabled in BIOS.\n");
        return STATUS_NOT_SUPPORTED;
    }

#ifndef USE_KDMAPPER
    DriverObject->DriverUnload = DriverUnload;
#endif

    NTSTATUS status = StartHypervisor();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV] Failed to start: 0x%X\n", status);
        StopHypervisor();
        return status;
    }

    DbgPrint("[HV] Blue Pill Installed Successfully.\n");
    return STATUS_SUCCESS;
}