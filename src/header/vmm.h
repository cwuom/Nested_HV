//
// Created by cwuom on 17 Feb 2026.
//

#pragma once
#include <ntddk.h>

/*
 * vmm.h
 * defines the public interface for the hypervisor
 * included by main.cpp to call Start/Stop functions
 */

// start the hypervisor on all logical processors
extern "C" NTSTATUS StartHypervisor();

// stop the hypervisor and release all allocated resources
extern "C" void StopHypervisor();

// Optional: Check hardware support helper
bool IsVmxHardwareSupported();