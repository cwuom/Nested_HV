# Nested-HV

![IDE](https://img.shields.io/badge/IDE-CLion%20(CMake)-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue)
![Standard](https://img.shields.io/badge/Standard-C%2B%2B17-blue)
![Tested](https://img.shields.io/badge/Tested-Windows%2011%2025H2-green)

**Nested-HV** is a minimalistic Type-2 Hypervisor (Blue Pill) implementation for Intel Processors based on VT-x technology.

Designed for research and educational purposes, it subverts the running operating system into a virtual machine on the fly. It is fully compatible with modern Windows environments, specifically optimized for **Windows 11 (Build 26100+)**.

## Features

* **Blue Pill Architecture**: Seamlessly transitions the OS into a VM without rebooting.
* **Nested Compatible**: Runs stable inside other hypervisors (e.g., VMware Workstation with VT-x enabled) and on bare metal hardware (tested on **i7-14700KF**).
* **State Transparency**: Preserves full GPR and Extended State (XSave/XRstor).
* **Modern Toolchain**: Built using **CLion**, **CMake**, and **Ninja** with MSVC.

## Roadmap

* **Nested Virtualization Support**: Future updates will implement VMX instruction emulation to support running Hyper-V/WSL2 inside the Guest.
* **EPT (Extended Page Tables)**: Implementation of SLAT for memory hiding.

## Important Note on Manual Mapping

If you plan to load this driver using **kdmapper**:
1.  **Define `USE_KDMAPPER`**: You must add `-DUSE_KDMAPPER=ON` to your CMake options.
2.  **No Unload Support**: The driver unload callback is disabled in this mode to prevent BSODs. A system restart is required to stop the hypervisor.

## Build Instructions (CLion)

### Prerequisites
* **CLion** (with bundled Ninja & CMake).
* **Visual Studio 2022** (C++ Desktop Development workload).
* **Windows Driver Kit (WDK)** (Tested with version **10.0.26100.0**).

### Configuration
1.  Clone the repository.
2.  Open the project folder in **CLion**.
3.  **Crucial**: Open `CMakeLists.txt` and verify the WDK paths match your installation:
    ```cmake
    # Update this path to your WDK installation
    set(ENV{WDKContentRoot} "E:/Windows Kits/10") 
    
    # Update the library version if necessary
    set(WDK_KM_LIBS "E:/Windows Kits/10/Lib/10.0.26100.0/km/x64")
    ```
4.  Reload the CMake project.

### Compilation
1.  Select the `Nested_HV` target in CLion.
2.  Build (Ctrl+F9).
3.  The output driver `Nested_HV.sys` will be generated in `cmake-build-debug` (or release).

## License

MIT License.