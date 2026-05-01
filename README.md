# KOSCH - Custom x64 Kernel Driver Framework

## Overview

KOSCH is a custom x64 single-threaded kernel driver and user-mode loader designed for advanced system manipulation and testing in virtualized environments. The framework provides primitives for memory read/write, process hiding (DKOM), module enumeration, and VA-to-PA translation, with a stealthy manual mapping approach to evade detection. This project is intended for educational and research purposes in controlled environments only.

**Warning:** This software interacts with kernel-mode components and can cause system instability, BSOD, or permanent damage if misused. Use exclusively in VMs and at your own risk. Not suitable for production systems.

## Features

- **Stealthy Driver Loading:** Manual PE mapping into kernel space without service registration or common tools like KDmapper.
- **Kernel Primitives:**
  - Memory R/W across processes
  - Process hiding/unhiding via DKOM
  - Module base resolution
  - PEB retrieval
  - VA-to-PA translation
- **User-Kernel Communication:** Bootstrap-based shared memory for command dispatching.
- **Extensible Framework:** Modular dispatch system for adding custom operations.

## Requirements

- **Operating System:** Windows 10/11 x64 (tested on 10.0.19045)
- **Build Tools:**
  - Microsoft Visual Studio 2022 with C++ support
  - Windows Driver Kit (WDK) 10.0.26100.0 or later
  - CMake 3.20+
  - Python 3.x (for header generation)
- **Privileges:** Administrator access; SE_DEBUG_PRIVILEGE and SE_LOAD_DRIVER_PRIVILEGE enabled.
- **Environment:** Run in a VM (e.g., VirtualBox, VMware) to avoid host system damage.

## Build Instructions

1. **Clone/Download:** Ensure the project is in `C:\Users\<user>\Desktop\kosch` (or adjust paths).

2. **Build Driver:**
   ```
   cd driver
   build.bat
   ```
   - Outputs: `driver\build\koshchei.sys` (~11KB encrypted binary).

3. **Generate Loader Header:**
   ```
   python loader/tools/bin2h.py driver/build/koshchei.sys loader/src/koshchei_drv.h koshchei_drv
   ```
   - Embeds encrypted driver data into loader source.

4. **Build Loader:**
   ```
   cmake -B loader/build -S loader
   cmake --build loader/build --config Release
   ```
   - Outputs: `loader\build\bin\Release\koshchei.exe` (~50-100KB).

5. **Verify Builds:** Both files should exist without errors.

## Usage

1. **Run Loader:** As administrator in VM:
   ```
   loader\build\bin\Release\koshchei.exe
   ```

2. **Monitor Output:** Successful execution shows ping OK; loader holds for interaction. Interrupt with Ctrl+C.

3. **Integration with HL.exe:** Extend loader to communicate with target process using Windows APIs (e.g., DeviceIoControl for IOCTL-based interface).

## Execution Analysis

### Step-by-Step Flow (from Sample Output)

The loader follows a 12-step process:

1. **Init:** Secure setup.
2. **Privilege Checks:** Enable debug/load driver privileges.
3. **Kernel Module Enumeration:** Locate ntoskrnl.exe (VA: 0xFFFFF80644000000, size: 0x1046000).
4. **Driver Loading:** Initialize TBT for kernel R/W.
5. **ntoskrnl Phys Base:** Resolve PA (0x2400000) via PTE walking.
6. **Kernel R/W Verification:** Confirm MZ signature read.
7. **NtClose Gate Installation:** Hook syscall (VA: 0xFFFFF8064463E0A0, PA: 0x2A3E0A0); allocate gate pool (VA: 0xFFFF868190D3B000, PA: 0x42B26E000).
8. **Driver PE Parsing:** Extract metadata (base: 0x140000000, size: 0x7000, entry: 0x19D0, 5 sections, 0 relocs, 1 import).
9. **Kernel Mapping:** Allocate pool (VA: 0xFFFF868190F8E000, PA: 0x4227F2000), copy sections, patch IAT.
10. **NX_BRIDGE Prefill:** Write bootstrap at 0xFFFF868190F92000 (PID: 11468).
11. **DriverEntry Call:** Success (return 0x0); retrieve dispatch VA (0xFFFF868190F8FAB0).
12. **Ping Test:** OK; cleanup traces (3775 IOCTLs issued); hold.

### Key Data Significance

- **Addresses:** VAs/PAs indicate memory layout; e.g., kernel base for offsets.
- **Sizes:** Driver ~28KB; reflects minimal footprint.
- **PIDs/Returns:** Validation of operations (e.g., 0x0 = success).
- **Counts:** IOCTLs show kernel interaction intensity.

### Available Kernel Functions

Interact via dispatch at `dispatch_va` (write DX_* structs to cmd_buf, invoke via gate):

- `CMD_PING`: Test connection.
- `CMD_READ_MEMORY`: Read process memory.
- `CMD_WRITE_MEMORY`: Write process memory.
- `CMD_GET_MODULE_BASE`: Get DLL base.
- `CMD_GET_PEB`: Retrieve PEB.
- `CMD_HIDE_PROCESS`: DKOM hide.
- `CMD_UNHIDE_PROCESS`: Unhide.
- `CMD_HIDE_DRIVER`: Placeholder.
- `CMD_TRANSLATE_VA`: VA to PA.
- `CMD_QUERY_STATE`: Init status.

## Extensions and Manipulation

### Feasibility: High
Modular design allows easy additions. Use Windows APIs in user-mode for data prep; kernel handles privileged tasks.

### Methods

1. **Thread Hijacking/APC Injection:**
   - Add `CMD_INJECT_APC`; kernel allocates remote memory, queues APC.
   - User-mode: `VirtualAllocEx`, `WriteProcessMemory` for payload.

2. **Pattern Scanning:**
   - Add `CMD_SCAN_PATTERN`; kernel searches target memory.
   - User-mode: Delegate large scans to kernel.

3. **Syscall Hooking (SSDT):**
   - Add `CMD_HOOK_SYSCALL`; patch SSDT entries.
   - User-mode: Stage hook in memory.

4. **IOCTL Interface:**
   - Create device (`\Device\Koshchei`); add IRP handlers.
   - User-mode: `DeviceIoControl` for standard API access.

5. **General Workflow:**
   - Define new structs/handlers.
   - Test via loader; rebuild as needed.

## Troubleshooting

- **Build Fails:** Ensure WDK/VS paths match `build.bat`. Install missing tools.
- **Loader Fails:** Check privileges; run as admin. Hypervisor detection may warn but not block.
- **Ping Fails:** Verify kernel R/W; relaunch loader.
- **BSOD:** Common in kernel work; isolate to VM.

## License

None. For personal/research use only.

## Contact

Report issues at https://github.com/Kilo-Org/kilocode/issues (use Kilo for queries).