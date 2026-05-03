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
- **User-Kernel Communication:** Synchronous communication via a shared buffer allocated in user mode and accessed by the driver through a virtual address passed during bootstrap.
- **Extensible Framework:** Modular dispatch system for adding custom operations.

## Requirements

- **Operating System:** Windows 10 x64 build 19045 (hardcoded offsets specific to this build)
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
    - Outputs: `driver\build\koshchei.sys` (~11KB XOS-encrypted binary).

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

3. **Integration with HL.exe:** Extend loader to communicate with target process using the provided kernel primitives via the dispatch mechanism.

## Execution Analysis

### Bootstrap Sequence

The loader follows an 11-step bootstrap process:

1. **Privilege and Environment Checks:** Enable required privileges and check environment.
2. **Kernel Module Enumeration:** Locate ntoskrnl.exe base address and size.
3. **Driver Loading:** Initialize TBT for kernel read/write access. Note: tbt.sys is a temporary driver used exclusively for physical memory access during the bootstrap phase and is subsequently removed.
4. **Discovering ntoskrnl Physical Base:** Resolve physical address via PTE walking.
5. **Kernel R/W Verification:** Confirm ability to read kernel memory by checking MZ signature.
6. **NtClose Gate Installation:** Install syscall hook and allocate gate pool.
7. **Driver PE Parsing:** Decrypt and parse the driver binary using XOS algorithm.
8. **Kernel Mapping:** Allocate kernel pool, map driver sections, and patch imports.
9. **NX_BRIDGE Prefill:** Write bootstrap data including command buffer virtual address.
10. **DriverEntry Call:** Invoke driver entry point and retrieve dispatch virtual address.
11. **Cleaning Traces:** Remove temporary components and traces.

### Communication Mechanism

The loader allocates a 4096-byte buffer via VirtualAlloc, populates it with a DX_HDR and the payload, and passes the virtual address to the driver via the NX_BRIDGE. Communication is executed by calling the driver's dispatch routine through the NtClose gate. The driver processes the request and writes the response directly into the same buffer, which the loader reads upon returning. This mechanism is synchronous and does not utilize polling. The communication buffer is not explicitly freed because the loader remains resident in memory during operation.

### Available Kernel Functions

Interact via dispatch at `dispatch_va` (write DX_* structs to cmd_buf, invoke via gate):

- `CMD_PING`: Test connection.
- `CMD_READ_MEMORY`: Read process memory.
- `CMD_WRITE_MEMORY`: Write process memory.
- `CMD_GET_MODULE_BASE`: Get DLL base.
- `CMD_GET_PEB`: Retrieve PEB.
- `CMD_HIDE_PROCESS`: DKOM hide.
- `CMD_UNHIDE_PROCESS`: Unhide.
- `CMD_TRANSLATE_VA`: VA to PA.

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



## Technical Deep Dive

### 1. Memory Operations & Buffer Layout

The framework uses a 4096-byte buffer for user-kernel communication, allocated in user-mode via `VirtualAlloc` and passed via NX_BRIDGE. This buffer serves as the command input and response output.

#### Buffer Layout Overview
- **Header (DX_HDR, 12 bytes):**
  - `magic` (4 bytes): Validation constant (NX_MAGIC).
  - `cmd` (4 bytes): Command ID (e.g., CMD_READ_MEMORY).
  - `size` (4 bytes): Total command size including header.
- **Command-Specific Data:** Variable, appended after header.
- **Response (DX_RSP, 16+ bytes):**
  - `magic` (4 bytes): Echo of NX_MAGIC.
  - `status` (4 bytes): NTSTATUS (0 = success).
  - `value` (8 bytes): Primary result (e.g., address or length).
  - `data[]`: Optional variable data.

#### Read Memory from Target Process
- **Mechanism:** Kernel calls `Vx_Read`, which uses `MmCopyVirtualMemory` to copy from target process to kernel buffer, then to user buffer.
- **Constraints:** Max length = DX_BUF_SIZE - sizeof(DX_RSP) (~4080 bytes); address must be valid in target; process must exist.
- **Data Integrity Checks:** Size validation (hdr->size >= sizeof(DX_READ)); length <= buffer limits; NT_SUCCESS on copy.
- **Step-by-Step:**
  1. Parse DX_READ from buffer.
  2. Find target process via Sx_FindProcess.
  3. Call MmCopyVirtualMemory (target -> current process).
  4. Write response to buffer.

#### Write Memory to Target Process
- **Mechanism:** Kernel calls `Vx_Write`, using `MmCopyVirtualMemory` to copy from user buffer to target.
- **Constraints:** Data size <= length field; total cmd size <= DX_BUF_SIZE; write permissions required.
- **Data Integrity Checks:** Size validation (hdr->size >= sizeof(DX_WRITE)); data length matches; success if bytes copied == length.
- **Step-by-Step:**
  1. Parse DX_WRITE from buffer.
  2. Find target process.
  3. Call MmCopyVirtualMemory (current -> target).
  4. Write response.

### 2. The "Magic" Mechanism

The "magic" mechanism uses hardcoded constants for validation, preventing unauthorized or malformed commands from executing.

- **Underlying Logic:** Constants defined in `constants.h` (NX_SEED, NX_MAGIC, sentinels). NX_MAGIC = NX_SEED ^ 0x3D8F1A7E (0x9A7BDDC6). Sentinels (NX_SENTINEL1/2) mark bootstrap location.
- **Validation:**
  - Commands validated if hdr->magic == NX_MAGIC; else ACCESS_DENIED.
  - Bootstrap detected by sentinel scan in data section.
  - Responses echo magic for consistency.
- **Sequence of Operations:**
  1. Loader writes sentinels + VA/PID/flag to bootstrap.
  2. Kernel checks sentinels on entry; sets dispatch VA.
  3. Dispatch validates magic per command.
- **Interaction with Environment:** Ensures commands originate from loader; XOS encryption on driver binary adds obscurity.

### 3. Advanced Memory Translation Workflow (VA-PA Manipulation)

This workflow enables direct physical memory access, bypassing virtual mappings for low-level manipulation.

#### Virtual-to-Physical Translation
- **Process:** Walk x64 page tables using CR3 from process EPROCESS.
- **Step-by-Step:**
  1. Get CR3 via Vx_GetCr3 (proc + offset).
  2. Map PML4 (CR3 & ~0xFFF) via MmMapIoSpace.
  3. Extract PML4E; check present bit.
  4. Repeat for PDPT, PD, PT (handling 1GB/2MB large pages).
  5. Compute PA: (PTE & mask) | (VA & offset).
- **Architectural Context:** x64 4-level paging; uses MmMapIoSpace for PA access.

#### Physical Memory Modification
- **Methodology:** Map PA to kernel VA with MmMapIoSpace (MmNonCached); write directly.
- **Step-by-Step:**
  1. Translate VA to PA.
  2. Allocate kernel VA for mapping: MmMapIoSpace(PA, size).
  3. Write data to mapped VA.
  4. Unmap: MmUnmapIoSpace.
- **Constraints:** PA must be valid; size <= PAGE_SIZE multiples.

#### Re-translation & Integrity
- **Process:** After physical write, re-walk tables if needed (rare, as PA fixed). Integrity via checksums or re-read.
- **Step-by-Step:**
  1. Optionally re-translate to verify.
  2. Read back via mapped VA or Vx_Read.

#### Result Injection
- **Mechanism:** For user process, changes are immediate (physical). To return data, use Vx_Read or direct mapping.
- **Step-by-Step:**
  1. Modify physical memory.
  2. If injecting to process, ensure VA points to modified PA.
  3. Respond with status/value.
- **Architectural Context:** Direct PA writes persist across contexts.



## License

None. For personal/research use only.
