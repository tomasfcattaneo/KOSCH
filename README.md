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

## Technical Deep Dive

### 1. Memory Operations & Buffer Layout

The framework uses a shared 4096-byte buffer (`DX_BUF_SIZE`) for user-kernel communication, allocated in user-mode via `VirtualAlloc` and passed via bootstrap. This buffer serves as the command input and response output, ensuring efficient data exchange without additional allocations.

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

**Architectural Context:** Buffer is mapped read-write in user space; kernel accesses via VA in bootstrap. Side effects: Potential race conditions if concurrent commands; mitigated by single-threaded design.

#### Read Memory from Target Process
- **Mechanism:** Kernel calls `Vx_Read`, which uses `MmCopyVirtualMemory` to copy from target process to kernel buffer, then to user buffer.
- **Constraints:** Max length = DX_BUF_SIZE - sizeof(DX_RSP) (~4080 bytes); address must be valid in target; process must exist.
- **Data Integrity Checks:** Size validation (hdr->size >= sizeof(DX_READ)); length <= buffer limits; NT_SUCCESS on copy.
- **Step-by-Step:**
  1. Parse DX_READ from buffer.
  2. Find target process via Sx_FindProcess.
  3. Call MmCopyVirtualMemory (target -> current process).
  4. Write response to buffer.
- **Side Effects:** Temporary kernel buffer usage; potential page faults if address invalid.

#### Write Memory to Target Process
- **Mechanism:** Kernel calls `Vx_Write`, using `MmCopyVirtualMemory` to copy from user buffer to target.
- **Constraints:** Data size <= length field; total cmd size <= DX_BUF_SIZE; write permissions required.
- **Data Integrity Checks:** Size validation (hdr->size >= sizeof(DX_WRITE)); data length matches; success if bytes copied == length.
- **Step-by-Step:**
  1. Parse DX_WRITE from buffer.
  2. Find target process.
  3. Call MmCopyVirtualMemory (current -> target).
  4. Write response.
- **Side Effects:** Direct memory modification; no undo; can corrupt target if invalid data.

### 2. The "Magic" Mechanism

The "magic" mechanism uses hardcoded constants for validation and synchronization, preventing unauthorized or malformed commands from executing.

- **Underlying Logic:** Constants defined in `constants.h` (NX_SEED, NX_MAGIC, sentinels). NX_MAGIC = NX_SEED ^ 0x3D8F1A7E (0x9A7BDDC6). Sentinels (NX_SENTINEL1/2) mark bootstrap location.
- **Triggers/Algorithms:** 
  - Commands validated if hdr->magic == NX_MAGIC; else ACCESS_DENIED.
  - Bootstrap detected by sentinel scan in data section.
  - Responses echo magic for consistency.
- **Sequence of Operations:**
  1. Loader writes sentinels + VA/PID/flag to bootstrap.
  2. Kernel checks sentinels on entry; sets dispatch VA.
  3. Dispatch validates magic per command.
- **Interaction with Environment:** Ensures commands originate from loader; XOR encryption on driver binary adds obscurity. Side effects: False positives if magic collides; low risk due to randomness.

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
- **Architectural Context:** x64 4-level paging; uses MmMapIoSpace for PA access. Side effects: Temporary mappings; resource exhaustion if many calls.

#### Physical Memory Modification
- **Methodology:** Map PA to kernel VA with MmMapIoSpace (MmNonCached); write directly.
- **Step-by-Step:**
  1. Translate VA to PA.
  2. Allocate kernel VA for mapping: MmMapIoSpace(PA, size).
  3. Write data to mapped VA.
  4. Unmap: MmUnmapIoSpace.
- **Constraints:** PA must be valid; size <= PAGE_SIZE multiples. Side effects: Bypasses protections; can corrupt memory.

#### Re-translation & Integrity
- **Process:** After physical write, re-walk tables if needed (rare, as PA fixed). Integrity via checksums or re-read.
- **Step-by-Step:**
  1. Optionally re-translate to verify.
  2. Read back via mapped VA or Vx_Read.
- **Side Effects:** TLB invalidation may be needed (KeFlushEntireTb); inconsistencies if paging changes.

#### Result Injection
- **Mechanism:** For user process, changes are immediate (physical). To return data, use Vx_Read or direct mapping.
- **Step-by-Step:**
  1. Modify physical memory.
  2. If injecting to process, ensure VA points to modified PA.
  3. Respond with status/value.
- **Architectural Context:** Direct PA writes persist across contexts. Side effects: Requires careful VA-PA alignment; potential data races.

## Technical Feasibility Study: Driverless DeviceIoControl Implementation

### Overview
This study evaluates the feasibility of achieving kernel-mode interaction or IPC via `DeviceIoControl` and IOCTL codes without deploying a custom kernel-mode driver or creating a dedicated device object. The analysis draws from Windows I/O subsystem architecture, focusing on architectural necessities, alternatives, workarounds, security, and recommendations.

### 1. Architectural Constraints
The Windows I/O Manager mandates a device object as the endpoint for `IRP_MJ_DEVICE_CONTROL` requests. `DeviceIoControl` internally creates an IRP with major function `IRP_MJ_DEVICE_CONTROL`, routing it to the target device's stack via the I/O Manager.

- **Requirement of Device Object:** `IoCreateDevice` instantiates a DEVICE_OBJECT, which holds the device extension, flags, and pointers to dispatch routines. Without this, no valid handle exists for `DeviceIoControl` to target. The function fails with `ERROR_INVALID_HANDLE` if the device path doesn't resolve to a device object.

- **Dispatch Routine Tie-In:** Each device object references a DRIVER_OBJECT, whose MajorFunction array (index `IRP_MJ_DEVICE_CONTROL`) points to a dispatch routine (e.g., `Dx_Ioctl`). This routine processes IOCTL codes, validates buffers, and performs operations. Absent a custom driver, no dispatch routine can handle custom IOCTLs, as system drivers have predefined handlers.

- **Fundamental Barrier:** The I/O subsystem enforces this for security and stability—IRP routing ensures controlled access. Bypassing requires kernel-mode code to alter dispatch pointers, which defeats the "driverless" premise.

### 2. Alternative Interface Vectors
Leveraging existing system device objects (e.g., `\Device\HarddiskVolumeX` for disks, `\Device\PhysicalMemory` for memory) to proxy custom IOCTL communication is theoretically possible but impractical.

- **Viability Assessment:**
  - **Proxying:** Send IOCTLs to existing devices and interpret responses as tunneled data. For example, encode custom data in unused fields of disk IOCTLs (e.g., `IOCTL_DISK_GET_DRIVE_LAYOUT`).
  - **Feasibility:** Low. System devices have rigid handlers; custom data would be ignored or cause errors. `\Device\PhysicalMemory` requires special privileges and doesn't support arbitrary IOCTLs.
  - **Third-Party Drivers:** Objects like those from antivirus drivers could be targeted, but their IOCTLs are undocumented and change with updates.

- **Limitations:** No guarantee of custom processing; risks misinterpretation or system errors. Requires reverse-engineering target drivers, which is unstable and illegal without consent.

### 3. Workaround Mechanisms
Alternative "IOCTL-style" patterns for driverless kernel interaction:

- **ALPC (Advanced Local Procedure Call):**
  - **Efficiency:** High; low-latency, asynchronous messaging between user/kernel (via `NtAlpcSendWaitReceivePort`).
  - **Security:** Strong; ACL-based, supports impersonation.
  - **Complexity:** Moderate; requires setting up ALPC ports in kernel (needs driver for server side).
  - **Comparison:** Suitable for IPC but not pure kernel interaction without driver code.

- **Shared Memory (Section Objects):**
  - **Efficiency:** Excellent; direct access via `ZwMapViewOfSection`.
  - **Security:** Depends on ACLs; vulnerable to tampering.
  - **Complexity:** Low for basic sharing, but synchronization (events/mutexes) adds overhead.
  - **Comparison:** Ideal for data exchange; integrity via checksums; no built-in commands like IOCTL.

- **Named Pipes/RPC:**
  - **Efficiency:** Moderate; RPC has marshalling overhead; pipes are stream-based.
  - **Security:** ACLs, encryption possible.
  - **Complexity:** Low; `CreateNamedPipe` or RPC tools.
  - **Comparison:** User-user focused; kernel extension requires driver (e.g., via FSD).

- **Windows Filtering Platform (WFP) or Callback Routines:**
  - **Efficiency:** Variable; callbacks add latency.
  - **Security:** Kernel-level; high privilege needed.
  - **Complexity:** High; registering callbacks requires driver.
  - **Comparison:** For intercepting traffic, not direct IOCTL emulation.

Overall, shared memory offers the best driverless kernel data exchange, but lacks command structure.

### 4. Security and Privilege Implications
Hijacking or using existing device objects poses severe risks:

- **ACL Restrictions:** Device objects have ACLs; unauthorized access triggers `STATUS_ACCESS_DENIED`. Escalation requires `SeLoadDriverPrivilege` or kernel exploits.

- **Driver Signature Enforcement (DSE):** Windows enforces signed drivers; unsigned code (e.g., for hijacking) is blocked, requiring test mode or bypasses that alert EDR.

- **EDR Heuristics:** Unusual IOCTLs to system devices flag as suspicious. Hijacking attempts (e.g., patching dispatch routines) are detected as rootkits, triggering alerts or blocks.

- **Privilege Needs:** `SeDebugPrivilege` for process access; kernel interaction demands SYSTEM-level. Risks include permanent system damage or legal issues.

### 5. Conclusion and Recommendation
A "driverless" `DeviceIoControl` implementation is **not architecturally sound**. The I/O subsystem fundamentally requires a device object with a dispatch routine for IOCTL handling, making pure user-mode proxies unstable and insecure. Hijacking existing objects violates security models and is detectable.

**Recommendation:** Retain the current manual mapping approach for stealth. For IOCTL-style access, extend the driver with `IoCreateDevice` as outlined earlier—it's robust, with low latency (direct IRP), high throughput (buffered I/O), and stability (controlled dispatch). Latency: <1ms; Throughput: ~100MB/s via buffered IOCTLs; Stability: High in VMs.

For driverless alternatives, use **shared memory** with synchronization primitives for IPC, supplemented by ALPC for commands. This avoids custom drivers while maintaining performance.

## Detailed Explanation: Shared Memory Concept

### 1. Definición y Fundamentos
La memoria compartida (Shared Memory) es un mecanismo de comunicación interprocesos (IPC) que permite a múltiples procesos acceder directamente al mismo segmento de memoria física. A diferencia del paso de mensajes (Message Passing), donde los datos se copian entre procesos a través de buffers del kernel (como en pipes o sockets), la memoria compartida elimina la copia intermedia al mapear la misma región de memoria física en los espacios de direcciones virtuales de los procesos involucrados.

- **Fundamentos Técnicos:** En sistemas operativos modernos (como Linux/Unix con POSIX o Windows), la memoria compartida se basa en objetos de sección (section objects) o segmentos de memoria anónima. Un proceso crea o abre un segmento compartido, y otros procesos lo mapean en su espacio de direcciones. Esto resulta en múltiples entradas en tablas de páginas (page tables) apuntando a las mismas páginas físicas, optimizando el acceso sin sobrecargar el kernel en transferencias de datos.

- **Diferenciación con Message Passing:** Mientras Message Passing implica syscalls (e.g., `write`/`read`) que copian datos al kernel y luego al receptor, Shared Memory permite acceso directo, reduciendo latencia y CPU overhead. Sin embargo, requiere sincronización manual para evitar corrupción.

### 2. Mecanismo de Funcionamiento
El proceso de manejo de memoria compartida involucra tres fases principales: creación, mapeo y desmapeo.

- **Creación:** Un proceso crea un segmento usando APIs como `shmget` (POSIX) o `CreateFileMapping` (Windows). Se especifica el tamaño y un nombre/clave para identificación. El kernel asigna páginas físicas y crea un objeto compartido.

- **Mapeo:** Procesos llaman a `shmat` (POSIX) o `MapViewOfFile` (Windows) para mapear el segmento en su espacio virtual. El kernel actualiza las tablas de páginas para que direcciones virtuales apunten a las mismas páginas físicas. El mapeo puede ser read-only, read-write, o con protecciones específicas.

- **Desmapeo:** `shmdt` o `UnmapViewOfFile` remueve el mapeo del espacio virtual. Si es el último proceso, el kernel puede liberar la memoria (dependiendo de flags como `IPC_RMID`).

- **Consideraciones Arquitecturales:** En x64, el TLB (Translation Lookaside Buffer) acelera traducciones VA-PA. Cambios requieren invalidación TLB si se modifica mapeo. En NUMA, proximidad de memoria afecta rendimiento.

### 3. Casos de Uso Reales
La memoria compartida es ideal para escenarios de alto rendimiento con grandes volúmenes de datos:

- **Procesamiento de Señales en Tiempo Real:** Aplicaciones como DAWs (Digital Audio Workstations) usan shared memory para buffers de audio, evitando latencia de copia en pipelines de efectos.

- **Bases de Datos de Alto Rendimiento:** Sistemas como PostgreSQL usan shared memory para buffers compartidos entre procesos servidor, reduciendo I/O disk y mejorando throughput (e.g., 10-100x vs. message passing).

- **Transferencia de Grandes Volúmenes de Datos:** En HPC (High-Performance Computing), procesos paralelos comparten matrices grandes para simulaciones científicas, minimizando overhead de MPI (Message Passing Interface).

- **Ejemplos Específicos:** En Windows, `GlobalAlloc` con `GMEM_SHARE` para clipboard; en Linux, `/dev/shm` para tmpfs-based sharing.

### 4. El Problema de la Sincronización
Sin sincronización, múltiples procesos accediendo concurrentemente causan race conditions y corrupción.

- **Riesgos Detallados:** Un proceso escribe mientras otro lee, resultando en datos inconsistentes (e.g., partial writes). En arquitecturas multicore, cache coherency (MESI protocol) no garantiza orden sin barreras.

- **Soluciones con Primitivas:**
  - **Semáforos:** Contadores para controlar acceso (e.g., `sem_wait`/`sem_post` en POSIX). Binarios para exclusión mutua; contadores para límites.
  - **Mutexes:** Locks binarios (e.g., `pthread_mutex_lock`). Bloquean thread hasta liberación; evitan starvation con fairness.
  - **Spinlocks:** Busy-wait locks (e.g., `spin_lock` en kernel). Eficientes para secciones cortas, pero consumen CPU.

- **Implementación:** Usar mutex para proteger writes/reads; semáforos para producer-consumer. Ejemplo: Producer signals semaphore post-write; consumer waits pre-read.

### 5. Implementación Técnica
Ejemplo en C usando POSIX (Linux/Unix). Para Windows, usar `CreateFileMapping`/`MapViewOfFile`.

**Productor (Crea y Escribe):**
```c
#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>

#define SHM_KEY 1234
#define SHM_SIZE 1024

int main() {
    int shmid = shmget(SHM_KEY, SHM_SIZE, IPC_CREAT | 0666);
    char *shm_ptr = (char *)shmat(shmid, NULL, 0);
    
    sem_t *sem = sem_open("/mysem", O_CREAT, 0666, 0);  // Semaphore for sync
    
    strcpy(shm_ptr, "Hello from producer");
    sem_post(sem);  // Signal consumer
    
    sleep(1);  // Wait for consumer
    shmdt(shm_ptr);
    shmctl(shmid, IPC_RMID, NULL);
    sem_close(sem);
    return 0;
}
```

**Consumidor (Lee):**
```c
#include <sys/shm.h>
#include <semaphore.h>

#define SHM_KEY 1234

int main() {
    int shmid = shmget(SHM_KEY, SHM_SIZE, 0666);
    char *shm_ptr = (char *)shmat(shmid, NULL, 0);
    
    sem_t *sem = sem_open("/mysem", 0);
    sem_wait(sem);  // Wait for producer
    
    printf("%s\n", shm_ptr);
    shmdt(shm_ptr);
    sem_close(sem);
    return 0;
}
```

**Windows Ejemplo (Pseudocódigo):**
```cpp
HANDLE hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1024, "MySharedMem");
char *ptr = (char *)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 1024);
// Write/read
UnmapViewOfFile(ptr);
CloseHandle(hMap);
```

### 6. Ventajas y Desventajas
- **Ventajas:** Velocidad excepcional (latencia <1μs vs. 10-100μs en message passing; throughput >1GB/s). Baja CPU overhead, ideal para datos grandes.
- **Desventajas:** Complejidad de sincronización (bugs comunes); seguridad baja (acceso directo expone a exploits); gestión manual de lifecycle. Comparado con message passing, shared memory es más rápido pero menos seguro y portable.

En resumen, shared memory es poderosa para rendimiento, pero requiere expertise en concurrencia.

## License

None. For personal/research use only.
