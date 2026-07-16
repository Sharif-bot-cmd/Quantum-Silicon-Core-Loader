; ============================================================================
; QSLCL MICRO-VM SPECIFICATION v5.8
; ============================================================================
; This specification defines the instruction set architecture (ISA) for the
; QSLCL micro-VM. It is architecture-agnostic and designed to be implemented
; on any target hardware (ARM, x86, RISC-V, MIPS, PowerPC, etc.)
;
; The implementation in build.py generates bytecode according to this spec.
; This is a PURE specification - it does NOT contain device-specific routines.
; ============================================================================

; ============================================================================
; SECTION 1: DATA TYPES & REGISTERS
; ============================================================================

; ============================================================================
; 1.1: Registers (16 general-purpose registers)
; ============================================================================

R0      EQU 0x00   ; General purpose / return value
R1      EQU 0x01   ; General purpose
R2      EQU 0x02   ; General purpose
R3      EQU 0x03   ; General purpose
R4      EQU 0x04   ; General purpose
R5      EQU 0x05   ; General purpose
R6      EQU 0x06   ; General purpose
R7      EQU 0x07   ; General purpose
R8      EQU 0x08   ; General purpose
R9      EQU 0x09   ; General purpose
R10     EQU 0x0A   ; General purpose
R11     EQU 0x0B   ; General purpose
R12     EQU 0x0C   ; General purpose
R13     EQU 0x0D   ; Stack pointer (grows down)
R14     EQU 0x0E   ; Link register (return address)
R15     EQU 0x0F   ; Program counter (not directly accessible)

; ============================================================================
; 1.2: Memory Regions (standard layout from build.py)
; ============================================================================

MEM_BOOT    EQU 0x1000   ; Bootstrap code area (QSLCLBST)
MEM_DATA    EQU 0x2000   ; Data storage
MEM_STACK   EQU 0x3000   ; Stack area (grows down)
MEM_USB     EQU 0x4000   ; USB buffer (QSLCLUSB)
MEM_IPC     EQU 0x5000   ; IPC buffer
MEM_CRYPTO  EQU 0x6000   ; Crypto buffer (QSLCLENC)
MEM_FUZZ    EQU 0x7000   ; Fuzzing buffer (for TEST/FUZZ commands)
MEM_DIAG    EQU 0x8000   ; Diagnostic buffer (QSLCLRTF)

; ============================================================================
; 1.3: Status Flags (stored in a special status register)
; ============================================================================

FLAG_ZERO   EQU 0x01   ; Zero flag (result is zero)
FLAG_CARRY  EQU 0x02   ; Carry flag (unsigned overflow)
FLAG_SIGN   EQU 0x04   ; Sign flag (negative result)
FLAG_OVERFLOW EQU 0x08 ; Overflow flag (signed overflow)
FLAG_ERROR  EQU 0x10   ; Error flag
FLAG_RAWMODE EQU 0x20  ; RAWMODE active flag
FLAG_USB4   EQU 0x40   ; USB4 v2.0 available flag
FLAG_ENCRYPT EQU 0x80  ; Encryption active flag

; ============================================================================
; SECTION 2: OPCODE DEFINITIONS
; ============================================================================
; All opcodes are defined in build.py's UOP dictionaries.
; This section documents the complete instruction set.

; ============================================================================
; 2.1: Core Operations (0x00-0x0F)
; ============================================================================

OP_NOP      EQU 0x00   ; No operation (2 bytes: 0x00, 0x00, 0x00)
OP_MOV      EQU 0x01   ; MOV reg, value   - Move immediate to register (3 bytes)
OP_XOR      EQU 0x02   ; XOR reg, value  - XOR register with value (3 bytes)
OP_ADD      EQU 0x03   ; ADD reg, value  - Add value to register (3 bytes)
OP_SUB      EQU 0x04   ; SUB reg, value  - Subtract value from register (3 bytes)
OP_MUL      EQU 0x05   ; MUL reg, value  - Multiply register by value (3 bytes)
OP_DIV      EQU 0x06   ; DIV reg, value  - Divide register by value (3 bytes)
OP_CMP      EQU 0x07   ; CMP reg, value  - Compare register with value (3 bytes)
OP_JMP      EQU 0x08   ; JMP address     - Unconditional jump (3 bytes)
OP_JZ       EQU 0x09   ; JZ address      - Jump if zero flag set (3 bytes)
OP_JNZ      EQU 0x0A   ; JNZ address     - Jump if zero flag not set (3 bytes)
OP_CALL     EQU 0x0B   ; CALL address    - Call subroutine (3 bytes)
OP_RET      EQU 0x0C   ; RET             - Return from subroutine (1 byte)
OP_PUSH     EQU 0x0D   ; PUSH reg        - Push register to stack (2 bytes)
OP_POP      EQU 0x0E   ; POP reg         - Pop register from stack (2 bytes)
OP_SWAP     EQU 0x0F   ; SWAP reg1, reg2 - Swap two registers (3 bytes)

; ============================================================================
; 2.2: Memory Operations (0x10-0x1F)
; ============================================================================

OP_LOAD8    EQU 0x10   ; LOAD8 reg, addr  - Load 8-bit from memory (3 bytes)
OP_STORE8   EQU 0x11   ; STORE8 reg, addr - Store 8-bit to memory (3 bytes)
OP_LOAD16   EQU 0x12   ; LOAD16 reg, addr - Load 16-bit from memory (3 bytes)
OP_STORE16  EQU 0x13   ; STORE16 reg, addr - Store 16-bit to memory (3 bytes)
OP_LOAD32   EQU 0x14   ; LOAD32 reg, addr - Load 32-bit from memory (3 bytes)
OP_STORE32  EQU 0x15   ; STORE32 reg, addr - Store 32-bit to memory (3 bytes)
OP_LOAD64   EQU 0x16   ; LOAD64 reg, addr - Load 64-bit from memory (5 bytes)
OP_STORE64  EQU 0x17   ; STORE64 reg, addr - Store 64-bit to memory (5 bytes)
OP_MEMCPY   EQU 0x18   ; MEMCPY dst, src, len - Memory copy (4 bytes)
OP_MEMSET   EQU 0x19   ; MEMSET addr, value, len - Memory set (4 bytes)
OP_ALLOC    EQU 0x1A   ; ALLOC size      - Allocate memory (2 bytes)
OP_FREE     EQU 0x1B   ; FREE addr       - Free memory (2 bytes)
OP_MMU_MAP  EQU 0x1C   ; MMU_MAP addr, size - Map memory (4 bytes)
OP_MMU_UNMAP EQU 0x1D  ; MMU_UNMAP addr  - Unmap memory (2 bytes)

; ============================================================================
; 2.3: System Operations (0x20-0x2F)
; ============================================================================

OP_SYSCALL  EQU 0x20   ; SYSCALL number  - System call (2 bytes)
OP_TEST     EQU 0x21   ; TEST reg, pattern - Test register against pattern (3 bytes)
OP_FUZZ     EQU 0x22   ; FUZZ reg, count  - Fuzz with pattern count (3 bytes)
OP_YIELD    EQU 0x23   ; YIELD           - Yield CPU (1 byte)
OP_SLEEP    EQU 0x24   ; SLEEP ms        - Sleep for milliseconds (2 bytes)
OP_WAIT     EQU 0x25   ; WAIT condition  - Wait for condition (2 bytes)
OP_SIGNAL   EQU 0x26   ; SIGNAL id       - Signal event (2 bytes)
OP_LOCK     EQU 0x27   ; LOCK            - Acquire lock (1 byte)
OP_UNLOCK   EQU 0x28   ; UNLOCK          - Release lock (1 byte)
OP_IRQ_ENABLE EQU 0x29 ; IRQ_ENABLE      - Enable interrupts (1 byte)
OP_IRQ_DISABLE EQU 0x2A ; IRQ_DISABLE    - Disable interrupts (1 byte)
OP_CONTEXT_SW EQU 0x2B ; CONTEXT_SW      - Context switch (2 bytes)
OP_TASK_CREATE EQU 0x2C ; TASK_CREATE addr - Create task (4 bytes)
OP_TASK_EXIT EQU 0x2D  ; TASK_EXIT       - Exit current task (1 byte)

; ============================================================================
; 2.4: IPC Operations (0x30-0x3F)
; ============================================================================

OP_IPC_SEND  EQU 0x30  ; IPC_SEND port, data - Send IPC message (4 bytes)
OP_IPC_RECV  EQU 0x31  ; IPC_RECV port   - Receive IPC message (2 bytes)
OP_MSG_SEND  EQU 0x32  ; MSG_SEND addr   - Send message (2 bytes)
OP_MSG_RECV  EQU 0x33  ; MSG_RECV        - Receive message (1 byte)
OP_SEM_WAIT  EQU 0x34  ; SEM_WAIT sem    - Wait on semaphore (2 bytes)
OP_SEM_POST  EQU 0x35  ; SEM_POST sem    - Post to semaphore (2 bytes)
OP_MUTEX_LOCK EQU 0x36 ; MUTEX_LOCK mutex - Lock mutex (2 bytes)
OP_MUTEX_UNLOCK EQU 0x37 ; MUTEX_UNLOCK mutex - Unlock mutex (2 bytes)

; ============================================================================
; 2.5: I/O Operations (0x40-0x4F)
; ============================================================================

OP_IO_READ8  EQU 0x40  ; IO_READ8 reg, port - Read 8-bit from I/O port (3 bytes)
OP_IO_WRITE8 EQU 0x41  ; IO_WRITE8 port, value - Write 8-bit to I/O port (3 bytes)
OP_IO_READ16 EQU 0x42  ; IO_READ16 reg, port - Read 16-bit from I/O port (3 bytes)
OP_IO_WRITE16 EQU 0x43 ; IO_WRITE16 port, value - Write 16-bit to I/O port (3 bytes)
OP_IO_READ32 EQU 0x44  ; IO_READ32 reg, port - Read 32-bit from I/O port (3 bytes)
OP_IO_WRITE32 EQU 0x45 ; IO_WRITE32 port, value - Write 32-bit to I/O port (3 bytes)
OP_TIMER_READ EQU 0x46 ; TIMER_READ reg  - Read timer (2 bytes)
OP_TIMER_SET  EQU 0x47 ; TIMER_SET value - Set timer (2 bytes)
OP_DMA_START  EQU 0x48 ; DMA_START src, dst, len - Start DMA transfer (4 bytes)
OP_DMA_WAIT   EQU 0x49 ; DMA_WAIT        - Wait for DMA completion (1 byte)

; ============================================================================
; 2.6: Crypto Operations (0x50-0x5F) - From QSLCLENC
; ============================================================================

OP_ENTROPY   EQU 0x50  ; ENTROPY reg     - Get entropy (2 bytes)
OP_SHA256    EQU 0x51  ; SHA256 addr, len - SHA256 hash (4 bytes)
OP_AES_ENC   EQU 0x52  ; AES_ENC addr, len - AES encrypt (4 bytes)
OP_AES_DEC   EQU 0x53  ; AES_DEC addr, len - AES decrypt (4 bytes)
OP_RSA_ENC   EQU 0x54  ; RSA_ENC addr, len - RSA encrypt (4 bytes)
OP_RSA_DEC   EQU 0x55  ; RSA_DEC addr, len - RSA decrypt (4 bytes)
OP_HMAC      EQU 0x56  ; HMAC key, data, len - HMAC (6 bytes)
OP_RNG       EQU 0x57  ; RNG reg         - Get random number (2 bytes)
OP_CRC32     EQU 0x58  ; CRC32 addr, len - CRC32 checksum (4 bytes)
OP_VERIFY    EQU 0x59  ; VERIFY addr     - Verify signature (2 bytes)

; ============================================================================
; 2.7: Debug Operations (0x60-0x6F) - From QSLCLRTF
; ============================================================================

OP_DEBUG     EQU 0x60  ; DEBUG msg       - Debug message (2 bytes)
OP_TRACE     EQU 0x61  ; TRACE           - Enable trace (1 byte)
OP_PROFILE   EQU 0x62  ; PROFILE         - Enable profiling (1 byte)
OP_LOG       EQU 0x63  ; LOG msg         - Log message (2 bytes)
OP_ASSERT    EQU 0x64  ; ASSERT condition - Assert condition (2 bytes)
OP_BREAK     EQU 0x65  ; BREAK           - Breakpoint (1 byte)
OP_DUMP_REGS EQU 0x66  ; DUMP_REGS       - Dump registers (1 byte)
OP_DUMP_MEM  EQU 0x67  ; DUMP_MEM addr, len - Dump memory (4 bytes)

; ============================================================================
; 2.8: Power Operations (0x70-0x7F)
; ============================================================================

OP_PWR_SLEEP EQU 0x70  ; PWR_SLEEP       - Sleep mode (1 byte)
OP_PWR_DEEP  EQU 0x71  ; PWR_DEEP        - Deep sleep (1 byte)
OP_PWR_WAKE  EQU 0x72  ; PWR_WAKE        - Wake from sleep (1 byte)
OP_CLK_SET   EQU 0x73  ; CLK_SET freq    - Set clock frequency (2 bytes)
OP_VOLT_SET  EQU 0x74  ; VOLT_SET volt   - Set voltage (2 bytes)
OP_TEMP_READ EQU 0x75  ; TEMP_READ reg   - Read temperature (2 bytes)
OP_BATT_READ EQU 0x76  ; BATT_READ reg   - Read battery level (2 bytes)

; ============================================================================
; 2.9: Fault Recovery (0x80-0x8F) - From QSLCLRTF
; ============================================================================

OP_FAILSAFE  EQU 0x80  ; FAILSAFE        - Enter failsafe mode (1 byte)
OP_WATCHDOG  EQU 0x81  ; WATCHDOG value  - Feed/watchdog (2 bytes)
OP_ERROR     EQU 0x82  ; ERROR code      - Signal error (2 bytes)
OP_RESET     EQU 0x83  ; RESET           - Reset system (1 byte)
OP_RECOVER   EQU 0x84  ; RECOVER         - Recover from error (1 byte)
OP_CHECKPOINT EQU 0x85 ; CHECKPOINT      - Create checkpoint (1 byte)
OP_ROLLBACK  EQU 0x86  ; ROLLBACK        - Rollback to checkpoint (1 byte)

; ============================================================================
; 2.10: USB Core Operations (0xA0-0xAF) - From QSLCLUSB
; ============================================================================

OP_USB_INIT   EQU 0xA0 ; USB_INIT        - Initialize USB (1 byte)
OP_USB_RESET  EQU 0xA1 ; USB_RESET       - Reset USB (1 byte)
OP_SET_ADDRESS EQU 0xA2 ; SET_ADDRESS addr - Set USB address (2 bytes)
OP_GET_STATUS EQU 0xA3 ; GET_STATUS      - Get USB status (1 byte)
OP_SET_FEATURE EQU 0xA4 ; SET_FEATURE    - Set USB feature (1 byte)
OP_CLEAR_FEATURE EQU 0xA5 ; CLEAR_FEATURE - Clear USB feature (1 byte)
OP_EP_ENABLE  EQU 0xA6 ; EP_ENABLE ep    - Enable endpoint (2 bytes)
OP_EP_DISABLE EQU 0xA7 ; EP_DISABLE ep   - Disable endpoint (2 bytes)
OP_EP_STALL   EQU 0xA8 ; EP_STALL ep     - Stall endpoint (2 bytes)
OP_EP_UNSTALL EQU 0xA9 ; EP_UNSTALL ep   - Unstall endpoint (2 bytes)
OP_EP_READY   EQU 0xAA ; EP_READY ep     - Mark endpoint ready (2 bytes)

; ============================================================================
; 2.11: USB Data Operations (0xB0-0xBF) - From QSLCLUSB
; ============================================================================

OP_READ8     EQU 0xB0  ; READ8 addr      - Read 8-bit from USB (2 bytes)
OP_WRITE8    EQU 0xB1  ; WRITE8 addr, value - Write 8-bit to USB (3 bytes)
OP_READ16    EQU 0xB2  ; READ16 addr     - Read 16-bit from USB (2 bytes)
OP_WRITE16   EQU 0xB3  ; WRITE16 addr, value - Write 16-bit to USB (3 bytes)
OP_READFIFO  EQU 0xB4  ; READFIFO addr   - Read from FIFO (2 bytes)
OP_WRITEFIFO EQU 0xB5  ; WRITEFIFO addr, value - Write to FIFO (3 bytes)
OP_FIFO_FLUSH EQU 0xB6 ; FIFO_FLUSH      - Flush FIFO (1 byte)
OP_READ_BULK EQU 0xB7  ; READ_BULK ep    - Bulk read (2 bytes)
OP_WRITE_BULK EQU 0xB8 ; WRITE_BULK ep, data - Bulk write (4 bytes)
OP_READ_CTRL EQU 0xB9  ; READ_CTRL       - Control read (1 byte)
OP_WRITE_CTRL EQU 0xBA ; WRITE_CTRL      - Control write (1 byte)

; ============================================================================
; 2.12: Data Transfer Protocol (0xD0-0xDF) - From QSLCLDAT
; ============================================================================

OP_DATA_INIT   EQU 0xD0 ; DATA_INIT mode  - Initialize data transfer (2 bytes)
OP_DATA_RECV   EQU 0xD1 ; DATA_RECV       - Receive data frame (1 byte)
OP_DATA_ACK    EQU 0xD2 ; DATA_ACK seq, status - Send acknowledgement (4 bytes)
OP_DATA_ASSEMBLE EQU 0xD3 ; DATA_ASSEMBLE - Assemble chunks (1 byte)
OP_DATA_VERIFY EQU 0xD4 ; DATA_VERIFY     - Verify transfer (1 byte)
OP_DATA_STORE  EQU 0xD5 ; DATA_STORE addr - Store received data (2 bytes)
OP_DATA_ABORT  EQU 0xD6 ; DATA_ABORT code - Abort transfer (2 bytes)
OP_DATA_SEND   EQU 0xD7 ; DATA_SEND seq, len - Send data frame (4 bytes)

; ============================================================================
; 2.13: Bootstrap Operations (0xE0-0xEF) - From QSLCLBST
; ============================================================================

OP_BOOT_INIT  EQU 0xE0 ; BOOT_INIT       - Initialize bootstrap (1 byte)
OP_BOOT_VERIFY EQU 0xE1 ; BOOT_VERIFY    - Verify bootstrap (1 byte)
OP_BOOT_JUMP  EQU 0xE2 ; BOOT_JUMP addr  - Jump to bootstrap entry (2 bytes)
OP_BOOT_SETUP EQU 0xE3 ; BOOT_SETUP      - Setup bootstrap environment (1 byte)
OP_BOOT_SECURE EQU 0xE4 ; BOOT_SECURE    - Secure bootstrap (1 byte)
OP_BOOT_RECOVER EQU 0xE5 ; BOOT_RECOVER  - Recover bootstrap (1 byte)

; ============================================================================
; 2.14: USB4 v2.0 Operations (0xF0-0xFF) - From USB4V2MC
; ============================================================================

OP_USB4_TUNNEL_CREATE EQU 0xF0 ; USB4_TUNNEL_CREATE type - Create USB4 tunnel (2 bytes)
OP_USB4_TUNNEL_DESTROY EQU 0xF1 ; USB4_TUNNEL_DESTROY id - Destroy USB4 tunnel (2 bytes)
OP_USB4_BANDWIDTH_SET EQU 0xF2 ; USB4_BANDWIDTH_SET id, bw - Set USB4 bandwidth (4 bytes)
OP_USB4_PATH_OPTIMIZE EQU 0xF3 ; USB4_PATH_OPTIMIZE id - Optimize USB4 path (2 bytes)
OP_USB4_SECURE_CHANNEL EQU 0xF4 ; USB4_SECURE_CHANNEL id - Secure channel (2 bytes)
OP_USB4_DMA_DIRECT EQU 0xF5 ; USB4_DMA_DIRECT src, dst, len - Direct DMA (6 bytes)
OP_USB4_80G_MODE EQU 0xF6 ; USB4_80G_MODE enable - Enable 80Gbps mode (2 bytes)
OP_USB4_PAM_ENCODE EQU 0xF7 ; USB4_PAM_ENCODE mode - PAM encoding (2 bytes)
OP_USB4_LANE_AGGREGATE EQU 0xF8 ; USB4_LANE_AGGREGATE count - Lane aggregation (2 bytes)
OP_USB4_LATENCY_PROBE EQU 0xF9 ; USB4_LATENCY_PROBE - Probe latency (1 byte)
OP_USB4_CMA_MEASURE EQU 0xFA ; USB4_CMA_MEASURE - Component measurement (1 byte)
OP_USB4_ATTEST EQU 0xFB ; USB4_ATTEST    - Attestation (1 byte)

; ============================================================================
; SECTION 3: MACROS (Common Instruction Patterns)
; ============================================================================
; These macros correspond to the code generated by build.py's
; generate_command_code() function.

; ============================================================================
; 3.1: Function Call Macros
; ============================================================================

; Define a function (label)
%macro FUNC 1
    %1:
%endmacro

; Call a function
%macro CALL_FUNC 1
    CALL %1
%endmacro

; Return from function
%macro RET_FUNC 0
    RET
%endmacro

; ============================================================================
; 3.2: Memory Access Macros
; ============================================================================

; Load 32-bit value from memory
%macro LOAD 2
    LOAD32 %1, %2
%endmacro

; Store 32-bit value to memory
%macro STORE 2
    STORE32 %1, %2
%endmacro

; Load 8-bit value from memory
%macro LOADB 2
    LOAD8 %1, %2
%endmacro

; Store 8-bit value to memory
%macro STOREB 2
    STORE8 %1, %2
%endmacro

; ============================================================================
; 3.3: USB Operation Macros - Generated by build.py
; ============================================================================

; Initialize USB
%macro USB_INIT 0
    OP_USB_INIT 0, 0
%endmacro

; Read from USB control endpoint
%macro USB_READ_CTRL 0
    READ_CTRL
%endmacro

; Write to USB control endpoint
%macro USB_WRITE_CTRL 0
    WRITE_CTRL
%endmacro

; ============================================================================
; 3.4: Data Transfer Macros - From QSLCLDAT
; ============================================================================

; Initialize data transfer (receive mode)
%macro DATA_RECV_INIT 0
    DATA_INIT 0
%endmacro

; Initialize data transfer (send mode)
%macro DATA_SEND_INIT 0
    DATA_INIT 1
%endmacro

; Send data acknowledgement
%macro DATA_ACK_SEND 2
    DATA_ACK %1, %2
%endmacro

; ============================================================================
; 3.5: Crypto Macros - From QSLCLENC
; ============================================================================

; Get random number into register
%macro RAND 1
    RNG %1
%endmacro

; Calculate SHA256 of memory region
%macro SHA256 2
    SHA256 %1, %2
%endmacro

; Calculate CRC32 of memory region
%macro CRC32 2
    CRC32 %1, %2
%endmacro

; ============================================================================
; 3.6: Bootstrap Macros - From QSLCLBST
; ============================================================================

; Boot from USB (standard bootstrap sequence)
%macro BOOT_USB 0
    BOOT_INIT
    BOOT_VERIFY
    BOOT_JUMP 0x5000
%endmacro

; Secure bootstrap with verification
%macro BOOT_SECURE 0
    BOOT_INIT
    BOOT_SECURE
    BOOT_VERIFY
    BOOT_JUMP 0x5000
%endmacro

; ============================================================================
; 3.7: Diagnostic Macros - From build.py's TEST/FUZZ commands
; ============================================================================

; Test register against expected value
%macro TEST_REG 2
    TEST %1, %2
%endmacro

; Fuzz register with pattern
%macro FUZZ_REG 2
    FUZZ %1, %2
%endmacro

; ============================================================================
; 3.8: USB4 v2.0 Macros - From USB4V2MC
; ============================================================================

; Enable USB4 80Gbps mode
%macro USB4_80G 0
    USB4_80G_MODE 1
%endmacro

; Create PCIe tunnel
%macro USB4_TUNNEL_PCIE 0
    USB4_TUNNEL_CREATE 1
%endmacro

; Create DisplayPort tunnel
%macro USB4_TUNNEL_DP 0
    USB4_TUNNEL_CREATE 2
%endmacro

; ============================================================================
; SECTION 4: EXAMPLE PROGRAMS
; ============================================================================
; These examples show how build.py generates code for each command family.
; They are PURELY ILLUSTRATIVE of the bytecode structure.

; ============================================================================
; 4.1: Hello Command (SYS Family) - From build.py
; ============================================================================
; Generated by generate_command_code() for CMD_HELLO
; Family: SYS, Tier: 1

HELLO_HANDLER:
    MOV R0, 0           ; Initialize
    IPC_SEND 0, 0xF0    ; Send IPC message
    RET

; ============================================================================
; 4.2: GetInfo Command (SYS Family) - From build.py
; ============================================================================
; Generated by generate_command_code() for CMD_GETINFO
; Family: SYS, Tier: 1

GETINFO_HANDLER:
    LOAD32 R0, 0x1000   ; Load info from memory
    IPC_SEND 0, 0xF2    ; Send IPC message with info
    RET

; ============================================================================
; 4.3: Read Command (MEM Family) - From build.py
; ============================================================================
; Generated by generate_command_code() for CMD_READ
; Family: MEM, Tier: 1

READ_HANDLER:
    LOAD32 R0, 0x2000   ; Load address
    IPC_SEND 0, 0xE0    ; Send read request
    RET

; ============================================================================
; 4.4: Write Command (MEM Family) - From build.py
; ============================================================================
; Generated by generate_command_code() for CMD_WRITE
; Family: MEM, Tier: 2

WRITE_HANDLER:
    IPC_RECV 1, 0xE1    ; Receive data
    STORE32 R1, 0x2000  ; Store to memory
    RET

; ============================================================================
; 4.5: RawMode Command (RAW Family) - From build.py
; ============================================================================
; Generated by generate_command_code() for CMD_RAWMODE
; Family: RAW, Tier: 5

RAWMODE_HANDLER:
    PRIV_UP 0, 0        ; Raise privilege
    MOV R0, 1           ; Set RAWMODE value
    STORE32 R0, 0xF000  ; Store to RAWMODE register
    IPC_SEND 0, 0xC0    ; Send confirmation
    RET

; ============================================================================
; 4.6: Test Command (DIAG Family) - From build.py
; ============================================================================
; Generated by generate_command_code() for CMD_TEST
; Family: DIAG, Tier: 2

TEST_HANDLER:
    MOV R0, 0           ; Initialize counter
    TEST R1, 0xAA       ; Test pattern 0xAA
    CMP R1, 0xAA        ; Verify
    JZ 0x08             ; Jump if match
    MOV R0, 1           ; Set error flag
    JMP 0x10            ; Skip to end
    TEST R1, 0x55       ; Test pattern 0x55
    CMP R1, 0x55        ; Verify
    JZ 0x08             ; Jump if match
    MOV R0, 2           ; Set different error
    IPC_SEND 0, 0xF5    ; Send results
    RET

; ============================================================================
; 4.7: Fuzz Command (DIAG Family) - From build.py
; ============================================================================
; Generated by generate_command_code() for CMD_FUZZ
; Family: DIAG, Tier: 3

FUZZ_HANDLER:
    MOV R0, 0           ; Fuzz iteration counter
    FUZZ R1, 0x100      ; Fuzz 256 iterations
    LOAD32 R2, 0x3000   ; Load fuzz buffer
    MEMCPY R2, 0x2000   ; Copy to target
    IPC_SEND 2, 0xE8    ; Send fuzz data
    CRC32 R3, 0x2000    ; Calculate CRC
    STORE32 R3, 0x3010  ; Store CRC result
    MOV R0, 0           ; Success status
    RET

; ============================================================================
; SECTION 5: QSLCLBIN STRUCTURE (from build.py)
; ============================================================================

; QSLCL Binary Layout (v0.7.4):
;
; 0x000000  QSLCLBIN (Main Header + Pointers)
; 0x000200+ QSLCLCMD (28 Commands) 
; 0x004000+ QSLCLDIS (Dispatch Table)
; 0x005000+ QSLCLUSB (USB Micro-Engine)
; 0x006000+ QSLCLBLK (64 Endpoints)
; 0x007000+ QSLCLBST (Bootstrap Engine)
; 0x008000+ QSLCLVM5 (Nano-Kernel)
; 0x009000+ QSLCLSPT (USB Setup Packets)
; 0x00A000+ QSLCLRTF (Runtime Fault Table)
; 0x00B000+ QSLCLENC (Encryption Layer)
; 0x00C000+ QSLCLDAT (Data Protocol)
; 0x00D000+ QSLCLSYN (Sync Block)
; 0x00E000+ QSLCLHDR (Certificate)
; 0x00F000+ QSLCLINT (Integrity Footer)
; 0x010000+ USB4V2MC (USB4 v2.0 80Gbps)

; ============================================================================
; SECTION 6: COMMAND DEFINITIONS (28 commands - from build.py)
; ============================================================================

; Core Memory Operations (0x01-0x07)
CMD_READ        EQU 0x01
CMD_WRITE       EQU 0x02
CMD_ERASE       EQU 0x03
CMD_PEEK        EQU 0x04
CMD_POKE        EQU 0x05
CMD_PATCH       EQU 0x06
CMD_DUMP        EQU 0x07

; Device Interaction (0x10-0x13)
CMD_HELLO       EQU 0x10
CMD_PING        EQU 0x11
CMD_GETINFO     EQU 0x12
CMD_GETSECTOR   EQU 0x13

; System Control (0x20-0x22)
CMD_RESET       EQU 0x20
CMD_POWER       EQU 0x21
CMD_CONFIG      EQU 0x22

; Voltage & Hardware (0x30-0x31)
CMD_VOLTAGE     EQU 0x30
CMD_RAWSTATE    EQU 0x31

; Security & Analysis (0x40-0x43)
CMD_RAWMODE     EQU 0x40
CMD_BYPASS      EQU 0x41
CMD_VERIFY      EQU 0x42
CMD_FOOTER      EQU 0x43

; Diagnostic & Testing (0x50-0x54)
CMD_CRASH       EQU 0x50
CMD_GLITCH      EQU 0x51
CMD_BRUTEFORCE  EQU 0x52
CMD_TEST        EQU 0x53
CMD_FUZZ        EQU 0x54

; Manufacturing & ODM (0x60-0x61)
CMD_OEM         EQU 0x60
CMD_ODM         EQU 0x61

; ============================================================================
; SECTION 7: SYSTEM CALL NUMBERS (from build.py)
; ============================================================================

SYS_IPC_SEND    EQU 0x01
SYS_IPC_RECV    EQU 0x02
SYS_USB_SEND    EQU 0xA0  ; Matches build.py's SYSCALL for USB
SYS_USB_RECV    EQU 0xA1
SYS_CRYPTO      EQU 0x05
SYS_MMU         EQU 0x06
SYS_POWER       EQU 0xFE  ; Matches build.py
SYS_RESET       EQU 0xFF  ; Matches build.py
SYS_WATCHDOG    EQU 0x0A

; ============================================================================
; SECTION 8: FAULT CODES (from QSLCLRTF in build.py)
; ============================================================================

FAULT_SUCCESS           EQU 0x0000
FAULT_ERROR_GENERAL     EQU 0x0001
FAULT_INVALID_COMMAND   EQU 0x0002
FAULT_INVALID_ADDRESS   EQU 0x0003
FAULT_INVALID_SIZE      EQU 0x0004
FAULT_CRC_MISMATCH      EQU 0x0005
FAULT_AUTH_FAILED       EQU 0x0006
FAULT_RAWMODE_REQUIRED  EQU 0x0007
FAULT_TIMEOUT           EQU 0x0008
FAULT_MEMORY_FAULT      EQU 0x0009
FAULT_USB_STALL         EQU 0x000A
FAULT_DATA_SEQUENCE     EQU 0x0010
FAULT_DATA_INCOMPLETE   EQU 0x0011

; ============================================================================
; SECTION 9: ENCRYPTION LAYER CONSTANTS (QSLCLENC in build.py)
; ============================================================================

ENC_CHACHA20    EQU 0x01   ; ChaCha20-Poly1305
ENC_AES_GCM     EQU 0x02   ; AES-256-GCM
ENC_KEY_EXCH    EQU 0x04   ; Session key negotiation
ENC_PFS         EQU 0x08   ; Perfect forward secrecy
ENC_ANTI_REPLAY EQU 0x10   ; Anti-replay protection

; ============================================================================
; SECTION 10: USB4 v2.0 CONSTANTS (USB4V2MC in build.py)
; ============================================================================

USB4_SPEED_40G  EQU 40000  ; USB4 v1.0 speed
USB4_SPEED_80G  EQU 80000  ; USB4 v2.0 speed
USB4_SPEED_120G EQU 120000 ; Asymmetric 120/40 mode
USB4_SPEED_160G EQU 160000 ; Future reserved

USB4_TUNNEL_PCIE   EQU 0x01
USB4_TUNNEL_DP     EQU 0x02
USB4_TUNNEL_USB3   EQU 0x03
USB4_TUNNEL_HOST   EQU 0x04

USB4_PAM3         EQU 0x01  ; PAM3 encoding (3 levels)
USB4_PAM4         EQU 0x02  ; PAM4 encoding (4 levels)
USB4_PAM_AUTO     EQU 0x03  ; Auto-detect encoding

; ============================================================================
; SECTION 11: COMMAND FAMILIES (from build.py's TIER/FAMILY tables)
; ============================================================================

; Command Families
FAMILY_SYS      EQU 0x01  ; System commands (HELLO, PING, GETINFO, RESET, CRASH)
FAMILY_MEM      EQU 0x02  ; Memory commands (READ, WRITE, ERASE, PEEK, POKE, DUMP)
FAMILY_SEC      EQU 0x03  ; Security commands (VERIFY)
FAMILY_PWR      EQU 0x04  ; Power commands (POWER, VOLTAGE)
FAMILY_RAW      EQU 0x05  ; Raw commands (RAWMODE, RAWSTATE, FOOTER)
FAMILY_OEM      EQU 0x06  ; OEM commands (OEM, ODM)
FAMILY_CFG      EQU 0x07  ; Config commands (CONFIG)
FAMILY_ROM      EQU 0x08  ; ROM commands (PATCH)
FAMILY_TIMING   EQU 0x09  ; Timing commands (GLITCH)
FAMILY_META     EQU 0x0A  ; Meta commands (BYPASS)
FAMILY_DIAG     EQU 0x0B  ; Diagnostic commands (TEST, FUZZ)

; Command Tiers (privilege levels)
TIER_1          EQU 0x01  ; Basic - no special privileges
TIER_2          EQU 0x02  ; Memory access
TIER_3          EQU 0x03  ; System control
TIER_4          EQU 0x04  ; Security sensitive
TIER_5          EQU 0x05  ; Highest privilege (RAWMODE)

; ============================================================================
; END OF FILE
; ============================================================================