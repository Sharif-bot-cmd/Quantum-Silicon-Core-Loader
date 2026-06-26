; ============================================================================
; QSLCL Micro-VM Assembly Language (Architecture-Neutral)
; Version: 1.0
; For: qslcl.bin v0.7.4
; ============================================================================
;
; The QSLCL Micro-VM is a simple, architecture-neutral virtual machine
; that executes bytecode on any SoC (ARM, x86, RISC-V, MIPS, PowerPC).
;
; Instruction Format: 4 bytes
; [OPCODE (1 byte)] [REGISTER (1 byte)] [ARGUMENT (2 bytes)]
;
; Registers: 16 general-purpose (R0-R15)
; Memory: 64KB address space (16-bit addressing)
; Stack: 256 bytes
;
; ============================================================================

; ============================================================================
; SECTION 1: DATA TYPES & REGISTERS
; ============================================================================

; Registers
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
R13     EQU 0x0D   ; Stack pointer
R14     EQU 0x0E   ; Link register (return address)
R15     EQU 0x0F   ; Program counter

; Memory regions
MEM_BOOT    EQU 0x1000   ; Bootstrap code area
MEM_DATA    EQU 0x2000   ; Data storage
MEM_STACK   EQU 0x3000   ; Stack area (grows down)
MEM_USB     EQU 0x4000   ; USB buffer
MEM_IPC     EQU 0x5000   ; IPC buffer
MEM_CRYPTO  EQU 0x6000   ; Crypto buffer

; ============================================================================
; SECTION 2: OPCODE DEFINITIONS
; ============================================================================

; ============================================================================
; 2.1: Core Operations (0x00-0x0F)
; ============================================================================

OP_NOP      EQU 0x00   ; No operation
OP_MOV      EQU 0x01   ; MOV reg, value   - Move immediate to register
OP_XOR      EQU 0x02   ; XOR reg, value  - XOR register with value
OP_ADD      EQU 0x03   ; ADD reg, value  - Add value to register
OP_SUB      EQU 0x04   ; SUB reg, value  - Subtract value from register
OP_MUL      EQU 0x05   ; MUL reg, value  - Multiply register by value
OP_DIV      EQU 0x06   ; DIV reg, value  - Divide register by value
OP_CMP      EQU 0x07   ; CMP reg, value  - Compare register with value
OP_JMP      EQU 0x08   ; JMP address     - Unconditional jump
OP_JZ       EQU 0x09   ; JZ address      - Jump if zero flag set
OP_JNZ      EQU 0x0A   ; JNZ address     - Jump if zero flag not set
OP_CALL     EQU 0x0B   ; CALL address    - Call subroutine
OP_RET      EQU 0x0C   ; RET             - Return from subroutine
OP_PUSH     EQU 0x0D   ; PUSH reg        - Push register to stack
OP_POP      EQU 0x0E   ; POP reg         - Pop register from stack
OP_SWAP     EQU 0x0F   ; SWAP reg1, reg2 - Swap two registers

; ============================================================================
; 2.2: Memory Operations (0x10-0x1F)
; ============================================================================

OP_LOAD8    EQU 0x10   ; LOAD8 reg, addr  - Load 8-bit from memory
OP_STORE8   EQU 0x11   ; STORE8 reg, addr - Store 8-bit to memory
OP_LOAD16   EQU 0x12   ; LOAD16 reg, addr - Load 16-bit from memory
OP_STORE16  EQU 0x13   ; STORE16 reg, addr - Store 16-bit to memory
OP_LOAD32   EQU 0x14   ; LOAD32 reg, addr - Load 32-bit from memory
OP_STORE32  EQU 0x15   ; STORE32 reg, addr - Store 32-bit to memory
OP_LOAD64   EQU 0x16   ; LOAD64 reg, addr - Load 64-bit from memory
OP_STORE64  EQU 0x17   ; STORE64 reg, addr - Store 64-bit to memory
OP_MEMCPY   EQU 0x18   ; MEMCPY dst, src, len - Memory copy
OP_MEMSET   EQU 0x19   ; MEMSET addr, value, len - Memory set
OP_ALLOC    EQU 0x1A   ; ALLOC size      - Allocate memory
OP_FREE     EQU 0x1B   ; FREE addr       - Free memory
OP_MMU_MAP  EQU 0x1C   ; MMU_MAP addr, size - Map memory
OP_MMU_UNMAP EQU 0x1D  ; MMU_UNMAP addr  - Unmap memory

; ============================================================================
; 2.3: System Operations (0x20-0x2F)
; ============================================================================

OP_SYSCALL  EQU 0x20   ; SYSCALL number  - System call
OP_YIELD    EQU 0x21   ; YIELD           - Yield CPU
OP_SLEEP    EQU 0x22   ; SLEEP ms        - Sleep for milliseconds
OP_WAIT     EQU 0x23   ; WAIT condition  - Wait for condition
OP_SIGNAL   EQU 0x24   ; SIGNAL id       - Signal event
OP_LOCK     EQU 0x25   ; LOCK            - Acquire lock
OP_UNLOCK   EQU 0x26   ; UNLOCK          - Release lock
OP_IRQ_ENABLE EQU 0x27 ; IRQ_ENABLE      - Enable interrupts
OP_IRQ_DISABLE EQU 0x28 ; IRQ_DISABLE    - Disable interrupts
OP_CONTEXT_SW EQU 0x29 ; CONTEXT_SW      - Context switch
OP_TASK_CREATE EQU 0x2A ; TASK_CREATE addr - Create task
OP_TASK_EXIT EQU 0x2B  ; TASK_EXIT       - Exit current task

; ============================================================================
; 2.4: IPC Operations (0x30-0x3F)
; ============================================================================

OP_IPC_SEND  EQU 0x30  ; IPC_SEND port, data - Send IPC message
OP_IPC_RECV  EQU 0x31  ; IPC_RECV port   - Receive IPC message
OP_MSG_SEND  EQU 0x32  ; MSG_SEND addr   - Send message
OP_MSG_RECV  EQU 0x33  ; MSG_RECV        - Receive message
OP_SEM_WAIT  EQU 0x34  ; SEM_WAIT sem    - Wait on semaphore
OP_SEM_POST  EQU 0x35  ; SEM_POST sem    - Post to semaphore
OP_MUTEX_LOCK EQU 0x36 ; MUTEX_LOCK mutex - Lock mutex
OP_MUTEX_UNLOCK EQU 0x37 ; MUTEX_UNLOCK mutex - Unlock mutex

; ============================================================================
; 2.5: I/O Operations (0x40-0x4F)
; ============================================================================

OP_IO_READ8  EQU 0x40  ; IO_READ8 reg, port - Read 8-bit from I/O port
OP_IO_WRITE8 EQU 0x41  ; IO_WRITE8 port, value - Write 8-bit to I/O port
OP_IO_READ16 EQU 0x42  ; IO_READ16 reg, port - Read 16-bit from I/O port
OP_IO_WRITE16 EQU 0x43 ; IO_WRITE16 port, value - Write 16-bit to I/O port
OP_IO_READ32 EQU 0x44  ; IO_READ32 reg, port - Read 32-bit from I/O port
OP_IO_WRITE32 EQU 0x45 ; IO_WRITE32 port, value - Write 32-bit to I/O port
OP_TIMER_READ EQU 0x46 ; TIMER_READ reg  - Read timer
OP_TIMER_SET  EQU 0x47 ; TIMER_SET value - Set timer
OP_DMA_START  EQU 0x48 ; DMA_START src, dst, len - Start DMA transfer
OP_DMA_WAIT   EQU 0x49 ; DMA_WAIT        - Wait for DMA completion

; ============================================================================
; 2.6: Crypto Operations (0x50-0x5F)
; ============================================================================

OP_ENTROPY   EQU 0x50  ; ENTROPY reg     - Get entropy
OP_SHA256    EQU 0x51  ; SHA256 addr, len - SHA256 hash
OP_AES_ENC   EQU 0x52  ; AES_ENC addr, len - AES encrypt
OP_AES_DEC   EQU 0x53  ; AES_DEC addr, len - AES decrypt
OP_RSA_ENC   EQU 0x54  ; RSA_ENC addr, len - RSA encrypt
OP_RSA_DEC   EQU 0x55  ; RSA_DEC addr, len - RSA decrypt
OP_HMAC      EQU 0x56  ; HMAC key, data, len - HMAC
OP_RNG       EQU 0x57  ; RNG reg         - Get random number
OP_CRC32     EQU 0x58  ; CRC32 addr, len - CRC32 checksum
OP_VERIFY    EQU 0x59  ; VERIFY addr     - Verify signature

; ============================================================================
; 2.7: Debug Operations (0x60-0x6F)
; ============================================================================

OP_DEBUG     EQU 0x60  ; DEBUG msg       - Debug message
OP_TRACE     EQU 0x61  ; TRACE           - Enable trace
OP_PROFILE   EQU 0x62  ; PROFILE         - Enable profiling
OP_LOG       EQU 0x63  ; LOG msg         - Log message
OP_ASSERT    EQU 0x64  ; ASSERT condition - Assert condition
OP_BREAK     EQU 0x65  ; BREAK           - Breakpoint
OP_DUMP_REGS EQU 0x66  ; DUMP_REGS       - Dump registers
OP_DUMP_MEM  EQU 0x67  ; DUMP_MEM addr, len - Dump memory

; ============================================================================
; 2.8: Power Operations (0x70-0x7F)
; ============================================================================

OP_PWR_SLEEP EQU 0x70  ; PWR_SLEEP       - Sleep mode
OP_PWR_DEEP  EQU 0x71  ; PWR_DEEP        - Deep sleep
OP_PWR_WAKE  EQU 0x72  ; PWR_WAKE        - Wake from sleep
OP_CLK_SET   EQU 0x73  ; CLK_SET freq    - Set clock frequency
OP_VOLT_SET  EQU 0x74  ; VOLT_SET volt   - Set voltage
OP_TEMP_READ EQU 0x75  ; TEMP_READ reg   - Read temperature
OP_BATT_READ EQU 0x76  ; BATT_READ reg   - Read battery level

; ============================================================================
; 2.9: Fault Recovery (0x80-0x8F)
; ============================================================================

OP_FAILSAFE  EQU 0x80  ; FAILSAFE        - Enter failsafe mode
OP_WATCHDOG  EQU 0x81  ; WATCHDOG value  - Feed watchdog
OP_ERROR     EQU 0x82  ; ERROR code      - Signal error
OP_RESET     EQU 0x83  ; RESET           - Reset system
OP_RECOVER   EQU 0x84  ; RECOVER         - Recover from error
OP_CHECKPOINT EQU 0x85 ; CHECKPOINT      - Create checkpoint
OP_ROLLBACK  EQU 0x86  ; ROLLBACK        - Rollback to checkpoint

; ============================================================================
; 2.10: QSLCL-Specific Operations (0xA0-0xAF)
; ============================================================================

OP_USB_INIT   EQU 0xA0 ; USB_INIT        - Initialize USB
OP_USB_RESET  EQU 0xA1 ; USB_RESET       - Reset USB
OP_SET_ADDRESS EQU 0xA2 ; SET_ADDRESS addr - Set USB address
OP_GET_STATUS EQU 0xA3 ; GET_STATUS      - Get USB status
OP_SET_FEATURE EQU 0xA4 ; SET_FEATURE    - Set USB feature
OP_CLEAR_FEATURE EQU 0xA5 ; CLEAR_FEATURE - Clear USB feature
OP_EP_ENABLE  EQU 0xA6 ; EP_ENABLE ep    - Enable endpoint
OP_EP_DISABLE EQU 0xA7 ; EP_DISABLE ep   - Disable endpoint
OP_EP_STALL   EQU 0xA8 ; EP_STALL ep     - Stall endpoint
OP_EP_UNSTALL EQU 0xA9 ; EP_UNSTALL ep   - Unstall endpoint
OP_EP_READY   EQU 0xAA ; EP_READY ep     - Mark endpoint ready

; ============================================================================
; 2.11: USB Data Operations (0xB0-0xBF)
; ============================================================================

OP_READ8     EQU 0xB0  ; READ8 addr      - Read 8-bit from USB
OP_WRITE8    EQU 0xB1  ; WRITE8 addr, value - Write 8-bit to USB
OP_READ16    EQU 0xB2  ; READ16 addr     - Read 16-bit from USB
OP_WRITE16   EQU 0xB3  ; WRITE16 addr, value - Write 16-bit to USB
OP_READFIFO  EQU 0xB4  ; READFIFO addr   - Read from FIFO
OP_WRITEFIFO EQU 0xB5  ; WRITEFIFO addr, value - Write to FIFO
OP_FIFO_FLUSH EQU 0xB6 ; FIFO_FLUSH      - Flush FIFO
OP_READ_BULK EQU 0xB7  ; READ_BULK ep    - Bulk read
OP_WRITE_BULK EQU 0xB8 ; WRITE_BULK ep, data - Bulk write
OP_READ_CTRL EQU 0xB9  ; READ_CTRL       - Control read
OP_WRITE_CTRL EQU 0xBA ; WRITE_CTRL      - Control write

; ============================================================================
; 2.12: Data Transfer Operations (0xD0-0xDF)
; ============================================================================

OP_DATA_INIT   EQU 0xD0 ; DATA_INIT       - Initialize data transfer
OP_DATA_RECV   EQU 0xD1 ; DATA_RECV       - Receive data frame
OP_DATA_ACK    EQU 0xD2 ; DATA_ACK        - Send acknowledgement
OP_DATA_ASSEMBLE EQU 0xD3 ; DATA_ASSEMBLE - Assemble chunks
OP_DATA_VERIFY EQU 0xD4 ; DATA_VERIFY     - Verify transfer
OP_DATA_STORE  EQU 0xD5 ; DATA_STORE      - Store received data
OP_DATA_ABORT  EQU 0xD6 ; DATA_ABORT      - Abort transfer
OP_DATA_SEND   EQU 0xD7 ; DATA_SEND       - Send data frame

; ============================================================================
; 2.13: QSLCL Bootstrap Operations (0xE0-0xEF)
; ============================================================================

OP_BOOT_INIT  EQU 0xE0 ; BOOT_INIT       - Initialize bootstrap
OP_BOOT_VERIFY EQU 0xE1 ; BOOT_VERIFY    - Verify bootstrap
OP_BOOT_JUMP  EQU 0xE2 ; BOOT_JUMP       - Jump to bootstrap entry
OP_BOOT_SETUP EQU 0xE3 ; BOOT_SETUP      - Setup bootstrap environment
OP_BOOT_SECURE EQU 0xE4 ; BOOT_SECURE    - Secure bootstrap
OP_BOOT_RECOVER EQU 0xE5 ; BOOT_RECOVER  - Recover bootstrap

; ============================================================================
; 2.14: USB4 v2.0 Operations (0xF0-0xFF)
; ============================================================================

OP_USB4_TUNNEL_CREATE EQU 0xF0 ; USB4_TUNNEL_CREATE - Create USB4 tunnel
OP_USB4_TUNNEL_DESTROY EQU 0xF1 ; USB4_TUNNEL_DESTROY - Destroy USB4 tunnel
OP_USB4_BANDWIDTH_SET EQU 0xF2 ; USB4_BANDWIDTH_SET - Set USB4 bandwidth
OP_USB4_PATH_OPTIMIZE EQU 0xF3 ; USB4_PATH_OPTIMIZE - Optimize USB4 path
OP_USB4_SECURE_CHANNEL EQU 0xF4 ; USB4_SECURE_CHANNEL - Secure channel
OP_USB4_DMA_DIRECT EQU 0xF5 ; USB4_DMA_DIRECT - Direct DMA
OP_USB4_80G_MODE EQU 0xF6 ; USB4_80G_MODE - Enable 80Gbps mode
OP_USB4_PAM_ENCODE EQU 0xF7 ; USB4_PAM_ENCODE - PAM encoding
OP_USB4_LANE_AGGREGATE EQU 0xF8 ; USB4_LANE_AGGREGATE - Lane aggregation
OP_USB4_LATENCY_PROBE EQU 0xF9 ; USB4_LATENCY_PROBE - Probe latency
OP_USB4_CMA_MEASURE EQU 0xFA ; USB4_CMA_MEASURE - Component measurement
OP_USB4_ATTEST EQU 0xFB ; USB4_ATTEST   - Attestation

; ============================================================================
; SECTION 3: MACROS (Common Instruction Patterns)
; ============================================================================

; ----------------------------------------------------------------------------
; 3.1: Function Call Macros
; ----------------------------------------------------------------------------

; Define a function
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

; ----------------------------------------------------------------------------
; 3.2: Memory Access Macros
; ----------------------------------------------------------------------------

; Load 32-bit value from memory
%macro LOAD 2
    LOAD32 %1, %2
%endmacro

; Store 32-bit value to memory
%macro STORE 2
    STORE32 %1, %2
%endmacro

; ----------------------------------------------------------------------------
; 3.3: USB Operation Macros
; ----------------------------------------------------------------------------

; Send USB packet
%macro USB_SEND 0
    CALL usb_send
%endmacro

; Receive USB packet
%macro USB_RECV 0
    CALL usb_recv
%endmacro

; Initialize USB
%macro USB_INIT 0
    OP_USB_INIT 0, 0
%endmacro

; ----------------------------------------------------------------------------
; 3.4: Crypto Macros
; ----------------------------------------------------------------------------

; Get random number into register
%macro RAND 1
    RNG %1
%endmacro

; Calculate SHA256
%macro SHA256 2
    SHA256 %1, %2
%endmacro

; Calculate CRC32
%macro CRC32 2
    CRC32 %1, %2
%endmacro

; ----------------------------------------------------------------------------
; 3.5: BootROM Operations
; ----------------------------------------------------------------------------

; Boot from USB
%macro BOOT_USB 0
    BOOT_INIT
    BOOT_VERIFY
    BOOT_JUMP
%endmacro

; ============================================================================
; SECTION 4: EXAMPLE PROGRAMS
; ============================================================================

; ----------------------------------------------------------------------------
; 4.1: Minimal "Hello World" Program
; ----------------------------------------------------------------------------

START:
    MOV R0, 1           ; Message type
    MOV R1, 100         ; Message length
    CALL send_message   ; Send message
    RET                 ; Return

send_message:
    PUSH R14            ; Save return address
    LOAD32 R2, 0x1000   ; Load message address
    LOAD32 R3, 0x100    ; Load message length
    SYSCALL 1           ; Send IPC message
    POP R14             ; Restore return address
    RET

; ----------------------------------------------------------------------------
; 4.2: USB Setup Packet Handler
; ----------------------------------------------------------------------------

; Setup packet format: [bmRequestType][bRequest][wValue][wIndex][wLength]
SETUP_HANDLER:
    PUSH R14            ; Save return address
    
    ; Read setup packet
    USB_READ_CTRL
    CMP R0, 0           ; Check if packet received
    JZ SETUP_ERROR      ; Jump if error
    
    ; Check request type
    LOAD8 R1, 0x2000    ; Load bmRequestType
    CMP R1, 0x80        ; Check if device-to-host
    JNZ SETUP_ERROR
    
    ; Process standard request
    MOV R2, 0x06        ; GET_DESCRIPTOR
    CALL process_descriptor
    
    POP R14             ; Restore return address
    RET

SETUP_ERROR:
    MOV R0, 0xFFFF      ; Return error
    RET

; ----------------------------------------------------------------------------
; 4.3: Watchdog Disabler
; ----------------------------------------------------------------------------

; Disable watchdog on Apple A-series (0x20E00000)
DISABLE_WATCHDOG:
    PUSH R14
    MOV R0, 0x20E00000  ; Watchdog address
    LOAD32 R1, R0       ; Read current value
    MOV R2, 0x00000000  ; Disable value
    STORE32 R2, R0      ; Write disable value
    POP R14
    RET

; ============================================================================
; SECTION 5: QSLCLBIN STRUCTURE
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
; SECTION 6: COMMAND DEFINITIONS (28 commands)
; ============================================================================

; Core Memory Operations
CMD_READ        EQU 0x01
CMD_WRITE       EQU 0x02
CMD_ERASE       EQU 0x03
CMD_PEEK        EQU 0x04
CMD_POKE        EQU 0x05
CMD_PATCH       EQU 0x06
CMD_DUMP        EQU 0x07

; Device Interaction
CMD_HELLO       EQU 0x10
CMD_PING        EQU 0x11
CMD_GETINFO     EQU 0x12

; System Control
CMD_RESET       EQU 0x20
CMD_POWER       EQU 0x21
CMD_CONFIG      EQU 0x22

; Voltage & Hardware
CMD_VOLTAGE     EQU 0x30
CMD_RAWSTATE    EQU 0x31

; Security & Analysis
CMD_RAWMODE     EQU 0x40
CMD_BYPASS      EQU 0x41
CMD_VERIFY      EQU 0x42
CMD_FOOTER      EQU 0x43

; Diagnostic & Testing
CMD_CRASH       EQU 0x50
CMD_GLITCH      EQU 0x51
CMD_BRUTEFORCE  EQU 0x52
CMD_TEST        EQU 0x53
CMD_FUZZ        EQU 0x54

; Manufacturing & ODM
CMD_OEM         EQU 0x60
CMD_ODM         EQU 0x61

; ============================================================================
; SECTION 7: FAULT CODES (from QSLCLRTF)
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
; END OF FILE
; ============================================================================