TODOs

1. Memory operations
    - [x] Segment add
    - [x] Read/write operations
    - [x] Map address to segment
    - [x] Testing
2. ELF
    - [x] ELF file loading
    - [x] Testing
3. CPU operations
    - [x] Registers
    - [~] Decoding
        - [x] Correct routing to CALL, Format2, and Format3
    - [~] Instructions
        - [x] CALL
        - [x] SAVE
        - [x] RESTORE
        - [x] NOP
        - [x] SETHI
        - [x] OR
        - [x] CLR
        - [x] TA
            - Created new TrapInstruction class since format of trap instructions is different from Format3Instruction
        - [x] JMPL/RETL
        - [x] ST
        - [x] LD
    - [x] Register windows
        - [x] Windows implemented
        - [x] SAVE Instruction
        - [x] RESTORE Instruction
    - [ ] Cycling
    - [~] Testing
4. Syscalls
    - [x] Write
    - [x] Exit
    - [~] Testing