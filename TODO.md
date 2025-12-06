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
    - [x] Instructions
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
        - [x] Bicc (b/ba, bne, bl, be, ble, bg, bge, bgu, bleu, bcc, bcs, bpos, bneg, bvc, bvs)
        - [x] ADD
        - [x] ADDCC
        - [x] SUB
        - [x] SUBCC (cmp)
        - [x] SRA
        - [x] SMUL
        - [x] SDIV
        - [x] WRY
    - [x] Register windows
        - [x] Windows implemented
        - [x] SAVE Instruction
        - [x] RESTORE Instruction
    - [x] Cycling
    - [x] Integer Condition Codes (ICC)
    - [~] Testing
4. Syscalls
    - [x] Write
    - [x] Exit
    - [~] Testing
