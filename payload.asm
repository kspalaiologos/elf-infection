format ELF64 executable
use64

entry _start

seed: dq 0

LCG_A equ 1103515245
LCG_B equ 12345

_start:
    ; Query the current time stamp counter as a source of randomness.
    ; rdtsc will set rdx and rax to the higher and lower bits of the time
    ; stamp counter, so we put them together and store them in the RNG seed
    ; variable.
    rdtsc
    shl rdx, 32
    or rdx, rax
    mov qword [seed], rdx
    ; Open the sound device.
    mov rax, 2
    mov r8, 1
    mov edi, snddev
    mov rsi, r8
    syscall
    ; Play the "suspense" sound.
    mov edi, eax
    xor ebp, ebp
    ; Load the place on the stack where the sample is saved.
    lea rsi, [rsp - 4]
    xor ebx, ebx
.susp_loop:
    ; 58000 ticks.
    cmp ebx, 58000
    je .susp_done
    ; Generate the sample.
    mov ecx, ebx
    shr ecx, 13
    and cl, 27
    mov eax, 322376503
    shr eax, cl
    and eax, 127
    imul eax, ebx
    mov ecx, ebx
    shr ecx, 4
    or ecx, ebp
    or ecx, eax
    ; Save and write.
    mov dword [rsp - 4], ecx
    mov rdx, r8
    mov rax, r8
    syscall
    ; Loop again.
    inc ebx
    add ebp, 32
    jmp .susp_loop
.susp_done:
    ; Purposefully waste some CPU cycles for delay.
    mov eax, 100000
.busy:
    sub eax, 1
    jb .busydone
    nop
    jmp .busy
.busydone:
    ; Roll a dice. 33% chance of playing the "doomy" sound.
    imul rax, qword [seed], LCG_A
    add rax, LCG_B
    mov qword [seed], rax
    xor ebp, ebp
    mov r9, 3
    xor edx, edx
    div r9
    test rdx, rdx
    je .doomy
    ; Generate the "good" samples!
    mov r10d, 1
    mov ebx, 8
    mov ebp, 13
    lea rsi, [rsp - 12]
    mov r14d, 12
    ; The song is procedurally generated in stages three stages:
    ; stage 0, stage 1 and stage 2.
.good_main:
    cmp r10d, 106000
    je .good_done
    mov eax, ebp
    mov ecx, ebx
    cmp r10d, 35000
    jb .good0
    cmp r10d, 67499
    ja .good1
    lea ecx, [r10 + 8 * r10]
    mov eax, ebp
    jmp .good0
.good1:
    cmp r10d, 83999
    ja .good2
    lea ecx, [r10 + 8 * r10]
    mov eax, r14d
    jmp .good0
.good2:
    lea ecx, [8*r10]
    cmp r10d, 98000
    mov eax, ebp
    sbb eax, 0
.good0:
    mov edx, r10d
    shr edx, 2
    imul eax, r10d
    add eax, edx
    mov edx, r10d
    shr edx, 3
    or edx, ecx
    mov ecx, r10d
    shr ecx, 5
    or ecx, edx
    or ecx, eax
    ; Write the sample.
    mov dword [rsp - 12], ecx
    mov rdx, r8
    mov rax, r8
    syscall
    inc r10d
    add ebx, 8
    jmp .good_main
.good_done:
    ; Close file descriptor.
    mov rax, r9
    syscall
    jmp .cleanup
.doomy:
    ; "Doomy" track.
    lea rsi, [rsp - 8]
.doomy_loop:
    cmp ebp, 250000
    je .cleanup
    mov eax, ebp
    shr eax, 11
    mov ecx, ebp
    shr ecx, 1
    or ecx, eax
    imul eax, ecx, 430
    ; Write the sample.
    mov dword [rsp - 8], eax
    mov rdx, r8
    mov rax, r8
    syscall
    add ebp, 5
    jmp .doomy_loop
.cleanup:
    ; Exit with code 0.
    mov rax, 60
    xor edi, edi
    syscall

snddev: db "/dev/dsp1", 0
