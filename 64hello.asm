%idefine TWORD_size 10
%idefine QWORD_size 8
%idefine DWORD_size 4
%idefine WORD_size 2
%idefine BYTE_size 1
%imacro VAR 2+
%{1}: %{2}
%{1}_size equ ($-%{1})
%endmacro
%idefine sizeof(_x_) _x_%+_size

section .text
    global _start

_start:
 times 100 db 90h

    call drgs
    var msg, db "Hello D R E G!",10,10,0
    drgs:

    pop rsi
    mov rax, 1
    mov rdi, 1
    mov rdx, sizeof(msg)
    syscall

 times 100 db 90h
