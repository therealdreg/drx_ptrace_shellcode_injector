#!/bin/bash

# MIT License - Copyright 2020
# David Reguera Garcia aka Dreg - dreg@fr33project.org
# -
# http://github.com/David-Reguera-Garcia-Dreg/ - http://www.fr33project.org/
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

set -x
rm -f 64hello 64hello.o
rm -f 32hello 32hello.o
nasm -felf64 -o 64hello.o 64hello.asm  && ld -m elf_x86_64 64hello.o -o 64hello && hexdump -v -e '"\\""x" 1/1 "%02x" ""' 64hello && echo && echo
nasm -felf32 -o 32hello.o 32hello.asm  && ld -m elf_i386 32hello.o -o 32hello && hexdump -v -e '"\\""x" 1/1 "%02x" ""' 32hello && echo && echo
