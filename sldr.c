/*
 * This project is based on tel_ldr.
 * tel_ldr:
 *   The MIT License (MIT)
 *   Copyright (c) 2015 Shinichiro Hamaji
 *   https://github.com/shinh/tel_ldr
 *
 * License: MIT <http://www.opensource.org/licenses/mit-license.php>
 */

#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef DEBUG_BUILD
#define DEBUG_PRINTF(format, ...) \
  printf("[%u] " format, __LINE__, ##__VA_ARGS__)
#define RELEASE_UNUSED
#else
#define DEBUG_PRINTF(format, ...) ((void)0)
#define RELEASE_UNUSED __attribute__((__unused__))
#endif

#define UNUSED __attribute__((__unused__))

void abort_with_msg(const char* msg) {
  if (errno)
    perror(msg);
  else
    fprintf(stderr, "%s\n", msg);

  abort();
}

void und_func() {
  fprintf(stderr, "undefined function\n");

  abort();
}

int g_argc;
char** g_argv;

int H__libc_start_main(int (*guest_main)(int, char**, char**),
                       int argc, char** argv,
                       void (*init)(void), void (*fini)(void) UNUSED,
                       void (*rtld_fini)(void) UNUSED, void (*stack_end) UNUSED) {
  if (g_argc) {
    argc = g_argc;
    argv = g_argv;
  }

  DEBUG_PRINTF("%s: init(%p), fini(%p), rtld_fini(%p), stack_end(%p)\n", __func__, init, fini, rtld_fini, stack_end);

  if (init)
    (*init)();

  exit(guest_main(argc, argv, 0));
}

#define HOST_FUNC_ENTRY(n) { #n, (void*)&H ## n },
struct {
  const char* name;
  void* sym;
} HOST_SYMS[] = {
  {"stdin",  NULL},
  {"stdout", NULL},
  {"stderr", NULL},
  HOST_FUNC_ENTRY(__libc_start_main)
  {0, 0},
};

#define D_HANDLES_MAX 10
struct {
  int dstroff;
  void* handle;
} D_HANDLES[D_HANDLES_MAX + 1] = {};

void relocate(const char* reloc_type RELEASE_UNUSED,
              Elf32_Rel* rel, int relsz,
              Elf32_Sym* dsym, char* dstr) {
  unsigned int i;

  for (i = 0; i < relsz / sizeof(*rel); rel++, i++) {
    int k;
    int* addr = (int*)rel->r_offset;
    int type = ELF32_R_TYPE(rel->r_info);
    Elf32_Sym* sym = dsym + ELF32_R_SYM(rel->r_info);
    char* sym_name = dstr + sym->st_name;
    void* val = 0;

    for (k=0; HOST_SYMS[k].name; k++) {
      if (!strcmp(sym_name, HOST_SYMS[k].name)) {
        val = HOST_SYMS[k].sym;
        break;
      }
    }
    if (!val)
      val = dlsym(RTLD_DEFAULT, sym_name);

    for (k = 0; !val && D_HANDLES[k].dstroff != 0; k++)
      val = dlsym(D_HANDLES[k].handle, sym_name);

    DEBUG_PRINTF("%s: %p %s(%d) %d => %p\n",
           reloc_type, (void*)addr, sym_name, (int)sym, type, val);

    switch (type) {
      case R_386_COPY: {
        if (val) {
          *addr = *(int*)val;
        } else {
          fprintf(stderr, "undefined: %s\n", sym_name);
          abort();
        }
        break;
      }
      case R_386_JMP_SLOT: {
        if (val) {
          *addr = (int)val;
        } else {
          *addr = (int)&und_func;
        }
        break;
      }
    }
  }
}

void cleanup(void) {
  int i;

  DEBUG_PRINTF("%s\n", __func__);

  for (i = 0; D_HANDLES[i].dstroff != 0; i++)
    dlclose(D_HANDLES[i].handle);
}

int main(int argc, char* argv[]) {
  int i, fd;
  int entry, phoff, phnum;
  Elf32_Ehdr ehdr;

  HOST_SYMS[0].sym = &stdin;
  HOST_SYMS[1].sym = &stdout;
  HOST_SYMS[2].sym = &stderr;

  if (argc < 2)
    abort_with_msg("Usage: sldr <elf>");

  DEBUG_PRINTF("loading %s\n", argv[1]);

  fd = open(argv[1], O_RDONLY);
  if (fd < 0)
    abort_with_msg("cannot open elf");

  if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
    abort_with_msg("reading elf header failed");

  if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG))
    abort_with_msg("not elf");

  if (ehdr.e_type != ET_EXEC || ehdr.e_machine != EM_386)
    abort_with_msg("not i386 exec");

  entry = ehdr.e_entry;
  phoff = ehdr.e_phoff;
  phnum = ehdr.e_phnum;
  DEBUG_PRINTF("entry=0x%x phoff=0x%x phnum=0x%x\n", entry, phoff, phnum);

  if (lseek(fd, phoff, SEEK_SET) != phoff)
    abort_with_msg("lseek failed");

  DEBUG_PRINTF("\n");
  for (i = 0; i < phnum; i++) {
    int poff, paddr, pfsize, psize, pafsize, pflag;
    Elf32_Phdr phdr;

    if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr))
      abort_with_msg("reading program header failed");

    poff = phdr.p_offset;
    paddr = phdr.p_vaddr;
    pfsize = phdr.p_filesz;
    psize = phdr.p_memsz;
    pflag = phdr.p_flags;

    switch (phdr.p_type) {
      case PT_PHDR: {
        DEBUG_PRINTF("PT_PHDR\n");
        break;
      }
      case PT_INTERP: {
        DEBUG_PRINTF("PT_INTERP\n");
        break;
      }
      case PT_NOTE: {
        DEBUG_PRINTF("PT_NOTE\n");
        break;
      }
      case PT_LOAD: {
        int prot = 0;

        if (pflag & 1)
          prot |= PROT_EXEC;
        if (pflag & 2)
          prot |= PROT_WRITE;
        if (pflag & 4)
          prot |= PROT_READ;
        psize += paddr & 0xfff;
        pfsize += paddr & 0xfff;
        poff -= paddr & 0xfff;
        paddr &= ~0xfff;
        pafsize = (pfsize + 0xfff) & ~0xfff;
        psize = (psize + 0xfff) & ~0xfff;
        DEBUG_PRINTF("PT_LOAD psize=%d pafsize=%d pflag=%d paddr=0x%x prot=%d poff=%d\n",
               psize, pafsize, pflag, paddr, prot, poff);
        if (mmap((void*)paddr, pafsize, prot, MAP_FILE|MAP_PRIVATE|MAP_FIXED,
                 fd, poff) == MAP_FAILED) {
          abort_with_msg("mmap(file)");
        }
        if ((prot & PROT_WRITE)) {
          for (; pfsize < pafsize; pfsize++) {
            char* p = (char*)paddr;
            p[pfsize] = 0;
          }
          if (pfsize != psize) {
            if (mmap((void*)(paddr + pfsize),
                     psize - pfsize, prot, MAP_ANON|MAP_PRIVATE,
                     -1, 0) == MAP_FAILED) {
              abort_with_msg("mmap(anon)");
            }
          }
        }
        break;
      }
      case PT_DYNAMIC: {
        char* dstr = NULL;
        Elf32_Sym* dsym = NULL;
        Elf32_Rel* rel = NULL;
        int relsz = 0, pltrelsz = 0, k = 0;
        Elf32_Dyn* dyn;

        DEBUG_PRINTF("PT_DYNAMIC\n");

        for (dyn = (Elf32_Dyn*)paddr; dyn->d_tag != DT_NULL; dyn++) {
          switch (dyn->d_tag) {
            case DT_PLTGOT: {
              DEBUG_PRINTF("DT_PLTGOT %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_STRSZ: {
              DEBUG_PRINTF("DT_STRSZ %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_SYMENT: {
              DEBUG_PRINTF("DT_SYMENT %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_INIT: {
              DEBUG_PRINTF("DT_INIT %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_FINI: {
              DEBUG_PRINTF("DT_FINI %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_INIT_ARRAY: {
              DEBUG_PRINTF("DT_INIT_ARRAY %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_FINI_ARRAY: {
              DEBUG_PRINTF("DT_FINI_ARRAY %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_INIT_ARRAYSZ: {
              DEBUG_PRINTF("DT_INIT_ARRAYSZ %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_FINI_ARRAYSZ: {
              DEBUG_PRINTF("DT_FINI_ARRAYSZ %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_NEEDED: {
              DEBUG_PRINTF("needed: %d\n", dyn->d_un.d_val);
              assert(k < D_HANDLES_MAX);
              D_HANDLES[k++].dstroff = dyn->d_un.d_val;
              break;
            }
            case DT_RPATH: {
              printf("warning: unsupport(DT_RPATH)\n");
              printf("         use the environment variable LD_LIBRARY_PATH\n");
              break;
            }
            case DT_RUNPATH: {
              printf("warning: unsupport(DT_RUNPATH)\n");
              printf("         use the environment variable LD_LIBRARY_PATH\n");
              break;
            }
            case DT_PLTRELSZ: {
              pltrelsz = dyn->d_un.d_val;
              DEBUG_PRINTF("pltrelsz: %d\n", pltrelsz);
              break;
            }
            case DT_STRTAB: {
              dstr = (char*)dyn->d_un.d_ptr;
              DEBUG_PRINTF("dstr: %p %s\n", dstr, dstr+1);
              break;
            }
            case DT_SYMTAB: {
              dsym = (Elf32_Sym*)dyn->d_un.d_ptr;
              DEBUG_PRINTF("dsym: %p\n", dsym);
              break;
            }
            case DT_REL: {
              rel = (Elf32_Rel*)dyn->d_un.d_ptr;
              DEBUG_PRINTF("rel: %p\n", rel);
              break;
            }
            case DT_RELSZ: {
              relsz = dyn->d_un.d_val;
              DEBUG_PRINTF("relsz: %d\n", relsz);
              break;
            }
            case DT_RELENT: {
              int relent = dyn->d_un.d_val;

              DEBUG_PRINTF("relent: %d\n", relent);
              if (relent != sizeof(*rel))
                abort_with_msg("unexpected RELENT");
              break;
            }
            case DT_PLTREL: {
              int pltrel = dyn->d_un.d_val;

              DEBUG_PRINTF("pltrel: %d\n", pltrel);
              if (pltrel != DT_REL)
                abort_with_msg("unexpected PLTREL");
              break;
            }
            case DT_DEBUG: {
              DEBUG_PRINTF("DT_DEBUG %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_JMPREL: {
              DEBUG_PRINTF("DT_JMPREL %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_GNU_HASH: {
              DEBUG_PRINTF("DT_GNU_HASH %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_VERSYM: {
              DEBUG_PRINTF("DT_VERSYM %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_VERNEED: {
              DEBUG_PRINTF("DT_VERNEED %d\n", dyn->d_un.d_val);
              break;
            }
            case DT_VERNEEDNUM: {
              DEBUG_PRINTF("DT_VERNEEDNUM %d\n", dyn->d_un.d_val);
              break;
            }
            default:
              DEBUG_PRINTF("unknown DYN %d %d\n", dyn->d_tag, dyn->d_un.d_val);
              break;
          }
        }
        if (!dsym || !dstr)
          abort_with_msg("no dsym or dstr");

        for (k = 0; D_HANDLES[k].dstroff != 0; k++) {
          D_HANDLES[k].handle = dlopen(dstr+D_HANDLES[k].dstroff, RTLD_LAZY);
          DEBUG_PRINTF("dlopen: %p %s\n", D_HANDLES[k].handle, dstr+D_HANDLES[k].dstroff);
        }

        relocate("rel", rel, relsz, dsym, dstr);
        relocate("pltrel", rel + relsz / sizeof(*rel), pltrelsz, dsym, dstr);

        break;
      }
      case PT_GNU_EH_FRAME: {
        DEBUG_PRINTF("PT_GNU_EH_FRAME\n");
        break;
      }
      case PT_GNU_STACK: {
        DEBUG_PRINTF("PT_GNU_STACK\n");
        break;
      }
      case PT_GNU_RELRO: {
        DEBUG_PRINTF("PT_GNU_RELRO\n");
        break;
      }
      default:
        DEBUG_PRINTF("unknown PT %d\n", phdr.p_type);
        break;
    }
    DEBUG_PRINTF("\n");
  }

  atexit(cleanup);

  g_argc = argc - 1;
  g_argv = argv + 1;

  printf("START %s entry(0x%x)\n", argv[1], entry);
  printf("---\n");

  ((void*(*)())entry)();

  return 1;
}
