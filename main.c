#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#define PACKAGE         42  /* Defined to ignore config.h include in bfd.h */
#define PACKAGE_VERSION 42  /* Defined to ignore config.h include in bfd.h */
#include <bfd.h>
#include <dis-asm.h>


/* Special thanks to the following for providing a very helpful example of how
 * to use libopcodes + libbfd:
 * http://www.toothycat.net/wiki/wiki.pl?Binutils/libopcodes
 */
#define _PR(_tag, ...) do {                               \
        fprintf(stderr, "[symscan]" _tag __VA_ARGS__); \
        fputc('\n', stderr);                              \
} while(0)

#define ERR(...) _PR("[error]", __VA_ARGS__)

#ifdef DEBUG
#define DBG(...) _PR("[debug]", __VA_ARGS__)
#else
#define DBG(...)
#endif

/* Globals accessable from callbacks which have no other means of accessing this
 * data.
 */
static bfd *bin;
static asymbol **symbols;
static struct disassemble_info dis_info;

/* Address to the current instruction we are processing */
static bfd_vma curr_addr, start_addr;

/* Each insn and all arguments are passed as individual strings:
 * We only care about calls and returns.
 * 
 * We look for call and the next value, which should be the address/function
 * being called.
 *
 * We also look for 'ret' and the next address will be the beginning of the new
 * function.
 */ 
static int process_insn(void *stream, const char *fmt, ...)
{
    va_list va;
    unsigned lineno;
    const char *str, *fname, *fnname;
    static int have_call;
    
    va_start(va, fmt);
    str = va_arg(va, char *);

    if (!str)
    {
        va_end(va);
        return 0;
    }

    if (strncmp(str, "call", strlen("call")) == 0)
      have_call = 1;
    else if (have_call)
    {
        have_call = 0;
        if (!bfd_find_nearest_line(bin, dis_info.section, symbols, curr_addr - start_addr,
                                   &fname, &fnname, &lineno))
        {
            va_end(va);
            return 0;
        }
        printf("\"%s\" -> \"%s\"\n", fnname, str);
    }

    va_end(va);
    return 0;
}


int main(int argc, char **argv)
{
    int length;
    const char *fname;
    //bfd_vma start_addr;
    asection *text;
    disassembler_ftype dis;

    if (argc != 2)
    {
        printf("Usage: %s <executable>\n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    fname = argv[1];
    
    /* Initialize the binary description (needed for disassembly parsing) */ 
    bfd_init();
    if (!(bin = bfd_openr(fname, NULL)))
    {
        bfd_perror("Error opening executable");
        exit(EXIT_FAILURE);
    }
    
    if (!bfd_check_format(bin, bfd_object))
    {
        bfd_perror("Bad format (expected object)");
        exit(EXIT_FAILURE);
    }

    /* Get the information about the .text section of the binary */
    if (!(text = bfd_get_section_by_name(bin, ".text")))
    {
        bfd_perror("Could not locate .text section of the binary");
        exit(EXIT_FAILURE);
    }

    /* Initialize libopcodes */
    init_disassemble_info(&dis_info, stdout, (fprintf_ftype)process_insn);
    dis_info.arch = bfd_get_arch(bin);
    dis_info.mach = bfd_get_mach(bin);
    dis_info.section = text;
    dis_info.buffer_vma = text->vma;
    dis_info.buffer_length = text->size;
    disassemble_init_for_target(&dis_info);

    /* Suck in .text */
    bfd_malloc_and_get_section(bin, text, &dis_info.buffer);

    /* Get symbols */
    symbols = malloc(bfd_get_symtab_upper_bound(bin));
    if (!symbols)
        ERR("Could not allocate enough room to store the symbol table");

    if (!bfd_canonicalize_symtab(bin, symbols))
        ERR("Could not obtain the symbol table");

    /* Create a handle to the disassembler */
    if (!(dis = disassembler(bin)))
    {
        bfd_perror("Error creating disassembler parser");
        exit(EXIT_FAILURE);
    }

    /* dot output */
    printf("digraph \"%s\"{\n", fname);

    curr_addr = start_addr = bfd_get_start_address(bin);
    while ((length = dis(curr_addr, &dis_info)))
    {
        curr_addr += length;
        if ((length < 1) || (curr_addr >= (text->size + start_addr)))
            break;
    }

    bfd_close(bin);
    printf("}\n");

    return 0;
}
