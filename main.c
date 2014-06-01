#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#define PACKAGE         42  /* Defined to ignore config.h include in bfd.h */
#define PACKAGE_VERSION 42  /* Defined to ignore config.h include in bfd.h */
#include <bfd.h>
#include <dis-asm.h>


/* Special thanks to the following for providing a very helpful example of how
 * to use libopcodes + libbfd:
 * http://www.toothycat.net/wiki/wiki.pl?Binutils/libopcodes
 */
#define _PR(_tag, ...) do {                            \
        fprintf(stderr, "[symscan]" _tag __VA_ARGS__); \
        fputc('\n', stderr);                           \
        exit(EXIT_FAILURE);                            \
} while(0)

#define ERR(...) _PR("[error] ", __VA_ARGS__)

#ifdef DEBUG
#define DBG(...) _PR("[debug] ", __VA_ARGS__)
#else
#define DBG(...)
#endif


/* Globals accessable from callbacks which have no other means of accessing this
 * data.
 */
static bfd *bin;
static asymbol **symbols, **sorted_symbols;
static struct disassemble_info dis_info;


/* Address to the current instruction we are processing */
static bfd_vma curr_addr, start_addr;


/* Given a vm address scan the symbol table  and return the given symbol if
 * found, and NULL otherwise.
 */
static const asymbol *addr_to_symbol(bfd_vma addr)
{
    int i;

    /* If we find an exact match return early */
    for (i=0; sorted_symbols[i]; ++i)
      if (addr == bfd_asymbol_value(sorted_symbols[i]))
        return sorted_symbols[i];
    return NULL;
}


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
    const asymbol *sym;
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
        if (!bfd_find_nearest_line(bin, dis_info.section, symbols,
                                   curr_addr - start_addr,
                                   &fname, &fnname, &lineno))
        {
            va_end(va);
            return 0;
        }

        /* Convert the string representation of the call operand to a value */
        sym = addr_to_symbol(strtoll(str, NULL, 16));
        printf("\t\"%s\" -> \"%s\"\n",
               fnname, sym ? bfd_asymbol_name(sym) : str);
    }

    va_end(va);
    return 0;
}


static void dump_symbols(const asymbol **syms)
{
#ifdef DEBUG
    int i;

    DBG("Dumping symbols:");
    for (i=0; syms[i]; ++i)
      DBG("  %d) %s (0x%lx)",
          i+1, 
          bfd_asymbol_name(syms[i]),
          bfd_asymbol_value(syms[i]));
#endif
}


/* Predicate to qsort */
static int cmp_symbol_addr(const void *s1, const void *s2)
{
    bfd_vma a = bfd_asymbol_value(*(const asymbol **)s1);
    bfd_vma b = bfd_asymbol_value(*(const asymbol **)s2);
    if (a < b)
      return -1;
    else if (a == b)
      return 0;
    else
      return 1;
}


/* Read the BFD and obtain the symbols.  We take a hint from addr2line and
 * objdump.  If we have no normal symbols (e.g., the case of a striped binary)
 * then we use the dynamic symbol table.  We only use the latter if there are no
 * regular symbols.
 */
static void get_symbols(bfd *bin)
{
    int i, idx, n_syms, size;
    bool is_dynamic;

    /* Debugging */
    DBG("Symbols:         %ld", bfd_get_symtab_upper_bound(bin));
    DBG("Dynamic Symbols: %ld", bfd_get_dynamic_symtab_upper_bound(bin));

    /* Get symbol table size (if no regular syms, get dynamic syms) */
    is_dynamic = false;
    size = bfd_get_symtab_upper_bound(bin);
    if (!size)
    {
        if (!(size = bfd_get_dynamic_symtab_upper_bound(bin)))
          ERR("Could not locate any symbols");
        is_dynamic = 1;
    }

    if (!(symbols = malloc(size)))
      ERR("Could not allocate enough memory to store the symbol table");

    n_syms = (is_dynamic) ? bfd_canonicalize_dynamic_symtab(bin, symbols) :
                            bfd_canonicalize_symtab(bin, symbols);

    if (!n_syms)
      ERR("Could not locate any symbols");

    DBG("Loaded %d symbols\n", n_syms);

    /* Sort the symbols for easer searching via location */
    if (!(sorted_symbols = calloc(n_syms, sizeof(asymbol*))))
      ERR("Could not allocate enough memory to store a sorted symbol table");

    /* Ignore symbols with a value(address) of 0 */
    for (i=0, idx=0; i<n_syms; ++i)
      if (bfd_asymbol_value(symbols[i]) != 0)
        sorted_symbols[idx++] = symbols[i];
    qsort(sorted_symbols, idx, sizeof(asymbol *), cmp_symbol_addr);

    /* Debug */
    dump_symbols((const asymbol **)sorted_symbols);
}


int main(int argc, char **argv)
{
    int length;
    const char *fname;
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

    get_symbols(bin);

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
