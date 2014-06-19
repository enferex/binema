/******************************************************************************
 * main.c
 *
 * binema - Binary to callgraph generator
 *
 * Copyright (C) 2014, Matt Davis (enferex) <mattdavis9@gmail.com>
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or (at
 * your option) any later version.
 *             
 * This program is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more
 * details.
 *                             
 * You should have received a copy of the GNU
 * General Public License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
******************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#define PACKAGE         42  /* Defined to ignore config.h include in bfd.h */
#define PACKAGE_VERSION 42  /* Defined to ignore config.h include in bfd.h */
#include <bfd.h>
#include <dis-asm.h>

#ifdef USE_IGRAPH
#include <igraph/igraph.h>
#endif


/* Special thanks to the following for providing a very helpful example of how
 * to use libopcodes + libbfd:
 * http://www.toothycat.net/wiki/wiki.pl?Binutils/libopcodes
 */
#define _PR(_tag, ...) do {                            \
        fprintf(stderr, "[symscan]" _tag __VA_ARGS__); \
        fputc('\n', stderr);                           \
} while(0)

#define ERR(...) do {             \
    _PR("[error] ", __VA_ARGS__); \
    exit(EXIT_FAILURE);           \
} while(0)

#ifdef DEBUG
#define DBG(...) _PR("[debug] ", __VA_ARGS__)
#else
#define DBG(...)
#endif


/* A container to keep a list of nodes... */
static unsigned id_pool;
struct _func_t;
typedef struct _node_list_t 
{
    struct _func_t *func;
    struct _node_list_t *next;
} node_list_t;


/* A node in a callgraph is a function */
typedef struct _func_t
{
    const asymbol  *sym;  /* Symbol name for the function         */
    node_list_t *callees; /* Other functions this function calls  */
    unsigned  id;         /* Unique number for each func instance */

    /* If no symbol 'sym' store the str from disassembly here
     * 'str' represents the disassembly string, usually an address with no
     * associated symbol name
     */
    const char *str;
} func_t;


/* Data type to store our callgraph */
typedef struct _graph_t
{
    const char *filename;
    node_list_t *funcs;
} graph_t;


/* Globals accessable from callbacks which have no other means of accessing this
 * data.
 */
static bfd *bin;
static asymbol **symbols, **sorted_symbols;
static struct disassemble_info dis_info;


/* Address to the current instruction we are processing */
static bfd_vma curr_addr, start_addr;


static void usage(const char *execname)
{
    printf("Usage: %s [-f executable] [-d] [-s]\n"
           "  -f executable: File to create a callgraph from\n"
           "  -d:            Output callgraph in dot format\n"
#ifdef USE_IGRAPH
           "  -s:            Output graph summary\n"
#endif
           , execname);
    exit(EXIT_SUCCESS);
}


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


/* Search the symbol table for the symbol that matches the given string */
static const asymbol *str_to_symbol(const char *name)
{
    int i;

    for (i=0; symbols[i]; ++i)
      if (strcmp(symbols[i]->name, name) == 0)
        return symbols[i];

    return NULL;
}


/* Create and add a node to the graph (this does not check uniqueness) */
static func_t *add_node(graph_t *graph, const asymbol *sym, const char *str)
{
    func_t *func;
    node_list_t *list;

    if (!(func =  calloc(1, sizeof(func_t))) ||
        !(list = calloc(1, sizeof(node_list_t))))
    {
        fprintf(stderr, "Ran out of memory... game over!\n");
        exit(-ENOMEM);
    }

    /* Initialzie the node */
    func->id = id_pool++;
    func->sym = sym;
    func->str = str;
    
    /* Add the node */
    list->func = func;
    list->next = graph->funcs;
    graph->funcs = list;
    return func;
}


/* Search the 'graph' for 'func'.  If 'func' cannot be found a new node is
 * instantiated for that node.
 * TODO: Hash function names for quick lookup (e.g., remove strcmp)
 */
static func_t *find_func(graph_t *graph, const asymbol *func)
{
    const node_list_t *node;

    for (node=graph->funcs; node; node=node->next)
      if (node->func->sym == func)
        return node->func;

    /* Could not locate caller, so create a new node for this caller */
    return add_node(graph, func, NULL);
}


/* Search the 'graph' for 'str'  If that str does not exist then it will be
 * added as a new node to the graph.
 */
static func_t *find_func_str(graph_t *graph, const char *str)
{
    const node_list_t *node;

    if (!str)
      return NULL;

    for (node=graph->funcs; node; node=node->next)
      if (node->func->str && strcmp(node->func->str, str) == 0)
        return node->func;

    /* Could not locate caller, so create a new node for this caller */
    return add_node(graph, NULL, str);
}


/* Given a callee and caller, return the callee if it already exists in the
 * caller
 */
static const func_t *find_callee(const func_t *caller, const func_t *callee)
{
    const node_list_t *node;

    for (node=caller->callees; node; node=node->next)
      if (node->func->sym == callee->sym)
        return node->func;

    return NULL;
}


/* Add a callee (to caller function if the caller does not already have an
 * instance of the callee).
 */
static void add_callee(func_t *caller, func_t *callee)
{
    node_list_t *list;

    /* If we have already added this callee... */
    if (find_callee(caller, callee))
      return;

    if (!(list = calloc(1, sizeof(node_list_t))))
    {
        fprintf(stderr, "Could not allocate enough memory to contain a node\n");
        exit(-ENOMEM);
    }

    /* Add the callee to the list and add the list to the callees list */
    list->func = callee;
    list->next = caller->callees;
    caller->callees = list;
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
    func_t *caller, *callee;
    graph_t *graph;
    
    va_start(va, fmt);
    str = va_arg(va, char *);

    if (!str)
    {
        va_end(va);
        return 0;
    }

    /* Only look for call instructions... */
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

        /* Create a new node to represent the callee and add it to the caller */
        graph = *(graph_t **)dis_info.application_data;
        sym = addr_to_symbol(strtoll(str, NULL, 16));
        caller = find_func(graph, str_to_symbol(fnname));
        callee = sym ? find_func(graph, sym) : find_func_str(graph, str);
        add_callee(caller, callee);
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
    DBG("Symbol table upper bound:         %ld bytes",
        bfd_get_symtab_upper_bound(bin));
    DBG("Dynamic symbol table upper bound: %ld bytes",
        bfd_get_dynamic_symtab_upper_bound(bin));

    /* Get symbol table size (if no regular syms, get dynamic syms)
    * There is always a sentinel symbol (e.g., sizeof(asymbol*)
    */
    is_dynamic = false;
    if ((size = bfd_get_symtab_upper_bound(bin)) <= sizeof(asymbol*))
    {
        if ((size=bfd_get_dynamic_symtab_upper_bound(bin)) <= sizeof(asymbol*))
          ERR("Could not locate any symbols to use");
        is_dynamic = 1;
    }

    /* TODO: For now exit if we only have dynamic symbols */
    if (is_dynamic)
      ERR("Could not locate any symbols (dynamic symbols not supported)");

    if (!(symbols = malloc(size)))
      ERR("Could not allocate enough memory to store the symbol table");

    n_syms = (is_dynamic) ? bfd_canonicalize_dynamic_symtab(bin, symbols) :
                            bfd_canonicalize_symtab(bin, symbols);

    if (!n_syms)
      ERR("Could not locate any symbols");

    DBG("Loaded %d symbols", n_syms);

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


/* Instantaite a new graph instance */
static graph_t *new_graph(const char *filename)
{
    graph_t *g = calloc(1, sizeof(graph_t));

    if (!g || !(g->filename = strdup(filename)))
    {
        fprintf(stderr, "Not enough memory to create a graph\n");
        exit(-ENOMEM);
    }

    return g;
}


/* Open the file and use libopcodes + libfd to create a callgraph */
static graph_t *build_graph(const char *fname)
{
    int length;
    asection *text;
    graph_t *graph;
    disassembler_ftype dis;

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
    graph = new_graph(fname);
    dis_info.application_data = &graph;
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

    /* Start disassembly... */
    curr_addr = start_addr = bfd_get_start_address(bin);
    while ((length = dis(curr_addr, &dis_info)))
    {
        curr_addr += length;
        if ((length < 1) || (curr_addr >= (text->size + start_addr)))
            break;
    }

    return graph;
}


/* Output graph in dot format */
static void output_dot(const graph_t *graph)
{
    const node_list_t *caller, *callee;

    printf("digraph \"%s\"{\n", graph->filename);
    for (caller=graph->funcs; caller; caller=caller->next)
      for (callee=caller->func->callees; callee; callee=callee->next)
        printf("\t\"%s\" -> \"%s\"\n",
               caller->func->sym ? bfd_asymbol_name(caller->func->sym) : "N/A",
               callee->func->sym ? bfd_asymbol_name(callee->func->sym) : "N/A");
    printf("}\n");
}


/* Count the number of edges in graph */
static inline int count_edges(const graph_t *graph)
{
    return id_pool;
}


/* Output graph summary */
static void output_igraph_summary(const graph_t *graph, const char *fname)
{
#ifdef USE_IGRAPH
    igraph_t ig;
    igraph_vector_t edges;
    igraph_real_t radius;
    const node_list_t *caller, *callee;

    /* Setup error handling */
    igraph_set_error_handler(igraph_error_handler_abort);

    /* id_pool can be used as a count for number of verticies */
    igraph_empty(&ig, id_pool, IGRAPH_DIRECTED);
    
    /* Add in the edges individually */
    for (caller=graph->funcs; caller; caller=caller->next)
      for (callee=caller->func->callees; callee; callee=callee->next)
        igraph_add_edge(&ig, caller->func->id, callee->func->id);

    /* Summarize */
    igraph_radius(&ig, &radius, IGRAPH_ALL);
    printf("igraph summary: %s\n", fname);
    printf("  * Number of Verticies: %d\n", igraph_vcount(&ig));
    printf("  * Number of Edges:     %d\n", igraph_ecount(&ig));
    printf("  * Radius:              %f\n", radius);

    /* Cleanup */
    igraph_vector_destroy(&edges);
    igraph_destroy(&ig);
#endif
}


int main(int argc, char **argv)
{
    int opt;
    bool do_dot_output, do_igraph_summary;
    const char *fname;
    graph_t *graph;

    /* Default args */
    fname = NULL;
    do_igraph_summary = do_dot_output = false;

    while ((opt = getopt(argc, argv, "dsf:")) != -1)
    {
        switch (opt)
        {
            case 'f': fname = optarg; break;
            case 'd': do_dot_output = true; break;
            case 's': do_igraph_summary = true; break;
            default:  usage(argv[0]); break;
        }
    }

    /* Sanity */
    if (!fname)
      usage(argv[0]);

    /* Create a callgraph */
    graph = build_graph(fname);

    /* Output the results */
    if (do_dot_output)
      output_dot(graph);
    if (do_igraph_summary)
      output_igraph_summary(graph, fname);
   
    /* Done */ 
    free(graph);
    bfd_close(bin);
    
    return 0;
}
