#ifndef DEBUGGER_H_
#define DEBUGGER_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "elf64.h"

#define GLOBAL 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define STT_FUNC 2
#define ET_EXEC 2

/* an enum for return values */
typedef enum {
    READING_ERROR,
    ALLOCATION_ERROR,
    NOT_ELF,
    NOT_EXE,
    FUNC_NOT_FOUND,
    FUNC_NOT_GLOBAL,
    FUNC_LOAD_IN_RUN_TIME,
    SUCCESS
} ErrorTypes;

/* a struct to house all sort of useful information for performing checks, and getting information from the file */
typedef struct {
    FILE*       file;                  /* ELF file                     */
	Elf64_Ehdr	file_header;	      /* ELF file header              */
    Elf64_Shdr*	section_header;	     /* ELF Section headers,which is actually an array */
    Elf64_Phdr*	program_header;	    /* ELF program headers,which is actually an array */
    // Elf64_Dyn   dynamic_table;	   /* dynamic table                */
    // Elf64_Rel   rel_tab;          /* relocation talbe             */
    // Elf64_Rela  rela_tab;        /* relocation talbe with addend */
    // Elf64_Sym   symbols_table;	/* ELF symbols table entries    */
} Filedata;

size_t fpread(void *buffer, size_t size, size_t count, size_t offset, FILE *fp); // behaves like fread() but it reads at an offset
void releaseAllocatedMemory(Filedata* file_data);
bool isFileElfFormat(char *file_path); // may not be necessary to check if file is an elf or not!
ErrorTypes get_file_header(Filedata* file_data);
ErrorTypes get_file_section_header(Filedata* file_data);
ErrorTypes get_file_program_header(Filedata* file_data);
/* potentially expendable functions */
// ErrorTypes get_file_dynamic_table(Filedata* file_data);
// ErrorTypes get_file_relocation_table(Filedata* file_data);
// ErrorTypes get_file_symbols_table(Filedata* file_data);
ErrorTypes read_info(Filedata* file_data);
ErrorTypes checkIfProgramIsAnExecutable(Filedata* file_data);
ErrorTypes isFunctionAGlobalSymbol(Filedata* file_data,char* func_name);
ErrorTypes validity_check(Filedata* file_data, char* func_name, char *prog_path);
ErrorTypes process_file(char *argv[]);



#endif // DEBUGGER_H_