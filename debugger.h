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
#define SHT_DYNSYM 11
#define SHT_RELA 4
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
} Filedata;

/* a struct to house all sort of useful information for performing checks, and getting information from the file */
typedef struct {
    Elf64_Addr address;
    Elf64_Addr got_address;
    bool undefined;
} FunctionData;

void runTarget(char *argv[], FunctionData *func_data);

#endif // DEBUGGER_H_