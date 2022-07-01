#include "debugger.h"

// a function that reads input at an offset like pread() system call
size_t static fpread(void* buffer, size_t size, size_t count, size_t offset, FILE* stream)
{
    // SEEK_SET denotes beginning of the file
    if (fseek(stream, offset, SEEK_SET) != 0) {
        return 0; // denotes that a reading error has occured!
    }
    return fread(buffer, size, count, stream);
}

void static releaseAllocatedMemory(Filedata* file_data)
{
    free(file_data->section_header);
    file_data->section_header = NULL;
}

bool static isFileElfFormat(char* file_path)
{
    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        return false; // an error occured, wasn't able to open file!
    }

    char* magic_num = (char*)malloc(sizeof(char) * 5); // the file starts with ".ELF", there are 4 characters and we have to make it a null terminated string
    if (fread(magic_num, 1, 4, file) < 4) // fread() returns the number of character read, which should be 4 if no errors occured!
    {
        if (file != NULL) {
            fclose(file);
        }
        free(magic_num);
        return false; // a reading error occured, wasn't able to read all characters from file!
    }

    magic_num[4] = '\0'; // to make magic_num a null terminated string!
    if (strcmp(magic_num + 1, "ELF") == 0) // start from magic_num+1 because the first character is "." / "_" and is irrelevant for our comparison!
    {
        fclose(file);
        free(magic_num);
        return true; // the file is elf format!
    }

    return false; // the file is not elf format, we checked above!
}

ErrorTypes static get_file_header(Filedata* file_data)
{
    // read the file header of type : Elf64_Ehdr,
    if (fread(&(file_data->file_header), sizeof(file_data->file_header), 1, file_data->file) != 1) // saleh's version
    {
        return READING_ERROR;
    }
    return SUCCESS;
}

ErrorTypes static get_file_section_header(Filedata* file_data)
{
    Elf64_Half num_of_sh_entries = file_data->file_header.e_shnum; // Section header is actually an array, so we have to read all of its members!
    file_data->section_header = (Elf64_Shdr*)calloc(num_of_sh_entries, sizeof(*(file_data->section_header)));
    if (file_data->section_header == NULL) {
        return ALLOCATION_ERROR;
    }
    if (fpread(file_data->section_header, sizeof(*(file_data->section_header)), num_of_sh_entries, file_data->file_header.e_shoff, file_data->file) != num_of_sh_entries) {
        return READING_ERROR;
    }
    return SUCCESS;
}

ErrorTypes static read_info(Filedata* file_data)
{
    ErrorTypes res;
    res = get_file_header(file_data);
    if (res != SUCCESS) {
        return res;
    }
    res = get_file_section_header(file_data);
    if (res != SUCCESS) {
        return res;
    }
    return res;
}

ErrorTypes static checkIfProgramIsAnExecutable(Filedata* file_data)
{
    Elf64_Half type = file_data->file_header.e_type;
    if (type == ET_EXEC) // I believe the number 2 actually corresponds to ET_EXEC, as we defined it in the header file
    {
        return SUCCESS; // SUCCESS corresponds to file is and executable
    }
    return NOT_EXE;
}

int32_t static FindDynFuncSymNum(Filedata* file_data, Elf64_Off dyn_str_tab_offset, Elf64_Shdr* dyn_sym_hdr, char* func_name)
{
    Elf64_Xword symbols_number = (dyn_sym_hdr->sh_size) ? dyn_sym_hdr->sh_size / dyn_sym_hdr->sh_entsize : 0;
    Elf64_Off dyn_sym_tab_offset = dyn_sym_hdr->sh_offset;
    size_t sym_name_length = strlen(func_name) + 1;
    Elf64_Sym* dyn_sym_tab = malloc(sizeof(*dyn_sym_tab)); // array like sh
    if (dyn_sym_tab == NULL) {
        return ALLOCATION_ERROR;
    }
    char* sym_name = malloc(sym_name_length);
    if (sym_name == NULL) {
        free(dyn_sym_tab);
        return ALLOCATION_ERROR;
    }
    for (Elf64_Off i = 0; i < symbols_number; i++) {
        fpread(dyn_sym_tab, sizeof(*dyn_sym_tab), 1, dyn_sym_tab_offset + (Elf64_Off)i * sizeof(*dyn_sym_tab), file_data->file);
        fpread(sym_name, sym_name_length, 1, dyn_str_tab_offset + (Elf64_Off)dyn_sym_tab->st_name, file_data->file);
        if ((strcmp(func_name, sym_name) == 0) && (ELF64_ST_BIND(dyn_sym_tab->st_info) == GLOBAL) && (ELF64_ST_TYPE(dyn_sym_tab->st_info) == STT_FUNC)) // maybe check if it's a global symbol and if it's a function? -saleh
        { // change - saleh!!
            free(dyn_sym_tab);
            free(sym_name);
            return (int32_t)i;
        }
    }
    free(dyn_sym_tab);
    free(sym_name);
    return -1;
}

Elf64_Addr static FindRelaFuncSymAddr(Filedata* file_data, Elf64_Shdr* rela_hdr, int32_t dyn_func_num)
{
    Elf64_Xword rel_number = (rela_hdr->sh_size) ? rela_hdr->sh_size / rela_hdr->sh_entsize : 0;
    Elf64_Xword rel_size = rela_hdr->sh_entsize;
    Elf64_Off rel_tab_offset = rela_hdr->sh_offset;
    Elf64_Rel* rel_entry = malloc(sizeof(*rel_entry)); // array like sh
    if (rel_entry == NULL) {
        return ALLOCATION_ERROR;
    }
    for (Elf64_Off i = 0; i < rel_number; i++) {
        fpread(rel_entry, sizeof(*rel_entry), 1, rel_tab_offset + (Elf64_Off)i * rel_size, file_data->file);
        if (ELF64_R_SYM(rel_entry->r_info) == dyn_func_num) {
            Elf64_Addr rela_addr = rel_entry->r_offset;
            free(rel_entry);
            return rela_addr;
        }
    }
    free(rel_entry);
    return 0;
}

bool static isSectionHeaderName(Filedata* file_data, Elf64_Shdr* sect, const char* name_to_check)
{
    char* section_name = malloc(strlen(name_to_check) + 1);
    if (section_name == NULL) {
        return false;
    }
    Elf64_Off shstr_offset = file_data->section_header[file_data->file_header.e_shstrndx].sh_offset;
    fpread(section_name, strlen(name_to_check) + 1, 1, shstr_offset + (Elf64_Off)sect->sh_name, file_data->file);
    bool equal = strcmp(name_to_check, section_name) == 0;
    free(section_name);
    return equal;
}

ErrorTypes static getSymFuncInformation(Filedata* file_data, FunctionData* func_data, char* func_name)
{
    Elf64_Xword symbols_number;
    Elf64_Off sym_tab_offset;
    Elf64_Off str_tab_offset;
    Elf64_Off dyn_str_tab_offset;
    Elf64_Xword sym_tab_entry_size;

    Elf64_Shdr* dyn_tab;
    int32_t dyn_func_num;

    size_t sym_name_length = strlen(func_name) + 1;

    Elf64_Sym* sym_tab = malloc(sizeof(*sym_tab));
    if (sym_tab == NULL) {
        return ALLOCATION_ERROR;
    }
    char* sym_name = malloc(sym_name_length);
    if (sym_name == NULL) {
        free(sym_tab);
        return ALLOCATION_ERROR;
    }
    /* We first need to get the offset of the symbol table of the elf */
    for (Elf64_Half i = 0; i < file_data->file_header.e_shnum; i++) {
        if (file_data->section_header[i].sh_type == SHT_SYMTAB) {
            sym_tab_offset = file_data->section_header[i].sh_offset;
            sym_tab_entry_size = file_data->section_header[i].sh_entsize;
            symbols_number = file_data->section_header[i].sh_size / sym_tab_entry_size;
        }
        if (file_data->section_header[i].sh_type == SHT_STRTAB && isSectionHeaderName(file_data, &file_data->section_header[i], ".dynstr")) {
            dyn_str_tab_offset = file_data->section_header[i].sh_offset;
        }
        if (file_data->section_header[i].sh_type == SHT_STRTAB && isSectionHeaderName(file_data, &file_data->section_header[i], ".strtab")) {
            str_tab_offset = file_data->section_header[i].sh_offset;
        }
    }
    for (Elf64_Half i = 0; i < file_data->file_header.e_shnum; i++) {
        if (file_data->section_header[i].sh_type == SHT_DYNSYM) {
            dyn_func_num = FindDynFuncSymNum(file_data, dyn_str_tab_offset, &file_data->section_header[i], func_name);
        }
    }
    if (dyn_func_num != -1) {
        for (Elf64_Half i = 0; i < file_data->file_header.e_shnum; i++) {
            if (file_data->section_header[i].sh_type == SHT_RELA) {
                Elf64_Addr rela_addr = FindRelaFuncSymAddr(file_data, &file_data->section_header[i], dyn_func_num);
                if (rela_addr != 0) {
                    func_data->got_address = rela_addr;
                    break;
                }
            }
        }
    }
    for (Elf64_Off i = 0; i < symbols_number; i++) {
        fpread(sym_tab, sizeof(*sym_tab), 1, sym_tab_offset + (Elf64_Off)i * sizeof(*sym_tab), file_data->file);
        fpread(sym_name, sym_name_length, 1, str_tab_offset + (Elf64_Off)sym_tab->st_name, file_data->file);

        if (strcmp(func_name, sym_name) == 0) {
            if ((ELF64_ST_BIND(sym_tab->st_info) == GLOBAL) && (ELF64_ST_TYPE(sym_tab->st_info) == STT_FUNC)) {
                func_data->address = sym_tab->st_value;
                func_data->undefined = sym_tab->st_shndx == 0;
                free(sym_tab);
                free(sym_name);
                return SUCCESS; // function was found and it's a global one!
            } else {
                free(sym_tab);
                free(sym_name);
                return FUNC_NOT_GLOBAL;
            }
        }
    }
    free(sym_tab);
    free(sym_name);
    return FUNC_NOT_FOUND; // didn't return SUCCESS & FUNC_NOT_GLOBAL therefore it's definitely FUNC_BOT_FOUND!
}

ErrorTypes static validity_check(Filedata* file_data, FunctionData* func_data, char* func_name, char* prog_path)
{
    ErrorTypes res = checkIfProgramIsAnExecutable(file_data);
    if (res == NOT_EXE) {
        printf("PRF:: %s not an executable! :(\n", prog_path);
        return res;
    }

    res = getSymFuncInformation(file_data, func_data, func_name);

    if (res == FUNC_NOT_FOUND) {
        printf("PRF:: %s not found!\n", func_name);
        return res;
    } else if (res == FUNC_NOT_GLOBAL) {
        printf("PRF:: %s is not a global symbol! :(\n", func_name);
        return res;
    }
    return res; // passed all validity checks :) should return SUCCESS
}

ErrorTypes static process_file(char* argv[])
{
    ErrorTypes res; // for checking information
    FunctionData func_data;
    char* func_name = argv[1]; // first argument is the function's name
    char* prog_path = argv[2]; // second argument is the program's name

    if (isFileElfFormat(prog_path) != true) {
        return NOT_ELF; // should never return this, as we are hypothetically working with ELF files only
    }

    Filedata* file_data = calloc(1, sizeof(*file_data)); // it's going to house important information about our file
    if (file_data == NULL) {
        return ALLOCATION_ERROR;
    }

    FILE* elf_file = fopen(prog_path, "rb");
    if (elf_file == NULL) {
        free(file_data);
        return READING_ERROR; // couldn't open the file
    }

    file_data->file = elf_file;
    res = read_info(file_data);
    if (res != SUCCESS) {
        fclose(file_data->file);
        releaseAllocatedMemory(file_data);
        return res;
    }
    res = validity_check(file_data, &func_data, func_name, prog_path);
    fclose(file_data->file);
    releaseAllocatedMemory(file_data);
    runTarget(&argv[2], &func_data);
    return res;
}

int main(int argc, char* argv[])
{
    ErrorTypes res = process_file(argv);
    if (res != SUCCESS) {
        return 1;
    }
    return 0;
}
