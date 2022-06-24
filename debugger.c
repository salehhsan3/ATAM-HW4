#include "debugger.h"

size_t fpread(void *buffer, size_t size, size_t count, size_t offset, FILE *stream) // a function that reads input at an offset like pread() system call
{
    // SEEK_SET denotes beginning of the file
    if ( fseek(stream, offset, SEEK_SET) != 0)
    {
        return 0; // denotes that a reading error has occured!
    }
    return fread(buffer, size, count, stream);
}

void releaseAllocatedMemory(Filedata* file_data)
{
    free(file_data->section_header);
    file_data->section_header = NULL;
    free(file_data->program_header);
    file_data->program_header = NULL;
    free(file_data);
    file_data = NULL;
}

bool isFileElfFormat(char *file_path)
{
    FILE* file = fopen(file_path,"r");
    if (file == NULL)
    {
        return false; // an error occured, wasn't able to open file!
    }

    char *magic_num = (char*)malloc(sizeof(char) * 5); // the file starts with ".ELF", there are 4 characters and we have to make it a null terminated string
    if (fread(magic_num,1,4,file) < 4) // fread() returns the number of character read, which should be 4 if no errors occured!
    {
        if (file != NULL)
        {
            fclose(file);
        }
        free(magic_num);
        return false; // a reading error occured, wasn't able to read all characters from file!
    }

    magic_num[4] = '\0'; // to make magic_num a null terminated string!
    if (strcmp(magic_num+1,"ELF") == 0) // start from magic_num+1 because the first character is "." / "_" and is irrelevant for our comparison!
    {
        fclose(file);
        free(magic_num);
        return true; // the file is elf format!
    }

    return false; // the file is not elf format, we checked above!
}

ErrorTypes get_file_header(Filedata* file_data)
{
    // read the file header of type : Elf64_Ehdr,
    if (fread ( &(file_data->file_header), sizeof(file_data->file_header) , 1 , file_data->file) != 1) // saleh's version
    {
        return READING_ERROR;
    }
    return SUCCESS;
}

ErrorTypes get_file_section_header(Filedata* file_data)
{
    Elf64_Half num_of_sh_entries = file_data->file_header.e_shnum; // Section header is actually an array, so we have to read all of its members!
    file_data->section_header = (Elf64_Shdr*)calloc(num_of_sh_entries,sizeof(file_data->section_header));
    if ( file_data->section_header == NULL )
    {
        return ALLOCATION_ERROR;
    }
    if ( fpread ( (file_data->section_header) , sizeof(file_data->section_header), num_of_sh_entries, file_data->file_header.e_shoff, file_data->file) != num_of_sh_entries)
    {
        free(file_data->program_header);
        return READING_ERROR;
    }
    return SUCCESS;
}

ErrorTypes get_file_program_header(Filedata* file_data)
{
    Elf64_Half num_of_ph_entries = file_data->file_header.e_phnum; // Program header is actually an array, so we have to read all of its members!
    file_data->program_header = (Elf64_Phdr*)calloc(num_of_ph_entries,sizeof(file_data->program_header));
    if ( file_data->program_header == NULL )
    {
        return ALLOCATION_ERROR;
    }
    if (fpread ( (file_data->program_header), sizeof(file_data->program_header), num_of_ph_entries, file_data->file_header.e_phoff, file_data->file) != num_of_ph_entries)
    {
        free(file_data->program_header);
        return READING_ERROR;
    }
    return SUCCESS;
}

ErrorTypes read_info(Filedata* file_data)
{
    ErrorTypes res;
    res = get_file_header(file_data);
    if (res != SUCCESS)
    {
        return res;
    }
    res = get_file_section_header(file_data);
    if (res != SUCCESS)
    {
        return res;
    }
    res = get_file_program_header(file_data);
    if (res != SUCCESS)
    {
        return res;
    }
    /* maybe more information should be read for later stages, not sure */
    return res;
}

ErrorTypes checkIfProgramIsAnExecutable(Filedata* file_data)
{
    Elf64_Half type = file_data->file_header.e_type;
    if (type == ET_EXEC) // I believe the number 2 actually corresponds to ET_EXEC, as we defined it in the header file
    {
        return SUCCESS; // SUCCESS corresponds to file is and executable
    }
    return NOT_EXE;
}

ErrorTypes isFunctionAGlobalSymbol(Filedata* file_data,char* func_name)
{
    // functions should appear inside the .text section
    Elf64_Off sh_base_offset = file_data->section_header->sh_offset; // section header table beginning offset from start of the file!
    Elf64_Shdr sh_string_section = file_data->section_header[file_data->file_header.e_shstrndx];
    // char *sh_section_table = (char*)sh_string_section.sh_offset; // im not sure if this comparison is additonal or necessary!
    Elf64_Half sh_sections_num = file_data->file_header.e_shnum;
    Elf64_Sym *sym_tab;
    char *str_tab;
    int symbols_num = 0;
    /************************ maybe save base offset for the section header to be able to perform pointer arithmetic? ************************/
    for (int i = 0; i < sh_sections_num; i++)
    {
        if (file_data->section_header[i].sh_type == SHT_SYMTAB)
        {
            sym_tab = file_data->section_header + (file_data->section_header[i].sh_offset - sh_base_offset); // correct calculation?
            symbols_num = ( (file_data->section_header[i].sh_size) / (file_data->section_header[i].sh_entsize) ); 
        }
        else if (file_data->section_header[i].sh_type == SHT_STRTAB)
        {
            str_tab = (char*)file_data->section_header + (file_data->section_header[i].sh_offset - sh_base_offset); // correct calculation?
        }
    }

    for (int i = 0; i < symbols_num; i++)
    {
        char *current_symol = str_tab + sym_tab[i].st_name;
        if (strcmp(func_name,current_symol) == 0)
        {
            if( (ELF64_ST_BIND(sym_tab[i].st_info) == GLOBAL) && (ELF64_ST_TYPE(sym_tab[i].st_info) == STT_FUNC) ) 
            {
                return SUCCESS; // function was found and it's a global one!
            }
            else
            {
                return FUNC_NOT_GLOBAL;
            }
        }
    }
    return FUNC_NOT_FOUND; // didn't return SUCCESS & FUNC_NOT_GLOBAL therefore it's definitely FUNC_BOT_FOUND!
    
}

ErrorTypes validity_check(Filedata* file_data, char* func_name, char *prog_path)
{
    ErrorTypes res = checkIfProgramIsAnExecutable(file_data);
    if (res == NOT_EXE)
    {
        printf("PRF:: %s not an executable! :(\n",prog_path);
        return res;
    } 

    res = isFunctionAGlobalSymbol(file_data,func_name);
    if (res == FUNC_NOT_FOUND)
    {     
        printf("PRF:: %s not found!\n",func_name);
        return res;
    }
    else if (res == FUNC_NOT_GLOBAL)
    {
        printf("%s is not a global symbol! :(\n",func_name);
        return res;
    } 
    return res; // passed all validity checks :) should return SUCCESS
}

ErrorTypes process_file(char *argv[])
{
    ErrorTypes res; // for checking information
    char *func_name = argv[1]; // first argument is the function's name
    char *prog_path = argv[2]; // second argument is the program's name

    if ( isFileElfFormat(prog_path) != true)
    {
        return NOT_ELF; // should never return this, as we are hypothetically working with ELF files only
    }

    Filedata *file_data = calloc(1,sizeof(*file_data)); // it's going to house important information about our file
    if (file_data == NULL)
    {
        return ALLOCATION_ERROR;
    }

    FILE* elf_file = fopen(prog_path,"rb");
    if (elf_file == NULL)
    {
        free(file_data);
        return READING_ERROR; // couldn't open the file
    }

    file_data->file = elf_file;
    res = read_info(file_data); 
    if (res != SUCCESS)
    {
        fclose(file_data->file);
        releaseAllocatedMemory(file_data);
        return res;
    }
    res = validity_check(file_data,func_name,prog_path);
    
    /* end function or perform other stuff? */
    fclose(file_data->file);
    releaseAllocatedMemory(file_data);
    return res;
}

int main(int argc, char *argv[])
{
    // the function's name should appear in strtab ? or should it be in another section?

    // by convention argv[0] is the command with which the program is invoked
    char *func_name = argv[1]; // first argument is the function's name
    char *prog_path = argv[2]; // second argument is the program's name

    ErrorTypes res = process_file(argv); 
    if (res != SUCCESS)
    {
        return 1; //some sort of error occured, end process!
    }
    
    return 0;
}

/* potentially expendable functions*/

// ErrorTypes get_file_dynamic_table(Filedata* file_data) // complete later
// {
//     if (fpread (&(file_data->dynamic_table), sizeof(Elf64_Dyn), 1, offset, file_data->file) != 1)
//     {
//         return READING_ERROR;
//     }
//     return SUCCESS;
// }

// ErrorTypes get_file_relocation_table(Filedata* file_data) // complete later
// {
//     if (fpread (&(file_data->rel_tab), sizeof(Elf64_Rel), 1, offset, file_data->file) != 1)
//     {
//         return READING_ERROR;
//     }
//     return SUCCESS;
// }

// ErrorTypes get_file_symbols_table(Filedata* file_data) // complete later
// {
//     if (fpread (&(file_data->symbols_table), sizeof(Elf64_Sym), 1, offset, file_data->file) != 1)
//     {
//         return READING_ERROR;
//     }
//     return SUCCESS;
// }
