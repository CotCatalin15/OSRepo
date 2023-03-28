#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

//#define DEBUG
#ifdef DEBUG

#define LogDebug(msg, ...) printf("DEBUG: "msg"\n", ##__VA_ARGS__)
#define LogError(msg, ...) printf("ERROR line: %d\n"msg"\n", __LINE__, ##__VA_ARGS__)

#else
#define LogDebug(...) 
#define LogError(msg, ...) printf("ERROR\n"msg"\n", ##__VA_ARGS__)
#endif

typedef unsigned char boolean;
#define TRUE (boolean)1
#define FALSE (boolean)0

typedef enum _ErrorCode
{
    ERROR_SUCCESS,

    //Default errors
    ERROR_UNSUCCESSFUL,
    ERROR_INVALID_FILE,

    //SF file errors
    ERROR_INVALID_MAGIC_NUMBER,
    ERROR_INVALID_VERSION,
    ERROR_INVALID_SECTION_NR,
    ERROR_INVALID_HEADER_SIZE,
    ERROR_INVALID_SECTION_TYPE

}ErrorCode;


//Structures
typedef struct _LIST_CMD_ARGS
{
    const char* dirPath;

    //optional
    boolean recursive;
    const char* startstWith;
    boolean permWrite;
}LIST_CMD_ARGS;

typedef struct __attribute__((packed))
{
    union
    {
        uint32_t magic;
        char magic_name[4];
    };
    uint16_t header_size;
    uint16_t version;
    uint8_t  num_sections;
}SFHeader;

typedef struct __attribute__((packed))
{
    uint8_t sec_name[12];
    uint16_t sec_type;
    uint32_t sec_offset;
    uint32_t sec_size;
}SFSectionHeader;

typedef struct
{
    char* path;
    SFHeader header;
    SFSectionHeader* sections;
}SFParsed;

//Utils
typedef void(*PFN_OnFileFound)(const char*, struct dirent*, void* );
int iterate_all_files(const char* path, boolean rec, PFN_OnFileFound callback, void* context);

//Sf file parse
ErrorCode parse_sf_file(const char* path, SFParsed* * OutParsed);
void sf_file_destroy(SFParsed** Parse);

int parse_cmd_line_args(int argc, char** argv);
//Commands
//list
int execute_list_cmd(int argc, char** argv);
int execute_parse_cmd(int argc, char** argv);
int execute_extract_cmd(int argc, char** argv);
int execute_finall_cmd(int argc, char** argv);

int main(int argc, char **argv)
{
    if(argc < 2)
    {
        printf("Usage %s [options] [parameters]\n", argv[0]);
        return -1;
    }
    
    LogDebug("Arguments:");
    for(int i = 0; i < argc; ++i)
    {
        LogDebug("%s", argv[i]);
    }

    int retCode = parse_cmd_line_args(argc, argv);

    return retCode;
}

int parse_cmd_line_args(int argc, char** argv)
{
    const char* cmd = argv[1];

    if(0 == strcmp(cmd, "variant"))
    {
        printf("64890");
        return 0;
    }
    else if(0 == strcmp(cmd, "list"))
    {
        return execute_list_cmd(argc, argv);
    }    
    else if(0 == strcmp(cmd, "parse"))
    {
        return execute_parse_cmd(argc, argv);
    }
    else if(0 == strcmp(cmd, "extract"))
    {
        return execute_extract_cmd(argc, argv);
    }
    else if(0 == strcmp(cmd, "findall"))
    {
        return execute_finall_cmd(argc, argv);
    }
    LogError("Unknown command %s", cmd);
    return -1;
}

void ListCmdIterateFileCallback(const char* path, struct dirent* entry, void* context)
{
    LogDebug("ListCmdIterateFileCallback: %s", entry->d_name);
    const LIST_CMD_ARGS* pArgs = (const LIST_CMD_ARGS*)context;

    if(pArgs->startstWith != NULL)
    {
        if(entry->d_name != strstr(entry->d_name, pArgs->startstWith))
        {
            return;
        }
    }
    if(TRUE == pArgs->permWrite)
        {
            char fullPath[256];
            fullPath[0] = 0;
            strcat(fullPath, path);
            strcat(fullPath, "/");
            strcat(fullPath, entry->d_name);
            struct stat fileStat;
            int statCode = stat(fullPath, &fileStat);
            if(0 != statCode)
            {
                LogDebug("stat fn returned: %d", statCode);
                return;
            }
            
            //User does not have write permission
            if(!(S_IWUSR & fileStat.st_mode))
            {
                return;
            }
        }

    printf("%s/%s\n", path, entry->d_name);
}

int execute_list_cmd(int argc, char** argv)
{
    LIST_CMD_ARGS listArgs;
    memset(&listArgs, 0, sizeof(listArgs));

    for(int i = 2; i < argc; ++i)
    {
        const char* opt = argv[i];
        if(0 == strcmp("recursive", opt))
        {
            listArgs.recursive = TRUE;
        }
        else if(opt == strstr(opt, "path=")) //starts with path
        {
            listArgs.dirPath = opt + sizeof("path=") - 1;
        }
        else if(opt == strstr(opt, "name_starts_with="))
        {
            listArgs.startstWith = opt + sizeof("name_starts_with=") - 1;
        }
        else if(0 == strcmp(opt, "has_perm_write"))
        {
            listArgs.permWrite = TRUE;
        }
        else
        {
            LogError("Unknown option for list cmd: %s", opt);
            return -1;
        }
    }

    LogDebug("Dir: %s rec: %d, starts_with:%s, write:%d", listArgs.dirPath, listArgs.recursive, listArgs.startstWith, listArgs.permWrite);

    if(NULL == listArgs.dirPath)
    {
        LogError("Usage: %s list [recursive] <filtering_options> path=<dir_path>", argv[0]);
    }

    DIR* dirHandle = opendir(listArgs.dirPath);
    if(NULL == dirHandle)
    {
        LogError("Invalid directory path");
        return -1;
    }
    closedir(dirHandle);

    printf("SUCCESS\n");
    return iterate_all_files(listArgs.dirPath, listArgs.recursive, ListCmdIterateFileCallback, &listArgs);
}

int execute_parse_cmd(int argc, char** argv)
{
    if(3 != argc)
    {
        return -1;
    }

    const char* path = NULL;
    if(argv[2] == strstr(argv[2], "path=")) //starts with path
    {
        path = argv[2] + sizeof("path=") - 1;
    }
    if(NULL == path)
    {
        LogError("Invalid path");
        return -1;
    }

    SFParsed* parsed = NULL;
    ErrorCode status = parse_sf_file(path, &parsed);
    LogDebug("parse_sf_file returned: %u", status);
    if(ERROR_SUCCESS != status)
    {
        switch(status)
        {
            case ERROR_INVALID_MAGIC_NUMBER:
                LogError("wrong magic");
            break;
            case ERROR_INVALID_VERSION:
                LogError("wrong version");
            break;
            case ERROR_INVALID_SECTION_NR:
                LogError("wrong sect_nr");
            break;
            case ERROR_INVALID_HEADER_SIZE:
                LogError("wrong header_size");
            break;
            case ERROR_INVALID_SECTION_TYPE:
                LogError("wrong sect_types");
            break;
            case ERROR_INVALID_FILE:
                LogError("wrong invalid_file");
            break;
            default:
                LogError("wrong unknown");
            break;
        }
    }
    if(ERROR_SUCCESS != status || NULL == parsed)
    {
        return -1;
    }

    printf("SUCCESS\n");
    printf("version=%u\n", parsed->header.version);
    printf("nr_sections=%u\n", parsed->header.num_sections);
    for(int i = 0; i < parsed->header.num_sections; ++i)
    {
        SFSectionHeader* section = &parsed->sections[i];
        printf("section%d: ", i+1);
        for(int j = 0; j < 12; ++j) if(section->sec_name[j] != 0) printf("%c", section->sec_name[j]);
        printf(" %u %u\n", section->sec_type, section->sec_size);
    }

    sf_file_destroy(&parsed);
    return 0;
}

int execute_extract_cmd(int argc, char** argv)
{
    if(argc != 5)
    {
        return -1;
    }
    const char* path = NULL;
    int section = -1;
    int line = -1;

    for(int i = 2; i < 5; ++i)
    {
        const char* opt = argv[i];
        if(opt == strstr(opt, "path="))
        {
            path = opt + sizeof("path=") - 1;
        }
        else if(opt == strstr(opt, "section="))
        {
            const char* sectionOpt = opt + sizeof("section=") - 1;
            if(1 != sscanf(sectionOpt, "%d", &section))
            {
                LogError("Invalid section number");
                return -1;
            }
        }
        else if(opt == strstr(opt, "line="))
        {
            const char* lineOpt = opt + sizeof("line=") - 1;
            if(1 != sscanf(lineOpt, "%d", &line))
            {
                LogError("Invalid line number");
                return -1;
            }
        }
    }

    if(-1 == line || -1 == section || NULL == path)
    {
        LogError("Invalid cmd args");
    }

    LogDebug("Extract: path=%s\tsection=%d\tline=%d", path, section, line);

    SFParsed* parsed = NULL;
    ErrorCode status = ERROR_SUCCESS;
    int fd = -1;
    char* data = NULL;

    status =  parse_sf_file(path, &parsed);
    if(ERROR_SUCCESS != status)
    {
        LogError("invalid file");
        return -1;
    }

    if(section <= 0 || section > parsed->header.num_sections)
    {
        LogError("invalid section");
        status = ERROR_UNSUCCESSFUL;
        goto cleanup;
    }

    SFSectionHeader* sectionHeader = &parsed->sections[section - 1];
    LogDebug("Extracting section[%u]: size: %u offset: %u", section, sectionHeader->sec_size, sectionHeader->sec_offset);

    fd = open(parsed->path, O_RDONLY);  
    if(-1 == fd)
    {
        status = ERROR_INVALID_FILE;
        LogError("invalid file");
        goto cleanup;
    }

    data = malloc(sizeof(char) * (sectionHeader->sec_size + 1));
    if(NULL == data)
    {
        status = ERROR_UNSUCCESSFUL;
        LogError("out of memory");
        goto cleanup;
    }

    off_t offset = lseek(fd, sectionHeader->sec_offset, SEEK_SET);
    if(sectionHeader->sec_offset != offset)
    {
        LogDebug("lseek returned: %d expected: %d", (int)offset, sectionHeader->sec_offset);
        status = ERROR_INVALID_FILE;
        LogError("invalid section");
        goto cleanup;
    }
    ssize_t bytesReturned = read(fd, data, sectionHeader->sec_size);
    if(bytesReturned != sectionHeader->sec_size)
    {
        LogDebug("read returned: %d expected: %d", (int)bytesReturned, sectionHeader->sec_size);
        status = ERROR_UNSUCCESSFUL;
        LogError("invalid sections");
        goto cleanup;
    }
    data[sectionHeader->sec_size] = '\0';
    char* p = strtok(data, "\n");
    int i = 1;
    for(; i < line && p; ++i)
    {
        p = strtok(NULL, "\n");
    }

    if(i != line || NULL == p) 
    {
        status = ERROR_INVALID_FILE;
        LogError("invalid sections");
        goto cleanup;
    }

    LogDebug("Len: %p", p);
    int len = strlen(p);
    printf("SUCCESS\n");
    for(i = len - 1; i >= 0; --i)
    {
        printf("%c", p[i]);
    }
    printf("\n");

cleanup:
    if(-1 != fd)
    {
        close(fd);
    }
    
    if(NULL != data)
    {
        free(data);
    }
    
    if(NULL != parsed)
    {
        sf_file_destroy(&parsed);
    }
        
    return 0;
}

void FindallCmdIterateSFFileCallback(const char* path, struct dirent* entry, void* context)
{
    ErrorCode status = ERROR_SUCCESS;
    SFParsed* parsed = NULL;

    char fullPath[256];
    fullPath[0] = 0;
    strcat(fullPath, path);
    strcat(fullPath, "/");
    strcat(fullPath, entry->d_name);

    status = parse_sf_file(fullPath, &parsed);
    if(ERROR_SUCCESS != status)
    {
        goto cleanup;
    }

    for(int i = 0; i < parsed->header.num_sections; ++i)
    {
        SFSectionHeader* section = &parsed->sections[i];
        if(section->sec_size > 1143)
        {
            goto cleanup;
        }
    }

    printf("%s\n", fullPath);

cleanup:
    if(NULL != parsed)
    {
        sf_file_destroy(&parsed);
    }
}

int execute_finall_cmd(int argc, char** argv)
{
    if(3 != argc)
    {
        return -1;
    }

    const char* path = NULL;
    if(argv[2] == strstr(argv[2], "path=")) //starts with path
    {
        path = argv[2] + sizeof("path=") - 1;
    }
    if(NULL == path)
    {
        LogError("Invalid path");
        return -1;
    }
    
    printf("SUCCESS\n");
    iterate_all_files(path, TRUE, FindallCmdIterateSFFileCallback, NULL);
    printf("\n");
    return 0;
}

int iterate_all_files(const char* path, boolean rec, PFN_OnFileFound callback, void* context)
{
    LogDebug("iterate_all_files: path=%s", path);
    DIR* dirHandle = opendir(path);

    if(NULL == dirHandle)
    {
        LogDebug("Failed to open dir: %s", path);
        return -1;
    }
    
    struct dirent* entry = NULL;
    while((entry = readdir(dirHandle)) != NULL)
    {
        if(0 == strcmp(entry->d_name, "..") || 0 == strcmp(entry->d_name, "."))
        {
            continue;
        }
        //If its a directory
        if(DT_DIR == entry->d_type)
        {
            callback(path, entry, context);
            if(TRUE == rec)
            {
                int currentDirLen = strlen(path);
                int entryDirLen = strlen(entry->d_name);
                int newDirLen = currentDirLen + entryDirLen + 2;

                //+2 for the / ch and null ch
                char* dirPath = malloc(sizeof(char) * newDirLen);
                if(NULL == dirPath)
                {
                    LogError("Out of memory!");
                    return -1;
                }
                dirPath[0] = 0;
                strcat(dirPath, path);
                strcat(dirPath, "/");
                strcat(dirPath, entry->d_name);

                
                iterate_all_files(dirPath, rec, callback, context);

                free(dirPath);
            }
        }
        else if(DT_REG == entry->d_type)
        {
            callback(path, entry, context);
        }
    }

    closedir(dirHandle);
    return 0;
}

ErrorCode parse_sf_file(const char* path, SFParsed* *OutParsed)
{
    *OutParsed = NULL;
    ErrorCode status = ERROR_SUCCESS;

    int fileHandle = open(path, O_RDONLY);
    if(-1 == fileHandle)
    {
        LogDebug("SF %s not found", path);
        return ERROR_INVALID_FILE;
    }
    LogDebug("Reading SF File: %s", path);

    SFParsed* parsed = NULL;
    ssize_t bytesRead = 0;

    parsed = malloc(sizeof(SFParsed));
    if(NULL == parsed)
    {
        status = ERROR_UNSUCCESSFUL;
        goto error;
    }
    memset(parsed, 0, sizeof(SFParsed));

    parsed->path = malloc((strlen(path) + 1) * sizeof(char));    
    if(NULL == parsed->path)
    {
        status = ERROR_UNSUCCESSFUL;
        goto error;
    }
    strcpy(parsed->path, path);

    bytesRead = read(fileHandle, &parsed->header, sizeof(SFHeader));
    if(sizeof(SFHeader) != bytesRead)
    {
        status = ERROR_UNSUCCESSFUL;
        goto error;
    }
    
    LogDebug("SF Header: magic: %c%c%c%c header_size: %u version: %u nr_sections: %u", 
                parsed->header.magic_name[0], parsed->header.magic_name[1], parsed->header.magic_name[2], parsed->header.magic_name[3],
                (uint32_t)parsed->header.header_size, (uint32_t)parsed->header.version, (uint32_t)parsed->header.num_sections);

    if(0 != strncmp((const char*)&parsed->header.magic, "Qht0", 4))
    {
        status = ERROR_INVALID_MAGIC_NUMBER;
        goto error;
    }

    if(!(parsed->header.version >= 86 && parsed->header.version <= 129))
    {
        status = ERROR_INVALID_VERSION;
        goto error;
    }

    if(!(parsed->header.num_sections >= 2 && parsed->header.num_sections <= 12))
    {
        status = ERROR_INVALID_SECTION_NR;
        goto error;
    }

    uint32_t expectedHeaderSize = sizeof(SFHeader) + sizeof(SFSectionHeader) * parsed->header.num_sections;
    LogDebug("Expected header size: %u", expectedHeaderSize);
    if(parsed->header.header_size != expectedHeaderSize)
    {
        status = ERROR_INVALID_HEADER_SIZE;
        goto error;
    }

    uint32_t sectionSize = sizeof(SFSectionHeader) * parsed->header.num_sections;
    parsed->sections = malloc(sectionSize);
    if(NULL == parsed->sections)
    {
        status = ERROR_SUCCESS;
        goto error;
    }
    memset(parsed->sections, 0, sectionSize);

    bytesRead = read(fileHandle, parsed->sections, sectionSize);
    if(bytesRead != sectionSize)
    {
        status = ERROR_UNSUCCESSFUL;
        goto error;
    }

    for(int i = 0; i < parsed->header.num_sections; ++i)
    {
        SFSectionHeader* section = &parsed->sections[i];
        const size_t validTypeSize = 5;
        uint16_t validTypes[5] = {68, 92, 36, 57, 91};
        boolean foundValid = FALSE;
        for(uint32_t j = 0; j < validTypeSize; ++j)
        {
            if(section->sec_type == validTypes[j])
            {
                foundValid = TRUE;
                break;
            }
        }
        if(FALSE == foundValid)
        {
            status = ERROR_INVALID_SECTION_TYPE;
            goto error;
        }

        LogDebug("SF Section[%u]: name: %11s type: %u, offset: %u, size: %u", 
                i + 1, section->sec_name, (uint32_t)section->sec_type, section->sec_offset, section->sec_size);
    }
error:
    if(ERROR_SUCCESS != status)
    {
        if(NULL != parsed)
        {
            sf_file_destroy(&parsed);
        }
        parsed = NULL;
    }

    close(fileHandle);
    *OutParsed = parsed;
    return status;
}

void sf_file_destroy(SFParsed** Parse)
{
    if(NULL == Parse || NULL == *Parse)
    {
        LogDebug("sf_file_destroy null data");
        return;
    }

    SFParsed* data = *Parse;
    if(NULL != data->path)
    {
        free(data->path);
    }

    if(NULL != data->sections)
    {
        free(data->sections);
    }
    free(data);
    *Parse = NULL;
}
