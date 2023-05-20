#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

#ifdef DEBUG

#define LogDebug(msg, ...) printf("DEBUG: "msg"\n", ##__VA_ARGS__)
#define LogError(msg, ...) printf("ERROR line: %d\n"msg"\n", __LINE__, ##__VA_ARGS__)

#else
#define LogDebug(...) 
#define LogError(msg, ...) printf("ERROR\n"msg"\n", ##__VA_ARGS__)
#endif

#define WRITE_PIPE_NAME "RESP_PIPE_64890"
#define READ_PIPE_NAME "REQ_PIPE_64890"

#define END_CH '#'
#define REQUEST_BUFFER_CAPACITY 1024






//-----------------------------SF_FILE_DATA--------------------
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

//points in the maped file to these locations
typedef struct
{
    SFHeader header;
    SFSectionHeader sections[0];
}SFMappedData;

//-----------------------------END_SF_FILE_DATA--------------------



typedef struct {
    int sh_memory_fd;
    void* sh_addr;
    unsigned int sh_size;
}SHMemoryData;

typedef struct {
    int fd;
    unsigned int map_size;
    union{
        void* file_data;
        SFMappedData* sf_mapped;
    };
}MapFileData;

struct {
    int read_pipe;
    int write_pipe;
    SHMemoryData sh_memory;
    MapFileData map_file;
}GData;

typedef struct{
    char* buffer;
    int offset;
    int size;
}RequestBuffer;

int process_request_buffer(RequestBuffer request_buffer);

int read_unsigned_int(RequestBuffer* buffer, unsigned int* out_value);
int read_string(RequestBuffer* buffer, char* *out_string, unsigned int* out_string_size);

int write_unsigned_int(unsigned int value);
int write_string(const char* string);

// Main function
int main() 
{
    memset(&GData, 0, sizeof(GData));

    if(-1 == mkfifo(WRITE_PIPE_NAME, 0666))
    {
        LogError("cannot create the response pipe");
        return -1;
    }

    GData.read_pipe = open(READ_PIPE_NAME, O_RDONLY);
    if(-1 == GData.read_pipe)
    {
        LogError("cannot create the request pipe");
        goto cleanup;
    }

    GData.write_pipe = open(WRITE_PIPE_NAME, O_WRONLY);
    if(-1 == GData.write_pipe)
    {
        LogError("cannot create the response pipe");
        goto cleanup;
    }

    if(-1 == write(GData.write_pipe, "START#", strlen("START#")))
    {
        LogError("Failed to send start to the server\n");
        goto cleanup;
    }
    printf("SUCCESS\n");

    char buffer[REQUEST_BUFFER_CAPACITY + 1];
    while(1)
    {
        memset(buffer, 0, sizeof(buffer));

        ssize_t size = read(GData.read_pipe, buffer, sizeof(buffer) - 1);
        if(size < 0)
        {
            LogError("Failed tor read from pipe \n");
            goto cleanup;
        }
        buffer[size] = 0;

        RequestBuffer request_buffer;
        memset(&request_buffer, 0, sizeof(RequestBuffer));
        request_buffer.size = size;
        request_buffer.buffer = buffer;

        int res = process_request_buffer(request_buffer);
        if(res == 1)
        {
            break;
        }
    }

cleanup:
    if(GData.read_pipe <= 0)
    {
        close(GData.read_pipe);
    }    
    if(GData.write_pipe <= 0)
    {
        close(GData.write_pipe);
    }
    unlink(WRITE_PIPE_NAME);

    if(NULL != GData.sh_memory.sh_addr)
    {
        munmap(GData.sh_memory.sh_addr, GData.sh_memory.sh_size);
    }
    if(GData.sh_memory.sh_memory_fd)
    {
        close(GData.sh_memory.sh_memory_fd);
    }

    return 0;
}

void execute_create_shm(RequestBuffer* request_buffer);
void execute_write_to_shm(RequestBuffer* request_buffer);
void execute_map_file(RequestBuffer* request_buffer);
void execute_read_from_file_offset(RequestBuffer* request_buffer);
void execute_read_from_file_section(RequestBuffer* request_buffer);
void execute_read_from_logical_space_offset(RequestBuffer* RequestBuffer);

int process_request_buffer(RequestBuffer request_buffer)
{
    char* cmd = NULL;
    read_string(&request_buffer, &cmd, NULL);
    printf("CMD RECEIVED: %s\n", cmd);
    if(0 == strcmp(cmd, "VARIANT"))
    {
        write_string("VARIANT");
        write_string("VALUE");
        write_unsigned_int(64890);
    }
    else if(0 == strcmp(cmd, "CREATE_SHM"))
    {
        execute_create_shm(&request_buffer);
    }
    else if(0 == strcmp(cmd, "WRITE_TO_SHM"))
    {
        execute_write_to_shm(&request_buffer);
    }
    else if(0 == strcmp(cmd, "MAP_FILE"))
    {
        execute_map_file(&request_buffer);
    }
    else if(0 == strcmp(cmd, "READ_FROM_FILE_OFFSET"))
    {
        execute_read_from_file_offset(&request_buffer);
    }
    else if(0 == strcmp(cmd, "READ_FROM_FILE_SECTION"))
    {
        execute_read_from_file_section(&request_buffer);
    }
    else if(0 == strcmp(cmd, "READ_FROM_LOGICAL_SPACE_OFFSET"))
    {
        execute_read_from_logical_space_offset(&request_buffer);
    }
    else if(0 == strcmp(cmd, "EXIT"))
    {
        return 1;
    }

    printf("%d---%d\n", request_buffer.offset, request_buffer.size);

    return 0;
}

void execute_create_shm(RequestBuffer* request_buffer)
{
    void* sh_memory = MAP_FAILED;
    const char* sh_memory_name = "/mVxqMW";
    unsigned int sh_memory_size = 0;
    int file_desc = -1;
    int status = 0;

    read_unsigned_int(request_buffer, &sh_memory_size);

    file_desc =  shm_open(sh_memory_name, O_CREAT | O_RDWR, 0664);
    if(file_desc == -1)
    {
        status = -1;
        goto cleanup;
    }

    if(-1 == ftruncate(file_desc, sh_memory_size))
    {
        status = -1;
        goto cleanup;
    }

    sh_memory = mmap(NULL, sh_memory_size, PROT_READ | PROT_WRITE, MAP_SHARED, file_desc, 0);
    if(MAP_FAILED == sh_memory)
    {
        status = -1;
        goto cleanup;
    }

    GData.sh_memory.sh_memory_fd = file_desc;
    GData.sh_memory.sh_addr = sh_memory;
    GData.sh_memory.sh_size = sh_memory_size;

    write_string("CREATE_SHM");
    write_string("SUCCESS");

cleanup:

    if(-1 == status)
    {
        if(-1 != file_desc)
        {
            close(file_desc);
        }
        if(MAP_FAILED != sh_memory)
        {
            munmap(sh_memory, sh_memory_size);
        }

        write_string("CREATE_SHM");
        write_string("ERROR");
    }
}

void execute_map_file(RequestBuffer* request_buffer)
{
    char* file_name = NULL;
    int status = 0;
    int fd = -1;
    void* map_data = MAP_FAILED;
    unsigned int file_size = 0;
    struct stat file_stat = {0};

    read_string(request_buffer, &file_name, NULL);

    fd = open(file_name, O_RDONLY);
    if(-1 == fd)
    {
        status = -1;
        goto cleanup;
    }
    
    if(-1 == fstat(fd, &file_stat))
    {
        status = -1;
        goto cleanup;
    }
    file_size = file_stat.st_size;

    map_data = mmap(NULL, file_size, PROT_READ, MAP_SHARED, fd, 0);
    if(MAP_FAILED == map_data)
    {
        status = -1;
        goto cleanup;
    }
    
    printf("MAP FILE DATA: size: %d\n", file_size);

    GData.map_file.fd = fd;
    GData.map_file.file_data = map_data;
    GData.map_file.map_size = file_stat.st_size;

    write_string("MAP_FILE");
    write_string("SUCCESS");
cleanup:
    if(-1 == status)
    {
        if(MAP_FAILED != map_data)
        {
            munmap(map_data, file_size);
        }

        if(-1 != fd)
        {
            close(fd);
        }

        write_string("MAP_FILE");
        write_string("ERROR");
    }

}

void execute_write_to_shm(RequestBuffer* request_buffer)
{
    unsigned int offset = 0;
    unsigned int value = 0;
    int status = 0;

    read_unsigned_int(request_buffer, &offset);
    read_unsigned_int(request_buffer, &value);

    if(offset + sizeof(unsigned int) >= GData.sh_memory.sh_size)
    {
        status = -1;
        goto cleanup;
    }

    *(unsigned int*)((char*)GData.sh_memory.sh_addr + offset) = value;

    write_string("WRITE_TO_SHM");
    write_string("SUCCESS");
cleanup:
    if(-1 == status)
    {
        write_string("WRITE_TO_SHM");
        write_string("ERROR");
    }
}

void execute_read_from_file_offset(RequestBuffer* request_buffer)
{
    int status = 0;
    unsigned int offset = 0;
    unsigned int read_size = 0;

    read_unsigned_int(request_buffer, &offset);
    read_unsigned_int(request_buffer, &read_size);

    if(NULL == GData.sh_memory.sh_addr)
    {
        status = -1;
        goto cleanup;
    }

    if(NULL == GData.map_file.file_data)
    {
        status = -1;
        goto cleanup;
    }

    if(offset + read_size >= GData.map_file.map_size)
    {
        status = -1;
        goto cleanup;
    }

    if(read_size >= GData.sh_memory.sh_size)
    {
        status = -1;
        goto cleanup;
    }

    memcpy(GData.sh_memory.sh_addr, GData.map_file.file_data + offset, read_size);

    write_string("READ_FROM_FILE_OFFSET");
    write_string("SUCCESS");
cleanup:
    if(-1 == status)
    {
        write_string("READ_FROM_FILE_OFFSET");
        write_string("ERROR");
    }
}

void execute_read_from_file_section(RequestBuffer* request_buffer)
{
    unsigned int section_number = 0;
    unsigned int offset = 0;
    unsigned int no_of_bytes = 0;

    int status = 0;

    read_unsigned_int(request_buffer, &section_number);
    read_unsigned_int(request_buffer, &offset);
    read_unsigned_int(request_buffer, &no_of_bytes);

    if(NULL == GData.sh_memory.sh_addr)
    {
        status = -1;
        goto cleanup;
    }

    if(NULL == GData.map_file.file_data)
    {
        status = -1;
        goto cleanup;
    }

    if(section_number > GData.map_file.sf_mapped->header.num_sections)
    {
        status = -1;
        goto cleanup;
    }
    SFSectionHeader* section_header = &GData.map_file.sf_mapped->sections[section_number - 1];
    if(no_of_bytes + offset >= section_header->sec_size)
    {
        status = -1;
        goto cleanup;
    }

    unsigned int read_offset = section_header->sec_offset + offset;

    if(read_offset + no_of_bytes >= GData.map_file.map_size)
    {
        status = -1;
        goto cleanup;
    }

    memcpy(GData.sh_memory.sh_addr, GData.map_file.file_data + read_offset, no_of_bytes);

    write_string("READ_FROM_FILE_SECTION");
    write_string("SUCCESS");
cleanup:
    if(-1 == status)
    {
        write_string("READ_FROM_FILE_SECTION");
        write_string("ERROR");
    }
}

#define ALIGN_4096(x) ((x + (4096) - 1) & ~((4096) - 1))

unsigned int min(unsigned int a, unsigned int b)
{
    return a < b ? (a) : (b);
}

unsigned int max(unsigned int a, unsigned int b)
{
    return a > b ? (a) : (b);
}

void execute_read_from_logical_space_offset(RequestBuffer* request_buffer)
{
    unsigned int logical_offset = 0;
    unsigned int no_of_bytes = 0;
    int status = 0;    

    read_unsigned_int(request_buffer, &logical_offset);
    read_unsigned_int(request_buffer, &no_of_bytes);

    printf("%d--%d\n", logical_offset, no_of_bytes);

    if(NULL == GData.sh_memory.sh_addr)
    {
        status = -1;
        goto cleanup;
    }

    if(NULL == GData.map_file.file_data)
    {
        status = -1;
        goto cleanup;
    }

    if(no_of_bytes >= GData.sh_memory.sh_size)
    {
        status = -1;
        goto cleanup;
    }

    unsigned int totalSize = 0;
    for(int i = 0; i < GData.map_file.sf_mapped->header.num_sections; ++i)
    {
        totalSize += ALIGN_4096(GData.map_file.sf_mapped->sections[i].sec_size);
    }
    
    if(logical_offset + no_of_bytes >= totalSize)
    {
        status = -1;
        goto cleanup;
    }

    void* data = mmap(NULL, totalSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("ALLOCED: %p\n", data);
    uint32_t offset = 0;
    for(int i = 0; i < GData.map_file.sf_mapped->header.num_sections; ++i)
    {
        SFSectionHeader* section_header = &GData.map_file.sf_mapped->sections[i];
        uint32_t aligned_size = ALIGN_4096(section_header->sec_size);
        memcpy((char*)data + offset, GData.map_file.file_data + section_header->sec_offset, section_header->sec_size);
        offset += aligned_size;
    }

    memcpy(GData.sh_memory.sh_addr, data + logical_offset, no_of_bytes);

    munmap(data, totalSize);
    write_string("READ_FROM_LOGICAL_SPACE_OFFSET");
    write_string("SUCCESS");
cleanup:
    
    if(-1 == status)
    {
        write_string("READ_FROM_LOGICAL_SPACE_OFFSET");
        write_string("ERROR");
    }
}

//If the buffer its at the end of the read size, then we read more to prepare for a read
void prepare_read(RequestBuffer* buffer)
{
    if(buffer->offset != buffer->size)
    {
        return;
    }

    ssize_t read_size = read(GData.read_pipe, buffer->buffer + buffer->offset, REQUEST_BUFFER_CAPACITY - buffer->offset);
    buffer->size += read_size;
}

int read_unsigned_int(RequestBuffer* buffer, unsigned int* out_value)
{
    for(int t = 0; t < 10 && buffer->size - buffer->offset < sizeof(unsigned int); ++t)
    {
        printf("RE_READING INT\n");
        ssize_t read_size = read(GData.read_pipe, buffer->buffer + buffer->size, REQUEST_BUFFER_CAPACITY - buffer->offset);
        buffer->size += read_size;
        buffer->buffer[buffer->size] = 0;
        printf("DONE RE_READING INT\n");
    }

    *out_value = *(unsigned int*)(buffer->buffer + buffer->offset);
    buffer->offset += sizeof(unsigned int);

    return 0;
}

int read_string(RequestBuffer* buffer, char* *out_string, unsigned int* out_string_size)
{
    int string_size = 0;
    char* buffer_off = buffer->buffer + buffer->offset;

    char* end_str = strchr(buffer_off, END_CH);
    for(int t = 0; t < 10 && NULL == end_str; ++t)
    {
        printf("RE_READING STRING\n");
        ssize_t read_size = read(GData.read_pipe, buffer->buffer + buffer->size, REQUEST_BUFFER_CAPACITY - buffer->offset);
        buffer->size += read_size;
        buffer->buffer[buffer->size] = 0;

        printf("DONE RE_READING STRING\n");
        end_str = strchr(buffer_off, END_CH);
    }

    
    if(NULL == end_str)
    {
        LogError("read_string invalid string buffer");
        return -1;
    }

    *end_str = '\0';

    string_size = end_str - buffer_off;
    buffer->offset += string_size + 1;

    *out_string = buffer_off;
    if(NULL != out_string_size)
    {
        *out_string_size = string_size;
    }

    return 0;
}

int write_unsigned_int(unsigned int value)
{
    write(GData.write_pipe, &value, sizeof(value));
    return 0;
}

int write_string(const char* string)
{
    char send_string[256];
    int size = strlen(string);
    if(size >= 256)
    {
        LogError("write_string to large");
        return -1;
    }

    strcpy(send_string, string);
    send_string[size] = END_CH;
    write(GData.write_pipe, send_string, size + 1);

    return 0;
}