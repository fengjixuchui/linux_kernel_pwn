/*************************************************************
 * File Name: userfaultfd_demo.c
 * 
 * Created on: 2019-11-13 19:19:15
 * Author: raycp
 * 
 * Last Modified: 2019-11-13 22:55:04
 * Description: demo for userfaultfd  
************************************************************/
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <assert.h>
#include <inttypes.h>

static int page_size;

uint64_t fault_page;
uint64_t fault_page_len;

void die(const char* msg) 
{
    perror(msg);
    _exit(-1);
}

static void *
fault_handler_thread(void *arg)
{
   static struct uffd_msg msg;   /* Data read from userfaultfd */
   long uffd;                    /* userfaultfd file descriptor */
   static char *page = NULL;
   struct uffdio_copy uffdio_copy;
   ssize_t nread;

   uffd = (long) arg;

   /* Create a page that will be copied into the faulting region */
   if (page == NULL) {
	   page = (char*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	   if (page == MAP_FAILED)
		   die("mmap");
   }

   /* Loop, handling incoming events on the userfaultfd
	  file descriptor */

   for (;;) {

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

	   printf("fault page address = %llx\n", msg.arg.pagefault.address);

	   /* Copy the page pointed to by 'page' into the faulting region.*/
	   memset(page, 'A', page_size);

	   uffdio_copy.src = (unsigned long) page;

	   /* We need to handle page faults in units of pages(!).
		  So, round faulting address down to page boundary */
	   uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
										  ~(page_size - 1);
	   uffdio_copy.len = page_size;
	   uffdio_copy.mode = 0;
	   uffdio_copy.copy = 0;
	   if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
		   die("ioctl-UFFDIO_COPY");

   }
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
   char *addr;         /* Start of region handled by userfaultfd */

   page_size = sysconf(_SC_PAGE_SIZE);

   /* Create a private anonymous mapping. The memory will be
	  demand-zero paged--that is, not yet allocated. When we
	  actually touch the memory, it will be allocated via
	  the userfaultfd. */
   addr = (char*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   if (addr == MAP_FAILED)
	   die("mmap");
   printf("Address returned by mmap() = %p\n", addr);

   // register userfaultfd
   fault_page = (uint64_t)addr;
   fault_page_len = page_size;
   register_userfault();

   // check the result.
   char c = addr[0];
   printf("char: %c\n",c);
   printf("string: %s\n", addr);

   return 0;
}
