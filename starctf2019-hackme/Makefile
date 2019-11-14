ALL:
	gcc -static -O0 -o ./cpio/home/pwn/exp_ptmx exp_ptmx.c -lpthread
	gcc -static -O0 -o ./cpio/home/pwn/exp_heap exp_heap.c -lpthread
	gcc -static -O0 -o ./cpio/home/pwn/exp_userfaultfd exp_userfaultfd.c -lpthread
	cd cpio && find . | cpio -o --format=newc > ../initramfs.cpio

HEAP_ATTACK:
	gcc -static -O0 -o ./cpio/home/pwn/exp_heap exp_heap.c -lpthread
	cd cpio && find . | cpio -o --format=newc > ../initramfs.cpio

USERFAULTFD:
	gcc -static -O0 -o ./cpio/home/pwn/exp_userfaultfd exp_userfaultfd.c -lpthread
	cd cpio && find . | cpio -o --format=newc > ../initramfs.cpio

PTMX:
	gcc -static -O0 -o ./cpio/home/pwn/exp_ptmx exp_ptmx.c -lpthread
	cd cpio && find . | cpio -o --format=newc > ../initramfs.cpio



clean:
	-rm ./cpio/home/pwn/exp_ptmx
	-rm ./cpio/home/pwn/exp_heap
	-rm ./cpio/home/pwn/exp_userfaultfd
	cd cpio && find . | cpio -o --format=newc > ../initramfs.cpio

