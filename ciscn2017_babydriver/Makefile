ALL:
	gcc -O0 -static  -o exp_smep exp_smep.c
	gcc -O0 -static  -o exp_uaf exp_uaf.c
	find . | cpio -o --format=newc > ../rootfs.cpio
SMEP:
	gcc -static -g  -o exp_smep exp_smep.c
	find . | cpio -o --format=newc > ../rootfs.cpio
UAF:
	gcc -O0 -static  -o exp_uaf exp_uaf.c
	find . | cpio -o --format=newc > ../rootfs.cpio

clean:
	rm exp_uaf
	rm exp_smep
