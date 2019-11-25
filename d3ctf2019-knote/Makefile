ALL:
	gcc -O0 -static  -o ./cpio/exp exp.c -lpthread
	strip ./cpio/exp
	cd cpio && find . | cpio -o --format=newc > ../rootfs.img
	#cd cpio&&./gen_cpio.sh ../core.cpio

clean:
	rm ./cpio/exp

