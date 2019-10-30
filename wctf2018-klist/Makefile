ALL:
	gcc -static -O0 -o ./cpio/exp exp.c -lpthread
	cd cpio && find . | cpio -o --format=newc > ../rootfs.cpio

clean:
	rm ./exp
