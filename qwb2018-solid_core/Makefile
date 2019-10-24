ALL:
	gcc -O0 -static -D_GNU_SOURCE -o ./cpio/exp exp.c	
	cd cpio && find . | cpio -o --format=newc > ../solid_core.cpio

clean:
	rm ./cpio/exp
