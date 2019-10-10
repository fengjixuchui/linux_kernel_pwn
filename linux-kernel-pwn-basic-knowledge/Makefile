ALL:
	gcc -O0 -static  -o ./exp exp.c
	find ./cpio | cpio -o --format=newc > ./core.cpio
	#cd cpio&&./gen_cpio.sh ../core.cpio

clean:
	rm ./cpio/exp

