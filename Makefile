sha1collision: sha1collision.c sha1.o
	gcc -std=c99 -march=native -Wall -O3 -o $@ $^

*.o: *.c
	gcc -std=c99 -march=native -Wall -O3 -c -o $@ $<
