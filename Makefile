CFLAGS=-Wall -Werror -O2

all: fsync_stress

fsync_stress: fsync_stress.o
	$(CC) -o fsync_stress fsync_stress.o

clean:
	rm -f fsync_stress *.o
