CFLAGS=-Wall -Werror -O2
LDFLAGS=-lpthread

all: fsync_stress

fsync_stress: fsync_stress.o
	$(CC) -o fsync_stress fsync_stress.o $(LDFLAGS)

clean:
	rm -f fsync_stress *.o
