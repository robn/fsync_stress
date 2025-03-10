/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Klara, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* this is a relatively untested WIP. probably don't use it yet */

#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>

static void
usage()
{
	fprintf(stderr,
	    "usage: fsync_stress "
	    "[-o resultfile] "
	    "[-n numthreads] [-t timeout] "
	    "[-m minsz] [-M maxsz] <basedir>\n");
	exit(1);
}

static int
fill_random(uint8_t *v, size_t sz)
{
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return (errno);

	while (sz > 0) {
		ssize_t r = read(fd, v, sz);
		if (r < 0) {
			close(fd);
			return (errno);
		}
		v += r;
		sz -= r;
	}

	close(fd);

	return (0);
}

static inline uint64_t
now_ns(void)
{
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ((((uint64_t)ts.tv_sec) * 1000000000) + ts.tv_nsec);
}


typedef struct {
	int basedirfd;
	size_t minsz;
	size_t maxsz;
	const uint8_t *data;
	size_t datasz;
} file_opts_t;

typedef enum {
	F_ST_SETUP = 0,
	F_ST_OPEN,
	F_ST_HEADER,
	F_ST_DATA,
	F_ST_FOOTER,
	F_ST_RENAME,
	F_ST_FSYNC,
	F_ST_CLOSE,
	F_ST_DONE,
} file_state_t;

const char *file_state_str[] = {
	"SETUP",
	"OPEN",
	"HEADER",
	"DATA",
	"FOOTER",
	"RENAME",
	"FSYNC",
	"CLOSE",
	"DONE",
};

typedef struct {
	void *next;
	unsigned int filenum;
	file_state_t state;
	size_t filesz;
	int err;
	uint64_t ns;
} file_result_t;

const char footer[] = "ENDOFLINE";

atomic_uint t_filenum;
atomic_bool t_exit;
atomic_uint t_exited;

file_result_t *results = NULL;
pthread_mutex_t results_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t results_cv = PTHREAD_COND_INITIALIZER;

static void *
file_thread(void *arg)
{
	const file_opts_t *opts = arg;

	char dirname[32];
	char filename[32];
	char filename_tmp[32];

	while (!atomic_load(&t_exit)) {
		int fd = -1, dirfd = -1;
		uint64_t start_ns = 0, end_ns;

		file_result_t *res = calloc(1, sizeof (file_result_t));

		res->filenum = atomic_fetch_add(&t_filenum, 1);
		res->state = F_ST_SETUP;

		snprintf(dirname, sizeof (dirname), "d%03u",
		    res->filenum % 1000);
		dirfd = openat(opts->basedirfd, dirname, O_DIRECTORY);
		if (dirfd < 0) {
			if (errno != ENOENT) {
				res->err = errno;
				goto ferr;
			}
			if (mkdirat(opts->basedirfd, dirname, S_IRWXU) < 0) {
				if (errno != EEXIST) {
					res->err = errno;
					goto ferr;
				}
			}
			dirfd = openat(opts->basedirfd, dirname, O_DIRECTORY);
			if (dirfd < 0) {
				res->err = errno;
				goto ferr;
			}
		}

		snprintf(filename, sizeof (filename), "%u", res->filenum);
		snprintf(filename_tmp, sizeof (filename), "%u.tmp", res->filenum);

		res->filesz =
		    (random() % (opts->maxsz+1-opts->minsz)) + opts->minsz;

		start_ns = now_ns();

		res->state++;
		fd = openat(dirfd, filename_tmp,
		    O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR);
		if (fd < 0) {
			res->err = errno;
			goto ferr;
		}

		res->state++;
		int nw = write(fd, &res->filesz, sizeof (size_t));
		if (nw < 0) {
			res->err = errno;
			goto ferr;
		}

		res->state++;
		size_t rem = res->filesz;
		while (rem > 0) {
			nw = write(fd, &opts->data[res->filesz-rem], rem);
			if (nw < 0) {
				res->err = errno;
				goto ferr;
			}
			rem -= nw;
		}

		res->state++;
		nw = write(fd, footer, sizeof (footer));
		if (nw < 0) {
			res->err = errno;
			goto ferr;
		}

		res->state++;
		if (renameat(dirfd, filename_tmp, dirfd, filename) < 0) {
			res->err = errno;
			goto ferr;
		}

		res->state++;
		if (fsync(fd) < 0) {
			res->err = errno;
			goto ferr;
		}

		res->state++;
		if (close(fd) < 0)
			res->err = errno;
		else
			res->state++;
		fd = -1;

ferr:
		end_ns = now_ns();
		res->ns = start_ns > 0 ? end_ns - start_ns : 0;

		if (fd >= 0)
			close(fd);
		if (dirfd >= 0)
			close(dirfd);

		pthread_mutex_lock(&results_lock);
		res->next = results;
		results = res;
		pthread_cond_signal(&results_cv);
		pthread_mutex_unlock(&results_lock);
	}

	atomic_fetch_add(&t_exited, 1);
	pthread_cond_signal(&results_cv);

	return (NULL);
}

int
main(int argc, char **argv)
{
	char *resultfile = "result.log";
	char *basedir = NULL;
	int nthreads = 10;
	time_t runtime = 1;
	size_t minsz = 1024, maxsz = 1408*1024;

	int c;
	while ((c = getopt(argc, argv, "o:n:t:m:M:")) != -1) {
		switch (c) {
		case 'o':
			resultfile = optarg;
			break;
		case 'n':
			nthreads = atoi(optarg);
			if (nthreads <= 0) {
				fprintf(stderr, "E: invalid number of threads: "
				    "%s\n", optarg);
				usage();
			}
			break;
		case 't':
			runtime = atoi(optarg);
			if (runtime <= 0) {
				fprintf(stderr, "E: invalid run time: %s\n",
				    optarg);
				usage();
			}
			break;
		case 'm':
			minsz = atoll(optarg);
			if (minsz <= 0) {
				fprintf(stderr, "E: invalid min size: %s\n",
				    optarg);
				usage();
			}
			break;
		case 'M':
			maxsz = atoll(optarg);
			if (maxsz <= 0) {
				fprintf(stderr, "E: invalid max size: %s\n",
				    optarg);
				usage();
			}
			break;
		default:
			usage();
		}
	}

	if (minsz > maxsz) {
		fprintf(stderr, "E: min size must be <= max size\n");
		usage();
	}
	if (maxsz > 16*1024*1024) {
		fprintf(stderr, "E: max size must be <= 16M\n");
		usage();
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	basedir = argv[0];

	srandom(time(NULL));

	atomic_init(&t_filenum, 0);
	atomic_init(&t_exit, 0);
	atomic_init(&t_exited, 0);

	size_t datasz = 16*1024*1024;
	uint8_t *data = NULL;
	int basedirfd = -1;
	int resultfd = -1;
	FILE *resultfh = NULL;
	int rc = 3;

	basedirfd = open(basedir, O_DIRECTORY);
	if (basedirfd < 0) {
		fprintf(stderr, "E: couldn't open dir %s: %s\n",
		    basedir, strerror(errno));
		goto out;
	}

	data = malloc(datasz);
	if (data == NULL) {
		fprintf(stderr, "E: couldn't allocate file data memory: %s\n",
		    strerror(errno));
		goto out;
	}
	int err = fill_random(data, datasz);
	if (err != 0) {
		fprintf(stderr, "E: couldn't fill random data: %s\n",
		    strerror(err));
		goto out;
	}

	resultfd = open(resultfile, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR);
	if (resultfd < 0) {
		fprintf(stderr, "E: couldn't open result file %s: %s\n",
		    resultfile, strerror(errno));
		goto out;
	}
	resultfh = fdopen(resultfd, "w");

	rc = 0;

	struct timespec timeout = {
		.tv_sec = time(NULL) + runtime,
		.tv_nsec = 0,
	};

	file_opts_t opts = {
		.basedirfd = basedirfd,
		.minsz = minsz,
		.maxsz = maxsz,
		.data = data,
		.datasz = datasz,
	};

	pthread_t *threads = malloc(nthreads * sizeof (pthread_t));
	for (int i = 0; i < nthreads; i++) {
		err = pthread_create(&threads[i], NULL, file_thread, &opts);
		if (err != 0) {
			fprintf(stderr, "E: couldn't create thread %d: %s\n",
			    i, strerror(err));
			rc = 2;
			goto out;
		}
	}

	enum { RUNNING, EXITING, DONE, TIMEDOUT } runstate = RUNNING;
	while (runstate < DONE) {
		file_result_t *res = NULL;

		pthread_mutex_lock(&results_lock);
		while (results == NULL && runstate < DONE) {
			int err = pthread_cond_timedwait(
			    &results_cv, &results_lock, &timeout);
			if (err != 0) {
				if (err != ETIMEDOUT) {
					fprintf(stderr, "E: condvar wait "
					    "failed: %s\n", strerror(errno));
					rc = 2;
					goto out;
				}

				if (runstate == RUNNING) {
					atomic_store(&t_exit, 1);
					timeout.tv_sec += 10;
					runstate = EXITING;
				} else {
					runstate = TIMEDOUT;
				}
			}
		}

		res = results;
		results = NULL;
		pthread_mutex_unlock(&results_lock);

		while (res != NULL) {
			fprintf(resultfh, "%s: filenum=%u state=%s size=%lu "
			    "err=%d ns=%lu\n",
			    res->err == 0 ? "OK" : "FAIL", res->filenum,
			    file_state_str[res->state], res->filesz, res->err,
			    res->ns / 1000);
			void *next = res->next;
			free(res);
			res = next;
		}
		fflush(resultfh);

		if (atomic_load(&t_exited) == nthreads) {
			if (results != NULL)
				runstate = EXITING;
			else
				runstate = DONE;
		}
	}

	if (runstate == TIMEDOUT) {
		fprintf(stderr, "W: not all threads returned after exit "
		    "signal; are they stuck? exiting without cleanup\n");
		rc = 5;
		goto out;
	}

	for (int i = 0; i < nthreads; i++)
	    pthread_join(threads[i], NULL);

	free(threads);

out:
	if (resultfh != NULL)
		fclose(resultfh);
	if (resultfd >= 0)
		close(resultfd);
	if (data != NULL)
		free(data);
	if (basedirfd >= 0)
		close(basedirfd);

	return (rc);
}
