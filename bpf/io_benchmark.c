#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
    struct timespec time_value;
    clock_gettime(CLOCK_MONOTONIC_RAW, &time_value);
    return (uint64_t)time_value.tv_sec * 1000000000ULL +
           (uint64_t)time_value.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s PATH ITERATIONS read|write\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    long iterations = strtol(argv[2], NULL, 10);
    int write_mode = strcmp(argv[3], "write") == 0;
    long allowed = 0;
    long denied = 0;
    uint64_t start = now_ns();
    for (long index = 0; index < iterations; ++index) {
        int descriptor = open(path, write_mode ? O_WRONLY : O_RDONLY);
        if (descriptor < 0) {
            if (errno == EPERM || errno == EACCES || errno == EROFS) {
                ++denied;
                continue;
            }
            perror("open");
            return 1;
        }
        char byte = write_mode ? (char)('A' + index % 26) : 0;
        ssize_t result = write_mode
                             ? pwrite(descriptor, &byte, 1, 0)
                             : pread(descriptor, &byte, 1, 0);
        if (result == 1)
            ++allowed;
        else if (errno == EPERM || errno == EACCES || errno == EROFS)
            ++denied;
        else {
            perror(write_mode ? "pwrite" : "pread");
            close(descriptor);
            return 1;
        }
        close(descriptor);
    }
    uint64_t elapsed = now_ns() - start;
    printf("iterations,allowed,denied,total_ns,ns_per_operation\n");
    printf("%ld,%ld,%ld,%llu,%.3f\n", iterations, allowed, denied,
           (unsigned long long)elapsed, (double)elapsed / iterations);
    return 0;
}
