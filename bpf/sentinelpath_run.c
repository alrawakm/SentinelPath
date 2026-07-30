#define _GNU_SOURCE
#include "third_party/libbpf/src/bpf.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

struct sentinel_config {
    uint64_t inode;
    uint64_t device;
    uint32_t authorized_tgid;
    uint32_t enforce;
    uint64_t pidns_device;
    uint64_t pidns_inode;
};

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s PIN_PATH COMMAND [ARG...]\n", argv[0]);
        return 2;
    }
    int map_fd = bpf_obj_get(argv[1]);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }
    uint32_t key = 0;
    struct sentinel_config config;
    if (bpf_map_lookup_elem(map_fd, &key, &config) != 0) {
        perror("lookup config");
        return 1;
    }
    int gate[2];
    if (pipe2(gate, O_CLOEXEC) != 0) {
        perror("pipe");
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        close(gate[1]);
        char byte;
        if (read(gate[0], &byte, 1) != 1)
            _exit(126);
        close(gate[0]);
        execvp(argv[2], &argv[2]);
        perror("execvp");
        _exit(127);
    }
    close(gate[0]);
    config.authorized_tgid = (uint32_t)child;
    if (bpf_map_update_elem(map_fd, &key, &config, BPF_ANY) != 0) {
        perror("authorize child");
        return 1;
    }
    if (write(gate[1], "x", 1) != 1)
        perror("release child");
    close(gate[1]);
    int status;
    waitpid(child, &status, 0);
    config.authorized_tgid = 0;
    bpf_map_update_elem(map_fd, &key, &config, BPF_ANY);
    close(map_fd);
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return 128 + WTERMSIG(status);
}
