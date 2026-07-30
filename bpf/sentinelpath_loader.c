#define _GNU_SOURCE
#include "third_party/libbpf/src/bpf.h"
#include "third_party/libbpf/src/libbpf.h"
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

struct sentinel_config {
    uint64_t inode;
    uint64_t device;
    uint32_t authorized_tgid;
    uint32_t enforce;
    uint64_t pidns_device;
    uint64_t pidns_inode;
};

struct sentinel_event {
    uint64_t time_ns;
    uint64_t inode;
    uint64_t device;
    uint32_t tgid;
    uint32_t uid;
    uint32_t operation;
    int32_t decision;
};

static volatile sig_atomic_t running = 1;
static FILE *log_file;

static void stop_handler(int signal_number)
{
    (void)signal_number;
    running = 0;
}

static int event_handler(void *context, void *data, size_t size)
{
    (void)context;
    if (size < sizeof(struct sentinel_event))
        return 0;
    const struct sentinel_event *event = data;
    static const char *names[] = {"unknown", "open", "write", "unlink", "rename"};
    const char *name = event->operation < 5 ? names[event->operation] : names[0];
    fprintf(log_file,
            "{\"time_ns\":%llu,\"operation\":\"%s\",\"tgid\":%u,"
            "\"uid\":%u,\"inode\":%llu,\"device\":%llu,\"decision\":\"%s\"}\n",
            (unsigned long long)event->time_ns, name, event->tgid,
            event->uid, (unsigned long long)event->inode,
            (unsigned long long)event->device,
            event->decision == 0 ? "allow" :
            (event->decision < 0 ? "deny" : "observe"));
    fflush(log_file);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s BPF_OBJECT PROTECTED_PATH LOG_PATH PIN_PATH\n",
                argv[0]);
        return 2;
    }
    struct stat target;
    if (stat(argv[2], &target) != 0) {
        perror("stat protected path");
        return 1;
    }
    struct stat pid_namespace;
    if (stat("/proc/self/ns/pid", &pid_namespace) != 0) {
        perror("stat pid namespace");
        return 1;
    }
    log_file = fopen(argv[3], "a");
    if (!log_file) {
        perror("fopen log");
        return 1;
    }
    setvbuf(log_file, NULL, _IOLBF, 0);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct bpf_object *object = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(object)) {
        fprintf(stderr, "cannot open BPF object\n");
        return 1;
    }
    struct bpf_map *config_map = bpf_object__find_map_by_name(object, "config");
    if (!config_map) {
        fprintf(stderr, "config map missing\n");
        return 1;
    }
    bpf_map__set_pin_path(config_map, argv[4]);
    if (bpf_object__load(object) != 0) {
        fprintf(stderr, "cannot load BPF object (is bpf in the active LSM list?)\n");
        return 1;
    }
    int config_fd = bpf_map__fd(config_map);
    uint32_t key = 0;
    struct sentinel_config config = {
        .inode = target.st_ino,
        .device = ((uint64_t)major(target.st_dev) << 20) |
                  (uint64_t)minor(target.st_dev),
        .authorized_tgid = 0,
        .enforce = 1,
        .pidns_device = pid_namespace.st_dev,
        .pidns_inode = pid_namespace.st_ino,
    };
    if (bpf_map_update_elem(config_fd, &key, &config, BPF_ANY) != 0) {
        perror("update config");
        return 1;
    }

    struct bpf_link *links[8] = {0};
    size_t link_count = 0;
    struct bpf_program *program;
    bpf_object__for_each_program(program, object) {
        struct bpf_link *link = bpf_program__attach(program);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "cannot attach program %s\n", bpf_program__name(program));
            return 1;
        }
        links[link_count++] = link;
    }
    struct bpf_map *event_map = bpf_object__find_map_by_name(object, "events");
    struct ring_buffer *ring =
        ring_buffer__new(bpf_map__fd(event_map), event_handler, NULL, NULL);
    if (!ring) {
        fprintf(stderr, "cannot create ring buffer\n");
        return 1;
    }
    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);
    fprintf(log_file,
            "{\"event\":\"monitor_start\",\"inode\":%llu,\"device\":%llu}\n",
            (unsigned long long)config.inode,
            (unsigned long long)config.device);
    while (running) {
        int result = ring_buffer__poll(ring, 200);
        if (result == -EINTR)
            continue;
        if (result < 0)
            break;
    }
    config.enforce = 0;
    bpf_map_update_elem(config_fd, &key, &config, BPF_ANY);
    fprintf(log_file, "{\"event\":\"monitor_stop\"}\n");
    ring_buffer__free(ring);
    for (size_t i = 0; i < link_count; ++i)
        bpf_link__destroy(links[i]);
    unlink(argv[4]);
    bpf_object__close(object);
    fclose(log_file);
    return 0;
}
