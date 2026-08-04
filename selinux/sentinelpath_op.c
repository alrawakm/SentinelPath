#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int write_path(const char *path) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) return errno;
    if (write(fd, "X\n", 2) != 2) {
        int saved = errno ? errno : EIO;
        close(fd);
        return saved;
    }
    return close(fd) == 0 ? 0 : errno;
}

static int read_path(const char *path) {
    char byte;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return errno;
    if (read(fd, &byte, 1) < 0) {
        int saved = errno;
        close(fd);
        return saved;
    }
    return close(fd) == 0 ? 0 : errno;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: sentinelpath_op MODE ROOT\n");
        return 2;
    }
    const char *mode = argv[1];
    const char *root = argv[2];
    char target[512], other[512], symlink_path[512], hardlink[512];
    char moved[512], replacement[512];
    snprintf(target, sizeof(target), "%s/protected.json", root);
    snprintf(other, sizeof(other), "%s/unrelated.json", root);
    snprintf(symlink_path, sizeof(symlink_path), "%s/symlink.json", root);
    snprintf(hardlink, sizeof(hardlink), "%s/hardlink.json", root);
    snprintf(moved, sizeof(moved), "%s/moved.json", root);
    snprintf(replacement, sizeof(replacement), "%s/replacement.json", root);

    int result;
    if (strcmp(mode, "direct_write") == 0) result = write_path(target);
    else if (strcmp(mode, "symlink_write") == 0) result = write_path(symlink_path);
    else if (strcmp(mode, "hardlink_write") == 0) result = write_path(hardlink);
    else if (strcmp(mode, "rename_away") == 0) result = rename(target, moved) == 0 ? 0 : errno;
    else if (strcmp(mode, "rename_overwrite") == 0) result = rename(replacement, target) == 0 ? 0 : errno;
    else if (strcmp(mode, "unlink") == 0) result = unlink(target) == 0 ? 0 : errno;
    else if (strcmp(mode, "protected_read") == 0) result = read_path(target);
    else if (strcmp(mode, "unrelated_write") == 0) result = write_path(other);
    else return 2;

    if (result != 0) {
        fprintf(stderr, "%s\n", strerror(result));
        return result > 125 ? 125 : result;
    }
    return 0;
}
