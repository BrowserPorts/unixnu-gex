/* rt-clonecopy SRC DST: DST (made, empty) a copy of all of SRC by
 * copy_file_range, as a file system's clone is asked for (coreutils' cp,
 * Wine's CopyFile): says "copied N", or why it could not.
 * rt-clonecopy -w PATH OFFSET TEXT: TEXT written into PATH at OFFSET, in
 * place, and synced. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct stat st;
    long long left, total = 0;
    int in, out;

    if (argc == 5 && !strcmp(argv[1], "-w"))
    {
        int fd = open(argv[2], O_WRONLY);
        size_t n = strlen(argv[4]);
        if (fd < 0) { perror(argv[2]); return 1; }
        if (pwrite(fd, argv[4], n, atoll(argv[3])) != (ssize_t)n || fsync(fd)) { perror("pwrite"); return 1; }
        return 0;
    }
    if (argc != 3) { fprintf(stderr, "usage: rt-clonecopy SRC DST\n"); return 2; }
    if ((in = open(argv[1], O_RDONLY)) < 0 || fstat(in, &st)) { perror(argv[1]); return 1; }
    if ((out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) { perror(argv[2]); return 1; }
    for (left = st.st_size; left > 0;)
    {
        ssize_t n = copy_file_range(in, NULL, out, NULL, left, 0);
        if (n < 0) { perror("copy_file_range"); return 1; }
        if (!n) break;
        left -= n;
        total += n;
    }
    if (fsync(out)) { perror("fsync"); return 1; }
    printf("copied %lld\n", total);
    return 0;
}
