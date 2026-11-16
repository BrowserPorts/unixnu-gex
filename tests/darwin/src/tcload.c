// AMFI loads a trust cache (__mac_syscall 101, load_trust_cache_with_type)
// for a task whose com.apple.private.pmap.load-trust-cache entitlement
// allows the cache's type: a request without its IM4P, or naming a
// manifest it does not give, is EINVAL; a type the entitlement does not
// allow, or a task without it, is EPERM; an IM4P that does not decode
// fails its Image4 evaluation (KERN_FAILURE, ECANCELED).

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int __mac_syscall(const char *policy, int call, void *arg);

struct load {
    uint8_t type;
    const void *payload;
    uint32_t payload_len;
    const void *manifest;
    uint32_t manifest_len;
    const void *aux;
    uint32_t aux_len;
};

static int load(struct load *l, int want, const char *what) {
    int r = __mac_syscall("AMFI", 101, l);
    int e = r == 0 ? 0 : errno;
    if (e != want) {
        printf("tcload: %s: %d, want %d\n", what, e, want);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    static const char junk[] = "junk";
    struct load l = {0x0d, junk, 4, junk, 4, NULL, 0};
    if (argc > 1 && strcmp(argv[1], "noent") == 0) {
        if (!load(&l, EPERM, "an unentitled load")) return 1;
        printf("tcload noent ok\n");
        return 0;
    }
    if (!load(NULL, EINVAL, "no request")) return 1;
    l.payload = NULL;
    if (!load(&l, EINVAL, "no IM4P")) return 1;
    l.payload = junk;
    l.payload_len = 0;
    if (!load(&l, EINVAL, "an empty IM4P")) return 1;
    l.payload_len = 4;
    l.manifest = NULL;
    if (!load(&l, EINVAL, "a manifest's length without it")) return 1;
    l.manifest = junk;
    l.aux_len = 4;
    if (!load(&l, EINVAL, "an auxiliary manifest's length without it")) return 1;
    l.aux_len = 0;
    l.type = 0x0e;
    if (!load(&l, EPERM, "the AppOS type, which the entitlement does not allow")) return 1;
    l.type = 0x0d;
    if (!load(&l, ECANCELED, "an IM4P that does not decode")) return 1;
    printf("tcload ok\n");
    return 0;
}
