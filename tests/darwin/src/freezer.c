// The freezer's controls in memorystatus_control: the frozen processes
// (none: the device freezes only under pressure), dasd's trial
// identifiers, a reset, the candidate lists and the probabilities of use,
// each checked as the kernel checks them; a development kernel's status is
// not supported.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

#define CMD_FREEZER_CONTROL 20
#define CMD_GET_PROCESS_IS_FROZEN 24
#define CMD_GRP_SET_PROPERTIES 100
#define GRP_SET_PROBABILITY 0x10
#define GRP_SET_FREEZE_PRIORITY 0x100
#define GRP_SET_DEMOTE_PRIORITY 0x200

struct frozen {
    uint64_t num;
    struct {
        int32_t pid;
        char name[33];
    } procs[40];
};

struct trial {
    int version;
    char treatment[37];
    char experiment[37];
    int deployment;
};

struct freeze_entry {
    int version;
    int32_t pid;
    uint32_t priority;
    char name[33];
    char pad[3];
};

struct prop_entry {
    int version;
    int32_t pid;
    int32_t priority;
    int use_probability;
    uint64_t user_data;
    int32_t limit;
    uint32_t state;
    char name[17];
};

static int bad(const char *what, long got, long want) {
    printf("freezer: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int call(uint32_t cmd, uint32_t flags, void *buf, size_t size) {
    int r = memorystatus_control(cmd, 0, flags, buf, size);
    return r < 0 ? -errno : r;
}

int main(void) {
    if (sizeof(struct frozen) != 1608 || sizeof(struct trial) != 84 || sizeof(struct freeze_entry) != 48 || sizeof(struct prop_entry) != 56)
        return bad("the structures' sizes", sizeof(struct frozen), 1608);
    struct frozen f;
    memset(&f, 0xff, sizeof f);
    int r = call(CMD_FREEZER_CONTROL, 2, &f, sizeof f);
    if (r != (int)sizeof f || f.num != 0) return bad("the frozen processes", r, sizeof f);
    if ((r = call(CMD_FREEZER_CONTROL, 2, &f, sizeof f - 1)) != -EINVAL) return bad("a short buffer", r, -EINVAL);
    if ((r = call(CMD_FREEZER_CONTROL, 1, &f, sizeof f)) != -ENOTSUP) return bad("the status", r, -ENOTSUP);
    struct trial t = {.version = 1, .deployment = 7};
    strcpy(t.treatment, "11111111-2222-3333-4444-555555555555");
    if ((r = call(CMD_FREEZER_CONTROL, 3, &t, sizeof t)) != 0) return bad("trial identifiers", r, 0);
    t.version = 2;
    if ((r = call(CMD_FREEZER_CONTROL, 3, &t, sizeof t)) != -EINVAL) return bad("a second version", r, -EINVAL);
    if ((r = call(CMD_FREEZER_CONTROL, 3, &t, sizeof t - 4)) != -EINVAL) return bad("a short trial", r, -EINVAL);
    if ((r = call(CMD_FREEZER_CONTROL, 4, NULL, 0)) != 0) return bad("a reset", r, 0);

    struct freeze_entry list[2] = {{1, getpid(), 10, "freezer", ""}, {1, 1, 5, "launchd", ""}};
    if ((r = call(CMD_GRP_SET_PROPERTIES, GRP_SET_FREEZE_PRIORITY, list, sizeof list)) != 0) return bad("the freeze list", r, 0);
    if ((r = call(CMD_GRP_SET_PROPERTIES, GRP_SET_DEMOTE_PRIORITY, list, sizeof list[0])) != 0) return bad("the demote list", r, 0);
    if ((r = call(CMD_GRP_SET_PROPERTIES, GRP_SET_FREEZE_PRIORITY, list, sizeof list - 1)) != -EINVAL) return bad("a list cut short", r, -EINVAL);
    if ((r = call(CMD_GRP_SET_PROPERTIES, GRP_SET_FREEZE_PRIORITY, NULL, 0)) != -EINVAL) return bad("an empty list", r, -EINVAL);

    struct prop_entry p = {.version = 1, .pid = getpid(), .use_probability = 1, .name = "freezer"};
    if ((r = call(CMD_GRP_SET_PROPERTIES, GRP_SET_PROBABILITY, &p, sizeof p)) != 0) return bad("the probabilities", r, 0);
    p.use_probability = 2;
    if ((r = call(CMD_GRP_SET_PROPERTIES, GRP_SET_PROBABILITY, &p, sizeof p)) != -EINVAL) return bad("a probability past 1", r, -EINVAL);
    p.use_probability = 0;
    p.version = 2;
    if ((r = call(CMD_GRP_SET_PROPERTIES, GRP_SET_PROBABILITY, &p, sizeof p)) != -EINVAL) return bad("a second version", r, -EINVAL);

    if ((r = memorystatus_control(CMD_GET_PROCESS_IS_FROZEN, getpid(), 0, NULL, 0)) != 0) return bad("frozen", r, 0);
    printf("freezer ok\n");
    return 0;
}
