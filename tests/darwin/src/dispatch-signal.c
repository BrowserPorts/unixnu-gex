// libdispatch signal sources: SIGUSR1 ignored, a source counting it, and
// two signals sent to the process itself (EVFILT_SIGNAL).
//
// What is timed is the signals' delivery: the 5 seconds start when they
// are sent, not when the timer that sends them is armed (nothing bounds
// when a new process's queue first runs a block), and the timeout runs on
// the source's own queue, so it and the handler never both report.

#include <dispatch/dispatch.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    signal(SIGUSR1, SIG_IGN);
    dispatch_queue_t q = dispatch_queue_create("gex.signal", NULL);
    dispatch_source_t s = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, q);
    __block unsigned long seen = 0;
    dispatch_source_set_event_handler(s, ^{
        seen += dispatch_source_get_data(s);
        if (seen >= 2) {
            printf("dispatch-signal %lu\n", seen);
            exit(0);
        }
    });
    dispatch_activate(s);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_MSEC), q, ^{
        kill(getpid(), SIGUSR1);
        kill(getpid(), SIGUSR1);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), q, ^{
            printf("dispatch-signal timed out at %lu\n", seen);
            exit(1);
        });
    });
    dispatch_main();
}
