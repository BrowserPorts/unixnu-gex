/* sigadapt.c's callees, declared there with other types */
int sig_counter;
int sig_extra() { return 5; }
int sig_missing(int a, int b) { return a * 100 + b; }
int sig_narrow(int x) { return x; }
int sig_val(void) { sig_counter++; return 3; }
void sig_novalue(void) { sig_counter += 10; }
long long sig_widen(long long x) { return x; }
void *sig_extra_addr(void) { return (void *)sig_extra; }
