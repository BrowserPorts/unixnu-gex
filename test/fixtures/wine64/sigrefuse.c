/* A call no slot semantics make work: an int passed where the callee
 * (sigrefuse2.c) reads a double, another register file. The link fails. */
int sig_float(int);
int main(void) { return sig_float(3); }
