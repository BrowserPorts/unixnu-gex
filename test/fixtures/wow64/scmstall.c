/* scmstall: in a session booted without wineboot (WINEGEX_NO_WINEBOOT=1),
 * the first OpenSCManager starts services.exe and waits for it to serve.
 * With "serve" never (built -DNEVER, as the session's services.exe): it
 * sleeps. Otherwise, asks the service manager twice, saying how each ask
 * ended ("scmstall N failed ERR" or "scmstall N ok"). */
#include <windows.h>
#include <stdio.h>

int main(void)
{
#ifdef NEVER
    Sleep(300000);
    return 0;
#else
    int i;
    for (i = 1; i <= 2; i++)
    {
        SC_HANDLE h = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (h) { printf("scmstall %d ok\n", i); CloseServiceHandle(h); }
        else printf("scmstall %d failed %lu\n", i, GetLastError());
        fflush(stdout);
    }
    return 0;
#endif
}
