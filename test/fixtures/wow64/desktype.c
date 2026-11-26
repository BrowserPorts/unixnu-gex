/* Typing on Wine's desktop selects the icon it names, and Enter opens it
 * (explorer /desktop, desktype.test.js). Run as ztarget*.exe (a copy on the
 * desktop, which the test puts there): the opened icon, which makes
 * C:\desktype-opened. Run otherwise: a click on the desktop where no icon
 * is, the keys Z, T and Enter, and the file looked for for 30 s; what it
 * finds goes to C:\desktype.txt (a program the desktop starts has no console
 * to print to). */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static const char marker[] = "C:\\desktype-opened";

static void say(const char *fmt, ...)
{
    FILE *f = fopen("C:\\desktype.txt", "a");
    va_list a;

    if (!f) return;
    va_start(a, fmt);
    vfprintf(f, fmt, a);
    va_end(a);
    fclose(f);
}

static void key(WORD vk)
{
    INPUT in[2] = {0};
    in[0].type = in[1].type = INPUT_KEYBOARD;
    in[0].ki.wVk = in[1].ki.wVk = vk;
    in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, in, sizeof(INPUT));
    Sleep(50);
}

int main(void)
{
    char path[MAX_PATH], *name;
    INPUT in[3] = {0};
    int i, w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);

    GetModuleFileNameA(NULL, path, sizeof(path));
    name = strrchr(path, '\\') ? strrchr(path, '\\') + 1 : path;
    if (!strnicmp(name, "ztarget", 7))
    {
        HANDLE f = CreateFileA(marker, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        CloseHandle(f);
        return 0;
    }
    DeleteFileA(marker);
    DeleteFileA("C:\\desktype.txt");
    /* the desktop's icons are drawn from its top left, the taskbar along its
     * bottom; input injected goes to the input desktop only, which this
     * process's (explorer /desktop=NAME's) is made */
    Sleep(3000);
    if (!SwitchDesktop(GetThreadDesktop(GetCurrentThreadId()))) say("desktype FAIL SwitchDesktop: error %lu\n", GetLastError());
    for (i = 0; i < 3; i++) in[i].type = INPUT_MOUSE;
    in[0].mi.dx = in[1].mi.dx = in[2].mi.dx = 65535 * 3 / 4;
    in[0].mi.dy = in[1].mi.dy = in[2].mi.dy = 65535 / 2;
    in[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
    in[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_ABSOLUTE;
    in[2].mi.dwFlags = MOUSEEVENTF_LEFTUP | MOUSEEVENTF_ABSOLUTE;
    if (SendInput(3, in, sizeof(INPUT)) != 3) say("desktype FAIL SendInput: error %lu\n", GetLastError());
    Sleep(500);
    say("desktype screen %dx%d, foreground %p after the click\n", w, h, GetForegroundWindow());
    key('Z');
    key('T');
    Sleep(300);
    key(VK_RETURN);
    for (i = 0; i < 300; i++)
    {
        if (GetFileAttributesA(marker) != INVALID_FILE_ATTRIBUTES)
        {
            say("desktype ok\n");
            return 0;
        }
        Sleep(100);
    }
    say("desktype FAIL no icon was opened\n");
    return 1;
}
