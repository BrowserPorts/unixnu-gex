/* A captioned top-level window keeps its caption inside the work area
 * (win32u keep_caption_on_screen): one taller than the work area, shown with
 * its caption above it, opens with the caption inside and no taller than the
 * work area; a shown one a program moves above the work area comes back to its
 * top at its own size. Left alone: a window parked at -32000,-32000, a tool
 * window above the work area, and a maximized window (its frame above the
 * work area, as Windows places it). Driver-agnostic: everything is measured
 * against SPI_GETWORKAREA.
 * gex-nt-cc: clang --target=ARCH-w64-mingw32 -fms-extensions -fuse-ld=lld */
#include <windows.h>
#include <stdio.h>

static int failures;
#define CHECK(name, cond, ...) do { int ok_ = (cond); printf("%s %s", ok_ ? "ok" : "FAIL", name); \
    if (!ok_) { printf(": "); printf(__VA_ARGS__); failures++; } printf("\n"); } while (0)

static LRESULT CALLBACK proc(HWND w, UINT m, WPARAM wp, LPARAM lp) { return DefWindowProcA(w, m, wp, lp); }

static HWND make(DWORD ex, DWORD style, const char *title, int x, int y, int cx, int cy) {
    return CreateWindowExA(ex, "capkeep", title, style, x, y, cx, cy, NULL, NULL, GetModuleHandleA(NULL), NULL);
}

int main(void) {
    WNDCLASSA wc = { 0 };
    RECT work, r, c;
    POINT o = { 0, 0 };
    HWND w;
    int work_h;

    wc.lpfnWndProc = proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "capkeep";
    RegisterClassA(&wc);
    SystemParametersInfoA(SPI_GETWORKAREA, 0, &work, 0);
    work_h = work.bottom - work.top;
    /* 2000 px taller than the work area, its caption 100 px above it. CreateWindow cuts it to the screen's height
     * plus its frame (WM_GETMINMAXINFO), so its caption must be near enough for the rest to stay on the monitor:
     * one wholly above every monitor is parked, and left there. */
    w = make(0, WS_OVERLAPPEDWINDOW, "capkeep tall", work.left + 50, work.top - 100, 400, work_h + 2000);
    ShowWindow(w, SW_SHOWNORMAL);
    GetWindowRect(w, &r);
    GetClientRect(w, &c);
    ClientToScreen(w, &o);
    CHECK("a tall window opens with its caption in the work area", r.top >= work.top && o.y <= work.bottom,
          "window %ld,%ld-%ld,%ld client top %ld, work area %ld,%ld-%ld,%ld", r.left, r.top, r.right, r.bottom, o.y,
          work.left, work.top, work.right, work.bottom);
    CHECK("and no taller than the work area", r.bottom - r.top <= work_h, "height %ld, work %d", r.bottom - r.top, work_h);
    CHECK("and at its own x", r.left == work.left + 50, "left %ld", r.left);

    /* A program move of a shown window above the work area: back to its top, the size kept. */
    SetWindowPos(w, NULL, work.left + 60, work.top - 100, 400, 300, SWP_NOZORDER | SWP_NOACTIVATE);
    GetWindowRect(w, &r);
    CHECK("a program move above the work area comes back to its top", r.top == work.top && r.left == work.left + 60,
          "window %ld,%ld", r.left, r.top);
    CHECK("at the size the program gave", r.right - r.left == 400 && r.bottom - r.top == 300,
          "%ldx%ld", r.right - r.left, r.bottom - r.top);

    /* A program move inside the work area: untouched. */
    SetWindowPos(w, NULL, work.left + 70, work.top + 30, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    GetWindowRect(w, &r);
    CHECK("a move inside the work area is the program's", r.left == work.left + 70 && r.top == work.top + 30,
          "window %ld,%ld", r.left, r.top);

    /* Parked off every monitor. */
    SetWindowPos(w, NULL, -32000, -32000, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    GetWindowRect(w, &r);
    CHECK("a window parked at -32000,-32000 stays there", r.left == -32000 && r.top == -32000, "window %ld,%ld", r.left, r.top);
    DestroyWindow(w);

    /* A tool window above the work area. */
    w = make(WS_EX_TOOLWINDOW, WS_OVERLAPPEDWINDOW, "capkeep tool", work.left + 50, work.top - 100, 300, 200);
    ShowWindow(w, SW_SHOWNOACTIVATE);
    GetWindowRect(w, &r);
    CHECK("a tool window is where it was put", r.top == work.top - 100 && r.bottom - r.top == 200, "window %ld,%ld %ldx%ld",
          r.left, r.top, r.right - r.left, r.bottom - r.top);
    DestroyWindow(w);

    /* Maximized: its frame above the work area, as Windows places it. */
    w = make(0, WS_OVERLAPPEDWINDOW, "capkeep max", work.left + 50, work.top + 50, 300, 200);
    ShowWindow(w, SW_SHOWMAXIMIZED);
    GetWindowRect(w, &r);
    CHECK("a maximized window keeps its frame above the work area", (GetWindowLongA(w, GWL_STYLE) & WS_MAXIMIZE) && r.top < work.top,
          "window %ld,%ld-%ld,%ld", r.left, r.top, r.right, r.bottom);
    DestroyWindow(w);

    printf("%d failures\n", failures);
    return failures != 0;
}
