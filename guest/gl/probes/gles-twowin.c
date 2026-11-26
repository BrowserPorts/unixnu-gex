/* Two GLES2 windows on X11 drawn with one EGL context, made current on each
 * window's surface in turn and swapped there, as a toolkit draws its main
 * window and a dialog (Godot's project manager does it through WGL). Window
 * "twowin A" is 200x150 cleared to magenta, "twowin B" 100x80 cleared to
 * cyan; each must show its own colour, at its own size.
 *
 *   gles-twowin [frames] [seconds]   (default: 60 frames each, then 30 s shown)
 *
 * Says "windows 0x<a> 0x<b>", "frames N gl error E", then keeps both up,
 * swapping each a frame a second, until the seconds are over. */
#define _GNU_SOURCE
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void frame(EGLDisplay egl, EGLSurface s, EGLContext ctx, int w, int h, float r, float g, float b) {
    eglMakeCurrent(egl, s, s, ctx);
    glViewport(0, 0, w, h);
    glClearColor(r, g, b, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    eglSwapBuffers(egl, s);
}

int main(int argc, char **argv) {
    const int frames = argc > 1 ? atoi(argv[1]) : 60;
    const int seconds = argc > 2 ? atoi(argv[2]) : 30;
    setvbuf(stdout, NULL, _IONBF, 0);
    void *x = dlopen("libX11.so.6", RTLD_NOW | RTLD_GLOBAL);
    if (!x) { printf("no libX11: %s\n", dlerror()); return 1; }
    void *(*open_display)(const char *) = dlsym(x, "XOpenDisplay");
    int (*default_screen)(void *) = dlsym(x, "XDefaultScreen");
    unsigned long (*root_window)(void *, int) = dlsym(x, "XRootWindow");
    unsigned long (*create)(void *, unsigned long, int, int, unsigned, unsigned, unsigned, unsigned long, unsigned long) = dlsym(x, "XCreateSimpleWindow");
    int (*store_name)(void *, unsigned long, const char *) = dlsym(x, "XStoreName");
    int (*map)(void *, unsigned long) = dlsym(x, "XMapWindow");
    int (*sync)(void *, int) = dlsym(x, "XSync");
    if (!open_display || !default_screen || !root_window || !create || !store_name || !map || !sync) { printf("Xlib is missing calls\n"); return 1; }
    void *dpy = open_display(NULL);
    if (!dpy) { printf("no X display\n"); return 1; }
    const int screen = default_screen(dpy);
    const unsigned long a = create(dpy, root_window(dpy, screen), 0, 0, 200, 150, 0, 0, 0);
    const unsigned long b = create(dpy, root_window(dpy, screen), 300, 0, 100, 80, 0, 0, 0);
    store_name(dpy, a, "twowin A");
    store_name(dpy, b, "twowin B");
    map(dpy, a);
    map(dpy, b);
    sync(dpy, 0);
    printf("windows 0x%lx 0x%lx\n", a, b);

    EGLDisplay egl = eglGetDisplay((EGLNativeDisplayType)dpy);
    if (!eglInitialize(egl, NULL, NULL)) { printf("eglInitialize failed\n"); return 1; }
    const EGLint cfg_attrs[] = { EGL_SURFACE_TYPE, EGL_WINDOW_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
                                 EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_NONE };
    EGLConfig cfg;
    EGLint n = 0;
    if (!eglChooseConfig(egl, cfg_attrs, &cfg, 1, &n) || n < 1) { printf("no EGL config\n"); return 1; }
    eglBindAPI(EGL_OPENGL_ES_API);
    EGLSurface sa = eglCreateWindowSurface(egl, cfg, (EGLNativeWindowType)a, NULL);
    EGLSurface sb = eglCreateWindowSurface(egl, cfg, (EGLNativeWindowType)b, NULL);
    if (sa == EGL_NO_SURFACE || sb == EGL_NO_SURFACE) { printf("no window surface\n"); return 1; }
    const EGLint ctx_attrs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    EGLContext ctx = eglCreateContext(egl, cfg, EGL_NO_CONTEXT, ctx_attrs);
    if (ctx == EGL_NO_CONTEXT) { printf("no context\n"); return 1; }
    for (int i = 0; i < frames; i++) {
        frame(egl, sa, ctx, 200, 150, 1.0f, 0.0f, 1.0f);
        frame(egl, sb, ctx, 100, 80, 0.0f, 1.0f, 1.0f);
    }
    printf("frames %d gl error %u\n", frames, glGetError());
    for (int s = 0; s < seconds; s++) {
        sleep(1);
        frame(egl, sa, ctx, 200, 150, 1.0f, 0.0f, 1.0f);
        frame(egl, sb, ctx, 100, 80, 0.0f, 1.0f, 1.0f);
    }
    printf("done\n");
    return 0;
}
