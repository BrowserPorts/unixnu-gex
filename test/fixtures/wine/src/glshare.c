/* Textures shared between two wgl contexts, as Qt's QQuickWidget and
 * QOpenGLWidget use them: context B renders into a framebuffer object whose
 * colour is a texture, and context A, which shares B's objects, draws that
 * texture into the window; A's pixels are read back. Three ways to share:
 * wglShareLists before B makes any object, wglShareLists with A's texture
 * made first (the texture made in A, rendered into from B), and
 * wglCreateContextAttribsARB with A as the share context. Then what is not
 * shared stays each context's own: B's clear colour, bound texture,
 * framebuffer binding, viewport and enables are not A's. Each prints "ok
 * NAME" or "FAIL NAME (got R,G,B)", then "N failures". Last, two threads
 * draw at once, each in its own context on its own window, and ask for
 * their own state back each time (Qt Quick's render thread beside the GUI
 * thread): what each gets is its own.
 * gex-nt-cc: clang --target=ARCH-w64-mingw32 -fuse-ld=lld -lgdi32 -lopengl32 */
#include <windows.h>
#include <GL/gl.h>
#include <stdio.h>
#include <stdlib.h>

#define GL_FRAMEBUFFER 0x8D40
#define GL_COLOR_ATTACHMENT0 0x8CE0
#define GL_FRAMEBUFFER_COMPLETE 0x8CD5
#define WGL_CONTEXT_MAJOR_VERSION_ARB 0x2091
#define WGL_CONTEXT_MINOR_VERSION_ARB 0x2092
#define WGL_CONTEXT_PROFILE_MASK_ARB 0x9126
#define WGL_CONTEXT_COMPATIBILITY_PROFILE_BIT_ARB 0x0002

#define PROC(ret, name, args) typedef ret (WINAPI *name##_t) args; static name##_t p##name;
PROC(void, glGenFramebuffers, (GLsizei, GLuint *))
PROC(void, glBindFramebuffer, (GLenum, GLuint))
PROC(void, glFramebufferTexture2D, (GLenum, GLenum, GLenum, GLuint, GLint))
PROC(GLenum, glCheckFramebufferStatus, (GLenum))
PROC(void, glDeleteFramebuffers, (GLsizei, const GLuint *))
PROC(HGLRC, wglCreateContextAttribsARB, (HDC, HGLRC, const int *))

static int failures;
static HDC dc;

static GLuint make_texture(void) {
    GLuint t;
    glGenTextures(1, &t);
    glBindTexture(GL_TEXTURE_2D, t);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 64, 64, 0, GL_RGBA, GL_UNSIGNED_BYTE, 0);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glBindTexture(GL_TEXTURE_2D, 0);
    return t;
}

/* in B: the texture cleared to the colour through a framebuffer object */
static int render_into(GLuint t, float r, float g, float b) {
    GLuint fb;
    pglGenFramebuffers(1, &fb);
    pglBindFramebuffer(GL_FRAMEBUFFER, fb);
    pglFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, t, 0);
    int complete = pglCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE;
    glViewport(0, 0, 64, 64);
    glClearColor(r, g, b, 1);
    glClear(GL_COLOR_BUFFER_BIT);
    pglBindFramebuffer(GL_FRAMEBUFFER, 0);
    pglDeleteFramebuffers(1, &fb);
    /* what Qt does before another context samples the texture */
    glFlush();
    return complete;
}

/* in A: the texture drawn over the whole window, its middle pixel read back */
static void sample(const char *name, GLuint t, int R, int G, int B) {
    glViewport(0, 0, 64, 64);
    glClearColor(0, 0, 0, 1);
    glClear(GL_COLOR_BUFFER_BIT);
    glEnable(GL_TEXTURE_2D);
    glBindTexture(GL_TEXTURE_2D, t);
    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_REPLACE);
    glBegin(GL_QUADS);
    glTexCoord2f(0, 0); glVertex2f(-1, -1);
    glTexCoord2f(1, 0); glVertex2f(1, -1);
    glTexCoord2f(1, 1); glVertex2f(1, 1);
    glTexCoord2f(0, 1); glVertex2f(-1, 1);
    glEnd();
    glDisable(GL_TEXTURE_2D);
    glBindTexture(GL_TEXTURE_2D, 0);
    unsigned char px[4] = {0};
    glReadPixels(32, 32, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, px);
    int ok = abs(px[0] - R) < 8 && abs(px[1] - G) < 8 && abs(px[2] - B) < 8;
    if (ok) printf("ok %s\n", name);
    else { printf("FAIL %s (got %d,%d,%d, want %d,%d,%d)\n", name, px[0], px[1], px[2], R, G, B); failures++; }
    fflush(stdout);
}

static void check(const char *name, int cond) {
    printf("%s %s\n", cond ? "ok" : "FAIL", name);
    fflush(stdout);
    if (!cond) failures++;
}

/* One of the drawing threads: its own window, context, viewport and clear
   colour, set, drawn and asked for 300 times. */
struct drawer { int n; HGLRC share; volatile LONG *go; int made, wrong_viewport, wrong_clear, wrong_pixel; };
static PIXELFORMATDESCRIPTOR drawer_pfd = {sizeof drawer_pfd, 1, PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER, PFD_TYPE_RGBA, 32};
static DWORD WINAPI drawer_main(void *arg) {
    struct drawer *d = arg;
    HWND w = CreateWindowExW(0, L"gex_glshare", L"gex gl share drawer", WS_POPUP, 0, 0, 64, 64, 0, 0, GetModuleHandleW(0), 0);
    HDC hdc = GetDC(w);
    SetPixelFormat(hdc, ChoosePixelFormat(hdc, &drawer_pfd), &drawer_pfd);
    HGLRC c = wglCreateContext(hdc);
    if (d->share) wglShareLists(d->share, c);
    d->made = c && wglMakeCurrent(hdc, c);
    /* Its own framebuffer object to draw and read: a host may have one
       drawable for every window (the native host's pbuffer). */
    GLuint tex = 0, fb = 0;
    if (d->made) {
        tex = make_texture();
        pglGenFramebuffers(1, &fb);
        pglBindFramebuffer(GL_FRAMEBUFFER, fb);
        pglFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, tex, 0);
    }
    InterlockedIncrement(d->go);
    while (*d->go < 2) Sleep(0);
    const float r = d->n ? 0.25f : 0.75f, g = d->n ? 0.5f : 0.125f;
    for (int i = 0; d->made && i < 300; i++) {
        const int x = d->n * 4 + (i & 1), y = d->n * 2;
        glViewport(x, y, 60 - x, 60 - y);
        glClearColor(r, g, (float)(i % 5) / 4.f, 1);
        glClear(GL_COLOR_BUFFER_BIT);
        GLint vp[4] = {0};
        GLfloat cc[4] = {0};
        glGetIntegerv(GL_VIEWPORT, vp);
        glGetFloatv(GL_COLOR_CLEAR_VALUE, cc);
        if (vp[0] != x || vp[1] != y || vp[2] != 60 - x || vp[3] != 60 - y) d->wrong_viewport++;
        if (cc[0] != r || cc[1] != g || cc[2] != (float)(i % 5) / 4.f) d->wrong_clear++;
        if (i % 10 == 0) {
            unsigned char px[4] = {0};
            glReadPixels(30, 30, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, px);
            if (abs(px[0] - (int)(r * 255)) > 8 || abs(px[1] - (int)(g * 255)) > 8) d->wrong_pixel++;
        }
    }
    if (d->made) {
        pglBindFramebuffer(GL_FRAMEBUFFER, 0);
        pglDeleteFramebuffers(1, &fb);
        glDeleteTextures(1, &tex);
    }
    wglMakeCurrent(0, 0);
    wglDeleteContext(c);
    ReleaseDC(w, hdc);
    DestroyWindow(w);
    return 0;
}

int main(void) {
    WNDCLASSW wc = {0};
    wc.style = CS_OWNDC;
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(0);
    wc.lpszClassName = L"gex_glshare";
    RegisterClassW(&wc);
    HWND w = CreateWindowExW(0, L"gex_glshare", L"gex gl share", WS_POPUP | WS_VISIBLE, 0, 0, 64, 64, 0, 0, wc.hInstance, 0);
    dc = GetDC(w);
    PIXELFORMATDESCRIPTOR pfd = {sizeof pfd, 1, PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER, PFD_TYPE_RGBA, 32};
    SetPixelFormat(dc, ChoosePixelFormat(dc, &pfd), &pfd);

    HGLRC a = wglCreateContext(dc);
    wglMakeCurrent(dc, a);
#define LOAD(name) p##name = (name##_t)wglGetProcAddress(#name)
    LOAD(glGenFramebuffers); LOAD(glBindFramebuffer); LOAD(glFramebufferTexture2D);
    LOAD(glCheckFramebufferStatus); LOAD(glDeleteFramebuffers); LOAD(wglCreateContextAttribsARB);
    if (!pglGenFramebuffers || !pglBindFramebuffer || !pglFramebufferTexture2D || !pglCheckFramebufferStatus) {
        printf("FAIL framebuffer objects: no entry points\n1 failures\n");
        return 1;
    }

    /* 1. wglShareLists(A, B) before B makes anything; the texture made in B */
    {
        HGLRC b = wglCreateContext(dc);
        check("wglShareLists(A, B)", wglShareLists(a, b));
        wglMakeCurrent(dc, b);
        GLuint t = make_texture();
        check("B's framebuffer object on its texture is complete", render_into(t, 10 / 255.f, 200 / 255.f, 30 / 255.f));
        wglMakeCurrent(dc, a);
        check("A sees B's texture name (glIsTexture)", glIsTexture(t));
        sample("A samples the texture B rendered (shared with wglShareLists)", t, 10, 200, 30);
        glDeleteTextures(1, &t);
        wglMakeCurrent(0, 0);
        wglDeleteContext(b);
        wglMakeCurrent(dc, a);
    }
    /* 2. the texture made in A, rendered into from B */
    {
        GLuint t = make_texture();
        HGLRC b = wglCreateContext(dc);
        check("wglShareLists(A, B) (A has objects)", wglShareLists(a, b));
        wglMakeCurrent(dc, b);
        check("B's framebuffer object on A's texture is complete", render_into(t, 200 / 255.f, 60 / 255.f, 20 / 255.f));
        wglMakeCurrent(dc, a);
        sample("A samples its own texture after B rendered into it", t, 200, 60, 20);
        glDeleteTextures(1, &t);
        wglMakeCurrent(0, 0);
        wglDeleteContext(b);
        wglMakeCurrent(dc, a);
    }
    /* 3. B made with A as its share context (Qt's QOpenGLContext::setShareContext) */
    if (pwglCreateContextAttribsARB) {
        const int attrs[] = {WGL_CONTEXT_MAJOR_VERSION_ARB, 3, WGL_CONTEXT_MINOR_VERSION_ARB, 0,
                             WGL_CONTEXT_PROFILE_MASK_ARB, WGL_CONTEXT_COMPATIBILITY_PROFILE_BIT_ARB, 0};
        HGLRC b = pwglCreateContextAttribsARB(dc, a, attrs);
        check("wglCreateContextAttribsARB with a share context", b != 0);
        if (b) {
            wglMakeCurrent(dc, b);
            GLuint t = make_texture();
            check("B's framebuffer object is complete (attribs share)", render_into(t, 40 / 255.f, 60 / 255.f, 210 / 255.f));
            wglMakeCurrent(dc, a);
            sample("A samples the texture B rendered (shared at creation)", t, 40, 60, 210);
            glDeleteTextures(1, &t);
            wglMakeCurrent(0, 0);
            wglDeleteContext(b);
        }
    } else check("wglCreateContextAttribsARB is there", 0);

    /* 4. state is each context's own (only objects are shared) */
    {
        wglMakeCurrent(dc, a);
        GLuint ta = make_texture();
        glClearColor(1, 0, 0, 1);
        glBindTexture(GL_TEXTURE_2D, ta);
        glViewport(1, 2, 30, 40);
        glDisable(GL_BLEND);
        GLint bound0 = 0, vp0[4] = {0};
        glGetIntegerv(GL_TEXTURE_BINDING_2D, &bound0);
        glGetIntegerv(GL_VIEWPORT, vp0);
        printf("  A before: texture %d (made %u), viewport %d,%d,%d,%d\n", bound0, ta, vp0[0], vp0[1], vp0[2], vp0[3]);
        HGLRC b = wglCreateContext(dc);
        wglShareLists(a, b);
        wglMakeCurrent(dc, b);
        GLuint tb = make_texture(), fb;
        glClearColor(0, 1, 0, 1);
        glBindTexture(GL_TEXTURE_2D, tb);
        glViewport(5, 6, 7, 8);
        glEnable(GL_BLEND);
        pglGenFramebuffers(1, &fb);
        pglBindFramebuffer(GL_FRAMEBUFFER, fb);
        pglFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, tb, 0);
        wglMakeCurrent(dc, a);
        float cc[4] = {0};
        GLint bound = 0, fbo = -1, vp[4] = {0};
        glGetFloatv(GL_COLOR_CLEAR_VALUE, cc);
        glGetIntegerv(GL_TEXTURE_BINDING_2D, &bound);
        glGetIntegerv(0x8CA6 /* GL_DRAW_FRAMEBUFFER_BINDING */, &fbo);
        glGetIntegerv(GL_VIEWPORT, vp);
        printf("  A after: texture %d, viewport %d,%d,%d,%d, framebuffer %d\n", bound, vp[0], vp[1], vp[2], vp[3], fbo);
        check("A's clear colour is its own after B set one", cc[0] == 1 && cc[1] == 0);
        check("A's bound texture is its own after B bound one", bound == (GLint)ta);
        check("A's framebuffer binding is its own after B bound an FBO", fbo == 0);
        check("A's viewport is its own after B set one", vp[0] == 1 && vp[1] == 2 && vp[2] == 30 && vp[3] == 40);
        check("A's blend enable is its own after B enabled it", !glIsEnabled(GL_BLEND));
        wglMakeCurrent(dc, b);
        pglBindFramebuffer(GL_FRAMEBUFFER, 0);
        pglDeleteFramebuffers(1, &fb);
        glDeleteTextures(1, &tb);
        wglMakeCurrent(dc, a);
        glDeleteTextures(1, &ta);
        wglMakeCurrent(0, 0);
        wglDeleteContext(b);
    }

    /* 5. B current on a window never shown (Qt's QOffscreenSurface on
       Windows is a hidden window), rendering into its framebuffer object */
    {
        HWND hidden = CreateWindowExW(0, L"gex_glshare", L"gex gl share hidden", WS_POPUP, 0, 0, 64, 64, 0, 0, wc.hInstance, 0);
        HDC hdc = GetDC(hidden);
        SetPixelFormat(hdc, ChoosePixelFormat(hdc, &pfd), &pfd);
        wglMakeCurrent(dc, a);
        HGLRC b = wglCreateContext(hdc);
        check("wglShareLists(A, B on a hidden window)", wglShareLists(a, b));
        check("B made current on the hidden window", wglMakeCurrent(hdc, b));
        GLuint t = make_texture();
        check("B's framebuffer object is complete (hidden window)", render_into(t, 220 / 255.f, 200 / 255.f, 40 / 255.f));
        wglMakeCurrent(dc, a);
        sample("A samples the texture B rendered on a hidden window", t, 220, 200, 40);
        glDeleteTextures(1, &t);
        wglMakeCurrent(0, 0);
        wglDeleteContext(b);
        ReleaseDC(hidden, hdc);
        DestroyWindow(hidden);
    }

    /* 6. two threads drawing at once, each with its own context */
    {
        wglMakeCurrent(0, 0);
        volatile LONG go = 0;
        struct drawer d[2] = {{0, a, &go}, {1, a, &go}};
        HANDLE t[2];
        for (int i = 0; i < 2; i++) t[i] = CreateThread(0, 0, drawer_main, &d[i], 0, 0);
        WaitForMultipleObjects(2, t, TRUE, 120000);
        for (int i = 0; i < 2; i++) {
            char name[160];
            printf("  thread %d: viewport wrong %d, clear colour wrong %d, pixel wrong %d of 300/300/30\n",
                   i, d[i].wrong_viewport, d[i].wrong_clear, d[i].wrong_pixel);
            snprintf(name, sizeof name, "thread %d's context made current", i);
            check(name, d[i].made);
            snprintf(name, sizeof name, "thread %d gets its own state back while the other draws", i);
            check(name, d[i].made && !d[i].wrong_viewport && !d[i].wrong_clear);
            snprintf(name, sizeof name, "thread %d reads its own framebuffer's pixels", i);
            check(name, d[i].made && !d[i].wrong_pixel);
            CloseHandle(t[i]);
        }
    }

    wglMakeCurrent(0, 0);
    wglDeleteContext(a);
    printf("%d failures\n", failures);
    return failures != 0;
}
