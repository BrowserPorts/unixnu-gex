/* DirectWrite glyph pixels, as programs that draw their own text get them
 * (CreateGlyphRunAnalysis, CreateAlphaTexture): "W" in the system set's
 * Tahoma, and in the same font file from memory (an in-memory loader's
 * file, as a program that ships its fonts makes), its bytes on the heap and
 * in zeroed static data. Each must have lit pixels, and the same count. */
#define COBJMACROS
#include <windows.h>
#include <initguid.h>
#include <dwrite_3.h>
#include <stdio.h>
#include <string.h>

static IDWriteFactory5 *factory;
static char zeroed[4 << 20];

/* The lit pixels of "W" at 32 px in `face`, -1 on a failure (said). */
static int lit(const char *what, IDWriteFontFace *face)
{
    DWRITE_GLYPH_RUN run = { 0 };
    IDWriteGlyphRunAnalysis *ga;
    UINT32 cp = 'W';
    UINT16 glyph = 0;
    FLOAT adv = 0;
    RECT r;
    BYTE *px;
    HRESULT hr;
    int n = 0, i, size;

    if (FAILED(hr = IDWriteFontFace_GetGlyphIndices(face, &cp, 1, &glyph)) || !glyph)
    {
        printf("glyphs: %s: no glyph (%#lx)\n", what, hr);
        return -1;
    }
    run.fontFace = face;
    run.fontEmSize = 32;
    run.glyphCount = 1;
    run.glyphIndices = &glyph;
    run.glyphAdvances = &adv;
    if (FAILED(hr = IDWriteFactory_CreateGlyphRunAnalysis((IDWriteFactory *)factory, &run, 1.0f, NULL, DWRITE_RENDERING_MODE_NATURAL,
            DWRITE_MEASURING_MODE_NATURAL, 0, 0, &ga)))
    {
        printf("glyphs: %s: CreateGlyphRunAnalysis %#lx\n", what, hr);
        return -1;
    }
    IDWriteGlyphRunAnalysis_GetAlphaTextureBounds(ga, DWRITE_TEXTURE_CLEARTYPE_3x1, &r);
    size = (r.right - r.left) * (r.bottom - r.top) * 3;
    if (size <= 0 || !(px = calloc(1, size)))
    {
        printf("glyphs: %s: empty bounds %ld,%ld-%ld,%ld\n", what, r.left, r.top, r.right, r.bottom);
        IDWriteGlyphRunAnalysis_Release(ga);
        return -1;
    }
    if (FAILED(hr = IDWriteGlyphRunAnalysis_CreateAlphaTexture(ga, DWRITE_TEXTURE_CLEARTYPE_3x1, &r, px, size)))
        printf("glyphs: %s: CreateAlphaTexture %#lx\n", what, hr), n = -1;
    else
        for (i = 0; i < size; i++) n += px[i] != 0;
    free(px);
    IDWriteGlyphRunAnalysis_Release(ga);
    return n;
}

/* `bytes` as a file of an in-memory loader, its first face's lit pixels. */
static int from_memory(const char *what, IDWriteInMemoryFontFileLoader *mem, void *bytes, UINT32 size)
{
    IDWriteFontFile *file;
    IDWriteFontFace *face;
    int n = -1;

    if (FAILED(IDWriteInMemoryFontFileLoader_CreateInMemoryFontFileReference(mem, (IDWriteFactory *)factory, bytes, size, NULL, &file)))
    {
        printf("glyphs: %s: no file reference\n", what);
        return -1;
    }
    if (SUCCEEDED(IDWriteFactory5_CreateFontFace(factory, DWRITE_FONT_FACE_TYPE_TRUETYPE, 1, &file, 0, DWRITE_FONT_SIMULATIONS_NONE, &face)))
    {
        n = lit(what, face);
        IDWriteFontFace_Release(face);
    }
    else printf("glyphs: %s: no face\n", what);
    IDWriteFontFile_Release(file);
    return n;
}

int main(int argc, char **argv)
{
    IDWriteInMemoryFontFileLoader *mem;
    IDWriteFontFaceReference *ref;
    IDWriteFontFileStream *stream;
    IDWriteFontFileLoader *loader;
    IDWriteFontSet *sys, *got;
    IDWriteFontFace3 *face3;
    IDWriteFontFile *file;
    const void *key, *frag;
    UINT32 keysize, size = 0;
    UINT64 len;
    void *ctx, *heap = NULL;
    int sysn = -1, heapn = -1, statn = -1;

    if (FAILED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_ISOLATED, &IID_IDWriteFactory5, (IUnknown **)&factory)))
        return 1;
    IDWriteFactory5_GetSystemFontSet(factory, &sys);
    if (FAILED(IDWriteFontSet_GetMatchingFonts_(sys, L"Tahoma", DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
            DWRITE_FONT_STYLE_NORMAL, &got)) || FAILED(IDWriteFontSet_GetFontFaceReference(got, 0, &ref)))
    {
        printf("glyphs: no Tahoma\n");
        return 1;
    }
    if (SUCCEEDED(IDWriteFontFaceReference_CreateFontFace(ref, &face3)))
    {
        sysn = lit("system", (IDWriteFontFace *)face3);
        IDWriteFontFace3_Release(face3);
    }
    /* its file's bytes */
    if (SUCCEEDED(IDWriteFontFaceReference_GetFontFile(ref, &file)) && SUCCEEDED(IDWriteFontFile_GetReferenceKey(file, &key, &keysize))
            && SUCCEEDED(IDWriteFontFile_GetLoader(file, &loader))
            && SUCCEEDED(IDWriteFontFileLoader_CreateStreamFromKey(loader, key, keysize, &stream))
            && SUCCEEDED(IDWriteFontFileStream_GetFileSize(stream, &len))
            && SUCCEEDED(IDWriteFontFileStream_ReadFileFragment(stream, &frag, 0, len, &ctx)))
    {
        if (len <= sizeof(zeroed) && (heap = malloc(len)))
        {
            memcpy(heap, frag, len);
            memcpy(zeroed, frag, len);
            size = len;
        }
        IDWriteFontFileStream_ReleaseFileFragment(stream, ctx);
    }
    if (heap && SUCCEEDED(IDWriteFactory5_CreateInMemoryFontFileLoader(factory, &mem)))
    {
        IDWriteFactory5_RegisterFontFileLoader(factory, (IDWriteFontFileLoader *)mem);
        heapn = from_memory("heap", mem, heap, size);
        statn = from_memory("static", mem, zeroed, size);
    }
    printf("glyphs: system %d heap %d static %d\n", sysn, heapn, statn);
    if (sysn > 0 && heapn == sysn && statn == sysn)
        printf("glyphs ok\n");
    return 0;
}
