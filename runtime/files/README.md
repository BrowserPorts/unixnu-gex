# page

The `@gexemu/runtime` package (`runtime/`, `runtime/README.md`, built by
`make runtime PKG=DIR` with the tools `package.json` names), the internal
modules it is made of (`runtime/src/`), and the builds of what it loads into
`public/`:

- the browser shim, the shared kernel module and the seed, from
  `hosts/browser` and `hosts/kernel` (`build-assets.sh`);
- Mesa for wasm32, from the `third_party/mesa` submodule. It draws through
  Gallium's `gex_wgpu` driver on the browser's WebGPU. A guest's GL calls
  reach it through `guest/gl` and `ports/mesa/src/gexgl-mesa.cpp`
  (`build-mesa-wasm.sh`);
- Xwayland as wasm32, which runs in a Worker of the page and talks to
  `hosts/hostwl` (`build-xwayland-wasm.sh`);
- the guest root filesystems come from the debdemo repository, which
  writes them into `runtime/files/out/rootfs`.

A page imports the package and decides how its files arrive
(`runtime/README.md`). gex's own pages, the app library an ejected
program ships and its sites are built over these files too
(`runtime/app/README.md`).

## The two builds

| build | threads | hosting |
|-------|---------|---------|
| multi-process (default) | each guest thread is a Worker on shared memory | needs COOP/COEP (SharedArrayBuffer) |
| single-thread | every guest thread is a fiber in one Worker | any static host |

Both builds load the same shim, kernel and seed. Each builds its own Mesa
and Xwayland, with or without `-pthread`.

```console
$ make assets                    # the shim, kernel, seed and providers
$ make mesa                      # Mesa for the multi-process build (FLAVOUR=--sp, --both)
$ make xwayland                  # Xwayland, the same
$ make runtime PKG=DIR           # the package (runtime/build.sh; --single for the single-thread one)
```

`runtime/files/build.sh` runs them together. Its header lists the steps and the
options for building one part alone. Mesa comes from the
`third_party/mesa` submodule, which `make mesa` checks out.

The first Mesa build also builds Tint (`tint/build-tint.sh`), so it takes
much longer than later ones.
