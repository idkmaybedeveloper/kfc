# kfc - ida pro loader for Titan M2 firmware

loads nugget-os `.ec.bin` images directly in ida pro

supported chip:
- **Titan M2** (acropora) - RISC-V 32-bit, magic `0xFFFFFFFD`

creates three segments matching the full address space:

| Segment | Perms | Description |
|---------|-------|-------------|
| `RO_A`  | r-x   | read-only firmware partition |
| `RW_A`  | r-x   | read-write firmware partition |
| `SRAM`  | rw-   | RAM placeholder (zeroed) |

## build

requires IDA SDK (submodule at `third-party/idasdk`).

```sh
git submodule update --init --recursive
cmake -B build -G Ninja
cmake --build build
```

if `IDASDK` env var is not set, cmake picks up the submodule automatically.

copy the built `kfc.dylib` / `kfc.so` / `kfc.dll` to IDA's `loaders/` directory.
