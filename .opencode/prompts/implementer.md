Implement `src/<subsystem>/<file>.c` -> `src/<subsystem>/<file>.rs`.
Mechanical C-to-Rust only: raw pointers *mut T/*const T, wrapping arithmetic,
exact integer promotions, pointer arithmetic * element size, syscall_cp vs syscall ordering.
Run `cargo check` on the single flat crate after each file and fix until zero errors.
