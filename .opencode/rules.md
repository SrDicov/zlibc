# zlibc agent rules

Single flat crate: hard #![no_std], no unstable features, no crate splitting.
Only one module subtree is editable by a given worktree.

ABI truth: freeze types in src/abi; ABI items are pthread*, jmp_buf, sigset_t,
sigaction, stat, dirent, termios, iovec, pollfd. FILE and Dso are internal.

Every ported file must pass cargo check before commit. Every commit is atomic:
port(subsys): file.c (N/1650 syms).

weak_alias!(new_alias, strong_symbol) uses reverse order from musl. Static mut
targets of a weak alias cannot be zero/null (otherwise COMMON).

errno/TLS: never dereference %fs:0 without FS_BASE helpers; cold boot paths
must remain pre-reloc safe.
