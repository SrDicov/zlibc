/* Probe: measures musl's real struct sizes/offsets with the C
 * compiler and prints them as `NAME decimal` lines. build.rs runs
 * this and turns the output into Rust constants (abi_probed.rs),
 * which lib.rs static-asserts against the #[repr(C)] mirrors.
 *
 * KEEP IN SYNC: every field of abi::IoFile / abi::PthreadHead in
 * src/abi.rs must have a line here, and vice versa.
 */
#include <stdio.h>
#include <stddef.h>
#include <locale.h> /* locale_t, needed by pthread_impl.h */
#include "stdio_impl.h" /* struct _IO_FILE definition (public stdio.h only forward-declares it) */
#include "pthread_impl.h"
#include <pthread.h> /* pthread_t (already pulled in via pthread_impl.h; explicit here for the SIZE_PTHREAD_T probe) */
#include <elf.h> /* Elf64_* file structures for the ldso probes */
#include <link.h> /* Elf_Symndx (arch/generic/bits/link.h:1) for the dso probe */
#include <stdint.h> /* uint32_t/int16_t/uintptr_t for the dso probe */
#include <sys/types.h> /* dev_t/ino_t for the dso probe */
#include <sys/stat.h> /* struct stat: the loader's (st_dev, st_ino) dedup key */
#include "libc.h" /* struct tls_module (src/internal/libc.h:14-18) for the dso probe */
#include <netdb.h> /* struct addrinfo (Ola 10) */
#include <netinet/in.h> /* struct sockaddr_in/in6 (Ola 10) */
#include <pwd.h> /* struct passwd (Ola 10) */
#include <grp.h> /* struct group (Ola 10) */
#include <shadow.h> /* struct spwd (Ola 10) */
#include <sys/resource.h> /* struct rlimit/rusage (Ola 10) */
#include <sys/utsname.h> /* struct utsname (Ola 10) */
#include <sys/sysinfo.h> /* struct sysinfo (Ola 10) */
#include <sys/msg.h> /* struct msqid_ds (Ola 10) */
#include <sys/shm.h> /* struct shmid_ds (Ola 10) */
#include <sys/sem.h> /* struct semid_ds (Ola 10) */
#include <mqueue.h> /* struct mq_attr (Ola 10) */
#include <pthread.h> /* pthread_rwlock_t/barrier_t/spinlock_t/attr (Ola 11A) */
#include <semaphore.h> /* sem_t (Ola 11A) */

#define E(n, v) printf(#n " %lu\n", (unsigned long)(v))

/* Layout mirror of musl `struct dso` (ldso/dynlink.c:67-121, x86_64 with
 * DL_FDPIC=0: `base` first, `loadmap` pointer at tail). Field types and
 * order match musl exactly so gcc lays this out identically; the probe
 * prints the real C sizeof/offsets and lib.rs asserts the Rust mirror
 * (src/ldso/dso.rs) against them. The C `buf[]` flex tail is omitted
 * (adds 0 to sizeof). LIMIT: `struct dso` itself is static to
 * dynlink.c, so this mirror cannot name it; if musl adds, removes, or
 * reorders a field, update this struct AND src/ldso/dso.rs together.
 */
struct td_index;
struct fdpic_loadmap;
struct zlibc_dso {
	unsigned char *base;
	char *name;
	size_t *dynv;
	struct zlibc_dso *next, *prev;
	Elf64_Phdr *phdr;
	int phnum;
	size_t phentsize;
	Elf64_Sym *syms;
	Elf_Symndx *hashtab;
	uint32_t *ghashtab;
	int16_t *versym;
	char *strings;
	struct zlibc_dso *syms_next, *lazy_next;
	size_t *lazy, lazy_cnt;
	unsigned char *map;
	size_t map_len;
	dev_t dev;
	ino_t ino;
	char relocated, constructed, kernel_mapped, mark, bfs_built, runtime_loaded;
	struct zlibc_dso **deps, *needed_by;
	size_t ndeps_direct, next_dep;
	pthread_t ctor_visitor;
	char *rpath_orig, *rpath;
	struct tls_module tls;
	size_t tls_id, relro_start, relro_end;
	uintptr_t *new_dtv;
	unsigned char *new_tls;
	struct td_index *td_index;
	struct zlibc_dso *fini_next;
	char *shortname;
	struct fdpic_loadmap *loadmap;
	struct zlibc_funcdesc { void *addr; size_t *got; } *funcdescs;
	size_t *got;
};

int main(void)
{
	E(SIZE_IOFILE, sizeof(struct _IO_FILE));
	E(OFF_IOFILE_FLAGS, offsetof(struct _IO_FILE, flags));
	E(OFF_IOFILE_RPOS, offsetof(struct _IO_FILE, rpos));
	E(OFF_IOFILE_REND, offsetof(struct _IO_FILE, rend));
	E(OFF_IOFILE_CLOSE, offsetof(struct _IO_FILE, close));
	E(OFF_IOFILE_WEND, offsetof(struct _IO_FILE, wend));
	E(OFF_IOFILE_WPOS, offsetof(struct _IO_FILE, wpos));
	E(OFF_IOFILE_MUSTBEZERO_1, offsetof(struct _IO_FILE, mustbezero_1));
	E(OFF_IOFILE_WBASE, offsetof(struct _IO_FILE, wbase));
	E(OFF_IOFILE_READ, offsetof(struct _IO_FILE, read));
	E(OFF_IOFILE_WRITE, offsetof(struct _IO_FILE, write));
	E(OFF_IOFILE_SEEK, offsetof(struct _IO_FILE, seek));
	E(OFF_IOFILE_BUF, offsetof(struct _IO_FILE, buf));
	E(OFF_IOFILE_BUF_SIZE, offsetof(struct _IO_FILE, buf_size));
	E(OFF_IOFILE_PREV, offsetof(struct _IO_FILE, prev));
	E(OFF_IOFILE_NEXT, offsetof(struct _IO_FILE, next));
	E(OFF_IOFILE_FD, offsetof(struct _IO_FILE, fd));
	E(OFF_IOFILE_PIPE_PID, offsetof(struct _IO_FILE, pipe_pid));
	E(OFF_IOFILE_LOCKCOUNT, offsetof(struct _IO_FILE, lockcount));
	E(OFF_IOFILE_MODE, offsetof(struct _IO_FILE, mode));
	E(OFF_IOFILE_LOCK, offsetof(struct _IO_FILE, lock));
	E(OFF_IOFILE_LBF, offsetof(struct _IO_FILE, lbf));
	E(OFF_IOFILE_COOKIE, offsetof(struct _IO_FILE, cookie));
	E(OFF_IOFILE_OFF, offsetof(struct _IO_FILE, off));
	E(OFF_IOFILE_GETLN_BUF, offsetof(struct _IO_FILE, getln_buf));
	E(OFF_IOFILE_MUSTBEZERO_2, offsetof(struct _IO_FILE, mustbezero_2));
	E(OFF_IOFILE_SHEND, offsetof(struct _IO_FILE, shend));
	E(OFF_IOFILE_SHLIM, offsetof(struct _IO_FILE, shlim));
	E(OFF_IOFILE_SHCNT, offsetof(struct _IO_FILE, shcnt));
	E(OFF_IOFILE_PREV_LOCKED, offsetof(struct _IO_FILE, prev_locked));
	E(OFF_IOFILE_NEXT_LOCKED, offsetof(struct _IO_FILE, next_locked));
	E(OFF_IOFILE_LOCALE, offsetof(struct _IO_FILE, locale));

	/* struct pthread Part 1 only (Part 2 is explicitly non-ABI). */
	E(SIZE_PTHREAD_P1, offsetof(struct pthread, canary) + sizeof(((struct pthread *)0)->canary));
	E(OFF_PTHREAD_SELF, offsetof(struct pthread, self));
	E(OFF_PTHREAD_DTV, offsetof(struct pthread, dtv));
	E(OFF_PTHREAD_SYSINFO, offsetof(struct pthread, sysinfo));
	E(OFF_PTHREAD_CANARY, offsetof(struct pthread, canary));

	/* pthread_t (include/alltypes.h.in: struct __pthread * on x86_64). */
	E(SIZE_PTHREAD_T, sizeof(pthread_t));

	/* pthread_mutex_t overlay (src/internal/pthread_impl.h:86-91). */
	E(SIZE_MUTEX, sizeof(pthread_mutex_t));
	E(OFF_M_TYPE, (size_t)&((pthread_mutex_t *)0)->_m_type);
	E(OFF_M_LOCK, (size_t)&((pthread_mutex_t *)0)->_m_lock);
	E(OFF_M_WAITERS, (size_t)&((pthread_mutex_t *)0)->_m_waiters);
	E(OFF_M_COUNT, (size_t)&((pthread_mutex_t *)0)->_m_count);

	/* pthread_cond_t overlay (src/internal/pthread_impl.h:92-97). */
	E(SIZE_COND, sizeof(pthread_cond_t));
	E(OFF_C_SEQ, (size_t)&((pthread_cond_t *)0)->_c_seq);
	E(OFF_C_WAITERS, (size_t)&((pthread_cond_t *)0)->_c_waiters);
	E(OFF_C_CLOCK, (size_t)&((pthread_cond_t *)0)->_c_clock);
	E(OFF_C_LOCK, (size_t)&((pthread_cond_t *)0)->_c_lock);

	/* ELF64 file structures (include/elf.h) for src/ldso/mod.rs. */
	E(SIZE_ELF64_EHDR, sizeof(Elf64_Ehdr));
	E(SIZE_ELF64_PHDR, sizeof(Elf64_Phdr));
	E(SIZE_ELF64_DYN, sizeof(Elf64_Dyn));
	E(SIZE_ELF64_SYM, sizeof(Elf64_Sym));
	E(OFF_ELF64_SYM_ST_NAME, offsetof(Elf64_Sym, st_name));
	E(OFF_ELF64_SYM_ST_INFO, offsetof(Elf64_Sym, st_info));
	E(OFF_ELF64_SYM_ST_OTHER, offsetof(Elf64_Sym, st_other));
	E(OFF_ELF64_SYM_ST_SHNDX, offsetof(Elf64_Sym, st_shndx));
	E(OFF_ELF64_SYM_ST_VALUE, offsetof(Elf64_Sym, st_value));
	E(OFF_ELF64_SYM_ST_SIZE, offsetof(Elf64_Sym, st_size));

	/* struct tls_module (src/internal/libc.h:14-18) for TlsModule. */
	E(SIZE_TLS_MODULE, sizeof(struct tls_module));
	E(OFF_TLS_MODULE_NEXT, offsetof(struct tls_module, next));
	E(OFF_TLS_MODULE_IMAGE, offsetof(struct tls_module, image));
	E(OFF_TLS_MODULE_LEN, offsetof(struct tls_module, len));
	E(OFF_TLS_MODULE_SIZE, offsetof(struct tls_module, size));
	E(OFF_TLS_MODULE_ALIGN, offsetof(struct tls_module, align));
	E(OFF_TLS_MODULE_OFFSET, offsetof(struct tls_module, offset));

	/* struct dso mirror above, for Dso in src/ldso/dso.rs. */
	E(SIZE_DSO, sizeof(struct zlibc_dso));
	E(OFF_DSO_BASE, offsetof(struct zlibc_dso, base));
	E(OFF_DSO_NAME, offsetof(struct zlibc_dso, name));
	E(OFF_DSO_DYNV, offsetof(struct zlibc_dso, dynv));
	E(OFF_DSO_NEXT, offsetof(struct zlibc_dso, next));
	E(OFF_DSO_PREV, offsetof(struct zlibc_dso, prev));
	E(OFF_DSO_PHDR, offsetof(struct zlibc_dso, phdr));
	E(OFF_DSO_PHNUM, offsetof(struct zlibc_dso, phnum));
	E(OFF_DSO_PHENTSIZE, offsetof(struct zlibc_dso, phentsize));
	E(OFF_DSO_SYMS, offsetof(struct zlibc_dso, syms));
	E(OFF_DSO_HASHTAB, offsetof(struct zlibc_dso, hashtab));
	E(OFF_DSO_GHASHTAB, offsetof(struct zlibc_dso, ghashtab));
	E(OFF_DSO_VERSYM, offsetof(struct zlibc_dso, versym));
	E(OFF_DSO_STRINGS, offsetof(struct zlibc_dso, strings));
	E(OFF_DSO_SYMS_NEXT, offsetof(struct zlibc_dso, syms_next));
	E(OFF_DSO_LAZY_NEXT, offsetof(struct zlibc_dso, lazy_next));
	E(OFF_DSO_LAZY, offsetof(struct zlibc_dso, lazy));
	E(OFF_DSO_LAZY_CNT, offsetof(struct zlibc_dso, lazy_cnt));
	E(OFF_DSO_MAP, offsetof(struct zlibc_dso, map));
	E(OFF_DSO_MAP_LEN, offsetof(struct zlibc_dso, map_len));
	E(OFF_DSO_DEV, offsetof(struct zlibc_dso, dev));
	E(OFF_DSO_INO, offsetof(struct zlibc_dso, ino));
	E(OFF_DSO_RELOCATED, offsetof(struct zlibc_dso, relocated));
	E(OFF_DSO_CONSTRUCTED, offsetof(struct zlibc_dso, constructed));
	E(OFF_DSO_KERNEL_MAPPED, offsetof(struct zlibc_dso, kernel_mapped));
	E(OFF_DSO_MARK, offsetof(struct zlibc_dso, mark));
	E(OFF_DSO_BFS_BUILT, offsetof(struct zlibc_dso, bfs_built));
	E(OFF_DSO_RUNTIME_LOADED, offsetof(struct zlibc_dso, runtime_loaded));
	E(OFF_DSO_DEPS, offsetof(struct zlibc_dso, deps));
	E(OFF_DSO_NEEDED_BY, offsetof(struct zlibc_dso, needed_by));
	E(OFF_DSO_NDEPS_DIRECT, offsetof(struct zlibc_dso, ndeps_direct));
	E(OFF_DSO_NEXT_DEP, offsetof(struct zlibc_dso, next_dep));
	E(OFF_DSO_CTOR_VISITOR, offsetof(struct zlibc_dso, ctor_visitor));
	E(OFF_DSO_RPATH_ORIG, offsetof(struct zlibc_dso, rpath_orig));
	E(OFF_DSO_RPATH, offsetof(struct zlibc_dso, rpath));
	E(OFF_DSO_TLS, offsetof(struct zlibc_dso, tls));
	E(OFF_DSO_TLS_ID, offsetof(struct zlibc_dso, tls_id));
	E(OFF_DSO_RELRO_START, offsetof(struct zlibc_dso, relro_start));
	E(OFF_DSO_RELRO_END, offsetof(struct zlibc_dso, relro_end));
	E(OFF_DSO_NEW_DTV, offsetof(struct zlibc_dso, new_dtv));
	E(OFF_DSO_NEW_TLS, offsetof(struct zlibc_dso, new_tls));
	E(OFF_DSO_TD_INDEX, offsetof(struct zlibc_dso, td_index));
	E(OFF_DSO_FINI_NEXT, offsetof(struct zlibc_dso, fini_next));
	E(OFF_DSO_SHORTNAME, offsetof(struct zlibc_dso, shortname));
	E(OFF_DSO_LOADMAP, offsetof(struct zlibc_dso, loadmap));
	E(OFF_DSO_FUNCDESCS, offsetof(struct zlibc_dso, funcdescs));
	E(OFF_DSO_GOT, offsetof(struct zlibc_dso, got));
	E(OFF_STAT_DEV, offsetof(struct stat, st_dev));
	E(OFF_STAT_INO, offsetof(struct stat, st_ino));
	E(SIZE_ADDRINFO, sizeof(struct addrinfo));
	E(OFF_ADDRINFO_ADDR, offsetof(struct addrinfo, ai_addr));
	E(SIZE_SOCKADDR_IN, sizeof(struct sockaddr_in));
	E(OFF_SOCKADDR_IN_ADDR, offsetof(struct sockaddr_in, sin_addr));
	E(SIZE_SOCKADDR_IN6, sizeof(struct sockaddr_in6));
	E(OFF_SOCKADDR_IN6_ADDR, offsetof(struct sockaddr_in6, sin6_addr));
	E(SIZE_PASSWD, sizeof(struct passwd));
	E(OFF_PASSWD_NAME, offsetof(struct passwd, pw_name));
	E(OFF_PASSWD_UID, offsetof(struct passwd, pw_uid));
	E(SIZE_GROUP, sizeof(struct group));
	E(OFF_GROUP_NAME, offsetof(struct group, gr_name));
	E(OFF_GROUP_GID, offsetof(struct group, gr_gid));
	E(SIZE_SPWD, sizeof(struct spwd));
	E(OFF_SPWD_NAME, offsetof(struct spwd, sp_namp));
	E(SIZE_RLIMIT, sizeof(struct rlimit));
	E(OFF_RLIMIT_MAX, offsetof(struct rlimit, rlim_max));
	E(SIZE_RUSAGE, sizeof(struct rusage));
	E(OFF_RUSAGE_MAXRSS, offsetof(struct rusage, ru_maxrss));
	E(SIZE_UTSNAME, sizeof(struct utsname));
	E(OFF_UTSNAME_RELEASE, offsetof(struct utsname, release));
	E(SIZE_SYSINFO, sizeof(struct sysinfo));
	E(OFF_SYSINFO_TOTALRAM, offsetof(struct sysinfo, totalram));
	E(OFF_SYSINFO_MEMUNIT, offsetof(struct sysinfo, mem_unit));
	E(SIZE_MSQID_DS, sizeof(struct msqid_ds));
	E(SIZE_SHMID_DS, sizeof(struct shmid_ds));
	E(SIZE_SEMID_DS, sizeof(struct semid_ds));
	E(SIZE_MQ_ATTR, sizeof(struct mq_attr));
	E(OFF_MQ_ATTR_MSGSIZE, offsetof(struct mq_attr, mq_msgsize));
	E(SIZE_RWLOCK, sizeof(pthread_rwlock_t));
	E(SIZE_RWLOCKATTR, sizeof(pthread_rwlockattr_t));
	E(SIZE_BARRIER, sizeof(pthread_barrier_t));
	E(SIZE_SPIN, sizeof(pthread_spinlock_t));
	E(SIZE_SEM, sizeof(sem_t));
	return 0;
}
