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

#define E(n, v) printf(#n " %lu\n", (unsigned long)(v))

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
	return 0;
}
