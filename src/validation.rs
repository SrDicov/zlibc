//! D5 gate: hello + pthreads + malloc/stdio running *together*.
//!
//! One integration test (serial step — it clones real threads): two of
//! our threads format per-thread messages with our `snprintf` into our
//! `malloc`'d buffers and push them through our `socketpair`, while the
//! parent joins, reads back, and checks every byte. If allocation,
//! formatting, threads, and fds interoperate, the wave-4 gate holds.

use core::ffi::{c_char, c_int, c_void};
use core::ptr::{addr_of_mut, null_mut};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::abi::PthreadT;
use crate::malloc::{free, malloc};
use crate::net::{recvfrom, sendto, socketpair, AF_UNIX, SOCK_STREAM};
use crate::thread::create::{__pthread_create, __pthread_join};

extern "C" {
    fn snprintf(s: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
}

static GOT0: AtomicUsize = AtomicUsize::new(0);
static GOT1: AtomicUsize = AtomicUsize::new(0);

/// Child code: format, send, release. Pure our-ABI calls only — never
/// touches host TLS (its `FS` is our TCB) and never asserts.
unsafe extern "C" fn hello_child(arg: *mut c_void) -> *mut c_void {
    unsafe {
        let slot = arg as *mut c_int;
        let id = *slot;
        let fd = *slot.add(1);
        let sum: c_int = (0..100).sum();
        let buf = malloc(64) as *mut c_char;
        if buf.is_null() {
            return null_mut();
        }
        let n = snprintf(buf, 64, c"t%d=%d".as_ptr(), id, sum);
        if n > 0 {
            sendto(fd, buf as *const c_void, n as usize, 0, null_mut(), 0);
        }
        free(buf as *mut c_void);
        if id == 0 {
            GOT0.store(n as usize, Ordering::SeqCst);
        } else {
            GOT1.store(n as usize, Ordering::SeqCst);
        }
        null_mut()
    }
}

unsafe fn read_all(fd: c_int, out: &mut [u8]) -> usize {
    unsafe {
        let mut got = 0usize;
        while got < out.len() {
            let r = recvfrom(
                fd,
                out.as_mut_ptr().add(got) as *mut c_void,
                out.len() - got,
                0,
                null_mut(),
                null_mut(),
            );
            if r <= 0 {
                break;
            }
            got += r as usize;
        }
        got
    }
}

unsafe fn close_fd(fd: c_int) {
    unsafe {
        use crate::syscall::{syscall3, syscall_ret};
        const SYS_CLOSE: usize = 3;
        let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
    }
}

/// The wave-4 gate as one executable sentence. Serial step: clones.
#[cfg(target_arch = "x86_64")]
#[test]
fn hello_threads_malloc_stdio_interoperate() {
    unsafe {
        let mut results = [0 as c_int; 4]; // (id0, fd0, id1, fd1)
        let mut pair0 = [0 as c_int; 2];
        let mut pair1 = [0 as c_int; 2];
        assert_eq!(socketpair(AF_UNIX, SOCK_STREAM, 0, pair0.as_mut_ptr()), 0);
        assert_eq!(socketpair(AF_UNIX, SOCK_STREAM, 0, pair1.as_mut_ptr()), 0);
        results[0] = 0;
        results[1] = pair0[1];
        results[2] = 1;
        results[3] = pair1[1];
        let mut t0: PthreadT = null_mut();
        let mut t1: PthreadT = null_mut();
        let base = addr_of_mut!(results).cast::<c_int>();
        assert_eq!(
            __pthread_create(&mut t0, null_mut(), Some(hello_child), base as *mut c_void),
            0
        );
        assert_eq!(
            __pthread_create(
                &mut t1,
                null_mut(),
                Some(hello_child),
                base.add(2) as *mut c_void
            ),
            0
        );
        assert_eq!(__pthread_join(t0, null_mut()), 0);
        assert_eq!(__pthread_join(t1, null_mut()), 0);
        // Both children formatted "t{id}=4950" (5 bytes each).
        assert_eq!(GOT0.load(Ordering::SeqCst), 7);
        assert_eq!(GOT1.load(Ordering::SeqCst), 7);
        close_fd(pair0[1]);
        close_fd(pair1[1]);
        let mut m0 = [0u8; 8];
        let mut m1 = [0u8; 8];
        assert_eq!(read_all(pair0[0], &mut m0), 7);
        assert_eq!(read_all(pair1[0], &mut m1), 7);
        assert_eq!(&m0[..7], b"t0=4950");
        assert_eq!(&m1[..7], b"t1=4950");
        close_fd(pair0[0]);
        close_fd(pair1[0]);
    }
}
