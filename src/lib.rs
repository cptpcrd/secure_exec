//! This crate provides an easy way to check if the current process requires "secure exection",
//! meaning it was started as set-UID, set-GID, or (on Linux) with file capabilities.
//!
//! Sample usage:
//!
//! ```
//! if secure_exec::is_secure() {
//!     println!("started set-UID/set-GID/with file capabilities");
//! } else {
//!     println!("NOT started set-UID/set-GID/with file capabilities");
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(target_os = "linux")]
const AT_SECURE: libc::c_ulong = 23;

#[cfg(target_os = "linux")]
extern "C" {
    fn getauxval(ent_type: libc::c_ulong) -> libc::c_ulong;
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos",
    target_os = "solaris",
    target_os = "illumos",
))]
extern "C" {
    fn issetugid() -> libc::c_int;
}

/// Identical to [`is_secure()`], but with no caching (i.e. probes the OS-specific feature directly).
///
/// See the warnings in [`is_secure()`]'s documentation regarding the result changing.
///
/// [`is_secure()`]: ./fn.is_secure.html
#[allow(clippy::needless_return)]
#[inline]
pub fn is_secure_uncached() -> bool {
    #[cfg(target_os = "linux")]
    return unsafe { getauxval(AT_SECURE) } != 0;

    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "solaris",
        target_os = "illumos",
    ))]
    return unsafe { issetugid() } != 0;

    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "solaris",
        target_os = "illumos",
    )))]
    return unsafe { libc::geteuid() != libc::getuid() || libc::getegid() != libc::getgid() };
}

/// Check if this program was launched in a way that requires "secure execution".
///
/// This usually means that the executed binary is set-UID, set-GID, or (on Linux) has file
/// capabilities.
///
/// On Linux, this calls `getauxval(AT_SECURE)`; on macOS, the BSDs, and Solaris/Illumos, it calls
/// `issetugid()`; and on other platforms it checks if the effective UID/GID is different from the
/// real UID/GID. The result is cached after the first call.
///
/// # IMPORTANT: CALL THIS FUNCTION EARLY (and from the main thread)
///
/// On some platforms, certain operations (i.e. changing the process's UID/GID) can cause the
/// value reported by [`is_secure_uncached()`] to change (either from `true` to `false` OR from
/// `false` to `true`). That's why the result of this function is cached by default, and it's also
/// why [`is_secure_uncached()`] should be used with caution.
///
/// As a result, this function should be called for the first time **before** taking any action
/// (`setuid()`, `setreuid()`, `setgid()`, etc.) that could cause the OS's reported "secure" value
/// to change. In binary crates, it's recommended to call this function at the start of `main()`,
/// even if you don't need the value right away.
///
/// ## Concurrency
///
/// **TL;DR**: Either avoid calling this function from multiple threads, or call it at least once
/// from the main thread before spawning any other threads.
///
/// In the interests of efficiency, the cache is implemented using an atomic data type, not a lock
/// or a `Once`-like synchronization primitive. As a result, if this function is called concurrently
/// from multiple threads, two or more of them might **all** re-check the value by calling
/// [`is_secure_uncached()`].
///
/// So if you call this function for the first time across multiple threads, you should **not**
/// assume that it's safe to take actions that might change the result of [`is_secure_uncached()`]
/// as soon as one of the calls finishes, because other threads might checking concurrently. You
/// need to either synchronize calls to this function using a mutex, or (preferably) call it before
/// launching any other threads.
///
/// [`is_secure_uncached()`]: ./fn.is_secure_uncached.html
pub fn is_secure() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};

    static mut RES: AtomicU8 = AtomicU8::new(2);

    match unsafe { RES.load(Ordering::SeqCst) } {
        0 => false,
        1 => true,

        // Not set; need to re-determine
        _ => {
            let res = is_secure_uncached();

            unsafe {
                RES.store(res as u8, Ordering::SeqCst);
            }

            res
        }
    }
}

/// Get the specified environmental variable from the current process's environment (unless the
/// program requires "secure execution").
///
/// Other than returning a "not found" error if [`is_secure()`] returns true, this is equivalent to
/// `std::env::var()`.
///
/// [`is_secure()`]: ./fn.is_secure.html
#[cfg(feature = "std")]
#[inline]
pub fn secure_getenv<K: AsRef<std::ffi::OsStr>>(key: K) -> Result<String, std::env::VarError> {
    if is_secure() {
        Err(std::env::VarError::NotPresent)
    } else {
        std::env::var(key)
    }
}

/// Get the specified environmental variable from the current process's environment (unless the
/// program requires "secure execution").
///
/// Other than returning `None` if [`is_secure()`] returns true, this is equivalent to
/// `std::env::var_os()`.
///
/// [`is_secure()`]: ./fn.is_secure.html
#[cfg(feature = "std")]
#[inline]
pub fn secure_getenv_os<K: AsRef<std::ffi::OsStr>>(key: K) -> Option<std::ffi::OsString> {
    if is_secure() {
        None
    } else {
        std::env::var_os(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_secure() {
        assert!(!is_secure_uncached());
        assert!(!is_secure_uncached());

        assert!(!is_secure());
        assert!(!is_secure());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_secure_getenv() {
        assert_eq!(
            secure_getenv("PATH").unwrap(),
            std::env::var("PATH").unwrap()
        );

        assert_eq!(
            secure_getenv_os("PATH").unwrap(),
            std::env::var_os("PATH").unwrap()
        );
    }
}
