// LocalCloud Key Management - Secure Memory Utilities
//
// Platform-specific memory locking and core dump prevention.
// All operations are best-effort — failures are logged but not fatal
// (some environments don't allow mlock).

/// Lock a memory region to prevent it from being swapped to disk.
pub fn mlock_slice(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    unsafe { libc::mlock(data.as_ptr() as *const libc::c_void, data.len()) == 0 }
}

/// Unlock a previously locked memory region.
pub fn munlock_slice(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    unsafe {
        libc::munlock(data.as_ptr() as *const libc::c_void, data.len());
    }
}

/// Constant-time equality for 32-byte arrays.
///
/// Hand-rolled to avoid adding a `subtle` dependency. The XOR-OR
/// accumulation has a constant data-flow path; the final `acc == 0`
/// compiles to a single non-data-dependent comparison on mainstream
/// targets (x86_64, aarch64).
#[inline(never)]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time check whether a 32-byte array is all zero.
///
/// Used to reject contributory-to-zero ECDH outputs per RFC 7748 §6.1
/// (low-order recipient public key on Curve25519 produces a
/// shared secret with attacker-known value).
#[inline(never)]
pub fn is_zero_32(a: &[u8; 32]) -> bool {
    let mut acc: u8 = 0;
    for &b in a {
        acc |= b;
    }
    acc == 0
}

/// Disable core dumps for this process using prctl(PR_SET_DUMPABLE, 0).
///
/// This prevents key material from appearing in core dump files.
pub fn disable_core_dumps() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        const PR_SET_DUMPABLE: libc::c_int = 4;
        let ret = unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if ret != 0 {
            return Err(format!(
                "prctl(PR_SET_DUMPABLE, 0) failed with errno: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On non-Linux, we can't use prctl but we still continue
        // The caller should be aware that core dump prevention may not work
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlock_munlock() {
        let data = [0u8; 64];
        // mlock may fail in test environments (insufficient privileges)
        // but it should not panic
        let locked = mlock_slice(&data);
        if locked {
            munlock_slice(&data);
        }
    }

    #[test]
    fn test_mlock_empty_slice() {
        assert!(mlock_slice(&[]));
    }

    #[test]
    fn test_disable_core_dumps() {
        // Should succeed on Linux, may be a no-op elsewhere
        let result = disable_core_dumps();
        assert!(result.is_ok());
    }
}
