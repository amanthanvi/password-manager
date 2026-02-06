use std::ffi::c_void;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FORCE_MLOCK_FAIL: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
pub(crate) struct ForceMlockFailGuard;

#[cfg(test)]
impl ForceMlockFailGuard {
    pub(crate) fn enable() -> Self {
        FORCE_MLOCK_FAIL.with(|flag| flag.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for ForceMlockFailGuard {
    fn drop(&mut self) {
        FORCE_MLOCK_FAIL.with(|flag| flag.set(false));
    }
}

#[derive(Debug)]
pub(crate) struct MemoryLock {
    ptr: *const u8,
    len: usize,
    locked: bool,
}

impl MemoryLock {
    pub(crate) fn new(label: &'static str, ptr: *const u8, len: usize) -> Self {
        let mut lock = Self {
            ptr,
            len,
            locked: false,
        };

        if len == 0 {
            return lock;
        }

        #[cfg(test)]
        if FORCE_MLOCK_FAIL.with(|flag| flag.get()) {
            log_mlock_warning(label, "forced failure (test)");
            return lock;
        }

        #[cfg(any(unix, windows))]
        {
            if let Err(error) = unsafe { try_mlock(ptr, len) } {
                log_mlock_warning(label, &error.to_string());
            } else {
                lock.locked = true;
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = label;
        }

        lock
    }

    pub(crate) fn unlock(&mut self) {
        if !self.locked || self.len == 0 {
            return;
        }

        #[cfg(any(unix, windows))]
        {
            // Best-effort: never crash if the OS refuses to unlock.
            let _ = unsafe { try_munlock(self.ptr, self.len) };
        }

        self.locked = false;
    }

    #[cfg(test)]
    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for MemoryLock {
    fn drop(&mut self) {
        self.unlock();
    }
}

fn log_mlock_warning(label: &'static str, message: &str) {
    eprintln!(
        "npw: warning: mlock({}) failed: {}; continuing with zeroize-only",
        label, message
    );
}

#[cfg(unix)]
unsafe fn try_mlock(ptr: *const u8, len: usize) -> std::io::Result<()> {
    unsafe extern "C" {
        fn mlock(addr: *const c_void, len: usize) -> i32;
    }
    let result = unsafe { mlock(ptr as *const c_void, len) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
unsafe fn try_munlock(ptr: *const u8, len: usize) -> std::io::Result<()> {
    unsafe extern "C" {
        fn munlock(addr: *const c_void, len: usize) -> i32;
    }
    let result = unsafe { munlock(ptr as *const c_void, len) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
unsafe fn try_mlock(ptr: *const u8, len: usize) -> std::io::Result<()> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualLock(lp_address: *const c_void, dw_size: usize) -> i32;
        fn GetLastError() -> u32;
    }

    if unsafe { VirtualLock(ptr as *const c_void, len) } != 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() }.try_into().unwrap_or(i32::MAX),
        ))
    }
}

#[cfg(windows)]
unsafe fn try_munlock(ptr: *const u8, len: usize) -> std::io::Result<()> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualUnlock(lp_address: *const c_void, dw_size: usize) -> i32;
        fn GetLastError() -> u32;
    }

    if unsafe { VirtualUnlock(ptr as *const c_void, len) } != 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() }.try_into().unwrap_or(i32::MAX),
        ))
    }
}
