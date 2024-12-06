```diff
diff --git a/Android.bp b/Android.bp
index 6eda226..f69b1d1 100644
--- a/Android.bp
+++ b/Android.bp
@@ -6,12 +6,19 @@ package {
 rust_defaults {
     name: "librustutils_defaults",
     srcs: ["lib.rs"],
+    host_supported: true,
+    target: {
+        android: {
+            rustlibs: [
+                "libcutils_bindgen",
+                "libsystem_properties_bindgen_sys",
+            ],
+        },
+    },
     rustlibs: [
         "libanyhow",
-        "libcutils_bindgen",
         "liblibc",
         "libnix",
-        "libsystem_properties_bindgen_sys",
         "libthiserror",
     ],
 }
@@ -42,6 +49,15 @@ rust_test {
     defaults: ["librustutils_defaults"],
     test_suites: ["general-tests"],
     auto_gen_config: true,
+    rustlibs: [
+        "libtempfile",
+    ],
+    // Below flags are to run each test function in a separate process which is needed for
+    // the crate::inherited_fd::test. Note that tests still run in parallel.
+    flags: [
+        "-C panic=abort",
+        "-Z panic_abort_tests",
+    ]
 }
 
 // Build a separate rust_library rather than depending directly on libsystem_properties_bindgen,
diff --git a/inherited_fd.rs b/inherited_fd.rs
new file mode 100644
index 0000000..f5e2d6b
--- /dev/null
+++ b/inherited_fd.rs
@@ -0,0 +1,270 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Library for safely obtaining `OwnedFd` for inherited file descriptors.
+
+use nix::fcntl::{fcntl, FdFlag, F_SETFD};
+use nix::libc;
+use std::collections::HashMap;
+use std::fs::canonicalize;
+use std::fs::read_dir;
+use std::os::fd::FromRawFd;
+use std::os::fd::OwnedFd;
+use std::os::fd::RawFd;
+use std::sync::Mutex;
+use std::sync::OnceLock;
+use thiserror::Error;
+
+/// Errors that can occur while taking an ownership of `RawFd`
+#[derive(Debug, PartialEq, Error)]
+pub enum Error {
+    /// init_once() not called
+    #[error("init_once() not called")]
+    NotInitialized,
+
+    /// Ownership already taken
+    #[error("Ownership of FD {0} is already taken")]
+    OwnershipTaken(RawFd),
+
+    /// Not an inherited file descriptor
+    #[error("FD {0} is either invalid file descriptor or not an inherited one")]
+    FileDescriptorNotInherited(RawFd),
+
+    /// Failed to set CLOEXEC
+    #[error("Failed to set CLOEXEC on FD {0}")]
+    FailCloseOnExec(RawFd),
+}
+
+static INHERITED_FDS: OnceLock<Mutex<HashMap<RawFd, Option<OwnedFd>>>> = OnceLock::new();
+
+/// Take ownership of all open file descriptors in this process, which later can be obtained by
+/// calling `take_fd_ownership`.
+///
+/// # Safety
+/// This function has to be called very early in the program before the ownership of any file
+/// descriptors (except stdin/out/err) is taken.
+pub unsafe fn init_once() -> Result<(), std::io::Error> {
+    let mut fds = HashMap::new();
+
+    let fd_path = canonicalize("/proc/self/fd")?;
+
+    for entry in read_dir(&fd_path)? {
+        let entry = entry?;
+
+        // Files in /prod/self/fd are guaranteed to be numbers. So parsing is always successful.
+        let file_name = entry.file_name();
+        let raw_fd = file_name.to_str().unwrap().parse::<RawFd>().unwrap();
+
+        // We don't take ownership of the stdio FDs as the Rust runtime owns them.
+        if [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO].contains(&raw_fd) {
+            continue;
+        }
+
+        // Exceptional case: /proc/self/fd/* may be a dir fd created by read_dir just above. Since
+        // the file descriptor is owned by read_dir (and thus closed by it), we shouldn't take
+        // ownership to it.
+        if entry.path().read_link()? == fd_path {
+            continue;
+        }
+
+        // SAFETY: /proc/self/fd/* are file descriptors that are open. If `init_once()` was called
+        // at the very beginning of the program execution (as requested by the safety requirement
+        // of this function), this is the first time to claim the ownership of these file
+        // descriptors.
+        let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
+        fds.insert(raw_fd, Some(owned_fd));
+    }
+
+    INHERITED_FDS
+        .set(Mutex::new(fds))
+        .or(Err(std::io::Error::other("Inherited fds were already initialized")))
+}
+
+/// Take the ownership of the given `RawFd` and returns `OwnedFd` for it. The returned FD is set
+/// CLOEXEC. `Error` is returned when the ownership was already taken (by a prior call to this
+/// function with the same `RawFd`) or `RawFd` is not an inherited file descriptor.
+pub fn take_fd_ownership(raw_fd: RawFd) -> Result<OwnedFd, Error> {
+    let mut fds = INHERITED_FDS.get().ok_or(Error::NotInitialized)?.lock().unwrap();
+
+    if let Some(value) = fds.get_mut(&raw_fd) {
+        if let Some(owned_fd) = value.take() {
+            fcntl(raw_fd, F_SETFD(FdFlag::FD_CLOEXEC)).or(Err(Error::FailCloseOnExec(raw_fd)))?;
+            Ok(owned_fd)
+        } else {
+            Err(Error::OwnershipTaken(raw_fd))
+        }
+    } else {
+        Err(Error::FileDescriptorNotInherited(raw_fd))
+    }
+}
+
+#[cfg(test)]
+mod test {
+    use super::*;
+    use anyhow::Result;
+    use nix::fcntl::{fcntl, FdFlag, F_GETFD, F_SETFD};
+    use nix::unistd::close;
+    use std::os::fd::{AsRawFd, IntoRawFd};
+    use tempfile::tempfile;
+
+    struct Fixture {
+        fds: Vec<RawFd>,
+    }
+
+    impl Fixture {
+        fn setup(num_fds: usize) -> Result<Self> {
+            let mut fds = Vec::new();
+            for _ in 0..num_fds {
+                fds.push(tempfile()?.into_raw_fd());
+            }
+            Ok(Fixture { fds })
+        }
+
+        fn open_new_file(&mut self) -> Result<RawFd> {
+            let raw_fd = tempfile()?.into_raw_fd();
+            self.fds.push(raw_fd);
+            Ok(raw_fd)
+        }
+    }
+
+    impl Drop for Fixture {
+        fn drop(&mut self) {
+            self.fds.iter().for_each(|fd| {
+                let _ = close(*fd);
+            });
+        }
+    }
+
+    fn is_fd_opened(raw_fd: RawFd) -> bool {
+        fcntl(raw_fd, F_GETFD).is_ok()
+    }
+
+    #[test]
+    fn happy_case() -> Result<()> {
+        let fixture = Fixture::setup(2)?;
+        let f0 = fixture.fds[0];
+        let f1 = fixture.fds[1];
+
+        // SAFETY: assume files opened by Fixture are inherited ones
+        unsafe {
+            init_once()?;
+        }
+
+        let f0_owned = take_fd_ownership(f0)?;
+        let f1_owned = take_fd_ownership(f1)?;
+        assert_eq!(f0, f0_owned.as_raw_fd());
+        assert_eq!(f1, f1_owned.as_raw_fd());
+
+        drop(f0_owned);
+        drop(f1_owned);
+        assert!(!is_fd_opened(f0));
+        assert!(!is_fd_opened(f1));
+        Ok(())
+    }
+
+    #[test]
+    fn access_non_inherited_fd() -> Result<()> {
+        let mut fixture = Fixture::setup(2)?;
+
+        // SAFETY: assume files opened by Fixture are inherited ones
+        unsafe {
+            init_once()?;
+        }
+
+        let f = fixture.open_new_file()?;
+        assert_eq!(Some(Error::FileDescriptorNotInherited(f)), take_fd_ownership(f).err());
+        Ok(())
+    }
+
+    #[test]
+    fn call_init_once_multiple_times() -> Result<()> {
+        let _ = Fixture::setup(2)?;
+
+        // SAFETY: assume files opened by Fixture are inherited ones
+        unsafe {
+            init_once()?;
+        }
+
+        // SAFETY: for testing
+        let res = unsafe { init_once() };
+        assert!(res.is_err());
+        Ok(())
+    }
+
+    #[test]
+    fn access_without_init_once() -> Result<()> {
+        let fixture = Fixture::setup(2)?;
+
+        let f = fixture.fds[0];
+        assert_eq!(Some(Error::NotInitialized), take_fd_ownership(f).err());
+        Ok(())
+    }
+
+    #[test]
+    fn double_ownership() -> Result<()> {
+        let fixture = Fixture::setup(2)?;
+        let f = fixture.fds[0];
+
+        // SAFETY: assume files opened by Fixture are inherited ones
+        unsafe {
+            init_once()?;
+        }
+
+        let f_owned = take_fd_ownership(f)?;
+        let f_double_owned = take_fd_ownership(f);
+        assert_eq!(Some(Error::OwnershipTaken(f)), f_double_owned.err());
+
+        // just to highlight that f_owned is kept alive when the second call to take_fd_ownership
+        // is made.
+        drop(f_owned);
+        Ok(())
+    }
+
+    #[test]
+    fn take_drop_retake() -> Result<()> {
+        let fixture = Fixture::setup(2)?;
+        let f = fixture.fds[0];
+
+        // SAFETY: assume files opened by Fixture are inherited ones
+        unsafe {
+            init_once()?;
+        }
+
+        let f_owned = take_fd_ownership(f)?;
+        drop(f_owned);
+
+        let f_double_owned = take_fd_ownership(f);
+        assert_eq!(Some(Error::OwnershipTaken(f)), f_double_owned.err());
+        Ok(())
+    }
+
+    #[test]
+    fn cloexec() -> Result<()> {
+        let fixture = Fixture::setup(2)?;
+        let f = fixture.fds[0];
+
+        // SAFETY: assume files opened by Fixture are inherited ones
+        unsafe {
+            init_once()?;
+        }
+
+        // Intentionally cleaar cloexec to see if it is set by take_fd_ownership
+        fcntl(f, F_SETFD(FdFlag::empty()))?;
+
+        let f_owned = take_fd_ownership(f)?;
+        let flags = fcntl(f_owned.as_raw_fd(), F_GETFD)?;
+        assert_eq!(flags, FdFlag::FD_CLOEXEC.bits());
+        Ok(())
+    }
+}
diff --git a/lib.rs b/lib.rs
index d15eb99..a1beab5 100644
--- a/lib.rs
+++ b/lib.rs
@@ -14,6 +14,13 @@
 
 //! Android rust utilities.
 
+#[cfg(target_os = "android")]
 pub mod sockets;
+
+#[cfg(target_os = "android")]
 pub mod system_properties;
+
+#[cfg(target_os = "android")]
 pub mod users;
+
+pub mod inherited_fd;
diff --git a/sockets.rs b/sockets.rs
index 0ea65fc..5edbd6c 100644
--- a/sockets.rs
+++ b/sockets.rs
@@ -14,40 +14,41 @@
 
 //! Provides utilities for sockets.
 
-use nix::errno::Errno;
-use nix::fcntl::{fcntl, FdFlag, F_SETFD};
 use std::ffi::CString;
-use std::os::unix::io::RawFd;
+use std::os::fd::OwnedFd;
 use thiserror::Error;
 
+use crate::inherited_fd;
+
 /// Errors this crate can generate
 #[derive(Error, Debug)]
 pub enum SocketError {
-    /// invalid name parameter
-    #[error("socket name {0} contains NUL byte")]
-    NulError(String),
-
-    /// android_get_control_socket failed to get a fd
-    #[error("android_get_control_socket({0}) failed")]
-    GetControlSocketFailed(String),
+    /// Invalid socket name. It could be either due to a null byte in the name, or the name refers
+    /// to a non-existing socket.
+    #[error("socket name {0} is invalid")]
+    InvalidName(String),
 
-    /// Failed to execute fcntl
-    #[error("Failed to execute fcntl {0}")]
-    FcntlFailed(Errno),
+    /// Error when taking ownership of the socket file descriptor.
+    #[error("Failed to take file descriptor ownership: {0}")]
+    OwnershipFailed(inherited_fd::Error),
 }
 
-/// android_get_control_socket - simple helper function to get the file
-/// descriptor of our init-managed Unix domain socket. `name' is the name of the
-/// socket, as given in init.rc. Returns -1 on error.
+/// Get `OwnedFd` for a Unix domain socket that init created under the name `name`. See
+/// [Android Init Language]
+/// (https://cs.android.com/android/platform/superproject/main/+/main:system/core/init/README.md)
+/// for creating sockets and giving them names.
+///
 /// The returned file descriptor has the flag CLOEXEC set.
-pub fn android_get_control_socket(name: &str) -> Result<RawFd, SocketError> {
-    let cstr = CString::new(name).map_err(|_| SocketError::NulError(name.to_owned()))?;
+///
+/// This function returns `SocketError::OwnershipFailed` if `crate::inherited_fd::init_once` was
+/// not called very early in the process startup or this function is called multile times with the
+/// same `name`.
+pub fn android_get_control_socket(name: &str) -> Result<OwnedFd, SocketError> {
+    let cstr = CString::new(name).map_err(|_| SocketError::InvalidName(name.to_owned()))?;
     // SAFETY: android_get_control_socket doesn't take ownership of name
     let fd = unsafe { cutils_bindgen::android_get_control_socket(cstr.as_ptr()) };
     if fd < 0 {
-        return Err(SocketError::GetControlSocketFailed(name.to_owned()));
+        return Err(SocketError::InvalidName(name.to_owned()));
     }
-    // The file descriptor had CLOEXEC disabled to be inherited from the parent.
-    fcntl(fd, F_SETFD(FdFlag::FD_CLOEXEC)).map_err(SocketError::FcntlFailed)?;
-    Ok(fd)
+    inherited_fd::take_fd_ownership(fd).map_err(SocketError::OwnershipFailed)
 }
diff --git a/system_properties.rs b/system_properties.rs
index f800ccd..4d04571 100644
--- a/system_properties.rs
+++ b/system_properties.rs
@@ -36,37 +36,33 @@ pub mod parsers_formatters;
 /// property, or wait for it to change.
 pub struct PropertyWatcher {
     prop_name: CString,
-    prop_info: *const PropInfo,
+    prop_info: Option<&'static PropInfo>,
     serial: c_uint,
 }
 
 impl PropertyWatcher {
     /// Create a PropertyWatcher for the named system property.
     pub fn new(name: &str) -> Result<Self> {
-        Ok(Self { prop_name: CString::new(name)?, prop_info: null(), serial: 0 })
+        Ok(Self { prop_name: CString::new(name)?, prop_info: None, serial: 0 })
     }
 
     // Lazy-initializing accessor for self.prop_info.
-    fn get_prop_info(&mut self) -> Option<*const PropInfo> {
-        if self.prop_info.is_null() {
+    fn get_prop_info(&mut self) -> Option<&'static PropInfo> {
+        if self.prop_info.is_none() {
             // SAFETY: Input and output are both const. The returned pointer is valid for the
             // lifetime of the program.
             self.prop_info = unsafe {
-                system_properties_bindgen::__system_property_find(self.prop_name.as_ptr())
+                system_properties_bindgen::__system_property_find(self.prop_name.as_ptr()).as_ref()
             };
         }
-        if self.prop_info.is_null() {
-            None
-        } else {
-            Some(self.prop_info)
-        }
+        self.prop_info
     }
 
-    fn read_raw(prop_info: *const PropInfo, mut f: impl FnMut(Option<&CStr>, Option<&CStr>)) {
+    fn read_raw<F: FnMut(Option<&CStr>, Option<&CStr>)>(prop_info: &PropInfo, mut f: F) {
         // Unsafe function converts values passed to us by
         // __system_property_read_callback to Rust form
         // and pass them to inner callback.
-        unsafe extern "C" fn callback(
+        unsafe extern "C" fn callback<F: FnMut(Option<&CStr>, Option<&CStr>)>(
             res_p: *mut c_void,
             name: *const c_char,
             value: *const c_char,
@@ -86,20 +82,18 @@ impl PropertyWatcher {
                 // IsLegalPropertyValue in system/core/init/util.cpp.
                 Some(unsafe { CStr::from_ptr(value) })
             };
-            // SAFETY: We converted the FnMut from `f` to a void pointer below, now we convert it
+            // SAFETY: We converted the FnMut from `F` to a void pointer below, now we convert it
             // back.
-            let f = unsafe { &mut *res_p.cast::<&mut dyn FnMut(Option<&CStr>, Option<&CStr>)>() };
+            let f = unsafe { &mut *res_p.cast::<F>() };
             f(name, value);
         }
 
-        let mut f: &mut dyn FnMut(Option<&CStr>, Option<&CStr>) = &mut f;
-
         // SAFETY: We convert the FnMut to a void pointer, and unwrap it in our callback.
         unsafe {
             system_properties_bindgen::__system_property_read_callback(
                 prop_info,
-                Some(callback),
-                &mut f as *mut _ as *mut c_void,
+                Some(callback::<F>),
+                &mut f as *mut F as *mut c_void,
             )
         }
     }
@@ -160,9 +154,9 @@ impl PropertyWatcher {
     ///
     /// This records the serial number of the last change, so race conditions are avoided.
     fn wait_for_property_change_until(&mut self, until: Option<Instant>) -> Result<()> {
-        // If the property is null, then wait for it to be created. Subsequent waits will
+        // If the property is None, then wait for it to be created. Subsequent waits will
         // skip this step and wait for our specific property to change.
-        if self.prop_info.is_null() {
+        if self.prop_info.is_none() {
             return self.wait_for_property_creation_until(None);
         }
 
@@ -172,7 +166,10 @@ impl PropertyWatcher {
         // valid.
         if !unsafe {
             system_properties_bindgen::__system_property_wait(
-                self.prop_info,
+                match self.prop_info {
+                    Some(p) => p,
+                    None => null(),
+                },
                 self.serial,
                 &mut new_serial,
                 if let Some(remaining_timeout) = &remaining_timeout {
@@ -319,7 +316,7 @@ where
     let retval = unsafe {
         system_properties_bindgen::__system_property_foreach(
             Some(foreach_callback::<F>),
-            &mut f as *mut _ as *mut c_void,
+            &mut f as *mut F as *mut c_void,
         )
     };
     if retval < 0 {
```

