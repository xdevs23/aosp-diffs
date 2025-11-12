```diff
diff --git a/Android.bp b/Android.bp
index 5a71bb0..4ff000e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -18,6 +18,7 @@ rust_defaults {
     rustlibs: [
         "libanyhow",
         "liblibc",
+        "liblog_rust",
         "libnix",
         "libthiserror",
     ],
diff --git a/inherited_fd.rs b/inherited_fd.rs
index f5e2d6b..31ab297 100644
--- a/inherited_fd.rs
+++ b/inherited_fd.rs
@@ -40,16 +40,12 @@ pub enum Error {
     /// Not an inherited file descriptor
     #[error("FD {0} is either invalid file descriptor or not an inherited one")]
     FileDescriptorNotInherited(RawFd),
-
-    /// Failed to set CLOEXEC
-    #[error("Failed to set CLOEXEC on FD {0}")]
-    FailCloseOnExec(RawFd),
 }
 
 static INHERITED_FDS: OnceLock<Mutex<HashMap<RawFd, Option<OwnedFd>>>> = OnceLock::new();
 
 /// Take ownership of all open file descriptors in this process, which later can be obtained by
-/// calling `take_fd_ownership`.
+/// calling `take_fd_ownership`. Set the FD_CLOEXEC on all of these file descriptors.
 ///
 /// # Safety
 /// This function has to be called very early in the program before the ownership of any file
@@ -78,6 +74,8 @@ pub unsafe fn init_once() -> Result<(), std::io::Error> {
             continue;
         }
 
+        fcntl(raw_fd, F_SETFD(FdFlag::FD_CLOEXEC))?;
+
         // SAFETY: /proc/self/fd/* are file descriptors that are open. If `init_once()` was called
         // at the very beginning of the program execution (as requested by the safety requirement
         // of this function), this is the first time to claim the ownership of these file
@@ -99,7 +97,6 @@ pub fn take_fd_ownership(raw_fd: RawFd) -> Result<OwnedFd, Error> {
 
     if let Some(value) = fds.get_mut(&raw_fd) {
         if let Some(owned_fd) = value.take() {
-            fcntl(raw_fd, F_SETFD(FdFlag::FD_CLOEXEC)).or(Err(Error::FailCloseOnExec(raw_fd)))?;
             Ok(owned_fd)
         } else {
             Err(Error::OwnershipTaken(raw_fd))
@@ -254,17 +251,17 @@ mod test {
         let fixture = Fixture::setup(2)?;
         let f = fixture.fds[0];
 
+        fcntl(f, F_SETFD(FdFlag::empty()))?;
+
         // SAFETY: assume files opened by Fixture are inherited ones
         unsafe {
             init_once()?;
         }
 
-        // Intentionally cleaar cloexec to see if it is set by take_fd_ownership
-        fcntl(f, F_SETFD(FdFlag::empty()))?;
-
-        let f_owned = take_fd_ownership(f)?;
-        let flags = fcntl(f_owned.as_raw_fd(), F_GETFD)?;
+        // FD_CLOEXEC should be set by init_once
+        let flags = fcntl(f.as_raw_fd(), F_GETFD)?;
         assert_eq!(flags, FdFlag::FD_CLOEXEC.bits());
+
         Ok(())
     }
 }
diff --git a/lib.rs b/lib.rs
index a1beab5..51edf09 100644
--- a/lib.rs
+++ b/lib.rs
@@ -14,6 +14,8 @@
 
 //! Android rust utilities.
 
+pub mod log;
+
 #[cfg(target_os = "android")]
 pub mod sockets;
 
diff --git a/log.rs b/log.rs
new file mode 100644
index 0000000..280cf2b
--- /dev/null
+++ b/log.rs
@@ -0,0 +1,238 @@
+// Copyright (C) 2025 The Android Open Source Project
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
+//! Provides utilities for logging.
+
+use log::Log;
+
+/// A [logger] that logs each record to both `L0` and `L1`.
+///
+/// # Examples
+///
+/// Log anything `debug` or above to `stderr` and `logcat`.
+/// The `RUST_LOG` environment variable overrides this behavior for `env_logger`
+/// but not `android_logger`.
+///
+/// ```ignore
+/// use std::sync::OnceLock;
+///
+/// static LOGGER: OnceLock<LogBoth<env_logger::Logger, android_logger::AndroidLogger>> =
+///     OnceLock::new();
+///
+/// log::set_logger(LOGGER.get_or_init(|| {
+///     LogBoth(
+///         env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
+///             .build(),
+///         android_logger::AndroidLogger::new(
+///             Config::default()
+///                 .with_max_level(log::LevelFilter::Trace)
+///                 .with_tag("tag_name"),
+///         ),
+///     )
+/// }))
+/// .unwrap_or_else(|e| panic!("{e}"));
+/// ```
+///
+/// Or, using `set_boxed_logger`:
+///
+/// ```ignore
+/// log::set_boxed_logger(Box::new(LogBoth(
+///     env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
+///         .build(),
+///     android_logger::AndroidLogger::new(
+///         android_logger::Config::default()
+///             .with_max_level(log::LevelFilter::Debug)
+///             .with_tag("tag_name"),
+///     ),
+/// )))
+/// .unwrap_or_else(|e| panic!("{e}"));
+/// ```
+///
+/// [logger]: log::Log
+pub struct LogBoth<L0, L1>(pub L0, pub L1);
+
+impl<L0: Log, L1: Log> Log for LogBoth<L0, L1> {
+    fn enabled(&self, metadata: &log::Metadata) -> bool {
+        self.0.enabled(metadata) || self.1.enabled(metadata)
+    }
+
+    fn log(&self, record: &log::Record) {
+        // No need to check `enabled` - implementors must filter in `log` as well.
+        self.0.log(record);
+        self.1.log(record);
+    }
+
+    fn flush(&self) {
+        self.0.flush();
+        self.1.flush();
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use log::{Level, LevelFilter, Metadata, Record};
+    use std::sync::Mutex;
+
+    struct FakeLogger {
+        filter: LevelFilter,
+        records: Mutex<Vec<String>>,
+        flushed_record_count: Mutex<usize>,
+    }
+
+    impl FakeLogger {
+        fn new(filter: LevelFilter) -> Self {
+            Self { filter, records: Mutex::new(Vec::new()), flushed_record_count: Mutex::new(0) }
+        }
+
+        fn logged_messages(&self) -> Vec<String> {
+            self.records.lock().unwrap().clone()
+        }
+
+        fn last_flush_count(&self) -> usize {
+            *self.flushed_record_count.lock().unwrap()
+        }
+    }
+
+    impl Log for FakeLogger {
+        fn enabled(&self, metadata: &log::Metadata) -> bool {
+            metadata.level() <= self.filter
+        }
+
+        fn log(&self, record: &log::Record) {
+            if self.enabled(record.metadata()) {
+                self.records.lock().unwrap().push(format!("{}", record.args()));
+            }
+        }
+
+        fn flush(&self) {
+            let current_len = self.records.lock().unwrap().len();
+            *self.flushed_record_count.lock().unwrap() = current_len;
+        }
+    }
+
+    // `format_args` always creates temporaries, so we can't build a `Record<'static>`.
+    macro_rules! make_record {
+        ($level:expr, $message:literal) => {
+            Record::builder()
+                .args(format_args!("{}", $message))
+                .level($level)
+                .target("test")
+                .build()
+        };
+    }
+
+    fn make_metadata(level: Level) -> Metadata<'static> {
+        Metadata::builder().level(level).target("test").build()
+    }
+
+    #[test]
+    fn test_log_both_enabled() {
+        let log_both =
+            LogBoth(FakeLogger::new(LevelFilter::Info), FakeLogger::new(LevelFilter::Debug));
+
+        // Test enabled()
+        assert!(log_both.enabled(&make_metadata(Level::Error))); // Both enabled
+        assert!(log_both.enabled(&make_metadata(Level::Warn))); // Both enabled
+        assert!(log_both.enabled(&make_metadata(Level::Info))); // Both enabled
+        assert!(log_both.enabled(&make_metadata(Level::Debug))); // Only logger1 enabled
+        assert!(!log_both.enabled(&make_metadata(Level::Trace))); // Neither enabled (logger1 debug, logger0 info)
+
+        // Test enabled() when one logger has a higher filter
+        let log_both_varied =
+            LogBoth(FakeLogger::new(LevelFilter::Info), FakeLogger::new(LevelFilter::Trace));
+        assert!(log_both_varied.enabled(&make_metadata(Level::Trace))); // logger_trace enables it
+    }
+
+    #[test]
+    fn test_log_both_log_calls() {
+        let log_both =
+            LogBoth(FakeLogger::new(LevelFilter::Info), FakeLogger::new(LevelFilter::Debug));
+
+        // Log an Info message (both should log)
+        log_both.log(&make_record!(Level::Info, "Info message"));
+        assert_eq!(log_both.0.logged_messages(), vec!["Info message"]);
+        assert_eq!(log_both.1.logged_messages(), vec!["Info message"]);
+
+        // Log a Debug message (only log_both.1 should log)
+        log_both.0.records.lock().unwrap().clear();
+        log_both.1.records.lock().unwrap().clear();
+        log_both.log(&make_record!(Level::Debug, "Debug message"));
+        assert!(log_both.0.logged_messages().is_empty());
+        assert_eq!(log_both.1.logged_messages(), vec!["Debug message"]);
+
+        // Log a Trace message (neither should log)
+        log_both.0.records.lock().unwrap().clear();
+        log_both.1.records.lock().unwrap().clear();
+        log_both.log(&make_record!(Level::Trace, "Trace message"));
+        assert!(log_both.0.logged_messages().is_empty());
+        assert!(log_both.1.logged_messages().is_empty());
+    }
+
+    #[test]
+    fn test_log_both_flush() {
+        let log_both =
+            LogBoth(FakeLogger::new(LevelFilter::Info), FakeLogger::new(LevelFilter::Debug));
+
+        log_both.0.records.lock().unwrap().push("msg1".to_string());
+        log_both.1.records.lock().unwrap().push("msg2".to_string());
+        log_both.1.records.lock().unwrap().push("msg3".to_string());
+
+        assert_eq!(log_both.0.last_flush_count(), 0);
+        assert_eq!(log_both.1.last_flush_count(), 0);
+
+        log_both.flush();
+
+        assert_eq!(log_both.0.last_flush_count(), 1);
+        assert_eq!(log_both.1.last_flush_count(), 2);
+    }
+
+    #[test]
+    fn test_enabled_l0_only() {
+        let logger0 = FakeLogger::new(LevelFilter::Info);
+        let logger1 = FakeLogger::new(LevelFilter::Error); // Higher filter
+        let log_both = LogBoth(logger0, logger1);
+        assert!(log_both.enabled(&make_metadata(Level::Info))); // Enabled by logger0
+    }
+
+    #[test]
+    fn test_enabled_l1_only() {
+        let logger0 = FakeLogger::new(LevelFilter::Error); // Higher filter
+        let logger1 = FakeLogger::new(LevelFilter::Info);
+        let log_both = LogBoth(logger0, logger1);
+        assert!(log_both.enabled(&make_metadata(Level::Info))); // Enabled by logger1
+    }
+
+    #[test]
+    fn test_enabled_neither() {
+        let logger0 = FakeLogger::new(LevelFilter::Error);
+        let logger1 = FakeLogger::new(LevelFilter::Warn);
+        let log_both = LogBoth(logger0, logger1);
+        assert!(!log_both.enabled(&make_metadata(Level::Info))); // Neither enabled
+    }
+
+    #[test]
+    fn test_log_when_one_disabled() {
+        let log_both =
+            LogBoth(FakeLogger::new(LevelFilter::Info), FakeLogger::new(LevelFilter::Warn));
+
+        log_both.log(&make_record!(Level::Info, "Test Info"));
+        assert_eq!(log_both.0.logged_messages(), vec!["Test Info"]);
+        assert!(log_both.1.logged_messages().is_empty()); // log_both.1 (Warn filter) shouldn't log Info
+
+        log_both.log(&make_record!(Level::Warn, "Test Warn"));
+        assert_eq!(log_both.0.logged_messages(), vec!["Test Info", "Test Warn"]);
+        assert_eq!(log_both.1.logged_messages(), vec!["Test Warn"]);
+    }
+}
```

