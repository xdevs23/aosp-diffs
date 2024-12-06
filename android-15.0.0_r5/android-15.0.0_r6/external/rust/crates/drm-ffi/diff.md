```diff
diff --git a/.cargo_vcs_info.json b/.cargo_vcs_info.json
index c628ad1..1d8fe8c 100644
--- a/.cargo_vcs_info.json
+++ b/.cargo_vcs_info.json
@@ -1,6 +1,6 @@
 {
   "git": {
-    "sha1": "328742fddc675b3370057b382eb54acbc9b48c79"
+    "sha1": "74a9bd372866d52e2d6c98c75c676b080856848d"
   },
   "path_in_vcs": "drm-ffi"
 }
\ No newline at end of file
diff --git a/Android.bp b/Android.bp
index 30e6e0a..58060c5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -3,13 +3,23 @@
 // because the changes will be overridden on upgrade.
 // Content before the first "rust_*" or "genrule" module is preserved.
 
-// TODO: Add license.
+package {
+    default_applicable_licenses: ["external_rust_crates_drm-ffi_license"],
+}
+
+license {
+    name: "external_rust_crates_drm-ffi_license",
+    visibility: [":__subpackages__"],
+    license_kinds: ["SPDX-license-identifier-MIT"],
+    license_text: ["LICENSE"],
+}
+
 rust_library {
     name: "libdrm_ffi",
     host_supported: true,
     crate_name: "drm_ffi",
     cargo_env_compat: true,
-    cargo_pkg_version: "0.7.1",
+    cargo_pkg_version: "0.8.0",
     crate_root: "src/lib.rs",
     edition: "2021",
     rustlibs: [
diff --git a/Cargo.toml b/Cargo.toml
index f0c9b04..455c416 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -13,14 +13,14 @@
 edition = "2021"
 rust-version = "1.65"
 name = "drm-ffi"
-version = "0.7.1"
+version = "0.8.0"
 authors = ["Tyler Slabinski <tslabinski@slabity.net>"]
 description = "Safe, low-level bindings to the Direct Rendering Manager API"
 license = "MIT"
 repository = "https://github.com/Smithay/drm-rs"
 
 [dependencies.drm-sys]
-version = "0.6.1"
+version = "0.7.0"
 
 [dependencies.rustix]
 version = "0.38.22"
diff --git a/Cargo.toml.orig b/Cargo.toml.orig
index 298170f..8561e53 100644
--- a/Cargo.toml.orig
+++ b/Cargo.toml.orig
@@ -2,14 +2,14 @@
 name = "drm-ffi"
 description = "Safe, low-level bindings to the Direct Rendering Manager API"
 repository = "https://github.com/Smithay/drm-rs"
-version = "0.7.1"
+version = "0.8.0"
 license = "MIT"
 authors = ["Tyler Slabinski <tslabinski@slabity.net>"]
 rust-version = "1.65"
 edition = "2021"
 
 [dependencies]
-drm-sys = { path = "drm-sys", version = "0.6.1" }
+drm-sys = { path = "drm-sys", version = "0.7.0" }
 rustix = { version = "0.38.22" }
 
 [features]
diff --git a/METADATA b/METADATA
index 12c8c9b..e874b0f 100644
--- a/METADATA
+++ b/METADATA
@@ -1,20 +1,25 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/rust/crates/drm-ffi
+# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+
 name: "drm-ffi"
 description: "Safe, low-level bindings to the Direct Rendering Manager API"
 third_party {
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2024
+    month: 8
+    day: 8
+  }
   identifier {
     type: "crates.io"
-    value: "drm-ffi"
+    value: "https://static.crates.io/crates/drm-ffi/drm-ffi-0.8.0.crate"
+    version: "0.7.1"
   }
   identifier {
     type: "Archive"
     value: "https://static.crates.io/crates/drm-ffi/drm-ffi-0.7.1.crate"
+    version: "0.8.0"
     primary_source: true
   }
-  version: "0.7.1"
-  license_type: NOTICE
-  last_upgrade_date {
-    year: 2024
-    month: 3
-    day: 13
-  }
 }
diff --git a/OWNERS b/OWNERS
index 697f117..37be8d1 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,5 +3,4 @@ include platform/prebuilts/rust:main:/OWNERS
 
 dextero@google.com
 vill@google.com
-nputikhin@google.com
 istvannador@google.com
diff --git a/src/ioctl.rs b/src/ioctl.rs
index 0f46801..c053ede 100644
--- a/src/ioctl.rs
+++ b/src/ioctl.rs
@@ -278,4 +278,6 @@ pub(crate) mod syncobj {
         0xCD,
         drm_syncobj_timeline_array
     );
+    /// Register an eventfd to be signalled by a syncobj.
+    ioctl_readwrite!(eventfd, DRM_IOCTL_BASE, 0xCF, drm_syncobj_eventfd);
 }
diff --git a/src/syncobj.rs b/src/syncobj.rs
index 6cb45a9..5334944 100644
--- a/src/syncobj.rs
+++ b/src/syncobj.rs
@@ -110,6 +110,7 @@ pub fn wait(
         },
         first_signaled: 0,
         pad: 0,
+        deadline_nsec: 0,
     };
 
     unsafe {
@@ -181,6 +182,7 @@ pub fn timeline_wait(
         },
         first_signaled: 0,
         pad: 0,
+        deadline_nsec: 0,
     };
 
     unsafe {
@@ -262,3 +264,31 @@ pub fn timeline_signal(
 
     Ok(args)
 }
+
+/// Register an eventfd to be signalled by a syncobj.
+pub fn eventfd(
+    fd: BorrowedFd<'_>,
+    handle: u32,
+    point: u64,
+    eventfd: BorrowedFd<'_>,
+    wait_available: bool,
+) -> io::Result<drm_syncobj_eventfd> {
+    let flags = if wait_available {
+        DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE
+    } else {
+        0
+    };
+    let mut args = drm_syncobj_eventfd {
+        handle,
+        point,
+        flags,
+        fd: eventfd.as_raw_fd(),
+        pad: 0,
+    };
+
+    unsafe {
+        ioctl::syncobj::eventfd(fd, &mut args)?;
+    }
+
+    Ok(args)
+}
```

