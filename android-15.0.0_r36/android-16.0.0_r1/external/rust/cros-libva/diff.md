```diff
diff --git a/METADATA b/METADATA
index 9404810..cae6815 100644
--- a/METADATA
+++ b/METADATA
@@ -1,18 +1,20 @@
-name: "cros-libva"
-description:
-    "This crate provides lightweight and (hopefully) safe libva abstractions "
-    "for use within Rust code with minimal dependencies. It is developed for "
-    "use in ChromeOS, but has no ChromeOS specifics or dependencies and should "
-    "thus be usable anywhere."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/rust/cros-libva
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "cros-libva"
+description: "This crate provides lightweight and (hopefully) safe libva abstractions for use within Rust code with minimal dependencies. It is developed for use in ChromeOS, but has no ChromeOS specifics or dependencies and should thus be usable anywhere."
 third_party {
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2024
+    month: 12
+    day: 6
+  }
   identifier {
     type: "Git"
     value: "https://github.com/chromeos/cros-libva"
+    version: "v0.0.13"
     primary_source: true
-    version: "v0.0.10"
   }
-  version: "v0.0.10"
-  last_upgrade_date { year: 2024 month: 11 day: 14 }
-  license_type: NOTICE
 }
diff --git a/README.md b/README.md
index 691aaae..da3e73c 100644
--- a/README.md
+++ b/README.md
@@ -9,10 +9,10 @@ usable anywhere.
 
 The native [libva](https://github.com/intel/libva) library is required at link
 time, so make sure to have the `libva-dev` or equivalent package for your
-distribution installed. The compatible libva version is 1.22.0. The VA-API
-driver corresponding to your hardware is also required: for Intel hardware it
-will be [intel-media-driver](https://github.com/intel/media-driver), whereas AMD
-hardware relies on [Mesa](https://gitlab.freedesktop.org/mesa/mesa).
+distribution installed. The libva version needs to be 1.20.0 or newer. The
+VA-API driver corresponding to your hardware is also required: for Intel
+hardware it will be [intel-media-driver](https://github.com/intel/media-driver),
+whereas AMD hardware relies on [Mesa](https://gitlab.freedesktop.org/mesa/mesa).
 
 An easy way to see whether everything is in order is to run the `vainfo`
 utility packaged with `libva-utils` or as a standalone package in some
diff --git a/lib/Android.bp b/lib/Android.bp
index 7c31eb9..923895c 100644
--- a/lib/Android.bp
+++ b/lib/Android.bp
@@ -26,6 +26,13 @@ rust_library {
         "//apex_available:anyapex",
     ],
 
+    cfgs: [
+        "libva_1_21_or_higher",
+        "libva_1_20_or_higher",
+        "libva_1_19_or_higher",
+        "libva_1_16_or_higher",
+    ],
+
     vendor: true,
     enabled: false,
     arch: {
diff --git a/lib/Cargo.toml b/lib/Cargo.toml
index df66f93..ef00985 100644
--- a/lib/Cargo.toml
+++ b/lib/Cargo.toml
@@ -1,6 +1,6 @@
 [package]
 name = "cros-libva"
-version = "0.0.10"
+version = "0.0.13"
 license = "BSD-3-Clause"
 description = "Safe bindings over libva"
 repository = "https://github.com/chromeos/cros-libva"
@@ -16,7 +16,8 @@ log = { version = "0", features = ["release_max_level_debug"] }
 
 [build-dependencies]
 bindgen = "0.70.1"
-pkg-config = "0.3.26"
+pkg-config = "0.3.31"
+regex = "1.11.1"
 
 [dev-dependencies]
 crc32fast = "1.2.1"
diff --git a/lib/build.rs b/lib/build.rs
index 160accf..b6730e6 100644
--- a/lib/build.rs
+++ b/lib/build.rs
@@ -2,7 +2,10 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
+use regex::Regex;
+use std::env::VarError;
 use std::env::{self};
+use std::fs::read_to_string;
 use std::path::{Path, PathBuf};
 
 mod bindgen_gen;
@@ -16,13 +19,70 @@ const CROS_LIBVA_LIB_PATH_ENV: &str = "CROS_LIBVA_LIB_PATH";
 /// Wrapper file to use as input of bindgen.
 const WRAPPER_PATH: &str = "libva-wrapper.h";
 
+// Return VA_MAJOR_VERSION and VA_MINOR_VERSION from va_version.h.
+fn get_va_version(va_h_path: &str) -> (u32, u32) {
+    let va_version_h_path = Path::new(va_h_path).join("va/va_version.h");
+    assert!(
+        va_version_h_path.exists(),
+        "{} doesn't exist",
+        va_version_h_path.display()
+    );
+    let header_content = read_to_string(va_version_h_path).unwrap();
+    let lines = header_content.lines();
+
+    const VERSION_REGEX_STRINGS: [&str; 2] = [
+        r"#define VA_MAJOR_VERSION\s*[0-9]+",
+        r"#define VA_MINOR_VERSION\s*[0-9]+",
+    ];
+    let mut numbers: [u32; 2] = [0; 2];
+    for i in 0..2 {
+        let re = Regex::new(VERSION_REGEX_STRINGS[i]).unwrap();
+        let match_line = lines
+            .clone()
+            .filter(|&s| re.is_match(s))
+            .collect::<Vec<_>>();
+        assert_eq!(
+            match_line.len(),
+            1,
+            "unexpected match for {}: {:?}",
+            VERSION_REGEX_STRINGS[i],
+            match_line
+        );
+        let number_str = Regex::new(r"[0-9]+")
+            .unwrap()
+            .find(match_line[0])
+            .unwrap()
+            .as_str();
+        numbers[i] = number_str.parse::<u32>().unwrap();
+    }
+
+    (numbers[0], numbers[1])
+}
+
 fn main() {
     // Do not require dependencies when generating docs.
     if std::env::var("CARGO_DOC").is_ok() || std::env::var("DOCS_RS").is_ok() {
         return;
     }
 
-    let va_h_path = env::var(CROS_LIBVA_H_PATH_ENV).unwrap_or_default();
+    let va_h_path = env::var(CROS_LIBVA_H_PATH_ENV)
+        .or_else(|e| {
+            if let VarError::NotPresent = e {
+                let libva_library = pkg_config::probe_library("libva");
+                match libva_library {
+                    Ok(_) => Ok(libva_library.unwrap().include_paths[0]
+                        .clone()
+                        .into_os_string()
+                        .into_string()
+                        .unwrap()),
+                    Err(e) => panic!("libva is not found in system: {}", e),
+                }
+            } else {
+                Err(e)
+            }
+        })
+        .expect("libva header location is unknown");
+
     let va_lib_path = env::var(CROS_LIBVA_LIB_PATH_ENV).unwrap_or_default();
     // Check the path exists.
     if !va_h_path.is_empty() {
@@ -33,11 +93,30 @@ fn main() {
         );
     }
 
+    let (major, minor) = get_va_version(&va_h_path);
+    println!("libva {}.{} is used to generate bindings", major, minor);
+    let va_check_version = |desired_major: u32, desired_minor: u32| {
+        major > desired_major || (major == desired_major && minor >= desired_minor)
+    };
+
+    if va_check_version(1, 21) {
+        println!("cargo::rustc-cfg=libva_1_21_or_higher");
+    }
+    if va_check_version(1, 20) {
+        println!("cargo::rustc-cfg=libva_1_20_or_higher")
+    }
+    if va_check_version(1, 19) {
+        println!("cargo::rustc-cfg=libva_1_19_or_higher")
+    }
+    if va_check_version(1, 16) {
+        println!("cargo::rustc-cfg=libva_1_16_or_higher")
+    }
+
     if !va_lib_path.is_empty() {
         assert!(
-            Path::new(&va_h_path).exists(),
+            Path::new(&va_lib_path).exists(),
             "{} doesn't exist",
-            va_h_path
+            va_lib_path
         );
         println!("cargo:rustc-link-arg=-Wl,-rpath={}", va_lib_path);
     }
diff --git a/lib/src/buffer/av1.rs b/lib/src/buffer/av1.rs
index 6b21c0c..bc60782 100644
--- a/lib/src/buffer/av1.rs
+++ b/lib/src/buffer/av1.rs
@@ -621,6 +621,7 @@ impl AV1EncSeqFields {
                 bit_depth_minus8,
                 subsampling_x,
                 subsampling_y,
+                #[cfg(libva_1_19_or_higher)]
                 mono_chrome,
                 Default::default(),
             );
@@ -655,6 +656,7 @@ impl EncSequenceParameterBufferAV1 {
             seq_profile,
             seq_level_idx,
             seq_tier,
+            #[cfg(libva_1_16_or_higher)]
             hierarchical_flag,
             intra_period,
             ip_period,
@@ -736,10 +738,12 @@ impl AV1EncPictureFlags {
         let disable_frame_recon = disable_frame_recon as u32;
         let allow_intrabc = allow_intrabc as u32;
         let palette_mode_enable = palette_mode_enable as u32;
+        #[cfg(libva_1_21_or_higher)]
         let allow_screen_content_tools = allow_screen_content_tools as u32;
+        #[cfg(libva_1_21_or_higher)]
         let force_integer_mv = force_integer_mv as u32;
 
-        let _bitfield_1 =
+        let _bitfield_1 = {
             bindings::_VAEncPictureParameterBufferAV1__bindgen_ty_1__bindgen_ty_1::new_bitfield_1(
                 frame_type,
                 error_resilient_mode,
@@ -754,11 +758,13 @@ impl AV1EncPictureFlags {
                 disable_frame_recon,
                 allow_intrabc,
                 palette_mode_enable,
+                #[cfg(libva_1_21_or_higher)]
                 allow_screen_content_tools,
+                #[cfg(libva_1_21_or_higher)]
                 force_integer_mv,
                 Default::default(),
-            );
-
+            )
+        };
         Self(bindings::_VAEncPictureParameterBufferAV1__bindgen_ty_1 {
             bits: bindings::_VAEncPictureParameterBufferAV1__bindgen_ty_1__bindgen_ty_1 {
                 _bitfield_align_1: Default::default(),
@@ -1073,6 +1079,7 @@ impl EncPictureParameterBufferAV1 {
             coded_buf,
             reference_frames,
             ref_frame_idx,
+            #[cfg(libva_1_19_or_higher)]
             hierarchical_level_plus1,
             primary_ref_frame,
             order_hint,
diff --git a/lib/src/lib.rs b/lib/src/lib.rs
index 6935eb5..c7111f3 100644
--- a/lib/src/lib.rs
+++ b/lib/src/lib.rs
@@ -18,19 +18,9 @@ mod picture;
 mod surface;
 mod usage_hint;
 
-pub use bindings::VAConfigAttrib;
-pub use bindings::VAConfigAttribType;
-pub use bindings::VADRMPRIMESurfaceDescriptor;
-pub use bindings::VAEntrypoint;
-pub use bindings::VAImageFormat;
-pub use bindings::VAProfile;
-pub use bindings::VASurfaceAttrib;
-pub use bindings::VASurfaceAttribExternalBuffers;
-pub use bindings::VASurfaceAttribType;
-pub use bindings::VASurfaceID;
-pub use bindings::VASurfaceStatus;
 pub use bindings::_VADRMPRIMESurfaceDescriptor__bindgen_ty_1 as VADRMPRIMESurfaceDescriptorObject;
 pub use bindings::_VADRMPRIMESurfaceDescriptor__bindgen_ty_2 as VADRMPRIMESurfaceDescriptorLayer;
+pub use bindings::*;
 pub use buffer::*;
 pub use config::*;
 pub use context::*;
@@ -43,8 +33,6 @@ pub use usage_hint::*;
 
 use std::num::NonZeroI32;
 
-use crate::bindings::VAStatus;
-
 /// A `VAStatus` that is guaranteed to not be `VA_STATUS_SUCCESS`.
 #[derive(Debug)]
 pub struct VaError(NonZeroI32);
diff --git a/lib/src/surface.rs b/lib/src/surface.rs
index 0ef74f4..3597409 100644
--- a/lib/src/surface.rs
+++ b/lib/src/surface.rs
@@ -101,6 +101,7 @@ where
 pub enum DecodeErrorType {
     SliceMissing = bindings::VADecodeErrorType::VADecodeSliceMissing,
     MBError = bindings::VADecodeErrorType::VADecodeMBError,
+    #[cfg(libva_1_20_or_higher)]
     Reset = bindings::VADecodeErrorType::VADecodeReset,
 }
 
@@ -307,6 +308,7 @@ impl<D: SurfaceMemoryDescriptor> Surface<D> {
             let type_ = match error.decode_error_type {
                 bindings::VADecodeErrorType::VADecodeSliceMissing => DecodeErrorType::SliceMissing,
                 bindings::VADecodeErrorType::VADecodeMBError => DecodeErrorType::MBError,
+                #[cfg(libva_1_20_or_higher)]
                 bindings::VADecodeErrorType::VADecodeReset => DecodeErrorType::Reset,
                 _ => {
                     log::warn!(
```

