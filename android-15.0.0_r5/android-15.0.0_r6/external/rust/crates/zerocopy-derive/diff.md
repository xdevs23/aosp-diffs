```diff
diff --git a/.cargo_vcs_info.json b/.cargo_vcs_info.json
index 22f380d..754de32 100644
--- a/.cargo_vcs_info.json
+++ b/.cargo_vcs_info.json
@@ -1,6 +1,6 @@
 {
   "git": {
-    "sha1": "4147d951c9003b16affbb32ba24d744a01178331"
+    "sha1": "727de668608f2d16e151c42e344d172c0931b1e9"
   },
   "path_in_vcs": "zerocopy-derive"
 }
\ No newline at end of file
diff --git a/Android.bp b/Android.bp
index 79d9be6..a681a4e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,32 +1,23 @@
 // This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
+// Do not modify this file because the changes will be overridden on upgrade.
 
 package {
-    default_applicable_licenses: [
-        "external_rust_crates_zerocopy-derive_license",
-    ],
+    default_applicable_licenses: ["external_rust_crates_zerocopy-derive_license"],
+    default_team: "trendy_team_android_rust",
 }
 
-// Added automatically by a large-scale-change
-// See: http://go/android-license-faq
 license {
     name: "external_rust_crates_zerocopy-derive_license",
     visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-BSD",
-    ],
-    license_text: [
-        "LICENSE",
-    ],
+    license_kinds: ["SPDX-license-identifier-Apache-2.0"],
+    license_text: ["LICENSE"],
 }
 
 rust_proc_macro {
     name: "libzerocopy_derive",
     crate_name: "zerocopy_derive",
     cargo_env_compat: true,
-    cargo_pkg_version: "0.7.34",
+    cargo_pkg_version: "0.7.35",
     crate_root: "src/lib.rs",
     edition: "2018",
     rustlibs: [
diff --git a/Cargo.toml b/Cargo.toml
index 4be23af..70758ac 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -11,9 +11,8 @@
 
 [package]
 edition = "2018"
-rust-version = "1.60.0"
 name = "zerocopy-derive"
-version = "0.7.34"
+version = "0.7.35"
 authors = ["Joshua Liebow-Feeser <joshlf@google.com>"]
 exclude = [
     ".*",
diff --git a/Cargo.toml.orig b/Cargo.toml.orig
index ce4f377..bde423d 100644
--- a/Cargo.toml.orig
+++ b/Cargo.toml.orig
@@ -9,12 +9,11 @@
 [package]
 edition = "2018"
 name = "zerocopy-derive"
-version = "0.7.34"
+version = "0.7.35"
 authors = ["Joshua Liebow-Feeser <joshlf@google.com>"]
 description = "Custom derive for traits from the zerocopy crate"
 license = "BSD-2-Clause OR Apache-2.0 OR MIT"
 repository = "https://github.com/google/zerocopy"
-rust-version = "1.60.0"
 
 # We prefer to include tests when publishing to crates.io so that Crater [1] can
 # detect regressions in our test suite. These two tests are excessively large,
diff --git a/METADATA b/METADATA
index 9a7cfac..ab503dc 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/rust/crates/zerocopy-derive
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "zerocopy-derive"
 description: "Custom derive for traits from the zerocopy crate"
@@ -8,13 +8,13 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 5
-    day: 31
+    month: 9
+    day: 5
   }
   homepage: "https://crates.io/crates/zerocopy-derive"
   identifier {
     type: "Archive"
-    value: "https://static.crates.io/crates/zerocopy-derive/zerocopy-derive-0.7.34.crate"
-    version: "0.7.34"
+    value: "https://static.crates.io/crates/zerocopy-derive/zerocopy-derive-0.7.35.crate"
+    version: "0.7.35"
   }
 }
diff --git a/patches/LICENSE.patch b/patches/LICENSE.patch
new file mode 100644
index 0000000..150d4e0
--- /dev/null
+++ b/patches/LICENSE.patch
@@ -0,0 +1,30 @@
+diff --git b/LICENSE a/LICENSE
+new file mode 100644
+index 0000000..7ed244f
+--- /dev/null
++++ a/LICENSE
+@@ -0,0 +1,24 @@
++Copyright 2019 The Fuchsia Authors.
++
++Redistribution and use in source and binary forms, with or without
++modification, are permitted provided that the following conditions are
++met:
++
++   * Redistributions of source code must retain the above copyright
++notice, this list of conditions and the following disclaimer.
++   * Redistributions in binary form must reproduce the above
++copyright notice, this list of conditions and the following disclaimer
++in the documentation and/or other materials provided with the
++distribution.
++
++THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
++"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
++LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
++A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
++OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
++SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
++LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
++DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
++THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
++(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
++OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
diff --git a/tests/ui-stable/derive_transparent.stderr b/tests/ui-stable/derive_transparent.stderr
index b13fffe..57d34cb 100644
--- a/tests/ui-stable/derive_transparent.stderr
+++ b/tests/ui-stable/derive_transparent.stderr
@@ -5,14 +5,14 @@ error[E0277]: the trait bound `NotZerocopy: FromZeroes` is not satisfied
    |                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ the trait `FromZeroes` is not implemented for `NotZerocopy`, which is required by `TransparentStruct<NotZerocopy>: FromZeroes`
    |
    = help: the following other types implement trait `FromZeroes`:
-             bool
-             char
-             isize
-             i8
-             i16
-             i32
-             i64
-             i128
+             ()
+             *const T
+             *mut T
+             AU16
+             F32<O>
+             F64<O>
+             I128<O>
+             I16<O>
            and $N others
 note: required for `TransparentStruct<NotZerocopy>` to implement `FromZeroes`
   --> tests/ui-stable/derive_transparent.rs:27:19
@@ -33,14 +33,14 @@ error[E0277]: the trait bound `NotZerocopy: FromBytes` is not satisfied
    |                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ the trait `FromBytes` is not implemented for `NotZerocopy`, which is required by `TransparentStruct<NotZerocopy>: FromBytes`
    |
    = help: the following other types implement trait `FromBytes`:
-             isize
-             i8
-             i16
-             i32
-             i64
-             i128
-             usize
-             u8
+             ()
+             AU16
+             F32<O>
+             F64<O>
+             I128<O>
+             I16<O>
+             I32<O>
+             I64<O>
            and $N others
 note: required for `TransparentStruct<NotZerocopy>` to implement `FromBytes`
   --> tests/ui-stable/derive_transparent.rs:27:31
@@ -61,14 +61,14 @@ error[E0277]: the trait bound `NotZerocopy: AsBytes` is not satisfied
    |                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ the trait `AsBytes` is not implemented for `NotZerocopy`, which is required by `TransparentStruct<NotZerocopy>: AsBytes`
    |
    = help: the following other types implement trait `AsBytes`:
-             bool
-             char
-             isize
-             i8
-             i16
-             i32
-             i64
-             i128
+             ()
+             AU16
+             F32<O>
+             F64<O>
+             I128<O>
+             I16<O>
+             I32<O>
+             I64<O>
            and $N others
 note: required for `TransparentStruct<NotZerocopy>` to implement `AsBytes`
   --> tests/ui-stable/derive_transparent.rs:27:10
@@ -89,14 +89,14 @@ error[E0277]: the trait bound `NotZerocopy: Unaligned` is not satisfied
    |                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ the trait `Unaligned` is not implemented for `NotZerocopy`, which is required by `TransparentStruct<NotZerocopy>: Unaligned`
    |
    = help: the following other types implement trait `Unaligned`:
-             bool
-             i8
-             u8
-             TransparentStruct<T>
-             NonZero<i8>
-             NonZero<u8>
-             U16<O>
-             U32<O>
+             ()
+             F32<O>
+             F64<O>
+             I128<O>
+             I16<O>
+             I32<O>
+             I64<O>
+             ManuallyDrop<T>
            and $N others
 note: required for `TransparentStruct<NotZerocopy>` to implement `Unaligned`
   --> tests/ui-stable/derive_transparent.rs:27:42
diff --git a/tests/ui-stable/late_compile_pass.stderr b/tests/ui-stable/late_compile_pass.stderr
index e16638b..0c66ae5 100644
--- a/tests/ui-stable/late_compile_pass.stderr
+++ b/tests/ui-stable/late_compile_pass.stderr
@@ -13,14 +13,14 @@ error[E0277]: the trait bound `NotZerocopy: FromZeroes` is not satisfied
    |          ^^^^^^^^^^ the trait `FromZeroes` is not implemented for `NotZerocopy`
    |
    = help: the following other types implement trait `FromZeroes`:
-             bool
-             char
-             isize
-             i8
-             i16
-             i32
-             i64
-             i128
+             ()
+             *const T
+             *mut T
+             AU16
+             F32<O>
+             F64<O>
+             FromZeroes1
+             I128<O>
            and $N others
    = help: see issue #48214
    = note: this error originates in the derive macro `FromZeroes` (in Nightly builds, run with -Z macro-backtrace for more info)
@@ -32,14 +32,14 @@ error[E0277]: the trait bound `NotZerocopy: FromBytes` is not satisfied
    |          ^^^^^^^^^ the trait `FromBytes` is not implemented for `NotZerocopy`
    |
    = help: the following other types implement trait `FromBytes`:
-             isize
-             i8
-             i16
-             i32
-             i64
-             i128
-             usize
-             u8
+             ()
+             AU16
+             F32<O>
+             F64<O>
+             FromBytes1
+             I128<O>
+             I16<O>
+             I32<O>
            and $N others
    = help: see issue #48214
    = note: this error originates in the derive macro `FromBytes` (in Nightly builds, run with -Z macro-backtrace for more info)
@@ -51,14 +51,14 @@ error[E0277]: the trait bound `FromBytes1: FromZeroes` is not satisfied
    |          ^^^^^^^^^ the trait `FromZeroes` is not implemented for `FromBytes1`
    |
    = help: the following other types implement trait `FromZeroes`:
-             bool
-             char
-             isize
-             i8
-             i16
-             i32
-             i64
-             i128
+             ()
+             *const T
+             *mut T
+             AU16
+             F32<O>
+             F64<O>
+             FromZeroes1
+             I128<O>
            and $N others
 note: required by a bound in `FromBytes`
   --> $WORKSPACE/src/lib.rs
@@ -74,14 +74,14 @@ error[E0277]: the trait bound `NotZerocopy: AsBytes` is not satisfied
    |          ^^^^^^^ the trait `AsBytes` is not implemented for `NotZerocopy`
    |
    = help: the following other types implement trait `AsBytes`:
-             bool
-             char
-             isize
-             i8
-             i16
-             i32
-             i64
-             i128
+             ()
+             AU16
+             AsBytes1
+             F32<O>
+             F64<O>
+             I128<O>
+             I16<O>
+             I32<O>
            and $N others
    = help: see issue #48214
    = note: this error originates in the derive macro `AsBytes` (in Nightly builds, run with -Z macro-backtrace for more info)
@@ -93,14 +93,14 @@ error[E0277]: the trait bound `AU16: Unaligned` is not satisfied
    |          ^^^^^^^^^ the trait `Unaligned` is not implemented for `AU16`
    |
    = help: the following other types implement trait `Unaligned`:
-             bool
-             i8
-             u8
-             Unaligned1
-             Unaligned2
-             Unaligned3
-             NonZero<i8>
-             NonZero<u8>
+             ()
+             F32<O>
+             F64<O>
+             I128<O>
+             I16<O>
+             I32<O>
+             I64<O>
+             ManuallyDrop<T>
            and $N others
    = help: see issue #48214
    = note: this error originates in the derive macro `Unaligned` (in Nightly builds, run with -Z macro-backtrace for more info)
@@ -112,14 +112,14 @@ error[E0277]: the trait bound `AU16: Unaligned` is not satisfied
    |          ^^^^^^^^^ the trait `Unaligned` is not implemented for `AU16`
    |
    = help: the following other types implement trait `Unaligned`:
-             bool
-             i8
-             u8
-             Unaligned1
-             Unaligned2
-             Unaligned3
-             NonZero<i8>
-             NonZero<u8>
+             ()
+             F32<O>
+             F64<O>
+             I128<O>
+             I16<O>
+             I32<O>
+             I64<O>
+             ManuallyDrop<T>
            and $N others
    = help: see issue #48214
    = note: this error originates in the derive macro `Unaligned` (in Nightly builds, run with -Z macro-backtrace for more info)
@@ -131,14 +131,14 @@ error[E0277]: the trait bound `AU16: Unaligned` is not satisfied
    |          ^^^^^^^^^ the trait `Unaligned` is not implemented for `AU16`
    |
    = help: the following other types implement trait `Unaligned`:
-             bool
-             i8
-             u8
-             Unaligned1
-             Unaligned2
-             Unaligned3
-             NonZero<i8>
-             NonZero<u8>
+             ()
+             F32<O>
+             F64<O>
+             I128<O>
+             I16<O>
+             I32<O>
+             I64<O>
+             ManuallyDrop<T>
            and $N others
    = help: see issue #48214
    = note: this error originates in the derive macro `Unaligned` (in Nightly builds, run with -Z macro-backtrace for more info)
diff --git a/tests/ui-stable/struct.stderr b/tests/ui-stable/struct.stderr
index b4c003b..c1e95af 100644
--- a/tests/ui-stable/struct.stderr
+++ b/tests/ui-stable/struct.stderr
@@ -79,14 +79,14 @@ error[E0277]: the trait bound `NotKnownLayoutDst: KnownLayout` is not satisfied
    |          ^^^^^^^^^^^ the trait `KnownLayout` is not implemented for `NotKnownLayoutDst`
    |
    = help: the following other types implement trait `KnownLayout`:
-             bool
-             char
-             isize
-             i8
-             i16
-             i32
-             i64
-             i128
+             ()
+             *const T
+             *mut T
+             AU16
+             F32<O>
+             F64<O>
+             I128<O>
+             I16<O>
            and $N others
    = help: see issue #48214
    = note: this error originates in the derive macro `KnownLayout` (in Nightly builds, run with -Z macro-backtrace for more info)
@@ -98,14 +98,14 @@ error[E0277]: the trait bound `NotKnownLayout: KnownLayout` is not satisfied
    |          ^^^^^^^^^^^ the trait `KnownLayout` is not implemented for `NotKnownLayout`
    |
    = help: the following other types implement trait `KnownLayout`:
-             bool
-             char
-             isize
-             i8
-             i16
-             i32
-             i64
-             i128
+             ()
+             *const T
+             *mut T
+             AU16
+             F32<O>
+             F64<O>
+             I128<O>
+             I16<O>
            and $N others
    = help: see issue #48214
    = note: this error originates in the derive macro `KnownLayout` (in Nightly builds, run with -Z macro-backtrace for more info)
```
