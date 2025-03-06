```diff
diff --git a/include/bootimg/bootimg.h b/include/bootimg/bootimg.h
index 8ad95a8..67ae349 100644
--- a/include/bootimg/bootimg.h
+++ b/include/bootimg/bootimg.h
@@ -1,17 +1,30 @@
 /*
  * Copyright (C) 2007 The Android Open Source Project
  *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
+ * Redistribution and use in source and binary forms, with or without modification,
+ * are permitted provided that the following conditions are met:
  *
- *      http://www.apache.org/licenses/LICENSE-2.0
+ * 1. Redistributions of source code must retain the above copyright notice, this
+ *    list of conditions and the following disclaimer.
  *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
+ * 2. Redistributions in binary form must reproduce the above copyright notice,
+ *    this list of conditions and the following disclaimer in the documentation
+ *    and/or other materials provided with the distribution.
+ *
+ * 3. Neither the name of the copyright holder nor the names of its contributors
+ *    may be used to endorse or promote products derived from this software without
+ *    specific prior written permission.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
+ * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
+ * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
+ * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
+ * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+ * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
+ * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
+ * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+ * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
+ * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  */
 
 #pragma once
diff --git a/rust/Android.bp b/rust/Android.bp
index 353070e..d232eec 100644
--- a/rust/Android.bp
+++ b/rust/Android.bp
@@ -4,26 +4,25 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-rust_defaults {
-    name: "libbootimg_private_defaults",
-    srcs: ["bootimg_priv.rs"],
+rust_bindgen {
+    name: "libbootimg_bindgen",
+    wrapper_src: "bindgen/bootimg.hpp",
+    crate_name: "bootimg_bindgen",
+    edition: "2021",
+    source_stem: "bindings",
+    bindgen_flags: [
+        "--ctypes-prefix=core::ffi",
+        "--use-core",
+        "--with-derive-default",
+        "--blocklist-type=__.+|.?int.+",
+        "--blocklist-item=_.+|.?INT.+|PTR.+|ATOMIC.+|.+SOURCE|.+_H|SIG_.+|SIZE_.+|.?CHAR.+",
+        "--with-derive-custom-struct=(vendor_)?(boot_img_hdr|ramdisk_table_entry)_v\\d+=AsBytes,FromBytes,FromZeroes,PartialEq,Copy,Clone,Debug",
+        "--raw-line=use zerocopy::{AsBytes, FromBytes, FromZeroes};",
+    ],
+    header_libs: ["bootimg_headers"],
     rustlibs: ["libzerocopy"],
-    lints: "none",
-}
-
-rust_library {
-    name: "libbootimg_private",
-    crate_name: "bootimg_private",
     vendor_available: true,
-    defaults: ["libbootimg_private_defaults"],
     host_supported: true,
-    visibility: [":__subpackages__"],
-}
-
-rust_test_host {
-    name: "libbootimg_tests_priv",
-    auto_gen_config: true,
-    defaults: ["libbootimg_private_defaults"],
 }
 
 rust_defaults {
@@ -31,7 +30,7 @@ rust_defaults {
     srcs: ["bootimg.rs"],
     rustlibs: [
         "libzerocopy",
-        "libbootimg_private",
+        "libbootimg_bindgen",
     ],
 }
 
diff --git a/rust/OWNERS b/rust/OWNERS
new file mode 100644
index 0000000..9661fc7
--- /dev/null
+++ b/rust/OWNERS
@@ -0,0 +1,3 @@
+dimorinny@google.com
+dovs@google.com
+dpursell@google.com
diff --git a/rust/bindgen.sh b/rust/bindgen.sh
deleted file mode 100755
index 6e75618..0000000
--- a/rust/bindgen.sh
+++ /dev/null
@@ -1,76 +0,0 @@
-#! /usr/bin/env bash
-# Copyright 2023, The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-set -e
-
-# Run this script to regenerate bootimg_priv.rs if
-# include/bootimg/bootimg.h ever changes.
-# The rust_bindgen rule is not cooperative, causing custom derive types
-# to not percolate to the generated structures.
-# It's just easier to do all the munging in a script.
-
-SCRATCH_DIR=$(mktemp -d)
-
-cleanup (){
-    rm -rf ${SCRATCH_DIR}
-}
-
-trap cleanup EXIT
-pushd ~/aosp > /dev/null
-
-BOOTIMG_DIR=$(realpath system/tools/mkbootimg/)
-# The stdint include generates a lot of unnecessary types that the
-# generated rust bindings really don't need.
-BLOCKED_TYPES_RE="__.+|.?int.+"
-# The stdint include generates a lot of unnecessary constants that the
-# generated rust bindings really don't need.
-BLOCKED_ITEMS_RE="_.+|.?INT.+|PTR.+|ATOMIC.+|.+SOURCE|.+_H|SIG_.+|SIZE_.+|.?CHAR.+"
-CUSTOM_STRUCT_RE="(vendor_)?(boot_img_hdr|ramdisk_table_entry)_v\d+"
-CUSTOM_STRUCT_DERIVES="AsBytes,FromBytes,FromZeroes,PartialEq,Copy,Clone,Debug"
-BINDGEN_FLAGS="--use-core --with-derive-default"
-BOOTIMG_PRIV=${BOOTIMG_DIR}/rust/bootimg_priv.rs
-
-# We need C++ isms, and the only obvious way to convince bindgen
-# that the source is C++ is with a C++ extension.
-cp ${BOOTIMG_DIR}/include/bootimg/bootimg.h ${SCRATCH_DIR}/bootimg.hpp
-
-./out/host/linux-x86/bin/bindgen \
-    --blocklist-type="${BLOCKED_TYPES_RE}" \
-    --blocklist-item="${BLOCKED_ITEMS_RE}" \
-    --with-derive-custom-struct="${CUSTOM_STRUCT_RE}=${CUSTOM_STRUCT_DERIVES}" \
-    ${BINDGEN_FLAGS} \
-    ${SCRATCH_DIR}/bootimg.hpp \
-    -o ${SCRATCH_DIR}/bootimg_gen.rs
-
-cat << EOF | cat - ${SCRATCH_DIR}/bootimg_gen.rs > ${BOOTIMG_PRIV}
-// Copyright $(date +%Y), The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-use zerocopy::{AsBytes, FromBytes, FromZeroes};
-
-EOF
-
-rustfmt ${BOOTIMG_PRIV} --config-path system/tools/aidl/rustfmt.toml
diff --git a/rust/bindgen/bootimg.hpp b/rust/bindgen/bootimg.hpp
new file mode 100644
index 0000000..bf73e8f
--- /dev/null
+++ b/rust/bindgen/bootimg.hpp
@@ -0,0 +1,21 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+// Use .hpp to let the rust bindgen know that bootimg.h is a C++ header.
+
+#pragma once
+
+#include <bootimg.h>
diff --git a/rust/bootimg.rs b/rust/bootimg.rs
index bc83eb1..72f0d0c 100644
--- a/rust/bootimg.rs
+++ b/rust/bootimg.rs
@@ -15,7 +15,7 @@
 //! The public interface for bootimg structs
 use zerocopy::{ByteSlice, LayoutVerified};
 
-use bootimg_private::{
+use bootimg_bindgen::{
     boot_img_hdr_v0, boot_img_hdr_v1, boot_img_hdr_v2, boot_img_hdr_v3, boot_img_hdr_v4,
     vendor_boot_img_hdr_v3, vendor_boot_img_hdr_v4, BOOT_MAGIC, BOOT_MAGIC_SIZE, VENDOR_BOOT_MAGIC,
     VENDOR_BOOT_MAGIC_SIZE,
diff --git a/rust/bootimg_priv.rs b/rust/bootimg_priv.rs
deleted file mode 100644
index 15fd0d9..0000000
--- a/rust/bootimg_priv.rs
+++ /dev/null
@@ -1,669 +0,0 @@
-// Copyright 2023, The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-use zerocopy::{AsBytes, FromBytes, FromZeroes};
-
-/* automatically generated by rust-bindgen 0.65.1 */
-
-pub const BOOT_MAGIC: &[u8; 9usize] = b"ANDROID!\0";
-pub const BOOT_MAGIC_SIZE: u32 = 8;
-pub const BOOT_NAME_SIZE: u32 = 16;
-pub const BOOT_ARGS_SIZE: u32 = 512;
-pub const BOOT_EXTRA_ARGS_SIZE: u32 = 1024;
-pub const VENDOR_BOOT_MAGIC: &[u8; 9usize] = b"VNDRBOOT\0";
-pub const VENDOR_BOOT_MAGIC_SIZE: u32 = 8;
-pub const VENDOR_BOOT_ARGS_SIZE: u32 = 2048;
-pub const VENDOR_BOOT_NAME_SIZE: u32 = 16;
-pub const VENDOR_RAMDISK_TYPE_NONE: u32 = 0;
-pub const VENDOR_RAMDISK_TYPE_PLATFORM: u32 = 1;
-pub const VENDOR_RAMDISK_TYPE_RECOVERY: u32 = 2;
-pub const VENDOR_RAMDISK_TYPE_DLKM: u32 = 3;
-pub const VENDOR_RAMDISK_NAME_SIZE: u32 = 32;
-pub const VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE: u32 = 16;
-#[repr(C, packed)]
-#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Copy, Clone, Debug)]
-pub struct boot_img_hdr_v0 {
-    pub magic: [u8; 8usize],
-    pub kernel_size: u32,
-    pub kernel_addr: u32,
-    pub ramdisk_size: u32,
-    pub ramdisk_addr: u32,
-    pub second_size: u32,
-    pub second_addr: u32,
-    pub tags_addr: u32,
-    pub page_size: u32,
-    pub header_version: u32,
-    pub os_version: u32,
-    pub name: [u8; 16usize],
-    pub cmdline: [u8; 512usize],
-    pub id: [u32; 8usize],
-    pub extra_cmdline: [u8; 1024usize],
-}
-#[test]
-fn bindgen_test_layout_boot_img_hdr_v0() {
-    const UNINIT: ::core::mem::MaybeUninit<boot_img_hdr_v0> = ::core::mem::MaybeUninit::uninit();
-    let ptr = UNINIT.as_ptr();
-    assert_eq!(
-        ::core::mem::size_of::<boot_img_hdr_v0>(),
-        1632usize,
-        concat!("Size of: ", stringify!(boot_img_hdr_v0))
-    );
-    assert_eq!(
-        ::core::mem::align_of::<boot_img_hdr_v0>(),
-        1usize,
-        concat!("Alignment of ", stringify!(boot_img_hdr_v0))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).magic) as usize - ptr as usize },
-        0usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(magic))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).kernel_size) as usize - ptr as usize },
-        8usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(kernel_size))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).kernel_addr) as usize - ptr as usize },
-        12usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(kernel_addr))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).ramdisk_size) as usize - ptr as usize },
-        16usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(ramdisk_size))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).ramdisk_addr) as usize - ptr as usize },
-        20usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(ramdisk_addr))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).second_size) as usize - ptr as usize },
-        24usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(second_size))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).second_addr) as usize - ptr as usize },
-        28usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(second_addr))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).tags_addr) as usize - ptr as usize },
-        32usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(tags_addr))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).page_size) as usize - ptr as usize },
-        36usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(page_size))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).header_version) as usize - ptr as usize },
-        40usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(header_version))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).os_version) as usize - ptr as usize },
-        44usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(os_version))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).name) as usize - ptr as usize },
-        48usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(name))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).cmdline) as usize - ptr as usize },
-        64usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(cmdline))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).id) as usize - ptr as usize },
-        576usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(id))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).extra_cmdline) as usize - ptr as usize },
-        608usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v0), "::", stringify!(extra_cmdline))
-    );
-}
-impl Default for boot_img_hdr_v0 {
-    fn default() -> Self {
-        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
-        unsafe {
-            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
-            s.assume_init()
-        }
-    }
-}
-pub type boot_img_hdr = boot_img_hdr_v0;
-#[repr(C, packed)]
-#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Copy, Clone, Debug)]
-pub struct boot_img_hdr_v1 {
-    pub _base: boot_img_hdr_v0,
-    pub recovery_dtbo_size: u32,
-    pub recovery_dtbo_offset: u64,
-    pub header_size: u32,
-}
-#[test]
-fn bindgen_test_layout_boot_img_hdr_v1() {
-    const UNINIT: ::core::mem::MaybeUninit<boot_img_hdr_v1> = ::core::mem::MaybeUninit::uninit();
-    let ptr = UNINIT.as_ptr();
-    assert_eq!(
-        ::core::mem::size_of::<boot_img_hdr_v1>(),
-        1648usize,
-        concat!("Size of: ", stringify!(boot_img_hdr_v1))
-    );
-    assert_eq!(
-        ::core::mem::align_of::<boot_img_hdr_v1>(),
-        1usize,
-        concat!("Alignment of ", stringify!(boot_img_hdr_v1))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).recovery_dtbo_size) as usize - ptr as usize },
-        1632usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(boot_img_hdr_v1),
-            "::",
-            stringify!(recovery_dtbo_size)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).recovery_dtbo_offset) as usize - ptr as usize },
-        1636usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(boot_img_hdr_v1),
-            "::",
-            stringify!(recovery_dtbo_offset)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).header_size) as usize - ptr as usize },
-        1644usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v1), "::", stringify!(header_size))
-    );
-}
-impl Default for boot_img_hdr_v1 {
-    fn default() -> Self {
-        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
-        unsafe {
-            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
-            s.assume_init()
-        }
-    }
-}
-#[repr(C, packed)]
-#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Copy, Clone, Debug)]
-pub struct boot_img_hdr_v2 {
-    pub _base: boot_img_hdr_v1,
-    pub dtb_size: u32,
-    pub dtb_addr: u64,
-}
-#[test]
-fn bindgen_test_layout_boot_img_hdr_v2() {
-    const UNINIT: ::core::mem::MaybeUninit<boot_img_hdr_v2> = ::core::mem::MaybeUninit::uninit();
-    let ptr = UNINIT.as_ptr();
-    assert_eq!(
-        ::core::mem::size_of::<boot_img_hdr_v2>(),
-        1660usize,
-        concat!("Size of: ", stringify!(boot_img_hdr_v2))
-    );
-    assert_eq!(
-        ::core::mem::align_of::<boot_img_hdr_v2>(),
-        1usize,
-        concat!("Alignment of ", stringify!(boot_img_hdr_v2))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).dtb_size) as usize - ptr as usize },
-        1648usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v2), "::", stringify!(dtb_size))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).dtb_addr) as usize - ptr as usize },
-        1652usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v2), "::", stringify!(dtb_addr))
-    );
-}
-impl Default for boot_img_hdr_v2 {
-    fn default() -> Self {
-        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
-        unsafe {
-            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
-            s.assume_init()
-        }
-    }
-}
-#[repr(C, packed)]
-#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Copy, Clone, Debug)]
-pub struct boot_img_hdr_v3 {
-    pub magic: [u8; 8usize],
-    pub kernel_size: u32,
-    pub ramdisk_size: u32,
-    pub os_version: u32,
-    pub header_size: u32,
-    pub reserved: [u32; 4usize],
-    pub header_version: u32,
-    pub cmdline: [u8; 1536usize],
-}
-#[test]
-fn bindgen_test_layout_boot_img_hdr_v3() {
-    const UNINIT: ::core::mem::MaybeUninit<boot_img_hdr_v3> = ::core::mem::MaybeUninit::uninit();
-    let ptr = UNINIT.as_ptr();
-    assert_eq!(
-        ::core::mem::size_of::<boot_img_hdr_v3>(),
-        1580usize,
-        concat!("Size of: ", stringify!(boot_img_hdr_v3))
-    );
-    assert_eq!(
-        ::core::mem::align_of::<boot_img_hdr_v3>(),
-        1usize,
-        concat!("Alignment of ", stringify!(boot_img_hdr_v3))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).magic) as usize - ptr as usize },
-        0usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v3), "::", stringify!(magic))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).kernel_size) as usize - ptr as usize },
-        8usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v3), "::", stringify!(kernel_size))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).ramdisk_size) as usize - ptr as usize },
-        12usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v3), "::", stringify!(ramdisk_size))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).os_version) as usize - ptr as usize },
-        16usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v3), "::", stringify!(os_version))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).header_size) as usize - ptr as usize },
-        20usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v3), "::", stringify!(header_size))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).reserved) as usize - ptr as usize },
-        24usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v3), "::", stringify!(reserved))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).header_version) as usize - ptr as usize },
-        40usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v3), "::", stringify!(header_version))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).cmdline) as usize - ptr as usize },
-        44usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v3), "::", stringify!(cmdline))
-    );
-}
-impl Default for boot_img_hdr_v3 {
-    fn default() -> Self {
-        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
-        unsafe {
-            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
-            s.assume_init()
-        }
-    }
-}
-#[repr(C, packed)]
-#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Copy, Clone, Debug)]
-pub struct vendor_boot_img_hdr_v3 {
-    pub magic: [u8; 8usize],
-    pub header_version: u32,
-    pub page_size: u32,
-    pub kernel_addr: u32,
-    pub ramdisk_addr: u32,
-    pub vendor_ramdisk_size: u32,
-    pub cmdline: [u8; 2048usize],
-    pub tags_addr: u32,
-    pub name: [u8; 16usize],
-    pub header_size: u32,
-    pub dtb_size: u32,
-    pub dtb_addr: u64,
-}
-#[test]
-fn bindgen_test_layout_vendor_boot_img_hdr_v3() {
-    const UNINIT: ::core::mem::MaybeUninit<vendor_boot_img_hdr_v3> =
-        ::core::mem::MaybeUninit::uninit();
-    let ptr = UNINIT.as_ptr();
-    assert_eq!(
-        ::core::mem::size_of::<vendor_boot_img_hdr_v3>(),
-        2112usize,
-        concat!("Size of: ", stringify!(vendor_boot_img_hdr_v3))
-    );
-    assert_eq!(
-        ::core::mem::align_of::<vendor_boot_img_hdr_v3>(),
-        1usize,
-        concat!("Alignment of ", stringify!(vendor_boot_img_hdr_v3))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).magic) as usize - ptr as usize },
-        0usize,
-        concat!("Offset of field: ", stringify!(vendor_boot_img_hdr_v3), "::", stringify!(magic))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).header_version) as usize - ptr as usize },
-        8usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v3),
-            "::",
-            stringify!(header_version)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).page_size) as usize - ptr as usize },
-        12usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v3),
-            "::",
-            stringify!(page_size)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).kernel_addr) as usize - ptr as usize },
-        16usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v3),
-            "::",
-            stringify!(kernel_addr)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).ramdisk_addr) as usize - ptr as usize },
-        20usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v3),
-            "::",
-            stringify!(ramdisk_addr)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).vendor_ramdisk_size) as usize - ptr as usize },
-        24usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v3),
-            "::",
-            stringify!(vendor_ramdisk_size)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).cmdline) as usize - ptr as usize },
-        28usize,
-        concat!("Offset of field: ", stringify!(vendor_boot_img_hdr_v3), "::", stringify!(cmdline))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).tags_addr) as usize - ptr as usize },
-        2076usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v3),
-            "::",
-            stringify!(tags_addr)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).name) as usize - ptr as usize },
-        2080usize,
-        concat!("Offset of field: ", stringify!(vendor_boot_img_hdr_v3), "::", stringify!(name))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).header_size) as usize - ptr as usize },
-        2096usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v3),
-            "::",
-            stringify!(header_size)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).dtb_size) as usize - ptr as usize },
-        2100usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v3),
-            "::",
-            stringify!(dtb_size)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).dtb_addr) as usize - ptr as usize },
-        2104usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v3),
-            "::",
-            stringify!(dtb_addr)
-        )
-    );
-}
-impl Default for vendor_boot_img_hdr_v3 {
-    fn default() -> Self {
-        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
-        unsafe {
-            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
-            s.assume_init()
-        }
-    }
-}
-#[repr(C, packed)]
-#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Copy, Clone, Debug)]
-pub struct boot_img_hdr_v4 {
-    pub _base: boot_img_hdr_v3,
-    pub signature_size: u32,
-}
-#[test]
-fn bindgen_test_layout_boot_img_hdr_v4() {
-    const UNINIT: ::core::mem::MaybeUninit<boot_img_hdr_v4> = ::core::mem::MaybeUninit::uninit();
-    let ptr = UNINIT.as_ptr();
-    assert_eq!(
-        ::core::mem::size_of::<boot_img_hdr_v4>(),
-        1584usize,
-        concat!("Size of: ", stringify!(boot_img_hdr_v4))
-    );
-    assert_eq!(
-        ::core::mem::align_of::<boot_img_hdr_v4>(),
-        1usize,
-        concat!("Alignment of ", stringify!(boot_img_hdr_v4))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).signature_size) as usize - ptr as usize },
-        1580usize,
-        concat!("Offset of field: ", stringify!(boot_img_hdr_v4), "::", stringify!(signature_size))
-    );
-}
-impl Default for boot_img_hdr_v4 {
-    fn default() -> Self {
-        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
-        unsafe {
-            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
-            s.assume_init()
-        }
-    }
-}
-#[repr(C, packed)]
-#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Copy, Clone, Debug)]
-pub struct vendor_boot_img_hdr_v4 {
-    pub _base: vendor_boot_img_hdr_v3,
-    pub vendor_ramdisk_table_size: u32,
-    pub vendor_ramdisk_table_entry_num: u32,
-    pub vendor_ramdisk_table_entry_size: u32,
-    pub bootconfig_size: u32,
-}
-#[test]
-fn bindgen_test_layout_vendor_boot_img_hdr_v4() {
-    const UNINIT: ::core::mem::MaybeUninit<vendor_boot_img_hdr_v4> =
-        ::core::mem::MaybeUninit::uninit();
-    let ptr = UNINIT.as_ptr();
-    assert_eq!(
-        ::core::mem::size_of::<vendor_boot_img_hdr_v4>(),
-        2128usize,
-        concat!("Size of: ", stringify!(vendor_boot_img_hdr_v4))
-    );
-    assert_eq!(
-        ::core::mem::align_of::<vendor_boot_img_hdr_v4>(),
-        1usize,
-        concat!("Alignment of ", stringify!(vendor_boot_img_hdr_v4))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).vendor_ramdisk_table_size) as usize - ptr as usize },
-        2112usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v4),
-            "::",
-            stringify!(vendor_ramdisk_table_size)
-        )
-    );
-    assert_eq!(
-        unsafe {
-            ::core::ptr::addr_of!((*ptr).vendor_ramdisk_table_entry_num) as usize - ptr as usize
-        },
-        2116usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v4),
-            "::",
-            stringify!(vendor_ramdisk_table_entry_num)
-        )
-    );
-    assert_eq!(
-        unsafe {
-            ::core::ptr::addr_of!((*ptr).vendor_ramdisk_table_entry_size) as usize - ptr as usize
-        },
-        2120usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v4),
-            "::",
-            stringify!(vendor_ramdisk_table_entry_size)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).bootconfig_size) as usize - ptr as usize },
-        2124usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_boot_img_hdr_v4),
-            "::",
-            stringify!(bootconfig_size)
-        )
-    );
-}
-impl Default for vendor_boot_img_hdr_v4 {
-    fn default() -> Self {
-        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
-        unsafe {
-            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
-            s.assume_init()
-        }
-    }
-}
-#[repr(C, packed)]
-#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Copy, Clone, Debug)]
-pub struct vendor_ramdisk_table_entry_v4 {
-    pub ramdisk_size: u32,
-    pub ramdisk_offset: u32,
-    pub ramdisk_type: u32,
-    pub ramdisk_name: [u8; 32usize],
-    pub board_id: [u32; 16usize],
-}
-#[test]
-fn bindgen_test_layout_vendor_ramdisk_table_entry_v4() {
-    const UNINIT: ::core::mem::MaybeUninit<vendor_ramdisk_table_entry_v4> =
-        ::core::mem::MaybeUninit::uninit();
-    let ptr = UNINIT.as_ptr();
-    assert_eq!(
-        ::core::mem::size_of::<vendor_ramdisk_table_entry_v4>(),
-        108usize,
-        concat!("Size of: ", stringify!(vendor_ramdisk_table_entry_v4))
-    );
-    assert_eq!(
-        ::core::mem::align_of::<vendor_ramdisk_table_entry_v4>(),
-        1usize,
-        concat!("Alignment of ", stringify!(vendor_ramdisk_table_entry_v4))
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).ramdisk_size) as usize - ptr as usize },
-        0usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_ramdisk_table_entry_v4),
-            "::",
-            stringify!(ramdisk_size)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).ramdisk_offset) as usize - ptr as usize },
-        4usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_ramdisk_table_entry_v4),
-            "::",
-            stringify!(ramdisk_offset)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).ramdisk_type) as usize - ptr as usize },
-        8usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_ramdisk_table_entry_v4),
-            "::",
-            stringify!(ramdisk_type)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).ramdisk_name) as usize - ptr as usize },
-        12usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_ramdisk_table_entry_v4),
-            "::",
-            stringify!(ramdisk_name)
-        )
-    );
-    assert_eq!(
-        unsafe { ::core::ptr::addr_of!((*ptr).board_id) as usize - ptr as usize },
-        44usize,
-        concat!(
-            "Offset of field: ",
-            stringify!(vendor_ramdisk_table_entry_v4),
-            "::",
-            stringify!(board_id)
-        )
-    );
-}
-impl Default for vendor_ramdisk_table_entry_v4 {
-    fn default() -> Self {
-        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
-        unsafe {
-            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
-            s.assume_init()
-        }
-    }
-}
```

