```diff
diff --git a/.cargo_vcs_info.json b/.cargo_vcs_info.json
index cb25ea3..efcfb9e 100644
--- a/.cargo_vcs_info.json
+++ b/.cargo_vcs_info.json
@@ -1,6 +1,6 @@
 {
   "git": {
-    "sha1": "4dbe66da6a922c64436a8f3a00a4ab1f0ebafbb6"
+    "sha1": "315350b7dd73e3bf4788c4475fe4602c18246824"
   },
   "path_in_vcs": "pdl-compiler"
 }
\ No newline at end of file
diff --git a/Android.bp b/Android.bp
index 1708971..9b003a3 100644
--- a/Android.bp
+++ b/Android.bp
@@ -5,9 +5,10 @@
 
 rust_library_host {
     name: "libpdl_compiler",
+    host_cross_supported: false,
     crate_name: "pdl_compiler",
     cargo_env_compat: true,
-    cargo_pkg_version: "0.3.0",
+    cargo_pkg_version: "0.3.1",
     crate_root: "src/lib.rs",
     edition: "2021",
     features: [
@@ -32,6 +33,7 @@ rust_library_host {
 
 rust_binary_host {
     name: "pdlc",
+    host_cross_supported: false,
     crate_name: "pdlc",
     cargo_env_compat: true,
     cargo_pkg_version: "0.3.0",
@@ -120,6 +122,7 @@ filegroup {
 
 rust_test_host {
     name: "pdl_tests",
+    host_cross_supported: false,
     srcs: ["src/main.rs"],
     rustlibs: [
         "libargh",
diff --git a/Cargo.toml b/Cargo.toml
index c89b1ff..41974b5 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -12,7 +12,7 @@
 [package]
 edition = "2021"
 name = "pdl-compiler"
-version = "0.3.0"
+version = "0.3.1"
 authors = [
     "Henri Chataing <henrichataing@google.com>",
     "David de Jesus Duarte <licorne@google.com>",
diff --git a/Cargo.toml.orig b/Cargo.toml.orig
index bfd1edf..7d9ea31 100644
--- a/Cargo.toml.orig
+++ b/Cargo.toml.orig
@@ -1,6 +1,6 @@
 [package]
 name = "pdl-compiler"
-version = "0.3.0"
+version = "0.3.1"
 edition = "2021"
 description = "Parser and serializer generator for protocol binary packets"
 repository = "https://github.com/google/pdl/"
diff --git a/METADATA b/METADATA
index 8ffef1d..5d40f30 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 5
-    day: 29
+    month: 7
+    day: 15
   }
   homepage: "https://crates.io/crates/pdl-compiler"
   identifier {
     type: "Archive"
-    value: "https://static.crates.io/crates/pdl-compiler/pdl-compiler-0.3.0.crate"
-    version: "0.3.0"
+    value: "https://static.crates.io/crates/pdl-compiler/pdl-compiler-0.3.1.crate"
+    version: "0.3.1"
   }
 }
diff --git a/cargo2android_toplevel.bp b/cargo2android_toplevel.bp
index f94b16d..566e400 100644
--- a/cargo2android_toplevel.bp
+++ b/cargo2android_toplevel.bp
@@ -60,6 +60,7 @@ filegroup {
 
 rust_test_host {
     name: "pdl_tests",
+    host_cross_supported: false,
     srcs: ["src/main.rs"],
     rustlibs: [
         "libargh",
diff --git a/patches/0001-Add-scripts-Android.bp.patch b/patches/0001-Add-scripts-Android.bp.patch
deleted file mode 100644
index 30817f9..0000000
--- a/patches/0001-Add-scripts-Android.bp.patch
+++ /dev/null
@@ -1,78 +0,0 @@
-From 0a7535a664dee90b5f773d8966d4cebb5971bb9d Mon Sep 17 00:00:00 2001
-From: Henri Chataing <henrichataing@google.com>
-Date: Wed, 26 Jul 2023 09:38:09 +0000
-Subject: [PATCH] Add scripts/Android.bp
-
-Change-Id: Iac28b4b30e99467733a65524609eae5e905b6b38
----
- scripts/Android.bp | 43 +++++++++++++++++++++++++++++++++++++++++++
- 1 file changed, 43 insertions(+)
- create mode 100644 scripts/Android.bp
-
-diff --git a/scripts/Android.bp b/scripts/Android.bp
-new file mode 100644
-index 0000000..bb0932c
---- /dev/null
-+++ b/scripts/Android.bp
-@@ -0,0 +1,58 @@
-+// Python generator.
-+python_binary_host {
-+    name: "pdl_python_generator",
-+    main: "generate_python_backend.py",
-+    srcs: [
-+        "generate_python_backend.py",
-+        "pdl/ast.py",
-+        "pdl/core.py",
-+        "pdl/utils.py",
-+    ],
-+    version: {
-+        py3: {
-+            embedded_launcher: true,
-+        },
-+    },
-+}
-+
-+// C++ generator.
-+python_binary_host {
-+    name: "pdl_cxx_generator",
-+    main: "generate_cxx_backend.py",
-+    srcs: [
-+        "generate_cxx_backend.py",
-+        "pdl/ast.py",
-+        "pdl/core.py",
-+        "pdl/utils.py",
-+    ],
-+    version: {
-+        py3: {
-+            embedded_launcher: true,
-+        },
-+    },
-+}
-+
-+// C++ test generator.
-+python_binary_host {
-+    name: "pdl_cxx_unittest_generator",
-+    main: "generate_cxx_backend_tests.py",
-+    srcs: [
-+        "generate_cxx_backend_tests.py",
-+        "pdl/ast.py",
-+        "pdl/core.py",
-+        "pdl/utils.py",
-+    ],
-+    version: {
-+        py3: {
-+            embedded_launcher: true,
-+        },
-+    },
-+}
-+
-+// C++ packet runtime.
-+cc_library_headers {
-+    name: "pdl_cxx_packet_runtime",
-+    export_include_dirs: ["."],
-+    host_supported: true,
-+    vendor_available: true,
-+}
---
-2.41.0.487.g6d72f3e995-goog
-
diff --git a/src/backends/rust/parser.rs b/src/backends/rust/decoder.rs
similarity index 100%
rename from src/backends/rust/parser.rs
rename to src/backends/rust/decoder.rs
diff --git a/src/backends/rust/serializer.rs b/src/backends/rust/encoder.rs
similarity index 98%
rename from src/backends/rust/serializer.rs
rename to src/backends/rust/encoder.rs
index c4b88e0..891ce8e 100644
--- a/src/backends/rust/serializer.rs
+++ b/src/backends/rust/encoder.rs
@@ -139,7 +139,7 @@ impl Encoder {
         });
 
         match schema.decl_size(decl.key) {
-            analyzer::Size::Static(s) => self.packet_size.constant += s,
+            analyzer::Size::Static(s) => self.packet_size.constant += s / 8,
             _ => self.packet_size.variable.push(quote! { self.#id.encoded_len() }),
         }
     }
@@ -539,9 +539,10 @@ impl Encoder {
         };
 
         let array_size = match element_width {
+            Some(8) => quote! { self.#id.len() },
             Some(element_width) => {
                 let element_size = proc_macro2::Literal::usize_unsuffixed(element_width / 8);
-                quote! { self.#id.len() * #element_size }
+                quote! { (self.#id.len() * #element_size) }
             }
             _ => {
                 quote! {
@@ -578,7 +579,11 @@ impl Encoder {
             }
         });
 
-        self.packet_size.variable.push(array_size)
+        if let Some(padding_size) = padding_size {
+            self.packet_size.constant += padding_size / 8;
+        } else {
+            self.packet_size.variable.push(array_size);
+        }
     }
 
     fn encode_field(
diff --git a/src/backends/rust/mod.rs b/src/backends/rust/mod.rs
index 0e57eb8..080fe7a 100644
--- a/src/backends/rust/mod.rs
+++ b/src/backends/rust/mod.rs
@@ -21,14 +21,14 @@ use std::collections::HashMap;
 use std::path::Path;
 use syn::LitInt;
 
-mod parser;
+mod decoder;
+mod encoder;
 mod preamble;
-mod serializer;
 pub mod test;
 mod types;
 
+use decoder::FieldParser;
 pub use heck::ToUpperCamelCase;
-use parser::FieldParser;
 
 pub trait ToIdent {
     /// Generate a sanitized rust identifier.
@@ -231,7 +231,7 @@ fn generate_root_packet_decl(
     }
 
     let (encode_fields, encoded_len) =
-        serializer::encode(scope, schema, endianness, "buf".to_ident(), decl);
+        encoder::encode(scope, schema, endianness, "buf".to_ident(), decl);
 
     let encode = quote! {
          fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
@@ -431,7 +431,7 @@ fn generate_derived_packet_decl(
     }
 
     let (partial_field_serializer, field_serializer, encoded_len) =
-        serializer::encode_partial(scope, schema, endianness, "buf".to_ident(), decl);
+        encoder::encode_partial(scope, schema, endianness, "buf".to_ident(), decl);
 
     let encode_partial = quote! {
         pub fn encode_partial(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
diff --git a/src/backends/rust/test.rs b/src/backends/rust/test.rs
index 0805024..2be688f 100644
--- a/src/backends/rust/test.rs
+++ b/src/backends/rust/test.rs
@@ -110,6 +110,7 @@ fn generate_unit_tests(input: &str, packet_names: &[&str]) -> Result<String, Str
                 fn #parse_test_name() {
                     let packed = #packed;
                     let actual = #packet_name::decode_full(&packed).unwrap();
+                    assert_eq!(actual.encoded_len(), packed.len());
                     #(#assertions)*
                 }
 
@@ -118,6 +119,7 @@ fn generate_unit_tests(input: &str, packet_names: &[&str]) -> Result<String, Str
                     let packet: #packet_name = serde_json::from_str(#json)
                         .expect("Could not create packet from canonical JSON data");
                     let packed: Vec<u8> = #packed;
+                    assert_eq!(packet.encoded_len(), packed.len());
                     assert_eq!(packet.encode_to_vec(), Ok(packed));
                 }
             });
diff --git a/tests/generated/rust/packet_decl_24bit_enum_array_big_endian.rs b/tests/generated/rust/packet_decl_24bit_enum_array_big_endian.rs
index 6fe68e4..7e4f43d 100644
--- a/tests/generated/rust/packet_decl_24bit_enum_array_big_endian.rs
+++ b/tests/generated/rust/packet_decl_24bit_enum_array_big_endian.rs
@@ -81,7 +81,7 @@ impl Bar {
 }
 impl Packet for Bar {
     fn encoded_len(&self) -> usize {
-        self.x.len() * 3
+        (self.x.len() * 3)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.x {
diff --git a/tests/generated/rust/packet_decl_24bit_enum_array_little_endian.rs b/tests/generated/rust/packet_decl_24bit_enum_array_little_endian.rs
index 2e863dd..f3248a0 100644
--- a/tests/generated/rust/packet_decl_24bit_enum_array_little_endian.rs
+++ b/tests/generated/rust/packet_decl_24bit_enum_array_little_endian.rs
@@ -81,7 +81,7 @@ impl Bar {
 }
 impl Packet for Bar {
     fn encoded_len(&self) -> usize {
-        self.x.len() * 3
+        (self.x.len() * 3)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.x {
diff --git a/tests/generated/rust/packet_decl_24bit_scalar_array_big_endian.rs b/tests/generated/rust/packet_decl_24bit_scalar_array_big_endian.rs
index 4cb8e6c..807f37c 100644
--- a/tests/generated/rust/packet_decl_24bit_scalar_array_big_endian.rs
+++ b/tests/generated/rust/packet_decl_24bit_scalar_array_big_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.x.len() * 3
+        (self.x.len() * 3)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.x {
diff --git a/tests/generated/rust/packet_decl_24bit_scalar_array_little_endian.rs b/tests/generated/rust/packet_decl_24bit_scalar_array_little_endian.rs
index 08f2cd5..315f7d5 100644
--- a/tests/generated/rust/packet_decl_24bit_scalar_array_little_endian.rs
+++ b/tests/generated/rust/packet_decl_24bit_scalar_array_little_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.x.len() * 3
+        (self.x.len() * 3)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.x {
diff --git a/tests/generated/rust/packet_decl_64bit_enum_array_big_endian.rs b/tests/generated/rust/packet_decl_64bit_enum_array_big_endian.rs
index f46a9bf..b8dce48 100644
--- a/tests/generated/rust/packet_decl_64bit_enum_array_big_endian.rs
+++ b/tests/generated/rust/packet_decl_64bit_enum_array_big_endian.rs
@@ -66,7 +66,7 @@ impl Bar {
 }
 impl Packet for Bar {
     fn encoded_len(&self) -> usize {
-        self.x.len() * 8
+        (self.x.len() * 8)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.x {
diff --git a/tests/generated/rust/packet_decl_64bit_enum_array_little_endian.rs b/tests/generated/rust/packet_decl_64bit_enum_array_little_endian.rs
index ee0ae20..23387af 100644
--- a/tests/generated/rust/packet_decl_64bit_enum_array_little_endian.rs
+++ b/tests/generated/rust/packet_decl_64bit_enum_array_little_endian.rs
@@ -66,7 +66,7 @@ impl Bar {
 }
 impl Packet for Bar {
     fn encoded_len(&self) -> usize {
-        self.x.len() * 8
+        (self.x.len() * 8)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.x {
diff --git a/tests/generated/rust/packet_decl_64bit_scalar_array_big_endian.rs b/tests/generated/rust/packet_decl_64bit_scalar_array_big_endian.rs
index 666de4b..1669c9a 100644
--- a/tests/generated/rust/packet_decl_64bit_scalar_array_big_endian.rs
+++ b/tests/generated/rust/packet_decl_64bit_scalar_array_big_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.x.len() * 8
+        (self.x.len() * 8)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.x {
diff --git a/tests/generated/rust/packet_decl_64bit_scalar_array_little_endian.rs b/tests/generated/rust/packet_decl_64bit_scalar_array_little_endian.rs
index a5ad742..2bb33b1 100644
--- a/tests/generated/rust/packet_decl_64bit_scalar_array_little_endian.rs
+++ b/tests/generated/rust/packet_decl_64bit_scalar_array_little_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.x.len() * 8
+        (self.x.len() * 8)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.x {
diff --git a/tests/generated/rust/packet_decl_8bit_enum_array_big_endian.rs b/tests/generated/rust/packet_decl_8bit_enum_array_big_endian.rs
index e48e5fc..0f63a9d 100644
--- a/tests/generated/rust/packet_decl_8bit_enum_array_big_endian.rs
+++ b/tests/generated/rust/packet_decl_8bit_enum_array_big_endian.rs
@@ -96,7 +96,7 @@ impl Bar {
 }
 impl Packet for Bar {
     fn encoded_len(&self) -> usize {
-        self.x.len() * 1
+        self.x.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.x {
diff --git a/tests/generated/rust/packet_decl_8bit_enum_array_little_endian.rs b/tests/generated/rust/packet_decl_8bit_enum_array_little_endian.rs
index e48e5fc..0f63a9d 100644
--- a/tests/generated/rust/packet_decl_8bit_enum_array_little_endian.rs
+++ b/tests/generated/rust/packet_decl_8bit_enum_array_little_endian.rs
@@ -96,7 +96,7 @@ impl Bar {
 }
 impl Packet for Bar {
     fn encoded_len(&self) -> usize {
-        self.x.len() * 1
+        self.x.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.x {
diff --git a/tests/generated/rust/packet_decl_8bit_scalar_array_big_endian.rs b/tests/generated/rust/packet_decl_8bit_scalar_array_big_endian.rs
index ad91b8d..84f342f 100644
--- a/tests/generated/rust/packet_decl_8bit_scalar_array_big_endian.rs
+++ b/tests/generated/rust/packet_decl_8bit_scalar_array_big_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.x.len() * 1
+        self.x.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.x {
diff --git a/tests/generated/rust/packet_decl_8bit_scalar_array_little_endian.rs b/tests/generated/rust/packet_decl_8bit_scalar_array_little_endian.rs
index ad91b8d..84f342f 100644
--- a/tests/generated/rust/packet_decl_8bit_scalar_array_little_endian.rs
+++ b/tests/generated/rust/packet_decl_8bit_scalar_array_little_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.x.len() * 1
+        self.x.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.x {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_count_big_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_count_big_endian.rs
index 2c6faa8..72b80ff 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_count_big_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_count_big_endian.rs
@@ -39,7 +39,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        1 + self.x.len() * 3
+        1 + (self.x.len() * 3)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         if self.x.len() > 0x1f {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_count_little_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_count_little_endian.rs
index 687a614..fc11c17 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_count_little_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_count_little_endian.rs
@@ -39,7 +39,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        1 + self.x.len() * 3
+        1 + (self.x.len() * 3)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         if self.x.len() > 0x1f {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_element_size_big_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_element_size_big_endian.rs
index bd95da3..b78173f 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_element_size_big_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_element_size_big_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.inner.len() * 1
+        self.inner.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.inner {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_count_big_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_count_big_endian.rs
index 795f94b..82cf600 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_count_big_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_count_big_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.inner.len() * 1
+        self.inner.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.inner {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_count_little_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_count_little_endian.rs
index 795f94b..82cf600 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_count_little_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_count_little_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.inner.len() * 1
+        self.inner.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.inner {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_size_big_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_size_big_endian.rs
index aa84e02..2706910 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_size_big_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_size_big_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.inner.len() * 1
+        self.inner.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.inner {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_size_little_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_size_little_endian.rs
index aa84e02..2706910 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_size_little_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_element_size_dynamic_size_little_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.inner.len() * 1
+        self.inner.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.inner {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_element_size_little_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_element_size_little_endian.rs
index bd95da3..b78173f 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_element_size_little_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_element_size_little_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.inner.len() * 1
+        self.inner.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.inner {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_1_big_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_1_big_endian.rs
index 8b38b98..e3715d3 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_1_big_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_1_big_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.inner.len() * 1
+        self.inner.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.inner {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_1_little_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_1_little_endian.rs
index 8b38b98..e3715d3 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_1_little_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_1_little_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.inner.len() * 1
+        self.inner.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.inner {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_big_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_big_endian.rs
index 0a86f0e..f7fd004 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_big_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_big_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.inner.len() * 1
+        self.inner.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.inner {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_little_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_little_endian.rs
index 0a86f0e..f7fd004 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_little_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_element_size_static_count_little_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        self.inner.len() * 1
+        self.inner.len()
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         for elem in &self.inner {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_size_big_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_size_big_endian.rs
index 4c7bb72..ce542f6 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_size_big_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_size_big_endian.rs
@@ -39,7 +39,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        1 + self.x.len() * 3
+        1 + (self.x.len() * 3)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         if (self.x.len() * 3) > 0x1f {
diff --git a/tests/generated/rust/packet_decl_array_dynamic_size_little_endian.rs b/tests/generated/rust/packet_decl_array_dynamic_size_little_endian.rs
index 4d226f8..8cc1330 100644
--- a/tests/generated/rust/packet_decl_array_dynamic_size_little_endian.rs
+++ b/tests/generated/rust/packet_decl_array_dynamic_size_little_endian.rs
@@ -39,7 +39,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        1 + self.x.len() * 3
+        1 + (self.x.len() * 3)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         if (self.x.len() * 3) > 0x1f {
diff --git a/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_count_big_endian.rs b/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_count_big_endian.rs
index d9d7733..ab1c384 100644
--- a/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_count_big_endian.rs
+++ b/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_count_big_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        5 + self.a.len() * 2
+        5 + (self.a.len() * 2)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         if self.a.len() > 0xff_ffff_ffff_usize {
diff --git a/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_count_little_endian.rs b/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_count_little_endian.rs
index eb249ac..5a161e7 100644
--- a/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_count_little_endian.rs
+++ b/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_count_little_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        5 + self.a.len() * 2
+        5 + (self.a.len() * 2)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         if self.a.len() > 0xff_ffff_ffff_usize {
diff --git a/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_size_big_endian.rs b/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_size_big_endian.rs
index ef1ead6..9793db3 100644
--- a/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_size_big_endian.rs
+++ b/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_size_big_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        5 + self.a.len() * 2
+        5 + (self.a.len() * 2)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         if self.a.len() > 0xff_ffff_ffff_usize {
diff --git a/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_size_little_endian.rs b/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_size_little_endian.rs
index 91381c5..432ae4a 100644
--- a/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_size_little_endian.rs
+++ b/tests/generated/rust/packet_decl_array_unknown_element_width_dynamic_size_little_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        5 + self.a.len() * 2
+        5 + (self.a.len() * 2)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         if self.a.len() > 0xff_ffff_ffff_usize {
diff --git a/tests/generated/rust/packet_decl_array_with_padding_big_endian.rs b/tests/generated/rust/packet_decl_array_with_padding_big_endian.rs
index 44d3643..92c61e5 100644
--- a/tests/generated/rust/packet_decl_array_with_padding_big_endian.rs
+++ b/tests/generated/rust/packet_decl_array_with_padding_big_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        5 + self.a.len() * 2
+        5 + (self.a.len() * 2)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         if self.a.len() > 0xff_ffff_ffff_usize {
@@ -86,7 +86,7 @@ impl Bar {
 }
 impl Packet for Bar {
     fn encoded_len(&self) -> usize {
-        self.a.iter().map(Packet::encoded_len).sum::<usize>()
+        128
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         let array_size = self.a.iter().map(Packet::encoded_len).sum::<usize>();
diff --git a/tests/generated/rust/packet_decl_array_with_padding_little_endian.rs b/tests/generated/rust/packet_decl_array_with_padding_little_endian.rs
index 9295e39..c97a536 100644
--- a/tests/generated/rust/packet_decl_array_with_padding_little_endian.rs
+++ b/tests/generated/rust/packet_decl_array_with_padding_little_endian.rs
@@ -35,7 +35,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        5 + self.a.len() * 2
+        5 + (self.a.len() * 2)
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         if self.a.len() > 0xff_ffff_ffff_usize {
@@ -86,7 +86,7 @@ impl Bar {
 }
 impl Packet for Bar {
     fn encoded_len(&self) -> usize {
-        self.a.iter().map(Packet::encoded_len).sum::<usize>()
+        128
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         let array_size = self.a.iter().map(Packet::encoded_len).sum::<usize>();
diff --git a/tests/generated/rust/packet_decl_custom_field_big_endian.rs b/tests/generated/rust/packet_decl_custom_field_big_endian.rs
index fc9f02a..989f61a 100644
--- a/tests/generated/rust/packet_decl_custom_field_big_endian.rs
+++ b/tests/generated/rust/packet_decl_custom_field_big_endian.rs
@@ -116,7 +116,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        56
+        7
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         buf.put_uint(u32::from(self.a) as u64, 3);
diff --git a/tests/generated/rust/packet_decl_custom_field_little_endian.rs b/tests/generated/rust/packet_decl_custom_field_little_endian.rs
index e48f67e..5eda550 100644
--- a/tests/generated/rust/packet_decl_custom_field_little_endian.rs
+++ b/tests/generated/rust/packet_decl_custom_field_little_endian.rs
@@ -116,7 +116,7 @@ impl Foo {
 }
 impl Packet for Foo {
     fn encoded_len(&self) -> usize {
-        56
+        7
     }
     fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
         buf.put_uint_le(u32::from(self.a) as u64, 3);
```

