```diff
diff --git a/Android.bp b/Android.bp
index 8cb75873f..aceecf122 100644
--- a/Android.bp
+++ b/Android.bp
@@ -52,6 +52,7 @@ rust_binary {
         "audio_aaudio",
         "balloon",
         "config-file",
+        "fs_runtime_ugid_map",
         "gdb",
         "gdbstub",
         "gdbstub_arch",
@@ -74,7 +75,7 @@ rust_binary {
         "libargh",
         "libaudio_streams",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbroker_ipc",
         "libcfg_if",
         "libcros_async",
@@ -195,6 +196,7 @@ rust_test {
         "audio_aaudio",
         "balloon",
         "config-file",
+        "fs_runtime_ugid_map",
         "gdb",
         "gdbstub",
         "gdbstub_arch",
@@ -217,7 +219,7 @@ rust_test {
         "libargh",
         "libaudio_streams",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbroker_ipc",
         "libcfg_if",
         "libcros_async",
diff --git a/Cargo.lock b/Cargo.lock
index a4889c642..50498b389 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -149,7 +149,7 @@ checksum = "b382dbd3288e053331f03399e1db106c9fb0d8562ad62cb04859ae926f324fa6"
 dependencies = [
  "argh_shared",
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "syn 1.0.103",
 ]
 
@@ -158,8 +158,8 @@ name = "argh_helpers"
 version = "0.1.0"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
- "syn 2.0.37",
+ "quote 1.0.36",
+ "syn 2.0.77",
 ]
 
 [[package]]
@@ -190,7 +190,7 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "96cf8829f67d2eab0b2dfa42c5d0ef737e0724e4a82b01b3e292456202b19716"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "syn 1.0.103",
 ]
 
@@ -304,8 +304,8 @@ name = "base_event_token_derive"
 version = "0.1.0"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
- "syn 2.0.37",
+ "quote 1.0.36",
+ "syn 2.0.77",
 ]
 
 [[package]]
@@ -337,7 +337,7 @@ dependencies = [
  "log",
  "peeking_take_while",
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "regex",
  "rustc-hash",
  "shlex",
@@ -358,11 +358,34 @@ dependencies = [
  "lazycell",
  "peeking_take_while",
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "regex",
  "rustc-hash",
  "shlex",
- "syn 2.0.37",
+ "syn 2.0.77",
+]
+
+[[package]]
+name = "bindgen"
+version = "0.69.4"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "a00dc851838a2120612785d195287475a3ac45514741da670b735818822129a0"
+dependencies = [
+ "bitflags 2.4.0",
+ "cexpr",
+ "clang-sys",
+ "itertools",
+ "lazy_static",
+ "lazycell",
+ "log",
+ "prettyplease",
+ "proc-macro2",
+ "quote 1.0.36",
+ "regex",
+ "rustc-hash",
+ "shlex",
+ "syn 2.0.77",
+ "which",
 ]
 
 [[package]]
@@ -377,8 +400,8 @@ name = "bit_field_derive"
 version = "0.1.0"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
- "syn 2.0.37",
+ "quote 1.0.36",
+ "syn 2.0.77",
 ]
 
 [[package]]
@@ -439,8 +462,8 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "965ab7eb5f8f97d2a083c799f3a1b994fc397b2fe2da5d1da1626ce15a39f2b1"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
- "syn 2.0.37",
+ "quote 1.0.36",
+ "syn 2.0.77",
 ]
 
 [[package]]
@@ -473,10 +496,10 @@ checksum = "a6358dedf60f4d9b8db43ad187391afe959746101346fe51bb978126bec61dfb"
 dependencies = [
  "clap 3.2.23",
  "heck",
- "indexmap",
+ "indexmap 1.9.1",
  "log",
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "serde",
  "serde_json",
  "syn 1.0.103",
@@ -545,7 +568,7 @@ dependencies = [
  "atty",
  "bitflags 1.3.2",
  "clap_lex 0.2.4",
- "indexmap",
+ "indexmap 1.9.1",
  "strsim",
  "termcolor",
  "textwrap",
@@ -575,7 +598,7 @@ dependencies = [
  "heck",
  "proc-macro-error",
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "syn 1.0.103",
 ]
 
@@ -710,7 +733,7 @@ name = "cros_fdt"
 version = "0.1.0"
 dependencies = [
  "anyhow",
- "indexmap",
+ "indexmap 1.9.1",
  "remain",
  "thiserror",
 ]
@@ -1056,6 +1079,7 @@ dependencies = [
  "usb_util",
  "vfio_sys",
  "vhost",
+ "virtio-media",
  "virtio_sys",
  "vm_control",
  "vm_memory",
@@ -1070,6 +1094,7 @@ dependencies = [
 name = "disk"
 version = "0.1.0"
 dependencies = [
+ "anyhow",
  "async-trait",
  "base",
  "cfg-if",
@@ -1089,6 +1114,7 @@ dependencies = [
  "vm_memory",
  "winapi",
  "zerocopy",
+ "zstd",
 ]
 
 [[package]]
@@ -1132,13 +1158,13 @@ checksum = "3f107b87b6afc2a64fd13cac55fe06d6c8859f12d4b14cbcdd2c67d0976781be"
 
 [[package]]
 name = "enumn"
-version = "0.1.4"
+version = "0.1.13"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "052bc8773a98bd051ff37db74a8a25f00e6bfa2cbd03373390c72e9f7afbf344"
+checksum = "6fd000fd6988e73bbe993ea3db9b1aa64906ab88766d654973924340c8cddb42"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
- "syn 1.0.103",
+ "quote 1.0.36",
+ "syn 2.0.77",
 ]
 
 [[package]]
@@ -1150,6 +1176,12 @@ dependencies = [
  "log",
 ]
 
+[[package]]
+name = "equivalent"
+version = "1.0.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "5443807d6dff69373d433ab9ef5378ad8df50ca6298caf15de6e52e24aaf54d5"
+
 [[package]]
 name = "errno"
 version = "0.2.8"
@@ -1339,7 +1371,7 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "33c1e13800337f4d4d7a316bf45a567dbcb6ffe087f16424852d97e97a91f512"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "syn 1.0.103",
 ]
 
@@ -1467,6 +1499,12 @@ version = "0.12.3"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "8a9ee70c43aaf417c914396645a0fa852624801b24ebb7ae78fe8272889ac888"
 
+[[package]]
+name = "hashbrown"
+version = "0.15.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "1e087f84d4f86bf4b218b927129862374b72199ae7d8657835f1e89000eea4fb"
+
 [[package]]
 name = "heck"
 version = "0.4.0"
@@ -1522,9 +1560,9 @@ name = "hypervisor_test_macro"
 version = "0.1.0"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "rand",
- "syn 2.0.37",
+ "syn 2.0.77",
 ]
 
 [[package]]
@@ -1544,7 +1582,17 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "10a35a97730320ffe8e2d410b5d3b69279b98d2c14bdb8b70ea89ecf7888d41e"
 dependencies = [
  "autocfg",
- "hashbrown",
+ "hashbrown 0.12.3",
+]
+
+[[package]]
+name = "indexmap"
+version = "2.6.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "707907fe3c25f5424cce2cb7e1cbcafee6bdbe735ca90ef77c29e84591e5b9da"
+dependencies = [
+ "equivalent",
+ "hashbrown 0.15.0",
 ]
 
 [[package]]
@@ -1599,6 +1647,15 @@ dependencies = [
  "windows-sys 0.45.0",
 ]
 
+[[package]]
+name = "itertools"
+version = "0.12.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "ba291022dbbd398a455acf126c1e341954079855bc60dfdda641363bd6922569"
+dependencies = [
+ "either",
+]
+
 [[package]]
 name = "itoa"
 version = "1.0.2"
@@ -1695,9 +1752,9 @@ checksum = "830d08ce1d1d941e6b30645f1a0eb5643013d835ce3779a5fc208261dbe10f55"
 
 [[package]]
 name = "libc"
-version = "0.2.153"
+version = "0.2.161"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "9c198f91728a82281a64e1f4f9eeb25d82cb32a5de251c6bd1b5154d63a8e7bd"
+checksum = "8e9489c2807c139ffd9c1794f4af0ebe86a828db53ecdc7fea2111d0fed085d1"
 
 [[package]]
 name = "libcras"
@@ -1800,12 +1857,9 @@ dependencies = [
 
 [[package]]
 name = "log"
-version = "0.4.17"
+version = "0.4.21"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "abb12e687cfb44aa40f41fc3978ef76448f9b6038cad6aef4259d3c095a2382e"
-dependencies = [
- "cfg-if",
-]
+checksum = "90ed8c1e510134f979dbc4f070f87d4313098b704861a105fe34231c70a3901c"
 
 [[package]]
 name = "lz4_flex"
@@ -1873,7 +1927,7 @@ checksum = "209d075476da2e63b4b29e72a2ef627b840589588e71400a25e3565c4f849d07"
 dependencies = [
  "proc-macro-error",
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "syn 1.0.103",
 ]
 
@@ -2120,7 +2174,7 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "b501e44f11665960c7e7fcf062c7d96a14ade4aa98116c004b2e37b5be7d736c"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "syn 1.0.103",
 ]
 
@@ -2160,7 +2214,7 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "e6085210d8ec9bcbdf38b5c8e97bccef1877f3f291eae48b65388ca979f5314e"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "syn 1.0.103",
 ]
 
@@ -2259,6 +2313,7 @@ dependencies = [
  "proto_build_tools",
  "protobuf",
  "remain",
+ "system_api",
  "thiserror",
 ]
 
@@ -2277,6 +2332,16 @@ dependencies = [
  "named-lock",
 ]
 
+[[package]]
+name = "prettyplease"
+version = "0.2.22"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "479cf940fbbb3426c32c5d5176f62ad57549a0bb84773423ba8be9d089f5faba"
+dependencies = [
+ "proc-macro2",
+ "syn 2.0.77",
+]
+
 [[package]]
 name = "proc-macro-error"
 version = "1.0.4"
@@ -2285,7 +2350,7 @@ checksum = "da25490ff9892aab3fcf7c36f08cfb902dd3e71ca0f9f9517bea02a73a5ce38c"
 dependencies = [
  "proc-macro-error-attr",
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "syn 1.0.103",
  "version_check",
 ]
@@ -2297,15 +2362,15 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "a1be40180e52ecc98ad80b184934baf3d0d29f979574e439af5a55274b35f869"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "version_check",
 ]
 
 [[package]]
 name = "proc-macro2"
-version = "1.0.67"
+version = "1.0.85"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "3d433d9f1a3e8c1263d9456598b16fec66f4acc9a74dacffd35c7bb09b3a1328"
+checksum = "22244ce15aa966053a896d1accb3a6e68469b97c7f33f284b99f0d576879fc23"
 dependencies = [
  "unicode-ident",
 ]
@@ -2319,9 +2384,9 @@ dependencies = [
 
 [[package]]
 name = "protobuf"
-version = "3.2.0"
+version = "3.6.0"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "b55bad9126f378a853655831eb7363b7b01b81d19f8cb1218861086ca4a1a61e"
+checksum = "3018844a02746180074f621e847703737d27d89d7f0721a7a4da317f88b16385"
 dependencies = [
  "once_cell",
  "protobuf-support",
@@ -2330,9 +2395,9 @@ dependencies = [
 
 [[package]]
 name = "protobuf-codegen"
-version = "3.2.0"
+version = "3.6.0"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "0dd418ac3c91caa4032d37cb80ff0d44e2ebe637b2fb243b6234bf89cdac4901"
+checksum = "411c15a212b4de05eb8bc989fd066a74c86bd3c04e27d6e86bd7703b806d7734"
 dependencies = [
  "anyhow",
  "once_cell",
@@ -2345,12 +2410,12 @@ dependencies = [
 
 [[package]]
 name = "protobuf-parse"
-version = "3.2.0"
+version = "3.6.0"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "9d39b14605eaa1f6a340aec7f320b34064feb26c93aec35d6a9a2272a8ddfa49"
+checksum = "06f45f16b522d92336e839b5e40680095a045e36a1e7f742ba682ddc85236772"
 dependencies = [
  "anyhow",
- "indexmap",
+ "indexmap 2.6.0",
  "log",
  "protobuf",
  "protobuf-support",
@@ -2361,9 +2426,9 @@ dependencies = [
 
 [[package]]
 name = "protobuf-support"
-version = "3.2.0"
+version = "3.6.0"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "a5d4d7b8601c814cfb36bcebb79f0e61e45e1e93640cf778837833bbed05c372"
+checksum = "faf96d872914fcda2b66d66ea3fff2be7c66865d31c7bb2790cff32c0e714880"
 dependencies = [
  "thiserror",
 ]
@@ -2385,9 +2450,9 @@ checksum = "7a6e920b65c65f10b2ae65c831a81a073a89edd28c7cce89475bff467ab4167a"
 
 [[package]]
 name = "quote"
-version = "1.0.33"
+version = "1.0.36"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "5267fca4496028628a95160fc423a33e8b2e6af8a5302579e322e4b520293cae"
+checksum = "0fa76aaf39101c457836aec0ce2316dbdc3ab723cdda1c6bd4e6ad4208acaca7"
 dependencies = [
  "proc-macro2",
 ]
@@ -2487,7 +2552,7 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "5704e2cda92fd54202f05430725317ba0ea7d0c96b246ca0a92e45177127ba3b"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "syn 1.0.103",
 ]
 
@@ -2571,6 +2636,8 @@ dependencies = [
  "nix 0.28.0",
  "pkg-config",
  "remain",
+ "serde",
+ "serde_json",
  "thiserror",
  "winapi",
  "zerocopy",
@@ -2626,7 +2693,7 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "b3267c900aee8fbc8451235b70c5e2dae96bb19110eabc325be5d5dfed8e7461"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "syn 1.0.103",
 ]
 
@@ -2656,7 +2723,7 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "6f2122636b9fe3b81f1cb25099fcf2d3f542cdb1d45940d56c713158884a05da"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "syn 1.0.103",
 ]
 
@@ -2690,8 +2757,8 @@ version = "0.1.0"
 dependencies = [
  "argh",
  "proc-macro2",
- "quote 1.0.33",
- "syn 2.0.37",
+ "quote 1.0.36",
+ "syn 2.0.77",
 ]
 
 [[package]]
@@ -2780,18 +2847,18 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "a864042229133ada95abf3b54fdc62ef5ccabe9515b64717bcb9a1919e59445d"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "unicode-ident",
 ]
 
 [[package]]
 name = "syn"
-version = "2.0.37"
+version = "2.0.77"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "7303ef2c05cd654186cb250d29049a24840ca25d2747c25c0381c8d9e2f582e8"
+checksum = "9f35bcdf61fd8e7be6caf75f429fdca8beb3ed76584befb503b1569faee373ed"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "unicode-ident",
 ]
 
@@ -2861,7 +2928,7 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "1fb327af4685e4d03fa8cbcf1716380da910eeb2bb8be417e7f9fd3fb164f36f"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "syn 1.0.103",
 ]
 
@@ -2913,8 +2980,8 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "630bdcf245f78637c13ec01ffae6187cca34625e8c63150d424b59e55af2675e"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
- "syn 2.0.37",
+ "quote 1.0.36",
+ "syn 2.0.77",
 ]
 
 [[package]]
@@ -3044,6 +3111,21 @@ dependencies = [
  "serde",
 ]
 
+[[package]]
+name = "v4l2r"
+version = "0.0.5"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "fe1d612d2df2a0802020c49a1b029282c45991cdfff1731b5fc61ed3dce4168a"
+dependencies = [
+ "anyhow",
+ "bindgen 0.69.4",
+ "bitflags 2.4.0",
+ "enumn",
+ "log",
+ "nix 0.28.0",
+ "thiserror",
+]
+
 [[package]]
 name = "vcpkg"
 version = "0.2.15"
@@ -3078,6 +3160,22 @@ dependencies = [
  "vm_memory",
 ]
 
+[[package]]
+name = "virtio-media"
+version = "0.0.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "986653f821d3a3ed13543c37ba0819877457101855454e7d08611784eb63fa0c"
+dependencies = [
+ "anyhow",
+ "enumn",
+ "libc",
+ "log",
+ "nix 0.28.0",
+ "thiserror",
+ "v4l2r",
+ "zerocopy",
+]
+
 [[package]]
 name = "virtio_sys"
 version = "0.1.0"
@@ -3183,13 +3281,13 @@ dependencies = [
  "crossbeam-queue",
  "half",
  "heck",
- "indexmap",
+ "indexmap 1.9.1",
  "lazy_static",
  "libloading",
  "objc",
  "parking_lot",
  "proc-macro2",
- "quote 1.0.33",
+ "quote 1.0.36",
  "regex",
  "serde",
  "serde_json",
@@ -3550,8 +3648,8 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "9ce1b18ccd8e73a9321186f97e46f9f04b778851177567b1975109d26a08d2a6"
 dependencies = [
  "proc-macro2",
- "quote 1.0.33",
- "syn 2.0.37",
+ "quote 1.0.36",
+ "syn 2.0.77",
 ]
 
 [[package]]
@@ -3559,3 +3657,31 @@ name = "zeroize"
 version = "1.5.7"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "c394b5bd0c6f669e7275d9c20aa90ae064cb22e75a1cad54e1b34088034b149f"
+
+[[package]]
+name = "zstd"
+version = "0.13.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "fcf2b778a664581e31e389454a7072dab1647606d44f7feea22cd5abb9c9f3f9"
+dependencies = [
+ "zstd-safe",
+]
+
+[[package]]
+name = "zstd-safe"
+version = "7.2.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "54a3ab4db68cea366acc5c897c7b4d4d1b8994a9cd6e6f841f8964566a419059"
+dependencies = [
+ "zstd-sys",
+]
+
+[[package]]
+name = "zstd-sys"
+version = "2.0.13+zstd.1.5.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "38ff0f21cfee8f97d94cef41359e0c89aa6113028ab0291aa8ca0038995a95aa"
+dependencies = [
+ "cc",
+ "pkg-config",
+]
diff --git a/Cargo.toml b/Cargo.toml
index d4a3eefdf..f94461df0 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -139,6 +139,15 @@ balloon = ["devices/balloon", "vm_control/balloon"]
 ## concatenate large file system images into a single disk image.
 composite-disk = ["protos/composite-disk", "protobuf", "disk/composite-disk"]
 
+## Enables support for using a seekable zstd archive of a raw disk image as a read-only disk.
+## See [Format Specs](https://github.com/facebook/zstd/tree/v1.5.6/contrib/seekable_format) for
+## more information.
+zstd-disk = ["disk/zstd-disk"]
+
+## Enables virtiofs uid-gid mapping from the host side through command line when user-namespace
+## isn't available for non-root users. This format is supported only for vhost-user-fs.
+fs_runtime_ugid_map = ["devices/fs_runtime_ugid_map"]
+
 ## Enables support for JSON configuration files that can be specified using `--cfg`. See
 ## [Configuration Files](https://crosvm.dev/book/running_crosvm/options.html#configuration-files)
 ## for more information.
@@ -244,6 +253,9 @@ ffmpeg = ["devices/ffmpeg"]
 # Enables the VAAPI backend of video devices.
 vaapi = ["devices/vaapi"]
 
+## Enables the virtio-media device.
+media = ["devices/media"]
+
 #! ### Linux-specific feature flags
 
 ## Enables the use of the GenieZone hypervisor
@@ -279,6 +291,15 @@ whpx = ["devices/whpx", "hypervisor/whpx"]
 ## Enables a libslirp based network device. Currently only supported on Windows.
 slirp = ["devices/slirp", "net_util/slirp"]
 
+## Enables slirp debugging.
+slirp-debug = ["net_util/slirp-debug"]
+
+## Enables slirp capture.
+slirp-ring-capture = [
+    "net_util/slirp-ring-capture",
+    "devices/slirp-ring-capture",
+]
+
 #! ### Non-additive feature flags
 #!
 #! These feature flags change the behavior of crosvm instead of adding functionality.
@@ -341,6 +362,12 @@ vtpm = ["devices/vtpm"]
 ## Enables reporting of crosvm crashes
 crash-report = ["broker_ipc/crash-report", "crash_report"]
 
+gvm = []
+perfetto = []
+process-invariants = []
+prod-build = []
+sandbox = []
+
 #! ### Platform Feature Sets
 #!
 #! These feature flags enable all features that are supported for a given platform.
@@ -356,11 +383,13 @@ all-default = [
     "crash-report",
     "default",
     "ffmpeg",
+    "fs_runtime_ugid_map",
     "gdb",
     "geniezone",
     "gfxstream",
     "gfxstream_stub",
     "libvda-stub",
+    "media",
     "net",
     "noncoherent-dma",
     "pci-hotplug",
@@ -378,6 +407,7 @@ all-default = [
     "vtpm",
     "wl-dmabuf",
     "x",
+    "zstd-disk"
 ]
 
 ## All features that are compiled and tested for aarch64
@@ -427,6 +457,7 @@ all-mingw64 = [
     "haxm",
     "net",
     "slirp",
+    "slirp-debug",
     "stats",
     "vulkan_display",
     "pvclock",
@@ -437,21 +468,22 @@ all-msvc64 = [ "all-mingw64" ]
 
 ## All features that are compiled and tested for android builds
 all-android = [
-        "android-sparse",
-        "audio",
-        "audio_aaudio",
-        "balloon",
-        "config-file",
-        "gdb",
-        "gdbstub",
-        "gdbstub_arch",
-        "geniezone",
-        "gunyah",
-        "libaaudio_stub",
-        "net",
-        "qcow",
-        "usb",
-        "composite-disk",
+    "android-sparse",
+    "audio",
+    "audio_aaudio",
+    "balloon",
+    "composite-disk",
+    "config-file",
+    "fs_runtime_ugid_map",
+    "gdb",
+    "gdbstub",
+    "gdbstub_arch",
+    "geniezone",
+    "gunyah",
+    "libaaudio_stub",
+    "net",
+    "qcow",
+    "usb",
 ]
 
 [dependencies]
diff --git a/OWNERS.android b/OWNERS.android
index fe82b0cb5..e07a56335 100644
--- a/OWNERS.android
+++ b/OWNERS.android
@@ -2,3 +2,4 @@ adelva@google.com
 fmayle@google.com
 qwandor@google.com
 smoreland@google.com
+khei@google.com
diff --git a/aarch64/src/fdt.rs b/aarch64/src/fdt.rs
index 60e60b39f..f90f7bdda 100644
--- a/aarch64/src/fdt.rs
+++ b/aarch64/src/fdt.rs
@@ -50,6 +50,7 @@ use crate::AARCH64_RTC_SIZE;
 use crate::AARCH64_SERIAL_SPEED;
 use crate::AARCH64_VIRTFREQ_BASE;
 use crate::AARCH64_VIRTFREQ_SIZE;
+use crate::AARCH64_VIRTFREQ_V2_SIZE;
 use crate::AARCH64_VMWDT_IRQ;
 
 // This is an arbitrary number to specify the node for the GIC.
@@ -251,6 +252,16 @@ fn create_virt_cpufreq_node(fdt: &mut Fdt, num_cpus: u64) -> Result<()> {
     Ok(())
 }
 
+fn create_virt_cpufreq_v2_node(fdt: &mut Fdt, num_cpus: u64) -> Result<()> {
+    let compatible = "qemu,virtual-cpufreq";
+    let vcf_node = fdt.root_mut().subnode_mut("cpufreq")?;
+    let reg = [AARCH64_VIRTFREQ_BASE, AARCH64_VIRTFREQ_V2_SIZE * num_cpus];
+
+    vcf_node.set_prop("compatible", compatible)?;
+    vcf_node.set_prop("reg", &reg)?;
+    Ok(())
+}
+
 fn create_pmu_node(fdt: &mut Fdt, num_cpus: u32) -> Result<()> {
     let compatible = "arm,armv8-pmuv3";
     let cpu_mask: u32 =
@@ -665,6 +676,7 @@ pub fn create_fdt(
     dynamic_power_coefficient: BTreeMap<usize, u32>,
     device_tree_overlays: Vec<DtbOverlay>,
     serial_devices: &[SerialDeviceInfo],
+    virt_cpufreq_v2: bool,
 ) -> Result<()> {
     let mut fdt = Fdt::new(&[]);
     let mut phandles_key_cache = Vec::new();
@@ -719,7 +731,11 @@ pub fn create_fdt(
     create_kvm_cpufreq_node(&mut fdt)?;
     vm_generator(&mut fdt, &phandles)?;
     if !cpu_frequencies.is_empty() {
-        create_virt_cpufreq_node(&mut fdt, num_cpus as u64)?;
+        if virt_cpufreq_v2 {
+            create_virt_cpufreq_v2_node(&mut fdt, num_cpus as u64)?;
+        } else {
+            create_virt_cpufreq_node(&mut fdt, num_cpus as u64)?;
+        }
     }
 
     let pviommu_ids = get_pkvm_pviommu_ids(&platform_dev_resources)?;
diff --git a/aarch64/src/lib.rs b/aarch64/src/lib.rs
index da1090921..912fa04d9 100644
--- a/aarch64/src/lib.rs
+++ b/aarch64/src/lib.rs
@@ -10,6 +10,7 @@ use std::collections::BTreeMap;
 use std::fs::File;
 use std::io;
 use std::path::PathBuf;
+use std::sync::atomic::AtomicU32;
 use std::sync::mpsc;
 use std::sync::Arc;
 
@@ -18,7 +19,9 @@ use arch::CpuSet;
 use arch::DtbOverlay;
 use arch::FdtPosition;
 use arch::GetSerialCmdlineError;
+use arch::MemoryRegionConfig;
 use arch::RunnableLinuxVm;
+use arch::SveConfig;
 use arch::VcpuAffinity;
 use arch::VmComponents;
 use arch::VmImage;
@@ -43,6 +46,8 @@ use devices::PciRootCommand;
 use devices::Serial;
 #[cfg(any(target_os = "android", target_os = "linux"))]
 use devices::VirtCpufreq;
+#[cfg(any(target_os = "android", target_os = "linux"))]
+use devices::VirtCpufreqV2;
 #[cfg(feature = "gdb")]
 use gdbstub::arch::Arch;
 #[cfg(feature = "gdb")]
@@ -100,7 +105,6 @@ const AARCH64_GIC_CPUI_SIZE: u64 = 0x20000;
 
 // This indicates the start of DRAM inside the physical address space.
 const AARCH64_PHYS_MEM_START: u64 = 0x80000000;
-const AARCH64_AXI_BASE: u64 = 0x40000000;
 const AARCH64_PLATFORM_MMIO_SIZE: u64 = 0x800000;
 
 const AARCH64_PROTECTED_VM_FW_MAX_SIZE: u64 = 0x400000;
@@ -108,12 +112,12 @@ const AARCH64_PROTECTED_VM_FW_START: u64 =
     AARCH64_PHYS_MEM_START - AARCH64_PROTECTED_VM_FW_MAX_SIZE;
 
 const AARCH64_PVTIME_IPA_MAX_SIZE: u64 = 0x10000;
-const AARCH64_PVTIME_IPA_START: u64 = AARCH64_MMIO_BASE - AARCH64_PVTIME_IPA_MAX_SIZE;
+const AARCH64_PVTIME_IPA_START: u64 = 0x1ff0000;
 const AARCH64_PVTIME_SIZE: u64 = 64;
 
 // These constants indicate the placement of the GIC registers in the physical
 // address space.
-const AARCH64_GIC_DIST_BASE: u64 = AARCH64_AXI_BASE - AARCH64_GIC_DIST_SIZE;
+const AARCH64_GIC_DIST_BASE: u64 = 0x40000000 - AARCH64_GIC_DIST_SIZE;
 const AARCH64_GIC_CPUI_BASE: u64 = AARCH64_GIC_DIST_BASE - AARCH64_GIC_CPUI_SIZE;
 const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;
 
@@ -124,6 +128,51 @@ const PSR_I_BIT: u64 = 0x00000080;
 const PSR_A_BIT: u64 = 0x00000100;
 const PSR_D_BIT: u64 = 0x00000200;
 
+// This was the speed kvmtool used, not sure if it matters.
+const AARCH64_SERIAL_SPEED: u32 = 1843200;
+// The serial device gets the first interrupt line
+// Which gets mapped to the first SPI interrupt (physical 32).
+const AARCH64_SERIAL_1_3_IRQ: u32 = 0;
+const AARCH64_SERIAL_2_4_IRQ: u32 = 2;
+
+// Place the RTC device at page 2
+const AARCH64_RTC_ADDR: u64 = 0x2000;
+// The RTC device gets one 4k page
+const AARCH64_RTC_SIZE: u64 = 0x1000;
+// The RTC device gets the second interrupt line
+const AARCH64_RTC_IRQ: u32 = 1;
+
+// The Goldfish battery device gets the 3rd interrupt line
+const AARCH64_BAT_IRQ: u32 = 3;
+
+// Place the virtual watchdog device at page 3
+const AARCH64_VMWDT_ADDR: u64 = 0x3000;
+// The virtual watchdog device gets one 4k page
+const AARCH64_VMWDT_SIZE: u64 = 0x1000;
+
+// Default PCI MMIO configuration region base address.
+const AARCH64_PCI_CAM_BASE_DEFAULT: u64 = 0x10000;
+// Default PCI MMIO configuration region size.
+const AARCH64_PCI_CAM_SIZE_DEFAULT: u64 = 0x1000000;
+// Default PCI mem base address.
+const AARCH64_PCI_MEM_BASE_DEFAULT: u64 = 0x2000000;
+// Default PCI mem size.
+const AARCH64_PCI_MEM_SIZE_DEFAULT: u64 = 0x2000000;
+// Virtio devices start at SPI interrupt number 4
+const AARCH64_IRQ_BASE: u32 = 4;
+
+// Virtual CPU Frequency Device.
+const AARCH64_VIRTFREQ_BASE: u64 = 0x1040000;
+const AARCH64_VIRTFREQ_SIZE: u64 = 0x8;
+const AARCH64_VIRTFREQ_MAXSIZE: u64 = 0x10000;
+const AARCH64_VIRTFREQ_V2_SIZE: u64 = 0x1000;
+
+// PMU PPI interrupt, same as qemu
+const AARCH64_PMU_IRQ: u32 = 7;
+
+// VCPU stall detector interrupt
+const AARCH64_VMWDT_IRQ: u32 = 15;
+
 enum PayloadType {
     Bios {
         entry: GuestAddress,
@@ -170,50 +219,6 @@ fn get_swiotlb_addr(
     }
 }
 
-// This was the speed kvmtool used, not sure if it matters.
-const AARCH64_SERIAL_SPEED: u32 = 1843200;
-// The serial device gets the first interrupt line
-// Which gets mapped to the first SPI interrupt (physical 32).
-const AARCH64_SERIAL_1_3_IRQ: u32 = 0;
-const AARCH64_SERIAL_2_4_IRQ: u32 = 2;
-
-// Place the RTC device at page 2
-const AARCH64_RTC_ADDR: u64 = 0x2000;
-// The RTC device gets one 4k page
-const AARCH64_RTC_SIZE: u64 = 0x1000;
-// The RTC device gets the second interrupt line
-const AARCH64_RTC_IRQ: u32 = 1;
-
-// The Goldfish battery device gets the 3rd interrupt line
-const AARCH64_BAT_IRQ: u32 = 3;
-
-// Place the virtual watchdog device at page 3
-const AARCH64_VMWDT_ADDR: u64 = 0x3000;
-// The virtual watchdog device gets one 4k page
-const AARCH64_VMWDT_SIZE: u64 = 0x1000;
-
-// PCI MMIO configuration region base address.
-const AARCH64_PCI_CFG_BASE: u64 = 0x10000;
-// PCI MMIO configuration region size.
-const AARCH64_PCI_CFG_SIZE: u64 = 0x1000000;
-// This is the base address of MMIO devices.
-const AARCH64_MMIO_BASE: u64 = 0x2000000;
-// Size of the whole MMIO region.
-const AARCH64_MMIO_SIZE: u64 = 0x2000000;
-// Virtio devices start at SPI interrupt number 4
-const AARCH64_IRQ_BASE: u32 = 4;
-
-// Virtual CPU Frequency Device.
-const AARCH64_VIRTFREQ_BASE: u64 = 0x1040000;
-const AARCH64_VIRTFREQ_SIZE: u64 = 0x8;
-const AARCH64_VIRTFREQ_MAXSIZE: u64 = 0x10000;
-
-// PMU PPI interrupt, same as qemu
-const AARCH64_PMU_IRQ: u32 = 7;
-
-// VCPU stall detector interrupt
-const AARCH64_VMWDT_IRQ: u32 = 15;
-
 #[sorted]
 #[derive(Error, Debug)]
 pub enum Error {
@@ -229,6 +234,10 @@ pub enum Error {
     CloneIrqChip(base::Error),
     #[error("the given kernel command line was invalid: {0}")]
     Cmdline(kernel_cmdline::Error),
+    #[error("bad PCI CAM configuration: {0}")]
+    ConfigurePciCam(String),
+    #[error("bad PCI mem configuration: {0}")]
+    ConfigurePciMem(String),
     #[error("failed to configure CPU Frequencies: {0}")]
     CpuFrequencies(base::Error),
     #[error("failed to configure CPU topology: {0}")]
@@ -363,23 +372,75 @@ fn get_vcpu_mpidr_aff<Vcpu: VcpuAArch64>(vcpus: &[Vcpu], index: usize) -> Option
     Some(vcpus.get(index)?.get_mpidr().ok()? & MPIDR_AFF_MASK)
 }
 
+fn main_memory_size(components: &VmComponents, hypervisor: &(impl Hypervisor + ?Sized)) -> u64 {
+    // Static swiotlb is allocated from the end of RAM as a separate memory region, so, if
+    // enabled, make the RAM memory region smaller to leave room for it.
+    let mut main_memory_size = components.memory_size;
+    if let Some(size) = components.swiotlb {
+        if hypervisor.check_capability(HypervisorCap::StaticSwiotlbAllocationRequired) {
+            main_memory_size -= size;
+        }
+    }
+    main_memory_size
+}
+
+pub struct ArchMemoryLayout {
+    pci_cam: AddressRange,
+    pci_mem: AddressRange,
+}
+
 impl arch::LinuxArch for AArch64 {
     type Error = Error;
+    type ArchMemoryLayout = ArchMemoryLayout;
+
+    fn arch_memory_layout(
+        components: &VmComponents,
+    ) -> std::result::Result<Self::ArchMemoryLayout, Self::Error> {
+        let (pci_cam_start, pci_cam_size) = match components.pci_config.cam {
+            Some(MemoryRegionConfig { start, size }) => {
+                (start, size.unwrap_or(AARCH64_PCI_CAM_SIZE_DEFAULT))
+            }
+            None => (AARCH64_PCI_CAM_BASE_DEFAULT, AARCH64_PCI_CAM_SIZE_DEFAULT),
+        };
+        // TODO: Make the PCI slot allocator aware of the CAM size so we can remove this check.
+        if pci_cam_size != AARCH64_PCI_CAM_SIZE_DEFAULT {
+            return Err(Error::ConfigurePciCam(format!(
+                "PCI CAM size must be {AARCH64_PCI_CAM_SIZE_DEFAULT:#x}, got {pci_cam_size:#x}"
+            )));
+        }
+        let pci_cam = AddressRange::from_start_and_size(pci_cam_start, pci_cam_size).ok_or(
+            Error::ConfigurePciCam("PCI CAM region overflowed".to_string()),
+        )?;
+        if pci_cam.end >= AARCH64_PHYS_MEM_START {
+            return Err(Error::ConfigurePciCam(format!(
+                "PCI CAM ({pci_cam:?}) must be before start of RAM ({AARCH64_PHYS_MEM_START:#x})"
+            )));
+        }
+
+        let pci_mem = match components.pci_config.mem {
+            Some(MemoryRegionConfig { start, size }) => AddressRange::from_start_and_size(
+                start,
+                size.unwrap_or(AARCH64_PCI_MEM_SIZE_DEFAULT),
+            )
+            .ok_or(Error::ConfigurePciMem("region overflowed".to_string()))?,
+            None => AddressRange::from_start_and_size(
+                AARCH64_PCI_MEM_BASE_DEFAULT,
+                AARCH64_PCI_MEM_SIZE_DEFAULT,
+            )
+            .unwrap(),
+        };
+
+        Ok(ArchMemoryLayout { pci_cam, pci_mem })
+    }
 
     /// Returns a Vec of the valid memory addresses.
     /// These should be used to configure the GuestMemory structure for the platform.
     fn guest_memory_layout(
         components: &VmComponents,
+        _arch_memory_layout: &Self::ArchMemoryLayout,
         hypervisor: &impl Hypervisor,
     ) -> std::result::Result<Vec<(GuestAddress, u64, MemoryRegionOptions)>, Self::Error> {
-        // Static swiotlb is allocated from the end of RAM as a separate memory region, so, if
-        // enabled, make the RAM memory region smaller to leave room for it.
-        let mut main_memory_size = components.memory_size;
-        if let Some(size) = components.swiotlb {
-            if hypervisor.check_capability(HypervisorCap::StaticSwiotlbAllocationRequired) {
-                main_memory_size -= size;
-            }
-        }
+        let main_memory_size = main_memory_size(components, hypervisor);
 
         let mut memory_regions = vec![(
             GuestAddress(AARCH64_PHYS_MEM_START),
@@ -409,15 +470,40 @@ impl arch::LinuxArch for AArch64 {
         Ok(memory_regions)
     }
 
-    fn get_system_allocator_config<V: Vm>(vm: &V) -> SystemAllocatorConfig {
-        Self::get_resource_allocator_config(
-            vm.get_memory().end_addr(),
-            vm.get_guest_phys_addr_bits(),
-        )
+    fn get_system_allocator_config<V: Vm>(
+        vm: &V,
+        arch_memory_layout: &Self::ArchMemoryLayout,
+    ) -> SystemAllocatorConfig {
+        let guest_phys_end = 1u64 << vm.get_guest_phys_addr_bits();
+        // The platform MMIO region is immediately past the end of RAM.
+        let plat_mmio_base = vm.get_memory().end_addr().offset();
+        let plat_mmio_size = AARCH64_PLATFORM_MMIO_SIZE;
+        // The high MMIO region is the rest of the address space after the platform MMIO region.
+        let high_mmio_base = plat_mmio_base + plat_mmio_size;
+        let high_mmio_size = guest_phys_end
+            .checked_sub(high_mmio_base)
+            .unwrap_or_else(|| {
+                panic!(
+                    "guest_phys_end {:#x} < high_mmio_base {:#x}",
+                    guest_phys_end, high_mmio_base,
+                );
+            });
+        SystemAllocatorConfig {
+            io: None,
+            low_mmio: arch_memory_layout.pci_mem,
+            high_mmio: AddressRange::from_start_and_size(high_mmio_base, high_mmio_size)
+                .expect("invalid high mmio region"),
+            platform_mmio: Some(
+                AddressRange::from_start_and_size(plat_mmio_base, plat_mmio_size)
+                    .expect("invalid platform mmio region"),
+            ),
+            first_irq: AARCH64_IRQ_BASE,
+        }
     }
 
     fn build_vm<V, Vcpu>(
         mut components: VmComponents,
+        arch_memory_layout: &Self::ArchMemoryLayout,
         _vm_evt_wrtube: &SendTube,
         system_allocator: &mut SystemAllocator,
         serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
@@ -434,6 +520,7 @@ impl arch::LinuxArch for AArch64 {
         _guest_suspended_cvar: Option<Arc<(Mutex<bool>, Condvar)>>,
         device_tree_overlays: Vec<DtbOverlay>,
         fdt_position: Option<FdtPosition>,
+        no_pmu: bool,
     ) -> std::result::Result<RunnableLinuxVm<V, Vcpu>, Self::Error>
     where
         V: VmAArch64,
@@ -442,6 +529,8 @@ impl arch::LinuxArch for AArch64 {
         let has_bios = matches!(components.vm_image, VmImage::Bios(_));
         let mem = vm.get_memory().clone();
 
+        let main_memory_size = main_memory_size(&components, vm.get_hypervisor());
+
         let fdt_position = fdt_position.unwrap_or(if has_bios {
             FdtPosition::Start
         } else {
@@ -481,7 +570,7 @@ impl arch::LinuxArch for AArch64 {
                         let initrd_addr =
                             (kernel_end + (AARCH64_INITRD_ALIGN - 1)) & !(AARCH64_INITRD_ALIGN - 1);
                         let initrd_max_size =
-                            components.memory_size - (initrd_addr - AARCH64_PHYS_MEM_START);
+                            main_memory_size - (initrd_addr - AARCH64_PHYS_MEM_START);
                         let initrd_addr = GuestAddress(initrd_addr);
                         let initrd_size =
                             arch::load_image(&mem, &mut initrd_file, initrd_addr, initrd_max_size)
@@ -497,7 +586,7 @@ impl arch::LinuxArch for AArch64 {
             }
         };
 
-        let memory_end = GuestAddress(AARCH64_PHYS_MEM_START + components.memory_size);
+        let memory_end = GuestAddress(AARCH64_PHYS_MEM_START + main_memory_size);
 
         let fdt_address = match fdt_position {
             FdtPosition::Start => GuestAddress(AARCH64_PHYS_MEM_START),
@@ -517,6 +606,7 @@ impl arch::LinuxArch for AArch64 {
         let mut use_pmu = vm
             .get_hypervisor()
             .check_capability(HypervisorCap::ArmPmuV3);
+        use_pmu &= !no_pmu;
         let vcpu_count = components.vcpu_count;
         let mut has_pvtime = true;
         let mut vcpus = Vec::with_capacity(vcpu_count);
@@ -550,8 +640,9 @@ impl arch::LinuxArch for AArch64 {
 
         // Initialize Vcpus after all Vcpu objects have been created.
         for (vcpu_id, vcpu) in vcpus.iter().enumerate() {
-            vcpu.init(&Self::vcpu_features(vcpu_id, use_pmu, components.boot_cpu))
-                .map_err(Error::VcpuInit)?;
+            let features =
+                &Self::vcpu_features(vcpu_id, use_pmu, components.boot_cpu, components.sve_config);
+            vcpu.init(features).map_err(Error::VcpuInit)?;
         }
 
         irq_chip.finalize().map_err(Error::FinalizeIrqChip)?;
@@ -621,7 +712,7 @@ impl arch::LinuxArch for AArch64 {
                 pci_devices,
                 irq_chip.as_irq_chip_mut(),
                 mmio_bus.clone(),
-                GuestAddress(AARCH64_PCI_CFG_BASE),
+                GuestAddress(arch_memory_layout.pci_cam.start),
                 8,
                 io_bus.clone(),
                 system_allocator,
@@ -693,43 +784,83 @@ impl arch::LinuxArch for AArch64 {
             .map_err(Error::RegisterIrqfd)?;
 
         mmio_bus
-            .insert(pci_bus, AARCH64_PCI_CFG_BASE, AARCH64_PCI_CFG_SIZE)
+            .insert(
+                pci_bus,
+                arch_memory_layout.pci_cam.start,
+                arch_memory_layout.pci_cam.len().unwrap(),
+            )
             .map_err(Error::RegisterPci)?;
 
+        let (vcpufreq_host_tube, vcpufreq_control_tube) =
+            Tube::pair().map_err(Error::CreateTube)?;
+        let vcpufreq_shared_tube = Arc::new(Mutex::new(vcpufreq_control_tube));
         #[cfg(any(target_os = "android", target_os = "linux"))]
         if !components.cpu_frequencies.is_empty() {
+            let mut freq_domain_vcpus: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
+            let mut freq_domain_perfs: BTreeMap<u32, Arc<AtomicU32>> = BTreeMap::new();
+            let mut vcpu_affinities: Vec<u32> = Vec::new();
             for vcpu in 0..vcpu_count {
+                let freq_domain = *components.vcpu_domains.get(&vcpu).unwrap_or(&(vcpu as u32));
+                freq_domain_vcpus.entry(freq_domain).or_default().push(vcpu);
                 let vcpu_affinity = match components.vcpu_affinity.clone() {
                     Some(VcpuAffinity::Global(v)) => v,
                     Some(VcpuAffinity::PerVcpu(mut m)) => m.remove(&vcpu).unwrap_or_default(),
                     None => panic!("vcpu_affinity needs to be set for VirtCpufreq"),
                 };
+                vcpu_affinities.push(vcpu_affinity[0].try_into().unwrap());
+            }
+            for domain in freq_domain_vcpus.keys() {
+                let domain_perf = Arc::new(AtomicU32::new(0));
+                freq_domain_perfs.insert(*domain, domain_perf);
+            }
+            let largest_vcpu_affinity_idx = *vcpu_affinities.iter().max().unwrap() as usize;
+            for (vcpu, vcpu_affinity) in vcpu_affinities.iter().enumerate() {
+                let mut virtfreq_size = AARCH64_VIRTFREQ_SIZE;
+                if components.virt_cpufreq_v2 {
+                    let domain = *components.vcpu_domains.get(&vcpu).unwrap_or(&(vcpu as u32));
+                    virtfreq_size = AARCH64_VIRTFREQ_V2_SIZE;
+                    let virt_cpufreq = Arc::new(Mutex::new(VirtCpufreqV2::new(
+                        *vcpu_affinity,
+                        components.cpu_frequencies.get(&vcpu).unwrap().clone(),
+                        components.vcpu_domain_paths.get(&vcpu).cloned(),
+                        domain,
+                        *components.normalized_cpu_capacities.get(&vcpu).unwrap(),
+                        largest_vcpu_affinity_idx,
+                        vcpufreq_shared_tube.clone(),
+                        freq_domain_vcpus.get(&domain).unwrap().clone(),
+                        freq_domain_perfs.get(&domain).unwrap().clone(),
+                    )));
+                    mmio_bus
+                        .insert(
+                            virt_cpufreq,
+                            AARCH64_VIRTFREQ_BASE + (vcpu as u64 * virtfreq_size),
+                            virtfreq_size,
+                        )
+                        .map_err(Error::RegisterVirtCpufreq)?;
+                } else {
+                    let virt_cpufreq = Arc::new(Mutex::new(VirtCpufreq::new(
+                        *vcpu_affinity,
+                        *components.normalized_cpu_capacities.get(&vcpu).unwrap(),
+                        *components
+                            .cpu_frequencies
+                            .get(&vcpu)
+                            .unwrap()
+                            .iter()
+                            .max()
+                            .unwrap(),
+                    )));
+                    mmio_bus
+                        .insert(
+                            virt_cpufreq,
+                            AARCH64_VIRTFREQ_BASE + (vcpu as u64 * virtfreq_size),
+                            virtfreq_size,
+                        )
+                        .map_err(Error::RegisterVirtCpufreq)?;
+                }
 
-                let virt_cpufreq = Arc::new(Mutex::new(VirtCpufreq::new(
-                    vcpu_affinity[0].try_into().unwrap(),
-                    *components.normalized_cpu_capacities.get(&vcpu).unwrap(),
-                    *components
-                        .cpu_frequencies
-                        .get(&vcpu)
-                        .unwrap()
-                        .iter()
-                        .max()
-                        .unwrap(),
-                )));
-
-                if vcpu as u64 * AARCH64_VIRTFREQ_SIZE + AARCH64_VIRTFREQ_SIZE
-                    > AARCH64_VIRTFREQ_MAXSIZE
-                {
+                if vcpu as u64 * AARCH64_VIRTFREQ_SIZE + virtfreq_size > AARCH64_VIRTFREQ_MAXSIZE {
                     panic!("Exceeded maximum number of virt cpufreq devices");
                 }
-
-                mmio_bus
-                    .insert(
-                        virt_cpufreq,
-                        AARCH64_VIRTFREQ_BASE + (vcpu as u64 * AARCH64_VIRTFREQ_SIZE),
-                        AARCH64_VIRTFREQ_SIZE,
-                    )
-                    .map_err(Error::RegisterVirtCpufreq)?;
             }
         }
 
@@ -748,8 +879,8 @@ impl arch::LinuxArch for AArch64 {
         let psci_version = vcpus[0].get_psci_version().map_err(Error::GetPsciVersion)?;
 
         let pci_cfg = fdt::PciConfigRegion {
-            base: AARCH64_PCI_CFG_BASE,
-            size: AARCH64_PCI_CFG_SIZE,
+            base: arch_memory_layout.pci_cam.start,
+            size: arch_memory_layout.pci_cam.len().unwrap(),
         };
 
         let mut pci_ranges: Vec<fdt::PciRange> = Vec::new();
@@ -837,6 +968,7 @@ impl arch::LinuxArch for AArch64 {
             components.dynamic_power_coefficient,
             device_tree_overlays,
             &serial_devices,
+            components.virt_cpufreq_v2,
         )
         .map_err(Error::CreateFdt)?;
 
@@ -847,7 +979,7 @@ impl arch::LinuxArch for AArch64 {
         )
         .map_err(Error::InitVmError)?;
 
-        let vm_request_tubes = vec![vmwdt_host_tube];
+        let vm_request_tubes = vec![vmwdt_host_tube, vcpufreq_host_tube];
 
         Ok(RunnableLinuxVm {
             vm,
@@ -864,8 +996,6 @@ impl arch::LinuxArch for AArch64 {
             rt_cpus: components.rt_cpus,
             delay_rt: components.delay_rt,
             bat_control,
-            #[cfg(feature = "gdb")]
-            gdb: components.gdb,
             pm: None,
             resume_notify_devices: Vec::new(),
             root_config: pci_root,
@@ -1167,44 +1297,6 @@ impl AArch64 {
         cmdline
     }
 
-    /// Returns a system resource allocator configuration.
-    ///
-    /// # Arguments
-    ///
-    /// * `memory_end` - The first address beyond the end of guest memory.
-    /// * `guest_phys_addr_bits` - Size of guest physical addresses (IPA) in bits.
-    fn get_resource_allocator_config(
-        memory_end: GuestAddress,
-        guest_phys_addr_bits: u8,
-    ) -> SystemAllocatorConfig {
-        let guest_phys_end = 1u64 << guest_phys_addr_bits;
-        // The platform MMIO region is immediately past the end of RAM.
-        let plat_mmio_base = memory_end.offset();
-        let plat_mmio_size = AARCH64_PLATFORM_MMIO_SIZE;
-        // The high MMIO region is the rest of the address space after the platform MMIO region.
-        let high_mmio_base = plat_mmio_base + plat_mmio_size;
-        let high_mmio_size = guest_phys_end
-            .checked_sub(high_mmio_base)
-            .unwrap_or_else(|| {
-                panic!(
-                    "guest_phys_end {:#x} < high_mmio_base {:#x}",
-                    guest_phys_end, high_mmio_base,
-                );
-            });
-        SystemAllocatorConfig {
-            io: None,
-            low_mmio: AddressRange::from_start_and_size(AARCH64_MMIO_BASE, AARCH64_MMIO_SIZE)
-                .expect("invalid mmio region"),
-            high_mmio: AddressRange::from_start_and_size(high_mmio_base, high_mmio_size)
-                .expect("invalid high mmio region"),
-            platform_mmio: Some(
-                AddressRange::from_start_and_size(plat_mmio_base, plat_mmio_size)
-                    .expect("invalid platform mmio region"),
-            ),
-            first_irq: AARCH64_IRQ_BASE,
-        }
-    }
-
     /// This adds any early platform devices for this architecture.
     ///
     /// # Arguments
@@ -1265,7 +1357,12 @@ impl AArch64 {
     ///
     /// * `vcpu_id` - The VM's index for `vcpu`.
     /// * `use_pmu` - Should `vcpu` be configured to use the Performance Monitor Unit.
-    fn vcpu_features(vcpu_id: usize, use_pmu: bool, boot_cpu: usize) -> Vec<VcpuFeature> {
+    fn vcpu_features(
+        vcpu_id: usize,
+        use_pmu: bool,
+        boot_cpu: usize,
+        sve: SveConfig,
+    ) -> Vec<VcpuFeature> {
         let mut features = vec![VcpuFeature::PsciV0_2];
         if use_pmu {
             features.push(VcpuFeature::PmuV3);
@@ -1274,6 +1371,9 @@ impl AArch64 {
         if vcpu_id != boot_cpu {
             features.push(VcpuFeature::PowerOff);
         }
+        if sve.enable {
+            features.push(VcpuFeature::Sve);
+        }
 
         features
     }
diff --git a/arch/src/lib.rs b/arch/src/lib.rs
index f351c3f13..83d68435f 100644
--- a/arch/src/lib.rs
+++ b/arch/src/lib.rs
@@ -68,8 +68,6 @@ use jail::FakeMinijailStub as Minijail;
 #[cfg(any(target_os = "android", target_os = "linux"))]
 use minijail::Minijail;
 use remain::sorted;
-#[cfg(target_arch = "x86_64")]
-use resources::AddressRange;
 use resources::SystemAllocator;
 use resources::SystemAllocatorConfig;
 use serde::de::Visitor;
@@ -173,6 +171,15 @@ impl FromIterator<usize> for CpuSet {
     }
 }
 
+/// The SVE config for Vcpus.
+#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
+#[serde(deny_unknown_fields, rename_all = "kebab-case")]
+pub struct SveConfig {
+    /// Use SVE
+    pub enable: bool,
+}
+
 fn parse_cpu_range(s: &str, cpuset: &mut Vec<usize>) -> Result<(), String> {
     fn parse_cpu(s: &str) -> Result<usize, String> {
         s.parse().map_err(|_| {
@@ -334,6 +341,26 @@ pub enum VcpuAffinity {
     PerVcpu(BTreeMap<usize, CpuSet>),
 }
 
+/// Memory region with optional size.
+#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, FromKeyValues)]
+pub struct MemoryRegionConfig {
+    pub start: u64,
+    pub size: Option<u64>,
+}
+
+/// General PCI config.
+#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, FromKeyValues)]
+pub struct PciConfig {
+    /// region for PCI Configuration Access Mechanism
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+    pub cam: Option<MemoryRegionConfig>,
+    /// region for PCIe Enhanced Configuration Access Mechanism
+    #[cfg(target_arch = "x86_64")]
+    pub ecam: Option<MemoryRegionConfig>,
+    /// region for non-prefetchable PCI device memory below 4G
+    pub mem: Option<MemoryRegionConfig>,
+}
+
 /// Holds the pieces needed to build a VM. Passed to `build_vm` in the `LinuxArch` trait below to
 /// create a `RunnableLinuxVm`.
 #[sorted]
@@ -360,8 +387,6 @@ pub struct VmComponents {
     pub force_s2idle: bool,
     pub fw_cfg_enable: bool,
     pub fw_cfg_parameters: Vec<FwCfgParameters>,
-    #[cfg(feature = "gdb")]
-    pub gdb: Option<(u32, Tube)>, // port and control tube.
     pub host_cpu_topology: bool,
     pub hugepages: bool,
     pub hv_cfg: hypervisor::Config,
@@ -376,10 +401,7 @@ pub struct VmComponents {
         any(target_os = "android", target_os = "linux")
     ))]
     pub normalized_cpu_capacities: BTreeMap<usize, u32>,
-    #[cfg(target_arch = "x86_64")]
-    pub pci_low_start: Option<u64>,
-    #[cfg(target_arch = "x86_64")]
-    pub pcie_ecam: Option<AddressRange>,
+    pub pci_config: PciConfig,
     pub pflash_block_size: u32,
     pub pflash_image: Option<File>,
     pub pstore: Option<Pstore>,
@@ -389,9 +411,26 @@ pub struct VmComponents {
     pub rt_cpus: CpuSet,
     #[cfg(target_arch = "x86_64")]
     pub smbios: SmbiosOptions,
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+    pub sve_config: SveConfig,
     pub swiotlb: Option<u64>,
     pub vcpu_affinity: Option<VcpuAffinity>,
     pub vcpu_count: usize,
+    #[cfg(all(
+        any(target_arch = "arm", target_arch = "aarch64"),
+        any(target_os = "android", target_os = "linux")
+    ))]
+    pub vcpu_domain_paths: BTreeMap<usize, PathBuf>,
+    #[cfg(all(
+        any(target_arch = "arm", target_arch = "aarch64"),
+        any(target_os = "android", target_os = "linux")
+    ))]
+    pub vcpu_domains: BTreeMap<usize, u32>,
+    #[cfg(all(
+        any(target_arch = "arm", target_arch = "aarch64"),
+        any(target_os = "android", target_os = "linux")
+    ))]
+    pub virt_cpufreq_v2: bool,
     pub vm_image: VmImage,
 }
 
@@ -401,8 +440,6 @@ pub struct RunnableLinuxVm<V: VmArch, Vcpu: VcpuArch> {
     pub bat_control: Option<BatControl>,
     pub delay_rt: bool,
     pub devices_thread: Option<std::thread::JoinHandle<()>>,
-    #[cfg(feature = "gdb")]
-    pub gdb: Option<(u32, Tube)>,
     pub hotplug_bus: BTreeMap<u8, Arc<Mutex<dyn HotPlugBus>>>,
     pub io_bus: Arc<Bus>,
     pub irq_chip: Box<dyn IrqChipArch>,
@@ -437,6 +474,13 @@ pub struct VirtioDeviceStub {
 /// set up the memory, cpus, and system devices and to boot the kernel.
 pub trait LinuxArch {
     type Error: StdError;
+    type ArchMemoryLayout;
+
+    /// Decide architecture specific memory layout details to be used by later stages of the VM
+    /// setup.
+    fn arch_memory_layout(
+        components: &VmComponents,
+    ) -> std::result::Result<Self::ArchMemoryLayout, Self::Error>;
 
     /// Returns a Vec of the valid memory addresses as pairs of address and length. These should be
     /// used to configure the `GuestMemory` structure for the platform.
@@ -446,6 +490,7 @@ pub trait LinuxArch {
     /// * `components` - Parts used to determine the memory layout.
     fn guest_memory_layout(
         components: &VmComponents,
+        arch_memory_layout: &Self::ArchMemoryLayout,
         hypervisor: &impl hypervisor::Hypervisor,
     ) -> std::result::Result<Vec<(GuestAddress, u64, MemoryRegionOptions)>, Self::Error>;
 
@@ -458,7 +503,10 @@ pub trait LinuxArch {
     /// # Arguments
     ///
     /// * `vm` - The virtual machine to be used as a template for the `SystemAllocator`.
-    fn get_system_allocator_config<V: Vm>(vm: &V) -> SystemAllocatorConfig;
+    fn get_system_allocator_config<V: Vm>(
+        vm: &V,
+        arch_memory_layout: &Self::ArchMemoryLayout,
+    ) -> SystemAllocatorConfig;
 
     /// Takes `VmComponents` and generates a `RunnableLinuxVm`.
     ///
@@ -482,6 +530,7 @@ pub trait LinuxArch {
     /// * `device_tree_overlays` - Device tree overlay binaries
     fn build_vm<V, Vcpu>(
         components: VmComponents,
+        arch_memory_layout: &Self::ArchMemoryLayout,
         vm_evt_wrtube: &SendTube,
         system_allocator: &mut SystemAllocator,
         serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
@@ -500,6 +549,7 @@ pub trait LinuxArch {
         guest_suspended_cvar: Option<Arc<(Mutex<bool>, Condvar)>>,
         device_tree_overlays: Vec<DtbOverlay>,
         fdt_position: Option<FdtPosition>,
+        no_pmu: bool,
     ) -> std::result::Result<RunnableLinuxVm<V, Vcpu>, Self::Error>
     where
         V: VmArch,
@@ -894,7 +944,7 @@ pub fn generate_virtio_mmio_bus(
 }
 
 // Generate pci topology starting from parent bus
-pub fn generate_pci_topology(
+fn generate_pci_topology(
     parent_bus: Arc<Mutex<PciBus>>,
     resources: &mut SystemAllocator,
     io_ranges: &mut BTreeMap<usize, Vec<BarRange>>,
diff --git a/arch/src/serial.rs b/arch/src/serial.rs
index 18455dc45..bfd897ba9 100644
--- a/arch/src/serial.rs
+++ b/arch/src/serial.rs
@@ -209,7 +209,7 @@ pub fn get_serial_cmdline(
                     .insert("console", &format!("ttyS{}", num - 1))
                     .map_err(GetSerialCmdlineError::KernelCmdline)?;
             }
-            (SerialHardware::VirtioConsole, num) | (SerialHardware::LegacyVirtioConsole, num) => {
+            (SerialHardware::VirtioConsole, num) => {
                 cmdline
                     .insert("console", &format!("hvc{}", num - 1))
                     .map_err(GetSerialCmdlineError::KernelCmdline)?;
@@ -291,16 +291,10 @@ mod tests {
             SerialParameters {
                 type_: SerialType::Stdout,
                 hardware: SerialHardware::VirtioConsole,
-                name: None,
-                path: None,
-                input: None,
                 num: 1,
                 console: true,
-                earlycon: false,
                 stdin: true,
-                out_timestamp: false,
-                debugcon_port: 0,
-                pci_address: None,
+                ..Default::default()
             },
         );
 
@@ -337,16 +331,10 @@ mod tests {
             SerialParameters {
                 type_: SerialType::Stdout,
                 hardware: SerialHardware::VirtioConsole,
-                name: None,
-                path: None,
-                input: None,
                 num: 1,
                 console: true,
-                earlycon: false,
                 stdin: true,
-                out_timestamp: false,
-                debugcon_port: 0,
-                pci_address: None,
+                ..Default::default()
             },
         );
 
@@ -356,16 +344,9 @@ mod tests {
             SerialParameters {
                 type_: SerialType::Stdout,
                 hardware: SerialHardware::Serial,
-                name: None,
-                path: None,
-                input: None,
                 num: 1,
-                console: false,
                 earlycon: true,
-                stdin: false,
-                out_timestamp: false,
-                debugcon_port: 0,
-                pci_address: None,
+                ..Default::default()
             },
         );
 
@@ -403,16 +384,10 @@ mod tests {
             SerialParameters {
                 type_: SerialType::Stdout,
                 hardware: SerialHardware::VirtioConsole,
-                name: None,
-                path: None,
-                input: None,
                 num: 1,
-                console: false,
                 earlycon: true,
                 stdin: true,
-                out_timestamp: false,
-                debugcon_port: 0,
-                pci_address: None,
+                ..Default::default()
             },
         );
 
diff --git a/arch/src/sys/linux.rs b/arch/src/sys/linux.rs
index f536535f6..d7dc5ad3e 100644
--- a/arch/src/sys/linux.rs
+++ b/arch/src/sys/linux.rs
@@ -59,11 +59,17 @@ pub fn add_goldfish_battery(
         Tube::pair().map_err(DeviceRegistrationError::CreateTube)?;
 
     #[cfg(feature = "power-monitor-powerd")]
-    let create_monitor = Some(Box::new(power_monitor::powerd::DBusMonitor::connect)
-        as Box<dyn power_monitor::CreatePowerMonitorFn>);
+    let (create_monitor, create_client) = (
+        Some(
+            Box::new(power_monitor::powerd::monitor::DBusMonitor::connect)
+                as Box<dyn power_monitor::CreatePowerMonitorFn>,
+        ),
+        Some(Box::new(power_monitor::powerd::client::DBusClient::connect)
+            as Box<dyn power_monitor::CreatePowerClientFn>),
+    );
 
     #[cfg(not(feature = "power-monitor-powerd"))]
-    let create_monitor = None;
+    let (create_monitor, create_client) = (None, None);
 
     let irq_evt = devices::IrqLevelEvent::new().map_err(DeviceRegistrationError::EventCreate)?;
 
@@ -75,6 +81,7 @@ pub fn add_goldfish_battery(
             .map_err(DeviceRegistrationError::EventClone)?,
         response_tube,
         create_monitor,
+        create_client,
     )
     .map_err(DeviceRegistrationError::RegisterBattery)?;
     goldfish_bat.to_aml_bytes(amls);
diff --git a/base/src/custom_serde.rs b/base/src/custom_serde.rs
index 94965486e..9d4eed736 100644
--- a/base/src/custom_serde.rs
+++ b/base/src/custom_serde.rs
@@ -60,3 +60,36 @@ where
     })?;
     Ok(vals_arr)
 }
+
+pub fn serialize_map_as_kv_vec<
+    'se,
+    MapKeyType: 'se + Serialize,
+    MapValType: 'se + Serialize,
+    MapType: std::iter::IntoIterator<Item = (&'se MapKeyType, &'se MapValType)>,
+    S,
+>(
+    map: MapType,
+    serializer: S,
+) -> Result<S::Ok, S::Error>
+where
+    S: Serializer,
+{
+    let kv_vec: Vec<(&MapKeyType, &MapValType)> = map.into_iter().collect();
+    serde::Serialize::serialize(&kv_vec, serializer)
+}
+
+pub fn deserialize_map_from_kv_vec<
+    'de,
+    MapKeyType: Deserialize<'de>,
+    MapValType: Deserialize<'de>,
+    MapType: std::iter::FromIterator<(MapKeyType, MapValType)>,
+    D,
+>(
+    deserializer: D,
+) -> Result<MapType, D::Error>
+where
+    D: Deserializer<'de>,
+{
+    let kv_vec: Vec<(MapKeyType, MapValType)> = serde::Deserialize::deserialize(deserializer)?;
+    Ok(MapType::from_iter(kv_vec))
+}
diff --git a/base/src/lib.rs b/base/src/lib.rs
index 2232bfdae..455992052 100644
--- a/base/src/lib.rs
+++ b/base/src/lib.rs
@@ -186,6 +186,7 @@ pub use platform::getpid;
 pub use platform::open_file_or_duplicate;
 pub use platform::platform_timer_resolution::enable_high_res_timers;
 pub use platform::set_cpu_affinity;
+pub use platform::set_thread_name;
 pub use platform::BlockingMode;
 pub use platform::EventContext;
 pub use platform::FramingMode;
diff --git a/base/src/sys/linux/mod.rs b/base/src/sys/linux/mod.rs
index ea185c816..77463a9a9 100644
--- a/base/src/sys/linux/mod.rs
+++ b/base/src/sys/linux/mod.rs
@@ -40,6 +40,7 @@ mod timer;
 pub mod vsock;
 mod write_zeroes;
 
+use std::ffi::CString;
 use std::fs::remove_file;
 use std::fs::File;
 use std::fs::OpenOptions;
@@ -69,6 +70,7 @@ use libc::c_int;
 use libc::c_long;
 use libc::fcntl;
 use libc::pipe2;
+use libc::prctl;
 use libc::syscall;
 use libc::waitpid;
 use libc::SYS_getpid;
@@ -76,6 +78,7 @@ use libc::SYS_getppid;
 use libc::SYS_gettid;
 use libc::EINVAL;
 use libc::O_CLOEXEC;
+use libc::PR_SET_NAME;
 use libc::SIGKILL;
 use libc::WNOHANG;
 pub use mmap::*;
@@ -114,6 +117,19 @@ pub type Uid = libc::uid_t;
 pub type Gid = libc::gid_t;
 pub type Mode = libc::mode_t;
 
+/// Safe wrapper for PR_SET_NAME(2const)
+#[inline(always)]
+pub fn set_thread_name(name: &str) -> Result<()> {
+    let name = CString::new(name).or(Err(Error::new(EINVAL)))?;
+    // SAFETY: prctl copies name and doesn't expect it to outlive this function.
+    let ret = unsafe { prctl(PR_SET_NAME, name.as_c_str()) };
+    if ret == 0 {
+        Ok(())
+    } else {
+        errno_result()
+    }
+}
+
 /// This bypasses `libc`'s caching `getpid(2)` wrapper which can be invalid if a raw clone was used
 /// elsewhere.
 #[inline(always)]
diff --git a/base/src/sys/macos/mod.rs b/base/src/sys/macos/mod.rs
index db16a1e39..510ef11f2 100644
--- a/base/src/sys/macos/mod.rs
+++ b/base/src/sys/macos/mod.rs
@@ -21,6 +21,10 @@ pub(in crate::sys) use net::sockaddr_un;
 pub(in crate::sys) use net::sockaddrv4_to_lib_c;
 pub(in crate::sys) use net::sockaddrv6_to_lib_c;
 
+pub fn set_thread_name(_name: &str) -> crate::errno::Result<()> {
+    todo!();
+}
+
 pub fn get_cpu_affinity() -> crate::errno::Result<Vec<usize>> {
     todo!();
 }
diff --git a/base/src/sys/windows/mod.rs b/base/src/sys/windows/mod.rs
index b1181c7f9..464c73314 100644
--- a/base/src/sys/windows/mod.rs
+++ b/base/src/sys/windows/mod.rs
@@ -4,8 +4,6 @@
 
 //! Small system utility modules for usage by other modules.
 
-#![cfg(windows)]
-
 #[macro_use]
 pub mod ioctl;
 #[macro_use]
@@ -64,6 +62,7 @@ pub use system_info::allocation_granularity;
 pub use system_info::getpid;
 pub use system_info::number_of_logical_cores;
 pub use system_info::pagesize;
+pub use system_info::set_thread_name;
 pub use terminal::*;
 use winapi::shared::minwindef::DWORD;
 pub(crate) use write_zeroes::file_write_zeroes_at;
diff --git a/base/src/sys/windows/punch_hole.rs b/base/src/sys/windows/punch_hole.rs
index 094d2c469..67111f612 100644
--- a/base/src/sys/windows/punch_hole.rs
+++ b/base/src/sys/windows/punch_hole.rs
@@ -20,13 +20,13 @@ struct FILE_ZERO_DATA_INFORMATION {
 }
 
 pub(crate) fn file_punch_hole(handle: &File, offset: u64, length: u64) -> io::Result<()> {
-    let large_offset = if offset > std::i64::MAX as u64 {
+    let large_offset = if offset > i64::MAX as u64 {
         return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
     } else {
         LargeInteger::new(offset as i64)
     };
 
-    if (offset + length) > std::i64::MAX as u64 {
+    if (offset + length) > i64::MAX as u64 {
         return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
     }
 
diff --git a/base/src/sys/windows/system_info.rs b/base/src/sys/windows/system_info.rs
index 6b0a98bab..019b9282a 100644
--- a/base/src/sys/windows/system_info.rs
+++ b/base/src/sys/windows/system_info.rs
@@ -56,3 +56,8 @@ pub fn getpid() -> Pid {
     // Safe because we only use the return value.
     unsafe { GetCurrentProcessId() }
 }
+
+/// Set the name of the thread.
+pub fn set_thread_name(_name: &str) -> Result<()> {
+    todo!();
+}
diff --git a/bit_field/Android.bp b/bit_field/Android.bp
index 21278e1c8..fca166c4e 100644
--- a/bit_field/Android.bp
+++ b/bit_field/Android.bp
@@ -26,7 +26,7 @@ rust_test {
         unit_test: true,
     },
     edition: "2021",
-    rustlibs: ["libbit_field"],
+    rustlibs: ["libbit_field_crosvm"],
     proc_macros: ["libbit_field_derive"],
 }
 
@@ -44,12 +44,12 @@ rust_test {
         unit_test: true,
     },
     edition: "2021",
-    rustlibs: ["libbit_field"],
+    rustlibs: ["libbit_field_crosvm"],
     proc_macros: ["libbit_field_derive"],
 }
 
 rust_library {
-    name: "libbit_field",
+    name: "libbit_field_crosvm",
     defaults: ["crosvm_inner_defaults"],
     host_supported: true,
     crate_name: "bit_field",
diff --git a/cargo_embargo.json b/cargo_embargo.json
index 4a8f7685d..c651adae1 100644
--- a/cargo_embargo.json
+++ b/cargo_embargo.json
@@ -12,6 +12,7 @@
     "audio_aaudio",
     "balloon",
     "config-file",
+    "fs_runtime_ugid_map",
     // TODO: The "protos" crate has been modified such that it doesn't work with cargo. If we fix that,
     // we can remove a some patch files and enable "composite-disk" and "registered_events" here.
     // "composite-disk",
@@ -69,6 +70,7 @@
   "module_name_overrides": {
     "libbase": "libbase_rust",
     "libbase64": "libbase64_rust",
+    "libbit_field": "libbit_field_crosvm",
     "libfuse": "libfuse_rust",
     "liblog": "liblog_rust",
     "libminijail": "libminijail_rust",
@@ -95,6 +97,9 @@
       // For QCOM's crosvm fork.
       "//vendor:__subpackages__"
     ],
+    "libcrosvm_control_static": [
+      "//packages/modules/Virtualization/android/virtmgr"
+    ],
     "libdevices": [
       // For QCOM's crosvm fork.
       "//vendor:__subpackages__"
@@ -117,9 +122,6 @@
       // For QCOM's crosvm fork.
       "//vendor:__subpackages__"
     ],
-    "libvm_control": [
-      "//packages/modules/Virtualization/android/virtmgr"
-    ],
     "libvm_memory": [
       // For QCOM's crosvm fork.
       "//vendor:__subpackages__"
@@ -200,8 +202,7 @@
       "no_presubmit": true
     },
     "power_monitor": {
-      "copy_out": true,
-      "patch": "power_monitor/patches/Android.bp.patch"
+      "copy_out": true
     },
     "protos": {
       "add_toplevel_block": "protos/cargo2android_protobuf.bp",
diff --git a/cros_async/src/executor.rs b/cros_async/src/executor.rs
index 35e409561..25ec7ff8a 100644
--- a/cros_async/src/executor.rs
+++ b/cros_async/src/executor.rs
@@ -142,7 +142,6 @@ impl<'de> Deserialize<'de> for ExecutorKind {
     where
         D: serde::Deserializer<'de>,
     {
-        base::error!("ExecutorKind::deserialize");
         let string = String::deserialize(deserializer)?;
         ExecutorKind::from_arg_value(&string).map_err(serde::de::Error::custom)
     }
diff --git a/cros_async/src/sync/mu.rs b/cros_async/src/sync/mu.rs
index 596c4630e..064883903 100644
--- a/cros_async/src/sync/mu.rs
+++ b/cros_async/src/sync/mu.rs
@@ -826,7 +826,7 @@ unsafe impl<T: ?Sized + Send> Send for RwLock<T> {}
 #[allow(clippy::undocumented_unsafe_blocks)]
 unsafe impl<T: ?Sized + Send> Sync for RwLock<T> {}
 
-impl<T: ?Sized + Default> Default for RwLock<T> {
+impl<T: Default> Default for RwLock<T> {
     fn default() -> Self {
         Self::new(Default::default())
     }
diff --git a/cros_async/src/sync/spin.rs b/cros_async/src/sync/spin.rs
index 9af83a13d..20bdd4174 100644
--- a/cros_async/src/sync/spin.rs
+++ b/cros_async/src/sync/spin.rs
@@ -100,7 +100,7 @@ unsafe impl<T: ?Sized + Send> Send for SpinLock<T> {}
 #[allow(clippy::undocumented_unsafe_blocks)]
 unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}
 
-impl<T: ?Sized + Default> Default for SpinLock<T> {
+impl<T: Default> Default for SpinLock<T> {
     fn default() -> Self {
         Self::new(Default::default())
     }
diff --git a/crosvm_control/Android.bp b/crosvm_control/Android.bp
index 8d3755aae..d73c7ec15 100644
--- a/crosvm_control/Android.bp
+++ b/crosvm_control/Android.bp
@@ -56,4 +56,5 @@ rust_ffi_static {
     // doesn't actually exist.
     //
     // static_libs: ["libcrosvm_control_test"],
+    visibility: ["//packages/modules/Virtualization/android/virtmgr"],
 }
diff --git a/crosvm_control/cargo2android.bp.patch b/crosvm_control/cargo2android.bp.patch
index 50041b751..7b659f8ac 100644
--- a/crosvm_control/cargo2android.bp.patch
+++ b/crosvm_control/cargo2android.bp.patch
@@ -1,9 +1,9 @@
 diff --git a/crosvm_control/Android.bp b/crosvm_control/Android.bp
-index 1bce61cdd..ea437fc59 100644
+index 34e77e142..d73c7ec15 100644
 --- a/crosvm_control/Android.bp
 +++ b/crosvm_control/Android.bp
-@@ -25,7 +25,11 @@ rust_ffi_shared {
-         "liblibc",
+@@ -28,7 +28,11 @@ rust_ffi_shared {
+         "libswap",
          "libvm_control",
      ],
 -    static_libs: ["libcrosvm_control_test"],
@@ -15,8 +15,8 @@ index 1bce61cdd..ea437fc59 100644
  }
  
  rust_ffi_static {
-@@ -43,5 +47,9 @@ rust_ffi_static {
-         "liblibc",
+@@ -47,6 +51,10 @@ rust_ffi_static {
+         "libswap",
          "libvm_control",
      ],
 -    static_libs: ["libcrosvm_control_test"],
@@ -25,4 +25,5 @@ index 1bce61cdd..ea437fc59 100644
 +    // doesn't actually exist.
 +    //
 +    // static_libs: ["libcrosvm_control_test"],
+     visibility: ["//packages/modules/Virtualization/android/virtmgr"],
  }
diff --git a/crosvm_control/src/lib.rs b/crosvm_control/src/lib.rs
index 687c3c031..48a83ea72 100644
--- a/crosvm_control/src/lib.rs
+++ b/crosvm_control/src/lib.rs
@@ -44,6 +44,7 @@ use vm_control::client::handle_request;
 use vm_control::client::handle_request_with_timeout;
 use vm_control::client::vms_request;
 use vm_control::BalloonControlCommand;
+use vm_control::BatProperty;
 use vm_control::DiskControlCommand;
 use vm_control::RegisteredEvent;
 use vm_control::SwapCommand;
@@ -56,10 +57,13 @@ use vm_control::USB_CONTROL_MAX_PORTS;
 pub const VIRTIO_BALLOON_WS_MAX_NUM_BINS: usize = 16;
 pub const VIRTIO_BALLOON_WS_MAX_NUM_INTERVALS: usize = 15;
 
-fn validate_socket_path(socket_path: *const c_char) -> Option<PathBuf> {
+/// # Safety
+///
+/// This function is safe when the caller ensures the socket_path raw pointer can be safely passed
+/// to `CStr::from_ptr()`.
+unsafe fn validate_socket_path(socket_path: *const c_char) -> Option<PathBuf> {
     if !socket_path.is_null() {
-        // SAFETY: just checked that `socket_path` is not null.
-        let socket_path = unsafe { CStr::from_ptr(socket_path) };
+        let socket_path = CStr::from_ptr(socket_path);
         Some(PathBuf::from(socket_path.to_str().ok()?))
     } else {
         None
@@ -110,6 +114,9 @@ pub unsafe extern "C" fn crosvm_client_suspend_vm(socket_path: *const c_char) ->
 
 /// Resumes the crosvm instance whose control socket is listening on `socket_path`.
 ///
+/// Note: this function just resumes vcpus of the vm. If you need to perform a full resume, call
+/// crosvm_client_resume_vm_full.
+///
 /// The function returns true on success or false if an error occurred.
 ///
 /// # Safety
@@ -129,6 +136,29 @@ pub unsafe extern "C" fn crosvm_client_resume_vm(socket_path: *const c_char) ->
     .unwrap_or(false)
 }
 
+/// Resumes the crosvm instance whose control socket is listening on `socket_path`.
+///
+/// Note: unlike crosvm_client_resume_vm, this function resumes both vcpus and devices.
+///
+/// The function returns true on success or false if an error occurred.
+///
+/// # Safety
+///
+/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
+/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
+/// null pointers are passed.
+#[no_mangle]
+pub unsafe extern "C" fn crosvm_client_resume_vm_full(socket_path: *const c_char) -> bool {
+    catch_unwind(|| {
+        if let Some(socket_path) = validate_socket_path(socket_path) {
+            vms_request(&VmRequest::ResumeVm, socket_path).is_ok()
+        } else {
+            false
+        }
+    })
+    .unwrap_or(false)
+}
+
 /// Creates an RT vCPU for the crosvm instance whose control socket is listening on `socket_path`.
 ///
 /// The function returns true on success or false if an error occurred.
@@ -656,9 +686,8 @@ pub unsafe extern "C" fn crosvm_client_net_tap_detach(
 ///
 /// # Safety
 ///
-/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
-/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
-/// null pointers are passed.
+/// The caller will ensure the raw pointers in arguments passed in can be safely used by
+/// `CStr::from_ptr()`
 #[no_mangle]
 pub unsafe extern "C" fn crosvm_client_modify_battery(
     socket_path: *const c_char,
@@ -692,6 +721,92 @@ pub unsafe extern "C" fn crosvm_client_modify_battery(
     .unwrap_or(false)
 }
 
+/// Fakes the battery status of crosvm instance. The power status will always be on
+/// battery, and the maximum battery capacity could be read by guest is set to the
+/// `max_battery_capacity`.
+///
+/// The function returns true on success or false if an error occurred.
+///
+/// # Arguments
+///
+/// * `socket_path` - Path to the crosvm control socket
+/// * `battery_type` - Type of battery emulation corresponding to vm_tools::BatteryType
+/// * `max_battery_capacity` - maximum battery capacity could be read by guest
+///
+/// # Safety
+///
+/// The caller will ensure the raw pointers in arguments passed in can be safely used by
+/// `CStr::from_ptr()`
+#[no_mangle]
+pub unsafe extern "C" fn crosvm_client_fake_power(
+    socket_path: *const c_char,
+    battery_type: *const c_char,
+    max_battery_capacity: u32,
+) -> bool {
+    catch_unwind(|| {
+        if let Some(socket_path) = validate_socket_path(socket_path) {
+            if battery_type.is_null() || max_battery_capacity > 100 {
+                return false;
+            }
+
+            let battery_type = CStr::from_ptr(battery_type);
+            let fake_max_capacity_target: String = max_battery_capacity.to_string();
+
+            do_modify_battery(
+                socket_path.clone(),
+                battery_type.to_str().unwrap(),
+                &BatProperty::SetFakeBatConfig.to_string(),
+                fake_max_capacity_target.as_str(),
+            )
+            .is_ok()
+        } else {
+            false
+        }
+    })
+    .unwrap_or(false)
+}
+
+/// Resume the battery status of crosvm instance from fake status
+///
+/// The function returns true on success or false if an error occurred.
+///
+/// # Arguments
+///
+/// * `socket_path` - Path to the crosvm control socket
+/// * `battery_type` - Type of battery emulation corresponding to vm_tools::BatteryType
+///
+/// # Safety
+///
+/// The caller will ensure the raw pointers in arguments passed in can be safely used by
+/// `CStr::from_ptr()`.
+#[no_mangle]
+pub unsafe extern "C" fn crosvm_client_cancel_fake_power(
+    socket_path: *const c_char,
+    battery_type: *const c_char,
+) -> bool {
+    catch_unwind(|| {
+        if let Some(socket_path) = validate_socket_path(socket_path) {
+            if battery_type.is_null() {
+                return false;
+            }
+
+            // SAFETY: the caller has a responsibility of giving a valid char* pointer
+            let battery_type = CStr::from_ptr(battery_type);
+
+            do_modify_battery(
+                socket_path,
+                battery_type.to_str().unwrap(),
+                &BatProperty::CancelFakeBatConfig.to_string(),
+                "",
+            )
+            .is_ok()
+        } else {
+            false
+        }
+    })
+    .unwrap_or(false)
+}
+
 /// Resizes the disk of the crosvm instance whose control socket is listening on `socket_path`.
 ///
 /// The function returns true on success or false if an error occurred.
@@ -810,7 +925,11 @@ pub unsafe extern "C" fn crosvm_client_balloon_stats_with_timeout(
     )
 }
 
-fn crosvm_client_balloon_stats_impl(
+/// # Safety
+///
+/// This function is safe when the caller ensures the socket_path raw pointer can be safely passed
+/// to `CStr::from_ptr()`.
+unsafe fn crosvm_client_balloon_stats_impl(
     socket_path: *const c_char,
     timeout_ms: Option<Duration>,
     stats: *mut BalloonStatsFfi,
diff --git a/devices/Android.bp b/devices/Android.bp
index 8ca613244..642482664 100644
--- a/devices/Android.bp
+++ b/devices/Android.bp
@@ -32,6 +32,8 @@ rust_test {
         "audio",
         "audio_aaudio",
         "balloon",
+        "fs_permission_translation",
+        "fs_runtime_ugid_map",
         "geniezone",
         "gfxstream",
         "gpu",
@@ -51,7 +53,7 @@ rust_test {
         "libaudio_util",
         "libballoon_control",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbytes",
         "libcfg_if",
         "libchrono",
@@ -126,6 +128,8 @@ rust_test {
         "audio",
         "audio_aaudio",
         "balloon",
+        "fs_permission_translation",
+        "fs_runtime_ugid_map",
         "geniezone",
         "gfxstream",
         "gpu",
@@ -145,7 +149,7 @@ rust_test {
         "libaudio_util",
         "libballoon_control",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbytes",
         "libcfg_if",
         "libchrono",
@@ -216,6 +220,8 @@ rust_library {
         "audio",
         "audio_aaudio",
         "balloon",
+        "fs_permission_translation",
+        "fs_runtime_ugid_map",
         "geniezone",
         "gfxstream",
         "gpu",
@@ -235,7 +241,7 @@ rust_library {
         "libaudio_util",
         "libballoon_control",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libcfg_if",
         "libchrono",
         "libcros_async",
diff --git a/devices/Cargo.toml b/devices/Cargo.toml
index e161af4ec..eeb33a79f 100644
--- a/devices/Cargo.toml
+++ b/devices/Cargo.toml
@@ -7,7 +7,13 @@ edition = "2021"
 [features]
 android_display = ["gpu_display/android_display"]
 android_display_stub = ["gpu_display/android_display_stub"]
-arc_quota = ["dbus", "protobuf", "system_api"]
+arc_quota = ["dbus", "protobuf", "system_api", "fs_permission_translation"]
+fs_runtime_ugid_map = ["fs_permission_translation"]
+# Allow intercepting incoming virtio-fs requests to modify its permission, UID or GID.
+#
+# This feature is not supposed to be specified directly. Instead, this will be automatically
+# enabled when either `arc_quota` or `fs_runtime_ugid_map` is enabled.
+fs_permission_translation = []
 audio = []
 audio_aaudio = []
 audio_cras = ["libcras"]
@@ -20,15 +26,17 @@ pvclock = []
 geniezone = []
 usb = []
 vaapi = ["cros-codecs/vaapi", "crc32fast"]
+media = ["virtio-media"]
 video-decoder = []
 video-encoder = []
 minigbm = ["rutabaga_gfx/minigbm"]
 x = ["gpu_display/x", "rutabaga_gfx/x"]
 virgl_renderer = ["gpu", "rutabaga_gfx/virgl_renderer"]
 vtpm = ["system_api", "protobuf", "dbus"]
-gfxstream = ["gpu", "rutabaga_gfx/gfxstream"]
+gfxstream = ["gpu", "gpu_display/gfxstream", "rutabaga_gfx/gfxstream"]
 registered_events = []
 slirp = ["net_util/slirp"]
+slirp-ring-capture = []
 stats = []
 seccomp_trace = []
 swap = ["swap/enable"]
@@ -87,6 +95,7 @@ cros_tracing = { path = "../cros_tracing" }
 swap = { path = "../swap" }
 vmm_vhost = { path = "../third_party/vmm_vhost" }
 virtio_sys = { path = "../virtio_sys" }
+virtio-media = { version = "0.0.6", optional = true }
 vm_control = { path = "../vm_control" }
 vm_memory = { path = "../vm_memory" }
 zerocopy = { version = "0.7", features = ["derive"] }
diff --git a/devices/src/bat.rs b/devices/src/bat.rs
index 0deaaa1a0..a85501388 100644
--- a/devices/src/bat.rs
+++ b/devices/src/bat.rs
@@ -6,6 +6,7 @@ use std::sync::Arc;
 
 use acpi_tables::aml;
 use acpi_tables::aml::Aml;
+use anyhow::bail;
 use anyhow::Context;
 use base::error;
 use base::warn;
@@ -17,12 +18,14 @@ use base::Tube;
 use base::WaitContext;
 use base::WorkerThread;
 use power_monitor::BatteryStatus;
+use power_monitor::CreatePowerClientFn;
 use power_monitor::CreatePowerMonitorFn;
 use remain::sorted;
 use serde::Deserialize;
 use serde::Serialize;
 use sync::Mutex;
 use thiserror::Error;
+use vm_control::BatConfig;
 use vm_control::BatControlCommand;
 use vm_control::BatControlResult;
 
@@ -62,6 +65,7 @@ struct GoldfishBatteryState {
     current: u32,
     charge_counter: u32,
     charge_full: u32,
+    initialized: bool,
 }
 
 macro_rules! create_battery_func {
@@ -117,6 +121,9 @@ pub struct GoldfishBattery {
     monitor_thread: Option<WorkerThread<()>>,
     tube: Option<Tube>,
     create_power_monitor: Option<Box<dyn CreatePowerMonitorFn>>,
+    create_powerd_client: Option<Box<dyn CreatePowerClientFn>>,
+    // battery_config is used for goldfish battery to report fake battery to the guest.
+    battery_config: Arc<Mutex<BatConfig>>,
 }
 
 #[derive(Serialize, Deserialize)]
@@ -159,6 +166,9 @@ const BATTERY_STATUS_VAL_NOT_CHARGING: u32 = 3;
 /// Goldfish Battery health
 const BATTERY_HEALTH_VAL_UNKNOWN: u32 = 0;
 
+// Goldfish ac online status
+const AC_ONLINE_VAL_OFFLINE: u32 = 0;
+
 #[derive(EventToken)]
 pub(crate) enum Token {
     Commands,
@@ -173,6 +183,7 @@ fn command_monitor(
     kill_evt: Event,
     state: Arc<Mutex<GoldfishBatteryState>>,
     create_power_monitor: Option<Box<dyn CreatePowerMonitorFn>>,
+    battery_config: Arc<Mutex<BatConfig>>,
 ) {
     let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
         (&tube, Token::Commands),
@@ -223,6 +234,7 @@ fn command_monitor(
                         }
                     };
 
+                    let mut bat_config = battery_config.lock();
                     let mut bat_state = state.lock();
                     let inject_irq = match req {
                         BatControlCommand::SetStatus(status) => bat_state.set_status(status.into()),
@@ -239,6 +251,15 @@ fn command_monitor(
                             let v = ac_online != 0;
                             bat_state.set_ac_online(v.into())
                         }
+                        BatControlCommand::SetFakeBatConfig(max_capacity) => {
+                            let max_capacity = std::cmp::min(max_capacity, 100);
+                            *bat_config = BatConfig::Fake { max_capacity };
+                            true
+                        }
+                        BatControlCommand::CancelFakeConfig => {
+                            *bat_config = BatConfig::Real;
+                            true
+                        }
                     };
 
                     if inject_irq {
@@ -323,6 +344,7 @@ impl GoldfishBattery {
         irq_evt: IrqLevelEvent,
         tube: Tube,
         create_power_monitor: Option<Box<dyn CreatePowerMonitorFn>>,
+        create_powerd_client: Option<Box<dyn CreatePowerClientFn>>,
     ) -> Result<Self> {
         if mmio_base + GOLDFISHBAT_MMIO_LEN - 1 > u32::MAX as u64 {
             return Err(BatteryError::Non32BitMmioAddress);
@@ -339,8 +361,11 @@ impl GoldfishBattery {
             current: 0,
             charge_counter: 0,
             charge_full: 0,
+            initialized: false,
         }));
 
+        let battery_config = Arc::new(Mutex::new(BatConfig::default()));
+
         Ok(GoldfishBattery {
             state,
             mmio_base: mmio_base as u32,
@@ -350,6 +375,8 @@ impl GoldfishBattery {
             monitor_thread: None,
             tube: Some(tube),
             create_power_monitor,
+            create_powerd_client,
+            battery_config,
         })
     }
 
@@ -377,12 +404,60 @@ impl GoldfishBattery {
             let irq_evt = self.irq_evt.try_clone().unwrap();
             let bat_state = self.state.clone();
             let create_monitor_fn = self.create_power_monitor.take();
+            let battery_config = self.battery_config.clone();
             self.monitor_thread = Some(WorkerThread::start(self.debug_label(), move |kill_evt| {
-                command_monitor(tube, irq_evt, kill_evt, bat_state, create_monitor_fn)
+                command_monitor(
+                    tube,
+                    irq_evt,
+                    kill_evt,
+                    bat_state,
+                    create_monitor_fn,
+                    battery_config,
+                )
             }));
             self.activated = true;
         }
     }
+
+    fn initialize_battery_state(&mut self) -> anyhow::Result<()> {
+        let mut power_client = match &self.create_powerd_client {
+            Some(f) => match f() {
+                Ok(c) => c,
+                Err(e) => bail!("failed to connect to the powerd: {:#}", e),
+            },
+            None => return Ok(()),
+        };
+        match power_client.get_power_data() {
+            Ok(data) => {
+                let mut bat_state = self.state.lock();
+                bat_state.set_ac_online(data.ac_online.into());
+
+                match data.battery {
+                    Some(battery_data) => {
+                        bat_state.set_capacity(battery_data.percent);
+                        let battery_status = match battery_data.status {
+                            BatteryStatus::Unknown => BATTERY_STATUS_VAL_UNKNOWN,
+                            BatteryStatus::Charging => BATTERY_STATUS_VAL_CHARGING,
+                            BatteryStatus::Discharging => BATTERY_STATUS_VAL_DISCHARGING,
+                            BatteryStatus::NotCharging => BATTERY_STATUS_VAL_NOT_CHARGING,
+                        };
+                        bat_state.set_status(battery_status);
+                        bat_state.set_voltage(battery_data.voltage);
+                        bat_state.set_current(battery_data.current);
+                        bat_state.set_charge_counter(battery_data.charge_counter);
+                        bat_state.set_charge_full(battery_data.charge_full);
+                    }
+                    None => {
+                        bat_state.set_present(0);
+                    }
+                }
+                Ok(())
+            }
+            Err(e) => {
+                bail!("failed to get response from powerd: {:#}", e);
+            }
+        }
+    }
 }
 
 impl Drop for GoldfishBattery {
@@ -412,17 +487,43 @@ impl BusDevice for GoldfishBattery {
             return;
         }
 
+        // Before first read, we try to ask powerd the actual power data to initialize `self.state`.
+        if !self.state.lock().initialized {
+            match self.initialize_battery_state() {
+                Ok(()) => self.state.lock().initialized = true,
+                Err(e) => {
+                    error!(
+                        "{}: failed to get power data and update: {:#}",
+                        self.debug_label(),
+                        e
+                    );
+                }
+            }
+        }
+
         let val = match info.offset as u32 {
             BATTERY_INT_STATUS => {
                 // read to clear the interrupt status
                 std::mem::replace(&mut self.state.lock().int_status, 0)
             }
             BATTERY_INT_ENABLE => self.state.lock().int_enable,
-            BATTERY_AC_ONLINE => self.state.lock().ac_online,
-            BATTERY_STATUS => self.state.lock().status,
+            BATTERY_AC_ONLINE => match *self.battery_config.lock() {
+                BatConfig::Real => self.state.lock().ac_online,
+                BatConfig::Fake { max_capacity: _ } => AC_ONLINE_VAL_OFFLINE,
+            },
+            BATTERY_STATUS => match *self.battery_config.lock() {
+                BatConfig::Real => self.state.lock().status,
+                BatConfig::Fake { max_capacity: _ } => BATTERY_STATUS_VAL_DISCHARGING,
+            },
             BATTERY_HEALTH => self.state.lock().health,
             BATTERY_PRESENT => self.state.lock().present,
-            BATTERY_CAPACITY => self.state.lock().capacity,
+            BATTERY_CAPACITY => {
+                let max_capacity = match *self.battery_config.lock() {
+                    BatConfig::Real => 100,
+                    BatConfig::Fake { max_capacity } => max_capacity,
+                };
+                std::cmp::min(max_capacity, self.state.lock().capacity)
+            }
             BATTERY_VOLTAGE => self.state.lock().voltage,
             BATTERY_TEMP => 0,
             BATTERY_CHARGE_COUNTER => self.state.lock().charge_counter,
@@ -547,6 +648,7 @@ mod tests {
             IrqLevelEvent::new().unwrap(),
             Tube::pair().unwrap().1,
             None,
+            None,
         ).unwrap(),
         modify_device
     }
diff --git a/devices/src/bus.rs b/devices/src/bus.rs
index 755e7e9e7..ef433b580 100644
--- a/devices/src/bus.rs
+++ b/devices/src/bus.rs
@@ -700,11 +700,15 @@ impl Bus {
 
     /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
     ///
-    /// Returns true on success, otherwise `data` is untouched.
+    /// Returns true on success, otherwise `data` is filled with zeroes.
     pub fn read(&self, addr: u64, data: &mut [u8]) -> bool {
         #[cfg(feature = "stats")]
         let start = self.stats.lock().start_stat();
 
+        // Initialize `data` with all zeroes to ensure consistent results even if device `read()`
+        // implementations don't always fill every byte.
+        data.fill(0);
+
         let device_index = if let Some((offset, address, entry)) = self.get_device(addr) {
             let io = BusAccessInfo {
                 address,
@@ -965,6 +969,17 @@ mod tests {
         assert!(bus.write(0x15, &values));
     }
 
+    #[test]
+    fn bus_read_no_device() {
+        let bus = Bus::new(BusType::Io);
+
+        // read() should return false, since there is no device at address 0x10, but it should
+        // also fill the data with 0s.
+        let mut values = [1, 2, 3, 4];
+        assert!(!bus.read(0x10, &mut values));
+        assert_eq!(values, [0, 0, 0, 0]);
+    }
+
     suspendable_tests!(
         constant_device_true,
         ConstantDevice {
diff --git a/devices/src/irqchip/geniezone/mod.rs b/devices/src/irqchip/geniezone/mod.rs
index 3904c6bb6..77124a7f7 100644
--- a/devices/src/irqchip/geniezone/mod.rs
+++ b/devices/src/irqchip/geniezone/mod.rs
@@ -55,7 +55,7 @@ const AARCH64_GIC_DIST_SIZE: u64 = 0x10000;
 
 // These constants indicate the placement of the GIC registers in the physical
 // address space.
-const AARCH64_GIC_DIST_BASE: u64 = AARCH64_AXI_BASE - AARCH64_GIC_DIST_SIZE;
+const AARCH64_GIC_DIST_BASE: u64 = 0x40000000 - AARCH64_GIC_DIST_SIZE;
 const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;
 
 // This is the minimum number of SPI interrupts aligned to 32 + 32 for the
@@ -64,8 +64,6 @@ const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;
 // Number of SPIs (32), which is the NR_IRQS (64) minus the number of PPIs (16) and GSIs (16)
 pub const AARCH64_GIC_NR_SPIS: u32 = 32;
 
-const AARCH64_AXI_BASE: u64 = 0x40000000;
-
 impl GeniezoneKernelIrqChip {
     /// Construct a new GzvmKernelIrqchip.
     pub fn new(vm: GeniezoneVm, num_vcpus: usize) -> Result<GeniezoneKernelIrqChip> {
diff --git a/devices/src/irqchip/kvm/aarch64.rs b/devices/src/irqchip/kvm/aarch64.rs
index 46ff79109..452a140e8 100644
--- a/devices/src/irqchip/kvm/aarch64.rs
+++ b/devices/src/irqchip/kvm/aarch64.rs
@@ -48,7 +48,7 @@ const AARCH64_GIC_CPUI_SIZE: u64 = 0x20000;
 
 // These constants indicate the placement of the GIC registers in the physical
 // address space.
-const AARCH64_GIC_DIST_BASE: u64 = AARCH64_AXI_BASE - AARCH64_GIC_DIST_SIZE;
+const AARCH64_GIC_DIST_BASE: u64 = 0x40000000 - AARCH64_GIC_DIST_SIZE;
 const AARCH64_GIC_CPUI_BASE: u64 = AARCH64_GIC_DIST_BASE - AARCH64_GIC_CPUI_SIZE;
 const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;
 
@@ -58,8 +58,6 @@ pub const AARCH64_GIC_NR_IRQS: u32 = 64;
 // Number of SPIs (32), which is the NR_IRQS (64) minus the number of PPIs (16) and GSIs (16)
 pub const AARCH64_GIC_NR_SPIS: u32 = 32;
 
-const AARCH64_AXI_BASE: u64 = 0x40000000;
-
 impl KvmKernelIrqChip {
     /// Construct a new KvmKernelIrqchip.
     pub fn new(vm: KvmVm, num_vcpus: usize) -> Result<KvmKernelIrqChip> {
diff --git a/devices/src/lib.rs b/devices/src/lib.rs
index 28ab5a476..c124d7208 100644
--- a/devices/src/lib.rs
+++ b/devices/src/lib.rs
@@ -29,6 +29,8 @@ mod suspendable;
 mod sys;
 #[cfg(any(target_os = "android", target_os = "linux"))]
 mod virtcpufreq;
+#[cfg(any(target_os = "android", target_os = "linux"))]
+mod virtcpufreq_v2;
 pub mod virtio;
 #[cfg(feature = "vtpm")]
 mod vtpm_proxy;
@@ -132,6 +134,8 @@ pub use self::suspendable::DeviceState;
 pub use self::suspendable::Suspendable;
 #[cfg(any(target_os = "android", target_os = "linux"))]
 pub use self::virtcpufreq::VirtCpufreq;
+#[cfg(any(target_os = "android", target_os = "linux"))]
+pub use self::virtcpufreq_v2::VirtCpufreqV2;
 pub use self::virtio::VirtioMmioDevice;
 pub use self::virtio::VirtioPciDevice;
 #[cfg(feature = "vtpm")]
diff --git a/devices/src/register_space/register.rs b/devices/src/register_space/register.rs
index a61424397..c5cbe7eb4 100644
--- a/devices/src/register_space/register.rs
+++ b/devices/src/register_space/register.rs
@@ -131,6 +131,7 @@ pub trait RegisterInterface: Send {
     /// Handle write.
     fn write(&self, _addr: RegisterOffset, _data: &[u8]) {}
     /// Reset this register to default value.
+    #[allow(dead_code)]
     fn reset(&self) {}
 }
 
diff --git a/devices/src/serial/sys/windows.rs b/devices/src/serial/sys/windows.rs
index 1ae78f038..88b20532a 100644
--- a/devices/src/serial/sys/windows.rs
+++ b/devices/src/serial/sys/windows.rs
@@ -273,8 +273,8 @@ mod tests {
         #[allow(clippy::undocumented_unsafe_blocks)]
         unsafe {
             // Check that serial output is sent to the pipe
-            device.write(serial_bus_address(DATA), &[b'T']);
-            device.write(serial_bus_address(DATA), &[b'D']);
+            device.write(serial_bus_address(DATA), b"T");
+            device.write(serial_bus_address(DATA), b"D");
 
             let mut read_buf: [u8; 2] = [0; 2];
 
diff --git a/devices/src/serial_device.rs b/devices/src/serial_device.rs
index 3330a9ca2..e8db88c3d 100644
--- a/devices/src/serial_device.rs
+++ b/devices/src/serial_device.rs
@@ -9,6 +9,8 @@ use std::fs::OpenOptions;
 use std::io;
 use std::io::stdin;
 use std::io::stdout;
+#[cfg(unix)]
+use std::os::unix::net::UnixStream;
 use std::path::PathBuf;
 
 use base::error;
@@ -37,12 +39,16 @@ use crate::PciAddress;
 pub enum Error {
     #[error("Unable to clone an Event: {0}")]
     CloneEvent(base::Error),
+    #[error("Unable to clone a Unix Stream: {0}")]
+    CloneUnixStream(std::io::Error),
     #[error("Unable to clone file: {0}")]
     FileClone(std::io::Error),
     #[error("Unable to create file '{1}': {0}")]
     FileCreate(std::io::Error, PathBuf),
     #[error("Unable to open file '{1}': {0}")]
     FileOpen(std::io::Error, PathBuf),
+    #[error("Invalid serial config specified: {0}")]
+    InvalidConfig(String),
     #[error("Serial device path '{0} is invalid")]
     InvalidPath(PathBuf),
     #[error("Invalid serial hardware: {0}")]
@@ -64,6 +70,8 @@ pub enum Error {
 /// Trait for types that can be used as input for a serial device.
 pub trait SerialInput: io::Read + ReadNotifier + Send {}
 impl SerialInput for File {}
+#[cfg(unix)]
+impl SerialInput for UnixStream {}
 #[cfg(windows)]
 impl SerialInput for WinConsole {}
 
@@ -78,6 +86,9 @@ pub enum SerialType {
     #[cfg_attr(unix, serde(rename = "unix"))]
     #[cfg_attr(windows, serde(rename = "namedpipe"))]
     SystemSerialType,
+    // Use the same Unix domain socket for input and output.
+    #[cfg(unix)]
+    UnixStream,
 }
 
 impl Default for SerialType {
@@ -94,6 +105,8 @@ impl Display for SerialType {
             SerialType::Sink => "Sink".to_string(),
             SerialType::Syslog => "Syslog".to_string(),
             SerialType::SystemSerialType => SYSTEM_SERIAL_TYPE_NAME.to_string(),
+            #[cfg(unix)]
+            SerialType::UnixStream => "UnixStream".to_string(),
         };
 
         write!(f, "{}", s)
@@ -104,10 +117,15 @@ impl Display for SerialType {
 #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
 #[serde(rename_all = "kebab-case")]
 pub enum SerialHardware {
-    Serial,              // Standard PC-style (8250/16550 compatible) UART
-    VirtioConsole,       // virtio-console device
-    Debugcon,            // Bochs style debug port
-    LegacyVirtioConsole, // legacy virtio-console device (alias for VirtioConsole)
+    /// Standard PC-style (8250/16550 compatible) UART
+    Serial,
+
+    /// virtio-console device
+    #[serde(alias = "legacy-virtio-console")]
+    VirtioConsole,
+
+    /// Bochs style debug port
+    Debugcon,
 }
 
 impl Default for SerialHardware {
@@ -122,7 +140,6 @@ impl Display for SerialHardware {
             SerialHardware::Serial => "serial".to_string(),
             SerialHardware::VirtioConsole => "virtio-console".to_string(),
             SerialHardware::Debugcon => "debugcon".to_string(),
-            SerialHardware::LegacyVirtioConsole => "legacy-virtio-console".to_string(),
         };
 
         write!(f, "{}", s)
@@ -147,6 +164,10 @@ pub struct SerialParameters {
     pub name: Option<String>,
     pub path: Option<PathBuf>,
     pub input: Option<PathBuf>,
+    /// Use the given `UnixStream` as input as well as output.
+    /// This flag can be used only when `type_` is `UnixStream`.
+    #[cfg(unix)]
+    pub input_unix_stream: bool,
     #[serde(default = "serial_parameters_default_num")]
     pub num: u8,
     pub console: bool,
@@ -189,6 +210,24 @@ impl SerialParameters {
         keep_rds.push(evt.as_raw_descriptor());
         cros_tracing::push_descriptors!(keep_rds);
         metrics::push_descriptors(keep_rds);
+
+        // When `self.input_unix_stream` is specified, use `self.path` for both output and input.
+        #[cfg(unix)]
+        if self.input_unix_stream {
+            if self.input.is_some() {
+                return Err(Error::InvalidConfig(
+                    "input-unix-stream can't be passed when input is specified".to_string(),
+                ));
+            }
+            if self.type_ != SerialType::UnixStream {
+                return Err(Error::InvalidConfig(
+                    "input-unix-stream must be used with type=unix-stream".to_string(),
+                ));
+            }
+
+            return create_unix_stream_serial_device(self, protection_type, evt, keep_rds);
+        }
+
         let input: Option<Box<dyn SerialInput>> = if let Some(input_path) = &self.input {
             let input_path = input_path.as_path();
 
@@ -242,6 +281,13 @@ impl SerialParameters {
                     keep_rds,
                 );
             }
+            #[cfg(unix)]
+            SerialType::UnixStream => {
+                let path = self.path.as_ref().ok_or(Error::PathRequired)?;
+                let output = UnixStream::connect(path).map_err(Error::SocketConnect)?;
+                keep_rds.push(output.as_raw_descriptor());
+                (Some(Box::new(output)), None)
+            }
         };
         Ok(T::new(
             protection_type,
@@ -282,6 +328,8 @@ mod tests {
                 name: None,
                 path: None,
                 input: None,
+                #[cfg(unix)]
+                input_unix_stream: false,
                 num: 1,
                 console: false,
                 earlycon: false,
@@ -307,6 +355,11 @@ mod tests {
         let opt = "type=namedpipe";
         let params = from_serial_arg(opt).unwrap();
         assert_eq!(params.type_, SerialType::SystemSerialType);
+        #[cfg(unix)]
+        {
+            let params = from_serial_arg("type=unix-stream").unwrap();
+            assert_eq!(params.type_, SerialType::UnixStream);
+        }
         let params = from_serial_arg("type=foobar");
         assert!(params.is_err());
 
@@ -332,6 +385,19 @@ mod tests {
         let params = from_serial_arg("input");
         assert!(params.is_err());
 
+        #[cfg(unix)]
+        {
+            // input-unix-stream parameter
+            let params = from_serial_arg("input-unix-stream").unwrap();
+            assert!(params.input_unix_stream);
+            let params = from_serial_arg("input-unix-stream=true").unwrap();
+            assert!(params.input_unix_stream);
+            let params = from_serial_arg("input-unix-stream=false").unwrap();
+            assert!(!params.input_unix_stream);
+            let params = from_serial_arg("input-unix-stream=foobar");
+            assert!(params.is_err());
+        }
+
         // console parameter
         let params = from_serial_arg("console").unwrap();
         assert!(params.console);
@@ -392,6 +458,8 @@ mod tests {
                 name: None,
                 path: Some("/some/path".into()),
                 input: Some("/some/input".into()),
+                #[cfg(unix)]
+                input_unix_stream: false,
                 num: 5,
                 console: true,
                 earlycon: true,
diff --git a/devices/src/sys/linux/serial_device.rs b/devices/src/sys/linux/serial_device.rs
index d7d122892..460692955 100644
--- a/devices/src/sys/linux/serial_device.rs
+++ b/devices/src/sys/linux/serial_device.rs
@@ -8,6 +8,7 @@ use std::io;
 use std::io::ErrorKind;
 use std::io::Write;
 use std::os::unix::net::UnixDatagram;
+use std::os::unix::net::UnixStream;
 use std::path::Path;
 use std::path::PathBuf;
 use std::thread;
@@ -231,3 +232,32 @@ pub(crate) fn create_system_type_serial_device<T: SerialDevice>(
         None => Err(Error::PathRequired),
     }
 }
+
+/// Creates a serial device that use the given UnixStream path for both input and output.
+pub(crate) fn create_unix_stream_serial_device<T: SerialDevice>(
+    param: &SerialParameters,
+    protection_type: ProtectionType,
+    evt: Event,
+    keep_rds: &mut Vec<RawDescriptor>,
+) -> std::result::Result<T, Error> {
+    let path = param.path.as_ref().ok_or(Error::PathRequired)?;
+    let input = UnixStream::connect(path).map_err(Error::SocketConnect)?;
+    let output = input.try_clone().map_err(Error::CloneUnixStream)?;
+    keep_rds.push(input.as_raw_descriptor());
+    keep_rds.push(output.as_raw_descriptor());
+
+    Ok(T::new(
+        protection_type,
+        evt,
+        Some(Box::new(input)),
+        Some(Box::new(output)),
+        None,
+        SerialOptions {
+            name: param.name.clone(),
+            out_timestamp: param.out_timestamp,
+            console: param.console,
+            pci_address: param.pci_address,
+        },
+        keep_rds.to_vec(),
+    ))
+}
diff --git a/devices/src/usb/backend/host_backend/host_device.rs b/devices/src/usb/backend/host_backend/host_device.rs
index c24eb5be9..73ba24d79 100644
--- a/devices/src/usb/backend/host_backend/host_device.rs
+++ b/devices/src/usb/backend/host_backend/host_device.rs
@@ -367,12 +367,7 @@ impl XhciBackendDevice for HostDevice {
     }
 
     fn get_speed(&self) -> Option<DeviceSpeed> {
-        let speed = self.device.lock().get_speed();
-        if let Ok(speed) = speed {
-            speed
-        } else {
-            None
-        }
+        self.device.lock().get_speed().unwrap_or(None)
     }
 
     fn alloc_streams(&self, ep: u8, num_streams: u16) -> Result<()> {
diff --git a/devices/src/virtcpufreq_v2.rs b/devices/src/virtcpufreq_v2.rs
new file mode 100644
index 000000000..713d8bb3d
--- /dev/null
+++ b/devices/src/virtcpufreq_v2.rs
@@ -0,0 +1,420 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+use std::fs::File;
+use std::path::PathBuf;
+use std::sync::atomic::AtomicU32;
+use std::sync::atomic::Ordering;
+use std::sync::Arc;
+use std::time::Duration;
+
+use anyhow::Context;
+use base::sched_attr;
+use base::sched_setattr;
+use base::set_cpu_affinity;
+use base::warn;
+use base::Error;
+use base::Event;
+use base::EventToken;
+use base::Timer;
+use base::TimerTrait;
+use base::Tube;
+use base::WaitContext;
+use base::WorkerThread;
+use sync::Mutex;
+
+use crate::pci::CrosvmDeviceId;
+use crate::BusAccessInfo;
+use crate::BusDevice;
+use crate::DeviceId;
+use crate::Suspendable;
+
+const CPUFREQ_GOV_SCALE_FACTOR_DEFAULT: u32 = 100;
+const CPUFREQ_GOV_SCALE_FACTOR_SCHEDUTIL: u32 = 80;
+
+const SCHED_FLAG_RESET_ON_FORK: u64 = 0x1;
+const SCHED_FLAG_KEEP_POLICY: u64 = 0x08;
+const SCHED_FLAG_KEEP_PARAMS: u64 = 0x10;
+const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
+const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 0x40;
+
+const VCPUFREQ_CUR_PERF: u32 = 0x0;
+const VCPUFREQ_SET_PERF: u32 = 0x4;
+const VCPUFREQ_FREQTBL_LEN: u32 = 0x8;
+const VCPUFREQ_FREQTBL_SEL: u32 = 0xc;
+const VCPUFREQ_FREQTBL_RD: u32 = 0x10;
+const VCPUFREQ_PERF_DOMAIN: u32 = 0x14;
+
+const SCHED_FLAG_KEEP_ALL: u64 = SCHED_FLAG_KEEP_POLICY | SCHED_FLAG_KEEP_PARAMS;
+const SCHED_CAPACITY_SCALE: u32 = 1024;
+
+// Timer values in microseconds
+const MIN_TIMER_US: u32 = 75;
+const TIMER_OVERHEAD_US: u32 = 15;
+
+/// Upstream linux compatible version of the virtual cpufreq interface
+pub struct VirtCpufreqV2 {
+    vcpu_freq_table: Vec<u32>,
+    pcpu_fmax: u32,
+    pcpu_capacity: u32,
+    pcpu: u32,
+    util_factor: u32,
+    freqtbl_sel: u32,
+    vcpu_domain: u32,
+    domain_uclamp_min: Option<File>,
+    domain_uclamp_max: Option<File>,
+    vcpu_fmax: u32,
+    vcpu_capacity: u32,
+    vcpu_relative_capacity: u32,
+    worker: Option<WorkerThread<()>>,
+    timer: Arc<Mutex<Timer>>,
+    vm_ctrl: Arc<Mutex<Tube>>,
+    pcpu_min_cap: u32,
+    /// The largest(or the last) pCPU index to be used by all the vCPUs. This index is used to
+    /// figure out the proper placement of the throttle workers which are placed on pCPUs right
+    /// after the last pCPU being used the vCPUs. Throttle workers require their own exclusive
+    /// pCPU allocation and this ensure that the workers are placed contiguously and makes it
+    /// easier for user to manage pCPU allocations when running multiple instances on a large
+    /// server.
+    largest_pcpu_idx: usize,
+    //TODO: Put the shared_domain_members in a struct
+    shared_domain_vcpus: Vec<usize>,
+    shared_domain_perf: Arc<AtomicU32>,
+}
+
+fn get_cpu_info(cpu_id: u32, property: &str) -> Result<u32, Error> {
+    let path = format!("/sys/devices/system/cpu/cpu{cpu_id}/{property}");
+    std::fs::read_to_string(path)?
+        .trim()
+        .parse()
+        .map_err(|_| Error::new(libc::EINVAL))
+}
+
+fn get_cpu_info_str(cpu_id: u32, property: &str) -> Result<String, Error> {
+    let path = format!("/sys/devices/system/cpu/cpu{cpu_id}/{property}");
+    std::fs::read_to_string(path).map_err(|_| Error::new(libc::EINVAL))
+}
+
+fn get_cpu_capacity(cpu_id: u32) -> Result<u32, Error> {
+    get_cpu_info(cpu_id, "cpu_capacity")
+}
+
+fn get_cpu_maxfreq_khz(cpu_id: u32) -> Result<u32, Error> {
+    get_cpu_info(cpu_id, "cpufreq/cpuinfo_max_freq")
+}
+
+fn get_cpu_minfreq_khz(cpu_id: u32) -> Result<u32, Error> {
+    get_cpu_info(cpu_id, "cpufreq/cpuinfo_min_freq")
+}
+
+fn get_cpu_curfreq_khz(cpu_id: u32) -> Result<u32, Error> {
+    get_cpu_info(cpu_id, "cpufreq/scaling_cur_freq")
+}
+
+fn get_cpu_util_factor(cpu_id: u32) -> Result<u32, Error> {
+    let gov = get_cpu_info_str(cpu_id, "cpufreq/scaling_governor")?;
+    match gov.trim() {
+        "schedutil" => Ok(CPUFREQ_GOV_SCALE_FACTOR_SCHEDUTIL),
+        _ => Ok(CPUFREQ_GOV_SCALE_FACTOR_DEFAULT),
+    }
+}
+
+impl VirtCpufreqV2 {
+    pub fn new(
+        pcpu: u32,
+        vcpu_freq_table: Vec<u32>,
+        vcpu_domain_path: Option<PathBuf>,
+        vcpu_domain: u32,
+        vcpu_capacity: u32,
+        largest_pcpu_idx: usize,
+        vm_ctrl: Arc<Mutex<Tube>>,
+        shared_domain_vcpus: Vec<usize>,
+        shared_domain_perf: Arc<AtomicU32>,
+    ) -> Self {
+        let pcpu_capacity = get_cpu_capacity(pcpu).expect("Error reading capacity");
+        let pcpu_fmax = get_cpu_maxfreq_khz(pcpu).expect("Error reading max freq");
+        let util_factor = get_cpu_util_factor(pcpu).expect("Error getting util factor");
+        let freqtbl_sel = 0;
+        let mut domain_uclamp_min = None;
+        let mut domain_uclamp_max = None;
+        // The vcpu_capacity passed in is normalized for frequency, reverse the normalization to
+        // get the performance per clock ratio between the vCPU and the pCPU its running on. This
+        // "relative capacity" is an approximation of the delta in IPC (Instructions per Cycle)
+        // between the pCPU vs vCPU running a usecase containing a mix of instruction types.
+        let vcpu_fmax = vcpu_freq_table.clone().into_iter().max().unwrap();
+        let vcpu_relative_capacity =
+            u32::try_from(u64::from(vcpu_capacity) * u64::from(pcpu_fmax) / u64::from(vcpu_fmax))
+                .unwrap();
+        let pcpu_min_cap =
+            get_cpu_minfreq_khz(pcpu).expect("Error reading min freq") * pcpu_capacity / pcpu_fmax;
+
+        if let Some(cgroup_path) = &vcpu_domain_path {
+            domain_uclamp_min = Some(
+                File::create(cgroup_path.join("cpu.uclamp.min")).unwrap_or_else(|err| {
+                    panic!(
+                        "Err: {}, Unable to open: {}",
+                        err,
+                        cgroup_path.join("cpu.uclamp.min").display()
+                    )
+                }),
+            );
+            domain_uclamp_max = Some(
+                File::create(cgroup_path.join("cpu.uclamp.max")).unwrap_or_else(|err| {
+                    panic!(
+                        "Err: {}, Unable to open: {}",
+                        err,
+                        cgroup_path.join("cpu.uclamp.max").display()
+                    )
+                }),
+            );
+        }
+
+        VirtCpufreqV2 {
+            vcpu_freq_table,
+            pcpu_fmax,
+            pcpu_capacity,
+            pcpu,
+            util_factor,
+            freqtbl_sel,
+            vcpu_domain,
+            domain_uclamp_min,
+            domain_uclamp_max,
+            vcpu_fmax,
+            vcpu_capacity,
+            vcpu_relative_capacity,
+            worker: None,
+            timer: Arc::new(Mutex::new(Timer::new().expect("failed to create Timer"))),
+            vm_ctrl,
+            pcpu_min_cap,
+            largest_pcpu_idx,
+            shared_domain_vcpus,
+            shared_domain_perf,
+        }
+    }
+}
+
+impl BusDevice for VirtCpufreqV2 {
+    fn device_id(&self) -> DeviceId {
+        CrosvmDeviceId::VirtCpufreq.into()
+    }
+
+    fn debug_label(&self) -> String {
+        "VirtCpufreq Device".to_owned()
+    }
+
+    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
+        if data.len() != std::mem::size_of::<u32>() {
+            warn!(
+                "{}: unsupported read length {}, only support 4bytes read",
+                self.debug_label(),
+                data.len()
+            );
+            return;
+        }
+
+        let val = match info.offset as u32 {
+            VCPUFREQ_CUR_PERF => {
+                let shared_util = self.shared_domain_perf.load(Ordering::SeqCst);
+                if shared_util != 0 && shared_util < self.pcpu_min_cap {
+                    shared_util * self.vcpu_fmax / self.vcpu_capacity
+                } else {
+                    match get_cpu_curfreq_khz(self.pcpu) {
+                        Ok(freq) => u32::try_from(
+                            u64::from(freq) * u64::from(self.pcpu_capacity)
+                                / u64::from(self.vcpu_relative_capacity),
+                        )
+                        .unwrap(),
+                        Err(_) => 0,
+                    }
+                }
+            }
+            VCPUFREQ_FREQTBL_LEN => self.vcpu_freq_table.len() as u32,
+            VCPUFREQ_PERF_DOMAIN => self.vcpu_domain,
+            VCPUFREQ_FREQTBL_RD => *self
+                .vcpu_freq_table
+                .get(self.freqtbl_sel as usize)
+                .unwrap_or(&0),
+            _ => {
+                warn!("{}: unsupported read address {}", self.debug_label(), info);
+                return;
+            }
+        };
+
+        let val_arr = val.to_ne_bytes();
+        data.copy_from_slice(&val_arr);
+    }
+
+    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
+        let val: u32 = match data.try_into().map(u32::from_ne_bytes) {
+            Ok(v) => v,
+            Err(e) => {
+                warn!(
+                    "{}: unsupported write length {:#}, only support 4bytes write",
+                    self.debug_label(),
+                    e
+                );
+                return;
+            }
+        };
+
+        match info.offset as u32 {
+            VCPUFREQ_SET_PERF => {
+                // Util margin depends on the cpufreq governor on the host
+                let util_raw = match u32::try_from(
+                    u64::from(self.vcpu_capacity) * u64::from(val) / u64::from(self.vcpu_fmax),
+                ) {
+                    Ok(util) => util,
+                    Err(e) => {
+                        warn!("Potential overflow {:#}", e);
+                        SCHED_CAPACITY_SCALE
+                    }
+                };
+
+                let util = util_raw * self.util_factor / CPUFREQ_GOV_SCALE_FACTOR_DEFAULT;
+
+                if let (Some(domain_uclamp_min), Some(domain_uclamp_max)) =
+                    (&mut self.domain_uclamp_min, &mut self.domain_uclamp_max)
+                {
+                    use std::io::Write;
+                    let val = util as f32 * 100.0 / SCHED_CAPACITY_SCALE as f32;
+                    let val_formatted = format!("{:4}", val).into_bytes();
+
+                    if self.vcpu_fmax != self.pcpu_fmax {
+                        if let Err(e) = domain_uclamp_max.write(&val_formatted) {
+                            warn!("Error setting uclamp_max: {:#}", e);
+                        }
+                    }
+                    if let Err(e) = domain_uclamp_min.write(&val_formatted) {
+                        warn!("Error setting uclamp_min: {:#}", e);
+                    }
+                } else {
+                    let mut sched_attr = sched_attr::default();
+                    sched_attr.sched_flags = SCHED_FLAG_KEEP_ALL
+                        | SCHED_FLAG_UTIL_CLAMP_MIN
+                        | SCHED_FLAG_UTIL_CLAMP_MAX
+                        | SCHED_FLAG_RESET_ON_FORK;
+                    sched_attr.sched_util_min = util;
+
+                    if self.vcpu_fmax != self.pcpu_fmax {
+                        sched_attr.sched_util_max = util;
+                    } else {
+                        sched_attr.sched_util_max = SCHED_CAPACITY_SCALE;
+                    }
+
+                    if let Err(e) = sched_setattr(0, &mut sched_attr, 0) {
+                        panic!("{}: Error setting util value: {:#}", self.debug_label(), e);
+                    }
+                }
+
+                self.shared_domain_perf.store(util_raw, Ordering::SeqCst);
+                let timer = self.timer.clone();
+                if self.worker.is_none() {
+                    let vcpu_id = info.id;
+                    let vm_ctrl = self.vm_ctrl.clone();
+                    let worker_cpu_affinity = self.largest_pcpu_idx + self.vcpu_domain as usize + 1;
+                    let shared_domain_vcpus = self.shared_domain_vcpus.clone();
+
+                    self.worker = Some(WorkerThread::start(
+                        format!("vcpu_throttle{vcpu_id}"),
+                        move |kill_evt| {
+                            vcpufreq_worker_thread(
+                                shared_domain_vcpus,
+                                kill_evt,
+                                timer,
+                                vm_ctrl,
+                                worker_cpu_affinity,
+                            )
+                            .expect("error running vpucfreq_worker")
+                        },
+                    ));
+                } else if util_raw < self.pcpu_min_cap {
+                    // The period is porportional to the performance requested by the vCPU, we
+                    // reduce the timeout period to increase the amount of throttling applied to
+                    // the vCPU as the performance decreases. Ex. If vCPU requests half of the
+                    // performance relatively to its pCPU@FMin, the vCPU will spend 50% of its
+                    // cycles being throttled to increase time for the same workload that otherwise
+                    // would've taken 1/2 of the time if ran at pCPU@FMin. We could've
+                    // alternatively adjusted the workload and used some fixed period (such as
+                    // 250us), but there's a floor for the minimum delay we add (cost of handling
+                    // the userspace exit) and limits the range of performance we can emulate.
+                    let timeout_period = (MIN_TIMER_US + TIMER_OVERHEAD_US) as f32
+                        / (1.0 - (util_raw as f32 / self.pcpu_min_cap as f32));
+                    let _ = timer
+                        .lock()
+                        .reset_repeating(Duration::from_micros(timeout_period as u64));
+                } else {
+                    let _ = timer.lock().clear();
+                }
+            }
+            VCPUFREQ_FREQTBL_SEL => self.freqtbl_sel = val,
+            _ => {
+                warn!("{}: unsupported read address {}", self.debug_label(), info);
+            }
+        }
+    }
+}
+
+pub fn vcpufreq_worker_thread(
+    shared_domain_vcpus: Vec<usize>,
+    kill_evt: Event,
+    timer: Arc<Mutex<Timer>>,
+    vm_ctrl: Arc<Mutex<Tube>>,
+    cpu_affinity: usize,
+) -> anyhow::Result<()> {
+    #[derive(EventToken)]
+    enum Token {
+        // The timer expired.
+        TimerExpire,
+        // The parent thread requested an exit.
+        Kill,
+    }
+
+    let wait_ctx = WaitContext::build_with(&[
+        (&*timer.lock(), Token::TimerExpire),
+        (&kill_evt, Token::Kill),
+    ])
+    .context("Failed to create wait_ctx")?;
+
+    // The vcpufreq thread has strict scheduling requirements, let's affine it away from the vCPU
+    // threads and clamp its util to high value.
+    let cpu_set: Vec<usize> = vec![cpu_affinity];
+    set_cpu_affinity(cpu_set)?;
+
+    let mut sched_attr = sched_attr::default();
+    sched_attr.sched_flags = SCHED_FLAG_KEEP_ALL
+        | SCHED_FLAG_UTIL_CLAMP_MIN
+        | SCHED_FLAG_UTIL_CLAMP_MAX
+        | SCHED_FLAG_RESET_ON_FORK;
+    sched_attr.sched_util_min = SCHED_CAPACITY_SCALE;
+    sched_attr.sched_util_max = SCHED_CAPACITY_SCALE;
+    if let Err(e) = sched_setattr(0, &mut sched_attr, 0) {
+        warn!("Error setting util value: {}", e);
+    }
+
+    loop {
+        let events = wait_ctx.wait().context("Failed to wait for events")?;
+        for event in events.iter().filter(|e| e.is_readable) {
+            match event.token {
+                Token::TimerExpire => {
+                    timer
+                        .lock()
+                        .mark_waited()
+                        .context("failed to reset timer")?;
+                    let vm_ctrl_unlocked = vm_ctrl.lock();
+                    for vcpu_id in &shared_domain_vcpus {
+                        let msg = vm_control::VmRequest::Throttle(*vcpu_id, MIN_TIMER_US);
+                        vm_ctrl_unlocked
+                            .send(&msg)
+                            .context("failed to stall vCPUs")?;
+                    }
+                }
+                Token::Kill => {
+                    return Ok(());
+                }
+            }
+        }
+    }
+}
+
+impl Suspendable for VirtCpufreqV2 {}
diff --git a/devices/src/virtio/balloon.rs b/devices/src/virtio/balloon.rs
index 7a5d8ea96..1ecdbe0fa 100644
--- a/devices/src/virtio/balloon.rs
+++ b/devices/src/virtio/balloon.rs
@@ -49,6 +49,7 @@ use remain::sorted;
 use serde::Deserialize;
 use serde::Serialize;
 use thiserror::Error as ThisError;
+#[cfg(windows)]
 use vm_control::api::VmMemoryClient;
 #[cfg(feature = "registered_events")]
 use vm_control::RegisteredEventWithData;
@@ -855,6 +856,7 @@ struct WorkerReturn {
     #[cfg(feature = "registered_events")]
     registered_evt_q: Option<SendTube>,
     paused_queues: Option<PausedQueues>,
+    #[cfg(windows)]
     vm_memory_client: VmMemoryClient,
 }
 
@@ -868,7 +870,7 @@ fn run_worker(
     ws_data_queue: Option<Queue>,
     ws_op_queue: Option<Queue>,
     command_tube: Tube,
-    vm_memory_client: VmMemoryClient,
+    #[cfg(windows)] vm_memory_client: VmMemoryClient,
     release_memory_tube: Option<Tube>,
     interrupt: Interrupt,
     kill_evt: Event,
@@ -903,7 +905,10 @@ fn run_worker(
                 sys::free_memory(
                     &guest_address,
                     len,
+                    #[cfg(windows)]
                     &vm_memory_client,
+                    #[cfg(any(target_os = "android", target_os = "linux"))]
+                    &mem,
                 )
             },
             stop_rx,
@@ -925,6 +930,7 @@ fn run_worker(
                 sys::reclaim_memory(
                     &guest_address,
                     len,
+                    #[cfg(windows)]
                     &vm_memory_client,
                 )
             },
@@ -975,7 +981,10 @@ fn run_worker(
                     sys::free_memory(
                         &guest_address,
                         len,
+                        #[cfg(windows)]
                         &vm_memory_client,
+                        #[cfg(any(target_os = "android", target_os = "linux"))]
+                        &mem,
                     )
                 },
                 stop_rx,
@@ -1054,6 +1063,7 @@ fn run_worker(
         let target_reached = handle_target_reached(
             &ex,
             target_reached_evt,
+            #[cfg(windows)]
             &vm_memory_client,
         );
         pin_mut!(target_reached);
@@ -1135,6 +1145,7 @@ fn run_worker(
         release_memory_tube,
         #[cfg(feature = "registered_events")]
         registered_evt_q,
+        #[cfg(windows)]
         vm_memory_client,
     }
 }
@@ -1142,7 +1153,7 @@ fn run_worker(
 async fn handle_target_reached(
     ex: &Executor,
     target_reached_evt: Event,
-    vm_memory_client: &VmMemoryClient,
+    #[cfg(windows)] vm_memory_client: &VmMemoryClient,
 ) -> anyhow::Result<()> {
     let event_async =
         EventAsync::new(target_reached_evt, ex).context("failed to create EventAsync")?;
@@ -1153,6 +1164,7 @@ async fn handle_target_reached(
         // size yet.
         sys::balloon_target_reached(
             0,
+            #[cfg(windows)]
             vm_memory_client,
         );
     }
@@ -1166,6 +1178,7 @@ async fn handle_target_reached(
 /// Virtio device for memory balloon inflation/deflation.
 pub struct Balloon {
     command_tube: Option<Tube>,
+    #[cfg(windows)]
     vm_memory_client: Option<VmMemoryClient>,
     release_memory_tube: Option<Tube>,
     pending_adjusted_response_event: Event,
@@ -1197,7 +1210,7 @@ impl Balloon {
     pub fn new(
         base_features: u64,
         command_tube: Tube,
-        vm_memory_client: VmMemoryClient,
+        #[cfg(windows)] vm_memory_client: VmMemoryClient,
         release_memory_tube: Option<Tube>,
         init_balloon_size: u64,
         enabled_features: u64,
@@ -1212,6 +1225,7 @@ impl Balloon {
 
         Ok(Balloon {
             command_tube: Some(command_tube),
+            #[cfg(windows)]
             vm_memory_client: Some(vm_memory_client),
             release_memory_tube,
             pending_adjusted_response_event: Event::new().map_err(BalloonError::CreatingEvent)?,
@@ -1257,7 +1271,10 @@ impl Balloon {
             {
                 self.registered_evt_q = worker_ret.registered_evt_q;
             }
-            self.vm_memory_client = Some(worker_ret.vm_memory_client);
+            #[cfg(windows)]
+            {
+                self.vm_memory_client = Some(worker_ret.vm_memory_client);
+            }
 
             if let Some(queues) = worker_ret.paused_queues {
                 StoppedWorker::WithQueues(Box::new(queues))
@@ -1334,6 +1351,7 @@ impl Balloon {
 
         let command_tube = self.command_tube.take().unwrap();
 
+        #[cfg(windows)]
         let vm_memory_client = self.vm_memory_client.take().unwrap();
         let release_memory_tube = self.release_memory_tube.take();
         #[cfg(feature = "registered_events")]
@@ -1352,6 +1370,7 @@ impl Balloon {
                 queues.ws_data,
                 queues.ws_op,
                 command_tube,
+                #[cfg(windows)]
                 vm_memory_client,
                 release_memory_tube,
                 interrupt,
@@ -1559,6 +1578,7 @@ mod tests {
 
     struct BalloonContext {
         _ctrl_tube: Tube,
+        #[cfg(windows)]
         _mem_client_tube: Tube,
     }
 
@@ -1568,15 +1588,18 @@ mod tests {
 
     fn create_device() -> (BalloonContext, Balloon) {
         let (_ctrl_tube, ctrl_tube_device) = Tube::pair().unwrap();
+        #[cfg(windows)]
         let (_mem_client_tube, mem_client_tube_device) = Tube::pair().unwrap();
         (
             BalloonContext {
                 _ctrl_tube,
+                #[cfg(windows)]
                 _mem_client_tube,
             },
             Balloon::new(
                 0,
                 ctrl_tube_device,
+                #[cfg(windows)]
                 VmMemoryClient::new(mem_client_tube_device),
                 None,
                 1024,
diff --git a/devices/src/virtio/balloon/sys/linux.rs b/devices/src/virtio/balloon/sys/linux.rs
index 2dad9ee18..ac1f5df73 100644
--- a/devices/src/virtio/balloon/sys/linux.rs
+++ b/devices/src/virtio/balloon/sys/linux.rs
@@ -3,32 +3,21 @@
 // found in the LICENSE file.
 
 use base::warn;
-use base::Tube;
-use vm_control::api::VmMemoryClient;
 use vm_memory::GuestAddress;
+use vm_memory::GuestMemory;
 
 pub(in crate::virtio::balloon) fn free_memory(
     guest_address: &GuestAddress,
     len: u64,
-    vm_memory_client: &VmMemoryClient,
+    mem: &GuestMemory,
 ) {
-    if let Err(e) = vm_memory_client.dynamically_free_memory_range(*guest_address, len) {
-        warn!(
-            "Failed to dynamically free memory range. Marking pages unused failed: {}, addr={}",
-            e, guest_address
-        );
+    if let Err(e) = mem.remove_range(*guest_address, len) {
+        warn!("Marking pages unused failed: {}, addr={}", e, guest_address);
     }
 }
 
 // no-op
-pub(in crate::virtio::balloon) fn reclaim_memory(
-    guest_address: &GuestAddress,
-    len: u64,
-    _vm_memory_client: &VmMemoryClient,
-) {}
+pub(in crate::virtio::balloon) fn reclaim_memory(_guest_address: &GuestAddress, _len: u64) {}
 
 // no-op
-pub(in crate::virtio::balloon) fn balloon_target_reached(
-    size: u64,
-    _vm_memory_client: &VmMemoryClient,
-) {}
+pub(in crate::virtio::balloon) fn balloon_target_reached(_size: u64) {}
diff --git a/devices/src/virtio/block/asynchronous.rs b/devices/src/virtio/block/asynchronous.rs
index 0238fc517..511de981d 100644
--- a/devices/src/virtio/block/asynchronous.rs
+++ b/devices/src/virtio/block/asynchronous.rs
@@ -1598,6 +1598,9 @@ mod tests {
         // Create an empty disk image
         let f = tempfile::NamedTempFile::new().unwrap();
         f.as_file().set_len(0x1000).unwrap();
+        // Close the file so that it is possible for the disk implementation to take exclusive
+        // access when opening it.
+        let path: tempfile::TempPath = f.into_temp_path();
 
         // Create an empty guest memory
         let mem = GuestMemory::new(&[(GuestAddress(0u64), 4 * 1024 * 1024)])
@@ -1612,7 +1615,7 @@ mod tests {
         let features = base_features(ProtectionType::Unprotected);
         let id = b"Block serial number\0";
         let disk_option = DiskOption {
-            path: f.path().to_owned(),
+            path: path.to_path_buf(),
             read_only: true,
             id: Some(*id),
             sparse: false,
diff --git a/devices/src/virtio/device_constants.rs b/devices/src/virtio/device_constants.rs
index 52edc1780..b40695cf4 100644
--- a/devices/src/virtio/device_constants.rs
+++ b/devices/src/virtio/device_constants.rs
@@ -156,6 +156,11 @@ pub mod snd {
     }
 }
 
+pub mod media {
+    const QUEUE_SIZE: u16 = 256;
+    pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];
+}
+
 pub mod video {
     use data_model::Le32;
     use serde::Deserialize;
diff --git a/devices/src/virtio/fs/arc_ioctl.rs b/devices/src/virtio/fs/arc_ioctl.rs
index c3dc79f79..74b41697c 100644
--- a/devices/src/virtio/fs/arc_ioctl.rs
+++ b/devices/src/virtio/fs/arc_ioctl.rs
@@ -12,22 +12,6 @@ pub const FS_IOCTL_PATH_MAX_LEN: usize = 128;
 pub const FS_IOCTL_XATTR_NAME_MAX_LEN: usize = 128;
 pub const FS_IOCTL_XATTR_VALUE_MAX_LEN: usize = 128;
 
-#[derive(Debug, Clone, PartialEq)]
-pub(crate) struct PermissionData {
-    pub guest_uid: libc::uid_t,
-    pub guest_gid: libc::gid_t,
-    pub host_uid: libc::uid_t,
-    pub host_gid: libc::gid_t,
-    pub umask: libc::mode_t,
-    pub perm_path: String,
-}
-
-impl PermissionData {
-    pub(crate) fn need_set_permission(&self, path: &str) -> bool {
-        path.starts_with(&self.perm_path)
-    }
-}
-
 #[repr(C)]
 #[derive(Clone, Copy, AsBytes, FromZeroes, FromBytes)]
 pub(crate) struct FsPermissionDataBuffer {
diff --git a/devices/src/virtio/fs/config.rs b/devices/src/virtio/fs/config.rs
index 35d4075ef..0f4aa9198 100644
--- a/devices/src/virtio/fs/config.rs
+++ b/devices/src/virtio/fs/config.rs
@@ -2,9 +2,15 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
+#[cfg(feature = "fs_permission_translation")]
+use std::io;
+#[cfg(feature = "fs_permission_translation")]
+use std::str::FromStr;
 use std::time::Duration;
 
-#[cfg(feature = "arc_quota")]
+#[cfg(feature = "fs_permission_translation")]
+use libc;
+#[allow(unused_imports)]
 use serde::de::Error;
 use serde::Deserialize;
 use serde::Deserializer;
@@ -73,6 +79,119 @@ fn deserialize_privileged_quota_uids<'de, D: Deserializer<'de>>(
         .collect()
 }
 
+/// Permission structure that is configured to map the UID-GID at runtime
+#[cfg(feature = "fs_permission_translation")]
+#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
+pub struct PermissionData {
+    /// UID to be set for all the files in the path inside guest.
+    pub guest_uid: libc::uid_t,
+
+    /// GID to be set for all the files in the path inside guest.
+    pub guest_gid: libc::gid_t,
+
+    /// UID to be set for all the files in the path in the host.
+    pub host_uid: libc::uid_t,
+
+    /// GID to be set for all the files in the path in the host.
+    pub host_gid: libc::gid_t,
+
+    /// umask to be set at runtime for the files in the path.
+    pub umask: libc::mode_t,
+
+    /// This is the absolute path from the root of the shared directory.
+    pub perm_path: String,
+}
+
+#[cfg(feature = "fs_runtime_ugid_map")]
+fn process_ugid_map(result: Vec<Vec<String>>) -> Result<Vec<PermissionData>, io::Error> {
+    let mut permissions = Vec::new();
+
+    for inner_vec in result {
+        let guest_uid = match libc::uid_t::from_str(&inner_vec[0]) {
+            Ok(uid) => uid,
+            Err(_) => {
+                return Err(io::Error::from_raw_os_error(libc::EINVAL));
+            }
+        };
+
+        let guest_gid = match libc::gid_t::from_str(&inner_vec[1]) {
+            Ok(gid) => gid,
+            Err(_) => {
+                return Err(io::Error::from_raw_os_error(libc::EINVAL));
+            }
+        };
+
+        let host_uid = match libc::uid_t::from_str(&inner_vec[2]) {
+            Ok(uid) => uid,
+            Err(_) => {
+                return Err(io::Error::from_raw_os_error(libc::EINVAL));
+            }
+        };
+
+        let host_gid = match libc::gid_t::from_str(&inner_vec[3]) {
+            Ok(gid) => gid,
+            Err(_) => {
+                return Err(io::Error::from_raw_os_error(libc::EINVAL));
+            }
+        };
+
+        let umask = match libc::mode_t::from_str(&inner_vec[4]) {
+            Ok(mode) => mode,
+            Err(_) => {
+                return Err(io::Error::from_raw_os_error(libc::EINVAL));
+            }
+        };
+
+        let perm_path = inner_vec[5].clone();
+
+        // Create PermissionData and push it to the vector
+        permissions.push(PermissionData {
+            guest_uid,
+            guest_gid,
+            host_uid,
+            host_gid,
+            umask,
+            perm_path,
+        });
+    }
+
+    Ok(permissions)
+}
+
+#[cfg(feature = "fs_runtime_ugid_map")]
+fn deserialize_ugid_map<'de, D: Deserializer<'de>>(
+    deserializer: D,
+) -> Result<Vec<PermissionData>, D::Error> {
+    // space-separated list
+    let s: &str = serde::Deserialize::deserialize(deserializer)?;
+
+    let result: Vec<Vec<String>> = s
+        .split(';')
+        .map(|group| group.trim().split(' ').map(String::from).collect())
+        .collect();
+
+    // Length Validation for each inner vector
+    for inner_vec in &result {
+        if inner_vec.len() != 6 {
+            return Err(D::Error::custom(
+                "Invalid ugid_map format. Each group must have 6 elements.",
+            ));
+        }
+    }
+
+    let permissions = match process_ugid_map(result) {
+        Ok(p) => p,
+        Err(e) => {
+            return Err(D::Error::custom(format!(
+                "Error processing uid_gid_map: {}",
+                e
+            )));
+        }
+    };
+
+    Ok(permissions)
+}
+
 /// Options that configure the behavior of the file system.
 #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromKeyValues)]
 #[serde(deny_unknown_fields, rename_all = "snake_case")]
@@ -204,6 +323,27 @@ pub struct Config {
     // The default value for this option is true
     #[serde(default = "config_default_security_ctx")]
     pub security_ctx: bool,
+
+    // Specifies run-time UID/GID mapping that works without user namespaces.
+    //
+    // The virtio-fs usually does mapping of UIDs/GIDs between host and guest with user namespace.
+    // In Android, however, user namespace isn't available for non-root users.
+    // This allows mapping UIDs and GIDs without user namespace by intercepting FUSE
+    // requests and translating UID/GID in virito-fs's process at runtime.
+    //
+    // The format is "guest-uid, guest-gid, host-uid, host-gid, umask, path;{repeat}"
+    //
+    // guest-uid: UID to be set for all the files in the path inside guest.
+    // guest-gid: GID to be set for all the files in the path inside guest.
+    // host-uid: UID to be set for all the files in the path in the host.
+    // host-gid: GID to be set for all the files in the path in the host.
+    // umask: umask to be set at runtime for the files in the path.
+    // path: This is the absolute path from the root of the shared directory.
+    //
+    // This follows similar format to ARCVM IOCTL "FS_IOC_SETPERMISSION"
+    #[cfg(feature = "fs_runtime_ugid_map")]
+    #[serde(default, deserialize_with = "deserialize_ugid_map")]
+    pub ugid_map: Vec<PermissionData>,
 }
 
 impl Default for Config {
@@ -222,6 +362,151 @@ impl Default for Config {
             max_dynamic_perm: 0,
             max_dynamic_xattr: 0,
             security_ctx: config_default_security_ctx(),
+            #[cfg(feature = "fs_runtime_ugid_map")]
+            ugid_map: Vec::new(),
         }
     }
 }
+
+#[cfg(all(test, feature = "fs_runtime_ugid_map"))]
+mod tests {
+
+    use super::*;
+    #[test]
+    fn test_deserialize_ugid_map_valid() {
+        let input_string =
+            "\"1000 1000 1000 1000 0022 /path/to/dir;2000 2000 2000 2000 0022 /path/to/other/dir\"";
+
+        let mut deserializer = serde_json::Deserializer::from_str(input_string);
+        let result = deserialize_ugid_map(&mut deserializer).unwrap();
+
+        assert_eq!(result.len(), 2);
+        assert_eq!(
+            result,
+            vec![
+                PermissionData {
+                    guest_uid: 1000,
+                    guest_gid: 1000,
+                    host_uid: 1000,
+                    host_gid: 1000,
+                    umask: 22,
+                    perm_path: "/path/to/dir".to_string(),
+                },
+                PermissionData {
+                    guest_uid: 2000,
+                    guest_gid: 2000,
+                    host_uid: 2000,
+                    host_gid: 2000,
+                    umask: 22,
+                    perm_path: "/path/to/other/dir".to_string(),
+                },
+            ]
+        );
+    }
+
+    #[test]
+    fn test_process_ugid_map_valid() {
+        let input_vec = vec![
+            vec![
+                "1000".to_string(),
+                "1000".to_string(),
+                "1000".to_string(),
+                "1000".to_string(),
+                "0022".to_string(),
+                "/path/to/dir".to_string(),
+            ],
+            vec![
+                "2000".to_string(),
+                "2000".to_string(),
+                "2000".to_string(),
+                "2000".to_string(),
+                "0022".to_string(),
+                "/path/to/other/dir".to_string(),
+            ],
+        ];
+
+        let result = process_ugid_map(input_vec).unwrap();
+        assert_eq!(result.len(), 2);
+        assert_eq!(
+            result,
+            vec![
+                PermissionData {
+                    guest_uid: 1000,
+                    guest_gid: 1000,
+                    host_uid: 1000,
+                    host_gid: 1000,
+                    umask: 22,
+                    perm_path: "/path/to/dir".to_string(),
+                },
+                PermissionData {
+                    guest_uid: 2000,
+                    guest_gid: 2000,
+                    host_uid: 2000,
+                    host_gid: 2000,
+                    umask: 22,
+                    perm_path: "/path/to/other/dir".to_string(),
+                },
+            ]
+        );
+    }
+
+    #[test]
+    fn test_deserialize_ugid_map_invalid_format() {
+        let input_string = "\"1000 1000 1000 0022 /path/to/dir\""; // Missing one element
+
+        // Create a Deserializer from the input string
+        let mut deserializer = serde_json::Deserializer::from_str(input_string);
+        let result = deserialize_ugid_map(&mut deserializer);
+        assert!(result.is_err());
+    }
+
+    #[test]
+    fn test_deserialize_ugid_map_invalid_guest_uid() {
+        let input_string = "\"invalid 1000 1000 1000 0022 /path/to/dir\""; // Invalid guest-UID
+
+        // Create a Deserializer from the input string
+        let mut deserializer = serde_json::Deserializer::from_str(input_string);
+        let result = deserialize_ugid_map(&mut deserializer);
+        assert!(result.is_err());
+    }
+
+    #[test]
+    fn test_deserialize_ugid_map_invalid_guest_gid() {
+        let input_string = "\"1000 invalid 1000 1000 0022 /path/to/dir\""; // Invalid guest-GID
+
+        // Create a Deserializer from the input string
+        let mut deserializer = serde_json::Deserializer::from_str(input_string);
+        let result = deserialize_ugid_map(&mut deserializer);
+        assert!(result.is_err());
+    }
+
+    #[test]
+    fn test_deserialize_ugid_map_invalid_umask() {
+        let input_string = "\"1000 1000 1000 1000 invalid /path/to/dir\""; // Invalid umask
+
+        // Create a Deserializer from the input string
+        let mut deserializer = serde_json::Deserializer::from_str(input_string);
+        let result = deserialize_ugid_map(&mut deserializer);
+        assert!(result.is_err());
+    }
+
+    #[test]
+    fn test_deserialize_ugid_map_invalid_host_uid() {
+        let input_string = "\"1000 1000 invalid 1000 0022 /path/to/dir\""; // Invalid host-UID
+
+        // Create a Deserializer from the input string
+        let mut deserializer = serde_json::Deserializer::from_str(input_string);
+        let result = deserialize_ugid_map(&mut deserializer);
+        assert!(result.is_err());
+    }
+
+    #[test]
+    fn test_deserialize_ugid_map_invalid_host_gid() {
+        let input_string = "\"1000 1000 1000 invalid 0022 /path/to/dir\""; // Invalid host-UID
+
+        // Create a Deserializer from the input string
+        let mut deserializer = serde_json::Deserializer::from_str(input_string);
+        let result = deserialize_ugid_map(&mut deserializer);
+        assert!(result.is_err());
+    }
+}
diff --git a/devices/src/virtio/fs/mod.rs b/devices/src/virtio/fs/mod.rs
index 869324885..d1dc0cfcb 100644
--- a/devices/src/virtio/fs/mod.rs
+++ b/devices/src/virtio/fs/mod.rs
@@ -54,8 +54,7 @@ pub use config::CachePolicy;
 pub use config::Config;
 use fuse::Server;
 use passthrough::PassthroughFs;
-pub use worker::process_fs_queue;
-use worker::Worker;
+pub use worker::Worker;
 
 const QUEUE_SIZE: u16 = 1024;
 
@@ -241,7 +240,7 @@ impl VirtioDevice for Fs {
                 .send(&request)
                 .expect("failed to send allocation message");
             slot = match socket.recv() {
-                Ok(VmResponse::RegisterMemory { gfn: _, slot }) => slot,
+                Ok(VmResponse::RegisterMemory { slot }) => slot,
                 Ok(VmResponse::Err(e)) => panic!("failed to allocate shared memory region: {}", e),
                 r => panic!(
                     "unexpected response to allocate shared memory region: {:?}",
diff --git a/devices/src/virtio/fs/passthrough.rs b/devices/src/virtio/fs/passthrough.rs
index d985ae147..a077ec1e4 100644
--- a/devices/src/virtio/fs/passthrough.rs
+++ b/devices/src/virtio/fs/passthrough.rs
@@ -9,6 +9,8 @@ use std::collections::btree_map;
 use std::collections::BTreeMap;
 use std::ffi::CStr;
 use std::ffi::CString;
+#[cfg(feature = "fs_runtime_ugid_map")]
+use std::ffi::OsStr;
 use std::fs::File;
 use std::io;
 use std::mem;
@@ -16,6 +18,10 @@ use std::mem::size_of;
 use std::mem::MaybeUninit;
 use std::os::raw::c_int;
 use std::os::raw::c_long;
+#[cfg(feature = "fs_runtime_ugid_map")]
+use std::os::unix::ffi::OsStrExt;
+#[cfg(feature = "fs_runtime_ugid_map")]
+use std::path::Path;
 use std::ptr;
 use std::ptr::addr_of;
 use std::ptr::addr_of_mut;
@@ -24,7 +30,7 @@ use std::sync::atomic::AtomicU64;
 use std::sync::atomic::Ordering;
 use std::sync::Arc;
 use std::sync::MutexGuard;
-#[cfg(feature = "arc_quota")]
+#[cfg(feature = "fs_permission_translation")]
 use std::sync::RwLock;
 use std::time::Duration;
 
@@ -79,8 +85,6 @@ use crate::virtio::fs::arc_ioctl::FsPathXattrDataBuffer;
 #[cfg(feature = "arc_quota")]
 use crate::virtio::fs::arc_ioctl::FsPermissionDataBuffer;
 #[cfg(feature = "arc_quota")]
-use crate::virtio::fs::arc_ioctl::PermissionData;
-#[cfg(feature = "arc_quota")]
 use crate::virtio::fs::arc_ioctl::XattrData;
 use crate::virtio::fs::caps::Capability;
 use crate::virtio::fs::caps::Caps;
@@ -88,14 +92,15 @@ use crate::virtio::fs::caps::Set as CapSet;
 use crate::virtio::fs::caps::Value as CapValue;
 use crate::virtio::fs::config::CachePolicy;
 use crate::virtio::fs::config::Config;
+#[cfg(feature = "fs_permission_translation")]
+use crate::virtio::fs::config::PermissionData;
 use crate::virtio::fs::expiring_map::ExpiringMap;
 use crate::virtio::fs::multikey::MultikeyBTreeMap;
 use crate::virtio::fs::read_dir::ReadDir;
 
-const EMPTY_CSTR: &[u8] = b"\0";
-const ROOT_CSTR: &[u8] = b"/\0";
-const PROC_CSTR: &[u8] = b"/proc\0";
-const UNLABELED_CSTR: &[u8] = b"unlabeled\0";
+const EMPTY_CSTR: &CStr = c"";
+const PROC_CSTR: &CStr = c"/proc";
+const UNLABELED_CSTR: &CStr = c"unlabeled";
 
 const USER_VIRTIOFS_XATTR: &[u8] = b"user.virtiofs.";
 const SECURITY_XATTR: &[u8] = b"security.";
@@ -377,8 +382,7 @@ thread_local!(static THREAD_FSCREATE: RefCell<Option<File>> = const { RefCell::n
 // Opens and returns a write-only handle to /proc/thread-self/attr/fscreate. Panics if it fails to
 // open the file.
 fn open_fscreate(proc: &File) -> File {
-    // SAFETY: This string is nul-terminated and does not contain any interior nul bytes
-    let fscreate = unsafe { CStr::from_bytes_with_nul_unchecked(b"thread-self/attr/fscreate\0") };
+    let fscreate = c"thread-self/attr/fscreate";
 
     // SAFETY: this doesn't modify any memory and we check the return value.
     let raw_descriptor = unsafe {
@@ -512,14 +516,11 @@ fn eexist() -> io::Error {
 fn stat<F: AsRawDescriptor + ?Sized>(f: &F) -> io::Result<libc::stat64> {
     let mut st: MaybeUninit<libc::stat64> = MaybeUninit::<libc::stat64>::zeroed();
 
-    // SAFETY: this is a constant value that is a nul-terminated string without interior nul bytes.
-    let pathname = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };
-
     // SAFETY: the kernel will only write data in `st` and we check the return value.
     syscall!(unsafe {
         libc::fstatat64(
             f.as_raw_descriptor(),
-            pathname.as_ptr(),
+            EMPTY_CSTR.as_ptr(),
             st.as_mut_ptr(),
             libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
         )
@@ -663,6 +664,13 @@ impl ExpiringCasefoldLookupCaches {
     }
 }
 
+#[cfg(feature = "fs_permission_translation")]
+impl PermissionData {
+    pub(crate) fn need_set_permission(&self, path: &str) -> bool {
+        path.starts_with(&self.perm_path)
+    }
+}
+
 /// A file system that simply "passes through" all requests it receives to the underlying file
 /// system. To keep the implementation simple it servers the contents of its root directory. Users
 /// that wish to serve only a specific directory should set up the environment so that that
@@ -715,7 +723,7 @@ pub struct PassthroughFs {
     expiring_casefold_lookup_caches: Option<Mutex<ExpiringCasefoldLookupCaches>>,
 
     // paths and coresponding permission setting set by `crosvm_client_fs_permission_set` API
-    #[cfg(feature = "arc_quota")]
+    #[cfg(feature = "fs_permission_translation")]
     permission_paths: RwLock<Vec<PermissionData>>,
 
     // paths and coresponding xattr setting set by `crosvm_client_fs_xattr_set` API
@@ -723,6 +731,16 @@ pub struct PassthroughFs {
     xattr_paths: RwLock<Vec<XattrData>>,
 
     cfg: Config,
+
+    // Set the root directory when pivot root isn't enabled for jailed process.
+    //
+    // virtio-fs typically uses mount namespaces and pivot_root for file system isolation,
+    // making the jailed process's root directory "/".
+    //
+    // However, Android's security model prevents crosvm from having the necessary SYS_ADMIN
+    // capability for mount namespaces and pivot_root. This lack of isolation means that
+    // root_dir defaults to the path provided via "--shared-dir".
+    root_dir: String,
 }
 
 impl std::fmt::Debug for PassthroughFs {
@@ -742,15 +760,11 @@ impl std::fmt::Debug for PassthroughFs {
 
 impl PassthroughFs {
     pub fn new(tag: &str, cfg: Config) -> io::Result<PassthroughFs> {
-        // SAFETY: this is a constant value that is a nul-terminated string without interior
-        // nul bytes.
-        let proc_cstr = unsafe { CStr::from_bytes_with_nul_unchecked(PROC_CSTR) };
-
         // SAFETY: this doesn't modify any memory and we check the return value.
         let raw_descriptor = syscall!(unsafe {
             libc::openat64(
                 libc::AT_FDCWD,
-                proc_cstr.as_ptr(),
+                PROC_CSTR.as_ptr(),
                 libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
             )
         })?;
@@ -780,7 +794,8 @@ impl PassthroughFs {
             None
         };
 
-        let passthroughfs = PassthroughFs {
+        #[allow(unused_mut)]
+        let mut passthroughfs = PassthroughFs {
             process_lock: Mutex::new(()),
             tag: tag.to_string(),
             inodes: Mutex::new(MultikeyBTreeMap::new()),
@@ -800,13 +815,17 @@ impl PassthroughFs {
             #[cfg(feature = "arc_quota")]
             dbus_fd,
             expiring_casefold_lookup_caches,
-            #[cfg(feature = "arc_quota")]
+            #[cfg(feature = "fs_permission_translation")]
             permission_paths: RwLock::new(Vec::new()),
             #[cfg(feature = "arc_quota")]
             xattr_paths: RwLock::new(Vec::new()),
             cfg,
+            root_dir: "/".to_string(),
         };
 
+        #[cfg(feature = "fs_runtime_ugid_map")]
+        passthroughfs.set_permission_path();
+
         cros_tracing::trace_simple_print!(
             VirtioFs,
             "New PassthroughFS initialized: {:?}",
@@ -815,6 +834,32 @@ impl PassthroughFs {
         Ok(passthroughfs)
     }
 
+    #[cfg(feature = "fs_runtime_ugid_map")]
+    fn set_permission_path(&mut self) {
+        if !self.cfg.ugid_map.is_empty() {
+            let mut write_lock = self
+                .permission_paths
+                .write()
+                .expect("Failed to acquire write lock on permission_paths");
+            *write_lock = self.cfg.ugid_map.clone();
+        }
+    }
+
+    #[cfg(feature = "fs_runtime_ugid_map")]
+    pub fn set_root_dir(&mut self, shared_dir: String) -> io::Result<()> {
+        let canonicalized_root = match std::fs::canonicalize(shared_dir) {
+            Ok(path) => path,
+            Err(e) => {
+                return Err(io::Error::new(
+                    io::ErrorKind::InvalidInput,
+                    format!("Failed to canonicalize root_dir: {}", e),
+                ));
+            }
+        };
+        self.root_dir = canonicalized_root.to_string_lossy().to_string();
+        Ok(())
+    }
+
     pub fn cfg(&self) -> &Config {
         &self.cfg
     }
@@ -926,13 +971,15 @@ impl PassthroughFs {
     fn add_entry(
         &self,
         f: File,
-        #[cfg(feature = "arc_quota")] mut st: libc::stat64,
-        #[cfg(not(feature = "arc_quota"))] st: libc::stat64,
+        #[cfg_attr(not(feature = "fs_permission_translation"), allow(unused_mut))]
+        mut st: libc::stat64,
         open_flags: libc::c_int,
         path: String,
     ) -> Entry {
         #[cfg(feature = "arc_quota")]
         self.set_permission(&mut st, &path);
+        #[cfg(feature = "fs_runtime_ugid_map")]
+        self.set_ugid_permission(&mut st, &path);
         let mut inodes = self.inodes.lock();
 
         let altkey = InodeAltKey {
@@ -1008,10 +1055,8 @@ impl PassthroughFs {
     }
 
     fn do_lookup(&self, parent: &InodeData, name: &CStr) -> io::Result<Entry> {
-        #[cfg(feature = "arc_quota")]
+        #[cfg_attr(not(feature = "fs_permission_translation"), allow(unused_mut))]
         let mut st = statat(parent, name)?;
-        #[cfg(not(feature = "arc_quota"))]
-        let st = statat(parent, name)?;
 
         let altkey = InodeAltKey {
             ino: st.st_ino,
@@ -1029,6 +1074,8 @@ impl PassthroughFs {
             // Return the same inode with the reference counter increased.
             #[cfg(feature = "arc_quota")]
             self.set_permission(&mut st, &path);
+            #[cfg(feature = "fs_runtime_ugid_map")]
+            self.set_ugid_permission(&mut st, &path);
             return Ok(Entry {
                 inode: self.increase_inode_refcount(data),
                 generation: 0,
@@ -1189,12 +1236,13 @@ impl PassthroughFs {
     }
 
     fn do_getattr(&self, inode: &InodeData) -> io::Result<(libc::stat64, Duration)> {
-        #[cfg(feature = "arc_quota")]
+        #[allow(unused_mut)]
         let mut st = stat(inode)?;
+
         #[cfg(feature = "arc_quota")]
         self.set_permission(&mut st, &inode.path);
-        #[cfg(not(feature = "arc_quota"))]
-        let st = stat(inode)?;
+        #[cfg(feature = "fs_runtime_ugid_map")]
+        self.set_ugid_permission(&mut st, &inode.path);
         Ok((st, self.cfg.timeout))
     }
 
@@ -1677,6 +1725,103 @@ impl PassthroughFs {
     }
 }
 
+#[cfg(feature = "fs_runtime_ugid_map")]
+impl PassthroughFs {
+    fn find_and_set_ugid_permission(
+        &self,
+        st: &mut libc::stat64,
+        path: &str,
+        is_root_path: bool,
+    ) -> bool {
+        for perm_data in self
+            .permission_paths
+            .read()
+            .expect("acquire permission_paths read lock")
+            .iter()
+        {
+            if (is_root_path && perm_data.perm_path == "/")
+                || (!is_root_path
+                    && perm_data.perm_path != "/"
+                    && perm_data.need_set_permission(path))
+            {
+                self.set_permission_from_data(st, perm_data);
+                return true;
+            }
+        }
+        false
+    }
+
+    fn set_permission_from_data(&self, st: &mut libc::stat64, perm_data: &PermissionData) {
+        st.st_uid = perm_data.guest_uid;
+        st.st_gid = perm_data.guest_gid;
+        st.st_mode = (st.st_mode & libc::S_IFMT) | (0o777 & !perm_data.umask);
+    }
+
+    /// Set permission according to path
+    fn set_ugid_permission(&self, st: &mut libc::stat64, path: &str) {
+        let is_root_path = path.is_empty();
+
+        if self.find_and_set_ugid_permission(st, path, is_root_path) {
+            return;
+        }
+
+        if let Some(perm_data) = self
+            .permission_paths
+            .read()
+            .expect("acquire permission_paths read lock")
+            .iter()
+            .find(|pd| pd.perm_path == "/")
+        {
+            self.set_permission_from_data(st, perm_data);
+        }
+    }
+
+    /// Set host uid/gid to configured value according to path
+    fn change_ugid_creds(&self, ctx: &Context, parent_data: &InodeData, name: &CStr) -> (u32, u32) {
+        let path = format!(
+            "{}/{}",
+            parent_data.path.clone(),
+            name.to_str().unwrap_or("<non UTF-8 str>")
+        );
+
+        let is_root_path = path.is_empty();
+
+        if self.find_ugid_creds_for_path(&path, is_root_path).is_some() {
+            return self.find_ugid_creds_for_path(&path, is_root_path).unwrap();
+        }
+
+        if let Some(perm_data) = self
+            .permission_paths
+            .read()
+            .expect("acquire permission_paths read lock")
+            .iter()
+            .find(|pd| pd.perm_path == "/")
+        {
+            return (perm_data.host_uid, perm_data.host_gid);
+        }
+
+        (ctx.uid, ctx.gid)
+    }
+
+    fn find_ugid_creds_for_path(&self, path: &str, is_root_path: bool) -> Option<(u32, u32)> {
+        for perm_data in self
+            .permission_paths
+            .read()
+            .expect("acquire permission_paths read lock")
+            .iter()
+        {
+            if (is_root_path && perm_data.perm_path == "/")
+                || (!is_root_path
+                    && perm_data.perm_path != "/"
+                    && perm_data.need_set_permission(path))
+            {
+                return Some((perm_data.host_uid, perm_data.host_gid));
+            }
+        }
+        None
+    }
+}
+
 #[cfg(feature = "arc_quota")]
 impl PassthroughFs {
     /// Convert u8 slice to string
@@ -1976,9 +2121,8 @@ impl FileSystem for PassthroughFs {
     type DirIter = ReadDir<Box<[u8]>>;
 
     fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
-        // SAFETY: this is a constant value that is a nul-terminated string without interior
-        // nul bytes.
-        let root = unsafe { CStr::from_bytes_with_nul_unchecked(ROOT_CSTR) };
+        let root = CString::new(self.root_dir.clone())
+            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
 
         let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
         // SAFETY: this doesn't modify any memory and we check the return value.
@@ -2156,13 +2300,16 @@ impl FileSystem for PassthroughFs {
         let data = self.find_inode(parent)?;
 
         let _ctx = security_ctx
-            .filter(|ctx| ctx.to_bytes_with_nul() != UNLABELED_CSTR)
+            .filter(|ctx| *ctx != UNLABELED_CSTR)
             .map(|ctx| ScopedSecurityContext::new(&self.proc, ctx))
             .transpose()?;
 
+        #[allow(unused_variables)]
         #[cfg(feature = "arc_quota")]
         let (uid, gid) = self.change_creds(&ctx, &data, name);
-        #[cfg(not(feature = "arc_quota"))]
+        #[cfg(feature = "fs_runtime_ugid_map")]
+        let (uid, gid) = self.change_ugid_creds(&ctx, &data, name);
+        #[cfg(not(feature = "fs_permission_translation"))]
         let (uid, gid) = (ctx.uid, ctx.gid);
 
         let (_uid, _gid) = set_creds(uid, gid)?;
@@ -2268,19 +2415,22 @@ impl FileSystem for PassthroughFs {
         let data = self.find_inode(parent)?;
 
         let _ctx = security_ctx
-            .filter(|ctx| ctx.to_bytes_with_nul() != UNLABELED_CSTR)
+            .filter(|ctx| *ctx != UNLABELED_CSTR)
             .map(|ctx| ScopedSecurityContext::new(&self.proc, ctx))
             .transpose()?;
 
         let tmpflags = libc::O_RDWR | libc::O_TMPFILE | libc::O_CLOEXEC | libc::O_NOFOLLOW;
 
-        // SAFETY: This string is nul-terminated and does not contain any interior nul bytes
-        let current_dir = unsafe { CStr::from_bytes_with_nul_unchecked(b".\0") };
+        let current_dir = c".";
 
+        #[allow(unused_variables)]
         #[cfg(feature = "arc_quota")]
         let (uid, gid) = self.change_creds(&ctx, &data, current_dir);
-        #[cfg(not(feature = "arc_quota"))]
+        #[cfg(feature = "fs_runtime_ugid_map")]
+        let (uid, gid) = self.change_ugid_creds(&ctx, &data, current_dir);
+        #[cfg(not(feature = "fs_permission_translation"))]
         let (uid, gid) = (ctx.uid, ctx.gid);
+
         let (_uid, _gid) = set_creds(uid, gid)?;
 
         let fd = {
@@ -2332,14 +2482,18 @@ impl FileSystem for PassthroughFs {
         let data = self.find_inode(parent)?;
 
         let _ctx = security_ctx
-            .filter(|ctx| ctx.to_bytes_with_nul() != UNLABELED_CSTR)
+            .filter(|ctx| *ctx != UNLABELED_CSTR)
             .map(|ctx| ScopedSecurityContext::new(&self.proc, ctx))
             .transpose()?;
 
+        #[allow(unused_variables)]
         #[cfg(feature = "arc_quota")]
         let (uid, gid) = self.change_creds(&ctx, &data, name);
-        #[cfg(not(feature = "arc_quota"))]
+        #[cfg(feature = "fs_runtime_ugid_map")]
+        let (uid, gid) = self.change_ugid_creds(&ctx, &data, name);
+        #[cfg(not(feature = "fs_permission_translation"))]
         let (uid, gid) = (ctx.uid, ctx.gid);
+
         let (_uid, _gid) = set_creds(uid, gid)?;
 
         let flags = self.update_open_flags(flags as i32);
@@ -2384,10 +2538,9 @@ impl FileSystem for PassthroughFs {
                 entry.inode,
                 flags as u32 & !((libc::O_CREAT | libc::O_EXCL | libc::O_NOCTTY) as u32),
             )
-            .map_err(|e| {
+            .inspect_err(|_e| {
                 // Don't leak the entry.
                 self.forget(ctx, entry.inode, 1);
-                e
             })?
         };
         Ok((entry, handle, opts))
@@ -2569,15 +2722,11 @@ impl FileSystem for PassthroughFs {
                 u32::MAX
             };
 
-            // SAFETY: this is a constant value that is a nul-terminated string without interior
-            // nul bytes.
-            let empty = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };
-
             // SAFETY: this doesn't modify any memory and we check the return value.
             syscall!(unsafe {
                 libc::fchownat(
                     inode_data.as_raw_descriptor(),
-                    empty.as_ptr(),
+                    EMPTY_CSTR.as_ptr(),
                     uid,
                     gid,
                     libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
@@ -2701,14 +2850,18 @@ impl FileSystem for PassthroughFs {
         let data = self.find_inode(parent)?;
 
         let _ctx = security_ctx
-            .filter(|ctx| ctx.to_bytes_with_nul() != UNLABELED_CSTR)
+            .filter(|ctx| *ctx != UNLABELED_CSTR)
             .map(|ctx| ScopedSecurityContext::new(&self.proc, ctx))
             .transpose()?;
 
+        #[allow(unused_variables)]
         #[cfg(feature = "arc_quota")]
         let (uid, gid) = self.change_creds(&ctx, &data, name);
-        #[cfg(not(feature = "arc_quota"))]
+        #[cfg(feature = "fs_runtime_ugid_map")]
+        let (uid, gid) = self.change_ugid_creds(&ctx, &data, name);
+        #[cfg(not(feature = "fs_permission_translation"))]
         let (uid, gid) = (ctx.uid, ctx.gid);
+
         let (_uid, _gid) = set_creds(uid, gid)?;
         {
             let _scoped_umask = ScopedUmask::new(umask);
@@ -2777,14 +2930,18 @@ impl FileSystem for PassthroughFs {
         let data = self.find_inode(parent)?;
 
         let _ctx = security_ctx
-            .filter(|ctx| ctx.to_bytes_with_nul() != UNLABELED_CSTR)
+            .filter(|ctx| *ctx != UNLABELED_CSTR)
             .map(|ctx| ScopedSecurityContext::new(&self.proc, ctx))
             .transpose()?;
 
+        #[allow(unused_variables)]
         #[cfg(feature = "arc_quota")]
         let (uid, gid) = self.change_creds(&ctx, &data, name);
-        #[cfg(not(feature = "arc_quota"))]
+        #[cfg(feature = "fs_runtime_ugid_map")]
+        let (uid, gid) = self.change_ugid_creds(&ctx, &data, name);
+        #[cfg(not(feature = "fs_permission_translation"))]
         let (uid, gid) = (ctx.uid, ctx.gid);
+
         let (_uid, _gid) = set_creds(uid, gid)?;
         {
             let casefold_cache = self.lock_casefold_lookup_caches();
@@ -2806,21 +2963,28 @@ impl FileSystem for PassthroughFs {
 
         let mut buf = vec![0; libc::PATH_MAX as usize];
 
-        // SAFETY: this is a constant value that is a nul-terminated string without interior nul
-        // bytes.
-        let empty = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };
-
         // SAFETY: this will only modify the contents of `buf` and we check the return value.
         let res = syscall!(unsafe {
             libc::readlinkat(
                 data.as_raw_descriptor(),
-                empty.as_ptr(),
+                EMPTY_CSTR.as_ptr(),
                 buf.as_mut_ptr() as *mut libc::c_char,
                 buf.len(),
             )
         })?;
 
         buf.resize(res as usize, 0);
+
+        #[cfg(feature = "fs_runtime_ugid_map")]
+        {
+            let link_target = Path::new(OsStr::from_bytes(&buf[..res as usize]));
+            if !link_target.starts_with(&self.root_dir) {
+                return Err(io::Error::new(
+                    io::ErrorKind::InvalidInput,
+                    "Symbolic link points outside of root_dir",
+                ));
+            }
+        }
         Ok(buf)
     }
 
@@ -3407,10 +3571,14 @@ impl FileSystem for PassthroughFs {
         // Perform lookup but not create negative dentry
         let data = self.find_inode(parent)?;
 
+        #[allow(unused_variables)]
         #[cfg(feature = "arc_quota")]
         let (uid, gid) = self.change_creds(&ctx, &data, name);
-        #[cfg(not(feature = "arc_quota"))]
+        #[cfg(feature = "fs_runtime_ugid_map")]
+        let (uid, gid) = self.change_ugid_creds(&ctx, &data, name);
+        #[cfg(not(feature = "fs_permission_translation"))]
         let (uid, gid) = (ctx.uid, ctx.gid);
+
         let (_uid, _gid) = set_creds(uid, gid)?;
 
         // This lookup serves two purposes:
@@ -3673,24 +3841,19 @@ mod tests {
         let p = PassthroughFs::new("tag", cfg).expect("Failed to create PassthroughFs");
 
         // Selinux shouldn't get overwritten.
-        // SAFETY: trivially safe
-        let selinux = unsafe { CStr::from_bytes_with_nul_unchecked(b"security.selinux\0") };
+        let selinux = c"security.selinux";
         assert_eq!(p.rewrite_xattr_name(selinux).to_bytes(), selinux.to_bytes());
 
         // user, trusted, and system should not be changed either.
-        // SAFETY: trivially safe
-        let user = unsafe { CStr::from_bytes_with_nul_unchecked(b"user.foobar\0") };
+        let user = c"user.foobar";
         assert_eq!(p.rewrite_xattr_name(user).to_bytes(), user.to_bytes());
-        // SAFETY: trivially safe
-        let trusted = unsafe { CStr::from_bytes_with_nul_unchecked(b"trusted.foobar\0") };
+        let trusted = c"trusted.foobar";
         assert_eq!(p.rewrite_xattr_name(trusted).to_bytes(), trusted.to_bytes());
-        // SAFETY: trivially safe
-        let system = unsafe { CStr::from_bytes_with_nul_unchecked(b"system.foobar\0") };
+        let system = c"system.foobar";
         assert_eq!(p.rewrite_xattr_name(system).to_bytes(), system.to_bytes());
 
         // sehash should be re-written.
-        // SAFETY: trivially safe
-        let sehash = unsafe { CStr::from_bytes_with_nul_unchecked(b"security.sehash\0") };
+        let sehash = c"security.sehash";
         assert_eq!(
             p.rewrite_xattr_name(sehash).to_bytes(),
             b"user.virtiofs.security.sehash"
diff --git a/devices/src/virtio/fs/worker.rs b/devices/src/virtio/fs/worker.rs
index aa3c7b07f..e41324f39 100644
--- a/devices/src/virtio/fs/worker.rs
+++ b/devices/src/virtio/fs/worker.rs
@@ -139,14 +139,14 @@ impl fuse::Mapper for Mapper {
 }
 
 pub struct Worker<F: FileSystem + Sync> {
-    queue: Queue,
+    pub(crate) queue: Queue,
     server: Arc<fuse::Server<F>>,
     irq: Interrupt,
     tube: Arc<Mutex<Tube>>,
     slot: u32,
 }
 
-pub fn process_fs_queue<F: FileSystem + Sync>(
+fn process_fs_queue<F: FileSystem + Sync>(
     queue: &mut Queue,
     server: &Arc<fuse::Server<F>>,
     tube: &Arc<Mutex<Tube>>,
diff --git a/devices/src/virtio/gpu/mod.rs b/devices/src/virtio/gpu/mod.rs
index 4d5229e54..ffbaf8c21 100644
--- a/devices/src/virtio/gpu/mod.rs
+++ b/devices/src/virtio/gpu/mod.rs
@@ -18,10 +18,12 @@ use std::sync::mpsc;
 use std::sync::Arc;
 
 use anyhow::anyhow;
-use anyhow::bail;
 use anyhow::Context;
+use base::custom_serde::deserialize_map_from_kv_vec;
+use base::custom_serde::serialize_map_as_kv_vec;
 use base::debug;
 use base::error;
+use base::info;
 #[cfg(any(target_os = "android", target_os = "linux"))]
 use base::linux::move_task_to_cgroup;
 use base::warn;
@@ -161,6 +163,12 @@ pub struct FenceState {
 
 #[derive(Serialize, Deserialize)]
 struct FenceStateSnapshot {
+    // Customize serialization to avoid errors when trying to use objects as keys in JSON
+    // dictionaries.
+    #[serde(
+        serialize_with = "serialize_map_as_kv_vec",
+        deserialize_with = "deserialize_map_from_kv_vec"
+    )]
     completed_fences: BTreeMap<VirtioGpuRing, u64>,
 }
 
@@ -804,6 +812,7 @@ enum WorkerToken {
     Display,
     GpuControl,
     InterruptResample,
+    Sleep,
     Kill,
     ResourceBridge {
         index: usize,
@@ -855,62 +864,277 @@ impl<'a> EventManager<'a> {
     }
 }
 
-struct Worker {
-    interrupt: Interrupt,
-    exit_evt_wrtube: SendTube,
-    gpu_control_tube: Tube,
+#[derive(Serialize, Deserialize)]
+struct WorkerSnapshot {
+    fence_state_snapshot: FenceStateSnapshot,
+    virtio_gpu_snapshot: VirtioGpuSnapshot,
+}
+
+struct WorkerActivateRequest {
+    resources: GpuActivationResources,
+}
+
+enum WorkerRequest {
+    Activate(WorkerActivateRequest),
+    Suspend,
+    Snapshot,
+    Restore(WorkerSnapshot),
+}
+
+enum WorkerResponse {
+    Ok,
+    Suspend(GpuDeactivationResources),
+    Snapshot(WorkerSnapshot),
+}
+
+struct GpuActivationResources {
     mem: GuestMemory,
+    interrupt: Interrupt,
     ctrl_queue: SharedQueueReader,
     cursor_queue: LocalQueueReader,
+}
+
+struct GpuDeactivationResources {
+    queues: Option<Vec<Queue>>,
+}
+
+struct Worker {
+    request_receiver: mpsc::Receiver<WorkerRequest>,
+    response_sender: mpsc::Sender<anyhow::Result<WorkerResponse>>,
+    exit_evt_wrtube: SendTube,
+    gpu_control_tube: Tube,
     resource_bridges: ResourceBridges,
+    suspend_evt: Event,
     kill_evt: Event,
     state: Frontend,
+    fence_state: Arc<Mutex<FenceState>>,
+    fence_handler_resources: Arc<Mutex<Option<FenceHandlerActivationResources<SharedQueueReader>>>>,
     #[cfg(windows)]
     gpu_display_wait_descriptor_ctrl_rd: RecvTube,
+    activation_resources: Option<GpuActivationResources>,
 }
 
-struct WorkerReturn {
-    gpu_control_tube: Tube,
-    resource_bridges: ResourceBridges,
-    event_devices: Vec<EventDevice>,
-    // None if device not yet activated.
-    activated_state: Option<(Vec<Queue>, WorkerSnapshot)>,
+#[derive(Copy, Clone)]
+enum WorkerStopReason {
+    Sleep,
+    Kill,
 }
 
-#[derive(Serialize, Deserialize)]
-struct WorkerSnapshot {
-    fence_state_snapshot: FenceStateSnapshot,
-    virtio_gpu_snapshot: VirtioGpuSnapshot,
+enum WorkerState {
+    Inactive,
+    Active,
+    Error,
 }
 
 impl Worker {
+    fn new(
+        rutabaga_builder: RutabagaBuilder,
+        rutabaga_server_descriptor: Option<RutabagaDescriptor>,
+        display_backends: Vec<DisplayBackend>,
+        display_params: Vec<GpuDisplayParameters>,
+        display_event: Arc<AtomicBool>,
+        mapper: Arc<Mutex<Option<Box<dyn SharedMemoryMapper>>>>,
+        event_devices: Vec<EventDevice>,
+        external_blob: bool,
+        fixed_blob_mapping: bool,
+        udmabuf: bool,
+        request_receiver: mpsc::Receiver<WorkerRequest>,
+        response_sender: mpsc::Sender<anyhow::Result<WorkerResponse>>,
+        exit_evt_wrtube: SendTube,
+        gpu_control_tube: Tube,
+        resource_bridges: ResourceBridges,
+        suspend_evt: Event,
+        kill_evt: Event,
+        #[cfg(windows)] mut wndproc_thread: Option<WindowProcedureThread>,
+        #[cfg(windows)] gpu_display_wait_descriptor_ctrl_rd: RecvTube,
+        #[cfg(windows)] gpu_display_wait_descriptor_ctrl_wr: SendTube,
+    ) -> anyhow::Result<Worker> {
+        let fence_state = Arc::new(Mutex::new(Default::default()));
+        let fence_handler_resources = Arc::new(Mutex::new(None));
+        let fence_handler =
+            create_fence_handler(fence_handler_resources.clone(), fence_state.clone());
+        let rutabaga = rutabaga_builder.build(fence_handler, rutabaga_server_descriptor)?;
+        let mut virtio_gpu = build(
+            &display_backends,
+            display_params,
+            display_event,
+            rutabaga,
+            mapper,
+            external_blob,
+            fixed_blob_mapping,
+            #[cfg(windows)]
+            &mut wndproc_thread,
+            udmabuf,
+            #[cfg(windows)]
+            gpu_display_wait_descriptor_ctrl_wr,
+        )
+        .ok_or_else(|| anyhow!("failed to build virtio gpu"))?;
+
+        for event_device in event_devices {
+            virtio_gpu
+                .import_event_device(event_device)
+                // We lost the `EventDevice`, so fail hard.
+                .context("failed to import event device")?;
+        }
+
+        Ok(Worker {
+            request_receiver,
+            response_sender,
+            exit_evt_wrtube,
+            gpu_control_tube,
+            resource_bridges,
+            suspend_evt,
+            kill_evt,
+            state: Frontend::new(virtio_gpu, fence_state.clone()),
+            fence_state,
+            fence_handler_resources,
+            #[cfg(windows)]
+            gpu_display_wait_descriptor_ctrl_rd,
+            activation_resources: None,
+        })
+    }
+
     fn run(&mut self) {
-        let display_desc =
-            match SafeDescriptor::try_from(&*self.state.display().borrow() as &dyn AsRawDescriptor)
-            {
-                Ok(v) => v,
-                Err(e) => {
-                    error!("failed getting event descriptor for display: {}", e);
+        // This loop effectively only runs while the worker is inactive. Once activated via
+        // a `WorkerRequest::Activate`, the worker will remain in `run_until_sleep_or_exit()`
+        // until suspended via `kill_evt` or `suspend_evt` being signaled.
+        loop {
+            let request = match self.request_receiver.recv() {
+                Ok(r) => r,
+                Err(_) => {
+                    info!("virtio gpu worker connection ended, exiting.");
                     return;
                 }
             };
 
-        let ctrl_evt = self
+            match request {
+                WorkerRequest::Activate(request) => {
+                    let response = self.on_activate(request).map(|_| WorkerResponse::Ok);
+                    self.response_sender
+                        .send(response)
+                        .expect("failed to send gpu worker response for activate");
+
+                    let stop_reason = self
+                        .run_until_sleep_or_exit()
+                        .expect("failed to run gpu worker processing");
+
+                    if let WorkerStopReason::Kill = stop_reason {
+                        break;
+                    }
+                }
+                WorkerRequest::Suspend => {
+                    let response = self.on_suspend().map(WorkerResponse::Suspend);
+                    self.response_sender
+                        .send(response)
+                        .expect("failed to send gpu worker response for suspend");
+                }
+                WorkerRequest::Snapshot => {
+                    let response = self.on_snapshot().map(WorkerResponse::Snapshot);
+                    self.response_sender
+                        .send(response)
+                        .expect("failed to send gpu worker response for snapshot");
+                }
+                WorkerRequest::Restore(snapshot) => {
+                    let response = self.on_restore(snapshot).map(|_| WorkerResponse::Ok);
+                    self.response_sender
+                        .send(response)
+                        .expect("failed to send gpu worker response for restore");
+                }
+            }
+        }
+    }
+
+    fn on_activate(&mut self, request: WorkerActivateRequest) -> anyhow::Result<()> {
+        self.fence_handler_resources
+            .lock()
+            .replace(FenceHandlerActivationResources {
+                mem: request.resources.mem.clone(),
+                ctrl_queue: request.resources.ctrl_queue.clone(),
+            });
+
+        self.state
+            .virtio_gpu
+            .resume(&request.resources.mem)
+            .context("gpu worker failed to activate virtio frontend")?;
+
+        self.activation_resources = Some(request.resources);
+
+        Ok(())
+    }
+
+    fn on_suspend(&mut self) -> anyhow::Result<GpuDeactivationResources> {
+        self.state
+            .virtio_gpu
+            .suspend()
+            .context("failed to suspend VirtioGpu")?;
+
+        self.fence_handler_resources.lock().take();
+
+        let queues = if let Some(activation_resources) = self.activation_resources.take() {
+            Some(vec![
+                match Arc::try_unwrap(activation_resources.ctrl_queue.queue) {
+                    Ok(x) => x.into_inner(),
+                    Err(_) => panic!("too many refs on ctrl_queue"),
+                },
+                activation_resources.cursor_queue.queue.into_inner(),
+            ])
+        } else {
+            None
+        };
+
+        Ok(GpuDeactivationResources { queues })
+    }
+
+    fn on_snapshot(&mut self) -> anyhow::Result<WorkerSnapshot> {
+        Ok(WorkerSnapshot {
+            fence_state_snapshot: self.fence_state.lock().snapshot(),
+            virtio_gpu_snapshot: self
+                .state
+                .virtio_gpu
+                .snapshot()
+                .context("failed to snapshot VirtioGpu")?,
+        })
+    }
+
+    fn on_restore(&mut self, snapshot: WorkerSnapshot) -> anyhow::Result<()> {
+        self.fence_state
+            .lock()
+            .restore(snapshot.fence_state_snapshot);
+
+        self.state
+            .virtio_gpu
+            .restore(snapshot.virtio_gpu_snapshot)
+            .context("failed to restore VirtioGpu")?;
+
+        Ok(())
+    }
+
+    fn run_until_sleep_or_exit(&mut self) -> anyhow::Result<WorkerStopReason> {
+        let activation_resources = self
+            .activation_resources
+            .as_ref()
+            .context("virtio gpu worker missing activation resources")?;
+
+        let display_desc =
+            SafeDescriptor::try_from(&*self.state.display().borrow() as &dyn AsRawDescriptor)
+                .context("failed getting event descriptor for display")?;
+
+        let ctrl_evt = activation_resources
             .ctrl_queue
             .queue
             .lock()
             .event()
             .try_clone()
-            .expect("failed to clone queue event");
-        let cursor_evt = self
+            .context("failed to clone queue event")?;
+        let cursor_evt = activation_resources
             .cursor_queue
             .queue
             .borrow()
             .event()
             .try_clone()
-            .expect("failed to clone queue event");
+            .context("failed to clone queue event")?;
 
-        let mut event_manager = match EventManager::build_with(&[
+        let mut event_manager = EventManager::build_with(&[
             (&ctrl_evt, WorkerToken::CtrlQueue),
             (&cursor_evt, WorkerToken::CursorQueue),
             (&display_desc, WorkerToken::Display),
@@ -918,37 +1142,28 @@ impl Worker {
                 self.gpu_control_tube.get_read_notifier(),
                 WorkerToken::GpuControl,
             ),
+            (&self.suspend_evt, WorkerToken::Sleep),
             (&self.kill_evt, WorkerToken::Kill),
             #[cfg(windows)]
             (
                 self.gpu_display_wait_descriptor_ctrl_rd.get_read_notifier(),
                 WorkerToken::DisplayDescriptorRequest,
             ),
-        ]) {
-            Ok(v) => v,
-            Err(e) => {
-                error!("failed creating WaitContext: {}", e);
-                return;
-            }
-        };
+        ])
+        .context("failed creating gpu worker WaitContext")?;
 
-        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
-            if let Err(e) = event_manager.add(resample_evt, WorkerToken::InterruptResample) {
-                error!(
-                    "failed adding interrupt resample event to WaitContext: {}",
-                    e
-                );
-                return;
-            }
+        if let Some(resample_evt) = activation_resources.interrupt.get_resample_evt() {
+            event_manager
+                .add(resample_evt, WorkerToken::InterruptResample)
+                .context("failed adding interrupt resample event to WaitContext")?;
         }
 
         let poll_desc: SafeDescriptor;
         if let Some(desc) = self.state.virtio_gpu.poll_descriptor() {
             poll_desc = desc;
-            if let Err(e) = event_manager.add(&poll_desc, WorkerToken::VirtioGpuPoll) {
-                error!("failed adding poll event to WaitContext: {}", e);
-                return;
-            }
+            event_manager
+                .add(&poll_desc, WorkerToken::VirtioGpuPoll)
+                .context("failed adding poll event to WaitContext")?;
         }
 
         self.resource_bridges
@@ -962,14 +1177,12 @@ impl Worker {
         // might be handled first instead of the other way around.  In practice, the cursor queue
         // isn't used so this isn't a huge issue.
 
-        'wait: loop {
-            let events = match event_manager.wait_ctx.wait() {
-                Ok(v) => v,
-                Err(e) => {
-                    error!("failed polling for events: {}", e);
-                    break;
-                }
-            };
+        loop {
+            let events = event_manager
+                .wait_ctx
+                .wait()
+                .context("failed polling for gpu worker events")?;
+
             let mut signal_used_cursor = false;
             let mut signal_used_ctrl = false;
             let mut ctrl_available = false;
@@ -996,7 +1209,10 @@ impl Worker {
                     }
                     WorkerToken::CursorQueue => {
                         let _ = cursor_evt.wait();
-                        if self.state.process_queue(&self.mem, &self.cursor_queue) {
+                        if self.state.process_queue(
+                            &activation_resources.mem,
+                            &activation_resources.cursor_queue,
+                        ) {
                             signal_used_cursor = true;
                         }
                     }
@@ -1029,36 +1245,34 @@ impl Worker {
                         }
                     }
                     WorkerToken::GpuControl => {
-                        let req = match self.gpu_control_tube.recv() {
-                            Ok(req) => req,
-                            Err(e) => {
-                                error!("gpu control socket failed recv: {:?}", e);
-                                break 'wait;
-                            }
-                        };
-
+                        let req = self
+                            .gpu_control_tube
+                            .recv()
+                            .context("failed to recv from gpu control socket")?;
                         let resp = self.state.process_gpu_control_command(req);
 
                         if let GpuControlResult::DisplaysUpdated = resp {
                             needs_config_interrupt = true;
                         }
 
-                        if let Err(e) = self.gpu_control_tube.send(&resp) {
-                            error!("display control socket failed send: {}", e);
-                            break 'wait;
-                        }
+                        self.gpu_control_tube
+                            .send(&resp)
+                            .context("failed to send gpu control socket response")?;
                     }
                     WorkerToken::ResourceBridge { index } => {
                         self.resource_bridges.set_should_process(index);
                     }
                     WorkerToken::InterruptResample => {
-                        self.interrupt.interrupt_resample();
+                        activation_resources.interrupt.interrupt_resample();
                     }
                     WorkerToken::VirtioGpuPoll => {
                         self.state.event_poll();
                     }
+                    WorkerToken::Sleep => {
+                        return Ok(WorkerStopReason::Sleep);
+                    }
                     WorkerToken::Kill => {
-                        break 'wait;
+                        return Ok(WorkerStopReason::Kill);
                     }
                 }
             }
@@ -1076,7 +1290,11 @@ impl Worker {
                 };
             }
 
-            if ctrl_available && self.state.process_queue(&self.mem, &self.ctrl_queue) {
+            if ctrl_available
+                && self
+                    .state
+                    .process_queue(&activation_resources.mem, &activation_resources.ctrl_queue)
+            {
                 signal_used_ctrl = true;
             }
 
@@ -1090,15 +1308,15 @@ impl Worker {
                 .process_resource_bridges(&mut self.state, &mut event_manager.wait_ctx);
 
             if signal_used_ctrl {
-                self.ctrl_queue.signal_used();
+                activation_resources.ctrl_queue.signal_used();
             }
 
             if signal_used_cursor {
-                self.cursor_queue.signal_used();
+                activation_resources.cursor_queue.signal_used();
             }
 
             if needs_config_interrupt {
-                self.interrupt.signal_config_changed();
+                activation_resources.interrupt.signal_config_changed();
             }
         }
     }
@@ -1160,29 +1378,17 @@ impl DisplayBackend {
     }
 }
 
-/// Resources that are not available until the device is activated.
-struct GpuActivationResources {
-    mem: GuestMemory,
-    interrupt: Interrupt,
-    ctrl_queue: SharedQueueReader,
-    cursor_queue: LocalQueueReader,
-    worker_snapshot: Option<WorkerSnapshot>,
-}
-
 pub struct Gpu {
     exit_evt_wrtube: SendTube,
     pub gpu_control_tube: Option<Tube>,
     mapper: Arc<Mutex<Option<Box<dyn SharedMemoryMapper>>>>,
     resource_bridges: Option<ResourceBridges>,
     event_devices: Option<Vec<EventDevice>>,
-    // The worker thread + a channel used to activate it.
-    // NOTE: The worker thread doesn't respond to `WorkerThread::stop` when in the pre-activate
-    // phase. You must drop the channel first. That is also why the channel is first in the tuple
-    // (tuple members are dropped in order).
-    worker_thread: Option<(
-        mpsc::Sender<GpuActivationResources>,
-        WorkerThread<WorkerReturn>,
-    )>,
+    worker_suspend_evt: Option<Event>,
+    worker_request_sender: Option<mpsc::Sender<WorkerRequest>>,
+    worker_response_receiver: Option<mpsc::Receiver<anyhow::Result<WorkerResponse>>>,
+    worker_state: WorkerState,
+    worker_thread: Option<WorkerThread<()>>,
     display_backends: Vec<DisplayBackend>,
     display_params: Vec<GpuDisplayParameters>,
     display_event: Arc<AtomicBool>,
@@ -1209,10 +1415,6 @@ pub struct Gpu {
     capset_mask: u64,
     #[cfg(any(target_os = "android", target_os = "linux"))]
     gpu_cgroup_path: Option<PathBuf>,
-    /// Used to differentiate worker kill events that are for shutdown vs sleep. `virtio_sleep`
-    /// sets this to true while stopping the worker.
-    sleep_requested: Arc<AtomicBool>,
-    worker_snapshot: Option<WorkerSnapshot>,
 }
 
 impl Gpu {
@@ -1295,6 +1497,10 @@ impl Gpu {
             mapper: Arc::new(Mutex::new(None)),
             resource_bridges: Some(ResourceBridges::new(resource_bridges)),
             event_devices: Some(event_devices),
+            worker_request_sender: None,
+            worker_response_receiver: None,
+            worker_suspend_evt: None,
+            worker_state: WorkerState::Inactive,
             worker_thread: None,
             display_backends,
             display_params,
@@ -1317,8 +1523,6 @@ impl Gpu {
             capset_mask: gpu_parameters.capset_mask,
             #[cfg(any(target_os = "android", target_os = "linux"))]
             gpu_cgroup_path: gpu_cgroup_path.cloned(),
-            sleep_requested: Arc::new(AtomicBool::new(false)),
-            worker_snapshot: None,
         }
     }
 
@@ -1370,6 +1574,12 @@ impl Gpu {
 
     // This is not invoked when running with vhost-user GPU.
     fn start_worker_thread(&mut self) {
+        let suspend_evt = Event::new().unwrap();
+        let suspend_evt_copy = suspend_evt
+            .try_clone()
+            .context("error cloning suspend event")
+            .unwrap();
+
         let exit_evt_wrtube = self
             .exit_evt_wrtube
             .try_clone()
@@ -1395,7 +1605,6 @@ impl Gpu {
         let external_blob = self.external_blob;
         let fixed_blob_mapping = self.fixed_blob_mapping;
         let udmabuf = self.udmabuf;
-        let fence_state = Arc::new(Mutex::new(Default::default()));
 
         #[cfg(windows)]
         let mut wndproc_thread = self.wndproc_thread.take();
@@ -1423,8 +1632,9 @@ impl Gpu {
         });
 
         let (init_finished_tx, init_finished_rx) = mpsc::channel();
-        let (activate_tx, activate_rx) = mpsc::channel();
-        let sleep_requested = self.sleep_requested.clone();
+
+        let (worker_request_sender, worker_request_receiver) = mpsc::channel();
+        let (worker_response_sender, worker_response_receiver) = mpsc::channel();
 
         let worker_thread = WorkerThread::start("v_gpu", move |kill_evt| {
             #[cfg(any(target_os = "android", target_os = "linux"))]
@@ -1433,157 +1643,57 @@ impl Gpu {
                     .expect("Failed to move v_gpu into requested cgroup");
             }
 
-            let rutabaga_fence_handler_resources = Arc::new(Mutex::new(None));
-            let rutabaga_fence_handler = create_fence_handler(
-                rutabaga_fence_handler_resources.clone(),
-                fence_state.clone(),
-            );
-            let rutabaga =
-                match rutabaga_builder.build(rutabaga_fence_handler, rutabaga_server_descriptor) {
-                    Ok(rutabaga) => rutabaga,
-                    Err(e) => {
-                        error!("failed to build rutabaga {}", e);
-                        return WorkerReturn {
-                            gpu_control_tube,
-                            resource_bridges,
-                            event_devices,
-                            activated_state: None,
-                        };
-                    }
-                };
-
-            let mut virtio_gpu = match build(
-                &display_backends,
+            let mut worker = Worker::new(
+                rutabaga_builder,
+                rutabaga_server_descriptor,
+                display_backends,
                 display_params,
                 display_event,
-                rutabaga,
                 mapper,
+                event_devices,
                 external_blob,
                 fixed_blob_mapping,
-                #[cfg(windows)]
-                &mut wndproc_thread,
                 udmabuf,
-                #[cfg(windows)]
-                gpu_display_wait_descriptor_ctrl_wr,
-            ) {
-                Some(backend) => backend,
-                None => {
-                    return WorkerReturn {
-                        gpu_control_tube,
-                        resource_bridges,
-                        event_devices,
-                        activated_state: None,
-                    };
-                }
-            };
-
-            for event_device in event_devices {
-                virtio_gpu
-                    .import_event_device(event_device)
-                    // We lost the `EventDevice`, so fail hard.
-                    .expect("failed to import event device");
-            }
-
-            // Tell the parent thread that the init phase is complete.
-            let _ = init_finished_tx.send(());
-
-            let activation_resources: GpuActivationResources = match activate_rx.recv() {
-                Ok(x) => x,
-                // Other half of channel was dropped.
-                Err(mpsc::RecvError) => {
-                    return WorkerReturn {
-                        gpu_control_tube,
-                        resource_bridges,
-                        event_devices: virtio_gpu.display().borrow_mut().take_event_devices(),
-                        activated_state: None,
-                    };
-                }
-            };
-
-            rutabaga_fence_handler_resources
-                .lock()
-                .replace(FenceHandlerActivationResources {
-                    mem: activation_resources.mem.clone(),
-                    ctrl_queue: activation_resources.ctrl_queue.clone(),
-                });
-            // Drop so we don't hold extra refs on the queue's `Arc`.
-            std::mem::drop(rutabaga_fence_handler_resources);
-
-            let mut worker = Worker {
-                interrupt: activation_resources.interrupt,
+                worker_request_receiver,
+                worker_response_sender,
                 exit_evt_wrtube,
                 gpu_control_tube,
-                mem: activation_resources.mem,
-                ctrl_queue: activation_resources.ctrl_queue,
-                cursor_queue: activation_resources.cursor_queue,
                 resource_bridges,
+                suspend_evt_copy,
                 kill_evt,
-                state: Frontend::new(virtio_gpu, fence_state),
+                #[cfg(windows)]
+                wndproc_thread,
                 #[cfg(windows)]
                 gpu_display_wait_descriptor_ctrl_rd,
-            };
-
-            // If a snapshot was provided, restore from it.
-            if let Some(snapshot) = activation_resources.worker_snapshot {
-                worker
-                    .state
-                    .fence_state
-                    .lock()
-                    .restore(snapshot.fence_state_snapshot);
-                worker
-                    .state
-                    .virtio_gpu
-                    .restore(snapshot.virtio_gpu_snapshot, &worker.mem)
-                    .expect("failed to restore VirtioGpu");
-            }
+                #[cfg(windows)]
+                gpu_display_wait_descriptor_ctrl_wr,
+            )
+            .expect("Failed to create virtio gpu worker thread");
 
-            worker.run();
+            // Tell the parent thread that the init phase is complete.
+            let _ = init_finished_tx.send(());
 
-            let event_devices = worker
-                .state
-                .virtio_gpu
-                .display()
-                .borrow_mut()
-                .take_event_devices();
-            // If we are stopping the worker because of a virtio_sleep request, then take a
-            // snapshot and reclaim the queues.
-            let activated_state = if sleep_requested.load(Ordering::SeqCst) {
-                let worker_snapshot = WorkerSnapshot {
-                    fence_state_snapshot: worker.state.fence_state.lock().snapshot(),
-                    virtio_gpu_snapshot: worker
-                        .state
-                        .virtio_gpu
-                        .snapshot()
-                        .expect("failed to snapshot VirtioGpu"),
-                };
-                // Need to drop `Frontend` for the `Arc::try_unwrap` below to succeed.
-                std::mem::drop(worker.state);
-                Some((
-                    vec![
-                        match Arc::try_unwrap(worker.ctrl_queue.queue) {
-                            Ok(x) => x.into_inner(),
-                            Err(_) => panic!("too many refs on ctrl_queue"),
-                        },
-                        worker.cursor_queue.queue.into_inner(),
-                    ],
-                    worker_snapshot,
-                ))
-            } else {
-                None
-            };
-            WorkerReturn {
-                gpu_control_tube: worker.gpu_control_tube,
-                resource_bridges: worker.resource_bridges,
-                event_devices,
-                activated_state,
-            }
+            worker.run()
         });
 
-        self.worker_thread = Some((activate_tx, worker_thread));
+        self.worker_request_sender = Some(worker_request_sender);
+        self.worker_response_receiver = Some(worker_response_receiver);
+        self.worker_suspend_evt = Some(suspend_evt);
+        self.worker_state = WorkerState::Inactive;
+        self.worker_thread = Some(worker_thread);
 
         match init_finished_rx.recv() {
             Ok(()) => {}
-            Err(mpsc::RecvError) => error!("virtio-gpu worker thread init failed"),
+            Err(mpsc::RecvError) => panic!("virtio-gpu worker thread init failed"),
+        }
+    }
+
+    fn stop_worker_thread(&mut self) {
+        self.worker_request_sender.take();
+        self.worker_response_receiver.take();
+        self.worker_suspend_evt.take();
+        if let Some(worker_thread) = self.worker_thread.take() {
+            worker_thread.stop();
         }
     }
 
@@ -1757,24 +1867,28 @@ impl VirtioDevice for Gpu {
         let ctrl_queue = SharedQueueReader::new(queues.remove(&0).unwrap());
         let cursor_queue = LocalQueueReader::new(queues.remove(&1).unwrap());
 
-        match self
-            .worker_thread
-            .as_mut()
-            .expect("worker thread missing on activate")
-            .0
-            .send(GpuActivationResources {
-                mem,
-                interrupt,
-                ctrl_queue,
-                cursor_queue,
-                worker_snapshot: self.worker_snapshot.take(),
-            }) {
-            Err(mpsc::SendError(gpu_activation_resources)) => {
-                self.worker_snapshot = gpu_activation_resources.worker_snapshot;
-                bail!("failed to send activation resources to worker thread");
-            }
-            Ok(()) => Ok(()),
-        }
+        self.worker_request_sender
+            .as_ref()
+            .context("worker thread missing on activate?")?
+            .send(WorkerRequest::Activate(WorkerActivateRequest {
+                resources: GpuActivationResources {
+                    mem,
+                    interrupt,
+                    ctrl_queue,
+                    cursor_queue,
+                },
+            }))
+            .map_err(|e| anyhow!("failed to send virtio gpu worker activate request: {:?}", e))?;
+
+        self.worker_response_receiver
+            .as_ref()
+            .context("worker thread missing on activate?")?
+            .recv()
+            .inspect(|_| self.worker_state = WorkerState::Active)
+            .inspect_err(|_| self.worker_state = WorkerState::Error)
+            .context("failed to receive response for virtio gpu worker resume request")??;
+
+        Ok(())
     }
 
     fn pci_address(&self) -> Option<PciAddress> {
@@ -1819,47 +1933,83 @@ impl VirtioDevice for Gpu {
     //     Wayland socket (for example).
     //   * No state about pending virtio requests needs to be snapshotted because the 2d backend
     //     completes them synchronously.
-
     fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
-        if let Some((activate_tx, worker_thread)) = self.worker_thread.take() {
-            self.sleep_requested.store(true, Ordering::SeqCst);
-            drop(activate_tx);
-            let WorkerReturn {
-                gpu_control_tube,
-                resource_bridges,
-                event_devices,
-                activated_state,
-            } = worker_thread.stop();
-            self.sleep_requested.store(false, Ordering::SeqCst);
-
-            self.resource_bridges = Some(resource_bridges);
-            self.gpu_control_tube = Some(gpu_control_tube);
-            self.event_devices = Some(event_devices);
-
-            match activated_state {
-                Some((queues, worker_snapshot)) => {
-                    self.worker_snapshot = Some(worker_snapshot);
-                    return Ok(Some(queues.into_iter().enumerate().collect()));
-                }
-                // Device not activated yet.
-                None => {
-                    self.worker_snapshot = None;
-                    return Ok(None);
+        match self.worker_state {
+            WorkerState::Error => {
+                return Err(anyhow!(
+                    "failed to sleep virtio gpu worker which is in error state"
+                ));
+            }
+            WorkerState::Inactive => {
+                return Ok(None);
+            }
+            _ => (),
+        };
+
+        if let (
+            Some(worker_request_sender),
+            Some(worker_response_receiver),
+            Some(worker_suspend_evt),
+        ) = (
+            &self.worker_request_sender,
+            &self.worker_response_receiver,
+            &self.worker_suspend_evt,
+        ) {
+            worker_request_sender
+                .send(WorkerRequest::Suspend)
+                .map_err(|e| {
+                    anyhow!(
+                        "failed to send suspend request to virtio gpu worker: {:?}",
+                        e
+                    )
+                })?;
+
+            worker_suspend_evt
+                .signal()
+                .context("failed to signal virtio gpu worker suspend event")?;
+
+            let response = worker_response_receiver
+                .recv()
+                .inspect(|_| self.worker_state = WorkerState::Inactive)
+                .inspect_err(|_| self.worker_state = WorkerState::Error)
+                .context("failed to receive response for virtio gpu worker suspend request")??;
+
+            worker_suspend_evt
+                .reset()
+                .context("failed to reset virtio gpu worker suspend event")?;
+
+            match response {
+                WorkerResponse::Suspend(deactivation_resources) => Ok(deactivation_resources
+                    .queues
+                    .map(|q| q.into_iter().enumerate().collect())),
+                _ => {
+                    panic!("unexpected response from virtio gpu worker sleep request");
                 }
             }
+        } else {
+            Err(anyhow!("virtio gpu worker not available for sleep"))
         }
-        Ok(None)
     }
 
     fn virtio_wake(
         &mut self,
         queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
     ) -> anyhow::Result<()> {
+        match self.worker_state {
+            WorkerState::Error => {
+                return Err(anyhow!(
+                    "failed to wake virtio gpu worker which is in error state"
+                ));
+            }
+            WorkerState::Active => {
+                return Ok(());
+            }
+            _ => (),
+        };
+
         match queues_state {
             None => Ok(()),
             Some((mem, interrupt, queues)) => {
-                assert!(self.worker_thread.is_none());
-                self.start_worker_thread();
                 // TODO(khei): activate is just what we want at the moment, but we should probably
                 // move it into a "start workers" function to make it obvious that it isn't
                 // strictly used for activate events.
@@ -1870,15 +2020,104 @@ impl VirtioDevice for Gpu {
     }
 
     fn virtio_snapshot(&mut self) -> anyhow::Result<serde_json::Value> {
-        Ok(serde_json::to_value(&self.worker_snapshot)?)
+        match self.worker_state {
+            WorkerState::Error => {
+                return Err(anyhow!(
+                    "failed to snapshot virtio gpu worker which is in error state"
+                ));
+            }
+            WorkerState::Active => {
+                return Err(anyhow!(
+                    "failed to snapshot virtio gpu worker which is in active state"
+                ));
+            }
+            _ => (),
+        };
+
+        if let (Some(worker_request_sender), Some(worker_response_receiver)) =
+            (&self.worker_request_sender, &self.worker_response_receiver)
+        {
+            worker_request_sender
+                .send(WorkerRequest::Snapshot)
+                .map_err(|e| {
+                    anyhow!(
+                        "failed to send snapshot request to virtio gpu worker: {:?}",
+                        e
+                    )
+                })?;
+
+            match worker_response_receiver
+                .recv()
+                .inspect_err(|_| self.worker_state = WorkerState::Error)
+                .context("failed to receive response for virtio gpu worker suspend request")??
+            {
+                WorkerResponse::Snapshot(snapshot) => Ok(serde_json::to_value(snapshot)?),
+                _ => {
+                    panic!("unexpected response from virtio gpu worker sleep request");
+                }
+            }
+        } else {
+            Err(anyhow!("virtio gpu worker not available for snapshot"))
+        }
     }
 
     fn virtio_restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
-        self.worker_snapshot = serde_json::from_value(data)?;
+        match self.worker_state {
+            WorkerState::Error => {
+                return Err(anyhow!(
+                    "failed to restore virtio gpu worker which is in error state"
+                ));
+            }
+            WorkerState::Active => {
+                return Err(anyhow!(
+                    "failed to restore virtio gpu worker which is in active state"
+                ));
+            }
+            _ => (),
+        };
+
+        let snapshot: WorkerSnapshot = serde_json::from_value(data)?;
+
+        if let (Some(worker_request_sender), Some(worker_response_receiver)) =
+            (&self.worker_request_sender, &self.worker_response_receiver)
+        {
+            worker_request_sender
+                .send(WorkerRequest::Restore(snapshot))
+                .map_err(|e| {
+                    anyhow!(
+                        "failed to send suspend request to virtio gpu worker: {:?}",
+                        e
+                    )
+                })?;
+
+            let response = worker_response_receiver
+                .recv()
+                .inspect_err(|_| self.worker_state = WorkerState::Error)
+                .context("failed to receive response for virtio gpu worker suspend request")??;
+
+            match response {
+                WorkerResponse::Ok => Ok(()),
+                _ => {
+                    panic!("unexpected response from virtio gpu worker sleep request");
+                }
+            }
+        } else {
+            Err(anyhow!("virtio gpu worker not available for restore"))
+        }
+    }
+
+    fn reset(&mut self) -> anyhow::Result<()> {
+        self.stop_worker_thread();
         Ok(())
     }
 }
 
+impl Drop for Gpu {
+    fn drop(&mut self) {
+        let _ = self.reset();
+    }
+}
+
 /// This struct takes the ownership of resource bridges and tracks which ones should be processed.
 struct ResourceBridges {
     resource_bridges: Vec<Tube>,
diff --git a/devices/src/virtio/gpu/virtio_gpu.rs b/devices/src/virtio/gpu/virtio_gpu.rs
index 6e885a726..bf3e9602c 100644
--- a/devices/src/virtio/gpu/virtio_gpu.rs
+++ b/devices/src/virtio/gpu/virtio_gpu.rs
@@ -109,6 +109,7 @@ struct VirtioGpuResourceSnapshot {
     size: u64,
 
     backing_iovecs: Option<Vec<(GuestAddress, usize)>>,
+    shmem_offset: Option<u64>,
 }
 
 impl VirtioGpuResource {
@@ -129,17 +130,17 @@ impl VirtioGpuResource {
     }
 
     fn snapshot(&self) -> VirtioGpuResourceSnapshot {
-        // Only the 2D backend is support and it doesn't use these fields.
-        assert!(self.shmem_offset.is_none());
+        // Only the 2D backend is fully supported and it doesn't use these fields. 3D is WIP.
         assert!(self.scanout_data.is_none());
         assert!(self.display_import.is_none());
-        assert_eq!(self.rutabaga_external_mapping, false);
+
         VirtioGpuResourceSnapshot {
             resource_id: self.resource_id,
             width: self.width,
             height: self.height,
             size: self.size,
             backing_iovecs: self.backing_iovecs.clone(),
+            shmem_offset: self.shmem_offset,
         }
     }
 
@@ -457,6 +458,7 @@ pub struct VirtioGpu {
     external_blob: bool,
     fixed_blob_mapping: bool,
     udmabuf_driver: Option<UdmabufDriver>,
+    deferred_snapshot_load: Option<VirtioGpuSnapshot>,
 }
 
 // Only the 2D mode is supported. Notes on `VirtioGpu` fields:
@@ -564,6 +566,7 @@ impl VirtioGpu {
             external_blob,
             fixed_blob_mapping,
             udmabuf_driver,
+            deferred_snapshot_load: None,
         })
     }
 
@@ -1288,6 +1291,12 @@ impl VirtioGpu {
         Ok(OkNoData)
     }
 
+    pub fn suspend(&self) -> anyhow::Result<()> {
+        self.rutabaga
+            .suspend()
+            .context("failed to suspend rutabaga")
+    }
+
     pub fn snapshot(&self) -> anyhow::Result<VirtioGpuSnapshot> {
         Ok(VirtioGpuSnapshot {
             scanouts: self
@@ -1312,45 +1321,60 @@ impl VirtioGpu {
         })
     }
 
-    pub fn restore(
-        &mut self,
-        snapshot: VirtioGpuSnapshot,
-        mem: &GuestMemory,
-    ) -> anyhow::Result<()> {
-        assert!(self.scanouts.keys().eq(snapshot.scanouts.keys()));
-        for (i, s) in snapshot.scanouts.into_iter() {
-            self.scanouts.get_mut(&i).unwrap().restore(
-                s,
-                // Only the cursor scanout can have a parent.
-                None,
-                &self.display,
-            )?;
-        }
-        self.scanouts_updated
-            .store(snapshot.scanouts_updated, Ordering::SeqCst);
-
-        let cursor_parent_surface_id = snapshot
-            .cursor_scanout
-            .parent_scanout_id
-            .and_then(|i| self.scanouts.get(&i).unwrap().surface_id);
-        self.cursor_scanout.restore(
-            snapshot.cursor_scanout,
-            cursor_parent_surface_id,
-            &self.display,
-        )?;
+    pub fn restore(&mut self, snapshot: VirtioGpuSnapshot) -> anyhow::Result<()> {
+        self.deferred_snapshot_load = Some(snapshot);
+        Ok(())
+    }
 
-        self.rutabaga
-            .restore(&mut &snapshot.rutabaga[..], "")
-            .context("failed to restore rutabaga")?;
-
-        for (id, s) in snapshot.resources.into_iter() {
-            let backing_iovecs = s.backing_iovecs.clone();
-            self.resources.insert(id, VirtioGpuResource::restore(s));
-            if let Some(backing_iovecs) = backing_iovecs {
-                self.attach_backing(id, mem, backing_iovecs)?;
+    pub fn resume(&mut self, mem: &GuestMemory) -> anyhow::Result<()> {
+        if let Some(snapshot) = self.deferred_snapshot_load.take() {
+            assert!(self.scanouts.keys().eq(snapshot.scanouts.keys()));
+            for (i, s) in snapshot.scanouts.into_iter() {
+                self.scanouts
+                    .get_mut(&i)
+                    .unwrap()
+                    .restore(
+                        s,
+                        // Only the cursor scanout can have a parent.
+                        None,
+                        &self.display,
+                    )
+                    .context("failed to restore scanouts")?;
+            }
+            self.scanouts_updated
+                .store(snapshot.scanouts_updated, Ordering::SeqCst);
+
+            let cursor_parent_surface_id = snapshot
+                .cursor_scanout
+                .parent_scanout_id
+                .and_then(|i| self.scanouts.get(&i).unwrap().surface_id);
+            self.cursor_scanout
+                .restore(
+                    snapshot.cursor_scanout,
+                    cursor_parent_surface_id,
+                    &self.display,
+                )
+                .context("failed to restore cursor scanout")?;
+
+            self.rutabaga
+                .restore(&mut &snapshot.rutabaga[..], "")
+                .context("failed to restore rutabaga")?;
+
+            for (id, s) in snapshot.resources.into_iter() {
+                let backing_iovecs = s.backing_iovecs.clone();
+                let shmem_offset = s.shmem_offset;
+                self.resources.insert(id, VirtioGpuResource::restore(s));
+                if let Some(backing_iovecs) = backing_iovecs {
+                    self.attach_backing(id, mem, backing_iovecs)
+                        .context("failed to restore resource backing")?;
+                }
+                if let Some(shmem_offset) = shmem_offset {
+                    self.resource_map_blob(id, shmem_offset)
+                        .context("failed to restore resource mapping")?;
+                }
             }
         }
 
-        Ok(())
+        self.rutabaga.resume().context("failed to resume rutabaga")
     }
 }
diff --git a/devices/src/virtio/input/defaults.rs b/devices/src/virtio/input/defaults.rs
index db34ce55a..6ea3956fe 100644
--- a/devices/src/virtio/input/defaults.rs
+++ b/devices/src/virtio/input/defaults.rs
@@ -4,6 +4,7 @@
 
 use std::collections::BTreeMap;
 
+use base::warn;
 use linux_input_sys::constants::*;
 
 use super::virtio_input_absinfo;
@@ -145,6 +146,39 @@ pub fn new_multi_touch_config(
     )
 }
 
+/// Initializes a VirtioInputConfig object for a custom virtio-input device.
+///
+/// # Arguments
+///
+/// * `idx` - input device index
+/// * `name` - input device name
+/// * `serial_name` - input device serial name
+/// * `supported_events` - Event configuration provided by a configuration file
+pub fn new_custom_config(
+    idx: u32,
+    name: &str,
+    serial_name: &str,
+    supported_events: BTreeMap<u16, virtio_input_bitmap>,
+) -> VirtioInputConfig {
+    let name: String = format!("{name} {idx}");
+    let serial_name = format!("{serial_name}-{idx}");
+    if name.as_bytes().len() > 128 {
+        warn!("name: {name} exceeds 128 bytes, will be truncated.");
+    }
+    if serial_name.as_bytes().len() > 128 {
+        warn!("serial_name: {serial_name} exceeds 128 bytes, will be truncated.");
+    }
+
+    VirtioInputConfig::new(
+        virtio_input_device_ids::new(0, 0, 0, 0),
+        name,
+        serial_name,
+        virtio_input_bitmap::new([0u8; 128]),
+        supported_events,
+        BTreeMap::new(),
+    )
+}
+
 fn default_touchscreen_absinfo(width: u32, height: u32) -> BTreeMap<u16, virtio_input_absinfo> {
     let mut absinfo: BTreeMap<u16, virtio_input_absinfo> = BTreeMap::new();
     absinfo.insert(ABS_X, virtio_input_absinfo::new(0, width, 0, 0));
diff --git a/devices/src/virtio/input/mod.rs b/devices/src/virtio/input/mod.rs
index d956958ff..edaa88ba3 100644
--- a/devices/src/virtio/input/mod.rs
+++ b/devices/src/virtio/input/mod.rs
@@ -8,8 +8,10 @@ mod evdev;
 mod event_source;
 
 use std::collections::BTreeMap;
+use std::fs;
 use std::io::Read;
 use std::io::Write;
+use std::path::PathBuf;
 
 use anyhow::anyhow;
 use anyhow::bail;
@@ -17,6 +19,7 @@ use anyhow::Context;
 use base::custom_serde::deserialize_seq_to_arr;
 use base::custom_serde::serialize_arr;
 use base::error;
+use base::info;
 use base::warn;
 use base::AsRawDescriptor;
 use base::Event;
@@ -88,6 +91,9 @@ pub enum InputError {
     // Invalid UTF-8 string
     #[error("invalid UTF-8 string: {0}")]
     InvalidString(std::string::FromUtf8Error),
+    // Failed to parse event config file
+    #[error("failed to parse event config file: {0}")]
+    ParseEventConfigError(String),
     // Error while reading from virtqueue
     #[error("failed to read from virtqueue: {0}")]
     ReadQueue(std::io::Error),
@@ -193,7 +199,7 @@ impl virtio_input_config {
     }
 }
 
-#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
+#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
 #[repr(C)]
 pub struct virtio_input_bitmap {
     #[serde(
@@ -835,3 +841,190 @@ where
         virtio_features,
     })
 }
+
+/// Creates a new custom virtio input device
+pub fn new_custom<T>(
+    idx: u32,
+    source: T,
+    input_config_path: PathBuf,
+    virtio_features: u64,
+) -> Result<Input<SocketEventSource<T>>>
+where
+    T: Read + Write + AsRawDescriptor + Send + 'static,
+{
+    let config = parse_input_config_file(&input_config_path, idx)?;
+
+    Ok(Input {
+        worker_thread: None,
+        config: defaults::new_custom_config(
+            idx,
+            &config.name,
+            &config.serial_name,
+            config.supported_events,
+        ),
+        source: Some(SocketEventSource::new(source)),
+        virtio_features,
+    })
+}
+
+#[derive(Debug, Deserialize)]
+struct InputConfigFile {
+    name: Option<String>,
+    serial_name: Option<String>,
+    events: Vec<InputConfigFileEvent>,
+}
+
+#[derive(Debug, Deserialize)]
+struct InputConfigFileEvent {
+    event_type: String,
+    event_type_code: u16,
+    supported_events: BTreeMap<String, u16>,
+}
+
+struct CustomInputConfig {
+    name: String,
+    serial_name: String,
+    supported_events: BTreeMap<u16, virtio_input_bitmap>,
+}
+
+// Read and parse input event config file to input device bitmaps. If parsing is successful, this
+// function returns a CustomInputConfig. The field in CustomInputConfig are corresponding to the
+// same field in struct VirtioInputConfig.
+fn parse_input_config_file(config_path: &PathBuf, device_idx: u32) -> Result<CustomInputConfig> {
+    let mut supported_events: BTreeMap<u16, virtio_input_bitmap> = BTreeMap::new();
+
+    // Read the json file to String
+    let contents = fs::read_to_string(config_path).map_err(|e| {
+        InputError::ParseEventConfigError(format!(
+            "Failed to read input event config from {}: {}",
+            config_path.display(),
+            e
+        ))
+    })?;
+
+    // Parse the string into a JSON object
+    let config_file: InputConfigFile = serde_json::from_str(contents.as_str()).map_err(|e| {
+        InputError::ParseEventConfigError(format!("Failed to parse json string: {}", e))
+    })?;
+    // Parse the supported events
+    for event in config_file.events {
+        let mut bit_map_idx: Vec<u16> = Vec::new();
+        for (event_name, event_code) in event.supported_events {
+            if event_code >= 1024 {
+                return Err(InputError::ParseEventConfigError(format!(
+                    "The {} config file's {} event has event_code exceeds bounds(>=1024)",
+                    config_path.display(),
+                    event_name
+                )));
+            }
+            bit_map_idx.push(event_code);
+        }
+        let bitmap = virtio_input_bitmap::from_bits(&bit_map_idx);
+        if supported_events
+            .insert(event.event_type_code, bitmap)
+            .is_some()
+        {
+            return Err(InputError::ParseEventConfigError(format!(
+                "The {} event has been repeatedly defined by {}",
+                event.event_type,
+                config_path.display()
+            )));
+        }
+        info!(
+            "{} event is defined by {} for input device id {}",
+            event.event_type,
+            config_path.display(),
+            device_idx
+        );
+    }
+
+    let name = config_file
+        .name
+        .unwrap_or_else(|| "Crosvm Virtio Custom".to_string());
+    let serial_name = config_file
+        .serial_name
+        .unwrap_or_else(|| "virtio-custom".to_string());
+
+    Ok(CustomInputConfig {
+        name,
+        serial_name,
+        supported_events,
+    })
+}
+
+#[cfg(test)]
+mod tests {
+    use tempfile::TempDir;
+
+    use super::*;
+    #[test]
+    fn parse_keyboard_like_input_config_file_success() {
+        pub const EV_KEY: u16 = 0x01;
+        pub const EV_LED: u16 = 0x11;
+        pub const EV_REP: u16 = 0x14;
+        // Create a sample JSON file for testing
+        let temp_file = TempDir::new().unwrap();
+        let path = temp_file.path().join("test.json");
+        let test_json = r#"
+        {
+          "name": "Virtio Custom Test",
+          "serial_name": "virtio-custom-test",
+          "events": [
+            {
+              "event_type": "EV_KEY",
+              "event_type_code": 1,
+              "supported_events": {
+                "KEY_ESC": 1,
+                "KEY_1": 2,
+                "KEY_2": 3,
+                "KEY_A": 30,
+                "KEY_B": 48,
+                "KEY_SPACE": 57
+              }
+            },
+            {
+              "event_type": "EV_REP",
+              "event_type_code": 20,
+              "supported_events": {
+                "REP_DELAY": 0,
+                "REP_PERIOD": 1
+            }
+            },
+            {
+              "event_type": "EV_LED",
+              "event_type_code": 17,
+              "supported_events": {
+                "LED_NUML": 0,
+                "LED_CAPSL": 1,
+                "LED_SCROLLL": 2
+              }
+            }
+          ]
+        }"#;
+        fs::write(&path, test_json).expect("Unable to write test file");
+
+        // Call the function and assert the result
+        let result = parse_input_config_file(&path, 0);
+        assert!(result.is_ok());
+
+        let supported_event = result.unwrap().supported_events;
+        // EV_KEY type
+        let ev_key_events = supported_event.get(&EV_KEY);
+        assert!(ev_key_events.is_some());
+        let ev_key_bitmap = ev_key_events.unwrap();
+        let expected_ev_key_bitmap = &virtio_input_bitmap::from_bits(&[1, 2, 3, 30, 48, 57]);
+        assert_eq!(ev_key_bitmap, expected_ev_key_bitmap);
+        // EV_REP type
+        let ev_rep_events = supported_event.get(&EV_REP);
+        assert!(ev_rep_events.is_some());
+        let ev_rep_bitmap = ev_rep_events.unwrap();
+        let expected_ev_rep_bitmap = &virtio_input_bitmap::from_bits(&[0, 1]);
+        assert_eq!(ev_rep_bitmap, expected_ev_rep_bitmap);
+        // EV_LED type
+        let ev_led_events = supported_event.get(&EV_LED);
+        assert!(ev_led_events.is_some());
+        let ev_led_bitmap = ev_led_events.unwrap();
+        let expected_ev_led_bitmap = &virtio_input_bitmap::from_bits(&[0, 1, 2]);
+        assert_eq!(ev_led_bitmap, expected_ev_led_bitmap);
+    }
+}
diff --git a/devices/src/virtio/iommu.rs b/devices/src/virtio/iommu.rs
index 93d377690..bec053cf0 100644
--- a/devices/src/virtio/iommu.rs
+++ b/devices/src/virtio/iommu.rs
@@ -53,7 +53,9 @@ use vm_memory::GuestAddress;
 use vm_memory::GuestMemory;
 use vm_memory::GuestMemoryError;
 use zerocopy::AsBytes;
+#[cfg(target_arch = "x86_64")]
 use zerocopy::FromBytes;
+#[cfg(target_arch = "x86_64")]
 use zerocopy::FromZeroes;
 
 #[cfg(target_arch = "x86_64")]
@@ -86,6 +88,7 @@ const VIRTIO_IOMMU_VIOT_NODE_VIRTIO_IOMMU_PCI: u8 = 3;
 
 #[derive(Copy, Clone, Debug, Default, FromZeroes, FromBytes, AsBytes)]
 #[repr(C, packed)]
+#[cfg(target_arch = "x86_64")]
 struct VirtioIommuViotHeader {
     node_count: u16,
     node_offset: u16,
@@ -94,6 +97,7 @@ struct VirtioIommuViotHeader {
 
 #[derive(Copy, Clone, Debug, Default, FromZeroes, FromBytes, AsBytes)]
 #[repr(C, packed)]
+#[cfg(target_arch = "x86_64")]
 struct VirtioIommuViotVirtioPciNode {
     type_: u8,
     reserved: [u8; 1],
@@ -105,6 +109,7 @@ struct VirtioIommuViotVirtioPciNode {
 
 #[derive(Copy, Clone, Debug, Default, FromZeroes, FromBytes, AsBytes)]
 #[repr(C, packed)]
+#[cfg(target_arch = "x86_64")]
 struct VirtioIommuViotPciRangeNode {
     type_: u8,
     reserved: [u8; 1],
diff --git a/devices/src/virtio/media.rs b/devices/src/virtio/media.rs
new file mode 100644
index 000000000..88da89f3e
--- /dev/null
+++ b/devices/src/virtio/media.rs
@@ -0,0 +1,727 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+//! Support for virtio-media devices in crosvm.
+//!
+//! This module provides implementation for the virtio-media traits required to make virtio-media
+//! devices operate under crosvm. Sub-modules then integrate these devices with crosvm.
+
+use std::collections::BTreeMap;
+use std::os::fd::AsRawFd;
+use std::os::fd::BorrowedFd;
+use std::path::Path;
+use std::path::PathBuf;
+use std::rc::Rc;
+use std::sync::Arc;
+
+use anyhow::Context;
+use base::error;
+use base::Descriptor;
+use base::Event;
+use base::EventToken;
+use base::EventType;
+use base::MappedRegion;
+use base::MemoryMappingArena;
+use base::Protection;
+use base::WaitContext;
+use base::WorkerThread;
+use resources::address_allocator::AddressAllocator;
+use resources::AddressRange;
+use resources::Alloc;
+use sync::Mutex;
+use virtio_media::io::WriteToDescriptorChain;
+use virtio_media::poll::SessionPoller;
+use virtio_media::protocol::SgEntry;
+use virtio_media::protocol::V4l2Event;
+use virtio_media::protocol::VirtioMediaDeviceConfig;
+use virtio_media::GuestMemoryRange;
+use virtio_media::VirtioMediaDevice;
+use virtio_media::VirtioMediaDeviceRunner;
+use virtio_media::VirtioMediaEventQueue;
+use virtio_media::VirtioMediaGuestMemoryMapper;
+use virtio_media::VirtioMediaHostMemoryMapper;
+use vm_control::VmMemorySource;
+use vm_memory::GuestAddress;
+use vm_memory::GuestMemory;
+
+use crate::virtio::copy_config;
+use crate::virtio::device_constants::media::QUEUE_SIZES;
+use crate::virtio::DeviceType;
+use crate::virtio::Interrupt;
+use crate::virtio::Queue;
+use crate::virtio::Reader;
+use crate::virtio::SharedMemoryMapper;
+use crate::virtio::SharedMemoryRegion;
+use crate::virtio::VirtioDevice;
+use crate::virtio::Writer;
+
+/// Structure supporting the implementation of `VirtioMediaEventQueue` for sending events to the
+/// driver.
+struct EventQueue(Queue);
+
+impl VirtioMediaEventQueue for EventQueue {
+    /// Wait until an event descriptor becomes available and send `event` to the guest.
+    fn send_event(&mut self, event: V4l2Event) {
+        let mut desc;
+
+        loop {
+            match self.0.pop() {
+                Some(d) => {
+                    desc = d;
+                    break;
+                }
+                None => {
+                    if let Err(e) = self.0.event().wait() {
+                        error!("could not obtain a descriptor to send event to: {:#}", e);
+                        return;
+                    }
+                }
+            }
+        }
+
+        if let Err(e) = match event {
+            V4l2Event::Error(event) => WriteToDescriptorChain::write_obj(&mut desc.writer, event),
+            V4l2Event::DequeueBuffer(event) => {
+                WriteToDescriptorChain::write_obj(&mut desc.writer, event)
+            }
+            V4l2Event::Event(event) => WriteToDescriptorChain::write_obj(&mut desc.writer, event),
+        } {
+            error!("failed to write event: {}", e);
+        }
+
+        let written = desc.writer.bytes_written() as u32;
+        self.0.add_used(desc, written);
+        self.0.trigger_interrupt();
+    }
+}
+
+/// A `SharedMemoryMapper` behind an `Arc`, allowing it to be shared.
+///
+/// This is required by the fact that devices can be activated several times, but the mapper is
+/// only provided once. This might be a defect of the `VirtioDevice` interface.
+#[derive(Clone)]
+struct ArcedMemoryMapper(Arc<Mutex<Box<dyn SharedMemoryMapper>>>);
+
+impl From<Box<dyn SharedMemoryMapper>> for ArcedMemoryMapper {
+    fn from(mapper: Box<dyn SharedMemoryMapper>) -> Self {
+        Self(Arc::new(Mutex::new(mapper)))
+    }
+}
+
+impl SharedMemoryMapper for ArcedMemoryMapper {
+    fn add_mapping(
+        &mut self,
+        source: VmMemorySource,
+        offset: u64,
+        prot: Protection,
+        cache: hypervisor::MemCacheType,
+    ) -> anyhow::Result<()> {
+        self.0.lock().add_mapping(source, offset, prot, cache)
+    }
+
+    fn remove_mapping(&mut self, offset: u64) -> anyhow::Result<()> {
+        self.0.lock().remove_mapping(offset)
+    }
+
+    fn as_raw_descriptor(&self) -> Option<base::RawDescriptor> {
+        self.0.lock().as_raw_descriptor()
+    }
+}
+
+/// Provides the ability to map host memory into the guest physical address space. Used to
+/// implement `VirtioMediaHostMemoryMapper`.
+struct HostMemoryMapper<M: SharedMemoryMapper> {
+    /// Mapper.
+    shm_mapper: M,
+    /// Address allocator for the mapper.
+    allocator: AddressAllocator,
+}
+
+impl<M: SharedMemoryMapper> VirtioMediaHostMemoryMapper for HostMemoryMapper<M> {
+    fn add_mapping(
+        &mut self,
+        buffer: BorrowedFd,
+        length: u64,
+        offset: u64,
+        rw: bool,
+    ) -> Result<u64, i32> {
+        // TODO: technically `offset` can be used twice if a buffer is deleted and some other takes
+        // its place...
+        let shm_offset = self
+            .allocator
+            .allocate(length, Alloc::FileBacked(offset), "".into())
+            .map_err(|_| libc::ENOMEM)?;
+
+        match self.shm_mapper.add_mapping(
+            VmMemorySource::Descriptor {
+                descriptor: buffer.try_clone_to_owned().map_err(|_| libc::EIO)?.into(),
+                offset: 0,
+                size: length,
+            },
+            shm_offset,
+            if rw {
+                Protection::read_write()
+            } else {
+                Protection::read()
+            },
+            hypervisor::MemCacheType::CacheCoherent,
+        ) {
+            Ok(()) => Ok(shm_offset),
+            Err(e) => {
+                base::error!("failed to map memory buffer: {:#}", e);
+                Err(libc::EINVAL)
+            }
+        }
+    }
+
+    fn remove_mapping(&mut self, offset: u64) -> Result<(), i32> {
+        let _ = self.allocator.release_containing(offset);
+
+        self.shm_mapper
+            .remove_mapping(offset)
+            .map_err(|_| libc::EINVAL)
+    }
+}
+
+/// Direct linear mapping of sparse guest memory.
+///
+/// A re-mapping of sparse guest memory into an arena that is linear to the host.
+struct GuestMemoryMapping {
+    arena: MemoryMappingArena,
+    start_offset: usize,
+}
+
+impl GuestMemoryMapping {
+    fn new(mem: &GuestMemory, sgs: &[SgEntry]) -> anyhow::Result<Self> {
+        let page_size = base::pagesize() as u64;
+        let page_mask = page_size - 1;
+
+        // Validate the SGs.
+        //
+        // We can only map full pages and need to maintain a linear area. This means that the
+        // following invariants must be withheld:
+        //
+        // - For all entries but the first, the start offset within the page must be 0.
+        // - For all entries but the last, `start + len` must be a multiple of page size.
+        for sg in sgs.iter().skip(1) {
+            if sg.start & page_mask != 0 {
+                anyhow::bail!("non-initial SG entry start offset is not 0");
+            }
+        }
+        for sg in sgs.iter().take(sgs.len() - 1) {
+            if (sg.start + sg.len as u64) & page_mask != 0 {
+                anyhow::bail!("non-terminal SG entry with start + len != page_size");
+            }
+        }
+
+        // Compute the arena size.
+        let arena_size = sgs
+            .iter()
+            .fold(0, |size, sg| size + (sg.start & page_mask) + sg.len as u64)
+            // Align to page size if the last entry did not cover a full page.
+            .next_multiple_of(page_size);
+        let mut arena = MemoryMappingArena::new(arena_size as usize)?;
+
+        // Map all SG entries.
+        let mut pos = 0;
+        for region in sgs {
+            // Address of the first page of the region.
+            let region_first_page = region.start & !page_mask;
+            let len = region.start - region_first_page + region.len as u64;
+            // Make sure to map whole pages (only necessary for the last entry).
+            let len = len.next_multiple_of(page_size) as usize;
+            // TODO: find the offset from the region, this assumes a single
+            // region starting at address 0.
+            let fd = mem.offset_region(region_first_page)?;
+            // Always map whole pages
+            arena.add_fd_offset(pos, len, fd, region_first_page)?;
+
+            pos += len;
+        }
+
+        let start_offset = sgs
+            .first()
+            .map(|region| region.start & page_mask)
+            .unwrap_or(0) as usize;
+
+        Ok(GuestMemoryMapping {
+            arena,
+            start_offset,
+        })
+    }
+}
+
+impl GuestMemoryRange for GuestMemoryMapping {
+    fn as_ptr(&self) -> *const u8 {
+        // SAFETY: the arena has a valid pointer that covers `start_offset + len`.
+        unsafe { self.arena.as_ptr().add(self.start_offset) }
+    }
+
+    fn as_mut_ptr(&mut self) -> *mut u8 {
+        // SAFETY: the arena has a valid pointer that covers `start_offset + len`.
+        unsafe { self.arena.as_ptr().add(self.start_offset) }
+    }
+}
+
+/// Copy of sparse guest memory that is written back upon destruction.
+///
+/// Contrary to `GuestMemoryMapping` which re-maps guest memory to make it appear linear to the
+/// host, this copies the sparse guest memory into a linear vector that is copied back upon
+/// destruction. Doing so can be faster than a costly mapping operation if the guest area is small
+/// enough.
+struct GuestMemoryShadowMapping {
+    /// Sparse data copied from the guest.
+    data: Vec<u8>,
+    /// Guest memory to read from.
+    mem: GuestMemory,
+    /// SG entries describing the sparse guest area.
+    sgs: Vec<SgEntry>,
+    /// Whether the data has potentially been modified and requires to be written back to the
+    /// guest.
+    dirty: bool,
+}
+
+impl GuestMemoryShadowMapping {
+    fn new(mem: &GuestMemory, sgs: Vec<SgEntry>) -> anyhow::Result<Self> {
+        let total_size = sgs.iter().fold(0, |total, sg| total + sg.len as usize);
+        let mut data = vec![0u8; total_size];
+        let mut pos = 0;
+        for sg in &sgs {
+            mem.read_exact_at_addr(
+                &mut data[pos..pos + sg.len as usize],
+                GuestAddress(sg.start),
+            )?;
+            pos += sg.len as usize;
+        }
+
+        Ok(Self {
+            data,
+            mem: mem.clone(),
+            sgs,
+            dirty: false,
+        })
+    }
+}
+
+impl GuestMemoryRange for GuestMemoryShadowMapping {
+    fn as_ptr(&self) -> *const u8 {
+        self.data.as_ptr()
+    }
+
+    fn as_mut_ptr(&mut self) -> *mut u8 {
+        self.dirty = true;
+        self.data.as_mut_ptr()
+    }
+}
+
+/// Write the potentially modified shadow buffer back into the guest memory.
+impl Drop for GuestMemoryShadowMapping {
+    fn drop(&mut self) {
+        // No need to copy back if no modification has been done.
+        if !self.dirty {
+            return;
+        }
+
+        let mut pos = 0;
+        for sg in &self.sgs {
+            if let Err(e) = self.mem.write_all_at_addr(
+                &self.data[pos..pos + sg.len as usize],
+                GuestAddress(sg.start),
+            ) {
+                base::error!("failed to write back guest memory shadow mapping: {:#}", e);
+            }
+            pos += sg.len as usize;
+        }
+    }
+}
+
+/// A chunk of guest memory which can be either directly mapped, or copied into a shadow buffer.
+enum GuestMemoryChunk {
+    Mapping(GuestMemoryMapping),
+    Shadow(GuestMemoryShadowMapping),
+}
+
+impl GuestMemoryRange for GuestMemoryChunk {
+    fn as_ptr(&self) -> *const u8 {
+        match self {
+            GuestMemoryChunk::Mapping(m) => m.as_ptr(),
+            GuestMemoryChunk::Shadow(s) => s.as_ptr(),
+        }
+    }
+
+    fn as_mut_ptr(&mut self) -> *mut u8 {
+        match self {
+            GuestMemoryChunk::Mapping(m) => m.as_mut_ptr(),
+            GuestMemoryChunk::Shadow(s) => s.as_mut_ptr(),
+        }
+    }
+}
+
+/// Newtype to implement `VirtioMediaGuestMemoryMapper` on `GuestMemory`.
+///
+/// Whether to use a direct mapping or to copy the guest data into a shadow buffer is decided by
+/// the size of the guest mapping. If it is below `MAPPING_THRESHOLD`, a shadow buffer is used ;
+/// otherwise the area is mapped.
+struct GuestMemoryMapper(GuestMemory);
+
+impl VirtioMediaGuestMemoryMapper for GuestMemoryMapper {
+    type GuestMemoryMapping = GuestMemoryChunk;
+
+    fn new_mapping(&self, sgs: Vec<SgEntry>) -> anyhow::Result<Self::GuestMemoryMapping> {
+        /// Threshold at which we perform a direct mapping of the guest memory into the host.
+        /// Anything below that is copied into a shadow buffer and synced back to the guest when
+        /// the memory chunk is destroyed.
+        const MAPPING_THRESHOLD: usize = 0x400;
+        let total_size = sgs.iter().fold(0, |total, sg| total + sg.len as usize);
+
+        if total_size >= MAPPING_THRESHOLD {
+            GuestMemoryMapping::new(&self.0, &sgs).map(GuestMemoryChunk::Mapping)
+        } else {
+            GuestMemoryShadowMapping::new(&self.0, sgs).map(GuestMemoryChunk::Shadow)
+        }
+    }
+}
+
+#[derive(EventToken, Debug)]
+enum Token {
+    CommandQueue,
+    V4l2Session(u32),
+    Kill,
+    InterruptResample,
+}
+
+/// Newtype to implement `SessionPoller` on `Rc<WaitContext<Token>>`.
+#[derive(Clone)]
+struct WaitContextPoller(Rc<WaitContext<Token>>);
+
+impl SessionPoller for WaitContextPoller {
+    fn add_session(&self, session: BorrowedFd, session_id: u32) -> Result<(), i32> {
+        self.0
+            .add_for_event(
+                &Descriptor(session.as_raw_fd()),
+                EventType::Read,
+                Token::V4l2Session(session_id),
+            )
+            .map_err(|e| e.errno())
+    }
+
+    fn remove_session(&self, session: BorrowedFd) {
+        let _ = self.0.delete(&Descriptor(session.as_raw_fd()));
+    }
+}
+
+/// Worker to operate a virtio-media device inside a worker thread.
+struct Worker<D: VirtioMediaDevice<Reader, Writer>> {
+    runner: VirtioMediaDeviceRunner<Reader, Writer, D, WaitContextPoller>,
+    cmd_queue: (Queue, Interrupt),
+    wait_ctx: Rc<WaitContext<Token>>,
+}
+
+impl<D> Worker<D>
+where
+    D: VirtioMediaDevice<Reader, Writer>,
+{
+    /// Create a new worker instance for `device`.
+    fn new(
+        device: D,
+        cmd_queue: Queue,
+        cmd_interrupt: Interrupt,
+        kill_evt: Event,
+        wait_ctx: Rc<WaitContext<Token>>,
+    ) -> anyhow::Result<Self> {
+        wait_ctx
+            .add_many(&[
+                (cmd_queue.event(), Token::CommandQueue),
+                (&kill_evt, Token::Kill),
+            ])
+            .context("when adding worker events to wait context")?;
+
+        Ok(Self {
+            runner: VirtioMediaDeviceRunner::new(device, WaitContextPoller(Rc::clone(&wait_ctx))),
+            cmd_queue: (cmd_queue, cmd_interrupt),
+            wait_ctx,
+        })
+    }
+
+    fn run(&mut self) -> anyhow::Result<()> {
+        if let Some(resample_evt) = self.cmd_queue.1.get_resample_evt() {
+            self.wait_ctx
+                .add(resample_evt, Token::InterruptResample)
+                .context("failed adding resample event to WaitContext.")?;
+        }
+
+        loop {
+            let wait_events = self.wait_ctx.wait().context("Wait error")?;
+
+            for wait_event in wait_events.iter() {
+                match wait_event.token {
+                    Token::CommandQueue => {
+                        let _ = self.cmd_queue.0.event().wait();
+                        while let Some(mut desc) = self.cmd_queue.0.pop() {
+                            self.runner
+                                .handle_command(&mut desc.reader, &mut desc.writer);
+                            // Return the descriptor to the guest.
+                            let written = desc.writer.bytes_written() as u32;
+                            self.cmd_queue.0.add_used(desc, written);
+                            self.cmd_queue.0.trigger_interrupt();
+                        }
+                    }
+                    Token::Kill => {
+                        return Ok(());
+                    }
+                    Token::V4l2Session(session_id) => {
+                        let session = match self.runner.sessions.get_mut(&session_id) {
+                            Some(session) => session,
+                            None => {
+                                base::error!(
+                                    "received event for non-registered session {}",
+                                    session_id
+                                );
+                                continue;
+                            }
+                        };
+
+                        if let Err(e) = self.runner.device.process_events(session) {
+                            base::error!(
+                                "error while processing events for session {}: {:#}",
+                                session_id,
+                                e
+                            );
+                            if let Some(session) = self.runner.sessions.remove(&session_id) {
+                                self.runner.device.close_session(session);
+                            }
+                        }
+                    }
+                    Token::InterruptResample => {
+                        self.cmd_queue.1.interrupt_resample();
+                    }
+                }
+            }
+        }
+    }
+}
+
+/// Implements the required traits to operate a [`VirtioMediaDevice`] under crosvm.
+struct CrosvmVirtioMediaDevice<
+    D: VirtioMediaDevice<Reader, Writer>,
+    F: Fn(EventQueue, GuestMemoryMapper, HostMemoryMapper<ArcedMemoryMapper>) -> anyhow::Result<D>,
+> {
+    /// Closure to create the device once all its resources are acquired.
+    create_device: F,
+    /// Virtio configuration area.
+    config: VirtioMediaDeviceConfig,
+
+    /// Virtio device features.
+    base_features: u64,
+    /// Mapper to make host video buffers visible to the guest.
+    ///
+    /// We unfortunately need to put it behind a `Arc` because the mapper is only passed once,
+    /// whereas the device can be activated several times, so we need to keep a reference to it
+    /// even after it is passed to the device.
+    shm_mapper: Option<ArcedMemoryMapper>,
+    /// Worker thread for the device.
+    worker_thread: Option<WorkerThread<()>>,
+}
+
+impl<D, F> CrosvmVirtioMediaDevice<D, F>
+where
+    D: VirtioMediaDevice<Reader, Writer>,
+    F: Fn(EventQueue, GuestMemoryMapper, HostMemoryMapper<ArcedMemoryMapper>) -> anyhow::Result<D>,
+{
+    fn new(base_features: u64, config: VirtioMediaDeviceConfig, create_device: F) -> Self {
+        Self {
+            base_features,
+            config,
+            shm_mapper: None,
+            create_device,
+            worker_thread: None,
+        }
+    }
+}
+
+const HOST_MAPPER_RANGE: u64 = 1 << 32;
+
+impl<D, F> VirtioDevice for CrosvmVirtioMediaDevice<D, F>
+where
+    D: VirtioMediaDevice<Reader, Writer> + Send + 'static,
+    F: Fn(EventQueue, GuestMemoryMapper, HostMemoryMapper<ArcedMemoryMapper>) -> anyhow::Result<D>
+        + Send,
+{
+    fn keep_rds(&self) -> Vec<base::RawDescriptor> {
+        let mut keep_rds = Vec::new();
+
+        if let Some(fd) = self.shm_mapper.as_ref().and_then(|m| m.as_raw_descriptor()) {
+            keep_rds.push(fd);
+        }
+
+        keep_rds
+    }
+
+    fn device_type(&self) -> DeviceType {
+        DeviceType::Media
+    }
+
+    fn queue_max_sizes(&self) -> &[u16] {
+        QUEUE_SIZES
+    }
+
+    fn features(&self) -> u64 {
+        self.base_features
+    }
+
+    fn read_config(&self, offset: u64, data: &mut [u8]) {
+        copy_config(data, 0, self.config.as_ref(), offset);
+    }
+
+    fn activate(
+        &mut self,
+        mem: vm_memory::GuestMemory,
+        interrupt: Interrupt,
+        mut queues: BTreeMap<usize, Queue>,
+    ) -> anyhow::Result<()> {
+        if queues.len() != QUEUE_SIZES.len() {
+            anyhow::bail!(
+                "wrong number of queues are passed: expected {}, actual {}",
+                queues.len(),
+                QUEUE_SIZES.len()
+            );
+        }
+
+        let cmd_queue = queues.remove(&0).context("missing queue 0")?;
+        let event_queue = EventQueue(queues.remove(&1).context("missing queue 1")?);
+
+        let shm_mapper = self
+            .shm_mapper
+            .clone()
+            .take()
+            .context("shared memory mapper was not specified")?;
+
+        let wait_ctx = WaitContext::new()?;
+        let device = (self.create_device)(
+            event_queue,
+            GuestMemoryMapper(mem),
+            HostMemoryMapper {
+                shm_mapper,
+                allocator: AddressAllocator::new(
+                    AddressRange::from_start_and_end(0, HOST_MAPPER_RANGE - 1),
+                    Some(base::pagesize() as u64),
+                    None,
+                )?,
+            },
+        )?;
+
+        let worker_thread = WorkerThread::start("v_media_worker", move |e| {
+            let wait_ctx = Rc::new(wait_ctx);
+            let mut worker = match Worker::new(device, cmd_queue, interrupt, e, wait_ctx) {
+                Ok(worker) => worker,
+                Err(e) => {
+                    error!("failed to create virtio-media worker: {:#}", e);
+                    return;
+                }
+            };
+            if let Err(e) = worker.run() {
+                error!("virtio_media worker exited with error: {:#}", e);
+            }
+        });
+
+        self.worker_thread = Some(worker_thread);
+        Ok(())
+    }
+
+    fn reset(&mut self) -> anyhow::Result<()> {
+        if let Some(worker_thread) = self.worker_thread.take() {
+            worker_thread.stop();
+        }
+
+        Ok(())
+    }
+
+    fn get_shared_memory_region(&self) -> Option<SharedMemoryRegion> {
+        Some(SharedMemoryRegion {
+            id: 0,
+            // We need a 32-bit address space as m2m devices start their CAPTURE buffers' offsets
+            // at 2GB.
+            length: HOST_MAPPER_RANGE,
+        })
+    }
+
+    fn set_shared_memory_mapper(&mut self, mapper: Box<dyn SharedMemoryMapper>) {
+        self.shm_mapper = Some(ArcedMemoryMapper::from(mapper));
+    }
+}
+
+/// Create a simple media capture device.
+///
+/// This device can only generate a fixed pattern at a fixed resolution, and should only be used
+/// for checking that the virtio-media pipeline is working properly.
+pub fn create_virtio_media_simple_capture_device(features: u64) -> Box<dyn VirtioDevice> {
+    use virtio_media::devices::SimpleCaptureDevice;
+    use virtio_media::v4l2r::ioctl::Capabilities;
+
+    let mut card = [0u8; 32];
+    let card_name = "simple_device";
+    card[0..card_name.len()].copy_from_slice(card_name.as_bytes());
+
+    let device = CrosvmVirtioMediaDevice::new(
+        features,
+        VirtioMediaDeviceConfig {
+            device_caps: (Capabilities::VIDEO_CAPTURE | Capabilities::STREAMING).bits(),
+            // VFL_TYPE_VIDEO
+            device_type: 0,
+            card,
+        },
+        |event_queue, _, host_mapper| Ok(SimpleCaptureDevice::new(event_queue, host_mapper)),
+    );
+
+    Box::new(device)
+}
+
+/// Create a proxy device for a host V4L2 device.
+///
+/// Since V4L2 is a Linux-specific API, this is only available on Linux targets.
+#[cfg(any(target_os = "android", target_os = "linux"))]
+pub fn create_virtio_media_v4l2_proxy_device<P: AsRef<Path>>(
+    features: u64,
+    device_path: P,
+) -> anyhow::Result<Box<dyn VirtioDevice>> {
+    use virtio_media::devices::V4l2ProxyDevice;
+    use virtio_media::v4l2r;
+    use virtio_media::v4l2r::ioctl::Capabilities;
+
+    let device = v4l2r::device::Device::open(
+        device_path.as_ref(),
+        v4l2r::device::DeviceConfig::new().non_blocking_dqbuf(),
+    )?;
+    let mut device_caps = device.caps().device_caps();
+
+    // We are only exposing one device worth of capabilities.
+    device_caps.remove(Capabilities::DEVICE_CAPS);
+
+    // Read-write is not supported by design.
+    device_caps.remove(Capabilities::READWRITE);
+
+    let mut config = VirtioMediaDeviceConfig {
+        device_caps: device_caps.bits(),
+        // VFL_TYPE_VIDEO
+        device_type: 0,
+        card: Default::default(),
+    };
+    let card = &device.caps().card;
+    let name_slice = card[0..std::cmp::min(card.len(), config.card.len())].as_bytes();
+    config.card.as_mut_slice()[0..name_slice.len()].copy_from_slice(name_slice);
+    let device_path = PathBuf::from(device_path.as_ref());
+
+    let device = CrosvmVirtioMediaDevice::new(
+        features,
+        config,
+        move |event_queue, guest_mapper, host_mapper| {
+            let device =
+                V4l2ProxyDevice::new(device_path.clone(), event_queue, guest_mapper, host_mapper);
+
+            Ok(device)
+        },
+    );
+
+    Ok(Box::new(device))
+}
diff --git a/devices/src/virtio/mod.rs b/devices/src/virtio/mod.rs
index e159e3910..894b362f4 100644
--- a/devices/src/virtio/mod.rs
+++ b/devices/src/virtio/mod.rs
@@ -32,6 +32,8 @@ pub mod block;
 pub mod console;
 #[cfg(feature = "gpu")]
 pub mod gpu;
+#[cfg(all(unix, feature = "media"))]
+pub mod media;
 pub mod resource_bridge;
 pub mod scsi;
 #[cfg(feature = "audio")]
@@ -184,6 +186,7 @@ pub enum DeviceType {
     Wl = virtio_ids::VIRTIO_ID_WL,
     Tpm = virtio_ids::VIRTIO_ID_TPM,
     Pvclock = virtio_ids::VIRTIO_ID_PVCLOCK,
+    Media = virtio_ids::VIRTIO_ID_MEDIA,
 }
 
 impl DeviceType {
@@ -214,6 +217,7 @@ impl DeviceType {
             DeviceType::Wl => 2,            // in, out
             DeviceType::Tpm => 1,           // request queue
             DeviceType::Pvclock => 1,       // request queue
+            DeviceType::Media => 2,         // commandq, eventq
         }
     }
 }
@@ -243,6 +247,7 @@ impl std::fmt::Display for DeviceType {
             DeviceType::VideoEncoder => write!(f, "video-encoder"),
             DeviceType::Mac80211HwSim => write!(f, "mac80211-hwsim"),
             DeviceType::Scmi => write!(f, "scmi"),
+            DeviceType::Media => write!(f, "media"),
         }
     }
 }
diff --git a/devices/src/virtio/queue/packed_queue.rs b/devices/src/virtio/queue/packed_queue.rs
index b8a5aa9c8..842c17873 100644
--- a/devices/src/virtio/queue/packed_queue.rs
+++ b/devices/src/virtio/queue/packed_queue.rs
@@ -266,9 +266,8 @@ impl PackedQueue {
         let desc = self
             .mem
             .read_obj_from_addr::<PackedDesc>(desc_addr)
-            .map_err(|e| {
+            .inspect_err(|_e| {
                 error!("failed to read desc {:#x}", desc_addr.offset());
-                e
             })
             .ok()?;
 
diff --git a/devices/src/virtio/snd/vios_backend/shm_streams.rs b/devices/src/virtio/snd/vios_backend/shm_streams.rs
index 7d8d47562..f45f96c89 100644
--- a/devices/src/virtio/snd/vios_backend/shm_streams.rs
+++ b/devices/src/virtio/snd/vios_backend/shm_streams.rs
@@ -167,11 +167,10 @@ impl ShmStreamSource<base::Error> for VioSShmStreamSource {
                 client_shm,
                 buffer_offsets,
             )
-            .map_err(|e| {
+            .inspect_err(|_e| {
                 // Attempt to release the stream so that it can be used later. This is a best effort
                 // attempt, so we ignore any error it may return.
                 let _ = self.vios_client.lock().release_stream(stream_id);
-                e
             })?;
         *self.stream_descs[stream_id as usize].state.lock() = StreamState::Acquired;
         Ok(stream)
diff --git a/devices/src/virtio/vhost/user/device/block/sys/linux.rs b/devices/src/virtio/vhost/user/device/block/sys/linux.rs
index 77dd55ee2..8569ce9f0 100644
--- a/devices/src/virtio/vhost/user/device/block/sys/linux.rs
+++ b/devices/src/virtio/vhost/user/device/block/sys/linux.rs
@@ -4,26 +4,34 @@
 
 use anyhow::Context;
 use argh::FromArgs;
-use base::info;
+use base::RawDescriptor;
 use cros_async::Executor;
 use hypervisor::ProtectionType;
 
 use crate::virtio::base_features;
 use crate::virtio::block::DiskOption;
-use crate::virtio::vhost::user::device::connection::sys::VhostUserListener;
-use crate::virtio::vhost::user::device::connection::VhostUserConnectionTrait;
+use crate::virtio::vhost::user::device::BackendConnection;
 use crate::virtio::BlockAsync;
 
 #[derive(FromArgs)]
 #[argh(subcommand, name = "block")]
 /// Block device
 pub struct Options {
+    #[argh(option, arg_name = "PATH", hidden_help)]
+    /// deprecated - please use --socket-path instead
+    socket: Option<String>,
+    #[argh(option, arg_name = "PATH")]
+    /// path to the vhost-user socket to bind to.
+    /// If this flag is set, --fd cannot be specified.
+    socket_path: Option<String>,
+    #[argh(option, arg_name = "FD")]
+    /// file descriptor of a connected vhost-user socket.
+    /// If this flag is set, --socket-path cannot be specified.
+    fd: Option<RawDescriptor>,
+
     #[argh(option, arg_name = "PATH<:read-only>")]
     /// path and options of the disk file.
     file: String,
-    #[argh(option, arg_name = "PATH")]
-    /// path to a vhost-user socket
-    socket: String,
 }
 
 /// Starts a vhost-user block device.
@@ -50,8 +58,8 @@ pub fn start_device(opts: Options) -> anyhow::Result<()> {
         None,
     )?);
 
-    let listener = VhostUserListener::new(&opts.socket)?;
-    info!("vhost-user disk device ready, starting run loop...");
+    let conn =
+        BackendConnection::from_opts(opts.socket.as_deref(), opts.socket_path.as_deref(), opts.fd)?;
 
-    listener.run_device(ex, block)
+    conn.run_device(ex, block)
 }
diff --git a/devices/src/virtio/vhost/user/device/connection.rs b/devices/src/virtio/vhost/user/device/connection.rs
index 620f51518..54a7fa4f0 100644
--- a/devices/src/virtio/vhost/user/device/connection.rs
+++ b/devices/src/virtio/vhost/user/device/connection.rs
@@ -12,6 +12,13 @@ use futures::Future;
 use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
 use crate::virtio::vhost::user::device::handler::VhostUserDevice;
 use crate::virtio::vhost::user::VhostUserDeviceBuilder;
+use crate::virtio::vhost::user::VhostUserListener;
+use crate::virtio::vhost::user::VhostUserStream;
+
+pub enum BackendConnection {
+    Listener(VhostUserListener),
+    Stream(VhostUserStream),
+}
 
 /// Trait that the platform-specific type `VhostUserConnection` needs to implement. It contains all
 /// the methods that are ok to call from non-platform specific code.
diff --git a/devices/src/virtio/vhost/user/device/connection/sys/linux.rs b/devices/src/virtio/vhost/user/device/connection/sys/linux.rs
index 1fe06ab8b..0f4a19805 100644
--- a/devices/src/virtio/vhost/user/device/connection/sys/linux.rs
+++ b/devices/src/virtio/vhost/user/device/connection/sys/linux.rs
@@ -5,5 +5,80 @@
 mod listener;
 mod stream;
 
+use std::future::Future;
+use std::pin::Pin;
+
+use anyhow::bail;
+use anyhow::Result;
+use base::warn;
+use base::AsRawDescriptor;
+use base::RawDescriptor;
+use cros_async::Executor;
 pub use listener::VhostUserListener;
 pub use stream::VhostUserStream;
+
+use crate::virtio::vhost::user::device::BackendConnection;
+use crate::virtio::vhost::user::VhostUserConnectionTrait;
+use crate::virtio::vhost::user::VhostUserDevice;
+use crate::virtio::vhost::user::VhostUserDeviceBuilder;
+
+impl BackendConnection {
+    pub fn from_opts(
+        socket: Option<&str>,
+        socket_path: Option<&str>,
+        fd: Option<RawDescriptor>,
+    ) -> Result<BackendConnection> {
+        let socket_path = if let Some(socket_path) = socket_path {
+            Some(socket_path)
+        } else if let Some(socket) = socket {
+            warn!("--socket is deprecated; please use --socket-path instead");
+            Some(socket)
+        } else {
+            None
+        };
+
+        match (socket_path, fd) {
+            (Some(socket), None) => {
+                let listener = VhostUserListener::new(socket)?;
+                Ok(BackendConnection::Listener(listener))
+            }
+            (None, Some(fd)) => {
+                let stream = VhostUserStream::new_socket_from_fd(fd)?;
+                Ok(BackendConnection::Stream(stream))
+            }
+            (Some(_), Some(_)) => bail!("Cannot specify both a socket path and a file descriptor"),
+            (None, None) => bail!("Must specify either a socket or a file descriptor"),
+        }
+    }
+
+    pub fn run_device(
+        self,
+        ex: Executor,
+        device: Box<dyn VhostUserDeviceBuilder>,
+    ) -> anyhow::Result<()> {
+        match self {
+            BackendConnection::Listener(listener) => listener.run_device(ex, device),
+            BackendConnection::Stream(stream) => stream.run_device(ex, device),
+        }
+    }
+
+    pub fn run_backend<'e>(
+        self,
+        backend: impl VhostUserDevice + 'static,
+        ex: &'e Executor,
+    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'e>> {
+        match self {
+            BackendConnection::Listener(listener) => listener.run_backend(backend, ex),
+            BackendConnection::Stream(stream) => stream.run_backend(backend, ex),
+        }
+    }
+}
+
+impl AsRawDescriptor for BackendConnection {
+    fn as_raw_descriptor(&self) -> RawDescriptor {
+        match self {
+            BackendConnection::Listener(listener) => listener.as_raw_descriptor(),
+            BackendConnection::Stream(stream) => stream.as_raw_descriptor(),
+        }
+    }
+}
diff --git a/devices/src/virtio/vhost/user/device/connection/sys/linux/stream.rs b/devices/src/virtio/vhost/user/device/connection/sys/linux/stream.rs
index 31efd5d78..f3b008562 100644
--- a/devices/src/virtio/vhost/user/device/connection/sys/linux/stream.rs
+++ b/devices/src/virtio/vhost/user/device/connection/sys/linux/stream.rs
@@ -35,18 +35,12 @@ fn path_is_socket(path: &Path) -> bool {
 impl VhostUserStream {
     /// Creates a new vhost-user listener from an existing connected socket file descriptor.
     ///
-    /// `keep_rds` can be specified to retrieve the raw descriptor that must be preserved for this
-    /// listener to keep working after forking.
-    ///
     /// # Errors
     ///
     /// Returns an error if:
     /// - The provided file descriptor is not a socket.
     /// - An error occurs while creating the underlying `SocketListener`.
-    pub fn new_socket_from_fd(
-        socket_fd: RawDescriptor,
-        keep_rds: Option<&mut Vec<RawDescriptor>>,
-    ) -> anyhow::Result<Self> {
+    pub fn new_socket_from_fd(socket_fd: RawDescriptor) -> anyhow::Result<Self> {
         let path = PathBuf::from(format!("/proc/self/fd/{}", socket_fd));
         if !path_is_socket(&path) {
             return Err(SocketFromFdError(path).into());
@@ -54,10 +48,6 @@ impl VhostUserStream {
 
         let safe_fd = safe_descriptor_from_cmdline_fd(&socket_fd)?;
 
-        if let Some(rds) = keep_rds {
-            rds.push(safe_fd.as_raw_descriptor());
-        }
-
         let stream = UnixStream::from(safe_fd);
 
         Ok(VhostUserStream(stream))
@@ -74,6 +64,12 @@ impl VhostUserConnectionTrait for VhostUserStream {
     }
 }
 
+impl AsRawDescriptor for VhostUserStream {
+    fn as_raw_descriptor(&self) -> RawDescriptor {
+        self.0.as_raw_descriptor()
+    }
+}
+
 async fn stream_run_with_handler(
     stream: UnixStream,
     handler: Box<dyn vmm_vhost::Backend>,
diff --git a/devices/src/virtio/vhost/user/device/console.rs b/devices/src/virtio/vhost/user/device/console.rs
index ebc7a75d4..9f8613d85 100644
--- a/devices/src/virtio/vhost/user/device/console.rs
+++ b/devices/src/virtio/vhost/user/device/console.rs
@@ -21,10 +21,9 @@ use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;
 use crate::virtio::console::device::ConsoleDevice;
 use crate::virtio::console::device::ConsoleSnapshot;
 use crate::virtio::console::port::ConsolePort;
-use crate::virtio::vhost::user::device::connection::sys::VhostUserListener;
-use crate::virtio::vhost::user::device::connection::VhostUserConnectionTrait;
 use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
 use crate::virtio::vhost::user::device::handler::VhostUserDevice;
+use crate::virtio::vhost::user::device::BackendConnection;
 use crate::virtio::vhost::user::device::VhostUserDeviceBuilder;
 use crate::virtio::Queue;
 use crate::SerialHardware;
@@ -130,9 +129,18 @@ impl VhostUserDevice for ConsoleBackend {
 #[argh(subcommand, name = "console")]
 /// Console device
 pub struct Options {
+    #[argh(option, arg_name = "PATH", hidden_help)]
+    /// deprecated - please use --socket-path instead
+    socket: Option<String>,
     #[argh(option, arg_name = "PATH")]
-    /// path to a vhost-user socket
-    socket: String,
+    /// path to the vhost-user socket to bind to.
+    /// If this flag is set, --fd cannot be specified.
+    socket_path: Option<String>,
+    #[argh(option, arg_name = "FD")]
+    /// file descriptor of a connected vhost-user socket.
+    /// If this flag is set, --socket-path cannot be specified.
+    fd: Option<RawDescriptor>,
+
     #[argh(option, arg_name = "OUTFILE")]
     /// path to a file
     output_file: Option<PathBuf>,
@@ -187,9 +195,9 @@ fn run_multi_port_device(opts: Options) -> anyhow::Result<()> {
     let device = Box::new(create_vu_multi_port_device(&opts.port, &mut Vec::new())?);
     let ex = Executor::new().context("Failed to create executor")?;
 
-    let listener = VhostUserListener::new(&opts.socket)?;
-
-    listener.run_device(ex, device)
+    let conn =
+        BackendConnection::from_opts(opts.socket.as_deref(), opts.socket_path.as_deref(), opts.fd)?;
+    conn.run_device(ex, device)
 }
 
 /// Return a new vhost-user console device. `params` are the device's configuration, and `keep_rds`
@@ -256,7 +264,8 @@ pub fn run_console_device(opts: Options) -> anyhow::Result<()> {
     let device = Box::new(create_vu_console_device(&params, &mut Vec::new())?);
     let ex = Executor::new().context("Failed to create executor")?;
 
-    let listener = VhostUserListener::new(&opts.socket)?;
+    let conn =
+        BackendConnection::from_opts(opts.socket.as_deref(), opts.socket_path.as_deref(), opts.fd)?;
 
-    listener.run_device(ex, device)
+    conn.run_device(ex, device)
 }
diff --git a/devices/src/virtio/vhost/user/device/fs.rs b/devices/src/virtio/vhost/user/device/fs.rs
index 8dc3ed42f..09d5a2f77 100644
--- a/devices/src/virtio/vhost/user/device/fs.rs
+++ b/devices/src/virtio/vhost/user/device/fs.rs
@@ -4,21 +4,16 @@
 
 mod sys;
 
-use std::cell::RefCell;
+use std::collections::BTreeMap;
 use std::path::PathBuf;
-use std::rc::Rc;
 use std::sync::Arc;
 
 use anyhow::bail;
-use anyhow::Context;
 use argh::FromArgs;
-use base::error;
 use base::warn;
-use base::AsRawDescriptors;
 use base::RawDescriptor;
 use base::Tube;
-use cros_async::EventAsync;
-use cros_async::Executor;
+use base::WorkerThread;
 use data_model::Le32;
 use fuse::Server;
 use hypervisor::ProtectionType;
@@ -34,47 +29,31 @@ use crate::virtio;
 use crate::virtio::copy_config;
 use crate::virtio::device_constants::fs::FS_MAX_TAG_LEN;
 use crate::virtio::fs::passthrough::PassthroughFs;
-use crate::virtio::fs::process_fs_queue;
 use crate::virtio::fs::Config;
+use crate::virtio::fs::Result as FsResult;
+use crate::virtio::fs::Worker;
 use crate::virtio::vhost::user::device::handler::Error as DeviceError;
 use crate::virtio::vhost::user::device::handler::VhostUserDevice;
-use crate::virtio::vhost::user::device::handler::WorkerState;
 use crate::virtio::Queue;
 
 const MAX_QUEUE_NUM: usize = 2; /* worker queue and high priority queue */
 
-async fn handle_fs_queue(
-    queue: Rc<RefCell<virtio::Queue>>,
-    kick_evt: EventAsync,
-    server: Arc<fuse::Server<PassthroughFs>>,
-    tube: Arc<Mutex<Tube>>,
-) {
-    // Slot is always going to be 0 because we do not support DAX
-    let slot: u32 = 0;
-
-    loop {
-        if let Err(e) = kick_evt.next_val().await {
-            error!("Failed to read kick event for fs queue: {}", e);
-            break;
-        }
-        if let Err(e) = process_fs_queue(&mut queue.borrow_mut(), &server, &tube, slot) {
-            error!("Process FS queue failed: {}", e);
-            break;
-        }
-    }
-}
-
 struct FsBackend {
-    ex: Executor,
     server: Arc<fuse::Server<PassthroughFs>>,
-    tag: [u8; FS_MAX_TAG_LEN],
+    tag: String,
     avail_features: u64,
-    workers: [Option<WorkerState<Rc<RefCell<Queue>>, ()>>; MAX_QUEUE_NUM],
+    workers: BTreeMap<usize, WorkerThread<FsResult<Queue>>>,
     keep_rds: Vec<RawDescriptor>,
 }
 
 impl FsBackend {
-    pub fn new(ex: &Executor, tag: &str, cfg: Option<Config>) -> anyhow::Result<Self> {
+    #[allow(unused_variables)]
+    pub fn new(
+        tag: &str,
+        shared_dir: &str,
+        skip_pivot_root: bool,
+        cfg: Option<Config>,
+    ) -> anyhow::Result<Self> {
         if tag.len() > FS_MAX_TAG_LEN {
             bail!(
                 "fs tag is too long: {} (max supported: {})",
@@ -82,27 +61,26 @@ impl FsBackend {
                 FS_MAX_TAG_LEN
             );
         }
-        let mut fs_tag = [0u8; FS_MAX_TAG_LEN];
-        fs_tag[..tag.len()].copy_from_slice(tag.as_bytes());
 
         let avail_features = virtio::base_features(ProtectionType::Unprotected)
             | 1 << VHOST_USER_F_PROTOCOL_FEATURES;
 
         // Use default passthroughfs config
-        let fs = PassthroughFs::new(tag, cfg.unwrap_or_default())?;
+        #[allow(unused_mut)]
+        let mut fs = PassthroughFs::new(tag, cfg.unwrap_or_default())?;
+        #[cfg(feature = "fs_runtime_ugid_map")]
+        if skip_pivot_root {
+            fs.set_root_dir(shared_dir.to_string())?;
+        }
 
         let mut keep_rds: Vec<RawDescriptor> = [0, 1, 2].to_vec();
         keep_rds.append(&mut fs.keep_rds());
 
-        let ex = ex.clone();
-        keep_rds.extend(ex.as_raw_descriptors());
-
         let server = Arc::new(Server::new(fs));
 
         Ok(FsBackend {
-            ex,
             server,
-            tag: fs_tag,
+            tag: tag.to_owned(),
             avail_features,
             workers: Default::default(),
             keep_rds,
@@ -124,16 +102,17 @@ impl VhostUserDevice for FsBackend {
     }
 
     fn read_config(&self, offset: u64, data: &mut [u8]) {
-        let config = virtio_fs_config {
-            tag: self.tag,
+        let mut config = virtio_fs_config {
+            tag: [0; FS_MAX_TAG_LEN],
             num_request_queues: Le32::from(1),
         };
+        config.tag[..self.tag.len()].copy_from_slice(self.tag.as_bytes());
         copy_config(data, 0, config.as_bytes(), offset);
     }
 
     fn reset(&mut self) {
-        for worker in self.workers.iter_mut().filter_map(Option::take) {
-            let _ = self.ex.run_until(worker.queue_task.cancel());
+        for worker in std::mem::take(&mut self.workers).into_values() {
+            let _ = worker.stop();
         }
     }
 
@@ -143,38 +122,34 @@ impl VhostUserDevice for FsBackend {
         queue: virtio::Queue,
         _mem: GuestMemory,
     ) -> anyhow::Result<()> {
-        if self.workers[idx].is_some() {
+        if self.workers.contains_key(&idx) {
             warn!("Starting new queue handler without stopping old handler");
             self.stop_queue(idx)?;
         }
 
-        let kick_evt = queue
-            .event()
-            .try_clone()
-            .context("failed to clone queue event")?;
-        let kick_evt = EventAsync::new(kick_evt, &self.ex)
-            .context("failed to create EventAsync for kick_evt")?;
         let (_, fs_device_tube) = Tube::pair()?;
+        let tube = Arc::new(Mutex::new(fs_device_tube));
+
+        let server = self.server.clone();
+        let irq = queue.interrupt().clone();
+
+        // Slot is always going to be 0 because we do not support DAX
+        let slot: u32 = 0;
 
-        let queue = Rc::new(RefCell::new(queue));
-        let queue_task = self.ex.spawn_local(handle_fs_queue(
-            queue.clone(),
-            kick_evt,
-            self.server.clone(),
-            Arc::new(Mutex::new(fs_device_tube)),
-        ));
+        let worker = WorkerThread::start(format!("v_fs:{}:{}", self.tag, idx), move |kill_evt| {
+            let mut worker = Worker::new(queue, server, irq, tube, slot);
+            worker.run(kill_evt, false)?;
+            Ok(worker.queue)
+        });
+        self.workers.insert(idx, worker);
 
-        self.workers[idx] = Some(WorkerState { queue_task, queue });
         Ok(())
     }
 
     fn stop_queue(&mut self, idx: usize) -> anyhow::Result<virtio::Queue> {
-        if let Some(worker) = self.workers.get_mut(idx).and_then(Option::take) {
-            // Wait for queue_task to be aborted.
-            let _ = self.ex.run_until(worker.queue_task.cancel());
-
-            let queue = match Rc::try_unwrap(worker.queue) {
-                Ok(queue_cell) => queue_cell.into_inner(),
+        if let Some(worker) = self.workers.remove(&idx) {
+            let queue = match worker.stop() {
+                Ok(queue) => queue,
                 Err(_) => panic!("failed to recover queue from worker"),
             };
 
@@ -202,15 +177,18 @@ impl VhostUserDevice for FsBackend {
 #[argh(subcommand, name = "fs")]
 /// FS Device
 pub struct Options {
+    #[argh(option, arg_name = "PATH", hidden_help)]
+    /// deprecated - please use --socket-path instead
+    socket: Option<String>,
     #[argh(option, arg_name = "PATH")]
-    /// the UDS path to a vhost-user socket.
+    /// path to the vhost-user socket to bind to.
     /// If this flag is set, --fd cannot be specified.
-    socket: Option<String>,
-    #[cfg(unix)]
+    socket_path: Option<String>,
     #[argh(option, arg_name = "FD")]
     /// file descriptor of a connected vhost-user socket.
-    /// If this flag is set, --socket cannot be specified.
-    fd: Option<i32>,
+    /// If this flag is set, --socket-path cannot be specified.
+    fd: Option<RawDescriptor>,
+
     #[argh(option, arg_name = "TAG")]
     /// the virtio-fs tag
     tag: String,
@@ -254,4 +232,17 @@ pub struct Options {
     /// a new mount namespace and run without seccomp filter.
     /// Default: false.
     disable_sandbox: bool,
+    #[argh(option, arg_name = "skip_pivot_root", default = "false")]
+    /// disable pivot_root when process is jailed.
+    ///
+    /// virtio-fs typically uses mount namespaces and pivot_root for file system isolation,
+    /// making the jailed process's root directory "/".
+    ///
+    /// Android's security model restricts crosvm's access to certain system capabilities,
+    /// specifically those related to managing mount namespaces and using pivot_root.
+    /// These capabilities are typically associated with the SYS_ADMIN capability.
+    /// To maintain a secure environment, Android relies on mechanisms like SELinux to
+    /// enforce isolation and control access to directories.
+    #[allow(dead_code)]
+    skip_pivot_root: bool,
 }
diff --git a/devices/src/virtio/vhost/user/device/fs/sys/linux.rs b/devices/src/virtio/vhost/user/device/fs/sys/linux.rs
index 034eb143d..c9989b732 100644
--- a/devices/src/virtio/vhost/user/device/fs/sys/linux.rs
+++ b/devices/src/virtio/vhost/user/device/fs/sys/linux.rs
@@ -9,17 +9,17 @@ use anyhow::bail;
 use anyhow::Context;
 use base::linux::max_open_files;
 use base::AsRawDescriptor;
+use base::AsRawDescriptors;
 use base::RawDescriptor;
 use cros_async::Executor;
 use jail::create_base_minijail;
+use jail::create_base_minijail_without_pivot_root;
 use jail::set_embedded_bpf_program;
 use minijail::Minijail;
 
-use crate::virtio::vhost::user::device::connection::sys::VhostUserListener;
-use crate::virtio::vhost::user::device::connection::sys::VhostUserStream;
-use crate::virtio::vhost::user::device::connection::VhostUserConnectionTrait;
 use crate::virtio::vhost::user::device::fs::FsBackend;
 use crate::virtio::vhost::user::device::fs::Options;
+use crate::virtio::vhost::user::device::BackendConnection;
 
 fn default_uidmap() -> String {
     // SAFETY: trivially safe
@@ -42,13 +42,18 @@ fn jail_and_fork(
     uid_map: Option<String>,
     gid_map: Option<String>,
     disable_sandbox: bool,
+    pivot_root: bool,
 ) -> anyhow::Result<i32> {
     let limit = max_open_files()
         .context("failed to get max open files")?
         .rlim_max;
     // Create new minijail sandbox
     let jail = if disable_sandbox {
-        create_base_minijail(dir_path.as_path(), limit)?
+        if pivot_root {
+            create_base_minijail(dir_path.as_path(), limit)
+        } else {
+            create_base_minijail_without_pivot_root(dir_path.as_path(), limit)
+        }?
     } else {
         let mut j: Minijail = Minijail::new()?;
         j.namespace_pids();
@@ -109,30 +114,40 @@ fn jail_and_fork(
 
 /// Starts a vhost-user fs device.
 /// Returns an error if the given `args` is invalid or the device fails to run.
-pub fn start_device(opts: Options) -> anyhow::Result<()> {
+#[allow(unused_mut)]
+pub fn start_device(mut opts: Options) -> anyhow::Result<()> {
+    #[allow(unused_mut)]
+    let mut is_pivot_root_required = true;
+    #[cfg(feature = "fs_runtime_ugid_map")]
+    if let Some(ref mut cfg) = opts.cfg {
+        if !cfg.ugid_map.is_empty() && (!opts.disable_sandbox || !opts.skip_pivot_root) {
+            bail!("uid_gid_map can only be set with disable sandbox and skip_pivot_root option");
+        }
+
+        if opts.skip_pivot_root {
+            is_pivot_root_required = false;
+        }
+    }
     let ex = Executor::new().context("Failed to create executor")?;
-    let fs_device = FsBackend::new(&ex, &opts.tag, opts.cfg)?;
+    let fs_device = FsBackend::new(
+        &opts.tag,
+        opts.shared_dir
+            .to_str()
+            .expect("Failed to convert opts.shared_dir to str()"),
+        opts.skip_pivot_root,
+        opts.cfg,
+    )?;
 
     let mut keep_rds = fs_device.keep_rds.clone();
+    keep_rds.append(&mut ex.as_raw_descriptors());
 
-    let (listener, stream) = match (opts.socket, opts.fd) {
-        (Some(socket), None) => {
-            let listener = VhostUserListener::new(&socket)?;
-            keep_rds.push(listener.as_raw_descriptor());
-            (Some(listener), None)
-        }
-        (None, Some(fd)) => {
-            let stream = VhostUserStream::new_socket_from_fd(fd, Some(&mut keep_rds))?;
-            (None, Some(stream))
-        }
-        (Some(_), Some(_)) => bail!("Cannot specify both a socket path and a file descriptor"),
-        (None, None) => bail!("Must specify either a socket or a file descriptor"),
-    };
+    let conn =
+        BackendConnection::from_opts(opts.socket.as_deref(), opts.socket_path.as_deref(), opts.fd)?;
+    keep_rds.push(conn.as_raw_descriptor());
 
     base::syslog::push_descriptors(&mut keep_rds);
     cros_tracing::push_descriptors!(&mut keep_rds);
     metrics::push_descriptors(&mut keep_rds);
-
     let pid = jail_and_fork(
         keep_rds,
         opts.shared_dir,
@@ -141,6 +156,7 @@ pub fn start_device(opts: Options) -> anyhow::Result<()> {
         opts.uid_map,
         opts.gid_map,
         opts.disable_sandbox,
+        is_pivot_root_required,
     )?;
 
     // Parent, nothing to do but wait and then exit
@@ -150,34 +166,6 @@ pub fn start_device(opts: Options) -> anyhow::Result<()> {
         return Ok(());
     }
 
-    // TODO(crbug.com/1199487): Remove this once libc provides the wrapper for all targets.
-    #[cfg(target_os = "linux")]
-    {
-        // We need to set the no setuid fixup secure bit so that we don't drop capabilities when
-        // changing the thread uid/gid. Without this, creating new entries can fail in some corner
-        // cases.
-        const SECBIT_NO_SETUID_FIXUP: i32 = 1 << 2;
-
-        // SAFETY:
-        // Safe because this doesn't modify any memory and we check the return value.
-        let mut securebits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS) };
-        if securebits < 0 {
-            bail!(std::io::Error::last_os_error());
-        }
-        securebits |= SECBIT_NO_SETUID_FIXUP;
-        // SAFETY:
-        // Safe because this doesn't modify any memory and we check the return value.
-        let ret = unsafe { libc::prctl(libc::PR_SET_SECUREBITS, securebits) };
-        if ret < 0 {
-            bail!(std::io::Error::last_os_error());
-        }
-    }
-
-    if let Some(listener) = listener {
-        // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
-        ex.run_until(listener.run_backend(fs_device, &ex))?
-    } else {
-        let stream = stream.expect("if listener is none, the stream should be some");
-        ex.run_until(stream.run_backend(fs_device, &ex))?
-    }
+    // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
+    ex.run_until(conn.run_backend(fs_device, &ex))?
 }
diff --git a/devices/src/virtio/vhost/user/device/gpu.rs b/devices/src/virtio/vhost/user/device/gpu.rs
index aea86d5f0..074362233 100644
--- a/devices/src/virtio/vhost/user/device/gpu.rs
+++ b/devices/src/virtio/vhost/user/device/gpu.rs
@@ -17,6 +17,8 @@ use base::Tube;
 use cros_async::EventAsync;
 use cros_async::Executor;
 use cros_async::TaskHandle;
+use futures::FutureExt;
+use futures::StreamExt;
 use sync::Mutex;
 pub use sys::run_gpu_device;
 pub use sys::Options;
@@ -87,15 +89,21 @@ struct GpuBackend {
     state: Option<Rc<RefCell<gpu::Frontend>>>,
     fence_state: Arc<Mutex<gpu::FenceState>>,
     queue_workers: [Option<WorkerState<Arc<Mutex<Queue>>, ()>>; MAX_QUEUE_NUM],
-    platform_workers: Rc<RefCell<Vec<TaskHandle<()>>>>,
+    // In the downstream, we may add platform workers after start_platform_workers returns.
+    platform_worker_tx: futures::channel::mpsc::UnboundedSender<TaskHandle<()>>,
+    platform_worker_rx: futures::channel::mpsc::UnboundedReceiver<TaskHandle<()>>,
     shmem_mapper: Arc<Mutex<Option<Box<dyn SharedMemoryMapper>>>>,
 }
 
 impl GpuBackend {
     fn stop_non_queue_workers(&mut self) -> anyhow::Result<()> {
-        for handle in self.platform_workers.borrow_mut().drain(..) {
-            let _ = self.ex.run_until(handle.cancel());
-        }
+        self.ex
+            .run_until(async {
+                while let Some(Some(handle)) = self.platform_worker_rx.next().now_or_never() {
+                    handle.cancel().await;
+                }
+            })
+            .context("stopping the non-queue workers for GPU")?;
         Ok(())
     }
 }
diff --git a/devices/src/virtio/vhost/user/device/gpu/sys/linux.rs b/devices/src/virtio/vhost/user/device/gpu/sys/linux.rs
index b2356447e..f86d2078d 100644
--- a/devices/src/virtio/vhost/user/device/gpu/sys/linux.rs
+++ b/devices/src/virtio/vhost/user/device/gpu/sys/linux.rs
@@ -12,6 +12,7 @@ use anyhow::Context;
 use argh::FromArgs;
 use base::clone_descriptor;
 use base::error;
+use base::RawDescriptor;
 use base::SafeDescriptor;
 use base::Tube;
 use base::UnixSeqpacketListener;
@@ -25,10 +26,9 @@ use sync::Mutex;
 use crate::virtio;
 use crate::virtio::gpu;
 use crate::virtio::gpu::ProcessDisplayResult;
-use crate::virtio::vhost::user::device::connection::sys::VhostUserListener;
-use crate::virtio::vhost::user::device::connection::VhostUserConnectionTrait;
 use crate::virtio::vhost::user::device::gpu::GpuBackend;
 use crate::virtio::vhost::user::device::wl::parse_wayland_sock;
+use crate::virtio::vhost::user::device::BackendConnection;
 use crate::virtio::Gpu;
 use crate::virtio::GpuDisplayParameters;
 use crate::virtio::GpuParameters;
@@ -92,7 +92,9 @@ impl GpuBackend {
             let task = self
                 .ex
                 .spawn_local(run_resource_bridge(tube, state.clone()));
-            self.platform_workers.borrow_mut().push(task);
+            self.platform_worker_tx
+                .unbounded_send(task)
+                .context("sending the run_resource_bridge task")?;
         }
 
         // Start handling the display.
@@ -106,7 +108,9 @@ impl GpuBackend {
             })?;
 
         let task = self.ex.spawn_local(run_display(display, state));
-        self.platform_workers.borrow_mut().push(task);
+        self.platform_worker_tx
+            .unbounded_send(task)
+            .context("sending the run_display task")?;
 
         Ok(())
     }
@@ -119,9 +123,18 @@ fn gpu_parameters_from_str(input: &str) -> Result<GpuParameters, String> {
 /// GPU device
 #[argh(subcommand, name = "gpu")]
 pub struct Options {
+    #[argh(option, arg_name = "PATH", hidden_help)]
+    /// deprecated - please use --socket-path instead
+    socket: Option<String>,
     #[argh(option, arg_name = "PATH")]
-    /// path to bind a listening vhost-user socket
-    socket: String,
+    /// path to the vhost-user socket to bind to.
+    /// If this flag is set, --fd cannot be specified.
+    socket_path: Option<String>,
+    #[argh(option, arg_name = "FD")]
+    /// file descriptor of a connected vhost-user socket.
+    /// If this flag is set, --socket-path cannot be specified.
+    fd: Option<RawDescriptor>,
+
     #[argh(option, from_str_fn(parse_wayland_sock), arg_name = "PATH[,name=NAME]")]
     /// path to one or more Wayland sockets. The unnamed socket is
     /// used for displaying virtual screens while the named ones are used for IPC
@@ -149,6 +162,8 @@ pub fn run_gpu_device(opts: Options) -> anyhow::Result<()> {
         params: mut gpu_parameters,
         resource_bridge,
         socket,
+        socket_path,
+        fd,
         wayland_sock,
     } = opts;
 
@@ -220,7 +235,7 @@ pub fn run_gpu_device(opts: Options) -> anyhow::Result<()> {
 
     let base_features = virtio::base_features(ProtectionType::Unprotected);
 
-    let listener = VhostUserListener::new(&socket)?;
+    let conn = BackendConnection::from_opts(socket.as_deref(), socket_path.as_deref(), fd)?;
 
     let gpu = Rc::new(RefCell::new(Gpu::new(
         exit_evt_wrtube,
@@ -237,6 +252,7 @@ pub fn run_gpu_device(opts: Options) -> anyhow::Result<()> {
         None,
     )));
 
+    let (platform_worker_tx, platform_worker_rx) = futures::channel::mpsc::unbounded();
     let backend = GpuBackend {
         ex: ex.clone(),
         gpu,
@@ -244,12 +260,13 @@ pub fn run_gpu_device(opts: Options) -> anyhow::Result<()> {
         state: None,
         fence_state: Default::default(),
         queue_workers: Default::default(),
-        platform_workers: Default::default(),
+        platform_worker_rx,
+        platform_worker_tx,
         shmem_mapper: Arc::new(Mutex::new(None)),
     };
 
     // Run until the backend is finished.
-    let _ = ex.run_until(listener.run_backend(backend, &ex))?;
+    let _ = ex.run_until(conn.run_backend(backend, &ex))?;
 
     // Process any tasks from the backend's destructor.
     Ok(ex.run_until(async {})?)
diff --git a/devices/src/virtio/vhost/user/device/gpu/sys/windows.rs b/devices/src/virtio/vhost/user/device/gpu/sys/windows.rs
index 98e50f7f2..e3c321139 100644
--- a/devices/src/virtio/vhost/user/device/gpu/sys/windows.rs
+++ b/devices/src/virtio/vhost/user/device/gpu/sys/windows.rs
@@ -130,7 +130,9 @@ impl GpuBackend {
         let task = self
             .ex
             .spawn_local(run_display(display, state.clone(), self.gpu.clone()));
-        self.platform_workers.borrow_mut().push(task);
+        self.platform_worker_tx
+            .unbounded_send(task)
+            .context("sending the run_display task for the initial display")?;
 
         let task = self.ex.spawn_local(run_gpu_control_command_handler(
             AsyncTube::new(
@@ -145,7 +147,9 @@ impl GpuBackend {
             state,
             interrupt,
         ));
-        self.platform_workers.borrow_mut().push(task);
+        self.platform_worker_tx
+            .unbounded_send(task)
+            .context("sending the run_gpu_control_command_handler task")?;
 
         Ok(())
     }
@@ -310,6 +314,7 @@ pub fn run_gpu_device_worker(
 
     let ex = Executor::new().context("failed to create executor")?;
 
+    let (platform_worker_tx, platform_worker_rx) = futures::channel::mpsc::unbounded();
     let backend = GpuBackend {
         ex: ex.clone(),
         gpu,
@@ -317,7 +322,8 @@ pub fn run_gpu_device_worker(
         state: None,
         fence_state: Default::default(),
         queue_workers: Default::default(),
-        platform_workers: Default::default(),
+        platform_worker_tx,
+        platform_worker_rx,
         shmem_mapper: Arc::new(Mutex::new(None)),
     };
 
diff --git a/devices/src/virtio/vhost/user/device/mod.rs b/devices/src/virtio/vhost/user/device/mod.rs
index 556351aac..44be1f95e 100644
--- a/devices/src/virtio/vhost/user/device/mod.rs
+++ b/devices/src/virtio/vhost/user/device/mod.rs
@@ -35,6 +35,8 @@ pub use snd::run_snd_device;
 #[cfg(feature = "audio")]
 pub use snd::Options as SndOptions;
 
+pub use crate::virtio::vhost::user::device::connection::BackendConnection;
+
 cfg_if::cfg_if! {
     if #[cfg(any(target_os = "android", target_os = "linux"))] {
         mod console;
diff --git a/devices/src/virtio/vhost/user/device/snd/sys/linux.rs b/devices/src/virtio/vhost/user/device/snd/sys/linux.rs
index f810e199e..01ceb7601 100644
--- a/devices/src/virtio/vhost/user/device/snd/sys/linux.rs
+++ b/devices/src/virtio/vhost/user/device/snd/sys/linux.rs
@@ -4,20 +4,29 @@
 
 use anyhow::Context;
 use argh::FromArgs;
+use base::RawDescriptor;
 use cros_async::Executor;
 
 use crate::virtio::snd::parameters::Parameters;
-use crate::virtio::vhost::user::device::connection::sys::VhostUserListener;
-use crate::virtio::vhost::user::device::connection::VhostUserConnectionTrait;
 use crate::virtio::vhost::user::device::snd::SndBackend;
+use crate::virtio::vhost::user::device::BackendConnection;
 
 #[derive(FromArgs)]
 #[argh(subcommand, name = "snd")]
 /// Snd device
 pub struct Options {
+    #[argh(option, arg_name = "PATH", hidden_help)]
+    /// deprecated - please use --socket-path instead
+    socket: Option<String>,
     #[argh(option, arg_name = "PATH")]
-    /// path to bind a listening vhost-user socket
-    socket: String,
+    /// path to the vhost-user socket to bind to.
+    /// If this flag is set, --fd cannot be specified.
+    socket_path: Option<String>,
+    #[argh(option, arg_name = "FD")]
+    /// file descriptor of a connected vhost-user socket.
+    /// If this flag is set, --socket-path cannot be specified.
+    fd: Option<RawDescriptor>,
+
     #[argh(
         option,
         arg_name = "CONFIG",
@@ -50,7 +59,8 @@ pub fn run_snd_device(opts: Options) -> anyhow::Result<()> {
     let ex = Executor::new().context("Failed to create executor")?;
     let snd_device = Box::new(SndBackend::new(&ex, opts.params, 0)?);
 
-    let listener = VhostUserListener::new(&opts.socket)?;
+    let conn =
+        BackendConnection::from_opts(opts.socket.as_deref(), opts.socket_path.as_deref(), opts.fd)?;
 
-    listener.run_device(ex, snd_device)
+    conn.run_device(ex, snd_device)
 }
diff --git a/devices/src/virtio/vhost/user/device/vsock.rs b/devices/src/virtio/vhost/user/device/vsock.rs
index d0333c61a..f2bda9ca0 100644
--- a/devices/src/virtio/vhost/user/device/vsock.rs
+++ b/devices/src/virtio/vhost/user/device/vsock.rs
@@ -15,6 +15,7 @@ use anyhow::Context;
 use argh::FromArgs;
 use base::AsRawDescriptor;
 use base::Event;
+use base::RawDescriptor;
 use base::SafeDescriptor;
 use cros_async::Executor;
 use data_model::Le64;
@@ -38,13 +39,12 @@ use vmm_vhost::Result;
 use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;
 use zerocopy::AsBytes;
 
+use super::BackendConnection;
 use crate::virtio::device_constants::vsock::NUM_QUEUES;
 use crate::virtio::vhost::user::device::handler::vmm_va_to_gpa;
 use crate::virtio::vhost::user::device::handler::MappingInfo;
 use crate::virtio::vhost::user::device::handler::VhostUserRegularOps;
-use crate::virtio::vhost::user::VhostUserConnectionTrait;
 use crate::virtio::vhost::user::VhostUserDeviceBuilder;
-use crate::virtio::vhost::user::VhostUserListener;
 use crate::virtio::Queue;
 use crate::virtio::QueueConfig;
 
@@ -444,9 +444,18 @@ impl vmm_vhost::Backend for VsockBackend {
 #[argh(subcommand, name = "vsock")]
 /// Vsock device
 pub struct Options {
+    #[argh(option, arg_name = "PATH", hidden_help)]
+    /// deprecated - please use --socket-path instead
+    socket: Option<String>,
     #[argh(option, arg_name = "PATH")]
-    /// path to bind a listening vhost-user socket
-    socket: String,
+    /// path to the vhost-user socket to bind to.
+    /// If this flag is set, --fd cannot be specified.
+    socket_path: Option<String>,
+    #[argh(option, arg_name = "FD")]
+    /// file descriptor of a connected vhost-user socket.
+    /// If this flag is set, --socket-path cannot be specified.
+    fd: Option<RawDescriptor>,
+
     #[argh(option, arg_name = "INT")]
     /// the vsock context id for this device
     cid: u64,
@@ -463,9 +472,10 @@ pub struct Options {
 pub fn run_vsock_device(opts: Options) -> anyhow::Result<()> {
     let ex = Executor::new().context("failed to create executor")?;
 
-    let listener = VhostUserListener::new(&opts.socket)?;
+    let conn =
+        BackendConnection::from_opts(opts.socket.as_deref(), opts.socket_path.as_deref(), opts.fd)?;
 
     let vsock_device = Box::new(VhostUserVsockDevice::new(opts.cid, opts.vhost_socket)?);
 
-    listener.run_device(ex, vsock_device)
+    conn.run_device(ex, vsock_device)
 }
diff --git a/devices/src/virtio/vhost/user/device/wl.rs b/devices/src/virtio/vhost/user/device/wl.rs
index 2f5d6535f..a2468c9a0 100644
--- a/devices/src/virtio/vhost/user/device/wl.rs
+++ b/devices/src/virtio/vhost/user/device/wl.rs
@@ -17,6 +17,7 @@ use argh::FromArgs;
 use base::clone_descriptor;
 use base::error;
 use base::warn;
+use base::RawDescriptor;
 use base::SafeDescriptor;
 use base::Tube;
 use base::UnixSeqpacket;
@@ -38,13 +39,12 @@ use crate::virtio::device_constants::wl::NUM_QUEUES;
 use crate::virtio::device_constants::wl::VIRTIO_WL_F_SEND_FENCES;
 use crate::virtio::device_constants::wl::VIRTIO_WL_F_TRANS_FLAGS;
 use crate::virtio::device_constants::wl::VIRTIO_WL_F_USE_SHMEM;
-use crate::virtio::vhost::user::device::connection::sys::VhostUserListener;
-use crate::virtio::vhost::user::device::connection::VhostUserConnectionTrait;
 use crate::virtio::vhost::user::device::handler::Error as DeviceError;
 use crate::virtio::vhost::user::device::handler::VhostBackendReqConnection;
 use crate::virtio::vhost::user::device::handler::VhostBackendReqConnectionState;
 use crate::virtio::vhost::user::device::handler::VhostUserDevice;
 use crate::virtio::vhost::user::device::handler::WorkerState;
+use crate::virtio::vhost::user::device::BackendConnection;
 use crate::virtio::wl;
 use crate::virtio::Queue;
 use crate::virtio::SharedMemoryRegion;
@@ -321,9 +321,18 @@ pub fn parse_wayland_sock(value: &str) -> Result<(String, PathBuf), String> {
 #[argh(subcommand, name = "wl")]
 /// Wayland device
 pub struct Options {
+    #[argh(option, arg_name = "PATH", hidden_help)]
+    /// deprecated - please use --socket-path instead
+    socket: Option<String>,
     #[argh(option, arg_name = "PATH")]
-    /// path to bind a listening vhost-user socket
-    socket: String,
+    /// path to the vhost-user socket to bind to.
+    /// If this flag is set, --fd cannot be specified.
+    socket_path: Option<String>,
+    #[argh(option, arg_name = "FD")]
+    /// file descriptor of a connected vhost-user socket.
+    /// If this flag is set, --socket-path cannot be specified.
+    fd: Option<RawDescriptor>,
+
     #[argh(option, from_str_fn(parse_wayland_sock), arg_name = "PATH[,name=NAME]")]
     /// path to one or more Wayland sockets. The unnamed socket is used for
     /// displaying virtual screens while the named ones are used for IPC
@@ -339,6 +348,8 @@ pub fn run_wl_device(opts: Options) -> anyhow::Result<()> {
     let Options {
         wayland_sock,
         socket,
+        socket_path,
+        fd,
         resource_bridge,
     } = opts;
 
@@ -365,9 +376,9 @@ pub fn run_wl_device(opts: Options) -> anyhow::Result<()> {
 
     let ex = Executor::new().context("failed to create executor")?;
 
-    let listener = VhostUserListener::new(&socket)?;
+    let conn = BackendConnection::from_opts(socket.as_deref(), socket_path.as_deref(), fd)?;
 
     let backend = WlBackend::new(&ex, wayland_paths, resource_bridge);
     // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
-    ex.run_until(listener.run_backend(backend, &ex))?
+    ex.run_until(conn.run_backend(backend, &ex))?
 }
diff --git a/devices/src/virtio/vhost_user_frontend/mod.rs b/devices/src/virtio/vhost_user_frontend/mod.rs
index cdcce1b44..9955290ae 100644
--- a/devices/src/virtio/vhost_user_frontend/mod.rs
+++ b/devices/src/virtio/vhost_user_frontend/mod.rs
@@ -14,6 +14,7 @@ use std::cell::RefCell;
 use std::collections::BTreeMap;
 use std::io::Read;
 use std::io::Write;
+use std::sync::Arc;
 
 use anyhow::bail;
 use anyhow::Context;
@@ -24,6 +25,7 @@ use base::Event;
 use base::RawDescriptor;
 use base::WorkerThread;
 use serde_json::Value;
+use sync::Mutex;
 use vm_memory::GuestMemory;
 use vmm_vhost::message::VhostUserConfigFlags;
 use vmm_vhost::message::VhostUserMigrationPhase;
@@ -54,7 +56,7 @@ pub struct VhostUserFrontend {
     device_type: DeviceType,
     worker_thread: Option<WorkerThread<Option<BackendReqHandler>>>,
 
-    backend_client: BackendClient,
+    backend_client: Arc<Mutex<BackendClient>>,
     avail_features: u64,
     acked_features: u64,
     protocol_features: VhostUserProtocolFeatures,
@@ -238,7 +240,7 @@ impl VhostUserFrontend {
         Ok(VhostUserFrontend {
             device_type,
             worker_thread: None,
-            backend_client,
+            backend_client: Arc::new(Mutex::new(backend_client)),
             avail_features,
             acked_features,
             protocol_features,
@@ -265,6 +267,7 @@ impl VhostUserFrontend {
             .collect();
 
         self.backend_client
+            .lock()
             .set_mem_table(regions.as_slice())
             .map_err(Error::SetMemTable)?;
 
@@ -279,7 +282,8 @@ impl VhostUserFrontend {
         queue: &Queue,
         irqfd: &Event,
     ) -> Result<()> {
-        self.backend_client
+        let backend_client = self.backend_client.lock();
+        backend_client
             .set_vring_num(queue_index, queue.size())
             .map_err(Error::SetVringNum)?;
 
@@ -297,25 +301,25 @@ impl VhostUserFrontend {
                 .map_err(Error::GetHostAddress)? as u64,
             log_addr: None,
         };
-        self.backend_client
+        backend_client
             .set_vring_addr(queue_index, &config_data)
             .map_err(Error::SetVringAddr)?;
 
-        self.backend_client
+        backend_client
             .set_vring_base(queue_index, queue.next_avail_to_process())
             .map_err(Error::SetVringBase)?;
 
-        self.backend_client
+        backend_client
             .set_vring_call(queue_index, irqfd)
             .map_err(Error::SetVringCall)?;
-        self.backend_client
+        backend_client
             .set_vring_kick(queue_index, queue.event())
             .map_err(Error::SetVringKick)?;
 
         // Per protocol documentation, `VHOST_USER_SET_VRING_ENABLE` should be sent only when
         // `VHOST_USER_F_PROTOCOL_FEATURES` has been negotiated.
         if self.acked_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES != 0 {
-            self.backend_client
+            backend_client
                 .set_vring_enable(queue_index, true)
                 .map_err(Error::SetVringEnable)?;
         }
@@ -325,14 +329,15 @@ impl VhostUserFrontend {
 
     /// Stops the vring for the given `queue`, returning its base index.
     fn deactivate_vring(&self, queue_index: usize) -> Result<u16> {
+        let backend_client = self.backend_client.lock();
+
         if self.acked_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES != 0 {
-            self.backend_client
+            backend_client
                 .set_vring_enable(queue_index, false)
                 .map_err(Error::SetVringEnable)?;
         }
 
-        let vring_base = self
-            .backend_client
+        let vring_base = backend_client
             .get_vring_base(queue_index)
             .map_err(Error::GetVringBase)?;
 
@@ -349,7 +354,7 @@ impl VhostUserFrontend {
             "BUG: attempted to start worker twice"
         );
 
-        let label = format!("vhost_user_virtio_{}", self.device_type);
+        let label = self.debug_label();
 
         let mut backend_req_handler = self.backend_req_handler.take();
         if let Some(handler) = &mut backend_req_handler {
@@ -357,21 +362,20 @@ impl VhostUserFrontend {
             handler.frontend_mut().set_interrupt(interrupt.clone());
         }
 
+        let backend_client = self.backend_client.clone();
+
         self.worker_thread = Some(WorkerThread::start(label.clone(), move |kill_evt| {
-            let ex = cros_async::Executor::new().expect("failed to create an executor");
-            let ex2 = ex.clone();
-            ex.run_until(async {
-                let mut worker = Worker {
-                    kill_evt,
-                    non_msix_evt,
-                    backend_req_handler,
-                };
-                if let Err(e) = worker.run(&ex2, interrupt).await {
-                    error!("failed to run {} worker: {:#}", label, e);
-                }
-                worker.backend_req_handler
-            })
-            .expect("run_until failed")
+            let mut worker = Worker {
+                kill_evt,
+                non_msix_evt,
+                backend_req_handler,
+                backend_client,
+            };
+            worker
+                .run(interrupt)
+                .with_context(|| format!("{label}: vhost_user_frontend worker failed"))
+                .unwrap();
+            worker.backend_req_handler
         }));
     }
 }
@@ -402,6 +406,7 @@ impl VirtioDevice for VhostUserFrontend {
         let features = (features & self.avail_features) | self.acked_features;
         if let Err(e) = self
             .backend_client
+            .lock()
             .set_features(features)
             .map_err(Error::SetFeatures)
         {
@@ -428,7 +433,7 @@ impl VirtioDevice for VhostUserFrontend {
             );
             return;
         };
-        let (_, config) = match self.backend_client.get_config(
+        let (_, config) = match self.backend_client.lock().get_config(
             offset,
             data_len,
             VhostUserConfigFlags::WRITABLE,
@@ -450,6 +455,7 @@ impl VirtioDevice for VhostUserFrontend {
         };
         if let Err(e) = self
             .backend_client
+            .lock()
             .set_config(offset, VhostUserConfigFlags::empty(), data)
             .map_err(Error::SetConfig)
         {
@@ -519,6 +525,7 @@ impl VirtioDevice for VhostUserFrontend {
         }
         let regions = match self
             .backend_client
+            .lock()
             .get_shared_memory_regions()
             .map_err(Error::ShmemRegions)
         {
@@ -614,11 +621,11 @@ impl VirtioDevice for VhostUserFrontend {
         {
             bail!("snapshot requires VHOST_USER_PROTOCOL_F_DEVICE_STATE");
         }
+        let backend_client = self.backend_client.lock();
         // Send the backend an FD to write the device state to. If it gives us an FD back, then
         // we need to read from that instead.
         let (mut r, w) = new_pipe_pair()?;
-        let backend_r = self
-            .backend_client
+        let backend_r = backend_client
             .set_device_state_fd(
                 VhostUserTransferDirection::Save,
                 VhostUserMigrationPhase::Stopped,
@@ -637,7 +644,7 @@ impl VirtioDevice for VhostUserFrontend {
         }
         .context("failed to read device state")?;
         // Call `check_device_state` to ensure the data transfer was successful.
-        self.backend_client
+        backend_client
             .check_device_state()
             .context("failed to transfer device state")?;
         Ok(serde_json::to_value(snapshot_bytes).map_err(Error::SliceToSerdeValue)?)
@@ -651,12 +658,12 @@ impl VirtioDevice for VhostUserFrontend {
             bail!("restore requires VHOST_USER_PROTOCOL_F_DEVICE_STATE");
         }
 
+        let backend_client = self.backend_client.lock();
         let data_bytes: Vec<u8> = serde_json::from_value(data).map_err(Error::SerdeValueToSlice)?;
         // Send the backend an FD to read the device state from. If it gives us an FD back,
         // then we need to write to that instead.
         let (r, w) = new_pipe_pair()?;
-        let backend_w = self
-            .backend_client
+        let backend_w = backend_client
             .set_device_state_fd(
                 VhostUserTransferDirection::Load,
                 VhostUserMigrationPhase::Stopped,
@@ -678,7 +685,7 @@ impl VirtioDevice for VhostUserFrontend {
             .context("failed to write device state")?;
         }
         // Call `check_device_state` to ensure the data transfer was successful.
-        self.backend_client
+        backend_client
             .check_device_state()
             .context("failed to transfer device state")?;
         Ok(())
diff --git a/devices/src/virtio/vhost_user_frontend/sys.rs b/devices/src/virtio/vhost_user_frontend/sys.rs
index 1fb85b2b1..873d3179c 100644
--- a/devices/src/virtio/vhost_user_frontend/sys.rs
+++ b/devices/src/virtio/vhost_user_frontend/sys.rs
@@ -13,4 +13,3 @@ cfg_if::cfg_if! {
 }
 
 pub(in super::super) use platform::create_backend_req_handler;
-pub(super) use platform::run_backend_request_handler;
diff --git a/devices/src/virtio/vhost_user_frontend/sys/unix.rs b/devices/src/virtio/vhost_user_frontend/sys/unix.rs
index 5d18de30b..2bab0dfdf 100644
--- a/devices/src/virtio/vhost_user_frontend/sys/unix.rs
+++ b/devices/src/virtio/vhost_user_frontend/sys/unix.rs
@@ -2,19 +2,7 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-use std::pin::pin;
-
-use anyhow::bail;
-use anyhow::Context;
-use anyhow::Result;
-use base::info;
-use base::AsRawDescriptor;
 use base::SafeDescriptor;
-use cros_async::AsyncWrapper;
-use cros_async::Executor;
-use futures::channel::oneshot;
-use futures::future::FutureExt;
-use vmm_vhost::Error as VhostError;
 use vmm_vhost::FrontendServer;
 
 use crate::virtio::vhost_user_frontend::handler::BackendReqHandler;
@@ -27,43 +15,3 @@ pub fn create_backend_req_handler(
 ) -> VhostResult<(BackendReqHandler, SafeDescriptor)> {
     FrontendServer::with_stream(h).map_err(Error::CreateBackendReqHandler)
 }
-
-/// Process requests from the backend.
-///
-/// If `stop_rx` is sent a value, the function will exit at a well defined point so that
-/// `run_backend_request_handler` can be re-invoked to resume processing the connection.
-pub async fn run_backend_request_handler(
-    ex: &Executor,
-    handler: &mut BackendReqHandler,
-    mut stop_rx: oneshot::Receiver<()>,
-) -> Result<()> {
-    let h = SafeDescriptor::try_from(handler as &dyn AsRawDescriptor)
-        .map(AsyncWrapper::new)
-        .context("failed to get safe descriptor for handler")?;
-    let handler_source = ex
-        .async_from(h)
-        .context("failed to create an async source")?;
-
-    let mut wait_readable_future = pin!(handler_source.wait_readable().fuse());
-
-    loop {
-        futures::select_biased! {
-            _ = stop_rx => return Ok(()),
-            r = wait_readable_future => {
-                r.context("failed to wait for the handler to become readable")?;
-                match handler.handle_request() {
-                    Ok(_) => (),
-                    Err(VhostError::ClientExit) => {
-                        info!("vhost-user connection closed");
-                        // Exit as the client closed the connection.
-                        return Ok(());
-                    }
-                    Err(e) => {
-                        bail!("failed to handle a vhost-user request: {}", e);
-                    }
-                };
-                wait_readable_future.set(handler_source.wait_readable().fuse());
-            }
-        };
-    }
-}
diff --git a/devices/src/virtio/vhost_user_frontend/sys/windows.rs b/devices/src/virtio/vhost_user_frontend/sys/windows.rs
index fa3fc7cc8..8035f0d7f 100644
--- a/devices/src/virtio/vhost_user_frontend/sys/windows.rs
+++ b/devices/src/virtio/vhost_user_frontend/sys/windows.rs
@@ -2,20 +2,8 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-use anyhow::Context;
-use anyhow::Result;
-use base::info;
-use base::CloseNotifier;
-use base::ReadNotifier;
 use base::SafeDescriptor;
 use base::Tube;
-use cros_async::EventAsync;
-use cros_async::Executor;
-use futures::channel::oneshot;
-use futures::pin_mut;
-use futures::select_biased;
-use futures::FutureExt;
-use vmm_vhost::message::VhostUserProtocolFeatures;
 
 use crate::virtio::vhost_user_frontend::handler::BackendReqHandler;
 use crate::virtio::vhost_user_frontend::handler::BackendReqHandlerImpl;
@@ -29,43 +17,3 @@ pub fn create_backend_req_handler(
     let backend_pid = backend_pid.expect("tube needs target pid for backend requests");
     vmm_vhost::FrontendServer::with_tube(h, backend_pid).map_err(Error::CreateBackendReqHandler)
 }
-
-/// Process requests from the backend.
-///
-/// If `stop_rx` is sent a value, the function will exit at a well defined point so that
-/// `run_backend_request_handler` can be re-invoked to resume processing the connection.
-pub async fn run_backend_request_handler(
-    ex: &Executor,
-    handler: &mut BackendReqHandler,
-    mut stop_rx: oneshot::Receiver<()>,
-) -> Result<()> {
-    let read_notifier = handler.get_read_notifier();
-    let close_notifier = handler.get_close_notifier();
-
-    let read_event = EventAsync::clone_raw_without_reset(read_notifier, ex)
-        .context("failed to create an async event")?;
-    let close_event = EventAsync::clone_raw_without_reset(close_notifier, ex)
-        .context("failed to create an async event")?;
-
-    let read_event_fut = read_event.next_val().fuse();
-    let close_event_fut = close_event.next_val().fuse();
-    pin_mut!(read_event_fut);
-    pin_mut!(close_event_fut);
-
-    loop {
-        select_biased! {
-            _ = stop_rx => return Ok(()),
-            _read_res = read_event_fut => {
-                handler
-                    .handle_request()
-                    .context("failed to handle a vhost-user request")?;
-                read_event_fut.set(read_event.next_val().fuse());
-            }
-            // Tube closed event.
-            _close_res = close_event_fut => {
-                info!("exit run loop: got close event");
-                return Ok(())
-            }
-        }
-    }
-}
diff --git a/devices/src/virtio/vhost_user_frontend/worker.rs b/devices/src/virtio/vhost_user_frontend/worker.rs
index 4412e0744..da282de99 100644
--- a/devices/src/virtio/vhost_user_frontend/worker.rs
+++ b/devices/src/virtio/vhost_user_frontend/worker.rs
@@ -2,19 +2,24 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-use std::pin::pin;
+use std::sync::Arc;
 
+use anyhow::bail;
 use anyhow::Context;
+use base::info;
+use base::warn;
+#[cfg(windows)]
+use base::CloseNotifier;
 use base::Event;
-use cros_async::EventAsync;
-use cros_async::Executor;
-use futures::channel::oneshot;
-use futures::select_biased;
-use futures::FutureExt;
+use base::EventToken;
+use base::EventType;
+use base::ReadNotifier;
+use base::WaitContext;
+use sync::Mutex;
+use vmm_vhost::BackendClient;
+use vmm_vhost::Error as VhostError;
 
-use crate::virtio::async_utils;
 use crate::virtio::vhost_user_frontend::handler::BackendReqHandler;
-use crate::virtio::vhost_user_frontend::sys::run_backend_request_handler;
 use crate::virtio::Interrupt;
 use crate::virtio::VIRTIO_MSI_NO_VECTOR;
 
@@ -22,64 +27,132 @@ pub struct Worker {
     pub kill_evt: Event,
     pub non_msix_evt: Event,
     pub backend_req_handler: Option<BackendReqHandler>,
+    pub backend_client: Arc<Mutex<BackendClient>>,
 }
 
 impl Worker {
-    // Runs asynchronous tasks.
-    pub async fn run(&mut self, ex: &Executor, interrupt: Interrupt) -> anyhow::Result<()> {
-        let non_msix_evt = self
-            .non_msix_evt
-            .try_clone()
-            .expect("failed to clone non_msix_evt");
-        let mut handle_non_msix_evt =
-            pin!(handle_non_msix_evt(ex, non_msix_evt, interrupt.clone()).fuse());
+    pub fn run(&mut self, interrupt: Interrupt) -> anyhow::Result<()> {
+        #[derive(EventToken)]
+        enum Token {
+            Kill,
+            NonMsixEvt,
+            Resample,
+            ReqHandlerRead,
+            #[cfg(target_os = "windows")]
+            ReqHandlerClose,
+            // monitor whether backend_client_fd is broken
+            BackendCloseNotify,
+        }
+        let wait_ctx = WaitContext::build_with(&[
+            (&self.non_msix_evt, Token::NonMsixEvt),
+            (&self.kill_evt, Token::Kill),
+        ])
+        .context("failed to build WaitContext")?;
 
-        let mut resample = pin!(async_utils::handle_irq_resample(ex, interrupt).fuse());
+        if let Some(resample_evt) = interrupt.get_resample_evt() {
+            wait_ctx
+                .add(resample_evt, Token::Resample)
+                .context("failed to add resample event to WaitContext")?;
+        }
 
-        let kill_evt = self.kill_evt.try_clone().expect("failed to clone kill_evt");
-        let mut kill = pin!(async_utils::await_and_exit(ex, kill_evt).fuse());
+        if let Some(backend_req_handler) = self.backend_req_handler.as_mut() {
+            wait_ctx
+                .add(
+                    backend_req_handler.get_read_notifier(),
+                    Token::ReqHandlerRead,
+                )
+                .context("failed to add backend req handler to WaitContext")?;
 
-        let (stop_tx, stop_rx) = oneshot::channel();
-        let mut req_handler = pin!(if let Some(backend_req_handler) =
-            self.backend_req_handler.as_mut()
-        {
-            run_backend_request_handler(ex, backend_req_handler, stop_rx)
-                .fuse()
-                .left_future()
-        } else {
-            stop_rx.map(|_| Ok(())).right_future()
+            #[cfg(target_os = "windows")]
+            wait_ctx
+                .add(
+                    backend_req_handler.get_close_notifier(),
+                    Token::ReqHandlerClose,
+                )
+                .context("failed to add backend req handler close notifier to WaitContext")?;
         }
-        .fuse());
 
-        select_biased! {
-            r = kill => {
-                r.context("failed to wait on the kill event")?;
-                // Stop req_handler cooperatively.
-                let _ = stop_tx.send(());
-                req_handler.await.context("backend request failure on stop")?;
+        #[cfg(any(target_os = "android", target_os = "linux"))]
+        wait_ctx
+            .add_for_event(
+                self.backend_client.lock().get_read_notifier(),
+                EventType::None,
+                Token::BackendCloseNotify,
+            )
+            .context("failed to add backend client close notifier to WaitContext")?;
+        #[cfg(target_os = "windows")]
+        wait_ctx
+            .add(
+                self.backend_client.lock().get_close_notifier(),
+                Token::BackendCloseNotify,
+            )
+            .context("failed to add backend client close notifier to WaitContext")?;
+
+        'wait: loop {
+            let events = wait_ctx.wait().context("WaitContext::wait() failed")?;
+            for event in events {
+                match event.token {
+                    Token::Kill => {
+                        break 'wait;
+                    }
+                    Token::NonMsixEvt => {
+                        // The vhost-user protocol allows the backend to signal events, but for
+                        // non-MSI-X devices, a device must also update the interrupt status mask.
+                        // `non_msix_evt` proxies events from the vhost-user backend to update the
+                        // status mask.
+                        let _ = self.non_msix_evt.wait();
+
+                        // The parameter vector of signal_used_queue is used only when msix is
+                        // enabled.
+                        interrupt.signal_used_queue(VIRTIO_MSI_NO_VECTOR);
+                    }
+                    Token::Resample => {
+                        interrupt.interrupt_resample();
+                    }
+                    Token::ReqHandlerRead => {
+                        let Some(backend_req_handler) = self.backend_req_handler.as_mut() else {
+                            continue;
+                        };
+
+                        match backend_req_handler.handle_request() {
+                            Ok(_) => (),
+                            Err(VhostError::ClientExit) | Err(VhostError::Disconnect) => {
+                                info!("backend req handler connection closed");
+                                // Stop monitoring `backend_req_handler` as the client closed
+                                // the connection.
+                                let _ = wait_ctx.delete(backend_req_handler.get_read_notifier());
+                                #[cfg(target_os = "windows")]
+                                let _ = wait_ctx.delete(backend_req_handler.get_close_notifier());
+                                self.backend_req_handler = None;
+                            }
+                            Err(e) => return Err(e).context("failed to handle vhost-user request"),
+                        }
+                    }
+                    #[cfg(target_os = "windows")]
+                    Token::ReqHandlerClose => {
+                        let Some(backend_req_handler) = self.backend_req_handler.as_mut() else {
+                            continue;
+                        };
+
+                        info!("backend req handler connection closed");
+                        let _ = wait_ctx.delete(backend_req_handler.get_read_notifier());
+                        let _ = wait_ctx.delete(backend_req_handler.get_close_notifier());
+                        self.backend_req_handler = None;
+                    }
+                    Token::BackendCloseNotify => {
+                        // For linux domain socket, the close notifier fd is same with read/write
+                        // notifier We need check whether the event is caused by socket broken.
+                        #[cfg(any(target_os = "android", target_os = "linux"))]
+                        if !event.is_hungup {
+                            warn!("event besides hungup should not be notified");
+                            continue;
+                        }
+                        bail!("Backend device disconnected early");
+                    }
+                }
             }
-            r = handle_non_msix_evt => r.context("non msix event failure")?,
-            r = resample => r.context("failed to resample a irq value")?,
-            r = req_handler => r.context("backend request failure")?,
         }
 
         Ok(())
     }
 }
-
-// The vhost-user protocol allows the backend to signal events, but for non-MSI-X devices,
-// a device must also update the interrupt status mask. `handle_non_msix_evt` proxies events
-// from the vhost-user backend to update the status mask.
-async fn handle_non_msix_evt(
-    ex: &Executor,
-    non_msix_evt: Event,
-    interrupt: Interrupt,
-) -> anyhow::Result<()> {
-    let event_async =
-        EventAsync::new(non_msix_evt, ex).expect("failed to create async non_msix_evt");
-    loop {
-        let _ = event_async.next_val().await;
-        // The parameter vector of signal_used_queue is used only when msix is enabled.
-        interrupt.signal_used_queue(VIRTIO_MSI_NO_VECTOR);
-    }
-}
diff --git a/devices/src/virtio/video/decoder/backend/ffmpeg.rs b/devices/src/virtio/video/decoder/backend/ffmpeg.rs
index fafb832ad..dd8385ca8 100644
--- a/devices/src/virtio/video/decoder/backend/ffmpeg.rs
+++ b/devices/src/virtio/video/decoder/backend/ffmpeg.rs
@@ -387,16 +387,9 @@ impl FfmpegDecoderSession {
 
         // Prepare the picture ready event that we will emit once the frame is written into the
         // target buffer.
-        let avframe_ref = avframe.as_ref();
         let picture_ready_event = DecoderEvent::PictureReady {
             picture_buffer_id: picture_buffer_id as i32,
-            timestamp: avframe_ref.pts as u64,
-            visible_rect: Rect {
-                left: 0,
-                top: 0,
-                right: avframe_ref.width,
-                bottom: avframe_ref.height,
-            },
+            timestamp: avframe.pts as u64,
         };
 
         // Convert the frame into the target buffer and emit the picture ready event.
diff --git a/devices/src/virtio/video/decoder/backend/mod.rs b/devices/src/virtio/video/decoder/backend/mod.rs
index 96aa9fda5..3f192ce67 100644
--- a/devices/src/virtio/video/decoder/backend/mod.rs
+++ b/devices/src/virtio/video/decoder/backend/mod.rs
@@ -231,7 +231,6 @@ pub enum DecoderEvent {
     PictureReady {
         picture_buffer_id: i32,
         timestamp: u64,
-        visible_rect: Rect,
     },
     /// Emitted when an input buffer passed to `decode()` is not used by the
     /// device anymore and can be reused by the decoder. The parameter corresponds
@@ -387,43 +386,32 @@ mod tests {
         let mut decoded_frames_count = 0usize;
         let mut expected_frames_crcs = H264_STREAM_CRCS.lines();
 
-        let mut on_frame_decoded =
-            |session: &mut D::Session, picture_buffer_id: i32, visible_rect: Rect| {
-                assert_eq!(
-                    visible_rect,
-                    Rect {
-                        left: 0,
-                        top: 0,
-                        right: H264_STREAM_WIDTH,
-                        bottom: H264_STREAM_HEIGHT,
-                    }
-                );
-
-                // Verify that the CRC of the decoded frame matches the expected one.
-                let mapping = MemoryMappingBuilder::new(OUTPUT_BUFFER_SIZE)
-                    .from_shared_memory(&output_buffers[picture_buffer_id as usize])
-                    .build()
-                    .unwrap();
-                let mut frame_data = vec![0u8; mapping.size()];
-                assert_eq!(
-                    mapping.read_slice(&mut frame_data, 0).unwrap(),
-                    mapping.size()
-                );
-
-                let mut hasher = crc32fast::Hasher::new();
-                hasher.update(&frame_data);
-                let frame_crc = hasher.finalize();
-                assert_eq!(
-                    format!("{:08x}", frame_crc),
-                    expected_frames_crcs
-                        .next()
-                        .expect("No CRC for decoded frame")
-                );
-
-                // We can recycle the frame now.
-                session.reuse_output_buffer(picture_buffer_id).unwrap();
-                decoded_frames_count += 1;
-            };
+        let mut on_frame_decoded = |session: &mut D::Session, picture_buffer_id: i32| {
+            // Verify that the CRC of the decoded frame matches the expected one.
+            let mapping = MemoryMappingBuilder::new(OUTPUT_BUFFER_SIZE)
+                .from_shared_memory(&output_buffers[picture_buffer_id as usize])
+                .build()
+                .unwrap();
+            let mut frame_data = vec![0u8; mapping.size()];
+            assert_eq!(
+                mapping.read_slice(&mut frame_data, 0).unwrap(),
+                mapping.size()
+            );
+
+            let mut hasher = crc32fast::Hasher::new();
+            hasher.update(&frame_data);
+            let frame_crc = hasher.finalize();
+            assert_eq!(
+                format!("{:08x}", frame_crc),
+                expected_frames_crcs
+                    .next()
+                    .expect("No CRC for decoded frame")
+            );
+
+            // We can recycle the frame now.
+            session.reuse_output_buffer(picture_buffer_id).unwrap();
+            decoded_frames_count += 1;
+        };
 
         // Simple value by which we will multiply the frame number to obtain a fake timestamp.
         const TIMESTAMP_FOR_INPUT_ID_FACTOR: u64 = 1_000_000;
@@ -521,10 +509,8 @@ mod tests {
             for event in events {
                 match event {
                     DecoderEvent::PictureReady {
-                        picture_buffer_id,
-                        visible_rect,
-                        ..
-                    } => on_frame_decoded(&mut session, picture_buffer_id, visible_rect),
+                        picture_buffer_id, ..
+                    } => on_frame_decoded(&mut session, picture_buffer_id),
                     e => panic!("Unexpected event: {:?}", e),
                 }
             }
@@ -537,10 +523,8 @@ mod tests {
         while !wait_ctx.wait_timeout(Duration::ZERO).unwrap().is_empty() {
             match session.read_event().unwrap() {
                 DecoderEvent::PictureReady {
-                    picture_buffer_id,
-                    visible_rect,
-                    ..
-                } => on_frame_decoded(&mut session, picture_buffer_id, visible_rect),
+                    picture_buffer_id, ..
+                } => on_frame_decoded(&mut session, picture_buffer_id),
                 DecoderEvent::FlushCompleted(Ok(())) => {
                     received_flush_completed = true;
                     break;
diff --git a/devices/src/virtio/video/decoder/backend/vaapi.rs b/devices/src/virtio/video/decoder/backend/vaapi.rs
index 17a296001..91cf0311f 100644
--- a/devices/src/virtio/video/decoder/backend/vaapi.rs
+++ b/devices/src/virtio/video/decoder/backend/vaapi.rs
@@ -520,7 +520,6 @@ impl VaapiDecoderSession {
         decoded_frame: &dyn DecodedHandle<Descriptor = BufferDescWithPicId>,
         event_queue: &mut EventQueue<DecoderEvent>,
     ) -> Result<()> {
-        let display_resolution = decoded_frame.display_resolution();
         let timestamp = decoded_frame.timestamp();
 
         let buffer_desc = decoded_frame.resource();
@@ -553,12 +552,6 @@ impl VaapiDecoderSession {
             .queue_event(DecoderEvent::PictureReady {
                 picture_buffer_id,
                 timestamp,
-                visible_rect: Rect {
-                    left: 0,
-                    top: 0,
-                    right: display_resolution.width as i32,
-                    bottom: display_resolution.height as i32,
-                },
             })
             .map_err(|e| {
                 VideoError::BackendFailure(anyhow!("Can't queue the PictureReady event {}", e))
diff --git a/devices/src/virtio/video/decoder/backend/vda.rs b/devices/src/virtio/video/decoder/backend/vda.rs
index e3d516bae..f716974d3 100644
--- a/devices/src/virtio/video/decoder/backend/vda.rs
+++ b/devices/src/virtio/video/decoder/backend/vda.rs
@@ -101,20 +101,11 @@ impl From<libvda::decode::Event> for DecoderEvent {
             LibvdaEvent::PictureReady {
                 buffer_id,
                 bitstream_id,
-                left,
-                top,
-                right,
-                bottom,
+                ..
             } => DecoderEvent::PictureReady {
                 picture_buffer_id: buffer_id,
                 // Restore the truncated timestamp to its original value (hopefully).
                 timestamp: TIMESTAMP_TRUNCATE_FACTOR.wrapping_mul(bitstream_id as u64),
-                visible_rect: Rect {
-                    left,
-                    top,
-                    right,
-                    bottom,
-                },
             },
             LibvdaEvent::NotifyEndOfBitstreamBuffer { bitstream_id } => {
                 // We will patch the timestamp to the actual bitstream ID in `read_event`.
diff --git a/devices/src/virtio/virtio_device.rs b/devices/src/virtio/virtio_device.rs
index 63d0af223..4449b152a 100644
--- a/devices/src/virtio/virtio_device.rs
+++ b/devices/src/virtio/virtio_device.rs
@@ -71,6 +71,27 @@ pub trait SharedMemoryMapper: Send {
 /// and all the events, memory, and queues for device operation will be moved into the device.
 /// Optionally, a virtio device can implement device reset in which it returns said resources and
 /// resets its internal.
+///
+/// Virtio device state machine
+/// ```none
+///                           restore (inactive)
+///       ----------------------------------------------------
+///       |                                                  |
+///       |                                                  V
+///       |                       ------------         --------------
+/// ------------- restore(active) |  asleep  |         |   asleep   |   // States in this row
+/// |asleep(new)|---------------> | (active) |         | (inactive) |   // can be snapshotted
+/// -------------                 ------------         --------------
+///    ^       |                     ^    |              ^      |
+///    |       |                     |    |              |      |
+///  sleep    wake                sleep  wake         sleep   wake
+///    |       |                     |    |              |      |
+///    |       V                     |    V              |      V
+///  ------------     activate     ----------  reset   ------------
+///  |    new   | ---------------> | active | ------>  | inactive |
+///  ------------                  ---------- <------  ------------
+///                                           activate
+/// ```
 pub trait VirtioDevice: Send {
     /// Returns a label suitable for debug output.
     fn debug_label(&self) -> String {
@@ -377,7 +398,11 @@ macro_rules! suspendable_virtio_tests {
                 device
                     .virtio_wake(Some((mem.clone(), interrupt.clone(), sleep_result)))
                     .expect("failed to wake");
+
+                // Create a new device to restore the previously taken snapshot
                 let (_ctx2, mut device) = $dev();
+                // Sleep the device before restore
+                assert!(device.virtio_sleep().expect("failed to sleep").is_none());
                 device
                     .virtio_restore(snap.clone())
                     .expect("failed to restore");
diff --git a/devices/src/virtio/virtio_pci_device.rs b/devices/src/virtio/virtio_pci_device.rs
index 01f4ebd9a..ce87b4985 100644
--- a/devices/src/virtio/virtio_pci_device.rs
+++ b/devices/src/virtio/virtio_pci_device.rs
@@ -445,6 +445,10 @@ impl VirtioPciDevice {
                 PciClassCode::MultimediaController,
                 &PciMultimediaSubclass::VideoController as &dyn PciSubclass,
             ),
+            DeviceType::Media => (
+                PciClassCode::MultimediaController,
+                &PciMultimediaSubclass::VideoController as &dyn PciSubclass,
+            ),
             DeviceType::Scmi => (
                 PciClassCode::BaseSystemPeripheral,
                 &PciBaseSystemPeripheralSubclass::Other as &dyn PciSubclass,
diff --git a/devices/tests/irqchip/userspace.rs b/devices/tests/irqchip/userspace.rs
index 440d8f661..29015f955 100644
--- a/devices/tests/irqchip/userspace.rs
+++ b/devices/tests/irqchip/userspace.rs
@@ -674,13 +674,10 @@ impl Vcpu for FakeVcpu {
         unimplemented!()
     }
 
-    fn handle_mmio(
-        &self,
-        _handle_fn: &mut dyn FnMut(IoParams) -> Result<Option<[u8; 8]>>,
-    ) -> Result<()> {
+    fn handle_mmio(&self, _handle_fn: &mut dyn FnMut(IoParams) -> Result<()>) -> Result<()> {
         unimplemented!()
     }
-    fn handle_io(&self, _handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
+    fn handle_io(&self, _handle_fn: &mut dyn FnMut(IoParams)) -> Result<()> {
         unimplemented!()
     }
     fn on_suspend(&self) -> Result<()> {
diff --git a/disk/Android.bp b/disk/Android.bp
index a61efa253..bd924f731 100644
--- a/disk/Android.bp
+++ b/disk/Android.bp
@@ -32,6 +32,7 @@ rust_test {
         "qcow",
     ],
     rustlibs: [
+        "libanyhow",
         "libbase_rust",
         "libcfg_if",
         "libcrc32fast", // Added manually
@@ -70,6 +71,7 @@ rust_library {
         "qcow",
     ],
     rustlibs: [
+        "libanyhow",
         "libbase_rust",
         "libcfg_if",
         "libcrc32fast", // Added manually
diff --git a/disk/Cargo.toml b/disk/Cargo.toml
index 39f4b47eb..79237ecff 100644
--- a/disk/Cargo.toml
+++ b/disk/Cargo.toml
@@ -11,8 +11,10 @@ path = "src/disk.rs"
 android-sparse = []
 composite-disk = ["crc32fast", "protos", "protobuf", "uuid"]
 qcow = []
+zstd-disk = ["zstd"]
 
 [dependencies]
+anyhow = "*"
 async-trait = "0.1.36"
 base = { path = "../base" }
 cfg-if = "1.0.0"
@@ -23,12 +25,13 @@ libc = "0.2"
 protobuf = { version = "3.2", optional = true }
 protos = { path = "../protos", features = ["composite-disk"], optional = true }
 remain = "0.2"
-serde = { version = "1", features = [ "derive" ] }
+serde = { version = "1", features = ["derive"] }
 sync = { path = "../common/sync" }
 thiserror = "1"
 uuid = { version = "1", features = ["v4"], optional = true }
 vm_memory = { path = "../vm_memory" }
 zerocopy = { version = "0.7", features = ["derive"] }
+zstd = { version = "0.13", optional = true }
 
 [target.'cfg(windows)'.dependencies]
 winapi = "0.3"
diff --git a/disk/patches/Android.bp.patch b/disk/patches/Android.bp.patch
index 736a238c6..bfdb10bdc 100644
--- a/disk/patches/Android.bp.patch
+++ b/disk/patches/Android.bp.patch
@@ -1,8 +1,8 @@
 diff --git a/disk/Android.bp b/disk/Android.bp
-index ef8395e82..088ac60b8 100644
+index dcc6c2774..bd924f731 100644
 --- a/disk/Android.bp
 +++ b/disk/Android.bp
-@@ -28,19 +28,24 @@ rust_test {
+@@ -28,20 +28,25 @@ rust_test {
      edition: "2021",
      features: [
          "android-sparse",
@@ -10,6 +10,7 @@ index ef8395e82..088ac60b8 100644
          "qcow",
      ],
      rustlibs: [
+         "libanyhow",
          "libbase_rust",
          "libcfg_if",
 +        "libcrc32fast", // Added manually
@@ -27,7 +28,7 @@ index ef8395e82..088ac60b8 100644
          "libvm_memory",
          "libzerocopy",
      ],
-@@ -61,18 +66,23 @@ rust_library {
+@@ -62,19 +67,24 @@ rust_library {
      edition: "2021",
      features: [
          "android-sparse",
@@ -35,6 +36,7 @@ index ef8395e82..088ac60b8 100644
          "qcow",
      ],
      rustlibs: [
+         "libanyhow",
          "libbase_rust",
          "libcfg_if",
 +        "libcrc32fast", // Added manually
diff --git a/disk/src/composite.rs b/disk/src/composite.rs
index ac64d8211..e2d1bec40 100644
--- a/disk/src/composite.rs
+++ b/disk/src/composite.rs
@@ -1387,7 +1387,8 @@ mod tests {
                     path: "/partition1.img".to_string().into(),
                     partition_type: ImagePartitionType::LinuxFilesystem,
                     writable: false,
-                    size: 0,
+                    // Needs small amount of padding.
+                    size: 4000,
                     part_guid: None,
                 },
                 PartitionInfo {
@@ -1395,7 +1396,8 @@ mod tests {
                     path: "/partition2.img".to_string().into(),
                     partition_type: ImagePartitionType::LinuxFilesystem,
                     writable: true,
-                    size: 0,
+                    // Needs no padding.
+                    size: 4096,
                     part_guid: Some(Uuid::from_u128(0x4049C8DC_6C2B_C740_A95A_BDAA629D4378)),
                 },
             ],
@@ -1407,6 +1409,54 @@ mod tests {
             &mut composite_image,
         )
         .unwrap();
+
+        // Check magic.
+        composite_image.rewind().unwrap();
+        let mut magic_space = [0u8; CDISK_MAGIC.len()];
+        composite_image.read_exact(&mut magic_space[..]).unwrap();
+        assert_eq!(magic_space, CDISK_MAGIC.as_bytes());
+        // Check proto.
+        let proto = CompositeDisk::parse_from_reader(&mut composite_image).unwrap();
+        assert_eq!(
+            proto,
+            CompositeDisk {
+                version: 2,
+                component_disks: vec![
+                    ComponentDisk {
+                        file_path: "/header_path.img".to_string(),
+                        offset: 0,
+                        read_write_capability: ReadWriteCapability::READ_ONLY.into(),
+                        ..ComponentDisk::new()
+                    },
+                    ComponentDisk {
+                        file_path: "/partition1.img".to_string(),
+                        offset: 0x5000, // GPT_BEGINNING_SIZE,
+                        read_write_capability: ReadWriteCapability::READ_ONLY.into(),
+                        ..ComponentDisk::new()
+                    },
+                    ComponentDisk {
+                        file_path: "/zero_filler.img".to_string(),
+                        offset: 0x5fa0, // GPT_BEGINNING_SIZE + 4000,
+                        read_write_capability: ReadWriteCapability::READ_ONLY.into(),
+                        ..ComponentDisk::new()
+                    },
+                    ComponentDisk {
+                        file_path: "/partition2.img".to_string(),
+                        offset: 0x6000, // GPT_BEGINNING_SIZE + 4096,
+                        read_write_capability: ReadWriteCapability::READ_WRITE.into(),
+                        ..ComponentDisk::new()
+                    },
+                    ComponentDisk {
+                        file_path: "/footer_path.img".to_string(),
+                        offset: 0x7000, // GPT_BEGINNING_SIZE + 4096 + 4096,
+                        read_write_capability: ReadWriteCapability::READ_ONLY.into(),
+                        ..ComponentDisk::new()
+                    },
+                ],
+                length: 0x10000, // 1 << DISK_SIZE_SHIFT
+                ..CompositeDisk::new()
+            }
+        );
     }
 
     /// Attempts to create a composite disk image with two partitions with the same label.
diff --git a/disk/src/disk.rs b/disk/src/disk.rs
index 324dcdc2d..25b3273fa 100644
--- a/disk/src/disk.rs
+++ b/disk/src/disk.rs
@@ -65,6 +65,17 @@ use android_sparse::AndroidSparse;
 use android_sparse::SPARSE_HEADER_MAGIC;
 use sys::read_from_disk;
 
+#[cfg(feature = "zstd")]
+mod zstd;
+#[cfg(feature = "zstd")]
+use zstd::ZstdDisk;
+#[cfg(feature = "zstd")]
+use zstd::ZSTD_FRAME_MAGIC;
+#[cfg(feature = "zstd")]
+use zstd::ZSTD_SKIPPABLE_MAGIC_HIGH;
+#[cfg(feature = "zstd")]
+use zstd::ZSTD_SKIPPABLE_MAGIC_LOW;
+
 /// Nesting depth limit for disk formats that can open other disk files.
 const MAX_NESTING_DEPTH: u32 = 10;
 
@@ -80,6 +91,9 @@ pub enum Error {
     #[cfg(feature = "composite-disk")]
     #[error("failure in composite disk: {0}")]
     CreateCompositeDisk(composite::Error),
+    #[cfg(feature = "zstd")]
+    #[error("failure in zstd disk: {0}")]
+    CreateZstdDisk(anyhow::Error),
     #[error("failure creating single file disk: {0}")]
     CreateSingleFileDisk(cros_async::AsyncError),
     #[error("failed to set O_DIRECT on disk image: {0}")]
@@ -201,6 +215,7 @@ pub enum ImageType {
     Qcow2,
     CompositeDisk,
     AndroidSparse,
+    Zstd,
 }
 
 /// Detect the type of an image file by checking for a valid header of the supported formats.
@@ -239,8 +254,12 @@ pub fn detect_image_type(file: &File, overlapped_mode: bool) -> Result<ImageType
         }
     }
 
-    #[allow(unused_variables)] // magic4 is only used with the qcow or android-sparse features.
-    if let Some(magic4) = magic.data.get(0..4) {
+    #[allow(unused_variables)] // magic4 is only used with the qcow/android-sparse/zstd features.
+    if let Some(magic4) = magic
+        .data
+        .get(0..4)
+        .and_then(|v| <&[u8] as std::convert::TryInto<[u8; 4]>>::try_into(v).ok())
+    {
         #[cfg(feature = "qcow")]
         if magic4 == QCOW_MAGIC.to_be_bytes() {
             return Ok(ImageType::Qcow2);
@@ -249,6 +268,13 @@ pub fn detect_image_type(file: &File, overlapped_mode: bool) -> Result<ImageType
         if magic4 == SPARSE_HEADER_MAGIC.to_le_bytes() {
             return Ok(ImageType::AndroidSparse);
         }
+        #[cfg(feature = "zstd")]
+        if u32::from_le_bytes(magic4) == ZSTD_FRAME_MAGIC
+            || (u32::from_le_bytes(magic4) >= ZSTD_SKIPPABLE_MAGIC_LOW
+                && u32::from_le_bytes(magic4) <= ZSTD_SKIPPABLE_MAGIC_HIGH)
+        {
+            return Ok(ImageType::Zstd);
+        }
     }
 
     Ok(ImageType::Raw)
@@ -306,6 +332,9 @@ pub fn open_disk_file(params: DiskFileParams) -> Result<Box<dyn DiskFile>> {
             Box::new(AndroidSparse::from_file(raw_image).map_err(Error::CreateAndroidSparseDisk)?)
                 as Box<dyn DiskFile>
         }
+        #[cfg(feature = "zstd")]
+        ImageType::Zstd => Box::new(ZstdDisk::from_file(raw_image).map_err(Error::CreateZstdDisk)?)
+            as Box<dyn DiskFile>,
         #[allow(unreachable_patterns)]
         _ => return Err(Error::UnknownType),
     })
diff --git a/disk/src/qcow/qcow_raw_file.rs b/disk/src/qcow/qcow_raw_file.rs
index f13202f45..20fc8b8d5 100644
--- a/disk/src/qcow/qcow_raw_file.rs
+++ b/disk/src/qcow/qcow_raw_file.rs
@@ -15,6 +15,7 @@ use std::mem::size_of_val;
 use base::FileReadWriteAtVolatile;
 use base::VolatileSlice;
 use base::WriteZeroesAt;
+use zerocopy::AsBytes;
 
 /// A qcow file. Allows reading/writing clusters and appending clusters.
 #[derive(Debug)]
@@ -48,11 +49,10 @@ impl QcowRawFile {
     ) -> io::Result<Vec<u64>> {
         let mut table = vec![0; count as usize];
         self.file.seek(SeekFrom::Start(offset))?;
+        self.file.read_exact(table.as_bytes_mut())?;
         let mask = mask.unwrap_or(u64::MAX);
         for ptr in &mut table {
-            let mut value = [0u8; 8];
-            self.file.read_exact(&mut value)?;
-            *ptr = u64::from_be_bytes(value) & mask;
+            *ptr = u64::from_be(*ptr) & mask;
         }
         Ok(table)
     }
@@ -83,6 +83,7 @@ impl QcowRawFile {
             };
             buffer.write_all(&val.to_be_bytes())?;
         }
+        buffer.flush()?;
         Ok(())
     }
 
@@ -92,10 +93,9 @@ impl QcowRawFile {
         let count = self.cluster_size / size_of::<u16>() as u64;
         let mut table = vec![0; count as usize];
         self.file.seek(SeekFrom::Start(offset))?;
+        self.file.read_exact(table.as_bytes_mut())?;
         for refcount in &mut table {
-            let mut value = [0u8; 2];
-            self.file.read_exact(&mut value)?;
-            *refcount = u16::from_be_bytes(value);
+            *refcount = u16::from_be(*refcount);
         }
         Ok(table)
     }
@@ -107,6 +107,7 @@ impl QcowRawFile {
         for count in table {
             buffer.write_all(&count.to_be_bytes())?;
         }
+        buffer.flush()?;
         Ok(())
     }
 
diff --git a/disk/src/sys/windows.rs b/disk/src/sys/windows.rs
index 99f413d01..0a4d7a805 100644
--- a/disk/src/sys/windows.rs
+++ b/disk/src/sys/windows.rs
@@ -14,7 +14,6 @@ use cros_async::Executor;
 use winapi::um::winbase::FILE_FLAG_NO_BUFFERING;
 use winapi::um::winbase::FILE_FLAG_OVERLAPPED;
 use winapi::um::winnt::FILE_SHARE_READ;
-use winapi::um::winnt::FILE_SHARE_WRITE;
 
 use crate::DiskFileParams;
 use crate::Error;
@@ -33,8 +32,13 @@ pub fn open_raw_disk_image(params: &DiskFileParams) -> Result<File> {
     let mut options = File::options();
     options.read(true).write(!params.is_read_only);
     if params.lock {
-        // We only prevent file deletion and renaming right now.
-        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
+        if params.is_read_only {
+            // Shared read-only file access.
+            options.share_mode(FILE_SHARE_READ);
+        } else {
+            // Exclusive file access.
+            options.share_mode(0);
+        }
     }
 
     let mut flags = 0;
diff --git a/disk/src/zstd.rs b/disk/src/zstd.rs
new file mode 100644
index 000000000..c48c64fa6
--- /dev/null
+++ b/disk/src/zstd.rs
@@ -0,0 +1,483 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+//! Use seekable zstd archive of raw disk image as read only disk
+
+use std::cmp::min;
+use std::fs::File;
+use std::io;
+use std::io::ErrorKind;
+use std::io::Read;
+use std::io::Seek;
+use std::sync::Arc;
+
+use anyhow::bail;
+use anyhow::Context;
+use async_trait::async_trait;
+use base::AsRawDescriptor;
+use base::FileAllocate;
+use base::FileReadWriteAtVolatile;
+use base::FileSetLen;
+use base::RawDescriptor;
+use base::VolatileSlice;
+use cros_async::BackingMemory;
+use cros_async::Executor;
+use cros_async::IoSource;
+
+use crate::AsyncDisk;
+use crate::DiskFile;
+use crate::DiskGetLen;
+use crate::Error as DiskError;
+use crate::Result as DiskResult;
+use crate::ToAsyncDisk;
+
+// Zstandard frame magic
+pub const ZSTD_FRAME_MAGIC: u32 = 0xFD2FB528;
+
+// Skippable frame magic can be anything between [0x184D2A50, 0x184D2A5F]
+pub const ZSTD_SKIPPABLE_MAGIC_LOW: u32 = 0x184D2A50;
+pub const ZSTD_SKIPPABLE_MAGIC_HIGH: u32 = 0x184D2A5F;
+pub const ZSTD_SEEK_TABLE_MAGIC: u32 = 0x8F92EAB1;
+
+pub const ZSTD_DEFAULT_FRAME_SIZE: usize = 128 << 10; // 128KB
+
+#[derive(Clone, Debug)]
+pub struct ZstdSeekTable {
+    // Cumulative sum of decompressed sizes of all frames before the indexed frame.
+    // The last element is the total decompressed size of the zstd archive.
+    cumulative_decompressed_sizes: Vec<u64>,
+    // Cumulative sum of compressed sizes of all frames before the indexed frame.
+    // The last element is the total compressed size of the zstd archive.
+    cumulative_compressed_sizes: Vec<u64>,
+}
+
+impl ZstdSeekTable {
+    /// Read seek table entries from seek_table_entries
+    pub fn from_footer(
+        seek_table_entries: &[u8],
+        num_frames: u32,
+        checksum_flag: bool,
+    ) -> anyhow::Result<ZstdSeekTable> {
+        let mut cumulative_decompressed_size: u64 = 0;
+        let mut cumulative_compressed_size: u64 = 0;
+        let mut cumulative_decompressed_sizes = Vec::with_capacity(num_frames as usize + 1);
+        let mut cumulative_compressed_sizes = Vec::with_capacity(num_frames as usize + 1);
+        let mut offset = 0;
+        cumulative_decompressed_sizes.push(0);
+        cumulative_compressed_sizes.push(0);
+        for _ in 0..num_frames {
+            let compressed_size = u32::from_le_bytes(
+                seek_table_entries
+                    .get(offset..offset + 4)
+                    .context("failed to parse seektable entry")?
+                    .try_into()?,
+            );
+            let decompressed_size = u32::from_le_bytes(
+                seek_table_entries
+                    .get(offset + 4..offset + 8)
+                    .context("failed to parse seektable entry")?
+                    .try_into()?,
+            );
+            cumulative_decompressed_size += decompressed_size as u64;
+            cumulative_compressed_size += compressed_size as u64;
+            cumulative_decompressed_sizes.push(cumulative_decompressed_size);
+            cumulative_compressed_sizes.push(cumulative_compressed_size);
+            offset += 8 + (checksum_flag as usize * 4);
+        }
+        cumulative_decompressed_sizes.push(cumulative_decompressed_size);
+        cumulative_compressed_sizes.push(cumulative_compressed_size);
+
+        Ok(ZstdSeekTable {
+            cumulative_decompressed_sizes,
+            cumulative_compressed_sizes,
+        })
+    }
+
+    /// Returns the index of the frame that contains the given decompressed offset.
+    pub fn find_frame_index(&self, decompressed_offset: u64) -> Option<usize> {
+        if self.cumulative_decompressed_sizes.is_empty()
+            || decompressed_offset >= *self.cumulative_decompressed_sizes.last().unwrap()
+        {
+            return None;
+        }
+        self.cumulative_decompressed_sizes
+            .partition_point(|&size| size <= decompressed_offset)
+            .checked_sub(1)
+    }
+}
+
+#[derive(Debug)]
+pub struct ZstdDisk {
+    file: File,
+    seek_table: ZstdSeekTable,
+}
+
+impl ZstdDisk {
+    pub fn from_file(mut file: File) -> anyhow::Result<ZstdDisk> {
+        // Verify file is large enough to contain a seek table (17 bytes)
+        if file.metadata()?.len() < 17 {
+            return Err(anyhow::anyhow!("File too small to contain zstd seek table"));
+        }
+
+        // Read last 9 bytes as seek table footer
+        let mut seektable_footer = [0u8; 9];
+        file.seek(std::io::SeekFrom::End(-9))?;
+        file.read_exact(&mut seektable_footer)?;
+
+        // Verify last 4 bytes of footer is seek table magic
+        if u32::from_le_bytes(seektable_footer[5..9].try_into()?) != ZSTD_SEEK_TABLE_MAGIC {
+            return Err(anyhow::anyhow!("Invalid zstd seek table magic"));
+        }
+
+        // Get number of frame from seek table
+        let num_frames = u32::from_le_bytes(seektable_footer[0..4].try_into()?);
+
+        // Read flags from seek table descriptor
+        let checksum_flag = (seektable_footer[4] >> 7) & 1 != 0;
+        if (seektable_footer[4] & 0x7C) != 0 {
+            bail!(
+                "This zstd seekable decoder cannot parse seek table with non-zero reserved flags"
+            );
+        }
+
+        let seek_table_entries_size = num_frames * (8 + (checksum_flag as u32 * 4));
+
+        // Seek to the beginning of the seek table
+        file.seek(std::io::SeekFrom::End(
+            -(9 + seek_table_entries_size as i64),
+        ))?;
+
+        // Return new ZstdDisk
+        let mut seek_table_entries: Vec<u8> = vec![0u8; seek_table_entries_size as usize];
+        file.read_exact(&mut seek_table_entries)?;
+
+        let seek_table =
+            ZstdSeekTable::from_footer(&seek_table_entries, num_frames, checksum_flag)?;
+
+        Ok(ZstdDisk { file, seek_table })
+    }
+}
+
+impl DiskGetLen for ZstdDisk {
+    fn get_len(&self) -> std::io::Result<u64> {
+        self.seek_table
+            .cumulative_decompressed_sizes
+            .last()
+            .copied()
+            .ok_or(io::ErrorKind::InvalidData.into())
+    }
+}
+
+impl FileSetLen for ZstdDisk {
+    fn set_len(&self, _len: u64) -> std::io::Result<()> {
+        Err(io::Error::new(
+            io::ErrorKind::PermissionDenied,
+            "unsupported operation",
+        ))
+    }
+}
+
+impl AsRawDescriptor for ZstdDisk {
+    fn as_raw_descriptor(&self) -> RawDescriptor {
+        self.file.as_raw_descriptor()
+    }
+}
+
+struct CompressedReadInstruction {
+    frame_index: usize,
+    read_offset: u64,
+    read_size: u64,
+}
+
+fn compresed_frame_read_instruction(
+    seek_table: &ZstdSeekTable,
+    offset: u64,
+) -> anyhow::Result<CompressedReadInstruction> {
+    let frame_index = seek_table
+        .find_frame_index(offset)
+        .with_context(|| format!("no frame for offset {}", offset))?;
+    let compressed_offset = seek_table.cumulative_compressed_sizes[frame_index];
+    let next_compressed_offset = seek_table
+        .cumulative_compressed_sizes
+        .get(frame_index + 1)
+        .context("Offset out of range (next_compressed_offset overflow)")?;
+    let compressed_size = next_compressed_offset - compressed_offset;
+    Ok(CompressedReadInstruction {
+        frame_index,
+        read_offset: compressed_offset,
+        read_size: compressed_size,
+    })
+}
+
+impl FileReadWriteAtVolatile for ZstdDisk {
+    fn read_at_volatile(&self, slice: VolatileSlice, offset: u64) -> io::Result<usize> {
+        let read_instruction = compresed_frame_read_instruction(&self.seek_table, offset)
+            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
+
+        let mut compressed_data = vec![0u8; read_instruction.read_size as usize];
+
+        let compressed_frame_slice = VolatileSlice::new(compressed_data.as_mut_slice());
+
+        self.file
+            .read_at_volatile(compressed_frame_slice, read_instruction.read_offset)
+            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
+
+        let mut decompressor: zstd::bulk::Decompressor<'_> = zstd::bulk::Decompressor::new()?;
+        let mut decompressed_data = Vec::with_capacity(ZSTD_DEFAULT_FRAME_SIZE);
+        let decoded_size =
+            decompressor.decompress_to_buffer(&compressed_data, &mut decompressed_data)?;
+
+        let decompressed_offset_in_frame =
+            offset - self.seek_table.cumulative_decompressed_sizes[read_instruction.frame_index];
+
+        if decompressed_offset_in_frame >= decoded_size as u64 {
+            return Err(io::Error::new(
+                io::ErrorKind::InvalidData,
+                "BUG: Frame offset larger than decoded size",
+            ));
+        }
+
+        let read_len = min(
+            slice.size() as u64,
+            (decoded_size as u64) - decompressed_offset_in_frame,
+        ) as usize;
+        let data_to_copy = &decompressed_data[decompressed_offset_in_frame as usize..][..read_len];
+        slice
+            .sub_slice(0, read_len)
+            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
+            .copy_from(data_to_copy);
+        Ok(data_to_copy.len())
+    }
+
+    fn write_at_volatile(&self, _slice: VolatileSlice, _offset: u64) -> io::Result<usize> {
+        Err(io::Error::new(
+            io::ErrorKind::PermissionDenied,
+            "unsupported operation",
+        ))
+    }
+}
+
+pub struct AsyncZstdDisk {
+    inner: IoSource<File>,
+    seek_table: ZstdSeekTable,
+}
+
+impl ToAsyncDisk for ZstdDisk {
+    fn to_async_disk(self: Box<Self>, ex: &Executor) -> DiskResult<Box<dyn AsyncDisk>> {
+        Ok(Box::new(AsyncZstdDisk {
+            inner: ex.async_from(self.file).map_err(DiskError::ToAsync)?,
+            seek_table: self.seek_table,
+        }))
+    }
+}
+
+impl DiskGetLen for AsyncZstdDisk {
+    fn get_len(&self) -> io::Result<u64> {
+        self.seek_table
+            .cumulative_decompressed_sizes
+            .last()
+            .copied()
+            .ok_or(io::ErrorKind::InvalidData.into())
+    }
+}
+
+impl FileSetLen for AsyncZstdDisk {
+    fn set_len(&self, _len: u64) -> io::Result<()> {
+        Err(io::Error::new(
+            io::ErrorKind::PermissionDenied,
+            "unsupported operation",
+        ))
+    }
+}
+
+impl FileAllocate for AsyncZstdDisk {
+    fn allocate(&self, _offset: u64, _length: u64) -> io::Result<()> {
+        Err(io::Error::new(
+            io::ErrorKind::PermissionDenied,
+            "unsupported operation",
+        ))
+    }
+}
+
+#[async_trait(?Send)]
+impl AsyncDisk for AsyncZstdDisk {
+    async fn flush(&self) -> DiskResult<()> {
+        // zstd is read-only, nothing to flush.
+        Ok(())
+    }
+
+    async fn fsync(&self) -> DiskResult<()> {
+        // Do nothing because it's read-only.
+        Ok(())
+    }
+
+    async fn fdatasync(&self) -> DiskResult<()> {
+        // Do nothing because it's read-only.
+        Ok(())
+    }
+
+    /// Reads data from `file_offset` of decompressed disk image till the end of current
+    /// zstd frame and write them into memory `mem` at `mem_offsets`. This function should
+    /// function the same as running `preadv()` on decompressed zstd image and reading into
+    /// the array of `iovec`s specified with `mem` and `mem_offsets`.
+    async fn read_to_mem<'a>(
+        &'a self,
+        file_offset: u64,
+        mem: Arc<dyn BackingMemory + Send + Sync>,
+        mem_offsets: cros_async::MemRegionIter<'a>,
+    ) -> DiskResult<usize> {
+        let read_instruction = compresed_frame_read_instruction(&self.seek_table, file_offset)
+            .map_err(|e| DiskError::ReadingData(io::Error::new(io::ErrorKind::InvalidData, e)))?;
+
+        let compressed_data = vec![0u8; read_instruction.read_size as usize];
+
+        let (compressed_read_size, compressed_data) = self
+            .inner
+            .read_to_vec(Some(read_instruction.read_offset), compressed_data)
+            .await
+            .map_err(|e| DiskError::ReadingData(io::Error::new(ErrorKind::Other, e)))?;
+
+        if compressed_read_size != read_instruction.read_size as usize {
+            return Err(DiskError::ReadingData(io::Error::new(
+                ErrorKind::UnexpectedEof,
+                "Read from compressed data result in wrong length",
+            )));
+        }
+
+        let mut decompressor: zstd::bulk::Decompressor<'_> =
+            zstd::bulk::Decompressor::new().map_err(DiskError::ReadingData)?;
+        let mut decompressed_data = Vec::with_capacity(ZSTD_DEFAULT_FRAME_SIZE);
+        let decoded_size = decompressor
+            .decompress_to_buffer(&compressed_data, &mut decompressed_data)
+            .map_err(DiskError::ReadingData)?;
+
+        let decompressed_offset_in_frame = file_offset
+            - self.seek_table.cumulative_decompressed_sizes[read_instruction.frame_index];
+
+        if decompressed_offset_in_frame as usize > decoded_size {
+            return Err(DiskError::ReadingData(io::Error::new(
+                ErrorKind::InvalidData,
+                "BUG: Frame offset larger than decoded size",
+            )));
+        }
+
+        // Copy the decompressed data to the provided memory regions.
+        let mut total_copied = 0;
+        for mem_region in mem_offsets {
+            let src_slice =
+                &decompressed_data[decompressed_offset_in_frame as usize + total_copied..];
+            let dst_slice = mem
+                .get_volatile_slice(mem_region)
+                .map_err(DiskError::GuestMemory)?;
+
+            let to_copy = min(src_slice.len(), dst_slice.size());
+
+            if to_copy > 0 {
+                dst_slice
+                    .sub_slice(0, to_copy)
+                    .map_err(|e| DiskError::ReadingData(io::Error::new(ErrorKind::Other, e)))?
+                    .copy_from(&src_slice[..to_copy]);
+
+                total_copied += to_copy;
+
+                // if fully copied destination buffers, break the loop.
+                if total_copied == dst_slice.size() {
+                    break;
+                }
+            }
+        }
+
+        Ok(total_copied)
+    }
+
+    async fn write_from_mem<'a>(
+        &'a self,
+        _file_offset: u64,
+        _mem: Arc<dyn BackingMemory + Send + Sync>,
+        _mem_offsets: cros_async::MemRegionIter<'a>,
+    ) -> DiskResult<usize> {
+        Err(DiskError::UnsupportedOperation)
+    }
+
+    async fn punch_hole(&self, _file_offset: u64, _length: u64) -> DiskResult<()> {
+        Err(DiskError::UnsupportedOperation)
+    }
+
+    async fn write_zeroes_at(&self, _file_offset: u64, _length: u64) -> DiskResult<()> {
+        Err(DiskError::UnsupportedOperation)
+    }
+}
+
+impl DiskFile for ZstdDisk {}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test_find_frame_index_empty() {
+        let seek_table = ZstdSeekTable {
+            cumulative_decompressed_sizes: vec![0],
+            cumulative_compressed_sizes: vec![0],
+        };
+        assert_eq!(seek_table.find_frame_index(0), None);
+        assert_eq!(seek_table.find_frame_index(5), None);
+    }
+
+    #[test]
+    fn test_find_frame_index_single_frame() {
+        let seek_table = ZstdSeekTable {
+            cumulative_decompressed_sizes: vec![0, 100],
+            cumulative_compressed_sizes: vec![0, 50],
+        };
+        assert_eq!(seek_table.find_frame_index(0), Some(0));
+        assert_eq!(seek_table.find_frame_index(50), Some(0));
+        assert_eq!(seek_table.find_frame_index(99), Some(0));
+        assert_eq!(seek_table.find_frame_index(100), None);
+    }
+
+    #[test]
+    fn test_find_frame_index_multiple_frames() {
+        let seek_table = ZstdSeekTable {
+            cumulative_decompressed_sizes: vec![0, 100, 300, 500],
+            cumulative_compressed_sizes: vec![0, 50, 120, 200],
+        };
+        assert_eq!(seek_table.find_frame_index(0), Some(0));
+        assert_eq!(seek_table.find_frame_index(99), Some(0));
+        assert_eq!(seek_table.find_frame_index(100), Some(1));
+        assert_eq!(seek_table.find_frame_index(299), Some(1));
+        assert_eq!(seek_table.find_frame_index(300), Some(2));
+        assert_eq!(seek_table.find_frame_index(499), Some(2));
+        assert_eq!(seek_table.find_frame_index(500), None);
+        assert_eq!(seek_table.find_frame_index(1000), None);
+    }
+
+    #[test]
+    fn test_find_frame_index_with_skippable_frames() {
+        let seek_table = ZstdSeekTable {
+            cumulative_decompressed_sizes: vec![0, 100, 100, 100, 300],
+            cumulative_compressed_sizes: vec![0, 50, 60, 70, 150],
+        };
+        assert_eq!(seek_table.find_frame_index(0), Some(0));
+        assert_eq!(seek_table.find_frame_index(99), Some(0));
+        // Correctly skips the skippable frames.
+        assert_eq!(seek_table.find_frame_index(100), Some(3));
+        assert_eq!(seek_table.find_frame_index(299), Some(3));
+        assert_eq!(seek_table.find_frame_index(300), None);
+    }
+
+    #[test]
+    fn test_find_frame_index_with_last_skippable_frame() {
+        let seek_table = ZstdSeekTable {
+            cumulative_decompressed_sizes: vec![0, 20, 40, 40, 60, 60, 80, 80],
+            cumulative_compressed_sizes: vec![0, 10, 20, 30, 40, 50, 60, 70],
+        };
+        assert_eq!(seek_table.find_frame_index(0), Some(0));
+        assert_eq!(seek_table.find_frame_index(20), Some(1));
+        assert_eq!(seek_table.find_frame_index(21), Some(1));
+        assert_eq!(seek_table.find_frame_index(79), Some(5));
+        assert_eq!(seek_table.find_frame_index(80), None);
+        assert_eq!(seek_table.find_frame_index(300), None);
+    }
+}
diff --git a/docs/book/src/appendix/memory_layout.md b/docs/book/src/appendix/memory_layout.md
index 14d0f92a0..33b82f0d6 100644
--- a/docs/book/src/appendix/memory_layout.md
+++ b/docs/book/src/appendix/memory_layout.md
@@ -62,13 +62,12 @@ These apply for all boot modes.
 | [`SERIAL_ADDR[0]`][serial_addr]   | `3f8`           | `400`           | 8 bytes        | Serial port MMIO                                              |
 | [`AARCH64_RTC_ADDR`]              | `2000`          | `3000`          | 4 KiB          | Real-time clock                                               |
 | [`AARCH64_VMWDT_ADDR`]            | `3000`          | `4000`          | 4 KiB          | Watchdog device                                               |
-| [`AARCH64_PCI_CFG_BASE`]          | `1_0000`        | `2_0000`        | 64 KiB         | PCI configuration (CAM)                                       |
+| [`AARCH64_PCI_CAM_BASE_DEFAULT`]  | `1_0000`        | `101_0000`      | 16 MiB         | PCI configuration (CAM)                                       |
 | [`AARCH64_VIRTFREQ_BASE`]         | `104_0000`      | `105_0000`      | 64 KiB         | Virtual cpufreq device                                        |
-| [`AARCH64_PVTIME_IPA_START`]      | `1f0_0000`      | `200_0000`      | 64 KiB         | Paravirtualized time                                          |
-| [`AARCH64_MMIO_BASE`]             | `200_0000`      | `400_0000`      | 32 MiB         | Low MMIO allocation area                                      |
+| [`AARCH64_PVTIME_IPA_START`]      | `1ff_0000`      | `200_0000`      | 64 KiB         | Paravirtualized time                                          |
+| [`AARCH64_PCI_CAM_BASE_DEFAULT`]  | `200_0000`      | `400_0000`      | 32 MiB         | Low MMIO allocation area                                      |
 | [`AARCH64_GIC_CPUI_BASE`]         | `3ffd_0000`     | `3fff_0000`     | 128 KiB        | vGIC                                                          |
 | [`AARCH64_GIC_DIST_BASE`]         | `3fff_0000`     | `4000_0000`     | 64 KiB         | vGIC                                                          |
-| [`AARCH64_AXI_BASE`]              | `4000_0000`     |                 |                | Seemingly unused? Is this hard-coded somewhere in the kernel? |
 | [`AARCH64_PROTECTED_VM_FW_START`] | `7fc0_0000`     | `8000_0000`     | 4 MiB          | pVM firmware (if running a protected VM)                      |
 | [`AARCH64_PHYS_MEM_START`]        | `8000_0000`     |                 | --mem size     | RAM (starts at IPA = 2 GiB)                                   |
 | [`plat_mmio_base`]                | after RAM       | +0x800000       | 8 MiB          | Platform device MMIO region                                   |
@@ -106,12 +105,11 @@ with a 16 MiB alignment.
 [serial_addr]: https://crsrc.org/o/src/platform/crosvm/arch/src/serial.rs;l=78?q=SERIAL_ADDR
 [`aarch64_rtc_addr`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=177?q=AARCH64_RTC_ADDR
 [`aarch64_vmwdt_addr`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=187?q=AARCH64_VMWDT_ADDR
-[`aarch64_pci_cfg_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=192?q=AARCH64_PCI_CFG_BASE
+[`aarch64_pci_cfg_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=192?q=AARCH64_PCI_CAM_BASE_DEFAULT
 [`aarch64_virtfreq_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=207?q=AARCH64_VIRTFREQ_BASE
-[`aarch64_mmio_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=196?q=AARCH64_MMIO_BASE
+[`aarch64_mmio_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=196?q=AARCH64_PCI_CAM_BASE_DEFAULT
 [`aarch64_gic_cpui_base`]: https://crsrc.org/o/src/platform/crosvm/devices/src/irqchip/kvm/aarch64.rs;l=106?q=AARCH64_GIC_CPUI_BASE
 [`aarch64_gic_dist_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=105?q=AARCH64_GIC_DIST_BASE
-[`aarch64_axi_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=86?q=AARCH64_AXI_BASE
 [`aarch64_pvtime_ipa_start`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=100?q=AARCH64_PVTIME_IPA_START
 [`aarch64_protected_vm_fw_start`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=96?q=AARCH64_PROTECTED_VM_FW_START
 [`aarch64_phys_mem_start`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=85?q=AARCH64_PHYS_MEM_START
diff --git a/docs/book/src/appendix/rutabaga_gfx.md b/docs/book/src/appendix/rutabaga_gfx.md
index 2b9ec7976..ac35364ce 100644
--- a/docs/book/src/appendix/rutabaga_gfx.md
+++ b/docs/book/src/appendix/rutabaga_gfx.md
@@ -105,11 +105,12 @@ ninja -C client-build/ install
 
 ## Build gfxstream guest
 
-The same repo as gfxstream host is used, but with a different build configuration.
+Mesa provides gfxstream vulkan guest libraries.
 
 ```sh
-cd $(gfxstream_dir)
-meson setup guest-build/ -Dgfxstream-build=guest
+git clone https://gitlab.freedesktop.org/mesa/mesa.git
+cd mesa
+meson setup guest-build/ -Dvulkan-drivers="gfxstream-experimental" -Dgallium-drivers="" -Dopengl=false
 ninja -C guest-build/
 ```
 
@@ -127,7 +128,8 @@ In another terminal, run:
 ```sh
 export MESA_LOADER_DRIVER_OVERRIDE=zink
 export VIRTGPU_KUMQUAT=1
-export VK_ICD_FILENAMES=$(gfxstream_dir)/guest-build/guest/vulkan/gfxstream_vk_devenv_icd.x86_64.json
+export VK_ICD_FILENAMES=$(mesa_dir)/guest-build/src/gfxstream/guest/vulkan/gfxstream_vk_devenv_icd.x86_64.json
+
 vkcube
 ```
 
@@ -139,19 +141,12 @@ To test gfxstream with Debian guests, make sure your display environment is head
 systemctl set-default multi-user.target
 ```
 
-Build gfxstream-vk:
-
-```sh
-cd $(gfxstream_dir)
-meson setup guest-build/ -Dgfxstream-build=guest
-ninja -C guest-build/
-```
-
-Start the compositor:
+Build gfxstream guest as previously and start the compositor. The `VIRTGPU_KUMQUAT` variable is no
+longer needed:
 
 ```sh
 export MESA_LOADER_DRIVER_OVERRIDE=zink
-export VK_ICD_FILENAMES=$(gfxstream_dir)/guest-build/guest/vulkan/gfxstream_vk_devenv_icd.x86_64.json
+export VK_ICD_FILENAMES=$(mesa_dir)/guest-build/src/gfxstream/guest/vulkan/gfxstream_vk_devenv_icd.x86_64.json
 weston --backend=drm
 ```
 
@@ -161,6 +156,7 @@ To contribute to gfxstream without an Android tree:
 
 ```sh
 git clone https://android.googlesource.com/platform/hardware/google/gfxstream
+cd gfxstream/
 git commit -a -m blah
 git push origin HEAD:refs/for/main
 ```
diff --git a/docs/book/src/building_crosvm/index.md b/docs/book/src/building_crosvm/index.md
index d43218d76..ad28c191a 100644
--- a/docs/book/src/building_crosvm/index.md
+++ b/docs/book/src/building_crosvm/index.md
@@ -2,6 +2,8 @@
 
 This chapter describes how to build crosvm on each host OS:
 
+Pre-requisite: install [Rust](https://www.rust-lang.org/).
+
 - [Linux](./linux.md)
 - [Windows](./windows.md)
 
diff --git a/docs/book/src/devices/input.md b/docs/book/src/devices/input.md
index 0efa6dccc..3631abeb8 100644
--- a/docs/book/src/devices/input.md
+++ b/docs/book/src/devices/input.md
@@ -180,3 +180,60 @@ crosvm run \
   --input trackpad[path=/tmp/trackpad-socket,width=1920,height=1080,name=mytouch1]
   ...
 ```
+
+### Custom
+
+Add a custom virtio-input device.
+
+- `path` (required): path to event source socket
+- `config_path` (required): path to file configuring device
+
+```sh
+crosvm run \
+  --input custom[path=/tmp/keyboard-socket,config-path=/tmp/custom-keyboard-config.json] \
+  ...
+```
+
+This config_path requires a JSON-formatted configuration file. "events" configures the supported
+events. "name" defines the customized device name, "serial" defines customized serial name. The
+properties and axis info are yet to be supported.
+
+Here is an example of event config file:
+
+```
+{
+  "name": "Virtio Custom",
+  "serial_name": "virtio-custom",
+  "events": [
+    {
+      "event_type": "EV_KEY",
+      "event_type_code": 1,
+      "supported_events": {
+        "KEY_ESC": 1,
+        "KEY_1": 2,
+        "KEY_2": 3,
+        "KEY_A": 30,
+        "KEY_B": 48,
+        "KEY_SPACE": 57
+      }
+    },
+    {
+      "event_type": "EV_REP",
+      "event_type_code": 20,
+      "supported_events": {
+        "REP_DELAY": 0,
+        "REP_PERIOD": 1
+      }
+    },
+    {
+      "event_type": "EV_LED",
+      "event_type_code": 17,
+      "supported_events": {
+        "LED_NUML": 0,
+        "LED_CAPSL": 1,
+        "LED_SCROLLL": 2
+      }
+    }
+  ]
+}
+```
diff --git a/docs/book/src/devices/vhost_user.md b/docs/book/src/devices/vhost_user.md
index d8de79b94..b2ccfb151 100644
--- a/docs/book/src/devices/vhost_user.md
+++ b/docs/book/src/devices/vhost_user.md
@@ -3,8 +3,9 @@
 Crosvm supports [vhost-user] devices for most virtio devices (block, net, etc ) so that device
 emulation can be done outside of the main vmm process.
 
-Here is a diagram showing how vhost-user block device back-end and a vhost-user block front-end in
-crosvm VMM work together.
+Here is a diagram showing how vhost-user block device back-end (implementing the actual disk in
+userspace) and a vhost-user block front-end (implementing the device facing the guest OS) in crosvm
+VMM work together.
 
 <!-- Image from https://docs.google.com/presentation/d/1s6wH5L_F8NNiXls5UgWbD34jtBmijoZuiyLu76Fc2NM/edit#slide=id.ge5067b4ec2_0_55 -->
 
@@ -28,7 +29,7 @@ VHOST_USER_SOCK=/tmp/vhost-user.socket
 crosvm devices --block vhost=${VHOST_USER_SOCK},path=disk.img
 ```
 
-Then, open another terminal and start a vmm process with `--vhost-user` flag.
+Then, open another terminal and start a vmm process with `--vhost-user` flag (the frontend).
 
 ```sh
 crosvm run \
@@ -39,4 +40,4 @@ crosvm run \
 
 As a result, `disk.img` should be exposed as `/dev/vda` just like with `--block disk.img`.
 
-[vhost-user]: https://qemu.readthedocs.io/en/latest/interop/vhost-user.html
+[vhost-user]: https://qemu-project.gitlab.io/qemu/interop/vhost-user.html
diff --git a/docs/book/src/testing/index.md b/docs/book/src/testing/index.md
index aeb43f807..58822dac7 100644
--- a/docs/book/src/testing/index.md
+++ b/docs/book/src/testing/index.md
@@ -84,7 +84,7 @@ If you require exclusive access to a device or file, you have to use
 [file-based locking](https://docs.rs/named-lock/latest/named_lock) to prevent access by other test
 processes.
 
-## Platorms tested
+## Platforms tested
 
 The platforms below can all be tested using `tools/run_tests -p $platform`. The table indicates how
 these tests are executed:
@@ -99,6 +99,33 @@ these tests are executed:
 
 Crosvm CI will use the same configuration as `tools/run_tests`.
 
+## Debugging Tips
+
+Here are some tips for developing or/and debugging crosvm tests.
+
+### Enter a test VM to see logs
+
+When you run a test on a VM with `./tools/run_tests --dut=vm`, if the test fails, you'll see
+extracted log messages. To see the full messages or monitor the test process during the runtime, you
+may want to enter the test VM.
+
+First, enter the VM's shell and start printing the syslog:
+
+```console
+$ ./tools/dev_container # Enter the dev_container
+$ ./tools/x86vm shell   # Enter the test VM
+crosvm@testvm-x8664:~$ journalctl -f
+# syslog messages will be printed...
+```
+
+Then, open another terminal and run a test:
+
+```console
+$ ./tools/run_tests --dut=vm --filter-expr 'package(e2e_tests) and test(boot)'
+```
+
+So you'll see the crosvm log in the first terminal.
+
 [^qemu-user]: qemu-aarch64-static or qemu-arm-static translate instructions into x86 and executes them on the
     host kernel. This works well for unit tests, but will fail when interacting with platform
     specific kernel features.
diff --git a/e2e_tests/fixture/src/sys/windows.rs b/e2e_tests/fixture/src/sys/windows.rs
index 61537a487..03762eb31 100644
--- a/e2e_tests/fixture/src/sys/windows.rs
+++ b/e2e_tests/fixture/src/sys/windows.rs
@@ -226,7 +226,7 @@ impl TestVmSys {
             "--kernel-log-file",
             hypervisor_log_str,
         ]);
-        command.args(&get_hypervisor_args());
+        command.args(get_hypervisor_args());
         command.args(cfg.extra_args);
 
         println!("Running command: {:?}", command);
diff --git a/e2e_tests/fixture/src/utils.rs b/e2e_tests/fixture/src/utils.rs
index 618b3ad1f..7346bc52b 100644
--- a/e2e_tests/fixture/src/utils.rs
+++ b/e2e_tests/fixture/src/utils.rs
@@ -209,7 +209,7 @@ pub fn create_vu_block_config(cmd_type: CmdType, socket: &Path, disk: &Path) ->
     match cmd_type {
         CmdType::Device => VuConfig::new(cmd_type, "block").extra_args(vec![
             "block".to_string(),
-            "--socket".to_string(),
+            "--socket-path".to_string(),
             socket_path.to_string(),
             "--file".to_string(),
             disk_path.to_string(),
@@ -229,7 +229,7 @@ pub fn create_vu_console_multiport_config(
 
     let mut args = vec![
         "console".to_string(),
-        "--socket".to_string(),
+        "--socket-path".to_string(),
         socket_path.to_string(),
     ];
 
diff --git a/e2e_tests/tests/fs.rs b/e2e_tests/tests/fs.rs
index 1e1a1c3f7..109790d70 100644
--- a/e2e_tests/tests/fs.rs
+++ b/e2e_tests/tests/fs.rs
@@ -170,7 +170,7 @@ pub fn create_vu_fs_config(socket: &Path, shared_dir: &Path, tag: &str) -> VuCon
     println!("socket={socket_path}, tag={tag}, shared_dir={shared_dir_path}");
     VuConfig::new(CmdType::Device, "vhost-user-fs").extra_args(vec![
         "fs".to_string(),
-        format!("--socket={socket_path}"),
+        format!("--socket-path={socket_path}"),
         format!("--shared-dir={shared_dir_path}"),
         format!("--tag={tag}"),
         format!("--uid-map=0 {uid} 1"),
@@ -213,3 +213,112 @@ fn vhost_user_fs_mount_rw() {
 
     mount_rw(vm, tag, temp_dir);
 }
+
+fn copy_file_validate_ugid_mapping(
+    mut vm: TestVm,
+    tag: &str,
+    dir: TempDir,
+    mapped_uid: u32,
+    mapped_gid: u32,
+) {
+    use std::os::linux::fs::MetadataExt;
+    const ORIGINAL_FILE_NAME: &str = "original.txt";
+    const NEW_FILE_NAME: &str = "new.txt";
+    const TEST_DATA: &str = "Hello world!";
+
+    let orig_file = dir.path().join(ORIGINAL_FILE_NAME);
+
+    std::fs::write(orig_file, TEST_DATA).unwrap();
+
+    vm.exec_in_guest(&format!(
+        "mount -t virtiofs {tag} /mnt && cp /mnt/{} /mnt/{} && sync",
+        ORIGINAL_FILE_NAME, NEW_FILE_NAME,
+    ))
+    .unwrap();
+
+    let output = vm
+        .exec_in_guest(&format!("stat /mnt/{}", ORIGINAL_FILE_NAME,))
+        .unwrap();
+
+    assert!(output.stdout.contains(&format!("Uid: ({}/", mapped_uid)));
+    assert!(output.stdout.contains(&format!("Gid: ({}/", mapped_gid)));
+
+    let new_file = dir.path().join(NEW_FILE_NAME);
+    let output_stat = std::fs::metadata(new_file.clone());
+
+    assert_eq!(
+        output_stat
+            .as_ref()
+            .expect("stat of new_file failed")
+            .st_uid(),
+        base::geteuid()
+    );
+    assert_eq!(
+        output_stat
+            .as_ref()
+            .expect("stat of new_file failed")
+            .st_gid(),
+        base::getegid()
+    );
+
+    let contents = std::fs::read(new_file).unwrap();
+    assert_eq!(TEST_DATA.as_bytes(), &contents);
+}
+
+pub fn create_ugid_map_config(
+    socket: &Path,
+    shared_dir: &Path,
+    tag: &str,
+    mapped_uid: u32,
+    mapped_gid: u32,
+) -> VuConfig {
+    let socket_path = socket.to_str().unwrap();
+    let shared_dir_path = shared_dir.to_str().unwrap();
+
+    let uid = base::geteuid();
+    let gid = base::getegid();
+    let ugid_map_value = format!("{} {} {} {} 7 /", mapped_uid, mapped_gid, uid, gid,);
+
+    let cfg_arg = format!("writeback=true,ugid_map='{}'", ugid_map_value);
+
+    println!("socket={socket_path}, tag={tag}, shared_dir={shared_dir_path}");
+
+    VuConfig::new(CmdType::Device, "vhost-user-fs").extra_args(vec![
+        "fs".to_string(),
+        format!("--socket-path={socket_path}"),
+        format!("--shared-dir={shared_dir_path}"),
+        format!("--tag={tag}"),
+        format!("--cfg={cfg_arg}"),
+        format!("--disable-sandbox"),
+        format!("--skip-pivot-root=true"),
+    ])
+}
+
+/// Tests file copy with disabled sandbox
+///
+/// 1. Create `original.txt` on a temporal directory.
+/// 2. Setup ugid_map for vhost-user-fs backend
+/// 3. Start a VM with a virtiofs device for the temporal directory.
+/// 4. Copy `original.txt` to `new.txt` in the guest.
+/// 5. Check that `new.txt` is created in the host.
+/// 6. Verify the UID/GID of the files both in the guest and the host.
+#[test]
+fn vhost_user_fs_without_sandbox_and_pivot_root() {
+    let socket = NamedTempFile::new().unwrap();
+    let temp_dir = tempfile::tempdir().unwrap();
+
+    let config = Config::new();
+    let tag = "android";
+
+    let mapped_uid = 123456;
+    let mapped_gid = 12345;
+    let vu_config =
+        create_ugid_map_config(socket.path(), temp_dir.path(), tag, mapped_uid, mapped_gid);
+
+    let _vu_device = VhostUserBackend::new(vu_config).unwrap();
+
+    let config = config.with_vhost_user_fs(socket.path(), tag);
+    let vm = TestVm::new(config).unwrap();
+
+    copy_file_validate_ugid_mapping(vm, tag, temp_dir, mapped_uid, mapped_gid);
+}
diff --git a/e2e_tests/tests/pmem_ext2.rs b/e2e_tests/tests/pmem_ext2.rs
index 34b6d00be..bf3779e98 100644
--- a/e2e_tests/tests/pmem_ext2.rs
+++ b/e2e_tests/tests/pmem_ext2.rs
@@ -104,8 +104,8 @@ fn pmem_ext2_manyfiles() -> anyhow::Result<()> {
 
     let temp_dir = tempfile::tempdir()?;
     for i in 0..1000 {
-        let f = temp_dir.path().join(&format!("{i}.txt"));
-        std::fs::write(f, &format!("{i}"))?;
+        let f = temp_dir.path().join(format!("{i}.txt"));
+        std::fs::write(f, format!("{i}"))?;
     }
 
     let config = Config::new().extra_args(vec![
diff --git a/e2e_tests/tests/snd.rs b/e2e_tests/tests/snd.rs
index e7e7c4d35..3a5b4c37f 100644
--- a/e2e_tests/tests/snd.rs
+++ b/e2e_tests/tests/snd.rs
@@ -48,7 +48,7 @@ fn do_playback_with_vhost_user() {
         "snd".to_string(),
         "--config".to_string(),
         get_virtio_snd_args(temp_dir_path_str),
-        "--socket".to_string(),
+        "--socket-path".to_string(),
         socket_path_str.to_string(),
     ]);
     let _vu_device = VhostUserBackend::new(vu_config).unwrap();
diff --git a/e2e_tests/tests/vsock.rs b/e2e_tests/tests/vsock.rs
index 361c925c2..1cb24dc12 100644
--- a/e2e_tests/tests/vsock.rs
+++ b/e2e_tests/tests/vsock.rs
@@ -268,7 +268,7 @@ fn create_vu_config(cmd_type: CmdType, socket: &Path, cid: u32) -> VuConfig {
     match cmd_type {
         CmdType::Device => VuConfig::new(cmd_type, "vsock").extra_args(vec![
             "vsock".to_string(),
-            "--socket".to_string(),
+            "--socket-path".to_string(),
             socket_path.to_string(),
             "--cid".to_string(),
             cid.to_string(),
diff --git a/ext2/examples/mkfs.rs b/ext2/examples/mkfs.rs
index 7613ae01a..8621c23cf 100644
--- a/ext2/examples/mkfs.rs
+++ b/ext2/examples/mkfs.rs
@@ -8,7 +8,7 @@
 mod linux {
     use std::fs::OpenOptions;
     use std::io::Write;
-    use std::path::Path;
+    use std::path::PathBuf;
 
     use argh::FromArgs;
     use base::MappedRegion;
@@ -44,16 +44,14 @@ mod linux {
 
     pub fn main() -> anyhow::Result<()> {
         let args: Args = argh::from_env();
-        let src_dir = args.src.as_ref().map(|s| Path::new(s.as_str()));
+        let src_dir = args.src.as_ref().map(|s| PathBuf::new().join(s));
         let builder = ext2::Builder {
             blocks_per_group: args.blocks_per_group,
             inodes_per_group: args.inodes_per_group,
             size: args.size,
+            root_dir: src_dir,
         };
-        let mem = builder
-            .allocate_memory()?
-            .build_mmap_info(src_dir)?
-            .do_mmap()?;
+        let mem = builder.allocate_memory()?.build_mmap_info()?.do_mmap()?;
         if args.dry_run {
             println!("Done!");
             return Ok(());
diff --git a/ext2/src/blockgroup.rs b/ext2/src/blockgroup.rs
index 456524ae5..6b01f5900 100644
--- a/ext2/src/blockgroup.rs
+++ b/ext2/src/blockgroup.rs
@@ -147,6 +147,7 @@ mod test {
                 inodes_per_group: 1024,
                 blocks_per_group,
                 size,
+                root_dir: None,
             },
         )
         .unwrap();
@@ -200,6 +201,7 @@ mod test {
                 inodes_per_group: 512,
                 blocks_per_group,
                 size: mem_size,
+                root_dir: None,
             },
         )
         .unwrap();
diff --git a/ext2/src/builder.rs b/ext2/src/builder.rs
index 0c0365fe1..4f773a798 100644
--- a/ext2/src/builder.rs
+++ b/ext2/src/builder.rs
@@ -4,7 +4,7 @@
 
 //! Provides structs and logic to build ext2 file system with configurations.
 
-use std::path::Path;
+use std::path::PathBuf;
 
 use anyhow::bail;
 use anyhow::Context;
@@ -29,6 +29,8 @@ pub struct Builder {
     pub inodes_per_group: u32,
     /// The size of the memory region.
     pub size: u32,
+    /// The roof directory to be copied to the file system.
+    pub root_dir: Option<PathBuf>,
 }
 
 impl Default for Builder {
@@ -37,6 +39,7 @@ impl Default for Builder {
             blocks_per_group: 4096,
             inodes_per_group: 4096,
             size: 4096 * 4096,
+            root_dir: None,
         }
     }
 }
@@ -88,10 +91,10 @@ pub struct MemRegion {
 
 impl MemRegion {
     /// Constructs an ext2 metadata by traversing `src_dir`.
-    pub fn build_mmap_info(mut self, src_dir: Option<&Path>) -> Result<MemRegionWithMappingInfo> {
+    pub fn build_mmap_info(mut self) -> Result<MemRegionWithMappingInfo> {
         let arena = Arena::new(BLOCK_SIZE, &mut self.mem).context("failed to allocate arena")?;
         let mut ext2 = Ext2::new(&self.cfg, &arena).context("failed to create Ext2 struct")?;
-        if let Some(dir) = src_dir {
+        if let Some(dir) = self.cfg.root_dir {
             ext2.copy_dirtree(&arena, dir)
                 .context("failed to copy directory tree")?;
         }
diff --git a/ext2/src/fs.rs b/ext2/src/fs.rs
index 6cf8b818d..aafa75ea7 100644
--- a/ext2/src/fs.rs
+++ b/ext2/src/fs.rs
@@ -34,6 +34,7 @@ use crate::inode::InodeBlocksCount;
 use crate::inode::InodeNum;
 use crate::inode::InodeType;
 use crate::superblock::SuperBlock;
+use crate::xattr::InlineXattrs;
 
 #[repr(C)]
 #[derive(Copy, Clone, FromZeroes, FromBytes, AsBytes, Debug)]
@@ -132,7 +133,7 @@ impl DirEntryBlock<'_> {
 }
 
 /// A struct to represent an ext2 filesystem.
-pub struct Ext2<'a> {
+pub(crate) struct Ext2<'a> {
     sb: &'a mut SuperBlock,
     cur_block_group: usize,
     cur_inode_table: usize,
@@ -143,10 +144,8 @@ pub struct Ext2<'a> {
 }
 
 impl<'a> Ext2<'a> {
-    /// Create a new ext2 filesystem.
-    pub(crate) fn new(cfg: &Builder, arena: &'a Arena<'a>) -> Result<Self> {
-        let sb = SuperBlock::new(arena, cfg)?;
-
+    pub(crate) fn new(builder: &Builder, arena: &'a Arena<'a>) -> Result<Self> {
+        let sb = SuperBlock::new(arena, builder)?;
         let mut group_metadata = vec![];
         for i in 0..sb.num_groups() {
             group_metadata.push(GroupMetaData::new(arena, sb, i)?);
@@ -162,13 +161,18 @@ impl<'a> Ext2<'a> {
 
         // Add rootdir
         let root_inode = InodeNum::new(2)?;
-        ext2.add_reserved_dir(arena, root_inode, root_inode, OsStr::new("/"))?;
+        let root_xattr = match &builder.root_dir {
+            Some(dir) => Some(InlineXattrs::from_path(dir)?),
+            None => None,
+        };
+        ext2.add_reserved_dir(arena, root_inode, root_inode, OsStr::new("/"), root_xattr)?;
         let lost_found_inode = ext2.allocate_inode()?;
         ext2.add_reserved_dir(
             arena,
             lost_found_inode,
             root_inode,
             OsStr::new("lost+found"),
+            None,
         )?;
 
         Ok(ext2)
@@ -376,6 +380,7 @@ impl<'a> Ext2<'a> {
         inode_num: InodeNum,
         parent_inode: InodeNum,
         name: &OsStr,
+        xattr: Option<InlineXattrs>,
     ) -> Result<()> {
         let group_id = self.group_num_for_inode(inode_num);
         let inode = Inode::new(
@@ -384,6 +389,7 @@ impl<'a> Ext2<'a> {
             inode_num,
             InodeType::Directory,
             BLOCK_SIZE as u32,
+            xattr,
         )?;
         self.add_inode(inode_num, inode)?;
 
@@ -418,6 +424,7 @@ impl<'a> Ext2<'a> {
     ) -> Result<()> {
         let group_id = self.group_num_for_inode(inode_num);
 
+        let xattr = InlineXattrs::from_path(path)?;
         let inode = Inode::from_metadata(
             arena,
             &mut self.group_metadata[group_id],
@@ -427,6 +434,7 @@ impl<'a> Ext2<'a> {
             0,
             InodeBlocksCount::from_bytes_len(0),
             InodeBlock::default(),
+            Some(xattr),
         )?;
 
         self.add_inode(inode_num, inode)?;
@@ -602,6 +610,8 @@ impl<'a> Ext2<'a> {
         let blocks = InodeBlocksCount::from_bytes_len((used_blocks * BLOCK_SIZE) as u32);
         let group_id = self.group_num_for_inode(inode_num);
         let size = file_size as u32;
+
+        let xattr = InlineXattrs::from_path(path)?;
         let inode = Inode::from_metadata(
             arena,
             &mut self.group_metadata[group_id],
@@ -611,10 +621,10 @@ impl<'a> Ext2<'a> {
             1,
             blocks,
             block,
+            Some(xattr),
         )?;
 
         self.add_inode(inode_num, inode)?;
-
         self.allocate_dir_entry(arena, parent_inode, inode_num, InodeType::Regular, name)?;
 
         Ok(())
@@ -640,6 +650,7 @@ impl<'a> Ext2<'a> {
         let mut block = InodeBlock::default();
         block.set_inline_symlink(dst)?;
         let group_id = self.group_num_for_inode(inode_num);
+        let xattr = InlineXattrs::from_path(&link)?;
         let inode = Inode::from_metadata(
             arena,
             &mut self.group_metadata[group_id],
@@ -649,6 +660,7 @@ impl<'a> Ext2<'a> {
             1, //links_count,
             InodeBlocksCount::from_bytes_len(0),
             block,
+            Some(xattr),
         )?;
         self.add_inode(inode_num, inode)?;
 
@@ -680,6 +692,7 @@ impl<'a> Ext2<'a> {
         block.set_direct_blocks(&[symlink_block])?;
 
         let group_id = self.group_num_for_inode(inode_num);
+        let xattr = InlineXattrs::from_path(link)?;
         let inode = Inode::from_metadata(
             arena,
             &mut self.group_metadata[group_id],
@@ -689,6 +702,7 @@ impl<'a> Ext2<'a> {
             1, //links_count,
             InodeBlocksCount::from_bytes_len(BLOCK_SIZE as u32),
             block,
+            Some(xattr),
         )?;
         self.add_inode(inode_num, inode)?;
 
diff --git a/ext2/src/inode.rs b/ext2/src/inode.rs
index 29dda22d6..320d3d832 100644
--- a/ext2/src/inode.rs
+++ b/ext2/src/inode.rs
@@ -4,6 +4,7 @@
 
 //! Defines the inode structure.
 
+use std::mem::MaybeUninit;
 use std::os::unix::fs::MetadataExt;
 
 use anyhow::bail;
@@ -16,6 +17,7 @@ use zerocopy_derive::FromZeroes;
 use crate::arena::Arena;
 use crate::arena::BlockId;
 use crate::blockgroup::GroupMetaData;
+use crate::xattr::InlineXattrs;
 
 /// Types of inodes.
 #[derive(Debug, PartialEq, Eq, Clone, Copy, N)]
@@ -170,7 +172,7 @@ impl InodeBlock {
 ///
 /// The field names are based on [the specification](https://www.nongnu.org/ext2-doc/ext2.html#inode-table).
 #[repr(C)]
-#[derive(Default, Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
+#[derive(Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
 pub(crate) struct Inode {
     mode: u16,
     uid: u16,
@@ -194,7 +196,24 @@ pub(crate) struct Inode {
     _reserved1: u16,
     uid_high: u16,
     gid_high: u16,
-    _reserved2: u32,
+    _reserved2: u32, // 128-th byte
+
+    // We don't use any inode metadata region beyond the basic 128 bytes.
+    // However set `extra_size` to the minimum value to let Linux kernel know that there are
+    // inline extended attribute data. The minimum possible is 4 bytes, so define extra_size
+    // and add the next padding.
+    pub extra_size: u16,
+    _paddings: u16, // padding for 32-bit alignment
+}
+
+impl Default for Inode {
+    fn default() -> Self {
+        // SAFETY: zero-filled value is a valid value.
+        let mut r: Self = unsafe { MaybeUninit::zeroed().assume_init() };
+        // Set extra size to 4 for `extra_size` and `paddings` fields.
+        r.extra_size = 4;
+        r
+    }
 }
 
 /// Used in `Inode` to represent how many 512-byte blocks are used by a file.
@@ -219,17 +238,17 @@ impl InodeBlocksCount {
 
 impl Inode {
     /// Size of the inode record in bytes.
-    /// Its return value must be stored in `Superblock` and used to calculate the size of
-    /// inode tables.
+    ///
+    /// From ext2 revision 1, inode size larger than 128 bytes is supported.
+    /// We use 256 byte here, which is the default value for ext4.
     ///
     /// Note that inode "record" size can be larger that inode "structure" size.
     /// The gap between the end of the inode structure and the end of the inode record can be used
     /// to store extended attributes.
-    pub fn inode_record_size() -> u16 {
-        // TODO(b/333988434): Support larger inode size (258 bytes) for extended attributes.
-        const EXT2_GOOD_OLD_INODE_SIZE: u16 = 128;
-        EXT2_GOOD_OLD_INODE_SIZE
-    }
+    pub const INODE_RECORD_SIZE: usize = 256;
+
+    /// Size of the region that inline extended attributes can be written.
+    pub const XATTR_AREA_SIZE: usize = Inode::INODE_RECORD_SIZE - std::mem::size_of::<Inode>();
 
     pub fn new<'a>(
         arena: &'a Arena<'a>,
@@ -237,6 +256,7 @@ impl Inode {
         inode_num: InodeNum,
         typ: InodeType,
         size: u32,
+        xattr: Option<InlineXattrs>,
     ) -> Result<&'a mut Self> {
         const EXT2_S_IRUSR: u16 = 0x0100; // user read
         const EXT2_S_IXUSR: u16 = 0x0040; // user execute
@@ -245,7 +265,7 @@ impl Inode {
         const EXT2_S_IROTH: u16 = 0x0004; // others read
         const EXT2_S_IXOTH: u16 = 0x0001; // others execute
 
-        let inode_offset = inode_num.to_table_index() * Inode::inode_record_size() as usize;
+        let inode_offset = inode_num.to_table_index() * Inode::INODE_RECORD_SIZE;
         let inode =
             arena.allocate::<Inode>(BlockId::from(group.group_desc.inode_table), inode_offset)?;
 
@@ -271,7 +291,6 @@ impl Inode {
         let gid_high = (gid >> 16) as u16;
         let gid_low = gid as u16;
 
-        // TODO(b/333988434): Support extended attributes.
         *inode = Self {
             mode,
             size,
@@ -284,6 +303,10 @@ impl Inode {
             gid_high,
             ..Default::default()
         };
+        if let Some(xattr) = xattr {
+            Self::add_xattr(arena, group, inode, inode_offset, xattr)?;
+        }
+
         Ok(inode)
     }
 
@@ -296,11 +319,12 @@ impl Inode {
         links_count: u16,
         blocks: InodeBlocksCount,
         block: InodeBlock,
+        xattr: Option<InlineXattrs>,
     ) -> Result<&'a mut Self> {
         let inodes_per_group = group.inode_bitmap.len();
         // (inode_num - 1) because inode is 1-indexed.
         let inode_offset =
-            ((usize::from(inode_num) - 1) % inodes_per_group) * Inode::inode_record_size() as usize;
+            ((usize::from(inode_num) - 1) % inodes_per_group) * Inode::INODE_RECORD_SIZE;
         let inode =
             arena.allocate::<Inode>(BlockId::from(group.group_desc.inode_table), inode_offset)?;
 
@@ -333,9 +357,46 @@ impl Inode {
             ..Default::default()
         };
 
+        if let Some(xattr) = xattr {
+            Self::add_xattr(arena, group, inode, inode_offset, xattr)?;
+        }
+
         Ok(inode)
     }
 
+    fn add_xattr<'a>(
+        arena: &'a Arena<'a>,
+        group: &mut GroupMetaData,
+        inode: &mut Inode,
+        inode_offset: usize,
+        xattr: InlineXattrs,
+    ) -> Result<()> {
+        let xattr_region = arena.allocate::<[u8; Inode::XATTR_AREA_SIZE]>(
+            BlockId::from(group.group_desc.inode_table),
+            inode_offset + std::mem::size_of::<Inode>(),
+        )?;
+
+        if !xattr.entry_table.is_empty() {
+            // Linux and debugfs uses extra_size to check if inline xattr is stored so we need to
+            // set a positive value here. 4 (= sizeof(extra_size) + sizeof(_paddings))
+            // is the smallest value.
+            inode.extra_size = 4;
+            let InlineXattrs {
+                entry_table,
+                values,
+            } = xattr;
+
+            if entry_table.len() + values.len() > Inode::XATTR_AREA_SIZE {
+                bail!("xattr size is too large for inline store: entry_table.len={}, values.len={}, inline region size={}",
+                        entry_table.len(), values.len(), Inode::XATTR_AREA_SIZE);
+            }
+            // `entry_table` should be aligned to the beginning of the region.
+            xattr_region[..entry_table.len()].copy_from_slice(&entry_table);
+            xattr_region[Inode::XATTR_AREA_SIZE - values.len()..].copy_from_slice(&values);
+        }
+        Ok(())
+    }
+
     pub fn update_metadata(&mut self, m: &std::fs::Metadata) {
         self.mode = m.mode() as u16;
 
@@ -355,3 +416,21 @@ impl Inode {
         InodeType::n((self.mode >> 12) as u8)
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test_inode_size() {
+        assert_eq!(std::mem::offset_of!(Inode, extra_size), 128);
+        // Check that no implicit paddings is inserted after the padding field.
+        assert_eq!(
+            std::mem::offset_of!(Inode, _paddings) + std::mem::size_of::<u16>(),
+            std::mem::size_of::<Inode>()
+        );
+
+        assert!(128 < std::mem::size_of::<Inode>());
+        assert!(std::mem::size_of::<Inode>() <= Inode::INODE_RECORD_SIZE);
+    }
+}
diff --git a/ext2/src/lib.rs b/ext2/src/lib.rs
index 2d6a7b9bc..8502121a3 100644
--- a/ext2/src/lib.rs
+++ b/ext2/src/lib.rs
@@ -14,6 +14,9 @@ mod builder;
 mod fs;
 mod inode;
 mod superblock;
+mod xattr;
 
 pub use blockgroup::BLOCK_SIZE;
 pub use builder::Builder;
+pub use xattr::dump_xattrs;
+pub use xattr::set_xattr;
diff --git a/ext2/src/superblock.rs b/ext2/src/superblock.rs
index f3ac0edca..a719c6a42 100644
--- a/ext2/src/superblock.rs
+++ b/ext2/src/superblock.rs
@@ -98,11 +98,11 @@ impl SuperBlock {
             mtime: now,
             wtime: now,
             magic: EXT2_MAGIC_NUMBER,
-            state: 1,  // clean
-            errors: 1, // continue on errors
-            rev_level: 1,
+            state: 1,     // clean
+            errors: 1,    // continue on errors
+            rev_level: 1, // Rev 1 for variable inode sizes
             first_ino,
-            inode_size: Inode::inode_record_size(),
+            inode_size: Inode::INODE_RECORD_SIZE as u16,
             block_group_nr: 1, // super block is in block group 1
             feature_compat: COMPAT_EXT_ATTR,
             feature_incompat: 0x2, // Directory entries contain a type field
diff --git a/ext2/src/xattr.rs b/ext2/src/xattr.rs
new file mode 100644
index 000000000..36ec06341
--- /dev/null
+++ b/ext2/src/xattr.rs
@@ -0,0 +1,447 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+//! Provides utilites for extended attributes.
+
+use std::ffi::c_char;
+use std::ffi::CString;
+use std::os::unix::ffi::OsStrExt;
+use std::path::Path;
+
+use anyhow::bail;
+use anyhow::Context;
+use anyhow::Result;
+use zerocopy::AsBytes;
+use zerocopy::FromBytes;
+use zerocopy::FromZeroes;
+
+use crate::inode::Inode;
+
+fn listxattr(path: &CString) -> Result<Vec<Vec<u8>>> {
+    // SAFETY: Passing valid pointers and values.
+    let size = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
+    if size < 0 {
+        bail!(
+            "failed to get xattr size: {}",
+            std::io::Error::last_os_error()
+        );
+    }
+
+    if size == 0 {
+        // No extended attributes were set.
+        return Ok(vec![]);
+    }
+
+    let mut buf = vec![0 as c_char; size as usize];
+
+    // SAFETY: Passing valid pointers and values.
+    let size = unsafe { libc::llistxattr(path.as_ptr(), buf.as_mut_ptr(), buf.len()) };
+    if size < 0 {
+        bail!(
+            "failed to list of xattr: {}",
+            std::io::Error::last_os_error()
+        );
+    }
+
+    buf.pop(); // Remove null terminator
+
+    // While `c_char` is `i8` on x86_64, it's `u8` on ARM. So, disable the clippy for the cast.
+    #[cfg_attr(
+        any(target_arch = "arm", target_arch = "aarch64"),
+        allow(clippy::unnecessary_cast)
+    )]
+    let keys = buf
+        .split(|c| *c == 0)
+        .map(|v| v.iter().map(|c| *c as u8).collect::<Vec<_>>())
+        .collect::<Vec<Vec<_>>>();
+
+    Ok(keys)
+}
+
+fn lgetxattr(path: &CString, name: &CString) -> Result<Vec<u8>> {
+    // SAFETY: passing valid pointers.
+    let size = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
+    if size < 0 {
+        bail!(
+            "failed to get xattr size for {:?}: {}",
+            name,
+            std::io::Error::last_os_error()
+        );
+    }
+    let mut buf = vec![0; size as usize];
+    // SAFETY: passing valid pointers and length.
+    let size = unsafe {
+        libc::lgetxattr(
+            path.as_ptr(),
+            name.as_ptr(),
+            buf.as_mut_ptr() as *mut libc::c_void,
+            buf.len(),
+        )
+    };
+    if size < 0 {
+        bail!(
+            "failed to get xattr for {:?}: {}",
+            name,
+            std::io::Error::last_os_error()
+        );
+    }
+
+    Ok(buf)
+}
+
+/// Retrieves the list of pairs of a name and a value of the extended attribute of the given `path`.
+/// If `path` is a symbolic link, it won't be followed and the value of the symlink itself is
+/// returned.
+/// The return values are byte arrays WITHOUT trailing NULL byte.
+pub fn dump_xattrs(path: &Path) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
+    let mut path_vec = path.as_os_str().as_bytes().to_vec();
+    path_vec.push(0);
+    let path_str = CString::from_vec_with_nul(path_vec)?;
+
+    let keys = listxattr(&path_str).context("failed to listxattr")?;
+
+    let mut kvs = vec![];
+    for key in keys {
+        let mut key_vec = key.to_vec();
+        key_vec.push(0);
+        let name = CString::from_vec_with_nul(key_vec)?;
+
+        let buf = lgetxattr(&path_str, &name).context("failed to getxattr")?;
+        kvs.push((key.to_vec(), buf));
+    }
+
+    Ok(kvs)
+}
+
+/// Sets the extended attribute of the given `path` with the given `key` and `value`.
+pub fn set_xattr(path: &Path, key: &str, value: &str) -> Result<()> {
+    let mut path_bytes = path
+        .as_os_str()
+        .as_bytes()
+        .iter()
+        .map(|i| *i as c_char)
+        .collect::<Vec<_>>();
+    path_bytes.push(0); // null terminator
+
+    // While name must be a nul-terminated string, value is not, as it can be a binary data.
+    let mut key_vec = key.bytes().collect::<Vec<_>>();
+    key_vec.push(0);
+    let name = CString::from_vec_with_nul(key_vec)?;
+    let v = value.bytes().collect::<Vec<_>>();
+
+    // SAFETY: `path_bytes` and `nam` are null-terminated byte arrays.
+    // `v` is valid data.
+    let size = unsafe {
+        libc::lsetxattr(
+            path_bytes.as_ptr(),
+            name.as_ptr(),
+            v.as_ptr() as *const libc::c_void,
+            v.len(),
+            0,
+        )
+    };
+    if size != 0 {
+        bail!(
+            "failed to set xattr for {:?}: {}",
+            path,
+            std::io::Error::last_os_error()
+        );
+    }
+    Ok(())
+}
+
+#[repr(C)]
+#[derive(Default, Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
+pub(crate) struct XattrEntry {
+    name_len: u8,
+    name_index: u8,
+    value_offs: u16,
+    value_inum: u32,
+    value_size: u32,
+    hash: u32,
+    // name[name_len] follows
+}
+
+impl XattrEntry {
+    /// Creates a new `XattrEntry` instance with the name as a byte sequence that follows.
+    pub(crate) fn new_with_name<'a>(
+        name: &'a [u8],
+        value: &[u8],
+        value_offs: u16,
+    ) -> Result<(Self, &'a [u8])> {
+        let (name_index, key_str) = Self::split_key_prefix(name);
+        let name_len = key_str.len() as u8;
+        let value_size = value.len() as u32;
+        Ok((
+            XattrEntry {
+                name_len,
+                name_index,
+                value_offs,
+                value_inum: 0,
+                value_size,
+                hash: 0,
+            },
+            key_str,
+        ))
+    }
+
+    /// Split the given xatrr key string into it's prefix's name index and the remaining part.
+    /// e.g. "user.foo" -> (1, "foo") because the key prefix "user." has index 1.
+    fn split_key_prefix(name: &[u8]) -> (u8, &[u8]) {
+        // ref. https://docs.kernel.org/filesystems/ext4/dynamic.html#attribute-name-indices
+        for (name_index, key_prefix) in [
+            (1, "user."),
+            (2, "system.posix_acl_access"),
+            (3, "system.posix_acl_default"),
+            (4, "trusted."),
+            // 5 is skipped
+            (6, "security."),
+            (7, "system."),
+            (8, "system.richacl"),
+        ] {
+            let prefix_bytes = key_prefix.as_bytes();
+            if name.starts_with(prefix_bytes) {
+                return (name_index, &name[prefix_bytes.len()..]);
+            }
+        }
+        (0, name)
+    }
+}
+
+/// Xattr data written into Inode's inline xattr space.
+#[derive(Default, Debug, PartialEq, Eq)]
+pub struct InlineXattrs {
+    pub entry_table: Vec<u8>,
+    pub values: Vec<u8>,
+}
+
+fn align<T: Clone + Default>(mut v: Vec<T>, alignment: usize) -> Vec<T> {
+    let aligned = v.len().next_multiple_of(alignment);
+    v.extend(vec![T::default(); aligned - v.len()]);
+    v
+}
+
+const XATTR_HEADER_MAGIC: u32 = 0xEA020000;
+
+impl InlineXattrs {
+    // Creates `InlineXattrs` for the given path.
+    pub fn from_path(path: &Path) -> Result<Self> {
+        let v = dump_xattrs(path).with_context(|| format!("failed to get xattr for {:?}", path))?;
+
+        // Assume all the data are in inode record.
+        let mut entry_table = vec![];
+        let mut values = vec![];
+        // Data layout of the inline Inode record is as follows.
+        //
+        // | Inode struct | header | extra region |
+        //  <--------- Inode record  ------------>
+        //
+        // The value `val_offset` below is an offset from the beginning of the extra region and used
+        // to indicate the place where the next xattr value will be written. While we place
+        // attribute entries from the beginning of the extra region, we place values from the end of
+        // the region. So the initial value of `val_offset` indicates the end of the extra
+        // region.
+        //
+        // See Table 5.1. at https://www.nongnu.org/ext2-doc/ext2.html#extended-attribute-layout for the more details on data layout.
+        // Although this table is for xattr in a separate block, data layout is same.
+        let mut val_offset = Inode::INODE_RECORD_SIZE
+            - std::mem::size_of::<Inode>()
+            - std::mem::size_of_val(&XATTR_HEADER_MAGIC);
+
+        entry_table.extend(XATTR_HEADER_MAGIC.to_le_bytes());
+        for (name, value) in v {
+            let aligned_val_len = value.len().next_multiple_of(4);
+
+            if entry_table.len()
+                + values.len()
+                + std::mem::size_of::<XattrEntry>()
+                + aligned_val_len
+                > Inode::XATTR_AREA_SIZE
+            {
+                bail!("Xattr entry is too large");
+            }
+
+            val_offset -= aligned_val_len;
+            let (entry, name) = XattrEntry::new_with_name(&name, &value, val_offset as u16)?;
+            entry_table.extend(entry.as_bytes());
+            entry_table.extend(name);
+            entry_table = align(entry_table, 4);
+            values.push(align(value, 4));
+        }
+        let values = values.iter().rev().flatten().copied().collect::<Vec<_>>();
+
+        Ok(Self {
+            entry_table,
+            values,
+        })
+    }
+}
+
+#[cfg(test)]
+pub(crate) mod tests {
+    use std::collections::BTreeMap;
+    use std::fs::File;
+
+    use tempfile::tempdir;
+
+    use super::*;
+
+    fn to_char_array(s: &str) -> Vec<u8> {
+        s.bytes().collect()
+    }
+
+    #[test]
+    fn test_attr_name_index() {
+        assert_eq!(
+            XattrEntry::split_key_prefix(b"user.foo"),
+            (1, "foo".as_bytes())
+        );
+        assert_eq!(
+            XattrEntry::split_key_prefix(b"trusted.bar"),
+            (4, "bar".as_bytes())
+        );
+        assert_eq!(
+            XattrEntry::split_key_prefix(b"security.abcdefgh"),
+            (6, "abcdefgh".as_bytes())
+        );
+
+        // "system."-prefix
+        assert_eq!(
+            XattrEntry::split_key_prefix(b"system.posix_acl_access"),
+            (2, "".as_bytes())
+        );
+        assert_eq!(
+            XattrEntry::split_key_prefix(b"system.posix_acl_default"),
+            (3, "".as_bytes())
+        );
+        assert_eq!(
+            XattrEntry::split_key_prefix(b"system.abcdefgh"),
+            (7, "abcdefgh".as_bytes())
+        );
+
+        // unmatched prefix
+        assert_eq!(
+            XattrEntry::split_key_prefix(b"invalid.foo"),
+            (0, "invalid.foo".as_bytes())
+        );
+    }
+
+    #[test]
+    fn test_get_xattr_empty() {
+        let td = tempdir().unwrap();
+        let test_path = td.path().join("test.txt");
+
+        // Don't set any extended attributes.
+        File::create(&test_path).unwrap();
+
+        let kvs = dump_xattrs(&test_path).unwrap();
+        assert_eq!(kvs.len(), 0);
+    }
+
+    #[test]
+    fn test_inline_xattr_from_path() {
+        let td = tempdir().unwrap();
+        let test_path = td.path().join("test.txt");
+        File::create(&test_path).unwrap();
+
+        let key = "key";
+        let xattr_key = &format!("user.{key}");
+        let value = "value";
+
+        set_xattr(&test_path, xattr_key, value).unwrap();
+
+        let xattrs = InlineXattrs::from_path(&test_path).unwrap();
+        let entry = XattrEntry {
+            name_len: key.len() as u8,
+            name_index: 1,
+            value_offs: (Inode::INODE_RECORD_SIZE
+                - std::mem::size_of::<Inode>()
+                - std::mem::size_of_val(&XATTR_HEADER_MAGIC)
+                - value.len().next_multiple_of(4)) as u16,
+            value_size: value.len() as u32,
+            value_inum: 0,
+            ..Default::default()
+        };
+        assert_eq!(
+            xattrs.entry_table,
+            align(
+                [
+                    XATTR_HEADER_MAGIC.to_le_bytes().to_vec(),
+                    entry.as_bytes().to_vec(),
+                    key.as_bytes().to_vec(),
+                ]
+                .concat(),
+                4
+            ),
+        );
+        assert_eq!(xattrs.values, align(value.as_bytes().to_vec(), 4),);
+    }
+
+    #[test]
+    fn test_too_many_values_for_inline_xattr() {
+        let td = tempdir().unwrap();
+        let test_path = td.path().join("test.txt");
+        File::create(&test_path).unwrap();
+
+        // Prepare 10 pairs of xattributes, which will not fit inline space.
+        let mut xattr_pairs = vec![];
+        for i in 0..10 {
+            xattr_pairs.push((format!("user.foo{i}"), "bar"));
+        }
+
+        for (key, value) in &xattr_pairs {
+            set_xattr(&test_path, key, value).unwrap();
+        }
+
+        // Must fail
+        InlineXattrs::from_path(&test_path).unwrap_err();
+    }
+
+    #[test]
+    fn test_get_xattr() {
+        let td = tempdir().unwrap();
+        let test_path = td.path().join("test.txt");
+        File::create(&test_path).unwrap();
+
+        let xattr_pairs = vec![
+            ("user.foo", "bar"),
+            ("user.hash", "09f7e02f1290be211da707a266f153b3"),
+            ("user.empty", ""),
+        ];
+
+        for (key, value) in &xattr_pairs {
+            set_xattr(&test_path, key, value).unwrap();
+        }
+
+        let kvs = dump_xattrs(&test_path).unwrap();
+        assert_eq!(kvs.len(), xattr_pairs.len());
+
+        let xattr_map: BTreeMap<Vec<u8>, Vec<u8>> = kvs.into_iter().collect();
+
+        for (orig_k, orig_v) in xattr_pairs {
+            let k = to_char_array(orig_k);
+            let v = to_char_array(orig_v);
+            let got = xattr_map.get(&k).unwrap();
+            assert_eq!(&v, got);
+        }
+    }
+
+    #[test]
+    fn test_get_xattr_symlink() {
+        let td = tempdir().unwrap();
+
+        // Set xattr on test.txt.
+        let test_path = td.path().join("test.txt");
+        File::create(&test_path).unwrap();
+        set_xattr(&test_path, "user.name", "user.test.txt").unwrap();
+
+        // Create a symlink to test.txt.
+        let symlink_path = td.path().join("symlink");
+        std::os::unix::fs::symlink(&test_path, &symlink_path).unwrap();
+
+        // dump_xattrs shouldn't follow a symlink.
+        let kvs = dump_xattrs(&symlink_path).unwrap();
+        assert_eq!(kvs, vec![]);
+    }
+}
diff --git a/ext2/tests/tests.rs b/ext2/tests/tests.rs
index 96dd0cbca..cb1838de5 100644
--- a/ext2/tests/tests.rs
+++ b/ext2/tests/tests.rs
@@ -4,6 +4,7 @@
 
 #![cfg(target_os = "linux")]
 
+use std::collections::BTreeMap;
 use std::collections::BTreeSet;
 use std::fs;
 use std::fs::create_dir;
@@ -23,6 +24,7 @@ use std::process::Command;
 use base::MappedRegion;
 use ext2::Builder;
 use tempfile::tempdir;
+use tempfile::tempdir_in;
 use tempfile::TempDir;
 use walkdir::WalkDir;
 
@@ -63,12 +65,12 @@ fn run_debugfs_cmd(args: &[&str], disk: &PathBuf) -> String {
     stdout.trim_start().trim_end().to_string()
 }
 
-fn mkfs(td: &TempDir, builder: Builder, src_dir: Option<&Path>) -> PathBuf {
+fn mkfs(td: &TempDir, builder: Builder) -> PathBuf {
     let path = td.path().join("empty.ext2");
     let mem = builder
         .allocate_memory()
         .unwrap()
-        .build_mmap_info(src_dir)
+        .build_mmap_info()
         .unwrap()
         .do_mmap()
         .unwrap();
@@ -97,7 +99,6 @@ fn test_mkfs_empty() {
             inodes_per_group: 1024,
             ..Default::default()
         },
-        None,
     );
 
     // Ensure the content of the generated disk image with `debugfs`.
@@ -122,8 +123,8 @@ fn test_mkfs_empty_multi_block_groups() {
             blocks_per_group,
             inodes_per_group: 4096,
             size: 4096 * blocks_per_group * num_groups,
+            ..Default::default()
         },
-        None,
     );
     assert_eq!(
         run_debugfs_cmd(&["ls"], &disk),
@@ -156,7 +157,14 @@ fn collect_paths(dir: &Path, skip_lost_found: bool) -> BTreeSet<(String, PathBuf
         .collect()
 }
 
-fn assert_eq_dirs(td: &TempDir, dir: &Path, disk: &PathBuf) {
+fn assert_eq_dirs(
+    td: &TempDir,
+    dir: &Path,
+    disk: &PathBuf,
+    // Check the correct xattr is set and any unexpected one isn't set.
+    // Pass None to skip this check for test cases where many files are created.
+    xattr_map: Option<BTreeMap<String, Vec<(&str, &str)>>>,
+) {
     // dump the disk contents to `dump_dir`.
     let dump_dir = td.path().join("dump");
     std::fs::create_dir(&dump_dir).unwrap();
@@ -209,10 +217,28 @@ fn assert_eq_dirs(td: &TempDir, dir: &Path, disk: &PathBuf) {
         );
 
         if m1.file_type().is_file() {
+            // Check contents
             let c1 = std::fs::read_to_string(path1).unwrap();
             let c2 = std::fs::read_to_string(path2).unwrap();
             assert_eq!(c1, c2, "content mismatch: ({name1})");
         }
+
+        // Check xattr
+        if let Some(mp) = &xattr_map {
+            match mp.get(name1) {
+                Some(expected_xattrs) if !expected_xattrs.is_empty() => {
+                    for (key, value) in expected_xattrs {
+                        let s = run_debugfs_cmd(&[&format!("ea_get -V {name1} {key}",)], disk);
+                        assert_eq!(&s, value);
+                    }
+                }
+                // If no xattr is specified, any value must not be set.
+                _ => {
+                    let s = run_debugfs_cmd(&[&format!("ea_list {}", name1,)], disk);
+                    assert_eq!(s, "");
+                }
+            }
+        }
     }
 }
 
@@ -235,12 +261,12 @@ fn test_simple_dir() {
         Builder {
             blocks_per_group: 2048,
             inodes_per_group: 4096,
+            root_dir: Some(dir.clone()),
             ..Default::default()
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, Some(Default::default()));
 
     td.close().unwrap(); // make sure that tempdir is properly deleted.
 }
@@ -269,12 +295,12 @@ fn test_nested_dirs() {
         Builder {
             blocks_per_group: 2048,
             inodes_per_group: 4096,
+            root_dir: Some(dir.clone()),
             ..Default::default()
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, Some(Default::default()));
 }
 
 #[test]
@@ -298,12 +324,12 @@ fn test_file_contents() {
         Builder {
             blocks_per_group: 2048,
             inodes_per_group: 4096,
+            root_dir: Some(dir.clone()),
             ..Default::default()
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, Some(Default::default()));
 }
 
 #[test]
@@ -321,12 +347,12 @@ fn test_max_file_name() {
         Builder {
             blocks_per_group: 2048,
             inodes_per_group: 4096,
+            root_dir: Some(dir.clone()),
             ..Default::default()
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, Some(Default::default()));
 }
 
 #[test]
@@ -350,12 +376,12 @@ fn test_mkfs_indirect_block() {
         Builder {
             blocks_per_group: 4096,
             inodes_per_group: 4096,
+            root_dir: Some(dir.clone()),
             ..Default::default()
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, Some(Default::default()));
 }
 
 #[test]
@@ -387,12 +413,12 @@ fn test_mkfs_symlink() {
         Builder {
             blocks_per_group: 2048,
             inodes_per_group: 4096,
+            root_dir: Some(dir.clone()),
             ..Default::default()
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, Some(Default::default()));
 }
 
 #[test]
@@ -418,12 +444,12 @@ fn test_mkfs_abs_symlink() {
         Builder {
             blocks_per_group: 2048,
             inodes_per_group: 4096,
+            root_dir: Some(dir.clone()),
             ..Default::default()
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, Some(Default::default()));
 }
 
 #[test]
@@ -444,12 +470,12 @@ fn test_mkfs_symlink_to_deleted() {
         Builder {
             blocks_per_group: 2048,
             inodes_per_group: 4096,
+            root_dir: Some(dir.clone()),
             ..Default::default()
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, Some(Default::default()));
 }
 
 #[test]
@@ -485,12 +511,12 @@ fn test_mkfs_long_symlink() {
         Builder {
             blocks_per_group: 2048,
             inodes_per_group: 4096,
+            root_dir: Some(dir.clone()),
             ..Default::default()
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, Some(Default::default()));
 }
 
 #[test]
@@ -519,9 +545,9 @@ fn test_ignore_lost_found() {
         Builder {
             blocks_per_group: 2048,
             inodes_per_group: 4096,
+            root_dir: Some(dir.clone()),
             ..Default::default()
         },
-        Some(&dir),
     );
 
     // dump the disk contents to `dump_dir`.
@@ -568,7 +594,7 @@ fn test_multiple_block_directory_entry() {
     std::fs::create_dir(&dir).unwrap();
 
     for i in 0..1000 {
-        let path = dir.join(&format!("{i}.txt"));
+        let path = dir.join(format!("{i}.txt"));
         File::create(&path).unwrap();
     }
 
@@ -577,12 +603,12 @@ fn test_multiple_block_directory_entry() {
         Builder {
             blocks_per_group: 2048,
             inodes_per_group: 4096,
+            root_dir: Some(dir.clone()),
             ..Default::default()
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, None); // skip xattr check
 }
 
 // Test a case where the inode tables spans multiple block groups.
@@ -617,11 +643,11 @@ fn test_multiple_bg_multi_inode_bitmap() {
             blocks_per_group,
             inodes_per_group,
             size: BLOCK_SIZE * blocks_per_group * num_groups,
+            root_dir: Some(dir.clone()),
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, None);
 }
 
 /// Test a case where the block tables spans multiple block groups.
@@ -656,11 +682,11 @@ fn test_multiple_bg_multi_block_bitmap() {
             blocks_per_group,
             inodes_per_group,
             size: BLOCK_SIZE * blocks_per_group * num_groups,
+            root_dir: Some(dir.clone()),
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, None);
 }
 
 // Test a case where a file spans multiple block groups.
@@ -679,7 +705,7 @@ fn test_multiple_bg_big_files() {
     // Prepare a large data.
     let data = vec!["0123456789"; 5000 * 20].concat();
     for i in 0..10 {
-        let path = dir.join(&format!("{i}.txt"));
+        let path = dir.join(format!("{i}.txt"));
         let mut f = File::create(&path).unwrap();
         f.write_all(data.as_bytes()).unwrap();
     }
@@ -687,16 +713,72 @@ fn test_multiple_bg_big_files() {
     // Set `blocks_per_group` to a value smaller than |size of a file| / 4K.
     // So, each file spans multiple block groups.
     let blocks_per_group = 128;
-    let num_groups = 30;
+    let num_groups = 50;
     let disk = mkfs(
         &td,
         Builder {
             blocks_per_group,
             inodes_per_group: 1024,
             size: BLOCK_SIZE * blocks_per_group * num_groups,
+            root_dir: Some(dir.clone()),
         },
-        Some(&dir),
     );
 
-    assert_eq_dirs(&td, &dir, &disk);
+    assert_eq_dirs(&td, &dir, &disk, Some(Default::default()));
+}
+
+#[test]
+fn test_mkfs_xattr() {
+    // Since tmpfs doesn't support xattr, use the current directory.
+    let td = tempdir_in(".").unwrap();
+    let dir = td.path().join("testdata");
+    // testdata
+    // ├── a.txt ("user.foo"="a", "user.bar"="0123456789")
+    // ├── b.txt ("security.selinux"="unconfined_u:object_r:user_home_t:s0")
+    // ├── c.txt (no xattr)
+    // └── dir/ ("user.foo"="directory")
+    //     └─ d.txt ("user.foo"="in_directory")
+    std::fs::create_dir(&dir).unwrap();
+
+    let dir_xattrs = vec![("dir".to_string(), vec![("user.foo", "directory")])];
+    let file_xattrs = vec![
+        (
+            "a.txt".to_string(),
+            vec![("user.foo", "a"), ("user.number", "0123456789")],
+        ),
+        (
+            "b.txt".to_string(),
+            vec![("security.selinux", "unconfined_u:object_r:user_home_t:s0")],
+        ),
+        ("c.txt".to_string(), vec![]),
+        ("dir/d.txt".to_string(), vec![("user.foo", "in_directory")]),
+    ];
+
+    // Create dirs
+    for (fname, xattrs) in &dir_xattrs {
+        let f_path = dir.join(fname);
+        std::fs::create_dir(&f_path).unwrap();
+        for (key, value) in xattrs {
+            ext2::set_xattr(&f_path, key, value).unwrap();
+        }
+    }
+    // Create files
+    for (fname, xattrs) in &file_xattrs {
+        let f_path = dir.join(fname);
+        File::create(&f_path).unwrap();
+        for (key, value) in xattrs {
+            ext2::set_xattr(&f_path, key, value).unwrap();
+        }
+    }
+
+    let xattr_map: BTreeMap<String, Vec<(&str, &str)>> =
+        file_xattrs.into_iter().chain(dir_xattrs).collect();
+
+    let builder = Builder {
+        root_dir: Some(dir.clone()),
+        ..Default::default()
+    };
+    let disk = mkfs(&td, builder);
+
+    assert_eq_dirs(&td, &dir, &disk, Some(xattr_map));
 }
diff --git a/fuzz/Cargo.toml b/fuzz/Cargo.toml
index 2cd2ed17c..932007b07 100644
--- a/fuzz/Cargo.toml
+++ b/fuzz/Cargo.toml
@@ -7,6 +7,9 @@ edition = "2021"
 [package.metadata]
 cargo-fuzz = true
 
+[lints.rust]
+unexpected_cfgs = { level = "warn", check-cfg = ['cfg(fuzzing)'] }
+
 [dependencies]
 devices = { path = "../devices" }
 disk = { path = "../disk" }
diff --git a/gpu_display/Android.bp b/gpu_display/Android.bp
index 39ba03909..57cf83254 100644
--- a/gpu_display/Android.bp
+++ b/gpu_display/Android.bp
@@ -29,6 +29,7 @@ rust_library {
     edition: "2021",
     features: [
         "android_display",
+        "gfxstream",
     ],
     rustlibs: [
         "libanyhow",
diff --git a/gpu_display/Cargo.toml b/gpu_display/Cargo.toml
index b9231a104..0d89f4349 100644
--- a/gpu_display/Cargo.toml
+++ b/gpu_display/Cargo.toml
@@ -14,6 +14,7 @@ android_display = []
 # Stub implementation of the Android display backend. This is only used for building and testing the
 # Android display backend on a non-Android target
 android_display_stub = []
+gfxstream = []
 
 [dependencies]
 anyhow = "1"
diff --git a/gpu_display/patches/Android.bp.patch b/gpu_display/patches/Android.bp.patch
index 1a42124b1..a352e940c 100644
--- a/gpu_display/patches/Android.bp.patch
+++ b/gpu_display/patches/Android.bp.patch
@@ -2,14 +2,14 @@ diff --git a/gpu_display/Android.bp b/gpu_display/Android.bp
 index dc5db8549..18a04722e 100644
 --- a/gpu_display/Android.bp
 +++ b/gpu_display/Android.bp
-@@ -27,7 +27,6 @@ rust_library {
+@@ -29,7 +29,6 @@ rust_library {
      edition: "2021",
      features: [
          "android_display",
 -        "android_display_stub",
+         "gfxstream",
      ],
      rustlibs: [
-         "libanyhow",
 @@ -43,7 +42,26 @@ rust_library {
      ],
      proc_macros: ["libremain"],
diff --git a/gpu_display/src/gpu_display_win/math_util.rs b/gpu_display/src/gpu_display_win/math_util.rs
index 93ce4016f..9714dca77 100644
--- a/gpu_display/src/gpu_display_win/math_util.rs
+++ b/gpu_display/src/gpu_display_win/math_util.rs
@@ -25,12 +25,18 @@ pub trait SizeExtension {
         expected_aspect_ratio: f32,
         should_adjust_width: bool,
     ) -> Self;
+    #[allow(dead_code)]
     fn get_largest_inner_rect_size(original_size: &Self, expected_aspect_ratio: f32) -> Self;
+    #[allow(dead_code)]
     fn scale(&self, ratio: f32) -> Self;
+    #[allow(dead_code)]
     fn transpose(&self) -> Self;
+    #[allow(dead_code)]
     fn shorter_edge(&self) -> i32;
     fn aspect_ratio(&self) -> f32;
+    #[allow(dead_code)]
     fn is_square(&self) -> bool;
+    #[allow(dead_code)]
     fn is_landscape(&self) -> bool;
 }
 
diff --git a/gpu_display/src/gpu_display_win/window.rs b/gpu_display/src/gpu_display_win/window.rs
index 84509331d..5cbc6d78e 100644
--- a/gpu_display/src/gpu_display_win/window.rs
+++ b/gpu_display/src/gpu_display_win/window.rs
@@ -279,6 +279,7 @@ pub(crate) trait BasicWindow {
     }
 
     /// Calls `RemovePropW()` internally.
+    #[allow(dead_code)]
     fn remove_property(&self, property: &str) -> Result<()> {
         // SAFETY:
         // Safe because the window object won't outlive the HWND, and failures are handled below.
diff --git a/gpu_display/src/lib.rs b/gpu_display/src/lib.rs
index 49656fbb5..929c0f3d9 100644
--- a/gpu_display/src/lib.rs
+++ b/gpu_display/src/lib.rs
@@ -262,21 +262,25 @@ trait GpuDisplaySurface {
     }
 
     /// Returns the type of the completed buffer.
+    #[allow(dead_code)]
     fn buffer_completion_type(&self) -> u32 {
         0
     }
 
     /// Draws the current buffer on the screen.
+    #[allow(dead_code)]
     fn draw_current_buffer(&mut self) {
         // no-op
     }
 
     /// Handles a compositor-specific client event.
+    #[allow(dead_code)]
     fn on_client_message(&mut self, _client_data: u64) {
         // no-op
     }
 
     /// Handles a compositor-specific shared memory completion event.
+    #[allow(dead_code)]
     fn on_shm_completion(&mut self, _shm_complete: u64) {
         // no-op
     }
diff --git a/gpu_display/src/vulkan/sys/windows.rs b/gpu_display/src/vulkan/sys/windows.rs
index dbdc82d67..ba9c36d9c 100644
--- a/gpu_display/src/vulkan/sys/windows.rs
+++ b/gpu_display/src/vulkan/sys/windows.rs
@@ -368,7 +368,7 @@ static WND_CLASS_REGISTRATION_SUCCESS: Mutex<bool> = Mutex::new(false);
 
 /// # Safety
 ///  - The passed in `worker` must not be destroyed before the created window is destroyed if the
-/// window creation succeeds.
+///    window creation succeeds.
 ///  - The WNDPROC must be called within the same thread that calls create_window.
 /// # Arguments
 /// * `worker` - we use the runtime borrow checker to make sure there is no unwanted borrowing to
diff --git a/hypervisor/Android.bp b/hypervisor/Android.bp
index 004ff142c..702a7ea1e 100644
--- a/hypervisor/Android.bp
+++ b/hypervisor/Android.bp
@@ -29,7 +29,7 @@ rust_test {
     rustlibs: [
         "libanyhow",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbitflags",
         "libcros_fdt",
         "libdata_model",
@@ -71,7 +71,7 @@ rust_test {
     rustlibs: [
         "libanyhow",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbitflags",
         "libcros_fdt",
         "libdata_model",
@@ -114,7 +114,7 @@ rust_test {
     rustlibs: [
         "libanyhow",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbitflags",
         "libcros_fdt",
         "libdata_model",
@@ -157,7 +157,7 @@ rust_test {
     rustlibs: [
         "libanyhow",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbitflags",
         "libcros_fdt",
         "libdata_model",
@@ -200,7 +200,7 @@ rust_test {
     rustlibs: [
         "libanyhow",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbitflags",
         "libcros_fdt",
         "libdata_model",
@@ -243,7 +243,7 @@ rust_test {
     rustlibs: [
         "libanyhow",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbitflags",
         "libcros_fdt",
         "libdata_model",
@@ -286,7 +286,7 @@ rust_test {
     rustlibs: [
         "libanyhow",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbitflags",
         "libcros_fdt",
         "libdata_model",
@@ -329,7 +329,7 @@ rust_test {
     rustlibs: [
         "libanyhow",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbitflags",
         "libcros_fdt",
         "libdata_model",
@@ -372,7 +372,7 @@ rust_test {
     rustlibs: [
         "libanyhow",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbitflags",
         "libcros_fdt",
         "libdata_model",
@@ -410,7 +410,7 @@ rust_library {
     rustlibs: [
         "libanyhow",
         "libbase_rust",
-        "libbit_field",
+        "libbit_field_crosvm",
         "libbitflags",
         "libcros_fdt",
         "libdata_model",
diff --git a/hypervisor/Cargo.toml b/hypervisor/Cargo.toml
index 73ce7bdac..662cecd0a 100644
--- a/hypervisor/Cargo.toml
+++ b/hypervisor/Cargo.toml
@@ -5,9 +5,11 @@ authors = ["The ChromiumOS Authors"]
 edition = "2021"
 
 [features]
+enable_haxm_tests = []
 haxm = []
 whpx = []
 geniezone = []
+gvm = []
 gunyah = []
 noncoherent-dma = []
 
diff --git a/hypervisor/src/aarch64.rs b/hypervisor/src/aarch64.rs
index bae426743..c91d51be1 100644
--- a/hypervisor/src/aarch64.rs
+++ b/hypervisor/src/aarch64.rs
@@ -356,6 +356,8 @@ pub enum VcpuFeature {
     PmuV3,
     /// Starts the VCPU in a power-off state.
     PowerOff,
+    /// Scalable Vector Extension support
+    Sve,
 }
 
 #[cfg(test)]
diff --git a/hypervisor/src/geniezone/mod.rs b/hypervisor/src/geniezone/mod.rs
index 6b27947ba..f0240e5fb 100644
--- a/hypervisor/src/geniezone/mod.rs
+++ b/hypervisor/src/geniezone/mod.rs
@@ -19,6 +19,7 @@ use std::sync::Arc;
 use base::errno_result;
 use base::error;
 use base::ioctl;
+use base::ioctl_with_mut_ref;
 use base::ioctl_with_ref;
 use base::ioctl_with_val;
 use base::pagesize;
@@ -805,12 +806,12 @@ impl GeniezoneVm {
 
     /// Checks whether a particular GZVM-specific capability is available for this VM.
     fn check_raw_capability(&self, capability: GeniezoneCap) -> bool {
-        let cap: u64 = capability as u64;
+        let mut cap: u64 = capability as u64;
         // SAFETY:
         // Safe because we know that our file is a GZVM fd, and if the cap is invalid GZVM assumes
         // it's an unavailable extension and returns 0.
         unsafe {
-            ioctl_with_ref(self, GZVM_CHECK_EXTENSION, &cap);
+            ioctl_with_mut_ref(self, GZVM_CHECK_EXTENSION, &mut cap);
         }
         cap == 1
     }
@@ -1209,10 +1210,7 @@ impl Vcpu for GeniezoneVcpu {
         }
     }
 
-    fn handle_mmio(
-        &self,
-        handle_fn: &mut dyn FnMut(IoParams) -> Result<Option<[u8; 8]>>,
-    ) -> Result<()> {
+    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Result<()>) -> Result<()> {
         // SAFETY:
         // Safe because we know we mapped enough memory to hold the gzvm_vcpu_run struct because the
         // kernel told us how large it was. The pointer is page aligned so casting to a different
@@ -1226,29 +1224,22 @@ impl Vcpu for GeniezoneVcpu {
         // union field to use.
         let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
         let address = mmio.phys_addr;
-
-        let size = mmio.size as usize;
+        let data = &mut mmio.data[..mmio.size as usize];
 
         if mmio.is_write != 0 {
             handle_fn(IoParams {
                 address,
-                size,
-                operation: IoOperation::Write { data: mmio.data },
-            })?;
-            Ok(())
-        } else if let Some(data) = handle_fn(IoParams {
-            address,
-            size,
-            operation: IoOperation::Read,
-        })? {
-            mmio.data[..size].copy_from_slice(&data[..size]);
-            Ok(())
+                operation: IoOperation::Write(data),
+            })
         } else {
-            Err(Error::new(EINVAL))
+            handle_fn(IoParams {
+                address,
+                operation: IoOperation::Read(data),
+            })
         }
     }
 
-    fn handle_io(&self, _handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
+    fn handle_io(&self, _handle_fn: &mut dyn FnMut(IoParams)) -> Result<()> {
         Err(Error::new(EINVAL))
     }
 }
diff --git a/hypervisor/src/gunyah/mod.rs b/hypervisor/src/gunyah/mod.rs
index 8987a43cf..d52b0e190 100644
--- a/hypervisor/src/gunyah/mod.rs
+++ b/hypervisor/src/gunyah/mod.rs
@@ -6,7 +6,6 @@
 mod aarch64;
 
 mod gunyah_sys;
-use std::cmp::min;
 use std::cmp::Reverse;
 use std::collections::BTreeMap;
 use std::collections::BinaryHeap;
@@ -810,10 +809,7 @@ impl Vcpu for GunyahVcpu {
         }
     }
 
-    fn handle_mmio(
-        &self,
-        handle_fn: &mut dyn FnMut(IoParams) -> Result<Option<[u8; 8]>>,
-    ) -> Result<()> {
+    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Result<()>) -> Result<()> {
         // SAFETY:
         // Safe because we know we mapped enough memory to hold the gh_vcpu_run struct because the
         // kernel told us how large it was. The pointer is page aligned so casting to a different
@@ -826,27 +822,21 @@ impl Vcpu for GunyahVcpu {
         // union field to use.
         let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
         let address = mmio.phys_addr;
-        let size = min(mmio.len as usize, mmio.data.len());
+        let data = &mut mmio.data[..mmio.len as usize];
         if mmio.is_write != 0 {
             handle_fn(IoParams {
                 address,
-                size,
-                operation: IoOperation::Write { data: mmio.data },
-            })?;
-            Ok(())
-        } else if let Some(data) = handle_fn(IoParams {
-            address,
-            size,
-            operation: IoOperation::Read,
-        })? {
-            mmio.data[..size].copy_from_slice(&data[..size]);
-            Ok(())
+                operation: IoOperation::Write(data),
+            })
         } else {
-            Err(Error::new(EINVAL))
+            handle_fn(IoParams {
+                address,
+                operation: IoOperation::Read(data),
+            })
         }
     }
 
-    fn handle_io(&self, _handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
+    fn handle_io(&self, _handle_fn: &mut dyn FnMut(IoParams)) -> Result<()> {
         unreachable!()
     }
 
diff --git a/hypervisor/src/haxm.rs b/hypervisor/src/haxm.rs
index d042aa77e..a175d95fc 100644
--- a/hypervisor/src/haxm.rs
+++ b/hypervisor/src/haxm.rs
@@ -226,11 +226,6 @@ impl HypervisorX86_64 for Haxm {
         })
     }
 
-    fn get_emulated_cpuid(&self) -> Result<CpuId> {
-        // HAXM does not emulate any cpuids that the host does not support
-        Ok(CpuId::new(0))
-    }
-
     /// Gets the list of supported MSRs.
     fn get_msr_index_list(&self) -> Result<Vec<u32>> {
         // HAXM supported MSRs come from
diff --git a/hypervisor/src/haxm/vcpu.rs b/hypervisor/src/haxm/vcpu.rs
index 2f93e20f1..144b54a84 100644
--- a/hypervisor/src/haxm/vcpu.rs
+++ b/hypervisor/src/haxm/vcpu.rs
@@ -4,9 +4,7 @@
 
 use core::ffi::c_void;
 use std::arch::x86_64::CpuidResult;
-use std::cmp::min;
 use std::collections::BTreeMap;
-use std::intrinsics::copy_nonoverlapping;
 use std::mem::size_of;
 
 use base::errno_result;
@@ -177,10 +175,7 @@ impl Vcpu for HaxmVcpu {
     /// Once called, it will determine whether a mmio read or mmio write was the reason for the mmio
     /// exit, call `handle_fn` with the respective IoOperation to perform the mmio read or
     /// write, and set the return data in the vcpu so that the vcpu can resume running.
-    fn handle_mmio(
-        &self,
-        handle_fn: &mut dyn FnMut(IoParams) -> Result<Option<[u8; 8]>>,
-    ) -> Result<()> {
+    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Result<()>) -> Result<()> {
         // SAFETY:
         // Safe because we know we mapped enough memory to hold the hax_tunnel struct because the
         // kernel told us how large it was.
@@ -194,39 +189,34 @@ impl Vcpu for HaxmVcpu {
             // Safe because the exit_reason (which comes from the kernel) told us which
             // union field to use.
             unsafe { ((*mmio).gpa, (*mmio).size as usize, (*mmio).direction) };
+        // SAFETY:
+        // Safe because the exit_reason (which comes from the kernel) told us which
+        // union field to use. We use `addr_of_mut!()` to get a potentially unaligned u64 pointer,
+        // but it is then cast via a u8 pointer to a u8 slice, which has no alignment requirements.
+        let data = unsafe {
+            assert!(size <= size_of::<u64>());
+            std::slice::from_raw_parts_mut(
+                std::ptr::addr_of_mut!((*mmio).__bindgen_anon_1.value) as *mut u8,
+                size,
+            )
+        };
 
         match direction {
             HAX_EXIT_DIRECTION_MMIO_READ => {
-                if let Some(data) = handle_fn(IoParams {
+                handle_fn(IoParams {
                     address,
-                    size,
-                    operation: IoOperation::Read,
+                    operation: IoOperation::Read(data),
                 })
                 // We have to unwrap/panic here because HAXM doesn't have a
                 // facility to inject a GP fault here. Once HAXM can do that, we
                 // should inject a GP fault & bubble the error.
-                .unwrap()
-                {
-                    let data = u64::from_ne_bytes(data);
-                    // SAFETY:
-                    // Safe because we know this is an mmio read, so we need to put data into the
-                    // "value" field of the hax_fastmmio.
-                    unsafe {
-                        (*mmio).__bindgen_anon_1.value = data;
-                    }
-                }
+                .unwrap();
                 Ok(())
             }
             HAX_EXIT_DIRECTION_MMIO_WRITE => {
-                // SAFETY:
-                // safe because we trust haxm to fill in the union properly.
-                let data = unsafe { (*mmio).__bindgen_anon_1.value };
                 handle_fn(IoParams {
                     address,
-                    size,
-                    operation: IoOperation::Write {
-                        data: data.to_ne_bytes(),
-                    },
+                    operation: IoOperation::Write(data),
                 })
                 // Similarly to the read direction, we MUST panic here.
                 .unwrap();
@@ -242,7 +232,7 @@ impl Vcpu for HaxmVcpu {
     /// call `handle_fn` with the respective IoOperation to perform the io in or io out,
     /// and set the return data in the vcpu so that the vcpu can resume running.
     #[allow(clippy::cast_ptr_alignment)]
-    fn handle_io(&self, handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
+    fn handle_io(&self, handle_fn: &mut dyn FnMut(IoParams)) -> Result<()> {
         // SAFETY:
         // Safe because we know we mapped enough memory to hold the hax_tunnel struct because the
         // kernel told us how large it was.
@@ -255,39 +245,33 @@ impl Vcpu for HaxmVcpu {
         // union field to use.
         let io = unsafe { (*self.tunnel).__bindgen_anon_1.io };
         let address = io.port.into();
-        let size = (io.count as usize) * (io.size as usize);
+        let size = io.size as usize;
+        let count = io.count as usize;
+        let data_len = count * size;
+        // SAFETY:
+        // Safe because the exit_reason (which comes from the kernel) told us that this is port io,
+        // where the iobuf can be treated as a *u8
+        let buffer: &mut [u8] =
+            unsafe { std::slice::from_raw_parts_mut(self.io_buffer as *mut u8, data_len) };
+        let data_chunks = buffer.chunks_mut(size);
+
         match io.direction as u32 {
             HAX_EXIT_DIRECTION_PIO_IN => {
-                if let Some(data) = handle_fn(IoParams {
-                    address,
-                    size,
-                    operation: IoOperation::Read,
-                }) {
-                    // SAFETY:
-                    // Safe because the exit_reason (which comes from the kernel) told us that
-                    // this is port io, where the iobuf can be treated as a *u8
-                    unsafe {
-                        copy_nonoverlapping(data.as_ptr(), self.io_buffer as *mut u8, size);
-                    }
+                for data in data_chunks {
+                    handle_fn(IoParams {
+                        address,
+                        operation: IoOperation::Read(data),
+                    });
                 }
                 Ok(())
             }
             HAX_EXIT_DIRECTION_PIO_OUT => {
-                let mut data = [0; 8];
-                // SAFETY:
-                // safe because we check the size, from what the kernel told us is the max to copy.
-                unsafe {
-                    copy_nonoverlapping(
-                        self.io_buffer as *const u8,
-                        data.as_mut_ptr(),
-                        min(size, data.len()),
-                    );
+                for data in data_chunks {
+                    handle_fn(IoParams {
+                        address,
+                        operation: IoOperation::Write(data),
+                    });
                 }
-                handle_fn(IoParams {
-                    address,
-                    size,
-                    operation: IoOperation::Write { data },
-                });
                 Ok(())
             }
             _ => Err(Error::new(EINVAL)),
diff --git a/hypervisor/src/kvm/aarch64.rs b/hypervisor/src/kvm/aarch64.rs
index 3c06085f9..9fffdd7ab 100644
--- a/hypervisor/src/kvm/aarch64.rs
+++ b/hypervisor/src/kvm/aarch64.rs
@@ -375,6 +375,61 @@ impl KvmVcpu {
         let reg_list: &[u64] = unsafe { kvm_reg_list[0].reg.as_slice(n as usize) };
         Ok(reg_list.to_vec())
     }
+
+    fn get_features_bitmap(&self, features: &[VcpuFeature]) -> Result<u32> {
+        let mut all_features = 0;
+        let check_extension = |ext: u32| -> bool {
+            // SAFETY:
+            // Safe because we know self.vm is a real kvm fd
+            unsafe { ioctl_with_val(&self.vm, KVM_CHECK_EXTENSION, ext.into()) == 1 }
+        };
+
+        for f in features {
+            let shift = match f {
+                VcpuFeature::PsciV0_2 => KVM_ARM_VCPU_PSCI_0_2,
+                VcpuFeature::PmuV3 => KVM_ARM_VCPU_PMU_V3,
+                VcpuFeature::PowerOff => KVM_ARM_VCPU_POWER_OFF,
+                VcpuFeature::Sve => {
+                    if !check_extension(KVM_CAP_ARM_SVE) {
+                        return Err(Error::new(ENOTSUP));
+                    }
+                    KVM_ARM_VCPU_SVE
+                }
+            };
+            all_features |= 1 << shift;
+        }
+
+        if check_extension(KVM_CAP_ARM_PTRAUTH_ADDRESS)
+            && check_extension(KVM_CAP_ARM_PTRAUTH_GENERIC)
+        {
+            all_features |= 1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS;
+            all_features |= 1 << KVM_ARM_VCPU_PTRAUTH_GENERIC;
+        }
+
+        Ok(all_features)
+    }
+
+    /// Finalize VCPU features setup. This does not affect features that do not make use of
+    /// finalize.
+    fn finalize(&self, features: u32) -> Result<()> {
+        if (features & 1 << KVM_ARM_VCPU_SVE) != 0 {
+            // SAFETY:
+            // Safe because we know that our file is a Vcpu fd and we verify the return result.
+            let ret = unsafe {
+                ioctl_with_ref(
+                    self,
+                    KVM_ARM_VCPU_FINALIZE,
+                    &std::os::raw::c_int::try_from(KVM_ARM_VCPU_SVE)
+                        .map_err(|_| Error::new(EINVAL))?,
+                )
+            };
+            if ret != 0 {
+                return errno_result();
+            }
+        }
+
+        Ok(())
+    }
 }
 
 /// KVM registers as used by the `GET_ONE_REG`/`SET_ONE_REG` ioctl API
@@ -542,36 +597,17 @@ impl VcpuAArch64 for KvmVcpu {
             return errno_result();
         }
 
-        for f in features {
-            let shift = match f {
-                VcpuFeature::PsciV0_2 => KVM_ARM_VCPU_PSCI_0_2,
-                VcpuFeature::PmuV3 => KVM_ARM_VCPU_PMU_V3,
-                VcpuFeature::PowerOff => KVM_ARM_VCPU_POWER_OFF,
-            };
-            kvi.features[0] |= 1 << shift;
-        }
-
-        let check_extension = |ext: u32| -> bool {
-            // SAFETY:
-            // Safe because we know self.vm is a real kvm fd
-            unsafe { ioctl_with_val(&self.vm, KVM_CHECK_EXTENSION, ext.into()) == 1 }
-        };
-        if check_extension(KVM_CAP_ARM_PTRAUTH_ADDRESS)
-            && check_extension(KVM_CAP_ARM_PTRAUTH_GENERIC)
-        {
-            kvi.features[0] |= 1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS;
-            kvi.features[0] |= 1 << KVM_ARM_VCPU_PTRAUTH_GENERIC;
-        }
-
+        kvi.features[0] = self.get_features_bitmap(features)?;
         // SAFETY:
         // Safe because we allocated the struct and we know the kernel will read exactly the size of
         // the struct.
         let ret = unsafe { ioctl_with_ref(self, KVM_ARM_VCPU_INIT, &kvi) };
-        if ret == 0 {
-            Ok(())
-        } else {
-            errno_result()
+        if ret != 0 {
+            return errno_result();
         }
+
+        self.finalize(kvi.features[0])?;
+        Ok(())
     }
 
     fn init_pmu(&self, irq: u64) -> Result<()> {
@@ -737,24 +773,19 @@ impl VcpuAArch64 for KvmVcpu {
         let mut sys_regs = BTreeMap::new();
         for reg in reg_list {
             if (reg as u32) & KVM_REG_ARM_COPROC_MASK == KVM_REG_ARM64_SYSREG {
-                if reg as u16 == cntvct_el0 {
-                    sys_regs.insert(
-                        AArch64SysRegId::CNTV_CVAL_EL0,
-                        self.get_one_reg(VcpuRegAArch64::System(AArch64SysRegId::CNTV_CVAL_EL0))?,
-                    );
+                let r = if reg as u16 == cntvct_el0 {
+                    AArch64SysRegId::CNTV_CVAL_EL0
                 } else if reg as u16 == cntv_cval_el0 {
-                    sys_regs.insert(
-                        AArch64SysRegId::CNTVCT_EL0,
-                        self.get_one_reg(VcpuRegAArch64::System(AArch64SysRegId::CNTVCT_EL0))?,
-                    );
+                    AArch64SysRegId::CNTVCT_EL0
                 } else {
-                    sys_regs.insert(
-                        AArch64SysRegId::from_encoded((reg & 0xFFFF) as u16),
-                        self.get_one_reg(VcpuRegAArch64::System(AArch64SysRegId::from_encoded(
-                            (reg & 0xFFFF) as u16,
-                        )))?,
-                    );
-                }
+                    AArch64SysRegId::from_encoded((reg & 0xFFFF) as u16)
+                };
+                sys_regs.insert(r, self.get_one_reg(VcpuRegAArch64::System(r))?);
+                // The register representations are tricky. Double check they round trip correctly.
+                assert_eq!(
+                    Ok(reg),
+                    self.kvm_reg_id(VcpuRegAArch64::System(r)).map(u64::from),
+                );
             }
         }
         Ok(sys_regs)
diff --git a/hypervisor/src/kvm/mod.rs b/hypervisor/src/kvm/mod.rs
index be9d7aabf..fc2788b41 100644
--- a/hypervisor/src/kvm/mod.rs
+++ b/hypervisor/src/kvm/mod.rs
@@ -16,7 +16,6 @@ mod riscv64;
 #[cfg(target_arch = "x86_64")]
 mod x86_64;
 
-use std::cmp::min;
 use std::cmp::Reverse;
 use std::collections::BTreeMap;
 use std::collections::BinaryHeap;
@@ -27,7 +26,6 @@ use std::os::raw::c_ulong;
 use std::os::raw::c_void;
 use std::os::unix::prelude::OsStrExt;
 use std::path::Path;
-use std::ptr::copy_nonoverlapping;
 use std::sync::Arc;
 
 use base::errno_result;
@@ -1039,14 +1037,10 @@ impl Vcpu for KvmVcpu {
         }
     }
 
-    fn handle_mmio(
-        &self,
-        handle_fn: &mut dyn FnMut(IoParams) -> Result<Option<[u8; 8]>>,
-    ) -> Result<()> {
+    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Result<()>) -> Result<()> {
         // SAFETY:
         // Safe because we know we mapped enough memory to hold the kvm_run struct because the
-        // kernel told us how large it was. The pointer is page aligned so casting to a different
-        // type is well defined, hence the clippy allow attribute.
+        // kernel told us how large it was.
         let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) };
         // Verify that the handler is called in the right context.
         assert!(run.exit_reason == KVM_EXIT_MMIO);
@@ -1055,31 +1049,24 @@ impl Vcpu for KvmVcpu {
         // union field to use.
         let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
         let address = mmio.phys_addr;
-        let size = min(mmio.len as usize, mmio.data.len());
+        let data = &mut mmio.data[..mmio.len as usize];
         if mmio.is_write != 0 {
             handle_fn(IoParams {
                 address,
-                size,
-                operation: IoOperation::Write { data: mmio.data },
-            })?;
-            Ok(())
-        } else if let Some(data) = handle_fn(IoParams {
-            address,
-            size,
-            operation: IoOperation::Read,
-        })? {
-            mmio.data[..size].copy_from_slice(&data[..size]);
-            Ok(())
+                operation: IoOperation::Write(data),
+            })
         } else {
-            Err(Error::new(EINVAL))
+            handle_fn(IoParams {
+                address,
+                operation: IoOperation::Read(data),
+            })
         }
     }
 
-    fn handle_io(&self, handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
+    fn handle_io(&self, handle_fn: &mut dyn FnMut(IoParams)) -> Result<()> {
         // SAFETY:
         // Safe because we know we mapped enough memory to hold the kvm_run struct because the
-        // kernel told us how large it was. The pointer is page aligned so casting to a different
-        // type is well defined, hence the clippy allow attribute.
+        // kernel told us how large it was.
         let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) };
         // Verify that the handler is called in the right context.
         assert!(run.exit_reason == KVM_EXIT_IO);
@@ -1087,52 +1074,42 @@ impl Vcpu for KvmVcpu {
         // Safe because the exit_reason (which comes from the kernel) told us which
         // union field to use.
         let io = unsafe { run.__bindgen_anon_1.io };
+        let address = u64::from(io.port);
         let size = usize::from(io.size);
+        let count = io.count as usize;
+        let data_len = count * size;
+        let data_offset = io.data_offset as usize;
+        assert!(data_offset + data_len <= self.run_mmap.size());
 
         // SAFETY:
         // The data_offset is defined by the kernel to be some number of bytes into the kvm_run
         // structure, which we have fully mmap'd.
-        let mut data_ptr = unsafe { (run as *mut kvm_run as *mut u8).add(io.data_offset as usize) };
-
-        match io.direction as u32 {
-            KVM_EXIT_IO_IN => {
-                for _ in 0..io.count {
-                    if let Some(data) = handle_fn(IoParams {
-                        address: io.port.into(),
-                        size,
-                        operation: IoOperation::Read,
-                    }) {
-                        // TODO(b/315998194): Add safety comment
-                        #[allow(clippy::undocumented_unsafe_blocks)]
-                        unsafe {
-                            copy_nonoverlapping(data.as_ptr(), data_ptr, size);
-                            data_ptr = data_ptr.add(size);
-                        }
-                    } else {
-                        return Err(Error::new(EINVAL));
-                    }
-                }
-                Ok(())
+        let buffer: &mut [u8] = unsafe {
+            std::slice::from_raw_parts_mut(
+                (run as *mut kvm_run as *mut u8).add(data_offset),
+                data_len,
+            )
+        };
+        let data_chunks = buffer.chunks_mut(size);
+
+        if io.direction == KVM_EXIT_IO_IN as u8 {
+            for data in data_chunks {
+                handle_fn(IoParams {
+                    address,
+                    operation: IoOperation::Read(data),
+                });
             }
-            KVM_EXIT_IO_OUT => {
-                for _ in 0..io.count {
-                    let mut data = [0; 8];
-                    // TODO(b/315998194): Add safety comment
-                    #[allow(clippy::undocumented_unsafe_blocks)]
-                    unsafe {
-                        copy_nonoverlapping(data_ptr, data.as_mut_ptr(), min(size, data.len()));
-                        data_ptr = data_ptr.add(size);
-                    }
-                    handle_fn(IoParams {
-                        address: io.port.into(),
-                        size,
-                        operation: IoOperation::Write { data },
-                    });
-                }
-                Ok(())
+        } else {
+            debug_assert_eq!(io.direction, KVM_EXIT_IO_OUT as u8);
+            for data in data_chunks {
+                handle_fn(IoParams {
+                    address,
+                    operation: IoOperation::Write(data),
+                });
             }
-            _ => Err(Error::new(EINVAL)),
         }
+
+        Ok(())
     }
 }
 
diff --git a/hypervisor/src/kvm/riscv64.rs b/hypervisor/src/kvm/riscv64.rs
index 252f20b9a..a830912d9 100644
--- a/hypervisor/src/kvm/riscv64.rs
+++ b/hypervisor/src/kvm/riscv64.rs
@@ -4,6 +4,7 @@
 
 use base::errno_result;
 use base::error;
+use base::ioctl_with_mut_ref;
 use base::ioctl_with_ref;
 use base::Error;
 use base::Result;
@@ -156,10 +157,10 @@ impl VcpuRiscv64 for KvmVcpu {
     }
 
     fn get_one_reg(&self, reg: VcpuRegister) -> Result<u64> {
-        let val: u64 = 0;
+        let mut val: u64 = 0;
         let onereg = kvm_one_reg {
             id: vcpu_reg_id(reg),
-            addr: (&val as *const u64) as u64,
+            addr: (&mut val as *mut u64) as u64,
         };
 
         // Safe because we allocated the struct and we know the kernel will read exactly the size of
diff --git a/hypervisor/src/kvm/x86_64.rs b/hypervisor/src/kvm/x86_64.rs
index a8c897898..7d0ce4ffe 100644
--- a/hypervisor/src/kvm/x86_64.rs
+++ b/hypervisor/src/kvm/x86_64.rs
@@ -156,11 +156,9 @@ impl Kvm {
         get_cpuid_with_initial_capacity(self, kind, KVM_MAX_ENTRIES)
     }
 
-    // The x86 machine type is always 0. Protected VMs are not supported.
     pub fn get_vm_type(&self, protection_type: ProtectionType) -> Result<u32> {
         if protection_type.isolates_memory() {
-            error!("Protected mode is not supported on x86_64.");
-            Err(Error::new(libc::EINVAL))
+            Ok(KVM_X86_PKVM_PROTECTED_VM)
         } else {
             Ok(0)
         }
@@ -178,10 +176,6 @@ impl HypervisorX86_64 for Kvm {
         self.get_cpuid(KVM_GET_SUPPORTED_CPUID)
     }
 
-    fn get_emulated_cpuid(&self) -> Result<CpuId> {
-        self.get_cpuid(KVM_GET_EMULATED_CPUID)
-    }
-
     fn get_msr_index_list(&self) -> Result<Vec<u32>> {
         const MAX_KVM_MSR_ENTRIES: usize = 256;
 
diff --git a/hypervisor/src/lib.rs b/hypervisor/src/lib.rs
index ede57408d..8abc20bc3 100644
--- a/hypervisor/src/lib.rs
+++ b/hypervisor/src/lib.rs
@@ -268,23 +268,22 @@ pub trait Vm: Send {
 }
 
 /// Operation for Io and Mmio
-#[derive(Copy, Clone, Debug)]
-pub enum IoOperation {
-    Read,
-    Write {
-        /// Data to be written.
-        ///
-        /// For 64 bit architecture, Mmio and Io only work with at most 8 bytes of data.
-        data: [u8; 8],
-    },
+#[derive(Debug)]
+pub enum IoOperation<'a> {
+    /// Data to be read from a device on the bus.
+    ///
+    /// The `handle_fn` should fill the entire slice with the read data.
+    Read(&'a mut [u8]),
+
+    /// Data to be written to a device on the bus.
+    Write(&'a [u8]),
 }
 
 /// Parameters describing an MMIO or PIO from the guest.
-#[derive(Copy, Clone, Debug)]
-pub struct IoParams {
+#[derive(Debug)]
+pub struct IoParams<'a> {
     pub address: u64,
-    pub size: usize,
-    pub operation: IoOperation,
+    pub operation: IoOperation<'a>,
 }
 
 /// Handle to a virtual CPU that may be used to request a VM exit from within a signal handler.
@@ -350,10 +349,7 @@ pub trait Vcpu: downcast_rs::DowncastSync {
     /// Once called, it will determine whether a MMIO read or MMIO write was the reason for the MMIO
     /// exit, call `handle_fn` with the respective IoParams to perform the MMIO read or write, and
     /// set the return data in the vcpu so that the vcpu can resume running.
-    fn handle_mmio(
-        &self,
-        handle_fn: &mut dyn FnMut(IoParams) -> Result<Option<[u8; 8]>>,
-    ) -> Result<()>;
+    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Result<()>) -> Result<()>;
 
     /// Handles an incoming PIO from the guest.
     ///
@@ -363,7 +359,7 @@ pub trait Vcpu: downcast_rs::DowncastSync {
     /// Once called, it will determine whether an input or output was the reason for the Io exit,
     /// call `handle_fn` with the respective IoParams to perform the input/output operation, and set
     /// the return data in the vcpu so that the vcpu can resume running.
-    fn handle_io(&self, handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()>;
+    fn handle_io(&self, handle_fn: &mut dyn FnMut(IoParams)) -> Result<()>;
 
     /// Signals to the hypervisor that this Vcpu is being paused by userspace.
     fn on_suspend(&self) -> Result<()>;
diff --git a/hypervisor/src/whpx.rs b/hypervisor/src/whpx.rs
index 3dafa0d5e..3343442ef 100644
--- a/hypervisor/src/whpx.rs
+++ b/hypervisor/src/whpx.rs
@@ -228,12 +228,6 @@ impl HypervisorX86_64 for Whpx {
         })
     }
 
-    /// Get the system emulated CPUID values.
-    /// TODO: this is only used by the plugin
-    fn get_emulated_cpuid(&self) -> Result<CpuId> {
-        Ok(CpuId::new(0))
-    }
-
     /// Gets the list of supported MSRs.
     /// TODO: this is only used by the plugin
     fn get_msr_index_list(&self) -> Result<Vec<u32>> {
diff --git a/hypervisor/src/whpx/vcpu.rs b/hypervisor/src/whpx/vcpu.rs
index 5f6297ced..8fa7341b4 100644
--- a/hypervisor/src/whpx/vcpu.rs
+++ b/hypervisor/src/whpx/vcpu.rs
@@ -7,6 +7,7 @@ use std::arch::x86_64::CpuidResult;
 use std::collections::BTreeMap;
 use std::convert::TryInto;
 use std::mem::size_of;
+use std::mem::size_of_val;
 use std::sync::Arc;
 
 use base::Error;
@@ -105,8 +106,8 @@ trait InstructionEmulatorCallbacks {
 struct InstructionEmulatorContext<'a> {
     vm_partition: Arc<SafePartition>,
     index: u32,
-    handle_mmio: Option<&'a mut dyn FnMut(IoParams) -> Result<Option<[u8; 8]>>>,
-    handle_io: Option<&'a mut dyn FnMut(IoParams) -> Option<[u8; 8]>>,
+    handle_mmio: Option<&'a mut dyn FnMut(IoParams) -> Result<()>>,
+    handle_io: Option<&'a mut dyn FnMut(IoParams)>,
 }
 
 impl InstructionEmulatorCallbacks for SafeInstructionEmulator {
@@ -117,46 +118,33 @@ impl InstructionEmulatorCallbacks for SafeInstructionEmulator {
         // unsafe because windows could decide to call this at any time.
         // However, we trust the kernel to call this while the vm/vcpu is valid.
         let ctx = unsafe { &mut *(context as *mut InstructionEmulatorContext) };
+        let Some(handle_io) = &mut ctx.handle_io else {
+            return E_UNEXPECTED;
+        };
+
         // safe because we trust the kernel to fill in the io_access
         let io_access_info = unsafe { &mut *io_access };
         let address = io_access_info.Port.into();
         let size = io_access_info.AccessSize as usize;
+        // SAFETY: We trust the kernel to fill in the io_access
+        let data: &mut [u8] = unsafe {
+            assert!(size <= size_of_val(&io_access_info.Data));
+            std::slice::from_raw_parts_mut(&mut io_access_info.Data as *mut u32 as *mut u8, size)
+        };
         match io_access_info.Direction {
             WHPX_EXIT_DIRECTION_PIO_IN => {
-                if let Some(handle_io) = &mut ctx.handle_io {
-                    if let Some(data) = handle_io(IoParams {
-                        address,
-                        size,
-                        operation: IoOperation::Read,
-                    }) {
-                        // Safe because we know this is an io_access_info field of u32,
-                        //  so casting as a &mut [u8] of len 4 is safe.
-                        let buffer = unsafe {
-                            std::slice::from_raw_parts_mut(
-                                &mut io_access_info.Data as *mut u32 as *mut u8,
-                                4,
-                            )
-                        };
-                        buffer[..size].copy_from_slice(&data[..size]);
-                    }
-                    S_OK
-                } else {
-                    E_UNEXPECTED
-                }
+                handle_io(IoParams {
+                    address,
+                    operation: IoOperation::Read(data),
+                });
+                S_OK
             }
             WHPX_EXIT_DIRECTION_PIO_OUT => {
-                if let Some(handle_io) = &mut ctx.handle_io {
-                    handle_io(IoParams {
-                        address,
-                        size,
-                        operation: IoOperation::Write {
-                            data: (io_access_info.Data as u64).to_ne_bytes(),
-                        },
-                    });
-                    S_OK
-                } else {
-                    E_UNEXPECTED
-                }
+                handle_io(IoParams {
+                    address,
+                    operation: IoOperation::Write(data),
+                });
+                S_OK
             }
             _ => E_UNEXPECTED,
         }
@@ -168,49 +156,38 @@ impl InstructionEmulatorCallbacks for SafeInstructionEmulator {
         // unsafe because windows could decide to call this at any time.
         // However, we trust the kernel to call this while the vm/vcpu is valid.
         let ctx = unsafe { &mut *(context as *mut InstructionEmulatorContext) };
+        let Some(handle_mmio) = &mut ctx.handle_mmio else {
+            return E_UNEXPECTED;
+        };
+
         // safe because we trust the kernel to fill in the memory_access
         let memory_access_info = unsafe { &mut *memory_access };
         let address = memory_access_info.GpaAddress;
         let size = memory_access_info.AccessSize as usize;
+        let data = &mut memory_access_info.Data[..size];
+
         match memory_access_info.Direction {
             WHPX_EXIT_DIRECTION_MMIO_READ => {
-                ctx.handle_mmio
-                    .as_mut()
-                    .map_or(E_UNEXPECTED, |handle_mmio| {
-                        handle_mmio(IoParams {
-                            address,
-                            size,
-                            operation: IoOperation::Read,
-                        })
-                        .map_err(|e| {
-                            error!("handle_mmio failed with {e}");
-                            e
-                        })
-                        .ok()
-                        .flatten()
-                        .map_or(E_UNEXPECTED, |data| {
-                            memory_access_info.Data = data;
-                            S_OK
-                        })
-                    })
+                if let Err(e) = handle_mmio(IoParams {
+                    address,
+                    operation: IoOperation::Read(data),
+                }) {
+                    error!("handle_mmio failed with {e}");
+                    E_UNEXPECTED
+                } else {
+                    S_OK
+                }
             }
             WHPX_EXIT_DIRECTION_MMIO_WRITE => {
-                ctx.handle_mmio
-                    .as_mut()
-                    .map_or(E_UNEXPECTED, |handle_mmio| {
-                        handle_mmio(IoParams {
-                            address,
-                            size,
-                            operation: IoOperation::Write {
-                                data: memory_access_info.Data,
-                            },
-                        })
-                        .map_err(|e| {
-                            error!("handle_mmio failed with {e}");
-                            e
-                        })
-                        .map_or(E_UNEXPECTED, |_| S_OK)
-                    })
+                if let Err(e) = handle_mmio(IoParams {
+                    address,
+                    operation: IoOperation::Write(data),
+                }) {
+                    error!("handle_mmio write with {e}");
+                    E_UNEXPECTED
+                } else {
+                    S_OK
+                }
             }
             _ => E_UNEXPECTED,
         }
@@ -559,10 +536,7 @@ impl Vcpu for WhpxVcpu {
     /// Once called, it will determine whether a mmio read or mmio write was the reason for the mmio
     /// exit, call `handle_fn` with the respective IoOperation to perform the mmio read or
     /// write, and set the return data in the vcpu so that the vcpu can resume running.
-    fn handle_mmio(
-        &self,
-        handle_fn: &mut dyn FnMut(IoParams) -> Result<Option<[u8; 8]>>,
-    ) -> Result<()> {
+    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Result<()>) -> Result<()> {
         let mut status: WHV_EMULATOR_STATUS = Default::default();
         let mut ctx = InstructionEmulatorContext {
             vm_partition: self.vm_partition.clone(),
@@ -596,7 +570,7 @@ impl Vcpu for WhpxVcpu {
     /// Once called, it will determine whether an io in or io out was the reason for the io exit,
     /// call `handle_fn` with the respective IoOperation to perform the io in or io out,
     /// and set the return data in the vcpu so that the vcpu can resume running.
-    fn handle_io(&self, handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
+    fn handle_io(&self, handle_fn: &mut dyn FnMut(IoParams)) -> Result<()> {
         let mut status: WHV_EMULATOR_STATUS = Default::default();
         let mut ctx = InstructionEmulatorContext {
             vm_partition: self.vm_partition.clone(),
diff --git a/hypervisor/src/x86_64.rs b/hypervisor/src/x86_64.rs
index 077da2e24..1b9dc3f36 100644
--- a/hypervisor/src/x86_64.rs
+++ b/hypervisor/src/x86_64.rs
@@ -48,9 +48,6 @@ pub trait HypervisorX86_64: Hypervisor {
     /// Get the system supported CPUID values.
     fn get_supported_cpuid(&self) -> Result<CpuId>;
 
-    /// Get the system emulated CPUID values.
-    fn get_emulated_cpuid(&self) -> Result<CpuId>;
-
     /// Gets the list of supported MSRs.
     fn get_msr_index_list(&self) -> Result<Vec<u32>>;
 }
diff --git a/hypervisor/tests/hypervisor_virtualization.rs b/hypervisor/tests/hypervisor_virtualization.rs
index db5fd1f09..fb12833a3 100644
--- a/hypervisor/tests/hypervisor_virtualization.rs
+++ b/hypervisor/tests/hypervisor_virtualization.rs
@@ -884,27 +884,20 @@ fn test_io_exit_handler() {
     let exit_matcher =
         move |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
             VcpuExit::Io => {
-                vcpu.handle_io(&mut |IoParams {
-                                         address,
-                                         size,
-                                         operation,
-                                     }| {
+                vcpu.handle_io(&mut |IoParams { address, operation }| {
                     match operation {
-                        IoOperation::Read => {
-                            let mut data = [0u8; 8];
+                        IoOperation::Read(data) => {
                             assert_eq!(address, 0x20);
-                            assert_eq!(size, 1);
+                            assert_eq!(data.len(), 1);
                             // The original number written below will be doubled and
                             // passed back.
                             data[0] = cached_byte.load(Ordering::SeqCst) * 2;
-                            Some(data)
                         }
-                        IoOperation::Write { data } => {
+                        IoOperation::Write(data) => {
                             assert_eq!(address, 0x10);
-                            assert_eq!(size, 1);
+                            assert_eq!(data.len(), 1);
                             assert_eq!(data[0], 0x34);
                             cached_byte.fetch_add(data[0], Ordering::SeqCst);
-                            None
                         }
                     }
                 })
@@ -919,6 +912,90 @@ fn test_io_exit_handler() {
     run_tests!(setup, regs_matcher, &exit_matcher);
 }
 
+global_asm_data!(
+    test_io_rep_string_code,
+    ".code16",
+    "cld",
+    "mov dx, 0x80",  // read data from I/O port 80h
+    "mov di, 0x100", // write data to memory address 0x100
+    "mov cx, 5",     // repeat 5 times
+    "rep insb",
+    "mov si, 0x100", // read data from memory address 0x100
+    "mov dx, 0x80",  // write data to I/O port 80h
+    "mov cx, 5",     // repeat 5 times
+    "rep outsb",
+    "mov cx, 0x5678",
+    "hlt",
+);
+
+#[cfg(not(feature = "haxm"))]
+#[test]
+fn test_io_rep_string() {
+    // Test the REP OUTS*/REP INS* string I/O instructions, which should call the IO handler
+    // multiple times to handle the requested repeat count.
+    let load_addr = GuestAddress(0x1000);
+    let setup = TestSetup {
+        assembly: test_io_rep_string_code::data().to_vec(),
+        load_addr,
+        initial_regs: Regs {
+            rip: load_addr.offset(),
+            rax: 0x1234,
+            rflags: 2,
+            ..Default::default()
+        },
+        ..Default::default()
+    };
+
+    let regs_matcher = |_, regs: &Regs, _: &_| {
+        // The string I/O instructions should not modify AX.
+        assert_eq!(regs.rax, 0x1234);
+        assert_eq!(regs.rcx, 0x5678);
+    };
+
+    let read_data = AtomicU8::new(0);
+    let write_data = AtomicU8::new(0);
+    let exit_matcher =
+        move |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| match exit {
+            VcpuExit::Io => {
+                vcpu.handle_io(&mut |IoParams { address, operation }| {
+                    match operation {
+                        IoOperation::Read(data) => {
+                            assert_eq!(address, 0x80);
+                            assert_eq!(data.len(), 1);
+                            // Return 0, 1, 2, 3, 4 for subsequent reads.
+                            data[0] = read_data.fetch_add(1, Ordering::SeqCst);
+                        }
+                        IoOperation::Write(data) => {
+                            assert_eq!(address, 0x80);
+                            assert_eq!(data.len(), 1);
+                            // Expect 0, 1, 2, 3, 4 to be written.
+                            let expected_write = write_data.fetch_add(1, Ordering::SeqCst);
+                            assert_eq!(data[0], expected_write);
+                        }
+                    }
+                })
+                .expect("failed to set the data");
+                false // Continue VM runloop
+            }
+            VcpuExit::Hlt => {
+                // Verify 5 reads and writes occurred.
+                assert_eq!(read_data.load(Ordering::SeqCst), 5);
+                assert_eq!(write_data.load(Ordering::SeqCst), 5);
+
+                // Verify the data that should have been written to memory by REP INSB.
+                let mem = vm.get_memory();
+                let mut data = [0u8; 5];
+                mem.read_exact_at_addr(&mut data, GuestAddress(0x100))
+                    .unwrap();
+                assert_eq!(data, [0, 1, 2, 3, 4]);
+
+                true // Break VM runloop
+            }
+            r => panic!("unexpected exit reason: {:?}", r),
+        };
+    run_tests!(setup, regs_matcher, &exit_matcher);
+}
+
 global_asm_data!(
     test_mmio_exit_cross_page_code,
     ".code16",
@@ -955,14 +1032,10 @@ fn test_mmio_exit_cross_page() {
 
     let exit_matcher = |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
         VcpuExit::Mmio => {
-            vcpu.handle_mmio(&mut |IoParams {
-                                       address,
-                                       size,
-                                       operation,
-                                   }| {
+            vcpu.handle_mmio(&mut |IoParams { address, operation }| {
                 match operation {
-                    IoOperation::Read => {
-                        match (address, size) {
+                    IoOperation::Read(data) => {
+                        match (address, data.len()) {
                             // First MMIO read asks to load the first 8 bytes
                             // of a new execution page, when an instruction
                             // crosses page boundary.
@@ -971,21 +1044,25 @@ fn test_mmio_exit_cross_page() {
                             (0x1000, 8) => {
                                 // Ensure this instruction is the first read
                                 // in the sequence.
-                                Ok(Some([0x88, 0x03, 0x67, 0x8a, 0x01, 0xf4, 0, 0]))
+                                data.copy_from_slice(&[0x88, 0x03, 0x67, 0x8a, 0x01, 0xf4, 0, 0]);
+                                Ok(())
                             }
                             // Second MMIO read is a regular read from an
                             // unmapped memory (pointed to by initial EAX).
-                            (0x3010, 1) => Ok(Some([0x66, 0, 0, 0, 0, 0, 0, 0])),
+                            (0x3010, 1) => {
+                                data.copy_from_slice(&[0x66]);
+                                Ok(())
+                            }
                             _ => {
-                                panic!("invalid address({:#x})/size({})", address, size)
+                                panic!("invalid address({:#x})/size({})", address, data.len())
                             }
                         }
                     }
-                    IoOperation::Write { data } => {
+                    IoOperation::Write(data) => {
                         assert_eq!(address, 0x3000);
                         assert_eq!(data[0], 0x33);
-                        assert_eq!(size, 1);
-                        Ok(None)
+                        assert_eq!(data.len(), 1);
+                        Ok(())
                     }
                 }
             })
@@ -1068,19 +1145,15 @@ fn test_mmio_exit_readonly_memory() {
 
     let exit_matcher = |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
         VcpuExit::Mmio => {
-            vcpu.handle_mmio(&mut |IoParams {
-                                       address,
-                                       size,
-                                       operation,
-                                   }| match operation {
-                IoOperation::Read => {
+            vcpu.handle_mmio(&mut |IoParams { address, operation }| match operation {
+                IoOperation::Read(_) => {
                     panic!("unexpected mmio read call");
                 }
-                IoOperation::Write { data } => {
-                    assert_eq!(size, 1);
+                IoOperation::Write(data) => {
+                    assert_eq!(data.len(), 1);
                     assert_eq!(address, 0x5000);
                     assert_eq!(data[0], 0x67);
-                    Ok(None)
+                    Ok(())
                 }
             })
             .expect("failed to set the data");
@@ -1381,6 +1454,7 @@ global_asm_data!(
     "hlt",
 );
 
+#[cfg(not(unix))]
 #[test]
 fn test_getsec_instruction() {
     let setup = TestSetup {
@@ -1605,6 +1679,7 @@ global_asm_data!(
 
 // TODO(b/342183625): invvpid instruction is not valid in real mode. Reconsider how we should write
 // this test.
+#[cfg(not(unix))]
 #[test]
 fn test_invvpid_instruction() {
     let setup = TestSetup {
@@ -2545,7 +2620,6 @@ fn test_interrupt_ready_when_normally_not_interruptible() {
                         }
                         instrumentation_traces.borrow_mut().push(instrumentation);
                         // We are always handling out IO port, so no data to return.
-                        None
                     })
                     .expect("should handle IO successfully");
                     if should_inject_interrupt {
@@ -2603,7 +2677,6 @@ fn test_interrupt_ready_when_interrupt_enable_flag_not_set() {
                     vcpu.handle_io(&mut |io_params| {
                         addr = io_params.address;
                         // We are always handling out IO port, so no data to return.
-                        None
                     })
                     .expect("should handle IO successfully");
                     let regs = vcpu
@@ -2849,7 +2922,7 @@ fn test_request_interrupt_window() {
                     VcpuExit::Intr => false,
                     VcpuExit::Io => {
                         // We are always handling out IO port, so no data to return.
-                        vcpu.handle_io(&mut |_| None)
+                        vcpu.handle_io(&mut |_| {})
                             .expect("should handle IO successfully");
 
                         assert!(!vcpu.ready_for_interrupt());
@@ -3005,7 +3078,7 @@ fn test_mmx_state_is_preserved_by_hypervisor() {
             false
         }
         VcpuExit::Io => {
-            vcpu.handle_io(&mut |_| None)
+            vcpu.handle_io(&mut |_| {})
                 .expect("should handle IO successfully");
 
             // kaiyili@ pointed out we should check the XSAVE state exposed by the hypervisor via
@@ -3145,7 +3218,7 @@ fn test_avx_state_is_preserved_by_hypervisor() {
             false
         }
         VcpuExit::Io => {
-            vcpu.handle_io(&mut |_| None)
+            vcpu.handle_io(&mut |_| {})
                 .expect("should handle IO successfully");
 
             // kaiyili@ pointed out we should check the XSAVE state exposed by the hypervisor via
@@ -3567,7 +3640,7 @@ fn test_slat_on_region_removal_is_mmio() {
                 //
                 // We strictly don't care what this data is, since the VM exits before running any
                 // further instructions.
-                vcpu.handle_io(&mut |_| None)
+                vcpu.handle_io(&mut |_| {})
                     .expect("should handle IO successfully");
 
                 // Remove the test memory region to cause a SLAT fault (in the passing case).
@@ -3579,21 +3652,18 @@ fn test_slat_on_region_removal_is_mmio() {
                 false
             }
             VcpuExit::Mmio => {
-                vcpu.handle_mmio(&mut |IoParams {
-                                           address,
-                                           size,
-                                           operation,
-                                       }| {
+                vcpu.handle_mmio(&mut |IoParams { address, operation }| {
                     assert_eq!(address, 0x20000, "MMIO for wrong address");
-                    assert_eq!(size, 1);
-                    assert!(
-                        matches!(operation, IoOperation::Read),
-                        "got unexpected IO operation {:?}",
-                        operation
-                    );
-                    // We won't vmenter again, so there's no need to actually satisfy the MMIO by
-                    // returning data; however, some hypervisors (WHPX) require it.
-                    Ok(Some([0u8; 8]))
+                    match operation {
+                        IoOperation::Read(data) => {
+                            assert_eq!(data.len(), 1);
+                            data[0] = 0;
+                            Ok(())
+                        }
+                        IoOperation::Write(_) => {
+                            panic!("got unexpected IO operation {:?}", operation);
+                        }
+                    }
                 })
                 .unwrap();
                 true
@@ -3798,7 +3868,7 @@ fn test_interrupt_injection_when_not_ready() {
                 VcpuExit::FailEntry { .. } | VcpuExit::Shutdown(..) | VcpuExit::Hlt => true,
                 VcpuExit::Io => {
                     // We are always handling out IO port, so no data to return.
-                    vcpu.handle_io(&mut |_| None)
+                    vcpu.handle_io(&mut |_| {})
                         .expect("should handle IO successfully");
                     assert!(!vcpu.ready_for_interrupt());
                     // We don't care whether we inject the interrupt successfully or not.
@@ -3866,7 +3936,6 @@ fn test_ready_for_interrupt_for_intercepted_instructions() {
                     vcpu.handle_io(&mut |params| {
                         io_port = params.address;
                         // We are always handling out IO port, so no data to return.
-                        None
                     })
                     .expect("should handle port IO successfully");
                     match io_port {
diff --git a/hypervisor/tests/kvm/x86_64.rs b/hypervisor/tests/kvm/x86_64.rs
index f3ea2cf02..8ab04d71d 100644
--- a/hypervisor/tests/kvm/x86_64.rs
+++ b/hypervisor/tests/kvm/x86_64.rs
@@ -40,13 +40,6 @@ fn get_supported_cpuid() {
     assert!(!cpuid.cpu_id_entries.is_empty());
 }
 
-#[test]
-fn get_emulated_cpuid() {
-    let hypervisor = Kvm::new().unwrap();
-    let cpuid = hypervisor.get_emulated_cpuid().unwrap();
-    assert!(!cpuid.cpu_id_entries.is_empty());
-}
-
 #[test]
 fn get_msr_index_list() {
     let kvm = Kvm::new().unwrap();
diff --git a/hypervisor/tests/mmio_and_pio.rs b/hypervisor/tests/mmio_and_pio.rs
index 2e0f5489d..1956d251c 100644
--- a/hypervisor/tests/mmio_and_pio.rs
+++ b/hypervisor/tests/mmio_and_pio.rs
@@ -111,54 +111,42 @@ where
     loop {
         match vcpu.run().expect("run failed") {
             VcpuExit::Mmio => {
-                vcpu.handle_mmio(&mut |IoParams {
-                                           address,
-                                           size,
-                                           operation,
-                                       }| {
+                vcpu.handle_mmio(&mut |IoParams { address, operation }| {
                     match operation {
-                        IoOperation::Read => {
-                            let mut data = [0u8; 8];
+                        IoOperation::Read(data) => {
                             assert_eq!(address, 0x3010);
-                            assert_eq!(size, 1);
+                            assert_eq!(data.len(), 1);
                             exits.fetch_add(1, Ordering::SeqCst);
                             // this number will be read into al register
-                            data.copy_from_slice(&0x66_u64.to_ne_bytes());
-                            Ok(Some(data))
+                            data.copy_from_slice(&[0x66]);
+                            Ok(())
                         }
-                        IoOperation::Write { data } => {
+                        IoOperation::Write(data) => {
                             assert_eq!(address, 0x3000);
                             assert_eq!(data[0], 0x33);
-                            assert_eq!(size, 1);
+                            assert_eq!(data.len(), 1);
                             exits.fetch_add(1, Ordering::SeqCst);
-                            Ok(None)
+                            Ok(())
                         }
                     }
                 })
                 .expect("failed to set the data");
             }
             VcpuExit::Io => {
-                vcpu.handle_io(&mut |IoParams {
-                                         address,
-                                         size,
-                                         operation,
-                                     }| {
+                vcpu.handle_io(&mut |IoParams { address, operation }| {
                     match operation {
-                        IoOperation::Read => {
-                            let mut data = [0u8; 8];
+                        IoOperation::Read(data) => {
                             assert_eq!(address, 0x20);
-                            assert_eq!(size, 1);
+                            assert_eq!(data.len(), 1);
                             exits.fetch_add(1, Ordering::SeqCst);
                             // this number will be read into the al register
-                            data.copy_from_slice(&0x77_u64.to_ne_bytes());
-                            Some(data)
+                            data.copy_from_slice(&[0x77]);
                         }
-                        IoOperation::Write { data } => {
+                        IoOperation::Write(data) => {
                             assert_eq!(address, 0x19);
-                            assert_eq!(size, 1);
+                            assert_eq!(data.len(), 1);
                             assert_eq!(data[0], 0x66);
                             exits.fetch_add(1, Ordering::SeqCst);
-                            None
                         }
                     }
                 })
@@ -282,27 +270,20 @@ where
     loop {
         match vcpu.run().expect("run failed") {
             VcpuExit::Io => {
-                vcpu.handle_io(&mut |IoParams {
-                                         address,
-                                         size,
-                                         operation,
-                                     }| {
-                    match operation {
-                        IoOperation::Read => panic!("unexpected PIO read"),
-                        IoOperation::Write { data } => {
-                            assert!((1..=4).contains(&address));
-                            if address % 2 == 0 {
-                                assert_eq!(size, 1);
-                                assert_eq!(data[0], address as u8);
-                            } else {
-                                assert_eq!(size, 2);
-                                assert_eq!(data[0], address as u8);
-                                assert_eq!(data[1], 0);
-                            }
-                            exit_bits.fetch_or(1 << (address - 1), Ordering::SeqCst);
-                            exit_count.fetch_add(1, Ordering::SeqCst);
-                            None
+                vcpu.handle_io(&mut |IoParams { address, operation }| match operation {
+                    IoOperation::Read(_) => panic!("unexpected PIO read"),
+                    IoOperation::Write(data) => {
+                        assert!((1..=4).contains(&address));
+                        if address % 2 == 0 {
+                            assert_eq!(data.len(), 1);
+                            assert_eq!(data[0], address as u8);
+                        } else {
+                            assert_eq!(data.len(), 2);
+                            assert_eq!(data[0], address as u8);
+                            assert_eq!(data[1], 0);
                         }
+                        exit_bits.fetch_or(1 << (address - 1), Ordering::SeqCst);
+                        exit_count.fetch_add(1, Ordering::SeqCst);
                     }
                 })
                 .expect("failed to set the data");
@@ -427,31 +408,23 @@ where
     loop {
         match vcpu.run().expect("run failed") {
             VcpuExit::Io => {
-                vcpu.handle_io(&mut |IoParams {
-                                         address,
-                                         size,
-                                         operation,
-                                     }| {
-                    match operation {
-                        IoOperation::Read => {
-                            let mut data = [0u8; 8];
-                            assert!((1..=4).contains(&address));
-
-                            if address % 2 == 0 {
-                                assert_eq!(size, 1);
-                                data[0] = address as u8;
-                            } else {
-                                assert_eq!(size, 2);
-                                data[0] = address as u8;
-                                data[1] = address as u8;
-                            }
-
-                            exit_bits.fetch_or(1 << (address - 1), Ordering::SeqCst);
-                            exit_count.fetch_add(1, Ordering::SeqCst);
-                            Some(data)
+                vcpu.handle_io(&mut |IoParams { address, operation }| match operation {
+                    IoOperation::Read(data) => {
+                        assert!((1..=4).contains(&address));
+
+                        if address % 2 == 0 {
+                            assert_eq!(data.len(), 1);
+                            data[0] = address as u8;
+                        } else {
+                            assert_eq!(data.len(), 2);
+                            data[0] = address as u8;
+                            data[1] = address as u8;
                         }
-                        IoOperation::Write { .. } => panic!("unexpected PIO write"),
+
+                        exit_bits.fetch_or(1 << (address - 1), Ordering::SeqCst);
+                        exit_count.fetch_add(1, Ordering::SeqCst);
                     }
+                    IoOperation::Write(_) => panic!("unexpected PIO write"),
                 })
                 .expect("failed to set the data");
             }
diff --git a/hypervisor/tests/mmio_fetch_memory.rs b/hypervisor/tests/mmio_fetch_memory.rs
index 162c26841..4da3e7ed9 100644
--- a/hypervisor/tests/mmio_fetch_memory.rs
+++ b/hypervisor/tests/mmio_fetch_memory.rs
@@ -80,15 +80,11 @@ fn test_whpx_mmio_fetch_memory() {
         match vcpu.run().expect("run failed") {
             VcpuExit::Mmio => {
                 exits.fetch_add(1, Ordering::SeqCst);
-                vcpu.handle_mmio(&mut |IoParams {
-                                           address,
-                                           size,
-                                           operation,
-                                       }| {
+                vcpu.handle_mmio(&mut |IoParams { address, operation }| {
                     match operation {
-                        IoOperation::Read => {
+                        IoOperation::Read(data) => {
                             memory_reads.fetch_add(1, Ordering::SeqCst);
-                            match (address, size) {
+                            match (address, data.len()) {
                                 // First MMIO read from the WHV_EMULATOR asks to
                                 // load the first 8 bytes of a new execution
                                 // page, when an instruction crosses page
@@ -99,22 +95,28 @@ fn test_whpx_mmio_fetch_memory() {
                                     // Ensure this instruction is the first read
                                     // in the sequence.
                                     assert_eq!(memory_reads.load(Ordering::SeqCst), 1);
-                                    Ok(Some([0x88, 0x03, 0x67, 0x8a, 0x01, 0xf4, 0, 0]))
+                                    data.copy_from_slice(&[
+                                        0x88, 0x03, 0x67, 0x8a, 0x01, 0xf4, 0, 0,
+                                    ]);
+                                    Ok(())
                                 }
                                 // Second MMIO read is a regular read from an
                                 // unmapped memory.
-                                (0x3010, 1) => Ok(Some([0x66, 0, 0, 0, 0, 0, 0, 0])),
+                                (0x3010, 1) => {
+                                    data.copy_from_slice(&[0x66]);
+                                    Ok(())
+                                }
                                 _ => {
-                                    panic!("invalid address({:#x})/size({})", address, size)
+                                    panic!("invalid address({:#x})/size({})", address, data.len())
                                 }
                             }
                         }
-                        IoOperation::Write { data } => {
+                        IoOperation::Write(data) => {
                             assert_eq!(address, 0x3000);
                             assert_eq!(data[0], 0x33);
-                            assert_eq!(size, 1);
+                            assert_eq!(data.len(), 1);
                             memory_writes.fetch_add(1, Ordering::SeqCst);
-                            Ok(None)
+                            Ok(())
                         }
                     }
                 })
diff --git a/hypervisor/tests/read_only_memory.rs b/hypervisor/tests/read_only_memory.rs
index 187ba176a..d44d9be52 100644
--- a/hypervisor/tests/read_only_memory.rs
+++ b/hypervisor/tests/read_only_memory.rs
@@ -163,20 +163,16 @@ where
             VcpuExit::Intr => continue,
             VcpuExit::Hlt => break,
             VcpuExit::Mmio => {
-                vcpu.handle_mmio(&mut |IoParams {
-                                           address,
-                                           size,
-                                           operation,
-                                       }| match operation {
-                    IoOperation::Read => {
+                vcpu.handle_mmio(&mut |IoParams { address, operation }| match operation {
+                    IoOperation::Read(_) => {
                         panic!("unexpected mmio read call");
                     }
-                    IoOperation::Write { data } => {
-                        assert_eq!(size, 1);
+                    IoOperation::Write(data) => {
+                        assert_eq!(data.len(), 1);
                         assert_eq!(address, vcpu_sregs.es.base);
                         assert_eq!(data[0], 0x67);
                         exits.fetch_add(1, Ordering::SeqCst);
-                        Ok(None)
+                        Ok(())
                     }
                 })
                 .expect("failed to set the data");
diff --git a/hypervisor/tests/real_run_addr.rs b/hypervisor/tests/real_run_addr.rs
index b84fdf793..79080f630 100644
--- a/hypervisor/tests/real_run_addr.rs
+++ b/hypervisor/tests/real_run_addr.rs
@@ -108,19 +108,14 @@ where
     loop {
         match vcpu.run().expect("run failed") {
             VcpuExit::Io => {
-                vcpu.handle_io(&mut |IoParams {
-                                         address,
-                                         size,
-                                         operation,
-                                     }| match operation {
-                    IoOperation::Read => {
+                vcpu.handle_io(&mut |IoParams { address, operation }| match operation {
+                    IoOperation::Read(_) => {
                         panic!("unexpected io in call");
                     }
-                    IoOperation::Write { data } => {
+                    IoOperation::Write(data) => {
                         assert_eq!(address, 0x3f8);
-                        assert_eq!(size, 1);
+                        assert_eq!(data.len(), 1);
                         out.lock().push(data[0] as char);
-                        None
                     }
                 })
                 .expect("failed to set the data");
diff --git a/hypervisor/tests/remove_memory.rs b/hypervisor/tests/remove_memory.rs
index 7384d671e..5854ee8ab 100644
--- a/hypervisor/tests/remove_memory.rs
+++ b/hypervisor/tests/remove_memory.rs
@@ -168,19 +168,14 @@ where
             VcpuExit::Intr => continue,
             VcpuExit::Hlt => break,
             VcpuExit::Mmio => {
-                vcpu.handle_mmio(&mut |IoParams {
-                                           address,
-                                           size,
-                                           operation,
-                                       }| match operation {
-                    IoOperation::Read => {
-                        let mut data = [0u8; 8];
+                vcpu.handle_mmio(&mut |IoParams { address, operation }| match operation {
+                    IoOperation::Read(data) => {
                         assert_eq!(address, 0x3000);
-                        assert_eq!(size, 1);
-                        data.copy_from_slice(&0x44_u64.to_ne_bytes());
-                        Ok(Some(data))
+                        assert_eq!(data.len(), 1);
+                        data.copy_from_slice(&[0x44]);
+                        Ok(())
                     }
-                    IoOperation::Write { .. } => {
+                    IoOperation::Write(_) => {
                         panic!("unexpected mmio write");
                     }
                 })
diff --git a/infra/README.recipes.md b/infra/README.recipes.md
index c20bbfb32..e296cd79f 100644
--- a/infra/README.recipes.md
+++ b/infra/README.recipes.md
@@ -181,19 +181,19 @@ This recipe requires ambient luci authentication. To test locally run:
 
 &mdash; **def [RunSteps](/infra/recipes/update_chromeos_merges.py#14)(api):**
 
-[depot_tools/recipe_modules/bot_update]: https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/d1259b49c5b41bc4939ba7c5bb8e8e08083a05f6/recipes/README.recipes.md#recipe_modules-bot_update
-[depot_tools/recipe_modules/depot_tools]: https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/d1259b49c5b41bc4939ba7c5bb8e8e08083a05f6/recipes/README.recipes.md#recipe_modules-depot_tools
-[depot_tools/recipe_modules/gclient]: https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/d1259b49c5b41bc4939ba7c5bb8e8e08083a05f6/recipes/README.recipes.md#recipe_modules-gclient
-[depot_tools/recipe_modules/git]: https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/d1259b49c5b41bc4939ba7c5bb8e8e08083a05f6/recipes/README.recipes.md#recipe_modules-git
-[depot_tools/recipe_modules/gsutil]: https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/d1259b49c5b41bc4939ba7c5bb8e8e08083a05f6/recipes/README.recipes.md#recipe_modules-gsutil
-[recipe_engine/recipe_modules/buildbucket]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/c291dd7687aee4b10811b3d3b517fd20c83e8333/README.recipes.md#recipe_modules-buildbucket
-[recipe_engine/recipe_modules/cipd]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/c291dd7687aee4b10811b3d3b517fd20c83e8333/README.recipes.md#recipe_modules-cipd
-[recipe_engine/recipe_modules/context]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/c291dd7687aee4b10811b3d3b517fd20c83e8333/README.recipes.md#recipe_modules-context
-[recipe_engine/recipe_modules/file]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/c291dd7687aee4b10811b3d3b517fd20c83e8333/README.recipes.md#recipe_modules-file
-[recipe_engine/recipe_modules/json]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/c291dd7687aee4b10811b3d3b517fd20c83e8333/README.recipes.md#recipe_modules-json
-[recipe_engine/recipe_modules/path]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/c291dd7687aee4b10811b3d3b517fd20c83e8333/README.recipes.md#recipe_modules-path
-[recipe_engine/recipe_modules/platform]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/c291dd7687aee4b10811b3d3b517fd20c83e8333/README.recipes.md#recipe_modules-platform
-[recipe_engine/recipe_modules/properties]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/c291dd7687aee4b10811b3d3b517fd20c83e8333/README.recipes.md#recipe_modules-properties
-[recipe_engine/recipe_modules/raw_io]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/c291dd7687aee4b10811b3d3b517fd20c83e8333/README.recipes.md#recipe_modules-raw_io
-[recipe_engine/recipe_modules/step]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/c291dd7687aee4b10811b3d3b517fd20c83e8333/README.recipes.md#recipe_modules-step
-[recipe_engine/wkt/RecipeApi]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/c291dd7687aee4b10811b3d3b517fd20c83e8333/recipe_engine/recipe_api.py#433
+[depot_tools/recipe_modules/bot_update]: https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/2515d3513f7b15bf0cf40994599989b5dd7128ac/recipes/README.recipes.md#recipe_modules-bot_update
+[depot_tools/recipe_modules/depot_tools]: https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/2515d3513f7b15bf0cf40994599989b5dd7128ac/recipes/README.recipes.md#recipe_modules-depot_tools
+[depot_tools/recipe_modules/gclient]: https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/2515d3513f7b15bf0cf40994599989b5dd7128ac/recipes/README.recipes.md#recipe_modules-gclient
+[depot_tools/recipe_modules/git]: https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/2515d3513f7b15bf0cf40994599989b5dd7128ac/recipes/README.recipes.md#recipe_modules-git
+[depot_tools/recipe_modules/gsutil]: https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/2515d3513f7b15bf0cf40994599989b5dd7128ac/recipes/README.recipes.md#recipe_modules-gsutil
+[recipe_engine/recipe_modules/buildbucket]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/3624a48ac89993276cb80e675a88fcd3b39a0f39/README.recipes.md#recipe_modules-buildbucket
+[recipe_engine/recipe_modules/cipd]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/3624a48ac89993276cb80e675a88fcd3b39a0f39/README.recipes.md#recipe_modules-cipd
+[recipe_engine/recipe_modules/context]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/3624a48ac89993276cb80e675a88fcd3b39a0f39/README.recipes.md#recipe_modules-context
+[recipe_engine/recipe_modules/file]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/3624a48ac89993276cb80e675a88fcd3b39a0f39/README.recipes.md#recipe_modules-file
+[recipe_engine/recipe_modules/json]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/3624a48ac89993276cb80e675a88fcd3b39a0f39/README.recipes.md#recipe_modules-json
+[recipe_engine/recipe_modules/path]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/3624a48ac89993276cb80e675a88fcd3b39a0f39/README.recipes.md#recipe_modules-path
+[recipe_engine/recipe_modules/platform]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/3624a48ac89993276cb80e675a88fcd3b39a0f39/README.recipes.md#recipe_modules-platform
+[recipe_engine/recipe_modules/properties]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/3624a48ac89993276cb80e675a88fcd3b39a0f39/README.recipes.md#recipe_modules-properties
+[recipe_engine/recipe_modules/raw_io]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/3624a48ac89993276cb80e675a88fcd3b39a0f39/README.recipes.md#recipe_modules-raw_io
+[recipe_engine/recipe_modules/step]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/3624a48ac89993276cb80e675a88fcd3b39a0f39/README.recipes.md#recipe_modules-step
+[recipe_engine/wkt/RecipeApi]: https://chromium.googlesource.com/infra/luci/recipes-py.git/+/3624a48ac89993276cb80e675a88fcd3b39a0f39/recipe_engine/recipe_api.py#433
diff --git a/infra/config/recipes.cfg b/infra/config/recipes.cfg
index f32176259..45d9f0533 100644
--- a/infra/config/recipes.cfg
+++ b/infra/config/recipes.cfg
@@ -20,12 +20,12 @@
   "deps": {
     "depot_tools": {
       "branch": "refs/heads/main",
-      "revision": "d1259b49c5b41bc4939ba7c5bb8e8e08083a05f6",
+      "revision": "2515d3513f7b15bf0cf40994599989b5dd7128ac",
       "url": "https://chromium.googlesource.com/chromium/tools/depot_tools.git"
     },
     "recipe_engine": {
       "branch": "refs/heads/main",
-      "revision": "c291dd7687aee4b10811b3d3b517fd20c83e8333",
+      "revision": "3624a48ac89993276cb80e675a88fcd3b39a0f39",
       "url": "https://chromium.googlesource.com/infra/luci/recipes-py.git"
     }
   },
diff --git a/jail/seccomp/aarch64/vhost_user.policy b/jail/seccomp/aarch64/vhost_user.policy
index d9e32b6e2..49d537d84 100644
--- a/jail/seccomp/aarch64/vhost_user.policy
+++ b/jail/seccomp/aarch64/vhost_user.policy
@@ -12,3 +12,5 @@ ioctl: arg1 == FIONBIO || arg1 == TCGETS || arg1 == TCSETS
 accept4: 1
 # For creating a socket if the specified socket path does not exits
 socketpair: arg0 == AF_UNIX
+# For crosvm to reap child after vhost_user device exits
+wait4: 1
diff --git a/jail/seccomp/aarch64/virtual_ext2.policy b/jail/seccomp/aarch64/virtual_ext2.policy
index 429685d33..bf5f20536 100644
--- a/jail/seccomp/aarch64/virtual_ext2.policy
+++ b/jail/seccomp/aarch64/virtual_ext2.policy
@@ -10,6 +10,8 @@ getdents64: 1
 getegid: 1
 geteuid: 1
 getrandom: 1
+lgetxattr: 1
+llistxattr: 1
 msync: 1
 mmap: arg2 in ~PROT_EXEC
 munmap: 1
diff --git a/jail/seccomp/arm/virtual_ext2.policy b/jail/seccomp/arm/virtual_ext2.policy
index 0eecb331f..601291ca6 100644
--- a/jail/seccomp/arm/virtual_ext2.policy
+++ b/jail/seccomp/arm/virtual_ext2.policy
@@ -12,6 +12,8 @@ getdents64: 1
 getegid: 1
 geteuid: 1
 getrandom: 1
+lgetxattr: 1
+llistxattr: 1
 mmap2: arg2 in ~PROT_EXEC
 msync: 1
 munmap: 1
diff --git a/jail/seccomp/x86_64/vhost_user.policy b/jail/seccomp/x86_64/vhost_user.policy
index 608530834..8b3443840 100644
--- a/jail/seccomp/x86_64/vhost_user.policy
+++ b/jail/seccomp/x86_64/vhost_user.policy
@@ -13,3 +13,5 @@ ioctl: arg1 == FIONBIO || arg1 == TCGETS || arg1 == TCSETS || arg1 == 0x1277
 accept4: 1
 # For creating a socket if the specified socket path does not exits
 socketpair: arg0 == AF_UNIX
+# For crosvm to reap child after vhost_user device exits
+wait4: 1
diff --git a/jail/seccomp/x86_64/virtual_ext2.policy b/jail/seccomp/x86_64/virtual_ext2.policy
index e96ef723c..57a38baba 100644
--- a/jail/seccomp/x86_64/virtual_ext2.policy
+++ b/jail/seccomp/x86_64/virtual_ext2.policy
@@ -14,8 +14,10 @@ getegid: 1
 geteuid: 1
 getpid: 1
 getrandom: 1
-mmap: arg2 in ~PROT_EXEC
+lgetxattr: 1
+llistxattr: 1
 madvise: 1
+mmap: arg2 in ~PROT_EXEC
 mremap: 1
 msync: 1
 munmap: 1
diff --git a/jail/src/helpers.rs b/jail/src/helpers.rs
index 68a37cab5..28a49e74a 100644
--- a/jail/src/helpers.rs
+++ b/jail/src/helpers.rs
@@ -122,13 +122,11 @@ pub fn create_base_minijail(root: &Path, max_open_files: u64) -> Result<Minijail
         bail!("{:?} is not absolute path", root);
     }
 
-    // All child jails run in a new user namespace without any users mapped, they run as nobody
-    // unless otherwise configured.
     let mut jail = Minijail::new().context("failed to jail device")?;
 
     // Only pivot_root if we are not re-using the current root directory.
     if root != Path::new("/") {
-        // It's safe to call `namespace_vfs` multiple times.
+        // Run in a new mount namespace.
         jail.namespace_vfs();
         jail.enter_pivot_root(root)
             .context("failed to pivot root device")?;
@@ -140,6 +138,42 @@ pub fn create_base_minijail(root: &Path, max_open_files: u64) -> Result<Minijail
     Ok(jail)
 }
 
+/// Creates a [Minijail] instance which just invokes a jail process and sets
+/// `max_open_files` using `RLIMIT_NOFILE`. This is helpful with crosvm process
+/// runs as a non-root user without SYS_ADMIN capabilities.
+///
+/// Unlike `create_base_minijail`, this function doesn't call `pivot_root`
+/// and `mount namespace`. So, it runs as a non-root user without
+/// SYS_ADMIN capabilities.
+///
+/// Note that since there is no file system isolation provided by this function,
+/// caller of this function should enforce other security mechanisum such as selinux
+/// on the host to protect directories.
+///
+/// # Arguments
+///
+/// * `root` - The root path to checked before the process is jailed
+/// * `max_open_files` - The maximum number of file descriptors to allow a jailed process to open.
+#[allow(clippy::unnecessary_cast)]
+pub fn create_base_minijail_without_pivot_root(
+    root: &Path,
+    max_open_files: u64,
+) -> Result<Minijail> {
+    // Validate new root directory. Path::is_dir() also checks the existence.
+    if !root.is_dir() {
+        bail!("{:?} is not a directory, cannot create jail", root);
+    }
+    if !root.is_absolute() {
+        bail!("{:?} is not absolute path", root);
+    }
+
+    let mut jail = Minijail::new().context("failed to jail device")?;
+    jail.set_rlimit(libc::RLIMIT_NOFILE as i32, max_open_files, max_open_files)
+        .context("error setting max open files")?;
+
+    Ok(jail)
+}
+
 /// Creates a [Minijail] instance which creates a sandbox.
 ///
 /// # Arguments
diff --git a/kvm_sys/bindgen.sh b/kvm_sys/bindgen.sh
index 0b417715e..9c6b51860 100755
--- a/kvm_sys/bindgen.sh
+++ b/kvm_sys/bindgen.sh
@@ -24,6 +24,7 @@ pub const KVM_CAP_ARM_PROTECTED_VM: u32 = 0xffbadab1;
 pub const KVM_CAP_ARM_PROTECTED_VM_FLAGS_SET_FW_IPA: u32 = 0;
 pub const KVM_CAP_ARM_PROTECTED_VM_FLAGS_INFO: u32 = 1;
 pub const KVM_VM_TYPE_ARM_PROTECTED: u32 = 0x80000000;
+pub const KVM_X86_PKVM_PROTECTED_VM: u32 = 28;
 pub const KVM_DEV_VFIO_PVIOMMU: u32 = 2;
 pub const KVM_DEV_VFIO_PVIOMMU_ATTACH: u32 = 1;
 #[repr(C)]
diff --git a/kvm_sys/src/aarch64/bindings.rs b/kvm_sys/src/aarch64/bindings.rs
index 4790df549..d181722f0 100644
--- a/kvm_sys/src/aarch64/bindings.rs
+++ b/kvm_sys/src/aarch64/bindings.rs
@@ -22,6 +22,7 @@ pub const KVM_CAP_ARM_PROTECTED_VM: u32 = 0xffbadab1;
 pub const KVM_CAP_ARM_PROTECTED_VM_FLAGS_SET_FW_IPA: u32 = 0;
 pub const KVM_CAP_ARM_PROTECTED_VM_FLAGS_INFO: u32 = 1;
 pub const KVM_VM_TYPE_ARM_PROTECTED: u32 = 0x80000000;
+pub const KVM_X86_PKVM_PROTECTED_VM: u32 = 28;
 pub const KVM_DEV_VFIO_PVIOMMU: u32 = 2;
 pub const KVM_DEV_VFIO_PVIOMMU_ATTACH: u32 = 1;
 #[repr(C)]
diff --git a/kvm_sys/src/lib.rs b/kvm_sys/src/lib.rs
index 5962d42b9..38c77a61b 100644
--- a/kvm_sys/src/lib.rs
+++ b/kvm_sys/src/lib.rs
@@ -82,6 +82,7 @@ pub mod aarch64 {
         0xb5,
         kvm_arm_counter_offset
     );
+    ioctl_iow_nr!(KVM_ARM_VCPU_FINALIZE, KVMIO, 0xc2, libc::c_int);
 
     #[cfg(target_os = "android")]
     ioctl_iowr_nr!(KVM_PVIOMMU_SET_CONFIG, KVMIO, 0x1, kvm_vfio_iommu_config);
diff --git a/kvm_sys/src/riscv64/bindings.rs b/kvm_sys/src/riscv64/bindings.rs
index 0c4f6e910..0dfbbd2c7 100644
--- a/kvm_sys/src/riscv64/bindings.rs
+++ b/kvm_sys/src/riscv64/bindings.rs
@@ -22,6 +22,7 @@ pub const KVM_CAP_ARM_PROTECTED_VM: u32 = 0xffbadab1;
 pub const KVM_CAP_ARM_PROTECTED_VM_FLAGS_SET_FW_IPA: u32 = 0;
 pub const KVM_CAP_ARM_PROTECTED_VM_FLAGS_INFO: u32 = 1;
 pub const KVM_VM_TYPE_ARM_PROTECTED: u32 = 0x80000000;
+pub const KVM_X86_PKVM_PROTECTED_VM: u32 = 28;
 pub const KVM_DEV_VFIO_PVIOMMU: u32 = 2;
 pub const KVM_DEV_VFIO_PVIOMMU_ATTACH: u32 = 1;
 #[repr(C)]
diff --git a/kvm_sys/src/x86/bindings.rs b/kvm_sys/src/x86/bindings.rs
index c491d6f43..6702b3f81 100644
--- a/kvm_sys/src/x86/bindings.rs
+++ b/kvm_sys/src/x86/bindings.rs
@@ -22,6 +22,7 @@ pub const KVM_CAP_ARM_PROTECTED_VM: u32 = 0xffbadab1;
 pub const KVM_CAP_ARM_PROTECTED_VM_FLAGS_SET_FW_IPA: u32 = 0;
 pub const KVM_CAP_ARM_PROTECTED_VM_FLAGS_INFO: u32 = 1;
 pub const KVM_VM_TYPE_ARM_PROTECTED: u32 = 0x80000000;
+pub const KVM_X86_PKVM_PROTECTED_VM: u32 = 28;
 pub const KVM_DEV_VFIO_PVIOMMU: u32 = 2;
 pub const KVM_DEV_VFIO_PVIOMMU_ATTACH: u32 = 1;
 #[repr(C)]
diff --git a/media/ffmpeg/src/avcodec.rs b/media/ffmpeg/src/avcodec.rs
index 14221df62..8cab4db4e 100644
--- a/media/ffmpeg/src/avcodec.rs
+++ b/media/ffmpeg/src/avcodec.rs
@@ -1041,7 +1041,6 @@ impl Drop for AvFrame {
 
 #[cfg(test)]
 mod tests {
-    use std::ptr;
     use std::sync::atomic::AtomicBool;
     use std::sync::atomic::Ordering;
     use std::sync::Arc;
@@ -1078,7 +1077,7 @@ mod tests {
         }
         impl AvBufferSource for DropTestBufferSource {
             fn as_ptr(&self) -> *const u8 {
-                ptr::null()
+                [].as_ptr()
             }
 
             fn len(&self) -> usize {
diff --git a/net_util/src/sys/linux/tap.rs b/net_util/src/sys/linux/tap.rs
index cf707c1be..4d9e0a81c 100644
--- a/net_util/src/sys/linux/tap.rs
+++ b/net_util/src/sys/linux/tap.rs
@@ -504,30 +504,55 @@ fn create_socket() -> Result<net::UdpSocket> {
     Err(Error::CreateSocket(SysError::last()))
 }
 
+fn sockaddr_from_sockaddr_in(addr_in: libc::sockaddr_in) -> libc::sockaddr {
+    assert_eq!(
+        mem::size_of::<libc::sockaddr_in>(),
+        mem::size_of::<libc::sockaddr>()
+    );
+
+    // SAFETY: trivially safe
+    unsafe { mem::transmute::<libc::sockaddr_in, libc::sockaddr>(addr_in) }
+}
+
+fn sockaddr_in_from_sockaddr(addr: libc::sockaddr) -> Option<libc::sockaddr_in> {
+    if addr.sa_family as i32 != libc::AF_INET {
+        return None;
+    }
+
+    assert_eq!(
+        mem::size_of::<libc::sockaddr_in>(),
+        mem::size_of::<libc::sockaddr>()
+    );
+
+    // SAFETY:
+    // This is safe because sockaddr and sockaddr_in are the same size, and we've checked that
+    // this address is AF_INET.
+    Some(unsafe { mem::transmute::<libc::sockaddr, libc::sockaddr_in>(addr) })
+}
+
 /// Create a sockaddr_in from an IPv4 address, and expose it as
 /// an opaque sockaddr suitable for usage by socket ioctls.
 fn create_sockaddr(ip_addr: net::Ipv4Addr) -> libc::sockaddr {
-    // IPv4 addresses big-endian (network order), but Ipv4Addr will give us
-    // a view of those bytes directly so we can avoid any endian trickiness.
     let addr_in = libc::sockaddr_in {
         sin_family: libc::AF_INET as u16,
         sin_port: 0,
-        // SAFETY: trivially safe
-        sin_addr: unsafe { mem::transmute(ip_addr.octets()) },
+        sin_addr: libc::in_addr {
+            // `Ipv4Addr::octets()` returns the address in network byte order, so use
+            // `from_be_bytes()` to convert it into the native endianness, then `to_be()` to convert
+            // it back into big-endian (network) byte order as required by `sockaddr_in`. This is
+            // effectively a no-op, and we could use `u32::from_ne_bytes()` instead, but it is
+            // easier to understand when written this way.
+            s_addr: u32::from_be_bytes(ip_addr.octets()).to_be(),
+        },
         sin_zero: [0; 8usize],
     };
 
-    // SAFETY: trivially safe
-    unsafe { mem::transmute(addr_in) }
+    sockaddr_from_sockaddr_in(addr_in)
 }
 
 /// Extract the IPv4 address from a sockaddr. Assumes the sockaddr is a sockaddr_in.
 fn read_ipv4_addr(addr: &libc::sockaddr) -> net::Ipv4Addr {
-    debug_assert_eq!(addr.sa_family as i32, libc::AF_INET);
-    // SAFETY:
-    // This is safe because sockaddr and sockaddr_in are the same size, and we've checked that
-    // this address is AF_INET.
-    let in_addr: libc::sockaddr_in = unsafe { mem::transmute(*addr) };
+    let in_addr = sockaddr_in_from_sockaddr(*addr).unwrap();
     net::Ipv4Addr::from(in_addr.sin_addr.s_addr)
 }
 
@@ -666,3 +691,22 @@ pub mod fakes {
     impl TapT for FakeTap {}
     volatile_impl!(FakeTap);
 }
+
+#[cfg(test)]
+pub mod tests {
+    use super::*;
+
+    #[test]
+    fn sockaddr_byte_order() {
+        let sa = create_sockaddr(net::Ipv4Addr::new(1, 2, 3, 4));
+        assert_eq!(sa.sa_family, 2); // AF_INET
+        assert_eq!(
+            sa.sa_data,
+            [
+                0, 0, // sin_port
+                1, 2, 3, 4, // sin_addr
+                0, 0, 0, 0, 0, 0, 0, 0, // sin_zero
+            ]
+        );
+    }
+}
diff --git a/power_monitor/Android.bp b/power_monitor/Android.bp
index dd5547d9d..dfb12af3e 100644
--- a/power_monitor/Android.bp
+++ b/power_monitor/Android.bp
@@ -27,14 +27,12 @@ rust_library {
     cargo_env_compat: true,
     cargo_pkg_version: "0.1.0",
     crate_root: "src/lib.rs",
+    srcs: [":copy_power_monitor_build_out"],
     edition: "2021",
     rustlibs: [
         "libbase_rust",
         "libprotobuf",
         "libthiserror",
     ],
-    srcs: [
-        ":copy_power_monitor_build_out",
-    ],
     proc_macros: ["libremain"],
 }
diff --git a/power_monitor/Cargo.toml b/power_monitor/Cargo.toml
index c31dd73d1..f92a7fafd 100644
--- a/power_monitor/Cargo.toml
+++ b/power_monitor/Cargo.toml
@@ -5,13 +5,14 @@ authors = ["The ChromiumOS Authors"]
 edition = "2021"
 
 [features]
-powerd = ["dbus"]
+powerd = ["dbus", "system_api"]
 
 [dependencies]
 base = { path = "../base" }
 dbus = { version = "0.9", optional = true }
 protobuf = "3.2"
 remain = "0.2"
+system_api = { path = "../system_api", optional = true }
 thiserror = "1.0.20"
 
 [build-dependencies]
diff --git a/power_monitor/patches/Android.bp.patch b/power_monitor/patches/Android.bp.patch
deleted file mode 100644
index ad701c224..000000000
--- a/power_monitor/patches/Android.bp.patch
+++ /dev/null
@@ -1,27 +0,0 @@
-diff --git a/power_monitor/Android.bp b/power_monitor/Android.bp
-index 524ba3aaa..dd5547d9d 100644
---- a/power_monitor/Android.bp
-+++ b/power_monitor/Android.bp
-@@ -12,6 +12,13 @@ package {
-     default_applicable_licenses: ["external_crosvm_license"],
- }
- 
-+genrule {
-+    name: "copy_power_monitor_build_out",
-+    srcs: ["out/*"],
-+    cmd: "cp $(in) $(genDir)",
-+    out: ["generated.rs"],
-+}
-+
- rust_library {
-     name: "libpower_monitor",
-     defaults: ["crosvm_inner_defaults"],
-@@ -26,5 +33,8 @@ rust_library {
-         "libprotobuf",
-         "libthiserror",
-     ],
-+    srcs: [
-+        ":copy_power_monitor_build_out",
-+    ],
-     proc_macros: ["libremain"],
- }
diff --git a/power_monitor/src/lib.rs b/power_monitor/src/lib.rs
index 75c8d47b9..1b8e2c648 100644
--- a/power_monitor/src/lib.rs
+++ b/power_monitor/src/lib.rs
@@ -12,12 +12,17 @@ pub trait PowerMonitor: ReadNotifier {
     fn read_message(&mut self) -> std::result::Result<Option<PowerData>, Box<dyn Error>>;
 }
 
+pub trait PowerClient {
+    fn get_power_data(&mut self) -> std::result::Result<PowerData, Box<dyn Error>>;
+}
+
+#[derive(Debug)]
 pub struct PowerData {
     pub ac_online: bool,
     pub battery: Option<BatteryData>,
 }
 
-#[derive(Clone, Copy)]
+#[derive(Clone, Copy, Debug)]
 pub struct BatteryData {
     pub status: BatteryStatus,
     pub percent: u32,
@@ -31,7 +36,7 @@ pub struct BatteryData {
     pub charge_full: u32,
 }
 
-#[derive(Clone, Copy)]
+#[derive(Clone, Copy, Debug)]
 pub enum BatteryStatus {
     Unknown,
     Charging,
@@ -49,6 +54,16 @@ impl<T> CreatePowerMonitorFn for T where
 {
 }
 
+pub trait CreatePowerClientFn:
+    Send + Fn() -> std::result::Result<Box<dyn PowerClient>, Box<dyn Error>>
+{
+}
+
+impl<T> CreatePowerClientFn for T where
+    T: Send + Fn() -> std::result::Result<Box<dyn PowerClient>, Box<dyn Error>>
+{
+}
+
 #[cfg(feature = "powerd")]
 pub mod powerd;
 
diff --git a/power_monitor/src/powerd.rs b/power_monitor/src/powerd.rs
new file mode 100644
index 000000000..c60571941
--- /dev/null
+++ b/power_monitor/src/powerd.rs
@@ -0,0 +1,64 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+//! Bindings for the ChromeOS `powerd` D-Bus API.
+//!
+//! <https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/README.md>
+
+use crate::protos::power_supply_properties::power_supply_properties;
+use crate::protos::power_supply_properties::PowerSupplyProperties;
+use crate::BatteryData;
+use crate::BatteryStatus;
+use crate::PowerData;
+
+// Interface name from power_manager/dbus_bindings/org.chromium.PowerManager.xml.
+pub const POWER_INTERFACE_NAME: &str = "org.chromium.PowerManager";
+// Object path from power_manager/dbus_bindings/org.chromium.PowerManager.xml.
+pub const POWER_OBJECT_PATH: &str = "/org/chromium/PowerManager";
+
+pub mod client;
+pub mod monitor;
+
+impl From<PowerSupplyProperties> for PowerData {
+    fn from(props: PowerSupplyProperties) -> Self {
+        let ac_online = if props.has_external_power() {
+            props.external_power() != power_supply_properties::ExternalPower::DISCONNECTED
+        } else {
+            false
+        };
+
+        let battery = if props.has_battery_state()
+            && props.battery_state() != power_supply_properties::BatteryState::NOT_PRESENT
+        {
+            let status = match props.battery_state() {
+                power_supply_properties::BatteryState::FULL => BatteryStatus::NotCharging,
+                power_supply_properties::BatteryState::CHARGING => BatteryStatus::Charging,
+                power_supply_properties::BatteryState::DISCHARGING => BatteryStatus::Discharging,
+                _ => BatteryStatus::Unknown,
+            };
+
+            let percent = std::cmp::min(100, props.battery_percent().round() as u32);
+            // Convert from volts to microvolts.
+            let voltage = (props.battery_voltage() * 1_000_000f64).round() as u32;
+            // Convert from amps to microamps.
+            let current = (props.battery_current() * 1_000_000f64).round() as u32;
+            // Convert from ampere-hours to micro ampere-hours.
+            let charge_counter = (props.battery_charge() * 1_000_000f64).round() as u32;
+            let charge_full = (props.battery_charge_full() * 1_000_000f64).round() as u32;
+
+            Some(BatteryData {
+                status,
+                percent,
+                voltage,
+                current,
+                charge_counter,
+                charge_full,
+            })
+        } else {
+            None
+        };
+
+        Self { ac_online, battery }
+    }
+}
diff --git a/power_monitor/src/powerd/client.rs b/power_monitor/src/powerd/client.rs
new file mode 100644
index 000000000..e3c3b3d0f
--- /dev/null
+++ b/power_monitor/src/powerd/client.rs
@@ -0,0 +1,71 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+//! Dbus client for sending request to powerd to get power properties.
+
+use std::error::Error;
+use std::time::Duration;
+
+use dbus::blocking::Connection;
+use protobuf::Message;
+use remain::sorted;
+use system_api::client::OrgChromiumPowerManager;
+use thiserror::Error;
+
+use crate::powerd::POWER_INTERFACE_NAME;
+use crate::powerd::POWER_OBJECT_PATH;
+use crate::protos::power_supply_properties::PowerSupplyProperties;
+use crate::PowerClient;
+use crate::PowerData;
+
+// 25 seconds is the default timeout for dbus-send.
+const DEFAULT_DBUS_TIMEOUT: Duration = Duration::from_secs(25);
+
+pub struct DBusClient {
+    connection: Connection,
+}
+
+#[sorted]
+#[derive(Error, Debug)]
+pub enum DBusClientError {
+    #[error("failed to convert protobuf message: {0}")]
+    ConvertProtobuf(protobuf::Error),
+    #[error("failed to connect to D-Bus: {0}")]
+    DBusConnect(dbus::Error),
+    #[error("failed to read D-Bus message: {0}")]
+    DBusRead(dbus::Error),
+}
+
+impl DBusClient {
+    /// Creates a new blocking dbus connection to system bus.
+    pub fn connect() -> std::result::Result<Box<dyn PowerClient>, Box<dyn Error>> {
+        let channel = dbus::channel::Channel::get_private(dbus::channel::BusType::System)
+            .map_err(DBusClientError::DBusConnect)?;
+
+        let connection = dbus::blocking::Connection::from(channel);
+
+        Ok(Box::new(Self { connection }))
+    }
+}
+
+// Send GetPowerSupplyProperties dbus request to power_manager(powerd), blocks until it gets
+// response, and converts the response into PowerData.
+impl PowerClient for DBusClient {
+    fn get_power_data(&mut self) -> std::result::Result<PowerData, Box<dyn Error>> {
+        let proxy = self.connection.with_proxy(
+            POWER_INTERFACE_NAME,
+            POWER_OBJECT_PATH,
+            DEFAULT_DBUS_TIMEOUT,
+        );
+        let data_bytes = proxy
+            .get_power_supply_properties()
+            .map_err(DBusClientError::DBusRead)?;
+        let mut props = PowerSupplyProperties::new();
+        props
+            .merge_from_bytes(&data_bytes)
+            .map_err(DBusClientError::ConvertProtobuf)?;
+        let data: PowerData = props.into();
+        Ok(data)
+    }
+}
diff --git a/power_monitor/src/powerd/mod.rs b/power_monitor/src/powerd/monitor.rs
similarity index 74%
rename from power_monitor/src/powerd/mod.rs
rename to power_monitor/src/powerd/monitor.rs
index 39fe6b611..b02a2b685 100644
--- a/power_monitor/src/powerd/mod.rs
+++ b/power_monitor/src/powerd/monitor.rs
@@ -1,10 +1,8 @@
-// Copyright 2020 The ChromiumOS Authors
+// Copyright 2024 The ChromiumOS Authors
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-//! Bindings for the ChromeOS `powerd` D-Bus API.
-//!
-//! <https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/README.md>
+//! Dbus monitor for polling signal from powerd to update power properties.
 
 use std::error::Error;
 use std::os::unix::io::RawFd;
@@ -20,62 +18,15 @@ use protobuf::Message;
 use remain::sorted;
 use thiserror::Error;
 
-use crate::protos::power_supply_properties::power_supply_properties;
+use crate::powerd::POWER_INTERFACE_NAME;
 use crate::protos::power_supply_properties::PowerSupplyProperties;
 use crate::BatteryData;
-use crate::BatteryStatus;
 use crate::PowerData;
 use crate::PowerMonitor;
 
-// Interface name from power_manager/dbus_bindings/org.chromium.PowerManager.xml.
-const POWER_INTERFACE_NAME: &str = "org.chromium.PowerManager";
-
 // Signal name from power_manager/dbus_constants.h.
 const POLL_SIGNAL_NAME: &str = "PowerSupplyPoll";
 
-impl From<PowerSupplyProperties> for PowerData {
-    fn from(props: PowerSupplyProperties) -> Self {
-        let ac_online = if props.has_external_power() {
-            props.external_power() != power_supply_properties::ExternalPower::DISCONNECTED
-        } else {
-            false
-        };
-
-        let battery = if props.has_battery_state()
-            && props.battery_state() != power_supply_properties::BatteryState::NOT_PRESENT
-        {
-            let status = match props.battery_state() {
-                power_supply_properties::BatteryState::FULL => BatteryStatus::NotCharging,
-                power_supply_properties::BatteryState::CHARGING => BatteryStatus::Charging,
-                power_supply_properties::BatteryState::DISCHARGING => BatteryStatus::Discharging,
-                _ => BatteryStatus::Unknown,
-            };
-
-            let percent = std::cmp::min(100, props.battery_percent().round() as u32);
-            // Convert from volts to microvolts.
-            let voltage = (props.battery_voltage() * 1_000_000f64).round() as u32;
-            // Convert from amps to microamps.
-            let current = (props.battery_current() * 1_000_000f64).round() as u32;
-            // Convert from ampere-hours to micro ampere-hours.
-            let charge_counter = (props.battery_charge() * 1_000_000f64).round() as u32;
-            let charge_full = (props.battery_charge_full() * 1_000_000f64).round() as u32;
-
-            Some(BatteryData {
-                status,
-                percent,
-                voltage,
-                current,
-                charge_counter,
-                charge_full,
-            })
-        } else {
-            None
-        };
-
-        Self { ac_online, battery }
-    }
-}
-
 #[sorted]
 #[derive(Error, Debug)]
 pub enum DBusMonitorError {
diff --git a/riscv64/src/lib.rs b/riscv64/src/lib.rs
index 24aae8b34..90d1a2799 100644
--- a/riscv64/src/lib.rs
+++ b/riscv64/src/lib.rs
@@ -134,7 +134,9 @@ pub enum Error {
     InitrdLoadFailure(arch::LoadImageError),
     #[error("kernel could not be loaded: {0}")]
     KernelLoadFailure(arch::LoadImageError),
-    #[error("protected vms not supported on riscv(yet)")]
+    #[error("PCI mem region not configurable on riscv (yet)")]
+    PciMemNotConfigurable,
+    #[error("protected vms not supported on riscv (yet)")]
     ProtectedVmUnsupported,
     #[error("ramoops address is different from high_mmio_base: {0} vs {1}")]
     RamoopsAddress(u64, u64),
@@ -158,15 +160,28 @@ pub enum Error {
 
 pub type Result<T> = std::result::Result<T, Error>;
 
+pub struct ArchMemoryLayout {}
+
 pub struct Riscv64;
 
 impl arch::LinuxArch for Riscv64 {
     type Error = Error;
+    type ArchMemoryLayout = ArchMemoryLayout;
+
+    fn arch_memory_layout(
+        components: &VmComponents,
+    ) -> std::result::Result<Self::ArchMemoryLayout, Self::Error> {
+        if components.pci_config.mem.is_some() {
+            return Err(Error::PciMemNotConfigurable);
+        }
+        Ok(ArchMemoryLayout {})
+    }
 
     /// Returns a Vec of the valid memory addresses.
     /// These should be used to configure the GuestMemory structure for the platfrom.
     fn guest_memory_layout(
         components: &VmComponents,
+        _arch_memory_layout: &Self::ArchMemoryLayout,
         _hypervisor: &impl Hypervisor,
     ) -> std::result::Result<Vec<(GuestAddress, u64, MemoryRegionOptions)>, Self::Error> {
         Ok(vec![(
@@ -176,12 +191,26 @@ impl arch::LinuxArch for Riscv64 {
         )])
     }
 
-    fn get_system_allocator_config<V: Vm>(vm: &V) -> SystemAllocatorConfig {
-        get_resource_allocator_config(vm.get_memory().memory_size(), vm.get_guest_phys_addr_bits())
+    fn get_system_allocator_config<V: Vm>(
+        vm: &V,
+        _arch_memory_layout: &Self::ArchMemoryLayout,
+    ) -> SystemAllocatorConfig {
+        let (high_mmio_base, high_mmio_size) =
+            get_high_mmio_base_size(vm.get_memory().memory_size(), vm.get_guest_phys_addr_bits());
+        SystemAllocatorConfig {
+            io: None,
+            low_mmio: AddressRange::from_start_and_size(RISCV64_MMIO_BASE, RISCV64_MMIO_SIZE)
+                .expect("invalid mmio region"),
+            high_mmio: AddressRange::from_start_and_size(high_mmio_base, high_mmio_size)
+                .expect("invalid high mmio region"),
+            platform_mmio: None,
+            first_irq: RISCV64_IRQ_BASE,
+        }
     }
 
     fn build_vm<V, Vcpu>(
         mut components: VmComponents,
+        _arch_memory_layout: &Self::ArchMemoryLayout,
         _vm_evt_wrtube: &SendTube,
         system_allocator: &mut SystemAllocator,
         serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
@@ -198,6 +227,7 @@ impl arch::LinuxArch for Riscv64 {
         _guest_suspended_cvar: Option<Arc<(Mutex<bool>, Condvar)>>,
         device_tree_overlays: Vec<DtbOverlay>,
         fdt_position: Option<FdtPosition>,
+        _no_pmu: bool,
     ) -> std::result::Result<RunnableLinuxVm<V, Vcpu>, Self::Error>
     where
         V: VmRiscv64,
@@ -424,8 +454,6 @@ impl arch::LinuxArch for Riscv64 {
             delay_rt: components.delay_rt,
             suspend_tube: (Arc::new(Mutex::new(suspend_tube_send)), suspend_tube_recv),
             bat_control: None,
-            #[cfg(feature = "gdb")]
-            gdb: components.gdb,
             pm: None,
             devices_thread: None,
             vm_request_tubes: Vec::new(),
@@ -554,22 +582,3 @@ fn get_base_linux_cmdline() -> kernel_cmdline::Cmdline {
     cmdline.insert_str("panic=-1").unwrap();
     cmdline
 }
-
-/// Returns a system resource allocator coniguration.
-///
-/// # Arguments
-///
-/// * `mem_size` - Size of guest memory (RAM) in bytes.
-/// * `guest_phys_addr_bits` - Size of guest physical addresses (IPA) in bits.
-fn get_resource_allocator_config(mem_size: u64, guest_phys_addr_bits: u8) -> SystemAllocatorConfig {
-    let (high_mmio_base, high_mmio_size) = get_high_mmio_base_size(mem_size, guest_phys_addr_bits);
-    SystemAllocatorConfig {
-        io: None,
-        low_mmio: AddressRange::from_start_and_size(RISCV64_MMIO_BASE, RISCV64_MMIO_SIZE)
-            .expect("invalid mmio region"),
-        high_mmio: AddressRange::from_start_and_size(high_mmio_base, high_mmio_size)
-            .expect("invalid high mmio region"),
-        platform_mmio: None,
-        first_irq: RISCV64_IRQ_BASE,
-    }
-}
diff --git a/rutabaga_gfx/Android.bp b/rutabaga_gfx/Android.bp
index 4964f3118..cc1bd610b 100644
--- a/rutabaga_gfx/Android.bp
+++ b/rutabaga_gfx/Android.bp
@@ -30,6 +30,8 @@ rust_library {
         "liblibc",
         "liblog_rust",
         "libnix",
+        "libserde",
+        "libserde_json",
         "libthiserror",
         "libzerocopy",
     ],
@@ -77,6 +79,8 @@ rust_library {
         "liblibc",
         "liblog_rust",
         "libnix",
+        "libserde",
+        "libserde_json",
         "libthiserror",
         "libzerocopy",
     ],
@@ -84,6 +88,7 @@ rust_library {
     target: {
         host: {
             cfgs: [
+                "fence_passing_option1",
                 "gfxstream_unstable",
             ],
             features: [
@@ -100,6 +105,7 @@ rust_library {
         },
         android: {
             cfgs: [
+                "fence_passing_option1",
                 "gfxstream_unstable",
             ],
         },
@@ -129,6 +135,8 @@ rust_test {
         "liblibc",
         "liblog_rust",
         "libnix",
+        "libserde",
+        "libserde_json",
         "libthiserror",
         "libzerocopy",
     ],
diff --git a/rutabaga_gfx/Cargo.toml b/rutabaga_gfx/Cargo.toml
index 78ae2bcb0..944dfd361 100644
--- a/rutabaga_gfx/Cargo.toml
+++ b/rutabaga_gfx/Cargo.toml
@@ -20,6 +20,8 @@ x = []
 cfg-if = "1.0.0"
 libc = "0.2.116"
 remain = "0.2"
+serde = { version = "1", features = ["derive"] }
+serde_json = "1"
 thiserror = "1.0.23"
 zerocopy = { version = "0.7", features = ["derive"] }
 
diff --git a/rutabaga_gfx/build.rs b/rutabaga_gfx/build.rs
index 875504cc8..c277e4b23 100644
--- a/rutabaga_gfx/build.rs
+++ b/rutabaga_gfx/build.rs
@@ -94,6 +94,7 @@ fn build_and_probe_minigbm(out_dir: &Path) -> Result<()> {
         .env("MAKEFLAGS", make_flags)
         .env("VERBOSE", "1")
         .env("CROSS_COMPILE", get_cross_compile_prefix())
+        .env("PKG_CONFIG", "pkg-config")
         .arg(format!("OUT={}", out_dir.display()))
         .arg("CC_STATIC_LIBRARY(libminigbm.pie.a)")
         .current_dir(SOURCE_DIR)
@@ -278,8 +279,10 @@ fn gfxstream() -> Result<()> {
 }
 
 fn main() -> Result<()> {
+    println!("cargo:rustc-check-cfg=cfg(fence_passing_option1)");
     println!("cargo:rustc-check-cfg=cfg(gfxstream_unstable)");
     println!("cargo:rustc-check-cfg=cfg(virgl_renderer_unstable)");
+    let mut use_fence_passing_option1 = true;
 
     // Skip installing dependencies when generating documents.
     if env::var("CARGO_DOC").is_ok() {
@@ -292,6 +295,7 @@ fn main() -> Result<()> {
 
     if env::var("CARGO_FEATURE_VIRGL_RENDERER").is_ok() {
         virglrenderer()?;
+        use_fence_passing_option1 = false;
     }
 
     if env::var("CARGO_FEATURE_GFXSTREAM").is_ok()
@@ -300,5 +304,9 @@ fn main() -> Result<()> {
         gfxstream()?;
     }
 
+    if use_fence_passing_option1 {
+        println!("cargo:rustc-cfg=fence_passing_option1");
+    }
+
     Ok(())
 }
diff --git a/rutabaga_gfx/ffi/src/include/rutabaga_gfx_ffi.h b/rutabaga_gfx/ffi/src/include/rutabaga_gfx_ffi.h
index 307fd13f5..59019f6d8 100644
--- a/rutabaga_gfx/ffi/src/include/rutabaga_gfx_ffi.h
+++ b/rutabaga_gfx/ffi/src/include/rutabaga_gfx_ffi.h
@@ -364,6 +364,8 @@ int32_t rutabaga_snapshot(struct rutabaga *ptr, const char *dir);
  */
 int32_t rutabaga_restore(struct rutabaga *ptr, const char *dir);
 
+int32_t rutabaga_resource_wait_sync(struct rutabaga *ptr, uint32_t resource_id);
+
 #ifdef __cplusplus
 }
 #endif
diff --git a/rutabaga_gfx/ffi/src/lib.rs b/rutabaga_gfx/ffi/src/lib.rs
index 83e078180..0073d4f46 100644
--- a/rutabaga_gfx/ffi/src/lib.rs
+++ b/rutabaga_gfx/ffi/src/lib.rs
@@ -697,3 +697,12 @@ pub unsafe extern "C" fn rutabaga_restore(ptr: &mut rutabaga, dir: *const c_char
     }))
     .unwrap_or(-ESRCH)
 }
+
+#[no_mangle]
+pub extern "C" fn rutabaga_resource_wait_sync(ptr: &mut rutabaga, resource_id: u32) -> i32 {
+    catch_unwind(AssertUnwindSafe(|| {
+        let result = ptr.wait_sync(resource_id);
+        return_result(result)
+    }))
+    .unwrap_or(-ESRCH)
+}
diff --git a/rutabaga_gfx/kumquat/gpu_client/src/include/virtgpu_kumquat_ffi.h b/rutabaga_gfx/kumquat/gpu_client/src/include/virtgpu_kumquat_ffi.h
index 33e534483..1c0426485 100644
--- a/rutabaga_gfx/kumquat/gpu_client/src/include/virtgpu_kumquat_ffi.h
+++ b/rutabaga_gfx/kumquat/gpu_client/src/include/virtgpu_kumquat_ffi.h
@@ -34,24 +34,24 @@ struct drm_kumquat_execbuffer_syncobj {
     uint64_t point;
 };
 
-#define VIRTGPU_KUMQUAT_EXECBUF_FENCE_FD_IN 0x01
-#define VIRTGPU_KUMQUAT_EXECBUF_FENCE_FD_OUT 0x02
+#define VIRTGPU_KUMQUAT_EXECBUF_FENCE_HANDLE_IN 0x01
+#define VIRTGPU_KUMQUAT_EXECBUF_FENCE_HANDLE_OUT 0x02
 #define VIRTGPU_KUMQUAT_EXECBUF_RING_IDX 0x04
 #define VIRTGPU_KUMQUAT_EXECBUF_SHAREABLE_IN 0x08
 #define VIRTGPU_KUMQUAT_EXECBUF_SHAREABLE_OUT 0x10
 
 #define VIRTGPU_KUMQUAT_EXECBUF_FLAGS                                                              \
-    (VIRTGPU_EXECBUF_FENCE_FD_IN | VIRTGPU_EXECBUF_FENCE_FD_OUT | VIRTGPU_EXECBUF_RING_IDX |       \
-     VIRTGPU_EXECBUF_SHAREABLE_IN | VIRTGPU_EXECBUF_SHAREABLE_OUT | 0)
+    (VIRTGPU_EXECBUF_FENCE_HANDLE_IN | VIRTGPU_EXECBUF_FENCE_HANDLE_OUT |                          \
+     VIRTGPU_EXECBUF_RING_IDX | VIRTGPU_EXECBUF_SHAREABLE_IN | VIRTGPU_EXECBUF_SHAREABLE_OUT | 0)
 
-/* fence_fd is modified on success if VIRTGPU_KUMQUAT_EXECBUF_FENCE_FD_OUT flag is set. */
+/* fence_fd is modified on success if VIRTGPU_KUMQUAT_EXECBUF_FENCE_HANDLE_OUT flag is set. */
 struct drm_kumquat_execbuffer {
     uint32_t flags;
     uint32_t size;
     uint64_t command; /* void* */
     uint64_t bo_handles;
     uint32_t num_bo_handles;
-    int32_t fence_fd;        /* in/out fence fd (see VIRTGPU_KUMQUAT_EXECBUF_FENCE_FD_IN/OUT) */
+    int64_t fence_handle;    /* in/out fence fd (see VIRTGPU_KUMQUAT_EXECBUF_FENCE_HANDLE_IN/OUT) */
     uint32_t ring_idx;       /* command ring index (see VIRTGPU_KUMQUAT_EXECBUF_RING_IDX) */
     uint32_t syncobj_stride; /* size of @drm_kumquat_execbuffer_syncobj */
     uint32_t num_in_syncobjs;
diff --git a/rutabaga_gfx/kumquat/gpu_client/src/lib.rs b/rutabaga_gfx/kumquat/gpu_client/src/lib.rs
index 5b582d688..e2d280dad 100644
--- a/rutabaga_gfx/kumquat/gpu_client/src/lib.rs
+++ b/rutabaga_gfx/kumquat/gpu_client/src/lib.rs
@@ -20,6 +20,7 @@ use std::sync::Mutex;
 use libc::EINVAL;
 use libc::ESRCH;
 use log::error;
+use rutabaga_gfx::kumquat_support::RUTABAGA_DEFAULT_RAW_DESCRIPTOR;
 use rutabaga_gfx::RutabagaDescriptor;
 use rutabaga_gfx::RutabagaFromRawDescriptor;
 use rutabaga_gfx::RutabagaHandle;
@@ -283,14 +284,17 @@ pub unsafe extern "C" fn virtgpu_kumquat_execbuffer(
         // TODO
         let in_fences: &[u64] = &[0; 0];
 
+        let mut descriptor: RutabagaRawDescriptor = RUTABAGA_DEFAULT_RAW_DESCRIPTOR;
         let result = ptr.lock().unwrap().submit_command(
             cmd.flags,
             bo_handles,
             cmd_buf,
             cmd.ring_idx,
             in_fences,
-            &mut cmd.fence_fd as &mut RutabagaRawDescriptor,
+            &mut descriptor,
         );
+
+        cmd.fence_handle = descriptor as i64;
         return_result(result)
     }))
     .unwrap_or(-ESRCH)
@@ -335,7 +339,7 @@ pub unsafe extern "C" fn virtgpu_kumquat_resource_import(
     catch_unwind(AssertUnwindSafe(|| {
         let handle = RutabagaHandle {
             os_handle: RutabagaDescriptor::from_raw_descriptor(
-                (*cmd).os_handle.try_into().unwrap(),
+                (*cmd).os_handle.into_raw_descriptor(),
             ),
             handle_type: (*cmd).handle_type,
         };
diff --git a/rutabaga_gfx/kumquat/gpu_client/src/virtgpu/defines.rs b/rutabaga_gfx/kumquat/gpu_client/src/virtgpu/defines.rs
index 0f2dd81a3..bc50504e1 100644
--- a/rutabaga_gfx/kumquat/gpu_client/src/virtgpu/defines.rs
+++ b/rutabaga_gfx/kumquat/gpu_client/src/virtgpu/defines.rs
@@ -132,7 +132,7 @@ pub struct VirtGpuExecBuffer {
     pub command: u64,
     pub bo_handles: u64,
     pub num_bo_handles: u32,
-    pub fence_fd: i32,
+    pub fence_handle: i64,
     pub ring_idx: u32,
     pub syncobj_stride: u32,
     pub num_in_syncobjs: u32,
diff --git a/rutabaga_gfx/kumquat/gpu_client/src/virtgpu/virtgpu_kumquat.rs b/rutabaga_gfx/kumquat/gpu_client/src/virtgpu/virtgpu_kumquat.rs
index 8ad07be81..3e03bc9a6 100644
--- a/rutabaga_gfx/kumquat/gpu_client/src/virtgpu/virtgpu_kumquat.rs
+++ b/rutabaga_gfx/kumquat/gpu_client/src/virtgpu/virtgpu_kumquat.rs
@@ -5,27 +5,22 @@
 use std::cmp::min;
 use std::collections::BTreeMap as Map;
 use std::convert::TryInto;
-use std::fs::File;
-use std::os::fd::AsRawFd;
-use std::os::fd::OwnedFd;
 use std::path::PathBuf;
 use std::slice::from_raw_parts_mut;
 use std::sync::Mutex;
 use std::sync::OnceLock;
 
-use nix::sys::eventfd::EfdFlags;
-use nix::sys::eventfd::EventFd;
-use nix::unistd::read;
 use rutabaga_gfx::kumquat_support::kumquat_gpu_protocol::*;
+use rutabaga_gfx::kumquat_support::RutabagaEvent;
 use rutabaga_gfx::kumquat_support::RutabagaMemoryMapping;
 use rutabaga_gfx::kumquat_support::RutabagaReader;
 use rutabaga_gfx::kumquat_support::RutabagaSharedMemory;
 use rutabaga_gfx::kumquat_support::RutabagaStream;
 use rutabaga_gfx::kumquat_support::RutabagaTube;
+use rutabaga_gfx::kumquat_support::RutabagaTubeType;
 use rutabaga_gfx::kumquat_support::RutabagaWriter;
 use rutabaga_gfx::RutabagaDescriptor;
 use rutabaga_gfx::RutabagaError;
-use rutabaga_gfx::RutabagaFromRawDescriptor;
 use rutabaga_gfx::RutabagaGralloc;
 use rutabaga_gfx::RutabagaGrallocBackendFlags;
 use rutabaga_gfx::RutabagaHandle;
@@ -35,7 +30,6 @@ use rutabaga_gfx::RutabagaMapping;
 use rutabaga_gfx::RutabagaRawDescriptor;
 use rutabaga_gfx::RutabagaResult;
 use rutabaga_gfx::VulkanInfo;
-use rutabaga_gfx::RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD;
 use rutabaga_gfx::RUTABAGA_FLAG_FENCE;
 use rutabaga_gfx::RUTABAGA_FLAG_FENCE_HOST_SHAREABLE;
 use rutabaga_gfx::RUTABAGA_FLAG_INFO_RING_IDX;
@@ -124,7 +118,7 @@ pub struct VirtGpuKumquat {
 impl VirtGpuKumquat {
     pub fn new(gpu_socket: &str) -> RutabagaResult<VirtGpuKumquat> {
         let path = PathBuf::from(gpu_socket);
-        let connection = RutabagaTube::new(path)?;
+        let connection = RutabagaTube::new(path, RutabagaTubeType::Packet)?;
         let mut stream = RutabagaStream::new(connection);
 
         let get_num_capsets = kumquat_gpu_protocol_ctrl_hdr {
@@ -418,17 +412,8 @@ impl VirtGpuKumquat {
             .get_mut(&transfer.bo_handle)
             .ok_or(RutabagaError::InvalidResourceId)?;
 
-        // TODO(b/356504311): We should really move EventFd creation into rutabaga_os..
-        let owned: OwnedFd = EventFd::from_flags(EfdFlags::empty())?.into();
-        let eventfd: File = owned.into();
-
-        // SAFETY: Safe because the eventfd is valid and owned by us.
-        let emulated_fence = RutabagaHandle {
-            os_handle: unsafe {
-                RutabagaDescriptor::from_raw_descriptor(eventfd.into_raw_descriptor())
-            },
-            handle_type: RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD,
-        };
+        let event = RutabagaEvent::new()?;
+        let emulated_fence: RutabagaHandle = event.into();
 
         resource.attached_fences.push(emulated_fence.try_clone()?);
 
@@ -467,17 +452,8 @@ impl VirtGpuKumquat {
             .get_mut(&transfer.bo_handle)
             .ok_or(RutabagaError::InvalidResourceId)?;
 
-        // TODO(b/356504311): We should really move EventFd creation into rutabaga_os..
-        let owned: OwnedFd = EventFd::from_flags(EfdFlags::empty())?.into();
-        let eventfd: File = owned.into();
-
-        // SAFETY: Safe because the eventfd is valid and owned by us.
-        let emulated_fence = RutabagaHandle {
-            os_handle: unsafe {
-                RutabagaDescriptor::from_raw_descriptor(eventfd.into_raw_descriptor())
-            },
-            handle_type: RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD,
-        };
+        let event = RutabagaEvent::new()?;
+        let emulated_fence: RutabagaHandle = event.into();
 
         resource.attached_fences.push(emulated_fence.try_clone()?);
         let transfer_from_host = kumquat_gpu_protocol_transfer_host_3d {
@@ -607,8 +583,8 @@ impl VirtGpuKumquat {
 
         let new_fences: Vec<RutabagaHandle> = std::mem::take(&mut resource.attached_fences);
         for fence in new_fences {
-            let file = unsafe { File::from_raw_descriptor(fence.os_handle.into_raw_descriptor()) };
-            read(file.as_raw_fd(), &mut 1u64.to_ne_bytes())?;
+            let event: RutabagaEvent = fence.try_into()?;
+            event.wait()?;
         }
 
         Ok(())
diff --git a/rutabaga_gfx/kumquat/server/src/kumquat.rs b/rutabaga_gfx/kumquat/server/src/kumquat.rs
index 6cfcc9487..2355440ef 100644
--- a/rutabaga_gfx/kumquat/server/src/kumquat.rs
+++ b/rutabaga_gfx/kumquat/server/src/kumquat.rs
@@ -4,62 +4,68 @@
 
 use std::collections::btree_map::Entry;
 use std::collections::BTreeMap as Map;
-use std::time::Duration;
+use std::path::PathBuf;
 
+use rutabaga_gfx::kumquat_support::RutabagaListener;
 use rutabaga_gfx::kumquat_support::RutabagaWaitContext;
+use rutabaga_gfx::kumquat_support::RutabagaWaitTimeout;
+use rutabaga_gfx::RutabagaAsBorrowedDescriptor as AsBorrowedDescriptor;
 use rutabaga_gfx::RutabagaError;
 use rutabaga_gfx::RutabagaResult;
 
 use crate::kumquat_gpu::KumquatGpu;
 use crate::kumquat_gpu::KumquatGpuConnection;
 
+enum KumquatConnection {
+    GpuListener,
+    GpuConnection(KumquatGpuConnection),
+}
+
 pub struct Kumquat {
-    kumquat_gpu: KumquatGpu,
+    connection_id: u64,
     wait_ctx: RutabagaWaitContext,
-    connections: Map<u64, KumquatGpuConnection>,
+    kumquat_gpu_opt: Option<KumquatGpu>,
+    gpu_listener_opt: Option<RutabagaListener>,
+    connections: Map<u64, KumquatConnection>,
 }
 
 impl Kumquat {
-    pub fn new(capset_names: String, renderer_features: String) -> RutabagaResult<Kumquat> {
-        Ok(Kumquat {
-            kumquat_gpu: KumquatGpu::new(capset_names, renderer_features)?,
-            wait_ctx: RutabagaWaitContext::new()?,
-            connections: Default::default(),
-        })
-    }
-
-    pub fn add_connection(
-        &mut self,
-        connection_id: u64,
-        connection: KumquatGpuConnection,
-    ) -> RutabagaResult<()> {
-        let _ = self.wait_ctx.add(connection_id, &connection);
-        self.connections.insert(connection_id, connection);
-        Ok(())
-    }
-
     pub fn run(&mut self) -> RutabagaResult<()> {
-        if self.connections.is_empty() {
-            return Ok(());
-        }
-
-        // TODO(b/356504311): This is necessary in case client B connects to the socket when the
-        // thread is waiting on a client A command (which never happens without client B). The
-        // correct solution would be to add the listner to the WaitContext in the future.
-        let events = self.wait_ctx.wait(Some(Duration::from_millis(100)))?;
+        let events = self.wait_ctx.wait(RutabagaWaitTimeout::NoTimeout)?;
         for event in events {
             let mut hung_up = false;
             match self.connections.entry(event.connection_id) {
                 Entry::Occupied(mut o) => {
                     let connection = o.get_mut();
-                    if event.readable {
-                        hung_up =
-                            !connection.process_command(&mut self.kumquat_gpu)? && event.hung_up;
-                    }
+                    match connection {
+                        KumquatConnection::GpuListener => {
+                            if let Some(ref listener) = self.gpu_listener_opt {
+                                let stream = listener.accept()?;
+                                self.connection_id += 1;
+                                let new_gpu_conn = KumquatGpuConnection::new(stream);
+                                self.wait_ctx.add(
+                                    self.connection_id,
+                                    new_gpu_conn.as_borrowed_descriptor(),
+                                )?;
+                                self.connections.insert(
+                                    self.connection_id,
+                                    KumquatConnection::GpuConnection(new_gpu_conn),
+                                );
+                            }
+                        }
+                        KumquatConnection::GpuConnection(ref mut gpu_conn) => {
+                            if event.readable {
+                                if let Some(ref mut kumquat_gpu) = self.kumquat_gpu_opt {
+                                    hung_up =
+                                        !gpu_conn.process_command(kumquat_gpu)? && event.hung_up;
+                                }
+                            }
 
-                    if hung_up {
-                        self.wait_ctx.delete(&connection)?;
-                        o.remove_entry();
+                            if hung_up {
+                                self.wait_ctx.delete(gpu_conn.as_borrowed_descriptor())?;
+                                o.remove_entry();
+                            }
+                        }
                     }
                 }
                 Entry::Vacant(_) => {
@@ -71,3 +77,68 @@ impl Kumquat {
         Ok(())
     }
 }
+
+pub struct KumquatBuilder {
+    capset_names_opt: Option<String>,
+    gpu_socket_opt: Option<String>,
+    renderer_features_opt: Option<String>,
+}
+
+impl KumquatBuilder {
+    pub fn new() -> KumquatBuilder {
+        KumquatBuilder {
+            capset_names_opt: None,
+            gpu_socket_opt: None,
+            renderer_features_opt: None,
+        }
+    }
+
+    pub fn set_capset_names(mut self, capset_names: String) -> KumquatBuilder {
+        self.capset_names_opt = Some(capset_names);
+        self
+    }
+
+    pub fn set_gpu_socket(mut self, gpu_socket_opt: Option<String>) -> KumquatBuilder {
+        self.gpu_socket_opt = gpu_socket_opt;
+        self
+    }
+
+    pub fn set_renderer_features(mut self, renderer_features: String) -> KumquatBuilder {
+        self.renderer_features_opt = Some(renderer_features);
+        self
+    }
+
+    pub fn build(self) -> RutabagaResult<Kumquat> {
+        let connection_id: u64 = 0;
+        let mut wait_ctx = RutabagaWaitContext::new()?;
+        let mut kumquat_gpu_opt: Option<KumquatGpu> = None;
+        let mut gpu_listener_opt: Option<RutabagaListener> = None;
+        let mut connections: Map<u64, KumquatConnection> = Default::default();
+
+        if let Some(gpu_socket) = self.gpu_socket_opt {
+            // Remove path if it exists
+            let path = PathBuf::from(&gpu_socket);
+            let _ = std::fs::remove_file(&path);
+
+            // Should not panic, since main.rs always calls set_capset_names and
+            // set_renderer_features, even with the empty string.
+            kumquat_gpu_opt = Some(KumquatGpu::new(
+                self.capset_names_opt.unwrap(),
+                self.renderer_features_opt.unwrap(),
+            )?);
+
+            let gpu_listener = RutabagaListener::bind(path)?;
+            wait_ctx.add(connection_id, gpu_listener.as_borrowed_descriptor())?;
+            connections.insert(connection_id, KumquatConnection::GpuListener);
+            gpu_listener_opt = Some(gpu_listener);
+        }
+
+        Ok(Kumquat {
+            connection_id,
+            wait_ctx,
+            kumquat_gpu_opt,
+            gpu_listener_opt,
+            connections,
+        })
+    }
+}
diff --git a/rutabaga_gfx/kumquat/server/src/kumquat_gpu/mod.rs b/rutabaga_gfx/kumquat/server/src/kumquat_gpu/mod.rs
index 45f379485..ad3967d84 100644
--- a/rutabaga_gfx/kumquat/server/src/kumquat_gpu/mod.rs
+++ b/rutabaga_gfx/kumquat/server/src/kumquat_gpu/mod.rs
@@ -5,21 +5,15 @@
 use std::collections::btree_map::Entry;
 use std::collections::BTreeMap as Map;
 use std::collections::BTreeSet as Set;
-use std::fs::File;
 use std::io::Cursor;
-use std::io::Write;
-use std::os::fd::AsFd;
-use std::os::fd::BorrowedFd;
-use std::os::fd::OwnedFd;
 use std::os::raw::c_void;
 use std::sync::Arc;
 use std::sync::Mutex;
 
 use log::error;
-use nix::sys::eventfd::EfdFlags;
-use nix::sys::eventfd::EventFd;
 use rutabaga_gfx::calculate_capset_mask;
 use rutabaga_gfx::kumquat_support::kumquat_gpu_protocol::*;
+use rutabaga_gfx::kumquat_support::RutabagaEvent;
 use rutabaga_gfx::kumquat_support::RutabagaMemoryMapping;
 use rutabaga_gfx::kumquat_support::RutabagaSharedMemory;
 use rutabaga_gfx::kumquat_support::RutabagaStream;
@@ -27,21 +21,19 @@ use rutabaga_gfx::kumquat_support::RutabagaTube;
 use rutabaga_gfx::ResourceCreate3D;
 use rutabaga_gfx::ResourceCreateBlob;
 use rutabaga_gfx::Rutabaga;
+use rutabaga_gfx::RutabagaAsBorrowedDescriptor as AsBorrowedDescriptor;
 use rutabaga_gfx::RutabagaBuilder;
 use rutabaga_gfx::RutabagaComponentType;
 use rutabaga_gfx::RutabagaDescriptor;
 use rutabaga_gfx::RutabagaError;
 use rutabaga_gfx::RutabagaFence;
 use rutabaga_gfx::RutabagaFenceHandler;
-use rutabaga_gfx::RutabagaFromRawDescriptor;
 use rutabaga_gfx::RutabagaHandle;
-use rutabaga_gfx::RutabagaIntoRawDescriptor;
 use rutabaga_gfx::RutabagaIovec;
 use rutabaga_gfx::RutabagaResult;
 use rutabaga_gfx::RutabagaWsi;
 use rutabaga_gfx::Transfer3D;
 use rutabaga_gfx::VulkanInfo;
-use rutabaga_gfx::RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD;
 use rutabaga_gfx::RUTABAGA_FLAG_FENCE;
 use rutabaga_gfx::RUTABAGA_FLAG_FENCE_HOST_SHAREABLE;
 use rutabaga_gfx::RUTABAGA_MAP_ACCESS_RW;
@@ -60,7 +52,7 @@ pub struct KumquatGpuResource {
 }
 
 pub struct FenceData {
-    pub pending_fences: Map<u64, RutabagaHandle>,
+    pub pending_fences: Map<u64, RutabagaEvent>,
 }
 
 pub type FenceState = Arc<Mutex<FenceData>>;
@@ -70,11 +62,8 @@ pub fn create_fence_handler(fence_state: FenceState) -> RutabagaFenceHandler {
         let mut state = fence_state.lock().unwrap();
         match (*state).pending_fences.entry(completed_fence.fence_id) {
             Entry::Occupied(o) => {
-                let (_, signaled_fence) = o.remove_entry();
-                let mut file = unsafe {
-                    File::from_raw_descriptor(signaled_fence.os_handle.into_raw_descriptor())
-                };
-                file.write(&mut 1u64.to_ne_bytes()).unwrap();
+                let (_, mut event) = o.remove_entry();
+                event.signal().unwrap();
             }
             Entry::Vacant(_) => {
                 // This is fine, since an actual fence doesn't create emulated sync
@@ -317,14 +306,8 @@ impl KumquatGpuConnection {
                         .rutabaga
                         .transfer_write(cmd.ctx_id, resource_id, transfer)?;
 
-                    // SAFETY: Safe because the emulated fence and owned by us.
-                    let mut file = unsafe {
-                        File::from_raw_descriptor(emulated_fence.os_handle.into_raw_descriptor())
-                    };
-
-                    // TODO(b/356504311): An improvement would be `impl From<RutabagaHandle> for
-                    // RutabagaEvent` + `RutabagaEvent::signal`
-                    file.write(&mut 1u64.to_ne_bytes())?;
+                    let mut event: RutabagaEvent = emulated_fence.try_into()?;
+                    event.signal()?;
                 }
                 KumquatGpuProtocol::TransferFromHost3d(cmd, emulated_fence) => {
                     let resource_id = cmd.resource_id;
@@ -346,14 +329,8 @@ impl KumquatGpuConnection {
                         .rutabaga
                         .transfer_read(cmd.ctx_id, resource_id, transfer, None)?;
 
-                    // SAFETY: Safe because the emulated fence and owned by us.
-                    let mut file = unsafe {
-                        File::from_raw_descriptor(emulated_fence.os_handle.into_raw_descriptor())
-                    };
-
-                    // TODO(b/356504311): An improvement would be `impl From<RutabagaHandle> for
-                    // RutabagaEvent` + `RutabagaEvent::signal`
-                    file.write(&mut 1u64.to_ne_bytes())?;
+                    let mut event: RutabagaEvent = emulated_fence.try_into()?;
+                    event.signal()?;
                 }
                 KumquatGpuProtocol::CmdSubmit3d(cmd, mut cmd_buf, fence_ids) => {
                     kumquat_gpu.rutabaga.submit_command(
@@ -374,24 +351,13 @@ impl KumquatGpuConnection {
                         let mut fence_descriptor_opt: Option<RutabagaHandle> = None;
                         let actual_fence = cmd.flags & RUTABAGA_FLAG_FENCE_HOST_SHAREABLE != 0;
                         if !actual_fence {
-                            // This code should really be rutabaga_os.
-                            let owned: OwnedFd = EventFd::from_flags(EfdFlags::empty())?.into();
-                            let eventfd: File = owned.into();
-
-                            let emulated_fence = RutabagaHandle {
-                                os_handle: unsafe {
-                                    RutabagaDescriptor::from_raw_descriptor(
-                                        eventfd.into_raw_descriptor(),
-                                    )
-                                },
-                                handle_type: RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD,
-                            };
-
-                            fence_descriptor_opt = Some(emulated_fence.try_clone()?);
+                            let event: RutabagaEvent = RutabagaEvent::new()?;
+                            let clone = event.try_clone()?;
+                            let emulated_fence: RutabagaHandle = clone.into();
+
+                            fence_descriptor_opt = Some(emulated_fence);
                             let mut fence_state = kumquat_gpu.fence_state.lock().unwrap();
-                            (*fence_state)
-                                .pending_fences
-                                .insert(fence_id, emulated_fence);
+                            (*fence_state).pending_fences.insert(fence_id, event);
                         }
 
                         kumquat_gpu.rutabaga.create_fence(fence)?;
@@ -484,6 +450,7 @@ impl KumquatGpuConnection {
                     self.stream.write(KumquatGpuProtocolWrite::Cmd(resp))?;
                 }
                 KumquatGpuProtocol::SnapshotRestore => {
+                    kumquat_gpu.snapshot_buffer.set_position(0);
                     kumquat_gpu
                         .rutabaga
                         .restore(&mut kumquat_gpu.snapshot_buffer, SNAPSHOT_DIR)?;
@@ -509,8 +476,8 @@ impl KumquatGpuConnection {
     }
 }
 
-impl AsFd for KumquatGpuConnection {
-    fn as_fd(&self) -> BorrowedFd<'_> {
-        self.stream.as_borrowed_file()
+impl AsBorrowedDescriptor for KumquatGpuConnection {
+    fn as_borrowed_descriptor(&self) -> &RutabagaDescriptor {
+        self.stream.as_borrowed_descriptor()
     }
 }
diff --git a/rutabaga_gfx/kumquat/server/src/main.rs b/rutabaga_gfx/kumquat/server/src/main.rs
index e1c285a32..b8e02fc50 100644
--- a/rutabaga_gfx/kumquat/server/src/main.rs
+++ b/rutabaga_gfx/kumquat/server/src/main.rs
@@ -5,19 +5,10 @@
 mod kumquat;
 mod kumquat_gpu;
 
-use std::convert::TryInto;
-use std::fs::File;
-use std::io::Error as IoError;
-use std::io::ErrorKind as IoErrorKind;
-use std::io::Write;
-use std::path::PathBuf;
-
 use clap::Parser;
-use kumquat::Kumquat;
-use kumquat_gpu::KumquatGpuConnection;
-use rutabaga_gfx::kumquat_support::RutabagaListener;
-use rutabaga_gfx::RutabagaError;
-use rutabaga_gfx::RutabagaFromRawDescriptor;
+use kumquat::KumquatBuilder;
+use rutabaga_gfx::kumquat_support::RutabagaWritePipe;
+use rutabaga_gfx::RutabagaIntoRawDescriptor;
 use rutabaga_gfx::RutabagaResult;
 
 #[derive(Parser, Debug)]
@@ -44,35 +35,18 @@ struct Args {
 fn main() -> RutabagaResult<()> {
     let args = Args::parse();
 
-    let mut kumquat = Kumquat::new(args.capset_names, args.renderer_features)?;
-    let mut connection_id: u64 = 0;
-
-    // Remove path if it exists
-    let path = PathBuf::from(&args.gpu_socket_path);
-    let _ = std::fs::remove_file(&path);
-
-    let listener = RutabagaListener::bind(path)?;
+    let mut kumquat = KumquatBuilder::new()
+        .set_capset_names(args.capset_names)
+        .set_gpu_socket((!args.gpu_socket_path.is_empty()).then(|| args.gpu_socket_path))
+        .set_renderer_features(args.renderer_features)
+        .build()?;
 
     if args.pipe_descriptor != 0 {
-        // SAFETY: We trust the user to provide a valid descriptor. The subsequent write call
-        // should fail otherwise.
-        let mut pipe: File = unsafe { File::from_raw_descriptor(args.pipe_descriptor.try_into()?) };
-        pipe.write(&1u64.to_ne_bytes())?;
+        let write_pipe = RutabagaWritePipe::new(args.pipe_descriptor.into_raw_descriptor());
+        write_pipe.write(&1u64.to_ne_bytes())?;
     }
 
     loop {
-        match listener.accept() {
-            Ok(stream) => {
-                connection_id += 1;
-                kumquat.add_connection(connection_id, KumquatGpuConnection::new(stream))?;
-            }
-            Err(RutabagaError::IoError(e)) => match e.kind() {
-                IoErrorKind::WouldBlock => (),
-                kind => return Err(IoError::from(kind).into()),
-            },
-            Err(e) => return Err(e),
-        };
-
         kumquat.run()?;
     }
 }
diff --git a/rutabaga_gfx/patches/Android.bp.patch b/rutabaga_gfx/patches/Android.bp.patch
index aa33a6805..0a37fca48 100644
--- a/rutabaga_gfx/patches/Android.bp.patch
+++ b/rutabaga_gfx/patches/Android.bp.patch
@@ -1,5 +1,5 @@
 diff --git a/rutabaga_gfx/Android.bp b/rutabaga_gfx/Android.bp
-index c69e8a386..4964f3118 100644
+index ab64209dd..1795150d6 100644
 --- a/rutabaga_gfx/Android.bp
 +++ b/rutabaga_gfx/Android.bp
 @@ -23,7 +23,6 @@ rust_library {
@@ -10,7 +10,7 @@ index c69e8a386..4964f3118 100644
          "virgl_renderer",
      ],
      rustlibs: [
-@@ -35,16 +34,78 @@ rust_library {
+@@ -37,16 +36,82 @@ rust_library {
          "libzerocopy",
      ],
      proc_macros: ["libremain"],
@@ -61,6 +61,8 @@ index c69e8a386..4964f3118 100644
 +        "liblibc",
 +        "liblog_rust",
 +        "libnix",
++        "libserde",
++        "libserde_json",
 +        "libthiserror",
 +        "libzerocopy",
 +    ],
@@ -68,6 +70,7 @@ index c69e8a386..4964f3118 100644
 +    target: {
 +        host: {
 +            cfgs: [
++                "fence_passing_option1",
 +                "gfxstream_unstable",
 +            ],
 +            features: [
@@ -84,6 +87,7 @@ index c69e8a386..4964f3118 100644
 +        },
 +        android: {
 +            cfgs: [
++                "fence_passing_option1",
 +                "gfxstream_unstable",
 +            ],
 +        },
@@ -93,7 +97,7 @@ index c69e8a386..4964f3118 100644
  rust_test {
      name: "rutabaga_gfx_test_src_lib",
      defaults: ["crosvm_inner_defaults"],
-@@ -61,7 +122,6 @@ rust_test {
+@@ -63,7 +126,6 @@ rust_test {
      edition: "2021",
      features: [
          "gfxstream",
@@ -101,7 +105,7 @@ index c69e8a386..4964f3118 100644
          "virgl_renderer",
      ],
      rustlibs: [
-@@ -73,12 +133,9 @@ rust_test {
+@@ -77,12 +139,9 @@ rust_test {
          "libzerocopy",
      ],
      proc_macros: ["libremain"],
diff --git a/rutabaga_gfx/src/cross_domain/mod.rs b/rutabaga_gfx/src/cross_domain/mod.rs
index 1e1ade2b8..068e156cc 100644
--- a/rutabaga_gfx/src/cross_domain/mod.rs
+++ b/rutabaga_gfx/src/cross_domain/mod.rs
@@ -9,7 +9,6 @@ use std::cmp::max;
 use std::collections::BTreeMap as Map;
 use std::collections::VecDeque;
 use std::convert::TryInto;
-use std::fs::File;
 use std::mem::size_of;
 use std::sync::Arc;
 use std::sync::Condvar;
@@ -22,21 +21,24 @@ use zerocopy::FromBytes;
 use zerocopy::FromZeroes;
 
 use crate::cross_domain::cross_domain_protocol::*;
-use crate::cross_domain::sys::channel;
-use crate::cross_domain::sys::channel_signal;
-use crate::cross_domain::sys::channel_wait;
-use crate::cross_domain::sys::descriptor_analysis;
-use crate::cross_domain::sys::read_volatile;
-use crate::cross_domain::sys::write_volatile;
-use crate::cross_domain::sys::Receiver;
-use crate::cross_domain::sys::Sender;
 use crate::rutabaga_core::RutabagaComponent;
 use crate::rutabaga_core::RutabagaContext;
 use crate::rutabaga_core::RutabagaResource;
+use crate::rutabaga_os::create_pipe;
+use crate::rutabaga_os::AsBorrowedDescriptor;
+use crate::rutabaga_os::AsRawDescriptor;
+use crate::rutabaga_os::DescriptorType;
+use crate::rutabaga_os::Event;
+use crate::rutabaga_os::IntoRawDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_os::RawDescriptor;
-use crate::rutabaga_os::SafeDescriptor;
+use crate::rutabaga_os::ReadPipe;
 use crate::rutabaga_os::Tube;
+use crate::rutabaga_os::TubeType;
 use crate::rutabaga_os::WaitContext;
+use crate::rutabaga_os::WaitTimeout;
+use crate::rutabaga_os::WritePipe;
+use crate::rutabaga_os::DEFAULT_RAW_DESCRIPTOR;
 use crate::rutabaga_utils::*;
 use crate::DrmFormat;
 use crate::ImageAllocationInfo;
@@ -46,7 +48,6 @@ use crate::RutabagaGrallocBackendFlags;
 use crate::RutabagaGrallocFlags;
 
 mod cross_domain_protocol;
-mod sys;
 
 const CROSS_DOMAIN_CONTEXT_CHANNEL_ID: u64 = 1;
 const CROSS_DOMAIN_RESAMPLE_ID: u64 = 2;
@@ -56,37 +57,34 @@ const CROSS_DOMAIN_DEFAULT_BUFFER_SIZE: usize = 4096;
 const CROSS_DOMAIN_MAX_SEND_RECV_SIZE: usize =
     CROSS_DOMAIN_DEFAULT_BUFFER_SIZE - size_of::<CrossDomainSendReceive>();
 
-pub(crate) enum CrossDomainItem {
+enum CrossDomainItem {
     ImageRequirements(ImageMemoryRequirements),
-    WaylandKeymap(SafeDescriptor),
-    #[allow(dead_code)] // `WaylandReadPipe` is never constructed on Windows.
-    WaylandReadPipe(File),
-    WaylandWritePipe(File),
+    WaylandKeymap(OwnedDescriptor),
+    WaylandReadPipe(ReadPipe),
+    WaylandWritePipe(WritePipe),
 }
 
-pub(crate) enum CrossDomainJob {
+enum CrossDomainJob {
     HandleFence(RutabagaFence),
-    #[allow(dead_code)] // `AddReadPipe` is never constructed on Windows.
     AddReadPipe(u32),
     Finish,
 }
 
 enum RingWrite<'a, T> {
     Write(T, Option<&'a [u8]>),
-    WriteFromFile(CrossDomainReadWrite, &'a mut File, bool),
+    WriteFromPipe(CrossDomainReadWrite, &'a mut ReadPipe, bool),
 }
 
-pub(crate) type CrossDomainResources = Arc<Mutex<Map<u32, CrossDomainResource>>>;
+type CrossDomainResources = Arc<Mutex<Map<u32, CrossDomainResource>>>;
 type CrossDomainJobs = Mutex<Option<VecDeque<CrossDomainJob>>>;
-pub(crate) type CrossDomainItemState = Arc<Mutex<CrossDomainItems>>;
+type CrossDomainItemState = Arc<Mutex<CrossDomainItems>>;
 
-pub(crate) struct CrossDomainResource {
-    #[allow(dead_code)] // `handle` is never used on Windows.
-    pub handle: Option<Arc<RutabagaHandle>>,
-    pub backing_iovecs: Option<Vec<RutabagaIovec>>,
+struct CrossDomainResource {
+    handle: Option<Arc<RutabagaHandle>>,
+    backing_iovecs: Option<Vec<RutabagaIovec>>,
 }
 
-pub(crate) struct CrossDomainItems {
+struct CrossDomainItems {
     descriptor_id: u32,
     requirements_blob_id: u32,
     read_pipe_id: u32,
@@ -105,21 +103,20 @@ struct CrossDomainState {
 struct CrossDomainWorker {
     wait_ctx: WaitContext,
     state: Arc<CrossDomainState>,
-    pub(crate) item_state: CrossDomainItemState,
+    item_state: CrossDomainItemState,
     fence_handler: RutabagaFenceHandler,
 }
 
-pub(crate) struct CrossDomainContext {
-    #[allow(dead_code)] // `channels` is unused on Windows.
-    pub(crate) channels: Option<Vec<RutabagaChannel>>,
+struct CrossDomainContext {
+    channels: Option<Vec<RutabagaChannel>>,
     gralloc: Arc<Mutex<RutabagaGralloc>>,
     state: Option<Arc<CrossDomainState>>,
-    pub(crate) context_resources: CrossDomainResources,
-    pub(crate) item_state: CrossDomainItemState,
+    context_resources: CrossDomainResources,
+    item_state: CrossDomainItemState,
     fence_handler: RutabagaFenceHandler,
     worker_thread: Option<thread::JoinHandle<RutabagaResult<()>>>,
-    pub(crate) resample_evt: Option<Sender>,
-    kill_evt: Option<Sender>,
+    resample_evt: Option<Event>,
+    kill_evt: Option<Event>,
 }
 
 /// The CrossDomain component contains a list of channels that the guest may connect to and the
@@ -131,9 +128,9 @@ pub struct CrossDomain {
 }
 
 // TODO(gurchetansingh): optimize the item tracker.  Each requirements blob is long-lived and can
-// be stored in a Slab or vector.  Descriptors received from the Wayland socket *seem* to come one
-// at a time, and can be stored as options.  Need to confirm.
-pub(crate) fn add_item(item_state: &CrossDomainItemState, item: CrossDomainItem) -> u32 {
+// be stored in a Slab or vector.  OwnedDescriptors received from the Wayland socket *seem* to come
+// one at a time, and can be stored as options.  Need to confirm.
+fn add_item(item_state: &CrossDomainItemState, item: CrossDomainItem) -> u32 {
     let mut items = item_state.lock().unwrap();
 
     let item_id = match item {
@@ -185,7 +182,6 @@ impl CrossDomainState {
         }
     }
 
-    #[allow(dead_code)]
     fn send_msg(&self, opaque_data: &[u8], descriptors: &[RawDescriptor]) -> RutabagaResult<usize> {
         match self.connection {
             Some(ref connection) => connection.send(opaque_data, descriptors),
@@ -193,14 +189,14 @@ impl CrossDomainState {
         }
     }
 
-    pub fn receive_msg(&self, opaque_data: &mut [u8]) -> RutabagaResult<(usize, Vec<File>)> {
+    fn receive_msg(&self, opaque_data: &mut [u8]) -> RutabagaResult<(usize, Vec<OwnedDescriptor>)> {
         match self.connection {
             Some(ref connection) => connection.receive(opaque_data),
             None => Err(RutabagaError::InvalidCrossDomainChannel),
         }
     }
 
-    pub(crate) fn add_job(&self, job: CrossDomainJob) {
+    fn add_job(&self, job: CrossDomainJob) {
         let mut jobs = self.jobs.lock().unwrap();
         if let Some(queue) = jobs.as_mut() {
             queue.push_back(job);
@@ -252,15 +248,16 @@ impl CrossDomainState {
                     opaque_data_slice[..opaque_data.len()].copy_from_slice(opaque_data);
                 }
             }
-            RingWrite::WriteFromFile(mut cmd_read, ref mut file, readable) => {
+            RingWrite::WriteFromPipe(mut cmd_read, ref mut read_pipe, readable) => {
                 if slice.len() < size_of::<CrossDomainReadWrite>() {
                     return Err(RutabagaError::InvalidIovec);
                 }
+
                 let (cmd_slice, opaque_data_slice) =
                     slice.split_at_mut(size_of::<CrossDomainReadWrite>());
 
                 if readable {
-                    bytes_read = read_volatile(file, opaque_data_slice)?;
+                    bytes_read = read_pipe.read(opaque_data_slice)?;
                 }
 
                 if bytes_read == 0 {
@@ -296,10 +293,10 @@ impl CrossDomainWorker {
     fn handle_fence(
         &mut self,
         fence: RutabagaFence,
-        thread_resample_evt: &Receiver,
+        thread_resample_evt: &Event,
         receive_buf: &mut [u8],
     ) -> RutabagaResult<()> {
-        let events = self.wait_ctx.wait(None)?;
+        let events = self.wait_ctx.wait(WaitTimeout::NoTimeout)?;
 
         // The worker thread must:
         //
@@ -319,13 +316,13 @@ impl CrossDomainWorker {
         if let Some(event) = events.first() {
             match event.connection_id {
                 CROSS_DOMAIN_CONTEXT_CHANNEL_ID => {
-                    let (len, files) = self.state.receive_msg(receive_buf)?;
-                    if len != 0 || !files.is_empty() {
+                    let (len, descriptors) = self.state.receive_msg(receive_buf)?;
+                    if len != 0 || !descriptors.is_empty() {
                         let mut cmd_receive: CrossDomainSendReceive = Default::default();
 
-                        let num_files = files.len();
+                        let num_descriptors = descriptors.len();
                         cmd_receive.hdr.cmd = CROSS_DOMAIN_CMD_RECEIVE;
-                        cmd_receive.num_identifiers = files.len().try_into()?;
+                        cmd_receive.num_identifiers = descriptors.len().try_into()?;
                         cmd_receive.opaque_data_size = len.try_into()?;
 
                         let iter = cmd_receive
@@ -333,23 +330,28 @@ impl CrossDomainWorker {
                             .iter_mut()
                             .zip(cmd_receive.identifier_types.iter_mut())
                             .zip(cmd_receive.identifier_sizes.iter_mut())
-                            .zip(files)
-                            .take(num_files);
-
-                        for (((identifier, identifier_type), identifier_size), mut file) in iter {
-                            // Safe since the descriptors from receive_msg(..) are owned by us and
-                            // valid.
-                            descriptor_analysis(&mut file, identifier_type, identifier_size)?;
-
-                            *identifier = match *identifier_type {
-                                CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB => add_item(
-                                    &self.item_state,
-                                    CrossDomainItem::WaylandKeymap(file.into()),
-                                ),
-                                CROSS_DOMAIN_ID_TYPE_WRITE_PIPE => add_item(
-                                    &self.item_state,
-                                    CrossDomainItem::WaylandWritePipe(file),
-                                ),
+                            .zip(descriptors)
+                            .take(num_descriptors);
+
+                        for (((identifier, identifier_type), identifier_size), descriptor) in iter {
+                            *identifier = match descriptor.determine_type() {
+                                Ok(DescriptorType::Memory(size)) => {
+                                    *identifier_type = CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB;
+                                    *identifier_size = size;
+                                    add_item(
+                                        &self.item_state,
+                                        CrossDomainItem::WaylandKeymap(descriptor),
+                                    )
+                                }
+                                Ok(DescriptorType::WritePipe) => {
+                                    *identifier_type = CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB;
+                                    add_item(
+                                        &self.item_state,
+                                        CrossDomainItem::WaylandWritePipe(WritePipe::new(
+                                            descriptor.into_raw_descriptor(),
+                                        )),
+                                    )
+                                }
                                 _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                             };
                         }
@@ -372,7 +374,7 @@ impl CrossDomainWorker {
                     //
                     // Fence handling is tied to some new data transfer across a pollable
                     // descriptor.  When we're adding new descriptors, we stop polling.
-                    channel_wait(thread_resample_evt)?;
+                    thread_resample_evt.wait()?;
                     self.state.add_job(CrossDomainJob::HandleFence(fence));
                 }
                 CROSS_DOMAIN_KILL_ID => {
@@ -393,9 +395,9 @@ impl CrossDomainWorker {
                         .ok_or(RutabagaError::InvalidCrossDomainItemId)?;
 
                     match item {
-                        CrossDomainItem::WaylandReadPipe(ref mut file) => {
+                        CrossDomainItem::WaylandReadPipe(ref mut readpipe) => {
                             let ring_write =
-                                RingWrite::WriteFromFile(cmd_read, file, event.readable);
+                                RingWrite::WriteFromPipe(cmd_read, readpipe, event.readable);
                             bytes_read = self.state.write_to_ring::<CrossDomainReadWrite>(
                                 ring_write,
                                 self.state.channel_ring_id,
@@ -403,7 +405,7 @@ impl CrossDomainWorker {
 
                             // Zero bytes read indicates end-of-file on POSIX.
                             if event.hung_up && bytes_read == 0 {
-                                self.wait_ctx.delete(file)?;
+                                self.wait_ctx.delete(readpipe.as_borrowed_descriptor())?;
                             }
                         }
                         _ => return Err(RutabagaError::InvalidCrossDomainItemType),
@@ -421,14 +423,15 @@ impl CrossDomainWorker {
         Ok(())
     }
 
-    fn run(
-        &mut self,
-        thread_kill_evt: Receiver,
-        thread_resample_evt: Receiver,
-    ) -> RutabagaResult<()> {
-        self.wait_ctx
-            .add(CROSS_DOMAIN_RESAMPLE_ID, &thread_resample_evt)?;
-        self.wait_ctx.add(CROSS_DOMAIN_KILL_ID, &thread_kill_evt)?;
+    fn run(&mut self, thread_kill_evt: Event, thread_resample_evt: Event) -> RutabagaResult<()> {
+        self.wait_ctx.add(
+            CROSS_DOMAIN_RESAMPLE_ID,
+            thread_resample_evt.as_borrowed_descriptor(),
+        )?;
+        self.wait_ctx.add(
+            CROSS_DOMAIN_KILL_ID,
+            thread_kill_evt.as_borrowed_descriptor(),
+        )?;
         let mut receive_buf: Vec<u8> = vec![0; CROSS_DOMAIN_MAX_SEND_RECV_SIZE];
 
         while let Some(job) = self.state.wait_for_job() {
@@ -450,9 +453,9 @@ impl CrossDomainWorker {
                         .ok_or(RutabagaError::InvalidCrossDomainItemId)?;
 
                     match item {
-                        CrossDomainItem::WaylandReadPipe(file) => {
-                            self.wait_ctx.add(read_pipe_id as u64, file)?
-                        }
+                        CrossDomainItem::WaylandReadPipe(read_pipe) => self
+                            .wait_ctx
+                            .add(read_pipe_id as u64, read_pipe.as_borrowed_descriptor())?,
                         _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                     }
                 }
@@ -481,7 +484,7 @@ impl CrossDomain {
 }
 
 impl CrossDomainContext {
-    pub fn get_connection(&mut self, cmd_init: &CrossDomainInit) -> RutabagaResult<Tube> {
+    fn get_connection(&mut self, cmd_init: &CrossDomainInit) -> RutabagaResult<Tube> {
         let channels = self
             .channels
             .take()
@@ -492,7 +495,7 @@ impl CrossDomainContext {
             .ok_or(RutabagaError::InvalidCrossDomainChannel)?
             .base_channel;
 
-        Tube::new(base_channel.clone())
+        Tube::new(base_channel.clone(), TubeType::Stream)
     }
 
     fn initialize(&mut self, cmd_init: &CrossDomainInit) -> RutabagaResult<()> {
@@ -522,11 +525,17 @@ impl CrossDomainContext {
 
             let connection = self.get_connection(cmd_init)?;
 
-            let (kill_evt, thread_kill_evt) = channel()?;
-            let (resample_evt, thread_resample_evt) = channel()?;
+            let kill_evt = Event::new()?;
+            let thread_kill_evt = kill_evt.try_clone()?;
+
+            let resample_evt = Event::new()?;
+            let thread_resample_evt = resample_evt.try_clone()?;
 
             let mut wait_ctx = WaitContext::new()?;
-            wait_ctx.add(CROSS_DOMAIN_CONTEXT_CHANNEL_ID, &connection)?;
+            wait_ctx.add(
+                CROSS_DOMAIN_CONTEXT_CHANNEL_ID,
+                connection.as_borrowed_descriptor(),
+            )?;
 
             let state = Arc::new(CrossDomainState::new(
                 query_ring_id,
@@ -611,6 +620,93 @@ impl CrossDomainContext {
         }
     }
 
+    fn send(
+        &mut self,
+        cmd_send: &CrossDomainSendReceive,
+        opaque_data: &[u8],
+    ) -> RutabagaResult<()> {
+        let mut descriptors: [RawDescriptor; CROSS_DOMAIN_MAX_IDENTIFIERS] =
+            [DEFAULT_RAW_DESCRIPTOR; CROSS_DOMAIN_MAX_IDENTIFIERS];
+
+        let mut write_pipe_opt: Option<WritePipe> = None;
+        let mut read_pipe_id_opt: Option<u32> = None;
+
+        let num_identifiers = cmd_send.num_identifiers.try_into()?;
+
+        if num_identifiers > CROSS_DOMAIN_MAX_IDENTIFIERS {
+            return Err(RutabagaError::SpecViolation(
+                "max cross domain identifiers exceeded",
+            ));
+        }
+
+        let iter = cmd_send
+            .identifiers
+            .iter()
+            .zip(cmd_send.identifier_types.iter())
+            .zip(descriptors.iter_mut())
+            .take(num_identifiers);
+
+        for ((identifier, identifier_type), descriptor) in iter {
+            if *identifier_type == CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB {
+                let context_resources = self.context_resources.lock().unwrap();
+
+                let context_resource = context_resources
+                    .get(identifier)
+                    .ok_or(RutabagaError::InvalidResourceId)?;
+
+                if let Some(ref handle) = context_resource.handle {
+                    *descriptor = handle.os_handle.as_raw_descriptor();
+                } else {
+                    return Err(RutabagaError::InvalidRutabagaHandle);
+                }
+            } else if *identifier_type == CROSS_DOMAIN_ID_TYPE_READ_PIPE {
+                // In practice, just 1 pipe pair per send is observed.  If we encounter
+                // more, this can be changed later.
+                if write_pipe_opt.is_some() {
+                    return Err(RutabagaError::SpecViolation("expected just one pipe pair"));
+                }
+
+                let (read_pipe, write_pipe) = create_pipe()?;
+
+                *descriptor = write_pipe.as_raw_descriptor();
+                let read_pipe_id: u32 = add_item(
+                    &self.item_state,
+                    CrossDomainItem::WaylandReadPipe(read_pipe),
+                );
+
+                // For Wayland read pipes, the guest guesses which identifier the host will use to
+                // avoid waiting for the host to generate one.  Validate guess here.  This works
+                // because of the way Sommelier copy + paste works.  If the Sommelier sequence of
+                // events changes, it's always possible to wait for the host
+                // response.
+                if read_pipe_id != *identifier {
+                    return Err(RutabagaError::InvalidCrossDomainItemId);
+                }
+
+                // The write pipe needs to be dropped after the send_msg(..) call is complete, so
+                // the read pipe can receive subsequent hang-up events.
+                write_pipe_opt = Some(write_pipe);
+                read_pipe_id_opt = Some(read_pipe_id);
+            } else {
+                // Don't know how to handle anything else yet.
+                return Err(RutabagaError::InvalidCrossDomainItemType);
+            }
+        }
+
+        if let (Some(state), Some(ref mut resample_evt)) = (&self.state, &mut self.resample_evt) {
+            state.send_msg(opaque_data, &descriptors[..num_identifiers])?;
+
+            if let Some(read_pipe_id) = read_pipe_id_opt {
+                state.add_job(CrossDomainJob::AddReadPipe(read_pipe_id));
+                resample_evt.signal()?;
+            }
+        } else {
+            return Err(RutabagaError::InvalidCrossDomainState);
+        }
+
+        Ok(())
+    }
+
     fn write(&self, cmd_write: &CrossDomainReadWrite, opaque_data: &[u8]) -> RutabagaResult<()> {
         let mut items = self.item_state.lock().unwrap();
 
@@ -624,15 +720,15 @@ impl CrossDomainContext {
 
         let len: usize = cmd_write.opaque_data_size.try_into()?;
         match item {
-            CrossDomainItem::WaylandWritePipe(file) => {
+            CrossDomainItem::WaylandWritePipe(write_pipe) => {
                 if len != 0 {
-                    write_volatile(&file, opaque_data)?;
+                    write_pipe.write(opaque_data)?;
                 }
 
                 if cmd_write.hang_up == 0 {
                     items.table.insert(
                         cmd_write.identifier,
-                        CrossDomainItem::WaylandWritePipe(file),
+                        CrossDomainItem::WaylandWritePipe(write_pipe),
                     );
                 }
 
@@ -649,9 +745,9 @@ impl Drop for CrossDomainContext {
             state.add_job(CrossDomainJob::Finish);
         }
 
-        if let Some(kill_evt) = self.kill_evt.take() {
+        if let Some(mut kill_evt) = self.kill_evt.take() {
             // Log the error, but still try to join the worker thread
-            match channel_signal(&kill_evt) {
+            match kill_evt.signal() {
                 Ok(_) => (),
                 Err(e) => {
                     error!("failed to write cross domain kill event: {}", e);
diff --git a/rutabaga_gfx/src/cross_domain/sys/linux.rs b/rutabaga_gfx/src/cross_domain/sys/linux.rs
deleted file mode 100644
index 4e706774d..000000000
--- a/rutabaga_gfx/src/cross_domain/sys/linux.rs
+++ /dev/null
@@ -1,177 +0,0 @@
-// Copyright 2021 The ChromiumOS Authors
-// Use of this source code is governed by a BSD-style license that can be
-// found in the LICENSE file.
-
-use std::fs::File;
-use std::io::Seek;
-use std::io::SeekFrom;
-use std::os::fd::AsFd;
-use std::os::unix::io::AsRawFd;
-
-use libc::O_ACCMODE;
-use libc::O_WRONLY;
-use nix::fcntl::fcntl;
-use nix::fcntl::FcntlArg;
-use nix::sys::eventfd::EfdFlags;
-use nix::sys::eventfd::EventFd;
-use nix::unistd::pipe;
-use nix::unistd::read;
-use nix::unistd::write;
-
-use super::super::add_item;
-use super::super::cross_domain_protocol::CrossDomainSendReceive;
-use super::super::cross_domain_protocol::CROSS_DOMAIN_ID_TYPE_READ_PIPE;
-use super::super::cross_domain_protocol::CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB;
-use super::super::cross_domain_protocol::CROSS_DOMAIN_ID_TYPE_WRITE_PIPE;
-use super::super::cross_domain_protocol::CROSS_DOMAIN_MAX_IDENTIFIERS;
-use super::super::CrossDomainContext;
-use super::super::CrossDomainItem;
-use super::super::CrossDomainJob;
-use crate::rutabaga_os::AsRawDescriptor;
-use crate::RutabagaError;
-use crate::RutabagaResult;
-
-// Determine type of OS-specific descriptor.  See `from_file` in wl.rs  for explantation on the
-// current, Linux-based method.
-pub fn descriptor_analysis(
-    descriptor: &mut File,
-    descriptor_type: &mut u32,
-    size: &mut u32,
-) -> RutabagaResult<()> {
-    match descriptor.seek(SeekFrom::End(0)) {
-        Ok(seek_size) => {
-            *descriptor_type = CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB;
-            *size = seek_size.try_into()?;
-            Ok(())
-        }
-        _ => {
-            let flags = fcntl(descriptor.as_raw_descriptor(), FcntlArg::F_GETFL)?;
-            *descriptor_type = match flags & O_ACCMODE {
-                O_WRONLY => CROSS_DOMAIN_ID_TYPE_WRITE_PIPE,
-                _ => return Err(RutabagaError::InvalidCrossDomainItemType),
-            };
-
-            Ok(())
-        }
-    }
-}
-
-impl CrossDomainContext {
-    pub(crate) fn send(
-        &self,
-        cmd_send: &CrossDomainSendReceive,
-        opaque_data: &[u8],
-    ) -> RutabagaResult<()> {
-        let mut descriptors = [0; CROSS_DOMAIN_MAX_IDENTIFIERS];
-
-        let mut write_pipe_opt: Option<File> = None;
-        let mut read_pipe_id_opt: Option<u32> = None;
-
-        let num_identifiers = cmd_send.num_identifiers.try_into()?;
-
-        if num_identifiers > CROSS_DOMAIN_MAX_IDENTIFIERS {
-            return Err(RutabagaError::SpecViolation(
-                "max cross domain identifiers exceeded",
-            ));
-        }
-
-        let iter = cmd_send
-            .identifiers
-            .iter()
-            .zip(cmd_send.identifier_types.iter())
-            .zip(descriptors.iter_mut())
-            .take(num_identifiers);
-
-        for ((identifier, identifier_type), descriptor) in iter {
-            if *identifier_type == CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB {
-                let context_resources = self.context_resources.lock().unwrap();
-
-                let context_resource = context_resources
-                    .get(identifier)
-                    .ok_or(RutabagaError::InvalidResourceId)?;
-
-                if let Some(ref handle) = context_resource.handle {
-                    *descriptor = handle.os_handle.as_raw_descriptor();
-                } else {
-                    return Err(RutabagaError::InvalidRutabagaHandle);
-                }
-            } else if *identifier_type == CROSS_DOMAIN_ID_TYPE_READ_PIPE {
-                // In practice, just 1 pipe pair per send is observed.  If we encounter
-                // more, this can be changed later.
-                if write_pipe_opt.is_some() {
-                    return Err(RutabagaError::SpecViolation("expected just one pipe pair"));
-                }
-
-                let (raw_read_pipe, raw_write_pipe) = pipe()?;
-                let read_pipe = File::from(raw_read_pipe);
-                let write_pipe = File::from(raw_write_pipe);
-
-                *descriptor = write_pipe.as_raw_descriptor();
-                let read_pipe_id: u32 = add_item(
-                    &self.item_state,
-                    CrossDomainItem::WaylandReadPipe(read_pipe),
-                );
-
-                // For Wayland read pipes, the guest guesses which identifier the host will use to
-                // avoid waiting for the host to generate one.  Validate guess here.  This works
-                // because of the way Sommelier copy + paste works.  If the Sommelier sequence of
-                // events changes, it's always possible to wait for the host
-                // response.
-                if read_pipe_id != *identifier {
-                    return Err(RutabagaError::InvalidCrossDomainItemId);
-                }
-
-                // The write pipe needs to be dropped after the send_msg(..) call is complete, so
-                // the read pipe can receive subsequent hang-up events.
-                write_pipe_opt = Some(write_pipe);
-                read_pipe_id_opt = Some(read_pipe_id);
-            } else {
-                // Don't know how to handle anything else yet.
-                return Err(RutabagaError::InvalidCrossDomainItemType);
-            }
-        }
-
-        if let (Some(state), Some(resample_evt)) = (&self.state, &self.resample_evt) {
-            state.send_msg(opaque_data, &descriptors[..num_identifiers])?;
-
-            if let Some(read_pipe_id) = read_pipe_id_opt {
-                state.add_job(CrossDomainJob::AddReadPipe(read_pipe_id));
-                channel_signal(resample_evt)?;
-            }
-        } else {
-            return Err(RutabagaError::InvalidCrossDomainState);
-        }
-
-        Ok(())
-    }
-}
-
-pub type Sender = EventFd;
-// TODO: Receiver should be EventFd as well, but there is no way to clone a nix EventFd.
-pub type Receiver = File;
-
-pub fn channel_signal(sender: &Sender) -> RutabagaResult<()> {
-    sender.write(1)?;
-    Ok(())
-}
-
-pub fn channel_wait(receiver: &Receiver) -> RutabagaResult<()> {
-    read(receiver.as_raw_fd(), &mut 1u64.to_ne_bytes())?;
-    Ok(())
-}
-
-pub fn read_volatile(file: &File, opaque_data: &mut [u8]) -> RutabagaResult<usize> {
-    let bytes_read = read(file.as_raw_fd(), opaque_data)?;
-    Ok(bytes_read)
-}
-
-pub fn write_volatile(file: &File, opaque_data: &[u8]) -> RutabagaResult<()> {
-    write(file.as_fd(), opaque_data)?;
-    Ok(())
-}
-
-pub fn channel() -> RutabagaResult<(Sender, Receiver)> {
-    let sender = EventFd::from_flags(EfdFlags::empty())?;
-    let receiver = sender.as_fd().try_clone_to_owned()?.into();
-    Ok((sender, receiver))
-}
diff --git a/rutabaga_gfx/src/cross_domain/sys/mod.rs b/rutabaga_gfx/src/cross_domain/sys/mod.rs
deleted file mode 100644
index f92c83866..000000000
--- a/rutabaga_gfx/src/cross_domain/sys/mod.rs
+++ /dev/null
@@ -1,25 +0,0 @@
-// Copyright 2022 The ChromiumOS Authors
-// Use of this source code is governed by a BSD-style license that can be
-// found in the LICENSE file.
-
-cfg_if::cfg_if! {
-    if #[cfg(any(target_os = "android", target_os = "linux"))] {
-        pub(crate) mod linux;
-        use linux as platform;
-    } else if #[cfg(any(target_os = "fuchsia",target_os = "windows", target_os = "macos",
-                        target_os = "nto"))] {
-        pub(crate) mod stub;
-        use stub as platform;
-    } else {
-        compile_error!("Unsupported platform");
-    }
-}
-
-pub use platform::channel;
-pub use platform::channel_signal;
-pub use platform::channel_wait;
-pub use platform::descriptor_analysis;
-pub use platform::read_volatile;
-pub use platform::write_volatile;
-pub use platform::Receiver;
-pub use platform::Sender;
diff --git a/rutabaga_gfx/src/cross_domain/sys/stub.rs b/rutabaga_gfx/src/cross_domain/sys/stub.rs
deleted file mode 100644
index 9080292b6..000000000
--- a/rutabaga_gfx/src/cross_domain/sys/stub.rs
+++ /dev/null
@@ -1,61 +0,0 @@
-// Copyright 2021 The ChromiumOS Authors
-// Use of this source code is governed by a BSD-style license that can be
-// found in the LICENSE file.
-
-use std::fs::File;
-
-use super::super::cross_domain_protocol::CrossDomainSendReceive;
-use super::super::CrossDomainContext;
-use crate::rutabaga_os::WaitTrait;
-use crate::rutabaga_utils::RutabagaError;
-use crate::rutabaga_utils::RutabagaResult;
-
-pub struct Stub(());
-
-// Determine type of OS-specific descriptor.
-pub fn descriptor_analysis(
-    _descriptor: &mut File,
-    _descriptor_type: &mut u32,
-    _size: &mut u32,
-) -> RutabagaResult<()> {
-    Err(RutabagaError::Unsupported)
-}
-
-impl CrossDomainContext {
-    pub(crate) fn send(
-        &self,
-        _cmd_send: &CrossDomainSendReceive,
-        _opaque_data: &[u8],
-    ) -> RutabagaResult<()> {
-        Err(RutabagaError::Unsupported)
-    }
-}
-
-pub type Sender = Stub;
-pub type Receiver = Stub;
-
-impl WaitTrait for Stub {}
-impl WaitTrait for &Stub {}
-impl WaitTrait for File {}
-impl WaitTrait for &File {}
-impl WaitTrait for &mut File {}
-
-pub fn channel_signal(_sender: &Sender) -> RutabagaResult<()> {
-    Err(RutabagaError::Unsupported)
-}
-
-pub fn channel_wait(_receiver: &Receiver) -> RutabagaResult<()> {
-    Err(RutabagaError::Unsupported)
-}
-
-pub fn read_volatile(_file: &File, _opaque_data: &mut [u8]) -> RutabagaResult<usize> {
-    Err(RutabagaError::Unsupported)
-}
-
-pub fn write_volatile(_file: &File, _opaque_data: &[u8]) -> RutabagaResult<()> {
-    Err(RutabagaError::Unsupported)
-}
-
-pub fn channel() -> RutabagaResult<(Sender, Receiver)> {
-    Err(RutabagaError::Unsupported)
-}
diff --git a/rutabaga_gfx/src/gfxstream.rs b/rutabaga_gfx/src/gfxstream.rs
index fc044a38d..aba70698e 100644
--- a/rutabaga_gfx/src/gfxstream.rs
+++ b/rutabaga_gfx/src/gfxstream.rs
@@ -31,8 +31,8 @@ use crate::rutabaga_core::RutabagaContext;
 use crate::rutabaga_core::RutabagaResource;
 use crate::rutabaga_os::FromRawDescriptor;
 use crate::rutabaga_os::IntoRawDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_os::RawDescriptor;
-use crate::rutabaga_os::SafeDescriptor;
 use crate::rutabaga_utils::*;
 
 // See `virtgpu-gfxstream-renderer.h` for definitions
@@ -184,11 +184,20 @@ extern "C" {
         context_init: u32,
     ) -> c_int;
 
+    #[cfg(gfxstream_unstable)]
+    fn stream_renderer_suspend() -> c_int;
+
     #[cfg(gfxstream_unstable)]
     fn stream_renderer_snapshot(dir: *const c_char) -> c_int;
 
     #[cfg(gfxstream_unstable)]
     fn stream_renderer_restore(dir: *const c_char) -> c_int;
+
+    #[cfg(gfxstream_unstable)]
+    fn stream_renderer_resume() -> c_int;
+
+    #[cfg(gfxstream_unstable)]
+    fn stream_renderer_wait_sync_resource(res_handle: u32) -> c_int;
 }
 
 /// The virtio-gpu backend state tracker which supports accelerated rendering.
@@ -215,7 +224,7 @@ impl GfxstreamContext {
         // SAFETY:
         // Safe because the handle was just returned by a successful gfxstream call so it must
         // be valid and owned by us.
-        let handle = unsafe { SafeDescriptor::from_raw_descriptor(raw_descriptor) };
+        let handle = unsafe { OwnedDescriptor::from_raw_descriptor(raw_descriptor) };
 
         Ok(RutabagaHandle {
             os_handle: handle,
@@ -446,7 +455,7 @@ impl Gfxstream {
         // SAFETY:
         // Safe because the handle was just returned by a successful gfxstream call so it must be
         // valid and owned by us.
-        let handle = unsafe { SafeDescriptor::from_raw_descriptor(raw_descriptor) };
+        let handle = unsafe { OwnedDescriptor::from_raw_descriptor(raw_descriptor) };
 
         Ok(Arc::new(RutabagaHandle {
             os_handle: handle,
@@ -783,6 +792,15 @@ impl RutabagaComponent for Gfxstream {
         }))
     }
 
+    #[cfg(gfxstream_unstable)]
+    fn suspend(&self) -> RutabagaResult<()> {
+        // SAFETY:
+        // Safe because gfxstream is initialized by now.
+        let ret = unsafe { stream_renderer_suspend() };
+        ret_to_res(ret)?;
+        Ok(())
+    }
+
     #[cfg(gfxstream_unstable)]
     fn snapshot(&self, directory: &str) -> RutabagaResult<()> {
         let cstring = CString::new(directory)?;
@@ -805,4 +823,20 @@ impl RutabagaComponent for Gfxstream {
         ret_to_res(ret)?;
         Ok(())
     }
+
+    #[cfg(gfxstream_unstable)]
+    fn resume(&self) -> RutabagaResult<()> {
+        // SAFETY:
+        // Safe because gfxstream is initialized by now.
+        let ret = unsafe { stream_renderer_resume() };
+        ret_to_res(ret)?;
+        Ok(())
+    }
+
+    #[cfg(gfxstream_unstable)]
+    fn wait_sync(&self, resource: &RutabagaResource) -> RutabagaResult<()> {
+        let ret = unsafe { stream_renderer_wait_sync_resource(resource.resource_id) };
+        ret_to_res(ret)?;
+        Ok(())
+    }
 }
diff --git a/rutabaga_gfx/src/gfxstream_stub.rs b/rutabaga_gfx/src/gfxstream_stub.rs
index 2a7eb47b3..07077f9f9 100644
--- a/rutabaga_gfx/src/gfxstream_stub.rs
+++ b/rutabaga_gfx/src/gfxstream_stub.rs
@@ -180,3 +180,27 @@ extern "C" fn stream_renderer_context_create(
 extern "C" fn stream_renderer_create_fence(_fence: *const stream_renderer_fence) -> c_int {
     unimplemented!();
 }
+
+#[cfg(gfxstream_unstable)]
+#[no_mangle]
+extern "C" fn stream_renderer_suspend() -> c_int {
+    unimplemented!();
+}
+
+#[cfg(gfxstream_unstable)]
+#[no_mangle]
+extern "C" fn stream_renderer_snapshot(dir: *const c_char) -> c_int {
+    unimplemented!();
+}
+
+#[cfg(gfxstream_unstable)]
+#[no_mangle]
+extern "C" fn stream_renderer_restore(dir: *const c_char) -> c_int {
+    unimplemented!();
+}
+
+#[cfg(gfxstream_unstable)]
+#[no_mangle]
+extern "C" fn stream_renderer_resume() -> c_int {
+    unimplemented!();
+}
diff --git a/rutabaga_gfx/src/ipc/rutabaga_stream.rs b/rutabaga_gfx/src/ipc/rutabaga_stream.rs
index 173cc53fc..c99d60586 100644
--- a/rutabaga_gfx/src/ipc/rutabaga_stream.rs
+++ b/rutabaga_gfx/src/ipc/rutabaga_stream.rs
@@ -3,12 +3,7 @@
 // found in the LICENSE file.
 
 use std::collections::VecDeque;
-use std::fs::File;
 use std::mem::size_of;
-#[cfg(any(target_os = "android", target_os = "linux"))]
-use std::os::fd::AsFd;
-#[cfg(any(target_os = "android", target_os = "linux"))]
-use std::os::fd::BorrowedFd;
 
 use zerocopy::AsBytes;
 use zerocopy::FromBytes;
@@ -16,11 +11,10 @@ use zerocopy::FromBytes;
 use crate::bytestream::Reader;
 use crate::bytestream::Writer;
 use crate::ipc::kumquat_gpu_protocol::*;
+use crate::rutabaga_os::AsBorrowedDescriptor;
 use crate::rutabaga_os::AsRawDescriptor;
-use crate::rutabaga_os::FromRawDescriptor;
-use crate::rutabaga_os::IntoRawDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_os::RawDescriptor;
-use crate::rutabaga_os::SafeDescriptor;
 use crate::rutabaga_os::Tube;
 use crate::rutabaga_os::DEFAULT_RAW_DESCRIPTOR;
 use crate::rutabaga_utils::RutabagaError;
@@ -83,8 +77,8 @@ impl RutabagaStream {
 
     pub fn read(&mut self) -> RutabagaResult<Vec<KumquatGpuProtocol>> {
         let mut vec: Vec<KumquatGpuProtocol> = Vec::new();
-        let (bytes_read, files_vec) = self.stream.receive(&mut self.read_buffer)?;
-        let mut files: VecDeque<File> = files_vec.into();
+        let (bytes_read, descriptor_vec) = self.stream.receive(&mut self.read_buffer)?;
+        let mut descriptors: VecDeque<OwnedDescriptor> = descriptor_vec.into();
 
         if bytes_read == 0 {
             vec.push(KumquatGpuProtocol::OkNoData);
@@ -123,14 +117,11 @@ impl RutabagaStream {
                     KumquatGpuProtocol::ResourceCreate3d(reader.read_obj()?)
                 }
                 KUMQUAT_GPU_PROTOCOL_TRANSFER_TO_HOST_3D => {
-                    let file = files.pop_front().ok_or(RutabagaError::InvalidResourceId)?;
+                    let os_handle = descriptors
+                        .pop_front()
+                        .ok_or(RutabagaError::InvalidResourceId)?;
                     let resp: kumquat_gpu_protocol_transfer_host_3d = reader.read_obj()?;
 
-                    // SAFETY: Safe because we know the underlying OS descriptor is valid and
-                    // owned by us.
-                    let os_handle =
-                        unsafe { SafeDescriptor::from_raw_descriptor(file.into_raw_descriptor()) };
-
                     let handle = RutabagaHandle {
                         os_handle,
                         handle_type: RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD,
@@ -139,14 +130,11 @@ impl RutabagaStream {
                     KumquatGpuProtocol::TransferToHost3d(resp, handle)
                 }
                 KUMQUAT_GPU_PROTOCOL_TRANSFER_FROM_HOST_3D => {
-                    let file = files.pop_front().ok_or(RutabagaError::InvalidResourceId)?;
+                    let os_handle = descriptors
+                        .pop_front()
+                        .ok_or(RutabagaError::InvalidResourceId)?;
                     let resp: kumquat_gpu_protocol_transfer_host_3d = reader.read_obj()?;
 
-                    // SAFETY: Safe because we know the underlying OS descriptor is valid and
-                    // owned by us.
-                    let os_handle =
-                        unsafe { SafeDescriptor::from_raw_descriptor(file.into_raw_descriptor()) };
-
                     let handle = RutabagaHandle {
                         os_handle,
                         handle_type: RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD,
@@ -208,14 +196,11 @@ impl RutabagaStream {
                     KumquatGpuProtocol::RespContextCreate(hdr.payload)
                 }
                 KUMQUAT_GPU_PROTOCOL_RESP_RESOURCE_CREATE => {
-                    let file = files.pop_front().ok_or(RutabagaError::InvalidResourceId)?;
+                    let os_handle = descriptors
+                        .pop_front()
+                        .ok_or(RutabagaError::InvalidResourceId)?;
                     let resp: kumquat_gpu_protocol_resp_resource_create = reader.read_obj()?;
 
-                    // SAFETY: Safe because we know the underlying OS descriptor is valid and
-                    // owned by us.
-                    let os_handle =
-                        unsafe { SafeDescriptor::from_raw_descriptor(file.into_raw_descriptor()) };
-
                     let handle = RutabagaHandle {
                         os_handle,
                         handle_type: resp.handle_type,
@@ -224,14 +209,11 @@ impl RutabagaStream {
                     KumquatGpuProtocol::RespResourceCreate(resp, handle)
                 }
                 KUMQUAT_GPU_PROTOCOL_RESP_CMD_SUBMIT_3D => {
-                    let file = files.pop_front().ok_or(RutabagaError::InvalidResourceId)?;
+                    let os_handle = descriptors
+                        .pop_front()
+                        .ok_or(RutabagaError::InvalidResourceId)?;
                     let resp: kumquat_gpu_protocol_resp_cmd_submit_3d = reader.read_obj()?;
 
-                    // SAFETY: Safe because we know the underlying OS descriptor is valid and
-                    // owned by us.
-                    let os_handle =
-                        unsafe { SafeDescriptor::from_raw_descriptor(file.into_raw_descriptor()) };
-
                     let handle = RutabagaHandle {
                         os_handle,
                         handle_type: resp.handle_type,
@@ -254,8 +236,7 @@ impl RutabagaStream {
         Ok(vec)
     }
 
-    #[cfg(any(target_os = "android", target_os = "linux"))]
-    pub fn as_borrowed_file(&self) -> BorrowedFd<'_> {
-        self.stream.as_fd()
+    pub fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        self.stream.as_borrowed_descriptor()
     }
 }
diff --git a/rutabaga_gfx/src/lib.rs b/rutabaga_gfx/src/lib.rs
index 6f721799f..378c1869f 100644
--- a/rutabaga_gfx/src/lib.rs
+++ b/rutabaga_gfx/src/lib.rs
@@ -19,7 +19,6 @@ mod rutabaga_2d;
 mod rutabaga_core;
 mod rutabaga_gralloc;
 mod rutabaga_os;
-mod rutabaga_snapshot;
 mod rutabaga_utils;
 mod virgl_renderer;
 
@@ -33,12 +32,13 @@ pub use crate::rutabaga_gralloc::ImageMemoryRequirements;
 pub use crate::rutabaga_gralloc::RutabagaGralloc;
 pub use crate::rutabaga_gralloc::RutabagaGrallocBackendFlags;
 pub use crate::rutabaga_gralloc::RutabagaGrallocFlags;
+pub use crate::rutabaga_os::AsBorrowedDescriptor as RutabagaAsBorrowedDescriptor;
 pub use crate::rutabaga_os::AsRawDescriptor;
 pub use crate::rutabaga_os::FromRawDescriptor as RutabagaFromRawDescriptor;
 pub use crate::rutabaga_os::IntoRawDescriptor as RutabagaIntoRawDescriptor;
 pub use crate::rutabaga_os::MappedRegion as RutabagaMappedRegion;
+pub use crate::rutabaga_os::OwnedDescriptor as RutabagaDescriptor;
 pub use crate::rutabaga_os::RawDescriptor as RutabagaRawDescriptor;
-pub use crate::rutabaga_os::SafeDescriptor as RutabagaDescriptor;
 pub use crate::rutabaga_utils::*;
 
 pub mod kumquat_support {
@@ -46,9 +46,14 @@ pub mod kumquat_support {
     pub use crate::bytestream::Writer as RutabagaWriter;
     pub use crate::ipc::kumquat_gpu_protocol;
     pub use crate::ipc::RutabagaStream;
+    pub use crate::rutabaga_os::Event as RutabagaEvent;
     pub use crate::rutabaga_os::Listener as RutabagaListener;
     pub use crate::rutabaga_os::MemoryMapping as RutabagaMemoryMapping;
     pub use crate::rutabaga_os::SharedMemory as RutabagaSharedMemory;
     pub use crate::rutabaga_os::Tube as RutabagaTube;
+    pub use crate::rutabaga_os::TubeType as RutabagaTubeType;
     pub use crate::rutabaga_os::WaitContext as RutabagaWaitContext;
+    pub use crate::rutabaga_os::WaitTimeout as RutabagaWaitTimeout;
+    pub use crate::rutabaga_os::WritePipe as RutabagaWritePipe;
+    pub use crate::rutabaga_os::DEFAULT_RAW_DESCRIPTOR as RUTABAGA_DEFAULT_RAW_DESCRIPTOR;
 }
diff --git a/rutabaga_gfx/src/renderer_utils.rs b/rutabaga_gfx/src/renderer_utils.rs
index 8c2395960..7a60db638 100644
--- a/rutabaga_gfx/src/renderer_utils.rs
+++ b/rutabaga_gfx/src/renderer_utils.rs
@@ -4,7 +4,7 @@
 
 //! renderer_utils: Utility functions and structs used by virgl_renderer and gfxstream.
 
-use crate::rutabaga_os::SafeDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_utils::RutabagaDebugHandler;
 use crate::rutabaga_utils::RutabagaError;
 use crate::rutabaga_utils::RutabagaFenceHandler;
@@ -29,7 +29,7 @@ pub fn ret_to_res(ret: i32) -> RutabagaResult<()> {
 }
 
 pub struct RutabagaCookie {
-    pub render_server_fd: Option<SafeDescriptor>,
+    pub render_server_fd: Option<OwnedDescriptor>,
     pub fence_handler: Option<RutabagaFenceHandler>,
     pub debug_handler: Option<RutabagaDebugHandler>,
 }
diff --git a/rutabaga_gfx/src/rutabaga_core.rs b/rutabaga_gfx/src/rutabaga_core.rs
index b0ea5111b..ec27db4ae 100644
--- a/rutabaga_gfx/src/rutabaga_core.rs
+++ b/rutabaga_gfx/src/rutabaga_core.rs
@@ -10,14 +10,15 @@ use std::io::Read;
 use std::io::Write;
 use std::sync::Arc;
 
+use serde::Deserialize;
+use serde::Serialize;
+
 use crate::cross_domain::CrossDomain;
 #[cfg(feature = "gfxstream")]
 use crate::gfxstream::Gfxstream;
 use crate::rutabaga_2d::Rutabaga2D;
 use crate::rutabaga_os::MemoryMapping;
-use crate::rutabaga_os::SafeDescriptor;
-use crate::rutabaga_snapshot::RutabagaResourceSnapshot;
-use crate::rutabaga_snapshot::RutabagaSnapshot;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_utils::*;
 #[cfg(feature = "virgl_renderer")]
 use crate::virgl_renderer::VirglRenderer;
@@ -51,6 +52,64 @@ pub struct RutabagaResource {
     pub mapping: Option<MemoryMapping>,
 }
 
+#[derive(Deserialize, Serialize)]
+pub struct RutabagaResourceSnapshot {
+    pub resource_id: u32,
+    pub width: u32,
+    pub height: u32,
+}
+
+impl TryFrom<&RutabagaResource> for RutabagaResourceSnapshot {
+    type Error = RutabagaError;
+    fn try_from(resource: &RutabagaResource) -> Result<Self, Self::Error> {
+        let info = resource
+            .info_2d
+            .as_ref()
+            .ok_or(RutabagaError::Unsupported)?;
+        assert_eq!(
+            usize::try_from(info.width * info.height * 4).unwrap(),
+            info.host_mem.len()
+        );
+        assert_eq!(usize::try_from(resource.size).unwrap(), info.host_mem.len());
+        Ok(RutabagaResourceSnapshot {
+            resource_id: resource.resource_id,
+            width: info.width,
+            height: info.height,
+        })
+    }
+}
+
+impl TryFrom<RutabagaResourceSnapshot> for RutabagaResource {
+    type Error = RutabagaError;
+    fn try_from(snapshot: RutabagaResourceSnapshot) -> Result<Self, Self::Error> {
+        let size = u64::from(snapshot.width * snapshot.height * 4);
+        Ok(RutabagaResource {
+            resource_id: snapshot.resource_id,
+            handle: None,
+            blob: false,
+            blob_mem: 0,
+            blob_flags: 0,
+            map_info: None,
+            info_2d: Some(Rutabaga2DInfo {
+                width: snapshot.width,
+                height: snapshot.height,
+                host_mem: vec![0; usize::try_from(size).unwrap()],
+            }),
+            info_3d: None,
+            vulkan_info: None,
+            // NOTE: `RutabagaResource::backing_iovecs` isn't snapshotted because the
+            // pointers won't be valid at restore time, see the `Rutabaga::restore` doc.
+            // If the client doesn't attach new iovecs, the restored resource will
+            // behave as if they had been detached (instead of segfaulting on the stale
+            // iovec pointers).
+            backing_iovecs: None,
+            component_mask: 1 << (RutabagaComponentType::Rutabaga2D as u8),
+            size,
+            mapping: None,
+        })
+    }
+}
+
 /// A RutabagaComponent is a building block of the Virtual Graphics Interface (VGI).  Each component
 /// on it's own is sufficient to virtualize graphics on many Google products.  These components wrap
 /// libraries like gfxstream or virglrenderer, and Rutabaga's own 2D and cross-domain prototype
@@ -85,7 +144,7 @@ pub trait RutabagaComponent {
 
     /// Used only by VirglRenderer to return a poll_descriptor that is signaled when a poll() is
     /// necessary.
-    fn poll_descriptor(&self) -> Option<SafeDescriptor> {
+    fn poll_descriptor(&self) -> Option<OwnedDescriptor> {
         None
     }
 
@@ -200,6 +259,11 @@ pub trait RutabagaComponent {
         Err(RutabagaError::Unsupported)
     }
 
+    /// Implementations should stop workers.
+    fn suspend(&self) -> RutabagaResult<()> {
+        Ok(())
+    }
+
     /// Implementations must snapshot to the specified directory
     fn snapshot(&self, _directory: &str) -> RutabagaResult<()> {
         Err(RutabagaError::Unsupported)
@@ -209,6 +273,16 @@ pub trait RutabagaComponent {
     fn restore(&self, _directory: &str) -> RutabagaResult<()> {
         Err(RutabagaError::Unsupported)
     }
+
+    /// Implementations should resume workers.
+    fn resume(&self) -> RutabagaResult<()> {
+        Ok(())
+    }
+
+    /// Implementations must perform a blocking wait-sync on the resource identified by resource_id
+    fn wait_sync(&self, _resource: &RutabagaResource) -> RutabagaResult<()> {
+        Err(RutabagaError::Unsupported)
+    }
 }
 
 pub trait RutabagaContext {
@@ -349,7 +423,7 @@ fn calculate_component(component_mask: u8) -> RutabagaResult<RutabagaComponentTy
 /// thread-safe is more difficult.
 pub struct Rutabaga {
     resources: Map<u32, RutabagaResource>,
-    #[cfg(gfxstream_unstable)]
+    #[cfg(fence_passing_option1)]
     shareable_fences: Map<u64, RutabagaHandle>,
     contexts: Map<u32, Box<dyn RutabagaContext>>,
     // Declare components after resources and contexts such that it is dropped last.
@@ -359,7 +433,23 @@ pub struct Rutabaga {
     fence_handler: RutabagaFenceHandler,
 }
 
+/// The serialized and deserialized parts of `Rutabaga` that are preserved across
+/// snapshot() and restore().
+#[derive(Deserialize, Serialize)]
+pub struct RutabagaSnapshot {
+    pub resources: Map<u32, RutabagaResourceSnapshot>,
+}
+
 impl Rutabaga {
+    pub fn suspend(&self) -> RutabagaResult<()> {
+        let component = self
+            .components
+            .get(&self.default_component)
+            .ok_or(RutabagaError::InvalidComponent)?;
+
+        component.suspend()
+    }
+
     /// Take a snapshot of Rutabaga's current state. The snapshot is serialized into an opaque byte
     /// stream and written to `w`.
     pub fn snapshot(&self, w: &mut impl Write, directory: &str) -> RutabagaResult<()> {
@@ -375,24 +465,11 @@ impl Rutabaga {
                 resources: self
                     .resources
                     .iter()
-                    .map(|(i, r)| {
-                        let info = r.info_2d.as_ref().ok_or(RutabagaError::Unsupported)?;
-                        assert_eq!(
-                            usize::try_from(info.width * info.height * 4).unwrap(),
-                            info.host_mem.len()
-                        );
-                        assert_eq!(usize::try_from(r.size).unwrap(), info.host_mem.len());
-                        let s = RutabagaResourceSnapshot {
-                            resource_id: r.resource_id,
-                            width: info.width,
-                            height: info.height,
-                        };
-                        Ok((*i, s))
-                    })
+                    .map(|(i, r)| Ok((*i, RutabagaResourceSnapshot::try_from(r)?)))
                     .collect::<RutabagaResult<_>>()?,
             };
 
-            return snapshot.serialize_to(w).map_err(RutabagaError::IoError);
+            serde_json::to_writer(w, &snapshot).map_err(|e| RutabagaError::IoError(e.into()))
         } else {
             Err(RutabagaError::Unsupported)
         }
@@ -428,40 +505,14 @@ impl Rutabaga {
 
             component.restore(directory)
         } else if self.default_component == RutabagaComponentType::Rutabaga2D {
-            let snapshot = RutabagaSnapshot::deserialize_from(r).map_err(RutabagaError::IoError)?;
+            let snapshot: RutabagaSnapshot =
+                serde_json::from_reader(r).map_err(|e| RutabagaError::IoError(e.into()))?;
 
             self.resources = snapshot
                 .resources
                 .into_iter()
-                .map(|(i, s)| {
-                    let size = u64::from(s.width * s.height * 4);
-                    let r = RutabagaResource {
-                        resource_id: s.resource_id,
-                        handle: None,
-                        blob: false,
-                        blob_mem: 0,
-                        blob_flags: 0,
-                        map_info: None,
-                        info_2d: Some(Rutabaga2DInfo {
-                            width: s.width,
-                            height: s.height,
-                            host_mem: vec![0; usize::try_from(size).unwrap()],
-                        }),
-                        info_3d: None,
-                        vulkan_info: None,
-                        // NOTE: `RutabagaResource::backing_iovecs` isn't snapshotted because the
-                        // pointers won't be valid at restore time, see the `Rutabaga::restore` doc.
-                        // If the client doesn't attach new iovecs, the restored resource will
-                        // behave as if they had been detached (instead of segfaulting on the stale
-                        // iovec pointers).
-                        backing_iovecs: None,
-                        component_mask: 1 << (RutabagaComponentType::Rutabaga2D as u8),
-                        size,
-                        mapping: None,
-                    };
-                    (i, r)
-                })
-                .collect();
+                .map(|(i, s)| Ok((i, RutabagaResource::try_from(s)?)))
+                .collect::<RutabagaResult<_>>()?;
 
             return Ok(());
         } else {
@@ -469,6 +520,15 @@ impl Rutabaga {
         }
     }
 
+    pub fn resume(&self) -> RutabagaResult<()> {
+        let component = self
+            .components
+            .get(&self.default_component)
+            .ok_or(RutabagaError::InvalidComponent)?;
+
+        component.resume()
+    }
+
     fn capset_id_to_component_type(&self, capset_id: u32) -> RutabagaResult<RutabagaComponentType> {
         let component = self
             .capset_info
@@ -545,7 +605,7 @@ impl Rutabaga {
             #[allow(unused_variables)]
             let handle_opt = ctx.context_create_fence(fence)?;
 
-            #[cfg(gfxstream_unstable)]
+            #[cfg(fence_passing_option1)]
             if fence.flags & RUTABAGA_FLAG_FENCE_HOST_SHAREABLE != 0 {
                 let handle = handle_opt.unwrap();
                 self.shareable_fences.insert(fence.fence_id, handle);
@@ -571,7 +631,7 @@ impl Rutabaga {
 
     /// Returns a pollable descriptor for the default rutabaga component. In practice, it is only
     /// not None if the default component is virglrenderer.
-    pub fn poll_descriptor(&self) -> Option<SafeDescriptor> {
+    pub fn poll_descriptor(&self) -> Option<OwnedDescriptor> {
         let component = self.components.get(&self.default_component).or(None)?;
         component.poll_descriptor()
     }
@@ -890,7 +950,7 @@ impl Rutabaga {
 
     /// Exports the given fence for import into other processes.
     pub fn export_fence(&mut self, fence_id: u64) -> RutabagaResult<RutabagaHandle> {
-        #[cfg(gfxstream_unstable)]
+        #[cfg(fence_passing_option1)]
         if let Some(handle) = self.shareable_fences.get_mut(&fence_id) {
             return handle.try_clone();
         }
@@ -992,11 +1052,11 @@ impl Rutabaga {
         #[allow(unused_mut)]
         let mut shareable_fences: Vec<RutabagaHandle> = Vec::with_capacity(fence_ids.len());
 
-        #[cfg(gfxstream_unstable)]
+        #[cfg(fence_passing_option1)]
         for (i, fence_id) in fence_ids.iter().enumerate() {
             let handle = self
                 .shareable_fences
-                .get_mut(&fence_id)
+                .get_mut(fence_id)
                 .ok_or(RutabagaError::InvalidRutabagaHandle)?;
 
             let clone = handle.try_clone()?;
@@ -1007,16 +1067,33 @@ impl Rutabaga {
     }
 
     /// destroy fences that are still outstanding
-    #[cfg(gfxstream_unstable)]
+    #[cfg(fence_passing_option1)]
     pub fn destroy_fences(&mut self, fence_ids: &[u64]) -> RutabagaResult<()> {
         for fence_id in fence_ids {
             self.shareable_fences
-                .remove(&fence_id)
+                .remove(fence_id)
                 .ok_or(RutabagaError::InvalidRutabagaHandle)?;
         }
 
         Ok(())
     }
+
+    /// Performs a blocking wait-sync for all pending operations on the resource identified by
+    /// resource_id
+    pub fn wait_sync(&mut self, resource_id: u32) -> RutabagaResult<()> {
+        let component = self
+            .components
+            .get_mut(&self.default_component)
+            .ok_or(RutabagaError::InvalidComponent)?;
+
+        let resource = self
+            .resources
+            .get(&resource_id)
+            .ok_or(RutabagaError::InvalidResourceId)?;
+
+        component.wait_sync(resource)?;
+        Ok(())
+    }
 }
 
 /// Rutabaga Builder, following the Rust builder pattern.
@@ -1157,7 +1234,7 @@ impl RutabagaBuilder {
     pub fn build(
         mut self,
         fence_handler: RutabagaFenceHandler,
-        #[allow(unused_variables)] rutabaga_server_descriptor: Option<SafeDescriptor>,
+        #[allow(unused_variables)] rutabaga_server_descriptor: Option<OwnedDescriptor>,
     ) -> RutabagaResult<Rutabaga> {
         let mut rutabaga_components: Map<RutabagaComponentType, Box<dyn RutabagaComponent>> =
             Default::default();
@@ -1228,8 +1305,6 @@ impl RutabagaBuilder {
             ));
         }
 
-        #[allow(unused_mut)]
-        let mut fallback_2d = false;
         if self.default_component != RutabagaComponentType::Rutabaga2D {
             #[cfg(feature = "virgl_renderer")]
             if self.default_component == RutabagaComponentType::VirglRenderer {
@@ -1246,7 +1321,7 @@ impl RutabagaBuilder {
                     push_capset(RUTABAGA_CAPSET_DRM);
                 } else {
                     log::warn!("error initializing gpu backend=virglrenderer, falling back to 2d.");
-                    fallback_2d = true;
+                    self.default_component = RutabagaComponentType::Rutabaga2D;
                 };
             }
 
@@ -1274,14 +1349,14 @@ impl RutabagaBuilder {
             push_capset(RUTABAGA_CAPSET_CROSS_DOMAIN);
         }
 
-        if self.default_component == RutabagaComponentType::Rutabaga2D || fallback_2d {
+        if self.default_component == RutabagaComponentType::Rutabaga2D {
             let rutabaga_2d = Rutabaga2D::init(fence_handler.clone())?;
             rutabaga_components.insert(RutabagaComponentType::Rutabaga2D, rutabaga_2d);
         }
 
         Ok(Rutabaga {
             resources: Default::default(),
-            #[cfg(gfxstream_unstable)]
+            #[cfg(fence_passing_option1)]
             shareable_fences: Default::default(),
             contexts: Default::default(),
             components: rutabaga_components,
diff --git a/rutabaga_gfx/src/rutabaga_os/defines.rs b/rutabaga_gfx/src/rutabaga_os/defines.rs
new file mode 100644
index 000000000..e6a657524
--- /dev/null
+++ b/rutabaga_gfx/src/rutabaga_os/defines.rs
@@ -0,0 +1,48 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+use std::time::Duration;
+
+use crate::rutabaga_utils::RutabagaMapping;
+
+pub enum TubeType {
+    Stream,
+    Packet,
+}
+
+pub enum WaitTimeout {
+    Finite(Duration),
+    NoTimeout,
+}
+
+pub struct WaitEvent {
+    pub connection_id: u64,
+    pub hung_up: bool,
+    pub readable: bool,
+}
+
+#[allow(dead_code)]
+pub const WAIT_CONTEXT_MAX: usize = 16;
+
+pub enum DescriptorType {
+    Unknown,
+    Memory(u32),
+    WritePipe,
+}
+
+/// # Safety
+///
+/// Caller must ensure that MappedRegion's lifetime contains the lifetime of
+/// pointer returned.
+pub unsafe trait MappedRegion: Send + Sync {
+    /// Returns a pointer to the beginning of the memory region. Should only be
+    /// used for passing this region to ioctls for setting guest memory.
+    fn as_ptr(&self) -> *mut u8;
+
+    /// Returns the size of the memory region in bytes.
+    fn size(&self) -> usize;
+
+    /// Returns rutabaga mapping representation of the region
+    fn as_rutabaga_mapping(&self) -> RutabagaMapping;
+}
diff --git a/rutabaga_gfx/src/rutabaga_os/descriptor.rs b/rutabaga_gfx/src/rutabaga_os/descriptor.rs
index 4f362216e..82693ee5d 100644
--- a/rutabaga_gfx/src/rutabaga_os/descriptor.rs
+++ b/rutabaga_gfx/src/rutabaga_os/descriptor.rs
@@ -2,17 +2,9 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-use std::fs::File;
-use std::mem;
-use std::mem::ManuallyDrop;
-
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_os::RawDescriptor;
 
-/// Wraps a RawDescriptor and safely closes it when self falls out of scope.
-pub struct SafeDescriptor {
-    pub(crate) descriptor: RawDescriptor,
-}
-
 /// Trait for forfeiting ownership of the current raw descriptor, and returning the raw descriptor
 pub trait IntoRawDescriptor {
     fn into_raw_descriptor(self) -> RawDescriptor;
@@ -30,7 +22,7 @@ pub trait AsRawDescriptor {
     ///
     /// If you need to use the descriptor for a longer time (and particularly if you cannot reliably
     /// track the lifetime of the providing object), you should probably consider using
-    /// [`SafeDescriptor`] (possibly along with [`trait@IntoRawDescriptor`]) to get full ownership
+    /// `OwnedDescriptor` (possibly along with `IntoRawDescriptor`) to get full ownership
     /// over a descriptor pointing to the same resource.
     fn as_raw_descriptor(&self) -> RawDescriptor;
 }
@@ -42,93 +34,12 @@ pub trait FromRawDescriptor {
     unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self;
 }
 
-impl AsRawDescriptor for SafeDescriptor {
-    fn as_raw_descriptor(&self) -> RawDescriptor {
-        self.descriptor
-    }
-}
-
-impl IntoRawDescriptor for SafeDescriptor {
+impl IntoRawDescriptor for i64 {
     fn into_raw_descriptor(self) -> RawDescriptor {
-        let descriptor = self.descriptor;
-        mem::forget(self);
-        descriptor
-    }
-}
-
-impl FromRawDescriptor for SafeDescriptor {
-    /// # Safety
-    /// Safe only if the caller ensures nothing has access to the descriptor after passing it to
-    /// `from_raw_descriptor`
-    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
-        SafeDescriptor { descriptor }
+        self as RawDescriptor
     }
 }
 
-impl TryFrom<&dyn AsRawDescriptor> for SafeDescriptor {
-    type Error = std::io::Error;
-
-    /// Clones the underlying descriptor (handle), internally creating a new descriptor.
-    ///
-    /// WARNING: Windows does NOT support cloning/duplicating all types of handles. DO NOT use this
-    /// function on IO completion ports, sockets, or pseudo-handles (except those from
-    /// GetCurrentProcess or GetCurrentThread). See
-    /// <https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle>
-    /// for further details.
-    ///
-    /// TODO(b/191800567): this API has sharp edges on Windows. We should evaluate making some
-    /// adjustments to smooth those edges.
-    fn try_from(rd: &dyn AsRawDescriptor) -> std::result::Result<Self, Self::Error> {
-        // SAFETY:
-        // Safe because the underlying raw descriptor is guaranteed valid by rd's existence.
-        //
-        // Note that we are cloning the underlying raw descriptor since we have no guarantee of
-        // its existence after this function returns.
-        let rd_as_safe_desc = ManuallyDrop::new(unsafe {
-            SafeDescriptor::from_raw_descriptor(rd.as_raw_descriptor())
-        });
-
-        // We have to clone rd because we have no guarantee ownership was transferred (rd is
-        // borrowed).
-        rd_as_safe_desc
-            .try_clone()
-            .map_err(|_| Self::Error::last_os_error())
-    }
-}
-
-impl From<File> for SafeDescriptor {
-    fn from(f: File) -> SafeDescriptor {
-        // SAFETY:
-        // Safe because we own the File at this point.
-        unsafe { SafeDescriptor::from_raw_descriptor(f.into_raw_descriptor()) }
-    }
-}
-
-/// For use cases where a simple wrapper around a [`RawDescriptor`] is needed, in order to e.g.
-/// implement [`trait@AsRawDescriptor`].
-///
-/// This is a simply a wrapper and does not manage the lifetime of the descriptor. As such it is the
-/// responsibility of the user to ensure that the wrapped descriptor will not be closed for as long
-/// as the `Descriptor` is alive.
-///
-/// Most use-cases should prefer [`SafeDescriptor`] or implementing and using
-/// [`trait@AsRawDescriptor`] on the type providing the descriptor. Using this wrapper usually means
-/// something can be improved in your code.
-///
-/// Valid uses of this struct include:
-/// * You only have a valid [`RawDescriptor`] and need to pass something that implements
-///   [`trait@AsRawDescriptor`] to a function,
-/// * You need to serialize a [`RawDescriptor`],
-/// * You need [`trait@Send`] or [`trait@Sync`] for your descriptor and properly handle the case
-///   where your descriptor gets closed.
-///
-/// Note that with the exception of the last use-case (which requires proper error checking against
-/// the descriptor being closed), the `Descriptor` instance would be very short-lived.
-#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
-#[repr(transparent)]
-pub struct Descriptor(pub RawDescriptor);
-impl AsRawDescriptor for Descriptor {
-    fn as_raw_descriptor(&self) -> RawDescriptor {
-        self.0
-    }
+pub trait AsBorrowedDescriptor {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor;
 }
diff --git a/rutabaga_gfx/src/rutabaga_os/memory_mapping.rs b/rutabaga_gfx/src/rutabaga_os/memory_mapping.rs
index 6fadec2ad..186d9338a 100644
--- a/rutabaga_gfx/src/rutabaga_os/memory_mapping.rs
+++ b/rutabaga_gfx/src/rutabaga_os/memory_mapping.rs
@@ -3,7 +3,7 @@
 // found in the LICENSE file.
 
 use crate::rutabaga_os::sys::platform::MemoryMapping as PlatformMapping;
-use crate::rutabaga_os::SafeDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_utils::RutabagaMapping;
 use crate::rutabaga_utils::RutabagaResult;
 
@@ -13,7 +13,7 @@ pub struct MemoryMapping {
 
 impl MemoryMapping {
     pub fn from_safe_descriptor(
-        descriptor: SafeDescriptor,
+        descriptor: OwnedDescriptor,
         size: usize,
         map_info: u32,
     ) -> RutabagaResult<MemoryMapping> {
diff --git a/rutabaga_gfx/src/rutabaga_os/mod.rs b/rutabaga_gfx/src/rutabaga_os/mod.rs
index ef38a4c8f..2f135ea3b 100644
--- a/rutabaga_gfx/src/rutabaga_os/mod.rs
+++ b/rutabaga_gfx/src/rutabaga_os/mod.rs
@@ -2,50 +2,27 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
+mod defines;
 mod descriptor;
 mod memory_mapping;
 mod shm;
 pub mod sys;
 
+pub use defines::*;
+pub use descriptor::AsBorrowedDescriptor;
 pub use descriptor::AsRawDescriptor;
 pub use descriptor::FromRawDescriptor;
 pub use descriptor::IntoRawDescriptor;
-pub use descriptor::SafeDescriptor;
 pub use memory_mapping::MemoryMapping;
 pub use shm::SharedMemory;
+pub use sys::platform::descriptor::OwnedDescriptor;
 pub use sys::platform::descriptor::RawDescriptor;
 pub use sys::platform::descriptor::DEFAULT_RAW_DESCRIPTOR;
+pub use sys::platform::event::Event;
+pub use sys::platform::pipe::create_pipe;
+pub use sys::platform::pipe::ReadPipe;
+pub use sys::platform::pipe::WritePipe;
 pub use sys::platform::shm::round_up_to_page_size;
 pub use sys::platform::tube::Listener;
 pub use sys::platform::tube::Tube;
 pub use sys::platform::wait_context::WaitContext;
-
-use crate::rutabaga_utils::RutabagaMapping;
-
-pub struct WaitEvent {
-    pub connection_id: u64,
-    pub hung_up: bool,
-    pub readable: bool,
-}
-
-#[allow(dead_code)]
-const WAIT_CONTEXT_MAX: usize = 16;
-
-#[allow(dead_code)]
-pub trait WaitTrait {}
-
-/// # Safety
-///
-/// Caller must ensure that MappedRegion's lifetime contains the lifetime of
-/// pointer returned.
-pub unsafe trait MappedRegion: Send + Sync {
-    /// Returns a pointer to the beginning of the memory region. Should only be
-    /// used for passing this region to ioctls for setting guest memory.
-    fn as_ptr(&self) -> *mut u8;
-
-    /// Returns the size of the memory region in bytes.
-    fn size(&self) -> usize;
-
-    /// Returns rutabaga mapping representation of the region
-    fn as_rutabaga_mapping(&self) -> RutabagaMapping;
-}
diff --git a/rutabaga_gfx/src/rutabaga_os/shm.rs b/rutabaga_gfx/src/rutabaga_os/shm.rs
index 7aaeeb8b0..e49a949ca 100644
--- a/rutabaga_gfx/src/rutabaga_os/shm.rs
+++ b/rutabaga_gfx/src/rutabaga_os/shm.rs
@@ -8,8 +8,8 @@ use crate::rutabaga_os::sys::platform::SharedMemory as SysUtilSharedMemory;
 use crate::rutabaga_os::AsRawDescriptor;
 use crate::rutabaga_os::FromRawDescriptor;
 use crate::rutabaga_os::IntoRawDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_os::RawDescriptor;
-use crate::rutabaga_os::SafeDescriptor;
 use crate::rutabaga_utils::RutabagaResult;
 
 pub struct SharedMemory(pub(crate) SysUtilSharedMemory);
@@ -40,10 +40,10 @@ impl IntoRawDescriptor for SharedMemory {
     }
 }
 
-impl From<SharedMemory> for SafeDescriptor {
-    fn from(sm: SharedMemory) -> SafeDescriptor {
+impl From<SharedMemory> for OwnedDescriptor {
+    fn from(sm: SharedMemory) -> OwnedDescriptor {
         // SAFETY:
         // Safe because we own the SharedMemory at this point.
-        unsafe { SafeDescriptor::from_raw_descriptor(sm.into_raw_descriptor()) }
+        unsafe { OwnedDescriptor::from_raw_descriptor(sm.into_raw_descriptor()) }
     }
 }
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/linux/descriptor.rs b/rutabaga_gfx/src/rutabaga_os/sys/linux/descriptor.rs
index b23278e12..bab2ee23a 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/linux/descriptor.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/linux/descriptor.rs
@@ -2,145 +2,121 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-use std::convert::TryFrom;
 use std::fs::File;
+use std::io::ErrorKind as IoErrorKind;
 use std::os::fd::AsFd;
 use std::os::fd::BorrowedFd;
+use std::os::fd::OwnedFd;
 use std::os::unix::io::AsRawFd;
 use std::os::unix::io::FromRawFd;
 use std::os::unix::io::IntoRawFd;
-use std::os::unix::io::OwnedFd;
 use std::os::unix::io::RawFd;
 
+use libc::O_ACCMODE;
+use libc::O_WRONLY;
+use nix::fcntl::fcntl;
+use nix::fcntl::FcntlArg;
+use nix::unistd::lseek;
+use nix::unistd::Whence;
+
 use crate::rutabaga_os::descriptor::AsRawDescriptor;
-use crate::rutabaga_os::descriptor::Descriptor;
 use crate::rutabaga_os::descriptor::FromRawDescriptor;
 use crate::rutabaga_os::descriptor::IntoRawDescriptor;
-use crate::rutabaga_os::descriptor::SafeDescriptor;
-
-type Error = std::io::Error;
-type Result<T> = std::result::Result<T, Error>;
+use crate::rutabaga_os::DescriptorType;
 
 pub type RawDescriptor = RawFd;
 pub const DEFAULT_RAW_DESCRIPTOR: RawDescriptor = -1;
 
-/// Clones `fd`, returning a new file descriptor that refers to the same open file description as
-/// `fd`. The cloned fd will have the `FD_CLOEXEC` flag set but will not share any other file
-/// descriptor flags with `fd`.
-fn clone_fd(fd: &dyn AsRawFd) -> Result<RawFd> {
-    // SAFETY:
-    // Safe because this doesn't modify any memory and we check the return value.
-    let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
-    if ret < 0 {
-        Err(Error::last_os_error())
-    } else {
-        Ok(ret)
-    }
+type Error = std::io::Error;
+type Result<T> = std::result::Result<T, Error>;
+
+pub struct OwnedDescriptor {
+    owned: OwnedFd,
 }
 
-impl Drop for SafeDescriptor {
-    fn drop(&mut self) {
-        // SAFETY:
-        // Safe because we own the SafeDescriptor at this point.
-        let _ = unsafe { libc::close(self.descriptor) };
+impl OwnedDescriptor {
+    pub fn try_clone(&self) -> Result<OwnedDescriptor> {
+        let clone = self.owned.try_clone()?;
+        Ok(OwnedDescriptor { owned: clone })
     }
-}
 
-impl AsRawFd for SafeDescriptor {
-    fn as_raw_fd(&self) -> RawFd {
-        self.as_raw_descriptor()
+    pub fn determine_type(&self) -> Result<DescriptorType> {
+        match lseek(self.as_raw_descriptor(), 0, Whence::SeekEnd) {
+            Ok(seek_size) => {
+                let size: u32 = seek_size
+                    .try_into()
+                    .map_err(|_| Error::from(IoErrorKind::Unsupported))?;
+                Ok(DescriptorType::Memory(size))
+            }
+            _ => {
+                let flags = fcntl(self.as_raw_descriptor(), FcntlArg::F_GETFL)?;
+                match flags & O_ACCMODE {
+                    O_WRONLY => Ok(DescriptorType::WritePipe),
+                    _ => Err(Error::from(IoErrorKind::Unsupported)),
+                }
+            }
+        }
     }
 }
 
-impl TryFrom<&dyn AsRawFd> for SafeDescriptor {
-    type Error = std::io::Error;
-
-    fn try_from(fd: &dyn AsRawFd) -> Result<Self> {
-        Ok(SafeDescriptor {
-            descriptor: clone_fd(fd)?,
-        })
+impl AsRawDescriptor for OwnedDescriptor {
+    fn as_raw_descriptor(&self) -> RawDescriptor {
+        self.owned.as_raw_fd()
     }
 }
 
-impl SafeDescriptor {
-    /// Clones this descriptor, internally creating a new descriptor. The new SafeDescriptor will
-    /// share the same underlying count within the kernel.
-    pub fn try_clone(&self) -> Result<SafeDescriptor> {
-        // SAFETY:
-        // Safe because this doesn't modify any memory and we check the return value.
-        let descriptor = unsafe { libc::fcntl(self.descriptor, libc::F_DUPFD_CLOEXEC, 0) };
-        if descriptor < 0 {
-            Err(Error::last_os_error())
-        } else {
-            Ok(SafeDescriptor { descriptor })
+impl FromRawDescriptor for OwnedDescriptor {
+    // SAFETY:
+    // It is caller's responsibility to ensure that the descriptor is valid and
+    // stays valid for the lifetime of Self
+    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
+        OwnedDescriptor {
+            owned: OwnedFd::from_raw_fd(descriptor),
         }
     }
 }
 
-impl From<SafeDescriptor> for File {
-    fn from(s: SafeDescriptor) -> File {
-        // SAFETY:
-        // Safe because we own the SafeDescriptor at this point.
-        unsafe { File::from_raw_fd(s.into_raw_descriptor()) }
+impl IntoRawDescriptor for OwnedDescriptor {
+    fn into_raw_descriptor(self) -> RawDescriptor {
+        self.owned.into_raw_fd()
     }
 }
 
-// AsRawFd for interoperability with interfaces that require it. Within crosvm,
-// always use AsRawDescriptor when possible.
-impl AsRawFd for Descriptor {
-    fn as_raw_fd(&self) -> RawFd {
-        self.0
+impl AsFd for OwnedDescriptor {
+    fn as_fd(&self) -> BorrowedFd<'_> {
+        self.owned.as_fd()
     }
 }
 
-impl AsFd for SafeDescriptor {
-    fn as_fd(&self) -> BorrowedFd {
-        // SAFETY: the `BorrowedFd` we return lives no longer than this `SafeDescriptor`, so the
-        // descriptor will remain open.
-        unsafe { BorrowedFd::borrow_raw(self.descriptor) }
+impl AsRawDescriptor for File {
+    fn as_raw_descriptor(&self) -> RawDescriptor {
+        self.as_raw_fd()
     }
 }
 
-macro_rules! AsRawDescriptor {
-    ($name:ident) => {
-        impl AsRawDescriptor for $name {
-            fn as_raw_descriptor(&self) -> RawDescriptor {
-                self.as_raw_fd()
-            }
-        }
-    };
+impl FromRawDescriptor for File {
+    // SAFETY:
+    // It is caller's responsibility to ensure that the descriptor is valid and
+    // stays valid for the lifetime of Self
+    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
+        File::from_raw_fd(descriptor)
+    }
 }
 
-macro_rules! FromRawDescriptor {
-    ($name:ident) => {
-        impl FromRawDescriptor for $name {
-            // SAFETY:
-            // It is caller's responsibility to ensure that the descriptor is valid and
-            // stays valid for the lifetime of Self
-            unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
-                $name::from_raw_fd(descriptor)
-            }
-        }
-    };
+impl IntoRawDescriptor for File {
+    fn into_raw_descriptor(self) -> RawDescriptor {
+        self.into_raw_fd()
+    }
 }
 
-macro_rules! IntoRawDescriptor {
-    ($name:ident) => {
-        impl IntoRawDescriptor for $name {
-            fn into_raw_descriptor(self) -> RawDescriptor {
-                self.into_raw_fd()
-            }
-        }
-    };
+impl From<File> for OwnedDescriptor {
+    fn from(f: File) -> OwnedDescriptor {
+        OwnedDescriptor { owned: f.into() }
+    }
 }
 
-// Implementations for File. This enables the File-type to use
-// RawDescriptor, but does not mean File should be used as a generic
-// descriptor container. That should go to either SafeDescriptor or another more
-// relevant container type.
-AsRawDescriptor!(File);
-FromRawDescriptor!(File);
-IntoRawDescriptor!(File);
-AsRawDescriptor!(OwnedFd);
-FromRawDescriptor!(OwnedFd);
-IntoRawDescriptor!(OwnedFd);
+impl From<OwnedFd> for OwnedDescriptor {
+    fn from(o: OwnedFd) -> OwnedDescriptor {
+        OwnedDescriptor { owned: o }
+    }
+}
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/linux/event.rs b/rutabaga_gfx/src/rutabaga_os/sys/linux/event.rs
new file mode 100644
index 000000000..bc4e0f387
--- /dev/null
+++ b/rutabaga_gfx/src/rutabaga_os/sys/linux/event.rs
@@ -0,0 +1,76 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+use std::convert::From;
+use std::convert::TryFrom;
+use std::os::fd::OwnedFd;
+
+use nix::sys::eventfd::EfdFlags;
+use nix::sys::eventfd::EventFd;
+use nix::unistd::read;
+use nix::unistd::write;
+
+use crate::rutabaga_os::AsBorrowedDescriptor;
+use crate::rutabaga_os::AsRawDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
+use crate::rutabaga_utils::RutabagaError;
+use crate::rutabaga_utils::RutabagaHandle;
+use crate::rutabaga_utils::RutabagaResult;
+use crate::rutabaga_utils::RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD;
+
+pub struct Event {
+    descriptor: OwnedDescriptor,
+}
+
+impl Event {
+    pub fn new() -> RutabagaResult<Event> {
+        let owned: OwnedFd = EventFd::from_flags(EfdFlags::empty())?.into();
+        Ok(Event {
+            descriptor: owned.into(),
+        })
+    }
+
+    pub fn signal(&mut self) -> RutabagaResult<()> {
+        let _ = write(&self.descriptor, &1u64.to_ne_bytes())?;
+        Ok(())
+    }
+
+    pub fn wait(&self) -> RutabagaResult<()> {
+        read(self.descriptor.as_raw_descriptor(), &mut 1u64.to_ne_bytes())?;
+        Ok(())
+    }
+
+    pub fn try_clone(&self) -> RutabagaResult<Event> {
+        let clone = self.descriptor.try_clone()?;
+        Ok(Event { descriptor: clone })
+    }
+}
+
+impl TryFrom<RutabagaHandle> for Event {
+    type Error = RutabagaError;
+    fn try_from(handle: RutabagaHandle) -> Result<Self, Self::Error> {
+        if handle.handle_type != RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD {
+            return Err(RutabagaError::InvalidRutabagaHandle);
+        }
+
+        Ok(Event {
+            descriptor: handle.os_handle,
+        })
+    }
+}
+
+impl From<Event> for RutabagaHandle {
+    fn from(evt: Event) -> Self {
+        RutabagaHandle {
+            os_handle: evt.descriptor,
+            handle_type: RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD,
+        }
+    }
+}
+
+impl AsBorrowedDescriptor for Event {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        &self.descriptor
+    }
+}
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/linux/memory_mapping.rs b/rutabaga_gfx/src/rutabaga_os/sys/linux/memory_mapping.rs
index 3503b7269..6963f8f37 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/linux/memory_mapping.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/linux/memory_mapping.rs
@@ -12,7 +12,7 @@ use nix::sys::mman::munmap;
 use nix::sys::mman::MapFlags;
 use nix::sys::mman::ProtFlags;
 
-use crate::rutabaga_os::descriptor::SafeDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_utils::RutabagaError;
 use crate::rutabaga_utils::RutabagaResult;
 use crate::rutabaga_utils::RUTABAGA_MAP_ACCESS_MASK;
@@ -41,7 +41,7 @@ impl Drop for MemoryMapping {
 
 impl MemoryMapping {
     pub fn from_safe_descriptor(
-        descriptor: SafeDescriptor,
+        descriptor: OwnedDescriptor,
         size: usize,
         map_info: u32,
     ) -> RutabagaResult<MemoryMapping> {
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/linux/mod.rs b/rutabaga_gfx/src/rutabaga_os/sys/linux/mod.rs
index f617bafad..5bc895be3 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/linux/mod.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/linux/mod.rs
@@ -3,7 +3,9 @@
 // found in the LICENSE file.
 
 pub mod descriptor;
+pub mod event;
 pub mod memory_mapping;
+pub mod pipe;
 pub mod shm;
 pub mod tube;
 pub mod wait_context;
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/linux/pipe.rs b/rutabaga_gfx/src/rutabaga_os/sys/linux/pipe.rs
new file mode 100644
index 000000000..5bc601bd5
--- /dev/null
+++ b/rutabaga_gfx/src/rutabaga_os/sys/linux/pipe.rs
@@ -0,0 +1,75 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+use std::os::fd::AsFd;
+
+use nix::unistd::pipe;
+use nix::unistd::read;
+use nix::unistd::write;
+
+use crate::rutabaga_os::AsBorrowedDescriptor;
+use crate::rutabaga_os::AsRawDescriptor;
+use crate::rutabaga_os::FromRawDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
+use crate::rutabaga_os::RawDescriptor;
+use crate::rutabaga_utils::RutabagaResult;
+
+pub struct ReadPipe {
+    descriptor: OwnedDescriptor,
+}
+
+pub struct WritePipe {
+    descriptor: OwnedDescriptor,
+}
+
+pub fn create_pipe() -> RutabagaResult<(ReadPipe, WritePipe)> {
+    let (read_pipe, write_pipe) = pipe()?;
+    Ok((
+        ReadPipe {
+            descriptor: read_pipe.into(),
+        },
+        WritePipe {
+            descriptor: write_pipe.into(),
+        },
+    ))
+}
+
+impl ReadPipe {
+    pub fn read(&self, data: &mut [u8]) -> RutabagaResult<usize> {
+        let bytes_read = read(self.descriptor.as_raw_descriptor(), data)?;
+        Ok(bytes_read)
+    }
+}
+
+impl AsBorrowedDescriptor for ReadPipe {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        &self.descriptor
+    }
+}
+
+impl WritePipe {
+    pub fn new(descriptor: RawDescriptor) -> WritePipe {
+        // SAFETY: Safe because we know the underlying OS descriptor is valid and
+        // owned by us.
+        let owned = unsafe { OwnedDescriptor::from_raw_descriptor(descriptor) };
+        WritePipe { descriptor: owned }
+    }
+
+    pub fn write(&self, data: &[u8]) -> RutabagaResult<usize> {
+        let bytes_written = write(self.descriptor.as_fd(), data)?;
+        Ok(bytes_written)
+    }
+}
+
+impl AsBorrowedDescriptor for WritePipe {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        &self.descriptor
+    }
+}
+
+impl AsRawDescriptor for WritePipe {
+    fn as_raw_descriptor(&self) -> RawDescriptor {
+        self.descriptor.as_raw_descriptor()
+    }
+}
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/linux/shm.rs b/rutabaga_gfx/src/rutabaga_os/sys/linux/shm.rs
index 68472e5fb..3eda262f4 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/linux/shm.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/linux/shm.rs
@@ -4,6 +4,8 @@
 
 use std::convert::TryInto;
 use std::ffi::CStr;
+use std::os::fd::AsRawFd;
+use std::os::fd::IntoRawFd;
 use std::os::unix::io::OwnedFd;
 
 use libc::off_t;
@@ -54,13 +56,13 @@ impl SharedMemory {
 
 impl AsRawDescriptor for SharedMemory {
     fn as_raw_descriptor(&self) -> RawDescriptor {
-        self.fd.as_raw_descriptor()
+        self.fd.as_raw_fd()
     }
 }
 
 impl IntoRawDescriptor for SharedMemory {
     fn into_raw_descriptor(self) -> RawDescriptor {
-        self.fd.into_raw_descriptor()
+        self.fd.into_raw_fd()
     }
 }
 
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/linux/tube.rs b/rutabaga_gfx/src/rutabaga_os/sys/linux/tube.rs
index 2ac1cb3f3..297454931 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/linux/tube.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/linux/tube.rs
@@ -2,14 +2,10 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-use std::fs::File;
 use std::io::Error as IoError;
 use std::io::IoSlice;
 use std::io::IoSliceMut;
-use std::os::fd::AsFd;
 use std::os::fd::AsRawFd;
-use std::os::fd::BorrowedFd;
-use std::os::fd::OwnedFd;
 use std::path::Path;
 
 use nix::cmsg_space;
@@ -33,32 +29,44 @@ use nix::sys::socket::SockType;
 use nix::sys::socket::UnixAddr;
 use nix::NixPath;
 
+use crate::rutabaga_os::AsBorrowedDescriptor;
 use crate::rutabaga_os::AsRawDescriptor;
 use crate::rutabaga_os::FromRawDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_os::RawDescriptor;
+use crate::rutabaga_os::TubeType;
 use crate::rutabaga_utils::RutabagaError;
 use crate::rutabaga_utils::RutabagaResult;
 
 const MAX_IDENTIFIERS: usize = 28;
 
 pub struct Tube {
-    socket: File,
+    socket: OwnedDescriptor,
 }
 
 impl Tube {
-    pub fn new<P: AsRef<Path> + NixPath>(path: P) -> RutabagaResult<Tube> {
-        let socket_fd = socket(
-            AddressFamily::Unix,
-            SockType::SeqPacket,
-            SockFlag::empty(),
-            None,
-        )?;
+    pub fn new<P: AsRef<Path> + NixPath>(path: P, kind: TubeType) -> RutabagaResult<Tube> {
+        let socket_fd = match kind {
+            TubeType::Packet => socket(
+                AddressFamily::Unix,
+                SockType::SeqPacket,
+                SockFlag::empty(),
+                None,
+            )?,
+            TubeType::Stream => socket(
+                AddressFamily::Unix,
+                SockType::Stream,
+                SockFlag::SOCK_CLOEXEC,
+                None,
+            )?,
+        };
 
         let unix_addr = UnixAddr::new(&path)?;
         connect(socket_fd.as_raw_fd(), &unix_addr)?;
-        let socket: File = socket_fd.into();
 
-        Ok(Tube { socket })
+        Ok(Tube {
+            socket: socket_fd.into(),
+        })
     }
 
     pub fn send(&self, opaque_data: &[u8], descriptors: &[RawDescriptor]) -> RutabagaResult<usize> {
@@ -74,7 +82,7 @@ impl Tube {
         Ok(bytes_sent)
     }
 
-    pub fn receive(&self, opaque_data: &mut [u8]) -> RutabagaResult<(usize, Vec<File>)> {
+    pub fn receive(&self, opaque_data: &mut [u8]) -> RutabagaResult<(usize, Vec<OwnedDescriptor>)> {
         let mut iovecs = [IoSliceMut::new(opaque_data)];
         let mut cmsgspace = cmsg_space!([RawDescriptor; MAX_IDENTIFIERS]);
         let flags = MsgFlags::empty();
@@ -87,14 +95,14 @@ impl Tube {
         )?;
 
         let len = r.bytes;
-        let files = match r.cmsgs().next() {
+        let descriptors = match r.cmsgs().next() {
             Some(ControlMessageOwned::ScmRights(fds)) => {
                 fds.into_iter()
                     .map(|fd| {
                         // SAFETY:
                         // Safe since the descriptors from recvmsg(..) are owned by us and
                         // valid.
-                        unsafe { File::from_raw_descriptor(fd) }
+                        unsafe { OwnedDescriptor::from_raw_descriptor(fd) }
                     })
                     .collect()
             }
@@ -102,24 +110,18 @@ impl Tube {
             None => Vec::new(),
         };
 
-        Ok((len, files))
+        Ok((len, descriptors))
     }
 }
 
-impl AsFd for Tube {
-    fn as_fd(&self) -> BorrowedFd {
-        self.socket.as_fd()
-    }
-}
-
-impl From<File> for Tube {
-    fn from(file: File) -> Tube {
-        Tube { socket: file }
+impl AsBorrowedDescriptor for Tube {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        &self.socket
     }
 }
 
 pub struct Listener {
-    socket: OwnedFd,
+    socket: OwnedDescriptor,
 }
 
 impl Listener {
@@ -138,18 +140,26 @@ impl Listener {
 
         fcntl(socket.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
 
-        Ok(Listener { socket })
+        Ok(Listener {
+            socket: socket.into(),
+        })
     }
 
     pub fn accept(&self) -> RutabagaResult<Tube> {
-        let sock = match accept(self.socket.as_raw_fd()) {
+        let sock = match accept(self.socket.as_raw_descriptor()) {
             Ok(socket) => socket,
             Err(_) => return Err(IoError::last_os_error().into()),
         };
 
         // SAFETY: Safe because we know the underlying OS descriptor is valid and
         // owned by us.
-        let descriptor: File = unsafe { File::from_raw_descriptor(sock) };
-        Ok(descriptor.into())
+        let descriptor: OwnedDescriptor = unsafe { OwnedDescriptor::from_raw_descriptor(sock) };
+        Ok(Tube { socket: descriptor })
+    }
+}
+
+impl AsBorrowedDescriptor for Listener {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        &self.socket
     }
 }
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/linux/wait_context.rs b/rutabaga_gfx/src/rutabaga_os/sys/linux/wait_context.rs
index f145a6531..0a497dba5 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/linux/wait_context.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/linux/wait_context.rs
@@ -2,16 +2,15 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-use std::os::fd::AsFd;
-use std::time::Duration;
-
 use nix::sys::epoll::Epoll;
 use nix::sys::epoll::EpollCreateFlags;
 use nix::sys::epoll::EpollEvent;
 use nix::sys::epoll::EpollFlags;
 use nix::sys::epoll::EpollTimeout;
 
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_os::WaitEvent;
+use crate::rutabaga_os::WaitTimeout;
 use crate::rutabaga_os::WAIT_CONTEXT_MAX;
 use crate::rutabaga_utils::RutabagaResult;
 
@@ -25,32 +24,25 @@ impl WaitContext {
         Ok(WaitContext { epoll_ctx: epoll })
     }
 
-    pub fn add<Waitable: AsFd>(
-        &mut self,
-        connection_id: u64,
-        waitable: Waitable,
-    ) -> RutabagaResult<()> {
+    pub fn add(&mut self, connection_id: u64, descriptor: &OwnedDescriptor) -> RutabagaResult<()> {
         self.epoll_ctx.add(
-            waitable,
+            descriptor,
             EpollEvent::new(EpollFlags::EPOLLIN, connection_id),
         )?;
         Ok(())
     }
 
-    pub fn wait(&mut self, duration_opt: Option<Duration>) -> RutabagaResult<Vec<WaitEvent>> {
+    pub fn wait(&mut self, timeout: WaitTimeout) -> RutabagaResult<Vec<WaitEvent>> {
         let mut events = [EpollEvent::empty(); WAIT_CONTEXT_MAX];
 
-        let epoll_timeout = duration_opt
-            .map(|duration| {
-                if duration.is_zero() {
-                    EpollTimeout::ZERO
-                } else {
-                    // We shouldn't need timeouts greater than 60s.
-                    let timeout: u16 = duration.as_millis().try_into().unwrap_or(u16::MAX);
-                    EpollTimeout::from(timeout)
-                }
-            })
-            .unwrap_or(EpollTimeout::NONE);
+        let epoll_timeout = match timeout {
+            WaitTimeout::Finite(duration) => {
+                // We shouldn't need timeouts greater than 60s.
+                let timeout: u16 = duration.as_millis().try_into().unwrap_or(u16::MAX);
+                EpollTimeout::from(timeout)
+            }
+            WaitTimeout::NoTimeout => EpollTimeout::NONE,
+        };
 
         let count = loop {
             match self.epoll_ctx.wait(&mut events, epoll_timeout) {
@@ -71,8 +63,8 @@ impl WaitContext {
         Ok(events)
     }
 
-    pub fn delete<Waitable: AsFd>(&mut self, waitable: Waitable) -> RutabagaResult<()> {
-        self.epoll_ctx.delete(waitable)?;
+    pub fn delete(&mut self, descriptor: &OwnedDescriptor) -> RutabagaResult<()> {
+        self.epoll_ctx.delete(descriptor)?;
         Ok(())
     }
 }
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/stub/descriptor.rs b/rutabaga_gfx/src/rutabaga_os/sys/stub/descriptor.rs
index 8d501fe0c..e00a07cab 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/stub/descriptor.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/stub/descriptor.rs
@@ -3,73 +3,93 @@
 // found in the LICENSE file.
 
 use std::fs::File;
+use std::io::ErrorKind as IoErrorKind;
+use std::os::fd::AsFd;
+use std::os::fd::BorrowedFd;
+use std::os::fd::OwnedFd;
+use std::os::unix::io::AsRawFd;
+use std::os::unix::io::FromRawFd;
+use std::os::unix::io::IntoRawFd;
+use std::os::unix::io::RawFd;
 
 use crate::rutabaga_os::descriptor::AsRawDescriptor;
 use crate::rutabaga_os::descriptor::FromRawDescriptor;
 use crate::rutabaga_os::descriptor::IntoRawDescriptor;
-use crate::rutabaga_os::descriptor::SafeDescriptor;
+use crate::rutabaga_os::DescriptorType;
+
+pub type RawDescriptor = RawFd;
+pub const DEFAULT_RAW_DESCRIPTOR: RawDescriptor = -1;
 
 type Error = std::io::Error;
 type Result<T> = std::result::Result<T, Error>;
 
-pub type RawDescriptor = i64;
-pub const DEFAULT_RAW_DESCRIPTOR: RawDescriptor = -1;
+pub struct OwnedDescriptor {
+    owned: OwnedFd,
+}
 
-impl Drop for SafeDescriptor {
-    fn drop(&mut self) {
-        unimplemented!()
+impl OwnedDescriptor {
+    pub fn try_clone(&self) -> Result<OwnedDescriptor> {
+        let clone = self.owned.try_clone()?;
+        Ok(OwnedDescriptor { owned: clone })
     }
-}
 
-impl SafeDescriptor {
-    /// Clones this descriptor, internally creating a new descriptor. The new SafeDescriptor will
-    /// share the same underlying count within the kernel.
-    pub fn try_clone(&self) -> Result<SafeDescriptor> {
-        Err(Error::last_os_error())
+    pub fn determine_type(&self) -> Result<DescriptorType> {
+        Err(Error::from(IoErrorKind::Unsupported))
     }
 }
 
-impl From<SafeDescriptor> for File {
-    fn from(_s: SafeDescriptor) -> File {
-        // Safe because we own the SafeDescriptor at this point.
-        unimplemented!()
+impl AsRawDescriptor for OwnedDescriptor {
+    fn as_raw_descriptor(&self) -> RawDescriptor {
+        self.owned.as_raw_fd()
     }
 }
 
-macro_rules! AsRawDescriptor {
-    ($name:ident) => {
-        impl AsRawDescriptor for $name {
-            fn as_raw_descriptor(&self) -> RawDescriptor {
-                unimplemented!()
-            }
+impl FromRawDescriptor for OwnedDescriptor {
+    // SAFETY:
+    // It is caller's responsibility to ensure that the descriptor is valid and
+    // stays valid for the lifetime of Self
+    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
+        OwnedDescriptor {
+            owned: OwnedFd::from_raw_fd(descriptor),
         }
-    };
+    }
 }
 
-macro_rules! FromRawDescriptor {
-    ($name:ident) => {
-        impl FromRawDescriptor for $name {
-            unsafe fn from_raw_descriptor(_descriptor: RawDescriptor) -> Self {
-                unimplemented!()
-            }
-        }
-    };
+impl IntoRawDescriptor for OwnedDescriptor {
+    fn into_raw_descriptor(self) -> RawDescriptor {
+        self.owned.into_raw_fd()
+    }
 }
 
-macro_rules! IntoRawDescriptor {
-    ($name:ident) => {
-        impl IntoRawDescriptor for $name {
-            fn into_raw_descriptor(self) -> RawDescriptor {
-                unimplemented!()
-            }
-        }
-    };
+impl AsFd for OwnedDescriptor {
+    fn as_fd(&self) -> BorrowedFd<'_> {
+        self.owned.as_fd()
+    }
 }
 
-// Implementations for File. This enables the File-type to use
-// RawDescriptor, but does not mean File should be used as a generic
-// descriptor container. That should go to either SafeDescriptor or another more
-// relevant container type.
-AsRawDescriptor!(File);
-FromRawDescriptor!(File);
-IntoRawDescriptor!(File);
+impl AsRawDescriptor for File {
+    fn as_raw_descriptor(&self) -> RawDescriptor {
+        self.as_raw_fd()
+    }
+}
+
+impl FromRawDescriptor for File {
+    // SAFETY:
+    // It is caller's responsibility to ensure that the descriptor is valid and
+    // stays valid for the lifetime of Self
+    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
+        File::from_raw_fd(descriptor)
+    }
+}
+
+impl IntoRawDescriptor for File {
+    fn into_raw_descriptor(self) -> RawDescriptor {
+        self.into_raw_fd()
+    }
+}
+
+impl From<File> for OwnedDescriptor {
+    fn from(f: File) -> OwnedDescriptor {
+        OwnedDescriptor { owned: f.into() }
+    }
+}
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/stub/event.rs b/rutabaga_gfx/src/rutabaga_os/sys/stub/event.rs
new file mode 100644
index 000000000..8c9b5d423
--- /dev/null
+++ b/rutabaga_gfx/src/rutabaga_os/sys/stub/event.rs
@@ -0,0 +1,51 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+use std::convert::From;
+use std::convert::TryFrom;
+
+use crate::rutabaga_os::AsBorrowedDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
+use crate::rutabaga_utils::RutabagaError;
+use crate::rutabaga_utils::RutabagaHandle;
+use crate::rutabaga_utils::RutabagaResult;
+
+pub struct Event(());
+
+impl Event {
+    pub fn new() -> RutabagaResult<Event> {
+        Err(RutabagaError::Unsupported)
+    }
+
+    pub fn signal(&mut self) -> RutabagaResult<()> {
+        Err(RutabagaError::Unsupported)
+    }
+
+    pub fn wait(&self) -> RutabagaResult<()> {
+        Err(RutabagaError::Unsupported)
+    }
+
+    pub fn try_clone(&self) -> RutabagaResult<Event> {
+        Err(RutabagaError::Unsupported)
+    }
+}
+
+impl TryFrom<RutabagaHandle> for Event {
+    type Error = RutabagaError;
+    fn try_from(_handle: RutabagaHandle) -> Result<Self, Self::Error> {
+        Err(RutabagaError::Unsupported)
+    }
+}
+
+impl From<Event> for RutabagaHandle {
+    fn from(_evt: Event) -> Self {
+        unimplemented!()
+    }
+}
+
+impl AsBorrowedDescriptor for Event {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        unimplemented!()
+    }
+}
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/stub/memory_mapping.rs b/rutabaga_gfx/src/rutabaga_os/sys/stub/memory_mapping.rs
index 6f7cc281c..618e832a2 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/stub/memory_mapping.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/stub/memory_mapping.rs
@@ -6,7 +6,7 @@ use std::ptr::NonNull;
 
 use libc::c_void;
 
-use crate::rutabaga_os::SafeDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_utils::RutabagaError;
 use crate::rutabaga_utils::RutabagaResult;
 
@@ -20,7 +20,7 @@ pub struct MemoryMapping {
 
 impl MemoryMapping {
     pub fn from_safe_descriptor(
-        _descriptor: SafeDescriptor,
+        _descriptor: OwnedDescriptor,
         _size: usize,
         _map_info: u32,
     ) -> RutabagaResult<MemoryMapping> {
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/stub/mod.rs b/rutabaga_gfx/src/rutabaga_os/sys/stub/mod.rs
index f617bafad..5bc895be3 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/stub/mod.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/stub/mod.rs
@@ -3,7 +3,9 @@
 // found in the LICENSE file.
 
 pub mod descriptor;
+pub mod event;
 pub mod memory_mapping;
+pub mod pipe;
 pub mod shm;
 pub mod tube;
 pub mod wait_context;
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/stub/pipe.rs b/rutabaga_gfx/src/rutabaga_os/sys/stub/pipe.rs
new file mode 100644
index 000000000..5398fd056
--- /dev/null
+++ b/rutabaga_gfx/src/rutabaga_os/sys/stub/pipe.rs
@@ -0,0 +1,54 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+use crate::rutabaga_os::AsBorrowedDescriptor;
+use crate::rutabaga_os::AsRawDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
+use crate::rutabaga_os::RawDescriptor;
+use crate::rutabaga_utils::RutabagaError;
+use crate::rutabaga_utils::RutabagaResult;
+
+pub struct ReadPipeStub(());
+pub struct WritePipeStub(());
+
+pub type ReadPipe = ReadPipeStub;
+pub type WritePipe = WritePipeStub;
+
+pub fn create_pipe() -> RutabagaResult<(ReadPipe, WritePipe)> {
+    Err(RutabagaError::Unsupported)
+}
+
+impl ReadPipe {
+    pub fn read(&self, _data: &mut [u8]) -> RutabagaResult<usize> {
+        Err(RutabagaError::Unsupported)
+    }
+}
+
+impl AsBorrowedDescriptor for ReadPipe {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        unimplemented!()
+    }
+}
+
+impl WritePipe {
+    pub fn new(_descriptor: RawDescriptor) -> WritePipe {
+        unimplemented!()
+    }
+
+    pub fn write(&self, _data: &[u8]) -> RutabagaResult<usize> {
+        Err(RutabagaError::Unsupported)
+    }
+}
+
+impl AsBorrowedDescriptor for WritePipe {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        unimplemented!()
+    }
+}
+
+impl AsRawDescriptor for WritePipe {
+    fn as_raw_descriptor(&self) -> RawDescriptor {
+        unimplemented!()
+    }
+}
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/stub/tube.rs b/rutabaga_gfx/src/rutabaga_os/sys/stub/tube.rs
index 57b8d60ca..fb1bc2f61 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/stub/tube.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/stub/tube.rs
@@ -2,11 +2,12 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-use std::fs::File;
 use std::path::Path;
 
+use crate::rutabaga_os::AsBorrowedDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_os::RawDescriptor;
-use crate::rutabaga_os::WaitTrait;
+use crate::rutabaga_os::TubeType;
 use crate::rutabaga_utils::RutabagaError;
 use crate::rutabaga_utils::RutabagaResult;
 
@@ -15,7 +16,7 @@ pub type Tube = Stub;
 pub type Listener = Stub;
 
 impl Tube {
-    pub fn new<P: AsRef<Path>>(_path: P) -> RutabagaResult<Tube> {
+    pub fn new<P: AsRef<Path>>(_path: P, _kind: TubeType) -> RutabagaResult<Tube> {
         Err(RutabagaError::Unsupported)
     }
 
@@ -27,13 +28,19 @@ impl Tube {
         Err(RutabagaError::Unsupported)
     }
 
-    pub fn receive(&self, _opaque_data: &mut [u8]) -> RutabagaResult<(usize, Vec<File>)> {
+    pub fn receive(
+        &self,
+        _opaque_data: &mut [u8],
+    ) -> RutabagaResult<(usize, Vec<OwnedDescriptor>)> {
         Err(RutabagaError::Unsupported)
     }
 }
 
-impl WaitTrait for Tube {}
-impl WaitTrait for &Tube {}
+impl AsBorrowedDescriptor for Tube {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        unimplemented!()
+    }
+}
 
 impl Listener {
     /// Creates a new `Listener` bound to the given path.
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/stub/wait_context.rs b/rutabaga_gfx/src/rutabaga_os/sys/stub/wait_context.rs
index 1c2303bd9..41f8c846e 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/stub/wait_context.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/stub/wait_context.rs
@@ -2,10 +2,9 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-use std::time::Duration;
-
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_os::WaitEvent;
-use crate::rutabaga_os::WaitTrait;
+use crate::rutabaga_os::WaitTimeout;
 use crate::rutabaga_utils::RutabagaError;
 use crate::rutabaga_utils::RutabagaResult;
 
@@ -17,19 +16,19 @@ impl WaitContext {
         Err(RutabagaError::Unsupported)
     }
 
-    pub fn add<Waitable: WaitTrait>(
+    pub fn add(
         &mut self,
         _connection_id: u64,
-        _waitable: Waitable,
+        _descriptor: &OwnedDescriptor,
     ) -> RutabagaResult<()> {
         Err(RutabagaError::Unsupported)
     }
 
-    pub fn wait(&mut self, _duration_opt: Option<Duration>) -> RutabagaResult<Vec<WaitEvent>> {
+    pub fn wait(&mut self, _timeout: WaitTimeout) -> RutabagaResult<Vec<WaitEvent>> {
         Err(RutabagaError::Unsupported)
     }
 
-    pub fn delete<Waitable: WaitTrait>(&mut self, _waitable: Waitable) -> RutabagaResult<()> {
+    pub fn delete(&mut self, _descriptor: &OwnedDescriptor) -> RutabagaResult<()> {
         Err(RutabagaError::Unsupported)
     }
 }
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/windows/descriptor.rs b/rutabaga_gfx/src/rutabaga_os/sys/windows/descriptor.rs
index 1d1aaba11..b4735841c 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/windows/descriptor.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/windows/descriptor.rs
@@ -2,171 +2,71 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-use std::convert::TryFrom;
 use std::fs::File;
-use std::io;
-use std::marker::Send;
-use std::marker::Sync;
-use std::ops::Drop;
+use std::io::ErrorKind as IoErrorKind;
 use std::os::windows::io::AsRawHandle;
 use std::os::windows::io::FromRawHandle;
 use std::os::windows::io::IntoRawHandle;
+use std::os::windows::io::OwnedHandle;
 use std::os::windows::io::RawHandle;
 use std::os::windows::raw::HANDLE;
 
-use winapi::shared::minwindef::FALSE;
-use winapi::shared::minwindef::TRUE;
-use winapi::um::handleapi::CloseHandle;
-use winapi::um::handleapi::DuplicateHandle;
-use winapi::um::processthreadsapi::GetCurrentProcess;
-use winapi::um::winnt::DUPLICATE_SAME_ACCESS;
-
 use crate::rutabaga_os::descriptor::AsRawDescriptor;
-use crate::rutabaga_os::descriptor::Descriptor;
 use crate::rutabaga_os::descriptor::FromRawDescriptor;
 use crate::rutabaga_os::descriptor::IntoRawDescriptor;
-use crate::rutabaga_os::descriptor::SafeDescriptor;
-
-type Error = std::io::Error;
-type Result<T> = std::result::Result<T, Error>;
+use crate::rutabaga_os::DescriptorType;
 
 pub type RawDescriptor = RawHandle;
 // Same as winapi::um::handleapi::INVALID_HANDLE_VALUE, but avoids compile issues.
 pub const DEFAULT_RAW_DESCRIPTOR: RawDescriptor = -1isize as HANDLE;
 
-impl Drop for SafeDescriptor {
-    fn drop(&mut self) {
-        // SAFETY: Safe because we own the descriptor.
-        unsafe { CloseHandle(self.descriptor as _) };
-    }
-}
+type Error = std::io::Error;
+type Result<T> = std::result::Result<T, Error>;
 
-impl AsRawHandle for SafeDescriptor {
-    fn as_raw_handle(&self) -> RawHandle {
-        self.as_raw_descriptor()
-    }
+pub struct OwnedDescriptor {
+    owned: OwnedHandle,
 }
 
-pub fn duplicate_handle_from_source_process(
-    source_process_handle: RawHandle,
-    hndl: RawHandle,
-    target_process_handle: RawHandle,
-) -> io::Result<RawHandle> {
-    // SAFETY: Safe because:
-    // 1. We are checking the return code
-    // 2. new_handle_ptr points to a valid location on the stack
-    // 3. Caller guarantees hndl is a real valid handle.
-    unsafe {
-        let new_handle: RawHandle = std::ptr::null_mut();
-        let success_flag = DuplicateHandle(
-            /* hSourceProcessHandle= */ source_process_handle as _,
-            /* hSourceHandle= */ hndl as _,
-            /* hTargetProcessHandle= */ target_process_handle as _,
-            /* lpTargetHandle= */ new_handle as _,
-            /* dwDesiredAccess= */ 0,
-            /* bInheritHandle= */ TRUE,
-            /* dwOptions= */ DUPLICATE_SAME_ACCESS,
-        );
-
-        if success_flag == FALSE {
-            Err(io::Error::last_os_error())
-        } else {
-            Ok(new_handle)
-        }
+impl OwnedDescriptor {
+    pub fn try_clone(&self) -> Result<OwnedDescriptor> {
+        let clone = self.owned.try_clone()?;
+        Ok(OwnedDescriptor { owned: clone })
     }
-}
-
-fn duplicate_handle_with_target_handle(
-    hndl: RawHandle,
-    target_process_handle: RawHandle,
-) -> io::Result<RawHandle> {
-    duplicate_handle_from_source_process(
-        // SAFETY:
-        // Safe because `GetCurrentProcess` just gets the current process handle.
-        unsafe { GetCurrentProcess() as _ },
-        hndl,
-        target_process_handle,
-    )
-}
-
-pub fn duplicate_handle(hndl: RawHandle) -> io::Result<RawHandle> {
-    // SAFETY:
-    // Safe because `GetCurrentProcess` just gets the current process handle.
-    duplicate_handle_with_target_handle(hndl, unsafe { GetCurrentProcess() as _ })
-}
-
-impl TryFrom<&dyn AsRawHandle> for SafeDescriptor {
-    type Error = std::io::Error;
 
-    fn try_from(handle: &dyn AsRawHandle) -> std::result::Result<Self, Self::Error> {
-        Ok(SafeDescriptor {
-            descriptor: duplicate_handle(handle.as_raw_handle())?,
-        })
+    pub fn determine_type(&self) -> Result<DescriptorType> {
+        Err(Error::from(IoErrorKind::Unsupported))
     }
 }
 
-impl SafeDescriptor {
-    /// Clones this descriptor, internally creating a new descriptor. The new SafeDescriptor will
-    /// share the same underlying count within the kernel.
-    pub fn try_clone(&self) -> Result<SafeDescriptor> {
-        // SAFETY:
-        // Safe because `duplicate_handle` will return a valid handle, or at the very least error
-        // out.
-        Ok(unsafe { SafeDescriptor::from_raw_descriptor(duplicate_handle(self.descriptor)?) })
+impl AsRawDescriptor for OwnedDescriptor {
+    fn as_raw_descriptor(&self) -> RawDescriptor {
+        self.owned.as_raw_handle()
     }
 }
 
-// SAFETY:
-// On Windows, RawHandles are represented by raw pointers but are not used as such in
-// rust code, and are therefore safe to send between threads.
-unsafe impl Send for SafeDescriptor {}
-// SAFETY: See safety comments for impl Send
-unsafe impl Sync for SafeDescriptor {}
-
-// SAFETY:
-// On Windows, RawHandles are represented by raw pointers but are opaque to the
-// userspace and cannot be derefenced by rust code, and are therefore safe to
-// send between threads.
-unsafe impl Send for Descriptor {}
-// SAFETY: See safety comments for impl Send
-unsafe impl Sync for Descriptor {}
-
-macro_rules! AsRawDescriptor {
-    ($name:ident) => {
-        impl AsRawDescriptor for $name {
-            fn as_raw_descriptor(&self) -> RawDescriptor {
-                return self.as_raw_handle();
-            }
+impl FromRawDescriptor for OwnedDescriptor {
+    // SAFETY: It is caller's responsibility to ensure that the descriptor is valid.
+    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
+        OwnedDescriptor {
+            owned: OwnedHandle::from_raw_handle(descriptor),
         }
-    };
+    }
 }
 
-macro_rules! FromRawDescriptor {
-    ($name:ident) => {
-        impl FromRawDescriptor for $name {
-            // SAFETY: It is caller's responsibility to ensure that the descriptor is valid.
-            unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
-                return $name::from_raw_handle(descriptor);
-            }
-        }
-    };
+impl IntoRawDescriptor for OwnedDescriptor {
+    fn into_raw_descriptor(self) -> RawDescriptor {
+        self.owned.into_raw_handle()
+    }
 }
 
-macro_rules! IntoRawDescriptor {
-    ($name:ident) => {
-        impl IntoRawDescriptor for $name {
-            fn into_raw_descriptor(self) -> RawDescriptor {
-                return self.into_raw_handle();
-            }
-        }
-    };
+impl IntoRawDescriptor for File {
+    fn into_raw_descriptor(self) -> RawDescriptor {
+        self.into_raw_handle()
+    }
 }
 
-// Implementations for File. This enables the File-type to use the cross-platform
-// RawDescriptor, but does not mean File should be used as a generic
-// descriptor container. That should go to either SafeDescriptor or another more
-// relevant container type.
-// TODO(b/148971445): Ensure there are no usages of File that aren't actually files.
-AsRawDescriptor!(File);
-FromRawDescriptor!(File);
-IntoRawDescriptor!(File);
+impl From<File> for OwnedDescriptor {
+    fn from(f: File) -> OwnedDescriptor {
+        OwnedDescriptor { owned: f.into() }
+    }
+}
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/windows/event.rs b/rutabaga_gfx/src/rutabaga_os/sys/windows/event.rs
new file mode 100644
index 000000000..8c9b5d423
--- /dev/null
+++ b/rutabaga_gfx/src/rutabaga_os/sys/windows/event.rs
@@ -0,0 +1,51 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+use std::convert::From;
+use std::convert::TryFrom;
+
+use crate::rutabaga_os::AsBorrowedDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
+use crate::rutabaga_utils::RutabagaError;
+use crate::rutabaga_utils::RutabagaHandle;
+use crate::rutabaga_utils::RutabagaResult;
+
+pub struct Event(());
+
+impl Event {
+    pub fn new() -> RutabagaResult<Event> {
+        Err(RutabagaError::Unsupported)
+    }
+
+    pub fn signal(&mut self) -> RutabagaResult<()> {
+        Err(RutabagaError::Unsupported)
+    }
+
+    pub fn wait(&self) -> RutabagaResult<()> {
+        Err(RutabagaError::Unsupported)
+    }
+
+    pub fn try_clone(&self) -> RutabagaResult<Event> {
+        Err(RutabagaError::Unsupported)
+    }
+}
+
+impl TryFrom<RutabagaHandle> for Event {
+    type Error = RutabagaError;
+    fn try_from(_handle: RutabagaHandle) -> Result<Self, Self::Error> {
+        Err(RutabagaError::Unsupported)
+    }
+}
+
+impl From<Event> for RutabagaHandle {
+    fn from(_evt: Event) -> Self {
+        unimplemented!()
+    }
+}
+
+impl AsBorrowedDescriptor for Event {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        unimplemented!()
+    }
+}
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/windows/memory_mapping.rs b/rutabaga_gfx/src/rutabaga_os/sys/windows/memory_mapping.rs
index 6f7cc281c..618e832a2 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/windows/memory_mapping.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/windows/memory_mapping.rs
@@ -6,7 +6,7 @@ use std::ptr::NonNull;
 
 use libc::c_void;
 
-use crate::rutabaga_os::SafeDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_utils::RutabagaError;
 use crate::rutabaga_utils::RutabagaResult;
 
@@ -20,7 +20,7 @@ pub struct MemoryMapping {
 
 impl MemoryMapping {
     pub fn from_safe_descriptor(
-        _descriptor: SafeDescriptor,
+        _descriptor: OwnedDescriptor,
         _size: usize,
         _map_info: u32,
     ) -> RutabagaResult<MemoryMapping> {
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/windows/mod.rs b/rutabaga_gfx/src/rutabaga_os/sys/windows/mod.rs
index f617bafad..5bc895be3 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/windows/mod.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/windows/mod.rs
@@ -3,7 +3,9 @@
 // found in the LICENSE file.
 
 pub mod descriptor;
+pub mod event;
 pub mod memory_mapping;
+pub mod pipe;
 pub mod shm;
 pub mod tube;
 pub mod wait_context;
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/windows/pipe.rs b/rutabaga_gfx/src/rutabaga_os/sys/windows/pipe.rs
new file mode 100644
index 000000000..5398fd056
--- /dev/null
+++ b/rutabaga_gfx/src/rutabaga_os/sys/windows/pipe.rs
@@ -0,0 +1,54 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+use crate::rutabaga_os::AsBorrowedDescriptor;
+use crate::rutabaga_os::AsRawDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
+use crate::rutabaga_os::RawDescriptor;
+use crate::rutabaga_utils::RutabagaError;
+use crate::rutabaga_utils::RutabagaResult;
+
+pub struct ReadPipeStub(());
+pub struct WritePipeStub(());
+
+pub type ReadPipe = ReadPipeStub;
+pub type WritePipe = WritePipeStub;
+
+pub fn create_pipe() -> RutabagaResult<(ReadPipe, WritePipe)> {
+    Err(RutabagaError::Unsupported)
+}
+
+impl ReadPipe {
+    pub fn read(&self, _data: &mut [u8]) -> RutabagaResult<usize> {
+        Err(RutabagaError::Unsupported)
+    }
+}
+
+impl AsBorrowedDescriptor for ReadPipe {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        unimplemented!()
+    }
+}
+
+impl WritePipe {
+    pub fn new(_descriptor: RawDescriptor) -> WritePipe {
+        unimplemented!()
+    }
+
+    pub fn write(&self, _data: &[u8]) -> RutabagaResult<usize> {
+        Err(RutabagaError::Unsupported)
+    }
+}
+
+impl AsBorrowedDescriptor for WritePipe {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        unimplemented!()
+    }
+}
+
+impl AsRawDescriptor for WritePipe {
+    fn as_raw_descriptor(&self) -> RawDescriptor {
+        unimplemented!()
+    }
+}
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/windows/shm.rs b/rutabaga_gfx/src/rutabaga_os/sys/windows/shm.rs
index 2afe7a1f5..61322c9fb 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/windows/shm.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/windows/shm.rs
@@ -6,14 +6,14 @@ use std::ffi::CStr;
 
 use crate::rutabaga_os::descriptor::AsRawDescriptor;
 use crate::rutabaga_os::descriptor::IntoRawDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_os::RawDescriptor;
-use crate::rutabaga_os::SafeDescriptor;
 use crate::rutabaga_utils::RutabagaError;
 use crate::rutabaga_utils::RutabagaResult;
 
 /// A shared memory file descriptor and its size.
 pub struct SharedMemory {
-    pub descriptor: SafeDescriptor,
+    pub descriptor: OwnedDescriptor,
     pub size: u64,
 }
 
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/windows/tube.rs b/rutabaga_gfx/src/rutabaga_os/sys/windows/tube.rs
index 57b8d60ca..fb1bc2f61 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/windows/tube.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/windows/tube.rs
@@ -2,11 +2,12 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-use std::fs::File;
 use std::path::Path;
 
+use crate::rutabaga_os::AsBorrowedDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_os::RawDescriptor;
-use crate::rutabaga_os::WaitTrait;
+use crate::rutabaga_os::TubeType;
 use crate::rutabaga_utils::RutabagaError;
 use crate::rutabaga_utils::RutabagaResult;
 
@@ -15,7 +16,7 @@ pub type Tube = Stub;
 pub type Listener = Stub;
 
 impl Tube {
-    pub fn new<P: AsRef<Path>>(_path: P) -> RutabagaResult<Tube> {
+    pub fn new<P: AsRef<Path>>(_path: P, _kind: TubeType) -> RutabagaResult<Tube> {
         Err(RutabagaError::Unsupported)
     }
 
@@ -27,13 +28,19 @@ impl Tube {
         Err(RutabagaError::Unsupported)
     }
 
-    pub fn receive(&self, _opaque_data: &mut [u8]) -> RutabagaResult<(usize, Vec<File>)> {
+    pub fn receive(
+        &self,
+        _opaque_data: &mut [u8],
+    ) -> RutabagaResult<(usize, Vec<OwnedDescriptor>)> {
         Err(RutabagaError::Unsupported)
     }
 }
 
-impl WaitTrait for Tube {}
-impl WaitTrait for &Tube {}
+impl AsBorrowedDescriptor for Tube {
+    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
+        unimplemented!()
+    }
+}
 
 impl Listener {
     /// Creates a new `Listener` bound to the given path.
diff --git a/rutabaga_gfx/src/rutabaga_os/sys/windows/wait_context.rs b/rutabaga_gfx/src/rutabaga_os/sys/windows/wait_context.rs
index 1c2303bd9..41f8c846e 100644
--- a/rutabaga_gfx/src/rutabaga_os/sys/windows/wait_context.rs
+++ b/rutabaga_gfx/src/rutabaga_os/sys/windows/wait_context.rs
@@ -2,10 +2,9 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
-use std::time::Duration;
-
+use crate::rutabaga_os::OwnedDescriptor;
 use crate::rutabaga_os::WaitEvent;
-use crate::rutabaga_os::WaitTrait;
+use crate::rutabaga_os::WaitTimeout;
 use crate::rutabaga_utils::RutabagaError;
 use crate::rutabaga_utils::RutabagaResult;
 
@@ -17,19 +16,19 @@ impl WaitContext {
         Err(RutabagaError::Unsupported)
     }
 
-    pub fn add<Waitable: WaitTrait>(
+    pub fn add(
         &mut self,
         _connection_id: u64,
-        _waitable: Waitable,
+        _descriptor: &OwnedDescriptor,
     ) -> RutabagaResult<()> {
         Err(RutabagaError::Unsupported)
     }
 
-    pub fn wait(&mut self, _duration_opt: Option<Duration>) -> RutabagaResult<Vec<WaitEvent>> {
+    pub fn wait(&mut self, _timeout: WaitTimeout) -> RutabagaResult<Vec<WaitEvent>> {
         Err(RutabagaError::Unsupported)
     }
 
-    pub fn delete<Waitable: WaitTrait>(&mut self, _waitable: Waitable) -> RutabagaResult<()> {
+    pub fn delete(&mut self, _descriptor: &OwnedDescriptor) -> RutabagaResult<()> {
         Err(RutabagaError::Unsupported)
     }
 }
diff --git a/rutabaga_gfx/src/rutabaga_snapshot.rs b/rutabaga_gfx/src/rutabaga_snapshot.rs
deleted file mode 100644
index 355ff44c6..000000000
--- a/rutabaga_gfx/src/rutabaga_snapshot.rs
+++ /dev/null
@@ -1,73 +0,0 @@
-// Copyright 2023 The ChromiumOS Authors
-// Use of this source code is governed by a BSD-style license that can be
-// found in the LICENSE file.
-
-use std::collections::BTreeMap;
-use std::io::Read;
-use std::io::Write;
-
-use zerocopy::AsBytes;
-use zerocopy::FromBytes;
-
-pub struct RutabagaSnapshot {
-    pub resources: BTreeMap<u32, RutabagaResourceSnapshot>,
-}
-
-pub struct RutabagaResourceSnapshot {
-    pub resource_id: u32,
-    pub width: u32,
-    pub height: u32,
-}
-
-impl RutabagaSnapshot {
-    // To avoid adding a build dependency, we use a custom serialization format. It is an internal
-    // detail, doesn't need to support host migration (e.g. we don't need to care about endianess
-    // or integer sizes), and isn't expected to be stable across releases.
-    pub fn serialize_to(&self, w: &mut impl Write) -> std::io::Result<()> {
-        fn write(w: &mut impl Write, v: impl AsBytes) -> std::io::Result<()> {
-            w.write_all(v.as_bytes())
-        }
-
-        write(w, self.resources.len())?;
-        for (id, resource) in self.resources.iter() {
-            assert_eq!(*id, resource.resource_id);
-            write(w, resource.resource_id)?;
-            write(w, resource.width)?;
-            write(w, resource.height)?;
-        }
-
-        Ok(())
-    }
-
-    pub fn deserialize_from(r: &mut impl Read) -> std::io::Result<Self> {
-        fn read<T: AsBytes + FromBytes + Default>(r: &mut impl Read) -> std::io::Result<T> {
-            let mut v: T = Default::default();
-            r.read_exact(v.as_bytes_mut())?;
-            Ok(v)
-        }
-
-        let num_resources: usize = read::<usize>(r)?;
-        let mut resources = BTreeMap::new();
-        for _ in 0..num_resources {
-            let resource_id = read(r)?;
-            let width = read(r)?;
-            let height = read(r)?;
-            resources.insert(
-                resource_id,
-                RutabagaResourceSnapshot {
-                    resource_id,
-                    width,
-                    height,
-                },
-            );
-        }
-
-        // Verify we have consumed the all the input by checking for EOF.
-        let mut buf = [0u8];
-        if r.read(&mut buf)? != 0 {
-            return Err(std::io::ErrorKind::InvalidData.into());
-        }
-
-        Ok(RutabagaSnapshot { resources })
-    }
-}
diff --git a/rutabaga_gfx/src/rutabaga_utils.rs b/rutabaga_gfx/src/rutabaga_utils.rs
index 62a57f008..8104ca978 100644
--- a/rutabaga_gfx/src/rutabaga_utils.rs
+++ b/rutabaga_gfx/src/rutabaga_utils.rs
@@ -36,7 +36,7 @@ use zerocopy::AsBytes;
 use zerocopy::FromBytes;
 use zerocopy::FromZeroes;
 
-use crate::rutabaga_os::SafeDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
 
 /// Represents a buffer.  `base` contains the address of a buffer, while `len` contains the length
 /// of the buffer.
@@ -675,7 +675,7 @@ pub const RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD: u32 = 0x000a;
 
 /// Handle to OS-specific memory or synchronization objects.
 pub struct RutabagaHandle {
-    pub os_handle: SafeDescriptor,
+    pub os_handle: OwnedDescriptor,
     pub handle_type: u32,
 }
 
diff --git a/rutabaga_gfx/src/virgl_renderer.rs b/rutabaga_gfx/src/virgl_renderer.rs
index 648a30c3f..7b64646d6 100644
--- a/rutabaga_gfx/src/virgl_renderer.rs
+++ b/rutabaga_gfx/src/virgl_renderer.rs
@@ -8,15 +8,14 @@
 #![cfg(feature = "virgl_renderer")]
 
 use std::cmp::min;
-use std::convert::TryFrom;
 use std::io::Error as SysError;
 use std::io::IoSliceMut;
 use std::mem::size_of;
 use std::mem::transmute;
+use std::mem::ManuallyDrop;
 use std::os::raw::c_char;
 use std::os::raw::c_int;
 use std::os::raw::c_void;
-use std::os::unix::io::AsRawFd;
 use std::panic::catch_unwind;
 use std::process::abort;
 use std::ptr::null_mut;
@@ -36,11 +35,25 @@ use crate::rutabaga_core::RutabagaContext;
 use crate::rutabaga_core::RutabagaResource;
 use crate::rutabaga_os::FromRawDescriptor;
 use crate::rutabaga_os::IntoRawDescriptor;
-use crate::rutabaga_os::SafeDescriptor;
+use crate::rutabaga_os::OwnedDescriptor;
+use crate::rutabaga_os::RawDescriptor;
 use crate::rutabaga_utils::*;
 
 type Query = virgl_renderer_export_query;
 
+fn dup(rd: RawDescriptor) -> RutabagaResult<OwnedDescriptor> {
+    // SAFETY:
+    // Safe because the underlying raw descriptor is guaranteed valid by rd's existence.
+    //
+    // Note that we are cloning the underlying raw descriptor since we have no guarantee of
+    // its existence after this function returns.
+    let rd_as_safe_desc = ManuallyDrop::new(unsafe { OwnedDescriptor::from_raw_descriptor(rd) });
+
+    // We have to clone rd because we have no guarantee ownership was transferred (rd is
+    // borrowed).
+    Ok(rd_as_safe_desc.try_clone()?)
+}
+
 /// The virtio-gpu backend state tracker which supports accelerated rendering.
 pub struct VirglRenderer {}
 
@@ -278,7 +291,7 @@ unsafe extern "C" fn get_server_fd(cookie: *mut c_void, version: u32) -> c_int {
         cookie
             .render_server_fd
             .take()
-            .map(SafeDescriptor::into_raw_descriptor)
+            .map(OwnedDescriptor::into_raw_descriptor)
             .unwrap_or(-1)
     })
     .unwrap_or_else(|_| abort())
@@ -319,7 +332,7 @@ impl VirglRenderer {
     pub fn init(
         virglrenderer_flags: VirglRendererFlags,
         fence_handler: RutabagaFenceHandler,
-        render_server_fd: Option<SafeDescriptor>,
+        render_server_fd: Option<OwnedDescriptor>,
     ) -> RutabagaResult<Box<dyn RutabagaComponent>> {
         if cfg!(debug_assertions) {
             // TODO(b/315870313): Add safety comment
@@ -415,7 +428,7 @@ impl VirglRenderer {
         // SAFETY:
         // Safe because the FD was just returned by a successful virglrenderer
         // call so it must be valid and owned by us.
-        let handle = unsafe { SafeDescriptor::from_raw_descriptor(fd) };
+        let handle = unsafe { OwnedDescriptor::from_raw_descriptor(fd) };
 
         let handle_type = match fd_type {
             VIRGL_RENDERER_BLOB_FD_TYPE_DMABUF => RUTABAGA_MEM_HANDLE_TYPE_DMABUF,
@@ -495,12 +508,13 @@ impl RutabagaComponent for VirglRenderer {
         };
     }
 
-    fn poll_descriptor(&self) -> Option<SafeDescriptor> {
+    fn poll_descriptor(&self) -> Option<OwnedDescriptor> {
         // SAFETY:
         // Safe because it can be called anytime and returns -1 in the event of an error.
         let fd = unsafe { virgl_renderer_get_poll_fd() };
         if fd >= 0 {
-            if let Ok(dup_fd) = SafeDescriptor::try_from(&fd as &dyn AsRawFd) {
+            let descriptor: RawDescriptor = fd as RawDescriptor;
+            if let Ok(dup_fd) = dup(descriptor) {
                 return Some(dup_fd);
             }
         }
@@ -760,7 +774,7 @@ impl RutabagaComponent for VirglRenderer {
             // SAFETY:
             // Safe because the FD was just returned by a successful virglrenderer call so it must
             // be valid and owned by us.
-            let fence = unsafe { SafeDescriptor::from_raw_descriptor(fd) };
+            let fence = unsafe { OwnedDescriptor::from_raw_descriptor(fd) };
             Ok(RutabagaHandle {
                 os_handle: fence,
                 handle_type: RUTABAGA_FENCE_HANDLE_TYPE_SYNC_FD,
diff --git a/src/crosvm/cmdline.rs b/src/crosvm/cmdline.rs
index 82e26f8c8..c99616fb9 100644
--- a/src/crosvm/cmdline.rs
+++ b/src/crosvm/cmdline.rs
@@ -24,6 +24,9 @@ use std::sync::atomic::Ordering;
 
 use arch::CpuSet;
 use arch::FdtPosition;
+#[cfg(target_arch = "x86_64")]
+use arch::MemoryRegionConfig;
+use arch::PciConfig;
 use arch::Pstore;
 #[cfg(target_arch = "x86_64")]
 use arch::SmbiosOptions;
@@ -86,8 +89,6 @@ use crate::crosvm::config::parse_cpu_capacity;
 ))]
 use crate::crosvm::config::parse_cpu_frequencies;
 use crate::crosvm::config::parse_dynamic_power_coefficient;
-#[cfg(target_arch = "x86_64")]
-use crate::crosvm::config::parse_memory_region;
 use crate::crosvm::config::parse_mmio_address_range;
 use crate::crosvm::config::parse_pflash_parameters;
 use crate::crosvm::config::parse_serial_options;
@@ -646,6 +647,7 @@ pub struct UsbAttachCommand {
         arg_name = "BUS_ID:ADDR:BUS_NUM:DEV_NUM",
         from_str_fn(parse_bus_id_addr)
     )]
+    #[allow(dead_code)]
     pub addr: (u8, u8, u16, u16),
     #[argh(positional)]
     /// usb device path
@@ -1150,7 +1152,11 @@ pub struct RunCommand {
     )]
     #[serde(skip)]
     #[merge(strategy = overwrite_option)]
-    /// set the list of frequencies in KHz for the given CPU (default: no frequencies)
+    /// set the list of frequencies in KHz for the given CPU (default: no frequencies).
+    /// In the event that the user specifies a frequency (after normalizing for cpu_capacity)
+    /// that results in a performance point that goes below the lowest frequency that the pCPU can
+    /// support, the virtual cpufreq device will actively throttle the vCPU to deliberately slow
+    /// its performance to match the guest's request.
     pub cpu_frequencies_khz: Option<BTreeMap<usize, Vec<u32>>>, // CPU index -> frequencies
 
     #[argh(option, short = 'c')]
@@ -1179,6 +1185,22 @@ pub struct RunCommand {
     ///       vCPU 1 as intel Atom type, also set vCPU 2 and vCPU 3
     ///       as intel Core type.
     ///     boot-cpu=NUM - Select vCPU to boot from. (default: 0) (aarch64 only)
+    ///     freq_domains=[[FREQ_DOMAIN],...] - CPU freq_domains (default: None) (aarch64 only)
+    ///       Usage is identical to clusters, each FREQ_DOMAIN is a set containing a
+    ///       list of CPUs that should belong to the same freq_domain. Individual
+    ///       CPU ids or ranges can be specified, comma-separated.
+    ///       Examples:
+    ///       freq_domains=[[0],[1],[2],[3]] - creates 4 freq_domains, one
+    ///         for each specified core.
+    ///       freq_domains=[[0-3]] - creates a freq_domain for cores 0 to 3
+    ///         included.
+    ///       freq_domains=[[0,2],[1,3],[4-7,12]] - creates one freq_domain
+    ///         for cores 0 and 2, another one for cores 1 and 3,
+    ///         and one last for cores 4, 5, 6, 7 and 12.
+    ///     sve=[enabled=bool] - SVE Config. (aarch64 only)
+    ///         Examples:
+    ///         sve=[enabled=true] - Enables SVE on device. Will fail is SVE unsupported.
+    ///         default value = false.
     pub cpus: Option<CpuOptions>,
 
     #[cfg(feature = "crash-report")]
@@ -1366,7 +1388,7 @@ pub struct RunCommand {
     /// Possible key values:
     ///     backend=(2d|virglrenderer|gfxstream) - Which backend to
     ///        use for virtio-gpu (determining rendering protocol)
-    ///     max_num_displays=INT - The maximum number of concurrent
+    ///     max-num-displays=INT - The maximum number of concurrent
     ///        virtual displays in this VM. This must not exceed
     ///        VIRTIO_GPU_MAX_SCANOUTS (i.e. 16).
     ///     displays=[[GpuDisplayParameters]] - The list of virtual
@@ -1634,6 +1656,14 @@ pub struct RunCommand {
     /// to 800x1280) and a name for the input device
     pub multi_touch: Vec<TouchDeviceOption>,
 
+    #[argh(option)]
+    #[merge(strategy = overwrite_option)]
+    /// optional name for the VM. This is used as the name of the crosvm
+    /// process which is helpful to distinguish multiple crosvm processes.
+    /// A name longer than 15 bytes is truncated on Linux-like OSes. This
+    /// is no-op on Windows and MacOS at the moment.
+    pub name: Option<String>,
+
     #[cfg(all(unix, feature = "net"))]
     #[argh(
         option,
@@ -1711,6 +1741,13 @@ pub struct RunCommand {
     /// don't use legacy KBD devices emulation
     pub no_i8042: Option<bool>,
 
+    #[cfg(target_arch = "aarch64")]
+    #[argh(switch)]
+    #[serde(skip)] // TODO(b/255223604)
+    #[merge(strategy = overwrite_option)]
+    /// disable Performance Monitor Unit (PMU)
+    pub no_pmu: Option<bool>,
+
     #[argh(switch)]
     #[serde(skip)] // TODO(b/255223604)
     #[merge(strategy = overwrite_option)]
@@ -1749,6 +1786,21 @@ pub struct RunCommand {
     /// extra kernel or plugin command line arguments. Can be given more than once
     pub params: Vec<String>,
 
+    #[argh(option)]
+    #[serde(default)]
+    #[merge(strategy = overwrite_option)]
+    /// PCI parameters.
+    ///
+    /// Possible key values:
+    ///     mem=[start=INT,size=INT] - region for non-prefetchable PCI device memory below 4G
+    ///
+    /// Possible key values (aarch64 only):
+    ///     cam=[start=INT,size=INT] - region for PCI Configuration Access Mechanism
+    ///
+    /// Possible key values (x86_64 only):
+    ///     ecam=[start=INT,size=INT] - region for PCIe Enhanced Configuration Access Mechanism
+    pub pci: Option<PciConfig>,
+
     #[cfg(any(target_os = "android", target_os = "linux"))]
     #[argh(option, arg_name = "pci_hotplug_slots")]
     #[serde(default)]
@@ -1763,17 +1815,6 @@ pub struct RunCommand {
     /// the pci mmio start address below 4G
     pub pci_start: Option<u64>,
 
-    #[cfg(target_arch = "x86_64")]
-    #[argh(
-        option,
-        arg_name = "mmio_base,mmio_length",
-        from_str_fn(parse_memory_region)
-    )]
-    #[serde(skip)] // TODO(b/255223604)
-    #[merge(strategy = overwrite_option)]
-    /// region for PCIe Enhanced Configuration Access Mechanism
-    pub pcie_ecam: Option<AddressRange>,
-
     #[argh(switch)]
     #[serde(skip)] // TODO(b/255223604)
     #[merge(strategy = overwrite_option)]
@@ -2101,7 +2142,10 @@ pub struct RunCommand {
     /// devices. Can be given more than once.
     /// Possible key values:
     ///     type=(stdout,syslog,sink,file) - Where to route the
-    ///        serial device
+    ///        serial device.
+    ///        Platform-specific options:
+    ///        On Unix: 'unix' (datagram) and 'unix-stream' (stream)
+    ///        On Windows: 'namedpipe'
     ///     hardware=(serial,virtio-console,debugcon,
     ///               legacy-virtio-console) - Which type of
     ///        serial hardware to emulate. Defaults to 8250 UART
@@ -2117,6 +2161,11 @@ pub struct RunCommand {
     ///        type=file
     ///     input=PATH - The path to the file to read from when not
     ///        stdin
+    ///     input-unix-stream - (Unix-only) Whether to use the given
+    ///        Unix stream socket for input as well as output.
+    ///        This flag is only valid when type=unix-stream and
+    ///        the socket path is specified with path=.
+    ///        Can't be passed when input is specified.
     ///     console - Use this serial device as the guest console.
     ///        Will default to first serial port if not provided.
     ///     earlycon - Use this serial device as the early console.
@@ -2224,6 +2273,14 @@ pub struct RunCommand {
     ///     and give CAP_SETUID/CAP_SETGID to the crosvm.
     pub shared_dir: Vec<SharedDir>,
 
+    #[cfg(all(unix, feature = "media"))]
+    #[argh(switch)]
+    #[serde(default)]
+    #[merge(strategy = overwrite_option)]
+    /// enable the simple virtio-media device, a virtual capture device generating a fixed pattern
+    /// for testing purposes.
+    pub simple_media_device: Option<bool>,
+
     #[argh(
         option,
         arg_name = "[path=]PATH[,width=WIDTH][,height=HEIGHT][,name=NAME]",
@@ -2386,6 +2443,14 @@ pub struct RunCommand {
     /// (EXPERIMENTAL/FOR DEBUGGING) Use VM firmware, but allow host access to guest memory
     pub unprotected_vm_with_firmware: Option<PathBuf>,
 
+    #[cfg(any(target_os = "android", target_os = "linux"))]
+    #[cfg(all(unix, feature = "media"))]
+    #[argh(option, arg_name = "[device]")]
+    #[serde(default)]
+    #[merge(strategy = append)]
+    /// path to a V4L2 device to expose to the guest using the virtio-media protocol.
+    pub v4l2_proxy: Vec<PathBuf>,
+
     #[argh(option, arg_name = "PATH")]
     #[serde(skip)] // TODO(b/255223604)
     #[merge(strategy = overwrite_option)]
@@ -2572,6 +2637,17 @@ pub struct RunCommand {
     /// enable a virtual cpu freq device
     pub virt_cpufreq: Option<bool>,
 
+    #[cfg(all(
+        any(target_arch = "arm", target_arch = "aarch64"),
+        any(target_os = "android", target_os = "linux")
+    ))]
+    #[argh(switch)]
+    #[serde(skip)]
+    #[merge(strategy = overwrite_option)]
+    /// enable version of the virtual cpu freq device compatible
+    /// with the driver in upstream linux
+    pub virt_cpufreq_upstream: Option<bool>,
+
     #[cfg(feature = "audio")]
     #[argh(
         option,
@@ -2716,6 +2792,7 @@ impl TryFrom<RunCommand> for super::config::Config {
             let cpus = cmd.cpus.unwrap_or_default();
             cfg.vcpu_count = cpus.num_cores;
             cfg.boot_cpu = cpus.boot_cpu.unwrap_or_default();
+            cfg.cpu_freq_domains = cpus.freq_domains;
 
             // Only allow deprecated `--cpu-cluster` option only if `--cpu clusters=[...]` is not
             // used.
@@ -2750,6 +2827,10 @@ impl TryFrom<RunCommand> for super::config::Config {
                     }
                 }
             }
+            #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+            {
+                cfg.sve = cpus.sve;
+            }
         }
 
         cfg.vcpu_affinity = cmd.cpu_affinity;
@@ -2768,6 +2849,10 @@ impl TryFrom<RunCommand> for super::config::Config {
         ))]
         {
             cfg.virt_cpufreq = cmd.virt_cpufreq.unwrap_or_default();
+            cfg.virt_cpufreq_v2 = cmd.virt_cpufreq_upstream.unwrap_or_default();
+            if cfg.virt_cpufreq && cfg.virt_cpufreq_v2 {
+                return Err("Only one version of virt-cpufreq can be used!".to_string());
+            }
             if let Some(frequencies) = cmd.cpu_frequencies_khz {
                 cfg.cpu_frequencies_khz = frequencies;
             }
@@ -2799,6 +2884,7 @@ impl TryFrom<RunCommand> for super::config::Config {
                 );
             }
             cfg.mte = cmd.mte.unwrap_or_default();
+            cfg.no_pmu = cmd.no_pmu.unwrap_or_default();
             cfg.swiotlb = cmd.swiotlb;
         }
 
@@ -3526,17 +3612,28 @@ impl TryFrom<RunCommand> for super::config::Config {
 
         cfg.host_cpu_topology = cmd.host_cpu_topology.unwrap_or_default();
 
+        cfg.pci_config = cmd.pci.unwrap_or_default();
+
         #[cfg(target_arch = "x86_64")]
         {
             cfg.break_linux_pci_config_io = cmd.break_linux_pci_config_io.unwrap_or_default();
             cfg.enable_hwp = cmd.enable_hwp.unwrap_or_default();
             cfg.force_s2idle = cmd.s2idle.unwrap_or_default();
-            cfg.pcie_ecam = cmd.pcie_ecam;
-            cfg.pci_low_start = cmd.pci_start;
             cfg.no_i8042 = cmd.no_i8042.unwrap_or_default();
             cfg.no_rtc = cmd.no_rtc.unwrap_or_default();
             cfg.smbios = cmd.smbios.unwrap_or_default();
 
+            if let Some(pci_start) = cmd.pci_start {
+                if cfg.pci_config.mem.is_some() {
+                    return Err("--pci-start cannot be used with --pci mem=[...]".to_string());
+                }
+                log::warn!("`--pci-start` is deprecated; use `--pci mem=[start={pci_start:#?}]");
+                cfg.pci_config.mem = Some(MemoryRegionConfig {
+                    start: pci_start,
+                    size: None,
+                });
+            }
+
             if !cmd.oem_strings.is_empty() {
                 log::warn!(
                     "`--oem-strings` is deprecated; use `--smbios oem-strings=[...]` instead."
@@ -3604,6 +3701,13 @@ impl TryFrom<RunCommand> for super::config::Config {
 
         cfg.fdt_position = cmd.fdt_position;
 
+        #[cfg(any(target_os = "android", target_os = "linux"))]
+        #[cfg(all(unix, feature = "media"))]
+        {
+            cfg.v4l2_proxy = cmd.v4l2_proxy;
+            cfg.simple_media_device = cmd.simple_media_device.unwrap_or_default();
+        }
+
         cfg.file_backed_mappings = cmd.file_backed_mapping;
 
         #[cfg(target_os = "android")]
@@ -3644,6 +3748,8 @@ impl TryFrom<RunCommand> for super::config::Config {
             cfg.jail_config = None;
         }
 
+        cfg.name = cmd.name;
+
         // Now do validation of constructed config
         super::config::validate_config(&mut cfg)?;
 
diff --git a/src/crosvm/config.rs b/src/crosvm/config.rs
index a3cd1ac8f..59a024f0a 100644
--- a/src/crosvm/config.rs
+++ b/src/crosvm/config.rs
@@ -14,9 +14,12 @@ use std::time::Duration;
 use arch::set_default_serial_parameters;
 use arch::CpuSet;
 use arch::FdtPosition;
+use arch::PciConfig;
 use arch::Pstore;
 #[cfg(target_arch = "x86_64")]
 use arch::SmbiosOptions;
+#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+use arch::SveConfig;
 use arch::VcpuAffinity;
 use base::debug;
 use base::pagesize;
@@ -80,14 +83,6 @@ cfg_if::cfg_if! {
     }
 }
 
-#[cfg(target_arch = "x86_64")]
-const ONE_MB: u64 = 1 << 20;
-#[cfg(target_arch = "x86_64")]
-const MB_ALIGNED: u64 = ONE_MB - 1;
-// the max bus number is 256 and each bus occupy 1MB, so the max pcie cfg mmio size = 256M
-#[cfg(target_arch = "x86_64")]
-const MAX_PCIE_ECAM_SIZE: u64 = ONE_MB * 256;
-
 // by default, if enabled, the balloon WS features will use 4 bins.
 #[cfg(feature = "balloon")]
 const VIRTIO_BALLOON_WS_DEFAULT_NUM_BINS: u8 = 4;
@@ -141,6 +136,12 @@ pub struct CpuOptions {
     /// Select which CPU to boot from.
     #[serde(default)]
     pub boot_cpu: Option<usize>,
+    /// Vector of CPU ids to be grouped into the same freq domain.
+    #[serde(default)]
+    pub freq_domains: Vec<CpuSet>,
+    /// Scalable Vector Extension.
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+    pub sve: Option<SveConfig>,
 }
 
 /// Device tree overlay configuration.
@@ -378,6 +379,11 @@ pub enum InputDeviceOption {
         height: Option<u32>,
         name: Option<String>,
     },
+    #[serde(rename_all = "kebab-case")]
+    Custom {
+        path: PathBuf,
+        config_path: PathBuf,
+    },
 }
 
 #[derive(Debug, Serialize, Deserialize, FromKeyValues)]
@@ -448,10 +454,7 @@ pub fn validate_serial_parameters(params: &SerialParameters) -> Result<(), Strin
         ));
     }
 
-    if params.pci_address.is_some()
-        && params.hardware != SerialHardware::VirtioConsole
-        && params.hardware != SerialHardware::LegacyVirtioConsole
-    {
+    if params.pci_address.is_some() && params.hardware != SerialHardware::VirtioConsole {
         return Err(invalid_value_err(
             params.pci_address.unwrap().to_string(),
             "Providing serial PCI address is only supported for virtio-console hardware type",
@@ -469,63 +472,6 @@ pub fn parse_serial_options(s: &str) -> Result<SerialParameters, String> {
     Ok(params)
 }
 
-#[cfg(target_arch = "x86_64")]
-pub fn parse_memory_region(value: &str) -> Result<AddressRange, String> {
-    let paras: Vec<&str> = value.split(',').collect();
-    if paras.len() != 2 {
-        return Err(invalid_value_err(
-            value,
-            "pcie-ecam must have exactly 2 parameters: ecam_base,ecam_size",
-        ));
-    }
-    let base = parse_hex_or_decimal(paras[0]).map_err(|_| {
-        invalid_value_err(
-            value,
-            "pcie-ecam, the first parameter base should be integer",
-        )
-    })?;
-    let mut len = parse_hex_or_decimal(paras[1]).map_err(|_| {
-        invalid_value_err(
-            value,
-            "pcie-ecam, the second parameter size should be integer",
-        )
-    })?;
-
-    if (base & MB_ALIGNED != 0) || (len & MB_ALIGNED != 0) {
-        return Err(invalid_value_err(
-            value,
-            "pcie-ecam, the base and len should be aligned to 1MB",
-        ));
-    }
-
-    if len > MAX_PCIE_ECAM_SIZE {
-        len = MAX_PCIE_ECAM_SIZE;
-    }
-
-    if base + len >= 0x1_0000_0000 {
-        return Err(invalid_value_err(
-            value,
-            "pcie-ecam, the end address couldn't beyond 4G",
-        ));
-    }
-
-    if base % len != 0 {
-        return Err(invalid_value_err(
-            value,
-            "pcie-ecam, base should be multiple of len",
-        ));
-    }
-
-    if let Some(range) = AddressRange::from_start_and_size(base, len) {
-        Ok(range)
-    } else {
-        Err(invalid_value_err(
-            value,
-            "pcie-ecam must be representable as AddressRange",
-        ))
-    }
-}
-
 pub fn parse_bus_id_addr(v: &str) -> Result<(u8, u8, u16, u16), String> {
     debug!("parse_bus_id_addr: {}", v);
     let mut ids = v.split(':');
@@ -753,6 +699,7 @@ pub struct Config {
     pub core_scheduling: bool,
     pub cpu_capacity: BTreeMap<usize, u32>, // CPU index -> capacity
     pub cpu_clusters: Vec<CpuSet>,
+    pub cpu_freq_domains: Vec<CpuSet>,
     #[cfg(all(
         any(target_arch = "arm", target_arch = "aarch64"),
         any(target_os = "android", target_os = "linux")
@@ -822,20 +769,19 @@ pub struct Config {
     pub mmio_address_ranges: Vec<AddressRange>,
     #[cfg(target_arch = "aarch64")]
     pub mte: bool,
+    pub name: Option<String>,
     #[cfg(feature = "net")]
     pub net: Vec<NetParameters>,
     #[cfg(windows)]
     pub net_vhost_user_tube: Option<Tube>,
     pub no_i8042: bool,
+    pub no_pmu: bool,
     pub no_rtc: bool,
     pub no_smt: bool,
     pub params: Vec<String>,
+    pub pci_config: PciConfig,
     #[cfg(feature = "pci-hotplug")]
     pub pci_hotplug_slots: Option<u8>,
-    #[cfg(target_arch = "x86_64")]
-    pub pci_low_start: Option<u64>,
-    #[cfg(target_arch = "x86_64")]
-    pub pcie_ecam: Option<AddressRange>,
     pub per_vm_core_scheduling: bool,
     pub pflash_parameters: Option<PflashParameters>,
     #[cfg(feature = "plugin")]
@@ -873,6 +819,8 @@ pub struct Config {
     #[cfg(any(target_os = "android", target_os = "linux"))]
     #[serde(skip)]
     pub shared_dirs: Vec<SharedDir>,
+    #[cfg(feature = "media")]
+    pub simple_media_device: bool,
     #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
     pub slirp_capture_file: Option<String>,
     #[cfg(target_arch = "x86_64")]
@@ -884,6 +832,8 @@ pub struct Config {
     pub sound: Option<PathBuf>,
     pub stub_pci_devices: Vec<StubPciParameters>,
     pub suspended: bool,
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+    pub sve: Option<SveConfig>,
     pub swap_dir: Option<PathBuf>,
     pub swiotlb: Option<u64>,
     #[cfg(target_os = "android")]
@@ -891,6 +841,9 @@ pub struct Config {
     #[cfg(any(target_os = "android", target_os = "linux"))]
     pub unmap_guest_memory_on_fork: bool,
     pub usb: bool,
+    #[cfg(any(target_os = "android", target_os = "linux"))]
+    #[cfg(feature = "media")]
+    pub v4l2_proxy: Vec<PathBuf>,
     pub vcpu_affinity: Option<VcpuAffinity>,
     pub vcpu_cgroup_path: Option<PathBuf>,
     pub vcpu_count: Option<usize>,
@@ -918,6 +871,7 @@ pub struct Config {
         any(target_os = "android", target_os = "linux")
     ))]
     pub virt_cpufreq: bool,
+    pub virt_cpufreq_v2: bool,
     pub virtio_input: Vec<InputDeviceOption>,
     #[cfg(feature = "audio")]
     #[serde(skip)]
@@ -979,6 +933,7 @@ impl Default for Config {
                 any(target_os = "android", target_os = "linux")
             ))]
             cpu_frequencies_khz: BTreeMap::new(),
+            cpu_freq_domains: Vec::new(),
             delay_rt: false,
             device_tree_overlay: Vec::new(),
             disks: Vec::new(),
@@ -1049,20 +1004,19 @@ impl Default for Config {
             mmio_address_ranges: Vec::new(),
             #[cfg(target_arch = "aarch64")]
             mte: false,
+            name: None,
             #[cfg(feature = "net")]
             net: Vec::new(),
             #[cfg(windows)]
             net_vhost_user_tube: None,
             no_i8042: false,
+            no_pmu: false,
             no_rtc: false,
             no_smt: false,
             params: Vec::new(),
+            pci_config: Default::default(),
             #[cfg(feature = "pci-hotplug")]
             pci_hotplug_slots: None,
-            #[cfg(target_arch = "x86_64")]
-            pci_low_start: None,
-            #[cfg(target_arch = "x86_64")]
-            pcie_ecam: None,
             per_vm_core_scheduling: false,
             pflash_parameters: None,
             #[cfg(feature = "plugin")]
@@ -1093,6 +1047,8 @@ impl Default for Config {
             service_pipe_name: None,
             #[cfg(any(target_os = "android", target_os = "linux"))]
             shared_dirs: Vec::new(),
+            #[cfg(feature = "media")]
+            simple_media_device: Default::default(),
             #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
             slirp_capture_file: None,
             #[cfg(target_arch = "x86_64")]
@@ -1104,6 +1060,8 @@ impl Default for Config {
             sound: None,
             stub_pci_devices: Vec::new(),
             suspended: false,
+            #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+            sve: None,
             swap_dir: None,
             swiotlb: None,
             #[cfg(target_os = "android")]
@@ -1139,9 +1097,13 @@ impl Default for Config {
                 any(target_os = "android", target_os = "linux")
             ))]
             virt_cpufreq: false,
+            virt_cpufreq_v2: false,
             virtio_input: Vec::new(),
             #[cfg(feature = "audio")]
             virtio_snds: Vec::new(),
+            #[cfg(any(target_os = "android", target_os = "linux"))]
+            #[cfg(feature = "media")]
+            v4l2_proxy: Vec::new(),
             #[cfg(feature = "vtpm")]
             vtpm_proxy: false,
             wayland_socket_paths: BTreeMap::new(),
@@ -1234,8 +1196,8 @@ pub fn validate_config(cfg: &mut Config) -> std::result::Result<(), String> {
         any(target_os = "android", target_os = "linux")
     ))]
     if !cfg.cpu_frequencies_khz.is_empty() {
-        if !cfg.virt_cpufreq {
-            return Err("`cpu-frequencies` requires `virt-cpufreq`".to_string());
+        if !cfg.virt_cpufreq_v2 {
+            return Err("`cpu-frequencies` requires `virt-cpufreq-upstream`".to_string());
         }
 
         if cfg.host_cpu_topology {
@@ -1406,6 +1368,13 @@ mod tests {
 
     use super::*;
 
+    fn config_from_args(args: &[&str]) -> Config {
+        crate::crosvm::cmdline::RunCommand::from_args(&[], args)
+            .unwrap()
+            .try_into()
+            .unwrap()
+    }
+
     #[test]
     fn parse_cpu_opts() {
         let res: CpuOptions = from_key_values("").unwrap();
@@ -2473,6 +2442,80 @@ mod tests {
         );
     }
 
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+    #[test]
+    fn parse_pci_cam() {
+        assert_eq!(
+            config_from_args(&["--pci", "cam=[start=0x123]", "/dev/null"]).pci_config,
+            PciConfig {
+                cam: Some(arch::MemoryRegionConfig {
+                    start: 0x123,
+                    size: None,
+                }),
+                ..PciConfig::default()
+            }
+        );
+        assert_eq!(
+            config_from_args(&["--pci", "cam=[start=0x123,size=0x456]", "/dev/null"]).pci_config,
+            PciConfig {
+                cam: Some(arch::MemoryRegionConfig {
+                    start: 0x123,
+                    size: Some(0x456),
+                }),
+                ..PciConfig::default()
+            },
+        );
+    }
+
+    #[cfg(target_arch = "x86_64")]
+    #[test]
+    fn parse_pci_ecam() {
+        assert_eq!(
+            config_from_args(&["--pci", "ecam=[start=0x123]", "/dev/null"]).pci_config,
+            PciConfig {
+                ecam: Some(arch::MemoryRegionConfig {
+                    start: 0x123,
+                    size: None,
+                }),
+                ..PciConfig::default()
+            }
+        );
+        assert_eq!(
+            config_from_args(&["--pci", "ecam=[start=0x123,size=0x456]", "/dev/null"]).pci_config,
+            PciConfig {
+                ecam: Some(arch::MemoryRegionConfig {
+                    start: 0x123,
+                    size: Some(0x456),
+                }),
+                ..PciConfig::default()
+            },
+        );
+    }
+
+    #[test]
+    fn parse_pci_mem() {
+        assert_eq!(
+            config_from_args(&["--pci", "mem=[start=0x123]", "/dev/null"]).pci_config,
+            PciConfig {
+                mem: Some(arch::MemoryRegionConfig {
+                    start: 0x123,
+                    size: None,
+                }),
+                ..PciConfig::default()
+            }
+        );
+        assert_eq!(
+            config_from_args(&["--pci", "mem=[start=0x123,size=0x456]", "/dev/null"]).pci_config,
+            PciConfig {
+                mem: Some(arch::MemoryRegionConfig {
+                    start: 0x123,
+                    size: Some(0x456),
+                }),
+                ..PciConfig::default()
+            },
+        );
+    }
+
     #[test]
     fn parse_pmem_options_missing_path() {
         assert!(from_key_values::<PmemOption>("")
diff --git a/src/crosvm/plugin/mod.rs b/src/crosvm/plugin/mod.rs
index e739dd8c9..0e656523f 100644
--- a/src/crosvm/plugin/mod.rs
+++ b/src/crosvm/plugin/mod.rs
@@ -795,7 +795,7 @@ pub fn run_config(cfg: Config) -> Result<()> {
                 None => None,
                 Some(cgroup_path) => {
                     // Move main process to cgroup_path
-                    let mut f = File::create(&cgroup_path.join("tasks"))?;
+                    let mut f = File::create(cgroup_path.join("tasks"))?;
                     f.write_all(std::process::id().to_string().as_bytes())?;
                     Some(f)
                 }
diff --git a/src/crosvm/plugin/process.rs b/src/crosvm/plugin/process.rs
index 008452321..7603384f7 100644
--- a/src/crosvm/plugin/process.rs
+++ b/src/crosvm/plugin/process.rs
@@ -662,7 +662,7 @@ impl Process {
             // cap is cast back to an integer and fed to an ioctl. If the extension name is actually
             // invalid, the kernel will safely reject the extension under the assumption that the
             // capability is legitimately unsupported.
-            let cap = unsafe { transmute(request.check_extension().extension) };
+            let cap = unsafe { transmute::<u32, kvm::Cap>(request.check_extension().extension) };
             response.mut_check_extension().has_extension = vm.check_extension(cap);
             Ok(())
         } else if request.has_reserve_range() {
diff --git a/src/crosvm/sys/linux.rs b/src/crosvm/sys/linux.rs
index abf6150aa..19233971b 100644
--- a/src/crosvm/sys/linux.rs
+++ b/src/crosvm/sys/linux.rs
@@ -29,11 +29,12 @@ use std::collections::HashMap;
 use std::collections::HashSet;
 use std::convert::TryInto;
 use std::ffi::CString;
+#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+use std::fs::create_dir_all;
 use std::fs::File;
 use std::fs::OpenOptions;
 #[cfg(feature = "registered_events")]
 use std::hash::Hash;
-use std::io::prelude::*;
 use std::io::stdin;
 use std::iter;
 use std::mem;
@@ -42,6 +43,9 @@ use std::ops::RangeInclusive;
 use std::os::unix::prelude::OpenOptionsExt;
 use std::os::unix::process::ExitStatusExt;
 use std::path::Path;
+#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+use std::path::PathBuf;
+#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
 use std::process;
 #[cfg(feature = "registered_events")]
 use std::rc::Rc;
@@ -219,21 +223,13 @@ fn create_virtio_devices(
     cfg: &Config,
     vm: &mut impl VmArch,
     resources: &mut SystemAllocator,
+    add_control_tube: &mut impl FnMut(AnyControlTube),
     #[cfg_attr(not(feature = "gpu"), allow(unused_variables))] vm_evt_wrtube: &SendTube,
-    #[cfg(feature = "balloon")] balloon_device_tube: Option<Tube>,
     #[cfg(feature = "balloon")] balloon_inflate_tube: Option<Tube>,
-    #[cfg(feature = "balloon")] init_balloon_size: u64,
-    #[cfg(feature = "balloon")] dynamic_mapping_device_tube: Option<Tube>,
-    disk_device_tubes: &mut Vec<Tube>,
-    pmem_device_tubes: &mut Vec<Tube>,
-    pmem_ext2_mem_clients: &mut Vec<VmMemoryClient>,
-    fs_device_tubes: &mut Vec<Tube>,
     worker_process_pids: &mut BTreeSet<Pid>,
-    #[cfg(feature = "gpu")] gpu_control_tube: Tube,
     #[cfg(feature = "gpu")] render_server_fd: Option<SafeDescriptor>,
     #[cfg(feature = "gpu")] has_vfio_gfx_device: bool,
     #[cfg(feature = "registered_events")] registered_evt_q: &SendTube,
-    #[cfg(feature = "pvclock")] pvclock_device_tube: Option<Tube>,
 ) -> DeviceResult<Vec<VirtioDeviceStub>> {
     let mut devs = Vec::new();
 
@@ -359,10 +355,13 @@ fn create_virtio_devices(
                 event_devices.push(EventDevice::keyboard(event_device_socket));
             }
 
+            let (gpu_control_host_tube, gpu_control_device_tube) =
+                Tube::pair().context("failed to create gpu tube")?;
+            add_control_tube(DeviceControlTube::Gpu(gpu_control_host_tube).into());
             devs.push(create_gpu_device(
                 cfg,
                 vm_evt_wrtube,
-                gpu_control_tube,
+                gpu_control_device_tube,
                 resource_bridges,
                 render_server_fd,
                 has_vfio_gfx_device,
@@ -371,16 +370,19 @@ fn create_virtio_devices(
         }
     }
 
-    for (_, param) in cfg.serial_parameters.iter().filter(|(_k, v)| {
-        v.hardware == SerialHardware::VirtioConsole
-            || v.hardware == SerialHardware::LegacyVirtioConsole
-    }) {
+    for (_, param) in cfg
+        .serial_parameters
+        .iter()
+        .filter(|(_k, v)| v.hardware == SerialHardware::VirtioConsole)
+    {
         let dev = param.create_virtio_device_and_jail(cfg.protection_type, &cfg.jail_config)?;
         devs.push(dev);
     }
 
     for disk in &cfg.disks {
-        let disk_config = DiskConfig::new(disk, Some(disk_device_tubes.remove(0)));
+        let (disk_host_tube, disk_device_tube) = Tube::pair().context("failed to create tube")?;
+        add_control_tube(DeviceControlTube::Disk(disk_host_tube).into());
+        let disk_config = DiskConfig::new(disk, Some(disk_device_tube));
         devs.push(
             disk_config.create_virtio_device_and_jail(cfg.protection_type, &cfg.jail_config)?,
         );
@@ -394,7 +396,8 @@ fn create_virtio_devices(
     }
 
     for (index, pmem_disk) in cfg.pmems.iter().enumerate() {
-        let pmem_device_tube = pmem_device_tubes.remove(0);
+        let (pmem_host_tube, pmem_device_tube) = Tube::pair().context("failed to create tube")?;
+        add_control_tube(TaggedControlTube::VmMsync(pmem_host_tube).into());
         devs.push(create_pmem_device(
             cfg.protection_type,
             &cfg.jail_config,
@@ -407,8 +410,20 @@ fn create_virtio_devices(
     }
 
     for (index, pmem_ext2) in cfg.pmem_ext2.iter().enumerate() {
-        let pmem_device_tube = pmem_device_tubes.remove(0);
-        let vm_memory_client = pmem_ext2_mem_clients.remove(0);
+        // Prepare a `VmMemoryClient` for pmem-ext2 device to send a request for mmap() and memory
+        // registeration.
+        let (pmem_ext2_host_tube, pmem_ext2_device_tube) =
+            Tube::pair().context("failed to create tube")?;
+        let vm_memory_client = VmMemoryClient::new(pmem_ext2_device_tube);
+        add_control_tube(
+            VmMemoryTube {
+                tube: pmem_ext2_host_tube,
+                expose_with_viommu: false,
+            }
+            .into(),
+        );
+        let (pmem_host_tube, pmem_device_tube) = Tube::pair().context("failed to create tube")?;
+        add_control_tube(TaggedControlTube::VmMsync(pmem_host_tube).into());
         devs.push(create_pmem_ext2_device(
             cfg.protection_type,
             &cfg.jail_config,
@@ -426,7 +441,11 @@ fn create_virtio_devices(
     }
 
     #[cfg(feature = "pvclock")]
-    if let Some(suspend_tube) = pvclock_device_tube {
+    if cfg.pvclock {
+        // pvclock gets a tube for handling suspend/resume requests from the main thread.
+        let (host_suspend_tube, suspend_tube) = Tube::pair().context("failed to create tube")?;
+        add_control_tube(DeviceControlTube::PvClock(host_suspend_tube).into());
+
         let frequency: u64;
         #[cfg(target_arch = "x86_64")]
         {
@@ -488,6 +507,7 @@ fn create_virtio_devices(
     let mut single_touch_idx = 0;
     let mut trackpad_idx = 0;
     let mut multi_touch_trackpad_idx = 0;
+    let mut custom_idx = 0;
     for input in &cfg.virtio_input {
         let input_dev = match input {
             InputDeviceOption::Evdev { path } => {
@@ -625,24 +645,67 @@ fn create_virtio_devices(
                 multi_touch_trackpad_idx += 1;
                 dev
             }
+            InputDeviceOption::Custom { path, config_path } => {
+                let dev = create_custom_device(
+                    cfg.protection_type,
+                    &cfg.jail_config,
+                    path.as_path(),
+                    custom_idx,
+                    config_path.clone(),
+                )?;
+                custom_idx += 1;
+                dev
+            }
         };
         devs.push(input_dev);
     }
 
     #[cfg(feature = "balloon")]
-    if let (Some(balloon_device_tube), Some(dynamic_mapping_device_tube)) =
-        (balloon_device_tube, dynamic_mapping_device_tube)
-    {
+    if cfg.balloon {
+        let balloon_device_tube = if let Some(ref path) = cfg.balloon_control {
+            Tube::new_from_unix_seqpacket(UnixSeqpacket::connect(path).with_context(|| {
+                format!(
+                    "failed to connect to balloon control socket {}",
+                    path.display(),
+                )
+            })?)?
+        } else {
+            // Balloon gets a special socket so balloon requests can be forwarded
+            // from the main process.
+            let (host, device) = Tube::pair().context("failed to create tube")?;
+            add_control_tube(DeviceControlTube::Balloon(host).into());
+            device
+        };
+
         let balloon_features = (cfg.balloon_page_reporting as u64)
             << BalloonFeatures::PageReporting as u64
             | (cfg.balloon_ws_reporting as u64) << BalloonFeatures::WSReporting as u64;
+
+        let init_balloon_size = if let Some(init_memory) = cfg.init_memory {
+            let init_memory_bytes = init_memory.saturating_mul(1024 * 1024);
+            let total_memory_bytes = vm.get_memory().memory_size();
+
+            if init_memory_bytes > total_memory_bytes {
+                bail!(
+                    "initial memory {} cannot be greater than total memory {}",
+                    init_memory,
+                    total_memory_bytes / (1024 * 1024),
+                );
+            }
+
+            // The initial balloon size is the total memory size minus the initial memory size.
+            total_memory_bytes - init_memory_bytes
+        } else {
+            // No --init-mem specified; start with balloon completely deflated.
+            0
+        };
+
         devs.push(create_balloon_device(
             cfg.protection_type,
             &cfg.jail_config,
             balloon_device_tube,
             balloon_inflate_tube,
             init_balloon_size,
-            dynamic_mapping_device_tube,
             balloon_features,
             #[cfg(feature = "registered_events")]
             Some(
@@ -673,6 +736,19 @@ fn create_virtio_devices(
         }
     }
 
+    #[cfg(any(target_os = "android", target_os = "linux"))]
+    #[cfg(feature = "media")]
+    {
+        for v4l2_device in &cfg.v4l2_proxy {
+            devs.push(create_v4l2_device(cfg.protection_type, v4l2_device)?);
+        }
+    }
+
+    #[cfg(feature = "media")]
+    if cfg.simple_media_device {
+        devs.push(create_simple_media_device(cfg.protection_type)?);
+    }
+
     #[cfg(feature = "video-decoder")]
     {
         for (tube, backend) in video_dec_cfg {
@@ -738,7 +814,9 @@ fn create_virtio_devices(
 
         let dev = match kind {
             SharedDirKind::FS => {
-                let device_tube = fs_device_tubes.remove(0);
+                let (host_tube, device_tube) = Tube::pair().context("failed to create tube")?;
+                add_control_tube(TaggedControlTube::Fs(host_tube).into());
+
                 create_fs_device(
                     cfg.protection_type,
                     &cfg.jail_config,
@@ -789,24 +867,13 @@ fn create_devices(
     cfg: &Config,
     vm: &mut impl VmArch,
     resources: &mut SystemAllocator,
+    add_control_tube: &mut impl FnMut(AnyControlTube),
     vm_evt_wrtube: &SendTube,
     iommu_attached_endpoints: &mut BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
-    irq_control_tubes: &mut Vec<Tube>,
-    vm_memory_control_tubes: &mut Vec<VmMemoryTube>,
-    control_tubes: &mut Vec<TaggedControlTube>,
-    #[cfg(feature = "balloon")] balloon_device_tube: Option<Tube>,
-    #[cfg(feature = "balloon")] init_balloon_size: u64,
-    #[cfg(feature = "balloon")] dynamic_mapping_device_tube: Option<Tube>,
-    disk_device_tubes: &mut Vec<Tube>,
-    pmem_device_tubes: &mut Vec<Tube>,
-    pmem_ext2_mem_clients: &mut Vec<VmMemoryClient>,
-    fs_device_tubes: &mut Vec<Tube>,
     #[cfg(feature = "usb")] usb_provider: DeviceProvider,
-    #[cfg(feature = "gpu")] gpu_control_tube: Tube,
     #[cfg(feature = "gpu")] render_server_fd: Option<SafeDescriptor>,
     iova_max_addr: &mut Option<u64>,
     #[cfg(feature = "registered_events")] registered_evt_q: &SendTube,
-    #[cfg(feature = "pvclock")] pvclock_device_tube: Option<Tube>,
     vfio_container_manager: &mut VfioContainerManager,
     // Stores a set of PID of child processes that are suppose to exit cleanly.
     worker_process_pids: &mut BTreeSet<Pid>,
@@ -824,9 +891,7 @@ fn create_devices(
                 &cfg.jail_config,
                 vm,
                 resources,
-                irq_control_tubes,
-                vm_memory_control_tubes,
-                control_tubes,
+                add_control_tube,
                 &vfio_dev.path,
                 false,
                 None,
@@ -900,10 +965,13 @@ fn create_devices(
                 .context("failed to get vfio container")?;
             let (coiommu_host_tube, coiommu_device_tube) =
                 Tube::pair().context("failed to create coiommu tube")?;
-            vm_memory_control_tubes.push(VmMemoryTube {
-                tube: coiommu_host_tube,
-                expose_with_viommu: false,
-            });
+            add_control_tube(
+                VmMemoryTube {
+                    tube: coiommu_host_tube,
+                    expose_with_viommu: false,
+                }
+                .into(),
+            );
             let vcpu_count = cfg.vcpu_count.unwrap_or(1) as u64;
             #[cfg(feature = "balloon")]
             match Tube::pair() {
@@ -935,30 +1003,17 @@ fn create_devices(
         cfg,
         vm,
         resources,
+        add_control_tube,
         vm_evt_wrtube,
         #[cfg(feature = "balloon")]
-        balloon_device_tube,
-        #[cfg(feature = "balloon")]
         balloon_inflate_tube,
-        #[cfg(feature = "balloon")]
-        init_balloon_size,
-        #[cfg(feature = "balloon")]
-        dynamic_mapping_device_tube,
-        disk_device_tubes,
-        pmem_device_tubes,
-        pmem_ext2_mem_clients,
-        fs_device_tubes,
         worker_process_pids,
         #[cfg(feature = "gpu")]
-        gpu_control_tube,
-        #[cfg(feature = "gpu")]
         render_server_fd,
         #[cfg(feature = "gpu")]
         has_vfio_gfx_device,
         #[cfg(feature = "registered_events")]
         registered_evt_q,
-        #[cfg(feature = "pvclock")]
-        pvclock_device_tube,
     )?;
 
     for stub in stubs {
@@ -966,15 +1021,18 @@ fn create_devices(
             VirtioTransportType::Pci => {
                 let (msi_host_tube, msi_device_tube) =
                     Tube::pair().context("failed to create tube")?;
-                irq_control_tubes.push(msi_host_tube);
+                add_control_tube(AnyControlTube::IrqTube(msi_host_tube));
 
                 let shared_memory_tube = if stub.dev.get_shared_memory_region().is_some() {
                     let (host_tube, device_tube) =
                         Tube::pair().context("failed to create shared memory tube")?;
-                    vm_memory_control_tubes.push(VmMemoryTube {
-                        tube: host_tube,
-                        expose_with_viommu: stub.dev.expose_shmem_descriptors_with_viommu(),
-                    });
+                    add_control_tube(
+                        VmMemoryTube {
+                            tube: host_tube,
+                            expose_with_viommu: stub.dev.expose_shmem_descriptors_with_viommu(),
+                        }
+                        .into(),
+                    );
                     Some(device_tube)
                 } else {
                     None
@@ -982,14 +1040,17 @@ fn create_devices(
 
                 let (ioevent_host_tube, ioevent_device_tube) =
                     Tube::pair().context("failed to create ioevent tube")?;
-                vm_memory_control_tubes.push(VmMemoryTube {
-                    tube: ioevent_host_tube,
-                    expose_with_viommu: false,
-                });
+                add_control_tube(
+                    VmMemoryTube {
+                        tube: ioevent_host_tube,
+                        expose_with_viommu: false,
+                    }
+                    .into(),
+                );
 
                 let (host_tube, device_tube) =
                     Tube::pair().context("failed to create device control tube")?;
-                control_tubes.push(TaggedControlTube::Vm(host_tube));
+                add_control_tube(TaggedControlTube::Vm(host_tube).into());
 
                 let dev = VirtioPciDevice::new(
                     vm.get_memory().clone(),
@@ -1127,7 +1188,7 @@ impl HotPlugStub {
 /// find the empty bus and create a total virtual pcie rp
 fn create_pure_virtual_pcie_root_port(
     sys_allocator: &mut SystemAllocator,
-    irq_control_tubes: &mut Vec<Tube>,
+    add_control_tube: &mut impl FnMut(AnyControlTube),
     devices: &mut Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>,
     hp_bus_count: u8,
 ) -> Result<HotPlugStub> {
@@ -1147,7 +1208,7 @@ fn create_pure_virtual_pcie_root_port(
             .pme_notify_devs
             .insert(i, pcie_root_port.clone() as Arc<Mutex<dyn PmeNotify>>);
         let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
-        irq_control_tubes.push(msi_host_tube);
+        add_control_tube(AnyControlTube::IrqTube(msi_host_tube));
         let pci_bridge = Box::new(PciBridge::new(pcie_root_port.clone(), msi_device_tube));
         // no ipc is used if the root port disables hotplug
         devices.push((pci_bridge, None));
@@ -1165,7 +1226,7 @@ fn create_pure_virtual_pcie_root_port(
             pcie_root_port.clone() as Arc<Mutex<dyn PmeNotify>>,
         );
         let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
-        irq_control_tubes.push(msi_host_tube);
+        add_control_tube(AnyControlTube::IrqTube(msi_host_tube));
         let pci_bridge = Box::new(PciBridge::new(pcie_root_port.clone(), msi_device_tube));
 
         hp_stub.iommu_bus_ranges.push(RangeInclusive::new(
@@ -1268,58 +1329,118 @@ fn setup_vm_components(cfg: &Config) -> Result<VmComponents> {
     };
 
     #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
-    if cfg.virt_cpufreq {
+    let mut vcpu_domain_paths = BTreeMap::new();
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+    let mut vcpu_domains = BTreeMap::new();
+
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+    if cfg.virt_cpufreq || cfg.virt_cpufreq_v2 {
         if !cfg.cpu_frequencies_khz.is_empty() {
             cpu_frequencies = cfg.cpu_frequencies_khz.clone();
         } else {
-            let host_cpu_frequencies = Arch::get_host_cpu_frequencies_khz()?;
-
-            for cpu_id in 0..cfg.vcpu_count.unwrap_or(1) {
-                let vcpu_affinity = match cfg.vcpu_affinity.clone() {
-                    Some(VcpuAffinity::Global(v)) => v,
-                    Some(VcpuAffinity::PerVcpu(mut m)) => m.remove(&cpu_id).unwrap_or_default(),
-                    None => {
-                        panic!("There must be some vcpu_affinity setting with VirtCpufreq enabled!")
-                    }
-                };
+            match Arch::get_host_cpu_frequencies_khz() {
+                Ok(host_cpu_frequencies) => {
+                    for cpu_id in 0..cfg.vcpu_count.unwrap_or(1) {
+                        let vcpu_affinity = match cfg.vcpu_affinity.clone() {
+                            Some(VcpuAffinity::Global(v)) => v,
+                            Some(VcpuAffinity::PerVcpu(mut m)) => {
+                                m.remove(&cpu_id).unwrap_or_default()
+                            }
+                            None => {
+                                panic!("There must be some vcpu_affinity setting with VirtCpufreq enabled!")
+                            }
+                        };
 
-                // Check that the physical CPUs that the vCPU is affined to all share the same
-                // frequency domain.
-                if let Some(freq_domain) = host_cpu_frequencies.get(&vcpu_affinity[0]) {
-                    for cpu in vcpu_affinity.iter() {
-                        if let Some(frequencies) = host_cpu_frequencies.get(cpu) {
-                            if frequencies != freq_domain {
-                                panic!("Affined CPUs do not share a frequency domain!");
+                        // Check that the physical CPUs that the vCPU is affined to all share the
+                        // same frequency domain.
+                        if let Some(freq_domain) = host_cpu_frequencies.get(&vcpu_affinity[0]) {
+                            for cpu in vcpu_affinity.iter() {
+                                if let Some(frequencies) = host_cpu_frequencies.get(cpu) {
+                                    if frequencies != freq_domain {
+                                        panic!("Affined CPUs do not share a frequency domain!");
+                                    }
+                                }
                             }
+                            cpu_frequencies.insert(cpu_id, freq_domain.clone());
+                        } else {
+                            panic!("No frequency domain for cpu:{}", cpu_id);
                         }
                     }
-                    cpu_frequencies.insert(cpu_id, freq_domain.clone());
-                } else {
-                    panic!("No frequency domain for cpu:{}", cpu_id);
+                }
+                Err(e) => {
+                    warn!("Unable to get host cpu frequencies {:#}", e);
                 }
             }
         }
-        let mut max_freqs = Vec::new();
 
-        for (_cpu, frequencies) in cpu_frequencies.iter() {
-            max_freqs.push(*frequencies.iter().max().ok_or(Error::new(libc::EINVAL))?)
-        }
+        if !cpu_frequencies.is_empty() {
+            let mut max_freqs = Vec::new();
 
-        let host_max_freqs = Arch::get_host_cpu_max_freq_khz()?;
-        let largest_host_max_freq = host_max_freqs
-            .values()
-            .max()
-            .ok_or(Error::new(libc::EINVAL))?;
-
-        for (cpu_id, max_freq) in max_freqs.iter().enumerate() {
-            let normalized_cpu_capacity = (u64::from(*cpu_capacity.get(&cpu_id).unwrap())
-                * u64::from(*max_freq))
-            .checked_div(u64::from(*largest_host_max_freq))
-            .ok_or(Error::new(libc::EINVAL))?;
-            normalized_cpu_capacities.insert(
-                cpu_id,
-                u32::try_from(normalized_cpu_capacity).map_err(|_| Error::new(libc::EINVAL))?,
-            );
+            for (_cpu, frequencies) in cpu_frequencies.iter() {
+                max_freqs.push(*frequencies.iter().max().ok_or(Error::new(libc::EINVAL))?)
+            }
+
+            let host_max_freqs = Arch::get_host_cpu_max_freq_khz()?;
+            let largest_host_max_freq = host_max_freqs
+                .values()
+                .max()
+                .ok_or(Error::new(libc::EINVAL))?;
+
+            for (cpu_id, max_freq) in max_freqs.iter().enumerate() {
+                let normalized_cpu_capacity = (u64::from(*cpu_capacity.get(&cpu_id).unwrap())
+                    * u64::from(*max_freq))
+                .checked_div(u64::from(*largest_host_max_freq))
+                .ok_or(Error::new(libc::EINVAL))?;
+                normalized_cpu_capacities.insert(
+                    cpu_id,
+                    u32::try_from(normalized_cpu_capacity).map_err(|_| Error::new(libc::EINVAL))?,
+                );
+            }
+
+            if !cfg.cpu_freq_domains.is_empty() {
+                let cgroup_path = cfg
+                    .vcpu_cgroup_path
+                    .clone()
+                    .context("cpu_freq_domains requires vcpu_cgroup_path")?;
+
+                if !cgroup_path.join("cgroup.controllers").exists() {
+                    panic!("CGroupsV2 must be enabled for cpu freq domain support!");
+                }
+
+                // Assign parent crosvm process to top level cgroup
+                let cgroup_procs_path = cgroup_path.join("cgroup.procs");
+                std::fs::write(
+                    cgroup_procs_path.clone(),
+                    process::id().to_string().as_bytes(),
+                )
+                .with_context(|| {
+                    format!(
+                        "failed to create vcpu-cgroup-path {}",
+                        cgroup_procs_path.display(),
+                    )
+                })?;
+
+                for (freq_domain_idx, cpus) in cfg.cpu_freq_domains.iter().enumerate() {
+                    let vcpu_domain_path =
+                        cgroup_path.join(format!("vcpu-domain{}", freq_domain_idx));
+                    // Create subtree for domain
+                    create_dir_all(&vcpu_domain_path)?;
+
+                    // Set vcpu_domain cgroup type as 'threaded' to get thread level granularity
+                    // controls
+                    let cgroup_type_path = cgroup_path.join(vcpu_domain_path.join("cgroup.type"));
+                    std::fs::write(cgroup_type_path.clone(), b"threaded").with_context(|| {
+                        format!(
+                            "failed to create vcpu-cgroup-path {}",
+                            cgroup_type_path.display(),
+                        )
+                    })?;
+                    for core_idx in cpus.iter() {
+                        vcpu_domain_paths.insert(*core_idx, vcpu_domain_path.clone());
+                        vcpu_domains.insert(*core_idx, freq_domain_idx as u32);
+                    }
+                }
+            }
         }
     }
 
@@ -1339,6 +1460,10 @@ fn setup_vm_components(cfg: &Config) -> Result<VmComponents> {
         vcpu_count: cfg.vcpu_count.unwrap_or(1),
         vcpu_affinity: cfg.vcpu_affinity.clone(),
         #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+        vcpu_domains,
+        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+        vcpu_domain_paths,
+        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
         cpu_frequencies,
         fw_cfg_parameters: cfg.fw_cfg_parameters.clone(),
         cpu_clusters,
@@ -1376,8 +1501,6 @@ fn setup_vm_components(cfg: &Config) -> Result<VmComponents> {
             .collect::<Result<Vec<SDT>>>()?,
         rt_cpus: cfg.rt_cpus.clone(),
         delay_rt: cfg.delay_rt,
-        #[cfg(feature = "gdb")]
-        gdb: None,
         no_i8042: cfg.no_i8042,
         no_rtc: cfg.no_rtc,
         #[cfg(target_arch = "x86_64")]
@@ -1387,12 +1510,13 @@ fn setup_vm_components(cfg: &Config) -> Result<VmComponents> {
         #[cfg(target_arch = "x86_64")]
         force_s2idle: cfg.force_s2idle,
         pvm_fw: pvm_fw_image,
-        #[cfg(target_arch = "x86_64")]
-        pcie_ecam: cfg.pcie_ecam,
-        #[cfg(target_arch = "x86_64")]
-        pci_low_start: cfg.pci_low_start,
+        pci_config: cfg.pci_config,
         dynamic_power_coefficient: cfg.dynamic_power_coefficient.clone(),
         boot_cpu: cfg.boot_cpu,
+        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+        virt_cpufreq_v2: cfg.virt_cpufreq_v2,
+        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+        sve_config: cfg.sve.unwrap_or_default(),
     })
 }
 
@@ -1450,9 +1574,10 @@ fn punch_holes_in_guest_mem_layout_for_mappings(
 fn create_guest_memory(
     cfg: &Config,
     components: &VmComponents,
+    arch_memory_layout: &<Arch as LinuxArch>::ArchMemoryLayout,
     hypervisor: &impl Hypervisor,
 ) -> Result<GuestMemory> {
-    let guest_mem_layout = Arch::guest_memory_layout(components, hypervisor)
+    let guest_mem_layout = Arch::guest_memory_layout(components, arch_memory_layout, hypervisor)
         .context("failed to create guest memory layout")?;
 
     let guest_mem_layout =
@@ -1494,7 +1619,9 @@ fn run_gz(device_path: Option<&Path>, cfg: Config, components: VmComponents) ->
     let gzvm = Geniezone::new_with_path(device_path)
         .with_context(|| format!("failed to open GenieZone device {}", device_path.display()))?;
 
-    let guest_mem = create_guest_memory(&cfg, &components, &gzvm)?;
+    let arch_memory_layout =
+        Arch::arch_memory_layout(&components).context("failed to create arch memory layout")?;
+    let guest_mem = create_guest_memory(&cfg, &components, &arch_memory_layout, &gzvm)?;
 
     #[cfg(feature = "swap")]
     let swap_controller = if let Some(swap_dir) = cfg.swap_dir.as_ref() {
@@ -1529,6 +1656,7 @@ fn run_gz(device_path: Option<&Path>, cfg: Config, components: VmComponents) ->
     run_vm::<GeniezoneVcpu, GeniezoneVm>(
         cfg,
         components,
+        &arch_memory_layout,
         vm,
         &mut irq_chip,
         ioapic_host_tube,
@@ -1549,7 +1677,9 @@ fn run_kvm(device_path: Option<&Path>, cfg: Config, components: VmComponents) ->
     let kvm = Kvm::new_with_path(device_path)
         .with_context(|| format!("failed to open KVM device {}", device_path.display()))?;
 
-    let guest_mem = create_guest_memory(&cfg, &components, &kvm)?;
+    let arch_memory_layout =
+        Arch::arch_memory_layout(&components).context("failed to create arch memory layout")?;
+    let guest_mem = create_guest_memory(&cfg, &components, &arch_memory_layout, &kvm)?;
 
     #[cfg(feature = "swap")]
     let swap_controller = if let Some(swap_dir) = cfg.swap_dir.as_ref() {
@@ -1570,6 +1700,9 @@ fn run_kvm(device_path: Option<&Path>, cfg: Config, components: VmComponents) ->
     }
 
     // Check that the VM was actually created in protected mode as expected.
+    // This check is only needed on aarch64. On x86_64, protected VM creation will fail
+    // if protected mode is not supported.
+    #[cfg(not(target_arch = "x86_64"))]
     if cfg.protection_type.isolates_memory() && !vm.check_capability(VmCap::Protected) {
         bail!("Failed to create protected VM");
     }
@@ -1627,6 +1760,7 @@ fn run_kvm(device_path: Option<&Path>, cfg: Config, components: VmComponents) ->
     run_vm::<KvmVcpu, KvmVm>(
         cfg,
         components,
+        &arch_memory_layout,
         vm,
         irq_chip.as_mut(),
         ioapic_host_tube,
@@ -1650,7 +1784,9 @@ fn run_gunyah(
     let gunyah = Gunyah::new_with_path(device_path)
         .with_context(|| format!("failed to open Gunyah device {}", device_path.display()))?;
 
-    let guest_mem = create_guest_memory(&cfg, &components, &gunyah)?;
+    let arch_memory_layout =
+        Arch::arch_memory_layout(&components).context("failed to create arch memory layout")?;
+    let guest_mem = create_guest_memory(&cfg, &components, &arch_memory_layout, &gunyah)?;
 
     #[cfg(feature = "swap")]
     let swap_controller = if let Some(swap_dir) = cfg.swap_dir.as_ref() {
@@ -1674,6 +1810,7 @@ fn run_gunyah(
     run_vm::<GunyahVcpu, GunyahVm>(
         cfg,
         components,
+        &arch_memory_layout,
         vm,
         &mut GunyahIrqChip::new(vm_clone)?,
         None,
@@ -1747,6 +1884,7 @@ pub fn run_config(cfg: Config) -> Result<ExitState> {
 fn run_vm<Vcpu, V>(
     cfg: Config,
     #[allow(unused_mut)] mut components: VmComponents,
+    arch_memory_layout: &<Arch as LinuxArch>::ArchMemoryLayout,
     mut vm: V,
     irq_chip: &mut dyn IrqChipArch,
     ioapic_host_tube: Option<Tube>,
@@ -1792,10 +1930,6 @@ where
         None
     };
 
-    #[cfg(feature = "gpu")]
-    let (gpu_control_host_tube, gpu_control_device_tube) =
-        Tube::pair().context("failed to create gpu tube")?;
-
     #[cfg(feature = "usb")]
     let (usb_control_tube, usb_provider) =
         DeviceProvider::new().context("failed to create usb provider")?;
@@ -1812,90 +1946,11 @@ where
         None => None,
     };
 
-    let mut control_tubes = Vec::new();
-    let mut irq_control_tubes = Vec::new();
-    let mut vm_memory_control_tubes = Vec::new();
-
-    #[cfg(feature = "gdb")]
-    if let Some(port) = cfg.gdb {
-        // GDB needs a control socket to interrupt vcpus.
-        let (gdb_host_tube, gdb_control_tube) = Tube::pair().context("failed to create tube")?;
-        control_tubes.push(TaggedControlTube::Vm(gdb_host_tube));
-        components.gdb = Some((port, gdb_control_tube));
-    }
-
-    #[cfg(feature = "balloon")]
-    let (balloon_host_tube, balloon_device_tube) = if cfg.balloon {
-        if let Some(ref path) = cfg.balloon_control {
-            (
-                None,
-                Some(Tube::new_from_unix_seqpacket(
-                    UnixSeqpacket::connect(path).with_context(|| {
-                        format!(
-                            "failed to connect to balloon control socket {}",
-                            path.display(),
-                        )
-                    })?,
-                )?),
-            )
-        } else {
-            // Balloon gets a special socket so balloon requests can be forwarded
-            // from the main process.
-            let (host, device) = Tube::pair().context("failed to create tube")?;
-            (Some(host), Some(device))
-        }
-    } else {
-        (None, None)
-    };
-
-    // The balloon device also needs a tube to communicate back to the main process to
-    // handle remapping memory dynamically.
-    #[cfg(feature = "balloon")]
-    let dynamic_mapping_device_tube = if cfg.balloon {
-        let (dynamic_mapping_host_tube, dynamic_mapping_device_tube) =
-            Tube::pair().context("failed to create tube")?;
-        vm_memory_control_tubes.push(VmMemoryTube {
-            tube: dynamic_mapping_host_tube,
-            expose_with_viommu: false,
-        });
-        Some(dynamic_mapping_device_tube)
-    } else {
-        None
-    };
-
-    // Create one control socket per disk.
-    let mut disk_device_tubes = Vec::new();
-    let mut disk_host_tubes = Vec::new();
-    let disk_count = cfg.disks.len();
-    for _ in 0..disk_count {
-        let (disk_host_tub, disk_device_tube) = Tube::pair().context("failed to create tube")?;
-        disk_host_tubes.push(disk_host_tub);
-        disk_device_tubes.push(disk_device_tube);
-    }
-
-    let mut pmem_device_tubes = Vec::new();
-    let pmem_count = cfg.pmems.len() + cfg.pmem_ext2.len();
-    for _ in 0..pmem_count {
-        let (pmem_host_tube, pmem_device_tube) = Tube::pair().context("failed to create tube")?;
-        pmem_device_tubes.push(pmem_device_tube);
-        control_tubes.push(TaggedControlTube::VmMsync(pmem_host_tube));
-    }
-    let mut pmem_ext2_mem_client = Vec::new();
-    for _ in 0..cfg.pmem_ext2.len() {
-        let (pmem_ext2_host_tube, pmem_ext2_device_tube) =
-            Tube::pair().context("failed to create tube")?;
-        // Prepare two communication channels for pmem-ext2 device
-        // - pmem_ext2_mem_client: To send a request for mmap() and memory registeration.
-        // - vm_memory_control_tubes: To receive a memory slot number once the memory is registered.
-        pmem_ext2_mem_client.push(VmMemoryClient::new(pmem_ext2_device_tube));
-        vm_memory_control_tubes.push(VmMemoryTube {
-            tube: pmem_ext2_host_tube,
-            expose_with_viommu: false,
-        });
-    }
+    let mut all_control_tubes = Vec::new();
+    let mut add_control_tube = |t| all_control_tubes.push(t);
 
     if let Some(ioapic_host_tube) = ioapic_host_tube {
-        irq_control_tubes.push(ioapic_host_tube);
+        add_control_tube(AnyControlTube::IrqTube(ioapic_host_tube));
     }
 
     let battery = if cfg.battery_config.is_some() {
@@ -1927,24 +1982,12 @@ where
         (cfg.battery_config.as_ref().map(|c| c.type_), None)
     };
 
-    let fs_count = cfg
-        .shared_dirs
-        .iter()
-        .filter(|sd| sd.kind == SharedDirKind::FS)
-        .count();
-    let mut fs_device_tubes = Vec::with_capacity(fs_count);
-    for _ in 0..fs_count {
-        let (fs_host_tube, fs_device_tube) = Tube::pair().context("failed to create tube")?;
-        control_tubes.push(TaggedControlTube::Fs(fs_host_tube));
-        fs_device_tubes.push(fs_device_tube);
-    }
-
     let (vm_evt_wrtube, vm_evt_rdtube) =
         Tube::directional_pair().context("failed to create vm event tube")?;
 
     let pstore_size = components.pstore.as_ref().map(|pstore| pstore.size as u64);
     let mut sys_allocator = SystemAllocator::new(
-        Arch::get_system_allocator_config(&vm),
+        Arch::get_system_allocator_config(&vm, arch_memory_layout),
         pstore_size,
         &cfg.mmio_address_ranges,
     )
@@ -1974,29 +2017,12 @@ where
             (None, None)
         };
 
-    #[cfg(feature = "balloon")]
-    let init_balloon_size = components
-        .memory_size
-        .checked_sub(cfg.init_memory.map_or(components.memory_size, |m| {
-            m.checked_mul(1024 * 1024).unwrap_or(u64::MAX)
-        }))
-        .context("failed to calculate init balloon size")?;
-
     let mut iommu_attached_endpoints: BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>> =
         BTreeMap::new();
     let mut iova_max_addr: Option<u64> = None;
 
     let mut vfio_container_manager = VfioContainerManager::new();
 
-    // pvclock gets a tube for handling suspend/resume requests from the main thread.
-    #[cfg(feature = "pvclock")]
-    let (pvclock_host_tube, pvclock_device_tube) = if cfg.pvclock {
-        let (host, device) = Tube::pair().context("failed to create tube")?;
-        (Some(host), Some(device))
-    } else {
-        (None, None)
-    };
-
     #[cfg(feature = "registered_events")]
     let (reg_evt_wrtube, reg_evt_rdtube) =
         Tube::directional_pair().context("failed to create registered event tube")?;
@@ -2007,32 +2033,16 @@ where
         &cfg,
         &mut vm,
         &mut sys_allocator,
+        &mut add_control_tube,
         &vm_evt_wrtube,
         &mut iommu_attached_endpoints,
-        &mut irq_control_tubes,
-        &mut vm_memory_control_tubes,
-        &mut control_tubes,
-        #[cfg(feature = "balloon")]
-        balloon_device_tube,
-        #[cfg(feature = "balloon")]
-        init_balloon_size,
-        #[cfg(feature = "balloon")]
-        dynamic_mapping_device_tube,
-        &mut disk_device_tubes,
-        &mut pmem_device_tubes,
-        &mut pmem_ext2_mem_client,
-        &mut fs_device_tubes,
         #[cfg(feature = "usb")]
         usb_provider,
         #[cfg(feature = "gpu")]
-        gpu_control_device_tube,
-        #[cfg(feature = "gpu")]
         render_server_fd,
         &mut iova_max_addr,
         #[cfg(feature = "registered_events")]
         &reg_evt_wrtube,
-        #[cfg(feature = "pvclock")]
-        pvclock_device_tube,
         &mut vfio_container_manager,
         &mut worker_process_pids,
     )?;
@@ -2047,7 +2057,7 @@ where
     #[cfg(target_arch = "x86_64")]
     let hp_stub = create_pure_virtual_pcie_root_port(
         &mut sys_allocator,
-        &mut irq_control_tubes,
+        &mut add_control_tube,
         &mut devices,
         pci_hotplug_slots.unwrap_or(1),
     )?;
@@ -2130,16 +2140,19 @@ where
         )?;
 
         let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
-        irq_control_tubes.push(msi_host_tube);
+        add_control_tube(AnyControlTube::IrqTube(msi_host_tube));
         let (ioevent_host_tube, ioevent_device_tube) =
             Tube::pair().context("failed to create ioevent tube")?;
-        vm_memory_control_tubes.push(VmMemoryTube {
-            tube: ioevent_host_tube,
-            expose_with_viommu: false,
-        });
+        add_control_tube(
+            VmMemoryTube {
+                tube: ioevent_host_tube,
+                expose_with_viommu: false,
+            }
+            .into(),
+        );
         let (host_tube, device_tube) =
             Tube::pair().context("failed to create device control tube")?;
-        control_tubes.push(TaggedControlTube::Vm(host_tube));
+        add_control_tube(TaggedControlTube::Vm(host_tube).into());
         let mut dev = VirtioPciDevice::new(
             vm.get_memory().clone(),
             iommu_dev.dev,
@@ -2198,8 +2211,12 @@ where
         })
         .collect::<Result<Vec<DtbOverlay>>>()?;
 
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+    let vcpu_domain_paths = components.vcpu_domain_paths.clone();
+
     let mut linux = Arch::build_vm::<V, Vcpu>(
         components,
+        arch_memory_layout,
         &vm_evt_wrtube,
         &mut sys_allocator,
         &cfg.serial_parameters,
@@ -2221,11 +2238,12 @@ where
         guest_suspended_cvar.clone(),
         dt_overlays,
         cfg.fdt_position,
+        cfg.no_pmu,
     )
     .context("the architecture failed to build the vm")?;
 
     for tube in linux.vm_request_tubes.drain(..) {
-        control_tubes.push(TaggedControlTube::Vm(tube));
+        add_control_tube(TaggedControlTube::Vm(tube).into());
     }
 
     #[cfg(target_arch = "x86_64")]
@@ -2258,10 +2276,13 @@ where
 
         let (hp_vm_mem_host_tube, hp_vm_mem_worker_tube) =
             Tube::pair().context("failed to create tube")?;
-        vm_memory_control_tubes.push(VmMemoryTube {
-            tube: hp_vm_mem_host_tube,
-            expose_with_viommu: false,
-        });
+        add_control_tube(
+            VmMemoryTube {
+                tube: hp_vm_mem_host_tube,
+                expose_with_viommu: false,
+            }
+            .into(),
+        );
 
         let supports_readonly_mapping = linux.vm.supports_readonly_mapping();
         let pci_root = linux.root_config.clone();
@@ -2285,14 +2306,7 @@ where
         sys_allocator,
         cfg,
         control_server_socket,
-        irq_control_tubes,
-        vm_memory_control_tubes,
-        control_tubes,
-        #[cfg(feature = "balloon")]
-        balloon_host_tube,
-        &disk_host_tubes,
-        #[cfg(feature = "gpu")]
-        gpu_control_host_tube,
+        all_control_tubes,
         #[cfg(feature = "usb")]
         usb_control_tube,
         vm_evt_rdtube,
@@ -2312,11 +2326,11 @@ where
         #[cfg(feature = "registered_events")]
         reg_evt_rdtube,
         guest_suspended_cvar,
-        #[cfg(feature = "pvclock")]
-        pvclock_host_tube,
         metrics_recv,
         vfio_container_manager,
         worker_process_pids,
+        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+        vcpu_domain_paths,
     )
 }
 
@@ -2422,9 +2436,7 @@ fn add_hotplug_device<V: VmArch, Vcpu: VcpuArch>(
     linux: &mut RunnableLinuxVm<V, Vcpu>,
     sys_allocator: &mut SystemAllocator,
     cfg: &Config,
-    irq_control_tubes: &mut Vec<Tube>,
-    vm_memory_control_tubes: &mut Vec<VmMemoryTube>,
-    control_tubes: &mut Vec<TaggedControlTube>,
+    add_control_tube: &mut impl FnMut(AnyControlTube),
     hp_control_tube: &mpsc::Sender<PciRootCommand>,
     iommu_host_tube: Option<&Tube>,
     device: &HotPlugDeviceInfo,
@@ -2438,9 +2450,9 @@ fn add_hotplug_device<V: VmArch, Vcpu: VcpuArch>(
     let (hotplug_key, pci_address) = match device.device_type {
         HotPlugDeviceType::UpstreamPort | HotPlugDeviceType::DownstreamPort => {
             let (vm_host_tube, vm_device_tube) = Tube::pair().context("failed to create tube")?;
-            control_tubes.push(TaggedControlTube::Vm(vm_host_tube));
+            add_control_tube(TaggedControlTube::Vm(vm_host_tube).into());
             let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
-            irq_control_tubes.push(msi_host_tube);
+            add_control_tube(AnyControlTube::IrqTube(msi_host_tube));
             let pcie_host = PcieHostPort::new(device.path.as_path(), vm_device_tube)?;
             let (hotplug_key, pci_bridge) = match device.device_type {
                 HotPlugDeviceType::UpstreamPort => {
@@ -2491,9 +2503,7 @@ fn add_hotplug_device<V: VmArch, Vcpu: VcpuArch>(
                 &cfg.jail_config,
                 &linux.vm,
                 sys_allocator,
-                irq_control_tubes,
-                vm_memory_control_tubes,
-                control_tubes,
+                add_control_tube,
                 &device.path,
                 true,
                 None,
@@ -2556,22 +2566,23 @@ fn add_hotplug_device<V: VmArch, Vcpu: VcpuArch>(
 fn add_hotplug_net<V: VmArch, Vcpu: VcpuArch>(
     linux: &mut RunnableLinuxVm<V, Vcpu>,
     sys_allocator: &mut SystemAllocator,
-    irq_control_tubes: &mut Vec<Tube>,
-    vm_memory_control_tubes: &mut Vec<VmMemoryTube>,
-    vm_control_tubes: &mut Vec<TaggedControlTube>,
+    add_control_tube: &mut impl FnMut(AnyControlTube),
     hotplug_manager: &mut PciHotPlugManager,
     net_param: NetParameters,
 ) -> Result<u8> {
     let (msi_host_tube, msi_device_tube) = Tube::pair().context("create tube")?;
-    irq_control_tubes.push(msi_host_tube);
+    add_control_tube(AnyControlTube::IrqTube(msi_host_tube));
     let (ioevent_host_tube, ioevent_device_tube) = Tube::pair().context("create tube")?;
     let ioevent_vm_memory_client = VmMemoryClient::new(ioevent_device_tube);
-    vm_memory_control_tubes.push(VmMemoryTube {
-        tube: ioevent_host_tube,
-        expose_with_viommu: false,
-    });
+    add_control_tube(
+        VmMemoryTube {
+            tube: ioevent_host_tube,
+            expose_with_viommu: false,
+        }
+        .into(),
+    );
     let (vm_control_host_tube, vm_control_device_tube) = Tube::pair().context("create tube")?;
-    vm_control_tubes.push(TaggedControlTube::Vm(vm_control_host_tube));
+    add_control_tube(TaggedControlTube::Vm(vm_control_host_tube).into());
     let net_carrier_device = NetResourceCarrier::new(
         net_param,
         msi_device_tube,
@@ -2590,18 +2601,14 @@ fn handle_hotplug_net_command<V: VmArch, Vcpu: VcpuArch>(
     net_cmd: NetControlCommand,
     linux: &mut RunnableLinuxVm<V, Vcpu>,
     sys_allocator: &mut SystemAllocator,
-    irq_control_tubes: &mut Vec<Tube>,
-    vm_memory_control_tubes: &mut Vec<VmMemoryTube>,
-    vm_control_tubes: &mut Vec<TaggedControlTube>,
+    add_control_tube: &mut impl FnMut(AnyControlTube),
     hotplug_manager: &mut PciHotPlugManager,
 ) -> VmResponse {
     match net_cmd {
         NetControlCommand::AddTap(tap_name) => handle_hotplug_net_add(
             linux,
             sys_allocator,
-            irq_control_tubes,
-            vm_memory_control_tubes,
-            vm_control_tubes,
+            add_control_tube,
             hotplug_manager,
             &tap_name,
         ),
@@ -2615,9 +2622,7 @@ fn handle_hotplug_net_command<V: VmArch, Vcpu: VcpuArch>(
 fn handle_hotplug_net_add<V: VmArch, Vcpu: VcpuArch>(
     linux: &mut RunnableLinuxVm<V, Vcpu>,
     sys_allocator: &mut SystemAllocator,
-    irq_control_tubes: &mut Vec<Tube>,
-    vm_memory_control_tubes: &mut Vec<VmMemoryTube>,
-    vm_control_tubes: &mut Vec<TaggedControlTube>,
+    add_control_tube: &mut impl FnMut(AnyControlTube),
     hotplug_manager: &mut PciHotPlugManager,
     tap_name: &str,
 ) -> VmResponse {
@@ -2635,9 +2640,7 @@ fn handle_hotplug_net_add<V: VmArch, Vcpu: VcpuArch>(
     let ret = add_hotplug_net(
         linux,
         sys_allocator,
-        irq_control_tubes,
-        vm_memory_control_tubes,
-        vm_control_tubes,
+        add_control_tube,
         hotplug_manager,
         net_param,
     );
@@ -2903,9 +2906,7 @@ fn handle_hotplug_command<V: VmArch, Vcpu: VcpuArch>(
     linux: &mut RunnableLinuxVm<V, Vcpu>,
     sys_allocator: &mut SystemAllocator,
     cfg: &Config,
-    add_irq_control_tubes: &mut Vec<Tube>,
-    add_vm_memory_control_tubes: &mut Vec<VmMemoryTube>,
-    add_tubes: &mut Vec<TaggedControlTube>,
+    add_control_tube: &mut impl FnMut(AnyControlTube),
     hp_control_tube: &mpsc::Sender<PciRootCommand>,
     iommu_host_tube: Option<&Tube>,
     device: &HotPlugDeviceInfo,
@@ -2924,9 +2925,7 @@ fn handle_hotplug_command<V: VmArch, Vcpu: VcpuArch>(
             linux,
             sys_allocator,
             cfg,
-            add_irq_control_tubes,
-            add_vm_memory_control_tubes,
-            add_tubes,
+            add_control_tube,
             hp_control_tube,
             iommu_host_tube,
             device,
@@ -2941,8 +2940,7 @@ fn handle_hotplug_command<V: VmArch, Vcpu: VcpuArch>(
     match ret {
         Ok(()) => VmResponse::Ok,
         Err(e) => {
-            error!("hanlde_hotplug_command failure: {}", e);
-            add_tubes.clear();
+            error!("handle_hotplug_command failure: {}", e);
             VmResponse::Err(base::Error::new(libc::EINVAL))
         }
     }
@@ -2955,7 +2953,7 @@ struct ControlLoopState<'a, V: VmArch, Vcpu: VcpuArch> {
     control_tubes: &'a BTreeMap<usize, TaggedControlTube>,
     disk_host_tubes: &'a [Tube],
     #[cfg(feature = "gpu")]
-    gpu_control_tube: &'a Tube,
+    gpu_control_tube: Option<&'a Tube>,
     #[cfg(feature = "usb")]
     usb_control_tube: &'a Tube,
     #[cfg(target_arch = "x86_64")]
@@ -3010,6 +3008,16 @@ fn process_vm_request<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
     #[cfg(any(target_arch = "x86_64", feature = "pci-hotplug"))]
     let mut add_vm_memory_control_tubes = Vec::new();
 
+    #[cfg(any(target_arch = "x86_64", feature = "pci-hotplug"))]
+    let mut add_control_tube = |t| match t {
+        AnyControlTube::DeviceControlTube(_) => {
+            panic!("hotplugging DeviceControlTube not supported yet")
+        }
+        AnyControlTube::IrqTube(t) => add_irq_control_tubes.push(t),
+        AnyControlTube::TaggedControlTube(t) => add_tubes.push(t),
+        AnyControlTube::VmMemoryTube(t) => add_vm_memory_control_tubes.push(t),
+    };
+
     let response = match request {
         VmRequest::Exit => {
             return Ok(VmRequestResult::new(Some(VmResponse::Ok), true));
@@ -3021,9 +3029,7 @@ fn process_vm_request<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
                     state.linux,
                     &mut state.sys_allocator.lock(),
                     state.cfg,
-                    &mut add_irq_control_tubes,
-                    &mut add_vm_memory_control_tubes,
-                    add_tubes,
+                    &mut add_control_tube,
                     state.hp_control_tube,
                     state.iommu_host_tube.as_ref().map(|t| t.lock()).as_deref(),
                     &device,
@@ -3049,9 +3055,7 @@ fn process_vm_request<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
                     net_cmd,
                     state.linux,
                     &mut state.sys_allocator.lock(),
-                    &mut add_irq_control_tubes,
-                    &mut add_vm_memory_control_tubes,
-                    add_tubes,
+                    &mut add_control_tube,
                     hotplug_manager,
                 )
             } else {
@@ -3119,6 +3123,14 @@ fn process_vm_request<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
         VmRequest::VcpuPidTid => VmResponse::VcpuPidTidResponse {
             pid_tid_map: state.vcpus_pid_tid.clone(),
         },
+        VmRequest::Throttle(vcpu, cycles) => {
+            vcpu::kick_vcpu(
+                &state.vcpu_handles.get(vcpu),
+                state.linux.irq_chip.as_irq_chip(),
+                VcpuControl::Throttle(cycles),
+            );
+            return Ok(VmRequestResult::new(None, false));
+        }
         _ => {
             if !state.cfg.force_s2idle {
                 #[cfg(feature = "pvclock")]
@@ -3156,7 +3168,7 @@ fn process_vm_request<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
                 state.disk_host_tubes,
                 &mut state.linux.pm,
                 #[cfg(feature = "gpu")]
-                Some(state.gpu_control_tube),
+                state.gpu_control_tube,
                 #[cfg(not(feature = "gpu"))]
                 None,
                 #[cfg(feature = "usb")]
@@ -3165,6 +3177,13 @@ fn process_vm_request<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
                 None,
                 &mut state.linux.bat_control,
                 kick_all_vcpus,
+                |index, msg| {
+                    vcpu::kick_vcpu(
+                        &state.vcpu_handles.get(index),
+                        state.linux.irq_chip.as_irq_chip(),
+                        msg,
+                    )
+                },
                 state.cfg.force_s2idle,
                 #[cfg(feature = "swap")]
                 state.swap_controller.as_ref(),
@@ -3394,12 +3413,7 @@ fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
     sys_allocator: SystemAllocator,
     cfg: Config,
     control_server_socket: Option<UnlinkUnixSeqpacketListener>,
-    irq_control_tubes: Vec<Tube>,
-    vm_memory_control_tubes: Vec<VmMemoryTube>,
-    control_tubes: Vec<TaggedControlTube>,
-    #[cfg(feature = "balloon")] balloon_host_tube: Option<Tube>,
-    disk_host_tubes: &[Tube],
-    #[cfg(feature = "gpu")] gpu_control_tube: Tube,
+    all_control_tubes: Vec<AnyControlTube>,
     #[cfg(feature = "usb")] usb_control_tube: Tube,
     vm_evt_rdtube: RecvTube,
     vm_evt_wrtube: SendTube,
@@ -3415,12 +3429,67 @@ fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
     mut swap_controller: Option<SwapController>,
     #[cfg(feature = "registered_events")] reg_evt_rdtube: RecvTube,
     guest_suspended_cvar: Option<Arc<(Mutex<bool>, Condvar)>>,
-    #[cfg(feature = "pvclock")] pvclock_host_tube: Option<Tube>,
     metrics_tube: RecvTube,
     mut vfio_container_manager: VfioContainerManager,
     // A set of PID of child processes whose clean exit is expected and can be ignored.
     mut worker_process_pids: BTreeSet<Pid>,
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))] vcpu_domain_paths: BTreeMap<
+        usize,
+        PathBuf,
+    >,
 ) -> Result<ExitState> {
+    // Split up `all_control_tubes`.
+    #[cfg(feature = "balloon")]
+    let mut balloon_host_tube = None;
+    let mut disk_host_tubes = Vec::new();
+    #[cfg(feature = "gpu")]
+    let mut gpu_control_tube = None;
+    #[cfg(feature = "pvclock")]
+    let mut pvclock_host_tube = None;
+    let mut irq_control_tubes = Vec::new();
+    let mut vm_memory_control_tubes = Vec::new();
+    let mut control_tubes = Vec::new();
+    for t in all_control_tubes {
+        match t {
+            #[cfg(feature = "balloon")]
+            AnyControlTube::DeviceControlTube(DeviceControlTube::Balloon(t)) => {
+                assert!(balloon_host_tube.is_none());
+                balloon_host_tube = Some(t)
+            }
+            AnyControlTube::DeviceControlTube(DeviceControlTube::Disk(t)) => {
+                disk_host_tubes.push(t)
+            }
+            #[cfg(feature = "gpu")]
+            AnyControlTube::DeviceControlTube(DeviceControlTube::Gpu(t)) => {
+                assert!(gpu_control_tube.is_none());
+                gpu_control_tube = Some(t)
+            }
+            #[cfg(feature = "pvclock")]
+            AnyControlTube::DeviceControlTube(DeviceControlTube::PvClock(t)) => {
+                assert!(pvclock_host_tube.is_none());
+                pvclock_host_tube = Some(Arc::new(t))
+            }
+            AnyControlTube::IrqTube(t) => irq_control_tubes.push(t),
+            AnyControlTube::TaggedControlTube(t) => control_tubes.push(t),
+            AnyControlTube::VmMemoryTube(t) => vm_memory_control_tubes.push(t),
+        }
+    }
+
+    #[cfg(feature = "gdb")]
+    let (to_gdb_channel, gdb) = if let Some(port) = cfg.gdb {
+        // GDB needs a control socket to interrupt vcpus.
+        let (gdb_host_tube, gdb_control_tube) = Tube::pair().context("failed to create tube")?;
+        control_tubes.push(TaggedControlTube::Vm(gdb_host_tube));
+        // Create a channel for GDB thread.
+        let (to_gdb_channel, from_vcpu_channel) = mpsc::channel();
+        (
+            Some(to_gdb_channel),
+            Some((port, gdb_control_tube, from_vcpu_channel)),
+        )
+    } else {
+        (None, None)
+    };
+
     #[derive(EventToken)]
     enum Token {
         VmEvent,
@@ -3480,15 +3549,6 @@ fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
         drop_capabilities().context("failed to drop process capabilities")?;
     }
 
-    #[cfg(feature = "gdb")]
-    // Create a channel for GDB thread.
-    let (to_gdb_channel, from_vcpu_channel) = if linux.gdb.is_some() {
-        let (s, r) = mpsc::channel();
-        (Some(s), Some(r))
-    } else {
-        (None, None)
-    };
-
     let (device_ctrl_tube, device_ctrl_resp) = Tube::pair().context("failed to create tube")?;
     // Create devices thread, and restore if a restore file exists.
     linux.devices_thread = match create_devices_worker_thread(
@@ -3531,20 +3591,39 @@ fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
             error!("Failed to enable core scheduling: {}", e);
         }
     }
+
+    // The tasks file only exist on sysfs if CgroupV1 hierachies are enabled
     let vcpu_cgroup_tasks_file = match &cfg.vcpu_cgroup_path {
         None => None,
         Some(cgroup_path) => {
             // Move main process to cgroup_path
-            let mut f = File::create(cgroup_path.join("tasks")).with_context(|| {
+            match File::create(cgroup_path.join("tasks")) {
+                Ok(file) => Some(file),
+                Err(_) => {
+                    info!(
+                        "Unable to open tasks file in cgroup: {}, trying CgroupV2",
+                        cgroup_path.display()
+                    );
+                    None
+                }
+            }
+        }
+    };
+
+    // vCPU freq domains are currently only supported with CgroupsV2.
+    let mut vcpu_cgroup_v2_files: std::collections::BTreeMap<usize, File> = BTreeMap::new();
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+    for (vcpu_id, vcpu_domain_path) in vcpu_domain_paths.iter() {
+        let vcpu_cgroup_v2_file = File::create(vcpu_domain_path.join("cgroup.threads"))
+            .with_context(|| {
                 format!(
                     "failed to create vcpu-cgroup-path {}",
-                    cgroup_path.display(),
+                    vcpu_domain_path.join("cgroup.threads").display(),
                 )
             })?;
-            f.write_all(process::id().to_string().as_bytes())?;
-            Some(f)
-        }
-    };
+        vcpu_cgroup_v2_files.insert(*vcpu_id, vcpu_cgroup_v2_file);
+    }
+
     #[cfg(target_arch = "x86_64")]
     let bus_lock_ratelimit_ctrl: Arc<Mutex<Ratelimit>> = Arc::new(Mutex::new(Ratelimit::new()));
     #[cfg(target_arch = "x86_64")]
@@ -3597,15 +3676,25 @@ fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
         (run_mode, run_mode)
     };
 
-    #[cfg(feature = "pvclock")]
-    let pvclock_host_tube = pvclock_host_tube.map(Arc::new);
-
     // Architecture-specific code must supply a vcpu_init element for each VCPU.
     assert_eq!(vcpus.len(), linux.vcpu_init.len());
 
     let (vcpu_pid_tid_sender, vcpu_pid_tid_receiver) = mpsc::channel();
     for ((cpu_id, vcpu), vcpu_init) in vcpus.into_iter().enumerate().zip(linux.vcpu_init.drain(..))
     {
+        let vcpu_cgroup_file: Option<File>;
+        if let Some(cgroup_file) = &vcpu_cgroup_tasks_file {
+            vcpu_cgroup_file = Some(cgroup_file.try_clone().unwrap())
+        } else if !cfg.cpu_freq_domains.is_empty() {
+            vcpu_cgroup_file = Some(
+                (vcpu_cgroup_v2_files.remove(&cpu_id).unwrap())
+                    .try_clone()
+                    .unwrap(),
+            )
+        } else {
+            vcpu_cgroup_file = None
+        };
+
         let (to_vcpu_channel, from_main_channel) = mpsc::channel();
         let vcpu_affinity = match linux.vcpu_affinity.clone() {
             Some(VcpuAffinity::Global(v)) => v,
@@ -3664,7 +3753,7 @@ fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
             cfg.core_scheduling,
             cfg.per_vm_core_scheduling,
             cpu_config,
-            match vcpu_cgroup_tasks_file {
+            match vcpu_cgroup_file {
                 None => None,
                 Some(ref f) => Some(
                     f.try_clone()
@@ -3701,16 +3790,12 @@ fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
 
     #[cfg(feature = "gdb")]
     // Spawn GDB thread.
-    if let Some((gdb_port_num, gdb_control_tube)) = linux.gdb.take() {
+    if let Some((gdb_port_num, gdb_control_tube, from_vcpu_channel)) = gdb {
         let to_vcpu_channels = vcpu_handles
             .iter()
             .map(|(_handle, channel)| channel.clone())
             .collect();
-        let target = GdbStub::new(
-            gdb_control_tube,
-            to_vcpu_channels,
-            from_vcpu_channel.unwrap(), // Must succeed to unwrap()
-        );
+        let target = GdbStub::new(gdb_control_tube, to_vcpu_channels, from_vcpu_channel);
         std::thread::Builder::new()
             .name("gdb".to_owned())
             .spawn(move || gdb_thread(target, gdb_port_num))
@@ -3999,9 +4084,9 @@ fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
                             cfg: &cfg,
                             sys_allocator: &sys_allocator_mutex,
                             control_tubes: &control_tubes,
-                            disk_host_tubes,
+                            disk_host_tubes: &disk_host_tubes[..],
                             #[cfg(feature = "gpu")]
-                            gpu_control_tube: &gpu_control_tube,
+                            gpu_control_tube: gpu_control_tube.as_ref(),
                             #[cfg(feature = "usb")]
                             usb_control_tube: &usb_control_tube,
                             #[cfg(target_arch = "x86_64")]
diff --git a/src/crosvm/sys/linux/device_helpers.rs b/src/crosvm/sys/linux/device_helpers.rs
index 327761eef..821b49a11 100644
--- a/src/crosvm/sys/linux/device_helpers.rs
+++ b/src/crosvm/sys/linux/device_helpers.rs
@@ -97,9 +97,63 @@ use crate::crosvm::config::VhostUserFrontendOption;
 use crate::crosvm::config::VhostUserFsOption;
 use crate::crosvm::sys::config::PmemExt2Option;
 
+/// All the tube types collected and passed to `run_control`.
+///
+/// This mainly exists to simplify the device setup plumbing. We collect the tubes of all the
+/// devices into one list using this enum and then separate them out in `run_control` to be handled
+/// individually.
+#[remain::sorted]
+pub enum AnyControlTube {
+    DeviceControlTube(DeviceControlTube),
+    /// Receives `IrqHandlerRequest`.
+    IrqTube(Tube),
+    TaggedControlTube(TaggedControlTube),
+    VmMemoryTube(VmMemoryTube),
+}
+
+impl From<DeviceControlTube> for AnyControlTube {
+    fn from(value: DeviceControlTube) -> Self {
+        AnyControlTube::DeviceControlTube(value)
+    }
+}
+
+impl From<TaggedControlTube> for AnyControlTube {
+    fn from(value: TaggedControlTube) -> Self {
+        AnyControlTube::TaggedControlTube(value)
+    }
+}
+
+impl From<VmMemoryTube> for AnyControlTube {
+    fn from(value: VmMemoryTube) -> Self {
+        AnyControlTube::VmMemoryTube(value)
+    }
+}
+
+/// Tubes that initiate requests to devices.
+#[remain::sorted]
+pub enum DeviceControlTube {
+    // See `BalloonTube`.
+    #[cfg(feature = "balloon")]
+    Balloon(Tube),
+    // Sends `DiskControlCommand`.
+    Disk(Tube),
+    // Sends `GpuControlCommand`.
+    #[cfg(feature = "gpu")]
+    Gpu(Tube),
+    // Sends `PvClockCommand`.
+    #[cfg(feature = "pvclock")]
+    PvClock(Tube),
+}
+
+/// Tubes that service requests from devices.
+///
+/// Only includes those that happen to be handled together in the main `WaitContext` loop.
 pub enum TaggedControlTube {
+    /// Receives `FsMappingRequest`.
     Fs(Tube),
+    /// Receives `VmRequest`.
     Vm(Tube),
+    /// Receives `VmMemoryMappingRequest`.
     VmMsync(Tube),
 }
 
@@ -124,6 +178,7 @@ impl ReadNotifier for TaggedControlTube {
     }
 }
 
+/// Tubes that service `VmMemoryRequest` requests from devices.
 #[derive(serde::Serialize, serde::Deserialize)]
 pub struct VmMemoryTube {
     pub tube: Tube,
@@ -749,6 +804,31 @@ pub fn create_vinput_device(
     })
 }
 
+pub fn create_custom_device<T: IntoUnixStream>(
+    protection_type: ProtectionType,
+    jail_config: &Option<JailConfig>,
+    custom_device_socket: T,
+    idx: u32,
+    input_config_path: PathBuf,
+) -> DeviceResult {
+    let socket = custom_device_socket
+        .into_unix_stream()
+        .context("failed configuring custom virtio input device")?;
+
+    let dev = virtio::input::new_custom(
+        idx,
+        socket,
+        input_config_path,
+        virtio::base_features(protection_type),
+    )
+    .context("failed to set up input device")?;
+
+    Ok(VirtioDeviceStub {
+        dev: Box::new(dev),
+        jail: simple_jail(jail_config, "input_device")?,
+    })
+}
+
 #[cfg(feature = "balloon")]
 pub fn create_balloon_device(
     protection_type: ProtectionType,
@@ -756,7 +836,6 @@ pub fn create_balloon_device(
     tube: Tube,
     inflate_tube: Option<Tube>,
     init_balloon_size: u64,
-    dynamic_mapping_device_tube: Tube,
     enabled_features: u64,
     #[cfg(feature = "registered_events")] registered_evt_q: Option<SendTube>,
     ws_num_bins: u8,
@@ -764,7 +843,6 @@ pub fn create_balloon_device(
     let dev = virtio::Balloon::new(
         virtio::base_features(protection_type),
         tube,
-        VmMemoryClient::new(dynamic_mapping_device_tube),
         inflate_tube,
         init_balloon_size,
         enabled_features,
@@ -1044,6 +1122,30 @@ pub fn register_video_device(
     Ok(())
 }
 
+#[cfg(feature = "media")]
+pub fn create_simple_media_device(protection_type: ProtectionType) -> DeviceResult {
+    use devices::virtio::media::create_virtio_media_simple_capture_device;
+
+    let features = virtio::base_features(protection_type);
+    let dev = create_virtio_media_simple_capture_device(features);
+
+    Ok(VirtioDeviceStub { dev, jail: None })
+}
+
+#[cfg(any(target_os = "android", target_os = "linux"))]
+#[cfg(feature = "media")]
+pub fn create_v4l2_device<P: AsRef<Path>>(
+    protection_type: ProtectionType,
+    path: P,
+) -> DeviceResult {
+    use devices::virtio::media::create_virtio_media_v4l2_proxy_device;
+
+    let features = virtio::base_features(protection_type);
+    let dev = create_virtio_media_v4l2_proxy_device(features, path)?;
+
+    Ok(VirtioDeviceStub { dev, jail: None })
+}
+
 impl VirtioDeviceBuilder for &VsockConfig {
     const NAME: &'static str = "vhost_vsock";
 
@@ -1254,7 +1356,10 @@ pub fn create_pmem_device(
                 Alloc::PmemDevice(index),
                 format!("pmem_disk_image_{}", index),
                 AllocOptions::new()
-                .top_down(true)
+                // Allocate from the bottom up rather than top down to avoid exceeding PHYSMEM_END
+                // with kaslr.
+                // TODO: b/375506171: Find a proper fix.
+                .top_down(false)
                 .prefetchable(true)
                 // Linux kernel requires pmem namespaces to be 128 MiB aligned.
                 // cf. https://github.com/pmem/ndctl/issues/76
@@ -1310,6 +1415,7 @@ pub fn create_pmem_ext2_device(
         inodes_per_group: opts.inodes_per_group,
         blocks_per_group: opts.blocks_per_group,
         size: mapping_size as u32,
+        ..Default::default()
     };
 
     let max_open_files = base::linux::max_open_files()
@@ -1504,9 +1610,7 @@ pub fn create_vfio_device(
     jail_config: &Option<JailConfig>,
     vm: &impl Vm,
     resources: &mut SystemAllocator,
-    irq_control_tubes: &mut Vec<Tube>,
-    vm_memory_control_tubes: &mut Vec<VmMemoryTube>,
-    control_tubes: &mut Vec<TaggedControlTube>,
+    add_control_tube: &mut impl FnMut(AnyControlTube),
     vfio_path: &Path,
     hotplug: bool,
     hotplug_bus: Option<u8>,
@@ -1522,13 +1626,16 @@ pub fn create_vfio_device(
 
     let (vfio_host_tube_mem, vfio_device_tube_mem) =
         Tube::pair().context("failed to create tube")?;
-    vm_memory_control_tubes.push(VmMemoryTube {
-        tube: vfio_host_tube_mem,
-        expose_with_viommu: false,
-    });
+    add_control_tube(
+        VmMemoryTube {
+            tube: vfio_host_tube_mem,
+            expose_with_viommu: false,
+        }
+        .into(),
+    );
 
     let (vfio_host_tube_vm, vfio_device_tube_vm) = Tube::pair().context("failed to create tube")?;
-    control_tubes.push(TaggedControlTube::Vm(vfio_host_tube_vm));
+    add_control_tube(TaggedControlTube::Vm(vfio_host_tube_vm).into());
 
     let vfio_device =
         VfioDevice::new_passthrough(&vfio_path, vm, vfio_container.clone(), iommu_dev, dt_symbol)
@@ -1538,11 +1645,11 @@ pub fn create_vfio_device(
         VfioDeviceType::Pci => {
             let (vfio_host_tube_msi, vfio_device_tube_msi) =
                 Tube::pair().context("failed to create tube")?;
-            irq_control_tubes.push(vfio_host_tube_msi);
+            add_control_tube(AnyControlTube::IrqTube(vfio_host_tube_msi));
 
             let (vfio_host_tube_msix, vfio_device_tube_msix) =
                 Tube::pair().context("failed to create tube")?;
-            irq_control_tubes.push(vfio_host_tube_msix);
+            add_control_tube(AnyControlTube::IrqTube(vfio_host_tube_msix));
 
             let mut vfio_pci_device = VfioPciDevice::new(
                 vfio_path,
diff --git a/src/crosvm/sys/linux/ext2.rs b/src/crosvm/sys/linux/ext2.rs
index 375a44e87..1f843f501 100644
--- a/src/crosvm/sys/linux/ext2.rs
+++ b/src/crosvm/sys/linux/ext2.rs
@@ -49,7 +49,7 @@ pub fn launch(
     path: &Path,
     ugid: &(Option<u32>, Option<u32>),
     ugid_map: (&str, &str),
-    builder: ext2::Builder,
+    mut builder: ext2::Builder,
     jail_config: &Option<JailConfig>,
 ) -> Result<Pid> {
     let max_open_files = base::linux::max_open_files()
@@ -72,6 +72,9 @@ pub fn launch(
         create_base_minijail(path, max_open_files)?
     };
 
+    // Use "/" in the new mount namespace as the root for mkfs.
+    builder.root_dir = Some(std::path::PathBuf::from("/"));
+
     let shm = SharedMemory::new("pmem_ext2_shm", builder.size as u64)
         .context("failed to create shared memory")?;
     let mut keep_rds = vec![
@@ -102,11 +105,10 @@ fn mkfs_callback(
     builder: ext2::Builder,
     shm: SharedMemory,
 ) -> Result<()> {
-    let jailed_root = Some(std::path::Path::new("/"));
     let file_mappings = builder
         .build_on_shm(&shm)
         .context("failed to build memory region")?
-        .build_mmap_info(jailed_root)
+        .build_mmap_info()
         .context("failed to build ext2")?
         .mapping_info;
 
diff --git a/src/crosvm/sys/linux/pci_hotplug_manager.rs b/src/crosvm/sys/linux/pci_hotplug_manager.rs
index 861f779ad..efd7ee408 100644
--- a/src/crosvm/sys/linux/pci_hotplug_manager.rs
+++ b/src/crosvm/sys/linux/pci_hotplug_manager.rs
@@ -86,9 +86,8 @@ impl WorkerClient {
                 control_evt_cpy,
                 &kill_evt,
             )?;
-            worker.run(kill_evt).map_err(|e| {
-                error!("Worker exited with error: {:?}", &e);
-                e
+            worker.run(kill_evt).inspect_err(|e| {
+                error!("Worker exited with error: {:?}", e);
             })
         });
         Ok(WorkerClient {
diff --git a/src/crosvm/sys/linux/vcpu.rs b/src/crosvm/sys/linux/vcpu.rs
index 80eff6838..20d730d55 100644
--- a/src/crosvm/sys/linux/vcpu.rs
+++ b/src/crosvm/sys/linux/vcpu.rs
@@ -64,35 +64,6 @@ const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
 const SCHED_SCALE_CAPACITY: u32 = 1024;
 const SCHED_FLAG_KEEP_ALL: u64 = SCHED_FLAG_KEEP_POLICY | SCHED_FLAG_KEEP_PARAMS;
 
-fn bus_io_handler(bus: &Bus) -> impl FnMut(IoParams) -> Option<[u8; 8]> + '_ {
-    |IoParams {
-         address,
-         mut size,
-         operation: direction,
-     }| match direction {
-        IoOperation::Read => {
-            let mut data = [0u8; 8];
-            if size > data.len() {
-                error!("unsupported Read size of {} bytes", size);
-                size = data.len();
-            }
-            // Ignore the return value of `read()`. If no device exists on the bus at the given
-            // location, return the initial value of data, which is all zeroes.
-            let _ = bus.read(address, &mut data[..size]);
-            Some(data)
-        }
-        IoOperation::Write { data } => {
-            if size > data.len() {
-                error!("unsupported Write size of {} bytes", size);
-                size = data.len()
-            }
-            let data = &data[..size];
-            bus.write(address, data);
-            None
-        }
-    }
-}
-
 /// Set the VCPU thread affinity and other per-thread scheduler properties.
 /// This function will be called from each VCPU thread at startup.
 #[allow(clippy::unnecessary_cast)]
@@ -104,12 +75,6 @@ pub fn set_vcpu_thread_scheduling(
     run_rt: bool,
     boost_uclamp: bool,
 ) -> anyhow::Result<()> {
-    if !vcpu_affinity.is_empty() {
-        if let Err(e) = set_cpu_affinity(vcpu_affinity) {
-            error!("Failed to set CPU affinity: {}", e);
-        }
-    }
-
     if boost_uclamp {
         let mut sched_attr = sched_attr::default();
         sched_attr.sched_flags = SCHED_FLAG_KEEP_ALL as u64
@@ -135,6 +100,15 @@ pub fn set_vcpu_thread_scheduling(
             .context("failed to write vcpu tid to cgroup tasks")?;
     }
 
+    // vcpu_affinity needs to be set after moving to cgroup
+    // or it will be overriden by cgroup settings, vcpu_affinity
+    // here is bounded by the cpuset specified in the cgroup
+    if !vcpu_affinity.is_empty() {
+        if let Err(e) = set_cpu_affinity(vcpu_affinity) {
+            error!("Failed to set CPU affinity: {}", e);
+        }
+    }
+
     if run_rt {
         const DEFAULT_VCPU_RT_LEVEL: u16 = 6;
         if let Err(e) = set_rt_prio_limit(u64::from(DEFAULT_VCPU_RT_LEVEL))
@@ -371,6 +345,16 @@ where
                                 error!("Failed to send restore response: {}", e);
                             }
                         }
+                        VcpuControl::Throttle(target_us) => {
+                            let start_time = std::time::Instant::now();
+
+                            while start_time.elapsed().as_micros() < target_us.into() {
+                                // TODO: Investigate replacing this with std::hint::spin_loop()
+                                // to hint to the pCPU to potentially save some power. Also revisit
+                                // this when scheduler updates are available on newer kernel
+                                // versions.
+                            }
+                        }
                     }
                 }
                 if run_mode == VmRunMode::Running {
@@ -399,13 +383,31 @@ where
         if !interrupted_by_signal {
             match vcpu.run() {
                 Ok(VcpuExit::Io) => {
-                    if let Err(e) = vcpu.handle_io(&mut bus_io_handler(&io_bus)) {
+                    if let Err(e) =
+                        vcpu.handle_io(&mut |IoParams { address, operation }| match operation {
+                            IoOperation::Read(data) => {
+                                io_bus.read(address, data);
+                            }
+                            IoOperation::Write(data) => {
+                                io_bus.write(address, data);
+                            }
+                        })
+                    {
                         error!("failed to handle io: {}", e)
                     }
                 }
                 Ok(VcpuExit::Mmio) => {
                     if let Err(e) =
-                        vcpu.handle_mmio(&mut |io_params| Ok(bus_io_handler(&mmio_bus)(io_params)))
+                        vcpu.handle_mmio(&mut |IoParams { address, operation }| match operation {
+                            IoOperation::Read(data) => {
+                                mmio_bus.read(address, data);
+                                Ok(())
+                            }
+                            IoOperation::Write(data) => {
+                                mmio_bus.write(address, data);
+                                Ok(())
+                            }
+                        })
                     {
                         error!("failed to handle mmio: {}", e);
                     }
diff --git a/src/crosvm/sys/windows/cmdline.rs b/src/crosvm/sys/windows/cmdline.rs
index cf3e78bbb..27d17e385 100644
--- a/src/crosvm/sys/windows/cmdline.rs
+++ b/src/crosvm/sys/windows/cmdline.rs
@@ -37,6 +37,7 @@ pub struct RunMainCommand {
 /// Start a new metrics instance
 pub struct RunMetricsCommand {
     #[argh(option, arg_name = "TRANSPORT_TUBE_RD")]
+    #[allow(dead_code)]
     /// tube transporter descriptor used to bootstrap the metrics process.
     pub bootstrap: usize,
 }
diff --git a/src/main.rs b/src/main.rs
index 7e4f2af88..2fbbbfc51 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -18,6 +18,7 @@ use argh::FromArgs;
 use base::debug;
 use base::error;
 use base::info;
+use base::set_thread_name;
 use base::syslog;
 use base::syslog::LogArgs;
 use base::syslog::LogConfig;
@@ -151,6 +152,10 @@ fn run_vm(cmd: RunCommand, log_config: LogConfig) -> Result<CommandStatus> {
         }
     };
 
+    if let Some(ref name) = cfg.name {
+        set_thread_name(name).context("Failed to set the name")?;
+    }
+
     #[cfg(feature = "plugin")]
     if executable_is_plugin(&cfg.executable_path) {
         let res = match crosvm::plugin::run_config(cfg) {
diff --git a/src/sys/windows.rs b/src/sys/windows.rs
index 6eb817700..b1b6cf82a 100644
--- a/src/sys/windows.rs
+++ b/src/sys/windows.rs
@@ -2110,10 +2110,7 @@ fn setup_vm_components(cfg: &Config) -> Result<VmComponents> {
         fw_cfg_parameters: cfg.fw_cfg_parameters.clone(),
         itmt: false,
         pvm_fw: None,
-        #[cfg(target_arch = "x86_64")]
-        pci_low_start: cfg.pci_low_start,
-        #[cfg(target_arch = "x86_64")]
-        pcie_ecam: cfg.pcie_ecam,
+        pci_config: cfg.pci_config,
         #[cfg(target_arch = "x86_64")]
         smbios: cfg.smbios.clone(),
         dynamic_power_coefficient: cfg.dynamic_power_coefficient.clone(),
@@ -2291,12 +2288,14 @@ pub fn run_config(cfg: Config) -> Result<ExitState> {
 
 fn create_guest_memory(
     components: &VmComponents,
+    arch_memory_layout: &<Arch as LinuxArch>::ArchMemoryLayout,
     hypervisor: &impl Hypervisor,
 ) -> Result<GuestMemory> {
-    let guest_mem_layout = Arch::guest_memory_layout(components, hypervisor).exit_context(
-        Exit::GuestMemoryLayout,
-        "failed to create guest memory layout",
-    )?;
+    let guest_mem_layout = Arch::guest_memory_layout(components, arch_memory_layout, hypervisor)
+        .exit_context(
+            Exit::GuestMemoryLayout,
+            "failed to create guest memory layout",
+        )?;
     GuestMemory::new_with_options(&guest_mem_layout)
         .exit_context(Exit::CreateGuestMemory, "failed to create guest memory")
 }
@@ -2312,6 +2311,7 @@ fn run_config_inner(
     cros_tracing::add_per_trace_callback(set_tsc_clock_snapshot);
 
     let components: VmComponents = setup_vm_components(&cfg)?;
+    let arch_memory_layout = Arch::arch_memory_layout(&components)?;
 
     #[allow(unused_mut)]
     let mut hypervisor = cfg
@@ -2333,7 +2333,7 @@ fn run_config_inner(
             }
             info!("Creating HAXM ghaxm={}", get_use_ghaxm());
             let haxm = Haxm::new()?;
-            let guest_mem = create_guest_memory(&components, &haxm)?;
+            let guest_mem = create_guest_memory(&components, &arch_memory_layout, &haxm)?;
             let vm = create_haxm_vm(haxm, guest_mem, &cfg.kernel_log_file)?;
             let (ioapic_host_tube, ioapic_device_tube) =
                 Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
@@ -2342,6 +2342,7 @@ fn run_config_inner(
             run_vm::<HaxmVcpu, HaxmVm>(
                 cfg,
                 components,
+                &arch_memory_layout,
                 vm,
                 WindowsIrqChip::Userspace(irq_chip).as_mut(),
                 Some(ioapic_host_tube),
@@ -2370,7 +2371,7 @@ fn run_config_inner(
 
             info!("Creating Whpx");
             let whpx = Whpx::new()?;
-            let guest_mem = create_guest_memory(&components, &whpx)?;
+            let guest_mem = create_guest_memory(&components, &arch_memory_layout, &whpx)?;
             let vm = create_whpx_vm(
                 whpx,
                 guest_mem,
@@ -2404,6 +2405,7 @@ fn run_config_inner(
             run_vm::<WhpxVcpu, WhpxVm>(
                 cfg,
                 components,
+                &arch_memory_layout,
                 vm,
                 irq_chip.as_mut(),
                 Some(ioapic_host_tube),
@@ -2415,7 +2417,7 @@ fn run_config_inner(
         HypervisorKind::Gvm => {
             info!("Creating GVM");
             let gvm = Gvm::new()?;
-            let guest_mem = create_guest_memory(&components, &gvm)?;
+            let guest_mem = create_guest_memory(&components, &arch_memory_layout, &gvm)?;
             let vm = create_gvm_vm(gvm, guest_mem)?;
             let ioapic_host_tube;
             let mut irq_chip = match cfg.irq_chip.unwrap_or(IrqChipKind::Kernel) {
@@ -2437,6 +2439,7 @@ fn run_config_inner(
             run_vm::<GvmVcpu, GvmVm>(
                 cfg,
                 components,
+                &arch_memory_layout,
                 vm,
                 irq_chip.as_mut(),
                 ioapic_host_tube,
@@ -2451,6 +2454,7 @@ fn run_config_inner(
 fn run_vm<Vcpu, V>(
     #[allow(unused_mut)] mut cfg: Config,
     #[allow(unused_mut)] mut components: VmComponents,
+    arch_memory_layout: &<Arch as LinuxArch>::ArchMemoryLayout,
     mut vm: V,
     irq_chip: &mut dyn IrqChipArch,
     ioapic_host_tube: Option<Tube>,
@@ -2514,7 +2518,7 @@ where
 
     let pstore_size = components.pstore.as_ref().map(|pstore| pstore.size as u64);
     let mut sys_allocator = SystemAllocator::new(
-        Arch::get_system_allocator_config(&vm),
+        Arch::get_system_allocator_config(&vm, arch_memory_layout),
         pstore_size,
         &cfg.mmio_address_ranges,
     )
@@ -2641,6 +2645,7 @@ where
     let (vwmdt_host_tube, vmwdt_device_tube) = Tube::pair().context("failed to create tube")?;
     let windows = Arch::build_vm::<V, Vcpu>(
         components,
+        arch_memory_layout,
         &vm_evt_wrtube,
         &mut sys_allocator,
         &cfg.serial_parameters,
@@ -2658,6 +2663,7 @@ where
         /* guest_suspended_cvar= */ None,
         dt_overlays,
         cfg.fdt_position,
+        cfg.no_pmu,
     )
     .exit_context(Exit::BuildVm, "the architecture failed to build the vm")?;
 
diff --git a/src/sys/windows/run_vcpu.rs b/src/sys/windows/run_vcpu.rs
index 8a0c64906..13b91c3c8 100644
--- a/src/sys/windows/run_vcpu.rs
+++ b/src/sys/windows/run_vcpu.rs
@@ -732,71 +732,47 @@ where
             match exit {
                 Ok(VcpuExit::Io) => {
                     let _trace_event = trace_event!(crosvm, "VcpuExit::Io");
-                    vcpu.handle_io(&mut |IoParams { address, mut size, operation}| {
+                    vcpu.handle_io(&mut |IoParams { address, operation}| {
                         match operation {
-                            IoOperation::Read => {
-                                let mut data = [0u8; 8];
-                                if size > data.len() {
-                                    error!("unsupported IoIn size of {} bytes", size);
-                                    size = data.len();
-                                }
-                                io_bus.read(address, &mut data[..size]);
-                                Some(data)
+                            IoOperation::Read(data) => {
+                                io_bus.read(address, data);
                             }
-                            IoOperation::Write { data } => {
-                                if size > data.len() {
-                                    error!("unsupported IoOut size of {} bytes", size);
-                                    size = data.len()
-                                }
-                                vm.handle_io_events(IoEventAddress::Pio(address), &data[..size])
+                            IoOperation::Write(data) => {
+                                vm.handle_io_events(IoEventAddress::Pio(address), data)
                                     .unwrap_or_else(|e| error!(
                                         "failed to handle ioevent for pio write to {} on vcpu {}: {}",
                                         address, context.cpu_id, e
                                     ));
-                                io_bus.write(address, &data[..size]);
-                                None
+                                io_bus.write(address, data);
                             }
                         }
                     }).unwrap_or_else(|e| error!("failed to handle io: {}", e));
                 }
                 Ok(VcpuExit::Mmio) => {
                     let _trace_event = trace_event!(crosvm, "VcpuExit::Mmio");
-                    vcpu.handle_mmio(&mut |IoParams { address, mut size, operation }| {
+                    vcpu.handle_mmio(&mut |IoParams { address, operation }| {
                         match operation {
-                            IoOperation::Read => {
-                                let mut data = [0u8; 8];
-                                if size > data.len() {
-                                    error!("unsupported MmioRead size of {} bytes", size);
-                                    size = data.len();
-                                }
-                                {
-                                    let data = &mut data[..size];
-                                    if !mmio_bus.read(address, data) {
-                                        info!(
-                                            "mmio read failed: {:x}; trying memory read..",
-                                            address
-                                        );
-                                        vm.get_memory()
-                                            .read_exact_at_addr(
-                                                data,
-                                                vm_memory::GuestAddress(address),
+                            IoOperation::Read(data) => {
+                                if !mmio_bus.read(address, data) {
+                                    info!(
+                                        "mmio read failed: {:x}; trying memory read..",
+                                        address
+                                    );
+                                    vm.get_memory()
+                                        .read_exact_at_addr(
+                                            data,
+                                            vm_memory::GuestAddress(address),
+                                        )
+                                        .unwrap_or_else(|e| {
+                                            error!(
+                                                "guest memory read failed at {:x}: {}",
+                                                address, e
                                             )
-                                            .unwrap_or_else(|e| {
-                                                error!(
-                                                    "guest memory read failed at {:x}: {}",
-                                                    address, e
-                                                )
-                                            });
-                                    }
+                                        });
                                 }
-                                Ok(Some(data))
+                                Ok(())
                             }
-                            IoOperation::Write { data } => {
-                                if size > data.len() {
-                                    error!("unsupported MmioWrite size of {} bytes", size);
-                                    size = data.len()
-                                }
-                                let data = &data[..size];
+                            IoOperation::Write(data) => {
                                 vm.handle_io_events(IoEventAddress::Mmio(address), data)
                                     .unwrap_or_else(|e| error!(
                                         "failed to handle ioevent for mmio write to {} on vcpu {}: {}",
@@ -814,12 +790,13 @@ where
                                             address, e
                                         ));
                                 }
-                                Ok(None)
+                                Ok(())
                             }
                         }
                     }).unwrap_or_else(|e| error!("failed to handle mmio: {}", e));
                 }
                 Ok(VcpuExit::IoapicEoi { vector }) => {
+                    let _trace_event = trace_event!(crosvm, "VcpuExit::IoapicEoi");
                     irq_chip.broadcast_eoi(vector).unwrap_or_else(|e| {
                         error!(
                             "failed to broadcast eoi {} on vcpu {}: {}",
@@ -827,7 +804,9 @@ where
                         )
                     });
                 }
-                Ok(VcpuExit::IrqWindowOpen) => {}
+                Ok(VcpuExit::IrqWindowOpen) => {
+                    let _trace_event = trace_event!(crosvm, "VcpuExit::IrqWindowOpen");
+                }
                 Ok(VcpuExit::Hlt) => irq_chip.halted(context.cpu_id),
 
                 // VcpuExit::Shutdown is always an error on Windows.  HAXM exits with
@@ -865,8 +844,14 @@ where
                 // can happen during normal operation too, when GVM's timer finds requests
                 // pending from the host.  So we set check_vm_shutdown, then below check the
                 // VmRunMode state to see if we should exit the run loop.
-                Ok(VcpuExit::Intr) => check_vm_shutdown = true,
-                Ok(VcpuExit::Canceled) => check_vm_shutdown = true,
+                Ok(VcpuExit::Intr) => {
+                    let _trace_event = trace_event!(crosvm, "VcpuExit::Intr");
+                    check_vm_shutdown = true
+                }
+                Ok(VcpuExit::Canceled) => {
+                    let _trace_event = trace_event!(crosvm, "VcpuExit::Canceled");
+                    check_vm_shutdown = true
+                }
                 #[cfg(target_arch = "x86_64")]
                 Ok(VcpuExit::Cpuid { mut entry }) => {
                     let _trace_event = trace_event!(crosvm, "VcpuExit::Cpuid");
@@ -882,8 +867,11 @@ where
                     });
                 }
                 #[cfg(target_arch = "x86_64")]
-                Ok(VcpuExit::MsrAccess) => {} // MsrAccess handled by hypervisor impl
+                Ok(VcpuExit::MsrAccess) => {
+                    let _trace_event = trace_event!(crosvm, "VcpuExit::MsrAccess");
+                } // MsrAccess handled by hypervisor impl
                 Ok(r) => {
+                    let _trace_event = trace_event!(crosvm, "VcpuExit::Unexpected");
                     error!("unexpected vcpu.run return value: {:?}", r);
                     check_vm_shutdown = true;
                 }
diff --git a/swap/tests/common/mod.rs b/swap/tests/common/mod.rs
index 3d3afcd8e..ec62bb9b4 100644
--- a/swap/tests/common/mod.rs
+++ b/swap/tests/common/mod.rs
@@ -18,6 +18,7 @@ pub fn create_uffd_for_test() -> Userfaultfd {
 }
 
 pub struct SharedMemoryMapping {
+    #[allow(dead_code)]
     pub shm: SharedMemory,
     pub mmap: MemoryMapping,
 }
diff --git a/system_api/src/bindings/client/org_chromium_power_manager.rs b/system_api/src/bindings/client/org_chromium_power_manager.rs
new file mode 100644
index 000000000..71ac381df
--- /dev/null
+++ b/system_api/src/bindings/client/org_chromium_power_manager.rs
@@ -0,0 +1,686 @@
+// This code was autogenerated with `dbus-codegen-rust -s -m None`, see https://github.com/diwic/dbus-rs
+use dbus as dbus;
+#[allow(unused_imports)]
+use dbus::arg;
+use dbus::blocking;
+
+pub trait OrgChromiumPowerManager {
+    fn request_shutdown(&self, reason: i32, description: &str) -> Result<(), dbus::Error>;
+    fn request_restart(&self, reason: i32, description: &str) -> Result<(), dbus::Error>;
+    fn change_wifi_reg_domain(&self, domain: i32) -> Result<(), dbus::Error>;
+    fn request_suspend(&self, external_wakeup_count: u64, wakeup_timeout: i32, suspend_flavor: u32) -> Result<(), dbus::Error>;
+    fn set_screen_brightness(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error>;
+    fn decrease_screen_brightness(&self, allow_off: bool) -> Result<(), dbus::Error>;
+    fn increase_screen_brightness(&self) -> Result<(), dbus::Error>;
+    fn get_screen_brightness_percent(&self) -> Result<f64, dbus::Error>;
+    fn has_keyboard_backlight(&self) -> Result<bool, dbus::Error>;
+    fn decrease_keyboard_brightness(&self) -> Result<(), dbus::Error>;
+    fn increase_keyboard_brightness(&self) -> Result<(), dbus::Error>;
+    fn toggle_keyboard_backlight(&self) -> Result<(), dbus::Error>;
+    fn set_keyboard_brightness(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error>;
+    fn get_keyboard_brightness_percent(&self) -> Result<f64, dbus::Error>;
+    fn set_keyboard_ambient_light_sensor_enabled(&self, enabled: bool) -> Result<(), dbus::Error>;
+    fn get_power_supply_properties(&self) -> Result<Vec<u8>, dbus::Error>;
+    fn get_battery_state(&self) -> Result<(u32, u32, f64), dbus::Error>;
+    fn handle_video_activity(&self, fullscreen: bool) -> Result<(), dbus::Error>;
+    fn handle_user_activity(&self, type_: i32) -> Result<(), dbus::Error>;
+    fn set_is_projecting(&self, is_projecting: bool) -> Result<(), dbus::Error>;
+    fn set_policy(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error>;
+    fn set_power_source(&self, id: &str) -> Result<(), dbus::Error>;
+    fn handle_power_button_acknowledgment(&self, timestamp_internal: i64) -> Result<(), dbus::Error>;
+    fn ignore_next_power_button_press(&self, timeout_internal: i64) -> Result<(), dbus::Error>;
+    fn register_suspend_delay(&self, serialized_request_proto: Vec<u8>) -> Result<Vec<u8>, dbus::Error>;
+    fn unregister_suspend_delay(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error>;
+    fn handle_suspend_readiness(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error>;
+    fn register_dark_suspend_delay(&self, serialized_request_proto: Vec<u8>) -> Result<Vec<u8>, dbus::Error>;
+    fn unregister_dark_suspend_delay(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error>;
+    fn handle_dark_suspend_readiness(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error>;
+    fn record_dark_resume_wake_reason(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error>;
+    fn get_inactivity_delays(&self) -> Result<Vec<u8>, dbus::Error>;
+    fn has_ambient_color_device(&self) -> Result<bool, dbus::Error>;
+    fn get_thermal_state(&self) -> Result<Vec<u8>, dbus::Error>;
+    fn set_external_display_alsbrightness(&self, enabled: bool) -> Result<(), dbus::Error>;
+    fn get_external_display_alsbrightness(&self) -> Result<bool, dbus::Error>;
+    fn charge_now_for_adaptive_charging(&self) -> Result<(), dbus::Error>;
+    fn get_charge_history(&self) -> Result<Vec<u8>, dbus::Error>;
+    fn get_battery_saver_mode_state(&self) -> Result<Vec<u8>, dbus::Error>;
+    fn set_battery_saver_mode_state(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error>;
+    fn has_ambient_light_sensor(&self) -> Result<bool, dbus::Error>;
+    fn set_ambient_light_sensor_enabled(&self, enabled: bool) -> Result<(), dbus::Error>;
+    fn battery_state_poll(&self) -> Result<(u32, u32, f64), dbus::Error>;
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerBatterySaverModeStateChanged {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerBatterySaverModeStateChanged {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerBatterySaverModeStateChanged {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerBatterySaverModeStateChanged {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerBatterySaverModeStateChanged {
+    const NAME: &'static str = "BatterySaverModeStateChanged";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerScreenBrightnessChanged {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerScreenBrightnessChanged {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerScreenBrightnessChanged {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerScreenBrightnessChanged {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerScreenBrightnessChanged {
+    const NAME: &'static str = "ScreenBrightnessChanged";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerKeyboardBrightnessChanged {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerKeyboardBrightnessChanged {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerKeyboardBrightnessChanged {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerKeyboardBrightnessChanged {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerKeyboardBrightnessChanged {
+    const NAME: &'static str = "KeyboardBrightnessChanged";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerKeyboardAmbientLightSensorEnabledChanged {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerKeyboardAmbientLightSensorEnabledChanged {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerKeyboardAmbientLightSensorEnabledChanged {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerKeyboardAmbientLightSensorEnabledChanged {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerKeyboardAmbientLightSensorEnabledChanged {
+    const NAME: &'static str = "KeyboardAmbientLightSensorEnabledChanged";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerPeripheralBatteryStatus {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerPeripheralBatteryStatus {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerPeripheralBatteryStatus {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerPeripheralBatteryStatus {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerPeripheralBatteryStatus {
+    const NAME: &'static str = "PeripheralBatteryStatus";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerPowerSupplyPoll {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerPowerSupplyPoll {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerPowerSupplyPoll {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerPowerSupplyPoll {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerPowerSupplyPoll {
+    const NAME: &'static str = "PowerSupplyPoll";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerLidOpened {
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerLidOpened {
+    fn append(&self, _: &mut arg::IterAppend) {
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerLidOpened {
+    fn read(_: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerLidOpened {
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerLidOpened {
+    const NAME: &'static str = "LidOpened";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerLidClosed {
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerLidClosed {
+    fn append(&self, _: &mut arg::IterAppend) {
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerLidClosed {
+    fn read(_: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerLidClosed {
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerLidClosed {
+    const NAME: &'static str = "LidClosed";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerSuspendImminent {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerSuspendImminent {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerSuspendImminent {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerSuspendImminent {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerSuspendImminent {
+    const NAME: &'static str = "SuspendImminent";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerSuspendDone {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerSuspendDone {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerSuspendDone {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerSuspendDone {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerSuspendDone {
+    const NAME: &'static str = "SuspendDone";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerDarkSuspendImminent {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerDarkSuspendImminent {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerDarkSuspendImminent {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerDarkSuspendImminent {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerDarkSuspendImminent {
+    const NAME: &'static str = "DarkSuspendImminent";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerInputEvent {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerInputEvent {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerInputEvent {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerInputEvent {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerInputEvent {
+    const NAME: &'static str = "InputEvent";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerIdleActionImminent {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerIdleActionImminent {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerIdleActionImminent {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerIdleActionImminent {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerIdleActionImminent {
+    const NAME: &'static str = "IdleActionImminent";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerIdleActionDeferred {
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerIdleActionDeferred {
+    fn append(&self, _: &mut arg::IterAppend) {
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerIdleActionDeferred {
+    fn read(_: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerIdleActionDeferred {
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerIdleActionDeferred {
+    const NAME: &'static str = "IdleActionDeferred";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerScreenIdleStateChanged {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerScreenIdleStateChanged {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerScreenIdleStateChanged {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerScreenIdleStateChanged {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerScreenIdleStateChanged {
+    const NAME: &'static str = "ScreenIdleStateChanged";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerInactivityDelaysChanged {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerInactivityDelaysChanged {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerInactivityDelaysChanged {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerInactivityDelaysChanged {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerInactivityDelaysChanged {
+    const NAME: &'static str = "InactivityDelaysChanged";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerAmbientColorTemperatureChanged {
+    pub color_temp: u32,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerAmbientColorTemperatureChanged {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.color_temp, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerAmbientColorTemperatureChanged {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerAmbientColorTemperatureChanged {
+            color_temp: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerAmbientColorTemperatureChanged {
+    const NAME: &'static str = "AmbientColorTemperatureChanged";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerThermalEvent {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerThermalEvent {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerThermalEvent {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerThermalEvent {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerThermalEvent {
+    const NAME: &'static str = "ThermalEvent";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+#[derive(Debug)]
+pub struct OrgChromiumPowerManagerAmbientLightSensorEnabledChanged {
+    pub serialized_proto: Vec<u8>,
+}
+
+impl arg::AppendAll for OrgChromiumPowerManagerAmbientLightSensorEnabledChanged {
+    fn append(&self, i: &mut arg::IterAppend) {
+        arg::RefArg::append(&self.serialized_proto, i);
+    }
+}
+
+impl arg::ReadAll for OrgChromiumPowerManagerAmbientLightSensorEnabledChanged {
+    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
+        Ok(OrgChromiumPowerManagerAmbientLightSensorEnabledChanged {
+            serialized_proto: i.read()?,
+        })
+    }
+}
+
+impl dbus::message::SignalArgs for OrgChromiumPowerManagerAmbientLightSensorEnabledChanged {
+    const NAME: &'static str = "AmbientLightSensorEnabledChanged";
+    const INTERFACE: &'static str = "org.chromium.PowerManager";
+}
+
+impl<'a, T: blocking::BlockingSender, C: ::std::ops::Deref<Target=T>> OrgChromiumPowerManager for blocking::Proxy<'a, C> {
+
+    fn request_shutdown(&self, reason: i32, description: &str) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "RequestShutdown", (reason, description, ))
+    }
+
+    fn request_restart(&self, reason: i32, description: &str) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "RequestRestart", (reason, description, ))
+    }
+
+    fn change_wifi_reg_domain(&self, domain: i32) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "ChangeWifiRegDomain", (domain, ))
+    }
+
+    fn request_suspend(&self, external_wakeup_count: u64, wakeup_timeout: i32, suspend_flavor: u32) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "RequestSuspend", (external_wakeup_count, wakeup_timeout, suspend_flavor, ))
+    }
+
+    fn set_screen_brightness(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "SetScreenBrightness", (serialized_proto, ))
+    }
+
+    fn decrease_screen_brightness(&self, allow_off: bool) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "DecreaseScreenBrightness", (allow_off, ))
+    }
+
+    fn increase_screen_brightness(&self) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "IncreaseScreenBrightness", ())
+    }
+
+    fn get_screen_brightness_percent(&self) -> Result<f64, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "GetScreenBrightnessPercent", ())
+            .and_then(|r: (f64, )| Ok(r.0, ))
+    }
+
+    fn has_keyboard_backlight(&self) -> Result<bool, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "HasKeyboardBacklight", ())
+            .and_then(|r: (bool, )| Ok(r.0, ))
+    }
+
+    fn decrease_keyboard_brightness(&self) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "DecreaseKeyboardBrightness", ())
+    }
+
+    fn increase_keyboard_brightness(&self) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "IncreaseKeyboardBrightness", ())
+    }
+
+    fn toggle_keyboard_backlight(&self) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "ToggleKeyboardBacklight", ())
+    }
+
+    fn set_keyboard_brightness(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "SetKeyboardBrightness", (serialized_proto, ))
+    }
+
+    fn get_keyboard_brightness_percent(&self) -> Result<f64, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "GetKeyboardBrightnessPercent", ())
+            .and_then(|r: (f64, )| Ok(r.0, ))
+    }
+
+    fn set_keyboard_ambient_light_sensor_enabled(&self, enabled: bool) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "SetKeyboardAmbientLightSensorEnabled", (enabled, ))
+    }
+
+    fn get_power_supply_properties(&self) -> Result<Vec<u8>, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "GetPowerSupplyProperties", ())
+            .and_then(|r: (Vec<u8>, )| Ok(r.0, ))
+    }
+
+    fn get_battery_state(&self) -> Result<(u32, u32, f64), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "GetBatteryState", ())
+    }
+
+    fn handle_video_activity(&self, fullscreen: bool) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "HandleVideoActivity", (fullscreen, ))
+    }
+
+    fn handle_user_activity(&self, type_: i32) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "HandleUserActivity", (type_, ))
+    }
+
+    fn set_is_projecting(&self, is_projecting: bool) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "SetIsProjecting", (is_projecting, ))
+    }
+
+    fn set_policy(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "SetPolicy", (serialized_proto, ))
+    }
+
+    fn set_power_source(&self, id: &str) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "SetPowerSource", (id, ))
+    }
+
+    fn handle_power_button_acknowledgment(&self, timestamp_internal: i64) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "HandlePowerButtonAcknowledgment", (timestamp_internal, ))
+    }
+
+    fn ignore_next_power_button_press(&self, timeout_internal: i64) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "IgnoreNextPowerButtonPress", (timeout_internal, ))
+    }
+
+    fn register_suspend_delay(&self, serialized_request_proto: Vec<u8>) -> Result<Vec<u8>, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "RegisterSuspendDelay", (serialized_request_proto, ))
+            .and_then(|r: (Vec<u8>, )| Ok(r.0, ))
+    }
+
+    fn unregister_suspend_delay(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "UnregisterSuspendDelay", (serialized_proto, ))
+    }
+
+    fn handle_suspend_readiness(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "HandleSuspendReadiness", (serialized_proto, ))
+    }
+
+    fn register_dark_suspend_delay(&self, serialized_request_proto: Vec<u8>) -> Result<Vec<u8>, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "RegisterDarkSuspendDelay", (serialized_request_proto, ))
+            .and_then(|r: (Vec<u8>, )| Ok(r.0, ))
+    }
+
+    fn unregister_dark_suspend_delay(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "UnregisterDarkSuspendDelay", (serialized_proto, ))
+    }
+
+    fn handle_dark_suspend_readiness(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "HandleDarkSuspendReadiness", (serialized_proto, ))
+    }
+
+    fn record_dark_resume_wake_reason(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "RecordDarkResumeWakeReason", (serialized_proto, ))
+    }
+
+    fn get_inactivity_delays(&self) -> Result<Vec<u8>, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "GetInactivityDelays", ())
+            .and_then(|r: (Vec<u8>, )| Ok(r.0, ))
+    }
+
+    fn has_ambient_color_device(&self) -> Result<bool, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "HasAmbientColorDevice", ())
+            .and_then(|r: (bool, )| Ok(r.0, ))
+    }
+
+    fn get_thermal_state(&self) -> Result<Vec<u8>, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "GetThermalState", ())
+            .and_then(|r: (Vec<u8>, )| Ok(r.0, ))
+    }
+
+    fn set_external_display_alsbrightness(&self, enabled: bool) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "SetExternalDisplayALSBrightness", (enabled, ))
+    }
+
+    fn get_external_display_alsbrightness(&self) -> Result<bool, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "GetExternalDisplayALSBrightness", ())
+            .and_then(|r: (bool, )| Ok(r.0, ))
+    }
+
+    fn charge_now_for_adaptive_charging(&self) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "ChargeNowForAdaptiveCharging", ())
+    }
+
+    fn get_charge_history(&self) -> Result<Vec<u8>, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "GetChargeHistory", ())
+            .and_then(|r: (Vec<u8>, )| Ok(r.0, ))
+    }
+
+    fn get_battery_saver_mode_state(&self) -> Result<Vec<u8>, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "GetBatterySaverModeState", ())
+            .and_then(|r: (Vec<u8>, )| Ok(r.0, ))
+    }
+
+    fn set_battery_saver_mode_state(&self, serialized_proto: Vec<u8>) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "SetBatterySaverModeState", (serialized_proto, ))
+    }
+
+    fn has_ambient_light_sensor(&self) -> Result<bool, dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "HasAmbientLightSensor", ())
+            .and_then(|r: (bool, )| Ok(r.0, ))
+    }
+
+    fn set_ambient_light_sensor_enabled(&self, enabled: bool) -> Result<(), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "SetAmbientLightSensorEnabled", (enabled, ))
+    }
+
+    fn battery_state_poll(&self) -> Result<(u32, u32, f64), dbus::Error> {
+        self.method_call("org.chromium.PowerManager", "BatteryStatePoll", ())
+    }
+}
diff --git a/system_api/src/bindings/client/org_chromium_spaced.rs b/system_api/src/bindings/client/org_chromium_spaced.rs
index f07c1fa33..3409f94a3 100644
--- a/system_api/src/bindings/client/org_chromium_spaced.rs
+++ b/system_api/src/bindings/client/org_chromium_spaced.rs
@@ -12,6 +12,9 @@ pub trait OrgChromiumSpaced {
     fn get_quota_current_space_for_uid(&self, path: &str, uid: u32) -> Result<i64, dbus::Error>;
     fn get_quota_current_space_for_gid(&self, path: &str, gid: u32) -> Result<i64, dbus::Error>;
     fn get_quota_current_space_for_project_id(&self, path: &str, project_id: u32) -> Result<i64, dbus::Error>;
+    fn get_quota_current_spaces_for_ids(&self, request: Vec<u8>) -> Result<Vec<u8>, dbus::Error>;
+    fn get_quota_overall_usage(&self, path: &str) -> Result<Vec<u8>, dbus::Error>;
+    fn get_quota_overall_usage_pretty_print(&self, path: &str) -> Result<String, dbus::Error>;
     fn set_project_id(&self, fd: arg::OwnedFd, project_id: u32) -> Result<Vec<u8>, dbus::Error>;
     fn set_project_inheritance_flag(&self, fd: arg::OwnedFd, enable: bool) -> Result<Vec<u8>, dbus::Error>;
 }
@@ -77,6 +80,21 @@ impl<'a, T: blocking::BlockingSender, C: ::std::ops::Deref<Target=T>> OrgChromiu
             .and_then(|r: (i64, )| Ok(r.0, ))
     }
 
+    fn get_quota_current_spaces_for_ids(&self, request: Vec<u8>) -> Result<Vec<u8>, dbus::Error> {
+        self.method_call("org.chromium.Spaced", "GetQuotaCurrentSpacesForIds", (request, ))
+            .and_then(|r: (Vec<u8>, )| Ok(r.0, ))
+    }
+
+    fn get_quota_overall_usage(&self, path: &str) -> Result<Vec<u8>, dbus::Error> {
+        self.method_call("org.chromium.Spaced", "GetQuotaOverallUsage", (path, ))
+            .and_then(|r: (Vec<u8>, )| Ok(r.0, ))
+    }
+
+    fn get_quota_overall_usage_pretty_print(&self, path: &str) -> Result<String, dbus::Error> {
+        self.method_call("org.chromium.Spaced", "GetQuotaOverallUsagePrettyPrint", (path, ))
+            .and_then(|r: (String, )| Ok(r.0, ))
+    }
+
     fn set_project_id(&self, fd: arg::OwnedFd, project_id: u32) -> Result<Vec<u8>, dbus::Error> {
         self.method_call("org.chromium.Spaced", "SetProjectId", (fd, project_id, ))
             .and_then(|r: (Vec<u8>, )| Ok(r.0, ))
diff --git a/system_api/src/bindings/include_modules.rs b/system_api/src/bindings/include_modules.rs
index 96c368233..c5b8bf9d4 100644
--- a/system_api/src/bindings/include_modules.rs
+++ b/system_api/src/bindings/include_modules.rs
@@ -5,4 +5,6 @@ pub mod client {
   pub use org_chromium_spaced::*;
   pub mod org_chromium_vtpm;
   pub use org_chromium_vtpm::*;
+  pub mod org_chromium_power_manager;
+  pub use org_chromium_power_manager::*;
 }
diff --git a/system_api/src/protos/spaced.rs b/system_api/src/protos/spaced.rs
index 2df2193fa..b19aeb714 100644
--- a/system_api/src/protos/spaced.rs
+++ b/system_api/src/protos/spaced.rs
@@ -1,5 +1,5 @@
-// This file is generated by rust-protobuf 3.2.0. Do not edit
-// .proto file is parsed by protoc 3.21.9
+// This file is generated by rust-protobuf 3.6.0. Do not edit
+// .proto file is parsed by protoc 3.21.12
 // @generated
 
 // https://github.com/rust-lang/rust-clippy/issues/702
@@ -9,7 +9,6 @@
 #![allow(unused_attributes)]
 #![cfg_attr(rustfmt, rustfmt::skip)]
 
-#![allow(box_pointers)]
 #![allow(dead_code)]
 #![allow(missing_docs)]
 #![allow(non_camel_case_types)]
@@ -24,10 +23,10 @@
 
 /// Generated files are compatible only with the same version
 /// of protobuf runtime.
-const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_2_0;
+const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_6_0;
 
-#[derive(PartialEq,Clone,Default,Debug)]
 // @@protoc_insertion_point(message:spaced.SetProjectIdReply)
+#[derive(PartialEq,Clone,Default,Debug)]
 pub struct SetProjectIdReply {
     // message fields
     // @@protoc_insertion_point(field:spaced.SetProjectIdReply.success)
@@ -129,8 +128,8 @@ impl ::protobuf::Message for SetProjectIdReply {
     }
 }
 
-#[derive(PartialEq,Clone,Default,Debug)]
 // @@protoc_insertion_point(message:spaced.SetProjectInheritanceFlagReply)
+#[derive(PartialEq,Clone,Default,Debug)]
 pub struct SetProjectInheritanceFlagReply {
     // message fields
     // @@protoc_insertion_point(field:spaced.SetProjectInheritanceFlagReply.success)
@@ -232,8 +231,8 @@ impl ::protobuf::Message for SetProjectInheritanceFlagReply {
     }
 }
 
-#[derive(PartialEq,Clone,Default,Debug)]
 // @@protoc_insertion_point(message:spaced.StatefulDiskSpaceUpdate)
+#[derive(PartialEq,Clone,Default,Debug)]
 pub struct StatefulDiskSpaceUpdate {
     // message fields
     // @@protoc_insertion_point(field:spaced.StatefulDiskSpaceUpdate.state)
@@ -335,6 +334,306 @@ impl ::protobuf::Message for StatefulDiskSpaceUpdate {
     }
 }
 
+// @@protoc_insertion_point(message:spaced.GetQuotaCurrentSpacesForIdsRequest)
+#[derive(PartialEq,Clone,Default,Debug)]
+pub struct GetQuotaCurrentSpacesForIdsRequest {
+    // message fields
+    // @@protoc_insertion_point(field:spaced.GetQuotaCurrentSpacesForIdsRequest.path)
+    pub path: ::std::string::String,
+    // @@protoc_insertion_point(field:spaced.GetQuotaCurrentSpacesForIdsRequest.uids)
+    pub uids: ::std::vec::Vec<u32>,
+    // @@protoc_insertion_point(field:spaced.GetQuotaCurrentSpacesForIdsRequest.gids)
+    pub gids: ::std::vec::Vec<u32>,
+    // @@protoc_insertion_point(field:spaced.GetQuotaCurrentSpacesForIdsRequest.project_ids)
+    pub project_ids: ::std::vec::Vec<u32>,
+    // special fields
+    // @@protoc_insertion_point(special_field:spaced.GetQuotaCurrentSpacesForIdsRequest.special_fields)
+    pub special_fields: ::protobuf::SpecialFields,
+}
+
+impl<'a> ::std::default::Default for &'a GetQuotaCurrentSpacesForIdsRequest {
+    fn default() -> &'a GetQuotaCurrentSpacesForIdsRequest {
+        <GetQuotaCurrentSpacesForIdsRequest as ::protobuf::Message>::default_instance()
+    }
+}
+
+impl GetQuotaCurrentSpacesForIdsRequest {
+    pub fn new() -> GetQuotaCurrentSpacesForIdsRequest {
+        ::std::default::Default::default()
+    }
+}
+
+impl ::protobuf::Message for GetQuotaCurrentSpacesForIdsRequest {
+    const NAME: &'static str = "GetQuotaCurrentSpacesForIdsRequest";
+
+    fn is_initialized(&self) -> bool {
+        true
+    }
+
+    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
+        while let Some(tag) = is.read_raw_tag_or_eof()? {
+            match tag {
+                10 => {
+                    self.path = is.read_string()?;
+                },
+                18 => {
+                    is.read_repeated_packed_uint32_into(&mut self.uids)?;
+                },
+                16 => {
+                    self.uids.push(is.read_uint32()?);
+                },
+                26 => {
+                    is.read_repeated_packed_uint32_into(&mut self.gids)?;
+                },
+                24 => {
+                    self.gids.push(is.read_uint32()?);
+                },
+                34 => {
+                    is.read_repeated_packed_uint32_into(&mut self.project_ids)?;
+                },
+                32 => {
+                    self.project_ids.push(is.read_uint32()?);
+                },
+                tag => {
+                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
+                },
+            };
+        }
+        ::std::result::Result::Ok(())
+    }
+
+    // Compute sizes of nested messages
+    #[allow(unused_variables)]
+    fn compute_size(&self) -> u64 {
+        let mut my_size = 0;
+        if !self.path.is_empty() {
+            my_size += ::protobuf::rt::string_size(1, &self.path);
+        }
+        my_size += ::protobuf::rt::vec_packed_uint32_size(2, &self.uids);
+        my_size += ::protobuf::rt::vec_packed_uint32_size(3, &self.gids);
+        my_size += ::protobuf::rt::vec_packed_uint32_size(4, &self.project_ids);
+        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
+        self.special_fields.cached_size().set(my_size as u32);
+        my_size
+    }
+
+    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
+        if !self.path.is_empty() {
+            os.write_string(1, &self.path)?;
+        }
+        os.write_repeated_packed_uint32(2, &self.uids)?;
+        os.write_repeated_packed_uint32(3, &self.gids)?;
+        os.write_repeated_packed_uint32(4, &self.project_ids)?;
+        os.write_unknown_fields(self.special_fields.unknown_fields())?;
+        ::std::result::Result::Ok(())
+    }
+
+    fn special_fields(&self) -> &::protobuf::SpecialFields {
+        &self.special_fields
+    }
+
+    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
+        &mut self.special_fields
+    }
+
+    fn new() -> GetQuotaCurrentSpacesForIdsRequest {
+        GetQuotaCurrentSpacesForIdsRequest::new()
+    }
+
+    fn clear(&mut self) {
+        self.path.clear();
+        self.uids.clear();
+        self.gids.clear();
+        self.project_ids.clear();
+        self.special_fields.clear();
+    }
+
+    fn default_instance() -> &'static GetQuotaCurrentSpacesForIdsRequest {
+        static instance: GetQuotaCurrentSpacesForIdsRequest = GetQuotaCurrentSpacesForIdsRequest {
+            path: ::std::string::String::new(),
+            uids: ::std::vec::Vec::new(),
+            gids: ::std::vec::Vec::new(),
+            project_ids: ::std::vec::Vec::new(),
+            special_fields: ::protobuf::SpecialFields::new(),
+        };
+        &instance
+    }
+}
+
+// @@protoc_insertion_point(message:spaced.GetQuotaCurrentSpacesForIdsReply)
+#[derive(PartialEq,Clone,Default,Debug)]
+pub struct GetQuotaCurrentSpacesForIdsReply {
+    // message fields
+    // @@protoc_insertion_point(field:spaced.GetQuotaCurrentSpacesForIdsReply.curspaces_for_uids)
+    pub curspaces_for_uids: ::std::collections::HashMap<u32, i64>,
+    // @@protoc_insertion_point(field:spaced.GetQuotaCurrentSpacesForIdsReply.curspaces_for_gids)
+    pub curspaces_for_gids: ::std::collections::HashMap<u32, i64>,
+    // @@protoc_insertion_point(field:spaced.GetQuotaCurrentSpacesForIdsReply.curspaces_for_project_ids)
+    pub curspaces_for_project_ids: ::std::collections::HashMap<u32, i64>,
+    // special fields
+    // @@protoc_insertion_point(special_field:spaced.GetQuotaCurrentSpacesForIdsReply.special_fields)
+    pub special_fields: ::protobuf::SpecialFields,
+}
+
+impl<'a> ::std::default::Default for &'a GetQuotaCurrentSpacesForIdsReply {
+    fn default() -> &'a GetQuotaCurrentSpacesForIdsReply {
+        <GetQuotaCurrentSpacesForIdsReply as ::protobuf::Message>::default_instance()
+    }
+}
+
+impl GetQuotaCurrentSpacesForIdsReply {
+    pub fn new() -> GetQuotaCurrentSpacesForIdsReply {
+        ::std::default::Default::default()
+    }
+}
+
+impl ::protobuf::Message for GetQuotaCurrentSpacesForIdsReply {
+    const NAME: &'static str = "GetQuotaCurrentSpacesForIdsReply";
+
+    fn is_initialized(&self) -> bool {
+        true
+    }
+
+    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
+        while let Some(tag) = is.read_raw_tag_or_eof()? {
+            match tag {
+                10 => {
+                    let len = is.read_raw_varint32()?;
+                    let old_limit = is.push_limit(len as u64)?;
+                    let mut key = ::std::default::Default::default();
+                    let mut value = ::std::default::Default::default();
+                    while let Some(tag) = is.read_raw_tag_or_eof()? {
+                        match tag {
+                            8 => key = is.read_uint32()?,
+                            16 => value = is.read_int64()?,
+                            _ => ::protobuf::rt::skip_field_for_tag(tag, is)?,
+                        };
+                    }
+                    is.pop_limit(old_limit);
+                    self.curspaces_for_uids.insert(key, value);
+                },
+                18 => {
+                    let len = is.read_raw_varint32()?;
+                    let old_limit = is.push_limit(len as u64)?;
+                    let mut key = ::std::default::Default::default();
+                    let mut value = ::std::default::Default::default();
+                    while let Some(tag) = is.read_raw_tag_or_eof()? {
+                        match tag {
+                            8 => key = is.read_uint32()?,
+                            16 => value = is.read_int64()?,
+                            _ => ::protobuf::rt::skip_field_for_tag(tag, is)?,
+                        };
+                    }
+                    is.pop_limit(old_limit);
+                    self.curspaces_for_gids.insert(key, value);
+                },
+                26 => {
+                    let len = is.read_raw_varint32()?;
+                    let old_limit = is.push_limit(len as u64)?;
+                    let mut key = ::std::default::Default::default();
+                    let mut value = ::std::default::Default::default();
+                    while let Some(tag) = is.read_raw_tag_or_eof()? {
+                        match tag {
+                            8 => key = is.read_uint32()?,
+                            16 => value = is.read_int64()?,
+                            _ => ::protobuf::rt::skip_field_for_tag(tag, is)?,
+                        };
+                    }
+                    is.pop_limit(old_limit);
+                    self.curspaces_for_project_ids.insert(key, value);
+                },
+                tag => {
+                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
+                },
+            };
+        }
+        ::std::result::Result::Ok(())
+    }
+
+    // Compute sizes of nested messages
+    #[allow(unused_variables)]
+    fn compute_size(&self) -> u64 {
+        let mut my_size = 0;
+        for (k, v) in &self.curspaces_for_uids {
+            let mut entry_size = 0;
+            entry_size += ::protobuf::rt::uint32_size(1, *k);
+            entry_size += ::protobuf::rt::int64_size(2, *v);
+            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(entry_size) + entry_size
+        };
+        for (k, v) in &self.curspaces_for_gids {
+            let mut entry_size = 0;
+            entry_size += ::protobuf::rt::uint32_size(1, *k);
+            entry_size += ::protobuf::rt::int64_size(2, *v);
+            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(entry_size) + entry_size
+        };
+        for (k, v) in &self.curspaces_for_project_ids {
+            let mut entry_size = 0;
+            entry_size += ::protobuf::rt::uint32_size(1, *k);
+            entry_size += ::protobuf::rt::int64_size(2, *v);
+            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(entry_size) + entry_size
+        };
+        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
+        self.special_fields.cached_size().set(my_size as u32);
+        my_size
+    }
+
+    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
+        for (k, v) in &self.curspaces_for_uids {
+            let mut entry_size = 0;
+            entry_size += ::protobuf::rt::uint32_size(1, *k);
+            entry_size += ::protobuf::rt::int64_size(2, *v);
+            os.write_raw_varint32(10)?; // Tag.
+            os.write_raw_varint32(entry_size as u32)?;
+            os.write_uint32(1, *k)?;
+            os.write_int64(2, *v)?;
+        };
+        for (k, v) in &self.curspaces_for_gids {
+            let mut entry_size = 0;
+            entry_size += ::protobuf::rt::uint32_size(1, *k);
+            entry_size += ::protobuf::rt::int64_size(2, *v);
+            os.write_raw_varint32(18)?; // Tag.
+            os.write_raw_varint32(entry_size as u32)?;
+            os.write_uint32(1, *k)?;
+            os.write_int64(2, *v)?;
+        };
+        for (k, v) in &self.curspaces_for_project_ids {
+            let mut entry_size = 0;
+            entry_size += ::protobuf::rt::uint32_size(1, *k);
+            entry_size += ::protobuf::rt::int64_size(2, *v);
+            os.write_raw_varint32(26)?; // Tag.
+            os.write_raw_varint32(entry_size as u32)?;
+            os.write_uint32(1, *k)?;
+            os.write_int64(2, *v)?;
+        };
+        os.write_unknown_fields(self.special_fields.unknown_fields())?;
+        ::std::result::Result::Ok(())
+    }
+
+    fn special_fields(&self) -> &::protobuf::SpecialFields {
+        &self.special_fields
+    }
+
+    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
+        &mut self.special_fields
+    }
+
+    fn new() -> GetQuotaCurrentSpacesForIdsReply {
+        GetQuotaCurrentSpacesForIdsReply::new()
+    }
+
+    fn clear(&mut self) {
+        self.curspaces_for_uids.clear();
+        self.curspaces_for_gids.clear();
+        self.curspaces_for_project_ids.clear();
+        self.special_fields.clear();
+    }
+
+    fn default_instance() -> &'static GetQuotaCurrentSpacesForIdsReply {
+        static instance: ::protobuf::rt::Lazy<GetQuotaCurrentSpacesForIdsReply> = ::protobuf::rt::Lazy::new();
+        instance.get(GetQuotaCurrentSpacesForIdsReply::new)
+    }
+}
+
 #[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
 // @@protoc_insertion_point(enum:spaced.StatefulDiskSpaceState)
 pub enum StatefulDiskSpaceState {
@@ -365,6 +664,16 @@ impl ::protobuf::Enum for StatefulDiskSpaceState {
         }
     }
 
+    fn from_str(str: &str) -> ::std::option::Option<StatefulDiskSpaceState> {
+        match str {
+            "NONE" => ::std::option::Option::Some(StatefulDiskSpaceState::NONE),
+            "NORMAL" => ::std::option::Option::Some(StatefulDiskSpaceState::NORMAL),
+            "LOW" => ::std::option::Option::Some(StatefulDiskSpaceState::LOW),
+            "CRITICAL" => ::std::option::Option::Some(StatefulDiskSpaceState::CRITICAL),
+            _ => ::std::option::Option::None
+        }
+    }
+
     const VALUES: &'static [StatefulDiskSpaceState] = &[
         StatefulDiskSpaceState::NONE,
         StatefulDiskSpaceState::NORMAL,
diff --git a/system_api/src/protos/vtpm_interface.rs b/system_api/src/protos/vtpm_interface.rs
index 8696f9237..3c9c7963b 100644
--- a/system_api/src/protos/vtpm_interface.rs
+++ b/system_api/src/protos/vtpm_interface.rs
@@ -1,5 +1,5 @@
-// This file is generated by rust-protobuf 3.2.0. Do not edit
-// .proto file is parsed by protoc 3.21.9
+// This file is generated by rust-protobuf 3.6.0. Do not edit
+// .proto file is parsed by protoc 3.21.12
 // @generated
 
 // https://github.com/rust-lang/rust-clippy/issues/702
@@ -9,7 +9,6 @@
 #![allow(unused_attributes)]
 #![cfg_attr(rustfmt, rustfmt::skip)]
 
-#![allow(box_pointers)]
 #![allow(dead_code)]
 #![allow(missing_docs)]
 #![allow(non_camel_case_types)]
@@ -24,10 +23,10 @@
 
 /// Generated files are compatible only with the same version
 /// of protobuf runtime.
-const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_2_0;
+const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_6_0;
 
-#[derive(PartialEq,Clone,Default,Debug)]
 // @@protoc_insertion_point(message:vtpm.SendCommandRequest)
+#[derive(PartialEq,Clone,Default,Debug)]
 pub struct SendCommandRequest {
     // message fields
     // @@protoc_insertion_point(field:vtpm.SendCommandRequest.command)
@@ -152,8 +151,8 @@ impl ::protobuf::Message for SendCommandRequest {
     }
 }
 
-#[derive(PartialEq,Clone,Default,Debug)]
 // @@protoc_insertion_point(message:vtpm.SendCommandResponse)
+#[derive(PartialEq,Clone,Default,Debug)]
 pub struct SendCommandResponse {
     // message fields
     // @@protoc_insertion_point(field:vtpm.SendCommandResponse.response)
diff --git a/system_api/update_bindings.sh b/system_api/update_bindings.sh
index 7e1a2202b..b433856c4 100755
--- a/system_api/update_bindings.sh
+++ b/system_api/update_bindings.sh
@@ -16,6 +16,7 @@ fi
 FILES=(
     "src/bindings/client/org_chromium_spaced.rs"
     "src/bindings/client/org_chromium_vtpm.rs"
+    "src/bindings/client/org_chromium_power_manager.rs"
     "src/protos/spaced.rs"
     "src/protos/vtpm_interface.rs"
 )
diff --git a/third_party/vmm_vhost/src/backend_client.rs b/third_party/vmm_vhost/src/backend_client.rs
index eee561faa..f091ca9a2 100644
--- a/third_party/vmm_vhost/src/backend_client.rs
+++ b/third_party/vmm_vhost/src/backend_client.rs
@@ -5,8 +5,11 @@ use std::fs::File;
 use std::mem;
 
 use base::AsRawDescriptor;
+#[cfg(windows)]
+use base::CloseNotifier;
 use base::Event;
 use base::RawDescriptor;
+use base::ReadNotifier;
 use base::INVALID_DESCRIPTOR;
 use zerocopy::AsBytes;
 use zerocopy::FromBytes;
@@ -643,6 +646,19 @@ impl BackendClient {
     }
 }
 
+#[cfg(windows)]
+impl CloseNotifier for BackendClient {
+    fn get_close_notifier(&self) -> &dyn AsRawDescriptor {
+        self.connection.0.get_close_notifier()
+    }
+}
+
+impl ReadNotifier for BackendClient {
+    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
+        self.connection.0.get_read_notifier()
+    }
+}
+
 // TODO(b/221882601): likely need pairs of RDs and/or SharedMemory to represent mmaps on Windows.
 /// Context object to pass guest memory configuration to BackendClient::set_mem_table().
 struct VhostUserMemoryContext {
diff --git a/third_party/vmm_vhost/src/message.rs b/third_party/vmm_vhost/src/message.rs
index 9f555d891..04300d223 100644
--- a/third_party/vmm_vhost/src/message.rs
+++ b/third_party/vmm_vhost/src/message.rs
@@ -152,14 +152,6 @@ pub enum FrontendReq {
     CHECK_DEVICE_STATE = 43,
 
     // Non-standard message types.
-    /// Stop all queue handlers and save each queue state.
-    DEPRECATED__SLEEP = 1000,
-    /// Start up all queue handlers with their saved queue state.
-    DEPRECATED__WAKE = 1001,
-    /// Request serialized state of vhost process.
-    DEPRECATED__SNAPSHOT = 1002,
-    /// Request to restore state of vhost process.
-    DEPRECATED__RESTORE = 1003,
     /// Get a list of the device's shared memory regions.
     GET_SHARED_MEMORY_REGIONS = 1004,
 }
diff --git a/third_party/vmm_vhost/src/sys/unix.rs b/third_party/vmm_vhost/src/sys/unix.rs
index 035e633c4..5ad7d3b81 100644
--- a/third_party/vmm_vhost/src/sys/unix.rs
+++ b/third_party/vmm_vhost/src/sys/unix.rs
@@ -16,6 +16,7 @@ use std::path::PathBuf;
 
 use base::AsRawDescriptor;
 use base::RawDescriptor;
+use base::ReadNotifier;
 use base::SafeDescriptor;
 use base::ScmSocket;
 
@@ -243,6 +244,12 @@ impl AsRawDescriptor for SocketPlatformConnection {
     }
 }
 
+impl ReadNotifier for SocketPlatformConnection {
+    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
+        &self.sock
+    }
+}
+
 impl<R: Req> TryFrom<SafeDescriptor> for Connection<R> {
     type Error = Error;
 
@@ -276,12 +283,17 @@ impl<R: Req> Connection<R> {
 }
 
 impl<S: Frontend> AsRawDescriptor for FrontendServer<S> {
-    /// Used for polling.
     fn as_raw_descriptor(&self) -> RawDescriptor {
         self.sub_sock.as_raw_descriptor()
     }
 }
 
+impl<S: Frontend> ReadNotifier for FrontendServer<S> {
+    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
+        self.sub_sock.0.get_read_notifier()
+    }
+}
+
 impl<S: Frontend> FrontendServer<S> {
     /// Create a `FrontendServer` that uses a Unix stream internally.
     ///
diff --git a/third_party/vmm_vhost/src/sys/windows.rs b/third_party/vmm_vhost/src/sys/windows.rs
index 01ba3f0b3..464fb62a1 100644
--- a/third_party/vmm_vhost/src/sys/windows.rs
+++ b/third_party/vmm_vhost/src/sys/windows.rs
@@ -205,6 +205,19 @@ impl AsRawDescriptor for TubePlatformConnection {
     }
 }
 
+impl CloseNotifier for TubePlatformConnection {
+    /// Used for closing.
+    fn get_close_notifier(&self) -> &dyn AsRawDescriptor {
+        self.tube.get_close_notifier()
+    }
+}
+
+impl ReadNotifier for TubePlatformConnection {
+    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
+        self.tube.get_close_notifier()
+    }
+}
+
 impl<S: Frontend> FrontendServer<S> {
     /// Create a `FrontendServer` that uses a Tube internally. Must specify the backend process
     /// which will receive the Tube.
diff --git a/tools/contrib/crosvmdump/src/main.rs b/tools/contrib/crosvmdump/src/main.rs
index 14a58ccc1..3fa87df9b 100644
--- a/tools/contrib/crosvmdump/src/main.rs
+++ b/tools/contrib/crosvmdump/src/main.rs
@@ -215,8 +215,7 @@ fn main() -> Result<()> {
     for (i, line) in commandline_flags.iter().enumerate() {
         match *line {
             "--shared-dir" => shared_dir_params.push(commandline_flags[i + 1]),
-            "--rwdisk" => disk_params.push(commandline_flags[i + 1]),
-            "--disk" => disk_params.push(commandline_flags[i + 1]),
+            "--block" => disk_params.push(commandline_flags[i + 1]),
             "--socket" => socket = commandline_flags[i + 1],
             _ => {
                 // Skip other flags.
diff --git a/tools/custom_checks b/tools/custom_checks
index 17b2efdce..00630fec0 100755
--- a/tools/custom_checks
+++ b/tools/custom_checks
@@ -92,8 +92,14 @@ def check_rust_lockfiles(*files: str):
 # These crosvm features are currently not built upstream. Do not add to this list.
 KNOWN_DISABLED_FEATURES = [
     "default-no-sandbox",
+    "gvm",
     "libvda",
+    "perfetto",
+    "process-invariants",
+    "prod-build",
+    "sandbox",
     "seccomp_trace",
+    "slirp-ring-capture",
     "vulkano",
     "whpx",
 ]
diff --git a/tools/install-deps b/tools/install-deps
index 9bf5bbb97..e326cc894 100755
--- a/tools/install-deps
+++ b/tools/install-deps
@@ -101,3 +101,11 @@ cargo binstall --no-confirm mdbook-linkcheck --version "0.7.7"
 
 # Nextest is an improved test runner for cargo
 cargo binstall --no-confirm cargo-nextest --version "0.9.49"
+
+Red='\033[0;31m'
+Reset='\033[0m'
+# Check if submodules were initialized. If a submodule is not initialized, git
+# submodule status will be prefixed with `-`
+if git submodule status | grep '^-'; then
+    >&2 echo -e "${Red}ERROR${Reset}: Git modules were not initialized. Run 'git submodule update --init' to initialize them."
+fi
diff --git a/usb_sys/src/lib.rs b/usb_sys/src/lib.rs
index 897df07a9..90b25bff1 100644
--- a/usb_sys/src/lib.rs
+++ b/usb_sys/src/lib.rs
@@ -9,6 +9,7 @@
 #![allow(non_upper_case_globals)]
 #![allow(non_camel_case_types)]
 #![allow(non_snake_case)]
+#![allow(dead_code)]
 
 use std::os::raw::c_char;
 use std::os::raw::c_int;
diff --git a/vhost/src/lib.rs b/vhost/src/lib.rs
index b474bf2f7..cb57e662e 100644
--- a/vhost/src/lib.rs
+++ b/vhost/src/lib.rs
@@ -202,42 +202,6 @@ pub trait Vhost: AsRawDescriptor + std::marker::Sized {
         Ok(())
     }
 
-    // TODO(smbarber): This is copypasta. Eliminate the copypasta.
-    #[allow(clippy::if_same_then_else)]
-    fn is_valid(
-        &self,
-        mem: &GuestMemory,
-        queue_max_size: u16,
-        queue_size: u16,
-        desc_addr: GuestAddress,
-        avail_addr: GuestAddress,
-        used_addr: GuestAddress,
-    ) -> bool {
-        let desc_table_size = 16 * queue_size as usize;
-        let avail_ring_size = 6 + 2 * queue_size as usize;
-        let used_ring_size = 6 + 8 * queue_size as usize;
-        if queue_size > queue_max_size || queue_size == 0 || (queue_size & (queue_size - 1)) != 0 {
-            false
-        } else if desc_addr
-            .checked_add(desc_table_size as u64)
-            .map_or(true, |v| !mem.address_in_range(v))
-        {
-            false
-        } else if avail_addr
-            .checked_add(avail_ring_size as u64)
-            .map_or(true, |v| !mem.address_in_range(v))
-        {
-            false
-        } else if used_addr
-            .checked_add(used_ring_size as u64)
-            .map_or(true, |v| !mem.address_in_range(v))
-        {
-            false
-        } else {
-            true
-        }
-    }
-
     /// Set the addresses for a given vring.
     ///
     /// # Arguments
@@ -261,28 +225,27 @@ pub trait Vhost: AsRawDescriptor + std::marker::Sized {
         avail_addr: GuestAddress,
         log_addr: Option<GuestAddress>,
     ) -> Result<()> {
-        // TODO(smbarber): Refactor out virtio from crosvm so we can
-        // validate a Queue struct directly.
-        if !self.is_valid(
-            mem,
-            queue_max_size,
-            queue_size,
-            desc_addr,
-            used_addr,
-            avail_addr,
-        ) {
+        if queue_size > queue_max_size || queue_size == 0 || !queue_size.is_power_of_two() {
             return Err(Error::InvalidQueue);
         }
 
-        let desc_addr = mem
-            .get_host_address(desc_addr)
+        let queue_size = usize::from(queue_size);
+
+        let desc_table_size = 16 * queue_size;
+        let desc_table = mem
+            .get_slice_at_addr(desc_addr, desc_table_size)
             .map_err(Error::DescriptorTableAddress)?;
-        let used_addr = mem
-            .get_host_address(used_addr)
+
+        let used_ring_size = 6 + 8 * queue_size;
+        let used_ring = mem
+            .get_slice_at_addr(used_addr, used_ring_size)
             .map_err(Error::UsedAddress)?;
-        let avail_addr = mem
-            .get_host_address(avail_addr)
+
+        let avail_ring_size = 6 + 2 * queue_size;
+        let avail_ring = mem
+            .get_slice_at_addr(avail_addr, avail_ring_size)
             .map_err(Error::AvailAddress)?;
+
         let log_addr = match log_addr {
             None => null(),
             Some(a) => mem.get_host_address(a).map_err(Error::LogAddress)?,
@@ -291,9 +254,9 @@ pub trait Vhost: AsRawDescriptor + std::marker::Sized {
         let vring_addr = virtio_sys::vhost::vhost_vring_addr {
             index: queue_index as u32,
             flags,
-            desc_user_addr: desc_addr as u64,
-            used_user_addr: used_addr as u64,
-            avail_user_addr: avail_addr as u64,
+            desc_user_addr: desc_table.as_ptr() as u64,
+            used_user_addr: used_ring.as_ptr() as u64,
+            avail_user_addr: avail_ring.as_ptr() as u64,
             log_guest_addr: log_addr as u64,
         };
 
diff --git a/virtio_sys/bindgen.sh b/virtio_sys/bindgen.sh
index 7dcefd904..b3d9609c6 100755
--- a/virtio_sys/bindgen.sh
+++ b/virtio_sys/bindgen.sh
@@ -58,6 +58,8 @@ VIRTIO_IDS_EXTRAS="
 // Added by virtio_sys/bindgen.sh - do not edit the generated file.
 // TODO(b/236144983): Fix this id when an official virtio-id is assigned to this device.
 pub const VIRTIO_ID_PVCLOCK: u32 = 61;
+// TODO: Remove this once the ID is included in the Linux headers.
+pub const VIRTIO_ID_MEDIA: u32 = 48;
 "
 
 bindgen_generate \
diff --git a/virtio_sys/src/virtio_ids.rs b/virtio_sys/src/virtio_ids.rs
index d85025666..f77fea955 100644
--- a/virtio_sys/src/virtio_ids.rs
+++ b/virtio_sys/src/virtio_ids.rs
@@ -14,6 +14,8 @@
 // Added by virtio_sys/bindgen.sh - do not edit the generated file.
 // TODO(b/236144983): Fix this id when an official virtio-id is assigned to this device.
 pub const VIRTIO_ID_PVCLOCK: u32 = 61;
+// TODO: Remove this once the ID is included in the Linux headers.
+pub const VIRTIO_ID_MEDIA: u32 = 48;
 
 pub const VIRTIO_ID_NET: u32 = 1;
 pub const VIRTIO_ID_BLOCK: u32 = 2;
diff --git a/vm_control/Android.bp b/vm_control/Android.bp
index 0f6930708..d76104a6a 100644
--- a/vm_control/Android.bp
+++ b/vm_control/Android.bp
@@ -52,7 +52,6 @@ rust_library {
     ],
     proc_macros: ["libremain"],
     aliases: ["crypto_generic:crypto"],
-    visibility: ["//packages/modules/Virtualization/android/virtmgr"],
 }
 
 rust_test {
diff --git a/vm_control/src/lib.rs b/vm_control/src/lib.rs
index 886c59c03..5f91cb54e 100644
--- a/vm_control/src/lib.rs
+++ b/vm_control/src/lib.rs
@@ -141,6 +141,8 @@ pub enum VcpuControl {
     // the channel after completion/failure.
     Snapshot(SnapshotWriter, mpsc::Sender<anyhow::Result<()>>),
     Restore(VcpuRestoreRequest),
+    #[cfg(any(target_os = "android", target_os = "linux"))]
+    Throttle(u32),
 }
 
 /// Request to restore a Vcpu from a given snapshot, and report the results
@@ -647,7 +649,7 @@ enum RegisteredMemory {
 }
 
 pub struct VmMappedMemoryRegion {
-    gfn: u64,
+    guest_address: GuestAddress,
     slot: MemSlot,
 }
 
@@ -672,7 +674,10 @@ fn try_map_to_prepared_region(
         return None;
     };
 
-    let VmMappedMemoryRegion { gfn, slot } = region_state.mapped_regions.get(allocation)?;
+    let VmMappedMemoryRegion {
+        guest_address,
+        slot,
+    } = region_state.mapped_regions.get(allocation)?;
 
     let (descriptor, file_offset, size) = match source {
         VmMemorySource::Descriptor {
@@ -707,8 +712,8 @@ fn try_map_to_prepared_region(
         return Some(VmMemoryResponse::Err(err));
     }
 
-    let gfn = gfn + (dest_offset >> 12);
-    let region_id = VmMemoryRegionId(gfn);
+    let guest_address = GuestAddress(guest_address.0 + dest_offset);
+    let region_id = VmMemoryRegionId(guest_address);
     region_state.registered_memory.insert(
         region_id,
         RegisteredMemory::FixedMapping {
@@ -802,7 +807,7 @@ impl VmMemoryRequest {
                     Err(e) => return VmMemoryResponse::Err(e),
                 };
 
-                let region_id = VmMemoryRegionId(guest_addr.0 >> 12);
+                let region_id = VmMemoryRegionId(guest_addr);
                 if let (Some(descriptor), Some(iommu_client)) = (descriptor, iommu_client) {
                     let request =
                         VirtioIOMMURequest::VfioCommand(VirtioIOMMUVfioCommand::VfioDmabufMap {
@@ -919,7 +924,7 @@ impl VmMemoryRequest {
                     Err(e) => return VmMemoryResponse::Err(e),
                 };
 
-                let region_id = VmMemoryRegionId(guest_addr.0 >> 12);
+                let region_id = VmMemoryRegionId(guest_addr);
 
                 region_state
                     .registered_memory
@@ -1049,8 +1054,8 @@ impl VmMemoryRequest {
 
 #[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Eq, Ord, Clone, Copy)]
 /// Identifer for registered memory regions. Globally unique.
-// The current implementation uses gfn as the unique identifier.
-pub struct VmMemoryRegionId(u64);
+// The current implementation uses guest physical address as the unique identifier.
+pub struct VmMemoryRegionId(GuestAddress);
 
 #[derive(Serialize, Deserialize, Debug)]
 pub enum VmMemoryResponse {
@@ -1207,6 +1212,7 @@ pub enum BatControlResult {
     NoSuchStatus,
     NoSuchBatType,
     StringParseIntErr,
+    StringParseBoolErr,
 }
 
 impl Display for BatControlResult {
@@ -1221,6 +1227,7 @@ impl Display for BatControlResult {
             NoSuchStatus => write!(f, "Invalid Battery status setting. Only support: unknown/charging/discharging/notcharging/full"),
             NoSuchBatType => write!(f, "Invalid Battery type setting. Only support: goldfish"),
             StringParseIntErr => write!(f, "Battery property target ParseInt error"),
+            StringParseBoolErr => write!(f, "Battery property target ParseBool error"),
         }
     }
 }
@@ -1250,6 +1257,8 @@ pub enum BatProperty {
     Present,
     Capacity,
     ACOnline,
+    SetFakeBatConfig,
+    CancelFakeBatConfig,
 }
 
 impl FromStr for BatProperty {
@@ -1262,11 +1271,27 @@ impl FromStr for BatProperty {
             "present" => Ok(BatProperty::Present),
             "capacity" => Ok(BatProperty::Capacity),
             "aconline" => Ok(BatProperty::ACOnline),
+            "set_fake_bat_config" => Ok(BatProperty::SetFakeBatConfig),
+            "cancel_fake_bat_config" => Ok(BatProperty::CancelFakeBatConfig),
             _ => Err(BatControlResult::NoSuchProperty),
         }
     }
 }
 
+impl Display for BatProperty {
+    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
+        match *self {
+            BatProperty::Status => write!(f, "status"),
+            BatProperty::Health => write!(f, "health"),
+            BatProperty::Present => write!(f, "present"),
+            BatProperty::Capacity => write!(f, "capacity"),
+            BatProperty::ACOnline => write!(f, "aconline"),
+            BatProperty::SetFakeBatConfig => write!(f, "set_fake_bat_config"),
+            BatProperty::CancelFakeBatConfig => write!(f, "cancel_fake_bat_config"),
+        }
+    }
+}
+
 #[derive(Serialize, Deserialize, Debug)]
 pub enum BatStatus {
     Unknown,
@@ -1350,6 +1375,21 @@ impl From<BatHealth> for u32 {
     }
 }
 
+/// Configuration of fake battery status information.
+#[derive(Serialize, Deserialize, Debug, Default)]
+pub enum BatConfig {
+    // Propagates host's battery status
+    #[default]
+    Real,
+    // Fake on battery status. Simulates a disconnected AC adapter.
+    // This forces ac_online to false and sets the battery status
+    // to DISCHARGING
+    Fake {
+        // Sets the maximum battery capacity reported to the guest
+        max_capacity: u32,
+    },
+}
+
 #[derive(Serialize, Deserialize, Debug)]
 pub enum BatControlCommand {
     SetStatus(BatStatus),
@@ -1357,6 +1397,8 @@ pub enum BatControlCommand {
     SetPresent(u32),
     SetCapacity(u32),
     SetACOnline(u32),
+    SetFakeBatConfig(u32),
+    CancelFakeConfig,
 }
 
 impl BatControlCommand {
@@ -1380,6 +1422,12 @@ impl BatControlCommand {
                     .parse::<u32>()
                     .map_err(|_| BatControlResult::StringParseIntErr)?,
             )),
+            BatProperty::SetFakeBatConfig => Ok(BatControlCommand::SetFakeBatConfig(
+                target
+                    .parse::<u32>()
+                    .map_err(|_| BatControlResult::StringParseIntErr)?,
+            )),
+            BatProperty::CancelFakeBatConfig => Ok(BatControlCommand::CancelFakeConfig),
         }
     }
 }
@@ -1505,6 +1553,8 @@ pub enum VmRequest {
     ResumeVm,
     /// Returns Vcpus PID/TID
     VcpuPidTid,
+    /// Throttles the requested vCPU for microseconds
+    Throttle(usize, u32),
 }
 
 /// NOTE: when making any changes to this enum please also update
@@ -1783,6 +1833,7 @@ impl VmRequest {
         usb_control_tube: Option<&Tube>,
         bat_control: &mut Option<BatControl>,
         kick_vcpus: impl Fn(VcpuControl),
+        #[cfg(any(target_os = "android", target_os = "linux"))] kick_vcpu: impl Fn(usize, VcpuControl),
         force_s2idle: bool,
         #[cfg(feature = "swap")] swap_controller: Option<&swap::SwapController>,
         device_control_tube: &Tube,
@@ -2209,6 +2260,7 @@ impl VmRequest {
             } => VmResponse::Ok,
             VmRequest::Unregister { socket_addr: _ } => VmResponse::Ok,
             VmRequest::VcpuPidTid => unreachable!(),
+            VmRequest::Throttle(_, _) => unreachable!(),
         }
     }
 }
@@ -2417,9 +2469,8 @@ pub enum VmResponse {
     Err(SysError),
     /// Indicates the request encountered some error during execution.
     ErrString(String),
-    /// The request to register memory into guest address space was successfully done at guest page
-    /// frame number `gfn` and memory slot number `slot`.
-    RegisterMemory { gfn: u64, slot: u32 },
+    /// The memory was registered into guest address space in memory slot number `slot`.
+    RegisterMemory { slot: u32 },
     /// Results of balloon control commands.
     #[cfg(feature = "balloon")]
     BalloonStats {
@@ -2460,11 +2511,7 @@ impl Display for VmResponse {
             Ok => write!(f, "ok"),
             Err(e) => write!(f, "error: {}", e),
             ErrString(e) => write!(f, "error: {}", e),
-            RegisterMemory { gfn, slot } => write!(
-                f,
-                "memory registered to guest page frame number {:#x} and memory slot {}",
-                gfn, slot
-            ),
+            RegisterMemory { slot } => write!(f, "memory registered in slot {}", slot),
             #[cfg(feature = "balloon")]
             VmResponse::BalloonStats {
                 stats,
diff --git a/vm_control/src/sys/linux.rs b/vm_control/src/sys/linux.rs
index 729749723..5472b0c8a 100644
--- a/vm_control/src/sys/linux.rs
+++ b/vm_control/src/sys/linux.rs
@@ -212,7 +212,7 @@ pub fn prepare_shared_memory_region(
                 cache,
             ) {
                 Ok(slot) => Ok(VmMappedMemoryRegion {
-                    gfn: range.start >> 12,
+                    guest_address: GuestAddress(range.start),
                     slot,
                 }),
                 Err(e) => Err(e),
@@ -255,9 +255,7 @@ impl FsMappingRequest {
                     alloc,
                     MemCacheType::CacheCoherent,
                 ) {
-                    Ok(VmMappedMemoryRegion { gfn, slot }) => {
-                        VmResponse::RegisterMemory { gfn, slot }
-                    }
+                    Ok(VmMappedMemoryRegion { slot, .. }) => VmResponse::RegisterMemory { slot },
                     Err(e) => VmResponse::Err(e),
                 }
             }
diff --git a/win_audio/src/win_audio_impl/async_stream.rs b/win_audio/src/win_audio_impl/async_stream.rs
index f40d55d36..73ef3bcce 100644
--- a/win_audio/src/win_audio_impl/async_stream.rs
+++ b/win_audio/src/win_audio_impl/async_stream.rs
@@ -228,16 +228,11 @@ impl AsyncPlaybackBufferStream for WinAudioRenderer {
                             self.device.guest_frame_rate,
                             self.device.incoming_buffer_size_in_frames,
                         )
-                        .map_err(|e| {
-                            match &e {
-                                RenderError::WinAudioError(win_audio_error) => {
-                                    log_playback_error_with_limit(win_audio_error.into())
-                                }
-                                _ => {
-                                    log_playback_error_with_limit((&WinAudioError::Unknown).into())
-                                }
+                        .inspect_err(|e| match &e {
+                            RenderError::WinAudioError(win_audio_error) => {
+                                log_playback_error_with_limit(win_audio_error.into())
                             }
-                            e
+                            _ => log_playback_error_with_limit((&WinAudioError::Unknown).into()),
                         })?;
                 }
             }
diff --git a/win_audio/src/win_audio_impl/mod.rs b/win_audio/src/win_audio_impl/mod.rs
index e97a52152..9bdae09de 100644
--- a/win_audio/src/win_audio_impl/mod.rs
+++ b/win_audio/src/win_audio_impl/mod.rs
@@ -47,6 +47,7 @@ use base::Error;
 use base::Event;
 use base::EventExt;
 use base::EventWaitResult;
+use base::IntoRawDescriptor;
 use completion_handler::WinAudioActivateAudioInterfaceCompletionHandler;
 use sync::Mutex;
 use thiserror::Error as ThisError;
@@ -1671,13 +1672,10 @@ fn create_and_set_audio_client_event(
     )?;
 
     let async_ready_event = if let Some(ex) = ex {
-        // SAFETY:
-        // Unsafe if `ready_event` and `async_ready_event` have different
-        // lifetimes because both can close the underlying `RawDescriptor`. However, both
-        // will be stored in the `DeviceRenderer` or `DeviceCapturer` fields, so this should be
-        // safe.
+        let ready_event = ready_event.try_clone().map_err(WinAudioError::CloneEvent)?;
+        // SAFETY: ready_event is cloned from an Event. Its RawDescriptor must be also an Event.
         Some(unsafe {
-            ex.async_event(ready_event.as_raw_descriptor())
+            ex.async_event(ready_event.into_raw_descriptor())
                 .map_err(|e| {
                     WinAudioError::AsyncError(e, "Failed to create async event".to_string())
                 })?
diff --git a/x86_64/src/bzimage.rs b/x86_64/src/bzimage.rs
index c8e60e0a8..fed61d1c2 100644
--- a/x86_64/src/bzimage.rs
+++ b/x86_64/src/bzimage.rs
@@ -5,10 +5,12 @@
 //! Loader for bzImage-format Linux kernels as described in
 //! <https://www.kernel.org/doc/Documentation/x86/boot.txt>
 
+use std::cmp::Ordering;
 use std::io;
 use std::mem::offset_of;
 
 use base::debug;
+use base::FileGetLen;
 use base::FileReadWriteAtVolatile;
 use base::VolatileSlice;
 use remain::sorted;
@@ -31,6 +33,8 @@ pub enum Error {
     BadSignature,
     #[error("entry point out of range")]
     EntryPointOutOfRange,
+    #[error("unable to get kernel file size: {0}")]
+    GetFileLen(io::Error),
     #[error("guest memory error {0}")]
     GuestMemoryError(GuestMemoryError),
     #[error("invalid setup_header_end value {0}")]
@@ -62,7 +66,7 @@ pub fn load_bzimage<F>(
     kernel_image: &mut F,
 ) -> Result<(boot_params, u64, GuestAddress, CpuMode)>
 where
-    F: FileReadWriteAtVolatile,
+    F: FileReadWriteAtVolatile + FileGetLen,
 {
     let mut params = boot_params::default();
 
@@ -120,9 +124,29 @@ where
         .checked_mul(16)
         .ok_or(Error::InvalidSysSize(params.hdr.syssize))?;
 
+    let file_size = kernel_image.get_len().map_err(Error::GetFileLen)?;
+    let load_size = file_size
+        .checked_sub(kernel_offset)
+        .and_then(|n| usize::try_from(n).ok())
+        .ok_or(Error::InvalidSetupSects(params.hdr.setup_sects))?;
+
+    match kernel_size.cmp(&load_size) {
+        Ordering::Greater => {
+            // `syssize` from header was larger than the actual file.
+            return Err(Error::InvalidSysSize(params.hdr.syssize));
+        }
+        Ordering::Less => {
+            debug!(
+                "loading {} extra bytes appended to bzImage",
+                load_size - kernel_size
+            );
+        }
+        Ordering::Equal => {}
+    }
+
     // Load the whole kernel image to kernel_start
     let guest_slice = guest_mem
-        .get_slice_at_addr(kernel_start, kernel_size)
+        .get_slice_at_addr(kernel_start, load_size)
         .map_err(Error::GuestMemoryError)?;
     kernel_image
         .read_exact_at_volatile(guest_slice, kernel_offset)
@@ -140,7 +164,7 @@ where
 
     Ok((
         params,
-        kernel_start.offset() + kernel_size as u64,
+        kernel_start.offset() + load_size as u64,
         bzimage_entry,
         cpu_mode,
     ))
diff --git a/x86_64/src/fdt.rs b/x86_64/src/fdt.rs
index 96380d464..cf8bf5e38 100644
--- a/x86_64/src/fdt.rs
+++ b/x86_64/src/fdt.rs
@@ -16,23 +16,22 @@ use base::open_file_or_duplicate;
 use cros_fdt::Error;
 use cros_fdt::Fdt;
 
-use crate::SetupData;
-use crate::SetupDataType;
-
 /// Creates a flattened device tree containing all of the parameters for the
-/// kernel and returns it as `SetupData`.
+/// kernel and returns it as DTB.
 ///
 /// # Arguments
 ///
 /// * `android_fstab` - the File object for the android fstab
 pub fn create_fdt(
-    android_fstab: File,
+    android_fstab: Option<File>,
     dump_device_tree_blob: Option<PathBuf>,
     device_tree_overlays: Vec<DtbOverlay>,
-) -> Result<SetupData, Error> {
+) -> Result<Vec<u8>, Error> {
     let mut fdt = Fdt::new(&[]);
     // The whole thing is put into one giant node with some top level properties
-    create_android_fdt(&mut fdt, android_fstab)?;
+    if let Some(android_fstab) = android_fstab {
+        create_android_fdt(&mut fdt, android_fstab)?;
+    }
 
     // Done writing base FDT, now apply DT overlays
     apply_device_tree_overlays(
@@ -60,8 +59,5 @@ pub fn create_fdt(
             .map_err(|e| Error::FdtDumpIoError(e, file_path.clone()))?;
     }
 
-    Ok(SetupData {
-        data: fdt_final,
-        type_: SetupDataType::Dtb,
-    })
+    Ok(fdt_final)
 }
diff --git a/x86_64/src/lib.rs b/x86_64/src/lib.rs
index afbbcde0f..ebd583104 100644
--- a/x86_64/src/lib.rs
+++ b/x86_64/src/lib.rs
@@ -60,6 +60,8 @@ use arch::CpuSet;
 use arch::DtbOverlay;
 use arch::FdtPosition;
 use arch::GetSerialCmdlineError;
+use arch::MemoryRegionConfig;
+use arch::PciConfig;
 use arch::RunnableLinuxVm;
 use arch::VmComponents;
 use arch::VmImage;
@@ -121,7 +123,6 @@ use jail::read_jail_addr;
 use jail::FakeMinijailStub as Minijail;
 #[cfg(any(target_os = "android", target_os = "linux"))]
 use minijail::Minijail;
-use once_cell::sync::OnceCell;
 use rand::rngs::OsRng;
 use rand::RngCore;
 use remain::sorted;
@@ -173,6 +174,10 @@ pub enum Error {
     CommandLineOverflow,
     #[error("failed to configure hotplugged pci device: {0}")]
     ConfigurePciDevice(arch::DeviceRegistrationError),
+    #[error("bad PCI ECAM configuration: {0}")]
+    ConfigurePciEcam(String),
+    #[error("bad PCI mem configuration: {0}")]
+    ConfigurePciMem(String),
     #[error("failed to configure segment registers: {0}")]
     ConfigureSegments(regs::Error),
     #[error("error configuring the system")]
@@ -356,7 +361,7 @@ const MEM_32BIT_GAP_SIZE: u64 = 768 * MB;
 const END_ADDR_BEFORE_32BITS: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;
 // Reserved memory for nand_bios/LAPIC/IOAPIC/HPET/.....
 const RESERVED_MEM_SIZE: u64 = 0x800_0000;
-const PCI_MMIO_END: u64 = FIRST_ADDR_PAST_32BITS - RESERVED_MEM_SIZE - 1;
+const DEFAULT_PCI_MEM_END: u64 = FIRST_ADDR_PAST_32BITS - RESERVED_MEM_SIZE - 1;
 // Reserve 64MB for pcie enhanced configuration
 const DEFAULT_PCIE_CFG_MMIO_SIZE: u64 = 0x400_0000;
 const DEFAULT_PCIE_CFG_MMIO_END: u64 = FIRST_ADDR_PAST_32BITS - RESERVED_MEM_SIZE - 1;
@@ -404,85 +409,90 @@ pub fn get_cpu_manufacturer() -> CpuManufacturer {
     cpuid::cpu_manufacturer()
 }
 
-// Memory layout below 4G
-struct LowMemoryLayout {
+pub struct ArchMemoryLayout {
     // the pci mmio range below 4G
-    pci_mmio: AddressRange,
+    pci_mmio_before_32bit: AddressRange,
     // the pcie cfg mmio range
     pcie_cfg_mmio: AddressRange,
     // the pVM firmware memory (if running a protected VM)
     pvmfw_mem: Option<AddressRange>,
 }
 
-static LOW_MEMORY_LAYOUT: OnceCell<LowMemoryLayout> = OnceCell::new();
-
-pub fn init_low_memory_layout(
-    pcie_ecam: Option<AddressRange>,
-    pci_low_start: Option<u64>,
+pub fn create_arch_memory_layout(
+    pci_config: &PciConfig,
     has_protected_vm_firmware: bool,
-) -> Result<()> {
-    LOW_MEMORY_LAYOUT.get_or_init(|| {
-        const DEFAULT_PCIE_CFG_MMIO: AddressRange = AddressRange {
-            start: DEFAULT_PCIE_CFG_MMIO_START,
-            end: DEFAULT_PCIE_CFG_MMIO_END,
-        };
-
-        let pcie_cfg_mmio = pcie_ecam.unwrap_or(DEFAULT_PCIE_CFG_MMIO);
-
-        let pci_mmio = if let Some(pci_low) = pci_low_start {
-            AddressRange {
-                start: pci_low,
-                end: PCI_MMIO_END,
-            }
-        } else {
-            AddressRange {
-                start: pcie_cfg_mmio
-                    .start
-                    .min(FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE),
-                end: PCI_MMIO_END,
-            }
-        };
-
-        let pvmfw_mem = if has_protected_vm_firmware {
-            Some(AddressRange {
-                start: PROTECTED_VM_FW_START,
-                end: PROTECTED_VM_FW_START + PROTECTED_VM_FW_MAX_SIZE - 1,
-            })
-        } else {
-            None
-        };
-
-        LowMemoryLayout {
-            pci_mmio,
-            pcie_cfg_mmio,
-            pvmfw_mem,
+) -> Result<ArchMemoryLayout> {
+    // the max bus number is 256 and each bus occupy 1MB, so the max pcie cfg mmio size = 256M
+    const MAX_PCIE_ECAM_SIZE: u64 = 256 * MB;
+    let pcie_cfg_mmio = match pci_config.ecam {
+        Some(MemoryRegionConfig {
+            start,
+            size: Some(size),
+        }) => AddressRange::from_start_and_size(start, size.min(MAX_PCIE_ECAM_SIZE)).unwrap(),
+        Some(MemoryRegionConfig { start, size: None }) => {
+            AddressRange::from_start_and_end(start, DEFAULT_PCIE_CFG_MMIO_END)
         }
-    });
-
-    if has_protected_vm_firmware {
-        let pci_mmio = read_pci_mmio_before_32bit();
-        let pvmfw_mem = read_pvmfw_mem().unwrap();
-
-        if !pci_mmio.intersect(pvmfw_mem).is_empty() {
-            return Err(Error::PciMmioOverlapPvmFw);
+        None => {
+            AddressRange::from_start_and_end(DEFAULT_PCIE_CFG_MMIO_START, DEFAULT_PCIE_CFG_MMIO_END)
         }
+    };
+    if pcie_cfg_mmio.start % pcie_cfg_mmio.len().unwrap() != 0
+        || pcie_cfg_mmio.start % MB != 0
+        || pcie_cfg_mmio.len().unwrap() % MB != 0
+    {
+        return Err(Error::ConfigurePciEcam(
+            "base and len must be aligned to 1MB and base must be a multiple of len".to_string(),
+        ));
+    }
+    if pcie_cfg_mmio.end >= 0x1_0000_0000 {
+        return Err(Error::ConfigurePciEcam(
+            "end address can't go beyond 4G".to_string(),
+        ));
     }
 
-    Ok(())
-}
+    let pci_mmio_before_32bit = match pci_config.mem {
+        Some(MemoryRegionConfig {
+            start,
+            size: Some(size),
+        }) => AddressRange::from_start_and_size(start, size)
+            .ok_or(Error::ConfigurePciMem("region overflowed".to_string()))?,
+        Some(MemoryRegionConfig { start, size: None }) => {
+            AddressRange::from_start_and_end(start, DEFAULT_PCI_MEM_END)
+        }
+        None => AddressRange::from_start_and_end(
+            pcie_cfg_mmio
+                .start
+                .min(FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE),
+            DEFAULT_PCI_MEM_END,
+        ),
+    };
+
+    let pvmfw_mem = if has_protected_vm_firmware {
+        let range = AddressRange {
+            start: PROTECTED_VM_FW_START,
+            end: PROTECTED_VM_FW_START + PROTECTED_VM_FW_MAX_SIZE - 1,
+        };
+        if !pci_mmio_before_32bit.intersect(range).is_empty() {
+            return Err(Error::PciMmioOverlapPvmFw);
+        }
 
-pub fn read_pci_mmio_before_32bit() -> AddressRange {
-    LOW_MEMORY_LAYOUT.get().unwrap().pci_mmio
-}
-pub fn read_pcie_cfg_mmio() -> AddressRange {
-    LOW_MEMORY_LAYOUT.get().unwrap().pcie_cfg_mmio
-}
-fn read_pvmfw_mem() -> Option<AddressRange> {
-    LOW_MEMORY_LAYOUT.get().unwrap().pvmfw_mem
+        Some(range)
+    } else {
+        None
+    };
+
+    Ok(ArchMemoryLayout {
+        pci_mmio_before_32bit,
+        pcie_cfg_mmio,
+        pvmfw_mem,
+    })
 }
 
-fn max_ram_end_before_32bit(has_protected_vm_firmware: bool) -> u64 {
-    let pci_start = read_pci_mmio_before_32bit().start;
+fn max_ram_end_before_32bit(
+    arch_memory_layout: &ArchMemoryLayout,
+    has_protected_vm_firmware: bool,
+) -> u64 {
+    let pci_start = arch_memory_layout.pci_mmio_before_32bit.start;
     if has_protected_vm_firmware {
         pci_start.min(PROTECTED_VM_FW_START)
     } else {
@@ -658,6 +668,7 @@ fn add_e820_entry(
 
 /// Generate a memory map in INT 0x15 AX=0xE820 format.
 fn generate_e820_memory_map(
+    arch_memory_layout: &ArchMemoryLayout,
     guest_mem: &GuestMemory,
     ram_below_1m: AddressRange,
     ram_below_4g: AddressRange,
@@ -676,11 +687,11 @@ fn generate_e820_memory_map(
         // After the pVM firmware jumped to the guest, the pVM firmware itself
         // is no longer running, so its memory is reusable by the guest OS.
         // So add this memory as RAM rather than Reserved.
-        let pvmfw_range = read_pvmfw_mem().unwrap();
+        let pvmfw_range = arch_memory_layout.pvmfw_mem.unwrap();
         add_e820_entry(&mut e820_entries, pvmfw_range, E820Type::Ram)?;
     }
 
-    let pcie_cfg_mmio_range = read_pcie_cfg_mmio();
+    let pcie_cfg_mmio_range = arch_memory_layout.pcie_cfg_mmio;
     add_e820_entry(&mut e820_entries, pcie_cfg_mmio_range, E820Type::Reserved)?;
 
     add_e820_entry(
@@ -707,6 +718,7 @@ fn generate_e820_memory_map(
 /// For x86_64 all addresses are valid from the start of the kernel except a
 /// carve out at the end of 32bit address space.
 pub fn arch_memory_regions(
+    arch_memory_layout: &ArchMemoryLayout,
     size: u64,
     bios_size: Option<u64>,
     has_protected_vm_firmware: bool,
@@ -733,7 +745,10 @@ pub fn arch_memory_regions(
     let mem_end = GuestAddress(mem_size + mem_start);
 
     let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
-    let max_end_32bits = GuestAddress(max_ram_end_before_32bit(has_protected_vm_firmware));
+    let max_end_32bits = GuestAddress(max_ram_end_before_32bit(
+        arch_memory_layout,
+        has_protected_vm_firmware,
+    ));
 
     if mem_end <= max_end_32bits {
         regions.push((GuestAddress(mem_start), mem_size, Default::default()));
@@ -761,39 +776,48 @@ pub fn arch_memory_regions(
 
 impl arch::LinuxArch for X8664arch {
     type Error = Error;
+    type ArchMemoryLayout = ArchMemoryLayout;
+
+    fn arch_memory_layout(
+        components: &VmComponents,
+    ) -> std::result::Result<Self::ArchMemoryLayout, Self::Error> {
+        create_arch_memory_layout(
+            &components.pci_config,
+            components.hv_cfg.protection_type.runs_firmware(),
+        )
+    }
 
     fn guest_memory_layout(
         components: &VmComponents,
+        arch_memory_layout: &Self::ArchMemoryLayout,
         _hypervisor: &impl Hypervisor,
     ) -> std::result::Result<Vec<(GuestAddress, u64, MemoryRegionOptions)>, Self::Error> {
         let has_protected_vm_firmware = components.hv_cfg.protection_type.runs_firmware();
 
-        init_low_memory_layout(
-            components.pcie_ecam,
-            components.pci_low_start,
-            has_protected_vm_firmware,
-        )?;
-
         let bios_size = match &components.vm_image {
             VmImage::Bios(bios_file) => Some(bios_file.metadata().map_err(Error::LoadBios)?.len()),
             VmImage::Kernel(_) => None,
         };
 
         Ok(arch_memory_regions(
+            arch_memory_layout,
             components.memory_size,
             bios_size,
             has_protected_vm_firmware,
         ))
     }
 
-    fn get_system_allocator_config<V: Vm>(vm: &V) -> SystemAllocatorConfig {
+    fn get_system_allocator_config<V: Vm>(
+        vm: &V,
+        arch_memory_layout: &Self::ArchMemoryLayout,
+    ) -> SystemAllocatorConfig {
         SystemAllocatorConfig {
             io: Some(AddressRange {
                 start: 0xc000,
                 end: 0xffff,
             }),
-            low_mmio: read_pci_mmio_before_32bit(),
-            high_mmio: Self::get_high_mmio_range(vm),
+            low_mmio: arch_memory_layout.pci_mmio_before_32bit,
+            high_mmio: Self::get_high_mmio_range(vm, arch_memory_layout),
             platform_mmio: None,
             first_irq: X86_64_IRQ_BASE,
         }
@@ -801,6 +825,7 @@ impl arch::LinuxArch for X8664arch {
 
     fn build_vm<V, Vcpu>(
         mut components: VmComponents,
+        arch_memory_layout: &Self::ArchMemoryLayout,
         vm_evt_wrtube: &SendTube,
         system_allocator: &mut SystemAllocator,
         serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
@@ -819,15 +844,12 @@ impl arch::LinuxArch for X8664arch {
         guest_suspended_cvar: Option<Arc<(Mutex<bool>, Condvar)>>,
         device_tree_overlays: Vec<DtbOverlay>,
         _fdt_position: Option<FdtPosition>,
+        _no_pmu: bool,
     ) -> std::result::Result<RunnableLinuxVm<V, Vcpu>, Self::Error>
     where
         V: VmX86_64,
         Vcpu: VcpuX86_64,
     {
-        if components.hv_cfg.protection_type.isolates_memory() {
-            return Err(Error::UnsupportedProtectionType);
-        }
-
         let mem = vm.get_memory().clone();
 
         let vcpu_count = components.vcpu_count;
@@ -844,7 +866,7 @@ impl arch::LinuxArch for X8664arch {
 
         // punch pcie config mmio from pci low mmio, so that it couldn't be
         // allocated to any device.
-        let pcie_cfg_mmio_range = read_pcie_cfg_mmio();
+        let pcie_cfg_mmio_range = arch_memory_layout.pcie_cfg_mmio;
         system_allocator
             .reserve_mmio(pcie_cfg_mmio_range)
             .map_err(Error::ReservePcieCfgMmio)?;
@@ -965,6 +987,7 @@ impl arch::LinuxArch for X8664arch {
                 .context("create tube")
                 .map_err(Error::SetupCmos)?;
             Self::setup_legacy_cmos_device(
+                arch_memory_layout,
                 &io_bus,
                 irq_chip,
                 device_tube,
@@ -1020,6 +1043,7 @@ impl arch::LinuxArch for X8664arch {
         // each bus occupy 1MB mmio for pcie enhanced configuration
         let max_bus = (pcie_cfg_mmio_len / 0x100000 - 1) as u8;
         let (mut acpi_dev_resource, bat_control) = Self::setup_acpi_devices(
+            arch_memory_layout,
             pci.clone(),
             &mem,
             &io_bus,
@@ -1103,7 +1127,7 @@ impl arch::LinuxArch for X8664arch {
                 .map_err(Error::Cmdline)?;
         }
 
-        let pci_start = read_pci_mmio_before_32bit().start;
+        let pci_start = arch_memory_layout.pci_mmio_before_32bit.start;
 
         let mut vcpu_init = vec![VcpuInitX86_64::default(); vcpu_count];
         let mut msrs = BTreeMap::new();
@@ -1134,6 +1158,7 @@ impl arch::LinuxArch for X8664arch {
                 info!("Loaded {} kernel", kernel_type);
 
                 Self::setup_system_memory(
+                    arch_memory_layout,
                     &mem,
                     cmdline,
                     components.initrd_image,
@@ -1231,8 +1256,6 @@ impl arch::LinuxArch for X8664arch {
             rt_cpus: components.rt_cpus,
             delay_rt: components.delay_rt,
             bat_control,
-            #[cfg(feature = "gdb")]
-            gdb: components.gdb,
             pm: Some(acpi_dev_resource.pm),
             root_config: pci,
             #[cfg(any(target_os = "android", target_os = "linux"))]
@@ -1598,6 +1621,7 @@ impl X8664arch {
     /// * `cmdline` - the kernel commandline
     /// * `initrd_file` - an initial ramdisk image
     pub fn setup_system_memory(
+        arch_memory_layout: &ArchMemoryLayout,
         mem: &GuestMemory,
         cmdline: kernel_cmdline::Cmdline,
         initrd_file: Option<File>,
@@ -1624,7 +1648,8 @@ impl X8664arch {
 
         // Find the end of the part of guest memory below 4G that is not pVM firmware memory.
         // This part of guest memory includes just one region, so just find the end of this region.
-        let max_ram_end_below_4g = max_ram_end_before_32bit(has_protected_vm_firmware) - 1;
+        let max_ram_end_below_4g =
+            max_ram_end_before_32bit(arch_memory_layout, has_protected_vm_firmware) - 1;
         let guest_mem_end_below_4g = mem
             .regions()
             .map(|r| r.guest_addr.offset() + r.size as u64 - 1)
@@ -1641,6 +1666,7 @@ impl X8664arch {
         };
 
         let e820_entries = generate_e820_memory_map(
+            arch_memory_layout,
             mem,
             ram_below_1m,
             ram_below_4g,
@@ -1663,12 +1689,16 @@ impl X8664arch {
         )?;
 
         let mut setup_data = Vec::<SetupData>::new();
-        if let Some(android_fstab) = android_fstab {
-            setup_data.push(
+        if android_fstab.is_some() || !device_tree_overlays.is_empty() {
+            let device_tree_blob =
                 fdt::create_fdt(android_fstab, dump_device_tree_blob, device_tree_overlays)
-                    .map_err(Error::CreateFdt)?,
-            );
+                    .map_err(Error::CreateFdt)?;
+            setup_data.push(SetupData {
+                data: device_tree_blob,
+                type_: SetupDataType::Dtb,
+            });
         }
+
         setup_data.push(setup_data_rng_seed());
 
         let setup_data = write_setup_data(
@@ -1727,9 +1757,9 @@ impl X8664arch {
     }
 
     /// Returns the high mmio range
-    fn get_high_mmio_range<V: Vm>(vm: &V) -> AddressRange {
+    fn get_high_mmio_range<V: Vm>(vm: &V, arch_memory_layout: &ArchMemoryLayout) -> AddressRange {
         let mem = vm.get_memory();
-        let start = Self::get_pcie_vcfg_mmio_range(mem, &read_pcie_cfg_mmio()).end + 1;
+        let start = Self::get_pcie_vcfg_mmio_range(mem, &arch_memory_layout.pcie_cfg_mmio).end + 1;
 
         let phys_mem_end = (1u64 << vm.get_guest_phys_addr_bits()) - 1;
         let high_mmio_end = std::cmp::min(phys_mem_end, HIGH_MMIO_MAX_END);
@@ -1848,13 +1878,19 @@ impl X8664arch {
     /// * - `io_bus` - the IO bus object
     /// * - `mem_size` - the size in bytes of physical ram for the guest
     pub fn setup_legacy_cmos_device(
+        arch_memory_layout: &ArchMemoryLayout,
         io_bus: &Bus,
         irq_chip: &mut dyn IrqChipX86_64,
         vm_control: Tube,
         mem_size: u64,
         has_protected_vm_firmware: bool,
     ) -> anyhow::Result<()> {
-        let mem_regions = arch_memory_regions(mem_size, None, has_protected_vm_firmware);
+        let mem_regions = arch_memory_regions(
+            arch_memory_layout,
+            mem_size,
+            None,
+            has_protected_vm_firmware,
+        );
 
         let mem_below_4g = mem_regions
             .iter()
@@ -1907,6 +1943,7 @@ impl X8664arch {
     /// * `pci_irqs` IRQ assignment of PCI devices. Tuples of (PCI address, gsi, PCI interrupt pin).
     ///   Note that this matches one of the return values of generate_pci_root.
     pub fn setup_acpi_devices(
+        arch_memory_layout: &ArchMemoryLayout,
         pci_root: Arc<Mutex<PciRoot>>,
         mem: &GuestMemory,
         io_bus: &Bus,
@@ -1973,7 +2010,7 @@ impl X8664arch {
 
         let pcie_vcfg = aml::Name::new(
             "VCFG".into(),
-            &Self::get_pcie_vcfg_mmio_range(mem, &read_pcie_cfg_mmio()).start,
+            &Self::get_pcie_vcfg_mmio_range(mem, &arch_memory_layout.pcie_cfg_mmio).start,
         );
         pcie_vcfg.to_aml_bytes(&mut amls);
 
@@ -2108,8 +2145,9 @@ impl X8664arch {
         .to_aml_bytes(&mut amls);
 
         if let (Some(start), Some(len)) = (
-            u32::try_from(read_pcie_cfg_mmio().start).ok(),
-            read_pcie_cfg_mmio()
+            u32::try_from(arch_memory_layout.pcie_cfg_mmio.start).ok(),
+            arch_memory_layout
+                .pcie_cfg_mmio
                 .len()
                 .and_then(|l| u32::try_from(l).ok()),
         ) {
@@ -2352,16 +2390,25 @@ mod tests {
 
     const TEST_MEMORY_SIZE: u64 = 2 * GB;
 
-    fn setup() {
-        let pcie_ecam = Some(AddressRange::from_start_and_size(3 * GB, 256 * MB).unwrap());
-        let pci_start = Some(2 * GB);
-        init_low_memory_layout(pcie_ecam, pci_start, false).expect("init_low_memory_layout");
+    fn setup() -> ArchMemoryLayout {
+        let pci_config = PciConfig {
+            ecam: Some(MemoryRegionConfig {
+                start: 3 * GB,
+                size: Some(256 * MB),
+            }),
+            mem: Some(MemoryRegionConfig {
+                start: 2 * GB,
+                size: None,
+            }),
+        };
+        create_arch_memory_layout(&pci_config, false).unwrap()
     }
 
     #[test]
     fn regions_lt_4gb_nobios() {
-        setup();
+        let arch_memory_layout = setup();
         let regions = arch_memory_regions(
+            &arch_memory_layout,
             512 * MB,
             /* bios_size */ None,
             /* has_protected_vm_firmware */ false,
@@ -2373,10 +2420,13 @@ mod tests {
 
     #[test]
     fn regions_gt_4gb_nobios() {
-        setup();
+        let arch_memory_layout = setup();
         let size = 4 * GB + 0x8000;
         let regions = arch_memory_regions(
-            size, /* bios_size */ None, /* has_protected_vm_firmware */ false,
+            &arch_memory_layout,
+            size,
+            /* bios_size */ None,
+            /* has_protected_vm_firmware */ false,
         );
         assert_eq!(2, regions.len());
         assert_eq!(GuestAddress(START_OF_RAM_32BITS), regions[0].0);
@@ -2386,9 +2436,10 @@ mod tests {
 
     #[test]
     fn regions_lt_4gb_bios() {
-        setup();
+        let arch_memory_layout = setup();
         let bios_len = 1 * MB;
         let regions = arch_memory_regions(
+            &arch_memory_layout,
             512 * MB,
             Some(bios_len),
             /* has_protected_vm_firmware */ false,
@@ -2405,9 +2456,10 @@ mod tests {
 
     #[test]
     fn regions_gt_4gb_bios() {
-        setup();
+        let arch_memory_layout = setup();
         let bios_len = 1 * MB;
         let regions = arch_memory_regions(
+            &arch_memory_layout,
             4 * GB + 0x8000,
             Some(bios_len),
             /* has_protected_vm_firmware */ false,
@@ -2424,9 +2476,10 @@ mod tests {
 
     #[test]
     fn regions_eq_4gb_nobios() {
-        setup();
+        let arch_memory_layout = setup();
         // Test with exact size of 4GB - the overhead.
         let regions = arch_memory_regions(
+            &arch_memory_layout,
             TEST_MEMORY_SIZE - START_OF_RAM_32BITS,
             /* bios_size */ None,
             /* has_protected_vm_firmware */ false,
@@ -2439,10 +2492,11 @@ mod tests {
 
     #[test]
     fn regions_eq_4gb_bios() {
-        setup();
+        let arch_memory_layout = setup();
         // Test with exact size of 4GB - the overhead.
         let bios_len = 1 * MB;
         let regions = arch_memory_regions(
+            &arch_memory_layout,
             TEST_MEMORY_SIZE - START_OF_RAM_32BITS,
             Some(bios_len),
             /* has_protected_vm_firmware */ false,
@@ -2459,18 +2513,21 @@ mod tests {
 
     #[test]
     fn check_pci_mmio_layout() {
-        setup();
+        let arch_memory_layout = setup();
 
-        assert_eq!(read_pci_mmio_before_32bit().start, 2 * GB);
-        assert_eq!(read_pcie_cfg_mmio().start, 3 * GB);
-        assert_eq!(read_pcie_cfg_mmio().len().unwrap(), 256 * MB);
+        assert_eq!(arch_memory_layout.pci_mmio_before_32bit.start, 2 * GB);
+        assert_eq!(arch_memory_layout.pcie_cfg_mmio.start, 3 * GB);
+        assert_eq!(arch_memory_layout.pcie_cfg_mmio.len().unwrap(), 256 * MB);
     }
 
     #[test]
     fn check_32bit_gap_size_alignment() {
-        setup();
-        // pci_low_start is 256 MB aligned to be friendly for MTRR mappings.
-        assert_eq!(read_pci_mmio_before_32bit().start % (256 * MB), 0);
+        let arch_memory_layout = setup();
+        // pci_mmio_before_32bit is 256 MB aligned to be friendly for MTRR mappings.
+        assert_eq!(
+            arch_memory_layout.pci_mmio_before_32bit.start % (256 * MB),
+            0
+        );
     }
 
     #[test]
```

