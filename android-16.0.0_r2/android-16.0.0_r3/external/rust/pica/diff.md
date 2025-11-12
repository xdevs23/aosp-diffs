```diff
diff --git a/Android.bp b/Android.bp
index 19bdfb5..42d3c8b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -17,7 +17,7 @@ license {
 
 genrule {
     name: "libpica_uci_packets",
-    defaults: ["pdl_rust_legacy_generator_defaults"],
+    defaults: ["pdl_rust_generator_defaults"],
     srcs: ["src/uci_packets.pdl"],
     out: ["uci_packets.rs"],
 }
diff --git a/Cargo.lock b/Cargo.lock
index ba629f1..1b0f9d0 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -4,9 +4,9 @@ version = 3
 
 [[package]]
 name = "addr2line"
-version = "0.21.0"
+version = "0.20.0"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "8a30b2e23b9e17a9f90641c7ab1549cd9b44f296d3ccbf309d2863cfe398a0cb"
+checksum = "f4fa78e18c64fce05e902adecd7a5eed15a5e0a3439f7b0e169f0252214865e3"
 dependencies = [
  "gimli",
 ]
@@ -42,7 +42,7 @@ dependencies = [
  "argh_shared",
  "proc-macro2",
  "quote",
- "syn 2.0.38",
+ "syn 2.0.94",
 ]
 
 [[package]]
@@ -62,9 +62,9 @@ checksum = "d468802bab17cbc0cc575e9b053f41e72aa36bfa6b7f55e3529ffa43161b97fa"
 
 [[package]]
 name = "backtrace"
-version = "0.3.69"
+version = "0.3.68"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "2089b7e3f35b9dd2d0ed921ead4f6d318c27680d4a5bd167b3ee120edb105837"
+checksum = "4319208da049c43661739c5fade2ba182f09d1dc2299b32298d3a31692b17e12"
 dependencies = [
  "addr2line",
  "cc",
@@ -98,12 +98,9 @@ checksum = "a2bd12c1caf447e69cd4528f47f94d203fd2582878ecb9e9465484c4148a8223"
 
 [[package]]
 name = "cc"
-version = "1.0.83"
+version = "1.0.98"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "f1174fb0b6ec23863f8b971027804a42614e347eafb0a95bf0b12cdae21fc4d0"
-dependencies = [
- "libc",
-]
+checksum = "41c270e7540d725e65ac7f1b212ac8ce349719624d7bcff99f8e2e488e8cf03f"
 
 [[package]]
 name = "cfg-if"
@@ -255,7 +252,7 @@ checksum = "87750cf4b7a4c0625b1529e4c543c2182106e4dedc60a2a6455e00d212c489ac"
 dependencies = [
  "proc-macro2",
  "quote",
- "syn 2.0.38",
+ "syn 2.0.94",
 ]
 
 [[package]]
@@ -300,9 +297,9 @@ dependencies = [
 
 [[package]]
 name = "gimli"
-version = "0.28.1"
+version = "0.27.3"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "4271d37baee1b8c7e4b708028c57d816cf9d2434acb33a549475f78c181f6253"
+checksum = "b6c80984affa11d98d1b88b66ac8853f143217b399d3c74116778ff8fdb4ed2e"
 
 [[package]]
 name = "glam"
@@ -470,9 +467,9 @@ dependencies = [
 
 [[package]]
 name = "object"
-version = "0.32.2"
+version = "0.31.1"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "a6a622008b6e321afc04970976f62ee297fdbaa6f95318ca343e3eebb9648441"
+checksum = "8bda667d9f2b5051b8833f59f3bf748b28ef54f850f4fcb389a252aa383866d1"
 dependencies = [
  "memchr",
 ]
@@ -491,9 +488,9 @@ checksum = "9b7820b9daea5457c9f21c69448905d723fbd21136ccf521748f23fd49e723ee"
 
 [[package]]
 name = "pdl-compiler"
-version = "0.3.0"
+version = "0.3.2"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "6853e3b47aa4a5be1287e9115d6fae9b3118971eba855f4d60323d19a66c07cf"
+checksum = "36351a4c62b0d63cbc803df83f5e15e37e4c008dce9e437edb64c9e1159bb6b3"
 dependencies = [
  "argh",
  "codespan-reporting",
@@ -505,35 +502,35 @@ dependencies = [
  "quote",
  "serde",
  "serde_json",
- "syn 2.0.38",
+ "syn 2.0.94",
 ]
 
 [[package]]
 name = "pdl-runtime"
-version = "0.3.0"
+version = "0.3.2"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "a8684812e36689336c83de6033669573b33b6e59c831145ee496c38a71ed0d7c"
+checksum = "942c617429160244ba162716030b0a9db99da1374010a953144112455e6344f8"
 dependencies = [
  "bytes",
- "thiserror",
+ "thiserror 1.0.49",
 ]
 
 [[package]]
 name = "pest"
-version = "2.7.4"
+version = "2.7.15"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "c022f1e7b65d6a24c0dbbd5fb344c66881bc01f3e5ae74a1c8100f2f985d98a4"
+checksum = "8b7cafe60d6cf8e62e1b9b2ea516a089c008945bb5a275416789e7db0bc199dc"
 dependencies = [
  "memchr",
- "thiserror",
+ "thiserror 2.0.9",
  "ucd-trie",
 ]
 
 [[package]]
 name = "pest_derive"
-version = "2.7.4"
+version = "2.7.15"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "35513f630d46400a977c4cb58f78e1bfbe01434316e60c37d27b9ad6139c66d8"
+checksum = "816518421cfc6887a0d62bf441b6ffb4536fcc926395a69e1a85852d4363f57e"
 dependencies = [
  "pest",
  "pest_generator",
@@ -541,22 +538,22 @@ dependencies = [
 
 [[package]]
 name = "pest_generator"
-version = "2.7.4"
+version = "2.7.15"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "bc9fc1b9e7057baba189b5c626e2d6f40681ae5b6eb064dc7c7834101ec8123a"
+checksum = "7d1396fd3a870fc7838768d171b4616d5c91f6cc25e377b673d714567d99377b"
 dependencies = [
  "pest",
  "pest_meta",
  "proc-macro2",
  "quote",
- "syn 2.0.38",
+ "syn 2.0.94",
 ]
 
 [[package]]
 name = "pest_meta"
-version = "2.7.4"
+version = "2.7.15"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "1df74e9e7ec4053ceb980e7c0c8bd3594e977fde1af91daba9c928e8e8c6708d"
+checksum = "e1e58089ea25d717bfd31fb534e4f3afcc2cc569c70de3e239778991ea3b7dea"
 dependencies = [
  "once_cell",
  "pest",
@@ -582,7 +579,7 @@ dependencies = [
  "pdl-runtime",
  "serde",
  "serde_json",
- "thiserror",
+ "thiserror 1.0.49",
  "tokio",
  "tokio-stream",
 ]
@@ -606,7 +603,7 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "ae005bd773ab59b4725093fd7df83fd7892f7d8eafb48dbd7de6e024e4215f9d"
 dependencies = [
  "proc-macro2",
- "syn 2.0.38",
+ "syn 2.0.94",
 ]
 
 [[package]]
@@ -635,18 +632,18 @@ dependencies = [
 
 [[package]]
 name = "proc-macro2"
-version = "1.0.69"
+version = "1.0.92"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "134c189feb4956b20f6f547d2cf727d4c0fe06722b20a0eec87ed445a97f92da"
+checksum = "37d3544b3f2748c54e147655edb5025752e2303145b5aefb3c3ea2c78b973bb0"
 dependencies = [
  "unicode-ident",
 ]
 
 [[package]]
 name = "quote"
-version = "1.0.33"
+version = "1.0.38"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "5267fca4496028628a95160fc423a33e8b2e6af8a5302579e322e4b520293cae"
+checksum = "0e4dccaaaf89514f546c693ddc140f729f958c247918a13380cccc6078391acc"
 dependencies = [
  "proc-macro2",
 ]
@@ -680,7 +677,7 @@ checksum = "1e48d1f918009ce3145511378cf68d613e3b3d9137d67272562080d68a2b32d5"
 dependencies = [
  "proc-macro2",
  "quote",
- "syn 2.0.38",
+ "syn 2.0.94",
 ]
 
 [[package]]
@@ -747,9 +744,9 @@ dependencies = [
 
 [[package]]
 name = "syn"
-version = "2.0.38"
+version = "2.0.94"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "e96b79aaa137db8f61e26363a0c9b47d8b4ec75da28b7d1d614c2303e232408b"
+checksum = "987bc0be1cdea8b10216bd06e2ca407d40b9543468fafd3ddfb02f36e77f71f3"
 dependencies = [
  "proc-macro2",
  "quote",
@@ -771,7 +768,16 @@ version = "1.0.49"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "1177e8c6d7ede7afde3585fd2513e611227efd6481bd78d2e82ba1ce16557ed4"
 dependencies = [
- "thiserror-impl",
+ "thiserror-impl 1.0.49",
+]
+
+[[package]]
+name = "thiserror"
+version = "2.0.9"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "f072643fd0190df67a8bab670c20ef5d8737177d6ac6b2e9a236cb096206b2cc"
+dependencies = [
+ "thiserror-impl 2.0.9",
 ]
 
 [[package]]
@@ -782,7 +788,18 @@ checksum = "10712f02019e9288794769fba95cd6847df9874d49d871d062172f9dd41bc4cc"
 dependencies = [
  "proc-macro2",
  "quote",
- "syn 2.0.38",
+ "syn 2.0.94",
+]
+
+[[package]]
+name = "thiserror-impl"
+version = "2.0.9"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "7b50fa271071aae2e6ee85f842e2e28ba8cd2c5fb67f11fcb1fd70b276f9e7d4"
+dependencies = [
+ "proc-macro2",
+ "quote",
+ "syn 2.0.94",
 ]
 
 [[package]]
@@ -810,7 +827,7 @@ checksum = "5b8a1e28f2deaa14e508979454cb3a223b10b938b45af148bc0986de36f1923b"
 dependencies = [
  "proc-macro2",
  "quote",
- "syn 2.0.38",
+ "syn 2.0.94",
 ]
 
 [[package]]
@@ -941,9 +958,9 @@ checksum = "ac3b87c63620426dd9b991e5ce0329eff545bccbbb34f3be09ff6fb6ab51b7b6"
 
 [[package]]
 name = "winapi-util"
-version = "0.1.6"
+version = "0.1.5"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "f29e6f9198ba0d26b4c9f07dbe6f9ed633e1f3d5b8b414090084349e46a52596"
+checksum = "70ec6ce85bb158151cae5e5c87f95a8e97d2c0c4b001223f33a334e3ce5de178"
 dependencies = [
  "winapi",
 ]
diff --git a/Cargo.toml b/Cargo.toml
index d9666be..3f22df7 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -41,7 +41,7 @@ default = ["web"]
 web = ["hyper", "tokio/rt-multi-thread"]
 
 [build-dependencies]
-pdl-compiler = "0.3.0"
+pdl-compiler = "0.3.2"
 
 [dependencies]
 anyhow = "1.0.56"
@@ -55,7 +55,7 @@ log = "0.4.17"
 env_logger = { version = "0.10.0", default-features = false }
 num-derive = "0.3.3"
 num-traits = "0.2.17"
-pdl-runtime = "0.3.0"
+pdl-runtime = "0.3.2"
 serde = { version = "1.0", features = ["derive"] }
 serde_json = "1.0"
 thiserror = "1.0.49"
diff --git a/build.rs b/build.rs
index c99bdd8..d9002bc 100644
--- a/build.rs
+++ b/build.rs
@@ -39,7 +39,7 @@ fn generate_module(in_file: &Path) {
     )
     .expect("PDL parse failed");
     let analyzed_file = pdl_compiler::analyzer::analyze(&parsed_file).expect("PDL analysis failed");
-    let rust_source = pdl_compiler::backends::rust_legacy::generate(&sources, &analyzed_file);
+    let rust_source = pdl_compiler::backends::rust::generate(&sources, &analyzed_file, &[]);
     out_file
         .write_all(rust_source.as_bytes())
         .expect("Could not write to output file");
diff --git a/py/pica/pica/packets/uci.py b/py/pica/pica/packets/uci.py
index 574feab..99b11b1 100644
--- a/py/pica/pica/packets/uci.py
+++ b/py/pica/pica/packets/uci.py
@@ -1120,19 +1120,31 @@ class ControlPacket(Packet):
         span = bytes([])
         fields['payload'] = payload
         try:
-            return CorePacket.parse(fields.copy(), payload)
+            child, remainder = CorePacket.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionConfigPacket.parse(fields.copy(), payload)
+            child, remainder = SessionConfigPacket.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionControlPacket.parse(fields.copy(), payload)
+            child, remainder = SessionControlPacket.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return AndroidPacket.parse(fields.copy(), payload)
+            child, remainder = AndroidPacket.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         return ControlPacket(**fields), span
@@ -1174,11 +1186,17 @@ class DataPacket(Packet):
         span = bytes([])
         fields['payload'] = payload
         try:
-            return DataMessageSnd.parse(fields.copy(), payload)
+            child, remainder = DataMessageSnd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return DataMessageRcv.parse(fields.copy(), payload)
+            child, remainder = DataMessageRcv.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         return DataPacket(**fields), span
@@ -1331,59 +1349,101 @@ class CorePacket(ControlPacket):
         span = bytes([])
         fields['payload'] = payload
         try:
-            return CoreDeviceResetCmd.parse(fields.copy(), payload)
+            child, remainder = CoreDeviceResetCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreDeviceResetRsp.parse(fields.copy(), payload)
+            child, remainder = CoreDeviceResetRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreDeviceStatusNtf.parse(fields.copy(), payload)
+            child, remainder = CoreDeviceStatusNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreGetDeviceInfoCmd.parse(fields.copy(), payload)
+            child, remainder = CoreGetDeviceInfoCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreGetDeviceInfoRsp.parse(fields.copy(), payload)
+            child, remainder = CoreGetDeviceInfoRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreGetCapsInfoCmd.parse(fields.copy(), payload)
+            child, remainder = CoreGetCapsInfoCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreGetCapsInfoRsp.parse(fields.copy(), payload)
+            child, remainder = CoreGetCapsInfoRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreSetConfigCmd.parse(fields.copy(), payload)
+            child, remainder = CoreSetConfigCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreSetConfigRsp.parse(fields.copy(), payload)
+            child, remainder = CoreSetConfigRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreGetConfigCmd.parse(fields.copy(), payload)
+            child, remainder = CoreGetConfigCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreGetConfigRsp.parse(fields.copy(), payload)
+            child, remainder = CoreGetConfigRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreGenericErrorNtf.parse(fields.copy(), payload)
+            child, remainder = CoreGenericErrorNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreQueryTimeStampCmd.parse(fields.copy(), payload)
+            child, remainder = CoreQueryTimeStampCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return CoreQueryTimeStampRsp.parse(fields.copy(), payload)
+            child, remainder = CoreQueryTimeStampRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         return CorePacket(**fields), span
@@ -1419,95 +1479,164 @@ class SessionConfigPacket(ControlPacket):
         span = bytes([])
         fields['payload'] = payload
         try:
-            return SessionInitCmd.parse(fields.copy(), payload)
+            child, remainder = SessionInitCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionInitRsp_V2.parse(fields.copy(), payload)
+            child, remainder = SessionInitRsp_V2.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionInitRsp.parse(fields.copy(), payload)
+            child, remainder = SessionInitRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionDeinitCmd.parse(fields.copy(), payload)
+            child, remainder = SessionDeinitCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionDeinitRsp.parse(fields.copy(), payload)
+            child, remainder = SessionDeinitRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionStatusNtf.parse(fields.copy(), payload)
+            child, remainder = SessionStatusNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionSetAppConfigCmd.parse(fields.copy(), payload)
+            child, remainder = SessionSetAppConfigCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionSetAppConfigRsp.parse(fields.copy(), payload)
+            child, remainder = SessionSetAppConfigRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionGetAppConfigCmd.parse(fields.copy(), payload)
+            child, remainder = SessionGetAppConfigCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionGetAppConfigRsp.parse(fields.copy(), payload)
+            child, remainder = SessionGetAppConfigRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionGetCountCmd.parse(fields.copy(), payload)
+            child, remainder = SessionGetCountCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionGetCountRsp.parse(fields.copy(), payload)
+            child, remainder = SessionGetCountRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionGetStateCmd.parse(fields.copy(), payload)
+            child, remainder = SessionGetStateCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionGetStateRsp.parse(fields.copy(), payload)
+            child, remainder = SessionGetStateRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionUpdateDtAnchorRangingRoundsCmd.parse(fields.copy(), payload)
+            child, remainder = SessionUpdateDtAnchorRangingRoundsCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionUpdateDtAnchorRangingRoundsRsp.parse(fields.copy(), payload)
+            child, remainder = SessionUpdateDtAnchorRangingRoundsRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionUpdateDtTagRangingRoundsCmd.parse(fields.copy(), payload)
+            child, remainder = SessionUpdateDtTagRangingRoundsCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionUpdateDtTagRangingRoundsRsp.parse(fields.copy(), payload)
+            child, remainder = SessionUpdateDtTagRangingRoundsRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionUpdateControllerMulticastListCmd.parse(fields.copy(), payload)
+            child, remainder = SessionUpdateControllerMulticastListCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionUpdateControllerMulticastListRsp.parse(fields.copy(), payload)
+            child, remainder = SessionUpdateControllerMulticastListRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionUpdateControllerMulticastListNtf.parse(fields.copy(), payload)
+            child, remainder = SessionUpdateControllerMulticastListNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionQueryMaxDataSizeInRangingCmd.parse(fields.copy(), payload)
+            child, remainder = SessionQueryMaxDataSizeInRangingCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionQueryMaxDataSizeInRangingRsp.parse(fields.copy(), payload)
+            child, remainder = SessionQueryMaxDataSizeInRangingRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         return SessionConfigPacket(**fields), span
@@ -1543,39 +1672,66 @@ class SessionControlPacket(ControlPacket):
         span = bytes([])
         fields['payload'] = payload
         try:
-            return SessionDataCreditNtf.parse(fields.copy(), payload)
+            child, remainder = SessionDataCreditNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionDataTransferStatusNtf.parse(fields.copy(), payload)
+            child, remainder = SessionDataTransferStatusNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionStartCmd.parse(fields.copy(), payload)
+            child, remainder = SessionStartCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionStartRsp.parse(fields.copy(), payload)
+            child, remainder = SessionStartRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionInfoNtf.parse(fields.copy(), payload)
+            child, remainder = SessionInfoNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionStopCmd.parse(fields.copy(), payload)
+            child, remainder = SessionStopCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionStopRsp.parse(fields.copy(), payload)
+            child, remainder = SessionStopRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionGetRangingCountCmd.parse(fields.copy(), payload)
+            child, remainder = SessionGetRangingCountCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return SessionGetRangingCountRsp.parse(fields.copy(), payload)
+            child, remainder = SessionGetRangingCountRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         return SessionControlPacket(**fields), span
@@ -1611,23 +1767,38 @@ class AndroidPacket(ControlPacket):
         span = bytes([])
         fields['payload'] = payload
         try:
-            return AndroidGetPowerStatsCmd.parse(fields.copy(), payload)
+            child, remainder = AndroidGetPowerStatsCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return AndroidGetPowerStatsRsp.parse(fields.copy(), payload)
+            child, remainder = AndroidGetPowerStatsRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return AndroidSetCountryCodeCmd.parse(fields.copy(), payload)
+            child, remainder = AndroidSetCountryCodeCmd.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return AndroidSetCountryCodeRsp.parse(fields.copy(), payload)
+            child, remainder = AndroidSetCountryCodeRsp.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return AndroidRangeDiagnosticsNtf.parse(fields.copy(), payload)
+            child, remainder = AndroidRangeDiagnosticsNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         return AndroidPacket(**fields), span
@@ -3237,7 +3408,6 @@ class SessionUpdateControllerMulticastListRsp(SessionConfigPacket):
 @dataclass
 class ControleeStatus(Packet):
     mac_address: bytearray = field(kw_only=True, default_factory=bytearray)
-    subsession_id: int = field(kw_only=True, default=0)
     status: MulticastUpdateStatus = field(kw_only=True, default=MulticastUpdateStatus.OK_MULTICAST_LIST_UPDATE)
 
     def __post_init__(self):
@@ -3250,32 +3420,25 @@ class ControleeStatus(Packet):
             raise Exception('Invalid packet size')
         fields['mac_address'] = list(span[:2])
         span = span[2:]
-        if len(span) < 5:
+        if len(span) < 1:
             raise Exception('Invalid packet size')
-        value_ = int.from_bytes(span[0:4], byteorder='little')
-        fields['subsession_id'] = value_
-        fields['status'] = MulticastUpdateStatus.from_int(span[4])
-        span = span[5:]
+        fields['status'] = MulticastUpdateStatus.from_int(span[0])
+        span = span[1:]
         return ControleeStatus(**fields), span
 
     def serialize(self, payload: bytes = None) -> bytes:
         _span = bytearray()
         _span.extend(self.mac_address)
-        if self.subsession_id > 4294967295:
-            print(f"Invalid value for field ControleeStatus::subsession_id: {self.subsession_id} > 4294967295; the value will be truncated")
-            self.subsession_id &= 4294967295
-        _span.extend(int.to_bytes((self.subsession_id << 0), length=4, byteorder='little'))
         _span.append((self.status << 0))
         return bytes(_span)
 
     @property
     def size(self) -> int:
-        return 7
+        return 3
 
 @dataclass
 class SessionUpdateControllerMulticastListNtf(SessionConfigPacket):
     session_token: int = field(kw_only=True, default=0)
-    remaining_multicast_list_size: int = field(kw_only=True, default=0)
     controlee_status: List[ControleeStatus] = field(kw_only=True, default_factory=list)
 
     def __post_init__(self):
@@ -3287,20 +3450,19 @@ class SessionUpdateControllerMulticastListNtf(SessionConfigPacket):
     def parse(fields: dict, span: bytes) -> Tuple['SessionUpdateControllerMulticastListNtf', bytes]:
         if fields['mt'] != MessageType.NOTIFICATION or fields['oid'] != SessionConfigOpcodeId.UPDATE_CONTROLLER_MULTICAST_LIST or fields['gid'] != GroupId.SESSION_CONFIG:
             raise Exception("Invalid constraint field values")
-        if len(span) < 6:
+        if len(span) < 5:
             raise Exception('Invalid packet size')
         value_ = int.from_bytes(span[0:4], byteorder='little')
         fields['session_token'] = value_
-        fields['remaining_multicast_list_size'] = span[4]
-        controlee_status_count = span[5]
-        span = span[6:]
-        if len(span) < controlee_status_count * 7:
+        controlee_status_count = span[4]
+        span = span[5:]
+        if len(span) < controlee_status_count * 3:
             raise Exception('Invalid packet size')
         controlee_status = []
         for n in range(controlee_status_count):
-            controlee_status.append(ControleeStatus.parse_all(span[n * 7:(n + 1) * 7]))
+            controlee_status.append(ControleeStatus.parse_all(span[n * 3:(n + 1) * 3]))
         fields['controlee_status'] = controlee_status
-        span = span[controlee_status_count * 7:]
+        span = span[controlee_status_count * 3:]
         return SessionUpdateControllerMulticastListNtf(**fields), span
 
     def serialize(self, payload: bytes = None) -> bytes:
@@ -3309,10 +3471,6 @@ class SessionUpdateControllerMulticastListNtf(SessionConfigPacket):
             print(f"Invalid value for field SessionUpdateControllerMulticastListNtf::session_token: {self.session_token} > 4294967295; the value will be truncated")
             self.session_token &= 4294967295
         _span.extend(int.to_bytes((self.session_token << 0), length=4, byteorder='little'))
-        if self.remaining_multicast_list_size > 255:
-            print(f"Invalid value for field SessionUpdateControllerMulticastListNtf::remaining_multicast_list_size: {self.remaining_multicast_list_size} > 255; the value will be truncated")
-            self.remaining_multicast_list_size &= 255
-        _span.append((self.remaining_multicast_list_size << 0))
         if len(self.controlee_status) > 255:
             print(f"Invalid length for field SessionUpdateControllerMulticastListNtf::controlee_status:  {len(self.controlee_status)} > 255; the array will be truncated")
             del self.controlee_status[255:]
@@ -3323,7 +3481,7 @@ class SessionUpdateControllerMulticastListNtf(SessionConfigPacket):
 
     @property
     def size(self) -> int:
-        return sum([elt.size for elt in self.controlee_status]) + 6
+        return sum([elt.size for elt in self.controlee_status]) + 5
 
 @dataclass
 class SessionDataCreditNtf(SessionControlPacket):
@@ -3916,6 +4074,365 @@ class ExtendedAddressOwrAoaRangingMeasurement(Packet):
     def size(self) -> int:
         return 19
 
+@dataclass
+class Wgs84Location(Packet):
+    data: bytearray = field(kw_only=True, default_factory=bytearray)
+
+    def __post_init__(self):
+        pass
+
+    @staticmethod
+    def parse(span: bytes) -> Tuple['Wgs84Location', bytes]:
+        fields = {'payload': None}
+        if len(span) < 12:
+            raise Exception('Invalid packet size')
+        fields['data'] = list(span[:12])
+        span = span[12:]
+        return Wgs84Location(**fields), span
+
+    def serialize(self, payload: bytes = None) -> bytes:
+        _span = bytearray()
+        _span.extend(self.data)
+        return bytes(_span)
+
+    @property
+    def size(self) -> int:
+        return 12
+
+@dataclass
+class RelativeLocation(Packet):
+    x: int = field(kw_only=True, default=0)
+    y: int = field(kw_only=True, default=0)
+    z: int = field(kw_only=True, default=0)
+
+    def __post_init__(self):
+        pass
+
+    @staticmethod
+    def parse(span: bytes) -> Tuple['RelativeLocation', bytes]:
+        fields = {'payload': None}
+        if len(span) < 10:
+            raise Exception('Invalid packet size')
+        value_ = int.from_bytes(span[0:7], byteorder='little')
+        fields['x'] = (value_ >> 0) & 0xfffffff
+        fields['y'] = (value_ >> 28) & 0xfffffff
+        value_ = int.from_bytes(span[7:10], byteorder='little')
+        fields['z'] = value_
+        span = span[10:]
+        return RelativeLocation(**fields), span
+
+    def serialize(self, payload: bytes = None) -> bytes:
+        _span = bytearray()
+        if self.x > 268435455:
+            print(f"Invalid value for field RelativeLocation::x: {self.x} > 268435455; the value will be truncated")
+            self.x &= 268435455
+        if self.y > 268435455:
+            print(f"Invalid value for field RelativeLocation::y: {self.y} > 268435455; the value will be truncated")
+            self.y &= 268435455
+        _value = (
+            (self.x << 0) |
+            (self.y << 28)
+        )
+        _span.extend(int.to_bytes(_value, length=7, byteorder='little'))
+        if self.z > 16777215:
+            print(f"Invalid value for field RelativeLocation::z: {self.z} > 16777215; the value will be truncated")
+            self.z &= 16777215
+        _span.extend(int.to_bytes((self.z << 0), length=3, byteorder='little'))
+        return bytes(_span)
+
+    @property
+    def size(self) -> int:
+        return 10
+
+@dataclass
+class DlTdoaRangingMeasurement(Packet):
+    status: Status = field(kw_only=True, default=Status.OK)
+    message_type: int = field(kw_only=True, default=0)
+    tx_timestamp_type: int = field(kw_only=True, default=0)
+    block_index: int = field(kw_only=True, default=0)
+    round_index: int = field(kw_only=True, default=0)
+    nlos: int = field(kw_only=True, default=0)
+    aoa_azimuth: int = field(kw_only=True, default=0)
+    aoa_azimuth_fom: int = field(kw_only=True, default=0)
+    aoa_elevation: int = field(kw_only=True, default=0)
+    aoa_elevation_fom: int = field(kw_only=True, default=0)
+    rssi: int = field(kw_only=True, default=0)
+    tx_timestamp_40: Optional[int] = field(kw_only=True, default=None)
+    tx_timestamp_64: Optional[int] = field(kw_only=True, default=None)
+    rx_timestamp_40: Optional[int] = field(kw_only=True, default=None)
+    rx_timestamp_64: Optional[int] = field(kw_only=True, default=None)
+    anchor_cfo: int = field(kw_only=True, default=0)
+    cfo: int = field(kw_only=True, default=0)
+    initiator_reply_time: int = field(kw_only=True, default=0)
+    responder_reply_time: int = field(kw_only=True, default=0)
+    initiator_responder_tof: int = field(kw_only=True, default=0)
+    wgs84_location: List[Wgs84Location] = field(kw_only=True, default_factory=list)
+    relative_location: List[RelativeLocation] = field(kw_only=True, default_factory=list)
+    active_ranging_rounds: bytearray = field(kw_only=True, default_factory=bytearray)
+
+    def __post_init__(self):
+        pass
+
+    @staticmethod
+    def parse(span: bytes) -> Tuple['DlTdoaRangingMeasurement', bytes]:
+        fields = {'payload': None}
+        if len(span) < 15:
+            raise Exception('Invalid packet size')
+        fields['status'] = Status.from_int(span[0])
+        fields['message_type'] = span[1]
+        value_ = int.from_bytes(span[2:4], byteorder='little')
+        fields['tx_timestamp_type'] = (value_ >> 0) & 0x1
+        tx_timestamp_length = (value_ >> 1) & 0x1
+        rx_timestamp_length = (value_ >> 3) & 0x1
+        wgs84_location_count = (value_ >> 5) & 0x1
+        relative_location_count = (value_ >> 6) & 0x1
+        active_ranging_rounds_count = (value_ >> 7) & 0xf
+        value_ = int.from_bytes(span[4:6], byteorder='little')
+        fields['block_index'] = value_
+        fields['round_index'] = span[6]
+        fields['nlos'] = span[7]
+        value_ = int.from_bytes(span[8:10], byteorder='little')
+        fields['aoa_azimuth'] = value_
+        fields['aoa_azimuth_fom'] = span[10]
+        value_ = int.from_bytes(span[11:13], byteorder='little')
+        fields['aoa_elevation'] = value_
+        fields['aoa_elevation_fom'] = span[13]
+        fields['rssi'] = span[14]
+        span = span[15:]
+        
+        if tx_timestamp_length == 0:
+            if len(span) < 5:
+                raise Exception('Invalid packet size')
+            fields['tx_timestamp_40'] = int.from_bytes(span[:5], byteorder='little')
+            span = span[5:]
+        
+        
+        if tx_timestamp_length == 1:
+            if len(span) < 8:
+                raise Exception('Invalid packet size')
+            fields['tx_timestamp_64'] = int.from_bytes(span[:8], byteorder='little')
+            span = span[8:]
+        
+        
+        if rx_timestamp_length == 0:
+            if len(span) < 5:
+                raise Exception('Invalid packet size')
+            fields['rx_timestamp_40'] = int.from_bytes(span[:5], byteorder='little')
+            span = span[5:]
+        
+        
+        if rx_timestamp_length == 1:
+            if len(span) < 8:
+                raise Exception('Invalid packet size')
+            fields['rx_timestamp_64'] = int.from_bytes(span[:8], byteorder='little')
+            span = span[8:]
+        
+        if len(span) < 14:
+            raise Exception('Invalid packet size')
+        value_ = int.from_bytes(span[0:2], byteorder='little')
+        fields['anchor_cfo'] = value_
+        value_ = int.from_bytes(span[2:4], byteorder='little')
+        fields['cfo'] = value_
+        value_ = int.from_bytes(span[4:8], byteorder='little')
+        fields['initiator_reply_time'] = value_
+        value_ = int.from_bytes(span[8:12], byteorder='little')
+        fields['responder_reply_time'] = value_
+        value_ = int.from_bytes(span[12:14], byteorder='little')
+        fields['initiator_responder_tof'] = value_
+        span = span[14:]
+        if len(span) < wgs84_location_count * 12:
+            raise Exception('Invalid packet size')
+        wgs84_location = []
+        for n in range(wgs84_location_count):
+            wgs84_location.append(Wgs84Location.parse_all(span[n * 12:(n + 1) * 12]))
+        fields['wgs84_location'] = wgs84_location
+        span = span[wgs84_location_count * 12:]
+        if len(span) < relative_location_count * 10:
+            raise Exception('Invalid packet size')
+        relative_location = []
+        for n in range(relative_location_count):
+            relative_location.append(RelativeLocation.parse_all(span[n * 10:(n + 1) * 10]))
+        fields['relative_location'] = relative_location
+        span = span[relative_location_count * 10:]
+        if len(span) < active_ranging_rounds_count:
+            raise Exception('Invalid packet size')
+        fields['active_ranging_rounds'] = list(span[:active_ranging_rounds_count])
+        span = span[active_ranging_rounds_count:]
+        return DlTdoaRangingMeasurement(**fields), span
+
+    def serialize(self, payload: bytes = None) -> bytes:
+        _span = bytearray()
+        _span.append((self.status << 0))
+        if self.message_type > 255:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::message_type: {self.message_type} > 255; the value will be truncated")
+            self.message_type &= 255
+        _span.append((self.message_type << 0))
+        if self.tx_timestamp_type > 1:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::tx_timestamp_type: {self.tx_timestamp_type} > 1; the value will be truncated")
+            self.tx_timestamp_type &= 1
+        if len(self.wgs84_location) > 1:
+            print(f"Invalid length for field DlTdoaRangingMeasurement::wgs84_location:  {len(self.wgs84_location)} > 1; the array will be truncated")
+            del self.wgs84_location[1:]
+        if len(self.relative_location) > 1:
+            print(f"Invalid length for field DlTdoaRangingMeasurement::relative_location:  {len(self.relative_location)} > 1; the array will be truncated")
+            del self.relative_location[1:]
+        if len(self.active_ranging_rounds) > 15:
+            print(f"Invalid length for field DlTdoaRangingMeasurement::active_ranging_rounds:  {len(self.active_ranging_rounds)} > 15; the array will be truncated")
+            del self.active_ranging_rounds[15:]
+        _value = (
+            (self.tx_timestamp_type << 0) |
+            ((0 if self.tx_timestamp_64 is None else 1) << 1) |
+            ((0 if self.rx_timestamp_64 is None else 1) << 3) |
+            (len(self.wgs84_location) << 5) |
+            (len(self.relative_location) << 6) |
+            (len(self.active_ranging_rounds) << 7)
+        )
+        _span.extend(int.to_bytes(_value, length=2, byteorder='little'))
+        if self.block_index > 65535:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::block_index: {self.block_index} > 65535; the value will be truncated")
+            self.block_index &= 65535
+        _span.extend(int.to_bytes((self.block_index << 0), length=2, byteorder='little'))
+        if self.round_index > 255:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::round_index: {self.round_index} > 255; the value will be truncated")
+            self.round_index &= 255
+        _span.append((self.round_index << 0))
+        if self.nlos > 255:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::nlos: {self.nlos} > 255; the value will be truncated")
+            self.nlos &= 255
+        _span.append((self.nlos << 0))
+        if self.aoa_azimuth > 65535:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::aoa_azimuth: {self.aoa_azimuth} > 65535; the value will be truncated")
+            self.aoa_azimuth &= 65535
+        _span.extend(int.to_bytes((self.aoa_azimuth << 0), length=2, byteorder='little'))
+        if self.aoa_azimuth_fom > 255:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::aoa_azimuth_fom: {self.aoa_azimuth_fom} > 255; the value will be truncated")
+            self.aoa_azimuth_fom &= 255
+        _span.append((self.aoa_azimuth_fom << 0))
+        if self.aoa_elevation > 65535:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::aoa_elevation: {self.aoa_elevation} > 65535; the value will be truncated")
+            self.aoa_elevation &= 65535
+        _span.extend(int.to_bytes((self.aoa_elevation << 0), length=2, byteorder='little'))
+        if self.aoa_elevation_fom > 255:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::aoa_elevation_fom: {self.aoa_elevation_fom} > 255; the value will be truncated")
+            self.aoa_elevation_fom &= 255
+        _span.append((self.aoa_elevation_fom << 0))
+        if self.rssi > 255:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::rssi: {self.rssi} > 255; the value will be truncated")
+            self.rssi &= 255
+        _span.append((self.rssi << 0))
+        
+        if self.tx_timestamp_40 is not None:
+            _span.extend(int.to_bytes(self.tx_timestamp_40, length=5, byteorder='little'))
+        
+        
+        if self.tx_timestamp_64 is not None:
+            _span.extend(int.to_bytes(self.tx_timestamp_64, length=8, byteorder='little'))
+        
+        
+        if self.rx_timestamp_40 is not None:
+            _span.extend(int.to_bytes(self.rx_timestamp_40, length=5, byteorder='little'))
+        
+        
+        if self.rx_timestamp_64 is not None:
+            _span.extend(int.to_bytes(self.rx_timestamp_64, length=8, byteorder='little'))
+        
+        if self.anchor_cfo > 65535:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::anchor_cfo: {self.anchor_cfo} > 65535; the value will be truncated")
+            self.anchor_cfo &= 65535
+        _span.extend(int.to_bytes((self.anchor_cfo << 0), length=2, byteorder='little'))
+        if self.cfo > 65535:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::cfo: {self.cfo} > 65535; the value will be truncated")
+            self.cfo &= 65535
+        _span.extend(int.to_bytes((self.cfo << 0), length=2, byteorder='little'))
+        if self.initiator_reply_time > 4294967295:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::initiator_reply_time: {self.initiator_reply_time} > 4294967295; the value will be truncated")
+            self.initiator_reply_time &= 4294967295
+        _span.extend(int.to_bytes((self.initiator_reply_time << 0), length=4, byteorder='little'))
+        if self.responder_reply_time > 4294967295:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::responder_reply_time: {self.responder_reply_time} > 4294967295; the value will be truncated")
+            self.responder_reply_time &= 4294967295
+        _span.extend(int.to_bytes((self.responder_reply_time << 0), length=4, byteorder='little'))
+        if self.initiator_responder_tof > 65535:
+            print(f"Invalid value for field DlTdoaRangingMeasurement::initiator_responder_tof: {self.initiator_responder_tof} > 65535; the value will be truncated")
+            self.initiator_responder_tof &= 65535
+        _span.extend(int.to_bytes((self.initiator_responder_tof << 0), length=2, byteorder='little'))
+        for _elt in self.wgs84_location:
+            _span.extend(_elt.serialize())
+        for _elt in self.relative_location:
+            _span.extend(_elt.serialize())
+        _span.extend(self.active_ranging_rounds)
+        return bytes(_span)
+
+    @property
+    def size(self) -> int:
+        (0 if self.tx_timestamp_40 is None else 40)
+
+@dataclass
+class ShortAddressDlTdoaRangingMeasurement(Packet):
+    mac_address: int = field(kw_only=True, default=0)
+    measurement: DlTdoaRangingMeasurement = field(kw_only=True, default_factory=DlTdoaRangingMeasurement)
+
+    def __post_init__(self):
+        pass
+
+    @staticmethod
+    def parse(span: bytes) -> Tuple['ShortAddressDlTdoaRangingMeasurement', bytes]:
+        fields = {'payload': None}
+        if len(span) < 2:
+            raise Exception('Invalid packet size')
+        value_ = int.from_bytes(span[0:2], byteorder='little')
+        fields['mac_address'] = value_
+        span = span[2:]
+        measurement, span = DlTdoaRangingMeasurement.parse(span)
+        fields['measurement'] = measurement
+        return ShortAddressDlTdoaRangingMeasurement(**fields), span
+
+    def serialize(self, payload: bytes = None) -> bytes:
+        _span = bytearray()
+        if self.mac_address > 65535:
+            print(f"Invalid value for field ShortAddressDlTdoaRangingMeasurement::mac_address: {self.mac_address} > 65535; the value will be truncated")
+            self.mac_address &= 65535
+        _span.extend(int.to_bytes((self.mac_address << 0), length=2, byteorder='little'))
+        _span.extend(self.measurement.serialize())
+        return bytes(_span)
+
+    @property
+    def size(self) -> int:
+        return self.measurement.size + 2
+
+@dataclass
+class ExtendedAddressDlTdoaRangingMeasurement(Packet):
+    mac_address: int = field(kw_only=True, default=0)
+    measurement: DlTdoaRangingMeasurement = field(kw_only=True, default_factory=DlTdoaRangingMeasurement)
+
+    def __post_init__(self):
+        pass
+
+    @staticmethod
+    def parse(span: bytes) -> Tuple['ExtendedAddressDlTdoaRangingMeasurement', bytes]:
+        fields = {'payload': None}
+        if len(span) < 8:
+            raise Exception('Invalid packet size')
+        value_ = int.from_bytes(span[0:8], byteorder='little')
+        fields['mac_address'] = value_
+        span = span[8:]
+        measurement, span = DlTdoaRangingMeasurement.parse(span)
+        fields['measurement'] = measurement
+        return ExtendedAddressDlTdoaRangingMeasurement(**fields), span
+
+    def serialize(self, payload: bytes = None) -> bytes:
+        _span = bytearray()
+        if self.mac_address > 18446744073709551615:
+            print(f"Invalid value for field ExtendedAddressDlTdoaRangingMeasurement::mac_address: {self.mac_address} > 18446744073709551615; the value will be truncated")
+            self.mac_address &= 18446744073709551615
+        _span.extend(int.to_bytes((self.mac_address << 0), length=8, byteorder='little'))
+        _span.extend(self.measurement.serialize())
+        return bytes(_span)
+
+    @property
+    def size(self) -> int:
+        return self.measurement.size + 8
+
 class RangingMeasurementType(enum.IntEnum):
     ONE_WAY = 0x0
     TWO_WAY = 0x1
@@ -3965,27 +4482,45 @@ class SessionInfoNtf(SessionControlPacket):
         span = bytes([])
         fields['payload'] = payload
         try:
-            return ShortMacTwoWaySessionInfoNtf.parse(fields.copy(), payload)
+            child, remainder = ShortMacTwoWaySessionInfoNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return ExtendedMacTwoWaySessionInfoNtf.parse(fields.copy(), payload)
+            child, remainder = ExtendedMacTwoWaySessionInfoNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return ShortMacDlTDoASessionInfoNtf.parse(fields.copy(), payload)
+            child, remainder = ShortMacDlTDoASessionInfoNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return ExtendedMacDlTDoASessionInfoNtf.parse(fields.copy(), payload)
+            child, remainder = ExtendedMacDlTDoASessionInfoNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return ShortMacOwrAoaSessionInfoNtf.parse(fields.copy(), payload)
+            child, remainder = ShortMacOwrAoaSessionInfoNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return ExtendedMacOwrAoaSessionInfoNtf.parse(fields.copy(), payload)
+            child, remainder = ExtendedMacOwrAoaSessionInfoNtf.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         return SessionInfoNtf(**fields), span
@@ -4119,8 +4654,7 @@ class ExtendedMacTwoWaySessionInfoNtf(SessionInfoNtf):
 
 @dataclass
 class ShortMacDlTDoASessionInfoNtf(SessionInfoNtf):
-    no_of_ranging_measurements: int = field(kw_only=True, default=0)
-    dl_tdoa_measurements: bytearray = field(kw_only=True, default_factory=bytearray)
+    dl_tdoa_measurements: List[ShortAddressDlTdoaRangingMeasurement] = field(kw_only=True, default_factory=list)
 
     def __post_init__(self):
         self.ranging_measurement_type = RangingMeasurementType.DL_TDOA
@@ -4135,29 +4669,32 @@ class ShortMacDlTDoASessionInfoNtf(SessionInfoNtf):
             raise Exception("Invalid constraint field values")
         if len(span) < 1:
             raise Exception('Invalid packet size')
-        fields['no_of_ranging_measurements'] = span[0]
+        dl_tdoa_measurements_count = span[0]
         span = span[1:]
-        fields['dl_tdoa_measurements'] = list(span)
-        span = bytes()
+        dl_tdoa_measurements = []
+        for n in range(dl_tdoa_measurements_count):
+            element, span = ShortAddressDlTdoaRangingMeasurement.parse(span)
+            dl_tdoa_measurements.append(element)
+        fields['dl_tdoa_measurements'] = dl_tdoa_measurements
         return ShortMacDlTDoASessionInfoNtf(**fields), span
 
     def serialize(self, payload: bytes = None) -> bytes:
         _span = bytearray()
-        if self.no_of_ranging_measurements > 255:
-            print(f"Invalid value for field ShortMacDlTDoASessionInfoNtf::no_of_ranging_measurements: {self.no_of_ranging_measurements} > 255; the value will be truncated")
-            self.no_of_ranging_measurements &= 255
-        _span.append((self.no_of_ranging_measurements << 0))
-        _span.extend(self.dl_tdoa_measurements)
+        if len(self.dl_tdoa_measurements) > 255:
+            print(f"Invalid length for field ShortMacDlTDoASessionInfoNtf::dl_tdoa_measurements:  {len(self.dl_tdoa_measurements)} > 255; the array will be truncated")
+            del self.dl_tdoa_measurements[255:]
+        _span.append((len(self.dl_tdoa_measurements) << 0))
+        for _elt in self.dl_tdoa_measurements:
+            _span.extend(_elt.serialize())
         return SessionInfoNtf.serialize(self, payload = bytes(_span))
 
     @property
     def size(self) -> int:
-        return len(self.dl_tdoa_measurements) * 1 + 1
+        return sum([elt.size for elt in self.dl_tdoa_measurements]) + 1
 
 @dataclass
 class ExtendedMacDlTDoASessionInfoNtf(SessionInfoNtf):
-    no_of_ranging_measurements: int = field(kw_only=True, default=0)
-    dl_tdoa_measurements: bytearray = field(kw_only=True, default_factory=bytearray)
+    dl_tdoa_measurements: List[ExtendedAddressDlTdoaRangingMeasurement] = field(kw_only=True, default_factory=list)
 
     def __post_init__(self):
         self.ranging_measurement_type = RangingMeasurementType.DL_TDOA
@@ -4172,24 +4709,28 @@ class ExtendedMacDlTDoASessionInfoNtf(SessionInfoNtf):
             raise Exception("Invalid constraint field values")
         if len(span) < 1:
             raise Exception('Invalid packet size')
-        fields['no_of_ranging_measurements'] = span[0]
+        dl_tdoa_measurements_count = span[0]
         span = span[1:]
-        fields['dl_tdoa_measurements'] = list(span)
-        span = bytes()
+        dl_tdoa_measurements = []
+        for n in range(dl_tdoa_measurements_count):
+            element, span = ExtendedAddressDlTdoaRangingMeasurement.parse(span)
+            dl_tdoa_measurements.append(element)
+        fields['dl_tdoa_measurements'] = dl_tdoa_measurements
         return ExtendedMacDlTDoASessionInfoNtf(**fields), span
 
     def serialize(self, payload: bytes = None) -> bytes:
         _span = bytearray()
-        if self.no_of_ranging_measurements > 255:
-            print(f"Invalid value for field ExtendedMacDlTDoASessionInfoNtf::no_of_ranging_measurements: {self.no_of_ranging_measurements} > 255; the value will be truncated")
-            self.no_of_ranging_measurements &= 255
-        _span.append((self.no_of_ranging_measurements << 0))
-        _span.extend(self.dl_tdoa_measurements)
+        if len(self.dl_tdoa_measurements) > 255:
+            print(f"Invalid length for field ExtendedMacDlTDoASessionInfoNtf::dl_tdoa_measurements:  {len(self.dl_tdoa_measurements)} > 255; the array will be truncated")
+            del self.dl_tdoa_measurements[255:]
+        _span.append((len(self.dl_tdoa_measurements) << 0))
+        for _elt in self.dl_tdoa_measurements:
+            _span.extend(_elt.serialize())
         return SessionInfoNtf.serialize(self, payload = bytes(_span))
 
     @property
     def size(self) -> int:
-        return len(self.dl_tdoa_measurements) * 1 + 1
+        return sum([elt.size for elt in self.dl_tdoa_measurements]) + 1
 
 @dataclass
 class ShortMacOwrAoaSessionInfoNtf(SessionInfoNtf):
@@ -4645,15 +5186,24 @@ class FrameReportTlvPacket(Packet):
         span = span[_body__size:]
         fields['payload'] = payload
         try:
-            return Rssi.parse(fields.copy(), payload)
+            child, remainder = Rssi.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return Aoa.parse(fields.copy(), payload)
+            child, remainder = Aoa.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         try:
-            return Cir.parse(fields.copy(), payload)
+            child, remainder = Cir.parse(fields.copy(), payload)
+            if remainder:
+                raise Exception('Unexpected parsing remainder')
+            return child, span
         except Exception as exn:
             pass
         return FrameReportTlvPacket(**fields), span
diff --git a/src/device.rs b/src/device.rs
index 0558dbc..fdbbb3d 100644
--- a/src/device.rs
+++ b/src/device.rs
@@ -99,6 +99,11 @@ impl Default for DeviceConfig {
 }
 
 pub struct Device {
+    /// Flag set when the device has received the Core Device Reset command.
+    /// The first command received by the device is expected to be Core Device
+    /// Reset, receiving any other command before this is indicative of a
+    /// bad host state.
+    is_reset: bool,
     pub handle: usize,
     pub mac_address: MacAddress,
     config: DeviceConfig,
@@ -108,7 +113,6 @@ pub struct Device {
     pub tx: mpsc::UnboundedSender<UciPacket>,
     pica_tx: mpsc::Sender<PicaCommand>,
     country_code: [u8; 2],
-
     pub n_active_sessions: usize,
 }
 
@@ -122,6 +126,7 @@ impl Device {
         Device {
             handle,
             mac_address,
+            is_reset: false,
             config: Default::default(),
             state: DeviceState::DeviceStateError, // Will be overwitten
             sessions: Default::default(),
@@ -144,8 +149,7 @@ impl Device {
         tokio::spawn(async move {
             time::sleep(Duration::from_millis(5)).await;
             tx.send(
-                CoreDeviceStatusNtfBuilder { device_state }
-                    .build()
+                CoreDeviceStatusNtf { device_state }
                     .encode_to_vec()
                     .unwrap(),
             )
@@ -212,29 +216,29 @@ impl Device {
     // The fira norm specify to send a response, then reset, then
     // send a notification once the reset is done
     fn core_device_reset(&mut self, cmd: CoreDeviceResetCmd) -> CoreDeviceResetRsp {
-        let reset_config = cmd.get_reset_config();
+        let reset_config = cmd.reset_config;
         log::debug!("[{}] DeviceReset", self.handle);
         log::debug!("  reset_config={:?}", reset_config);
 
-        let status = match reset_config {
-            ResetConfig::UwbsReset => uci::Status::Ok,
-        };
         *self = Device::new(
             self.handle,
             self.mac_address,
             self.tx.clone(),
             self.pica_tx.clone(),
         );
+        self.is_reset = true;
         self.init();
 
-        CoreDeviceResetRspBuilder { status }.build()
+        CoreDeviceResetRsp {
+            status: uci::Status::Ok,
+        }
     }
 
     fn core_get_device_info(&self, _cmd: CoreGetDeviceInfoCmd) -> CoreGetDeviceInfoRsp {
         // TODO: Implement a fancy build time state machine instead of crash at runtime
         log::debug!("[{}] GetDeviceInfo", self.handle);
         assert_eq!(self.state, DeviceState::DeviceStateReady);
-        CoreGetDeviceInfoRspBuilder {
+        CoreGetDeviceInfoRsp {
             status: uci::Status::Ok,
             uci_version: UCI_VERSION,
             mac_version: MAC_VERSION,
@@ -242,7 +246,6 @@ impl Device {
             uci_test_version: TEST_VERSION,
             vendor_spec_info: Vec::new(),
         }
-        .build()
     }
 
     pub fn core_get_caps_info(&self, _cmd: CoreGetCapsInfoCmd) -> CoreGetCapsInfoRsp {
@@ -256,11 +259,10 @@ impl Device {
             })
             .collect();
 
-        CoreGetCapsInfoRspBuilder {
+        CoreGetCapsInfoRsp {
             status: uci::Status::Ok,
             tlvs: caps,
         }
-        .build()
     }
 
     pub fn core_set_config(&mut self, cmd: CoreSetConfigCmd) -> CoreSetConfigRsp {
@@ -274,7 +276,7 @@ impl Device {
         // available in the UWBS. All other configuration parameters should
         // have been set to the new values within the UWBS.
         let mut invalid_parameters = vec![];
-        for parameter in cmd.get_parameters() {
+        for parameter in cmd.parameters {
             match parameter.id {
                 uci::ConfigParameterId::DeviceState => {
                     invalid_parameters.push(uci::ConfigParameterStatus {
@@ -295,7 +297,7 @@ impl Device {
             }
         }
 
-        CoreSetConfigRspBuilder {
+        CoreSetConfigRsp {
             status: if invalid_parameters.is_empty() {
                 uci::Status::Ok
             } else {
@@ -303,7 +305,6 @@ impl Device {
             },
             parameters: invalid_parameters,
         }
-        .build()
     }
 
     pub fn core_get_config(&self, cmd: CoreGetConfigCmd) -> CoreGetConfigRsp {
@@ -318,41 +319,38 @@ impl Device {
         // that are available in the UWBS.
         let mut valid_parameters = vec![];
         let mut invalid_parameters = vec![];
-        for id in cmd.get_parameter_ids() {
+        for id in cmd.parameter_ids {
             match id {
                 ConfigParameterId::DeviceState => valid_parameters.push(ConfigParameter {
-                    id: *id,
+                    id,
                     value: vec![self.config.device_state.into()],
                 }),
                 ConfigParameterId::LowPowerMode => valid_parameters.push(ConfigParameter {
-                    id: *id,
+                    id,
                     value: vec![self.config.low_power_mode.into()],
                 }),
-                ConfigParameterId::Rfu(_) => invalid_parameters.push(ConfigParameter {
-                    id: *id,
-                    value: vec![],
-                }),
+                ConfigParameterId::Rfu(_) => {
+                    invalid_parameters.push(ConfigParameter { id, value: vec![] })
+                }
             }
         }
 
         if invalid_parameters.is_empty() {
-            CoreGetConfigRspBuilder {
+            CoreGetConfigRsp {
                 status: uci::Status::Ok,
                 parameters: valid_parameters,
             }
-            .build()
         } else {
-            CoreGetConfigRspBuilder {
+            CoreGetConfigRsp {
                 status: uci::Status::InvalidParam,
                 parameters: invalid_parameters,
             }
-            .build()
         }
     }
 
     fn session_init(&mut self, cmd: SessionInitCmd) -> SessionInitRsp {
-        let session_id = cmd.get_session_id();
-        let session_type = cmd.get_session_type();
+        let session_id = cmd.session_id;
+        let session_type = cmd.session_type;
 
         log::debug!("[{}] Session init", self.handle);
         log::debug!("  session_id=0x{:x}", session_id);
@@ -374,11 +372,11 @@ impl Device {
             }
         };
 
-        SessionInitRspBuilder { status }.build()
+        SessionInitRsp { status }
     }
 
     fn session_deinit(&mut self, cmd: SessionDeinitCmd) -> SessionDeinitRsp {
-        let session_id = cmd.get_session_token();
+        let session_id = cmd.session_token;
         log::debug!("[{}] Session deinit", self.handle);
         log::debug!("  session_id=0x{:x}", session_id);
 
@@ -395,21 +393,20 @@ impl Device {
             }
             None => uci::Status::ErrorSessionNotExist,
         };
-        SessionDeinitRspBuilder { status }.build()
+        SessionDeinitRsp { status }
     }
 
     fn session_get_count(&self, _cmd: SessionGetCountCmd) -> SessionGetCountRsp {
         log::debug!("[{}] Session get count", self.handle);
 
-        SessionGetCountRspBuilder {
+        SessionGetCountRsp {
             status: uci::Status::Ok,
             session_count: self.sessions.len() as u8,
         }
-        .build()
     }
 
     fn session_set_app_config(&mut self, cmd: SessionSetAppConfigCmd) -> SessionSetAppConfigRsp {
-        let session_handle = cmd.get_session_token();
+        let session_handle = cmd.session_token;
 
         log::debug!(
             "[{}:0x{:x}] Session Set App Config",
@@ -418,11 +415,10 @@ impl Device {
         );
 
         let Some(session) = self.sessions.get_mut(&session_handle) else {
-            return SessionSetAppConfigRspBuilder {
+            return SessionSetAppConfigRsp {
                 cfg_status: Vec::new(),
                 status: uci::Status::ErrorSessionNotExist,
-            }
-            .build();
+            };
         };
 
         assert!(
@@ -433,15 +429,14 @@ impl Device {
         if session.state == SessionState::SessionStateActive {
             const IMMUTABLE_PARAMETERS: &[AppConfigTlvType] = &[AppConfigTlvType::AoaResultReq];
             if cmd
-                .get_tlvs()
+                .tlvs
                 .iter()
                 .any(|cfg| IMMUTABLE_PARAMETERS.contains(&cfg.cfg_id))
             {
-                return SessionSetAppConfigRspBuilder {
+                return SessionSetAppConfigRsp {
                     status: uci::Status::ErrorSessionActive,
                     cfg_status: vec![],
-                }
-                .build();
+                };
             }
         }
 
@@ -452,7 +447,7 @@ impl Device {
         } else {
             let mut app_config = session.app_config.clone();
             let mut invalid_parameters = vec![];
-            for cfg in cmd.get_tlvs() {
+            for cfg in cmd.tlvs {
                 match app_config.set(cfg.cfg_id, &cfg.v) {
                     Ok(_) => (),
                     Err(_) => invalid_parameters.push(AppConfigStatus {
@@ -485,11 +480,10 @@ impl Device {
                     self.handle,
                     session_handle
                 );
-                return SessionSetAppConfigRspBuilder {
+                return SessionSetAppConfigRsp {
                     status: uci::Status::Rejected,
                     cfg_status: vec![],
-                }
-                .build();
+                };
             }
 
             if invalid_parameters.is_empty() {
@@ -506,15 +500,14 @@ impl Device {
             }
         };
 
-        SessionSetAppConfigRspBuilder {
+        SessionSetAppConfigRsp {
             status,
             cfg_status: invalid_parameters,
         }
-        .build()
     }
 
     fn session_get_app_config(&self, cmd: SessionGetAppConfigCmd) -> SessionGetAppConfigRsp {
-        let session_handle = cmd.get_session_token();
+        let session_handle = cmd.session_token;
 
         log::debug!(
             "[{}:0x{:x}] Session Get App Config",
@@ -523,24 +516,23 @@ impl Device {
         );
 
         let Some(session) = self.sessions.get(&session_handle) else {
-            return SessionGetAppConfigRspBuilder {
+            return SessionGetAppConfigRsp {
                 tlvs: vec![],
                 status: uci::Status::ErrorSessionNotExist,
-            }
-            .build();
+            };
         };
 
         let (status, valid_parameters) = {
             let mut valid_parameters = vec![];
             let mut invalid_parameters = vec![];
-            for id in cmd.get_app_cfg() {
-                match session.app_config.get(*id) {
+            for id in cmd.app_cfg {
+                match session.app_config.get(id) {
                     Ok(value) => valid_parameters.push(AppConfigTlv {
-                        cfg_id: *id,
+                        cfg_id: id,
                         v: value,
                     }),
                     Err(_) => invalid_parameters.push(AppConfigTlv {
-                        cfg_id: *id,
+                        cfg_id: id,
                         v: vec![],
                     }),
                 }
@@ -553,38 +545,35 @@ impl Device {
             }
         };
 
-        SessionGetAppConfigRspBuilder {
+        SessionGetAppConfigRsp {
             status,
             tlvs: valid_parameters,
         }
-        .build()
     }
 
     fn session_get_state(&self, cmd: SessionGetStateCmd) -> SessionGetStateRsp {
-        let session_handle = cmd.get_session_token();
+        let session_handle = cmd.session_token;
 
         log::debug!("[{}:0x{:x}] Session Get State", self.handle, session_handle);
 
         let Some(session) = self.sessions.get(&session_handle) else {
-            return SessionGetStateRspBuilder {
+            return SessionGetStateRsp {
                 session_state: SessionState::SessionStateInit,
                 status: uci::Status::ErrorSessionNotExist,
-            }
-            .build();
+            };
         };
 
-        SessionGetStateRspBuilder {
+        SessionGetStateRsp {
             status: uci::Status::Ok,
             session_state: session.state,
         }
-        .build()
     }
 
     fn session_update_controller_multicast_list(
         &mut self,
         cmd: SessionUpdateControllerMulticastListCmd,
     ) -> SessionUpdateControllerMulticastListRsp {
-        let session_handle = cmd.get_session_token();
+        let session_handle = cmd.session_token;
 
         log::debug!(
             "[{}:0x{:x}] Session Update Controller Multicast List",
@@ -593,10 +582,10 @@ impl Device {
         );
 
         let Some(session) = self.sessions.get_mut(&session_handle) else {
-            return SessionUpdateControllerMulticastListRspBuilder {
+            return SessionUpdateControllerMulticastListRsp {
                 status: uci::Status::ErrorSessionNotExist,
-            }
-            .build();
+                controlee_status: vec![],
+            };
         };
 
         if (session.state != SessionState::SessionStateActive
@@ -604,18 +593,18 @@ impl Device {
             || session.app_config.device_type != Some(DeviceType::Controller)
             || session.app_config.multi_node_mode != Some(MultiNodeMode::OneToMany)
         {
-            return SessionUpdateControllerMulticastListRspBuilder {
+            return SessionUpdateControllerMulticastListRsp {
                 status: uci::Status::Rejected,
-            }
-            .build();
+                controlee_status: vec![],
+            };
         }
-        let action = cmd.get_action();
+        let action = cmd.action;
         let mut dst_addresses = session.app_config.dst_mac_address.clone();
         let new_controlees: Vec<Controlee> = match action {
             UpdateMulticastListAction::AddControlee
             | UpdateMulticastListAction::RemoveControlee => {
                 if let Ok(packet) =
-                    SessionUpdateControllerMulticastListCmdPayload::parse(cmd.get_payload())
+                    SessionUpdateControllerMulticastListCmdPayload::decode_full(&cmd.payload)
                 {
                     packet
                         .controlees
@@ -623,16 +612,16 @@ impl Device {
                         .map(|controlee| controlee.into())
                         .collect()
                 } else {
-                    return SessionUpdateControllerMulticastListRspBuilder {
+                    return SessionUpdateControllerMulticastListRsp {
                         status: uci::Status::SyntaxError,
-                    }
-                    .build();
+                        controlee_status: vec![],
+                    };
                 }
             }
             UpdateMulticastListAction::AddControleeWithShortSubSessionKey => {
                 if let Ok(packet) =
-                    SessionUpdateControllerMulticastListCmd_2_0_16_Byte_Payload::parse(
-                        cmd.get_payload(),
+                    SessionUpdateControllerMulticastListCmd_2_0_16_Byte_Payload::decode_full(
+                        &cmd.payload,
                     )
                 {
                     packet
@@ -641,16 +630,16 @@ impl Device {
                         .map(|controlee| controlee.into())
                         .collect()
                 } else {
-                    return SessionUpdateControllerMulticastListRspBuilder {
+                    return SessionUpdateControllerMulticastListRsp {
                         status: uci::Status::SyntaxError,
-                    }
-                    .build();
+                        controlee_status: vec![],
+                    };
                 }
             }
             UpdateMulticastListAction::AddControleeWithExtendedSubSessionKey => {
                 if let Ok(packet) =
-                    SessionUpdateControllerMulticastListCmd_2_0_32_Byte_Payload::parse(
-                        cmd.get_payload(),
+                    SessionUpdateControllerMulticastListCmd_2_0_32_Byte_Payload::decode_full(
+                        &cmd.payload,
                     )
                 {
                     packet
@@ -659,14 +648,15 @@ impl Device {
                         .map(|controlee| controlee.into())
                         .collect()
                 } else {
-                    return SessionUpdateControllerMulticastListRspBuilder {
+                    return SessionUpdateControllerMulticastListRsp {
                         status: uci::Status::SyntaxError,
-                    }
-                    .build();
+                        controlee_status: vec![],
+                    };
                 }
             }
         };
-        let mut controlee_status = Vec::new();
+        let mut controlee_status_ntf = Vec::new();
+        let mut controlee_status_rsp = Vec::new();
         let mut status = uci::Status::Ok;
 
         match action {
@@ -675,34 +665,49 @@ impl Device {
             | UpdateMulticastListAction::AddControleeWithExtendedSubSessionKey => {
                 new_controlees.iter().for_each(|controlee| {
                     let mut update_status = MulticastUpdateStatus::OkMulticastListUpdate;
-                    if !dst_addresses.contains(&controlee.short_address) {
-                        if dst_addresses.len() == MAX_NUMBER_OF_CONTROLEES {
-                            status = uci::Status::ErrorMulticastListFull;
-                            update_status = MulticastUpdateStatus::ErrorMulticastListFull;
-                        } else if (action
-                            == UpdateMulticastListAction::AddControleeWithShortSubSessionKey
-                            || action
-                                == UpdateMulticastListAction::AddControleeWithExtendedSubSessionKey)
-                            && session.app_config.sts_config
-                                != uci::StsConfig::ProvisionedForResponderSubSessionKey
-                        {
-                            // If Action is 0x02 or 0x03 for STS_CONFIG values other than
-                            // 0x04, the UWBS shall return SESSION_UPDATE_CONTROLLER_MULTICAST_LIST_NTF
-                            // with Status set to STATUS_ERROR_SUB_SESSION_KEY_NOT_APPLICABLE for each
-                            // Controlee in the Controlee List.
-                            status = uci::Status::Failed;
-                            update_status = MulticastUpdateStatus::ErrorSubSessionKeyNotApplicable;
+                    if (action == UpdateMulticastListAction::AddControleeWithShortSubSessionKey
+                        || action
+                            == UpdateMulticastListAction::AddControleeWithExtendedSubSessionKey)
+                        && session.app_config.sts_config
+                            != uci::StsConfig::ProvisionedForResponderSubSessionKey
+                    {
+                        // If Action is 0x02 or 0x03 for STS_CONFIG values other than
+                        // 0x04, the UWBS shall return SESSION_UPDATE_CONTROLLER_MULTICAST_LIST_NTF
+                        // with Status set to STATUS_ERROR_SUB_SESSION_KEY_NOT_APPLICABLE for each
+                        // Controlee in the Controlee List.
+                        status = uci::Status::Failed;
+                        update_status = MulticastUpdateStatus::ErrorSubSessionKeyNotApplicable;
+                        controlee_status_ntf.push(ControleeStatus {
+                            mac_address: match controlee.short_address {
+                                MacAddress::Short(address) => address,
+                                MacAddress::Extended(_) => {
+                                    panic!("Extended address is not supported!")
+                                }
+                            },
+                            status: update_status,
+                        });
+                    } else {
+                        if !dst_addresses.contains(&controlee.short_address) {
+                            if dst_addresses.len() == MAX_NUMBER_OF_CONTROLEES {
+                                status = uci::Status::ErrorMulticastListFull;
+                                update_status = MulticastUpdateStatus::ErrorMulticastListFull;
+                            } else {
+                                dst_addresses.push(controlee.short_address);
+                            };
                         } else {
-                            dst_addresses.push(controlee.short_address);
-                        };
+                            status = uci::Status::Failed;
+                            update_status = MulticastUpdateStatus::ErrorAddressAlreadyPresent;
+                        }
+                        controlee_status_rsp.push(ControleeStatus {
+                            mac_address: match controlee.short_address {
+                                MacAddress::Short(address) => address,
+                                MacAddress::Extended(_) => {
+                                    panic!("Extended address is not supported!")
+                                }
+                            },
+                            status: update_status,
+                        });
                     }
-                    controlee_status.push(ControleeStatus {
-                        mac_address: match controlee.short_address {
-                            MacAddress::Short(address) => address,
-                            MacAddress::Extended(_) => panic!("Extended address is not supported!"),
-                        },
-                        status: update_status,
-                    });
                 });
             }
             UpdateMulticastListAction::RemoveControlee => {
@@ -713,7 +718,7 @@ impl Device {
                     let mut update_status = MulticastUpdateStatus::OkMulticastListUpdate;
                     if !dst_addresses.contains(&address) {
                         status = uci::Status::Failed;
-                        update_status = MulticastUpdateStatus::ErrorKeyFetchFail;
+                        update_status = MulticastUpdateStatus::ErrorAddressNotFound;
                     } else {
                         dst_addresses.retain(|value| *value != address);
                         // If IN_BAND_TERMINATION_ATTEMPT_COUNT is not equal to 0x00, then the
@@ -730,8 +735,17 @@ impl Device {
                                 }
                             });
                         }
+                        controlee_status_ntf.push(ControleeStatus {
+                            mac_address: match address {
+                                MacAddress::Short(addr) => addr,
+                                MacAddress::Extended(_) => {
+                                    panic!("Extended address is not supported!")
+                                }
+                            },
+                            status: update_status,
+                        });
                     }
-                    controlee_status.push(ControleeStatus {
+                    controlee_status_rsp.push(ControleeStatus {
                         mac_address: match address {
                             MacAddress::Short(addr) => addr,
                             MacAddress::Extended(_) => panic!("Extended address is not supported!"),
@@ -753,11 +767,10 @@ impl Device {
                         // TODO(#84) remove the sleep.
                         time::sleep(Duration::from_millis(5)).await;
                         tx.send(
-                            SessionUpdateControllerMulticastListNtfBuilder {
-                                controlee_status,
+                            SessionUpdateControllerMulticastListNtf {
+                                controlee_status: controlee_status_ntf,
                                 session_token: session_handle,
                             }
-                            .build()
                             .encode_to_vec()
                             .unwrap(),
                         )
@@ -777,26 +790,27 @@ impl Device {
                 ReasonCode::ErrorInvalidNumOfControlees,
             )
         }
-        SessionUpdateControllerMulticastListRspBuilder { status }.build()
+        SessionUpdateControllerMulticastListRsp {
+            status,
+            controlee_status: controlee_status_rsp,
+        }
     }
 
     fn session_start(&mut self, cmd: SessionStartCmd) -> SessionStartRsp {
-        let session_id = cmd.get_session_id();
+        let session_id = cmd.session_id;
 
         log::debug!("[{}:0x{:x}] Session Start", self.handle, session_id);
 
         let Some(session) = self.sessions.get_mut(&session_id) else {
-            return SessionStartRspBuilder {
+            return SessionStartRsp {
                 status: uci::Status::ErrorSessionNotExist,
-            }
-            .build();
+            };
         };
 
         if session.state != SessionState::SessionStateIdle {
-            return SessionStartRspBuilder {
+            return SessionStartRsp {
                 status: uci::Status::ErrorSessionNotConfigured,
-            }
-            .build();
+            };
         }
 
         assert!(session.ranging_task.is_none());
@@ -823,29 +837,26 @@ impl Device {
         self.n_active_sessions += 1;
         self.set_state(DeviceState::DeviceStateActive);
 
-        SessionStartRspBuilder {
+        SessionStartRsp {
             status: uci::Status::Ok,
         }
-        .build()
     }
 
     fn session_stop(&mut self, cmd: SessionStopCmd) -> SessionStopRsp {
-        let session_id = cmd.get_session_id();
+        let session_id = cmd.session_id;
 
         log::debug!("[{}:0x{:x}] Session Stop", self.handle, session_id);
 
         let Some(session) = self.sessions.get_mut(&session_id) else {
-            return SessionStopRspBuilder {
+            return SessionStopRsp {
                 status: uci::Status::ErrorSessionNotExist,
-            }
-            .build();
+            };
         };
 
         if session.state != SessionState::SessionStateActive {
-            return SessionStopRspBuilder {
+            return SessionStopRsp {
                 status: uci::Status::ErrorSessionActive,
-            }
-            .build();
+            };
         }
 
         session.stop_ranging_task();
@@ -859,17 +870,16 @@ impl Device {
             self.set_state(DeviceState::DeviceStateReady);
         }
 
-        SessionStopRspBuilder {
+        SessionStopRsp {
             status: uci::Status::Ok,
         }
-        .build()
     }
 
     fn session_get_ranging_count(
         &self,
         cmd: SessionGetRangingCountCmd,
     ) -> SessionGetRangingCountRsp {
-        let session_id = cmd.get_session_id();
+        let session_id = cmd.session_id;
 
         log::debug!(
             "[{}:0x{:x}] Session Get Ranging Count",
@@ -878,33 +888,31 @@ impl Device {
         );
 
         let Some(session) = self.sessions.get(&session_id) else {
-            return SessionGetRangingCountRspBuilder {
+            return SessionGetRangingCountRsp {
                 status: uci::Status::ErrorSessionNotExist,
                 count: 0,
-            }
-            .build();
+            };
         };
 
-        SessionGetRangingCountRspBuilder {
+        SessionGetRangingCountRsp {
             status: uci::Status::Ok,
             count: session.sequence_number,
         }
-        .build()
     }
 
     fn android_set_country_code(
         &mut self,
         cmd: AndroidSetCountryCodeCmd,
     ) -> AndroidSetCountryCodeRsp {
-        let country_code = *cmd.get_country_code();
+        let country_code = cmd.country_code;
+
         log::debug!("[{}] Set country code", self.handle);
         log::debug!("  country_code={},{}", country_code[0], country_code[1]);
 
         self.country_code = country_code;
-        AndroidSetCountryCodeRspBuilder {
+        AndroidSetCountryCodeRsp {
             status: uci::Status::Ok,
         }
-        .build()
     }
 
     fn android_get_power_stats(
@@ -914,7 +922,7 @@ impl Device {
         log::debug!("[{}] Get power stats", self.handle);
 
         // TODO
-        AndroidGetPowerStatsRspBuilder {
+        AndroidGetPowerStatsRsp {
             stats: PowerStats {
                 status: uci::Status::Ok,
                 idle_time_ms: 0,
@@ -923,38 +931,40 @@ impl Device {
                 total_wake_count: 0,
             },
         }
-        .build()
     }
 
     pub fn data_message_snd(&mut self, data: DataPacket) -> ControlPacket {
         log::debug!("[{}] data_message_send", self.handle);
-        match data.specialize() {
+        match data
+            .specialize()
+            .expect("failed to parse Data packet child")
+        {
             DataPacketChild::DataMessageSnd(data_msg_snd) => {
-                let session_token = data_msg_snd.get_session_handle();
+                let session_token = data_msg_snd.session_handle;
                 if let Some(session) = self.session_mut(session_token) {
                     session.data_message_snd(data_msg_snd)
                 } else {
-                    SessionDataTransferStatusNtfBuilder {
+                    SessionDataTransferStatusNtf {
                         session_token,
                         status: DataTransferNtfStatusCode::UciDataTransferStatusErrorRejected,
                         tx_count: 1, // TODO: support for retries?
                         uci_sequence_number: 0,
                     }
-                    .build()
-                    .into()
+                    .try_into()
+                    .unwrap()
                 }
             }
             DataPacketChild::DataMessageRcv(data_msg_rcv) => {
                 // This function should not be passed anything besides DataMessageSnd
-                let session_token = data_msg_rcv.get_session_handle();
-                SessionDataTransferStatusNtfBuilder {
+                let session_token = data_msg_rcv.session_handle;
+                SessionDataTransferStatusNtf {
                     session_token,
                     status: DataTransferNtfStatusCode::UciDataTransferStatusInvalidFormat,
                     tx_count: 1, // TODO: support for retries?
                     uci_sequence_number: 0,
                 }
-                .build()
-                .into()
+                .try_into()
+                .unwrap()
             }
             _ => {
                 unimplemented!()
@@ -969,65 +979,113 @@ impl Device {
         use SessionConfigPacketChild::*;
         use SessionControlPacketChild::*;
 
-        match cmd.specialize() {
+        // Check whether the first command received is the Core Device
+        // Reset command. The controller responds with Device Status
+        // Notification with DEVICE_STATE_ERROR otherwise.
+        if !self.is_reset && !cmd.is_core_device_reset_cmd() {
+            return uci::CoreDeviceStatusNtf {
+                device_state: DeviceState::DeviceStateError,
+            }
+            .try_into()
+            .unwrap();
+        }
+
+        match cmd
+            .specialize()
+            .expect("Failed to parse Control packet child")
+        {
             CorePacket(cmd) => match cmd.specialize() {
-                CoreDeviceResetCmd(cmd) => self.core_device_reset(cmd).into(),
-                CoreGetDeviceInfoCmd(cmd) => self.core_get_device_info(cmd).into(),
-                CoreGetCapsInfoCmd(cmd) => self.core_get_caps_info(cmd).into(),
-                CoreSetConfigCmd(cmd) => self.core_set_config(cmd).into(),
-                CoreGetConfigCmd(cmd) => self.core_get_config(cmd).into(),
-                _ => unimplemented!("Unsupported Core oid {:?}", cmd.get_oid()),
+                Ok(CoreDeviceResetCmd(cmd)) => self.core_device_reset(cmd).try_into().unwrap(),
+                Ok(CoreGetDeviceInfoCmd(cmd)) => self.core_get_device_info(cmd).try_into().unwrap(),
+                Ok(CoreGetCapsInfoCmd(cmd)) => self.core_get_caps_info(cmd).try_into().unwrap(),
+                Ok(CoreSetConfigCmd(cmd)) => self.core_set_config(cmd).try_into().unwrap(),
+                Ok(CoreGetConfigCmd(cmd)) => self.core_get_config(cmd).try_into().unwrap(),
+                _ => uci::CorePacket {
+                    mt: uci::MessageType::Response,
+                    oid: cmd.oid,
+                    payload: vec![0x1, uci::Status::SyntaxError.into()],
+                }
+                .try_into()
+                .unwrap(),
             },
             SessionConfigPacket(cmd) => match cmd.specialize() {
-                SessionInitCmd(cmd) => self.session_init(cmd).into(),
-                SessionDeinitCmd(cmd) => self.session_deinit(cmd).into(),
-                SessionGetCountCmd(cmd) => self.session_get_count(cmd).into(),
-                SessionSetAppConfigCmd(cmd) => self.session_set_app_config(cmd).into(),
-                SessionGetAppConfigCmd(cmd) => self.session_get_app_config(cmd).into(),
-                SessionGetStateCmd(cmd) => self.session_get_state(cmd).into(),
-                SessionUpdateControllerMulticastListCmd(cmd) => {
-                    self.session_update_controller_multicast_list(cmd).into()
+                Ok(SessionInitCmd(cmd)) => self.session_init(cmd).try_into().unwrap(),
+                Ok(SessionDeinitCmd(cmd)) => self.session_deinit(cmd).try_into().unwrap(),
+                Ok(SessionGetCountCmd(cmd)) => self.session_get_count(cmd).try_into().unwrap(),
+                Ok(SessionSetAppConfigCmd(cmd)) => {
+                    self.session_set_app_config(cmd).try_into().unwrap()
                 }
-                _ => unimplemented!("Unsupported Session Config oid {:?}", cmd.get_oid()),
+                Ok(SessionGetAppConfigCmd(cmd)) => {
+                    self.session_get_app_config(cmd).try_into().unwrap()
+                }
+                Ok(SessionGetStateCmd(cmd)) => self.session_get_state(cmd).try_into().unwrap(),
+                Ok(SessionUpdateControllerMulticastListCmd(cmd)) => self
+                    .session_update_controller_multicast_list(cmd)
+                    .try_into()
+                    .unwrap(),
+                _ => uci::SessionConfigPacket {
+                    mt: uci::MessageType::Response,
+                    oid: cmd.oid,
+                    payload: vec![0x1, uci::Status::SyntaxError.into()],
+                }
+                .try_into()
+                .unwrap(),
             },
             SessionControlPacket(cmd) => match cmd.specialize() {
-                SessionStartCmd(cmd) => self.session_start(cmd).into(),
-                SessionStopCmd(cmd) => self.session_stop(cmd).into(),
-                SessionGetRangingCountCmd(cmd) => self.session_get_ranging_count(cmd).into(),
-                _ => unimplemented!("Unsupported Session Control oid {:?}", cmd.get_oid()),
+                Ok(SessionStartCmd(cmd)) => self.session_start(cmd).try_into().unwrap(),
+                Ok(SessionStopCmd(cmd)) => self.session_stop(cmd).try_into().unwrap(),
+                Ok(SessionGetRangingCountCmd(cmd)) => {
+                    self.session_get_ranging_count(cmd).try_into().unwrap()
+                }
+                _ => uci::SessionControlPacket {
+                    mt: uci::MessageType::Response,
+                    oid: cmd.oid,
+                    payload: vec![0x1, uci::Status::SyntaxError.into()],
+                }
+                .try_into()
+                .unwrap(),
             },
             AndroidPacket(cmd) => match cmd.specialize() {
-                AndroidSetCountryCodeCmd(cmd) => self.android_set_country_code(cmd).into(),
-                AndroidGetPowerStatsCmd(cmd) => self.android_get_power_stats(cmd).into(),
-                _ => unimplemented!("Unsupported Android oid {:?}", cmd.get_oid()),
+                Ok(AndroidSetCountryCodeCmd(cmd)) => {
+                    self.android_set_country_code(cmd).try_into().unwrap()
+                }
+                Ok(AndroidGetPowerStatsCmd(cmd)) => {
+                    self.android_get_power_stats(cmd).try_into().unwrap()
+                }
+                _ => uci::AndroidPacket {
+                    mt: uci::MessageType::Response,
+                    oid: cmd.oid,
+                    payload: vec![0x1, uci::Status::SyntaxError.into()],
+                }
+                .try_into()
+                .unwrap(),
             },
-            ControlPacketChild::Payload(_)
+            ControlPacketChild::None
                 if matches!(
-                    cmd.get_mt(),
+                    cmd.mt,
                     uci::MessageType::Response | uci::MessageType::Notification
                 ) =>
             {
-                unreachable!("Unhandled control messsage with type {:?}", cmd.get_mt());
+                unreachable!("Unhandled control messsage with type {:?}", cmd.mt);
             }
-            ControlPacketChild::Payload(payload) => {
+            ControlPacketChild::None => {
                 // [UCI] 4.3.2 Exception Handling for Control Messages
                 // The UWBS shall respond to an unknown Command (unknown GID
                 // or OID) with a Response having the same GID and OID field
                 // values as the Command, followed by a Status field with the
                 // value of STATUS_UNKNOWN_GID/STATUS_UNKNOWN_OID respectively
                 // and no additional fields.
-                log::error!("Unsupported gid {:?}", cmd.get_gid());
-                ControlPacketBuilder {
+                log::error!("Unsupported gid {:?}", cmd.gid);
+                ControlPacket {
                     mt: uci::MessageType::Response,
-                    gid: cmd.get_gid(),
-                    payload: Some(
-                        vec![payload[0], payload[1], 0x1, uci::Status::UnknownGid.into()].into(),
-                    ),
+                    gid: cmd.gid,
+                    payload: vec![
+                        cmd.payload[0],
+                        cmd.payload[1],
+                        0x1,
+                        uci::Status::UnknownGid.into(),
+                    ],
                 }
-                .build()
-            }
-            ControlPacketChild::None => {
-                unreachable!()
             }
         }
     }
@@ -1035,7 +1093,7 @@ impl Device {
     pub fn receive_packet(&mut self, packet: Vec<u8>) {
         let mt = parse_message_type(packet[0]);
         match mt {
-            MessageType::Data => match DataPacket::parse(&packet) {
+            MessageType::Data => match DataPacket::decode_full(&packet) {
                 Ok(packet) => {
                     let notification = self.data_message_snd(packet);
                     self.send_control(notification)
@@ -1043,7 +1101,7 @@ impl Device {
                 Err(err) => log::error!("failed to parse incoming Data packet: {}", err),
             },
             MessageType::Command => {
-                match ControlPacket::parse(&packet) {
+                match ControlPacket::decode_full(&packet) {
                     // Parsing error. Determine what error response should be
                     // returned to the host:
                     // - response and notifications are ignored, no response
diff --git a/src/lib.rs b/src/lib.rs
index ef9fdd6..a1c7c7e 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -253,7 +253,7 @@ impl Pica {
                     .await
                     .ok_or(anyhow::anyhow!("input packet stream closed"))?;
                 let header =
-                    packets::uci::CommonPacketHeader::parse(&packet[0..COMMON_HEADER_SIZE])?;
+                    packets::uci::CommonPacketHeader::decode_full(&packet[0..COMMON_HEADER_SIZE])?;
 
                 if let Some(file) = pcapng_file {
                     file.write(&packet, pcapng::Direction::Tx)?;
@@ -266,8 +266,8 @@ impl Pica {
                     None => complete_packet = Some(packet),
                 }
 
-                if header.get_pbf() == packets::uci::PacketBoundaryFlag::Complete
-                    || header.get_mt() == packets::uci::MessageType::Data
+                if header.pbf == packets::uci::PacketBoundaryFlag::Complete
+                    || header.mt == packets::uci::MessageType::Data
                 {
                     break;
                 }
@@ -445,14 +445,18 @@ impl Pica {
                     .app_config
                     .device_mac_address
                     .unwrap();
-                let local = self
+                let Some(local) = self
                     .ranging_estimator
                     .estimate(&device.handle, &peer_device.handle)
-                    .unwrap_or(Default::default());
-                let remote = self
+                else {
+                    continue;
+                };
+                let Some(remote) = self
                     .ranging_estimator
                     .estimate(&peer_device.handle, &device.handle)
-                    .unwrap_or(Default::default());
+                else {
+                    continue;
+                };
                 measurements.push(make_measurement(&peer_mac_address, local, remote));
             }
 
@@ -469,7 +473,7 @@ impl Pica {
             peer_device
                 .tx
                 .send(
-                    DataMessageRcvBuilder {
+                    DataMessageRcv {
                         application_data: session.data().clone().into(),
                         data_sequence_number: 0x01,
                         pbf: PacketBoundaryFlag::Complete,
@@ -477,7 +481,6 @@ impl Pica {
                         source_address: session.app_config.device_mac_address.unwrap().into(),
                         status: uci::Status::Ok,
                     }
-                    .build()
                     .encode_to_vec()
                     .unwrap(),
                 )
@@ -488,7 +491,7 @@ impl Pica {
                 .tx
                 .send(
                     // TODO: support extended address
-                    ShortMacTwoWaySessionInfoNtfBuilder {
+                    ShortMacTwoWaySessionInfoNtf {
                         sequence_number: session.sequence_number,
                         session_token: session_id,
                         rcr_indicator: 0,            //TODO
@@ -496,7 +499,6 @@ impl Pica {
                         two_way_ranging_measurements: measurements,
                         vendor_data: vec![],
                     }
-                    .build()
                     .encode_to_vec()
                     .unwrap(),
                 )
diff --git a/src/packets.rs b/src/packets.rs
index 16e7b4f..50c4ff6 100644
--- a/src/packets.rs
+++ b/src/packets.rs
@@ -25,6 +25,15 @@ pub mod uci {
 
     include!(concat!(env!("OUT_DIR"), "/uci_packets.rs"));
 
+    impl ControlPacket {
+        pub fn is_core_device_reset_cmd(&self) -> bool {
+            let Ok(core_packet) = CorePacket::try_from(self) else {
+                return false;
+            };
+            core_packet.oid == CoreOpcodeId::DeviceReset
+        }
+    }
+
     /// Size of common UCI packet header.
     pub const COMMON_HEADER_SIZE: usize = 1;
     /// Size of UCI packet headers.
@@ -52,17 +61,18 @@ pub mod uci {
         socket.read_exact(&mut packet[0..HEADER_SIZE]).await.ok()?;
 
         let common_packet_header =
-            CommonPacketHeader::parse(&packet[0..COMMON_HEADER_SIZE]).ok()?;
+            CommonPacketHeader::decode_full(&packet[0..COMMON_HEADER_SIZE]).ok()?;
 
-        let payload_length = match common_packet_header.get_mt() {
+        let payload_length = match common_packet_header.mt {
             MessageType::Data => {
-                let data_packet_header = DataPacketHeader::parse(&packet[0..HEADER_SIZE]).ok()?;
-                data_packet_header.get_payload_length() as usize
+                let data_packet_header =
+                    DataPacketHeader::decode_full(&packet[0..HEADER_SIZE]).ok()?;
+                data_packet_header.payload_length as usize
             }
             _ => {
                 let control_packet_header =
-                    ControlPacketHeader::parse(&packet[0..HEADER_SIZE]).ok()?;
-                control_packet_header.get_payload_length() as usize
+                    ControlPacketHeader::decode_full(&packet[0..HEADER_SIZE]).ok()?;
+                control_packet_header.payload_length as usize
             }
         };
 
diff --git a/src/session.rs b/src/session.rs
index e31a262..c1e1d04 100644
--- a/src/session.rs
+++ b/src/session.rs
@@ -75,12 +75,11 @@ impl Session {
         tokio::spawn(async move {
             time::sleep(Duration::from_millis(1)).await;
             tx.send(
-                SessionStatusNtfBuilder {
+                SessionStatusNtf {
                     session_token: session_id,
                     session_state,
                     reason_code: reason_code.into(),
                 }
-                .build()
                 .encode_to_vec()
                 .unwrap(),
             )
@@ -134,30 +133,30 @@ impl Session {
 
     pub fn data_message_snd(&mut self, data: DataMessageSnd) -> ControlPacket {
         log::debug!("[{}] data_message_snd", self.device_handle);
-        let session_token = data.get_session_handle();
-        let uci_sequence_number = data.get_data_sequence_number() as u8;
+        let session_token = data.session_handle;
+        let uci_sequence_number = data.data_sequence_number as u8;
 
         if self.session_type != SessionType::FiraRangingAndInBandDataSession {
-            return SessionDataTransferStatusNtfBuilder {
+            return SessionDataTransferStatusNtf {
                 session_token,
                 status: DataTransferNtfStatusCode::UciDataTransferStatusSessionTypeNotSupported,
                 tx_count: 1, // TODO: support for retries?
                 uci_sequence_number,
             }
-            .build()
-            .into();
+            .try_into()
+            .unwrap();
         }
 
         assert_eq!(self.id, session_token);
 
-        self.data.extend_from_slice(data.get_application_data());
+        self.data.extend_from_slice(&data.application_data);
 
-        SessionDataCreditNtfBuilder {
+        SessionDataCreditNtf {
             credit_availability: CreditAvailability::CreditAvailable,
             session_token,
         }
-        .build()
-        .into()
+        .try_into()
+        .unwrap()
     }
 }
 
diff --git a/src/uci_packets.pdl b/src/uci_packets.pdl
index 05ba3f3..9bca3fc 100644
--- a/src/uci_packets.pdl
+++ b/src/uci_packets.pdl
@@ -1070,6 +1070,8 @@ struct SessionUpdateControllerMulticastListCmd_2_0_32_Byte_Payload {
 
 packet SessionUpdateControllerMulticastListRsp : SessionConfigPacket (mt = RESPONSE, oid = UPDATE_CONTROLLER_MULTICAST_LIST) {
     status: Status,
+    _count_(controlee_status): 8,
+    controlee_status: ControleeStatus[],
 }
 
 test SessionUpdateControllerMulticastListRsp {
@@ -1210,6 +1212,60 @@ struct ExtendedAddressOwrAoaRangingMeasurement {
     aoa_elevation_fom: 8,
 }
 
+struct Wgs84Location {
+    data: 8[12],
+}
+
+struct RelativeLocation {
+    x: 28,
+    y: 28,
+    z: 24,
+}
+
+struct DlTdoaRangingMeasurement {
+    status: Status,
+    message_type: 8,
+    tx_timestamp_type : 1,
+    tx_timestamp_length : 1,
+    _reserved_ : 1,
+    rx_timestamp_length : 1,
+    _reserved_ : 1,
+    _count_(wgs84_location) : 1,
+    _count_(relative_location) : 1,
+    _count_(active_ranging_rounds) : 4,
+    _reserved_ : 5,
+    block_index: 16,
+    round_index: 8,
+    nlos: 8,
+    aoa_azimuth: 16,
+    aoa_azimuth_fom: 8,
+    aoa_elevation: 16,
+    aoa_elevation_fom: 8,
+    rssi: 8,
+    tx_timestamp_40: 40 if tx_timestamp_length = 0,
+    tx_timestamp_64: 64 if tx_timestamp_length = 1,
+    rx_timestamp_40: 40 if rx_timestamp_length = 0,
+    rx_timestamp_64: 64 if rx_timestamp_length = 1,
+    anchor_cfo: 16,
+    cfo: 16,
+    initiator_reply_time: 32,
+    responder_reply_time: 32,
+    initiator_responder_tof: 16,
+    wgs84_location : Wgs84Location[],
+    relative_location : RelativeLocation[],
+    active_ranging_rounds: 8[],
+}
+
+struct ShortAddressDlTdoaRangingMeasurement {
+    mac_address: 16,
+    measurement: DlTdoaRangingMeasurement,
+}
+
+struct ExtendedAddressDlTdoaRangingMeasurement {
+    mac_address: 64,
+    measurement: DlTdoaRangingMeasurement,
+}
+
 enum RangingMeasurementType : 8 {
     ONE_WAY = 0x0,
     TWO_WAY = 0x1,
@@ -1250,8 +1306,8 @@ test ExtendedMacTwoWaySessionInfoNtf {
 }
 
 packet ShortMacDlTDoASessionInfoNtf : SessionInfoNtf (ranging_measurement_type = DL_TDOA, mac_address_indicator = SHORT_ADDRESS) {
-    no_of_ranging_measurements : 8,
-    dl_tdoa_measurements : 8[],
+    _count_(dl_tdoa_measurements) : 8,
+    dl_tdoa_measurements : ShortAddressDlTdoaRangingMeasurement[],
 }
 
 test ShortMacDlTDoASessionInfoNtf {
@@ -1259,8 +1315,8 @@ test ShortMacDlTDoASessionInfoNtf {
 }
 
 packet ExtendedMacDlTDoASessionInfoNtf : SessionInfoNtf (ranging_measurement_type = DL_TDOA, mac_address_indicator = EXTENDED_ADDRESS) {
-    no_of_ranging_measurements : 8,
-    dl_tdoa_measurements : 8[],
+    _count_(dl_tdoa_measurements) : 8,
+    dl_tdoa_measurements : ExtendedAddressDlTdoaRangingMeasurement[],
 }
 
 test ExtendedMacDlTDoASessionInfoNtf {
diff --git a/static/index.html b/static/index.html
index 6b4d188..37c7b77 100644
--- a/static/index.html
+++ b/static/index.html
@@ -73,6 +73,30 @@ limitations under the License.
   const map = document.getElementById("map");
   const info = document.getElementById("info");
 
+  function parse_device(device) {
+    const {
+      mac_address, x, y, z, yaw, pitch, roll,
+    } = device;
+    return {
+      mac_address,
+      position: { x, y, z },
+      yaw,
+      pitch,
+      roll,
+      neighbors: []
+    }
+  }
+
+  async function update_state() {
+    const res = await fetch('/get-state');
+    const { devices } = await res.json();
+    map.devices = devices.map(device => parse_device(device));
+  }
+
+  window.addEventListener('load', async () => {
+    update_state();
+  });
+
   map.addEventListener(
     "select",
     (event) => (info.device = event.detail.device)
@@ -119,19 +143,9 @@ limitations under the License.
     const data = JSON.parse(event.data);
     console.log("Device Added", data);
 
-    const {
-      mac_address, x, y, z, yaw, pitch, roll,
-    } = data;
     map.devices = [
       ...map.devices,
-      {
-        mac_address,
-        position: { x, y, z },
-        yaw,
-        pitch,
-        roll,
-        neighbors: [],
-      },
+      parse_device(data)
     ];
   });
 
```

