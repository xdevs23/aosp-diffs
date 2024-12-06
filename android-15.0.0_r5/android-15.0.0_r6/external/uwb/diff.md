```diff
diff --git a/src/Android.bp b/src/Android.bp
index 78fec77..875197a 100755
--- a/src/Android.bp
+++ b/src/Android.bp
@@ -10,7 +10,7 @@ rust_defaults {
     ],
     edition: "2021",
     proc_macros: ["libnum_derive"],
-    rustlibs:[
+    rustlibs: [
         "libbytes",
         "liblog_rust",
         "libnum_traits",
@@ -27,7 +27,7 @@ rust_test {
         android: {
             test_suites: [
                 "general-tests",
-                "mts-uwb"
+                "mts-uwb",
             ],
             test_config_template: "uwb_rust_test_config_template.xml",
         },
@@ -35,8 +35,8 @@ rust_test {
             test_suites: [
                 "general-tests",
             ],
-           // See b/268061150
-           stem: "libuwb_uci_packet_tests_host",
+            // See b/268061150
+            stem: "libuwb_uci_packet_tests_host",
         },
     },
     // Support multilib variants (using different suffix per sub-architecture), which is needed on
@@ -135,7 +135,7 @@ rust_test {
         android: {
             test_suites: [
                 "general-tests",
-                "mts-uwb"
+                "mts-uwb",
             ],
             test_config_template: "uwb_rust_test_config_template.xml",
         },
@@ -189,6 +189,13 @@ rust_library {
     rustlibs: [
         "libprotobuf",
     ],
+    flags: [
+        // Required due to the protoc-gen-rust tool emitting invalid
+        // annotations.  This can be removed when we upgrade to protobuf-4,
+        // if we patch  protobuf-3 to no longer emit `#![allow(box_pointers)]`,
+        // or switch to using a `rust_protobuf` rule instead of a `genrule`.
+        "-A renamed_and_removed_lints",
+    ],
     features: ["proto"],
     host_supported: true,
     native_coverage: false,
@@ -196,11 +203,14 @@ rust_library {
 
 genrule {
     name: "gen_uwb_core_proto",
-    tools: ["aprotoc", "protoc-gen-rust"],
+    tools: [
+        "aprotoc",
+        "protoc-gen-rust",
+    ],
     cmd: "$(location aprotoc)" +
-         " --proto_path=`dirname $(in)`" +
-         " --plugin=protoc-gen-rust=$(location protoc-gen-rust)" +
-         " --rust_out=$(genDir) $(in)",
+        " --proto_path=`dirname $(in)`" +
+        " --plugin=protoc-gen-rust=$(location protoc-gen-rust)" +
+        " --rust_out=$(genDir) $(in)",
     srcs: [
         "rust/uwb_core/protos/uwb_service.proto",
     ],
@@ -212,7 +222,7 @@ genrule {
 genrule {
     name: "include_uwb_core_proto",
     cmd: "echo '#[path = \"uwb_service.rs\"]' > $(out);" +
-         "echo 'pub mod bindings;' >> $(out);",
+        "echo 'pub mod bindings;' >> $(out);",
     out: [
         "proto_bindings.rs",
     ],
@@ -232,9 +242,10 @@ rust_fuzz {
             "android-uwb-team@google.com",
         ],
         componentid: 1042770,
-        fuzz_on_haiku_device: true,
-        fuzz_on_haiku_host: true,
+        fuzz_on_haiku_device: false,
+        fuzz_on_haiku_host: false,
     },
+
 }
 
 rust_defaults {
@@ -306,7 +317,7 @@ rust_test {
         android: {
             test_suites: [
                 "general-tests",
-                "mts-uwb"
+                "mts-uwb",
             ],
             test_config_template: "uwb_rust_test_config_template.xml",
         },
@@ -339,9 +350,7 @@ genrule {
         "rust/uwb_uci_packets/**/*",
         "rust/Cargo.toml",
     ],
-    cmd:
-        // Create a artifacts directory and copy the source code into it.
-        "mkdir $(genDir)/artifacts && " +
+    cmd: "mkdir $(genDir)/artifacts && " + // Create a artifacts directory and copy the source code into it.
         "cp -r external/uwb/src/rust/uwb_core " +
         "      external/uwb/src/rust/uwb_uci_packets " +
         "      external/uwb/src/rust/Cargo.toml " +
diff --git a/src/rust/uwb_uci_packets/src/debug_display.rs b/src/rust/uwb_uci_packets/src/debug_display.rs
new file mode 100644
index 0000000..3736182
--- /dev/null
+++ b/src/rust/uwb_uci_packets/src/debug_display.rs
@@ -0,0 +1,80 @@
+use std::{fmt::Debug, ops::Deref, path::Display};
+
+use crate::{ParsedFrameReport, PathSample, SegmentMetricsValue};
+
+pub struct DebugOverride<T>(T);
+
+impl<T> DebugOverride<T> {
+    fn take(self) -> T {
+        self.0
+    }
+}
+
+impl<T> From<T> for DebugOverride<T> {
+    fn from(value: T) -> Self {
+        DebugOverride::<T>(value)
+    }
+}
+
+impl<T> Deref for DebugOverride<T> {
+    type Target = T;
+
+    fn deref(&self) -> &T {
+        &self.0
+    }
+}
+
+impl Debug for ParsedFrameReport {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        f.debug_struct("FrameReport")
+            .field("uwb_msg_id", &self.uwb_msg_id)
+            .field("action", &self.action)
+            .field("antenna_set", &self.antenna_set)
+            .field("rssi", &self.rssi)
+            .field("aoa", &self.aoa)
+            .field("cir", &self.cir)
+            .field("segment_metrics", &self.segment_metrics.iter().map(DebugOverride))
+            .finish()
+    }
+}
+
+impl Debug for DebugOverride<Vec<SegmentMetricsValue>> {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        f.debug_tuple("").field(&self.0).finish()
+    }
+}
+
+impl Debug for DebugOverride<&SegmentMetricsValue> {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        f.debug_struct("")
+            .field("receiver/segment", &self.0.receiver_and_segment)
+            .field("rf_noise_floor", &f32::from(QFormat::<8, 8>(self.0.rf_noise_floor)))
+            .field("segment_rsl", &f32::from(QFormat::<8, 8>(self.0.segment_rsl)))
+            .field("first_path", &DebugOverride(&self.0.first_path))
+            .field("peak_path", &DebugOverride(&self.0.peak_path))
+            .finish()
+    }
+}
+
+impl Debug for DebugOverride<&PathSample> {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        f.debug_struct("")
+            .field("index", &self.0.index)
+            .field("rsl", &f32::from(QFormat::<8, 8>(self.0.rsl)))
+            .field("time_ns", &f32::from(QFormat::<6, 9>(self.0.time_ns)))
+            .finish()
+    }
+}
+
+#[derive(Copy, Clone)]
+pub struct QFormat<const I: u8, const F: u8>(u16);
+
+impl<const I: u8, const F: u8> From<QFormat<I, F>> for f32 {
+    fn from(value: QFormat<I, F>) -> Self {
+        let int_part = (value.0 >> F);
+        let frac_mask = (1 << F) - 1;
+        let frac_part = value.0 & frac_mask;
+        let frac = 2.0_f32.powf(-f32::from(F)) * f32::from(frac_part);
+        f32::from(int_part) + frac
+    }
+}
diff --git a/src/rust/uwb_uci_packets/src/lib.rs b/src/rust/uwb_uci_packets/src/lib.rs
index 6ed8b62..278a2df 100644
--- a/src/rust/uwb_uci_packets/src/lib.rs
+++ b/src/rust/uwb_uci_packets/src/lib.rs
@@ -26,6 +26,8 @@ use num_derive::FromPrimitive;
 use num_traits::FromPrimitive;
 use zeroize::Zeroize;
 
+mod debug_display;
+
 include!(concat!(env!("OUT_DIR"), "/uci_packets.rs"));
 
 const MAX_PAYLOAD_LEN: usize = 255;
@@ -768,7 +770,7 @@ pub struct ParsedDiagnosticNtfPacket {
 }
 
 #[allow(dead_code)]
-#[derive(Debug, Clone)]
+#[derive(Clone)]
 pub struct ParsedFrameReport {
     uwb_msg_id: u8,
     action: u8,
@@ -1069,15 +1071,11 @@ mod tests {
         }];
         let cir = CirBuilder { cir_value: cir_vec.clone() }.build();
         let segment_metrics_vec = vec![SegmentMetricsValue {
-            receiver: 1,
+            receiver_and_segment: ReceiverAndSegmentValue::parse(&[1]).unwrap(),
             rf_noise_floor: 2,
             segment_rsl: 3,
-            first_path_index: 4,
-            first_path_rsl: 5,
-            first_path_time_ns: 6,
-            peak_path_index: 7,
-            peak_path_rsl: 8,
-            peak_path_time_ns: 9,
+            first_path: PathSample { index: 4, rsl: 5, time_ns: 6 },
+            peak_path: PathSample { index: 7, rsl: 8, time_ns: 9 },
         }];
         let segment_metrics =
             SegmentMetricsBuilder { segment_metrics: segment_metrics_vec.clone() }.build();
diff --git a/src/rust/uwb_uci_packets/uci_packets.pdl b/src/rust/uwb_uci_packets/uci_packets.pdl
index 60a36d8..765e2a8 100644
--- a/src/rust/uwb_uci_packets/uci_packets.pdl
+++ b/src/rust/uwb_uci_packets/uci_packets.pdl
@@ -1448,16 +1448,32 @@ packet SegmentMetrics : FrameReportTlvPacket (t = SEGMENT_METRICS) {
     segment_metrics: SegmentMetricsValue[],
 }
 
+enum SegmentIdValue: 3 {
+    Ipatov = 0,
+    Sts0 = 1,
+    Sts1 = 2,
+    Sts2 = 3,
+    Sts3 = 4,
+}
+
+struct ReceiverAndSegmentValue {
+    segment_id: SegmentIdValue,
+    receiver_is_controller: 1,
+    receiver_id: 4,
+}
+
+struct PathSample {
+    index: 16,
+    rsl: 16, // Q8.8
+    time_ns: 16, // Q6.9
+}
+
 struct SegmentMetricsValue {
-    receiver: 8,
-    rf_noise_floor: 16,
-    segment_rsl: 16,
-    first_path_index: 16,
-    first_path_rsl: 16,
-    first_path_time_ns: 16,
-    peak_path_index: 16,
-    peak_path_rsl: 16,
-    peak_path_time_ns: 16,
+    receiver_and_segment: ReceiverAndSegmentValue,
+    rf_noise_floor: 16, // Q8.8
+    segment_rsl: 16, // Q8.8
+    first_path: PathSample,
+    peak_path: PathSample,
 }
 
 test SegmentMetrics {
```

