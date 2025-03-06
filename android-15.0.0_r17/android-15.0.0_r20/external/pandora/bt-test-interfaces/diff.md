```diff
diff --git a/pandora/a2dp.proto b/pandora/a2dp.proto
index d262d1b..a148846 100644
--- a/pandora/a2dp.proto
+++ b/pandora/a2dp.proto
@@ -92,6 +92,10 @@ service A2DP {
       returns (PlaybackAudioResponse);
   // Capture audio from a `Sink`
   rpc CaptureAudio(CaptureAudioRequest) returns (stream CaptureAudioResponse);
+  // Get codec configuration
+  rpc GetConfiguration(GetConfigurationRequest) returns (GetConfigurationResponse);
+  // Set codec configuration
+  rpc SetConfiguration(SetConfigurationRequest) returns (SetConfigurationResponse);
 }
 
 // Audio encoding formats.
@@ -104,6 +108,14 @@ enum AudioEncoding {
   PCM_S16_LE_48K_STEREO = 1;
 }
 
+// Channel mode.
+enum ChannelMode {
+  UNKNOWN = 0;
+  MONO = 1;
+  STEREO = 2;
+  DUALMONO = 3;
+}
+
 // A Token representing a Source stream (see [A2DP] 2.2).
 // It's acquired via an OpenSource on the A2DP service.
 message Source {
@@ -120,6 +132,49 @@ message Sink {
   bytes cookie = 1;
 }
 
+// Vendor codec.
+message Vendor {
+  // 16 bits - Vendor identifier, assigned by BT Sig [Assigned Numbers - 7.1]
+  uint32 id = 1;
+  // 16 bits - Assigned by the vendor
+  uint32 codecId = 2;
+}
+
+// Codec identifier defined for A2DP
+message CodecId {
+  oneof type {
+    google.protobuf.Empty sbc = 1;
+    google.protobuf.Empty mpeg_aac = 2;
+    Vendor vendor = 3;
+  }
+}
+
+message CodecParameters {
+  // Channel mode: Mono, Dual-Mono or Stereo
+  ChannelMode channel_mode = 1;
+  // Sampling frequencies in Hz.
+  uint32 sampling_frequency_hz = 2;
+  // Fixed point resolution in bits per sample.
+  uint32 bit_depth = 3;
+  // Bitrate limits on a frame basis, defined in bits per second.
+  // The 0 value for both means "undefined" or "don't care".
+  uint32 min_bitrate = 4;
+  uint32 max_bitrate = 5;
+  // Low-latency configuration. The interpretation is vendor specific.
+  bool low_latency = 6;
+  // Lossless effort indication. The 'False' value can be used as "don't care".
+  bool lossless = 7;
+  // Vendor specific parameters.
+  bytes vendor_specific_parameters = 8;
+}
+
+message Configuration {
+  // Codec indentifier.
+  CodecId id = 1;
+  // Codec parameters.
+  CodecParameters parameters = 2;
+}
+
 // Request for the `OpenSource` method.
 message OpenSourceRequest {
   // The connection that will open the stream.
@@ -294,3 +349,29 @@ message CaptureAudioResponse {
   // obtained in response of a `GetAudioEncoding` method call.
   bytes data = 1;
 }
+
+// Request for the `GetConfiguration` method.
+message GetConfigurationRequest {
+  // The connection to get codec configuration from.
+  Connection connection = 1;
+}
+
+// Response for the `GetConfiguration` method.
+message GetConfigurationResponse {
+  // Codec configuration.
+  Configuration configuration = 1;
+}
+
+// Request for the `SetConfiguration` method.
+message SetConfigurationRequest {
+  // The connection to set codec configuration.
+  Connection connection = 1;
+  // New codec configuration.
+  Configuration configuration = 2;
+}
+
+// Response for the `SetConfiguration` method.
+message SetConfigurationResponse {
+  // Set configuration result
+  bool success = 1;
+}
diff --git a/python/pandora/__init__.py b/python/pandora/__init__.py
index 6a16141..2a0df3a 100644
--- a/python/pandora/__init__.py
+++ b/python/pandora/__init__.py
@@ -14,4 +14,4 @@
 
 """Pandora gRPC Bluetooth test interfaces."""
 
-__version__ = "0.0.5"
+__version__ = "0.0.6"
diff --git a/python/pyproject.toml b/python/pyproject.toml
index 0e82566..0fcd7fc 100644
--- a/python/pyproject.toml
+++ b/python/pyproject.toml
@@ -7,7 +7,7 @@ classifiers = [
     "License :: OSI Approved :: Apache Software License"
 ]
 dependencies = [
-    "grpcio==1.57",
+    "grpcio>=1.62.1",
     "protobuf>=4.22.0"
 ]
 
@@ -40,6 +40,6 @@ reportImportCycles = false
 reportPrivateUsage = false
 
 [build-system]
-requires = ["flit_core==3.7.1", "grpcio-tools>=1.51.1"]
+requires = ["flit_core==3.7.1", "grpcio-tools>=1.62.1"]
 build-backend = "_build.backend"
 backend-path = ["."]
```

