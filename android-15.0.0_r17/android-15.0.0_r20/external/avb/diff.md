```diff
diff --git a/Android.bp b/Android.bp
index 6643a91..af5b6b6 100644
--- a/Android.bp
+++ b/Android.bp
@@ -218,7 +218,10 @@ cc_library_static {
 // implementation.
 cc_defaults {
     name: "libavb_baremetal_defaults",
-    defaults: ["libavb_base_defaults"],
+    defaults: [
+        "cc_baremetal_defaults",
+        "libavb_base_defaults",
+    ],
     cflags: ["-UAVB_ENABLE_DEBUG"],
     static_libs: [
         "libcrypto_baremetal",
@@ -345,7 +348,6 @@ cc_defaults {
         "test/data/*",
     ],
     test_config: "test/libavb_host_unittest.xml",
-    test_suites: ["general-tests"],
     static_libs: [
         "libavb_ab_host",
         "libgmock_host",
diff --git a/TEST_MAPPING b/TEST_MAPPING
deleted file mode 100644
index d848978..0000000
--- a/TEST_MAPPING
+++ /dev/null
@@ -1,10 +0,0 @@
-{
-  "presubmit": [
-    {
-      "name": "libavb_host_unittest"
-    },
-    {
-      "name": "libavb_host_unittest_sha"
-    }
-  ]
-}
\ No newline at end of file
diff --git a/libavb/avb_slot_verify.h b/libavb/avb_slot_verify.h
index c7f3f45..8702c21 100644
--- a/libavb/avb_slot_verify.h
+++ b/libavb/avb_slot_verify.h
@@ -248,7 +248,7 @@ typedef struct {
  *
  *   androidboot.vbmeta.device_state: set to "locked" or "unlocked"
  *   depending on the result of the result of AvbOps's
- *   read_is_unlocked() function.
+ *   read_is_device_unlocked() function.
  *
  *   androidboot.vbmeta.{hash_alg, size, digest}: Will be set to
  *   the digest of all images in |vbmeta_images|.
diff --git a/rust/Android.bp b/rust/Android.bp
index ce1c261..ae82438 100644
--- a/rust/Android.bp
+++ b/rust/Android.bp
@@ -295,6 +295,7 @@ filegroup {
 rust_defaults {
     name: "libavb_rs_test.defaults",
     srcs: ["tests/tests.rs"],
+    compile_multilib: "first",
     data: [
         ":avb_cert_test_permanent_attributes",
         ":avb_cert_test_unlock_challenge",
@@ -392,8 +393,9 @@ genrule {
 }
 
 // Standalone vbmeta image signing the test image descriptor.
-genrule {
+cc_genrule {
     name: "avbrs_test_vbmeta",
+    compile_multilib: "first",
     tools: ["avbtool"],
     srcs: [
         ":avbrs_test_image_descriptor",
@@ -405,8 +407,9 @@ genrule {
 
 // Standalone vbmeta image signing the test image descriptor with
 // `avb_cert_testkey_psk` and `avb_cert_test_metadata`.
-genrule {
+cc_genrule {
     name: "avbrs_test_vbmeta_cert",
+    compile_multilib: "first",
     tools: ["avbtool"],
     srcs: [
         ":avbrs_test_image_descriptor",
@@ -418,8 +421,9 @@ genrule {
 }
 
 // Standalone vbmeta image signing the test image descriptors for "test_part" and "test_part_2".
-genrule {
+cc_genrule {
     name: "avbrs_test_vbmeta_2_parts",
+    compile_multilib: "first",
     tools: ["avbtool"],
     srcs: [
         ":avbrs_test_image_descriptor",
@@ -431,7 +435,7 @@ genrule {
 }
 
 // Standalone vbmeta image signing the test image persistent digest descriptor.
-genrule {
+cc_genrule {
     name: "avbrs_test_vbmeta_persistent_digest",
     tools: ["avbtool"],
     srcs: [
@@ -443,8 +447,9 @@ genrule {
 }
 
 // Standalone vbmeta image with property descriptor "test_prop_key" = "test_prop_value".
-genrule {
+cc_genrule {
     name: "avbrs_test_vbmeta_with_property",
+    compile_multilib: "first",
     tools: ["avbtool"],
     srcs: [
         ":avbrs_test_image_descriptor",
@@ -455,7 +460,7 @@ genrule {
 }
 
 // Standalone vbmeta image with the test image hashtree descriptor.
-genrule {
+cc_genrule {
     name: "avbrs_test_vbmeta_with_hashtree",
     tools: ["avbtool"],
     srcs: [
@@ -467,8 +472,9 @@ genrule {
 }
 
 // Standalone vbmeta image with kernel commandline "test_cmdline_key=test_cmdline_value".
-genrule {
+cc_genrule {
     name: "avbrs_test_vbmeta_with_commandline",
+    compile_multilib: "first",
     tools: ["avbtool"],
     srcs: [
         ":avbrs_test_image_descriptor",
@@ -480,8 +486,9 @@ genrule {
 
 // Standalone vbmeta image with chain descriptor to "test_part_2" with rollback
 // index 4, signed by avb_testkey_rsa8192.
-genrule {
+cc_genrule {
     name: "avbrs_test_vbmeta_with_chained_partition",
+    compile_multilib: "first",
     tools: ["avbtool"],
     srcs: [
         ":avbrs_test_image_descriptor",
diff --git a/rust/tests/cert_tests.rs b/rust/tests/cert_tests.rs
index 77cd048..171fffb 100644
--- a/rust/tests/cert_tests.rs
+++ b/rust/tests/cert_tests.rs
@@ -58,9 +58,9 @@ fn build_test_cert_ops_one_image_one_vbmeta<'a>() -> TestOps<'a> {
 
     // Add the rollbacks for the cert keys.
     ops.rollbacks
-        .insert(CERT_PIK_VERSION_LOCATION, TEST_CERT_PIK_VERSION);
+        .insert(CERT_PIK_VERSION_LOCATION, Ok(TEST_CERT_PIK_VERSION));
     ops.rollbacks
-        .insert(CERT_PSK_VERSION_LOCATION, TEST_CERT_PSK_VERSION);
+        .insert(CERT_PSK_VERSION_LOCATION, Ok(TEST_CERT_PSK_VERSION));
 
     // It's non-trivial to sign a challenge without `avbtool.py`, so instead we inject the exact RNG
     // used by the pre-generated challenge so that we can use the pre-signed credential.
@@ -130,7 +130,11 @@ fn cert_verify_sets_key_rollbacks() {
 fn cert_verify_fails_with_pik_rollback_violation() {
     let mut ops = build_test_cert_ops_one_image_one_vbmeta();
     // If the image is signed with a lower key version than our rollback, it should fail to verify.
-    *ops.rollbacks.get_mut(&CERT_PIK_VERSION_LOCATION).unwrap() += 1;
+    *ops.rollbacks
+        .get_mut(&CERT_PIK_VERSION_LOCATION)
+        .unwrap()
+        .as_mut()
+        .unwrap() += 1;
 
     let result = verify_one_image_one_vbmeta(&mut ops);
 
@@ -141,7 +145,11 @@ fn cert_verify_fails_with_pik_rollback_violation() {
 fn cert_verify_fails_with_psk_rollback_violation() {
     let mut ops = build_test_cert_ops_one_image_one_vbmeta();
     // If the image is signed with a lower key version than our rollback, it should fail to verify.
-    *ops.rollbacks.get_mut(&CERT_PSK_VERSION_LOCATION).unwrap() += 1;
+    *ops.rollbacks
+        .get_mut(&CERT_PSK_VERSION_LOCATION)
+        .unwrap()
+        .as_mut()
+        .unwrap() += 1;
 
     let result = verify_one_image_one_vbmeta(&mut ops);
 
@@ -243,7 +251,11 @@ fn cert_validate_unlock_credential_fails_with_pik_rollback_violation() {
     let mut ops = build_test_cert_ops_one_image_one_vbmeta();
     // Rotating the PIK should invalidate all existing unlock keys, which includes our pre-signed
     // certificate.
-    *ops.rollbacks.get_mut(&CERT_PIK_VERSION_LOCATION).unwrap() += 1;
+    *ops.rollbacks
+        .get_mut(&CERT_PIK_VERSION_LOCATION)
+        .unwrap()
+        .as_mut()
+        .unwrap() += 1;
 
     let _ = cert_generate_unlock_challenge(&mut ops).unwrap();
 
diff --git a/rust/tests/test_ops.rs b/rust/tests/test_ops.rs
index 2c25c74..c7985ae 100644
--- a/rust/tests/test_ops.rs
+++ b/rust/tests/test_ops.rs
@@ -101,8 +101,10 @@ pub struct TestOps<'a> {
     /// not in this map will return `IoError::Io`.
     pub vbmeta_keys_for_partition: HashMap<&'static str, (FakeVbmetaKey, u32)>,
 
-    /// Rollback indices. Accessing unknown locations will return `IoError::Io`.
-    pub rollbacks: HashMap<usize, u64>,
+    /// Rollback indices. Set an error to simulate `IoError` during access. Writing a non-existent
+    /// rollback index value will create it; to simulate `NoSuchValue` instead, create an entry
+    /// with `Err(IoError::NoSuchValue)` as the value.
+    pub rollbacks: HashMap<usize, IoResult<u64>>,
 
     /// Unlock state. Set an error to simulate IoError during access.
     pub unlock_state: IoResult<bool>,
@@ -287,11 +289,15 @@ impl<'a> Ops<'a> for TestOps<'a> {
     }
 
     fn read_rollback_index(&mut self, location: usize) -> IoResult<u64> {
-        self.rollbacks.get(&location).ok_or(IoError::Io).copied()
+        self.rollbacks.get(&location).ok_or(IoError::Io)?.clone()
     }
 
     fn write_rollback_index(&mut self, location: usize, index: u64) -> IoResult<()> {
-        *(self.rollbacks.get_mut(&location).ok_or(IoError::Io)?) = index;
+        if let Some(Err(e)) = self.rollbacks.get(&location) {
+            return Err(e.clone());
+        }
+
+        self.rollbacks.insert(location, Ok(index));
         Ok(())
     }
 
diff --git a/rust/tests/tests.rs b/rust/tests/tests.rs
index d747ac3..e3891ea 100644
--- a/rust/tests/tests.rs
+++ b/rust/tests/tests.rs
@@ -34,7 +34,7 @@ fn build_test_ops_one_image_one_vbmeta<'a>() -> TestOps<'a> {
         public_key: fs::read(TEST_PUBLIC_KEY_PATH).unwrap(),
         public_key_metadata: None,
     });
-    ops.rollbacks.insert(TEST_VBMETA_ROLLBACK_LOCATION, 0);
+    ops.rollbacks.insert(TEST_VBMETA_ROLLBACK_LOCATION, Ok(0));
     ops.unlock_state = Ok(false);
     ops
 }
diff --git a/rust/tests/verify_tests.rs b/rust/tests/verify_tests.rs
index dfe5c62..a5e67c5 100644
--- a/rust/tests/verify_tests.rs
+++ b/rust/tests/verify_tests.rs
@@ -459,7 +459,7 @@ fn corrupted_vbmeta_fails_verification() {
 fn rollback_violation_fails_verification() {
     let mut ops = build_test_ops_one_image_one_vbmeta();
     // Device with rollback = 1 should refuse to boot image with rollback = 0.
-    ops.rollbacks.insert(TEST_VBMETA_ROLLBACK_LOCATION, 1);
+    ops.rollbacks.insert(TEST_VBMETA_ROLLBACK_LOCATION, Ok(1));
 
     let result = verify_one_image_one_vbmeta(&mut ops);
 
@@ -766,7 +766,7 @@ fn verify_chain_partition_descriptor() {
     // Add the rollback index for the chained partition's location.
     ops.rollbacks.insert(
         TEST_CHAINED_PARTITION_ROLLBACK_LOCATION,
-        TEST_CHAINED_PARTITION_ROLLBACK_INDEX,
+        Ok(TEST_CHAINED_PARTITION_ROLLBACK_INDEX),
     );
 
     let result = verify_two_images(&mut ops);
diff --git a/test/avb_unittest_util.cc b/test/avb_unittest_util.cc
index fa8de93..41151a6 100644
--- a/test/avb_unittest_util.cc
+++ b/test/avb_unittest_util.cc
@@ -51,11 +51,9 @@ void BaseAvbToolTest::SetUp() {
   /* Change current directory to test executable directory so that relative path
    * references to test dependencies don't rely on being manually run from
    * correct directory */
-  base::SetCurrentDirectory(
-      base::FilePath(android::base::GetExecutableDirectory()));
+  ASSERT_TRUE(chdir(android::base::GetExecutableDirectory().c_str()) == 0);
 
   /* Create temporary directory to stash images in. */
-  base::FilePath ret;
   char* buf = strdup("/tmp/libavb-tests.XXXXXX");
   ASSERT_TRUE(mkdtemp(buf) != nullptr);
   testdir_ = buf;
diff --git a/tools/transparency/verify/README.md b/tools/transparency/verify/README.md
index c69fb05..32a7d18 100644
--- a/tools/transparency/verify/README.md
+++ b/tools/transparency/verify/README.md
@@ -1,6 +1,6 @@
 # Verifier of Binary Transparency for Pixel Factory Images
 
-This repository contains code to read the transparency log for [Binary Transparency for Pixel Factory Images](https://developers.google.com/android/binary_transparency/pixel). See the particular section for this tool [here](https://developers.google.com/android/binary_transparency/pixel#verifying-image-inclusion-inclusion-proof).
+This repository contains code to read the transparency log for [Pixel Factory Images Binary Transparency](https://developers.google.com/android/binary_transparency/pixel_overview). See the particular section for this tool [here](https://developers.google.com/android/binary_transparency/pixel_verification#verifying-image-inclusion-inclusion-proof).
 
 ## Files and Directories
 * `cmd/verifier/`
@@ -24,14 +24,14 @@ $ ./verifier --payload_path=${PAYLOAD_PATH}
 ### Input
 The verifier takes a `payload_path` as input.
 
-Each Pixel Factory image corresponds to a [payload](https://developers.google.com/android/binary_transparency/pixel#log-content) stored in the transparency log, the format of which is:
+Each Pixel Factory image corresponds to a [payload](https://developers.google.com/android/binary_transparency/pixel_overview#log_content) stored in the transparency log, the format of which is:
 ```
 <build_fingerprint>\n<vbmeta_digest>\n
 ```
-See [here](https://developers.google.com/android/binary_transparency/pixel#construct-the-payload-for-verification) for a few methods detailing how to extract this payload from an image.
+See [here](https://developers.google.com/android/binary_transparency/pixel_verification#construct-the-payload-for-verification) for a few methods detailing how to extract this payload from an image.
 
 ### Output
 The output of the command is written to stdout:
-  * `OK` if the image is included in the log, i.e. that this [claim](https://developers.google.com/android/binary_transparency/pixel#claimant-model) is true,
+  * `OK` if the image is included in the log, i.e. that this [claim](https://developers.google.com/android/binary_transparency/pixel_overview#claimant_model) is true,
   * `FAILURE` otherwise.
 
diff --git a/tools/transparency/verify/cmd/verifier/log_pub_key.google_system_apk.pem b/tools/transparency/verify/cmd/verifier/log_pub_key.google_system_apk.pem
new file mode 100644
index 0000000..7fcffc2
--- /dev/null
+++ b/tools/transparency/verify/cmd/verifier/log_pub_key.google_system_apk.pem
@@ -0,0 +1,4 @@
+-----BEGIN PUBLIC KEY-----
+MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqH3GLlYoP5bFsCH8DHy5NtpjJbRQ
+w3fJNSATSmo8OlXUMp0oe12qRwHHtdP7k9XHlJsCYp8jj0dQaY+N9ftfLw==
+-----END PUBLIC KEY-----
\ No newline at end of file
diff --git a/tools/transparency/verify/cmd/verifier/log_pub_key.pem b/tools/transparency/verify/cmd/verifier/log_pub_key.pixel.pem
similarity index 100%
rename from tools/transparency/verify/cmd/verifier/log_pub_key.pem
rename to tools/transparency/verify/cmd/verifier/log_pub_key.pixel.pem
diff --git a/tools/transparency/verify/cmd/verifier/verifier.go b/tools/transparency/verify/cmd/verifier/verifier.go
index c579cd9..fcef847 100644
--- a/tools/transparency/verify/cmd/verifier/verifier.go
+++ b/tools/transparency/verify/cmd/verifier/verifier.go
@@ -7,7 +7,7 @@
 //     Transparency Log, see:
 //     https://developers.google.com/android/binary_transparency/image_info.txt
 //   - the path to a file containing the payload, see this page for instructions
-//     https://developers.google.com/android/binary_transparency/pixel#construct-the-payload-for-verification.
+//     https://developers.google.com/android/binary_transparency/pixel_verification#construct-the-payload-for-verification.
 //   - the log's base URL, if different from the default provided.
 //
 // Outputs:
@@ -16,7 +16,7 @@
 //
 // Usage: See README.md.
 // For more details on inclusion proofs, see:
-// https://developers.google.com/android/binary_transparency/pixel#verifying-image-inclusion-inclusion-proof
+// https://developers.google.com/android/binary_transparency/pixel_verification#verifying-image-inclusion-inclusion-proof
 package main
 
 import (
@@ -36,17 +36,28 @@ import (
 // Domain separation prefix for Merkle tree hashing with second preimage
 // resistance similar to that used in RFC 6962.
 const (
-	LeafHashPrefix     = 0
-	KeyNameForVerifier = "pixel_transparency_log"
+	LeafHashPrefix          = 0
+	KeyNameForVerifierPixel = "pixel_transparency_log"
+	KeyNameForVerifierG1P   = "developers.google.com/android/binary_transparency/google1p/0"
+	LogBaseURLPixel         = "https://developers.google.com/android/binary_transparency"
+	LogBaseURLG1P           = "https://developers.google.com/android/binary_transparency/google1p"
+	ImageInfoFilename       = "image_info.txt"
+	PackageInfoFilename     = "package_info.txt"
 )
 
-// See https://developers.google.com/android/binary_transparency/pixel#signature-verification.
-//go:embed log_pub_key.pem
-var logPubKey []byte
+// See https://developers.google.com/android/binary_transparency/pixel_tech_details#log_implementation.
+//
+//go:embed log_pub_key.pixel.pem
+var pixelLogPubKey []byte
+
+// See https://developers.google.com/android/binary_transparency/google1p/log_details#log_implementation.
+//
+//go:embed log_pub_key.google_system_apk.pem
+var googleSystemAppLogPubKey []byte
 
 var (
-	payloadPath = flag.String("payload_path", "", "Path to the payload describing the image of interest.")
-	logBaseURL  = flag.String("log_base_url", "https://developers.google.com/android/binary_transparency", "Base url for the verifiable log files.")
+	payloadPath = flag.String("payload_path", "", "Path to the payload describing the binary of interest.")
+	logType     = flag.String("log_type", "", "Which log: 'pixel' or 'google_system_apk'.")
 )
 
 func main() {
@@ -66,31 +77,50 @@ func main() {
 		log.Printf("Reformatted payload content from %q to %q", b, payloadBytes)
 	}
 
+	var logPubKey []byte
+	var logBaseURL string
+	var keyNameForVerifier string
+	var binaryInfoFilename string
+	if *logType == "" {
+		log.Fatal("must specify which log to verify against: 'pixel' or 'google_system_apk'")
+	} else if *logType == "pixel" {
+		logPubKey = pixelLogPubKey
+		logBaseURL = LogBaseURLPixel
+		keyNameForVerifier = KeyNameForVerifierPixel
+		binaryInfoFilename = ImageInfoFilename
+	} else if *logType == "google_system_apk" {
+		logPubKey = googleSystemAppLogPubKey
+		logBaseURL = LogBaseURLG1P
+		keyNameForVerifier = KeyNameForVerifierG1P
+		binaryInfoFilename = PackageInfoFilename
+	} else {
+		log.Fatal("unsupported log type")
+	}
 
-	v, err := checkpoint.NewVerifier(logPubKey, KeyNameForVerifier)
+	v, err := checkpoint.NewVerifier(logPubKey, keyNameForVerifier)
 	if err != nil {
 		log.Fatalf("error creating verifier: %v", err)
 	}
-	root, err := checkpoint.FromURL(*logBaseURL, v)
+	root, err := checkpoint.FromURL(logBaseURL, v)
 	if err != nil {
-		log.Fatalf("error reading checkpoint for log(%s): %v", *logBaseURL, err)
+		log.Fatalf("error reading checkpoint for log(%s): %v", logBaseURL, err)
 	}
 
-	m, err := tiles.ImageInfosIndex(*logBaseURL)
+	m, err := tiles.BinaryInfosIndex(logBaseURL, binaryInfoFilename)
 	if err != nil {
-		log.Fatalf("failed to load image info map to find log index: %v", err)
+		log.Fatalf("failed to load binary info map to find log index: %v", err)
 	}
-	imageInfoIndex, ok := m[string(payloadBytes)]
+	binaryInfoIndex, ok := m[string(payloadBytes)]
 	if !ok {
-		log.Fatalf("failed to find payload %q in %s", string(payloadBytes), filepath.Join(*logBaseURL, "image_info.txt"))
+		log.Fatalf("failed to find payload %q in %s", string(payloadBytes), filepath.Join(logBaseURL, binaryInfoFilename))
 	}
 
 	var th tlog.Hash
 	copy(th[:], root.Hash)
 
 	logSize := int64(root.Size)
-	r := tiles.HashReader{URL: *logBaseURL}
-	rp, err := tlog.ProveRecord(logSize, imageInfoIndex, r)
+	r := tiles.HashReader{URL: logBaseURL}
+	rp, err := tlog.ProveRecord(logSize, binaryInfoIndex, r)
 	if err != nil {
 		log.Fatalf("error in tlog.ProveRecord: %v", err)
 	}
@@ -100,10 +130,9 @@ func main() {
 		log.Fatalf("error hashing payload: %v", err)
 	}
 
-	if err := tlog.CheckRecord(rp, logSize, th, imageInfoIndex, leafHash); err != nil {
+	if err := tlog.CheckRecord(rp, logSize, th, binaryInfoIndex, leafHash); err != nil {
 		log.Fatalf("FAILURE: inclusion check error in tlog.CheckRecord: %v", err)
 	} else {
-		log.Print("OK. inclusion check success")
+		log.Print("OK. inclusion check success!")
 	}
 }
-
diff --git a/tools/transparency/verify/internal/checkpoint/checkpoint.go b/tools/transparency/verify/internal/checkpoint/checkpoint.go
index dbba338..c1a71ef 100644
--- a/tools/transparency/verify/internal/checkpoint/checkpoint.go
+++ b/tools/transparency/verify/internal/checkpoint/checkpoint.go
@@ -38,8 +38,10 @@ import (
 )
 
 const (
-	// originID identifies a checkpoint for the Pixel Binary Transparency Log.
-	originID = "developers.google.com/android/binary_transparency/0\n"
+	// originIDPixel identifies a checkpoint for the Pixel Binary Transparency Log.
+	originIDPixel = "developers.google.com/android/binary_transparency/0\n"
+	// originIDG1P identifies a checkpoint for the Google System APK Transparency Log.
+	originIDG1P = "developers.google.com/android/binary_transparency/google1p/0\n"
 )
 
 type verifier interface {
@@ -107,11 +109,16 @@ type Root struct {
 }
 
 func parseCheckpoint(ckpt string) (Root, error) {
-	if !strings.HasPrefix(ckpt, originID) {
-		return Root{}, errors.New(fmt.Sprintf("invalid checkpoint - unknown origin, must be %s", originID))
-	}
+	var body string
 	// Strip the origin ID and parse the rest of the checkpoint.
-	body := ckpt[len(originID):]
+	if strings.HasPrefix(ckpt, originIDPixel) {
+		body = ckpt[len(originIDPixel):]
+	} else if strings.HasPrefix(ckpt, originIDG1P) {
+		body = ckpt[len(originIDG1P):]
+	} else {
+		return Root{}, errors.New(fmt.Sprintf("invalid checkpoint - unknown origin, must be either %s or %s", originIDPixel, originIDG1P))
+	}
+
 	// body must contain exactly 2 lines, size and the root hash.
 	l := strings.SplitN(body, "\n", 3)
 	if len(l) != 3 || len(l[2]) != 0 {
diff --git a/tools/transparency/verify/internal/tiles/reader.go b/tools/transparency/verify/internal/tiles/reader.go
index f998f54..bd70b14 100644
--- a/tools/transparency/verify/internal/tiles/reader.go
+++ b/tools/transparency/verify/internal/tiles/reader.go
@@ -3,7 +3,6 @@ package tiles
 
 import (
 	"crypto/sha256"
-	"errors"
 	"fmt"
 	"io"
 	"net/http"
@@ -21,7 +20,6 @@ type HashReader struct {
 	URL string
 }
 
-
 // Domain separation prefix for Merkle tree hashing with second preimage
 // resistance similar to that used in RFC 6962.
 const (
@@ -58,26 +56,26 @@ func (h HashReader) ReadHashes(indices []int64) ([]tlog.Hash, error) {
 	return hashes, nil
 }
 
-// ImageInfosIndex returns a map from payload to its index in the
-// transparency log according to the image_info.txt.
-func ImageInfosIndex(logBaseURL string) (map[string]int64, error) {
-	b, err := readFromURL(logBaseURL, "image_info.txt")
+// BinaryInfosIndex returns a map from payload to its index in the
+// transparency log according to the `binaryInfoFilename` value.
+func BinaryInfosIndex(logBaseURL string, binaryInfoFilename string) (map[string]int64, error) {
+	b, err := readFromURL(logBaseURL, binaryInfoFilename)
 	if err != nil {
 		return nil, err
 	}
 
-	imageInfos := string(b)
-	return parseImageInfosIndex(imageInfos)
+	binaryInfos := string(b)
+	return parseBinaryInfosIndex(binaryInfos, binaryInfoFilename)
 }
 
-func parseImageInfosIndex(imageInfos string) (map[string]int64, error) {
+func parseBinaryInfosIndex(binaryInfos string, binaryInfoFilename string) (map[string]int64, error) {
 	m := make(map[string]int64)
 
-	infosStr := strings.Split(imageInfos, "\n\n")
+	infosStr := strings.Split(binaryInfos, "\n\n")
 	for _, infoStr := range infosStr {
 		pieces := strings.SplitN(infoStr, "\n", 2)
 		if len(pieces) != 2 {
-			return nil, errors.New("missing newline, malformed image_info.txt")
+			return nil, fmt.Errorf("missing newline, malformed %s", binaryInfoFilename)
 		}
 
 		idx, err := strconv.ParseInt(pieces[0], 10, 64)
diff --git a/tools/transparency/verify/internal/tiles/reader_test.go b/tools/transparency/verify/internal/tiles/reader_test.go
index 47e26c3..ecca52e 100644
--- a/tools/transparency/verify/internal/tiles/reader_test.go
+++ b/tools/transparency/verify/internal/tiles/reader_test.go
@@ -165,17 +165,56 @@ func TestParseImageInfosIndex(t *testing.T) {
 		},
 	} {
 		t.Run(tc.desc, func(t *testing.T) {
-			got, err := parseImageInfosIndex(tc.imageInfos)
+			got, err := parseBinaryInfosIndex(tc.imageInfos, "image_info.txt")
 			if err != nil && !tc.wantErr {
-				t.Fatalf("parseImageInfosIndex(%s) received unexpected err %q", tc.imageInfos, err)
+				t.Fatalf("parseBinaryInfosIndex(%s) received unexpected err %q", tc.imageInfos, err)
 			}
 
 			if err == nil && tc.wantErr {
-				t.Fatalf("parseImageInfosIndex(%s) did not return err, expected err", tc.imageInfos)
+				t.Fatalf("parseBinaryInfosIndex(%s) did not return err, expected err", tc.imageInfos)
 			}
 
 			if diff := cmp.Diff(tc.want, got); diff != "" {
-				t.Errorf("parseImageInfosIndex returned unexpected diff (-want +got):\n%s", diff)
+				t.Errorf("parseBinaryInfosIndex returned unexpected diff (-want +got):\n%s", diff)
+			}
+		})
+	}
+}
+
+func TestParsePackageInfosIndex(t *testing.T) {
+	for _, tc := range []struct {
+		desc         string
+		packageInfos string
+		want         map[string]int64
+		wantErr      bool
+	}{
+		{
+			desc:         "size 2",
+			packageInfos: "0\nhash0\nhash_desc0\npackage_name0\npackage_version0\n\n1\nhash1\nhash_desc1\npackage_name1\npackage_version1\n",
+			wantErr:      false,
+			want: map[string]int64{
+				"hash0\nhash_desc0\npackage_name0\npackage_version0\n": 0,
+				"hash1\nhash_desc1\npackage_name1\npackage_version1\n": 1,
+			},
+		},
+		{
+			desc:         "invalid log entry (no newlines)",
+			packageInfos: "0hashhash_descpackage_namepackage_version",
+			wantErr:      true,
+		},
+	} {
+		t.Run(tc.desc, func(t *testing.T) {
+			got, err := parseBinaryInfosIndex(tc.packageInfos, "package_info.txt")
+			if err != nil && !tc.wantErr {
+				t.Fatalf("parseBinaryInfosIndex(%s) received unexpected err %q", tc.packageInfos, err)
+			}
+
+			if err == nil && tc.wantErr {
+				t.Fatalf("parseBinaryInfosIndex(%s) did not return err, expected err", tc.packageInfos)
+			}
+
+			if diff := cmp.Diff(tc.want, got); diff != "" {
+				t.Errorf("parseBinaryInfosIndex returned unexpected diff (-want +got):\n%s", diff)
 			}
 		})
 	}
```

