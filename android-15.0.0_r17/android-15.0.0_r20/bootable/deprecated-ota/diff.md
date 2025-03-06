```diff
diff --git a/tests/Android.bp b/tests/Android.bp
index 06dc7ba..64d06c1 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -12,7 +12,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-
 cc_test_host {
     name: "recovery_host_test",
     isolated: true,
@@ -107,7 +106,7 @@ cc_test {
 
     static_libs: libapplypatch_static_libs + [
         "android.hardware.health-translate-ndk",
-        "android.hardware.health-V3-ndk",
+        "android.hardware.health-V4-ndk",
         "libhealthshim",
         "librecovery_ui",
         "libfusesideload",
```

