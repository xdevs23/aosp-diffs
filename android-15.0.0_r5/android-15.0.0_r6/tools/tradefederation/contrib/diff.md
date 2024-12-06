```diff
diff --git a/Android.bp b/Android.bp
index d861723..d66e1f5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -12,7 +12,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
@@ -21,7 +20,10 @@ tradefed_java_library_host {
     name: "tradefed-contrib",
     defaults: ["tradefed_errorprone_defaults"],
     // No extension of contrib is expected, it ships with Tradefed alone
-    visibility: ["//tools/tradefederation/contrib/tests"],
+    visibility: [
+        "//tools/tradefederation/contrib/tests",
+        "//tools/tradefederation/core",
+    ],
     // Only compile source java files in this lib.
     srcs: ["src/**/*.java"],
 
diff --git a/res/config/template/postprocessors/aggregate.xml b/res/config/template/postprocessors/aggregate.xml
index 773b2cd..445fc98 100644
--- a/res/config/template/postprocessors/aggregate.xml
+++ b/res/config/template/postprocessors/aggregate.xml
@@ -2,4 +2,19 @@
 <!-- Copyright 2019 Google Inc. All Rights Reserved -->
 <configuration description="Aggregates metrics across multiple invocations of the same test." >
     <metric_post_processor class="com.android.tradefed.postprocessor.AggregatePostProcessor" />
+    <metric_post_processor class="com.android.tradefed.postprocessor.MetricFilePostProcessor">
+        <option name="disable" value="true" />
+    </metric_post_processor>
+    <metric_post_processor class="com.android.tradefed.postprocessor.StatsdGenericPostProcessor">
+        <option name="disable" value="true" />
+    </metric_post_processor>
+    <metric_post_processor class="com.android.tradefed.postprocessor.StatsdEventMetricPostProcessor">
+        <option name="disable" value="true" />
+    </metric_post_processor>
+    <metric_post_processor class="com.android.tradefed.postprocessor.StatsdBeforeAfterGaugeMetricPostProcessor">
+        <option name="disable" value="true" />
+    </metric_post_processor>
+    <metric_post_processor class="com.android.tradefed.postprocessor.PerfettoGenericPostProcessor">
+        <option name="disable" value="true" />
+    </metric_post_processor>
 </configuration>
diff --git a/src/com/android/performance/tests/EmmcPerformanceTest.java b/src/com/android/performance/tests/EmmcPerformanceTest.java
index dc81b9c..5373960 100644
--- a/src/com/android/performance/tests/EmmcPerformanceTest.java
+++ b/src/com/android/performance/tests/EmmcPerformanceTest.java
@@ -57,7 +57,7 @@ public class EmmcPerformanceTest implements IDeviceTest, IRemoteTest {
     private static final String SEQUENTIAL_WRITE_KEY = "sequential_write";
     private static final String RANDOM_READ_KEY = "random_read";
     private static final String RANDOM_WRITE_KEY = "random_write";
-    private static final String PERF_RANDOM = "/data/local/tmp/rand_emmc_perf|#ABI32#|";
+    private static final String PERF_RANDOM = "/system/bin/rand_emmc_perf|#ABI32#|";
 
     private static final Pattern DD_PATTERN =
             Pattern.compile("\\d+ bytes transferred in \\d+\\.\\d+ secs \\((\\d+) bytes/sec\\)");
```

