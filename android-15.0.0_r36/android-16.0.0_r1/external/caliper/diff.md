```diff
diff --git a/OWNERS b/OWNERS
index 87a5dbe..41bd4fe 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/libcore:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/caliper/src/test/java/com/google/caliper/config/CaliperConfigLoaderTest.java b/caliper/src/test/java/com/google/caliper/config/CaliperConfigLoaderTest.java
index 317d1e5..988cba4 100644
--- a/caliper/src/test/java/com/google/caliper/config/CaliperConfigLoaderTest.java
+++ b/caliper/src/test/java/com/google/caliper/config/CaliperConfigLoaderTest.java
@@ -27,7 +27,7 @@ import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
-import org.mockito.runners.MockitoJUnitRunner;
+import org.mockito.junit.MockitoJUnitRunner;
 
 import java.io.File;
 import java.io.FileOutputStream;
diff --git a/caliper/src/test/java/com/google/caliper/config/LoggingConfigLoaderTest.java b/caliper/src/test/java/com/google/caliper/config/LoggingConfigLoaderTest.java
index e4320ef..f88fe70 100644
--- a/caliper/src/test/java/com/google/caliper/config/LoggingConfigLoaderTest.java
+++ b/caliper/src/test/java/com/google/caliper/config/LoggingConfigLoaderTest.java
@@ -34,7 +34,7 @@ import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Captor;
 import org.mockito.Mock;
-import org.mockito.runners.MockitoJUnitRunner;
+import org.mockito.junit.MockitoJUnitRunner;
 
 import java.io.File;
 import java.io.IOException;
diff --git a/caliper/src/test/java/com/google/caliper/runner/ExperimentingRunnerModuleTest.java b/caliper/src/test/java/com/google/caliper/runner/ExperimentingRunnerModuleTest.java
index a941f56..f671877 100644
--- a/caliper/src/test/java/com/google/caliper/runner/ExperimentingRunnerModuleTest.java
+++ b/caliper/src/test/java/com/google/caliper/runner/ExperimentingRunnerModuleTest.java
@@ -33,7 +33,7 @@ import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
-import org.mockito.runners.MockitoJUnitRunner;
+import org.mockito.junit.MockitoJUnitRunner;
 
 import java.lang.reflect.Method;
 
```

