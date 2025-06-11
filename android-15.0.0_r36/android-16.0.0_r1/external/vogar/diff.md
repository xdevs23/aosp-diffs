```diff
diff --git a/OWNERS b/OWNERS
index 2d36574..0a9fb62 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 # Bug component: 24949
 include platform/libcore:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/src/vogar/SshChrootTarget.java b/src/vogar/SshChrootTarget.java
new file mode 100644
index 0000000..663cf23
--- /dev/null
+++ b/src/vogar/SshChrootTarget.java
@@ -0,0 +1,115 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package vogar;
+
+import com.google.common.collect.ImmutableList;
+
+import java.io.File;
+import java.io.FileNotFoundException;
+import java.util.List;
+import java.util.ListIterator;
+
+public class SshChrootTarget extends SshTarget {
+    private final String chrootDir;
+
+    private final String targetProcessWrapper;
+
+    public SshChrootTarget(Log log, String hostAndPort, String chrootDir) {
+        super(log, hostAndPort);
+        this.chrootDir = chrootDir;
+        this.targetProcessWrapper = "unshare --user --map-root-user chroot " + chrootDir + " sh -c ";
+    }
+
+    @Override
+    public void await(File directory) {
+        super.await(chrootToRoot(directory));
+    }
+
+    @Override
+    public List<File> ls(File directory) throws FileNotFoundException {
+        // Add chroot prefix to searched directory.
+        List<File> files = super.ls(chrootToRoot(directory));
+        // Remove chroot prefix from files found in directory.
+        ListIterator<File> iterator = files.listIterator();
+        while (iterator.hasNext()) {
+            File file = iterator.next();
+            iterator.set(rootToChroot(file));
+        }
+        return files;
+    }
+
+    @Override
+    public void rm(File file) {
+        super.rm(chrootToRoot(file));
+    }
+
+    @Override
+    public void mkdirs(File file) {
+        super.mkdirs(chrootToRoot(file));
+    }
+
+    @Override
+    public void push(File local, File remote) {
+        super.push(local, chrootToRoot(remote));
+    }
+
+    @Override
+    public void pull(File remote, File local) {
+        super.pull(chrootToRoot(remote), local);
+    }
+
+    @Override
+    protected ImmutableList<String> targetProcessPrefix() {
+        return super.targetProcessPrefix();
+    }
+
+    @Override
+    protected String targetProcessWrapper() {
+        return this.targetProcessWrapper;
+    }
+
+    /**
+     * Convert a file relative to the chroot dir to a file relative to
+     * the device's filesystem "absolute" root.
+     */
+    private File chrootToRoot(File file) {
+        return new File(chrootDir + "/" + file.getPath());
+    }
+
+    /**
+     * Convert a file relative to the device's filesystem "absolute"
+     * root to a file relative to the chroot dir .
+     */
+    private File rootToChroot(File file) throws PathnameNotUnderChrootException {
+        String pathname = file.getPath();
+        if (!pathname.startsWith(chrootDir)) {
+            throw new PathnameNotUnderChrootException(pathname, chrootDir);
+        }
+        return new File(pathname.substring(chrootDir.length()));
+    }
+
+    /**
+     * Exception thrown when a pathname does not represent a file
+     * under the chroot directory.
+     */
+    private static class PathnameNotUnderChrootException extends RuntimeException {
+
+        public PathnameNotUnderChrootException(String pathname, String chrootDir) {
+            super("Pathname " + pathname + " does not represent a file under chroot directory "
+                    + chrootDir);
+        }
+    }
+}
diff --git a/src/vogar/SshTarget.java b/src/vogar/SshTarget.java
index 94177db..58173e8 100644
--- a/src/vogar/SshTarget.java
+++ b/src/vogar/SshTarget.java
@@ -30,7 +30,7 @@ import vogar.commands.Command;
 /**
  * Runs actions on a remote host using SSH.
  */
-public final class SshTarget extends Target {
+public class SshTarget extends Target {
     private final Log log;
     private final String host;
     private final int port;
diff --git a/src/vogar/Vogar.java b/src/vogar/Vogar.java
index c2136e2..9a437a7 100644
--- a/src/vogar/Vogar.java
+++ b/src/vogar/Vogar.java
@@ -676,7 +676,11 @@ public final class Vogar {
                 }
                 break;
             case SSH:
-                target = new SshTarget(console, sshHost);
+                if (chrootDir != null) {
+                    target = new SshChrootTarget(console, sshHost, chrootDir);
+                } else {
+                    target = new SshTarget(console, sshHost);
+                }
                 break;
             case LOCAL:
                 target = new LocalTarget(console, mkdir, rm);
diff --git a/test/vogar/android/DeviceRuntimeAdbTargetTest.java b/test/vogar/android/DeviceRuntimeAdbTargetTest.java
index 357f0b0..37f6577 100644
--- a/test/vogar/android/DeviceRuntimeAdbTargetTest.java
+++ b/test/vogar/android/DeviceRuntimeAdbTargetTest.java
@@ -23,7 +23,7 @@ import java.util.Arrays;
 import java.util.List;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.mockito.runners.MockitoJUnitRunner;
+import org.mockito.junit.MockitoJUnitRunner;
 import vogar.Classpath;
 import vogar.Mode;
 import vogar.ModeId;
diff --git a/test/vogar/android/DeviceRuntimeSshTargetTest.java b/test/vogar/android/DeviceRuntimeSshTargetTest.java
index 906e92f..b36670d 100644
--- a/test/vogar/android/DeviceRuntimeSshTargetTest.java
+++ b/test/vogar/android/DeviceRuntimeSshTargetTest.java
@@ -21,7 +21,7 @@ import java.util.Arrays;
 import java.util.List;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.mockito.runners.MockitoJUnitRunner;
+import org.mockito.junit.MockitoJUnitRunner;
 import vogar.Mode;
 import vogar.ModeId;
 import vogar.SshTarget;
diff --git a/test/vogar/android/HostRuntimeLocalTargetTest.java b/test/vogar/android/HostRuntimeLocalTargetTest.java
index a6fbd02..151a2ce 100644
--- a/test/vogar/android/HostRuntimeLocalTargetTest.java
+++ b/test/vogar/android/HostRuntimeLocalTargetTest.java
@@ -27,7 +27,7 @@ import java.util.regex.Matcher;
 import java.util.regex.Pattern;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.mockito.runners.MockitoJUnitRunner;
+import org.mockito.junit.MockitoJUnitRunner;
 import vogar.LocalTarget;
 import vogar.Mode;
 import vogar.ModeId;
diff --git a/test/vogar/target/junit4/MockitoFieldTest.java b/test/vogar/target/junit4/MockitoFieldTest.java
index 7664e85..a1a3a7c 100644
--- a/test/vogar/target/junit4/MockitoFieldTest.java
+++ b/test/vogar/target/junit4/MockitoFieldTest.java
@@ -18,7 +18,7 @@ package vogar.target.junit4;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
-import org.mockito.runners.MockitoJUnitRunner;
+import org.mockito.junit.MockitoJUnitRunner;
 
 import static org.junit.Assert.assertNotNull;
 
```

