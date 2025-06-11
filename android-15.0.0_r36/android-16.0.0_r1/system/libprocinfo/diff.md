```diff
diff --git a/include/procinfo/process.h b/include/procinfo/process.h
index 92d5997..7d6a1d5 100644
--- a/include/procinfo/process.h
+++ b/include/procinfo/process.h
@@ -28,7 +28,6 @@
 #include <type_traits>
 
 #include <android-base/file.h>
-#include <android-base/logging.h>
 #include <android-base/parseint.h>
 #include <android-base/stringprintf.h>
 #include <android-base/unique_fd.h>
diff --git a/include/procinfo/process_map.h b/include/procinfo/process_map.h
index a4fc181..5e5374e 100644
--- a/include/procinfo/process_map.h
+++ b/include/procinfo/process_map.h
@@ -16,12 +16,16 @@
 
 #pragma once
 
+#include <ctype.h>
+#include <fcntl.h>
 #include <inttypes.h>
 #include <stdint.h>
+#include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/mman.h>
 #include <sys/types.h>
+#include <unistd.h>
 
 #include <functional>
 #include <string>
diff --git a/process.cpp b/process.cpp
index 884570d..ef0e715 100644
--- a/process.cpp
+++ b/process.cpp
@@ -16,14 +16,20 @@
 
 #include <procinfo/process.h>
 
+#include <errno.h>
 #include <fcntl.h>
+#include <stdarg.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 
+#include <memory>
 #include <string>
+#include <utility>
 
+#include <android-base/file.h>
+#include <android-base/stringprintf.h>
 #include <android-base/unique_fd.h>
 
 using android::base::unique_fd;
diff --git a/process_test.cpp b/process_test.cpp
index a9d2f19..f0ddfe4 100644
--- a/process_test.cpp
+++ b/process_test.cpp
@@ -59,8 +59,10 @@ TEST(process_info, process_info_proc_pid_fd_smoke) {
   ASSERT_NE(-1, fd);
   ASSERT_TRUE(android::procinfo::GetProcessInfoFromProcPidFd(fd, gettid(), &self));
 
+  std::string process_path = android::base::GetExecutablePath();
+  std::string process_name = android::base::Basename(process_path);
   // Process name is capped at 15 bytes.
-  ASSERT_EQ("libprocinfo_tes", self.name);
+  ASSERT_EQ(process_name.substr(0, 15), self.name);
   ASSERT_EQ(gettid(), self.tid);
   ASSERT_EQ(getpid(), self.pid);
   ASSERT_EQ(getppid(), self.ppid);
```

