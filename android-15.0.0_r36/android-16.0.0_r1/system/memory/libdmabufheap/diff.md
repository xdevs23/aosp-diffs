```diff
diff --git a/include/BufferAllocator/BufferAllocator.h b/include/BufferAllocator/BufferAllocator.h
index bcc63a0..f569455 100644
--- a/include/BufferAllocator/BufferAllocator.h
+++ b/include/BufferAllocator/BufferAllocator.h
@@ -16,22 +16,21 @@
 
 #pragma once
 
-#include <BufferAllocator/dmabufheap-defs.h>
-
-#include <android-base/unique_fd.h>
-#include <linux/ion_4.12.h>
-#include <stdio.h>
-#include <stdlib.h>
-#include <string.h>
 #include <sys/types.h>
 
-#include <cstdint>
+#include <functional>
 #include <shared_mutex>
 #include <string>
 #include <unordered_map>
 #include <unordered_set>
 #include <vector>
 
+#include <linux/ion_4.12.h>
+
+#include <android-base/unique_fd.h>
+
+#include <BufferAllocator/dmabufheap-defs.h>
+
 
 class BufferAllocator {
   public:
```

