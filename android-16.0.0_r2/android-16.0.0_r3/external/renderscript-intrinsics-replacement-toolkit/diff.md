```diff
diff --git a/renderscript-toolkit/src/main/cpp/TaskProcessor.cpp b/renderscript-toolkit/src/main/cpp/TaskProcessor.cpp
index ed50909..7fc1dae 100644
--- a/renderscript-toolkit/src/main/cpp/TaskProcessor.cpp
+++ b/renderscript-toolkit/src/main/cpp/TaskProcessor.cpp
@@ -17,6 +17,7 @@
 #include "TaskProcessor.h"
 
 #include <cassert>
+#include <functional>
 #include <sys/prctl.h>
 
 #include "RenderScriptToolkit.h"
```

