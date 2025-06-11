```diff
diff --git a/OWNERS b/OWNERS
index ebd8fd0..c86b3a3 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,7 +2,6 @@ elaurent@google.com
 essick@google.com
 hunga@google.com
 jmtrivi@google.com
-krocard@google.com
 lajos@google.com
 mnaganov@google.com
 philburk@google.com
diff --git a/media/eco/include/eco/ECOService.h b/media/eco/include/eco/ECOService.h
index f528949..6a1963a 100644
--- a/media/eco/include/eco/ECOService.h
+++ b/media/eco/include/eco/ECOService.h
@@ -23,6 +23,7 @@
 #include <utils/Log.h>
 #include <utils/Mutex.h>
 
+#include <functional>
 #include <list>
 
 #include "eco/ECODebug.h"
```

