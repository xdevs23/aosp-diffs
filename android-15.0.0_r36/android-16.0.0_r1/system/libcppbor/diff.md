```diff
diff --git a/src/cppbor_parse.cpp b/src/cppbor_parse.cpp
index e84b625..060d9bf 100644
--- a/src/cppbor_parse.cpp
+++ b/src/cppbor_parse.cpp
@@ -17,6 +17,7 @@
 #include "cppbor_parse.h"
 
 #include <algorithm>
+#include <cstddef>
 #include <cstdint>
 #include <cstring>
 #include <memory>
@@ -53,7 +54,7 @@ std::string insufficientLengthString(size_t bytesNeeded, size_t bytesAvail,
 template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
 std::tuple<bool, uint64_t, const uint8_t*> parseLength(const uint8_t* pos, const uint8_t* end,
                                                        ParseClient* parseClient) {
-    if (pos + sizeof(T) > end) {
+    if ((end - pos) < static_cast<ptrdiff_t>(sizeof(T))) {
         parseClient->error(pos - 1, insufficientLengthString(sizeof(T), end - pos, "length field"));
         return {false, 0, pos};
     }
```

