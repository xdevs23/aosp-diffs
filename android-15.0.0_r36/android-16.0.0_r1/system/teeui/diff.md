```diff
diff --git a/libteeui/include/secure_input/evdev.h b/libteeui/include/secure_input/evdev.h
index 55198f2..ebbb119 100644
--- a/libteeui/include/secure_input/evdev.h
+++ b/libteeui/include/secure_input/evdev.h
@@ -24,6 +24,7 @@
 #include <atomic>
 #include <chrono>
 #include <condition_variable>
+#include <functional>
 #include <list>
 #include <mutex>
 #include <string>
diff --git a/libteeui/include/teeui/utils.h b/libteeui/include/teeui/utils.h
index e52c6eb..6c2d46b 100644
--- a/libteeui/include/teeui/utils.h
+++ b/libteeui/include/teeui/utils.h
@@ -177,11 +177,11 @@ using px = UnitT<Unit::PX>;
 using dp = UnitT<Unit::DP>;
 using mm = UnitT<Unit::MM>;
 
-template <typename Unit> static constexpr const char* str = "N/A";
+template <typename Unit> inline constexpr const char* str = "N/A";
 
-template <> static constexpr const char* str<px> = "px";
-template <> static constexpr const char* str<dp> = "dp";
-template <> static constexpr const char* str<mm> = "mm";
+template <> inline constexpr const char* str<px> = "px";
+template <> inline constexpr const char* str<dp> = "dp";
+template <> inline constexpr const char* str<mm> = "mm";
 
 using DefaultNumericType = float;
 
```

