```diff
diff --git a/app/cast_auth_impl.cc b/app/cast_auth_impl.cc
index b1ccdb4..4ef4569 100644
--- a/app/cast_auth_impl.cc
+++ b/app/cast_auth_impl.cc
@@ -19,6 +19,7 @@
 #include "cast_auth_impl.h"
 
 #include <binder/RpcServerTrusty.h>
+#include <lib/keybox/client/keybox.h>
 #include <lib/storage/storage.h>
 #include <lib/system_state/system_state.h>
 #include <lk/err_ptr.h>
@@ -31,8 +32,6 @@
 #include <trusty_log.h>
 #include <uapi/err.h>
 
-#include "lib/keybox/client/keybox.h"
-
 static const char* kKeyPath = "cast_auth_key";
 const int RSA_2048_SIZE_BYTES = 256;
 const int UNWRAPPED_KEY_MAX_BYTES = 1200;
diff --git a/app/rules.mk b/app/rules.mk
index 09a9d82..bf2ddc7 100644
--- a/app/rules.mk
+++ b/app/rules.mk
@@ -21,7 +21,6 @@ MODULE_LIBRARY_DEPS += \
 	trusty/user/base/lib/storage \
 	trusty/user/base/lib/system_state \
 	trusty/user/base/experimental/lib/tidl \
-	trusty/user/base/lib/keybox/client \
 	frameworks/native/libs/binder/trusty \
 
 MODULE_LIBRARY_DEPS += \
```

