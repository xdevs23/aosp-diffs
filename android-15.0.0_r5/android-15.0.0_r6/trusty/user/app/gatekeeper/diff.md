```diff
diff --git a/trusty_gatekeeper.cpp b/trusty_gatekeeper.cpp
index e20258d..8799129 100644
--- a/trusty_gatekeeper.cpp
+++ b/trusty_gatekeeper.cpp
@@ -15,6 +15,7 @@
  */
 
 #include "trusty_gatekeeper.h"
+#include "ipc/gatekeeper_ipc.h"
 
 #include <inttypes.h>
 #include <trusty/time.h>
@@ -166,8 +167,10 @@ void TrustyGateKeeper::ComputePasswordSignature(uint8_t* signature,
                                                 const uint8_t* password,
                                                 uint32_t password_length,
                                                 salt_t salt) const {
-    // todo: heap allocate
-    uint8_t salted_password[password_length + sizeof(salt)];
+    uint8_t salted_password[GATEKEEPER_MAX_BUFFER_LENGTH];
+
+    assert(password_length + sizeof(salt) <= sizeof(salted_password));
+
     memcpy(salted_password, &salt, sizeof(salt));
     memcpy(salted_password + sizeof(salt), password, password_length);
     ComputeSignature(signature, signature_length, key, key_length,
```

