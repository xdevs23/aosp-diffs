```diff
diff --git a/libese_weaver/Android.bp b/libese_weaver/Android.bp
index 4776e81..a7018b0 100644
--- a/libese_weaver/Android.bp
+++ b/libese_weaver/Android.bp
@@ -45,6 +45,7 @@ cc_library_shared {
     ],
 
     shared_libs: [
+        "android.hardware.secure_element-V1-ndk",
         "android.se.omapi-V1-ndk",
         "libcutils",
         "libjc_keymint_transport.nxp",
diff --git a/libese_weaver/inc/TransportFactory.h b/libese_weaver/inc/TransportFactory.h
index 9cc0036..9773538 100644
--- a/libese_weaver/inc/TransportFactory.h
+++ b/libese_weaver/inc/TransportFactory.h
@@ -30,24 +30,28 @@
  ** See the License for the specific language governing permissions and
  ** limitations under the License.
  **
- ** Copyright 2020-2023 NXP
+ ** Copyright 2020-2024 NXP
  **
  *********************************************************************************/
 
 #ifndef __SE_TRANSPORT_FACTORY__
 #define __SE_TRANSPORT_FACTORY__
 
-#include "HalToHalTransport.h"
+#ifdef OMAPI_TRANSPORT
 #include "OmapiTransport.h"
+#else
+#include "HalToHalTransport.h"
+#endif
 #include "SocketTransport.h"
 
 namespace se_transport {
 
-using keymint::javacard::HalToHalTransport;
 using keymint::javacard::ITransport;
 using keymint::javacard::SocketTransport;
 #ifdef OMAPI_TRANSPORT
 using keymint::javacard::OmapiTransport;
+#else
+using keymint::javacard::HalToHalTransport;
 #endif
 
 /**
```

