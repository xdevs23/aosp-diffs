```diff
diff --git a/service/java/com/android/server/wifi/WifiConfigurationUtil.java b/service/java/com/android/server/wifi/WifiConfigurationUtil.java
index 501a071b34..b46ee0e970 100644
--- a/service/java/com/android/server/wifi/WifiConfigurationUtil.java
+++ b/service/java/com/android/server/wifi/WifiConfigurationUtil.java
@@ -27,6 +27,7 @@ import static com.android.server.wifi.util.NativeUtil.addEnclosingQuotes;
 import android.annotation.SuppressLint;
 import android.net.IpConfiguration;
 import android.net.MacAddress;
+import android.net.ProxyInfo;
 import android.net.StaticIpConfiguration;
 import android.net.wifi.SecurityParams;
 import android.net.wifi.WifiConfiguration;
@@ -78,6 +79,7 @@ public class WifiConfigurationUtil {
     private static final int WEP104_KEY_BYTES_LEN = 13;
     private static final int WEP40_KEY_BYTES_LEN = 5;
     private static final int MAX_STRING_LENGTH = 512;
+    private static final int MAX_ENTRY_SIZE = 100;
 
     @VisibleForTesting
     public static final String PASSWORD_MASK = "*";
@@ -721,6 +723,42 @@ public class WifiConfigurationUtil {
                 Log.e(TAG, "validateIpConfiguration failed: null static ip Address");
                 return false;
             }
+            if (staticIpConfig.getDnsServers() != null
+                    && staticIpConfig.getDnsServers().size() > MAX_ENTRY_SIZE) {
+                Log.e(TAG, "validateIpConfiguration failed: too many DNS server");
+                return false;
+            }
+            if (staticIpConfig.getDomains() != null
+                    && staticIpConfig.getDomains().length() > MAX_STRING_LENGTH) {
+                Log.e(TAG, "validateIpConfiguration failed: domain name too long");
+                return false;
+            }
+        }
+        ProxyInfo proxyInfo = ipConfig.getHttpProxy();
+        if (proxyInfo != null) {
+            if (!proxyInfo.isValid()) {
+                Log.e(TAG, "validateIpConfiguration failed: invalid proxy info");
+                return false;
+            }
+            if (proxyInfo.getHost() != null
+                    && proxyInfo.getHost().length() > MAX_STRING_LENGTH) {
+                Log.e(TAG, "validateIpConfiguration failed: host name too long");
+                return false;
+            }
+            if (proxyInfo.getExclusionList() != null) {
+                if (proxyInfo.getExclusionList().length > MAX_ENTRY_SIZE) {
+                    Log.e(TAG, "validateIpConfiguration failed: too many entry in exclusion list");
+                    return false;
+                }
+                int sum = 0;
+                for (String s : proxyInfo.getExclusionList()) {
+                    sum += s.length();
+                    if (sum > MAX_STRING_LENGTH) {
+                        Log.e(TAG, "validateIpConfiguration failed: exclusion list size too large");
+                        return false;
+                    }
+                }
+            }
         }
         return true;
     }
diff --git a/service/tests/wifitests/src/com/android/server/wifi/WifiConfigurationUtilTest.java b/service/tests/wifitests/src/com/android/server/wifi/WifiConfigurationUtilTest.java
index 81b182c9df..e4fcc5c36a 100644
--- a/service/tests/wifitests/src/com/android/server/wifi/WifiConfigurationUtilTest.java
+++ b/service/tests/wifitests/src/com/android/server/wifi/WifiConfigurationUtilTest.java
@@ -30,6 +30,7 @@ import static org.mockito.Mockito.withSettings;
 import android.content.pm.UserInfo;
 import android.net.IpConfiguration;
 import android.net.MacAddress;
+import android.net.ProxyInfo;
 import android.net.wifi.ScanResult;
 import android.net.wifi.SecurityParams;
 import android.net.wifi.WifiConfiguration;
@@ -1681,4 +1682,27 @@ public class WifiConfigurationUtilTest extends WifiBaseTest {
         assertFalse(WifiConfigurationUtil.validate(pskConfig, SUPPORTED_FEATURES_ALL,
                 WifiConfigurationUtil.VALIDATE_FOR_ADD));
     }
+
+    @Test
+    public void testInvalidStaticIpConfig() {
+        WifiConfiguration pskConfig = WifiConfigurationTestUtil.createPskNetwork();
+        IpConfiguration ipConfig =
+                WifiConfigurationTestUtil.createStaticIpConfigurationWithPacProxy();
+        ipConfig.getStaticIpConfiguration().domains = "a".repeat(513);
+        pskConfig.setIpConfiguration(ipConfig);
+        assertFalse(WifiConfigurationUtil.validate(pskConfig, SUPPORTED_FEATURES_ALL,
+                WifiConfigurationUtil.VALIDATE_FOR_ADD));
+    }
+    @Test
+    public void testInvalidProxyInfo() {
+        WifiConfiguration pskConfig = WifiConfigurationTestUtil.createPskNetwork();
+        IpConfiguration ipConfig =
+                WifiConfigurationTestUtil.createStaticIpConfigurationWithStaticProxy();
+        ProxyInfo proxyInfo = ProxyInfo.buildDirectProxy(ipConfig.getHttpProxy().getHost(),
+                ipConfig.getHttpProxy().getPort(), List.of("a".repeat(513)));
+        ipConfig.setHttpProxy(proxyInfo);
+        pskConfig.setIpConfiguration(ipConfig);
+        assertFalse(WifiConfigurationUtil.validate(pskConfig, SUPPORTED_FEATURES_ALL,
+                WifiConfigurationUtil.VALIDATE_FOR_ADD));
+    }
 }
```

