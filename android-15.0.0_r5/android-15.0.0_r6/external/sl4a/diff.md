```diff
diff --git a/Common/src/com/googlecode/android_scripting/facade/wifi/WifiP2pManagerFacade.java b/Common/src/com/googlecode/android_scripting/facade/wifi/WifiP2pManagerFacade.java
index 68024077..0805350f 100644
--- a/Common/src/com/googlecode/android_scripting/facade/wifi/WifiP2pManagerFacade.java
+++ b/Common/src/com/googlecode/android_scripting/facade/wifi/WifiP2pManagerFacade.java
@@ -688,6 +688,9 @@ public class WifiP2pManagerFacade extends RpcReceiver {
             if (j.has("groupOwnerBand")) {
                 b.setGroupOperatingBand(Integer.parseInt(j.getString("groupOwnerBand")));
             }
+            if (j.has("groupOwnerFrequency")) {
+                b.setGroupOperatingFrequency(Integer.parseInt(j.getString("groupOwnerFrequency")));
+            }
             config = b.build();
         }
         if (j.has("deviceAddress")) {
diff --git a/OWNERS b/OWNERS
index f4dea96a..daff27be 100644
--- a/OWNERS
+++ b/OWNERS
@@ -8,6 +8,4 @@ jaineelm@google.com
 jpawlowski@google.com
 krisr@google.com
 siyuanh@google.com
-tturney@google.com
 xianyuanjia@google.com
-zachoverflow@google.com
```

