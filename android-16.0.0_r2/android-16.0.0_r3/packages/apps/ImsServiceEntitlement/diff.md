```diff
diff --git a/tests/unittests/src/com/android/imsserviceentitlement/utils/ImsUtilsTest.java b/tests/unittests/src/com/android/imsserviceentitlement/utils/ImsUtilsTest.java
index 961e913..44be1e0 100644
--- a/tests/unittests/src/com/android/imsserviceentitlement/utils/ImsUtilsTest.java
+++ b/tests/unittests/src/com/android/imsserviceentitlement/utils/ImsUtilsTest.java
@@ -20,6 +20,7 @@ import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
 
 import android.content.Context;
 import android.os.PersistableBundle;
@@ -35,6 +36,7 @@ import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
+import org.mockito.Spy;
 import org.mockito.junit.MockitoJUnit;
 import org.mockito.junit.MockitoRule;
 
@@ -46,10 +48,16 @@ public class ImsUtilsTest {
     @Mock ImsMmTelManager mMockImsMmTelManager;
     @Mock ProvisioningManager mMockProvisioningManager;
 
-    private Context mContext = ApplicationProvider.getApplicationContext();
+    @Spy private Context mContext = ApplicationProvider.getApplicationContext();
 
     @Test
     public void isWfcEnabledByUser_invalidSubId_defaultValues() {
+        PersistableBundle carrierConfig = new PersistableBundle();
+        when(mMockCarrierConfigManager.getConfigForSubId(
+                SubscriptionManager.INVALID_SUBSCRIPTION_ID)).thenReturn(carrierConfig);
+        when(mContext.getSystemService(CarrierConfigManager.class))
+                .thenReturn(mMockCarrierConfigManager);
+
         ImsUtils imsUtils =
                 ImsUtils.getInstance(mContext, SubscriptionManager.INVALID_SUBSCRIPTION_ID);
 
```

