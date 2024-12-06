```diff
diff --git a/Android.bp b/Android.bp
index 6efe391..0124e21 100644
--- a/Android.bp
+++ b/Android.bp
@@ -9,7 +9,6 @@ android_app_import {
     privileged: true,
     certificate: "platform",
     required: ["allowed_privapp_com.android.car.messenger"],
-    overrides: ["messaging"],
     // This flag is needed because we're inehriting 2 `uses-library` tags from `androidx.window`
     // that it's coming from Compose support in `car-ui-lib` in the manifest. And Soong is
     // enforcing that both the shared libraries must be in the image. But since both of them are
```

