```diff
diff --git a/main/java/com/google/android/setupcompat/template/FooterBarMixin.java b/main/java/com/google/android/setupcompat/template/FooterBarMixin.java
index 84cba21..5939a18 100644
--- a/main/java/com/google/android/setupcompat/template/FooterBarMixin.java
+++ b/main/java/com/google/android/setupcompat/template/FooterBarMixin.java
@@ -265,11 +265,11 @@ public class FooterBarMixin implements Mixin {
   }
 
   private View addSpace() {
-    LinearLayout buttonContainerlayout = ensureFooterInflated();
+    LinearLayout buttonContainerLayout = ensureFooterInflated();
     View space = new View(context);
     space.setLayoutParams(new LayoutParams(0, 0, 1.0f));
     space.setVisibility(View.INVISIBLE);
-    buttonContainerlayout.addView(space);
+    buttonContainerLayout.addView(space);
     return space;
   }
 
diff --git a/main/java/com/google/android/setupcompat/util/BuildCompatUtils.java b/main/java/com/google/android/setupcompat/util/BuildCompatUtils.java
index 55f3ad6..ef14d04 100644
--- a/main/java/com/google/android/setupcompat/util/BuildCompatUtils.java
+++ b/main/java/com/google/android/setupcompat/util/BuildCompatUtils.java
@@ -87,6 +87,16 @@ public final class BuildCompatUtils {
         || isAtLeastPreReleaseCodename("UpsideDownCake");
   }
 
+  /**
+   * Implementation of BuildCompat.isAtLeastV() suitable for use in Setup
+   *
+   * @return Whether the current OS version is higher or equal to V.
+   */
+  @ChecksSdkIntAtLeast(api = Build.VERSION_CODES.VANILLA_ICE_CREAM)
+  public static boolean isAtLeastV() {
+    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM;
+  }
+
   private static boolean isAtLeastPreReleaseCodename(String codename) {
     // Special case "REL", which means the build is not a pre-release build.
     if (Build.VERSION.CODENAME.equals("REL")) {
diff --git a/main/java/com/google/android/setupcompat/util/WizardManagerHelper.java b/main/java/com/google/android/setupcompat/util/WizardManagerHelper.java
index 1378c06..9c73ea9 100644
--- a/main/java/com/google/android/setupcompat/util/WizardManagerHelper.java
+++ b/main/java/com/google/android/setupcompat/util/WizardManagerHelper.java
@@ -54,7 +54,7 @@ public final class WizardManagerHelper {
 
   @VisibleForTesting public static final String ACTION_NEXT = "com.android.wizard.NEXT";
 
-  @VisibleForTesting static final String EXTRA_WIZARD_BUNDLE = "wizardBundle";
+  public static final String EXTRA_WIZARD_BUNDLE = "wizardBundle";
   private static final String EXTRA_RESULT_CODE = "com.android.setupwizard.ResultCode";
 
   /** Extra for notifying an Activity that it is inside the first SetupWizard flow or not. */
@@ -260,5 +260,7 @@ public final class WizardManagerHelper {
     }
   }
 
+  // (--
+
   private WizardManagerHelper() {}
 }
```

