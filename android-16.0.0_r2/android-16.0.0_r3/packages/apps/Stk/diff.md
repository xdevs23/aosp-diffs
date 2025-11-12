```diff
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 30a4315..26c3b1d 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -24,7 +24,7 @@
     <string name="stk_no_service" msgid="1905632157498220090">"Hakuna huduma inayopatikana"</string>
     <string name="button_ok" msgid="7914432227722142434">"Sawa"</string>
     <string name="button_cancel" msgid="137404731092374681">"Ghairi"</string>
-    <string name="button_yes" msgid="755426085739326674">"Ndio"</string>
+    <string name="button_yes" msgid="755426085739326674">"Ndiyo"</string>
     <string name="button_no" msgid="564962410861983724">"Hapana"</string>
     <string name="alphabet" msgid="9068318253752197929">"Alfabeti"</string>
     <string name="digits" msgid="7391551783961486324">"Tarakimu (0-9, *, #, +)"</string>
diff --git a/src/com/android/stk/StkLauncherActivity.java b/src/com/android/stk/StkLauncherActivity.java
index 907c6ee..3ee1869 100644
--- a/src/com/android/stk/StkLauncherActivity.java
+++ b/src/com/android/stk/StkLauncherActivity.java
@@ -57,6 +57,7 @@ public class StkLauncherActivity extends ListActivity {
     @Override
     public void onCreate(Bundle icicle) {
         super.onCreate(icicle);
+        StkApp.setupEdgeToEdge(this);
         getWindow().addSystemFlags(
                 WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
         CatLog.d(LOG_TAG, "onCreate+");
```

