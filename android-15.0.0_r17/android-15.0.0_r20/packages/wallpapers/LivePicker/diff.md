```diff
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 892a2ca..da0417e 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -26,17 +26,17 @@
     <string name="configure_wallpaper" msgid="4308477548538487192">"ಸೆಟ್ಟಿಂಗ್‌ಗಳು..."</string>
     <string name="delete_live_wallpaper" msgid="2401799265848069389">"ಅಳಿಸಿ"</string>
     <string name="preview" msgid="1067744492020029129">"ಪೂರ್ವವೀಕ್ಷಣೆ"</string>
-    <string name="wallpaper_instructions" msgid="6112878742140691445">"ವಾಲ್‌ಪೇಪರ್ ಹೊಂದಿಸಿ"</string>
+    <string name="wallpaper_instructions" msgid="6112878742140691445">"ವಾಲ್‌ಪೇಪರ್ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="live_wallpaper_empty" msgid="8057319062274870589">"ಲೈವ್ ವಾಲ್‌ಪೇಪರ್‌ಗಳಿಲ್ಲ."</string>
-    <string name="set_live_wallpaper" msgid="764007409845174475">"ವಾಲ್‌ಪೇಪರ್ ಹೊಂದಿಸಿ"</string>
+    <string name="set_live_wallpaper" msgid="764007409845174475">"ವಾಲ್‌ಪೇಪರ್ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="wallpaper_title_and_author" msgid="7606029050779779421">"<xliff:g id="AUTHOR">%2$s</xliff:g> ಅವರ <xliff:g id="TITLE">%1$s</xliff:g>"</string>
     <string name="live_wallpaper_loading" msgid="7218845906181560315">"ಲೈವ್ ವಾಲ್‌ಪೇಪರ್‌ ಅನ್ನು ಲೋಡ್ ಮಾಡಲಾಗುತ್ತಿದೆ…"</string>
     <string name="which_wallpaper_option_home_screen" msgid="3323619298489943624">"ಹೋಮ್ ಸ್ಕ್ರೀನ್"</string>
-    <string name="which_wallpaper_option_home_screen_and_lock_screen" msgid="1650093303691767601">"ಮುಖಪುಟದ ಪರದೆ ಮತ್ತು ಲಾಕ್ ಪರದೆ"</string>
+    <string name="which_wallpaper_option_home_screen_and_lock_screen" msgid="1650093303691767601">"ಮುಖಪುಟದ ಸ್ಕ್ರೀನ್ ಮತ್ತು ಲಾಕ್ ಸ್ಕ್ರೀನ್"</string>
     <string name="explore_further" msgid="489032063223099244">"ಎಕ್ಸ್‌ಪ್ಲೋರ್"</string>
     <string name="tab_info" msgid="5501369870701932475">"ಮಾಹಿತಿ"</string>
     <string name="tab_customize" msgid="9007237541087328909">"ಕಸ್ಟಮೈಸ್ ಮಾಡಿ"</string>
-    <string name="delete_wallpaper_confirmation" msgid="252765957117597457">"ನಿಮ್ಮ ಫೋನ್‌ನಿಂದ ಈ ವಾಲ್‌ಪೇಪರ್ ಅನ್ನು ಅಳಿಸುವುದೇ?"</string>
+    <string name="delete_wallpaper_confirmation" msgid="252765957117597457">"ನಿಮ್ಮ ಫೋನ್‌ನಿಂದ ಈ ವಾಲ್‌ಪೇಪರ್ ಅನ್ನು ಅಳಿಸಬೇಕೆ?"</string>
     <string name="collapse_attribution_panel" msgid="5368959884531941653">"ವಾಲ್‌ಪೇಪರ್ ಮಾಹಿತಿ ಫಲಕ ಸಂಕುಚಿಸಿ"</string>
     <string name="expand_attribution_panel" msgid="6540929859713706255">"ವಾಲ್‌ಪೇಪರ್ ಮಾಹಿತಿ ಫಲಕ ವಿಸ್ತರಿಸಿ"</string>
 </resources>
diff --git a/src/com/android/wallpaper/livepicker/LiveWallpaperPreview.java b/src/com/android/wallpaper/livepicker/LiveWallpaperPreview.java
index 5fed5c5..fb5f84a 100644
--- a/src/com/android/wallpaper/livepicker/LiveWallpaperPreview.java
+++ b/src/com/android/wallpaper/livepicker/LiveWallpaperPreview.java
@@ -21,6 +21,7 @@ import android.app.AlertDialog;
 import android.app.WallpaperColors;
 import android.app.WallpaperInfo;
 import android.app.WallpaperManager;
+import android.app.wallpaper.WallpaperDescription;
 import android.content.ActivityNotFoundException;
 import android.content.ComponentName;
 import android.content.Context;
@@ -77,6 +78,8 @@ import com.google.android.material.bottomsheet.BottomSheetBehavior.BottomSheetCa
 import com.google.android.material.tabs.TabLayout;
 
 import java.io.IOException;
+import java.lang.reflect.InvocationTargetException;
+import java.lang.reflect.Method;
 import java.util.ArrayList;
 import java.util.List;
 
@@ -638,16 +641,61 @@ public class LiveWallpaperPreview extends Activity {
 
         }
 
+        /*
+         * Tries to call the attach method used in Android 14(U) and earlier, returning true on
+         * success otherwise false.
+         */
+        private boolean tryPreUAttach(View root, int displayId) {
+            try {
+                Method preUMethod = mService.getClass().getMethod("attach",
+                        IWallpaperConnection.class, IBinder.class, int.class, boolean.class,
+                        int.class, int.class, Rect.class, int.class);
+                preUMethod.invoke(mService,this, root.getWindowToken(),
+                        LayoutParams.TYPE_APPLICATION_MEDIA, true, root.getWidth(),
+                        root.getHeight(), new Rect(0, 0, 0, 0), displayId);
+                return true;
+            } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
+                return false;
+            }
+        }
+
+        /*
+         * Tries to call the attach method used in Android 16(B) and earlier, returning true on
+         * success otherwise false.
+         */
+        private boolean tryPreBAttach(View root, int displayId) {
+            try {
+                Method preBMethod = mService.getClass().getMethod("attach",
+                        IWallpaperConnection.class, IBinder.class, int.class, boolean.class,
+                        int.class, int.class, Rect.class, int.class, WallpaperInfo.class);
+                preBMethod.invoke(mService,this, root.getWindowToken(),
+                        LayoutParams.TYPE_APPLICATION_MEDIA, true, root.getWidth(),
+                        root.getHeight(), new Rect(0, 0, 0, 0), displayId,
+                        WallpaperManager.FLAG_SYSTEM, mInfo);
+                return true;
+            } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
+                return false;
+            }
+        }
+
         public void onServiceConnected(ComponentName name, IBinder service) {
             if (mWallpaperConnection == this) {
                 mService = IWallpaperService.Stub.asInterface(service);
                 try {
                     final int displayId = getWindow().getDecorView().getDisplay().getDisplayId();
                     final View root = getWindow().getDecorView();
+
+                    if (tryPreUAttach(root, displayId)) return;
+                    if (tryPreBAttach(root, displayId)) return;
+
+                    WallpaperDescription desc = new WallpaperDescription.Builder().setComponent(
+                            (mInfo != null) ? mInfo.getComponent() : null).build();
                     mService.attach(this, root.getWindowToken(),
                             LayoutParams.TYPE_APPLICATION_MEDIA, true, root.getWidth(),
                             root.getHeight(), new Rect(0, 0, 0, 0), displayId,
-                            WallpaperManager.FLAG_SYSTEM, mInfo);
+                            WallpaperManager.FLAG_SYSTEM, mInfo, desc);
+                    Log.d(LOG_TAG, " called IWallpaperService#attach method with "
+                            + "WallpaperDescription");
                 } catch (RemoteException e) {
                     Log.w(LOG_TAG, "Failed attaching wallpaper; clearing", e);
                 }
```

