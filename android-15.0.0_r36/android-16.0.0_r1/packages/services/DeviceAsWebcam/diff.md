```diff
diff --git a/impl/res/layout/hq_dialog_warning.xml b/impl/res/layout/hq_dialog_warning.xml
index e37169a..5c049cb 100644
--- a/impl/res/layout/hq_dialog_warning.xml
+++ b/impl/res/layout/hq_dialog_warning.xml
@@ -38,13 +38,14 @@
             android:layout_marginTop="16dp"
             android:padding="8dp"
             android:text="@string/hq_warning_dialog_content_1"
+            android:textColor="@android:color/system_accent2_700"
             android:textAppearance="@android:style/TextAppearance.DeviceDefault.Small"/>
-
         <TextView
             android:layout_width="match_parent"
             android:layout_height="wrap_content"
             android:padding="8dp"
             android:text="@string/hq_warning_dialog_content_2"
+            android:textColor="@android:color/system_accent2_700"
             android:textAppearance="@android:style/TextAppearance.DeviceDefault.Small"/>
 
         <CheckBox
@@ -53,6 +54,7 @@
             android:layout_height="wrap_content"
             android:layout_marginTop="16dp"
             android:paddingHorizontal="8dp"
+            android:minHeight="48dp"
             android:text="@string/hq_warning_dialog_dont_show_again"
             android:textAppearance="@android:style/TextAppearance.DeviceDefault.Small"/>
 
diff --git a/impl/res/layout/preview_layout.xml b/impl/res/layout/preview_layout.xml
index a69008a..0d817e3 100644
--- a/impl/res/layout/preview_layout.xml
+++ b/impl/res/layout/preview_layout.xml
@@ -59,8 +59,8 @@
                 android:layout_width="32dp"
                 android:layout_height="32dp"
                 android:layout_gravity="top|left"
-                android:layout_marginTop="20dp"
-                android:layout_marginLeft="20dp"
+                android:layout_marginTop="28dp"
+                android:layout_marginLeft="28dp"
                 android:background="@drawable/ic_high_quality_bg"
                 android:padding="6dp"
                 android:scaleType="fitCenter"
diff --git a/impl/res/values-fa/strings.xml b/impl/res/values-fa/strings.xml
index 4ca53ec..630be6d 100644
--- a/impl/res/values-fa/strings.xml
+++ b/impl/res/values-fa/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_label" msgid="5357575528456632609">"سرویس وب‌بین"</string>
+    <string name="app_label" msgid="5357575528456632609">"سرویس وب‌کم"</string>
     <string name="view_finder_description" msgid="3685544621391457707">"نمایاب"</string>
     <string name="zoom_ratio_description" msgid="7895509594054136545">"نسبت بزرگ‌نمایی"</string>
     <string name="zoom_ratio_button_current_description" msgid="426459536172417249">"نسبت بزرگ‌نمایی کنونی"</string>
@@ -26,7 +26,7 @@
     <string name="toggle_high_quality_description_off" msgid="8625616955942340072">"خاموش کردن کیفیت بالا"</string>
     <string name="toggle_high_quality_description_on" msgid="2927400982468646409">"روشن کردن کیفیت بالا"</string>
     <string name="hq_warning_dialog_title" msgid="2219475457173758785">"حالت کیفیت بالا"</string>
-    <string name="hq_warning_dialog_content_1" msgid="4522581741851657138">"«حالت کیفیت بالا» بهینه‌سازی نیرو را برای بهبود کیفیت وب‌بین غیرفعال می‌کند. استفاده از این حالت ممکن است باعث افزایش قابل‌توجه مصرف باتری شود که می‌تواند منجر به گرم شدن دستگاه شود."</string>
+    <string name="hq_warning_dialog_content_1" msgid="4522581741851657138">"«حالت کیفیت بالا» بهینه‌سازی نیرو را برای بهبود کیفیت وب‌کم غیرفعال می‌کند. استفاده از این حالت ممکن است باعث افزایش قابل‌توجه مصرف باتری شود که می‌تواند منجر به گرم شدن دستگاه شود."</string>
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"هشدار:"</u></b>" استفاده طولانی‌مدت در دماهای بالا ممکن است تأثیر نامطلوب بر سلامت باتری این دستگاه داشته باشد."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"دیگر نشان داده نشود"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"تصدیق کردن"</string>
diff --git a/impl/res/values/colors.xml b/impl/res/values/colors.xml
index 22807c7..37ebd8b 100644
--- a/impl/res/values/colors.xml
+++ b/impl/res/values/colors.xml
@@ -34,7 +34,7 @@
     <color name="high_quality_on">@android:color/system_accent1_200</color>
     <color name="high_quality_off">@android:color/system_accent2_400</color>
     <color name="high_quality_warning">@android:color/system_error_light</color>
-    <color name="high_quality_ack_button">@android:color/system_accent1_500</color>
+    <color name="high_quality_ack_button">@android:color/system_accent1_700</color>
 
     <color name="zoom_knob_background_color">@android:color/system_accent1_500</color>
     <color name="zoom_seek_bar_background_color">#DB222222</color>
diff --git a/impl/res/values/dimens.xml b/impl/res/values/dimens.xml
index 4532ffd..5c926cf 100644
--- a/impl/res/values/dimens.xml
+++ b/impl/res/values/dimens.xml
@@ -36,7 +36,7 @@
     <dimen name="zoom_ui_toggle_background_margin_top">71.5dp</dimen>
     <dimen name="zoom_ui_toggle_btn_margin_top">69.5dp</dimen>
     <dimen name="zoom_ui_toggle_btn_size">32dp</dimen>
-    <dimen name="zoom_ui_toggle_btn_text_size">12dp</dimen>
+    <dimen name="zoom_ui_toggle_btn_text_size">12sp</dimen>
     <dimen name="zoom_ui_toggle_height">36dp</dimen>
     <dimen name="zoom_ui_toggle_options_layout_margin_top">43dp</dimen>
     <dimen name="zoom_ui_toggle_options_layout_padding_end">2dp</dimen>
@@ -58,4 +58,6 @@
     <dimen name="list_item_radio_button_margin">8dp</dimen>
 
     <dimen name="checkbox_padding">8dp</dimen>
+
+    <dimen name="hq_button_min_touch_target_size">48dp</dimen>
 </resources>
diff --git a/impl/src/com/android/deviceaswebcam/CameraController.java b/impl/src/com/android/deviceaswebcam/CameraController.java
index 1578d6d..4ed61e2 100644
--- a/impl/src/com/android/deviceaswebcam/CameraController.java
+++ b/impl/src/com/android/deviceaswebcam/CameraController.java
@@ -20,6 +20,7 @@ import android.content.Context;
 import android.graphics.Bitmap;
 import android.graphics.BitmapFactory;
 import android.graphics.Canvas;
+import android.graphics.ImageFormat;
 import android.graphics.Matrix;
 import android.graphics.Point;
 import android.graphics.Rect;
@@ -685,11 +686,12 @@ public class CameraController {
                 if (mImgReader != null) {
                     mImgReader.close();
                 }
-                mImgReader = new ImageReader.Builder(width, height)
-                        .setMaxImages(MAX_BUFFERS)
-                        .setDefaultHardwareBufferFormat(HardwareBuffer.YCBCR_420_888)
-                        .setUsage(usage)
-                        .build();
+                mImgReader =
+                        new ImageReader.Builder(width, height)
+                                .setMaxImages(MAX_BUFFERS)
+                                .setImageFormat(ImageFormat.YUV_420_888)
+                                .setUsage(usage)
+                                .build();
                 mImgReader.setOnImageAvailableListener(mOnImageAvailableListener,
                         mImageReaderHandler);
             }
diff --git a/impl/src/com/android/deviceaswebcam/DeviceAsWebcamPreview.java b/impl/src/com/android/deviceaswebcam/DeviceAsWebcamPreview.java
index 47f92da..4e57a80 100644
--- a/impl/src/com/android/deviceaswebcam/DeviceAsWebcamPreview.java
+++ b/impl/src/com/android/deviceaswebcam/DeviceAsWebcamPreview.java
@@ -29,6 +29,7 @@ import android.content.res.Configuration;
 import android.graphics.Bitmap;
 import android.graphics.Canvas;
 import android.graphics.Paint;
+import android.graphics.Rect;
 import android.graphics.SurfaceTexture;
 import android.graphics.drawable.BitmapDrawable;
 import android.graphics.drawable.Drawable;
@@ -50,6 +51,7 @@ import android.view.KeyEvent;
 import android.view.MotionEvent;
 import android.view.Surface;
 import android.view.TextureView;
+import android.view.TouchDelegate;
 import android.view.View;
 import android.view.ViewGroup;
 import android.view.Window;
@@ -102,9 +104,11 @@ public class DeviceAsWebcamPreview extends FragmentActivity {
     private View mFocusIndicator;
     private ZoomController mZoomController = null;
     private ImageButton mToggleCameraButton;
-    private ImageButton mHighQualityToggleButton;
     private CameraPickerDialog mCameraPickerDialog;
 
+    private ImageButton mHighQualityToggleButton;
+    private boolean mIsWaitingOnHQToggle = false; // Read/Write on main thread only.
+
     private UserPrefs mUserPrefs;
 
     // A listener to monitor the preview size change events. This might be invoked when toggling
@@ -401,6 +405,39 @@ public class DeviceAsWebcamPreview extends FragmentActivity {
                         /*bottom=*/displayCutout.getSafeInsetTop());
                 break;
         }
+
+        // Ensure the touch target of HQ button is at least the required size.
+        View hqButtonParent = (View) mHighQualityToggleButton.getParent();
+        // Post to the parent so we get an accurate number from getHitRect.
+        hqButtonParent.post(
+                () -> {
+                    int minSize =
+                            getResources()
+                                    .getDimensionPixelSize(R.dimen.hq_button_min_touch_target_size);
+                    Rect hitRect = new Rect();
+                    mHighQualityToggleButton.getHitRect(hitRect);
+
+                    int hitHeight = hitRect.height();
+                    int hitWidth = hitRect.width();
+
+                    if (hitHeight < minSize) {
+                        // Clamp to a minimum of 1, so we're never smaller than the required size
+                        int padding = Math.max((minSize - hitHeight) / 2, 1);
+                        hitRect.top -= padding;
+                        hitRect.bottom += padding;
+                    }
+
+                    if (hitWidth < minSize) {
+                        // Clamp to a minimum of 1, so we're never smaller than the required size
+                        int padding = Math.max((minSize - hitWidth / 2), 1);
+                        hitRect.left -= padding;
+                        hitRect.right += padding;
+                    }
+
+                    hqButtonParent.setTouchDelegate(
+                            new TouchDelegate(hitRect, mHighQualityToggleButton));
+                });
+
         // subscribe to layout changes of the texture view container so we can
         // resize the texture view once the container has been drawn with the new
         // margins
@@ -476,11 +513,16 @@ public class DeviceAsWebcamPreview extends FragmentActivity {
                 createCameraListForPicker(), mWebcamController.getCameraInfo().getCameraId());
 
         updateHighQualityButtonState(mWebcamController.isHighQualityModeEnabled());
-        mHighQualityToggleButton.setOnClickListener(v -> {
-            // Disable the toggle button to prevent spamming
-            mHighQualityToggleButton.setEnabled(false);
-            toggleHQWithWarningIfNeeded();
-        });
+        mHighQualityToggleButton.setOnClickListener(
+                v -> {
+                    // Don't do anything if we're waiting on HQ mode to be toggled. This prevents
+                    // queuing up of HQ toggle events in case WebcamController gets delayed.
+                    if (mIsWaitingOnHQToggle) {
+                        return;
+                    }
+                    mIsWaitingOnHQToggle = true;
+                    toggleHQWithWarningIfNeeded();
+                });
     }
 
     private void toggleHQWithWarningIfNeeded() {
@@ -528,7 +570,7 @@ public class DeviceAsWebcamPreview extends FragmentActivity {
                                 rotateUiByRotationDegrees(
                                         mWebcamController.getCurrentRotation(),
                                         /*animationDuration*/ 0L);
-                                mHighQualityToggleButton.setEnabled(true);
+                                mIsWaitingOnHQToggle = false;
                             });
                 };
         mWebcamController.setHighQualityModeEnabled(enabled, callback);
diff --git a/interface/proguard.flags b/interface/proguard.flags
index 852667a..09e04a5 100644
--- a/interface/proguard.flags
+++ b/interface/proguard.flags
@@ -1,8 +1,14 @@
 # Keeps methods that are invoked by JNI.
 
--keep class com.android.deviceaswebcam.annotations.UsedBy*
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep class com.android.deviceaswebcam.annotations.UsedBy* {
+  void <init>();
+}
 
--keep @com.android.deviceaswebcam.annotations.UsedBy* class *
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @com.android.deviceaswebcam.annotations.UsedBy* class * {
+  void <init>();
+}
 -keepclassmembers class * {
   @com.android.deviceaswebcam.annotations.UsedByNative *;
 }
@@ -12,4 +18,3 @@
 -keepclassmembers class * {
   native <methods>;
 }
-
diff --git a/interface/res/values-fa/strings.xml b/interface/res/values-fa/strings.xml
index aa3fe30..779bc6d 100644
--- a/interface/res/values-fa/strings.xml
+++ b/interface/res/values-fa/strings.xml
@@ -17,7 +17,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notif_channel_name" msgid="6360649882588343016">"سرویس پیش‌نما"</string>
-    <string name="notif_ticker" msgid="6915460822395652567">"وب‌بین"</string>
-    <string name="notif_title" msgid="802425098359640082">"وب‌بین"</string>
-    <string name="notif_desc" msgid="2524105328454274946">"برای پیش‌دید کردن و پیکربندی خروجی وب‌بین، تک‌ضرب بزنید"</string>
+    <string name="notif_ticker" msgid="6915460822395652567">"وب‌کم"</string>
+    <string name="notif_title" msgid="802425098359640082">"وب‌کم"</string>
+    <string name="notif_desc" msgid="2524105328454274946">"برای پیش‌دید کردن و پیکربندی خروجی وب‌کم، تک‌ضرب بزنید"</string>
 </resources>
```

