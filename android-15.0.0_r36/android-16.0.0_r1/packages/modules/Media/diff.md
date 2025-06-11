```diff
diff --git a/apex/OWNERS b/apex/OWNERS
index 6a85773..afd1907 100644
--- a/apex/OWNERS
+++ b/apex/OWNERS
@@ -1,8 +1,6 @@
 # Bug component: 1344
 hdmoon@google.com
-jinpark@google.com
 klhyun@google.com
-lnilsson@google.com
 
 # go/android-fwk-media-solutions for info on areas of ownership.
 include platform/frameworks/av:/media/janitors/media_solutions_OWNERS
diff --git a/apex/framework/Android.bp b/apex/framework/Android.bp
index 05cd56c..7ea9cba 100644
--- a/apex/framework/Android.bp
+++ b/apex/framework/Android.bp
@@ -34,6 +34,7 @@ java_library {
     optimize: {
         enabled: true,
         shrink: true,
+        proguard_compatibility: true,
         proguard_flags_files: ["updatable-media-proguard.flags"],
     },
 
diff --git a/apex/framework/java/android/media/MediaCommunicationManager.java b/apex/framework/java/android/media/MediaCommunicationManager.java
index 8dd6fed..852c548 100644
--- a/apex/framework/java/android/media/MediaCommunicationManager.java
+++ b/apex/framework/java/android/media/MediaCommunicationManager.java
@@ -147,7 +147,7 @@ public class MediaCommunicationManager {
     /**
      * This API is not generally intended for third party application developers.
      * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
-     * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+     * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
      * Library</a> for consistent behavior across all devices.
      * <p>
      * Gets a list of {@link Session2Token} with type {@link Session2Token#TYPE_SESSION} for the
diff --git a/apex/framework/java/android/media/MediaController2.java b/apex/framework/java/android/media/MediaController2.java
index 159e8e5..6a534ff 100644
--- a/apex/framework/java/android/media/MediaController2.java
+++ b/apex/framework/java/android/media/MediaController2.java
@@ -48,7 +48,7 @@ import java.util.concurrent.Executor;
 /**
  * This API is not generally intended for third party application developers.
  * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
- * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+ * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
  * Library</a> for consistent behavior across all devices.
  *
  * Allows an app to interact with an active {@link MediaSession2} or a
@@ -410,7 +410,7 @@ public class MediaController2 implements AutoCloseable {
     /**
      * This API is not generally intended for third party application developers.
      * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
-     * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+     * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
      * Library</a> for consistent behavior across all devices.
      * <p>
      * Builder for {@link MediaController2}.
@@ -512,7 +512,7 @@ public class MediaController2 implements AutoCloseable {
     /**
      * This API is not generally intended for third party application developers.
      * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
-     * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+     * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
      * Library</a> for consistent behavior across all devices.
      * <p>
      * Interface for listening to change in activeness of the {@link MediaSession2}.
diff --git a/apex/framework/java/android/media/MediaSession2.java b/apex/framework/java/android/media/MediaSession2.java
index 7d07eb3..74964dc 100644
--- a/apex/framework/java/android/media/MediaSession2.java
+++ b/apex/framework/java/android/media/MediaSession2.java
@@ -56,7 +56,7 @@ import java.util.concurrent.Executor;
 /**
  * This API is not generally intended for third party application developers.
  * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
- * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+ * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
  * Library</a> for consistent behavior across all devices.
  * <p>
  * Allows a media app to expose its transport controls and playback information in a process to
@@ -502,7 +502,7 @@ public class MediaSession2 implements AutoCloseable {
     /**
      * This API is not generally intended for third party application developers.
      * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
-     * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+     * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
      * Library</a> for consistent behavior across all devices.
      * <p>
      * Builder for {@link MediaSession2}.
@@ -648,7 +648,7 @@ public class MediaSession2 implements AutoCloseable {
     /**
      * This API is not generally intended for third party application developers.
      * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
-     * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+     * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
      * Library</a> for consistent behavior across all devices.
      * <p>
      * Information of a controller.
@@ -842,7 +842,7 @@ public class MediaSession2 implements AutoCloseable {
     /**
      * This API is not generally intended for third party application developers.
      * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
-     * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+     * <a href="{@docRoot}reference/androidx/media3/session/package-summary.html">Media3 session
      * Library</a> for consistent behavior across all devices.
      * <p>
      * Callback to be called for all incoming commands from {@link MediaController2}s.
diff --git a/apex/framework/java/android/media/MediaSession2Service.java b/apex/framework/java/android/media/MediaSession2Service.java
index 9f80c43..6c4c666 100644
--- a/apex/framework/java/android/media/MediaSession2Service.java
+++ b/apex/framework/java/android/media/MediaSession2Service.java
@@ -46,7 +46,7 @@ import java.util.Map;
 /**
  * This API is not generally intended for third party application developers.
  * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
- * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+ * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
  * Library</a> for consistent behavior across all devices.
  * <p>
  * Service containing {@link MediaSession2}.
@@ -289,7 +289,7 @@ public abstract class MediaSession2Service extends Service {
     /**
      * This API is not generally intended for third party application developers.
      * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
-     * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+     * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
      * Library</a> for consistent behavior across all devices.
      * <p>
      * Returned by {@link #onUpdateNotification(MediaSession2)} for making session service
diff --git a/apex/framework/java/android/media/Session2Command.java b/apex/framework/java/android/media/Session2Command.java
index 7e71591..4812080 100644
--- a/apex/framework/java/android/media/Session2Command.java
+++ b/apex/framework/java/android/media/Session2Command.java
@@ -28,7 +28,7 @@ import java.util.Objects;
 /**
  * This API is not generally intended for third party application developers.
  * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
- * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+ * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
  * Library</a> for consistent behavior across all devices.
  * <p>
  * Define a command that a {@link MediaController2} can send to a {@link MediaSession2}.
@@ -36,9 +36,6 @@ import java.util.Objects;
  * If {@link #getCommandCode()} isn't {@link #COMMAND_CODE_CUSTOM}), it's predefined command.
  * If {@link #getCommandCode()} is {@link #COMMAND_CODE_CUSTOM}), it's custom command and
  * {@link #getCustomAction()} shouldn't be {@code null}.
- * <p>
- * Refer to the <a href="{@docRoot}reference/androidx/media2/session/SessionCommand.html">
- * AndroidX SessionCommand</a> class for the list of valid commands.
  */
 public final class Session2Command implements Parcelable {
     /**
@@ -163,7 +160,7 @@ public final class Session2Command implements Parcelable {
     /**
      * This API is not generally intended for third party application developers.
      * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
-     * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+     * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
      * Library</a> for consistent behavior across all devices.
      * <p>
      * Contains the result of {@link Session2Command}.
diff --git a/apex/framework/java/android/media/Session2CommandGroup.java b/apex/framework/java/android/media/Session2CommandGroup.java
index af8184a..5a8ef47 100644
--- a/apex/framework/java/android/media/Session2CommandGroup.java
+++ b/apex/framework/java/android/media/Session2CommandGroup.java
@@ -30,7 +30,7 @@ import java.util.Set;
 /**
  * This API is not generally intended for third party application developers.
  * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
- * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+ * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
  * Library</a> for consistent behavior across all devices.
  * <p>
  * A set of {@link Session2Command} which represents a command group.
@@ -132,7 +132,7 @@ public final class Session2CommandGroup implements Parcelable {
     /**
      * This API is not generally intended for third party application developers.
      * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
-     * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+     * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
      * Library</a> for consistent behavior across all devices.
      * <p>
      * Builds a {@link Session2CommandGroup} object.
diff --git a/apex/framework/java/android/media/Session2Token.java b/apex/framework/java/android/media/Session2Token.java
index aae2e1b..7213fff 100644
--- a/apex/framework/java/android/media/Session2Token.java
+++ b/apex/framework/java/android/media/Session2Token.java
@@ -38,7 +38,7 @@ import java.util.Objects;
 /**
  * This API is not generally intended for third party application developers.
  * Use the <a href="{@docRoot}jetpack/androidx.html">AndroidX</a>
- * <a href="{@docRoot}reference/androidx/media2/session/package-summary.html">Media2 session
+ * <a href="{@docRoot}media/media3/session/control-playback">Media3 session
  * Library</a> for consistent behavior across all devices.
  * <p>
  * Represents an ongoing {@link MediaSession2} or a {@link MediaSession2Service}.
```

