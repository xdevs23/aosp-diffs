```diff
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraExt.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraExt.kt
index df24af5..8af0d9e 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraExt.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraExt.kt
@@ -23,7 +23,6 @@ import androidx.camera.camera2.interop.ExperimentalCamera2Interop
 import androidx.camera.core.CameraInfo
 import androidx.camera.core.CameraSelector
 import androidx.camera.core.DynamicRange as CXDynamicRange
-import androidx.camera.core.ExperimentalImageCaptureOutputFormat
 import androidx.camera.core.ImageCapture
 import androidx.camera.core.Preview
 import androidx.camera.core.UseCase
@@ -86,7 +85,6 @@ val CameraInfo.sensorLandscapeRatio: Float
             }
         } ?: Float.NaN
 
-@OptIn(ExperimentalImageCaptureOutputFormat::class)
 fun Int.toAppImageFormat(): ImageOutputFormat? {
     return when (this) {
         ImageCapture.OUTPUT_FORMAT_JPEG -> ImageOutputFormat.JPEG
@@ -121,7 +119,6 @@ fun CameraInfo.filterSupportedFixedFrameRates(desired: Set<Int>): Set<Int> {
 }
 
 val CameraInfo.supportedImageFormats: Set<ImageOutputFormat>
-    @OptIn(ExperimentalImageCaptureOutputFormat::class)
     get() = ImageCapture.getImageCaptureCapabilities(this).supportedOutputFormats
         .mapNotNull(Int::toAppImageFormat)
         .toSet()
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt
index fbed566..b2b446e 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt
@@ -38,7 +38,6 @@ import androidx.camera.core.CameraControl
 import androidx.camera.core.CameraEffect
 import androidx.camera.core.CameraInfo
 import androidx.camera.core.CameraSelector
-import androidx.camera.core.ExperimentalImageCaptureOutputFormat
 import androidx.camera.core.FocusMeteringAction
 import androidx.camera.core.ImageCapture
 import androidx.camera.core.Preview
@@ -309,7 +308,6 @@ internal fun createUseCaseGroup(
     }.build()
 }
 
-@OptIn(ExperimentalImageCaptureOutputFormat::class)
 private fun createImageUseCase(
     cameraInfo: CameraInfo,
     aspectRatio: AspectRatio,
```

