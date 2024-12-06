```diff
diff --git a/camera2/extensions/eyesFreeVidSample/src/android/camera/extensions/impl/service/EyesFreeVidService.java b/camera2/extensions/eyesFreeVidSample/src/android/camera/extensions/impl/service/EyesFreeVidService.java
index 496ead1..6379378 100644
--- a/camera2/extensions/eyesFreeVidSample/src/android/camera/extensions/impl/service/EyesFreeVidService.java
+++ b/camera2/extensions/eyesFreeVidSample/src/android/camera/extensions/impl/service/EyesFreeVidService.java
@@ -34,8 +34,6 @@ import android.hardware.camera2.CameraManager;
 import android.hardware.camera2.CameraMetadata;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.CaptureResult;
-import android.hardware.camera2.ExtensionCaptureRequest;
-import android.hardware.camera2.ExtensionCaptureResult;
 import android.hardware.camera2.extension.AdvancedExtender;
 import android.hardware.camera2.extension.CameraExtensionService;
 import android.hardware.camera2.extension.CharacteristicsMap;
@@ -54,7 +52,6 @@ import androidx.annotation.NonNull;
 
 import com.android.internal.camera.flags.Flags;
 
-@FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
 public class EyesFreeVidService extends CameraExtensionService {
 
     private static final String TAG = "EyesFreeVidService";
@@ -69,7 +66,6 @@ public class EyesFreeVidService extends CameraExtensionService {
     protected static final Key REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP =
             new Key<long[]>("android.request.availableColorSpaceProfilesMap", long[].class);
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     @Override
     public boolean onRegisterClient(IBinder token) {
         synchronized (mLock) {
@@ -81,7 +77,6 @@ public class EyesFreeVidService extends CameraExtensionService {
         }
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     @Override
     public void onUnregisterClient(IBinder token) {
         synchronized (mLock) {
@@ -89,42 +84,36 @@ public class EyesFreeVidService extends CameraExtensionService {
         }
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     @Override
     public AdvancedExtender onInitializeAdvancedExtension(int extensionType) {
         mCameraManager = getSystemService(CameraManager.class);
 
         switch (extensionType) {
-            case CameraExtensionCharacteristics.EXTENSION_EYES_FREE_VIDEOGRAPHY:
+            case CameraExtensionCharacteristics.EXTENSION_FACE_RETOUCH:
                 return new AdvancedExtenderEyesFreeImpl(mCameraManager);
             default:
                 return new AdvancedExtenderImpl(mCameraManager);
         }
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     public static class AdvancedExtenderEyesFreeImpl extends AdvancedExtender {
         private CameraCharacteristics mCameraCharacteristics;
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         public AdvancedExtenderEyesFreeImpl(@NonNull CameraManager cameraManager) {
             super(cameraManager);
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public boolean isExtensionAvailable(String cameraId,
                 CharacteristicsMap charsMap) {
             return true;
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public void initialize(String cameraId, CharacteristicsMap map) {
             mCameraCharacteristics = map.get(cameraId);
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public Map<Integer, List<Size>> getSupportedPreviewOutputResolutions(
                 String cameraId) {
@@ -153,7 +142,6 @@ public class EyesFreeVidService extends CameraExtensionService {
             return mCameraCharacteristics;
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public Map<Integer, List<Size>> getSupportedCaptureOutputResolutions(
                 String cameraId) {
@@ -161,45 +149,29 @@ public class EyesFreeVidService extends CameraExtensionService {
                     ImageFormat.JPEG, ImageFormat.JPEG_R, ImageFormat.YCBCR_P010));
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public SessionProcessor getSessionProcessor() {
             return new EyesFreeVidSessionProcessor(this);
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public List<CaptureRequest.Key> getAvailableCaptureRequestKeys(
                 String cameraId) {
             final CaptureRequest.Key [] CAPTURE_REQUEST_SET = {CaptureRequest.CONTROL_ZOOM_RATIO,
                 CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_REGIONS,
                 CaptureRequest.CONTROL_AF_TRIGGER, CaptureRequest.JPEG_QUALITY,
-                CaptureRequest.JPEG_ORIENTATION, ExtensionCaptureRequest.EFV_PADDING_ZOOM_FACTOR,
-                ExtensionCaptureRequest.EFV_AUTO_ZOOM,
-                ExtensionCaptureRequest.EFV_MAX_PADDING_ZOOM_FACTOR,
-                ExtensionCaptureRequest.EFV_STABILIZATION_MODE,
-                ExtensionCaptureRequest.EFV_TRANSLATE_VIEWPORT,
-                ExtensionCaptureRequest.EFV_ROTATE_VIEWPORT};
+                CaptureRequest.JPEG_ORIENTATION
+            };
             return Arrays.asList(CAPTURE_REQUEST_SET);
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public List<CaptureResult.Key> getAvailableCaptureResultKeys(
                 String cameraId) {
             final CaptureResult.Key [] CAPTURE_RESULT_SET = {CaptureResult.CONTROL_ZOOM_RATIO,
                 CaptureResult.CONTROL_AF_MODE, CaptureResult.CONTROL_AF_REGIONS,
                 CaptureResult.CONTROL_AF_TRIGGER, CaptureResult.CONTROL_AF_STATE,
-                CaptureResult.JPEG_QUALITY, CaptureResult.JPEG_ORIENTATION,
-                ExtensionCaptureResult.EFV_PADDING_REGION,
-                ExtensionCaptureResult.EFV_AUTO_ZOOM,
-                ExtensionCaptureResult.EFV_MAX_PADDING_ZOOM_FACTOR,
-                ExtensionCaptureResult.EFV_AUTO_ZOOM_PADDING_REGION,
-                ExtensionCaptureResult.EFV_STABILIZATION_MODE,
-                ExtensionCaptureResult.EFV_TARGET_COORDINATES,
-                ExtensionCaptureResult.EFV_PADDING_ZOOM_FACTOR,
-                ExtensionCaptureResult.EFV_TRANSLATE_VIEWPORT,
-                ExtensionCaptureResult.EFV_ROTATE_VIEWPORT
+                CaptureResult.JPEG_QUALITY, CaptureResult.JPEG_ORIENTATION
             };
             return Arrays.asList(CAPTURE_RESULT_SET);
         }
@@ -310,8 +282,6 @@ public class EyesFreeVidService extends CameraExtensionService {
                             new int[]{ CameraCharacteristics
                                     .CONTROL_VIDEO_STABILIZATION_MODE_PREVIEW_STABILIZATION
                             }),
-                    Pair.create(CameraExtensionCharacteristics.EFV_PADDING_ZOOM_FACTOR_RANGE,
-                            new Range<Float>(1.0f, 2.0f)),
                     Pair.create(REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP,
                             dynamicRangeProfileArray),
                     Pair.create(REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP,
@@ -320,28 +290,23 @@ public class EyesFreeVidService extends CameraExtensionService {
         }
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     public static class AdvancedExtenderImpl extends AdvancedExtender {
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         public AdvancedExtenderImpl(@NonNull CameraManager cameraManager) {
             super(cameraManager);
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public boolean isExtensionAvailable(String cameraId,
                 CharacteristicsMap charsMap) {
             return false;
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public void initialize(String cameraId, CharacteristicsMap map) {
             throw new RuntimeException("Extension not supported");
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public Map<Integer, List<Size>> getSupportedPreviewOutputResolutions(
                 String cameraId) {
@@ -356,20 +321,17 @@ public class EyesFreeVidService extends CameraExtensionService {
             throw new RuntimeException("Extension not supported");
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public Map<Integer, List<Size>> getSupportedCaptureOutputResolutions(
                 String cameraId) {
             throw new RuntimeException("Extension not supported");
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public SessionProcessor getSessionProcessor() {
             throw new RuntimeException("Extension not supported");
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public List<CaptureRequest.Key> getAvailableCaptureRequestKeys(
                 String cameraId) {
@@ -377,7 +339,6 @@ public class EyesFreeVidService extends CameraExtensionService {
 
         }
 
-        @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
         @Override
         public List<CaptureResult.Key> getAvailableCaptureResultKeys(
                 String cameraId) {
diff --git a/camera2/extensions/eyesFreeVidSample/src/android/camera/extensions/impl/service/EyesFreeVidSessionProcessor.java b/camera2/extensions/eyesFreeVidSample/src/android/camera/extensions/impl/service/EyesFreeVidSessionProcessor.java
index 9158792..364f959 100644
--- a/camera2/extensions/eyesFreeVidSample/src/android/camera/extensions/impl/service/EyesFreeVidSessionProcessor.java
+++ b/camera2/extensions/eyesFreeVidSample/src/android/camera/extensions/impl/service/EyesFreeVidSessionProcessor.java
@@ -37,8 +37,6 @@ import android.hardware.camera2.CameraDevice;
 import android.hardware.camera2.CaptureFailure;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.CaptureResult;
-import android.hardware.camera2.ExtensionCaptureRequest;
-import android.hardware.camera2.ExtensionCaptureResult;
 import android.hardware.camera2.TotalCaptureResult;
 import android.hardware.camera2.extension.CameraOutputSurface;
 import android.hardware.camera2.extension.CharacteristicsMap;
@@ -58,11 +56,9 @@ import android.util.Log;
 import android.util.Pair;
 import androidx.annotation.GuardedBy;
 
-import com.android.internal.camera.flags.Flags;
 import java.util.concurrent.atomic.AtomicBoolean;
 
 
-@FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
 public class EyesFreeVidSessionProcessor extends SessionProcessor {
 
     private static final String TAG = "EyesFreeVidSessionProcessor";
@@ -94,12 +90,10 @@ public class EyesFreeVidSessionProcessor extends SessionProcessor {
 
     protected AtomicBoolean mOnCaptureSessionEndStarted = new AtomicBoolean(false);
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     protected EyesFreeVidSessionProcessor(AdvancedExtenderEyesFreeImpl advancedExtender) {
         mAdvancedExtender = advancedExtender;
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     public ExtensionConfiguration initSession(@NonNull IBinder token,
             @NonNull String cameraId, @NonNull CharacteristicsMap map,
             @NonNull CameraOutputSurface previewSurface,
@@ -148,7 +142,6 @@ public class EyesFreeVidSessionProcessor extends SessionProcessor {
         return res;
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     @Override
     public void deInitSession(@NonNull IBinder token) {
         if (mPreviewImageReader != null) {
@@ -170,7 +163,6 @@ public class EyesFreeVidSessionProcessor extends SessionProcessor {
         }
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     @Override
     public void onCaptureSessionStart(@NonNull RequestProcessor requestProcessor,
             @NonNull String statsKey) {
@@ -195,7 +187,6 @@ public class EyesFreeVidSessionProcessor extends SessionProcessor {
         mPreviewImageReader.setOnImageAvailableListener(new ImageListener(), mHandler);
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     @Override
     public void onCaptureSessionEnd() {
         mOnCaptureSessionEndStarted.set(true);
@@ -207,7 +198,6 @@ public class EyesFreeVidSessionProcessor extends SessionProcessor {
         mRequestProcessor = null;
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     @Override
     public int startRepeating(@NonNull Executor executor,
             @NonNull CaptureCallback captureCallback) {
@@ -301,67 +291,6 @@ public class EyesFreeVidSessionProcessor extends SessionProcessor {
                 }
             }
 
-            synchronized (mParametersLock) {
-                List<Pair<CaptureRequest.Key, Object>> requestParameters = request.getParameters();
-                boolean autoZoomEnabled = false;
-                boolean stabilizationModeLocked = false;
-                for (Pair<CaptureRequest.Key, Object> parameter : requestParameters) {
-                    if (ExtensionCaptureRequest.EFV_AUTO_ZOOM.equals(parameter.first)) {
-                        captureResults.put(ExtensionCaptureResult.EFV_AUTO_ZOOM,
-                                (boolean) parameter.second);
-                        autoZoomEnabled = (boolean) parameter.second;
-                        if (autoZoomEnabled &&
-                                ExtensionCaptureRequest.EFV_MAX_PADDING_ZOOM_FACTOR.equals(
-                                parameter.first)) {
-                            captureResults.put(
-                                    ExtensionCaptureResult.EFV_MAX_PADDING_ZOOM_FACTOR,
-                                    (Float) parameter.second);
-                        }
-                    }
-                    if (ExtensionCaptureRequest.EFV_PADDING_ZOOM_FACTOR.equals(parameter.first)) {
-                        captureResults.put(ExtensionCaptureResult.EFV_PADDING_ZOOM_FACTOR,
-                                (Float) parameter.second);
-                    }
-                    if (ExtensionCaptureRequest.EFV_TRANSLATE_VIEWPORT.equals(parameter.first)) {
-                        captureResults.put(ExtensionCaptureResult.EFV_TRANSLATE_VIEWPORT,
-                                (Pair<Integer, Integer>) parameter.second);
-                    }
-                    if (ExtensionCaptureRequest.EFV_ROTATE_VIEWPORT.equals(parameter.first)) {
-                        captureResults.put(ExtensionCaptureResult.EFV_ROTATE_VIEWPORT,
-                                (Float) parameter.second);
-                    }
-                    if (ExtensionCaptureRequest.EFV_STABILIZATION_MODE.equals(parameter.first)) {
-                        if (ExtensionCaptureRequest.EFV_STABILIZATION_MODE_LOCKED ==
-                                (int) parameter.second) {
-                            stabilizationModeLocked = true;
-                            int[] samplePaddingRegion = {5, 5, 5, 5};
-                            captureResults.put(ExtensionCaptureResult.EFV_PADDING_REGION,
-                                    samplePaddingRegion);
-                            CameraCharacteristics cameraCharacteristics =
-                                    mAdvancedExtender.getCameraCharacteristics();
-                            Rect arraySize = cameraCharacteristics.get(
-                                    CameraCharacteristics.SENSOR_INFO_ACTIVE_ARRAY_SIZE);
-                            int centerX = arraySize.width() / 2;
-                            int centerY = arraySize.height() / 2;
-                            int squareSize = 5;
-                            PointF[] sampleTargetCoordinates = new PointF[]{
-                                    new PointF(centerX - squareSize, centerY - squareSize),
-                                    new PointF(centerX + squareSize, centerY - squareSize),
-                                    new PointF(centerX + squareSize, centerY + squareSize),
-                                    new PointF(centerX - squareSize, centerY + squareSize)
-                            };
-                            captureResults.put(ExtensionCaptureResult.EFV_TARGET_COORDINATES,
-                                    sampleTargetCoordinates);
-                        }
-                    }
-                }
-
-                if (autoZoomEnabled && stabilizationModeLocked) {
-                    int[] sampleAutoZoomPaddingRegion = {3, 3, 3, 3};
-                    captureResults.put(ExtensionCaptureResult.EFV_AUTO_ZOOM_PADDING_REGION,
-                            sampleAutoZoomPaddingRegion);
-                }
-            }
 
             captureCallback.onCaptureCompleted(shutterTimestamp, seqId, captureResults);
         }
@@ -382,13 +311,11 @@ public class EyesFreeVidSessionProcessor extends SessionProcessor {
         return mParametersList;
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     @Override
     public void stopRepeating() {
         mRequestProcessor.stopRepeating();
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     @Override
     public int startMultiFrameCapture(@NonNull Executor executor,
             @NonNull CaptureCallback captureCallback) {
@@ -453,7 +380,6 @@ public class EyesFreeVidSessionProcessor extends SessionProcessor {
         return seqId;
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     @Override
     public int startTrigger(@NonNull CaptureRequest captureRequest,
             @NonNull Executor executor, @NonNull CaptureCallback captureCallback) {
@@ -533,7 +459,6 @@ public class EyesFreeVidSessionProcessor extends SessionProcessor {
         return parameters;
     }
 
-    @FlaggedApi(Flags.FLAG_CONCERT_MODE_API)
     @Override
     public void setParameters(@NonNull CaptureRequest captureRequest) {
         synchronized (mParametersLock) {
diff --git a/camera2/extensions/stub/Android.bp b/camera2/extensions/stub/Android.bp
index 7ebfdea..aca5711 100644
--- a/camera2/extensions/stub/Android.bp
+++ b/camera2/extensions/stub/Android.bp
@@ -20,9 +20,7 @@ java_library {
     name: "androidx.camera.extensions.stub",
     installable: true,
 
-    static_libs: ["androidx.annotation_annotation"],
+    platform_apis: true,
 
     srcs: ["src/**/*.java"],
-
-    sdk_version: "current",
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/AutoImageCaptureExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/AutoImageCaptureExtenderImpl.java
old mode 100755
new mode 100644
index bd60570..e8414a7
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/AutoImageCaptureExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/AutoImageCaptureExtenderImpl.java
@@ -23,8 +23,8 @@ import android.util.Pair;
 import android.util.Range;
 import android.util.Size;
 
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 import java.util.List;
 
@@ -45,15 +45,18 @@ public final class AutoImageCaptureExtenderImpl implements ImageCaptureExtenderI
     }
 
     @Override
-    public void init(String cameraId, CameraCharacteristics cameraCharacteristics) {
+    public void init(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureProcessorImpl getCaptureProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public List<CaptureStageImpl> getCaptureStages() {
         throw new RuntimeException("Stub, replace with implementation.");
@@ -65,8 +68,9 @@ public final class AutoImageCaptureExtenderImpl implements ImageCaptureExtenderI
     }
 
     @Override
-    public void onInit(String cameraId, CameraCharacteristics cameraCharacteristics,
-            Context context) {
+    public void onInit(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics,
+            @NonNull Context context) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
@@ -75,44 +79,50 @@ public final class AutoImageCaptureExtenderImpl implements ImageCaptureExtenderI
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onPresetSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onEnableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onDisableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public List<Pair<Integer, Size[]>> getSupportedResolutions() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
-    public List<Pair<Integer, Size[]>> getSupportedPostviewResolutions(Size captureSize) {
+    public List<Pair<Integer, Size[]>> getSupportedPostviewResolutions(
+            @NonNull Size captureSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Nullable
     @Override
-    public Range<Long> getEstimatedCaptureLatencyRange(@NonNull Size captureOutputSize) {
+    public Range<Long> getEstimatedCaptureLatencyRange(@Nullable Size captureOutputSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
-    @Nullable
+    @NonNull
     @Override
     public List<CaptureRequest.Key> getAvailableCaptureRequestKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
-    @Nullable
+    @NonNull
     @Override
     public List<CaptureResult.Key> getAvailableCaptureResultKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
@@ -129,6 +139,7 @@ public final class AutoImageCaptureExtenderImpl implements ImageCaptureExtenderI
     }
 
     @Override
+    @Nullable
     public Pair<Long, Long> getRealtimeCaptureLatency() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/AutoPreviewExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/AutoPreviewExtenderImpl.java
old mode 100755
new mode 100644
index 0c4577a..f3f9693
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/AutoPreviewExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/AutoPreviewExtenderImpl.java
@@ -21,8 +21,8 @@ import android.hardware.camera2.CameraCharacteristics;
 import android.util.Pair;
 import android.util.Size;
 
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 import java.util.List;
 
@@ -44,28 +44,33 @@ public final class AutoPreviewExtenderImpl implements PreviewExtenderImpl {
     }
 
     @Override
-    public void init(String cameraId, CameraCharacteristics cameraCharacteristics) {
+    public void init(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public CaptureStageImpl getCaptureStage() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public ProcessorType getProcessorType() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public ProcessorImpl getProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public void onInit(String cameraId, CameraCharacteristics cameraCharacteristics,
-            Context context) {
+    public void onInit(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics,
+            @NonNull Context context) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
@@ -74,21 +79,25 @@ public final class AutoPreviewExtenderImpl implements PreviewExtenderImpl {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onPresetSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onEnableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onDisableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public List<Pair<Integer, Size[]>> getSupportedResolutions() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BeautyImageCaptureExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BeautyImageCaptureExtenderImpl.java
old mode 100755
new mode 100644
index 50c8040..98b9e6e
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BeautyImageCaptureExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BeautyImageCaptureExtenderImpl.java
@@ -23,8 +23,8 @@ import android.util.Pair;
 import android.util.Range;
 import android.util.Size;
 
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 import java.util.List;
 
@@ -45,15 +45,18 @@ public final class BeautyImageCaptureExtenderImpl implements ImageCaptureExtende
     }
 
     @Override
-    public void init(String cameraId, CameraCharacteristics cameraCharacteristics) {
+    public void init(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureProcessorImpl getCaptureProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public List<CaptureStageImpl> getCaptureStages() {
         throw new RuntimeException("Stub, replace with implementation.");
@@ -65,8 +68,9 @@ public final class BeautyImageCaptureExtenderImpl implements ImageCaptureExtende
     }
 
     @Override
-    public void onInit(String cameraId, CameraCharacteristics cameraCharacteristics,
-            Context context) {
+    public void onInit(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics,
+            @NonNull Context context) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
@@ -75,44 +79,49 @@ public final class BeautyImageCaptureExtenderImpl implements ImageCaptureExtende
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onPresetSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onEnableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onDisableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public List<Pair<Integer, Size[]>> getSupportedResolutions() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public List<Pair<Integer, Size[]>> getSupportedPostviewResolutions(Size captureSize) {
+    @Nullable
+    public List<Pair<Integer, Size[]>> getSupportedPostviewResolutions(@NonNull Size captureSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Nullable
     @Override
-    public Range<Long> getEstimatedCaptureLatencyRange(@NonNull Size captureOutputSize) {
+    public Range<Long> getEstimatedCaptureLatencyRange(@Nullable Size captureOutputSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
-    @Nullable
+    @NonNull
     @Override
     public List<CaptureRequest.Key> getAvailableCaptureRequestKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
-    @Nullable
+    @NonNull
     @Override
     public List<CaptureResult.Key> getAvailableCaptureResultKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
@@ -129,6 +138,7 @@ public final class BeautyImageCaptureExtenderImpl implements ImageCaptureExtende
     }
 
     @Override
+    @Nullable
     public Pair<Long, Long> getRealtimeCaptureLatency() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BeautyPreviewExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BeautyPreviewExtenderImpl.java
old mode 100755
new mode 100644
index 1f50174..77ac3a5
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BeautyPreviewExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BeautyPreviewExtenderImpl.java
@@ -21,8 +21,8 @@ import android.hardware.camera2.CameraCharacteristics;
 import android.util.Pair;
 import android.util.Size;
 
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 import java.util.List;
 
@@ -44,28 +44,33 @@ public final class BeautyPreviewExtenderImpl implements PreviewExtenderImpl {
     }
 
     @Override
-    public void init(String cameraId, CameraCharacteristics cameraCharacteristics) {
+    public void init(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public CaptureStageImpl getCaptureStage() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public ProcessorType getProcessorType() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public ProcessorImpl getProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public void onInit(String cameraId, CameraCharacteristics cameraCharacteristics,
-            Context context) {
+    public void onInit(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics,
+            @NonNull Context context) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
@@ -74,21 +79,25 @@ public final class BeautyPreviewExtenderImpl implements PreviewExtenderImpl {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onPresetSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onEnableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onDisableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public List<Pair<Integer, Size[]>> getSupportedResolutions() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BokehImageCaptureExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BokehImageCaptureExtenderImpl.java
index ee777cf..a81d6d9 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BokehImageCaptureExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BokehImageCaptureExtenderImpl.java
@@ -23,8 +23,8 @@ import android.util.Pair;
 import android.util.Range;
 import android.util.Size;
 
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 import java.util.List;
 
@@ -45,15 +45,18 @@ public final class BokehImageCaptureExtenderImpl implements ImageCaptureExtender
     }
 
     @Override
-    public void init(String cameraId, CameraCharacteristics cameraCharacteristics) {
+    public void init(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureProcessorImpl getCaptureProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public List<CaptureStageImpl> getCaptureStages() {
         throw new RuntimeException("Stub, replace with implementation.");
@@ -65,8 +68,9 @@ public final class BokehImageCaptureExtenderImpl implements ImageCaptureExtender
     }
 
     @Override
-    public void onInit(String cameraId, CameraCharacteristics cameraCharacteristics,
-            Context context) {
+    public void onInit(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics,
+            @NonNull Context context) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
@@ -75,44 +79,49 @@ public final class BokehImageCaptureExtenderImpl implements ImageCaptureExtender
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onPresetSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onEnableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onDisableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public List<Pair<Integer, Size[]>> getSupportedResolutions() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public List<Pair<Integer, Size[]>> getSupportedPostviewResolutions(Size captureSize) {
+    @Nullable
+    public List<Pair<Integer, Size[]>> getSupportedPostviewResolutions(@NonNull Size captureSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Nullable
     @Override
-    public Range<Long> getEstimatedCaptureLatencyRange(@NonNull Size captureOutputSize) {
+    public Range<Long> getEstimatedCaptureLatencyRange(@Nullable Size captureOutputSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
-    @Nullable
+    @NonNull
     @Override
     public List<CaptureRequest.Key> getAvailableCaptureRequestKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
-    @Nullable
+    @NonNull
     @Override
     public List<CaptureResult.Key> getAvailableCaptureResultKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
@@ -128,6 +137,7 @@ public final class BokehImageCaptureExtenderImpl implements ImageCaptureExtender
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public Pair<Long, Long> getRealtimeCaptureLatency() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BokehPreviewExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BokehPreviewExtenderImpl.java
index 1dc5ed7..6327b80 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BokehPreviewExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/BokehPreviewExtenderImpl.java
@@ -20,8 +20,8 @@ import android.hardware.camera2.CameraCharacteristics;
 import android.util.Pair;
 import android.util.Size;
 
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 import java.util.List;
 
@@ -42,28 +42,33 @@ public final class BokehPreviewExtenderImpl implements PreviewExtenderImpl {
     }
 
     @Override
-    public void init(String cameraId, CameraCharacteristics cameraCharacteristics) {
+    public void init(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public CaptureStageImpl getCaptureStage() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public ProcessorType getProcessorType() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public ProcessorImpl getProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public void onInit(String cameraId, CameraCharacteristics cameraCharacteristics,
-            Context context) {
+    public void onInit(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics,
+            @NonNull Context context) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
@@ -72,21 +77,25 @@ public final class BokehPreviewExtenderImpl implements PreviewExtenderImpl {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onPresetSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onEnableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onDisableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public List<Pair<Integer, Size[]>> getSupportedResolutions() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/CaptureProcessorImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/CaptureProcessorImpl.java
index f4719b8..1f121a8 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/CaptureProcessorImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/CaptureProcessorImpl.java
@@ -24,6 +24,9 @@ import android.util.Pair;
 import android.util.Size;
 import android.view.Surface;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 import java.util.Map;
 import java.util.concurrent.Executor;
 
@@ -44,7 +47,7 @@ public interface CaptureProcessorImpl extends ProcessorImpl {
      *                process. The {@link Image} that are contained within the map will become
      *                invalid after this method completes, so no references to them should be kept.
      */
-    void process(Map<Integer, Pair<Image, TotalCaptureResult>> results);
+    void process(@NonNull Map<Integer, Pair<Image, TotalCaptureResult>> results);
 
     /**
      * Informs the CaptureProcessorImpl where it should write the postview output to.
@@ -54,7 +57,7 @@ public interface CaptureProcessorImpl extends ProcessorImpl {
      *                that the CaptureProcessorImpl should write data into.
      * @since 1.4
      */
-    void onPostviewOutputSurface(Surface surface);
+    void onPostviewOutputSurface(@NonNull Surface surface);
 
     /**
      * Invoked when the Camera Framework changes the configured output resolution for
@@ -67,7 +70,7 @@ public interface CaptureProcessorImpl extends ProcessorImpl {
      * @param postviewSize for the surface for postview.
      * @since 1.4
      */
-    void onResolutionUpdate(Size size, Size postviewSize);
+    void onResolutionUpdate(@NonNull Size size, @NonNull Size postviewSize);
 
     /**
      * Process a set images captured that were requested.
@@ -85,8 +88,8 @@ public interface CaptureProcessorImpl extends ProcessorImpl {
      *                       run on any arbitrary executor.
      * @since 1.3
      */
-    void process(Map<Integer, Pair<Image, TotalCaptureResult>> results,
-            ProcessResultImpl resultCallback, Executor executor);
+    void process(@NonNull Map<Integer, Pair<Image, TotalCaptureResult>> results,
+            @NonNull ProcessResultImpl resultCallback, @Nullable Executor executor);
 
     /**
      * Process a set images captured that were requested for both postview and
@@ -111,6 +114,6 @@ public interface CaptureProcessorImpl extends ProcessorImpl {
      * @throws RuntimeException   if postview feature is not supported
      * @since 1.4
      */
-    void processWithPostview(Map<Integer, Pair<Image, TotalCaptureResult>> results,
-            ProcessResultImpl resultCallback, Executor executor);
+    void processWithPostview(@NonNull Map<Integer, Pair<Image, TotalCaptureResult>> results,
+            @NonNull ProcessResultImpl resultCallback, @Nullable Executor executor);
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/CaptureStageImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/CaptureStageImpl.java
index c4796c2..39a7db2 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/CaptureStageImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/CaptureStageImpl.java
@@ -19,6 +19,8 @@ package androidx.camera.extensions.impl;
 import android.hardware.camera2.CaptureRequest;
 import android.util.Pair;
 
+import android.annotation.NonNull;
+
 import java.util.List;
 
 /**
@@ -34,5 +36,6 @@ public interface CaptureStageImpl {
      * Returns the set of {@link CaptureRequest.Key} and the corresponding values that will be
      * set for a single {@link CaptureRequest}.
      */
+    @NonNull
     List<Pair<CaptureRequest.Key, Object>> getParameters();
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ExtenderStateListener.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ExtenderStateListener.java
index 4a3b01c..79e7e58 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ExtenderStateListener.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ExtenderStateListener.java
@@ -22,6 +22,9 @@ import android.hardware.camera2.CameraDevice;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.params.SessionConfiguration;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 /**
  * Provides interfaces that the OEM needs to implement to handle the state change.
  *
@@ -39,7 +42,8 @@ public interface ExtenderStateListener {
      * @param cameraCharacteristics The {@link CameraCharacteristics} of the camera.
      * @param context The {@link Context} used for CameraX.
      */
-    void onInit(String cameraId, CameraCharacteristics cameraCharacteristics, Context context);
+    void onInit(@NonNull String cameraId, @NonNull CameraCharacteristics cameraCharacteristics,
+            @NonNull Context context);
 
     /**
      * Notify to de-initialize the extension. This callback will be invoked after unbind.
@@ -58,6 +62,7 @@ public interface ExtenderStateListener {
      *
      * @return The request information to set the session wide camera parameters.
      */
+    @Nullable
     CaptureStageImpl onPresetSession();
 
     /**
@@ -69,6 +74,7 @@ public interface ExtenderStateListener {
      *
      * @return The request information to create a single capture request to camera device.
      */
+    @Nullable
     CaptureStageImpl onEnableSession();
 
     /**
@@ -79,6 +85,7 @@ public interface ExtenderStateListener {
      *
      * @return The request information to customize the session.
      */
+    @Nullable
     CaptureStageImpl onDisableSession();
 
     /**
@@ -90,10 +97,11 @@ public interface ExtenderStateListener {
      * is inconsistency between the session type values from preview and image extenders, then
      * the session configuration will fail.
      *
-     * @since 1.4
      * @return Camera capture session type. Regular and vendor specific types are supported but
      * not high speed values. The extension can return -1 in which case the camera capture session
      * will be configured to use the default regular type.
+     *
+     * @since 1.4
      */
     int onSessionType();
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ExtensionVersionImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ExtensionVersionImpl.java
index 7769551..7cd0190 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ExtensionVersionImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ExtensionVersionImpl.java
@@ -16,6 +16,8 @@
 
 package androidx.camera.extensions.impl;
 
+import android.annotation.NonNull;
+
 /**
  * Stub implementation for the extension version check.
  *
@@ -50,7 +52,8 @@ public class ExtensionVersionImpl {
      * @return the version that vendor supported in this device. The MAJOR.MINOR.PATCH format
      * should be used.
      */
-    public String checkApiVersion(String version) {
+    @NonNull
+    public String checkApiVersion(@NonNull String version) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/HdrImageCaptureExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/HdrImageCaptureExtenderImpl.java
index f3fd2f3..5f804f8 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/HdrImageCaptureExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/HdrImageCaptureExtenderImpl.java
@@ -23,8 +23,8 @@ import android.util.Pair;
 import android.util.Range;
 import android.util.Size;
 
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 import java.util.List;
 
@@ -45,15 +45,18 @@ public final class HdrImageCaptureExtenderImpl implements ImageCaptureExtenderIm
     }
 
     @Override
-    public void init(String cameraId, CameraCharacteristics cameraCharacteristics) {
+    public void init(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureProcessorImpl getCaptureProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public List<CaptureStageImpl> getCaptureStages() {
         throw new RuntimeException("Stub, replace with implementation.");
@@ -65,8 +68,9 @@ public final class HdrImageCaptureExtenderImpl implements ImageCaptureExtenderIm
     }
 
     @Override
-    public void onInit(String cameraId, CameraCharacteristics cameraCharacteristics,
-            Context context) {
+    public void onInit(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics,
+            @NonNull Context context) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
@@ -75,44 +79,49 @@ public final class HdrImageCaptureExtenderImpl implements ImageCaptureExtenderIm
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onPresetSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onEnableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onDisableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public List<Pair<Integer, Size[]>> getSupportedResolutions() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public List<Pair<Integer, Size[]>> getSupportedPostviewResolutions(Size captureSize) {
+    @Nullable
+    public List<Pair<Integer, Size[]>> getSupportedPostviewResolutions(@NonNull Size captureSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Nullable
     @Override
-    public Range<Long> getEstimatedCaptureLatencyRange(@NonNull Size captureOutputSize) {
+    public Range<Long> getEstimatedCaptureLatencyRange(@Nullable Size captureOutputSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
-    @Nullable
+    @NonNull
     @Override
     public List<CaptureRequest.Key> getAvailableCaptureRequestKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
-    @Nullable
+    @NonNull
     @Override
     public List<CaptureResult.Key> getAvailableCaptureResultKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
@@ -128,6 +137,7 @@ public final class HdrImageCaptureExtenderImpl implements ImageCaptureExtenderIm
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public Pair<Long, Long> getRealtimeCaptureLatency() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/HdrPreviewExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/HdrPreviewExtenderImpl.java
index af48464..f035f6f 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/HdrPreviewExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/HdrPreviewExtenderImpl.java
@@ -21,8 +21,8 @@ import android.hardware.camera2.CameraCharacteristics;
 import android.util.Pair;
 import android.util.Size;
 
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 import java.util.List;
 
@@ -44,28 +44,33 @@ public final class HdrPreviewExtenderImpl implements PreviewExtenderImpl {
     }
 
     @Override
-    public void init(String cameraId, CameraCharacteristics cameraCharacteristics) {
+    public void init(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public CaptureStageImpl getCaptureStage() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public ProcessorType getProcessorType() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public ProcessorImpl getProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public void onInit(String cameraId, CameraCharacteristics cameraCharacteristics,
-            Context context) {
+    public void onInit(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics,
+            @NonNull Context context) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
@@ -74,21 +79,25 @@ public final class HdrPreviewExtenderImpl implements PreviewExtenderImpl {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onPresetSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onEnableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onDisableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public List<Pair<Integer, Size[]>> getSupportedResolutions() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ImageCaptureExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ImageCaptureExtenderImpl.java
index 70c1804..9060b94 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ImageCaptureExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ImageCaptureExtenderImpl.java
@@ -16,7 +16,6 @@
 
 package androidx.camera.extensions.impl;
 
-import android.annotation.SuppressLint;
 import android.graphics.ImageFormat;
 import android.hardware.camera2.CameraCharacteristics;
 import android.hardware.camera2.CaptureRequest;
@@ -25,6 +24,9 @@ import android.util.Pair;
 import android.util.Range;
 import android.util.Size;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 import java.util.List;
 
 /**
@@ -32,7 +34,6 @@ import java.util.List;
  *
  * @since 1.0
  */
-@SuppressLint("UnknownNullness")
 public interface ImageCaptureExtenderImpl extends ExtenderStateListener {
     /**
      * Indicates whether the extension is supported on the device.
@@ -41,7 +42,8 @@ public interface ImageCaptureExtenderImpl extends ExtenderStateListener {
      * @param cameraCharacteristics The {@link CameraCharacteristics} of the camera.
      * @return true if the extension is supported, otherwise false
      */
-    boolean isExtensionAvailable(String cameraId, CameraCharacteristics cameraCharacteristics);
+    boolean isExtensionAvailable(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics);
 
     /**
      * Initializes the extender to be used with the specified camera.
@@ -52,14 +54,16 @@ public interface ImageCaptureExtenderImpl extends ExtenderStateListener {
      * @param cameraId The camera2 id string of the camera.
      * @param cameraCharacteristics The {@link CameraCharacteristics} of the camera.
      */
-    void init(String cameraId, CameraCharacteristics cameraCharacteristics);
+    void init(@NonNull String cameraId, @NonNull CameraCharacteristics cameraCharacteristics);
 
     /**
      * The processing that will be done on a set of captures to create and image with the effect.
      */
+    @Nullable
     CaptureProcessorImpl getCaptureProcessor();
 
     /** The set of captures that are needed to create an image with the effect. */
+    @NonNull
     List<CaptureStageImpl> getCaptureStages();
 
     /**
@@ -82,22 +86,21 @@ public interface ImageCaptureExtenderImpl extends ExtenderStateListener {
      *         {@link android.hardware.camera2.params.StreamConfigurationMap}.
      * @since 1.1
      */
+    @Nullable
     List<Pair<Integer, Size[]>> getSupportedResolutions();
 
     /**
-     * Returns the customized supported postview resolutions for a still capture using
-     * its size.
+     * Returns supported output format/size map for postview image. OEM is required to support
+     * YUV_420_888 format output.
      *
      * <p>Pair list composed with {@link ImageFormat} and {@link Size} array will be returned.
+     * The sizes must be smaller than or equal to the provided capture size and have the same
+     * aspect ratio as the given capture size.
      *
-     * <p>The returned resolutions should be subset of the supported sizes retrieved from
-     * {@link android.hardware.camera2.params.StreamConfigurationMap} for the camera device.
-     *
-     * @return the customized supported resolutions, or null to support all sizes retrieved from
-     *         {@link android.hardware.camera2.params.StreamConfigurationMap}.
      * @since 1.4
      */
-    List<Pair<Integer, Size[]>> getSupportedPostviewResolutions(Size captureSize);
+    @Nullable
+    List<Pair<Integer, Size[]>> getSupportedPostviewResolutions(@NonNull Size captureSize);
 
     /**
      * Returns the estimated capture latency range in milliseconds for the target capture
@@ -113,7 +116,8 @@ public interface ImageCaptureExtenderImpl extends ExtenderStateListener {
      * null if no capture latency info can be provided.
      * @since 1.2
      */
-    Range<Long> getEstimatedCaptureLatencyRange(Size captureOutputSize);
+    @Nullable
+    Range<Long> getEstimatedCaptureLatencyRange(@Nullable Size captureOutputSize);
 
     /**
      * Return a list of orthogonal capture request keys.
@@ -154,6 +158,7 @@ public interface ImageCaptureExtenderImpl extends ExtenderStateListener {
      * are not supported.
      * @since 1.3
      */
+    @NonNull
     List<CaptureRequest.Key> getAvailableCaptureRequestKeys();
 
     /**
@@ -173,6 +178,7 @@ public interface ImageCaptureExtenderImpl extends ExtenderStateListener {
      * supported.
      * @since 1.3
      */
+    @NonNull
     List<CaptureResult.Key> getAvailableCaptureResultKeys();
 
     /**
@@ -202,6 +208,7 @@ public interface ImageCaptureExtenderImpl extends ExtenderStateListener {
      * null pair.
      * @since 1.4
      */
+    @Nullable
     Pair<Long, Long> getRealtimeCaptureLatency();
 
     /**
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/InitializerImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/InitializerImpl.java
index 779a2ee..8958759 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/InitializerImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/InitializerImpl.java
@@ -18,8 +18,8 @@ package androidx.camera.extensions.impl;
 
 import android.content.Context;
 
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 import java.util.concurrent.Executor;
 
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/NightImageCaptureExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/NightImageCaptureExtenderImpl.java
old mode 100755
new mode 100644
index 6f0eaef..815f5d0
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/NightImageCaptureExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/NightImageCaptureExtenderImpl.java
@@ -23,8 +23,8 @@ import android.util.Pair;
 import android.util.Range;
 import android.util.Size;
 
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 import java.util.List;
 
@@ -45,15 +45,18 @@ public final class NightImageCaptureExtenderImpl implements ImageCaptureExtender
     }
 
     @Override
-    public void init(String cameraId, CameraCharacteristics cameraCharacteristics) {
+    public void init(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureProcessorImpl getCaptureProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public List<CaptureStageImpl> getCaptureStages() {
         throw new RuntimeException("Stub, replace with implementation.");
@@ -65,8 +68,9 @@ public final class NightImageCaptureExtenderImpl implements ImageCaptureExtender
     }
 
     @Override
-    public void onInit(String cameraId, CameraCharacteristics cameraCharacteristics,
-            Context context) {
+    public void onInit(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics,
+            @NonNull Context context) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
@@ -75,44 +79,49 @@ public final class NightImageCaptureExtenderImpl implements ImageCaptureExtender
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onPresetSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onEnableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onDisableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public List<Pair<Integer, Size[]>> getSupportedResolutions() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
-    public List<Pair<Integer, Size[]>> getSupportedPostviewResolutions(Size captureSize) {
+    public List<Pair<Integer, Size[]>> getSupportedPostviewResolutions(@NonNull Size captureSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Nullable
     @Override
-    public Range<Long> getEstimatedCaptureLatencyRange(@NonNull Size captureOutputSize) {
+    public Range<Long> getEstimatedCaptureLatencyRange(@Nullable Size captureOutputSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
-    @Nullable
+    @NonNull
     @Override
     public List<CaptureRequest.Key> getAvailableCaptureRequestKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
-    @Nullable
+    @NonNull
     @Override
     public List<CaptureResult.Key> getAvailableCaptureResultKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
@@ -128,6 +137,7 @@ public final class NightImageCaptureExtenderImpl implements ImageCaptureExtender
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public Pair<Long, Long> getRealtimeCaptureLatency() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/NightPreviewExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/NightPreviewExtenderImpl.java
old mode 100755
new mode 100644
index 825994f..5783aba
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/NightPreviewExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/NightPreviewExtenderImpl.java
@@ -21,8 +21,8 @@ import android.hardware.camera2.CameraCharacteristics;
 import android.util.Pair;
 import android.util.Size;
 
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 import java.util.List;
 
@@ -44,28 +44,33 @@ public final class NightPreviewExtenderImpl implements PreviewExtenderImpl {
     }
 
     @Override
-    public void init(String cameraId, CameraCharacteristics cameraCharacteristics) {
+    public void init(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public CaptureStageImpl getCaptureStage() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public ProcessorType getProcessorType() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public ProcessorImpl getProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public void onInit(String cameraId, CameraCharacteristics cameraCharacteristics,
-            Context context) {
+    public void onInit(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics,
+            @NonNull Context context) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
@@ -74,21 +79,25 @@ public final class NightPreviewExtenderImpl implements PreviewExtenderImpl {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onPresetSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onEnableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public CaptureStageImpl onDisableSession() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @Nullable
     @Override
     public List<Pair<Integer, Size[]>> getSupportedResolutions() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/PreviewExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/PreviewExtenderImpl.java
index 4324987..077cb95 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/PreviewExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/PreviewExtenderImpl.java
@@ -22,7 +22,8 @@ import android.hardware.camera2.TotalCaptureResult;
 import android.util.Pair;
 import android.util.Size;
 
-import androidx.annotation.Nullable;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 import java.util.List;
 
@@ -49,7 +50,8 @@ public interface PreviewExtenderImpl extends ExtenderStateListener {
      * @param cameraCharacteristics The {@link CameraCharacteristics} of the camera.
      * @return true if the extension is supported, otherwise false
      */
-    boolean isExtensionAvailable(String cameraId, CameraCharacteristics cameraCharacteristics);
+    boolean isExtensionAvailable(@NonNull String cameraId,
+            @NonNull CameraCharacteristics cameraCharacteristics);
 
     /**
      * Initializes the extender to be used with the specified camera.
@@ -60,7 +62,7 @@ public interface PreviewExtenderImpl extends ExtenderStateListener {
      * @param cameraId The camera2 id string of the camera.
      * @param cameraCharacteristics The {@link CameraCharacteristics} of the camera.
      */
-    void init(String cameraId, CameraCharacteristics cameraCharacteristics);
+    void init(@NonNull String cameraId, @NonNull CameraCharacteristics cameraCharacteristics);
 
     /**
      * The set of parameters required to produce the effect on the preview stream.
@@ -73,9 +75,11 @@ public interface PreviewExtenderImpl extends ExtenderStateListener {
      * CaptureStageImpl}. If the processing step returns a {@code null}, meaning the required
      * parameters has not changed, then calling this will return the previous non-null value.
      */
+    @NonNull
     CaptureStageImpl getCaptureStage();
 
     /** The type of preview processing to use. */
+    @NonNull
     ProcessorType getProcessorType();
 
     /**
@@ -91,6 +95,7 @@ public interface PreviewExtenderImpl extends ExtenderStateListener {
      * <tr><td> PROCESSOR_TYPE_NONE </td> <td> null </td> </tr>
      * </table>
      */
+    @Nullable
     ProcessorImpl getProcessor();
 
     /**
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/PreviewImageProcessorImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/PreviewImageProcessorImpl.java
index f203eba..48e810f 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/PreviewImageProcessorImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/PreviewImageProcessorImpl.java
@@ -16,11 +16,13 @@
 
 package androidx.camera.extensions.impl;
 
-import android.annotation.SuppressLint;
 import android.graphics.ImageFormat;
 import android.hardware.camera2.TotalCaptureResult;
 import android.media.Image;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 import java.util.concurrent.Executor;
 
 /**
@@ -29,7 +31,6 @@ import java.util.concurrent.Executor;
  *
  * @since 1.0
  */
-@SuppressLint("UnknownNullness")
 public interface PreviewImageProcessorImpl extends ProcessorImpl {
     /**
      * Processes the requested image capture.
@@ -41,7 +42,7 @@ public interface PreviewImageProcessorImpl extends ProcessorImpl {
      *               invalid after the method completes so no reference to it should be kept.
      * @param result The metadata associated with the image to process.
      */
-    void process(Image image, TotalCaptureResult result);
+    void process(@NonNull Image image, @NonNull TotalCaptureResult result);
 
     /**
      * Processes the requested image capture.
@@ -59,6 +60,7 @@ public interface PreviewImageProcessorImpl extends ProcessorImpl {
      *                       run on any arbitrary executor.
      * @since 1.3
      */
-    void process(Image image, TotalCaptureResult result, ProcessResultImpl resultCallback,
-            Executor executor);
+    void process(@NonNull Image image, @NonNull TotalCaptureResult result,
+            @NonNull ProcessResultImpl resultCallback,
+            @Nullable Executor executor);
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ProcessResultImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ProcessResultImpl.java
index 0e15445..e4f7f2c 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ProcessResultImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ProcessResultImpl.java
@@ -16,17 +16,17 @@
 
 package androidx.camera.extensions.impl;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.CaptureResult;
 import android.util.Pair;
 
+import android.annotation.NonNull;
+
 import java.util.List;
 
 /**
  * Allows clients to receive information about the capture result values of processed frames.
  *
  */
-@SuppressLint("UnknownNullness")
 public interface ProcessResultImpl {
     /**
      * Capture result callback that needs to be called when the process capture results are
@@ -41,7 +41,8 @@ public interface ProcessResultImpl {
      *                             supported and applied by the corresponding framework.
      * @since 1.3
      */
-    void onCaptureCompleted(long shutterTimestamp, List<Pair<CaptureResult.Key, Object>> result);
+    void onCaptureCompleted(long shutterTimestamp,
+            @NonNull List<Pair<CaptureResult.Key, Object>> result);
 
     /**
      * Capture progress callback that needs to be called when the process capture is
@@ -56,5 +57,5 @@ public interface ProcessResultImpl {
      * @param progress             Value between 0 and 100.
      * @since 1.4
      */
-    void onCaptureProcessProgressed(int progress);
+    default void onCaptureProcessProgressed(int progress) {}
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ProcessorImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ProcessorImpl.java
index 6be328b..45c8c13 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ProcessorImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/ProcessorImpl.java
@@ -19,6 +19,8 @@ package androidx.camera.extensions.impl;
 import android.util.Size;
 import android.view.Surface;
 
+import android.annotation.NonNull;
+
 /**
  * Processes an input image stream and produces an output image stream.
  *
@@ -31,23 +33,23 @@ public interface ProcessorImpl {
      * @param surface     The {@link Surface} that the ProcessorImpl should write data into.
      * @param imageFormat The format of that the surface expects.
      */
-    void onOutputSurface(Surface surface, int imageFormat);
+    void onOutputSurface(@NonNull Surface surface, int imageFormat);
 
     /**
      * Invoked when CameraX changes the configured output resolution.
      *
-     * <p>After this call, {@link CaptureProcessorImpl} should expect any {@link Image} received as
-     * input to be at the specified resolution.
+     * <p>After this call, {@link CaptureProcessorImpl} should expect any
+     * {@link android.media.Image} received as input to be at the specified resolution.
      *
      * @param size for the surface.
      */
-    void onResolutionUpdate(Size size);
+    void onResolutionUpdate(@NonNull Size size);
 
     /**
      * Invoked when CameraX changes the configured input image format.
      *
-     * <p>After this call, {@link CaptureProcessorImpl} should expect any {@link Image} received as
-     * input to have the specified image format.
+     * <p>After this call, {@link CaptureProcessorImpl} should expect any
+     * {@link android.media.Image} received as input to have the specified image format.
      *
      * @param imageFormat for the surface.
      */
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/RequestUpdateProcessorImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/RequestUpdateProcessorImpl.java
index 14637d7..a5bb70d 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/RequestUpdateProcessorImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/RequestUpdateProcessorImpl.java
@@ -18,6 +18,8 @@ package androidx.camera.extensions.impl;
 
 import android.hardware.camera2.TotalCaptureResult;
 
+import android.annotation.Nullable;
+
 /**
  * Processes a {@link TotalCaptureResult} to update a CaptureStage.
  *
@@ -32,5 +34,6 @@ public interface RequestUpdateProcessorImpl extends ProcessorImpl {
      * @return The updated parameters used for the repeating requests. If this is {@code null} then
      * the previous parameters will be used.
      */
-    CaptureStageImpl process(TotalCaptureResult result);
+    @Nullable
+    CaptureStageImpl process(@Nullable TotalCaptureResult result);
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/AdvancedExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/AdvancedExtenderImpl.java
index 4386b5e..282a47f 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/AdvancedExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/AdvancedExtenderImpl.java
@@ -16,7 +16,6 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.CameraCharacteristics;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.CaptureResult;
@@ -24,6 +23,8 @@ import android.util.Pair;
 import android.util.Range;
 import android.util.Size;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 import androidx.camera.extensions.impl.ExtensionVersionImpl;
 
 import java.util.List;
@@ -51,7 +52,6 @@ import java.util.Map;
  *
  * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public interface AdvancedExtenderImpl {
 
     /**
@@ -65,8 +65,8 @@ public interface AdvancedExtenderImpl {
      *                           physical camera ids and their CameraCharacteristics.
      * @return true if the extension is supported, otherwise false
      */
-    boolean isExtensionAvailable(String cameraId,
-            Map<String, CameraCharacteristics> characteristicsMap);
+    boolean isExtensionAvailable(@NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> characteristicsMap);
 
     /**
      * Initializes the extender to be used with the specified camera.
@@ -81,7 +81,8 @@ public interface AdvancedExtenderImpl {
      *                           If the camera is logical camera, it will also contain associated
      *                           physical camera ids and their CameraCharacteristics.
      */
-    void init(String cameraId, Map<String, CameraCharacteristics> characteristicsMap);
+    void init(@NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> characteristicsMap);
 
     /**
      * Returns the estimated capture latency range in milliseconds for the
@@ -98,8 +99,9 @@ public interface AdvancedExtenderImpl {
      * @return the range of estimated minimal and maximal capture latency in milliseconds.
      * Returns null if no capture latency info can be provided.
      */
-    Range<Long> getEstimatedCaptureLatencyRange(String cameraId,
-            Size captureOutputSize, int imageFormat);
+    @Nullable
+    Range<Long> getEstimatedCaptureLatencyRange(@NonNull String cameraId,
+            @Nullable Size captureOutputSize, int imageFormat);
 
     /**
      * Returns supported output format/size map for preview. The format could be PRIVATE or
@@ -112,7 +114,8 @@ public interface AdvancedExtenderImpl {
      * the HAL. Alternatively OEM can configure a intermediate YUV surface of the same size and
      * writes the output to the preview output surface.
      */
-    Map<Integer, List<Size>> getSupportedPreviewOutputResolutions(String cameraId);
+    @NonNull
+    Map<Integer, List<Size>> getSupportedPreviewOutputResolutions(@NonNull String cameraId);
 
     /**
      * Returns supported output format/size map for image capture. OEM is required to support
@@ -122,18 +125,21 @@ public interface AdvancedExtenderImpl {
      * format/size could be either added in CameraCaptureSession with HAL processing OR it
      * configures intermediate surfaces(YUV/RAW..) and writes the output to the output surface.
      */
-    Map<Integer, List<Size>> getSupportedCaptureOutputResolutions(String cameraId);
+    @NonNull
+    Map<Integer, List<Size>> getSupportedCaptureOutputResolutions(@NonNull String cameraId);
 
     /**
      * Returns supported output format/size map for postview image. OEM is required to support
      * both JPEG and YUV_420_888 format output.
      *
-     * <p>The surface created with this supported format/size could configure
-     * intermediate surfaces(YUV/RAW..) and write the output to the output surface.</p>
+     * <p>The returned sizes must be smaller than or equal to the provided capture size and have the
+     * same aspect ratio as the given capture size. If no supported resolution exists for the
+     * provided capture size then an empty map is returned.
      *
      * @since 1.4
      */
-    Map<Integer, List<Size>> getSupportedPostviewResolutions(Size captureSize);
+    @NonNull
+    Map<Integer, List<Size>> getSupportedPostviewResolutions(@NonNull Size captureSize);
 
     /**
      * Returns supported output sizes for Image Analysis (YUV_420_888 format).
@@ -142,12 +148,14 @@ public interface AdvancedExtenderImpl {
      * output surfaces. If imageAnalysis YUV surface is not supported, OEM should return null or
      * empty list.
      */
-    List<Size> getSupportedYuvAnalysisResolutions(String cameraId);
+    @Nullable
+    List<Size> getSupportedYuvAnalysisResolutions(@NonNull String cameraId);
 
     /**
      * Returns a processor for activating extension sessions. It implements all the interactions
      * required for starting a extension and cleanup.
      */
+    @NonNull
     SessionProcessorImpl createSessionProcessor();
 
     /**
@@ -181,6 +189,7 @@ public interface AdvancedExtenderImpl {
      * are not supported.
      * @since 1.3
      */
+    @NonNull
     List<CaptureRequest.Key> getAvailableCaptureRequestKeys();
 
     /**
@@ -196,6 +205,7 @@ public interface AdvancedExtenderImpl {
      * an empty list if capture results are not supported.
      * @since 1.3
      */
+    @NonNull
     List<CaptureResult.Key> getAvailableCaptureResultKeys();
 
     /**
@@ -205,7 +215,7 @@ public interface AdvancedExtenderImpl {
      * be triggered, {@code false} otherwise.
      * @since 1.4
      */
-    public boolean isCaptureProcessProgressAvailable();
+    boolean isCaptureProcessProgressAvailable();
 
     /**
      * Indicates whether the extension supports the postview for still capture feature.
@@ -234,7 +244,11 @@ public interface AdvancedExtenderImpl {
      * {@link CameraCharacteristics#CONTROL_VIDEO_STABILIZATION_MODE_OFF} for the key
      * {@link CameraCharacteristics#CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES}.
      *
-     * <p> Currently, the only synthetic keys supported for override are
+     * <p>Please note that it is mandatory to include
+     * {@link CameraCharacteristics#CONTROL_ZOOM_RATIO_RANGE} and
+     * {@link CameraCharacteristics#CONTROL_AF_AVAILABLE_MODES} in the list.
+     *
+     * <p>Currently, the only synthetic keys supported for override are
      * {@link CameraCharacteristics#REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES} and
      * {@link CameraCharacteristics#REQUEST_AVAILABLE_COLOR_SPACE_PROFILES}. To enable them, an OEM
      * should override the respective native keys
@@ -242,5 +256,6 @@ public interface AdvancedExtenderImpl {
      *  {@link CameraCharacteristics#REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP}.
      * @since 1.5
      */
+    @NonNull
     List<Pair<CameraCharacteristics.Key, Object>> getAvailableCharacteristicsKeyValues();
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/AutoAdvancedExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/AutoAdvancedExtenderImpl.java
index 45e4fcc..efc58bd 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/AutoAdvancedExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/AutoAdvancedExtenderImpl.java
@@ -16,7 +16,6 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.CameraCharacteristics;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.CaptureResult;
@@ -24,6 +23,9 @@ import android.util.Pair;
 import android.util.Range;
 import android.util.Size;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 import java.util.List;
 import java.util.Map;
 
@@ -34,64 +36,71 @@ import java.util.Map;
  *
  * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public class AutoAdvancedExtenderImpl implements AdvancedExtenderImpl {
     public AutoAdvancedExtenderImpl() {
     }
 
     @Override
-    public boolean isExtensionAvailable(String cameraId,
-            Map<String, CameraCharacteristics> characteristicsMap) {
+    public boolean isExtensionAvailable(@NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> characteristicsMap) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public void init(String cameraId,
-            Map<String, CameraCharacteristics> characteristicsMap) {
+    public void init(@NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> characteristicsMap) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @Nullable
     public Range<Long> getEstimatedCaptureLatencyRange(
-            String cameraId, Size size, int imageFormat) {
+            @NonNull String cameraId, @Nullable Size size, int imageFormat) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedPreviewOutputResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedCaptureOutputResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedPostviewResolutions(
-            Size captureSize) {
+            @NonNull Size captureSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @Nullable
     public List<Size> getSupportedYuvAnalysisResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public SessionProcessorImpl createSessionProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public List<CaptureRequest.Key> getAvailableCaptureRequestKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public List<CaptureResult.Key> getAvailableCaptureResultKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
@@ -106,6 +115,7 @@ public class AutoAdvancedExtenderImpl implements AdvancedExtenderImpl {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public List<Pair<CameraCharacteristics.Key, Object>> getAvailableCharacteristicsKeyValues() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/BeautyAdvancedExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/BeautyAdvancedExtenderImpl.java
index 8bb17f7..10a3440 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/BeautyAdvancedExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/BeautyAdvancedExtenderImpl.java
@@ -16,7 +16,6 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.CameraCharacteristics;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.CaptureResult;
@@ -24,6 +23,9 @@ import android.util.Pair;
 import android.util.Range;
 import android.util.Size;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 import java.util.List;
 import java.util.Map;
 
@@ -34,64 +36,71 @@ import java.util.Map;
  *
  * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public class BeautyAdvancedExtenderImpl implements AdvancedExtenderImpl {
     public BeautyAdvancedExtenderImpl() {
     }
 
     @Override
-    public boolean isExtensionAvailable(String cameraId,
-            Map<String, CameraCharacteristics> characteristicsMap) {
+    public boolean isExtensionAvailable(@NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> characteristicsMap) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public void init(String cameraId,
-            Map<String, CameraCharacteristics> characteristicsMap) {
+    public void init(@NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> characteristicsMap) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @Nullable
     public Range<Long> getEstimatedCaptureLatencyRange(
-            String cameraId, Size size, int imageFormat) {
+            @NonNull String cameraId, @Nullable Size size, int imageFormat) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedPreviewOutputResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedCaptureOutputResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedPostviewResolutions(
-            Size captureSize) {
+            @NonNull Size captureSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @Nullable
     public List<Size> getSupportedYuvAnalysisResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public SessionProcessorImpl createSessionProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public List<CaptureRequest.Key> getAvailableCaptureRequestKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public List<CaptureResult.Key> getAvailableCaptureResultKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
@@ -106,6 +115,7 @@ public class BeautyAdvancedExtenderImpl implements AdvancedExtenderImpl {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public List<Pair<CameraCharacteristics.Key, Object>> getAvailableCharacteristicsKeyValues() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/BokehAdvancedExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/BokehAdvancedExtenderImpl.java
index 71b38d6..c1d8852 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/BokehAdvancedExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/BokehAdvancedExtenderImpl.java
@@ -16,7 +16,6 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.CameraCharacteristics;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.CaptureResult;
@@ -24,6 +23,9 @@ import android.util.Pair;
 import android.util.Range;
 import android.util.Size;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 import java.util.List;
 import java.util.Map;
 
@@ -34,69 +36,76 @@ import java.util.Map;
  *
  * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public class BokehAdvancedExtenderImpl implements AdvancedExtenderImpl {
     public BokehAdvancedExtenderImpl() {
     }
 
     @Override
-    public boolean isExtensionAvailable(String cameraId,
-            Map<String, CameraCharacteristics> characteristicsMap) {
+    public boolean isExtensionAvailable(@NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> characteristicsMap) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public void init(String cameraId,
-            Map<String, CameraCharacteristics> characteristicsMap) {
+    public void init(@NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> characteristicsMap) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @Nullable
     public Range<Long> getEstimatedCaptureLatencyRange(
-            String cameraId, Size size, int imageFormat) {
+            @NonNull String cameraId, @Nullable Size size, int imageFormat) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedPreviewOutputResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedCaptureOutputResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedPostviewResolutions(
-            Size captureSize) {
+            @NonNull Size captureSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public List<Size> getSupportedYuvAnalysisResolutions(
-            String cameraId) {
+    @Nullable
+    public List<Size> getSupportedYuvAnalysisResolutions(@NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public SessionProcessorImpl createSessionProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public List<CaptureRequest.Key> getAvailableCaptureRequestKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public List<CaptureResult.Key> getAvailableCaptureResultKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public boolean isCaptureProcessProgressAvailable() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
@@ -106,6 +115,7 @@ public class BokehAdvancedExtenderImpl implements AdvancedExtenderImpl {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public List<Pair<CameraCharacteristics.Key, Object>> getAvailableCharacteristicsKeyValues() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2OutputConfigImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2OutputConfigImpl.java
index fe0cddf..942f6f6 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2OutputConfigImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2OutputConfigImpl.java
@@ -16,16 +16,18 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.params.DynamicRangeProfiles;
 
+import android.annotation.Nullable;
+
 import java.util.List;
 
 /**
  * A config representing a {@link android.hardware.camera2.params.OutputConfiguration} where
  * Surface will be created by the information in this config.
+ *
+ * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public interface Camera2OutputConfigImpl {
     /**
      * Gets thd id of this output config. The id can be used to identify the stream in vendor
@@ -42,6 +44,7 @@ public interface Camera2OutputConfigImpl {
     /**
      * Gets the physical camera id. Returns null if not specified.
      */
+    @Nullable
     String getPhysicalCameraId();
 
     /**
@@ -57,5 +60,6 @@ public interface Camera2OutputConfigImpl {
      * If non-null, enable surface sharing and add the surface constructed by the return
      * Camera2OutputConfig.
      */
+    @Nullable
     List<Camera2OutputConfigImpl> getSurfaceSharingOutputConfigs();
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2OutputConfigImplBuilder.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2OutputConfigImplBuilder.java
index 541ade6..343e998 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2OutputConfigImplBuilder.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2OutputConfigImplBuilder.java
@@ -16,12 +16,14 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.params.DynamicRangeProfiles;
 import android.hardware.camera2.params.OutputConfiguration;
 import android.util.Size;
 import android.view.Surface;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 import java.util.ArrayList;
 import java.util.List;
 import java.util.concurrent.atomic.AtomicInteger;
@@ -29,16 +31,15 @@ import java.util.concurrent.atomic.AtomicInteger;
 /**
  * A builder implementation to help OEM build the {@link Camera2OutputConfigImpl} instance.
  */
-@SuppressLint("UnknownNullness")
 public class Camera2OutputConfigImplBuilder {
     static AtomicInteger sLastId = new AtomicInteger(0);
     private OutputConfigImplImpl mOutputConfig;
     private int mSurfaceGroupId = OutputConfiguration.SURFACE_GROUP_ID_NONE;
+    private int mOutputConfigId = -1;
     private String mPhysicalCameraId;
     private List<Camera2OutputConfigImpl> mSurfaceSharingConfigs;
     private long mDynamicRangeProfile = DynamicRangeProfiles.STANDARD;
-
-    private Camera2OutputConfigImplBuilder(OutputConfigImplImpl outputConfig) {
+    private Camera2OutputConfigImplBuilder(@NonNull OutputConfigImplImpl outputConfig) {
         mOutputConfig = outputConfig;
     }
 
@@ -50,8 +51,21 @@ public class Camera2OutputConfigImplBuilder {
      * Creates a {@link Camera2OutputConfigImpl} that represents a {@link android.media.ImageReader}
      * with the given parameters.
      */
+    @NonNull
     public static Camera2OutputConfigImplBuilder newImageReaderConfig(
-            Size size, int imageFormat, int maxImages, long usage) {
+            @NonNull Size size, int imageFormat, int maxImages) {
+        return new Camera2OutputConfigImplBuilder(
+                new ImageReaderOutputConfigImplImpl(size, imageFormat, maxImages));
+    }
+
+
+    /**
+     * Creates a {@link Camera2OutputConfigImpl} that represents a {@link android.media.ImageReader}
+     * with the given parameters.
+     */
+    @NonNull
+    public static Camera2OutputConfigImplBuilder newImageReaderConfig(
+            @NonNull Size size, int imageFormat, int maxImages, long usage) {
         return new Camera2OutputConfigImplBuilder(
                 new ImageReaderOutputConfigImplImpl(size, imageFormat, maxImages, usage));
     }
@@ -60,6 +74,7 @@ public class Camera2OutputConfigImplBuilder {
      * Creates a {@link Camera2OutputConfigImpl} that represents a MultiResolutionImageReader with
      * the given parameters.
      */
+    @NonNull
     public static Camera2OutputConfigImplBuilder newMultiResolutionImageReaderConfig(
             int imageFormat, int maxImages) {
         return new Camera2OutputConfigImplBuilder(
@@ -69,15 +84,17 @@ public class Camera2OutputConfigImplBuilder {
     /**
      * Creates a {@link Camera2OutputConfigImpl} that contains the Surface directly.
      */
-    public static Camera2OutputConfigImplBuilder newSurfaceConfig(Surface surface) {
+    @NonNull
+    public static Camera2OutputConfigImplBuilder newSurfaceConfig(@NonNull Surface surface) {
         return new Camera2OutputConfigImplBuilder(new SurfaceOutputConfigImplImpl(surface));
     }
 
     /**
      * Adds a {@link Camera2SessionConfigImpl} to be shared with current config.
      */
+    @NonNull
     public Camera2OutputConfigImplBuilder addSurfaceSharingOutputConfig(
-            Camera2OutputConfigImpl camera2OutputConfig) {
+            @NonNull Camera2OutputConfigImpl camera2OutputConfig) {
         if (mSurfaceSharingConfigs == null) {
             mSurfaceSharingConfigs = new ArrayList<>();
         }
@@ -89,32 +106,50 @@ public class Camera2OutputConfigImplBuilder {
     /**
      * Sets a physical camera id.
      */
-    public Camera2OutputConfigImplBuilder setPhysicalCameraId(String physicalCameraId) {
+    @NonNull
+    public Camera2OutputConfigImplBuilder setPhysicalCameraId(@Nullable String physicalCameraId) {
         mPhysicalCameraId = physicalCameraId;
         return this;
     }
 
     /**
-     * Set dynamic range profile.
+     * Sets surface group id.
      */
-    public Camera2OutputConfigImplBuilder setDynamicRangeProfile(long dynamicRangeProfile) {
-        mDynamicRangeProfile = dynamicRangeProfile;
+    @NonNull
+    public Camera2OutputConfigImplBuilder setSurfaceGroupId(int surfaceGroupId) {
+        mSurfaceGroupId = surfaceGroupId;
         return this;
     }
 
     /**
-     * Sets surface group id.
+     * Sets Output Config id (Optional: Atomic Integer will be used if this function is not called)
      */
-    public Camera2OutputConfigImplBuilder setSurfaceGroupId(int surfaceGroupId) {
-        mSurfaceGroupId = surfaceGroupId;
+    @NonNull
+    public Camera2OutputConfigImplBuilder setOutputConfigId(int outputConfigId) {
+        mOutputConfigId = outputConfigId;
+        return this;
+    }
+
+    /**
+     * Set dynamic range profile.
+     */
+    @NonNull
+    public Camera2OutputConfigImplBuilder setDynamicRangeProfile(long dynamicRangeProfile) {
+        mDynamicRangeProfile = dynamicRangeProfile;
         return this;
     }
 
     /**
      * Build a {@link Camera2OutputConfigImpl} instance.
      */
+    @NonNull
     public Camera2OutputConfigImpl build() {
-        mOutputConfig.setId(getNextId());
+        // Sets an output config id otherwise an output config id will be generated
+        if (mOutputConfigId == -1) {
+            mOutputConfig.setId(getNextId());
+        } else {
+            mOutputConfig.setId(mOutputConfigId);
+        }
         mOutputConfig.setPhysicalCameraId(mPhysicalCameraId);
         mOutputConfig.setSurfaceGroup(mSurfaceGroupId);
         mOutputConfig.setSurfaceSharingConfigs(mSurfaceSharingConfigs);
@@ -148,6 +183,7 @@ public class Camera2OutputConfigImplBuilder {
         }
 
         @Override
+        @Nullable
         public String getPhysicalCameraId() {
             return mPhysicalCameraId;
         }
@@ -158,6 +194,7 @@ public class Camera2OutputConfigImplBuilder {
         }
 
         @Override
+        @Nullable
         public List<Camera2OutputConfigImpl> getSurfaceSharingOutputConfigs() {
             return mSurfaceSharingConfigs;
         }
@@ -170,7 +207,7 @@ public class Camera2OutputConfigImplBuilder {
             mSurfaceGroup = surfaceGroup;
         }
 
-        public void setPhysicalCameraId(String physicalCameraId) {
+        public void setPhysicalCameraId(@Nullable String physicalCameraId) {
             mPhysicalCameraId = physicalCameraId;
         }
 
@@ -179,20 +216,24 @@ public class Camera2OutputConfigImplBuilder {
         }
 
         public void setSurfaceSharingConfigs(
-                List<Camera2OutputConfigImpl> surfaceSharingConfigs) {
+                @Nullable List<Camera2OutputConfigImpl> surfaceSharingConfigs) {
+            if (surfaceSharingConfigs != null) {
+                surfaceSharingConfigs = new ArrayList<>(surfaceSharingConfigs);
+            }
             mSurfaceSharingConfigs = surfaceSharingConfigs;
         }
     }
 
     private static class SurfaceOutputConfigImplImpl extends OutputConfigImplImpl
             implements SurfaceOutputConfigImpl {
-        private Surface mSurface;
+        private final Surface mSurface;
 
-        SurfaceOutputConfigImplImpl(Surface surface) {
+        SurfaceOutputConfigImplImpl(@NonNull Surface surface) {
             mSurface = surface;
         }
 
         @Override
+        @NonNull
         public Surface getSurface() {
             return mSurface;
         }
@@ -200,12 +241,17 @@ public class Camera2OutputConfigImplBuilder {
 
     private static class ImageReaderOutputConfigImplImpl extends OutputConfigImplImpl
             implements ImageReaderOutputConfigImpl {
-        private Size mSize;
-        private int mImageFormat;
-        private int mMaxImages;
-        private long mUsage;
+        private static final long USAGE_UNSPECIFIED = -1;
+        private final Size mSize;
+        private final int mImageFormat;
+        private final int mMaxImages;
+        private final long mUsage;
+
+        ImageReaderOutputConfigImplImpl(@NonNull Size size, int imageFormat, int maxImages) {
+            this(size, imageFormat, maxImages, USAGE_UNSPECIFIED);
+        }
 
-        ImageReaderOutputConfigImplImpl(Size size, int imageFormat, int maxImages,
+        ImageReaderOutputConfigImplImpl(@NonNull Size size, int imageFormat, int maxImages,
                 long usage) {
             mSize = size;
             mImageFormat = imageFormat;
@@ -214,6 +260,7 @@ public class Camera2OutputConfigImplBuilder {
         }
 
         @Override
+        @NonNull
         public Size getSize() {
             return mSize;
         }
@@ -230,14 +277,17 @@ public class Camera2OutputConfigImplBuilder {
 
         @Override
         public long getUsage() {
+            if (mUsage == USAGE_UNSPECIFIED) {
+                return ImageReaderOutputConfigImpl.super.getUsage();
+            }
             return mUsage;
         }
     }
 
     private static class MultiResolutionImageReaderOutputConfigImplImpl extends OutputConfigImplImpl
             implements MultiResolutionImageReaderOutputConfigImpl {
-        private int mImageFormat;
-        private int mMaxImages;
+        private final int mImageFormat;
+        private final int mMaxImages;
 
         MultiResolutionImageReaderOutputConfigImplImpl(int imageFormat, int maxImages) {
             mImageFormat = imageFormat;
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2SessionConfigImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2SessionConfigImpl.java
index 5d4444f..474bb29 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2SessionConfigImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2SessionConfigImpl.java
@@ -16,27 +16,32 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.params.ColorSpaceProfiles;
+import android.hardware.camera2.params.SessionConfiguration;
+
+import android.annotation.NonNull;
 
 import java.util.List;
 import java.util.Map;
 
 /**
  * A config representing a {@link android.hardware.camera2.params.SessionConfiguration}
+ *
+ * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public interface Camera2SessionConfigImpl {
     /**
      * Returns all the {@link Camera2OutputConfigImpl}s that will be used to create
      * {@link android.hardware.camera2.params.OutputConfiguration}.
      */
+    @NonNull
     List<Camera2OutputConfigImpl> getOutputConfigs();
 
     /**
      * Gets all the parameters to create the session parameters with.
      */
+    @NonNull
     Map<CaptureRequest.Key<?>, Object> getSessionParameters();
 
     /**
@@ -50,18 +55,21 @@ public interface Camera2SessionConfigImpl {
      * Retrieves the session type to be used when initializing the
      * {@link android.hardware.camera2.CameraCaptureSession}.
      *
-     * @since 1.4
      * @return Camera capture session type. Regular and vendor specific types are supported but
      * not high speed values. The extension can return -1 in which case the camera capture session
      * will be configured to use the default regular type.
+     *
+     * @since 1.4
      */
-    int getSessionType();
+    default int getSessionType() {
+        return SessionConfiguration.SESSION_REGULAR;
+    }
 
     /**
      * Gets the color space.
      *
      * @since 1.5
-     * @return {@link android.graphics#ColorSpace.Named} set for session configuration
+     * @return {@link android.graphics.ColorSpace.Named} set for session configuration
      */
     default int getColorSpace() {
         return ColorSpaceProfiles.UNSPECIFIED;
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2SessionConfigImplBuilder.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2SessionConfigImplBuilder.java
index e745624..9fa97bf 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2SessionConfigImplBuilder.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/Camera2SessionConfigImplBuilder.java
@@ -16,13 +16,13 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-
-import android.annotation.SuppressLint;
 import android.hardware.camera2.CameraDevice;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.params.ColorSpaceProfiles;
 import android.hardware.camera2.params.SessionConfiguration;
 
+import android.annotation.NonNull;
+
 import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.List;
@@ -31,7 +31,6 @@ import java.util.Map;
 /**
  * A builder implementation to help OEM build the {@link Camera2SessionConfigImpl} instance.
  */
-@SuppressLint("UnknownNullness")
 public class Camera2SessionConfigImplBuilder {
     private int mSessionTemplateId = CameraDevice.TEMPLATE_PREVIEW;
     private int mColorSpace = ColorSpaceProfiles.UNSPECIFIED;
@@ -45,8 +44,9 @@ public class Camera2SessionConfigImplBuilder {
     /**
      * Adds a output config.
      */
+    @NonNull
     public Camera2SessionConfigImplBuilder addOutputConfig(
-            Camera2OutputConfigImpl outputConfig) {
+            @NonNull Camera2OutputConfigImpl outputConfig) {
         mCamera2OutputConfigs.add(outputConfig);
         return this;
     }
@@ -54,8 +54,9 @@ public class Camera2SessionConfigImplBuilder {
     /**
      * Sets session parameters.
      */
+    @NonNull
     public <T> Camera2SessionConfigImplBuilder addSessionParameter(
-            CaptureRequest.Key<T> key, T value) {
+            @NonNull CaptureRequest.Key<T> key, @NonNull T value) {
         mSessionParameters.put(key, value);
         return this;
     }
@@ -63,14 +64,25 @@ public class Camera2SessionConfigImplBuilder {
     /**
      * Sets the template id for session parameters request.
      */
+    @NonNull
     public Camera2SessionConfigImplBuilder setSessionTemplateId(int templateId) {
         mSessionTemplateId = templateId;
         return this;
     }
 
+    /**
+     * Sets the session type for the session.
+     */
+    @NonNull
+    public Camera2SessionConfigImplBuilder setSessionType(int sessionType) {
+        mSessionType = sessionType;
+        return this;
+    }
+
     /**
      * Sets the color space.
      */
+    @NonNull
     public Camera2SessionConfigImplBuilder setColorSpace(int colorSpace) {
         mColorSpace = colorSpace;
         return this;
@@ -93,6 +105,7 @@ public class Camera2SessionConfigImplBuilder {
     /**
      * Gets the session parameters.
      */
+    @NonNull
     public Map<CaptureRequest.Key<?>, Object> getSessionParameters() {
         return mSessionParameters;
     }
@@ -100,6 +113,7 @@ public class Camera2SessionConfigImplBuilder {
     /**
      * Gets all the output configs.
      */
+    @NonNull
     public List<Camera2OutputConfigImpl> getCamera2OutputConfigs() {
         return mCamera2OutputConfigs;
     }
@@ -114,32 +128,35 @@ public class Camera2SessionConfigImplBuilder {
     /**
      * Builds a {@link Camera2SessionConfigImpl} instance.
      */
+    @NonNull
     public Camera2SessionConfigImpl build() {
         return new Camera2SessionConfigImplImpl(this);
     }
 
     private static class Camera2SessionConfigImplImpl implements
             Camera2SessionConfigImpl {
-        int mSessionTemplateId;
-        int mSessionType;
-        int mColorSpace = ColorSpaceProfiles.UNSPECIFIED;
-        Map<CaptureRequest.Key<?>, Object> mSessionParameters;
-        List<Camera2OutputConfigImpl> mCamera2OutputConfigs;
+        private final int mSessionTemplateId;
+        private final int mSessionType;
+        private final int mColorSpace;
+        private final Map<CaptureRequest.Key<?>, Object> mSessionParameters;
+        private final List<Camera2OutputConfigImpl> mCamera2OutputConfigs;
 
-        Camera2SessionConfigImplImpl(Camera2SessionConfigImplBuilder builder) {
+        Camera2SessionConfigImplImpl(@NonNull Camera2SessionConfigImplBuilder builder) {
             mSessionTemplateId = builder.getSessionTemplateId();
-            mSessionParameters = builder.getSessionParameters();
+            mSessionParameters = new HashMap<>(builder.getSessionParameters());
             mColorSpace = builder.getColorSpace();
-            mCamera2OutputConfigs = builder.getCamera2OutputConfigs();
+            mCamera2OutputConfigs = new ArrayList<>(builder.getCamera2OutputConfigs());
             mSessionType = builder.getSessionType();
         }
 
         @Override
+        @NonNull
         public List<Camera2OutputConfigImpl> getOutputConfigs() {
             return mCamera2OutputConfigs;
         }
 
         @Override
+        @NonNull
         public Map<CaptureRequest.Key<?>, Object> getSessionParameters() {
             return mSessionParameters;
         }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/HdrAdvancedExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/HdrAdvancedExtenderImpl.java
index 7d87cc6..105f3a8 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/HdrAdvancedExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/HdrAdvancedExtenderImpl.java
@@ -16,7 +16,6 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.CameraCharacteristics;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.CaptureResult;
@@ -24,6 +23,9 @@ import android.util.Pair;
 import android.util.Range;
 import android.util.Size;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 import java.util.List;
 import java.util.Map;
 
@@ -34,65 +36,71 @@ import java.util.Map;
  *
  * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public class HdrAdvancedExtenderImpl implements AdvancedExtenderImpl {
     public HdrAdvancedExtenderImpl() {
     }
 
     @Override
-    public boolean isExtensionAvailable(String cameraId,
-            Map<String, CameraCharacteristics> characteristicsMap) {
+    public boolean isExtensionAvailable(@NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> characteristicsMap) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public void init(String cameraId,
-            Map<String, CameraCharacteristics> characteristicsMap) {
+    public void init(@NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> characteristicsMap) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @Nullable
     public Range<Long> getEstimatedCaptureLatencyRange(
-            String cameraId, Size size, int imageFormat) {
+            @NonNull String cameraId, @Nullable Size size, int imageFormat) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedPreviewOutputResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedCaptureOutputResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedPostviewResolutions(
-            Size captureSize) {
+            @NonNull Size captureSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public List<Size> getSupportedYuvAnalysisResolutions(
-            String cameraId) {
+    @Nullable
+    public List<Size> getSupportedYuvAnalysisResolutions(@NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public SessionProcessorImpl createSessionProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public List<CaptureRequest.Key> getAvailableCaptureRequestKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public List<CaptureResult.Key> getAvailableCaptureResultKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
@@ -107,6 +115,7 @@ public class HdrAdvancedExtenderImpl implements AdvancedExtenderImpl {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public List<Pair<CameraCharacteristics.Key, Object>> getAvailableCharacteristicsKeyValues() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/ImageProcessorImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/ImageProcessorImpl.java
index 037e947..6982512 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/ImageProcessorImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/ImageProcessorImpl.java
@@ -16,14 +16,16 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 
 /**
  * A interface to receive and process the upcoming next available Image.
  *
  * <p>Implemented by OEM.
+ *
+ * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public interface ImageProcessorImpl {
     /**
      * The reference count will not be decremented when this method returns. Extensions must
@@ -47,7 +49,7 @@ public interface ImageProcessorImpl {
     void onNextImageAvailable(
             int outputConfigId,
             long timestampNs,
-            ImageReferenceImpl imageReference,
-            String physicalCameraId
-            );
+            @NonNull ImageReferenceImpl imageReference,
+            @Nullable String physicalCameraId
+    );
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/ImageReaderOutputConfigImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/ImageReaderOutputConfigImpl.java
index 7c3b48e..495de98 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/ImageReaderOutputConfigImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/ImageReaderOutputConfigImpl.java
@@ -16,17 +16,22 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
+import android.graphics.ImageFormat;
+import android.hardware.HardwareBuffer;
 import android.util.Size;
 
+import android.annotation.NonNull;
+
 /**
  * Surface will be created by constructing a ImageReader.
+ *
+ * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public interface ImageReaderOutputConfigImpl extends Camera2OutputConfigImpl {
     /**
      * Returns the size of the surface.
      */
+    @NonNull
     Size getSize();
 
     /**
@@ -41,6 +46,11 @@ public interface ImageReaderOutputConfigImpl extends Camera2OutputConfigImpl {
 
     /**
      * Gets the surface usage bits.
+     * @since 1.5
      */
-    long getUsage();
+    default long getUsage() {
+        // Return the same default usage as in
+        // ImageReader.newInstance(width, height, format, maxImages)
+        return getImageFormat() == ImageFormat.PRIVATE ? 0 : HardwareBuffer.USAGE_CPU_READ_OFTEN;
+    }
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/ImageReferenceImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/ImageReferenceImpl.java
index 95f2c3b..f2ac413 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/ImageReferenceImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/ImageReferenceImpl.java
@@ -16,17 +16,19 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.media.Image;
 
+import android.annotation.Nullable;
+
 /**
  * A Image reference container that enables the Image sharing between Camera2/CameraX and OEM
  * using reference counting. The wrapped Image will be closed once the reference count
  * reaches 0.
  *
  * <p>Implemented by Camera2/CameraX.
+ *
+ * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public interface ImageReferenceImpl {
 
     /**
@@ -46,5 +48,6 @@ public interface ImageReferenceImpl {
      * Return the Android image. This object MUST not be closed directly.
      * Returns null when the reference count is zero.
      */
+    @Nullable
     Image get();
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/MultiResolutionImageReaderOutputConfigImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/MultiResolutionImageReaderOutputConfigImpl.java
index c3ad61b..ccc229d 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/MultiResolutionImageReaderOutputConfigImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/MultiResolutionImageReaderOutputConfigImpl.java
@@ -18,6 +18,8 @@ package androidx.camera.extensions.impl.advanced;
 
 /**
  * Surface will be created by constructing a MultiResolutionImageReader.
+ *
+ * @since 1.2
  */
 public interface MultiResolutionImageReaderOutputConfigImpl extends Camera2OutputConfigImpl {
     /**
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/NightAdvancedExtenderImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/NightAdvancedExtenderImpl.java
index 961d669..769f83b 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/NightAdvancedExtenderImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/NightAdvancedExtenderImpl.java
@@ -16,7 +16,6 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.CameraCharacteristics;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.CaptureResult;
@@ -24,6 +23,9 @@ import android.util.Pair;
 import android.util.Range;
 import android.util.Size;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 import java.util.List;
 import java.util.Map;
 
@@ -34,64 +36,71 @@ import java.util.Map;
  *
  * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public class NightAdvancedExtenderImpl implements AdvancedExtenderImpl {
     public NightAdvancedExtenderImpl() {
     }
 
     @Override
-    public boolean isExtensionAvailable(String cameraId,
-            Map<String, CameraCharacteristics> characteristicsMap) {
+    public boolean isExtensionAvailable(@NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> characteristicsMap) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
-    public void init(String cameraId,
-            Map<String, CameraCharacteristics> characteristicsMap) {
+    public void init(@NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> characteristicsMap) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @Nullable
     public Range<Long> getEstimatedCaptureLatencyRange(
-            String cameraId, Size size, int imageFormat) {
+            @NonNull String cameraId, @Nullable Size size, int imageFormat) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedPreviewOutputResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedCaptureOutputResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public Map<Integer, List<Size>> getSupportedPostviewResolutions(
-            Size captureSize) {
+            @NonNull Size captureSize) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @Nullable
     public List<Size> getSupportedYuvAnalysisResolutions(
-            String cameraId) {
+            @NonNull String cameraId) {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public SessionProcessorImpl createSessionProcessor() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public List<CaptureRequest.Key> getAvailableCaptureRequestKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
     @Override
+    @NonNull
     public List<CaptureResult.Key> getAvailableCaptureResultKeys() {
         throw new RuntimeException("Stub, replace with implementation.");
     }
@@ -106,6 +115,7 @@ public class NightAdvancedExtenderImpl implements AdvancedExtenderImpl {
         throw new RuntimeException("Stub, replace with implementation.");
     }
 
+    @NonNull
     @Override
     public List<Pair<CameraCharacteristics.Key, Object>> getAvailableCharacteristicsKeyValues() {
         throw new RuntimeException("Stub, replace with implementation.");
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/OutputSurfaceConfigurationImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/OutputSurfaceConfigurationImpl.java
index 217887b..5b1eb4c 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/OutputSurfaceConfigurationImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/OutputSurfaceConfigurationImpl.java
@@ -16,25 +16,45 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.params.ColorSpaceProfiles;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 /**
  * For specifying the output surface configurations for the extension.
  *
  * @since 1.4
  */
-@SuppressLint("UnknownNullness")
 public interface OutputSurfaceConfigurationImpl {
-    public OutputSurfaceImpl getPreviewOutputSurface();
+    /**
+     * gets the preview {@link OutputSurfaceImpl}, which may contain a <code>null</code> surface
+     * if the app doesn't specify the preview output surface.
+     */
+    @NonNull
+    OutputSurfaceImpl getPreviewOutputSurface();
 
-    public OutputSurfaceImpl getImageCaptureOutputSurface();
+    /**
+     * gets the still capture {@link OutputSurfaceImpl} which may contain a <code>null</code>
+     * surface if the app doesn't specify the still capture output surface.
+     */
+    @NonNull
+    OutputSurfaceImpl getImageCaptureOutputSurface();
 
-    public OutputSurfaceImpl getImageAnalysisOutputSurface();
+    /**
+     * gets the image analysis {@link OutputSurfaceImpl}.
+     */
+    @Nullable
+    OutputSurfaceImpl getImageAnalysisOutputSurface();
 
-    public OutputSurfaceImpl getPostviewOutputSurface();
+    /**
+     * gets the postview {@link OutputSurfaceImpl} which may contain a <code>null</code> surface
+     * if the app doesn't specify the postview output surface.
+     */
+    @Nullable
+    OutputSurfaceImpl getPostviewOutputSurface();
 
-    /*
+    /**
      * Gets the color space.
      *
      * @since 1.5
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/OutputSurfaceImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/OutputSurfaceImpl.java
index 72bc4ab..fec31ee 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/OutputSurfaceImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/OutputSurfaceImpl.java
@@ -16,24 +16,46 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.params.DynamicRangeProfiles;
 import android.util.Size;
 import android.view.Surface;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 /**
  * For specifying output surface of the extension.
+ *
+ * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public interface OutputSurfaceImpl {
     /**
-     * Gets the surface.
+     * This indicates the usage is not specified which could happen in the apps that use older
+     * version of CameraX extensions where getUsage() was not added yet.
+     *
+     * <p>We can't use 0 as 0 means GRALLOC_USAGE_SW_READ_NEVER.
+     */
+    long USAGE_UNSPECIFIED = -1;
+
+
+    /**
+     * This indicates the dataSpace is not specified which could happen in the apps that use older
+     * version of CameraX extensions where getDataspace() was not added yet.
+     *
      */
+    int DATASPACE_UNSPECIFIED = -1;
+
+    /**
+     * Gets the surface. It returns null if output surface is not specified.
+     */
+    @Nullable
     Surface getSurface();
 
+
     /**
      * Gets the size.
      */
+    @NonNull
     Size getSize();
 
     /**
@@ -42,14 +64,22 @@ public interface OutputSurfaceImpl {
     int getImageFormat();
 
     /**
-     * Gets the dataspace.
+     * Gets the dataspace. It returns {#link #DATASPACE_UNSPECIFIED} if not specified.
+     *
+     * @since 1.5
      */
-    int getDataspace();
+    default int getDataspace() {
+        return DATASPACE_UNSPECIFIED;
+    }
 
     /**
-    * Gets the surface usage bits.
-    */
-    long getUsage();
+     * Gets the surface usage bits. It returns {@link #USAGE_UNSPECIFIED} if not specified.
+     *
+     * @since 1.5
+     */
+    default long getUsage() {
+        return USAGE_UNSPECIFIED;
+    }
 
     /**
      * Gets the dynamic range profile.
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/RequestProcessorImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/RequestProcessorImpl.java
index 5185333..79a65e7 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/RequestProcessorImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/RequestProcessorImpl.java
@@ -16,45 +16,47 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.hardware.camera2.CaptureFailure;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.CaptureResult;
 import android.hardware.camera2.TotalCaptureResult;
 
+import android.annotation.NonNull;
+
 import java.util.List;
 import java.util.Map;
 
 /**
  * An Interface to execute Camera2 capture requests.
+ *
+ * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public interface RequestProcessorImpl {
     /**
      * Sets a {@link ImageProcessorImpl} to receive {@link ImageReferenceImpl} to process.
      */
-    void setImageProcessor(int outputconfigId, ImageProcessorImpl imageProcessor);
+    void setImageProcessor(int outputconfigId, @NonNull ImageProcessorImpl imageProcessor);
 
     /**
      * Submits a request.
      * @return the id of the capture sequence or -1 in case the processor encounters a fatal error
      *         or receives an invalid argument.
      */
-    int submit(Request request, Callback callback);
+    int submit(@NonNull Request request, @NonNull Callback callback);
 
     /**
      * Submits a list of requests.
      * @return the id of the capture sequence or -1 in case the processor encounters a fatal error
      *         or receives an invalid argument.
      */
-    int submit(List<Request> requests, Callback callback);
+    int submit(@NonNull List<Request> requests, @NonNull Callback callback);
 
     /**
      * Set repeating requests.
      * @return the id of the capture sequence or -1 in case the processor encounters a fatal error
      *         or receives an invalid argument.
      */
-    int setRepeating(Request request, Callback callback);
+    int setRepeating(@NonNull Request request, @NonNull Callback callback);
 
 
     /**
@@ -76,16 +78,19 @@ public interface RequestProcessorImpl {
          * Gets the target ids of {@link Camera2OutputConfigImpl} which identifies corresponding
          * Surface to be the targeted for the request.
          */
+        @NonNull
         List<Integer> getTargetOutputConfigIds();
 
         /**
          * Gets all the parameters.
          */
+        @NonNull
         Map<CaptureRequest.Key<?>, Object> getParameters();
 
         /**
          * Gets the template id.
          */
+        @NonNull
         Integer getTemplateId();
     }
 
@@ -94,24 +99,24 @@ public interface RequestProcessorImpl {
      */
     interface Callback {
         void onCaptureStarted(
-                Request request,
+                @NonNull Request request,
                 long frameNumber,
                 long timestamp);
 
         void onCaptureProgressed(
-                Request request,
-                CaptureResult partialResult);
+                @NonNull Request request,
+                @NonNull CaptureResult partialResult);
 
         void onCaptureCompleted(
-                Request request,
-                TotalCaptureResult totalCaptureResult);
+                @NonNull Request request,
+                @NonNull TotalCaptureResult totalCaptureResult);
 
         void onCaptureFailed(
-                Request request,
-                CaptureFailure captureFailure);
+                @NonNull Request request,
+                @NonNull CaptureFailure captureFailure);
 
         void onCaptureBufferLost(
-                Request request,
+                @NonNull Request request,
                 long frameNumber,
                 int outputStreamId);
 
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/SessionProcessorImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/SessionProcessorImpl.java
index 57fffd0..351022f 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/SessionProcessorImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/SessionProcessorImpl.java
@@ -16,15 +16,16 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.content.Context;
 import android.hardware.camera2.CameraCharacteristics;
-import android.hardware.camera2.CaptureFailure;
 import android.hardware.camera2.CaptureRequest;
 import android.hardware.camera2.CaptureResult;
 import android.util.Pair;
 import android.view.Surface;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
 import java.util.Map;
 
 /**
@@ -58,8 +59,9 @@ import java.util.Map;
  *
  * (6) {@link #deInitSession}: called when CameraCaptureSession is closed.
  * </pre>
+ *
+ * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public interface SessionProcessorImpl {
     /**
      * Initializes the session for the extension. This is where the OEMs allocate resources for
@@ -105,11 +107,12 @@ public interface SessionProcessorImpl {
      *
      * @since 1.4
      */
+    @NonNull
     Camera2SessionConfigImpl initSession(
-            String cameraId,
-            Map<String, CameraCharacteristics> cameraCharacteristicsMap,
-            Context context,
-            OutputSurfaceConfigurationImpl surfaceConfigs);
+            @NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> cameraCharacteristicsMap,
+            @NonNull Context context,
+            @NonNull OutputSurfaceConfigurationImpl surfaceConfigs);
 
     /**
      * Initializes the session for the extension. This is where the OEMs allocate resources for
@@ -156,13 +159,14 @@ public interface SessionProcessorImpl {
      * supported or mandatory stream combination BUT OEM must ensure this list will always
      * produce a valid camera capture session.
      */
+    @NonNull
     Camera2SessionConfigImpl initSession(
-            String cameraId,
-            Map<String, CameraCharacteristics> cameraCharacteristicsMap,
-            Context context,
-            OutputSurfaceImpl previewSurfaceConfig,
-            OutputSurfaceImpl imageCaptureSurfaceConfig,
-            OutputSurfaceImpl imageAnalysisSurfaceConfig);
+            @NonNull String cameraId,
+            @NonNull Map<String, CameraCharacteristics> cameraCharacteristicsMap,
+            @NonNull Context context,
+            @NonNull OutputSurfaceImpl previewSurfaceConfig,
+            @NonNull OutputSurfaceImpl imageCaptureSurfaceConfig,
+            @Nullable OutputSurfaceImpl imageAnalysisSurfaceConfig);
 
     /**
      * Notify to de-initialize the extension. This callback will be invoked after
@@ -175,15 +179,19 @@ public interface SessionProcessorImpl {
     /**
      * CameraX / Camera2 would call these API’s to pass parameters from the app to the OEM. It’s
      * expected that the OEM would (eventually) update the repeating request if the keys are
-     * supported. Setting a value to null explicitly un-sets the value.
+     * supported. These parameters should be set by the OEM on all capture requests sent during
+     * {@link #startRepeating(CaptureCallback)},
+     * {@link #startCapture(CaptureCallback)} and {@link #startTrigger(Map, CaptureCallback)}.
      */
-    void setParameters(Map<CaptureRequest.Key<?>, Object> parameters);
+    void setParameters(@NonNull Map<CaptureRequest.Key<?>, Object> parameters);
 
     /**
      * CameraX / Camera2 will call this interface in response to client requests involving
      * the output preview surface. Typical examples include requests that include AF/AE triggers.
      * Extensions can disregard any capture request keys that were not advertised in
-     * {@link AdvancedExtenderImpl#getAvailableCaptureRequestKeys}.
+     * {@link AdvancedExtenderImpl#getAvailableCaptureRequestKeys}. In addition to the
+     * Key/value map in the {@code trigger} parameter, the capture request must also
+     * include the parameters set in {@link #setParameters(Map)}.
      *
      * @param triggers Capture request key value map.
      * @param callback a callback to report the status.
@@ -193,7 +201,8 @@ public interface SessionProcessorImpl {
      *
      * @since 1.3
      */
-    int startTrigger(Map<CaptureRequest.Key<?>, Object> triggers, CaptureCallback callback);
+    int startTrigger(@NonNull Map<CaptureRequest.Key<?>, Object> triggers,
+            @NonNull CaptureCallback callback);
 
     /**
      * This will be invoked once after the {@link android.hardware.camera2.CameraCaptureSession}
@@ -201,7 +210,7 @@ public interface SessionProcessorImpl {
      * requests or set repeating requests. This ExtensionRequestProcessor will be valid to use
      * until onCaptureSessionEnd is called.
      */
-    void onCaptureSessionStart(RequestProcessorImpl requestProcessor);
+    void onCaptureSessionStart(@NonNull RequestProcessorImpl requestProcessor);
 
     /**
      * This will be invoked before the {@link android.hardware.camera2.CameraCaptureSession} is
@@ -213,12 +222,13 @@ public interface SessionProcessorImpl {
     /**
      * Starts the repeating request after CameraCaptureSession is called. Vendor should start the
      * repeating request by {@link RequestProcessorImpl}. Vendor can also update the
-     * repeating request when needed later.
+     * repeating request when needed later. The repeating request is expected to contain the
+     * parameters set in {@link #setParameters(Map)}.
      *
      * @param callback a callback to report the status.
      * @return the id of the capture sequence.
      */
-    int startRepeating(CaptureCallback callback);
+    int startRepeating(@NonNull CaptureCallback callback);
 
     /**
      * Stop the repeating request. To prevent OEM from not calling stopRepeating, CameraX will
@@ -233,7 +243,9 @@ public interface SessionProcessorImpl {
      *
      * When the capture is completed, {@link CaptureCallback#onCaptureSequenceCompleted}
      * is called and {@code OnImageAvailableListener#onImageAvailable}
-     * will also be called on the ImageReader that creates the image capture output surface.
+     * will also be called on the ImageReader that creates the image capture output surface. All
+     * the capture requests are expected to contain the parameters set in
+     * {@link #setParameters(Map)}.
      *
      * <p>Only one capture can perform at a time. Starting a capture when another capture is running
      * will cause onCaptureFailed to be called immediately.
@@ -241,7 +253,7 @@ public interface SessionProcessorImpl {
      * @param callback a callback to report the status.
      * @return the id of the capture sequence.
      */
-    int startCapture(CaptureCallback callback);
+    int startCapture(@NonNull CaptureCallback callback);
 
     /**
      * Start a multi-frame capture with a postview. {@link #startCapture(CaptureCallback)}
@@ -261,7 +273,7 @@ public interface SessionProcessorImpl {
      * @return the id of the capture sequence.
      * @since 1.4
      */
-    int startCaptureWithPostview(CaptureCallback callback);
+    int startCaptureWithPostview(@NonNull CaptureCallback callback);
 
     /**
      * Abort all capture tasks.
@@ -289,6 +301,7 @@ public interface SessionProcessorImpl {
      * null pair.
      * @since 1.4
      */
+    @Nullable
     Pair<Long, Long> getRealtimeCaptureLatency();
 
     /**
@@ -373,9 +386,10 @@ public interface SessionProcessorImpl {
          *                             as part of this callback. Both Camera2 and CameraX guarantee
          *                             that those two settings and results are always supported and
          *                             applied by the corresponding framework.
+         * @since 1.3
          */
-        void onCaptureCompleted(long timestamp, int captureSequenceId,
-                Map<CaptureResult.Key, Object> result);
+        default void onCaptureCompleted(long timestamp, int captureSequenceId,
+                @NonNull Map<CaptureResult.Key, Object> result) {}
 
         /**
          * Capture progress callback that needs to be called when the process capture is
@@ -390,7 +404,7 @@ public interface SessionProcessorImpl {
          * @param progress             Value between 0 and 100.
          * @since 1.4
          */
-        void onCaptureProcessProgressed(int progress);
+        default void onCaptureProcessProgressed(int progress) {}
 
         /**
          * This method is called instead of
@@ -405,6 +419,6 @@ public interface SessionProcessorImpl {
          * @param reason            The capture failure reason @see CaptureFailure#FailureReason
          * @since 1.5
          */
-        void onCaptureFailed(int captureSequenceId, int reason);
+        default void onCaptureFailed(int captureSequenceId, int reason) {}
     }
 }
diff --git a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/SurfaceOutputConfigImpl.java b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/SurfaceOutputConfigImpl.java
index 7b8d83c..b4567e7 100644
--- a/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/SurfaceOutputConfigImpl.java
+++ b/camera2/extensions/stub/src/main/java/androidx/camera/extensions/impl/advanced/SurfaceOutputConfigImpl.java
@@ -16,16 +16,19 @@
 
 package androidx.camera.extensions.impl.advanced;
 
-import android.annotation.SuppressLint;
 import android.view.Surface;
 
+import android.annotation.NonNull;
+
 /**
  * Use Surface directly to create the OutputConfiguration.
+ *
+ * @since 1.2
  */
-@SuppressLint("UnknownNullness")
 public interface SurfaceOutputConfigImpl extends Camera2OutputConfigImpl {
     /**
      * Get the {@link Surface}. It'll return valid surface only when type is TYPE_SURFACE.
      */
+    @NonNull
     Surface getSurface();
 }
```

