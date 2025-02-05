```diff
diff --git a/core/java/android/app/ResourcesManager.java b/core/java/android/app/ResourcesManager.java
index 84a4eb4acddc..9d7a165ce72f 100644
--- a/core/java/android/app/ResourcesManager.java
+++ b/core/java/android/app/ResourcesManager.java
@@ -174,22 +174,58 @@ public class ResourcesManager {
     }
 
     /**
-     * Apply the registered library paths to the passed impl object
-     * @return the hash code for the current version of the registered paths
+     * Apply the registered library paths to the passed AssetManager. If may create a new
+     * AssetManager if any changes are needed and it isn't allowed to reuse the old one.
+     *
+     * @return new AssetManager and the hash code for the current version of the registered paths
      */
-    public int updateResourceImplWithRegisteredLibs(@NonNull ResourcesImpl impl) {
+    public @NonNull Pair<AssetManager, Integer> updateResourceImplAssetsWithRegisteredLibs(
+            @NonNull AssetManager assets, boolean reuseAssets) {
         if (!Flags.registerResourcePaths()) {
-            return 0;
+            return new Pair<>(assets, 0);
         }
 
-        final var collector = new PathCollector(null);
-        final int size = mSharedLibAssetsMap.size();
-        for (int i = 0; i < size; i++) {
-            final var libraryKey = mSharedLibAssetsMap.valueAt(i).getResourcesKey();
-            collector.appendKey(libraryKey);
+        final int size;
+        final PathCollector collector;
+
+        synchronized (mLock) {
+            size = mSharedLibAssetsMap.size();
+            if (assets == AssetManager.getSystem()) {
+                return new Pair<>(assets, size);
+            }
+            collector = new PathCollector(resourcesKeyFromAssets(assets));
+            for (int i = 0; i < size; i++) {
+                final var libraryKey = mSharedLibAssetsMap.valueAt(i).getResourcesKey();
+                collector.appendKey(libraryKey);
+            }
         }
-        impl.getAssets().addPresetApkKeys(extractApkKeys(collector.collectedKey()));
-        return size;
+        if (collector.isSameAsOriginal()) {
+            return new Pair<>(assets, size);
+        }
+        if (reuseAssets) {
+            assets.addPresetApkKeys(extractApkKeys(collector.collectedKey()));
+            return new Pair<>(assets, size);
+        }
+        final var newAssetsBuilder = new AssetManager.Builder().setNoInit();
+        for (final var asset : assets.getApkAssets()) {
+            // Skip everything that's either default, or will get added by the collector (builder
+            // doesn't check for duplicates at all).
+            if (asset.isSystem() || asset.isForLoader() || asset.isOverlay()
+                    || asset.isSharedLib()) {
+                continue;
+            }
+            newAssetsBuilder.addApkAssets(asset);
+        }
+        for (final var key : extractApkKeys(collector.collectedKey())) {
+            try {
+                final var asset = loadApkAssets(key);
+                newAssetsBuilder.addApkAssets(asset);
+            } catch (IOException e) {
+                Log.e(TAG, "Couldn't load assets for key " + key, e);
+            }
+        }
+        assets.getLoaders().forEach(newAssetsBuilder::addLoader);
+        return new Pair<>(newAssetsBuilder.build(), size);
     }
 
     public static class ApkKey {
@@ -621,6 +657,23 @@ public class ResourcesManager {
         return apkKeys;
     }
 
+    private ResourcesKey resourcesKeyFromAssets(@NonNull AssetManager assets) {
+        final var libs = new ArrayList<String>();
+        final var overlays = new ArrayList<String>();
+        for (final ApkAssets asset : assets.getApkAssets()) {
+            if (asset.isSystem() || asset.isForLoader()) {
+                continue;
+            }
+            if (asset.isOverlay()) {
+                overlays.add(asset.getAssetPath());
+            } else if (asset.isSharedLib()) {
+                libs.add(asset.getAssetPath());
+            }
+        }
+        return new ResourcesKey(null, null, overlays.toArray(new String[0]),
+                libs.toArray(new String[0]), 0, null, null);
+    }
+
     /**
      * Creates an AssetManager from the paths within the ResourcesKey.
      *
@@ -749,7 +802,7 @@ public class ResourcesManager {
 
         final Configuration config = generateConfig(key);
         final DisplayMetrics displayMetrics = getDisplayMetrics(generateDisplayId(key), daj);
-        final ResourcesImpl impl = new ResourcesImpl(assets, displayMetrics, config, daj);
+        final ResourcesImpl impl = new ResourcesImpl(assets, displayMetrics, config, daj, true);
 
         if (DEBUG) {
             Slog.d(TAG, "- creating impl=" + impl + " with key: " + key);
@@ -1832,31 +1885,32 @@ public class ResourcesManager {
         for (int i = 0; i < resourcesCount; i++) {
             final WeakReference<Resources> ref = mAllResourceReferences.get(i);
             final Resources r = ref != null ? ref.get() : null;
-            if (r != null) {
-                final ResourcesKey key = updatedResourceKeys.get(r.getImpl());
-                if (key != null) {
-                    final ResourcesImpl impl = findOrCreateResourcesImplForKeyLocked(key);
-                    if (impl == null) {
-                        throw new Resources.NotFoundException("failed to redirect ResourcesImpl");
-                    }
-                    r.setImpl(impl);
-                } else {
-                    // ResourcesKey is null which means the ResourcesImpl could belong to a
-                    // Resources created by application through Resources constructor and was not
-                    // managed by ResourcesManager, so the ResourcesImpl needs to be recreated to
-                    // have shared library asset paths appended if there are any.
-                    if (r.getImpl() != null) {
-                        final ResourcesImpl oldImpl = r.getImpl();
-                        final AssetManager oldAssets = oldImpl.getAssets();
-                        // ResourcesImpl constructor will help to append shared library asset paths.
-                        if (oldAssets != AssetManager.getSystem() && oldAssets.isUpToDate()) {
-                            final ResourcesImpl newImpl = new ResourcesImpl(oldAssets,
-                                    oldImpl.getMetrics(), oldImpl.getConfiguration(),
-                                    oldImpl.getDisplayAdjustments());
+            if (r == null) {
+                continue;
+            }
+            final ResourcesKey key = updatedResourceKeys.get(r.getImpl());
+            if (key != null) {
+                final ResourcesImpl impl = findOrCreateResourcesImplForKeyLocked(key);
+                if (impl == null) {
+                    throw new Resources.NotFoundException("failed to redirect ResourcesImpl");
+                }
+                r.setImpl(impl);
+            } else {
+                // ResourcesKey is null which means the ResourcesImpl could belong to a
+                // Resources created by application through Resources constructor and was not
+                // managed by ResourcesManager, so the ResourcesImpl needs to be recreated to
+                // have shared library asset paths appended if there are any.
+                final ResourcesImpl oldImpl = r.getImpl();
+                if (oldImpl != null) {
+                    final AssetManager oldAssets = oldImpl.getAssets();
+                    // ResourcesImpl constructor will help to append shared library asset paths.
+                    if (oldAssets != AssetManager.getSystem()) {
+                        if (oldAssets.isUpToDate()) {
+                            final ResourcesImpl newImpl = new ResourcesImpl(oldImpl);
                             r.setImpl(newImpl);
                         } else {
-                            Slog.w(TAG, "Skip appending shared library asset paths for the "
-                                    + "Resource as its assets are not up to date.");
+                            Slog.w(TAG, "Skip appending shared library asset paths for "
+                                    + "the Resources as its assets are not up to date.");
                         }
                     }
                 }
diff --git a/core/java/android/content/res/ApkAssets.java b/core/java/android/content/res/ApkAssets.java
index 68b5d782bfbf..908999b64961 100644
--- a/core/java/android/content/res/ApkAssets.java
+++ b/core/java/android/content/res/ApkAssets.java
@@ -124,11 +124,13 @@ public final class ApkAssets {
 
     @Nullable
     @GuardedBy("this")
-    private final StringBlock mStringBlock;  // null or closed if mNativePtr = 0.
+    private StringBlock mStringBlock;  // null or closed if mNativePtr = 0.
 
     @PropertyFlags
     private final int mFlags;
 
+    private final boolean mIsOverlay;
+
     @Nullable
     private final AssetsProvider mAssets;
 
@@ -302,40 +304,43 @@ public final class ApkAssets {
 
     private ApkAssets(@FormatType int format, @NonNull String path, @PropertyFlags int flags,
             @Nullable AssetsProvider assets) throws IOException {
+        this(format, flags, assets);
         Objects.requireNonNull(path, "path");
-        mFlags = flags;
         mNativePtr = nativeLoad(format, path, flags, assets);
         mStringBlock = new StringBlock(nativeGetStringBlock(mNativePtr), true /*useSparse*/);
-        mAssets = assets;
     }
 
     private ApkAssets(@FormatType int format, @NonNull FileDescriptor fd,
             @NonNull String friendlyName, @PropertyFlags int flags, @Nullable AssetsProvider assets)
             throws IOException {
+        this(format, flags, assets);
         Objects.requireNonNull(fd, "fd");
         Objects.requireNonNull(friendlyName, "friendlyName");
-        mFlags = flags;
         mNativePtr = nativeLoadFd(format, fd, friendlyName, flags, assets);
         mStringBlock = new StringBlock(nativeGetStringBlock(mNativePtr), true /*useSparse*/);
-        mAssets = assets;
     }
 
     private ApkAssets(@FormatType int format, @NonNull FileDescriptor fd,
             @NonNull String friendlyName, long offset, long length, @PropertyFlags int flags,
             @Nullable AssetsProvider assets) throws IOException {
+        this(format, flags, assets);
         Objects.requireNonNull(fd, "fd");
         Objects.requireNonNull(friendlyName, "friendlyName");
-        mFlags = flags;
         mNativePtr = nativeLoadFdOffsets(format, fd, friendlyName, offset, length, flags, assets);
         mStringBlock = new StringBlock(nativeGetStringBlock(mNativePtr), true /*useSparse*/);
-        mAssets = assets;
     }
 
     private ApkAssets(@PropertyFlags int flags, @Nullable AssetsProvider assets) {
-        mFlags = flags;
+        this(FORMAT_APK, flags, assets);
         mNativePtr = nativeLoadEmpty(flags, assets);
         mStringBlock = null;
+    }
+
+    private ApkAssets(@FormatType int format, @PropertyFlags int flags,
+            @Nullable AssetsProvider assets) {
+        mFlags = flags;
         mAssets = assets;
+        mIsOverlay = format == FORMAT_IDMAP;
     }
 
     @UnsupportedAppUsage
@@ -425,6 +430,18 @@ public final class ApkAssets {
         }
     }
 
+    public boolean isSystem() {
+        return (mFlags & PROPERTY_SYSTEM) != 0;
+    }
+
+    public boolean isSharedLib() {
+        return (mFlags & PROPERTY_DYNAMIC) != 0;
+    }
+
+    public boolean isOverlay() {
+        return mIsOverlay;
+    }
+
     @Override
     public String toString() {
         return "ApkAssets{path=" + getDebugName() + "}";
diff --git a/core/java/android/content/res/ResourcesImpl.java b/core/java/android/content/res/ResourcesImpl.java
index e6b93427f413..bcaceb24d767 100644
--- a/core/java/android/content/res/ResourcesImpl.java
+++ b/core/java/android/content/res/ResourcesImpl.java
@@ -203,9 +203,25 @@ public class ResourcesImpl {
     @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
     public ResourcesImpl(@NonNull AssetManager assets, @Nullable DisplayMetrics metrics,
             @Nullable Configuration config, @NonNull DisplayAdjustments displayAdjustments) {
-        mAssets = assets;
-        mAppliedSharedLibsHash =
-                ResourcesManager.getInstance().updateResourceImplWithRegisteredLibs(this);
+        // Don't reuse assets by default as we have no control over whether they're already
+        // inside some other ResourcesImpl.
+        this(assets, metrics, config, displayAdjustments, false);
+    }
+
+    public ResourcesImpl(@NonNull ResourcesImpl orig) {
+        // We know for sure that the other assets are in use, so can't reuse the object here.
+        this(orig.getAssets(), orig.getMetrics(), orig.getConfiguration(),
+                orig.getDisplayAdjustments(), false);
+    }
+
+    public ResourcesImpl(@NonNull AssetManager assets, @Nullable DisplayMetrics metrics,
+            @Nullable Configuration config, @NonNull DisplayAdjustments displayAdjustments,
+            boolean reuseAssets) {
+        final var assetsAndHash =
+                ResourcesManager.getInstance().updateResourceImplAssetsWithRegisteredLibs(assets,
+                        reuseAssets);
+        mAssets = assetsAndHash.first;
+        mAppliedSharedLibsHash = assetsAndHash.second;
         mMetrics.setToDefaults();
         mDisplayAdjustments = displayAdjustments;
         mConfiguration.setToDefaults();
diff --git a/packages/SystemUI/src/com/android/systemui/mediaprojection/permission/MediaProjectionPermissionActivity.java b/packages/SystemUI/src/com/android/systemui/mediaprojection/permission/MediaProjectionPermissionActivity.java
index 8351597f35de..6cc60964c841 100644
--- a/packages/SystemUI/src/com/android/systemui/mediaprojection/permission/MediaProjectionPermissionActivity.java
+++ b/packages/SystemUI/src/com/android/systemui/mediaprojection/permission/MediaProjectionPermissionActivity.java
@@ -123,11 +123,14 @@ public class MediaProjectionPermissionActivity extends Activity {
         mReviewGrantedConsentRequired = launchingIntent.getBooleanExtra(
                 EXTRA_USER_REVIEW_GRANTED_CONSENT, false);
 
-        mPackageName = getCallingPackage();
-
-        // This activity is launched directly by an app, or system server. System server provides
-        // the package name through the intent if so.
-        if (mPackageName == null) {
+        // The original requester of this activity start
+        mPackageName = getLaunchedFromPackage();
+
+        // This activity is launched directly by using startActivity(),
+        // thus getCallingPackage() will be null.
+        if (getCallingPackage() == null) {
+            // System server provides the package name through the intent if so and is able to get
+            // the result back. Other applications can't.
             if (launchingIntent.hasExtra(EXTRA_PACKAGE_REUSING_GRANTED_CONSENT)) {
                 mPackageName = launchingIntent.getStringExtra(
                         EXTRA_PACKAGE_REUSING_GRANTED_CONSENT);
diff --git a/services/autofill/java/com/android/server/autofill/Helper.java b/services/autofill/java/com/android/server/autofill/Helper.java
index cd2a535aa2c5..e59bb42fd666 100644
--- a/services/autofill/java/com/android/server/autofill/Helper.java
+++ b/services/autofill/java/com/android/server/autofill/Helper.java
@@ -28,8 +28,11 @@ import android.app.ActivityManager;
 import android.app.assist.AssistStructure;
 import android.app.assist.AssistStructure.ViewNode;
 import android.app.assist.AssistStructure.WindowNode;
+import android.app.slice.Slice;
+import android.app.slice.SliceItem;
 import android.content.ComponentName;
 import android.content.Context;
+import android.graphics.drawable.Icon;
 import android.hardware.display.DisplayManager;
 import android.metrics.LogMaker;
 import android.os.UserHandle;
@@ -97,11 +100,12 @@ public final class Helper {
             @UserIdInt int userId, @NonNull RemoteViews rView) {
         final AtomicBoolean permissionsOk = new AtomicBoolean(true);
 
-        rView.visitUris(uri -> {
-            int uriOwnerId = android.content.ContentProvider.getUserIdFromUri(uri);
-            boolean allowed = uriOwnerId == userId;
-            permissionsOk.set(allowed & permissionsOk.get());
-        });
+        rView.visitUris(
+                uri -> {
+                    int uriOwnerId = android.content.ContentProvider.getUserIdFromUri(uri, userId);
+                    boolean allowed = uriOwnerId == userId;
+                    permissionsOk.set(allowed & permissionsOk.get());
+                });
 
         return permissionsOk.get();
     }
@@ -150,6 +154,47 @@ public final class Helper {
         return (ok ? rView : null);
     }
 
+    /**
+     * Checks the URI permissions of the icon in the slice, to see if the current userId is able to
+     * access it.
+     *
+     * <p>Returns null if slice contains user inaccessible icons
+     *
+     * <p>TODO: instead of returning a null Slice when the current userId cannot access an icon,
+     * return a reconstructed Slice without the icons. This is currently non-trivial since there are
+     * no public methods to generically add SliceItems to Slices
+     */
+    public static @Nullable Slice sanitizeSlice(Slice slice) {
+        if (slice == null) {
+            return null;
+        }
+
+        int userId = ActivityManager.getCurrentUser();
+
+        // Recontruct the Slice, filtering out bad icons
+        for (SliceItem sliceItem : slice.getItems()) {
+            if (!sliceItem.getFormat().equals(SliceItem.FORMAT_IMAGE)) {
+                // Not an image slice
+                continue;
+            }
+
+            Icon icon = sliceItem.getIcon();
+            if (icon.getType() != Icon.TYPE_URI
+                    && icon.getType() != Icon.TYPE_URI_ADAPTIVE_BITMAP) {
+                // No URIs to sanitize
+                continue;
+            }
+
+            int iconUriId = android.content.ContentProvider.getUserIdFromUri(icon.getUri(), userId);
+
+            if (iconUriId != userId) {
+                Slog.w(TAG, "sanitizeSlice() user: " + userId + " cannot access icons in Slice");
+                return null;
+            }
+        }
+
+        return slice;
+    }
 
     @Nullable
     static AutofillId[] toArray(@Nullable ArraySet<AutofillId> set) {
diff --git a/services/autofill/java/com/android/server/autofill/ui/RemoteInlineSuggestionViewConnector.java b/services/autofill/java/com/android/server/autofill/ui/RemoteInlineSuggestionViewConnector.java
index 38a412fa063d..50a26b355537 100644
--- a/services/autofill/java/com/android/server/autofill/ui/RemoteInlineSuggestionViewConnector.java
+++ b/services/autofill/java/com/android/server/autofill/ui/RemoteInlineSuggestionViewConnector.java
@@ -27,6 +27,7 @@ import android.service.autofill.InlinePresentation;
 import android.util.Slog;
 
 import com.android.server.LocalServices;
+import com.android.server.autofill.Helper;
 import com.android.server.autofill.RemoteInlineSuggestionRenderService;
 import com.android.server.inputmethod.InputMethodManagerInternal;
 
@@ -83,6 +84,10 @@ final class RemoteInlineSuggestionViewConnector {
      */
     public boolean renderSuggestion(int width, int height,
             @NonNull IInlineSuggestionUiCallback callback) {
+        if (Helper.sanitizeSlice(mInlinePresentation.getSlice()) == null) {
+            if (sDebug) Slog.d(TAG, "Skipped rendering inline suggestion.");
+            return false;
+        }
         if (mRemoteRenderService != null) {
             if (sDebug) Slog.d(TAG, "Request to recreate the UI");
             mRemoteRenderService.renderSuggestion(callback, mInlinePresentation, width, height,
diff --git a/services/companion/java/com/android/server/companion/CompanionDeviceManagerService.java b/services/companion/java/com/android/server/companion/CompanionDeviceManagerService.java
index c73e457c565d..0e6a85e332d2 100644
--- a/services/companion/java/com/android/server/companion/CompanionDeviceManagerService.java
+++ b/services/companion/java/com/android/server/companion/CompanionDeviceManagerService.java
@@ -724,11 +724,17 @@ public class CompanionDeviceManagerService extends SystemService {
 
         @Override
         public byte[] getBackupPayload(int userId) {
+            if (getCallingUid() != SYSTEM_UID) {
+                throw new SecurityException("Caller must be system");
+            }
             return mBackupRestoreProcessor.getBackupPayload(userId);
         }
 
         @Override
         public void applyRestoredPayload(byte[] payload, int userId) {
+            if (getCallingUid() != SYSTEM_UID) {
+                throw new SecurityException("Caller must be system");
+            }
             mBackupRestoreProcessor.applyRestoredPayload(payload, userId);
         }
 
diff --git a/services/core/java/com/android/server/SecurityStateManagerService.java b/services/core/java/com/android/server/SecurityStateManagerService.java
index 98039be20897..fe21fbda7130 100644
--- a/services/core/java/com/android/server/SecurityStateManagerService.java
+++ b/services/core/java/com/android/server/SecurityStateManagerService.java
@@ -22,6 +22,7 @@ import static android.os.SecurityStateManager.KEY_VENDOR_SPL;
 
 import android.content.Context;
 import android.content.pm.PackageManager;
+import android.os.Binder;
 import android.os.Build;
 import android.os.Bundle;
 import android.os.ISecurityStateManager;
@@ -56,6 +57,15 @@ public class SecurityStateManagerService extends ISecurityStateManager.Stub {
 
     @Override
     public Bundle getGlobalSecurityState() {
+        final long token = Binder.clearCallingIdentity();
+        try {
+            return getGlobalSecurityStateInternal();
+        } finally {
+            Binder.restoreCallingIdentity(token);
+        }
+    }
+
+    private Bundle getGlobalSecurityStateInternal() {
         Bundle globalSecurityState = new Bundle();
         globalSecurityState.putString(KEY_SYSTEM_SPL, Build.VERSION.SECURITY_PATCH);
         globalSecurityState.putString(KEY_VENDOR_SPL,
```

