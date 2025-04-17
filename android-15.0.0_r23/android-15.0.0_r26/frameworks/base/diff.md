```diff
diff --git a/core/java/android/os/BaseBundle.java b/core/java/android/os/BaseBundle.java
index 50121278f0e6..e2315d52e6b4 100644
--- a/core/java/android/os/BaseBundle.java
+++ b/core/java/android/os/BaseBundle.java
@@ -475,10 +475,10 @@ public class BaseBundle {
             map.erase();
             map.ensureCapacity(count);
         }
-        int numLazyValues = 0;
+        int[] numLazyValues = new int[]{0};
         try {
-            numLazyValues = parcelledData.readArrayMap(map, count, !parcelledByNative,
-                    /* lazy */ ownsParcel, mClassLoader);
+            parcelledData.readArrayMap(map, count, !parcelledByNative,
+                    /* lazy */ ownsParcel, mClassLoader, numLazyValues);
         } catch (BadParcelableException e) {
             if (sShouldDefuse) {
                 Log.w(TAG, "Failed to parse Bundle, but defusing quietly", e);
@@ -489,14 +489,14 @@ public class BaseBundle {
         } finally {
             mWeakParcelledData = null;
             if (ownsParcel) {
-                if (numLazyValues == 0) {
+                if (numLazyValues[0] == 0) {
                     recycleParcel(parcelledData);
                 } else {
                     mWeakParcelledData = new WeakReference<>(parcelledData);
                 }
             }
 
-            mLazyValues = numLazyValues;
+            mLazyValues = numLazyValues[0];
             mParcelledByNative = false;
             mMap = map;
             // Set field last as it is volatile
diff --git a/core/java/android/os/Parcel.java b/core/java/android/os/Parcel.java
index cf473ec9c3ea..26f768cc49f7 100644
--- a/core/java/android/os/Parcel.java
+++ b/core/java/android/os/Parcel.java
@@ -5538,7 +5538,7 @@ public final class Parcel {
 
     private void readArrayMapInternal(@NonNull ArrayMap<? super String, Object> outVal,
             int size, @Nullable ClassLoader loader) {
-        readArrayMap(outVal, size, /* sorted */ true, /* lazy */ false, loader);
+        readArrayMap(outVal, size, /* sorted */ true, /* lazy */ false, loader, null);
     }
 
     /**
@@ -5548,17 +5548,16 @@ public final class Parcel {
      * @param lazy   Whether to populate the map with lazy {@link Function} objects for
      *               length-prefixed values. See {@link Parcel#readLazyValue(ClassLoader)} for more
      *               details.
-     * @return a count of the lazy values in the map
+     * @param lazyValueCount number of lazy values added here
      * @hide
      */
-    int readArrayMap(ArrayMap<? super String, Object> map, int size, boolean sorted,
-            boolean lazy, @Nullable ClassLoader loader) {
-        int lazyValues = 0;
+    void readArrayMap(ArrayMap<? super String, Object> map, int size, boolean sorted,
+            boolean lazy, @Nullable ClassLoader loader, int[] lazyValueCount) {
         while (size > 0) {
             String key = readString();
             Object value = (lazy) ? readLazyValue(loader) : readValue(loader);
             if (value instanceof LazyValue) {
-                lazyValues++;
+                lazyValueCount[0]++;
             }
             if (sorted) {
                 map.append(key, value);
@@ -5570,7 +5569,6 @@ public final class Parcel {
         if (sorted) {
             map.validate();
         }
-        return lazyValues;
     }
 
     /**
diff --git a/core/java/com/android/internal/app/ChooserActivity.java b/core/java/com/android/internal/app/ChooserActivity.java
index ca4d1b63a928..3bdf3d65e99c 100644
--- a/core/java/com/android/internal/app/ChooserActivity.java
+++ b/core/java/com/android/internal/app/ChooserActivity.java
@@ -21,6 +21,7 @@ import static android.app.admin.DevicePolicyResources.Strings.Core.RESOLVER_CANT
 import static android.app.admin.DevicePolicyResources.Strings.Core.RESOLVER_CANT_SHARE_WITH_PERSONAL;
 import static android.app.admin.DevicePolicyResources.Strings.Core.RESOLVER_CANT_SHARE_WITH_WORK;
 import static android.app.admin.DevicePolicyResources.Strings.Core.RESOLVER_CROSS_PROFILE_BLOCKED_TITLE;
+import static android.content.ContentProvider.getUriWithoutUserId;
 import static android.content.ContentProvider.getUserIdFromUri;
 import static android.stats.devicepolicy.DevicePolicyEnums.RESOLVER_EMPTY_STATE_NO_SHARING_TO_PERSONAL;
 import static android.stats.devicepolicy.DevicePolicyEnums.RESOLVER_EMPTY_STATE_NO_SHARING_TO_WORK;
@@ -40,7 +41,9 @@ import android.annotation.Nullable;
 import android.app.Activity;
 import android.app.ActivityManager;
 import android.app.ActivityOptions;
+import android.app.IUriGrantsManager;
 import android.app.SharedElementCallback;
+import android.app.UriGrantsManager;
 import android.app.prediction.AppPredictionContext;
 import android.app.prediction.AppPredictionManager;
 import android.app.prediction.AppPredictor;
@@ -77,6 +80,7 @@ import android.graphics.Paint;
 import android.graphics.Path;
 import android.graphics.drawable.AnimatedVectorDrawable;
 import android.graphics.drawable.Drawable;
+import android.graphics.drawable.Icon;
 import android.metrics.LogMaker;
 import android.net.Uri;
 import android.os.AsyncTask;
@@ -86,6 +90,7 @@ import android.os.Handler;
 import android.os.Message;
 import android.os.Parcelable;
 import android.os.PatternMatcher;
+import android.os.RemoteException;
 import android.os.ResultReceiver;
 import android.os.UserHandle;
 import android.os.UserManager;
@@ -692,7 +697,11 @@ public class ChooserActivity extends ResolverActivity implements
                     targets = null;
                     break;
                 }
-                targets[i] = (ChooserTarget) pa[i];
+                ChooserTarget chooserTarget = (ChooserTarget) pa[i];
+                if (!hasValidIcon(chooserTarget)) {
+                    chooserTarget = removeIcon(chooserTarget);
+                }
+                targets[i] = chooserTarget;
             }
             mCallerChooserTargets = targets;
         }
@@ -4214,4 +4223,43 @@ public class ChooserActivity extends ResolverActivity implements
     private boolean shouldNearbyShareBeIncludedAsActionButton() {
         return !shouldNearbyShareBeFirstInRankedRow();
     }
+
+    private boolean hasValidIcon(ChooserTarget target) {
+        Icon icon = target.getIcon();
+        if (icon == null) {
+            return true;
+        }
+        if (icon.getType() == Icon.TYPE_URI || icon.getType() == Icon.TYPE_URI_ADAPTIVE_BITMAP) {
+            Uri uri = icon.getUri();
+            try {
+                getUriGrantsManager().checkGrantUriPermission_ignoreNonSystem(
+                        getLaunchedFromUid(),
+                        getPackageName(),
+                        getUriWithoutUserId(uri),
+                        Intent.FLAG_GRANT_READ_URI_PERMISSION,
+                        getUserIdFromUri(uri)
+                );
+            } catch (SecurityException | RemoteException e) {
+                Log.e(TAG, "Failed to get URI permission for: " + uri, e);
+                return false;
+            }
+        }
+        return true;
+    }
+
+    private IUriGrantsManager getUriGrantsManager() {
+        return UriGrantsManager.getService();
+    }
+
+    private static ChooserTarget removeIcon(ChooserTarget target) {
+        if (target == null) {
+            return null;
+        }
+        return new ChooserTarget(
+                target.getTitle(),
+                null,
+                target.getScore(),
+                target.getComponentName(),
+                target.getIntentExtras());
+    }
 }
diff --git a/core/java/com/android/internal/app/IntentForwarderActivity.java b/core/java/com/android/internal/app/IntentForwarderActivity.java
index 644d69919998..d29ef38bd57d 100644
--- a/core/java/com/android/internal/app/IntentForwarderActivity.java
+++ b/core/java/com/android/internal/app/IntentForwarderActivity.java
@@ -599,24 +599,35 @@ public class IntentForwarderActivity extends Activity  {
                 Intent.FLAG_ACTIVITY_FORWARD_RESULT | Intent.FLAG_ACTIVITY_PREVIOUS_IS_TOP);
         sanitizeIntent(forwardIntent);
 
-        Intent intentToCheck = forwardIntent;
-        if (Intent.ACTION_CHOOSER.equals(forwardIntent.getAction())) {
+        if (!canForwardInner(forwardIntent, sourceUserId, targetUserId, packageManager,
+                contentResolver)) {
             return null;
         }
         if (forwardIntent.getSelector() != null) {
-            intentToCheck = forwardIntent.getSelector();
+            sanitizeIntent(forwardIntent.getSelector());
+            if (!canForwardInner(forwardIntent.getSelector(), sourceUserId, targetUserId,
+                    packageManager, contentResolver)) {
+                return null;
+            }
+        }
+        return forwardIntent;
+    }
+
+    private static boolean canForwardInner(Intent intent, int sourceUserId, int targetUserId,
+            IPackageManager packageManager, ContentResolver contentResolver) {
+        if (Intent.ACTION_CHOOSER.equals(intent.getAction())) {
+            return false;
         }
-        String resolvedType = intentToCheck.resolveTypeIfNeeded(contentResolver);
-        sanitizeIntent(intentToCheck);
+        String resolvedType = intent.resolveTypeIfNeeded(contentResolver);
         try {
             if (packageManager.canForwardTo(
-                    intentToCheck, resolvedType, sourceUserId, targetUserId)) {
-                return forwardIntent;
+                    intent, resolvedType, sourceUserId, targetUserId)) {
+                return true;
             }
         } catch (RemoteException e) {
             Slog.e(TAG, "PackageManagerService is dead?");
         }
-        return null;
+        return false;
     }
 
     /**
diff --git a/libs/WindowManager/Shell/src/com/android/wm/shell/splitscreen/StageCoordinator.java b/libs/WindowManager/Shell/src/com/android/wm/shell/splitscreen/StageCoordinator.java
index 5eadd060ca44..221beaf2a0fa 100644
--- a/libs/WindowManager/Shell/src/com/android/wm/shell/splitscreen/StageCoordinator.java
+++ b/libs/WindowManager/Shell/src/com/android/wm/shell/splitscreen/StageCoordinator.java
@@ -2951,9 +2951,11 @@ public class StageCoordinator implements SplitLayout.SplitLayoutHandler,
             final int transitType = info.getType();
             TransitionInfo.Change pipChange = null;
             int closingSplitTaskId = -1;
-            // This array tracks if we are sending stages TO_BACK in this transition.
-            // TODO (b/349828130): Update for n apps
-            boolean[] stagesSentToBack = new boolean[2];
+            // This array tracks where we are sending stages (TO_BACK/TO_FRONT) in this transition.
+            // TODO (b/349828130): Update for n apps (needs to handle different indices than 0/1).
+            //  Also make sure having multiple changes per stage (2+ tasks in one stage) is being
+            //  handled properly.
+            int[] stageChanges = new int[2];
 
             for (int iC = 0; iC < info.getChanges().size(); ++iC) {
                 final TransitionInfo.Change change = info.getChanges().get(iC);
@@ -3016,18 +3018,25 @@ public class StageCoordinator implements SplitLayout.SplitLayoutHandler,
                                 + " with " + taskId + " before startAnimation().");
                     }
                 }
-                if (isClosingType(change.getMode()) &&
-                        getStageOfTask(taskId) != STAGE_TYPE_UNDEFINED) {
-
-                    // Record which stages are getting sent to back
-                    if (change.getMode() == TRANSIT_TO_BACK) {
-                        stagesSentToBack[getStageOfTask(taskId)] = true;
-                    }
 
+                final int stageOfTaskId = getStageOfTask(taskId);
+                if (stageOfTaskId == STAGE_TYPE_UNDEFINED) {
+                    continue;
+                }
+                if (isClosingType(change.getMode())) {
                     // (For PiP transitions) If either one of the 2 stages is closing we're assuming
                     // we'll break split
                     closingSplitTaskId = taskId;
                 }
+                if (transitType == WindowManager.TRANSIT_WAKE) {
+                    // Record which stages are receiving which changes
+                    if ((change.getMode() == TRANSIT_TO_BACK
+                            || change.getMode() == TRANSIT_TO_FRONT)
+                            && (stageOfTaskId == STAGE_TYPE_MAIN
+                            || stageOfTaskId == STAGE_TYPE_SIDE)) {
+                        stageChanges[stageOfTaskId] = change.getMode();
+                    }
+                }
             }
 
             if (pipChange != null) {
@@ -3052,19 +3061,11 @@ public class StageCoordinator implements SplitLayout.SplitLayoutHandler,
                 return true;
             }
 
-            // If keyguard is active, check to see if we have our TO_BACK transitions in order.
-            // This array should either be all false (no split stages sent to back) or all true
-            // (all stages sent to back). In any other case (which can happen with SHOW_ABOVE_LOCKED
-            // apps) we should break split.
-            if (mKeyguardActive) {
-                boolean isFirstStageSentToBack = stagesSentToBack[0];
-                for (boolean b : stagesSentToBack) {
-                    // Compare each boolean to the first one. If any are different, break split.
-                    if (b != isFirstStageSentToBack) {
-                        dismissSplitKeepingLastActiveStage(EXIT_REASON_SCREEN_LOCKED_SHOW_ON_TOP);
-                        break;
-                    }
-                }
+            // If keyguard is active, check to see if we have all our stages showing. If one stage
+            // was moved but not the other (which can happen with SHOW_ABOVE_LOCKED apps), we should
+            // break split.
+            if (mKeyguardActive && stageChanges[STAGE_TYPE_MAIN] != stageChanges[STAGE_TYPE_SIDE]) {
+                dismissSplitKeepingLastActiveStage(EXIT_REASON_SCREEN_LOCKED_SHOW_ON_TOP);
             }
 
             final ArraySet<StageTaskListener> dismissStages = record.getShouldDismissedStage();
diff --git a/packages/SystemUI/src/com/android/systemui/keyguard/ui/view/layout/sections/transitions/ClockSizeTransition.kt b/packages/SystemUI/src/com/android/systemui/keyguard/ui/view/layout/sections/transitions/ClockSizeTransition.kt
index a595d815e016..29bda7623675 100644
--- a/packages/SystemUI/src/com/android/systemui/keyguard/ui/view/layout/sections/transitions/ClockSizeTransition.kt
+++ b/packages/SystemUI/src/com/android/systemui/keyguard/ui/view/layout/sections/transitions/ClockSizeTransition.kt
@@ -86,15 +86,56 @@ class ClockSizeTransition(
             transition.values[SMARTSPACE_BOUNDS] = targetSSView.getRect()
         }
 
-        open fun mutateBounds(
-            view: View,
-            fromIsVis: Boolean,
-            toIsVis: Boolean,
-            fromBounds: Rect,
-            toBounds: Rect,
-            fromSSBounds: Rect?,
-            toSSBounds: Rect?,
-        ) {}
+        open fun initTargets(from: Target, to: Target) {}
+
+        open fun mutateTargets(from: Target, to: Target) {}
+
+        data class Target(
+            var view: View,
+            var visibility: Int,
+            var isVisible: Boolean,
+            var alpha: Float,
+            var bounds: Rect,
+            var ssBounds: Rect?,
+        ) {
+            companion object {
+                fun fromStart(startValues: TransitionValues): Target {
+                    var fromVis = startValues.values[PROP_VISIBILITY] as Int
+                    var fromIsVis = fromVis == View.VISIBLE
+                    var fromAlpha = startValues.values[PROP_ALPHA] as Float
+
+                    // Align starting visibility and alpha
+                    if (!fromIsVis) fromAlpha = 0f
+                    else if (fromAlpha <= 0f) {
+                        fromIsVis = false
+                        fromVis = View.INVISIBLE
+                    }
+
+                    return Target(
+                        view = startValues.view,
+                        visibility = fromVis,
+                        isVisible = fromIsVis,
+                        alpha = fromAlpha,
+                        bounds = startValues.values[PROP_BOUNDS] as Rect,
+                        ssBounds = startValues.values[SMARTSPACE_BOUNDS] as Rect?,
+                    )
+                }
+
+                fun fromEnd(endValues: TransitionValues): Target {
+                    val toVis = endValues.values[PROP_VISIBILITY] as Int
+                    val toIsVis = toVis == View.VISIBLE
+
+                    return Target(
+                        view = endValues.view,
+                        visibility = toVis,
+                        isVisible = toIsVis,
+                        alpha = if (toIsVis) 1f else 0f,
+                        bounds = endValues.values[PROP_BOUNDS] as Rect,
+                        ssBounds = endValues.values[SMARTSPACE_BOUNDS] as Rect?,
+                    )
+                }
+            }
+        }
 
         override fun createAnimator(
             sceenRoot: ViewGroup,
@@ -109,72 +150,58 @@ class ClockSizeTransition(
                 return null
             }
 
-            var fromVis = startValues.values[PROP_VISIBILITY] as Int
-            var fromIsVis = fromVis == View.VISIBLE
-            var fromAlpha = startValues.values[PROP_ALPHA] as Float
-            val fromBounds = startValues.values[PROP_BOUNDS] as Rect
-            val fromSSBounds = startValues.values[SMARTSPACE_BOUNDS] as Rect?
-
-            val toView = endValues.view
-            val toVis = endValues.values[PROP_VISIBILITY] as Int
-            val toBounds = endValues.values[PROP_BOUNDS] as Rect
-            val toSSBounds = endValues.values[SMARTSPACE_BOUNDS] as Rect?
-            val toIsVis = toVis == View.VISIBLE
-            val toAlpha = if (toIsVis) 1f else 0f
-
-            // Align starting visibility and alpha
-            if (!fromIsVis) fromAlpha = 0f
-            else if (fromAlpha <= 0f) {
-                fromIsVis = false
-                fromVis = View.INVISIBLE
-            }
+            val from = Target.fromStart(startValues)
+            val to = Target.fromEnd(endValues)
+            initTargets(from, to)
+            mutateTargets(from, to)
 
-            mutateBounds(toView, fromIsVis, toIsVis, fromBounds, toBounds, fromSSBounds, toSSBounds)
-            if (fromIsVis == toIsVis && fromBounds.equals(toBounds)) {
+            if (from.isVisible == to.isVisible && from.bounds.equals(to.bounds)) {
                 if (DEBUG) {
                     Log.w(
                         TAG,
-                        "Skipping no-op transition: $toView; " +
-                            "vis: $fromVis -> $toVis; " +
-                            "alpha: $fromAlpha -> $toAlpha; " +
-                            "bounds: $fromBounds -> $toBounds; ",
+                        "Skipping no-op transition: ${to.view}; " +
+                            "vis: ${from.visibility} -> ${to.visibility}; " +
+                            "alpha: ${from.alpha} -> ${to.alpha}; " +
+                            "bounds: ${from.bounds} -> ${to.bounds}; ",
                     )
                 }
                 return null
             }
 
-            val sendToBack = fromIsVis && !toIsVis
+            val sendToBack = from.isVisible && !to.isVisible
             fun lerp(start: Int, end: Int, fract: Float): Int =
                 MathUtils.lerp(start.toFloat(), end.toFloat(), fract).toInt()
             fun computeBounds(fract: Float): Rect =
                 Rect(
-                    lerp(fromBounds.left, toBounds.left, fract),
-                    lerp(fromBounds.top, toBounds.top, fract),
-                    lerp(fromBounds.right, toBounds.right, fract),
-                    lerp(fromBounds.bottom, toBounds.bottom, fract),
+                    lerp(from.bounds.left, to.bounds.left, fract),
+                    lerp(from.bounds.top, to.bounds.top, fract),
+                    lerp(from.bounds.right, to.bounds.right, fract),
+                    lerp(from.bounds.bottom, to.bounds.bottom, fract),
                 )
 
             fun assignAnimValues(src: String, fract: Float, vis: Int? = null) {
+                mutateTargets(from, to)
                 val bounds = computeBounds(fract)
-                val alpha = MathUtils.lerp(fromAlpha, toAlpha, fract)
+                val alpha = MathUtils.lerp(from.alpha, to.alpha, fract)
                 if (DEBUG) {
                     Log.i(
                         TAG,
-                        "$src: $toView; fract=$fract; alpha=$alpha; vis=$vis; bounds=$bounds;",
+                        "$src: ${to.view}; fract=$fract; alpha=$alpha; vis=$vis; bounds=$bounds;",
                     )
                 }
-                toView.setVisibility(vis ?: View.VISIBLE)
-                toView.setAlpha(alpha)
-                toView.setRect(bounds)
+
+                to.view.setVisibility(vis ?: View.VISIBLE)
+                to.view.setAlpha(alpha)
+                to.view.setRect(bounds)
             }
 
             if (DEBUG) {
                 Log.i(
                     TAG,
-                    "transitioning: $toView; " +
-                        "vis: $fromVis -> $toVis; " +
-                        "alpha: $fromAlpha -> $toAlpha; " +
-                        "bounds: $fromBounds -> $toBounds; ",
+                    "transitioning: ${to.view}; " +
+                        "vis: ${from.visibility} -> ${to.visibility}; " +
+                        "alpha: ${from.alpha} -> ${to.alpha}; " +
+                        "bounds: ${from.bounds} -> ${to.bounds}; ",
                 )
             }
 
@@ -190,11 +217,11 @@ class ClockSizeTransition(
                 this@VisibilityBoundsTransition.addListener(
                     object : TransitionListenerAdapter() {
                         override fun onTransitionStart(t: Transition) {
-                            toView.viewTreeObserver.addOnPreDrawListener(predrawCallback)
+                            to.view.viewTreeObserver.addOnPreDrawListener(predrawCallback)
                         }
 
                         override fun onTransitionEnd(t: Transition) {
-                            toView.viewTreeObserver.removeOnPreDrawListener(predrawCallback)
+                            to.view.viewTreeObserver.removeOnPreDrawListener(predrawCallback)
                         }
                     }
                 )
@@ -202,17 +229,17 @@ class ClockSizeTransition(
                 val listener =
                     object : AnimatorListenerAdapter() {
                         override fun onAnimationStart(anim: Animator) {
-                            assignAnimValues("start", 0f, fromVis)
+                            assignAnimValues("start", 0f, from.visibility)
                         }
 
                         override fun onAnimationEnd(anim: Animator) {
-                            assignAnimValues("end", 1f, toVis)
-                            if (sendToBack) toView.translationZ = 0f
+                            assignAnimValues("end", 1f, to.visibility)
+                            if (sendToBack) to.view.translationZ = 0f
                         }
                     }
 
                 anim.addListener(listener)
-                assignAnimValues("init", 0f, fromVis)
+                assignAnimValues("init", 0f, from.visibility)
             }
         }
 
@@ -251,31 +278,23 @@ class ClockSizeTransition(
             }
         }
 
-        override fun mutateBounds(
-            view: View,
-            fromIsVis: Boolean,
-            toIsVis: Boolean,
-            fromBounds: Rect,
-            toBounds: Rect,
-            fromSSBounds: Rect?,
-            toSSBounds: Rect?,
-        ) {
+        override fun initTargets(from: Target, to: Target) {
             // Move normally if clock is not changing visibility
-            if (fromIsVis == toIsVis) return
+            if (from.isVisible == to.isVisible) return
 
-            fromBounds.set(toBounds)
+            from.bounds.set(to.bounds)
             if (isLargeClock) {
                 // Large clock shouldn't move; fromBounds already set
-            } else if (toSSBounds != null && fromSSBounds != null) {
+            } else if (to.ssBounds != null && from.ssBounds != null) {
                 // Instead of moving the small clock the full distance, we compute the distance
                 // smartspace will move. We then scale this to match the duration of this animation
                 // so that the small clock moves at the same speed as smartspace.
                 val ssTranslation =
-                    abs((toSSBounds.top - fromSSBounds.top) * smallClockMoveScale).toInt()
-                fromBounds.top = toBounds.top - ssTranslation
-                fromBounds.bottom = toBounds.bottom - ssTranslation
+                    abs((to.ssBounds!!.top - from.ssBounds!!.top) * smallClockMoveScale).toInt()
+                from.bounds.top = to.bounds.top - ssTranslation
+                from.bounds.bottom = to.bounds.bottom - ssTranslation
             } else {
-                Log.e(TAG, "mutateBounds: smallClock received no smartspace bounds")
+                Log.e(TAG, "initTargets: smallClock received no smartspace bounds")
             }
         }
     }
@@ -320,10 +339,9 @@ class ClockSizeTransition(
         }
     }
 
-    // TODO: Might need a mechanism to update this one while in-progress
     class SmartspaceMoveTransition(
         val config: IntraBlueprintTransition.Config,
-        viewModel: KeyguardClockViewModel,
+        val viewModel: KeyguardClockViewModel,
     ) : VisibilityBoundsTransition() {
         private val isLargeClock = viewModel.isLargeClockVisible.value
         override val captureSmartspace = false
@@ -340,23 +358,23 @@ class ClockSizeTransition(
             addTarget(R.id.status_view_media_container)
         }
 
-        override fun mutateBounds(
-            view: View,
-            fromIsVis: Boolean,
-            toIsVis: Boolean,
-            fromBounds: Rect,
-            toBounds: Rect,
-            fromSSBounds: Rect?,
-            toSSBounds: Rect?,
-        ) {
+        override fun initTargets(from: Target, to: Target) {
             // If view is changing visibility, hold it in place
-            if (fromIsVis == toIsVis) return
-            if (DEBUG) Log.i(TAG, "Holding position of ${view.id}")
+            if (from.isVisible == to.isVisible) return
+            if (DEBUG) Log.i(TAG, "Holding position of ${to.view.id}")
 
-            if (fromIsVis) {
-                toBounds.set(fromBounds)
+            if (from.isVisible) {
+                to.bounds.set(from.bounds)
             } else {
-                fromBounds.set(toBounds)
+                from.bounds.set(to.bounds)
+            }
+        }
+
+        override fun mutateTargets(from: Target, to: Target) {
+            if (to.view.id == sharedR.id.date_smartspace_view) {
+                to.isVisible = !viewModel.hasCustomWeatherDataDisplay.value
+                to.visibility = if (to.isVisible) View.VISIBLE else View.GONE
+                to.alpha = if (to.isVisible) 1f else 0f
             }
         }
 
diff --git a/services/core/java/com/android/server/appop/AppOpsService.java b/services/core/java/com/android/server/appop/AppOpsService.java
index 06c586f5e9c2..82a51c3e0acc 100644
--- a/services/core/java/com/android/server/appop/AppOpsService.java
+++ b/services/core/java/com/android/server/appop/AppOpsService.java
@@ -603,7 +603,7 @@ public class AppOpsService extends IAppOpsService.Stub {
         }
     }
 
-    /** Returned from {@link #verifyAndGetBypass(int, String, String, String, boolean)}. */
+    /** Returned from {@link #verifyAndGetBypass(int, String, String, int, String, boolean)}. */
     private static final class PackageVerificationResult {
 
         final RestrictionBypass bypass;
@@ -3086,10 +3086,10 @@ public class AppOpsService extends IAppOpsService.Stub {
     public int checkPackage(int uid, String packageName) {
         Objects.requireNonNull(packageName);
         try {
-            verifyAndGetBypass(uid, packageName, null, null, true);
+            verifyAndGetBypass(uid, packageName, null, Process.INVALID_UID, null, true);
             // When the caller is the system, it's possible that the packageName is the special
             // one (e.g., "root") which isn't actually existed.
-            if (resolveUid(packageName) == uid
+            if (resolveNonAppUid(packageName) == uid
                     || (isPackageExisted(packageName)
                             && !filterAppAccessUnlocked(packageName, UserHandle.getUserId(uid)))) {
                 return AppOpsManager.MODE_ALLOWED;
@@ -3288,7 +3288,7 @@ public class AppOpsService extends IAppOpsService.Stub {
             boolean shouldCollectMessage) {
         PackageVerificationResult pvr;
         try {
-            pvr = verifyAndGetBypass(uid, packageName, attributionTag, proxyPackageName);
+            pvr = verifyAndGetBypass(uid, packageName, attributionTag, proxyUid, proxyPackageName);
             if (!pvr.isAttributionTagValid) {
                 attributionTag = null;
             }
@@ -3875,7 +3875,7 @@ public class AppOpsService extends IAppOpsService.Stub {
             // Test if the proxied operation will succeed before starting the proxy operation
             final SyncNotedAppOp testProxiedOp = startOperationDryRun(code,
                     proxiedUid, resolvedProxiedPackageName, proxiedAttributionTag,
-                    proxiedVirtualDeviceId, resolvedProxyPackageName, proxiedFlags,
+                    proxiedVirtualDeviceId, proxyUid, resolvedProxyPackageName, proxiedFlags,
                     startIfModeDefault);
 
             if (!shouldStartForMode(testProxiedOp.getOpMode(), startIfModeDefault)) {
@@ -3915,7 +3915,7 @@ public class AppOpsService extends IAppOpsService.Stub {
             int attributionChainId) {
         PackageVerificationResult pvr;
         try {
-            pvr = verifyAndGetBypass(uid, packageName, attributionTag, proxyPackageName);
+            pvr = verifyAndGetBypass(uid, packageName, attributionTag, proxyUid, proxyPackageName);
             if (!pvr.isAttributionTagValid) {
                 attributionTag = null;
             }
@@ -4042,11 +4042,11 @@ public class AppOpsService extends IAppOpsService.Stub {
      */
     private SyncNotedAppOp startOperationDryRun(int code, int uid,
             @NonNull String packageName, @Nullable String attributionTag, int virtualDeviceId,
-            String proxyPackageName, @OpFlags int flags,
+            int proxyUid, String proxyPackageName, @OpFlags int flags,
             boolean startIfModeDefault) {
         PackageVerificationResult pvr;
         try {
-            pvr = verifyAndGetBypass(uid, packageName, attributionTag, proxyPackageName);
+            pvr = verifyAndGetBypass(uid, packageName, attributionTag, proxyUid, proxyPackageName);
             if (!pvr.isAttributionTagValid) {
                 attributionTag = null;
             }
@@ -4601,13 +4601,17 @@ public class AppOpsService extends IAppOpsService.Stub {
     private boolean isSpecialPackage(int callingUid, @Nullable String packageName) {
         final String resolvedPackage = AppOpsManager.resolvePackageName(callingUid, packageName);
         return callingUid == Process.SYSTEM_UID
-                || resolveUid(resolvedPackage) != Process.INVALID_UID;
+                || resolveNonAppUid(resolvedPackage) != Process.INVALID_UID;
     }
 
     private boolean isCallerAndAttributionTrusted(@NonNull AttributionSource attributionSource) {
         if (attributionSource.getUid() != Binder.getCallingUid()
                 && attributionSource.isTrusted(mContext)) {
-            return true;
+            // if there is a next attribution source, it must be trusted, as well.
+            if (attributionSource.getNext() == null
+                    || attributionSource.getNext().isTrusted(mContext)) {
+                return true;
+            }
         }
         return mContext.checkPermission(android.Manifest.permission.UPDATE_APP_OPS_STATS,
                 Binder.getCallingPid(), Binder.getCallingUid(), null)
@@ -4702,19 +4706,20 @@ public class AppOpsService extends IAppOpsService.Stub {
     }
 
     /**
-     * @see #verifyAndGetBypass(int, String, String, String, boolean)
+     * @see #verifyAndGetBypass(int, String, String, int, String, boolean)
      */
     private @NonNull PackageVerificationResult verifyAndGetBypass(int uid, String packageName,
             @Nullable String attributionTag) {
-        return verifyAndGetBypass(uid, packageName, attributionTag, null);
+        return verifyAndGetBypass(uid, packageName, attributionTag, Process.INVALID_UID, null);
     }
 
     /**
-     * @see #verifyAndGetBypass(int, String, String, String, boolean)
+     * @see #verifyAndGetBypass(int, String, String, int, String, boolean)
      */
     private @NonNull PackageVerificationResult verifyAndGetBypass(int uid, String packageName,
-            @Nullable String attributionTag, @Nullable String proxyPackageName) {
-        return verifyAndGetBypass(uid, packageName, attributionTag, proxyPackageName, false);
+            @Nullable String attributionTag, int proxyUid, @Nullable String proxyPackageName) {
+        return verifyAndGetBypass(uid, packageName, attributionTag, proxyUid, proxyPackageName,
+                false);
     }
 
     /**
@@ -4725,14 +4730,15 @@ public class AppOpsService extends IAppOpsService.Stub {
      * @param uid The uid the package belongs to
      * @param packageName The package the might belong to the uid
      * @param attributionTag attribution tag or {@code null} if no need to verify
-     * @param proxyPackageName The proxy package, from which the attribution tag is to be pulled
+     * @param proxyUid The proxy uid, from which the attribution tag is to be pulled
+     * @param proxyPackageName The proxy package, from which the attribution tag may be pulled
      * @param suppressErrorLogs Whether to print to logcat about nonmatching parameters
      *
      * @return PackageVerificationResult containing {@link RestrictionBypass} and whether the
      *         attribution tag is valid
      */
     private @NonNull PackageVerificationResult verifyAndGetBypass(int uid, String packageName,
-            @Nullable String attributionTag, @Nullable String proxyPackageName,
+            @Nullable String attributionTag, int proxyUid, @Nullable String proxyPackageName,
             boolean suppressErrorLogs) {
         if (uid == Process.ROOT_UID) {
             // For backwards compatibility, don't check package name for root UID.
@@ -4776,34 +4782,47 @@ public class AppOpsService extends IAppOpsService.Stub {
 
         int callingUid = Binder.getCallingUid();
 
-        // Allow any attribution tag for resolvable uids
-        int pkgUid;
+        // Allow any attribution tag for resolvable, non-app uids
+        int nonAppUid;
         if (Objects.equals(packageName, "com.android.shell")) {
             // Special case for the shell which is a package but should be able
             // to bypass app attribution tag restrictions.
-            pkgUid = Process.SHELL_UID;
+            nonAppUid = Process.SHELL_UID;
         } else {
-            pkgUid = resolveUid(packageName);
+            nonAppUid = resolveNonAppUid(packageName);
         }
-        if (pkgUid != Process.INVALID_UID) {
-            if (pkgUid != UserHandle.getAppId(uid)) {
+        if (nonAppUid != Process.INVALID_UID) {
+            if (nonAppUid != UserHandle.getAppId(uid)) {
                 if (!suppressErrorLogs) {
                     Slog.e(TAG, "Bad call made by uid " + callingUid + ". "
-                            + "Package \"" + packageName + "\" does not belong to uid " + uid
-                            + ".");
+                                + "Package \"" + packageName + "\" does not belong to uid " + uid
+                                + ".");
+                }
+                String otherUidMessage =
+                            DEBUG ? " but it is really " + nonAppUid : " but it is not";
+                throw new SecurityException("Specified package \"" + packageName
+                            + "\" under uid " +  UserHandle.getAppId(uid) + otherUidMessage);
+            }
+            // We only allow bypassing the attribution tag verification if the proxy is a
+            // system app (or is null), in order to prevent abusive apps clogging the appops
+            // system with unlimited attribution tags via proxy calls.
+            boolean proxyIsSystemAppOrNull = true;
+            if (proxyPackageName != null) {
+                int proxyAppId = UserHandle.getAppId(proxyUid);
+                if (proxyAppId >= Process.FIRST_APPLICATION_UID) {
+                    proxyIsSystemAppOrNull =
+                            mPackageManagerInternal.isSystemPackage(proxyPackageName);
                 }
-                String otherUidMessage = DEBUG ? " but it is really " + pkgUid : " but it is not";
-                throw new SecurityException("Specified package \"" + packageName + "\" under uid "
-                        +  UserHandle.getAppId(uid) + otherUidMessage);
             }
             return new PackageVerificationResult(RestrictionBypass.UNRESTRICTED,
-                    /* isAttributionTagValid */ true);
+                    /* isAttributionTagValid */ proxyIsSystemAppOrNull);
         }
 
         int userId = UserHandle.getUserId(uid);
         RestrictionBypass bypass = null;
         boolean isAttributionTagValid = false;
 
+        int pkgUid = nonAppUid;
         final long ident = Binder.clearCallingIdentity();
         try {
             PackageManagerInternal pmInt = LocalServices.getService(PackageManagerInternal.class);
@@ -5594,7 +5613,7 @@ public class AppOpsService extends IAppOpsService.Stub {
             if (nonpackageUid != -1) {
                 packageName = null;
             } else {
-                packageUid = resolveUid(packageName);
+                packageUid = resolveNonAppUid(packageName);
                 if (packageUid < 0) {
                     packageUid = AppGlobals.getPackageManager().getPackageUid(packageName,
                             PackageManager.MATCH_UNINSTALLED_PACKAGES, userId);
@@ -6694,7 +6713,13 @@ public class AppOpsService extends IAppOpsService.Stub {
                 if (restricted && attrOp.isRunning()) {
                     attrOp.pause();
                 } else if (attrOp.isPaused()) {
-                    attrOp.resume();
+                    RestrictionBypass bypass = verifyAndGetBypass(uid, ops.packageName, attrOp.tag)
+                            .bypass;
+                    if (!isOpRestrictedLocked(uid, code, ops.packageName, attrOp.tag,
+                            Context.DEVICE_ID_DEFAULT, bypass, false)) {
+                        // Only resume if there are no other restrictions remaining on this op
+                        attrOp.resume();
+                    }
                 }
             }
         }
@@ -7143,7 +7168,7 @@ public class AppOpsService extends IAppOpsService.Stub {
         }
     }
 
-    private static int resolveUid(String packageName)  {
+    private static int resolveNonAppUid(String packageName)  {
         if (packageName == null) {
             return Process.INVALID_UID;
         }
diff --git a/services/core/java/com/android/server/notification/NotificationManagerService.java b/services/core/java/com/android/server/notification/NotificationManagerService.java
index 7db403f5818c..2eb42b1dbc7d 100644
--- a/services/core/java/com/android/server/notification/NotificationManagerService.java
+++ b/services/core/java/com/android/server/notification/NotificationManagerService.java
@@ -2611,7 +2611,6 @@ public class NotificationManagerService extends SystemService {
                 mNotificationChannelLogger,
                 mAppOps,
                 mUserProfiles,
-                mUgmInternal,
                 mShowReviewPermissionsNotification,
                 Clock.systemUTC());
         mRankingHelper = new RankingHelper(getContext(), mRankingHandler, mPreferencesHelper,
@@ -6888,7 +6887,13 @@ public class NotificationManagerService extends SystemService {
             final Uri originalSoundUri =
                     (originalChannel != null) ? originalChannel.getSound() : null;
             if (soundUri != null && !Objects.equals(originalSoundUri, soundUri)) {
-                PermissionHelper.grantUriPermission(mUgmInternal, soundUri, sourceUid);
+                Binder.withCleanCallingIdentity(() -> {
+                    mUgmInternal.checkGrantUriPermission(sourceUid, null,
+                            ContentProvider.getUriWithoutUserId(soundUri),
+                            Intent.FLAG_GRANT_READ_URI_PERMISSION,
+                            ContentProvider.getUserIdFromUri(soundUri,
+                            UserHandle.getUserId(sourceUid)));
+                });
             }
         }
 
diff --git a/services/core/java/com/android/server/notification/NotificationRecord.java b/services/core/java/com/android/server/notification/NotificationRecord.java
index 93f512bc7e17..a865798515c8 100644
--- a/services/core/java/com/android/server/notification/NotificationRecord.java
+++ b/services/core/java/com/android/server/notification/NotificationRecord.java
@@ -1493,23 +1493,14 @@ public final class NotificationRecord {
 
             final Notification notification = getNotification();
             notification.visitUris((uri) -> {
-                if (com.android.server.notification.Flags.notificationVerifyChannelSoundUri()) {
-                    visitGrantableUri(uri, false, false);
-                } else {
-                    oldVisitGrantableUri(uri, false, false);
-                }
+                visitGrantableUri(uri, false, false);
             });
 
             if (notification.getChannelId() != null) {
                 NotificationChannel channel = getChannel();
                 if (channel != null) {
-                    if (com.android.server.notification.Flags.notificationVerifyChannelSoundUri()) {
-                        visitGrantableUri(channel.getSound(), (channel.getUserLockedFields()
-                                & NotificationChannel.USER_LOCKED_SOUND) != 0, true);
-                    } else {
-                        oldVisitGrantableUri(channel.getSound(), (channel.getUserLockedFields()
-                                & NotificationChannel.USER_LOCKED_SOUND) != 0, true);
-                    }
+                    visitGrantableUri(channel.getSound(), (channel.getUserLockedFields()
+                            & NotificationChannel.USER_LOCKED_SOUND) != 0, true);
                 }
             }
         } finally {
@@ -1525,7 +1516,7 @@ public final class NotificationRecord {
      * {@link #mGrantableUris}. Otherwise, this will either log or throw
      * {@link SecurityException} depending on target SDK of enqueuing app.
      */
-    private void oldVisitGrantableUri(Uri uri, boolean userOverriddenUri, boolean isSound) {
+    private void visitGrantableUri(Uri uri, boolean userOverriddenUri, boolean isSound) {
         if (uri == null || !ContentResolver.SCHEME_CONTENT.equals(uri.getScheme())) return;
 
         if (mGrantableUris != null && mGrantableUris.contains(uri)) {
@@ -1564,45 +1555,6 @@ public final class NotificationRecord {
         }
     }
 
-    /**
-     * Note the presence of a {@link Uri} that should have permission granted to
-     * whoever will be rendering it.
-     * <p>
-     * If the enqueuing app has the ability to grant access, it will be added to
-     * {@link #mGrantableUris}. Otherwise, this will either log or throw
-     * {@link SecurityException} depending on target SDK of enqueuing app.
-     */
-    private void visitGrantableUri(Uri uri, boolean userOverriddenUri,
-            boolean isSound) {
-        if (mGrantableUris != null && mGrantableUris.contains(uri)) {
-            return; // already verified this URI
-        }
-
-        final int sourceUid = getSbn().getUid();
-        try {
-            PermissionHelper.grantUriPermission(mUgmInternal, uri, sourceUid);
-
-            if (mGrantableUris == null) {
-                mGrantableUris = new ArraySet<>();
-            }
-            mGrantableUris.add(uri);
-        } catch (SecurityException e) {
-            if (!userOverriddenUri) {
-                if (isSound) {
-                    mSound = Settings.System.DEFAULT_NOTIFICATION_URI;
-                    Log.w(TAG, "Replacing " + uri + " from " + sourceUid + ": " + e.getMessage());
-                } else {
-                    if (mTargetSdkVersion >= Build.VERSION_CODES.P) {
-                        throw e;
-                    } else {
-                        Log.w(TAG,
-                                "Ignoring " + uri + " from " + sourceUid + ": " + e.getMessage());
-                    }
-                }
-            }
-        }
-    }
-
     public LogMaker getLogMaker(long now) {
         LogMaker lm = getSbn().getLogMaker()
                 .addTaggedData(MetricsEvent.FIELD_NOTIFICATION_CHANNEL_IMPORTANCE, mImportance)
diff --git a/services/core/java/com/android/server/notification/PermissionHelper.java b/services/core/java/com/android/server/notification/PermissionHelper.java
index 1464d481311a..b6f48890c528 100644
--- a/services/core/java/com/android/server/notification/PermissionHelper.java
+++ b/services/core/java/com/android/server/notification/PermissionHelper.java
@@ -25,25 +25,19 @@ import android.Manifest;
 import android.annotation.NonNull;
 import android.annotation.UserIdInt;
 import android.companion.virtual.VirtualDeviceManager;
-import android.content.ContentProvider;
-import android.content.ContentResolver;
 import android.content.Context;
-import android.content.Intent;
 import android.content.pm.IPackageManager;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.ParceledListSlice;
-import android.net.Uri;
 import android.os.Binder;
 import android.os.RemoteException;
-import android.os.UserHandle;
 import android.permission.IPermissionManager;
 import android.util.ArrayMap;
 import android.util.Pair;
 import android.util.Slog;
 
 import com.android.internal.util.ArrayUtils;
-import com.android.server.uri.UriGrantsManagerInternal;
 
 import java.util.Collections;
 import java.util.HashSet;
@@ -64,7 +58,7 @@ public final class PermissionHelper {
     private final IPermissionManager mPermManager;
 
     public PermissionHelper(Context context, IPackageManager packageManager,
-                IPermissionManager permManager) {
+            IPermissionManager permManager) {
         mContext = context;
         mPackageManager = packageManager;
         mPermManager = permManager;
@@ -304,19 +298,6 @@ public final class PermissionHelper {
         return false;
     }
 
-    static void grantUriPermission(final UriGrantsManagerInternal ugmInternal, Uri uri,
-            int sourceUid) {
-        if (uri == null || !ContentResolver.SCHEME_CONTENT.equals(uri.getScheme())) return;
-
-        Binder.withCleanCallingIdentity(() -> {
-            // This will throw a SecurityException if the caller can't grant.
-            ugmInternal.checkGrantUriPermission(sourceUid, null,
-                    ContentProvider.getUriWithoutUserId(uri),
-                    Intent.FLAG_GRANT_READ_URI_PERMISSION,
-                    ContentProvider.getUserIdFromUri(uri, UserHandle.getUserId(sourceUid)));
-        });
-    }
-
     public static class PackagePermission {
         public final String packageName;
         public final @UserIdInt int userId;
diff --git a/services/core/java/com/android/server/notification/PreferencesHelper.java b/services/core/java/com/android/server/notification/PreferencesHelper.java
index 15377d6b269a..a5ecd8ebc0ba 100644
--- a/services/core/java/com/android/server/notification/PreferencesHelper.java
+++ b/services/core/java/com/android/server/notification/PreferencesHelper.java
@@ -101,7 +101,6 @@ import com.android.internal.util.XmlUtils;
 import com.android.modules.utils.TypedXmlPullParser;
 import com.android.modules.utils.TypedXmlSerializer;
 import com.android.server.notification.PermissionHelper.PackagePermission;
-import com.android.server.uri.UriGrantsManagerInternal;
 
 import org.json.JSONArray;
 import org.json.JSONException;
@@ -228,7 +227,6 @@ public class PreferencesHelper implements RankingConfig {
     private final NotificationChannelLogger mNotificationChannelLogger;
     private final AppOpsManager mAppOps;
     private final ManagedServices.UserProfiles mUserProfiles;
-    private final UriGrantsManagerInternal mUgmInternal;
 
     private SparseBooleanArray mBadgingEnabled;
     private SparseBooleanArray mBubblesEnabled;
@@ -249,7 +247,6 @@ public class PreferencesHelper implements RankingConfig {
             ZenModeHelper zenHelper, PermissionHelper permHelper, PermissionManager permManager,
             NotificationChannelLogger notificationChannelLogger,
             AppOpsManager appOpsManager, ManagedServices.UserProfiles userProfiles,
-            UriGrantsManagerInternal ugmInternal,
             boolean showReviewPermissionsNotification, Clock clock) {
         mContext = context;
         mZenModeHelper = zenHelper;
@@ -260,7 +257,6 @@ public class PreferencesHelper implements RankingConfig {
         mNotificationChannelLogger = notificationChannelLogger;
         mAppOps = appOpsManager;
         mUserProfiles = userProfiles;
-        mUgmInternal = ugmInternal;
         mShowReviewPermissionsNotification = showReviewPermissionsNotification;
         mIsMediaNotificationFilteringEnabled = context.getResources()
                 .getBoolean(R.bool.config_quickSettingsShowMediaPlayer);
@@ -1168,13 +1164,6 @@ public class PreferencesHelper implements RankingConfig {
                 }
                 clearLockedFieldsLocked(channel);
 
-                // Verify that the app has permission to read the sound Uri
-                // Only check for new channels, as regular apps can only set sound
-                // before creating. See: {@link NotificationChannel#setSound}
-                if (Flags.notificationVerifyChannelSoundUri()) {
-                    PermissionHelper.grantUriPermission(mUgmInternal, channel.getSound(), uid);
-                }
-
                 channel.setImportanceLockedByCriticalDeviceFunction(
                         r.defaultAppLockedImportance || r.fixedImportance);
 
diff --git a/services/core/java/com/android/server/notification/flags.aconfig b/services/core/java/com/android/server/notification/flags.aconfig
index 65a38ae1fcde..76ebb4749473 100644
--- a/services/core/java/com/android/server/notification/flags.aconfig
+++ b/services/core/java/com/android/server/notification/flags.aconfig
@@ -171,16 +171,6 @@ flag {
   bug: "358524009"
 }
 
-flag {
-  name: "notification_verify_channel_sound_uri"
-  namespace: "systemui"
-  description: "Verify Uri permission for sound when creating a notification channel"
-  bug: "337775777"
-  metadata {
-    purpose: PURPOSE_BUGFIX
-  }
-}
-
 flag {
   name: "notification_vibration_in_sound_uri_for_channel"
   namespace: "systemui"
diff --git a/services/core/java/com/android/server/pm/UserRestrictionsUtils.java b/services/core/java/com/android/server/pm/UserRestrictionsUtils.java
index 2bc6d53147fb..a1082481abb8 100644
--- a/services/core/java/com/android/server/pm/UserRestrictionsUtils.java
+++ b/services/core/java/com/android/server/pm/UserRestrictionsUtils.java
@@ -309,7 +309,8 @@ public class UserRestrictionsUtils {
      * in settings. So it is handled separately.
      */
     private static final Set<String> DEFAULT_ENABLED_FOR_MANAGED_PROFILES = Sets.newArraySet(
-            UserManager.DISALLOW_BLUETOOTH_SHARING
+            UserManager.DISALLOW_BLUETOOTH_SHARING,
+            UserManager.DISALLOW_DEBUGGING_FEATURES
     );
 
     /**
diff --git a/services/core/java/com/android/server/policy/PhoneWindowManager.java b/services/core/java/com/android/server/policy/PhoneWindowManager.java
index f1a481155458..80527541b150 100644
--- a/services/core/java/com/android/server/policy/PhoneWindowManager.java
+++ b/services/core/java/com/android/server/policy/PhoneWindowManager.java
@@ -3576,7 +3576,7 @@ public class PhoneWindowManager implements WindowManagerPolicy {
                 }
                 break;
             case KeyEvent.KEYCODE_I:
-                if (firstDown && event.isMetaPressed()) {
+                if (firstDown && event.isMetaPressed() && isUserSetupComplete() && !keyguardOn) {
                     showSystemSettings();
                     notifyKeyGestureCompleted(event,
                             KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_SYSTEM_SETTINGS);
@@ -4149,6 +4149,7 @@ public class PhoneWindowManager implements WindowManagerPolicy {
         int displayId = event.getDisplayId();
         int modifierState = event.getModifierState();
         boolean keyguardOn = keyguardOn();
+        boolean canLaunchApp = isUserSetupComplete() && !keyguardOn;
         switch (gestureType) {
             case KeyGestureEvent.KEY_GESTURE_TYPE_RECENT_APPS:
                 if (complete) {
@@ -4166,7 +4167,7 @@ public class PhoneWindowManager implements WindowManagerPolicy {
                 return true;
             case KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_ASSISTANT:
             case KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_VOICE_ASSISTANT:
-                if (complete) {
+                if (complete && canLaunchApp) {
                     launchAssistAction(Intent.EXTRA_ASSIST_INPUT_HINT_KEYBOARD,
                             deviceId, SystemClock.uptimeMillis(),
                             AssistUtils.INVOCATION_TYPE_UNKNOWN);
@@ -4179,7 +4180,7 @@ public class PhoneWindowManager implements WindowManagerPolicy {
                 }
                 return true;
             case KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_SYSTEM_SETTINGS:
-                if (complete) {
+                if (complete && canLaunchApp) {
                     showSystemSettings();
                 }
                 return true;
@@ -4282,7 +4283,7 @@ public class PhoneWindowManager implements WindowManagerPolicy {
                 }
                 return true;
             case KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_SEARCH:
-                if (complete) {
+                if (complete && canLaunchApp) {
                     launchTargetSearchActivity();
                 }
                 return true;
@@ -4363,8 +4364,8 @@ public class PhoneWindowManager implements WindowManagerPolicy {
                 break;
             case KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_APPLICATION:
                 AppLaunchData data = event.getAppLaunchData();
-                if (complete && isUserSetupComplete() && !keyguardOn
-                        && data != null && mModifierShortcutManager.launchApplication(data)) {
+                if (complete && canLaunchApp && data != null
+                        && mModifierShortcutManager.launchApplication(data)) {
                     dismissKeyboardShortcutsMenu();
                 }
                 return true;
diff --git a/services/core/java/com/android/server/wm/RootWindowContainer.java b/services/core/java/com/android/server/wm/RootWindowContainer.java
index 46312aff1fb6..a83b25eb009a 100644
--- a/services/core/java/com/android/server/wm/RootWindowContainer.java
+++ b/services/core/java/com/android/server/wm/RootWindowContainer.java
@@ -882,7 +882,9 @@ class RootWindowContainer extends WindowContainer<DisplayContent>
         if (!mWmService.mDisplayFrozen) {
             // Post these on a handler such that we don't call into power manager service while
             // holding the window manager lock to avoid lock contention with power manager lock.
-            mHandler.obtainMessage(SET_SCREEN_BRIGHTNESS_OVERRIDE, mDisplayBrightnessOverrides)
+            // Send a copy of the brightness overrides as they may be cleared before being sent out.
+            mHandler.obtainMessage(SET_SCREEN_BRIGHTNESS_OVERRIDE,
+                    mDisplayBrightnessOverrides.clone())
                     .sendToTarget();
             mHandler.obtainMessage(SET_USER_ACTIVITY_TIMEOUT, mUserActivityTimeout).sendToTarget();
         }
diff --git a/services/core/java/com/android/server/wm/Transition.java b/services/core/java/com/android/server/wm/Transition.java
index 1fc609b7d03a..3e7fbf4e97fe 100644
--- a/services/core/java/com/android/server/wm/Transition.java
+++ b/services/core/java/com/android/server/wm/Transition.java
@@ -1497,16 +1497,15 @@ class Transition implements BLASTSyncEngine.TransactionReadyListener {
         }
 
         // Update the input-sink (touch-blocking) state now that the animation is finished.
-        SurfaceControl.Transaction inputSinkTransaction = null;
+        boolean scheduleAnimation = false;
         for (int i = 0; i < mParticipants.size(); ++i) {
             final ActivityRecord ar = mParticipants.valueAt(i).asActivityRecord();
             if (ar == null || !ar.isVisible() || ar.getParent() == null) continue;
-            if (inputSinkTransaction == null) {
-                inputSinkTransaction = ar.mWmService.mTransactionFactory.get();
-            }
-            ar.mActivityRecordInputSink.applyChangesToSurfaceIfChanged(inputSinkTransaction);
+            scheduleAnimation = true;
+            ar.mActivityRecordInputSink.applyChangesToSurfaceIfChanged(ar.getPendingTransaction());
         }
-        if (inputSinkTransaction != null) inputSinkTransaction.apply();
+        // To apply pending transactions.
+        if (scheduleAnimation) mController.mAtm.mWindowManager.scheduleAnimationLocked();
 
         // Always schedule stop processing when transition finishes because activities don't
         // stop while they are in a transition thus their stop could still be pending.
diff --git a/services/devicepolicy/java/com/android/server/devicepolicy/DevicePolicyManagerService.java b/services/devicepolicy/java/com/android/server/devicepolicy/DevicePolicyManagerService.java
index 2627895b8c63..62d6258575a9 100644
--- a/services/devicepolicy/java/com/android/server/devicepolicy/DevicePolicyManagerService.java
+++ b/services/devicepolicy/java/com/android/server/devicepolicy/DevicePolicyManagerService.java
@@ -2723,16 +2723,16 @@ public class DevicePolicyManagerService extends IDevicePolicyManager.Stub {
         }
     }
 
-    /**
-     * Apply default restrictions that haven't been applied to a given admin yet.
-     */
+    /** Apply default restrictions that haven't been applied to a given admin yet. */
     private void maybeSetDefaultRestrictionsForAdminLocked(int userId, ActiveAdmin admin) {
-        Set<String> defaultRestrictions =
-                UserRestrictionsUtils.getDefaultEnabledForManagedProfiles();
-        if (defaultRestrictions.equals(admin.defaultEnabledRestrictionsAlreadySet)) {
+        Set<String> newDefaultRestrictions = new HashSet(
+            UserRestrictionsUtils.getDefaultEnabledForManagedProfiles());
+        newDefaultRestrictions.removeAll(admin.defaultEnabledRestrictionsAlreadySet);
+        if (newDefaultRestrictions.isEmpty()) {
             return; // The same set of default restrictions has been already applied.
         }
-        for (String restriction : defaultRestrictions) {
+
+        for (String restriction : newDefaultRestrictions) {
             mDevicePolicyEngine.setLocalPolicy(
                     PolicyDefinition.getPolicyDefinitionForUserRestriction(restriction),
                     EnforcingAdmin.createEnterpriseEnforcingAdmin(
@@ -2740,10 +2740,9 @@ public class DevicePolicyManagerService extends IDevicePolicyManager.Stub {
                             admin.getUserHandle().getIdentifier()),
                     new BooleanPolicyValue(true),
                     userId);
+            admin.defaultEnabledRestrictionsAlreadySet.add(restriction);
+            Slogf.i(LOG_TAG, "Enabled the following restriction by default: " + restriction);
         }
-        admin.defaultEnabledRestrictionsAlreadySet.addAll(defaultRestrictions);
-        Slogf.i(LOG_TAG, "Enabled the following restrictions by default: "
-                + defaultRestrictions);
     }
 
     private void maybeStartSecurityLogMonitorOnActivityManagerReady() {
@@ -10329,7 +10328,8 @@ public class DevicePolicyManagerService extends IDevicePolicyManager.Stub {
                 return false;
             }
 
-            if (isAdb(caller)) {
+            boolean isAdb = isAdb(caller);
+            if (isAdb) {
                 // Log profile owner provisioning was started using adb.
                 MetricsLogger.action(mContext, PROVISIONING_ENTRY_POINT_ADB, LOG_TAG_PROFILE_OWNER);
                 DevicePolicyEventLogger
@@ -10352,6 +10352,18 @@ public class DevicePolicyManagerService extends IDevicePolicyManager.Stub {
                     ensureUnknownSourcesRestrictionForProfileOwnerLocked(userHandle, admin,
                             true /* newOwner */);
                 }
+                if(isAdb) {
+                    // DISALLOW_DEBUGGING_FEATURES is being added to newly-created
+                    // work profile by default due to b/382064697 . This would have
+                    //  impacted certain CTS test flows when they interact with the
+                    // work profile via ADB (for example installing an app into the
+                    // work profile). Remove DISALLOW_DEBUGGING_FEATURES here to
+                    // reduce the potential impact.
+                    setLocalUserRestrictionInternal(
+                        EnforcingAdmin.createEnterpriseEnforcingAdmin(who, userHandle),
+                        UserManager.DISALLOW_DEBUGGING_FEATURES, false, userHandle);
+                }
+
                 sendOwnerChangedBroadcast(DevicePolicyManager.ACTION_PROFILE_OWNER_CHANGED,
                         userHandle);
             });
diff --git a/services/tests/uiservicestests/src/com/android/server/notification/NotificationManagerServiceTest.java b/services/tests/uiservicestests/src/com/android/server/notification/NotificationManagerServiceTest.java
index 074cbb57d5b7..f5361765fd0e 100644
--- a/services/tests/uiservicestests/src/com/android/server/notification/NotificationManagerServiceTest.java
+++ b/services/tests/uiservicestests/src/com/android/server/notification/NotificationManagerServiceTest.java
@@ -5185,41 +5185,6 @@ public class NotificationManagerServiceTest extends UiServiceTestCase {
                 eq(NotificationListenerService.NOTIFICATION_CHANNEL_OR_GROUP_UPDATED));
     }
 
-    @Test
-    public void
-        updateNotificationChannelFromPrivilegedListener_oldSoundNoUriPerm_newSoundHasUriPerm()
-            throws Exception {
-        mService.setPreferencesHelper(mPreferencesHelper);
-        when(mCompanionMgr.getAssociations(mPkg, mUserId))
-                .thenReturn(singletonList(mock(AssociationInfo.class)));
-        when(mPreferencesHelper.getNotificationChannel(eq(mPkg), anyInt(),
-                eq(mTestNotificationChannel.getId()), anyBoolean()))
-                .thenReturn(mTestNotificationChannel);
-
-        // Missing Uri permissions for the old channel sound
-        final Uri oldSoundUri = Settings.System.DEFAULT_NOTIFICATION_URI;
-        doThrow(new SecurityException("no access")).when(mUgmInternal)
-                .checkGrantUriPermission(eq(Process.myUid()), any(), eq(oldSoundUri),
-                anyInt(), eq(Process.myUserHandle().getIdentifier()));
-
-        // Has Uri permissions for the old channel sound
-        final Uri newSoundUri = Uri.parse("content://media/test/sound/uri");
-        final NotificationChannel updatedNotificationChannel = new NotificationChannel(
-                TEST_CHANNEL_ID, TEST_CHANNEL_ID, IMPORTANCE_DEFAULT);
-        updatedNotificationChannel.setSound(newSoundUri,
-                updatedNotificationChannel.getAudioAttributes());
-
-        mBinderService.updateNotificationChannelFromPrivilegedListener(
-                null, mPkg, Process.myUserHandle(), updatedNotificationChannel);
-
-        verify(mPreferencesHelper, times(1)).updateNotificationChannel(
-                anyString(), anyInt(), any(), anyBoolean(),  anyInt(), anyBoolean());
-
-        verify(mListeners, never()).notifyNotificationChannelChanged(eq(mPkg),
-                eq(Process.myUserHandle()), eq(mTestNotificationChannel),
-                eq(NotificationListenerService.NOTIFICATION_CHANNEL_OR_GROUP_UPDATED));
-    }
-
     @Test
     public void testGetNotificationChannelFromPrivilegedListener_cdm_success() throws Exception {
         mService.setPreferencesHelper(mPreferencesHelper);
diff --git a/services/tests/uiservicestests/src/com/android/server/notification/PreferencesHelperTest.java b/services/tests/uiservicestests/src/com/android/server/notification/PreferencesHelperTest.java
index b015c8cf8225..c8fa7c51c6d8 100644
--- a/services/tests/uiservicestests/src/com/android/server/notification/PreferencesHelperTest.java
+++ b/services/tests/uiservicestests/src/com/android/server/notification/PreferencesHelperTest.java
@@ -46,13 +46,11 @@ import static android.app.NotificationManager.IMPORTANCE_MAX;
 import static android.app.NotificationManager.IMPORTANCE_NONE;
 import static android.app.NotificationManager.IMPORTANCE_UNSPECIFIED;
 import static android.app.NotificationManager.VISIBILITY_NO_OVERRIDE;
-import static android.content.ContentResolver.SCHEME_ANDROID_RESOURCE;
-import static android.content.ContentResolver.SCHEME_CONTENT;
-import static android.content.ContentResolver.SCHEME_FILE;
 import static android.media.AudioAttributes.CONTENT_TYPE_SONIFICATION;
 import static android.media.AudioAttributes.USAGE_NOTIFICATION;
 import static android.os.UserHandle.USER_ALL;
 import static android.os.UserHandle.USER_SYSTEM;
+
 import static android.platform.test.flag.junit.SetFlagsRule.DefaultInitValueType.DEVICE_DEFAULT;
 import static android.service.notification.Adjustment.TYPE_CONTENT_RECOMMENDATION;
 import static android.service.notification.Adjustment.TYPE_NEWS;
@@ -66,7 +64,7 @@ import static com.android.internal.config.sysui.SystemUiSystemPropertiesFlags.No
 import static com.android.internal.util.FrameworkStatsLog.PACKAGE_NOTIFICATION_PREFERENCES__FSI_STATE__DENIED;
 import static com.android.internal.util.FrameworkStatsLog.PACKAGE_NOTIFICATION_PREFERENCES__FSI_STATE__GRANTED;
 import static com.android.internal.util.FrameworkStatsLog.PACKAGE_NOTIFICATION_PREFERENCES__FSI_STATE__NOT_REQUESTED;
-import static com.android.server.notification.Flags.FLAG_NOTIFICATION_VERIFY_CHANNEL_SOUND_URI;
+import static com.android.server.notification.Flags.FLAG_ALL_NOTIFS_NEED_TTL;
 import static com.android.server.notification.Flags.FLAG_PERSIST_INCOMPLETE_RESTORE_DATA;
 import static com.android.server.notification.NotificationChannelLogger.NotificationChannelEvent.NOTIFICATION_CHANNEL_UPDATED_BY_USER;
 import static com.android.server.notification.PreferencesHelper.DEFAULT_BUBBLE_PREFERENCE;
@@ -93,7 +91,6 @@ import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.clearInvocations;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
-import static org.mockito.Mockito.doThrow;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.reset;
@@ -380,10 +377,10 @@ public class PreferencesHelperTest extends UiServiceTestCase {
 
         mHelper = new PreferencesHelper(getContext(), mPm, mHandler, mMockZenModeHelper,
                 mPermissionHelper, mPermissionManager, mLogger, mAppOpsManager, mUserProfiles,
-                mUgmInternal, false, mClock);
+                false, mClock);
         mXmlHelper = new PreferencesHelper(getContext(), mPm, mHandler, mMockZenModeHelper,
                 mPermissionHelper, mPermissionManager, mLogger, mAppOpsManager, mUserProfiles,
-                mUgmInternal, false, mClock);
+                false, mClock);
         resetZenModeHelper();
 
         mAudioAttributes = new AudioAttributes.Builder()
@@ -795,7 +792,7 @@ public class PreferencesHelperTest extends UiServiceTestCase {
     public void testReadXml_oldXml_migrates() throws Exception {
         mXmlHelper = new PreferencesHelper(getContext(), mPm, mHandler, mMockZenModeHelper,
                 mPermissionHelper, mPermissionManager, mLogger, mAppOpsManager, mUserProfiles,
-                mUgmInternal, /* showReviewPermissionsNotification= */ true, mClock);
+                /* showReviewPermissionsNotification= */ true, mClock);
 
         String xml = "<ranking version=\"2\">\n"
                 + "<package name=\"" + PKG_N_MR1 + "\" uid=\"" + UID_N_MR1
@@ -931,7 +928,7 @@ public class PreferencesHelperTest extends UiServiceTestCase {
     public void testReadXml_newXml_noMigration_showPermissionNotification() throws Exception {
         mXmlHelper = new PreferencesHelper(getContext(), mPm, mHandler, mMockZenModeHelper,
                 mPermissionHelper, mPermissionManager, mLogger, mAppOpsManager, mUserProfiles,
-                mUgmInternal, /* showReviewPermissionsNotification= */ true, mClock);
+                /* showReviewPermissionsNotification= */ true, mClock);
 
         String xml = "<ranking version=\"3\">\n"
                 + "<package name=\"" + PKG_N_MR1 + "\" show_badge=\"true\">\n"
@@ -990,7 +987,7 @@ public class PreferencesHelperTest extends UiServiceTestCase {
     public void testReadXml_newXml_permissionNotificationOff() throws Exception {
         mHelper = new PreferencesHelper(getContext(), mPm, mHandler, mMockZenModeHelper,
                 mPermissionHelper, mPermissionManager, mLogger, mAppOpsManager, mUserProfiles,
-                mUgmInternal, /* showReviewPermissionsNotification= */ false, mClock);
+                /* showReviewPermissionsNotification= */ false, mClock);
 
         String xml = "<ranking version=\"3\">\n"
                 + "<package name=\"" + PKG_N_MR1 + "\" show_badge=\"true\">\n"
@@ -1049,7 +1046,7 @@ public class PreferencesHelperTest extends UiServiceTestCase {
     public void testReadXml_newXml_noMigration_noPermissionNotification() throws Exception {
         mHelper = new PreferencesHelper(getContext(), mPm, mHandler, mMockZenModeHelper,
                 mPermissionHelper, mPermissionManager, mLogger, mAppOpsManager, mUserProfiles,
-                mUgmInternal, /* showReviewPermissionsNotification= */ true, mClock);
+                /* showReviewPermissionsNotification= */ true, mClock);
 
         String xml = "<ranking version=\"4\">\n"
                 + "<package name=\"" + PKG_N_MR1 + "\" show_badge=\"true\">\n"
@@ -1643,7 +1640,7 @@ public class PreferencesHelperTest extends UiServiceTestCase {
         // simulate load after reboot
         mXmlHelper = new PreferencesHelper(getContext(), mPm, mHandler, mMockZenModeHelper,
                 mPermissionHelper, mPermissionManager, mLogger, mAppOpsManager, mUserProfiles,
-                mUgmInternal, false, mClock);
+                false, mClock);
         loadByteArrayXml(baos.toByteArray(), false, USER_ALL);
 
         // Trigger 2nd restore pass
@@ -1698,7 +1695,7 @@ public class PreferencesHelperTest extends UiServiceTestCase {
         // simulate load after reboot
         mXmlHelper = new PreferencesHelper(getContext(), mPm, mHandler, mMockZenModeHelper,
                 mPermissionHelper, mPermissionManager, mLogger, mAppOpsManager, mUserProfiles,
-                mUgmInternal, false, mClock);
+                false, mClock);
         loadByteArrayXml(xml.getBytes(), false, USER_ALL);
 
         // Trigger 2nd restore pass
@@ -1776,10 +1773,10 @@ public class PreferencesHelperTest extends UiServiceTestCase {
 
         mHelper = new PreferencesHelper(mContext, mPm, mHandler, mMockZenModeHelper,
                 mPermissionHelper, mPermissionManager, mLogger, mAppOpsManager, mUserProfiles,
-                mUgmInternal, false, mClock);
+                false, mClock);
         mXmlHelper = new PreferencesHelper(mContext, mPm, mHandler, mMockZenModeHelper,
                 mPermissionHelper, mPermissionManager, mLogger, mAppOpsManager, mUserProfiles,
-                mUgmInternal, false, mClock);
+                false, mClock);
 
         NotificationChannel channel =
                 new NotificationChannel("id", "name", IMPORTANCE_LOW);
@@ -3189,64 +3186,6 @@ public class PreferencesHelperTest extends UiServiceTestCase {
                 PKG_N_MR1, UID_N_MR1, channel.getId(), false).getSound());
     }
 
-    @Test
-    @EnableFlags(FLAG_NOTIFICATION_VERIFY_CHANNEL_SOUND_URI)
-    public void testCreateChannel_noSoundUriPermission_contentSchemeVerified() {
-        final Uri sound = Uri.parse(SCHEME_CONTENT + "://media/test/sound/uri");
-
-        doThrow(new SecurityException("no access")).when(mUgmInternal)
-                .checkGrantUriPermission(eq(UID_N_MR1), any(), eq(sound),
-                    anyInt(), eq(Process.myUserHandle().getIdentifier()));
-
-        final NotificationChannel channel = new NotificationChannel("id2", "name2",
-                NotificationManager.IMPORTANCE_DEFAULT);
-        channel.setSound(sound, mAudioAttributes);
-
-        assertThrows(SecurityException.class,
-                () -> mHelper.createNotificationChannel(PKG_N_MR1, UID_N_MR1, channel,
-                    true, false, UID_N_MR1, false));
-        assertThat(mHelper.getNotificationChannel(PKG_N_MR1, UID_N_MR1, channel.getId(), true))
-                .isNull();
-    }
-
-    @Test
-    @EnableFlags(FLAG_NOTIFICATION_VERIFY_CHANNEL_SOUND_URI)
-    public void testCreateChannel_noSoundUriPermission_fileSchemaIgnored() {
-        final Uri sound = Uri.parse(SCHEME_FILE + "://path/sound");
-
-        doThrow(new SecurityException("no access")).when(mUgmInternal)
-                .checkGrantUriPermission(eq(UID_N_MR1), any(), any(),
-                    anyInt(), eq(Process.myUserHandle().getIdentifier()));
-
-        final NotificationChannel channel = new NotificationChannel("id2", "name2",
-                NotificationManager.IMPORTANCE_DEFAULT);
-        channel.setSound(sound, mAudioAttributes);
-
-        mHelper.createNotificationChannel(PKG_N_MR1, UID_N_MR1, channel, true, false, UID_N_MR1,
-                false);
-        assertThat(mHelper.getNotificationChannel(PKG_N_MR1, UID_N_MR1, channel.getId(), true)
-                .getSound()).isEqualTo(sound);
-    }
-
-    @Test
-    @EnableFlags(FLAG_NOTIFICATION_VERIFY_CHANNEL_SOUND_URI)
-    public void testCreateChannel_noSoundUriPermission_resourceSchemaIgnored() {
-        final Uri sound = Uri.parse(SCHEME_ANDROID_RESOURCE + "://resId/sound");
-
-        doThrow(new SecurityException("no access")).when(mUgmInternal)
-                .checkGrantUriPermission(eq(UID_N_MR1), any(), any(),
-                    anyInt(), eq(Process.myUserHandle().getIdentifier()));
-
-        final NotificationChannel channel = new NotificationChannel("id2", "name2",
-                NotificationManager.IMPORTANCE_DEFAULT);
-        channel.setSound(sound, mAudioAttributes);
-
-        mHelper.createNotificationChannel(PKG_N_MR1, UID_N_MR1, channel, true, false, UID_N_MR1,
-                false);
-        assertThat(mHelper.getNotificationChannel(PKG_N_MR1, UID_N_MR1, channel.getId(), true)
-                .getSound()).isEqualTo(sound);
-    }
-
     @Test
     public void testPermanentlyDeleteChannels() throws Exception {
         NotificationChannel channel1 =
diff --git a/services/tests/wmtests/src/com/android/server/policy/KeyGestureEventTests.java b/services/tests/wmtests/src/com/android/server/policy/KeyGestureEventTests.java
index 41865b209f01..6c8c82618489 100644
--- a/services/tests/wmtests/src/com/android/server/policy/KeyGestureEventTests.java
+++ b/services/tests/wmtests/src/com/android/server/policy/KeyGestureEventTests.java
@@ -808,4 +808,44 @@ public class KeyGestureEventTests extends ShortcutKeyTestBase {
                 sendKeyGestureEventComplete(KeyGestureEvent.KEY_GESTURE_TYPE_TOGGLE_BOUNCE_KEYS));
         Assert.assertFalse(InputSettings.isAccessibilityBounceKeysEnabled(mContext));
     }
+
+    @Test
+    public void testLaunchSettingsAndSearchDoesntOpenAnything_withKeyguardOn() {
+        mPhoneWindowManager.overrideKeyguardOn(true);
+
+        sendKeyGestureEventComplete(KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_SYSTEM_SETTINGS);
+        sendKeyGestureEventComplete(KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_SEARCH);
+
+        mPhoneWindowManager.assertNoActivityLaunched();
+    }
+
+    @Test
+    public void testLaunchSettingsAndSearchDoesntOpenAnything_withUserSetupIncomplete() {
+        mPhoneWindowManager.overrideIsUserSetupComplete(false);
+
+        sendKeyGestureEventComplete(KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_SYSTEM_SETTINGS);
+        sendKeyGestureEventComplete(KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_SEARCH);
+
+        mPhoneWindowManager.assertNoActivityLaunched();
+    }
+
+    @Test
+    public void testLaunchAssistantDoesntWork_withKeyguardOn() {
+        mPhoneWindowManager.overrideKeyguardOn(true);
+
+        sendKeyGestureEventComplete(KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_ASSISTANT);
+        sendKeyGestureEventComplete(KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_VOICE_ASSISTANT);
+
+        mPhoneWindowManager.assertSearchManagerDoesntLaunchAssist();
+    }
+
+    @Test
+    public void testLaunchAssistantDoesntWork_withUserSetupIncomplete() {
+        mPhoneWindowManager.overrideIsUserSetupComplete(false);
+
+        sendKeyGestureEventComplete(KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_ASSISTANT);
+        sendKeyGestureEventComplete(KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_VOICE_ASSISTANT);
+
+        mPhoneWindowManager.assertSearchManagerDoesntLaunchAssist();
+    }
 }
diff --git a/services/tests/wmtests/src/com/android/server/policy/TestPhoneWindowManager.java b/services/tests/wmtests/src/com/android/server/policy/TestPhoneWindowManager.java
index 9db76d47fed7..8ea3a34be86e 100644
--- a/services/tests/wmtests/src/com/android/server/policy/TestPhoneWindowManager.java
+++ b/services/tests/wmtests/src/com/android/server/policy/TestPhoneWindowManager.java
@@ -563,6 +563,10 @@ class TestPhoneWindowManager {
         doNothing().when(mPhoneWindowManager).launchHomeFromHotKey(anyInt());
     }
 
+    void overrideKeyguardOn(boolean isKeyguardOn) {
+        doReturn(isKeyguardOn).when(mPhoneWindowManager).keyguardOn();
+    }
+
     void overrideIsUserSetupComplete(boolean isCompleted) {
         doReturn(isCompleted).when(mPhoneWindowManager).isUserSetupComplete();
     }
@@ -725,6 +729,11 @@ class TestPhoneWindowManager {
         verify(mSearchManager).launchAssist(any());
     }
 
+    void assertSearchManagerDoesntLaunchAssist() {
+        mTestLooper.dispatchAll();
+        verify(mSearchManager, never()).launchAssist(any());
+    }
+
     void assertLaunchSystemSettings() {
         mTestLooper.dispatchAll();
         ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
@@ -929,4 +938,10 @@ class TestPhoneWindowManager {
         verify(mInputManagerInternal)
                 .handleKeyGestureInKeyGestureController(anyInt(), any(), anyInt(), eq(gestureType));
     }
+
+    void assertNoActivityLaunched() {
+        mTestLooper.dispatchAll();
+        verify(mContext, never()).startActivityAsUser(any(), any(), any());
+        verify(mContext, never()).startActivityAsUser(any(), any());
+    }
 }
```

