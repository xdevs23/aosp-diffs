```diff
diff --git a/METADATA b/METADATA
index 2bdcd860..d8cf5548 100644
--- a/METADATA
+++ b/METADATA
@@ -1,15 +1,20 @@
-name: "leakcanary2"
-description:
-    "Memory leak detection library for Android."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/leakcanary2
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "leakcanary2"
+description: "Memory leak detection library for Android."
 third_party {
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 4
+    day: 25
+  }
   identifier {
     type: "Git"
     value: "https://github.com/square/leakcanary"
+    version: "v2.14"
     primary_source: true
-    version: "2.13"
   }
-  license_type: NOTICE
-  version: "2.13"
-  last_upgrade_date { year: 2024 month: 5 day: 20 }
 }
diff --git a/OWNERS b/OWNERS
index a2a42685..2e8f086e 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1 @@
 include platform/system/core:main:/janitors/OWNERS
-include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/docs/changelog.md b/docs/changelog.md
index 8c76d0cf..ddeecc11 100644
--- a/docs/changelog.md
+++ b/docs/changelog.md
@@ -5,7 +5,7 @@ Please thank our [contributors](https://github.com/square/leakcanary/graphs/cont
 
 I've started working on LeakCanary 3.0 so new 2.x releases only contain bug fixes and new known leak patterns.
 
-## Version 2.13 (2024-01-01)
+## Version 2.13 (2024-01-03)
 
 * 🐛 [#2565](https://github.com/square/leakcanary/issues/2565) Fix AndroidX Fragments incorrectly marked as leaking if detached but not destroyed.
 * 💥 [#2568](https://github.com/square/leakcanary/issues/2568) Fixed missing `RECEIVER_EXPORTED` flag when calling `registerReceiver()` on API 34+.
diff --git a/gradle.properties b/gradle.properties
index f55484e6..d344eb2d 100644
--- a/gradle.properties
+++ b/gradle.properties
@@ -1,5 +1,5 @@
 GROUP=com.squareup.leakcanary
-VERSION_NAME=2.13
+VERSION_NAME=2.14
 
 POM_DESCRIPTION=LeakCanary
 POM_INCEPTION_YEAR=2015
diff --git a/leakcanary-android-core/src/main/java/leakcanary/internal/HeapAnalyzerWorker.kt b/leakcanary-android-core/src/main/java/leakcanary/internal/HeapAnalyzerWorker.kt
index f2186c40..a4b69cca 100644
--- a/leakcanary-android-core/src/main/java/leakcanary/internal/HeapAnalyzerWorker.kt
+++ b/leakcanary-android-core/src/main/java/leakcanary/internal/HeapAnalyzerWorker.kt
@@ -6,12 +6,14 @@ import androidx.work.Data
 import androidx.work.ForegroundInfo
 import androidx.work.Worker
 import androidx.work.WorkerParameters
-import androidx.work.impl.utils.futures.SettableFuture
 import com.google.common.util.concurrent.ListenableFuture
 import com.squareup.leakcanary.core.R
 import leakcanary.EventListener.Event
 
-internal class HeapAnalyzerWorker(appContext: Context, workerParams: WorkerParameters) :
+internal class HeapAnalyzerWorker(
+  appContext: Context,
+  workerParams: WorkerParameters
+) :
   Worker(appContext, workerParams) {
   override fun doWork(): Result {
     val doneEvent =
@@ -23,7 +25,9 @@ internal class HeapAnalyzerWorker(appContext: Context, workerParams: WorkerParam
   }
 
   override fun getForegroundInfoAsync(): ListenableFuture<ForegroundInfo> {
-    return applicationContext.heapAnalysisForegroundInfoAsync()
+    return LazyImmediateFuture {
+      applicationContext.heapAnalysisForegroundInfo()
+    }
   }
 
   companion object {
@@ -36,21 +40,17 @@ internal class HeapAnalyzerWorker(appContext: Context, workerParams: WorkerParam
     inline fun <reified T> Data.asEvent(): T =
       Serializables.fromByteArray<T>(getByteArray(EVENT_BYTES)!!)!!
 
-    fun Context.heapAnalysisForegroundInfoAsync(): ListenableFuture<ForegroundInfo> {
-      val infoFuture = SettableFuture.create<ForegroundInfo>()
+    fun Context.heapAnalysisForegroundInfo(): ForegroundInfo {
       val builder = Notification.Builder(this)
         .setContentTitle(getString(R.string.leak_canary_notification_analysing))
         .setContentText("LeakCanary is working.")
         .setProgress(100, 0, true)
       val notification =
         Notifications.buildNotification(this, builder, NotificationType.LEAKCANARY_LOW)
-      infoFuture.set(
-        ForegroundInfo(
-          R.id.leak_canary_notification_analyzing_heap,
-          notification
-        )
+      return ForegroundInfo(
+        R.id.leak_canary_notification_analyzing_heap,
+        notification
       )
-      return infoFuture
     }
   }
 }
diff --git a/leakcanary-android-core/src/main/java/leakcanary/internal/LazyImmediateFuture.kt b/leakcanary-android-core/src/main/java/leakcanary/internal/LazyImmediateFuture.kt
new file mode 100644
index 00000000..a382748a
--- /dev/null
+++ b/leakcanary-android-core/src/main/java/leakcanary/internal/LazyImmediateFuture.kt
@@ -0,0 +1,34 @@
+package leakcanary.internal
+
+import com.google.common.util.concurrent.ListenableFuture
+import java.util.concurrent.Executor
+import java.util.concurrent.TimeUnit
+
+internal class LazyImmediateFuture<V>(
+  valueProvider: () -> V
+) : ListenableFuture<V> {
+
+  private val value by lazy {
+    valueProvider()
+  }
+
+  override fun cancel(mayInterruptIfRunning: Boolean) = false
+
+  override fun isCancelled() = false
+
+  override fun isDone() = true
+
+  override fun get() = value
+
+  override fun get(
+    timeout: Long,
+    unit: TimeUnit?
+  ): V = value
+
+  override fun addListener(
+    listener: Runnable,
+    executor: Executor
+  ) {
+    executor.execute(listener)
+  }
+}
diff --git a/leakcanary-android-core/src/main/java/leakcanary/internal/RemoteHeapAnalyzerWorker.kt b/leakcanary-android-core/src/main/java/leakcanary/internal/RemoteHeapAnalyzerWorker.kt
index 31223ccf..d9459389 100644
--- a/leakcanary-android-core/src/main/java/leakcanary/internal/RemoteHeapAnalyzerWorker.kt
+++ b/leakcanary-android-core/src/main/java/leakcanary/internal/RemoteHeapAnalyzerWorker.kt
@@ -9,10 +9,13 @@ import com.google.common.util.concurrent.ListenableFuture
 import leakcanary.BackgroundThreadHeapAnalyzer.heapAnalyzerThreadHandler
 import leakcanary.EventListener.Event.HeapDump
 import leakcanary.internal.HeapAnalyzerWorker.Companion.asEvent
-import leakcanary.internal.HeapAnalyzerWorker.Companion.heapAnalysisForegroundInfoAsync
+import leakcanary.internal.HeapAnalyzerWorker.Companion.heapAnalysisForegroundInfo
 import shark.SharkLog
 
-internal class RemoteHeapAnalyzerWorker(appContext: Context, workerParams: WorkerParameters) :
+internal class RemoteHeapAnalyzerWorker(
+  appContext: Context,
+  workerParams: WorkerParameters
+) :
   RemoteListenableWorker(appContext, workerParams) {
 
   override fun startRemoteWork(): ListenableFuture<Result> {
@@ -37,6 +40,8 @@ internal class RemoteHeapAnalyzerWorker(appContext: Context, workerParams: Worke
   }
 
   override fun getForegroundInfoAsync(): ListenableFuture<ForegroundInfo> {
-    return applicationContext.heapAnalysisForegroundInfoAsync()
+    return LazyImmediateFuture {
+      applicationContext.heapAnalysisForegroundInfo()
+    }
   }
 }
diff --git a/leakcanary-android-core/src/main/java/leakcanary/internal/activity/screen/HeapDumpsScreen.kt b/leakcanary-android-core/src/main/java/leakcanary/internal/activity/screen/HeapDumpsScreen.kt
index 0d788192..aad43eae 100644
--- a/leakcanary-android-core/src/main/java/leakcanary/internal/activity/screen/HeapDumpsScreen.kt
+++ b/leakcanary-android-core/src/main/java/leakcanary/internal/activity/screen/HeapDumpsScreen.kt
@@ -21,6 +21,7 @@ import leakcanary.internal.navigation.goTo
 import leakcanary.internal.navigation.inflate
 import leakcanary.internal.navigation.onCreateOptionsMenu
 import leakcanary.internal.navigation.onScreenExiting
+import leakcanary.internal.navigation.restoreViewStateFromTag
 
 internal class HeapDumpsScreen : Screen() {
   override fun createView(container: ViewGroup) =
@@ -111,5 +112,6 @@ internal class HeapDumpsScreen : Screen() {
         )
         countView.text = count
       }
+    restoreViewStateFromTag()
   }
 }
diff --git a/leakcanary-android-core/src/main/java/leakcanary/internal/activity/screen/LeaksScreen.kt b/leakcanary-android-core/src/main/java/leakcanary/internal/activity/screen/LeaksScreen.kt
index 96299681..6ef368c9 100644
--- a/leakcanary-android-core/src/main/java/leakcanary/internal/activity/screen/LeaksScreen.kt
+++ b/leakcanary-android-core/src/main/java/leakcanary/internal/activity/screen/LeaksScreen.kt
@@ -19,6 +19,7 @@ import leakcanary.internal.navigation.activity
 import leakcanary.internal.navigation.goTo
 import leakcanary.internal.navigation.inflate
 import leakcanary.internal.navigation.onScreenExiting
+import leakcanary.internal.navigation.restoreViewStateFromTag
 
 internal class LeaksScreen : Screen() {
   override fun createView(container: ViewGroup) =
@@ -70,5 +71,6 @@ internal class LeaksScreen : Screen() {
     listView.setOnItemClickListener { _, _, position, _ ->
       goTo(LeakScreen(projections[position].signature))
     }
+    restoreViewStateFromTag()
   }
-}
\ No newline at end of file
+}
diff --git a/leakcanary-android-core/src/main/java/leakcanary/internal/activity/screen/RenderHeapDumpScreen.kt b/leakcanary-android-core/src/main/java/leakcanary/internal/activity/screen/RenderHeapDumpScreen.kt
index b5bc7d03..09a62d5e 100644
--- a/leakcanary-android-core/src/main/java/leakcanary/internal/activity/screen/RenderHeapDumpScreen.kt
+++ b/leakcanary-android-core/src/main/java/leakcanary/internal/activity/screen/RenderHeapDumpScreen.kt
@@ -46,7 +46,10 @@ internal class RenderHeapDumpScreen(
 
       viewTreeObserver.addOnGlobalLayoutListener(object : OnGlobalLayoutListener {
         override fun onGlobalLayout() {
-
+          // Extract values from the main thread, these could change by the time
+          // we get to the IO thread.
+          val measuredWidth = measuredWidth
+          val measuredHeight = measuredHeight
           executeOnIo {
             val bitmap = HeapDumpRenderer.render(
               context, heapDumpFile, measuredWidth, measuredHeight, 0
diff --git a/leakcanary-android-core/src/main/java/leakcanary/internal/navigation/BackstackFrame.kt b/leakcanary-android-core/src/main/java/leakcanary/internal/navigation/BackstackFrame.kt
index a599172a..fc5d1e18 100644
--- a/leakcanary-android-core/src/main/java/leakcanary/internal/navigation/BackstackFrame.kt
+++ b/leakcanary-android-core/src/main/java/leakcanary/internal/navigation/BackstackFrame.kt
@@ -4,6 +4,7 @@ import android.os.Parcel
 import android.os.Parcelable
 import android.util.SparseArray
 import android.view.View
+import com.squareup.leakcanary.core.R
 
 internal class BackstackFrame : Parcelable {
 
@@ -32,11 +33,15 @@ internal class BackstackFrame : Parcelable {
     this.screen = screen
     viewState = SparseArray()
     view.saveHierarchyState(viewState)
+    view.setTag(R.id.leak_canary_restored_view_state, null)
   }
 
   fun restore(view: View) {
     if (viewState != null) {
       view.restoreHierarchyState(viewState)
+      view.setTag(R.id.leak_canary_restored_view_state, viewState)
+    } else {
+      view.setTag(R.id.leak_canary_restored_view_state, null)
     }
   }
 
diff --git a/leakcanary-android-core/src/main/java/leakcanary/internal/navigation/Views.kt b/leakcanary-android-core/src/main/java/leakcanary/internal/navigation/Views.kt
index 84a17653..fe243039 100644
--- a/leakcanary-android-core/src/main/java/leakcanary/internal/navigation/Views.kt
+++ b/leakcanary-android-core/src/main/java/leakcanary/internal/navigation/Views.kt
@@ -3,6 +3,8 @@ package leakcanary.internal.navigation
 import android.app.Activity
 import android.content.Context
 import android.os.Build.VERSION
+import android.os.Parcelable
+import android.util.SparseArray
 import android.view.LayoutInflater
 import android.view.Menu
 import android.view.View
@@ -12,6 +14,13 @@ import com.squareup.leakcanary.core.R
 internal fun ViewGroup.inflate(layoutResId: Int) = LayoutInflater.from(context)
   .inflate(layoutResId, this, false)!!
 
+internal fun View.restoreViewStateFromTag() {
+  val viewState = getTag(R.id.leak_canary_restored_view_state) as SparseArray<Parcelable>?
+  if (viewState != null) {
+    restoreHierarchyState(viewState)
+  }
+}
+
 internal val View.activity
   get() = context as Activity
 
@@ -54,4 +63,4 @@ internal fun View.notifyScreenExiting() {
   val callbacks = getTag(R.id.leak_canary_notification_on_screen_exit)
     as MutableList<() -> Unit>?
   callbacks?.forEach { it.invoke() }
-}
\ No newline at end of file
+}
diff --git a/leakcanary-android-core/src/main/res/values/leak_canary_ids.xml b/leakcanary-android-core/src/main/res/values/leak_canary_ids.xml
index d94af979..f1b2ea61 100644
--- a/leakcanary-android-core/src/main/res/values/leak_canary_ids.xml
+++ b/leakcanary-android-core/src/main/res/values/leak_canary_ids.xml
@@ -22,4 +22,5 @@
   <item type="id" name="leak_canary_notification_retained_objects" />
   <item type="id" name="leak_canary_notification_no_retained_object_on_tap" />
   <item type="id" name="leak_canary_notification_on_screen_exit" />
+  <item type="id" name="leak_canary_restored_view_state" />
 </resources>
diff --git a/leakcanary-android-release/api/leakcanary-android-release.api b/leakcanary-android-release/api/leakcanary-android-release.api
index 61db3202..bafb4cb7 100644
--- a/leakcanary-android-release/api/leakcanary-android-release.api
+++ b/leakcanary-android-release/api/leakcanary-android-release.api
@@ -38,21 +38,23 @@ public final class leakcanary/HeapAnalysisClient$Companion {
 
 public final class leakcanary/HeapAnalysisConfig {
 	public fun <init> ()V
-	public fun <init> (Ljava/util/List;Ljava/util/List;Lshark/MetadataExtractor;ZLshark/LeakingObjectFinder;Z)V
-	public synthetic fun <init> (Ljava/util/List;Ljava/util/List;Lshark/MetadataExtractor;ZLshark/LeakingObjectFinder;ZILkotlin/jvm/internal/DefaultConstructorMarker;)V
+	public fun <init> (Ljava/util/List;Ljava/util/List;Lshark/MetadataExtractor;ZLshark/LeakingObjectFinder;ZLkotlin/jvm/functions/Function0;)V
+	public synthetic fun <init> (Ljava/util/List;Ljava/util/List;Lshark/MetadataExtractor;ZLshark/LeakingObjectFinder;ZLkotlin/jvm/functions/Function0;ILkotlin/jvm/internal/DefaultConstructorMarker;)V
 	public final fun component1 ()Ljava/util/List;
 	public final fun component2 ()Ljava/util/List;
 	public final fun component3 ()Lshark/MetadataExtractor;
 	public final fun component4 ()Z
 	public final fun component5 ()Lshark/LeakingObjectFinder;
 	public final fun component6 ()Z
-	public final fun copy (Ljava/util/List;Ljava/util/List;Lshark/MetadataExtractor;ZLshark/LeakingObjectFinder;Z)Lleakcanary/HeapAnalysisConfig;
-	public static synthetic fun copy$default (Lleakcanary/HeapAnalysisConfig;Ljava/util/List;Ljava/util/List;Lshark/MetadataExtractor;ZLshark/LeakingObjectFinder;ZILjava/lang/Object;)Lleakcanary/HeapAnalysisConfig;
+	public final fun component7 ()Lkotlin/jvm/functions/Function0;
+	public final fun copy (Ljava/util/List;Ljava/util/List;Lshark/MetadataExtractor;ZLshark/LeakingObjectFinder;ZLkotlin/jvm/functions/Function0;)Lleakcanary/HeapAnalysisConfig;
+	public static synthetic fun copy$default (Lleakcanary/HeapAnalysisConfig;Ljava/util/List;Ljava/util/List;Lshark/MetadataExtractor;ZLshark/LeakingObjectFinder;ZLkotlin/jvm/functions/Function0;ILjava/lang/Object;)Lleakcanary/HeapAnalysisConfig;
 	public fun equals (Ljava/lang/Object;)Z
 	public final fun getComputeRetainedHeapSize ()Z
 	public final fun getLeakingObjectFinder ()Lshark/LeakingObjectFinder;
 	public final fun getMetadataExtractor ()Lshark/MetadataExtractor;
 	public final fun getObjectInspectors ()Ljava/util/List;
+	public final fun getProguardMappingProvider ()Lkotlin/jvm/functions/Function0;
 	public final fun getReferenceMatchers ()Ljava/util/List;
 	public final fun getStripHeapDump ()Z
 	public fun hashCode ()I
diff --git a/leakcanary-android-release/src/main/java/leakcanary/HeapAnalysisConfig.kt b/leakcanary-android-release/src/main/java/leakcanary/HeapAnalysisConfig.kt
index 0df5accc..5b7f6fd0 100644
--- a/leakcanary-android-release/src/main/java/leakcanary/HeapAnalysisConfig.kt
+++ b/leakcanary-android-release/src/main/java/leakcanary/HeapAnalysisConfig.kt
@@ -4,12 +4,13 @@ import shark.AndroidMetadataExtractor
 import shark.AndroidObjectInspectors
 import shark.AndroidReferenceMatchers
 import shark.FilteringLeakingObjectFinder
+import shark.IgnoredReferenceMatcher
 import shark.LeakingObjectFinder
+import shark.LibraryLeakReferenceMatcher
 import shark.MetadataExtractor
 import shark.ObjectInspector
-import shark.IgnoredReferenceMatcher
+import shark.ProguardMapping
 import shark.ReferenceMatcher
-import shark.LibraryLeakReferenceMatcher
 
 data class HeapAnalysisConfig(
 
@@ -71,5 +72,7 @@ data class HeapAnalysisConfig(
    * zeroes. This increases the overall processing time but limits the amount of time the heap
    * dump exists on disk with potential PII.
    */
-  val stripHeapDump: Boolean = false
+  val stripHeapDump: Boolean = false,
+
+  val proguardMappingProvider: () -> ProguardMapping? = { null }
 )
diff --git a/leakcanary-android-release/src/main/java/leakcanary/internal/RealHeapAnalysisJob.kt b/leakcanary-android-release/src/main/java/leakcanary/internal/RealHeapAnalysisJob.kt
index ae4d4dd2..f6c0f4fe 100644
--- a/leakcanary-android-release/src/main/java/leakcanary/internal/RealHeapAnalysisJob.kt
+++ b/leakcanary-android-release/src/main/java/leakcanary/internal/RealHeapAnalysisJob.kt
@@ -280,7 +280,7 @@ internal class RealHeapAnalysisJob(
       }
     }
 
-    return deletingFileSourceProvider.openHeapGraph().use { graph ->
+    return deletingFileSourceProvider.openHeapGraph(config.proguardMappingProvider()).use { graph ->
       val heapAnalysis = analyzeHeap(heapDumpFile, graph)
       val lruCacheStats = (graph as HprofHeapGraph).lruCacheStats()
       val randomAccessStats =
diff --git a/plumber-android-core/api/plumber-android-core.api b/plumber-android-core/api/plumber-android-core.api
index 6e8d5687..b88a8ad1 100644
--- a/plumber-android-core/api/plumber-android-core.api
+++ b/plumber-android-core/api/plumber-android-core.api
@@ -9,6 +9,7 @@ public abstract class leakcanary/AndroidLeakFixes : java/lang/Enum {
 	public static final field IMM_FOCUSED_VIEW Lleakcanary/AndroidLeakFixes;
 	public static final field LAST_HOVERED_VIEW Lleakcanary/AndroidLeakFixes;
 	public static final field MEDIA_SESSION_LEGACY_HELPER Lleakcanary/AndroidLeakFixes;
+	public static final field PERMISSION_CONTROLLER_MANAGER Lleakcanary/AndroidLeakFixes;
 	public static final field SAMSUNG_CLIPBOARD_MANAGER Lleakcanary/AndroidLeakFixes;
 	public static final field SPELL_CHECKER Lleakcanary/AndroidLeakFixes;
 	public static final field TEXT_LINE_POOL Lleakcanary/AndroidLeakFixes;
diff --git a/plumber-android-core/src/main/java/leakcanary/AndroidLeakFixes.kt b/plumber-android-core/src/main/java/leakcanary/AndroidLeakFixes.kt
index 796c25d8..f223ad44 100644
--- a/plumber-android-core/src/main/java/leakcanary/AndroidLeakFixes.kt
+++ b/plumber-android-core/src/main/java/leakcanary/AndroidLeakFixes.kt
@@ -707,6 +707,29 @@ enum class AndroidLeakFixes {
         SharkLog.d(ignored) { "Unable to fix SpellChecker leak" }
       }
     }
+  },
+
+  /**
+   * PermissionControllerManager stores the first context it's initialized with forever.
+   * Sometimes it's an Activity context which then leaks after Activity is destroyed.
+   *
+   * This fix makes sure the PermissionControllerManager is created with the application context.
+   *
+   * For Pixel devices the issue can be tracked here
+   * https://issuetracker.google.com/issues/318415056
+   */
+  PERMISSION_CONTROLLER_MANAGER {
+    @SuppressLint("WrongConstant")
+    override fun apply(application: Application) {
+      if (SDK_INT < 29) {
+        return
+      }
+      try {
+        application.getSystemService("permission_controller")
+      } catch (ignored: Exception) {
+        SharkLog.d(ignored) { "Unable to fix PermissionControllerManager leak" }
+      }
+    }
   }
 
   ;
diff --git a/shark-android/api/shark-android.api b/shark-android/api/shark-android.api
index fa6e6b11..a64e4b2d 100644
--- a/shark-android/api/shark-android.api
+++ b/shark-android/api/shark-android.api
@@ -133,6 +133,7 @@ public abstract class shark/AndroidReferenceMatchers : java/lang/Enum {
 	public static final field OEM_SCENE_CALL_BLOCKER Lshark/AndroidReferenceMatchers;
 	public static final field ONE_PLUS Ljava/lang/String;
 	public static final field PERF_MONITOR_LAST_CALLBACK Lshark/AndroidReferenceMatchers;
+	public static final field PERMISSION_CONTROLLER_MANAGER Lshark/AndroidReferenceMatchers;
 	public static final field PERSONA_MANAGER Lshark/AndroidReferenceMatchers;
 	public static final field PLAYER_BASE Lshark/AndroidReferenceMatchers;
 	public static final field RAZER Ljava/lang/String;
@@ -160,6 +161,7 @@ public abstract class shark/AndroidReferenceMatchers : java/lang/Enum {
 	public static final field TEXT_TO_SPEECH Lshark/AndroidReferenceMatchers;
 	public static final field TEXT_VIEW__MLAST_HOVERED_VIEW Lshark/AndroidReferenceMatchers;
 	public static final field TOAST_TN Lshark/AndroidReferenceMatchers;
+	public static final field UI_MODE_MANAGER Lshark/AndroidReferenceMatchers;
 	public static final field USER_MANAGER__SINSTANCE Lshark/AndroidReferenceMatchers;
 	public static final field VIEWLOCATIONHOLDER_ROOT Lshark/AndroidReferenceMatchers;
 	public static final field VIEW_CONFIGURATION__MCONTEXT Lshark/AndroidReferenceMatchers;
diff --git a/shark-android/src/main/java/shark/AndroidReferenceMatchers.kt b/shark-android/src/main/java/shark/AndroidReferenceMatchers.kt
index 7e2b2cee..2db963e4 100644
--- a/shark-android/src/main/java/shark/AndroidReferenceMatchers.kt
+++ b/shark-android/src/main/java/shark/AndroidReferenceMatchers.kt
@@ -50,6 +50,23 @@ enum class AndroidReferenceMatchers {
 
   // ######## Android Framework known leaks ########
 
+  PERMISSION_CONTROLLER_MANAGER {
+    override fun add(
+      references: MutableList<ReferenceMatcher>
+    ) {
+      references += instanceFieldLeak(
+        "android.permission.PermissionControllerManager", "mContext",
+        description = "On some devices PermissionControllerManager " +
+        "may be initialized with Activity as its Context field. " +
+        "Fix: you can \"fix\" this leak by calling getSystemService(\"permission_controller\") " +
+        "on an application context. " +
+        "Tracked here: https://issuetracker.google.com/issues/318415056"
+      ) {
+        sdkInt >= 29
+      }
+    }
+  },
+
   IREQUEST_FINISH_CALLBACK {
     override fun add(
       references: MutableList<ReferenceMatcher>
@@ -1007,6 +1024,25 @@ enum class AndroidReferenceMatchers {
     }
   },
 
+  UI_MODE_MANAGER {
+    override fun add(
+      references: MutableList<ReferenceMatcher>
+    ) {
+      references += nativeGlobalVariableLeak(
+        "android.app.UiModeManager\$1",
+        description = """
+          UiModeManager$1 is an anonymous class of the IUiModeManagerCallback.Stub that is
+          stored in memory native code. `this$0` is an instance of the UiModeManager that
+          contains the `mContext` field, which is why retain this reference.
+          Introduced in Android 14.0.0_r11: https://cs.android.com/android/_/android/platform/frameworks/base/+/cbbc772a41d20645ae434d74c482f3f4ad377e2c
+          Fixed in Android 14.0.0_r16: https://cs.android.com/android/_/android/platform/frameworks/base/+/2bc364179327022d0f60224a1f2420349074c5d2
+        """.trimIndent()
+      ) {
+        sdkInt == 34
+      }
+    }
+  },
+
   // ######## Manufacturer specific known leaks ########
 
   // SAMSUNG
```

