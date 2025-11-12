```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 40a81e7..316e8c5 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -11,5 +11,7 @@ checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPL
 
 ktlint_hook = ${REPO_ROOT}/prebuilts/ktlint/ktlint.py --no-verify-format -f ${PREUPLOAD_FILES}
 
+alint_hook =  ${REPO_ROOT}/vendor/google/tools/alint
+
 [Tool Paths]
 ktfmt = ${REPO_ROOT}/external/ktfmt/ktfmt.sh
diff --git a/aconfig/systemui.aconfig b/aconfig/systemui.aconfig
index 7fdc509..e684b75 100644
--- a/aconfig/systemui.aconfig
+++ b/aconfig/systemui.aconfig
@@ -137,13 +137,6 @@ flag {
     bug: "391401141"
 }
 
-flag {
-    name: "enable_lpp_squeeze_effect"
-    namespace: "systemui"
-    description: "Enables squeeze effect on power button long press launching Gemini"
-    bug: "396099245"
-}
-
 flag {
   name: "cursor_hot_corner"
   namespace: "systemui"
@@ -158,6 +151,16 @@ flag {
     bug: "389741821"
 }
 
+flag {
+    name: "smartspace_weather_use_monochrome_font_icons"
+    namespace: "systemui"
+    description: "Update Smartspace to use monochrome font icons for weather"
+    bug: "389957594"
+    metadata {
+         purpose: PURPOSE_BUGFIX
+    }
+}
+
 flag {
     name: "smartspace_ui_update_resources"
     namespace: "systemui"
@@ -167,11 +170,29 @@ flag {
 }
 
 flag {
-    name: "smartspace_remoteviews_intent_handler"
+    name: "enable_lpp_assist_invocation_effect"
     namespace: "systemui"
-    description: "Enables Smartspace RemoteViews intent handling on lockscreen"
-    bug: "399416038"
+    description: "Enables invocation effect on power button long press for launching assistant"
+    bug: "396099245"
+    metadata {
+         purpose: PURPOSE_BUGFIX
+    }
+}
+
+flag {
+    name: "enable_lpp_assist_invocation_haptic_effect"
+    namespace: "systemui"
+    description: "Enables haptics for the invocation effect on power button long press for launching assistant"
+    bug: "412325043"
     metadata {
          purpose: PURPOSE_BUGFIX
     }
 }
+
+flag {
+  name: "extendible_theme_manager"
+  namespace: "launcher"
+  description: "Enables custom theme manager in Launcher and Customization Picker"
+  bug: "381897614"
+}
+
diff --git a/displaylib/src/com/android/app/displaylib/DisplayLibComponent.kt b/displaylib/src/com/android/app/displaylib/DisplayLibComponent.kt
index 1ae3483..e40c1ca 100644
--- a/displaylib/src/com/android/app/displaylib/DisplayLibComponent.kt
+++ b/displaylib/src/com/android/app/displaylib/DisplayLibComponent.kt
@@ -17,6 +17,7 @@ package com.android.app.displaylib
 
 import android.hardware.display.DisplayManager
 import android.os.Handler
+import android.view.IWindowManager
 import dagger.Binds
 import dagger.BindsInstance
 import dagger.Component
@@ -40,6 +41,7 @@ interface DisplayLibComponent {
     interface Factory {
         fun create(
             @BindsInstance displayManager: DisplayManager,
+            @BindsInstance windowManager: IWindowManager,
             @BindsInstance bgHandler: Handler,
             @BindsInstance bgApplicationScope: CoroutineScope,
             @BindsInstance backgroundCoroutineDispatcher: CoroutineDispatcher,
@@ -47,11 +49,18 @@ interface DisplayLibComponent {
     }
 
     val displayRepository: DisplayRepository
+    val displaysWithDecorationsRepository: DisplaysWithDecorationsRepository
+    val displaysWithDecorationsRepositoryCompat: DisplaysWithDecorationsRepositoryCompat
 }
 
 @Module
 interface DisplayLibModule {
     @Binds fun bindDisplayManagerImpl(impl: DisplayRepositoryImpl): DisplayRepository
+
+    @Binds
+    fun bindDisplaysWithDecorationsRepositoryImpl(
+        impl: DisplaysWithDecorationsRepositoryImpl
+    ): DisplaysWithDecorationsRepository
 }
 
 /**
@@ -63,10 +72,17 @@ interface DisplayLibModule {
  */
 fun createDisplayLibComponent(
     displayManager: DisplayManager,
+    windowManager: IWindowManager,
     bgHandler: Handler,
     bgApplicationScope: CoroutineScope,
     backgroundCoroutineDispatcher: CoroutineDispatcher,
 ): DisplayLibComponent {
     return DaggerDisplayLibComponent.factory()
-        .create(displayManager, bgHandler, bgApplicationScope, backgroundCoroutineDispatcher)
+        .create(
+            displayManager,
+            windowManager,
+            bgHandler,
+            bgApplicationScope,
+            backgroundCoroutineDispatcher,
+        )
 }
diff --git a/displaylib/src/com/android/app/displaylib/DisplayRepository.kt b/displaylib/src/com/android/app/displaylib/DisplayRepository.kt
index 820c518..ed83f02 100644
--- a/displaylib/src/com/android/app/displaylib/DisplayRepository.kt
+++ b/displaylib/src/com/android/app/displaylib/DisplayRepository.kt
@@ -86,11 +86,28 @@ interface DisplayRepository {
     /**
      * Given a display ID int, return the corresponding Display object, or null if none exist.
      *
-     * This method is guaranteed to not result in any binder call.
+     * This method will not result in a binder call in most cases. The only exception is if there is
+     * an existing binder call ongoing to get the [Display] instance already. In that case, this
+     * will wait for the end of the binder call.
      */
-    fun getDisplay(displayId: Int): Display? =
+    fun getDisplay(displayId: Int): Display?
+
+    /**
+     * As [getDisplay], but it's always guaranteed to not block on any binder call.
+     *
+     * This might return null if the display id was not mapped to a [Display] object yet.
+     */
+    fun getCachedDisplay(displayId: Int): Display? =
         displays.value.firstOrNull { it.displayId == displayId }
 
+    /**
+     * Returns whether the given displayId is in the set of enabled displays.
+     *
+     * This is guaranteed to not cause a binder call. Use this instead of [getDisplay] (see its docs
+     * for why)
+     */
+    fun containsDisplay(displayId: Int): Boolean = displayIds.value.contains(displayId)
+
     /** Represents a connected display that has not been enabled yet. */
     interface PendingDisplay {
         /** Id of the pending display. */
@@ -375,6 +392,24 @@ constructor(
             .map { defaultDisplay.state == Display.STATE_OFF }
             .distinctUntilChanged()
 
+    override fun getDisplay(displayId: Int): Display? {
+        val cachedDisplay = getCachedDisplay(displayId)
+        if (cachedDisplay != null) return cachedDisplay
+        // cachedDisplay could be null for 2 reasons:
+        // 1. the displayId is being mapped to a display in the background, but the binder call is
+        // not done
+        // 2. the display is not there
+        // In case of option one, let's get it synchronously from display manager to make sure for
+        // this to be consistent.
+        return if (displayIds.value.contains(displayId)) {
+            traceSection("$TAG#getDisplayFallbackToDisplayManager") {
+                getDisplayFromDisplayManager(displayId)
+            }
+        } else {
+            null
+        }
+    }
+
     private fun <T> Flow<T>.debugLog(flowName: String): Flow<T> {
         return if (DEBUG) {
             traceEach(flowName, logcat = true, traceEmissionCount = true)
@@ -454,8 +489,10 @@ private sealed interface DisplayEvent {
  * upstream Flow.
  *
  * Useful for code that needs to compare the current value to the previous value.
+ *
+ * Note this has been taken from com.android.systemui.util.kotlin. It was copied to keep deps of
+ * displaylib minimal (and avoid creating a new shared lib for it).
  */
-// TODO b/401305290 - This should be moved to a shared lib, as it's also used by SystemUI.
 fun <T, R> Flow<T>.pairwiseBy(transform: suspend (old: T, new: T) -> R): Flow<R> = flow {
     val noVal = Any()
     var previousValue: Any? = noVal
diff --git a/displaylib/src/com/android/app/displaylib/DisplaysWithDecorationsRepository.kt b/displaylib/src/com/android/app/displaylib/DisplaysWithDecorationsRepository.kt
new file mode 100644
index 0000000..b184bd9
--- /dev/null
+++ b/displaylib/src/com/android/app/displaylib/DisplaysWithDecorationsRepository.kt
@@ -0,0 +1,119 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.app.displaylib
+
+import android.content.res.Configuration
+import android.graphics.Rect
+import android.view.IDisplayWindowListener
+import android.view.IWindowManager
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.channels.awaitClose
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.callbackFlow
+import kotlinx.coroutines.flow.distinctUntilChanged
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.merge
+import kotlinx.coroutines.flow.scan
+import kotlinx.coroutines.flow.stateIn
+
+/** Provides the displays with decorations. */
+interface DisplaysWithDecorationsRepository {
+    /** A [StateFlow] that maintains a set of display IDs that should have system decorations. */
+    val displayIdsWithSystemDecorations: StateFlow<Set<Int>>
+}
+
+@Singleton
+class DisplaysWithDecorationsRepositoryImpl
+@Inject
+constructor(
+    private val windowManager: IWindowManager,
+    bgApplicationScope: CoroutineScope,
+    displayRepository: DisplayRepository,
+) : DisplaysWithDecorationsRepository {
+
+    private val decorationEvents: Flow<Event> = callbackFlow {
+        val callback =
+            object : IDisplayWindowListener.Stub() {
+                override fun onDisplayAddSystemDecorations(displayId: Int) {
+                    trySend(Event.Add(displayId))
+                }
+
+                override fun onDisplayRemoveSystemDecorations(displayId: Int) {
+                    trySend(Event.Remove(displayId))
+                }
+
+                override fun onDesktopModeEligibleChanged(displayId: Int) {}
+
+                override fun onDisplayAdded(p0: Int) {}
+
+                override fun onDisplayConfigurationChanged(p0: Int, p1: Configuration?) {}
+
+                override fun onDisplayRemoved(p0: Int) {}
+
+                override fun onFixedRotationStarted(p0: Int, p1: Int) {}
+
+                override fun onFixedRotationFinished(p0: Int) {}
+
+                override fun onKeepClearAreasChanged(
+                    p0: Int,
+                    p1: MutableList<Rect>?,
+                    p2: MutableList<Rect>?,
+                ) {}
+            }
+        windowManager.registerDisplayWindowListener(callback)
+        awaitClose { windowManager.unregisterDisplayWindowListener(callback) }
+    }
+
+    private val initialDisplayIdsWithDecorations: Set<Int> =
+        displayRepository.displayIds.value
+            .filter { windowManager.shouldShowSystemDecors(it) }
+            .toSet()
+
+    /**
+     * A [StateFlow] that maintains a set of display IDs that should have system decorations.
+     *
+     * Updates to the set are triggered by:
+     * - Removing displays via [displayRemovalEvent] emissions.
+     *
+     * The set is initialized with displays that qualify for system decorations based on
+     * [WindowManager.shouldShowSystemDecors].
+     */
+    override val displayIdsWithSystemDecorations: StateFlow<Set<Int>> =
+        merge(decorationEvents, displayRepository.displayRemovalEvent.map { Event.Remove(it) })
+            .scan(initialDisplayIdsWithDecorations) { displayIds: Set<Int>, event: Event ->
+                when (event) {
+                    is Event.Add -> displayIds + event.displayId
+                    is Event.Remove -> displayIds - event.displayId
+                }
+            }
+            .distinctUntilChanged()
+            .stateIn(
+                scope = bgApplicationScope,
+                started = SharingStarted.WhileSubscribed(),
+                initialValue = initialDisplayIdsWithDecorations,
+            )
+
+    private sealed class Event(val displayId: Int) {
+        class Add(displayId: Int) : Event(displayId)
+
+        class Remove(displayId: Int) : Event(displayId)
+    }
+}
diff --git a/displaylib/src/com/android/app/displaylib/DisplaysWithDecorationsRepositoryCompat.kt b/displaylib/src/com/android/app/displaylib/DisplaysWithDecorationsRepositoryCompat.kt
new file mode 100644
index 0000000..d4f750b
--- /dev/null
+++ b/displaylib/src/com/android/app/displaylib/DisplaysWithDecorationsRepositoryCompat.kt
@@ -0,0 +1,132 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.app.displaylib
+
+import com.android.app.tracing.TraceUtils.traceAsync
+import com.android.internal.annotations.GuardedBy
+import java.util.concurrent.ConcurrentHashMap
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.sync.Mutex
+import kotlinx.coroutines.sync.withLock
+import kotlinx.coroutines.withContext
+
+/** Listener for display system decorations changes. */
+interface DisplayDecorationListener {
+    /** Called when system decorations should be added to the display.* */
+    fun onDisplayAddSystemDecorations(displayId: Int)
+
+    /** Called when a display is removed. */
+    fun onDisplayRemoved(displayId: Int)
+
+    /** Called when system decorations should be removed from the display. */
+    fun onDisplayRemoveSystemDecorations(displayId: Int)
+}
+
+/**
+ * This class is a compatibility layer that allows to register and unregister listeners for display
+ * decorations changes. It uses a [DisplaysWithDecorationsRepository] to get the current list of
+ * displays with decorations and notifies the listeners when the list changes.
+ */
+@Singleton
+class DisplaysWithDecorationsRepositoryCompat
+@Inject
+constructor(
+    private val bgApplicationScope: CoroutineScope,
+    private val displayRepository: DisplaysWithDecorationsRepository,
+) {
+    private val mutex = Mutex()
+    private var collectorJob: Job? = null
+    private val displayDecorationListenersWithDispatcher =
+        ConcurrentHashMap<DisplayDecorationListener, CoroutineDispatcher>()
+
+    /**
+     * Registers a [DisplayDecorationListener] to be notified when the list of displays with
+     * decorations changes.
+     *
+     * @param listener The listener to register.
+     * @param dispatcher The dispatcher to use when notifying the listener.
+     */
+    fun registerDisplayDecorationListener(
+        listener: DisplayDecorationListener,
+        dispatcher: CoroutineDispatcher,
+    ) {
+        var initialDisplayIdsForListener: Set<Int> = emptySet()
+        bgApplicationScope.launch {
+            mutex.withLock {
+                displayDecorationListenersWithDispatcher[listener] = dispatcher
+                initialDisplayIdsForListener =
+                    displayRepository.displayIdsWithSystemDecorations.value
+                startCollectingIfNeeded(initialDisplayIdsForListener)
+            }
+            // Emit all the existing displays with decorations when registering.
+            initialDisplayIdsForListener.forEach { displayId ->
+                withContext(dispatcher) { listener.onDisplayAddSystemDecorations(displayId) }
+            }
+        }
+    }
+
+    /**
+     * Unregisters a [DisplayDecorationListener].
+     *
+     * @param listener The listener to unregister.
+     */
+    fun unregisterDisplayDecorationListener(listener: DisplayDecorationListener) {
+            bgApplicationScope.launch {
+                mutex.withLock {
+                    displayDecorationListenersWithDispatcher.remove(listener)
+                    // stop collecting if no listeners
+                    if (displayDecorationListenersWithDispatcher.isEmpty()) {
+                        collectorJob?.cancel()
+                        collectorJob = null
+                    }
+                }
+            }
+    }
+
+    @GuardedBy("mutex")
+    private fun startCollectingIfNeeded(lastDisplaysWithDecorations: Set<Int>) {
+        if (collectorJob?.isActive == true) {
+            return
+        }
+        var oldDisplays: Set<Int> = lastDisplaysWithDecorations
+        collectorJob =
+            bgApplicationScope.launch {
+                displayRepository.displayIdsWithSystemDecorations.collect { currentDisplays ->
+                    val previous = oldDisplays
+                    oldDisplays = currentDisplays
+
+                    val newDisplaysWithDecorations = currentDisplays - previous
+                    val removedDisplays = previous - currentDisplays
+                    displayDecorationListenersWithDispatcher.forEach { (listener, dispatcher) ->
+                        withContext(dispatcher) {
+                            newDisplaysWithDecorations.forEach { displayId ->
+                                listener.onDisplayAddSystemDecorations(displayId)
+                            }
+                            removedDisplays.forEach { displayId ->
+                                listener.onDisplayRemoveSystemDecorations(displayId)
+                            }
+                        }
+                    }
+                }
+            }
+    }
+}
diff --git a/displaylib/src/com/android/app/displaylib/PerDisplayRepository.kt b/displaylib/src/com/android/app/displaylib/PerDisplayRepository.kt
index 13bd44a..0f2311a 100644
--- a/displaylib/src/com/android/app/displaylib/PerDisplayRepository.kt
+++ b/displaylib/src/com/android/app/displaylib/PerDisplayRepository.kt
@@ -18,6 +18,7 @@ package com.android.app.displaylib
 
 import android.util.Log
 import android.view.Display
+import android.view.Display.DEFAULT_DISPLAY
 import com.android.app.tracing.coroutines.flow.stateInTraced
 import com.android.app.tracing.coroutines.launchTraced as launch
 import com.android.app.tracing.traceSection
@@ -25,6 +26,7 @@ import dagger.assisted.Assisted
 import dagger.assisted.AssistedFactory
 import dagger.assisted.AssistedInject
 import java.util.concurrent.ConcurrentHashMap
+import java.util.function.Consumer
 import javax.inject.Qualifier
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.flow.SharingStarted
@@ -103,6 +105,15 @@ interface PerDisplayRepository<T> {
     fun interface InitCallback {
         fun onInit(debugName: String, instance: Any)
     }
+
+    /**
+     * Iterate over all the available displays performing the action on each object of type T.
+     *
+     * @param createIfAbsent If true, create instances of T if they are not already created. If
+     *   false, do not and skip calling action..
+     * @param action The action to perform on each instance.
+     */
+    fun forEach(createIfAbsent: Boolean, action: Consumer<T>)
 }
 
 /** Qualifier for [CoroutineScope] used for displaylib background tasks. */
@@ -181,7 +192,7 @@ constructor(
     }
 
     override fun get(displayId: Int): T? {
-        if (displayRepository.getDisplay(displayId) == null) {
+        if (!displayRepository.containsDisplay(displayId)) {
             Log.e(TAG, "<$debugName: Display with id $displayId doesn't exist.")
             return null
         }
@@ -229,6 +240,14 @@ constructor(
         return "PerDisplayInstanceRepositoryImpl(" +
             "debugName='$debugName', instances=$perDisplayInstances)"
     }
+
+    override fun forEach(createIfAbsent: Boolean, action: Consumer<T>) {
+        if (createIfAbsent) {
+            allowedDisplays.value.forEach { displayId -> get(displayId)?.let { action.accept(it) } }
+        } else {
+            perDisplayInstances.forEach { (_, instance) -> instance?.let { action.accept(it) } }
+        }
+    }
 }
 
 /**
@@ -247,11 +266,22 @@ class DefaultDisplayOnlyInstanceRepositoryImpl<T>(
     override val debugName: String,
     private val instanceProvider: PerDisplayInstanceProvider<T>,
 ) : PerDisplayRepository<T> {
-    private val lazyDefaultDisplayInstance by lazy {
+    private val lazyDefaultDisplayInstanceDelegate = lazy {
         instanceProvider.createInstance(Display.DEFAULT_DISPLAY)
     }
+    private val lazyDefaultDisplayInstance by lazyDefaultDisplayInstanceDelegate
 
     override fun get(displayId: Int): T? = lazyDefaultDisplayInstance
+
+    override fun forEach(createIfAbsent: Boolean, action: Consumer<T>) {
+        if (createIfAbsent) {
+            get(DEFAULT_DISPLAY)?.let { action.accept(it) }
+        } else {
+            if (lazyDefaultDisplayInstanceDelegate.isInitialized()) {
+                lazyDefaultDisplayInstance?.let { action.accept(it) }
+            }
+        }
+    }
 }
 
 /**
@@ -265,4 +295,8 @@ class DefaultDisplayOnlyInstanceRepositoryImpl<T>(
 class SingleInstanceRepositoryImpl<T>(override val debugName: String, private val instance: T) :
     PerDisplayRepository<T> {
     override fun get(displayId: Int): T? = instance
+
+    override fun forEach(createIfAbsent: Boolean, action: Consumer<T>) {
+        action.accept(instance)
+    }
 }
diff --git a/displaylib/src/com/android/app/displaylib/fakes/FakePerDisplayRepository.kt b/displaylib/src/com/android/app/displaylib/fakes/FakePerDisplayRepository.kt
new file mode 100644
index 0000000..c832462
--- /dev/null
+++ b/displaylib/src/com/android/app/displaylib/fakes/FakePerDisplayRepository.kt
@@ -0,0 +1,50 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.app.displaylib.fakes
+
+import com.android.app.displaylib.PerDisplayRepository
+import java.util.function.Consumer
+
+/** Fake version of [PerDisplayRepository], to be used in tests. */
+class FakePerDisplayRepository<T>(private val defaultIfAbsent: ((Int) -> T)? = null) :
+    PerDisplayRepository<T> {
+
+    private val instances = mutableMapOf<Int, T>()
+
+    fun add(displayId: Int, instance: T) {
+        instances[displayId] = instance
+    }
+
+    fun remove(displayId: Int) {
+        instances.remove(displayId)
+    }
+
+    override fun get(displayId: Int): T? {
+        return if (defaultIfAbsent != null) {
+            instances.getOrPut(displayId) { defaultIfAbsent(displayId) }
+        } else {
+            instances[displayId]
+        }
+    }
+
+    override val debugName: String
+        get() = "FakePerDisplayRepository"
+
+    override fun forEach(createIfAbsent: Boolean, action: Consumer<T>) {
+        instances.forEach { (_, t) -> action.accept(t) }
+    }
+}
diff --git a/displaylib/tests/src/com/android/app/displaylib/DisplayRepositoryTest.kt b/displaylib/tests/src/com/android/app/displaylib/DisplayRepositoryTest.kt
index 7e244d3..81a26cb 100644
--- a/displaylib/tests/src/com/android/app/displaylib/DisplayRepositoryTest.kt
+++ b/displaylib/tests/src/com/android/app/displaylib/DisplayRepositoryTest.kt
@@ -19,9 +19,13 @@ import androidx.test.ext.junit.runners.AndroidJUnit4
 import androidx.test.filters.SmallTest
 import org.junit.runner.RunWith
 
-@SmallTest
-@RunWith(AndroidJUnit4::class)
-class DisplayRepositoryTest {
-
-    // TODO b/401305290 - Move tests from The SystemUI DisplayRepositoryImpl to here.
-}
+/**
+ * Tests for display repository are in SystemUI:
+ * frameworks/base/packages/SystemUI/multivalentTestsForDevice/src/com/android/systemui/display/data/repository/DisplayRepositoryTest.kt
+ *
+ * This is because the repository was initially there, and tests depend on kosmos for dependency
+ * injection (which is sysui-specific).
+ *
+ * In case of changes, update tests in sysui.
+ */
+@SmallTest @RunWith(AndroidJUnit4::class) class DisplayRepositoryTest
diff --git a/iconloaderlib/Android.bp b/iconloaderlib/Android.bp
index 104f956..e991888 100644
--- a/iconloaderlib/Android.bp
+++ b/iconloaderlib/Android.bp
@@ -23,6 +23,7 @@ android_library {
     static_libs: [
         "androidx.core_core",
         "com_android_launcher3_flags_lib",
+        "com_android_systemui_shared_flags_lib",
     ],
     resource_dirs: [
         "res",
@@ -40,6 +41,7 @@ android_library {
     static_libs: [
         "androidx.core_core",
         "com_android_launcher3_flags_lib",
+        "com_android_systemui_shared_flags_lib",
     ],
     resource_dirs: [
         "res",
diff --git a/iconloaderlib/build.gradle.kts b/iconloaderlib/build.gradle.kts
index 15112bd..0203c5b 100644
--- a/iconloaderlib/build.gradle.kts
+++ b/iconloaderlib/build.gradle.kts
@@ -17,4 +17,5 @@ android {
 dependencies {
     implementation("androidx.core:core")
     api(project(":NexusLauncher:Flags"))
+    api(project(":frameworks:base:packages:SystemUI:SystemUISharedFlags"))
 }
diff --git a/iconloaderlib/res/values/config.xml b/iconloaderlib/res/values/config.xml
index 71a38f2..893f955 100644
--- a/iconloaderlib/res/values/config.xml
+++ b/iconloaderlib/res/values/config.xml
@@ -27,7 +27,4 @@
     <string name="calendar_component_name" translatable="false"></string>
     <string name="clock_component_name" translatable="false"></string>
 
-    <!-- Configures whether to enable forced theme icon, disabled by default -->
-    <bool name="enable_forced_themed_icon">false</bool>
-
 </resources>
\ No newline at end of file
diff --git a/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java b/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java
index 5f66114..1f107c8 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java
@@ -7,6 +7,7 @@ import static android.graphics.Paint.FILTER_BITMAP_FLAG;
 import static android.graphics.drawable.AdaptiveIconDrawable.getExtraInsetFraction;
 
 import static com.android.launcher3.icons.BitmapInfo.FLAG_INSTANT;
+import static com.android.launcher3.icons.IconNormalizer.ICON_VISIBLE_AREA_FACTOR;
 import static com.android.launcher3.icons.ShadowGenerator.BLUR_FACTOR;
 import static com.android.launcher3.icons.ShadowGenerator.ICON_SCALE_FOR_SHADOWS;
 
@@ -19,17 +20,18 @@ import android.content.pm.PackageManager;
 import android.content.res.Resources;
 import android.graphics.Bitmap;
 import android.graphics.Bitmap.Config;
+import android.graphics.BitmapShader;
 import android.graphics.Canvas;
 import android.graphics.Color;
 import android.graphics.Paint;
 import android.graphics.PaintFlagsDrawFilter;
 import android.graphics.Path;
 import android.graphics.Rect;
+import android.graphics.Shader.TileMode;
 import android.graphics.drawable.AdaptiveIconDrawable;
 import android.graphics.drawable.BitmapDrawable;
 import android.graphics.drawable.ColorDrawable;
 import android.graphics.drawable.Drawable;
-import android.graphics.drawable.DrawableWrapper;
 import android.graphics.drawable.InsetDrawable;
 import android.os.Build;
 import android.os.UserHandle;
@@ -92,15 +94,15 @@ public class BaseIconFactory implements AutoCloseable {
     @Nullable
     private ShadowGenerator mShadowGenerator;
 
-    // Shadow bitmap used as background for theme icons
+    /** Shadow bitmap used as background for theme icons */
     private Bitmap mWhiteShadowLayer;
+    /** Bitmap used for {@link BitmapShader} to mask Adaptive Icons when drawing */
+    private Bitmap mShaderBitmap;
 
     private int mWrapperBackgroundColor = DEFAULT_WRAPPER_BACKGROUND;
 
     private static int PLACEHOLDER_BACKGROUND_COLOR = Color.rgb(245, 245, 245);
 
-    private final boolean mShouldForceThemeIcon;
-
     protected BaseIconFactory(Context context, int fullResIconDpi, int iconBitmapSize,
             boolean unused) {
         this(context, fullResIconDpi, iconBitmapSize);
@@ -116,9 +118,6 @@ public class BaseIconFactory implements AutoCloseable {
         mCanvas = new Canvas();
         mCanvas.setDrawFilter(new PaintFlagsDrawFilter(DITHER_FLAG, FILTER_BITMAP_FLAG));
         clear();
-
-        mShouldForceThemeIcon = mContext.getResources().getBoolean(
-                R.bool.enable_forced_themed_icon);
     }
 
     protected void clear() {
@@ -171,7 +170,7 @@ public class BaseIconFactory implements AutoCloseable {
         AdaptiveIconDrawable drawable = new AdaptiveIconDrawable(
                 new ColorDrawable(PLACEHOLDER_BACKGROUND_COLOR),
                 new CenterTextDrawable(placeholder, color));
-        Bitmap icon = createIconBitmap(drawable, IconNormalizer.ICON_VISIBLE_AREA_FACTOR);
+        Bitmap icon = createIconBitmap(drawable, ICON_VISIBLE_AREA_FACTOR);
         return BitmapInfo.of(icon, color);
     }
 
@@ -191,8 +190,9 @@ public class BaseIconFactory implements AutoCloseable {
         Drawable drawable = new FixedSizeBitmapDrawable(iconBitmap);
         float inset = getExtraInsetFraction();
         inset = inset / (1 + 2 * inset);
-        return new AdaptiveIconDrawable(new ColorDrawable(Color.BLACK),
-                new InsetDrawable(drawable, inset, inset, inset, inset));
+        return new AdaptiveIconDrawable(new ColorDrawable(BLACK),
+                new InsetDrawable(drawable, inset, inset, inset, inset)
+        );
     }
 
     @NonNull
@@ -224,7 +224,6 @@ public class BaseIconFactory implements AutoCloseable {
         AdaptiveIconDrawable adaptiveIcon = normalizeAndWrapToAdaptiveIcon(tempIcon, scale);
         Bitmap bitmap = createIconBitmap(adaptiveIcon, scale[0],
                 options == null ? MODE_WITH_SHADOW : options.mGenerationMode);
-
         int color = (options != null && options.mExtractedColor != null)
                 ? options.mExtractedColor : ColorExtractor.findDominantColorByHue(bitmap);
         BitmapInfo info = BitmapInfo.of(bitmap, color);
@@ -241,7 +240,11 @@ public class BaseIconFactory implements AutoCloseable {
                     )
             );
         }
-        info = info.withFlags(getBitmapFlagOp(options));
+        FlagOp flagOp = getBitmapFlagOp(options);
+        if (adaptiveIcon instanceof WrappedAdaptiveIcon) {
+            flagOp = flagOp.addFlag(BitmapInfo.FLAG_WRAPPED_NON_ADAPTIVE);
+        }
+        info = info.withFlags(flagOp);
         return info;
     }
 
@@ -264,13 +267,6 @@ public class BaseIconFactory implements AutoCloseable {
         return op;
     }
 
-    /**
-     * @return True if forced theme icon is enabled
-     */
-    public boolean shouldForceThemeIcon() {
-        return mShouldForceThemeIcon;
-    }
-
     @NonNull
     protected UserIconInfo getUserInfo(@NonNull UserHandle user) {
         int key = user.hashCode();
@@ -294,10 +290,6 @@ public class BaseIconFactory implements AutoCloseable {
         return drawable.getIconMask();
     }
 
-    public float getIconScale() {
-        return 1f;
-    }
-
     @NonNull
     public Bitmap getWhiteShadowLayer() {
         if (mWhiteShadowLayer == null) {
@@ -308,6 +300,42 @@ public class BaseIconFactory implements AutoCloseable {
         return mWhiteShadowLayer;
     }
 
+    /**
+     * Takes an {@link AdaptiveIconDrawable} and uses it to create a new Shader Bitmap.
+     * {@link mShaderBitmap} will be used to create a {@link BitmapShader} for masking,
+     * such as for icon shapes. Will reuse underlying Bitmap where possible.
+     *
+     * @param adaptiveIcon AdaptiveIconDrawable to draw with shader
+     */
+    @NonNull
+    private Bitmap getAdaptiveShaderBitmap(AdaptiveIconDrawable adaptiveIcon) {
+        Rect bounds = adaptiveIcon.getBounds();
+        int iconWidth = bounds.width();
+        int iconHeight = bounds.width();
+
+        BitmapRenderer shaderRenderer = new BitmapRenderer() {
+            @Override
+            public void draw(Canvas canvas) {
+                canvas.translate(-bounds.left, -bounds.top);
+                canvas.drawColor(BLACK);
+                if (adaptiveIcon.getBackground() != null) {
+                    adaptiveIcon.getBackground().draw(canvas);
+                }
+                if (adaptiveIcon.getForeground() != null) {
+                    adaptiveIcon.getForeground().draw(canvas);
+                }
+            }
+        };
+        if (mShaderBitmap == null || iconWidth != mShaderBitmap.getWidth()
+                || iconHeight != mShaderBitmap.getHeight()) {
+            mShaderBitmap = BitmapRenderer.createSoftwareBitmap(iconWidth, iconHeight,
+                    shaderRenderer);
+        } else {
+            shaderRenderer.draw(new Canvas(mShaderBitmap));
+        }
+        return mShaderBitmap;
+    }
+
     @NonNull
     public Bitmap createScaledBitmap(@NonNull Drawable icon, @BitmapGenerationMode int mode) {
         float[] scale = new float[1];
@@ -329,7 +357,7 @@ public class BaseIconFactory implements AutoCloseable {
             return null;
         }
 
-        outScale[0] = IconNormalizer.ICON_VISIBLE_AREA_FACTOR;
+        outScale[0] = ICON_VISIBLE_AREA_FACTOR;
         return wrapToAdaptiveIcon(icon);
     }
 
@@ -358,12 +386,11 @@ public class BaseIconFactory implements AutoCloseable {
         if (icon instanceof AdaptiveIconDrawable aid) {
             return aid;
         } else {
-            EmptyWrapper foreground = new EmptyWrapper();
-            AdaptiveIconDrawable dr = new AdaptiveIconDrawable(
-                    new ColorDrawable(mWrapperBackgroundColor), foreground);
-            dr.setBounds(0, 0, 1, 1);
             float scale = new IconNormalizer(mIconBitmapSize).getScale(icon);
-            foreground.setDrawable(createScaledDrawable(icon, scale * LEGACY_ICON_SCALE));
+            AdaptiveIconDrawable dr = new WrappedAdaptiveIcon(
+                    new ColorDrawable(mWrapperBackgroundColor),
+                    createScaledDrawable(icon, scale * LEGACY_ICON_SCALE));
+            dr.setBounds(0, 0, 1, 1);
             return dr;
         }
     }
@@ -427,6 +454,7 @@ public class BaseIconFactory implements AutoCloseable {
             } else {
                 drawAdaptiveIcon(canvas, aid, shapePath);
             }
+
             canvas.restoreToCount(count);
         } else {
             if (icon instanceof BitmapDrawable) {
@@ -474,28 +502,28 @@ public class BaseIconFactory implements AutoCloseable {
     }
 
     /**
-     * Draws AdaptiveIconDrawable onto canvas.
-     * @param canvas canvas to draw on
-     * @param drawable AdaptiveIconDrawable to draw
-     * @param overridePath path to clip icon with for shapes
+     * Draws AdaptiveIconDrawable onto canvas using provided Path
+     * and {@link mShaderBitmap} as a shader.
+     *
+     * @param canvas    canvas to draw on
+     * @param drawable  AdaptiveIconDrawable to draw
+     * @param shapePath path to clip icon with for shapes
      */
     protected void drawAdaptiveIcon(
             @NonNull Canvas canvas,
             @NonNull AdaptiveIconDrawable drawable,
-            @NonNull Path overridePath
+            @NonNull Path shapePath
     ) {
-        if (!Flags.enableLauncherIconShapes()) {
+        Drawable background = drawable.getBackground();
+        Drawable foreground = drawable.getForeground();
+        if (!Flags.enableLauncherIconShapes() || (background == null && foreground == null)) {
             drawable.draw(canvas);
             return;
         }
-        canvas.clipPath(overridePath);
-        canvas.drawColor(BLACK);
-        if (drawable.getBackground() != null) {
-            drawable.getBackground().draw(canvas);
-        }
-        if (drawable.getForeground() != null) {
-            drawable.getForeground().draw(canvas);
-        }
+        Bitmap shaderBitmap = getAdaptiveShaderBitmap(drawable);
+        Paint paint = new Paint();
+        paint.setShader(new BitmapShader(shaderBitmap, TileMode.CLAMP, TileMode.CLAMP));
+        canvas.drawPath(shapePath, paint);
     }
 
     @Override
@@ -662,16 +690,10 @@ public class BaseIconFactory implements AutoCloseable {
         }
     }
 
-    private static class EmptyWrapper extends DrawableWrapper {
+    private static class WrappedAdaptiveIcon extends AdaptiveIconDrawable {
 
-        EmptyWrapper() {
-            super(new ColorDrawable());
-        }
-
-        @Override
-        public ConstantState getConstantState() {
-            Drawable d = getDrawable();
-            return d == null ? null : d.getConstantState();
+        WrappedAdaptiveIcon(Drawable backgroundDrawable, Drawable foregroundDrawable) {
+            super(backgroundDrawable, foregroundDrawable);
         }
     }
 }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.java b/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.java
deleted file mode 100644
index 62ca2ed..0000000
--- a/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.java
+++ /dev/null
@@ -1,268 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.launcher3.icons;
-
-import static com.android.launcher3.icons.cache.CacheLookupFlag.DEFAULT_LOOKUP_FLAG;
-
-import android.content.Context;
-import android.graphics.Bitmap;
-import android.graphics.Bitmap.Config;
-import android.graphics.Canvas;
-import android.graphics.Path;
-import android.graphics.drawable.Drawable;
-
-import androidx.annotation.IntDef;
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
-
-import com.android.launcher3.icons.cache.CacheLookupFlag;
-import com.android.launcher3.util.FlagOp;
-
-public class BitmapInfo {
-
-    public static final int FLAG_WORK = 1 << 0;
-    public static final int FLAG_INSTANT = 1 << 1;
-    public static final int FLAG_CLONE = 1 << 2;
-    public static final int FLAG_PRIVATE = 1 << 3;
-    @IntDef(flag = true, value = {
-            FLAG_WORK,
-            FLAG_INSTANT,
-            FLAG_CLONE,
-            FLAG_PRIVATE
-    })
-    @interface BitmapInfoFlags {}
-
-    public static final int FLAG_THEMED = 1 << 0;
-    public static final int FLAG_NO_BADGE = 1 << 1;
-    public static final int FLAG_SKIP_USER_BADGE = 1 << 2;
-    @IntDef(flag = true, value = {
-            FLAG_THEMED,
-            FLAG_NO_BADGE,
-            FLAG_SKIP_USER_BADGE,
-    })
-    public @interface DrawableCreationFlags {}
-
-    public static final Bitmap LOW_RES_ICON = Bitmap.createBitmap(1, 1, Config.ALPHA_8);
-    public static final BitmapInfo LOW_RES_INFO = fromBitmap(LOW_RES_ICON);
-
-    public static final String TAG = "BitmapInfo";
-
-    @NonNull
-    public final Bitmap icon;
-    public final int color;
-
-    @Nullable
-    private ThemedBitmap mThemedBitmap;
-
-    public @BitmapInfoFlags int flags;
-
-    // b/377618519: These are saved to debug why work badges sometimes don't show up on work apps
-    public @DrawableCreationFlags int creationFlags;
-
-    private BitmapInfo badgeInfo;
-
-    public BitmapInfo(@NonNull Bitmap icon, int color) {
-        this.icon = icon;
-        this.color = color;
-    }
-
-    public BitmapInfo withBadgeInfo(BitmapInfo badgeInfo) {
-        BitmapInfo result = clone();
-        result.badgeInfo = badgeInfo;
-        return result;
-    }
-
-    /**
-     * Returns a bitmapInfo with the flagOP applied
-     */
-    public BitmapInfo withFlags(@NonNull FlagOp op) {
-        if (op == FlagOp.NO_OP) {
-            return this;
-        }
-        BitmapInfo result = clone();
-        result.flags = op.apply(result.flags);
-        return result;
-    }
-
-    protected BitmapInfo copyInternalsTo(BitmapInfo target) {
-        target.mThemedBitmap = mThemedBitmap;
-        target.flags = flags;
-        target.badgeInfo = badgeInfo;
-        return target;
-    }
-
-    @Override
-    public BitmapInfo clone() {
-        return copyInternalsTo(new BitmapInfo(icon, color));
-    }
-
-    public void setThemedBitmap(@Nullable ThemedBitmap themedBitmap) {
-        mThemedBitmap = themedBitmap;
-    }
-
-    @Nullable
-    public ThemedBitmap getThemedBitmap() {
-        return mThemedBitmap;
-    }
-
-    /**
-     * Ideally icon should not be null, except in cases when generating hardware bitmap failed
-     */
-    public final boolean isNullOrLowRes() {
-        return icon == null || icon == LOW_RES_ICON;
-    }
-
-    public final boolean isLowRes() {
-        return LOW_RES_ICON == icon;
-    }
-
-    /**
-     * Returns the lookup flag to match this current state of this info
-     */
-    public CacheLookupFlag getMatchingLookupFlag() {
-        return DEFAULT_LOOKUP_FLAG.withUseLowRes(isLowRes());
-    }
-
-    /**
-     * BitmapInfo can be stored on disk or other persistent storage
-     */
-    public boolean canPersist() {
-        return !isNullOrLowRes();
-    }
-
-    /**
-     * Creates a drawable for the provided BitmapInfo
-     */
-    public FastBitmapDrawable newIcon(Context context) {
-        return newIcon(context, 0);
-    }
-
-    /**
-     * Creates a drawable for the provided BitmapInfo
-     */
-    public FastBitmapDrawable newIcon(Context context, @DrawableCreationFlags int creationFlags) {
-        return newIcon(context, creationFlags, null);
-    }
-
-    /**
-     * Creates a drawable for the provided BitmapInfo
-     *
-     * @param context Context
-     * @param creationFlags Flags for creating the FastBitmapDrawable
-     * @param badgeShape Optional Path for masking icon badges to a shape. Should be 100x100.
-     * @return FastBitmapDrawable
-     */
-    public FastBitmapDrawable newIcon(Context context, @DrawableCreationFlags int creationFlags,
-            @Nullable Path badgeShape) {
-        FastBitmapDrawable drawable;
-        if (isLowRes()) {
-            drawable = new PlaceHolderIconDrawable(this, context);
-        } else  if ((creationFlags & FLAG_THEMED) != 0 && mThemedBitmap != null) {
-            drawable = mThemedBitmap.newDrawable(this, context);
-        } else {
-            drawable = new FastBitmapDrawable(this);
-        }
-        applyFlags(context, drawable, creationFlags, badgeShape);
-        return drawable;
-    }
-
-    protected void applyFlags(Context context, FastBitmapDrawable drawable,
-            @DrawableCreationFlags int creationFlags, @Nullable Path badgeShape) {
-        this.creationFlags = creationFlags;
-        drawable.mDisabledAlpha = GraphicsUtils.getFloat(context, R.attr.disabledIconAlpha, 1f);
-        drawable.mCreationFlags = creationFlags;
-        if ((creationFlags & FLAG_NO_BADGE) == 0) {
-            Drawable badge = getBadgeDrawable(context, (creationFlags & FLAG_THEMED) != 0,
-                    (creationFlags & FLAG_SKIP_USER_BADGE) != 0, badgeShape);
-            if (badge != null) {
-                drawable.setBadge(badge);
-            }
-        }
-    }
-
-    /**
-     * Gets Badge drawable based on current flags
-     * @param context Context
-     * @param isThemed If Drawable is themed.
-     * @param badgeShape Optional Path to mask badges to a shape. Should be 100x100.
-     * @return Drawable for the badge.
-     */
-    public Drawable getBadgeDrawable(Context context, boolean isThemed, @Nullable Path badgeShape) {
-        return getBadgeDrawable(context, isThemed, false, badgeShape);
-    }
-
-
-    /**
-     * Creates a Drawable for an icon badge for this BitmapInfo
-     * @param context Context
-     * @param isThemed If the drawable is themed.
-     * @param skipUserBadge If should skip User Profile badging.
-     * @param badgeShape Optional Path to mask badge Drawable to a shape. Should be 100x100.
-     * @return Drawable for an icon Badge.
-     */
-    @Nullable
-    private Drawable getBadgeDrawable(Context context, boolean isThemed, boolean skipUserBadge,
-            @Nullable Path badgeShape) {
-        if (badgeInfo != null) {
-            int creationFlag = isThemed ? FLAG_THEMED : 0;
-            if (skipUserBadge) {
-                creationFlag |= FLAG_SKIP_USER_BADGE;
-            }
-            return badgeInfo.newIcon(context, creationFlag, badgeShape);
-        }
-        if (skipUserBadge) {
-            return null;
-        } else if ((flags & FLAG_INSTANT) != 0) {
-            return new UserBadgeDrawable(context, R.drawable.ic_instant_app_badge,
-                    R.color.badge_tint_instant, isThemed, badgeShape);
-        } else if ((flags & FLAG_WORK) != 0) {
-            return new UserBadgeDrawable(context, R.drawable.ic_work_app_badge,
-                    R.color.badge_tint_work, isThemed, badgeShape);
-        } else if ((flags & FLAG_CLONE) != 0) {
-            return new UserBadgeDrawable(context, R.drawable.ic_clone_app_badge,
-                    R.color.badge_tint_clone, isThemed, badgeShape);
-        } else if ((flags & FLAG_PRIVATE) != 0) {
-            return new UserBadgeDrawable(context, R.drawable.ic_private_profile_app_badge,
-                    R.color.badge_tint_private, isThemed, badgeShape);
-        }
-        return null;
-    }
-
-    public static BitmapInfo fromBitmap(@NonNull Bitmap bitmap) {
-        return of(bitmap, 0);
-    }
-
-    public static BitmapInfo of(@NonNull Bitmap bitmap, int color) {
-        return new BitmapInfo(bitmap, color);
-    }
-
-    /**
-     * Interface to be implemented by drawables to provide a custom BitmapInfo
-     */
-    public interface Extender {
-
-        /**
-         * Called for creating a custom BitmapInfo
-         */
-        BitmapInfo getExtendedInfo(Bitmap bitmap, int color,
-                BaseIconFactory iconFactory, float normalizationScale);
-
-        /**
-         * Called to draw the UI independent of any runtime configurations like time or theme
-         */
-        void drawForPersistence(Canvas canvas);
-    }
-}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.kt b/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.kt
new file mode 100644
index 0000000..1b3f0fa
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.kt
@@ -0,0 +1,272 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.android.launcher3.icons
+
+import android.content.Context
+import android.graphics.Bitmap
+import android.graphics.Canvas
+import android.graphics.Path
+import android.graphics.drawable.Drawable
+import androidx.annotation.ColorRes
+import androidx.annotation.DrawableRes
+import androidx.annotation.IntDef
+import com.android.launcher3.icons.cache.CacheLookupFlag
+import com.android.launcher3.util.FlagOp
+
+open class BitmapInfo(
+    @JvmField val icon: Bitmap,
+    @JvmField val color: Int,
+    @BitmapInfoFlags @JvmField var flags: Int = 0,
+    var themedBitmap: ThemedBitmap? = null,
+) {
+    @IntDef(
+        flag = true,
+        value = [FLAG_WORK, FLAG_INSTANT, FLAG_CLONE, FLAG_PRIVATE, FLAG_WRAPPED_NON_ADAPTIVE],
+    )
+    internal annotation class BitmapInfoFlags
+
+    @IntDef(flag = true, value = [FLAG_THEMED, FLAG_NO_BADGE, FLAG_SKIP_USER_BADGE])
+    annotation class DrawableCreationFlags
+
+    // b/377618519: These are saved to debug why work badges sometimes don't show up on work apps
+    @DrawableCreationFlags @JvmField var creationFlags: Int = 0
+
+    private var badgeInfo: BitmapInfo? = null
+
+    fun withBadgeInfo(badgeInfo: BitmapInfo?) = clone().also { it.badgeInfo = badgeInfo }
+
+    /** Returns a bitmapInfo with the flagOP applied */
+    fun withFlags(op: FlagOp): BitmapInfo {
+        if (op === FlagOp.NO_OP) {
+            return this
+        }
+        return clone().also { it.flags = op.apply(it.flags) }
+    }
+
+    @Override
+    open fun clone(): BitmapInfo {
+        return copyInternalsTo(BitmapInfo(icon, color))
+    }
+
+    protected fun copyInternalsTo(target: BitmapInfo): BitmapInfo {
+        target.themedBitmap = themedBitmap
+        target.flags = flags
+        target.badgeInfo = badgeInfo
+        return target
+    }
+
+    // TODO: rename or remove because icon can no longer be null?
+    val isNullOrLowRes: Boolean
+        get() = icon == LOW_RES_ICON
+
+    val isLowRes: Boolean
+        get() = matchingLookupFlag.useLowRes()
+
+    open val matchingLookupFlag: CacheLookupFlag
+        /** Returns the lookup flag to match this current state of this info */
+        get() =
+            CacheLookupFlag.DEFAULT_LOOKUP_FLAG.withUseLowRes(LOW_RES_ICON == icon)
+                .withThemeIcon(themedBitmap != null)
+
+    /** BitmapInfo can be stored on disk or other persistent storage */
+    open fun canPersist(): Boolean {
+        return !isNullOrLowRes
+    }
+
+    /** Creates a drawable for the provided BitmapInfo */
+    @JvmOverloads
+    fun newIcon(
+        context: Context,
+        @DrawableCreationFlags creationFlags: Int = 0,
+    ): FastBitmapDrawable {
+        return newIcon(context, creationFlags, null)
+    }
+
+    /**
+     * Creates a drawable for the provided BitmapInfo
+     *
+     * @param context Context
+     * @param creationFlags Flags for creating the FastBitmapDrawable
+     * @param badgeShape Optional Path for masking icon badges to a shape. Should be 100x100.
+     * @return FastBitmapDrawable
+     */
+    open fun newIcon(
+        context: Context,
+        @DrawableCreationFlags creationFlags: Int,
+        badgeShape: Path?,
+    ): FastBitmapDrawable {
+        val drawable: FastBitmapDrawable =
+            if (isLowRes) {
+                PlaceHolderIconDrawable(this, context)
+            } else if (
+                (creationFlags and FLAG_THEMED) != 0 &&
+                    themedBitmap != null &&
+                    themedBitmap !== ThemedBitmap.NOT_SUPPORTED
+            ) {
+                themedBitmap!!.newDrawable(this, context)
+            } else {
+                FastBitmapDrawable(this)
+            }
+        applyFlags(context, drawable, creationFlags, badgeShape)
+        return drawable
+    }
+
+    protected fun applyFlags(
+        context: Context, drawable: FastBitmapDrawable,
+        @DrawableCreationFlags creationFlags: Int, badgeShape: Path?
+    ) {
+        this.creationFlags = creationFlags
+        drawable.disabledAlpha = GraphicsUtils.getFloat(context, R.attr.disabledIconAlpha, 1f)
+        drawable.creationFlags = creationFlags
+        if ((creationFlags and FLAG_NO_BADGE) == 0) {
+            val badge = getBadgeDrawable(
+                context, (creationFlags and FLAG_THEMED) != 0,
+                (creationFlags and FLAG_SKIP_USER_BADGE) != 0, badgeShape
+            )
+            if (badge != null) {
+                drawable.badge = badge
+            }
+        }
+    }
+
+    /**
+     * Gets Badge drawable based on current flags
+     *
+     * @param context Context
+     * @param isThemed If Drawable is themed.
+     * @param badgeShape Optional Path to mask badges to a shape. Should be 100x100.
+     * @return Drawable for the badge.
+     */
+    fun getBadgeDrawable(context: Context, isThemed: Boolean, badgeShape: Path?): Drawable? {
+        return getBadgeDrawable(context, isThemed, false, badgeShape)
+    }
+
+    /**
+     * Creates a Drawable for an icon badge for this BitmapInfo
+     * @param context Context
+     * @param isThemed If the drawable is themed.
+     * @param skipUserBadge If should skip User Profile badging.
+     * @param badgeShape Optional Path to mask badge Drawable to a shape. Should be 100x100.
+     * @return Drawable for an icon Badge.
+     */
+    private fun getBadgeDrawable(
+        context: Context, isThemed: Boolean, skipUserBadge: Boolean, badgeShape: Path?
+    ): Drawable? {
+        if (badgeInfo != null) {
+            var creationFlag = if (isThemed) FLAG_THEMED else 0
+            if (skipUserBadge) {
+                creationFlag = creationFlag or FLAG_SKIP_USER_BADGE
+            }
+            return badgeInfo!!.newIcon(context, creationFlag, badgeShape)
+        }
+        if (skipUserBadge) {
+            return null
+        } else {
+            getBadgeDrawableInfo()?.let {
+                return UserBadgeDrawable(
+                    context,
+                    it.drawableRes,
+                    it.colorRes,
+                    isThemed,
+                    badgeShape
+                )
+            }
+        }
+        return null
+    }
+
+    /**
+     * Returns information about the badge to apply based on current flags.
+     */
+    fun getBadgeDrawableInfo(): BadgeDrawableInfo? {
+        return when {
+            (flags and FLAG_INSTANT) != 0 -> BadgeDrawableInfo(
+                R.drawable.ic_instant_app_badge,
+                R.color.badge_tint_instant
+            )
+            (flags and FLAG_WORK) != 0 -> BadgeDrawableInfo(
+                R.drawable.ic_work_app_badge,
+                R.color.badge_tint_work
+            )
+            (flags and FLAG_CLONE) != 0 -> BadgeDrawableInfo(
+                R.drawable.ic_clone_app_badge,
+                R.color.badge_tint_clone
+            )
+            (flags and FLAG_PRIVATE) != 0 -> BadgeDrawableInfo(
+                R.drawable.ic_private_profile_app_badge,
+                R.color.badge_tint_private
+            )
+            else -> null
+        }
+    }
+
+
+    /** Interface to be implemented by drawables to provide a custom BitmapInfo */
+    interface Extender {
+        /** Called for creating a custom BitmapInfo */
+        fun getExtendedInfo(
+            bitmap: Bitmap?,
+            color: Int,
+            iconFactory: BaseIconFactory?,
+            normalizationScale: Float,
+        ): BitmapInfo?
+
+        /** Called to draw the UI independent of any runtime configurations like time or theme */
+        fun drawForPersistence(canvas: Canvas?)
+    }
+
+    /**
+     * Drawables backing a specific badge shown on app icons.
+     * @param drawableRes Drawable resource for the badge.
+     * @param colorRes Color resource to tint the badge.
+     */
+    @JvmRecord
+    data class BadgeDrawableInfo(
+        @field:DrawableRes @param:DrawableRes val drawableRes: Int,
+        @field:ColorRes @param:ColorRes val colorRes: Int
+    )
+
+    companion object {
+        const val TAG: String = "BitmapInfo"
+
+        // BitmapInfo flags
+        const val FLAG_WORK: Int = 1 shl 0
+        const val FLAG_INSTANT: Int = 1 shl 1
+        const val FLAG_CLONE: Int = 1 shl 2
+        const val FLAG_PRIVATE: Int = 1 shl 3
+        const val FLAG_WRAPPED_NON_ADAPTIVE: Int = 1 shl 4
+
+        // Drawable creation flags
+        const val FLAG_THEMED: Int = 1 shl 0
+        const val FLAG_NO_BADGE: Int = 1 shl 1
+        const val FLAG_SKIP_USER_BADGE: Int = 1 shl 2
+
+        @JvmField
+        val LOW_RES_ICON: Bitmap = Bitmap.createBitmap(1, 1, Bitmap.Config.ALPHA_8)
+        @JvmField
+        val LOW_RES_INFO: BitmapInfo = fromBitmap(LOW_RES_ICON)
+
+        @JvmStatic
+        fun fromBitmap(bitmap: Bitmap): BitmapInfo {
+            return of(bitmap, 0)
+        }
+
+        @JvmStatic
+        fun of(bitmap: Bitmap, color: Int): BitmapInfo {
+            return BitmapInfo(bitmap, color)
+        }
+    }
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/ClockDrawableWrapper.java b/iconloaderlib/src/com/android/launcher3/icons/ClockDrawableWrapper.java
index 1311904..bd5ba66 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/ClockDrawableWrapper.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/ClockDrawableWrapper.java
@@ -16,6 +16,7 @@
 package com.android.launcher3.icons;
 
 import static com.android.launcher3.icons.IconProvider.ATLEAST_T;
+import static com.android.launcher3.icons.cache.CacheLookupFlag.DEFAULT_LOOKUP_FLAG;
 
 import android.annotation.TargetApi;
 import android.content.Context;
@@ -40,6 +41,7 @@ import android.os.Bundle;
 import android.os.SystemClock;
 import android.util.Log;
 
+import com.android.launcher3.icons.cache.CacheLookupFlag;
 import com.android.launcher3.icons.mono.ThemedIconDrawable;
 
 import java.util.Calendar;
@@ -273,7 +275,7 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
         ClockBitmapInfo(Bitmap icon, int color, float scale,
                 AnimationInfo animInfo, Bitmap background,
                 AnimationInfo themeInfo, Bitmap themeBackground) {
-            super(icon, color);
+            super(icon, color, /* flags */ 0, /* themedBitmap */ null);
             this.boundsOffset = Math.max(ShadowGenerator.BLUR_FACTOR, (1 - scale) / 2);
             this.animInfo = animInfo;
             this.mFlattenedBackground = background;
@@ -284,7 +286,7 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
         @Override
         @TargetApi(Build.VERSION_CODES.TIRAMISU)
         public FastBitmapDrawable newIcon(Context context,
-                @DrawableCreationFlags  int creationFlags, Path badgeShape) {
+                @DrawableCreationFlags int creationFlags, Path badgeShape) {
             AnimationInfo info;
             Bitmap bg;
             int themedFgColor;
@@ -320,8 +322,14 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
 
         @Override
         public BitmapInfo clone() {
-            return copyInternalsTo(new ClockBitmapInfo(icon, color, 1 - 2 * boundsOffset, animInfo,
-                    mFlattenedBackground, themeData, themeBackground));
+            return copyInternalsTo(new ClockBitmapInfo(icon, color,
+                    1 - 2 * boundsOffset, animInfo, mFlattenedBackground,
+                    themeData, themeBackground));
+        }
+
+        @Override
+        public CacheLookupFlag getMatchingLookupFlag() {
+            return DEFAULT_LOOKUP_FLAG.withThemeIcon(themeData != null);
         }
     }
 
@@ -342,7 +350,7 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
         private final float mCanvasScale;
 
         ClockIconDrawable(ClockConstantState cs) {
-            super(cs.mBitmapInfo);
+            super(cs.getBitmapInfo());
             mBoundsOffset = cs.mBoundsOffset;
             mAnimInfo = cs.mAnimInfo;
 
@@ -405,10 +413,11 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
         @Override
         protected void updateFilter() {
             super.updateFilter();
-            int alpha = mIsDisabled ? (int) (mDisabledAlpha * FULLY_OPAQUE) : FULLY_OPAQUE;
+            boolean isDisabled = isDisabled();
+            int alpha = isDisabled ? (int) (disabledAlpha * FULLY_OPAQUE) : FULLY_OPAQUE;
             setAlpha(alpha);
-            mBgPaint.setColorFilter(mIsDisabled ? getDisabledColorFilter() : mBgFilter);
-            mFG.setColorFilter(mIsDisabled ? getDisabledColorFilter() : null);
+            mBgPaint.setColorFilter(isDisabled ? getDisabledColorFilter() : mBgFilter);
+            mFG.setColorFilter(isDisabled ? getDisabledColorFilter() : null);
         }
 
         @Override
@@ -448,7 +457,7 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
 
         @Override
         public FastBitmapConstantState newConstantState() {
-            return new ClockConstantState(mBitmapInfo, mThemedFgColor, mBoundsOffset,
+            return new ClockConstantState(bitmapInfo, mThemedFgColor, mBoundsOffset,
                     mAnimInfo, mBG, mBgPaint.getColorFilter());
         }
 
diff --git a/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.java b/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.java
deleted file mode 100644
index f6ad4d1..0000000
--- a/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.java
+++ /dev/null
@@ -1,471 +0,0 @@
-/*
- * Copyright (C) 2008 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.launcher3.icons;
-
-import static com.android.launcher3.icons.BaseIconFactory.getBadgeSizeForIconSize;
-import static com.android.launcher3.icons.BitmapInfo.FLAG_NO_BADGE;
-import static com.android.launcher3.icons.BitmapInfo.FLAG_THEMED;
-import static com.android.launcher3.icons.GraphicsUtils.setColorAlphaBound;
-
-import android.animation.ObjectAnimator;
-import android.graphics.Bitmap;
-import android.graphics.Canvas;
-import android.graphics.Color;
-import android.graphics.ColorFilter;
-import android.graphics.ColorMatrix;
-import android.graphics.ColorMatrixColorFilter;
-import android.graphics.Paint;
-import android.graphics.PixelFormat;
-import android.graphics.Rect;
-import android.graphics.drawable.Drawable;
-import android.util.FloatProperty;
-import android.view.animation.AccelerateInterpolator;
-import android.view.animation.DecelerateInterpolator;
-import android.view.animation.Interpolator;
-import android.view.animation.PathInterpolator;
-
-import androidx.annotation.Nullable;
-import androidx.annotation.VisibleForTesting;
-import androidx.core.graphics.ColorUtils;
-
-import com.android.launcher3.icons.BitmapInfo.DrawableCreationFlags;
-
-public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
-
-    private static final Interpolator ACCEL = new AccelerateInterpolator();
-    private static final Interpolator DEACCEL = new DecelerateInterpolator();
-    private static final Interpolator HOVER_EMPHASIZED_DECELERATE_INTERPOLATOR =
-            new PathInterpolator(0.05f, 0.7f, 0.1f, 1.0f);
-
-    @VisibleForTesting protected static final float PRESSED_SCALE = 1.1f;
-    @VisibleForTesting protected static final float HOVERED_SCALE = 1.1f;
-    public static final int WHITE_SCRIM_ALPHA = 138;
-
-    private static final float DISABLED_DESATURATION = 1f;
-    private static final float DISABLED_BRIGHTNESS = 0.5f;
-    protected static final int FULLY_OPAQUE = 255;
-
-    public static final int CLICK_FEEDBACK_DURATION = 200;
-    public static final int HOVER_FEEDBACK_DURATION = 300;
-
-    private static boolean sFlagHoverEnabled = false;
-
-    protected final Paint mPaint = new Paint(Paint.FILTER_BITMAP_FLAG | Paint.ANTI_ALIAS_FLAG);
-    public final BitmapInfo mBitmapInfo;
-
-    @Nullable private ColorFilter mColorFilter;
-
-    @VisibleForTesting protected boolean mIsPressed;
-    @VisibleForTesting protected boolean mIsHovered;
-    protected boolean mIsDisabled;
-    protected float mDisabledAlpha = 1f;
-
-    @DrawableCreationFlags int mCreationFlags = 0;
-
-    // Animator and properties for the fast bitmap drawable's scale
-    @VisibleForTesting protected static final FloatProperty<FastBitmapDrawable> SCALE
-            = new FloatProperty<FastBitmapDrawable>("scale") {
-        @Override
-        public Float get(FastBitmapDrawable fastBitmapDrawable) {
-            return fastBitmapDrawable.mScale;
-        }
-
-        @Override
-        public void setValue(FastBitmapDrawable fastBitmapDrawable, float value) {
-            fastBitmapDrawable.mScale = value;
-            fastBitmapDrawable.invalidateSelf();
-        }
-    };
-    @VisibleForTesting protected ObjectAnimator mScaleAnimation;
-    private float mScale = 1;
-    private int mAlpha = 255;
-
-    private Drawable mBadge;
-
-    private boolean mHoverScaleEnabledForDisplay = true;
-
-    protected FastBitmapDrawable(Bitmap b, int iconColor) {
-        this(BitmapInfo.of(b, iconColor));
-    }
-
-    public FastBitmapDrawable(Bitmap b) {
-        this(BitmapInfo.fromBitmap(b));
-    }
-
-    public FastBitmapDrawable(BitmapInfo info) {
-        mBitmapInfo = info;
-        setFilterBitmap(true);
-    }
-
-    /**
-     * Returns true if the drawable points to the same bitmap icon object
-     */
-    public boolean isSameInfo(BitmapInfo info) {
-        return mBitmapInfo == info;
-    }
-
-    @Override
-    protected void onBoundsChange(Rect bounds) {
-        super.onBoundsChange(bounds);
-        updateBadgeBounds(bounds);
-    }
-
-    private void updateBadgeBounds(Rect bounds) {
-        if (mBadge != null) {
-            setBadgeBounds(mBadge, bounds);
-        }
-    }
-
-    @Override
-    public final void draw(Canvas canvas) {
-        if (mScale != 1f) {
-            int count = canvas.save();
-            Rect bounds = getBounds();
-            canvas.scale(mScale, mScale, bounds.exactCenterX(), bounds.exactCenterY());
-            drawInternal(canvas, bounds);
-            if (mBadge != null) {
-                mBadge.draw(canvas);
-            }
-            canvas.restoreToCount(count);
-        } else {
-            drawInternal(canvas, getBounds());
-            if (mBadge != null) {
-                mBadge.draw(canvas);
-            }
-        }
-    }
-
-    protected void drawInternal(Canvas canvas, Rect bounds) {
-        canvas.drawBitmap(mBitmapInfo.icon, null, bounds, mPaint);
-    }
-
-    /**
-     * Returns the primary icon color, slightly tinted white
-     */
-    public int getIconColor() {
-        int whiteScrim = setColorAlphaBound(Color.WHITE, WHITE_SCRIM_ALPHA);
-        return ColorUtils.compositeColors(whiteScrim, mBitmapInfo.color);
-    }
-
-    /**
-     * Returns if this represents a themed icon
-     */
-    public boolean isThemed() {
-        return false;
-    }
-
-    /**
-     * Returns true if the drawable was created with theme, even if it doesn't
-     * support theming itself.
-     */
-    public boolean isCreatedForTheme() {
-        return isThemed() || (mCreationFlags & FLAG_THEMED) != 0;
-    }
-
-    @Override
-    public void setColorFilter(ColorFilter cf) {
-        mColorFilter = cf;
-        updateFilter();
-    }
-
-    @Override
-    public int getOpacity() {
-        return PixelFormat.TRANSLUCENT;
-    }
-
-    @Override
-    public void setAlpha(int alpha) {
-        if (mAlpha != alpha) {
-            mAlpha = alpha;
-            mPaint.setAlpha(alpha);
-            invalidateSelf();
-            if (mBadge != null) {
-                mBadge.setAlpha(alpha);
-            }
-        }
-    }
-
-    @Override
-    public void setFilterBitmap(boolean filterBitmap) {
-        mPaint.setFilterBitmap(filterBitmap);
-        mPaint.setAntiAlias(filterBitmap);
-    }
-
-    @Override
-    public int getAlpha() {
-        return mAlpha;
-    }
-
-    public void resetScale() {
-        if (mScaleAnimation != null) {
-            mScaleAnimation.cancel();
-            mScaleAnimation = null;
-        }
-        mScale = 1;
-        invalidateSelf();
-    }
-
-    public float getAnimatedScale() {
-        return mScaleAnimation == null ? 1 : mScale;
-    }
-
-    @Override
-    public int getIntrinsicWidth() {
-        return mBitmapInfo.icon.getWidth();
-    }
-
-    @Override
-    public int getIntrinsicHeight() {
-        return mBitmapInfo.icon.getHeight();
-    }
-
-    @Override
-    public int getMinimumWidth() {
-        return getBounds().width();
-    }
-
-    @Override
-    public int getMinimumHeight() {
-        return getBounds().height();
-    }
-
-    @Override
-    public boolean isStateful() {
-        return true;
-    }
-
-    @Override
-    public ColorFilter getColorFilter() {
-        return mPaint.getColorFilter();
-    }
-
-    @Override
-    protected boolean onStateChange(int[] state) {
-        boolean isPressed = false;
-        boolean isHovered = false;
-        for (int s : state) {
-            if (s == android.R.attr.state_pressed) {
-                isPressed = true;
-                break;
-            } else if (sFlagHoverEnabled
-                    && s == android.R.attr.state_hovered
-                    && mHoverScaleEnabledForDisplay) {
-                isHovered = true;
-                // Do not break on hovered state, as pressed state should take precedence.
-            }
-        }
-        if (mIsPressed != isPressed || mIsHovered != isHovered) {
-            if (mScaleAnimation != null) {
-                mScaleAnimation.cancel();
-            }
-
-            float endScale = isPressed ? PRESSED_SCALE : (isHovered ? HOVERED_SCALE : 1f);
-            if (mScale != endScale) {
-                if (isVisible()) {
-                    Interpolator interpolator =
-                            isPressed != mIsPressed ? (isPressed ? ACCEL : DEACCEL)
-                                    : HOVER_EMPHASIZED_DECELERATE_INTERPOLATOR;
-                    int duration =
-                            isPressed != mIsPressed ? CLICK_FEEDBACK_DURATION
-                                    : HOVER_FEEDBACK_DURATION;
-                    mScaleAnimation = ObjectAnimator.ofFloat(this, SCALE, endScale);
-                    mScaleAnimation.setDuration(duration);
-                    mScaleAnimation.setInterpolator(interpolator);
-                    mScaleAnimation.start();
-                } else {
-                    mScale = endScale;
-                    invalidateSelf();
-                }
-            }
-            mIsPressed = isPressed;
-            mIsHovered = isHovered;
-            return true;
-        }
-        return false;
-    }
-
-    public void setIsDisabled(boolean isDisabled) {
-        if (mIsDisabled != isDisabled) {
-            mIsDisabled = isDisabled;
-            if (mBadge instanceof FastBitmapDrawable fbd) {
-                fbd.setIsDisabled(isDisabled);
-            }
-            updateFilter();
-        }
-    }
-
-    protected boolean isDisabled() {
-        return mIsDisabled;
-    }
-
-    public void setBadge(Drawable badge) {
-        if (mBadge != null) {
-            mBadge.setCallback(null);
-        }
-        mBadge = badge;
-        if (mBadge != null) {
-            mBadge.setCallback(this);
-        }
-        updateBadgeBounds(getBounds());
-        updateFilter();
-    }
-
-    @VisibleForTesting
-    public Drawable getBadge() {
-        return mBadge;
-    }
-
-    /**
-     * Updates the paint to reflect the current brightness and saturation.
-     */
-    protected void updateFilter() {
-        mPaint.setColorFilter(mIsDisabled ? getDisabledColorFilter(mDisabledAlpha) : mColorFilter);
-        if (mBadge != null) {
-            mBadge.setColorFilter(getColorFilter());
-        }
-        invalidateSelf();
-    }
-
-    protected FastBitmapConstantState newConstantState() {
-        return new FastBitmapConstantState(mBitmapInfo);
-    }
-
-    @Override
-    public final ConstantState getConstantState() {
-        FastBitmapConstantState cs = newConstantState();
-        cs.mIsDisabled = mIsDisabled;
-        if (mBadge != null) {
-            cs.mBadgeConstantState = mBadge.getConstantState();
-        }
-        cs.mCreationFlags = mCreationFlags;
-        return cs;
-    }
-
-    public static ColorFilter getDisabledColorFilter() {
-        return getDisabledColorFilter(1);
-    }
-
-    // Returns if the FastBitmapDrawable contains a badge.
-    public boolean hasBadge() {
-        return (mCreationFlags & FLAG_NO_BADGE) == 0;
-    }
-
-    private static ColorFilter getDisabledColorFilter(float disabledAlpha) {
-        ColorMatrix tempBrightnessMatrix = new ColorMatrix();
-        ColorMatrix tempFilterMatrix = new ColorMatrix();
-
-        tempFilterMatrix.setSaturation(1f - DISABLED_DESATURATION);
-        float scale = 1 - DISABLED_BRIGHTNESS;
-        int brightnessI =   (int) (255 * DISABLED_BRIGHTNESS);
-        float[] mat = tempBrightnessMatrix.getArray();
-        mat[0] = scale;
-        mat[6] = scale;
-        mat[12] = scale;
-        mat[4] = brightnessI;
-        mat[9] = brightnessI;
-        mat[14] = brightnessI;
-        mat[18] = disabledAlpha;
-        tempFilterMatrix.preConcat(tempBrightnessMatrix);
-        return new ColorMatrixColorFilter(tempFilterMatrix);
-    }
-
-    protected static final int getDisabledColor(int color) {
-        int component = (Color.red(color) + Color.green(color) + Color.blue(color)) / 3;
-        float scale = 1 - DISABLED_BRIGHTNESS;
-        int brightnessI = (int) (255 * DISABLED_BRIGHTNESS);
-        component = Math.min(Math.round(scale * component + brightnessI), FULLY_OPAQUE);
-        return Color.rgb(component, component, component);
-    }
-
-    /**
-     * Sets the bounds for the badge drawable based on the main icon bounds
-     */
-    public static void setBadgeBounds(Drawable badge, Rect iconBounds) {
-        int size = getBadgeSizeForIconSize(iconBounds.width());
-        badge.setBounds(iconBounds.right - size, iconBounds.bottom - size,
-                iconBounds.right, iconBounds.bottom);
-    }
-
-    @Override
-    public void invalidateDrawable(Drawable who) {
-        if (who == mBadge) {
-            invalidateSelf();
-        }
-    }
-
-    @Override
-    public void scheduleDrawable(Drawable who, Runnable what, long when) {
-        if (who == mBadge) {
-            scheduleSelf(what, when);
-        }
-    }
-
-    @Override
-    public void unscheduleDrawable(Drawable who, Runnable what) {
-        unscheduleSelf(what);
-    }
-
-    /**
-     * Sets whether hover state functionality is enabled.
-     */
-    public static void setFlagHoverEnabled(boolean isFlagHoverEnabled) {
-        sFlagHoverEnabled = isFlagHoverEnabled;
-    }
-
-    public void setHoverScaleEnabledForDisplay(boolean hoverScaleEnabledForDisplay) {
-        mHoverScaleEnabledForDisplay = hoverScaleEnabledForDisplay;
-    }
-
-    public static class FastBitmapConstantState extends ConstantState {
-        protected final BitmapInfo mBitmapInfo;
-
-        // These are initialized later so that subclasses don't need to
-        // pass everything in constructor
-        protected boolean mIsDisabled;
-        private ConstantState mBadgeConstantState;
-
-        @DrawableCreationFlags int mCreationFlags = 0;
-
-        public FastBitmapConstantState(Bitmap bitmap, int color) {
-            this(BitmapInfo.of(bitmap, color));
-        }
-
-        public FastBitmapConstantState(BitmapInfo info) {
-            mBitmapInfo = info;
-        }
-
-        protected FastBitmapDrawable createDrawable() {
-            return new FastBitmapDrawable(mBitmapInfo);
-        }
-
-        @Override
-        public final FastBitmapDrawable newDrawable() {
-            FastBitmapDrawable drawable = createDrawable();
-            drawable.setIsDisabled(mIsDisabled);
-            if (mBadgeConstantState != null) {
-                drawable.setBadge(mBadgeConstantState.newDrawable());
-            }
-            drawable.mCreationFlags = mCreationFlags;
-            return drawable;
-        }
-
-        @Override
-        public int getChangingConfigurations() {
-            return 0;
-        }
-    }
-}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.kt b/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.kt
new file mode 100644
index 0000000..670915a
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.kt
@@ -0,0 +1,369 @@
+/*
+ * Copyright (C) 2008 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.android.launcher3.icons
+
+import android.R
+import android.animation.ObjectAnimator
+import android.graphics.Bitmap
+import android.graphics.Canvas
+import android.graphics.Color
+import android.graphics.ColorFilter
+import android.graphics.ColorMatrix
+import android.graphics.ColorMatrixColorFilter
+import android.graphics.Paint
+import android.graphics.Paint.ANTI_ALIAS_FLAG
+import android.graphics.Paint.FILTER_BITMAP_FLAG
+import android.graphics.PixelFormat
+import android.graphics.Rect
+import android.graphics.drawable.Drawable
+import android.graphics.drawable.Drawable.Callback
+import android.util.FloatProperty
+import android.view.animation.AccelerateInterpolator
+import android.view.animation.DecelerateInterpolator
+import android.view.animation.Interpolator
+import android.view.animation.PathInterpolator
+import androidx.annotation.VisibleForTesting
+import androidx.core.graphics.ColorUtils
+import com.android.launcher3.icons.BitmapInfo.DrawableCreationFlags
+import kotlin.math.min
+
+open class FastBitmapDrawable(info: BitmapInfo?) : Drawable(), Callback {
+
+    @JvmOverloads constructor(b: Bitmap, iconColor: Int = 0) : this(BitmapInfo.of(b, iconColor))
+
+    @JvmField val bitmapInfo: BitmapInfo = info ?: BitmapInfo.LOW_RES_INFO
+    var isAnimationEnabled: Boolean = true
+
+    @JvmField protected val paint: Paint = Paint(FILTER_BITMAP_FLAG or ANTI_ALIAS_FLAG)
+
+    @JvmField @VisibleForTesting var isPressed: Boolean = false
+    @JvmField @VisibleForTesting var isHovered: Boolean = false
+
+    @JvmField var disabledAlpha: Float = 1f
+
+    var isDisabled: Boolean = false
+        set(value) {
+            if (field != value) {
+                field = value
+                badge.let { if (it is FastBitmapDrawable) it.isDisabled = value }
+                updateFilter()
+            }
+        }
+
+    @JvmField @DrawableCreationFlags var creationFlags: Int = 0
+    @JvmField @VisibleForTesting var scaleAnimation: ObjectAnimator? = null
+    var hoverScaleEnabledForDisplay = true
+
+    private var scale = 1f
+
+    private var paintAlpha = 255
+    private var paintFilter: ColorFilter? = null
+
+    init {
+        isFilterBitmap = true
+    }
+
+    var badge: Drawable? = null
+        set(value) {
+            field?.callback = null
+            field = value
+            field?.let {
+                it.callback = this
+                it.setBadgeBounds(bounds)
+            }
+            updateFilter()
+        }
+
+    /** Returns true if the drawable points to the same bitmap icon object */
+    fun isSameInfo(info: BitmapInfo): Boolean = bitmapInfo === info
+
+    override fun onBoundsChange(bounds: Rect) {
+        super.onBoundsChange(bounds)
+        badge?.setBadgeBounds(bounds)
+    }
+
+    override fun draw(canvas: Canvas) {
+        if (scale != 1f) {
+            val count = canvas.save()
+            val bounds = bounds
+            canvas.scale(scale, scale, bounds.exactCenterX(), bounds.exactCenterY())
+            drawInternal(canvas, bounds)
+            badge?.draw(canvas)
+            canvas.restoreToCount(count)
+        } else {
+            drawInternal(canvas, bounds)
+            badge?.draw(canvas)
+        }
+    }
+
+    protected open fun drawInternal(canvas: Canvas, bounds: Rect) {
+        canvas.drawBitmap(bitmapInfo.icon, null, bounds, paint)
+    }
+
+    /** Returns the primary icon color, slightly tinted white */
+    open fun getIconColor(): Int =
+        ColorUtils.compositeColors(
+            GraphicsUtils.setColorAlphaBound(Color.WHITE, WHITE_SCRIM_ALPHA),
+            bitmapInfo.color,
+        )
+
+    /** Returns if this represents a themed icon */
+    open fun isThemed(): Boolean = false
+
+    /**
+     * Returns true if the drawable was created with theme, even if it doesn't support theming
+     * itself.
+     */
+    fun isCreatedForTheme(): Boolean = isThemed() || (creationFlags and BitmapInfo.FLAG_THEMED) != 0
+
+    override fun setColorFilter(cf: ColorFilter?) {
+        paintFilter = cf
+        updateFilter()
+    }
+
+    override fun getColorFilter(): ColorFilter? = paint.colorFilter
+
+    @Deprecated("This method is no longer used in graphics optimizations")
+    override fun getOpacity(): Int = PixelFormat.TRANSLUCENT
+
+    override fun setAlpha(alpha: Int) {
+        if (paintAlpha != alpha) {
+            paintAlpha = alpha
+            paint.alpha = alpha
+            invalidateSelf()
+            badge?.alpha = alpha
+        }
+    }
+
+    override fun getAlpha(): Int = paintAlpha
+
+    override fun setFilterBitmap(filterBitmap: Boolean) {
+        paint.isFilterBitmap = filterBitmap
+        paint.isAntiAlias = filterBitmap
+    }
+
+    fun resetScale() {
+        scaleAnimation?.cancel()
+        scaleAnimation = null
+        scale = 1f
+        invalidateSelf()
+    }
+
+    fun getAnimatedScale(): Float = if (scaleAnimation == null) 1f else scale
+
+    override fun getIntrinsicWidth(): Int = bitmapInfo.icon.width
+
+    override fun getIntrinsicHeight(): Int = bitmapInfo.icon.height
+
+    override fun getMinimumWidth(): Int = bounds.width()
+
+    override fun getMinimumHeight(): Int = bounds.height()
+
+    override fun isStateful(): Boolean = true
+
+    public override fun onStateChange(state: IntArray): Boolean {
+        if (!isAnimationEnabled) {
+            return false
+        }
+
+        var isPressed = false
+        var isHovered = false
+        for (s in state) {
+            if (s == R.attr.state_pressed) {
+                isPressed = true
+                break
+            } else if (s == R.attr.state_hovered && hoverScaleEnabledForDisplay) {
+                isHovered = true
+                // Do not break on hovered state, as pressed state should take precedence.
+            }
+        }
+        if (this.isPressed != isPressed || this.isHovered != isHovered) {
+            scaleAnimation?.cancel()
+
+            val endScale =
+                when {
+                    isPressed -> PRESSED_SCALE
+                    isHovered -> HOVERED_SCALE
+                    else -> 1f
+                }
+            if (scale != endScale) {
+                if (isVisible) {
+                    scaleAnimation =
+                        ObjectAnimator.ofFloat(this, SCALE, endScale).apply {
+                            duration =
+                                if (isPressed != this@FastBitmapDrawable.isPressed)
+                                    CLICK_FEEDBACK_DURATION.toLong()
+                                else HOVER_FEEDBACK_DURATION.toLong()
+
+                            interpolator =
+                                if (isPressed != this@FastBitmapDrawable.isPressed)
+                                    (if (isPressed) ACCEL else DEACCEL)
+                                else HOVER_EMPHASIZED_DECELERATE_INTERPOLATOR
+                        }
+                    scaleAnimation?.start()
+                } else {
+                    scale = endScale
+                    invalidateSelf()
+                }
+            }
+            this.isPressed = isPressed
+            this.isHovered = isHovered
+            return true
+        }
+        return false
+    }
+
+    /** Updates the paint to reflect the current brightness and saturation. */
+    protected open fun updateFilter() {
+        paint.setColorFilter(if (isDisabled) getDisabledColorFilter(disabledAlpha) else paintFilter)
+        badge?.colorFilter = colorFilter
+        invalidateSelf()
+    }
+
+    protected open fun newConstantState(): FastBitmapConstantState {
+        return FastBitmapConstantState(bitmapInfo)
+    }
+
+    override fun getConstantState(): ConstantState {
+        val cs = newConstantState()
+        cs.mIsDisabled = isDisabled
+        cs.mBadgeConstantState = badge?.constantState
+        cs.mCreationFlags = creationFlags
+        return cs
+    }
+
+    // Returns if the FastBitmapDrawable contains a badge.
+    fun hasBadge(): Boolean = (creationFlags and BitmapInfo.FLAG_NO_BADGE) == 0
+
+    override fun invalidateDrawable(who: Drawable) {
+        if (who === badge) {
+            invalidateSelf()
+        }
+    }
+
+    override fun scheduleDrawable(who: Drawable, what: Runnable, time: Long) {
+        if (who === badge) {
+            scheduleSelf(what, time)
+        }
+    }
+
+    override fun unscheduleDrawable(who: Drawable, what: Runnable) {
+        unscheduleSelf(what)
+    }
+
+    open class FastBitmapConstantState(val bitmapInfo: BitmapInfo) : ConstantState() {
+        // These are initialized later so that subclasses don't need to
+        // pass everything in constructor
+        var mIsDisabled: Boolean = false
+        var mBadgeConstantState: ConstantState? = null
+
+        @DrawableCreationFlags var mCreationFlags: Int = 0
+
+        constructor(bitmap: Bitmap, color: Int) : this(BitmapInfo.of(bitmap, color))
+
+        protected open fun createDrawable(): FastBitmapDrawable {
+            return FastBitmapDrawable(bitmapInfo)
+        }
+
+        override fun newDrawable(): FastBitmapDrawable {
+            val drawable = createDrawable()
+            drawable.isDisabled = mIsDisabled
+            if (mBadgeConstantState != null) {
+                drawable.badge = mBadgeConstantState!!.newDrawable()
+            }
+            drawable.creationFlags = mCreationFlags
+            return drawable
+        }
+
+        override fun getChangingConfigurations(): Int = 0
+    }
+
+    companion object {
+        private val ACCEL: Interpolator = AccelerateInterpolator()
+        private val DEACCEL: Interpolator = DecelerateInterpolator()
+        private val HOVER_EMPHASIZED_DECELERATE_INTERPOLATOR: Interpolator =
+            PathInterpolator(0.05f, 0.7f, 0.1f, 1.0f)
+
+        @VisibleForTesting const val PRESSED_SCALE: Float = 1.1f
+
+        @VisibleForTesting const val HOVERED_SCALE: Float = 1.1f
+        const val WHITE_SCRIM_ALPHA: Int = 138
+
+        private const val DISABLED_DESATURATION = 1f
+        private const val DISABLED_BRIGHTNESS = 0.5f
+        const val FULLY_OPAQUE: Int = 255
+
+        const val CLICK_FEEDBACK_DURATION: Int = 200
+        const val HOVER_FEEDBACK_DURATION: Int = 300
+
+        // Animator and properties for the fast bitmap drawable's scale
+        @VisibleForTesting
+        @JvmField
+        val SCALE: FloatProperty<FastBitmapDrawable> =
+            object : FloatProperty<FastBitmapDrawable>("scale") {
+                override fun get(fastBitmapDrawable: FastBitmapDrawable): Float {
+                    return fastBitmapDrawable.scale
+                }
+
+                override fun setValue(fastBitmapDrawable: FastBitmapDrawable, value: Float) {
+                    fastBitmapDrawable.scale = value
+                    fastBitmapDrawable.invalidateSelf()
+                }
+            }
+
+        @JvmStatic
+        @JvmOverloads
+        fun getDisabledColorFilter(disabledAlpha: Float = 1f): ColorFilter {
+            val tempBrightnessMatrix = ColorMatrix()
+            val tempFilterMatrix = ColorMatrix()
+
+            tempFilterMatrix.setSaturation(1f - DISABLED_DESATURATION)
+            val scale = 1 - DISABLED_BRIGHTNESS
+            val brightnessI = (255 * DISABLED_BRIGHTNESS).toInt()
+            val mat = tempBrightnessMatrix.array
+            mat[0] = scale
+            mat[6] = scale
+            mat[12] = scale
+            mat[4] = brightnessI.toFloat()
+            mat[9] = brightnessI.toFloat()
+            mat[14] = brightnessI.toFloat()
+            mat[18] = disabledAlpha
+            tempFilterMatrix.preConcat(tempBrightnessMatrix)
+            return ColorMatrixColorFilter(tempFilterMatrix)
+        }
+
+        @JvmStatic
+        fun getDisabledColor(color: Int): Int {
+            val avgComponent = (Color.red(color) + Color.green(color) + Color.blue(color)) / 3
+            val scale = 1 - DISABLED_BRIGHTNESS
+            val brightnessI = (255 * DISABLED_BRIGHTNESS).toInt()
+            val component = min(Math.round(scale * avgComponent + brightnessI), FULLY_OPAQUE)
+            return Color.rgb(component, component, component)
+        }
+
+        /** Sets the bounds for the badge drawable based on the main icon bounds */
+        @JvmStatic
+        fun Drawable.setBadgeBounds(iconBounds: Rect) {
+            val size = BaseIconFactory.getBadgeSizeForIconSize(iconBounds.width())
+            setBounds(
+                iconBounds.right - size,
+                iconBounds.bottom - size,
+                iconBounds.right,
+                iconBounds.bottom,
+            )
+        }
+    }
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/IconProvider.java b/iconloaderlib/src/com/android/launcher3/icons/IconProvider.java
index 9410100..9bb571c 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/IconProvider.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/IconProvider.java
@@ -51,6 +51,8 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.core.os.BuildCompat;
 
+import com.android.launcher3.icons.cache.CachingLogic;
+import com.android.launcher3.util.ComponentKey;
 import com.android.launcher3.util.SafeCloseable;
 
 import java.util.Calendar;
@@ -149,7 +151,7 @@ public class IconProvider {
             icon = ClockDrawableWrapper.forPackage(mContext, mClock.getPackageName(), iconDpi);
         }
         if (icon == null) {
-            icon = loadPackageIcon(info, appInfo, iconDpi);
+            icon = loadPackageIconWithFallback(info, appInfo, iconDpi);
             if (ATLEAST_T && icon instanceof AdaptiveIconDrawable && td != null) {
                 AdaptiveIconDrawable aid = (AdaptiveIconDrawable) icon;
                 if  (aid.getMonochrome() == null) {
@@ -165,36 +167,39 @@ public class IconProvider {
         return null;
     }
 
-    private Drawable loadPackageIcon(PackageItemInfo info, ApplicationInfo appInfo, int density) {
+    private Drawable loadPackageIconWithFallback(
+            PackageItemInfo info, ApplicationInfo appInfo, int density) {
         Drawable icon = null;
         if (BuildCompat.isAtLeastV() && info.isArchived) {
             // Icons for archived apps com from system service, let the default impl handle that
             icon = info.loadIcon(mContext.getPackageManager());
         }
         if (icon == null && density != 0 && (info.icon != 0 || appInfo.icon != 0)) {
-            try {
-                final Resources resources = mContext.getPackageManager()
-                        .getResourcesForApplication(appInfo);
-                // Try to load the package item icon first
-                if (info != appInfo && info.icon != 0) {
-                    try {
-                        icon = resources.getDrawableForDensity(info.icon, density);
-                    } catch (Resources.NotFoundException exc) { }
-                }
-                if (icon == null && appInfo.icon != 0) {
-                    // Load the fallback app icon
-                    icon = loadAppInfoIcon(appInfo, resources, density);
-                }
-            } catch (NameNotFoundException | Resources.NotFoundException exc) { }
+            icon = loadPackageIcon(info, appInfo, density);
         }
         return icon != null ? icon : getFullResDefaultActivityIcon(density);
     }
 
     @Nullable
-    protected Drawable loadAppInfoIcon(ApplicationInfo info, Resources resources, int density) {
+    protected Drawable loadPackageIcon(
+            @NonNull PackageItemInfo info, @NonNull ApplicationInfo appInfo, int density) {
         try {
-            return resources.getDrawableForDensity(info.icon, density);
-        } catch (Resources.NotFoundException exc) { }
+            final Resources resources = mContext.getPackageManager()
+                    .getResourcesForApplication(appInfo);
+            // Try to load the package item icon first
+            if (info != appInfo && info.icon != 0) {
+                try {
+                    Drawable icon = resources.getDrawableForDensity(info.icon, density);
+                    if (icon != null) return icon;
+                } catch (Resources.NotFoundException exc) { }
+            }
+            if (appInfo.icon != 0) {
+                // Load the fallback app icon
+                try {
+                    return resources.getDrawableForDensity(appInfo.icon, density);
+                } catch (Resources.NotFoundException exc) { }
+            }
+        } catch (NameNotFoundException | Resources.NotFoundException exc) { }
         return null;
     }
 
@@ -298,6 +303,12 @@ public class IconProvider {
         return new IconChangeReceiver(listener, handler);
     }
 
+    /**
+     * Notifies the provider when an icon is loaded from cache
+     */
+    public void notifyIconLoaded(
+            @NonNull BitmapInfo icon, @NonNull ComponentKey key, @NonNull CachingLogic<?> logic) { }
+
     public static class ThemeData {
 
         final Resources mResources;
diff --git a/iconloaderlib/src/com/android/launcher3/icons/MonochromeIconFactory.java b/iconloaderlib/src/com/android/launcher3/icons/MonochromeIconFactory.java
index ae71236..e6ae124 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/MonochromeIconFactory.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/MonochromeIconFactory.java
@@ -100,12 +100,12 @@ public class MonochromeIconFactory extends Drawable {
      * Creates a monochrome version of the provided drawable
      */
     @WorkerThread
-    public Drawable wrap(AdaptiveIconDrawable icon, Path shapePath, Float iconScale) {
+    public Drawable wrap(AdaptiveIconDrawable icon, Path shapePath) {
         mFlatCanvas.drawColor(Color.BLACK);
         drawDrawable(icon.getBackground());
         drawDrawable(icon.getForeground());
         generateMono();
-        return new ClippedMonoDrawable(this, shapePath, iconScale);
+        return new ClippedMonoDrawable(this, shapePath);
     }
 
     @WorkerThread
diff --git a/iconloaderlib/src/com/android/launcher3/icons/PlaceHolderIconDrawable.java b/iconloaderlib/src/com/android/launcher3/icons/PlaceHolderIconDrawable.java
index 00f1942..531c35a 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/PlaceHolderIconDrawable.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/PlaceHolderIconDrawable.java
@@ -42,7 +42,7 @@ public class PlaceHolderIconDrawable extends FastBitmapDrawable {
     public PlaceHolderIconDrawable(BitmapInfo info, Context context) {
         super(info);
         mProgressPath = getDefaultPath();
-        mPaint.setColor(ColorUtils.compositeColors(
+        paint.setColor(ColorUtils.compositeColors(
                 GraphicsUtils.getAttrColor(context, R.attr.loadingIconColor), info.color));
     }
 
@@ -62,13 +62,13 @@ public class PlaceHolderIconDrawable extends FastBitmapDrawable {
         int saveCount = canvas.save();
         canvas.translate(bounds.left, bounds.top);
         canvas.scale(bounds.width() / 100f, bounds.height() / 100f);
-        canvas.drawPath(mProgressPath, mPaint);
+        canvas.drawPath(mProgressPath, paint);
         canvas.restoreToCount(saveCount);
     }
 
     /** Updates this placeholder to {@code newIcon} with animation. */
     public void animateIconUpdate(Drawable newIcon) {
-        int placeholderColor = mPaint.getColor();
+        int placeholderColor = paint.getColor();
         int originalAlpha = Color.alpha(placeholderColor);
 
         ValueAnimator iconUpdateAnimation = ValueAnimator.ofInt(originalAlpha, 0);
diff --git a/iconloaderlib/src/com/android/launcher3/icons/ThemedBitmap.kt b/iconloaderlib/src/com/android/launcher3/icons/ThemedBitmap.kt
index 6c937db..77b34ac 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/ThemedBitmap.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/ThemedBitmap.kt
@@ -28,6 +28,18 @@ interface ThemedBitmap {
     fun newDrawable(info: BitmapInfo, context: Context): FastBitmapDrawable
 
     fun serialize(): ByteArray
+
+    companion object {
+
+        @JvmField
+        /** ThemedBitmap to be used when theming is not supported for a particular bitmap */
+        val NOT_SUPPORTED =
+            object : ThemedBitmap {
+                override fun newDrawable(info: BitmapInfo, context: Context) = info.newIcon(context)
+
+                override fun serialize() = ByteArray(0)
+            }
+    }
 }
 
 interface IconThemeController {
@@ -46,8 +58,14 @@ interface IconThemeController {
         info: BitmapInfo,
         factory: BaseIconFactory,
         sourceHint: SourceHint,
-    ): ThemedBitmap?
+    ): ThemedBitmap
 
+    /**
+     * Creates an adaptive icon representation of the themed bitmap for various surface effects. The
+     * controller can return the [originalIcon] for using an un-themed icon for these effects or
+     * null to disable any surface effects in which can the static themed icon will be used without
+     * any additional effects.
+     */
     fun createThemedAdaptiveIcon(
         context: Context,
         originalIcon: AdaptiveIconDrawable,
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.kt
index 780ef80..eb8c5a2 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.kt
@@ -42,12 +42,15 @@ import android.util.SparseArray
 import androidx.annotation.VisibleForTesting
 import androidx.annotation.WorkerThread
 import com.android.launcher3.Flags
+import com.android.systemui.shared.Flags.extendibleThemeManager
 import com.android.launcher3.icons.BaseIconFactory
 import com.android.launcher3.icons.BaseIconFactory.IconOptions
 import com.android.launcher3.icons.BitmapInfo
+import com.android.launcher3.icons.BitmapInfo.Companion.LOW_RES_ICON
 import com.android.launcher3.icons.GraphicsUtils
 import com.android.launcher3.icons.IconProvider
 import com.android.launcher3.icons.SourceHint
+import com.android.launcher3.icons.ThemedBitmap
 import com.android.launcher3.icons.cache.CacheLookupFlag.Companion.DEFAULT_LOOKUP_FLAG
 import com.android.launcher3.util.ComponentKey
 import com.android.launcher3.util.FlagOp
@@ -221,9 +224,11 @@ constructor(
             }
 
         // Only add an entry in memory, if there was already something previously
-        if (cache[key] != null) {
+        val existingEntry = cache[key]
+        if (existingEntry != null) {
             val entry = CacheEntry()
-            entry.bitmap = bitmapInfo
+            entry.bitmap =
+                bitmapInfo.downSampleToLookupFlag(existingEntry.bitmap.matchingLookupFlag)
             entry.title = entryTitle
             entry.contentDescription = getUserBadgedLabel(entryTitle, user)
             cache[key] = entry
@@ -290,7 +295,7 @@ constructor(
                     obj,
                     entry,
                     cachingLogic,
-                    lookupFlags.usePackageIcon(),
+                    lookupFlags,
                     /* usePackageTitle= */ true,
                     componentName,
                     user,
@@ -309,7 +314,7 @@ constructor(
         obj: T?,
         entry: CacheEntry,
         cachingLogic: CachingLogic<T>,
-        usePackageIcon: Boolean,
+        lookupFlag: CacheLookupFlag,
         usePackageTitle: Boolean,
         componentName: ComponentName,
         user: UserHandle,
@@ -317,8 +322,9 @@ constructor(
         if (obj != null) {
             entry.bitmap = cachingLogic.loadIcon(context, this, obj)
         } else {
-            if (usePackageIcon) {
-                val packageEntry = getEntryForPackageLocked(componentName.packageName, user)
+            if (lookupFlag.usePackageIcon()) {
+                val packageEntry =
+                    getEntryForPackageLocked(componentName.packageName, user, lookupFlag)
                 if (DEBUG) {
                     Log.d(TAG, "using package default icon for " + componentName.toShortString())
                 }
@@ -329,6 +335,7 @@ constructor(
                     entry.title = packageEntry.title
                 }
             }
+            entry.bitmap = entry.bitmap.downSampleToLookupFlag(lookupFlag)
         }
     }
 
@@ -440,8 +447,7 @@ constructor(
                     // only keep the low resolution icon instead of the larger full-sized icon
                     val iconInfo = appInfoCachingLogic.loadIcon(context, this, appInfo)
                     entry.bitmap =
-                        if (lookupFlags.useLowRes())
-                            BitmapInfo.of(BitmapInfo.LOW_RES_ICON, iconInfo.color)
+                        if (lookupFlags.useLowRes()) BitmapInfo.of(LOW_RES_ICON, iconInfo.color)
                         else iconInfo
 
                     loadFallbackTitle(appInfo, entry, appInfoCachingLogic, user)
@@ -514,7 +520,7 @@ constructor(
         // Set the alpha to be 255, so that we never have a wrong color
         entry.bitmap =
             BitmapInfo.of(
-                BitmapInfo.LOW_RES_ICON,
+                LOW_RES_ICON,
                 GraphicsUtils.setColorAlphaBound(c.getInt(INDEX_COLOR), 255),
             )
         c.getString(INDEX_TITLE).let {
@@ -544,23 +550,29 @@ constructor(
                 return false
             }
 
-            iconFactory.use { factory ->
-                val themeController = factory.themeController
-                val monoIconData = c.getBlob(INDEX_MONO_ICON)
-                if (themeController != null && monoIconData != null) {
-                    entry.bitmap.themedBitmap =
-                        themeController.decode(
-                            data = monoIconData,
-                            info = entry.bitmap,
-                            factory = factory,
-                            sourceHint =
-                                SourceHint(cacheKey, logic, c.getString(INDEX_FRESHNESS_ID)),
-                        )
+            if (!extendibleThemeManager() || lookupFlags.hasThemeIcon()) {
+                // Always set a non-null theme bitmap if theming was requested
+                entry.bitmap.themedBitmap = ThemedBitmap.NOT_SUPPORTED
+
+                iconFactory.use { factory ->
+                    val themeController = factory.themeController
+                    val monoIconData = c.getBlob(INDEX_MONO_ICON)
+                    if (themeController != null && monoIconData != null) {
+                        entry.bitmap.themedBitmap =
+                            themeController.decode(
+                                data = monoIconData,
+                                info = entry.bitmap,
+                                factory = factory,
+                                sourceHint =
+                                    SourceHint(cacheKey, logic, c.getString(INDEX_FRESHNESS_ID)),
+                            )
+                    }
                 }
             }
         }
         entry.bitmap.flags = c.getInt(INDEX_FLAGS)
         entry.bitmap = entry.bitmap.withFlags(getUserFlagOpLocked(cacheKey.user))
+        iconProvider.notifyIconLoaded(entry.bitmap, cacheKey, logic)
         return true
     }
 
@@ -643,7 +655,7 @@ constructor(
             ComponentKey(ComponentName(packageName, packageName + EMPTY_CLASS_NAME), user)
 
         // Ensures themed bitmaps in the icon cache are invalidated
-        @JvmField val RELEASE_VERSION = if (Flags.forceMonochromeAppIcons()) 10 else 9
+        @JvmField val RELEASE_VERSION = if (Flags.enableLauncherIconShapes()) 11 else 10
 
         @JvmField val TABLE_NAME = "icons"
         @JvmField val COLUMN_ROWID = "rowid"
@@ -660,12 +672,17 @@ constructor(
         val COLUMNS_LOW_RES =
             arrayOf(COLUMN_COMPONENT, COLUMN_LABEL, COLUMN_ICON_COLOR, COLUMN_FLAGS)
 
+        @JvmField
+        val COLUMNS_HIGH_RES_NO_THEME =
+            COLUMNS_LOW_RES.copyOf(COLUMNS_LOW_RES.size + 2).apply {
+                this[size - 1] = COLUMN_ICON
+                this[size - 2] = COLUMN_FRESHNESS_ID
+            }
+
         @JvmField
         val COLUMNS_HIGH_RES =
-            COLUMNS_LOW_RES.copyOf(COLUMNS_LOW_RES.size + 3).apply {
-                this[size - 3] = COLUMN_ICON
-                this[size - 2] = COLUMN_MONO_ICON
-                this[size - 1] = COLUMN_FRESHNESS_ID
+            COLUMNS_HIGH_RES_NO_THEME.copyOf(COLUMNS_HIGH_RES_NO_THEME.size + 1).apply {
+                this[size - 1] = COLUMN_MONO_ICON
             }
 
         @JvmField val INDEX_TITLE = COLUMNS_HIGH_RES.indexOf(COLUMN_LABEL)
@@ -677,6 +694,20 @@ constructor(
 
         @JvmStatic
         fun CacheLookupFlag.toLookupColumns() =
-            if (useLowRes()) COLUMNS_LOW_RES else COLUMNS_HIGH_RES
+            when {
+                useLowRes() -> COLUMNS_LOW_RES
+                extendibleThemeManager() && !hasThemeIcon() -> COLUMNS_HIGH_RES_NO_THEME
+                else -> COLUMNS_HIGH_RES
+            }
+
+        @JvmStatic
+        protected fun BitmapInfo.downSampleToLookupFlag(flag: CacheLookupFlag) =
+            when {
+                !extendibleThemeManager() -> this
+                flag.useLowRes() -> BitmapInfo.of(LOW_RES_ICON, color)
+                !flag.hasThemeIcon() && themedBitmap != null ->
+                    clone().apply { themedBitmap = null }
+                else -> this
+            }
     }
 }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/CacheLookupFlag.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/CacheLookupFlag.kt
index 42fda24..9e56dbe 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/CacheLookupFlag.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/CacheLookupFlag.kt
@@ -16,6 +16,7 @@
 package com.android.launcher3.icons.cache
 
 import androidx.annotation.IntDef
+import com.android.systemui.shared.Flags.extendibleThemeManager
 import kotlin.annotation.AnnotationRetention.SOURCE
 
 /** Flags to control cache lookup behavior */
@@ -45,18 +46,30 @@ data class CacheLookupFlag private constructor(@LookupFlag private val flag: Int
     fun withSkipAddToMemCache(skipAddToMemCache: Boolean = true) =
         updateMask(SKIP_ADD_TO_MEM_CACHE, skipAddToMemCache)
 
+    /** Entry will include theme icon. Note that theme icon is only loaded for high-res icons */
+    fun hasThemeIcon() = hasFlag(LOAD_THEME_ICON)
+
+    @JvmOverloads
+    fun withThemeIcon(addThemeIcon: Boolean = true) = updateMask(LOAD_THEME_ICON, addThemeIcon)
+
     private fun hasFlag(@LookupFlag mask: Int) = flag.and(mask) != 0
 
     private fun updateMask(@LookupFlag mask: Int, addMask: Boolean) =
         if (addMask) flagCache[flag.or(mask)] else flagCache[flag.and(mask.inv())]
 
     /** Returns `true` if this flag has less UI information then [other] */
-    fun isVisuallyLessThan(other: CacheLookupFlag): Boolean {
-        return useLowRes() && !other.useLowRes()
-    }
+    fun isVisuallyLessThan(other: CacheLookupFlag) =
+        when {
+            useLowRes() && !other.useLowRes() -> true
+            extendibleThemeManager() && !hasThemeIcon() && other.hasThemeIcon() -> true
+            else -> false
+        }
 
     @Retention(SOURCE)
-    @IntDef(value = [USE_LOW_RES, USE_PACKAGE_ICON, SKIP_ADD_TO_MEM_CACHE], flag = true)
+    @IntDef(
+        value = [USE_LOW_RES, USE_PACKAGE_ICON, SKIP_ADD_TO_MEM_CACHE, LOAD_THEME_ICON],
+        flag = true,
+    )
     /** Various options to control cache lookup */
     private annotation class LookupFlag
 
@@ -64,8 +77,9 @@ data class CacheLookupFlag private constructor(@LookupFlag private val flag: Int
         private const val USE_LOW_RES: Int = 1 shl 0
         private const val USE_PACKAGE_ICON: Int = 1 shl 1
         private const val SKIP_ADD_TO_MEM_CACHE: Int = 1 shl 2
+        private const val LOAD_THEME_ICON: Int = 1 shl 3
 
-        private val flagCache = Array(8) { CacheLookupFlag(it) }
+        private val flagCache = Array(1 shl 4) { CacheLookupFlag(it) }
 
         @JvmField val DEFAULT_LOOKUP_FLAG = CacheLookupFlag(0)
     }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/mono/MonoIconThemeController.kt b/iconloaderlib/src/com/android/launcher3/icons/mono/MonoIconThemeController.kt
index 1c73dac..d3b4a0b 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/mono/MonoIconThemeController.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/mono/MonoIconThemeController.kt
@@ -46,7 +46,8 @@ import java.nio.ByteBuffer
 
 @TargetApi(Build.VERSION_CODES.TIRAMISU)
 class MonoIconThemeController(
-    private val colorProvider: (Context) -> IntArray = ThemedIconDrawable.Companion::getColors
+    private val shouldForceThemeIcon: Boolean = false,
+    private val colorProvider: (Context) -> IntArray = ThemedIconDrawable.Companion::getColors,
 ) : IconThemeController {
 
     override val themeID = "with-theme"
@@ -62,9 +63,8 @@ class MonoIconThemeController(
                 icon,
                 info,
                 factory.getShapePath(icon, Rect(0, 0, info.icon.width, info.icon.height)),
-                factory.iconScale,
                 sourceHint?.isFileDrawable ?: false,
-                factory.shouldForceThemeIcon(),
+                shouldForceThemeIcon,
             )
         if (mono != null) {
             return MonoThemedBitmap(
@@ -85,16 +85,15 @@ class MonoIconThemeController(
         base: AdaptiveIconDrawable,
         info: BitmapInfo,
         shapePath: Path,
-        iconScale: Float,
         isFileDrawable: Boolean,
         shouldForceThemeIcon: Boolean,
     ): Drawable? {
         val mono = base.monochrome
         if (mono != null) {
-            return ClippedMonoDrawable(mono, shapePath, iconScale)
+            return ClippedMonoDrawable(mono, shapePath)
         }
         if (Flags.forceMonochromeAppIcons() && shouldForceThemeIcon && !isFileDrawable) {
-            return MonochromeIconFactory(info.icon.width).wrap(base, shapePath, iconScale)
+            return MonochromeIconFactory(info.icon.width).wrap(base, shapePath)
         }
         return null
     }
@@ -104,9 +103,9 @@ class MonoIconThemeController(
         info: BitmapInfo,
         factory: BaseIconFactory,
         sourceHint: SourceHint,
-    ): ThemedBitmap? {
+    ): ThemedBitmap {
         val icon = info.icon
-        if (data.size != icon.height * icon.width) return null
+        if (data.size != icon.height * icon.width) return ThemedBitmap.NOT_SUPPORTED
 
         var monoBitmap = Bitmap.createBitmap(icon.width, icon.height, ALPHA_8)
         monoBitmap.copyPixelsFromBuffer(ByteBuffer.wrap(data))
@@ -123,7 +122,7 @@ class MonoIconThemeController(
         context: Context,
         originalIcon: AdaptiveIconDrawable,
         info: BitmapInfo?,
-    ): AdaptiveIconDrawable? {
+    ): AdaptiveIconDrawable {
         val colors = colorProvider(context)
         originalIcon.mutate()
         var monoDrawable = originalIcon.monochrome?.apply { setTint(colors[1]) }
@@ -147,13 +146,11 @@ class MonoIconThemeController(
         }
 
         return monoDrawable?.let { AdaptiveIconDrawable(ColorDrawable(colors[0]), it) }
+            ?: originalIcon
     }
 
-    class ClippedMonoDrawable(
-        base: Drawable?,
-        private val shapePath: Path,
-        private val iconScale: Float,
-    ) : InsetDrawable(base, -AdaptiveIconDrawable.getExtraInsetFraction()) {
+    class ClippedMonoDrawable(base: Drawable?, private val shapePath: Path) :
+        InsetDrawable(base, -AdaptiveIconDrawable.getExtraInsetFraction()) {
         // TODO(b/399666950): remove this after launcher icon shapes is fully enabled
         private val mCrop = AdaptiveIconDrawable(ColorDrawable(Color.BLACK), null)
 
@@ -162,7 +159,6 @@ class MonoIconThemeController(
             val saveCount = canvas.save()
             if (Flags.enableLauncherIconShapes()) {
                 canvas.clipPath(shapePath)
-                canvas.scale(iconScale, iconScale, bounds.width() / 2f, bounds.height() / 2f)
             } else {
                 canvas.clipPath(mCrop.iconMask)
             }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/mono/ThemedIconDrawable.kt b/iconloaderlib/src/com/android/launcher3/icons/mono/ThemedIconDrawable.kt
index 64aeb35..6e70d3d 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/mono/ThemedIconDrawable.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/mono/ThemedIconDrawable.kt
@@ -28,7 +28,7 @@ import com.android.launcher3.icons.R
 
 /** Class to handle monochrome themed app icons */
 class ThemedIconDrawable(constantState: ThemedConstantState) :
-    FastBitmapDrawable(constantState.getBitmapInfo()) {
+    FastBitmapDrawable(constantState.bitmapInfo) {
     private val colorFg = constantState.colorFg
     private val colorBg = constantState.colorBg
 
@@ -50,22 +50,22 @@ class ThemedIconDrawable(constantState: ThemedConstantState) :
 
     override fun updateFilter() {
         super.updateFilter()
-        val alpha = if (mIsDisabled) (mDisabledAlpha * FULLY_OPAQUE).toInt() else FULLY_OPAQUE
+        val alpha = if (isDisabled) (disabledAlpha * FULLY_OPAQUE).toInt() else FULLY_OPAQUE
         mBgPaint.alpha = alpha
         mBgPaint.setColorFilter(
-            if (mIsDisabled) BlendModeColorFilter(getDisabledColor(colorBg), SRC_IN) else bgFilter
+            if (isDisabled) BlendModeColorFilter(getDisabledColor(colorBg), SRC_IN) else bgFilter
         )
 
         monoPaint.alpha = alpha
         monoPaint.setColorFilter(
-            if (mIsDisabled) BlendModeColorFilter(getDisabledColor(colorFg), SRC_IN) else monoFilter
+            if (isDisabled) BlendModeColorFilter(getDisabledColor(colorFg), SRC_IN) else monoFilter
         )
     }
 
     override fun isThemed() = true
 
     override fun newConstantState() =
-        ThemedConstantState(mBitmapInfo, monoIcon, bgBitmap, colorBg, colorFg)
+        ThemedConstantState(bitmapInfo, monoIcon, bgBitmap, colorBg, colorFg)
 
     override fun getIconColor() = colorFg
 
@@ -78,8 +78,6 @@ class ThemedIconDrawable(constantState: ThemedConstantState) :
     ) : FastBitmapConstantState(bitmapInfo) {
 
         public override fun createDrawable() = ThemedIconDrawable(this)
-
-        fun getBitmapInfo(): BitmapInfo = mBitmapInfo
     }
 
     companion object {
diff --git a/mechanics/Android.bp b/mechanics/Android.bp
index a091c09..d683892 100644
--- a/mechanics/Android.bp
+++ b/mechanics/Android.bp
@@ -17,18 +17,11 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-filegroup {
-    name: "mechanics-srcs",
-    srcs: [
-        "src/**/*.kt",
-    ],
-}
-
 android_library {
     name: "mechanics",
     manifest: "AndroidManifest.xml",
     sdk_version: "system_current",
-    min_sdk_version: "current",
+    min_sdk_version: "31",
     static_libs: [
         "androidx.compose.runtime_runtime",
         "androidx.compose.material3_material3",
@@ -36,7 +29,7 @@ android_library {
         "androidx.compose.foundation_foundation-layout",
     ],
     srcs: [
-        ":mechanics-srcs",
+        "src/**/*.kt",
     ],
     kotlincflags: ["-Xjvm-default=all"],
 }
diff --git a/mechanics/TEST_MAPPING b/mechanics/TEST_MAPPING
index 4e50571..4dd86b9 100644
--- a/mechanics/TEST_MAPPING
+++ b/mechanics/TEST_MAPPING
@@ -3,13 +3,36 @@
     {
       "name": "mechanics_tests",
       "options": [
-        {
-          "exclude-annotation": "org.junit.Ignore"
-        },
-        {
-          "exclude-annotation": "androidx.test.filters.FlakyTest"
-        }
+        {"exclude-annotation": "org.junit.Ignore"},
+        {"exclude-annotation": "androidx.test.filters.FlakyTest"}
       ]
+    },
+    {
+      "name": "SystemUIGoogleTests",
+      "options": [
+        {"exclude-annotation": "org.junit.Ignore"},
+        {"exclude-annotation": "androidx.test.filters.FlakyTest"}
+      ]
+    },
+    {
+      "name": "PlatformComposeSceneTransitionLayoutTests"
+    },
+    {
+      "name": "PlatformComposeCoreTests"
+    }
+  ],
+  "presubmit-large": [
+    {
+      "name": "SystemUITests",
+      "options": [
+        {"exclude-annotation": "org.junit.Ignore"},
+        {"exclude-annotation": "androidx.test.filters.FlakyTest"}
+      ]
+    }
+  ],
+  "wm-cf": [
+    {
+      "name": "WMShellUnitTests"
     }
   ]
 }
diff --git a/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/ComposeBaselineBenchmark.kt b/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/ComposeBaselineBenchmark.kt
new file mode 100644
index 0000000..c000dfe
--- /dev/null
+++ b/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/ComposeBaselineBenchmark.kt
@@ -0,0 +1,105 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.benchmark
+
+import androidx.benchmark.junit4.BenchmarkRule
+import androidx.benchmark.junit4.measureRepeated
+import androidx.compose.animation.core.Animatable
+import androidx.compose.runtime.mutableFloatStateOf
+import androidx.compose.runtime.snapshotFlow
+import androidx.compose.runtime.snapshots.Snapshot
+import androidx.compose.ui.util.fastForEach
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import kotlinx.coroutines.flow.launchIn
+import kotlinx.coroutines.flow.onEach
+import kotlinx.coroutines.launch
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import platform.test.motion.compose.runMonotonicClockTest
+
+/** Benchmark, which will execute on an Android device. Previous results: go/mm-microbenchmarks */
+@RunWith(AndroidJUnit4::class)
+class ComposeBaselineBenchmark {
+    @get:Rule val benchmarkRule = BenchmarkRule()
+
+    // Compose specific
+
+    @Test
+    fun writeState_1snapshotFlow() = runMonotonicClockTest {
+        val composeState = mutableFloatStateOf(0f)
+
+        var lastRead = 0f
+        snapshotFlow { composeState.floatValue }.onEach { lastRead = it }.launchIn(backgroundScope)
+
+        benchmarkRule.measureRepeated {
+            composeState.floatValue++
+            Snapshot.sendApplyNotifications()
+            testScheduler.advanceTimeBy(16)
+        }
+
+        check(lastRead == composeState.floatValue) {
+            "snapshotFlow lastRead $lastRead != ${composeState.floatValue} (current composeState)"
+        }
+    }
+
+    @Test
+    fun writeState_100snapshotFlow() = runMonotonicClockTest {
+        val composeState = mutableFloatStateOf(0f)
+
+        repeat(100) { snapshotFlow { composeState.floatValue }.launchIn(backgroundScope) }
+
+        benchmarkRule.measureRepeated {
+            composeState.floatValue++
+            Snapshot.sendApplyNotifications()
+            testScheduler.advanceTimeBy(16)
+        }
+    }
+
+    @Test
+    fun readAnimatableValue_100animatables_keepRunning() = runMonotonicClockTest {
+        val anim = List(100) { Animatable(0f) }
+
+        benchmarkRule.measureRepeated {
+            testScheduler.advanceTimeBy(16)
+            anim.fastForEach {
+                it.value
+
+                if (!it.isRunning) {
+                    launch { it.animateTo(if (it.targetValue != 0f) 0f else 1f) }
+                }
+            }
+        }
+
+        testScheduler.advanceTimeBy(2000)
+    }
+
+    @Test
+    fun readAnimatableValue_100animatables_restartEveryFrame() = runMonotonicClockTest {
+        val animatables = List(100) { Animatable(0f) }
+
+        benchmarkRule.measureRepeated {
+            testScheduler.advanceTimeBy(16)
+            animatables.fastForEach { animatable ->
+                animatable.value
+                launch { animatable.animateTo(if (animatable.targetValue != 0f) 0f else 1f) }
+            }
+        }
+
+        testScheduler.advanceTimeBy(2000)
+    }
+}
diff --git a/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/ComposeStateTest.kt b/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/ComposeStateTest.kt
new file mode 100644
index 0000000..e70bc2b
--- /dev/null
+++ b/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/ComposeStateTest.kt
@@ -0,0 +1,168 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.benchmark
+
+import androidx.compose.runtime.derivedStateOf
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.snapshotFlow
+import androidx.compose.runtime.snapshots.Snapshot
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.flow.launchIn
+import kotlinx.coroutines.flow.onEach
+import org.junit.Test
+import org.junit.runner.RunWith
+import platform.test.motion.compose.runMonotonicClockTest
+
+@RunWith(AndroidJUnit4::class)
+class ComposeStateTest {
+    @Test
+    fun mutableState_sendApplyNotifications() = runMonotonicClockTest {
+        val mutableState = mutableStateOf(0f)
+
+        var lastRead = -1f
+        snapshotFlow { mutableState.value }.onEach { lastRead = it }.launchIn(backgroundScope)
+        check(lastRead == -1f) { "[1] lastRead $lastRead, snapshotFlow launchIn" }
+
+        // snapshotFlow will emit the first value (0f).
+        testScheduler.advanceTimeBy(1)
+        check(lastRead == 0f) { "[2] lastRead $lastRead, first advanceTimeBy()" }
+
+        // update composeState x5.
+        repeat(5) {
+            mutableState.value++
+            check(lastRead == 0f) { "[3 loop] lastRead $lastRead, composeState.floatValue++" }
+
+            testScheduler.advanceTimeBy(1)
+            check(lastRead == 0f) { "[4 loop] lastRead $lastRead, advanceTimeBy()" }
+        }
+
+        // Try to wait with a delay. It does nothing (lastRead == 0f).
+        delay(1)
+        check(mutableState.value == 5f) { "[5] mutableState ${mutableState.value}, after loop" }
+        check(lastRead == 0f) { "[5] lastRead $lastRead, after loop" }
+
+        // This should trigger the flow.
+        Snapshot.sendApplyNotifications()
+        check(lastRead == 0f) { "[6] lastRead $lastRead, Snapshot.sendApplyNotifications()" }
+
+        // lastRead will be updated (5f) after advanceTimeBy (or a delay).
+        testScheduler.advanceTimeBy(1)
+        check(lastRead == 5f) { "[7] lastRead $lastRead, advanceTimeBy" }
+    }
+
+    @Test
+    fun derivedState_readNotRequireASendApplyNotifications() = runMonotonicClockTest {
+        val mutableState = mutableStateOf(0f)
+
+        var derivedRuns = 0
+        val derived = derivedStateOf {
+            derivedRuns++
+            mutableState.value * 2f
+        }
+        check(derivedRuns == 0) { "[1] derivedRuns: $derivedRuns, should be 0" }
+
+        var lastRead = -1f
+        snapshotFlow { derived.value }.onEach { lastRead = it }.launchIn(backgroundScope)
+        check(lastRead == -1f) { "[2] lastRead $lastRead, snapshotFlow launchIn" }
+        check(derivedRuns == 0) { "[2] derivedRuns: $derivedRuns, should be 0" }
+
+        // snapshotFlow will emit the first value (0f * 2f = 0f).
+        testScheduler.advanceTimeBy(16)
+        check(lastRead == 0f) { "[3] lastRead $lastRead, first advanceTimeBy()" }
+        check(derivedRuns == 1) { "[3] derivedRuns: $derivedRuns, should be 1" }
+
+        // update composeState x5.
+        repeat(5) {
+            mutableState.value++
+            check(lastRead == 0f) { "[4 loop] lastRead $lastRead, composeState.floatValue++" }
+
+            testScheduler.advanceTimeBy(16)
+            check(lastRead == 0f) { "[5 loop] lastRead $lastRead, advanceTimeBy()" }
+        }
+
+        // Try to wait with a delay. It does nothing (lastRead == 0f).
+        delay(1)
+        check(mutableState.value == 5f) { "[6] mutableState ${mutableState.value}, after loop" }
+        check(lastRead == 0f) { "[6] lastRead $lastRead, after loop" }
+        check(derivedRuns == 1) { "[6] derivedRuns $derivedRuns, after loop" }
+
+        // Reading a derived state, this will trigger the flow.
+        // NOTE: We are not using Snapshot.sendApplyNotifications()
+        derived.value
+        check(lastRead == 0f) { "[7] lastRead $lastRead, read derivedDouble" }
+        check(derivedRuns == 2) { "[7] derivedRuns $derivedRuns, read derived" } // Triggered
+
+        // lastRead will be updated (5f * 2f = 10f) after advanceTimeBy (or a delay)
+        testScheduler.advanceTimeBy(16)
+        check(lastRead == 5f * 2f) { "[8] lastRead $lastRead, advanceTimeBy" } // New value
+        check(derivedRuns == 2) { "[8] derivedRuns $derivedRuns, read derived" }
+    }
+
+    @Test
+    fun derivedState_readADerivedStateTriggerOthersDerivedState() = runMonotonicClockTest {
+        val mutableState = mutableStateOf(0f)
+
+        var derivedRuns = 0
+        val derived = derivedStateOf {
+            derivedRuns++
+            mutableState.value
+        }
+
+        var otherRuns = 0
+        repeat(100) {
+            val otherState = derivedStateOf {
+                otherRuns++
+                mutableState.value
+            }
+            // Observer all otherStates.
+            snapshotFlow { otherState.value }.launchIn(backgroundScope)
+        }
+        check(derivedRuns == 0) { "[1] derivedRuns: $derivedRuns" }
+        check(otherRuns == 0) { "[1] otherRuns: $otherRuns" }
+
+        // Wait for snapshotFlow.
+        testScheduler.advanceTimeBy(16)
+        check(derivedRuns == 0) { "[2] derivedRuns: $derivedRuns" }
+        check(otherRuns == 100) { "[2] otherRuns: $otherRuns" }
+
+        // This write might trigger all otherStates observed, but it does not.
+        mutableState.value++
+        check(derivedRuns == 0) { "[3] derivedRuns: $derivedRuns" }
+        check(otherRuns == 100) { "[3] otherRuns: $otherRuns" }
+
+        // Wait for several frames, but still doesn't trigger otherStates.
+        repeat(10) { testScheduler.advanceTimeBy(16) }
+        check(derivedRuns == 0) { "[4] derivedRuns: $derivedRuns" }
+        check(otherRuns == 100) { "[4] otherRuns: $otherRuns" }
+
+        // Reading derived state will trigger all otherStates.
+        // This behavior is causing us some problems, because reading a derived state causes all
+        // the
+        // dirty derived states to be reread, and this can happen multiple times per frame,
+        // making
+        // derived states much more expensive than one might expect.
+        derived.value
+        check(derivedRuns == 1) { "[5] derivedRuns: $derivedRuns" }
+        check(otherRuns == 100) { "[5] otherRuns: $otherRuns" }
+
+        // Now we pay the cost of those derived states.
+        testScheduler.advanceTimeBy(1)
+        check(derivedRuns == 1) { "[6] derivedRuns: $derivedRuns" }
+        check(otherRuns == 200) { "[6] otherRuns: $otherRuns" }
+    }
+}
diff --git a/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/MotionValueBenchmark.kt b/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/MotionValueBenchmark.kt
index 2c38860..f5eab76 100644
--- a/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/MotionValueBenchmark.kt
+++ b/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/MotionValueBenchmark.kt
@@ -18,64 +18,243 @@ package com.android.mechanics.benchmark
 
 import androidx.benchmark.junit4.BenchmarkRule
 import androidx.benchmark.junit4.measureRepeated
+import androidx.compose.runtime.MutableFloatState
 import androidx.compose.runtime.mutableFloatStateOf
+import androidx.compose.runtime.snapshotFlow
+import androidx.compose.ui.util.fastForEach
 import androidx.test.ext.junit.runners.AndroidJUnit4
 import com.android.mechanics.DistanceGestureContext
 import com.android.mechanics.MotionValue
+import com.android.mechanics.spec.Guarantee
 import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.MotionSpec
+import com.android.mechanics.spec.builder.directionalMotionSpec
+import com.android.mechanics.spring.SpringParameters
+import kotlinx.coroutines.flow.launchIn
+import kotlinx.coroutines.launch
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
+import platform.test.motion.compose.MonotonicClockTestScope
 
 /** Benchmark, which will execute on an Android device. Previous results: go/mm-microbenchmarks */
 @RunWith(AndroidJUnit4::class)
 class MotionValueBenchmark {
     @get:Rule val benchmarkRule = BenchmarkRule()
 
+    private val tearDownOperations = mutableListOf<() -> Unit>()
+
+    /**
+     * Runs a test block within a [MonotonicClockTestScope] provided by the underlying
+     * [platform.test.motion.compose.runMonotonicClockTest] and ensures automatic cleanup.
+     *
+     * This mechanism provides a convenient way to register cleanup actions (e.g., stopping
+     * coroutines, resetting states) that should reliably run at the end of the test, simplifying
+     * test setup and teardown.
+     */
+    private fun runMonotonicClockTest(block: suspend MonotonicClockTestScope.() -> Unit) {
+        return platform.test.motion.compose.runMonotonicClockTest {
+            try {
+                block()
+            } finally {
+                tearDownOperations.fastForEach { it.invoke() }
+            }
+        }
+    }
+
+    private data class TestData(
+        val motionValue: MotionValue,
+        val gestureContext: DistanceGestureContext,
+        val input: MutableFloatState,
+        val spec: MotionSpec,
+    )
+
+    private fun testData(
+        gestureContext: DistanceGestureContext = DistanceGestureContext(0f, InputDirection.Max, 2f),
+        input: Float = 0f,
+        spec: MotionSpec = MotionSpec.Empty,
+    ): TestData {
+        val inputState = mutableFloatStateOf(input)
+        return TestData(
+            motionValue = MotionValue(inputState::floatValue, gestureContext, spec),
+            gestureContext = gestureContext,
+            input = inputState,
+            spec = spec,
+        )
+    }
+
+    // Fundamental operations on MotionValue: create, read, update.
+
     @Test
     fun createMotionValue() {
         val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 2f)
-        val currentInput = { 0f }
-        benchmarkRule.measureRepeated { MotionValue(currentInput, gestureContext) }
+        val input = { 0f }
+
+        benchmarkRule.measureRepeated { MotionValue(input, gestureContext) }
     }
 
     @Test
-    fun changeInput_readOutput() {
-        val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 2f)
-        val a = mutableFloatStateOf(0f)
-        val motionValue = MotionValue(a::floatValue, gestureContext)
+    fun stable_readOutput_noChanges() {
+        val data = testData()
+
+        // The first read may cost more than the others, it is not interesting for this test.
+        data.motionValue.floatValue
+
+        benchmarkRule.measureRepeated { data.motionValue.floatValue }
+    }
+
+    @Test
+    fun stable_readOutput_afterWriteInput() {
+        val data = testData()
 
         benchmarkRule.measureRepeated {
-            runWithMeasurementDisabled { a.floatValue += 1f }
-            motionValue.floatValue
+            runWithMeasurementDisabled { data.input.floatValue += 1f }
+            data.motionValue.floatValue
         }
     }
 
     @Test
-    fun readOutputMultipleTimes() {
-        val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 2f)
-        val a = mutableFloatStateOf(0f)
-        val motionValue = MotionValue(a::floatValue, gestureContext)
+    fun stable_writeInput_AND_readOutput() {
+        val data = testData()
 
         benchmarkRule.measureRepeated {
-            runWithMeasurementDisabled {
-                a.floatValue += 1f
-                motionValue.output
+            data.input.floatValue += 1f
+            data.motionValue.floatValue
+        }
+    }
+
+    @Test
+    fun stable_writeInput_AND_readOutput_keepRunning() = runMonotonicClockTest {
+        val data = testData()
+        keepRunningDuringTest(data.motionValue)
+
+        benchmarkRule.measureRepeated {
+            data.input.floatValue += 1f
+            testScheduler.advanceTimeBy(16)
+            data.motionValue.floatValue
+        }
+    }
+
+    @Test
+    fun stable_writeInput_AND_readOutput_100motionValues_keepRunning() = runMonotonicClockTest {
+        val dataList = List(100) { testData() }
+        dataList.forEach { keepRunningDuringTest(it.motionValue) }
+
+        benchmarkRule.measureRepeated {
+            dataList.fastForEach { it.input.floatValue += 1f }
+            testScheduler.advanceTimeBy(16)
+            dataList.fastForEach { it.motionValue.floatValue }
+        }
+    }
+
+    @Test
+    fun stable_readOutput_100motionValues_keepRunning() = runMonotonicClockTest {
+        val dataList = List(100) { testData() }
+        dataList.forEach { keepRunningDuringTest(it.motionValue) }
+
+        benchmarkRule.measureRepeated {
+            testScheduler.advanceTimeBy(16)
+            dataList.fastForEach { it.motionValue.floatValue }
+        }
+    }
+
+    // Animations
+
+    private fun MonotonicClockTestScope.keepRunningDuringTest(motionValue: MotionValue) {
+        val keepRunningJob = launch { motionValue.keepRunning() }
+        tearDownOperations += { keepRunningJob.cancel() }
+    }
+
+    private val MotionSpec.Companion.ZeroToOne_AtOne
+        get() =
+            MotionSpec(
+                directionalMotionSpec(
+                    defaultSpring = SpringParameters(stiffness = 300f, dampingRatio = .9f),
+                    initialMapping = Mapping.Zero,
+                ) {
+                    fixedValue(breakpoint = 1f, value = 1f)
+                }
+            )
+
+    private val InputDirection.opposite
+        get() = if (this == InputDirection.Min) InputDirection.Max else InputDirection.Min
+
+    @Test
+    fun unstable_resetGestureContext_readOutput() = runMonotonicClockTest {
+        val data = testData(input = 1f, spec = MotionSpec.ZeroToOne_AtOne)
+        keepRunningDuringTest(data.motionValue)
+
+        benchmarkRule.measureRepeated {
+            if (data.motionValue.isStable) {
+                data.gestureContext.reset(0f, data.gestureContext.direction.opposite)
             }
-            motionValue.output
+            testScheduler.advanceTimeBy(16)
+            data.motionValue.floatValue
         }
     }
 
     @Test
-    fun readOutputMultipleTimesMeasureAll() {
-        val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 2f)
-        val currentInput = mutableFloatStateOf(0f)
-        val motionValue = MotionValue(currentInput::floatValue, gestureContext)
+    fun unstable_resetGestureContext_readOutput_100motionValues() = runMonotonicClockTest {
+        val dataList = List(100) { testData(input = 1f, spec = MotionSpec.ZeroToOne_AtOne) }
+        dataList.forEach { keepRunningDuringTest(it.motionValue) }
+
+        benchmarkRule.measureRepeated {
+            dataList.fastForEach { data ->
+                if (data.motionValue.isStable) {
+                    data.gestureContext.reset(0f, data.gestureContext.direction.opposite)
+                }
+            }
+            testScheduler.advanceTimeBy(16)
+            dataList.fastForEach { it.motionValue.floatValue }
+        }
+    }
+
+    @Test
+    fun unstable_resetGestureContext_snapshotFlowOutput() = runMonotonicClockTest {
+        val data = testData(input = 1f, spec = MotionSpec.ZeroToOne_AtOne)
+        keepRunningDuringTest(data.motionValue)
+
+        snapshotFlow { data.motionValue.floatValue }.launchIn(backgroundScope)
+
+        benchmarkRule.measureRepeated {
+            if (data.motionValue.isStable) {
+                data.gestureContext.reset(0f, data.gestureContext.direction.opposite)
+            }
+            testScheduler.advanceTimeBy(16)
+        }
+    }
+
+    private val MotionSpec.Companion.ZeroToOne_AtOne_WithGuarantee
+        get() =
+            MotionSpec(
+                directionalMotionSpec(
+                    defaultSpring = SpringParameters(stiffness = 300f, dampingRatio = .9f),
+                    initialMapping = Mapping.Zero,
+                ) {
+                    fixedValue(
+                        breakpoint = 1f,
+                        value = 1f,
+                        guarantee = Guarantee.GestureDragDelta(1f),
+                    )
+                }
+            )
+
+    @Test
+    fun unstable_resetGestureContext_guarantee_readOutput() = runMonotonicClockTest {
+        val data = testData(input = 1f, spec = MotionSpec.ZeroToOne_AtOne_WithGuarantee)
+        keepRunningDuringTest(data.motionValue)
 
         benchmarkRule.measureRepeated {
-            currentInput.floatValue += 1f
-            motionValue.output
-            motionValue.output
+            if (data.motionValue.isStable) {
+                data.gestureContext.reset(0f, data.gestureContext.direction.opposite)
+            } else {
+                val isMax = data.gestureContext.direction == InputDirection.Max
+                data.gestureContext.dragOffset += if (isMax) 0.01f else -0.01f
+            }
+
+            testScheduler.advanceTimeBy(16)
+            data.motionValue.floatValue
         }
     }
 }
diff --git a/mechanics/compose/Android.bp b/mechanics/compose/Android.bp
new file mode 100644
index 0000000..bc852eb
--- /dev/null
+++ b/mechanics/compose/Android.bp
@@ -0,0 +1,33 @@
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_team: "trendy_team_motion",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_library {
+    name: "mechanics-compose",
+    manifest: "AndroidManifest.xml",
+    srcs: [
+        "src/**/*.kt",
+    ],
+    static_libs: [
+        "PlatformComposeCore",
+        "PlatformComposeSceneTransitionLayout",
+        "//frameworks/libs/systemui/mechanics:mechanics",
+        "androidx.compose.runtime_runtime",
+    ],
+    kotlincflags: ["-Xjvm-default=all"],
+}
diff --git a/mechanics/compose/AndroidManifest.xml b/mechanics/compose/AndroidManifest.xml
new file mode 100644
index 0000000..b84f740
--- /dev/null
+++ b/mechanics/compose/AndroidManifest.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.mechanics.compose">
+</manifest>
diff --git a/mechanics/compose/src/com/android/mechanics/compose/modifier/VerticalFadeContentRevealModifier.kt b/mechanics/compose/src/com/android/mechanics/compose/modifier/VerticalFadeContentRevealModifier.kt
new file mode 100644
index 0000000..1171573
--- /dev/null
+++ b/mechanics/compose/src/com/android/mechanics/compose/modifier/VerticalFadeContentRevealModifier.kt
@@ -0,0 +1,229 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.compose.modifier
+
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.geometry.Rect
+import androidx.compose.ui.graphics.CompositingStrategy
+import androidx.compose.ui.layout.ApproachLayoutModifierNode
+import androidx.compose.ui.layout.ApproachMeasureScope
+import androidx.compose.ui.layout.LayoutCoordinates
+import androidx.compose.ui.layout.Measurable
+import androidx.compose.ui.layout.MeasureResult
+import androidx.compose.ui.layout.MeasureScope
+import androidx.compose.ui.layout.Placeable
+import androidx.compose.ui.layout.boundsInParent
+import androidx.compose.ui.node.ModifierNodeElement
+import androidx.compose.ui.platform.InspectorInfo
+import androidx.compose.ui.unit.Constraints
+import androidx.compose.ui.unit.IntOffset
+import androidx.compose.ui.unit.IntSize
+import androidx.compose.ui.util.fastCoerceAtLeast
+import com.android.compose.animation.scene.ContentScope
+import com.android.compose.animation.scene.ElementKey
+import com.android.compose.animation.scene.mechanics.gestureContextOrDefault
+import com.android.mechanics.MotionValue
+import com.android.mechanics.debug.findMotionValueDebugger
+import com.android.mechanics.effects.FixedValue
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spec.builder.effectsMotionSpec
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.launch
+
+/**
+ * This component remains hidden until it reach its target height.
+ *
+ * TODO: Once b/413283893 is done, [motionBuilderContext] can be read internally via
+ *   CompositionLocalConsumerModifierNode, instead of passing it.
+ */
+fun Modifier.verticalFadeContentReveal(
+    contentScope: ContentScope,
+    motionBuilderContext: MotionBuilderContext,
+    container: ElementKey,
+    deltaY: Float = 0f,
+    label: String? = null,
+    debug: Boolean = false,
+): Modifier =
+    this then
+        FadeContentRevealElement(
+            contentScope = contentScope,
+            motionBuilderContext = motionBuilderContext,
+            container = container,
+            deltaY = deltaY,
+            label = label,
+            debug = debug,
+        )
+
+private data class FadeContentRevealElement(
+    val contentScope: ContentScope,
+    val motionBuilderContext: MotionBuilderContext,
+    val container: ElementKey,
+    val deltaY: Float,
+    val label: String?,
+    val debug: Boolean,
+) : ModifierNodeElement<FadeContentRevealNode>() {
+    override fun create(): FadeContentRevealNode =
+        FadeContentRevealNode(
+            contentScope = contentScope,
+            motionBuilderContext = motionBuilderContext,
+            container = container,
+            deltaY = deltaY,
+            label = label,
+            debug = debug,
+        )
+
+    override fun update(node: FadeContentRevealNode) {
+        node.update(
+            contentScope = contentScope,
+            motionBuilderContext = motionBuilderContext,
+            container = container,
+            deltaY = deltaY,
+        )
+    }
+
+    override fun InspectorInfo.inspectableProperties() {
+        name = "fadeContentReveal"
+        properties["container"] = container
+        properties["deltaY"] = deltaY
+        properties["label"] = label
+        properties["debug"] = debug
+    }
+}
+
+internal class FadeContentRevealNode(
+    private var contentScope: ContentScope,
+    private var motionBuilderContext: MotionBuilderContext,
+    private var container: ElementKey,
+    private var deltaY: Float,
+    label: String?,
+    private val debug: Boolean,
+) : Modifier.Node(), ApproachLayoutModifierNode {
+
+    private val motionValue =
+        MotionValue(
+            currentInput = {
+                with(contentScope) {
+                    val containerHeight =
+                        container.lastSize(contentKey)?.height ?: return@MotionValue 0f
+                    val containerCoordinates =
+                        container.targetCoordinates(contentKey) ?: return@MotionValue 0f
+                    val localCoordinates = lastCoordinates ?: return@MotionValue 0f
+
+                    val offsetY = containerCoordinates.localPositionOf(localCoordinates).y
+                    containerHeight - offsetY + deltaY
+                }
+            },
+            gestureContext = contentScope.gestureContextOrDefault(),
+            label = "FadeContentReveal(${label.orEmpty()})",
+        )
+
+    fun update(
+        contentScope: ContentScope,
+        motionBuilderContext: MotionBuilderContext,
+        container: ElementKey,
+        deltaY: Float,
+    ) {
+        this.contentScope = contentScope
+        this.motionBuilderContext = motionBuilderContext
+        this.container = container
+        this.deltaY = deltaY
+        updateMotionSpec()
+    }
+
+    private var motionValueJob: Job? = null
+
+    override fun onAttach() {
+        motionValueJob =
+            coroutineScope.launch {
+                val disposableHandle =
+                    if (debug) {
+                        findMotionValueDebugger()?.register(motionValue)
+                    } else {
+                        null
+                    }
+                try {
+                    motionValue.keepRunning()
+                } finally {
+                    disposableHandle?.dispose()
+                }
+            }
+    }
+
+    override fun onDetach() {
+        motionValueJob?.cancel()
+    }
+
+    private fun isAnimating(): Boolean {
+        return contentScope.layoutState.currentTransition != null || !motionValue.isStable
+    }
+
+    override fun isMeasurementApproachInProgress(lookaheadSize: IntSize) = isAnimating()
+
+    override fun Placeable.PlacementScope.isPlacementApproachInProgress(
+        lookaheadCoordinates: LayoutCoordinates
+    ) = isAnimating()
+
+    private var targetBounds = Rect.Zero
+
+    private var lastCoordinates: LayoutCoordinates? = null
+
+    private fun updateMotionSpec() {
+        motionValue.spec =
+            motionBuilderContext.effectsMotionSpec(Mapping.Zero) {
+                after(targetBounds.bottom, FixedValue.One)
+            }
+    }
+
+    override fun MeasureScope.measure(
+        measurable: Measurable,
+        constraints: Constraints,
+    ): MeasureResult {
+        val placeable = measurable.measure(constraints)
+        return layout(placeable.width, placeable.height) {
+            val coordinates = coordinates
+            if (isLookingAhead && coordinates != null) {
+                lastCoordinates = coordinates
+                val bounds = coordinates.boundsInParent()
+                if (targetBounds != bounds) {
+                    targetBounds = bounds
+                    updateMotionSpec()
+                }
+            }
+            placeable.place(IntOffset.Zero)
+        }
+    }
+
+    override fun ApproachMeasureScope.approachMeasure(
+        measurable: Measurable,
+        constraints: Constraints,
+    ): MeasureResult {
+        return measurable.measure(constraints).run {
+            layout(width, height) {
+                val revealAlpha = motionValue.output
+                if (revealAlpha < 1) {
+                    placeWithLayer(IntOffset.Zero) {
+                        alpha = revealAlpha.fastCoerceAtLeast(0f)
+                        compositingStrategy = CompositingStrategy.ModulateAlpha
+                    }
+                } else {
+                    place(IntOffset.Zero)
+                }
+            }
+        }
+    }
+}
diff --git a/mechanics/compose/src/com/android/mechanics/compose/modifier/VerticalTactileSurfaceRevealModifier.kt b/mechanics/compose/src/com/android/mechanics/compose/modifier/VerticalTactileSurfaceRevealModifier.kt
new file mode 100644
index 0000000..d4584e8
--- /dev/null
+++ b/mechanics/compose/src/com/android/mechanics/compose/modifier/VerticalTactileSurfaceRevealModifier.kt
@@ -0,0 +1,250 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.compose.modifier
+
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.geometry.Rect
+import androidx.compose.ui.graphics.CompositingStrategy
+import androidx.compose.ui.layout.ApproachLayoutModifierNode
+import androidx.compose.ui.layout.ApproachMeasureScope
+import androidx.compose.ui.layout.LayoutCoordinates
+import androidx.compose.ui.layout.Measurable
+import androidx.compose.ui.layout.MeasureResult
+import androidx.compose.ui.layout.MeasureScope
+import androidx.compose.ui.layout.Placeable
+import androidx.compose.ui.layout.boundsInParent
+import androidx.compose.ui.node.ModifierNodeElement
+import androidx.compose.ui.platform.InspectorInfo
+import androidx.compose.ui.unit.Constraints
+import androidx.compose.ui.unit.IntOffset
+import androidx.compose.ui.unit.IntSize
+import androidx.compose.ui.util.fastCoerceAtLeast
+import androidx.compose.ui.util.fastCoerceIn
+import com.android.compose.animation.scene.ContentScope
+import com.android.compose.animation.scene.ElementKey
+import com.android.compose.animation.scene.mechanics.gestureContextOrDefault
+import com.android.mechanics.MotionValue
+import com.android.mechanics.debug.findMotionValueDebugger
+import com.android.mechanics.effects.RevealOnThreshold
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spec.builder.spatialMotionSpec
+import kotlin.math.roundToInt
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.launch
+
+/**
+ * This component remains hidden until its target height meets a minimum threshold. At that point,
+ * it reveals itself by animating its height from 0 to the current target height.
+ *
+ * TODO: Once b/413283893 is done, [motionBuilderContext] can be read internally via
+ *   CompositionLocalConsumerModifierNode, instead of passing it.
+ */
+fun Modifier.verticalTactileSurfaceReveal(
+    contentScope: ContentScope,
+    motionBuilderContext: MotionBuilderContext,
+    container: ElementKey,
+    deltaY: Float = 0f,
+    revealOnThreshold: RevealOnThreshold = DefaultRevealOnThreshold,
+    label: String? = null,
+    debug: Boolean = false,
+): Modifier =
+    this then
+        VerticalTactileSurfaceRevealElement(
+            contentScope = contentScope,
+            motionBuilderContext = motionBuilderContext,
+            container = container,
+            deltaY = deltaY,
+            revealOnThreshold = revealOnThreshold,
+            label = label,
+            debug = debug,
+        )
+
+private val DefaultRevealOnThreshold = RevealOnThreshold()
+
+private data class VerticalTactileSurfaceRevealElement(
+    val contentScope: ContentScope,
+    val motionBuilderContext: MotionBuilderContext,
+    val container: ElementKey,
+    val deltaY: Float,
+    val revealOnThreshold: RevealOnThreshold,
+    val label: String?,
+    val debug: Boolean,
+) : ModifierNodeElement<VerticalTactileSurfaceRevealNode>() {
+    override fun create(): VerticalTactileSurfaceRevealNode =
+        VerticalTactileSurfaceRevealNode(
+            contentScope = contentScope,
+            motionBuilderContext = motionBuilderContext,
+            container = container,
+            deltaY = deltaY,
+            revealOnThreshold = revealOnThreshold,
+            label = label,
+            debug = debug,
+        )
+
+    override fun update(node: VerticalTactileSurfaceRevealNode) {
+        node.update(
+            contentScope = contentScope,
+            motionBuilderContext = motionBuilderContext,
+            container = container,
+            deltaY = deltaY,
+            revealOnThreshold = revealOnThreshold,
+        )
+    }
+
+    override fun InspectorInfo.inspectableProperties() {
+        name = "tactileSurfaceReveal"
+        properties["container"] = container
+        properties["deltaY"] = deltaY
+        properties["revealOnThreshold"] = revealOnThreshold
+        properties["label"] = label
+        properties["debug"] = debug
+    }
+}
+
+private class VerticalTactileSurfaceRevealNode(
+    private var contentScope: ContentScope,
+    private var motionBuilderContext: MotionBuilderContext,
+    private var container: ElementKey,
+    private var deltaY: Float,
+    private var revealOnThreshold: RevealOnThreshold,
+    label: String?,
+    private val debug: Boolean,
+) : Modifier.Node(), ApproachLayoutModifierNode {
+
+    private val motionValue =
+        MotionValue(
+            currentInput = {
+                with(contentScope) {
+                    val containerHeight =
+                        container.lastSize(contentKey)?.height ?: return@MotionValue 0f
+                    val containerCoordinates =
+                        container.targetCoordinates(contentKey) ?: return@MotionValue 0f
+                    val localCoordinates = lastCoordinates ?: return@MotionValue 0f
+
+                    val offsetY = containerCoordinates.localPositionOf(localCoordinates).y
+                    containerHeight - offsetY + deltaY
+                }
+            },
+            gestureContext = contentScope.gestureContextOrDefault(),
+            label = "TactileSurfaceReveal(${label.orEmpty()})",
+            stableThreshold = MotionBuilderContext.StableThresholdSpatial,
+        )
+
+    fun update(
+        contentScope: ContentScope,
+        motionBuilderContext: MotionBuilderContext,
+        container: ElementKey,
+        deltaY: Float,
+        revealOnThreshold: RevealOnThreshold,
+    ) {
+        this.contentScope = contentScope
+        this.motionBuilderContext = motionBuilderContext
+        this.container = container
+        this.deltaY = deltaY
+        this.revealOnThreshold = revealOnThreshold
+        updateMotionSpec()
+    }
+
+    private var motionValueJob: Job? = null
+
+    override fun onAttach() {
+        motionValueJob =
+            coroutineScope.launch {
+                val disposableHandle =
+                    if (debug) {
+                        findMotionValueDebugger()?.register(motionValue)
+                    } else {
+                        null
+                    }
+                try {
+                    motionValue.keepRunning()
+                } finally {
+                    disposableHandle?.dispose()
+                }
+            }
+    }
+
+    override fun onDetach() {
+        motionValueJob?.cancel()
+    }
+
+    private fun isAnimating(): Boolean {
+        return contentScope.layoutState.currentTransition != null || !motionValue.isStable
+    }
+
+    override fun isMeasurementApproachInProgress(lookaheadSize: IntSize) = isAnimating()
+
+    override fun Placeable.PlacementScope.isPlacementApproachInProgress(
+        lookaheadCoordinates: LayoutCoordinates
+    ) = isAnimating()
+
+    private var targetBounds = Rect.Zero
+
+    private var lastCoordinates: LayoutCoordinates? = null
+
+    private fun updateMotionSpec() {
+        motionValue.spec =
+            motionBuilderContext.spatialMotionSpec(Mapping.Zero) {
+                between(
+                    start = targetBounds.top,
+                    end = targetBounds.bottom,
+                    effect = revealOnThreshold,
+                )
+            }
+    }
+
+    override fun MeasureScope.measure(
+        measurable: Measurable,
+        constraints: Constraints,
+    ): MeasureResult {
+        val placeable = measurable.measure(constraints)
+        return layout(placeable.width, placeable.height) {
+            val coordinates = coordinates
+            if (isLookingAhead && coordinates != null) {
+                lastCoordinates = coordinates
+                val bounds = coordinates.boundsInParent()
+                if (targetBounds != bounds) {
+                    targetBounds = bounds
+                    updateMotionSpec()
+                }
+            }
+            placeable.place(IntOffset.Zero)
+        }
+    }
+
+    override fun ApproachMeasureScope.approachMeasure(
+        measurable: Measurable,
+        constraints: Constraints,
+    ): MeasureResult {
+        val height = motionValue.output.roundToInt().fastCoerceAtLeast(0)
+        val animatedConstraints = Constraints.fixed(width = constraints.maxWidth, height = height)
+        return measurable.measure(animatedConstraints).run {
+            layout(width, height) {
+                val revealAlpha = (height / revealOnThreshold.minSize.toPx()).fastCoerceIn(0f, 1f)
+                if (revealAlpha < 1) {
+                    placeWithLayer(IntOffset.Zero) {
+                        alpha = revealAlpha
+                        compositingStrategy = CompositingStrategy.ModulateAlpha
+                    }
+                } else {
+                    place(IntOffset.Zero)
+                }
+            }
+        }
+    }
+}
diff --git a/mechanics/compose/tests/AndroidManifest.xml b/mechanics/compose/tests/AndroidManifest.xml
new file mode 100644
index 0000000..182f244
--- /dev/null
+++ b/mechanics/compose/tests/AndroidManifest.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="utf-8"?><!--
+  ~ Copyright (C) 2025 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.mechanics.compose.tests">
+
+    <application android:debuggable="true">
+        <uses-library android:name="android.test.runner" />
+    </application>
+
+    <instrumentation
+        android:name="androidx.test.runner.AndroidJUnitRunner"
+        android:label="Tests for Motion Mechanics"
+        android:targetPackage="com.android.mechanics.compose.tests" />
+</manifest>
diff --git a/mechanics/src/com/android/mechanics/GestureContext.kt b/mechanics/src/com/android/mechanics/GestureContext.kt
index 88e9ef8..f1fb3ee 100644
--- a/mechanics/src/com/android/mechanics/GestureContext.kt
+++ b/mechanics/src/com/android/mechanics/GestureContext.kt
@@ -16,15 +16,37 @@
 
 package com.android.mechanics
 
+import androidx.compose.runtime.Composable
 import androidx.compose.runtime.Stable
 import androidx.compose.runtime.getValue
 import androidx.compose.runtime.mutableFloatStateOf
 import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.remember
 import androidx.compose.runtime.setValue
+import androidx.compose.ui.platform.LocalViewConfiguration
 import com.android.mechanics.spec.InputDirection
 import kotlin.math.max
 import kotlin.math.min
 
+/**
+ * Remembers [DistanceGestureContext] with the given initial distance / direction.
+ *
+ * Providing update [initDistance] or [initialDirection] will not re-create the
+ * [DistanceGestureContext].
+ *
+ * The `directionChangeSlop` is derived from `ViewConfiguration.touchSlop` and kept current without
+ * re-creating, should it ever change.
+ */
+@Composable
+fun rememberDistanceGestureContext(
+    initDistance: Float = 0f,
+    initialDirection: InputDirection = InputDirection.Max,
+): DistanceGestureContext {
+    val touchSlop = LocalViewConfiguration.current.touchSlop
+    return remember { DistanceGestureContext(initDistance, initialDirection, touchSlop) }
+        .also { it.directionChangeSlop = touchSlop }
+}
+
 /**
  * Gesture-specific context to augment [MotionValue.currentInput].
  *
diff --git a/mechanics/src/com/android/mechanics/MotionValue.kt b/mechanics/src/com/android/mechanics/MotionValue.kt
index 8ba09be..9d01c10 100644
--- a/mechanics/src/com/android/mechanics/MotionValue.kt
+++ b/mechanics/src/com/android/mechanics/MotionValue.kt
@@ -17,7 +17,6 @@
 package com.android.mechanics
 
 import androidx.compose.runtime.FloatState
-import androidx.compose.runtime.derivedStateOf
 import androidx.compose.runtime.getValue
 import androidx.compose.runtime.mutableFloatStateOf
 import androidx.compose.runtime.mutableLongStateOf
@@ -37,6 +36,8 @@ import com.android.mechanics.spec.InputDirection
 import com.android.mechanics.spec.Mapping
 import com.android.mechanics.spec.MotionSpec
 import com.android.mechanics.spec.SegmentData
+import com.android.mechanics.spec.SegmentKey
+import com.android.mechanics.spec.SemanticKey
 import com.android.mechanics.spring.SpringState
 import java.util.concurrent.atomic.AtomicInteger
 import kotlinx.coroutines.CoroutineName
@@ -140,6 +141,19 @@ class MotionValue(
     /** Whether an animation is currently running. */
     val isStable: Boolean by impl::isStable
 
+    /**
+     * The current value for the [SemanticKey].
+     *
+     * `null` if not defined in the spec.
+     */
+    operator fun <T> get(key: SemanticKey<T>): T? {
+        return impl.semanticState(key)
+    }
+
+    /** The current segment used to compute the output. */
+    val segmentKey: SegmentKey
+        get() = impl.currentComputedValues.segment.key
+
     /**
      * Keeps the [MotionValue]'s animated output running.
      *
@@ -239,7 +253,7 @@ private class ObservableComputations(
     initialSpec: MotionSpec = MotionSpec.Empty,
     override val stableThreshold: Float,
     override val label: String?,
-) : Computations {
+) : Computations() {
 
     // ----  CurrentFrameInput ---------------------------------------------------------------------
 
@@ -294,11 +308,6 @@ private class ObservableComputations(
 
     // ---- Computations ---------------------------------------------------------------------------
 
-    override val currentSegment by derivedStateOf { computeCurrentSegment() }
-    override val currentGuaranteeState by derivedStateOf { computeCurrentGuaranteeState() }
-    override val currentAnimation by derivedStateOf { computeCurrentAnimation() }
-    override val currentSpringState by derivedStateOf { computeCurrentSpringState() }
-
     suspend fun keepRunning(continueRunning: () -> Boolean) {
         check(!isActive) { "MotionValue($label) is already running" }
         isActive = true
@@ -306,9 +315,10 @@ private class ObservableComputations(
         // These `captured*` values will be applied to the `last*` values, at the beginning
         // of the each new frame.
         // TODO(b/397837971): Encapsulate the state in a StateRecord.
-        var capturedSegment = currentSegment
-        var capturedGuaranteeState = currentGuaranteeState
-        var capturedAnimation = currentAnimation
+        val initialValues = currentComputedValues
+        var capturedSegment = initialValues.segment
+        var capturedGuaranteeState = initialValues.guarantee
+        var capturedAnimation = initialValues.animation
         var capturedSpringState = currentSpringState
         var capturedFrameTimeNanos = currentAnimationTimeNanos
         var capturedInput = currentInput
@@ -349,37 +359,36 @@ private class ObservableComputations(
                 // same time not already applying the `last*` state (as this would cause a
                 // re-computation if the current state is being read before the next frame).
                 if (isAnimatingUninterrupted) {
-                    val currentDirectMapped = currentDirectMapped
-                    val lastDirectMapped =
-                        lastSegment.mapping.map(lastInput) - lastAnimation.targetValue
-
-                    val frameDuration =
-                        (currentAnimationTimeNanos - lastFrameTimeNanos) / 1_000_000_000.0
-                    val staticDelta = (currentDirectMapped - lastDirectMapped)
-                    directMappedVelocity = (staticDelta / frameDuration).toFloat()
+                    directMappedVelocity =
+                        computeDirectMappedVelocity(currentAnimationTimeNanos - lastFrameTimeNanos)
                 } else {
                     directMappedVelocity = 0f
                 }
 
-                var scheduleNextFrame = !isStable
-                if (capturedSegment != currentSegment) {
-                    capturedSegment = currentSegment
-                    scheduleNextFrame = true
-                }
+                var scheduleNextFrame = false
+                if (!isSameSegmentAndAtRest) {
+                    // Read currentComputedValues only once and update it, if necessary
+                    val currentValues = currentComputedValues
 
-                if (capturedGuaranteeState != currentGuaranteeState) {
-                    capturedGuaranteeState = currentGuaranteeState
-                    scheduleNextFrame = true
-                }
+                    if (capturedSegment != currentValues.segment) {
+                        capturedSegment = currentValues.segment
+                        scheduleNextFrame = true
+                    }
 
-                if (capturedAnimation != currentAnimation) {
-                    capturedAnimation = currentAnimation
-                    scheduleNextFrame = true
-                }
+                    if (capturedGuaranteeState != currentValues.guarantee) {
+                        capturedGuaranteeState = currentValues.guarantee
+                        scheduleNextFrame = true
+                    }
 
-                if (capturedSpringState != currentSpringState) {
-                    capturedSpringState = currentSpringState
-                    scheduleNextFrame = true
+                    if (capturedAnimation != currentValues.animation) {
+                        capturedAnimation = currentValues.animation
+                        scheduleNextFrame = true
+                    }
+
+                    if (capturedSpringState != currentSpringState) {
+                        capturedSpringState = currentSpringState
+                        scheduleNextFrame = true
+                    }
                 }
 
                 if (capturedInput != currentInput) {
diff --git a/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerBackground.kt b/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerBackground.kt
index 2d9f7f9..9738424 100644
--- a/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerBackground.kt
+++ b/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerBackground.kt
@@ -34,6 +34,7 @@ import androidx.compose.ui.util.fastCoerceAtLeast
 import androidx.compose.ui.util.fastCoerceIn
 import androidx.compose.ui.util.lerp
 import kotlin.math.min
+import kotlin.math.round
 
 /**
  * Draws the background of a vertically container, and applies clipping to it.
@@ -72,11 +73,10 @@ internal fun Modifier.verticalFloatingExpandContainerBackground(
             obtainGraphicsLayer().apply {
                 clip = true
                 setRoundRectOutline(shapeTopLeft, shapeSize, cornerRadius = currentRadiusPx)
-
-                record { drawContent() }
             }
 
         onDrawWithContent {
+            layer.record { this@onDrawWithContent.drawContent() }
             drawRoundRect(
                 color = backgroundColor,
                 topLeft = shapeTopLeft,
@@ -135,12 +135,13 @@ internal class EdgeContainerExpansionBackgroundNode(
         val radius = height.fastCoerceIn(spec.minRadius.toPx(), spec.radius.toPx())
 
         // Draw (at most) the bottom half of the rounded corner rectangle, aligned to the bottom.
-        val upperHeight = height - radius
+        // Round upper height to the closest integer to avoid to avoid a hairline gap being visible
+        // due to the two rectangles overlapping.
+        val upperHeight = round((height - radius)).fastCoerceAtLeast(0f)
 
         // The rounded rect is drawn at 2x the radius height, to avoid smaller corner radii.
-        // The clipRect limits this to the relevant part (-1 to avoid a hairline gap being visible
-        // between this and the fill below.
-        clipRect(top = (upperHeight - 1).fastCoerceAtLeast(0f)) {
+        // The clipRect limits this to the relevant part between this and the fill below.
+        clipRect(top = upperHeight) {
             drawRoundRect(
                 color = backgroundColor,
                 cornerRadius = CornerRadius(radius),
diff --git a/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerSpec.kt b/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerSpec.kt
index e7fb688..3bc264a 100644
--- a/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerSpec.kt
+++ b/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerSpec.kt
@@ -27,16 +27,13 @@ import androidx.compose.ui.util.fastCoerceIn
 import androidx.compose.ui.util.lerp
 import com.android.mechanics.spec.Breakpoint
 import com.android.mechanics.spec.BreakpointKey
-import com.android.mechanics.spec.DirectionalMotionSpec
 import com.android.mechanics.spec.InputDirection
 import com.android.mechanics.spec.Mapping
 import com.android.mechanics.spec.MotionSpec
 import com.android.mechanics.spec.OnChangeSegmentHandler
 import com.android.mechanics.spec.SegmentData
 import com.android.mechanics.spec.SegmentKey
-import com.android.mechanics.spec.buildDirectionalMotionSpec
-import com.android.mechanics.spec.builder
-import com.android.mechanics.spec.reverseBuilder
+import com.android.mechanics.spec.builder.directionalMotionSpec
 import com.android.mechanics.spring.SpringParameters
 
 /** Motion spec for a vertically expandable container. */
@@ -54,23 +51,38 @@ class VerticalExpandContainerSpec(
     val opacitySpring: SpringParameters = Defaults.OpacitySpring,
 ) {
     fun createHeightSpec(motionScheme: MotionScheme, density: Density): MotionSpec {
+        // TODO: michschn@ - replace with MagneticDetach
         return with(density) {
             val spatialSpring = SpringParameters(motionScheme.defaultSpatialSpec())
 
             val detachSpec =
-                DirectionalMotionSpec.builder(
-                        initialMapping = Mapping.Zero,
-                        defaultSpring = spatialSpring,
+                directionalMotionSpec(
+                    initialMapping = Mapping.Zero,
+                    defaultSpring = spatialSpring,
+                ) {
+                    fractionalInputFromCurrent(
+                        breakpoint = 0f,
+                        key = Breakpoints.Attach,
+                        fraction = preDetachRatio,
                     )
-                    .toBreakpoint(0f, key = Breakpoints.Attach)
-                    .continueWith(Mapping.Linear(preDetachRatio))
-                    .toBreakpoint(detachHeight.toPx(), key = Breakpoints.Detach)
-                    .completeWith(Mapping.Identity, detachSpring)
+                    identity(
+                        breakpoint = detachHeight.toPx(),
+                        key = Breakpoints.Detach,
+                        spring = detachSpring,
+                    )
+                }
 
             val attachSpec =
-                DirectionalMotionSpec.reverseBuilder(defaultSpring = spatialSpring)
-                    .toBreakpoint(attachHeight.toPx(), key = Breakpoints.Detach)
-                    .completeWith(mapping = Mapping.Zero, attachSpring)
+                directionalMotionSpec(
+                    initialMapping = Mapping.Zero,
+                    defaultSpring = spatialSpring,
+                ) {
+                    identity(
+                        breakpoint = attachHeight.toPx(),
+                        key = Breakpoints.Detach,
+                        spring = attachSpring,
+                    )
+                }
 
             val segmentHandlers =
                 mapOf<SegmentKey, OnChangeSegmentHandler>(
@@ -102,10 +114,10 @@ class VerticalExpandContainerSpec(
     ): MotionSpec {
         return with(density) {
             if (isFloating) {
-                MotionSpec(buildDirectionalMotionSpec(Mapping.Fixed(intrinsicWidth)))
+                MotionSpec(directionalMotionSpec(Mapping.Fixed(intrinsicWidth)))
             } else {
                 MotionSpec(
-                    buildDirectionalMotionSpec({ input ->
+                    directionalMotionSpec({ input ->
                         val fraction = (input / detachHeight.toPx()).fastCoerceIn(0f, 1f)
                         intrinsicWidth - lerp(widthOffset.toPx(), 0f, fraction)
                     })
@@ -116,23 +128,11 @@ class VerticalExpandContainerSpec(
 
     fun createAlphaSpec(motionScheme: MotionScheme, density: Density): MotionSpec {
         return with(density) {
-            val detachSpec =
-                DirectionalMotionSpec.builder(
-                        SpringParameters(motionScheme.defaultEffectsSpec()),
-                        initialMapping = Mapping.Zero,
-                    )
-                    .toBreakpoint(visibleHeight.toPx())
-                    .completeWith(Mapping.One, opacitySpring)
-
-            val attachSpec =
-                DirectionalMotionSpec.builder(
-                        SpringParameters(motionScheme.defaultEffectsSpec()),
-                        initialMapping = Mapping.Zero,
-                    )
-                    .toBreakpoint(visibleHeight.toPx())
-                    .completeWith(Mapping.One, opacitySpring)
-
-            MotionSpec(maxDirection = detachSpec, minDirection = attachSpec)
+            MotionSpec(
+                directionalMotionSpec(opacitySpring, initialMapping = Mapping.Zero) {
+                    fixedValue(breakpoint = visibleHeight.toPx(), value = 1f)
+                }
+            )
         }
     }
 
diff --git a/mechanics/src/com/android/mechanics/debug/DebugInspector.kt b/mechanics/src/com/android/mechanics/debug/DebugInspector.kt
index 0eb015f..088c78b 100644
--- a/mechanics/src/com/android/mechanics/debug/DebugInspector.kt
+++ b/mechanics/src/com/android/mechanics/debug/DebugInspector.kt
@@ -24,6 +24,8 @@ import com.android.mechanics.impl.DiscontinuityAnimation
 import com.android.mechanics.spec.InputDirection
 import com.android.mechanics.spec.SegmentData
 import com.android.mechanics.spec.SegmentKey
+import com.android.mechanics.spec.SemanticKey
+import com.android.mechanics.spec.SemanticValue
 import com.android.mechanics.spring.SpringParameters
 import com.android.mechanics.spring.SpringState
 import kotlinx.coroutines.DisposableHandle
@@ -74,11 +76,15 @@ internal constructor(
         get() = segment.key
 
     val output: Float
-        get() = currentDirectMapped + (animation.targetValue + springState.displacement)
+        get() = segment.mapping.map(input) + springState.displacement
 
     val outputTarget: Float
-        get() = currentDirectMapped + animation.targetValue
+        get() = segment.mapping.map(input)
 
-    private val currentDirectMapped: Float
-        get() = segment.mapping.map(input) - animation.targetValue
+    fun <T> semantic(semanticKey: SemanticKey<T>): T? {
+        return segment.semantic(semanticKey)
+    }
+
+    val semantics: List<SemanticValue<*>>
+        get() = with(segment) { spec.semantics(key) }
 }
diff --git a/mechanics/src/com/android/mechanics/debug/DebugVisualization.kt b/mechanics/src/com/android/mechanics/debug/DebugVisualization.kt
index 38140a3..b89728b 100644
--- a/mechanics/src/com/android/mechanics/debug/DebugVisualization.kt
+++ b/mechanics/src/com/android/mechanics/debug/DebugVisualization.kt
@@ -50,8 +50,10 @@ import com.android.mechanics.MotionValue
 import com.android.mechanics.spec.DirectionalMotionSpec
 import com.android.mechanics.spec.Guarantee
 import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.Mapping
 import com.android.mechanics.spec.MotionSpec
 import com.android.mechanics.spec.SegmentKey
+import kotlin.math.ceil
 import kotlin.math.max
 import kotlin.math.min
 import kotlinx.coroutines.flow.first
@@ -359,17 +361,36 @@ private fun DrawScope.drawDirectionalSpec(
         val segmentEnd = endBreakpoint.position
         val toInput = segmentEnd.fastCoerceAtMost(inputRange.endInclusive)
 
-        // TODO add support for functions that are not linear
+        val strokeWidth = if (isActiveSegment) 2.dp.toPx() else Stroke.HairlineWidth
+        val dotSize = if (isActiveSegment) 4.dp.toPx() else 2.dp.toPx()
         val fromY = mapPointInOutputToY(mapping.map(fromInput), outputRange)
         val toY = mapPointInOutputToY(mapping.map(toInput), outputRange)
 
         val start = Offset(mapPointInInputToX(fromInput, inputRange), fromY)
         val end = Offset(mapPointInInputToX(toInput, inputRange), toY)
+        if (mapping is Mapping.Fixed || mapping is Mapping.Identity || mapping is Mapping.Linear) {
+            drawLine(color, start, end, strokeWidth = strokeWidth)
+        } else {
+            val xStart = mapPointInInputToX(fromInput, inputRange)
+            val xEnd = mapPointInInputToX(toInput, inputRange)
 
-        val strokeWidth = if (isActiveSegment) 2.dp.toPx() else Stroke.HairlineWidth
-        val dotSize = if (isActiveSegment) 4.dp.toPx() else 2.dp.toPx()
+            val oneDpInPx = 1.dp.toPx()
+            val numberOfLines = ceil((xEnd - xStart) / oneDpInPx).toInt()
+            val inputLength = (toInput - fromInput) / numberOfLines
+
+            repeat(numberOfLines) {
+                val lineStart = fromInput + inputLength * it
+                val lineEnd = lineStart + inputLength
 
-        drawLine(color, start, end, strokeWidth = strokeWidth)
+                val partialFromY = mapPointInOutputToY(mapping.map(lineStart), outputRange)
+                val partialToY = mapPointInOutputToY(mapping.map(lineEnd), outputRange)
+
+                val partialStart = Offset(mapPointInInputToX(lineStart, inputRange), partialFromY)
+                val partialEnd = Offset(mapPointInInputToX(lineEnd, inputRange), partialToY)
+
+                drawLine(color, partialStart, partialEnd, strokeWidth = strokeWidth)
+            }
+        }
 
         if (segmentStart == fromInput) {
             drawCircle(color, dotSize, start)
diff --git a/mechanics/src/com/android/mechanics/effects/Fixed.kt b/mechanics/src/com/android/mechanics/effects/Fixed.kt
new file mode 100644
index 0000000..b1c5fb2
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/effects/Fixed.kt
@@ -0,0 +1,55 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.effects
+
+import com.android.mechanics.spec.BreakpointKey
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.builder.Effect
+import com.android.mechanics.spec.builder.EffectApplyScope
+import com.android.mechanics.spec.builder.EffectPlacement
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spec.builder.MotionSpecBuilderScope
+
+/** Creates a [FixedValue] effect with the given [value]. */
+fun MotionSpecBuilderScope.fixed(value: Float) = FixedValue(value)
+
+val MotionSpecBuilderScope.zero: FixedValue
+    get() = FixedValue.Zero
+val MotionSpecBuilderScope.one: FixedValue
+    get() = FixedValue.One
+
+/** Produces a fixed [value]. */
+class FixedValue(val value: Float) :
+    Effect.PlaceableAfter, Effect.PlaceableBefore, Effect.PlaceableBetween {
+
+    override fun MotionBuilderContext.intrinsicSize(): Float = Float.NaN
+
+    override fun EffectApplyScope.createSpec(
+        minLimit: Float,
+        minLimitKey: BreakpointKey,
+        maxLimit: Float,
+        maxLimitKey: BreakpointKey,
+        placement: EffectPlacement,
+    ) {
+        return unidirectional(Mapping.Fixed(value))
+    }
+
+    companion object {
+        val Zero = FixedValue(0f)
+        val One = FixedValue(1f)
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/effects/MagneticDetach.kt b/mechanics/src/com/android/mechanics/effects/MagneticDetach.kt
new file mode 100644
index 0000000..1e4e38b
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/effects/MagneticDetach.kt
@@ -0,0 +1,259 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+@file:OptIn(ExperimentalMaterial3ExpressiveApi::class)
+
+package com.android.mechanics.effects
+
+import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
+import androidx.compose.ui.unit.Dp
+import androidx.compose.ui.unit.dp
+import androidx.compose.ui.util.lerp
+import com.android.mechanics.spec.BreakpointKey
+import com.android.mechanics.spec.ChangeSegmentHandlers.PreventDirectionChangeWithinCurrentSegment
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.SegmentKey
+import com.android.mechanics.spec.SemanticKey
+import com.android.mechanics.spec.builder.Effect
+import com.android.mechanics.spec.builder.EffectApplyScope
+import com.android.mechanics.spec.builder.EffectPlacemenType
+import com.android.mechanics.spec.builder.EffectPlacement
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spec.with
+import com.android.mechanics.spring.SpringParameters
+
+/**
+ * Gesture effect that emulates effort to detach an element from its resting position.
+ *
+ * @param semanticState semantic state used to check the state of this effect.
+ * @param detachPosition distance from the origin to detach
+ * @param attachPosition distance from the origin to re-attach
+ * @param detachScale fraction of input changes propagated during detach.
+ * @param attachScale fraction of input changes propagated after re-attach.
+ * @param detachSpring spring used during detach
+ * @param attachSpring spring used during attach
+ */
+class MagneticDetach(
+    private val semanticState: SemanticKey<State> = Defaults.AttachDetachState,
+    private val semanticAttachedValue: SemanticKey<Float?> = Defaults.AttachedValue,
+    private val detachPosition: Dp = Defaults.DetachPosition,
+    private val attachPosition: Dp = Defaults.AttachPosition,
+    private val detachScale: Float = Defaults.AttachDetachScale,
+    private val attachScale: Float = Defaults.AttachDetachScale * (attachPosition / detachPosition),
+    private val detachSpring: SpringParameters = Defaults.Spring,
+    private val attachSpring: SpringParameters = Defaults.Spring,
+) : Effect.PlaceableAfter, Effect.PlaceableBefore {
+
+    init {
+        require(attachPosition <= detachPosition)
+    }
+
+    enum class State {
+        Attached,
+        Detached,
+    }
+
+    override fun MotionBuilderContext.intrinsicSize(): Float {
+        return detachPosition.toPx()
+    }
+
+    override fun EffectApplyScope.createSpec(
+        minLimit: Float,
+        minLimitKey: BreakpointKey,
+        maxLimit: Float,
+        maxLimitKey: BreakpointKey,
+        placement: EffectPlacement,
+    ) {
+        if (placement.type == EffectPlacemenType.Before) {
+            createPlacedBeforeSpec(minLimit, minLimitKey, maxLimit, maxLimitKey)
+        } else {
+            assert(placement.type == EffectPlacemenType.After)
+            createPlacedAfterSpec(minLimit, minLimitKey, maxLimit, maxLimitKey)
+        }
+    }
+
+    object Defaults {
+        val AttachDetachState = SemanticKey<State>()
+        val AttachedValue = SemanticKey<Float?>()
+        val AttachDetachScale = .3f
+        val DetachPosition = 80.dp
+        val AttachPosition = 40.dp
+        val Spring = SpringParameters(stiffness = 800f, dampingRatio = 0.95f)
+    }
+
+    /* Effect is attached at minLimit, and detaches at maxLimit. */
+    private fun EffectApplyScope.createPlacedAfterSpec(
+        minLimit: Float,
+        minLimitKey: BreakpointKey,
+        maxLimit: Float,
+        maxLimitKey: BreakpointKey,
+    ) {
+        val attachedValue = baseValue(minLimit)
+        val detachedValue = baseValue(maxLimit)
+        val reattachPos = minLimit + attachPosition.toPx()
+        val reattachValue = baseValue(reattachPos)
+
+        val attachedSemantics =
+            listOf(semanticState with State.Attached, semanticAttachedValue with attachedValue)
+        val detachedSemantics =
+            listOf(semanticState with State.Detached, semanticAttachedValue with null)
+
+        val scaledDetachValue = attachedValue + (detachedValue - attachedValue) * detachScale
+        val scaledReattachValue = attachedValue + (reattachValue - attachedValue) * attachScale
+
+        val attachKey = BreakpointKey("attach")
+        forward(
+            initialMapping = Mapping.Linear(minLimit, attachedValue, maxLimit, scaledDetachValue),
+            semantics = attachedSemantics,
+        ) {
+            after(spring = detachSpring, semantics = detachedSemantics)
+            before(semantics = listOf(semanticAttachedValue with null))
+        }
+
+        backward(
+            initialMapping =
+                Mapping.Linear(minLimit, attachedValue, reattachPos, scaledReattachValue),
+            semantics = attachedSemantics,
+        ) {
+            mapping(
+                breakpoint = reattachPos,
+                key = attachKey,
+                spring = attachSpring,
+                semantics = detachedSemantics,
+                mapping = baseMapping,
+            )
+            before(semantics = listOf(semanticAttachedValue with null))
+            after(semantics = listOf(semanticAttachedValue with null))
+        }
+
+        addSegmentHandlers(
+            beforeDetachSegment = SegmentKey(minLimitKey, maxLimitKey, InputDirection.Max),
+            beforeAttachSegment = SegmentKey(attachKey, maxLimitKey, InputDirection.Min),
+            afterAttachSegment = SegmentKey(minLimitKey, attachKey, InputDirection.Min),
+            minLimit = minLimit,
+            maxLimit = maxLimit,
+        )
+    }
+
+    /* Effect is attached at maxLimit, and detaches at minLimit. */
+    private fun EffectApplyScope.createPlacedBeforeSpec(
+        minLimit: Float,
+        minLimitKey: BreakpointKey,
+        maxLimit: Float,
+        maxLimitKey: BreakpointKey,
+    ) {
+        val attachedValue = baseValue(maxLimit)
+        val detachedValue = baseValue(minLimit)
+        val reattachPos = maxLimit - attachPosition.toPx()
+        val reattachValue = baseValue(reattachPos)
+
+        val attachedSemantics =
+            listOf(semanticState with State.Attached, semanticAttachedValue with attachedValue)
+        val detachedSemantics =
+            listOf(semanticState with State.Detached, semanticAttachedValue with null)
+
+        val scaledDetachValue = attachedValue + (detachedValue - attachedValue) * detachScale
+        val scaledReattachValue = attachedValue + (reattachValue - attachedValue) * attachScale
+
+        val attachKey = BreakpointKey("attach")
+
+        backward(
+            initialMapping = Mapping.Linear(minLimit, scaledDetachValue, maxLimit, attachedValue),
+            semantics = attachedSemantics,
+        ) {
+            before(spring = detachSpring, semantics = detachedSemantics)
+            after(semantics = listOf(semanticAttachedValue with null))
+        }
+
+        forward(initialMapping = baseMapping, semantics = detachedSemantics) {
+            target(
+                breakpoint = reattachPos,
+                key = attachKey,
+                from = scaledReattachValue,
+                to = attachedValue,
+                spring = attachSpring,
+                semantics = attachedSemantics,
+            )
+            after(semantics = listOf(semanticAttachedValue with null))
+        }
+
+        addSegmentHandlers(
+            beforeDetachSegment = SegmentKey(minLimitKey, maxLimitKey, InputDirection.Min),
+            beforeAttachSegment = SegmentKey(minLimitKey, attachKey, InputDirection.Max),
+            afterAttachSegment = SegmentKey(attachKey, maxLimitKey, InputDirection.Max),
+            minLimit = minLimit,
+            maxLimit = maxLimit,
+        )
+    }
+
+    private fun EffectApplyScope.addSegmentHandlers(
+        beforeDetachSegment: SegmentKey,
+        beforeAttachSegment: SegmentKey,
+        afterAttachSegment: SegmentKey,
+        minLimit: Float,
+        maxLimit: Float,
+    ) {
+        // Suppress direction change during detach. This prevents snapping to the origin when
+        // changing the direction while detaching.
+        addSegmentHandler(beforeDetachSegment, PreventDirectionChangeWithinCurrentSegment)
+        // Suppress direction when approaching attach. This prevents the detach effect when changing
+        // direction just before reattaching.
+        addSegmentHandler(beforeAttachSegment, PreventDirectionChangeWithinCurrentSegment)
+
+        // When changing direction after re-attaching, the pre-detach ratio is tweaked to
+        // interpolate between the direction change-position and the detach point.
+        addSegmentHandler(afterAttachSegment) { currentSegment, newInput, newDirection ->
+            val nextSegment = segmentAtInput(newInput, newDirection)
+            if (nextSegment.key == beforeDetachSegment) {
+                nextSegment.copy(
+                    mapping =
+                        switchMappingWithSamePivotValue(
+                            currentSegment.mapping,
+                            nextSegment.mapping,
+                            minLimit,
+                            newInput,
+                            maxLimit,
+                        )
+                )
+            } else {
+                nextSegment
+            }
+        }
+    }
+
+    private fun switchMappingWithSamePivotValue(
+        source: Mapping,
+        target: Mapping,
+        minLimit: Float,
+        pivot: Float,
+        maxLimit: Float,
+    ): Mapping {
+        val minValue = target.map(minLimit)
+        val pivotValue = source.map(pivot)
+        val maxValue = target.map(maxLimit)
+
+        return Mapping { input ->
+            if (input <= pivot) {
+                val t = (input - minLimit) / (pivot - minLimit)
+                lerp(minValue, pivotValue, t)
+            } else {
+                val t = (input - pivot) / (maxLimit - pivot)
+                lerp(pivotValue, maxValue, t)
+            }
+        }
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/effects/Overdrag.kt b/mechanics/src/com/android/mechanics/effects/Overdrag.kt
new file mode 100644
index 0000000..af1dca6
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/effects/Overdrag.kt
@@ -0,0 +1,69 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.effects
+
+import androidx.compose.ui.unit.Dp
+import androidx.compose.ui.unit.dp
+import com.android.mechanics.spec.BreakpointKey
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.SemanticKey
+import com.android.mechanics.spec.builder.Effect
+import com.android.mechanics.spec.builder.EffectApplyScope
+import com.android.mechanics.spec.builder.EffectPlacement
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spec.with
+
+/** Gesture effect to soft-limit. */
+class Overdrag(
+    private val overdragLimit: SemanticKey<Float?> = Defaults.OverdragLimit,
+    private val maxOverdrag: Dp = Defaults.MaxOverdrag,
+    private val tilt: Float = Defaults.tilt,
+) : Effect.PlaceableBefore, Effect.PlaceableAfter {
+
+    override fun MotionBuilderContext.intrinsicSize() = Float.POSITIVE_INFINITY
+
+    override fun EffectApplyScope.createSpec(
+        minLimit: Float,
+        minLimitKey: BreakpointKey,
+        maxLimit: Float,
+        maxLimitKey: BreakpointKey,
+        placement: EffectPlacement,
+    ) {
+
+        val maxOverdragPx = maxOverdrag.toPx()
+
+        val limitValue = baseValue(placement.start)
+        val mapping = Mapping { input ->
+            val baseMapped = baseMapping.map(input)
+
+            maxOverdragPx * kotlin.math.tanh((baseMapped - limitValue) / (maxOverdragPx * tilt)) +
+                limitValue
+        }
+
+        unidirectional(mapping, listOf(overdragLimit with limitValue)) {
+            if (!placement.isForward) {
+                after(semantics = listOf(overdragLimit with null))
+            }
+        }
+    }
+
+    object Defaults {
+        val OverdragLimit = SemanticKey<Float?>()
+        val MaxOverdrag = 30.dp
+        val tilt = 3f
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/effects/RevealOnThreshold.kt b/mechanics/src/com/android/mechanics/effects/RevealOnThreshold.kt
new file mode 100644
index 0000000..124f031
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/effects/RevealOnThreshold.kt
@@ -0,0 +1,56 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.effects
+
+import androidx.compose.ui.unit.Dp
+import androidx.compose.ui.unit.dp
+import androidx.compose.ui.util.fastCoerceAtMost
+import com.android.mechanics.spec.BreakpointKey
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.builder.Effect
+import com.android.mechanics.spec.builder.EffectApplyScope
+import com.android.mechanics.spec.builder.EffectPlacement
+
+/** An effect that reveals a component when the available space reaches a certain threshold. */
+data class RevealOnThreshold(val minSize: Dp = Defaults.MinSize) : Effect.PlaceableBetween {
+    init {
+        require(minSize >= 0.dp)
+    }
+
+    override fun EffectApplyScope.createSpec(
+        minLimit: Float,
+        minLimitKey: BreakpointKey,
+        maxLimit: Float,
+        maxLimitKey: BreakpointKey,
+        placement: EffectPlacement,
+    ) {
+        val maxSize = maxLimit - minLimit
+        val minSize = minSize.toPx().fastCoerceAtMost(maxSize)
+
+        unidirectional(initialMapping = Mapping.Zero) {
+            before(mapping = Mapping.Zero)
+
+            target(breakpoint = minLimit + minSize, from = minSize, to = maxSize)
+
+            after(mapping = Mapping.Fixed(maxSize))
+        }
+    }
+
+    object Defaults {
+        val MinSize: Dp = 8.dp
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/impl/Computations.kt b/mechanics/src/com/android/mechanics/impl/Computations.kt
index 124333f..2ac9574 100644
--- a/mechanics/src/com/android/mechanics/impl/Computations.kt
+++ b/mechanics/src/com/android/mechanics/impl/Computations.kt
@@ -23,25 +23,174 @@ import androidx.compose.ui.util.fastIsFinite
 import androidx.compose.ui.util.lerp
 import com.android.mechanics.MotionValue.Companion.TAG
 import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.MotionSpec
 import com.android.mechanics.spec.SegmentData
+import com.android.mechanics.spec.SemanticKey
 import com.android.mechanics.spring.SpringState
 import com.android.mechanics.spring.calculateUpdatedState
 
-internal interface ComputeSegment : CurrentFrameInput, LastFrameState, StaticConfig {
+internal abstract class Computations : CurrentFrameInput, LastFrameState, StaticConfig {
+    internal class ComputedValues(
+        val segment: SegmentData,
+        val guarantee: GuaranteeState,
+        val animation: DiscontinuityAnimation,
+    )
+
+    // currentComputedValues input
+    private var memoizedSpec: MotionSpec? = null
+    private var memoizedInput: Float = Float.MIN_VALUE
+    private var memoizedAnimationTimeNanos: Long = Long.MIN_VALUE
+    private var memoizedDirection: InputDirection = InputDirection.Min
+
+    // currentComputedValues output
+    private lateinit var memoizedComputedValues: ComputedValues
+
+    internal val currentComputedValues: ComputedValues
+        get() {
+            val currentSpec: MotionSpec = spec
+            val currentInput: Float = currentInput
+            val currentAnimationTimeNanos: Long = currentAnimationTimeNanos
+            val currentDirection: InputDirection = currentDirection
+
+            if (
+                memoizedSpec == currentSpec &&
+                    memoizedInput == currentInput &&
+                    memoizedAnimationTimeNanos == currentAnimationTimeNanos &&
+                    memoizedDirection == currentDirection
+            ) {
+                return memoizedComputedValues
+            }
+
+            memoizedSpec = currentSpec
+            memoizedInput = currentInput
+            memoizedAnimationTimeNanos = currentAnimationTimeNanos
+            memoizedDirection = currentDirection
+
+            val segment: SegmentData =
+                computeSegmentData(
+                    spec = currentSpec,
+                    input = currentInput,
+                    direction = currentDirection,
+                )
+
+            val segmentChange: SegmentChangeType =
+                getSegmentChangeType(
+                    segment = segment,
+                    input = currentInput,
+                    direction = currentDirection,
+                )
+
+            val guarantee: GuaranteeState =
+                computeGuaranteeState(
+                    segment = segment,
+                    segmentChange = segmentChange,
+                    input = currentInput,
+                )
+
+            val animation: DiscontinuityAnimation =
+                computeAnimation(
+                    segment = segment,
+                    guarantee = guarantee,
+                    segmentChange = segmentChange,
+                    spec = currentSpec,
+                    input = currentInput,
+                    animationTimeNanos = currentAnimationTimeNanos,
+                )
+
+            return ComputedValues(segment, guarantee, animation).also {
+                memoizedComputedValues = it
+            }
+        }
+
+    // currentSpringState input
+    private var memoizedAnimation: DiscontinuityAnimation? = null
+    private var memoizedTimeNanos: Long = Long.MIN_VALUE
+
+    // currentSpringState output
+    private var memoizedSpringState: SpringState = SpringState.AtRest
+
+    val currentSpringState: SpringState
+        get() {
+            val animation = currentComputedValues.animation
+            val timeNanos = currentAnimationTimeNanos
+            if (memoizedAnimation == animation && memoizedTimeNanos == timeNanos) {
+                return memoizedSpringState
+            }
+            memoizedAnimation = animation
+            memoizedTimeNanos = timeNanos
+            return computeSpringState(animation, timeNanos).also { memoizedSpringState = it }
+        }
+
+    val isSameSegmentAndAtRest: Boolean
+        get() =
+            lastSpringState == SpringState.AtRest &&
+                lastSegment.spec == spec &&
+                lastSegment.isValidForInput(currentInput, currentDirection)
+
+    val output: Float
+        get() =
+            if (isSameSegmentAndAtRest) {
+                lastSegment.mapping.map(currentInput)
+            } else {
+                outputTarget + currentSpringState.displacement
+            }
+
+    val outputTarget: Float
+        get() =
+            if (isSameSegmentAndAtRest) {
+                lastSegment.mapping.map(currentInput)
+            } else {
+                currentComputedValues.segment.mapping.map(currentInput)
+            }
+
+    val isStable: Boolean
+        get() =
+            if (isSameSegmentAndAtRest) {
+                true
+            } else {
+                currentSpringState == SpringState.AtRest
+            }
+
+    fun <T> semanticState(semanticKey: SemanticKey<T>): T? {
+        return with(if (isSameSegmentAndAtRest) lastSegment else currentComputedValues.segment) {
+            spec.semanticState(semanticKey, key)
+        }
+    }
+
+    fun computeDirectMappedVelocity(frameDurationNanos: Long): Float {
+        val directMappedDelta =
+            if (
+                lastSegment.spec == spec &&
+                    lastSegment.isValidForInput(currentInput, currentDirection)
+            ) {
+                lastSegment.mapping.map(currentInput) - lastSegment.mapping.map(lastInput)
+            } else {
+                val springChange = currentSpringState.displacement - lastSpringState.displacement
+
+                currentComputedValues.segment.mapping.map(currentInput) -
+                    lastSegment.mapping.map(lastInput) + springChange
+            }
+
+        val frameDuration = frameDurationNanos / 1_000_000_000.0
+        return (directMappedDelta / frameDuration).toFloat()
+    }
+
     /**
      * The current segment, which defines the [Mapping] function used to transform the input to the
      * output.
      *
-     * While both [spec] and [currentDirection] remain the same, and [currentInput] is within the
-     * segment (see [SegmentData.isValidForInput]), this is [lastSegment].
+     * While both [spec] and [direction] remain the same, and [input] is within the segment (see
+     * [SegmentData.isValidForInput]), this is [LastFrameState.lastSegment].
      *
      * Otherwise, [MotionSpec.onChangeSegment] is queried for an up-dated segment.
      */
-    fun computeCurrentSegment(): SegmentData {
-        val lastSegment = lastSegment
-        val input = currentInput
-        val direction = currentDirection
-
+    private fun computeSegmentData(
+        spec: MotionSpec,
+        input: Float,
+        direction: InputDirection,
+    ): SegmentData {
         val specChanged = lastSegment.spec != spec
         return if (specChanged || !lastSegment.isValidForInput(input, direction)) {
             spec.onChangeSegment(lastSegment, input, direction)
@@ -49,48 +198,43 @@ internal interface ComputeSegment : CurrentFrameInput, LastFrameState, StaticCon
             lastSegment
         }
     }
-}
-
-internal interface ComputeGuaranteeState : ComputeSegment {
-    val currentSegment: SegmentData
 
-    /** Computes the [SegmentChangeType] between [lastSegment] and [currentSegment]. */
-    val segmentChangeType: SegmentChangeType
-        get() {
-            val currentSegment = currentSegment
-            val lastSegment = lastSegment
-
-            if (currentSegment.key == lastSegment.key) {
-                return SegmentChangeType.Same
-            }
+    /** Computes the [SegmentChangeType] between [LastFrameState.lastSegment] and [segment]. */
+    private fun getSegmentChangeType(
+        segment: SegmentData,
+        input: Float,
+        direction: InputDirection,
+    ): SegmentChangeType {
+        if (segment.key == lastSegment.key) {
+            return SegmentChangeType.Same
+        }
 
-            if (
-                currentSegment.key.minBreakpoint == lastSegment.key.minBreakpoint &&
-                    currentSegment.key.maxBreakpoint == lastSegment.key.maxBreakpoint
-            ) {
-                return SegmentChangeType.SameOppositeDirection
-            }
+        if (
+            segment.key.minBreakpoint == lastSegment.key.minBreakpoint &&
+                segment.key.maxBreakpoint == lastSegment.key.maxBreakpoint
+        ) {
+            return SegmentChangeType.SameOppositeDirection
+        }
 
-            val currentSpec = currentSegment.spec
-            val lastSpec = lastSegment.spec
-            if (currentSpec !== lastSpec) {
-                // Determine/guess whether the segment change was due to the changed spec, or
-                // whether lastSpec would return the same segment key for the update input.
-                val lastSpecSegmentForSameInput =
-                    lastSpec.segmentAtInput(currentInput, currentDirection).key
-                if (currentSegment.key != lastSpecSegmentForSameInput) {
-                    // Note: this might not be correct if the new [MotionSpec.segmentHandlers] were
-                    // involved.
-                    return SegmentChangeType.Spec
-                }
+        val currentSpec = segment.spec
+        val lastSpec = lastSegment.spec
+        if (currentSpec !== lastSpec) {
+            // Determine/guess whether the segment change was due to the changed spec, or
+            // whether lastSpec would return the same segment key for the update input.
+            val lastSpecSegmentForSameInput = lastSpec.segmentAtInput(input, direction).key
+            if (segment.key != lastSpecSegmentForSameInput) {
+                // Note: this might not be correct if the new [MotionSpec.segmentHandlers] were
+                // involved.
+                return SegmentChangeType.Spec
             }
+        }
 
-            return if (currentSegment.direction == lastSegment.direction) {
-                SegmentChangeType.Traverse
-            } else {
-                SegmentChangeType.Direction
-            }
+        return if (segment.direction == lastSegment.direction) {
+            SegmentChangeType.Traverse
+        } else {
+            SegmentChangeType.Direction
         }
+    }
 
     /**
      * Computes the fraction of [position] between [lastInput] and [currentInput].
@@ -108,26 +252,33 @@ internal interface ComputeGuaranteeState : ComputeSegment {
      * Of course, this is a simplification that assumes the input velocity was uniform during the
      * last frame, but that is likely good enough.
      */
-    fun lastFrameFractionOfPosition(position: Float): Float {
-        return ((position - lastInput) / (currentInput - lastInput)).fastCoerceIn(0f, 1f)
+    private fun lastFrameFractionOfPosition(
+        position: Float,
+        lastInput: Float,
+        input: Float,
+    ): Float {
+        return ((position - lastInput) / (input - lastInput)).fastCoerceIn(0f, 1f)
     }
 
     /**
-     * The [GuaranteeState] for [currentSegment].
+     * The [GuaranteeState] for [segment].
      *
      * Without a segment change, this carries forward [lastGuaranteeState], adjusted to the new
      * input if needed.
      *
-     * If a segment change happened, this is a new [GuaranteeState] for the [currentSegment]. Any
-     * remaining [lastGuaranteeState] will be consumed in [currentAnimation].
+     * If a segment change happened, this is a new [GuaranteeState] for the [segment]. Any remaining
+     * [LastFrameState.lastGuaranteeState] will be consumed in [currentAnimation].
      */
-    fun computeCurrentGuaranteeState(): GuaranteeState {
-        val currentSegment = currentSegment
-        val entryBreakpoint = currentSegment.entryBreakpoint
+    private fun computeGuaranteeState(
+        segment: SegmentData,
+        segmentChange: SegmentChangeType,
+        input: Float,
+    ): GuaranteeState {
+        val entryBreakpoint = segment.entryBreakpoint
 
         // First, determine the origin of the guarantee computations
         val guaranteeOriginState =
-            when (segmentChangeType) {
+            when (segmentChange) {
                 // Still in the segment, the origin is carried over from the last frame
                 SegmentChangeType.Same -> lastGuaranteeState
                 // The direction changed within the same segment, no guarantee to enforce.
@@ -139,7 +290,7 @@ internal interface ComputeGuaranteeState : ComputeSegment {
                     // directionChangeSlop, the guarantee starts at the current input.
                     GuaranteeState.withStartValue(
                         when (entryBreakpoint.guarantee) {
-                            is Guarantee.InputDelta -> currentInput
+                            is Guarantee.InputDelta -> input
                             is Guarantee.GestureDragDelta -> currentGestureDragOffset
                             is Guarantee.None -> return GuaranteeState.Inactive
                         }
@@ -157,7 +308,11 @@ internal interface ComputeGuaranteeState : ComputeSegment {
                                 // is sampled, interpolate it according to when the breakpoint was
                                 // crossed in the last frame.
                                 val fractionalBreakpointPos =
-                                    lastFrameFractionOfPosition(entryBreakpoint.position)
+                                    lastFrameFractionOfPosition(
+                                        entryBreakpoint.position,
+                                        lastInput,
+                                        input,
+                                    )
 
                                 lerp(
                                     lastGestureDragOffset,
@@ -176,49 +331,43 @@ internal interface ComputeGuaranteeState : ComputeSegment {
         // Finally, update the origin state with the current guarantee value.
         return guaranteeOriginState.withCurrentValue(
             when (entryBreakpoint.guarantee) {
-                is Guarantee.InputDelta -> currentInput
+                is Guarantee.InputDelta -> input
                 is Guarantee.GestureDragDelta -> currentGestureDragOffset
                 is Guarantee.None -> return GuaranteeState.Inactive
             },
-            currentSegment.direction,
+            segment.direction,
         )
     }
-}
-
-internal interface ComputeAnimation : ComputeGuaranteeState {
-    val currentGuaranteeState: GuaranteeState
 
     /**
      * The [DiscontinuityAnimation] in effect for the current frame.
      *
      * This describes the starting condition of the spring animation, and is only updated if the
      * spring animation must restarted: that is, if yet another discontinuity must be animated as a
-     * result of a segment change, or if the [currentGuaranteeState] requires the spring to be
-     * tightened.
+     * result of a segment change, or if the [guarantee] requires the spring to be tightened.
      *
      * See [currentSpringState] for the continuously updated, animated spring values.
      */
-    fun computeCurrentAnimation(): DiscontinuityAnimation {
-        val currentSegment = currentSegment
-        val lastSegment = lastSegment
-        val currentSpec = spec
-        val currentInput = currentInput
-        val lastAnimation = lastAnimation
-
-        return when (segmentChangeType) {
+    private fun computeAnimation(
+        segment: SegmentData,
+        guarantee: GuaranteeState,
+        segmentChange: SegmentChangeType,
+        spec: MotionSpec,
+        input: Float,
+        animationTimeNanos: Long,
+    ): DiscontinuityAnimation {
+        return when (segmentChange) {
             SegmentChangeType.Same -> {
-                if (lastAnimation.isAtRest) {
+                if (lastSpringState == SpringState.AtRest) {
                     // Nothing to update if no animation is ongoing
-                    lastAnimation
-                } else if (lastGuaranteeState == currentGuaranteeState) {
+                    DiscontinuityAnimation.None
+                } else if (lastGuaranteeState == guarantee) {
                     // Nothing to update if the spring must not be tightened.
                     lastAnimation
                 } else {
                     // Compute the updated spring parameters
                     val tightenedSpringParameters =
-                        currentGuaranteeState.updatedSpringParameters(
-                            currentSegment.entryBreakpoint
-                        )
+                        guarantee.updatedSpringParameters(segment.entryBreakpoint)
 
                     lastAnimation.copy(
                         springStartState = lastSpringState,
@@ -232,8 +381,8 @@ internal interface ComputeAnimation : ComputeGuaranteeState {
             SegmentChangeType.Direction,
             SegmentChangeType.Spec -> {
                 // Determine the delta in the output, as produced by the old and new mapping.
-                val currentMapping = currentSegment.mapping.map(currentInput)
-                val lastMapping = lastSegment.mapping.map(currentInput)
+                val currentMapping = segment.mapping.map(input)
+                val lastMapping = lastSegment.mapping.map(input)
                 val delta = currentMapping - lastMapping
 
                 val deltaIsFinite = delta.fastIsFinite()
@@ -242,9 +391,9 @@ internal interface ComputeAnimation : ComputeGuaranteeState {
                         TAG,
                         "Delta between mappings is undefined!\n" +
                             "  MotionValue: $label\n" +
-                            "  input: $currentInput\n" +
+                            "  input: $input\n" +
                             "  lastMapping: $lastMapping (lastSegment: $lastSegment)\n" +
-                            "  currentMapping: $currentMapping (currentSegment: $currentSegment)",
+                            "  currentMapping: $currentMapping (currentSegment: $segment)",
                     )
                 }
 
@@ -253,15 +402,14 @@ internal interface ComputeAnimation : ComputeGuaranteeState {
                     lastAnimation
                 } else {
                     val springParameters =
-                        if (segmentChangeType == SegmentChangeType.Direction) {
-                            currentSegment.entryBreakpoint.spring
+                        if (segmentChange == SegmentChangeType.Direction) {
+                            segment.entryBreakpoint.spring
                         } else {
-                            currentSpec.resetSpring
+                            spec.resetSpring
                         }
 
                     val newTarget = delta - lastSpringState.displacement
                     DiscontinuityAnimation(
-                        newTarget,
                         SpringState(-newTarget, lastSpringState.velocity + directMappedVelocity),
                         springParameters,
                         lastFrameTimeNanos,
@@ -273,10 +421,10 @@ internal interface ComputeAnimation : ComputeGuaranteeState {
                 // Process all breakpoints traversed, in order.
                 // This is involved due to the guarantees - they have to be applied, one after the
                 // other, before crossing the next breakpoint.
-                val currentDirection = currentSegment.direction
+                val currentDirection = segment.direction
 
-                with(currentSpec[currentDirection]) {
-                    val targetIndex = findSegmentIndex(currentSegment.key)
+                with(spec[currentDirection]) {
+                    val targetIndex = findSegmentIndex(segment.key)
                     val sourceIndex = findSegmentIndex(lastSegment.key)
                     check(targetIndex != sourceIndex)
 
@@ -286,8 +434,8 @@ internal interface ComputeAnimation : ComputeGuaranteeState {
                     var lastAnimationTime = lastFrameTimeNanos
                     var guaranteeState = lastGuaranteeState
                     var springState = lastSpringState
-                    var springTarget = lastAnimation.targetValue
                     var springParameters = lastAnimation.springParameters
+                    var initialSpringVelocity = directMappedVelocity
 
                     var segmentIndex = sourceIndex
                     while (segmentIndex != targetIndex) {
@@ -295,12 +443,12 @@ internal interface ComputeAnimation : ComputeGuaranteeState {
                             breakpoints[segmentIndex + directionOffset.fastCoerceAtLeast(0)]
 
                         val nextBreakpointFrameFraction =
-                            lastFrameFractionOfPosition(nextBreakpoint.position)
+                            lastFrameFractionOfPosition(nextBreakpoint.position, lastInput, input)
 
                         val nextBreakpointCrossTime =
                             lerp(
                                 lastFrameTimeNanos,
-                                currentAnimationTimeNanos,
+                                animationTimeNanos,
                                 nextBreakpointFrameFraction,
                             )
                         if (
@@ -347,21 +495,38 @@ internal interface ComputeAnimation : ComputeGuaranteeState {
 
                         val delta = afterBreakpoint - beforeBreakpoint
                         val deltaIsFinite = delta.fastIsFinite()
-                        if (!deltaIsFinite) {
+                        if (deltaIsFinite) {
+                            if (delta != 0f) {
+                                // There is a discontinuity on this breakpoint, that needs to be
+                                // animated. The delta is pushed to the spring, to consume the
+                                // discontinuity over time.
+                                springState =
+                                    springState.nudge(
+                                        displacementDelta = -delta,
+                                        velocityDelta = initialSpringVelocity,
+                                    )
+
+                                // When *first* crossing a discontinuity in a given frame, the
+                                // static mapped velocity observed during previous frame is added as
+                                // initial velocity to the spring. This is done ot most once per
+                                // frame, and only if there is an actual discontinuity.
+                                initialSpringVelocity = 0f
+                            }
+                        } else {
+                            // The before and / or after mapping produced an non-finite number,
+                            // which is not allowed. This intentionally crashes eng-builds, since
+                            // it's a bug in the Mapping implementation that must be fixed. On
+                            // regular builds, it will likely cause a jumpcut.
                             Log.wtf(
                                 TAG,
                                 "Delta between breakpoints is undefined!\n" +
-                                    "  MotionValue: $label\n" +
+                                    "  MotionValue: ${label}\n" +
                                     "  position: ${nextBreakpoint.position}\n" +
                                     "  before: $beforeBreakpoint (mapping: $mappingBefore)\n" +
                                     "  after: $afterBreakpoint (mapping: $mappingAfter)",
                             )
                         }
 
-                        if (deltaIsFinite) {
-                            springTarget += delta
-                            springState = springState.nudge(displacementDelta = -delta)
-                        }
                         segmentIndex += directionOffset
                         lastBreakpoint = nextBreakpoint
                         guaranteeState =
@@ -382,30 +547,22 @@ internal interface ComputeAnimation : ComputeGuaranteeState {
                             }
                     }
 
-                    if (springState.displacement != 0f) {
-                        springState = springState.nudge(velocityDelta = directMappedVelocity)
-                    }
-
-                    val tightened =
-                        currentGuaranteeState.updatedSpringParameters(
-                            currentSegment.entryBreakpoint
-                        )
+                    val tightened = guarantee.updatedSpringParameters(segment.entryBreakpoint)
 
-                    DiscontinuityAnimation(springTarget, springState, tightened, lastAnimationTime)
+                    DiscontinuityAnimation(springState, tightened, lastAnimationTime)
                 }
             }
         }
     }
-}
 
-internal interface ComputeSpringState : ComputeAnimation {
-    val currentAnimation: DiscontinuityAnimation
-
-    fun computeCurrentSpringState(): SpringState {
-        with(currentAnimation) {
+    private fun computeSpringState(
+        animation: DiscontinuityAnimation,
+        timeNanos: Long,
+    ): SpringState {
+        with(animation) {
             if (isAtRest) return SpringState.AtRest
 
-            val nanosSinceAnimationStart = currentAnimationTimeNanos - springStartTimeNanos
+            val nanosSinceAnimationStart = timeNanos - springStartTimeNanos
             val updatedSpringState =
                 springStartState.calculateUpdatedState(nanosSinceAnimationStart, springParameters)
 
@@ -417,22 +574,3 @@ internal interface ComputeSpringState : ComputeAnimation {
         }
     }
 }
-
-internal interface Computations : ComputeSpringState {
-    val currentSpringState: SpringState
-
-    val currentDirectMapped: Float
-        get() = currentSegment.mapping.map(currentInput) - currentAnimation.targetValue
-
-    val currentAnimatedDelta: Float
-        get() = currentAnimation.targetValue + currentSpringState.displacement
-
-    val output: Float
-        get() = currentDirectMapped + currentAnimatedDelta
-
-    val outputTarget: Float
-        get() = currentDirectMapped + currentAnimation.targetValue
-
-    val isStable: Boolean
-        get() = currentSpringState == SpringState.AtRest
-}
diff --git a/mechanics/src/com/android/mechanics/impl/DiscontinuityAnimation.kt b/mechanics/src/com/android/mechanics/impl/DiscontinuityAnimation.kt
index 131aaa3..b0deb75 100644
--- a/mechanics/src/com/android/mechanics/impl/DiscontinuityAnimation.kt
+++ b/mechanics/src/com/android/mechanics/impl/DiscontinuityAnimation.kt
@@ -26,7 +26,6 @@ import com.android.mechanics.spring.SpringState
  * output values for the same input.
  */
 internal data class DiscontinuityAnimation(
-    val targetValue: Float,
     val springStartState: SpringState,
     val springParameters: SpringParameters,
     val springStartTimeNanos: Long,
@@ -37,7 +36,6 @@ internal data class DiscontinuityAnimation(
     companion object {
         val None =
             DiscontinuityAnimation(
-                targetValue = 0f,
                 springStartState = SpringState.AtRest,
                 springParameters = SpringParameters.Snap,
                 springStartTimeNanos = 0L,
diff --git a/mechanics/src/com/android/mechanics/spec/Breakpoint.kt b/mechanics/src/com/android/mechanics/spec/Breakpoint.kt
index 1ff5ad9..5ff18ed 100644
--- a/mechanics/src/com/android/mechanics/spec/Breakpoint.kt
+++ b/mechanics/src/com/android/mechanics/spec/Breakpoint.kt
@@ -16,6 +16,7 @@
 
 package com.android.mechanics.spec
 
+import androidx.compose.ui.util.fastIsFinite
 import com.android.mechanics.spring.SpringParameters
 
 /**
@@ -39,7 +40,13 @@ class BreakpointKey(val debugLabel: String? = null, val identity: Any = Object()
     }
 
     override fun toString(): String {
-        return if (debugLabel != null) "BreakpointKey(label=$debugLabel)" else "BreakpointKey()"
+        return "BreakpointKey(${debugLabel ?: ""}" +
+            "@${System.identityHashCode(identity).toString(16).padStart(8,'0')})"
+    }
+
+    internal companion object {
+        val MinLimit = BreakpointKey("built-in::min")
+        val MaxLimit = BreakpointKey("built-in::max")
     }
 }
 
@@ -65,11 +72,20 @@ data class Breakpoint(
     val spring: SpringParameters,
     val guarantee: Guarantee,
 ) : Comparable<Breakpoint> {
+
+    init {
+        when (key) {
+            BreakpointKey.MinLimit -> require(position == Float.NEGATIVE_INFINITY)
+            BreakpointKey.MaxLimit -> require(position == Float.POSITIVE_INFINITY)
+            else -> require(position.fastIsFinite())
+        }
+    }
+
     companion object {
         /** First breakpoint of each spec. */
         val minLimit =
             Breakpoint(
-                BreakpointKey("built-in::min"),
+                BreakpointKey.MinLimit,
                 Float.NEGATIVE_INFINITY,
                 SpringParameters.Snap,
                 Guarantee.None,
@@ -78,11 +94,24 @@ data class Breakpoint(
         /** Last breakpoint of each spec. */
         val maxLimit =
             Breakpoint(
-                BreakpointKey("built-in::max"),
+                BreakpointKey.MaxLimit,
                 Float.POSITIVE_INFINITY,
                 SpringParameters.Snap,
                 Guarantee.None,
             )
+
+        internal fun create(
+            breakpointKey: BreakpointKey,
+            breakpointPosition: Float,
+            springSpec: SpringParameters,
+            guarantee: Guarantee,
+        ): Breakpoint {
+            return when (breakpointKey) {
+                BreakpointKey.MinLimit -> minLimit
+                BreakpointKey.MaxLimit -> maxLimit
+                else -> Breakpoint(breakpointKey, breakpointPosition, springSpec, guarantee)
+            }
+        }
     }
 
     override fun compareTo(other: Breakpoint): Int {
diff --git a/mechanics/src/com/android/mechanics/spec/FluentSpecBuilder.kt b/mechanics/src/com/android/mechanics/spec/FluentSpecBuilder.kt
deleted file mode 100644
index 774d4b6..0000000
--- a/mechanics/src/com/android/mechanics/spec/FluentSpecBuilder.kt
+++ /dev/null
@@ -1,375 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.mechanics.spec
-
-import com.android.mechanics.spring.SpringParameters
-
-/**
- * Fluent builder for [DirectionalMotionSpec].
- *
- * This builder ensures correctness at compile-time, and simplifies the expression of the
- * input-to-output mapping.
- *
- * The [MotionSpec] is defined by specify interleaved [Mapping]s and [Breakpoint]s. [Breakpoint]s
- * must be specified in ascending order.
- *
- * NOTE: The returned fluent interfaces must only be used for chaining calls to build exactly one
- * [DirectionalMotionSpec], otherwise resulting behavior is undefined, since the builder is
- * internally mutated.
- *
- * @param defaultSpring spring to use for all breakpoints by default.
- * @param initialMapping the [Mapping] from [Breakpoint.minLimit] to the next [Breakpoint].
- * @see reverseBuilder to specify [Breakpoint]s in descending order.
- */
-fun DirectionalMotionSpec.Companion.builder(
-    defaultSpring: SpringParameters,
-    initialMapping: Mapping = Mapping.Identity,
-): FluentSpecEndSegmentWithNextBreakpoint<DirectionalMotionSpec> {
-    return FluentSpecBuilder(defaultSpring, InputDirection.Max) { it }
-        .apply { mappings.add(initialMapping) }
-}
-
-/**
- * Fluent builder for [DirectionalMotionSpec], specifying breakpoints and mappings in reverse order.
- *
- * Variant of [DirectionalMotionSpec.Companion.builder], where [Breakpoint]s must be specified in
- * *descending* order. The resulting [DirectionalMotionSpec] will contain the breakpoints in
- * ascending order.
- *
- * @param defaultSpring spring to use for all breakpoints by default.
- * @param initialMapping the [Mapping] from [Breakpoint.maxLimit] to the next [Breakpoint].
- * @see DirectionalMotionSpec.Companion.builder for more documentation.
- */
-fun DirectionalMotionSpec.Companion.reverseBuilder(
-    defaultSpring: SpringParameters,
-    initialMapping: Mapping = Mapping.Identity,
-): FluentSpecEndSegmentWithNextBreakpoint<DirectionalMotionSpec> {
-    return FluentSpecBuilder(defaultSpring, InputDirection.Min) { it }
-        .apply { mappings.add(initialMapping) }
-}
-
-/**
- * Fluent builder for a [MotionSpec], which uses the same spec in both directions.
- *
- * @param defaultSpring spring to use for all breakpoints by default.
- * @param initialMapping [Mapping] for the first segment
- * @param resetSpring the [MotionSpec.resetSpring].
- */
-fun MotionSpec.Companion.builder(
-    defaultSpring: SpringParameters,
-    initialMapping: Mapping = Mapping.Identity,
-    resetSpring: SpringParameters = defaultSpring,
-): FluentSpecEndSegmentWithNextBreakpoint<MotionSpec> {
-    return FluentSpecBuilder(defaultSpring, InputDirection.Max) {
-            MotionSpec(it, resetSpring = resetSpring)
-        }
-        .apply { mappings.add(initialMapping) }
-}
-
-/** Fluent-interface to end the current segment, by placing the next [Breakpoint]. */
-interface FluentSpecEndSegmentWithNextBreakpoint<R> {
-    /**
-     * Adds a new [Breakpoint] at the specified position.
-     *
-     * @param atPosition The position of the breakpoint, in the input domain of the [MotionValue].
-     * @param key identifies the breakpoint in the [DirectionalMotionSpec]. Must be specified to
-     *   reference the breakpoint or segment.
-     */
-    fun toBreakpoint(
-        atPosition: Float,
-        key: BreakpointKey = BreakpointKey(),
-    ): FluentSpecDefineBreakpointAndStartNextSegment<R>
-
-    /** Completes the spec by placing the last, implicit [Breakpoint]. */
-    fun complete(): R
-}
-
-/** Fluent-interface to define the [Breakpoint]'s properties and start to start the next segment. */
-interface FluentSpecDefineBreakpointAndStartNextSegment<R> {
-    /**
-     * Default spring parameters for breakpoint, as specified at creation time of the builder.
-     *
-     * Used as the default `spring` parameters.
-     */
-    val defaultSpring: SpringParameters
-
-    /**
-     * Starts the next segment, using the specified mapping.
-     *
-     * @param mapping the mapping to use for the next segment.
-     * @param spring the spring to animate this breakpoints discontinuity.
-     * @param guarantee a guarantee by when the animation must be complete
-     */
-    fun continueWith(
-        mapping: Mapping,
-        spring: SpringParameters = defaultSpring,
-        guarantee: Guarantee = Guarantee.None,
-    ): FluentSpecEndSegmentWithNextBreakpoint<R>
-
-    /**
-     * Starts the next linear-mapped segment, by specifying the output [value] this breakpoint.
-     *
-     * @param value the output value the new mapping will produce at this breakpoints position.
-     * @param spring the spring to animate this breakpoints discontinuity.
-     * @param guarantee a guarantee by when the animation must be complete
-     */
-    fun jumpTo(
-        value: Float,
-        spring: SpringParameters = defaultSpring,
-        guarantee: Guarantee = Guarantee.None,
-    ): FluentSpecDefineLinearSegmentMapping<R>
-
-    /**
-     * Starts the next linear-mapped segment, by offsetting the output by [delta] from the incoming
-     * mapping.
-     *
-     * @param delta the delta in output from the previous mapping's output.
-     * @param spring the spring to animate this breakpoints discontinuity.
-     * @param guarantee a guarantee by when the animation must be complete
-     */
-    fun jumpBy(
-        delta: Float,
-        spring: SpringParameters = defaultSpring,
-        guarantee: Guarantee = Guarantee.None,
-    ): FluentSpecDefineLinearSegmentMapping<R>
-
-    /**
-     * Completes the spec by using [mapping] between the this and the implicit sentinel breakpoint
-     * at infinity.
-     *
-     * @param mapping the mapping to use for the final segment.
-     * @param spring the spring to animate this breakpoints discontinuity.
-     * @param guarantee a guarantee by when the animation must be complete
-     */
-    fun completeWith(
-        mapping: Mapping,
-        spring: SpringParameters = defaultSpring,
-        guarantee: Guarantee = Guarantee.None,
-    ): R
-}
-
-/** Fluent-interface to define a linear mapping between two breakpoints. */
-interface FluentSpecDefineLinearSegmentMapping<R> {
-    /**
-     * The linear-mapping will produce the specified [target] output at the next breakpoint
-     * position.
-     *
-     * @param target the output value the new mapping will produce at the next breakpoint position.
-     */
-    fun continueWithTargetValue(target: Float): FluentSpecEndSegmentWithNextBreakpoint<R>
-
-    /**
-     * Defines the slope for the linear mapping, as a fraction of the input value.
-     *
-     * @param fraction the multiplier applied to the input value..
-     */
-    fun continueWithFractionalInput(fraction: Float): FluentSpecEndSegmentWithNextBreakpoint<R>
-
-    /**
-     * The linear-mapping will produce a constant value, as defined at the source breakpoint of this
-     * segment.
-     */
-    fun continueWithConstantValue(): FluentSpecEndSegmentWithNextBreakpoint<R>
-}
-
-/** Implements the fluent spec builder logic. */
-private class FluentSpecBuilder<R>(
-    override val defaultSpring: SpringParameters,
-    buildDirection: InputDirection = InputDirection.Max,
-    private val toResult: (DirectionalMotionSpec) -> R,
-) :
-    FluentSpecDefineLinearSegmentMapping<R>,
-    FluentSpecDefineBreakpointAndStartNextSegment<R>,
-    FluentSpecEndSegmentWithNextBreakpoint<R> {
-    private val buildForward = buildDirection == InputDirection.Max
-
-    val breakpoints = mutableListOf<Breakpoint>()
-    val mappings = mutableListOf<Mapping>()
-
-    var sourceValue: Float = Float.NaN
-    var targetValue: Float = Float.NaN
-    var fractionalMapping: Float = Float.NaN
-    var breakpointPosition: Float = Float.NaN
-    var breakpointKey: BreakpointKey? = null
-
-    init {
-        val initialBreakpoint = if (buildForward) Breakpoint.minLimit else Breakpoint.maxLimit
-        breakpoints.add(initialBreakpoint)
-    }
-
-    //  FluentSpecDefineLinearSegmentMapping
-
-    override fun continueWithTargetValue(target: Float): FluentSpecEndSegmentWithNextBreakpoint<R> {
-        check(sourceValue.isFinite())
-
-        // memoize for FluentSpecEndSegmentWithNextBreakpoint
-        targetValue = target
-
-        return this
-    }
-
-    override fun continueWithFractionalInput(
-        fraction: Float
-    ): FluentSpecEndSegmentWithNextBreakpoint<R> {
-        check(sourceValue.isFinite())
-
-        // memoize for FluentSpecEndSegmentWithNextBreakpoint
-        fractionalMapping = fraction
-
-        return this
-    }
-
-    override fun continueWithConstantValue(): FluentSpecEndSegmentWithNextBreakpoint<R> {
-        check(sourceValue.isFinite())
-
-        mappings.add(Mapping.Fixed(sourceValue))
-
-        sourceValue = Float.NaN
-        return this
-    }
-
-    // FluentSpecDefineBreakpointAndStartNextSegment implementation
-
-    override fun jumpTo(
-        value: Float,
-        spring: SpringParameters,
-        guarantee: Guarantee,
-    ): FluentSpecDefineLinearSegmentMapping<R> {
-        check(sourceValue.isNaN())
-
-        doAddBreakpoint(spring, guarantee)
-        sourceValue = value
-
-        return this
-    }
-
-    override fun jumpBy(
-        delta: Float,
-        spring: SpringParameters,
-        guarantee: Guarantee,
-    ): FluentSpecDefineLinearSegmentMapping<R> {
-        check(sourceValue.isNaN())
-
-        val breakpoint = doAddBreakpoint(spring, guarantee)
-        sourceValue = mappings.last().map(breakpoint.position) + delta
-
-        return this
-    }
-
-    override fun continueWith(
-        mapping: Mapping,
-        spring: SpringParameters,
-        guarantee: Guarantee,
-    ): FluentSpecEndSegmentWithNextBreakpoint<R> {
-        check(sourceValue.isNaN())
-
-        doAddBreakpoint(spring, guarantee)
-        mappings.add(mapping)
-
-        return this
-    }
-
-    override fun completeWith(mapping: Mapping, spring: SpringParameters, guarantee: Guarantee): R {
-        check(sourceValue.isNaN())
-
-        doAddBreakpoint(spring, guarantee)
-        mappings.add(mapping)
-
-        return complete()
-    }
-
-    // FluentSpecEndSegmentWithNextBreakpoint implementation
-
-    override fun toBreakpoint(
-        atPosition: Float,
-        key: BreakpointKey,
-    ): FluentSpecDefineBreakpointAndStartNextSegment<R> {
-        check(breakpointPosition.isNaN())
-        check(breakpointKey == null)
-
-        if (!targetValue.isNaN() || !fractionalMapping.isNaN()) {
-            check(!sourceValue.isNaN())
-
-            val sourcePosition = breakpoints.last().position
-            val breakpointDistance = atPosition - sourcePosition
-            val mapping =
-                if (breakpointDistance == 0f) {
-                    Mapping.Fixed(sourceValue)
-                } else {
-                    if (fractionalMapping.isNaN()) {
-                        val delta = targetValue - sourceValue
-                        fractionalMapping = delta / breakpointDistance
-                    } else {
-                        val delta = breakpointDistance * fractionalMapping
-                        targetValue = sourceValue + delta
-                    }
-
-                    val offset =
-                        if (buildForward) sourceValue - (sourcePosition * fractionalMapping)
-                        else targetValue - (atPosition * fractionalMapping)
-                    Mapping.Linear(fractionalMapping, offset)
-                }
-
-            mappings.add(mapping)
-            targetValue = Float.NaN
-            sourceValue = Float.NaN
-            fractionalMapping = Float.NaN
-        }
-
-        breakpointPosition = atPosition
-        breakpointKey = key
-
-        return this
-    }
-
-    override fun complete(): R {
-        check(targetValue.isNaN()) { "cant specify target value for last segment" }
-
-        if (!fractionalMapping.isNaN()) {
-            check(!sourceValue.isNaN())
-
-            val sourcePosition = breakpoints.last().position
-
-            mappings.add(
-                Mapping.Linear(
-                    fractionalMapping,
-                    sourceValue - (sourcePosition * fractionalMapping),
-                )
-            )
-        }
-
-        if (buildForward) {
-            breakpoints.add(Breakpoint.maxLimit)
-        } else {
-            breakpoints.add(Breakpoint.minLimit)
-            breakpoints.reverse()
-            mappings.reverse()
-        }
-
-        return toResult(DirectionalMotionSpec(breakpoints.toList(), mappings.toList()))
-    }
-
-    private fun doAddBreakpoint(springSpec: SpringParameters, guarantee: Guarantee): Breakpoint {
-        check(breakpointPosition.isFinite())
-        return Breakpoint(checkNotNull(breakpointKey), breakpointPosition, springSpec, guarantee)
-            .also {
-                breakpoints.add(it)
-                breakpointPosition = Float.NaN
-                breakpointKey = null
-            }
-    }
-}
diff --git a/mechanics/src/com/android/mechanics/spec/MotionSpec.kt b/mechanics/src/com/android/mechanics/spec/MotionSpec.kt
index 4bd4240..4628804 100644
--- a/mechanics/src/com/android/mechanics/spec/MotionSpec.kt
+++ b/mechanics/src/com/android/mechanics/spec/MotionSpec.kt
@@ -16,27 +16,9 @@
 
 package com.android.mechanics.spec
 
+import androidx.compose.ui.util.fastFirstOrNull
 import com.android.mechanics.spring.SpringParameters
 
-/**
- * Handler to allow for custom segment-change logic.
- *
- * This handler is called whenever the new input (position or direction) does not match
- * [currentSegment] anymore (see [SegmentData.isValidForInput]).
- *
- * This is intended to implement custom effects on direction-change.
- *
- * Implementations can return:
- * 1. [currentSegment] to delay/suppress segment change.
- * 2. `null` to use the default segment lookup based on [newPosition] and [newDirection]
- * 3. manually looking up segments on this [MotionSpec]
- * 4. create a [SegmentData] that is not in the spec.
- */
-typealias OnChangeSegmentHandler =
-    MotionSpec.(
-        currentSegment: SegmentData, newPosition: Float, newDirection: InputDirection,
-    ) -> SegmentData?
-
 /**
  * Specification for the mapping of input values to output values.
  *
@@ -70,6 +52,37 @@ data class MotionSpec(
         return get(segmentKey.direction).findSegmentIndex(segmentKey) != -1
     }
 
+    /**
+     * The semantic state for [key] at segment with [segmentKey].
+     *
+     * Returns `null` if no semantic value with [key] is defined. Throws [NoSuchElementException] if
+     * [segmentKey] does not exist in this [MotionSpec].
+     */
+    fun <T> semanticState(key: SemanticKey<T>, segmentKey: SegmentKey): T? {
+        with(get(segmentKey.direction)) {
+            val semanticValues = semantics.fastFirstOrNull { it.key == key } ?: return null
+            val segmentIndex = findSegmentIndex(segmentKey)
+            if (segmentIndex < 0) throw NoSuchElementException()
+
+            @Suppress("UNCHECKED_CAST")
+            return semanticValues.values[segmentIndex] as T
+        }
+    }
+
+    /**
+     * All [SemanticValue]s associated with the segment identified with [segmentKey].
+     *
+     * Throws [NoSuchElementException] if [segmentKey] does not exist in this [MotionSpec].
+     */
+    fun semantics(segmentKey: SegmentKey): List<SemanticValue<*>> {
+        with(get(segmentKey.direction)) {
+            val segmentIndex = findSegmentIndex(segmentKey)
+            if (segmentIndex < 0) throw NoSuchElementException()
+
+            return semantics.map { it[segmentIndex] }
+        }
+    }
+
     /**
      * The [SegmentData] for an input with the specified [position] and [direction].
      *
@@ -113,6 +126,8 @@ data class MotionSpec(
             ?: segmentAtInput(newPosition, newDirection)
     }
 
+    override fun toString() = toDebugString()
+
     companion object {
         /**
          * Default spring parameters for the reset spring. Matches the Fast Spatial spring of the
@@ -139,8 +154,17 @@ data class MotionSpec(
  *   element, and [Breakpoint.maxLimit] as the last element.
  * @param mappings All mappings in between the breakpoints, thus must always contain
  *   `breakpoints.size - 1` elements.
+ * @param semantics semantics provided by this spec, must only reference to breakpoint keys included
+ *   in [breakpoints].
  */
-data class DirectionalMotionSpec(val breakpoints: List<Breakpoint>, val mappings: List<Mapping>) {
+data class DirectionalMotionSpec(
+    val breakpoints: List<Breakpoint>,
+    val mappings: List<Mapping>,
+    val semantics: List<SegmentSemanticValues<*>> = emptyList(),
+) {
+    /** Maps all [BreakpointKey]s used in this spec to its index in [breakpoints]. */
+    private val breakpointIndexByKey: Map<BreakpointKey, Int>
+
     init {
         require(breakpoints.size >= 2)
         require(breakpoints.first() == Breakpoint.minLimit)
@@ -149,6 +173,15 @@ data class DirectionalMotionSpec(val breakpoints: List<Breakpoint>, val mappings
             "Breakpoints are not sorted ascending ${breakpoints.map { "${it.key}@${it.position}" }}"
         }
         require(mappings.size == breakpoints.size - 1)
+
+        breakpointIndexByKey =
+            breakpoints.mapIndexed { index, breakpoint -> breakpoint.key to index }.toMap()
+
+        semantics.forEach {
+            require(it.values.size == mappings.size) {
+                "Semantics ${it.key} contains ${it.values.size} values vs ${mappings.size} expected"
+            }
+        }
     }
 
     /**
@@ -182,17 +215,19 @@ data class DirectionalMotionSpec(val breakpoints: List<Breakpoint>, val mappings
      * exists.
      */
     fun findBreakpointIndex(breakpointKey: BreakpointKey): Int {
-        return breakpoints.indexOfFirst { it.key == breakpointKey }
+        return breakpointIndexByKey[breakpointKey] ?: -1
     }
 
     /** Index into [mappings] for the specified [segmentKey], or `-1` if no such segment exists. */
     fun findSegmentIndex(segmentKey: SegmentKey): Int {
-        val result = breakpoints.indexOfFirst { it.key == segmentKey.minBreakpoint }
-        if (result < 0 || breakpoints[result + 1].key != segmentKey.maxBreakpoint) return -1
+        val result = breakpointIndexByKey[segmentKey.minBreakpoint] ?: return -1
+        if (breakpoints[result + 1].key != segmentKey.maxBreakpoint) return -1
 
         return result
     }
 
+    override fun toString() = toDebugString()
+
     companion object {
         /* Empty spec, the full input domain is mapped to output using [Mapping.identity]. */
         val Empty =
diff --git a/mechanics/src/com/android/mechanics/spec/MotionSpecDebugFormatter.kt b/mechanics/src/com/android/mechanics/spec/MotionSpecDebugFormatter.kt
new file mode 100644
index 0000000..9c7f9bd
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/MotionSpecDebugFormatter.kt
@@ -0,0 +1,121 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec
+
+/** Returns a string representation of the [MotionSpec] for debugging by humans. */
+fun MotionSpec.toDebugString(): String {
+    return buildString {
+            if (minDirection == maxDirection) {
+                appendLine("unidirectional:")
+                appendLine(minDirection.toDebugString().prependIndent("  "))
+            } else {
+                appendLine("maxDirection:")
+                appendLine(maxDirection.toDebugString().prependIndent("  "))
+                appendLine("minDirection:")
+                appendLine(minDirection.toDebugString().prependIndent("  "))
+            }
+
+            if (segmentHandlers.isNotEmpty()) {
+                appendLine("segmentHandlers:")
+                segmentHandlers.keys.forEach {
+                    appendIndent(2)
+                    appendSegmentKey(it)
+                    appendLine()
+                }
+            }
+        }
+        .trim()
+}
+
+/** Returns a string representation of the [DirectionalMotionSpec] for debugging by humans. */
+fun DirectionalMotionSpec.toDebugString(): String {
+    return buildString {
+            appendBreakpointLine(breakpoints.first())
+            for (i in mappings.indices) {
+                appendMappingLine(mappings[i], indent = 2)
+                semantics.forEach { appendSemanticsLine(it.key, it.values[i], indent = 4) }
+                appendBreakpointLine(breakpoints[i + 1])
+            }
+        }
+        .trim()
+}
+
+private fun StringBuilder.appendIndent(indent: Int) {
+    repeat(indent) { append(' ') }
+}
+
+private fun StringBuilder.appendBreakpointLine(breakpoint: Breakpoint, indent: Int = 0) {
+    appendIndent(indent)
+    append("@")
+    append(breakpoint.position)
+
+    append(" [")
+    appendBreakpointKey(breakpoint.key)
+    append("]")
+
+    if (breakpoint.guarantee != Guarantee.None) {
+        append(" guarantee=")
+        append(breakpoint.key.debugLabel)
+    }
+
+    if (!breakpoint.spring.isSnapSpring) {
+        append(" spring=")
+        append(breakpoint.spring.stiffness)
+        append("/")
+        append(breakpoint.spring.dampingRatio)
+    }
+
+    appendLine()
+}
+
+private fun StringBuilder.appendBreakpointKey(key: BreakpointKey) {
+    if (key.debugLabel != null) {
+        append(key.debugLabel)
+        append("|")
+    }
+    append("id:0x")
+    append(System.identityHashCode(key.identity).toString(16).padStart(8, '0'))
+}
+
+private fun StringBuilder.appendSegmentKey(key: SegmentKey) {
+    appendBreakpointKey(key.minBreakpoint)
+    if (key.direction == InputDirection.Min) append(" << ") else append(" >> ")
+    appendBreakpointKey(key.maxBreakpoint)
+}
+
+private fun StringBuilder.appendMappingLine(mapping: Mapping, indent: Int = 0) {
+    appendIndent(indent)
+    append(mapping.toString())
+    appendLine()
+}
+
+private fun StringBuilder.appendSemanticsLine(
+    semanticKey: SemanticKey<*>,
+    value: Any?,
+    indent: Int = 0,
+) {
+    appendIndent(indent)
+
+    append(semanticKey.debugLabel)
+    append("[id:0x")
+    append(System.identityHashCode(semanticKey.identity).toString(16).padStart(8, '0'))
+    append("]")
+
+    append("=")
+    append(value)
+    appendLine()
+}
diff --git a/mechanics/src/com/android/mechanics/spec/Segment.kt b/mechanics/src/com/android/mechanics/spec/Segment.kt
index d3e95ad..d3bce7b 100644
--- a/mechanics/src/com/android/mechanics/spec/Segment.kt
+++ b/mechanics/src/com/android/mechanics/spec/Segment.kt
@@ -28,7 +28,11 @@ data class SegmentKey(
     val minBreakpoint: BreakpointKey,
     val maxBreakpoint: BreakpointKey,
     val direction: InputDirection,
-)
+) {
+    override fun toString(): String {
+        return "SegmentKey(min=$minBreakpoint, max=$maxBreakpoint, direction=$direction)"
+    }
+}
 
 /**
  * Captures denormalized segment data from a [MotionSpec].
@@ -75,6 +79,18 @@ data class SegmentData(
                 InputDirection.Max -> minBreakpoint
                 InputDirection.Min -> maxBreakpoint
             }
+
+    /** Semantic value for the given [semanticKey]. */
+    fun <T> semantic(semanticKey: SemanticKey<T>): T? {
+        return spec.semanticState(semanticKey, key)
+    }
+
+    val range: ClosedFloatingPointRange<Float>
+        get() = minBreakpoint.position..maxBreakpoint.position
+
+    override fun toString(): String {
+        return "SegmentData(key=$key, range=$range, mapping=$mapping)"
+    }
 }
 
 /**
@@ -91,6 +107,10 @@ fun interface Mapping {
         override fun map(input: Float): Float {
             return input
         }
+
+        override fun toString(): String {
+            return "Identity"
+        }
     }
 
     /** `f(x) = value` */
@@ -116,22 +136,20 @@ fun interface Mapping {
         }
     }
 
-    data class Tanh(val scaling: Float, val tilt: Float, val offset: Float = 0f) : Mapping {
-
-        init {
-            require(scaling.isFinite())
-            require(tilt.isFinite())
-            require(offset.isFinite())
-        }
-
-        override fun map(input: Float): Float {
-            return scaling * kotlin.math.tanh((input + offset) / (scaling * tilt))
-        }
-    }
-
     companion object {
         val Zero = Fixed(0f)
         val One = Fixed(1f)
         val Two = Fixed(2f)
+
+        /** Create a linear mapping defined as a line between {in0,out0} and {in1,out1}. */
+        fun Linear(in0: Float, out0: Float, in1: Float, out1: Float): Linear {
+            require(in0 != in1) {
+                "Cannot define a linear function with both inputs being the same ($in0)."
+            }
+
+            val factor = (out1 - out0) / (in1 - in0)
+            val offset = out0 - factor * in0
+            return Linear(factor, offset)
+        }
     }
 }
diff --git a/mechanics/src/com/android/mechanics/spec/SegmentChangeHandler.kt b/mechanics/src/com/android/mechanics/spec/SegmentChangeHandler.kt
new file mode 100644
index 0000000..b6ce6ab
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/SegmentChangeHandler.kt
@@ -0,0 +1,48 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec
+
+/**
+ * Handler to allow for custom segment-change logic.
+ *
+ * This handler is called whenever the new input (position or direction) does not match
+ * [currentSegment] anymore (see [SegmentData.isValidForInput]).
+ *
+ * This is intended to implement custom effects on direction-change.
+ *
+ * Implementations can return:
+ * 1. [currentSegment] to delay/suppress segment change.
+ * 2. `null` to use the default segment lookup based on [newPosition] and [newDirection]
+ * 3. manually looking up segments on this [MotionSpec]
+ * 4. create a [SegmentData] that is not in the spec.
+ */
+typealias OnChangeSegmentHandler =
+    MotionSpec.(
+        currentSegment: SegmentData, newPosition: Float, newDirection: InputDirection,
+    ) -> SegmentData?
+
+/** Generic change segment handlers. */
+object ChangeSegmentHandlers {
+    /** Prevents direction changes, as long as the input is still valid on the current segment. */
+    val PreventDirectionChangeWithinCurrentSegment: OnChangeSegmentHandler =
+        { currentSegment, newInput, newDirection ->
+            currentSegment.takeIf {
+                newDirection != currentSegment.direction &&
+                    it.isValidForInput(newInput, currentSegment.direction)
+            }
+        }
+}
diff --git a/mechanics/src/com/android/mechanics/spec/SemanticValue.kt b/mechanics/src/com/android/mechanics/spec/SemanticValue.kt
new file mode 100644
index 0000000..8adf61a
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/SemanticValue.kt
@@ -0,0 +1,74 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec
+
+/**
+ * Identifies a "semantic state" of a [MotionValue].
+ *
+ * Semantic states can be supplied by a [MotionSpec], and allows expose semantic information on the
+ * logical state a [MotionValue] is in.
+ */
+class SemanticKey<T>(val type: Class<T>, val debugLabel: String, val identity: Any = Object()) {
+    override fun equals(other: Any?): Boolean {
+        if (this === other) return true
+        if (javaClass != other?.javaClass) return false
+
+        other as SemanticKey<*>
+
+        return identity == other.identity
+    }
+
+    override fun hashCode(): Int {
+        return identity.hashCode()
+    }
+
+    override fun toString(): String {
+        return "Semantics($debugLabel)"
+    }
+}
+
+/** Creates a new semantic key of type [T], identified by [identity]. */
+inline fun <reified T> SemanticKey(
+    debugLabel: String = T::class.java.simpleName,
+    identity: Any = Object(),
+) = SemanticKey(T::class.java, debugLabel, identity)
+
+/** Pair of semantic [key] and [value]. */
+data class SemanticValue<T>(val key: SemanticKey<T>, val value: T)
+
+/**
+ * Creates a [SemanticValue] tuple from [SemanticKey] `this` with [value].
+ *
+ * This can be useful for creating [SemanticValue] literals with less noise.
+ */
+infix fun <T> SemanticKey<T>.with(value: T) = SemanticValue(this, value)
+
+/**
+ * Defines semantics values for [key], one per segment.
+ *
+ * This [values] are required to align with the segments of the [DirectionalMotionSpec] the instance
+ * will be passed to. The class has no particular value outside of a [DirectionalMotionSpec].
+ */
+class SegmentSemanticValues<T>(val key: SemanticKey<T>, val values: List<T>) {
+
+    /** Retrieves the [SemanticValue] at [segmentIndex]. */
+    operator fun get(segmentIndex: Int): SemanticValue<T> {
+        return SemanticValue(key, values[segmentIndex])
+    }
+
+    override fun toString() = "Semantics($key): [$values]"
+}
diff --git a/mechanics/src/com/android/mechanics/spec/builder/DirectionalBuilderImpl.kt b/mechanics/src/com/android/mechanics/spec/builder/DirectionalBuilderImpl.kt
new file mode 100644
index 0000000..994927f
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/builder/DirectionalBuilderImpl.kt
@@ -0,0 +1,388 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec.builder
+
+import com.android.mechanics.spec.Breakpoint
+import com.android.mechanics.spec.BreakpointKey
+import com.android.mechanics.spec.DirectionalMotionSpec
+import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.SegmentSemanticValues
+import com.android.mechanics.spec.SemanticKey
+import com.android.mechanics.spec.SemanticValue
+import com.android.mechanics.spring.SpringParameters
+
+/**
+ * Internal, reusable implementation of the [DirectionalBuilderScope].
+ *
+ * Clients must use [directionalMotionSpec] instead.
+ */
+internal open class DirectionalBuilderImpl(
+    override val defaultSpring: SpringParameters,
+    baseSemantics: List<SemanticValue<*>>,
+) : DirectionalBuilderScope {
+    internal val breakpoints = mutableListOf(Breakpoint.minLimit)
+    internal val semantics = mutableListOf<SegmentSemanticValuesBuilder<*>>()
+    internal val mappings = mutableListOf<Mapping>()
+    private var sourceValue: Float = Float.NaN
+    private var targetValue: Float = Float.NaN
+    private var fractionalMapping: Float = Float.NaN
+    private var breakpointPosition: Float = Float.NaN
+    private var breakpointKey: BreakpointKey? = null
+
+    init {
+        baseSemantics.forEach { getSemantics(it.key).apply { set(0, it.value) } }
+    }
+
+    /** Prepares the builder for invoking the [DirectionalBuilderFn] on it. */
+    fun prepareBuilderFn(
+        initialMapping: Mapping = Mapping.Identity,
+        initialSemantics: List<SemanticValue<*>> = emptyList(),
+    ) {
+        check(mappings.size == breakpoints.size - 1)
+
+        mappings.add(initialMapping)
+        val semanticIndex = mappings.size - 1
+        initialSemantics.forEach { semantic ->
+            getSemantics(semantic.key).apply { set(semanticIndex, semantic.value) }
+        }
+    }
+
+    internal fun <T> getSemantics(key: SemanticKey<T>): SegmentSemanticValuesBuilder<T> {
+        @Suppress("UNCHECKED_CAST")
+        var builder = semantics.firstOrNull { it.key == key } as SegmentSemanticValuesBuilder<T>?
+        if (builder == null) {
+            builder = SegmentSemanticValuesBuilder(key).also { semantics.add(it) }
+        }
+        return builder
+    }
+
+    /**
+     * Finalizes open segments, after invoking a [DirectionalBuilderFn].
+     *
+     * Afterwards, either [build] or another pair of {[prepareBuilderFn], [finalizeBuilderFn]} calls
+     * can be done.
+     */
+    fun finalizeBuilderFn(
+        atPosition: Float,
+        key: BreakpointKey,
+        springSpec: SpringParameters,
+        guarantee: Guarantee,
+        semantics: List<SemanticValue<*>>,
+    ) {
+        if (!(targetValue.isNaN() && fractionalMapping.isNaN())) {
+            // Finalizing will produce the mapping and breakpoint
+            check(mappings.size == breakpoints.size - 1)
+        } else {
+            // Mapping is already added, this will add the breakpoint
+            check(mappings.size == breakpoints.size)
+        }
+
+        if (key == BreakpointKey.MaxLimit) {
+            check(targetValue.isNaN()) { "cant specify target value for last segment" }
+            check(semantics.isEmpty()) { "cant specify semantics for last breakpoint" }
+        } else {
+            check(atPosition.isFinite())
+            check(atPosition > breakpoints.last().position) {
+                "Breakpoint ${breakpoints.last()} placed after partial sequence (end=$atPosition)"
+            }
+        }
+
+        toBreakpointImpl(atPosition, key, semantics)
+        doAddBreakpointImpl(springSpec, guarantee)
+    }
+
+    fun finalizeBuilderFn(breakpoint: Breakpoint) =
+        finalizeBuilderFn(
+            breakpoint.position,
+            breakpoint.key,
+            breakpoint.spring,
+            breakpoint.guarantee,
+            emptyList(),
+        )
+
+    /* Creates the [DirectionalMotionSpec] from the current builder state. */
+    fun build(): DirectionalMotionSpec {
+        require(mappings.size == breakpoints.size - 1)
+        check(breakpoints.last() == Breakpoint.maxLimit)
+
+        val segmentCount = mappings.size
+
+        val semantics = semantics.map { builder -> with(builder) { build(segmentCount) } }
+
+        return DirectionalMotionSpec(breakpoints.toList(), mappings.toList(), semantics)
+    }
+
+    override fun target(
+        breakpoint: Float,
+        from: Float,
+        to: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+        semantics: List<SemanticValue<*>>,
+    ) {
+        toBreakpointImpl(breakpoint, key, semantics)
+        jumpToImpl(from, spring, guarantee)
+        continueWithTargetValueImpl(to)
+    }
+
+    override fun targetFromCurrent(
+        breakpoint: Float,
+        to: Float,
+        delta: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+        semantics: List<SemanticValue<*>>,
+    ) {
+        toBreakpointImpl(breakpoint, key, semantics)
+        jumpByImpl(delta, spring, guarantee)
+        continueWithTargetValueImpl(to)
+    }
+
+    override fun fractionalInput(
+        breakpoint: Float,
+        from: Float,
+        fraction: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+        semantics: List<SemanticValue<*>>,
+    ): CanBeLastSegment {
+        toBreakpointImpl(breakpoint, key, semantics)
+        jumpToImpl(from, spring, guarantee)
+        continueWithFractionalInputImpl(fraction)
+        return CanBeLastSegmentImpl
+    }
+
+    override fun fractionalInputFromCurrent(
+        breakpoint: Float,
+        fraction: Float,
+        delta: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+        semantics: List<SemanticValue<*>>,
+    ): CanBeLastSegment {
+        toBreakpointImpl(breakpoint, key, semantics)
+        jumpByImpl(delta, spring, guarantee)
+        continueWithFractionalInputImpl(fraction)
+        return CanBeLastSegmentImpl
+    }
+
+    override fun fixedValue(
+        breakpoint: Float,
+        value: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+        semantics: List<SemanticValue<*>>,
+    ): CanBeLastSegment {
+        toBreakpointImpl(breakpoint, key, semantics)
+        jumpToImpl(value, spring, guarantee)
+        continueWithFixedValueImpl()
+        return CanBeLastSegmentImpl
+    }
+
+    override fun fixedValueFromCurrent(
+        breakpoint: Float,
+        delta: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+        semantics: List<SemanticValue<*>>,
+    ): CanBeLastSegment {
+        toBreakpointImpl(breakpoint, key, semantics)
+        jumpByImpl(delta, spring, guarantee)
+        continueWithFixedValueImpl()
+        return CanBeLastSegmentImpl
+    }
+
+    override fun mapping(
+        breakpoint: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+        semantics: List<SemanticValue<*>>,
+        mapping: Mapping,
+    ): CanBeLastSegment {
+        toBreakpointImpl(breakpoint, key, semantics)
+        continueWithImpl(mapping, spring, guarantee)
+        return CanBeLastSegmentImpl
+    }
+
+    private fun continueWithTargetValueImpl(target: Float) {
+        check(sourceValue.isFinite())
+
+        targetValue = target
+    }
+
+    private fun continueWithFractionalInputImpl(fraction: Float) {
+        check(sourceValue.isFinite())
+
+        fractionalMapping = fraction
+    }
+
+    private fun continueWithFixedValueImpl() {
+        check(sourceValue.isFinite())
+
+        mappings.add(Mapping.Fixed(sourceValue))
+        sourceValue = Float.NaN
+    }
+
+    private fun jumpToImpl(value: Float, spring: SpringParameters, guarantee: Guarantee) {
+        check(sourceValue.isNaN())
+
+        doAddBreakpointImpl(spring, guarantee)
+        sourceValue = value
+    }
+
+    private fun jumpByImpl(delta: Float, spring: SpringParameters, guarantee: Guarantee) {
+        check(sourceValue.isNaN())
+
+        val breakpoint = doAddBreakpointImpl(spring, guarantee)
+        sourceValue = mappings.last().map(breakpoint.position) + delta
+    }
+
+    private fun continueWithImpl(mapping: Mapping, spring: SpringParameters, guarantee: Guarantee) {
+        check(sourceValue.isNaN())
+
+        doAddBreakpointImpl(spring, guarantee)
+        mappings.add(mapping)
+    }
+
+    private fun toBreakpointImpl(
+        atPosition: Float,
+        key: BreakpointKey,
+        semantics: List<SemanticValue<*>>,
+    ) {
+        check(breakpointPosition.isNaN())
+        check(breakpointKey == null)
+
+        check(atPosition >= breakpoints.last().position) {
+            "Breakpoint position specified is before last breakpoint"
+        }
+
+        if (!targetValue.isNaN() || !fractionalMapping.isNaN()) {
+            check(!sourceValue.isNaN())
+
+            val sourcePosition = breakpoints.last().position
+            val breakpointDistance = atPosition - sourcePosition
+            val mapping =
+                if (breakpointDistance == 0f) {
+                    Mapping.Fixed(sourceValue)
+                } else {
+
+                    if (fractionalMapping.isNaN()) {
+                        val delta = targetValue - sourceValue
+                        fractionalMapping = delta / (atPosition - sourcePosition)
+                    } else {
+                        val delta = (atPosition - sourcePosition) * fractionalMapping
+                        targetValue = sourceValue + delta
+                    }
+
+                    val offset = sourceValue - (sourcePosition * fractionalMapping)
+                    Mapping.Linear(fractionalMapping, offset)
+                }
+
+            mappings.add(mapping)
+            targetValue = Float.NaN
+            sourceValue = Float.NaN
+            fractionalMapping = Float.NaN
+        }
+
+        breakpointPosition = atPosition
+        breakpointKey = key
+
+        semantics.forEach { (key, value) ->
+            getSemantics(key).apply {
+                // Last segment is guaranteed to be completed
+                set(mappings.size, value)
+            }
+        }
+    }
+
+    private fun doAddBreakpointImpl(
+        springSpec: SpringParameters,
+        guarantee: Guarantee,
+    ): Breakpoint {
+        val breakpoint =
+            Breakpoint.create(
+                checkNotNull(breakpointKey),
+                breakpointPosition,
+                springSpec,
+                guarantee,
+            )
+
+        breakpoints.add(breakpoint)
+        breakpointPosition = Float.NaN
+        breakpointKey = null
+
+        return breakpoint
+    }
+}
+
+internal class SegmentSemanticValuesBuilder<T>(val key: SemanticKey<T>) {
+    private val values = mutableListOf<SemanticValueHolder<T>>()
+    private val unspecified = SemanticValueHolder.Unspecified<T>()
+
+    @Suppress("UNCHECKED_CAST")
+    fun <V> set(segmentIndex: Int, value: V) {
+        if (segmentIndex < values.size) {
+            values[segmentIndex] = SemanticValueHolder.Specified(value as T)
+        } else {
+            backfill(segmentCount = segmentIndex)
+            values.add(SemanticValueHolder.Specified(value as T))
+        }
+    }
+
+    @Suppress("UNCHECKED_CAST")
+    fun <V> updateBefore(segmentIndex: Int, value: V) {
+        require(segmentIndex < values.size)
+
+        val specified = SemanticValueHolder.Specified(value as T)
+
+        for (i in segmentIndex downTo 0) {
+            if (values[i] is SemanticValueHolder.Specified) break
+            values[i] = specified
+        }
+    }
+
+    fun build(segmentCount: Int): SegmentSemanticValues<T> {
+        backfill(segmentCount)
+        val firstValue = values.firstNotNullOf { it as? SemanticValueHolder.Specified }.value
+        return SegmentSemanticValues(
+            key,
+            values.drop(1).runningFold(firstValue) { lastValue, thisHolder ->
+                if (thisHolder is SemanticValueHolder.Specified) thisHolder.value else lastValue
+            },
+        )
+    }
+
+    private fun backfill(segmentCount: Int) {
+        repeat(segmentCount - values.size) { values.add(unspecified) }
+    }
+}
+
+internal sealed interface SemanticValueHolder<T> {
+    class Specified<T>(val value: T) : SemanticValueHolder<T>
+
+    class Unspecified<T>() : SemanticValueHolder<T>
+}
+
+private data object CanBeLastSegmentImpl : CanBeLastSegment
diff --git a/mechanics/src/com/android/mechanics/spec/DirectionalMotionSpecBuilder.kt b/mechanics/src/com/android/mechanics/spec/builder/DirectionalBuilderScope.kt
similarity index 50%
rename from mechanics/src/com/android/mechanics/spec/DirectionalMotionSpecBuilder.kt
rename to mechanics/src/com/android/mechanics/spec/builder/DirectionalBuilderScope.kt
index 50df9fc..9eacd8f 100644
--- a/mechanics/src/com/android/mechanics/spec/DirectionalMotionSpecBuilder.kt
+++ b/mechanics/src/com/android/mechanics/spec/builder/DirectionalBuilderScope.kt
@@ -14,71 +14,25 @@
  * limitations under the License.
  */
 
-package com.android.mechanics.spec
-
+package com.android.mechanics.spec.builder
+
+import com.android.mechanics.spec.BreakpointKey
+import com.android.mechanics.spec.DirectionalMotionSpec
+import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.SemanticKey
+import com.android.mechanics.spec.SemanticValue
 import com.android.mechanics.spring.SpringParameters
 
-/**
- * Builds a [DirectionalMotionSpec] by defining a sequence of ([Breakpoint], [Mapping]) pairs.
- *
- * This function simplifies the creation of complex motion specifications. It allows you to define a
- * series of motion segments, each with its own behavior, separated by breakpoints. The breakpoints
- * and their corresponding segments will always be ordered from min to max value, regardless of how
- * the `DirectionalMotionSpec` is applied.
- *
- * Example Usage:
- * ```kotlin
- * val motionSpec = buildDirectionalMotionSpec(
- *     defaultSpring = materialSpatial,
- *
- *     // Start as a constant transition, always 0.
- *     initialMapping = Mapping.Zero
- * ) {
- *     // At breakpoint 10: Linear transition from 0 to 50.
- *     target(breakpoint = 10f, from = 0f, to = 50f)
- *
- *     // At breakpoint 20: Jump +5, and constant value 55.
- *     constantValueFromCurrent(breakpoint = 20f, delta = 5f)
- *
- *     // At breakpoint 30: Jump to 40. Linear mapping using: progress_since_breakpoint * fraction.
- *     fractionalInput(breakpoint = 30f, from = 40f, fraction = 2f)
- * }
- * ```
- *
- * @param defaultSpring The default [SpringParameters] to use for all breakpoints.
- * @param initialMapping The initial [Mapping] for the first segment (defaults to
- *   [Mapping.Identity]).
- * @param init A lambda function that configures the [DirectionalMotionSpecBuilder]. The lambda
- *   should return a [CanBeLastSegment] to indicate the end of the spec.
- * @return The constructed [DirectionalMotionSpec].
- */
-fun buildDirectionalMotionSpec(
-    defaultSpring: SpringParameters,
-    initialMapping: Mapping = Mapping.Identity,
-    init: DirectionalMotionSpecBuilder.() -> CanBeLastSegment,
-): DirectionalMotionSpec {
-    return DirectionalMotionSpecBuilderImpl(defaultSpring)
-        .also { it.mappings += initialMapping }
-        .also { it.init() }
-        .build()
-}
-
-/**
- * Builds a simple [DirectionalMotionSpec] with a single segment.
- *
- * @param mapping The [Mapping] to apply to the segment. Defaults to [Mapping.Identity].
- * @return A new [DirectionalMotionSpec] instance configured with the provided parameters.
- */
-fun buildDirectionalMotionSpec(mapping: Mapping = Mapping.Identity): DirectionalMotionSpec {
-    return DirectionalMotionSpec(listOf(Breakpoint.minLimit, Breakpoint.maxLimit), listOf(mapping))
-}
+/** Builder function signature. */
+typealias DirectionalBuilderFn = DirectionalBuilderScope.() -> CanBeLastSegment
 
 /**
  * Defines the contract for building a [DirectionalMotionSpec].
  *
  * Provides methods to define breakpoints and mappings for the motion specification.
  */
-interface DirectionalMotionSpecBuilder {
+interface DirectionalBuilderScope {
     /** The default [SpringParameters] used for breakpoints. */
     val defaultSpring: SpringParameters
 
@@ -98,6 +52,8 @@ interface DirectionalMotionSpecBuilder {
      *   [defaultSpring].
      * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
      * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     * @param semantics Updated semantics values to be applied. Must be a subset of the
+     *   [SemanticKey]s used when first creating this builder.
      */
     fun target(
         breakpoint: Float,
@@ -106,6 +62,7 @@ interface DirectionalMotionSpecBuilder {
         spring: SpringParameters = defaultSpring,
         guarantee: Guarantee = Guarantee.None,
         key: BreakpointKey = BreakpointKey(),
+        semantics: List<SemanticValue<*>> = emptyList(),
     )
 
     /**
@@ -124,6 +81,8 @@ interface DirectionalMotionSpecBuilder {
      *   [defaultSpring].
      * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
      * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     * @param semantics Updated semantics values to be applied. Must be a subset of the
+     *   [SemanticKey]s used when first creating this builder.
      */
     fun targetFromCurrent(
         breakpoint: Float,
@@ -132,6 +91,7 @@ interface DirectionalMotionSpecBuilder {
         spring: SpringParameters = defaultSpring,
         guarantee: Guarantee = Guarantee.None,
         key: BreakpointKey = BreakpointKey(),
+        semantics: List<SemanticValue<*>> = emptyList(),
     )
 
     /**
@@ -151,6 +111,8 @@ interface DirectionalMotionSpecBuilder {
      *   [defaultSpring].
      * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
      * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     * @param semantics Updated semantics values to be applied. Must be a subset of the
+     *   [SemanticKey]s used when first creating this builder.
      */
     fun fractionalInput(
         breakpoint: Float,
@@ -159,6 +121,7 @@ interface DirectionalMotionSpecBuilder {
         spring: SpringParameters = defaultSpring,
         guarantee: Guarantee = Guarantee.None,
         key: BreakpointKey = BreakpointKey(),
+        semantics: List<SemanticValue<*>> = emptyList(),
     ): CanBeLastSegment
 
     /**
@@ -177,6 +140,8 @@ interface DirectionalMotionSpecBuilder {
      *   [defaultSpring].
      * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
      * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     * @param semantics Updated semantics values to be applied. Must be a subset of the
+     *   [SemanticKey]s used when first creating this builder.
      */
     fun fractionalInputFromCurrent(
         breakpoint: Float,
@@ -185,11 +150,12 @@ interface DirectionalMotionSpecBuilder {
         spring: SpringParameters = defaultSpring,
         guarantee: Guarantee = Guarantee.None,
         key: BreakpointKey = BreakpointKey(),
+        semantics: List<SemanticValue<*>> = emptyList(),
     ): CanBeLastSegment
 
     /**
      * Ends the current segment at the [breakpoint] position and defines the next segment to output
-     * a constant value ([value]).
+     * a fixed value ([value]).
      *
      * Note: This segment can be used as the last segment in the specification.
      *
@@ -200,13 +166,16 @@ interface DirectionalMotionSpecBuilder {
      *   [defaultSpring].
      * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
      * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     * @param semantics Updated semantics values to be applied. Must be a subset of the
+     *   [SemanticKey]s used when first creating this builder.
      */
-    fun constantValue(
+    fun fixedValue(
         breakpoint: Float,
         value: Float,
         spring: SpringParameters = defaultSpring,
         guarantee: Guarantee = Guarantee.None,
         key: BreakpointKey = BreakpointKey(),
+        semantics: List<SemanticValue<*>> = emptyList(),
     ): CanBeLastSegment
 
     /**
@@ -218,19 +187,22 @@ interface DirectionalMotionSpecBuilder {
      *
      * @param breakpoint The breakpoint defining the end of the current segment and the start of the
      *   next.
-     * @param delta An optional offset to apply to the mapped value to determine the constant value.
+     * @param delta An optional offset to apply to the mapped value to determine the fixed value.
      *   Defaults to 0f.
      * @param spring The [SpringParameters] for the transition to this breakpoint. Defaults to
      *   [defaultSpring].
      * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
      * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     * @param semantics Updated semantics values to be applied. Must be a subset of the
+     *   [SemanticKey]s used when first creating this builder.
      */
-    fun constantValueFromCurrent(
+    fun fixedValueFromCurrent(
         breakpoint: Float,
         delta: Float = 0f,
         spring: SpringParameters = defaultSpring,
         guarantee: Guarantee = Guarantee.None,
         key: BreakpointKey = BreakpointKey(),
+        semantics: List<SemanticValue<*>> = emptyList(),
     ): CanBeLastSegment
 
     /**
@@ -245,6 +217,8 @@ interface DirectionalMotionSpecBuilder {
      *   [defaultSpring].
      * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
      * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     * @param semantics Updated semantics values to be applied. Must be a subset of the
+     *   [SemanticKey]s used when first creating this builder.
      * @param mapping The custom [Mapping] to use.
      */
     fun mapping(
@@ -252,228 +226,48 @@ interface DirectionalMotionSpecBuilder {
         spring: SpringParameters = defaultSpring,
         guarantee: Guarantee = Guarantee.None,
         key: BreakpointKey = BreakpointKey(),
+        semantics: List<SemanticValue<*>> = emptyList(),
         mapping: Mapping,
     ): CanBeLastSegment
-}
-
-/** Marker interface to indicate that a segment can be the last one in a [DirectionalMotionSpec]. */
-sealed interface CanBeLastSegment
-
-private data object CanBeLastSegmentImpl : CanBeLastSegment
-
-private class DirectionalMotionSpecBuilderImpl(override val defaultSpring: SpringParameters) :
-    DirectionalMotionSpecBuilder {
-    private val breakpoints = mutableListOf(Breakpoint.minLimit)
-    val mappings = mutableListOf<Mapping>()
-
-    private var sourceValue: Float = Float.NaN
-    private var targetValue: Float = Float.NaN
-    private var fractionalMapping: Float = Float.NaN
-    private var breakpointPosition: Float = Float.NaN
-    private var breakpointKey: BreakpointKey? = null
-
-    override fun target(
-        breakpoint: Float,
-        from: Float,
-        to: Float,
-        spring: SpringParameters,
-        guarantee: Guarantee,
-        key: BreakpointKey,
-    ) {
-        toBreakpointImpl(breakpoint, key)
-        jumpToImpl(from, spring, guarantee)
-        continueWithTargetValueImpl(to)
-    }
-
-    override fun targetFromCurrent(
-        breakpoint: Float,
-        to: Float,
-        delta: Float,
-        spring: SpringParameters,
-        guarantee: Guarantee,
-        key: BreakpointKey,
-    ) {
-        toBreakpointImpl(breakpoint, key)
-        jumpByImpl(delta, spring, guarantee)
-        continueWithTargetValueImpl(to)
-    }
-
-    override fun fractionalInput(
-        breakpoint: Float,
-        from: Float,
-        fraction: Float,
-        spring: SpringParameters,
-        guarantee: Guarantee,
-        key: BreakpointKey,
-    ): CanBeLastSegment {
-        toBreakpointImpl(breakpoint, key)
-        jumpToImpl(from, spring, guarantee)
-        continueWithFractionalInputImpl(fraction)
-        return CanBeLastSegmentImpl
-    }
-
-    override fun fractionalInputFromCurrent(
-        breakpoint: Float,
-        fraction: Float,
-        delta: Float,
-        spring: SpringParameters,
-        guarantee: Guarantee,
-        key: BreakpointKey,
-    ): CanBeLastSegment {
-        toBreakpointImpl(breakpoint, key)
-        jumpByImpl(delta, spring, guarantee)
-        continueWithFractionalInputImpl(fraction)
-        return CanBeLastSegmentImpl
-    }
 
-    override fun constantValue(
-        breakpoint: Float,
-        value: Float,
-        spring: SpringParameters,
-        guarantee: Guarantee,
-        key: BreakpointKey,
-    ): CanBeLastSegment {
-        toBreakpointImpl(breakpoint, key)
-        jumpToImpl(value, spring, guarantee)
-        continueWithConstantValueImpl()
-        return CanBeLastSegmentImpl
-    }
-
-    override fun constantValueFromCurrent(
-        breakpoint: Float,
-        delta: Float,
-        spring: SpringParameters,
-        guarantee: Guarantee,
-        key: BreakpointKey,
-    ): CanBeLastSegment {
-        toBreakpointImpl(breakpoint, key)
-        jumpByImpl(delta, spring, guarantee)
-        continueWithConstantValueImpl()
-        return CanBeLastSegmentImpl
-    }
-
-    override fun mapping(
+    /**
+     * Ends the current segment at the [breakpoint] position and defines the next segment to produce
+     * the input value as output (optionally with an offset of [delta]).
+     *
+     * Note: This segment can be used as the last segment in the specification.
+     *
+     * @param breakpoint The breakpoint defining the end of the current segment and the start of the
+     *   next.
+     * @param delta An optional offset to apply to the mapped value to determine the fixed value.
+     * @param spring The [SpringParameters] for the transition to this breakpoint.
+     * @param guarantee The animation guarantee for this transition.
+     * @param key A unique [BreakpointKey] for this breakpoint.
+     * @param semantics Updated semantics values to be applied. Must be a subset of the
+     *   [SemanticKey]s used when first creating this builder.
+     */
+    fun identity(
         breakpoint: Float,
-        spring: SpringParameters,
-        guarantee: Guarantee,
-        key: BreakpointKey,
-        mapping: Mapping,
+        delta: Float = 0f,
+        spring: SpringParameters = defaultSpring,
+        guarantee: Guarantee = Guarantee.None,
+        key: BreakpointKey = BreakpointKey(),
+        semantics: List<SemanticValue<*>> = emptyList(),
     ): CanBeLastSegment {
-        toBreakpointImpl(breakpoint, key)
-        continueWithImpl(mapping, spring, guarantee)
-        return CanBeLastSegmentImpl
-    }
-
-    fun build(): DirectionalMotionSpec {
-        completeImpl()
-        return DirectionalMotionSpec(breakpoints.toList(), mappings.toList())
-    }
-
-    private fun continueWithTargetValueImpl(target: Float) {
-        check(sourceValue.isFinite())
-
-        targetValue = target
-    }
-
-    private fun continueWithFractionalInputImpl(fraction: Float) {
-        check(sourceValue.isFinite())
-
-        fractionalMapping = fraction
-    }
-
-    private fun continueWithConstantValueImpl() {
-        check(sourceValue.isFinite())
-
-        mappings.add(Mapping.Fixed(sourceValue))
-        sourceValue = Float.NaN
-    }
-
-    private fun jumpToImpl(value: Float, spring: SpringParameters, guarantee: Guarantee) {
-        check(sourceValue.isNaN())
-
-        doAddBreakpointImpl(spring, guarantee)
-        sourceValue = value
-    }
-
-    private fun jumpByImpl(delta: Float, spring: SpringParameters, guarantee: Guarantee) {
-        check(sourceValue.isNaN())
-
-        val breakpoint = doAddBreakpointImpl(spring, guarantee)
-        sourceValue = mappings.last().map(breakpoint.position) + delta
-    }
-
-    private fun continueWithImpl(mapping: Mapping, spring: SpringParameters, guarantee: Guarantee) {
-        check(sourceValue.isNaN())
-
-        doAddBreakpointImpl(spring, guarantee)
-        mappings.add(mapping)
-    }
-
-    private fun toBreakpointImpl(atPosition: Float, key: BreakpointKey) {
-        check(breakpointPosition.isNaN())
-        check(breakpointKey == null)
-
-        if (!targetValue.isNaN() || !fractionalMapping.isNaN()) {
-            check(!sourceValue.isNaN())
-
-            val sourcePosition = breakpoints.last().position
-            val breakpointDistance = atPosition - sourcePosition
-            val mapping =
-                if (breakpointDistance == 0f) {
-                    Mapping.Fixed(sourceValue)
-                } else {
-
-                    if (fractionalMapping.isNaN()) {
-                        val delta = targetValue - sourceValue
-                        fractionalMapping = delta / (atPosition - sourcePosition)
-                    } else {
-                        val delta = (atPosition - sourcePosition) * fractionalMapping
-                        targetValue = sourceValue + delta
-                    }
-
-                    val offset = sourceValue - (sourcePosition * fractionalMapping)
-                    Mapping.Linear(fractionalMapping, offset)
-                }
-
-            mappings.add(mapping)
-            targetValue = Float.NaN
-            sourceValue = Float.NaN
-            fractionalMapping = Float.NaN
-        }
-
-        breakpointPosition = atPosition
-        breakpointKey = key
-    }
-
-    private fun completeImpl() {
-        check(targetValue.isNaN()) { "cant specify target value for last segment" }
-
-        if (!fractionalMapping.isNaN()) {
-            check(!sourceValue.isNaN())
-
-            val sourcePosition = breakpoints.last().position
-
-            mappings.add(
-                Mapping.Linear(
-                    fractionalMapping,
-                    sourceValue - (sourcePosition * fractionalMapping),
-                )
+        return if (delta == 0f) {
+            mapping(breakpoint, spring, guarantee, key, semantics, Mapping.Identity)
+        } else {
+            fractionalInput(
+                breakpoint,
+                fraction = 1f,
+                from = breakpoint + delta,
+                spring = spring,
+                guarantee = guarantee,
+                key = key,
+                semantics = semantics,
             )
         }
-
-        breakpoints.add(Breakpoint.maxLimit)
-    }
-
-    private fun doAddBreakpointImpl(
-        springSpec: SpringParameters,
-        guarantee: Guarantee,
-    ): Breakpoint {
-        check(breakpointPosition.isFinite())
-        return Breakpoint(checkNotNull(breakpointKey), breakpointPosition, springSpec, guarantee)
-            .also {
-                breakpoints.add(it)
-                breakpointPosition = Float.NaN
-                breakpointKey = null
-            }
     }
 }
+
+/** Marker interface to indicate that a segment can be the last one in a [DirectionalMotionSpec]. */
+sealed interface CanBeLastSegment
diff --git a/mechanics/src/com/android/mechanics/spec/builder/DirectionalSpecBuilder.kt b/mechanics/src/com/android/mechanics/spec/builder/DirectionalSpecBuilder.kt
new file mode 100644
index 0000000..b4483b7
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/builder/DirectionalSpecBuilder.kt
@@ -0,0 +1,128 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec.builder
+
+import com.android.mechanics.spec.Breakpoint
+import com.android.mechanics.spec.DirectionalMotionSpec
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.SegmentSemanticValues
+import com.android.mechanics.spec.SemanticValue
+import com.android.mechanics.spring.SpringParameters
+
+/**
+ * Builds a [DirectionalMotionSpec] for spatial values by defining a sequence of ([Breakpoint],
+ * [Mapping]) pairs
+ *
+ * The [initialMapping] is [Mapping.Identity], and the Material spatial.default spring is used,
+ * unless otherwise specified.
+ *
+ * @see directionalMotionSpec
+ */
+fun MotionBuilderContext.spatialDirectionalMotionSpec(
+    initialMapping: Mapping = Mapping.Identity,
+    semantics: List<SemanticValue<*>> = emptyList(),
+    defaultSpring: SpringParameters = this.spatial.default,
+    init: DirectionalBuilderFn,
+) = directionalMotionSpec(defaultSpring, initialMapping, semantics, init)
+
+/**
+ * Builds a [DirectionalMotionSpec] for effects values by defining a sequence of ([Breakpoint],
+ * [Mapping]) pairs
+ *
+ * The [initialMapping] is [Mapping.Zero], and the Material effects.default spring is used, unless
+ * otherwise specified.
+ *
+ * @see directionalMotionSpec
+ */
+fun MotionBuilderContext.effectsDirectionalMotionSpec(
+    initialMapping: Mapping = Mapping.Zero,
+    semantics: List<SemanticValue<*>> = emptyList(),
+    defaultSpring: SpringParameters = this.effects.default,
+    init: DirectionalBuilderFn,
+) = directionalMotionSpec(defaultSpring, initialMapping, semantics, init)
+
+/**
+ * Builds a [DirectionalMotionSpec] by defining a sequence of ([Breakpoint], [Mapping]) pairs.
+ *
+ * This function simplifies the creation of complex motion specifications. It allows you to define a
+ * series of motion segments, each with its own behavior, separated by breakpoints. The breakpoints
+ * and their corresponding segments will always be ordered from min to max value, regardless of how
+ * the `DirectionalMotionSpec` is applied.
+ *
+ * Example Usage:
+ * ```kotlin
+ * val motionSpec = directionalMotionSpec(
+ *     defaultSpring = materialSpatial,
+ *
+ *     // Start as a constant transition, always 0.
+ *     initialMapping = Mapping.Zero
+ * ) {
+ *     // At breakpoint 10: Linear transition from 0 to 50.
+ *     target(breakpoint = 10f, from = 0f, to = 50f)
+ *
+ *     // At breakpoint 20: Jump +5, and constant value 55.
+ *     fixedValueFromCurrent(breakpoint = 20f, delta = 5f)
+ *
+ *     // At breakpoint 30: Jump to 40. Linear mapping using: progress_since_breakpoint * fraction.
+ *     fractionalInput(breakpoint = 30f, from = 40f, fraction = 2f)
+ * }
+ * ```
+ *
+ * @param defaultSpring The default [SpringParameters] to use for all breakpoints.
+ * @param initialMapping The initial [Mapping] for the first segment (defaults to
+ *   [Mapping.Identity]).
+ * @param init A lambda function that configures the spec using the [DirectionalBuilderScope]. The
+ *   lambda should return a [CanBeLastSegment] to indicate the end of the spec.
+ * @param semantics Semantics specified in this spec, including the initial value applied for
+ *   [initialMapping].
+ *     @return The constructed [DirectionalMotionSpec].
+ */
+fun directionalMotionSpec(
+    defaultSpring: SpringParameters,
+    initialMapping: Mapping = Mapping.Identity,
+    semantics: List<SemanticValue<*>> = emptyList(),
+    init: DirectionalBuilderFn,
+): DirectionalMotionSpec {
+    return DirectionalBuilderImpl(defaultSpring, semantics)
+        .apply {
+            prepareBuilderFn(initialMapping)
+            init()
+            finalizeBuilderFn(Breakpoint.maxLimit)
+        }
+        .build()
+}
+
+/**
+ * Builds a simple [DirectionalMotionSpec] with a single segment.
+ *
+ * @param mapping The [Mapping] to apply to the segment. Defaults to [Mapping.Identity].
+ * @param semantics Semantics values for this spec.
+ * @return A new [DirectionalMotionSpec] instance configured with the provided parameters.
+ */
+fun directionalMotionSpec(
+    mapping: Mapping = Mapping.Identity,
+    semantics: List<SemanticValue<*>> = emptyList(),
+): DirectionalMotionSpec {
+    fun <T> toSegmentSemanticValues(semanticValue: SemanticValue<T>) =
+        SegmentSemanticValues(semanticValue.key, listOf(semanticValue.value))
+
+    return DirectionalMotionSpec(
+        listOf(Breakpoint.minLimit, Breakpoint.maxLimit),
+        listOf(mapping),
+        semantics.map { toSegmentSemanticValues(it) },
+    )
+}
diff --git a/mechanics/src/com/android/mechanics/spec/builder/Effect.kt b/mechanics/src/com/android/mechanics/spec/builder/Effect.kt
new file mode 100644
index 0000000..93314c0
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/builder/Effect.kt
@@ -0,0 +1,68 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec.builder
+
+import com.android.mechanics.spec.BreakpointKey
+
+/**
+ * Blueprint for a reusable behavior in a [MotionSpec].
+ *
+ * [Effect] instances are reusable for building multiple
+ */
+sealed interface Effect {
+
+    /**
+     * Applies the effect to the motion spec.
+     *
+     * The boundaries of the effect are defined by the [minLimit] and [maxLimit] properties, and
+     * extend in both, the min and max direction by the same amount.
+     *
+     * Implementations must invoke either [EffectApplyScope.unidirectional] or both,
+     * [EffectApplyScope.forward] and [EffectApplyScope.backward]. The motion spec builder will
+     * throw if neither is called.
+     */
+    fun EffectApplyScope.createSpec(
+        minLimit: Float,
+        minLimitKey: BreakpointKey,
+        maxLimit: Float,
+        maxLimitKey: BreakpointKey,
+        placement: EffectPlacement,
+    )
+
+    interface PlaceableAfter : Effect {
+        fun MotionBuilderContext.intrinsicSize(): Float
+    }
+
+    interface PlaceableBefore : Effect {
+        fun MotionBuilderContext.intrinsicSize(): Float
+    }
+
+    interface PlaceableBetween : Effect
+
+    interface PlaceableAt : Effect {
+        fun MotionBuilderContext.minExtent(): Float
+
+        fun MotionBuilderContext.maxExtent(): Float
+    }
+}
+
+/**
+ * Handle for an [Effect] that was placed within a [MotionSpecBuilderScope].
+ *
+ * Used to place effects relative to each other.
+ */
+@JvmInline value class PlacedEffect internal constructor(internal val id: Int)
diff --git a/mechanics/src/com/android/mechanics/spec/builder/EffectApplyScope.kt b/mechanics/src/com/android/mechanics/spec/builder/EffectApplyScope.kt
new file mode 100644
index 0000000..920b58b
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/builder/EffectApplyScope.kt
@@ -0,0 +1,182 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec.builder
+
+import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.OnChangeSegmentHandler
+import com.android.mechanics.spec.SegmentKey
+import com.android.mechanics.spec.SemanticValue
+import com.android.mechanics.spring.SpringParameters
+
+/**
+ * Defines the contract for applying [Effect]s within a [MotionSpecBuilder]
+ *
+ * Provides methods to define breakpoints and mappings for the motion specification.
+ *
+ * Breakpoints for [minLimit] and [maxLimit] will be created, with the specified key and parameters.
+ */
+interface EffectApplyScope : MotionBuilderContext {
+    /** Default spring in use when not otherwise specified. */
+    val defaultSpring: SpringParameters
+
+    /** Mapping used outside of the defined effects. */
+    val baseMapping: Mapping
+
+    /**
+     * Defines spec simultaneously for both, the min and max direction.
+     *
+     * The behavior is the same as for `directionalMotionSpec`, with the notable exception that the
+     * spec to be defined is confined within [minLimit] and [maxLimit]. Specifying breakpoints
+     * outside of this range will throw.
+     *
+     * Will throw if [forward] or [unidirectional] has been called in this scope before.
+     *
+     * The first / last semantic value will implicitly extend to the start / end of the resulting
+     * spec, unless redefined in another spec.
+     *
+     * @param initialMapping [Mapping] for the first segment after [minLimit].
+     * @param semantics Initial semantics for the effect.
+     * @param init Configures the effect's spec using [DirectionalBuilderScope].
+     * @see com.android.mechanics.spec.directionalMotionSpec for in-depth documentation.
+     */
+    fun unidirectional(
+        initialMapping: Mapping,
+        semantics: List<SemanticValue<*>> = emptyList(),
+        init: DirectionalEffectBuilderScope.() -> Unit,
+    )
+
+    /**
+     * Defines spec simultaneously for both, the min and max direction, using a single segment only.
+     *
+     * The behavior is the same as for `directionalMotionSpec`, with the notable exception that the
+     * spec to be defined is confined within [minLimit] and [maxLimit].
+     *
+     * Will throw if [forward] or [unidirectional] has been called in this scope before.
+     *
+     * The first / last semantic value will implicitly extend to the start / end of the resulting
+     * spec, unless redefined in another spec.
+     *
+     * @param mapping [Mapping] to be used between [minLimit] and [maxLimit].
+     * @param semantics Initial semantics for the effect.
+     * @see com.android.mechanics.spec.directionalMotionSpec for in depth documentation.
+     */
+    fun unidirectional(mapping: Mapping, semantics: List<SemanticValue<*>> = emptyList())
+
+    /**
+     * Defines the spec for max direction.
+     *
+     * The behavior is the same as for `directionalMotionSpec`, with the notable exception that the
+     * spec to be defined is confined within [minLimit] and [maxLimit]. Specifying breakpoints
+     * outside of this range will throw.
+     *
+     * Will throw if [forward] or [unidirectional] has been called in this scope before.
+     *
+     * The first / last semantic value will implicitly extend to the start / end of the resulting
+     * spec, unless redefined in another spec.
+     *
+     * @param initialMapping [Mapping] for the first segment after [minLimit].
+     * @param semantics Initial semantics for the effect.
+     * @param init Configures the effect's spec using [DirectionalBuilderScope].
+     * @see com.android.mechanics.spec.directionalMotionSpec for in-depth documentation.
+     */
+    fun forward(
+        initialMapping: Mapping,
+        semantics: List<SemanticValue<*>> = emptyList(),
+        init: DirectionalEffectBuilderScope.() -> Unit,
+    )
+
+    /**
+     * Defines the spec for max direction, using a single segment only.
+     *
+     * The behavior is the same as for `directionalMotionSpec`, with the notable exception that the
+     * spec to be defined is confined within [minLimit] and [maxLimit].
+     *
+     * Will throw if [forward] or [unidirectional] has been called in this scope before.
+     *
+     * The first / last semantic value will implicitly extend to the start / end of the resulting
+     * spec, unless redefined in another spec.
+     *
+     * @param mapping [Mapping] to be used between [minLimit] and [maxLimit].
+     * @param semantics Initial semantics for the effect.
+     * @see com.android.mechanics.spec.directionalMotionSpec for in depth documentation.
+     */
+    fun forward(mapping: Mapping, semantics: List<SemanticValue<*>> = emptyList())
+
+    /**
+     * Defines the spec for min direction.
+     *
+     * The behavior is the same as for `directionalMotionSpec`, with the notable exception that the
+     * spec to be defined is confined within [minLimit] and [maxLimit]. Specifying breakpoints
+     * outside of this range will throw.
+     *
+     * Will throw if [forward] or [unidirectional] has been called in this scope before.
+     *
+     * The first / last semantic value will implicitly extend to the start / end of the resulting
+     * spec, unless redefined in another spec.
+     *
+     * @param initialMapping [Mapping] for the first segment after [minLimit].
+     * @param semantics Initial semantics for the effect.
+     * @param init Configures the effect's spec using [DirectionalBuilderScope].
+     * @see com.android.mechanics.spec.directionalMotionSpec for in-depth documentation.
+     */
+    fun backward(
+        initialMapping: Mapping,
+        semantics: List<SemanticValue<*>> = emptyList(),
+        init: DirectionalEffectBuilderScope.() -> Unit,
+    )
+
+    /**
+     * Defines the spec for min direction, using a single segment only.
+     *
+     * The behavior is the same as for `directionalMotionSpec`, with the notable exception that the
+     * spec to be defined is confined within [minLimit] and [maxLimit].
+     *
+     * Will throw if [forward] or [unidirectional] has been called in this scope before.
+     *
+     * The first / last semantic value will implicitly extend to the start / end of the resulting
+     * spec, unless redefined in another spec.
+     *
+     * @param mapping [Mapping] to be used between [minLimit] and [maxLimit].
+     * @param semantics Initial semantics for the effect.
+     * @see com.android.mechanics.spec.directionalMotionSpec for in depth documentation.
+     */
+    fun backward(mapping: Mapping, semantics: List<SemanticValue<*>> = emptyList())
+
+    /** Adds a segment handler to the resulting [MotionSpec]. */
+    fun addSegmentHandler(key: SegmentKey, handler: OnChangeSegmentHandler)
+
+    /** Returns the value of [baseValue] at [position]. */
+    fun baseValue(position: Float): Float
+}
+
+interface DirectionalEffectBuilderScope : DirectionalBuilderScope {
+
+    fun before(
+        spring: SpringParameters? = null,
+        guarantee: Guarantee? = null,
+        semantics: List<SemanticValue<*>>? = null,
+        mapping: Mapping? = null,
+    )
+
+    fun after(
+        spring: SpringParameters? = null,
+        guarantee: Guarantee? = null,
+        semantics: List<SemanticValue<*>>? = null,
+        mapping: Mapping? = null,
+    )
+}
diff --git a/mechanics/src/com/android/mechanics/spec/builder/EffectPlacement.kt b/mechanics/src/com/android/mechanics/spec/builder/EffectPlacement.kt
new file mode 100644
index 0000000..00f4f10
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/builder/EffectPlacement.kt
@@ -0,0 +1,111 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec.builder
+
+import androidx.compose.ui.util.packFloats
+import androidx.compose.ui.util.unpackFloat1
+import androidx.compose.ui.util.unpackFloat2
+import kotlin.math.max
+import kotlin.math.min
+import kotlin.math.nextDown
+import kotlin.math.nextUp
+
+/**
+ * Describes the desired placement of an effect within the input domain of a [MotionSpec].
+ *
+ * [start] is always finite, and denotes a specific position in the input where the effects starts.
+ *
+ * [end] is either finite, describing a specific range in the input where the [Effect] applies.
+ * Alternatively, the [end] can be either [Float.NEGATIVE_INFINITY] or [Float.POSITIVE_INFINITY],
+ * indicating that the effect extends either
+ * - for the effects intrinsic extent
+ * - the boundaries of the next placed effect
+ * - the specs' min/max limit
+ *
+ * Thus, [start] and [end] define an implicit direction of the effect. If not [isForward], the
+ * [Effect] will be reversed when applied.
+ */
+@JvmInline
+value class EffectPlacement internal constructor(val value: Long) {
+
+    init {
+        require(start.isFinite())
+    }
+
+    val start: Float
+        get() = unpackFloat1(value)
+
+    val end: Float
+        get() = unpackFloat2(value)
+
+    val type: EffectPlacemenType
+        get() {
+            return when {
+                end.isNaN() -> EffectPlacemenType.At
+                end == Float.NEGATIVE_INFINITY -> EffectPlacemenType.Before
+                end == Float.POSITIVE_INFINITY -> EffectPlacemenType.After
+                else -> EffectPlacemenType.Between
+            }
+        }
+
+    val isForward: Boolean
+        get() {
+            return when (type) {
+                EffectPlacemenType.At -> true
+                EffectPlacemenType.Before -> false
+                EffectPlacemenType.After -> true
+                EffectPlacemenType.Between -> end >= start
+            }
+        }
+
+    internal val sortOrder: Float
+        get() {
+            return when (type) {
+                EffectPlacemenType.At -> start
+                EffectPlacemenType.Before -> start.nextDown()
+                EffectPlacemenType.After -> start.nextUp()
+                EffectPlacemenType.Between -> (start + end) / 2
+            }
+        }
+
+    internal val min: Float
+        get() = min(start, end)
+
+    internal val max: Float
+        get() = max(start, end)
+
+    override fun toString(): String {
+        return "EffectPlacement(start=$start, end=$end)"
+    }
+
+    companion object {
+        fun at(position: Float) = EffectPlacement(packFloats(position, Float.NaN))
+
+        fun after(position: Float) = EffectPlacement(packFloats(position, Float.POSITIVE_INFINITY))
+
+        fun before(position: Float) = EffectPlacement(packFloats(position, Float.NEGATIVE_INFINITY))
+
+        fun between(start: Float, end: Float) = EffectPlacement(packFloats(start, end))
+    }
+}
+
+enum class EffectPlacemenType {
+    At,
+    Before,
+    After,
+    Between,
+}
diff --git a/mechanics/src/com/android/mechanics/spec/builder/MotionBuilderContext.kt b/mechanics/src/com/android/mechanics/spec/builder/MotionBuilderContext.kt
new file mode 100644
index 0000000..989d481
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/builder/MotionBuilderContext.kt
@@ -0,0 +1,104 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+@file:OptIn(ExperimentalMaterial3ExpressiveApi::class)
+
+package com.android.mechanics.spec.builder
+
+import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
+import androidx.compose.material3.MaterialTheme
+import androidx.compose.material3.MotionScheme
+import androidx.compose.runtime.Composable
+import androidx.compose.runtime.remember
+import androidx.compose.ui.platform.LocalDensity
+import androidx.compose.ui.unit.Density
+import com.android.mechanics.spring.SpringParameters
+
+/**
+ * Device / scheme specific context for building motion specs.
+ *
+ * See go/motion-system.
+ *
+ * @see rememberMotionBuilderContext for Compose
+ * @see standardViewMotionBuilderContext for Views
+ * @see expressiveViewMotionBuilderContext for Views
+ */
+interface MotionBuilderContext : Density {
+    /**
+     * Spatial spring tokens.
+     *
+     * Used for animations that move something on screen, for example the x and y position,
+     * rotation, size, rounded corners.
+     *
+     * See go/motion-system#b99b0d12-e9c8-4605-96dd-e3f17bfe9538
+     */
+    val spatial: MaterialSprings
+
+    /**
+     * Effects spring tokens.
+     *
+     * Used to animate properties such as color and opacity animations.
+     *
+     * See go/motion-system#142c8835-7474-4f74-b2eb-e1187051ec1f
+     */
+    val effects: MaterialSprings
+
+    companion object {
+        /** Default threshold for effect springs. */
+        const val StableThresholdEffects = 0.01f
+        /**
+         * Default threshold for spatial springs.
+         *
+         * Cuts off when remaining oscillations are below 1px
+         */
+        const val StableThresholdSpatial = 1f
+    }
+}
+
+/** Material spring tokens, see go/motion-system##63b14c00-d049-4d3e-b8b6-83d8f524a8db for usage. */
+data class MaterialSprings(
+    val default: SpringParameters,
+    val fast: SpringParameters,
+    val slow: SpringParameters,
+    val stabilityThreshold: Float,
+)
+
+/** [MotionBuilderContext] based on the current [Density] and [MotionScheme]. */
+@Composable
+fun rememberMotionBuilderContext(): MotionBuilderContext {
+    val density = LocalDensity.current
+    val motionScheme = MaterialTheme.motionScheme
+    return remember(density, motionScheme) { ComposeMotionBuilderContext(motionScheme, density) }
+}
+
+class ComposeMotionBuilderContext(motionScheme: MotionScheme, density: Density) :
+    MotionBuilderContext, Density by density {
+
+    override val spatial =
+        MaterialSprings(
+            SpringParameters(motionScheme.defaultSpatialSpec<Float>()),
+            SpringParameters(motionScheme.fastSpatialSpec<Float>()),
+            SpringParameters(motionScheme.slowSpatialSpec<Float>()),
+            MotionBuilderContext.StableThresholdSpatial,
+        )
+    override val effects =
+        MaterialSprings(
+            SpringParameters(motionScheme.defaultEffectsSpec<Float>()),
+            SpringParameters(motionScheme.fastEffectsSpec<Float>()),
+            SpringParameters(motionScheme.slowEffectsSpec<Float>()),
+            MotionBuilderContext.StableThresholdEffects,
+        )
+}
diff --git a/mechanics/src/com/android/mechanics/spec/builder/MotionSpecBuilder.kt b/mechanics/src/com/android/mechanics/spec/builder/MotionSpecBuilder.kt
new file mode 100644
index 0000000..de62c44
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/builder/MotionSpecBuilder.kt
@@ -0,0 +1,162 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec.builder
+
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.MotionSpec
+import com.android.mechanics.spec.SemanticValue
+import com.android.mechanics.spring.SpringParameters
+
+/**
+ * Creates a [MotionSpec] for a spatial value.
+ *
+ * The [baseMapping] is [Mapping.Identity], and the Material spatial.default spring is used unless
+ * otherwise specified.
+ *
+ * @see motionSpec
+ */
+fun MotionBuilderContext.spatialMotionSpec(
+    baseMapping: Mapping = Mapping.Identity,
+    defaultSpring: SpringParameters = this.spatial.default,
+    resetSpring: SpringParameters = defaultSpring,
+    baseSemantics: List<SemanticValue<*>> = emptyList(),
+    init: MotionSpecBuilderScope.() -> Unit,
+) = motionSpec(baseMapping, defaultSpring, resetSpring, baseSemantics, init)
+
+/**
+ * Creates a [MotionSpec] for an effects value.
+ *
+ * The [baseMapping] is [Mapping.Zero], and the Material effects.default spring is used unless
+ * otherwise specified.
+ *
+ * @see motionSpec
+ */
+fun MotionBuilderContext.effectsMotionSpec(
+    baseMapping: Mapping = Mapping.Zero,
+    defaultSpring: SpringParameters = this.effects.default,
+    resetSpring: SpringParameters = defaultSpring,
+    baseSemantics: List<SemanticValue<*>> = emptyList(),
+    init: MotionSpecBuilderScope.() -> Unit,
+) = motionSpec(baseMapping, defaultSpring, resetSpring, baseSemantics, init)
+
+/**
+ * Creates a [MotionSpec], based on reusable effects.
+ *
+ * @param baseMapping The mapping in used for segments where no [Effect] is specified.
+ * @param defaultSpring The [DirectionalBuilderScope.defaultSpring], used for all discontinuities
+ *   unless otherwise specified.
+ * @param resetSpring spring parameters to animate a difference in output, if the difference is
+ *   caused by setting this new spec.
+ * @param baseSemantics initial semantics that apply before of effects override them.
+ * @param init
+ */
+fun MotionBuilderContext.motionSpec(
+    baseMapping: Mapping,
+    defaultSpring: SpringParameters,
+    resetSpring: SpringParameters = defaultSpring,
+    baseSemantics: List<SemanticValue<*>> = emptyList(),
+    init: MotionSpecBuilderScope.() -> Unit,
+): MotionSpec {
+    return MotionSpecBuilderImpl(
+            baseMapping,
+            defaultSpring,
+            resetSpring,
+            baseSemantics,
+            motionBuilderContext = this,
+        )
+        .apply(init)
+        .build()
+}
+
+/**
+ * Creates a [MotionSpec] producing a fixed output value, no matter the [MotionValues]'s input.
+ *
+ * The Material spatial.default spring is used to animate to the fixed output value.
+ *
+ * @see fixedValueSpec
+ */
+fun MotionBuilderContext.fixedSpatialValueSpec(
+    value: Float,
+    resetSpring: SpringParameters = this.spatial.default,
+    semantics: List<SemanticValue<*>> = emptyList(),
+) = fixedValueSpec(value, resetSpring, semantics)
+
+/**
+ * Creates a [MotionSpec] producing a fixed output value, no matter the [MotionValues]'s input.
+ *
+ * The Material effects.default spring is used to animate to the fixed output value.
+ *
+ * @see fixedValueSpec
+ */
+fun MotionBuilderContext.fixedEffectsValueSpec(
+    value: Float,
+    resetSpring: SpringParameters = this.effects.default,
+    semantics: List<SemanticValue<*>> = emptyList(),
+) = fixedValueSpec(value, resetSpring, semantics)
+
+/**
+ * Creates a [MotionSpec] producing a fixed output value, no matter the [MotionValues]'s input.
+ *
+ * @param value The fixed output value.
+ * @param resetSpring spring parameters to animate to the fixed output value.
+ * @param semantics for this spec.
+ */
+fun MotionBuilderContext.fixedValueSpec(
+    value: Float,
+    resetSpring: SpringParameters,
+    semantics: List<SemanticValue<*>> = emptyList(),
+): MotionSpec {
+    return MotionSpec(
+        directionalMotionSpec(Mapping.Fixed(value), semantics),
+        resetSpring = resetSpring,
+    )
+}
+
+/** Defines the contract placing [Effect]s within a [MotionSpecBuilder] */
+interface MotionSpecBuilderScope : MotionBuilderContext {
+
+    /**
+     * Places [effect] between [start] and [end].
+     *
+     * If `start > end`, the effect will be reversed when applied. The [effect] can overrule the
+     * `end` position with [Effect.measure].
+     */
+    fun between(start: Float, end: Float, effect: Effect.PlaceableBetween): PlacedEffect
+
+    /**
+     * Places [effect] at position, extending backwards.
+     *
+     * The effect will be reversed when applied.
+     */
+    fun before(position: Float, effect: Effect.PlaceableBefore): PlacedEffect
+
+    /** Places [effect] at position, extending forward. */
+    fun after(position: Float, effect: Effect.PlaceableAfter): PlacedEffect
+
+    /**
+     * Places [effect] at [otherEffect]'s min position, extending backwards.
+     *
+     * The effect will be reversed when applied.
+     */
+    fun before(otherEffect: PlacedEffect, effect: Effect.PlaceableBefore): PlacedEffect
+
+    /** Places [effect] after the end of [otherEffect], extending forward. */
+    fun after(otherEffect: PlacedEffect, effect: Effect.PlaceableAfter): PlacedEffect
+
+    /** Places [effect] at position. */
+    fun at(position: Float, effect: Effect.PlaceableAt): PlacedEffect
+}
diff --git a/mechanics/src/com/android/mechanics/spec/builder/MotionSpecBuilderImpl.kt b/mechanics/src/com/android/mechanics/spec/builder/MotionSpecBuilderImpl.kt
new file mode 100644
index 0000000..75b9953
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/builder/MotionSpecBuilderImpl.kt
@@ -0,0 +1,589 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec.builder
+
+import androidx.collection.MutableIntIntMap
+import androidx.collection.MutableIntList
+import androidx.collection.MutableIntLongMap
+import androidx.collection.MutableIntObjectMap
+import androidx.collection.MutableLongList
+import androidx.collection.ObjectList
+import androidx.collection.mutableObjectListOf
+import com.android.mechanics.spec.Breakpoint
+import com.android.mechanics.spec.BreakpointKey
+import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.MotionSpec
+import com.android.mechanics.spec.OnChangeSegmentHandler
+import com.android.mechanics.spec.SegmentKey
+import com.android.mechanics.spec.SemanticValue
+import com.android.mechanics.spring.SpringParameters
+
+internal class MotionSpecBuilderImpl(
+    override val baseMapping: Mapping,
+    override val defaultSpring: SpringParameters,
+    private val resetSpring: SpringParameters,
+    private val baseSemantics: List<SemanticValue<*>>,
+    motionBuilderContext: MotionBuilderContext,
+) : MotionSpecBuilderScope, MotionBuilderContext by motionBuilderContext, EffectApplyScope {
+
+    private val placedEffects = MutableIntObjectMap<Effect>()
+    private val absoluteEffectPlacements = MutableIntLongMap()
+    private val relativeEffectPlacements = MutableIntIntMap()
+
+    private lateinit var builders: ObjectList<DirectionalEffectBuilderScopeImpl>
+    private val forwardBuilder: DirectionalEffectBuilderScopeImpl
+        get() = builders[0]
+
+    private val reverseBuilder: DirectionalEffectBuilderScopeImpl
+        get() = builders[1]
+
+    private lateinit var segmentHandlers: MutableMap<SegmentKey, OnChangeSegmentHandler>
+
+    fun build(): MotionSpec {
+        if (placedEffects.isEmpty()) {
+            return MotionSpec(directionalMotionSpec(baseMapping), resetSpring = resetSpring)
+        }
+
+        builders =
+            mutableObjectListOf(
+                DirectionalEffectBuilderScopeImpl(defaultSpring, baseSemantics),
+                DirectionalEffectBuilderScopeImpl(defaultSpring, baseSemantics),
+            )
+        segmentHandlers = mutableMapOf()
+
+        val capacity = placedEffects.size * 2 + 1
+        val sortedEffects = MutableIntList(capacity)
+        val specifiedPlacements = MutablePlacementList(MutableLongList(capacity))
+        val actualPlacements = MutablePlacementList(MutableLongList(capacity))
+
+        placeEffects(sortedEffects, specifiedPlacements, actualPlacements)
+        check(sortedEffects.size >= 2)
+
+        var minLimitKey = BreakpointKey.MinLimit
+        lateinit var maxLimitKey: BreakpointKey
+
+        for (i in 0 until sortedEffects.lastIndex) {
+            maxLimitKey = BreakpointKey()
+            applyEffect(
+                sortedEffects[i],
+                specifiedPlacements[i],
+                actualPlacements[i],
+                minLimitKey,
+                maxLimitKey,
+            )
+            minLimitKey = maxLimitKey
+        }
+
+        maxLimitKey = BreakpointKey.MaxLimit
+
+        applyEffect(
+            sortedEffects.last(),
+            specifiedPlacements.last(),
+            actualPlacements.last(),
+            minLimitKey,
+            maxLimitKey,
+        )
+
+        return MotionSpec(
+            builders[0].build(),
+            builders[1].build(),
+            resetSpring,
+            segmentHandlers.toMap(),
+        )
+    }
+
+    private fun placeEffects(
+        sortedEffects: MutableIntList,
+        specifiedPlacements: MutablePlacementList,
+        actualPlacements: MutablePlacementList,
+    ) {
+
+        // To place the effects, do the following
+        // - sort all `absoluteEffectPlacements` in ascending order
+        // - use the sorted absolutely placed effects as seeds. For each of them, do the following:
+        //   - measure the effect
+        //   - recursively walk the relatively effects placed before, tracking the min boundary
+        //     (this requires effects that have a defined extend to the min side)
+        //   - upon reaching the beginning, start placing the effects in the forward direction.
+        //     continue up to the seed effects, t
+        //   - recursively continue placing effects relatively placed afterwards.
+
+        fun appendEffect(
+            effectId: Int,
+            specifiedPlacement: EffectPlacement,
+            measuredPlacement: EffectPlacement,
+        ) {
+            var actualPlacement = measuredPlacement
+            var prependNoPlaceholderEffect = false
+
+            if (actualPlacements.isEmpty()) {
+                // placing first effect.
+                if (measuredPlacement.min.isFinite()) {
+                    prependNoPlaceholderEffect = true
+                }
+            } else {
+
+                val previousPlacement = actualPlacements.last()
+                if (previousPlacement.max.isFinite()) {
+                    // The previous effect has a defined end-point.
+
+                    if (measuredPlacement.min == Float.NEGATIVE_INFINITY) {
+                        // The current effect wants to extend to the end of the previous effect.
+                        require(measuredPlacement.max.isFinite())
+                        actualPlacement =
+                            EffectPlacement.between(previousPlacement.max, measuredPlacement.max)
+                    } else if (measuredPlacement.min > previousPlacement.max) {
+                        // There's a gap between the last and the current effect, will need to
+                        // insert a placeholder
+                        require(measuredPlacement.min.isFinite())
+                        prependNoPlaceholderEffect = true
+                    } else {
+                        // In all other cases, the previous end has to match the current start.
+                        // In all other cases, effects are overlapping, which is not supported.
+                        require(measuredPlacement.min == previousPlacement.max) {
+                            "Effects are overlapping"
+                        }
+                    }
+                } else {
+                    // The previous effect wants to extend to the beginning of the next effect
+                    assert(previousPlacement.max == Float.POSITIVE_INFINITY)
+
+                    // Therefore the current effect is required to have a defined start-point
+                    require(measuredPlacement.min.isFinite()) {
+                        "Only one of the effects can extend to the  boundary, not both:\n" +
+                            "  this:  $actualPlacement (${placedEffects[effectId]})\n" +
+                            "  previous:  $previousPlacement (${placedEffects[effectId]}])\n"
+                    }
+
+                    actualPlacements[actualPlacements.lastIndex] =
+                        EffectPlacement.between(previousPlacement.min, measuredPlacement.min)
+                }
+            }
+
+            if (prependNoPlaceholderEffect) {
+                assert(actualPlacement.min.isFinite())
+                // Adding a placeholder that will be skipped, but simplifies the algorithm by
+                // ensuring all effects are back-to-back. The NoEffectPlaceholderId is used to
+
+                sortedEffects.add(NoEffectPlaceholderId)
+                val placeholderPlacement = EffectPlacement.before(actualPlacement.min)
+                specifiedPlacements.add(placeholderPlacement)
+                actualPlacements.add(placeholderPlacement)
+            }
+
+            sortedEffects.add(effectId)
+            specifiedPlacements.add(specifiedPlacement)
+
+            actualPlacements.add(actualPlacement)
+        }
+
+        fun processEffectsPlacedBefore(
+            anchorEffectId: Int,
+            anchorEffectPlacement: EffectPlacement,
+        ) {
+            val beforeEffectKey = -anchorEffectId
+            if (relativeEffectPlacements.containsKey(beforeEffectKey)) {
+                val effectId = relativeEffectPlacements[beforeEffectKey]
+                val effect = checkNotNull(placedEffects[effectId])
+
+                require(anchorEffectPlacement.min.isFinite())
+                val specifiedPlacement = EffectPlacement.before(anchorEffectPlacement.min)
+
+                val measuredPlacement = measureEffect(effect, specifiedPlacement)
+                processEffectsPlacedBefore(effectId, measuredPlacement)
+                appendEffect(effectId, specifiedPlacement, measuredPlacement)
+            }
+        }
+
+        fun processEffectsPlacedAfter(anchorEffectId: Int, anchorEffectPlacement: EffectPlacement) {
+            val afterEffectKey = anchorEffectId
+            if (relativeEffectPlacements.containsKey(afterEffectKey)) {
+                val effectId = relativeEffectPlacements[afterEffectKey]
+                val effect = checkNotNull(placedEffects[effectId])
+
+                require(anchorEffectPlacement.max.isFinite())
+                val specifiedPlacement = EffectPlacement.after(anchorEffectPlacement.max)
+
+                val measuredPlacement = measureEffect(effect, specifiedPlacement)
+                appendEffect(effectId, specifiedPlacement, measuredPlacement)
+                processEffectsPlacedAfter(effectId, measuredPlacement)
+            }
+        }
+
+        check(absoluteEffectPlacements.isNotEmpty())
+        // Implementation note: sortedAbsolutePlacedEffects should be an IntArray, but that cannot
+        // be sorted with a custom comparator, hence using a typed array.
+        val sortedAbsolutePlacedEffects =
+            Array(absoluteEffectPlacements.size) { 0 }
+                .also { array ->
+                    var index = 0
+                    absoluteEffectPlacements.forEachKey { array[index++] = it }
+                    array.sortBy { EffectPlacement(absoluteEffectPlacements[it]).sortOrder }
+                }
+
+        sortedAbsolutePlacedEffects.forEach { effectId ->
+            val effect = checkNotNull(placedEffects[effectId])
+            val specifiedPlacement = EffectPlacement(absoluteEffectPlacements[effectId])
+            val measuredPlacement = measureEffect(effect, specifiedPlacement)
+            processEffectsPlacedBefore(effectId, measuredPlacement)
+            appendEffect(effectId, specifiedPlacement, measuredPlacement)
+            processEffectsPlacedAfter(effectId, measuredPlacement)
+        }
+
+        if (actualPlacements.last().max != Float.POSITIVE_INFINITY) {
+            sortedEffects.add(NoEffectPlaceholderId)
+            val placeholderPlacement = EffectPlacement.after(actualPlacements.last().max)
+            specifiedPlacements.add(placeholderPlacement)
+            actualPlacements.add(placeholderPlacement)
+        }
+    }
+
+    // ---- MotionSpecBuilderScope implementation --------------------------------------------------
+
+    override fun at(position: Float, effect: Effect.PlaceableAt): PlacedEffect {
+        return addEffect(effect).also {
+            absoluteEffectPlacements[it.id] = EffectPlacement.after(position).value
+        }
+    }
+
+    override fun between(start: Float, end: Float, effect: Effect.PlaceableBetween): PlacedEffect {
+        return addEffect(effect).also {
+            absoluteEffectPlacements[it.id] = EffectPlacement.between(start, end).value
+        }
+    }
+
+    override fun before(position: Float, effect: Effect.PlaceableBefore): PlacedEffect {
+        return addEffect(effect).also {
+            absoluteEffectPlacements[it.id] = EffectPlacement.before(position).value
+        }
+    }
+
+    override fun before(otherEffect: PlacedEffect, effect: Effect.PlaceableBefore): PlacedEffect {
+        require(placedEffects.containsKey(otherEffect.id))
+        require(!relativeEffectPlacements.containsKey(-otherEffect.id))
+        return addEffect(effect).also { relativeEffectPlacements[-otherEffect.id] = it.id }
+    }
+
+    override fun after(position: Float, effect: Effect.PlaceableAfter): PlacedEffect {
+        return addEffect(effect).also {
+            absoluteEffectPlacements[it.id] = EffectPlacement.after(position).value
+        }
+    }
+
+    override fun after(otherEffect: PlacedEffect, effect: Effect.PlaceableAfter): PlacedEffect {
+        require(placedEffects.containsKey(otherEffect.id))
+        require(!relativeEffectPlacements.containsKey(otherEffect.id))
+
+        relativeEffectPlacements.forEach { key, value ->
+            if (value == otherEffect.id) {
+                require(key > 0) {
+                    val other = placedEffects[otherEffect.id]
+                    "Cannot place effect [$effect] *after* [$other], since the latter was placed" +
+                        "*before* an effect"
+                }
+            }
+        }
+
+        require(!relativeEffectPlacements.containsKey(otherEffect.id))
+        return addEffect(effect).also { relativeEffectPlacements[otherEffect.id] = it.id }
+    }
+
+    private fun addEffect(effect: Effect): PlacedEffect {
+        return PlacedEffect(placedEffects.size + 1).also { placedEffects[it.id] = effect }
+    }
+
+    // ----- EffectApplyScope implementation -------------------------------------------------------
+
+    override fun addSegmentHandler(key: SegmentKey, handler: OnChangeSegmentHandler) {
+        require(!segmentHandlers.containsKey(key))
+        segmentHandlers[key] = handler
+    }
+
+    override fun baseValue(position: Float): Float {
+        return baseMapping.map(position)
+    }
+
+    override fun unidirectional(
+        initialMapping: Mapping,
+        semantics: List<SemanticValue<*>>,
+        init: DirectionalEffectBuilderScope.() -> Unit,
+    ) {
+        forward(initialMapping, semantics, init)
+        backward(initialMapping, semantics, init)
+    }
+
+    override fun unidirectional(mapping: Mapping, semantics: List<SemanticValue<*>>) {
+        forward(mapping, semantics)
+        backward(mapping, semantics)
+    }
+
+    override fun forward(
+        initialMapping: Mapping,
+        semantics: List<SemanticValue<*>>,
+        init: DirectionalEffectBuilderScope.() -> Unit,
+    ) {
+        check(!forwardInvoked) { "Cannot define forward spec more than once" }
+        forwardInvoked = true
+
+        forwardBuilder.prepareBuilderFn(initialMapping, semantics)
+        forwardBuilder.init()
+    }
+
+    override fun forward(mapping: Mapping, semantics: List<SemanticValue<*>>) {
+        check(!forwardInvoked) { "Cannot define forward spec more than once" }
+        forwardInvoked = true
+
+        forwardBuilder.prepareBuilderFn(mapping, semantics)
+    }
+
+    override fun backward(
+        initialMapping: Mapping,
+        semantics: List<SemanticValue<*>>,
+        init: DirectionalEffectBuilderScope.() -> Unit,
+    ) {
+        check(!backwardInvoked) { "Cannot define backward spec more than once" }
+        backwardInvoked = true
+
+        reverseBuilder.prepareBuilderFn(initialMapping, semantics)
+        reverseBuilder.init()
+    }
+
+    override fun backward(mapping: Mapping, semantics: List<SemanticValue<*>>) {
+        check(!backwardInvoked) { "Cannot define backward spec more than once" }
+        backwardInvoked = true
+
+        reverseBuilder.prepareBuilderFn(mapping, semantics)
+    }
+
+    private var forwardInvoked = false
+    private var backwardInvoked = false
+
+    private fun applyEffect(
+        effectId: Int,
+        specifiedPlacement: EffectPlacement,
+        actualPlacement: EffectPlacement,
+        minLimitKey: BreakpointKey,
+        maxLimitKey: BreakpointKey,
+    ) {
+        require(minLimitKey != maxLimitKey)
+
+        if (effectId == NoEffectPlaceholderId) {
+            val maxBreakpoint =
+                Breakpoint.create(maxLimitKey, actualPlacement.max, defaultSpring, Guarantee.None)
+            builders.forEach { builder ->
+                builder.mappings += builder.afterMapping ?: baseMapping
+                builder.breakpoints += maxBreakpoint
+            }
+            return
+        }
+
+        val initialForwardSize = forwardBuilder.breakpoints.size
+        val initialReverseSize = reverseBuilder.breakpoints.size
+
+        val effect = checkNotNull(placedEffects[effectId])
+
+        forwardInvoked = false
+        backwardInvoked = false
+
+        builders.forEach { it.resetBeforeAfter() }
+        with(effect) {
+            createSpec(
+                actualPlacement.min,
+                minLimitKey,
+                actualPlacement.max,
+                maxLimitKey,
+                specifiedPlacement,
+            )
+        }
+
+        check(forwardInvoked) { "forward() spec not defined during createSpec()" }
+        check(backwardInvoked) { "backward() spec not defined during createSpec()" }
+
+        builders.forEachIndexed { index, builder ->
+            val initialSize = if (index == 0) initialForwardSize else initialReverseSize
+
+            require(builder.breakpoints[initialSize - 1].key == minLimitKey)
+
+            builder.finalizeBuilderFn(
+                actualPlacement.max,
+                maxLimitKey,
+                builder.afterSpring ?: defaultSpring,
+                builder.afterGuarantee ?: Guarantee.None,
+                builder.afterSemantics ?: emptyList(),
+            )
+            check(builder.breakpoints.size > initialSize)
+
+            if (builder.beforeSpring != null || builder.beforeGuarantee != null) {
+                val oldMinBreakpoint = builder.breakpoints[initialSize - 1]
+                builder.breakpoints[initialSize - 1] =
+                    oldMinBreakpoint.copy(
+                        spring = builder.beforeSpring ?: oldMinBreakpoint.spring,
+                        guarantee = builder.beforeGuarantee ?: oldMinBreakpoint.guarantee,
+                    )
+            }
+
+            builder.beforeMapping
+                ?.takeIf { initialSize >= 2 && builder.mappings[initialSize - 2] === baseMapping }
+                ?.also { builder.mappings[initialSize - 2] = it }
+
+            builder.beforeSemantics?.forEach {
+                builder.getSemantics(it.key).updateBefore(initialSize - 2, it.value)
+            }
+        }
+    }
+
+    companion object {
+        private val NoEffectPlaceholderId = -1
+    }
+}
+
+private class DirectionalEffectBuilderScopeImpl(
+    defaultSpring: SpringParameters,
+    baseSemantics: List<SemanticValue<*>>,
+) : DirectionalBuilderImpl(defaultSpring, baseSemantics), DirectionalEffectBuilderScope {
+
+    var beforeGuarantee: Guarantee? = null
+    var beforeSpring: SpringParameters? = null
+    var beforeSemantics: List<SemanticValue<*>>? = null
+    var beforeMapping: Mapping? = null
+
+    override fun before(
+        spring: SpringParameters?,
+        guarantee: Guarantee?,
+        semantics: List<SemanticValue<*>>?,
+        mapping: Mapping?,
+    ) {
+        beforeGuarantee = guarantee
+        beforeSpring = spring
+        beforeSemantics = semantics
+        beforeMapping = mapping
+    }
+
+    var afterGuarantee: Guarantee? = null
+    var afterSpring: SpringParameters? = null
+    var afterSemantics: List<SemanticValue<*>>? = null
+    var afterMapping: Mapping? = null
+
+    override fun after(
+        spring: SpringParameters?,
+        guarantee: Guarantee?,
+        semantics: List<SemanticValue<*>>?,
+        mapping: Mapping?,
+    ) {
+        afterGuarantee = guarantee
+        afterSpring = spring
+        afterSemantics = semantics
+        afterMapping = mapping
+    }
+
+    fun resetBeforeAfter() {
+        beforeGuarantee = null
+        beforeSpring = null
+        beforeSemantics = null
+        beforeMapping = null
+        afterGuarantee = null
+        afterSpring = null
+        afterSemantics = null
+        afterMapping = null
+    }
+}
+
+private fun MotionBuilderContext.measureEffect(
+    effect: Effect,
+    specifiedPlacement: EffectPlacement,
+): EffectPlacement {
+    return when (specifiedPlacement.type) {
+        EffectPlacemenType.At -> {
+            require(effect is Effect.PlaceableAt)
+            with(effect) {
+                val minExtend = minExtent()
+                require(minExtend.isFinite() && minExtend >= 0)
+                val maxExtend = maxExtent()
+                require(maxExtend.isFinite() && maxExtend >= 0)
+
+                EffectPlacement.between(
+                    specifiedPlacement.start - minExtend,
+                    specifiedPlacement.start + maxExtend,
+                )
+            }
+        }
+
+        EffectPlacemenType.Before -> {
+            require(effect is Effect.PlaceableBefore)
+            with(effect) {
+                val intrinsicSize = intrinsicSize()
+                if (intrinsicSize.isFinite()) {
+                    require(intrinsicSize >= 0)
+
+                    EffectPlacement.between(
+                        specifiedPlacement.start,
+                        specifiedPlacement.start - intrinsicSize,
+                    )
+                } else {
+                    specifiedPlacement
+                }
+            }
+        }
+
+        EffectPlacemenType.After -> {
+            require(effect is Effect.PlaceableAfter)
+            with(effect) {
+                val intrinsicSize = intrinsicSize()
+                if (intrinsicSize.isFinite()) {
+
+                    require(intrinsicSize >= 0)
+
+                    EffectPlacement.between(
+                        specifiedPlacement.start,
+                        specifiedPlacement.start + intrinsicSize,
+                    )
+                } else {
+                    specifiedPlacement
+                }
+            }
+        }
+
+        EffectPlacemenType.Between -> specifiedPlacement
+    }
+}
+
+@JvmInline
+value class MutablePlacementList(val storage: MutableLongList) {
+
+    val size: Int
+        get() = storage.size
+
+    val lastIndex: Int
+        get() = storage.lastIndex
+
+    val indices: IntRange
+        get() = storage.indices
+
+    fun isEmpty() = storage.isEmpty()
+
+    fun isNotEmpty() = storage.isNotEmpty()
+
+    operator fun get(index: Int) = EffectPlacement(storage.get(index))
+
+    fun last() = EffectPlacement(storage.last())
+
+    fun add(element: EffectPlacement) = storage.add(element.value)
+
+    operator fun set(index: Int, element: EffectPlacement) =
+        EffectPlacement(storage.set(index, element.value))
+}
diff --git a/mechanics/src/com/android/mechanics/view/ViewGestureContext.kt b/mechanics/src/com/android/mechanics/view/ViewGestureContext.kt
new file mode 100644
index 0000000..140fe75
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/view/ViewGestureContext.kt
@@ -0,0 +1,135 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.view
+
+import android.content.Context
+import android.view.ViewConfiguration
+import androidx.compose.ui.util.fastForEach
+import com.android.mechanics.spec.InputDirection
+import kotlin.math.max
+import kotlin.math.min
+
+fun interface GestureContextUpdateListener {
+    fun onGestureContextUpdated()
+}
+
+interface ViewGestureContext {
+    val direction: InputDirection
+    val dragOffset: Float
+
+    fun addUpdateCallback(listener: GestureContextUpdateListener)
+
+    fun removeUpdateCallback(listener: GestureContextUpdateListener)
+}
+
+/**
+ * [ViewGestureContext] driven by a gesture distance.
+ *
+ * The direction is determined from the gesture input, where going further than
+ * [directionChangeSlop] in the opposite direction toggles the direction.
+ *
+ * @param initialDragOffset The initial [dragOffset] of the [ViewGestureContext]
+ * @param initialDirection The initial [direction] of the [ViewGestureContext]
+ * @param directionChangeSlop the amount [dragOffset] must be moved in the opposite direction for
+ *   the [direction] to flip.
+ */
+class DistanceGestureContext(
+    initialDragOffset: Float,
+    initialDirection: InputDirection,
+    private val directionChangeSlop: Float,
+) : ViewGestureContext {
+    init {
+        require(directionChangeSlop > 0) {
+            "directionChangeSlop must be greater than 0, was $directionChangeSlop"
+        }
+    }
+
+    companion object {
+        @JvmStatic
+        fun create(
+            context: Context,
+            initialDragOffset: Float = 0f,
+            initialDirection: InputDirection = InputDirection.Max,
+        ): DistanceGestureContext {
+            val directionChangeSlop = ViewConfiguration.get(context).scaledTouchSlop.toFloat()
+            return DistanceGestureContext(initialDragOffset, initialDirection, directionChangeSlop)
+        }
+    }
+
+    private val callbacks = mutableListOf<GestureContextUpdateListener>()
+
+    override var dragOffset: Float = initialDragOffset
+        set(value) {
+            if (field == value) return
+
+            field = value
+            direction =
+                when (direction) {
+                    InputDirection.Max -> {
+                        if (furthestDragOffset - value > directionChangeSlop) {
+                            furthestDragOffset = value
+                            InputDirection.Min
+                        } else {
+                            furthestDragOffset = max(value, furthestDragOffset)
+                            InputDirection.Max
+                        }
+                    }
+
+                    InputDirection.Min -> {
+                        if (value - furthestDragOffset > directionChangeSlop) {
+                            furthestDragOffset = value
+                            InputDirection.Max
+                        } else {
+                            furthestDragOffset = min(value, furthestDragOffset)
+                            InputDirection.Min
+                        }
+                    }
+                }
+            invokeCallbacks()
+        }
+
+    override var direction = initialDirection
+        private set
+
+    private var furthestDragOffset = initialDragOffset
+
+    /**
+     * Sets [dragOffset] and [direction] to the specified values.
+     *
+     * This also resets memoized [furthestDragOffset], which is used to determine the direction
+     * change.
+     */
+    fun reset(dragOffset: Float, direction: InputDirection) {
+        this.dragOffset = dragOffset
+        this.direction = direction
+        this.furthestDragOffset = dragOffset
+
+        invokeCallbacks()
+    }
+
+    override fun addUpdateCallback(listener: GestureContextUpdateListener) {
+        callbacks.add(listener)
+    }
+
+    override fun removeUpdateCallback(listener: GestureContextUpdateListener) {
+        callbacks.remove(listener)
+    }
+
+    private fun invokeCallbacks() {
+        callbacks.fastForEach { it.onGestureContextUpdated() }
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/view/ViewMotionBuilderContext.kt b/mechanics/src/com/android/mechanics/view/ViewMotionBuilderContext.kt
new file mode 100644
index 0000000..5d1a21a
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/view/ViewMotionBuilderContext.kt
@@ -0,0 +1,127 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.view
+
+import android.content.Context
+import androidx.compose.ui.unit.Density
+import com.android.mechanics.spec.builder.MaterialSprings
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spring.SpringParameters
+import com.android.mechanics.view.ViewMaterialSprings.Default
+
+/**
+ * Creates a [MotionBuilderContext] using the **standard** motion spec.
+ *
+ * See go/motion-system.
+ *
+ * @param context The context to derive the density from.
+ */
+fun standardViewMotionBuilderContext(context: Context): MotionBuilderContext {
+    return standardViewMotionBuilderContext(context.resources.displayMetrics.density)
+}
+
+/**
+ * Creates a [MotionBuilderContext] using the **standard** motion spec.
+ *
+ * See go/motion-system.
+ *
+ * @param density The density of the display, as a scaling factor for the dp to px conversion.
+ */
+fun standardViewMotionBuilderContext(density: Float): MotionBuilderContext {
+    return with(ViewMaterialSprings.Default) {
+        ViewMotionBuilderContext(Spatial, Effects, Density(density))
+    }
+}
+
+/**
+ * Creates a [MotionBuilderContext] using the **expressive** motion spec.
+ *
+ * See go/motion-system.
+ *
+ * @param context The context to derive the density from.
+ */
+fun expressiveViewMotionBuilderContext(context: Context): MotionBuilderContext {
+    return expressiveViewMotionBuilderContext(context.resources.displayMetrics.density)
+}
+
+/**
+ * Creates a [MotionBuilderContext] using the **expressive** motion spec.
+ *
+ * See go/motion-system.
+ *
+ * @param density The density of the display, as a scaling factor for the dp to px conversion.
+ */
+fun expressiveViewMotionBuilderContext(density: Float): MotionBuilderContext {
+    return with(ViewMaterialSprings.Expressive) {
+        ViewMotionBuilderContext(Spatial, Effects, Density(density))
+    }
+}
+
+/**
+ * Material motion system spring definitions.
+ *
+ * See go/motion-system.
+ *
+ * NOTE: These are only defined here since material spring parameters are not available for View
+ * based APIs. There might be a delay in updating these values, should the material tokens be
+ * updated in the future.
+ *
+ * @see rememberMotionBuilderContext for Compose
+ */
+object ViewMaterialSprings {
+    object Default {
+        val Spatial =
+            MaterialSprings(
+                SpringParameters(700.0f, 0.9f),
+                SpringParameters(1400.0f, 0.9f),
+                SpringParameters(300.0f, 0.9f),
+                MotionBuilderContext.StableThresholdSpatial,
+            )
+
+        val Effects =
+            MaterialSprings(
+                SpringParameters(1600.0f, 1.0f),
+                SpringParameters(3800.0f, 1.0f),
+                SpringParameters(800.0f, 1.0f),
+                MotionBuilderContext.StableThresholdEffects,
+            )
+    }
+
+    object Expressive {
+        val Spatial =
+            MaterialSprings(
+                SpringParameters(380.0f, 0.8f),
+                SpringParameters(800.0f, 0.6f),
+                SpringParameters(200.0f, 0.8f),
+                MotionBuilderContext.StableThresholdSpatial,
+            )
+
+        val Effects =
+            MaterialSprings(
+                SpringParameters(1600.0f, 1.0f),
+                SpringParameters(3800.0f, 1.0f),
+                SpringParameters(800.0f, 1.0f),
+                MotionBuilderContext.StableThresholdEffects,
+            )
+    }
+}
+
+internal class ViewMotionBuilderContext(
+    override val spatial: MaterialSprings,
+    override val effects: MaterialSprings,
+    density: Density,
+) : MotionBuilderContext, Density by density
diff --git a/mechanics/src/com/android/mechanics/view/ViewMotionValue.kt b/mechanics/src/com/android/mechanics/view/ViewMotionValue.kt
new file mode 100644
index 0000000..617e363
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/view/ViewMotionValue.kt
@@ -0,0 +1,342 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.view
+
+import android.animation.ValueAnimator
+import androidx.compose.ui.util.fastForEach
+import com.android.mechanics.MotionValue.Companion.StableThresholdEffect
+import com.android.mechanics.debug.DebugInspector
+import com.android.mechanics.debug.FrameData
+import com.android.mechanics.impl.Computations
+import com.android.mechanics.impl.DiscontinuityAnimation
+import com.android.mechanics.impl.GuaranteeState
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.MotionSpec
+import com.android.mechanics.spec.SegmentData
+import com.android.mechanics.spec.SegmentKey
+import com.android.mechanics.spec.SemanticKey
+import com.android.mechanics.spring.SpringState
+import java.util.concurrent.atomic.AtomicInteger
+import kotlinx.coroutines.DisposableHandle
+
+/** Observe MotionValue output changes. */
+fun interface ViewMotionValueListener {
+    /** Invoked whenever the ViewMotionValue computed a new output. */
+    fun onMotionValueUpdated(motionValue: ViewMotionValue)
+}
+
+/**
+ * [MotionValue] implementation for View-based UIs.
+ *
+ * See the documentation of [MotionValue].
+ */
+class ViewMotionValue
+@JvmOverloads
+constructor(
+    initialInput: Float,
+    gestureContext: ViewGestureContext,
+    initialSpec: MotionSpec = MotionSpec.Empty,
+    label: String? = null,
+    stableThreshold: Float = StableThresholdEffect,
+) : DisposableHandle {
+
+    private val impl =
+        ImperativeComputations(
+            this,
+            initialInput,
+            gestureContext,
+            initialSpec,
+            stableThreshold,
+            label,
+        )
+
+    var input: Float by impl::currentInput
+
+    var spec: MotionSpec by impl::spec
+
+    /** Animated [output] value. */
+    val output: Float by impl::output
+
+    /**
+     * [output] value, but without animations.
+     *
+     * This value always reports the target value, even before a animation is finished.
+     *
+     * While [isStable], [outputTarget] and [output] are the same value.
+     */
+    val outputTarget: Float by impl::outputTarget
+
+    /** Whether an animation is currently running. */
+    val isStable: Boolean by impl::isStable
+
+    /**
+     * The current value for the [SemanticKey].
+     *
+     * `null` if not defined in the spec.
+     */
+    operator fun <T> get(key: SemanticKey<T>): T? {
+        return impl.semanticState(key)
+    }
+
+    /** The current segment used to compute the output. */
+    val segmentKey: SegmentKey
+        get() = impl.currentComputedValues.segment.key
+
+    val label: String? by impl::label
+
+    fun addUpdateCallback(listener: ViewMotionValueListener) {
+        check(impl.isActive)
+        impl.listeners.add(listener)
+    }
+
+    fun removeUpdateCallback(listener: ViewMotionValueListener) {
+        impl.listeners.remove(listener)
+    }
+
+    override fun dispose() {
+        impl.dispose()
+    }
+
+    companion object {
+        internal const val TAG = "ViewMotionValue"
+    }
+
+    private var debugInspectorRefCount = AtomicInteger(0)
+
+    private fun onDisposeDebugInspector() {
+        if (debugInspectorRefCount.decrementAndGet() == 0) {
+            impl.debugInspector = null
+        }
+    }
+
+    /**
+     * Provides access to internal state for debug tooling and tests.
+     *
+     * The returned [DebugInspector] must be [DebugInspector.dispose]d when no longer needed.
+     */
+    fun debugInspector(): DebugInspector {
+        if (debugInspectorRefCount.getAndIncrement() == 0) {
+            impl.debugInspector =
+                DebugInspector(
+                    FrameData(
+                        impl.lastInput,
+                        impl.lastSegment.direction,
+                        impl.lastGestureDragOffset,
+                        impl.lastFrameTimeNanos,
+                        impl.lastSpringState,
+                        impl.lastSegment,
+                        impl.lastAnimation,
+                    ),
+                    impl.isActive,
+                    impl.animationFrameDriver.isRunning,
+                    ::onDisposeDebugInspector,
+                )
+        }
+
+        return checkNotNull(impl.debugInspector)
+    }
+}
+
+private class ImperativeComputations(
+    private val motionValue: ViewMotionValue,
+    initialInput: Float,
+    val gestureContext: ViewGestureContext,
+    initialSpec: MotionSpec,
+    override val stableThreshold: Float,
+    override val label: String?,
+) : Computations(), GestureContextUpdateListener {
+
+    init {
+        gestureContext.addUpdateCallback(this)
+    }
+
+    override fun onGestureContextUpdated() {
+        ensureFrameRequested()
+    }
+
+    // ----  CurrentFrameInput ---------------------------------------------------------------------
+
+    override var spec: MotionSpec = initialSpec
+        set(value) {
+            if (field != value) {
+                field = value
+                ensureFrameRequested()
+            }
+        }
+
+    override var currentInput: Float = initialInput
+        set(value) {
+            if (field != value) {
+                field = value
+                ensureFrameRequested()
+            }
+        }
+
+    override val currentDirection: InputDirection
+        get() = gestureContext.direction
+
+    override val currentGestureDragOffset: Float
+        get() = gestureContext.dragOffset
+
+    override var currentAnimationTimeNanos: Long = -1L
+
+    // ----  LastFrameState ---------------------------------------------------------------------
+
+    override var lastSegment: SegmentData = spec.segmentAtInput(currentInput, currentDirection)
+    override var lastGuaranteeState: GuaranteeState = GuaranteeState.Inactive
+    override var lastAnimation: DiscontinuityAnimation = DiscontinuityAnimation.None
+    override var lastSpringState: SpringState = lastAnimation.springStartState
+    override var lastFrameTimeNanos: Long = -1L
+    override var lastInput: Float = currentInput
+    override var lastGestureDragOffset: Float = currentGestureDragOffset
+    override var directMappedVelocity: Float = 0f
+    var lastDirection: InputDirection = currentDirection
+
+    // ---- Lifecycle ------------------------------------------------------------------------------
+
+    // HACK: Use a ValueAnimator to listen to animation frames without using Choreographer directly.
+    // This is done solely for testability - because the AnimationHandler is not usable directly[1],
+    // this resumes/pauses a - for all practical purposes - infinite animation.
+    //
+    // [1] the android one is hidden API, the androidx one is package private, and the
+    // dynamicanimation one is not controllable from tests).
+    val animationFrameDriver =
+        ValueAnimator().apply {
+            setFloatValues(Float.MIN_VALUE, Float.MAX_VALUE)
+            duration = Long.MAX_VALUE
+            repeatMode = ValueAnimator.RESTART
+            repeatCount = ValueAnimator.INFINITE
+            start()
+            pause()
+            addUpdateListener {
+                val isAnimationFinished = updateOutputValue(currentPlayTime)
+                if (isAnimationFinished) {
+                    pause()
+                }
+            }
+        }
+
+    fun ensureFrameRequested() {
+        if (animationFrameDriver.isPaused) {
+            animationFrameDriver.resume()
+            debugInspector?.isAnimating = true
+        }
+    }
+
+    fun pauseFrameRequests() {
+        if (animationFrameDriver.isRunning) {
+            animationFrameDriver.pause()
+            debugInspector?.isAnimating = false
+        }
+    }
+
+    /** `true` until disposed with [MotionValue.dispose]. */
+    var isActive = true
+        set(value) {
+            field = value
+            debugInspector?.isActive = value
+        }
+
+    var debugInspector: DebugInspector? = null
+
+    val listeners = mutableListOf<ViewMotionValueListener>()
+
+    fun dispose() {
+        check(isActive) { "ViewMotionValue[$label] is already disposed" }
+        pauseFrameRequests()
+        animationFrameDriver.end()
+        isActive = false
+        listeners.clear()
+    }
+
+    // indicates whether doAnimationFrame is called continuously (as opposed to being
+    // suspended for an undetermined amount of time in between frames).
+    var isAnimatingUninterrupted = false
+
+    fun updateOutputValue(frameTimeMillis: Long): Boolean {
+        check(isActive) { "ViewMotionValue($label) is already disposed." }
+
+        currentAnimationTimeNanos = frameTimeMillis * 1_000_000L
+
+        // Read currentComputedValues only once and update it, if necessary
+        val currentValues = currentComputedValues
+
+        debugInspector?.run {
+            frame =
+                FrameData(
+                    currentInput,
+                    currentDirection,
+                    currentGestureDragOffset,
+                    currentAnimationTimeNanos,
+                    currentSpringState,
+                    currentValues.segment,
+                    currentValues.animation,
+                )
+        }
+
+        listeners.fastForEach { it.onMotionValueUpdated(motionValue) }
+
+        // Prepare last* state
+        if (isAnimatingUninterrupted) {
+            directMappedVelocity =
+                computeDirectMappedVelocity(currentAnimationTimeNanos - lastFrameTimeNanos)
+        } else {
+            directMappedVelocity = 0f
+        }
+
+        var isAnimationFinished = isStable
+        if (lastSegment != currentValues.segment) {
+            lastSegment = currentValues.segment
+            isAnimationFinished = false
+        }
+
+        if (lastGuaranteeState != currentValues.guarantee) {
+            lastGuaranteeState = currentValues.guarantee
+            isAnimationFinished = false
+        }
+
+        if (lastAnimation != currentValues.animation) {
+            lastAnimation = currentValues.animation
+            isAnimationFinished = false
+        }
+
+        if (lastSpringState != currentSpringState) {
+            lastSpringState = currentSpringState
+            isAnimationFinished = false
+        }
+
+        if (lastInput != currentInput) {
+            lastInput = currentInput
+            isAnimationFinished = false
+        }
+
+        if (lastGestureDragOffset != currentGestureDragOffset) {
+            lastGestureDragOffset = currentGestureDragOffset
+            isAnimationFinished = false
+        }
+
+        if (lastDirection != currentDirection) {
+            lastDirection = currentDirection
+            isAnimationFinished = false
+        }
+
+        lastFrameTimeNanos = currentAnimationTimeNanos
+        isAnimatingUninterrupted = !isAnimationFinished
+
+        return isAnimationFinished
+    }
+}
diff --git a/mechanics/testing/Android.bp b/mechanics/testing/Android.bp
new file mode 100644
index 0000000..ac49d16
--- /dev/null
+++ b/mechanics/testing/Android.bp
@@ -0,0 +1,37 @@
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_motion",
+}
+
+android_library {
+    name: "mechanics-testing",
+    manifest: "AndroidManifest.xml",
+    srcs: [
+        "src/**/*.kt",
+    ],
+    static_libs: [
+        "//frameworks/libs/systemui/mechanics:mechanics",
+        "platform-test-annotations",
+        "PlatformMotionTestingCompose",
+        "androidx.compose.runtime_runtime",
+        "androidx.compose.ui_ui-test-junit4",
+        "testables",
+        "truth",
+    ],
+    kotlincflags: ["-Xjvm-default=all"],
+}
diff --git a/mechanics/testing/AndroidManifest.xml b/mechanics/testing/AndroidManifest.xml
new file mode 100644
index 0000000..20c40b0
--- /dev/null
+++ b/mechanics/testing/AndroidManifest.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.mechanics.testing">
+</manifest>
diff --git a/mechanics/testing/src/com/android/mechanics/testing/ComposeMotionValueToolkit.kt b/mechanics/testing/src/com/android/mechanics/testing/ComposeMotionValueToolkit.kt
new file mode 100644
index 0000000..0144a16
--- /dev/null
+++ b/mechanics/testing/src/com/android/mechanics/testing/ComposeMotionValueToolkit.kt
@@ -0,0 +1,176 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+@file:OptIn(ExperimentalCoroutinesApi::class)
+
+package com.android.mechanics.testing
+
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableFloatStateOf
+import androidx.compose.runtime.setValue
+import androidx.compose.runtime.snapshots.Snapshot
+import com.android.mechanics.DistanceGestureContext
+import com.android.mechanics.MotionValue
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.MotionSpec
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.drop
+import kotlinx.coroutines.flow.take
+import kotlinx.coroutines.flow.takeWhile
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.runBlocking
+import platform.test.motion.MotionTestRule
+import platform.test.motion.compose.runMonotonicClockTest
+import platform.test.motion.golden.FrameId
+import platform.test.motion.golden.TimeSeries
+import platform.test.motion.golden.TimestampFrameId
+
+/** Toolkit to support [MotionValue] motion tests. */
+data object ComposeMotionValueToolkit : MotionValueToolkit<MotionValue, DistanceGestureContext>() {
+
+    override fun goldenTest(
+        motionTestRule: MotionTestRule<*>,
+        spec: MotionSpec,
+        createDerived: (underTest: MotionValue) -> List<MotionValue>,
+        initialValue: Float,
+        initialDirection: InputDirection,
+        directionChangeSlop: Float,
+        stableThreshold: Float,
+        verifyTimeSeries: TimeSeries.() -> VerifyTimeSeriesResult,
+        capture: CaptureTimeSeriesFn,
+        testInput: suspend InputScope<MotionValue, DistanceGestureContext>.() -> Unit,
+    ) = runMonotonicClockTest {
+        val frameEmitter = MutableStateFlow<Long>(0)
+
+        val testHarness =
+            ComposeMotionValueTestHarness(
+                initialValue,
+                initialDirection,
+                spec,
+                stableThreshold,
+                directionChangeSlop,
+                frameEmitter.asStateFlow(),
+                createDerived,
+            )
+        val underTest = testHarness.underTest
+        val derived = testHarness.derived
+
+        val motionValueCaptures = buildList {
+            add(MotionValueCapture(underTest.debugInspector()))
+            derived.forEach { add(MotionValueCapture(it.debugInspector(), "${it.label}-")) }
+        }
+
+        val keepRunningJobs = (derived + underTest).map { launch { it.keepRunning() } }
+
+        val recordingJob = launch { testInput.invoke(testHarness) }
+
+        val frameIds = mutableListOf<FrameId>()
+
+        fun recordFrame(frameId: TimestampFrameId) {
+            frameIds.add(frameId)
+            motionValueCaptures.forEach { it.captureCurrentFrame(capture) }
+        }
+        runBlocking(Dispatchers.Main) {
+            val startFrameTime = testScheduler.currentTime
+            while (!recordingJob.isCompleted) {
+                recordFrame(TimestampFrameId(testScheduler.currentTime - startFrameTime))
+
+                // Emulate setting input *before* the frame advances. This ensures the `testInput`
+                // coroutine will continue if needed. The specific value for frameEmitter is
+                // irrelevant, it only requires to be unique per frame.
+                frameEmitter.tryEmit(testScheduler.currentTime)
+                testScheduler.runCurrent()
+                // Whenever keepRunning was suspended, allow the snapshotFlow to wake up
+                Snapshot.sendApplyNotifications()
+
+                // Now advance the test clock
+                testScheduler.advanceTimeBy(FrameDuration)
+                // Since the tests capture the debugInspector output, make sure keepRunning()
+                // was able to complete the frame.
+                testScheduler.runCurrent()
+            }
+        }
+
+        val timeSeries = createTimeSeries(frameIds, motionValueCaptures)
+        motionValueCaptures.forEach { it.debugger.dispose() }
+        keepRunningJobs.forEach { it.cancel() }
+        verifyTimeSeries(motionTestRule, timeSeries, verifyTimeSeries)
+    }
+}
+
+private class ComposeMotionValueTestHarness(
+    initialInput: Float,
+    initialDirection: InputDirection,
+    spec: MotionSpec,
+    stableThreshold: Float,
+    directionChangeSlop: Float,
+    val onFrame: StateFlow<Long>,
+    createDerived: (underTest: MotionValue) -> List<MotionValue>,
+) : InputScope<MotionValue, DistanceGestureContext> {
+
+    override var input by mutableFloatStateOf(initialInput)
+    override val gestureContext: DistanceGestureContext =
+        DistanceGestureContext(initialInput, initialDirection, directionChangeSlop)
+
+    override val underTest =
+        MotionValue(
+            { input },
+            gestureContext,
+            stableThreshold = stableThreshold,
+            initialSpec = spec,
+        )
+
+    val derived = createDerived(underTest)
+
+    override fun updateInput(value: Float) {
+        input = value
+        gestureContext.dragOffset = value
+    }
+
+    override suspend fun awaitStable() {
+        val debugInspectors = buildList {
+            add(underTest.debugInspector())
+            addAll(derived.map { it.debugInspector() })
+        }
+        try {
+
+            onFrame
+                // Since this is a state-flow, the current frame is counted too.
+                .drop(1)
+                .takeWhile { debugInspectors.any { !it.frame.isStable } }
+                .collect {}
+        } finally {
+            debugInspectors.forEach { it.dispose() }
+        }
+    }
+
+    override suspend fun awaitFrames(frames: Int) {
+        onFrame
+            // Since this is a state-flow, the current frame is counted too.
+            .drop(1)
+            .take(frames)
+            .collect {}
+    }
+
+    override fun reset(position: Float, direction: InputDirection) {
+        input = position
+        gestureContext.reset(position, direction)
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/testing/DataPointTypes.kt b/mechanics/testing/src/com/android/mechanics/testing/DataPointTypes.kt
similarity index 67%
rename from mechanics/tests/src/com/android/mechanics/testing/DataPointTypes.kt
rename to mechanics/testing/src/com/android/mechanics/testing/DataPointTypes.kt
index 21c2f09..013a0dd 100644
--- a/mechanics/tests/src/com/android/mechanics/testing/DataPointTypes.kt
+++ b/mechanics/testing/src/com/android/mechanics/testing/DataPointTypes.kt
@@ -17,13 +17,17 @@
 package com.android.mechanics.testing
 
 import com.android.mechanics.spring.SpringParameters
+import com.android.mechanics.spring.SpringState
 import com.android.mechanics.testing.DataPointTypes.springParameters
+import com.android.mechanics.testing.DataPointTypes.springState
 import org.json.JSONObject
 import platform.test.motion.golden.DataPointType
 import platform.test.motion.golden.UnknownTypeException
 
 fun SpringParameters.asDataPoint() = springParameters.makeDataPoint(this)
 
+fun SpringState.asDataPoint() = springState.makeDataPoint(this)
+
 object DataPointTypes {
     val springParameters: DataPointType<SpringParameters> =
         DataPointType(
@@ -43,4 +47,23 @@ object DataPointTypes {
                 }
             },
         )
+
+    val springState: DataPointType<SpringState> =
+        DataPointType(
+            "springState",
+            jsonToValue = {
+                with(it as? JSONObject ?: throw UnknownTypeException()) {
+                    SpringState(
+                        getDouble("displacement").toFloat(),
+                        getDouble("velocity").toFloat(),
+                    )
+                }
+            },
+            valueToJson = {
+                JSONObject().apply {
+                    put("displacement", it.displacement)
+                    put("velocity", it.velocity)
+                }
+            },
+        )
 }
diff --git a/mechanics/testing/src/com/android/mechanics/testing/FakeMotionSpecBuilderContext.kt b/mechanics/testing/src/com/android/mechanics/testing/FakeMotionSpecBuilderContext.kt
new file mode 100644
index 0000000..93855f4
--- /dev/null
+++ b/mechanics/testing/src/com/android/mechanics/testing/FakeMotionSpecBuilderContext.kt
@@ -0,0 +1,54 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.testing
+
+import androidx.compose.ui.unit.Density
+import com.android.mechanics.spec.builder.MaterialSprings
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spring.SpringParameters
+
+/**
+ * [MotionBuilderContext] implementation for unit tests.
+ *
+ * Only use when the specifics of the spring parameters do not matter for the test.
+ *
+ * While the values are copied from the current material motion tokens, this can (and likely will)
+ * get out of sync with the material tokens, and is not intended reflect the up-to-date tokens, but
+ * provide a stable definitions of "some" spring parameters.
+ */
+class FakeMotionSpecBuilderContext(density: Float = 1f) :
+    MotionBuilderContext, Density by Density(density) {
+    override val spatial =
+        MaterialSprings(
+            SpringParameters(700.0f, 0.9f),
+            SpringParameters(1400.0f, 0.9f),
+            SpringParameters(300.0f, 0.9f),
+            MotionBuilderContext.StableThresholdSpatial,
+        )
+
+    override val effects =
+        MaterialSprings(
+            SpringParameters(1600.0f, 1.0f),
+            SpringParameters(3800.0f, 1.0f),
+            SpringParameters(800.0f, 1.0f),
+            MotionBuilderContext.StableThresholdEffects,
+        )
+
+    companion object {
+        val Default = FakeMotionSpecBuilderContext()
+    }
+}
diff --git a/mechanics/testing/src/com/android/mechanics/testing/FeatureCaptures.kt b/mechanics/testing/src/com/android/mechanics/testing/FeatureCaptures.kt
new file mode 100644
index 0000000..d8ef1cf
--- /dev/null
+++ b/mechanics/testing/src/com/android/mechanics/testing/FeatureCaptures.kt
@@ -0,0 +1,71 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.testing
+
+import com.android.mechanics.debug.DebugInspector
+import com.android.mechanics.spec.SemanticKey
+import com.android.mechanics.spring.SpringParameters
+import com.android.mechanics.spring.SpringState
+import platform.test.motion.golden.DataPointType
+import platform.test.motion.golden.FeatureCapture
+import platform.test.motion.golden.asDataPoint
+
+/** Feature captures on MotionValue's [DebugInspector] */
+object FeatureCaptures {
+    /** Input value of the current frame. */
+    val input = FeatureCapture<DebugInspector, Float>("input") { it.frame.input.asDataPoint() }
+
+    /** Gesture direction of the current frame. */
+    val gestureDirection =
+        FeatureCapture<DebugInspector, String>("gestureDirection") {
+            it.frame.gestureDirection.name.asDataPoint()
+        }
+
+    /** Animated output value of the current frame. */
+    val output = FeatureCapture<DebugInspector, Float>("output") { it.frame.output.asDataPoint() }
+
+    /** Output target value of the current frame. */
+    val outputTarget =
+        FeatureCapture<DebugInspector, Float>("outputTarget") {
+            it.frame.outputTarget.asDataPoint()
+        }
+
+    /** Spring parameters currently in use. */
+    val springParameters =
+        FeatureCapture<DebugInspector, SpringParameters>("springParameters") {
+            it.frame.springParameters.asDataPoint()
+        }
+
+    /** Spring state currently in use. */
+    val springState =
+        FeatureCapture<DebugInspector, SpringState>("springState") {
+            it.frame.springState.asDataPoint()
+        }
+
+    /** Whether the spring is currently stable. */
+    val isStable =
+        FeatureCapture<DebugInspector, Boolean>("isStable") { it.frame.isStable.asDataPoint() }
+
+    /** A semantic value to capture in the golden. */
+    fun <T> semantics(
+        key: SemanticKey<T>,
+        dataPointType: DataPointType<T & Any>,
+        name: String = key.debugLabel,
+    ): FeatureCapture<DebugInspector, T & Any> {
+        return FeatureCapture(name) { dataPointType.makeDataPoint(it.frame.semantic(key)) }
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/testing/MotionSpecSubject.kt b/mechanics/testing/src/com/android/mechanics/testing/MotionSpecSubject.kt
similarity index 61%
rename from mechanics/tests/src/com/android/mechanics/testing/MotionSpecSubject.kt
rename to mechanics/testing/src/com/android/mechanics/testing/MotionSpecSubject.kt
index cd58a48..9816d01 100644
--- a/mechanics/tests/src/com/android/mechanics/testing/MotionSpecSubject.kt
+++ b/mechanics/testing/src/com/android/mechanics/testing/MotionSpecSubject.kt
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -20,9 +20,11 @@ import com.android.mechanics.spec.Breakpoint
 import com.android.mechanics.spec.BreakpointKey
 import com.android.mechanics.spec.DirectionalMotionSpec
 import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.MotionSpec
+import com.android.mechanics.spec.SemanticKey
 import com.android.mechanics.testing.BreakpointSubject.Companion.BreakpointKeys
 import com.android.mechanics.testing.BreakpointSubject.Companion.BreakpointPositions
-import com.google.common.truth.Correspondence
+import com.google.common.truth.Correspondence.transforming
 import com.google.common.truth.FailureMetadata
 import com.google.common.truth.FloatSubject
 import com.google.common.truth.IterableSubject
@@ -30,6 +32,48 @@ import com.google.common.truth.Subject
 import com.google.common.truth.Subject.Factory
 import com.google.common.truth.Truth
 
+/** Subject to verify the definition of a [MotionSpec]. */
+class MotionSpecSubject
+internal constructor(failureMetadata: FailureMetadata, private val actual: MotionSpec?) :
+    Subject(failureMetadata, actual) {
+
+    fun minDirection(): DirectionalMotionSpecSubject {
+        isNotNull()
+
+        return check("min")
+            .about(DirectionalMotionSpecSubject.SubjectFactory)
+            .that(actual?.minDirection)
+    }
+
+    fun maxDirection(): DirectionalMotionSpecSubject {
+        isNotNull()
+
+        return check("max")
+            .about(DirectionalMotionSpecSubject.SubjectFactory)
+            .that(actual?.maxDirection)
+    }
+
+    fun bothDirections(): DirectionalMotionSpecSubject {
+        isNotNull()
+        check("both directions same").that(actual?.minDirection).isEqualTo(actual?.maxDirection)
+        return check("both")
+            .about(DirectionalMotionSpecSubject.SubjectFactory)
+            .that(actual?.maxDirection)
+    }
+
+    companion object {
+
+        /** Returns a factory to be used with [Truth.assertAbout]. */
+        val SubjectFactory = Factory { failureMetadata: FailureMetadata, subject: MotionSpec? ->
+            MotionSpecSubject(failureMetadata, subject)
+        }
+
+        /** Shortcut for `Truth.assertAbout(motionSpec()).that(spec)`. */
+        fun assertThat(spec: MotionSpec): MotionSpecSubject =
+            Truth.assertAbout(SubjectFactory).that(spec)
+    }
+}
+
 /** Subject to verify the definition of a [DirectionalMotionSpec]. */
 class DirectionalMotionSpecSubject
 internal constructor(failureMetadata: FailureMetadata, private val actual: DirectionalMotionSpec?) :
@@ -42,6 +86,17 @@ internal constructor(failureMetadata: FailureMetadata, private val actual: Direc
         return check("breakpoints").about(BreakpointsSubject.SubjectFactory).that(actual)
     }
 
+    fun breakpointsPositionsMatch(vararg positions: Float) {
+        isNotNull()
+
+        return check("breakpoints")
+            .about(BreakpointsSubject.SubjectFactory)
+            .that(actual)
+            .positions()
+            .containsExactlyElementsIn(positions.toTypedArray())
+            .inOrder()
+    }
+
     /** Assert on the mappings. */
     fun mappings(): MappingsSubject {
         isNotNull()
@@ -49,18 +104,49 @@ internal constructor(failureMetadata: FailureMetadata, private val actual: Direc
         return check("mappings").about(MappingsSubject.SubjectFactory).that(actual)
     }
 
+    /** Assert that the mappings contain exactly the specified mappings, in order . */
+    fun mappingsMatch(vararg mappings: Mapping) {
+        isNotNull()
+
+        check("mappings")
+            .about(MappingsSubject.SubjectFactory)
+            .that(actual)
+            .containsExactlyElementsIn(mappings)
+            .inOrder()
+    }
+
+    /** Assert that the mappings contain exactly the specified [Fixed] mappings, in order . */
+    fun fixedMappingsMatch(vararg fixedMappingValues: Float) {
+        isNotNull()
+
+        check("fixed mappings")
+            .about(MappingsSubject.SubjectFactory)
+            .that(actual)
+            .comparingElementsUsing(
+                transforming<Mapping, Float?>({ (it as? Mapping.Fixed)?.value }, "Fixed.value")
+            )
+            .containsExactlyElementsIn(fixedMappingValues.toTypedArray())
+            .inOrder()
+    }
+
+    /** Assert on the semantics. */
+    fun semantics(): SemanticsSubject {
+        isNotNull()
+
+        return check("semantics").about(SemanticsSubject.SubjectFactory).that(actual)
+    }
+
     companion object {
 
         /** Returns a factory to be used with [Truth.assertAbout]. */
-        fun directionalMotionSpec(): Factory<DirectionalMotionSpecSubject, DirectionalMotionSpec> {
-            return Factory { failureMetadata: FailureMetadata, subject: DirectionalMotionSpec? ->
+        val SubjectFactory =
+            Factory { failureMetadata: FailureMetadata, subject: DirectionalMotionSpec? ->
                 DirectionalMotionSpecSubject(failureMetadata, subject)
             }
-        }
 
         /** Shortcut for `Truth.assertAbout(directionalMotionSpec()).that(spec)`. */
         fun assertThat(spec: DirectionalMotionSpec): DirectionalMotionSpecSubject =
-            Truth.assertAbout(directionalMotionSpec()).that(spec)
+            Truth.assertAbout(SubjectFactory).that(spec)
     }
 }
 
@@ -126,10 +212,8 @@ internal constructor(failureMetadata: FailureMetadata, private val actual: Break
     fun hasKey(key: BreakpointKey) = key().isEqualTo(key)
 
     companion object {
-        val BreakpointKeys =
-            Correspondence.transforming<Breakpoint, BreakpointKey>({ it.key }, "key")
-        val BreakpointPositions =
-            Correspondence.transforming<Breakpoint, Float>({ it.position }, "position")
+        val BreakpointKeys = transforming<Breakpoint, BreakpointKey?>({ it?.key }, "key")
+        val BreakpointPositions = transforming<Breakpoint, Float?>({ it?.position }, "position")
 
         /** Returns a factory to be used with [Truth.assertAbout]. */
         val SubjectFactory =
@@ -177,7 +261,7 @@ internal constructor(failureMetadata: FailureMetadata, private val actual: Mappi
         check("input @ $in2").that(actual?.map(in2)).isEqualTo(out2)
     }
 
-    fun isConstantValue(value: Float) {
+    fun isFixedValue(value: Float) {
         when (actual) {
             is Mapping.Fixed -> check("fixed value").that(actual.value).isEqualTo(value)
             is Mapping.Linear -> {
@@ -201,3 +285,24 @@ internal constructor(failureMetadata: FailureMetadata, private val actual: Mappi
             Truth.assertAbout(SubjectFactory).that(mapping)
     }
 }
+
+/** Subject to assert on the list of semantic values of a [DirectionalMotionSpec]. */
+class SemanticsSubject(
+    failureMetadata: FailureMetadata,
+    private val actual: DirectionalMotionSpec?,
+) : IterableSubject(failureMetadata, actual?.semantics?.map { it.key }) {
+
+    /** Assert on the semantic values of the. */
+    fun withKey(key: SemanticKey<*>): IterableSubject {
+        return check("semantic $key")
+            .that(actual?.run { semantics.firstOrNull { it.key == key }?.values })
+    }
+
+    companion object {
+        /** Returns a factory to be used with [Truth.assertAbout]. */
+        val SubjectFactory =
+            Factory<SemanticsSubject, DirectionalMotionSpec> { failureMetadata, subject ->
+                SemanticsSubject(failureMetadata, subject)
+            }
+    }
+}
diff --git a/mechanics/testing/src/com/android/mechanics/testing/MotionValueToolkit.kt b/mechanics/testing/src/com/android/mechanics/testing/MotionValueToolkit.kt
new file mode 100644
index 0000000..a96ca99
--- /dev/null
+++ b/mechanics/testing/src/com/android/mechanics/testing/MotionValueToolkit.kt
@@ -0,0 +1,230 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.testing
+
+import com.android.mechanics.MotionValue
+import com.android.mechanics.debug.DebugInspector
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.MotionSpec
+import kotlin.math.abs
+import kotlin.math.floor
+import kotlin.math.sign
+import kotlin.time.Duration.Companion.milliseconds
+import platform.test.motion.MotionTestRule
+import platform.test.motion.RecordedMotion.Companion.create
+import platform.test.motion.golden.DataPoint
+import platform.test.motion.golden.Feature
+import platform.test.motion.golden.FrameId
+import platform.test.motion.golden.TimeSeries
+import platform.test.motion.golden.TimeSeriesCaptureScope
+
+/**
+ * Records and verifies a timeseries of the [MotionValue]'s output.
+ *
+ * Tests provide at a minimum the initial [spec], and a [testInput] function, which defines the
+ * [MotionValue] input over time.
+ *
+ * @param spec The initial [MotionSpec]
+ * @param initialValue The initial value of the [MotionValue]
+ * @param initialDirection The initial [InputDirection] of the [MotionValue]
+ * @param directionChangeSlop the minimum distance for the input to change in the opposite direction
+ *   before the underlying GestureContext changes direction.
+ * @param stableThreshold The maximum remaining oscillation amplitude for the springs to be
+ *   considered stable.
+ * @param verifyTimeSeries Custom verification function to write assertions on the captured time
+ *   series. If the function returns `SkipGoldenVerification`, the timeseries won`t be compared to a
+ *   golden.
+ * @param createDerived (experimental) Creates derived MotionValues
+ * @param capture The features to capture on each motion value. See [defaultFeatureCaptures] for
+ *   defaults.
+ * @param testInput Controls the MotionValue during the test. The timeseries is being recorded until
+ *   the function completes.
+ * @see ComposeMotionValueToolkit
+ * @see ViewMotionValueToolkit
+ */
+fun <
+    T : MotionValueToolkit<MotionValueType, GestureContextType>,
+    MotionValueType,
+    GestureContextType,
+> MotionTestRule<T>.goldenTest(
+    spec: MotionSpec,
+    initialValue: Float = 0f,
+    initialDirection: InputDirection = InputDirection.Max,
+    directionChangeSlop: Float = 5f,
+    stableThreshold: Float = 0.01f,
+    verifyTimeSeries: VerifyTimeSeriesFn = {
+        VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden()
+    },
+    createDerived: (underTest: MotionValueType) -> List<MotionValueType> = { emptyList() },
+    capture: CaptureTimeSeriesFn = defaultFeatureCaptures,
+    testInput: suspend (InputScope<MotionValueType, GestureContextType>).() -> Unit,
+) {
+    toolkit.goldenTest(
+        this,
+        spec,
+        createDerived,
+        initialValue,
+        initialDirection,
+        directionChangeSlop,
+        stableThreshold,
+        verifyTimeSeries,
+        capture,
+        testInput,
+    )
+}
+
+/** Scope to control the MotionValue during a test. */
+interface InputScope<MotionValueType, GestureContextType> {
+    /** Current input of the `MotionValue` */
+    val input: Float
+    /** GestureContext created for the `MotionValue` */
+    val gestureContext: GestureContextType
+    /** MotionValue being tested. */
+    val underTest: MotionValueType
+
+    /** Updates the input value *and* the `gestureContext.dragOffset`. */
+    fun updateInput(value: Float)
+
+    /** Resets the input value *and* the `gestureContext.dragOffset`, inclusive of direction. */
+    fun reset(position: Float, direction: InputDirection)
+
+    /** Waits for `underTest` and derived `MotionValues` to become stable. */
+    suspend fun awaitStable()
+
+    /** Waits for the next "frame" (16ms). */
+    suspend fun awaitFrames(frames: Int = 1)
+}
+
+/** Animates the input linearly from the current [input] to the [targetValue]. */
+suspend fun InputScope<*, *>.animateValueTo(
+    targetValue: Float,
+    changePerFrame: Float = abs(input - targetValue) / 5f,
+) {
+    require(changePerFrame > 0f)
+    var currentValue = input
+    val delta = targetValue - currentValue
+    val step = changePerFrame * delta.sign
+
+    val stepCount = floor((abs(delta) / changePerFrame) - 1).toInt()
+    repeat(stepCount) {
+        currentValue += step
+        updateInput(currentValue)
+        awaitFrames()
+    }
+
+    updateInput(targetValue)
+    awaitFrames()
+}
+
+/** Sets the input to the [values], one value per frame. */
+suspend fun InputScope<*, *>.animatedInputSequence(vararg values: Float) {
+    values.forEach {
+        updateInput(it)
+        awaitFrames()
+    }
+}
+
+/** Custom functions to write assertions on the recorded [TimeSeries] */
+typealias VerifyTimeSeriesFn = TimeSeries.() -> VerifyTimeSeriesResult
+
+/** [VerifyTimeSeriesFn] indicating whether the timeseries should be verified the golden file. */
+interface VerifyTimeSeriesResult {
+    data object SkipGoldenVerification : VerifyTimeSeriesResult
+
+    data class AssertTimeSeriesMatchesGolden(val goldenName: String? = null) :
+        VerifyTimeSeriesResult
+}
+
+typealias CaptureTimeSeriesFn = TimeSeriesCaptureScope<DebugInspector>.() -> Unit
+
+/** Default feature captures. */
+val defaultFeatureCaptures: CaptureTimeSeriesFn = {
+    feature(FeatureCaptures.input)
+    feature(FeatureCaptures.gestureDirection)
+    feature(FeatureCaptures.output)
+    feature(FeatureCaptures.outputTarget)
+    feature(FeatureCaptures.springParameters, name = "outputSpring")
+    feature(FeatureCaptures.isStable)
+}
+
+sealed class MotionValueToolkit<MotionValueType, GestureContextType> {
+    internal abstract fun goldenTest(
+        motionTestRule: MotionTestRule<*>,
+        spec: MotionSpec,
+        createDerived: (underTest: MotionValueType) -> List<MotionValueType>,
+        initialValue: Float,
+        initialDirection: InputDirection,
+        directionChangeSlop: Float,
+        stableThreshold: Float,
+        verifyTimeSeries: TimeSeries.() -> VerifyTimeSeriesResult,
+        capture: CaptureTimeSeriesFn,
+        testInput: suspend (InputScope<MotionValueType, GestureContextType>).() -> Unit,
+    )
+
+    internal fun createTimeSeries(
+        frameIds: List<FrameId>,
+        motionValueCaptures: List<MotionValueCapture>,
+    ): TimeSeries {
+        return TimeSeries(
+            frameIds.toList(),
+            motionValueCaptures.flatMap { motionValueCapture ->
+                motionValueCapture.propertyCollector.entries.map { (name, dataPoints) ->
+                    Feature("${motionValueCapture.prefix}$name", dataPoints)
+                }
+            },
+        )
+    }
+
+    internal fun verifyTimeSeries(
+        motionTestRule: MotionTestRule<*>,
+        timeSeries: TimeSeries,
+        verificationFn: TimeSeries.() -> VerifyTimeSeriesResult,
+    ) {
+        val recordedMotion = motionTestRule.create(timeSeries, screenshots = null)
+        var assertTimeseriesMatchesGolden = false
+        var goldenName: String? = null
+        try {
+
+            val result = verificationFn.invoke(recordedMotion.timeSeries)
+            if (result is VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden) {
+                assertTimeseriesMatchesGolden = true
+                goldenName = result.goldenName
+            }
+        } finally {
+            try {
+                motionTestRule.assertThat(recordedMotion).timeSeriesMatchesGolden(goldenName)
+            } catch (e: AssertionError) {
+                if (assertTimeseriesMatchesGolden) {
+                    throw e
+                }
+            }
+        }
+    }
+
+    companion object {
+        val FrameDuration = 16.milliseconds
+    }
+}
+
+internal class MotionValueCapture(val debugger: DebugInspector, val prefix: String = "") {
+    val propertyCollector = mutableMapOf<String, MutableList<DataPoint<*>>>()
+    val captureScope = TimeSeriesCaptureScope(debugger, propertyCollector)
+
+    fun captureCurrentFrame(captureFn: CaptureTimeSeriesFn) {
+        captureFn(captureScope)
+    }
+}
diff --git a/mechanics/testing/src/com/android/mechanics/testing/TimeSeries.kt b/mechanics/testing/src/com/android/mechanics/testing/TimeSeries.kt
new file mode 100644
index 0000000..d72d6d1
--- /dev/null
+++ b/mechanics/testing/src/com/android/mechanics/testing/TimeSeries.kt
@@ -0,0 +1,55 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.testing
+
+import platform.test.motion.golden.Feature
+import platform.test.motion.golden.TimeSeries
+import platform.test.motion.golden.ValueDataPoint
+
+val TimeSeries.input: List<Float>
+    get() = dataPoints("input")
+
+val TimeSeries.output: List<Float>
+    get() = dataPoints("output")
+
+val TimeSeries.outputTarget: List<Float>
+    get() = dataPoints("outputTarget")
+
+val TimeSeries.isStable: List<Boolean>
+    get() = dataPoints("isStable")
+
+/**
+ * Returns data points for the given [featureName].
+ *
+ * Throws a [ClassCastException] if any data point is not a [ValueDataPoint] of type [T].
+ */
+inline fun <reified T : Any> TimeSeries.dataPoints(featureName: String): List<T> {
+    return (features[featureName] as Feature<*>).dataPoints.map {
+        (it as ValueDataPoint).value as T
+    }
+}
+
+/**
+ * Returns data points for the given [featureName].
+ *
+ * Returns `null` for all data points that are not a [ValueDataPoint] of type [T].
+ */
+inline fun <reified T : Any> TimeSeries.nullableDataPoints(featureName: String): List<T?> {
+    return (features[featureName] as Feature<*>).dataPoints.map {
+        (it as? ValueDataPoint)?.value as T?
+    }
+}
diff --git a/mechanics/testing/src/com/android/mechanics/testing/ViewMotionValueToolkit.kt b/mechanics/testing/src/com/android/mechanics/testing/ViewMotionValueToolkit.kt
new file mode 100644
index 0000000..cbe18d5
--- /dev/null
+++ b/mechanics/testing/src/com/android/mechanics/testing/ViewMotionValueToolkit.kt
@@ -0,0 +1,167 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+@file:OptIn(ExperimentalCoroutinesApi::class)
+
+package com.android.mechanics.testing
+
+import android.animation.AnimatorTestRule
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.MotionSpec
+import com.android.mechanics.view.DistanceGestureContext
+import com.android.mechanics.view.ViewMotionValue
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.drop
+import kotlinx.coroutines.flow.take
+import kotlinx.coroutines.flow.takeWhile
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.runBlocking
+import kotlinx.coroutines.test.runCurrent
+import kotlinx.coroutines.test.runTest
+import platform.test.motion.MotionTestRule
+import platform.test.motion.golden.FrameId
+import platform.test.motion.golden.TimeSeries
+import platform.test.motion.golden.TimestampFrameId
+
+/** Toolkit to support [ViewMotionValue] motion tests. */
+class ViewMotionValueToolkit(private val animatorTestRule: AnimatorTestRule) :
+    MotionValueToolkit<ViewMotionValue, DistanceGestureContext>() {
+
+    override fun goldenTest(
+        motionTestRule: MotionTestRule<*>,
+        spec: MotionSpec,
+        createDerived: (underTest: ViewMotionValue) -> List<ViewMotionValue>,
+        initialValue: Float,
+        initialDirection: InputDirection,
+        directionChangeSlop: Float,
+        stableThreshold: Float,
+        verifyTimeSeries: TimeSeries.() -> VerifyTimeSeriesResult,
+        capture: CaptureTimeSeriesFn,
+        testInput: suspend InputScope<ViewMotionValue, DistanceGestureContext>.() -> Unit,
+    ) = runTest {
+        val frameEmitter = MutableStateFlow<Long>(0)
+
+        val testHarness =
+            runBlocking(Dispatchers.Main) {
+                ViewMotionValueTestHarness(
+                        initialValue,
+                        initialDirection,
+                        spec,
+                        stableThreshold,
+                        directionChangeSlop,
+                        frameEmitter.asStateFlow(),
+                        createDerived,
+                    )
+                    .also { animatorTestRule.initNewAnimators() }
+            }
+
+        val underTest = testHarness.underTest
+        val motionValueCapture = MotionValueCapture(underTest.debugInspector())
+        val recordingJob = launch { testInput.invoke(testHarness) }
+
+        val frameIds = mutableListOf<FrameId>()
+
+        fun recordFrame(frameId: TimestampFrameId) {
+            frameIds.add(frameId)
+            motionValueCapture.captureCurrentFrame(capture)
+        }
+
+        runBlocking(Dispatchers.Main) {
+            val startFrameTime = animatorTestRule.currentTime
+            while (!recordingJob.isCompleted) {
+                recordFrame(TimestampFrameId(animatorTestRule.currentTime - startFrameTime))
+
+                frameEmitter.tryEmit(animatorTestRule.currentTime)
+                runCurrent()
+
+                animatorTestRule.advanceTimeBy(FrameDuration.inWholeMilliseconds)
+                runCurrent()
+            }
+
+            val timeSeries = createTimeSeries(frameIds, listOf(motionValueCapture))
+
+            motionValueCapture.debugger.dispose()
+            underTest.dispose()
+            verifyTimeSeries(motionTestRule, timeSeries, verifyTimeSeries)
+        }
+    }
+}
+
+private class ViewMotionValueTestHarness(
+    initialInput: Float,
+    initialDirection: InputDirection,
+    spec: MotionSpec,
+    stableThreshold: Float,
+    directionChangeSlop: Float,
+    val onFrame: StateFlow<Long>,
+    createDerived: (underTest: ViewMotionValue) -> List<ViewMotionValue>,
+) : InputScope<ViewMotionValue, DistanceGestureContext> {
+
+    override val gestureContext =
+        DistanceGestureContext(initialInput, initialDirection, directionChangeSlop)
+
+    override val underTest =
+        ViewMotionValue(
+            initialInput,
+            gestureContext,
+            stableThreshold = stableThreshold,
+            initialSpec = spec,
+        )
+
+    override var input by underTest::input
+
+    init {
+        require(createDerived(underTest).isEmpty()) {
+            "testing derived values is not yet supported"
+        }
+    }
+
+    override fun updateInput(value: Float) {
+        input = value
+        gestureContext.dragOffset = value
+    }
+
+    override suspend fun awaitStable() {
+        val debugInspectors = buildList { add(underTest.debugInspector()) }
+        try {
+
+            onFrame
+                // Since this is a state-flow, the current frame is counted too.
+                .drop(1)
+                .takeWhile { debugInspectors.any { !it.frame.isStable } }
+                .collect {}
+        } finally {
+            debugInspectors.forEach { it.dispose() }
+        }
+    }
+
+    override suspend fun awaitFrames(frames: Int) {
+        onFrame
+            // Since this is a state-flow, the current frame is counted too.
+            .drop(1)
+            .take(frames)
+            .collect {}
+    }
+
+    override fun reset(position: Float, direction: InputDirection) {
+        input = position
+        gestureContext.reset(position, direction)
+    }
+}
diff --git a/mechanics/tests/Android.bp b/mechanics/tests/Android.bp
index 8fdf904..1fa3b2c 100644
--- a/mechanics/tests/Android.bp
+++ b/mechanics/tests/Android.bp
@@ -25,29 +25,26 @@ android_test {
 
     srcs: [
         "src/**/*.kt",
-
-        // TODO(b/240432457): Depend on mechanics directly
-        ":mechanics-srcs",
     ],
 
     static_libs: [
-        // ":mechanics" dependencies
-        "androidx.compose.runtime_runtime",
-        "androidx.compose.material3_material3",
-        "androidx.compose.ui_ui-util",
-        "androidx.compose.foundation_foundation-layout",
-
-        // ":mechanics_tests" dependencies
-        "androidx.compose.animation_animation-core",
+        "//frameworks/libs/systemui/mechanics:mechanics",
+        "//frameworks/libs/systemui/mechanics:mechanics-testing",
         "platform-test-annotations",
         "PlatformMotionTestingCompose",
+        "androidx.compose.runtime_runtime",
+        "androidx.compose.animation_animation-core",
         "androidx.compose.ui_ui-test-junit4",
         "androidx.compose.ui_ui-test-manifest",
         "androidx.test.runner",
         "androidx.test.ext.junit",
         "kotlin-test",
+        "testables",
         "truth",
     ],
+    associates: [
+        "mechanics",
+    ],
     asset_dirs: ["goldens"],
     kotlincflags: ["-Xjvm-default=all"],
 }
diff --git a/mechanics/tests/AndroidManifest.xml b/mechanics/tests/AndroidManifest.xml
index 636ebb8..049cfe2 100644
--- a/mechanics/tests/AndroidManifest.xml
+++ b/mechanics/tests/AndroidManifest.xml
@@ -17,6 +17,10 @@
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.android.mechanics.tests">
 
+    <application android:debuggable="true">
+        <uses-library android:name="android.test.runner" />
+    </application>
+
     <instrumentation
         android:name="androidx.test.runner.AndroidJUnitRunner"
         android:label="Tests for Motion Mechanics"
diff --git a/mechanics/tests/goldens/MagneticDetach/placedAfter_afterAttach_detachesAgain.json b/mechanics/tests/goldens/MagneticDetach/placedAfter_afterAttach_detachesAgain.json
new file mode 100644
index 0000000..f18ea96
--- /dev/null
+++ b/mechanics/tests/goldens/MagneticDetach/placedAfter_afterAttach_detachesAgain.json
@@ -0,0 +1,662 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416,
+    432,
+    448,
+    464,
+    480,
+    496,
+    512,
+    528,
+    544,
+    560,
+    576,
+    592,
+    608,
+    624,
+    640,
+    656,
+    672,
+    688,
+    704,
+    720,
+    736,
+    752,
+    768,
+    784,
+    800,
+    816,
+    832,
+    848,
+    864,
+    880,
+    896,
+    912,
+    928,
+    944,
+    960,
+    976
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        100,
+        95,
+        90,
+        85,
+        80,
+        75,
+        70,
+        65,
+        60,
+        55,
+        50,
+        45,
+        40,
+        35,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        35,
+        40,
+        45,
+        50,
+        55,
+        60,
+        65,
+        70,
+        75,
+        80,
+        85,
+        90,
+        95,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        100,
+        95,
+        90,
+        85,
+        80,
+        75,
+        70,
+        65,
+        60,
+        55,
+        50,
+        43.38443,
+        36.351646,
+        29.990938,
+        24.672552,
+        21.162388,
+        18.574236,
+        16.725906,
+        15.440355,
+        14.566638,
+        13.985239,
+        13.6060915,
+        13.363756,
+        13.212058,
+        13.11921,
+        13.063812,
+        13.031747,
+        13.013887,
+        13.004453,
+        13,
+        13.75,
+        14.5,
+        16.449999,
+        18.400002,
+        20.35,
+        22.300001,
+        24.25,
+        26.2,
+        28.15,
+        30.1,
+        32.05,
+        34,
+        44.585567,
+        58.759357,
+        68.21262,
+        76.507256,
+        83.19111,
+        88.2904,
+        92.03026,
+        94.689606,
+        96.532425,
+        97.780754,
+        98.60885,
+        99.14723,
+        99.49028,
+        99.70432,
+        99.83485,
+        99.9124,
+        99.957054,
+        99.98176,
+        99.994675,
+        100
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        100,
+        95,
+        90,
+        85,
+        80,
+        75,
+        70,
+        65,
+        60,
+        55,
+        16,
+        15.25,
+        14.5,
+        13.75,
+        13,
+        13,
+        13,
+        13,
+        13,
+        13,
+        13,
+        13,
+        13,
+        13,
+        13,
+        13,
+        13,
+        13,
+        13,
+        13,
+        13.75,
+        14.5,
+        16.449999,
+        18.400002,
+        20.35,
+        22.300001,
+        24.25,
+        26.2,
+        28.15,
+        30.1,
+        32.05,
+        90,
+        95,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100,
+        100
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/MagneticDetach/placedAfter_attach_snapsToOrigin.json b/mechanics/tests/goldens/MagneticDetach/placedAfter_attach_snapsToOrigin.json
new file mode 100644
index 0000000..7d668f6
--- /dev/null
+++ b/mechanics/tests/goldens/MagneticDetach/placedAfter_attach_snapsToOrigin.json
@@ -0,0 +1,392 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416,
+    432,
+    448,
+    464,
+    480,
+    496,
+    512,
+    528,
+    544
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        100,
+        95,
+        90,
+        85,
+        80,
+        75,
+        70,
+        65,
+        60,
+        55,
+        50,
+        45,
+        40,
+        35,
+        30,
+        25,
+        20,
+        15,
+        10,
+        5,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        100,
+        95,
+        90,
+        85,
+        80,
+        75,
+        70,
+        65,
+        60,
+        55,
+        50,
+        43.38443,
+        36.351646,
+        29.990938,
+        24.672552,
+        20.412388,
+        17.074236,
+        14.475905,
+        12.440355,
+        6.552413,
+        0.9461464,
+        0.54626375,
+        0.29212147,
+        0.13740596,
+        0.048214816,
+        0.0006277391,
+        -0.021660766,
+        -0.02938723,
+        -0.029362231,
+        -0.02572238,
+        -0.020845085,
+        -0.015992891,
+        -0.01175198,
+        -0.008320414,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        100,
+        95,
+        90,
+        85,
+        80,
+        75,
+        70,
+        65,
+        60,
+        55,
+        16,
+        15.25,
+        14.5,
+        13.75,
+        13,
+        12.25,
+        11.5,
+        10.75,
+        10,
+        5,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/MagneticDetach/placedAfter_beforeAttach_suppressesDirectionReverse.json b/mechanics/tests/goldens/MagneticDetach/placedAfter_beforeAttach_suppressesDirectionReverse.json
new file mode 100644
index 0000000..f65c772
--- /dev/null
+++ b/mechanics/tests/goldens/MagneticDetach/placedAfter_beforeAttach_suppressesDirectionReverse.json
@@ -0,0 +1,162 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        100,
+        90.2,
+        80.399994,
+        70.59999,
+        60.79999,
+        51,
+        60.8,
+        70.6,
+        80.4,
+        90.200005,
+        100,
+        100
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        100,
+        90.2,
+        80.399994,
+        70.59999,
+        60.79999,
+        51,
+        60.8,
+        70.6,
+        80.4,
+        90.200005,
+        100,
+        100
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        100,
+        90.2,
+        80.399994,
+        70.59999,
+        60.79999,
+        51,
+        60.8,
+        70.6,
+        80.4,
+        90.200005,
+        100,
+        100
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/MagneticDetach/placedAfter_beforeDetach_suppressesDirectionReverse.json b/mechanics/tests/goldens/MagneticDetach/placedAfter_beforeDetach_suppressesDirectionReverse.json
new file mode 100644
index 0000000..fcc6339
--- /dev/null
+++ b/mechanics/tests/goldens/MagneticDetach/placedAfter_beforeDetach_suppressesDirectionReverse.json
@@ -0,0 +1,162 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        14.2,
+        28.4,
+        42.6,
+        56.8,
+        71,
+        56.8,
+        42.6,
+        28.399998,
+        14.199998,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        11.26,
+        15.52,
+        19.779999,
+        24.04,
+        28.300001,
+        24.04,
+        19.779999,
+        15.5199995,
+        11.26,
+        7,
+        7
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        11.26,
+        15.52,
+        19.779999,
+        24.04,
+        28.300001,
+        24.04,
+        19.779999,
+        15.5199995,
+        11.26,
+        7,
+        7
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/MagneticDetach/placedAfter_detach_animatesDetach.json b/mechanics/tests/goldens/MagneticDetach/placedAfter_detach_animatesDetach.json
new file mode 100644
index 0000000..af8198e
--- /dev/null
+++ b/mechanics/tests/goldens/MagneticDetach/placedAfter_detach_animatesDetach.json
@@ -0,0 +1,432 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416,
+    432,
+    448,
+    464,
+    480,
+    496,
+    512,
+    528,
+    544,
+    560,
+    576,
+    592,
+    608
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        5,
+        10,
+        15,
+        20,
+        25,
+        30,
+        35,
+        40,
+        45,
+        50,
+        55,
+        60,
+        65,
+        70,
+        75,
+        80,
+        85,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        5,
+        10,
+        11.5,
+        13,
+        14.5,
+        16,
+        17.5,
+        19,
+        20.5,
+        22,
+        23.5,
+        25,
+        26.5,
+        28,
+        29.5,
+        31,
+        32.5,
+        34,
+        39.29379,
+        48.383503,
+        57.851955,
+        66.20173,
+        72.95019,
+        78.10937,
+        81.899025,
+        84.597176,
+        86.4689,
+        87.738045,
+        88.58072,
+        89.129074,
+        89.4788,
+        89.69721,
+        89.83055,
+        89.909874,
+        89.95562,
+        89.98097,
+        89.99428,
+        90
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        5,
+        10,
+        11.5,
+        13,
+        14.5,
+        16,
+        17.5,
+        19,
+        20.5,
+        22,
+        23.5,
+        25,
+        26.5,
+        28,
+        29.5,
+        31,
+        32.5,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90,
+        90
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/MagneticDetach/placedAfter_placedWithDifferentBaseMapping.json b/mechanics/tests/goldens/MagneticDetach/placedAfter_placedWithDifferentBaseMapping.json
new file mode 100644
index 0000000..a52fa05
--- /dev/null
+++ b/mechanics/tests/goldens/MagneticDetach/placedAfter_placedWithDifferentBaseMapping.json
@@ -0,0 +1,392 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416,
+    432,
+    448,
+    464,
+    480,
+    496,
+    512,
+    528,
+    544
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        -10,
+        6,
+        22,
+        38,
+        54,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70,
+        70
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        100,
+        52,
+        3.9999924,
+        -44.000008,
+        -92.000015,
+        -140,
+        -214.33502,
+        -311.3978,
+        -404.9687,
+        -484.4225,
+        -547.1691,
+        -594.3692,
+        -628.61395,
+        -652.7499,
+        -669.3473,
+        -680.51227,
+        -687.87,
+        -692.62244,
+        -695.6304,
+        -697.49365,
+        -698.6208,
+        -699.2841,
+        -699.66156,
+        -699.867,
+        -699.9719,
+        -700.02014,
+        -700.03784,
+        -700.04016,
+        -700.03577,
+        -700.02905,
+        -700.0223,
+        -700.0164,
+        -700.0117,
+        -700.0081,
+        -700
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        100,
+        52,
+        3.9999924,
+        -44.000008,
+        -92.000015,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700,
+        -700
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/MagneticDetach/placedBefore_afterAttach_detachesAgain.json b/mechanics/tests/goldens/MagneticDetach/placedBefore_afterAttach_detachesAgain.json
new file mode 100644
index 0000000..846fb16
--- /dev/null
+++ b/mechanics/tests/goldens/MagneticDetach/placedBefore_afterAttach_detachesAgain.json
@@ -0,0 +1,662 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416,
+    432,
+    448,
+    464,
+    480,
+    496,
+    512,
+    528,
+    544,
+    560,
+    576,
+    592,
+    608,
+    624,
+    640,
+    656,
+    672,
+    688,
+    704,
+    720,
+    736,
+    752,
+    768,
+    784,
+    800,
+    816,
+    832,
+    848,
+    864,
+    880,
+    896,
+    912,
+    928,
+    944,
+    960,
+    976
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        -100,
+        -95,
+        -90,
+        -85,
+        -80,
+        -75,
+        -70,
+        -65,
+        -60,
+        -55,
+        -50,
+        -45,
+        -40,
+        -35,
+        -30,
+        -30,
+        -30,
+        -30,
+        -30,
+        -30,
+        -30,
+        -30,
+        -30,
+        -30,
+        -30,
+        -30,
+        -30,
+        -30,
+        -30,
+        -30,
+        -35,
+        -40,
+        -45,
+        -50,
+        -55,
+        -60,
+        -65,
+        -70,
+        -75,
+        -80,
+        -85,
+        -90,
+        -95,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Min",
+        "Min",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        -100,
+        -95,
+        -90,
+        -85,
+        -80,
+        -75,
+        -70,
+        -65,
+        -60,
+        -55,
+        -50,
+        -43.38443,
+        -36.351646,
+        -29.990938,
+        -24.672552,
+        -21.162388,
+        -18.574236,
+        -16.725906,
+        -15.440355,
+        -14.566638,
+        -13.985239,
+        -13.6060915,
+        -13.363756,
+        -13.212058,
+        -13.11921,
+        -13.063812,
+        -13.031747,
+        -13.013887,
+        -13.004453,
+        -13,
+        -13.75,
+        -14.5,
+        -16.45,
+        -18.4,
+        -20.35,
+        -22.3,
+        -24.25,
+        -26.2,
+        -28.15,
+        -30.1,
+        -32.05,
+        -34,
+        -44.585567,
+        -58.759357,
+        -68.21262,
+        -76.507256,
+        -83.19111,
+        -88.2904,
+        -92.03026,
+        -94.689606,
+        -96.532425,
+        -97.780754,
+        -98.60885,
+        -99.14723,
+        -99.49028,
+        -99.70432,
+        -99.83485,
+        -99.9124,
+        -99.957054,
+        -99.98176,
+        -99.994675,
+        -100
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        -100,
+        -95,
+        -90,
+        -85,
+        -80,
+        -75,
+        -70,
+        -65,
+        -60,
+        -55,
+        -16,
+        -15.25,
+        -14.5,
+        -13.75,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13,
+        -13.75,
+        -14.5,
+        -16.45,
+        -18.4,
+        -20.35,
+        -22.3,
+        -24.25,
+        -26.2,
+        -28.15,
+        -30.1,
+        -32.05,
+        -90,
+        -95,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100,
+        -100
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/MagneticDetach/placedBefore_attach_snapsToOrigin.json b/mechanics/tests/goldens/MagneticDetach/placedBefore_attach_snapsToOrigin.json
new file mode 100644
index 0000000..8e6d26a
--- /dev/null
+++ b/mechanics/tests/goldens/MagneticDetach/placedBefore_attach_snapsToOrigin.json
@@ -0,0 +1,392 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416,
+    432,
+    448,
+    464,
+    480,
+    496,
+    512,
+    528,
+    544
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        -100,
+        -95,
+        -90,
+        -85,
+        -80,
+        -75,
+        -70,
+        -65,
+        -60,
+        -55,
+        -50,
+        -45,
+        -40,
+        -35,
+        -30,
+        -25,
+        -20,
+        -15,
+        -10,
+        -5,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Min",
+        "Min",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        -100,
+        -95,
+        -90,
+        -85,
+        -80,
+        -75,
+        -70,
+        -65,
+        -60,
+        -55,
+        -50,
+        -43.38443,
+        -36.351646,
+        -29.990938,
+        -24.672552,
+        -20.412388,
+        -17.074236,
+        -14.475905,
+        -12.440355,
+        -6.552413,
+        -0.9461464,
+        -0.54626375,
+        -0.29212147,
+        -0.13740596,
+        -0.048214816,
+        -0.0006277391,
+        0.021660766,
+        0.02938723,
+        0.029362231,
+        0.02572238,
+        0.020845085,
+        0.015992891,
+        0.01175198,
+        0.008320414,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        -100,
+        -95,
+        -90,
+        -85,
+        -80,
+        -75,
+        -70,
+        -65,
+        -60,
+        -55,
+        -16,
+        -15.25,
+        -14.5,
+        -13.75,
+        -13,
+        -12.25,
+        -11.5,
+        -10.75,
+        -10,
+        -5,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/MagneticDetach/placedBefore_beforeAttach_suppressesDirectionReverse.json b/mechanics/tests/goldens/MagneticDetach/placedBefore_beforeAttach_suppressesDirectionReverse.json
new file mode 100644
index 0000000..80f6813
--- /dev/null
+++ b/mechanics/tests/goldens/MagneticDetach/placedBefore_beforeAttach_suppressesDirectionReverse.json
@@ -0,0 +1,162 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        -100,
+        -90.2,
+        -80.399994,
+        -70.59999,
+        -60.79999,
+        -51,
+        -60.8,
+        -70.6,
+        -80.4,
+        -90.200005,
+        -100,
+        -100
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Min",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        -100,
+        -90.2,
+        -80.399994,
+        -70.59999,
+        -60.79999,
+        -51,
+        -60.8,
+        -70.6,
+        -80.4,
+        -90.200005,
+        -100,
+        -100
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        -100,
+        -90.2,
+        -80.399994,
+        -70.59999,
+        -60.79999,
+        -51,
+        -60.8,
+        -70.6,
+        -80.4,
+        -90.200005,
+        -100,
+        -100
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/MagneticDetach/placedBefore_beforeDetach_suppressesDirectionReverse.json b/mechanics/tests/goldens/MagneticDetach/placedBefore_beforeDetach_suppressesDirectionReverse.json
new file mode 100644
index 0000000..0a08476
--- /dev/null
+++ b/mechanics/tests/goldens/MagneticDetach/placedBefore_beforeDetach_suppressesDirectionReverse.json
@@ -0,0 +1,202 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        -14.2,
+        -28.4,
+        -42.6,
+        -56.8,
+        -71,
+        -56.8,
+        -42.6,
+        -28.399998,
+        -14.199998,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        -13.995375,
+        -17.821867,
+        -21.595097,
+        -25.403616,
+        -29.284393,
+        -24.725756,
+        -20.24163,
+        -15.81998,
+        -11.447464,
+        -7.1117826,
+        -7.0626464,
+        -7.031971,
+        -7.013703,
+        -7.003483,
+        -6.999998
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        -11.259998,
+        -15.519999,
+        -19.779999,
+        -24.039999,
+        -28.3,
+        -24.039999,
+        -19.779999,
+        -15.519998,
+        -11.259998,
+        -6.999998,
+        -6.999998,
+        -6.999998,
+        -6.999998,
+        -6.999998,
+        -6.999998
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/MagneticDetach/placedBefore_detach_animatesDetach.json b/mechanics/tests/goldens/MagneticDetach/placedBefore_detach_animatesDetach.json
new file mode 100644
index 0000000..6f9df8e
--- /dev/null
+++ b/mechanics/tests/goldens/MagneticDetach/placedBefore_detach_animatesDetach.json
@@ -0,0 +1,432 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416,
+    432,
+    448,
+    464,
+    480,
+    496,
+    512,
+    528,
+    544,
+    560,
+    576,
+    592,
+    608
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        -5,
+        -10,
+        -15,
+        -20,
+        -25,
+        -30,
+        -35,
+        -40,
+        -45,
+        -50,
+        -55,
+        -60,
+        -65,
+        -70,
+        -75,
+        -80,
+        -85,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        -5,
+        -9.999998,
+        -11.499998,
+        -12.999998,
+        -14.499998,
+        -15.999998,
+        -17.499998,
+        -18.999998,
+        -20.5,
+        -22,
+        -23.499998,
+        -24.999998,
+        -26.499998,
+        -27.999998,
+        -29.499998,
+        -30.999998,
+        -32.5,
+        -34,
+        -39.29379,
+        -48.383503,
+        -57.851955,
+        -66.20174,
+        -72.950195,
+        -78.10937,
+        -81.89903,
+        -84.597176,
+        -86.4689,
+        -87.738045,
+        -88.58072,
+        -89.129074,
+        -89.4788,
+        -89.69721,
+        -89.83055,
+        -89.909874,
+        -89.95562,
+        -89.98097,
+        -89.99428,
+        -90
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        -5,
+        -9.999998,
+        -11.499998,
+        -12.999998,
+        -14.499998,
+        -15.999998,
+        -17.499998,
+        -18.999998,
+        -20.5,
+        -22,
+        -23.499998,
+        -24.999998,
+        -26.499998,
+        -27.999998,
+        -29.499998,
+        -30.999998,
+        -32.5,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90,
+        -90
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/MagneticDetach/placedBefore_placedWithDifferentBaseMapping.json b/mechanics/tests/goldens/MagneticDetach/placedBefore_placedWithDifferentBaseMapping.json
new file mode 100644
index 0000000..3ae3c28
--- /dev/null
+++ b/mechanics/tests/goldens/MagneticDetach/placedBefore_placedWithDifferentBaseMapping.json
@@ -0,0 +1,392 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416,
+    432,
+    448,
+    464,
+    480,
+    496,
+    512,
+    528,
+    544
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        10,
+        -6,
+        -22,
+        -38,
+        -54,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70,
+        -70
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        -100,
+        52.204758,
+        83.69019,
+        113.146576,
+        143.9473,
+        177.50067,
+        240.57437,
+        329.32672,
+        416.95862,
+        492.2793,
+        552.2154,
+        597.5444,
+        630.5683,
+        653.9236,
+        670.03204,
+        680.8976,
+        688.07654,
+        692.7254,
+        695.6756,
+        697.5083,
+        698.62054,
+        699.2776,
+        699.65326,
+        699.85913,
+        699.9653,
+        700.0149,
+        700.0339,
+        700.0373,
+        700.03375,
+        700.02765,
+        700.02136,
+        700.0158,
+        700.01135,
+        700.0079,
+        700
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        -100,
+        -52,
+        -3.9999924,
+        44.000008,
+        92.000015,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700,
+        700
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 800,
+          "dampingRatio": 0.95
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/changeDirection_flipsBetweenDirectionalSegments.json b/mechanics/tests/goldens/changeDirection_flipsBetweenDirectionalSegments.json
index 9fd0087..c3f2364 100644
--- a/mechanics/tests/goldens/changeDirection_flipsBetweenDirectionalSegments.json
+++ b/mechanics/tests/goldens/changeDirection_flipsBetweenDirectionalSegments.json
@@ -14,8 +14,7 @@
     176,
     192,
     208,
-    224,
-    240
+    224
   ],
   "features": [
     {
@@ -36,7 +35,6 @@
         0,
         0,
         0,
-        0,
         0
       ]
     },
@@ -58,7 +56,6 @@
         "Min",
         "Min",
         "Min",
-        "Min",
         "Min"
       ]
     },
@@ -80,7 +77,6 @@
         0.97079945,
         0.9824491,
         0.98952854,
-        1,
         1
       ]
     },
@@ -102,7 +98,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -166,10 +161,6 @@
           "stiffness": 1400,
           "dampingRatio": 1
         },
-        {
-          "stiffness": 1400,
-          "dampingRatio": 1
-        },
         {
           "stiffness": 1400,
           "dampingRatio": 1
@@ -194,7 +185,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/changingInput_addsAnimationToMapping_becomesStable.json b/mechanics/tests/goldens/changingInput_addsAnimationToMapping_becomesStable.json
index 510426b..167e4ea 100644
--- a/mechanics/tests/goldens/changingInput_addsAnimationToMapping_becomesStable.json
+++ b/mechanics/tests/goldens/changingInput_addsAnimationToMapping_becomesStable.json
@@ -2,8 +2,7 @@
   "frame_ids": [
     0,
     16,
-    32,
-    48
+    32
   ],
   "features": [
     {
@@ -12,7 +11,6 @@
       "data_points": [
         0,
         0.5,
-        1.1,
         1.1
       ]
     },
@@ -20,7 +18,6 @@
       "name": "gestureDirection",
       "type": "string",
       "data_points": [
-        "Max",
         "Max",
         "Max",
         "Max"
@@ -32,8 +29,7 @@
       "data_points": [
         0,
         0,
-        0.05119291,
-        0.095428914
+        0.05119291
       ]
     },
     {
@@ -42,7 +38,6 @@
       "data_points": [
         0,
         0,
-        0.55,
         0.55
       ]
     },
@@ -58,10 +53,6 @@
           "stiffness": 100000,
           "dampingRatio": 1
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -74,7 +65,6 @@
       "data_points": [
         true,
         true,
-        false,
         false
       ]
     }
diff --git a/mechanics/tests/goldens/derivedValue_hasAnimationLifecycleOnItsOwn.json b/mechanics/tests/goldens/derivedValue_hasAnimationLifecycleOnItsOwn.json
index 873df80..f33165d 100644
--- a/mechanics/tests/goldens/derivedValue_hasAnimationLifecycleOnItsOwn.json
+++ b/mechanics/tests/goldens/derivedValue_hasAnimationLifecycleOnItsOwn.json
@@ -23,8 +23,7 @@
     320,
     336,
     352,
-    368,
-    384
+    368
   ],
   "features": [
     {
@@ -54,7 +53,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -85,7 +83,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -116,7 +113,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -147,7 +143,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -247,10 +242,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -284,7 +275,6 @@
         true,
         true,
         true,
-        true,
         true
       ]
     },
@@ -315,7 +305,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -346,7 +335,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -367,17 +355,16 @@
         0.89982635,
         0.74407,
         0.5794298,
-        0.43098712,
+        0.4309871,
         0.308447,
-        0.21313858,
-        0.1423173,
-        0.091676354,
-        0.056711912,
-        0.0333848,
-        0.01837182,
-        0.009094477,
-        0.003640592,
-        0,
+        0.21313861,
+        0.14231732,
+        0.09167635,
+        0.056711916,
+        0.033384826,
+        0.018371828,
+        0.009094476,
+        0.0036405649,
         0
       ]
     },
@@ -408,7 +395,6 @@
         0,
         0,
         0,
-        0,
         0
       ]
     },
@@ -508,10 +494,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -545,7 +527,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/derivedValue_reflectsInputChangeInSameFrame.json b/mechanics/tests/goldens/derivedValue_reflectsInputChangeInSameFrame.json
index e4bd600..28014eb 100644
--- a/mechanics/tests/goldens/derivedValue_reflectsInputChangeInSameFrame.json
+++ b/mechanics/tests/goldens/derivedValue_reflectsInputChangeInSameFrame.json
@@ -19,8 +19,7 @@
     256,
     272,
     288,
-    304,
-    320
+    304
   ],
   "features": [
     {
@@ -46,7 +45,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -73,7 +71,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -100,7 +97,6 @@
         0.9786911,
         0.98912483,
         0.9953385,
-        1,
         1
       ]
     },
@@ -127,7 +123,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -211,10 +206,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -244,7 +235,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     },
@@ -271,7 +261,6 @@
         0.9786911,
         0.98912483,
         0.9953385,
-        1,
         1
       ]
     },
@@ -298,7 +287,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -325,7 +313,6 @@
         0.9786911,
         0.98912483,
         0.9953385,
-        1,
         1
       ]
     },
@@ -352,7 +339,6 @@
         0.9786911,
         0.98912483,
         0.9953385,
-        1,
         1
       ]
     },
@@ -436,10 +422,6 @@
           "stiffness": 100000,
           "dampingRatio": 1
         },
-        {
-          "stiffness": 100000,
-          "dampingRatio": 1
-        },
         {
           "stiffness": 100000,
           "dampingRatio": 1
@@ -469,7 +451,6 @@
         true,
         true,
         true,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/directionChange_maxToMin_appliesGuarantee_afterDirectionChange.json b/mechanics/tests/goldens/directionChange_maxToMin_appliesGuarantee_afterDirectionChange.json
index c015899..def9a2b 100644
--- a/mechanics/tests/goldens/directionChange_maxToMin_appliesGuarantee_afterDirectionChange.json
+++ b/mechanics/tests/goldens/directionChange_maxToMin_appliesGuarantee_afterDirectionChange.json
@@ -12,8 +12,7 @@
     144,
     160,
     176,
-    192,
-    208
+    192
   ],
   "features": [
     {
@@ -32,7 +31,6 @@
         -2,
         -2,
         -2,
-        -2,
         -2
       ]
     },
@@ -52,7 +50,6 @@
         "Min",
         "Min",
         "Min",
-        "Min",
         "Min"
       ]
     },
@@ -70,9 +67,8 @@
         0.9303996,
         0.48961937,
         0.1611222,
-        0.04164827,
-        0.008622885,
-        0,
+        0.04164828,
+        0.008622912,
         0
       ]
     },
@@ -92,7 +88,6 @@
         0,
         0,
         0,
-        0,
         0
       ]
     },
@@ -148,10 +143,6 @@
           "stiffness": 8366.601,
           "dampingRatio": 0.95
         },
-        {
-          "stiffness": 8366.601,
-          "dampingRatio": 0.95
-        },
         {
           "stiffness": 8366.601,
           "dampingRatio": 0.95
@@ -174,7 +165,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/directionChange_maxToMin_changesSegmentWithDirectionChange.json b/mechanics/tests/goldens/directionChange_maxToMin_changesSegmentWithDirectionChange.json
index 37b9396..a4dea67 100644
--- a/mechanics/tests/goldens/directionChange_maxToMin_changesSegmentWithDirectionChange.json
+++ b/mechanics/tests/goldens/directionChange_maxToMin_changesSegmentWithDirectionChange.json
@@ -20,8 +20,7 @@
     272,
     288,
     304,
-    320,
-    336
+    320
   ],
   "features": [
     {
@@ -48,7 +47,6 @@
         -2,
         -2,
         -2,
-        -2,
         -2
       ]
     },
@@ -76,7 +74,6 @@
         "Min",
         "Min",
         "Min",
-        "Min",
         "Min"
       ]
     },
@@ -94,17 +91,16 @@
         0.9303996,
         0.7829481,
         0.61738,
-        0.46381497,
+        0.46381494,
         0.3348276,
-        0.2332502,
-        0.15701783,
+        0.23325022,
+        0.15701781,
         0.10203475,
-        0.06376374,
-        0.038021922,
-        0.021308899,
-        0.010875165,
-        0.0046615005,
-        0,
+        0.06376373,
+        0.038021944,
+        0.021308914,
+        0.010875157,
+        0.004661471,
         0
       ]
     },
@@ -132,7 +128,6 @@
         0,
         0,
         0,
-        0,
         0
       ]
     },
@@ -220,10 +215,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -254,7 +245,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/directionChange_minToMax_changesSegmentWithDirectionChange.json b/mechanics/tests/goldens/directionChange_minToMax_changesSegmentWithDirectionChange.json
index 0c034c2..c338c01 100644
--- a/mechanics/tests/goldens/directionChange_minToMax_changesSegmentWithDirectionChange.json
+++ b/mechanics/tests/goldens/directionChange_minToMax_changesSegmentWithDirectionChange.json
@@ -20,8 +20,7 @@
     272,
     288,
     304,
-    320,
-    336
+    320
   ],
   "features": [
     {
@@ -48,7 +47,6 @@
         4,
         4,
         4,
-        4,
         4
       ]
     },
@@ -76,7 +74,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -104,7 +101,6 @@
         0.9786911,
         0.98912483,
         0.9953385,
-        1,
         1
       ]
     },
@@ -132,7 +128,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -220,10 +215,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -254,7 +245,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/doNothingBeforeThreshold.json b/mechanics/tests/goldens/doNothingBeforeThreshold.json
new file mode 100644
index 0000000..15b6249
--- /dev/null
+++ b/mechanics/tests/goldens/doNothingBeforeThreshold.json
@@ -0,0 +1,92 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        10,
+        10
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/emptySpec_outputMatchesInput_withoutAnimation.json b/mechanics/tests/goldens/emptySpec_outputMatchesInput_withoutAnimation.json
index 70d62ab..f5f7612 100644
--- a/mechanics/tests/goldens/emptySpec_outputMatchesInput_withoutAnimation.json
+++ b/mechanics/tests/goldens/emptySpec_outputMatchesInput_withoutAnimation.json
@@ -5,8 +5,7 @@
     32,
     48,
     64,
-    80,
-    96
+    80
   ],
   "features": [
     {
@@ -18,7 +17,6 @@
         40,
         60,
         80,
-        100,
         100
       ]
     },
@@ -31,7 +29,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -44,7 +41,6 @@
         40,
         60,
         80,
-        100,
         100
       ]
     },
@@ -57,7 +53,6 @@
         40,
         60,
         80,
-        100,
         100
       ]
     },
@@ -85,10 +80,6 @@
           "stiffness": 100000,
           "dampingRatio": 1
         },
-        {
-          "stiffness": 100000,
-          "dampingRatio": 1
-        },
         {
           "stiffness": 100000,
           "dampingRatio": 1
@@ -104,7 +95,6 @@
         true,
         true,
         true,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/hideAnimation.json b/mechanics/tests/goldens/hideAnimation.json
new file mode 100644
index 0000000..1ed61bf
--- /dev/null
+++ b/mechanics/tests/goldens/hideAnimation.json
@@ -0,0 +1,322 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416,
+    432
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        36,
+        33,
+        30,
+        27,
+        24,
+        21,
+        18,
+        15,
+        12,
+        9,
+        6,
+        3,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        27,
+        27,
+        27,
+        24,
+        21,
+        18,
+        15,
+        12,
+        9,
+        6.1834006,
+        4.0823064,
+        2.5971997,
+        1.58311,
+        0.9141716,
+        0.4889884,
+        0.2301146,
+        0.08085263,
+        0.001194974,
+        -0.03613234,
+        -0.049089864,
+        -0.049071845,
+        -0.042999808,
+        -0.034852397,
+        -0.026743067,
+        -0.019653551,
+        -0.013916051,
+        -0.009518558,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        27,
+        27,
+        27,
+        24,
+        21,
+        18,
+        15,
+        12,
+        9,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/hideAnimationOnThreshold.json b/mechanics/tests/goldens/hideAnimationOnThreshold.json
new file mode 100644
index 0000000..aa75de7
--- /dev/null
+++ b/mechanics/tests/goldens/hideAnimationOnThreshold.json
@@ -0,0 +1,322 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416,
+    432
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        36,
+        33,
+        30,
+        27,
+        24,
+        21,
+        18,
+        15,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        27,
+        27,
+        27,
+        24,
+        21,
+        18,
+        15,
+        12,
+        8,
+        5.40525,
+        3.5262613,
+        2.2135293,
+        1.327303,
+        0.74965316,
+        0.38740715,
+        0.17046088,
+        0.04813948,
+        -0.014901603,
+        -0.042484254,
+        -0.05010864,
+        -0.04747553,
+        -0.04038017,
+        -0.03207883,
+        -0.02424037,
+        -0.017586533,
+        -0.012307796,
+        -0.0083231535,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        27,
+        27,
+        27,
+        24,
+        21,
+        18,
+        15,
+        12,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/overdrag_maxDirection_neverExceedsMaxOverdrag.json b/mechanics/tests/goldens/overdrag_maxDirection_neverExceedsMaxOverdrag.json
new file mode 100644
index 0000000..ef27af8
--- /dev/null
+++ b/mechanics/tests/goldens/overdrag_maxDirection_neverExceedsMaxOverdrag.json
@@ -0,0 +1,279 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        5,
+        10,
+        15,
+        20,
+        25,
+        30,
+        35,
+        40,
+        45,
+        50,
+        55,
+        60,
+        65,
+        70,
+        75,
+        80,
+        85,
+        90,
+        95,
+        100
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        5,
+        10,
+        11.662819,
+        13.302809,
+        14.898373,
+        16.430256,
+        17.88237,
+        19.242344,
+        20.501678,
+        21.655659,
+        22.70298,
+        23.645235,
+        24.486334,
+        25.231884,
+        25.88864,
+        26.464012,
+        26.965673,
+        27.401234,
+        27.77803,
+        28.102966
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        5,
+        10,
+        11.662819,
+        13.302809,
+        14.898373,
+        16.430256,
+        17.88237,
+        19.242344,
+        20.501678,
+        21.655659,
+        22.70298,
+        23.645235,
+        24.486334,
+        25.231884,
+        25.88864,
+        26.464012,
+        26.965673,
+        27.401234,
+        27.77803,
+        28.102966
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true
+      ]
+    },
+    {
+      "name": "overdragLimit",
+      "type": "float",
+      "data_points": [
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/overdrag_minDirection_neverExceedsMaxOverdrag.json b/mechanics/tests/goldens/overdrag_minDirection_neverExceedsMaxOverdrag.json
new file mode 100644
index 0000000..6039a70
--- /dev/null
+++ b/mechanics/tests/goldens/overdrag_minDirection_neverExceedsMaxOverdrag.json
@@ -0,0 +1,279 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        -5,
+        -10,
+        -15,
+        -20,
+        -25,
+        -30,
+        -35,
+        -40,
+        -45,
+        -50,
+        -55,
+        -60,
+        -65,
+        -70,
+        -75,
+        -80,
+        -85,
+        -90,
+        -95,
+        -100
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        -5,
+        -10,
+        -11.662819,
+        -13.302809,
+        -14.898373,
+        -16.430256,
+        -17.88237,
+        -19.242344,
+        -20.501678,
+        -21.655659,
+        -22.70298,
+        -23.645235,
+        -24.486334,
+        -25.231884,
+        -25.88864,
+        -26.464012,
+        -26.965673,
+        -27.401234,
+        -27.77803,
+        -28.102966
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        -5,
+        -10,
+        -11.662819,
+        -13.302809,
+        -14.898373,
+        -16.430256,
+        -17.88237,
+        -19.242344,
+        -20.501678,
+        -21.655659,
+        -22.70298,
+        -23.645235,
+        -24.486334,
+        -25.231884,
+        -25.88864,
+        -26.464012,
+        -26.965673,
+        -27.401234,
+        -27.77803,
+        -28.102966
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true
+      ]
+    },
+    {
+      "name": "overdragLimit",
+      "type": "float",
+      "data_points": [
+        null,
+        null,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/overdrag_nonStandardBaseFunction.json b/mechanics/tests/goldens/overdrag_nonStandardBaseFunction.json
new file mode 100644
index 0000000..f3823d9
--- /dev/null
+++ b/mechanics/tests/goldens/overdrag_nonStandardBaseFunction.json
@@ -0,0 +1,268 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        5,
+        10,
+        15,
+        20,
+        25,
+        30,
+        35,
+        40,
+        45,
+        50,
+        55,
+        60,
+        65,
+        70,
+        75,
+        80,
+        85,
+        90,
+        95,
+        100
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        -5,
+        -10,
+        -11.662819,
+        -13.302809,
+        -14.898373,
+        -16.430256,
+        -17.88237,
+        -19.242344,
+        -20.501678,
+        -21.655659,
+        -22.70298,
+        -23.645235,
+        -24.486334,
+        -25.231884,
+        -25.88864,
+        -26.464012,
+        -26.965673,
+        -27.401234,
+        -27.77803,
+        -28.102966
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        -5,
+        -10,
+        -11.662819,
+        -13.302809,
+        -14.898373,
+        -16.430256,
+        -17.88237,
+        -19.242344,
+        -20.501678,
+        -21.655659,
+        -22.70298,
+        -23.645235,
+        -24.486334,
+        -25.231884,
+        -25.88864,
+        -26.464012,
+        -26.965673,
+        -27.401234,
+        -27.77803,
+        -28.102966
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true
+      ]
+    },
+    {
+      "name": "overdragLimit",
+      "type": "float",
+      "data_points": [
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10,
+        -10
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/revealAnimation.json b/mechanics/tests/goldens/revealAnimation.json
new file mode 100644
index 0000000..f18dacc
--- /dev/null
+++ b/mechanics/tests/goldens/revealAnimation.json
@@ -0,0 +1,292 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        9,
+        12,
+        15,
+        18,
+        21,
+        24,
+        27,
+        30,
+        33,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        1.0731893,
+        4.910625,
+        9.1775,
+        13.488271,
+        17.657562,
+        21.616333,
+        25.358374,
+        25.907566,
+        26.298885,
+        26.568165,
+        26.74721,
+        26.862015,
+        26.93265,
+        26.97394,
+        26.996431,
+        27.00737,
+        27.011566,
+        27.012094,
+        27.010847,
+        27.008924,
+        27
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        9,
+        12,
+        15,
+        18,
+        21,
+        24,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/revealAnimation_afterFixedValue.json b/mechanics/tests/goldens/revealAnimation_afterFixedValue.json
new file mode 100644
index 0000000..f18dacc
--- /dev/null
+++ b/mechanics/tests/goldens/revealAnimation_afterFixedValue.json
@@ -0,0 +1,292 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        9,
+        12,
+        15,
+        18,
+        21,
+        24,
+        27,
+        30,
+        33,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36,
+        36
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        1.0731893,
+        4.910625,
+        9.1775,
+        13.488271,
+        17.657562,
+        21.616333,
+        25.358374,
+        25.907566,
+        26.298885,
+        26.568165,
+        26.74721,
+        26.862015,
+        26.93265,
+        26.97394,
+        26.996431,
+        27.00737,
+        27.011566,
+        27.012094,
+        27.010847,
+        27.008924,
+        27
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        9,
+        12,
+        15,
+        18,
+        21,
+        24,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27,
+        27
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_animationAtRest_doesNotAffectVelocity.json b/mechanics/tests/goldens/segmentChange_animationAtRest_doesNotAffectVelocity.json
new file mode 100644
index 0000000..84c7d82
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_animationAtRest_doesNotAffectVelocity.json
@@ -0,0 +1,312 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        1.5,
+        1.5,
+        1.5,
+        1.5,
+        1.5,
+        1.5,
+        1.5,
+        1.5,
+        1.5,
+        1.5,
+        1.5,
+        1.5,
+        1.8,
+        2.1,
+        2.3999999,
+        2.6999998,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0.18297386,
+        2.2765617,
+        5.4437504,
+        8.720676,
+        11.643903,
+        14.040831,
+        15.895933,
+        17.268913,
+        18.247213,
+        18.920414,
+        19.368025,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        19.303997,
+        17.829481,
+        16.173801,
+        14.638149,
+        13.348276,
+        12.332502,
+        11.570178,
+        11.020348,
+        10
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10,
+        10
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_atSpringStart.json b/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_atSpringStart.json
index e378671..964d834 100644
--- a/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_atSpringStart.json
+++ b/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_atSpringStart.json
@@ -22,8 +22,7 @@
     304,
     320,
     336,
-    352,
-    368
+    352
   ],
   "features": [
     {
@@ -52,7 +51,6 @@
         11,
         11,
         11,
-        11,
         11
       ]
     },
@@ -82,7 +80,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -100,19 +97,18 @@
         17.93786,
         18.712797,
         19.23355,
-        19.571312,
-        19.781933,
+        19.571314,
+        19.781935,
         19.907185,
         19.977114,
         20.01258,
         20.02758,
         20.031174,
-        20.029,
+        20.028997,
         20.024399,
         20.019238,
         20.014452,
         20.010433,
-        20,
         20
       ]
     },
@@ -142,7 +138,6 @@
         20,
         20,
         20,
-        20,
         20
       ]
     },
@@ -238,10 +233,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -274,7 +265,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_springVelocityIsNotAppliedTwice.json b/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_springVelocityIsNotAppliedTwice.json
index e37510d..fce12cb 100644
--- a/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_springVelocityIsNotAppliedTwice.json
+++ b/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_springVelocityIsNotAppliedTwice.json
@@ -26,8 +26,7 @@
     368,
     384,
     400,
-    416,
-    432
+    416
   ],
   "features": [
     {
@@ -60,7 +59,6 @@
         21,
         21,
         21,
-        21,
         21
       ]
     },
@@ -94,7 +92,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -109,26 +106,25 @@
         14.22027,
         20.881996,
         27.33559,
-        33.145477,
-        36.971085,
-        39.13093,
-        40.246414,
-        40.73661,
-        40.874382,
-        40.830643,
-        40.70759,
-        40.56272,
-        40.42557,
-        40.30897,
-        40.21637,
-        40.146416,
-        40.095673,
-        40.060165,
-        40.036156,
-        40.020485,
-        40.01064,
-        40.00473,
-        40,
+        32.265293,
+        34.588463,
+        36.34147,
+        37.611744,
+        38.499744,
+        39.099594,
+        39.49083,
+        39.73635,
+        39.883526,
+        39.96661,
+        40.009514,
+        40.028366,
+        40.033657,
+        40.03197,
+        40.027233,
+        40.021656,
+        40.016376,
+        40.01189,
+        40.008324,
         40
       ]
     },
@@ -162,7 +158,6 @@
         40,
         40,
         40,
-        40,
         40
       ]
     },
@@ -274,10 +269,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -314,7 +305,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_velocityAddedOnDiscontinuousSegment.json b/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_velocityAddedOnDiscontinuousSegment.json
new file mode 100644
index 0000000..e22cde1
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_velocityAddedOnDiscontinuousSegment.json
@@ -0,0 +1,372 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416,
+    432,
+    448,
+    464,
+    480,
+    496,
+    512
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        9,
+        12,
+        15,
+        18,
+        21,
+        24,
+        27,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        9,
+        21.715681,
+        38.426617,
+        54.4196,
+        69.30995,
+        76.55414,
+        77.88977,
+        76.3026,
+        73.54735,
+        70.58736,
+        67.89756,
+        65.666245,
+        63.924633,
+        62.626797,
+        61.696457,
+        61.052605,
+        60.62202,
+        60.344193,
+        60.171986,
+        60.07036,
+        60.01423,
+        59.986275,
+        59.974922,
+        59.97272,
+        59.975067,
+        59.97924,
+        59.983753,
+        59.98787,
+        59.991287,
+        60
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        9,
+        25,
+        40,
+        55,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60,
+        60
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_velocityNotAddedOnContinuousSegment.json b/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_velocityNotAddedOnContinuousSegment.json
new file mode 100644
index 0000000..6f04279
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_velocityNotAddedOnContinuousSegment.json
@@ -0,0 +1,262 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        9,
+        12,
+        15,
+        18,
+        21,
+        24,
+        27,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30,
+        30
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        9,
+        21.715681,
+        38.426617,
+        54.4196,
+        64.95479,
+        65.21017,
+        65.3034,
+        65.30942,
+        65.274,
+        65.22361,
+        65.172455,
+        65.12727,
+        65.09046,
+        65.062096,
+        65.04118,
+        65.02634,
+        65.01615,
+        65.0094,
+        65
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        9,
+        25,
+        40,
+        55,
+        65,
+        65,
+        65,
+        65,
+        65,
+        65,
+        65,
+        65,
+        65,
+        65,
+        65,
+        65,
+        65,
+        65,
+        65
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_guaranteeGestureDragDelta_springCompletesWithinDistance.json b/mechanics/tests/goldens/segmentChange_guaranteeGestureDragDelta_springCompletesWithinDistance.json
index 6eb0987..755ff78 100644
--- a/mechanics/tests/goldens/segmentChange_guaranteeGestureDragDelta_springCompletesWithinDistance.json
+++ b/mechanics/tests/goldens/segmentChange_guaranteeGestureDragDelta_springCompletesWithinDistance.json
@@ -7,8 +7,7 @@
     64,
     80,
     96,
-    112,
-    128
+    112
   ],
   "features": [
     {
@@ -22,7 +21,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -37,7 +35,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -52,7 +49,6 @@
         0.45275474,
         0.772992,
         0.9506903,
-        1,
         1
       ]
     },
@@ -67,7 +63,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -103,10 +98,6 @@
           "stiffness": 19129.314,
           "dampingRatio": 0.9666667
         },
-        {
-          "stiffness": 43737.062,
-          "dampingRatio": 0.98333335
-        },
         {
           "stiffness": 43737.062,
           "dampingRatio": 0.98333335
@@ -124,7 +115,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/segmentChange_guaranteeInputDelta_springCompletesWithinDistance.json b/mechanics/tests/goldens/segmentChange_guaranteeInputDelta_springCompletesWithinDistance.json
index 9ca1bfa..003f74b 100644
--- a/mechanics/tests/goldens/segmentChange_guaranteeInputDelta_springCompletesWithinDistance.json
+++ b/mechanics/tests/goldens/segmentChange_guaranteeInputDelta_springCompletesWithinDistance.json
@@ -8,8 +8,7 @@
     80,
     96,
     112,
-    128,
-    144
+    128
   ],
   "features": [
     {
@@ -24,7 +23,6 @@
         2.5,
         3,
         3.5,
-        4,
         4
       ]
     },
@@ -40,7 +38,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -56,7 +53,6 @@
         0.772992,
         0.9506903,
         1,
-        1,
         1
       ]
     },
@@ -72,7 +68,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -113,12 +108,8 @@
           "dampingRatio": 0.98333335
         },
         {
-          "stiffness": 100000,
-          "dampingRatio": 1
-        },
-        {
-          "stiffness": 100000,
-          "dampingRatio": 1
+          "stiffness": 43737.062,
+          "dampingRatio": 0.98333335
         }
       ]
     },
@@ -134,7 +125,6 @@
         false,
         false,
         true,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/segmentChange_guaranteeNone_springAnimatesIndependentOfInput.json b/mechanics/tests/goldens/segmentChange_guaranteeNone_springAnimatesIndependentOfInput.json
index fe6c211..58706ef 100644
--- a/mechanics/tests/goldens/segmentChange_guaranteeNone_springAnimatesIndependentOfInput.json
+++ b/mechanics/tests/goldens/segmentChange_guaranteeNone_springAnimatesIndependentOfInput.json
@@ -16,8 +16,7 @@
     208,
     224,
     240,
-    256,
-    272
+    256
   ],
   "features": [
     {
@@ -40,7 +39,6 @@
         5,
         5,
         5,
-        5,
         5
       ]
     },
@@ -64,7 +62,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -88,7 +85,6 @@
         0.9786911,
         0.98912483,
         0.9953385,
-        1,
         1
       ]
     },
@@ -112,7 +108,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -184,10 +179,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -214,7 +205,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/segmentChange_inMaxDirection_animatedWhenReachingBreakpoint.json b/mechanics/tests/goldens/segmentChange_inMaxDirection_animatedWhenReachingBreakpoint.json
index e78a244..f93fc6f 100644
--- a/mechanics/tests/goldens/segmentChange_inMaxDirection_animatedWhenReachingBreakpoint.json
+++ b/mechanics/tests/goldens/segmentChange_inMaxDirection_animatedWhenReachingBreakpoint.json
@@ -16,8 +16,7 @@
     208,
     224,
     240,
-    256,
-    272
+    256
   ],
   "features": [
     {
@@ -40,7 +39,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -64,7 +62,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -88,7 +85,6 @@
         0.9786911,
         0.98912483,
         0.9953385,
-        1,
         1
       ]
     },
@@ -112,7 +108,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -184,10 +179,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -214,7 +205,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/segmentChange_inMaxDirection_springAnimationStartedRetroactively.json b/mechanics/tests/goldens/segmentChange_inMaxDirection_springAnimationStartedRetroactively.json
index 0ad35c3..2355188 100644
--- a/mechanics/tests/goldens/segmentChange_inMaxDirection_springAnimationStartedRetroactively.json
+++ b/mechanics/tests/goldens/segmentChange_inMaxDirection_springAnimationStartedRetroactively.json
@@ -15,8 +15,7 @@
     192,
     208,
     224,
-    240,
-    256
+    240
   ],
   "features": [
     {
@@ -38,7 +37,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -61,7 +59,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -84,7 +81,6 @@
         0.971274,
         0.9845492,
         0.9926545,
-        1,
         1
       ]
     },
@@ -107,7 +103,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -175,10 +170,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -204,7 +195,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/segmentChange_inMaxDirection_zeroDelta.json b/mechanics/tests/goldens/segmentChange_inMaxDirection_zeroDelta.json
new file mode 100644
index 0000000..f68e961
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_inMaxDirection_zeroDelta.json
@@ -0,0 +1,82 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.5,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_inMinDirection_animatedWhenReachingBreakpoint.json b/mechanics/tests/goldens/segmentChange_inMinDirection_animatedWhenReachingBreakpoint.json
index 333387e..f00535c 100644
--- a/mechanics/tests/goldens/segmentChange_inMinDirection_animatedWhenReachingBreakpoint.json
+++ b/mechanics/tests/goldens/segmentChange_inMinDirection_animatedWhenReachingBreakpoint.json
@@ -16,8 +16,7 @@
     208,
     224,
     240,
-    256,
-    272
+    256
   ],
   "features": [
     {
@@ -40,7 +39,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -64,7 +62,6 @@
         "Min",
         "Min",
         "Min",
-        "Min",
         "Min"
       ]
     },
@@ -78,17 +75,16 @@
         0.9303996,
         0.7829481,
         0.61738,
-        0.46381497,
+        0.46381494,
         0.3348276,
-        0.2332502,
-        0.15701783,
+        0.23325022,
+        0.15701781,
         0.10203475,
-        0.06376374,
-        0.038021922,
-        0.021308899,
-        0.010875165,
-        0.0046615005,
-        0,
+        0.06376373,
+        0.038021944,
+        0.021308914,
+        0.010875157,
+        0.004661471,
         0
       ]
     },
@@ -112,7 +108,6 @@
         0,
         0,
         0,
-        0,
         0
       ]
     },
@@ -184,10 +179,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -214,7 +205,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/segmentChange_inMinDirection_springAnimationStartedRetroactively.json b/mechanics/tests/goldens/segmentChange_inMinDirection_springAnimationStartedRetroactively.json
index 87337cc..5efbd83 100644
--- a/mechanics/tests/goldens/segmentChange_inMinDirection_springAnimationStartedRetroactively.json
+++ b/mechanics/tests/goldens/segmentChange_inMinDirection_springAnimationStartedRetroactively.json
@@ -15,8 +15,7 @@
     192,
     208,
     224,
-    240,
-    256
+    240
   ],
   "features": [
     {
@@ -38,7 +37,6 @@
         1,
         1,
         1,
-        1,
         1
       ]
     },
@@ -61,7 +59,6 @@
         "Min",
         "Min",
         "Min",
-        "Min",
         "Min"
       ]
     },
@@ -75,16 +72,15 @@
         0.8618002,
         0.70001805,
         0.5380087,
-        0.39591217,
-        0.28066826,
-        0.19219774,
+        0.3959122,
+        0.28066823,
+        0.19219775,
         0.1271556,
-        0.0810855,
-        0.04956317,
-        0.028725982,
-        0.015450776,
-        0.0073454976,
-        0,
+        0.08108548,
+        0.04956314,
+        0.028725967,
+        0.0154508,
+        0.007345509,
         0
       ]
     },
@@ -107,7 +103,6 @@
         0,
         0,
         0,
-        0,
         0
       ]
     },
@@ -175,10 +170,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -204,7 +195,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/semantics_flipsBetweenDirectionalSegments.json b/mechanics/tests/goldens/semantics_flipsBetweenDirectionalSegments.json
new file mode 100644
index 0000000..2b2107e
--- /dev/null
+++ b/mechanics/tests/goldens/semantics_flipsBetweenDirectionalSegments.json
@@ -0,0 +1,323 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.2,
+        0.4,
+        0.6,
+        0.8,
+        1,
+        1.2,
+        1.4000001,
+        1.6000001,
+        1.8000002,
+        2.0000002,
+        2.2000003,
+        2.4000003,
+        2.6000004,
+        2.8000004,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0.0696004,
+        0.21705192,
+        0.38261998,
+        0.536185,
+        0.66517246,
+        0.8363503,
+        1.0600344,
+        1.2805854,
+        1.4724215,
+        1.6271507,
+        1.745441,
+        1.8321071,
+        1.8933039,
+        1.9350511,
+        1.9625617,
+        1.9800283,
+        1.9906485,
+        1.996761,
+        2
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    },
+    {
+      "name": "Foo",
+      "type": "string",
+      "data_points": [
+        "zero",
+        "zero",
+        "zero",
+        "zero",
+        "zero",
+        "one",
+        "one",
+        "one",
+        "one",
+        "one",
+        "two",
+        "two",
+        "two",
+        "two",
+        "two",
+        "two",
+        "two",
+        "two",
+        "two",
+        "two",
+        "two",
+        "two",
+        "two",
+        "two",
+        "two"
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/specChange_shiftSegmentBackwards_doesNotAnimateWithinSegment_animatesSegmentChange.json b/mechanics/tests/goldens/specChange_shiftSegmentBackwards_doesNotAnimateWithinSegment_animatesSegmentChange.json
index 2f23446..4b61281 100644
--- a/mechanics/tests/goldens/specChange_shiftSegmentBackwards_doesNotAnimateWithinSegment_animatesSegmentChange.json
+++ b/mechanics/tests/goldens/specChange_shiftSegmentBackwards_doesNotAnimateWithinSegment_animatesSegmentChange.json
@@ -13,8 +13,7 @@
     160,
     176,
     192,
-    208,
-    224
+    208
   ],
   "features": [
     {
@@ -34,7 +33,6 @@
         0.5,
         0.5,
         0.5,
-        0.5,
         0.5
       ]
     },
@@ -55,7 +53,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -70,13 +67,12 @@
         1.356505,
         0.92442614,
         0.5804193,
-        0.33967388,
+        0.3396739,
         0.18536365,
-        0.093348265,
-        0.042140007,
-        0.015731335,
-        0.0033904314,
-        0,
+        0.09334825,
+        0.042139973,
+        0.015731357,
+        0.003390434,
         0
       ]
     },
@@ -97,7 +93,6 @@
         0,
         0,
         0,
-        0,
         0
       ]
     },
@@ -157,10 +152,6 @@
           "stiffness": 1400,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 1400,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 1400,
           "dampingRatio": 0.9
@@ -184,7 +175,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/specChange_shiftSegmentForward_doesNotAnimateWithinSegment_animatesSegmentChange.json b/mechanics/tests/goldens/specChange_shiftSegmentForward_doesNotAnimateWithinSegment_animatesSegmentChange.json
index 0be0241..faf1211 100644
--- a/mechanics/tests/goldens/specChange_shiftSegmentForward_doesNotAnimateWithinSegment_animatesSegmentChange.json
+++ b/mechanics/tests/goldens/specChange_shiftSegmentForward_doesNotAnimateWithinSegment_animatesSegmentChange.json
@@ -11,8 +11,7 @@
     128,
     144,
     160,
-    176,
-    192
+    176
   ],
   "features": [
     {
@@ -30,7 +29,6 @@
         0.5,
         0.5,
         0.5,
-        0.5,
         0.5
       ]
     },
@@ -49,7 +47,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -64,11 +61,10 @@
         0.579976,
         0.36567324,
         0.21482599,
-        0.11771333,
-        0.05957961,
-        0.027098536,
-        0.010269046,
-        0,
+        0.11771336,
+        0.059579656,
+        0.027098525,
+        0.010269003,
         0
       ]
     },
@@ -87,7 +83,6 @@
         0,
         0,
         0,
-        0,
         0
       ]
     },
@@ -139,10 +134,6 @@
           "stiffness": 1400,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 1400,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 1400,
           "dampingRatio": 0.9
@@ -164,7 +155,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/traverseSegmentsInOneFrame_noGuarantee_combinesDiscontinuity.json b/mechanics/tests/goldens/traverseSegmentsInOneFrame_noGuarantee_combinesDiscontinuity.json
index 79fd8b3..7420c91 100644
--- a/mechanics/tests/goldens/traverseSegmentsInOneFrame_noGuarantee_combinesDiscontinuity.json
+++ b/mechanics/tests/goldens/traverseSegmentsInOneFrame_noGuarantee_combinesDiscontinuity.json
@@ -15,8 +15,7 @@
     192,
     208,
     224,
-    240,
-    256
+    240
   ],
   "features": [
     {
@@ -38,7 +37,6 @@
         2.5,
         2.5,
         2.5,
-        2.5,
         2.5
       ]
     },
@@ -61,7 +59,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -84,7 +81,6 @@
         1.981205,
         1.9906502,
         1.996214,
-        2,
         2
       ]
     },
@@ -107,7 +103,6 @@
         2,
         2,
         2,
-        2,
         2
       ]
     },
@@ -175,10 +170,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -204,7 +195,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/traverseSegmentsInOneFrame_withDirectionChange_appliesGuarantees.json b/mechanics/tests/goldens/traverseSegmentsInOneFrame_withDirectionChange_appliesGuarantees.json
index a2765d1..6f35e23 100644
--- a/mechanics/tests/goldens/traverseSegmentsInOneFrame_withDirectionChange_appliesGuarantees.json
+++ b/mechanics/tests/goldens/traverseSegmentsInOneFrame_withDirectionChange_appliesGuarantees.json
@@ -9,8 +9,7 @@
     96,
     112,
     128,
-    144,
-    160
+    144
   ],
   "features": [
     {
@@ -26,7 +25,6 @@
         0,
         0,
         0,
-        0,
         0
       ]
     },
@@ -43,7 +41,6 @@
         "Min",
         "Min",
         "Min",
-        "Min",
         "Min"
       ]
     },
@@ -56,11 +53,10 @@
         1.5158144,
         1.0649259,
         0.62475336,
-        0.29145694,
-        0.11132395,
-        0.036348104,
-        0.009979486,
-        0,
+        0.291457,
+        0.111323975,
+        0.03634805,
+        0.009979475,
         0
       ]
     },
@@ -77,7 +73,6 @@
         0,
         0,
         0,
-        0,
         0
       ]
     },
@@ -121,10 +116,6 @@
           "stiffness": 5094,
           "dampingRatio": 0.94000006
         },
-        {
-          "stiffness": 5094,
-          "dampingRatio": 0.94000006
-        },
         {
           "stiffness": 5094,
           "dampingRatio": 0.94000006
@@ -144,7 +135,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/traverseSegmentsInOneFrame_withGuarantee_appliesGuarantees.json b/mechanics/tests/goldens/traverseSegmentsInOneFrame_withGuarantee_appliesGuarantees.json
index 418a6de..ea0b8f6 100644
--- a/mechanics/tests/goldens/traverseSegmentsInOneFrame_withGuarantee_appliesGuarantees.json
+++ b/mechanics/tests/goldens/traverseSegmentsInOneFrame_withGuarantee_appliesGuarantees.json
@@ -12,8 +12,7 @@
     144,
     160,
     176,
-    192,
-    208
+    192
   ],
   "features": [
     {
@@ -32,7 +31,6 @@
         2.1,
         2.1,
         2.1,
-        2.1,
         2.1
       ]
     },
@@ -52,7 +50,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -72,7 +69,6 @@
         5.969008,
         5.9854507,
         5.9941716,
-        6,
         6
       ]
     },
@@ -92,7 +88,6 @@
         6,
         6,
         6,
-        6,
         6
       ]
     },
@@ -148,10 +143,6 @@
           "stiffness": 1214.8745,
           "dampingRatio": 0.91111106
         },
-        {
-          "stiffness": 1214.8745,
-          "dampingRatio": 0.91111106
-        },
         {
           "stiffness": 1214.8745,
           "dampingRatio": 0.91111106
@@ -174,7 +165,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/traverseSegments_maxDirection_noGuarantee_addsDiscontinuityToOngoingAnimation.json b/mechanics/tests/goldens/traverseSegments_maxDirection_noGuarantee_addsDiscontinuityToOngoingAnimation.json
index 35ede9c..7baaf1d 100644
--- a/mechanics/tests/goldens/traverseSegments_maxDirection_noGuarantee_addsDiscontinuityToOngoingAnimation.json
+++ b/mechanics/tests/goldens/traverseSegments_maxDirection_noGuarantee_addsDiscontinuityToOngoingAnimation.json
@@ -24,8 +24,7 @@
     336,
     352,
     368,
-    384,
-    400
+    384
   ],
   "features": [
     {
@@ -56,7 +55,6 @@
         3,
         3,
         3,
-        3,
         3
       ]
     },
@@ -88,7 +86,6 @@
         "Max",
         "Max",
         "Max",
-        "Max",
         "Max"
       ]
     },
@@ -120,7 +117,6 @@
         1.9800283,
         1.9906485,
         1.996761,
-        2,
         2
       ]
     },
@@ -152,7 +148,6 @@
         2,
         2,
         2,
-        2,
         2
       ]
     },
@@ -256,10 +251,6 @@
           "stiffness": 700,
           "dampingRatio": 0.9
         },
-        {
-          "stiffness": 700,
-          "dampingRatio": 0.9
-        },
         {
           "stiffness": 700,
           "dampingRatio": 0.9
@@ -294,7 +285,6 @@
         false,
         false,
         false,
-        true,
         true
       ]
     }
diff --git a/mechanics/tests/goldens/view/emptySpec_outputMatchesInput_withoutAnimation.json b/mechanics/tests/goldens/view/emptySpec_outputMatchesInput_withoutAnimation.json
new file mode 100644
index 0000000..f5f7612
--- /dev/null
+++ b/mechanics/tests/goldens/view/emptySpec_outputMatchesInput_withoutAnimation.json
@@ -0,0 +1,102 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        20,
+        40,
+        60,
+        80,
+        100
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        20,
+        40,
+        60,
+        80,
+        100
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        20,
+        40,
+        60,
+        80,
+        100
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/view/gestureContext_listensToGestureContextUpdates.json b/mechanics/tests/goldens/view/gestureContext_listensToGestureContextUpdates.json
new file mode 100644
index 0000000..755ff78
--- /dev/null
+++ b/mechanics/tests/goldens/view/gestureContext_listensToGestureContextUpdates.json
@@ -0,0 +1,122 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.5,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0.13920438,
+        0.45275474,
+        0.772992,
+        0.9506903,
+        1
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1600.4729,
+          "dampingRatio": 0.9166666
+        },
+        {
+          "stiffness": 3659.3052,
+          "dampingRatio": 0.9333333
+        },
+        {
+          "stiffness": 8366.601,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 19129.314,
+          "dampingRatio": 0.9666667
+        },
+        {
+          "stiffness": 43737.062,
+          "dampingRatio": 0.98333335
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/view/segmentChange_animatedWhenReachingBreakpoint.json b/mechanics/tests/goldens/view/segmentChange_animatedWhenReachingBreakpoint.json
new file mode 100644
index 0000000..f93fc6f
--- /dev/null
+++ b/mechanics/tests/goldens/view/segmentChange_animatedWhenReachingBreakpoint.json
@@ -0,0 +1,212 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.5,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0.0696004,
+        0.21705192,
+        0.38261998,
+        0.536185,
+        0.6651724,
+        0.7667498,
+        0.8429822,
+        0.89796525,
+        0.93623626,
+        0.9619781,
+        0.9786911,
+        0.98912483,
+        0.9953385,
+        1
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/view/specChange_triggersAnimation.json b/mechanics/tests/goldens/view/specChange_triggersAnimation.json
new file mode 100644
index 0000000..b237f39
--- /dev/null
+++ b/mechanics/tests/goldens/view/specChange_triggersAnimation.json
@@ -0,0 +1,152 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        1.5,
+        1.3117526,
+        0.96824056,
+        0.6450497,
+        0.39762264,
+        0.22869362,
+        0.122471645,
+        0.060223386,
+        0.026204487,
+        0.009041936,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        1.5,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/src/com/android/mechanics/MotionValueLifecycleTest.kt b/mechanics/tests/src/com/android/mechanics/MotionValueLifecycleTest.kt
new file mode 100644
index 0000000..72ba985
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/MotionValueLifecycleTest.kt
@@ -0,0 +1,176 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics
+
+import androidx.compose.runtime.LaunchedEffect
+import androidx.compose.runtime.mutableFloatStateOf
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.snapshotFlow
+import androidx.compose.ui.test.junit4.createComposeRule
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.MotionValueTest.Companion.FakeGestureContext
+import com.android.mechanics.MotionValueTest.Companion.specBuilder
+import com.android.mechanics.spec.Mapping
+import com.google.common.truth.Truth.assertThat
+import com.google.common.truth.Truth.assertWithMessage
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.test.runTest
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class MotionValueLifecycleTest {
+
+    @get:Rule(order = 0) val rule = createComposeRule()
+
+    @Test
+    fun keepRunning_suspendsWithoutAnAnimation() = runTest {
+        val input = mutableFloatStateOf(0f)
+        val spec = specBuilder(Mapping.Zero) { fixedValue(breakpoint = 1f, value = 1f) }
+        val underTest = MotionValue(input::value, FakeGestureContext, spec)
+        rule.setContent { LaunchedEffect(Unit) { underTest.keepRunning() } }
+
+        val inspector = underTest.debugInspector()
+        var framesCount = 0
+        backgroundScope.launch { snapshotFlow { inspector.frame }.collect { framesCount++ } }
+
+        rule.awaitIdle()
+        framesCount = 0
+        rule.mainClock.autoAdvance = false
+
+        assertThat(inspector.isActive).isTrue()
+        assertThat(inspector.isAnimating).isFalse()
+
+        // Update the value, but WITHOUT causing an animation
+        input.floatValue = 0.5f
+        rule.awaitIdle()
+
+        // Still on the old frame..
+        assertThat(framesCount).isEqualTo(0)
+        // ... [underTest] is now waiting for an animation frame
+        assertThat(inspector.isAnimating).isTrue()
+
+        rule.mainClock.advanceTimeByFrame()
+        rule.awaitIdle()
+
+        // Produces the frame..
+        assertThat(framesCount).isEqualTo(1)
+        // ... and is suspended again.
+        assertThat(inspector.isAnimating).isTrue()
+
+        rule.mainClock.advanceTimeByFrame()
+        rule.awaitIdle()
+
+        // Produces the frame..
+        assertThat(framesCount).isEqualTo(2)
+        // ... and is suspended again.
+        assertThat(inspector.isAnimating).isFalse()
+
+        rule.mainClock.autoAdvance = true
+        rule.awaitIdle()
+        // Ensure that no more frames are produced
+        assertThat(framesCount).isEqualTo(2)
+    }
+
+    @Test
+    fun keepRunning_remainsActiveWhileAnimating() = runTest {
+        val input = mutableFloatStateOf(0f)
+        val spec = specBuilder(Mapping.Zero) { fixedValue(breakpoint = 1f, value = 1f) }
+        val underTest = MotionValue(input::value, FakeGestureContext, spec)
+        rule.setContent { LaunchedEffect(Unit) { underTest.keepRunning() } }
+
+        val inspector = underTest.debugInspector()
+        var framesCount = 0
+        backgroundScope.launch { snapshotFlow { inspector.frame }.collect { framesCount++ } }
+
+        rule.awaitIdle()
+        framesCount = 0
+        rule.mainClock.autoAdvance = false
+
+        assertThat(inspector.isActive).isTrue()
+        assertThat(inspector.isAnimating).isFalse()
+
+        // Update the value, WITH triggering an animation
+        input.floatValue = 1.5f
+        rule.awaitIdle()
+
+        // Still on the old frame..
+        assertThat(framesCount).isEqualTo(0)
+        // ... [underTest] is now waiting for an animation frame
+        assertThat(inspector.isAnimating).isTrue()
+
+        // A couple frames should be generated without pausing
+        repeat(5) {
+            rule.mainClock.advanceTimeByFrame()
+            rule.awaitIdle()
+
+            // The spring is still settling...
+            assertThat(inspector.frame.isStable).isFalse()
+            // ... animation keeps going ...
+            assertThat(inspector.isAnimating).isTrue()
+            // ... and frames are produces...
+            assertThat(framesCount).isEqualTo(it + 1)
+        }
+
+        val timeBeforeAutoAdvance = rule.mainClock.currentTime
+
+        // But this will stop as soon as the animation is finished. Skip forward.
+        rule.mainClock.autoAdvance = true
+        rule.awaitIdle()
+
+        // At which point the spring is stable again...
+        assertThat(inspector.frame.isStable).isTrue()
+        // ... and animations are suspended again.
+        assertThat(inspector.isAnimating).isFalse()
+
+        rule.awaitIdle()
+
+        // Stabilizing the spring during awaitIdle() took 160ms (obtained from looking at reference
+        // test runs). That time is expected to be 100% reproducible, given the starting
+        // state/configuration of the spring before awaitIdle().
+        assertThat(rule.mainClock.currentTime).isEqualTo(timeBeforeAutoAdvance + 160)
+    }
+
+    @Test
+    fun keepRunningWhile_stopRunningWhileStable_endsImmediately() = runTest {
+        val input = mutableFloatStateOf(0f)
+        val spec = specBuilder(Mapping.Zero) { fixedValue(breakpoint = 1f, value = 1f) }
+        val underTest = MotionValue(input::value, FakeGestureContext, spec)
+
+        val continueRunning = mutableStateOf(true)
+
+        rule.setContent {
+            LaunchedEffect(Unit) { underTest.keepRunningWhile { continueRunning.value } }
+        }
+
+        val inspector = underTest.debugInspector()
+
+        rule.awaitIdle()
+
+        assertWithMessage("isActive").that(inspector.isActive).isTrue()
+        assertWithMessage("isAnimating").that(inspector.isAnimating).isFalse()
+
+        val timeBeforeStopRunning = rule.mainClock.currentTime
+        continueRunning.value = false
+        rule.awaitIdle()
+
+        assertWithMessage("isActive").that(inspector.isActive).isFalse()
+        assertWithMessage("isAnimating").that(inspector.isAnimating).isFalse()
+        assertThat(rule.mainClock.currentTime).isEqualTo(timeBeforeStopRunning)
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/MotionValueTest.kt b/mechanics/tests/src/com/android/mechanics/MotionValueTest.kt
index 218067c..ffb8e87 100644
--- a/mechanics/tests/src/com/android/mechanics/MotionValueTest.kt
+++ b/mechanics/tests/src/com/android/mechanics/MotionValueTest.kt
@@ -14,61 +14,58 @@
  * limitations under the License.
  */
 
-@file:OptIn(ExperimentalCoroutinesApi::class)
-
 package com.android.mechanics
 
 import android.util.Log
 import android.util.Log.TerribleFailureHandler
-import androidx.compose.runtime.LaunchedEffect
 import androidx.compose.runtime.mutableFloatStateOf
-import androidx.compose.runtime.mutableStateOf
-import androidx.compose.runtime.snapshotFlow
-import androidx.compose.ui.test.ExperimentalTestApi
-import androidx.compose.ui.test.TestMonotonicFrameClock
-import androidx.compose.ui.test.junit4.createComposeRule
 import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spec.Breakpoint
 import com.android.mechanics.spec.BreakpointKey
-import com.android.mechanics.spec.DirectionalMotionSpec
-import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.Guarantee.GestureDragDelta
+import com.android.mechanics.spec.Guarantee.InputDelta
+import com.android.mechanics.spec.Guarantee.None
 import com.android.mechanics.spec.InputDirection
 import com.android.mechanics.spec.Mapping
 import com.android.mechanics.spec.MotionSpec
-import com.android.mechanics.spec.builder
-import com.android.mechanics.spec.reverseBuilder
-import com.android.mechanics.testing.DefaultSprings.matStandardDefault
-import com.android.mechanics.testing.DefaultSprings.matStandardFast
-import com.android.mechanics.testing.MotionValueToolkit
-import com.android.mechanics.testing.MotionValueToolkit.Companion.dataPoints
-import com.android.mechanics.testing.MotionValueToolkit.Companion.input
-import com.android.mechanics.testing.MotionValueToolkit.Companion.isStable
-import com.android.mechanics.testing.MotionValueToolkit.Companion.output
+import com.android.mechanics.spec.SegmentKey
+import com.android.mechanics.spec.SemanticKey
+import com.android.mechanics.spec.SemanticValue
+import com.android.mechanics.spec.builder.CanBeLastSegment
+import com.android.mechanics.spec.builder.DirectionalBuilderScope
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spec.builder.directionalMotionSpec
+import com.android.mechanics.spec.with
+import com.android.mechanics.testing.ComposeMotionValueToolkit
+import com.android.mechanics.testing.FakeMotionSpecBuilderContext
+import com.android.mechanics.testing.FeatureCaptures
 import com.android.mechanics.testing.VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden
 import com.android.mechanics.testing.VerifyTimeSeriesResult.SkipGoldenVerification
+import com.android.mechanics.testing.animateValueTo
+import com.android.mechanics.testing.animatedInputSequence
+import com.android.mechanics.testing.dataPoints
+import com.android.mechanics.testing.defaultFeatureCaptures
 import com.android.mechanics.testing.goldenTest
+import com.android.mechanics.testing.input
+import com.android.mechanics.testing.isStable
+import com.android.mechanics.testing.output
 import com.google.common.truth.Truth.assertThat
-import com.google.common.truth.Truth.assertWithMessage
-import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.launch
-import kotlinx.coroutines.test.TestCoroutineScheduler
-import kotlinx.coroutines.test.TestScope
-import kotlinx.coroutines.test.runTest
-import kotlinx.coroutines.withContext
 import org.junit.Rule
 import org.junit.Test
 import org.junit.rules.ExternalResource
 import org.junit.runner.RunWith
 import platform.test.motion.MotionTestRule
+import platform.test.motion.compose.runMonotonicClockTest
+import platform.test.motion.golden.DataPointTypes
 import platform.test.motion.testing.createGoldenPathManager
 
 @RunWith(AndroidJUnit4::class)
-class MotionValueTest {
+class MotionValueTest : MotionBuilderContext by FakeMotionSpecBuilderContext.Default {
     private val goldenPathManager =
         createGoldenPathManager("frameworks/libs/systemui/mechanics/tests/goldens")
 
-    @get:Rule(order = 0) val rule = createComposeRule()
-    @get:Rule(order = 1) val motion = MotionTestRule(MotionValueToolkit(rule), goldenPathManager)
+    @get:Rule(order = 1) val motion = MotionTestRule(ComposeMotionValueToolkit, goldenPathManager)
     @get:Rule(order = 2) val wtfLog = WtfLogRule()
 
     @Test
@@ -81,26 +78,26 @@ class MotionValueTest {
                 // There must never be an ongoing animation.
                 assertThat(isStable).doesNotContain(false)
 
-                AssertTimeSeriesMatchesGolden
+                AssertTimeSeriesMatchesGolden()
             },
         ) {
             animateValueTo(100f)
         }
 
     // TODO the tests should describe the expected values not only in terms of goldens, but
-    // also explicitly in verifyTimeSeries
+    //  also explicitly in verifyTimeSeries
 
     @Test
     fun changingInput_addsAnimationToMapping_becomesStable() =
         motion.goldenTest(
             spec =
-                specBuilder(Mapping.Zero)
-                    .toBreakpoint(1f)
-                    .completeWith(Mapping.Linear(factor = 0.5f))
+                specBuilder(Mapping.Zero) {
+                    mapping(breakpoint = 1f, mapping = Mapping.Linear(factor = 0.5f))
+                }
         ) {
             animateValueTo(1.1f, changePerFrame = 0.5f)
             while (underTest.isStable) {
-                updateValue(input + 0.5f)
+                updateInput(input + 0.5f)
                 awaitFrames()
             }
         }
@@ -108,18 +105,25 @@ class MotionValueTest {
     @Test
     fun segmentChange_inMaxDirection_animatedWhenReachingBreakpoint() =
         motion.goldenTest(
-            spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One)
+            spec = specBuilder(Mapping.Zero) { fixedValue(breakpoint = 1f, value = 1f) }
         ) {
             animateValueTo(1f, changePerFrame = 0.5f)
             awaitStable()
         }
 
+    @Test
+    fun segmentChange_inMaxDirection_zeroDelta() =
+        motion.goldenTest(spec = specBuilder(Mapping.Zero) { fixedValueFromCurrent(0.5f) }) {
+            animateValueTo(1f, changePerFrame = 0.5f)
+            awaitStable()
+        }
+
     @Test
     fun segmentChange_inMinDirection_animatedWhenReachingBreakpoint() =
         motion.goldenTest(
             initialValue = 2f,
             initialDirection = InputDirection.Min,
-            spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One),
+            spec = specBuilder(Mapping.Zero) { fixedValue(breakpoint = 1f, value = 1f) },
         ) {
             animateValueTo(1f, changePerFrame = 0.5f)
             awaitStable()
@@ -128,7 +132,7 @@ class MotionValueTest {
     @Test
     fun segmentChange_inMaxDirection_springAnimationStartedRetroactively() =
         motion.goldenTest(
-            spec = specBuilder(Mapping.Zero).toBreakpoint(.75f).completeWith(Mapping.One)
+            spec = specBuilder(Mapping.Zero) { mapping(breakpoint = .75f, mapping = Mapping.One) }
         ) {
             animateValueTo(1f, changePerFrame = 0.5f)
             awaitStable()
@@ -139,7 +143,7 @@ class MotionValueTest {
         motion.goldenTest(
             initialValue = 2f,
             initialDirection = InputDirection.Min,
-            spec = specBuilder(Mapping.Zero).toBreakpoint(1.25f).completeWith(Mapping.One),
+            spec = specBuilder(Mapping.Zero) { mapping(breakpoint = 1.25f, mapping = Mapping.One) },
         ) {
             animateValueTo(1f, changePerFrame = 0.5f)
             awaitStable()
@@ -149,9 +153,9 @@ class MotionValueTest {
     fun segmentChange_guaranteeNone_springAnimatesIndependentOfInput() =
         motion.goldenTest(
             spec =
-                specBuilder(Mapping.Zero)
-                    .toBreakpoint(1f)
-                    .completeWith(Mapping.One, guarantee = Guarantee.None)
+                specBuilder(Mapping.Zero) {
+                    fixedValue(breakpoint = 1f, guarantee = None, value = 1f)
+                }
         ) {
             animateValueTo(5f, changePerFrame = 0.5f)
             awaitStable()
@@ -161,9 +165,9 @@ class MotionValueTest {
     fun segmentChange_guaranteeInputDelta_springCompletesWithinDistance() =
         motion.goldenTest(
             spec =
-                specBuilder(Mapping.Zero)
-                    .toBreakpoint(1f)
-                    .completeWith(Mapping.One, guarantee = Guarantee.InputDelta(3f))
+                specBuilder(Mapping.Zero) {
+                    fixedValue(breakpoint = 1f, guarantee = InputDelta(3f), value = 1f)
+                }
         ) {
             animateValueTo(4f, changePerFrame = 0.5f)
         }
@@ -172,9 +176,9 @@ class MotionValueTest {
     fun segmentChange_guaranteeGestureDragDelta_springCompletesWithinDistance() =
         motion.goldenTest(
             spec =
-                specBuilder(Mapping.Zero)
-                    .toBreakpoint(1f)
-                    .completeWith(Mapping.One, guarantee = Guarantee.GestureDragDelta(3f))
+                specBuilder(Mapping.Zero) {
+                    fixedValue(breakpoint = 1f, guarantee = GestureDragDelta(3f), value = 1f)
+                }
         ) {
             animateValueTo(1f, changePerFrame = 0.5f)
             while (!underTest.isStable) {
@@ -185,7 +189,7 @@ class MotionValueTest {
 
     @Test
     fun segmentChange_appliesOutputVelocity_atSpringStart() =
-        motion.goldenTest(spec = specBuilder().toBreakpoint(10f).completeWith(Mapping.Fixed(20f))) {
+        motion.goldenTest(spec = specBuilder { fixedValue(breakpoint = 10f, value = 20f) }) {
             animateValueTo(11f, changePerFrame = 3f)
             awaitStable()
         }
@@ -194,25 +198,66 @@ class MotionValueTest {
     fun segmentChange_appliesOutputVelocity_springVelocityIsNotAppliedTwice() =
         motion.goldenTest(
             spec =
-                specBuilder()
-                    .toBreakpoint(10f)
-                    .continueWith(Mapping.Linear(factor = 1f, offset = 20f))
-                    .toBreakpoint(20f)
-                    .completeWith(Mapping.Fixed(40f))
+                specBuilder {
+                    fractionalInputFromCurrent(breakpoint = 10f, fraction = 1f, delta = 20f)
+                    fixedValueFromCurrent(breakpoint = 20f)
+                }
         ) {
             animateValueTo(21f, changePerFrame = 3f)
             awaitStable()
         }
 
+    @Test
+    fun segmentChange_appliesOutputVelocity_velocityNotAddedOnContinuousSegment() =
+        motion.goldenTest(
+            spec =
+                specBuilder {
+                    fractionalInputFromCurrent(breakpoint = 10f, fraction = 5f, delta = 5f)
+                    fixedValueFromCurrent(breakpoint = 20f)
+                }
+        ) {
+            animateValueTo(30f, changePerFrame = 3f)
+            awaitStable()
+        }
+
+    @Test
+    fun segmentChange_appliesOutputVelocity_velocityAddedOnDiscontinuousSegment() =
+        motion.goldenTest(
+            spec =
+                specBuilder {
+                    fractionalInputFromCurrent(breakpoint = 10f, fraction = 5f, delta = 5f)
+                    fixedValueFromCurrent(breakpoint = 20f, delta = -5f)
+                }
+        ) {
+            animateValueTo(30f, changePerFrame = 3f)
+            awaitStable()
+        }
+
+    @Test
+    // Regression test for b/409726626
+    fun segmentChange_animationAtRest_doesNotAffectVelocity() =
+        motion.goldenTest(
+            spec =
+                specBuilder(Mapping.Zero) {
+                    fixedValue(breakpoint = 1f, value = 20f)
+                    fixedValue(breakpoint = 2f, value = 20f)
+                    fixedValue(breakpoint = 3f, value = 10f)
+                },
+            stableThreshold = 1f,
+        ) {
+            this.updateInput(1.5f)
+            awaitStable()
+            animateValueTo(3f)
+            awaitStable()
+        }
+
     @Test
     fun specChange_shiftSegmentBackwards_doesNotAnimateWithinSegment_animatesSegmentChange() {
         fun generateSpec(offset: Float) =
-            specBuilder(Mapping.Zero)
-                .toBreakpoint(offset, B1)
-                .jumpTo(1f)
-                .continueWithTargetValue(2f)
-                .toBreakpoint(offset + 1f, B2)
-                .completeWith(Mapping.Zero)
+            specBuilder(Mapping.Zero) {
+                targetFromCurrent(breakpoint = offset, key = B1, delta = 1f, to = 2f)
+                fixedValue(breakpoint = offset + 1f, key = B2, value = 0f)
+            }
 
         motion.goldenTest(spec = generateSpec(0f), initialValue = .5f) {
             var offset = 0f
@@ -228,12 +273,10 @@ class MotionValueTest {
     @Test
     fun specChange_shiftSegmentForward_doesNotAnimateWithinSegment_animatesSegmentChange() {
         fun generateSpec(offset: Float) =
-            specBuilder(Mapping.Zero)
-                .toBreakpoint(offset, B1)
-                .jumpTo(1f)
-                .continueWithTargetValue(2f)
-                .toBreakpoint(offset + 1f, B2)
-                .completeWith(Mapping.Zero)
+            specBuilder(Mapping.Zero) {
+                targetFromCurrent(breakpoint = offset, key = B1, delta = 1f, to = 2f)
+                fixedValue(breakpoint = offset + 1f, key = B2, value = 0f)
+            }
 
         motion.goldenTest(spec = generateSpec(0f), initialValue = .5f) {
             var offset = 0f
@@ -249,7 +292,7 @@ class MotionValueTest {
     @Test
     fun directionChange_maxToMin_changesSegmentWithDirectionChange() =
         motion.goldenTest(
-            spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One),
+            spec = specBuilder(Mapping.Zero) { fixedValue(breakpoint = 1f, value = 1f) },
             initialValue = 2f,
             initialDirection = InputDirection.Max,
             directionChangeSlop = 3f,
@@ -261,7 +304,7 @@ class MotionValueTest {
     @Test
     fun directionChange_minToMax_changesSegmentWithDirectionChange() =
         motion.goldenTest(
-            spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One),
+            spec = specBuilder(Mapping.Zero) { fixedValue(breakpoint = 1f, value = 1f) },
             initialValue = 0f,
             initialDirection = InputDirection.Min,
             directionChangeSlop = 3f,
@@ -274,9 +317,9 @@ class MotionValueTest {
     fun directionChange_maxToMin_appliesGuarantee_afterDirectionChange() =
         motion.goldenTest(
             spec =
-                specBuilder(Mapping.Zero)
-                    .toBreakpoint(1f)
-                    .completeWith(Mapping.One, guarantee = Guarantee.InputDelta(1f)),
+                specBuilder(Mapping.Zero) {
+                    fixedValue(breakpoint = 1f, value = 1f, guarantee = InputDelta(1f))
+                },
             initialValue = 2f,
             initialDirection = InputDirection.Max,
             directionChangeSlop = 3f,
@@ -289,11 +332,10 @@ class MotionValueTest {
     fun traverseSegments_maxDirection_noGuarantee_addsDiscontinuityToOngoingAnimation() =
         motion.goldenTest(
             spec =
-                specBuilder(Mapping.Zero)
-                    .toBreakpoint(1f)
-                    .continueWith(Mapping.One)
-                    .toBreakpoint(2f)
-                    .completeWith(Mapping.Two)
+                specBuilder(Mapping.Zero) {
+                    fixedValue(breakpoint = 1f, value = 1f)
+                    fixedValue(breakpoint = 2f, value = 2f)
+                }
         ) {
             animateValueTo(3f, changePerFrame = 0.2f)
             awaitStable()
@@ -303,13 +345,12 @@ class MotionValueTest {
     fun traverseSegmentsInOneFrame_noGuarantee_combinesDiscontinuity() =
         motion.goldenTest(
             spec =
-                specBuilder(Mapping.Zero)
-                    .toBreakpoint(1f)
-                    .continueWith(Mapping.One)
-                    .toBreakpoint(2f)
-                    .completeWith(Mapping.Two)
+                specBuilder(Mapping.Zero) {
+                    fixedValue(breakpoint = 1f, value = 1f)
+                    fixedValue(breakpoint = 2f, value = 2f)
+                }
         ) {
-            updateValue(2.5f)
+            updateInput(2.5f)
             awaitStable()
         }
 
@@ -317,16 +358,12 @@ class MotionValueTest {
     fun traverseSegmentsInOneFrame_withGuarantee_appliesGuarantees() =
         motion.goldenTest(
             spec =
-                specBuilder(Mapping.Zero)
-                    .toBreakpoint(1f)
-                    .jumpBy(5f, guarantee = Guarantee.InputDelta(.9f))
-                    .continueWithConstantValue()
-                    .toBreakpoint(2f)
-                    .jumpBy(1f, guarantee = Guarantee.InputDelta(.9f))
-                    .continueWithConstantValue()
-                    .complete()
+                specBuilder(Mapping.Zero) {
+                    fixedValueFromCurrent(breakpoint = 1f, delta = 5f, guarantee = InputDelta(.9f))
+                    fixedValueFromCurrent(breakpoint = 2f, delta = 1f, guarantee = InputDelta(.9f))
+                }
         ) {
-            updateValue(2.1f)
+            updateInput(2.1f)
             awaitStable()
         }
 
@@ -334,16 +371,15 @@ class MotionValueTest {
     fun traverseSegmentsInOneFrame_withDirectionChange_appliesGuarantees() =
         motion.goldenTest(
             spec =
-                specBuilder(Mapping.Zero)
-                    .toBreakpoint(1f)
-                    .continueWith(Mapping.One, guarantee = Guarantee.InputDelta(1f))
-                    .toBreakpoint(2f)
-                    .completeWith(Mapping.Two),
+                specBuilder(Mapping.Zero) {
+                    fixedValue(breakpoint = 1f, value = 1f, guarantee = InputDelta(1f))
+                    fixedValue(breakpoint = 2f, value = 2f)
+                },
             initialValue = 2.5f,
             initialDirection = InputDirection.Max,
             directionChangeSlop = 1f,
         ) {
-            updateValue(.5f)
+            updateInput(.5f)
             animateValueTo(0f)
             awaitStable()
         }
@@ -352,8 +388,8 @@ class MotionValueTest {
     fun changeDirection_flipsBetweenDirectionalSegments() {
         val spec =
             MotionSpec(
-                maxDirection = forwardSpecBuilder(Mapping.Zero).complete(),
-                minDirection = reverseSpecBuilder(Mapping.One).complete(),
+                maxDirection = directionalMotionSpec(Mapping.Zero),
+                minDirection = directionalMotionSpec(Mapping.One),
             )
 
         motion.goldenTest(
@@ -367,10 +403,74 @@ class MotionValueTest {
         }
     }
 
+    @Test
+    fun semantics_flipsBetweenDirectionalSegments() {
+        val s1 = SemanticKey<String>("Foo")
+        val spec =
+            specBuilder(Mapping.Zero, semantics = listOf(s1 with "zero")) {
+                fixedValue(1f, 1f, semantics = listOf(s1 with "one"))
+                fixedValue(2f, 2f, semantics = listOf(s1 with "two"))
+            }
+
+        motion.goldenTest(
+            spec = spec,
+            capture = {
+                defaultFeatureCaptures()
+                feature(FeatureCaptures.semantics(s1, DataPointTypes.string))
+            },
+        ) {
+            animateValueTo(3f, changePerFrame = .2f)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun semantics_returnsNullForUnknownKey() {
+        val underTest = MotionValue({ 1f }, FakeGestureContext)
+
+        val s1 = SemanticKey<String>("Foo")
+
+        assertThat(underTest[s1]).isNull()
+    }
+
+    @Test
+    fun semantics_returnsValueMatchingSegment() {
+        val s1 = SemanticKey<String>("Foo")
+        val spec =
+            specBuilder(Mapping.Zero, semantics = listOf(s1 with "zero")) {
+                fixedValue(1f, 1f, semantics = listOf(s1 with "one"))
+                fixedValue(2f, 2f, semantics = listOf(s1 with "two"))
+            }
+
+        val input = mutableFloatStateOf(0f)
+        val underTest = MotionValue(input::value, FakeGestureContext, spec)
+
+        assertThat(underTest[s1]).isEqualTo("zero")
+        input.floatValue = 2f
+        assertThat(underTest[s1]).isEqualTo("two")
+    }
+
+    @Test
+    fun segment_returnsCurrentSegmentKey() {
+        val spec =
+            specBuilder(Mapping.Zero) {
+                fixedValue(1f, 1f, key = B1)
+                fixedValue(2f, 2f, key = B2)
+            }
+
+        val input = mutableFloatStateOf(1f)
+        val underTest = MotionValue(input::value, FakeGestureContext, spec)
+
+        assertThat(underTest.segmentKey).isEqualTo(SegmentKey(B1, B2, InputDirection.Max))
+        input.floatValue = 2f
+        assertThat(underTest.segmentKey)
+            .isEqualTo(SegmentKey(B2, Breakpoint.maxLimit.key, InputDirection.Max))
+    }
+
     @Test
     fun derivedValue_reflectsInputChangeInSameFrame() {
         motion.goldenTest(
-            spec = specBuilder(Mapping.Zero).toBreakpoint(0.5f).completeWith(Mapping.One),
+            spec = specBuilder(Mapping.Zero) { fixedValue(breakpoint = 0.5f, value = 1f) },
             createDerived = { primary ->
                 listOf(MotionValue.createDerived(primary, MotionSpec.Empty, label = "derived"))
             },
@@ -380,9 +480,9 @@ class MotionValueTest {
                     .containsExactlyElementsIn(dataPoints<Float>("derived-output"))
                     .inOrder()
                 // and its never animated.
-                assertThat(dataPoints<Float>("derived-isStable")).doesNotContain(false)
+                assertThat(dataPoints<Boolean>("derived-isStable")).doesNotContain(false)
 
-                AssertTimeSeriesMatchesGolden
+                AssertTimeSeriesMatchesGolden()
             },
         ) {
             animateValueTo(1f, changePerFrame = 0.1f)
@@ -393,12 +493,12 @@ class MotionValueTest {
     @Test
     fun derivedValue_hasAnimationLifecycleOnItsOwn() {
         motion.goldenTest(
-            spec = specBuilder(Mapping.Zero).toBreakpoint(0.5f).completeWith(Mapping.One),
+            spec = specBuilder(Mapping.Zero) { fixedValue(breakpoint = 0.5f, value = 1f) },
             createDerived = { primary ->
                 listOf(
                     MotionValue.createDerived(
                         primary,
-                        specBuilder(Mapping.One).toBreakpoint(0.5f).completeWith(Mapping.Zero),
+                        specBuilder(Mapping.One) { fixedValue(breakpoint = 0.5f, value = 0f) },
                         label = "derived",
                     )
                 )
@@ -412,7 +512,7 @@ class MotionValueTest {
     @Test
     fun nonFiniteNumbers_producesNaN_recoversOnSubsequentFrames() {
         motion.goldenTest(
-            spec = specBuilder(Mapping { if (it >= 1f) Float.NaN else 0f }).complete(),
+            spec = MotionSpec(directionalMotionSpec({ if (it >= 1f) Float.NaN else 0f })),
             verifyTimeSeries = {
                 assertThat(output.drop(1).take(5))
                     .containsExactlyElementsIn(listOf(0f, Float.NaN, Float.NaN, 0f, 0f))
@@ -423,7 +523,7 @@ class MotionValueTest {
             animatedInputSequence(0f, 1f, 1f, 0f, 0f)
         }
 
-        assertThat(wtfLog.loggedFailures).isEmpty()
+        assertThat(wtfLog.hasLoggedFailures()).isFalse()
     }
 
     @Test
@@ -441,26 +541,27 @@ class MotionValueTest {
             },
         ) {
             animatedInputSequence(0f, 1f)
-            underTest.spec =
-                specBuilder()
-                    .toBreakpoint(0f)
-                    .completeWith(Mapping { if (it >= 1f) Float.NaN else 0f })
+            underTest.spec = specBuilder {
+                mapping(breakpoint = 0f) { if (it >= 1f) Float.NaN else 0f }
+            }
+
             awaitFrames()
 
             animatedInputSequence(0f, 0f)
         }
 
-        assertThat(wtfLog.loggedFailures).hasSize(1)
-        assertThat(wtfLog.loggedFailures.first()).startsWith("Delta between mappings is undefined")
+        val loggedFailures = wtfLog.removeLoggedFailures()
+        assertThat(loggedFailures).hasSize(1)
+        assertThat(loggedFailures.first()).startsWith("Delta between mappings is undefined")
     }
 
     @Test
     fun nonFiniteNumbers_segmentTraverse_skipsAnimation() {
         motion.goldenTest(
             spec =
-                specBuilder(Mapping.Zero)
-                    .toBreakpoint(1f)
-                    .completeWith(Mapping { if (it < 2f) Float.NaN else 2f }),
+                specBuilder(Mapping.Zero) {
+                    mapping(breakpoint = 1f) { if (it < 2f) Float.NaN else 2f }
+                },
             verifyTimeSeries = {
                 // The mappings produce a non-finite number during a breakpoint traversal.
                 // The animation thereof is skipped to avoid poisoning the state with non-finite
@@ -473,13 +574,13 @@ class MotionValueTest {
         ) {
             animatedInputSequence(0f, 0.5f, 1f, 1.5f, 2f, 3f)
         }
-        assertThat(wtfLog.loggedFailures).hasSize(1)
-        assertThat(wtfLog.loggedFailures.first())
-            .startsWith("Delta between breakpoints is undefined")
+        val loggedFailures = wtfLog.removeLoggedFailures()
+        assertThat(loggedFailures).hasSize(1)
+        assertThat(loggedFailures.first()).startsWith("Delta between breakpoints is undefined")
     }
 
     @Test
-    fun keepRunning_concurrentInvocationThrows() = runTestWithFrameClock { testScheduler, _ ->
+    fun keepRunning_concurrentInvocationThrows() = runMonotonicClockTest {
         val underTest = MotionValue({ 1f }, FakeGestureContext, label = "Foo")
         val realJob = launch { underTest.keepRunning() }
         testScheduler.runCurrent()
@@ -496,142 +597,6 @@ class MotionValueTest {
         realJob.cancel()
     }
 
-    @Test
-    fun keepRunning_suspendsWithoutAnAnimation() = runTest {
-        val input = mutableFloatStateOf(0f)
-        val spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One)
-        val underTest = MotionValue(input::value, FakeGestureContext, spec)
-        rule.setContent { LaunchedEffect(Unit) { underTest.keepRunning() } }
-
-        val inspector = underTest.debugInspector()
-        var framesCount = 0
-        backgroundScope.launch { snapshotFlow { inspector.frame }.collect { framesCount++ } }
-
-        rule.awaitIdle()
-        framesCount = 0
-        rule.mainClock.autoAdvance = false
-
-        assertThat(inspector.isActive).isTrue()
-        assertThat(inspector.isAnimating).isFalse()
-
-        // Update the value, but WITHOUT causing an animation
-        input.floatValue = 0.5f
-        rule.awaitIdle()
-
-        // Still on the old frame..
-        assertThat(framesCount).isEqualTo(0)
-        // ... [underTest] is now waiting for an animation frame
-        assertThat(inspector.isAnimating).isTrue()
-
-        rule.mainClock.advanceTimeByFrame()
-        rule.awaitIdle()
-
-        // Produces the frame..
-        assertThat(framesCount).isEqualTo(1)
-        // ... and is suspended again.
-        assertThat(inspector.isAnimating).isTrue()
-
-        rule.mainClock.advanceTimeByFrame()
-        rule.awaitIdle()
-
-        // Produces the frame..
-        assertThat(framesCount).isEqualTo(2)
-        // ... and is suspended again.
-        assertThat(inspector.isAnimating).isFalse()
-
-        rule.mainClock.autoAdvance = true
-        rule.awaitIdle()
-        // Ensure that no more frames are produced
-        assertThat(framesCount).isEqualTo(2)
-    }
-
-    @Test
-    fun keepRunning_remainsActiveWhileAnimating() = runTest {
-        val input = mutableFloatStateOf(0f)
-        val spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One)
-        val underTest = MotionValue(input::value, FakeGestureContext, spec)
-        rule.setContent { LaunchedEffect(Unit) { underTest.keepRunning() } }
-
-        val inspector = underTest.debugInspector()
-        var framesCount = 0
-        backgroundScope.launch { snapshotFlow { inspector.frame }.collect { framesCount++ } }
-
-        rule.awaitIdle()
-        framesCount = 0
-        rule.mainClock.autoAdvance = false
-
-        assertThat(inspector.isActive).isTrue()
-        assertThat(inspector.isAnimating).isFalse()
-
-        // Update the value, WITH triggering an animation
-        input.floatValue = 1.5f
-        rule.awaitIdle()
-
-        // Still on the old frame..
-        assertThat(framesCount).isEqualTo(0)
-        // ... [underTest] is now waiting for an animation frame
-        assertThat(inspector.isAnimating).isTrue()
-
-        // A couple frames should be generated without pausing
-        repeat(5) {
-            rule.mainClock.advanceTimeByFrame()
-            rule.awaitIdle()
-
-            // The spring is still settling...
-            assertThat(inspector.frame.isStable).isFalse()
-            // ... animation keeps going ...
-            assertThat(inspector.isAnimating).isTrue()
-            // ... and frames are produces...
-            assertThat(framesCount).isEqualTo(it + 1)
-        }
-
-        val timeBeforeAutoAdvance = rule.mainClock.currentTime
-
-        // But this will stop as soon as the animation is finished. Skip forward.
-        rule.mainClock.autoAdvance = true
-        rule.awaitIdle()
-
-        // At which point the spring is stable again...
-        assertThat(inspector.frame.isStable).isTrue()
-        // ... and animations are suspended again.
-        assertThat(inspector.isAnimating).isFalse()
-
-        rule.awaitIdle()
-
-        // Stabilizing the spring during awaitIdle() took 160ms (obtained from looking at reference
-        // test runs). That time is expected to be 100% reproducible, given the starting
-        // state/configuration of the spring before awaitIdle().
-        assertThat(rule.mainClock.currentTime).isEqualTo(timeBeforeAutoAdvance + 160)
-    }
-
-    @Test
-    fun keepRunningWhile_stopRunningWhileStable_endsImmediately() = runTest {
-        val input = mutableFloatStateOf(0f)
-        val spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One)
-        val underTest = MotionValue(input::value, FakeGestureContext, spec)
-
-        val continueRunning = mutableStateOf(true)
-
-        rule.setContent {
-            LaunchedEffect(Unit) { underTest.keepRunningWhile { continueRunning.value } }
-        }
-
-        val inspector = underTest.debugInspector()
-
-        rule.awaitIdle()
-
-        assertWithMessage("isActive").that(inspector.isActive).isTrue()
-        assertWithMessage("isAnimating").that(inspector.isAnimating).isFalse()
-
-        val timeBeforeStopRunning = rule.mainClock.currentTime
-        continueRunning.value = false
-        rule.awaitIdle()
-
-        assertWithMessage("isActive").that(inspector.isActive).isFalse()
-        assertWithMessage("isAnimating").that(inspector.isAnimating).isFalse()
-        assertThat(rule.mainClock.currentTime).isEqualTo(timeBeforeStopRunning)
-    }
-
     @Test
     fun debugInspector_sameInstance_whileInUse() {
         val underTest = MotionValue({ 1f }, FakeGestureContext)
@@ -649,21 +614,8 @@ class MotionValueTest {
         assertThat(underTest.debugInspector()).isNotSameInstanceAs(originalInspector)
     }
 
-    @OptIn(ExperimentalTestApi::class)
-    private fun runTestWithFrameClock(
-        testBody:
-            suspend CoroutineScope.(
-                testScheduler: TestCoroutineScheduler, backgroundScope: CoroutineScope,
-            ) -> Unit
-    ) = runTest {
-        val testScope: TestScope = this
-        withContext(TestMonotonicFrameClock(testScope, FrameDelayNanos)) {
-            testBody(testScope.testScheduler, testScope.backgroundScope)
-        }
-    }
-
     class WtfLogRule : ExternalResource() {
-        val loggedFailures = mutableListOf<String>()
+        private val loggedFailures = mutableListOf<String>()
 
         private lateinit var oldHandler: TerribleFailureHandler
 
@@ -678,6 +630,20 @@ class MotionValueTest {
 
         override fun after() {
             Log.setWtfHandler(oldHandler)
+
+            // In eng-builds, some misconfiguration in a MotionValue would cause a crash. However,
+            // in tests (and in production), we want animations to proceed even with such errors.
+            // When a test ends, we should check loggedFailures, if they were expected.
+            assertThat(loggedFailures).isEmpty()
+        }
+
+        fun hasLoggedFailures() = loggedFailures.isNotEmpty()
+
+        fun removeLoggedFailures(): List<String> {
+            if (loggedFailures.isEmpty()) error("loggedFailures is empty")
+            val list = loggedFailures.toList()
+            loggedFailures.clear()
+            return list
         }
     }
 
@@ -692,25 +658,18 @@ class MotionValueTest {
                 override val dragOffset: Float
                     get() = 0f
             }
-        private val FrameDelayNanos: Long = 16_000_000L
 
-        fun specBuilder(firstSegment: Mapping = Mapping.Identity) =
-            MotionSpec.builder(
-                defaultSpring = matStandardDefault,
-                resetSpring = matStandardFast,
-                initialMapping = firstSegment,
-            )
-
-        fun forwardSpecBuilder(firstSegment: Mapping = Mapping.Identity) =
-            DirectionalMotionSpec.builder(
-                defaultSpring = matStandardDefault,
-                initialMapping = firstSegment,
-            )
+        private val Springs = FakeMotionSpecBuilderContext.Default.spatial
 
-        fun reverseSpecBuilder(firstSegment: Mapping = Mapping.Identity) =
-            DirectionalMotionSpec.reverseBuilder(
-                defaultSpring = matStandardDefault,
-                initialMapping = firstSegment,
+        fun specBuilder(
+            initialMapping: Mapping = Mapping.Identity,
+            semantics: List<SemanticValue<*>> = emptyList(),
+            init: DirectionalBuilderScope.() -> CanBeLastSegment,
+        ): MotionSpec {
+            return MotionSpec(
+                directionalMotionSpec(Springs.default, initialMapping, semantics, init),
+                resetSpring = Springs.fast,
             )
+        }
     }
 }
diff --git a/mechanics/tests/src/com/android/mechanics/effects/MagneticDetachTest.kt b/mechanics/tests/src/com/android/mechanics/effects/MagneticDetachTest.kt
new file mode 100644
index 0000000..988f72e
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/effects/MagneticDetachTest.kt
@@ -0,0 +1,252 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.effects
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.effects.MagneticDetach.Defaults.AttachPosition
+import com.android.mechanics.effects.MagneticDetach.Defaults.DetachPosition
+import com.android.mechanics.effects.MagneticDetach.State.Attached
+import com.android.mechanics.effects.MagneticDetach.State.Detached
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.builder.EffectPlacemenType
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spec.builder.spatialMotionSpec
+import com.android.mechanics.testing.ComposeMotionValueToolkit
+import com.android.mechanics.testing.FakeMotionSpecBuilderContext
+import com.android.mechanics.testing.MotionSpecSubject.Companion.assertThat
+import com.android.mechanics.testing.VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden
+import com.android.mechanics.testing.animateValueTo
+import com.android.mechanics.testing.goldenTest
+import kotlin.test.fail
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.junit.runners.Parameterized
+import platform.test.motion.MotionTestRule
+import platform.test.motion.testing.createGoldenPathManager
+import platform.test.screenshot.PathConfig
+import platform.test.screenshot.PathElementNoContext
+
+@RunWith(AndroidJUnit4::class)
+class MagneticDetachSpecTest : MotionBuilderContext by FakeMotionSpecBuilderContext.Default {
+
+    @Test
+    fun magneticDetach_matchesSpec() {
+        val underTests = spatialMotionSpec { after(10f, MagneticDetach()) }
+
+        assertThat(underTests).maxDirection().breakpoints().positions().containsExactly(10f, 90f)
+        assertThat(underTests)
+            .minDirection()
+            .breakpoints()
+            .positions()
+            .containsExactly(10f, 50f, 90f)
+    }
+
+    @Test
+    fun attachDetachSemantics_placedAfter_isAppliedOutside() {
+        val underTests = spatialMotionSpec { after(10f, MagneticDetach()) }
+
+        assertThat(underTests)
+            .maxDirection()
+            .semantics()
+            .withKey(MagneticDetach.Defaults.AttachDetachState)
+            .containsExactly(Attached, Attached, Detached)
+
+        assertThat(underTests)
+            .minDirection()
+            .semantics()
+            .withKey(MagneticDetach.Defaults.AttachDetachState)
+            .containsExactly(Attached, Attached, Detached, Detached)
+    }
+
+    @Test
+    fun attachValueSemantics_placedAfter_isAppliedInside() {
+        val underTests = spatialMotionSpec { after(10f, MagneticDetach()) }
+
+        assertThat(underTests)
+            .maxDirection()
+            .semantics()
+            .withKey(MagneticDetach.Defaults.AttachedValue)
+            .containsExactly(null, 10f, null)
+
+        assertThat(underTests)
+            .minDirection()
+            .semantics()
+            .withKey(MagneticDetach.Defaults.AttachedValue)
+            .containsExactly(null, 10f, null, null)
+    }
+
+    @Test
+    fun attachDetachSemantics_placedBefore_isAppliedOutside() {
+        val underTests = spatialMotionSpec { before(10f, MagneticDetach()) }
+
+        assertThat(underTests)
+            .maxDirection()
+            .semantics()
+            .withKey(MagneticDetach.Defaults.AttachDetachState)
+            .containsExactly(Detached, Detached, Attached, Attached)
+
+        assertThat(underTests)
+            .minDirection()
+            .semantics()
+            .withKey(MagneticDetach.Defaults.AttachDetachState)
+            .containsExactly(Detached, Attached, Attached)
+    }
+
+    @Test
+    fun attachValueSemantics_placedBefore_isAppliedInside() {
+        val underTests = spatialMotionSpec { before(10f, MagneticDetach()) }
+
+        assertThat(underTests)
+            .maxDirection()
+            .semantics()
+            .withKey(MagneticDetach.Defaults.AttachedValue)
+            .containsExactly(null, null, 10f, null)
+
+        assertThat(underTests)
+            .minDirection()
+            .semantics()
+            .withKey(MagneticDetach.Defaults.AttachedValue)
+            .containsExactly(null, 10f, null)
+    }
+}
+
+@RunWith(Parameterized::class)
+class MagneticDetachGoldenTest(private val placement: EffectPlacemenType) :
+    MotionBuilderContext by FakeMotionSpecBuilderContext.Default {
+
+    companion object {
+        @Parameterized.Parameters(name = "{0}")
+        @JvmStatic
+        fun placements() = listOf(EffectPlacemenType.After, EffectPlacemenType.Before)
+    }
+
+    private val goldenPathManager =
+        createGoldenPathManager(
+            "frameworks/libs/systemui/mechanics/tests/goldens",
+            PathConfig(
+                PathElementNoContext("effect", isDir = true) { "MagneticDetach" },
+                PathElementNoContext("placement", isDir = false) { "placed${placement.name}" },
+            ),
+        )
+
+    @get:Rule val motion = MotionTestRule(ComposeMotionValueToolkit, goldenPathManager)
+
+    private val directionSign: Float
+        get() =
+            when (placement) {
+                EffectPlacemenType.After -> 1f
+                EffectPlacemenType.Before -> -1f
+                else -> fail()
+            }
+
+    private fun createTestSpec() = spatialMotionSpec {
+        if (placement == EffectPlacemenType.After) {
+            after(10f, MagneticDetach())
+        } else if (placement == EffectPlacemenType.Before) {
+            before(-10f, MagneticDetach())
+        }
+    }
+
+    @Test
+    fun detach_animatesDetach() {
+        motion.goldenTest(
+            createTestSpec(),
+            verifyTimeSeries = { AssertTimeSeriesMatchesGolden("detach_animatesDetach") },
+        ) {
+            animateValueTo((DetachPosition.toPx() + 10f) * directionSign, changePerFrame = 5f)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun attach_snapsToOrigin() {
+        motion.goldenTest(
+            createTestSpec(),
+            initialValue = (DetachPosition.toPx() + 20f) * directionSign,
+            initialDirection = InputDirection.Min,
+            verifyTimeSeries = { AssertTimeSeriesMatchesGolden("attach_snapsToOrigin") },
+        ) {
+            animateValueTo(0f, changePerFrame = 5f)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun beforeAttach_suppressesDirectionReverse() {
+        motion.goldenTest(
+            createTestSpec(),
+            initialValue = (DetachPosition.toPx() + 20f) * directionSign,
+            initialDirection = InputDirection.Min,
+            verifyTimeSeries = {
+                AssertTimeSeriesMatchesGolden("beforeAttach_suppressesDirectionReverse")
+            },
+        ) {
+            animateValueTo((AttachPosition.toPx() + 11f) * directionSign)
+            animateValueTo((DetachPosition.toPx() + 20f) * directionSign)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun afterAttach_detachesAgain() {
+        motion.goldenTest(
+            createTestSpec(),
+            initialValue = (DetachPosition.toPx() + 20f) * directionSign,
+            initialDirection = InputDirection.Min,
+            verifyTimeSeries = { AssertTimeSeriesMatchesGolden("afterAttach_detachesAgain") },
+        ) {
+            animateValueTo((AttachPosition.toPx() / 2f + 10f) * directionSign, changePerFrame = 5f)
+            awaitStable()
+            animateValueTo((DetachPosition.toPx() + 20f) * directionSign, changePerFrame = 5f)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun beforeDetach_suppressesDirectionReverse() {
+        motion.goldenTest(
+            createTestSpec(),
+            verifyTimeSeries = {
+                AssertTimeSeriesMatchesGolden("beforeDetach_suppressesDirectionReverse")
+            },
+        ) {
+            animateValueTo((DetachPosition.toPx() - 9f) * directionSign)
+            animateValueTo(0f)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun placedWithDifferentBaseMapping() {
+        motion.goldenTest(
+            spatialMotionSpec(baseMapping = Mapping.Linear(factor = -10f)) {
+                if (placement == EffectPlacemenType.After) {
+                    after(-10f, MagneticDetach())
+                } else if (placement == EffectPlacemenType.Before) {
+                    before(10f, MagneticDetach())
+                }
+            },
+            initialValue = (-10f) * directionSign,
+            verifyTimeSeries = { AssertTimeSeriesMatchesGolden("placedWithDifferentBaseMapping") },
+        ) {
+            animateValueTo((DetachPosition.toPx() - 10f) * directionSign)
+            awaitStable()
+        }
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/effects/OverdragTest.kt b/mechanics/tests/src/com/android/mechanics/effects/OverdragTest.kt
new file mode 100644
index 0000000..c0bd8cc
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/effects/OverdragTest.kt
@@ -0,0 +1,129 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.effects
+
+import androidx.compose.ui.unit.dp
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spec.builder.spatialMotionSpec
+import com.android.mechanics.testing.CaptureTimeSeriesFn
+import com.android.mechanics.testing.ComposeMotionValueToolkit
+import com.android.mechanics.testing.FakeMotionSpecBuilderContext
+import com.android.mechanics.testing.FeatureCaptures
+import com.android.mechanics.testing.VerifyTimeSeriesResult
+import com.android.mechanics.testing.animateValueTo
+import com.android.mechanics.testing.defaultFeatureCaptures
+import com.android.mechanics.testing.goldenTest
+import com.android.mechanics.testing.input
+import com.android.mechanics.testing.nullableDataPoints
+import com.android.mechanics.testing.output
+import com.google.common.truth.Truth.assertThat
+import kotlin.math.abs
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import platform.test.motion.MotionTestRule
+import platform.test.motion.golden.DataPointTypes
+import platform.test.motion.testing.createGoldenPathManager
+
+@RunWith(AndroidJUnit4::class)
+class OverdragTest : MotionBuilderContext by FakeMotionSpecBuilderContext.Default {
+    private val goldenPathManager =
+        createGoldenPathManager("frameworks/libs/systemui/mechanics/tests/goldens")
+
+    @get:Rule val motion = MotionTestRule(ComposeMotionValueToolkit, goldenPathManager)
+
+    @Test
+    fun overdrag_maxDirection_neverExceedsMaxOverdrag() {
+        motion.goldenTest(
+            spatialMotionSpec { after(10f, Overdrag(maxOverdrag = 20.dp)) },
+            capture = captureOverdragFeatures,
+            verifyTimeSeries = {
+                assertThat(output.filter { it > 30 }).isEmpty()
+                VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden()
+            },
+        ) {
+            animateValueTo(100f, changePerFrame = 5f)
+        }
+    }
+
+    @Test
+    fun overdrag_minDirection_neverExceedsMaxOverdrag() {
+        motion.goldenTest(
+            spatialMotionSpec { before(-10f, Overdrag(maxOverdrag = 20.dp)) },
+            capture = captureOverdragFeatures,
+            initialDirection = InputDirection.Min,
+            verifyTimeSeries = {
+                assertThat(output.filter { it < -30 }).isEmpty()
+
+                VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden()
+            },
+        ) {
+            animateValueTo(-100f, changePerFrame = 5f)
+        }
+    }
+
+    @Test
+    fun overdrag_nonStandardBaseFunction() {
+        motion.goldenTest(
+            spatialMotionSpec(baseMapping = { -it }) { after(10f, Overdrag(maxOverdrag = 20.dp)) },
+            capture = captureOverdragFeatures,
+            initialValue = 5f,
+            verifyTimeSeries = {
+                assertThat(output.filter { it < -30 }).isEmpty()
+                VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden()
+            },
+        ) {
+            animateValueTo(100f, changePerFrame = 5f)
+        }
+    }
+
+    @Test
+    fun semantics_exposesOverdragLimitWhileOverdragging() {
+        motion.goldenTest(
+            spatialMotionSpec {
+                before(-10f, Overdrag())
+                after(10f, Overdrag())
+            },
+            capture = captureOverdragFeatures,
+            verifyTimeSeries = {
+                val isOverdragging = input.map { abs(it) >= 10 }
+                val hasOverdragLimit = nullableDataPoints<Float>("overdragLimit").map { it != null }
+                assertThat(hasOverdragLimit).isEqualTo(isOverdragging)
+                VerifyTimeSeriesResult.SkipGoldenVerification
+            },
+        ) {
+            animateValueTo(20f, changePerFrame = 5f)
+            reset(0f, InputDirection.Min)
+            animateValueTo(-20f, changePerFrame = 5f)
+        }
+    }
+
+    companion object {
+        val captureOverdragFeatures: CaptureTimeSeriesFn = {
+            defaultFeatureCaptures()
+            feature(
+                FeatureCaptures.semantics(
+                    Overdrag.Defaults.OverdragLimit,
+                    DataPointTypes.float,
+                    "overdragLimit",
+                )
+            )
+        }
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/effects/RevealOnThresholdTest.kt b/mechanics/tests/src/com/android/mechanics/effects/RevealOnThresholdTest.kt
new file mode 100644
index 0000000..c0b5eb7
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/effects/RevealOnThresholdTest.kt
@@ -0,0 +1,118 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.effects
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spec.builder.spatialMotionSpec
+import com.android.mechanics.testing.ComposeMotionValueToolkit
+import com.android.mechanics.testing.FakeMotionSpecBuilderContext
+import com.android.mechanics.testing.MotionSpecSubject.Companion.assertThat
+import com.android.mechanics.testing.animateValueTo
+import com.android.mechanics.testing.goldenTest
+import com.google.common.truth.Truth.assertThat
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import platform.test.motion.MotionTestRule
+import platform.test.motion.testing.createGoldenPathManager
+
+@RunWith(AndroidJUnit4::class)
+class RevealOnThresholdTest : MotionBuilderContext by FakeMotionSpecBuilderContext.Default {
+
+    private val goldenPathManager =
+        createGoldenPathManager("frameworks/libs/systemui/mechanics/tests/goldens")
+
+    @get:Rule val motion = MotionTestRule(ComposeMotionValueToolkit, goldenPathManager)
+
+    @Test
+    fun matchesSpec() {
+        val underTests = spatialMotionSpec(Mapping.Zero) { between(3f, 30f, RevealOnThreshold()) }
+
+        val minSize = RevealOnThreshold.Defaults.MinSize.toPx()
+
+        assertThat(3f + minSize).isLessThan(30f)
+
+        assertThat(underTests)
+            .maxDirection()
+            .breakpoints()
+            .positions()
+            .containsExactly(3f, 3f + minSize, 30f)
+
+        assertThat(underTests)
+            .minDirection()
+            .breakpoints()
+            .positions()
+            .containsExactly(3f, 3f + minSize, 30f)
+    }
+
+    @Test
+    fun revealAnimation() {
+        motion.goldenTest(
+            spatialMotionSpec(Mapping.Zero) { between(3f, 30f, RevealOnThreshold()) }
+        ) {
+            animateValueTo(36f, changePerFrame = 3f)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun revealAnimation_afterFixedValue() {
+        motion.goldenTest(
+            spatialMotionSpec(Mapping.Zero) { between(3f, 30f, RevealOnThreshold()) }
+        ) {
+            animateValueTo(36f, changePerFrame = 3f)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun hideAnimation() {
+        motion.goldenTest(
+            spatialMotionSpec(Mapping.Zero) { between(3f, 30f, RevealOnThreshold()) },
+            initialValue = 36f,
+            initialDirection = InputDirection.Min,
+        ) {
+            animateValueTo(0f, changePerFrame = 3f)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun doNothingBeforeThreshold() {
+        motion.goldenTest(
+            spatialMotionSpec(Mapping.Zero) { between(3f, 30f, RevealOnThreshold()) }
+        ) {
+            animateValueTo(2f + RevealOnThreshold.Defaults.MinSize.toPx(), changePerFrame = 3f)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun hideAnimationOnThreshold() {
+        motion.goldenTest(
+            spatialMotionSpec(Mapping.Zero) { between(3f, 30f, RevealOnThreshold()) },
+            initialValue = 36f,
+            initialDirection = InputDirection.Min,
+        ) {
+            animateValueTo(3f + RevealOnThreshold.Defaults.MinSize.toPx(), changePerFrame = 3f)
+            awaitStable()
+        }
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecBuilderTest.kt b/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecBuilderTest.kt
deleted file mode 100644
index 52a0ab7..0000000
--- a/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecBuilderTest.kt
+++ /dev/null
@@ -1,170 +0,0 @@
-/*
- * Copyright (C) 2025 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.mechanics.spec
-
-import androidx.test.ext.junit.runners.AndroidJUnit4
-import com.android.mechanics.spring.SpringParameters
-import com.android.mechanics.testing.DirectionalMotionSpecSubject.Companion.assertThat
-import org.junit.Test
-import org.junit.runner.RunWith
-
-@RunWith(AndroidJUnit4::class)
-class DirectionalMotionSpecBuilderTest {
-
-    @Test
-    fun directionalSpec_buildEmptySpec() {
-        val result = buildDirectionalMotionSpec()
-
-        assertThat(result).breakpoints().isEmpty()
-        assertThat(result).mappings().containsExactly(Mapping.Identity)
-    }
-
-    @Test
-    fun directionalSpec_addBreakpointsAndMappings() {
-        val result =
-            buildDirectionalMotionSpec(Spring, Mapping.Zero) {
-                mapping(breakpoint = 0f, mapping = Mapping.One, key = B1)
-                mapping(breakpoint = 10f, mapping = Mapping.Two, key = B2)
-            }
-
-        assertThat(result).breakpoints().keys().containsExactly(B1, B2).inOrder()
-        assertThat(result).breakpoints().withKey(B1).isAt(0f)
-        assertThat(result).breakpoints().withKey(B2).isAt(10f)
-        assertThat(result)
-            .mappings()
-            .containsExactly(Mapping.Zero, Mapping.One, Mapping.Two)
-            .inOrder()
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_setsDefaultSpring() {
-        val result =
-            buildDirectionalMotionSpec(Spring) { constantValue(breakpoint = 10f, value = 20f) }
-
-        assertThat(result).breakpoints().atPosition(10f).spring().isEqualTo(Spring)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_canOverrideDefaultSpring() {
-        val otherSpring = SpringParameters(stiffness = 10f, dampingRatio = 0.1f)
-        val result =
-            buildDirectionalMotionSpec(Spring) {
-                constantValue(breakpoint = 10f, value = 20f, spring = otherSpring)
-            }
-
-        assertThat(result).breakpoints().atPosition(10f).spring().isEqualTo(otherSpring)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_defaultsToNoGuarantee() {
-        val result =
-            buildDirectionalMotionSpec(Spring) { constantValue(breakpoint = 10f, value = 20f) }
-
-        assertThat(result).breakpoints().atPosition(10f).guarantee().isEqualTo(Guarantee.None)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_canSetGuarantee() {
-        val guarantee = Guarantee.InputDelta(10f)
-        val result =
-            buildDirectionalMotionSpec(Spring) {
-                constantValue(breakpoint = 10f, value = 20f, guarantee = guarantee)
-            }
-
-        assertThat(result).breakpoints().atPosition(10f).guarantee().isEqualTo(guarantee)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_jumpTo_setsAbsoluteValue() {
-        val result =
-            buildDirectionalMotionSpec(Spring, Mapping.Fixed(99f)) {
-                constantValue(breakpoint = 10f, value = 20f)
-            }
-
-        assertThat(result).breakpoints().positions().containsExactly(10f)
-        assertThat(result).mappings().atOrAfter(10f).isConstantValue(20f)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_jumpBy_setsRelativeValue() {
-        val result =
-            buildDirectionalMotionSpec(Spring, Mapping.Linear(factor = 0.5f)) {
-                // At 10f the current value is 5f (10f * 0.5f)
-                constantValueFromCurrent(breakpoint = 10f, delta = 30f)
-            }
-
-        assertThat(result).breakpoints().positions().containsExactly(10f)
-        assertThat(result).mappings().atOrAfter(10f).isConstantValue(35f)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_continueWithConstantValue_usesSourceValue() {
-        val result =
-            buildDirectionalMotionSpec(Spring, Mapping.Linear(factor = 0.5f)) {
-                // At 5f the current value is 2.5f (5f * 0.5f)
-                constantValueFromCurrent(breakpoint = 5f)
-            }
-
-        assertThat(result).mappings().atOrAfter(5f).isConstantValue(2.5f)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_continueWithFractionalInput_matchesLinearMapping() {
-        val result =
-            buildDirectionalMotionSpec(Spring) {
-                fractionalInput(breakpoint = 5f, from = 1f, fraction = .1f)
-            }
-
-        assertThat(result)
-            .mappings()
-            .atOrAfter(5f)
-            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 15f, out2 = 2f)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_continueWithTargetValue_matchesLinearMapping() {
-        val result =
-            buildDirectionalMotionSpec(Spring) {
-                target(breakpoint = 5f, from = 1f, to = 20f)
-                mapping(breakpoint = 30f, mapping = Mapping.Identity)
-            }
-
-        assertThat(result)
-            .mappings()
-            .atOrAfter(5f)
-            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 30f, out2 = 20f)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_breakpointsAtSamePosition_producesValidSegment() {
-        val result =
-            buildDirectionalMotionSpec(Spring) {
-                target(breakpoint = 5f, from = 1f, to = 20f)
-                mapping(breakpoint = 5f, mapping = Mapping.Identity)
-            }
-        assertThat(result)
-            .mappings()
-            .containsExactly(Mapping.Identity, Mapping.Fixed(1f), Mapping.Identity)
-            .inOrder()
-    }
-
-    companion object {
-        val Spring = SpringParameters(stiffness = 100f, dampingRatio = 1f)
-        val B1 = BreakpointKey("One")
-        val B2 = BreakpointKey("Two")
-    }
-}
diff --git a/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecTest.kt b/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecTest.kt
index d73f39b..30c8513 100644
--- a/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecTest.kt
+++ b/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecTest.kt
@@ -17,6 +17,7 @@
 package com.android.mechanics.spec
 
 import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spec.builder.directionalMotionSpec
 import com.android.mechanics.spring.SpringParameters
 import com.google.common.truth.Truth.assertThat
 import kotlin.math.nextDown
@@ -76,7 +77,7 @@ class DirectionalMotionSpecTest {
 
     @Test
     fun findBreakpointIndex_returnsMinForEmptySpec() {
-        val underTest = DirectionalMotionSpec.builder(Spring).complete()
+        val underTest = DirectionalMotionSpec.Empty
 
         assertThat(underTest.findBreakpointIndex(0f)).isEqualTo(0)
         assertThat(underTest.findBreakpointIndex(Float.MAX_VALUE)).isEqualTo(0)
@@ -85,7 +86,7 @@ class DirectionalMotionSpecTest {
 
     @Test
     fun findBreakpointIndex_throwsForNonFiniteInput() {
-        val underTest = DirectionalMotionSpec.builder(Spring).complete()
+        val underTest = DirectionalMotionSpec.Empty
 
         assertFailsWith<IllegalArgumentException> { underTest.findBreakpointIndex(Float.NaN) }
         assertFailsWith<IllegalArgumentException> {
@@ -99,7 +100,7 @@ class DirectionalMotionSpecTest {
     @Test
     fun findBreakpointIndex_atBreakpoint_returnsIndex() {
         val underTest =
-            DirectionalMotionSpec.builder(Spring).toBreakpoint(10f).completeWith(Mapping.Identity)
+            directionalMotionSpec(Spring) { mapping(breakpoint = 10f, mapping = Mapping.Identity) }
 
         assertThat(underTest.findBreakpointIndex(10f)).isEqualTo(1)
     }
@@ -107,7 +108,7 @@ class DirectionalMotionSpecTest {
     @Test
     fun findBreakpointIndex_afterBreakpoint_returnsPreviousIndex() {
         val underTest =
-            DirectionalMotionSpec.builder(Spring).toBreakpoint(10f).completeWith(Mapping.Identity)
+            directionalMotionSpec(Spring) { mapping(breakpoint = 10f, mapping = Mapping.Identity) }
 
         assertThat(underTest.findBreakpointIndex(10f.nextUp())).isEqualTo(1)
     }
@@ -115,7 +116,7 @@ class DirectionalMotionSpecTest {
     @Test
     fun findBreakpointIndex_beforeBreakpoint_returnsIndex() {
         val underTest =
-            DirectionalMotionSpec.builder(Spring).toBreakpoint(10f).completeWith(Mapping.Identity)
+            directionalMotionSpec(Spring) { mapping(breakpoint = 10f, mapping = Mapping.Identity) }
 
         assertThat(underTest.findBreakpointIndex(10f.nextDown())).isEqualTo(0)
     }
@@ -123,9 +124,9 @@ class DirectionalMotionSpecTest {
     @Test
     fun findBreakpointIndexByKey_returnsIndex() {
         val underTest =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .completeWith(Mapping.Identity)
+            directionalMotionSpec(Spring) {
+                mapping(breakpoint = 10f, key = B1, mapping = Mapping.Identity)
+            }
 
         assertThat(underTest.findBreakpointIndex(B1)).isEqualTo(1)
     }
@@ -133,9 +134,9 @@ class DirectionalMotionSpecTest {
     @Test
     fun findBreakpointIndexByKey_unknown_returnsMinusOne() {
         val underTest =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .completeWith(Mapping.Identity)
+            directionalMotionSpec(Spring) {
+                mapping(breakpoint = 10f, key = B1, mapping = Mapping.Identity)
+            }
 
         assertThat(underTest.findBreakpointIndex(B2)).isEqualTo(-1)
     }
@@ -143,11 +144,10 @@ class DirectionalMotionSpecTest {
     @Test
     fun findSegmentIndex_returnsIndexForSegment_ignoringDirection() {
         val underTest =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(20f, key = B2)
-                .completeWith(Mapping.Identity)
+            directionalMotionSpec(Spring) {
+                mapping(breakpoint = 10f, key = B1, mapping = Mapping.One)
+                mapping(breakpoint = 20f, key = B2, mapping = Mapping.Identity)
+            }
 
         assertThat(underTest.findSegmentIndex(SegmentKey(B1, B2, InputDirection.Max))).isEqualTo(1)
         assertThat(underTest.findSegmentIndex(SegmentKey(B1, B2, InputDirection.Min))).isEqualTo(1)
@@ -156,22 +156,45 @@ class DirectionalMotionSpecTest {
     @Test
     fun findSegmentIndex_forInvalidKeys_returnsMinusOne() {
         val underTest =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(20f, key = B2)
-                .continueWith(Mapping.One)
-                .toBreakpoint(30f, key = B3)
-                .completeWith(Mapping.Identity)
+            directionalMotionSpec(Spring) {
+                mapping(breakpoint = 10f, key = B1, mapping = Mapping.One)
+                mapping(breakpoint = 20f, key = B2, mapping = Mapping.One)
+                mapping(breakpoint = 30f, key = B3, mapping = Mapping.Identity)
+            }
 
         assertThat(underTest.findSegmentIndex(SegmentKey(B2, B1, InputDirection.Max))).isEqualTo(-1)
         assertThat(underTest.findSegmentIndex(SegmentKey(B1, B3, InputDirection.Max))).isEqualTo(-1)
     }
 
+    @Test
+    fun semantics_tooFewValues_throws() {
+        assertFailsWith<IllegalArgumentException> {
+            DirectionalMotionSpec(
+                listOf(Breakpoint.minLimit, Breakpoint.maxLimit),
+                listOf(Mapping.Identity),
+                listOf(SegmentSemanticValues(Semantic1, emptyList())),
+            )
+        }
+    }
+
+    @Test
+    fun semantics_tooManyValues_throws() {
+        assertFailsWith<IllegalArgumentException> {
+            DirectionalMotionSpec(
+                listOf(Breakpoint.minLimit, Breakpoint.maxLimit),
+                listOf(Mapping.Identity),
+                listOf(SegmentSemanticValues(Semantic1, listOf("One", "Two"))),
+            )
+        }
+    }
+
     companion object {
         val B1 = BreakpointKey("one")
         val B2 = BreakpointKey("two")
         val B3 = BreakpointKey("three")
+        val Semantic1 = SemanticKey<String>("Foo")
+        val Semantic2 = SemanticKey<String>("Bar")
+
         val Spring = SpringParameters(stiffness = 100f, dampingRatio = 1f)
     }
 }
diff --git a/mechanics/tests/src/com/android/mechanics/spec/FluentSpecBuilderTest.kt b/mechanics/tests/src/com/android/mechanics/spec/FluentSpecBuilderTest.kt
deleted file mode 100644
index 1c20be9..0000000
--- a/mechanics/tests/src/com/android/mechanics/spec/FluentSpecBuilderTest.kt
+++ /dev/null
@@ -1,269 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.mechanics.spec
-
-import androidx.test.ext.junit.runners.AndroidJUnit4
-import com.android.mechanics.spring.SpringParameters
-import com.android.mechanics.testing.DirectionalMotionSpecSubject.Companion.assertThat
-import org.junit.Test
-import org.junit.runner.RunWith
-
-@RunWith(AndroidJUnit4::class)
-class FluentSpecBuilderTest {
-
-    @Test
-    fun directionalSpec_buildEmptySpec() {
-        val result = DirectionalMotionSpec.builder(Spring).complete()
-
-        assertThat(result).breakpoints().isEmpty()
-        assertThat(result).mappings().containsExactly(Mapping.Identity)
-    }
-
-    @Test
-    fun directionalSpec_buildEmptySpec_inReverse() {
-        val result = DirectionalMotionSpec.reverseBuilder(Spring).complete()
-
-        assertThat(result).breakpoints().isEmpty()
-        assertThat(result).mappings().containsExactly(Mapping.Identity)
-    }
-
-    @Test
-    fun motionSpec_sameSpecInBothDirections() {
-        val result =
-            MotionSpec.builder(Spring, Mapping.Zero)
-                .toBreakpoint(0f, B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(10f, B2)
-                .completeWith(Mapping.Two)
-
-        assertThat(result.maxDirection).isSameInstanceAs(result.minDirection)
-
-        assertThat(result.minDirection).breakpoints().keys().containsExactly(B1, B2).inOrder()
-        assertThat(result.minDirection)
-            .mappings()
-            .containsExactly(Mapping.Zero, Mapping.One, Mapping.Two)
-            .inOrder()
-    }
-
-    @Test
-    fun directionalSpec_addBreakpointsAndMappings() {
-        val result =
-            DirectionalMotionSpec.builder(Spring, Mapping.Zero)
-                .toBreakpoint(0f, B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(10f, B2)
-                .completeWith(Mapping.Two)
-
-        assertThat(result).breakpoints().keys().containsExactly(B1, B2).inOrder()
-        assertThat(result).breakpoints().withKey(B1).isAt(0f)
-        assertThat(result).breakpoints().withKey(B2).isAt(10f)
-        assertThat(result)
-            .mappings()
-            .containsExactly(Mapping.Zero, Mapping.One, Mapping.Two)
-            .inOrder()
-    }
-
-    @Test
-    fun directionalSpec_addBreakpointsAndMappings_inReverse() {
-        val result =
-            DirectionalMotionSpec.reverseBuilder(Spring, Mapping.Two)
-                .toBreakpoint(10f, B2)
-                .continueWith(Mapping.One)
-                .toBreakpoint(0f, B1)
-                .completeWith(Mapping.Zero)
-
-        assertThat(result).breakpoints().keys().containsExactly(B1, B2).inOrder()
-        assertThat(result).breakpoints().withKey(B1).isAt(0f)
-        assertThat(result).breakpoints().withKey(B2).isAt(10f)
-        assertThat(result)
-            .mappings()
-            .containsExactly(Mapping.Zero, Mapping.One, Mapping.Two)
-            .inOrder()
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_setsDefaultSpring() {
-        val result =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(10f)
-                .jumpTo(20f)
-                .continueWithConstantValue()
-                .complete()
-
-        assertThat(result).breakpoints().atPosition(10f).spring().isEqualTo(Spring)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_canOverrideDefaultSpring() {
-        val otherSpring = SpringParameters(stiffness = 10f, dampingRatio = 0.1f)
-        val result =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(10f)
-                .jumpTo(20f, spring = otherSpring)
-                .continueWithConstantValue()
-                .complete()
-
-        assertThat(result).breakpoints().atPosition(10f).spring().isEqualTo(otherSpring)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_defaultsToNoGuarantee() {
-        val result =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(10f)
-                .jumpTo(20f)
-                .continueWithConstantValue()
-                .complete()
-
-        assertThat(result).breakpoints().atPosition(10f).guarantee().isEqualTo(Guarantee.None)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_canSetGuarantee() {
-        val guarantee = Guarantee.InputDelta(10f)
-        val result =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(10f)
-                .jumpTo(20f, guarantee = guarantee)
-                .continueWithConstantValue()
-                .complete()
-
-        assertThat(result).breakpoints().atPosition(10f).guarantee().isEqualTo(guarantee)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_jumpTo_setsAbsoluteValue() {
-        val result =
-            DirectionalMotionSpec.builder(Spring, Mapping.Fixed(99f))
-                .toBreakpoint(10f)
-                .jumpTo(20f)
-                .continueWithConstantValue()
-                .complete()
-
-        assertThat(result).breakpoints().positions().containsExactly(10f)
-        assertThat(result).mappings().atOrAfter(10f).isConstantValue(20f)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_jumpBy_setsRelativeValue() {
-        val result =
-            DirectionalMotionSpec.builder(Spring, Mapping.Linear(factor = 0.5f))
-                .toBreakpoint(10f)
-                .jumpBy(30f)
-                .continueWithConstantValue()
-                .complete()
-
-        assertThat(result).breakpoints().positions().containsExactly(10f)
-        assertThat(result).mappings().atOrAfter(10f).isConstantValue(35f)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_continueWithConstantValue_usesSourceValue() {
-        val result =
-            DirectionalMotionSpec.builder(Spring, Mapping.Linear(factor = 0.5f))
-                .toBreakpoint(5f)
-                .jumpBy(0f)
-                .continueWithConstantValue()
-                .complete()
-
-        assertThat(result).mappings().atOrAfter(5f).isConstantValue(2.5f)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_continueWithFractionalInput_matchesLinearMapping() {
-        val result =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(5f)
-                .jumpTo(1f)
-                .continueWithFractionalInput(fraction = .1f)
-                .complete()
-
-        assertThat(result)
-            .mappings()
-            .atOrAfter(5f)
-            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 15f, out2 = 2f)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_reverse_continueWithFractionalInput_matchesLinearMapping() {
-        val result =
-            DirectionalMotionSpec.reverseBuilder(Spring)
-                .toBreakpoint(15f)
-                .jumpTo(2f)
-                .continueWithFractionalInput(fraction = .1f)
-                .complete()
-
-        assertThat(result)
-            .mappings()
-            .atOrAfter(5f)
-            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 15f, out2 = 2f)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_continueWithTargetValue_matchesLinearMapping() {
-        val result =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(5f)
-                .jumpTo(1f)
-                .continueWithTargetValue(target = 20f)
-                .toBreakpoint(30f)
-                .completeWith(Mapping.Identity)
-
-        assertThat(result)
-            .mappings()
-            .atOrAfter(5f)
-            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 30f, out2 = 20f)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_reverse_continueWithTargetValue_matchesLinearMapping() {
-        val result =
-            DirectionalMotionSpec.reverseBuilder(Spring)
-                .toBreakpoint(30f)
-                .jumpTo(20f)
-                .continueWithTargetValue(target = 1f)
-                .toBreakpoint(5f)
-                .completeWith(Mapping.Identity)
-
-        assertThat(result)
-            .mappings()
-            .atOrAfter(5f)
-            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 30f, out2 = 20f)
-    }
-
-    @Test
-    fun directionalSpec_mappingBuilder_breakpointsAtSamePosition_producesValidSegment() {
-        val result =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(5f)
-                .jumpTo(1f)
-                .continueWithTargetValue(target = 20f)
-                .toBreakpoint(5f)
-                .completeWith(Mapping.Identity)
-
-        assertThat(result)
-            .mappings()
-            .containsExactly(Mapping.Identity, Mapping.Fixed(1f), Mapping.Identity)
-            .inOrder()
-    }
-
-    companion object {
-        val Spring = SpringParameters(stiffness = 100f, dampingRatio = 1f)
-        val B1 = BreakpointKey("One")
-        val B2 = BreakpointKey("Two")
-    }
-}
diff --git a/mechanics/tests/src/com/android/mechanics/spec/MotionSpecDebugFormatterTest.kt b/mechanics/tests/src/com/android/mechanics/spec/MotionSpecDebugFormatterTest.kt
new file mode 100644
index 0000000..1777a72
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/spec/MotionSpecDebugFormatterTest.kt
@@ -0,0 +1,145 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spec.ChangeSegmentHandlers.PreventDirectionChangeWithinCurrentSegment
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spec.builder.effectsDirectionalMotionSpec
+import com.android.mechanics.spec.builder.spatialDirectionalMotionSpec
+import com.android.mechanics.testing.FakeMotionSpecBuilderContext
+import com.google.common.truth.Truth.assertThat
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class MotionSpecDebugFormatterTest : MotionBuilderContext by FakeMotionSpecBuilderContext.Default {
+
+    @Test
+    fun motionSpec_unidirectionalSpec_formatIsUseful() {
+        val spec = MotionSpec(effectsDirectionalMotionSpec { fixedValue(0f, value = 1f) })
+
+        assertThat(formatForTest(spec.toDebugString()))
+            .isEqualTo(
+                """
+unidirectional:
+  @-Infinity [built-in::min|id:0x1234cdef]
+    Fixed(value=0.0)
+  @0.0 [id:0x1234cdef] spring=1600.0/1.0
+    Fixed(value=1.0)
+  @Infinity [built-in::max|id:0x1234cdef]"""
+                    .trimIndent()
+            )
+    }
+
+    @Test
+    fun motionSpec_bidirectionalSpec_formatIsUseful() {
+        val spec =
+            MotionSpec(
+                spatialDirectionalMotionSpec(Mapping.Zero) { fixedValue(0f, value = 1f) },
+                spatialDirectionalMotionSpec(Mapping.One) { fixedValue(0f, value = 0f) },
+            )
+
+        assertThat(formatForTest(spec.toDebugString()))
+            .isEqualTo(
+                """
+maxDirection:
+  @-Infinity [built-in::min|id:0x1234cdef]
+    Fixed(value=0.0)
+  @0.0 [id:0x1234cdef] spring=700.0/0.9
+    Fixed(value=1.0)
+  @Infinity [built-in::max|id:0x1234cdef]
+minDirection:
+  @-Infinity [built-in::min|id:0x1234cdef]
+    Fixed(value=1.0)
+  @0.0 [id:0x1234cdef] spring=700.0/0.9
+    Fixed(value=0.0)
+  @Infinity [built-in::max|id:0x1234cdef]"""
+                    .trimIndent()
+            )
+    }
+
+    @Test
+    fun motionSpec_semantics_formatIsUseful() {
+        val semanticKey = SemanticKey<Float>("foo")
+
+        val spec =
+            MotionSpec(
+                effectsDirectionalMotionSpec(semantics = listOf(semanticKey with 42f)) {
+                    fixedValue(0f, value = 1f, semantics = listOf(semanticKey with 43f))
+                }
+            )
+
+        assertThat(formatForTest(spec.toDebugString()))
+            .isEqualTo(
+                """
+unidirectional:
+  @-Infinity [built-in::min|id:0x1234cdef]
+    Fixed(value=0.0)
+      foo[id:0x1234cdef]=42.0
+  @0.0 [id:0x1234cdef] spring=1600.0/1.0
+    Fixed(value=1.0)
+      foo[id:0x1234cdef]=43.0
+  @Infinity [built-in::max|id:0x1234cdef]"""
+                    .trimIndent()
+            )
+    }
+
+    @Test
+    fun motionSpec_segmentHandlers_formatIsUseful() {
+        val key1 = BreakpointKey("1")
+        val key2 = BreakpointKey("2")
+        val spec =
+            MotionSpec(
+                effectsDirectionalMotionSpec {
+                    fixedValue(0f, value = 1f, key = key1)
+                    fixedValue(2f, value = 2f, key = key1)
+                },
+                segmentHandlers =
+                    mapOf(
+                        SegmentKey(key1, key2, InputDirection.Max) to
+                            PreventDirectionChangeWithinCurrentSegment,
+                        SegmentKey(key1, key2, InputDirection.Min) to
+                            PreventDirectionChangeWithinCurrentSegment,
+                    ),
+            )
+
+        assertThat(formatForTest(spec.toDebugString()))
+            .isEqualTo(
+                """
+unidirectional:
+  @-Infinity [built-in::min|id:0x1234cdef]
+    Fixed(value=0.0)
+  @0.0 [1|id:0x1234cdef] spring=1600.0/1.0
+    Fixed(value=1.0)
+  @2.0 [1|id:0x1234cdef] spring=1600.0/1.0
+    Fixed(value=2.0)
+  @Infinity [built-in::max|id:0x1234cdef]
+segmentHandlers:
+  1|id:0x1234cdef >> 2|id:0x1234cdef
+  1|id:0x1234cdef << 2|id:0x1234cdef"""
+                    .trimIndent()
+            )
+    }
+
+    companion object {
+        private val idMatcher = Regex("id:0x[0-9a-f]{8}")
+
+        fun formatForTest(debugString: String) =
+            debugString.replace(idMatcher, "id:0x1234cdef").trim()
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/spec/MotionSpecTest.kt b/mechanics/tests/src/com/android/mechanics/spec/MotionSpecTest.kt
index 3254695..260a8a7 100644
--- a/mechanics/tests/src/com/android/mechanics/spec/MotionSpecTest.kt
+++ b/mechanics/tests/src/com/android/mechanics/spec/MotionSpecTest.kt
@@ -17,9 +17,11 @@
 package com.android.mechanics.spec
 
 import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spec.builder.directionalMotionSpec
 import com.android.mechanics.spring.SpringParameters
 import com.android.mechanics.testing.BreakpointSubject.Companion.assertThat
 import com.google.common.truth.Truth.assertThat
+import kotlin.test.assertFailsWith
 import org.junit.Test
 import org.junit.runner.RunWith
 
@@ -28,18 +30,19 @@ class MotionSpecTest {
 
     @Test
     fun containsSegment_unknownSegment_returnsFalse() {
-        val underTest = MotionSpec.builder(Spring).complete()
+        val underTest = MotionSpec.Empty
         assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Max))).isFalse()
     }
 
     @Test
     fun containsSegment_symmetricSpec_knownSegment_returnsTrue() {
         val underTest =
-            MotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(20f, key = B2)
-                .completeWith(Mapping.Identity)
+            MotionSpec(
+                directionalMotionSpec(Spring) {
+                    fixedValue(breakpoint = 10f, key = B1, value = 1f)
+                    identity(breakpoint = 20f, key = B2)
+                }
+            )
 
         assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Max))).isTrue()
         assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Min))).isTrue()
@@ -47,15 +50,15 @@ class MotionSpecTest {
 
     @Test
     fun containsSegment_asymmetricSpec_knownMaxDirectionSegment_trueOnlyInMaxDirection() {
-        val forward =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(20f, key = B2)
-                .completeWith(Mapping.Identity)
-        val reverse = DirectionalMotionSpec.builder(Spring).complete()
-
-        val underTest = MotionSpec(forward, reverse)
+        val underTest =
+            MotionSpec(
+                maxDirection =
+                    directionalMotionSpec(Spring) {
+                        fixedValue(breakpoint = 10f, key = B1, value = 1f)
+                        identity(breakpoint = 20f, key = B2)
+                    },
+                minDirection = DirectionalMotionSpec.Empty,
+            )
 
         assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Max))).isTrue()
         assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Min))).isFalse()
@@ -63,15 +66,15 @@ class MotionSpecTest {
 
     @Test
     fun containsSegment_asymmetricSpec_knownMinDirectionSegment_trueOnlyInMinDirection() {
-        val forward = DirectionalMotionSpec.builder(Spring).complete()
-        val reverse =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(20f, key = B2)
-                .completeWith(Mapping.Identity)
-
-        val underTest = MotionSpec(forward, reverse)
+        val underTest =
+            MotionSpec(
+                maxDirection = DirectionalMotionSpec.Empty,
+                minDirection =
+                    directionalMotionSpec(Spring) {
+                        fixedValue(breakpoint = 10f, key = B1, value = 1f)
+                        identity(breakpoint = 20f, key = B2)
+                    },
+            )
 
         assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Max))).isFalse()
         assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Min))).isTrue()
@@ -79,7 +82,7 @@ class MotionSpecTest {
 
     @Test
     fun segmentAtInput_emptySpec_maxDirection_segmentDataIsCorrect() {
-        val underTest = MotionSpec.builder(Spring).complete()
+        val underTest = MotionSpec.Empty
 
         val segmentAtInput = underTest.segmentAtInput(0f, InputDirection.Max)
 
@@ -92,7 +95,7 @@ class MotionSpecTest {
 
     @Test
     fun segmentAtInput_emptySpec_minDirection_segmentDataIsCorrect() {
-        val underTest = MotionSpec.builder(Spring).complete()
+        val underTest = MotionSpec.Empty
 
         val segmentAtInput = underTest.segmentAtInput(0f, InputDirection.Min)
 
@@ -106,11 +109,12 @@ class MotionSpecTest {
     @Test
     fun segmentAtInput_atBreakpointPosition() {
         val underTest =
-            MotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(20f, key = B2)
-                .completeWith(Mapping.Identity)
+            MotionSpec(
+                directionalMotionSpec(Spring) {
+                    fixedValue(breakpoint = 10f, key = B1, value = 1f)
+                    identity(breakpoint = 20f, key = B2)
+                }
+            )
 
         val segmentAtInput = underTest.segmentAtInput(10f, InputDirection.Max)
 
@@ -123,11 +127,12 @@ class MotionSpecTest {
     @Test
     fun segmentAtInput_reverse_atBreakpointPosition() {
         val underTest =
-            MotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(20f, key = B2)
-                .completeWith(Mapping.Identity)
+            MotionSpec(
+                directionalMotionSpec(Spring) {
+                    fixedValue(breakpoint = 10f, key = B1, value = 1f)
+                    identity(breakpoint = 20f, key = B2)
+                }
+            )
 
         val segmentAtInput = underTest.segmentAtInput(20f, InputDirection.Min)
 
@@ -139,20 +144,19 @@ class MotionSpecTest {
 
     @Test
     fun containsSegment_asymmetricSpec_readsFromIndicatedDirection() {
-        val forward =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(20f, key = B2)
-                .completeWith(Mapping.Identity)
-        val reverse =
-            DirectionalMotionSpec.builder(Spring)
-                .toBreakpoint(5f, key = B1)
-                .continueWith(Mapping.Two)
-                .toBreakpoint(25f, key = B2)
-                .completeWith(Mapping.Identity)
-
-        val underTest = MotionSpec(forward, reverse)
+        val underTest =
+            MotionSpec(
+                maxDirection =
+                    directionalMotionSpec(Spring) {
+                        fixedValue(breakpoint = 10f, key = B1, value = 1f)
+                        identity(breakpoint = 20f, key = B2)
+                    },
+                minDirection =
+                    directionalMotionSpec(Spring) {
+                        fixedValue(breakpoint = 5f, key = B1, value = 2f)
+                        identity(breakpoint = 25f, key = B2)
+                    },
+            )
 
         val segmentAtInputMax = underTest.segmentAtInput(15f, InputDirection.Max)
         assertThat(segmentAtInputMax.key).isEqualTo(SegmentKey(B1, B2, InputDirection.Max))
@@ -170,11 +174,12 @@ class MotionSpecTest {
     @Test
     fun onSegmentChanged_noHandler_returnsEqualSegmentForSameInput() {
         val underTest =
-            MotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(20f, key = B2)
-                .completeWith(Mapping.Identity)
+            MotionSpec(
+                directionalMotionSpec(Spring) {
+                    fixedValue(breakpoint = 10f, key = B1, value = 1f)
+                    identity(breakpoint = 20f, key = B2)
+                }
+            )
 
         val segmentAtInput = underTest.segmentAtInput(15f, InputDirection.Max)
         val onChangedResult = underTest.onChangeSegment(segmentAtInput, 15f, InputDirection.Max)
@@ -184,11 +189,12 @@ class MotionSpecTest {
     @Test
     fun onSegmentChanged_noHandler_returnsNewSegmentForNewInput() {
         val underTest =
-            MotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(20f, key = B2)
-                .completeWith(Mapping.Identity)
+            MotionSpec(
+                directionalMotionSpec(Spring) {
+                    fixedValue(breakpoint = 10f, key = B1, value = 1f)
+                    identity(breakpoint = 20f, key = B2)
+                }
+            )
 
         val segmentAtInput = underTest.segmentAtInput(15f, InputDirection.Max)
         val onChangedResult = underTest.onChangeSegment(segmentAtInput, 15f, InputDirection.Min)
@@ -200,11 +206,12 @@ class MotionSpecTest {
     @Test
     fun onSegmentChanged_withHandlerReturningNull_returnsSegmentAtInput() {
         val underTest =
-            MotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(20f, key = B2)
-                .completeWith(Mapping.Identity)
+            MotionSpec(
+                    directionalMotionSpec(Spring) {
+                        fixedValue(breakpoint = 10f, key = B1, value = 1f)
+                        identity(breakpoint = 20f, key = B2)
+                    }
+                )
                 .copy(
                     segmentHandlers =
                         mapOf(SegmentKey(B1, B2, InputDirection.Max) to { _, _, _ -> null })
@@ -220,11 +227,12 @@ class MotionSpecTest {
     @Test
     fun onSegmentChanged_withHandlerReturningSegment_returnsHandlerResult() {
         val underTest =
-            MotionSpec.builder(Spring)
-                .toBreakpoint(10f, key = B1)
-                .continueWith(Mapping.One)
-                .toBreakpoint(20f, key = B2)
-                .completeWith(Mapping.Identity)
+            MotionSpec(
+                    directionalMotionSpec(Spring) {
+                        fixedValue(breakpoint = 10f, key = B1, value = 1f)
+                        identity(breakpoint = 20f, key = B2)
+                    }
+                )
                 .copy(
                     segmentHandlers =
                         mapOf(
@@ -243,9 +251,70 @@ class MotionSpecTest {
             .isEqualTo(SegmentKey(Breakpoint.minLimit.key, B1, InputDirection.Min))
     }
 
+    @Test
+    fun semanticState_returnsStateFromSegment() {
+        val underTest =
+            MotionSpec(
+                maxDirection = directionalMotionSpec(semantics = listOf(S1 with "One")),
+                minDirection = directionalMotionSpec(semantics = listOf(S1 with "Two")),
+            )
+
+        val maxDirectionSegment = SegmentKey(BMin, BMax, InputDirection.Max)
+        assertThat(underTest.semanticState(S1, maxDirectionSegment)).isEqualTo("One")
+
+        val minDirectionSegment = SegmentKey(BMin, BMax, InputDirection.Min)
+        assertThat(underTest.semanticState(S1, minDirectionSegment)).isEqualTo("Two")
+    }
+
+    @Test
+    fun semanticState_unknownSegment_throws() {
+        val underTest = MotionSpec(directionalMotionSpec(semantics = listOf(S1 with "One")))
+
+        val unknownSegment = SegmentKey(BMin, B1, InputDirection.Max)
+        assertFailsWith<NoSuchElementException> { underTest.semanticState(S1, unknownSegment) }
+    }
+
+    @Test
+    fun semanticState_unknownSemantics_returnsNull() {
+        val underTest = MotionSpec(directionalMotionSpec(semantics = listOf(S1 with "One")))
+
+        val maxDirectionSegment = SegmentKey(BMin, BMax, InputDirection.Max)
+        assertThat(underTest.semanticState(S2, maxDirectionSegment)).isNull()
+    }
+
+    @Test
+    fun semantics_returnsAllValuesForSegment() {
+        val underTest =
+            MotionSpec(
+                directionalMotionSpec(Spring, semantics = listOf(S1 with "One", S2 with "AAA")) {
+                    identity(breakpoint = 0f, key = B1, semantics = listOf(S2 with "BBB"))
+                    identity(breakpoint = 2f, key = B2, semantics = listOf(S1 with "Two"))
+                }
+            )
+
+        assertThat(underTest.semantics(SegmentKey(BMin, B1, InputDirection.Max)))
+            .containsExactly(S1 with "One", S2 with "AAA")
+        assertThat(underTest.semantics(SegmentKey(B1, B2, InputDirection.Max)))
+            .containsExactly(S1 with "One", S2 with "BBB")
+        assertThat(underTest.semantics(SegmentKey(B2, BMax, InputDirection.Max)))
+            .containsExactly(S1 with "Two", S2 with "BBB")
+    }
+
+    @Test
+    fun semantics_unknownSegment_throws() {
+        val underTest = MotionSpec.Empty
+        val unknownSegment = SegmentKey(BMin, B1, InputDirection.Max)
+        assertFailsWith<NoSuchElementException> { underTest.semantics(unknownSegment) }
+    }
+
     companion object {
+        val BMin = Breakpoint.minLimit.key
         val B1 = BreakpointKey("one")
         val B2 = BreakpointKey("two")
+        val BMax = Breakpoint.maxLimit.key
+        val S1 = SemanticKey<String>("Foo")
+        val S2 = SemanticKey<String>("Bar")
+
         val Spring = SpringParameters(stiffness = 100f, dampingRatio = 1f)
     }
 }
diff --git a/mechanics/tests/src/com/android/mechanics/spec/builder/DirectionalBuilderImplTest.kt b/mechanics/tests/src/com/android/mechanics/spec/builder/DirectionalBuilderImplTest.kt
new file mode 100644
index 0000000..b399731
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/spec/builder/DirectionalBuilderImplTest.kt
@@ -0,0 +1,295 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec.builder
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spec.BreakpointKey
+import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.SemanticKey
+import com.android.mechanics.spec.with
+import com.android.mechanics.spring.SpringParameters
+import com.android.mechanics.testing.DirectionalMotionSpecSubject.Companion.assertThat
+import com.android.mechanics.testing.FakeMotionSpecBuilderContext
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class DirectionalBuilderImplTest {
+
+    @Test
+    fun directionalSpec_buildEmptySpec() {
+        val result = directionalMotionSpec()
+
+        assertThat(result).breakpoints().isEmpty()
+        assertThat(result).mappings().containsExactly(Mapping.Identity)
+    }
+
+    @Test
+    fun directionalSpec_addBreakpointsAndMappings() {
+        val result =
+            directionalMotionSpec(Spring, Mapping.Zero) {
+                mapping(breakpoint = 0f, mapping = Mapping.One, key = B1)
+                mapping(breakpoint = 10f, mapping = Mapping.Two, key = B2)
+            }
+
+        assertThat(result).breakpoints().keys().containsExactly(B1, B2).inOrder()
+        assertThat(result).breakpoints().withKey(B1).isAt(0f)
+        assertThat(result).breakpoints().withKey(B2).isAt(10f)
+        assertThat(result)
+            .mappings()
+            .containsExactly(Mapping.Zero, Mapping.One, Mapping.Two)
+            .inOrder()
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_setsDefaultSpring() {
+        val result = directionalMotionSpec(Spring) { fixedValue(breakpoint = 10f, value = 20f) }
+
+        assertThat(result).breakpoints().atPosition(10f).spring().isEqualTo(Spring)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_canOverrideDefaultSpring() {
+        val otherSpring = SpringParameters(stiffness = 10f, dampingRatio = 0.1f)
+        val result =
+            directionalMotionSpec(Spring) {
+                fixedValue(breakpoint = 10f, value = 20f, spring = otherSpring)
+            }
+
+        assertThat(result).breakpoints().atPosition(10f).spring().isEqualTo(otherSpring)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_defaultsToNoGuarantee() {
+        val result = directionalMotionSpec(Spring) { fixedValue(breakpoint = 10f, value = 20f) }
+
+        assertThat(result).breakpoints().atPosition(10f).guarantee().isEqualTo(Guarantee.None)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_canSetGuarantee() {
+        val guarantee = Guarantee.InputDelta(10f)
+        val result =
+            directionalMotionSpec(Spring) {
+                fixedValue(breakpoint = 10f, value = 20f, guarantee = guarantee)
+            }
+
+        assertThat(result).breakpoints().atPosition(10f).guarantee().isEqualTo(guarantee)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_jumpTo_setsAbsoluteValue() {
+        val result =
+            directionalMotionSpec(Spring, Mapping.Fixed(99f)) {
+                fixedValue(breakpoint = 10f, value = 20f)
+            }
+
+        assertThat(result).breakpoints().positions().containsExactly(10f)
+        assertThat(result).mappings().atOrAfter(10f).isFixedValue(20f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_jumpBy_setsRelativeValue() {
+        val result =
+            directionalMotionSpec(Spring, Mapping.Linear(factor = 0.5f)) {
+                // At 10f the current value is 5f (10f * 0.5f)
+                fixedValueFromCurrent(breakpoint = 10f, delta = 30f)
+            }
+
+        assertThat(result).breakpoints().positions().containsExactly(10f)
+        assertThat(result).mappings().atOrAfter(10f).isFixedValue(35f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_continueWithFixedValue_usesSourceValue() {
+        val result =
+            directionalMotionSpec(Spring, Mapping.Linear(factor = 0.5f)) {
+                // At 5f the current value is 2.5f (5f * 0.5f)
+                fixedValueFromCurrent(breakpoint = 5f)
+            }
+
+        assertThat(result).mappings().atOrAfter(5f).isFixedValue(2.5f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_continueWithFractionalInput_matchesLinearMapping() {
+        val result =
+            directionalMotionSpec(Spring) {
+                fractionalInput(breakpoint = 5f, from = 1f, fraction = .1f)
+            }
+
+        assertThat(result)
+            .mappings()
+            .atOrAfter(5f)
+            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 15f, out2 = 2f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_continueWithTargetValue_matchesLinearMapping() {
+        val result =
+            directionalMotionSpec(Spring) {
+                target(breakpoint = 5f, from = 1f, to = 20f)
+                mapping(breakpoint = 30f, mapping = Mapping.Identity)
+            }
+
+        assertThat(result)
+            .mappings()
+            .atOrAfter(5f)
+            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 30f, out2 = 20f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_breakpointsAtSamePosition_producesValidSegment() {
+        val result =
+            directionalMotionSpec(Spring) {
+                target(breakpoint = 5f, from = 1f, to = 20f)
+                mapping(breakpoint = 5f, mapping = Mapping.Identity)
+            }
+        assertThat(result)
+            .mappings()
+            .containsExactly(Mapping.Identity, Mapping.Fixed(1f), Mapping.Identity)
+            .inOrder()
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_identity_addsIdentityMapping() {
+        val result = directionalMotionSpec(Spring, Mapping.Zero) { identity(breakpoint = 10f) }
+        assertThat(result).mappings().containsExactly(Mapping.Zero, Mapping.Identity).inOrder()
+        assertThat(result).breakpoints().positions().containsExactly(10f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_identityWithDelta_producesLinearMapping() {
+        val result =
+            directionalMotionSpec(Spring, Mapping.Zero) { identity(breakpoint = 10f, delta = 2f) }
+
+        assertThat(result)
+            .mappings()
+            .atOrAfter(10f)
+            .matchesLinearMapping(in1 = 10f, out1 = 12f, in2 = 20f, out2 = 22f)
+    }
+
+    @Test
+    fun semantics_appliedForSingleSegment() {
+        val result = directionalMotionSpec(Mapping.Identity, listOf(S1 with "One", S2 with "Two"))
+
+        assertThat(result).semantics().containsExactly(S1, S2)
+        assertThat(result).semantics().withKey(S1).containsExactly("One")
+        assertThat(result).semantics().withKey(S2).containsExactly("Two")
+    }
+
+    @Test
+    fun directionalSpec_semantics_appliedForAllSegments() {
+        val result =
+            directionalMotionSpec(Spring, semantics = listOf(S1 with "One")) {
+                mapping(breakpoint = 0f, mapping = Mapping.Identity)
+            }
+        assertThat(result).mappings().hasSize(2)
+        assertThat(result).semantics().containsExactly(S1)
+        assertThat(result).semantics().withKey(S1).containsExactly("One", "One")
+    }
+
+    @Test
+    fun directionalSpec_semantics_appliedForCurrentSegment() {
+        val result =
+            directionalMotionSpec(Spring, semantics = listOf(S1 with "One")) {
+                mapping(breakpoint = 0f, mapping = Mapping.Identity)
+                mapping(
+                    breakpoint = 2f,
+                    mapping = Mapping.Identity,
+                    semantics = listOf(S1 with "Two"),
+                )
+            }
+        assertThat(result).mappings().hasSize(3)
+        assertThat(result).semantics().withKey(S1).containsExactly("One", "One", "Two").inOrder()
+    }
+
+    @Test
+    fun directionalSpec_semantics_changingUndeclaredSemantics_backfills() {
+        val result =
+            directionalMotionSpec(Spring) {
+                mapping(
+                    breakpoint = 0f,
+                    mapping = Mapping.Identity,
+                    semantics = listOf(S1 with "Two"),
+                )
+            }
+
+        assertThat(result).mappings().hasSize(2)
+        assertThat(result).semantics().withKey(S1).containsExactly("Two", "Two").inOrder()
+    }
+
+    @Test
+    fun directionalSpec_semantics_changeableIndividually() {
+        val result =
+            directionalMotionSpec(Spring, semantics = listOf(S1 with "One", S2 with "AAA")) {
+                mapping(
+                    breakpoint = 0f,
+                    mapping = Mapping.Identity,
+                    semantics = listOf(S2 with "BBB"),
+                )
+                mapping(
+                    breakpoint = 2f,
+                    mapping = Mapping.Identity,
+                    semantics = listOf(S1 with "Two"),
+                )
+            }
+        assertThat(result).mappings().hasSize(3)
+        assertThat(result).semantics().withKey(S1).containsExactly("One", "One", "Two").inOrder()
+        assertThat(result).semantics().withKey(S2).containsExactly("AAA", "BBB", "BBB").inOrder()
+    }
+
+    @Test
+    fun directionalSpec_semantics_lateCompletedSegmentsRetainSemantics() {
+        val result =
+            directionalMotionSpec(Spring, semantics = listOf(S1 with "One")) {
+                targetFromCurrent(breakpoint = 0f, to = 10f, semantics = listOf(S1 with "Two"))
+                identity(breakpoint = 1f, semantics = listOf(S1 with "Three"))
+            }
+        assertThat(result).mappings().hasSize(3)
+        assertThat(result).semantics().withKey(S1).containsExactly("One", "Two", "Three").inOrder()
+    }
+
+    @Test
+    fun builderContext_spatialDirectionalMotionSpec_defaultsToSpatialSpringAndIdentityMapping() {
+        val context = FakeMotionSpecBuilderContext.Default
+
+        val result = with(context) { spatialDirectionalMotionSpec { fixedValue(0f, value = 1f) } }
+
+        assertThat(result).mappings().containsExactly(Mapping.Identity, Mapping.One).inOrder()
+        assertThat(result).breakpoints().atPosition(0f).spring().isEqualTo(context.spatial.default)
+    }
+
+    @Test
+    fun builderContext_effectsDirectionalMotionSpec_defaultsToEffectsSpringAndZeroMapping() {
+        val context = FakeMotionSpecBuilderContext.Default
+
+        val result = with(context) { effectsDirectionalMotionSpec { fixedValue(0f, value = 1f) } }
+
+        assertThat(result).mappings().containsExactly(Mapping.Zero, Mapping.One).inOrder()
+        assertThat(result).breakpoints().atPosition(0f).spring().isEqualTo(context.effects.default)
+    }
+
+    companion object {
+        val Spring = SpringParameters(stiffness = 100f, dampingRatio = 1f)
+        val B1 = BreakpointKey("One")
+        val B2 = BreakpointKey("Two")
+        val S1 = SemanticKey<String>("Foo")
+        val S2 = SemanticKey<String>("Bar")
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/spec/builder/MotionSpecBuilderTest.kt b/mechanics/tests/src/com/android/mechanics/spec/builder/MotionSpecBuilderTest.kt
new file mode 100644
index 0000000..2b6760a
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/spec/builder/MotionSpecBuilderTest.kt
@@ -0,0 +1,740 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.spec.builder
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.effects.FixedValue
+import com.android.mechanics.spec.BreakpointKey
+import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.SemanticKey
+import com.android.mechanics.spec.SemanticValue
+import com.android.mechanics.spec.with
+import com.android.mechanics.spring.SpringParameters
+import com.android.mechanics.testing.FakeMotionSpecBuilderContext
+import com.android.mechanics.testing.MotionSpecSubject.Companion.assertThat
+import com.google.common.truth.Truth.assertThat
+import kotlin.test.assertFailsWith
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class MotionSpecBuilderTest : MotionBuilderContext by FakeMotionSpecBuilderContext.Default {
+
+    // placement & ordering
+    // placement types
+    // placement issues
+    // before & after mapping, springs etc
+
+    @Test
+    fun motionSpec_empty_usesBaseMapping() {
+        val result = spatialMotionSpec {}
+
+        assertThat(result).bothDirections().mappingsMatch(Mapping.Identity)
+        assertThat(result).bothDirections().breakpoints().isEmpty()
+    }
+
+    @Test
+    fun placement_absoluteAfter_createsTwoSegments() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                after(42f, FixedValue(1f))
+            }
+
+        assertThat(result).bothDirections().mappingsMatch(Mapping.Zero, Mapping.One)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(42f)
+    }
+
+    @Test
+    fun placement_absoluteBefore_createsTwoSegments() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                before(42f, FixedValue(1f))
+            }
+
+        assertThat(result).bothDirections().mappingsMatch(Mapping.One, Mapping.Zero)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(42f)
+    }
+
+    @Test
+    fun placement_absoluteBetween_createsThreeSegments() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(42f, 43f, FixedValue(1f))
+            }
+
+        assertThat(result).bothDirections().mappingsMatch(Mapping.Zero, Mapping.One, Mapping.Zero)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(42f, 43f)
+    }
+
+    @Test
+    fun placement_absoluteBetweenReverse_createsThreeSegments() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(43f, 42f, FixedValue(1f))
+            }
+
+        assertThat(result).bothDirections().mappingsMatch(Mapping.Zero, Mapping.One, Mapping.Zero)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(42f, 43f)
+    }
+
+    @Test
+    fun placement_adjacent_sharesBreakpoint() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, FixedValue(1f))
+                between(2f, 3f, FixedValue(2f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, 1f, 2f, 0f)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(1f, 2f, 3f)
+    }
+
+    @Test
+    fun placement_multiple_baseMappingInBetween() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, FixedValue(1f))
+                // Implicit baseMapping between 2 & 3
+                between(3f, 4f, FixedValue(2f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, 1f, 0f, 2f, 0f)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(1f, 2f, 3f, 4f)
+    }
+
+    @Test
+    fun placement_overlapping_throws() {
+        val exception =
+            assertFailsWith<IllegalArgumentException> {
+                motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                    between(1f, 2f, FixedValue(1f))
+                    between(1.5f, 2.5f, FixedValue(2f))
+                }
+            }
+        assertThat(exception).hasMessageThat().contains("overlap")
+    }
+
+    @Test
+    fun placement_embedded_throws() {
+        val exception =
+            assertFailsWith<IllegalArgumentException> {
+                motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                    between(1f, 3f, FixedValue(1f))
+                    between(1.5f, 2.5f, FixedValue(2f))
+                }
+            }
+        assertThat(exception).hasMessageThat().contains("overlap")
+    }
+
+    @Test
+    fun placement_subsequent_extendsToNext() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                after(1f, FixedValue(1f))
+                between(3f, 4f, FixedValue(2f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, 1f, 2f, 0f)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(1f, 3f, 4f)
+    }
+
+    @Test
+    fun placement_subsequent_extendsToPrevious() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, FixedValue(1f))
+                before(4f, FixedValue(2f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, 1f, 2f, 0f)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(1f, 2f, 4f)
+    }
+
+    @Test
+    fun placement_subsequent_bothExtend_throws() {
+        val exception =
+            assertFailsWith<IllegalArgumentException> {
+                motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                    after(1f, FixedValue(1f))
+                    before(3f, FixedValue(2f))
+                }
+            }
+        assertThat(exception).hasMessageThat().contains("extend")
+    }
+
+    @Test
+    fun placement_withFixedExtent_after_limitsEffect() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                after(1f, FixedValueWithExtent(1f, 2f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, 1f, 0f)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(1f, 3f)
+    }
+
+    @Test
+    fun placement_withFixedExtent_before_limitsEffect() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                before(1f, FixedValueWithExtent(1f, 2f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, 1f, 0f)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(-1f, 1f)
+    }
+
+    @Test
+    fun placement_relative_afterEffect() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                val effect1 = between(1f, 2f, FixedValue(1f))
+                after(effect1, FixedValue(2f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, 1f, 2f)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(1f, 2f)
+    }
+
+    @Test
+    fun placement_relative_beforeEffect() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                val effect1 = between(1f, 2f, FixedValue(1f))
+                before(effect1, FixedValue(2f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(2f, 1f, 0f)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(1f, 2f)
+    }
+
+    @Test
+    fun placement_relative_chainOfMappings() {
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                val rootEffect = after(1f, FixedValueWithExtent(-1f, 2f))
+
+                val left = before(rootEffect, FixedValueWithExtent(-2f, 3f))
+                before(left, FixedValueWithExtent(-3f, 4f))
+
+                val right = after(rootEffect, FixedValueWithExtent(-4f, 3f))
+                after(right, FixedValueWithExtent(-5f, 4f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, -3f, -2f, -1f, -4f, -5f, 0f)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(-6f, -2f, 1f, 3f, 6f, 10f)
+    }
+
+    @Test
+    fun placement_relative_overlappingChain_throws() {
+        assertFailsWith<IllegalArgumentException> {
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                val rootEffect = between(1f, 3f, FixedValue(-1f))
+                val left = before(rootEffect, FixedValue(-2f))
+                after(left, FixedValue(-3f))
+            }
+        }
+    }
+
+    @Test
+    fun effect_differentReverseSpec() {
+        val effect = SimpleEffect {
+            forward(Mapping.One)
+            backward(Mapping.Two)
+        }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+            }
+
+        assertThat(result).maxDirection().fixedMappingsMatch(0f, 1f, 0f)
+        assertThat(result).maxDirection().breakpointsPositionsMatch(1f, 2f)
+
+        assertThat(result).minDirection().fixedMappingsMatch(0f, 2f, 0f)
+        assertThat(result).minDirection().breakpointsPositionsMatch(1f, 2f)
+    }
+
+    @Test
+    fun effect_separateReverseSpec_withBuilder_canProduceDifferentSegmentCount() {
+        val effect =
+            object : Effect.PlaceableBetween {
+                override fun EffectApplyScope.createSpec(
+                    minLimit: Float,
+                    minLimitKey: BreakpointKey,
+                    maxLimit: Float,
+                    maxLimitKey: BreakpointKey,
+                    placement: EffectPlacement,
+                ) {
+                    forward(Mapping.One) { fixedValue(breakpoint = minLimit + 0.5f, 10f) }
+                    backward(Mapping.Two)
+                }
+            }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+            }
+
+        assertThat(result).maxDirection().fixedMappingsMatch(0f, 1f, 10f, 0f)
+        assertThat(result).maxDirection().breakpointsPositionsMatch(1f, 1.5f, 2f)
+
+        assertThat(result).minDirection().fixedMappingsMatch(0f, 2f, 0f)
+        assertThat(result).minDirection().breakpointsPositionsMatch(1f, 2f)
+    }
+
+    @Test
+    fun effect_identicalBackward_withBuilder_producesSameSpecInBothDirections() {
+        val breakpointKey = BreakpointKey("foo")
+        val effect =
+            UnidirectionalEffect(Mapping.One) {
+                fixedValue(breakpoint = 1.5f, value = 10f, key = breakpointKey)
+            }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, 1f, 10f, 0f)
+        assertThat(result).bothDirections().breakpointsPositionsMatch(1f, 1.5f, 2f)
+    }
+
+    @Test
+    fun effect_setBreakpointBeforeMinLimit_throws() {
+        val rogueEffect =
+            UnidirectionalEffect(Mapping.One) { this.fixedValue(breakpoint = 0.5f, value = 0f) }
+
+        assertFailsWith<IllegalStateException> {
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, rogueEffect)
+            }
+        }
+    }
+
+    @Test
+    fun effect_setBreakpointAfterMinLimit_throws() {
+        val rogueEffect =
+            UnidirectionalEffect(Mapping.One) { this.fixedValue(breakpoint = 2.5f, value = 0f) }
+
+        assertFailsWith<IllegalStateException> {
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, rogueEffect)
+            }
+        }
+    }
+
+    @Test
+    fun effect_semantics_applyToFullInputRange() {
+        val semanticKey = SemanticKey<String>("foo")
+        val effect =
+            UnidirectionalEffect(
+                Mapping.One,
+                semantics = listOf(SemanticValue(semanticKey, "initial")),
+            ) {
+                fixedValue(
+                    breakpoint = 1.5f,
+                    value = 2f,
+                    semantics = listOf(SemanticValue(semanticKey, "second")),
+                )
+            }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+            }
+
+        assertThat(result)
+            .maxDirection()
+            .semantics()
+            .withKey(semanticKey)
+            .containsExactly("initial", "initial", "second", "second")
+            .inOrder()
+    }
+
+    @Test
+    fun beforeAfter_minSpring_isChangeable() {
+        val spring = SpringParameters(stiffness = 1f, dampingRatio = 2f)
+        val effect = UnidirectionalEffect(Mapping.One) { before(spring = spring) }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+            }
+
+        assertThat(result).bothDirections().breakpoints().atPosition(1f).spring().isEqualTo(spring)
+    }
+
+    @Test
+    fun beforeAfter_maxSpring_isChangeable() {
+        val spring = SpringParameters(stiffness = 1f, dampingRatio = 2f)
+        val effect = UnidirectionalEffect(Mapping.One) { after(spring = spring) }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+            }
+
+        assertThat(result).bothDirections().breakpoints().atPosition(2f).spring().isEqualTo(spring)
+    }
+
+    @Test
+    fun beforeAfter_conflictingSpring_secondEffectWins() {
+        val spring1 = SpringParameters(stiffness = 1f, dampingRatio = 2f)
+        val spring2 = SpringParameters(stiffness = 2f, dampingRatio = 2f)
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, UnidirectionalEffect(Mapping.One) { after(spring = spring1) })
+                between(2f, 3f, UnidirectionalEffect(Mapping.One) { before(spring = spring2) })
+            }
+
+        assertThat(result).bothDirections().breakpoints().atPosition(2f).spring().isEqualTo(spring2)
+    }
+
+    @Test
+    fun beforeAfter_minGuarantee_isChangeable() {
+        val guarantee = Guarantee.InputDelta(1f)
+        val effect = UnidirectionalEffect(Mapping.One) { before(guarantee = guarantee) }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+            }
+
+        assertThat(result)
+            .bothDirections()
+            .breakpoints()
+            .atPosition(1f)
+            .guarantee()
+            .isEqualTo(guarantee)
+    }
+
+    @Test
+    fun beforeAfter_maxGuarantee_isChangeable() {
+        val guarantee = Guarantee.InputDelta(1f)
+        val effect = UnidirectionalEffect(Mapping.One) { after(guarantee = guarantee) }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+            }
+
+        assertThat(result)
+            .bothDirections()
+            .breakpoints()
+            .atPosition(2f)
+            .guarantee()
+            .isEqualTo(guarantee)
+    }
+
+    @Test
+    fun beforeAfter_conflictingGuarantee_secondEffectWins() {
+        val guarantee1 = Guarantee.InputDelta(1f)
+        val guarantee2 = Guarantee.InputDelta(2f)
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, UnidirectionalEffect(Mapping.One) { after(guarantee = guarantee1) })
+                between(
+                    2f,
+                    3f,
+                    UnidirectionalEffect(Mapping.One) { before(guarantee = guarantee2) },
+                )
+            }
+
+        assertThat(result)
+            .bothDirections()
+            .breakpoints()
+            .atPosition(2f)
+            .guarantee()
+            .isEqualTo(guarantee2)
+    }
+
+    @Test
+    fun beforeAfter_maxSemantics_applyAfterEffect() {
+        val effect =
+            UnidirectionalEffect(Mapping.One, testSemantics("s1")) {
+                after(semantics = testSemantics("s1+"))
+            }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                val effect1 = between(1f, 2f, effect)
+                after(effect1, FixedValue(2f))
+            }
+
+        assertThat(result)
+            .maxDirection()
+            .semantics()
+            .withKey(TestSemantics)
+            .containsExactly("s1", "s1", "s1+")
+            .inOrder()
+    }
+
+    @Test
+    fun beforeAfter_minSemantics_applyBeforeEffect() {
+        val effect =
+            UnidirectionalEffect(Mapping.One, testSemantics("s1")) {
+                before(semantics = testSemantics("s1-"))
+            }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+                before(1f, FixedValue(2f))
+            }
+
+        assertThat(result)
+            .maxDirection()
+            .semantics()
+            .withKey(TestSemantics)
+            .containsExactly("s1-", "s1", "s1")
+            .inOrder()
+    }
+
+    @Test
+    fun beforeAfter_conflictingSemantics_firstEffectWins() {
+        val effect1 =
+            UnidirectionalEffect(Mapping.One, testSemantics("s1")) {
+                after(semantics = testSemantics("s1+"))
+            }
+        val effect2 =
+            UnidirectionalEffect(Mapping.One, testSemantics("s2")) {
+                before(semantics = testSemantics("s2-"))
+            }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect1)
+                between(3f, 4f, effect2)
+            }
+
+        assertThat(result)
+            .maxDirection()
+            .semantics()
+            .withKey(TestSemantics)
+            .containsExactly("s1", "s1", "s1+", "s2", "s2")
+            .inOrder()
+    }
+
+    @Test
+    fun beforeAfter_semantics_specifiedByNextEffect_afterSemanticsIgnored() {
+        val effect1 =
+            UnidirectionalEffect(Mapping.One, testSemantics("s1")) {
+                after(semantics = testSemantics("s1+"))
+            }
+
+        val effect2 = UnidirectionalEffect(Mapping.One, semantics = testSemantics("s2"))
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect1)
+                between(2f, 3f, effect2)
+            }
+
+        assertThat(result)
+            .maxDirection()
+            .semantics()
+            .withKey(TestSemantics)
+            .containsExactly("s1", "s1", "s2", "s2")
+            .inOrder()
+    }
+
+    @Test
+    fun beforeAfter_semantics_specifiedByPreviousEffect_beforeSemanticsIgnored() {
+        val effect1 = UnidirectionalEffect(Mapping.One, testSemantics("s1"))
+
+        val effect2 =
+            UnidirectionalEffect(Mapping.One, semantics = testSemantics("s2")) {
+                before(semantics = testSemantics("s2-"))
+            }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect1)
+                between(2f, 3f, effect2)
+            }
+
+        assertThat(result)
+            .maxDirection()
+            .semantics()
+            .withKey(TestSemantics)
+            .containsExactly("s1", "s1", "s2", "s2")
+            .inOrder()
+    }
+
+    @Test
+    fun beforeAfter_maxMapping_applyAfterEffect() {
+        val effect = UnidirectionalEffect(Mapping.One) { after(mapping = Mapping.Two) }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, 1f, 2f)
+    }
+
+    @Test
+    fun beforeAfter_minMapping_applyBeforeEffect() {
+        val effect = UnidirectionalEffect(Mapping.One) { before(mapping = Mapping.Two) }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(2f, 1f, 0f)
+    }
+
+    @Test
+    fun beforeAfter_minMapping_ignoredWhenEffectBeforeSpecified() {
+        val effect = UnidirectionalEffect(Mapping.One) { before(mapping = Mapping.Two) }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+                before(1f, FixedValue(3f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(3f, 1f, 0f)
+    }
+
+    @Test
+    fun beforeAfter_maxMapping_ignoredWhenEffectAfterSpecified() {
+        val effect = UnidirectionalEffect(Mapping.One) { after(mapping = Mapping.Two) }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                between(1f, 2f, effect)
+                after(2f, FixedValue(3f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, 1f, 3f)
+    }
+
+    @Test
+    fun beforeAfter_minMapping_ignoredWhenFirstEffect() {
+        val effect = UnidirectionalEffect(Mapping.One) { before(mapping = Mapping.Two) }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                before(0f, effect)
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(1f, 0f)
+    }
+
+    @Test
+    fun beforeAfter_maxMapping_ignoredWhenLastEffect() {
+        val effect = UnidirectionalEffect(Mapping.One) { after(mapping = Mapping.Two) }
+
+        val result =
+            motionSpec(baseMapping = Mapping.Zero, defaultSpring = spatial.default) {
+                after(0f, effect)
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, 1f)
+    }
+
+    @Test
+    fun order_sharedBreakpoint_betweenAndAfter_sortedCorrectly() {
+        val result =
+            spatialMotionSpec(Mapping.Zero) {
+                after(2f, FixedValue(2f))
+                between(1f, 2f, FixedValue(1f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(0f, 1f, 2f)
+    }
+
+    @Test
+    fun order_sharedBreakpoint_betweenAndBefore_sortedCorrectly() {
+        val result =
+            spatialMotionSpec(Mapping.Zero) {
+                between(1f, 2f, FixedValue(2f))
+                before(1f, FixedValue(1f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(1f, 2f, 0f)
+    }
+
+    @Test
+    fun order_sharedBreakpoint_beforeAfter_sortedCorrectly() {
+        val result =
+            spatialMotionSpec(Mapping.Zero) {
+                after(1f, FixedValue(2f))
+                before(1f, FixedValue(1f))
+            }
+
+        assertThat(result).bothDirections().fixedMappingsMatch(1f, 2f)
+    }
+
+    private class SimpleEffect(private val createSpec: EffectApplyScope.() -> Unit) :
+        Effect.PlaceableBetween {
+        override fun EffectApplyScope.createSpec(
+            minLimit: Float,
+            minLimitKey: BreakpointKey,
+            maxLimit: Float,
+            maxLimitKey: BreakpointKey,
+            placement: EffectPlacement,
+        ) {
+            createSpec()
+        }
+    }
+
+    private class UnidirectionalEffect(
+        private val initialMapping: Mapping,
+        private val semantics: List<SemanticValue<*>> = emptyList(),
+        private val init: DirectionalEffectBuilderScope.() -> Unit = {},
+    ) : Effect.PlaceableBetween, Effect.PlaceableAfter, Effect.PlaceableBefore {
+        override fun MotionBuilderContext.intrinsicSize(): Float = Float.POSITIVE_INFINITY
+
+        override fun EffectApplyScope.createSpec(
+            minLimit: Float,
+            minLimitKey: BreakpointKey,
+            maxLimit: Float,
+            maxLimitKey: BreakpointKey,
+            placement: EffectPlacement,
+        ) {
+            unidirectional(initialMapping, semantics, init)
+        }
+    }
+
+    private class FixedValueWithExtent(val value: Float, val extent: Float) :
+        Effect.PlaceableAfter, Effect.PlaceableBefore {
+        override fun MotionBuilderContext.intrinsicSize() = extent
+
+        override fun EffectApplyScope.createSpec(
+            minLimit: Float,
+            minLimitKey: BreakpointKey,
+            maxLimit: Float,
+            maxLimitKey: BreakpointKey,
+            placement: EffectPlacement,
+        ) {
+            return unidirectional(Mapping.Fixed(value))
+        }
+    }
+
+    companion object {
+        val TestSemantics = SemanticKey<String>("foo")
+
+        fun testSemantics(value: String) = listOf(TestSemantics with value)
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/testing/DefaultSprings.kt b/mechanics/tests/src/com/android/mechanics/testing/DefaultSprings.kt
deleted file mode 100644
index 3d43d34..0000000
--- a/mechanics/tests/src/com/android/mechanics/testing/DefaultSprings.kt
+++ /dev/null
@@ -1,72 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.mechanics.testing
-
-import com.android.mechanics.spring.SpringParameters
-
-object DefaultSprings {
-    val matStandardDefault =
-        SpringParameters(
-            stiffness = StandardMotionTokens.SpringDefaultSpatialStiffness,
-            dampingRatio = StandardMotionTokens.SpringDefaultSpatialDamping,
-        )
-    val matStandardFast =
-        SpringParameters(
-            stiffness = StandardMotionTokens.SpringFastSpatialStiffness,
-            dampingRatio = StandardMotionTokens.SpringFastSpatialDamping,
-        )
-    val matExpressiveDefault =
-        SpringParameters(
-            stiffness = ExpressiveMotionTokens.SpringDefaultSpatialStiffness,
-            dampingRatio = ExpressiveMotionTokens.SpringDefaultSpatialDamping,
-        )
-    val matExpressiveFast =
-        SpringParameters(
-            stiffness = ExpressiveMotionTokens.SpringFastSpatialStiffness,
-            dampingRatio = ExpressiveMotionTokens.SpringFastSpatialDamping,
-        )
-
-    internal object StandardMotionTokens {
-        val SpringDefaultSpatialDamping = 0.9f
-        val SpringDefaultSpatialStiffness = 700.0f
-        val SpringDefaultEffectsDamping = 1.0f
-        val SpringDefaultEffectsStiffness = 1600.0f
-        val SpringFastSpatialDamping = 0.9f
-        val SpringFastSpatialStiffness = 1400.0f
-        val SpringFastEffectsDamping = 1.0f
-        val SpringFastEffectsStiffness = 3800.0f
-        val SpringSlowSpatialDamping = 0.9f
-        val SpringSlowSpatialStiffness = 300.0f
-        val SpringSlowEffectsDamping = 1.0f
-        val SpringSlowEffectsStiffness = 800.0f
-    }
-
-    internal object ExpressiveMotionTokens {
-        val SpringDefaultSpatialDamping = 0.8f
-        val SpringDefaultSpatialStiffness = 380.0f
-        val SpringDefaultEffectsDamping = 1.0f
-        val SpringDefaultEffectsStiffness = 1600.0f
-        val SpringFastSpatialDamping = 0.6f
-        val SpringFastSpatialStiffness = 800.0f
-        val SpringFastEffectsDamping = 1.0f
-        val SpringFastEffectsStiffness = 3800.0f
-        val SpringSlowSpatialDamping = 0.8f
-        val SpringSlowSpatialStiffness = 200.0f
-        val SpringSlowEffectsDamping = 1.0f
-        val SpringSlowEffectsStiffness = 800.0f
-    }
-}
diff --git a/mechanics/tests/src/com/android/mechanics/testing/MotionValueToolkit.kt b/mechanics/tests/src/com/android/mechanics/testing/MotionValueToolkit.kt
deleted file mode 100644
index e33865f..0000000
--- a/mechanics/tests/src/com/android/mechanics/testing/MotionValueToolkit.kt
+++ /dev/null
@@ -1,305 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-@file:OptIn(ExperimentalTestApi::class, ExperimentalCoroutinesApi::class)
-
-package com.android.mechanics.testing
-
-import androidx.compose.runtime.LaunchedEffect
-import androidx.compose.runtime.getValue
-import androidx.compose.runtime.mutableFloatStateOf
-import androidx.compose.runtime.setValue
-import androidx.compose.ui.test.ExperimentalTestApi
-import androidx.compose.ui.test.junit4.ComposeContentTestRule
-import com.android.mechanics.DistanceGestureContext
-import com.android.mechanics.MotionValue
-import com.android.mechanics.debug.FrameData
-import com.android.mechanics.spec.InputDirection
-import com.android.mechanics.spec.MotionSpec
-import kotlin.math.abs
-import kotlin.math.floor
-import kotlin.math.sign
-import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.NonDisposableHandle.dispose
-import kotlinx.coroutines.flow.MutableStateFlow
-import kotlinx.coroutines.flow.StateFlow
-import kotlinx.coroutines.flow.asStateFlow
-import kotlinx.coroutines.flow.drop
-import kotlinx.coroutines.flow.take
-import kotlinx.coroutines.flow.takeWhile
-import kotlinx.coroutines.launch
-import kotlinx.coroutines.test.runCurrent
-import kotlinx.coroutines.test.runTest
-import platform.test.motion.MotionTestRule
-import platform.test.motion.RecordedMotion.Companion.create
-import platform.test.motion.golden.Feature
-import platform.test.motion.golden.FrameId
-import platform.test.motion.golden.TimeSeries
-import platform.test.motion.golden.TimestampFrameId
-import platform.test.motion.golden.ValueDataPoint
-import platform.test.motion.golden.asDataPoint
-
-/** Toolkit to support [MotionValue] motion tests. */
-class MotionValueToolkit(val composeTestRule: ComposeContentTestRule) {
-    companion object {
-
-        val TimeSeries.input: List<Float>
-            get() = dataPoints("input")
-
-        val TimeSeries.output: List<Float>
-            get() = dataPoints("output")
-
-        val TimeSeries.outputTarget: List<Float>
-            get() = dataPoints("outputTarget")
-
-        val TimeSeries.isStable: List<Boolean>
-            get() = dataPoints("isStable")
-
-        internal const val TAG = "MotionValueToolkit"
-
-        fun <T> TimeSeries.dataPoints(featureName: String): List<T> {
-            @Suppress("UNCHECKED_CAST")
-            return (features[featureName] as Feature<T>).dataPoints.map {
-                require(it is ValueDataPoint)
-                it.value
-            }
-        }
-    }
-}
-
-interface InputScope {
-    val input: Float
-    val gestureContext: DistanceGestureContext
-    val underTest: MotionValue
-
-    suspend fun awaitStable()
-
-    suspend fun awaitFrames(frames: Int = 1)
-
-    var directionChangeSlop: Float
-
-    fun updateValue(position: Float)
-
-    suspend fun animateValueTo(
-        targetValue: Float,
-        changePerFrame: Float = abs(input - targetValue) / 5f,
-    )
-
-    suspend fun animatedInputSequence(vararg values: Float)
-
-    fun reset(position: Float, direction: InputDirection)
-}
-
-enum class VerifyTimeSeriesResult {
-    SkipGoldenVerification,
-    AssertTimeSeriesMatchesGolden,
-}
-
-fun MotionTestRule<MotionValueToolkit>.goldenTest(
-    spec: MotionSpec,
-    createDerived: (underTest: MotionValue) -> List<MotionValue> = { emptyList() },
-    initialValue: Float = 0f,
-    initialDirection: InputDirection = InputDirection.Max,
-    directionChangeSlop: Float = 5f,
-    stableThreshold: Float = 0.01f,
-    verifyTimeSeries: TimeSeries.() -> VerifyTimeSeriesResult = {
-        VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden
-    },
-    testInput: suspend InputScope.() -> Unit,
-) = runTest {
-    with(toolkit.composeTestRule) {
-        val frameEmitter = MutableStateFlow<Long>(0)
-
-        val testHarness =
-            MotionValueTestHarness(
-                initialValue,
-                initialDirection,
-                spec,
-                stableThreshold,
-                directionChangeSlop,
-                frameEmitter.asStateFlow(),
-                createDerived,
-            )
-        val underTest = testHarness.underTest
-        val derived = testHarness.derived
-
-        val inspectors = buildMap {
-            put(underTest, underTest.debugInspector())
-            derived.forEach { put(it, it.debugInspector()) }
-        }
-
-        setContent {
-            LaunchedEffect(Unit) {
-                launch { underTest.keepRunning() }
-                derived.forEach { launch { it.keepRunning() } }
-            }
-        }
-
-        val recordingJob = launch { testInput.invoke(testHarness) }
-
-        waitForIdle()
-        mainClock.autoAdvance = false
-
-        val frameIds = mutableListOf<FrameId>()
-        val frameData = mutableMapOf<MotionValue, MutableList<FrameData>>()
-
-        fun recordFrame(frameId: TimestampFrameId) {
-            frameIds.add(frameId)
-            inspectors.forEach { (motionValue, inspector) ->
-                frameData.computeIfAbsent(motionValue) { mutableListOf() }.add(inspector.frame)
-            }
-        }
-
-        val startFrameTime = mainClock.currentTime
-        recordFrame(TimestampFrameId(mainClock.currentTime - startFrameTime))
-        while (!recordingJob.isCompleted) {
-            frameEmitter.tryEmit(mainClock.currentTime + 16)
-            runCurrent()
-            mainClock.advanceTimeByFrame()
-            recordFrame(TimestampFrameId(mainClock.currentTime - startFrameTime))
-        }
-
-        val timeSeries =
-            TimeSeries(
-                frameIds.toList(),
-                buildList {
-                    frameData.forEach { (motionValue, frames) ->
-                        val prefix = if (motionValue == underTest) "" else "${motionValue.label}-"
-
-                        add(Feature("${prefix}input", frames.map { it.input.asDataPoint() }))
-                        add(
-                            Feature(
-                                "${prefix}gestureDirection",
-                                frames.map { it.gestureDirection.name.asDataPoint() },
-                            )
-                        )
-                        add(Feature("${prefix}output", frames.map { it.output.asDataPoint() }))
-                        add(
-                            Feature(
-                                "${prefix}outputTarget",
-                                frames.map { it.outputTarget.asDataPoint() },
-                            )
-                        )
-                        add(
-                            Feature(
-                                "${prefix}outputSpring",
-                                frames.map { it.springParameters.asDataPoint() },
-                            )
-                        )
-                        add(Feature("${prefix}isStable", frames.map { it.isStable.asDataPoint() }))
-                    }
-                },
-            )
-
-        inspectors.values.forEach { it.dispose() }
-
-        val recordedMotion = create(timeSeries, screenshots = null)
-        val skipGoldenVerification = verifyTimeSeries.invoke(recordedMotion.timeSeries)
-        if (skipGoldenVerification == VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden) {
-            assertThat(recordedMotion).timeSeriesMatchesGolden()
-        }
-    }
-}
-
-private class MotionValueTestHarness(
-    initialInput: Float,
-    initialDirection: InputDirection,
-    spec: MotionSpec,
-    stableThreshold: Float,
-    directionChangeSlop: Float,
-    val onFrame: StateFlow<Long>,
-    createDerived: (underTest: MotionValue) -> List<MotionValue>,
-) : InputScope {
-
-    override var input by mutableFloatStateOf(initialInput)
-    override val gestureContext: DistanceGestureContext =
-        DistanceGestureContext(initialInput, initialDirection, directionChangeSlop)
-
-    override val underTest =
-        MotionValue(
-            { input },
-            gestureContext,
-            stableThreshold = stableThreshold,
-            initialSpec = spec,
-        )
-
-    val derived = createDerived(underTest)
-
-    override fun updateValue(position: Float) {
-        input = position
-        gestureContext.dragOffset = position
-    }
-
-    override var directionChangeSlop: Float
-        get() = gestureContext.directionChangeSlop
-        set(value) {
-            gestureContext.directionChangeSlop = value
-        }
-
-    override suspend fun awaitStable() {
-        val debugInspectors = buildList {
-            add(underTest.debugInspector())
-            addAll(derived.map { it.debugInspector() })
-        }
-        try {
-
-            onFrame
-                // Since this is a state-flow, the current frame is counted too.
-                .drop(1)
-                .takeWhile { debugInspectors.any { !it.frame.isStable } }
-                .collect {}
-        } finally {
-            debugInspectors.forEach { it.dispose() }
-        }
-    }
-
-    override suspend fun awaitFrames(frames: Int) {
-        onFrame
-            // Since this is a state-flow, the current frame is counted too.
-            .drop(1)
-            .take(frames)
-            .collect {}
-    }
-
-    override suspend fun animateValueTo(targetValue: Float, changePerFrame: Float) {
-        require(changePerFrame > 0f)
-        var currentValue = input
-        val delta = targetValue - currentValue
-        val step = changePerFrame * delta.sign
-
-        val stepCount = floor((abs(delta) / changePerFrame) - 1).toInt()
-        repeat(stepCount) {
-            currentValue += step
-            updateValue(currentValue)
-            awaitFrames()
-        }
-
-        updateValue(targetValue)
-        awaitFrames()
-    }
-
-    override suspend fun animatedInputSequence(vararg values: Float) {
-        values.forEach {
-            updateValue(it)
-            awaitFrames()
-        }
-    }
-
-    override fun reset(position: Float, direction: InputDirection) {
-        input = position
-        gestureContext.reset(position, direction)
-    }
-}
diff --git a/mechanics/tests/src/com/android/mechanics/view/ViewGestureContextTest.kt b/mechanics/tests/src/com/android/mechanics/view/ViewGestureContextTest.kt
new file mode 100644
index 0000000..dbc6cb0
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/view/ViewGestureContextTest.kt
@@ -0,0 +1,202 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.view
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spec.InputDirection
+import com.google.common.truth.Truth.assertThat
+import kotlin.math.nextDown
+import kotlin.math.nextUp
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class ViewGestureContextTest {
+
+    @Test
+    fun update_maxDirection_increasingInput_keepsDirection() {
+        val underTest =
+            DistanceGestureContext(
+                initialDragOffset = 0f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 5f,
+            )
+
+        for (value in 0..6) {
+            underTest.dragOffset = value.toFloat()
+            assertThat(underTest.direction).isEqualTo(InputDirection.Max)
+        }
+    }
+
+    @Test
+    fun update_minDirection_decreasingInput_keepsDirection() {
+        val underTest =
+            DistanceGestureContext(
+                initialDragOffset = 0f,
+                initialDirection = InputDirection.Min,
+                directionChangeSlop = 5f,
+            )
+
+        for (value in 0 downTo -6) {
+            underTest.dragOffset = value.toFloat()
+            assertThat(underTest.direction).isEqualTo(InputDirection.Min)
+        }
+    }
+
+    @Test
+    fun update_maxDirection_decreasingInput_keepsDirection_belowDirectionChangeSlop() {
+        val underTest =
+            DistanceGestureContext(
+                initialDragOffset = 0f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 5f,
+            )
+
+        underTest.dragOffset = -5f
+        assertThat(underTest.direction).isEqualTo(InputDirection.Max)
+    }
+
+    @Test
+    fun update_maxDirection_decreasingInput_switchesDirection_aboveDirectionChangeSlop() {
+        val underTest =
+            DistanceGestureContext(
+                initialDragOffset = 0f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 5f,
+            )
+
+        underTest.dragOffset = (-5f).nextDown()
+        assertThat(underTest.direction).isEqualTo(InputDirection.Min)
+    }
+
+    @Test
+    fun update_minDirection_increasingInput_keepsDirection_belowDirectionChangeSlop() {
+        val underTest =
+            DistanceGestureContext(
+                initialDragOffset = 0f,
+                initialDirection = InputDirection.Min,
+                directionChangeSlop = 5f,
+            )
+
+        underTest.dragOffset = 5f
+        assertThat(underTest.direction).isEqualTo(InputDirection.Min)
+    }
+
+    @Test
+    fun update_minDirection_decreasingInput_switchesDirection_aboveDirectionChangeSlop() {
+        val underTest =
+            DistanceGestureContext(
+                initialDragOffset = 0f,
+                initialDirection = InputDirection.Min,
+                directionChangeSlop = 5f,
+            )
+
+        underTest.dragOffset = 5f.nextUp()
+        assertThat(underTest.direction).isEqualTo(InputDirection.Max)
+    }
+
+    @Test
+    fun reset_resetsFurthestValue() {
+        val underTest =
+            DistanceGestureContext(
+                initialDragOffset = 10f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 1f,
+            )
+
+        underTest.reset(5f, direction = InputDirection.Max)
+        assertThat(underTest.direction).isEqualTo(InputDirection.Max)
+        assertThat(underTest.dragOffset).isEqualTo(5f)
+
+        underTest.dragOffset -= 1f
+        assertThat(underTest.direction).isEqualTo(InputDirection.Max)
+        assertThat(underTest.dragOffset).isEqualTo(4f)
+
+        underTest.dragOffset = underTest.dragOffset.nextDown()
+        assertThat(underTest.direction).isEqualTo(InputDirection.Min)
+        assertThat(underTest.dragOffset).isWithin(0.0001f).of(4f)
+    }
+
+    @Test
+    fun callback_invokedOnChange() {
+        val underTest =
+            DistanceGestureContext(
+                initialDragOffset = 0f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 5f,
+            )
+
+        var invocationCount = 0
+        underTest.addUpdateCallback { invocationCount++ }
+
+        assertThat(invocationCount).isEqualTo(0)
+        underTest.dragOffset += 1
+        assertThat(invocationCount).isEqualTo(1)
+    }
+
+    @Test
+    fun callback_invokedOnReset() {
+        val underTest =
+            DistanceGestureContext(
+                initialDragOffset = 0f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 5f,
+            )
+
+        var invocationCount = 0
+        underTest.addUpdateCallback { invocationCount++ }
+
+        assertThat(invocationCount).isEqualTo(0)
+        underTest.reset(0f, InputDirection.Max)
+        assertThat(invocationCount).isEqualTo(1)
+    }
+
+    @Test
+    fun callback_ignoredForSameValues() {
+        val underTest =
+            DistanceGestureContext(
+                initialDragOffset = 0f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 5f,
+            )
+
+        var invocationCount = 0
+        underTest.addUpdateCallback { invocationCount++ }
+
+        assertThat(invocationCount).isEqualTo(0)
+        underTest.dragOffset += 0
+        assertThat(invocationCount).isEqualTo(0)
+    }
+
+    @Test
+    fun callback_removeUpdateCallback_removesCallback() {
+        val underTest =
+            DistanceGestureContext(
+                initialDragOffset = 0f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 5f,
+            )
+
+        var invocationCount = 0
+        val callback = GestureContextUpdateListener { invocationCount++ }
+        underTest.addUpdateCallback(callback)
+        assertThat(invocationCount).isEqualTo(0)
+        underTest.removeUpdateCallback(callback)
+        underTest.dragOffset += 1
+        assertThat(invocationCount).isEqualTo(0)
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/view/ViewMotionBuilderContextTest.kt b/mechanics/tests/src/com/android/mechanics/view/ViewMotionBuilderContextTest.kt
new file mode 100644
index 0000000..10dd4f6
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/view/ViewMotionBuilderContextTest.kt
@@ -0,0 +1,77 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+@file:OptIn(ExperimentalMaterial3ExpressiveApi::class)
+
+package com.android.mechanics.view
+
+import android.content.Context
+import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
+import androidx.compose.material3.MaterialTheme
+import androidx.compose.material3.MotionScheme
+import androidx.compose.ui.platform.LocalContext
+import androidx.compose.ui.test.junit4.createComposeRule
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spec.builder.MotionBuilderContext
+import com.android.mechanics.spec.builder.rememberMotionBuilderContext
+import com.google.common.truth.Truth
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class ViewMotionBuilderContextTest {
+
+    @get:Rule(order = 0) val rule = createComposeRule()
+
+    @Test
+    fun materialSprings_standardScheme_matchesComposeDefinition() {
+        lateinit var viewContext: Context
+        lateinit var composeReference: MotionBuilderContext
+
+        rule.setContent {
+            viewContext = LocalContext.current
+            MaterialTheme(motionScheme = MotionScheme.standard()) {
+                composeReference = rememberMotionBuilderContext()
+            }
+        }
+
+        val underTest = standardViewMotionBuilderContext(viewContext)
+
+        Truth.assertThat(underTest.density).isEqualTo(composeReference.density)
+        Truth.assertThat(underTest.spatial).isEqualTo(composeReference.spatial)
+        Truth.assertThat(underTest.effects).isEqualTo(composeReference.effects)
+    }
+
+    @Test
+    fun materialSprings_expressiveScheme_matchesComposeDefinition() {
+        lateinit var viewContext: Context
+        lateinit var composeReference: MotionBuilderContext
+
+        rule.setContent {
+            viewContext = LocalContext.current
+            MaterialTheme(motionScheme = MotionScheme.expressive()) {
+                composeReference = rememberMotionBuilderContext()
+            }
+        }
+
+        val underTest = expressiveViewMotionBuilderContext(viewContext)
+
+        Truth.assertThat(underTest.density).isEqualTo(composeReference.density)
+        Truth.assertThat(underTest.spatial).isEqualTo(composeReference.spatial)
+        Truth.assertThat(underTest.effects).isEqualTo(composeReference.effects)
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/view/ViewMotionValueTest.kt b/mechanics/tests/src/com/android/mechanics/view/ViewMotionValueTest.kt
new file mode 100644
index 0000000..7d7fdcd
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/view/ViewMotionValueTest.kt
@@ -0,0 +1,261 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.mechanics.view
+
+import android.platform.test.annotations.MotionTest
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.MotionValueTest.Companion.B1
+import com.android.mechanics.MotionValueTest.Companion.B2
+import com.android.mechanics.MotionValueTest.Companion.specBuilder
+import com.android.mechanics.spec.Breakpoint
+import com.android.mechanics.spec.Guarantee.GestureDragDelta
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.MotionSpec
+import com.android.mechanics.spec.SegmentKey
+import com.android.mechanics.spec.SemanticKey
+import com.android.mechanics.spec.with
+import com.android.mechanics.testing.VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden
+import com.android.mechanics.testing.ViewMotionValueToolkit
+import com.android.mechanics.testing.animateValueTo
+import com.android.mechanics.testing.goldenTest
+import com.android.mechanics.testing.input
+import com.android.mechanics.testing.isStable
+import com.android.mechanics.testing.output
+import com.google.common.truth.Truth.assertThat
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.runBlocking
+import kotlinx.coroutines.test.runTest
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import platform.test.motion.MotionTestRule
+import platform.test.motion.testing.createGoldenPathManager
+import platform.test.screenshot.PathConfig
+import platform.test.screenshot.PathElementNoContext
+
+/**
+ * NOTE: This only tests the lifecycle of ViewMotionValue, plus some basic animations.
+ *
+ * Most code is shared with MotionValue, and tested there.
+ */
+@RunWith(AndroidJUnit4::class)
+@MotionTest
+class ViewMotionValueTest {
+    private val goldenPathManager =
+        createGoldenPathManager(
+            "frameworks/libs/systemui/mechanics/tests/goldens",
+            // The ViewMotionValue goldens do not currently match MotionValue goldens, because
+            // the ViewMotionValue computes the output at the beginning of the new frame, while
+            // MotionValue computes it at when read. Therefore, the output of these goldens is
+            // delayed by one frame.
+            PathConfig(PathElementNoContext("base", isDir = true, { "view" })),
+        )
+
+    //    @get:Rule(order = 1) val activityRule =
+    // ActivityScenarioRule(EmptyTestActivity::class.java)
+    @get:Rule(order = 2) val animatorTestRule = android.animation.AnimatorTestRule(this)
+
+    @get:Rule(order = 3)
+    val motion = MotionTestRule(ViewMotionValueToolkit(animatorTestRule), goldenPathManager)
+
+    @Test
+    fun emptySpec_outputMatchesInput_withoutAnimation() =
+        motion.goldenTest(
+            spec = MotionSpec.Empty,
+            verifyTimeSeries = {
+                // Output always matches the input
+                assertThat(output).containsExactlyElementsIn(input).inOrder()
+                // There must never be an ongoing animation.
+                assertThat(isStable).doesNotContain(false)
+
+                AssertTimeSeriesMatchesGolden()
+            },
+        ) {
+            animateValueTo(100f)
+        }
+
+    @Test
+    fun segmentChange_animatedWhenReachingBreakpoint() =
+        motion.goldenTest(
+            spec = specBuilder(Mapping.Zero) { fixedValue(breakpoint = 1f, value = 1f) }
+        ) {
+            animateValueTo(1f, changePerFrame = 0.5f)
+            awaitStable()
+        }
+
+    @Test
+    fun semantics_returnsValueMatchingSegment() = runTest {
+        runBlocking(Dispatchers.Main) {
+            val s1 = SemanticKey<String>("Foo")
+            val spec =
+                specBuilder(Mapping.Zero, semantics = listOf(s1 with "zero")) {
+                    fixedValue(1f, 1f, semantics = listOf(s1 with "one"))
+                    fixedValue(2f, 2f, semantics = listOf(s1 with "two"))
+                }
+
+            val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 5f)
+            val underTest = ViewMotionValue(0f, gestureContext, spec)
+
+            assertThat(underTest[s1]).isEqualTo("zero")
+            underTest.input = 2f
+            animatorTestRule.advanceTimeBy(16L)
+            assertThat(underTest[s1]).isEqualTo("two")
+        }
+    }
+
+    @Test
+    fun segment_returnsCurrentSegmentKey() = runTest {
+        runBlocking(Dispatchers.Main) {
+            val spec =
+                specBuilder(Mapping.Zero) {
+                    fixedValue(1f, 1f, key = B1)
+                    fixedValue(2f, 2f, key = B2)
+                }
+
+            val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 5f)
+            val underTest = ViewMotionValue(1f, gestureContext, spec)
+
+            assertThat(underTest.segmentKey).isEqualTo(SegmentKey(B1, B2, InputDirection.Max))
+            underTest.input = 2f
+            animatorTestRule.advanceTimeBy(16L)
+            assertThat(underTest.segmentKey)
+                .isEqualTo(SegmentKey(B2, Breakpoint.maxLimit.key, InputDirection.Max))
+        }
+    }
+
+    @Test
+    fun gestureContext_listensToGestureContextUpdates() =
+        motion.goldenTest(
+            spec =
+                specBuilder(Mapping.Zero) {
+                    fixedValue(breakpoint = 1f, guarantee = GestureDragDelta(3f), value = 1f)
+                }
+        ) {
+            animateValueTo(1f, changePerFrame = 0.5f)
+            while (!underTest.isStable) {
+                gestureContext.dragOffset += 0.5f
+                awaitFrames()
+            }
+        }
+
+    @Test
+    fun specChange_triggersAnimation() {
+        fun generateSpec(offset: Float) =
+            specBuilder(Mapping.Zero) {
+                targetFromCurrent(breakpoint = offset, key = B1, delta = 1f, to = 2f)
+                fixedValue(breakpoint = offset + 1f, key = B2, value = 0f)
+            }
+
+        motion.goldenTest(spec = generateSpec(0f), initialValue = .5f) {
+            underTest.spec = generateSpec(1f)
+            awaitFrames()
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun update_triggersCallback() = runTest {
+        runBlocking(Dispatchers.Main) {
+            val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 5f)
+            val underTest = ViewMotionValue(0f, gestureContext, MotionSpec.Empty)
+
+            var invocationCount = 0
+            underTest.addUpdateCallback { invocationCount++ }
+            underTest.input = 1f
+            repeat(60) { animatorTestRule.advanceTimeBy(16L) }
+
+            assertThat(invocationCount).isEqualTo(2)
+        }
+    }
+
+    @Test
+    fun update_setSameValue_doesNotTriggerCallback() = runTest {
+        runBlocking(Dispatchers.Main) {
+            val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 5f)
+            val underTest = ViewMotionValue(0f, gestureContext, MotionSpec.Empty)
+
+            var invocationCount = 0
+            underTest.addUpdateCallback { invocationCount++ }
+            underTest.input = 0f
+            repeat(60) { animatorTestRule.advanceTimeBy(16L) }
+
+            assertThat(invocationCount).isEqualTo(0)
+        }
+    }
+
+    @Test
+    fun update_triggersCallbacksWhileAnimating() = runTest {
+        runBlocking(Dispatchers.Main) {
+            val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 5f)
+            val spec = specBuilder(Mapping.Zero) { fixedValue(breakpoint = 1f, value = 1f) }
+            val underTest = ViewMotionValue(0f, gestureContext, spec)
+
+            var invocationCount = 0
+            underTest.addUpdateCallback { invocationCount++ }
+            underTest.input = 1f
+            repeat(60) { animatorTestRule.advanceTimeBy(16L) }
+
+            assertThat(invocationCount).isEqualTo(17)
+        }
+    }
+
+    @Test
+    fun removeCallback_doesNotTriggerAfterRemoving() = runTest {
+        runBlocking(Dispatchers.Main) {
+            val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 5f)
+            val spec = specBuilder(Mapping.Zero) { fixedValue(breakpoint = 1f, value = 1f) }
+            val underTest = ViewMotionValue(0f, gestureContext, spec)
+
+            var invocationCount = 0
+            val callback = ViewMotionValueListener { invocationCount++ }
+            underTest.addUpdateCallback(callback)
+            underTest.input = 0.5f
+            animatorTestRule.advanceTimeBy(16L)
+            assertThat(invocationCount).isEqualTo(2)
+
+            underTest.removeUpdateCallback(callback)
+            underTest.input = 1f
+            repeat(60) { animatorTestRule.advanceTimeBy(16L) }
+
+            assertThat(invocationCount).isEqualTo(2)
+        }
+    }
+
+    @Test
+    fun debugInspector_sameInstance_whileInUse() = runTest {
+        runBlocking(Dispatchers.Main) {
+            val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 5f)
+            val underTest = ViewMotionValue(0f, gestureContext, MotionSpec.Empty)
+
+            val originalInspector = underTest.debugInspector()
+            assertThat(underTest.debugInspector()).isSameInstanceAs(originalInspector)
+        }
+    }
+
+    @Test
+    fun debugInspector_newInstance_afterUnused() = runTest {
+        runBlocking(Dispatchers.Main) {
+            val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 5f)
+            val underTest = ViewMotionValue(0f, gestureContext, MotionSpec.Empty)
+
+            val originalInspector = underTest.debugInspector()
+            originalInspector.dispose()
+            assertThat(underTest.debugInspector()).isNotSameInstanceAs(originalInspector)
+        }
+    }
+}
diff --git a/monet/src/com/android/systemui/monet/ColorScheme.java b/monet/src/com/android/systemui/monet/ColorScheme.java
index 7216026..dbede7c 100644
--- a/monet/src/com/android/systemui/monet/ColorScheme.java
+++ b/monet/src/com/android/systemui/monet/ColorScheme.java
@@ -67,6 +67,7 @@ public class ColorScheme {
 
     public ColorScheme(@ColorInt int seed, boolean isDark, @Style.Type int style,
             double contrastLevel) {
+
         this.mSeed = seed;
         this.mIsDark = isDark;
         this.mStyle = style;
diff --git a/monet/src/com/android/systemui/monet/CustomDynamicColors.java b/monet/src/com/android/systemui/monet/CustomDynamicColors.java
index 26bd612..e18a899 100644
--- a/monet/src/com/android/systemui/monet/CustomDynamicColors.java
+++ b/monet/src/com/android/systemui/monet/CustomDynamicColors.java
@@ -22,16 +22,17 @@ import com.google.ux.material.libmonet.dynamiccolor.MaterialDynamicColors;
 import com.google.ux.material.libmonet.dynamiccolor.ToneDeltaPair;
 import com.google.ux.material.libmonet.dynamiccolor.TonePolarity;
 
+import java.util.Arrays;
+import java.util.List;
 import java.util.function.Supplier;
 
 public class CustomDynamicColors {
     private final MaterialDynamicColors mMdc;
-    public final Supplier<DynamicColor>[] allColors;
+    public final List<Supplier<DynamicColor>> allColors;
 
-    public CustomDynamicColors(boolean isExtendedFidelity) {
-        this.mMdc = new MaterialDynamicColors(isExtendedFidelity);
-
-        allColors = new Supplier[]{
+    public CustomDynamicColors() {
+        this.mMdc = new MaterialDynamicColors();
+        allColors = Arrays.asList(
                 this::widgetBackground,
                 this::clockHour,
                 this::clockMinute,
@@ -54,297 +55,257 @@ public class CustomDynamicColors {
                 this::onShadeInactiveVariant,
                 this::shadeDisabled,
                 this::overviewBackground
-        };
+        );
     }
 
     // CLOCK COLORS
-
     public DynamicColor widgetBackground() {
-        return new DynamicColor(
-                /* name= */ "widget_background",
-                /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 20.0 : 95.0,
-                /* isBackground= */ true,
-                /* background= */ null,
-                /* secondBackground= */ null,
-                /* contrastCurve= */ null,
-                /* toneDeltaPair= */ null);
+        return new DynamicColor.Builder()
+                .setName("widget_background")
+                .setPalette((s) -> s.secondaryPalette)
+                .setTone((s) -> s.isDark ? 20.0 : 95.0)
+                .setIsBackground(true)
+                .build();
     }
 
     public DynamicColor clockHour() {
-        return new DynamicColor(
-                /* name= */ "clock_hour",
-                /* palette= */ (s) -> s.secondaryPalette,
-                /* tone= */ (s) -> s.isDark ? 60.0 : 30.0,
-                /* isBackground= */ false,
-                /* background= */ (s) -> widgetBackground(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(4.0, 4.0, 5.0, 15.0),
-                /* toneDeltaPair= */
-                (s) -> new ToneDeltaPair(clockHour(), clockMinute(), 10.0, TonePolarity.DARKER,
-                        false));
+        return new DynamicColor.Builder()
+                .setName("clock_hour")
+                .setPalette((s) -> s.isDark ? s.primaryPalette : s.secondaryPalette)
+                .setTone((s) -> s.isDark ? 80.0 : 30.0)
+                .setIsBackground(false)
+                .setBackground((s) -> widgetBackground())
+                .setContrastCurve((s) -> new ContrastCurve(4.0, 4.0, 5.0, 15.0))
+                .setToneDeltaPair((s) -> new ToneDeltaPair(clockHour(), clockMinute(), 10.0,
+                        TonePolarity.DARKER, ToneDeltaPair.DeltaConstraint.FARTHER))
+                .build();
     }
 
     public DynamicColor clockMinute() {
-        return new DynamicColor(
-                /* name= */ "clock_minute",
-                /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 90.0 : 40.0,
-                /* isBackground= */ false,
-                /* background= */ (s) -> widgetBackground(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(6.5, 6.5, 10.0, 15.0),
-                /* toneDeltaPair= */ null);
+        return new DynamicColor.Builder()
+                .setName("clock_minute")
+                .setPalette((s) -> s.primaryPalette)
+                .setTone((s) -> s.isDark ? 90.0 : 40.0)
+                .setIsBackground(false)
+                .setBackground((s) -> widgetBackground())
+                .setContrastCurve((s) -> new ContrastCurve(6.5, 6.5, 10.0, 15.0))
+                .build();
     }
 
     public DynamicColor clockSecond() {
-        return new DynamicColor(
-                /* name= */ "clock_second",
-                /* palette= */ (s) -> s.tertiaryPalette,
-                /* tone= */ (s) -> s.isDark ? 90.0 : 40.0,
-                /* isBackground= */ false,
-                /* background= */ (s) -> widgetBackground(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(5.0, 5.0, 70.0, 11.0),
-                /* toneDeltaPair= */ null);
+        return new DynamicColor.Builder()
+                .setName("clock_second")
+                .setPalette((s) -> s.tertiaryPalette)
+                .setTone((s) -> s.isDark ? 90.0 : 40.0)
+                .setIsBackground(false)
+                .setBackground((s) -> widgetBackground())
+                .setContrastCurve((s) -> new ContrastCurve(5.0, 5.0, 70.0, 11.0))
+                .build();
     }
 
     public DynamicColor weatherTemp() {
-        return new DynamicColor(
-                /* name= */ "weather_temp",
-                /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 80.0 : 55.0,
-                /* isBackground= */ false,
-                /* background= */ (s) -> widgetBackground(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(5.0, 5.0, 70.0, 11.0),
-                /* toneDeltaPair= */ null);
+        return new DynamicColor.Builder()
+                .setName("weather_temp")
+                .setPalette((s) -> s.primaryPalette)
+                .setTone((s) -> s.isDark ? 80.0 : 40.0)
+                .setIsBackground(false)
+                .setBackground((s) -> widgetBackground())
+                .setContrastCurve((s) -> new ContrastCurve(5.0, 5.0, 70.0, 11.0))
+                .build();
     }
 
     // THEME APP ICONS
-
     public DynamicColor themeApp() {
-        return new DynamicColor(
-                /* name= */ "theme_app",
-                /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 30.0 : 90.0, // Adjusted values
-                /* isBackground= */ true,
-                /* background= */ null,
-                /* secondBackground= */ null,
-                /* contrastCurve= */ null,
-                /* toneDeltaPair= */ null);
+        return new DynamicColor.Builder()
+                .setName("theme_app")
+                .setPalette((s) -> s.isDark ? s.secondaryPalette : s.primaryPalette)
+                .setTone((s) -> s.isDark ? 20.0 : 90.0)
+                .setIsBackground(true)
+                .build();
     }
 
     public DynamicColor onThemeApp() {
-        return new DynamicColor(
-                /* name= */ "on_theme_app",
-                /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 80.0 : 40.0, // Adjusted values
-                /* isBackground= */ false,
-                /* background= */ (s) -> themeApp(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 7.0, 10.0),
-                /* toneDeltaPair= */ null);
+        return new DynamicColor.Builder()
+                .setName("on_theme_app")
+                .setPalette((s) -> s.primaryPalette)
+                .setTone((s) -> s.isDark ? 80.0 : 30.0)
+                .setIsBackground(false)
+                .setBackground((s) -> themeApp())
+                .setContrastCurve((s) -> new ContrastCurve(3.0, 3.0, 7.0, 10.0))
+                .build();
     }
 
     public DynamicColor themeAppRing() {
-        return new DynamicColor(
-                /* name= */ "theme_app_ring",
-                /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> 70.0,
-                /* isBackground= */ true,
-                /* background= */ null,
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 1.0, 1.0),
-                /* toneDeltaPair= */ null);
+        return new DynamicColor.Builder()
+                .setName("theme_app_ring")
+                .setPalette((s) -> s.primaryPalette)
+                .setTone((s) -> 70.0)
+                .setIsBackground(true)
+                .build();
     }
 
     public DynamicColor themeNotif() {
-        return new DynamicColor(
-                /* name= */ "theme_notif",
-                /* palette= */ (s) -> s.tertiaryPalette,
-                /* tone= */ (s) -> s.isDark ? 90.0 : 80.0,
-                /* isBackground= */ false,
-                /* background= */ (s) -> themeAppRing(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 1.0, 1.0),
-                /* toneDeltaPair= */
-                (s) -> new ToneDeltaPair(themeNotif(), themeAppRing(), 10.0, TonePolarity.NEARER,
-                        false));
+        return new DynamicColor.Builder()
+                .setName("theme_notif")
+                .setPalette((s) -> s.tertiaryPalette)
+                .setTone((s) -> 80.0)
+                .setBackground((s) -> themeAppRing())
+                .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 1.0, 1.0))
+                .setToneDeltaPair((s) -> new ToneDeltaPair(themeNotif(), themeAppRing(), 10.0,
+                        TonePolarity.RELATIVE_LIGHTER, ToneDeltaPair.DeltaConstraint.FARTHER))
+                .build();
     }
 
     // SUPER G COLORS
-
     public DynamicColor brandA() {
-        return new DynamicColor(
-                /* name= */ "brand_a",
-                /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 80.0 : 40.0,
-                /* isBackground= */ true,
-                /* background= */ (s) -> mMdc.surfaceContainerLow(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 7.0, 17.0),
-                /* toneDeltaPair= */
-                (s) -> new ToneDeltaPair(brandA(), brandB(), 10.0, TonePolarity.NEARER, false));
+        return new DynamicColor.Builder()
+                .setName("brand_a")
+                .setPalette((s) -> s.primaryPalette)
+                .setTone((s) -> s.isDark ? 80.0 : 40.0)
+                .setBackground((s) -> mMdc.surfaceContainerLow())
+                .setContrastCurve((s) -> s.isDark ? new ContrastCurve(10.0, 10.0, 12.0, 13.0)
+                        : new ContrastCurve(6.0, 6.0, 9.0, 12.0))
+                .build();
     }
 
     public DynamicColor brandB() {
-        return new DynamicColor(
-                /* name= */ "brand_b",
-                /* palette= */ (s) -> s.secondaryPalette,
-                /* tone= */ (s) -> s.isDark ? 98.0 : 70.0,
-                /* isBackground= */ true,
-                /* background= */ (s) -> mMdc.surfaceContainerLow(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 3.0, 6.0),
-                /* toneDeltaPair= */
-                (s) -> new ToneDeltaPair(brandB(), brandC(), 10.0, TonePolarity.NEARER, false));
+        return new DynamicColor.Builder()
+                .setName("brand_b")
+                .setPalette((s) -> s.secondaryPalette)
+                .setTone((s) -> s.isDark ? 98.0 : 70.0)
+                .setBackground((s) -> mMdc.surfaceContainerLow())
+                .setContrastCurve((s) -> s.isDark ? new ContrastCurve(16.0, 16.0, 16.5, 17.0)
+                        : new ContrastCurve(2.0, 2.0, 3.0, 4.5))
+                .build();
     }
 
     public DynamicColor brandC() {
-        return new DynamicColor(
-                /* name= */ "brand_c",
-                /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 60.0 : 50.0,
-                /* isBackground= */ false,
-                /* background= */ (s) -> mMdc.surfaceContainerLow(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 4.0, 9.0),
-                /* toneDeltaPair= */
-                (s) -> new ToneDeltaPair(brandC(), brandD(), 10.0, TonePolarity.NEARER, false));
+        return new DynamicColor.Builder()
+                .setName("brand_c")
+                .setPalette((s) -> s.primaryPalette)
+                .setTone((s) -> s.isDark ? 60.0 : 50.0)
+                .setBackground((s) -> mMdc.surfaceContainerLow())
+                .setContrastCurve((s) -> s.isDark ? new ContrastCurve(6.0, 6.0, 9.0, 11.0)
+                        : new ContrastCurve(4.0, 4.0, 7.0, 8.0))
+                .build();
     }
 
     public DynamicColor brandD() {
-        return new DynamicColor(
-                /* name= */ "brand_d",
-                /* palette= */ (s) -> s.tertiaryPalette,
-                /* tone= */ (s) -> s.isDark ? 90.0 : 59.0,
-                /* isBackground= */ false,
-                /* background= */ (s) -> mMdc.surfaceContainerLow(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 4.0, 13.0),
-                /* toneDeltaPair= */
-                (s) -> new ToneDeltaPair(brandD(), brandA(), 10.0, TonePolarity.NEARER, false));
+        return new DynamicColor.Builder()
+                .setName("brand_d")
+                .setPalette((s) -> s.tertiaryPalette)
+                .setTone((s) -> s.isDark ? 90.0 : 59.0)
+                .setBackground((s) -> mMdc.surfaceContainerLow())
+                .setContrastCurve((s) -> s.isDark ? new ContrastCurve(13.0, 13.0, 14.0, 15.0)
+                        : new ContrastCurve(3.0, 3.0, 4.5, 6.0))
+                .build();
     }
 
-    // QUICK SETTING TIILES
-
+    // QUICK SETTING TILES
     public DynamicColor underSurface() {
-        return new DynamicColor(
-                /* name= */ "under_surface",
-                /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> 0.0,
-                /* isBackground= */ true,
-                /* background= */ null,
-                /* secondBackground= */ null,
-                /* contrastCurve= */ null,
-                /* toneDeltaPair= */ null);
+        return new DynamicColor.Builder()
+                .setName("under_surface")
+                .setPalette((s) -> s.primaryPalette)
+                .setTone((s) -> 0.0)
+                .setIsBackground(true)
+                .build();
     }
 
     public DynamicColor shadeActive() {
-        return new DynamicColor(
-                /* name= */ "shade_active",
-                /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> 90.0,
-                /* isBackground= */ true,
-                /* background= */ (s) -> underSurface(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 4.5, 7.0),
-                /* toneDeltaPair= */
-                (s) -> new ToneDeltaPair(shadeActive(), shadeInactive(), 30.0, TonePolarity.LIGHTER,
-                        false));
+        return new DynamicColor.Builder()
+                .setName("shade_active")
+                .setPalette((s) -> s.primaryPalette)
+                .setTone((s) -> 90.0)
+                .setIsBackground(true)
+                .setBackground((s) -> underSurface())
+                .setContrastCurve((s) -> new ContrastCurve(3.0, 3.0, 4.5, 7.0))
+                .setToneDeltaPair((s) -> new ToneDeltaPair(shadeActive(), shadeInactive(), 30.0,
+                        TonePolarity.LIGHTER, ToneDeltaPair.DeltaConstraint.FARTHER))
+                .build();
     }
 
     public DynamicColor onShadeActive() {
-        return new DynamicColor(
-                /* name= */ "on_shade_active",
-                /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> 10.0,
-                /* isBackground= */ false,
-                /* background= */ (s) -> shadeActive(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(4.5, 4.5, 7.0, 11.0),
-                /* toneDeltaPair= */
-                (s) -> new ToneDeltaPair(onShadeActive(), onShadeActiveVariant(), 20.0,
-                        TonePolarity.NEARER, false));
+        return new DynamicColor.Builder()
+                .setName("on_shade_active")
+                .setPalette((s) -> s.primaryPalette)
+                .setTone((s) -> 10.0)
+                .setIsBackground(false)
+                .setBackground((s) -> shadeActive())
+                .setContrastCurve((s) -> new ContrastCurve(4.5, 4.5, 7.0, 11.0))
+                .setToneDeltaPair(
+                        (s) -> new ToneDeltaPair(onShadeActive(), onShadeActiveVariant(), 20.0,
+                                TonePolarity.RELATIVE_LIGHTER,
+                                ToneDeltaPair.DeltaConstraint.FARTHER))
+                .build();
     }
 
     public DynamicColor onShadeActiveVariant() {
-        return new DynamicColor(
-                /* name= */ "on_shade_active_variant",
-                /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> 30.0,
-                /* isBackground= */ false,
-                /* background= */ (s) -> shadeActive(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(4.5, 4.5, 7.0, 11.0),
-                /* toneDeltaPair= */
-                (s) -> new ToneDeltaPair(onShadeActiveVariant(), onShadeActive(), 20.0,
-                        TonePolarity.NEARER, false));
+        return new DynamicColor.Builder()
+                .setName("on_shade_active_variant")
+                .setPalette((s) -> s.primaryPalette)
+                .setTone((s) -> 30.0)
+                .setIsBackground(false)
+                .setBackground((s) -> shadeActive())
+                .setContrastCurve((s) -> new ContrastCurve(4.5, 4.5, 7.0, 11.0))
+                .build();
     }
 
     public DynamicColor shadeInactive() {
-        return new DynamicColor(
-                /* name= */ "shade_inactive",
-                /* palette= */ (s) -> s.neutralPalette,
-                /* tone= */ (s) -> 20.0,
-                /* isBackground= */ true,
-                /* background= */ (s) -> underSurface(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 1.0, 1.0),
-                /* toneDeltaPair= */(s) -> new ToneDeltaPair(shadeInactive(), shadeDisabled(), 15.0,
-                TonePolarity.LIGHTER, false));
+        return new DynamicColor.Builder()
+                .setName("shade_inactive")
+                .setPalette((s) -> s.neutralPalette)
+                .setTone((s) -> 20.0)
+                .setIsBackground(true)
+                .setBackground((s) -> underSurface())
+                .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 1.0, 1.0))
+                .setToneDeltaPair((s) -> new ToneDeltaPair(shadeInactive(), shadeDisabled(), 15.0,
+                        TonePolarity.LIGHTER, ToneDeltaPair.DeltaConstraint.FARTHER))
+                .build();
     }
 
     public DynamicColor onShadeInactive() {
-        return new DynamicColor(
-                /* name= */ "on_shade_inactive",
-                /* palette= */ (s) -> s.neutralVariantPalette,
-                /* tone= */ (s) -> 90.0,
-                /* isBackground= */ false,
-                /* background= */ (s) -> shadeInactive(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(4.5, 4.5, 7.0, 11.0),
-                /* toneDeltaPair= */
-                (s) -> new ToneDeltaPair(onShadeInactive(), onShadeInactiveVariant(), 10.0,
-                        TonePolarity.NEARER, false));
+        return new DynamicColor.Builder()
+                .setName("on_shade_inactive")
+                .setPalette((s) -> s.neutralVariantPalette)
+                .setTone((s) -> 90.0)
+                .setIsBackground(false)
+                .setBackground((s) -> shadeInactive())
+                .setContrastCurve((s) -> new ContrastCurve(4.5, 4.5, 7.0, 11.0))
+                .setToneDeltaPair(
+                        (s) -> new ToneDeltaPair(onShadeInactive(), onShadeInactiveVariant(), 10.0,
+                                TonePolarity.RELATIVE_LIGHTER,
+                                ToneDeltaPair.DeltaConstraint.FARTHER))
+                .build();
     }
 
     public DynamicColor onShadeInactiveVariant() {
-        return new DynamicColor(
-                /* name= */ "on_shade_inactive_variant",
-                /* palette= */ (s) -> s.neutralVariantPalette,
-                /* tone= */ (s) -> 80.0,
-                /* isBackground= */ false,
-                /* background= */ (s) -> shadeInactive(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(4.5, 4.5, 7.0, 11.0),
-                /* toneDeltaPair= */
-                (s) -> new ToneDeltaPair(onShadeInactive(), onShadeInactiveVariant(), 10.0,
-                        TonePolarity.NEARER, false));
+        return new DynamicColor.Builder()
+                .setName("on_shade_inactive_variant")
+                .setPalette((s) -> s.neutralVariantPalette)
+                .setTone((s) -> 80.0)
+                .setIsBackground(false)
+                .setBackground((s) -> shadeInactive())
+                .setContrastCurve((s) -> new ContrastCurve(4.5, 4.5, 7.0, 11.0))
+                .build();
     }
 
     public DynamicColor shadeDisabled() {
-        return new DynamicColor(
-                /* name= */ "shade_disabled",
-                /* palette= */ (s) -> s.neutralPalette,
-                /* tone= */ (s) -> 4.0,
-                /* isBackground= */ false,
-                /* background= */ (s) -> underSurface(),
-                /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 1.0, 1.0),
-                /* toneDeltaPair= */ null);
+        return new DynamicColor.Builder()
+                .setName("shade_disabled")
+                .setPalette((s) -> s.neutralPalette)
+                .setTone((s) -> 4.0)
+                .setIsBackground(false)
+                .setBackground((s) -> underSurface())
+                .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 1.0, 1.0))
+                .build();
     }
 
     public DynamicColor overviewBackground() {
-        return new DynamicColor(
-                /* name= */ "overview_background",
-                /* palette= */ (s) -> s.neutralVariantPalette,
-                /* tone= */ (s) -> s.isDark ? 35.0 : 80.0,
-                /* isBackground= */ true,
-                /* background= */ null,
-                /* secondBackground= */ null,
-                /* contrastCurve= */null,
-                /* toneDeltaPair= */ null);
+        return new DynamicColor.Builder()
+                .setName("overview_background")
+                .setPalette((s) -> s.neutralVariantPalette)
+                .setTone((s) -> s.isDark ? 35.0 : 80.0)
+                .setIsBackground(true)
+                .build();
     }
 }
diff --git a/monet/src/com/android/systemui/monet/DynamicColors.java b/monet/src/com/android/systemui/monet/DynamicColors.java
index b76d3a6..a65d89b 100644
--- a/monet/src/com/android/systemui/monet/DynamicColors.java
+++ b/monet/src/com/android/systemui/monet/DynamicColors.java
@@ -16,129 +16,95 @@
 
 package com.android.systemui.monet;
 
+import static com.android.systemui.monet.TonalPalette.SHADE_KEYS;
+
 import android.util.Pair;
 
 import com.google.ux.material.libmonet.dynamiccolor.DynamicColor;
+import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme;
 import com.google.ux.material.libmonet.dynamiccolor.MaterialDynamicColors;
+import com.google.ux.material.libmonet.palettes.TonalPalette;
 
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.Comparator;
 import java.util.List;
+import java.util.function.Function;
 import java.util.function.Supplier;
+import java.util.stream.Collectors;
 
 public class DynamicColors {
+    /**
+     * Gets all DynamicColor tokens for the neutral palettes.
+     */
+    public static List<Pair<String, DynamicColor>> getAllNeutralPalette() {
+        List<Pair<String, Function<DynamicScheme, TonalPalette>>> neutralPaletteMap = Arrays.asList(
+                new Pair<>("neutral1", (s) -> s.neutralPalette),
+                new Pair<>("neutral2", (s) -> s.neutralVariantPalette)
+        );
+        // Call the helper method with the specific neutral palettes
+        return generatePaletteColors(neutralPaletteMap);
+    }
+
+    /**
+     * Gets all DynamicColor tokens for the accent palettes.
+     */
+    public static List<Pair<String, DynamicColor>> getAllAccentPalette() {
+        List<Pair<String, Function<DynamicScheme, TonalPalette>>> accentPaletteMap = Arrays.asList(
+                new Pair<>("accent1", (s) -> s.primaryPalette),
+                new Pair<>("accent2", (s) -> s.secondaryPalette),
+                new Pair<>("accent3", (s) -> s.tertiaryPalette)
+        );
+        // Call the helper method with the specific accent palettes
+        return generatePaletteColors(accentPaletteMap);
+    }
+
+    /**
+     * Gets all DynamicColor tokens for the error palette
+     */
+    public static List<Pair<String, DynamicColor>> getAllErrorPalette() {
+        List<Pair<String, Function<DynamicScheme, TonalPalette>>> errorPaletteMap = Arrays.asList(
+                new Pair<>("error", (s) -> s.errorPalette)
+        );
+
+        return generatePaletteColors(errorPaletteMap);
+    }
 
     /**
      * List of all public Dynamic Color (Light and Dark) resources
      *
-     * @param isExtendedFidelity boolean indicating if Fidelity is active
      * @return List of pairs of Resource Names / DynamicColor
      */
-    public static List<Pair<String, DynamicColor>> getAllDynamicColorsMapped(
-            boolean isExtendedFidelity) {
-        MaterialDynamicColors mdc = new MaterialDynamicColors(isExtendedFidelity);
-        final Supplier<DynamicColor>[] allColors = new Supplier[]{
-                mdc::primaryPaletteKeyColor,
-                mdc::secondaryPaletteKeyColor,
-                mdc::tertiaryPaletteKeyColor,
-                mdc::neutralPaletteKeyColor,
-                mdc::neutralVariantPaletteKeyColor,
-                mdc::background,
-                mdc::onBackground,
-                mdc::surface,
-                mdc::surfaceDim,
-                mdc::surfaceBright,
-                mdc::surfaceContainerLowest,
-                mdc::surfaceContainerLow,
-                mdc::surfaceContainer,
-                mdc::surfaceContainerHigh,
-                mdc::surfaceContainerHighest,
-                mdc::onSurface,
-                mdc::surfaceVariant,
-                mdc::onSurfaceVariant,
-                mdc::inverseSurface,
-                mdc::inverseOnSurface,
-                mdc::outline,
-                mdc::outlineVariant,
-                mdc::shadow,
-                mdc::scrim,
-                mdc::surfaceTint,
-                mdc::primary,
-                mdc::onPrimary,
-                mdc::primaryContainer,
-                mdc::onPrimaryContainer,
-                mdc::inversePrimary,
-                mdc::secondary,
-                mdc::onSecondary,
-                mdc::secondaryContainer,
-                mdc::onSecondaryContainer,
-                mdc::tertiary,
-                mdc::onTertiary,
-                mdc::tertiaryContainer,
-                mdc::onTertiaryContainer,
-                mdc::error,
-                mdc::onError,
-                mdc::errorContainer,
-                mdc::onErrorContainer,
-                mdc::controlActivated,
-                mdc::controlNormal,
-                mdc::controlHighlight,
-                mdc::textPrimaryInverse,
-                mdc::textSecondaryAndTertiaryInverse,
-                mdc::textPrimaryInverseDisableOnly,
-                mdc::textSecondaryAndTertiaryInverseDisabled,
-                mdc::textHintInverse
-        };
-
-        List<Pair<String, DynamicColor>> list = generateSysUINames(allColors);
-        return list;
+    public static List<Pair<String, DynamicColor>> getAllDynamicColorsMapped() {
+        MaterialDynamicColors mdc = new MaterialDynamicColors();
+        return generateSysUINames(mdc.allDynamicColors().stream().filter(
+                dc -> !dc.get().name.contains("fixed")).toList());
     }
 
     /**
      * List of all public Static Color resources
      *
-     * @param isExtendedFidelity boolean indicating if Fidelity is active
      * @return List of pairs of Resource Names / DynamicColor @return
      */
-    public static List<Pair<String, DynamicColor>> getFixedColorsMapped(
-            boolean isExtendedFidelity) {
-        MaterialDynamicColors mdc = new MaterialDynamicColors(isExtendedFidelity);
-
-        final Supplier<DynamicColor>[] allColors = new Supplier[]{
-                mdc::primaryFixed,
-                mdc::primaryFixedDim,
-                mdc::onPrimaryFixed,
-                mdc::onPrimaryFixedVariant,
-                mdc::secondaryFixed,
-                mdc::secondaryFixedDim,
-                mdc::onSecondaryFixed,
-                mdc::onSecondaryFixedVariant,
-                mdc::tertiaryFixed,
-                mdc::tertiaryFixedDim,
-                mdc::onTertiaryFixed,
-                mdc::onTertiaryFixedVariant
-        };
-
-        List<Pair<String, DynamicColor>> list = generateSysUINames(allColors);
-        return list;
-    }
+    public static List<Pair<String, DynamicColor>> getFixedColorsMapped() {
+        MaterialDynamicColors mdc = new MaterialDynamicColors();
 
+        return generateSysUINames(mdc.allDynamicColors().stream().filter(
+                dc -> dc.get().name.contains("fixed")).toList());
+    }
 
     /**
      * List of all private SystemUI Color resources
      *
-     * @param isExtendedFidelity boolean indicating if Fidelity is active
      * @return List of pairs of Resource Names / DynamicColor
      */
-    public static List<Pair<String, DynamicColor>> getCustomColorsMapped(
-            boolean isExtendedFidelity) {
-        CustomDynamicColors customMdc = new CustomDynamicColors(isExtendedFidelity);
-        List<Pair<String, DynamicColor>> list = generateSysUINames(customMdc.allColors);
-        return list;
+    public static List<Pair<String, DynamicColor>> getCustomColorsMapped() {
+        CustomDynamicColors customMdc = new CustomDynamicColors();
+        return generateSysUINames(customMdc.allColors);
     }
 
     private static List<Pair<String, DynamicColor>> generateSysUINames(
-            Supplier<DynamicColor>[] allColors) {
+            List<Supplier<DynamicColor>> allColors) {
         List<Pair<String, DynamicColor>> list = new ArrayList<>();
 
         for (Supplier<DynamicColor> supplier : allColors) {
@@ -158,5 +124,32 @@ public class DynamicColors {
         list.sort(Comparator.comparing(pair -> pair.first));
         return list;
     }
-}
 
+    private static List<Pair<String, DynamicColor>> generatePaletteColors(
+            List<Pair<String, Function<DynamicScheme, TonalPalette>>> paletteMap) {
+
+        return paletteMap.stream()
+                .flatMap(palettePair -> {
+                    String paletteName = palettePair.first;
+                    Function<DynamicScheme, TonalPalette> paletteExtractor = palettePair.second;
+
+                    // Stream over the shades for the current palette
+                    return SHADE_KEYS.stream().map(shade -> {
+                        String tokenName = paletteName + "_" + shade;
+
+                        DynamicColor token = new DynamicColor(
+                                /* name= */ tokenName,
+                                /* palette= */ paletteExtractor,
+                                /* tone= */ (s) -> (double) ((1000.0f - shade) / 10f),
+                                /* isBackground= */ true,
+                                /* background= */ null,
+                                /* secondBackground= */ null,
+                                /* contrastCurve= */ null,
+                                /* toneDeltaPair= */ null);
+
+                        return new Pair<>(tokenName, token);
+                    });
+                })
+                .collect(Collectors.toList());
+    }
+}
diff --git a/monet/tests/com/android/systemui/monet/ColorSchemeTest.kt b/monet/tests/com/android/systemui/monet/ColorSchemeTest.kt
index edbe729..f7e7a42 100644
--- a/monet/tests/com/android/systemui/monet/ColorSchemeTest.kt
+++ b/monet/tests/com/android/systemui/monet/ColorSchemeTest.kt
@@ -15,6 +15,8 @@
  */
 package com.android.systemui.monet
 
+import android.app.WallpaperColors
+import android.graphics.Color
 import android.util.Log
 import androidx.test.ext.junit.runners.AndroidJUnit4
 import androidx.test.filters.SmallTest
@@ -40,8 +42,6 @@ import org.w3c.dom.Node
 
 private const val CONTRAST = 0.0
 
-private const val IS_FIDELITY_ENABLED = false
-
 private const val fileHeader =
     """
   ~ Copyright (C) 2022 The Android Open Source Project
@@ -85,6 +85,11 @@ private fun commentShade(paletteName: String, tone: Int): String {
 @SmallTest
 @RunWith(AndroidJUnit4::class)
 class ColorSchemeTest {
+    private val paletteTokens =
+        DynamicColors.getAllAccentPalette() +
+            DynamicColors.getAllNeutralPalette() +
+            DynamicColors.getAllErrorPalette()
+
     @Test
     fun generateThemeStyles() {
         val document = buildDoc<Any>()
@@ -92,45 +97,57 @@ class ColorSchemeTest {
         val themes = document.createElement("themes")
         document.appendWithBreak(themes)
 
-        var hue = 0.0
-        while (hue < 360) {
-            val sourceColor = Hct.from(hue, 50.0, 50.0)
-            val sourceColorHex = sourceColor.toInt().toRGBHex()
-
-            val theme = document.createElement("theme")
-            theme.setAttribute("color", sourceColorHex)
-            themes.appendChild(theme)
-
-            for (styleValue in Style.values()) {
-                if (
-                    styleValue == Style.CLOCK ||
-                        styleValue == Style.CLOCK_VIBRANT ||
-                        styleValue == Style.CONTENT
-                ) {
-                    continue
+        for (isDarkMode in arrayOf(true, false)) {
+            val mode = document.createElement("mode")
+            mode.setAttribute("type", if (isDarkMode) "dark" else "light")
+            themes.appendChild(mode)
+
+            var hue = 0.0
+            while (hue < 360) {
+                val sourceColorHct = Hct.from(hue, 50.0, 50.0)
+                val sourceColorInt = sourceColorHct.toInt()
+                val sourceColor = Color.valueOf(sourceColorInt)
+                val sourceColorHex = "#" + sourceColorInt.toRGBHex()
+
+                val theme = document.createElement("theme")
+                theme.setAttribute("color", sourceColorHex)
+                mode.appendChild(theme)
+
+                for (styleValue in Style.values()) {
+                    if (
+                        styleValue == Style.CLOCK ||
+                            styleValue == Style.CLOCK_VIBRANT ||
+                            styleValue == Style.CONTENT
+                    ) {
+                        continue
+                    }
+
+                    val style = document.createElement(Style.name(styleValue).lowercase())
+                    val colorScheme =
+                        ColorScheme(
+                            WallpaperColors(sourceColor, sourceColor, sourceColor),
+                            isDarkMode,
+                            styleValue,
+                        )
+
+                    style.appendChild(
+                        document.createTextNode(
+                            listOf(
+                                    colorScheme.accent1,
+                                    colorScheme.accent2,
+                                    colorScheme.accent3,
+                                    colorScheme.neutral1,
+                                    colorScheme.neutral2,
+                                )
+                                .flatMap { a -> listOf(*a.allShades.toTypedArray()) }
+                                .joinToString(",", transform = Int::toRGBHex)
+                        )
+                    )
+                    theme.appendChild(style)
                 }
 
-                val style = document.createElement(Style.name(styleValue).lowercase())
-                val colorScheme = ColorScheme(sourceColor.toInt(), false, styleValue)
-
-                style.appendChild(
-                    document.createTextNode(
-                        listOf(
-                                colorScheme.accent1,
-                                colorScheme.accent2,
-                                colorScheme.accent3,
-                                colorScheme.neutral1,
-                                colorScheme.neutral2,
-                                colorScheme.error,
-                            )
-                            .flatMap { a -> listOf(*a.allShades.toTypedArray()) }
-                            .joinToString(",", transform = Int::toRGBHex)
-                    )
-                )
-                theme.appendChild(style)
+                hue += 60
             }
-
-            hue += 60
         }
 
         saveFile(document, "themes.xml")
@@ -144,37 +161,42 @@ class ColorSchemeTest {
         document.appendWithBreak(resources)
 
         // shade colors
-        val colorScheme = ColorScheme(GOOGLE_BLUE, false)
-        arrayOf(
-                Triple("accent1", "Primary", colorScheme.accent1),
-                Triple("accent2", "Secondary", colorScheme.accent2),
-                Triple("accent3", "Tertiary", colorScheme.accent3),
-                Triple("neutral1", "Neutral", colorScheme.neutral1),
-                Triple("neutral2", "Secondary Neutral", colorScheme.neutral2),
-                Triple("error", "Error", colorScheme.error),
-            )
-            .forEach {
-                val (paletteName, readable, palette) = it
-                palette.allShadesMapped.toSortedMap().entries.forEachIndexed {
-                    index,
-                    (shade, colorValue) ->
-                    val comment =
-                        when (index) {
-                            0 -> commentWhite(readable)
-                            palette.allShadesMapped.entries.size - 1 -> commentBlack(readable)
-                            else -> commentShade(readable, abs(shade / 10 - 100))
-                        }
-                    resources.createColorEntry("system_${paletteName}_$shade", colorValue, comment)
-                }
-            }
+        arrayOf(false, true).forEach { isDark ->
+            val suffix = if (isDark) "_dark" else "_light"
+            val dynamicScheme = SchemeTonalSpot(Hct.fromInt(GOOGLE_BLUE), isDark, CONTRAST)
+            (paletteTokens).forEach {
+                val paletteName =
+                    when (it.first.substringBefore("_")) {
+                        "accent1" -> "Primary"
+                        "accent2" -> "Secondary"
+                        "accent3" -> "Tertiary"
+                        "neutral1" -> "Neutral"
+                        "neutral2" -> "Neutral Variant"
+                        else -> "Error"
+                    }
+
+                val shade = it.first.substringAfter("_").toInt()
+
+                val comment =
+                    when (shade) {
+                        0 -> commentWhite(paletteName)
+                        1000 -> commentBlack(paletteName)
+                        else -> commentShade(paletteName, abs(shade / 10 - 100))
+                    }
 
-        resources.appendWithBreak(document.createComment(commentRoles), 2)
+                resources.createColorEntry(
+                    "system_${it.first}$suffix",
+                    it.second.getArgb(dynamicScheme),
+                    comment,
+                )
+            }
+        }
 
         // dynamic colors
         arrayOf(false, true).forEach { isDark ->
             val suffix = if (isDark) "_dark" else "_light"
             val dynamicScheme = SchemeTonalSpot(Hct.fromInt(GOOGLE_BLUE), isDark, CONTRAST)
-            DynamicColors.getAllDynamicColorsMapped(IS_FIDELITY_ENABLED).forEach {
+            DynamicColors.getAllDynamicColorsMapped().forEach {
                 resources.createColorEntry(
                     "system_${it.first}$suffix",
                     it.second.getArgb(dynamicScheme),
@@ -184,7 +206,7 @@ class ColorSchemeTest {
 
         // fixed colors
         val dynamicScheme = SchemeTonalSpot(Hct.fromInt(GOOGLE_BLUE), false, CONTRAST)
-        DynamicColors.getFixedColorsMapped(IS_FIDELITY_ENABLED).forEach {
+        DynamicColors.getFixedColorsMapped().forEach {
             resources.createColorEntry("system_${it.first}", it.second.getArgb(dynamicScheme))
         }
 
@@ -192,7 +214,7 @@ class ColorSchemeTest {
         arrayOf(false, true).forEach { isDark ->
             val suffix = if (isDark) "_dark" else "_light"
             val dynamicScheme = SchemeTonalSpot(Hct.fromInt(GOOGLE_BLUE), isDark, CONTRAST)
-            DynamicColors.getCustomColorsMapped(IS_FIDELITY_ENABLED).forEach {
+            DynamicColors.getCustomColorsMapped().forEach {
                 resources.createColorEntry(
                     "system_${it.first}$suffix",
                     it.second.getArgb(dynamicScheme),
@@ -210,10 +232,11 @@ class ColorSchemeTest {
         val resources = document.createElement("resources")
         document.appendWithBreak(resources)
 
-        (DynamicColors.getAllDynamicColorsMapped(IS_FIDELITY_ENABLED) +
-                DynamicColors.getFixedColorsMapped(IS_FIDELITY_ENABLED))
-            .forEach {
-                val newName = ("material_color_" + it.first).snakeToLowerCamelCase()
+        arrayOf(false, true).forEach { isDark ->
+            val suffix = if (isDark) "_dark" else "_light"
+
+            (paletteTokens).forEach {
+                val newName = "system_" + it.first + suffix // keep snake_case
 
                 resources.createEntry(
                     "java-symbol",
@@ -221,8 +244,19 @@ class ColorSchemeTest {
                     null,
                 )
             }
+        }
+
+        (DynamicColors.getAllDynamicColorsMapped() + DynamicColors.getFixedColorsMapped()).forEach {
+            val newName = ("material_color_" + it.first).snakeToLowerCamelCase()
 
-        DynamicColors.getCustomColorsMapped(IS_FIDELITY_ENABLED).forEach {
+            resources.createEntry(
+                "java-symbol",
+                arrayOf(Pair("name", newName), Pair("type", "color")),
+                null,
+            )
+        }
+
+        DynamicColors.getCustomColorsMapped().forEach {
             val newName = ("custom_color_" + it.first).snakeToLowerCamelCase()
 
             resources.createEntry(
@@ -233,7 +267,7 @@ class ColorSchemeTest {
         }
 
         arrayOf("_light", "_dark").forEach { suffix ->
-            DynamicColors.getCustomColorsMapped(IS_FIDELITY_ENABLED).forEach {
+            DynamicColors.getCustomColorsMapped().forEach {
                 val newName = "system_" + it.first + suffix
 
                 resources.createEntry(
@@ -255,21 +289,25 @@ class ColorSchemeTest {
             val resources = document.createElement("resources")
             document.appendWithBreak(resources)
 
-            (DynamicColors.getAllDynamicColorsMapped(IS_FIDELITY_ENABLED) +
-                    DynamicColors.getFixedColorsMapped(IS_FIDELITY_ENABLED))
+            val suffix = if (isDark) "_dark" else "_light"
+
+            (paletteTokens).forEach {
+                val newName = ("system_" + it.first) // keep snake_case
+                val colorValue = "@color/" + newName + suffix
+
+                resources.createColorEntry(newName, colorValue)
+            }
+
+            (DynamicColors.getAllDynamicColorsMapped() + DynamicColors.getFixedColorsMapped())
                 .forEach {
                     val newName = ("material_color_" + it.first).snakeToLowerCamelCase()
-
-                    val suffix = if (isDark) "_dark" else "_light"
                     val colorValue =
                         "@color/system_" + it.first + if (it.first.contains("fixed")) "" else suffix
 
                     resources.createColorEntry(newName, colorValue)
                 }
 
-            val suffix = if (isDark) "_dark" else "_light"
-
-            DynamicColors.getCustomColorsMapped(IS_FIDELITY_ENABLED).forEach {
+            DynamicColors.getCustomColorsMapped().forEach {
                 val newName = ("custom_color_" + it.first).snakeToLowerCamelCase()
                 resources.createColorEntry(newName, "@color/system_" + it.first + suffix)
             }
@@ -283,20 +321,16 @@ class ColorSchemeTest {
         val document = buildDoc<Any>()
 
         val resources = document.createElement("resources")
-
         val group = document.createElement("staging-public-group")
-        resources.appendChild(group)
 
+        resources.appendChild(group)
         document.appendWithBreak(resources)
 
-        val context = InstrumentationRegistry.getInstrumentation().targetContext
-        val res = context.resources
-
         val rClass = com.android.internal.R.color::class.java
         val existingFields = rClass.declaredFields.map { it.name }.toSet()
 
         arrayOf("_light", "_dark").forEach { suffix ->
-            DynamicColors.getAllDynamicColorsMapped(IS_FIDELITY_ENABLED).forEach {
+            DynamicColors.getAllDynamicColorsMapped().forEach {
                 val name = "system_" + it.first + suffix
                 if (!existingFields.contains(name)) {
                     group.createEntry("public", arrayOf(Pair("name", name)), null)
@@ -304,7 +338,7 @@ class ColorSchemeTest {
             }
         }
 
-        DynamicColors.getFixedColorsMapped(IS_FIDELITY_ENABLED).forEach {
+        DynamicColors.getFixedColorsMapped().forEach {
             val name = "system_${it.first}"
             if (!existingFields.contains(name)) {
                 group.createEntry("public", arrayOf(Pair("name", name)), null)
diff --git a/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLogger.kt b/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLogger.kt
index 6e255af..7ce884c 100644
--- a/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLogger.kt
+++ b/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLogger.kt
@@ -34,7 +34,7 @@ interface MSDLHistoryLogger {
 
     companion object {
 
-        const val HISTORY_SIZE = 20
+        const val HISTORY_SIZE = 50
         val DATE_FORMAT = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US)
     }
 }
diff --git a/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLoggerImpl.kt b/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLoggerImpl.kt
index bc8a810..30e5fb0 100644
--- a/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLoggerImpl.kt
+++ b/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLoggerImpl.kt
@@ -18,22 +18,26 @@ package com.google.android.msdl.logging
 
 import androidx.annotation.VisibleForTesting
 import androidx.annotation.VisibleForTesting.Companion.PACKAGE_PRIVATE
-import java.util.ArrayDeque
-import java.util.Deque
 
 @VisibleForTesting(otherwise = PACKAGE_PRIVATE)
 class MSDLHistoryLoggerImpl(private val maxHistorySize: Int) : MSDLHistoryLogger {
 
-    // Use an [ArrayDequeue] with a fixed size as the history structure
-    private val history: Deque<MSDLEvent> = ArrayDeque(maxHistorySize)
+    // Use an Array with a fixed size as the history structure. This will work as a ring buffer
+    private val history: Array<MSDLEvent?> = arrayOfNulls(size = maxHistorySize)
+    // The head will point to the next available position in the structure to add a new event
+    private var head = 0
 
     override fun addEvent(event: MSDLEvent) {
-        // Keep the history as a FIFO structure
-        if (history.size == maxHistorySize) {
-            history.removeFirst()
-        }
-        history.addLast(event)
+        history[head] = event
+        // Move the head pointer, wrapping if necessary
+        head = (head + 1) % maxHistorySize
     }
 
-    override fun getHistory(): List<MSDLEvent> = history.toList()
+    override fun getHistory(): List<MSDLEvent> {
+        val result = mutableListOf<MSDLEvent>()
+        repeat(times = maxHistorySize) { i ->
+            history[(i + head) % maxHistorySize]?.let { result.add(it) }
+        }
+        return result
+    }
 }
diff --git a/toruslib/torus-core/src/main/java/com/google/android/torus/core/power/FpsThrottler.kt b/toruslib/torus-core/src/main/java/com/google/android/torus/core/power/FpsThrottler.kt
index 873327d..b928f54 100644
--- a/toruslib/torus-core/src/main/java/com/google/android/torus/core/power/FpsThrottler.kt
+++ b/toruslib/torus-core/src/main/java/com/google/android/torus/core/power/FpsThrottler.kt
@@ -22,41 +22,38 @@ package com.google.android.torus.core.power
  */
 class FpsThrottler {
     companion object {
-        private const val NANO_TO_MILLIS = 1 / 1E6
+        const val NANO_TO_MILLIS = 1 / 1E6
 
         const val FPS_120 = 120f
         const val FPS_60 = 60f
         const val FPS_30 = 30f
         const val FPS_18 = 18f
 
-        @Deprecated(message = "Use FPS_60 instead.")
-        const val HIGH_FPS = 60f
-        @Deprecated(message = "Use FPS_30 instead.")
-        const val MED_FPS = 30f
-        @Deprecated(message = "Use FPS_18 instead.")
-        const val LOW_FPS = 18f
+        @Deprecated(message = "Use FPS_60 instead.") const val HIGH_FPS = 60f
+        @Deprecated(message = "Use FPS_30 instead.") const val MED_FPS = 30f
+        @Deprecated(message = "Use FPS_18 instead.") const val LOW_FPS = 18f
+
+        /** Small tolerance (ms) for float precision in frame timing. */
+        const val TOLERANCE_MILLIS = 1L
     }
 
     private var fps: Float = FPS_60
 
-    @Volatile
-    private var frameTimeMillis: Double = 1000.0 / fps.toDouble()
+    @Volatile private var frameTimeMillis: Double = 1000.0 / fps.toDouble()
     private var lastFrameTimeNanos: Long = -1
 
-    @Volatile
-    private var continuousRenderingMode: Boolean = true
+    @Volatile private var continuousRenderingMode: Boolean = true
 
-    @Volatile
-    private var requestRendering: Boolean = false
+    @Volatile private var requestRendering: Boolean = false
 
     private fun updateFrameTime() {
         frameTimeMillis = 1000.0 / fps.toDouble()
     }
 
     /**
-     * If [fps] is non-zero, update the requested FPS and calculate the frame time
-     * for the requested FPS. Otherwise disable continuous rendering (on demand rendering)
-     * without changing the frame rate.
+     * If [fps] is non-zero, update the requested FPS and calculate the frame time for the requested
+     * FPS. Otherwise disable continuous rendering (on demand rendering) without changing the frame
+     * rate.
      *
      * @param fps The requested FPS value.
      */
@@ -74,7 +71,7 @@ class FpsThrottler {
      * Sets rendering mode to continuous or on demand.
      *
      * @param continuousRenderingMode When true enable continuous rendering. When false disable
-     * continuous rendering (on demand).
+     *   continuous rendering (on demand).
      */
     fun setContinuousRenderingMode(continuousRenderingMode: Boolean) {
         this.continuousRenderingMode = continuousRenderingMode
@@ -86,13 +83,11 @@ class FpsThrottler {
     }
 
     /**
-     * Calculates whether we can render the next frame. In continuous mode return true only
-     * if enough time has passed since the last render to maintain requested FPS.
-     * In on demand mode, return true only if [requestRendering] was called to render
-     * the next frame.
+     * Calculates whether we can render the next frame. In continuous mode return true only if
+     * enough time has passed since the last render to maintain requested FPS. In on demand mode,
+     * return true only if [requestRendering] was called to render the next frame.
      *
      * @param frameTimeNanos The time in nanoseconds when the current frame started.
-     *
      * @return true if we can render the next frame.
      */
     fun canRender(frameTimeNanos: Long): Boolean {
@@ -102,7 +97,7 @@ class FpsThrottler {
                 true
             } else {
                 val deltaMillis = (frameTimeNanos - lastFrameTimeNanos) * NANO_TO_MILLIS
-                return (deltaMillis >= frameTimeMillis) && (fps > 0f)
+                return (deltaMillis >= frameTimeMillis - TOLERANCE_MILLIS) && (fps > 0f)
             }
         } else {
             // on demand rendering
@@ -119,8 +114,7 @@ class FpsThrottler {
      *
      * @param frameTimeNanos The time in nanoseconds when the current frame started.
      * @param onRenderPermitted The client delegate to dispatch if rendering is permitted at this
-     * time.
-     *
+     *   time.
      * @return true if a frame is permitted and then actually rendered.
      */
     fun tryRender(frameTimeNanos: Long, onRenderPermitted: () -> Boolean): Boolean {
diff --git a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt
index 66ff79b..b04bcf8 100644
--- a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt
+++ b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt
@@ -434,6 +434,17 @@ abstract class LiveWallpaper : WallpaperService() {
             return super.onCommand(action, x, y, z, extras, resultRequested)
         }
 
+        override fun onAmbientModeChanged(inAmbientMode: Boolean, animationDuration: Long) {
+            super.onAmbientModeChanged(inAmbientMode, animationDuration)
+
+            if (wallpaperEngine is LiveWallpaperEventListener) {
+                (wallpaperEngine as LiveWallpaperEventListener).onAmbientModeChanged(
+                    inAmbientMode,
+                    animationDuration,
+                )
+            }
+        }
+
         override fun onTouchEvent(event: MotionEvent) {
             super.onTouchEvent(event)
 
diff --git a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperEventListener.kt b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperEventListener.kt
index a3a2c95..c581bed 100644
--- a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperEventListener.kt
+++ b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperEventListener.kt
@@ -18,6 +18,7 @@ package com.google.android.torus.core.wallpaper.listener
 
 import android.app.WallpaperColors
 import android.os.Bundle
+import android.service.wallpaper.WallpaperService
 
 /**
  * Interface that is used to implement specific wallpaper callbacks like offset change (user swipes
@@ -101,6 +102,9 @@ interface LiveWallpaperEventListener {
      */
     fun onSleep(extras: Bundle)
 
+    /** @see WallpaperService.Engine.onAmbientModeChanged */
+    fun onAmbientModeChanged(inAmbientMode: Boolean, animationDuration: Long) {}
+
     /**
      * Indicates whether the zoom animation should be handled in WindowManager. Preferred to be set
      * to true to avoid pressuring GPU.
diff --git a/toruslib/torus-framework-canvas/src/main/java/com/google/android/torus/canvas/engine/CanvasWallpaperEngine.kt b/toruslib/torus-framework-canvas/src/main/java/com/google/android/torus/canvas/engine/CanvasWallpaperEngine.kt
index 814dff6..b9438af 100644
--- a/toruslib/torus-framework-canvas/src/main/java/com/google/android/torus/canvas/engine/CanvasWallpaperEngine.kt
+++ b/toruslib/torus-framework-canvas/src/main/java/com/google/android/torus/canvas/engine/CanvasWallpaperEngine.kt
@@ -31,9 +31,9 @@ import com.google.android.torus.core.wallpaper.LiveWallpaper
 import java.io.PrintWriter
 
 /**
- * Class that implements [TorusEngine] using Canvas and can be used in a [LiveWallpaper]. This
- * class also inherits from [LiveWallpaper.LiveWallpaperConnector] which allows to do some calls
- * related to Live Wallpapers, like the method [isPreview] or [notifyWallpaperColorsChanged].
+ * Class that implements [TorusEngine] using Canvas and can be used in a [LiveWallpaper]. This class
+ * also inherits from [LiveWallpaper.LiveWallpaperConnector] which allows to do some calls related
+ * to Live Wallpapers, like the method [isPreview] or [notifyWallpaperColorsChanged].
  *
  * By default it won't start [startUpdateLoop]. To run animations and update logic per frame, call
  * [startUpdateLoop] and [stopUpdateLoop] when it's no longer needed.
@@ -46,22 +46,22 @@ abstract class CanvasWallpaperEngine(
 
     /**
      * Defines if the surface should be hardware accelerated or not. If you are using
-     * [RuntimeShader], this value should be set to true. When setting it to true, some
-     * functions might not be supported. Please refer to the documentation:
+     * [RuntimeShader], this value should be set to true. When setting it to true, some functions
+     * might not be supported. Please refer to the documentation:
      * https://developer.android.com/guide/topics/graphics/hardware-accel#unsupported
      */
     private val hardwareAccelerated: Boolean = false,
 ) : LiveWallpaper.LiveWallpaperConnector(), TorusEngine {
 
     private val choreographer = Choreographer.getInstance()
-    private val timeController = TimeController().also {
-        it.resetDeltaTime(SystemClock.uptimeMillis())
-    }
+    private val timeController =
+        TimeController().also { it.resetDeltaTime(SystemClock.uptimeMillis()) }
     private val frameScheduler = FrameCallback()
     private val fpsThrottler = FpsThrottler()
 
     protected var screenSize = Size(0, 0)
         private set
+
     private var resizeCalled: Boolean = false
 
     private var isWallpaperEngineVisible = false
@@ -69,9 +69,9 @@ abstract class CanvasWallpaperEngine(
      * Indicates whether the engine#onCreate is called.
      *
      * TODO(b/277672928): These two booleans were introduced as a workaround where
-     *  [onSurfaceRedrawNeeded] called after an [onSurfaceDestroyed], without [onCreate]/
-     *  [onSurfaceCreated] being called between those. Remove these once it's fixed in
-     *  [WallpaperService].
+     *   [onSurfaceRedrawNeeded] called after an [onSurfaceDestroyed], without [onCreate]/
+     *   [onSurfaceCreated] being called between those. Remove these once it's fixed in
+     *   [WallpaperService].
      */
     private var isCreated = false
     private var shouldInvokeResume = false
@@ -110,8 +110,8 @@ abstract class CanvasWallpaperEngine(
      * update logic and render in this loop.
      *
      * @param deltaMillis The time in millis since the last time [onUpdate] was called.
-     * @param frameTimeNanos The time in nanoseconds when the frame started being rendered,
-     * in the [System.nanoTime] timebase.
+     * @param frameTimeNanos The time in nanoseconds when the frame started being rendered, in the
+     *   [System.nanoTime] timebase.
      */
     @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
     open fun onUpdate(deltaMillis: Long, frameTimeNanos: Long) {
@@ -122,7 +122,7 @@ abstract class CanvasWallpaperEngine(
      * Callback to handle when we need to destroy the surface.
      *
      * @param isLastActiveInstance Whether this was the last wallpaper engine instance (until the
-     * next [onCreate]).
+     *   next [onCreate]).
      */
     @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
     open fun onDestroy(isLastActiveInstance: Boolean) {
@@ -130,10 +130,11 @@ abstract class CanvasWallpaperEngine(
     }
 
     final override fun create(isFirstActiveInstance: Boolean) {
-        screenSize = Size(
-            getCurrentSurfaceHolder().surfaceFrame.width(),
-            getCurrentSurfaceHolder().surfaceFrame.height()
-        )
+        screenSize =
+            Size(
+                getCurrentSurfaceHolder().surfaceFrame.width(),
+                getCurrentSurfaceHolder().surfaceFrame.height(),
+            )
 
         onCreate(isFirstActiveInstance)
 
@@ -141,8 +142,10 @@ abstract class CanvasWallpaperEngine(
 
         if (shouldInvokeResume) {
             Log.e(
-                TAG, "Force invoke resume. onVisibilityChanged must have been called" +
-                        "before onCreate.")
+                TAG,
+                "Force invoke resume. onVisibilityChanged must have been called" +
+                    "before onCreate.",
+            )
             resume()
             shouldInvokeResume = false
         }
@@ -151,8 +154,10 @@ abstract class CanvasWallpaperEngine(
     final override fun pause() {
         if (!isCreated) {
             Log.e(
-                TAG, "Engine is not yet created but pause is called. Set a flag to invoke" +
-                        " resume on next create.")
+                TAG,
+                "Engine is not yet created but pause is called. Set a flag to invoke" +
+                    " resume on next create.",
+            )
             shouldInvokeResume = true
             return
         }
@@ -166,8 +171,10 @@ abstract class CanvasWallpaperEngine(
     final override fun resume() {
         if (!isCreated) {
             Log.e(
-                TAG, "Engine is not yet created but resume is called. Set a flag to " +
-                        "invoke resume on next create.")
+                TAG,
+                "Engine is not yet created but resume is called. Set a flag to " +
+                    "invoke resume on next create.",
+            )
             shouldInvokeResume = true
             return
         }
@@ -198,9 +205,8 @@ abstract class CanvasWallpaperEngine(
      * FPS that was set via [setFpsLimit].
      *
      * @param frameTimeNanos The time in nanoseconds when the frame started being rendered, in the
-     * [System.nanoTime] timebase.
+     *   [System.nanoTime] timebase.
      * @param onRender The callback triggered when the canvas is ready for render.
-     *
      * @return Whether it is rendered.
      */
     fun renderWithFpsLimit(frameTimeNanos: Long, onRender: (canvas: Canvas) -> Unit): Boolean {
@@ -215,16 +221,13 @@ abstract class CanvasWallpaperEngine(
             return renderWithFpsLimit(frameTimeNanos, onRender)
         }
 
-        return fpsThrottler.tryRender(frameTimeNanos) {
-            renderToCanvas(onRender)
-        }
+        return fpsThrottler.tryRender(frameTimeNanos) { renderToCanvas(onRender) }
     }
 
     /**
      * Renders to canvas.
      *
      * @param onRender The callback triggered when the canvas is ready for render.
-     *
      * @return Whether it is rendered.
      */
     fun render(onRender: (canvas: Canvas) -> Unit): Boolean {
@@ -250,9 +253,7 @@ abstract class CanvasWallpaperEngine(
         fpsThrottler.updateFps(fps)
     }
 
-    /**
-     * Starts the update loop.
-     */
+    /** Starts the update loop. */
     protected fun startUpdateLoop() {
         if (!frameScheduler.running) {
             frameScheduler.running = true
@@ -260,9 +261,7 @@ abstract class CanvasWallpaperEngine(
         }
     }
 
-    /**
-     * Stops the update loop.
-     */
+    /** Stops the update loop. */
     protected fun stopUpdateLoop() {
         if (frameScheduler.running) {
             frameScheduler.running = false
@@ -276,14 +275,14 @@ abstract class CanvasWallpaperEngine(
         var canvas: Canvas? = null
 
         try {
-            canvas = if (hardwareAccelerated) {
-                surfaceHolder.lockHardwareCanvas()
-            } else {
-                surfaceHolder.lockCanvas()
-            } ?: return false
+            canvas =
+                if (hardwareAccelerated) {
+                    surfaceHolder.lockHardwareCanvas()
+                } else {
+                    surfaceHolder.lockCanvas()
+                } ?: return false
 
             onRender(canvas)
-
         } catch (e: java.lang.Exception) {
             Log.e("canvas_exception", "canvas exception", e)
         } finally {
@@ -294,12 +293,9 @@ abstract class CanvasWallpaperEngine(
         return true
     }
 
-    private fun getCurrentSurfaceHolder(): SurfaceHolder =
-        getEngineSurfaceHolder() ?: defaultHolder
+    private fun getCurrentSurfaceHolder(): SurfaceHolder = getEngineSurfaceHolder() ?: defaultHolder
 
-    /**
-     * Implementation of [Choreographer.FrameCallback] which triggers [onUpdate].
-     */
+    /** Implementation of [Choreographer.FrameCallback] which triggers [onUpdate]. */
     inner class FrameCallback : Choreographer.FrameCallback {
         internal var running: Boolean = false
 
@@ -326,4 +322,4 @@ abstract class CanvasWallpaperEngine(
     private companion object {
         private val TAG: String = CanvasWallpaperEngine::class.java.simpleName
     }
-}
\ No newline at end of file
+}
diff --git a/toruslib/torus-utils/src/main/java/com/google/android/torus/utils/broadcast/PowerSaveController.kt b/toruslib/torus-utils/src/main/java/com/google/android/torus/utils/broadcast/PowerSaveController.kt
index c9f0d3e..5b0c0cc 100644
--- a/toruslib/torus-utils/src/main/java/com/google/android/torus/utils/broadcast/PowerSaveController.kt
+++ b/toruslib/torus-utils/src/main/java/com/google/android/torus/utils/broadcast/PowerSaveController.kt
@@ -23,25 +23,24 @@ import android.os.PowerManager
 import java.util.concurrent.atomic.AtomicBoolean
 
 /**
- * PowerSaveController registers a BroadcastReceiver that listens to
- * changes in Power Save Mode provided by the OS.
- * Forwards received broadcasts to be handled by a [PowerSaveListener].
+ * PowerSaveController registers a BroadcastReceiver that listens to changes in Power Save Mode
+ * provided by the OS. Forwards received broadcasts to be handled by a [PowerSaveListener].
  */
-class PowerSaveController(
-    context: Context,
-    private val listener: PowerSaveListener?
-) : BroadcastEventController(context) {
+class PowerSaveController(context: Context, listener: PowerSaveListener?) :
+    BroadcastEventController(context) {
     companion object {
         const val DEFAULT_POWER_SAVE_MODE = false
     }
 
+    private val listeners = mutableListOf<PowerSaveListener>()
+
     private var powerSaving: AtomicBoolean? = null
     private var powerManager: PowerManager? = null
 
     override fun initResources(): Boolean {
         if (powerSaving == null) powerSaving = AtomicBoolean(DEFAULT_POWER_SAVE_MODE)
-        if (powerManager == null) powerManager =
-                context.getSystemService(Context.POWER_SERVICE) as PowerManager?
+        if (powerManager == null)
+            powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager?
         return powerManager != null
     }
 
@@ -59,21 +58,32 @@ class PowerSaveController(
 
     override fun onUnregister() {}
 
+    init {
+        if (listener != null) {
+            listeners.add(listener)
+        }
+    }
+
     private fun setPowerSave(isPowerSave: Boolean, fire: Boolean) {
         powerSaving?.let {
             if (it.get() == isPowerSave) return
             it.set(isPowerSave)
         }
 
-        listener?.let {
-            if (fire) listener.onPowerSaveModeChanged(isPowerSave)
-        }
+        listeners.forEach { listener -> if (fire) listener.onPowerSaveModeChanged(isPowerSave) }
     }
 
     fun isPowerSaving(): Boolean = powerSaving?.get() ?: false
 
+    fun registerListener(listener: PowerSaveListener) {
+        listeners += listener
+    }
+
+    fun unregisterListener(listener: PowerSaveListener) {
+        listeners -= listener
+    }
+
     interface PowerSaveListener {
         fun onPowerSaveModeChanged(isPowerSaveMode: Boolean)
     }
-
 }
diff --git a/tracinglib/README.md b/tracinglib/README.md
index 86d863a..08ba9a6 100644
--- a/tracinglib/README.md
+++ b/tracinglib/README.md
@@ -93,7 +93,8 @@ Coroutine tracing is flagged off by default. To enable coroutine tracing on a de
 and restart the user-space system:
 
 ```
-adb shell device_config override systemui com.android.systemui.coroutine_tracing true
+adb shell aflags enable com.android.systemui.coroutine_tracing
+adb shell setprop persist.debug.coroutine_tracing 1
 adb shell am restart
 ```
 
@@ -101,8 +102,8 @@ adb shell am restart
 
 The behavior of coroutine tracing can be further fine-tuned using the following sysprops:
 
- - `debug.coroutine_tracing.walk_stack_override`
- - `debug.coroutine_tracing.count_continuations_override`
+ - `persist.debug.coroutine_tracing.walk_stack_override`
+ - `persist.debug.coroutine_tracing.count_continuations_override`
 
 See [`createCoroutineTracingContext()`](core/src/coroutines/TraceContextElement.kt) for
 documentation.
diff --git a/tracinglib/core/Android.bp b/tracinglib/core/Android.bp
index f292898..c476a37 100644
--- a/tracinglib/core/Android.bp
+++ b/tracinglib/core/Android.bp
@@ -28,6 +28,7 @@ java_library {
     static_libs: [
         "kotlinx_coroutines_android",
         "com_android_systemui_flags_lib",
+        "compilelib",
     ],
     kotlincflags: [
         "-Xjvm-default=all",
diff --git a/tracinglib/core/src/ListenersTracing.kt b/tracinglib/core/src/ListenersTracing.kt
index 25a1b6e..9617a1d 100644
--- a/tracinglib/core/src/ListenersTracing.kt
+++ b/tracinglib/core/src/ListenersTracing.kt
@@ -27,13 +27,13 @@ public object ListenersTracing {
      * listeners.forEach { it.dispatch(state) }
      * ```
      *
-     * often it's tricky to udnerstand which listener is causing delays. This can be used instead to
+     * often it's tricky to understand which listener is causing delays. This can be used instead to
      * log how much each listener is taking:
      * ```
      * listeners.forEachTraced(TAG) { it.dispatch(state) }
      * ```
      */
-    public inline fun <T : Any> List<T>.forEachTraced(tag: String = "", f: (T) -> Unit) {
+    public inline fun <T : Any> Iterable<T>.forEachTraced(tag: String = "", f: (T) -> Unit) {
         forEach { traceSection({ "$tag#${it::javaClass.get().name}" }) { f(it) } }
     }
 }
diff --git a/tracinglib/core/src/TraceUtils.kt b/tracinglib/core/src/TraceUtils.kt
index 9dfdfa1..579a69f 100644
--- a/tracinglib/core/src/TraceUtils.kt
+++ b/tracinglib/core/src/TraceUtils.kt
@@ -111,13 +111,14 @@ public inline fun <T> traceSection(tag: String, block: () -> T): T {
  * strings when not needed.
  */
 @OptIn(ExperimentalContracts::class)
-public inline fun <T> traceSection(tag: () -> String, block: () -> T): T {
+public inline fun <T> traceSection(tag: () -> String?, block: () -> T): T {
     contract {
         callsInPlace(tag, InvocationKind.AT_MOST_ONCE)
         callsInPlace(block, InvocationKind.EXACTLY_ONCE)
     }
-    val tracingEnabled = Trace.isEnabled()
-    if (tracingEnabled) beginSlice(tag())
+    val sliceName = if (Trace.isEnabled()) tag() else null
+    val tracingEnabled = sliceName != null
+    if (tracingEnabled) beginSlice(sliceName!!)
     return try {
         block()
     } finally {
diff --git a/tracinglib/core/src/coroutines/CoroutineTracing.kt b/tracinglib/core/src/coroutines/CoroutineTracing.kt
index 8ca6ca3..f835514 100644
--- a/tracinglib/core/src/coroutines/CoroutineTracing.kt
+++ b/tracinglib/core/src/coroutines/CoroutineTracing.kt
@@ -18,7 +18,9 @@
 
 package com.android.app.tracing.coroutines
 
+import com.android.app.tracing.coroutines.DebugSysProps.coroutineTracingEnabled
 import com.android.app.tracing.traceSection
+import com.android.systemui.util.Compile
 import kotlin.contracts.ExperimentalContracts
 import kotlin.contracts.InvocationKind
 import kotlin.contracts.contract
@@ -161,10 +163,10 @@ public suspend inline fun <T> withContextTraced(
 }
 
 /** @see kotlinx.coroutines.runBlocking */
-public inline fun <T> runBlockingTraced(
-    crossinline spanName: () -> String,
-    context: CoroutineContext,
-    noinline block: suspend CoroutineScope.() -> T,
+public fun <T> runBlockingTraced(
+    spanName: () -> String? = { null },
+    context: CoroutineContext = EmptyCoroutineContext,
+    block: suspend CoroutineScope.() -> T,
 ): T {
     contract {
         callsInPlace(spanName, InvocationKind.AT_MOST_ONCE)
@@ -222,12 +224,20 @@ public inline fun <T, R> R.traceCoroutine(crossinline spanName: () -> String, bl
     // tracing is not active (i.e. when TRACE_TAG_APP is disabled). Otherwise, when the
     // coroutine resumes when tracing is active, we won't know its name.
     try {
-        if (com.android.systemui.Flags.coroutineTracing()) {
+        if (
+            Compile.IS_DEBUG &&
+                com.android.systemui.Flags.coroutineTracing() &&
+                coroutineTracingEnabled
+        ) {
             traceThreadLocal.get()?.beginCoroutineTrace(spanName())
         }
         return block()
     } finally {
-        if (com.android.systemui.Flags.coroutineTracing()) {
+        if (
+            Compile.IS_DEBUG &&
+                com.android.systemui.Flags.coroutineTracing() &&
+                coroutineTracingEnabled
+        ) {
             traceThreadLocal.get()?.endCoroutineTrace()
         }
     }
@@ -242,12 +252,20 @@ public inline fun <T> traceCoroutine(crossinline spanName: () -> String, block:
     // tracing is not active (i.e. when TRACE_TAG_APP is disabled). Otherwise, when the
     // coroutine resumes when tracing is active, we won't know its name.
     try {
-        if (com.android.systemui.Flags.coroutineTracing()) {
+        if (
+            Compile.IS_DEBUG &&
+                com.android.systemui.Flags.coroutineTracing() &&
+                coroutineTracingEnabled
+        ) {
             traceThreadLocal.get()?.beginCoroutineTrace(spanName())
         }
         return block()
     } finally {
-        if (com.android.systemui.Flags.coroutineTracing()) {
+        if (
+            Compile.IS_DEBUG &&
+                com.android.systemui.Flags.coroutineTracing() &&
+                coroutineTracingEnabled
+        ) {
             traceThreadLocal.get()?.endCoroutineTrace()
         }
     }
@@ -266,10 +284,10 @@ public inline fun <T> traceCoroutine(spanName: String, block: () -> T): T {
 }
 
 /**
- * Returns the passed context if [com.android.systemui.Flags.coroutineTracing] is false. Otherwise,
- * returns a new context by adding [CoroutineTraceName] to the given context. The
- * [CoroutineTraceName] in the passed context will take precedence over the new
- * [CoroutineTraceName].
+ * Returns the given `CoroutineContext` if coroutine tracing is disabled. Otherwise, returns a new
+ * context by adding [CoroutineTraceName] to the given context. If the given [CoroutineTraceName]
+ * already has a [CoroutineTraceName], it will be used instead of the one that would have been
+ * created here, and it will preserve its original name.
  */
 @PublishedApi
 internal inline fun addName(
@@ -277,7 +295,9 @@ internal inline fun addName(
     context: CoroutineContext,
 ): CoroutineContext {
     contract { callsInPlace(spanName, InvocationKind.AT_MOST_ONCE) }
-    return if (com.android.systemui.Flags.coroutineTracing()) {
+    return if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         CoroutineTraceName(spanName()) + context
     } else {
         context
diff --git a/tracinglib/core/src/coroutines/TraceContextElement.kt b/tracinglib/core/src/coroutines/TraceContextElement.kt
index 466b0c6..d9ad27b 100644
--- a/tracinglib/core/src/coroutines/TraceContextElement.kt
+++ b/tracinglib/core/src/coroutines/TraceContextElement.kt
@@ -21,6 +21,8 @@ import android.os.PerfettoTrace
 import android.os.SystemProperties
 import android.os.Trace
 import android.util.Log
+import com.android.app.tracing.coroutines.DebugSysProps.coroutineTracingEnabled
+import com.android.systemui.util.Compile
 import java.lang.StackWalker.StackFrame
 import java.util.concurrent.ThreadLocalRandom
 import java.util.concurrent.atomic.AtomicInteger
@@ -51,14 +53,28 @@ import kotlinx.coroutines.ExperimentalCoroutinesApi
  */
 @PublishedApi internal val traceThreadLocal: TraceDataThreadLocal = TraceDataThreadLocal()
 
+@PublishedApi
 internal object DebugSysProps {
     @JvmField
-    val alwaysEnableStackWalker =
-        SystemProperties.getBoolean("debug.coroutine_tracing.walk_stack_override", false)
+    val coroutineTracingEnabled =
+        Compile.IS_DEBUG &&
+            com.android.systemui.Flags.coroutineTracing() &&
+            SystemProperties.getBoolean("persist.debug.coroutine_tracing", false)
+
+    @JvmField
+    val stackWalkerAlwaysEnabled =
+        Compile.IS_DEBUG &&
+            com.android.systemui.Flags.coroutineTracing() &&
+            SystemProperties.getBoolean("persist.debug.coroutine_tracing.walk_stack", true)
 
     @JvmField
-    val alwaysEnableContinuationCounting =
-        SystemProperties.getBoolean("debug.coroutine_tracing.count_continuations_override", false)
+    val continuationCountingAlwaysEnabled =
+        Compile.IS_DEBUG &&
+            com.android.systemui.Flags.coroutineTracing() &&
+            SystemProperties.getBoolean(
+                "persist.debug.coroutine_tracing.count_continuations",
+                false,
+            )
 }
 
 /**
@@ -84,8 +100,8 @@ internal object DebugSysProps {
  * }
  * ```
  *
- * **NOTE:** The sysprops `debug.coroutine_tracing.walk_stack_override` and
- * `debug.coroutine_tracing.count_continuations_override` can be used to override the parameters
+ * **NOTE:** The sysprops `persist.debug.coroutine_tracing.walk_stack` and
+ * `persist.debug.coroutine_tracing.count_continuations` can be used to override the parameters
  * `walkStackForDefaultNames` and `countContinuations` respectively, forcing them to always be
  * `true`. If the sysprop is `false` (or does not exist), the value of the parameter is passed here
  * is used. If `true`, all calls to [createCoroutineTracingContext] will be overwritten with that
@@ -120,14 +136,17 @@ public fun createCoroutineTracingContext(
     walkStackForDefaultNames: Boolean = false,
     shouldIgnoreClassName: ((String) -> Boolean)? = null,
 ): CoroutineContext {
-    return if (com.android.systemui.Flags.coroutineTracing()) {
+    return if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         TraceContextElement(
             name = name,
             isRoot = true,
             countContinuations =
-                !testMode && (countContinuations || DebugSysProps.alwaysEnableContinuationCounting),
+                !testMode &&
+                    (countContinuations || DebugSysProps.continuationCountingAlwaysEnabled),
             walkStackForDefaultNames =
-                walkStackForDefaultNames || DebugSysProps.alwaysEnableStackWalker,
+                walkStackForDefaultNames || DebugSysProps.stackWalkerAlwaysEnabled,
             shouldIgnoreClassName = shouldIgnoreClassName,
             parentId = null,
             inheritedTracePrefix = if (testMode) "" else null,
diff --git a/tracinglib/core/src/coroutines/TraceData.kt b/tracinglib/core/src/coroutines/TraceData.kt
index fcf2d27..31e59e9 100644
--- a/tracinglib/core/src/coroutines/TraceData.kt
+++ b/tracinglib/core/src/coroutines/TraceData.kt
@@ -20,7 +20,9 @@ package com.android.app.tracing.coroutines
 
 import android.os.Trace
 import com.android.app.tracing.beginSlice
+import com.android.app.tracing.coroutines.DebugSysProps.coroutineTracingEnabled
 import com.android.app.tracing.endSlice
+import com.android.systemui.util.Compile
 import java.util.ArrayDeque
 import kotlin.contracts.ExperimentalContracts
 import kotlin.math.max
@@ -38,7 +40,11 @@ private typealias TraceSection = String
 @PublishedApi
 internal class TraceDataThreadLocal : ThreadLocal<TraceStorage?>() {
     override fun initialValue(): TraceStorage? {
-        return if (com.android.systemui.Flags.coroutineTracing()) {
+        return if (
+            Compile.IS_DEBUG &&
+                com.android.systemui.Flags.coroutineTracing() &&
+                coroutineTracingEnabled
+        ) {
             TraceStorage(null)
         } else {
             null
diff --git a/tracinglib/core/src/coroutines/flow/FlowExt.kt b/tracinglib/core/src/coroutines/flow/FlowExt.kt
index 19819fa..407ed53 100644
--- a/tracinglib/core/src/coroutines/flow/FlowExt.kt
+++ b/tracinglib/core/src/coroutines/flow/FlowExt.kt
@@ -17,9 +17,11 @@
 package com.android.app.tracing.coroutines.flow
 
 import com.android.app.tracing.coroutines.CoroutineTraceName
+import com.android.app.tracing.coroutines.DebugSysProps.coroutineTracingEnabled
 import com.android.app.tracing.coroutines.traceCoroutine
 import com.android.app.tracing.coroutines.traceName
 import com.android.app.tracing.traceBlocking
+import com.android.systemui.util.Compile
 import kotlin.experimental.ExperimentalTypeInference
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.ExperimentalCoroutinesApi
@@ -152,7 +154,9 @@ private class TracedMutableStateFlow<T>(
 public fun <T> Flow<T>.flowName(name: String): Flow<T> = traceAs(name)
 
 public fun <T> Flow<T>.traceAs(name: String): Flow<T> {
-    return if (com.android.systemui.Flags.coroutineTracing()) {
+    return if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         return when (this) {
             is SharedFlow -> traceAs(name)
             else ->
@@ -168,7 +172,9 @@ public fun <T> Flow<T>.traceAs(name: String): Flow<T> {
 }
 
 public fun <T> SharedFlow<T>.traceAs(name: String): SharedFlow<T> {
-    return if (com.android.systemui.Flags.coroutineTracing()) {
+    return if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         when (this) {
             is MutableSharedFlow -> traceAs(name)
             is StateFlow -> traceAs(name)
@@ -180,7 +186,9 @@ public fun <T> SharedFlow<T>.traceAs(name: String): SharedFlow<T> {
 }
 
 public fun <T> StateFlow<T>.traceAs(name: String): StateFlow<T> {
-    return if (com.android.systemui.Flags.coroutineTracing()) {
+    return if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         when (this) {
             is MutableStateFlow -> traceAs(name)
             else -> TracedStateFlow(name, this)
@@ -191,7 +199,9 @@ public fun <T> StateFlow<T>.traceAs(name: String): StateFlow<T> {
 }
 
 public fun <T> MutableSharedFlow<T>.traceAs(name: String): MutableSharedFlow<T> {
-    return if (com.android.systemui.Flags.coroutineTracing()) {
+    return if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         when (this) {
             is MutableStateFlow -> traceAs(name)
             else -> TracedMutableSharedFlow(name, this)
@@ -202,7 +212,9 @@ public fun <T> MutableSharedFlow<T>.traceAs(name: String): MutableSharedFlow<T>
 }
 
 public fun <T> MutableStateFlow<T>.traceAs(name: String): MutableStateFlow<T> {
-    return if (com.android.systemui.Flags.coroutineTracing()) {
+    return if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         TracedMutableStateFlow(name, this)
     } else {
         this
@@ -230,7 +242,9 @@ public fun <T> Flow<T>.onEachTraced(name: String, action: suspend (T) -> Unit):
  * @see kotlinx.coroutines.flow.collect
  */
 public suspend fun <T> Flow<T>.collectTraced(name: String, collector: FlowCollector<T>) {
-    if (com.android.systemui.Flags.coroutineTracing()) {
+    if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         traceAs(name).collect(collector)
     } else {
         collect(collector)
@@ -239,7 +253,9 @@ public suspend fun <T> Flow<T>.collectTraced(name: String, collector: FlowCollec
 
 /** @see kotlinx.coroutines.flow.collect */
 public suspend fun <T> Flow<T>.collectTraced(name: String) {
-    if (com.android.systemui.Flags.coroutineTracing()) {
+    if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         traceAs(name).collect()
     } else {
         collect()
@@ -248,7 +264,9 @@ public suspend fun <T> Flow<T>.collectTraced(name: String) {
 
 /** @see kotlinx.coroutines.flow.collect */
 public suspend fun <T> Flow<T>.collectTraced(collector: FlowCollector<T>) {
-    if (com.android.systemui.Flags.coroutineTracing()) {
+    if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         collectTraced(name = collector.traceName, collector = collector)
     } else {
         collect(collector)
@@ -261,7 +279,9 @@ public fun <T, R> Flow<T>.mapLatestTraced(
     name: String,
     @BuilderInference transform: suspend (value: T) -> R,
 ): Flow<R> {
-    return if (com.android.systemui.Flags.coroutineTracing()) {
+    return if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         traceAs("mapLatest:$name").mapLatest { traceCoroutine(name) { transform(it) } }
     } else {
         mapLatest(transform)
@@ -273,7 +293,9 @@ public fun <T, R> Flow<T>.mapLatestTraced(
 public fun <T, R> Flow<T>.mapLatestTraced(
     @BuilderInference transform: suspend (value: T) -> R
 ): Flow<R> {
-    return if (com.android.systemui.Flags.coroutineTracing()) {
+    return if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         mapLatestTraced(transform.traceName, transform)
     } else {
         mapLatestTraced(transform)
@@ -285,7 +307,9 @@ internal suspend fun <T> Flow<T>.collectLatestTraced(
     name: String,
     action: suspend (value: T) -> Unit,
 ) {
-    if (com.android.systemui.Flags.coroutineTracing()) {
+    if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         return traceAs("collectLatest:$name").collectLatest { traceCoroutine(name) { action(it) } }
     } else {
         collectLatest(action)
@@ -294,7 +318,9 @@ internal suspend fun <T> Flow<T>.collectLatestTraced(
 
 /** @see kotlinx.coroutines.flow.collectLatest */
 public suspend fun <T> Flow<T>.collectLatestTraced(action: suspend (value: T) -> Unit) {
-    if (com.android.systemui.Flags.coroutineTracing()) {
+    if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         collectLatestTraced(action.traceName, action)
     } else {
         collectLatest(action)
@@ -307,7 +333,9 @@ public inline fun <T, R> Flow<T>.transformTraced(
     name: String,
     @BuilderInference crossinline transform: suspend FlowCollector<R>.(value: T) -> Unit,
 ): Flow<R> {
-    return if (com.android.systemui.Flags.coroutineTracing()) {
+    return if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         // Safe flow must be used because collector is exposed to the caller
         safeFlow {
             collect { value ->
@@ -326,7 +354,9 @@ public inline fun <T> Flow<T>.filterTraced(
     name: String,
     crossinline predicate: suspend (T) -> Boolean,
 ): Flow<T> {
-    return if (com.android.systemui.Flags.coroutineTracing()) {
+    return if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         unsafeTransform { value ->
             if (traceCoroutine(name) { predicate(value) }) {
                 emit(value)
@@ -342,7 +372,9 @@ public inline fun <T, R> Flow<T>.mapTraced(
     name: String,
     crossinline transform: suspend (value: T) -> R,
 ): Flow<R> {
-    return if (com.android.systemui.Flags.coroutineTracing()) {
+    return if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    ) {
         unsafeTransform { value ->
             val transformedValue = traceCoroutine(name) { transform(value) }
             emit(transformedValue)
@@ -394,4 +426,8 @@ public fun <T> MutableStateFlow<T>.asStateFlowTraced(name: String): StateFlow<T>
 }
 
 private fun <T> Flow<T>.maybeFuseTraceName(name: String): Flow<T> =
-    if (com.android.systemui.Flags.coroutineTracing()) flowOn(CoroutineTraceName(name)) else this
+    if (
+        Compile.IS_DEBUG && com.android.systemui.Flags.coroutineTracing() && coroutineTracingEnabled
+    )
+        flowOn(CoroutineTraceName(name))
+    else this
diff --git a/tracinglib/robolectric/Android.bp b/tracinglib/robolectric/Android.bp
index 38b2b62..07efa56 100644
--- a/tracinglib/robolectric/Android.bp
+++ b/tracinglib/robolectric/Android.bp
@@ -34,6 +34,7 @@ android_robolectric_test {
         "kotlinx_coroutines_android",
         "flag-junit",
         "com_android_systemui_flags_lib",
+        "compilelib",
     ],
     libs: [
         "androidx.test.core",
diff --git a/tracinglib/robolectric/src/FlagDisabledTest.kt b/tracinglib/robolectric/src/FlagDisabledTest.kt
index 3c62a37..4a3f45d 100644
--- a/tracinglib/robolectric/src/FlagDisabledTest.kt
+++ b/tracinglib/robolectric/src/FlagDisabledTest.kt
@@ -17,10 +17,12 @@
 package com.android.test.tracing.coroutines
 
 import android.platform.test.annotations.DisableFlags
+import com.android.app.tracing.coroutines.DebugSysProps.coroutineTracingEnabled
 import com.android.app.tracing.coroutines.createCoroutineTracingContext
 import com.android.app.tracing.coroutines.traceCoroutine
 import com.android.app.tracing.coroutines.traceThreadLocal
 import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import com.android.systemui.util.Compile
 import com.android.test.tracing.coroutines.util.FakeTraceState
 import kotlin.coroutines.CoroutineContext
 import kotlin.coroutines.EmptyCoroutineContext
@@ -36,7 +38,11 @@ class FlagDisabledTest : TestBase() {
 
     @Test
     fun tracingDisabledWhenFlagIsOff() = runTest {
-        assertFalse(com.android.systemui.Flags.coroutineTracing())
+        assertFalse(
+            com.android.systemui.Flags.coroutineTracing() &&
+                Compile.IS_DEBUG &&
+                coroutineTracingEnabled
+        )
         assertNull(traceThreadLocal.get())
         withContext(createCoroutineTracingContext(testMode = true)) {
             assertNull(traceThreadLocal.get())
diff --git a/tracinglib/robolectric/src/RunBlockingTracedTest.kt b/tracinglib/robolectric/src/RunBlockingTracedTest.kt
new file mode 100644
index 0000000..19dc8f4
--- /dev/null
+++ b/tracinglib/robolectric/src/RunBlockingTracedTest.kt
@@ -0,0 +1,113 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+@file:OptIn(ExperimentalStdlibApi::class, ExperimentalCoroutinesApi::class)
+
+package com.android.test.tracing.coroutines
+
+import com.android.app.tracing.coroutines.runBlockingTraced
+import com.android.app.tracing.traceSection
+import com.android.test.tracing.coroutines.util.FakeTraceState
+import com.android.test.tracing.coroutines.util.ShadowTrace
+import kotlin.coroutines.EmptyCoroutineContext
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.delay
+import org.junit.Assert.assertTrue
+import org.junit.Test
+import org.robolectric.annotation.Config
+
+@Config(shadows = [ShadowTrace::class])
+class RunBlockingTracedTest : TestBase() {
+
+    @Test
+    fun runBlockingTracedWithSpanNameLambda() =
+        runTest(totalEvents = 2) {
+            expect(1, "1^main")
+
+            val result =
+                runBlockingTraced({ "hello" }) {
+                    delay(1)
+                    expect(2, "1^main", "hello")
+                    true
+                }
+
+            assertTrue(result)
+        }
+
+    @Test
+    fun runBlockingTracedWithSpanNameString() =
+        runTest(totalEvents = 2) {
+            expect(1, "1^main")
+
+            val result =
+                runBlockingTraced(spanName = "hello", context = EmptyCoroutineContext) {
+                    delay(1)
+                    expect(2, "1^main", "hello")
+                    true
+                }
+
+            assertTrue(result)
+        }
+
+    @Test
+    fun runBlockingTracedWithDefaultSpanNameAndContext() =
+        runTest(totalEvents = 2) {
+            expect(1, "1^main")
+
+            val result = runBlockingTraced {
+                delay(1)
+                expect(
+                    2,
+                    "1^main",
+                    "RunBlockingTracedTest\$runBlockingTracedWithDefaultSpanNameAndContext\$1\$invokeSuspend\$\$inlined\$runBlockingTraced\$default\$1",
+                )
+                true
+            }
+            assertTrue(result)
+        }
+
+    @Test
+    fun runBlockingTracedNestedTraceSections() =
+        runTest(totalEvents = 2) {
+            expect(1, "1^main")
+
+            val result =
+                runBlockingTraced(spanName = { "OuterSpan" }) {
+                    traceSection("InnerSpan") {
+                        delay(1)
+                        expect(2, "1^main", "OuterSpan", "InnerSpan")
+                        true
+                    }
+                }
+            assertTrue(result)
+        }
+
+    @Test
+    fun runBlockingTracedWhenTracingDisabled() =
+        runTest(totalEvents = 2) {
+            FakeTraceState.isTracingEnabled = false
+
+            expect(1, "1^main")
+
+            val result =
+                runBlockingTraced(spanName = { "NoTraceSpan" }) {
+                    delay(1)
+                    expect(2, "1^main")
+                    true
+                }
+            assertTrue(result)
+        }
+}
diff --git a/viewcapturelib/Android.bp b/viewcapturelib/Android.bp
index fa772e6..899f60e 100644
--- a/viewcapturelib/Android.bp
+++ b/viewcapturelib/Android.bp
@@ -58,6 +58,7 @@ android_test {
         "view_capture",
         "androidx.test.ext.junit",
         "androidx.test.rules",
+        "flag-junit",
         "testables",
         "mockito-kotlin2",
         "mockito-target-extended-minus-junit4",
diff --git a/viewcapturelib/build.gradle b/viewcapturelib/build.gradle
index 6e22edc..e7919fe 100644
--- a/viewcapturelib/build.gradle
+++ b/viewcapturelib/build.gradle
@@ -29,6 +29,7 @@ android {
 dependencies {
     implementation "androidx.core:core:1.9.0"
     implementation project(":frameworks:libs:systemui:viewcapturelib:view_capture_proto")
+    api project(":frameworks:base:core:FrameworkFlags")
     androidTestImplementation project(':SharedTestLib')
     androidTestImplementation 'androidx.test.ext:junit:1.1.3'
     androidTestImplementation "androidx.test:rules:1.4.0"
diff --git a/viewcapturelib/src/com/android/app/viewcapture/PerfettoViewCapture.kt b/viewcapturelib/src/com/android/app/viewcapture/PerfettoViewCapture.kt
index ec7ef50..9154e50 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/PerfettoViewCapture.kt
+++ b/viewcapturelib/src/com/android/app/viewcapture/PerfettoViewCapture.kt
@@ -86,7 +86,7 @@ internal constructor(private val context: Context, executor: Executor) :
     override fun onCapturedViewPropertiesBg(
         elapsedRealtimeNanos: Long,
         windowName: String,
-        startFlattenedTree: ViewPropertyRef
+        startFlattenedTree: ViewPropertyRef,
     ) {
         Trace.beginSection("vc#onCapturedViewPropertiesBg")
 
@@ -99,7 +99,7 @@ internal constructor(private val context: Context, executor: Executor) :
                 windowName,
                 startFlattenedTree,
                 ctx.incrementalState,
-                newInternedStrings
+                newInternedStrings,
             )
             serializeIncrementalState(os, ctx.incrementalState, newInternedStrings)
         }
@@ -112,7 +112,7 @@ internal constructor(private val context: Context, executor: Executor) :
         windowName: String,
         startFlattenedTree: ViewPropertyRef,
         incrementalState: ViewCaptureDataSource.IncrementalState,
-        newInternedStrings: NewInternedStrings
+        newInternedStrings: NewInternedStrings,
     ) {
         mSerializationCurrentView = startFlattenedTree
         mSerializationCurrentId = 0
@@ -121,11 +121,11 @@ internal constructor(private val context: Context, executor: Executor) :
         val tokenViewCapture = os.start(WinscopeExtensionsImpl.VIEWCAPTURE)
         os.write(
             ViewCaptureMessage.PACKAGE_NAME_IID,
-            internPackageName(context.packageName, incrementalState, newInternedStrings)
+            internPackageName(context.packageName, incrementalState, newInternedStrings),
         )
         os.write(
             ViewCaptureMessage.WINDOW_NAME_IID,
-            internWindowName(windowName, incrementalState, newInternedStrings)
+            internWindowName(windowName, incrementalState, newInternedStrings),
         )
         serializeViewsRec(os, -1, incrementalState, newInternedStrings)
         os.end(tokenViewCapture)
@@ -136,7 +136,7 @@ internal constructor(private val context: Context, executor: Executor) :
         os: ProtoOutputStream,
         parentId: Int,
         incrementalState: ViewCaptureDataSource.IncrementalState,
-        newInternedStrings: NewInternedStrings
+        newInternedStrings: NewInternedStrings,
     ) {
         if (mSerializationCurrentView == null) {
             return
@@ -151,7 +151,7 @@ internal constructor(private val context: Context, executor: Executor) :
             mSerializationCurrentId,
             parentId,
             incrementalState,
-            newInternedStrings
+            newInternedStrings,
         )
 
         ++mSerializationCurrentId
@@ -168,7 +168,7 @@ internal constructor(private val context: Context, executor: Executor) :
         id: Int,
         parentId: Int,
         incrementalState: ViewCaptureDataSource.IncrementalState,
-        newInternedStrings: NewInternedStrings
+        newInternedStrings: NewInternedStrings,
     ) {
         val token = os.start(ViewCaptureMessage.VIEWS)
 
@@ -177,11 +177,11 @@ internal constructor(private val context: Context, executor: Executor) :
         os.write(ViewCaptureMessage.View.HASHCODE, view.hashCode)
         os.write(
             ViewCaptureMessage.View.VIEW_ID_IID,
-            internViewId(mViewIdProvider.getName(view.id), incrementalState, newInternedStrings)
+            internViewId(mViewIdProvider.getName(view.id), incrementalState, newInternedStrings),
         )
         os.write(
             ViewCaptureMessage.View.CLASS_NAME_IID,
-            internClassName(view.clazz.name, incrementalState, newInternedStrings)
+            internClassName(view.clazz.name, incrementalState, newInternedStrings),
         )
 
         os.write(ViewCaptureMessage.View.LEFT, view.left)
@@ -209,31 +209,31 @@ internal constructor(private val context: Context, executor: Executor) :
     private fun internClassName(
         string: String,
         incrementalState: ViewCaptureDataSource.IncrementalState,
-        newInternedStrings: NewInternedStrings
+        newInternedStrings: NewInternedStrings,
     ): Int {
         return internString(
             string,
             incrementalState.mInternMapClassName,
-            newInternedStrings.classNames
+            newInternedStrings.classNames,
         )
     }
 
     private fun internPackageName(
         string: String,
         incrementalState: ViewCaptureDataSource.IncrementalState,
-        newInternedStrings: NewInternedStrings
+        newInternedStrings: NewInternedStrings,
     ): Int {
         return internString(
             string,
             incrementalState.mInternMapPackageName,
-            newInternedStrings.packageNames
+            newInternedStrings.packageNames,
         )
     }
 
     private fun internViewId(
         string: String,
         incrementalState: ViewCaptureDataSource.IncrementalState,
-        newInternedStrings: NewInternedStrings
+        newInternedStrings: NewInternedStrings,
     ): Int {
         return internString(string, incrementalState.mInternMapViewId, newInternedStrings.viewIds)
     }
@@ -241,19 +241,19 @@ internal constructor(private val context: Context, executor: Executor) :
     private fun internWindowName(
         string: String,
         incrementalState: ViewCaptureDataSource.IncrementalState,
-        newInternedStrings: NewInternedStrings
+        newInternedStrings: NewInternedStrings,
     ): Int {
         return internString(
             string,
             incrementalState.mInternMapWindowName,
-            newInternedStrings.windowNames
+            newInternedStrings.windowNames,
         )
     }
 
     private fun internString(
         string: String,
         internMap: MutableMap<String, Int>,
-        newInternedStrings: MutableList<String>
+        newInternedStrings: MutableList<String>,
     ): Int {
         if (internMap.containsKey(string)) {
             return internMap[string]!!
@@ -271,7 +271,7 @@ internal constructor(private val context: Context, executor: Executor) :
     private fun serializeIncrementalState(
         os: ProtoOutputStream,
         incrementalState: ViewCaptureDataSource.IncrementalState,
-        newInternedStrings: NewInternedStrings
+        newInternedStrings: NewInternedStrings,
     ) {
         var flags = TracePacket.SEQ_NEEDS_INCREMENTAL_STATE
         if (!incrementalState.mHasNotifiedClearedState) {
@@ -285,25 +285,25 @@ internal constructor(private val context: Context, executor: Executor) :
             os,
             InternedData.VIEWCAPTURE_CLASS_NAME,
             incrementalState.mInternMapClassName,
-            newInternedStrings.classNames
+            newInternedStrings.classNames,
         )
         serializeInternMap(
             os,
             InternedData.VIEWCAPTURE_PACKAGE_NAME,
             incrementalState.mInternMapPackageName,
-            newInternedStrings.packageNames
+            newInternedStrings.packageNames,
         )
         serializeInternMap(
             os,
             InternedData.VIEWCAPTURE_VIEW_ID,
             incrementalState.mInternMapViewId,
-            newInternedStrings.viewIds
+            newInternedStrings.viewIds,
         )
         serializeInternMap(
             os,
             InternedData.VIEWCAPTURE_WINDOW_NAME,
             incrementalState.mInternMapWindowName,
-            newInternedStrings.windowNames
+            newInternedStrings.windowNames,
         )
         os.end(token)
     }
@@ -312,7 +312,7 @@ internal constructor(private val context: Context, executor: Executor) :
         os: ProtoOutputStream,
         fieldId: Long,
         map: Map<String, Int>,
-        newInternedStrings: List<String>
+        newInternedStrings: List<String>,
     ) {
         if (newInternedStrings.isEmpty()) {
             return
diff --git a/viewcapturelib/src/com/android/app/viewcapture/SettingsAwareViewCapture.kt b/viewcapturelib/src/com/android/app/viewcapture/SettingsAwareViewCapture.kt
deleted file mode 100644
index 2f2f3f8..0000000
--- a/viewcapturelib/src/com/android/app/viewcapture/SettingsAwareViewCapture.kt
+++ /dev/null
@@ -1,86 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.app.viewcapture
-
-import android.content.Context
-import android.content.pm.LauncherApps
-import android.database.ContentObserver
-import android.os.Handler
-import android.os.ParcelFileDescriptor
-import android.provider.Settings
-import android.util.Log
-import android.window.IDumpCallback
-import androidx.annotation.AnyThread
-import androidx.annotation.VisibleForTesting
-import java.util.concurrent.Executor
-
-private val TAG = SettingsAwareViewCapture::class.java.simpleName
-
-/**
- * ViewCapture that listens to system updates and enables / disables attached ViewCapture
- * WindowListeners accordingly. The Settings toggle is currently controlled by the Winscope
- * developer tile in the System developer options.
- */
-internal class SettingsAwareViewCapture
-internal constructor(private val context: Context, executor: Executor) :
-    ViewCapture(DEFAULT_MEMORY_SIZE, DEFAULT_INIT_POOL_SIZE, executor) {
-    /** Dumps all the active view captures to the wm trace directory via LauncherAppService */
-    private val mDumpCallback: IDumpCallback.Stub = object : IDumpCallback.Stub() {
-        override fun onDump(out: ParcelFileDescriptor) {
-            try {
-                ParcelFileDescriptor.AutoCloseOutputStream(out).use { os -> dumpTo(os, context) }
-            } catch (e: Exception) {
-                Log.e(TAG, "failed to dump data to wm trace", e)
-            }
-        }
-    }
-
-    init {
-        enableOrDisableWindowListeners()
-        mBgExecutor.execute {
-            context.contentResolver.registerContentObserver(
-                    Settings.Global.getUriFor(VIEW_CAPTURE_ENABLED),
-                    false,
-                    object : ContentObserver(Handler()) {
-                        override fun onChange(selfChange: Boolean) {
-                            enableOrDisableWindowListeners()
-                        }
-                    })
-        }
-    }
-
-    @AnyThread
-    private fun enableOrDisableWindowListeners() {
-        mBgExecutor.execute {
-            val isEnabled = Settings.Global.getInt(context.contentResolver, VIEW_CAPTURE_ENABLED,
-                    0) != 0
-            MAIN_EXECUTOR.execute {
-                enableOrDisableWindowListeners(isEnabled)
-            }
-            val launcherApps = context.getSystemService(LauncherApps::class.java)
-            if (isEnabled) {
-                launcherApps?.registerDumpCallback(mDumpCallback)
-            } else {
-                launcherApps?.unRegisterDumpCallback(mDumpCallback)
-            }
-        }
-    }
-
-    companion object {
-        @VisibleForTesting internal const val VIEW_CAPTURE_ENABLED = "view_capture_enabled"
-    }
-}
\ No newline at end of file
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java b/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java
index e6f0c72..32bced0 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java
@@ -61,6 +61,7 @@ import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.ExecutionException;
 import java.util.concurrent.Executor;
 import java.util.concurrent.TimeUnit;
+import java.util.concurrent.atomic.AtomicReference;
 import java.util.function.Consumer;
 import java.util.function.Predicate;
 import java.util.stream.Collectors;
@@ -316,8 +317,10 @@ public abstract class ViewCapture {
 
         private int mFrameIndexBg = -1;
         private boolean mIsFirstFrame = true;
-        private long[] mFrameTimesNanosBg = new long[mMemorySize];
-        private ViewPropertyRef[] mNodesBg = new ViewPropertyRef[mMemorySize];
+        private AtomicReference<long[]> mFrameTimesNanosBg =
+                new AtomicReference<>(new long[mMemorySize]);
+        private AtomicReference<ViewPropertyRef[]> mNodesBg =
+                new AtomicReference<>(new ViewPropertyRef[mMemorySize]);
 
         private boolean mIsActive = true;
         private final Consumer<ViewPropertyRef> mCaptureCallback =
@@ -368,14 +371,25 @@ public abstract class ViewCapture {
         private void copyCleanViewsFromLastFrameBg(ViewPropertyRef start) {
             Trace.beginSection("vc#copyCleanViewsFromLastFrameBg");
 
+            // onTrimMemory() might concurrently modify mFrameTimesNanosBg and mNodesBg (set new
+            // arrays with length = 0). So let's atomically acquire the array references and if any
+            // of the array lengths is 0, then a memory trim has been performed and this method
+            // must do nothing.
+            long[] frameTimesNanosBg = mFrameTimesNanosBg.get();
+            ViewPropertyRef[] nodesBg = mNodesBg.get();
+            if (frameTimesNanosBg.length == 0 || nodesBg.length == 0) {
+                Trace.endSection();
+                return;
+            }
+
             long elapsedRealtimeNanos = start.elapsedRealtimeNanos;
             mFrameIndexBg++;
             if (mFrameIndexBg >= mMemorySize) {
                 mFrameIndexBg = 0;
             }
-            mFrameTimesNanosBg[mFrameIndexBg] = elapsedRealtimeNanos;
+            frameTimesNanosBg[mFrameIndexBg] = elapsedRealtimeNanos;
 
-            ViewPropertyRef recycle = mNodesBg[mFrameIndexBg];
+            ViewPropertyRef recycle = nodesBg[mFrameIndexBg];
 
             ViewPropertyRef resultStart = null;
             ViewPropertyRef resultEnd = null;
@@ -395,7 +409,7 @@ public abstract class ViewCapture {
 
                 ViewPropertyRef copy = null;
                 if (end.childCount < 0) {
-                    copy = findInLastFrame(end.hashCode);
+                    copy = findInLastFrame(nodesBg, end.hashCode);
                     if (copy != null) {
                         copy.transferTo(end);
                     } else {
@@ -442,7 +456,7 @@ public abstract class ViewCapture {
                 }
                 end = end.next;
             }
-            mNodesBg[mFrameIndexBg] = resultStart;
+            nodesBg[mFrameIndexBg] = resultStart;
 
             onCapturedViewPropertiesBg(elapsedRealtimeNanos, name, resultStart);
 
@@ -450,9 +464,9 @@ public abstract class ViewCapture {
         }
 
         @WorkerThread
-        private @Nullable ViewPropertyRef findInLastFrame(int hashCode) {
+        private @Nullable ViewPropertyRef findInLastFrame(ViewPropertyRef[] nodesBg, int hashCode) {
             int lastFrameIndex = (mFrameIndexBg == 0) ? mMemorySize - 1 : mFrameIndexBg - 1;
-            ViewPropertyRef viewPropertyRef = mNodesBg[lastFrameIndex];
+            ViewPropertyRef viewPropertyRef = nodesBg[lastFrameIndex];
             while (viewPropertyRef != null && viewPropertyRef.hashCode != hashCode) {
                 viewPropertyRef = viewPropertyRef.next;
             }
@@ -534,15 +548,18 @@ public abstract class ViewCapture {
 
         @WorkerThread
         private WindowData dumpToProto(ViewIdProvider idProvider, ArrayList<Class> classList) {
+            ViewPropertyRef[] nodesBg = mNodesBg.get();
+            long[] frameTimesNanosBg = mFrameTimesNanosBg.get();
+
             WindowData.Builder builder = WindowData.newBuilder().setTitle(name);
-            int size = (mNodesBg[mMemorySize - 1] == null) ? mFrameIndexBg + 1 : mMemorySize;
+            int size = (nodesBg[mMemorySize - 1] == null) ? mFrameIndexBg + 1 : mMemorySize;
             for (int i = size - 1; i >= 0; i--) {
                 int index = (mMemorySize + mFrameIndexBg - i) % mMemorySize;
                 ViewNode.Builder nodeBuilder = ViewNode.newBuilder();
-                mNodesBg[index].toProto(idProvider, classList, nodeBuilder);
+                nodesBg[index].toProto(idProvider, classList, nodeBuilder);
                 FrameData.Builder frameDataBuilder = FrameData.newBuilder()
                         .setNode(nodeBuilder)
-                        .setTimestamp(mFrameTimesNanosBg[index]);
+                        .setTimestamp(frameTimesNanosBg[index]);
                 builder.addFrameData(frameDataBuilder);
             }
             return builder.build();
@@ -580,8 +597,8 @@ public abstract class ViewCapture {
         @Override
         public void onTrimMemory(int level) {
             if (level >= ComponentCallbacks2.TRIM_MEMORY_BACKGROUND) {
-                mNodesBg = new ViewPropertyRef[0];
-                mFrameTimesNanosBg = new long[0];
+                mNodesBg.set(new ViewPropertyRef[0]);
+                mFrameTimesNanosBg.set(new long[0]);
                 if (mRoot != null && mRoot.getContext() != null) {
                     mRoot.getContext().unregisterComponentCallbacks(this);
                 }
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt
index 416d441..578c89c 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt
@@ -18,12 +18,11 @@ package com.android.app.viewcapture
 
 import android.content.Context
 import android.media.permission.SafeCloseable
-import android.os.IBinder
 import android.view.View
 import android.view.ViewGroup
 import android.view.Window
 import android.view.WindowManager
-import android.view.WindowManagerImpl
+import android.view.WindowManagerWrapper
 
 /**
  * [WindowManager] implementation to enable view tracing. Adds [ViewCapture] to associated window
@@ -32,9 +31,8 @@ import android.view.WindowManagerImpl
  */
 internal class ViewCaptureAwareWindowManager(
     private val context: Context,
-    private val parent: Window? = null,
-    private val windowContextToken: IBinder? = null,
-) : WindowManagerImpl(context, parent, windowContextToken) {
+    private val base: WindowManager,
+) : WindowManagerWrapper(base) {
 
     private var viewCaptureCloseableMap: MutableMap<View, SafeCloseable> = mutableMapOf()
 
@@ -55,6 +53,10 @@ internal class ViewCaptureAwareWindowManager(
         super.removeViewImmediate(view)
     }
 
+    override fun createLocalWindowManager(parentWindow: Window): WindowManager {
+        return ViewCaptureAwareWindowManager(context, base.createLocalWindowManager(parentWindow))
+    }
+
     private fun getViewName(view: View) = "." + view.javaClass.name
 
     private fun removeViewFromCloseableMap(view: View?) {
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManagerFactory.kt b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManagerFactory.kt
index d471f27..1125d4d 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManagerFactory.kt
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManagerFactory.kt
@@ -17,16 +17,13 @@
 package com.android.app.viewcapture
 
 import android.content.Context
-import android.os.IBinder
 import android.os.Trace
 import android.os.Trace.TRACE_TAG_APP
-import android.view.Window
 import android.view.WindowManager
 import java.lang.ref.WeakReference
 import java.util.Collections
 import java.util.WeakHashMap
 
-
 /** Factory to create [Context] specific instances of [ViewCaptureAwareWindowManager]. */
 object ViewCaptureAwareWindowManagerFactory {
 
@@ -43,19 +40,22 @@ object ViewCaptureAwareWindowManagerFactory {
      * no instance is cached; it creates, caches and returns a new instance.
      */
     @JvmStatic
-    fun getInstance(
-        context: Context,
-        parent: Window? = null,
-        windowContextToken: IBinder? = null,
-    ): WindowManager {
-        Trace.traceCounter(TRACE_TAG_APP,
-            "ViewCaptureAwareWindowManagerFactory#instanceMap.size", instanceMap.size)
+    fun getInstance(context: Context): WindowManager {
+        Trace.traceCounter(
+            TRACE_TAG_APP,
+            "ViewCaptureAwareWindowManagerFactory#instanceMap.size",
+            instanceMap.size,
+        )
 
         val cachedWindowManager = instanceMap[context]?.get()
         if (cachedWindowManager != null) {
             return cachedWindowManager
         } else {
-            val windowManager = ViewCaptureAwareWindowManager(context, parent, windowContextToken)
+            val windowManager =
+                ViewCaptureAwareWindowManager(
+                    context,
+                    context.getSystemService(WindowManager::class.java),
+                )
             instanceMap[context] = WeakReference(windowManager)
             return windowManager
         }
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt
index 2575dbd..b0ec569 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt
@@ -18,7 +18,6 @@ package com.android.app.viewcapture
 
 import android.content.Context
 import android.os.Process
-import android.tracing.Flags
 import android.util.Log
 
 /**
@@ -31,31 +30,18 @@ object ViewCaptureFactory {
     private lateinit var appContext: Context
 
     private fun createInstance(): ViewCapture {
-        return when {
-            !android.os.Build.IS_DEBUGGABLE -> {
-                Log.i(TAG, "instantiating ${NoOpViewCapture::class.java.simpleName}")
-                NoOpViewCapture()
-            }
-            !Flags.perfettoViewCaptureTracing() -> {
-                Log.i(TAG, "instantiating ${SettingsAwareViewCapture::class.java.simpleName}")
-                SettingsAwareViewCapture(
-                    appContext,
-                    ViewCapture.createAndStartNewLooperExecutor(
-                        "SAViewCapture",
-                        Process.THREAD_PRIORITY_FOREGROUND,
-                    ),
-                )
-            }
-            else -> {
-                Log.i(TAG, "instantiating ${PerfettoViewCapture::class.java.simpleName}")
-                PerfettoViewCapture(
-                    appContext,
-                    ViewCapture.createAndStartNewLooperExecutor(
-                        "PerfettoViewCapture",
-                        Process.THREAD_PRIORITY_FOREGROUND,
-                    ),
-                )
-            }
+        return if (!android.os.Build.IS_DEBUGGABLE) {
+            Log.i(TAG, "instantiating ${NoOpViewCapture::class.java.simpleName}")
+            NoOpViewCapture()
+        } else {
+            Log.i(TAG, "instantiating ${PerfettoViewCapture::class.java.simpleName}")
+            PerfettoViewCapture(
+                appContext,
+                ViewCapture.createAndStartNewLooperExecutor(
+                    "PerfettoViewCapture",
+                    Process.THREAD_PRIORITY_FOREGROUND,
+                ),
+            )
         }
     }
 
diff --git a/viewcapturelib/tests/com/android/app/viewcapture/SettingsAwareViewCaptureTest.kt b/viewcapturelib/tests/com/android/app/viewcapture/SettingsAwareViewCaptureTest.kt
deleted file mode 100644
index 5654f7f..0000000
--- a/viewcapturelib/tests/com/android/app/viewcapture/SettingsAwareViewCaptureTest.kt
+++ /dev/null
@@ -1,100 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.app.viewcapture
-
-import android.Manifest
-import android.content.Context
-import android.content.Intent
-import android.media.permission.SafeCloseable
-import android.provider.Settings
-import android.testing.AndroidTestingRunner
-import android.view.Choreographer
-import android.view.View
-import androidx.test.ext.junit.rules.ActivityScenarioRule
-import androidx.test.filters.SmallTest
-import androidx.test.platform.app.InstrumentationRegistry
-import androidx.test.rule.GrantPermissionRule
-import com.android.app.viewcapture.SettingsAwareViewCapture.Companion.VIEW_CAPTURE_ENABLED
-import com.android.app.viewcapture.ViewCapture.MAIN_EXECUTOR
-import junit.framework.Assert.assertEquals
-import org.junit.Rule
-import org.junit.Test
-import org.junit.runner.RunWith
-
-@SmallTest
-@RunWith(AndroidTestingRunner::class)
-class SettingsAwareViewCaptureTest {
-    private val context: Context = InstrumentationRegistry.getInstrumentation().context
-    private val activityIntent = Intent(context, TestActivity::class.java)
-
-    @get:Rule val activityScenarioRule = ActivityScenarioRule<TestActivity>(activityIntent)
-    @get:Rule val grantPermissionRule =
-        GrantPermissionRule.grant(Manifest.permission.WRITE_SECURE_SETTINGS)
-
-    @Test
-    fun do_not_capture_view_hierarchies_if_setting_is_disabled() {
-        Settings.Global.putInt(context.contentResolver, VIEW_CAPTURE_ENABLED, 0)
-
-        activityScenarioRule.scenario.onActivity { activity ->
-            val viewCapture: ViewCapture = SettingsAwareViewCapture(context, MAIN_EXECUTOR)
-            val rootView: View = activity.requireViewById(android.R.id.content)
-
-            val closeable: SafeCloseable = viewCapture.startCapture(rootView, "rootViewId")
-            Choreographer.getInstance().postFrameCallback {
-                rootView.viewTreeObserver.dispatchOnDraw()
-
-                assertEquals(
-                    0,
-                    viewCapture
-                        .getDumpTask(activity.requireViewById(android.R.id.content))
-                        .get()
-                        .get()
-                        .frameDataList
-                        .size
-                )
-                closeable.close()
-            }
-        }
-    }
-
-    @Test
-    fun capture_view_hierarchies_if_setting_is_enabled() {
-        Settings.Global.putInt(context.contentResolver, VIEW_CAPTURE_ENABLED, 1)
-
-        activityScenarioRule.scenario.onActivity { activity ->
-            val viewCapture: ViewCapture = SettingsAwareViewCapture(context, MAIN_EXECUTOR)
-            val rootView: View = activity.requireViewById(android.R.id.content)
-
-            val closeable: SafeCloseable = viewCapture.startCapture(rootView, "rootViewId")
-            Choreographer.getInstance().postFrameCallback {
-                rootView.viewTreeObserver.dispatchOnDraw()
-
-                assertEquals(
-                    1,
-                    viewCapture
-                        .getDumpTask(activity.requireViewById(android.R.id.content))
-                        .get()
-                        .get()
-                        .frameDataList
-                        .size
-                )
-
-                closeable.close()
-            }
-        }
-    }
-}
diff --git a/viewcapturelib/tests/com/android/app/viewcapture/ViewCaptureAwareWindowManagerTest.kt b/viewcapturelib/tests/com/android/app/viewcapture/ViewCaptureAwareWindowManagerTest.kt
index 9e3175d..378f355 100644
--- a/viewcapturelib/tests/com/android/app/viewcapture/ViewCaptureAwareWindowManagerTest.kt
+++ b/viewcapturelib/tests/com/android/app/viewcapture/ViewCaptureAwareWindowManagerTest.kt
@@ -18,11 +18,23 @@ package com.android.app.viewcapture
 
 import android.content.Context
 import android.content.Intent
+import android.hardware.display.DisplayManager
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
 import android.testing.AndroidTestingRunner
+import android.view.Display.DEFAULT_DISPLAY
+import android.view.View
 import android.view.WindowManager
+import android.view.WindowManager.LayoutParams.TYPE_APPLICATION
+import android.view.WindowManager.LayoutParams.TYPE_APPLICATION_ATTACHED_DIALOG
+import android.window.WindowContext
 import androidx.test.ext.junit.rules.ActivityScenarioRule
 import androidx.test.filters.SmallTest
 import androidx.test.platform.app.InstrumentationRegistry
+import com.android.window.flags.Flags
+import com.google.common.truth.Truth.assertWithMessage
+import java.util.concurrent.CountDownLatch
+import java.util.concurrent.TimeUnit
 import org.junit.Assert.assertTrue
 import org.junit.Rule
 import org.junit.Test
@@ -38,10 +50,16 @@ class ViewCaptureAwareWindowManagerTest {
 
     @get:Rule val activityScenarioRule = ActivityScenarioRule<TestActivity>(activityIntent)
 
+    @get:Rule val mSetFlagsRule: SetFlagsRule = SetFlagsRule()
+
     @Test
     fun testAddView_verifyStartCaptureCall() {
         activityScenarioRule.scenario.onActivity { activity ->
-            mViewCaptureAwareWindowManager = ViewCaptureAwareWindowManager(mContext)
+            mViewCaptureAwareWindowManager =
+                ViewCaptureAwareWindowManager(
+                    mContext,
+                    mContext.getSystemService(WindowManager::class.java),
+                )
 
             val activityDecorView = activity.window.decorView
             // removing view since it is already added to view hierarchy on declaration
@@ -55,4 +73,71 @@ class ViewCaptureAwareWindowManagerTest {
             assertTrue(viewCapture.mIsStarted)
         }
     }
+
+    @EnableFlags(Flags.FLAG_ENABLE_WINDOW_CONTEXT_OVERRIDE_TYPE)
+    @Test
+    fun useWithWindowContext_attachWindow_attachToViewCaptureAwareWm() {
+        val windowContext =
+            mContext.createWindowContext(
+                mContext.getSystemService(DisplayManager::class.java).getDisplay(DEFAULT_DISPLAY),
+                TYPE_APPLICATION,
+                null, /* options */
+            ) as WindowContext
+
+        // Obtain ViewCaptureAwareWindowManager with WindowContext.
+        mViewCaptureAwareWindowManager =
+            ViewCaptureAwareWindowManagerFactory.getInstance(windowContext)
+                as ViewCaptureAwareWindowManager
+
+        // Attach to an Activity so that we can add an application parent window.
+        val params = WindowManager.LayoutParams()
+        activityScenarioRule.scenario.onActivity { activity ->
+            params.token = activity.activityToken
+        }
+
+        // Create and attach an application window, and listen to OnAttachStateChangeListener.
+        // We need to know when the parent window is attached and then we can add the attached
+        // dialog.
+        val listener = AttachStateListener()
+        val parentWindow = View(windowContext)
+        parentWindow.addOnAttachStateChangeListener(listener)
+        windowContext.attachWindow(parentWindow)
+
+        // Attach the parent window to ViewCaptureAwareWm
+        activityScenarioRule.scenario.onActivity {
+            mViewCaptureAwareWindowManager.addView(parentWindow, params)
+        }
+
+        // Wait for parent window to be attached.
+        listener.mLatch.await(TIMEOUT_IN_SECONDS, TimeUnit.SECONDS)
+        assertWithMessage("The WindowContext token must be attached.")
+            .that(params.mWindowContextToken)
+            .isEqualTo(windowContext.windowContextToken)
+
+        val subWindow = View(windowContext)
+        val subParams = WindowManager.LayoutParams(TYPE_APPLICATION_ATTACHED_DIALOG)
+
+        // Attach the sub-window
+        activityScenarioRule.scenario.onActivity {
+            mViewCaptureAwareWindowManager.addView(subWindow, subParams)
+        }
+
+        assertWithMessage("The sub-window must be attached to the parent window")
+            .that(subParams.token)
+            .isEqualTo(parentWindow.windowToken)
+    }
+
+    private class AttachStateListener : View.OnAttachStateChangeListener {
+        val mLatch: CountDownLatch = CountDownLatch(1)
+
+        override fun onViewAttachedToWindow(v: View) {
+            mLatch.countDown()
+        }
+
+        override fun onViewDetachedFromWindow(v: View) {}
+    }
+
+    companion object {
+        private const val TIMEOUT_IN_SECONDS = 4L
+    }
 }
diff --git a/weathereffects/debug/assets/test-background3.old.png b/weathereffects/debug/assets/test-background3.old.png
new file mode 100644
index 0000000..e72c535
Binary files /dev/null and b/weathereffects/debug/assets/test-background3.old.png differ
diff --git a/weathereffects/debug/assets/test-foreground3.old.png b/weathereffects/debug/assets/test-foreground3.old.png
new file mode 100644
index 0000000..2bbd84b
Binary files /dev/null and b/weathereffects/debug/assets/test-foreground3.old.png differ
diff --git a/weathereffects/debug/res/layout/debug_activity.xml b/weathereffects/debug/res/layout/debug_activity.xml
index 13b6349..f72f978 100644
--- a/weathereffects/debug/res/layout/debug_activity.xml
+++ b/weathereffects/debug/res/layout/debug_activity.xml
@@ -50,11 +50,21 @@
             android:text="@string/button_rain"
             android:layout_width="wrap_content"
             android:layout_height="wrap_content"
-            app:layout_constraintBottom_toTopOf="@id/fog"
+            app:layout_constraintBottom_toTopOf="@id/clouds"
             app:layout_constraintEnd_toEndOf="parent"
             android:layout_marginBottom="10dp"
             android:layout_marginEnd="20dp" />
 
+        <Button
+            android:id="@+id/clouds"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginEnd="20dp"
+            android:layout_marginBottom="10dp"
+            android:text="@string/button_clouds"
+            app:layout_constraintBottom_toTopOf="@id/fog"
+            app:layout_constraintEnd_toEndOf="parent" />
+
         <Button
             android:id="@+id/fog"
             android:text="@string/button_fog"
diff --git a/weathereffects/debug/res/values/strings.xml b/weathereffects/debug/res/values/strings.xml
index 31ba2b0..67cf513 100644
--- a/weathereffects/debug/res/values/strings.xml
+++ b/weathereffects/debug/res/values/strings.xml
@@ -21,6 +21,7 @@
     <string name="set_wallpaper" translatable="false">Set Wallpaper</string>
     <string name="button_rain" translatable="false">Rain</string>
     <string name="button_fog" translatable="false">Fog</string>
+    <string name="button_clouds" translatable="false">Clouds</string>
     <string name="button_snow" translatable="false">Snow</string>
     <string name="button_sunny" translatable="false">Sun</string>
     <string name="button_clear" translatable="false">Clear Weather</string>
diff --git a/weathereffects/debug/src/com/google/android/wallpaper/weathereffects/WallpaperEffectsDebugActivity.kt b/weathereffects/debug/src/com/google/android/wallpaper/weathereffects/WallpaperEffectsDebugActivity.kt
index 2f8687a..e29f042 100644
--- a/weathereffects/debug/src/com/google/android/wallpaper/weathereffects/WallpaperEffectsDebugActivity.kt
+++ b/weathereffects/debug/src/com/google/android/wallpaper/weathereffects/WallpaperEffectsDebugActivity.kt
@@ -41,24 +41,18 @@ import com.google.android.wallpaper.weathereffects.data.repository.WallpaperFile
 import com.google.android.wallpaper.weathereffects.domain.WeatherEffectsInteractor
 import com.google.android.wallpaper.weathereffects.provider.WallpaperInfoContract
 import com.google.android.wallpaper.weathereffects.shared.model.WallpaperFileModel
+import java.io.File
+import javax.inject.Inject
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.delay
 import kotlinx.coroutines.launch
-import java.io.File
-import javax.inject.Inject
 
 class WallpaperEffectsDebugActivity : TorusViewerActivity() {
 
-    @Inject
-    @MainScope
-    lateinit var mainScope: CoroutineScope
-    @Inject
-    @BackgroundScope
-    lateinit var bgScope: CoroutineScope
-    @Inject
-    lateinit var context: Context
-    @Inject
-    lateinit var interactor: WeatherEffectsInteractor
+    @Inject @MainScope lateinit var mainScope: CoroutineScope
+    @Inject @BackgroundScope lateinit var bgScope: CoroutineScope
+    @Inject lateinit var context: Context
+    @Inject lateinit var interactor: WeatherEffectsInteractor
 
     private lateinit var rootView: FrameLayout
     private lateinit var surfaceView: SurfaceView
@@ -73,13 +67,14 @@ class WallpaperEffectsDebugActivity : TorusViewerActivity() {
 
     override fun getWallpaperEngine(context: Context, surfaceView: SurfaceView): TorusEngine {
         this.surfaceView = surfaceView
-        val engine = WeatherEngine(
-            surfaceView.holder,
-            mainScope,
-            interactor,
-            context,
-            isDebugActivity = true
-        )
+        val engine =
+            WeatherEngine(
+                surfaceView.holder,
+                mainScope,
+                interactor,
+                context,
+                isDebugActivity = true,
+            )
         this.engine = engine
         return engine
     }
@@ -107,6 +102,11 @@ class WallpaperEffectsDebugActivity : TorusViewerActivity() {
             updateWallpaper()
             setDebugText(context.getString(R.string.generating))
         }
+        rootView.requireViewById<Button>(R.id.clouds).setOnClickListener {
+            weatherEffect = WallpaperInfoContract.WeatherEffect.CLOUDS
+            updateWallpaper()
+            setDebugText(context.getString(R.string.generating))
+        }
         rootView.requireViewById<Button>(R.id.snow).setOnClickListener {
             weatherEffect = WallpaperInfoContract.WeatherEffect.SNOW
             updateWallpaper()
@@ -133,46 +133,55 @@ class WallpaperEffectsDebugActivity : TorusViewerActivity() {
             i.action = WallpaperManager.ACTION_CHANGE_LIVE_WALLPAPER
             i.putExtra(
                 WallpaperManager.EXTRA_LIVE_WALLPAPER_COMPONENT,
-                ComponentName(this, WeatherWallpaperService::class.java)
+                ComponentName(this, WeatherWallpaperService::class.java),
             )
             this.startActivityForResult(i, SET_WALLPAPER_REQUEST_CODE)
             saveWallpaper()
         }
 
-        rootView.requireViewById<FrameLayout>(R.id.wallpaper_layout)
-            .setOnTouchListener { view, event ->
-                when (event?.action) {
-                    MotionEvent.ACTION_DOWN -> {
-                        if (rootView.requireViewById<ConstraintLayout>(R.id.buttons).visibility
-                            == View.GONE) {
-                            showButtons()
-                        } else {
-                            hideButtons()
-                        }
+        rootView.requireViewById<FrameLayout>(R.id.wallpaper_layout).setOnTouchListener {
+            view,
+            event ->
+            when (event?.action) {
+                MotionEvent.ACTION_DOWN -> {
+                    if (
+                        rootView.requireViewById<ConstraintLayout>(R.id.buttons).visibility ==
+                            View.GONE
+                    ) {
+                        showButtons()
+                    } else {
+                        hideButtons()
                     }
                 }
-
-                view.onTouchEvent(event)
             }
 
+            view.onTouchEvent(event)
+        }
+
         setDebugText()
         val seekBar = rootView.requireViewById<SeekBar>(R.id.seekBar)
-        seekBar.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
-            override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
-                // Convert progress to a value between 0 and 1
-                val value = progress.toFloat() / 100f
-                engine?.setTargetIntensity(value)
-                intensity = value
-            }
+        seekBar.setOnSeekBarChangeListener(
+            object : SeekBar.OnSeekBarChangeListener {
+                override fun onProgressChanged(
+                    seekBar: SeekBar?,
+                    progress: Int,
+                    fromUser: Boolean,
+                ) {
+                    // Convert progress to a value between 0 and 1
+                    val value = progress.toFloat() / 100f
+                    engine?.setTargetIntensity(value)
+                    intensity = value
+                }
 
-            override fun onStartTrackingTouch(seekBar: SeekBar?) {
-                hideButtons()
-            }
+                override fun onStartTrackingTouch(seekBar: SeekBar?) {
+                    hideButtons()
+                }
 
-            override fun onStopTrackingTouch(seekBar: SeekBar?) {
-                showButtons()
+                override fun onStopTrackingTouch(seekBar: SeekBar?) {
+                    showButtons()
+                }
             }
-        })
+        )
         intensity = seekBar.progress.toFloat() / 100f
 
         // This avoids that the initial state after installing is showing a black screen.
@@ -186,21 +195,25 @@ class WallpaperEffectsDebugActivity : TorusViewerActivity() {
             clear()
             addAll(
                 listOf(
-                    /* TODO(b/300991599): Add debug assets. */
-                    FOREGROUND_IMAGE_1,
-                    FOREGROUND_IMAGE_2,
-                    FOREGROUND_IMAGE_3,
-                ).map { getFileFromAssets(it).absolutePath })
+                        /* TODO(b/300991599): Add debug assets. */
+                        FOREGROUND_IMAGE_1,
+                        FOREGROUND_IMAGE_2,
+                        FOREGROUND_IMAGE_3,
+                    )
+                    .map { getFileFromAssets(it).absolutePath }
+            )
         }
         bgCachedAssetPaths.apply {
             clear()
             addAll(
                 listOf(
-                    /* TODO(b/300991599): Add debug assets. */
-                    BACKGROUND_IMAGE_1,
-                    BACKGROUND_IMAGE_2,
-                    BACKGROUND_IMAGE_3,
-                ).map { getFileFromAssets(it).absolutePath })
+                        /* TODO(b/300991599): Add debug assets. */
+                        BACKGROUND_IMAGE_1,
+                        BACKGROUND_IMAGE_2,
+                        BACKGROUND_IMAGE_3,
+                    )
+                    .map { getFileFromAssets(it).absolutePath }
+            )
         }
     }
 
@@ -208,9 +221,7 @@ class WallpaperEffectsDebugActivity : TorusViewerActivity() {
         return File(context.cacheDir, fileName).also {
             if (!it.exists()) {
                 it.outputStream().use { cache ->
-                    context.assets.open(fileName).use { inputStream ->
-                        inputStream.copyTo(cache)
-                    }
+                    context.assets.open(fileName).use { inputStream -> inputStream.copyTo(cache) }
                 }
             }
         }
@@ -220,25 +231,17 @@ class WallpaperEffectsDebugActivity : TorusViewerActivity() {
         mainScope.launch {
             val fgPath = fgCachedAssetPaths[assetIndex]
             val bgPath = bgCachedAssetPaths[assetIndex]
-            interactor.updateWallpaper(
-                WallpaperFileModel(
-                    fgPath,
-                    bgPath,
-                    weatherEffect,
-                )
-            )
+            interactor.updateWallpaper(WallpaperFileModel(fgPath, bgPath, weatherEffect))
             engine?.setTargetIntensity(intensity)
             setDebugText(
                 "Wallpaper updated successfully.\n* Weather: " +
-                        "$weatherEffect\n* Foreground: $fgPath\n* Background: $bgPath"
+                    "$weatherEffect\n* Foreground: $fgPath\n* Background: $bgPath"
             )
         }
     }
 
     private fun saveWallpaper() {
-        bgScope.launch {
-            interactor.saveWallpaper()
-        }
+        bgScope.launch { interactor.saveWallpaper() }
     }
 
     private fun setDebugText(text: String? = null) {
@@ -265,14 +268,17 @@ class WallpaperEffectsDebugActivity : TorusViewerActivity() {
 
     private fun hideButtons() {
         val buttons = rootView.requireViewById<ConstraintLayout>(R.id.buttons)
-        buttons.animate()
+        buttons
+            .animate()
             .alpha(0f)
             .setDuration(400)
-            .setListener(object : AnimatorListenerAdapter() {
-                override fun onAnimationEnd(animation: Animator) {
-                    buttons.visibility = View.GONE
+            .setListener(
+                object : AnimatorListenerAdapter() {
+                    override fun onAnimationEnd(animation: Animator) {
+                        buttons.visibility = View.GONE
+                    }
                 }
-            })
+            )
     }
 
     private companion object {
diff --git a/weathereffects/graphics/assets/shaders/clouds_effect.agsl b/weathereffects/graphics/assets/shaders/clouds_effect.agsl
new file mode 100644
index 0000000..ed93c47
--- /dev/null
+++ b/weathereffects/graphics/assets/shaders/clouds_effect.agsl
@@ -0,0 +1,121 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+uniform shader foreground;
+uniform shader background;
+uniform shader fog;
+uniform shader clouds;
+uniform half2 fogSize;
+uniform half2 cloudsSize;
+uniform half4 time;
+uniform half screenAspectRatio;
+uniform half2 screenSize;
+uniform half pixelDensity;
+uniform half intensity;
+uniform mat3 transformMatrixBitmap;
+uniform mat3 transformMatrixWeather;
+
+#include "shaders/constants.agsl"
+#include "shaders/utils.agsl"
+#include "shaders/simplex2d.agsl"
+
+vec3 drawGrid(vec3 color, float x, float y) {
+    if (x < 0.025) {
+        for(float i = 0.; i < 30.; i++) {
+            float iFrag = i / 10.;
+            if (y > iFrag - 0.005 && y < iFrag + 0.005) {
+                if (i == 0.) {
+                    color.rgb = vec3(1.);
+                } else if (mod(iFrag, 1.) == 0.) {
+                    color.g = 1.;
+                    color.rb = vec2(0.);
+                } else {
+                    color.r = 1.;
+                    color.gb = vec2(0.);
+                }
+
+            }
+        }
+    }
+    return color;
+}
+
+vec4 drawClouds(vec2 uv, float dither1, float dither2, vec2 time1, vec2 time2, float far) {
+    vec4 fogTexture = fog.eval(
+        0.75 * fogSize * (uv + dither1) +
+        // Moves UV based on time.
+        vec2(time1 * 4.5));
+
+    vec4 cloudsTexture = clouds.eval(
+        0.375 * cloudsSize * (uv + dither2) +
+        // Moves UV based on time.
+        vec2(time2 * 5.5));
+
+    // Makes them more heavy at the bottom, and rounded at the top.
+    float generalCloudshape = smoothstep(
+        0,
+        0.4,
+        uv.y - 0.1 * sin(10. * uv.x + time1.x * 3.5 / fogSize.x));
+    // The smoothstep limits define the variation between clearings and density of clouds.
+    float cloudsShape = smoothstep(
+        0.1,
+        0.4,
+        0.5 * generalCloudshape * cloudsTexture.b +
+        // Makes the general outline of the clouds, adding variation
+        cloudsTexture.g * fogTexture.g -
+        (0.8 - intensity));
+
+    const vec3 shadowColor = vec3(0.3, 0.3, 0.37);
+    const vec3 highlightColor = vec3(0.95, 0.95, 0.99);
+    const vec3 lightBlueGreyColor = vec3(0.6, 0.6, 0.65);
+    // Fade the clouds at the bottom.
+    // adds some color texture to the clouds.
+    vec3 color = mix(shadowColor, highlightColor, cloudsShape);
+    color = mix(shadowColor, color, 0.75 * fogTexture.b);
+    color = mix(shadowColor, color, far);
+    vec3 colorScattered = mix(lightBlueGreyColor, highlightColor, cloudsShape);
+    colorScattered = mix(lightBlueGreyColor, colorScattered, 0.75 * fogTexture.b);
+    colorScattered = mix(lightBlueGreyColor, colorScattered, far);
+
+    color = mix(colorScattered, color, smoothstep(0.6, 0.9, intensity));
+    cloudsShape *= smoothstep(0.7, 0.5, uv.y);
+    return vec4(color, cloudsShape);
+}
+
+vec4 main(float2 fragCoord) {
+    float2 adjustedCoord = transformPoint(transformMatrixBitmap, fragCoord);
+    float2 uv = transformPoint(transformMatrixWeather, fragCoord) / screenSize;
+    uv.y /= screenAspectRatio;
+
+    vec2 timeForeground = vec2(time.x, time.y);
+    vec2 timeBackground = vec2(time.z, time.w);
+
+    vec4 fgd = foreground.eval(adjustedCoord);
+    vec4 bgd = background.eval(adjustedCoord);
+
+    float dither1 = triangleNoise((fragCoord) * pixelDensity) * 0.006;
+    float dither2 = triangleNoise((fragCoord) * pixelDensity) * 0.006;
+    // set background color as the starting layer.
+    vec4 color = bgd;
+    vec2 offset = vec2(0.4, 0.);
+
+    vec4 clouds = drawClouds(1.5 * (uv - offset) - 0.25, dither1, dither2, 612 + timeBackground * 0.647, 323 + timeForeground * 0.687, 0.45);
+    color.rgb = normalBlendNotPremultiplied(color.rgb, clouds.rgb, clouds.a * 0.8);
+    clouds = drawClouds(uv + 0.2, dither1, dither2, timeBackground, timeForeground, 1.);
+    color.rgb = normalBlendNotPremultiplied(color.rgb, clouds.rgb, clouds.a);
+    color.rgb = normalBlend(color.rgb, fgd.rgb, fgd.a);
+    return color;
+}
\ No newline at end of file
diff --git a/weathereffects/graphics/assets/shaders/snow.agsl b/weathereffects/graphics/assets/shaders/snow.agsl
index b62ccc6..6a31701 100644
--- a/weathereffects/graphics/assets/shaders/snow.agsl
+++ b/weathereffects/graphics/assets/shaders/snow.agsl
@@ -19,15 +19,12 @@ struct Snow {
     highp vec2 cellUv;
 };
 
-const mat2 rot45 = mat2(
-    0.7071067812, 0.7071067812, // First column.
-    -0.7071067812, 0.7071067812 // second column.
-);
+const vec2 snowFlakeShape = vec2(0.28, 0.26);
+// decreasedFactor should match minDescreasedFactor * 2, minDescreasedFactor is defined in snow_flake_samples.agsl
+const float decreasedFactor = 1.0 / 0.28;
 
 uniform half intensity;
-
-const float farthestSnowLayerWiggleSpeed = 2.18;
-const float closestSnowLayerWiggleSpeed = 0.9;
+uniform half snowFlakeSamplesSize;
 
 /**
  * Generates snow flakes.
@@ -53,18 +50,14 @@ Snow generateSnow(
     in float minLayerIndex,
     in float maxLayerIndex
 ) {
-    // Normalize the layer index. 0 is closest, 1 is farthest.
     half normalizedLayerIndex = map(layerIndex, minLayerIndex, maxLayerIndex, 0, 1);
-
     /* Grid. */
     // Increase the last number to make each layer more separate from the previous one.
-    float depth = 0.65 + layerIndex * 0.555;
+    float depth = 0.65 + layerIndex * 0.755;
     float speedAdj = 1. + layerIndex * 0.225;
     float layerR = idGenerator(layerIndex);
     snowGridSize *= depth;
     time += layerR * 58.3;
-    // Number of rows and columns (each one is a cell, a drop).
-    float cellAspectRatio = snowGridSize.x / snowGridSize.y;
     // Aspect ratio impacts visible cells.
     uv.y /= screenAspectRatio;
     // Skew uv.x so it goes to left or right
@@ -81,60 +74,34 @@ Snow generateSnow(
     // Have time affect the position of each column as well.
     gridUv.y += columnId * 2.6 + time * 0.19 * (1 - columnId);
 
-    /* Cell. */
-    // Get the cell ID based on the grid position. Value from 0 to 1.
-    float cellId = idGenerator(floor(gridUv));
-    // For each cell, we set the internal UV from -0.5 (left, bottom) to 0.5 (right, top).
+    // Calclulate the grid this pixel belonging to, and also the offset in the cell.
+    vec2 gridIdx = floor(gridUv);
     vec2 cellUv = fract(gridUv) - 0.5;
     cellUv.y *= -1.;
-
-   /*
-    * Disable snow flakes with some probabilty. This is done by 1) assigning a random intensity
-    * value to the cell 2) then compare it with the given intensity.
-    */
-    half cellIntensity = idGenerator(floor(vec2(cellId * 856.16, 272.2)));
-    if (cellIntensity < 1. - intensity) {
-        // Remove snow flakes by seeting flake mask to 0.
+    // The bigger the decreasedFactor, the smaller the snow flake.
+    vec2 snowFlakePos = vec2(cellUv.x, cellUv.y * (snowGridSize.x / snowGridSize.y - 1.0 / snowGridSize.y) + uv.y - 0.5 / screenAspectRatio) * decreasedFactor;
+    if (abs(snowFlakePos.y) > 0.5 || abs(snowFlakePos.x) > 0.5 ) {
         return Snow(/* flakeMask= */ 0, cellUv);
     }
+    vec4 color = snowFlakeSamples.eval(snowFlakeSamplesSize * (gridIdx - 0.5 + snowFlakePos));
 
-    /* Cell-id-based variations. */
-    // 0 = snow flake invisible, 1 = snow flake visible.
+    float baseMask = color.r;
+    half cellIntensity = color.g;
+    float cellId = color.b;
+    if (cellIntensity <= 1. - intensity) {
+        // Remove snow flakes by seting flake mask to 0.
+        return Snow(/* flakeMask= */ 0, cellUv);
+    }
     float visibilityFactor = smoothstep(
         cellIntensity,
         max(cellIntensity - (0.02 + 0.18 * intensity), 0.0),
         1 - intensity);
-    // Adjust the size of each snow flake (higher is smaller) based on cell ID.
-    float decreaseFactor = 2.0 + map(cellId, 0., 1., -0.1, 2.8) + 5. * (1 - visibilityFactor);
-    // Adjust the opacity of the particle based on the cell id and distance from the camera.
     float farLayerFadeOut = map(normalizedLayerIndex, 0.7, 1, 1, 0.4);
     float closeLayerFadeOut = map(normalizedLayerIndex, 0, 0.2, 0.6, 1);
     float opacityVariation =
-        (1. - 0.9 * cellId) *
-        visibilityFactor *
-        closeLayerFadeOut *
-        farLayerFadeOut;
-
-    /* Cell snow flake. */
-    // Calculate snow flake.
-    vec2 snowFlakeShape = vec2(0.28, 0.26);
-    vec2 snowFlakePos = vec2(cellUv.x, cellUv.y * cellAspectRatio);
-    snowFlakePos -= vec2(
-            0.,
-            (uv.y - 0.5 / screenAspectRatio)  - cellUv.y / snowGridSize.y
-        ) * screenAspectRatio;
-    snowFlakePos *= snowFlakeShape * decreaseFactor;
-    vec2 snowFlakeShapeVariation = vec2(0.055) * // max variation
-        vec2((cellId * 2. - 1.), // random A based on cell ID
-            (fract((cellId + 0.03521) * 34.21) * 2. - 1.)); // random B based on cell ID
-    vec2 snowFlakePosR = 1.016 * abs(rot45 * (snowFlakePos + snowFlakeShapeVariation));
-    snowFlakePos = abs(snowFlakePos);
-    // Create the snowFlake mask.
-    float flakeMask = smoothstep(
-        0.3,
-        0.200 - 0.3 * opacityVariation,
-        snowFlakePos.x + snowFlakePos.y + snowFlakePosR.x + snowFlakePosR.y
-    ) * opacityVariation;
+        (1. - 0.9 * cellId)*
+        visibilityFactor * farLayerFadeOut * closeLayerFadeOut;
+   float flakeMask = baseMask * opacityVariation;
 
     return Snow(flakeMask, cellUv);
 }
diff --git a/weathereffects/graphics/assets/shaders/snow_accumulation.agsl b/weathereffects/graphics/assets/shaders/snow_accumulation_outline.agsl
similarity index 100%
rename from weathereffects/graphics/assets/shaders/snow_accumulation.agsl
rename to weathereffects/graphics/assets/shaders/snow_accumulation_outline.agsl
diff --git a/weathereffects/graphics/assets/shaders/snow_accumulation_result.agsl b/weathereffects/graphics/assets/shaders/snow_accumulation_result.agsl
new file mode 100644
index 0000000..7381f12
--- /dev/null
+++ b/weathereffects/graphics/assets/shaders/snow_accumulation_result.agsl
@@ -0,0 +1,56 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+// `foregroundOutline`: Original size bitmap with blurred foreground outline
+uniform shader foregroundOutline;
+uniform shader noise;
+uniform mat3 transformMatrixBitmapScaleOnly;
+
+#include "shaders/simplex2d.agsl"
+#include "shaders/utils.agsl"
+
+/**
+ * This shader generates ready-to-use snow accumulation with noise and a fluffy effect
+ * added to the foreground outline. It also proportionally scales the input bitmap
+ * to fit the screen size for memory efficiency.
+ *
+ * For snow_effects, only transform `fragCoord` based on parallax translation to access this result.
+ * - R channel: Controls accumulation thickness based on intensity.
+ * - G and B channels: Cache intermediate values to avoid redundant per-frame calculations.
+ */
+vec4 main(float2 fragCoord) {
+    vec4 color = vec4(0, 0, 0, 1.0);
+    // Apply transform matrix to fragCoord to scale down output
+    float2 adjustedUv = transformPoint(transformMatrixBitmapScaleOnly, fragCoord);
+    // Load noise texture to give "fluffiness" to the snow. Displace the sampling of the noise.
+    vec3 cloudsNoise = noise.eval(adjustedUv * 7000 + vec2(fragCoord.y, -fragCoord.x)).rgb;
+    // Add dither to give texture to the snow and ruffle the edges.
+    float dither = abs(triangleNoise(fragCoord * 0.01));
+    // Get the accumulated snow buffer. r contains its mask, g contains some random noise.
+    vec2 accSnow = foregroundOutline.eval(adjustedUv).rg;
+    //  R channel as intensity threshold
+    color.r = accSnow.r;
+    // Sharpen the mask of the accumulated snow, but not in excess.
+    // Makes the edges of the snow layer accumulation rougher.
+    color.g =  1. - cloudsNoise.b - 0.3 * dither;
+    // Load snow texture and dither. Make it have gray-ish values.
+    float accSnowTexture = smoothstep(0.2, 0.7, /* noise= */ accSnow.g) * 0.7;
+    accSnowTexture = map(accSnowTexture, dither - 1, 1, 0, 1);
+    // Adjust snow texture coverage/shape.
+    accSnowTexture = map(accSnowTexture, 0.67, 0.8, 0, 1);
+    color.b = 1.- 0.6 * accSnowTexture - 0.35 * dither;
+    return color;
+}
diff --git a/weathereffects/graphics/assets/shaders/snow_effect.agsl b/weathereffects/graphics/assets/shaders/snow_effect.agsl
index b397ff1..4204a04 100644
--- a/weathereffects/graphics/assets/shaders/snow_effect.agsl
+++ b/weathereffects/graphics/assets/shaders/snow_effect.agsl
@@ -17,13 +17,14 @@
 uniform shader foreground;
 uniform shader background;
 uniform shader accumulatedSnow;
-uniform shader noise;
 uniform float2 gridSize;
 uniform float time;
 uniform float screenAspectRatio;
 uniform float2 screenSize;
+uniform float cellAspectRatio;
 uniform mat3 transformMatrixBitmap;
 uniform mat3 transformMatrixWeather;
+uniform shader snowFlakeSamples;
 
 #include "shaders/constants.agsl"
 #include "shaders/utils.agsl"
@@ -31,11 +32,13 @@ uniform mat3 transformMatrixWeather;
 
 // Snow tint.
 const vec4 snowColor = vec4(1., 1., 1., 0.95);
+
 // Background tint
 const vec4 bgdTint = vec4(0.8, 0.8, 0.8, 0.07);
 
+
 // Indices of the different snow layers.
-const float farthestSnowLayerIndex = 6;
+const float farthestSnowLayerIndex = 4;
 const float midSnowLayerIndex = 2;
 const float closestSnowLayerIndex = 0;
 
@@ -53,7 +56,8 @@ vec4 main(float2 fragCoord) {
     // Apply transform matrix to fragCoord
     float2 adjustedUv = transformPoint(transformMatrixBitmap, fragCoord);
     // Calculate uv for snow based on transformed coordinates
-    float2 uv = transformPoint(transformMatrixWeather, fragCoord) / screenSize;
+    float2 weatherUv = transformPoint(transformMatrixWeather, fragCoord);
+    float2 uv = weatherUv / screenSize;
     float2 uvAdjusted = vec2(uv.x, uv.y / screenAspectRatio);
 
     vec4 colorForeground = foreground.eval(adjustedUv);
@@ -93,27 +97,11 @@ vec4 main(float2 fragCoord) {
     color.rgb = normalBlend(color.rgb, colorForeground.rgb, colorForeground.a);
 
     // 4. Add accumulated snow layer.
-    // Load noise texture to give "fluffy-ness" to the snow. Displace the sampling of the noise.
-    vec3 cloudsNoise = noise.eval(uvAdjusted * 7000 + vec2(fragCoord.y, -fragCoord.x)).rgb;
-    // Add dither to give texture to the snow and ruffle the edges.
-    float dither = abs(triangleNoise(fragCoord * 0.01));
-
-    // Get the accumulated snow buffer. r contains its mask, g contains some random noise.
-    vec2 accSnow = accumulatedSnow.eval(adjustedUv).rg;
-    // Sharpen the mask of the accumulated snow, but not in excess.
+    vec3 accSnow = accumulatedSnow.eval(weatherUv).rgb;
     float accSnowMask = smoothstep( (1.-intensity), 1.0, /* mask= */accSnow.r);
-    if (accSnowMask > 0) {
-        // Makes the edges of the snow layer accumulation rougher.
-        accSnowMask = map(accSnowMask, 1. - cloudsNoise.b - 0.3 * dither, 1., 0., 1.);
-        // Load snow texture and dither. Make it have gray-ish values.
-        float accSnowTexture = smoothstep(0.2, 0.7, /* noise= */ accSnow.g) * 0.7;
-        accSnowTexture = map(accSnowTexture, dither - 1, 1, 0, 1);
-        // Adjust snow texture coverage/shape.
-        accSnowTexture = map(accSnowTexture, 0.67, 0.8, 0, 1);
-        accSnowMask = map(accSnowMask, 0., 1., 0., 1.- 0.6 * accSnowTexture - 0.35 * dither);
-
-        color.rgb = normalBlendNotPremultiplied(color.rgb, snowColor.rgb, snowColor.a * accSnowMask);
-    }
+    accSnowMask = map(accSnowMask, accSnow.g, 1., 0., 1.);
+    accSnowMask = map(accSnowMask, 0., 1., 0., accSnow.b);
+    color.rgb = normalBlendNotPremultiplied(color.rgb, snowColor.rgb, snowColor.a * accSnowMask);
 
     // 5. Generate snow in front of the subject.
     for (float i = midSnowLayerIndex; i >= closestSnowLayerIndex; i--) {
@@ -131,4 +119,4 @@ vec4 main(float2 fragCoord) {
     }
 
     return color;
-}
+}
\ No newline at end of file
diff --git a/weathereffects/graphics/assets/shaders/snow_flake_samples.agsl b/weathereffects/graphics/assets/shaders/snow_flake_samples.agsl
new file mode 100644
index 0000000..5b9e95d
--- /dev/null
+++ b/weathereffects/graphics/assets/shaders/snow_flake_samples.agsl
@@ -0,0 +1,79 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+uniform float2 canvasSize;
+uniform float snowFlakeSamplesSize;
+
+#include "shaders/constants.agsl"
+#include "shaders/utils.agsl"
+
+
+const vec2 snowFlakeShape = vec2(0.28, 0.26);
+// Used in generate snow flake samples, and sampling it afterwards, to make sure snow flakes
+// will not go beyond bounding box
+const float minDecreaseFactor = 0.5 / 0.28;
+
+const float layerIndex = 0;
+
+const mat2 rot45 = mat2(
+    0.7071067812, 0.7071067812, // First column.
+    -0.7071067812, 0.7071067812 // second column.
+);
+
+/**
+ * This shader generates snow flake samples per cell. It stores the flake mask in the red channel,
+ * and pre-calculated `cellIntensity` and `cellId` in the green and blue channels for optimized access.
+ */
+vec4 main(float2 fragCoord) {
+    // Calculate uv for snow based on transformed coordinates
+    float2 uv = fragCoord / canvasSize;
+    float layerR = idGenerator(layerIndex);
+    // Number of rows and columns (each one is a cell, a snowflake).
+    vec2 gridSize = floor(canvasSize / snowFlakeSamplesSize);
+    float cellAspectRatio = gridSize.x / gridSize.y;
+    // Aspect ratio impacts visible cells.
+    vec2 gridUv = uv * gridSize;
+
+    /* Cell. */
+    // Get the cell ID based on the grid position. Value from 0 to 1.
+    float cellId = idGenerator(floor(gridUv));
+    // For each cell, we set the internal UV from -0.5 (left, bottom) to 0.5 (right, top).
+    vec2 cellUv = fract(gridUv) - 0.5;
+    cellUv.y *= -1.;
+
+   /*
+    * Disable snow flakes with some probabilty. This is done by 1) assigning a random intensity
+    * value to the cell 2) then compare it with the given intensity.
+    */
+    half cellIntensity = idGenerator(floor(vec2(cellId * 856.16, 272.2)));
+
+    /* Cell snow flake. */
+    // Calculate snow flake.
+    // With decreaseFactor <= minSnowShapeScale, we can make sure snow flakes not going out its
+    // snowFlakeSamplesSize * snowFlakeSamplesSize bounding box
+    float decreaseFactor = clamp(2.0 + map(cellId, 0., 1., 1., 1 + 5. * (1 - cellIntensity)),
+        minDecreaseFactor, 4);
+    // snowFlake center should be (0,0) in the cell when generating snowflake samples
+    vec2 snowFlakePos = vec2(cellUv.x, cellUv.y);
+    snowFlakePos *= snowFlakeShape * decreaseFactor;
+    vec2 snowFlakeShapeVariation = vec2(0.055) * // max variation
+        vec2((cellId * 2. - 1.), // random A based on cell ID
+        (fract((cellId + 0.03521) * 34.21) * 2. - 1.)); // random B based on cell ID
+    vec2 snowFlakePosR = 1.016 * abs(rot45 * (snowFlakePos + snowFlakeShapeVariation));
+    snowFlakePos = abs(snowFlakePos);
+    // Create the snowFlake mask.
+    float baseMask = 1 - clamp(snowFlakePos.x + snowFlakePos.y + snowFlakePosR.x + snowFlakePosR.y, 0, 1);
+    return vec4(baseMask, cellIntensity, cellId , 1);
+}
diff --git a/weathereffects/graphics/assets/shaders/sun_effect.agsl b/weathereffects/graphics/assets/shaders/sun_effect.agsl
index 601b3d3..3886eb3 100644
--- a/weathereffects/graphics/assets/shaders/sun_effect.agsl
+++ b/weathereffects/graphics/assets/shaders/sun_effect.agsl
@@ -30,8 +30,8 @@ uniform mat3 transformMatrixWeather;
 
 #include "shaders/lens_flare.agsl"
 
-const vec2 sunCenter = vec2(0.57, -0.8);
 const vec3 godRaysColor = vec3(1., 0.857, 0.71428);
+const vec2 sunCenter = vec2(0.67, -1.0);
 
 float calculateRay(float angle, float time) {
     /*
@@ -94,16 +94,25 @@ float checkBrightnessGodRaysAtCenter(
 }
 
 vec4 main(float2 fragCoord) {
+    float2 aspectRatioAdj = vec2(1.);
+    if (screenAspectRatio > 1) {
+        aspectRatioAdj.x = screenAspectRatio;
+    } else {
+        aspectRatioAdj.y = 1. / screenAspectRatio;
+    }
     // Apply transform matrix to fragCoord
     float2 adjustedUv = transformPoint(transformMatrixBitmap, fragCoord);
 
     float2 uv = transformPoint(transformMatrixWeather, fragCoord) / screenSize;
     uv -= vec2(0.5, 0.5);
-    uv.y /= screenAspectRatio;
-    vec2 sunVariation = vec2(0.1 * sin(time * 0.3), 0.14 * cos(time * 0.5));
-    sunVariation += 0.1 * (0.5 * sin(time * 0.456) + 0.5) * sunCenter / vec2(1., screenAspectRatio);
-    vec2 sunPos = sunVariation + sunCenter / vec2(1., screenAspectRatio);
-    //TODO(b/375214506): fix the uv position of the sun
+    uv *= aspectRatioAdj;
+    // Random sun variation based on sin/cos signal.
+    vec2 sunVariation = 0.08 * vec2(sin(time * 0.3), cos(time * 0.5));
+    // Variation that moves sun on the same direction than the vector that goes from (0,0)
+    // to sunCenter, but scaling distance.
+    sunVariation += 0.1 * (0.5 * sin(time * 0.456) + 0.5) * sunCenter;
+    vec2 sunPos = sunVariation + sunCenter;
+    sunPos *= aspectRatioAdj;
 
     vec4 colorForeground = foreground.eval(adjustedUv);
     vec4 color = background.eval(adjustedUv);
diff --git a/weathereffects/graphics/assets/shaders/utils.agsl b/weathereffects/graphics/assets/shaders/utils.agsl
index 04e20e4..4bc02c6 100644
--- a/weathereffects/graphics/assets/shaders/utils.agsl
+++ b/weathereffects/graphics/assets/shaders/utils.agsl
@@ -150,3 +150,7 @@ float2 transformPoint(mat3 transformMatrix, float2 point) {
     // Convert back to Cartesian coordinates (x, y)
     return transformedPoint.xy / transformedPoint.z;
 }
+
+float normalizeValue(float x, float minVal, float maxVal) {
+    return (x - minVal) / (maxVal - minVal);
+}
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffectBase.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffectBase.kt
index e2739b2..dc0ebba 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffectBase.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffectBase.kt
@@ -26,7 +26,7 @@ import android.util.SizeF
 import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
 import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.calculateTransformDifference
 import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.centerCropMatrix
-import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.getScale
+import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.getScaleFromMatrixValues
 import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.invertAndTransposeMatrix
 import kotlin.random.Random
 
@@ -37,18 +37,28 @@ abstract class WeatherEffectBase(
     /** The initial size of the surface where the effect will be shown. */
     private var surfaceSize: SizeF,
 ) : WeatherEffect {
-    private var centerCropMatrix: Matrix =
+    protected var centerCropMatrix: Matrix =
         centerCropMatrix(
             surfaceSize,
             SizeF(background.width.toFloat(), background.height.toFloat()),
         )
+        set(value) {
+            field = value
+            value.getValues(centerCropMatrixValues)
+        }
+
     protected var parallaxMatrix = Matrix(centerCropMatrix)
+    private val centerCropMatrixValues: FloatArray =
+        FloatArray(9).apply { centerCropMatrix.getValues(this) }
+    private val parallaxMatrixValues: FloatArray =
+        FloatArray(9).apply { parallaxMatrix.getValues(this) }
     // Currently, we use same transform for both foreground and background
     protected open val transformMatrixBitmap: FloatArray = FloatArray(9)
+    protected open val transformMatrixCenterCrop: FloatArray = FloatArray(9)
     // Apply to weather components not rely on image textures
     // Should be identity matrix in editor, and only change when parallax applied in homescreen
     private val transformMatrixWeather: FloatArray = FloatArray(9)
-    protected var bitmapScale = getScale(centerCropMatrix)
+    protected var bitmapScale = getScaleFromMatrixValues(centerCropMatrixValues)
     protected var elapsedTime: Float = 0f
 
     abstract val shader: RuntimeShader
@@ -57,24 +67,35 @@ abstract class WeatherEffectBase(
     abstract val colorGradingIntensity: Float
 
     override fun setMatrix(matrix: Matrix) {
-        this.parallaxMatrix.set(matrix)
-        bitmapScale = getScale(parallaxMatrix)
+        if (matrix == this.parallaxMatrix) {
+            return
+        }
+
+        this.parallaxMatrix.setAndUpdateFloatArray(matrix, parallaxMatrixValues)
+        bitmapScale = getScaleFromMatrixValues(parallaxMatrixValues)
         adjustCropping(surfaceSize)
     }
 
+    /** This function will be called every time parallax changes, don't do heavy things here */
     open fun adjustCropping(newSurfaceSize: SizeF) {
         invertAndTransposeMatrix(parallaxMatrix, transformMatrixBitmap)
+        invertAndTransposeMatrix(centerCropMatrix, transformMatrixCenterCrop)
         calculateTransformDifference(centerCropMatrix, parallaxMatrix, transformMatrixWeather)
         shader.setFloatUniform("transformMatrixBitmap", transformMatrixBitmap)
         shader.setFloatUniform("transformMatrixWeather", transformMatrixWeather)
-        shader.setFloatUniform("screenSize", newSurfaceSize.width, newSurfaceSize.height)
-        shader.setFloatUniform("screenAspectRatio", GraphicsUtils.getAspectRatio(newSurfaceSize))
     }
 
     open fun updateGridSize(newSurfaceSize: SizeF) {}
 
     override fun resize(newSurfaceSize: SizeF) {
         surfaceSize = newSurfaceSize
+        centerCropMatrix =
+            centerCropMatrix(
+                surfaceSize,
+                SizeF(background.width.toFloat(), background.height.toFloat()),
+            )
+        shader.setFloatUniform("screenSize", newSurfaceSize.width, newSurfaceSize.height)
+        shader.setFloatUniform("screenAspectRatio", GraphicsUtils.getAspectRatio(newSurfaceSize))
         adjustCropping(newSurfaceSize)
         updateGridSize(newSurfaceSize)
     }
@@ -113,8 +134,8 @@ abstract class WeatherEffectBase(
                 surfaceSize,
                 SizeF(background.width.toFloat(), background.height.toFloat()),
             )
-        parallaxMatrix.set(centerCropMatrix)
-        bitmapScale = getScale(centerCropMatrix)
+        parallaxMatrix.setAndUpdateFloatArray(centerCropMatrix, parallaxMatrixValues)
+        bitmapScale = getScaleFromMatrixValues(centerCropMatrixValues)
         shader.setInputBuffer(
             "background",
             BitmapShader(this.background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
@@ -137,6 +158,14 @@ abstract class WeatherEffectBase(
             "background",
             BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
         )
+
+        shader.setFloatUniform("screenSize", surfaceSize.width, surfaceSize.height)
+        shader.setFloatUniform("screenAspectRatio", GraphicsUtils.getAspectRatio(surfaceSize))
+    }
+
+    private fun Matrix.setAndUpdateFloatArray(src: Matrix, targetFloatArray: FloatArray) {
+        set(src)
+        src.getValues(targetFloatArray)
     }
 
     companion object {
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/clouds/CloudsEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/clouds/CloudsEffect.kt
new file mode 100644
index 0000000..b7eeeab
--- /dev/null
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/clouds/CloudsEffect.kt
@@ -0,0 +1,138 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.google.android.wallpaper.weathereffects.graphics.clouds
+
+import android.graphics.Bitmap
+import android.graphics.BitmapShader
+import android.graphics.Canvas
+import android.graphics.Paint
+import android.graphics.RuntimeShader
+import android.graphics.Shader
+import android.util.SizeF
+import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect.Companion.DEFAULT_INTENSITY
+import com.google.android.wallpaper.weathereffects.graphics.WeatherEffectBase
+import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
+import com.google.android.wallpaper.weathereffects.graphics.utils.TimeUtils
+import kotlin.math.sin
+
+/** Defines and generates the fog weather effect animation. */
+class CloudsEffect(
+    private val cloudsConfig: CloudsEffectConfig,
+    foreground: Bitmap,
+    background: Bitmap,
+    intensity: Float = DEFAULT_INTENSITY,
+    /** The initial size of the surface where the effect will be shown. */
+    surfaceSize: SizeF,
+) : WeatherEffectBase(foreground, background, surfaceSize) {
+
+    private val cloudsPaint = Paint().also { it.shader = cloudsConfig.colorGradingShader }
+
+    init {
+        updateTextureUniforms()
+        adjustCropping(surfaceSize)
+        prepareColorGrading()
+        updateGridSize(surfaceSize)
+        setIntensity(intensity)
+    }
+
+    override fun update(deltaMillis: Long, frameTimeNanos: Long) {
+        val deltaTime = TimeUtils.millisToSeconds(deltaMillis)
+
+        val time = TimeUtils.nanosToSeconds(frameTimeNanos)
+        // Variation range [0.4, 1]. We don't want the variation to be 0.
+        val variation = sin(0.06f * time + sin(0.18f * time)) * 0.3f + 0.7f
+        elapsedTime += variation * deltaTime
+
+        val scaledElapsedTime = elapsedTime * 0.248f
+
+        val variationFgd0 = 0.256f * sin(scaledElapsedTime)
+        val variationFgd1 = 0.156f * sin(scaledElapsedTime) * sin(scaledElapsedTime)
+        val timeFgd0 = 0.4f * elapsedTime * 5f + variationFgd0
+        val timeFgd1 = 0.03f * elapsedTime * 5f + variationFgd1
+
+        val variationBgd0 = 0.156f * sin((scaledElapsedTime + Math.PI.toFloat() / 2.0f))
+        val variationBgd1 =
+            0.0156f * sin((scaledElapsedTime + Math.PI.toFloat() / 3.0f)) * sin(scaledElapsedTime)
+        val timeBgd0 = 0.8f * elapsedTime * 5f + variationBgd0
+        val timeBgd1 = 0.2f * elapsedTime * 5f + variationBgd1
+
+        cloudsConfig.shader.setFloatUniform("time", timeFgd0, timeFgd1, timeBgd0, timeBgd1)
+
+        cloudsConfig.colorGradingShader.setInputShader("texture", cloudsConfig.shader)
+    }
+
+    override fun draw(canvas: Canvas) {
+        canvas.drawPaint(cloudsPaint)
+    }
+
+    override fun updateTextureUniforms() {
+        super.updateTextureUniforms()
+        cloudsConfig.shader.setInputBuffer(
+            "clouds",
+            BitmapShader(cloudsConfig.cloudsTexture, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT),
+        )
+
+        cloudsConfig.shader.setInputBuffer(
+            "fog",
+            BitmapShader(cloudsConfig.fogTexture, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT),
+        )
+
+        cloudsConfig.shader.setFloatUniform("pixelDensity", cloudsConfig.pixelDensity)
+    }
+
+    private fun prepareColorGrading() {
+        cloudsConfig.colorGradingShader.setInputShader("texture", cloudsConfig.shader)
+        cloudsConfig.lut?.let {
+            cloudsConfig.colorGradingShader.setInputShader(
+                "lut",
+                BitmapShader(it, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
+            )
+        }
+        cloudsConfig.colorGradingShader.setFloatUniform(
+            "intensity",
+            cloudsConfig.colorGradingIntensity,
+        )
+    }
+
+    override val shader: RuntimeShader
+        get() = cloudsConfig.shader
+
+    override val colorGradingShader: RuntimeShader
+        get() = cloudsConfig.colorGradingShader
+
+    override val lut: Bitmap?
+        get() = cloudsConfig.lut
+
+    override val colorGradingIntensity: Float
+        get() = cloudsConfig.colorGradingIntensity
+
+    override fun updateGridSize(newSurfaceSize: SizeF) {
+        val widthScreenScale =
+            GraphicsUtils.computeDefaultGridSize(newSurfaceSize, cloudsConfig.pixelDensity)
+        cloudsConfig.shader.setFloatUniform(
+            "cloudsSize",
+            widthScreenScale * cloudsConfig.cloudsTexture.width.toFloat(),
+            widthScreenScale * cloudsConfig.cloudsTexture.height.toFloat(),
+        )
+
+        cloudsConfig.shader.setFloatUniform(
+            "fogSize",
+            widthScreenScale * cloudsConfig.fogTexture.width.toFloat(),
+            widthScreenScale * cloudsConfig.fogTexture.height.toFloat(),
+        )
+    }
+}
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/clouds/CloudsEffectConfig.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/clouds/CloudsEffectConfig.kt
new file mode 100644
index 0000000..c4831a7
--- /dev/null
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/clouds/CloudsEffectConfig.kt
@@ -0,0 +1,79 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.google.android.wallpaper.weathereffects.graphics.clouds
+
+import android.content.res.AssetManager
+import android.graphics.Bitmap
+import android.graphics.RuntimeShader
+import androidx.annotation.FloatRange
+import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
+
+/** Configuration for a clouds effect. */
+data class CloudsEffectConfig(
+    /** The main shader of the effect. */
+    val shader: RuntimeShader,
+    /** The color grading shader. */
+    val colorGradingShader: RuntimeShader,
+    /** The main lut (color grading) for the effect. */
+    val lut: Bitmap?,
+    /**
+     * The clouds texture, which will be placed in front of the foreground. The texture is expected
+     * to be tileable, and at least 16-bit per channel for render quality.
+     */
+    val cloudsTexture: Bitmap,
+    /**
+     * The fog texture. This will be placed behind the foreground. The texture is expected to be
+     * tileable, and at least 16-bit per channel for render quality.
+     */
+    val fogTexture: Bitmap,
+    /** Pixel density of the display. Used for dithering. */
+    val pixelDensity: Float,
+    /** The intensity of the color grading. 0: no color grading, 1: color grading in full effect. */
+    @FloatRange(from = 0.0, to = 1.0) val colorGradingIntensity: Float,
+) {
+    /**
+     * Constructor for [CloudsEffectConfig].
+     *
+     * @param assets the application [AssetManager].
+     * @param pixelDensity pixel density of the display.
+     */
+    constructor(
+        assets: AssetManager,
+        pixelDensity: Float,
+    ) : this(
+        shader = GraphicsUtils.loadShader(assets, SHADER_PATH),
+        colorGradingShader = GraphicsUtils.loadShader(assets, COLOR_GRADING_SHADER_PATH),
+        lut = GraphicsUtils.loadTexture(assets, LOOKUP_TABLE_TEXTURE_PATH),
+        cloudsTexture =
+            GraphicsUtils.loadTexture(assets, CLOUDS_TEXTURE_PATH)
+                ?: throw RuntimeException("Clouds texture is missing."),
+        fogTexture =
+            GraphicsUtils.loadTexture(assets, FOG_TEXTURE_PATH)
+                ?: throw RuntimeException("Fog texture is missing."),
+        pixelDensity,
+        COLOR_GRADING_INTENSITY,
+    )
+
+    private companion object {
+        private const val SHADER_PATH = "shaders/clouds_effect.agsl"
+        private const val COLOR_GRADING_SHADER_PATH = "shaders/color_grading_lut.agsl"
+        private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/cloud_lut.png"
+        private const val CLOUDS_TEXTURE_PATH = "textures/clouds.png"
+        private const val FOG_TEXTURE_PATH = "textures/fog.png"
+        private const val COLOR_GRADING_INTENSITY = 0.4f
+    }
+}
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt
index 0009aa5..187abf2 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt
@@ -118,14 +118,10 @@ class RainEffect(
         get() = rainConfig.colorGradingIntensity
 
     override fun updateTextureUniforms() {
-        val foregroundBuffer =
-            BitmapShader(super.foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        rainConfig.rainShowerShader.setInputBuffer("foreground", foregroundBuffer)
-        rainConfig.outlineShader.setInputBuffer("texture", foregroundBuffer)
-
-        rainConfig.rainShowerShader.setInputBuffer(
-            "background",
-            BitmapShader(super.background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
+        super.updateTextureUniforms()
+        rainConfig.outlineShader.setInputBuffer(
+            "texture",
+            BitmapShader(super.foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
         )
         createOutlineBuffer()
     }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt
index 010b5c0..fca6eef 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt
@@ -24,7 +24,9 @@ import android.graphics.Paint
 import android.graphics.RenderEffect
 import android.graphics.RuntimeShader
 import android.graphics.Shader
+import android.hardware.HardwareBuffer
 import android.util.SizeF
+import androidx.core.graphics.createBitmap
 import com.google.android.wallpaper.weathereffects.graphics.FrameBuffer
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect.Companion.DEFAULT_INTENSITY
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffectBase
@@ -51,17 +53,51 @@ class SnowEffect(
     private var snowSpeed: Float = 0.8f
     private val snowPaint = Paint().also { it.shader = snowConfig.colorGradingShader }
 
-    private var frameBuffer = FrameBuffer(background.width, background.height)
-    private val frameBufferPaint = Paint().also { it.shader = snowConfig.accumulatedSnowShader }
+    // Use outlineFrameBuffer and outlineFrameBufferPaint to get foreground outline
+    // its process requires blur effects
+    private var outlineFrameBuffer = FrameBuffer(background.width, background.height)
+    private val outlineFrameBufferPaint =
+        Paint().also { it.shader = snowConfig.accumulatedSnowOutlineShader }
+    // accumulationFrameBuffer and accumulationFrameBufferPaint will get the result from
+    // outlineFrameBuffer and add noise to snow fluffiness
+    private var accumulationFrameBuffer =
+        FrameBuffer(
+            (background.width * bitmapScale).toInt(),
+            (background.height * bitmapScale).toInt(),
+        )
+    private val accumulationFrameBufferPaint =
+        Paint().also { it.shader = snowConfig.accumulatedSnowResultShader }
+
+    private val snowFlakeSamplesBuffer: FrameBuffer =
+        if (
+            HardwareBuffer.isSupported(
+                SNOW_FLAKE_SAMPLES_BUFFER_WIDTH,
+                SNOW_FLAKE_SAMPLES_BUFFER_HEIGHT,
+                HardwareBuffer.RGB_888,
+                1,
+                HardwareBuffer.USAGE_GPU_SAMPLED_IMAGE or HardwareBuffer.USAGE_GPU_COLOR_OUTPUT,
+            )
+        ) {
+            FrameBuffer(
+                SNOW_FLAKE_SAMPLES_BUFFER_WIDTH,
+                SNOW_FLAKE_SAMPLES_BUFFER_HEIGHT,
+                HardwareBuffer.RGB_888,
+            )
+        } else {
+            FrameBuffer(SNOW_FLAKE_SAMPLES_BUFFER_WIDTH, SNOW_FLAKE_SAMPLES_BUFFER_HEIGHT)
+        }
+
+    private val snowFlakeSamplesPaint = Paint().also { it.shader = snowConfig.snowFlakeSamples }
 
     init {
-        frameBuffer.setRenderEffect(
+        outlineFrameBuffer.setRenderEffect(
             RenderEffect.createBlurEffect(
                 BLUR_RADIUS / bitmapScale,
                 BLUR_RADIUS / bitmapScale,
                 Shader.TileMode.CLAMP,
             )
         )
+
         updateTextureUniforms()
         adjustCropping(surfaceSize)
         prepareColorGrading()
@@ -70,11 +106,11 @@ class SnowEffect(
 
         // Generate accumulated snow at the end after we updated all the uniforms.
         generateAccumulatedSnow()
+        generateSnowFlakeSamples()
     }
 
     override fun update(deltaMillis: Long, frameTimeNanos: Long) {
         elapsedTime += snowSpeed * TimeUtils.millisToSeconds(deltaMillis)
-
         snowConfig.shader.setFloatUniform("time", elapsedTime)
         snowConfig.colorGradingShader.setInputShader("texture", snowConfig.shader)
     }
@@ -85,7 +121,9 @@ class SnowEffect(
 
     override fun release() {
         super.release()
-        frameBuffer.close()
+        outlineFrameBuffer.close()
+        accumulationFrameBuffer.close()
+        snowFlakeSamplesBuffer.close()
     }
 
     override fun setIntensity(intensity: Float) {
@@ -105,11 +143,17 @@ class SnowEffect(
             return false
         }
 
-        frameBuffer.close()
-        frameBuffer = FrameBuffer(background.width, background.height)
+        outlineFrameBuffer.close()
+        accumulationFrameBuffer.close()
+        outlineFrameBuffer = FrameBuffer(background.width, background.height)
         val newScale = getScale(parallaxMatrix)
         bitmapScale = newScale
-        frameBuffer.setRenderEffect(
+        accumulationFrameBuffer =
+            FrameBuffer(
+                (background.width * bitmapScale).toInt(),
+                (background.height * bitmapScale).toInt(),
+            )
+        outlineFrameBuffer.setRenderEffect(
             RenderEffect.createBlurEffect(
                 BLUR_RADIUS / bitmapScale,
                 BLUR_RADIUS / bitmapScale,
@@ -139,23 +183,42 @@ class SnowEffect(
         super.setMatrix(matrix)
         // Blur radius should change with scale because it decides the fluffiness of snow
         if (abs(bitmapScale - oldScale) > FLOAT_TOLERANCE) {
-            frameBuffer.setRenderEffect(
+            outlineFrameBuffer.close()
+            accumulationFrameBuffer.close()
+            outlineFrameBuffer = FrameBuffer((background.width), (background.height))
+
+            outlineFrameBuffer.setRenderEffect(
                 RenderEffect.createBlurEffect(
                     BLUR_RADIUS / bitmapScale,
                     BLUR_RADIUS / bitmapScale,
                     Shader.TileMode.CLAMP,
                 )
             )
+            accumulationFrameBuffer =
+                FrameBuffer(
+                    (background.width * bitmapScale).toInt(),
+                    (background.height * bitmapScale).toInt(),
+                )
+            snowConfig.shader.setInputShader(
+                "accumulatedSnow",
+                BitmapShader(blankBitmap, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
+            )
+
             generateAccumulatedSnow()
         }
     }
 
     override fun updateTextureUniforms() {
         super.updateTextureUniforms()
-        snowConfig.shader.setInputBuffer(
+        snowConfig.accumulatedSnowResultShader.setInputBuffer(
             "noise",
             BitmapShader(snowConfig.noiseTexture, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT),
         )
+        snowConfig.shader.setFloatUniform("snowFlakeSamplesSize", SNOW_FLAKE_SAMPLES_SIZE.toFloat())
+        snowConfig.snowFlakeSamples.setFloatUniform(
+            "snowFlakeSamplesSize",
+            SNOW_FLAKE_SAMPLES_SIZE.toFloat(),
+        )
     }
 
     private fun prepareColorGrading() {
@@ -168,28 +231,55 @@ class SnowEffect(
         }
     }
 
+    // Generate accumulated snow requires two passes, first is to generate blurred foreground
+    // outline, second is to add snow fluffiness to it.
+    // It should only be called when bitmaps or screensize change, and should not be called
+    // per frame.
     private fun generateAccumulatedSnow() {
-        val renderingCanvas = frameBuffer.beginDrawing()
-        snowConfig.accumulatedSnowShader.setFloatUniform("scale", bitmapScale)
-        snowConfig.accumulatedSnowShader.setFloatUniform(
+        // Generate foreground outline
+        val renderingCanvas = outlineFrameBuffer.beginDrawing()
+        snowConfig.accumulatedSnowOutlineShader.setFloatUniform("scale", bitmapScale)
+        snowConfig.accumulatedSnowOutlineShader.setFloatUniform(
             "snowThickness",
             SNOW_THICKNESS / bitmapScale,
         )
-        snowConfig.accumulatedSnowShader.setFloatUniform("screenWidth", surfaceSize.width)
-        snowConfig.accumulatedSnowShader.setInputBuffer(
+        snowConfig.accumulatedSnowOutlineShader.setFloatUniform("screenWidth", surfaceSize.width)
+        snowConfig.accumulatedSnowOutlineShader.setInputBuffer(
             "foreground",
             BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
         )
 
-        renderingCanvas.drawPaint(frameBufferPaint)
-        frameBuffer.endDrawing()
+        renderingCanvas.drawPaint(outlineFrameBufferPaint)
+        outlineFrameBuffer.endDrawing()
+
+        outlineFrameBuffer.tryObtainingImage(
+            this::generateAccumulatedSnowWithBlurredOutline,
+            mainExecutor,
+        )
+    }
+
+    /** @param outlineImage is generated by outlineShader */
+    private fun generateAccumulatedSnowWithBlurredOutline(outlineImage: Bitmap) {
+        val renderingCanvas = accumulationFrameBuffer.beginDrawing()
+        snowConfig.accumulatedSnowResultShader.setInputBuffer(
+            "foregroundOutline",
+            BitmapShader(outlineImage, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
+        )
+        // Actually, we should not generate it with bitmap
+        snowConfig.accumulatedSnowResultShader.setFloatUniform(
+            "transformMatrixBitmapScaleOnly",
+            transformMatrixCenterCrop,
+        )
+        renderingCanvas.drawPaint(accumulationFrameBufferPaint)
+        accumulationFrameBuffer.endDrawing()
 
-        frameBuffer.tryObtainingImage(
+        accumulationFrameBuffer.tryObtainingImage(
             { image ->
                 snowConfig.shader.setInputBuffer(
                     "accumulatedSnow",
-                    BitmapShader(image, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
+                    BitmapShader(image, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP),
                 )
+                outlineFrameBuffer.close()
             },
             mainExecutor,
         )
@@ -197,14 +287,63 @@ class SnowEffect(
 
     override fun updateGridSize(newSurfaceSize: SizeF) {
         val gridSize = GraphicsUtils.computeDefaultGridSize(newSurfaceSize, snowConfig.pixelDensity)
-        snowConfig.shader.setFloatUniform("gridSize", 7 * gridSize, 2f * gridSize)
+        val gridSizeColumns = 7f * gridSize
+        val gridSizeRows = 2f * gridSize
+        snowConfig.shader.setFloatUniform("gridSize", gridSizeColumns, gridSizeRows)
+        snowConfig.shader.setFloatUniform("cellAspectRatio", gridSizeColumns / gridSizeRows)
+    }
+
+    /**
+     * Generates an offscreen bitmap containing pre-rendered snow flake patterns and properties.
+     *
+     * This bitmap serves as a lookup table for the main snow_effect shader, reducing per-frame
+     * calculations.
+     */
+    private fun generateSnowFlakeSamples() {
+        val renderingCanvas = snowFlakeSamplesBuffer.beginDrawing()
+        snowConfig.snowFlakeSamples.setFloatUniform(
+            "canvasSize",
+            SNOW_FLAKE_SAMPLES_BUFFER_WIDTH.toFloat(),
+            SNOW_FLAKE_SAMPLES_BUFFER_HEIGHT.toFloat(),
+        )
+        renderingCanvas.drawPaint(snowFlakeSamplesPaint)
+        snowFlakeSamplesBuffer.endDrawing()
+        snowFlakeSamplesBuffer.tryObtainingImage(
+            { snowFlakeSamples ->
+                snowConfig.shader.setInputShader(
+                    "snowFlakeSamples",
+                    BitmapShader(snowFlakeSamples, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
+                )
+            },
+            mainExecutor,
+        )
     }
 
     companion object {
-        val BLUR_RADIUS = 4f
+        const val BLUR_RADIUS = 4f
         // Use blur effect for both blurring the snow accumulation and generating a gradient edge
         // so that intensity can control snow thickness by cut the gradient edge in snow_effect
         // shader.
-        val SNOW_THICKNESS = 6f
+        const val SNOW_THICKNESS = 6f
+        // During wallpaper resizing, the updated accumulation texture might not be immediately
+        // available.
+        // To prevent displaying outdated accumulation, we use a tiny blank bitmap to temporarily
+        // clear the rendering area before the new texture is ready.
+        private val blankBitmap = createBitmap(1, 1)
+
+        // The `snow_flakes_samples` shader pre-generates diverse snow flake properties
+        // (shape mask, intensity, etc.) in a bitmap, reducing per-frame calculations. A higher
+        // column count provides more x-based visual variations.
+        // The following values balance the visual benefits with memory and shader sampling costs.
+        // Number of columns; increases x-based variation.
+        const val SNOW_FLAKE_SAMPLES_COLUMN_COUNT = 14
+        const val SNOW_FLAKE_SAMPLES_ROW_COUNT = 4
+        // Side length of each flake's square bounding box.
+        const val SNOW_FLAKE_SAMPLES_SIZE = 100
+
+        const val SNOW_FLAKE_SAMPLES_BUFFER_WIDTH =
+            SNOW_FLAKE_SAMPLES_COLUMN_COUNT * SNOW_FLAKE_SAMPLES_SIZE
+        const val SNOW_FLAKE_SAMPLES_BUFFER_HEIGHT =
+            SNOW_FLAKE_SAMPLES_ROW_COUNT * SNOW_FLAKE_SAMPLES_SIZE
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt
index fe8bba8..2dfacb9 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt
@@ -26,10 +26,14 @@ import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
 data class SnowEffectConfig(
     /** The main shader of the effect. */
     val shader: RuntimeShader,
-    /** The shader of accumulated snow effect. */
-    val accumulatedSnowShader: RuntimeShader,
+    /** The shader of foreground outline, which will be used in accumulatedSnowResultShader. */
+    val accumulatedSnowOutlineShader: RuntimeShader,
     /** The color grading shader. */
     val colorGradingShader: RuntimeShader,
+    /** The shader of accumulated snow with fluffy effects. */
+    val accumulatedSnowResultShader: RuntimeShader,
+    /** The shader of generate snow flake patterns. */
+    val snowFlakeSamples: RuntimeShader,
     /**
      * The noise texture, which will be used to add fluffiness to the snow flakes. The texture is
      * expected to be tileable, and at least 16-bit per channel for render quality.
@@ -56,8 +60,12 @@ data class SnowEffectConfig(
         pixelDensity: Float,
     ) : this(
         shader = GraphicsUtils.loadShader(assets, SHADER_PATH),
-        accumulatedSnowShader = GraphicsUtils.loadShader(assets, ACCUMULATED_SNOW_SHADER_PATH),
+        accumulatedSnowOutlineShader =
+            GraphicsUtils.loadShader(assets, ACCUMULATED_SNOW_OUTLINE_SHADER_PATH),
         colorGradingShader = GraphicsUtils.loadShader(assets, COLOR_GRADING_SHADER_PATH),
+        accumulatedSnowResultShader =
+            GraphicsUtils.loadShader(assets, ACCUMULATED_SNOW_RESULT_SHADER_PATH),
+        snowFlakeSamples = GraphicsUtils.loadShader(assets, SNOW_FLAKE_SPRITE_SHEET_PATH),
         noiseTexture =
             GraphicsUtils.loadTexture(assets, NOISE_TEXTURE_PATH)
                 ?: throw RuntimeException("Noise texture is missing."),
@@ -69,8 +77,12 @@ data class SnowEffectConfig(
 
     companion object {
         private const val SHADER_PATH = "shaders/snow_effect.agsl"
-        private const val ACCUMULATED_SNOW_SHADER_PATH = "shaders/snow_accumulation.agsl"
+        private const val ACCUMULATED_SNOW_OUTLINE_SHADER_PATH =
+            "shaders/snow_accumulation_outline.agsl"
+        private const val ACCUMULATED_SNOW_RESULT_SHADER_PATH =
+            "shaders/snow_accumulation_result.agsl"
         private const val COLOR_GRADING_SHADER_PATH = "shaders/color_grading_lut.agsl"
+        private const val SNOW_FLAKE_SPRITE_SHEET_PATH = "shaders/snow_flake_samples.agsl"
         private const val NOISE_TEXTURE_PATH = "textures/clouds.png"
         private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/snow_lut.png"
         private const val COLOR_GRADING_INTENSITY = 0.25f
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/MatrixUtils.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/MatrixUtils.kt
index 7d2afa6..382fdf7 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/MatrixUtils.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/MatrixUtils.kt
@@ -55,6 +55,10 @@ object MatrixUtils {
         return matrixValues[0]
     }
 
+    fun getScaleFromMatrixValues(matrixValuesArray: FloatArray): Float {
+        return matrixValuesArray[0]
+    }
+
     /**
      * Calculates the transformation matrix that, when applied to `originMatrix`, results in
      * `targetMatrix`. Current use case: Calculating parallax effect for the homescreen compared
@@ -70,11 +74,58 @@ object MatrixUtils {
         targetMatrix: Matrix,
         outArray: FloatArray,
     ): FloatArray {
-        targetMatrix.invert(inverseMatrix)
-        concatMatrix.set(originMatrix)
-        concatMatrix.postConcat(inverseMatrix)
+        originMatrix.invert(inverseMatrix)
+        concatMatrix.set(inverseMatrix)
+        concatMatrix.postConcat(targetMatrix)
         concatMatrix.getValues(matrixValues)
-        return transposeMatrixArray(matrixValues, outArray)
+        return invertAndTransposeMatrix(concatMatrix, outArray)
+    }
+
+    /**
+     * Calculates the difference in translation between two transformation matrices, represented as
+     * FloatArrays (`centerCropMatrixValues` and `parallaxMatrixValues`), after scaling
+     * `parallaxMatrixValues` to match the scale of `centerCropMatrixValues`. The resulting
+     * translation difference is then stored in the provided `outArray` as a 3x3 translation matrix
+     * (in column-major order).
+     *
+     * @param centerCropMatrixValues A FloatArray of length 9 representing the reference
+     *   transformation matrix (center-cropped view) in row-major order.
+     * @param parallaxMatrixValues A FloatArray of length 9 representing the transformation matrix
+     *   whose translation difference relative to `centerCropMatrixValues` is to be calculated, also
+     *   in row-major order. This array will be scaled to match the scale of
+     *   `centerCropMatrixValues`.
+     * @param outArray A FloatArray of length 9 to store the resulting 3x3 translation matrix. The
+     *   translation components (deltaX, deltaY) will be placed in the appropriate positions for a
+     *   column-major matrix.
+     */
+    fun calculateTranslationDifference(
+        centerCropMatrixValues: FloatArray,
+        parallaxMatrixValues: FloatArray,
+        outArray: FloatArray,
+    ): FloatArray {
+        val scaleX = centerCropMatrixValues[0] / parallaxMatrixValues[0]
+        val scaleY = centerCropMatrixValues[4] / parallaxMatrixValues[4]
+
+        val scaledParallaxTransX = parallaxMatrixValues[2] * scaleX
+        val scaledParallaxTransY = parallaxMatrixValues[5] * scaleY
+
+        val originTransX = centerCropMatrixValues[2]
+        val originTransY = centerCropMatrixValues[5]
+
+        val deltaTransX = originTransX - scaledParallaxTransX
+        val deltaTransY = originTransY - scaledParallaxTransY
+
+        outArray[0] = 1f
+        outArray[1] = 0f
+        outArray[2] = 0f
+        outArray[3] = 0f
+        outArray[4] = 1f
+        outArray[5] = 0f
+        outArray[6] = deltaTransX
+        outArray[7] = deltaTransY
+        outArray[8] = 1f
+
+        return outArray
     }
 
     // Transpose 3x3 matrix values as a FloatArray[9], write results to outArray
diff --git a/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt b/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt
index 0fd6adb..1a73c76 100644
--- a/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt
+++ b/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt
@@ -32,6 +32,8 @@ import com.google.android.torus.core.wallpaper.listener.LiveWallpaperEventListen
 import com.google.android.torus.core.wallpaper.listener.LiveWallpaperKeyguardEventListener
 import com.google.android.wallpaper.weathereffects.domain.WeatherEffectsInteractor
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect
+import com.google.android.wallpaper.weathereffects.graphics.clouds.CloudsEffect
+import com.google.android.wallpaper.weathereffects.graphics.clouds.CloudsEffectConfig
 import com.google.android.wallpaper.weathereffects.graphics.fog.FogEffect
 import com.google.android.wallpaper.weathereffects.graphics.fog.FogEffectConfig
 import com.google.android.wallpaper.weathereffects.graphics.none.NoEffect
@@ -222,6 +224,21 @@ class WeatherEngine(
                         screenSize.toSizeF(),
                     )
             }
+
+            WallpaperInfoContract.WeatherEffect.CLOUDS -> {
+                val cloudsConfig =
+                    CloudsEffectConfig(context.assets, context.resources.displayMetrics.density)
+
+                activeEffect =
+                    CloudsEffect(
+                        cloudsConfig,
+                        foreground,
+                        background,
+                        effectIntensity,
+                        screenSize.toSizeF(),
+                    )
+            }
+
             WallpaperInfoContract.WeatherEffect.SNOW -> {
                 val snowConfig =
                     SnowEffectConfig(context.assets, context.resources.displayMetrics.density)
diff --git a/weathereffects/src/com/google/android/wallpaper/weathereffects/provider/WallpaperInfoContract.kt b/weathereffects/src/com/google/android/wallpaper/weathereffects/provider/WallpaperInfoContract.kt
index 095b2e0..83d1896 100644
--- a/weathereffects/src/com/google/android/wallpaper/weathereffects/provider/WallpaperInfoContract.kt
+++ b/weathereffects/src/com/google/android/wallpaper/weathereffects/provider/WallpaperInfoContract.kt
@@ -21,14 +21,15 @@ import android.net.Uri
 
 object WallpaperInfoContract {
 
-    /** Returns a [Uri.Builder] for updating a wallpaper. This will produce a uri starts with
-     * content://com.google.android.wallpaper.weathereffects.effectprovider/update_wallpaper.
-     * Append parameters such as foreground and background images, etc.
+    /**
+     * Returns a [Uri.Builder] for updating a wallpaper. This will produce a uri starts with
+     * content://com.google.android.wallpaper.weathereffects.effectprovider/update_wallpaper. Append
+     * parameters such as foreground and background images, etc.
      *
      * All the parameters are optional.
      * <ul>
-     *   <li>For the initial generation, foreground and background images must be provided.
-     *   <li>When foreground and background images are already provided, but no weather type is
+     * <li>For the initial generation, foreground and background images must be provided.
+     * <li>When foreground and background images are already provided, but no weather type is
      *   provided, it clears the existing weather effect (foreground & background images composed).
      * </ul>
      *
@@ -37,7 +38,8 @@ object WallpaperInfoContract {
      * <path_to_background_texture>
      */
     fun getUpdateWallpaperUri(): Uri.Builder {
-        return Uri.Builder().scheme(SCHEME_CONTENT)
+        return Uri.Builder()
+            .scheme(SCHEME_CONTENT)
             .authority(AUTHORITY)
             .appendPath(WeatherEffectsContentProvider.UPDATE_WALLPAPER)
     }
@@ -45,6 +47,7 @@ object WallpaperInfoContract {
     enum class WeatherEffect(val value: String) {
         RAIN("rain"),
         FOG("fog"),
+        CLOUDS("clouds"),
         SNOW("snow"),
         SUN("SUN");
 
@@ -54,11 +57,10 @@ object WallpaperInfoContract {
              * Converts the String value to an enum.
              *
              * @param value a String representing the [value] of an enum. Note that this is the
-             * value that we created [value] and it does not refer to the [valueOf] value, which
-             * corresponds to the [name]. i.e.
-             * - RAIN("rain"):
-             *     -> [valueOf] needs [name] ("RAIN").
-             *     -> [fromStringValue] needs [value] ("rain").
+             *   value that we created [value] and it does not refer to the [valueOf] value, which
+             *   corresponds to the [name]. i.e.
+             * - RAIN("rain"): -> [valueOf] needs [name] ("RAIN"). -> [fromStringValue] needs
+             *   [value] ("rain").
              *
              * @return the associated [WeatherEffect].
              */
@@ -66,6 +68,7 @@ object WallpaperInfoContract {
                 return when (value) {
                     RAIN.value -> RAIN
                     FOG.value -> FOG
+                    CLOUDS.value -> CLOUDS
                     SNOW.value -> SNOW
                     SUN.value -> SUN
                     else -> null
@@ -85,8 +88,6 @@ object WallpaperInfoContract {
         const val BACKGROUND_TEXTURE = "background_texture"
         const val WEATHER_EFFECT = "weather_effect"
 
-        val DEFAULT_PROJECTION = arrayOf(
-            FOREGROUND_TEXTURE, BACKGROUND_TEXTURE, WEATHER_EFFECT
-        )
+        val DEFAULT_PROJECTION = arrayOf(FOREGROUND_TEXTURE, BACKGROUND_TEXTURE, WEATHER_EFFECT)
     }
 }
```

