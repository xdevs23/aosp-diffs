```diff
diff --git a/OWNERS b/OWNERS
index e4a726e..b0bc793 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,5 @@
 levarum@google.com
 khim@google.com
 dimitry@google.com
+anthonyjon@google.com
+richardfung@google.com
diff --git a/android_api/gen_known_trampolines.py b/android_api/gen_known_trampolines.py
index eb7fb20..3777375 100755
--- a/android_api/gen_known_trampolines.py
+++ b/android_api/gen_known_trampolines.py
@@ -74,6 +74,14 @@ def _get_type_str(guest_api, type_name, is_return_type):
   if kind == 'function':
     return _get_function_type_str(guest_api, type, 'auto(%s) -> %s')
 
+  # JNIEnv may be automatically converted.
+  if kind == 'pointer' and "JNIEnv" in type_name:
+    # Only support raw reference to JNIEnv.
+    # We don't have trampolines with transitive references to JNIEnv and thus
+    # don't know how to properly handle these.
+    assert(type_name == 'struct _JNIEnv*')
+    return 'JNIEnv*'
+
   # Handle pointers to functions.
   if kind == 'pointer':
     pointee_type = guest_api['types'][type['pointee_type']]
diff --git a/android_api/libamidi/proxy/trampolines_arm64_to_x86_64-inl.h b/android_api/libamidi/proxy/trampolines_arm64_to_x86_64-inl.h
index a8429c1..1cf4893 100644
--- a/android_api/libamidi/proxy/trampolines_arm64_to_x86_64-inl.h
+++ b/android_api/libamidi/proxy/trampolines_arm64_to_x86_64-inl.h
@@ -1,6 +1,6 @@
 // clang-format off
 const KnownTrampoline kKnownTrampolines[] = {
-{"AMidiDevice_fromJava", GetTrampolineFunc<auto(void*, void*, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
+{"AMidiDevice_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMidiDevice_getDefaultProtocol", GetTrampolineFunc<auto(void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMidiDevice_getNumInputPorts", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
 {"AMidiDevice_getNumOutputPorts", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libamidi/proxy/trampolines_arm_to_x86-inl.h b/android_api/libamidi/proxy/trampolines_arm_to_x86-inl.h
index 4ca1e20..dac234b 100644
--- a/android_api/libamidi/proxy/trampolines_arm_to_x86-inl.h
+++ b/android_api/libamidi/proxy/trampolines_arm_to_x86-inl.h
@@ -1,6 +1,6 @@
 // clang-format off
 const KnownTrampoline kKnownTrampolines[] = {
-{"AMidiDevice_fromJava", GetTrampolineFunc<auto(void*, void*, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
+{"AMidiDevice_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMidiDevice_getDefaultProtocol", GetTrampolineFunc<auto(void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMidiDevice_getNumInputPorts", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMidiDevice_getNumOutputPorts", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libamidi/proxy/trampolines_riscv64_to_x86_64-inl.h b/android_api/libamidi/proxy/trampolines_riscv64_to_x86_64-inl.h
index a8429c1..1cf4893 100644
--- a/android_api/libamidi/proxy/trampolines_riscv64_to_x86_64-inl.h
+++ b/android_api/libamidi/proxy/trampolines_riscv64_to_x86_64-inl.h
@@ -1,6 +1,6 @@
 // clang-format off
 const KnownTrampoline kKnownTrampolines[] = {
-{"AMidiDevice_fromJava", GetTrampolineFunc<auto(void*, void*, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
+{"AMidiDevice_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMidiDevice_getDefaultProtocol", GetTrampolineFunc<auto(void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMidiDevice_getNumInputPorts", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
 {"AMidiDevice_getNumOutputPorts", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libandroid/proxy/trampolines_arm64_to_x86_64-inl.h b/android_api/libandroid/proxy/trampolines_arm64_to_x86_64-inl.h
index 46f7c59..8df9038 100644
--- a/android_api/libandroid/proxy/trampolines_arm64_to_x86_64-inl.h
+++ b/android_api/libandroid/proxy/trampolines_arm64_to_x86_64-inl.h
@@ -7,7 +7,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AAssetDir_close", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AAssetDir_getNextFileName", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AAssetDir_rewind", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AAssetManager_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AAssetManager_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AAssetManager_open", GetTrampolineFunc<auto(void*, void*, int32_t) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AAssetManager_openDir", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AAsset_close", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
@@ -104,7 +104,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AHardwareBuffer_acquire", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_allocate", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_describe", GetTrampolineFunc<auto(void*, void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AHardwareBuffer_fromHardwareBuffer", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AHardwareBuffer_fromHardwareBuffer", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_getId", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_getNativeHandle", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_isSupported", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
@@ -114,17 +114,17 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AHardwareBuffer_recvHandleFromUnixSocket", GetTrampolineFunc<auto(int32_t, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_sendHandleToUnixSocket", GetTrampolineFunc<auto(void*, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AHardwareBuffer_toHardwareBuffer", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AHardwareBuffer_toHardwareBuffer", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_unlock", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputEvent_getDeviceId", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputEvent_getSource", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputEvent_getType", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputEvent_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AInputEvent_toJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AInputEvent_toJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_attachLooper", DoCustomTrampoline_AInputQueue_attachLooper, reinterpret_cast<void*>(DoBadThunk)},
 {"AInputQueue_detachLooper", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_finishEvent", GetTrampolineFunc<auto(void*, void*, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AInputQueue_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AInputQueue_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_getEvent", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_hasEvents", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_preDispatchEvent", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
@@ -136,10 +136,10 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AInputReceiver_createUnbatchedInputReceiver", GetTrampolineFunc<auto(void*, void*, void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputReceiver_getInputTransferToken", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputReceiver_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AInputTransferToken_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AInputTransferToken_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputTransferToken_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AInputTransferToken_toJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
-{"AKeyEvent_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AInputTransferToken_toJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AKeyEvent_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AKeyEvent_getAction", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AKeyEvent_getDownTime", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
 {"AKeyEvent_getEventTime", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
@@ -157,7 +157,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ALooper_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ALooper_removeFd", GetTrampolineFunc<auto(void*, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ALooper_wake", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AMotionEvent_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AMotionEvent_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AMotionEvent_getAction", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMotionEvent_getActionButton", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMotionEvent_getAxisValue", GetTrampolineFunc<auto(void*, int32_t, uint64_t) -> float>(), reinterpret_cast<void*>(NULL)},
@@ -206,14 +206,14 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ANativeActivity_setWindowFormat", DoCustomTrampoline_ANativeActivity_setWindowFormat, reinterpret_cast<void*>(DoBadThunk)},
 {"ANativeActivity_showSoftInput", DoCustomTrampoline_ANativeActivity_showSoftInput, reinterpret_cast<void*>(DoBadThunk)},
 {"ANativeWindow_acquire", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"ANativeWindow_fromSurface", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ANativeWindow_fromSurface", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_getFormat", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_getHeight", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_getWidth", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_lock", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_setBuffersGeometry", GetTrampolineFunc<auto(void*, int32_t, int32_t, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"ANativeWindow_toSurface", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ANativeWindow_toSurface", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_unlockAndPost", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AObbInfo_delete", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AObbInfo_getFlags", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
@@ -266,7 +266,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ASensor_isDirectChannelTypeSupported", GetTrampolineFunc<auto(void*, int32_t) -> uint8_t>(), reinterpret_cast<void*>(NULL)},
 {"ASensor_isWakeUpSensor", GetTrampolineFunc<auto(void*) -> uint8_t>(), reinterpret_cast<void*>(NULL)},
 {"ASharedMemory_create", GetTrampolineFunc<auto(void*, uint64_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"ASharedMemory_dupFromJava", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"ASharedMemory_dupFromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ASharedMemory_getSize", GetTrampolineFunc<auto(int32_t) -> uint64_t>(), reinterpret_cast<void*>(NULL)},
 {"ASharedMemory_setProt", GetTrampolineFunc<auto(int32_t, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AStorageManager_delete", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
@@ -280,7 +280,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ASurfaceControl_acquire", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_create", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_createFromWindow", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
-{"ASurfaceControl_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ASurfaceControl_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_getChoreographer", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_registerSurfaceStatsListener", GetTrampolineFunc<auto(void*, int32_t, void*, auto(*)(void*, int32_t, void*) -> void) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
@@ -288,7 +288,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ASurfaceTexture_acquireANativeWindow", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_attachToGLContext", GetTrampolineFunc<auto(void*, uint32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_detachFromGLContext", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"ASurfaceTexture_fromSurfaceTexture", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ASurfaceTexture_fromSurfaceTexture", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_getTimestamp", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_getTransformMatrix", GetTrampolineFunc<auto(void*, void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
@@ -303,7 +303,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ASurfaceTransaction_clearFrameRate", GetTrampolineFunc<auto(void*, void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_create", GetTrampolineFunc<auto(void) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_delete", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"ASurfaceTransaction_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ASurfaceTransaction_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_reparent", GetTrampolineFunc<auto(void*, void*, void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_setBuffer", GetTrampolineFunc<auto(void*, void*, void*, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_setBufferAlpha", GetTrampolineFunc<auto(void*, void*, float) -> void>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libandroid/proxy/trampolines_arm_to_x86-inl.h b/android_api/libandroid/proxy/trampolines_arm_to_x86-inl.h
index d449ad5..6fb3bf2 100644
--- a/android_api/libandroid/proxy/trampolines_arm_to_x86-inl.h
+++ b/android_api/libandroid/proxy/trampolines_arm_to_x86-inl.h
@@ -7,7 +7,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AAssetDir_close", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AAssetDir_getNextFileName", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AAssetDir_rewind", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AAssetManager_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AAssetManager_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AAssetManager_open", GetTrampolineFunc<auto(void*, void*, int32_t) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AAssetManager_openDir", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AAsset_close", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
@@ -104,7 +104,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AHardwareBuffer_acquire", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_allocate", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_describe", GetTrampolineFunc<auto(void*, void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AHardwareBuffer_fromHardwareBuffer", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AHardwareBuffer_fromHardwareBuffer", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_getId", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_getNativeHandle", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_isSupported", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
@@ -114,17 +114,17 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AHardwareBuffer_recvHandleFromUnixSocket", GetTrampolineFunc<auto(int32_t, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_sendHandleToUnixSocket", GetTrampolineFunc<auto(void*, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AHardwareBuffer_toHardwareBuffer", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AHardwareBuffer_toHardwareBuffer", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_unlock", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputEvent_getDeviceId", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputEvent_getSource", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputEvent_getType", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputEvent_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AInputEvent_toJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AInputEvent_toJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_attachLooper", DoCustomTrampoline_AInputQueue_attachLooper, reinterpret_cast<void*>(DoBadThunk)},
 {"AInputQueue_detachLooper", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_finishEvent", GetTrampolineFunc<auto(void*, void*, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AInputQueue_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AInputQueue_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_getEvent", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_hasEvents", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_preDispatchEvent", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
@@ -136,10 +136,10 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AInputReceiver_createUnbatchedInputReceiver", GetTrampolineFunc<auto(void*, void*, void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputReceiver_getInputTransferToken", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputReceiver_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AInputTransferToken_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AInputTransferToken_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputTransferToken_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AInputTransferToken_toJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
-{"AKeyEvent_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AInputTransferToken_toJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AKeyEvent_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AKeyEvent_getAction", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AKeyEvent_getDownTime", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
 {"AKeyEvent_getEventTime", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
@@ -157,7 +157,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ALooper_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ALooper_removeFd", GetTrampolineFunc<auto(void*, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ALooper_wake", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AMotionEvent_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AMotionEvent_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AMotionEvent_getAction", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMotionEvent_getActionButton", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMotionEvent_getAxisValue", GetTrampolineFunc<auto(void*, int32_t, uint32_t) -> float>(), reinterpret_cast<void*>(NULL)},
@@ -206,14 +206,14 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ANativeActivity_setWindowFormat", DoCustomTrampoline_ANativeActivity_setWindowFormat, reinterpret_cast<void*>(DoBadThunk)},
 {"ANativeActivity_showSoftInput", DoCustomTrampoline_ANativeActivity_showSoftInput, reinterpret_cast<void*>(DoBadThunk)},
 {"ANativeWindow_acquire", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"ANativeWindow_fromSurface", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ANativeWindow_fromSurface", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_getFormat", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_getHeight", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_getWidth", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_lock", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_setBuffersGeometry", GetTrampolineFunc<auto(void*, int32_t, int32_t, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"ANativeWindow_toSurface", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ANativeWindow_toSurface", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_unlockAndPost", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AObbInfo_delete", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AObbInfo_getFlags", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
@@ -266,7 +266,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ASensor_isDirectChannelTypeSupported", GetTrampolineFunc<auto(void*, int32_t) -> uint8_t>(), reinterpret_cast<void*>(NULL)},
 {"ASensor_isWakeUpSensor", GetTrampolineFunc<auto(void*) -> uint8_t>(), reinterpret_cast<void*>(NULL)},
 {"ASharedMemory_create", GetTrampolineFunc<auto(void*, uint32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"ASharedMemory_dupFromJava", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"ASharedMemory_dupFromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ASharedMemory_getSize", GetTrampolineFunc<auto(int32_t) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"ASharedMemory_setProt", GetTrampolineFunc<auto(int32_t, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AStorageManager_delete", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
@@ -280,7 +280,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ASurfaceControl_acquire", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_create", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_createFromWindow", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
-{"ASurfaceControl_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ASurfaceControl_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_getChoreographer", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_registerSurfaceStatsListener", GetTrampolineFunc<auto(void*, int32_t, void*, auto(*)(void*, int32_t, void*) -> void) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
@@ -288,7 +288,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ASurfaceTexture_acquireANativeWindow", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_attachToGLContext", GetTrampolineFunc<auto(void*, uint32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_detachFromGLContext", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"ASurfaceTexture_fromSurfaceTexture", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ASurfaceTexture_fromSurfaceTexture", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_getTimestamp", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_getTransformMatrix", GetTrampolineFunc<auto(void*, void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
@@ -303,7 +303,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ASurfaceTransaction_clearFrameRate", GetTrampolineFunc<auto(void*, void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_create", GetTrampolineFunc<auto(void) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_delete", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"ASurfaceTransaction_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ASurfaceTransaction_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_reparent", GetTrampolineFunc<auto(void*, void*, void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_setBuffer", GetTrampolineFunc<auto(void*, void*, void*, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_setBufferAlpha", GetTrampolineFunc<auto(void*, void*, float) -> void>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libandroid/proxy/trampolines_riscv64_to_x86_64-inl.h b/android_api/libandroid/proxy/trampolines_riscv64_to_x86_64-inl.h
index 46f7c59..8df9038 100644
--- a/android_api/libandroid/proxy/trampolines_riscv64_to_x86_64-inl.h
+++ b/android_api/libandroid/proxy/trampolines_riscv64_to_x86_64-inl.h
@@ -7,7 +7,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AAssetDir_close", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AAssetDir_getNextFileName", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AAssetDir_rewind", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AAssetManager_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AAssetManager_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AAssetManager_open", GetTrampolineFunc<auto(void*, void*, int32_t) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AAssetManager_openDir", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AAsset_close", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
@@ -104,7 +104,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AHardwareBuffer_acquire", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_allocate", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_describe", GetTrampolineFunc<auto(void*, void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AHardwareBuffer_fromHardwareBuffer", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AHardwareBuffer_fromHardwareBuffer", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_getId", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_getNativeHandle", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_isSupported", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
@@ -114,17 +114,17 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AHardwareBuffer_recvHandleFromUnixSocket", GetTrampolineFunc<auto(int32_t, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_sendHandleToUnixSocket", GetTrampolineFunc<auto(void*, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AHardwareBuffer_toHardwareBuffer", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AHardwareBuffer_toHardwareBuffer", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AHardwareBuffer_unlock", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputEvent_getDeviceId", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputEvent_getSource", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputEvent_getType", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputEvent_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AInputEvent_toJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AInputEvent_toJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_attachLooper", DoCustomTrampoline_AInputQueue_attachLooper, reinterpret_cast<void*>(DoBadThunk)},
 {"AInputQueue_detachLooper", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_finishEvent", GetTrampolineFunc<auto(void*, void*, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AInputQueue_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AInputQueue_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_getEvent", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_hasEvents", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AInputQueue_preDispatchEvent", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
@@ -136,10 +136,10 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AInputReceiver_createUnbatchedInputReceiver", GetTrampolineFunc<auto(void*, void*, void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputReceiver_getInputTransferToken", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputReceiver_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AInputTransferToken_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AInputTransferToken_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AInputTransferToken_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AInputTransferToken_toJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
-{"AKeyEvent_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AInputTransferToken_toJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AKeyEvent_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AKeyEvent_getAction", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AKeyEvent_getDownTime", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
 {"AKeyEvent_getEventTime", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
@@ -157,7 +157,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ALooper_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ALooper_removeFd", GetTrampolineFunc<auto(void*, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ALooper_wake", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AMotionEvent_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AMotionEvent_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AMotionEvent_getAction", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMotionEvent_getActionButton", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AMotionEvent_getAxisValue", GetTrampolineFunc<auto(void*, int32_t, uint64_t) -> float>(), reinterpret_cast<void*>(NULL)},
@@ -206,14 +206,14 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ANativeActivity_setWindowFormat", DoCustomTrampoline_ANativeActivity_setWindowFormat, reinterpret_cast<void*>(DoBadThunk)},
 {"ANativeActivity_showSoftInput", DoCustomTrampoline_ANativeActivity_showSoftInput, reinterpret_cast<void*>(DoBadThunk)},
 {"ANativeWindow_acquire", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"ANativeWindow_fromSurface", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ANativeWindow_fromSurface", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_getFormat", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_getHeight", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_getWidth", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_lock", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_setBuffersGeometry", GetTrampolineFunc<auto(void*, int32_t, int32_t, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"ANativeWindow_toSurface", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ANativeWindow_toSurface", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ANativeWindow_unlockAndPost", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AObbInfo_delete", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AObbInfo_getFlags", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
@@ -266,7 +266,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ASensor_isDirectChannelTypeSupported", GetTrampolineFunc<auto(void*, int32_t) -> uint8_t>(), reinterpret_cast<void*>(NULL)},
 {"ASensor_isWakeUpSensor", GetTrampolineFunc<auto(void*) -> uint8_t>(), reinterpret_cast<void*>(NULL)},
 {"ASharedMemory_create", GetTrampolineFunc<auto(void*, uint64_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"ASharedMemory_dupFromJava", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"ASharedMemory_dupFromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ASharedMemory_getSize", GetTrampolineFunc<auto(int32_t) -> uint64_t>(), reinterpret_cast<void*>(NULL)},
 {"ASharedMemory_setProt", GetTrampolineFunc<auto(int32_t, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AStorageManager_delete", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
@@ -280,7 +280,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ASurfaceControl_acquire", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_create", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_createFromWindow", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
-{"ASurfaceControl_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ASurfaceControl_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_getChoreographer", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_registerSurfaceStatsListener", GetTrampolineFunc<auto(void*, int32_t, void*, auto(*)(void*, int32_t, void*) -> void) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceControl_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
@@ -288,7 +288,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ASurfaceTexture_acquireANativeWindow", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_attachToGLContext", GetTrampolineFunc<auto(void*, uint32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_detachFromGLContext", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"ASurfaceTexture_fromSurfaceTexture", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ASurfaceTexture_fromSurfaceTexture", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_getTimestamp", GetTrampolineFunc<auto(void*) -> int64_t>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_getTransformMatrix", GetTrampolineFunc<auto(void*, void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTexture_release", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
@@ -303,7 +303,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ASurfaceTransaction_clearFrameRate", GetTrampolineFunc<auto(void*, void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_create", GetTrampolineFunc<auto(void) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_delete", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"ASurfaceTransaction_fromJava", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ASurfaceTransaction_fromJava", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_reparent", GetTrampolineFunc<auto(void*, void*, void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_setBuffer", GetTrampolineFunc<auto(void*, void*, void*, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
 {"ASurfaceTransaction_setBufferAlpha", GetTrampolineFunc<auto(void*, void*, float) -> void>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libandroid_runtime/proxy/trampolines_arm64_to_x86_64-inl.h b/android_api/libandroid_runtime/proxy/trampolines_arm64_to_x86_64-inl.h
index 5226b70..15237c8 100644
--- a/android_api/libandroid_runtime/proxy/trampolines_arm64_to_x86_64-inl.h
+++ b/android_api/libandroid_runtime/proxy/trampolines_arm64_to_x86_64-inl.h
@@ -38,6 +38,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_Z14SkStringPrintfPKcz", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z14StartIterationP10ZipArchivePPvNSt3__117basic_string_viewIcNS3_11char_traitsIcEEEES7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z14StartIterationP10ZipArchivePPvNSt3__18functionIFbNS3_17basic_string_viewIcNS3_11char_traitsIcEEEEEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_Z14sk_malloc_sizePvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z15ErrorCodeStringi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z15ExtractToMemoryP10ZipArchivePK10ZipEntry64Phm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z15ExtractToMemoryP10ZipArchivePK8ZipEntryPhm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -97,6 +98,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_Z34register_android_opengl_jni_GLES31P7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z34register_android_opengl_jni_GLES32P7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z35android_os_Process_killProcessGroupP7_JNIEnvP8_jobjectii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_Z35android_os_Process_sendSignalThrowsP7_JNIEnvP8_jobjectii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z35android_os_Process_setProcessFrozenP7_JNIEnvP8_jobjectiih", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z35convertAudioMixerAttributesToNativeP7_JNIEnvP8_jobjectP22audio_mixer_attributes", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z35register_android_hardware_SyncFenceP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -114,6 +116,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_Z37android_os_Process_getPidsForCommandsP7_JNIEnvP8_jobjectP13_jobjectArray", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37android_os_Process_getThreadSchedulerP7_JNIEnvP7_jclassi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37android_os_Process_parseProcLineArrayP7_JNIEnvP8_jobjectPciiP10_jintArrayP13_jobjectArrayP11_jlongArrayP12_jfloatArray", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_Z37android_os_Process_sendTgSignalThrowsP7_JNIEnvP8_jobjectiii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37android_os_Process_setThreadSchedulerP7_JNIEnvP7_jclassiii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37convertAudioMixerAttributesFromNativeP7_JNIEnvPK22audio_mixer_attributes", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37register_android_media_MicrophoneInfoP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -184,12 +187,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN14JniInputStreamC2EP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN14JniInputStreamD0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN14JniInputStreamD2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN15CdEntryMapZip32I17ZipStringOffset20E14ResetIterationEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN15CdEntryMapZip32I17ZipStringOffset20E4NextEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN15CdEntryMapZip32I17ZipStringOffset20E8AddToMapENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN15CdEntryMapZip32I17ZipStringOffset32E14ResetIterationEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN15CdEntryMapZip32I17ZipStringOffset32E4NextEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN15CdEntryMapZip32I17ZipStringOffset32E8AddToMapENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN15CdEntryMapZip6414ResetIterationEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN15CdEntryMapZip644NextEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN15CdEntryMapZip648AddToMapENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -418,6 +415,8 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android18PerfettoDataSourceD0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android18PerfettoDataSourceD1Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android18PerfettoDataSourceD2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android18createInputChannelERKNS_2spINS_7IBinderEEERKNS_18InputTransferTokenERKNS_14SurfaceControlES7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android18removeInputChannelERKNS_2spINS_7IBinderEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android19parcelForJavaObjectEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android19register_jni_commonEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android20VelocityTrackerState11addMovementERKNS_11MotionEventE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -546,7 +545,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android29register_android_app_ActivityEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android29register_android_view_SurfaceEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android30AssetManagerForNdkAssetManagerEP13AAssetManager", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android30android_view_KeyEvent_toNativeEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android30register_android_os_HidlMemoryEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android30register_android_os_MemoryFileEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android30register_android_util_EventLogEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -561,7 +559,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android31throw_sqlite3_exception_errcodeEP7_JNIEnviPKc", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32CameraMetadata_getNativeMetadataEP7_JNIEnvP8_jobjectPNS_14CameraMetadataE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32SurfaceTexture_getSurfaceTextureEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android32android_view_KeyEvent_fromNativeEP7_JNIEnvRKNS_8KeyEventE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32android_view_MotionEvent_recycleEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32android_view_VerifiedMotionEventEP7_JNIEnvRKNS_19VerifiedMotionEventE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32register_android_os_FileObserverEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -580,6 +577,8 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android33register_android_view_MotionEventEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android33register_android_view_PointerIconEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android33register_android_view_TextureViewEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvRKNS_8KeyEventE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android34convertHdrCapabilitiesToJavaObjectEP7_JNIEnvRKNS_15HdrCapabilitiesE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android34register_android_os_HwRemoteBinderEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android34register_android_os_ServiceManagerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -674,6 +673,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android41android_view_MotionEvent_obtainFromNativeEP7_JNIEnvNSt3__110unique_ptrINS_11MotionEventENS2_14default_deleteIS4_EEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android41register_android_tracing_PerfettoProducerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android41register_android_view_VerifiedMotionEventEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android41register_android_view_WindowManagerGlobalEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42android_view_InputChannel_createJavaObjectEP7_JNIEnvNSt3__110unique_ptrINS_12InputChannelENS2_14default_deleteIS4_EEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42register_android_content_res_ConfigurationEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42register_android_content_res_ResourceTimerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -683,6 +683,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android42register_android_os_storage_StorageManagerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42register_android_service_DataLoaderServiceEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42register_android_view_DisplayEventReceiverEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android42register_android_window_InputTransferTokenEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android43register_android_tracing_PerfettoDataSourceEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android43register_android_window_WindowInfosListenerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android43register_com_android_internal_os_ZygoteInitEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -700,11 +701,9 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android47register_android_view_TunnelModeEnabledListenerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android47register_com_android_internal_content_F2fsUtilsEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android49android_hardware_display_DisplayViewport_toNativeEP7_JNIEnvP8_jobjectPNS_15DisplayViewportE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android49android_view_SurfaceControl_getJavaSurfaceControlEP7_JNIEnvRKNS_14SurfaceControlE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android49register_android_hardware_display_DisplayViewportEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android49register_android_view_CompositionSamplingListenerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android4base4TrimIRNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEEES8_OT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android4base9ParseUintImEEbPKcPT_S4_b", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android4base9ParseUintItEEbPKcPT_S4_b", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android50com_android_internal_os_ZygoteCommandBuffer_insertEP7_JNIEnvP7_jclasslP8_jstring", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android50register_android_os_incremental_IncrementalManagerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android50register_com_android_internal_security_VerityUtilsEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -735,6 +734,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android58com_android_internal_os_ZygoteCommandBuffer_nativeGetCountEP7_JNIEnvP7_jclassl", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android58register_com_android_internal_os_KernelSingleUidTimeReaderEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android59android_view_SurfaceTransaction_getNativeSurfaceTransactionEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android59android_window_InputTransferToken_getJavaInputTransferTokenEP7_JNIEnvRKNS_18InputTransferTokenE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android59com_android_internal_os_ZygoteCommandBuffer_getNativeBufferEP7_JNIEnvP7_jclassi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android59register_com_android_internal_content_om_OverlayManagerImplEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android59register_com_android_internal_os_KernelCpuTotalBpfMapReaderEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -750,6 +750,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android60android_view_InputApplicationHandle_fromInputApplicationInfoEP7_JNIEnvNS_3gui20InputApplicationInfoE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android60com_android_internal_os_ZygoteCommandBuffer_freeNativeBufferEP7_JNIEnvP7_jclassl", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android60register_com_android_internal_os_ZygoteInit_nativeZygoteInitEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android61android_window_InputTransferToken_getNativeInputTransferTokenEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android64com_android_internal_os_ZygoteCommandBuffer_nativeForkRepeatedlyEP7_JNIEnvP7_jclassliiiP8_jstring", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android67android_hardware_display_DisplayManagerGlobal_signalNativeCallbacksEP7_JNIEnvP8_jobjectf", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android67com_android_internal_os_ZygoteCommandBuffer_nativeReadFullyAndResetEP7_JNIEnvP7_jclassl", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -770,7 +771,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android7JHwBlobC2EP7_JNIEnvP8_jobjectm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android7JHwBlobD0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android7JHwBlobD2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android8hardware10fromBinderINS_4hidl4base4V1_05IBaseENS4_8BpHwBaseENS4_8BnHwBaseEEENS_2spIT_EERKNS8_INS0_7IBinderEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android8hardware7display27IDeviceProductInfoConstants11asInterfaceERKNS_2spINS_7IBinderEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android8hardware7display27IDeviceProductInfoConstants14getDefaultImplEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android8hardware7display27IDeviceProductInfoConstants14setDefaultImplENS_2spIS2_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -897,8 +897,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZNK13NativeContext18getThumbnailHeightEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK13NativeContext9getResultEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK14ZipEntryCommon19GetModificationTimeEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK15CdEntryMapZip32I17ZipStringOffset20E16GetCdEntryOffsetENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK15CdEntryMapZip32I17ZipStringOffset32E16GetCdEntryOffsetENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK15CdEntryMapZip6416GetCdEntryOffsetENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK16InputStripSource6getIfdEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK16JNICameraContext33isRawImageCallbackBufferAvailableEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -915,9 +913,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZNK7android15JHwRemoteBinder9getBinderEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo13writeToParcelEPNS_6ParcelE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo16interceptsStylusEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android3gui10WindowInfo18frameContainsPointEii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo18supportsSplitTouchEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android3gui10WindowInfo28touchableRegionContainsPointEii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo5isSpyEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo8overlapsEPKS1_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfoeqERKS1_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -931,12 +927,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZNK7android3gui28IWindowInfosReportedListener22getInterfaceDescriptorEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android5vintf18KernelConfigParser5errorEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android5vintf18KernelConfigParser7configsEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android6VectorIiE10do_destroyEPvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android6VectorIiE12do_constructEPvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android6VectorIiE15do_move_forwardEPvPKvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android6VectorIiE16do_move_backwardEPvPKvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android6VectorIiE7do_copyEPvPKvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android6VectorIiE8do_splatEPvPKvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android7JHwBlob13writeToParcelEPNS_8hardware6ParcelE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android7JHwBlob21writeEmbeddedToParcelEPNS_8hardware6ParcelEmm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android7JHwBlob21writeSubBlobsToParcelEPNS_8hardware6ParcelEm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -971,128 +961,18 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZNK8SkString6equalsERKS_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK9Transform3mapEiiPiS0_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK9TransformeqERKS_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__110__back_refIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__110__l_anchorIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__110__r_anchorIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111__alternateIcE12__exec_splitEbRNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111__alternateIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111__end_stateIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111__lookaheadIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111__match_anyIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE21__match_at_start_ecmaINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE27__match_at_start_posix_subsINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE29__match_at_start_posix_nosubsINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE8__searchINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112__match_charIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112regex_traitsIcE18__lookup_classnameIPKcEEtT_S5_bc", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112regex_traitsIcE19__transform_primaryINS_11__wrap_iterIPcEEEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SC_c", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112regex_traitsIcE20__lookup_collatenameIPKcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SB_c", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112regex_traitsIcE20__lookup_collatenameIPcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SA_c", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112regex_traitsIcE9transformINS_11__wrap_iterIPcEEEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SC_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112regex_traitsIcE9transformIPcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SA_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__113__empty_stateIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__115__word_boundaryIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNKSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__116__back_ref_icaseIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__117__repeat_one_loopIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__118__back_ref_collateIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__118__match_char_icaseIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__120__bracket_expressionIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__120__match_char_collateIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__121__empty_non_own_stateIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__126__end_marked_subexpressionIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__128__begin_marked_subexpressionIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__16__loopIcE12__exec_splitEbRNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__16__loopIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE11__push_charEc", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE11__push_loopEmmPNS_16__owns_one_stateIcEEmmb", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_atomIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_grepIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_termIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE13__parse_egrepIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE15__push_back_refEi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE16__parse_ecma_expIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE16__push_lookaheadERKS3_bj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE17__parse_assertionIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE18__parse_awk_escapeIPKcEET_S7_S7_PNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE18__parse_nondupl_REIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE19__parse_alternativeIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE20__parse_ORD_CHAR_EREIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE20__parse_class_escapeIPKcEET_S7_S7_RNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPNS_20__bracket_expressionIcS2_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE21__parse_basic_reg_expIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_ERE_expressionIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_RE_dupl_symbolIPKcEET_S7_S7_PNS_16__owns_one_stateIcEEjj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_decimal_escapeIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_ERE_dupl_symbolIPKcEET_S7_S7_PNS_16__owns_one_stateIcEEjj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_QUOTED_CHAR_EREIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_expression_termIPKcEET_S7_S7_PNS_20__bracket_expressionIcS2_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_character_escapeIPKcEET_S7_S7_PNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_collating_symbolIPKcEET_S7_S7_RNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_extended_reg_expIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE25__parse_equivalence_classIPKcEET_S7_S7_PNS_20__bracket_expressionIcS2_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE25__parse_pattern_characterIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE26__parse_bracket_expressionIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE30__parse_character_class_escapeIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE32__parse_one_char_or_coll_elem_REIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE7__parseIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__112__deque_baseINS_7__stateIcEENS_9allocatorIS2_EEE5clearEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113__tree_removeIPNS_16__tree_node_baseIPvEEEEvT_S5_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE4syncEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE5imbueERKNS_6localeE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE6setbufEPcl", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE7seekoffExNS_8ios_base7seekdirEj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE7seekposENS_4fposI9mbstate_tEEj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE8overflowEi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE9pbackfailEi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE9underflowEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEEC2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE10push_frontEOS3_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE10push_frontERKS3_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE9push_backEOS3_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__114__split_bufferIPNS_7__stateIcEERNS_9allocatorIS3_EEE10push_frontERKS3_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__114__split_bufferIPNS_7__stateIcEERNS_9allocatorIS3_EEE9push_backEOS3_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strERKNS_12basic_stringIcS2_S4_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE7seekoffExNS_8ios_base7seekdirEj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE8overflowEi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE9pbackfailEi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE9underflowEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__116__owns_one_stateIcED0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__116__owns_one_stateIcED2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__117__call_once_proxyINS_5tupleIJRFvvEEEEEEvPv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__117__owns_two_statesIcED0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__117__owns_two_statesIcED2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__120__shared_ptr_pointerIPNS_13__empty_stateIcEENS_14default_deleteIS2_EENS_9allocatorIS2_EEE16__on_zero_sharedEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__120__shared_ptr_pointerIPNS_13__empty_stateIcEENS_14default_deleteIS2_EENS_9allocatorIS2_EEE21__on_zero_shared_weakEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__124__put_character_sequenceIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__127__tree_balance_after_insertIPNS_16__tree_node_baseIPvEEEEvT_S5_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__15dequeINS_7__stateIcEENS_9allocatorIS2_EEE19__add_back_capacityEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__15dequeINS_7__stateIcEENS_9allocatorIS2_EEE20__add_front_capacityEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16__treeINS_12__value_typeINS_17basic_string_viewIcNS_11char_traitsIcEEEEmEENS_19__map_value_compareIS5_S6_NS_4lessIS5_EELb1EEENS_9allocatorIS6_EEE25__emplace_unique_key_argsIS5_JNS_4pairIKS5_mEEEEENSF_INS_15__tree_iteratorIS6_PNS_11__tree_nodeIS6_PvEElEEbEERKT_DpOT0_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16__treeINS_12__value_typeINS_17basic_string_viewIcNS_11char_traitsIcEEEEmEENS_19__map_value_compareIS5_S6_NS_4lessIS5_EELb1EEENS_9allocatorIS6_EEE7destroyEPNS_11__tree_nodeIS6_PvEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16__treeIiNS_4lessIiEENS_9allocatorIiEEE7destroyEPNS_11__tree_nodeIiPvEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIRKS6_EEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIS6_EEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_4pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_EENS5_IS8_EEE21__push_back_slow_pathIS8_EEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_4pairIccEENS_9allocatorIS2_EEE21__push_back_slow_pathIS2_EEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_4pairImPKcEENS_9allocatorIS4_EEE6assignIPS4_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS4_NS_15iterator_traitsISB_E9referenceEEE5valueEvE4typeESB_SB_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_4pairImPKcEENS_9allocatorIS4_EEE8__appendEm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_7__stateIcEENS_9allocatorIS2_EEE21__push_back_slow_pathIS2_EEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_9sub_matchINS_11__wrap_iterIPKcEEEENS_9allocatorIS6_EEE8__appendEm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE6assignEmRKS4_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE6assignIPS4_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS4_NS_15iterator_traitsISB_E9referenceEEE5valueEvE4typeESB_SB_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE8__appendEmRKS4_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorIcNS_9allocatorIcEEE21__push_back_slow_pathIRKcEEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorIcNS_9allocatorIcEEE21__push_back_slow_pathIcEEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorIhNS_9allocatorIhEEE6resizeEm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorIhNS_9allocatorIhEEE8__appendEm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__16vectorIiNS_9allocatorIiEEE21__push_back_slow_pathIiEEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__16vectorIjNS_9allocatorIjEEE21__push_back_slow_pathIjEEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__16vectorIlNS_9allocatorIlEEE21__push_back_slow_pathIlEEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__16vectorImNS_9allocatorImEEE21__push_back_slow_pathImEEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__17getlineIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EES6_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__1lsIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_ostreamIT_T0_EES9_RKNS_12basic_stringIS6_S7_T1_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZThn16_N7android18NativeMessageQueue11handleEventEiiPv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZThn16_N7android18NativeMessageQueueD0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZThn16_N7android18NativeMessageQueueD1Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
diff --git a/android_api/libandroid_runtime/proxy/trampolines_arm_to_x86-inl.h b/android_api/libandroid_runtime/proxy/trampolines_arm_to_x86-inl.h
index 175fb36..0c0842e 100644
--- a/android_api/libandroid_runtime/proxy/trampolines_arm_to_x86-inl.h
+++ b/android_api/libandroid_runtime/proxy/trampolines_arm_to_x86-inl.h
@@ -38,6 +38,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_Z14SkStringPrintfPKcz", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z14StartIterationP10ZipArchivePPvNSt3__117basic_string_viewIcNS3_11char_traitsIcEEEES7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z14StartIterationP10ZipArchivePPvNSt3__18functionIFbNS3_17basic_string_viewIcNS3_11char_traitsIcEEEEEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_Z14sk_malloc_sizePvj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z15ErrorCodeStringi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z15ExtractToMemoryP10ZipArchivePK10ZipEntry64Phj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z15ExtractToMemoryP10ZipArchivePK8ZipEntryPhj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -97,6 +98,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_Z34register_android_opengl_jni_GLES31P7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z34register_android_opengl_jni_GLES32P7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z35android_os_Process_killProcessGroupP7_JNIEnvP8_jobjectii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_Z35android_os_Process_sendSignalThrowsP7_JNIEnvP8_jobjectii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z35android_os_Process_setProcessFrozenP7_JNIEnvP8_jobjectiih", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z35convertAudioMixerAttributesToNativeP7_JNIEnvP8_jobjectP22audio_mixer_attributes", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z35register_android_hardware_SyncFenceP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -114,6 +116,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_Z37android_os_Process_getPidsForCommandsP7_JNIEnvP8_jobjectP13_jobjectArray", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37android_os_Process_getThreadSchedulerP7_JNIEnvP7_jclassi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37android_os_Process_parseProcLineArrayP7_JNIEnvP8_jobjectPciiP10_jintArrayP13_jobjectArrayP11_jlongArrayP12_jfloatArray", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_Z37android_os_Process_sendTgSignalThrowsP7_JNIEnvP8_jobjectiii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37android_os_Process_setThreadSchedulerP7_JNIEnvP7_jclassiii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37convertAudioMixerAttributesFromNativeP7_JNIEnvPK22audio_mixer_attributes", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37register_android_media_MicrophoneInfoP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -427,6 +430,8 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android18PerfettoDataSourceD0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android18PerfettoDataSourceD1Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android18PerfettoDataSourceD2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android18createInputChannelERKNS_2spINS_7IBinderEEERKNS_18InputTransferTokenERKNS_14SurfaceControlES7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android18removeInputChannelERKNS_2spINS_7IBinderEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android19parcelForJavaObjectEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android19register_jni_commonEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android20VelocityTrackerState11addMovementERKNS_11MotionEventE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -561,7 +566,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android2spINS_3gui28IWindowInfosReportedListenerEED2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android2spINS_8hardware7display27IDeviceProductInfoConstantsEED2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android30AssetManagerForNdkAssetManagerEP13AAssetManager", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android30android_view_KeyEvent_toNativeEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android30register_android_os_HidlMemoryEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android30register_android_os_MemoryFileEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android30register_android_util_EventLogEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -576,7 +580,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android31throw_sqlite3_exception_errcodeEP7_JNIEnviPKc", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32CameraMetadata_getNativeMetadataEP7_JNIEnvP8_jobjectPNS_14CameraMetadataE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32SurfaceTexture_getSurfaceTextureEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android32android_view_KeyEvent_fromNativeEP7_JNIEnvRKNS_8KeyEventE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32android_view_MotionEvent_recycleEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32android_view_VerifiedMotionEventEP7_JNIEnvRKNS_19VerifiedMotionEventE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32register_android_os_FileObserverEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -595,6 +598,8 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android33register_android_view_MotionEventEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android33register_android_view_PointerIconEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android33register_android_view_TextureViewEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvRKNS_8KeyEventE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android34convertHdrCapabilitiesToJavaObjectEP7_JNIEnvRKNS_15HdrCapabilitiesE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android34register_android_os_HwRemoteBinderEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android34register_android_os_ServiceManagerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -689,6 +694,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android41android_view_MotionEvent_obtainFromNativeEP7_JNIEnvNSt3__110unique_ptrINS_11MotionEventENS2_14default_deleteIS4_EEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android41register_android_tracing_PerfettoProducerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android41register_android_view_VerifiedMotionEventEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android41register_android_view_WindowManagerGlobalEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42android_view_InputChannel_createJavaObjectEP7_JNIEnvNSt3__110unique_ptrINS_12InputChannelENS2_14default_deleteIS4_EEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42register_android_content_res_ConfigurationEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42register_android_content_res_ResourceTimerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -698,6 +704,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android42register_android_os_storage_StorageManagerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42register_android_service_DataLoaderServiceEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42register_android_view_DisplayEventReceiverEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android42register_android_window_InputTransferTokenEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android43register_android_tracing_PerfettoDataSourceEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android43register_android_window_WindowInfosListenerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android43register_com_android_internal_os_ZygoteInitEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -715,12 +722,10 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android47register_android_view_TunnelModeEnabledListenerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android47register_com_android_internal_content_F2fsUtilsEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android49android_hardware_display_DisplayViewport_toNativeEP7_JNIEnvP8_jobjectPNS_15DisplayViewportE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android49android_view_SurfaceControl_getJavaSurfaceControlEP7_JNIEnvRKNS_14SurfaceControlE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android49register_android_hardware_display_DisplayViewportEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android49register_android_view_CompositionSamplingListenerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android4base4TrimIRNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEEES8_OT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android4base9ParseUintImEEbPKcPT_S4_b", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android4base9ParseUintItEEbPKcPT_S4_b", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android4base9ParseUintIyEEbPKcPT_S4_b", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android50com_android_internal_os_ZygoteCommandBuffer_insertEP7_JNIEnvP7_jclassxP8_jstring", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android50register_android_os_incremental_IncrementalManagerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android50register_com_android_internal_security_VerityUtilsEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -751,6 +756,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android58com_android_internal_os_ZygoteCommandBuffer_nativeGetCountEP7_JNIEnvP7_jclassx", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android58register_com_android_internal_os_KernelSingleUidTimeReaderEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android59android_view_SurfaceTransaction_getNativeSurfaceTransactionEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android59android_window_InputTransferToken_getJavaInputTransferTokenEP7_JNIEnvRKNS_18InputTransferTokenE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android59com_android_internal_os_ZygoteCommandBuffer_getNativeBufferEP7_JNIEnvP7_jclassi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android59register_com_android_internal_content_om_OverlayManagerImplEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android59register_com_android_internal_os_KernelCpuTotalBpfMapReaderEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -766,6 +772,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android60android_view_InputApplicationHandle_fromInputApplicationInfoEP7_JNIEnvNS_3gui20InputApplicationInfoE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android60com_android_internal_os_ZygoteCommandBuffer_freeNativeBufferEP7_JNIEnvP7_jclassx", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android60register_com_android_internal_os_ZygoteInit_nativeZygoteInitEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android61android_window_InputTransferToken_getNativeInputTransferTokenEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android64com_android_internal_os_ZygoteCommandBuffer_nativeForkRepeatedlyEP7_JNIEnvP7_jclassxiiiP8_jstring", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android67android_hardware_display_DisplayManagerGlobal_signalNativeCallbacksEP7_JNIEnvP8_jobjectf", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android67com_android_internal_os_ZygoteCommandBuffer_nativeReadFullyAndResetEP7_JNIEnvP7_jclassx", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -966,9 +973,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZNK7android15JHwRemoteBinder9getBinderEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo13writeToParcelEPNS_6ParcelE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo16interceptsStylusEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android3gui10WindowInfo18frameContainsPointEii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo18supportsSplitTouchEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android3gui10WindowInfo28touchableRegionContainsPointEii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo5isSpyEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo8overlapsEPKS1_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfoeqERKS1_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -1190,6 +1195,8 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_RS6_RS8_RKNS_12placeholders4__phILi1EEEEEENSC_ISR_EEFvSE_EE7__cloneEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EE7__cloneEPNS0_6__baseISR_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EE7__cloneEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EE7__cloneEPNS0_6__baseISR_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EE7__cloneEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNKSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_E7__cloneEPNS0_6__baseIS2_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNKSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_E7__cloneEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNKSt3__110__function6__funcIPFvPvbENS_9allocatorIS4_EES3_E7__cloneEPNS0_6__baseIS3_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -1242,6 +1249,9 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EE18destroy_deallocateEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EE7destroyEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EEclEOSE_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EE18destroy_deallocateEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EE7destroyEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EEclESG_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_E18destroy_deallocateEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_E7destroyEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_EclEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
diff --git a/android_api/libandroid_runtime/proxy/trampolines_riscv64_to_x86_64-inl.h b/android_api/libandroid_runtime/proxy/trampolines_riscv64_to_x86_64-inl.h
index 5226b70..15237c8 100644
--- a/android_api/libandroid_runtime/proxy/trampolines_riscv64_to_x86_64-inl.h
+++ b/android_api/libandroid_runtime/proxy/trampolines_riscv64_to_x86_64-inl.h
@@ -38,6 +38,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_Z14SkStringPrintfPKcz", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z14StartIterationP10ZipArchivePPvNSt3__117basic_string_viewIcNS3_11char_traitsIcEEEES7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z14StartIterationP10ZipArchivePPvNSt3__18functionIFbNS3_17basic_string_viewIcNS3_11char_traitsIcEEEEEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_Z14sk_malloc_sizePvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z15ErrorCodeStringi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z15ExtractToMemoryP10ZipArchivePK10ZipEntry64Phm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z15ExtractToMemoryP10ZipArchivePK8ZipEntryPhm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -97,6 +98,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_Z34register_android_opengl_jni_GLES31P7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z34register_android_opengl_jni_GLES32P7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z35android_os_Process_killProcessGroupP7_JNIEnvP8_jobjectii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_Z35android_os_Process_sendSignalThrowsP7_JNIEnvP8_jobjectii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z35android_os_Process_setProcessFrozenP7_JNIEnvP8_jobjectiih", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z35convertAudioMixerAttributesToNativeP7_JNIEnvP8_jobjectP22audio_mixer_attributes", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z35register_android_hardware_SyncFenceP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -114,6 +116,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_Z37android_os_Process_getPidsForCommandsP7_JNIEnvP8_jobjectP13_jobjectArray", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37android_os_Process_getThreadSchedulerP7_JNIEnvP7_jclassi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37android_os_Process_parseProcLineArrayP7_JNIEnvP8_jobjectPciiP10_jintArrayP13_jobjectArrayP11_jlongArrayP12_jfloatArray", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_Z37android_os_Process_sendTgSignalThrowsP7_JNIEnvP8_jobjectiii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37android_os_Process_setThreadSchedulerP7_JNIEnvP7_jclassiii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37convertAudioMixerAttributesFromNativeP7_JNIEnvPK22audio_mixer_attributes", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_Z37register_android_media_MicrophoneInfoP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -184,12 +187,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN14JniInputStreamC2EP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN14JniInputStreamD0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN14JniInputStreamD2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN15CdEntryMapZip32I17ZipStringOffset20E14ResetIterationEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN15CdEntryMapZip32I17ZipStringOffset20E4NextEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN15CdEntryMapZip32I17ZipStringOffset20E8AddToMapENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN15CdEntryMapZip32I17ZipStringOffset32E14ResetIterationEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN15CdEntryMapZip32I17ZipStringOffset32E4NextEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN15CdEntryMapZip32I17ZipStringOffset32E8AddToMapENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN15CdEntryMapZip6414ResetIterationEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN15CdEntryMapZip644NextEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN15CdEntryMapZip648AddToMapENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -418,6 +415,8 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android18PerfettoDataSourceD0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android18PerfettoDataSourceD1Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android18PerfettoDataSourceD2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android18createInputChannelERKNS_2spINS_7IBinderEEERKNS_18InputTransferTokenERKNS_14SurfaceControlES7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android18removeInputChannelERKNS_2spINS_7IBinderEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android19parcelForJavaObjectEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android19register_jni_commonEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android20VelocityTrackerState11addMovementERKNS_11MotionEventE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -546,7 +545,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android29register_android_app_ActivityEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android29register_android_view_SurfaceEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android30AssetManagerForNdkAssetManagerEP13AAssetManager", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android30android_view_KeyEvent_toNativeEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android30register_android_os_HidlMemoryEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android30register_android_os_MemoryFileEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android30register_android_util_EventLogEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -561,7 +559,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android31throw_sqlite3_exception_errcodeEP7_JNIEnviPKc", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32CameraMetadata_getNativeMetadataEP7_JNIEnvP8_jobjectPNS_14CameraMetadataE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32SurfaceTexture_getSurfaceTextureEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android32android_view_KeyEvent_fromNativeEP7_JNIEnvRKNS_8KeyEventE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32android_view_MotionEvent_recycleEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32android_view_VerifiedMotionEventEP7_JNIEnvRKNS_19VerifiedMotionEventE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android32register_android_os_FileObserverEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -580,6 +577,8 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android33register_android_view_MotionEventEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android33register_android_view_PointerIconEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android33register_android_view_TextureViewEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvRKNS_8KeyEventE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android34convertHdrCapabilitiesToJavaObjectEP7_JNIEnvRKNS_15HdrCapabilitiesE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android34register_android_os_HwRemoteBinderEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android34register_android_os_ServiceManagerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -674,6 +673,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android41android_view_MotionEvent_obtainFromNativeEP7_JNIEnvNSt3__110unique_ptrINS_11MotionEventENS2_14default_deleteIS4_EEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android41register_android_tracing_PerfettoProducerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android41register_android_view_VerifiedMotionEventEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android41register_android_view_WindowManagerGlobalEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42android_view_InputChannel_createJavaObjectEP7_JNIEnvNSt3__110unique_ptrINS_12InputChannelENS2_14default_deleteIS4_EEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42register_android_content_res_ConfigurationEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42register_android_content_res_ResourceTimerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -683,6 +683,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android42register_android_os_storage_StorageManagerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42register_android_service_DataLoaderServiceEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android42register_android_view_DisplayEventReceiverEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android42register_android_window_InputTransferTokenEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android43register_android_tracing_PerfettoDataSourceEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android43register_android_window_WindowInfosListenerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android43register_com_android_internal_os_ZygoteInitEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -700,11 +701,9 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android47register_android_view_TunnelModeEnabledListenerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android47register_com_android_internal_content_F2fsUtilsEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android49android_hardware_display_DisplayViewport_toNativeEP7_JNIEnvP8_jobjectPNS_15DisplayViewportE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android49android_view_SurfaceControl_getJavaSurfaceControlEP7_JNIEnvRKNS_14SurfaceControlE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android49register_android_hardware_display_DisplayViewportEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android49register_android_view_CompositionSamplingListenerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android4base4TrimIRNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEEES8_OT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android4base9ParseUintImEEbPKcPT_S4_b", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android4base9ParseUintItEEbPKcPT_S4_b", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android50com_android_internal_os_ZygoteCommandBuffer_insertEP7_JNIEnvP7_jclasslP8_jstring", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android50register_android_os_incremental_IncrementalManagerEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android50register_com_android_internal_security_VerityUtilsEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -735,6 +734,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android58com_android_internal_os_ZygoteCommandBuffer_nativeGetCountEP7_JNIEnvP7_jclassl", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android58register_com_android_internal_os_KernelSingleUidTimeReaderEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android59android_view_SurfaceTransaction_getNativeSurfaceTransactionEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android59android_window_InputTransferToken_getJavaInputTransferTokenEP7_JNIEnvRKNS_18InputTransferTokenE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android59com_android_internal_os_ZygoteCommandBuffer_getNativeBufferEP7_JNIEnvP7_jclassi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android59register_com_android_internal_content_om_OverlayManagerImplEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android59register_com_android_internal_os_KernelCpuTotalBpfMapReaderEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -750,6 +750,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android60android_view_InputApplicationHandle_fromInputApplicationInfoEP7_JNIEnvNS_3gui20InputApplicationInfoE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android60com_android_internal_os_ZygoteCommandBuffer_freeNativeBufferEP7_JNIEnvP7_jclassl", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android60register_com_android_internal_os_ZygoteInit_nativeZygoteInitEP7_JNIEnv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"_ZN7android61android_window_InputTransferToken_getNativeInputTransferTokenEP7_JNIEnvP8_jobject", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android64com_android_internal_os_ZygoteCommandBuffer_nativeForkRepeatedlyEP7_JNIEnvP7_jclassliiiP8_jstring", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android67android_hardware_display_DisplayManagerGlobal_signalNativeCallbacksEP7_JNIEnvP8_jobjectf", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android67com_android_internal_os_ZygoteCommandBuffer_nativeReadFullyAndResetEP7_JNIEnvP7_jclassl", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -770,7 +771,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZN7android7JHwBlobC2EP7_JNIEnvP8_jobjectm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android7JHwBlobD0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android7JHwBlobD2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZN7android8hardware10fromBinderINS_4hidl4base4V1_05IBaseENS4_8BpHwBaseENS4_8BnHwBaseEEENS_2spIT_EERKNS8_INS0_7IBinderEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android8hardware7display27IDeviceProductInfoConstants11asInterfaceERKNS_2spINS_7IBinderEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android8hardware7display27IDeviceProductInfoConstants14getDefaultImplEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZN7android8hardware7display27IDeviceProductInfoConstants14setDefaultImplENS_2spIS2_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -897,8 +897,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZNK13NativeContext18getThumbnailHeightEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK13NativeContext9getResultEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK14ZipEntryCommon19GetModificationTimeEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK15CdEntryMapZip32I17ZipStringOffset20E16GetCdEntryOffsetENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK15CdEntryMapZip32I17ZipStringOffset32E16GetCdEntryOffsetENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK15CdEntryMapZip6416GetCdEntryOffsetENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEEPKh", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK16InputStripSource6getIfdEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK16JNICameraContext33isRawImageCallbackBufferAvailableEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -915,9 +913,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZNK7android15JHwRemoteBinder9getBinderEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo13writeToParcelEPNS_6ParcelE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo16interceptsStylusEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android3gui10WindowInfo18frameContainsPointEii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo18supportsSplitTouchEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android3gui10WindowInfo28touchableRegionContainsPointEii", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo5isSpyEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfo8overlapsEPKS1_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android3gui10WindowInfoeqERKS1_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -931,12 +927,6 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZNK7android3gui28IWindowInfosReportedListener22getInterfaceDescriptorEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android5vintf18KernelConfigParser5errorEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android5vintf18KernelConfigParser7configsEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android6VectorIiE10do_destroyEPvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android6VectorIiE12do_constructEPvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android6VectorIiE15do_move_forwardEPvPKvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android6VectorIiE16do_move_backwardEPvPKvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android6VectorIiE7do_copyEPvPKvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNK7android6VectorIiE8do_splatEPvPKvm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android7JHwBlob13writeToParcelEPNS_8hardware6ParcelE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android7JHwBlob21writeEmbeddedToParcelEPNS_8hardware6ParcelEmm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK7android7JHwBlob21writeSubBlobsToParcelEPNS_8hardware6ParcelEm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
@@ -971,128 +961,18 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"_ZNK8SkString6equalsERKS_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK9Transform3mapEiiPiS0_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNK9TransformeqERKS_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__110__back_refIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__110__l_anchorIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__110__r_anchorIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111__alternateIcE12__exec_splitEbRNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111__alternateIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111__end_stateIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111__lookaheadIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111__match_anyIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE21__match_at_start_ecmaINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE27__match_at_start_posix_subsINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE29__match_at_start_posix_nosubsINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE8__searchINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112__match_charIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112regex_traitsIcE18__lookup_classnameIPKcEEtT_S5_bc", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112regex_traitsIcE19__transform_primaryINS_11__wrap_iterIPcEEEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SC_c", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112regex_traitsIcE20__lookup_collatenameIPKcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SB_c", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112regex_traitsIcE20__lookup_collatenameIPcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SA_c", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112regex_traitsIcE9transformINS_11__wrap_iterIPcEEEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SC_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__112regex_traitsIcE9transformIPcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SA_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__113__empty_stateIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__115__word_boundaryIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNKSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__116__back_ref_icaseIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__117__repeat_one_loopIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__118__back_ref_collateIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__118__match_char_icaseIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__120__bracket_expressionIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__120__match_char_collateIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__121__empty_non_own_stateIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__126__end_marked_subexpressionIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__128__begin_marked_subexpressionIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__16__loopIcE12__exec_splitEbRNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNKSt3__16__loopIcE6__execERNS_7__stateIcEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE11__push_charEc", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE11__push_loopEmmPNS_16__owns_one_stateIcEEmmb", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_atomIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_grepIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_termIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE13__parse_egrepIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE15__push_back_refEi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE16__parse_ecma_expIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE16__push_lookaheadERKS3_bj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE17__parse_assertionIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE18__parse_awk_escapeIPKcEET_S7_S7_PNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE18__parse_nondupl_REIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE19__parse_alternativeIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE20__parse_ORD_CHAR_EREIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE20__parse_class_escapeIPKcEET_S7_S7_RNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPNS_20__bracket_expressionIcS2_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE21__parse_basic_reg_expIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_ERE_expressionIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_RE_dupl_symbolIPKcEET_S7_S7_PNS_16__owns_one_stateIcEEjj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_decimal_escapeIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_ERE_dupl_symbolIPKcEET_S7_S7_PNS_16__owns_one_stateIcEEjj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_QUOTED_CHAR_EREIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_expression_termIPKcEET_S7_S7_PNS_20__bracket_expressionIcS2_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_character_escapeIPKcEET_S7_S7_PNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_collating_symbolIPKcEET_S7_S7_RNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_extended_reg_expIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE25__parse_equivalence_classIPKcEET_S7_S7_PNS_20__bracket_expressionIcS2_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE25__parse_pattern_characterIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE26__parse_bracket_expressionIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE30__parse_character_class_escapeIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE32__parse_one_char_or_coll_elem_REIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE7__parseIPKcEET_S7_S7_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__112__deque_baseINS_7__stateIcEENS_9allocatorIS2_EEE5clearEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113__tree_removeIPNS_16__tree_node_baseIPvEEEEvT_S5_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE4syncEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE5imbueERKNS_6localeE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE6setbufEPcl", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE7seekoffExNS_8ios_base7seekdirEj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE7seekposENS_4fposI9mbstate_tEEj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE8overflowEi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE9pbackfailEi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE9underflowEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEEC2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE10push_frontEOS3_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE10push_frontERKS3_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE9push_backEOS3_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__114__split_bufferIPNS_7__stateIcEERNS_9allocatorIS3_EEE10push_frontERKS3_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__114__split_bufferIPNS_7__stateIcEERNS_9allocatorIS3_EEE9push_backEOS3_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strERKNS_12basic_stringIcS2_S4_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE7seekoffExNS_8ios_base7seekdirEj", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE8overflowEi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE9pbackfailEi", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE9underflowEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__116__owns_one_stateIcED0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__116__owns_one_stateIcED2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__117__call_once_proxyINS_5tupleIJRFvvEEEEEEvPv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__117__owns_two_statesIcED0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__117__owns_two_statesIcED2Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__120__shared_ptr_pointerIPNS_13__empty_stateIcEENS_14default_deleteIS2_EENS_9allocatorIS2_EEE16__on_zero_sharedEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__120__shared_ptr_pointerIPNS_13__empty_stateIcEENS_14default_deleteIS2_EENS_9allocatorIS2_EEE21__on_zero_shared_weakEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__124__put_character_sequenceIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__127__tree_balance_after_insertIPNS_16__tree_node_baseIPvEEEEvT_S5_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__15dequeINS_7__stateIcEENS_9allocatorIS2_EEE19__add_back_capacityEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__15dequeINS_7__stateIcEENS_9allocatorIS2_EEE20__add_front_capacityEv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16__treeINS_12__value_typeINS_17basic_string_viewIcNS_11char_traitsIcEEEEmEENS_19__map_value_compareIS5_S6_NS_4lessIS5_EELb1EEENS_9allocatorIS6_EEE25__emplace_unique_key_argsIS5_JNS_4pairIKS5_mEEEEENSF_INS_15__tree_iteratorIS6_PNS_11__tree_nodeIS6_PvEElEEbEERKT_DpOT0_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16__treeINS_12__value_typeINS_17basic_string_viewIcNS_11char_traitsIcEEEEmEENS_19__map_value_compareIS5_S6_NS_4lessIS5_EELb1EEENS_9allocatorIS6_EEE7destroyEPNS_11__tree_nodeIS6_PvEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16__treeIiNS_4lessIiEENS_9allocatorIiEEE7destroyEPNS_11__tree_nodeIiPvEE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIRKS6_EEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIS6_EEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_4pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_EENS5_IS8_EEE21__push_back_slow_pathIS8_EEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_4pairIccEENS_9allocatorIS2_EEE21__push_back_slow_pathIS2_EEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_4pairImPKcEENS_9allocatorIS4_EEE6assignIPS4_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS4_NS_15iterator_traitsISB_E9referenceEEE5valueEvE4typeESB_SB_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_4pairImPKcEENS_9allocatorIS4_EEE8__appendEm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_7__stateIcEENS_9allocatorIS2_EEE21__push_back_slow_pathIS2_EEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_9sub_matchINS_11__wrap_iterIPKcEEEENS_9allocatorIS6_EEE8__appendEm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE6assignEmRKS4_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE6assignIPS4_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS4_NS_15iterator_traitsISB_E9referenceEEE5valueEvE4typeESB_SB_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE8__appendEmRKS4_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorIcNS_9allocatorIcEEE21__push_back_slow_pathIRKcEEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorIcNS_9allocatorIcEEE21__push_back_slow_pathIcEEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorIhNS_9allocatorIhEEE6resizeEm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__16vectorIhNS_9allocatorIhEEE8__appendEm", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__16vectorIiNS_9allocatorIiEEE21__push_back_slow_pathIiEEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__16vectorIjNS_9allocatorIjEEE21__push_back_slow_pathIjEEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__16vectorIlNS_9allocatorIlEEE21__push_back_slow_pathIlEEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZNSt3__16vectorImNS_9allocatorImEEE21__push_back_slow_pathImEEvOT_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__17getlineIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EES6_", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
-{"_ZNSt3__1lsIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_ostreamIT_T0_EES9_RKNS_12basic_stringIS6_S7_T1_EE", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZThn16_N7android18NativeMessageQueue11handleEventEiiPv", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZThn16_N7android18NativeMessageQueueD0Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"_ZThn16_N7android18NativeMessageQueueD1Ev", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
diff --git a/android_api/libandroid_runtime/stubs_arm.cc b/android_api/libandroid_runtime/stubs_arm.cc
index ed2f935..8a42eaa 100644
--- a/android_api/libandroid_runtime/stubs_arm.cc
+++ b/android_api/libandroid_runtime/stubs_arm.cc
@@ -55,6 +55,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14GetArchiveInfoP10ZipArchive);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14SkStringPrintfPKcz);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14StartIterationP10ZipArchivePPvNSt3__117basic_string_viewIcNS3_11char_traitsIcEEEES7_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14StartIterationP10ZipArchivePPvNSt3__18functionIFbNS3_17basic_string_viewIcNS3_11char_traitsIcEEEEEEE);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14sk_malloc_sizePvj);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z15ErrorCodeStringi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z15ExtractToMemoryP10ZipArchivePK10ZipEntry64Phj);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z15ExtractToMemoryP10ZipArchivePK8ZipEntryPhj);
@@ -114,6 +115,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z34register_android_opengl_jni_GLES30P7_JNIE
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z34register_android_opengl_jni_GLES31P7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z34register_android_opengl_jni_GLES32P7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35android_os_Process_killProcessGroupP7_JNIEnvP8_jobjectii);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35android_os_Process_sendSignalThrowsP7_JNIEnvP8_jobjectii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35android_os_Process_setProcessFrozenP7_JNIEnvP8_jobjectiih);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35convertAudioMixerAttributesToNativeP7_JNIEnvP8_jobjectP22audio_mixer_attributes);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35register_android_hardware_SyncFenceP7_JNIEnv);
@@ -131,6 +133,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_createProcessGroupP7_J
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_getPidsForCommandsP7_JNIEnvP8_jobjectP13_jobjectArray);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_getThreadSchedulerP7_JNIEnvP7_jclassi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_parseProcLineArrayP7_JNIEnvP8_jobjectPciiP10_jintArrayP13_jobjectArrayP11_jlongArrayP12_jfloatArray);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_sendTgSignalThrowsP7_JNIEnvP8_jobjectiii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_setThreadSchedulerP7_JNIEnvP7_jclassiii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37convertAudioMixerAttributesFromNativeP7_JNIEnvPK22audio_mixer_attributes);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37register_android_media_MicrophoneInfoP7_JNIEnv);
@@ -444,6 +447,8 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18PerfettoDataSourceC2EP7_JNIEnvP8
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18PerfettoDataSourceD0Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18PerfettoDataSourceD1Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18PerfettoDataSourceD2Ev);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18createInputChannelERKNS_2spINS_7IBinderEEERKNS_18InputTransferTokenERKNS_14SurfaceControlES7_);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18removeInputChannelERKNS_2spINS_7IBinderEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android19parcelForJavaObjectEP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android19register_jni_commonEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android20VelocityTrackerState11addMovementERKNS_11MotionEventE);
@@ -578,7 +583,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android2spINS_30TransactionHangCallbackWr
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android2spINS_3gui28IWindowInfosReportedListenerEED2Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android2spINS_8hardware7display27IDeviceProductInfoConstantsEED2Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30AssetManagerForNdkAssetManagerEP13AAssetManager);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30android_view_KeyEvent_toNativeEP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30register_android_os_HidlMemoryEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30register_android_os_MemoryFileEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30register_android_util_EventLogEP7_JNIEnv);
@@ -593,7 +597,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android31register_android_os_SystemClockE
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android31throw_sqlite3_exception_errcodeEP7_JNIEnviPKc);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32CameraMetadata_getNativeMetadataEP7_JNIEnvP8_jobjectPNS_14CameraMetadataE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32SurfaceTexture_getSurfaceTextureEP7_JNIEnvP8_jobject);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32android_view_KeyEvent_fromNativeEP7_JNIEnvRKNS_8KeyEventE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32android_view_MotionEvent_recycleEP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32android_view_VerifiedMotionEventEP7_JNIEnvRKNS_19VerifiedMotionEventE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32register_android_os_FileObserverEP7_JNIEnv);
@@ -612,6 +615,8 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android33register_android_view_InputDevic
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android33register_android_view_MotionEventEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android33register_android_view_PointerIconEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android33register_android_view_TextureViewEP7_JNIEnv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvP8_jobject);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvRKNS_8KeyEventE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34convertHdrCapabilitiesToJavaObjectEP7_JNIEnvRKNS_15HdrCapabilitiesE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34register_android_os_HwRemoteBinderEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34register_android_os_ServiceManagerEP7_JNIEnv);
@@ -706,6 +711,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41android_view_InputChannel_getInp
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41android_view_MotionEvent_obtainFromNativeEP7_JNIEnvNSt3__110unique_ptrINS_11MotionEventENS2_14default_deleteIS4_EEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41register_android_tracing_PerfettoProducerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41register_android_view_VerifiedMotionEventEP7_JNIEnv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41register_android_view_WindowManagerGlobalEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42android_view_InputChannel_createJavaObjectEP7_JNIEnvNSt3__110unique_ptrINS_12InputChannelENS2_14default_deleteIS4_EEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_content_res_ConfigurationEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_content_res_ResourceTimerEP7_JNIEnv);
@@ -715,6 +721,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_os_PerformanceH
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_os_storage_StorageManagerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_service_DataLoaderServiceEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_view_DisplayEventReceiverEP7_JNIEnv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_window_InputTransferTokenEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android43register_android_tracing_PerfettoDataSourceEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android43register_android_window_WindowInfosListenerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android43register_com_android_internal_os_ZygoteInitEP7_JNIEnv);
@@ -732,12 +739,10 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android47register_android_animation_Prope
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android47register_android_view_TunnelModeEnabledListenerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android47register_com_android_internal_content_F2fsUtilsEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android49android_hardware_display_DisplayViewport_toNativeEP7_JNIEnvP8_jobjectPNS_15DisplayViewportE);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android49android_view_SurfaceControl_getJavaSurfaceControlEP7_JNIEnvRKNS_14SurfaceControlE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android49register_android_hardware_display_DisplayViewportEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android49register_android_view_CompositionSamplingListenerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android4base4TrimIRNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEEES8_OT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android4base9ParseUintImEEbPKcPT_S4_b);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android4base9ParseUintItEEbPKcPT_S4_b);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android4base9ParseUintIyEEbPKcPT_S4_b);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android50com_android_internal_os_ZygoteCommandBuffer_insertEP7_JNIEnvP7_jclassxP8_jstring);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android50register_android_os_incremental_IncrementalManagerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android50register_com_android_internal_security_VerityUtilsEP7_JNIEnv);
@@ -768,6 +773,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android57register_com_android_internal_os
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android58com_android_internal_os_ZygoteCommandBuffer_nativeGetCountEP7_JNIEnvP7_jclassx);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android58register_com_android_internal_os_KernelSingleUidTimeReaderEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59android_view_SurfaceTransaction_getNativeSurfaceTransactionEP7_JNIEnvP8_jobject);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59android_window_InputTransferToken_getJavaInputTransferTokenEP7_JNIEnvRKNS_18InputTransferTokenE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59com_android_internal_os_ZygoteCommandBuffer_getNativeBufferEP7_JNIEnvP7_jclassi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59register_com_android_internal_content_om_OverlayManagerImplEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59register_com_android_internal_os_KernelCpuTotalBpfMapReaderEP7_JNIEnv);
@@ -783,6 +789,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android5vintf18trimTrailingSpacesERKNSt3_
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android60android_view_InputApplicationHandle_fromInputApplicationInfoEP7_JNIEnvNS_3gui20InputApplicationInfoE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android60com_android_internal_os_ZygoteCommandBuffer_freeNativeBufferEP7_JNIEnvP7_jclassx);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android60register_com_android_internal_os_ZygoteInit_nativeZygoteInitEP7_JNIEnv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android61android_window_InputTransferToken_getNativeInputTransferTokenEP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android64com_android_internal_os_ZygoteCommandBuffer_nativeForkRepeatedlyEP7_JNIEnvP7_jclassxiiiP8_jstring);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android67android_hardware_display_DisplayManagerGlobal_signalNativeCallbacksEP7_JNIEnvP8_jobjectf);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android67com_android_internal_os_ZygoteCommandBuffer_nativeReadFullyAndResetEP7_JNIEnvP7_jclassx);
@@ -983,9 +990,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android15JHwRemoteBinder21getDeathRecipi
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android15JHwRemoteBinder9getBinderEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo13writeToParcelEPNS_6ParcelE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo16interceptsStylusEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo18frameContainsPointEii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo18supportsSplitTouchEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo28touchableRegionContainsPointEii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo5isSpyEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo8overlapsEPKS1_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfoeqERKS1_);
@@ -1207,6 +1212,8 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__function6__funcINS_6__bindIRFvP
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_RS6_RS8_RKNS_12placeholders4__phILi1EEEEEENSC_ISR_EEFvSE_EE7__cloneEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EE7__cloneEPNS0_6__baseISR_EE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EE7__cloneEv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EE7__cloneEPNS0_6__baseISR_EE);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EE7__cloneEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_E7__cloneEPNS0_6__baseIS2_EE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_E7__cloneEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__function6__funcIPFvPvbENS_9allocatorIS4_EES3_E7__cloneEPNS0_6__baseIS3_EE);
@@ -1259,6 +1266,9 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__110__function6__funcINS_6__bindIRFvP7
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EE18destroy_deallocateEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EE7destroyEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EEclEOSE_);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EE18destroy_deallocateEv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EE7destroyEv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EEclESG_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_E18destroy_deallocateEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_E7destroyEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_EclEv);
@@ -1564,6 +1574,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z14SkStringPrintfPKcz);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z14StartIterationP10ZipArchivePPvNSt3__117basic_string_viewIcNS3_11char_traitsIcEEEES7_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z14StartIterationP10ZipArchivePPvNSt3__18functionIFbNS3_17basic_string_viewIcNS3_11char_traitsIcEEEEEEE);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z14sk_malloc_sizePvj);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z15ErrorCodeStringi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z15ExtractToMemoryP10ZipArchivePK10ZipEntry64Phj);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z15ExtractToMemoryP10ZipArchivePK8ZipEntryPhj);
@@ -1623,6 +1634,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z34register_android_opengl_jni_GLES31P7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z34register_android_opengl_jni_GLES32P7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35android_os_Process_killProcessGroupP7_JNIEnvP8_jobjectii);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35android_os_Process_sendSignalThrowsP7_JNIEnvP8_jobjectii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35android_os_Process_setProcessFrozenP7_JNIEnvP8_jobjectiih);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35convertAudioMixerAttributesToNativeP7_JNIEnvP8_jobjectP22audio_mixer_attributes);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35register_android_hardware_SyncFenceP7_JNIEnv);
@@ -1640,6 +1652,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_getPidsForCommandsP7_JNIEnvP8_jobjectP13_jobjectArray);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_getThreadSchedulerP7_JNIEnvP7_jclassi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_parseProcLineArrayP7_JNIEnvP8_jobjectPciiP10_jintArrayP13_jobjectArrayP11_jlongArrayP12_jfloatArray);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_sendTgSignalThrowsP7_JNIEnvP8_jobjectiii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_setThreadSchedulerP7_JNIEnvP7_jclassiii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37convertAudioMixerAttributesFromNativeP7_JNIEnvPK22audio_mixer_attributes);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37register_android_media_MicrophoneInfoP7_JNIEnv);
@@ -1953,6 +1966,8 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18PerfettoDataSourceD0Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18PerfettoDataSourceD1Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18PerfettoDataSourceD2Ev);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18createInputChannelERKNS_2spINS_7IBinderEEERKNS_18InputTransferTokenERKNS_14SurfaceControlES7_);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18removeInputChannelERKNS_2spINS_7IBinderEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android19parcelForJavaObjectEP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android19register_jni_commonEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android20VelocityTrackerState11addMovementERKNS_11MotionEventE);
@@ -2087,7 +2102,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android2spINS_3gui28IWindowInfosReportedListenerEED2Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android2spINS_8hardware7display27IDeviceProductInfoConstantsEED2Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30AssetManagerForNdkAssetManagerEP13AAssetManager);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30android_view_KeyEvent_toNativeEP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30register_android_os_HidlMemoryEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30register_android_os_MemoryFileEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30register_android_util_EventLogEP7_JNIEnv);
@@ -2102,7 +2116,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android31throw_sqlite3_exception_errcodeEP7_JNIEnviPKc);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32CameraMetadata_getNativeMetadataEP7_JNIEnvP8_jobjectPNS_14CameraMetadataE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32SurfaceTexture_getSurfaceTextureEP7_JNIEnvP8_jobject);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32android_view_KeyEvent_fromNativeEP7_JNIEnvRKNS_8KeyEventE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32android_view_MotionEvent_recycleEP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32android_view_VerifiedMotionEventEP7_JNIEnvRKNS_19VerifiedMotionEventE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32register_android_os_FileObserverEP7_JNIEnv);
@@ -2121,6 +2134,8 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android33register_android_view_MotionEventEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android33register_android_view_PointerIconEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android33register_android_view_TextureViewEP7_JNIEnv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvP8_jobject);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvRKNS_8KeyEventE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34convertHdrCapabilitiesToJavaObjectEP7_JNIEnvRKNS_15HdrCapabilitiesE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34register_android_os_HwRemoteBinderEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34register_android_os_ServiceManagerEP7_JNIEnv);
@@ -2215,6 +2230,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android41android_view_MotionEvent_obtainFromNativeEP7_JNIEnvNSt3__110unique_ptrINS_11MotionEventENS2_14default_deleteIS4_EEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android41register_android_tracing_PerfettoProducerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android41register_android_view_VerifiedMotionEventEP7_JNIEnv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android41register_android_view_WindowManagerGlobalEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42android_view_InputChannel_createJavaObjectEP7_JNIEnvNSt3__110unique_ptrINS_12InputChannelENS2_14default_deleteIS4_EEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_content_res_ConfigurationEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_content_res_ResourceTimerEP7_JNIEnv);
@@ -2224,6 +2240,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_os_storage_StorageManagerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_service_DataLoaderServiceEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_view_DisplayEventReceiverEP7_JNIEnv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_window_InputTransferTokenEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android43register_android_tracing_PerfettoDataSourceEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android43register_android_window_WindowInfosListenerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android43register_com_android_internal_os_ZygoteInitEP7_JNIEnv);
@@ -2241,12 +2258,10 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android47register_android_view_TunnelModeEnabledListenerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android47register_com_android_internal_content_F2fsUtilsEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android49android_hardware_display_DisplayViewport_toNativeEP7_JNIEnvP8_jobjectPNS_15DisplayViewportE);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android49android_view_SurfaceControl_getJavaSurfaceControlEP7_JNIEnvRKNS_14SurfaceControlE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android49register_android_hardware_display_DisplayViewportEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android49register_android_view_CompositionSamplingListenerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android4base4TrimIRNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEEES8_OT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android4base9ParseUintImEEbPKcPT_S4_b);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android4base9ParseUintItEEbPKcPT_S4_b);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android4base9ParseUintIyEEbPKcPT_S4_b);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android50com_android_internal_os_ZygoteCommandBuffer_insertEP7_JNIEnvP7_jclassxP8_jstring);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android50register_android_os_incremental_IncrementalManagerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android50register_com_android_internal_security_VerityUtilsEP7_JNIEnv);
@@ -2277,6 +2292,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android58com_android_internal_os_ZygoteCommandBuffer_nativeGetCountEP7_JNIEnvP7_jclassx);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android58register_com_android_internal_os_KernelSingleUidTimeReaderEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59android_view_SurfaceTransaction_getNativeSurfaceTransactionEP7_JNIEnvP8_jobject);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59android_window_InputTransferToken_getJavaInputTransferTokenEP7_JNIEnvRKNS_18InputTransferTokenE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59com_android_internal_os_ZygoteCommandBuffer_getNativeBufferEP7_JNIEnvP7_jclassi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59register_com_android_internal_content_om_OverlayManagerImplEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59register_com_android_internal_os_KernelCpuTotalBpfMapReaderEP7_JNIEnv);
@@ -2292,6 +2308,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android60android_view_InputApplicationHandle_fromInputApplicationInfoEP7_JNIEnvNS_3gui20InputApplicationInfoE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android60com_android_internal_os_ZygoteCommandBuffer_freeNativeBufferEP7_JNIEnvP7_jclassx);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android60register_com_android_internal_os_ZygoteInit_nativeZygoteInitEP7_JNIEnv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android61android_window_InputTransferToken_getNativeInputTransferTokenEP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android64com_android_internal_os_ZygoteCommandBuffer_nativeForkRepeatedlyEP7_JNIEnvP7_jclassxiiiP8_jstring);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android67android_hardware_display_DisplayManagerGlobal_signalNativeCallbacksEP7_JNIEnvP8_jobjectf);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android67com_android_internal_os_ZygoteCommandBuffer_nativeReadFullyAndResetEP7_JNIEnvP7_jclassx);
@@ -2492,9 +2509,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android15JHwRemoteBinder9getBinderEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo13writeToParcelEPNS_6ParcelE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo16interceptsStylusEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo18frameContainsPointEii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo18supportsSplitTouchEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo28touchableRegionContainsPointEii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo5isSpyEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo8overlapsEPKS1_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfoeqERKS1_);
@@ -2716,6 +2731,8 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_RS6_RS8_RKNS_12placeholders4__phILi1EEEEEENSC_ISR_EEFvSE_EE7__cloneEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EE7__cloneEPNS0_6__baseISR_EE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EE7__cloneEv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EE7__cloneEPNS0_6__baseISR_EE);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EE7__cloneEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_E7__cloneEPNS0_6__baseIS2_EE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_E7__cloneEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__function6__funcIPFvPvbENS_9allocatorIS4_EES3_E7__cloneEPNS0_6__baseIS3_EE);
@@ -2768,6 +2785,9 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EE18destroy_deallocateEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EE7destroyEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_DnRKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSE_EEclEOSE_);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EE18destroy_deallocateEv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EE7destroyEv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__110__function6__funcINS_6__bindIRFvP7_JNIEnvPKcP8_jstringRKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEJRS4_S6_S8_RKNS_12placeholders4__phILi1EEEEEENSC_ISP_EEFvSG_EEclESG_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_E18destroy_deallocateEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_E7destroyEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__110__function6__funcIPFbvENS_9allocatorIS3_EES2_EclEv);
diff --git a/android_api/libandroid_runtime/stubs_arm64.cc b/android_api/libandroid_runtime/stubs_arm64.cc
index 525581e..1c99f50 100644
--- a/android_api/libandroid_runtime/stubs_arm64.cc
+++ b/android_api/libandroid_runtime/stubs_arm64.cc
@@ -55,6 +55,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14GetArchiveInfoP10ZipArchive);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14SkStringPrintfPKcz);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14StartIterationP10ZipArchivePPvNSt3__117basic_string_viewIcNS3_11char_traitsIcEEEES7_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14StartIterationP10ZipArchivePPvNSt3__18functionIFbNS3_17basic_string_viewIcNS3_11char_traitsIcEEEEEEE);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14sk_malloc_sizePvm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z15ErrorCodeStringi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z15ExtractToMemoryP10ZipArchivePK10ZipEntry64Phm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z15ExtractToMemoryP10ZipArchivePK8ZipEntryPhm);
@@ -114,6 +115,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z34register_android_opengl_jni_GLES30P7_JNIE
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z34register_android_opengl_jni_GLES31P7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z34register_android_opengl_jni_GLES32P7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35android_os_Process_killProcessGroupP7_JNIEnvP8_jobjectii);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35android_os_Process_sendSignalThrowsP7_JNIEnvP8_jobjectii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35android_os_Process_setProcessFrozenP7_JNIEnvP8_jobjectiih);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35convertAudioMixerAttributesToNativeP7_JNIEnvP8_jobjectP22audio_mixer_attributes);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35register_android_hardware_SyncFenceP7_JNIEnv);
@@ -131,6 +133,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_createProcessGroupP7_J
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_getPidsForCommandsP7_JNIEnvP8_jobjectP13_jobjectArray);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_getThreadSchedulerP7_JNIEnvP7_jclassi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_parseProcLineArrayP7_JNIEnvP8_jobjectPciiP10_jintArrayP13_jobjectArrayP11_jlongArrayP12_jfloatArray);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_sendTgSignalThrowsP7_JNIEnvP8_jobjectiii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_setThreadSchedulerP7_JNIEnvP7_jclassiii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37convertAudioMixerAttributesFromNativeP7_JNIEnvPK22audio_mixer_attributes);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37register_android_media_MicrophoneInfoP7_JNIEnv);
@@ -201,12 +204,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN14JniInputStream5closeEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN14JniInputStreamC2EP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN14JniInputStreamD0Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN14JniInputStreamD2Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip32I17ZipStringOffset20E14ResetIterationEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip32I17ZipStringOffset20E4NextEPKh);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip32I17ZipStringOffset20E8AddToMapENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip32I17ZipStringOffset32E14ResetIterationEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip32I17ZipStringOffset32E4NextEPKh);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip32I17ZipStringOffset32E8AddToMapENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip6414ResetIterationEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip644NextEPKh);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip648AddToMapENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEEPKh);
@@ -435,6 +432,8 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18PerfettoDataSourceC2EP7_JNIEnvP8
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18PerfettoDataSourceD0Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18PerfettoDataSourceD1Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18PerfettoDataSourceD2Ev);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18createInputChannelERKNS_2spINS_7IBinderEEERKNS_18InputTransferTokenERKNS_14SurfaceControlES7_);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18removeInputChannelERKNS_2spINS_7IBinderEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android19parcelForJavaObjectEP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android19register_jni_commonEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android20VelocityTrackerState11addMovementERKNS_11MotionEventE);
@@ -563,7 +562,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android29android_view_VerifiedKeyEventEP7
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android29register_android_app_ActivityEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android29register_android_view_SurfaceEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30AssetManagerForNdkAssetManagerEP13AAssetManager);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30android_view_KeyEvent_toNativeEP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30register_android_os_HidlMemoryEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30register_android_os_MemoryFileEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30register_android_util_EventLogEP7_JNIEnv);
@@ -578,7 +576,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android31register_android_os_SystemClockE
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android31throw_sqlite3_exception_errcodeEP7_JNIEnviPKc);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32CameraMetadata_getNativeMetadataEP7_JNIEnvP8_jobjectPNS_14CameraMetadataE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32SurfaceTexture_getSurfaceTextureEP7_JNIEnvP8_jobject);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32android_view_KeyEvent_fromNativeEP7_JNIEnvRKNS_8KeyEventE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32android_view_MotionEvent_recycleEP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32android_view_VerifiedMotionEventEP7_JNIEnvRKNS_19VerifiedMotionEventE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32register_android_os_FileObserverEP7_JNIEnv);
@@ -597,6 +594,8 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android33register_android_view_InputDevic
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android33register_android_view_MotionEventEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android33register_android_view_PointerIconEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android33register_android_view_TextureViewEP7_JNIEnv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvP8_jobject);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvRKNS_8KeyEventE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34convertHdrCapabilitiesToJavaObjectEP7_JNIEnvRKNS_15HdrCapabilitiesE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34register_android_os_HwRemoteBinderEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34register_android_os_ServiceManagerEP7_JNIEnv);
@@ -691,6 +690,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41android_view_InputChannel_getInp
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41android_view_MotionEvent_obtainFromNativeEP7_JNIEnvNSt3__110unique_ptrINS_11MotionEventENS2_14default_deleteIS4_EEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41register_android_tracing_PerfettoProducerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41register_android_view_VerifiedMotionEventEP7_JNIEnv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41register_android_view_WindowManagerGlobalEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42android_view_InputChannel_createJavaObjectEP7_JNIEnvNSt3__110unique_ptrINS_12InputChannelENS2_14default_deleteIS4_EEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_content_res_ConfigurationEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_content_res_ResourceTimerEP7_JNIEnv);
@@ -700,6 +700,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_os_PerformanceH
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_os_storage_StorageManagerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_service_DataLoaderServiceEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_view_DisplayEventReceiverEP7_JNIEnv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_window_InputTransferTokenEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android43register_android_tracing_PerfettoDataSourceEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android43register_android_window_WindowInfosListenerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android43register_com_android_internal_os_ZygoteInitEP7_JNIEnv);
@@ -717,11 +718,9 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android47register_android_animation_Prope
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android47register_android_view_TunnelModeEnabledListenerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android47register_com_android_internal_content_F2fsUtilsEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android49android_hardware_display_DisplayViewport_toNativeEP7_JNIEnvP8_jobjectPNS_15DisplayViewportE);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android49android_view_SurfaceControl_getJavaSurfaceControlEP7_JNIEnvRKNS_14SurfaceControlE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android49register_android_hardware_display_DisplayViewportEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android49register_android_view_CompositionSamplingListenerEP7_JNIEnv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android4base4TrimIRNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEEES8_OT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android4base9ParseUintImEEbPKcPT_S4_b);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android4base9ParseUintItEEbPKcPT_S4_b);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android50com_android_internal_os_ZygoteCommandBuffer_insertEP7_JNIEnvP7_jclasslP8_jstring);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android50register_android_os_incremental_IncrementalManagerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android50register_com_android_internal_security_VerityUtilsEP7_JNIEnv);
@@ -752,6 +751,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android57register_com_android_internal_os
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android58com_android_internal_os_ZygoteCommandBuffer_nativeGetCountEP7_JNIEnvP7_jclassl);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android58register_com_android_internal_os_KernelSingleUidTimeReaderEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59android_view_SurfaceTransaction_getNativeSurfaceTransactionEP7_JNIEnvP8_jobject);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59android_window_InputTransferToken_getJavaInputTransferTokenEP7_JNIEnvRKNS_18InputTransferTokenE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59com_android_internal_os_ZygoteCommandBuffer_getNativeBufferEP7_JNIEnvP7_jclassi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59register_com_android_internal_content_om_OverlayManagerImplEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59register_com_android_internal_os_KernelCpuTotalBpfMapReaderEP7_JNIEnv);
@@ -767,6 +767,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android5vintf18trimTrailingSpacesERKNSt3_
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android60android_view_InputApplicationHandle_fromInputApplicationInfoEP7_JNIEnvNS_3gui20InputApplicationInfoE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android60com_android_internal_os_ZygoteCommandBuffer_freeNativeBufferEP7_JNIEnvP7_jclassl);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android60register_com_android_internal_os_ZygoteInit_nativeZygoteInitEP7_JNIEnv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android61android_window_InputTransferToken_getNativeInputTransferTokenEP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android64com_android_internal_os_ZygoteCommandBuffer_nativeForkRepeatedlyEP7_JNIEnvP7_jclassliiiP8_jstring);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android67android_hardware_display_DisplayManagerGlobal_signalNativeCallbacksEP7_JNIEnvP8_jobjectf);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android67com_android_internal_os_ZygoteCommandBuffer_nativeReadFullyAndResetEP7_JNIEnvP7_jclassl);
@@ -787,7 +788,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android7JHwBlob9NewObjectEP7_JNIEnvm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android7JHwBlobC2EP7_JNIEnvP8_jobjectm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android7JHwBlobD0Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android7JHwBlobD2Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android8hardware10fromBinderINS_4hidl4base4V1_05IBaseENS4_8BpHwBaseENS4_8BnHwBaseEEENS_2spIT_EERKNS8_INS0_7IBinderEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android8hardware7display27IDeviceProductInfoConstants11asInterfaceERKNS_2spINS_7IBinderEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android8hardware7display27IDeviceProductInfoConstants14getDefaultImplEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android8hardware7display27IDeviceProductInfoConstants14setDefaultImplENS_2spIS2_EE);
@@ -914,8 +914,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK13NativeContext18getCharacteristicsEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK13NativeContext18getThumbnailHeightEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK13NativeContext9getResultEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK14ZipEntryCommon19GetModificationTimeEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK15CdEntryMapZip32I17ZipStringOffset20E16GetCdEntryOffsetENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK15CdEntryMapZip32I17ZipStringOffset32E16GetCdEntryOffsetENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK15CdEntryMapZip6416GetCdEntryOffsetENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEEPKh);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK16InputStripSource6getIfdEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK16JNICameraContext33isRawImageCallbackBufferAvailableEv);
@@ -932,9 +930,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android15JHwRemoteBinder21getDeathRecipi
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android15JHwRemoteBinder9getBinderEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo13writeToParcelEPNS_6ParcelE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo16interceptsStylusEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo18frameContainsPointEii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo18supportsSplitTouchEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo28touchableRegionContainsPointEii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo5isSpyEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo8overlapsEPKS1_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfoeqERKS1_);
@@ -948,12 +944,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui22StalledTransactionInfo13wri
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui28IWindowInfosReportedListener22getInterfaceDescriptorEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android5vintf18KernelConfigParser5errorEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android5vintf18KernelConfigParser7configsEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android6VectorIiE10do_destroyEPvm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android6VectorIiE12do_constructEPvm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android6VectorIiE15do_move_forwardEPvPKvm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android6VectorIiE16do_move_backwardEPvPKvm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android6VectorIiE7do_copyEPvPKvm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android6VectorIiE8do_splatEPvPKvm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android7JHwBlob13writeToParcelEPNS_8hardware6ParcelE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android7JHwBlob21writeEmbeddedToParcelEPNS_8hardware6ParcelEmm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android7JHwBlob21writeSubBlobsToParcelEPNS_8hardware6ParcelEm);
@@ -988,128 +978,18 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK8SkString6equalsEPKcm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK8SkString6equalsERKS_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK9Transform3mapEiiPiS0_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK9TransformeqERKS_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__back_refIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__l_anchorIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__r_anchorIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111__alternateIcE12__exec_splitEbRNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111__alternateIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111__end_stateIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111__lookaheadIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111__match_anyIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE21__match_at_start_ecmaINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE27__match_at_start_posix_subsINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE29__match_at_start_posix_nosubsINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE8__searchINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112__match_charIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112regex_traitsIcE18__lookup_classnameIPKcEEtT_S5_bc);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112regex_traitsIcE19__transform_primaryINS_11__wrap_iterIPcEEEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SC_c);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112regex_traitsIcE20__lookup_collatenameIPKcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SB_c);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112regex_traitsIcE20__lookup_collatenameIPcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SA_c);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112regex_traitsIcE9transformINS_11__wrap_iterIPcEEEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SC_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112regex_traitsIcE9transformIPcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SA_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__113__empty_stateIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__115__word_boundaryIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__116__back_ref_icaseIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__117__repeat_one_loopIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__118__back_ref_collateIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__118__match_char_icaseIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__120__bracket_expressionIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__120__match_char_collateIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__121__empty_non_own_stateIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__126__end_marked_subexpressionIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__128__begin_marked_subexpressionIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__16__loopIcE12__exec_splitEbRNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__16__loopIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE11__push_charEc);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE11__push_loopEmmPNS_16__owns_one_stateIcEEmmb);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_atomIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_grepIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_termIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE13__parse_egrepIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE15__push_back_refEi);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE16__parse_ecma_expIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE16__push_lookaheadERKS3_bj);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE17__parse_assertionIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE18__parse_awk_escapeIPKcEET_S7_S7_PNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE18__parse_nondupl_REIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE19__parse_alternativeIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE20__parse_ORD_CHAR_EREIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE20__parse_class_escapeIPKcEET_S7_S7_RNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPNS_20__bracket_expressionIcS2_EE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE21__parse_basic_reg_expIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_ERE_expressionIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_RE_dupl_symbolIPKcEET_S7_S7_PNS_16__owns_one_stateIcEEjj);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_decimal_escapeIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_ERE_dupl_symbolIPKcEET_S7_S7_PNS_16__owns_one_stateIcEEjj);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_QUOTED_CHAR_EREIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_expression_termIPKcEET_S7_S7_PNS_20__bracket_expressionIcS2_EE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_character_escapeIPKcEET_S7_S7_PNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_collating_symbolIPKcEET_S7_S7_RNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_extended_reg_expIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE25__parse_equivalence_classIPKcEET_S7_S7_PNS_20__bracket_expressionIcS2_EE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE25__parse_pattern_characterIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE26__parse_bracket_expressionIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE30__parse_character_class_escapeIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE32__parse_one_char_or_coll_elem_REIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE7__parseIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__112__deque_baseINS_7__stateIcEENS_9allocatorIS2_EEE5clearEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113__tree_removeIPNS_16__tree_node_baseIPvEEEEvT_S5_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE4syncEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE5imbueERKNS_6localeE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE6setbufEPcl);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE7seekoffExNS_8ios_base7seekdirEj);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE7seekposENS_4fposI9mbstate_tEEj);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE8overflowEi);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE9pbackfailEi);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE9underflowEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEEC2Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED0Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED2Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE10push_frontEOS3_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE10push_frontERKS3_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE9push_backEOS3_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__114__split_bufferIPNS_7__stateIcEERNS_9allocatorIS3_EEE10push_frontERKS3_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__114__split_bufferIPNS_7__stateIcEERNS_9allocatorIS3_EEE9push_backEOS3_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strERKNS_12basic_stringIcS2_S4_EE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE7seekoffExNS_8ios_base7seekdirEj);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE8overflowEi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE9pbackfailEi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE9underflowEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__116__owns_one_stateIcED0Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__116__owns_one_stateIcED2Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__117__call_once_proxyINS_5tupleIJRFvvEEEEEEvPv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__117__owns_two_statesIcED0Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__117__owns_two_statesIcED2Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__120__shared_ptr_pointerIPNS_13__empty_stateIcEENS_14default_deleteIS2_EENS_9allocatorIS2_EEE16__on_zero_sharedEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__120__shared_ptr_pointerIPNS_13__empty_stateIcEENS_14default_deleteIS2_EENS_9allocatorIS2_EEE21__on_zero_shared_weakEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__124__put_character_sequenceIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__127__tree_balance_after_insertIPNS_16__tree_node_baseIPvEEEEvT_S5_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__15dequeINS_7__stateIcEENS_9allocatorIS2_EEE19__add_back_capacityEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__15dequeINS_7__stateIcEENS_9allocatorIS2_EEE20__add_front_capacityEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16__treeINS_12__value_typeINS_17basic_string_viewIcNS_11char_traitsIcEEEEmEENS_19__map_value_compareIS5_S6_NS_4lessIS5_EELb1EEENS_9allocatorIS6_EEE25__emplace_unique_key_argsIS5_JNS_4pairIKS5_mEEEEENSF_INS_15__tree_iteratorIS6_PNS_11__tree_nodeIS6_PvEElEEbEERKT_DpOT0_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16__treeINS_12__value_typeINS_17basic_string_viewIcNS_11char_traitsIcEEEEmEENS_19__map_value_compareIS5_S6_NS_4lessIS5_EELb1EEENS_9allocatorIS6_EEE7destroyEPNS_11__tree_nodeIS6_PvEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16__treeIiNS_4lessIiEENS_9allocatorIiEEE7destroyEPNS_11__tree_nodeIiPvEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIRKS6_EEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIS6_EEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_4pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_EENS5_IS8_EEE21__push_back_slow_pathIS8_EEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_4pairIccEENS_9allocatorIS2_EEE21__push_back_slow_pathIS2_EEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_4pairImPKcEENS_9allocatorIS4_EEE6assignIPS4_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS4_NS_15iterator_traitsISB_E9referenceEEE5valueEvE4typeESB_SB_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_4pairImPKcEENS_9allocatorIS4_EEE8__appendEm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_7__stateIcEENS_9allocatorIS2_EEE21__push_back_slow_pathIS2_EEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_9sub_matchINS_11__wrap_iterIPKcEEEENS_9allocatorIS6_EEE8__appendEm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE6assignEmRKS4_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE6assignIPS4_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS4_NS_15iterator_traitsISB_E9referenceEEE5valueEvE4typeESB_SB_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE8__appendEmRKS4_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIcNS_9allocatorIcEEE21__push_back_slow_pathIRKcEEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIcNS_9allocatorIcEEE21__push_back_slow_pathIcEEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIhNS_9allocatorIhEEE6resizeEm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIhNS_9allocatorIhEEE8__appendEm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIiNS_9allocatorIiEEE21__push_back_slow_pathIiEEvOT_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIjNS_9allocatorIjEEE21__push_back_slow_pathIjEEvOT_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIlNS_9allocatorIlEEE21__push_back_slow_pathIlEEvOT_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorImNS_9allocatorImEEE21__push_back_slow_pathImEEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__17getlineIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EES6_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__1lsIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_ostreamIT_T0_EES9_RKNS_12basic_stringIS6_S7_T1_EE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZThn16_N7android18NativeMessageQueue11handleEventEiiPv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZThn16_N7android18NativeMessageQueueD0Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZThn16_N7android18NativeMessageQueueD1Ev);
@@ -1203,6 +1083,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z14SkStringPrintfPKcz);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z14StartIterationP10ZipArchivePPvNSt3__117basic_string_viewIcNS3_11char_traitsIcEEEES7_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z14StartIterationP10ZipArchivePPvNSt3__18functionIFbNS3_17basic_string_viewIcNS3_11char_traitsIcEEEEEEE);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z14sk_malloc_sizePvm);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z15ErrorCodeStringi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z15ExtractToMemoryP10ZipArchivePK10ZipEntry64Phm);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z15ExtractToMemoryP10ZipArchivePK8ZipEntryPhm);
@@ -1262,6 +1143,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z34register_android_opengl_jni_GLES31P7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z34register_android_opengl_jni_GLES32P7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35android_os_Process_killProcessGroupP7_JNIEnvP8_jobjectii);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35android_os_Process_sendSignalThrowsP7_JNIEnvP8_jobjectii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35android_os_Process_setProcessFrozenP7_JNIEnvP8_jobjectiih);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35convertAudioMixerAttributesToNativeP7_JNIEnvP8_jobjectP22audio_mixer_attributes);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35register_android_hardware_SyncFenceP7_JNIEnv);
@@ -1279,6 +1161,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_getPidsForCommandsP7_JNIEnvP8_jobjectP13_jobjectArray);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_getThreadSchedulerP7_JNIEnvP7_jclassi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_parseProcLineArrayP7_JNIEnvP8_jobjectPciiP10_jintArrayP13_jobjectArrayP11_jlongArrayP12_jfloatArray);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_sendTgSignalThrowsP7_JNIEnvP8_jobjectiii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_setThreadSchedulerP7_JNIEnvP7_jclassiii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37convertAudioMixerAttributesFromNativeP7_JNIEnvPK22audio_mixer_attributes);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37register_android_media_MicrophoneInfoP7_JNIEnv);
@@ -1349,12 +1232,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN14JniInputStreamC2EP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN14JniInputStreamD0Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN14JniInputStreamD2Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip32I17ZipStringOffset20E14ResetIterationEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip32I17ZipStringOffset20E4NextEPKh);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip32I17ZipStringOffset20E8AddToMapENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip32I17ZipStringOffset32E14ResetIterationEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip32I17ZipStringOffset32E4NextEPKh);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip32I17ZipStringOffset32E8AddToMapENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip6414ResetIterationEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip644NextEPKh);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip648AddToMapENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEEPKh);
@@ -1583,6 +1460,8 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18PerfettoDataSourceD0Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18PerfettoDataSourceD1Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18PerfettoDataSourceD2Ev);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18createInputChannelERKNS_2spINS_7IBinderEEERKNS_18InputTransferTokenERKNS_14SurfaceControlES7_);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18removeInputChannelERKNS_2spINS_7IBinderEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android19parcelForJavaObjectEP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android19register_jni_commonEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android20VelocityTrackerState11addMovementERKNS_11MotionEventE);
@@ -1711,7 +1590,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android29register_android_app_ActivityEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android29register_android_view_SurfaceEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30AssetManagerForNdkAssetManagerEP13AAssetManager);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30android_view_KeyEvent_toNativeEP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30register_android_os_HidlMemoryEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30register_android_os_MemoryFileEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30register_android_util_EventLogEP7_JNIEnv);
@@ -1726,7 +1604,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android31throw_sqlite3_exception_errcodeEP7_JNIEnviPKc);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32CameraMetadata_getNativeMetadataEP7_JNIEnvP8_jobjectPNS_14CameraMetadataE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32SurfaceTexture_getSurfaceTextureEP7_JNIEnvP8_jobject);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32android_view_KeyEvent_fromNativeEP7_JNIEnvRKNS_8KeyEventE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32android_view_MotionEvent_recycleEP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32android_view_VerifiedMotionEventEP7_JNIEnvRKNS_19VerifiedMotionEventE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32register_android_os_FileObserverEP7_JNIEnv);
@@ -1745,6 +1622,8 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android33register_android_view_MotionEventEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android33register_android_view_PointerIconEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android33register_android_view_TextureViewEP7_JNIEnv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvP8_jobject);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvRKNS_8KeyEventE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34convertHdrCapabilitiesToJavaObjectEP7_JNIEnvRKNS_15HdrCapabilitiesE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34register_android_os_HwRemoteBinderEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34register_android_os_ServiceManagerEP7_JNIEnv);
@@ -1839,6 +1718,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android41android_view_MotionEvent_obtainFromNativeEP7_JNIEnvNSt3__110unique_ptrINS_11MotionEventENS2_14default_deleteIS4_EEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android41register_android_tracing_PerfettoProducerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android41register_android_view_VerifiedMotionEventEP7_JNIEnv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android41register_android_view_WindowManagerGlobalEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42android_view_InputChannel_createJavaObjectEP7_JNIEnvNSt3__110unique_ptrINS_12InputChannelENS2_14default_deleteIS4_EEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_content_res_ConfigurationEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_content_res_ResourceTimerEP7_JNIEnv);
@@ -1848,6 +1728,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_os_storage_StorageManagerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_service_DataLoaderServiceEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_view_DisplayEventReceiverEP7_JNIEnv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_window_InputTransferTokenEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android43register_android_tracing_PerfettoDataSourceEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android43register_android_window_WindowInfosListenerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android43register_com_android_internal_os_ZygoteInitEP7_JNIEnv);
@@ -1865,11 +1746,9 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android47register_android_view_TunnelModeEnabledListenerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android47register_com_android_internal_content_F2fsUtilsEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android49android_hardware_display_DisplayViewport_toNativeEP7_JNIEnvP8_jobjectPNS_15DisplayViewportE);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android49android_view_SurfaceControl_getJavaSurfaceControlEP7_JNIEnvRKNS_14SurfaceControlE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android49register_android_hardware_display_DisplayViewportEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android49register_android_view_CompositionSamplingListenerEP7_JNIEnv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android4base4TrimIRNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEEES8_OT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android4base9ParseUintImEEbPKcPT_S4_b);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android4base9ParseUintItEEbPKcPT_S4_b);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android50com_android_internal_os_ZygoteCommandBuffer_insertEP7_JNIEnvP7_jclasslP8_jstring);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android50register_android_os_incremental_IncrementalManagerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android50register_com_android_internal_security_VerityUtilsEP7_JNIEnv);
@@ -1900,6 +1779,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android58com_android_internal_os_ZygoteCommandBuffer_nativeGetCountEP7_JNIEnvP7_jclassl);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android58register_com_android_internal_os_KernelSingleUidTimeReaderEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59android_view_SurfaceTransaction_getNativeSurfaceTransactionEP7_JNIEnvP8_jobject);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59android_window_InputTransferToken_getJavaInputTransferTokenEP7_JNIEnvRKNS_18InputTransferTokenE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59com_android_internal_os_ZygoteCommandBuffer_getNativeBufferEP7_JNIEnvP7_jclassi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59register_com_android_internal_content_om_OverlayManagerImplEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59register_com_android_internal_os_KernelCpuTotalBpfMapReaderEP7_JNIEnv);
@@ -1915,6 +1795,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android60android_view_InputApplicationHandle_fromInputApplicationInfoEP7_JNIEnvNS_3gui20InputApplicationInfoE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android60com_android_internal_os_ZygoteCommandBuffer_freeNativeBufferEP7_JNIEnvP7_jclassl);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android60register_com_android_internal_os_ZygoteInit_nativeZygoteInitEP7_JNIEnv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android61android_window_InputTransferToken_getNativeInputTransferTokenEP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android64com_android_internal_os_ZygoteCommandBuffer_nativeForkRepeatedlyEP7_JNIEnvP7_jclassliiiP8_jstring);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android67android_hardware_display_DisplayManagerGlobal_signalNativeCallbacksEP7_JNIEnvP8_jobjectf);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android67com_android_internal_os_ZygoteCommandBuffer_nativeReadFullyAndResetEP7_JNIEnvP7_jclassl);
@@ -1935,7 +1816,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android7JHwBlobC2EP7_JNIEnvP8_jobjectm);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android7JHwBlobD0Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android7JHwBlobD2Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android8hardware10fromBinderINS_4hidl4base4V1_05IBaseENS4_8BpHwBaseENS4_8BnHwBaseEEENS_2spIT_EERKNS8_INS0_7IBinderEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android8hardware7display27IDeviceProductInfoConstants11asInterfaceERKNS_2spINS_7IBinderEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android8hardware7display27IDeviceProductInfoConstants14getDefaultImplEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android8hardware7display27IDeviceProductInfoConstants14setDefaultImplENS_2spIS2_EE);
@@ -2062,8 +1942,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK13NativeContext18getThumbnailHeightEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK13NativeContext9getResultEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK14ZipEntryCommon19GetModificationTimeEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK15CdEntryMapZip32I17ZipStringOffset20E16GetCdEntryOffsetENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK15CdEntryMapZip32I17ZipStringOffset32E16GetCdEntryOffsetENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK15CdEntryMapZip6416GetCdEntryOffsetENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEEPKh);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK16InputStripSource6getIfdEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK16JNICameraContext33isRawImageCallbackBufferAvailableEv);
@@ -2080,9 +1958,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android15JHwRemoteBinder9getBinderEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo13writeToParcelEPNS_6ParcelE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo16interceptsStylusEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo18frameContainsPointEii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo18supportsSplitTouchEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo28touchableRegionContainsPointEii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo5isSpyEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo8overlapsEPKS1_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfoeqERKS1_);
@@ -2096,12 +1972,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui28IWindowInfosReportedListener22getInterfaceDescriptorEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android5vintf18KernelConfigParser5errorEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android5vintf18KernelConfigParser7configsEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android6VectorIiE10do_destroyEPvm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android6VectorIiE12do_constructEPvm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android6VectorIiE15do_move_forwardEPvPKvm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android6VectorIiE16do_move_backwardEPvPKvm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android6VectorIiE7do_copyEPvPKvm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android6VectorIiE8do_splatEPvPKvm);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android7JHwBlob13writeToParcelEPNS_8hardware6ParcelE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android7JHwBlob21writeEmbeddedToParcelEPNS_8hardware6ParcelEmm);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android7JHwBlob21writeSubBlobsToParcelEPNS_8hardware6ParcelEm);
@@ -2136,128 +2006,18 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK8SkString6equalsERKS_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK9Transform3mapEiiPiS0_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK9TransformeqERKS_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__back_refIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__l_anchorIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__r_anchorIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111__alternateIcE12__exec_splitEbRNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111__alternateIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111__end_stateIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111__lookaheadIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111__match_anyIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE21__match_at_start_ecmaINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE27__match_at_start_posix_subsINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE29__match_at_start_posix_nosubsINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE8__searchINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112__match_charIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112regex_traitsIcE18__lookup_classnameIPKcEEtT_S5_bc);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112regex_traitsIcE19__transform_primaryINS_11__wrap_iterIPcEEEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SC_c);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112regex_traitsIcE20__lookup_collatenameIPKcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SB_c);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112regex_traitsIcE20__lookup_collatenameIPcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SA_c);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112regex_traitsIcE9transformINS_11__wrap_iterIPcEEEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SC_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112regex_traitsIcE9transformIPcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SA_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__113__empty_stateIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__115__word_boundaryIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__116__back_ref_icaseIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__117__repeat_one_loopIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__118__back_ref_collateIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__118__match_char_icaseIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__120__bracket_expressionIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__120__match_char_collateIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__121__empty_non_own_stateIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__126__end_marked_subexpressionIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__128__begin_marked_subexpressionIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__16__loopIcE12__exec_splitEbRNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__16__loopIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE11__push_charEc);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE11__push_loopEmmPNS_16__owns_one_stateIcEEmmb);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_atomIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_grepIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_termIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE13__parse_egrepIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE15__push_back_refEi);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE16__parse_ecma_expIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE16__push_lookaheadERKS3_bj);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE17__parse_assertionIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE18__parse_awk_escapeIPKcEET_S7_S7_PNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE18__parse_nondupl_REIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE19__parse_alternativeIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE20__parse_ORD_CHAR_EREIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE20__parse_class_escapeIPKcEET_S7_S7_RNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPNS_20__bracket_expressionIcS2_EE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE21__parse_basic_reg_expIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_ERE_expressionIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_RE_dupl_symbolIPKcEET_S7_S7_PNS_16__owns_one_stateIcEEjj);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_decimal_escapeIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_ERE_dupl_symbolIPKcEET_S7_S7_PNS_16__owns_one_stateIcEEjj);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_QUOTED_CHAR_EREIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_expression_termIPKcEET_S7_S7_PNS_20__bracket_expressionIcS2_EE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_character_escapeIPKcEET_S7_S7_PNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_collating_symbolIPKcEET_S7_S7_RNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_extended_reg_expIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE25__parse_equivalence_classIPKcEET_S7_S7_PNS_20__bracket_expressionIcS2_EE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE25__parse_pattern_characterIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE26__parse_bracket_expressionIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE30__parse_character_class_escapeIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE32__parse_one_char_or_coll_elem_REIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE7__parseIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__112__deque_baseINS_7__stateIcEENS_9allocatorIS2_EEE5clearEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113__tree_removeIPNS_16__tree_node_baseIPvEEEEvT_S5_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE4syncEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE5imbueERKNS_6localeE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE6setbufEPcl);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE7seekoffExNS_8ios_base7seekdirEj);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE7seekposENS_4fposI9mbstate_tEEj);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE8overflowEi);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE9pbackfailEi);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE9underflowEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEEC2Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED0Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED2Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE10push_frontEOS3_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE10push_frontERKS3_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE9push_backEOS3_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__114__split_bufferIPNS_7__stateIcEERNS_9allocatorIS3_EEE10push_frontERKS3_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__114__split_bufferIPNS_7__stateIcEERNS_9allocatorIS3_EEE9push_backEOS3_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strERKNS_12basic_stringIcS2_S4_EE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE7seekoffExNS_8ios_base7seekdirEj);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE8overflowEi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE9pbackfailEi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE9underflowEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__116__owns_one_stateIcED0Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__116__owns_one_stateIcED2Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__117__call_once_proxyINS_5tupleIJRFvvEEEEEEvPv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__117__owns_two_statesIcED0Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__117__owns_two_statesIcED2Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__120__shared_ptr_pointerIPNS_13__empty_stateIcEENS_14default_deleteIS2_EENS_9allocatorIS2_EEE16__on_zero_sharedEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__120__shared_ptr_pointerIPNS_13__empty_stateIcEENS_14default_deleteIS2_EENS_9allocatorIS2_EEE21__on_zero_shared_weakEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__124__put_character_sequenceIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__127__tree_balance_after_insertIPNS_16__tree_node_baseIPvEEEEvT_S5_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__15dequeINS_7__stateIcEENS_9allocatorIS2_EEE19__add_back_capacityEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__15dequeINS_7__stateIcEENS_9allocatorIS2_EEE20__add_front_capacityEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16__treeINS_12__value_typeINS_17basic_string_viewIcNS_11char_traitsIcEEEEmEENS_19__map_value_compareIS5_S6_NS_4lessIS5_EELb1EEENS_9allocatorIS6_EEE25__emplace_unique_key_argsIS5_JNS_4pairIKS5_mEEEEENSF_INS_15__tree_iteratorIS6_PNS_11__tree_nodeIS6_PvEElEEbEERKT_DpOT0_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16__treeINS_12__value_typeINS_17basic_string_viewIcNS_11char_traitsIcEEEEmEENS_19__map_value_compareIS5_S6_NS_4lessIS5_EELb1EEENS_9allocatorIS6_EEE7destroyEPNS_11__tree_nodeIS6_PvEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16__treeIiNS_4lessIiEENS_9allocatorIiEEE7destroyEPNS_11__tree_nodeIiPvEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIRKS6_EEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIS6_EEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_4pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_EENS5_IS8_EEE21__push_back_slow_pathIS8_EEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_4pairIccEENS_9allocatorIS2_EEE21__push_back_slow_pathIS2_EEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_4pairImPKcEENS_9allocatorIS4_EEE6assignIPS4_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS4_NS_15iterator_traitsISB_E9referenceEEE5valueEvE4typeESB_SB_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_4pairImPKcEENS_9allocatorIS4_EEE8__appendEm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_7__stateIcEENS_9allocatorIS2_EEE21__push_back_slow_pathIS2_EEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_9sub_matchINS_11__wrap_iterIPKcEEEENS_9allocatorIS6_EEE8__appendEm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE6assignEmRKS4_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE6assignIPS4_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS4_NS_15iterator_traitsISB_E9referenceEEE5valueEvE4typeESB_SB_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE8__appendEmRKS4_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIcNS_9allocatorIcEEE21__push_back_slow_pathIRKcEEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIcNS_9allocatorIcEEE21__push_back_slow_pathIcEEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIhNS_9allocatorIhEEE6resizeEm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIhNS_9allocatorIhEEE8__appendEm);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIiNS_9allocatorIiEEE21__push_back_slow_pathIiEEvOT_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIjNS_9allocatorIjEEE21__push_back_slow_pathIjEEvOT_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIlNS_9allocatorIlEEE21__push_back_slow_pathIlEEvOT_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorImNS_9allocatorImEEE21__push_back_slow_pathImEEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__17getlineIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EES6_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__1lsIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_ostreamIT_T0_EES9_RKNS_12basic_stringIS6_S7_T1_EE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZThn16_N7android18NativeMessageQueue11handleEventEiiPv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZThn16_N7android18NativeMessageQueueD0Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZThn16_N7android18NativeMessageQueueD1Ev);
diff --git a/android_api/libandroid_runtime/stubs_riscv64.cc b/android_api/libandroid_runtime/stubs_riscv64.cc
index 525581e..1c99f50 100644
--- a/android_api/libandroid_runtime/stubs_riscv64.cc
+++ b/android_api/libandroid_runtime/stubs_riscv64.cc
@@ -55,6 +55,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14GetArchiveInfoP10ZipArchive);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14SkStringPrintfPKcz);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14StartIterationP10ZipArchivePPvNSt3__117basic_string_viewIcNS3_11char_traitsIcEEEES7_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14StartIterationP10ZipArchivePPvNSt3__18functionIFbNS3_17basic_string_viewIcNS3_11char_traitsIcEEEEEEE);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z14sk_malloc_sizePvm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z15ErrorCodeStringi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z15ExtractToMemoryP10ZipArchivePK10ZipEntry64Phm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z15ExtractToMemoryP10ZipArchivePK8ZipEntryPhm);
@@ -114,6 +115,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z34register_android_opengl_jni_GLES30P7_JNIE
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z34register_android_opengl_jni_GLES31P7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z34register_android_opengl_jni_GLES32P7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35android_os_Process_killProcessGroupP7_JNIEnvP8_jobjectii);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35android_os_Process_sendSignalThrowsP7_JNIEnvP8_jobjectii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35android_os_Process_setProcessFrozenP7_JNIEnvP8_jobjectiih);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35convertAudioMixerAttributesToNativeP7_JNIEnvP8_jobjectP22audio_mixer_attributes);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z35register_android_hardware_SyncFenceP7_JNIEnv);
@@ -131,6 +133,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_createProcessGroupP7_J
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_getPidsForCommandsP7_JNIEnvP8_jobjectP13_jobjectArray);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_getThreadSchedulerP7_JNIEnvP7_jclassi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_parseProcLineArrayP7_JNIEnvP8_jobjectPciiP10_jintArrayP13_jobjectArrayP11_jlongArrayP12_jfloatArray);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_sendTgSignalThrowsP7_JNIEnvP8_jobjectiii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37android_os_Process_setThreadSchedulerP7_JNIEnvP7_jclassiii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37convertAudioMixerAttributesFromNativeP7_JNIEnvPK22audio_mixer_attributes);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_Z37register_android_media_MicrophoneInfoP7_JNIEnv);
@@ -201,12 +204,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN14JniInputStream5closeEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN14JniInputStreamC2EP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN14JniInputStreamD0Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN14JniInputStreamD2Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip32I17ZipStringOffset20E14ResetIterationEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip32I17ZipStringOffset20E4NextEPKh);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip32I17ZipStringOffset20E8AddToMapENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip32I17ZipStringOffset32E14ResetIterationEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip32I17ZipStringOffset32E4NextEPKh);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip32I17ZipStringOffset32E8AddToMapENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip6414ResetIterationEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip644NextEPKh);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN15CdEntryMapZip648AddToMapENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEEPKh);
@@ -435,6 +432,8 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18PerfettoDataSourceC2EP7_JNIEnvP8
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18PerfettoDataSourceD0Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18PerfettoDataSourceD1Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18PerfettoDataSourceD2Ev);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18createInputChannelERKNS_2spINS_7IBinderEEERKNS_18InputTransferTokenERKNS_14SurfaceControlES7_);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android18removeInputChannelERKNS_2spINS_7IBinderEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android19parcelForJavaObjectEP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android19register_jni_commonEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android20VelocityTrackerState11addMovementERKNS_11MotionEventE);
@@ -563,7 +562,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android29android_view_VerifiedKeyEventEP7
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android29register_android_app_ActivityEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android29register_android_view_SurfaceEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30AssetManagerForNdkAssetManagerEP13AAssetManager);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30android_view_KeyEvent_toNativeEP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30register_android_os_HidlMemoryEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30register_android_os_MemoryFileEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android30register_android_util_EventLogEP7_JNIEnv);
@@ -578,7 +576,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android31register_android_os_SystemClockE
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android31throw_sqlite3_exception_errcodeEP7_JNIEnviPKc);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32CameraMetadata_getNativeMetadataEP7_JNIEnvP8_jobjectPNS_14CameraMetadataE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32SurfaceTexture_getSurfaceTextureEP7_JNIEnvP8_jobject);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32android_view_KeyEvent_fromNativeEP7_JNIEnvRKNS_8KeyEventE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32android_view_MotionEvent_recycleEP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32android_view_VerifiedMotionEventEP7_JNIEnvRKNS_19VerifiedMotionEventE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android32register_android_os_FileObserverEP7_JNIEnv);
@@ -597,6 +594,8 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android33register_android_view_InputDevic
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android33register_android_view_MotionEventEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android33register_android_view_PointerIconEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android33register_android_view_TextureViewEP7_JNIEnv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvP8_jobject);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvRKNS_8KeyEventE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34convertHdrCapabilitiesToJavaObjectEP7_JNIEnvRKNS_15HdrCapabilitiesE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34register_android_os_HwRemoteBinderEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android34register_android_os_ServiceManagerEP7_JNIEnv);
@@ -691,6 +690,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41android_view_InputChannel_getInp
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41android_view_MotionEvent_obtainFromNativeEP7_JNIEnvNSt3__110unique_ptrINS_11MotionEventENS2_14default_deleteIS4_EEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41register_android_tracing_PerfettoProducerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41register_android_view_VerifiedMotionEventEP7_JNIEnv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android41register_android_view_WindowManagerGlobalEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42android_view_InputChannel_createJavaObjectEP7_JNIEnvNSt3__110unique_ptrINS_12InputChannelENS2_14default_deleteIS4_EEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_content_res_ConfigurationEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_content_res_ResourceTimerEP7_JNIEnv);
@@ -700,6 +700,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_os_PerformanceH
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_os_storage_StorageManagerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_service_DataLoaderServiceEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_view_DisplayEventReceiverEP7_JNIEnv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android42register_android_window_InputTransferTokenEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android43register_android_tracing_PerfettoDataSourceEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android43register_android_window_WindowInfosListenerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android43register_com_android_internal_os_ZygoteInitEP7_JNIEnv);
@@ -717,11 +718,9 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android47register_android_animation_Prope
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android47register_android_view_TunnelModeEnabledListenerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android47register_com_android_internal_content_F2fsUtilsEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android49android_hardware_display_DisplayViewport_toNativeEP7_JNIEnvP8_jobjectPNS_15DisplayViewportE);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android49android_view_SurfaceControl_getJavaSurfaceControlEP7_JNIEnvRKNS_14SurfaceControlE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android49register_android_hardware_display_DisplayViewportEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android49register_android_view_CompositionSamplingListenerEP7_JNIEnv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android4base4TrimIRNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEEES8_OT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android4base9ParseUintImEEbPKcPT_S4_b);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android4base9ParseUintItEEbPKcPT_S4_b);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android50com_android_internal_os_ZygoteCommandBuffer_insertEP7_JNIEnvP7_jclasslP8_jstring);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android50register_android_os_incremental_IncrementalManagerEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android50register_com_android_internal_security_VerityUtilsEP7_JNIEnv);
@@ -752,6 +751,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android57register_com_android_internal_os
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android58com_android_internal_os_ZygoteCommandBuffer_nativeGetCountEP7_JNIEnvP7_jclassl);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android58register_com_android_internal_os_KernelSingleUidTimeReaderEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59android_view_SurfaceTransaction_getNativeSurfaceTransactionEP7_JNIEnvP8_jobject);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59android_window_InputTransferToken_getJavaInputTransferTokenEP7_JNIEnvRKNS_18InputTransferTokenE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59com_android_internal_os_ZygoteCommandBuffer_getNativeBufferEP7_JNIEnvP7_jclassi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59register_com_android_internal_content_om_OverlayManagerImplEP7_JNIEnv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android59register_com_android_internal_os_KernelCpuTotalBpfMapReaderEP7_JNIEnv);
@@ -767,6 +767,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android5vintf18trimTrailingSpacesERKNSt3_
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android60android_view_InputApplicationHandle_fromInputApplicationInfoEP7_JNIEnvNS_3gui20InputApplicationInfoE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android60com_android_internal_os_ZygoteCommandBuffer_freeNativeBufferEP7_JNIEnvP7_jclassl);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android60register_com_android_internal_os_ZygoteInit_nativeZygoteInitEP7_JNIEnv);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android61android_window_InputTransferToken_getNativeInputTransferTokenEP7_JNIEnvP8_jobject);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android64com_android_internal_os_ZygoteCommandBuffer_nativeForkRepeatedlyEP7_JNIEnvP7_jclassliiiP8_jstring);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android67android_hardware_display_DisplayManagerGlobal_signalNativeCallbacksEP7_JNIEnvP8_jobjectf);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android67com_android_internal_os_ZygoteCommandBuffer_nativeReadFullyAndResetEP7_JNIEnvP7_jclassl);
@@ -787,7 +788,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android7JHwBlob9NewObjectEP7_JNIEnvm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android7JHwBlobC2EP7_JNIEnvP8_jobjectm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android7JHwBlobD0Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android7JHwBlobD2Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android8hardware10fromBinderINS_4hidl4base4V1_05IBaseENS4_8BpHwBaseENS4_8BnHwBaseEEENS_2spIT_EERKNS8_INS0_7IBinderEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android8hardware7display27IDeviceProductInfoConstants11asInterfaceERKNS_2spINS_7IBinderEEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android8hardware7display27IDeviceProductInfoConstants14getDefaultImplEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZN7android8hardware7display27IDeviceProductInfoConstants14setDefaultImplENS_2spIS2_EE);
@@ -914,8 +914,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK13NativeContext18getCharacteristicsEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK13NativeContext18getThumbnailHeightEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK13NativeContext9getResultEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK14ZipEntryCommon19GetModificationTimeEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK15CdEntryMapZip32I17ZipStringOffset20E16GetCdEntryOffsetENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK15CdEntryMapZip32I17ZipStringOffset32E16GetCdEntryOffsetENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK15CdEntryMapZip6416GetCdEntryOffsetENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEEPKh);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK16InputStripSource6getIfdEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK16JNICameraContext33isRawImageCallbackBufferAvailableEv);
@@ -932,9 +930,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android15JHwRemoteBinder21getDeathRecipi
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android15JHwRemoteBinder9getBinderEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo13writeToParcelEPNS_6ParcelE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo16interceptsStylusEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo18frameContainsPointEii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo18supportsSplitTouchEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo28touchableRegionContainsPointEii);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo5isSpyEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfo8overlapsEPKS1_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui10WindowInfoeqERKS1_);
@@ -948,12 +944,6 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui22StalledTransactionInfo13wri
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android3gui28IWindowInfosReportedListener22getInterfaceDescriptorEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android5vintf18KernelConfigParser5errorEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android5vintf18KernelConfigParser7configsEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android6VectorIiE10do_destroyEPvm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android6VectorIiE12do_constructEPvm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android6VectorIiE15do_move_forwardEPvPKvm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android6VectorIiE16do_move_backwardEPvPKvm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android6VectorIiE7do_copyEPvPKvm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android6VectorIiE8do_splatEPvPKvm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android7JHwBlob13writeToParcelEPNS_8hardware6ParcelE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android7JHwBlob21writeEmbeddedToParcelEPNS_8hardware6ParcelEmm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK7android7JHwBlob21writeSubBlobsToParcelEPNS_8hardware6ParcelEm);
@@ -988,128 +978,18 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK8SkString6equalsEPKcm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK8SkString6equalsERKS_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK9Transform3mapEiiPiS0_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNK9TransformeqERKS_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__back_refIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__l_anchorIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__110__r_anchorIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111__alternateIcE12__exec_splitEbRNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111__alternateIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111__end_stateIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111__lookaheadIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111__match_anyIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE21__match_at_start_ecmaINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE27__match_at_start_posix_subsINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE29__match_at_start_posix_nosubsINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE8__searchINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112__match_charIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112regex_traitsIcE18__lookup_classnameIPKcEEtT_S5_bc);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112regex_traitsIcE19__transform_primaryINS_11__wrap_iterIPcEEEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SC_c);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112regex_traitsIcE20__lookup_collatenameIPKcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SB_c);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112regex_traitsIcE20__lookup_collatenameIPcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SA_c);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112regex_traitsIcE9transformINS_11__wrap_iterIPcEEEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SC_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__112regex_traitsIcE9transformIPcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SA_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__113__empty_stateIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__115__word_boundaryIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__116__back_ref_icaseIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__117__repeat_one_loopIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__118__back_ref_collateIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__118__match_char_icaseIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__120__bracket_expressionIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__120__match_char_collateIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__121__empty_non_own_stateIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__126__end_marked_subexpressionIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__128__begin_marked_subexpressionIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__16__loopIcE12__exec_splitEbRNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNKSt3__16__loopIcE6__execERNS_7__stateIcEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE11__push_charEc);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE11__push_loopEmmPNS_16__owns_one_stateIcEEmmb);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_atomIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_grepIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_termIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE13__parse_egrepIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE15__push_back_refEi);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE16__parse_ecma_expIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE16__push_lookaheadERKS3_bj);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE17__parse_assertionIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE18__parse_awk_escapeIPKcEET_S7_S7_PNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE18__parse_nondupl_REIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE19__parse_alternativeIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE20__parse_ORD_CHAR_EREIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE20__parse_class_escapeIPKcEET_S7_S7_RNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPNS_20__bracket_expressionIcS2_EE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE21__parse_basic_reg_expIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_ERE_expressionIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_RE_dupl_symbolIPKcEET_S7_S7_PNS_16__owns_one_stateIcEEjj);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_decimal_escapeIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_ERE_dupl_symbolIPKcEET_S7_S7_PNS_16__owns_one_stateIcEEjj);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_QUOTED_CHAR_EREIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_expression_termIPKcEET_S7_S7_PNS_20__bracket_expressionIcS2_EE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_character_escapeIPKcEET_S7_S7_PNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_collating_symbolIPKcEET_S7_S7_RNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_extended_reg_expIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE25__parse_equivalence_classIPKcEET_S7_S7_PNS_20__bracket_expressionIcS2_EE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE25__parse_pattern_characterIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE26__parse_bracket_expressionIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE30__parse_character_class_escapeIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE32__parse_one_char_or_coll_elem_REIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE7__parseIPKcEET_S7_S7_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__112__deque_baseINS_7__stateIcEENS_9allocatorIS2_EEE5clearEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113__tree_removeIPNS_16__tree_node_baseIPvEEEEvT_S5_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE4syncEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE5imbueERKNS_6localeE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE6setbufEPcl);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE7seekoffExNS_8ios_base7seekdirEj);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE7seekposENS_4fposI9mbstate_tEEj);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE8overflowEi);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE9pbackfailEi);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE9underflowEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEEC2Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED0Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED2Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE10push_frontEOS3_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE10push_frontERKS3_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE9push_backEOS3_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__114__split_bufferIPNS_7__stateIcEERNS_9allocatorIS3_EEE10push_frontERKS3_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__114__split_bufferIPNS_7__stateIcEERNS_9allocatorIS3_EEE9push_backEOS3_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strERKNS_12basic_stringIcS2_S4_EE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE7seekoffExNS_8ios_base7seekdirEj);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE8overflowEi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE9pbackfailEi);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE9underflowEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__116__owns_one_stateIcED0Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__116__owns_one_stateIcED2Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__117__call_once_proxyINS_5tupleIJRFvvEEEEEEvPv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__117__owns_two_statesIcED0Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__117__owns_two_statesIcED2Ev);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__120__shared_ptr_pointerIPNS_13__empty_stateIcEENS_14default_deleteIS2_EENS_9allocatorIS2_EEE16__on_zero_sharedEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__120__shared_ptr_pointerIPNS_13__empty_stateIcEENS_14default_deleteIS2_EENS_9allocatorIS2_EEE21__on_zero_shared_weakEv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__124__put_character_sequenceIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__127__tree_balance_after_insertIPNS_16__tree_node_baseIPvEEEEvT_S5_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__15dequeINS_7__stateIcEENS_9allocatorIS2_EEE19__add_back_capacityEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__15dequeINS_7__stateIcEENS_9allocatorIS2_EEE20__add_front_capacityEv);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16__treeINS_12__value_typeINS_17basic_string_viewIcNS_11char_traitsIcEEEEmEENS_19__map_value_compareIS5_S6_NS_4lessIS5_EELb1EEENS_9allocatorIS6_EEE25__emplace_unique_key_argsIS5_JNS_4pairIKS5_mEEEEENSF_INS_15__tree_iteratorIS6_PNS_11__tree_nodeIS6_PvEElEEbEERKT_DpOT0_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16__treeINS_12__value_typeINS_17basic_string_viewIcNS_11char_traitsIcEEEEmEENS_19__map_value_compareIS5_S6_NS_4lessIS5_EELb1EEENS_9allocatorIS6_EEE7destroyEPNS_11__tree_nodeIS6_PvEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16__treeIiNS_4lessIiEENS_9allocatorIiEEE7destroyEPNS_11__tree_nodeIiPvEE);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIRKS6_EEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIS6_EEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_4pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_EENS5_IS8_EEE21__push_back_slow_pathIS8_EEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_4pairIccEENS_9allocatorIS2_EEE21__push_back_slow_pathIS2_EEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_4pairImPKcEENS_9allocatorIS4_EEE6assignIPS4_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS4_NS_15iterator_traitsISB_E9referenceEEE5valueEvE4typeESB_SB_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_4pairImPKcEENS_9allocatorIS4_EEE8__appendEm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_7__stateIcEENS_9allocatorIS2_EEE21__push_back_slow_pathIS2_EEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_9sub_matchINS_11__wrap_iterIPKcEEEENS_9allocatorIS6_EEE8__appendEm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE6assignEmRKS4_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE6assignIPS4_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS4_NS_15iterator_traitsISB_E9referenceEEE5valueEvE4typeESB_SB_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE8__appendEmRKS4_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIcNS_9allocatorIcEEE21__push_back_slow_pathIRKcEEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIcNS_9allocatorIcEEE21__push_back_slow_pathIcEEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIhNS_9allocatorIhEEE6resizeEm);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIhNS_9allocatorIhEEE8__appendEm);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIiNS_9allocatorIiEEE21__push_back_slow_pathIiEEvOT_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIjNS_9allocatorIjEEE21__push_back_slow_pathIjEEvOT_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorIlNS_9allocatorIlEEE21__push_back_slow_pathIlEEvOT_);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__16vectorImNS_9allocatorImEEE21__push_back_slow_pathImEEvOT_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__17getlineIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EES6_);
-DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZNSt3__1lsIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_ostreamIT_T0_EES9_RKNS_12basic_stringIS6_S7_T1_EE);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZThn16_N7android18NativeMessageQueue11handleEventEiiPv);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZThn16_N7android18NativeMessageQueueD0Ev);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_ZThn16_N7android18NativeMessageQueueD1Ev);
@@ -1203,6 +1083,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z14SkStringPrintfPKcz);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z14StartIterationP10ZipArchivePPvNSt3__117basic_string_viewIcNS3_11char_traitsIcEEEES7_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z14StartIterationP10ZipArchivePPvNSt3__18functionIFbNS3_17basic_string_viewIcNS3_11char_traitsIcEEEEEEE);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z14sk_malloc_sizePvm);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z15ErrorCodeStringi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z15ExtractToMemoryP10ZipArchivePK10ZipEntry64Phm);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z15ExtractToMemoryP10ZipArchivePK8ZipEntryPhm);
@@ -1262,6 +1143,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z34register_android_opengl_jni_GLES31P7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z34register_android_opengl_jni_GLES32P7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35android_os_Process_killProcessGroupP7_JNIEnvP8_jobjectii);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35android_os_Process_sendSignalThrowsP7_JNIEnvP8_jobjectii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35android_os_Process_setProcessFrozenP7_JNIEnvP8_jobjectiih);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35convertAudioMixerAttributesToNativeP7_JNIEnvP8_jobjectP22audio_mixer_attributes);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z35register_android_hardware_SyncFenceP7_JNIEnv);
@@ -1279,6 +1161,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_getPidsForCommandsP7_JNIEnvP8_jobjectP13_jobjectArray);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_getThreadSchedulerP7_JNIEnvP7_jclassi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_parseProcLineArrayP7_JNIEnvP8_jobjectPciiP10_jintArrayP13_jobjectArrayP11_jlongArrayP12_jfloatArray);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_sendTgSignalThrowsP7_JNIEnvP8_jobjectiii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37android_os_Process_setThreadSchedulerP7_JNIEnvP7_jclassiii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37convertAudioMixerAttributesFromNativeP7_JNIEnvPK22audio_mixer_attributes);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _Z37register_android_media_MicrophoneInfoP7_JNIEnv);
@@ -1349,12 +1232,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN14JniInputStreamC2EP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN14JniInputStreamD0Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN14JniInputStreamD2Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip32I17ZipStringOffset20E14ResetIterationEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip32I17ZipStringOffset20E4NextEPKh);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip32I17ZipStringOffset20E8AddToMapENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip32I17ZipStringOffset32E14ResetIterationEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip32I17ZipStringOffset32E4NextEPKh);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip32I17ZipStringOffset32E8AddToMapENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip6414ResetIterationEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip644NextEPKh);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN15CdEntryMapZip648AddToMapENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEEPKh);
@@ -1583,6 +1460,8 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18PerfettoDataSourceD0Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18PerfettoDataSourceD1Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18PerfettoDataSourceD2Ev);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18createInputChannelERKNS_2spINS_7IBinderEEERKNS_18InputTransferTokenERKNS_14SurfaceControlES7_);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android18removeInputChannelERKNS_2spINS_7IBinderEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android19parcelForJavaObjectEP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android19register_jni_commonEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android20VelocityTrackerState11addMovementERKNS_11MotionEventE);
@@ -1711,7 +1590,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android29register_android_app_ActivityEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android29register_android_view_SurfaceEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30AssetManagerForNdkAssetManagerEP13AAssetManager);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30android_view_KeyEvent_toNativeEP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30register_android_os_HidlMemoryEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30register_android_os_MemoryFileEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android30register_android_util_EventLogEP7_JNIEnv);
@@ -1726,7 +1604,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android31throw_sqlite3_exception_errcodeEP7_JNIEnviPKc);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32CameraMetadata_getNativeMetadataEP7_JNIEnvP8_jobjectPNS_14CameraMetadataE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32SurfaceTexture_getSurfaceTextureEP7_JNIEnvP8_jobject);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32android_view_KeyEvent_fromNativeEP7_JNIEnvRKNS_8KeyEventE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32android_view_MotionEvent_recycleEP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32android_view_VerifiedMotionEventEP7_JNIEnvRKNS_19VerifiedMotionEventE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android32register_android_os_FileObserverEP7_JNIEnv);
@@ -1745,6 +1622,8 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android33register_android_view_MotionEventEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android33register_android_view_PointerIconEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android33register_android_view_TextureViewEP7_JNIEnv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvP8_jobject);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34android_view_KeyEvent_obtainAsCopyEP7_JNIEnvRKNS_8KeyEventE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34convertHdrCapabilitiesToJavaObjectEP7_JNIEnvRKNS_15HdrCapabilitiesE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34register_android_os_HwRemoteBinderEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android34register_android_os_ServiceManagerEP7_JNIEnv);
@@ -1839,6 +1718,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android41android_view_MotionEvent_obtainFromNativeEP7_JNIEnvNSt3__110unique_ptrINS_11MotionEventENS2_14default_deleteIS4_EEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android41register_android_tracing_PerfettoProducerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android41register_android_view_VerifiedMotionEventEP7_JNIEnv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android41register_android_view_WindowManagerGlobalEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42android_view_InputChannel_createJavaObjectEP7_JNIEnvNSt3__110unique_ptrINS_12InputChannelENS2_14default_deleteIS4_EEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_content_res_ConfigurationEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_content_res_ResourceTimerEP7_JNIEnv);
@@ -1848,6 +1728,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_os_storage_StorageManagerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_service_DataLoaderServiceEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_view_DisplayEventReceiverEP7_JNIEnv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android42register_android_window_InputTransferTokenEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android43register_android_tracing_PerfettoDataSourceEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android43register_android_window_WindowInfosListenerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android43register_com_android_internal_os_ZygoteInitEP7_JNIEnv);
@@ -1865,11 +1746,9 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android47register_android_view_TunnelModeEnabledListenerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android47register_com_android_internal_content_F2fsUtilsEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android49android_hardware_display_DisplayViewport_toNativeEP7_JNIEnvP8_jobjectPNS_15DisplayViewportE);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android49android_view_SurfaceControl_getJavaSurfaceControlEP7_JNIEnvRKNS_14SurfaceControlE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android49register_android_hardware_display_DisplayViewportEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android49register_android_view_CompositionSamplingListenerEP7_JNIEnv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android4base4TrimIRNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEEES8_OT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android4base9ParseUintImEEbPKcPT_S4_b);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android4base9ParseUintItEEbPKcPT_S4_b);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android50com_android_internal_os_ZygoteCommandBuffer_insertEP7_JNIEnvP7_jclasslP8_jstring);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android50register_android_os_incremental_IncrementalManagerEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android50register_com_android_internal_security_VerityUtilsEP7_JNIEnv);
@@ -1900,6 +1779,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android58com_android_internal_os_ZygoteCommandBuffer_nativeGetCountEP7_JNIEnvP7_jclassl);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android58register_com_android_internal_os_KernelSingleUidTimeReaderEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59android_view_SurfaceTransaction_getNativeSurfaceTransactionEP7_JNIEnvP8_jobject);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59android_window_InputTransferToken_getJavaInputTransferTokenEP7_JNIEnvRKNS_18InputTransferTokenE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59com_android_internal_os_ZygoteCommandBuffer_getNativeBufferEP7_JNIEnvP7_jclassi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59register_com_android_internal_content_om_OverlayManagerImplEP7_JNIEnv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android59register_com_android_internal_os_KernelCpuTotalBpfMapReaderEP7_JNIEnv);
@@ -1915,6 +1795,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android60android_view_InputApplicationHandle_fromInputApplicationInfoEP7_JNIEnvNS_3gui20InputApplicationInfoE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android60com_android_internal_os_ZygoteCommandBuffer_freeNativeBufferEP7_JNIEnvP7_jclassl);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android60register_com_android_internal_os_ZygoteInit_nativeZygoteInitEP7_JNIEnv);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android61android_window_InputTransferToken_getNativeInputTransferTokenEP7_JNIEnvP8_jobject);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android64com_android_internal_os_ZygoteCommandBuffer_nativeForkRepeatedlyEP7_JNIEnvP7_jclassliiiP8_jstring);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android67android_hardware_display_DisplayManagerGlobal_signalNativeCallbacksEP7_JNIEnvP8_jobjectf);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android67com_android_internal_os_ZygoteCommandBuffer_nativeReadFullyAndResetEP7_JNIEnvP7_jclassl);
@@ -1935,7 +1816,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android7JHwBlobC2EP7_JNIEnvP8_jobjectm);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android7JHwBlobD0Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android7JHwBlobD2Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android8hardware10fromBinderINS_4hidl4base4V1_05IBaseENS4_8BpHwBaseENS4_8BnHwBaseEEENS_2spIT_EERKNS8_INS0_7IBinderEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android8hardware7display27IDeviceProductInfoConstants11asInterfaceERKNS_2spINS_7IBinderEEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android8hardware7display27IDeviceProductInfoConstants14getDefaultImplEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZN7android8hardware7display27IDeviceProductInfoConstants14setDefaultImplENS_2spIS2_EE);
@@ -2062,8 +1942,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK13NativeContext18getThumbnailHeightEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK13NativeContext9getResultEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK14ZipEntryCommon19GetModificationTimeEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK15CdEntryMapZip32I17ZipStringOffset20E16GetCdEntryOffsetENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK15CdEntryMapZip32I17ZipStringOffset32E16GetCdEntryOffsetENSt3__117basic_string_viewIcNS2_11char_traitsIcEEEEPKh);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK15CdEntryMapZip6416GetCdEntryOffsetENSt3__117basic_string_viewIcNS0_11char_traitsIcEEEEPKh);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK16InputStripSource6getIfdEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK16JNICameraContext33isRawImageCallbackBufferAvailableEv);
@@ -2080,9 +1958,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android15JHwRemoteBinder9getBinderEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo13writeToParcelEPNS_6ParcelE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo16interceptsStylusEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo18frameContainsPointEii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo18supportsSplitTouchEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo28touchableRegionContainsPointEii);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo5isSpyEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfo8overlapsEPKS1_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui10WindowInfoeqERKS1_);
@@ -2096,12 +1972,6 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android3gui28IWindowInfosReportedListener22getInterfaceDescriptorEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android5vintf18KernelConfigParser5errorEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android5vintf18KernelConfigParser7configsEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android6VectorIiE10do_destroyEPvm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android6VectorIiE12do_constructEPvm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android6VectorIiE15do_move_forwardEPvPKvm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android6VectorIiE16do_move_backwardEPvPKvm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android6VectorIiE7do_copyEPvPKvm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android6VectorIiE8do_splatEPvPKvm);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android7JHwBlob13writeToParcelEPNS_8hardware6ParcelE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android7JHwBlob21writeEmbeddedToParcelEPNS_8hardware6ParcelEmm);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK7android7JHwBlob21writeSubBlobsToParcelEPNS_8hardware6ParcelEm);
@@ -2136,128 +2006,18 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK8SkString6equalsERKS_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK9Transform3mapEiiPiS0_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNK9TransformeqERKS_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__back_refIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__l_anchorIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__110__r_anchorIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111__alternateIcE12__exec_splitEbRNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111__alternateIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111__end_stateIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111__lookaheadIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111__match_anyIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE21__match_at_start_ecmaINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE27__match_at_start_posix_subsINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE29__match_at_start_posix_nosubsINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeEb);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__111basic_regexIcNS_12regex_traitsIcEEE8__searchINS_9allocatorINS_9sub_matchIPKcEEEEEEbS8_S8_RNS_13match_resultsIS8_T_EENS_15regex_constants15match_flag_typeE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112__match_charIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112regex_traitsIcE18__lookup_classnameIPKcEEtT_S5_bc);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112regex_traitsIcE19__transform_primaryINS_11__wrap_iterIPcEEEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SC_c);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112regex_traitsIcE20__lookup_collatenameIPKcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SB_c);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112regex_traitsIcE20__lookup_collatenameIPcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SA_c);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112regex_traitsIcE9transformINS_11__wrap_iterIPcEEEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SC_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__112regex_traitsIcE9transformIPcEENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEET_SA_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__113__empty_stateIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__115__word_boundaryIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__116__back_ref_icaseIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__117__repeat_one_loopIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__118__back_ref_collateIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__118__match_char_icaseIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__120__bracket_expressionIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__120__match_char_collateIcNS_12regex_traitsIcEEE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__121__empty_non_own_stateIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__126__end_marked_subexpressionIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__128__begin_marked_subexpressionIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__16__loopIcE12__exec_splitEbRNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNKSt3__16__loopIcE6__execERNS_7__stateIcEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE11__push_charEc);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE11__push_loopEmmPNS_16__owns_one_stateIcEEmmb);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_atomIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_grepIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE12__parse_termIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE13__parse_egrepIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE15__push_back_refEi);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE16__parse_ecma_expIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE16__push_lookaheadERKS3_bj);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE17__parse_assertionIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE18__parse_awk_escapeIPKcEET_S7_S7_PNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE18__parse_nondupl_REIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE19__parse_alternativeIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE20__parse_ORD_CHAR_EREIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE20__parse_class_escapeIPKcEET_S7_S7_RNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPNS_20__bracket_expressionIcS2_EE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE21__parse_basic_reg_expIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_ERE_expressionIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_RE_dupl_symbolIPKcEET_S7_S7_PNS_16__owns_one_stateIcEEjj);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE22__parse_decimal_escapeIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_ERE_dupl_symbolIPKcEET_S7_S7_PNS_16__owns_one_stateIcEEjj);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_QUOTED_CHAR_EREIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE23__parse_expression_termIPKcEET_S7_S7_PNS_20__bracket_expressionIcS2_EE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_character_escapeIPKcEET_S7_S7_PNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_collating_symbolIPKcEET_S7_S7_RNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE24__parse_extended_reg_expIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE25__parse_equivalence_classIPKcEET_S7_S7_PNS_20__bracket_expressionIcS2_EE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE25__parse_pattern_characterIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE26__parse_bracket_expressionIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE30__parse_character_class_escapeIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE32__parse_one_char_or_coll_elem_REIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__111basic_regexIcNS_12regex_traitsIcEEE7__parseIPKcEET_S7_S7_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__112__deque_baseINS_7__stateIcEENS_9allocatorIS2_EEE5clearEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113__tree_removeIPNS_16__tree_node_baseIPvEEEEvT_S5_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE4syncEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE5imbueERKNS_6localeE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE6setbufEPcl);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE7seekoffExNS_8ios_base7seekdirEj);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE7seekposENS_4fposI9mbstate_tEEj);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE8overflowEi);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE9pbackfailEi);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE9underflowEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEEC2Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED0Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED2Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE10push_frontEOS3_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE10push_frontERKS3_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__114__split_bufferIPNS_7__stateIcEENS_9allocatorIS3_EEE9push_backEOS3_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__114__split_bufferIPNS_7__stateIcEERNS_9allocatorIS3_EEE10push_frontERKS3_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__114__split_bufferIPNS_7__stateIcEERNS_9allocatorIS3_EEE9push_backEOS3_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strERKNS_12basic_stringIcS2_S4_EE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE7seekoffExNS_8ios_base7seekdirEj);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE8overflowEi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE9pbackfailEi);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE9underflowEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__116__owns_one_stateIcED0Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__116__owns_one_stateIcED2Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__117__call_once_proxyINS_5tupleIJRFvvEEEEEEvPv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__117__owns_two_statesIcED0Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__117__owns_two_statesIcED2Ev);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__120__shared_ptr_pointerIPNS_13__empty_stateIcEENS_14default_deleteIS2_EENS_9allocatorIS2_EEE16__on_zero_sharedEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__120__shared_ptr_pointerIPNS_13__empty_stateIcEENS_14default_deleteIS2_EENS_9allocatorIS2_EEE21__on_zero_shared_weakEv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__124__put_character_sequenceIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__127__tree_balance_after_insertIPNS_16__tree_node_baseIPvEEEEvT_S5_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__15dequeINS_7__stateIcEENS_9allocatorIS2_EEE19__add_back_capacityEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__15dequeINS_7__stateIcEENS_9allocatorIS2_EEE20__add_front_capacityEv);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16__treeINS_12__value_typeINS_17basic_string_viewIcNS_11char_traitsIcEEEEmEENS_19__map_value_compareIS5_S6_NS_4lessIS5_EELb1EEENS_9allocatorIS6_EEE25__emplace_unique_key_argsIS5_JNS_4pairIKS5_mEEEEENSF_INS_15__tree_iteratorIS6_PNS_11__tree_nodeIS6_PvEElEEbEERKT_DpOT0_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16__treeINS_12__value_typeINS_17basic_string_viewIcNS_11char_traitsIcEEEEmEENS_19__map_value_compareIS5_S6_NS_4lessIS5_EELb1EEENS_9allocatorIS6_EEE7destroyEPNS_11__tree_nodeIS6_PvEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16__treeIiNS_4lessIiEENS_9allocatorIiEEE7destroyEPNS_11__tree_nodeIiPvEE);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIRKS6_EEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIS6_EEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_4pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_EENS5_IS8_EEE21__push_back_slow_pathIS8_EEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_4pairIccEENS_9allocatorIS2_EEE21__push_back_slow_pathIS2_EEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_4pairImPKcEENS_9allocatorIS4_EEE6assignIPS4_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS4_NS_15iterator_traitsISB_E9referenceEEE5valueEvE4typeESB_SB_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_4pairImPKcEENS_9allocatorIS4_EEE8__appendEm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_7__stateIcEENS_9allocatorIS2_EEE21__push_back_slow_pathIS2_EEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_9sub_matchINS_11__wrap_iterIPKcEEEENS_9allocatorIS6_EEE8__appendEm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE6assignEmRKS4_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE6assignIPS4_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS4_NS_15iterator_traitsISB_E9referenceEEE5valueEvE4typeESB_SB_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorINS_9sub_matchIPKcEENS_9allocatorIS4_EEE8__appendEmRKS4_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIcNS_9allocatorIcEEE21__push_back_slow_pathIRKcEEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIcNS_9allocatorIcEEE21__push_back_slow_pathIcEEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIhNS_9allocatorIhEEE6resizeEm);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIhNS_9allocatorIhEEE8__appendEm);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIiNS_9allocatorIiEEE21__push_back_slow_pathIiEEvOT_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIjNS_9allocatorIjEEE21__push_back_slow_pathIjEEvOT_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorIlNS_9allocatorIlEEE21__push_back_slow_pathIlEEvOT_);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__16vectorImNS_9allocatorImEEE21__push_back_slow_pathImEEvOT_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__17getlineIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EES6_);
-  INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZNSt3__1lsIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_ostreamIT_T0_EES9_RKNS_12basic_stringIS6_S7_T1_EE);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZThn16_N7android18NativeMessageQueue11handleEventEiiPv);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZThn16_N7android18NativeMessageQueueD0Ev);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libandroid_runtime.so", _ZThn16_N7android18NativeMessageQueueD1Ev);
diff --git a/android_api/libbinder_ndk/proxy/trampolines_arm64_to_x86_64-inl.h b/android_api/libbinder_ndk/proxy/trampolines_arm64_to_x86_64-inl.h
index 7f1e162..5e722f5 100644
--- a/android_api/libbinder_ndk/proxy/trampolines_arm64_to_x86_64-inl.h
+++ b/android_api/libbinder_ndk/proxy/trampolines_arm64_to_x86_64-inl.h
@@ -25,7 +25,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AIBinder_dump", GetTrampolineFunc<auto(void*, int32_t, void*, uint32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_forceDowngradeToSystemStability", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_forceDowngradeToVendorStability", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AIBinder_fromJavaBinder", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AIBinder_fromJavaBinder", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_getCallingPid", GetTrampolineFunc<auto(void) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_getCallingSid", GetTrampolineFunc<auto(void) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_getCallingUid", GetTrampolineFunc<auto(void) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
@@ -48,13 +48,13 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AIBinder_setInheritRt", GetTrampolineFunc<auto(void*, uint8_t) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_setMinSchedulerPolicy", GetTrampolineFunc<auto(void*, int32_t, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_setRequestingSid", GetTrampolineFunc<auto(void*, uint8_t) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AIBinder_toJavaBinder", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AIBinder_toJavaBinder", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_transact", GetTrampolineFunc<auto(void*, uint32_t, void*, void*, uint32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_unlinkToDeath", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_appendFrom", GetTrampolineFunc<auto(void*, void*, int32_t, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_create", GetTrampolineFunc<auto(void) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_delete", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AParcel_fromJavaParcel", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AParcel_fromJavaParcel", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_getAllowFds", GetTrampolineFunc<auto(void*) -> uint8_t>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_getDataPosition", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_getDataSize", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libbinder_ndk/proxy/trampolines_arm_to_x86-inl.h b/android_api/libbinder_ndk/proxy/trampolines_arm_to_x86-inl.h
index 5253557..b831fd7 100644
--- a/android_api/libbinder_ndk/proxy/trampolines_arm_to_x86-inl.h
+++ b/android_api/libbinder_ndk/proxy/trampolines_arm_to_x86-inl.h
@@ -25,7 +25,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AIBinder_dump", GetTrampolineFunc<auto(void*, int32_t, void*, uint32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_forceDowngradeToSystemStability", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_forceDowngradeToVendorStability", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AIBinder_fromJavaBinder", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AIBinder_fromJavaBinder", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_getCallingPid", GetTrampolineFunc<auto(void) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_getCallingSid", GetTrampolineFunc<auto(void) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_getCallingUid", GetTrampolineFunc<auto(void) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
@@ -48,13 +48,13 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AIBinder_setInheritRt", GetTrampolineFunc<auto(void*, uint8_t) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_setMinSchedulerPolicy", GetTrampolineFunc<auto(void*, int32_t, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_setRequestingSid", GetTrampolineFunc<auto(void*, uint8_t) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AIBinder_toJavaBinder", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AIBinder_toJavaBinder", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_transact", GetTrampolineFunc<auto(void*, uint32_t, void*, void*, uint32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_unlinkToDeath", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_appendFrom", GetTrampolineFunc<auto(void*, void*, int32_t, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_create", GetTrampolineFunc<auto(void) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_delete", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AParcel_fromJavaParcel", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AParcel_fromJavaParcel", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_getAllowFds", GetTrampolineFunc<auto(void*) -> uint8_t>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_getDataPosition", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_getDataSize", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libbinder_ndk/proxy/trampolines_riscv64_to_x86_64-inl.h b/android_api/libbinder_ndk/proxy/trampolines_riscv64_to_x86_64-inl.h
index 7f1e162..5e722f5 100644
--- a/android_api/libbinder_ndk/proxy/trampolines_riscv64_to_x86_64-inl.h
+++ b/android_api/libbinder_ndk/proxy/trampolines_riscv64_to_x86_64-inl.h
@@ -25,7 +25,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AIBinder_dump", GetTrampolineFunc<auto(void*, int32_t, void*, uint32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_forceDowngradeToSystemStability", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_forceDowngradeToVendorStability", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AIBinder_fromJavaBinder", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AIBinder_fromJavaBinder", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_getCallingPid", GetTrampolineFunc<auto(void) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_getCallingSid", GetTrampolineFunc<auto(void) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_getCallingUid", GetTrampolineFunc<auto(void) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
@@ -48,13 +48,13 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AIBinder_setInheritRt", GetTrampolineFunc<auto(void*, uint8_t) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_setMinSchedulerPolicy", GetTrampolineFunc<auto(void*, int32_t, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_setRequestingSid", GetTrampolineFunc<auto(void*, uint8_t) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AIBinder_toJavaBinder", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AIBinder_toJavaBinder", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_transact", GetTrampolineFunc<auto(void*, uint32_t, void*, void*, uint32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AIBinder_unlinkToDeath", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_appendFrom", GetTrampolineFunc<auto(void*, void*, int32_t, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_create", GetTrampolineFunc<auto(void) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_delete", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"AParcel_fromJavaParcel", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"AParcel_fromJavaParcel", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_getAllowFds", GetTrampolineFunc<auto(void*) -> uint8_t>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_getDataPosition", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AParcel_getDataSize", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libcamera2ndk/proxy/android_camera_checks.h b/android_api/libcamera2ndk/proxy/android_camera_checks.h
index fdf53e5..625841a 100644
--- a/android_api/libcamera2ndk/proxy/android_camera_checks.h
+++ b/android_api/libcamera2ndk/proxy/android_camera_checks.h
@@ -65,7 +65,7 @@ CHECK_FIELD_LAYOUT(ACameraCaptureSession_stateCallbacks, onClosed, 32, 32);
 CHECK_FIELD_LAYOUT(ACameraCaptureSession_stateCallbacks, onReady, 64, 32);
 CHECK_FIELD_LAYOUT(ACameraCaptureSession_stateCallbacks, onActive, 96, 32);
 
-CHECK_STRUCT_LAYOUT(ACameraDevice_StateCallbacks, 96, 32);
+CHECK_STRUCT_LAYOUT(ACameraDevice_StateCallbacks, 128, 32);
 CHECK_FIELD_LAYOUT(ACameraDevice_StateCallbacks, context, 0, 32);
 CHECK_FIELD_LAYOUT(ACameraDevice_StateCallbacks, onDisconnected, 32, 32);
 CHECK_FIELD_LAYOUT(ACameraDevice_StateCallbacks, onError, 64, 32);
@@ -112,7 +112,7 @@ CHECK_FIELD_LAYOUT(ACameraCaptureSession_stateCallbacks, onClosed, 64, 64);
 CHECK_FIELD_LAYOUT(ACameraCaptureSession_stateCallbacks, onReady, 128, 64);
 CHECK_FIELD_LAYOUT(ACameraCaptureSession_stateCallbacks, onActive, 192, 64);
 
-CHECK_STRUCT_LAYOUT(ACameraDevice_StateCallbacks, 192, 64);
+CHECK_STRUCT_LAYOUT(ACameraDevice_StateCallbacks, 256, 64);
 CHECK_FIELD_LAYOUT(ACameraDevice_StateCallbacks, context, 0, 64);
 CHECK_FIELD_LAYOUT(ACameraDevice_StateCallbacks, onDisconnected, 64, 64);
 CHECK_FIELD_LAYOUT(ACameraDevice_StateCallbacks, onError, 128, 64);
diff --git a/android_api/libcamera2ndk/proxy/trampolines_arm64_to_x86_64-inl.h b/android_api/libcamera2ndk/proxy/trampolines_arm64_to_x86_64-inl.h
index 008ee94..6a119ac 100644
--- a/android_api/libcamera2ndk/proxy/trampolines_arm64_to_x86_64-inl.h
+++ b/android_api/libcamera2ndk/proxy/trampolines_arm64_to_x86_64-inl.h
@@ -34,7 +34,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ACameraManager_unregisterExtendedAvailabilityCallback", GetTrampolineFunc<auto(void*, void*) -> uint32_t>(), reinterpret_cast<void*>(DoThunk_ACameraManager_unregisterExtendedAvailabilityCallback)},
 {"ACameraMetadata_copy", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ACameraMetadata_free", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"ACameraMetadata_fromCameraMetadata", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ACameraMetadata_fromCameraMetadata", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ACameraMetadata_getAllTags", GetTrampolineFunc<auto(void*, void*, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"ACameraMetadata_getConstEntry", GetTrampolineFunc<auto(void*, uint32_t, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"ACameraMetadata_getTagFromName", GetTrampolineFunc<auto(void*, void*, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libcamera2ndk/proxy/trampolines_arm_to_x86-inl.h b/android_api/libcamera2ndk/proxy/trampolines_arm_to_x86-inl.h
index 008ee94..6a119ac 100644
--- a/android_api/libcamera2ndk/proxy/trampolines_arm_to_x86-inl.h
+++ b/android_api/libcamera2ndk/proxy/trampolines_arm_to_x86-inl.h
@@ -34,7 +34,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ACameraManager_unregisterExtendedAvailabilityCallback", GetTrampolineFunc<auto(void*, void*) -> uint32_t>(), reinterpret_cast<void*>(DoThunk_ACameraManager_unregisterExtendedAvailabilityCallback)},
 {"ACameraMetadata_copy", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ACameraMetadata_free", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"ACameraMetadata_fromCameraMetadata", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ACameraMetadata_fromCameraMetadata", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ACameraMetadata_getAllTags", GetTrampolineFunc<auto(void*, void*, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"ACameraMetadata_getConstEntry", GetTrampolineFunc<auto(void*, uint32_t, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"ACameraMetadata_getTagFromName", GetTrampolineFunc<auto(void*, void*, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libcamera2ndk/proxy/trampolines_riscv64_to_x86_64-inl.h b/android_api/libcamera2ndk/proxy/trampolines_riscv64_to_x86_64-inl.h
index 008ee94..6a119ac 100644
--- a/android_api/libcamera2ndk/proxy/trampolines_riscv64_to_x86_64-inl.h
+++ b/android_api/libcamera2ndk/proxy/trampolines_riscv64_to_x86_64-inl.h
@@ -34,7 +34,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"ACameraManager_unregisterExtendedAvailabilityCallback", GetTrampolineFunc<auto(void*, void*) -> uint32_t>(), reinterpret_cast<void*>(DoThunk_ACameraManager_unregisterExtendedAvailabilityCallback)},
 {"ACameraMetadata_copy", GetTrampolineFunc<auto(void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ACameraMetadata_free", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
-{"ACameraMetadata_fromCameraMetadata", GetTrampolineFunc<auto(void*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"ACameraMetadata_fromCameraMetadata", GetTrampolineFunc<auto(JNIEnv*, void*) -> void*>(), reinterpret_cast<void*>(NULL)},
 {"ACameraMetadata_getAllTags", GetTrampolineFunc<auto(void*, void*, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"ACameraMetadata_getConstEntry", GetTrampolineFunc<auto(void*, uint32_t, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"ACameraMetadata_getTagFromName", GetTrampolineFunc<auto(void*, void*, void*) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libjnigraphics/proxy/trampolines_arm64_to_x86_64-inl.h b/android_api/libjnigraphics/proxy/trampolines_arm64_to_x86_64-inl.h
index e8e6f8e..9d68b38 100644
--- a/android_api/libjnigraphics/proxy/trampolines_arm64_to_x86_64-inl.h
+++ b/android_api/libjnigraphics/proxy/trampolines_arm64_to_x86_64-inl.h
@@ -34,11 +34,11 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AImageDecoder_setTargetSize", GetTrampolineFunc<auto(void*, int32_t, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AImageDecoder_setUnpremultipliedRequired", GetTrampolineFunc<auto(void*, uint8_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AndroidBitmap_compress", GetTrampolineFunc<auto(void*, int32_t, void*, int32_t, int32_t, void*, auto(*)(void*, void*, uint64_t) -> uint8_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_getDataSpace", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_getHardwareBuffer", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_getInfo", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_lockPixels", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_unlockPixels", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_getDataSpace", GetTrampolineFunc<auto(JNIEnv*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_getHardwareBuffer", GetTrampolineFunc<auto(JNIEnv*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_getInfo", GetTrampolineFunc<auto(JNIEnv*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_lockPixels", GetTrampolineFunc<auto(JNIEnv*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_unlockPixels", GetTrampolineFunc<auto(JNIEnv*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 };  // kKnownTrampolines
 const KnownVariable kKnownVariables[] = {
 };  // kKnownVariables
diff --git a/android_api/libjnigraphics/proxy/trampolines_arm_to_x86-inl.h b/android_api/libjnigraphics/proxy/trampolines_arm_to_x86-inl.h
index 579399f..b5b0b0e 100644
--- a/android_api/libjnigraphics/proxy/trampolines_arm_to_x86-inl.h
+++ b/android_api/libjnigraphics/proxy/trampolines_arm_to_x86-inl.h
@@ -34,11 +34,11 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AImageDecoder_setTargetSize", GetTrampolineFunc<auto(void*, int32_t, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AImageDecoder_setUnpremultipliedRequired", GetTrampolineFunc<auto(void*, uint8_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AndroidBitmap_compress", GetTrampolineFunc<auto(void*, int32_t, void*, int32_t, int32_t, void*, auto(*)(void*, void*, uint32_t) -> uint8_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_getDataSpace", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_getHardwareBuffer", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_getInfo", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_lockPixels", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_unlockPixels", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_getDataSpace", GetTrampolineFunc<auto(JNIEnv*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_getHardwareBuffer", GetTrampolineFunc<auto(JNIEnv*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_getInfo", GetTrampolineFunc<auto(JNIEnv*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_lockPixels", GetTrampolineFunc<auto(JNIEnv*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_unlockPixels", GetTrampolineFunc<auto(JNIEnv*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 };  // kKnownTrampolines
 const KnownVariable kKnownVariables[] = {
 };  // kKnownVariables
diff --git a/android_api/libjnigraphics/proxy/trampolines_riscv64_to_x86_64-inl.h b/android_api/libjnigraphics/proxy/trampolines_riscv64_to_x86_64-inl.h
index e8e6f8e..9d68b38 100644
--- a/android_api/libjnigraphics/proxy/trampolines_riscv64_to_x86_64-inl.h
+++ b/android_api/libjnigraphics/proxy/trampolines_riscv64_to_x86_64-inl.h
@@ -34,11 +34,11 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"AImageDecoder_setTargetSize", GetTrampolineFunc<auto(void*, int32_t, int32_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AImageDecoder_setUnpremultipliedRequired", GetTrampolineFunc<auto(void*, uint8_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"AndroidBitmap_compress", GetTrampolineFunc<auto(void*, int32_t, void*, int32_t, int32_t, void*, auto(*)(void*, void*, uint64_t) -> uint8_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_getDataSpace", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_getHardwareBuffer", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_getInfo", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_lockPixels", GetTrampolineFunc<auto(void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
-{"AndroidBitmap_unlockPixels", GetTrampolineFunc<auto(void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_getDataSpace", GetTrampolineFunc<auto(JNIEnv*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_getHardwareBuffer", GetTrampolineFunc<auto(JNIEnv*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_getInfo", GetTrampolineFunc<auto(JNIEnv*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_lockPixels", GetTrampolineFunc<auto(JNIEnv*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
+{"AndroidBitmap_unlockPixels", GetTrampolineFunc<auto(JNIEnv*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 };  // kKnownTrampolines
 const KnownVariable kKnownVariables[] = {
 };  // kKnownVariables
diff --git a/android_api/libnativehelper/proxy/trampolines_arm64_to_x86_64-inl.h b/android_api/libnativehelper/proxy/trampolines_arm64_to_x86_64-inl.h
index d9e49c7..4c0b5f2 100644
--- a/android_api/libnativehelper/proxy/trampolines_arm64_to_x86_64-inl.h
+++ b/android_api/libnativehelper/proxy/trampolines_arm64_to_x86_64-inl.h
@@ -18,6 +18,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"JniConstants_FileDescriptorClass", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_FileDescriptor_descriptor", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_FileDescriptor_init", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"JniConstants_FileDescriptor_setInt$", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_NIOAccessClass", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_NIOAccess_getBaseArray", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_NIOAccess_getBaseArrayOffset", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
diff --git a/android_api/libnativehelper/proxy/trampolines_arm_to_x86-inl.h b/android_api/libnativehelper/proxy/trampolines_arm_to_x86-inl.h
index d9e49c7..4c0b5f2 100644
--- a/android_api/libnativehelper/proxy/trampolines_arm_to_x86-inl.h
+++ b/android_api/libnativehelper/proxy/trampolines_arm_to_x86-inl.h
@@ -18,6 +18,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"JniConstants_FileDescriptorClass", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_FileDescriptor_descriptor", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_FileDescriptor_init", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"JniConstants_FileDescriptor_setInt$", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_NIOAccessClass", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_NIOAccess_getBaseArray", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_NIOAccess_getBaseArrayOffset", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
diff --git a/android_api/libnativehelper/proxy/trampolines_riscv64_to_x86_64-inl.h b/android_api/libnativehelper/proxy/trampolines_riscv64_to_x86_64-inl.h
index d9e49c7..4c0b5f2 100644
--- a/android_api/libnativehelper/proxy/trampolines_riscv64_to_x86_64-inl.h
+++ b/android_api/libnativehelper/proxy/trampolines_riscv64_to_x86_64-inl.h
@@ -18,6 +18,7 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"JniConstants_FileDescriptorClass", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_FileDescriptor_descriptor", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_FileDescriptor_init", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
+{"JniConstants_FileDescriptor_setInt$", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_NIOAccessClass", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_NIOAccess_getBaseArray", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
 {"JniConstants_NIOAccess_getBaseArrayOffset", DoBadTrampoline, reinterpret_cast<void*>(DoBadThunk)},
diff --git a/android_api/libnativehelper/stubs_arm.cc b/android_api/libnativehelper/stubs_arm.cc
index 569816b..afb8453 100644
--- a/android_api/libnativehelper/stubs_arm.cc
+++ b/android_api/libnativehelper/stubs_arm.cc
@@ -35,6 +35,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(JNI_GetDefaultJavaVMInitArgs);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_FileDescriptorClass);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_FileDescriptor_descriptor);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_FileDescriptor_init);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_FileDescriptor_setInt$);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_NIOAccessClass);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_NIOAccess_getBaseArray);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_NIOAccess_getBaseArrayOffset);
@@ -84,6 +85,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_FileDescriptorClass);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_FileDescriptor_descriptor);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_FileDescriptor_init);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_FileDescriptor_setInt$);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_NIOAccessClass);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_NIOAccess_getBaseArray);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_NIOAccess_getBaseArrayOffset);
diff --git a/android_api/libnativehelper/stubs_arm64.cc b/android_api/libnativehelper/stubs_arm64.cc
index 569816b..afb8453 100644
--- a/android_api/libnativehelper/stubs_arm64.cc
+++ b/android_api/libnativehelper/stubs_arm64.cc
@@ -35,6 +35,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(JNI_GetDefaultJavaVMInitArgs);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_FileDescriptorClass);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_FileDescriptor_descriptor);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_FileDescriptor_init);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_FileDescriptor_setInt$);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_NIOAccessClass);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_NIOAccess_getBaseArray);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_NIOAccess_getBaseArrayOffset);
@@ -84,6 +85,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_FileDescriptorClass);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_FileDescriptor_descriptor);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_FileDescriptor_init);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_FileDescriptor_setInt$);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_NIOAccessClass);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_NIOAccess_getBaseArray);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_NIOAccess_getBaseArrayOffset);
diff --git a/android_api/libnativehelper/stubs_riscv64.cc b/android_api/libnativehelper/stubs_riscv64.cc
index 569816b..afb8453 100644
--- a/android_api/libnativehelper/stubs_riscv64.cc
+++ b/android_api/libnativehelper/stubs_riscv64.cc
@@ -35,6 +35,7 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(JNI_GetDefaultJavaVMInitArgs);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_FileDescriptorClass);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_FileDescriptor_descriptor);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_FileDescriptor_init);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_FileDescriptor_setInt$);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_NIOAccessClass);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_NIOAccess_getBaseArray);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(JniConstants_NIOAccess_getBaseArrayOffset);
@@ -84,6 +85,7 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_FileDescriptorClass);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_FileDescriptor_descriptor);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_FileDescriptor_init);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_FileDescriptor_setInt$);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_NIOAccessClass);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_NIOAccess_getBaseArray);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libnativehelper.so", JniConstants_NIOAccess_getBaseArrayOffset);
diff --git a/android_api/libvulkan/proxy/gen_vulkan.go b/android_api/libvulkan/proxy/gen_vulkan.go
index 6b77f5e..64a9807 100644
--- a/android_api/libvulkan/proxy/gen_vulkan.go
+++ b/android_api/libvulkan/proxy/gen_vulkan.go
@@ -919,7 +919,8 @@ func getRequiredConversions(commands map[string]cpp_types.Type, types map[string
 						base_name == "VkDrmFormatModifierProperties2EXT" ||
 						base_name == "VkDrmFormatModifierPropertiesEXT" ||
 						base_name == "VkRenderPassCreationFeedbackInfoEXT" ||
-						base_name == "VkRenderPassSubpassFeedbackInfoEXT" {
+						base_name == "VkRenderPassSubpassFeedbackInfoEXT" ||
+						base_name == "VkPhysicalDeviceLayeredApiPropertiesListKHR" {
 						// TODO(b/171255170): Process the optional structures correctly.
 					} else if base_name == "VkPipelineCreationFeedback" {
 						// VkPipelineCreationFeedback is referred from input data structure VkPipelineCreationFeedbackCreateInfo
diff --git a/android_api/libvulkan/proxy/vulkan_types.go b/android_api/libvulkan/proxy/vulkan_types.go
index d45bc56..88c108e 100644
--- a/android_api/libvulkan/proxy/vulkan_types.go
+++ b/android_api/libvulkan/proxy/vulkan_types.go
@@ -185,6 +185,12 @@ func PlatformTypes() map[string]cpp_types.Type {
 		"StdVideoH265SubLayerHrdParameters":            cpp_types.VoidType, // Treat as opaque type for now.
 		"StdVideoH265VideoParameterSet":                cpp_types.VoidType, // Treat as opaque type for now.
 		"StdVideoH265VpsFlags":                         cpp_types.VoidType, // Treat as opaque type for now.
+		"StdVideoAV1Profile":				cpp_types.IntType,  // Treat as opaque type for now.
+		"StdVideoAV1Level":				cpp_types.IntType,  // Treat as opaque type for now.
+		"StdVideoAV1SequenceHeader":			cpp_types.VoidType, // Treat as opaque type for now.
+		"StdVideoDecodeAV1PictureInfo":			cpp_types.VoidType, // Treat as opaque type for now.
+		"StdVideoDecodeAV1ReferenceInfo":		cpp_types.VoidType, // Treat as opaque type for now.
+		"StdVideoDecodeAV1ReferenceInfoFlags":		cpp_types.IntType,
 		"uint8_t":                                      cpp_types.UInt8TType,
 		"uint16_t":                                     cpp_types.UInt16TType,
 		"uint32_t":                                     cpp_types.UInt32TType,
diff --git a/android_api/libvulkan/proxy/vulkan_xml.go b/android_api/libvulkan/proxy/vulkan_xml.go
index 3924d76..8244663 100644
--- a/android_api/libvulkan/proxy/vulkan_xml.go
+++ b/android_api/libvulkan/proxy/vulkan_xml.go
@@ -279,6 +279,11 @@ var known_types = map[string]string{
 	"StdVideoH265SubLayerHrdParameters":            "vk_video/vulkan_video_codec_h265std.h",
 	"StdVideoH265VideoParameterSet":                "vk_video/vulkan_video_codec_h265std.h",
 	"StdVideoH265VpsFlags":                         "vk_video/vulkan_video_codec_h265std.h",
+	"StdVideoAV1Profile":				"vk_video/vulkan_video_codec_av1std.h",
+	"StdVideoAV1Level":				"vk_video/vulkan_video_codec_av1std.h",
+	"StdVideoAV1SequenceHeader":			"vk_video/vulkan_video_codec_av1std.h",
+	"StdVideoDecodeAV1PictureInfo":			"vk_video/vulkan_video_codec_av1std_decode.h",
+	"StdVideoDecodeAV1ReferenceInfo":		"vk_video/vulkan_video_codec_av1std_decode.h",
 	"uint8_t":                                      "vk_platform",
 	"uint16_t":                                     "vk_platform",
 	"uint32_t":                                     "vk_platform",
@@ -325,6 +330,8 @@ var known_defines = map[string]string{
 		"#define <name>VK_API_VERSION_1_2</name> <type>VK_MAKE_API_VERSION</type>(0, 1, 2, 0)// Patch version should always be set to 0",
 	"VK_API_VERSION_1_3": "// Vulkan 1.3 version number\n" +
 		"#define <name>VK_API_VERSION_1_3</name> <type>VK_MAKE_API_VERSION</type>(0, 1, 3, 0)// Patch version should always be set to 0",
+	"VK_API_VERSION_1_4": "// Vulkan 1.4 version number\n" +
+		"#define <name>VK_API_VERSION_1_4</name> <type>VK_MAKE_API_VERSION</type>(0, 1, 4, 0)// Patch version should always be set to 0",
 	"VKSC_API_VERSION_1_0": "// Vulkan SC 1.0 version number\n#define <name>VKSC_API_VERSION_1_0</name> <type>VK_MAKE_API_VERSION</type>(VKSC_API_VARIANT, 1, 0, 0)// Patch version should always be set to 0",
 	"VK_HEADER_VERSION": "// Version of this file\n" +
 		"#define <name>VK_HEADER_VERSION</name> ",
@@ -748,31 +755,31 @@ func vulkanBaseTypeFromXML(typе *typeInfo) (cpp_types.Type, error) {
 		return cpp_types.OpaqueType("CAMetalLayer"), nil
 	}
 	if typе.Name == "MTLDevice_id" {
-		if RawXML != "#ifdef __OBJC__ @protocol MTLDevice; typedef id&lt;MTLDevice&gt; MTLDevice_id; #else typedef void* <name>MTLDevice_id</name>; #endif" {
+		if RawXML != "#ifdef __OBJC__ @protocol MTLDevice; typedef __unsafe_unretained id&lt;MTLDevice&gt; MTLDevice_id; #else typedef void* <name>MTLDevice_id</name>; #endif" {
 			return nil, errors.New("Unexpected define \"" + typе.Name + "\": \"" + typе.RawXML + "\"\"")
 		}
 		return cpp_types.PointerType(cpp_types.VoidType), nil
 	}
 	if typе.Name == "MTLCommandQueue_id" {
-		if RawXML != "#ifdef __OBJC__ @protocol MTLCommandQueue; typedef id&lt;MTLCommandQueue&gt; MTLCommandQueue_id; #else typedef void* <name>MTLCommandQueue_id</name>; #endif" {
+		if RawXML != "#ifdef __OBJC__ @protocol MTLCommandQueue; typedef __unsafe_unretained id&lt;MTLCommandQueue&gt; MTLCommandQueue_id; #else typedef void* <name>MTLCommandQueue_id</name>; #endif" {
 			return nil, errors.New("Unexpected define \"" + typе.Name + "\": \"" + typе.RawXML + "\"\"")
 		}
 		return cpp_types.PointerType(cpp_types.VoidType), nil
 	}
 	if typе.Name == "MTLBuffer_id" {
-		if RawXML != "#ifdef __OBJC__ @protocol MTLBuffer; typedef id&lt;MTLBuffer&gt; MTLBuffer_id; #else typedef void* <name>MTLBuffer_id</name>; #endif" {
+		if RawXML != "#ifdef __OBJC__ @protocol MTLBuffer; typedef __unsafe_unretained id&lt;MTLBuffer&gt; MTLBuffer_id; #else typedef void* <name>MTLBuffer_id</name>; #endif" {
 			return nil, errors.New("Unexpected define \"" + typе.Name + "\": \"" + typе.RawXML + "\"\"")
 		}
 		return cpp_types.PointerType(cpp_types.VoidType), nil
 	}
 	if typе.Name == "MTLTexture_id" {
-		if RawXML != "#ifdef __OBJC__ @protocol MTLTexture; typedef id&lt;MTLTexture&gt; MTLTexture_id; #else typedef void* <name>MTLTexture_id</name>; #endif" {
+		if RawXML != "#ifdef __OBJC__ @protocol MTLTexture; typedef __unsafe_unretained id&lt;MTLTexture&gt; MTLTexture_id; #else typedef void* <name>MTLTexture_id</name>; #endif" {
 			return nil, errors.New("Unexpected define \"" + typе.Name + "\": \"" + typе.RawXML + "\"\"")
 		}
 		return cpp_types.PointerType(cpp_types.VoidType), nil
 	}
 	if typе.Name == "MTLSharedEvent_id" {
-		if RawXML != "#ifdef __OBJC__ @protocol MTLSharedEvent; typedef id&lt;MTLSharedEvent&gt; MTLSharedEvent_id; #else typedef void* <name>MTLSharedEvent_id</name>; #endif" {
+		if RawXML != "#ifdef __OBJC__ @protocol MTLSharedEvent; typedef __unsafe_unretained id&lt;MTLSharedEvent&gt; MTLSharedEvent_id; #else typedef void* <name>MTLSharedEvent_id</name>; #endif" {
 			return nil, errors.New("Unexpected define \"" + typе.Name + "\": \"" + typе.RawXML + "\"\"")
 		}
 		return cpp_types.PointerType(cpp_types.VoidType), nil
@@ -1215,6 +1222,10 @@ func vulkanStructuralTypeMembersFromXML(name string, members []structuralMemberI
 				element_type.Kind(cpp_types.FirstArch) != cpp_types.UInt32T {
 				return nil, errors.New("Unexpected altlen field in \"" + member.Name + "\"")
 			}
+			// Weird case with constant 1 length. This is currently only used by GetDeviceSubpassShadingMaxWorkgroupSize,
+			// for a VkExtent2D, which should not require translation.
+		} else if member.Length == "1" {
+			// TODO(b/372341855): Figure out what we really need to do in this case.
 		} else if member.Length != "" && member.Length != "null-terminated" && !strings.HasSuffix(member.Length, ",null-terminated") {
 			if length, ok := field_map[member.Length]; ok {
 				field_map[member.Name].length = length
diff --git a/android_api/libvulkan/proxy/vulkan_xml_define.h b/android_api/libvulkan/proxy/vulkan_xml_define.h
index 9ce08ff..a46ba91 100644
--- a/android_api/libvulkan/proxy/vulkan_xml_define.h
+++ b/android_api/libvulkan/proxy/vulkan_xml_define.h
@@ -115,6 +115,7 @@
 // Android.
 #define BERBERIS_VK_WAYLAND_SURFACE_CREATE_FLAGS_NOVERIFY_KHR 1
 #define BERBERIS_VK_WAYLAND_SURFACE_CREATE_INFO_NOVERIFY_KHR 1
+#define BERBERIS_VK_WAYLAND_SURFACE_CREATE_FLAG_BITS_NOVERIFY_KHR 1
 
 // Windows types: vulkan_win32.h requires windows.h which is not available on Android.
 #define BERBERIS_VK_FULL_SCREEN_EXCLUSIVE_NOVERIFY_EXT 1
@@ -453,6 +454,38 @@
 #define BERBERIS_VK_STRUCTURE_TYPE_IMPORT_BUFFER_GOOGLE_NOVERIFY 1
 #define BERBERIS_VK_STRUCTURE_TYPE_IMPORT_COLOR_BUFFER_GOOGLE_NOVERIFY 1
 #define BERBERIS_VK_STRUCTURE_TYPE_CREATE_BLOB_GOOGLE_NOVERIFY 1
+#define BERBERIS_VK_ACCESS_2_RESERVED_57_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_ACCESS_2_RESERVED_58_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_ACCESS_2_RESERVED_59_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_ACCESS_2_RESERVED_55_BIT_NV_NOVERIFY 1
+#define BERBERIS_VK_ACCESS_2_RESERVED_56_BIT_NV_NOVERIFY 1
+#define BERBERIS_VK_BUFFER_USAGE_2_EXTENSION_573_BIT_EXT_NOVERIFY 1
+#define BERBERIS_VK_BUFFER_USAGE_FLAG_BITS2_MAX_ENUM_NOVERIFY 1
+#define BERBERIS_VK_DEPENDENCY_EXTENSION_575_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_DEPENDENCY_EXTENSION_586_BIT_IMG_NOVERIFY 1
+#define BERBERIS_VK_EXTERNAL_MEMORY_HANDLE_TYPE_590_BIT_HUAWEI_NOVERIFY 1
+#define BERBERIS_VK_EXTERNAL_MEMORY_HANDLE_TYPE_603_BIT_EXT_NOVERIFY 1
+#define BERBERIS_VK_EXTERNAL_MEMORY_HANDLE_TYPE_603_BIT_2_EXT_NOVERIFY 1
+#define BERBERIS_VK_FORMAT_FEATURE_2_RESERVED_51_BIT_EXT_NOVERIFY 1
+#define BERBERIS_VK_FORMAT_FEATURE_2_RESERVED_49_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_FORMAT_FEATURE_2_RESERVED_50_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_IMAGE_USAGE_RESERVED_25_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_IMAGE_USAGE_RESERVED_26_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_PIPELINE_CREATE_RESERVED_36_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_PIPELINE_CREATE_2_RESERVED_33_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_PIPELINE_CREATE_2_RESERVED_33_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_PIPELINE_CREATE_2_EXTENSION_573_BIT_EXT_NOVERIFY 1
+#define BERBERIS_VK_PIPELINE_CREATE_2_RESERVED_35_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_PIPELINE_CREATE_2_RESERVED_37_BIT_ARM_NOVERIFY 1
+#define BERBERIS_VK_PIPELINE_CREATE_FLAG_BITS2_MAX_ENUM_NOVERIFY 1
+#define BERBERIS_VK_PIPELINE_STAGE_2_RESERVED_44_BIT_NV_NOVERIFY 1
+#define BERBERIS_VK_PIPELINE_STAGE_2_RESERVED_45_BIT_NV_NOVERIFY 1
+#define BERBERIS_VK_RENDERING_EXTENSION_505_BIT_EXT_NOVERIFY 1
+#define BERBERIS_VK_SHADER_STAGE_RESERVED_15_BIT_NV_NOVERIFY 1
+#define BERBERIS_VK_VIDEO_SESSION_CREATE_RESERVED_3_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_VIDEO_SESSION_CREATE_RESERVED_4_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_VIDEO_SESSION_CREATE_RESERVED_5_BIT_KHR_NOVERIFY 1
+#define BERBERIS_VK_VIDEO_SESSION_CREATE_RESERVED_6_BIT_KHR_NOVERIFY 1
 
 // Forward compatibility: types which became opaque/different in later versiona of Vulkan.
 #define BERBERIS_VK_ACCELERATION_STRUCTURE_CAPTURE_DESCRIPTOR_DATA_INFO_NOVERIFY_EXT 1
diff --git a/android_api/vdso/Android.bp b/android_api/vdso/Android.bp
index 8754194..94e91f7 100644
--- a/android_api/vdso/Android.bp
+++ b/android_api/vdso/Android.bp
@@ -23,9 +23,9 @@ cc_library_shared {
     enabled: false,
     native_bridge_supported: true,
     target: {
-       native_bridge: {
-           enabled: true,
-       }
+        native_bridge: {
+            enabled: true,
+        },
     },
     arch: {
         arm64: {
@@ -47,6 +47,9 @@ cc_library_shared {
         // TODO(b/146399556): Use -z,separate-code to ensure that each segment's p_offset and
         // p_vaddr values are equal to work around problems with __libc_init_vdso in Bionic.
         "-Wl,-z,separate-code",
+        // We need sysv hash style to support vdso-parser:
+        // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/vDSO/parse_vdso.c
+        "-Wl,--hash-style=both",
     ],
     system_shared_libs: [],
     // Opt out of native_coverage when opting out of system_shared_libs
diff --git a/android_api/vdso/include/native_bridge_support/vdso/interceptable_functions.h b/android_api/vdso/include/native_bridge_support/vdso/interceptable_functions.h
index 3066bbc..31e8e9d 100644
--- a/android_api/vdso/include/native_bridge_support/vdso/interceptable_functions.h
+++ b/android_api/vdso/include/native_bridge_support/vdso/interceptable_functions.h
@@ -17,33 +17,77 @@
 #ifndef NATIVE_BRIDGE_SUPPORT_VDSO_INTERCEPTABLE_FUNCTIONS_H_
 #define NATIVE_BRIDGE_SUPPORT_VDSO_INTERCEPTABLE_FUNCTIONS_H_
 
-#include <assert.h>
 #include <stdint.h>
 
 #include "native_bridge_support/vdso/vdso.h"
 
+// An app may patch symbols exported from NDK libraries (e.g. b/378772009). This effectively
+// invalidates trampolines bound to such symbols. In addition invalidation usually affects the whole
+// cache line so that unpatched functions adjacent to the patched one may lose trampoline
+// connection too.
+//
+// As a workaround to this issue each symbol below has two entries: a regular exported symbol and a
+// hidden stub. The regular symbol simply jumps to the stub which we bind to a trampoline. This way
+// if the regular symbol is patched the stub still remains correctly connected to the trampoline.
+// Since the stub is hidden it's unlikely that it'll be patched on purpose.
+//
+// When a symbol is patched the corresponding instruction cache invalidation instruction is
+// issued on ARM and RISC-V. It usually invalidates the whole cache line so that unpatched functions
+// adjacent to the patched one may also lose trampoline connection. Since currently regular and stub
+// entries are interleaved we align them on cache line size (64 bytes) so that invalidations are
+// isolated.
+// TODO(b/379378784): This results in somewhat larger stubs binaries (<1Mb in total for all of
+// them). If we combine regular and stub entries in two groups, we'll only need to ensure alignment
+// at the start/end of the regular symbols group. Note, that we should leave enough code for
+// patching to be successful. E.g. 8 bytes may not be enough to encode arbitrary 64-bit address,
+// but 16 bytes should always be enough.
+//
+// As an optimization we keep regular symbols bound to trampolines as well, so that we don't need
+// to translate their code unless and until it's invalidated.
+
 #if defined(__arm__)
-#define INTERCEPTABLE_STUB_ASM_FUNCTION(name)                  \
-  extern "C" void __attribute((target("arm"), naked)) name() { \
-    __asm__ __volatile__(                                      \
-        "ldr r3, =0\n"                                         \
-        "bx r3");                                              \
+
+#define INTERCEPTABLE_STUB_ASM_FUNCTION(name)                                                      \
+  extern "C" void                                                                                  \
+      __attribute__((target("arm"), aligned(64), naked, __visibility__("hidden"))) name##_stub() { \
+    __asm__ __volatile__(                                                                          \
+        "ldr r3, =0\n"                                                                             \
+        "bx r3");                                                                                  \
+  }                                                                                                \
+                                                                                                   \
+  extern "C" __attribute__((target("arm"), aligned(64), naked)) void name() {                      \
+    __asm__ __volatile__("b " #name "_stub");                                                      \
   }
+
 #elif defined(__aarch64__)
-#define INTERCEPTABLE_STUB_ASM_FUNCTION(name)   \
-  extern "C" void __attribute((naked)) name() { \
-    __asm__ __volatile__(                       \
-        "ldr x3, =0\n"                          \
-        "blr x3");                              \
+
+#define INTERCEPTABLE_STUB_ASM_FUNCTION(name)                                                   \
+  extern "C" void __attribute__((aligned(64), naked, __visibility__("hidden"))) name##_stub() { \
+    /* TODO(b/232598137): maybe replace with "udf imm16" */                                     \
+    __asm__ __volatile__(                                                                       \
+        "ldr x3, =0\n"                                                                          \
+        "blr x3\n");                                                                            \
+  }                                                                                             \
+                                                                                                \
+  extern "C" __attribute__((aligned(64), naked)) void name() {                                  \
+    __asm__ __volatile__("b " #name "_stub");                                                   \
   }
+
 #elif defined(__riscv)
-#define INTERCEPTABLE_STUB_ASM_FUNCTION(name)   \
-  extern "C" void __attribute((naked)) name() { \
-    __asm__ __volatile__(                       \
-        "unimp");                               \
+
+#define INTERCEPTABLE_STUB_ASM_FUNCTION(name)                                                   \
+  extern "C" void __attribute__((aligned(64), naked, __visibility__("hidden"))) name##_stub() { \
+    __asm__ __volatile__("unimp\n");                                                            \
+  }                                                                                             \
+                                                                                                \
+  extern "C" __attribute__((aligned(64), naked)) void name() {                                  \
+    __asm__ __volatile__("j " #name "_stub");                                                   \
   }
+
 #else
+
 #error Unknown architecture, only riscv64, arm and aarch64 are supported.
+
 #endif
 
 #define DEFINE_INTERCEPTABLE_STUB_VARIABLE(name) uintptr_t name;
@@ -51,11 +95,10 @@
 #define INIT_INTERCEPTABLE_STUB_VARIABLE(library_name, name) \
   native_bridge_intercept_symbol(&name, library_name, #name)
 
-#define DEFINE_INTERCEPTABLE_STUB_FUNCTION(name) \
-  extern "C" void name();                        \
-  INTERCEPTABLE_STUB_ASM_FUNCTION(name)
+#define DEFINE_INTERCEPTABLE_STUB_FUNCTION(name) INTERCEPTABLE_STUB_ASM_FUNCTION(name)
 
-#define INIT_INTERCEPTABLE_STUB_FUNCTION(library_name, name) \
-  native_bridge_intercept_symbol(reinterpret_cast<void*>(name), library_name, #name)
+#define INIT_INTERCEPTABLE_STUB_FUNCTION(library_name, name)                          \
+  native_bridge_intercept_symbol(reinterpret_cast<void*>(name), library_name, #name); \
+  native_bridge_intercept_symbol(reinterpret_cast<void*>(name##_stub), library_name, #name)
 
 #endif  // NATIVE_BRIDGE_SUPPORT_VDSO_INTERCEPTABLE_FUNCTIONS_H_
diff --git a/guest_state/include/native_bridge_support/arm64/guest_state/guest_state_cpu_state.h b/guest_state/include/native_bridge_support/arm64/guest_state/guest_state_cpu_state.h
index 83d06dd..df67894 100644
--- a/guest_state/include/native_bridge_support/arm64/guest_state/guest_state_cpu_state.h
+++ b/guest_state/include/native_bridge_support/arm64/guest_state/guest_state_cpu_state.h
@@ -30,12 +30,21 @@ struct CPUState {
 
   // Flags
   // clang-format off
+#if defined(__x86_64__)
   enum FlagMask {
     kFlagNegative = 1 << 15,
     kFlagZero     = 1 << 14,
     kFlagCarry    = 1 << 8,
     kFlagOverflow = 1,
   };
+#else
+  enum FlagMask {
+    kFlagNegative = 1 << 3,
+    kFlagZero     = 1 << 2,
+    kFlagCarry    = 1 << 1,
+    kFlagOverflow = 1,
+  };
+#endif
 
   static constexpr uint32_t kFpsrQcBit = 1U << 27;
 
```

