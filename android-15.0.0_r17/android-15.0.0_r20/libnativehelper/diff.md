```diff
diff --git a/JniInvocation.c b/JniInvocation.c
index 7effddb..ce99a9b 100644
--- a/JniInvocation.c
+++ b/JniInvocation.c
@@ -26,6 +26,7 @@
 #include <errno.h>
 #include <jni.h>
 #include <stdbool.h>
+#include <stdlib.h>
 #include <string.h>
 #include <sys/types.h>
 #include <sys/stat.h>
@@ -64,8 +65,18 @@ static struct JniInvocationImpl g_impl;
 
 #define UNUSED(x) (x) = (x)
 
+static bool RunningOnVM() {
+  const char* on_vm = getenv("ART_TEST_ON_VM");
+  return on_vm != NULL && strcmp("true", on_vm) == 0;
+}
+
 static bool IsDebuggable() {
 #ifdef __ANDROID__
+  if (RunningOnVM()) {
+    // VM environment is always treated as debuggable, as it has no system properties to query.
+    return true;
+  }
+
   char debuggable[PROP_VALUE_MAX] = {0};
   __system_property_get("ro.debuggable", debuggable);
   return strcmp(debuggable, "1") == 0;
diff --git a/include/android/file_descriptor_jni.h b/include/android/file_descriptor_jni.h
index 26529b9..305953b 100644
--- a/include/android/file_descriptor_jni.h
+++ b/include/android/file_descriptor_jni.h
@@ -49,7 +49,7 @@ __BEGIN_DECLS
  * \param env a pointer to the JNI Native Interface of the current thread.
  * \return a java.io.FileDescriptor on success, nullptr if insufficient heap memory is available.
  */
-jobject AFileDescriptor_create(JNIEnv* env) __INTRODUCED_IN(31);
+JNIEXPORT jobject AFileDescriptor_create(JNIEnv* env) __INTRODUCED_IN(31);
 
 /**
  * Returns the Unix file descriptor represented by the given java.io.FileDescriptor.
@@ -64,7 +64,7 @@ jobject AFileDescriptor_create(JNIEnv* env) __INTRODUCED_IN(31);
  * \param fileDescriptor a java.io.FileDescriptor instance.
  * \return the Unix file descriptor wrapped by \a fileDescriptor.
  */
-int AFileDescriptor_getFd(JNIEnv* env, jobject fileDescriptor) __INTRODUCED_IN(31);
+JNIEXPORT int AFileDescriptor_getFd(JNIEnv* env, jobject fileDescriptor) __INTRODUCED_IN(31);
 
 /**
  * Sets the Unix file descriptor represented by the given java.io.FileDescriptor.
@@ -81,7 +81,7 @@ int AFileDescriptor_getFd(JNIEnv* env, jobject fileDescriptor) __INTRODUCED_IN(3
  * \param fileDescriptor a java.io.FileDescriptor instance.
  * \param fd a Unix file descriptor that \a fileDescriptor will subsequently represent.
  */
-void AFileDescriptor_setFd(JNIEnv* env, jobject fileDescriptor, int fd) __INTRODUCED_IN(31);
+JNIEXPORT void AFileDescriptor_setFd(JNIEnv* env, jobject fileDescriptor, int fd) __INTRODUCED_IN(31);
 
 __END_DECLS
 
diff --git a/include_jni/jni.h b/include_jni/jni.h
index 8346ca4..7cbdfda 100644
--- a/include_jni/jni.h
+++ b/include_jni/jni.h
@@ -1102,8 +1102,13 @@ jint JNI_GetDefaultJavaVMInitArgs(void*);
 jint JNI_CreateJavaVM(JavaVM**, JNIEnv**, void*);
 jint JNI_GetCreatedJavaVMs(JavaVM**, jsize, jsize*);
 
+#ifdef _WIN32
+#define JNIIMPORT  __declspec(dllimport)
+#define JNIEXPORT  __declspec(dllexport)
+#else
 #define JNIIMPORT
 #define JNIEXPORT  __attribute__ ((visibility ("default")))
+#endif
 #define JNICALL
 
 /*
```

