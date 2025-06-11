```diff
diff --git a/Android.bp b/Android.bp
index 447f977..5dddd3b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -154,15 +154,15 @@ rust_bindgen {
         "android.hardware.common.fmq-V1-rust",
         "android.hardware.common-V2-rust",
     ],
-    static_libs: [
-        "libfmq",
-    ],
     whole_static_libs: [
+        "libfmq",
         "libfmq_erased",
     ],
     shared_libs: [
         "libc++",
         "liblog",
+        "libbase",
+        "libutils",
         "android.hardware.common.fmq-V1-ndk",
     ],
     apex_available: [
@@ -192,6 +192,7 @@ rust_defaults {
     visibility: [
         ":__subpackages__",
         "//system/software_defined_vehicle/core_services/sdv_comms:__subpackages__",
+        "//vendor:__subpackages__",
     ],
     crate_name: "fmq",
     srcs: ["libfmq.rs"],
diff --git a/libfmq.rs b/libfmq.rs
index 47c5c15..c2309da 100644
--- a/libfmq.rs
+++ b/libfmq.rs
@@ -22,11 +22,11 @@ use fmq_bindgen::{
     ndk_ScopedFileDescriptor, ErasedMessageQueue, ErasedMessageQueueDesc, GrantorDescriptor,
     MQDescriptor, MemTransaction, NativeHandle, ParcelFileDescriptor, SynchronizedReadWrite,
 };
+use log::error;
+use zerocopy::{FromBytes, Immutable, IntoBytes};
 
 use std::ptr::addr_of_mut;
 
-use log::error;
-
 /// A trait indicating that a type is safe to pass through shared memory.
 ///
 /// # Safety
@@ -40,8 +40,10 @@ use log::error;
 /// the same process. As such, `Share` is a supertrait of `Sync`.
 pub unsafe trait Share: Sync {}
 
-// SAFETY: All types implementing the `zerocopy::AsBytes` trait implement `Share`.
-unsafe impl<T: zerocopy::AsBytes + zerocopy::FromBytes + Send + Sync> Share for T {}
+// SAFETY: All types implementing the zerocopy `Immutable`, `IntoBytes` and `FromBytes` traits
+// implement `Share`, because that implies that they don't have any interior mutability and can be
+// treated as just a slice of bytes.
+unsafe impl<T: Immutable + IntoBytes + FromBytes + Send + Sync> Share for T {}
 
 /// An IPC message queue for values of type T.
 pub struct MessageQueue<T> {
@@ -63,7 +65,7 @@ pub struct WriteCompletion<'a, T: Share> {
     n_written: usize,
 }
 
-impl<'a, T: Share> WriteCompletion<'a, T> {
+impl<T: Share> WriteCompletion<'_, T> {
     /// Obtain a pointer to the location at which the idx'th item should be
     /// stored.
     ///
@@ -135,7 +137,7 @@ impl<'a, T: Share> WriteCompletion<'a, T> {
     }
 }
 
-impl<'a, T: Share> Drop for WriteCompletion<'a, T> {
+impl<T: Share> Drop for WriteCompletion<'_, T> {
     fn drop(&mut self) {
         if self.n_written < self.n_elems {
             error!(
@@ -351,7 +353,7 @@ pub struct ReadCompletion<'a, T: Share> {
     n_read: usize,
 }
 
-impl<'a, T: Share> ReadCompletion<'a, T> {
+impl<T: Share> ReadCompletion<'_, T> {
     /// Obtain a pointer to the location at which the idx'th item is located.
     ///
     /// The returned pointer is only valid while `self` has not been dropped and
@@ -419,7 +421,7 @@ impl<'a, T: Share> ReadCompletion<'a, T> {
     }
 }
 
-impl<'a, T: Share> Drop for ReadCompletion<'a, T> {
+impl<T: Share> Drop for ReadCompletion<'_, T> {
     fn drop(&mut self) {
         if self.n_read < self.n_elems {
             error!(
```

