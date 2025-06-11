```diff
diff --git a/Cargo.lock b/Cargo.lock
index ba67ef2..32f8cf8 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -599,7 +599,7 @@ checksum = "3354b9ac3fae1ff6755cb6db53683adb661634f67557942dea4facebec0fee4b"
 
 [[package]]
 name = "v4l2r"
-version = "0.0.4"
+version = "0.0.5"
 dependencies = [
  "anyhow",
  "bindgen",
diff --git a/README.md b/README.md
index c29aca6..c34cad2 100644
--- a/README.md
+++ b/README.md
@@ -49,6 +49,14 @@ e.g. video decoding and encoding.
 library other projects can link against. A `v4l2r.h` header file with the public
 API is generated upon build.
 
+## Build options
+
+`cargo build` will attempt to generate the V4L2 bindings from
+`/usr/include/linux/videodev2.h` by default. The `V4L2R_VIDEODEV2_H_PATH`
+environment variable can be set to a different location that contains a
+`videodev2.h` file if you need to generate the bindings from a different
+location.
+
 ## How to use
 
 Check `lib/examples/vicodec_test/device_api.rs` for a short example of how to
diff --git a/ffi/src/decoder.rs b/ffi/src/decoder.rs
index a2720d5..29dbb63 100644
--- a/ffi/src/decoder.rs
+++ b/ffi/src/decoder.rs
@@ -28,7 +28,7 @@ use v4l2r::{
         CompletedInputBuffer, DecoderEvent, DecoderEventCallback, FormatChangedCallback,
         FormatChangedReply, InputDoneCallback,
     },
-    device::queue::{direction::Capture, dqbuf::DqBuffer, qbuf::OutputQueueable, FormatBuilder},
+    device::queue::{direction::Capture, dqbuf::DqBuffer, FormatBuilder, OutputQueueable},
     memory::DmaBufHandle,
     PixelFormat, PlaneLayout, Rect,
 };
@@ -139,13 +139,10 @@ fn set_capture_format_cb(
     desired_pixel_format: Option<PixelFormat>,
     visible_rect: Rect,
     min_num_buffers: usize,
-    decoder: *mut v4l2r_decoder,
+    decoder: &mut v4l2r_decoder,
     event_cb: v4l2r_decoder_event_cb,
     cb_data: *mut c_void,
 ) -> anyhow::Result<FormatChangedReply<Arc<v4l2r_video_frame_provider>>> {
-    // Safe unless the C part did something funny with the decoder returned by
-    // `v4l2r_decoder_new`.
-    let decoder = unsafe { decoder.as_mut().unwrap() };
     let mut v4l2_format: bindings::v4l2_format = match desired_pixel_format {
         Some(format) => f.set_pixelformat(format).apply()?,
         None => f.apply()?,
@@ -213,6 +210,7 @@ fn frame_decoded_cb(
         // Should be safe as `provider` is initialized in the format
         // change callback and is thus valid, as well as `frame`.
         match &decoder.provider {
+            // SAFETY: `provider` is a valid pointer to a frame provider.
             Some(provider) => unsafe {
                 v4l2r_video_frame_provider_queue_frame(provider.as_ref(), frame);
             },
@@ -330,6 +328,8 @@ fn v4l2r_decoder_new_safe(
         let decoder_ptr = decoder_ptr;
         let cb_data = cb_data;
 
+        // SAFETY: `decoder_ptr` will be initialized with a valid decoder by the time this
+        // callback is called.
         let decoder = unsafe { decoder_ptr.0.as_mut().unwrap() };
 
         match event {
@@ -367,12 +367,16 @@ fn v4l2r_decoder_new_safe(
                 let decoder_ptr = decoder_ptr;
                 let cb_data = cb_data;
 
+                // SAFETY: `decoder_ptr` will be initialized with a valid decoder by the time this
+                // callback is called.
+                let decoder = unsafe { decoder_ptr.0.as_mut().unwrap() };
+
                 set_capture_format_cb(
                     f,
                     output_format,
                     visible_rect,
                     min_num_buffers,
-                    decoder_ptr.0,
+                    decoder,
                     event_cb,
                     cb_data.0,
                 )
@@ -396,6 +400,7 @@ fn v4l2r_decoder_new_safe(
         input_buf_size: input_format.plane_fmt[0].sizeimage as u64,
     };
 
+    // SAFETY: `decoder` is a `v4l2r_decoder`, the same type expected by `decoder_box`.
     let decoder_box = unsafe {
         // Replace our uninitialized heap memory with our valid decoder.
         decoder_box.as_mut_ptr().write(decoder);
diff --git a/ffi/src/memory.rs b/ffi/src/memory.rs
index c0c7491..48cb0cd 100644
--- a/ffi/src/memory.rs
+++ b/ffi/src/memory.rs
@@ -17,10 +17,7 @@ use v4l2r::{
         poller::Waker,
         queue::{
             handles_provider::{GetSuitableBufferError, HandlesProvider},
-            qbuf::{
-                get_free::GetFreeCaptureBuffer, get_indexed::GetCaptureBufferByIndex,
-                CaptureQueueableProvider,
-            },
+            GetCaptureBufferByIndex, GetFreeCaptureBuffer,
         },
     },
     memory::{BufferHandles, DmaBufHandle, DmaBufSource, MemoryType, PrimitiveBufferHandles},
@@ -164,10 +161,7 @@ impl HandlesProvider for v4l2r_video_frame_provider {
         &self,
         handles: &Self::HandleType,
         queue: &'a Q,
-    ) -> Result<
-        <Q as CaptureQueueableProvider<'a, Self::HandleType>>::Queueable,
-        GetSuitableBufferError,
-    >
+    ) -> Result<Q::Queueable, GetSuitableBufferError>
     where
         Q: GetCaptureBufferByIndex<'a, Self::HandleType>
             + GetFreeCaptureBuffer<'a, Self::HandleType>,
diff --git a/lib/Android.bp b/lib/Android.bp
index 8bc9b59..2173cca 100644
--- a/lib/Android.bp
+++ b/lib/Android.bp
@@ -10,7 +10,7 @@ rust_library {
     host_supported: true,
     crate_name: "v4l2r",
     cargo_env_compat: true,
-    cargo_pkg_version: "0.0.4",
+    cargo_pkg_version: "0.0.5",
     crate_root: "src/lib.rs",
     edition: "2021",
     rustlibs: [
@@ -37,7 +37,7 @@ rust_test {
     host_supported: true,
     crate_name: "v4l2r",
     cargo_env_compat: true,
-    cargo_pkg_version: "0.0.4",
+    cargo_pkg_version: "0.0.5",
     crate_root: "src/lib.rs",
     test_suites: ["general-tests"],
     auto_gen_config: true,
diff --git a/lib/Cargo.toml b/lib/Cargo.toml
index f48bb59..ae5c411 100644
--- a/lib/Cargo.toml
+++ b/lib/Cargo.toml
@@ -1,6 +1,6 @@
 [package]
 name = "v4l2r"
-version = "0.0.4"
+version = "0.0.5"
 authors = ["Alexandre Courbot <gnurou@gmail.com>"]
 edition = "2021"
 description = "Safe and flexible abstraction over V4L2"
@@ -11,6 +11,12 @@ license = "MIT"
 
 readme.workspace = true
 
+[features]
+# Generate the bindings for 64-bit even if the host is 32-bit.
+arch64 = []
+# Generate the bindings for 32-bit even if the host is 64-bit.
+arch32 = []
+
 [dependencies]
 nix = { version = "0.28", features = ["ioctl", "mman", "poll", "fs", "event"] }
 bitflags = "2.4"
diff --git a/lib/build.rs b/lib/build.rs
index 608ec6d..a3b7f69 100644
--- a/lib/build.rs
+++ b/lib/build.rs
@@ -30,9 +30,17 @@ fn main() {
     println!("cargo::rerun-if-changed={}", videodev2_h.display());
     println!("cargo::rerun-if-changed={}", WRAPPER_H);
 
+    let clang_args = [
+        format!("-I{}", videodev2_h_path),
+        #[cfg(all(feature = "arch64", not(feature = "arch32")))]
+        "--target=x86_64-linux-gnu".into(),
+        #[cfg(all(feature = "arch32", not(feature = "arch64")))]
+        "--target=i686-linux-gnu".into(),
+    ];
+
     let bindings = v4l2r_bindgen_builder(bindgen::Builder::default())
         .header(WRAPPER_H)
-        .clang_args([format!("-I{}", videodev2_h_path)])
+        .clang_args(clang_args)
         .generate()
         .expect("unable to generate bindings");
 
diff --git a/lib/examples/fwht_encoder/main.rs b/lib/examples/fwht_encoder/main.rs
index e5e786e..82b5516 100644
--- a/lib/examples/fwht_encoder/main.rs
+++ b/lib/examples/fwht_encoder/main.rs
@@ -13,7 +13,7 @@ use v4l2r::{
             dqbuf::DqBuffer,
             generic::{GenericBufferHandles, GenericQBuffer, GenericSupportedMemoryType},
             handles_provider::MmapProvider,
-            qbuf::OutputQueueable,
+            OutputQueueable,
         },
     },
     encoder::*,
diff --git a/lib/examples/vicodec_test/device_api.rs b/lib/examples/vicodec_test/device_api.rs
index aa1af2e..a9c9fff 100644
--- a/lib/examples/vicodec_test/device_api.rs
+++ b/lib/examples/vicodec_test/device_api.rs
@@ -5,8 +5,7 @@ use std::sync::Arc;
 use std::time::Instant;
 use v4l2r_utils::framegen::FrameGenerator;
 
-use qbuf::{get_free::GetFreeCaptureBuffer, get_indexed::GetOutputBufferByIndex};
-use v4l2r::{device::queue::qbuf::OutputQueueable, memory::MemoryType, Format};
+use v4l2r::{device::queue::OutputQueueable, memory::MemoryType, Format};
 use v4l2r::{device::queue::*, memory::MmapHandle};
 use v4l2r::{
     device::{
diff --git a/lib/src/decoder/stateful.rs b/lib/src/decoder/stateful.rs
index 392180a..a6b18ca 100644
--- a/lib/src/decoder/stateful.rs
+++ b/lib/src/decoder/stateful.rs
@@ -7,13 +7,9 @@ use crate::{
         queue::{
             direction::{Capture, Output},
             handles_provider::HandlesProvider,
-            qbuf::{
-                get_free::{GetFreeBufferError, GetFreeCaptureBuffer, GetFreeOutputBuffer},
-                get_indexed::GetCaptureBufferByIndex,
-                OutputQueueableProvider,
-            },
-            BuffersAllocated, CreateQueueError, FormatBuilder, Queue, QueueInit,
-            RequestBuffersError,
+            BuffersAllocated, CreateQueueError, FormatBuilder, GetCaptureBufferByIndex,
+            GetFreeBufferError, GetFreeCaptureBuffer, GetFreeOutputBuffer, OutputQueueableProvider,
+            Queue, QueueInit, RequestBuffersError,
         },
         AllocatedQueue, Device, DeviceConfig, DeviceOpenError, Stream, TryDequeue,
     },
diff --git a/lib/src/decoder/stateful/capture_thread.rs b/lib/src/decoder/stateful/capture_thread.rs
index 8dc849e..67e3268 100644
--- a/lib/src/decoder/stateful/capture_thread.rs
+++ b/lib/src/decoder/stateful/capture_thread.rs
@@ -6,14 +6,8 @@ use crate::{
     device::{
         poller::{DeviceEvent, PollEvent, Poller, Waker},
         queue::{
-            self,
-            direction::Capture,
-            handles_provider::HandlesProvider,
-            qbuf::{
-                get_free::GetFreeCaptureBuffer, get_indexed::GetCaptureBufferByIndex,
-                CaptureQueueable,
-            },
-            BuffersAllocated, Queue, QueueInit,
+            self, direction::Capture, handles_provider::HandlesProvider, BuffersAllocated,
+            CaptureQueueable, GetCaptureBufferByIndex, GetFreeCaptureBuffer, Queue, QueueInit,
         },
         AllocatedQueue, Device, Stream, TryDequeue,
     },
@@ -255,7 +249,7 @@ where
                 // an infinite number of handles. Break out of the loop when this happens - we will
                 // be called again the next time a CAPTURE buffer becomes available.
                 Err(queue::handles_provider::GetSuitableBufferError::TryGetFree(
-                    queue::qbuf::get_free::GetFreeBufferError::NoFreeBuffer,
+                    queue::GetFreeBufferError::NoFreeBuffer,
                 )) => {
                     break 'enqueue;
                 }
diff --git a/lib/src/device/queue.rs b/lib/src/device/queue.rs
index e2a5e42..2cc15ec 100644
--- a/lib/src/device/queue.rs
+++ b/lib/src/device/queue.rs
@@ -5,8 +5,6 @@ pub mod generic;
 pub mod handles_provider;
 pub mod qbuf;
 
-use self::qbuf::{get_free::GetFreeOutputBuffer, get_indexed::GetOutputBufferByIndex};
-
 use super::{AllocatedQueue, Device, FreeBuffersResult, Stream, TryDequeue};
 use crate::ioctl::{DqBufResult, QueryBufError, V4l2BufferFromError};
 use crate::{bindings, memory::*};
@@ -21,13 +19,8 @@ use crate::{Format, PixelFormat, QueueType};
 use buffer::*;
 use direction::*;
 use dqbuf::*;
-use generic::{GenericBufferHandles, GenericQBuffer, GenericSupportedMemoryType};
 use log::debug;
-use qbuf::{
-    get_free::{GetFreeBufferError, GetFreeCaptureBuffer},
-    get_indexed::{GetCaptureBufferByIndex, TryGetBufferError},
-    *,
-};
+use qbuf::*;
 
 use std::convert::{Infallible, TryFrom};
 use std::os::unix::io::{AsRawFd, RawFd};
@@ -37,7 +30,7 @@ use thiserror::Error;
 /// Base values of a queue, that are always value no matter the state the queue
 /// is in. This base object remains alive as long as the queue is borrowed from
 /// the `Device`.
-pub struct QueueBase {
+struct QueueBase {
     // Reference to the device, so we can perform operations on its `fd` and to let us mark the
     // queue as free again upon destruction.
     device: Arc<Device>,
@@ -116,8 +109,8 @@ where
     }
 
     /// Returns an iterator over all the formats currently supported by this queue.
-    pub fn format_iter(&self) -> ioctl::FormatIterator<QueueBase> {
-        ioctl::FormatIterator::new(&self.inner, self.inner.type_)
+    pub fn format_iter(&self) -> ioctl::FormatIterator<Device> {
+        ioctl::FormatIterator::new(self.inner.device.as_ref(), self.inner.type_)
     }
 
     pub fn get_selection(&self, target: SelectionTarget) -> Result<Rect, ioctl::GSelectionError> {
@@ -516,51 +509,89 @@ impl<D: Direction, P: BufferHandles> TryDequeue for Queue<D, BuffersAllocated<P>
     }
 }
 
+#[derive(Debug, Error)]
+pub enum TryGetBufferError {
+    #[error("buffer with provided index {0} does not exist")]
+    InvalidIndex(usize),
+    #[error("buffer is already in use")]
+    AlreadyUsed,
+}
+
+#[derive(Debug, Error)]
+pub enum GetFreeBufferError {
+    #[error("all buffers are currently being used")]
+    NoFreeBuffer,
+}
+
 mod private {
+    use std::ops::Deref;
+
     use super::*;
 
-    /// Private trait for providing a Queuable regardless of the queue's
-    /// direction. Avoids duplicating the same code in
-    /// Capture/OutputQueueableProvider's implementations.
-    pub trait GetBufferByIndex<'a> {
-        type Queueable: 'a;
+    /// The lifetime `'a` is here to allow implementations to attach the lifetime of their return
+    /// value to `self`. This is useful when we want the buffer to hold a reference to the queue
+    /// that prevents the latter from mutating as long as the buffer is not consumed.
+    pub trait QueueableProvider<'a> {
+        type Queueable;
+    }
 
+    /// Private trait for providing a Queuable regardless of the queue's direction.
+    ///
+    /// This avoids duplicating the same code in Capture/OutputQueueableProvider's implementations.
+    pub trait GetBufferByIndex<'a>: QueueableProvider<'a> {
         fn try_get_buffer(&'a self, index: usize) -> Result<Self::Queueable, TryGetBufferError>;
     }
 
     /// Same as `GetBufferByIndex` but for providing any free buffer.
-    pub trait GetFreeBuffer<'a, ErrorType = GetFreeBufferError>: GetBufferByIndex<'a> {
-        fn try_get_free_buffer(&'a self) -> Result<Self::Queueable, ErrorType>;
+    pub trait GetFreeBuffer<'a>: QueueableProvider<'a> {
+        fn try_get_free_buffer(&'a self) -> Result<Self::Queueable, GetFreeBufferError>;
     }
 
-    impl<'a, D: Direction, P: PrimitiveBufferHandles> GetBufferByIndex<'a>
+    impl<'a, D: Direction, P: PrimitiveBufferHandles> QueueableProvider<'a>
         for Queue<D, BuffersAllocated<P>>
     {
-        type Queueable = QBuffer<'a, D, P, P>;
+        type Queueable = QBuffer<D, P, P, &'a Queue<D, BuffersAllocated<P>>>;
+    }
 
+    impl<'a, D: Direction, P: PrimitiveBufferHandles> GetBufferByIndex<'a>
+        for Queue<D, BuffersAllocated<P>>
+    {
         // Take buffer `id` in order to prepare it for queueing, provided it is available.
         fn try_get_buffer(&'a self, index: usize) -> Result<Self::Queueable, TryGetBufferError> {
             Ok(QBuffer::new(self, self.try_obtain_buffer(index)?))
         }
     }
 
-    impl<'a, D: Direction> GetBufferByIndex<'a> for Queue<D, BuffersAllocated<GenericBufferHandles>> {
-        type Queueable = GenericQBuffer<'a, D>;
+    impl<'a, D, P, Q> QueueableProvider<'a> for Q
+    where
+        D: Direction,
+        P: PrimitiveBufferHandles,
+        Q: Deref<Target = Queue<D, BuffersAllocated<P>>> + Clone,
+    {
+        type Queueable = QBuffer<D, P, P, Q>;
+    }
 
+    /// Allows to obtain a [`QBuffer`] with a `'static` lifetime from e.g. an `Arc<Queue>`.
+    ///
+    /// [`QBuffer`]s obtained directly from a [`Queue`] maintain consistency by holding a reference
+    /// to the [`Queue`], which can be inconvenient if we need to keep the [`QBuffer`] aside for
+    /// some time. This implementation allows [`QBuffer`]s to be created with a static lifetime
+    /// from a queue behind a cloneable and dereferencable type (typically [`std::rc::Rc`] or
+    /// [`std::sync::Arc`]).
+    ///
+    /// This added flexibility comes with the counterpart that the user must unwrap the [`Queue`]
+    /// from its container reference before applying mutable operations to it like
+    /// [`Queue::request_buffers`]. Doing so requires calling methods like
+    /// [`std::sync::Arc::into_inner`], which only succeed if there is no other reference to the
+    /// queue, preserving consistency explicitly at runtime instead of implicitly at compile-time.
+    impl<'a, D, P, Q> GetBufferByIndex<'a> for Q
+    where
+        D: Direction,
+        P: PrimitiveBufferHandles,
+        Q: Deref<Target = Queue<D, BuffersAllocated<P>>> + Clone,
+    {
         fn try_get_buffer(&'a self, index: usize) -> Result<Self::Queueable, TryGetBufferError> {
-            let buffer_info = self.try_obtain_buffer(index)?;
-
-            Ok(match self.state.memory_type {
-                GenericSupportedMemoryType::Mmap => {
-                    GenericQBuffer::Mmap(QBuffer::new(self, buffer_info))
-                }
-                GenericSupportedMemoryType::UserPtr => {
-                    GenericQBuffer::User(QBuffer::new(self, buffer_info))
-                }
-                GenericSupportedMemoryType::DmaBuf => {
-                    GenericQBuffer::DmaBuf(QBuffer::new(self, buffer_info))
-                }
-            })
+            Ok(QBuffer::new(self.clone(), self.try_obtain_buffer(index)?))
         }
     }
 
@@ -571,43 +602,111 @@ mod private {
         Self: GetBufferByIndex<'a>,
     {
         fn try_get_free_buffer(&'a self) -> Result<Self::Queueable, GetFreeBufferError> {
-            let res = self
-                .state
+            self.state
                 .buffer_info
                 .iter()
                 .enumerate()
-                .find(|(_, s)| s.do_with_state(|s| matches!(s, BufferState::Free)));
+                .find(|(_, s)| s.do_with_state(|s| matches!(s, BufferState::Free)))
+                .ok_or(GetFreeBufferError::NoFreeBuffer)
+                // We found a buffer with a `Free` state, so calling `try_get_buffer` on it is
+                // guaranteed to succeed.
+                .map(|(i, _)| self.try_get_buffer(i).unwrap())
+        }
+    }
 
-            match res {
-                None => Err(GetFreeBufferError::NoFreeBuffer),
-                Some((i, _)) => Ok(self.try_get_buffer(i).unwrap()),
-            }
+    /// Allows to obtain a [`QBuffer`] with a `'static` lifetime from e.g. an `Arc<Queue>`.
+    ///
+    /// [`QBuffer`]s obtained directly from a [`Queue`] maintain consistency by holding a reference
+    /// to the [`Queue`], which can be inconvenient if we need to keep the [`QBuffer`] aside for
+    /// some time. This implementation allows [`QBuffer`]s to be created with a static lifetime
+    /// from a queue behind a cloneable and dereferencable type (typically [`std::rc::Rc`] or
+    /// [`std::sync::Arc`]).
+    ///
+    /// This added flexibility comes with the counterpart that the user must unwrap the [`Queue`]
+    /// from its container reference before applying mutable operations to it like
+    /// [`Queue::request_buffers`]. Doing so requires calling methods like
+    /// [`std::sync::Arc::into_inner`], which only succeed if there is no other reference to the
+    /// queue, preserving consistency explicitly at runtime instead of implicitly at compile-time.
+    impl<'a, D, P, Q> GetFreeBuffer<'a> for Q
+    where
+        D: Direction,
+        P: PrimitiveBufferHandles,
+        Q: Deref<Target = Queue<D, BuffersAllocated<P>>> + Clone,
+    {
+        fn try_get_free_buffer(&'a self) -> Result<Self::Queueable, GetFreeBufferError> {
+            self.state
+                .buffer_info
+                .iter()
+                .enumerate()
+                .find(|(_, s)| s.do_with_state(|s| matches!(s, BufferState::Free)))
+                .ok_or(GetFreeBufferError::NoFreeBuffer)
+                // We found a buffer with a `Free` state, so calling `try_get_buffer` on it is
+                // guaranteed to succeed.
+                .map(|(i, _)| self.try_get_buffer(i).unwrap())
         }
     }
 }
 
-impl<'a, P: PrimitiveBufferHandles> CaptureQueueableProvider<'a, P>
-    for Queue<Capture, BuffersAllocated<P>>
+/// Trait for queueable CAPTURE buffers. These buffers only require handles to
+/// be queued.
+pub trait CaptureQueueable<B: BufferHandles> {
+    /// Queue the buffer after binding `handles`, consuming the object.
+    /// The number of handles must match the buffer's expected number of planes.
+    fn queue_with_handles(self, handles: B) -> QueueResult<(), B>;
+}
+
+/// Trait for queueable OUTPUT buffers. The number of bytes used must be
+/// specified for each plane.
+pub trait OutputQueueable<B: BufferHandles> {
+    /// Queue the buffer after binding `handles`, consuming the object.
+    /// The number of handles must match the buffer's expected number of planes.
+    /// `bytes_used` must be a slice with as many slices as there are handles,
+    /// describing the amount of useful data in each of them.
+    fn queue_with_handles(self, handles: B, bytes_used: &[usize]) -> QueueResult<(), B>;
+}
+
+/// Trait for all objects that are capable of providing objects that can be
+/// queued to the CAPTURE queue.
+pub trait CaptureQueueableProvider<'a, B: BufferHandles> {
+    type Queueable: CaptureQueueable<B>;
+}
+
+impl<'a, B, Q> CaptureQueueableProvider<'a, B> for Q
 where
-    Self: private::GetBufferByIndex<'a>,
-    <Self as private::GetBufferByIndex<'a>>::Queueable: CaptureQueueable<P>,
+    B: BufferHandles,
+    Q: private::QueueableProvider<'a>,
+    Q::Queueable: CaptureQueueable<B>,
 {
-    type Queueable = <Self as private::GetBufferByIndex<'a>>::Queueable;
+    type Queueable = <Self as private::QueueableProvider<'a>>::Queueable;
 }
 
-impl<'a, P: PrimitiveBufferHandles> OutputQueueableProvider<'a, P>
-    for Queue<Output, BuffersAllocated<P>>
+/// Trait for all objects that are capable of providing objects that can be
+/// queued to the CAPTURE queue.
+pub trait OutputQueueableProvider<'a, B: BufferHandles> {
+    type Queueable: OutputQueueable<B>;
+}
+
+impl<'a, B, Q> OutputQueueableProvider<'a, B> for Q
 where
-    Self: private::GetBufferByIndex<'a>,
-    <Self as private::GetBufferByIndex<'a>>::Queueable: OutputQueueable<P>,
+    B: BufferHandles,
+    Q: private::QueueableProvider<'a>,
+    Q::Queueable: OutputQueueable<B>,
 {
-    type Queueable = <Self as private::GetBufferByIndex<'a>>::Queueable;
+    type Queueable = <Self as private::QueueableProvider<'a>>::Queueable;
 }
 
-impl<'a, P: BufferHandles, R> GetOutputBufferByIndex<'a, P> for Queue<Output, BuffersAllocated<P>>
+pub trait GetOutputBufferByIndex<'a, B, ErrorType = TryGetBufferError>
 where
-    Self: private::GetBufferByIndex<'a, Queueable = R>,
-    Self: OutputQueueableProvider<'a, P, Queueable = R>,
+    B: BufferHandles,
+    Self: OutputQueueableProvider<'a, B>,
+{
+    fn try_get_buffer(&'a self, index: usize) -> Result<Self::Queueable, ErrorType>;
+}
+
+impl<'a, B: BufferHandles> GetOutputBufferByIndex<'a, B> for Queue<Output, BuffersAllocated<B>>
+where
+    Self: private::GetBufferByIndex<'a>,
+    <Self as private::QueueableProvider<'a>>::Queueable: OutputQueueable<B>,
 {
     // Take buffer `id` in order to prepare it for queueing, provided it is available.
     fn try_get_buffer(&'a self, index: usize) -> Result<Self::Queueable, TryGetBufferError> {
@@ -615,10 +714,17 @@ where
     }
 }
 
-impl<'a, P: BufferHandles, R> GetCaptureBufferByIndex<'a, P> for Queue<Capture, BuffersAllocated<P>>
+pub trait GetCaptureBufferByIndex<'a, P: BufferHandles, ErrorType = TryGetBufferError>
 where
-    Self: private::GetBufferByIndex<'a, Queueable = R>,
-    Self: CaptureQueueableProvider<'a, P, Queueable = R>,
+    Self: CaptureQueueableProvider<'a, P>,
+{
+    fn try_get_buffer(&'a self, index: usize) -> Result<Self::Queueable, ErrorType>;
+}
+
+impl<'a, P: BufferHandles> GetCaptureBufferByIndex<'a, P> for Queue<Capture, BuffersAllocated<P>>
+where
+    Self: private::GetBufferByIndex<'a>,
+    <Self as private::QueueableProvider<'a>>::Queueable: CaptureQueueable<P>,
 {
     // Take buffer `id` in order to prepare it for queueing, provided it is available.
     fn try_get_buffer(&'a self, index: usize) -> Result<Self::Queueable, TryGetBufferError> {
@@ -626,20 +732,34 @@ where
     }
 }
 
-impl<'a, P: BufferHandles, R> GetFreeOutputBuffer<'a, P> for Queue<Output, BuffersAllocated<P>>
+pub trait GetFreeOutputBuffer<'a, P: BufferHandles, ErrorType = GetFreeBufferError>
 where
-    Self: private::GetFreeBuffer<'a, Queueable = R>,
-    Self: OutputQueueableProvider<'a, P, Queueable = R>,
+    Self: OutputQueueableProvider<'a, P>,
+{
+    fn try_get_free_buffer(&'a self) -> Result<Self::Queueable, ErrorType>;
+}
+
+impl<'a, P: BufferHandles, Q> GetFreeOutputBuffer<'a, P> for Q
+where
+    Self: private::GetFreeBuffer<'a>,
+    <Self as private::QueueableProvider<'a>>::Queueable: OutputQueueable<P>,
 {
     fn try_get_free_buffer(&'a self) -> Result<Self::Queueable, GetFreeBufferError> {
         <Self as private::GetFreeBuffer<'a>>::try_get_free_buffer(self)
     }
 }
 
-impl<'a, P: BufferHandles, R> GetFreeCaptureBuffer<'a, P> for Queue<Capture, BuffersAllocated<P>>
+pub trait GetFreeCaptureBuffer<'a, P: BufferHandles, ErrorType = GetFreeBufferError>
+where
+    Self: CaptureQueueableProvider<'a, P>,
+{
+    fn try_get_free_buffer(&'a self) -> Result<Self::Queueable, ErrorType>;
+}
+
+impl<'a, P: BufferHandles, Q> GetFreeCaptureBuffer<'a, P> for Q
 where
-    Self: private::GetFreeBuffer<'a, Queueable = R>,
-    Self: CaptureQueueableProvider<'a, P, Queueable = R>,
+    Self: private::GetFreeBuffer<'a>,
+    <Self as private::QueueableProvider<'a>>::Queueable: CaptureQueueable<P>,
 {
     fn try_get_free_buffer(&'a self) -> Result<Self::Queueable, GetFreeBufferError> {
         <Self as private::GetFreeBuffer<'a>>::try_get_free_buffer(self)
diff --git a/lib/src/device/queue/generic.rs b/lib/src/device/queue/generic.rs
index cf857c3..a590fc9 100644
--- a/lib/src/device/queue/generic.rs
+++ b/lib/src/device/queue/generic.rs
@@ -1,11 +1,9 @@
 use crate::{
     device::queue::{
         direction::{Capture, Direction, Output},
-        qbuf::{
-            CaptureQueueable, CaptureQueueableProvider, OutputQueueable, OutputQueueableProvider,
-            QBuffer, QueueResult,
-        },
-        BuffersAllocated, Queue,
+        private,
+        qbuf::{QBuffer, QueueResult},
+        BuffersAllocated, CaptureQueueable, OutputQueueable, Queue, TryGetBufferError,
     },
     memory::DmaBufHandle,
 };
@@ -13,7 +11,7 @@ use crate::{
     memory::MmapHandle,
     memory::{BufferHandles, MemoryType, UserPtrHandle},
 };
-use std::{fmt::Debug, fs::File};
+use std::{fmt::Debug, fs::File, ops::Deref};
 
 /// Supported memory types for `GenericBufferHandles`.
 /// TODO: This should be renamed to "DynamicBufferHandles", and be constructed
@@ -84,38 +82,78 @@ impl BufferHandles for GenericBufferHandles {
 
 /// A QBuffer that holds either MMAP or UserPtr handles, depending on which
 /// memory type has been selected for the queue at runtime.
-pub enum GenericQBuffer<'a, D: Direction> {
-    Mmap(QBuffer<'a, D, Vec<MmapHandle>, GenericBufferHandles>),
-    User(QBuffer<'a, D, Vec<UserPtrHandle<Vec<u8>>>, GenericBufferHandles>),
-    DmaBuf(QBuffer<'a, D, Vec<DmaBufHandle<File>>, GenericBufferHandles>),
+pub enum GenericQBuffer<
+    D: Direction,
+    Q: Deref<Target = Queue<D, BuffersAllocated<GenericBufferHandles>>>,
+> {
+    Mmap(QBuffer<D, Vec<MmapHandle>, GenericBufferHandles, Q>),
+    User(QBuffer<D, Vec<UserPtrHandle<Vec<u8>>>, GenericBufferHandles, Q>),
+    DmaBuf(QBuffer<D, Vec<DmaBufHandle<File>>, GenericBufferHandles, Q>),
 }
 
-impl<'a, D: Direction> From<QBuffer<'a, D, Vec<MmapHandle>, GenericBufferHandles>>
-    for GenericQBuffer<'a, D>
+impl<D, Q> From<QBuffer<D, Vec<MmapHandle>, GenericBufferHandles, Q>> for GenericQBuffer<D, Q>
+where
+    D: Direction,
+    Q: Deref<Target = Queue<D, BuffersAllocated<GenericBufferHandles>>>,
 {
-    fn from(qb: QBuffer<'a, D, Vec<MmapHandle>, GenericBufferHandles>) -> Self {
+    fn from(qb: QBuffer<D, Vec<MmapHandle>, GenericBufferHandles, Q>) -> Self {
         GenericQBuffer::Mmap(qb)
     }
 }
 
-impl<'a, D: Direction> From<QBuffer<'a, D, Vec<UserPtrHandle<Vec<u8>>>, GenericBufferHandles>>
-    for GenericQBuffer<'a, D>
+impl<D, Q> From<QBuffer<D, Vec<UserPtrHandle<Vec<u8>>>, GenericBufferHandles, Q>>
+    for GenericQBuffer<D, Q>
+where
+    D: Direction,
+    Q: Deref<Target = Queue<D, BuffersAllocated<GenericBufferHandles>>>,
 {
-    fn from(qb: QBuffer<'a, D, Vec<UserPtrHandle<Vec<u8>>>, GenericBufferHandles>) -> Self {
+    fn from(qb: QBuffer<D, Vec<UserPtrHandle<Vec<u8>>>, GenericBufferHandles, Q>) -> Self {
         GenericQBuffer::User(qb)
     }
 }
 
-impl<'a, D: Direction> From<QBuffer<'a, D, Vec<DmaBufHandle<File>>, GenericBufferHandles>>
-    for GenericQBuffer<'a, D>
+impl<D, Q> From<QBuffer<D, Vec<DmaBufHandle<File>>, GenericBufferHandles, Q>>
+    for GenericQBuffer<D, Q>
+where
+    D: Direction,
+    Q: Deref<Target = Queue<D, BuffersAllocated<GenericBufferHandles>>>,
 {
-    fn from(qb: QBuffer<'a, D, Vec<DmaBufHandle<File>>, GenericBufferHandles>) -> Self {
+    fn from(qb: QBuffer<D, Vec<DmaBufHandle<File>>, GenericBufferHandles, Q>) -> Self {
         GenericQBuffer::DmaBuf(qb)
     }
 }
 
+impl<'a, D: Direction> private::QueueableProvider<'a>
+    for Queue<D, BuffersAllocated<GenericBufferHandles>>
+{
+    type Queueable = GenericQBuffer<D, &'a Self>;
+}
+
+impl<'a, D: Direction> private::GetBufferByIndex<'a>
+    for Queue<D, BuffersAllocated<GenericBufferHandles>>
+{
+    fn try_get_buffer(&'a self, index: usize) -> Result<Self::Queueable, TryGetBufferError> {
+        let buffer_info = self.try_obtain_buffer(index)?;
+
+        Ok(match self.state.memory_type {
+            GenericSupportedMemoryType::Mmap => {
+                GenericQBuffer::Mmap(QBuffer::new(self, buffer_info))
+            }
+            GenericSupportedMemoryType::UserPtr => {
+                GenericQBuffer::User(QBuffer::new(self, buffer_info))
+            }
+            GenericSupportedMemoryType::DmaBuf => {
+                GenericQBuffer::DmaBuf(QBuffer::new(self, buffer_info))
+            }
+        })
+    }
+}
+
 /// Any CAPTURE GenericQBuffer implements CaptureQueueable.
-impl CaptureQueueable<GenericBufferHandles> for GenericQBuffer<'_, Capture> {
+impl<Q> CaptureQueueable<GenericBufferHandles> for GenericQBuffer<Capture, Q>
+where
+    Q: Deref<Target = Queue<Capture, BuffersAllocated<GenericBufferHandles>>>,
+{
     fn queue_with_handles(
         self,
         handles: GenericBufferHandles,
@@ -129,7 +167,10 @@ impl CaptureQueueable<GenericBufferHandles> for GenericQBuffer<'_, Capture> {
 }
 
 /// Any OUTPUT GenericQBuffer implements OutputQueueable.
-impl OutputQueueable<GenericBufferHandles> for GenericQBuffer<'_, Output> {
+impl<Q> OutputQueueable<GenericBufferHandles> for GenericQBuffer<Output, Q>
+where
+    Q: Deref<Target = Queue<Output, BuffersAllocated<GenericBufferHandles>>>,
+{
     fn queue_with_handles(
         self,
         handles: GenericBufferHandles,
@@ -142,15 +183,3 @@ impl OutputQueueable<GenericBufferHandles> for GenericQBuffer<'_, Output> {
         }
     }
 }
-
-impl<'a> CaptureQueueableProvider<'a, GenericBufferHandles>
-    for Queue<Capture, BuffersAllocated<GenericBufferHandles>>
-{
-    type Queueable = GenericQBuffer<'a, Capture>;
-}
-
-impl<'a> OutputQueueableProvider<'a, GenericBufferHandles>
-    for Queue<Output, BuffersAllocated<GenericBufferHandles>>
-{
-    type Queueable = GenericQBuffer<'a, Output>;
-}
diff --git a/lib/src/device/queue/handles_provider.rs b/lib/src/device/queue/handles_provider.rs
index f796884..148864d 100644
--- a/lib/src/device/queue/handles_provider.rs
+++ b/lib/src/device/queue/handles_provider.rs
@@ -7,6 +7,9 @@ use std::{
 
 use log::error;
 
+use crate::device::queue::{
+    GetCaptureBufferByIndex, GetFreeBufferError, GetFreeCaptureBuffer, TryGetBufferError,
+};
 use crate::{
     bindings,
     device::poller::Waker,
@@ -16,12 +19,6 @@ use crate::{
 
 use thiserror::Error;
 
-use super::qbuf::{
-    get_free::{GetFreeBufferError, GetFreeCaptureBuffer},
-    get_indexed::{GetCaptureBufferByIndex, TryGetBufferError},
-    CaptureQueueableProvider,
-};
-
 #[derive(Debug, Error)]
 pub enum GetSuitableBufferError {
     #[error("error while calling try_get_free_buffer(): {0}")]
@@ -42,10 +39,7 @@ pub trait HandlesProvider: Send + 'static {
         &self,
         _handles: &Self::HandleType,
         queue: &'a Q,
-    ) -> Result<
-        <Q as CaptureQueueableProvider<'a, Self::HandleType>>::Queueable,
-        GetSuitableBufferError,
-    >
+    ) -> Result<Q::Queueable, GetSuitableBufferError>
     where
         Q: GetCaptureBufferByIndex<'a, Self::HandleType>
             + GetFreeCaptureBuffer<'a, Self::HandleType>,
@@ -66,10 +60,7 @@ impl<P: HandlesProvider> HandlesProvider for Box<P> {
         &self,
         handles: &Self::HandleType,
         queue: &'a Q,
-    ) -> Result<
-        <Q as CaptureQueueableProvider<'a, Self::HandleType>>::Queueable,
-        GetSuitableBufferError,
-    >
+    ) -> Result<Q::Queueable, GetSuitableBufferError>
     where
         Q: GetCaptureBufferByIndex<'a, Self::HandleType>
             + GetFreeCaptureBuffer<'a, Self::HandleType>,
@@ -89,10 +80,7 @@ impl<P: HandlesProvider + Sync> HandlesProvider for Arc<P> {
         &self,
         handles: &Self::HandleType,
         queue: &'a Q,
-    ) -> Result<
-        <Q as CaptureQueueableProvider<'a, Self::HandleType>>::Queueable,
-        GetSuitableBufferError,
-    >
+    ) -> Result<Q::Queueable, GetSuitableBufferError>
     where
         Q: GetCaptureBufferByIndex<'a, Self::HandleType>
             + GetFreeCaptureBuffer<'a, Self::HandleType>,
diff --git a/lib/src/device/queue/qbuf.rs b/lib/src/device/queue/qbuf.rs
index cea7c37..58295ff 100644
--- a/lib/src/device/queue/qbuf.rs
+++ b/lib/src/device/queue/qbuf.rs
@@ -1,9 +1,12 @@
 //! Provides types related to queuing buffers on a `Queue` object.
-use super::{buffer::BufferInfo, Capture, Direction, Output};
-use super::{BufferState, BufferStateFuse, BuffersAllocated, Queue};
+use crate::device::queue::{
+    buffer::BufferInfo, BufferState, BufferStateFuse, BuffersAllocated, Capture, CaptureQueueable,
+    Direction, Output, OutputQueueable, Queue,
+};
 use crate::ioctl::{self, QBufIoctlError, QBufResult};
 use crate::memory::*;
 use std::convert::Infallible;
+use std::ops::Deref;
 use std::{
     fmt::{self, Debug},
     os::fd::RawFd,
@@ -13,26 +16,23 @@ use std::{
 use nix::sys::time::{TimeVal, TimeValLike};
 use thiserror::Error;
 
-pub mod get_free;
-pub mod get_indexed;
-
 /// Error that can occur when queuing a buffer. It wraps a regular error and also
 /// returns the plane handles back to the user.
 #[derive(Error)]
 #[error("{}", self.error)]
-pub struct QueueError<P: BufferHandles> {
+pub struct QueueError<B: BufferHandles> {
     pub error: ioctl::QBufError<Infallible>,
-    pub plane_handles: P,
+    pub plane_handles: B,
 }
 
-impl<P: BufferHandles> Debug for QueueError<P> {
+impl<B: BufferHandles> Debug for QueueError<B> {
     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
         Debug::fmt(&self.error, f)
     }
 }
 
 #[allow(type_alias_bounds)]
-pub type QueueResult<R, P: BufferHandles> = std::result::Result<R, QueueError<P>>;
+pub type QueueResult<R, B: BufferHandles> = std::result::Result<R, QueueError<B>>;
 
 /// A free buffer that has just been obtained from `Queue::get_buffer()` and
 /// which is being prepared to the queued.
@@ -62,21 +62,29 @@ pub type QueueResult<R, P: BufferHandles> = std::result::Result<R, QueueError<P>
 /// queue or device cannot be changed while it is being used. Contrary to
 /// DQBuffer which can be freely duplicated and passed around, instances of this
 /// struct are supposed to be short-lived.
-pub struct QBuffer<'a, D: Direction, P: PrimitiveBufferHandles, Q: BufferHandles + From<P>> {
-    queue: &'a Queue<D, BuffersAllocated<Q>>,
+pub struct QBuffer<
+    D: Direction,
+    P: PrimitiveBufferHandles,
+    B: BufferHandles + From<P>,
+    Q: Deref<Target = Queue<D, BuffersAllocated<B>>>,
+> {
+    queue: Q,
     index: usize,
     num_planes: usize,
     timestamp: TimeVal,
     request: Option<RawFd>,
-    fuse: BufferStateFuse<Q>,
+    fuse: BufferStateFuse<B>,
     _p: std::marker::PhantomData<P>,
 }
 
-impl<'a, D: Direction, P: PrimitiveBufferHandles, Q: BufferHandles + From<P>> QBuffer<'a, D, P, Q> {
-    pub(super) fn new(
-        queue: &'a Queue<D, BuffersAllocated<Q>>,
-        buffer_info: &Arc<BufferInfo<Q>>,
-    ) -> Self {
+impl<D, P, B, Q> QBuffer<D, P, B, Q>
+where
+    D: Direction,
+    P: PrimitiveBufferHandles,
+    B: BufferHandles + From<P>,
+    Q: Deref<Target = Queue<D, BuffersAllocated<B>>>,
+{
+    pub(super) fn new(queue: Q, buffer_info: &Arc<BufferInfo<B>>) -> Self {
         let buffer = &buffer_info.features;
         let fuse = BufferStateFuse::new(Arc::downgrade(buffer_info));
 
@@ -116,7 +124,7 @@ impl<'a, D: Direction, P: PrimitiveBufferHandles, Q: BufferHandles + From<P>> QB
     // Caller is responsible for making sure that the number of planes and
     // plane_handles is the same as the number of expected planes for this
     // buffer.
-    fn queue_bound_planes<R: BufferHandles + Into<Q>>(
+    fn queue_bound_planes<R: BufferHandles + Into<B>>(
         mut self,
         planes: Vec<ioctl::QBufPlane>,
         plane_handles: R,
@@ -155,11 +163,12 @@ impl<'a, D: Direction, P: PrimitiveBufferHandles, Q: BufferHandles + From<P>> QB
     }
 }
 
-impl<'a, P, Q> QBuffer<'a, Output, P, Q>
+impl<P, B, Q> QBuffer<Output, P, B, Q>
 where
     P: PrimitiveBufferHandles,
     P::HandleType: Mappable,
-    Q: BufferHandles + From<P>,
+    B: BufferHandles + From<P>,
+    Q: Deref<Target = Queue<Output, BuffersAllocated<B>>>,
 {
     pub fn get_plane_mapping(&self, plane: usize) -> Option<ioctl::PlaneMapping> {
         let buffer_info = self.queue.state.buffer_info.get(self.index)?;
@@ -168,41 +177,14 @@ where
     }
 }
 
-/// Trait for queueable CAPTURE buffers. These buffers only require handles to
-/// be queued.
-pub trait CaptureQueueable<Q: BufferHandles> {
-    /// Queue the buffer after binding `handles`, consuming the object.
-    /// The number of handles must match the buffer's expected number of planes.
-    fn queue_with_handles(self, handles: Q) -> QueueResult<(), Q>;
-}
-
-/// Trait for queueable OUTPUT buffers. The number of bytes used must be
-/// specified for each plane.
-pub trait OutputQueueable<Q: BufferHandles> {
-    /// Queue the buffer after binding `handles`, consuming the object.
-    /// The number of handles must match the buffer's expected number of planes.
-    /// `bytes_used` must be a slice with as many slices as there are handles,
-    /// describing the amount of useful data in each of them.
-    fn queue_with_handles(self, handles: Q, bytes_used: &[usize]) -> QueueResult<(), Q>;
-}
-
-/// Trait for all objects that are capable of providing objects that can be
-/// queued to the CAPTURE queue.
-pub trait CaptureQueueableProvider<'a, Q: BufferHandles> {
-    type Queueable: 'a + CaptureQueueable<Q>;
-}
-
-/// Trait for all objects that are capable of providing objects that can be
-/// queued to the CAPTURE queue.
-pub trait OutputQueueableProvider<'a, Q: BufferHandles> {
-    type Queueable: 'a + OutputQueueable<Q>;
-}
-
 /// Any CAPTURE QBuffer implements CaptureQueueable.
-impl<P: PrimitiveBufferHandles, Q: BufferHandles + From<P>> CaptureQueueable<Q>
-    for QBuffer<'_, Capture, P, Q>
+impl<P, B, Q> CaptureQueueable<B> for QBuffer<Capture, P, B, Q>
+where
+    P: PrimitiveBufferHandles,
+    B: BufferHandles + From<P>,
+    Q: Deref<Target = Queue<Capture, BuffersAllocated<B>>>,
 {
-    fn queue_with_handles(self, handles: Q) -> QueueResult<(), Q> {
+    fn queue_with_handles(self, handles: B) -> QueueResult<(), B> {
         if handles.len() != self.num_expected_planes() {
             return Err(QueueError {
                 error: QBufIoctlError::NumPlanesMismatch(handles.len(), self.num_expected_planes())
@@ -211,8 +193,8 @@ impl<P: PrimitiveBufferHandles, Q: BufferHandles + From<P>> CaptureQueueable<Q>
             });
         }
 
-        // TODO BufferHandles should have a method returning the actual MEMORY_TYPE implemented? So we can check
-        // that it matches with P.
+        // TODO: BufferHandles should have a method returning the actual MEMORY_TYPE implemented?
+        // So we can check that it matches with P.
 
         let planes: Vec<_> = (0..self.num_expected_planes())
             .map(|i| {
@@ -227,10 +209,13 @@ impl<P: PrimitiveBufferHandles, Q: BufferHandles + From<P>> CaptureQueueable<Q>
 }
 
 /// Any OUTPUT QBuffer implements OutputQueueable.
-impl<P: PrimitiveBufferHandles, Q: BufferHandles + From<P>> OutputQueueable<Q>
-    for QBuffer<'_, Output, P, Q>
+impl<P, B, Q> OutputQueueable<B> for QBuffer<Output, P, B, Q>
+where
+    P: PrimitiveBufferHandles,
+    B: BufferHandles + From<P>,
+    Q: Deref<Target = Queue<Output, BuffersAllocated<B>>>,
 {
-    fn queue_with_handles(self, handles: Q, bytes_used: &[usize]) -> QueueResult<(), Q> {
+    fn queue_with_handles(self, handles: B, bytes_used: &[usize]) -> QueueResult<(), B> {
         if handles.len() != self.num_expected_planes() {
             return Err(QueueError {
                 error: QBufIoctlError::NumPlanesMismatch(handles.len(), self.num_expected_planes())
@@ -251,8 +236,8 @@ impl<P: PrimitiveBufferHandles, Q: BufferHandles + From<P>> OutputQueueable<Q>
             });
         }
 
-        // TODO BufferHandles should have a method returning the actual MEMORY_TYPE implemented? So we can check
-        // that it matches with P.
+        // TODO: BufferHandles should have a method returning the actual MEMORY_TYPE implemented?
+        // So we can check that it matches with P.
 
         let planes: Vec<_> = bytes_used
             .iter()
@@ -272,9 +257,12 @@ impl<P: PrimitiveBufferHandles, Q: BufferHandles + From<P>> OutputQueueable<Q>
 /// empty handles.
 /// Since we don't receive plane handles, we also don't need to return any, so
 /// the returned error can be simplified.
-impl<P: PrimitiveBufferHandles + Default, Q: BufferHandles + From<P>> QBuffer<'_, Capture, P, Q>
+impl<P, B, Q> QBuffer<Capture, P, B, Q>
 where
+    P: PrimitiveBufferHandles + Default,
     <P::HandleType as PlaneHandle>::Memory: SelfBacked,
+    B: BufferHandles + From<P>,
+    Q: Deref<Target = Queue<Capture, BuffersAllocated<B>>>,
 {
     pub fn queue(self) -> QBufResult<(), Infallible> {
         let planes: Vec<_> = (0..self.num_expected_planes())
@@ -290,9 +278,12 @@ where
 /// empty handles.
 /// Since we don't receive plane handles, we also don't need to return any, so
 /// the returned error can be simplified.
-impl<P: PrimitiveBufferHandles + Default, Q: BufferHandles + From<P>> QBuffer<'_, Output, P, Q>
+impl<P, B, Q> QBuffer<Output, P, B, Q>
 where
     <P::HandleType as PlaneHandle>::Memory: SelfBacked,
+    P: PrimitiveBufferHandles + Default,
+    B: BufferHandles + From<P>,
+    Q: Deref<Target = Queue<Output, BuffersAllocated<B>>>,
 {
     pub fn queue(self, bytes_used: &[usize]) -> QBufResult<(), Infallible> {
         // TODO make specific error for bytes_used?
diff --git a/lib/src/device/queue/qbuf/get_free.rs b/lib/src/device/queue/qbuf/get_free.rs
deleted file mode 100644
index f037912..0000000
--- a/lib/src/device/queue/qbuf/get_free.rs
+++ /dev/null
@@ -1,31 +0,0 @@
-//! Traits for buffers providers with their own allocation policy. Users of this
-//! interface leave the choice of which buffer to return to the implementor,
-//! which must define its own allocation policy.
-//!
-//! The returned buffer shall not outlive the object that produced it.
-
-use thiserror::Error;
-
-use crate::memory::BufferHandles;
-
-use super::{CaptureQueueableProvider, OutputQueueableProvider};
-
-#[derive(Debug, Error)]
-pub enum GetFreeBufferError {
-    #[error("all buffers are currently being used")]
-    NoFreeBuffer,
-}
-
-pub trait GetFreeOutputBuffer<'a, P: BufferHandles, ErrorType = GetFreeBufferError>
-where
-    Self: OutputQueueableProvider<'a, P>,
-{
-    fn try_get_free_buffer(&'a self) -> Result<Self::Queueable, ErrorType>;
-}
-
-pub trait GetFreeCaptureBuffer<'a, P: BufferHandles, ErrorType = GetFreeBufferError>
-where
-    Self: CaptureQueueableProvider<'a, P>,
-{
-    fn try_get_free_buffer(&'a self) -> Result<Self::Queueable, ErrorType>;
-}
diff --git a/lib/src/device/queue/qbuf/get_indexed.rs b/lib/src/device/queue/qbuf/get_indexed.rs
deleted file mode 100644
index 073f511..0000000
--- a/lib/src/device/queue/qbuf/get_indexed.rs
+++ /dev/null
@@ -1,34 +0,0 @@
-//! Traits for trying to obtain a queueable, writable buffer from its index.
-//!
-//! `try_get_buffer()` returns the buffer with specified `index`, provided that
-//! this buffer is currently available for use.
-//!
-//! The returned buffer shall not outlive the object that produced it.
-
-use thiserror::Error;
-
-use crate::memory::BufferHandles;
-
-use super::{CaptureQueueableProvider, OutputQueueableProvider};
-
-#[derive(Debug, Error)]
-pub enum TryGetBufferError {
-    #[error("buffer with provided index {0} does not exist")]
-    InvalidIndex(usize),
-    #[error("buffer is already in use")]
-    AlreadyUsed,
-}
-
-pub trait GetOutputBufferByIndex<'a, P: BufferHandles, ErrorType = TryGetBufferError>
-where
-    Self: OutputQueueableProvider<'a, P>,
-{
-    fn try_get_buffer(&'a self, index: usize) -> Result<Self::Queueable, ErrorType>;
-}
-
-pub trait GetCaptureBufferByIndex<'a, P: BufferHandles, ErrorType = TryGetBufferError>
-where
-    Self: CaptureQueueableProvider<'a, P>,
-{
-    fn try_get_buffer(&'a self, index: usize) -> Result<Self::Queueable, ErrorType>;
-}
diff --git a/lib/src/encoder.rs b/lib/src/encoder.rs
index 86c6be3..0286f2f 100644
--- a/lib/src/encoder.rs
+++ b/lib/src/encoder.rs
@@ -7,13 +7,9 @@ use crate::{
             direction::{Capture, Output},
             dqbuf::DqBuffer,
             handles_provider::HandlesProvider,
-            qbuf::{
-                get_free::{GetFreeBufferError, GetFreeCaptureBuffer, GetFreeOutputBuffer},
-                get_indexed::GetCaptureBufferByIndex,
-                CaptureQueueable, OutputQueueableProvider,
-            },
-            BuffersAllocated, CanceledBuffer, CreateQueueError, FormatBuilder, Queue, QueueInit,
-            RequestBuffersError,
+            BuffersAllocated, CanceledBuffer, CaptureQueueable, CreateQueueError, FormatBuilder,
+            GetCaptureBufferByIndex, GetFreeBufferError, GetFreeCaptureBuffer, GetFreeOutputBuffer,
+            OutputQueueableProvider, Queue, QueueInit, RequestBuffersError,
         },
         AllocatedQueue, Device, DeviceConfig, DeviceOpenError, Stream, TryDequeue,
     },
@@ -185,11 +181,7 @@ impl<OP: BufferHandles> Encoder<AwaitingCaptureBuffers<OP>> {
         memory_type: <P::HandleType as BufferHandles>::SupportedMemoryType,
         num_capture: usize,
         capture_memory_provider: P,
-    ) -> Result<Encoder<ReadyToEncode<OP, P>>, RequestBuffersError>
-    where
-        for<'a> Queue<Capture, BuffersAllocated<P::HandleType>>:
-            GetFreeCaptureBuffer<'a, P::HandleType>,
-    {
+    ) -> Result<Encoder<ReadyToEncode<OP, P>>, RequestBuffersError> {
         Ok(Encoder {
             device: self.device,
             state: ReadyToEncode {
@@ -211,8 +203,6 @@ impl<OP: BufferHandles> Encoder<AwaitingCaptureBuffers<OP>> {
     ) -> Result<Encoder<ReadyToEncode<OP, P>>, RequestBuffersError>
     where
         P::HandleType: PrimitiveBufferHandles,
-        for<'a> Queue<Capture, BuffersAllocated<P::HandleType>>:
-            GetFreeCaptureBuffer<'a, P::HandleType>,
     {
         self.allocate_capture_buffers_generic(
             P::HandleType::MEMORY_TYPE,
diff --git a/lib/src/ioctl.rs b/lib/src/ioctl.rs
index 7ab697f..c76b925 100644
--- a/lib/src/ioctl.rs
+++ b/lib/src/ioctl.rs
@@ -916,6 +916,12 @@ pub enum V4l2BufferFromError {
     UnknownQueueType(u32),
     #[error("unknown memory type {0}")]
     UnknownMemoryType(u32),
+    #[error("invalid number of planes {0}")]
+    InvalidNumberOfPlanes(u32),
+    #[error("plane {0} has bytesused field larger than its length ({1} > {2})")]
+    PlaneSizeOverflow(usize, u32, u32),
+    #[error("plane {0} has data_offset field larger or equal to its bytesused ({1} >= {2})")]
+    InvalidDataOffset(usize, u32, u32),
 }
 
 impl TryFrom<UncheckedV4l2Buffer> for V4l2Buffer {
@@ -925,15 +931,53 @@ impl TryFrom<UncheckedV4l2Buffer> for V4l2Buffer {
     /// fail.
     fn try_from(buffer: UncheckedV4l2Buffer) -> Result<Self, Self::Error> {
         let v4l2_buf = buffer.0;
-        let v4l2_planes = buffer.1;
-        QueueType::n(v4l2_buf.type_)
+        let queue = QueueType::n(v4l2_buf.type_)
             .ok_or(V4l2BufferFromError::UnknownQueueType(v4l2_buf.type_))?;
         MemoryType::n(v4l2_buf.memory)
             .ok_or(V4l2BufferFromError::UnknownMemoryType(v4l2_buf.memory))?;
 
+        let v4l2_planes = buffer.1.unwrap_or_default();
+
+        // Validate plane information
+        if queue.is_multiplanar() {
+            if v4l2_buf.length >= bindings::VIDEO_MAX_PLANES {
+                return Err(V4l2BufferFromError::InvalidNumberOfPlanes(v4l2_buf.length));
+            }
+
+            for (i, plane) in v4l2_planes[0..v4l2_buf.length as usize].iter().enumerate() {
+                if plane.bytesused > plane.length {
+                    return Err(V4l2BufferFromError::PlaneSizeOverflow(
+                        i,
+                        plane.bytesused,
+                        plane.length,
+                    ));
+                }
+
+                let bytesused = if plane.bytesused != 0 {
+                    plane.bytesused
+                } else {
+                    plane.length
+                };
+
+                if plane.data_offset != 0 && plane.data_offset >= bytesused {
+                    return Err(V4l2BufferFromError::InvalidDataOffset(
+                        i,
+                        plane.data_offset,
+                        bytesused,
+                    ));
+                }
+            }
+        } else if v4l2_buf.bytesused > v4l2_buf.length {
+            return Err(V4l2BufferFromError::PlaneSizeOverflow(
+                0,
+                v4l2_buf.bytesused,
+                v4l2_buf.length,
+            ));
+        }
+
         Ok(Self {
             buffer: v4l2_buf,
-            planes: v4l2_planes.unwrap_or_default(),
+            planes: v4l2_planes,
         })
     }
 }
diff --git a/lib/src/memory.rs b/lib/src/memory.rs
index 0a4999c..de15657 100644
--- a/lib/src/memory.rs
+++ b/lib/src/memory.rs
@@ -41,8 +41,8 @@ use crate::{
     ioctl::{PlaneMapping, QueryBufPlane},
 };
 use enumn::N;
-use std::fmt::Debug;
 use std::os::unix::io::AsFd;
+use std::{fmt::Debug, ops::Deref};
 
 /// All the supported V4L2 memory types.
 #[derive(Debug, Clone, Copy, PartialEq, Eq, N)]
@@ -142,17 +142,22 @@ pub trait BufferHandles: Send + Debug + 'static {
     }
 }
 
-/// Implementation of `BufferHandles` for all vectors of `PlaneHandle`. This is
-/// The simplest way to use primitive handles.
-impl<P: PlaneHandle> BufferHandles for Vec<P> {
+/// Implementation of `BufferHandles` for all indexables of `PlaneHandle` (e.g. [`std::vec::Vec`]).
+///
+/// This is The simplest way to use primitive handles.
+impl<P, Q> BufferHandles for Q
+where
+    P: PlaneHandle,
+    Q: Send + Debug + 'static + Deref<Target = [P]>,
+{
     type SupportedMemoryType = MemoryType;
 
     fn len(&self) -> usize {
-        self.len()
+        self.deref().len()
     }
 
     fn fill_v4l2_plane(&self, index: usize, plane: &mut bindings::v4l2_plane) {
-        self[index].fill_v4l2_plane(plane);
+        self.deref()[index].fill_v4l2_plane(plane);
     }
 }
 
@@ -163,8 +168,13 @@ pub trait PrimitiveBufferHandles: BufferHandles {
     const MEMORY_TYPE: Self::SupportedMemoryType;
 }
 
-/// Implementation of `PrimitiveBufferHandles` for all vectors of `PlaneHandle`.
-impl<P: PlaneHandle> PrimitiveBufferHandles for Vec<P> {
+/// Implementation of `PrimitiveBufferHandles` for all indexables of `PlaneHandle` (e.g.
+/// [`std::vec::Vec`]).
+impl<P, Q> PrimitiveBufferHandles for Q
+where
+    P: PlaneHandle,
+    Q: Send + Debug + 'static + Deref<Target = [P]>,
+{
     type HandleType = P;
     const MEMORY_TYPE: Self::SupportedMemoryType = P::Memory::MEMORY_TYPE;
 }
```

