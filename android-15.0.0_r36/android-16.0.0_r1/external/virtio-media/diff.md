```diff
diff --git a/METADATA b/METADATA
index e6c837e..782bb25 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: RESTRICTED
   last_upgrade_date {
     year: 2024
-    month: 10
-    day: 22
+    month: 11
+    day: 26
   }
   identifier {
     type: "Git"
     value: "https://github.com/chromeos/virtio-media"
-    version: "v0.0.5"
+    version: "598283b5ebe4854dd33b22a0987db0947af8e537"
     primary_source: true
   }
 }
diff --git a/OWNERS b/OWNERS
index a982478..40312fa 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 include platform/system/core:main:/janitors/OWNERS
 adelva@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index 306f714..7934854 100644
--- a/README.md
+++ b/README.md
@@ -69,7 +69,7 @@ Implemented devices are:
 
 ## Virtio device ID
 
-Virtio-media uses device ID `49`.
+Virtio-media uses device ID `48`.
 
 ## Virtqueues
 
diff --git a/device/Cargo.lock b/device/Cargo.lock
index a478434..5125c4b 100644
--- a/device/Cargo.lock
+++ b/device/Cargo.lock
@@ -336,9 +336,9 @@ checksum = "3354b9ac3fae1ff6755cb6db53683adb661634f67557942dea4facebec0fee4b"
 
 [[package]]
 name = "v4l2r"
-version = "0.0.4"
+version = "0.0.5"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "4dbef75deba5f801229a648f72cffc2007befa7732fedfe05ca73ace030f597a"
+checksum = "fe1d612d2df2a0802020c49a1b029282c45991cdfff1731b5fc61ed3dce4168a"
 dependencies = [
  "anyhow",
  "bindgen",
@@ -351,7 +351,7 @@ dependencies = [
 
 [[package]]
 name = "virtio-media"
-version = "0.0.5"
+version = "0.0.6"
 dependencies = [
  "anyhow",
  "enumn",
diff --git a/device/Cargo.toml b/device/Cargo.toml
index 90c87d4..51af8a2 100644
--- a/device/Cargo.toml
+++ b/device/Cargo.toml
@@ -1,6 +1,6 @@
 [package]
 name = "virtio-media"
-version = "0.0.5"
+version = "0.0.6"
 license = "BSD-3-Clause"
 description = "Device support for virtio-media"
 repository = "https://github.com/chromeos/virtio-media"
@@ -14,7 +14,8 @@ libc = "0.2.151"
 log = "0.4.20"
 nix = { version = "0.28", features = ["fs"] }
 thiserror = "1.0.38"
-v4l2r = "0.0.4"
+# Use 64-bit bindings as this is the format used by virtio-media
+v4l2r = { version = "0.0.5", features = ["arch64"] }
 zerocopy = { version = "0.7.31", features = ["derive"] }
 
 [features]
diff --git a/device/src/devices/simple_device.rs b/device/src/devices/simple_device.rs
index 2863258..6f989f3 100644
--- a/device/src/devices/simple_device.rs
+++ b/device/src/devices/simple_device.rs
@@ -40,10 +40,12 @@ use crate::protocol::SgEntry;
 use crate::protocol::V4l2Event;
 use crate::protocol::V4l2Ioctl;
 use crate::protocol::VIRTIO_MEDIA_MMAP_FLAG_RW;
+use crate::ReadFromDescriptorChain;
 use crate::VirtioMediaDevice;
 use crate::VirtioMediaDeviceSession;
 use crate::VirtioMediaEventQueue;
 use crate::VirtioMediaHostMemoryMapper;
+use crate::WriteToDescriptorChain;
 
 /// Current status of a buffer.
 #[derive(Debug, PartialEq, Eq)]
@@ -203,8 +205,8 @@ impl<Q, HM, Reader, Writer> VirtioMediaDevice<Reader, Writer> for SimpleCaptureD
 where
     Q: VirtioMediaEventQueue,
     HM: VirtioMediaHostMemoryMapper,
-    Reader: std::io::Read,
-    Writer: std::io::Write,
+    Reader: ReadFromDescriptorChain,
+    Writer: WriteToDescriptorChain,
 {
     type Session = SimpleCaptureDeviceSession;
 
diff --git a/device/src/devices/v4l2_device_proxy.rs b/device/src/devices/v4l2_device_proxy.rs
index 2bd0500..fad5c63 100644
--- a/device/src/devices/v4l2_device_proxy.rs
+++ b/device/src/devices/v4l2_device_proxy.rs
@@ -92,11 +92,13 @@ use crate::protocol::V4l2Event;
 use crate::protocol::V4l2Ioctl;
 use crate::protocol::VIRTIO_MEDIA_MMAP_FLAG_RW;
 use crate::GuestMemoryRange;
+use crate::ReadFromDescriptorChain;
 use crate::VirtioMediaDevice;
 use crate::VirtioMediaDeviceSession;
 use crate::VirtioMediaEventQueue;
 use crate::VirtioMediaGuestMemoryMapper;
 use crate::VirtioMediaHostMemoryMapper;
+use crate::WriteToDescriptorChain;
 
 type GuestAddrType = <UserPtr as Memory>::RawBacking;
 
@@ -1208,8 +1210,8 @@ where
     Q: VirtioMediaEventQueue,
     M: VirtioMediaGuestMemoryMapper,
     HM: VirtioMediaHostMemoryMapper,
-    Reader: std::io::Read,
-    Writer: std::io::Write,
+    Reader: ReadFromDescriptorChain,
+    Writer: WriteToDescriptorChain,
 {
     type Session = V4l2Session<M>;
 
@@ -1233,10 +1235,7 @@ where
     ) -> Result<(u64, u64), i32> {
         let rw = (flags & VIRTIO_MEDIA_MMAP_FLAG_RW) != 0;
 
-        let plane_info = self
-            .mmap_buffers
-            .get_mut(&offset)
-            .ok_or(libc::EINVAL)?;
+        let plane_info = self.mmap_buffers.get_mut(&offset).ok_or(libc::EINVAL)?;
 
         // Export the FD for the plane and cache it if needed.
         //
diff --git a/device/src/devices/video_decoder.rs b/device/src/devices/video_decoder.rs
index b542507..047ba5a 100644
--- a/device/src/devices/video_decoder.rs
+++ b/device/src/devices/video_decoder.rs
@@ -27,6 +27,8 @@ use v4l2r::QueueType;
 use v4l2r::XferFunc;
 use v4l2r::YCbCrEncoding;
 
+use crate::io::ReadFromDescriptorChain;
+use crate::io::WriteToDescriptorChain;
 use crate::ioctl::virtio_media_dispatch_ioctl;
 use crate::ioctl::IoctlResult;
 use crate::ioctl::VirtioMediaIoctlHandler;
@@ -575,8 +577,8 @@ where
     B: VideoDecoderBackend,
     Q: VirtioMediaEventQueue,
     HM: VirtioMediaHostMemoryMapper,
-    Reader: std::io::Read,
-    Writer: std::io::Write,
+    Reader: ReadFromDescriptorChain,
+    Writer: WriteToDescriptorChain,
 {
     type Session = <Self as VirtioMediaIoctlHandler>::Session;
 
@@ -928,11 +930,10 @@ where
                         &[sizeimage as usize],
                         mmap_offset,
                     )
-                    .map_err(|e| {
+                    .inspect_err(|_| {
                         // TODO: no, we need to unregister all the buffers and restore the
                         // previous state?
                         self.host_mapper.unregister_buffer(mmap_offset);
-                        e
                     })
                 })
                 .collect::<IoctlResult<Vec<_>>>()?;
diff --git a/device/src/io.rs b/device/src/io.rs
new file mode 100644
index 0000000..c77c917
--- /dev/null
+++ b/device/src/io.rs
@@ -0,0 +1,132 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+//! Traits and implementations for reading virtio-media commands from and writing responses to
+//! virtio descriptors.
+//!
+//! Virtio-media requires data send through virtqueues to be in little-endian order, but there is
+//! no guarantee that the host also uses the same endianness. The [`VmediaType`] trait needs to be
+//! implemented for all types transiting through virtio in order to ensure they are converted
+//! from/to the correct representation if needed.
+//!
+//! Commands and responses can be read and written from any type implementing [`std::io::Read`] or
+//! [`std::io::Write`] respectively. The [`ReadFromDescriptorChain`] and [`WriteToDescriptorChain`]
+//! sealed extension traits are the only way to write or read data from virtio descriptors. They
+//! ensure that transiting data is always in little-endian representation by using [`VmediaType`]
+//! to wrap it into [`LeWrapper`].
+
+use std::io::Result as IoResult;
+use std::mem::MaybeUninit;
+
+use zerocopy::AsBytes;
+use zerocopy::FromBytes;
+use zerocopy::FromZeroes;
+
+#[cfg(target_endian = "little")]
+mod le;
+#[cfg(target_endian = "little")]
+pub use le::*;
+
+#[cfg(target_endian = "big")]
+mod be;
+#[cfg(target_endian = "big")]
+pub use be::*;
+
+use crate::RespHeader;
+
+/// Seals for [`ReadFromDescriptorChain`] and [`WriteToDescriptorChain`] so no new implementations can
+/// be created outside of this crate.
+mod private {
+    pub trait RSealed {}
+    impl<R> RSealed for R where R: std::io::Read {}
+
+    pub trait WSealed {}
+    impl<W> WSealed for W where W: std::io::Write {}
+}
+
+/// Extension trait for reading objects from the device-readable section of a descriptor chain,
+/// converting them from little-endian to the native endianness of the system.
+pub trait ReadFromDescriptorChain: private::RSealed {
+    fn read_obj<T: VmediaType>(&mut self) -> std::io::Result<T>;
+}
+
+/// Any implementor of [`std::io::Read`] can be used to read virtio-media commands.
+impl<R> ReadFromDescriptorChain for R
+where
+    R: std::io::Read,
+{
+    fn read_obj<T: VmediaType>(&mut self) -> std::io::Result<T> {
+        // We use `zeroed` instead of `uninit` because `read_exact` cannot be called with
+        // uninitialized memory. Since `T` implements `FromBytes`, its zeroed form is valid and
+        // initialized.
+        let mut obj: MaybeUninit<LeWrapper<T>> = std::mem::MaybeUninit::zeroed();
+        // Safe because the slice boundaries cover `obj`, and the slice doesn't outlive it.
+        let slice = unsafe {
+            std::slice::from_raw_parts_mut(obj.as_mut_ptr() as *mut u8, std::mem::size_of::<T>())
+        };
+
+        self.read_exact(slice)?;
+
+        // Safe because obj can be initialized from an array of bytes.
+        Ok(unsafe { obj.assume_init() }.into_native())
+    }
+}
+
+/// Extension trait for writing objects and responses into the device-writable section of a
+/// descriptor chain, after converting them to little-endian representation.
+pub trait WriteToDescriptorChain: private::WSealed {
+    /// Write an arbitrary object to the guest.
+    fn write_obj<T: VmediaType>(&mut self, obj: T) -> IoResult<()>;
+
+    /// Write a command response to the guest.
+    fn write_response<T: VmediaType>(&mut self, response: T) -> IoResult<()> {
+        self.write_obj(response)
+    }
+
+    /// Send `code` as the error code of an error response.
+    fn write_err_response(&mut self, code: libc::c_int) -> IoResult<()> {
+        self.write_response(RespHeader::err(code))
+    }
+}
+
+/// Any implementor of [`std::io::Write`] can be used to write virtio-media responses.
+impl<W> WriteToDescriptorChain for W
+where
+    W: std::io::Write,
+{
+    fn write_obj<T: VmediaType>(&mut self, obj: T) -> IoResult<()> {
+        self.write_all(obj.to_le().as_bytes())
+    }
+}
+
+/// Private wrapper for all types that can be sent/received over virtio. Wrapped objects are
+/// guaranteed to use little-endian representation.
+///
+/// Wrapped objects are inaccessible and can only be passed to methods writing to virtio
+/// descriptors. [`Self::into_native`] can be used to retrieve the object in its native ordering.
+#[repr(transparent)]
+pub struct LeWrapper<T: VmediaType>(T);
+
+impl<T: VmediaType> LeWrapper<T> {
+    /// Convert the wrapped object back to native ordering and return it.
+    pub fn into_native(self) -> T {
+        T::from_le(self)
+    }
+}
+
+unsafe impl<T: VmediaType> FromZeroes for LeWrapper<T> {
+    fn only_derive_is_allowed_to_implement_this_trait() {}
+}
+
+unsafe impl<T: VmediaType> FromBytes for LeWrapper<T> {
+    fn only_derive_is_allowed_to_implement_this_trait() {}
+}
+
+unsafe impl<T: VmediaType> AsBytes for LeWrapper<T> {
+    fn only_derive_is_allowed_to_implement_this_trait()
+    where
+        Self: Sized,
+    {
+    }
+}
diff --git a/device/src/io/be.rs b/device/src/io/be.rs
new file mode 100644
index 0000000..4a729a8
--- /dev/null
+++ b/device/src/io/be.rs
@@ -0,0 +1,14 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+std::compile_error!("Big-endian hosts are not supported yet");
+
+pub trait VmediaType: Sized {
+    fn to_le(self) -> LeWrapper<Self>;
+
+    fn from_le(le: LeWrapper<Self>) -> Self {
+        // Assume endianness conversion is symmetrical, which is should be.
+        self.0.to_le().0
+    }
+}
diff --git a/device/src/io/le.rs b/device/src/io/le.rs
new file mode 100644
index 0000000..8636249
--- /dev/null
+++ b/device/src/io/le.rs
@@ -0,0 +1,87 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+//! Since the wire format of virtio-media uses little-endian, a host using the same ordering does
+//! not need to perform any swapping - hence the definitions here are no-ops.
+
+use v4l2r::bindings;
+
+use crate::io::LeWrapper;
+use crate::CloseCmd;
+use crate::CmdHeader;
+use crate::DequeueBufferEvent;
+use crate::ErrorEvent;
+use crate::IoctlCmd;
+use crate::MmapCmd;
+use crate::MmapResp;
+use crate::MunmapCmd;
+use crate::MunmapResp;
+use crate::OpenCmd;
+use crate::OpenResp;
+use crate::RespHeader;
+use crate::SessionEvent;
+use crate::SgEntry;
+
+/// Trait for types that can be sent as part of the virtio-media protocol.
+pub trait VmediaType: Sized {
+    fn to_le(self) -> LeWrapper<Self> {
+        LeWrapper(self)
+    }
+    fn from_le(le: LeWrapper<Self>) -> Self {
+        le.0
+    }
+}
+
+impl VmediaType for () {}
+impl VmediaType for u32 {}
+impl VmediaType for i32 {}
+
+impl VmediaType for CmdHeader {}
+impl VmediaType for RespHeader {}
+impl VmediaType for OpenCmd {}
+impl VmediaType for OpenResp {}
+impl VmediaType for CloseCmd {}
+impl VmediaType for IoctlCmd {}
+impl VmediaType for SgEntry {}
+impl VmediaType for MmapCmd {}
+impl VmediaType for MmapResp {}
+impl VmediaType for MunmapCmd {}
+impl VmediaType for MunmapResp {}
+impl VmediaType for DequeueBufferEvent {}
+impl VmediaType for SessionEvent {}
+impl VmediaType for ErrorEvent {}
+
+impl VmediaType for bindings::v4l2_buffer {}
+impl VmediaType for bindings::v4l2_standard {}
+impl VmediaType for bindings::v4l2_input {}
+impl VmediaType for bindings::v4l2_control {}
+impl VmediaType for bindings::v4l2_std_id {}
+impl VmediaType for bindings::v4l2_tuner {}
+impl VmediaType for bindings::v4l2_audio {}
+impl VmediaType for bindings::v4l2_plane {}
+impl VmediaType for bindings::v4l2_format {}
+impl VmediaType for bindings::v4l2_enc_idx {}
+impl VmediaType for bindings::v4l2_output {}
+impl VmediaType for bindings::v4l2_audioout {}
+impl VmediaType for bindings::v4l2_modulator {}
+impl VmediaType for bindings::v4l2_frequency {}
+impl VmediaType for bindings::v4l2_frmsizeenum {}
+impl VmediaType for bindings::v4l2_frmivalenum {}
+impl VmediaType for bindings::v4l2_encoder_cmd {}
+impl VmediaType for bindings::v4l2_decoder_cmd {}
+impl VmediaType for bindings::v4l2_dv_timings {}
+impl VmediaType for bindings::v4l2_event_subscription {}
+impl VmediaType for bindings::v4l2_create_buffers {}
+impl VmediaType for bindings::v4l2_selection {}
+impl VmediaType for bindings::v4l2_enum_dv_timings {}
+impl VmediaType for bindings::v4l2_dv_timings_cap {}
+impl VmediaType for bindings::v4l2_frequency_band {}
+impl VmediaType for bindings::v4l2_query_ext_ctrl {}
+impl VmediaType for bindings::v4l2_queryctrl {}
+impl VmediaType for bindings::v4l2_querymenu {}
+impl VmediaType for bindings::v4l2_ext_control {}
+impl VmediaType for bindings::v4l2_ext_controls {}
+impl VmediaType for bindings::v4l2_fmtdesc {}
+impl VmediaType for bindings::v4l2_requestbuffers {}
+impl VmediaType for bindings::v4l2_streamparm {}
diff --git a/device/src/ioctl.rs b/device/src/ioctl.rs
index 1436aba..5918e04 100644
--- a/device/src/ioctl.rs
+++ b/device/src/ioctl.rs
@@ -57,122 +57,188 @@ use v4l2r::memory::MemoryType;
 use v4l2r::QueueDirection;
 use v4l2r::QueueType;
 
+use crate::io::ReadFromDescriptorChain;
+use crate::io::VmediaType;
+use crate::io::WriteToDescriptorChain;
 use crate::protocol::RespHeader;
 use crate::protocol::SgEntry;
 use crate::protocol::V4l2Ioctl;
-use crate::FromDescriptorChain;
-use crate::ReadFromDescriptorChain;
-use crate::ToDescriptorChain;
-use crate::WriteToDescriptorChain;
 
-/// Module allowing select V4L2 structures from implementing zerocopy and implementations of
-/// [`FromDescriptorChain`] and [`ToDescriptorChain`] for them.
-mod v4l2_zerocopy {
-    use v4l2r::bindings;
-    use zerocopy::AsBytes;
-    use zerocopy::FromBytes;
-    use zerocopy::FromZeroes;
+/// Reads a SG list of guest physical addresses passed from the driver and returns it.
+fn get_userptr_regions<R: ReadFromDescriptorChain>(
+    r: &mut R,
+    size: usize,
+) -> anyhow::Result<Vec<SgEntry>> {
+    let mut bytes_taken = 0;
+    let mut res = Vec::new();
 
-    use crate::FromDescriptorChain;
-    use crate::ReadFromDescriptorChain;
-    use crate::ToDescriptorChain;
+    while bytes_taken < size {
+        let sg_entry = r.read_obj::<SgEntry>()?;
+        bytes_taken += sg_entry.len as usize;
+        res.push(sg_entry);
+    }
 
-    /// Wrapper allowing any structure to be read/written using zerocopy. This obviously should be
-    /// used with caution and thus is private.
-    #[repr(transparent)]
-    struct ForceZeroCopyWrapper<T: Sized>(T);
+    Ok(res)
+}
 
-    unsafe impl<T: Sized> FromZeroes for ForceZeroCopyWrapper<T> {
-        fn only_derive_is_allowed_to_implement_this_trait() {}
-    }
+/// Local trait for reading simple or complex objects from a reader, e.g. the device-readable
+/// section of a descriptor chain.
+trait FromDescriptorChain {
+    fn read_from_chain<R: ReadFromDescriptorChain>(reader: &mut R) -> std::io::Result<Self>
+    where
+        Self: Sized;
+}
 
-    unsafe impl<T: Sized> FromBytes for ForceZeroCopyWrapper<T> {
-        fn only_derive_is_allowed_to_implement_this_trait() {}
+/// Implementation for simple objects that can be returned as-is after their endianness is
+/// fixed.
+impl<T> FromDescriptorChain for T
+where
+    T: VmediaType,
+{
+    fn read_from_chain<R: ReadFromDescriptorChain>(reader: &mut R) -> std::io::Result<Self> {
+        reader.read_obj()
     }
+}
+
+/// Implementation to easily read a `v4l2_buffer` of `USERPTR` memory type and its associated
+/// guest-side buffers from a descriptor chain.
+impl FromDescriptorChain for (V4l2Buffer, Vec<Vec<SgEntry>>) {
+    fn read_from_chain<R: ReadFromDescriptorChain>(reader: &mut R) -> IoResult<Self>
+    where
+        Self: Sized,
+    {
+        let v4l2_buffer = reader.read_obj::<v4l2_buffer>()?;
+        let queue = match QueueType::n(v4l2_buffer.type_) {
+            Some(queue) => queue,
+            None => return Err(std::io::ErrorKind::InvalidData.into()),
+        };
+
+        let v4l2_planes = if queue.is_multiplanar() && v4l2_buffer.length > 0 {
+            if v4l2_buffer.length > v4l2r::bindings::VIDEO_MAX_PLANES {
+                return Err(std::io::ErrorKind::InvalidData.into());
+            }
+
+            let planes: [v4l2r::bindings::v4l2_plane; v4l2r::bindings::VIDEO_MAX_PLANES as usize] =
+                (0..v4l2_buffer.length as usize)
+                    .map(|_| reader.read_obj::<v4l2_plane>())
+                    .collect::<IoResult<Vec<_>>>()?
+                    .into_iter()
+                    .chain(std::iter::repeat(Default::default()))
+                    .take(v4l2r::bindings::VIDEO_MAX_PLANES as usize)
+                    .collect::<Vec<_>>()
+                    .try_into()
+                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
+            Some(planes)
+        } else {
+            None
+        };
 
-    unsafe impl<T: Sized> AsBytes for ForceZeroCopyWrapper<T> {
-        fn only_derive_is_allowed_to_implement_this_trait()
-        where
-            Self: Sized,
+        let v4l2_buffer = V4l2Buffer::try_from(UncheckedV4l2Buffer(v4l2_buffer, v4l2_planes))
+            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
+
+        // Read the `MemRegion`s of all planes if the buffer is `USERPTR`.
+        let guest_regions = if let V4l2PlanesWithBacking::UserPtr(planes) =
+            v4l2_buffer.planes_with_backing_iter()
         {
-        }
+            planes
+                .filter(|p| *p.length > 0)
+                .map(|p| {
+                    get_userptr_regions(reader, *p.length as usize)
+                        .map_err(|_| std::io::ErrorKind::InvalidData.into())
+                })
+                .collect::<IoResult<Vec<_>>>()?
+        } else {
+            vec![]
+        };
+
+        Ok((v4l2_buffer, guest_regions))
     }
+}
 
-    impl<T> FromDescriptorChain for ForceZeroCopyWrapper<T> {
-        fn read_from_chain<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
-            reader.read_obj()
-        }
+/// Implementation to easily read a `v4l2_ext_controls` struct, its array of controls, and the SG
+/// list of the buffers pointed to by the controls from a descriptor chain.
+impl FromDescriptorChain for (v4l2_ext_controls, Vec<v4l2_ext_control>, Vec<Vec<SgEntry>>) {
+    fn read_from_chain<R: ReadFromDescriptorChain>(reader: &mut R) -> std::io::Result<Self>
+    where
+        Self: Sized,
+    {
+        let ctrls = reader.read_obj::<v4l2_ext_controls>()?;
+
+        let ctrl_array = (0..ctrls.count)
+            .map(|_| reader.read_obj::<v4l2_ext_control>())
+            .collect::<IoResult<Vec<_>>>()?;
+
+        // Read all the payloads.
+        let mem_regions = ctrl_array
+            .iter()
+            .filter(|ctrl| ctrl.size > 0)
+            .map(|ctrl| {
+                get_userptr_regions(reader, ctrl.size as usize)
+                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))
+            })
+            .collect::<IoResult<Vec<_>>>()?;
+
+        Ok((ctrls, ctrl_array, mem_regions))
     }
+}
 
-    impl<T> ToDescriptorChain for ForceZeroCopyWrapper<T> {
-        fn write_to_chain<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
-            writer.write_all(self.as_bytes())
-        }
+/// Local trait for writing simple or complex objects to a writer, e.g. the device-writable section
+/// of a descriptor chain.
+trait ToDescriptorChain {
+    fn write_to_chain<W: WriteToDescriptorChain>(self, writer: &mut W) -> std::io::Result<()>;
+}
+
+/// Implementation for simple objects that can be written as-is after their endianness is
+/// fixed.
+impl<T> ToDescriptorChain for T
+where
+    T: VmediaType,
+{
+    fn write_to_chain<W: WriteToDescriptorChain>(self, writer: &mut W) -> std::io::Result<()> {
+        writer.write_obj(self)
     }
+}
 
-    /// Trait granting implementations of [`FromDescriptorChain`] and [`ToDescriptorChain`] to
-    /// implementors.
-    ///
-    /// # Safety
-    ///
-    /// Only types that can be read from an arbitrary stream of data should implement this. This
-    /// covers all V4L2 types used in ioctls.
-    unsafe trait ForceZeroCopy {}
+/// Implementation to easily write a `v4l2_buffer` to a descriptor chain, while ensuring the number
+/// of planes written is not larger than a limit (i.e. the maximum number of planes that the
+/// descriptor chain can receive).
+impl ToDescriptorChain for (V4l2Buffer, usize) {
+    fn write_to_chain<W: WriteToDescriptorChain>(self, writer: &mut W) -> std::io::Result<()> {
+        let mut v4l2_buffer = *self.0.as_v4l2_buffer();
+        // If the buffer is multiplanar, nullify the `planes` pointer to avoid leaking host
+        // addresses.
+        if self.0.queue().is_multiplanar() {
+            v4l2_buffer.m.planes = std::ptr::null_mut();
+        }
+        writer.write_obj(v4l2_buffer)?;
 
-    impl<T: ForceZeroCopy> FromDescriptorChain for T {
-        fn read_from_chain<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
-            ForceZeroCopyWrapper::<T>::read_from_chain(reader).map(|r| r.0)
+        // Write plane information if the buffer is multiplanar. Limit the number of planes to the
+        // upper bound we were given.
+        for plane in self.0.as_v4l2_planes().iter().take(self.1) {
+            writer.write_obj(*plane)?;
         }
+
+        Ok(())
     }
+}
+
+/// Implementation to easily write a `v4l2_ext_controls` struct and its array of controls to a
+/// descriptor chain.
+impl ToDescriptorChain for (v4l2_ext_controls, Vec<v4l2_ext_control>) {
+    fn write_to_chain<W: WriteToDescriptorChain>(self, writer: &mut W) -> std::io::Result<()> {
+        let (ctrls, ctrl_array) = self;
+        let mut ctrls = ctrls;
 
-    impl<T: ForceZeroCopy> ToDescriptorChain for T {
-        fn write_to_chain<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
-            unsafe { std::mem::transmute::<&T, &ForceZeroCopyWrapper<T>>(self) }
-                .write_to_chain(writer)
+        // Nullify the control pointer to avoid leaking host addresses.
+        ctrls.controls = std::ptr::null_mut();
+        writer.write_obj(ctrls)?;
+
+        for ctrl in ctrl_array {
+            writer.write_obj(ctrl)?;
         }
-    }
 
-    // Allows V4L2 types to be read from/written to a descriptor chain.
-
-    unsafe impl ForceZeroCopy for () {}
-    unsafe impl ForceZeroCopy for u32 {}
-    unsafe impl ForceZeroCopy for i32 {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_buffer {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_standard {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_input {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_control {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_std_id {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_tuner {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_audio {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_plane {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_format {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_enc_idx {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_output {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_audioout {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_modulator {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_frequency {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_frmsizeenum {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_frmivalenum {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_encoder_cmd {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_decoder_cmd {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_dv_timings {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_event_subscription {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_create_buffers {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_selection {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_enum_dv_timings {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_dv_timings_cap {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_frequency_band {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_query_ext_ctrl {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_queryctrl {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_querymenu {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_ext_control {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_ext_controls {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_fmtdesc {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_requestbuffers {}
-    unsafe impl ForceZeroCopy for bindings::v4l2_streamparm {}
-
-    unsafe impl ForceZeroCopy for crate::protocol::DequeueBufferEvent {}
-    unsafe impl ForceZeroCopy for crate::protocol::SessionEvent {}
+        Ok(())
+    }
 }
 
 /// Returns `ENOTTY` to signal that an ioctl is not handled by this device.
@@ -622,7 +688,7 @@ pub trait VirtioMediaIoctlHandler {
 
 /// Writes a `ENOTTY` error response into `writer` to signal that an ioctl is not implemented by
 /// the device.
-fn invalid_ioctl<W: std::io::Write>(code: V4l2Ioctl, writer: &mut W) -> IoResult<()> {
+fn invalid_ioctl<W: WriteToDescriptorChain>(code: V4l2Ioctl, writer: &mut W) -> IoResult<()> {
     writer.write_err_response(libc::ENOTTY).map_err(|e| {
         log::error!(
             "failed to write error response for invalid ioctl {:?}: {:#}",
@@ -633,143 +699,6 @@ fn invalid_ioctl<W: std::io::Write>(code: V4l2Ioctl, writer: &mut W) -> IoResult
     })
 }
 
-/// Reads a SG list of guest physical addresses passed from the driver and returns it.
-fn get_userptr_regions<R: std::io::Read>(r: &mut R, size: usize) -> anyhow::Result<Vec<SgEntry>> {
-    let mut bytes_taken = 0;
-    let mut res = Vec::new();
-
-    while bytes_taken < size {
-        let sg_entry = r.read_obj::<SgEntry>()?;
-        bytes_taken += sg_entry.len as usize;
-        res.push(sg_entry);
-    }
-
-    Ok(res)
-}
-
-/// Allows to easily read a `v4l2_buffer` of `USERPTR` memory type and its associated guest-side
-/// buffers from a descriptor chain.
-impl FromDescriptorChain for (V4l2Buffer, Vec<Vec<SgEntry>>) {
-    fn read_from_chain<R: std::io::Read>(reader: &mut R) -> IoResult<Self>
-    where
-        Self: Sized,
-    {
-        let v4l2_buffer = v4l2_buffer::read_from_chain(reader)?;
-        let queue = match QueueType::n(v4l2_buffer.type_) {
-            Some(queue) => queue,
-            None => return Err(std::io::ErrorKind::InvalidData.into()),
-        };
-
-        let v4l2_planes = if queue.is_multiplanar() && v4l2_buffer.length > 0 {
-            if v4l2_buffer.length > v4l2r::bindings::VIDEO_MAX_PLANES {
-                return Err(std::io::ErrorKind::InvalidData.into());
-            }
-
-            let planes: [v4l2r::bindings::v4l2_plane; v4l2r::bindings::VIDEO_MAX_PLANES as usize] =
-                (0..v4l2_buffer.length as usize)
-                    .map(|_| v4l2_plane::read_from_chain(reader))
-                    .collect::<IoResult<Vec<_>>>()?
-                    .into_iter()
-                    .chain(std::iter::repeat(Default::default()))
-                    .take(v4l2r::bindings::VIDEO_MAX_PLANES as usize)
-                    .collect::<Vec<_>>()
-                    .try_into()
-                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
-            Some(planes)
-        } else {
-            None
-        };
-
-        let v4l2_buffer = V4l2Buffer::try_from(UncheckedV4l2Buffer(v4l2_buffer, v4l2_planes))
-            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
-
-        // Read the `MemRegion`s of all planes if the buffer is `USERPTR`.
-        let guest_regions = if let V4l2PlanesWithBacking::UserPtr(planes) =
-            v4l2_buffer.planes_with_backing_iter()
-        {
-            planes
-                .filter(|p| *p.length > 0)
-                .map(|p| {
-                    get_userptr_regions(reader, *p.length as usize)
-                        .map_err(|_| std::io::ErrorKind::InvalidData.into())
-                })
-                .collect::<IoResult<Vec<_>>>()?
-        } else {
-            vec![]
-        };
-
-        Ok((v4l2_buffer, guest_regions))
-    }
-}
-
-/// Write a `v4l2_buffer` to a descriptor chain, while ensuring the number of planes written is not
-/// larger than a limit (i.e. the maximum number of planes that the descriptor chain can receive).
-impl ToDescriptorChain for (V4l2Buffer, usize) {
-    fn write_to_chain<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
-        let mut v4l2_buffer = *self.0.as_v4l2_buffer();
-        // If the buffer is multiplanar, nullify the `planes` pointer to avoid leaking host
-        // addresses.
-        if self.0.queue().is_multiplanar() {
-            v4l2_buffer.m.planes = std::ptr::null_mut();
-        }
-        v4l2_buffer.write_to_chain(writer)?;
-
-        // Write plane information if the buffer is multiplanar. Limit the number of planes to the
-        // upper bound we were given.
-        for plane in self.0.as_v4l2_planes().iter().take(self.1) {
-            plane.write_to_chain(writer)?;
-        }
-
-        Ok(())
-    }
-}
-
-/// Allows to easily read a `v4l2_ext_controls` struct, its array of controls, and the SG list of
-/// the buffers pointed to by the controls from a descriptor chain.
-impl FromDescriptorChain for (v4l2_ext_controls, Vec<v4l2_ext_control>, Vec<Vec<SgEntry>>) {
-    fn read_from_chain<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self>
-    where
-        Self: Sized,
-    {
-        let ctrls = v4l2_ext_controls::read_from_chain(reader)?;
-
-        let ctrl_array = (0..ctrls.count)
-            .map(|_| v4l2_ext_control::read_from_chain(reader))
-            .collect::<IoResult<Vec<_>>>()?;
-
-        // Read all the payloads.
-        let mem_regions = ctrl_array
-            .iter()
-            .filter(|ctrl| ctrl.size > 0)
-            .map(|ctrl| {
-                get_userptr_regions(reader, ctrl.size as usize)
-                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))
-            })
-            .collect::<IoResult<Vec<_>>>()?;
-
-        Ok((ctrls, ctrl_array, mem_regions))
-    }
-}
-
-/// Allows to easily write a `v4l2_ext_controls` struct and its array of controls to a descriptor
-/// chain.
-impl ToDescriptorChain for (v4l2_ext_controls, Vec<v4l2_ext_control>) {
-    fn write_to_chain<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
-        let (ctrls, ctrl_array) = self;
-        let mut ctrls = *ctrls;
-
-        // Nullify the control pointer to avoid leaking host addresses.
-        ctrls.controls = std::ptr::null_mut();
-        ctrls.write_to_chain(writer)?;
-
-        for ctrl in ctrl_array {
-            ctrl.write_to_chain(writer)?;
-        }
-
-        Ok(())
-    }
-}
-
 /// Implements a `WR` ioctl for which errors may also carry a payload.
 ///
 /// * `Reader` is the reader to the device-readable part of the descriptor chain,
@@ -786,8 +715,8 @@ fn wr_ioctl_with_err_payload<Reader, Writer, I, O, X>(
     process: X,
 ) -> IoResult<()>
 where
-    Reader: std::io::Read,
-    Writer: std::io::Write,
+    Reader: ReadFromDescriptorChain,
+    Writer: WriteToDescriptorChain,
     I: FromDescriptorChain,
     O: ToDescriptorChain,
     X: FnOnce(I) -> Result<O, (i32, Option<O>)>,
@@ -828,8 +757,8 @@ fn wr_ioctl<Reader, Writer, I, O, X>(
     process: X,
 ) -> IoResult<()>
 where
-    Reader: std::io::Read,
-    Writer: std::io::Write,
+    Reader: ReadFromDescriptorChain,
+    Writer: WriteToDescriptorChain,
     I: FromDescriptorChain,
     O: ToDescriptorChain,
     X: FnOnce(I) -> Result<O, i32>,
@@ -853,8 +782,8 @@ fn w_ioctl<Reader, Writer, I, X>(
 ) -> IoResult<()>
 where
     I: FromDescriptorChain,
-    Reader: std::io::Read,
-    Writer: std::io::Write,
+    Reader: ReadFromDescriptorChain,
+    Writer: WriteToDescriptorChain,
     X: FnOnce(I) -> Result<(), i32>,
 {
     wr_ioctl(ioctl, reader, writer, process)
@@ -868,7 +797,7 @@ where
 ///   the guest is returned.
 fn r_ioctl<Writer, O, X>(ioctl: V4l2Ioctl, writer: &mut Writer, process: X) -> IoResult<()>
 where
-    Writer: std::io::Write,
+    Writer: WriteToDescriptorChain,
     O: ToDescriptorChain,
     X: FnOnce() -> Result<O, i32>,
 {
@@ -905,8 +834,8 @@ pub fn virtio_media_dispatch_ioctl<S, H, Reader, Writer>(
 ) -> IoResult<()>
 where
     H: VirtioMediaIoctlHandler<Session = S>,
-    Reader: std::io::Read,
-    Writer: std::io::Write,
+    Reader: ReadFromDescriptorChain,
+    Writer: WriteToDescriptorChain,
 {
     use V4l2Ioctl::*;
 
diff --git a/device/src/lib.rs b/device/src/lib.rs
index c4b2bc4..8d1f93d 100644
--- a/device/src/lib.rs
+++ b/device/src/lib.rs
@@ -46,12 +46,15 @@
 //!   module.
 
 pub mod devices;
+pub mod io;
 pub mod ioctl;
 pub mod memfd;
 pub mod mmap;
 pub mod poll;
 pub mod protocol;
 
+use io::ReadFromDescriptorChain;
+use io::WriteToDescriptorChain;
 use poll::SessionPoller;
 pub use v4l2r;
 
@@ -61,24 +64,9 @@ use std::os::fd::BorrowedFd;
 
 use anyhow::Context;
 use log::error;
-use zerocopy::AsBytes;
-use zerocopy::FromBytes;
 
 use protocol::*;
 
-/// Trait for reading objects from a reader, e.g. the device-readable section of a descriptor
-/// chain.
-pub trait FromDescriptorChain {
-    fn read_from_chain<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self>
-    where
-        Self: Sized;
-}
-
-/// Trait for writing objects to a writer, e.g. the device-writable section of a descriptor chain.
-pub trait ToDescriptorChain {
-    fn write_to_chain<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()>;
-}
-
 /// Trait for sending V4L2 events to the driver.
 pub trait VirtioMediaEventQueue {
     /// Wait until an event descriptor becomes available and send `event` to the guest.
@@ -169,7 +157,7 @@ pub trait VirtioMediaDeviceSession {
 /// [`VirtioMediaDeviceRunner`], which takes care of reading and dispatching commands. In addition,
 /// [`ioctl::VirtioMediaIoctlHandler`] should also be used to automatically parse and dispatch
 /// ioctls.
-pub trait VirtioMediaDevice<Reader: std::io::Read, Writer: std::io::Write> {
+pub trait VirtioMediaDevice<Reader: ReadFromDescriptorChain, Writer: WriteToDescriptorChain> {
     type Session: VirtioMediaDeviceSession;
 
     /// Create a new session which ID is `session_id`.
@@ -226,8 +214,8 @@ pub trait VirtioMediaDevice<Reader: std::io::Read, Writer: std::io::Write> {
 /// processing its commands.
 pub struct VirtioMediaDeviceRunner<Reader, Writer, Device, Poller>
 where
-    Reader: std::io::Read,
-    Writer: std::io::Write,
+    Reader: ReadFromDescriptorChain,
+    Writer: WriteToDescriptorChain,
     Device: VirtioMediaDevice<Reader, Writer>,
     Poller: SessionPoller,
 {
@@ -240,8 +228,8 @@ where
 
 impl<Reader, Writer, Device, Poller> VirtioMediaDeviceRunner<Reader, Writer, Device, Poller>
 where
-    Reader: std::io::Read,
-    Writer: std::io::Write,
+    Reader: ReadFromDescriptorChain,
+    Writer: WriteToDescriptorChain,
     Device: VirtioMediaDevice<Reader, Writer>,
     Poller: SessionPoller,
 {
@@ -255,65 +243,10 @@ where
     }
 }
 
-/// Crate-local extension trait for reading objects from the device-readable section of a
-/// descriptor chain.
-trait ReadFromDescriptorChain {
-    fn read_obj<T: FromBytes>(&mut self) -> std::io::Result<T>;
-}
-
-/// Any implementor of `Read` can be used to read virtio-media commands.
-impl<R> ReadFromDescriptorChain for R
-where
-    R: std::io::Read,
-{
-    fn read_obj<T: FromBytes>(&mut self) -> std::io::Result<T> {
-        // We use `zeroed` instead of `uninit` because `read_exact` cannot be called with
-        // uninitialized memory. Since `T` implements `FromBytes`, its zeroed form is valid and
-        // initialized.
-        let mut obj = std::mem::MaybeUninit::zeroed();
-        // Safe because the slice boundaries cover `obj`, and the slice doesn't outlive it.
-        let slice = unsafe {
-            std::slice::from_raw_parts_mut(obj.as_mut_ptr() as *mut u8, std::mem::size_of::<T>())
-        };
-
-        self.read_exact(slice)?;
-
-        // Safe because obj can be initialized from an array of bytes.
-        Ok(unsafe { obj.assume_init() })
-    }
-}
-
-/// Crate-local extension trait for writing objects and responses into the device-writable section
-/// of a descriptor chain.
-trait WriteToDescriptorChain {
-    /// Write an arbitrary object to the guest.
-    fn write_obj<T: AsBytes>(&mut self, obj: &T) -> IoResult<()>;
-
-    /// Write a command response to the guest.
-    fn write_response<T: AsBytes>(&mut self, response: T) -> IoResult<()> {
-        self.write_obj(&response)
-    }
-
-    /// Send `code` as the error code of an error response.
-    fn write_err_response(&mut self, code: libc::c_int) -> IoResult<()> {
-        self.write_response(RespHeader::err(code))
-    }
-}
-
-/// Any implementor of `Write` can be used to write virtio-media responses.
-impl<W> WriteToDescriptorChain for W
-where
-    W: std::io::Write,
-{
-    fn write_obj<T: AsBytes>(&mut self, obj: &T) -> IoResult<()> {
-        self.write_all(obj.as_bytes())
-    }
-}
-
 impl<Reader, Writer, Device, Poller> VirtioMediaDeviceRunner<Reader, Writer, Device, Poller>
 where
-    Reader: std::io::Read,
-    Writer: std::io::Write,
+    Reader: ReadFromDescriptorChain,
+    Writer: WriteToDescriptorChain,
     Device: VirtioMediaDevice<Reader, Writer>,
     Poller: SessionPoller,
 {
@@ -327,7 +260,7 @@ where
     /// are propagated to the guest, with the exception of errors triggered while writing the
     /// response which are logged on the host side.
     pub fn handle_command(&mut self, reader: &mut Reader, writer: &mut Writer) {
-        let hdr: CmdHeader = match reader.read_obj() {
+        let hdr = match reader.read_obj::<CmdHeader>() {
             Ok(hdr) => hdr,
             Err(e) => {
                 error!("error while reading command header: {:#}", e);
@@ -422,13 +355,17 @@ where
             VIRTIO_MEDIA_CMD_MUNMAP => reader
                 .read_obj()
                 .context("while reading UNMMAP command")
-                .and_then(|MunmapCmd { guest_addr }| {
-                    match self.device.do_munmap(guest_addr) {
-                        Ok(()) => writer.write_response(MunmapResp::ok()),
-                        Err(e) => writer.write_err_response(e),
-                    }
-                    .context("while writing response for MUNMAP command")
-                }),
+                .and_then(
+                    |MunmapCmd {
+                         driver_addr: guest_addr,
+                     }| {
+                        match self.device.do_munmap(guest_addr) {
+                            Ok(()) => writer.write_response(MunmapResp::ok()),
+                            Err(e) => writer.write_err_response(e),
+                        }
+                        .context("while writing response for MUNMAP command")
+                    },
+                ),
             _ => writer
                 .write_err_response(libc::ENOTTY)
                 .context("while writing error response for invalid command"),
diff --git a/device/src/protocol.rs b/device/src/protocol.rs
index 820e00e..31fe7d1 100644
--- a/device/src/protocol.rs
+++ b/device/src/protocol.rs
@@ -9,7 +9,7 @@ use zerocopy::AsBytes;
 use zerocopy::FromBytes;
 use zerocopy::FromZeroes;
 
-pub const VIRTIO_ID_MEDIA: u32 = 49;
+pub const VIRTIO_ID_MEDIA: u32 = 48;
 
 const VIRTIO_MEDIA_CARD_NAME_LEN: usize = 32;
 #[derive(Debug, AsBytes)]
@@ -208,7 +208,7 @@ pub struct MmapCmd {
 #[derive(Debug, AsBytes)]
 pub struct MmapResp {
     hdr: RespHeader,
-    guest_addr: u64,
+    driver_addr: u64,
     len: u64,
 }
 
@@ -216,7 +216,7 @@ impl MmapResp {
     pub fn ok(addr: u64, len: u64) -> Self {
         Self {
             hdr: RespHeader::ok(),
-            guest_addr: addr,
+            driver_addr: addr,
             len,
         }
     }
@@ -225,7 +225,7 @@ impl MmapResp {
 #[repr(C)]
 #[derive(Debug, FromZeroes, FromBytes)]
 pub struct MunmapCmd {
-    pub guest_addr: u64,
+    pub driver_addr: u64,
 }
 
 #[repr(C)]
diff --git a/driver/.clang-format b/driver/.clang-format
new file mode 100644
index 0000000..ccc9b93
--- /dev/null
+++ b/driver/.clang-format
@@ -0,0 +1,743 @@
+# SPDX-License-Identifier: GPL-2.0
+#
+# clang-format configuration file. Intended for clang-format >= 11.
+#
+# For more information, see:
+#
+#   Documentation/process/clang-format.rst
+#   https://clang.llvm.org/docs/ClangFormat.html
+#   https://clang.llvm.org/docs/ClangFormatStyleOptions.html
+#
+---
+AccessModifierOffset: -4
+AlignAfterOpenBracket: Align
+AlignConsecutiveAssignments: false
+AlignConsecutiveDeclarations: false
+AlignEscapedNewlines: Left
+AlignOperands: true
+AlignTrailingComments: false
+AllowAllParametersOfDeclarationOnNextLine: false
+AllowShortBlocksOnASingleLine: false
+AllowShortCaseLabelsOnASingleLine: false
+AllowShortFunctionsOnASingleLine: None
+AllowShortIfStatementsOnASingleLine: false
+AllowShortLoopsOnASingleLine: false
+AlwaysBreakAfterDefinitionReturnType: None
+AlwaysBreakAfterReturnType: None
+AlwaysBreakBeforeMultilineStrings: false
+AlwaysBreakTemplateDeclarations: false
+BinPackArguments: true
+BinPackParameters: true
+BraceWrapping:
+  AfterClass: false
+  AfterControlStatement: false
+  AfterEnum: false
+  AfterFunction: true
+  AfterNamespace: true
+  AfterObjCDeclaration: false
+  AfterStruct: false
+  AfterUnion: false
+  AfterExternBlock: false
+  BeforeCatch: false
+  BeforeElse: false
+  IndentBraces: false
+  SplitEmptyFunction: true
+  SplitEmptyRecord: true
+  SplitEmptyNamespace: true
+BreakBeforeBinaryOperators: None
+BreakBeforeBraces: Custom
+BreakBeforeInheritanceComma: false
+BreakBeforeTernaryOperators: false
+BreakConstructorInitializersBeforeComma: false
+BreakConstructorInitializers: BeforeComma
+BreakAfterJavaFieldAnnotations: false
+BreakStringLiterals: false
+ColumnLimit: 80
+CommentPragmas: '^ IWYU pragma:'
+CompactNamespaces: false
+ConstructorInitializerAllOnOneLineOrOnePerLine: false
+ConstructorInitializerIndentWidth: 8
+ContinuationIndentWidth: 8
+Cpp11BracedListStyle: false
+DerivePointerAlignment: false
+DisableFormat: false
+ExperimentalAutoDetectBinPacking: false
+FixNamespaceComments: false
+
+# Taken from:
+#   git grep -h '^#define [^[:space:]]*for_each[^[:space:]]*(' include/ tools/ \
+#   | sed "s,^#define \([^[:space:]]*for_each[^[:space:]]*\)(.*$,  - '\1'," \
+#   | LC_ALL=C sort -u
+ForEachMacros:
+  - '__ata_qc_for_each'
+  - '__bio_for_each_bvec'
+  - '__bio_for_each_segment'
+  - '__evlist__for_each_entry'
+  - '__evlist__for_each_entry_continue'
+  - '__evlist__for_each_entry_from'
+  - '__evlist__for_each_entry_reverse'
+  - '__evlist__for_each_entry_safe'
+  - '__for_each_mem_range'
+  - '__for_each_mem_range_rev'
+  - '__for_each_thread'
+  - '__hlist_for_each_rcu'
+  - '__map__for_each_symbol_by_name'
+  - '__pci_bus_for_each_res0'
+  - '__pci_bus_for_each_res1'
+  - '__pci_dev_for_each_res0'
+  - '__pci_dev_for_each_res1'
+  - '__perf_evlist__for_each_entry'
+  - '__perf_evlist__for_each_entry_reverse'
+  - '__perf_evlist__for_each_entry_safe'
+  - '__rq_for_each_bio'
+  - '__shost_for_each_device'
+  - '__sym_for_each'
+  - 'apei_estatus_for_each_section'
+  - 'ata_for_each_dev'
+  - 'ata_for_each_link'
+  - 'ata_qc_for_each'
+  - 'ata_qc_for_each_raw'
+  - 'ata_qc_for_each_with_internal'
+  - 'ax25_for_each'
+  - 'ax25_uid_for_each'
+  - 'bio_for_each_bvec'
+  - 'bio_for_each_bvec_all'
+  - 'bio_for_each_folio_all'
+  - 'bio_for_each_integrity_vec'
+  - 'bio_for_each_segment'
+  - 'bio_for_each_segment_all'
+  - 'bio_list_for_each'
+  - 'bip_for_each_vec'
+  - 'bond_for_each_slave'
+  - 'bond_for_each_slave_rcu'
+  - 'bpf_for_each'
+  - 'bpf_for_each_reg_in_vstate'
+  - 'bpf_for_each_reg_in_vstate_mask'
+  - 'bpf_for_each_spilled_reg'
+  - 'bpf_object__for_each_map'
+  - 'bpf_object__for_each_program'
+  - 'btree_for_each_safe128'
+  - 'btree_for_each_safe32'
+  - 'btree_for_each_safe64'
+  - 'btree_for_each_safel'
+  - 'card_for_each_dev'
+  - 'cgroup_taskset_for_each'
+  - 'cgroup_taskset_for_each_leader'
+  - 'cpu_aggr_map__for_each_idx'
+  - 'cpufreq_for_each_efficient_entry_idx'
+  - 'cpufreq_for_each_entry'
+  - 'cpufreq_for_each_entry_idx'
+  - 'cpufreq_for_each_valid_entry'
+  - 'cpufreq_for_each_valid_entry_idx'
+  - 'css_for_each_child'
+  - 'css_for_each_descendant_post'
+  - 'css_for_each_descendant_pre'
+  - 'damon_for_each_region'
+  - 'damon_for_each_region_from'
+  - 'damon_for_each_region_safe'
+  - 'damon_for_each_scheme'
+  - 'damon_for_each_scheme_safe'
+  - 'damon_for_each_target'
+  - 'damon_for_each_target_safe'
+  - 'damos_for_each_filter'
+  - 'damos_for_each_filter_safe'
+  - 'data__for_each_file'
+  - 'data__for_each_file_new'
+  - 'data__for_each_file_start'
+  - 'device_for_each_child_node'
+  - 'displayid_iter_for_each'
+  - 'dma_fence_array_for_each'
+  - 'dma_fence_chain_for_each'
+  - 'dma_fence_unwrap_for_each'
+  - 'dma_resv_for_each_fence'
+  - 'dma_resv_for_each_fence_unlocked'
+  - 'do_for_each_ftrace_op'
+  - 'drm_atomic_crtc_for_each_plane'
+  - 'drm_atomic_crtc_state_for_each_plane'
+  - 'drm_atomic_crtc_state_for_each_plane_state'
+  - 'drm_atomic_for_each_plane_damage'
+  - 'drm_client_for_each_connector_iter'
+  - 'drm_client_for_each_modeset'
+  - 'drm_connector_for_each_possible_encoder'
+  - 'drm_exec_for_each_locked_object'
+  - 'drm_exec_for_each_locked_object_reverse'
+  - 'drm_for_each_bridge_in_chain'
+  - 'drm_for_each_connector_iter'
+  - 'drm_for_each_crtc'
+  - 'drm_for_each_crtc_reverse'
+  - 'drm_for_each_encoder'
+  - 'drm_for_each_encoder_mask'
+  - 'drm_for_each_fb'
+  - 'drm_for_each_legacy_plane'
+  - 'drm_for_each_plane'
+  - 'drm_for_each_plane_mask'
+  - 'drm_for_each_privobj'
+  - 'drm_gem_for_each_gpuva'
+  - 'drm_gem_for_each_gpuva_safe'
+  - 'drm_gpuva_for_each_op'
+  - 'drm_gpuva_for_each_op_from_reverse'
+  - 'drm_gpuva_for_each_op_safe'
+  - 'drm_gpuvm_for_each_va'
+  - 'drm_gpuvm_for_each_va_range'
+  - 'drm_gpuvm_for_each_va_range_safe'
+  - 'drm_gpuvm_for_each_va_safe'
+  - 'drm_mm_for_each_hole'
+  - 'drm_mm_for_each_node'
+  - 'drm_mm_for_each_node_in_range'
+  - 'drm_mm_for_each_node_safe'
+  - 'dsa_switch_for_each_available_port'
+  - 'dsa_switch_for_each_cpu_port'
+  - 'dsa_switch_for_each_cpu_port_continue_reverse'
+  - 'dsa_switch_for_each_port'
+  - 'dsa_switch_for_each_port_continue_reverse'
+  - 'dsa_switch_for_each_port_safe'
+  - 'dsa_switch_for_each_user_port'
+  - 'dsa_tree_for_each_cpu_port'
+  - 'dsa_tree_for_each_user_port'
+  - 'dsa_tree_for_each_user_port_continue_reverse'
+  - 'dso__for_each_symbol'
+  - 'dsos__for_each_with_build_id'
+  - 'elf_hash_for_each_possible'
+  - 'elf_symtab__for_each_symbol'
+  - 'evlist__for_each_cpu'
+  - 'evlist__for_each_entry'
+  - 'evlist__for_each_entry_continue'
+  - 'evlist__for_each_entry_from'
+  - 'evlist__for_each_entry_reverse'
+  - 'evlist__for_each_entry_safe'
+  - 'flow_action_for_each'
+  - 'for_each_acpi_consumer_dev'
+  - 'for_each_acpi_dev_match'
+  - 'for_each_active_dev_scope'
+  - 'for_each_active_drhd_unit'
+  - 'for_each_active_iommu'
+  - 'for_each_active_route'
+  - 'for_each_aggr_pgid'
+  - 'for_each_and_bit'
+  - 'for_each_andnot_bit'
+  - 'for_each_available_child_of_node'
+  - 'for_each_bench'
+  - 'for_each_bio'
+  - 'for_each_board_func_rsrc'
+  - 'for_each_btf_ext_rec'
+  - 'for_each_btf_ext_sec'
+  - 'for_each_bvec'
+  - 'for_each_card_auxs'
+  - 'for_each_card_auxs_safe'
+  - 'for_each_card_components'
+  - 'for_each_card_dapms'
+  - 'for_each_card_pre_auxs'
+  - 'for_each_card_prelinks'
+  - 'for_each_card_rtds'
+  - 'for_each_card_rtds_safe'
+  - 'for_each_card_widgets'
+  - 'for_each_card_widgets_safe'
+  - 'for_each_cgroup_storage_type'
+  - 'for_each_child_of_node'
+  - 'for_each_clear_bit'
+  - 'for_each_clear_bit_from'
+  - 'for_each_clear_bitrange'
+  - 'for_each_clear_bitrange_from'
+  - 'for_each_cmd'
+  - 'for_each_cmsghdr'
+  - 'for_each_collection'
+  - 'for_each_comp_order'
+  - 'for_each_compatible_node'
+  - 'for_each_component_dais'
+  - 'for_each_component_dais_safe'
+  - 'for_each_conduit'
+  - 'for_each_console'
+  - 'for_each_console_srcu'
+  - 'for_each_cpu'
+  - 'for_each_cpu_and'
+  - 'for_each_cpu_andnot'
+  - 'for_each_cpu_or'
+  - 'for_each_cpu_wrap'
+  - 'for_each_dapm_widgets'
+  - 'for_each_dedup_cand'
+  - 'for_each_dev_addr'
+  - 'for_each_dev_scope'
+  - 'for_each_dma_cap_mask'
+  - 'for_each_dpcm_be'
+  - 'for_each_dpcm_be_rollback'
+  - 'for_each_dpcm_be_safe'
+  - 'for_each_dpcm_fe'
+  - 'for_each_drhd_unit'
+  - 'for_each_dss_dev'
+  - 'for_each_efi_memory_desc'
+  - 'for_each_efi_memory_desc_in_map'
+  - 'for_each_element'
+  - 'for_each_element_extid'
+  - 'for_each_element_id'
+  - 'for_each_endpoint_of_node'
+  - 'for_each_event'
+  - 'for_each_event_tps'
+  - 'for_each_evictable_lru'
+  - 'for_each_fib6_node_rt_rcu'
+  - 'for_each_fib6_walker_rt'
+  - 'for_each_free_mem_pfn_range_in_zone'
+  - 'for_each_free_mem_pfn_range_in_zone_from'
+  - 'for_each_free_mem_range'
+  - 'for_each_free_mem_range_reverse'
+  - 'for_each_func_rsrc'
+  - 'for_each_gpiochip_node'
+  - 'for_each_group_evsel'
+  - 'for_each_group_evsel_head'
+  - 'for_each_group_member'
+  - 'for_each_group_member_head'
+  - 'for_each_hstate'
+  - 'for_each_if'
+  - 'for_each_inject_fn'
+  - 'for_each_insn'
+  - 'for_each_insn_prefix'
+  - 'for_each_intid'
+  - 'for_each_iommu'
+  - 'for_each_ip_tunnel_rcu'
+  - 'for_each_irq_nr'
+  - 'for_each_lang'
+  - 'for_each_link_codecs'
+  - 'for_each_link_cpus'
+  - 'for_each_link_platforms'
+  - 'for_each_lru'
+  - 'for_each_matching_node'
+  - 'for_each_matching_node_and_match'
+  - 'for_each_media_entity_data_link'
+  - 'for_each_mem_pfn_range'
+  - 'for_each_mem_range'
+  - 'for_each_mem_range_rev'
+  - 'for_each_mem_region'
+  - 'for_each_member'
+  - 'for_each_memory'
+  - 'for_each_migratetype_order'
+  - 'for_each_missing_reg'
+  - 'for_each_mle_subelement'
+  - 'for_each_mod_mem_type'
+  - 'for_each_net'
+  - 'for_each_net_continue_reverse'
+  - 'for_each_net_rcu'
+  - 'for_each_netdev'
+  - 'for_each_netdev_continue'
+  - 'for_each_netdev_continue_rcu'
+  - 'for_each_netdev_continue_reverse'
+  - 'for_each_netdev_dump'
+  - 'for_each_netdev_feature'
+  - 'for_each_netdev_in_bond_rcu'
+  - 'for_each_netdev_rcu'
+  - 'for_each_netdev_reverse'
+  - 'for_each_netdev_safe'
+  - 'for_each_new_connector_in_state'
+  - 'for_each_new_crtc_in_state'
+  - 'for_each_new_mst_mgr_in_state'
+  - 'for_each_new_plane_in_state'
+  - 'for_each_new_plane_in_state_reverse'
+  - 'for_each_new_private_obj_in_state'
+  - 'for_each_new_reg'
+  - 'for_each_node'
+  - 'for_each_node_by_name'
+  - 'for_each_node_by_type'
+  - 'for_each_node_mask'
+  - 'for_each_node_state'
+  - 'for_each_node_with_cpus'
+  - 'for_each_node_with_property'
+  - 'for_each_nonreserved_multicast_dest_pgid'
+  - 'for_each_numa_hop_mask'
+  - 'for_each_of_allnodes'
+  - 'for_each_of_allnodes_from'
+  - 'for_each_of_cpu_node'
+  - 'for_each_of_pci_range'
+  - 'for_each_old_connector_in_state'
+  - 'for_each_old_crtc_in_state'
+  - 'for_each_old_mst_mgr_in_state'
+  - 'for_each_old_plane_in_state'
+  - 'for_each_old_private_obj_in_state'
+  - 'for_each_oldnew_connector_in_state'
+  - 'for_each_oldnew_crtc_in_state'
+  - 'for_each_oldnew_mst_mgr_in_state'
+  - 'for_each_oldnew_plane_in_state'
+  - 'for_each_oldnew_plane_in_state_reverse'
+  - 'for_each_oldnew_private_obj_in_state'
+  - 'for_each_online_cpu'
+  - 'for_each_online_node'
+  - 'for_each_online_pgdat'
+  - 'for_each_or_bit'
+  - 'for_each_path'
+  - 'for_each_pci_bridge'
+  - 'for_each_pci_dev'
+  - 'for_each_pcm_streams'
+  - 'for_each_physmem_range'
+  - 'for_each_populated_zone'
+  - 'for_each_possible_cpu'
+  - 'for_each_present_blessed_reg'
+  - 'for_each_present_cpu'
+  - 'for_each_prime_number'
+  - 'for_each_prime_number_from'
+  - 'for_each_probe_cache_entry'
+  - 'for_each_process'
+  - 'for_each_process_thread'
+  - 'for_each_prop_codec_conf'
+  - 'for_each_prop_dai_codec'
+  - 'for_each_prop_dai_cpu'
+  - 'for_each_prop_dlc_codecs'
+  - 'for_each_prop_dlc_cpus'
+  - 'for_each_prop_dlc_platforms'
+  - 'for_each_property_of_node'
+  - 'for_each_reg'
+  - 'for_each_reg_filtered'
+  - 'for_each_reloc'
+  - 'for_each_reloc_from'
+  - 'for_each_requested_gpio'
+  - 'for_each_requested_gpio_in_range'
+  - 'for_each_reserved_mem_range'
+  - 'for_each_reserved_mem_region'
+  - 'for_each_rtd_codec_dais'
+  - 'for_each_rtd_components'
+  - 'for_each_rtd_cpu_dais'
+  - 'for_each_rtd_dais'
+  - 'for_each_sband_iftype_data'
+  - 'for_each_script'
+  - 'for_each_sec'
+  - 'for_each_set_bit'
+  - 'for_each_set_bit_from'
+  - 'for_each_set_bit_wrap'
+  - 'for_each_set_bitrange'
+  - 'for_each_set_bitrange_from'
+  - 'for_each_set_clump8'
+  - 'for_each_sg'
+  - 'for_each_sg_dma_page'
+  - 'for_each_sg_page'
+  - 'for_each_sgtable_dma_page'
+  - 'for_each_sgtable_dma_sg'
+  - 'for_each_sgtable_page'
+  - 'for_each_sgtable_sg'
+  - 'for_each_sibling_event'
+  - 'for_each_sta_active_link'
+  - 'for_each_subelement'
+  - 'for_each_subelement_extid'
+  - 'for_each_subelement_id'
+  - 'for_each_sublist'
+  - 'for_each_subsystem'
+  - 'for_each_supported_activate_fn'
+  - 'for_each_supported_inject_fn'
+  - 'for_each_sym'
+  - 'for_each_test'
+  - 'for_each_thread'
+  - 'for_each_token'
+  - 'for_each_unicast_dest_pgid'
+  - 'for_each_valid_link'
+  - 'for_each_vif_active_link'
+  - 'for_each_vma'
+  - 'for_each_vma_range'
+  - 'for_each_vsi'
+  - 'for_each_wakeup_source'
+  - 'for_each_zone'
+  - 'for_each_zone_zonelist'
+  - 'for_each_zone_zonelist_nodemask'
+  - 'func_for_each_insn'
+  - 'fwnode_for_each_available_child_node'
+  - 'fwnode_for_each_child_node'
+  - 'fwnode_for_each_parent_node'
+  - 'fwnode_graph_for_each_endpoint'
+  - 'gadget_for_each_ep'
+  - 'genradix_for_each'
+  - 'genradix_for_each_from'
+  - 'genradix_for_each_reverse'
+  - 'hash_for_each'
+  - 'hash_for_each_possible'
+  - 'hash_for_each_possible_rcu'
+  - 'hash_for_each_possible_rcu_notrace'
+  - 'hash_for_each_possible_safe'
+  - 'hash_for_each_rcu'
+  - 'hash_for_each_safe'
+  - 'hashmap__for_each_entry'
+  - 'hashmap__for_each_entry_safe'
+  - 'hashmap__for_each_key_entry'
+  - 'hashmap__for_each_key_entry_safe'
+  - 'hctx_for_each_ctx'
+  - 'hists__for_each_format'
+  - 'hists__for_each_sort_list'
+  - 'hlist_bl_for_each_entry'
+  - 'hlist_bl_for_each_entry_rcu'
+  - 'hlist_bl_for_each_entry_safe'
+  - 'hlist_for_each'
+  - 'hlist_for_each_entry'
+  - 'hlist_for_each_entry_continue'
+  - 'hlist_for_each_entry_continue_rcu'
+  - 'hlist_for_each_entry_continue_rcu_bh'
+  - 'hlist_for_each_entry_from'
+  - 'hlist_for_each_entry_from_rcu'
+  - 'hlist_for_each_entry_rcu'
+  - 'hlist_for_each_entry_rcu_bh'
+  - 'hlist_for_each_entry_rcu_notrace'
+  - 'hlist_for_each_entry_safe'
+  - 'hlist_for_each_entry_srcu'
+  - 'hlist_for_each_safe'
+  - 'hlist_nulls_for_each_entry'
+  - 'hlist_nulls_for_each_entry_from'
+  - 'hlist_nulls_for_each_entry_rcu'
+  - 'hlist_nulls_for_each_entry_safe'
+  - 'i3c_bus_for_each_i2cdev'
+  - 'i3c_bus_for_each_i3cdev'
+  - 'idr_for_each_entry'
+  - 'idr_for_each_entry_continue'
+  - 'idr_for_each_entry_continue_ul'
+  - 'idr_for_each_entry_ul'
+  - 'in_dev_for_each_ifa_rcu'
+  - 'in_dev_for_each_ifa_rtnl'
+  - 'inet_bind_bucket_for_each'
+  - 'interval_tree_for_each_span'
+  - 'intlist__for_each_entry'
+  - 'intlist__for_each_entry_safe'
+  - 'kcore_copy__for_each_phdr'
+  - 'key_for_each'
+  - 'key_for_each_safe'
+  - 'klp_for_each_func'
+  - 'klp_for_each_func_safe'
+  - 'klp_for_each_func_static'
+  - 'klp_for_each_object'
+  - 'klp_for_each_object_safe'
+  - 'klp_for_each_object_static'
+  - 'kunit_suite_for_each_test_case'
+  - 'kvm_for_each_memslot'
+  - 'kvm_for_each_memslot_in_gfn_range'
+  - 'kvm_for_each_vcpu'
+  - 'libbpf_nla_for_each_attr'
+  - 'list_for_each'
+  - 'list_for_each_codec'
+  - 'list_for_each_codec_safe'
+  - 'list_for_each_continue'
+  - 'list_for_each_entry'
+  - 'list_for_each_entry_continue'
+  - 'list_for_each_entry_continue_rcu'
+  - 'list_for_each_entry_continue_reverse'
+  - 'list_for_each_entry_from'
+  - 'list_for_each_entry_from_rcu'
+  - 'list_for_each_entry_from_reverse'
+  - 'list_for_each_entry_lockless'
+  - 'list_for_each_entry_rcu'
+  - 'list_for_each_entry_reverse'
+  - 'list_for_each_entry_safe'
+  - 'list_for_each_entry_safe_continue'
+  - 'list_for_each_entry_safe_from'
+  - 'list_for_each_entry_safe_reverse'
+  - 'list_for_each_entry_srcu'
+  - 'list_for_each_from'
+  - 'list_for_each_prev'
+  - 'list_for_each_prev_safe'
+  - 'list_for_each_rcu'
+  - 'list_for_each_reverse'
+  - 'list_for_each_safe'
+  - 'llist_for_each'
+  - 'llist_for_each_entry'
+  - 'llist_for_each_entry_safe'
+  - 'llist_for_each_safe'
+  - 'lwq_for_each_safe'
+  - 'map__for_each_symbol'
+  - 'map__for_each_symbol_by_name'
+  - 'maps__for_each_entry'
+  - 'maps__for_each_entry_safe'
+  - 'mas_for_each'
+  - 'mci_for_each_dimm'
+  - 'media_device_for_each_entity'
+  - 'media_device_for_each_intf'
+  - 'media_device_for_each_link'
+  - 'media_device_for_each_pad'
+  - 'media_entity_for_each_pad'
+  - 'media_pipeline_for_each_entity'
+  - 'media_pipeline_for_each_pad'
+  - 'mlx5_lag_for_each_peer_mdev'
+  - 'msi_domain_for_each_desc'
+  - 'msi_for_each_desc'
+  - 'mt_for_each'
+  - 'nanddev_io_for_each_page'
+  - 'netdev_for_each_lower_dev'
+  - 'netdev_for_each_lower_private'
+  - 'netdev_for_each_lower_private_rcu'
+  - 'netdev_for_each_mc_addr'
+  - 'netdev_for_each_synced_mc_addr'
+  - 'netdev_for_each_synced_uc_addr'
+  - 'netdev_for_each_uc_addr'
+  - 'netdev_for_each_upper_dev_rcu'
+  - 'netdev_hw_addr_list_for_each'
+  - 'nft_rule_for_each_expr'
+  - 'nla_for_each_attr'
+  - 'nla_for_each_nested'
+  - 'nlmsg_for_each_attr'
+  - 'nlmsg_for_each_msg'
+  - 'nr_neigh_for_each'
+  - 'nr_neigh_for_each_safe'
+  - 'nr_node_for_each'
+  - 'nr_node_for_each_safe'
+  - 'of_for_each_phandle'
+  - 'of_property_for_each_string'
+  - 'of_property_for_each_u32'
+  - 'pci_bus_for_each_resource'
+  - 'pci_dev_for_each_resource'
+  - 'pcl_for_each_chunk'
+  - 'pcl_for_each_segment'
+  - 'pcm_for_each_format'
+  - 'perf_config_items__for_each_entry'
+  - 'perf_config_sections__for_each_entry'
+  - 'perf_config_set__for_each_entry'
+  - 'perf_cpu_map__for_each_cpu'
+  - 'perf_cpu_map__for_each_idx'
+  - 'perf_evlist__for_each_entry'
+  - 'perf_evlist__for_each_entry_reverse'
+  - 'perf_evlist__for_each_entry_safe'
+  - 'perf_evlist__for_each_evsel'
+  - 'perf_evlist__for_each_mmap'
+  - 'perf_hpp_list__for_each_format'
+  - 'perf_hpp_list__for_each_format_safe'
+  - 'perf_hpp_list__for_each_sort_list'
+  - 'perf_hpp_list__for_each_sort_list_safe'
+  - 'perf_tool_event__for_each_event'
+  - 'plist_for_each'
+  - 'plist_for_each_continue'
+  - 'plist_for_each_entry'
+  - 'plist_for_each_entry_continue'
+  - 'plist_for_each_entry_safe'
+  - 'plist_for_each_safe'
+  - 'pnp_for_each_card'
+  - 'pnp_for_each_dev'
+  - 'protocol_for_each_card'
+  - 'protocol_for_each_dev'
+  - 'queue_for_each_hw_ctx'
+  - 'radix_tree_for_each_slot'
+  - 'radix_tree_for_each_tagged'
+  - 'rb_for_each'
+  - 'rbtree_postorder_for_each_entry_safe'
+  - 'rdma_for_each_block'
+  - 'rdma_for_each_port'
+  - 'rdma_umem_for_each_dma_block'
+  - 'resort_rb__for_each_entry'
+  - 'resource_list_for_each_entry'
+  - 'resource_list_for_each_entry_safe'
+  - 'rhl_for_each_entry_rcu'
+  - 'rhl_for_each_rcu'
+  - 'rht_for_each'
+  - 'rht_for_each_entry'
+  - 'rht_for_each_entry_from'
+  - 'rht_for_each_entry_rcu'
+  - 'rht_for_each_entry_rcu_from'
+  - 'rht_for_each_entry_safe'
+  - 'rht_for_each_from'
+  - 'rht_for_each_rcu'
+  - 'rht_for_each_rcu_from'
+  - 'rq_for_each_bvec'
+  - 'rq_for_each_segment'
+  - 'rq_list_for_each'
+  - 'rq_list_for_each_safe'
+  - 'sample_read_group__for_each'
+  - 'scsi_for_each_prot_sg'
+  - 'scsi_for_each_sg'
+  - 'sctp_for_each_hentry'
+  - 'sctp_skb_for_each'
+  - 'sec_for_each_insn'
+  - 'sec_for_each_insn_continue'
+  - 'sec_for_each_insn_from'
+  - 'sec_for_each_sym'
+  - 'shdma_for_each_chan'
+  - 'shost_for_each_device'
+  - 'sk_for_each'
+  - 'sk_for_each_bound'
+  - 'sk_for_each_bound_bhash2'
+  - 'sk_for_each_entry_offset_rcu'
+  - 'sk_for_each_from'
+  - 'sk_for_each_rcu'
+  - 'sk_for_each_safe'
+  - 'sk_nulls_for_each'
+  - 'sk_nulls_for_each_from'
+  - 'sk_nulls_for_each_rcu'
+  - 'snd_array_for_each'
+  - 'snd_pcm_group_for_each_entry'
+  - 'snd_soc_dapm_widget_for_each_path'
+  - 'snd_soc_dapm_widget_for_each_path_safe'
+  - 'snd_soc_dapm_widget_for_each_sink_path'
+  - 'snd_soc_dapm_widget_for_each_source_path'
+  - 'strlist__for_each_entry'
+  - 'strlist__for_each_entry_safe'
+  - 'sym_for_each_insn'
+  - 'sym_for_each_insn_continue_reverse'
+  - 'symbols__for_each_entry'
+  - 'tb_property_for_each'
+  - 'tcf_act_for_each_action'
+  - 'tcf_exts_for_each_action'
+  - 'ttm_resource_manager_for_each_res'
+  - 'twsk_for_each_bound_bhash2'
+  - 'udp_portaddr_for_each_entry'
+  - 'udp_portaddr_for_each_entry_rcu'
+  - 'usb_hub_for_each_child'
+  - 'v4l2_device_for_each_subdev'
+  - 'v4l2_m2m_for_each_dst_buf'
+  - 'v4l2_m2m_for_each_dst_buf_safe'
+  - 'v4l2_m2m_for_each_src_buf'
+  - 'v4l2_m2m_for_each_src_buf_safe'
+  - 'virtio_device_for_each_vq'
+  - 'while_for_each_ftrace_op'
+  - 'xa_for_each'
+  - 'xa_for_each_marked'
+  - 'xa_for_each_range'
+  - 'xa_for_each_start'
+  - 'xas_for_each'
+  - 'xas_for_each_conflict'
+  - 'xas_for_each_marked'
+  - 'xbc_array_for_each_value'
+  - 'xbc_for_each_key_value'
+  - 'xbc_node_for_each_array_value'
+  - 'xbc_node_for_each_child'
+  - 'xbc_node_for_each_key_value'
+  - 'xbc_node_for_each_subkey'
+  - 'zorro_for_each_dev'
+
+IncludeBlocks: Preserve
+IncludeCategories:
+  - Regex: '.*'
+    Priority: 1
+IncludeIsMainRegex: '(Test)?$'
+IndentCaseLabels: false
+IndentGotoLabels: false
+IndentPPDirectives: None
+IndentWidth: 8
+IndentWrappedFunctionNames: false
+JavaScriptQuotes: Leave
+JavaScriptWrapImports: true
+KeepEmptyLinesAtTheStartOfBlocks: false
+MacroBlockBegin: ''
+MacroBlockEnd: ''
+MaxEmptyLinesToKeep: 1
+NamespaceIndentation: None
+ObjCBinPackProtocolList: Auto
+ObjCBlockIndentWidth: 8
+ObjCSpaceAfterProperty: true
+ObjCSpaceBeforeProtocolList: true
+
+# Taken from git's rules
+PenaltyBreakAssignment: 10
+PenaltyBreakBeforeFirstCallParameter: 30
+PenaltyBreakComment: 10
+PenaltyBreakFirstLessLess: 0
+PenaltyBreakString: 10
+PenaltyExcessCharacter: 100
+PenaltyReturnTypeOnItsOwnLine: 60
+
+PointerAlignment: Right
+ReflowComments: false
+SortIncludes: false
+SortUsingDeclarations: false
+SpaceAfterCStyleCast: false
+SpaceAfterTemplateKeyword: true
+SpaceBeforeAssignmentOperators: true
+SpaceBeforeCtorInitializerColon: true
+SpaceBeforeInheritanceColon: true
+SpaceBeforeParens: ControlStatementsExceptForEachMacros
+SpaceBeforeRangeBasedForLoopColon: true
+SpaceInEmptyParentheses: false
+SpacesBeforeTrailingComments: 1
+SpacesInAngles: false
+SpacesInContainerLiterals: false
+SpacesInCStyleCastParentheses: false
+SpacesInParentheses: false
+SpacesInSquareBrackets: false
+Standard: Cpp03
+TabWidth: 8
+UseTab: Always
+...
diff --git a/driver/.editorconfig b/driver/.editorconfig
new file mode 100644
index 0000000..29a30cc
--- /dev/null
+++ b/driver/.editorconfig
@@ -0,0 +1,29 @@
+# SPDX-License-Identifier: GPL-2.0-only
+
+root = true
+
+[{*.{awk,c,dts,dtsi,dtso,h,mk,s,S},Kconfig,Makefile,Makefile.*}]
+charset = utf-8
+end_of_line = lf
+insert_final_newline = true
+indent_style = tab
+indent_size = 8
+
+[*.{json,py,rs}]
+charset = utf-8
+end_of_line = lf
+insert_final_newline = true
+indent_style = space
+indent_size = 4
+
+# this must be below the general *.py to overwrite it
+[tools/{perf,power,rcu,testing/kunit}/**.py,]
+indent_style = tab
+indent_size = 8
+
+[*.yaml]
+charset = utf-8
+end_of_line = lf
+insert_final_newline = true
+indent_style = space
+indent_size = 2
diff --git a/driver/protocol.h b/driver/protocol.h
index f476f83..750cb1f 100644
--- a/driver/protocol.h
+++ b/driver/protocol.h
@@ -19,7 +19,7 @@
  * struct virtio_media_cmd_header - Header for all virtio commands from the driver to the device on the commandq.
  *
  * @cmd: one of VIRTIO_MEDIA_CMD_*.
- * @__padding: must be set to zero by the guest.
+ * @__padding: must be set to zero by the driver.
  */
 struct virtio_media_cmd_header {
 	u32 cmd;
@@ -143,7 +143,7 @@ struct virtio_media_resp_ioctl {
 #define VIRTIO_MEDIA_MMAP_FLAG_RW (1 << 0)
 
 /**
- * VIRTIO_MEDIA_CMD_MMAP - Command for mapping a MMAP buffer into the guest's address space.
+ * VIRTIO_MEDIA_CMD_MMAP - Command for mapping a MMAP buffer into the driver's address space.
  *
  */
 #define VIRTIO_MEDIA_CMD_MMAP 4
@@ -162,12 +162,12 @@ struct virtio_media_cmd_mmap {
  * struct virtio_media_resp_mmap - Device response for VIRTIO_MEDIA_CMD_MMAP.
  *
  * @hdr: header containing the status of the command.
- * @guest_addr: offset into SHM region 0 of the start of the mapping.
+ * @driver_addr: offset into SHM region 0 of the start of the mapping.
  * @len: length of the mapping.
  */
 struct virtio_media_resp_mmap {
 	struct virtio_media_resp_header hdr;
-	u64 guest_addr;
+	u64 driver_addr;
 	u64 len;
 };
 
@@ -179,12 +179,12 @@ struct virtio_media_resp_mmap {
 /**
  * struct virtio_media_cmd_munmap - Driver command for VIRTIO_MEDIA_CMD_MUNMAP.
  *
- * @guest_addr: offset into SHM region 0 at which the buffer has been previously
+ * @driver_addr: offset into SHM region 0 at which the buffer has been previously
  * mapped.
  */
 struct virtio_media_cmd_munmap {
 	struct virtio_media_cmd_header hdr;
-	u64 guest_addr;
+	u64 driver_addr;
 };
 
 /**
diff --git a/driver/virtio_media_driver.c b/driver/virtio_media_driver.c
index 512297f..3ab7013 100644
--- a/driver/virtio_media_driver.c
+++ b/driver/virtio_media_driver.c
@@ -16,10 +16,6 @@
 #include <linux/vmalloc.h>
 #include <linux/wait.h>
 #include <linux/workqueue.h>
-#include <media/frame_vector.h>
-#include <media/v4l2-dev.h>
-#include <media/v4l2-event.h>
-#include <media/videobuf2-memops.h>
 #include <linux/module.h>
 #include <linux/moduleparam.h>
 #include <linux/version.h>
@@ -27,6 +23,10 @@
 #include <linux/virtio_config.h>
 #include <linux/virtio_ids.h>
 
+#include <media/frame_vector.h>
+#include <media/v4l2-dev.h>
+#include <media/v4l2-event.h>
+#include <media/videobuf2-memops.h>
 #include <media/v4l2-device.h>
 #include <media/v4l2-ioctl.h>
 
@@ -37,7 +37,7 @@
 #define VIRTIO_MEDIA_NUM_EVENT_BUFS 16
 
 #ifndef VIRTIO_ID_MEDIA
-#define VIRTIO_ID_MEDIA 49
+#define VIRTIO_ID_MEDIA 48
 #endif
 
 /* ID of the SHM region into which MMAP buffer will be mapped. */
@@ -622,7 +622,7 @@ static void virtio_media_vma_close_locked(struct vm_area_struct *vma)
 
 	mutex_lock(&vv->bufs_lock);
 	cmd_munmap->hdr.cmd = VIRTIO_MEDIA_CMD_MUNMAP;
-	cmd_munmap->guest_addr =
+	cmd_munmap->driver_addr =
 		(vma->vm_pgoff << PAGE_SHIFT) - vv->mmap_region.addr;
 	ret = virtio_media_send_command(vv, sgs, 1, 1, sizeof(*resp_munmap),
 					NULL);
@@ -699,7 +699,7 @@ static int virtio_media_device_mmap(struct file *file,
 	 * Keep the guest address at which the buffer is mapped since we will
 	 * use that to unmap.
 	 */
-	vma->vm_pgoff = (resp_mmap->guest_addr + vv->mmap_region.addr) >>
+	vma->vm_pgoff = (resp_mmap->driver_addr + vv->mmap_region.addr) >>
 			PAGE_SHIFT;
 
 	if (vma->vm_end - vma->vm_start > PAGE_ALIGN(resp_mmap->len)) {
@@ -852,6 +852,7 @@ static void virtio_media_remove(struct virtio_device *virtio_dev)
 	struct virtio_media *vv = virtio_dev->priv;
 	struct list_head *p, *n;
 
+	cancel_work_sync(&vv->eventq_work);
 	virtio_reset_device(virtio_dev);
 
 	v4l2_device_unregister(&vv->v4l2_dev);
diff --git a/extras/ffmpeg-decoder/Cargo.lock b/extras/ffmpeg-decoder/Cargo.lock
index a8f6f20..f07f7bc 100644
--- a/extras/ffmpeg-decoder/Cargo.lock
+++ b/extras/ffmpeg-decoder/Cargo.lock
@@ -387,9 +387,9 @@ checksum = "3354b9ac3fae1ff6755cb6db53683adb661634f67557942dea4facebec0fee4b"
 
 [[package]]
 name = "v4l2r"
-version = "0.0.4"
+version = "0.0.5"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "4dbef75deba5f801229a648f72cffc2007befa7732fedfe05ca73ace030f597a"
+checksum = "fe1d612d2df2a0802020c49a1b029282c45991cdfff1731b5fc61ed3dce4168a"
 dependencies = [
  "anyhow",
  "bindgen 0.69.4",
@@ -402,7 +402,7 @@ dependencies = [
 
 [[package]]
 name = "virtio-media"
-version = "0.0.5"
+version = "0.0.6"
 dependencies = [
  "anyhow",
  "enumn",
@@ -416,7 +416,7 @@ dependencies = [
 
 [[package]]
 name = "virtio-media-ffmpeg-decoder"
-version = "0.0.5"
+version = "0.0.6"
 dependencies = [
  "anyhow",
  "bindgen 0.63.0",
diff --git a/extras/ffmpeg-decoder/Cargo.toml b/extras/ffmpeg-decoder/Cargo.toml
index 783e909..0e7e999 100644
--- a/extras/ffmpeg-decoder/Cargo.toml
+++ b/extras/ffmpeg-decoder/Cargo.toml
@@ -1,6 +1,6 @@
 [package]
 name = "virtio-media-ffmpeg-decoder"
-version = "0.0.5"
+version = "0.0.6"
 edition = "2021"
 
 [dependencies]
```

