```diff
diff --git a/lib/bindgen_gen.rs b/lib/bindgen_gen.rs
index 9a8fb8e..62dcd70 100644
--- a/lib/bindgen_gen.rs
+++ b/lib/bindgen_gen.rs
@@ -3,7 +3,7 @@
 // found in the LICENSE file.
 
 /// The allow list of VA functions, structures and enum values.
-const ALLOW_LIST_TYPE : &str = ".*ExternalBuffers.*|.*PRIME.*|.*MPEG2.*|.*VP8.*|.*VP9.*|.*H264.*|.*HEVC.*|VACodedBufferSegment|.*AV1.*|VAEncMisc.*|VASurfaceDecodeMBErrors|VADecodeErrorType";
+const ALLOW_LIST_TYPE : &str = ".*ExternalBuffers.*|.*PRIME.*|.*MPEG2.*|.*VP8.*|.*VP9.*|.*H264.*|.*HEVC.*|.*JPEGBaseline.*|VACodedBufferSegment|.*AV1.*|VAEncMisc.*|VASurfaceDecodeMBErrors|VADecodeErrorType";
 
 // The common bindgen builder for VA-API.
 pub fn vaapi_gen_builder(builder: bindgen::Builder) -> bindgen::Builder {
diff --git a/lib/src/buffer.rs b/lib/src/buffer.rs
index 0ab539b..5e3a373 100644
--- a/lib/src/buffer.rs
+++ b/lib/src/buffer.rs
@@ -8,6 +8,7 @@ mod av1;
 mod enc_misc;
 mod h264;
 mod hevc;
+mod jpeg_baseline;
 mod mpeg2;
 mod vp8;
 mod vp9;
@@ -86,6 +87,10 @@ impl Buffer {
                     wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                     std::mem::size_of_val(wrapper.inner_mut()),
                 ),
+                PictureParameter::JPEGBaseline(ref mut wrapper) => (
+                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
+                    std::mem::size_of_val(wrapper.inner_mut()),
+                ),
             },
 
             BufferType::SliceParameter(ref mut slice_param) => match slice_param {
@@ -117,6 +122,10 @@ impl Buffer {
                     wrapper.inner_mut().as_mut_ptr() as *mut std::ffi::c_void,
                     std::mem::size_of::<bindings::VASliceParameterBufferAV1>(),
                 ),
+                SliceParameter::JPEGBaseline(ref mut wrapper) => (
+                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
+                    std::mem::size_of_val(wrapper.inner_mut()),
+                ),
             },
 
             BufferType::IQMatrix(ref mut iq_matrix) => match iq_matrix {
@@ -136,6 +145,17 @@ impl Buffer {
                     wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                     std::mem::size_of_val(wrapper.inner_mut()),
                 ),
+                IQMatrix::JPEGBaseline(ref mut wrapper) => (
+                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
+                    std::mem::size_of_val(wrapper.inner_mut()),
+                ),
+            },
+
+            BufferType::HuffmanTable(ref mut huffman_table) => match huffman_table {
+                HuffmanTable::JPEGBaseline(ref mut wrapper) => (
+                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
+                    std::mem::size_of_val(wrapper.inner_mut()),
+                ),
             },
 
             BufferType::Probability(ref mut wrapper) => (
@@ -297,12 +317,14 @@ impl Drop for Buffer {
 
 /// Abstraction over `VABufferType`s.
 pub enum BufferType {
-    /// Abstraction over `VAPictureParameterBufferType`. Needed for MPEG2, VP8, VP9, H264.
+    /// Abstraction over `VAPictureParameterBufferType`. Needed for MPEG2, VP8, VP9, H264, JPEGBaseline.
     PictureParameter(PictureParameter),
-    /// Abstraction over `VASliceParameterBufferType`. Needed for MPEG2, VP8, VP9, H264.
+    /// Abstraction over `VASliceParameterBufferType`. Needed for MPEG2, VP8, VP9, H264, JPEGBaseline.
     SliceParameter(SliceParameter),
-    /// Abstraction over `VAIQMatrixBufferType`. Needed for VP8, H264.
+    /// Abstraction over `VAIQMatrixBufferType`. Needed for VP8, H264, JPEGBaseline.
     IQMatrix(IQMatrix),
+    /// Abstraction over `HuffmanTableBufferType`. Needed for JPEGBaseline.
+    HuffmanTable(HuffmanTable),
     /// Abstraction over `VAProbabilityDataBufferType`. Needed for VP8.
     Probability(vp8::ProbabilityDataBufferVP8),
     /// Abstraction over `VASliceDataBufferType`. Needed for VP9, H264.
@@ -328,6 +350,7 @@ impl BufferType {
             BufferType::PictureParameter(_) => bindings::VABufferType::VAPictureParameterBufferType,
             BufferType::SliceParameter(_) => bindings::VABufferType::VASliceParameterBufferType,
             BufferType::IQMatrix(_) => bindings::VABufferType::VAIQMatrixBufferType,
+            BufferType::HuffmanTable(_) => bindings::VABufferType::VAHuffmanTableBufferType,
             BufferType::Probability(_) => bindings::VABufferType::VAProbabilityBufferType,
             BufferType::SliceData { .. } => bindings::VABufferType::VASliceDataBufferType,
 
@@ -372,6 +395,8 @@ pub enum PictureParameter {
     HEVCScc(hevc::PictureParameterBufferHEVCScc),
     /// Wrapper over VADecPictureParameterBufferAV1
     AV1(av1::PictureParameterBufferAV1),
+    /// Wrapper over VAPictureParameterBufferJPEGBaseline
+    JPEGBaseline(jpeg_baseline::PictureParameterBufferJPEGBaseline),
 }
 
 /// Abstraction over the `SliceParameterBuffer` types we support
@@ -390,6 +415,8 @@ pub enum SliceParameter {
     HEVCRext(hevc::SliceParameterBufferHEVCRext),
     /// Wrapper over VASliceParameterBufferAV1
     AV1(av1::SliceParameterBufferAV1),
+    /// Wrapper over VASliceParameterBufferJPEGBaseline
+    JPEGBaseline(jpeg_baseline::SliceParameterBufferJPEGBaseline),
 }
 
 /// Abstraction over the `IQMatrixBuffer` types we support.
@@ -402,6 +429,14 @@ pub enum IQMatrix {
     H264(h264::IQMatrixBufferH264),
     /// Abstraction over `VAIQMatrixBufferHEVC`
     HEVC(hevc::IQMatrixBufferHEVC),
+    /// Abstraction over `VAIQMatrixBufferJPEGBaseline``
+    JPEGBaseline(jpeg_baseline::IQMatrixBufferJPEGBaseline),
+}
+
+/// Abstraction over the `HuffmanTable` types we support.
+pub enum HuffmanTable {
+    /// Abstraction over `VAHuffmanTableBufferJPEGBaseline`
+    JPEGBaseline(jpeg_baseline::HuffmanTableBufferJPEGBaseline),
 }
 
 /// Abstraction over the `EncSequenceParameter` types we support.
diff --git a/lib/src/buffer/jpeg_baseline.rs b/lib/src/buffer/jpeg_baseline.rs
new file mode 100644
index 0000000..76fa356
--- /dev/null
+++ b/lib/src/buffer/jpeg_baseline.rs
@@ -0,0 +1,214 @@
+// Copyright 2025 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+//! Wrappers around JPEGBaseline `VABuffer` types.
+
+use crate::bindings;
+
+/// Wrapper over the `components` bindgen field in `VAPictureParameterBufferJPEGBaseline`.
+pub struct PictureParameterBufferJPEGBaselineComponent(bindings::_VAPictureParameterBufferJPEGBaseline__bindgen_ty_1);
+
+impl PictureParameterBufferJPEGBaselineComponent {
+    /// Creates the bindgen field.
+    #[allow(clippy::too_many_arguments)]
+    pub fn new(
+        component_id: u8,
+        h_sampling_factor: u8,
+        v_sampling_factor: u8,
+        quantiser_table_selector: u8,
+    ) -> Self {
+        Self(bindings::_VAPictureParameterBufferJPEGBaseline__bindgen_ty_1 {
+            component_id,
+            h_sampling_factor,
+            v_sampling_factor,
+            quantiser_table_selector,
+        })
+    }
+
+    /// Returns the inner FFI type. Useful for testing purposes.
+    pub fn inner(&mut self) -> &bindings::_VAPictureParameterBufferJPEGBaseline__bindgen_ty_1 {
+        &self.0
+    }
+}
+
+/// Wrapper over the `VAPictureParameterBufferJPEGBaseline` FFI type.
+pub struct PictureParameterBufferJPEGBaseline(Box<bindings::VAPictureParameterBufferJPEGBaseline>);
+
+impl PictureParameterBufferJPEGBaseline {
+    /// Creates the wrapper.
+    pub fn new(
+        picture_width: u16,
+        picture_height: u16,
+        components: [PictureParameterBufferJPEGBaselineComponent; 255usize],
+        num_components: u8,
+        color_space: u8,
+        rotation: u32,
+        crop_rectangle: bindings::VARectangle,
+    ) -> Self {
+        Self(Box::new(bindings::VAPictureParameterBufferJPEGBaseline {
+            picture_width,
+            picture_height,
+            components: components.map(|component| component.0),
+            num_components,
+            color_space,
+            rotation,
+            crop_rectangle,
+            va_reserved: Default::default(),
+        }))
+    }
+
+    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VAPictureParameterBufferJPEGBaseline {
+        self.0.as_mut()
+    }
+
+    /// Returns the inner FFI type. Useful for testing purposes.
+    pub fn inner(&mut self) -> &bindings::VAPictureParameterBufferJPEGBaseline {
+        self.0.as_ref()
+    }
+}
+
+/// Wrapper over the `components` bindgen field in `VASliceParameterBufferJPEGBaseline`.
+pub struct VASliceParameterBufferJPEGBaselineComponent(bindings::_VASliceParameterBufferJPEGBaseline__bindgen_ty_1);
+
+impl VASliceParameterBufferJPEGBaselineComponent {
+    /// Creates the bindgen field.
+    #[allow(clippy::too_many_arguments)]
+    pub fn new(
+        component_selector: u8,
+        dc_table_selector: u8,
+        ac_table_selector: u8,
+    ) -> Self {
+        Self(bindings::_VASliceParameterBufferJPEGBaseline__bindgen_ty_1 {
+            component_selector,
+            dc_table_selector,
+            ac_table_selector,
+        })
+    }
+
+    /// Returns the inner FFI type. Useful for testing purposes.
+    pub fn inner(&mut self) -> &bindings::_VASliceParameterBufferJPEGBaseline__bindgen_ty_1 {
+        &self.0
+    }
+}
+
+/// Wrapper over the `VASliceParameterBufferJPEGBaseline` FFI type.
+pub struct SliceParameterBufferJPEGBaseline(Box<bindings::VASliceParameterBufferJPEGBaseline>);
+
+impl SliceParameterBufferJPEGBaseline {
+    /// Creates the wrapper.
+    pub fn new(
+        slice_data_size: u32,
+        slice_data_offset: u32,
+        slice_data_flag: u32,
+        slice_horizontal_position: u32,
+        slice_vertical_position: u32,
+        components: [VASliceParameterBufferJPEGBaselineComponent; 4usize],
+        num_components: u8,
+        restart_interval: u16,
+        num_mcus: u32,
+    ) -> Self {
+        Self(Box::new(bindings::VASliceParameterBufferJPEGBaseline {
+            slice_data_size,
+            slice_data_offset,
+            slice_data_flag,
+            slice_horizontal_position,
+            slice_vertical_position,
+            components: components.map(|component| component.0),
+            num_components,
+            restart_interval,
+            num_mcus,
+            va_reserved: Default::default(),
+        }))
+    }
+
+    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VASliceParameterBufferJPEGBaseline {
+        self.0.as_mut()
+    }
+
+    /// Returns the inner FFI type. Useful for testing purposes.
+    pub fn inner(&mut self) -> &bindings::VASliceParameterBufferJPEGBaseline {
+        self.0.as_ref()
+    }
+}
+
+/// Wrapper over the `VAIQMatrixBufferJPEGBaseline` FFI type.
+pub struct IQMatrixBufferJPEGBaseline(Box<bindings::VAIQMatrixBufferJPEGBaseline>);
+
+impl IQMatrixBufferJPEGBaseline {
+    /// Creates the wrapper.
+    #[allow(clippy::too_many_arguments)]
+    pub fn new(
+        load_quantiser_table: [u8; 4usize],
+        quantiser_table: [[u8; 64usize]; 4usize],
+    ) -> Self {
+        Self(Box::new(bindings::VAIQMatrixBufferJPEGBaseline {
+            load_quantiser_table,
+            quantiser_table,
+            va_reserved: Default::default(),
+        }))
+    }
+
+    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VAIQMatrixBufferJPEGBaseline {
+        self.0.as_mut()
+    }
+
+    /// Returns the inner FFI type. Useful for testing purposes.
+    pub fn inner(&self) -> &bindings::VAIQMatrixBufferJPEGBaseline {
+        self.0.as_ref()
+    }
+}
+
+/// Wrapper over the `huffman_table` bindgen field in `VAHuffmanTableBufferJPEGBaseline`.
+pub struct HuffmanTableBufferJPEGBaselineHuffmanTable(bindings::_VAHuffmanTableBufferJPEGBaseline__bindgen_ty_1);
+
+impl HuffmanTableBufferJPEGBaselineHuffmanTable {
+    /// Creates the bindgen field.
+    #[allow(clippy::too_many_arguments)]
+    pub fn new(
+        num_dc_codes: [u8; 16usize],
+        dc_values: [u8; 12usize],
+        num_ac_codes: [u8; 16usize],
+        ac_values: [u8; 162usize],
+        pad: [u8; 2usize],
+    ) -> Self {
+        Self(bindings::_VAHuffmanTableBufferJPEGBaseline__bindgen_ty_1 {
+            num_dc_codes,
+            dc_values,
+            num_ac_codes,
+            ac_values,
+            pad,
+        })
+    }
+
+    /// Returns the inner FFI type. Useful for testing purposes.
+    pub fn inner(&mut self) -> &bindings::_VAHuffmanTableBufferJPEGBaseline__bindgen_ty_1 {
+        &self.0
+    }
+}
+
+/// Wrapper over the `VAHuffmanTableBufferJPEGBaseline` FFI type.
+pub struct HuffmanTableBufferJPEGBaseline(Box<bindings::VAHuffmanTableBufferJPEGBaseline>);
+
+impl HuffmanTableBufferJPEGBaseline {
+    /// Creates the wrapper.
+    pub fn new(
+        load_huffman_table: [u8; 2usize],
+        huffman_table: [HuffmanTableBufferJPEGBaselineHuffmanTable; 2usize],
+    ) -> Self {
+        Self(Box::new(bindings::VAHuffmanTableBufferJPEGBaseline {
+            load_huffman_table,
+            huffman_table: huffman_table.map(|component| component.0),
+            va_reserved: Default::default(),
+        }))
+    }
+
+    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VAHuffmanTableBufferJPEGBaseline {
+        self.0.as_mut()
+    }
+
+    /// Returns the inner FFI type. Useful for testing purposes.
+    pub fn inner(&mut self) -> &bindings::VAHuffmanTableBufferJPEGBaseline {
+        self.0.as_ref()
+    }
+}
```

