```diff
diff --git a/Android.bp b/Android.bp
index cb02c0f..89ed4b3 100644
--- a/Android.bp
+++ b/Android.bp
@@ -23,11 +23,6 @@ cc_library_headers {
 
 python_defaults {
     name: "mkbootimg_defaults",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_binary_host {
diff --git a/gki/certify_bootimg_test.py b/gki/certify_bootimg_test.py
index 264aec6..4619d8c 100644
--- a/gki/certify_bootimg_test.py
+++ b/gki/certify_bootimg_test.py
@@ -196,7 +196,7 @@ def extract_boot_archive_with_signatures(boot_img_archive, output_dir):
       - |output_dir|/boot-lz4/boot_signature1
       - |output_dir|/boot-lz4/boot_signature2
     """
-    shutil.unpack_archive(boot_img_archive, output_dir)
+    shutil.unpack_archive(boot_img_archive, output_dir, filter='data')
     for boot_img in glob.glob(os.path.join(output_dir, 'boot*.img')):
         img_name = os.path.splitext(os.path.basename(boot_img))[0]
         signature_output_dir = os.path.join(output_dir, img_name)
diff --git a/gki/generate_gki_certificate.py b/gki/generate_gki_certificate.py
index 2797cca..739c61b 100755
--- a/gki/generate_gki_certificate.py
+++ b/gki/generate_gki_certificate.py
@@ -26,13 +26,10 @@ def generate_gki_certificate(image, avbtool, name, algorithm, key, salt,
                              additional_avb_args, output):
     """Shell out to avbtool to generate a GKI certificate."""
 
-    # Need to specify a value of --partition_size for avbtool to work.
-    # We use 64 MB below, but avbtool will not resize the boot image to
-    # this size because --do_not_append_vbmeta_image is also specified.
     avbtool_cmd = [
         avbtool, 'add_hash_footer',
         '--partition_name', name,
-        '--partition_size', str(64 * 1024 * 1024),
+        '--dynamic_partition_size',
         '--image', image,
         '--algorithm', algorithm,
         '--key', key,
diff --git a/rust/Android.bp b/rust/Android.bp
index d232eec..22483ea 100644
--- a/rust/Android.bp
+++ b/rust/Android.bp
@@ -16,8 +16,8 @@ rust_bindgen {
         "--with-derive-default",
         "--blocklist-type=__.+|.?int.+",
         "--blocklist-item=_.+|.?INT.+|PTR.+|ATOMIC.+|.+SOURCE|.+_H|SIG_.+|SIZE_.+|.?CHAR.+",
-        "--with-derive-custom-struct=(vendor_)?(boot_img_hdr|ramdisk_table_entry)_v\\d+=AsBytes,FromBytes,FromZeroes,PartialEq,Copy,Clone,Debug",
-        "--raw-line=use zerocopy::{AsBytes, FromBytes, FromZeroes};",
+        "--with-derive-custom-struct=(vendor_)?(boot_img_hdr|ramdisk_table_entry)_v\\d+=FromBytes,Immutable,IntoBytes,KnownLayout,PartialEq,Copy,Clone,Debug",
+        "--raw-line=use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};",
     ],
     header_libs: ["bootimg_headers"],
     rustlibs: ["libzerocopy"],
diff --git a/rust/bootimg.rs b/rust/bootimg.rs
index 72f0d0c..a5ad367 100644
--- a/rust/bootimg.rs
+++ b/rust/bootimg.rs
@@ -13,7 +13,7 @@
 // limitations under the License.
 
 //! The public interface for bootimg structs
-use zerocopy::{ByteSlice, LayoutVerified};
+use zerocopy::{ByteSlice, Immutable, KnownLayout, Ref, SplitByteSlice};
 
 use bootimg_bindgen::{
     boot_img_hdr_v0, boot_img_hdr_v1, boot_img_hdr_v2, boot_img_hdr_v3, boot_img_hdr_v4,
@@ -25,24 +25,24 @@ use bootimg_bindgen::{
 #[derive(PartialEq, Debug)]
 pub enum BootImage<B: ByteSlice + PartialEq> {
     /// Version 0 header
-    V0(LayoutVerified<B, boot_img_hdr_v0>),
+    V0(Ref<B, boot_img_hdr_v0>),
     /// Version 1 header
-    V1(LayoutVerified<B, boot_img_hdr_v1>),
+    V1(Ref<B, boot_img_hdr_v1>),
     /// Version 2 header
-    V2(LayoutVerified<B, boot_img_hdr_v2>),
+    V2(Ref<B, boot_img_hdr_v2>),
     /// Version 3 header
-    V3(LayoutVerified<B, boot_img_hdr_v3>),
+    V3(Ref<B, boot_img_hdr_v3>),
     /// Version 4 header
-    V4(LayoutVerified<B, boot_img_hdr_v4>),
+    V4(Ref<B, boot_img_hdr_v4>),
 }
 
 /// Generalized vendor boot header from a backing store of bytes.
 #[derive(PartialEq, Debug)]
 pub enum VendorImageHeader<B: ByteSlice + PartialEq> {
     /// Version 3 header
-    V3(LayoutVerified<B, vendor_boot_img_hdr_v3>),
+    V3(Ref<B, vendor_boot_img_hdr_v3>),
     /// Version 4 header
-    V4(LayoutVerified<B, vendor_boot_img_hdr_v4>),
+    V4(Ref<B, vendor_boot_img_hdr_v4>),
 }
 
 /// Boot related errors.
@@ -73,11 +73,13 @@ impl core::fmt::Display for ImageError {
 /// Common result type for use with boot headers
 pub type BootResult<T> = Result<T, ImageError>;
 
-fn parse_header<B: ByteSlice + PartialEq, T>(buffer: B) -> BootResult<LayoutVerified<B, T>> {
-    Ok(LayoutVerified::<B, T>::new_from_prefix(buffer).ok_or(ImageError::BufferTooSmall)?.0)
+fn parse_header<B: SplitByteSlice + PartialEq, T: Immutable + KnownLayout>(
+    buffer: B,
+) -> BootResult<Ref<B, T>> {
+    Ok(Ref::<B, T>::new_from_prefix(buffer).ok_or(ImageError::BufferTooSmall)?.0)
 }
 
-impl<B: ByteSlice + PartialEq> BootImage<B> {
+impl<B: SplitByteSlice + PartialEq> BootImage<B> {
     /// Given a byte buffer, attempt to parse the contents and return a zero-copy reference
     /// to the associated boot image header.
     ///
@@ -103,9 +105,8 @@ impl<B: ByteSlice + PartialEq> BootImage<B> {
         // Note: even though the v3 header is not a prefix for the v0, v1, or v2 header,
         // the version and the magic string exist at the same offset and have the same types.
         // Make a v3 temporary because it is the smallest.
-        let (hdr, _) =
-            LayoutVerified::<&[u8], boot_img_hdr_v3>::new_from_prefix(buffer.get(..).unwrap())
-                .ok_or(ImageError::BufferTooSmall)?;
+        let (hdr, _) = Ref::<&[u8], boot_img_hdr_v3>::new_from_prefix(buffer.get(..).unwrap())
+            .ok_or(ImageError::BufferTooSmall)?;
 
         if hdr.magic.ne(&BOOT_MAGIC[..magic_size]) {
             return Err(ImageError::BadMagic);
@@ -122,7 +123,7 @@ impl<B: ByteSlice + PartialEq> BootImage<B> {
     }
 }
 
-impl<B: ByteSlice + PartialEq> VendorImageHeader<B> {
+impl<B: SplitByteSlice + PartialEq> VendorImageHeader<B> {
     /// Given a byte buffer, attempt to parse the contents and return a zero-copy reference
     /// to the associated vendor boot image header.
     ///
@@ -145,10 +146,9 @@ impl<B: ByteSlice + PartialEq> VendorImageHeader<B> {
     /// ```
     pub fn parse(buffer: B) -> BootResult<Self> {
         let magic_size = VENDOR_BOOT_MAGIC_SIZE as usize;
-        let (hdr, _) = LayoutVerified::<&[u8], vendor_boot_img_hdr_v3>::new_from_prefix(
-            buffer.get(..).unwrap(),
-        )
-        .ok_or(ImageError::BufferTooSmall)?;
+        let (hdr, _) =
+            Ref::<&[u8], vendor_boot_img_hdr_v3>::new_from_prefix(buffer.get(..).unwrap())
+                .ok_or(ImageError::BufferTooSmall)?;
 
         if hdr.magic.ne(&VENDOR_BOOT_MAGIC[..magic_size]) {
             return Err(ImageError::BadMagic);
@@ -165,12 +165,12 @@ impl<B: ByteSlice + PartialEq> VendorImageHeader<B> {
 #[cfg(test)]
 mod tests {
     use super::*;
-    use zerocopy::AsBytes;
+    use zerocopy::IntoBytes;
 
     const MAGIC_SIZE: usize = BOOT_MAGIC_SIZE as usize;
     const VENDOR_MAGIC_SIZE: usize = VENDOR_BOOT_MAGIC_SIZE as usize;
 
-    pub fn add<T: AsBytes>(buffer: &mut [u8], t: T) {
+    pub fn add<T: Immutable + IntoBytes>(buffer: &mut [u8], t: T) {
         t.write_to_prefix(buffer).unwrap();
     }
 
@@ -232,8 +232,7 @@ mod tests {
                 ..Default::default()
             },
         );
-        let expected =
-            Ok(BootImage::V0(LayoutVerified::<&[u8], boot_img_hdr_v0>::new(&buffer).unwrap()));
+        let expected = Ok(BootImage::V0(Ref::<&[u8], boot_img_hdr_v0>::new(&buffer).unwrap()));
         assert_eq!(BootImage::parse(&buffer[..]), expected);
     }
 
@@ -251,8 +250,7 @@ mod tests {
                 ..Default::default()
             },
         );
-        let expected =
-            Ok(BootImage::V1(LayoutVerified::<&[u8], boot_img_hdr_v1>::new(&buffer).unwrap()));
+        let expected = Ok(BootImage::V1(Ref::<&[u8], boot_img_hdr_v1>::new(&buffer).unwrap()));
         assert_eq!(BootImage::parse(&buffer[..]), expected);
     }
 
@@ -273,8 +271,7 @@ mod tests {
                 ..Default::default()
             },
         );
-        let expected =
-            Ok(BootImage::V2(LayoutVerified::<&[u8], boot_img_hdr_v2>::new(&buffer).unwrap()));
+        let expected = Ok(BootImage::V2(Ref::<&[u8], boot_img_hdr_v2>::new(&buffer).unwrap()));
         assert_eq!(BootImage::parse(&buffer[..]), expected);
     }
 
@@ -289,8 +286,7 @@ mod tests {
                 ..Default::default()
             },
         );
-        let expected =
-            Ok(BootImage::V3(LayoutVerified::<&[u8], boot_img_hdr_v3>::new(&buffer).unwrap()));
+        let expected = Ok(BootImage::V3(Ref::<&[u8], boot_img_hdr_v3>::new(&buffer).unwrap()));
         assert_eq!(BootImage::parse(&buffer[..]), expected);
     }
 
@@ -308,8 +304,7 @@ mod tests {
                 ..Default::default()
             },
         );
-        let expected =
-            Ok(BootImage::V4(LayoutVerified::<&[u8], boot_img_hdr_v4>::new(&buffer).unwrap()));
+        let expected = Ok(BootImage::V4(Ref::<&[u8], boot_img_hdr_v4>::new(&buffer).unwrap()));
         assert_eq!(BootImage::parse(&buffer[..]), expected);
     }
 
@@ -371,9 +366,8 @@ mod tests {
                 ..Default::default()
             },
         );
-        let expected = Ok(VendorImageHeader::V3(
-            LayoutVerified::<&[u8], vendor_boot_img_hdr_v3>::new(&buffer).unwrap(),
-        ));
+        let expected =
+            Ok(VendorImageHeader::V3(Ref::<&[u8], vendor_boot_img_hdr_v3>::new(&buffer).unwrap()));
         assert_eq!(VendorImageHeader::parse(&buffer[..]), expected);
     }
 
@@ -391,9 +385,8 @@ mod tests {
                 ..Default::default()
             },
         );
-        let expected = Ok(VendorImageHeader::V4(
-            LayoutVerified::<&[u8], vendor_boot_img_hdr_v4>::new(&buffer).unwrap(),
-        ));
+        let expected =
+            Ok(VendorImageHeader::V4(Ref::<&[u8], vendor_boot_img_hdr_v4>::new(&buffer).unwrap()));
         assert_eq!(VendorImageHeader::parse(&buffer[..]), expected);
     }
 }
```

