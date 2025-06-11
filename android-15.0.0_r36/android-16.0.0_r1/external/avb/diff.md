```diff
diff --git a/Android.bp b/Android.bp
index af5b6b6..ab8a21b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -227,6 +227,12 @@ cc_defaults {
         "libcrypto_baremetal",
     ],
     srcs: ["libavb/avb_sysdeps_posix.c"],
+
+    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
+    // until cross-language lto is supported.
+    lto: {
+        never: true,
+    },
 }
 
 // Baremetal libavb
diff --git a/OWNERS b/OWNERS
index f9893cf..8b76914 100644
--- a/OWNERS
+++ b/OWNERS
@@ -4,3 +4,4 @@ zeuthen@google.com
 dkrahn@google.com
 tweek@google.com
 billylau@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/avbtool.py b/avbtool.py
index 7e292f0..595936c 100755
--- a/avbtool.py
+++ b/avbtool.py
@@ -47,6 +47,7 @@ AVB_FOOTER_VERSION_MAJOR = 1
 AVB_FOOTER_VERSION_MINOR = 0
 
 AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED = 1
+AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED = 2
 
 # Configuration for enabling logging of calls to avbtool.
 AVB_INVOCATION_LOGFILE = os.environ.get('AVB_INVOCATION_LOGFILE')
@@ -2423,13 +2424,14 @@ class Avb(object):
     misc_image.seek(self.AB_MISC_METADATA_OFFSET)
     misc_image.write(ab_data)
 
-  def info_image(self, image_filename, output, cert):
+  def info_image(self, image_filename, output, cert, output_pubkey=None):
     """Implements the 'info_image' command.
 
     Arguments:
       image_filename: Image file to get information from (file object).
       output: Output file to write human-readable information to (file object).
       cert: If True, show information about the avb_cert certificates.
+      output_pubkey: Optional file to write the public key to (file object).
     """
     image = ImageHandler(image_filename, read_only=True)
     o = output
@@ -2466,6 +2468,9 @@ class Avb(object):
     if key_blob:
       hexdig = hashlib.sha1(key_blob).hexdigest()
       o.write('Public key (sha1):        {}\n'.format(hexdig))
+      if output_pubkey is not None:
+        output_pubkey.write(key_blob)
+
     o.write('Algorithm:                {}\n'.format(alg_name))
     o.write('Rollback Index:           {}\n'.format(header.rollback_index))
     o.write('Flags:                    {}\n'.format(header.flags))
@@ -3280,6 +3285,20 @@ class Avb(object):
     """
     output.write(RSAPublicKey(key_path).encode())
 
+  def extract_public_key_digest(self, key_path, output):
+    """Implements the 'extract_public_key_digest' command.
+
+    Arguments:
+      key_path: The path to a RSA private key file.
+      output: The file to write to.
+
+    Raises:
+      AvbError: If the public key could not be extracted.
+    """
+    hasher = hashlib.sha256()
+    hasher.update(RSAPublicKey(key_path).encode())
+    output.write(hasher.hexdigest())
+
   def append_vbmeta_image(self, image_filename, vbmeta_image_filename,
                           partition_size):
     """Implementation of the append_vbmeta_image command.
@@ -3584,13 +3603,13 @@ class Avb(object):
       image.truncate(original_image_size)
       raise AvbError('Adding hash_footer failed: {}.'.format(e)) from e
 
-  def add_hashtree_footer(self, image_filename, partition_size, partition_name,
+  def add_hashtree_footer(self, image_filename, partition_size: int, partition_name,
                           generate_fec, fec_num_roots, hash_algorithm,
                           block_size, salt, chain_partitions_use_ab,
                           chain_partitions_do_not_use_ab,
                           algorithm_name, key_path,
                           public_key_metadata_path, rollback_index, flags,
-                          rollback_index_location,
+                          rollback_index_location: int,
                           props, props_from_file, kernel_cmdlines,
                           setup_rootfs_from_kernel,
                           setup_as_rootfs_from_kernel,
@@ -4294,6 +4313,9 @@ class AvbTool(object):
     sub_parser.add_argument('--set_hashtree_disabled_flag',
                             help='Set the HASHTREE_DISABLED flag',
                             action='store_true')
+    sub_parser.add_argument('--set_verification_disabled_flag',
+                            help='Set the VERIFICATION_DISABLED flag',
+                            action='store_true')
 
   def _add_common_footer_args(self, sub_parser):
     """Adds arguments used by add_*_footer sub-commands.
@@ -4325,6 +4347,8 @@ class AvbTool(object):
     """
     if args.set_hashtree_disabled_flag:
       args.flags |= AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED
+    if args.set_verification_disabled_flag:
+      args.flags |= AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED
     return args
 
   def run(self, argv):
@@ -4369,6 +4393,17 @@ class AvbTool(object):
                             required=True)
     sub_parser.set_defaults(func=self.extract_public_key)
 
+    sub_parser = subparsers.add_parser('extract_public_key_digest',
+                                       help='Extract SHA-256 digest of public key.')
+    sub_parser.add_argument('--key',
+                            help='Path to RSA private key file',
+                            required=True)
+    sub_parser.add_argument('--output',
+                            help='Output file name',
+                            type=argparse.FileType('w', encoding='UTF-8'),
+                            required=True)
+    sub_parser.set_defaults(func=self.extract_public_key_digest)
+
     sub_parser = subparsers.add_parser('make_vbmeta_image',
                                        help='Makes a vbmeta image.')
     sub_parser.add_argument('--output',
@@ -4570,6 +4605,10 @@ class AvbTool(object):
                             help=('Show information about the avb_cert '
                                   'extension certificate.'),
                             action='store_true')
+    sub_parser.add_argument('--output_pubkey',
+                            help='Write public key to file',
+                            type=argparse.FileType('wb'),
+                            required=False)
     sub_parser.set_defaults(func=self.info_image)
 
     sub_parser = subparsers.add_parser(
@@ -4815,6 +4854,10 @@ class AvbTool(object):
     """Implements the 'extract_public_key' sub-command."""
     self.avb.extract_public_key(args.key, args.output)
 
+  def extract_public_key_digest(self, args):
+    """Implements the 'extract_public_key_digest' sub-command."""
+    self.avb.extract_public_key_digest(args.key, args.output)
+
   def make_vbmeta_image(self, args):
     """Implements the 'make_vbmeta_image' sub-command."""
     args = self._fixup_common_args(args)
@@ -4937,7 +4980,8 @@ Please use '--hash_algorithm sha256'.
 
   def info_image(self, args):
     """Implements the 'info_image' sub-command."""
-    self.avb.info_image(args.image.name, args.output, args.cert)
+    self.avb.info_image(args.image.name, args.output,
+                        args.cert, args.output_pubkey)
 
   def verify_image(self, args):
     """Implements the 'verify_image' sub-command."""
diff --git a/libavb/avb_cmdline.c b/libavb/avb_cmdline.c
index 6613020..b6793c1 100644
--- a/libavb/avb_cmdline.c
+++ b/libavb/avb_cmdline.c
@@ -207,11 +207,33 @@ static int cmdline_append_hex(AvbSlotVerifyData* slot_data,
   return ret;
 }
 
+static const char* cmdline_get_digest_name(AvbDigestType avb_digest_type) {
+  const char* ret = NULL;
+  switch (avb_digest_type) {
+    case AVB_DIGEST_TYPE_SHA256:
+      ret = "sha256";
+      break;
+    case AVB_DIGEST_TYPE_SHA512:
+      ret = "sha512";
+      break;
+      /* Do not add a 'default:' case here because of -Wswitch. */
+  }
+
+  if (ret == NULL) {
+    avb_error("Unknown AvbDigestType.\n");
+    ret = "unknown";
+  }
+
+  return ret;
+}
+
 AvbSlotVerifyResult avb_append_options(
     AvbOps* ops,
     AvbSlotVerifyFlags flags,
     AvbSlotVerifyData* slot_data,
     AvbVBMetaImageHeader* toplevel_vbmeta,
+    const uint8_t* toplevel_vbmeta_public_key_data,
+    size_t toplevel_vbmeta_public_key_length,
     AvbAlgorithmType algorithm_type,
     AvbHashtreeErrorMode hashtree_error_mode,
     AvbHashtreeErrorMode resolved_hashtree_error_mode) {
@@ -219,17 +241,37 @@ AvbSlotVerifyResult avb_append_options(
   const char* verity_mode;
   bool is_device_unlocked;
   AvbIOResult io_ret;
+  char* requested_partition_hash_alg = NULL;
+  char* requested_partition_digest = NULL;
 
-  /* Add androidboot.vbmeta.device option... except if not using a vbmeta
-   * partition since it doesn't make sense in that case.
-   */
+  /* Add options that only make sense if there is a vbmeta partition. */
   if (!(flags & AVB_SLOT_VERIFY_FLAGS_NO_VBMETA_PARTITION)) {
+    /* Add androidboot.vbmeta.device option. */
     if (!cmdline_append_option(slot_data,
                                "androidboot.vbmeta.device",
                                "PARTUUID=$(ANDROID_VBMETA_PARTUUID)")) {
       ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
       goto out;
     }
+
+    /* Set androidboot.vbmeta.public_key_digest to the SHA-256 hash of the
+     * public key used to verify the vbmeta image. */
+    if (toplevel_vbmeta_public_key_data != NULL &&
+        toplevel_vbmeta_public_key_length > 0) {
+      AvbSHA256Ctx ctx;
+      avb_sha256_init(&ctx);
+      avb_sha256_update(&ctx,
+                        toplevel_vbmeta_public_key_data,
+                        toplevel_vbmeta_public_key_length);
+      uint8_t* vbmeta_public_key_digest = avb_sha256_final(&ctx);
+      if (!cmdline_append_hex(slot_data,
+                              "androidboot.vbmeta.public_key_digest",
+                              vbmeta_public_key_digest,
+                              AVB_SHA256_DIGEST_SIZE)) {
+        ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
+        goto out;
+      }
+    }
   }
 
   /* Add androidboot.vbmeta.avb_version option. */
@@ -380,10 +422,61 @@ AvbSlotVerifyResult avb_append_options(
     }
   }
 
+  size_t i;
+  for (i = 0; i < slot_data->num_loaded_partitions; i++) {
+    if (slot_data->loaded_partitions[i].partition_name != NULL &&
+        slot_data->loaded_partitions[i].digest != NULL) {
+      requested_partition_hash_alg =
+          avb_strdupv("androidboot.vbmeta.",
+                      slot_data->loaded_partitions[i].partition_name,
+                      ".hash_alg",
+                      NULL);
+      if (requested_partition_hash_alg == NULL) {
+        ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
+        goto out;
+      }
+
+      requested_partition_digest =
+          avb_strdupv("androidboot.vbmeta.",
+                      slot_data->loaded_partitions[i].partition_name,
+                      ".digest",
+                      NULL);
+      if (requested_partition_digest == NULL) {
+        ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
+        goto out;
+      }
+
+      if (!cmdline_append_option(
+              slot_data,
+              requested_partition_hash_alg,
+              cmdline_get_digest_name(
+                  slot_data->loaded_partitions[i].digest_type)) ||
+          !cmdline_append_hex(slot_data,
+                              requested_partition_digest,
+                              slot_data->loaded_partitions[i].digest,
+                              slot_data->loaded_partitions[i].digest_size)) {
+        ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
+        goto out;
+      }
+
+      avb_free(requested_partition_hash_alg);
+      requested_partition_hash_alg = NULL;
+      avb_free(requested_partition_digest);
+      requested_partition_digest = NULL;
+    }
+  }
+
   ret = AVB_SLOT_VERIFY_RESULT_OK;
 
 out:
-
+  if (requested_partition_hash_alg != NULL) {
+    avb_free(requested_partition_hash_alg);
+    requested_partition_hash_alg = NULL;
+  }
+  if (requested_partition_digest != NULL) {
+    avb_free(requested_partition_digest);
+    requested_partition_digest = NULL;
+  }
   return ret;
 }
 
diff --git a/libavb/avb_cmdline.h b/libavb/avb_cmdline.h
index 377783f..f690312 100644
--- a/libavb/avb_cmdline.h
+++ b/libavb/avb_cmdline.h
@@ -65,6 +65,8 @@ AvbSlotVerifyResult avb_append_options(
     AvbSlotVerifyFlags flags,
     AvbSlotVerifyData* slot_data,
     AvbVBMetaImageHeader* toplevel_vbmeta,
+    const uint8_t* toplevel_vbmeta_public_key_data,
+    size_t toplevel_vbmeta_public_key_length,
     AvbAlgorithmType algorithm_type,
     AvbHashtreeErrorMode hashtree_error_mode,
     AvbHashtreeErrorMode resolved_hashtree_error_mode);
diff --git a/libavb/avb_slot_verify.c b/libavb/avb_slot_verify.c
index 3ff59c2..4f010da 100644
--- a/libavb/avb_slot_verify.c
+++ b/libavb/avb_slot_verify.c
@@ -291,6 +291,7 @@ static AvbSlotVerifyResult load_and_verify_hash_partition(
   bool image_preloaded = false;
   uint8_t* digest;
   size_t digest_len;
+  AvbDigestType digest_type;
   const char* found;
   uint64_t image_size;
   size_t expected_digest_len = 0;
@@ -400,12 +401,14 @@ static AvbSlotVerifyResult load_and_verify_hash_partition(
     avb_sha256_update(&sha256_ctx, image_buf, image_size_to_hash);
     digest = avb_sha256_final(&sha256_ctx);
     digest_len = AVB_SHA256_DIGEST_SIZE;
+    digest_type = AVB_DIGEST_TYPE_SHA256;
   } else if (avb_strcmp((const char*)hash_desc.hash_algorithm, "sha512") == 0) {
     avb_sha512_init(&sha512_ctx);
     avb_sha512_update(&sha512_ctx, desc_salt, hash_desc.salt_len);
     avb_sha512_update(&sha512_ctx, image_buf, image_size_to_hash);
     digest = avb_sha512_final(&sha512_ctx);
     digest_len = AVB_SHA512_DIGEST_SIZE;
+    digest_type = AVB_DIGEST_TYPE_SHA512;
   } else {
     avb_error(part_name, ": Unsupported hash algorithm.\n");
     ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
@@ -460,6 +463,14 @@ out:
     }
     loaded_partition =
         &slot_data->loaded_partitions[slot_data->num_loaded_partitions++];
+    loaded_partition->digest = avb_calloc(digest_len);
+    if (loaded_partition->digest == NULL) {
+      ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
+      goto fail;
+    }
+    avb_memcpy(loaded_partition->digest, digest, digest_len);
+    loaded_partition->digest_size = digest_len;
+    loaded_partition->digest_type = digest_type;
     loaded_partition->partition_name = avb_strdup(found);
     loaded_partition->data_size = image_size;
     loaded_partition->data = image_buf;
@@ -565,6 +576,8 @@ static AvbSlotVerifyResult load_and_verify_vbmeta(
     size_t expected_public_key_length,
     AvbSlotVerifyData* slot_data,
     AvbAlgorithmType* out_algorithm_type,
+    uint8_t** out_toplevel_vbmeta_public_key_data,
+    size_t* out_toplevel_vbmeta_public_key_length,
     AvbCmdlineSubstList* out_additional_cmdline_subst,
     bool use_ab_suffix) {
   char full_partition_name[AVB_PART_NAME_MAX_SIZE];
@@ -753,6 +766,8 @@ static AvbSlotVerifyResult load_and_verify_vbmeta(
                                    0 /* expected_public_key_length */,
                                    slot_data,
                                    out_algorithm_type,
+                                   out_toplevel_vbmeta_public_key_data,
+                                   out_toplevel_vbmeta_public_key_length,
                                    out_additional_cmdline_subst,
                                    use_ab_suffix);
       goto out;
@@ -772,6 +787,22 @@ static AvbSlotVerifyResult load_and_verify_vbmeta(
   switch (vbmeta_ret) {
     case AVB_VBMETA_VERIFY_RESULT_OK:
       avb_assert(pk_data != NULL && pk_len > 0);
+      if (is_main_vbmeta) {
+        if (out_toplevel_vbmeta_public_key_data != NULL) {
+          *out_toplevel_vbmeta_public_key_data = avb_malloc(pk_len);
+          if (*out_toplevel_vbmeta_public_key_data == NULL) {
+            ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
+            goto out;
+          }
+          // Copy the public key data into the output parameter since pk_data
+          // is a pointer to data in vbmeta_buf, whose memory gets deallocated
+          // at the end of this function.
+          avb_memcpy(*out_toplevel_vbmeta_public_key_data, pk_data, pk_len);
+        }
+        if (out_toplevel_vbmeta_public_key_length != NULL) {
+          *out_toplevel_vbmeta_public_key_length = pk_len;
+        }
+      }
       break;
 
     case AVB_VBMETA_VERIFY_RESULT_OK_NOT_SIGNED:
@@ -1052,6 +1083,8 @@ static AvbSlotVerifyResult load_and_verify_vbmeta(
                                    chain_desc.public_key_len,
                                    slot_data,
                                    NULL, /* out_algorithm_type */
+                                   out_toplevel_vbmeta_public_key_data,
+                                   out_toplevel_vbmeta_public_key_length,
                                    NULL, /* out_additional_cmdline_subst */
                                    use_ab_suffix);
         if (sub_ret != AVB_SLOT_VERIFY_RESULT_OK) {
@@ -1393,6 +1426,8 @@ AvbSlotVerifyResult avb_slot_verify(AvbOps* ops,
   AvbAlgorithmType algorithm_type = AVB_ALGORITHM_TYPE_NONE;
   bool using_boot_for_vbmeta = false;
   AvbVBMetaImageHeader toplevel_vbmeta;
+  uint8_t* toplevel_vbmeta_public_key_data = NULL;
+  size_t toplevel_vbmeta_public_key_length = 0;
   bool allow_verification_error =
       (flags & AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR);
   AvbCmdlineSubstList* additional_cmdline_subst = NULL;
@@ -1483,21 +1518,24 @@ AvbSlotVerifyResult avb_slot_verify(AvbOps* ops,
 
     /* No vbmeta partition, go through each of the requested partitions... */
     for (size_t n = 0; requested_partitions[n] != NULL; n++) {
-      ret = load_and_verify_vbmeta(ops,
-                                   requested_partitions,
-                                   ab_suffix,
-                                   flags,
-                                   allow_verification_error,
-                                   0 /* toplevel_vbmeta_flags */,
-                                   0 /* rollback_index_location */,
-                                   requested_partitions[n],
-                                   avb_strlen(requested_partitions[n]),
-                                   NULL /* expected_public_key */,
-                                   0 /* expected_public_key_length */,
-                                   slot_data,
-                                   &algorithm_type,
-                                   additional_cmdline_subst,
-                                   true /*use_ab_suffix*/);
+      ret = load_and_verify_vbmeta(
+          ops,
+          requested_partitions,
+          ab_suffix,
+          flags,
+          allow_verification_error,
+          0 /* toplevel_vbmeta_flags */,
+          0 /* rollback_index_location */,
+          requested_partitions[n],
+          avb_strlen(requested_partitions[n]),
+          NULL /* expected_public_key */,
+          0 /* expected_public_key_length */,
+          slot_data,
+          &algorithm_type,
+          NULL /* out_toplevel_vbmeta_public_key_data */,
+          NULL /* out_toplevel_vbmeta_public_key_length */,
+          additional_cmdline_subst,
+          true /*use_ab_suffix*/);
       if (!allow_verification_error && ret != AVB_SLOT_VERIFY_RESULT_OK) {
         goto fail;
       }
@@ -1518,6 +1556,8 @@ AvbSlotVerifyResult avb_slot_verify(AvbOps* ops,
                                  0 /* expected_public_key_length */,
                                  slot_data,
                                  &algorithm_type,
+                                 &toplevel_vbmeta_public_key_data,
+                                 &toplevel_vbmeta_public_key_length,
                                  additional_cmdline_subst,
                                  true /*use_ab_suffix*/);
     if (!allow_verification_error && ret != AVB_SLOT_VERIFY_RESULT_OK) {
@@ -1598,6 +1638,8 @@ AvbSlotVerifyResult avb_slot_verify(AvbOps* ops,
                                  flags,
                                  slot_data,
                                  &toplevel_vbmeta,
+                                 toplevel_vbmeta_public_key_data,
+                                 toplevel_vbmeta_public_key_length,
                                  algorithm_type,
                                  hashtree_error_mode,
                                  resolved_hashtree_error_mode);
@@ -1631,6 +1673,10 @@ AvbSlotVerifyResult avb_slot_verify(AvbOps* ops,
     avb_slot_verify_data_free(slot_data);
   }
 
+  if (toplevel_vbmeta_public_key_data != NULL) {
+    avb_free(toplevel_vbmeta_public_key_data);
+  }
+
   avb_free_cmdline_subst_list(additional_cmdline_subst);
   additional_cmdline_subst = NULL;
 
@@ -1644,6 +1690,9 @@ fail:
   if (slot_data != NULL) {
     avb_slot_verify_data_free(slot_data);
   }
+  if (toplevel_vbmeta_public_key_data != NULL) {
+    avb_free(toplevel_vbmeta_public_key_data);
+  }
   if (additional_cmdline_subst != NULL) {
     avb_free_cmdline_subst_list(additional_cmdline_subst);
   }
@@ -1680,6 +1729,9 @@ void avb_slot_verify_data_free(AvbSlotVerifyData* data) {
       if (loaded_partition->data != NULL && !loaded_partition->preloaded) {
         avb_free(loaded_partition->data);
       }
+      if (loaded_partition->digest != NULL) {
+        avb_free(loaded_partition->digest);
+      }
     }
     avb_free(data->loaded_partitions);
   }
diff --git a/libavb/avb_slot_verify.h b/libavb/avb_slot_verify.h
index 8702c21..8c76b21 100644
--- a/libavb/avb_slot_verify.h
+++ b/libavb/avb_slot_verify.h
@@ -159,6 +159,9 @@ typedef struct {
   size_t data_size;
   bool preloaded;
   AvbSlotVerifyResult verify_result;
+  uint8_t* digest;
+  size_t digest_size;
+  AvbDigestType digest_type;
 } AvbPartitionData;
 
 /* AvbVBMetaData contains a vbmeta struct loaded from a partition when
@@ -253,6 +256,11 @@ typedef struct {
  *   androidboot.vbmeta.{hash_alg, size, digest}: Will be set to
  *   the digest of all images in |vbmeta_images|.
  *
+ *   androidboot.vbmeta.public_key_digest: Will be set to the SHA-256
+ *   digest of the public key used to verify the vbmeta partition (or
+ *   boot partition if there is no vbmeta partition). If the flag
+ *   AVB_SLOT_VERIFY_FLAGS_NO_VBMETA_PARTITION is used, this is not set.
+ *
  *   androidboot.vbmeta.device: This is set to the value
  *   PARTUUID=$(ANDROID_VBMETA_PARTUUID) before substitution so it
  *   will end up pointing to the vbmeta partition for the verified
diff --git a/rust/Android.bp b/rust/Android.bp
index ae82438..0ec4911 100644
--- a/rust/Android.bp
+++ b/rust/Android.bp
@@ -34,17 +34,17 @@ rust_defaults {
         "--bitfield-enum=Avb.*Flags",
         "--default-enum-style rust",
         "--with-derive-default",
-        "--with-derive-custom=Avb.*Descriptor=FromZeroes,FromBytes",
-        "--with-derive-custom=AvbCertPermanentAttributes=FromZeroes,FromBytes,AsBytes",
-        "--with-derive-custom=AvbCertCertificate.*=FromZeroes,FromBytes,AsBytes",
-        "--with-derive-custom=AvbCertUnlock.*=FromZeroes,FromBytes,AsBytes",
+        "--with-derive-custom=Avb.*Descriptor=FromBytes,Immutable,KnownLayout",
+        "--with-derive-custom=AvbCertPermanentAttributes=FromBytes,Immutable,IntoBytes,KnownLayout",
+        "--with-derive-custom=AvbCertCertificate.*=FromBytes,Immutable,IntoBytes,KnownLayout",
+        "--with-derive-custom=AvbCertUnlock.*=FromBytes,Immutable,IntoBytes,KnownLayout",
         "--allowlist-type=AvbDescriptorTag",
         "--allowlist-type=Avb.*Flags",
         "--allowlist-function=.*",
         "--allowlist-var=AVB.*",
         "--use-core",
         "--raw-line=#![no_std]",
-        "--raw-line=use zerocopy::{AsBytes, FromBytes, FromZeroes};",
+        "--raw-line=use zerocopy::{Immutable, IntoBytes, FromBytes, KnownLayout};",
         "--ctypes-prefix=core::ffi",
     ],
     cflags: ["-DBORINGSSL_NO_CXX"],
@@ -55,7 +55,7 @@ rust_defaults {
     name: "libavb_bindgen.std.defaults",
     defaults: ["libavb_bindgen.common.defaults"],
     host_supported: true,
-    static_libs: ["libavb_cert"],
+    whole_static_libs: ["libavb_cert"],
     shared_libs: ["libcrypto"],
     rustlibs: ["libzerocopy"],
     apex_available: ["com.android.virt"],
@@ -65,7 +65,7 @@ rust_defaults {
 rust_defaults {
     name: "libavb_bindgen.nostd.defaults",
     defaults: ["libavb_bindgen.common.defaults"],
-    static_libs: [
+    whole_static_libs: [
         "libavb_cert_baremetal",
         "libcrypto_baremetal",
     ],
diff --git a/rust/src/cert.rs b/rust/src/cert.rs
index aa54859..7f9f8ef 100644
--- a/rust/src/cert.rs
+++ b/rust/src/cert.rs
@@ -104,6 +104,9 @@ pub use avb_bindgen::AvbCertUnlockCredential as CertUnlockCredential;
 /// Size in bytes of a SHA256 digest.
 pub const SHA256_DIGEST_SIZE: usize = avb_bindgen::AVB_SHA256_DIGEST_SIZE as usize;
 
+/// Size in bytes of a SHA512 digest.
+pub const SHA512_DIGEST_SIZE: usize = avb_bindgen::AVB_SHA512_DIGEST_SIZE as usize;
+
 /// Product intermediate key (PIK) rollback index location.
 ///
 /// If using libavb_cert, make sure no vbmetas use this location, it must be reserved for the PIK.
@@ -329,7 +332,7 @@ struct CertOnlyOps<'a> {
     cert_ops: &'a mut dyn CertOps,
 }
 
-impl<'a> Ops<'static> for CertOnlyOps<'a> {
+impl Ops<'static> for CertOnlyOps<'_> {
     fn read_from_partition(
         &mut self,
         _partition: &CStr,
diff --git a/rust/src/descriptor/mod.rs b/rust/src/descriptor/mod.rs
index 488401e..3a657fd 100644
--- a/rust/src/descriptor/mod.rs
+++ b/rust/src/descriptor/mod.rs
@@ -91,7 +91,7 @@ impl From<FromBytesUntilNulError> for DescriptorError {
 /// `Result` type for `DescriptorError` errors.
 pub type DescriptorResult<T> = Result<T, DescriptorError>;
 
-impl<'a> Descriptor<'a> {
+impl Descriptor<'_> {
     /// Extracts the fully-typed descriptor from the generic `AvbDescriptor` header.
     ///
     /// # Arguments
@@ -102,7 +102,7 @@ impl<'a> Descriptor<'a> {
     ///
     /// # Safety
     /// `raw_descriptor` must point to a valid `AvbDescriptor`, including the `num_bytes_following`
-    /// data contents, that lives at least as long as `'a`.
+    /// data contents, that lives at least as long as `'_`.
     unsafe fn new(raw_descriptor: *const AvbDescriptor) -> DescriptorResult<Self> {
         // Transform header to host-endian.
         let mut descriptor = AvbDescriptor {
diff --git a/rust/src/descriptor/util.rs b/rust/src/descriptor/util.rs
index e4e23fd..546d70a 100644
--- a/rust/src/descriptor/util.rs
+++ b/rust/src/descriptor/util.rs
@@ -15,7 +15,7 @@
 //! Descriptor utilities.
 
 use super::{DescriptorError, DescriptorResult};
-use zerocopy::{FromBytes, FromZeroes, Ref};
+use zerocopy::{FromBytes, Immutable, KnownLayout, Ref};
 
 /// Splits `size` bytes off the front of `data`.
 ///
@@ -82,11 +82,11 @@ pub(super) struct ParsedDescriptor<'a, T> {
 /// invalid.
 pub(super) fn parse_descriptor<T>(data: &[u8]) -> DescriptorResult<ParsedDescriptor<T>>
 where
-    T: Default + FromZeroes + FromBytes + ValidateAndByteswap,
+    T: Default + FromBytes + Immutable + KnownLayout + ValidateAndByteswap,
 {
     let (raw_header, body) =
         Ref::<_, T>::new_from_prefix(data).ok_or(DescriptorError::InvalidHeader)?;
-    let raw_header = raw_header.into_ref();
+    let raw_header = Ref::into_ref(raw_header);
 
     let mut header = T::default();
     // SAFETY:
@@ -97,11 +97,7 @@ where
         return Err(DescriptorError::InvalidHeader);
     }
 
-    Ok(ParsedDescriptor {
-        raw_header,
-        header,
-        body,
-    })
+    Ok(ParsedDescriptor { raw_header, header, body })
 }
 
 #[cfg(test)]
diff --git a/rust/src/error.rs b/rust/src/error.rs
index a5642c6..f777a47 100644
--- a/rust/src/error.rs
+++ b/rust/src/error.rs
@@ -35,6 +35,9 @@ use avb_bindgen::{AvbIOResult, AvbSlotVerifyResult, AvbVBMetaVerifyResult};
 use core::{fmt, str::Utf8Error};
 
 /// `AvbSlotVerifyResult` error wrapper.
+///
+/// Some of the errors can contain the resulting `SlotVerifyData` if the `AllowVerificationError`
+/// flag was passed into `slot_verify()`.
 #[derive(Debug, PartialEq, Eq)]
 pub enum SlotVerifyError<'a> {
     /// `AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT`
@@ -46,15 +49,12 @@ pub enum SlotVerifyError<'a> {
     /// `AVB_SLOT_VERIFY_RESULT_ERROR_OOM`
     Oom,
     /// `AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED`
-    PublicKeyRejected,
+    PublicKeyRejected(Option<SlotVerifyData<'a>>),
     /// `AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX`
-    RollbackIndex,
+    RollbackIndex(Option<SlotVerifyData<'a>>),
     /// `AVB_SLOT_VERIFY_RESULT_ERROR_UNSUPPORTED_VERSION`
     UnsupportedVersion,
     /// `AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION`
-    ///
-    /// This verification error can contain the resulting `SlotVerifyData` if the
-    /// `AllowVerificationError` flag was passed into `slot_verify()`.
     Verification(Option<SlotVerifyData<'a>>),
     /// Unexpected internal error. This does not have a corresponding libavb error code.
     Internal,
@@ -80,24 +80,35 @@ impl<'a> SlotVerifyError<'a> {
             Self::InvalidMetadata => SlotVerifyError::InvalidMetadata,
             Self::Io => SlotVerifyError::Io,
             Self::Oom => SlotVerifyError::Oom,
-            Self::PublicKeyRejected => SlotVerifyError::PublicKeyRejected,
-            Self::RollbackIndex => SlotVerifyError::RollbackIndex,
+            Self::PublicKeyRejected(_) => SlotVerifyError::PublicKeyRejected(None),
+            Self::RollbackIndex(_) => SlotVerifyError::RollbackIndex(None),
             Self::UnsupportedVersion => SlotVerifyError::UnsupportedVersion,
             Self::Verification(_) => SlotVerifyError::Verification(None),
             Self::Internal => SlotVerifyError::Internal,
         }
     }
+
+    /// Returns a `SlotVerifyData` which can be provided with non-fatal errors in case
+    /// `AllowVerificationError` flag was passed into `slot_verify()`.
+    pub fn verification_data(&self) -> Option<&SlotVerifyData<'a>> {
+        match self {
+            SlotVerifyError::PublicKeyRejected(data)
+            | SlotVerifyError::RollbackIndex(data)
+            | SlotVerifyError::Verification(data) => data.as_ref(),
+            _ => None,
+        }
+    }
 }
 
-impl<'a> fmt::Display for SlotVerifyError<'a> {
+impl fmt::Display for SlotVerifyError<'_> {
     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
         match self {
             Self::InvalidArgument => write!(f, "Invalid parameters"),
             Self::InvalidMetadata => write!(f, "Invalid metadata"),
             Self::Io => write!(f, "I/O error"),
             Self::Oom => write!(f, "Unable to allocate memory"),
-            Self::PublicKeyRejected => write!(f, "Public key rejected or data not signed"),
-            Self::RollbackIndex => write!(f, "Rollback index violation"),
+            Self::PublicKeyRejected(_) => write!(f, "Public key rejected or data not signed"),
+            Self::RollbackIndex(_) => write!(f, "Rollback index violation"),
             Self::UnsupportedVersion => write!(f, "Unsupported vbmeta version"),
             Self::Verification(_) => write!(f, "Verification failure"),
             Self::Internal => write!(f, "Internal error"),
@@ -109,8 +120,8 @@ impl<'a> fmt::Display for SlotVerifyError<'a> {
 /// `AVB_SLOT_VERIFY_RESULT_OK` to the Rust equivalent `Ok(())` and errors to the corresponding
 /// `Err(SlotVerifyError)`.
 ///
-/// A `Verification` error returned here will always have a `None` `SlotVerifyData`; the data should
-/// be added in later if it exists.
+/// An error returned here will always have a `None` `SlotVerifyData`; the data should be added
+/// in later if it exists.
 ///
 /// This function is also important to serve as a compile-time check that we're handling all the
 /// libavb enums; if a new one is added to (or removed from) the C code, this will fail to compile
@@ -129,10 +140,10 @@ pub(crate) fn slot_verify_enum_to_result(
         AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_IO => Err(SlotVerifyError::Io),
         AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_OOM => Err(SlotVerifyError::Oom),
         AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED => {
-            Err(SlotVerifyError::PublicKeyRejected)
+            Err(SlotVerifyError::PublicKeyRejected(None))
         }
         AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX => {
-            Err(SlotVerifyError::RollbackIndex)
+            Err(SlotVerifyError::RollbackIndex(None))
         }
         AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_UNSUPPORTED_VERSION => {
             Err(SlotVerifyError::UnsupportedVersion)
diff --git a/rust/src/lib.rs b/rust/src/lib.rs
index 99962ab..f39075e 100644
--- a/rust/src/lib.rs
+++ b/rust/src/lib.rs
@@ -36,6 +36,7 @@ pub use cert::{
     cert_generate_unlock_challenge, cert_validate_unlock_credential,
     cert_validate_vbmeta_public_key, CertOps, CertPermanentAttributes, CertUnlockChallenge,
     CertUnlockCredential, CERT_PIK_VERSION_LOCATION, CERT_PSK_VERSION_LOCATION, SHA256_DIGEST_SIZE,
+    SHA512_DIGEST_SIZE,
 };
 pub use descriptor::{
     ChainPartitionDescriptor, ChainPartitionDescriptorFlags, Descriptor, DescriptorError,
diff --git a/rust/src/verify.rs b/rust/src/verify.rs
index bea2275..1fa736a 100644
--- a/rust/src/verify.rs
+++ b/rust/src/verify.rs
@@ -237,14 +237,14 @@ pub struct SlotVerifyData<'a> {
 }
 
 // Useful so that `SlotVerifyError`, which may hold a `SlotVerifyData`, can derive `PartialEq`.
-impl<'a> PartialEq for SlotVerifyData<'a> {
+impl PartialEq for SlotVerifyData<'_> {
     fn eq(&self, other: &Self) -> bool {
         // A `SlotVerifyData` uniquely owns the underlying data so is only equal to itself.
         ptr::eq(self, other)
     }
 }
 
-impl<'a> Eq for SlotVerifyData<'a> {}
+impl Eq for SlotVerifyData<'_> {}
 
 impl<'a> SlotVerifyData<'a> {
     /// Creates a `SlotVerifyData` wrapping the given raw `AvbSlotVerifyData`.
@@ -351,7 +351,7 @@ impl<'a> SlotVerifyData<'a> {
 }
 
 /// Frees any internally-allocated and owned data.
-impl<'a> Drop for SlotVerifyData<'a> {
+impl Drop for SlotVerifyData<'_> {
     fn drop(&mut self) {
         // SAFETY:
         // * `raw_data` points to a valid `AvbSlotVerifyData` object owned by us.
@@ -364,7 +364,7 @@ impl<'a> Drop for SlotVerifyData<'a> {
 ///
 /// This implementation will print the slot, partition name, and verification status for all
 /// vbmetadata and images.
-impl<'a> fmt::Display for SlotVerifyData<'a> {
+impl fmt::Display for SlotVerifyData<'_> {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         write!(
             f,
@@ -378,7 +378,7 @@ impl<'a> fmt::Display for SlotVerifyData<'a> {
 
 /// Forwards to `Display` formatting; the default `Debug` formatting implementation isn't very
 /// useful as it's mostly raw pointer addresses.
-impl<'a> fmt::Debug for SlotVerifyData<'a> {
+impl fmt::Debug for SlotVerifyData<'_> {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         fmt::Display::fmt(self, f)
     }
@@ -428,7 +428,7 @@ pub fn slot_verify<'a>(
 
     // To be more Rust idiomatic we allow `ab_suffix` to be `None`, but libavb requires a valid
     // pointer to an empty string in this case, not NULL.
-    let ab_suffix = ab_suffix.unwrap_or(CStr::from_bytes_with_nul(b"\0").unwrap());
+    let ab_suffix = ab_suffix.unwrap_or(c"");
 
     let ops_bridge = pin!(ops::OpsBridge::new(ops));
     let mut out_data: *mut AvbSlotVerifyData = null_mut();
@@ -465,7 +465,11 @@ pub fn slot_verify<'a>(
     match result {
         // libavb will always provide verification data on success.
         Ok(()) => Ok(data.unwrap()),
-        // Data may also be provided on verification failure, fold it into the error.
+        // Data may also be provided on non-fatal failures, fold it into the error.
+        Err(SlotVerifyError::PublicKeyRejected(None)) => {
+            Err(SlotVerifyError::PublicKeyRejected(data))
+        }
+        Err(SlotVerifyError::RollbackIndex(None)) => Err(SlotVerifyError::RollbackIndex(data)),
         Err(SlotVerifyError::Verification(None)) => Err(SlotVerifyError::Verification(data)),
         // No other error provides verification data.
         Err(e) => Err(e),
diff --git a/rust/tests/cert_tests.rs b/rust/tests/cert_tests.rs
index 171fffb..4412545 100644
--- a/rust/tests/cert_tests.rs
+++ b/rust/tests/cert_tests.rs
@@ -27,7 +27,7 @@ use avb::{
 };
 use hex::decode;
 use std::{collections::HashMap, fs, mem::size_of};
-use zerocopy::{AsBytes, FromBytes};
+use zerocopy::{FromBytes, IntoBytes};
 
 /// Initializes a `TestOps` object such that cert verification will succeed on
 /// `TEST_PARTITION_NAME`.
@@ -49,18 +49,12 @@ fn build_test_cert_ops_one_image_one_vbmeta<'a>() -> TestOps<'a> {
     let perm_attr_bytes = fs::read(TEST_CERT_PERMANENT_ATTRIBUTES_PATH).unwrap();
     ops.cert_permanent_attributes =
         Some(CertPermanentAttributes::read_from(&perm_attr_bytes[..]).unwrap());
-    ops.cert_permanent_attributes_hash = Some(
-        decode(TEST_CERT_PERMANENT_ATTRIBUTES_HASH_HEX)
-            .unwrap()
-            .try_into()
-            .unwrap(),
-    );
+    ops.cert_permanent_attributes_hash =
+        Some(decode(TEST_CERT_PERMANENT_ATTRIBUTES_HASH_HEX).unwrap().try_into().unwrap());
 
     // Add the rollbacks for the cert keys.
-    ops.rollbacks
-        .insert(CERT_PIK_VERSION_LOCATION, Ok(TEST_CERT_PIK_VERSION));
-    ops.rollbacks
-        .insert(CERT_PSK_VERSION_LOCATION, Ok(TEST_CERT_PSK_VERSION));
+    ops.rollbacks.insert(CERT_PIK_VERSION_LOCATION, Ok(TEST_CERT_PIK_VERSION));
+    ops.rollbacks.insert(CERT_PSK_VERSION_LOCATION, Ok(TEST_CERT_PSK_VERSION));
 
     // It's non-trivial to sign a challenge without `avbtool.py`, so instead we inject the exact RNG
     // used by the pre-generated challenge so that we can use the pre-signed credential.
@@ -130,30 +124,22 @@ fn cert_verify_sets_key_rollbacks() {
 fn cert_verify_fails_with_pik_rollback_violation() {
     let mut ops = build_test_cert_ops_one_image_one_vbmeta();
     // If the image is signed with a lower key version than our rollback, it should fail to verify.
-    *ops.rollbacks
-        .get_mut(&CERT_PIK_VERSION_LOCATION)
-        .unwrap()
-        .as_mut()
-        .unwrap() += 1;
+    *ops.rollbacks.get_mut(&CERT_PIK_VERSION_LOCATION).unwrap().as_mut().unwrap() += 1;
 
     let result = verify_one_image_one_vbmeta(&mut ops);
 
-    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected);
+    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected(None));
 }
 
 #[test]
 fn cert_verify_fails_with_psk_rollback_violation() {
     let mut ops = build_test_cert_ops_one_image_one_vbmeta();
     // If the image is signed with a lower key version than our rollback, it should fail to verify.
-    *ops.rollbacks
-        .get_mut(&CERT_PSK_VERSION_LOCATION)
-        .unwrap()
-        .as_mut()
-        .unwrap() += 1;
+    *ops.rollbacks.get_mut(&CERT_PSK_VERSION_LOCATION).unwrap().as_mut().unwrap() += 1;
 
     let result = verify_one_image_one_vbmeta(&mut ops);
 
-    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected);
+    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected(None));
 }
 
 #[test]
@@ -164,7 +150,7 @@ fn cert_verify_fails_with_wrong_vbmeta_key() {
 
     let result = verify_one_image_one_vbmeta(&mut ops);
 
-    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected);
+    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected(None));
 }
 
 #[test]
@@ -175,7 +161,7 @@ fn cert_verify_fails_with_bad_permanent_attributes_hash() {
 
     let result = verify_one_image_one_vbmeta(&mut ops);
 
-    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected);
+    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected(None));
 }
 
 #[test]
@@ -185,10 +171,7 @@ fn cert_generate_unlock_challenge_succeeds() {
     let challenge = cert_generate_unlock_challenge(&mut ops).unwrap();
 
     // Make sure the challenge token used our cert callback data correctly.
-    assert_eq!(
-        challenge.product_id_hash,
-        &decode(TEST_CERT_PRODUCT_ID_HASH_HEX).unwrap()[..]
-    );
+    assert_eq!(challenge.product_id_hash, &decode(TEST_CERT_PRODUCT_ID_HASH_HEX).unwrap()[..]);
     assert_eq!(challenge.challenge, UNLOCK_CHALLENGE_FAKE_RNG);
 }
 
@@ -199,10 +182,7 @@ fn cert_generate_unlock_challenge_fails_without_permanent_attributes() {
     // Challenge generation should fail without the product ID provided by the permanent attributes.
     ops.cert_permanent_attributes = None;
 
-    assert_eq!(
-        cert_generate_unlock_challenge(&mut ops).unwrap_err(),
-        IoError::Io
-    );
+    assert_eq!(cert_generate_unlock_challenge(&mut ops).unwrap_err(), IoError::Io);
 }
 
 #[test]
@@ -212,10 +192,7 @@ fn cert_generate_unlock_challenge_fails_insufficient_rng() {
     // Remove a byte of RNG so there isn't enough.
     ops.cert_fake_rng.pop();
 
-    assert_eq!(
-        cert_generate_unlock_challenge(&mut ops).unwrap_err(),
-        IoError::Io
-    );
+    assert_eq!(cert_generate_unlock_challenge(&mut ops).unwrap_err(), IoError::Io);
 }
 
 #[test]
@@ -226,10 +203,7 @@ fn cert_validate_unlock_credential_success() {
     // call this function so the libavb_cert internal state is ready for the unlock cred.
     let _ = cert_generate_unlock_challenge(&mut ops).unwrap();
 
-    assert_eq!(
-        cert_validate_unlock_credential(&mut ops, &test_unlock_credential()),
-        Ok(true)
-    );
+    assert_eq!(cert_validate_unlock_credential(&mut ops, &test_unlock_credential()), Ok(true));
 }
 
 #[test]
@@ -240,10 +214,7 @@ fn cert_validate_unlock_credential_fails_wrong_rng() {
 
     let _ = cert_generate_unlock_challenge(&mut ops).unwrap();
 
-    assert_eq!(
-        cert_validate_unlock_credential(&mut ops, &test_unlock_credential()),
-        Ok(false)
-    );
+    assert_eq!(cert_validate_unlock_credential(&mut ops, &test_unlock_credential()), Ok(false));
 }
 
 #[test]
@@ -251,18 +222,11 @@ fn cert_validate_unlock_credential_fails_with_pik_rollback_violation() {
     let mut ops = build_test_cert_ops_one_image_one_vbmeta();
     // Rotating the PIK should invalidate all existing unlock keys, which includes our pre-signed
     // certificate.
-    *ops.rollbacks
-        .get_mut(&CERT_PIK_VERSION_LOCATION)
-        .unwrap()
-        .as_mut()
-        .unwrap() += 1;
+    *ops.rollbacks.get_mut(&CERT_PIK_VERSION_LOCATION).unwrap().as_mut().unwrap() += 1;
 
     let _ = cert_generate_unlock_challenge(&mut ops).unwrap();
 
-    assert_eq!(
-        cert_validate_unlock_credential(&mut ops, &test_unlock_credential()),
-        Ok(false)
-    );
+    assert_eq!(cert_validate_unlock_credential(&mut ops, &test_unlock_credential()), Ok(false));
 }
 
 #[test]
@@ -270,10 +234,7 @@ fn cert_validate_unlock_credential_fails_no_challenge() {
     let mut ops = build_test_cert_ops_one_image_one_vbmeta();
 
     // We never called `cert_generate_unlock_challenge()`, so no credentials should validate.
-    assert_eq!(
-        cert_validate_unlock_credential(&mut ops, &test_unlock_credential()),
-        Ok(false)
-    );
+    assert_eq!(cert_validate_unlock_credential(&mut ops, &test_unlock_credential()), Ok(false));
 }
 
 // In practice, devices will usually be passing unlock challenges and credentials over fastboot as
@@ -286,7 +247,7 @@ fn cert_validate_unlock_credential_bytes_api() {
     // Write an unlock challenge to a byte buffer for TX over fastboot.
     let challenge = cert_generate_unlock_challenge(&mut ops).unwrap();
     let mut buffer = vec![0u8; size_of::<CertUnlockChallenge>()];
-    assert_eq!(challenge.write_to(&mut buffer[..]), Some(())); // zerocopy::AsBytes.
+    assert!(challenge.write_to_prefix(&mut buffer[..]).is_ok()); // zerocopy::IntoBytes.
 
     // Read an unlock credential from a byte buffer for RX from fastboot.
     let buffer = vec![0u8; size_of::<CertUnlockCredential>()];
@@ -294,8 +255,5 @@ fn cert_validate_unlock_credential_bytes_api() {
 
     // It shouldn't actually validate since the credential is just zeroes, the important thing
     // is that it compiles.
-    assert_eq!(
-        cert_validate_unlock_credential(&mut ops, credential),
-        Ok(false)
-    );
+    assert_eq!(cert_validate_unlock_credential(&mut ops, credential), Ok(false));
 }
diff --git a/rust/tests/test_ops.rs b/rust/tests/test_ops.rs
index c7985ae..58e6e30 100644
--- a/rust/tests/test_ops.rs
+++ b/rust/tests/test_ops.rs
@@ -30,7 +30,7 @@ pub enum PartitionContents<'a> {
     Preloaded(&'a [u8]),
 }
 
-impl<'a> PartitionContents<'a> {
+impl PartitionContents<'_> {
     /// Returns the partition data.
     pub fn as_slice(&self) -> &[u8] {
         match self {
@@ -391,7 +391,7 @@ impl<'a> Ops<'a> for TestOps<'a> {
     }
 }
 
-impl<'a> CertOps for TestOps<'a> {
+impl CertOps for TestOps<'_> {
     fn read_permanent_attributes(
         &mut self,
         attributes: &mut CertPermanentAttributes,
diff --git a/rust/tests/verify_tests.rs b/rust/tests/verify_tests.rs
index a5e67c5..45c15c3 100644
--- a/rust/tests/verify_tests.rs
+++ b/rust/tests/verify_tests.rs
@@ -464,7 +464,7 @@ fn rollback_violation_fails_verification() {
     let result = verify_one_image_one_vbmeta(&mut ops);
 
     let error = result.unwrap_err();
-    assert!(matches!(error, SlotVerifyError::RollbackIndex));
+    assert!(matches!(error, SlotVerifyError::RollbackIndex(None)));
 }
 
 #[test]
@@ -489,7 +489,7 @@ fn untrusted_vbmeta_keys_fails_verification() {
     let result = verify_one_image_one_vbmeta(&mut ops);
 
     let error = result.unwrap_err();
-    assert!(matches!(error, SlotVerifyError::PublicKeyRejected));
+    assert!(matches!(error, SlotVerifyError::PublicKeyRejected(None)));
 }
 
 #[test]
@@ -629,9 +629,8 @@ fn corrupted_image_verification_data_display() {
     );
 
     let error = result.unwrap_err();
-    let data = match error {
-        SlotVerifyError::Verification(Some(data)) => data,
-        _ => panic!("Expected verification data to exist"),
+    let SlotVerifyError::Verification(Some(data)) = error else {
+        panic!("Expected Verification with verification data");
     };
     assert_eq!(
         format!("{data}"),
@@ -639,6 +638,56 @@ fn corrupted_image_verification_data_display() {
     );
 }
 
+#[test]
+fn invalid_public_key_verification_data_provided() {
+    let mut ops = build_test_ops_one_image_one_vbmeta();
+    ops.default_vbmeta_key = Some(FakeVbmetaKey::Avb {
+        public_key: b"not_the_key".into(),
+        public_key_metadata: None,
+    });
+
+    let result = slot_verify(
+        &mut ops,
+        &[&CString::new(TEST_PARTITION_NAME).unwrap()],
+        None,
+        SlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
+        HashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_EIO,
+    );
+
+    let error = result.unwrap_err();
+    let SlotVerifyError::PublicKeyRejected(Some(data)) = error else {
+        panic!("Expected PublicKeyRejected with verification data");
+    };
+    assert_eq!(
+        format!("{data}"),
+        r#"slot: "", vbmeta: ["vbmeta": Ok(())], images: ["test_part": Ok(())]"#
+    );
+}
+
+#[test]
+fn invalid_rollback_index_verification_data_provided() {
+    let mut ops = build_test_ops_one_image_one_vbmeta();
+    // Device with rollback = 1 should refuse to boot image with rollback = 0.
+    ops.rollbacks.insert(TEST_VBMETA_ROLLBACK_LOCATION, Ok(1));
+
+    let result = slot_verify(
+        &mut ops,
+        &[&CString::new(TEST_PARTITION_NAME).unwrap()],
+        None,
+        SlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
+        HashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_EIO,
+    );
+
+    let error = result.unwrap_err();
+    let SlotVerifyError::RollbackIndex(Some(data)) = error else {
+        panic!("Expected RollbackIndex with verification data");
+    };
+    assert_eq!(
+        format!("{data}"),
+        r#"slot: "", vbmeta: ["vbmeta": Ok(())], images: ["test_part": Ok(())]"#
+    );
+}
+
 #[test]
 fn one_image_gives_single_descriptor() {
     let mut ops = build_test_ops_one_image_one_vbmeta();
diff --git a/test/avb_slot_verify_unittest.cc b/test/avb_slot_verify_unittest.cc
index 76af86a..90a4271 100644
--- a/test/avb_slot_verify_unittest.cc
+++ b/test/avb_slot_verify_unittest.cc
@@ -53,6 +53,14 @@ class AvbSlotVerifyTest : public BaseAvbToolTest,
                             bool has_system_partition);
 };
 
+// This digest appears in all tests that check the kernel commandline options
+// and use the key in "test/data/testkey_rsa2048.pem", so we check that the
+// digest is correct in a standalone test to avoid repetition.
+TEST_F(AvbSlotVerifyTest, Rsa2048TestKey) {
+  EXPECT_EQ("22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c",
+            PublicKeyAVBDigest("test/data/testkey_rsa2048.pem"));
+}
+
 TEST_F(AvbSlotVerifyTest, Basic) {
   GenerateVBMetaImage("vbmeta_a.img",
                       "SHA256_RSA2048",
@@ -74,6 +82,8 @@ TEST_F(AvbSlotVerifyTest, Basic) {
   EXPECT_NE(nullptr, slot_data);
   EXPECT_EQ(
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1152 "
@@ -114,6 +124,8 @@ TEST_F(AvbSlotVerifyTest, BasicSha512) {
   EXPECT_NE(nullptr, slot_data);
   EXPECT_EQ(
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha512 androidboot.vbmeta.size=1152 "
@@ -161,6 +173,8 @@ TEST_F(AvbSlotVerifyTest, BasicUnlocked) {
   EXPECT_NE(nullptr, slot_data);
   EXPECT_EQ(
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=unlocked "
       "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1152 "
@@ -724,13 +738,19 @@ TEST_F(AvbSlotVerifyTest, HashDescriptorInVBMeta) {
       "cmdline in vbmeta 1234-fake-guid-for:boot_a cmdline in hash footer "
       "1234-fake-guid-for:system_a "
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1472 "
       "androidboot.vbmeta.digest="
       "99e84e34697a77414f0d7dd7896e98ac4da2d26bdd3756ef59ec79918de2adbe "
       "androidboot.vbmeta.invalidate_on_error=yes "
-      "androidboot.veritymode=enforcing",
+      "androidboot.veritymode=enforcing "
+      "androidboot.vbmeta.boot.hash_alg=sha256 "
+      "androidboot.vbmeta.boot.digest="
+      "184cb36243adb8b87d2d8c4802de32125fe294ec46753d732144ee65df68a23d",
+
       std::string(slot_data->cmdline));
   EXPECT_EQ(4UL, slot_data->rollback_indexes[0]);
   for (size_t n = 1; n < AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_LOCATIONS; n++) {
@@ -1105,13 +1125,18 @@ TEST_F(AvbSlotVerifyTest, HashDescriptorInChainedPartition) {
   EXPECT_EQ(
       "cmdline2 in hash footer cmdline2 in vbmeta "
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=4416 "
       "androidboot.vbmeta.digest="
       "4a45faa9adfeb94e9154fe682c11fef1a1a3d829b67cbf1a12ac7f0aa4f8e2e4 "
       "androidboot.vbmeta.invalidate_on_error=yes "
-      "androidboot.veritymode=enforcing",
+      "androidboot.veritymode=enforcing "
+      "androidboot.vbmeta.boot.hash_alg=sha256 "
+      "androidboot.vbmeta.boot.digest="
+      "184cb36243adb8b87d2d8c4802de32125fe294ec46753d732144ee65df68a23d",
       std::string(slot_data->cmdline));
   EXPECT_EQ(11UL, slot_data->rollback_indexes[0]);
   EXPECT_EQ(12UL, slot_data->rollback_indexes[1]);
@@ -1576,13 +1601,18 @@ TEST_F(AvbSlotVerifyTest, HashDescriptorInOtherVBMetaPartition) {
   EXPECT_EQ(
       "cmdline2 in hash footer cmdline2 in vbmeta "
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=4416 "
       "androidboot.vbmeta.digest="
       "232447e92370ed31c2b6c5fb7328eb5d828a9819b3e6f6c10d96b9ca6fd209a1 "
       "androidboot.vbmeta.invalidate_on_error=yes "
-      "androidboot.veritymode=enforcing",
+      "androidboot.veritymode=enforcing "
+      "androidboot.vbmeta.boot.hash_alg=sha256 "
+      "androidboot.vbmeta.boot.digest="
+      "184cb36243adb8b87d2d8c4802de32125fe294ec46753d732144ee65df68a23d",
       std::string(slot_data->cmdline));
   EXPECT_EQ(11UL, slot_data->rollback_indexes[0]);
   EXPECT_EQ(12UL, slot_data->rollback_indexes[1]);
@@ -1922,13 +1952,18 @@ TEST_F(AvbSlotVerifyTest, ChainedPartitionNoSlots) {
   EXPECT_EQ(
       "cmdline2 in hash footer cmdline2 in vbmeta "
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=4416 "
       "androidboot.vbmeta.digest="
       "4a45faa9adfeb94e9154fe682c11fef1a1a3d829b67cbf1a12ac7f0aa4f8e2e4 "
       "androidboot.vbmeta.invalidate_on_error=yes "
-      "androidboot.veritymode=enforcing",
+      "androidboot.veritymode=enforcing "
+      "androidboot.vbmeta.boot.hash_alg=sha256 "
+      "androidboot.vbmeta.boot.digest="
+      "184cb36243adb8b87d2d8c4802de32125fe294ec46753d732144ee65df68a23d",
       std::string(slot_data->cmdline));
   EXPECT_EQ(11UL, slot_data->rollback_indexes[0]);
   EXPECT_EQ(12UL, slot_data->rollback_indexes[1]);
@@ -2214,7 +2249,8 @@ TEST_F(AvbSlotVerifyTest, NoVBMetaPartitionFlag) {
   EXPECT_EQ(size_t(2), slot_data->num_loaded_partitions);
   EXPECT_EQ("foo", std::string(slot_data->loaded_partitions[0].partition_name));
   EXPECT_EQ("bar", std::string(slot_data->loaded_partitions[1].partition_name));
-  // Note the absence of 'androidboot.vbmeta.device'
+  // Note the absence of 'androidboot.vbmeta.device' and
+  // 'androidboot.vbmeta.public_key_digest'.
   EXPECT_EQ(
       "this is=5 from foo=42 and=43 from bar "
       "androidboot.vbmeta.avb_version=1.3 "
@@ -2224,7 +2260,13 @@ TEST_F(AvbSlotVerifyTest, NoVBMetaPartitionFlag) {
       "androidboot.vbmeta.digest="
       "b5dbfb1743073f9a4cb45f94d1d849f89ca9777d158a2a06d09517c79ffd86cd "
       "androidboot.vbmeta.invalidate_on_error=yes "
-      "androidboot.veritymode=enforcing",
+      "androidboot.veritymode=enforcing "
+      "androidboot.vbmeta.foo.hash_alg=sha256 "
+      "androidboot.vbmeta.foo.digest="
+      "184cb36243adb8b87d2d8c4802de32125fe294ec46753d732144ee65df68a23d "
+      "androidboot.vbmeta.bar.hash_alg=sha256 "
+      "androidboot.vbmeta.bar.digest="
+      "baea4bbd261d0edf4d1fe5e6e5a36976c291eeba66b6a46fa81dba691327a727",
       std::string(slot_data->cmdline));
   avb_slot_verify_data_free(slot_data);
 
@@ -2280,6 +2322,8 @@ TEST_F(AvbSlotVerifyTest, PublicKeyMetadata) {
   EXPECT_NE(nullptr, slot_data);
   EXPECT_EQ(
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=2688 "
@@ -2389,6 +2433,8 @@ void AvbSlotVerifyTest::CmdlineWithHashtreeVerification(
         "restart_on_corruption ignore_zero_blocks\" root=/dev/dm-0 "
         "should_be_in_both=1 "
         "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+        "androidboot.vbmeta.public_key_digest="
+        "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
         "androidboot.vbmeta.avb_version=1.3 "
         "androidboot.vbmeta.device_state=locked "
         "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1536 "
@@ -2403,6 +2449,8 @@ void AvbSlotVerifyTest::CmdlineWithHashtreeVerification(
     EXPECT_EQ(
         "root=PARTUUID=1234-fake-guid-for:system_a should_be_in_both=1 "
         "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+        "androidboot.vbmeta.public_key_digest="
+        "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
         "androidboot.vbmeta.avb_version=1.3 "
         "androidboot.vbmeta.device_state=locked "
         "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1536 "
@@ -2570,6 +2618,8 @@ void AvbSlotVerifyTest::CmdlineWithChainedHashtreeVerification(
         "restart_on_corruption ignore_zero_blocks\" root=/dev/dm-0 "
         "should_be_in_both=1 "
         "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+        "androidboot.vbmeta.public_key_digest="
+        "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
         "androidboot.vbmeta.avb_version=1.3 "
         "androidboot.vbmeta.device_state=locked "
         "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=3456 "
@@ -2584,6 +2634,8 @@ void AvbSlotVerifyTest::CmdlineWithChainedHashtreeVerification(
     EXPECT_EQ(
         "root=PARTUUID=1234-fake-guid-for:system_a should_be_in_both=1 "
         "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+        "androidboot.vbmeta.public_key_digest="
+        "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
         "androidboot.vbmeta.avb_version=1.3 "
         "androidboot.vbmeta.device_state=locked "
         "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=3456 "
@@ -2975,13 +3027,18 @@ TEST_F(AvbSlotVerifyTest, NoVBMetaPartition) {
       "4096 4096 4096 4096 sha1 c9ffc3bfae5000269a55a56621547fd1fcf819df "
       "d00df00d 2 restart_on_corruption ignore_zero_blocks\" root=/dev/dm-0 "
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:boot "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=5312 "
       "androidboot.vbmeta.digest="
       "b297d90aa92a5d49725d1206ff1301b054c5a0214f1cb2fc12b809b317d943e4 "
       "androidboot.vbmeta.invalidate_on_error=yes "
-      "androidboot.veritymode=enforcing",
+      "androidboot.veritymode=enforcing "
+      "androidboot.vbmeta.boot.hash_alg=sha256 "
+      "androidboot.vbmeta.boot.digest="
+      "4c109399b20e476bab15363bff55740add83e1c1e97e0b132f5c713ddd8c7868",
       std::string(slot_data->cmdline));
   avb_slot_verify_data_free(slot_data);
 }
@@ -3144,6 +3201,8 @@ TEST_F(AvbSlotVerifyTest, HashtreeErrorModes) {
       "c9ffc3bfae5000269a55a56621547fd1fcf819df d00df00d 2 "
       "restart_on_corruption ignore_zero_blocks\" root=/dev/dm-0 "
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 "
@@ -3174,6 +3233,8 @@ TEST_F(AvbSlotVerifyTest, HashtreeErrorModes) {
       "c9ffc3bfae5000269a55a56621547fd1fcf819df d00df00d 2 "
       "restart_on_corruption ignore_zero_blocks\" root=/dev/dm-0 "
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 "
@@ -3203,6 +3264,8 @@ TEST_F(AvbSlotVerifyTest, HashtreeErrorModes) {
       "c9ffc3bfae5000269a55a56621547fd1fcf819df d00df00d 2 "
       "ignore_zero_blocks ignore_zero_blocks\" root=/dev/dm-0 "
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 "
@@ -3244,6 +3307,8 @@ TEST_F(AvbSlotVerifyTest, HashtreeErrorModes) {
       "c9ffc3bfae5000269a55a56621547fd1fcf819df d00df00d 2 "
       "ignore_corruption ignore_zero_blocks\" root=/dev/dm-0 "
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 "
@@ -3284,6 +3349,8 @@ TEST_F(AvbSlotVerifyTest, HashtreeErrorModes) {
     EXPECT_EQ(
         "root=PARTUUID=1234-fake-guid-for:system "
         "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
+        "androidboot.vbmeta.public_key_digest="
+        "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
         "androidboot.vbmeta.avb_version=1.3 "
         "androidboot.vbmeta.device_state=locked "
         "androidboot.vbmeta.hash_alg=sha256 "
@@ -3474,6 +3541,8 @@ TEST_F(AvbSlotVerifyTestWithPersistentDigest, Basic) {
   Verify(true /* expect_success */);
   EXPECT_EQ(
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 "
@@ -3481,7 +3550,10 @@ TEST_F(AvbSlotVerifyTestWithPersistentDigest, Basic) {
       "androidboot.vbmeta.digest="
       "f7a4ce48092379fe0e913ffda10d859cd5fc19fa721c9e81f05f8bfea14b9873 "
       "androidboot.vbmeta.invalidate_on_error=yes "
-      "androidboot.veritymode=enforcing",
+      "androidboot.veritymode=enforcing "
+      "androidboot.vbmeta.factory.hash_alg=sha256 "
+      "androidboot.vbmeta.factory.digest="
+      "2e7cab6314e9614b6f2da12630661c3038e5592025f6534ba5823c3b340a1cb6",
       last_cmdline_);
 }
 
@@ -3679,6 +3751,8 @@ TEST_F(AvbSlotVerifyTestWithPersistentDigest, Basic_Hashtree_Sha1) {
       // Note: Here appear the bytes used in write_persistent_value above.
       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 "
@@ -3706,6 +3780,8 @@ TEST_F(AvbSlotVerifyTestWithPersistentDigest, Basic_Hashtree_Sha256) {
       // Note: Here appear the bytes used in write_persistent_value above.
       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 "
@@ -3737,6 +3813,8 @@ TEST_F(AvbSlotVerifyTestWithPersistentDigest, Basic_Hashtree_Sha512) {
       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 "
@@ -4043,6 +4121,8 @@ TEST_F(AvbSlotVerifyTest, NoSystemPartition) {
   EXPECT_NE(nullptr, slot_data);
   EXPECT_EQ(
       "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
+      "androidboot.vbmeta.public_key_digest="
+      "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c "
       "androidboot.vbmeta.avb_version=1.3 "
       "androidboot.vbmeta.device_state=locked "
       "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1152 "
diff --git a/test/avb_unittest_util.cc b/test/avb_unittest_util.cc
index 41151a6..3588049 100644
--- a/test/avb_unittest_util.cc
+++ b/test/avb_unittest_util.cc
@@ -165,4 +165,16 @@ std::string BaseAvbToolTest::PublicKeyAVB(const std::string& key_path) {
   return key_data;
 }
 
+std::string BaseAvbToolTest::PublicKeyAVBDigest(const std::string& key_path) {
+  std::filesystem::path tmp_path = testdir_ / "public_key_digest";
+  EXPECT_COMMAND(0,
+                 "./avbtool.py extract_public_key_digest --key %s"
+                 " --output %s",
+                 key_path.c_str(),
+                 tmp_path.c_str());
+  std::string digest_data;
+  EXPECT_TRUE(android::base::ReadFileToString(tmp_path.string(), &digest_data));
+  return digest_data;
+}
+
 }  // namespace avb
diff --git a/test/avb_unittest_util.h b/test/avb_unittest_util.h
index 781877a..3726acd 100644
--- a/test/avb_unittest_util.h
+++ b/test/avb_unittest_util.h
@@ -93,6 +93,11 @@ class BaseAvbToolTest : public ::testing::Test {
   /* Returns public key in AVB format for a .pem key */
   std::string PublicKeyAVB(const std::string& key_path);
 
+  /* Returns a hex string containing the SHA-256 digest of the public key in AVB
+   * format for a .pem key.
+   */
+  std::string PublicKeyAVBDigest(const std::string& key_path);
+
   void SetUp() override;
   void TearDown() override;
 
diff --git a/test/avbtool_unittest.cc b/test/avbtool_unittest.cc
index e1d14d8..d3792cd 100644
--- a/test/avbtool_unittest.cc
+++ b/test/avbtool_unittest.cc
@@ -416,6 +416,42 @@ TEST_F(AvbToolTest, Info) {
       InfoImage(vbmeta_image_path_.string()));
 }
 
+TEST_F(AvbToolTest, InfoWithPublicKey) {
+  GenerateVBMetaImage("vbmeta.img",
+      "SHA256_RSA2048",
+      0,
+      "test/data/testkey_rsa2048.pem",
+      "--internal_release_string \"\"");
+
+  std::string key_data = PublicKeyAVB("test/data/testkey_rsa2048.pem");
+
+  AvbVBMetaImageHeader h;
+  avb_vbmeta_image_header_to_host_byte_order(
+      reinterpret_cast<AvbVBMetaImageHeader*>(vbmeta_image_.data()), &h);
+  uint8_t* d = reinterpret_cast<uint8_t*>(vbmeta_image_.data());
+  size_t auxiliary_data_block_offset =
+      sizeof(AvbVBMetaImageHeader) + h.authentication_data_block_size;
+  EXPECT_GT(h.auxiliary_data_block_size, key_data.size());
+  EXPECT_EQ(0,
+            memcmp(key_data.data(),
+                   d + auxiliary_data_block_offset + h.public_key_offset,
+                   key_data.size()));
+
+  // Extracts the public key of vbmeta.img into vbmeta_pubkey.bin.
+  std::filesystem::path output_pubkey = testdir_ / "vbmeta_pubkey.bin";
+  EXPECT_COMMAND(0,
+                 "./avbtool.py info_image --image %s "
+                 "--output_pubkey %s",
+                 vbmeta_image_path_.c_str(),
+                 output_pubkey.c_str());
+  std::string output_pubkey_data;
+  ASSERT_TRUE(android::base::ReadFileToString(
+      output_pubkey.string(), &output_pubkey_data));
+
+  // Compare the extracted public key with the original key.
+  EXPECT_EQ(key_data, output_pubkey_data);
+}
+
 static bool collect_descriptors(const AvbDescriptor* descriptor,
                                 void* user_data) {
   std::vector<const AvbDescriptor*>* descriptors =
diff --git a/tools/transparency/verify/README.md b/tools/transparency/verify/README.md
index 32a7d18..e60158a 100644
--- a/tools/transparency/verify/README.md
+++ b/tools/transparency/verify/README.md
@@ -1,10 +1,16 @@
 # Verifier of Binary Transparency for Pixel Factory Images
 
-This repository contains code to read the transparency log for [Pixel Factory Images Binary Transparency](https://developers.google.com/android/binary_transparency/pixel_overview). See the particular section for this tool [here](https://developers.google.com/android/binary_transparency/pixel_verification#verifying-image-inclusion-inclusion-proof).
+This repository contains code to read the transparency log for two logs:
+  * [Pixel Factory Images Binary Transparency](https://developers.google.com/android/binary_transparency/pixel_overview).
+  * [Google System APK Transparency](https://developers.google.com/android/binary_transparency/google1p/overview)
+
+See the particular section for this tool:
+  * [Pixel](https://developers.google.com/android/binary_transparency/pixel_verification#verifying-image-inclusion-inclusion-proof)
+  * [Google System APKs](https://developers.google.com/android/binary_transparency/google1p/verification_details#verifying_package_inclusion_inclusion_proof)
 
 ## Files and Directories
 * `cmd/verifier/`
-  * Contains the binary to read the transparency log. It is embedded with the public key of the log to verify log identity.
+  * Contains the binary to read any of the transparency logs. It is embedded with the public keys of the logs to verify log identity.
 * `internal/`
   * Internal libraries for the verifier binary.
 
@@ -14,24 +20,38 @@ This module requires Go 1.17. Install [here](https://go.dev/doc/install), and ru
 An executable named `verifier` should be produced upon successful build.
 
 ## Usage
-The verifier uses the checkpoint and the log contents (found at the [tile directory](https://developers.google.com/android/binary_transparency/tile)) to check that your image payload is in the transparency log, i.e. that it is published by Google.
+The verifier uses the associated checkpoint (depending on the target log) and the log contents to check that your candidate binary is included in the transparency log, i.e. that it is published by Google. The tile directory for each supported log is listed below:
+  * Pixel Transparency Log
+    * `https://developers.google.com/android/binary_transparency/tile/`
+  * Google System APK Transparency Log
+    * `https://developers.google.com/android/binary_transparency/google1p/tile/`
 
 To run the verifier after you have built it in the previous section:
 ```
-$ ./verifier --payload_path=${PAYLOAD_PATH}
+$ ./verifier --payload_path=${PAYLOAD_PATH} --log_type=<log_type>
 ```
+where `log_type` is either `pixel` or `google_system_apk`.
 
 ### Input
-The verifier takes a `payload_path` as input.
+The verifier takes a `payload_path` and a `log_type `as input.
 
+#### Pixel
 Each Pixel Factory image corresponds to a [payload](https://developers.google.com/android/binary_transparency/pixel_overview#log_content) stored in the transparency log, the format of which is:
 ```
 <build_fingerprint>\n<vbmeta_digest>\n
 ```
 See [here](https://developers.google.com/android/binary_transparency/pixel_verification#construct-the-payload-for-verification) for a few methods detailing how to extract this payload from an image.
 
+#### Google System APK
+Each Google System APK corresponds to a [payload](https://developers.google.com/android/binary_transparency/google1p/overview#log_content) stored in the transparency log, the format of which is:
+```
+<hash>\n<hash_description>\n<package_name>\n<package_version_code>\n
+```
+
+Currently, `hash_description` is fixed as `SHA256(Signed Code Transparency JWT)`.
+See [here](https://developers.google.com/android/binary_transparency/google1p/verification_details#construct_a_payload_for_verification) to find out how to construct this payload from a candidate APK.
+
 ### Output
 The output of the command is written to stdout:
-  * `OK` if the image is included in the log, i.e. that this [claim](https://developers.google.com/android/binary_transparency/pixel_overview#claimant_model) is true,
-  * `FAILURE` otherwise.
-
+  * `OK. inclusion check success!` if the candidate binary is included in the log. Depending on which log, this means either the [Pixel claim](https://developers.google.com/android/binary_transparency/pixel_overview#claimant_model) or the [Google System APK claim](https://developers.google.com/android/binary_transparency/google1p/overview#claimant_model) is true,
+  * `FAILURE` otherwise.
\ No newline at end of file
```

