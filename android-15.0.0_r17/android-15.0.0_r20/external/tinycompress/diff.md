```diff
diff --git a/compress.c b/compress.c
index ac2c73f..027d36d 100644
--- a/compress.c
+++ b/compress.c
@@ -619,6 +619,25 @@ int compress_wait(struct compress *compress, int timeout_ms)
 	return oops(compress, EIO, "poll signalled unhandled event");
 }
 
+int compress_set_codec_params(struct compress *compress,
+	struct snd_codec *codec) {
+	struct snd_compr_params params;
+
+	if (!is_compress_ready(compress) || !compress->next_track)
+		return oops(compress, ENODEV, "device not ready");
+
+	params.buffer.fragment_size = compress->config->fragment_size;
+	params.buffer.fragments = compress->config->fragments;
+	memcpy(&params.codec, codec, sizeof(params.codec));
+	memcpy(&compress->config->codec, codec, sizeof(struct snd_codec));
+
+	if (compress->ops->ioctl(compress->data, SNDRV_COMPRESS_SET_PARAMS, &params))
+		return oops(compress, errno, "cannot set device");
+
+	compress->next_track = 0;
+	return 0;
+}
+
 #ifdef ENABLE_EXTENDED_COMPRESS_FORMAT
 int compress_get_metadata(struct compress *compress,
 		struct snd_compr_metadata *mdata) {
diff --git a/compress_plugin.c b/compress_plugin.c
index 7a5538d..eac0f38 100644
--- a/compress_plugin.c
+++ b/compress_plugin.c
@@ -84,7 +84,9 @@ static int compress_plug_set_params(struct compress_plug_data *plug_data,
 	struct compress_plugin *plugin = plug_data->plugin;
 	int rc;
 
-	if (plugin->state != COMPRESS_PLUG_STATE_OPEN)
+	if (plugin->state == COMPRESS_PLUG_STATE_RUNNING)
+		return plugin->ops->set_params(plugin, params);
+	else if (plugin->state != COMPRESS_PLUG_STATE_OPEN)
 		return -EBADFD;
 
 	if (params->buffer.fragment_size == 0 ||
diff --git a/include/tinycompress/tinycompress.h b/include/tinycompress/tinycompress.h
index 0ab7134..d430e4d 100644
--- a/include/tinycompress/tinycompress.h
+++ b/include/tinycompress/tinycompress.h
@@ -309,6 +309,17 @@ const char *compress_get_error(struct compress *compress);
 /* utility functions */
 unsigned int compress_get_alsa_rate(unsigned int rate);
 
+ /*
+  * compress_set_codec_params: set codec config intended for next track
+  * if DSP has support to switch CODEC config during gapless playback
+  * This API is expected to be called after compress_next_track is called
+  * return 0 on success, negative on error
+  *
+  * @compress: compress stream for which metadata has to set
+  * @codec: codec configuration for next track
+  */
+int compress_set_codec_params(struct compress *compress, struct snd_codec *codec);
+
 #ifdef ENABLE_EXTENDED_COMPRESS_FORMAT
 /* set metadata */
 int compress_set_metadata(struct compress *compress,
```

