```diff
diff --git a/METADATA b/METADATA
index df77656..11a747f 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,19 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update sonic
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/sonic
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "sonic"
 description: "Sonic is a simple algorithm for speeding up or slowing down speech."
 third_party {
-  url {
-    type: ARCHIVE
-    value: "https://github.com/waywardgeek/sonic/archive/8694c596378c24e340c09ff2cd47c065494233f1.zip"
-  }
-  version: "8694c596378c24e340c09ff2cd47c065494233f1"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2023
-    month: 10
-    day: 13
+    year: 2025
+    month: 2
+    day: 3
+  }
+  identifier {
+    type: "Archive"
+    value: "https://github.com/waywardgeek/sonic/archive/36910922b6a76e2fc0cc2889f8750a422768f973.zip"
+    version: "36910922b6a76e2fc0cc2889f8750a422768f973"
   }
 }
diff --git a/Makefile b/Makefile
index 5e99ad1..044db4f 100644
--- a/Makefile
+++ b/Makefile
@@ -69,8 +69,8 @@ EXTRA_OBJ=$(EXTRA_SRC:.c=.o)
 
 all: sonic sonic_lite $(LIB_NAME)$(LIB_TAG) libsonic.a libsonic_internal.a $(LIB_INTERNAL_NAME)$(LIB_TAG)
 
-sonic: wave.o main.o libsonic.a
-	$(CC) $(CFLAGS) $(LDFLAGS) -o sonic wave.o main.o libsonic.a -lm $(FFTLIB)
+sonic: main.o libsonic.a
+	$(CC) $(CFLAGS) $(LDFLAGS) -o sonic main.o libsonic.a -lm $(FFTLIB)
 
 sonic_lite: wave.c main_lite.c sonic_lite.c sonic_lite.h
 	$(CC) $(CFLAGS) $(LDFLAGS) -o sonic_lite sonic_lite.c wave.c main_lite.c
diff --git a/sonic.c b/sonic.c
index d04f015..eb7c9b8 100644
--- a/sonic.c
+++ b/sonic.c
@@ -391,7 +391,7 @@ static int allocateStreamBuffers(sonicStream stream, int sampleRate,
   /* Allocate 25% more than needed so we hopefully won't grow. */
   stream->pitchBufferSize = maxRequired + (maxRequired >> 2);
   stream->pitchBuffer =
-      (short*)sonicCalloc(maxRequired, sizeof(short) * numChannels);
+      (short*)sonicCalloc(stream->pitchBufferSize, sizeof(short) * numChannels);
   if (stream->pitchBuffer == NULL) {
     sonicDestroyStream(stream);
     return 0;
@@ -887,15 +887,12 @@ static int moveNewSamplesToPitchBuffer(sonicStream stream,
                                        int originalNumOutputSamples) {
   int numSamples = stream->numOutputSamples - originalNumOutputSamples;
   int numChannels = stream->numChannels;
+  int pitchBufferSize = stream->pitchBufferSize;
 
-  if (stream->numPitchSamples + numSamples > stream->pitchBufferSize) {
-    int pitchBufferSize = stream->pitchBufferSize;
+  if (stream->numPitchSamples + numSamples > pitchBufferSize) {
     stream->pitchBufferSize += (pitchBufferSize >> 1) + numSamples;
-    stream->pitchBuffer = (short*)sonicRealloc(
-        stream->pitchBuffer,
-        pitchBufferSize,
-        stream->pitchBufferSize,
-        sizeof(short) * numChannels);
+    stream->pitchBuffer = (short*)sonicRealloc(stream->pitchBuffer,
+        pitchBufferSize, stream->pitchBufferSize, sizeof(short) * numChannels);
   }
   memcpy(stream->pitchBuffer + stream->numPitchSamples * numChannels,
          stream->outputBuffer + originalNumOutputSamples * numChannels,
diff --git a/sonic.h b/sonic.h
index f393dce..8c7076a 100644
--- a/sonic.h
+++ b/sonic.h
@@ -251,8 +251,6 @@ struct sonicBitmapStruct {
   int numCols;
 };
 
-typedef struct sonicBitmapStruct* sonicBitmap;
-
 /* Enable coomputation of a spectrogram on the fly. */
 void sonicComputeSpectrogram(sonicStream stream);
 
diff --git a/spectrogram.c b/spectrogram.c
index 6305130..e24a898 100644
--- a/spectrogram.c
+++ b/spectrogram.c
@@ -7,7 +7,7 @@
 */
 
 #ifdef  KISS_FFT
-#include <stddef.h>  /* kiss_fft.h failes to load this */
+#include <stddef.h>  /* kiss_fft.h fails to load this */
 #include <kiss_fft.h>
 #include <kiss_fft_impl.h>
 #else
@@ -370,3 +370,8 @@ int sonicWritePGM(sonicBitmap bitmap, char* fileName) {
   fclose(file);
   return 1;
 }
+
+#ifdef	MAIN
+main(){
+}
+#endif
```

