```diff
diff --git a/utils/tinyplay.c b/utils/tinyplay.c
index d617074..da3c5e7 100644
--- a/utils/tinyplay.c
+++ b/utils/tinyplay.c
@@ -261,16 +261,19 @@ void print_usage(const char *argv0)
 {
     fprintf(stderr, "usage: %s file.wav [options]\n", argv0);
     fprintf(stderr, "options:\n");
-    fprintf(stderr, "-D | --card   <card number>    The card to receive the audio\n");
-    fprintf(stderr, "-d | --device <device number>  The device to receive the audio\n");
-    fprintf(stderr, "-p | --period-size <size>      The size of the PCM's period\n");
-    fprintf(stderr, "-n | --period-count <count>    The number of PCM periods\n");
-    fprintf(stderr, "-i | --file-type <file-type>   The type of file to read (raw or wav)\n");
-    fprintf(stderr, "-c | --channels <count>        The amount of channels per frame\n");
-    fprintf(stderr, "-r | --rate <rate>             The amount of frames per second\n");
-    fprintf(stderr, "-b | --bits <bit-count>        The number of bits in one sample\n");
-    fprintf(stderr, "-f | --float                   The frames are in floating-point PCM\n");
-    fprintf(stderr, "-M | --mmap                    Use memory mapped IO to play audio\n");
+    fprintf(stderr, "-D | --card   <card number>     The card to receive the audio\n");
+    fprintf(stderr, "-d | --device <device number>   The device to receive the audio\n");
+    fprintf(stderr, "-p | --period-size <size>       The size of the PCM's period\n");
+    fprintf(stderr, "-n | --period-count <count>     The number of PCM periods\n");
+    fprintf(stderr, "-i | --file-type <file-type>    The type of file to read (raw or wav)\n");
+    fprintf(stderr, "-c | --channels <count>         The amount of channels per frame\n");
+    fprintf(stderr, "-r | --rate <rate>              The amount of frames per second\n");
+    fprintf(stderr, "-b | --bits <bit-count>         The number of bits in one sample\n");
+    fprintf(stderr, "-f | --float                    The frames are in floating-point PCM\n");
+    fprintf(stderr, "-M | --mmap                     Use memory mapped IO to play audio\n");
+    fprintf(stderr, "-s | --silence-threshold <size> The minimum number of frames to silence the PCM\n");
+    fprintf(stderr, "-t | --start-threshold <size>   The minimum number of frames required to start the PCM\n");
+    fprintf(stderr, "-T | --stop-threshold <size>    The minimum number of frames required to stop the PCM\n");
 }
 
 int main(int argc, char **argv)
@@ -280,17 +283,20 @@ int main(int argc, char **argv)
     struct ctx ctx;
     struct optparse opts;
     struct optparse_long long_options[] = {
-        { "card",         'D', OPTPARSE_REQUIRED },
-        { "device",       'd', OPTPARSE_REQUIRED },
-        { "period-size",  'p', OPTPARSE_REQUIRED },
-        { "period-count", 'n', OPTPARSE_REQUIRED },
-        { "file-type",    'i', OPTPARSE_REQUIRED },
-        { "channels",     'c', OPTPARSE_REQUIRED },
-        { "rate",         'r', OPTPARSE_REQUIRED },
-        { "bits",         'b', OPTPARSE_REQUIRED },
-        { "float",        'f', OPTPARSE_NONE     },
-        { "mmap",         'M', OPTPARSE_NONE     },
-        { "help",         'h', OPTPARSE_NONE     },
+        { "card",              'D', OPTPARSE_REQUIRED },
+        { "device",            'd', OPTPARSE_REQUIRED },
+        { "period-size",       'p', OPTPARSE_REQUIRED },
+        { "period-count",      'n', OPTPARSE_REQUIRED },
+        { "file-type",         'i', OPTPARSE_REQUIRED },
+        { "channels",          'c', OPTPARSE_REQUIRED },
+        { "rate",              'r', OPTPARSE_REQUIRED },
+        { "bits",              'b', OPTPARSE_REQUIRED },
+        { "float",             'f', OPTPARSE_NONE     },
+        { "mmap",              'M', OPTPARSE_NONE     },
+        { "help",              'h', OPTPARSE_NONE     },
+        { "silence-threshold", 's', OPTPARSE_REQUIRED },
+        { "start-threshold",   't', OPTPARSE_REQUIRED },
+        { "stop-threshold",    'T', OPTPARSE_REQUIRED },
         { 0, 0, 0 }
     };
 
@@ -301,6 +307,9 @@ int main(int argc, char **argv)
 
     cmd_init(&cmd);
     optparse_init(&opts, argv);
+    unsigned silence_threshold = 0;
+    unsigned start_threshold = 0;
+    unsigned stop_threshold = 0;
     while ((c = optparse_long(&opts, long_options, NULL)) != -1) {
         switch (c) {
         case 'D':
@@ -354,6 +363,24 @@ int main(int argc, char **argv)
         case 'M':
             cmd.flags |= PCM_MMAP;
             break;
+        case 's':
+            if (sscanf(opts.optarg, "%u", &silence_threshold) != 1) {
+                fprintf(stderr, "failed parsing silence threshold '%s'\n", argv[1]);
+                return EXIT_FAILURE;
+            }
+            break;
+        case 't':
+            if (sscanf(opts.optarg, "%u", &start_threshold) != 1) {
+                fprintf(stderr, "failed parsing start threshold '%s'\n", argv[1]);
+                return EXIT_FAILURE;
+            }
+            break;
+        case 'T':
+            if (sscanf(opts.optarg, "%u", &stop_threshold) != 1) {
+                fprintf(stderr, "failed parsing stop threshold '%s'\n", argv[1]);
+                return EXIT_FAILURE;
+            }
+            break;
         case 'h':
             print_usage(argv[0]);
             return EXIT_SUCCESS;
@@ -373,6 +400,16 @@ int main(int argc, char **argv)
     cmd.config.stop_threshold = cmd.config.period_size * cmd.config.period_count;
     cmd.config.start_threshold = cmd.config.period_size;
 
+    if (silence_threshold != 0) {
+      cmd.config.silence_threshold = silence_threshold;
+    }
+    if (start_threshold != 0) {
+      cmd.config.start_threshold = start_threshold;
+    }
+    if (stop_threshold != 0) {
+      cmd.config.stop_threshold = stop_threshold;
+    }
+
     if (ctx_init(&ctx, &cmd) < 0) {
         return EXIT_FAILURE;
     }
```

