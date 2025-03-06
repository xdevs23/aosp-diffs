```diff
diff --git a/Android.bp b/Android.bp
index 7644dad..49694e3 100644
--- a/Android.bp
+++ b/Android.bp
@@ -47,6 +47,7 @@ cc_library_static {
         "//external/webrtc:__subpackages__",
         "//frameworks/av/media/libaudioclient/tests",
         "//hardware/interfaces/audio/aidl/vts",
+        "//vendor:__subpackages__",
     ],
     cflags: [
         "-Wno-#pragma-messages",
diff --git a/LICENSE b/LICENSE
new file mode 100644
index 0000000..1ee09cd
--- /dev/null
+++ b/LICENSE
@@ -0,0 +1,38 @@
+
+Copyright (c) 2020  Dario Mambro ( dario.mambro@gmail.com )
+Copyright (c) 2019  Hayati Ayguen ( h_ayguen@web.de )
+Copyright (c) 2013  Julien Pommier ( pommier@modartt.com )
+
+Copyright (c) 2004 the University Corporation for Atmospheric
+Research ("UCAR"). All rights reserved. Developed by NCAR's
+Computational and Information Systems Laboratory, UCAR,
+www.cisl.ucar.edu.
+
+Redistribution and use of the Software in source and binary forms,
+with or without modification, is permitted provided that the
+following conditions are met:
+
+- Neither the names of NCAR's Computational and Information Systems
+Laboratory, the University Corporation for Atmospheric Research,
+nor the names of its sponsors or contributors may be used to
+endorse or promote products derived from this Software without
+specific prior written permission.  
+
+- Redistributions of source code must retain the above copyright
+notices, this list of conditions, and the disclaimer below.
+
+- Redistributions in binary form must reproduce the above copyright
+notice, this list of conditions, and the disclaimer below in the
+documentation and/or other materials provided with the
+distribution.
+
+THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO THE WARRANTIES OF
+MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
+NONINFRINGEMENT. IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT
+HOLDERS BE LIABLE FOR ANY CLAIM, INDIRECT, INCIDENTAL, SPECIAL,
+EXEMPLARY, OR CONSEQUENTIAL DAMAGES OR OTHER LIABILITY, WHETHER IN AN
+ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
+CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE
+SOFTWARE.
+
```

