```diff
diff --git a/Android.bp b/Android.bp
index 4a84d24..979245b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -17,15 +17,15 @@ package {
 }
 
 license {
-    name: "external_wayland-protocols_freedesktop.org-MIT-license",
+    name: "external_wayland-protocols-MIT-license",
     license_kinds: [
         "SPDX-license-identifier-MIT",
     ],
-    license_text: ["freedesktop.org/COPYING"],
+    license_text: ["MIT_LICENSE.txt"],
 }
 
 license {
-    name: "external_wayland-protocols_freedesktop.org-ISC-license",
+    name: "external_wayland-protocols-ISC-license",
     license_kinds: [
         "SPDX-license-identifier-ISC",
     ],
@@ -33,11 +33,11 @@ license {
 }
 
 license {
-    name: "external_wayland-protocols_chromium.org-license",
+    name: "external_wayland-protocols-BSD-license",
     license_kinds: [
-        "SPDX-license-identifier-MIT",
+        "SPDX-license-identifier-BSD",
     ],
-    license_text: ["chromium.org/LICENSE"],
+    license_text: ["BSD_LICENSE.txt"],
 }
 
 // Build and use the "wayland_protocol_codegen" extension. This is just a bit
@@ -64,11 +64,13 @@ bootstrap_go_package {
 // All the MIT licensed freedesktop.org defined extension protocols.
 filegroup {
     name: "freedesktop.org-MIT-wayland_extension_protocols",
-    licenses: ["external_wayland-protocols_freedesktop.org-MIT-license"],
+    licenses: ["external_wayland-protocols-MIT-license"],
     srcs: [
         "./freedesktop.org/stable/presentation-time/presentation-time.xml",
         "./freedesktop.org/stable/viewporter/viewporter.xml",
         "./freedesktop.org/stable/xdg-shell/xdg-shell.xml",
+        "./freedesktop.org/staging/drm-lease/drm-lease-v1.xml",
+        "./freedesktop.org/staging/xdg-activation/xdg-activation-v1.xml",
         "./freedesktop.org/unstable/fullscreen-shell/fullscreen-shell-unstable-v1.xml",
         "./freedesktop.org/unstable/idle-inhibit/idle-inhibit-unstable-v1.xml",
         "./freedesktop.org/unstable/input-method/input-method-unstable-v1.xml",
@@ -97,18 +99,55 @@ filegroup {
 // All the ISC licensed freedesktop.org defined extension protocols.
 filegroup {
     name: "freedesktop.org-ISC-wayland_extension_protocols",
-    licenses: ["external_wayland-protocols_freedesktop.org-ISC-license"],
+    licenses: ["external_wayland-protocols-ISC-license"],
     srcs: [
         "./freedesktop.org/unstable/text-input/text-input-unstable-v3.xml",
     ],
 }
 
-// All the chromium.org defined extension protocols.
+// All the BSD licensed freedesktop.org defined extension protocols.
+filegroup {
+    name: "freedesktop.org-BSD-wayland_extension_protocols",
+    licenses: ["external_wayland-protocols-BSD-license"],
+    srcs: [
+    ],
+}
+
+// All the BSD licensed chromium.org defined extension protocols.
 filegroup {
     name: "chromium.org-wayland_extension_protocols",
-    licenses: ["external_wayland-protocols_chromium.org-license"],
+    licenses: ["external_wayland-protocols-BSD-license"],
+    srcs: [
+        "./chromium.org/components/exo/wayland/protocol/aura-output-management.xml",
+        "./chromium.org/components/exo/wayland/protocol/aura-shell.xml",
+        "./chromium.org/components/exo/wayland/protocol/chrome-color-management.xml",
+        "./chromium.org/components/exo/wayland/protocol/overlay-prioritizer.xml",
+        "./chromium.org/components/exo/wayland/protocol/surface-augmenter.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/alpha-compositing/alpha-compositing-unstable-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/cursor-shapes/cursor-shapes-unstable-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/extended-drag/extended-drag-unstable-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/gaming-input/gaming-input-unstable-v2.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/keyboard/keyboard-configuration-unstable-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/keyboard/keyboard-extension-unstable-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/notification-shell/notification-shell-unstable-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/remote-shell/remote-shell-unstable-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/remote-shell/remote-shell-unstable-v2.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/secure-output/secure-output-unstable-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/stylus-tools/stylus-tools-unstable-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/stylus/stylus-unstable-v2.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/text-input/text-input-extension-unstable-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/touchpad-haptics/touchpad-haptics-unstable-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/ui-controls/ui-controls-unstable-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/vsync-feedback/vsync-feedback-unstable-v1.xml",
+    ],
+}
+
+filegroup {
+    name: "chromium.org-MIT-wayland_extension_protocols",
+    licenses: ["external_wayland-protocols-MIT-license"],
     srcs: [
-        "chromium.org/**/*.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/content-type/content-type-v1.xml",
+        "./chromium.org/third_party/wayland-protocols/unstable/gtk-primary-selection/gtk-primary-selection.xml",
     ],
 }
 
@@ -116,9 +155,11 @@ filegroup {
 filegroup {
     name: "wayland_extension_protocols",
     srcs: [
+        ":freedesktop.org-BSD-wayland_extension_protocols",
         ":freedesktop.org-MIT-wayland_extension_protocols",
         ":freedesktop.org-ISC-wayland_extension_protocols",
         ":chromium.org-wayland_extension_protocols",
+        ":chromium.org-MIT-wayland_extension_protocols",
     ],
 }
 
diff --git a/BSD_LICENSE.txt b/BSD_LICENSE.txt
new file mode 100644
index 0000000..018ad9a
--- /dev/null
+++ b/BSD_LICENSE.txt
@@ -0,0 +1,27 @@
+Copyright 2015 The Chromium Authors
+
+Redistribution and use in source and binary forms, with or without
+modification, are permitted provided that the following conditions are
+met:
+
+* Redistributions of source code must retain the above copyright
+notice, this list of conditions and the following disclaimer.
+* Redistributions in binary form must reproduce the above
+copyright notice, this list of conditions and the following disclaimer
+in the documentation and/or other materials provided with the
+distribution.
+* Neither the name of Google LLC nor the names of its
+contributors may be used to endorse or promote products derived from
+this software without specific prior written permission.
+
+THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
+A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
+OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
+SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
+LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
+DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
+THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
+OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
diff --git a/MIT_LICENSE.txt b/MIT_LICENSE.txt
new file mode 100644
index 0000000..8ab3291
--- /dev/null
+++ b/MIT_LICENSE.txt
@@ -0,0 +1,33 @@
+Copyright © 2008-2013 Kristian Høgsberg
+Copyright © 2010-2013 Intel Corporation
+Copyright © 2013      Rafael Antognolli
+Copyright © 2013      Jasper St. Pierre
+Copyright © 2014      Jonas Ådahl
+Copyright © 2014      Jason Ekstrand
+Copyright © 2014-2015 Collabora, Ltd.
+Copyright © 2015      Red Hat Inc.
+
+Permission is hereby granted, free of charge, to any person obtaining a
+copy of this software and associated documentation files (the "Software"),
+to deal in the Software without restriction, including without limitation
+the rights to use, copy, modify, merge, publish, distribute, sublicense,
+and/or sell copies of the Software, and to permit persons to whom the
+Software is furnished to do so, subject to the following conditions:
+
+The above copyright notice and this permission notice (including the next
+paragraph) shall be included in all copies or substantial portions of the
+Software.
+
+THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
+FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
+DEALINGS IN THE SOFTWARE.
+
+---
+
+The above is the version of the MIT "Expat" License used by X.org:
+
+    http://cgit.freedesktop.org/xorg/xserver/tree/COPYING
diff --git a/README.android b/README.android
index 76ee8c7..8c2bde4 100644
--- a/README.android
+++ b/README.android
@@ -1,53 +1,24 @@
-These instructions are for the Android external/wayland-protcools repository.
-
 ## Updating from upstream
 
-### Update the freedesktop.org/ directory
-
-  1. Checkout the upstream sources to a working directory if you haven't
-     already with
-     `git clone git://anongit.freedesktop.org/wayland/wayland-protocols`,
-     or otherwise pull down the latest changes if you have a checkout.
-  2. Sync to the desired release tag (`git tag -l` to view them)
-     `git checkout $TAG`
-  3. The freedesktop.org/ directory here should be a simple copy of this
-     checkout. A tool such as `meld` can be used to view and apply the
-     differences.
-     `meld freedesktop.org/ /path/to/freedesktop.org/wayland-protocols/`
-  4. Note that we add NOTICE, MODULE_LICENSE_MIT and METADATA files as part of
-     our policies around open source code. Leave these alone unless there is
-     a reason to change them.
-       * NOTICE should duplicate COPYING from upstream.
-       * MODULE_LICENSE_MIT should match the source code license.
-       * METADATA should indicate the version of the upstream source used, and
-         should be updated to match.
+### Update the freedesktop.org/ subdirectory
+
+1) Run import_snapshot.py freedesktop.org $VERSION
+
+```sh
+# Determine the actual version you want from gitlab.freedesktop.org/wayland/wayland-protocols
+cd path/to/external/wayland-protocols
+./import_snapshot.py freedesktop.org 1.32
+```
+
+2) Modify the top-level Android.bp to reference any new .xml protocol files.
 
 ### Update the chromium.org/ directory
 
-  1. Checkout Chromium sources if you haven't already with
-     `git clone https://chromium.googlesource.com/chromium/src.git`, or
-     otherwise pull down the latest changes. This is a large checkout
-     unfortunately, even though we only want a small subset of it.
-  2. Sync to the desired release tag, or just use master if you would like.
-  3. The chromium.org/ directory should ba a **PARTIAL** copy of
-     src/third_party/wayland-protocols from your checkout. In particular these
-     should match:
-       * chromium.org/unstable/ and src/third_party/wayland-protocols/unstable/
-       * chromium.org/LICENSE and src/third_party/wayland-protocols/LICENSE
-       * chromium.org/README.chromium and src/third_party/wayland-protocols/README.chromium
-     We **do not** need:
-       * src/third_party/wayland-protocols/include/ and
-         src/third_party/wayland-protocols/protocol both contain source code
-         generated from the protocol files, which is not needed here.
-       * src/third_party/wayland-protocols/src (if you have it) is itself a clone
-         of a version of the freedesktop.org upstream sources.
-       * src/third_party/wayland-protocols/OWNERS causes trouble with Android
-         Gerrit.
-       * src/third_party/wayland-protocols/BUILD.gn.
-  4. Note that we add NOTICE, MODULE_LICENSE_MIT and METADATA files as part of
-     our policies around open source code. Leave these alone unless there is
-     a reason to change them.
-       * NOTICE should duplicate LICENSE from upstream.
-       * MODULE_LICENSE_MIT should match the source code license.
-       * METADATA should indicate the version of the upstream source used, and
-         should be updated to match.
+1) Run import_snapshot.py chromium.org main
+
+```sh
+cd path/to/external/wayland-protocols
+./import_snapshot.py chromium.org main
+```
+
+2) Modify the top-level Android.bp to reference any new .xml protocol files.
diff --git a/chromium.org/LICENSE b/chromium.org/LICENSE
index 8ab3291..2249a28 100644
--- a/chromium.org/LICENSE
+++ b/chromium.org/LICENSE
@@ -1,33 +1,27 @@
-Copyright © 2008-2013 Kristian Høgsberg
-Copyright © 2010-2013 Intel Corporation
-Copyright © 2013      Rafael Antognolli
-Copyright © 2013      Jasper St. Pierre
-Copyright © 2014      Jonas Ådahl
-Copyright © 2014      Jason Ekstrand
-Copyright © 2014-2015 Collabora, Ltd.
-Copyright © 2015      Red Hat Inc.
-
-Permission is hereby granted, free of charge, to any person obtaining a
-copy of this software and associated documentation files (the "Software"),
-to deal in the Software without restriction, including without limitation
-the rights to use, copy, modify, merge, publish, distribute, sublicense,
-and/or sell copies of the Software, and to permit persons to whom the
-Software is furnished to do so, subject to the following conditions:
-
-The above copyright notice and this permission notice (including the next
-paragraph) shall be included in all copies or substantial portions of the
-Software.
-
-THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
-THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
-FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
-DEALINGS IN THE SOFTWARE.
-
----
-
-The above is the version of the MIT "Expat" License used by X.org:
-
-    http://cgit.freedesktop.org/xorg/xserver/tree/COPYING
+// Copyright 2015 The Chromium Authors
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions are
+// met:
+//
+//    * Redistributions of source code must retain the above copyright
+// notice, this list of conditions and the following disclaimer.
+//    * Redistributions in binary form must reproduce the above
+// copyright notice, this list of conditions and the following disclaimer
+// in the documentation and/or other materials provided with the
+// distribution.
+//    * Neither the name of Google LLC nor the names of its
+// contributors may be used to endorse or promote products derived from
+// this software without specific prior written permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
+// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
+// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
+// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
+// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
+// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
+// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
+// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
diff --git a/chromium.org/METADATA b/chromium.org/METADATA
index 9939af6..1f8d026 100644
--- a/chromium.org/METADATA
+++ b/chromium.org/METADATA
@@ -9,7 +9,7 @@ third_party {
     type: GIT
     value: "https://chromium.googlesource.com/chromium/src.git/+/main/components/exo/wayland/protocol"
   }
-  version: "97f4417444a6d90d4501b4e878745d6bdf5d49dc"
-  last_upgrade_date { year: 2017 month: 11 day: 29 }
+  version: "126.0.6457.1"
+  last_upgrade_date { year: 2024 month: 7 day: 23 }
   license_type: NOTICE
 }
diff --git a/chromium.org/MODULE_LICENSE_MIT b/chromium.org/MODULE_LICENSE_MIT
deleted file mode 100644
index e69de29..0000000
diff --git a/chromium.org/README.chromium b/chromium.org/README.chromium
deleted file mode 100644
index 3527d0e..0000000
--- a/chromium.org/README.chromium
+++ /dev/null
@@ -1,66 +0,0 @@
-Name: wayland-protocols
-URL: http://wayland.freedesktop.org/
-Version: 1.8
-License: MIT
-License File: src/COPYING
-Security Critical: yes
-
-Description:
-wayland-protocols contains Wayland protocols that adds functionality not
-available in the Wayland core protocol. Such protocols either adds
-completely new functionality, or extends the functionality of some other
-protocol either in Wayland core, or some other protocol in
-wayland-protocols.
-
-To import a new snapshot of wayland-protocols:
-- Checkout the latest release tag: git checkout 1.8
-- Change the DEPS entry to the newly checked out commit.
-- Update generated files:
-    wayland-scanner code < src/unstable/xdg-shell/xdg-shell-unstable-v5.xml > protocol/xdg-shell-v5-protocol.c
-    wayland-scanner server-header < src/unstable/xdg-shell/xdg-shell-unstable-v5.xml > include/protocol/xdg-shell-unstable-v5-server-protocol.h
-    wayland-scanner client-header < src/unstable/xdg-shell/xdg-shell-unstable-v5.xml > include/protocol/xdg-shell-unstable-v5-client-protocol.h
-    wayland-scanner code < src/unstable/xdg-shell/xdg-shell-unstable-v6.xml > protocol/xdg-shell-v6-protocol.c
-    wayland-scanner server-header < src/unstable/xdg-shell/xdg-shell-unstable-v6.xml > include/protocol/xdg-shell-unstable-v6-server-protocol.h
-    wayland-scanner client-header < src/unstable/xdg-shell/xdg-shell-unstable-v6.xml > include/protocol/xdg-shell-unstable-v6-client-protocol.h
-    wayland-scanner code < src/unstable/linux-dmabuf/linux-dmabuf-unstable-v1.xml > protocol/linux-dmabuf-protocol.c
-    wayland-scanner server-header < src/unstable/linux-dmabuf/linux-dmabuf-unstable-v1.xml > include/protocol/linux-dmabuf-unstable-v1-server-protocol.h
-    wayland-scanner client-header < src/unstable/linux-dmabuf/linux-dmabuf-unstable-v1.xml > include/protocol/linux-dmabuf-unstable-v1-client-protocol.h
-    wayland-scanner code < src/stable/viewporter/viewporter.xml > protocol/viewporter-protocol.c
-    wayland-scanner server-header < src/stable/viewporter/viewporter.xml > include/protocol/viewporter-server-protocol.h
-    wayland-scanner client-header < src/stable/viewporter/viewporter.xml > include/protocol/viewporter-client-protocol.h
-    wayland-scanner code < src/stable/presentation-time/presentation-time.xml > protocol/presentation-time-protocol.c
-    wayland-scanner server-header < src/stable/presentation-time/presentation-time.xml > include/protocol/presentation-time-server-protocol.h
-    wayland-scanner client-header < src/stable/presentation-time/presentation-time.xml > include/protocol/presentation-time-client-protocol.h
-    wayland-scanner code < unstable/secure-output/secure-output-unstable-v1.xml > protocol/secure-output-protocol.c
-    wayland-scanner server-header < unstable/secure-output/secure-output-unstable-v1.xml > include/protocol/secure-output-unstable-v1-server-protocol.h
-    wayland-scanner client-header < unstable/secure-output/secure-output-unstable-v1.xml > include/protocol/secure-output-unstable-v1-client-protocol.h
-    wayland-scanner code < unstable/alpha-compositing/alpha-compositing-unstable-v1.xml > protocol/alpha-compositing-protocol.c
-    wayland-scanner server-header < unstable/alpha-compositing/alpha-compositing-unstable-v1.xml > include/protocol/alpha-compositing-unstable-v1-server-protocol.h
-    wayland-scanner client-header < unstable/alpha-compositing/alpha-compositing-unstable-v1.xml > include/protocol/alpha-compositing-unstable-v1-client-protocol.h
-    wayland-scanner code < unstable/remote-shell/remote-shell-unstable-v1.xml > protocol/remote-shell-protocol.c
-    wayland-scanner server-header < unstable/remote-shell/remote-shell-unstable-v1.xml > include/protocol/remote-shell-unstable-v1-server-protocol.h
-    wayland-scanner client-header < unstable/remote-shell/remote-shell-unstable-v1.xml > include/protocol/remote-shell-unstable-v1-client-protocol.h
-    wayland-scanner code < unstable/vsync-feedback/vsync-feedback-unstable-v1.xml > protocol/vsync-feedback-protocol.c
-    wayland-scanner server-header < unstable/vsync-feedback/vsync-feedback-unstable-v1.xml > include/protocol/vsync-feedback-unstable-v1-server-protocol.h
-    wayland-scanner client-header < unstable/vsync-feedback/vsync-feedback-unstable-v1.xml > include/protocol/vsync-feedback-unstable-v1-client-protocol.h
-    wayland-scanner code < unstable/gaming-input/gaming-input-unstable-v1.xml > protocol/gaming-input-protocol-v1.c
-    wayland-scanner server-header < unstable/gaming-input/gaming-input-unstable-v1.xml > include/protocol/gaming-input-unstable-v1-server-protocol.h
-    wayland-scanner client-header < unstable/gaming-input/gaming-input-unstable-v1.xml > include/protocol/gaming-input-unstable-v1-client-protocol.h
-    wayland-scanner code < unstable/gaming-input/gaming-input-unstable-v2.xml > protocol/gaming-input-protocol-v2.c
-    wayland-scanner server-header < unstable/gaming-input/gaming-input-unstable-v2.xml > include/protocol/gaming-input-unstable-v2-server-protocol.h
-    wayland-scanner client-header < unstable/gaming-input/gaming-input-unstable-v2.xml > include/protocol/gaming-input-unstable-v2-client-protocol.h
-    wayland-scanner code < unstable/stylus/stylus-unstable-v2.xml > protocol/stylus-protocol-v2.c
-    wayland-scanner server-header < unstable/stylus/stylus-unstable-v2.xml > include/protocol/stylus-unstable-v2-server-protocol.h
-    wayland-scanner client-header < unstable/stylus/stylus-unstable-v2.xml > include/protocol/stylus-unstable-v2-client-protocol.h
-    wayland-scanner code < unstable/keyboard/keyboard-configuration-unstable-v1.xml > protocol/keyboard-configuration-protocol.c
-    wayland-scanner server-header < unstable/keyboard/keyboard-configuration-unstable-v1.xml > include/protocol/keyboard-configuration-unstable-v1-server-protocol.h
-    wayland-scanner client-header < unstable/keyboard/keyboard-configuration-unstable-v1.xml > include/protocol/keyboard-configuration-unstable-v1-client-protocol.h
-    wayland-scanner code < unstable/stylus-tools/stylus-tools-unstable-v1.xml > protocol/stylus-tools-protocol.c
-    wayland-scanner server-header < unstable/stylus-tools/stylus-tools-unstable-v1.xml > include/protocol/stylus-tools-unstable-v1-server-protocol.h
-    wayland-scanner client-header < unstable/stylus-tools/stylus-tools-unstable-v1.xml > include/protocol/stylus-tools-unstable-v1-client-protocol.h
-    wayland-scanner code < unstable/keyboard/keyboard-extension-unstable-v1.xml > protocol/keyboard-extension-protocol.c
-    wayland-scanner server-header < unstable/keyboard/keyboard-extension-unstable-v1.xml > include/protocol/keyboard-extension-unstable-v1-server-protocol.h
-    wayland-scanner client-header < unstable/keyboard/keyboard-extension-unstable-v1.xml > include/protocol/keyboard-extension-unstable-v1-client-protocol.h
-    wayland-scanner client-header < src/unstable/pointer-gestures/pointer-gestures-unstable-v1.xml > include/protocol/pointer-gestures-unstable-v1-client-protocol.h
-    wayland-scanner server-header < src/unstable/pointer-gestures/pointer-gestures-unstable-v1.xml > include/protocol/pointer-gestures-unstable-v1-server-protocol.h
-- Update this README to reflect the new version number.
diff --git a/chromium.org/components/exo/wayland/protocol/BUILD.gn b/chromium.org/components/exo/wayland/protocol/BUILD.gn
new file mode 100644
index 0000000..3217be3
--- /dev/null
+++ b/chromium.org/components/exo/wayland/protocol/BUILD.gn
@@ -0,0 +1,24 @@
+# Copyright 2018 The Chromium Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
+import("//third_party/wayland/wayland_protocol.gni")
+
+wayland_protocol("aura_output_management_protocol") {
+  sources = [ "aura-output-management.xml" ]
+}
+
+wayland_protocol("aura_shell_protocol") {
+  sources = [ "aura-shell.xml" ]
+}
+
+wayland_protocol("chrome_color_management_protocol") {
+  sources = [ "chrome-color-management.xml" ]
+}
+
+wayland_protocol("surface_augmenter_protocol") {
+  sources = [ "surface-augmenter.xml" ]
+}
+
+wayland_protocol("overlay_prioritizer_protocol") {
+  sources = [ "overlay-prioritizer.xml" ]
+}
diff --git a/chromium.org/unstable/aura-output-management/aura-output-management.xml b/chromium.org/components/exo/wayland/protocol/aura-output-management.xml
similarity index 100%
rename from chromium.org/unstable/aura-output-management/aura-output-management.xml
rename to chromium.org/components/exo/wayland/protocol/aura-output-management.xml
diff --git a/chromium.org/unstable/aura-shell/aura-shell.xml b/chromium.org/components/exo/wayland/protocol/aura-shell.xml
similarity index 97%
rename from chromium.org/unstable/aura-shell/aura-shell.xml
rename to chromium.org/components/exo/wayland/protocol/aura-shell.xml
index c94c40c..b77eead 100644
--- a/chromium.org/unstable/aura-shell/aura-shell.xml
+++ b/chromium.org/components/exo/wayland/protocol/aura-shell.xml
@@ -24,7 +24,7 @@
     DEALINGS IN THE SOFTWARE.
   </copyright>
 
-  <interface name="zaura_shell" version="63">
+  <interface name="zaura_shell" version="65">
     <description summary="aura_shell">
       The global interface exposing aura shell capabilities is used to
       instantiate an interface extension for a wl_surface object.
@@ -241,7 +241,9 @@
 
     <request name="set_frame_colors" since="3">
       <description summary="set the frame colors of this surface">
-	Set the frame colors.
+	Set the frame colors. This must be set before the initial
+	commit first, otherwise the subsequent request may not be
+	fulfilled.
       </description>
       <arg name="active_color" type="uint" summary="32 bit ARGB color value, not premultiplied"/>
       <arg name="inactive_color" type="uint" summary="32 bit ARGB color value, not premultiplied"/>
@@ -805,7 +807,7 @@
     </event>
   </interface>
 
-  <interface name="zaura_toplevel" version="63">
+  <interface name="zaura_toplevel" version="65">
     <description summary="aura shell interface to the toplevel shell">
       An interface to the toplevel shell, which allows the
       client to access shell specific functionality.
@@ -924,6 +926,16 @@
           The window is in PiP mode.
         </description>
       </entry>
+      <entry name="pinned" value="106" since="64">
+        <description summary="window is pinned">
+          The window is pinned.
+        </description>
+      </entry>
+      <entry name="trusted_pinned" value="107" since="64">
+        <description summary="window is trusted pinned">
+          The window is trusted pinned.
+        </description>
+      </entry>
     </enum>
 
     <event name="origin_change" since="29">
@@ -975,8 +987,10 @@
     <request name="set_decoration" since="35">
       <description summary="request a decoration for surface">
         Clients are allowed to request a particular decoration for a
-        zaura_toplevel. The server is not required to honor this request. See
-        decoration_type for available options. Available since M105.
+        zaura_toplevel. The server is not required to honor this
+        request. See decoration_type for available options. This must
+        be set before the initial commit first, otherwise the
+        subsequent request may not be fulfilled. Available since M105.
       </description>
       <arg name="type" type="uint" summary="the new frame type"/>
     </request>
@@ -1091,6 +1105,14 @@
       <description summary="Sets the behavior of the surface in fullscreen.">
         Suggests how the windowing manager should behave if this surface were
         to go fullscreen. Does not make the surface fullscreen.
+
+        In precise, if the surface is not in fullscreen yet, switching the mode
+        does not have immediate impact from the client side perspective, but
+        will change the behavior when making the surface fullscreen is
+        requested next time.
+        If the surface is already in fullscreen, then this request has an
+        immediate impact to switch the fullscreen mode between plan and
+        immersive.
       </description>
       <arg name="mode" type="uint" enum="fullscreen_mode"/>
     </request>
@@ -1376,6 +1398,21 @@
       <arg name="lower_right_radius" type="uint"/>
       <arg name="lower_left_radius" type="uint"/>
     </request>
+
+    <!-- Version 65 additions -->
+    <event name="configure_occlusion_state" since="65">
+      <description summary="set the occlusion state during a configure">
+        Sets the occlusion state of this window. This should be called during a
+        configure event sequence. This is used when the occlusion state needs to
+        be set as a synchronized operation, compared to occlusion_state_changed,
+        which is not synchronized. For example, this can be used to mark a
+        window as hidden so it can discard resources. When making it visible
+        again, it may need some time to recreate its buffers, which is why this
+        operation needs to be synchronized.
+      </description>
+      <arg name="mode" type="uint" enum="occlusion_state"/>
+    </event>
+
   </interface>
 
   <interface name="zaura_popup" version="46">
@@ -1446,6 +1483,9 @@
 
   <interface name="zaura_output_manager" version="3">
     <description summary="aura shell interface to the output manager">
+      [Deprecated] Deprecated since M122. See the zaura_output_manager_v2
+      interface.
+
       A global responsible for ensuring clients have a complete view of a given
       output's state immediately following the bind of wl_output, and
       subsequently as needed.
diff --git a/chromium.org/components/exo/wayland/protocol/chrome-color-management.xml b/chromium.org/components/exo/wayland/protocol/chrome-color-management.xml
new file mode 100644
index 0000000..7d01661
--- /dev/null
+++ b/chromium.org/components/exo/wayland/protocol/chrome-color-management.xml
@@ -0,0 +1,800 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<protocol name="chrome_color_management">
+
+  <!--
+    NOTE: This protocol was forked from an upstream proposal. Once that proposal
+    is approved, we'll migrate to it. The proposal can be found at:
+    https://gitlab.freedesktop.org/wayland/wayland-protocols/-/merge_requests/14
+  -->
+
+  <copyright>
+	Copyright 2019 Sebastian Wick
+	Copyright 2019 Erwin Burema
+	Copyright 2020 AMD
+	Copyright 2020 Collabora, Ltd.
+
+	Permission is hereby granted, free of charge, to any person obtaining a
+	copy of this software and associated documentation files (the "Software"),
+	to deal in the Software without restriction, including without limitation
+	the rights to use, copy, modify, merge, publish, distribute, sublicense,
+	and/or sell copies of the Software, and to permit persons to whom the
+	Software is furnished to do so, subject to the following conditions:
+
+	The above copyright notice and this permission notice (including the next
+	paragraph) shall be included in all copies or substantial portions of the
+	Software.
+
+	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+	THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
+	FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
+	DEALINGS IN THE SOFTWARE.
+  </copyright>
+
+  <description summary="color management protocol">
+	This protocol specifies a way for a client to set the color space and
+	HDR metadata of a surface and to get information about the color spaces
+	and HDR capabilities of outputs.
+
+  This protocol is based on a proposed upstream protocol, which we will migrate
+  to once it is approved. It may diverge from the proposed upstream protocol
+  over the course of our development.
+  </description>
+
+  <interface name="zcr_color_manager_v1" version="6">
+    <description summary="color manager singleton">
+	A global interface used for getting color management surface and color
+	management output objects as well as creating color space objects from
+	ICC profiles, parameters, or enumerated names.
+    </description>
+
+    <enum name="eotf_names">
+      <description summary="well-known EOTF names">
+	Names that describe a well-known EOTF.
+
+	A compositor must support all of these based on the protocol interface
+	version.
+      </description>
+      <!-- TODO EOTFs -->
+      <!-- <entry name="bt1886" value="" summary="BT.1886 transfer function"/> -->
+      <!-- <entry name="dci_p3" value="" summary="DCI-P3 transfer function"/> -->
+      <entry name="unknown" value="0" summary="unknown EOTF"/>
+      <entry name="linear" value="1" summary="Linear transfer function"/>
+      <entry name="srgb" value="2" summary="sRGB transfer function"/>
+      <entry name="bt2087" value="3" summary="BT.2087 transfer function"/>
+      <entry name="adobergb" value="4" summary="AdobeRGB transfer function"/>
+      <entry name="pq" value="5" summary="Perceptual quantizer / SMPTEST2084"/>
+	  <entry name="hlg" value="6" summary="hybrid log gamma" since="2"/>
+      <entry name="bt709" value="7" summary="gamma for rec709 encoded videos" since="2"/>
+      <entry name="extendedsrgb10" value="8" summary="sRGB transfer function with headroom for HDR" since="2"/>
+      <entry name="smpte170m" value="9" summary="SMPTE240M transfer function" since="5"/>
+      <entry name="smpte240m" value="10" summary="SMPTE240M transfer function" since="5"/>
+      <entry name="smptest428_1" value="11" summary="SMPTEST428_1 transfer function" since="5"/>
+      <entry name="log" value="12" summary="LOG transfer function" since="5"/>
+      <entry name="log_sqrt" value="13" summary="LOG Sqrt transfer function" since="5"/>
+      <entry name="iec61966_2_4" value="14" summary="IEC61966_2_4 transfer function" since="5"/>
+      <entry name="bt1361_ecg" value="15" summary="BT1361_ECG transfer function" since="5"/>
+      <entry name="bt2020_10" value="16" summary="BT2020_10 transfer function" since="5"/>
+      <entry name="bt2020_12" value="17" summary="BT2020_12 transfer function" since="5"/>
+      <entry name="scrgb_linear_80_nits" value="18" summary="SCRGB Linear transfer function" since="5"/>
+      <entry name="gamma18" value="19" summary="GAMMA18 transfer function" since="5"/>
+      <entry name="gamma28" value="20" summary="GAMMA28 transfer function" since="5"/>
+      <entry name="srgb_hdr" value="21" summary="sRGB transfer function" since="6"/>
+    </enum>
+
+    <enum name="chromaticity_names">
+      <description summary="well-known chromaticity names">
+	Names that describe well-known chromaticities.
+
+	A compositor must support all of these based on the protocol interface
+	version.
+      </description>
+      <entry name="unknown" value="0" summary="unknown chromaticity"/>
+      <entry name="bt601_525_line" value="1"
+             summary="ITU-R BT.601 http://www.itu.int/rec/R-REC-BT.601/en"/>
+      <entry name="bt601_625_line" value="2"
+             summary="ITU-R BT.601 http://www.itu.int/rec/R-REC-BT.601/en"/>
+      <entry name="smpte170m" value="3"
+             summary="SMPTE 170M-1999 https://www.itu.int/rec/R-REC-BT.1700/en"/>
+      <entry name="bt709" value="4"
+             summary="ITU-R BT.709 https://www.itu.int/rec/R-REC-BT.709/en"/>
+      <entry name="bt2020" value="5"
+             summary="ITU-R BT.2020 http://www.itu.int/rec/R-REC-BT.2020/en"/>
+      <entry name="srgb" value="6"
+             summary="IEC/4WD 61966-2-1: sRGB https://webstore.iec.ch/publication/6169"/>
+      <entry name="displayp3" value="7"
+             summary="Display P3 https://developer.apple.com/reference/coregraphics/cgcolorspace/1408916-displayp3"/>
+      <entry name="adobergb" value="8"
+             summary="Adobe RGB https://www.adobe.com/digitalimag/pdfs/AdobeRGB1998.pdf"/>
+      <entry name="wide_gamut_color_spin" value="9"
+             summary="" since="5"/>
+      <entry name="bt470m" value="10"
+             summary="" since="5"/>
+      <entry name="smpte240m" value="11"
+             summary="" since="5"/>
+      <entry name="xyz_d50" value="12"
+             summary="" since="5"/>
+      <entry name="smptest428_1" value="13"
+             summary="" since="5"/>
+      <entry name="smptest431_2" value="14"
+             summary="" since="5"/>
+      <entry name="film" value="15"
+             summary="" since="5"/>
+    </enum>
+
+    <enum name="whitepoint_names">
+      <description summary="well-known whitepoint names">
+	Names that describe well-known whitepoints.
+
+	A compositor must support all of these based on the protocol interface
+	version.
+      </description>
+      <!-- TODO Whitepoints -->
+      <!-- <entry name="d55" value="" summary="D55 whitepoint"/> -->
+      <entry name="unknown" value="0" summary="unknown whitepoint"/>
+      <entry name="dci" value="1" summary="DCI whitepoint"/>
+      <entry name="d50" value="2" summary="D50 whitepoint"/>
+      <entry name="d65" value="3" summary="D65 whitepoint"/>
+    </enum>
+
+    <enum name="error">
+      <entry name="icc_fd" value="0" summary="given ICC fd has bad properties"/>
+      <entry name="bad_enum" value="1" summary="bad value given as a well-known name"/>
+      <entry name="bad_param" value="2" summary="bad parameter value"/>
+    </enum>
+
+    <request name="create_color_space_from_icc">
+      <description summary="create a color space object from ICC profiles">
+	Create a color space object from an ICC profile. This request returns
+	a zcr_color_space_creator_v1 object which either returns an error
+	or the successfully created zcr_color_space_v1 object.
+
+	The description of the color space to create is sent in the form of an
+	ICC profile as a file descriptor in the argument icc.
+
+	The fd must be seekable and the maximum size of the ICC profile is 4 MB.
+	Violating these requirements will raise an icc_fd protocol error. A
+	compositor must not modify the contents of the file, and the fd may be
+	sealed for writes and size changes.
+
+	The file contents must represent a valid ICC profile.
+	The ICC profile version must be 2 or 4, it must be a 3 channel profile
+	and the class must be 'input', 'output', 'abstract' or 'display'.
+	Violating these requirements will not result in a protocol error but
+	raise the zcr_color_space_creator_v1.error event.
+
+	See the zcr_color_space_v1 and zcr_color_space_creator_v1 interface for
+	more details about the created object.
+
+	See the specification from International Color Consortium for more
+	details about ICC profiles, also known as ISO 15076-1:2010.
+      </description>
+      <arg name="id" type="new_id" interface="zcr_color_space_creator_v1"/>
+      <arg name="icc" type="fd"/>
+    </request>
+
+    <request name="create_color_space_from_names">
+      <description summary="create a color space object from well-known names">
+	[Deprecated] Create a color space object from well-known names. This request returns
+	a zcr_color_space_creator_v1 object which either returns an error
+	or the successfully created zcr_color_space_v1 object.
+
+	EOTF, chromaticity and whitepoint must not be unknown. Otherwise, or
+	if a given value is not listed in the enumeration, the protocol error
+	bad_enum is raised.
+
+	See the zcr_color_space_v1 and zcr_color_space_creator_v1 interface for
+	more details about the created object. Use create_color_space_from_complete_names
+	instead.
+      </description>
+      <arg name="id" type="new_id" interface="zcr_color_space_creator_v1"/>
+      <arg name="eotf" type="uint" enum="eotf_names" summary="EOTF"/>
+      <arg name="chromaticity" type="uint" enum="chromaticity_names" summary="chromaticity"/>
+      <arg name="whitepoint" type="uint" enum="whitepoint_names" summary="whitepoint"/>
+    </request>
+
+    <request name="create_color_space_from_params">
+      <description summary="create a color space object from parameters">
+	[Deprecated] Create a color space object from parameters. This request returns
+	a zcr_color_space_creator_v1 object which either returns an error
+	or the successfully created zcr_color_space_v1 object.
+
+	EOTF must not be unknown. Otherwise, or if a given EOTF is not listed
+	in the enumeration, the protocol error bad_enum is raised.
+
+	The white point must be inside the triangle created by the red, green
+	and blue primaries. Otherwise the bad_param protocol error is raised.
+
+	All the chromaticity values are multiplied by 10000 to produce the
+	integers carried by the protocol.
+
+	See the zcr_color_space_v1 and zcr_color_space_creator_v1 interface for
+	more details about the created object. Use create_color_space_from_complete_params
+	instead.
+      </description>
+      <arg name="id" type="new_id" interface="zcr_color_space_creator_v1"/>
+      <arg name="eotf" type="uint" enum="eotf_names" summary="EOTF"/>
+      <arg name="primary_r_x" type="uint" summary="red primary X * 10000"/>
+      <arg name="primary_r_y" type="uint" summary="red primary Y * 10000"/>
+      <arg name="primary_g_x" type="uint" summary="green primary X * 10000"/>
+      <arg name="primary_g_y" type="uint" summary="green primary Y * 10000"/>
+      <arg name="primary_b_x" type="uint" summary="blue primary X * 10000"/>
+      <arg name="primary_b_y" type="uint" summary="blue primary Y * 10000"/>
+      <arg name="white_point_x" type="uint" summary="white point X * 10000"/>
+      <arg name="white_point_y" type="uint" summary="white point Y * 10000"/>
+    </request>
+
+    <request name="get_color_management_output">
+      <description summary="create a color management interface for a wl_output">
+	This creates a new zcr_color_management_output_v1 object for the
+	given wl_output.
+
+	See the zcr_color_management_output_v1 interface for more details.
+      </description>
+      <arg name="id" type="new_id" interface="zcr_color_management_output_v1"/>
+      <arg name="output" type="object" interface="wl_output"/>
+    </request>
+
+    <request name="get_color_management_surface">
+      <description summary="create a color management interface for a wl_surface">
+	This creates a new color zcr_color_management_surface_v1 object for the
+	given wl_surface.
+
+	See the zcr_color_management_surface_v1 interface for more details.
+      </description>
+      <arg name="id" type="new_id" interface="zcr_color_management_surface_v1"/>
+      <arg name="surface" type="object" interface="wl_surface"/>
+    </request>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the color manager">
+	Destroy the zcr_color_manager_v1 object. This does not affect any other
+	objects in any way.
+      </description>
+    </request>
+
+    <!-- Version 3 additions -->
+
+    <enum name="matrix_names">
+      <description summary="For specifying color matrices">
+	Names that describe typical ColorSpace Matrix IDs
+
+      </description>
+      <entry name="unknown" value="0" summary="Unknown range"/>
+      <entry name="rgb" value="1" summary="RGB matrix"/>
+      <entry name="bt709" value="2" summary="BT709 matrix"/>
+      <entry name="bt2020_ncl" value="3" summary="BT2020_NCL matrix"/>
+      <entry name="bt2020_cl" value="4" summary="BT2020_CL matrix"/>
+      <entry name="fcc" value="5" summary="FCC matrix"/>
+      <entry name="smpte170m" value="6" summary="SMPTE170M matrix"/>
+      <entry name="smpte240m" value="7" summary="SMPTE240M matrix"/>
+      <entry name="ydzdx" value="8" summary="YDZDX matrix" since="5"/>
+      <entry name="bt470bg" value="9" summary="BT470BG matrix" since="5"/>
+      <entry name="gbr" value="10" summary="GBR matrix" since="5"/>
+      <entry name="ycocg" value="11" summary="YCOCG matrix" since="5"/>
+    </enum>
+
+    <enum name="range_names">
+      <description summary="For specifying RGB ranges">
+	Names that describe typical RGB value ranges.
+
+      </description>
+      <entry name="unknown" value="0" summary="Unknown range"/>
+      <entry name="limited" value="1" summary="Limited RGB color range (values from 16-235 for 8-bit)"/>
+      <entry name="full" value="2" summary="Full RGB color range (values from 0 to 255 for 8-bit)"/>
+      <entry name="derived" value="3" summary="Range is defined by EOTF/MatrixID"/>
+    </enum>
+
+    <request name="create_color_space_from_complete_names" since="3">
+      <description summary="create a color space object from well-known names">
+	Create a color space object from well-known names. This request returns
+	a zcr_color_space_creator_v1 object which either returns an error
+	or the successfully created zcr_color_space_v1 object.
+
+	EOTF, chromaticity and whitepoint must not be unknown. Otherwise, or
+	if a given value is not listed in the enumeration, the protocol error
+	bad_enum is raised.
+
+	This request additionally includes matrix and range information.
+
+	See the zcr_color_space_v1 and zcr_color_space_creator_v1 interface for
+	more details about the created object.
+      </description>
+      <arg name="id" type="new_id" interface="zcr_color_space_creator_v1"/>
+      <arg name="eotf" type="uint" enum="eotf_names" summary="EOTF"/>
+      <arg name="chromaticity" type="uint" enum="chromaticity_names" summary="chromaticity"/>
+      <arg name="whitepoint" type="uint" enum="whitepoint_names" summary="whitepoint"/>
+      <arg name="matrix" type="uint" enum="matrix_names" summary="color matrix"/>
+      <arg name="range" type="uint" enum="range_names" summary="color range"/>
+    </request>
+
+    <request name="create_color_space_from_complete_params" since="3">
+      <description summary="create a color space object from parameters">
+	Create a color space object from parameters. This request returns
+	a zcr_color_space_creator_v1 object which either returns an error
+	or the successfully created zcr_color_space_v1 object.
+
+	EOTF must not be unknown. Otherwise, or if a given EOTF is not listed
+	in the enumeration, the protocol error bad_enum is raised.
+
+	The white point must be inside the triangle created by the red, green
+	and blue primaries. Otherwise the bad_param protocol error is raised.
+
+	All the chromaticity values are multiplied by 10000 to produce the
+	integers carried by the protocol.
+
+	This request additionally includes matrix and range information.
+
+	See the zcr_color_space_v1 and zcr_color_space_creator_v1 interface for
+	more details about the created object.
+      </description>
+      <arg name="id" type="new_id" interface="zcr_color_space_creator_v1"/>
+      <arg name="eotf" type="uint" enum="eotf_names" summary="EOTF"/>
+      <arg name="matrix" type="uint" enum="matrix_names" summary="Color matrix"/>
+      <arg name="range" type="uint" enum="range_names" summary="Color range"/>
+      <arg name="primary_r_x" type="uint" summary="red primary X * 10000"/>
+      <arg name="primary_r_y" type="uint" summary="red primary Y * 10000"/>
+      <arg name="primary_g_x" type="uint" summary="green primary X * 10000"/>
+      <arg name="primary_g_y" type="uint" summary="green primary Y * 10000"/>
+      <arg name="primary_b_x" type="uint" summary="blue primary X * 10000"/>
+      <arg name="primary_b_y" type="uint" summary="blue primary Y * 10000"/>
+      <arg name="white_point_x" type="uint" summary="white point X * 10000"/>
+      <arg name="white_point_y" type="uint" summary="white point Y * 10000"/>
+    </request>
+  </interface>
+
+  <interface name="zcr_color_management_output_v1" version="4">
+    <description summary="output color properties">
+	A zcr_color_management_output_v1 describes the color properties of an
+	output.
+
+	When zcr_color_management_output_v1 object is created, it will send
+	its initial events followed by a wl_output.done event. When creating
+	wl_output and its extension objects, use a final wl_display.sync to
+	guarantee that all output events have been received across all
+	extensions.
+
+	If the wl_output associated with the zcr_color_management_output_v1 is
+	destroyed, the zcr_color_management_output_v1 object becomes inert.
+    </description>
+
+    <event name="color_space_changed">
+      <description summary="color space changed">
+	The color_space_changed event is sent whenever the color space of the
+	output changed, followed by one wl_output.done event common to
+	output events across all extensions.
+
+	This is not an initial event.
+      </description>
+    </event>
+
+    <event name="extended_dynamic_range">
+      <description summary="output extended dynamic range">
+	This is both an initial event and sent whenever the value changed.
+	When the value changed, this event is followed by one wl_output.done
+	event common to output events across all extensions.
+
+	The extended dynamic range value describes how much dynamic range is
+	available relative to the SDR maximum white. EDR value is proportional
+	to luminance, and the luminance of black is used as the zero level.
+	A value of 1.0 means that the the display can not display
+	anything brighter than SDR maximum white. A value of 3.0 means that the
+	SDR maximum white is at one third of the highest luminance the display
+	can produce.
+
+	The absolute luminance of the SDR maximum white depends on the monitor
+	capabilities, the viewing conditions and the viewer personal
+	preferences. A such, it cannot be given a single value in cd/m².
+	Compositors using HDR video modes should allow users to control the the
+	SDR maximum white level which the output EDR value is calculated from.
+
+	The SDR maximum white is a relative reference luminance that allows
+	to tone-map content from different dynamic ranges into a single common
+	dynamic range for display.
+
+	The EDR value is multiplied by 1000 to produce the integer value
+	carried by the protocol.
+      </description>
+      <arg name="value" type="uint" summary="EDR value * 1000"/>
+    </event>
+
+    <request name="get_color_space">
+      <description summary="get the color space of the output">
+	This creates a new zcr_color_space_v1 object for the current color space
+	of the output. There always is exactly one color space active for an
+	output so the client should destroy the color space created by earlier
+	invocations of this request. This request is usually sent as a reaction
+	to the color_space_changed event or when creating a
+	zcr_color_management_output_v1 object.
+
+	The created zcr_color_space_v1 object preserves the color space
+	of the output from the time the object was created.
+
+	The resulting color space object allows get_information request.
+
+	See the zcr_color_space_v1 interface for more details.
+      </description>
+      <arg name="id" type="new_id" interface="zcr_color_space_v1"/>
+    </request>
+
+    <!-- TODO: HDR capabilities event -->
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the color management output">
+	Destroy the color zcr_color_management_output_v1 object. This does not
+	affect any remaining protocol objects.
+      </description>
+    </request>
+  </interface>
+
+  <interface name="zcr_color_management_surface_v1" version="4">
+    <description summary="color management extension to a surface">
+	A zcr_color_management_surface_v1 allows the client to set the color
+	space and HDR properties of a surface.
+
+	If the wl_surface associated with the zcr_color_management_surface_v1 is
+	destroyed, the zcr_color_management_surface_v1 object becomes inert.
+    </description>
+
+    <enum name="render_intent">
+      <description summary="render intent">
+	<!-- FIXME: rendering intent is not just a hint -->
+	Rendering intent allow the client to hint at how to perform color space
+	transformations.
+
+	See the ICC specification for more details about rendering intent.
+      </description>
+      <entry name="perceptual" value="0" summary="perceptual"/>
+      <entry name="relative" value="1" summary="media-relative colorimetric"/>
+      <entry name="saturation" value="2" summary="saturation"/>
+      <entry name="absolute" value="3" summary="ICC-absolute colorimetric"/>
+      <entry name="relative_bpc" value="4" summary="media-relative colorimetric + black point compensation"/>
+    </enum>
+
+    <enum name="alpha_mode">
+      <description summary="alpha mode">
+	Specifies whether alpha is pre-multiplied into color channels or not.
+	If pre-multiplied, the linear alpha value is already multiplied with the
+	(non-linear) color channel code values in the color channels.
+      </description>
+      <entry name="straight" value="0" summary="alpha is independent from color channels"/>
+      <entry name="premultiplied" value="1" summary="alpha is pre-multiplied into color channels"/>
+    </enum>
+
+    <request name="set_alpha_mode">
+      <description summary="set the surface alpha mode">
+	Assuming an alpha channel exists, it is always linear. The alpha mode
+	determines whether the color channels include alpha pre-multiplied or
+	not. Using straight alpha might have performance benefits.
+
+	Alpha mode is double buffered, and will be applied at the time
+	wl_surface.commit of the corresponding wl_surface is called.
+
+	By default, a surface is assumed to have pre-multiplied alpha.
+      </description>
+      <arg name="alpha_mode" type="uint" enum="alpha_mode" summary="alpha mode"/>
+    </request>
+
+    <request name="set_extended_dynamic_range">
+      <description summary="set the content extended dynamic range">
+	Set the extended dynamic range (EDR) value for the underlying surface.
+	The EDR value is double buffered, and will be applied at the time
+	wl_surface.commit of the corresponding wl_surface is called.
+
+	The EDR value describes how much dynamic range is encoded relative to
+	the SDR maximum white. EDR value is proportional to luminance, using
+	the luminance of black as the zero level. A value of 1.0 means that the
+	SDR maximum white is the highest possible luminance of the surface. A
+	value of 3.0 means that the SDR maximum white is one third of the
+	highest possible luminance of the surface.
+
+	The color space attached to the surface can make the code values in the
+	buffer non-linear in regards to the luminance. The code value to produce
+	a third of the luminance of the biggest code value therefore might not
+	be one third of the biggest code value.
+
+	For the definition of the SDR maximum white on an output, see
+	zcr_color_management_output_v1.extended_dynamic_range. Content
+	producers are free to choose their SDR maximum white level. How it
+	shall be displayed depends on the monitor capabilities and the output
+	EDR value.
+
+	By default the EDR value is 1.0. The compositor will tone map the image
+	to match the EDR of each output the surface is shown on. The aim for
+	the EDR-EDR mapping is to produce a relative luminance mapping that
+	looks equally good regardless of the viewing conditions and the monitor
+	capabilities, assuming the output EDR value was tuned to the output
+	capabilities and the viewing environment. There might be performance
+	and image quality benefits from providing content readily tone mapped to
+	the EDR value of the output the surface is shown on.
+
+	The EDR value is multiplied by 1000 to produce the integer value
+	carried by the protocol.
+      </description>
+     <arg name="value" type="uint" summary="EDR value * 1000"/>
+    </request>
+
+    <request name="set_color_space">
+      <description summary="set the surface color space">
+	Set the color space of the underlying surface. The color space and
+	render intent are double buffered, and will be applied
+	at the time wl_surface.commit of the corresponding wl_surface is called.
+
+	<!-- FIXME: same problem as in the render_intent enum -->
+	The render intent gives the compositor a hint what to optimize for in
+	color space transformations.
+
+	By default, a surface is assumed to have the sRGB color space and an
+	arbitrary render intent.
+
+	If the color space of the surface matches the color space of an output
+	it is shown on the performance and color accuracy might improve. To find
+	those color spaces the client can listen to the preferred_color_space or
+	the wl_surface.enter/leave events. This improvement may require using
+	the color space object created by
+	zcr_color_management_output_v1.get_color_space.
+      </description>
+      <arg name="color_space" type="object" interface="zcr_color_space_v1"/>
+      <arg name="render_intent" type="uint" enum="render_intent" summary="render intent"/>
+    </request>
+
+    <request name="set_default_color_space">
+      <description summary="set the surface color space to default">
+	This request sets the surface color space to the defaults, see
+	set_color_space. The setting will be applied at the time
+	wl_surface.commit of the corresponding wl_surface is called.
+      </description>
+    </request>
+
+    <!-- TODO: HDR metadata request -->
+
+    <event name="preferred_color_space">
+      <description summary="output for color optimization">
+	The preferred_color_space event is sent when the compositor determines
+	or switches the output that implies the preferred color space. The
+	preferred color space is the one which likely has the most performance
+	and quality benefits if used by a client for its surface contents.
+
+	The event does not carry a zcr_color_space_v1 but a wl_output object.
+	The concrete zcr_color_space_v1 can be created by calling
+	zcr_color_management_output_v1.get_color_space on the output and
+	listening to zcr_color_management_output_v1.color_space_changed
+	events.
+
+	As clients may bind to the same global wl_output multiple
+	times, this event is sent for each bound instance that matches
+	the preferred color space output. If a client has not bound to
+	the right wl_output global at all, this event is not sent.
+
+	This is only a hint and clients can set any valid color space with
+	set_color_space but there might be performance and color accuracy
+	improvements by providing the surface in the preferred color space.
+      </description>
+      <arg name="output" type="object" interface="wl_output"/>
+    </event>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the color management interface for a surface">
+	Destroy the zcr_color_management_surface_v1 object.
+
+	When the last zcr_color_management_surface_v1 object for a wl_surface
+	is destroyed, the destruction will pend unsetting the wl_surface's
+	color space, render intent and alpha mode similar to set_color_space
+	will pend a set.
+      </description>
+    </request>
+  </interface>
+
+  <interface name="zcr_color_space_creator_v1" version="4">
+    <description summary="color space creator">
+	A zcr_color_space_creator_v1 object returns a created color space
+	or the error which occured during creation.
+
+	Once a zcr_color_space_creator_v1 object has delivered a 'created'
+	or 'error' event it is automatically destroyed.
+    </description>
+
+    <enum name="creation_error" bitfield="true">
+      <description summary="color space creation error">
+	Bitmask of errors which occured while trying to create a color space
+      </description>
+      <entry name="malformed_icc" value="0x1" summary="malformed ICC profile"/>
+      <entry name="bad_icc" value="0x2" summary="ICC profile does not meet requirements"/>
+      <entry name="bad_primaries" value="0x4" summary="bad primaries"/>
+      <entry name="bad_whitepoint" value="0x8" summary="bad whitepoint"/>
+    </enum>
+
+    <event name="created">
+      <description summary="color space object created">
+	Delivers the successfully created color space.
+
+	The resulting color space object does not allow get_information request.
+      </description>
+      <arg name="id" type="new_id" interface="zcr_color_space_v1"/>
+    </event>
+
+    <event name="error">
+      <description summary="color space creation failed">
+	This event is sent if the color space creation failed.
+      </description>
+      <arg name="error" type="uint" enum="creation_error" summary="error bitmask"/>
+    </event>
+  </interface>
+
+  <interface name="zcr_color_space_v1" version="4">
+    <description summary="color space">
+	Refers to a color space which can be attached to a surface
+	(zcr_color_management_surface_v1.set_color_space). It may provide
+	information like the ICC profile and the well-known names to allow
+	clients to know the color space and do color transformations of their
+	own.
+
+	Once created and regardless of how it was created, a zcr_color_space_v1
+	object always refers to one fixed color space.
+
+	The client can create a zcr_color_space_v1 object with
+	zcr_color_manager_v1 requests or from an output by calling
+	zcr_color_management_output_v1.get_color_space.
+
+	Other extensions may define more zcr_color_space_v1 factory interfaces.
+	Those interfaces must explicitly specify the interface version for the
+	object created, otherwise versioning zcr_color_space_v1 correctly
+	becomes impossible. Using a 'new_id' argument without 'interface'
+	attribute defined in XML forces code generators to add two explicit
+	arguments: interface and version. Version is the explicit version
+	number needed, and interface should be required to be
+	"zcr_color_space_v1". The compositor supported zcr_color_space_v1
+	versions are defined by the advertised zcr_color_manager_v1 in
+	wl_registry.
+    </description>
+
+    <enum name="error">
+      <entry name="no_information" value="0" summary="get_information disallowed"/>
+    </enum>
+
+    <request name="get_information">
+      <description summary="get information about the color space">
+	As a reply to this request, the compositor will send all available
+	information events describing this color space object and finally
+	the 'done' event. Other extensions may define more events to be sent
+	before 'done'.
+
+	This request is allowed only on zcr_color_space_v1 objects where the
+	message that created the object specifies that get_information is
+	allowed. Otherwise protocol error no_information is raised.
+
+	Every get_information request on the same object will always return the
+	exact same data.
+
+	See zcr_color_management_output_v1.get_color_space and
+	zcr_color_space_creator_v1.created.
+      </description>
+    </request>
+
+    <event name="icc_file">
+      <description summary="ICC profile describing the color space">
+	This event may be sent only as a response to
+	zcr_color_space_v1.get_information.
+
+	The icc argument provides a file descriptor to the client which can be
+	memory-mapped to provide the ICC profile describing the color space.
+	The fd must be mapped with MAP_PRIVATE and read-only by the client.
+
+	Compositors should send this event always when information is requested.
+	ICC profiles provide the common foundation which all color managed
+	clients may rely on.
+      </description>
+      <arg name="icc" type="fd" summary="ICC profile file descriptor"/>
+      <arg name="icc_size" type="uint" summary="ICC profile size, in bytes"/>
+    </event>
+
+    <event name="names">
+      <description summary="well-known names of a color space">
+	[Deprecated] This event may be sent only as a response to
+	zcr_color_space_v1.get_information.
+
+	EOTF, chromaticity and whitepoint contain well-known names of those
+	properties if available and unknown otherwise.
+
+	Compositors should not assume that all clients can understand these
+	names. The names are provided for client convenience. If a client
+	understands the name triplet, it may ignore other information about
+	the color space, the ICC profile for example. Use complete_names instead.
+      </description>
+      <arg name="eotf" type="uint" enum="zcr_color_manager_v1.eotf_names" summary="EOTF"/>
+      <arg name="chromaticity" type="uint" enum="zcr_color_manager_v1.chromaticity_names" summary="chromaticity"/>
+      <arg name="whitepoint" type="uint" enum="zcr_color_manager_v1.whitepoint_names" summary="whitepoint"/>
+    </event>
+
+    <event name="params">
+      <description summary="RGB primaries along with whitepoint defining color space">
+	[Deprecated] This event may be sent only as a response to
+	zcr_color_space_v1.get_information.
+
+	The RGB primary value arguments along with the whitepoint value arguments
+	and eotf can be used to define an arbitrary or custom color space.
+
+	The eotf enum contains well known names of that property, but the compositor
+	should not assume that all clients will understand those names. Use
+	complete_params instead.
+      </description>
+      <arg name="eotf" type="uint" enum="zcr_color_manager_v1.eotf_names" summary="EOTF"/>
+      <arg name="primary_r_x" type="uint" summary="red primary X * 10000"/>
+      <arg name="primary_r_y" type="uint" summary="red primary Y * 10000"/>
+      <arg name="primary_g_x" type="uint" summary="green primary X * 10000"/>
+      <arg name="primary_g_y" type="uint" summary="green primary Y * 10000"/>
+      <arg name="primary_b_x" type="uint" summary="blue primary X * 10000"/>
+      <arg name="primary_b_y" type="uint" summary="blue primary Y * 10000"/>
+      <arg name="white_point_x" type="uint" summary="white point X * 10000"/>
+      <arg name="white_point_y" type="uint" summary="white point Y * 10000"/>
+    </event>
+
+    <event name="done">
+      <description summary="end of color space information">
+	This event may be sent only as a response to
+	zcr_color_space_v1.get_information.
+
+	This signifies that all color space information events have been
+	delivered for the object.
+      </description>
+    </event>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the color space">
+	Destroy the zcr_color_space_v1 object.
+
+	Destroying the zcr_color_space_v1 which is active on a surface or an
+	output does not change the color space of those objects.
+      </description>
+    </request>
+
+	<!-- Version 3 additions -->
+
+    <event name="complete_names" since="3">
+      <description summary="well-known names of a color space">
+	This event may be sent only as a response to
+	zcr_color_space_v1.get_information.
+
+	EOTF, chromaticity, matrix, range and whitepoint contain well-known names of those
+	properties if available and unknown otherwise.
+
+	Compositors should not assume that all clients can understand these
+	names. The names are provided for client convenience. If a client
+	understands the name triplet, it may ignore other information about
+	the color space, the ICC profile for example.
+      </description>
+      <arg name="eotf" type="uint" enum="zcr_color_manager_v1.eotf_names" summary="EOTF"/>
+      <arg name="chromaticity" type="uint" enum="zcr_color_manager_v1.chromaticity_names" summary="chromaticity"/>
+      <arg name="whitepoint" type="uint" enum="zcr_color_manager_v1.whitepoint_names" summary="whitepoint"/>
+      <arg name="matrix" type="uint" enum="zcr_color_manager_v1.matrix_names" summary="Color matrix"/>
+      <arg name="range" type="uint" enum="zcr_color_manager_v1.range_names" summary="Color range"/>
+    </event>
+
+    <event name="complete_params" since="3">
+      <description summary="RGB primaries along with whitepoint defining color space">
+	This event may be sent only as a response to
+	zcr_color_space_v1.get_information.
+
+	The RGB primary value arguments along with the whitepoint value arguments
+	and eotf can be used to define an arbitrary or custom color space.
+
+	The eotf enum contains well known names of that property, but the compositor
+	should not assume that all clients will understand those names.
+      </description>
+      <arg name="eotf" type="uint" enum="zcr_color_manager_v1.eotf_names" summary="EOTF"/>
+      <arg name="matrix" type="uint" enum="zcr_color_manager_v1.matrix_names" summary="Color matrix"/>
+      <arg name="range" type="uint" enum="zcr_color_manager_v1.range_names" summary="Color range"/>
+      <arg name="primary_r_x" type="uint" summary="red primary X * 10000"/>
+      <arg name="primary_r_y" type="uint" summary="red primary Y * 10000"/>
+      <arg name="primary_g_x" type="uint" summary="green primary X * 10000"/>
+      <arg name="primary_g_y" type="uint" summary="green primary Y * 10000"/>
+      <arg name="primary_b_x" type="uint" summary="blue primary X * 10000"/>
+      <arg name="primary_b_y" type="uint" summary="blue primary Y * 10000"/>
+      <arg name="white_point_x" type="uint" summary="white point X * 10000"/>
+      <arg name="white_point_y" type="uint" summary="white point Y * 10000"/>
+    </event>
+  </interface>
+
+</protocol>
diff --git a/chromium.org/components/exo/wayland/protocol/overlay-prioritizer.xml b/chromium.org/components/exo/wayland/protocol/overlay-prioritizer.xml
new file mode 100644
index 0000000..a16ed79
--- /dev/null
+++ b/chromium.org/components/exo/wayland/protocol/overlay-prioritizer.xml
@@ -0,0 +1,99 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<protocol name="overlay_prioritizer">
+
+  <copyright>
+    Copyright 2021 The Chromium Authors
+
+    Permission is hereby granted, free of charge, to any person obtaining a
+    copy of this software and associated documentation files (the "Software"),
+    to deal in the Software without restriction, including without limitation
+    the rights to use, copy, modify, merge, publish, distribute, sublicense,
+    and/or sell copies of the Software, and to permit persons to whom the
+    Software is furnished to do so, subject to the following conditions:
+
+    The above copyright notice and this permission notice (including the next
+    paragraph) shall be included in all copies or substantial portions of the
+    Software.
+
+    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
+    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
+    DEALINGS IN THE SOFTWARE.
+  </copyright>
+
+  <interface name="overlay_prioritizer" version="1">
+    <description summary="overlay hint prioritization">
+      The global interface exposing overlay delegated prioritization
+      hint capabilities is used to instantiate an interface extension for a
+      wl_surface object. This extended interface will then allow
+      delegated overlay prioritization of the surface.
+    </description>
+
+    <request name="destroy" type="destructor">
+      <description summary="Destroy the overlay prioritizer.">
+        Informs the server that the client will not be using this
+        protocol object anymore. This does not affect any other objects,
+        prioritizer objects included.
+      </description>
+    </request>
+
+    <enum name="error">
+      <entry name="overlay_hinted_surface_exists" value="0"
+             summary="the surface already has a prioritizer object
+             associated"/>
+    </enum>
+
+    <request name="get_overlay_prioritized_surface">
+      <description summary="extend surface interface for overlay prioritization hint">
+	Instantiate an interface extension for the given wl_surface to
+	add support for overlay prioritization hinting. If the given wl_surface already has
+	a prioritization object associated, the delegate_exists protocol error is
+  raised.
+      </description>
+      <arg name="id" type="new_id" interface="overlay_prioritized_surface"
+           summary="the new prioritized interface id"/>
+      <arg name="surface" type="object" interface="wl_surface"
+           summary="the surface"/>
+    </request>
+  </interface>
+
+  <interface name="overlay_prioritized_surface" version="1">
+    <description summary="delegate overlay prioritization hint of a wl_surface">
+      An additional interface to a wl_surface object, which allows the
+      client to specify hints for the overlay prioritization of the surface.
+    </description>
+     <request name="destroy" type="destructor">
+      <description summary="remove overlay prioritization the surface">
+	The associated wl_surface's overlay prioritization is removed.
+	The change is applied on the next wl_surface.commit.
+      </description>
+    </request>
+
+    <enum name="error">
+      <entry name="bad_value" value="0"
+	     summary="negative values in radius or size"/>
+      <entry name="no_surface" value="1"
+	     summary="the wl_surface was destroyed"/>
+    </enum>
+
+    <enum name="overlay_priority">
+    <description summary="hints for overlay prioritization">
+    </description>
+      <entry name="none" value="0" summary="overlay promotion is not necessary for this surface" />
+      <entry name="regular" value="1" summary="surface could be considered as a candidate for promotion" />
+      <entry name="preferred_low_latency_canvas" value="2" summary="the surface is a low latency canvas that works better if promoted to overlay" />
+      <entry name="required_hardware_protection" value="3" summary="the surface contains protected content and requires to be promoted to overlay" />
+    </enum>
+
+    <request name="set_overlay_priority">
+      <description summary="set the surface overlay priority">
+      </description>
+      <arg name="priority" type="uint" />
+    </request>
+
+  </interface>
+
+</protocol>
diff --git a/chromium.org/components/exo/wayland/protocol/surface-augmenter.xml b/chromium.org/components/exo/wayland/protocol/surface-augmenter.xml
new file mode 100644
index 0000000..6c9f542
--- /dev/null
+++ b/chromium.org/components/exo/wayland/protocol/surface-augmenter.xml
@@ -0,0 +1,401 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<protocol name="surface_augmenter">
+
+  <copyright>
+    Copyright 2021 The Chromium Authors
+
+    Permission is hereby granted, free of charge, to any person obtaining a
+    copy of this software and associated documentation files (the "Software"),
+    to deal in the Software without restriction, including without limitation
+    the rights to use, copy, modify, merge, publish, distribute, sublicense,
+    and/or sell copies of the Software, and to permit persons to whom the
+    Software is furnished to do so, subject to the following conditions:
+
+    The above copyright notice and this permission notice (including the next
+    paragraph) shall be included in all copies or substantial portions of the
+    Software.
+
+    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
+    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
+    DEALINGS IN THE SOFTWARE.
+  </copyright>
+
+  <interface name="surface_augmenter" version="12">
+    <description summary="surface composition delegation">
+      The global interface exposing surface delegated composition
+      capabilities is used to instantiate an interface extension for a
+      wl_surface object. This extended interface will then allow
+      delegated compostion of the surface contents, effectively
+      disconnecting the direct relationship between the buffer and the
+      surface content (adding support for solid quads and rounded corner
+      for instance).
+    </description>
+
+    <request name="destroy" type="destructor">
+      <description summary="Destroy the surface augmenter.">
+        Informs the server that the client will not be using this
+        protocol object anymore. This does not affect any other objects,
+        augmenter objects included.
+      </description>
+    </request>
+
+    <enum name="error">
+      <entry name="augmented_surface_exists" value="0"
+             summary="the surface already has a augmenter object
+             associated"/>
+    </enum>
+
+    <request name="create_solid_color_buffer">
+      <description summary="creates a solid color buffer">
+	Instantiate a buffer of the given size for the purpose of a solid color
+  quad of a given color.
+
+	<!-- Version 12 additions -->
+	This buffer does not require resources in the compositor, so it is immediately
+	reusable and shareable. So it is not responsible for sending wl_buffer.release
+	or zwp_linux_buffer_release_v1.*_release events.
+      </description>
+      <arg name="id" type="new_id" interface="wl_buffer"/>
+      <arg name="color" type="array" summary="quad color represented by a SkColor4f"/>
+      <arg name="width" type="int"/>
+      <arg name="height" type="int"/>
+    </request>
+
+    <request name="get_augmented_surface">
+      <description summary="extend surface interface for delegation">
+	Instantiate an interface extension for the given wl_surface to
+	extend composition of its content. If the given wl_surface already has
+	a augmentation object associated, the delegate_exists protocol error is
+  raised.
+
+	<!-- Version 12 additions -->
+	If needs to be called, this must be called before a surface role object is
+	created.
+      </description>
+      <arg name="id" type="new_id" interface="augmented_surface"
+           summary="the new augmenter interface id"/>
+      <arg name="surface" type="object" interface="wl_surface"
+           summary="the surface"/>
+    </request>
+
+    <!-- Version 2 additions -->
+
+    <request name="get_augmented_subsurface" since="2">
+      <description summary="extend sub surface interface for delegation">
+	Instantiate an interface extension for the given wl_subsurface to
+	extend composition of its content. If the given wl_subsurface already has
+	a augmentation object associated, the delegate_exists protocol error is
+  raised.
+      </description>
+      <arg name="id" type="new_id" interface="augmented_sub_surface"
+           summary="the new augmenter interface id"/>
+      <arg name="subsurface" type="object" interface="wl_subsurface"
+           summary="the subsurface"/>
+    </request>
+  </interface>
+
+  <interface name="augmented_surface" version="12">
+    <description summary="delegate composition of a wl_surface">
+      An additional interface to a wl_surface object, which allows the
+      client to specify the delegated composition of the surface
+      contents.
+
+      <!-- Version 12 additions -->
+      This makes the surface an object only used to composite its parent
+      surface. This means the surface will be clipped to the parent bounds, will
+      not receive input events or display enter/leave events, etc.
+
+      Use wl_subsurface role objects to express which parent surface this will
+      perform delegate composition for.
+
+      The commits to this surface is assumed to behave synchronized with its
+      parent commits, as a synchronized wl_subsurface would.
+
+      The compositor does not perform fine-grained damage extension calculation
+      that is introduced by an augmented_surface moving, resizing, changing
+      stacking, or disappearing. A client performing such operations should
+      account for it and damage the parent non-augmented wl_surface accordingly.
+
+      Various changes like adding or removing an augmented sub-surface, changing
+      its position or stacking order, will not introduce extra damage on the
+      compositor side. The parent wl_surface should account for the extra damage
+      introduced.
+
+      This surface, using a wl_subsurface role of its parent, cannot be stacked
+      relative to non-augmented sub-surfaces of the parent, but can be stacked
+      relative to other augmented children. Nor can this surface have
+      non-augmented sub-surface children.
+
+      A mixed tree structure of using augmented_surfaces to delegate composite
+      wl_surfaces would look like this:
+
+                wl_surface@1:{ augmented_surface@1,2,3 }
+                /           \_____
+               /                   \
+        wl_surface@2:               wl_surface@3:
+          { augmented_surface@4,5 }   { augmented_surface@6 }
+
+      Every wl_surface has a list of augmented_surfaces. Assuming the
+      wl_surface stacking order, from bottom to top, is:
+      wl_surface@1, wl_surface@2, wl_surface@3
+
+      Then the final composition order, from bottom to top, is:
+      wl_surface@1, augmented_surface@1,2,3, wl_surface@2, augmented_surface@4,5,
+      wl_surface@3, augmented_surface@6
+    </description>
+     <request name="destroy" type="destructor">
+      <description summary="remove delegated composition of the surface">
+	Client will no longer be able to control the delegated composition properties
+	of this surface. This does not change the existing delegated composition
+	behavior.
+      </description>
+    </request>
+
+    <enum name="error">
+      <entry name="bad_value" value="0"
+	     summary="negative values in radius or size"/>
+      <entry name="no_surface" value="1"
+	     summary="the wl_surface was destroyed"/>
+      <entry name="bad_surface" value="2"
+	     summary="incompatible surface"/>
+    </enum>
+
+    <request name="set_rounded_corners">
+    <!-- Note that this might be moved to a different protocol if there is
+      usage for it outside of Chrome OS -->
+      <description summary="set the surface rounded corners">
+        [Deprecated]. Use set_rounded_corners_clip_bounds request below.
+
+        Informs the server that it must apply the rounded corners
+        mask filter that shall be applied on next commit. Use
+        set_rounded_corners_bounds instead.
+      </description>
+      <arg name="top_left" type="fixed" summary="top left corner"/>
+      <arg name="top_right" type="fixed" summary="top right corner"/>
+      <arg name="bottom_right" type="fixed" summary="bottom right corner"/>
+      <arg name="bottom_left" type="fixed" summary="bottom left corner"/>
+    </request>
+
+    <!-- Version 2 additions -->
+
+    <request name="set_destination_size" since="2">
+      <description summary="set the surface destination viewport size, with subpixel accuracy">
+      Sets the surface destination viewport size, with subpixel accuracy.
+      This state is double-buffered, and is applied on the next wl_surface.commit.
+      </description>
+      <arg name="width" type="fixed" summary="width of the surface"/>
+      <arg name="height" type="fixed" summary="height of the surface"/>
+    </request>
+
+    <request name="set_rounded_clip_bounds" since="2">
+    <!-- Note that this might be moved to a different protocol if there is
+      usage for it outside of Chrome OS -->
+      <description summary="set the surface rounded clip bounds">
+        [Deprecated]. Use set_rounded_corners_clip_bounds request below.
+
+        Informs the server that it must apply the rounded clipping mask filter
+        that shall be applied on next commit. The mask can be uniform for
+        several surfaces and applied uniformally so that two or more
+        surfaces visually look as a single surface with rounded corners.
+        Please note this is can only be used on surfaces that are used as
+        overlays, which must not have any subtrees. The rounding will be
+        ignored if the bounds are outside of the surface.
+      </description>
+      <arg name="x" type="int"/>
+      <arg name="y" type="int"/>
+      <arg name="width" type="int"/>
+      <arg name="height" type="int"/>
+      <arg name="top_left" type="fixed" summary="top left corner"/>
+      <arg name="top_right" type="fixed" summary="top right corner"/>
+      <arg name="bottom_right" type="fixed" summary="bottom right corner"/>
+      <arg name="bottom_left" type="fixed" summary="bottom left corner"/>
+    </request>
+
+    <!-- Version 3 additions -->
+
+    <request name="set_background_color" since="3">
+      <description summary="sets a background color of this surface">
+        Sets a background color of a this surface. This information will be
+        associated with the next buffer commit. Please note this is different
+        from solid color buffers, which creates a new buffer instance, and
+        rather provides additional information how the buffer should be
+        composited. Passing empty array means the background color is reset.
+        The default value is determined by the Wayland compositor then.
+      </description>
+      <arg name="color" type="array"
+           summary="overlay color represented by a SkColor4f"/>
+    </request>
+
+    <!-- Version 6 additions -->
+
+    <request name="set_trusted_damage" since="6">
+      <description summary="sets the trusted damage state of this surface">
+        [Deprecated] When set, this surface trusts all damage reported to this
+        surface and descendant sub-surfaces is accurate, and will not try to
+        recompute it. If not set, various changes like adding or removing a
+        sub-surface, changing its position or stacking order, can cause full
+        damage on this surface.
+
+        The initial state is disabled.
+      </description>
+      <arg name="enabled" type="int"/>
+    </request>
+
+    <!-- Version 7 additions -->
+
+    <request name="set_rounded_corners_clip_bounds" since="7">
+    <!-- Note that this might be moved to a different protocol if there is
+      usage for it outside of Chrome OS -->
+      <description summary="set the surface rounded corners clip bounds">
+        Informs the server that it must apply the rounded clipping mask filter
+        that shall be applied on next commit. The mask can be uniform for
+        several surfaces and applied uniformally so that two or more
+        surfaces visually look as a single surface with rounded corners.
+
+        Since version 9, the bounds will be placed with its origin (top left
+        corner pixel) at the location x, y of the surface local coordinate
+        system. On version 8 or before, it is placed with its root surface
+        coordinates, but this is deperecated.
+
+        Please note this is can only be used on surfaces that are used as
+        overlays, which must not have any subtrees. The rounding will be
+        ignored if the bounds are outside of the surface.
+      </description>
+      <arg name="x" type="fixed"/>
+      <arg name="y" type="fixed"/>
+      <arg name="width" type="fixed"/>
+      <arg name="height" type="fixed"/>
+      <arg name="top_left" type="fixed" summary="top left corner"/>
+      <arg name="top_right" type="fixed" summary="top right corner"/>
+      <arg name="bottom_right" type="fixed" summary="bottom right corner"/>
+      <arg name="bottom_left" type="fixed" summary="bottom left corner"/>
+    </request>
+
+    <!-- Version 8 additions -->
+
+    <request name="set_clip_rect" since="8">
+      <description summary="sets a subsurface clip rect on surface local coordinates">
+  This schedules a clip rect to be applied when drawing this sub-surface.
+  The clip will be placed with its origin (top left corner pixel) at the
+  location x, y of the surface local coordinate system. The coordinates are not
+  restricted to the surface area. Negative x and y values are allowed.
+
+  If all of x, y, width and height are -1.0, the clip rect is unset instead.
+
+  Initially, surfaces have no clip set.
+  This state is double-buffered, and is applied on the next wl_surface.commit.
+      </description>
+      <arg name="x" type="fixed" summary="x coordinate in the surface local coordinates"/>
+      <arg name="y" type="fixed" summary="y coordinate in the surface local coordinates"/>
+      <arg name="width" type="fixed" summary="width of the clip rect"/>
+      <arg name="height" type="fixed" summary="height of the clip rect"/>
+    </request>
+
+    <!-- Version 9 additions -->
+
+    <!--
+      This version updates `set_rounded_corners_clip_bounds` behavior.
+      No protocol is added for this version.
+    -->
+
+    <!-- Version 10 additions -->
+
+    <!--
+      This version updates the inner implementation of surface coordinate.
+      No protocol is added for this version.
+    -->
+
+    <!-- Version 11 additions -->
+    <request name="set_frame_trace_id" since="11">
+      <description summary="sets a trace ID for tracking frame submission flow">
+        This sets a trace ID to connect the frame submission trace event flow at
+        the client and the server side.
+        This state is double-buffered, and is applied on the next
+        wl_surface.commit.
+      </description>
+      <arg name="id_hi" type="uint" summary="high 32 bits of the trace ID"/>
+      <arg name="id_lo" type="uint" summary="low 32 bits of the trace ID"/>
+    </request>
+
+  </interface>
+
+  <interface name="augmented_sub_surface" version="5">
+    <description summary="delegate composition of a wl_subsurface">
+      An additional interface to a wl_subsurface object, which allows the
+      client to specify the delegated composition of the surface
+      contents.
+    </description>
+    <request name="destroy" type="destructor">
+      <description summary="remove delegated composition of the surface">
+	The associated wl_surface's augmenter is removed.
+	The change is applied on the next wl_surface.commit.
+      </description>
+    </request>
+    <request name="set_position">
+      <description summary="sets a subsurface position with subpixel accuracy">
+	This schedules a sub-surface position change.
+	The sub-surface will be moved so that its origin (top left
+	corner pixel) will be at the location x, y of the parent surface
+	coordinate system. The coordinates are not restricted to the parent
+	surface area. Negative values are allowed.
+
+	The scheduled coordinates will take effect whenever the state of the
+	parent surface is applied. When this happens depends on whether the
+	parent surface is in synchronized mode or not. See
+	wl_subsurface.set_sync and wl_subsurface.set_desync for details.
+
+	If more than one set_position request is invoked by the client before
+	the commit of the parent surface, the position of a new request always
+	replaces the scheduled position from any previous request.
+
+	The initial position is 0, 0.
+  This state is double-buffered, and is applied on the next wl_surface.commit.
+      </description>
+      <arg name="x" type="fixed" summary="x coordinate in the parent surface"/>
+      <arg name="y" type="fixed" summary="y coordinate in the parent surface"/>
+    </request>
+    <request name="set_clip_rect" since="4">
+      <description summary="sets a subsurface clip rect with subpixel accuracy">
+  [Deprecated] Use set_clip_rect on augmented_surface instead.
+  This schedules a clip rect to be applied when drawing this sub-surface.
+  The clip will be placed with its origin (top left corner pixel) at the
+  location x, y of the parent surface coordinate system. The coordinates are not
+  restricted to the parent surface area. Negative x and y values are allowed.
+
+  If all of x, y, width and height are -1.0, the clip rect is unset instead.
+
+  Initially, surfaces have no clip set.
+  This state is double-buffered, and is applied on the next wl_surface.commit.
+      </description>
+      <arg name="x" type="fixed" summary="x coordinate in the parent surface"/>
+      <arg name="y" type="fixed" summary="y coordinate in the parent surface"/>
+      <arg name="width" type="fixed" summary="width of the clip rect"/>
+      <arg name="height" type="fixed" summary="height of the clip rect"/>
+    </request>
+    <request name="set_transform" since="5">
+      <description summary="sets a subsurface transform as an affine matrix">
+        This schedules a transform to be applied when drawing this sub-surface.
+        This transform does not apply to any child surfaces of this sub-surface.
+
+        The matrix should be passed as an array of 6 floats in column major
+        order. An empty array can be sent to set the transform to the identity
+        matrix.
+
+        The initial transform is identity.
+        This state is double-buffered, and is applied on the next
+        wl_surface.commit.
+      </description>
+      <arg name="matrix" type="array" summary="size 6 affine matrix, or size 0 for identity matrix"/>
+    </request>
+
+    <enum name="error">
+      <entry name="invalid_size" value="0"
+	     summary="array sent with invalid dimensions"/>
+    </enum>
+  </interface>
+
+</protocol>
diff --git a/chromium.org/unstable/alpha-compositing/README b/chromium.org/third_party/wayland-protocols/unstable/alpha-compositing/README
similarity index 100%
rename from chromium.org/unstable/alpha-compositing/README
rename to chromium.org/third_party/wayland-protocols/unstable/alpha-compositing/README
diff --git a/chromium.org/unstable/alpha-compositing/alpha-compositing-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/alpha-compositing/alpha-compositing-unstable-v1.xml
similarity index 99%
rename from chromium.org/unstable/alpha-compositing/alpha-compositing-unstable-v1.xml
rename to chromium.org/third_party/wayland-protocols/unstable/alpha-compositing/alpha-compositing-unstable-v1.xml
index 6f67669..00a1341 100644
--- a/chromium.org/unstable/alpha-compositing/alpha-compositing-unstable-v1.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/alpha-compositing/alpha-compositing-unstable-v1.xml
@@ -2,7 +2,7 @@
 <protocol name="alpha_compositing_unstable_v1">
 
   <copyright>
-    Copyright 2016 The Chromium Authors.
+    Copyright 2016 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
diff --git a/chromium.org/third_party/wayland-protocols/unstable/content-type/README b/chromium.org/third_party/wayland-protocols/unstable/content-type/README
new file mode 100644
index 0000000..63258e0
--- /dev/null
+++ b/chromium.org/third_party/wayland-protocols/unstable/content-type/README
@@ -0,0 +1,5 @@
+Content type hint protocol
+
+Maintainers:
+Emmanuel Gil Peyrot <linkmauve@linkmauve.fr>
+Xaver Hugl <xaver.hugl@gmail.com>
diff --git a/chromium.org/third_party/wayland-protocols/unstable/content-type/content-type-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/content-type/content-type-v1.xml
new file mode 100644
index 0000000..e5de7ab
--- /dev/null
+++ b/chromium.org/third_party/wayland-protocols/unstable/content-type/content-type-v1.xml
@@ -0,0 +1,129 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<protocol name="content_type_v1">
+  <copyright>
+    Copyright © 2021 Emmanuel Gil Peyrot
+    Copyright © 2022 Xaver Hugl
+
+    Permission is hereby granted, free of charge, to any person obtaining a
+    copy of this software and associated documentation files (the "Software"),
+    to deal in the Software without restriction, including without limitation
+    the rights to use, copy, modify, merge, publish, distribute, sublicense,
+    and/or sell copies of the Software, and to permit persons to whom the
+    Software is furnished to do so, subject to the following conditions:
+
+    The above copyright notice and this permission notice (including the next
+    paragraph) shall be included in all copies or substantial portions of the
+    Software.
+
+    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
+    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
+    DEALINGS IN THE SOFTWARE.
+  </copyright>
+
+  <interface name="wp_content_type_manager_v1" version="1">
+    <description summary="surface content type manager">
+      This interface allows a client to describe the kind of content a surface
+      will display, to allow the compositor to optimize its behavior for it.
+
+      Warning! The protocol described in this file is currently in the testing
+      phase. Backward compatible changes may be added together with the
+      corresponding interface version bump. Backward incompatible changes can
+      only be done by creating a new major version of the extension.
+    </description>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the content type manager object">
+        Destroy the content type manager. This doesn't destroy objects created
+        with the manager.
+      </description>
+    </request>
+
+    <enum name="error">
+      <entry name="already_constructed" value="0"
+             summary="wl_surface already has a content type object"/>
+    </enum>
+
+    <request name="get_surface_content_type">
+      <description summary="create a new toplevel decoration object">
+        Create a new content type object associated with the given surface.
+
+        Creating a wp_content_type_v1 from a wl_surface which already has one
+        attached is a client error: already_constructed.
+      </description>
+      <arg name="id" type="new_id" interface="wp_content_type_v1"/>
+      <arg name="surface" type="object" interface="wl_surface"/>
+    </request>
+  </interface>
+
+  <interface name="wp_content_type_v1" version="1">
+    <description summary="content type object for a surface">
+      The content type object allows the compositor to optimize for the kind
+      of content shown on the surface. A compositor may for example use it to
+      set relevant drm properties like "content type".
+
+      The client may request to switch to another content type at any time.
+      When the associated surface gets destroyed, this object becomes inert and
+      the client should destroy it.
+    </description>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the content type object">
+        Switch back to not specifying the content type of this surface. This is
+        equivalent to setting the content type to none, including double
+        buffering semantics. See set_content_type for details.
+      </description>
+    </request>
+
+    <enum name="type">
+      <description summary="possible content types">
+        These values describe the available content types for a surface.
+      </description>
+      <entry name="none" value="0">
+        <description summary="no content type applies">
+          The content type none means that either the application has no data
+          about the content type, or that the content doesn't fit into one of
+          the other categories.
+        </description>
+      </entry>
+      <entry name="photo" value="1">
+        <description summary="photo content type">
+          The content type photo describes content derived from digital still
+          pictures and may be presented with minimal processing.
+        </description>
+      </entry>
+      <entry name="video" value="2">
+        <description summary="video content type">
+          The content type video describes a video or animation that may be
+          presented with reduced changes in latency in order to avoid stutter.
+          Where scaling is needed, scaling methods more appropriate for video
+          may be used.
+        </description>
+      </entry>
+      <entry name="game" value="3">
+        <description summary="game content type">
+          The content type game describes a running game. Its content may be
+          presented with reduced latency.
+        </description>
+      </entry>
+    </enum>
+
+    <request name="set_content_type">
+      <description summary="specify the content type">
+        Set the surface content type. This informs the compositor that the
+        client believes it is displaying buffers matching this content type.
+
+        This is purely a hint for the compositor, which can be used to adjust
+        its behavior or hardware settings to fit the presented content best.
+
+        The content type is double-buffered state, see wl_surface.commit for
+        details.
+      </description>
+      <arg name="content_type" type="uint" enum="content_type"
+           summary="the content type"/>
+    </request>
+  </interface>
+</protocol>
diff --git a/chromium.org/unstable/cursor-shapes/README b/chromium.org/third_party/wayland-protocols/unstable/cursor-shapes/README
similarity index 100%
rename from chromium.org/unstable/cursor-shapes/README
rename to chromium.org/third_party/wayland-protocols/unstable/cursor-shapes/README
diff --git a/chromium.org/unstable/cursor-shapes/cursor-shapes-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/cursor-shapes/cursor-shapes-unstable-v1.xml
similarity index 99%
rename from chromium.org/unstable/cursor-shapes/cursor-shapes-unstable-v1.xml
rename to chromium.org/third_party/wayland-protocols/unstable/cursor-shapes/cursor-shapes-unstable-v1.xml
index f94a6b4..36fa3b1 100644
--- a/chromium.org/unstable/cursor-shapes/cursor-shapes-unstable-v1.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/cursor-shapes/cursor-shapes-unstable-v1.xml
@@ -2,7 +2,7 @@
 <protocol name="cursor_shapes_v1">
 
   <copyright>
-    Copyright 2018 The Chromium Authors.
+    Copyright 2018 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
diff --git a/chromium.org/unstable/extended-drag/README b/chromium.org/third_party/wayland-protocols/unstable/extended-drag/README
similarity index 100%
rename from chromium.org/unstable/extended-drag/README
rename to chromium.org/third_party/wayland-protocols/unstable/extended-drag/README
diff --git a/chromium.org/unstable/extended-drag/extended-drag-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/extended-drag/extended-drag-unstable-v1.xml
similarity index 99%
rename from chromium.org/unstable/extended-drag/extended-drag-unstable-v1.xml
rename to chromium.org/third_party/wayland-protocols/unstable/extended-drag/extended-drag-unstable-v1.xml
index cb4c1dc..2ce4fe2 100644
--- a/chromium.org/unstable/extended-drag/extended-drag-unstable-v1.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/extended-drag/extended-drag-unstable-v1.xml
@@ -2,7 +2,7 @@
 <protocol name="extended_drag_unstable_v1">
 
   <copyright>
-    Copyright 2020 The Chromium Authors.
+    Copyright 2020 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
diff --git a/chromium.org/unstable/gaming-input/README b/chromium.org/third_party/wayland-protocols/unstable/gaming-input/README
similarity index 100%
rename from chromium.org/unstable/gaming-input/README
rename to chromium.org/third_party/wayland-protocols/unstable/gaming-input/README
diff --git a/chromium.org/unstable/gaming-input/gaming-input-unstable-v2.xml b/chromium.org/third_party/wayland-protocols/unstable/gaming-input/gaming-input-unstable-v2.xml
similarity index 99%
rename from chromium.org/unstable/gaming-input/gaming-input-unstable-v2.xml
rename to chromium.org/third_party/wayland-protocols/unstable/gaming-input/gaming-input-unstable-v2.xml
index 5e57e4a..644e7e0 100644
--- a/chromium.org/unstable/gaming-input/gaming-input-unstable-v2.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/gaming-input/gaming-input-unstable-v2.xml
@@ -2,7 +2,7 @@
 <protocol name="gaming_input_unstable_v2">
 
   <copyright>
-    Copyright 2016 The Chromium Authors.
+    Copyright 2016 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
diff --git a/chromium.org/third_party/wayland-protocols/unstable/gtk-primary-selection/README b/chromium.org/third_party/wayland-protocols/unstable/gtk-primary-selection/README
new file mode 100644
index 0000000..9f02e5f
--- /dev/null
+++ b/chromium.org/third_party/wayland-protocols/unstable/gtk-primary-selection/README
@@ -0,0 +1,4 @@
+GTK primary selection protocol
+
+Maintainers:
+Alexander Dunaev <adunaev@igalia.com>
diff --git a/chromium.org/third_party/wayland-protocols/unstable/gtk-primary-selection/gtk-primary-selection.xml b/chromium.org/third_party/wayland-protocols/unstable/gtk-primary-selection/gtk-primary-selection.xml
new file mode 100644
index 0000000..02cab94
--- /dev/null
+++ b/chromium.org/third_party/wayland-protocols/unstable/gtk-primary-selection/gtk-primary-selection.xml
@@ -0,0 +1,225 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<protocol name="gtk_primary_selection">
+  <copyright>
+    Copyright © 2015, 2016 Red Hat
+
+    Permission is hereby granted, free of charge, to any person obtaining a
+    copy of this software and associated documentation files (the "Software"),
+    to deal in the Software without restriction, including without limitation
+    the rights to use, copy, modify, merge, publish, distribute, sublicense,
+    and/or sell copies of the Software, and to permit persons to whom the
+    Software is furnished to do so, subject to the following conditions:
+
+    The above copyright notice and this permission notice (including the next
+    paragraph) shall be included in all copies or substantial portions of the
+    Software.
+
+    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
+    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
+    DEALINGS IN THE SOFTWARE.
+  </copyright>
+
+  <description summary="Primary selection protocol">
+    This protocol provides the ability to have a primary selection device to
+    match that of the X server. This primary selection is a shortcut to the
+    common clipboard selection, where text just needs to be selected in order
+    to allow copying it elsewhere. The de facto way to perform this action
+    is the middle mouse button, although it is not limited to this one.
+
+    Clients wishing to honor primary selection should create a primary
+    selection source and set it as the selection through
+    wp_primary_selection_device.set_selection whenever the text selection
+    changes. In order to minimize calls in pointer-driven text selection,
+    it should happen only once after the operation finished. Similarly,
+    a NULL source should be set when text is unselected.
+
+    wp_primary_selection_offer objects are first announced through the
+    wp_primary_selection_device.data_offer event. Immediately after this event,
+    the primary data offer will emit wp_primary_selection_offer.offer events
+    to let know of the mime types being offered.
+
+    When the primary selection changes, the client with the keyboard focus
+    will receive wp_primary_selection_device.selection events. Only the client
+    with the keyboard focus will receive such events with a non-NULL
+    wp_primary_selection_offer. Across keyboard focus changes, previously
+    focused clients will receive wp_primary_selection_device.events with a
+    NULL wp_primary_selection_offer.
+
+    In order to request the primary selection data, the client must pass
+    a recent serial pertaining to the press event that is triggering the
+    operation, if the compositor deems the serial valid and recent, the
+    wp_primary_selection_source.send event will happen in the other end
+    to let the transfer begin. The client owning the primary selection
+    should write the requested data, and close the file descriptor
+    immediately.
+
+    If the primary selection owner client disappeared during the transfer,
+    the client reading the data will receive a
+    wp_primary_selection_device.selection event with a NULL
+    wp_primary_selection_offer, the client should take this as a hint
+    to finish the reads related to the no longer existing offer.
+
+    The primary selection owner should be checking for errors during
+    writes, merely cancelling the ongoing transfer if any happened.
+  </description>
+
+  <interface name="gtk_primary_selection_device_manager" version="1">
+    <description summary="X primary selection emulation">
+      The primary selection device manager is a singleton global object that
+      provides access to the primary selection. It allows to create
+      wp_primary_selection_source objects, as well as retrieving the per-seat
+      wp_primary_selection_device objects.
+    </description>
+
+    <request name="create_source">
+      <description summary="create a new primary selection source">
+	Create a new primary selection source.
+      </description>
+      <arg name="id" type="new_id" interface="gtk_primary_selection_source"/>
+    </request>
+
+    <request name="get_device">
+      <description summary="create a new primary selection device">
+        Create a new data device for a given seat.
+      </description>
+      <arg name="id" type="new_id" interface="gtk_primary_selection_device"/>
+      <arg name="seat" type="object" interface="wl_seat"/>
+    </request>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the primary selection device manager">
+	Destroy the primary selection device manager.
+      </description>
+    </request>
+  </interface>
+
+  <interface name="gtk_primary_selection_device" version="1">
+    <request name="set_selection">
+      <description summary="set the primary selection">
+	Replaces the current selection. The previous owner of the primary selection
+	will receive a wp_primary_selection_source.cancelled event.
+
+	To unset the selection, set the source to NULL.
+      </description>
+      <arg name="source" type="object" interface="gtk_primary_selection_source" allow-null="true"/>
+      <arg name="serial" type="uint" summary="serial of the event that triggered this request"/>
+    </request>
+
+    <event name="data_offer">
+      <description summary="introduce a new wp_primary_selection_offer">
+	Introduces a new wp_primary_selection_offer object that may be used
+	to receive the current primary selection. Immediately following this
+	event, the new wp_primary_selection_offer object will send
+	wp_primary_selection_offer.offer events to describe the offered mime
+	types.
+      </description>
+      <arg name="offer" type="new_id" interface="gtk_primary_selection_offer"/>
+    </event>
+
+    <event name="selection">
+      <description summary="advertise a new primary selection">
+	The wp_primary_selection_device.selection event is sent to notify the
+	client of a new primary selection. This event is sent after the
+	wp_primary_selection.data_offer event introducing this object, and after
+	the offer has announced its mimetypes through
+	wp_primary_selection_offer.offer.
+
+	The data_offer is valid until a new offer or NULL is received
+	or until the client loses keyboard focus. The client must destroy the
+	previous selection data_offer, if any, upon receiving this event.
+      </description>
+      <arg name="id" type="object" interface="gtk_primary_selection_offer" allow-null="true"/>
+    </event>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the primary selection device">
+	Destroy the primary selection device.
+      </description>
+    </request>
+  </interface>
+
+  <interface name="gtk_primary_selection_offer" version="1">
+    <description summary="offer to transfer primary selection contents">
+      A wp_primary_selection_offer represents an offer to transfer the contents
+      of the primary selection clipboard to the client. Similar to
+      wl_data_offer, the offer also describes the mime types that the source
+      will transferthat the
+      data can be converted to and provides the mechanisms for transferring the
+      data directly to the client.
+    </description>
+
+    <request name="receive">
+      <description summary="request that the data is transferred">
+	To transfer the contents of the primary selection clipboard, the client
+	issues this request and indicates the mime type that it wants to
+	receive. The transfer happens through the passed file descriptor
+	(typically created with the pipe system call). The source client writes
+	the data in the mime type representation requested and then closes the
+	file descriptor.
+
+	The receiving client reads from the read end of the pipe until EOF and
+	closes its end, at which point the transfer is complete.
+      </description>
+      <arg name="mime_type" type="string"/>
+      <arg name="fd" type="fd"/>
+    </request>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the primary selection offer">
+	Destroy the primary selection offer.
+      </description>
+    </request>
+
+    <event name="offer">
+      <description summary="advertise offered mime type">
+	Sent immediately after creating announcing the wp_primary_selection_offer
+	through wp_primary_selection_device.data_offer. One event is sent per
+	offered mime type.
+      </description>
+      <arg name="mime_type" type="string"/>
+    </event>
+  </interface>
+
+  <interface name="gtk_primary_selection_source" version="1">
+    <description summary="offer to replace the contents of the primary selection">
+      The source side of a wp_primary_selection_offer, it provides a way to
+      describe the offered data and respond to requests to transfer the
+      requested contents of the primary selection clipboard.
+    </description>
+
+    <request name="offer">
+      <description summary="add an offered mime type">
+	This request adds a mime type to the set of mime types advertised to
+	targets. Can be called several times to offer multiple types.
+      </description>
+      <arg name="mime_type" type="string"/>
+    </request>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the primary selection source">
+	Destroy the primary selection source.
+      </description>
+    </request>
+
+    <event name="send">
+      <description summary="send the primary selection contents">
+	Request for the current primary selection contents from the client.
+	Send the specified mime type over the passed file descriptor, then
+	close it.
+      </description>
+      <arg name="mime_type" type="string"/>
+      <arg name="fd" type="fd"/>
+    </event>
+
+    <event name="cancelled">
+      <description summary="request for primary selection contents was canceled">
+	This primary selection source is no longer valid. The client should
+	clean up and destroy this primary selection source.
+      </description>
+    </event>
+  </interface>
+</protocol>
diff --git a/chromium.org/unstable/keyboard/README b/chromium.org/third_party/wayland-protocols/unstable/keyboard/README
similarity index 100%
rename from chromium.org/unstable/keyboard/README
rename to chromium.org/third_party/wayland-protocols/unstable/keyboard/README
diff --git a/chromium.org/unstable/keyboard/keyboard-configuration-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/keyboard/keyboard-configuration-unstable-v1.xml
similarity index 98%
rename from chromium.org/unstable/keyboard/keyboard-configuration-unstable-v1.xml
rename to chromium.org/third_party/wayland-protocols/unstable/keyboard/keyboard-configuration-unstable-v1.xml
index e6f1607..751de46 100644
--- a/chromium.org/unstable/keyboard/keyboard-configuration-unstable-v1.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/keyboard/keyboard-configuration-unstable-v1.xml
@@ -2,7 +2,7 @@
 <protocol name="keyboard_configuration_unstable_v1">
 
   <copyright>
-    Copyright 2016 The Chromium Authors.
+    Copyright 2016 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
@@ -97,7 +97,7 @@
     <!-- Version 3 additions -->
     <event name="supported_key_bits" since="3">
       <description summary="supported key bits">
-        Supported scan code key bits of all connected keyboards.
+        Union of supported scan code key bits of all connected keyboards.
       </description>
       <arg name="key_bits" type="array" summary="Uint64 key bits" />
     </event>
diff --git a/chromium.org/unstable/keyboard/keyboard-extension-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/keyboard/keyboard-extension-unstable-v1.xml
similarity index 99%
rename from chromium.org/unstable/keyboard/keyboard-extension-unstable-v1.xml
rename to chromium.org/third_party/wayland-protocols/unstable/keyboard/keyboard-extension-unstable-v1.xml
index a42ee7d..256ce88 100644
--- a/chromium.org/unstable/keyboard/keyboard-extension-unstable-v1.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/keyboard/keyboard-extension-unstable-v1.xml
@@ -2,7 +2,7 @@
 <protocol name="keyboard_extension_unstable_v1">
 
   <copyright>
-    Copyright 2017 The Chromium Authors.
+    Copyright 2017 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
diff --git a/chromium.org/third_party/wayland-protocols/unstable/notification-shell/README b/chromium.org/third_party/wayland-protocols/unstable/notification-shell/README
new file mode 100644
index 0000000..fbec853
--- /dev/null
+++ b/chromium.org/third_party/wayland-protocols/unstable/notification-shell/README
@@ -0,0 +1,4 @@
+Notification shell protocol
+
+Maintainers:
+Toshiki Kikuchi <toshikikikuchi@chromium.org>
diff --git a/chromium.org/unstable/notification-shell/notification-shell-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/notification-shell/notification-shell-unstable-v1.xml
similarity index 99%
rename from chromium.org/unstable/notification-shell/notification-shell-unstable-v1.xml
rename to chromium.org/third_party/wayland-protocols/unstable/notification-shell/notification-shell-unstable-v1.xml
index 597f59a..4fb3c48 100644
--- a/chromium.org/unstable/notification-shell/notification-shell-unstable-v1.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/notification-shell/notification-shell-unstable-v1.xml
@@ -2,7 +2,7 @@
 <protocol name="notification_shell_unstable_v1">
 
   <copyright>
-    Copyright 2018 The Chromium Authors.
+    Copyright 2018 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
diff --git a/chromium.org/unstable/remote-shell/README b/chromium.org/third_party/wayland-protocols/unstable/remote-shell/README
similarity index 100%
rename from chromium.org/unstable/remote-shell/README
rename to chromium.org/third_party/wayland-protocols/unstable/remote-shell/README
diff --git a/chromium.org/unstable/remote-shell/remote-shell-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/remote-shell/remote-shell-unstable-v1.xml
similarity index 99%
rename from chromium.org/unstable/remote-shell/remote-shell-unstable-v1.xml
rename to chromium.org/third_party/wayland-protocols/unstable/remote-shell/remote-shell-unstable-v1.xml
index cfc9c85..59d18ba 100644
--- a/chromium.org/unstable/remote-shell/remote-shell-unstable-v1.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/remote-shell/remote-shell-unstable-v1.xml
@@ -2,7 +2,7 @@
 <protocol name="remote_shell_unstable_v1">
 
   <copyright>
-    Copyright 2016 The Chromium Authors.
+    Copyright 2016 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
diff --git a/chromium.org/unstable/remote-shell/remote-shell-unstable-v2.xml b/chromium.org/third_party/wayland-protocols/unstable/remote-shell/remote-shell-unstable-v2.xml
similarity index 100%
rename from chromium.org/unstable/remote-shell/remote-shell-unstable-v2.xml
rename to chromium.org/third_party/wayland-protocols/unstable/remote-shell/remote-shell-unstable-v2.xml
diff --git a/chromium.org/unstable/secure-output/README b/chromium.org/third_party/wayland-protocols/unstable/secure-output/README
similarity index 100%
rename from chromium.org/unstable/secure-output/README
rename to chromium.org/third_party/wayland-protocols/unstable/secure-output/README
diff --git a/chromium.org/unstable/secure-output/secure-output-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/secure-output/secure-output-unstable-v1.xml
similarity index 99%
rename from chromium.org/unstable/secure-output/secure-output-unstable-v1.xml
rename to chromium.org/third_party/wayland-protocols/unstable/secure-output/secure-output-unstable-v1.xml
index ebcff97..af9edd5 100644
--- a/chromium.org/unstable/secure-output/secure-output-unstable-v1.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/secure-output/secure-output-unstable-v1.xml
@@ -2,7 +2,7 @@
 <protocol name="secure_output_unstable_v1">
 
   <copyright>
-    Copyright 2016 The Chromium Authors.
+    Copyright 2016 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
diff --git a/chromium.org/unstable/stylus-tools/README b/chromium.org/third_party/wayland-protocols/unstable/stylus-tools/README
similarity index 100%
rename from chromium.org/unstable/stylus-tools/README
rename to chromium.org/third_party/wayland-protocols/unstable/stylus-tools/README
diff --git a/chromium.org/unstable/stylus-tools/stylus-tools-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/stylus-tools/stylus-tools-unstable-v1.xml
similarity index 99%
rename from chromium.org/unstable/stylus-tools/stylus-tools-unstable-v1.xml
rename to chromium.org/third_party/wayland-protocols/unstable/stylus-tools/stylus-tools-unstable-v1.xml
index 0d753c5..b623208 100644
--- a/chromium.org/unstable/stylus-tools/stylus-tools-unstable-v1.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/stylus-tools/stylus-tools-unstable-v1.xml
@@ -2,7 +2,7 @@
 <protocol name="stylus_tools_unstable_v1">
 
   <copyright>
-    Copyright 2017 The Chromium Authors.
+    Copyright 2017 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
diff --git a/chromium.org/unstable/stylus/README b/chromium.org/third_party/wayland-protocols/unstable/stylus/README
similarity index 100%
rename from chromium.org/unstable/stylus/README
rename to chromium.org/third_party/wayland-protocols/unstable/stylus/README
diff --git a/chromium.org/unstable/stylus/stylus-unstable-v2.xml b/chromium.org/third_party/wayland-protocols/unstable/stylus/stylus-unstable-v2.xml
similarity index 99%
rename from chromium.org/unstable/stylus/stylus-unstable-v2.xml
rename to chromium.org/third_party/wayland-protocols/unstable/stylus/stylus-unstable-v2.xml
index cb3ca24..6cb3742 100644
--- a/chromium.org/unstable/stylus/stylus-unstable-v2.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/stylus/stylus-unstable-v2.xml
@@ -2,7 +2,7 @@
 <protocol name="stylus_unstable_v2">
 
   <copyright>
-    Copyright 2016 The Chromium Authors.
+    Copyright 2016 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
diff --git a/chromium.org/unstable/text-input/README b/chromium.org/third_party/wayland-protocols/unstable/text-input/README
similarity index 100%
rename from chromium.org/unstable/text-input/README
rename to chromium.org/third_party/wayland-protocols/unstable/text-input/README
diff --git a/chromium.org/third_party/wayland-protocols/unstable/text-input/text-input-extension-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/text-input/text-input-extension-unstable-v1.xml
new file mode 100644
index 0000000..0dd7d80
--- /dev/null
+++ b/chromium.org/third_party/wayland-protocols/unstable/text-input/text-input-extension-unstable-v1.xml
@@ -0,0 +1,442 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<protocol name="text_input_extension_unstable_v1">
+
+  <copyright>
+    Copyright 2021 The Chromium Authors
+
+    Permission is hereby granted, free of charge, to any person obtaining a
+    copy of this software and associated documentation files (the "Software"),
+    to deal in the Software without restriction, including without limitation
+    the rights to use, copy, modify, merge, publish, distribute, sublicense,
+    and/or sell copies of the Software, and to permit persons to whom the
+    Software is furnished to do so, subject to the following conditions:
+
+    The above copyright notice and this permission notice (including the next
+    paragraph) shall be included in all copies or substantial portions of the
+    Software.
+
+    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
+    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
+    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
+    DEALINGS IN THE SOFTWARE.
+  </copyright>
+
+  <interface name="zcr_text_input_extension_v1" version="13">
+    <description summary="extends text_input to support richer operations">
+      Allows a text_input to sends more variation of operations to support
+      richer features, such as set_preedit_region.
+
+      Warning! The protocol described in this file is experimental and
+      backward incompatible changes may be made. Backward compatible changes
+      may be added together with the corresponding uinterface version bump.
+      Backward incompatible changes are done by bumping the version number in
+      the protocol and interface names and resetting the interface version.
+      Once the protocol is to be declared stable, the 'z' prefix and the
+      version number in the protocol and interface names are removed and the
+      interface version number is reset.
+    </description>
+
+    <enum name="error">
+      <entry name="extended_text_input_exists" value="0"
+             summary="the text_input already has an extended_text_input object associated"/>
+    </enum>
+
+    <request name="get_extended_text_input">
+      <description summary="get extended_text_input for a text_input">
+        Create extended_text_input object.
+        See zcr_extended_text_input interface for details.
+        If the given text_input object already has a extended_text_input object
+        associated, the extended_text_input_exists protocol error is raised.
+      </description>
+      <arg name="id" type="new_id" interface="zcr_extended_text_input_v1"/>
+      <arg name="text_input" type="object" interface="zwp_text_input_v1"/>
+    </request>
+
+  </interface>
+
+  <interface name="zcr_extended_text_input_v1" version="13">
+    <description summary="extension of text_input protocol">
+      The zcr_extended_text_input_v1 interface extends the text_input interface
+      to support more rich operations on text_input.
+    </description>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy extended_text_input object"/>
+    </request>
+
+    <event name="set_preedit_region">
+      <description summary="set preedit from the surrounding text">
+        IME requests to update text_input client to set the preedit
+        from the surrounding text.
+
+        index is the starting point of the preedit, relative to the current
+        cursor position in utf-8 byte-offset.
+        length is the length of the preedit region in utf-8 byte length.
+
+        Following the convention we have in text_input::preedit_string,
+        text_input::preedit_styling sent just before this will be applied.
+      </description>
+      <arg name="index" type="int" />
+      <arg name="length" type="uint" />
+    </event>
+
+    <!-- Version 2 -->
+
+    <enum name="input_type" since="2">
+      <description summary="Chrome's TextInputType">
+        Wayland has its own input-type support, which is
+        zwp_text_input::content_purpose. However, it is not rich enough to
+        represent all Chrome's input types. This enum is introduced to keep
+        all entries so exo can understand it without any information loss.
+        See TextInputType's description for details about each entry.
+      </description>
+      <entry name="none" value="0" />
+      <entry name="text" value="1" />
+      <entry name="password" value="2" />
+      <entry name="search" value="3" />
+      <entry name="email" value="4" />
+      <entry name="number" value="5" />
+      <entry name="telephone" value="6" />
+      <entry name="url" value="7" />
+      <entry name="date" value="8" />
+      <entry name="date_time" value="9" />
+      <entry name="date_time_local" value="10" />
+      <entry name="month" value="11" />
+      <entry name="time" value="12" />
+      <entry name="week" value="13" />
+      <entry name="text_area" value="14" />
+      <entry name="content_editable" value="15" />
+      <entry name="date_time_field" value="16" />
+      <entry name="null" value="17" />
+    </enum>
+
+    <enum name="input_mode" since="2">
+      <description summary="Chrome's TextInputMode">
+        Similar to input_type defined above, this keeps Chrome's TextInputMode.
+        See TextInputMode's description for details for each entry.
+      </description>
+      <entry name="default" value="0" />
+      <entry name="none" value="1" />
+      <entry name="text" value="2" />
+      <entry name="tel" value="3" />
+      <entry name="url" value="4" />
+      <entry name="email" value="5" />
+      <entry name="numeric" value="6" />
+      <entry name="decimal" value="7" />
+      <entry name="search" value="8" />
+    </enum>
+
+    <enum name="input_flags" since="2">
+      <description summary="Chrome's TextInputFlags">
+        Similar to input_type defined above, this keeps Chrome's TextInputFlags,
+        because content_hint is not enough power to represent what Chrome wants.
+        See TextInputFlags' description for details for each entry.
+      </description>
+      <entry name="none" value="0" />
+      <entry name="autocomplete_on" value="1 &lt;&lt; 0" />
+      <entry name="autocomplete_off" value="1 &lt;&lt; 1" />
+      <entry name="autocorrect_on" value="1 &lt;&lt; 2" />
+      <entry name="autocorrect_off" value="1 &lt;&lt; 3" />
+      <entry name="spellcheck_on" value="1 &lt;&lt; 4" />
+      <entry name="spellcheck_off" value="1 &lt;&lt; 5" />
+      <entry name="autocapitalize_none" value="1 &lt;&lt; 6" />
+      <entry name="autocapitalize_characters" value="1 &lt;&lt; 7" />
+      <entry name="autocapitalize_words" value="1 &lt;&lt; 8" />
+      <entry name="autocapitalize_sentences" value="1 &lt;&lt; 9" />
+      <entry name="has_been_password" value="1 &lt;&lt; 10" />
+      <entry name="vertical" value="1 &lt;&lt; 11" />
+    </enum>
+
+    <enum name="learning_mode" since="2">
+      <description summary="Whether IME is allowed to learn" />
+      <entry name="disabled" value="0" />
+      <entry name="enabled" value="1" />
+    </enum>
+
+    <request name="deprecated_set_input_type" since="2">
+      <description summary="Sets input type, mode and flags together">
+        Deprecated. Use the new set_input_type.
+      </description>
+      <arg name="input_type" type="uint" enum="input_type" />
+      <arg name="input_mode" type="uint" enum="input_mode" />
+      <arg name="input_flags" type="uint" />
+      <arg name="learning_mode" type="uint" enum="learning_mode" />
+    </request>
+
+    <!-- Version 3 -->
+
+    <event name="clear_grammar_fragments" since="3">
+      <description summary="clear grammar fragments in a range">
+        IME requests to clear all the grammar markers within the given range
+        defined by start and end.
+
+        start and end are relative to the beginning of the input field in
+        utf-8 byte length.
+      </description>
+      <arg name="start" type="uint" />
+      <arg name="end" type="uint" />
+    </event>
+
+    <event name="add_grammar_fragment" since="3">
+      <description summary="add grammar fragment">
+        IME requests to add a new grammar fragment.
+
+        A grammar fragment describes a range of text (start, end) that has
+        grammar error and also gives the correct replacement text. It is
+        expected that the renderer will render markers (e.g. squigles or dashed
+        underlines) under the text to notify users that there is a grammar
+        error. It is also expected that the renderer will maintain and update
+        the position of fragment when users edit other parts of the text, e.g.
+        if users type something before the grammar fragment, the marker should
+        move accordingly.
+
+        start and end are relative to the beginning of the input field in
+        utf-8 byte length. suggestion is the correct replacement text, encoded
+        in utf-8 and suggested by ML model.
+      </description>
+      <arg name="start" type="uint" />
+      <arg name="end" type="uint" />
+      <arg name="suggestion" type="string" />
+    </event>
+
+    <request name="set_grammar_fragment_at_cursor" since="3">
+      <description summary="add grammar fragment">
+        Informs the IME of the grammar fragment containing the current cursor.
+        If not existing, both start and end are set to 0. This is called
+        whenever the cursor position or surrounding text have changed.
+
+        start and end are relative to the beginning of the input field in
+        utf-8 byte length. suggestion is the correct replacement text encoded
+        in utf-8 and suggested by ML model.
+      </description>
+      <arg name="start" type="uint" />
+      <arg name="end" type="uint" />
+      <arg name="suggestion" type="string" />
+    </request>
+
+    <!-- Version 4 -->
+
+    <event name="set_autocorrect_range" since="4">
+      <description summary="set autocorrect range">
+        IME requests to update text_input client to set the autocorrect range.
+        There is only one autocorrect range, so this replaces any existing
+        autocorrect ranges.
+
+        start and end are relative to the beginning of the input field in utf-8
+        byte length.
+
+        If start and end are the same, then the autocorrect range is cleared.
+      </description>
+      <arg name="start" type="uint" />
+      <arg name="end" type="uint" />
+    </event>
+
+    <request name="set_autocorrect_info" since="4">
+      <description summary="set autocorrect range">
+        Informs the IME the range and bounds of the current autocorrect change.
+        This is called whenever the range or bounds have changed.
+
+        start and end are relative to the beginning of the input field in utf-8
+        byte length.
+
+        x, y, width, and height are the bounds of the autocorrect text, relative
+        to the window.
+
+        This request only changes a pending state that will be effective on the
+        next 'set_surrounding_text' request.
+      </description>
+      <arg name="start" type="uint" />
+      <arg name="end" type="uint" />
+      <arg name="x" type="uint" />
+      <arg name="y" type="uint" />
+      <arg name="width" type="uint" />
+      <arg name="height" type="uint" />
+    </request>
+
+    <!-- Version 5 -->
+
+    <event name="set_virtual_keyboard_occluded_bounds" since="5">
+      <description summary="Sets the virtual keyboard's occluded bounds.">
+        This event tells the client about the part of the virtual keyboard's
+        bounds that occludes the text input's window, in screen DIP coordinates.
+        In order for the text input to make proper use of this information, it
+        needs to know its window's screen DIP bounds via another interface such
+        as the aura-shell.
+
+        The occluded bounds may be smaller than the keyboard's visual bounds.
+
+        When the virtual keyboard is hidden or floating, empty bounds are sent,
+        i.e. with zero width and height.
+      </description>
+      <arg name="x" type="int"/>
+      <arg name="y" type="int"/>
+      <arg name="width" type="int"/>
+      <arg name="height" type="int"/>
+    </event>
+
+    <!-- Version 6 -->
+
+    <request name="finalize_virtual_keyboard_changes" since="6">
+      <description summary="Finalizes the requested virtual keyboard changes.">
+        This request notifies the server that the client has finished making
+        requested changes to the virtual keyboard, and the server should update
+        the client with the latest virtual keyboard state. This avoids spurious
+        intermediate requests from causing the virtual keyboard to change state
+        unnecessarily.
+
+        Clients that connect to the server at this or higher versions must send
+        this request after it finishes sending the applicable requests. The
+        server is free to decide how it handles or honors this request.
+
+        As of version 6, the applicable requests are:
+          - zwp_text_input_v1.show_input_panel
+          - zwp_text_input_v1.hide_input_panel
+      </description>
+    </request>
+
+    <!-- Version 7 -->
+
+    <enum name="focus_reason_type" since="7">
+      <description summary="Chrome's TextInputClient::FocusReason">
+        This represents the reasons why the text input gets focused.
+      </description>
+      <entry name="none" value="0" />
+      <entry name="mouse" value="1" />
+      <entry name="touch" value="2" />
+      <entry name="pen" value="3" />
+      <entry name="other" value="4" />
+    </enum>
+
+    <request name="set_focus_reason" since="7">
+      <description summary="Specifies the reason of the following focus event">
+        Updates the reason why the following focus event is triggered.
+        This should be called just before text_input::activate,
+        and is in effect when it is called together (i.e. it is not in effect
+        until text_input::activate is called).
+
+        `reason` is an extended parameter providing the mode for the next
+        `text_input::active request`.
+      </description>
+      <arg name="reason" type="uint" enum="focus_reason_type" />
+    </request>
+
+    <!-- Version 8 -->
+
+    <enum name="inline_composition_support" since="8">
+      <description summary="Whether inline composition is supported">
+        Inline composition is an IME feature for certain languages (e.g. CJK)
+        which displays the uncommitted composition inside the input field as it
+        is being typed.
+      </description>
+      <entry name="unsupported" value="0" />
+      <entry name="supported" value="1" />
+    </enum>
+
+    <request name="set_input_type" since="8">
+      <description summary="Sets input type, mode and flags together">
+        Used in place of zwp_text_input::set_content_type.
+
+        Instead of hint and purpose, this API uses concepts that more closely
+        align with those used by Chrome.
+      </description>
+      <arg name="input_type" type="uint" enum="input_type" />
+      <arg name="input_mode" type="uint" enum="input_mode" />
+      <arg name="input_flags" type="uint" />
+      <arg name="learning_mode" type="uint" enum="learning_mode" />
+      <arg name="inline_composition_support" type="uint" enum="inline_composition_support" />
+    </request>
+
+    <!-- Version 9 -->
+
+    <enum name="surrounding_text_support" since="9">
+      <description summary="Whether surrounding text is supported" />
+      <entry name="unsupported" value="0" />
+      <entry name="supported" value="1" />
+    </enum>
+
+    <request name="set_surrounding_text_support" since="9">
+      <description summary="Sets whether surrounding text is supported">
+        Some clients are not able to provide surrounding text or selection.
+        When the server receives this request with the unsupproted enum, it
+        will disable functionality relying on surrounding text and avoid
+        sending events that depend on it like delete_surrounding_text,
+        set_preedit_region and cursor_position.
+
+        This request will take effect on the next 'set_content_type' or
+        'set_input_type' request.
+
+        By default, the server will assume surrounding text is supported.
+      </description>
+      <arg name="support" type="uint" enum="surrounding_text_support" />
+    </request>
+
+    <!-- Version 10 -->
+
+    <request name="set_surrounding_text_offset_utf16" since="10">
+      <description summary="Sets surrounding text's offset">
+        This updates UTF-16 offset of the immediately following
+        text_input::set_surrounding_text.
+
+        The value will be invalidated when the next set_surrounding_text
+        comes (i.e., if two consecutive set_surrounding_text is called,
+        the second set_surrounding_text's offset should be reset to 0).
+
+        Note: unlike other APIs, this is in "UTF-16" unit for Chrome's purpose,
+        because there's no way to convert UTF-8 offset to UTF-16 without
+        the original text, while sending whole text would cause performance
+        concerns.
+      </description>
+      <arg name="offset_utf16" type="uint"/>
+    </request>
+
+    <!-- Version 11 -->
+
+    <enum name="confirm_preedit_selection_behavior" since="11">
+      <description summary="How the selection range is affected by confirm_preedit"></description>
+      <entry name="after_preedit" value="0" summary="The cursor is moved to the end of the committed preedit text, if any."/>
+      <entry name="unchanged" value="1" summary="The selection range is not affected at all."/>
+    </enum>
+
+    <event name="confirm_preedit" since="11">
+      <description summary="Commits the current preedit">
+        Commits the current preedit and modify the selection range according to selection_behavior.
+        Has no effect if there's no preedit text.
+      </description>
+      <arg name="selection_behavior" type="uint" enum="confirm_preedit_selection_behavior" />
+    </event>
+
+    <!-- Version 12 -->
+
+    <request name="set_large_surrounding_text" since="12">
+      <description summary="sets the large surrounding text">
+        Almost as same as text_input::set_surrounding_text. However, this takes handle
+        instead of string in order to avoid the limit of the size.
+
+        |size| is the size of surrounding text in Utf-8, i.e. bytes to be read from fd.
+      </description>
+      <arg name="text" type="fd"/>
+      <arg name="size" type="uint"/>
+      <arg name="cursor" type="uint"/>
+      <arg name="anchor" type="uint"/>
+    </request>
+
+    <!-- Version 13 -->
+
+    <event name="insert_image" since="13">
+      <description summary="Inserts image">
+        This inserts a given image into current editing field. The value of src
+        should be a valid http(s) URL pointing to some image.
+
+        Note: this only works for richly-editable editing field in web apps.
+        Internally it sends a PasteFromImage editing command to blink engine.
+        If the current editing field is not richly-editable, this event will be
+        ignored.
+      </description>
+      <arg name="src" type="string" />
+    </event>
+
+  </interface>
+</protocol>
diff --git a/chromium.org/unstable/touchpad-haptics/README.md b/chromium.org/third_party/wayland-protocols/unstable/touchpad-haptics/README.md
similarity index 100%
rename from chromium.org/unstable/touchpad-haptics/README.md
rename to chromium.org/third_party/wayland-protocols/unstable/touchpad-haptics/README.md
diff --git a/chromium.org/unstable/touchpad-haptics/touchpad-haptics-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/touchpad-haptics/touchpad-haptics-unstable-v1.xml
similarity index 98%
rename from chromium.org/unstable/touchpad-haptics/touchpad-haptics-unstable-v1.xml
rename to chromium.org/third_party/wayland-protocols/unstable/touchpad-haptics/touchpad-haptics-unstable-v1.xml
index 5290bed..112e825 100644
--- a/chromium.org/unstable/touchpad-haptics/touchpad-haptics-unstable-v1.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/touchpad-haptics/touchpad-haptics-unstable-v1.xml
@@ -2,7 +2,7 @@
 <protocol name="touchpad_haptics_unstable_v1">
 
   <copyright>
-    Copyright 2021 The Chromium Authors.
+    Copyright 2021 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
diff --git a/chromium.org/third_party/wayland-protocols/unstable/ui-controls/README b/chromium.org/third_party/wayland-protocols/unstable/ui-controls/README
new file mode 100644
index 0000000..76da033
--- /dev/null
+++ b/chromium.org/third_party/wayland-protocols/unstable/ui-controls/README
@@ -0,0 +1,5 @@
+Input emulation that matches the semantics of ui_controls as defined in
+//ui/base/test/ui_controls.h.
+
+Maintainers:
+Max Ihlenfeldt <max@igalia.com>
diff --git a/chromium.org/third_party/wayland-protocols/unstable/ui-controls/ui-controls-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/ui-controls/ui-controls-unstable-v1.xml
new file mode 100644
index 0000000..6c72622
--- /dev/null
+++ b/chromium.org/third_party/wayland-protocols/unstable/ui-controls/ui-controls-unstable-v1.xml
@@ -0,0 +1,227 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<protocol name="ui_controls_unstable_v1">
+  <copyright>
+    Copyright 2022 The Chromium Authors.
+
+    Permission is hereby granted, free of charge, to any person obtaining a
+    copy of this software and associated documentation files (the "Software"),
+    to deal in the Software without restriction, including without limitation
+    the rights to use, copy, modify, merge, publish, distribute, sublicense,
+    and/or sell copies of the Software, and to permit persons to whom the
+    Software is furnished to do so, subject to the following conditions:
+
+    The above copyright notice and this permission notice (including the next
+    paragraph) shall be included in all copies or substantial portions of the
+    Software.
+
+    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
+    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
+    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
+    DEALINGS IN THE SOFTWARE.
+  </copyright>
+
+  <interface name="zcr_ui_controls_v1" version="3">
+    <description summary="requests for input emulation">
+      This global provides requests for different type of input emulation that
+      mirror the semantics of Chrome's ui_controls functions.
+    </description>
+
+    <enum name="key_state" bitfield="true">
+      <description
+          summary="whether to press, release, or press and release a key">
+        These flags signal which key events to emulate: press; release; or
+        press, then release.
+      </description>
+      <!-- same values as ui_controls::KeyEventType -->
+      <entry name="press" value="1"/>
+      <entry name="release" value="2"/>
+    </enum>
+
+    <enum name="mouse_button">
+      <description summary="which mouse button to emulate">
+        Which mouse button to emulate an event for.
+      </description>
+      <!-- same values as ui_controls::MouseButton -->
+      <entry name="left" value="0"/>
+      <entry name="middle" value="1"/>
+      <entry name="right" value="2"/>
+    </enum>
+
+    <enum name="mouse_button_state" bitfield="true">
+      <description summary="whether to press, release, or click a mouse button">
+        These flags signal which mouse button events to emulate: press; release;
+        or press, then release.
+      </description>
+      <!-- same values as ui_controls::MouseButtonState -->
+      <entry name="up" value="1"/>
+      <entry name="down" value="2"/>
+    </enum>
+
+    <enum name="modifier" bitfield="true">
+      <description summary="pressed modifiers">
+        These flags signal which modifiers should be pressed during an emulated
+        input, if any.
+      </description>
+      <!-- same values as ui_controls::AcceleratorState -->
+      <entry name="none" value="0"/>
+      <entry name="shift" value="1"/>
+      <entry name="control" value="2"/>
+      <entry name="alt" value="4"/>
+    </enum>
+
+    <enum name="touch_type" bitfield="true">
+      <description summary="type of touch to be generated">
+        These flags signal whether to emulate a touch press, release, or move.
+      </description>
+      <!-- same values as ui_controls::TouchType -->
+      <entry name="press" value="1"/>
+      <entry name="release" value="2"/>
+      <entry name="move" value="4"/>
+    </enum>
+
+    <request name="send_key_events">
+      <description summary="emulate a key press/release/press and release">
+        Requests the compositor to emulate a key press, release, or press and
+        release for the key corresponding to the given keycode, together with
+        the specified modifiers. The compositor will decide which specific
+        events to generate in response to this request. After the compositor has
+        finished processing this request, a request_processed event with a
+        matching `id` will be emitted.
+      </description>
+      <arg name="key" type="uint" summary="evdev key code"/>
+      <arg name="key_state" type="uint" enum="key_state"
+           summary="whether to press, release, or press and release the key"/>
+      <arg name="pressed_modifiers" type="uint" enum="modifier"
+           summary="pressed modifier keys"/>
+      <arg name="id" type="uint"
+           summary="will be echoed back in the matching sent event"/>
+    </request>
+
+    <request name="send_mouse_move">
+      <description summary="emulate a mouse move to the given location">
+        Requests the compositor to emulate a mouse move to the given location.
+        The compositor will decide which specific events to generate in response
+        to this request. After the compositor has finished processing this
+        request, a request_processed event with a matching `id` will be emitted.
+
+        If `surface` is null, `x` and `y` are global screen coordinates; else,
+        they are surface-local coordinates relative to `surface`.
+      </description>
+      <arg name="x" type="int" summary="x-coordinate in DIP"/>
+      <arg name="y" type="int" summary="x-coordinate in DIP"/>
+      <arg name="surface" type="object" interface="xdg_surface"
+           allow-null="true" summary="surface that x and y are relative to"/>
+      <arg name="id" type="uint"
+           summary="will be echoed back in the matching sent event"/>
+    </request>
+
+    <request name="send_mouse_button">
+      <description summary="emulate a mouse button press/release/click">
+        Requests the compositor to emulate an up (if `state` is up) / down (if
+        `state` is down) / click (i.e. down and up, if `state` is down|up) for
+        the specified mouse button at the current mouse position, together with
+        the specified modifiers. The compositor will decide which specific
+        events to generate in response to this request. After the compositor has
+        finished processing this request, a request_processed event with a
+        matching `id` will be emitted.
+      </description>
+      <arg name="button" type="uint" enum="mouse_button"
+           summary="button code of the mouse button"/>
+      <arg name="button_state" type="uint" enum="mouse_button_state"
+           summary="whether to press, release, or click the button"/>
+      <arg name="pressed_modifiers" type="uint" enum="modifier"
+           summary="pressed modifier keys"/>
+      <arg name="id" type="uint"
+           summary="will be echoed back in the matching sent event"/>
+    </request>
+
+    <request name="send_touch">
+      <description summary="emulate a touch press/release/move">
+        Requests the compositor to emulate a touch down (if `action` is press) /
+        touch up (if `action` is release) / move (if `action` is move) /
+        combination of these (if `action` is a combination of these flags) for
+        the touch point with the specified `id` (see wl_touch.down) at the
+        specified location. The compositor will decide which specific events to
+        generate in response to this request. After the compositor has finished
+        processing this request, a request_processed event with a matching `id`
+        will be emitted.
+
+        If `surface` is null, `x` and `y` are global screen coordinates; else,
+        they are surface-local coordinates relative to `surface`.
+      </description>
+      <arg name="action" type="uint" enum="touch_type"
+           summary="whether to emaulate a press, release, tap, or move"/>
+      <arg name="touch_id" type="uint"
+           summary="unique ID of the touch point (see wl_touch.down)"/>
+      <arg name="x" type="int" summary="x-coordinate in DIP"/>
+      <arg name="y" type="int" summary="x-coordinate in DIP"/>
+      <arg name="surface" type="object" interface="xdg_surface"
+           allow-null="true" summary="surface that x and y are relative to"/>
+      <arg name="id" type="uint"
+           summary="will be echoed back in the matching sent event"/>
+    </request>
+
+    <event name="request_processed">
+      <description summary="request has been processed">
+        The request with ID `id` has been fully processed.
+      </description>
+      <arg name="id" type="uint" summary="ID of the processed request"/>
+    </event>
+
+  <!-- Version 3 additions -->
+    <request name="set_display_info_id" since="3">
+      <description summary="set display ID for pending display">
+        Set the display id to be added. This is double buffered
+        and the display will be created upon `display_info_done`
+        request.
+      </description>
+      <arg name="display_id_hi" type="uint"/>
+      <arg name="display_id_low" type="uint"/>
+    </request>
+
+    <request name="set_display_info_size" since="3">
+      <description summary="set display size for pending display">
+        Set the display size to be added. The display will be
+        created upon `display_info_done` request.
+      </description>
+      <arg name="width" type="uint" summary="display width"/>
+      <arg name="height" type="uint" summary="display height"/>
+    </request>
+
+    <request name="set_display_info_device_scale_factor" since="3">
+      <description summary="set scale factor for pending display">
+        Set the display device scale factor to be added. The display
+        will be created upon `display_info_done` request.
+
+        The client has a 32-bit float scale factor that is associated with each
+        display. This scale factor must be propagated exactly to exo. To do so
+        we reinterpret_cast into a 32-bit uint and later cast back into a
+        float. This is because wayland does not support native transport of
+        floats. As different CPU architectures may use different endian
+        representations for IEEE 754 floats, this protocol implicitly assumes
+        that the caller and receiver are the same machine.
+      </description>
+      <arg name="device_scale_factor_as_uint" type="uint"
+        summary="device scale factor, in float format"/>
+    </request>
+
+    <request name="display_info_done" since="3">
+      <description summary="signal display info are done">
+        Add pending display to pending display list. The value
+        of display properties will use default value if they're
+        not set by request.
+      </description>
+    </request>
+
+    <request name="display_info_list_done" since="3">
+      <description summary="Signal the end of display info">
+        Flush the display information to ash and update the displays.
+      </description>
+        <arg name="id" type="uint"
+          summary="will be echoed back in the matching sent event"/>
+    </request>
+  </interface>
+</protocol>
diff --git a/chromium.org/unstable/vsync-feedback/README b/chromium.org/third_party/wayland-protocols/unstable/vsync-feedback/README
similarity index 100%
rename from chromium.org/unstable/vsync-feedback/README
rename to chromium.org/third_party/wayland-protocols/unstable/vsync-feedback/README
diff --git a/chromium.org/unstable/vsync-feedback/vsync-feedback-unstable-v1.xml b/chromium.org/third_party/wayland-protocols/unstable/vsync-feedback/vsync-feedback-unstable-v1.xml
similarity index 99%
rename from chromium.org/unstable/vsync-feedback/vsync-feedback-unstable-v1.xml
rename to chromium.org/third_party/wayland-protocols/unstable/vsync-feedback/vsync-feedback-unstable-v1.xml
index 79211ff..e8fba95 100644
--- a/chromium.org/unstable/vsync-feedback/vsync-feedback-unstable-v1.xml
+++ b/chromium.org/third_party/wayland-protocols/unstable/vsync-feedback/vsync-feedback-unstable-v1.xml
@@ -2,7 +2,7 @@
 <protocol name="vsync_feedback_unstable_v1">
 
   <copyright>
-    Copyright 2016 The Chromium Authors.
+    Copyright 2016 The Chromium Authors
 
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the "Software"),
diff --git a/chromium.org/unstable/color-space/README b/chromium.org/unstable/color-space/README
deleted file mode 100644
index eca7471..0000000
--- a/chromium.org/unstable/color-space/README
+++ /dev/null
@@ -1,4 +0,0 @@
-Color space protocol
-
-Maintainers:
-Jeffrey Kardatzke <jkardatzke@chromium.org>
diff --git a/chromium.org/unstable/color-space/color-space-unstable-v1.xml b/chromium.org/unstable/color-space/color-space-unstable-v1.xml
deleted file mode 100644
index 4663556..0000000
--- a/chromium.org/unstable/color-space/color-space-unstable-v1.xml
+++ /dev/null
@@ -1,192 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<protocol name="color_space_unstable_v1">
-
-  <copyright>
-    Copyright 2019 The Chromium Authors.
-
-    Permission is hereby granted, free of charge, to any person obtaining a
-    copy of this software and associated documentation files (the "Software"),
-    to deal in the Software without restriction, including without limitation
-    the rights to use, copy, modify, merge, publish, distribute, sublicense,
-    and/or sell copies of the Software, and to permit persons to whom the
-    Software is furnished to do so, subject to the following conditions:
-
-    The above copyright notice and this permission notice (including the next
-    paragraph) shall be included in all copies or substantial portions of the
-    Software.
-
-    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
-    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
-    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
-    DEALINGS IN THE SOFTWARE.
-  </copyright>
-
-  <interface name="zcr_color_space_v1" version="1">
-    <description summary="Protocol for setting the color space of a wl_surface">
-      This protocol specifies a an interface used to set the color space
-      information (primaries, transfer function, range, matrix) for a wl_surface
-      to enable correct color output for non-sRGB content.
-
-      Warning! The protocol described in this file is experimental and backward
-      incompatible changes may be made. Backward compatible changes may be added
-      together with the corresponding interface version bump. Backward
-      incompatible changes are done by bumping the version number in the
-      protocol and interface names and resetting the interface version. Once the
-      protocol is to be declared stable, the 'z' prefix and the version number
-      in the protocol and interface names are removed and the interface version
-      number is reset.
-    </description>
-
-    <request name="destroy" type="destructor">
-      <description summary="unbinds the color space interface">
-        Informs the server this interface will no longer be used. This does not
-        have any effect on wl_surface objects that have been modified through
-        this interface.
-      </description>
-    </request>
-
-    <enum name="error">
-      <entry name="invalid_primaries" value="0"
-             summary="the specified primaries are invalid"/>
-      <entry name="invalid_transfer_function" value="1"
-             summary="the specified transfer function is invalid"/>
-      <entry name="invalid_range" value="2"
-             summary="the specified range is invalid"/>
-      <entry name="invalid_matrix" value="3"
-             summary="the specified matrix is invalid"/>
-    </enum>
-
-    <enum name="primaries">
-      <entry name="bt709" value="0"
-             summary="BT.709, sRGB (HDTV)"/>
-      <entry name="bt470m" value="1"
-             summary="NTSC (Original, replaced by smpte170m)"/>
-      <entry name="bt470bg" value="2"
-             summary="PAL/SECAM (Original, replaced by smpte170m)"/>
-      <entry name="smpte170m" value="3"
-             summary="NTSC/PAL (SDTV)"/>
-      <entry name="smpte240m" value="4"
-             summary="HDTV (Original, replaced by bt709)"/>
-      <entry name="film" value="5"
-             summary="Generic film (color filters using Illuminant C)"/>
-      <entry name="bt2020" value="6"
-             summary="UHDTV"/>
-      <entry name="smptest428_1" value="7"
-             summary="D-Cinema"/>
-      <entry name="smptest431_2" value="8"
-             summary="DCI-P3"/>
-      <entry name="smptest432_1" value="9"
-             summary="Display P3"/>
-      <entry name="xyz_d50" value="10"
-             summary="XYZ color space with D50 white point"/>
-      <entry name="adobe_rgb" value="11"
-             summary="Adobe RGB"/>
-    </enum>
-
-    <enum name="transfer_function">
-      <entry name="bt709" value="0"
-             summary="BT.709, sRGB (HDTV)"/>
-      <entry name="gamma18" value="1"
-             summary="Gamma curve 1.8"/>
-      <entry name="gamma22" value="2"
-             summary="Gamma curve 2.2"/>
-      <entry name="gamma24" value="3"
-             summary="Gamma curve 2.4"/>
-      <entry name="gamma28" value="4"
-             summary="Gamma curve 2.8"/>
-      <entry name="smpte170m" value="5"
-             summary="NTSC/PAL (SDTV)"/>
-      <entry name="smpte240m" value="6"
-             summary="HDTV (Original, replaced by bt709)"/>
-      <entry name="linear" value="7"
-             summary="Linear transfer function"/>
-      <entry name="log" value="8"
-             summary="Logarithmic transfer function"/>
-      <entry name="log_sqrt" value="9"
-             summary="Logarithmic square root transfer function"/>
-      <entry name="iec61966_2_4" value="10"
-             summary="IEC 61966-2-4 transfer function"/>
-      <entry name="bt1361_ecg" value="11"
-             summary="ITU-BT.1361 ECG"/>
-      <entry name="iec61966_2_1" value="12"
-             summary="sRGB, IEC 61966-2-1 transfer function"/>
-      <entry name="bt2020_10" value="13"
-             summary="BT.2020 10 bit transfer function"/>
-      <entry name="bt2020_12" value="14"
-             summary="BT.2020 12 bit transfer function"/>
-      <entry name="smptest2084" value="15"
-             summary="SMPTE ST 2084 (PQ)"/>
-      <entry name="smptest428_1" value="16"
-             summary="D-Cinema transfer function"/>
-      <entry name="arib_std_b67" value="17"
-             summary="HLG transfer function"/>
-      <entry name="smptest2084_non_hdr" value="18"
-             summary="This is an ad-hoc transfer function that decodes SMPTE
-                      2084 content into a [0, 1] range more or less suitable for
-                      viewing on a non-hdr display"/>
-      <entry name="iec61966_2_1_hdr" value="19"
-             summary="The same as IEC61966_2_1 on the interval [0, 1], with the
-                      nonlinear segment continuing beyond 1 and point symmetry
-                      defining values below 0"/>
-      <entry name="linear_hdr" value="20"
-             summary="The same as linear but is defined for all real values"/>
-    </enum>
-
-    <enum name="matrix">
-      <entry name="rgb" value="0"
-             summary="Standard RGB components"/>
-      <entry name="bt709" value="1"
-             summary="BT.709 (HDTV) YUV"/>
-      <entry name="fcc" value="2"
-             summary="NTSC (Original, replaced by smpte170m) YUV"/>
-      <entry name="bt470bg" value="3"
-             summary="PAL/SECAM (Original, replaced by smpte170m) YUV"/>
-      <entry name="smpte170m" value="4"
-             summary="NTSC/PAL (SDTV) YUV"/>
-      <entry name="smpte240m" value="5"
-             summary="HDTV (Original, replaced by bt709) YUV"/>
-      <entry name="ycocg" value="6"
-             summary="YCoCg components"/>
-      <entry name="bt2020_ncl" value="7"
-             summary="BT.2020 YUV"/>
-      <entry name="bt2020_cl" value="8"
-             summary="BT.2020 RYB"/>
-      <entry name="ydzdx" value="9"
-             summary="YDZDX components"/>
-      <entry name="gbr" value="10"
-             summary="GBR component layout"/>
-    </enum>
-
-    <enum name="range">
-      <entry name="limited" value="0"
-             summary="Limited (16-235 for 8-bit)"/>
-      <entry name="full" value="1"
-             summary="Full (0-255 for 8-bit)"/>
-    </enum>
-
-    <request name="set_color_space">
-      <description summary="sets the color space for a surface">
-        This sets the full set of color space properties for a surface to enable
-        proper color conversion for compositing.  If any of these are invalid
-        then an error is raised.  This is double-buffered and takes effect on
-        the next commit of the surface.  It's the responsibility of the
-        compositor to do the necessary color conversions.
-      </description>
-      <arg name="surface" type="object" interface="wl_surface"
-           summary="surface"/>
-      <arg name="primaries" type="uint"
-           summary="primaries and white point"/>
-      <arg name="transfer_function" type="uint"
-           summary="electro-optical transfer function"/>
-      <arg name="matrix" type="uint"
-           summary="matrix for conversion to rgb" />
-      <arg name="range" type="uint"
-           summary="value range used by the pixels"/>
-    </request>
-
-  </interface>
-
-</protocol>
diff --git a/chromium.org/unstable/notification-shell/README b/chromium.org/unstable/notification-shell/README
deleted file mode 100644
index 01dc8cf..0000000
--- a/chromium.org/unstable/notification-shell/README
+++ /dev/null
@@ -1,4 +0,0 @@
-Notification shell protocol
-
-Maintainers:
-Tetsui Ohkubo <tetsui@chromium.org>
diff --git a/chromium.org/unstable/text-input/text-input-extension-unstable-v1.xml b/chromium.org/unstable/text-input/text-input-extension-unstable-v1.xml
deleted file mode 100644
index 5b777b4..0000000
--- a/chromium.org/unstable/text-input/text-input-extension-unstable-v1.xml
+++ /dev/null
@@ -1,86 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<protocol name="text_input_extension_unstable_v1">
-
-  <copyright>
-    Copyright 2021 The Chromium Authors.
-
-    Permission is hereby granted, free of charge, to any person obtaining a
-    copy of this software and associated documentation files (the "Software"),
-    to deal in the Software without restriction, including without limitation
-    the rights to use, copy, modify, merge, publish, distribute, sublicense,
-    and/or sell copies of the Software, and to permit persons to whom the
-    Software is furnished to do so, subject to the following conditions:
-
-    The above copyright notice and this permission notice (including the next
-    paragraph) shall be included in all copies or substantial portions of the
-    Software.
-
-    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
-    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
-    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
-    DEALINGS IN THE SOFTWARE.
-  </copyright>
-
-  <interface name="zcr_text_input_extension_v1" version="1">
-    <description summary="extends text_input to support richer operations">
-      Allows a text_input to sends more variation of operations to support
-      richer features, such as set_preedit_region.
-
-      Warning! The protocol described in this file is experimental and
-      backward incompatible changes may be made. Backward compatible changes
-      may be added together with the corresponding uinterface version bump.
-      Backward incompatible changes are done by bumping the version number in
-      the protocol and interface names and resetting the interface version.
-      Once the protocol is to be declared stable, the 'z' prefix and the
-      version number in the protocol and interface names are removed and the
-      interface version number is reset.
-    </description>
-
-    <enum name="error">
-      <entry name="extended_text_input_exists" value="0"
-             summary="the text_input already has an extended_text_input object associated"/>
-    </enum>
-
-    <request name="get_extended_text_input">
-      <description summary="get extended_text_input for a text_input">
-        Create extended_text_input object.
-        See zcr_extended_text_input interface for details.
-        If the given text_input object already has a extended_text_input object
-        associated, the extended_text_input_exists protocol error is raised.
-      </description>
-      <arg name="id" type="new_id" interface="zcr_extended_text_input_v1"/>
-      <arg name="text_input" type="object" interface="zwp_text_input_v1"/>
-    </request>
-  </interface>
-
-  <interface name="zcr_extended_text_input_v1" version="1">
-    <description summary="extension of text_input protocol">
-      The zcr_extended_text_input_v1 interface extends the text_input interface
-      to support more rich operations on text_input.
-    </description>
-
-    <request name="destroy" type="destructor">
-      <description summary="destroy extended_text_input object"/>
-    </request>
-
-    <event name="set_preedit_region">
-      <description summary="set preedit from the surrounding text">
-        IME requests to update text_input client to set the preedit
-        from the surrounding text.
-
-        index is the starting point of the preedit, relative to the current
-        cursor position in utf-8 byte-offset.
-        length is the length of the preedit region in utf-8 byte length.
-
-        Following the convention we have in text_input::preedit_string,
-        text_input::preedit_styling sent just before this will be applied.
-      </description>
-      <arg name="index" type="int" />
-      <arg name="length" type="uint" />
-    </event>
-
-  </interface>
-</protocol>
diff --git a/freedesktop.org/.gitlab-ci.yml b/freedesktop.org/.gitlab-ci.yml
index 66a56a3..23c3de3 100644
--- a/freedesktop.org/.gitlab-ci.yml
+++ b/freedesktop.org/.gitlab-ci.yml
@@ -1,27 +1,63 @@
-variables:
-  DEBIAN_TAG: 2019-11-21.0
-  DEBIAN_VERSION: stable
-  TEST_IMAGE: "$CI_REGISTRY_IMAGE/debian/$DEBIAN_VERSION:$DEBIAN_TAG"
+.templates_sha: &template_sha 290b79e0e78eab67a83766f4e9691be554fc4afd
 
 include:
-  - project: 'wayland/ci-templates'
-    ref: f69acac60d5dde0410124fd5674764600821b7a6
+  - project: 'freedesktop/ci-templates'
+    ref: *template_sha
     file: '/templates/debian.yml'
+  - project: 'freedesktop/ci-templates'
+    ref: *template_sha
+    file: '/templates/ci-fairy.yml'
 
 stages:
+  - review
   - containers-build
   - test
 
+variables:
+  FDO_UPSTREAM_REPO: wayland/wayland-protocols
+
+.debian:
+  variables:
+    FDO_DISTRIBUTION_VERSION: bullseye
+    FDO_DISTRIBUTION_PACKAGES: 'build-essential automake autoconf libtool pkg-config libwayland-dev meson'
+    FDO_DISTRIBUTION_TAG: '2021-03-24.0'
+
+check-commit:
+  extends:
+    - .fdo.ci-fairy
+  stage: review
+  script:
+    - ci-fairy check-commits --signed-off-by --junit-xml=results.xml
+  variables:
+    GIT_DEPTH: 100
+  artifacts:
+    reports:
+      junit: results.xml
+
 container_build:
-  extends: .debian@container-ifnot-exists
+  extends:
+    - .debian
+    - .fdo.container-build@debian
   stage: containers-build
   variables:
-    GIT_STRATEGY: none # no need to pull the whole tree for rebuilding the image
-    DEBIAN_DEBS: 'build-essential automake autoconf libtool pkg-config libwayland-dev'
+    GIT_STRATEGY: none
+
+test-meson:
+  stage: test
+  extends:
+    - .debian
+    - .fdo.distribution-image@debian
+  script:
+    - meson build
+    - ninja -C build
+    - meson test -C build
+    - ninja -C build install
 
-test:
+test-autotools:
   stage: test
-  image: $TEST_IMAGE
+  extends:
+    - .debian
+    - .fdo.distribution-image@debian
   script:
     - ./autogen.sh
     - make check
diff --git a/freedesktop.org/MEMBERS.md b/freedesktop.org/MEMBERS.md
index 8c35637..1aa112c 100644
--- a/freedesktop.org/MEMBERS.md
+++ b/freedesktop.org/MEMBERS.md
@@ -1,13 +1,15 @@
 # wayland-protocols members
 
-- EFL/Enlightenment: Mike Blumenkrantz <michael.blumenkrantz@gmail.com>
-- GTK/Mutter: Jonas Ådahl <jadahl@gmail.com>,
-  Carlos Garnacho <carlosg@gnome.org>
-- KWin: Eike Hein <hein@kde.org>,
-  David Edmundson <david@davidedmundson.co.uk>
-- Mir: Christopher James Halse Rogers <raof@ubuntu.com>,
+- EFL/Enlightenment: Mike Blumenkrantz <michael.blumenkrantz@gmail.com> (@zmike)
+- GTK/Mutter: Jonas Ådahl <jadahl@gmail.com> (@jadahl),
+  Carlos Garnacho <carlosg@gnome.org> (@carlosg)
+- KWin: Eike Hein <hein@kde.org> (@hein),
+  David Edmundson <david@davidedmundson.co.uk> (@davidedmundson)
+- Mir: Christopher James Halse Rogers <raof@ubuntu.com> (@RAOF),
   Alan Griffiths <alan.griffiths@canonical.com>
 - Qt: Eskil Abrahamsen Blomfeldt <eskil.abrahamsen-blomfeldt@qt.io>
-- Weston: Pekka Paalanen <pekka.paalanen@collabora.com>,
-  Daniel Stone <daniel@fooishbar.org>
-- wlroots/Sway: Drew DeVault <sir@cmpwn.com>, Simon Ser <contact@emersion.fr>
+  (@eskilblomfeldt)
+- Weston: Pekka Paalanen <pekka.paalanen@collabora.com> (@pq),
+  Daniel Stone <daniel@fooishbar.org> (@daniels)
+- wlroots/Sway: Drew DeVault <sir@cmpwn.com> (@ddevault),
+  Simon Ser <contact@emersion.fr> (@emersion)
diff --git a/freedesktop.org/METADATA b/freedesktop.org/METADATA
index 6a4aa06..4edaddf 100644
--- a/freedesktop.org/METADATA
+++ b/freedesktop.org/METADATA
@@ -11,7 +11,7 @@ third_party {
     type: GIT
     value: "https://gitlab.freedesktop.org/wayland/wayland-protocols.git"
   }
-  version: "d10d18f3d49374d2e3eb96d63511f32795aab5f7"
-  last_upgrade_date { year: 2020 month: 03 day: 17 }
+  version: "1.22"
+  last_upgrade_date { year: 2024 month: 7 day: 23 }
   license_type: NOTICE
 }
diff --git a/freedesktop.org/MODULE_LICENSE_MIT b/freedesktop.org/MODULE_LICENSE_MIT
deleted file mode 100644
index e69de29..0000000
diff --git a/freedesktop.org/Makefile.am b/freedesktop.org/Makefile.am
index 1f32890..8ae76f1 100644
--- a/freedesktop.org/Makefile.am
+++ b/freedesktop.org/Makefile.am
@@ -31,24 +31,43 @@ stable_protocols =								\
 	stable/xdg-shell/xdg-shell.xml						\
 	$(NULL)
 
+staging_protocols =								\
+	staging/drm-lease/drm-lease-v1.xml					\
+	staging/xdg-activation/xdg-activation-v1.xml				\
+	$(NULL)
+
+misc_documentation =								\
+	staging/xdg-activation/x11-interoperation.rst				\
+	$(NULL)
+
 nobase_dist_pkgdata_DATA =							\
 	$(unstable_protocols)							\
 	$(stable_protocols)							\
+	$(staging_protocols)							\
 	$(NULL)
 
 dist_noinst_DATA =								\
 	$(sort $(foreach p,$(unstable_protocols),$(dir $p)README))		\
 	$(sort $(foreach p,$(stable_protocols),$(dir $p)README))		\
+	$(sort $(foreach p,$(staging_protocols),$(dir $p)README))		\
+	$(misc_documentation)							\
 	README.md								\
 	GOVERNANCE.md								\
 	MEMBERS.md								\
+	meson.build								\
+	meson_options.txt							\
+	tests/meson.build							\
+	tests/build-cxx.cc.in							\
+	tests/build-pedantic.c.in						\
+	tests/replace.py							\
+	tests/scan.sh								\
 	$(NULL)
 
 noarch_pkgconfig_DATA = wayland-protocols.pc
 
 dist_check_SCRIPTS = tests/scan.sh
 
-TESTS = $(unstable_protocols) $(stable_protocols)
+TESTS = $(unstable_protocols) $(stable_protocols) $(staging_protocols)
 TEST_EXTENSIONS = .xml
 AM_TESTS_ENVIRONMENT = SCANNER='$(wayland_scanner)'; export SCANNER;
 XML_LOG_COMPILER = $(srcdir)/tests/scan.sh
diff --git a/freedesktop.org/README b/freedesktop.org/README
deleted file mode 100644
index da1f1d5..0000000
--- a/freedesktop.org/README
+++ /dev/null
@@ -1,141 +0,0 @@
-Wayland protocols
------------------
-
-wayland-protocols contains Wayland protocols that add functionality not
-available in the Wayland core protocol. Such protocols either add
-completely new functionality, or extend the functionality of some other
-protocol either in Wayland core, or some other protocol in
-wayland-protocols.
-
-A protocol in wayland-protocols consists of a directory containing a set
-of XML files containing the protocol specification, and a README file
-containing detailed state and a list of maintainers.
-
-Protocol directory tree structure
-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
-Protocols may be 'stable', 'unstable' or 'deprecated', and the interface
-and protocol names as well as place in the directory tree will reflect
-this.
-
-A stable protocol is a protocol which has been declared stable by
-the maintainers. Changes to such protocols will always be backward
-compatible.
-
-An unstable protocol is a protocol currently under development and this
-will be reflected in the protocol and interface names. See <<Unstable
-naming convention>>.
-
-A deprecated protocol is a protocol that has either been replaced by some
-other protocol, or declared undesirable for some other reason. No more
-changes will be made to a deprecated protocol.
-
-Depending on which of the above states the protocol is in, the protocol
-is placed within the toplevel directory containing the protocols with the
-same state. Stable protocols are placed in the +stable/+ directory,
-unstable protocols are placed in the +unstable/+ directory, and
-deprecated protocols are placed in the +deprecated/+ directory.
-
-Protocol development procedure
-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
-To propose a new protocol, create a patch adding the relevant files and
-Makefile.am entry to the wayland-protocols git repository with the
-explanation and motivation in the commit message. Then send the patch to
-the wayland-devel@lists.freedesktop.org mailing list using
-'git send-email' with the subject prefix 'RFC wayland-protocols' or
-'PATCH wayland-protocols' depending on what state the protocol is in.
-
-To propose changes to existing protocols, create a patch with the
-changes and send it to the list mentioned above while also CC:ing the
-maintainers mentioned in the README file. Use the same rule for adding a
-subject prefix as above and method for sending the patch.
-
-If the changes are backward incompatible changes to an unstable protocol,
-see <<Unstable protocol changes>>.
-
-Interface naming convention
-~~~~~~~~~~~~~~~~~~~~~~~~~~~
-All protocols should avoid using generic namespaces or no namespaces in
-the protocol interface names in order to minimize risk that the generated
-C API collides with other C API. Interface names that may collide with
-interface names from other protocols should also be avoided.
-
-For generic protocols not limited to certain configurations (such as
-specific desktop environment or operating system) the +wp_+ prefix
-should be used on all interfaces in the protocol.
-
-For operating system specific protocols, the interfaces should be
-prefixed with both +wp_+ and the operating system, for example
-+wp_linux_+, or +wp_freebsd_+, etc.
-
-Unstable naming convention
-~~~~~~~~~~~~~~~~~~~~~~~~~~
-Unstable protocols have a special naming convention in order to make it
-possible to make discoverable backward incompatible changes.
-
-An unstable protocol has at least two versions: the major version, which
-represents backward incompatible changes, and the minor version, which
-represents backward compatible changes to the interfaces in the protocol.
-
-The major version is part of the XML file name, the protocol name in the
-XML, and interface names in the protocol.
-
-Minor versions are the version attributes of the interfaces in the XML.
-There may be more than one minor version per protocol, if there are more
-than one global.
-
-The XML file and protocol name also has the word 'unstable' in them, and
-all of the interfaces in the protocol are prefixed with +z+ and
-suffixed with the major version number.
-
-For example, an unstable protocol called foo-bar with major version 2
-containing the two interfaces wp_foo and wp_bar both minor version 1 will
-be placed in the directory +unstable/foo-bar/+ consisting of one file
-called +README+ and one called +foo-bar-unstable-v2.xml+. The XML file
-will consist of two interfaces called +zwp_foo_v2+ and +zwp_bar_v2+ with
-the +version+ attribute set to +1+.
-
-Unstable protocol changes
-~~~~~~~~~~~~~~~~~~~~~~~~~
-During the development of a new protocol it is possible that backward
-incompatible changes are needed. Such a change needs to be represented
-in the major and minor versions of the protocol.
-
-Assuming a backward incompatible change is needed, the procedure for how to
-do so is the following:
-
-  . Make a copy of the XML file with the major version increased by +1+.
-  . Increase the major version number in the protocol XML by +1+.
-  . Increase the major version number in all of the interfaces in the
-    XML by +1+.
-  . Reset the minor version number (interface version attribute) of all
-    the interfaces to +1+.
-
-Backward compatible changes within a major unstable version can be done
-in the regular way as done in core Wayland or in stable protocols.
-
-Declaring a protocol stable
-~~~~~~~~~~~~~~~~~~~~~~~~~~~
-Once it is decided that a protocol should be declared stable, meaning no
-more backward incompatible changes will ever be allowed, one last
-breakage is needed.
-
-The procedure of doing this is the following:
-
-  . Create a new directory in the +stable/+ toplevel directory with the
-    same name as the protocol directory in the +unstable/+ directory.
-  . Copy the final version of the XML that is the version that was
-    decided to be declared stable into the new directory. The target name
-    should be the same name as the protocol directory but with the +.xml+
-    suffix.
-  . Rename the name of the protocol in the XML by removing the
-    'unstable' part and the major version number.
-  . Remove the +z+ prefix and the major version number suffix from all
-    of the interfaces in the protocol.
-  . Reset all of the interface version attributes to +1+.
-  . Update the +README+ file in the unstable directory and create a new
-    +README+ file in the new directory.
-
-Releases
-~~~~~~~~
-Each release of wayland-protocols finalizes the version of the protocols
-to their state they had at that time.
diff --git a/freedesktop.org/README.md b/freedesktop.org/README.md
index c61ed8a..5af76d9 100644
--- a/freedesktop.org/README.md
+++ b/freedesktop.org/README.md
@@ -10,29 +10,69 @@ A protocol in wayland-protocols consists of a directory containing a set
 of XML files containing the protocol specification, and a README file
 containing detailed state and a list of maintainers.
 
-## Protocol directory tree structure
-
-Protocols may be "stable", "unstable" or "deprecated", and the interface
-and protocol names as well as place in the directory tree will reflect
-this.
-
-A stable protocol is a protocol which has been declared stable by
-the maintainers. Changes to such protocols will always be backward
-compatible.
+## Protocol phases
+
+Protocols in general has three phases: the development phase, the testing
+phase, and the stable phase.
+
+In the development phase, a protocol is not officially part of
+wayland-protocols, but is actively being developed, for example by
+iterating over it in a
+[merge
+request](https://gitlab.freedesktop.org/wayland/wayland-protocols/merge_requests),
+or planning it in an
+[issue](https://gitlab.freedesktop.org/wayland/wayland-protocols/issues).
+
+During this phase, patches for clients and compositors are written as a test
+vehicle. Such patches must not be merged in clients and compositors, because
+the protocol can still change.
+
+When a protocol has reached a stage where it is ready for wider adoption,
+and after the [GOVERNANCE section
+2.3](GOVERNANCE.md#2.3-introducing-new-protocols) requirements have been
+met, it enters the "testing" phase. At this point, the protocol is added
+to `staging/` directory of wayland-protocols and made part of a release.
+What this means is that implementation is encouraged in clients and
+compositors where the functionality it specifies is wanted.
+
+Extensions in staging cannot have backward incompatible changes, in that
+sense they are equal to stable extensions. However, they may be completely
+replaced with a new major version, or a different protocol extension all
+together, if design flaws are found in the testing phase.
+
+After a staging protocol has been sufficiently tested in the wild and
+proven adequate, its maintainers and the community at large may declare it
+"stable", meaning it is unexpected to become superseded by a new major
+version.
+
+## Deprecation
+
+A protocol may be deprecated, if it has been replaced by some other
+protocol, or declared undesirable for some other reason. No more changes
+will be made to a deprecated protocol.
+
+## Legacy protocol phases
+
+An "unstable" protocol refers to a protocol categorization policy
+previously used by wayland-protocols, where protocols initially
+placed in the `unstable/` directory had certain naming conventions were
+applied, requiring a backward incompatible change to be declared "stable".
+
+During this phase, protocol extension interface names were in addition to
+the major version postfix also prefixed with `z` to distinguish from
+stable protocols.
 
-An unstable protocol is a protocol currently under development and this
-will be reflected in the protocol and interface names. See [Unstable
-naming convention](#unstable-naming-convention).
+## Protocol directory tree structure
 
-A deprecated protocol is a protocol that has either been replaced by some
-other protocol, or declared undesirable for some other reason. No more
-changes will be made to a deprecated protocol.
+Depending on which stage a protocol is in, the protocol is placed within
+the toplevel directory containing the protocols with the same stage.
+Stable protocols are placed in the `stable/` directory, staging protocols
+are placed in the `staging/` directory, and deprecated protocols are
+placed in the `deprecated/` directory.
 
-Depending on which of the above states the protocol is in, the protocol
-is placed within the toplevel directory containing the protocols with the
-same state. Stable protocols are placed in the `stable/` directory,
-unstable protocols are placed in the `unstable/` directory, and
-deprecated protocols are placed in the `deprecated/` directory.
+Unstable protocols (see [Legacy protocol phases](#legacy-protocol-phases))
+can be found in the `unstable/` directory, but new ones should never be
+placed here.
 
 ## Protocol development procedure
 
@@ -49,8 +89,11 @@ RFC, create a merge request and add the "WIP:" prefix in the title.
 
 To propose changes to existing protocols, create a GitLab merge request.
 
-If the changes are backward incompatible changes to an unstable protocol,
-see [Unstable protocol changes](#unstable-protocol-changes).
+Please include a `Signed-off-by` line at the end of the commit to certify
+that you wrote it or otherwise have the right to pass it on as an
+open-source patch. See the
+[Developer Certificate of Origin](https://developercertificate.org/) for
+a formal definition.
 
 ## Interface naming convention
 
@@ -73,38 +116,42 @@ prefixed with both `wp_` and the operating system, for example
 For more information about namespaces, see [GOVERNANCE section 2.1
 ](GOVERNANCE.md#21-protocol-namespaces).
 
-## Unstable naming convention
+Each new protocol XML file must include a major version postfix, starting
+with `-v1`. The purpose of this postfix is to make it possible to
+distinguish between backward incompatible major versions of the same
+protocol.
 
-Unstable protocols have a special naming convention in order to make it
-possible to make discoverable backward incompatible changes.
+The interfaces in the protocol XML file should as well have the same
+major version postfix in their names.
 
-An unstable protocol has at least two versions: the major version, which
-represents backward incompatible changes, and the minor version, which
-represents backward compatible changes to the interfaces in the protocol.
+For example, the protocol `foo-bar` may have a XML file
+`foo-bar/foo-bar-v1.xml`, consisting of the interface `wp_foo_bar_v1`,
+corresponding to the major version 1, as well as the newer version
+`foo-bar/foo-bar-v2.xml` consisting of the interface `wp_foo_bar_v2`,
+corresponding to the major version 2.
 
-The major version is part of the XML file name, the protocol name in the
-XML, and interface names in the protocol.
+## Include a disclaimer
 
-Minor versions are the version attributes of the interfaces in the XML.
-There may be more than one minor version per protocol, if there are more
-than one global.
+Include the following disclaimer:
 
-The XML file and protocol name also has the word 'unstable' in them, and
-all of the interfaces in the protocol are prefixed with `z` and
-suffixed with the major version number.
+```
+Warning! The protocol described in this file is currently in the testing
+phase. Backward compatible changes may be added together with the
+corresponding interface version bump. Backward incompatible changes can
+only be done by creating a new major version of the extension.
+```
 
-For example, an unstable protocol called `foo-bar` with major version 2
-containing the two interfaces `wp_foo` and `wp_bar` both minor version 1
-will be placed in the directory `unstable/foo-bar/` consisting of one file
-called `README` and one called `foo-bar-unstable-v2.xml`. The XML file
-will consist of two interfaces called `zwp_foo_v2` and `zwp_bar_v2` with
-the `version` attribute set to 1.
+## Backward compatible protocol changes
 
-## Unstable protocol changes
+A protocol may receive backward compatible additions and changes. This
+is to be done in the general Wayland way, using `version` and `since` XML
+element attributes.
 
-During the development of a new protocol it is possible that backward
-incompatible changes are needed. Such a change needs to be represented
-in the major and minor versions of the protocol.
+## Backward incompatible protocol changes
+
+While not preferred, a protocol may at any stage, especially during the
+testing phase, when it is located in the `staging/` directory, see
+backward incompatible changes.
 
 Assuming a backward incompatible change is needed, the procedure for how to
 do so is the following:
@@ -113,33 +160,38 @@ do so is the following:
 - Increase the major version number in the protocol XML by 1.
 - Increase the major version number in all of the interfaces in the
   XML by 1.
-- Reset the minor version number (interface version attribute) of all
+- Reset the interface version number (interface version attribute) of all
   the interfaces to 1.
-
-Backward compatible changes within a major unstable version can be done
-in the regular way as done in core Wayland or in stable protocols.
+- Remove all of the `since` attributes.
 
 ## Declaring a protocol stable
 
-Once it is decided that a protocol should be declared stable, meaning no
-more backward incompatible changes will ever be allowed, one last
-breakage is needed.
+Once it has been concluded that a protocol been proven adequate in
+production, and that it is deemed unlikely to receive any backward
+incompatible changes, it may be declared stable.
 
 The procedure of doing this is the following:
 
 - Create a new directory in the `stable/` toplevel directory with the
-  same name as the protocol directory in the `unstable/` directory.
+  same name as the protocol directory in the `staging/` directory.
 - Copy the final version of the XML that is the version that was
   decided to be declared stable into the new directory. The target name
   should be the same name as the protocol directory but with the `.xml`
   suffix.
-- Rename the name of the protocol in the XML by removing the
-  `unstable` part and the major version number.
-- Remove the `z` prefix and the major version number suffix from all
-  of the interfaces in the protocol.
-- Reset all of the interface version attributes to 1.
-- Update the `README` file in the unstable directory and create a new
+- Remove the disclaimer about the protocol being in the testing phase.
+- Update the `README` file in the staging directory and create a new
   `README` file in the new directory.
+- Replace the disclaimer in the protocol files left in the staging/
+  directory with the following:
+
+```
+Disclaimer: This protocol extension has been marked stable. This copy is
+no longer used and only retained for backwards compatibility. The
+canonical version can be found in the stable/ directory.
+```
+
+Note that the major version of the stable protocol extension, as well as
+all the interface versions and names, must remain unchanged.
 
 There are other requirements for declaring a protocol stable, see
 [GOVERNANCE section 2.3](GOVERNANCE.md#23-introducing-new-protocols).
@@ -177,9 +229,9 @@ implementations, see the GOVERNANCE.md document.
 
 When merge requests get their needed feedback and items, remove the
 corresponding label that marks it as needing something. For example, if a
-merge request receives all the required acknowledgments, remove the ~"Needs
-acks" label, or if 30 days passed since opening, remove any ~"In 30 days
-discussion period" label.
+merge request receives all the required acknowledgments, remove the
+~"Needs acks" label, or if 30 days passed since opening, remove any
+~"In 30 day discussion period" label.
 
 ### Nacking a merge request
 
diff --git a/freedesktop.org/configure.ac b/freedesktop.org/configure.ac
index 388004c..7f675a4 100644
--- a/freedesktop.org/configure.ac
+++ b/freedesktop.org/configure.ac
@@ -1,7 +1,7 @@
 AC_PREREQ([2.64])
 
 m4_define([wayland_protocols_major_version], [1])
-m4_define([wayland_protocols_minor_version], [20])
+m4_define([wayland_protocols_minor_version], [22])
 m4_define([wayland_protocols_version],
           [wayland_protocols_major_version.wayland_protocols_minor_version])
 
diff --git a/freedesktop.org/meson.build b/freedesktop.org/meson.build
new file mode 100644
index 0000000..6076c24
--- /dev/null
+++ b/freedesktop.org/meson.build
@@ -0,0 +1,120 @@
+project('wayland-protocols',
+	version: '1.22',
+	meson_version: '>= 0.54.0',
+	license: 'MIT/Expat',
+)
+
+wayland_protocols_version = meson.project_version()
+
+fs = import('fs')
+
+dep_scanner = dependency('wayland-scanner', native: true)
+
+stable_protocols = [
+	'presentation-time',
+	'viewporter',
+	'xdg-shell',
+]
+
+unstable_protocols = {
+	'fullscreen-shell': ['v1'],
+	'idle-inhibit': ['v1'],
+	'input-method': ['v1'],
+	'input-timestamps': ['v1'],
+	'keyboard-shortcuts-inhibit': ['v1'],
+	'linux-dmabuf': ['v1'],
+	'linux-explicit-synchronization': ['v1'],
+	'pointer-constraints': ['v1'],
+	'pointer-gestures': ['v1'],
+	'primary-selection': ['v1'],
+	'relative-pointer': ['v1'],
+	'tablet': ['v1', 'v2'],
+	'text-input': ['v1', 'v3'],
+	'xdg-decoration': ['v1'],
+	'xdg-foreign': ['v1', 'v2'],
+	'xdg-output': ['v1'],
+	'xdg-shell': ['v5', 'v6'],
+	'xwayland-keyboard-grab': ['v1'],
+}
+
+staging_protocols = {
+	'xdg-activation': ['v1'],
+	'drm-lease': ['v1'],
+}
+
+protocol_files = []
+
+foreach name : stable_protocols
+	protocol_files += ['stable/@0@/@0@.xml'.format(name)]
+endforeach
+
+foreach name : staging_protocols.keys()
+	foreach version : staging_protocols.get(name)
+		protocol_files += [
+			'staging/@0@/@0@-@1@.xml'.format(name, version)
+		]
+	endforeach
+endforeach
+
+foreach name : unstable_protocols.keys()
+	foreach version : unstable_protocols.get(name)
+		protocol_files += [
+			'unstable/@0@/@0@-unstable-@1@.xml'.format(name, version)
+		]
+	endforeach
+endforeach
+
+# Check that each protocol has a README
+foreach protocol_file : protocol_files
+	dir = fs.parent(protocol_file)
+	if not fs.is_file(dir + '/README')
+		error('Missing README in @0@'.format(protocol_file))
+	endif
+endforeach
+
+foreach protocol_file : protocol_files
+	protocol_install_dir = fs.parent(join_paths(
+		get_option('datadir'),
+		'wayland-protocols',
+		protocol_file,
+	))
+	install_data(
+		protocol_file,
+		install_dir: protocol_install_dir,
+	)
+endforeach
+
+wayland_protocols_srcdir = meson.current_source_dir()
+
+pkgconfig_configuration = configuration_data()
+pkgconfig_configuration.set('prefix', get_option('prefix'))
+pkgconfig_configuration.set('datarootdir', '${prefix}/@0@'.format(get_option('datadir')))
+pkgconfig_configuration.set('abs_top_srcdir', wayland_protocols_srcdir)
+pkgconfig_configuration.set('PACKAGE', 'wayland-protocols')
+pkgconfig_configuration.set('WAYLAND_PROTOCOLS_VERSION', wayland_protocols_version)
+
+pkg_install_dir = join_paths(get_option('datadir'), 'pkgconfig')
+configure_file(
+	input: 'wayland-protocols.pc.in',
+	output: 'wayland-protocols.pc',
+	configuration: pkgconfig_configuration,
+	install_dir: pkg_install_dir,
+)
+
+configure_file(
+	input: 'wayland-protocols-uninstalled.pc.in',
+	output: 'wayland-protocols-uninstalled.pc',
+	configuration: pkgconfig_configuration,
+)
+
+wayland_protocols = declare_dependency(
+	variables: {
+		'pkgdatadir': wayland_protocols_srcdir,
+	},
+)
+
+meson.override_dependency('wayland-protocols', wayland_protocols)
+
+if get_option('tests')
+	subdir('tests')
+endif
diff --git a/freedesktop.org/meson_options.txt b/freedesktop.org/meson_options.txt
new file mode 100644
index 0000000..f361d3b
--- /dev/null
+++ b/freedesktop.org/meson_options.txt
@@ -0,0 +1,4 @@
+option('tests',
+       type: 'boolean',
+       value: true,
+       description: 'Build the tests')
diff --git a/freedesktop.org/stable/presentation-time/presentation-time.xml b/freedesktop.org/stable/presentation-time/presentation-time.xml
index d1731f0..b666664 100644
--- a/freedesktop.org/stable/presentation-time/presentation-time.xml
+++ b/freedesktop.org/stable/presentation-time/presentation-time.xml
@@ -159,43 +159,43 @@
         These flags provide information about how the presentation of
         the related content update was done. The intent is to help
         clients assess the reliability of the feedback and the visual
-        quality with respect to possible tearing and timings. The
-        flags are:
-
-        VSYNC:
-        The presentation was synchronized to the "vertical retrace" by
-        the display hardware such that tearing does not happen.
-        Relying on user space scheduling is not acceptable for this
-        flag. If presentation is done by a copy to the active
-        frontbuffer, then it must guarantee that tearing cannot
-        happen.
-
-        HW_CLOCK:
-        The display hardware provided measurements that the hardware
-        driver converted into a presentation timestamp. Sampling a
-        clock in user space is not acceptable for this flag.
-
-        HW_COMPLETION:
-        The display hardware signalled that it started using the new
-        image content. The opposite of this is e.g. a timer being used
-        to guess when the display hardware has switched to the new
-        image content.
-
-        ZERO_COPY:
-        The presentation of this update was done zero-copy. This means
-        the buffer from the client was given to display hardware as
-        is, without copying it. Compositing with OpenGL counts as
-        copying, even if textured directly from the client buffer.
-        Possible zero-copy cases include direct scanout of a
-        fullscreen surface and a surface on a hardware overlay.
+        quality with respect to possible tearing and timings.
       </description>
-      <entry name="vsync" value="0x1" summary="presentation was vsync'd"/>
-      <entry name="hw_clock" value="0x2"
-             summary="hardware provided the presentation timestamp"/>
-      <entry name="hw_completion" value="0x4"
-             summary="hardware signalled the start of the presentation"/>
-      <entry name="zero_copy" value="0x8"
-             summary="presentation was done zero-copy"/>
+      <entry name="vsync" value="0x1">
+        <description summary="presentation was vsync'd">
+          The presentation was synchronized to the "vertical retrace" by
+          the display hardware such that tearing does not happen.
+          Relying on user space scheduling is not acceptable for this
+          flag. If presentation is done by a copy to the active
+          frontbuffer, then it must guarantee that tearing cannot
+          happen.
+        </description>
+      </entry>
+      <entry name="hw_clock" value="0x2">
+        <description summary="hardware provided the presentation timestamp">
+          The display hardware provided measurements that the hardware
+          driver converted into a presentation timestamp. Sampling a
+          clock in user space is not acceptable for this flag.
+        </description>
+      </entry>
+      <entry name="hw_completion" value="0x4">
+        <description summary="hardware signalled the start of the presentation">
+          The display hardware signalled that it started using the new
+          image content. The opposite of this is e.g. a timer being used
+          to guess when the display hardware has switched to the new
+          image content.
+        </description>
+      </entry>
+      <entry name="zero_copy" value="0x8">
+        <description summary="presentation was done zero-copy">
+          The presentation of this update was done zero-copy. This means
+          the buffer from the client was given to display hardware as
+          is, without copying it. Compositing with OpenGL counts as
+          copying, even if textured directly from the client buffer.
+          Possible zero-copy cases include direct scanout of a
+          fullscreen surface and a surface on a hardware overlay.
+        </description>
+      </entry>
     </enum>
 
     <event name="presented">
diff --git a/freedesktop.org/stable/xdg-shell/xdg-shell.xml b/freedesktop.org/stable/xdg-shell/xdg-shell.xml
index ae8ab67..364d130 100644
--- a/freedesktop.org/stable/xdg-shell/xdg-shell.xml
+++ b/freedesktop.org/stable/xdg-shell/xdg-shell.xml
@@ -75,7 +75,9 @@
       <description summary="create a shell surface from a surface">
 	This creates an xdg_surface for the given surface. While xdg_surface
 	itself is not a role, the corresponding surface may only be assigned
-	a role extending xdg_surface, such as xdg_toplevel or xdg_popup.
+	a role extending xdg_surface, such as xdg_toplevel or xdg_popup. It is
+	illegal to create an xdg_surface for a wl_surface which already has an
+	assigned role and this will result in a protocol error.
 
 	This creates an xdg_surface for the given surface. An xdg_surface is
 	used as basis to define a role to a given surface, such as xdg_toplevel
diff --git a/freedesktop.org/staging/drm-lease/README b/freedesktop.org/staging/drm-lease/README
new file mode 100644
index 0000000..36bfbcc
--- /dev/null
+++ b/freedesktop.org/staging/drm-lease/README
@@ -0,0 +1,6 @@
+Linux DRM lease
+
+Maintainers:
+Drew DeVault <sir@cmpwn.com>
+Marius Vlad <marius.vlad@collabora.com>
+Xaver Hugl <xaver.hugl@gmail.com>
diff --git a/freedesktop.org/staging/drm-lease/drm-lease-v1.xml b/freedesktop.org/staging/drm-lease/drm-lease-v1.xml
new file mode 100644
index 0000000..8724a1a
--- /dev/null
+++ b/freedesktop.org/staging/drm-lease/drm-lease-v1.xml
@@ -0,0 +1,303 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<protocol name="drm_lease_v1">
+  <copyright>
+    Copyright © 2018 NXP
+    Copyright © 2019 Status Research &amp; Development GmbH.
+    Copyright © 2021 Xaver Hugl
+
+    Permission is hereby granted, free of charge, to any person obtaining a
+    copy of this software and associated documentation files (the "Software"),
+    to deal in the Software without restriction, including without limitation
+    the rights to use, copy, modify, merge, publish, distribute, sublicense,
+    and/or sell copies of the Software, and to permit persons to whom the
+    Software is furnished to do so, subject to the following conditions:
+
+    The above copyright notice and this permission notice (including the next
+    paragraph) shall be included in all copies or substantial portions of the
+    Software.
+
+    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
+    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
+    DEALINGS IN THE SOFTWARE.
+  </copyright>
+
+  <interface name="wp_drm_lease_device_v1" version="1">
+    <description summary="lease device">
+      This protocol is used by Wayland compositors which act as Direct
+      Renderering Manager (DRM) masters to lease DRM resources to Wayland
+      clients.
+
+      The compositor will advertise one wp_drm_lease_device_v1 global for each
+      DRM node. Some time after a client binds to the wp_drm_lease_device_v1
+      global, the compositor will send a drm_fd event followed by zero, one or
+      more connector events. After all currently available connectors have been
+      sent, the compositor will send a wp_drm_lease_device_v1.done event.
+
+      When the list of connectors available for lease changes the compositor
+      will send wp_drm_lease_device_v1.connector events for added connectors and
+      wp_drm_lease_connector_v1.withdrawn events for removed connectors,
+      followed by a wp_drm_lease_device_v1.done event.
+
+      The compositor will indicate when a device is gone by removing the global
+      via a wl_registry.global_remove event. Upon receiving this event, the
+      client should destroy any matching wp_drm_lease_device_v1 object.
+
+      To destroy a wp_drm_lease_device_v1 object, the client must first issue
+      a release request. Upon receiving this request, the compositor will
+      immediately send a released event and destroy the object. The client must
+      continue to process and discard drm_fd and connector events until it
+      receives the released event. Upon receiving the released event, the
+      client can safely cleanup any client-side resources.
+
+      Warning! The protocol described in this file is currently in the testing
+      phase. Backward compatible changes may be added together with the
+      corresponding interface version bump. Backward incompatible changes can
+      only be done by creating a new major version of the extension.
+    </description>
+
+    <request name="create_lease_request">
+      <description summary="create a lease request object">
+        Creates a lease request object.
+
+        See the documentation for wp_drm_lease_request_v1 for details.
+      </description>
+      <arg name="id" type="new_id" interface="wp_drm_lease_request_v1" />
+    </request>
+
+    <request name="release">
+      <description summary="release this object">
+        Indicates the client no longer wishes to use this object. In response
+        the compositor will immediately send the released event and destroy
+        this object. It can however not guarantee that the client won't receive
+        connector events before the released event. The client must not send any
+        requests after this one, doing so will raise a wl_display error.
+        Existing connectors, lease request and leases will not be affected.
+      </description>
+    </request>
+
+    <event name="drm_fd">
+      <description summary="open a non-master fd for this DRM node">
+        The compositor will send this event when the wp_drm_lease_device_v1
+        global is bound, although there are no guarantees as to how long this
+        takes - the compositor might need to wait until regaining DRM master.
+        The included fd is a non-master DRM file descriptor opened for this
+        device and the compositor must not authenticate it.
+        The purpose of this event is to give the client the ability to
+        query DRM and discover information which may help them pick the
+        appropriate DRM device or select the appropriate connectors therein.
+      </description>
+      <arg name="fd" type="fd" summary="DRM file descriptor" />
+    </event>
+
+    <event name="connector">
+      <description summary="advertise connectors available for leases">
+        The compositor will use this event to advertise connectors available for
+        lease by clients. This object may be passed into a lease request to
+        indicate the client would like to lease that connector, see
+        wp_drm_lease_request_v1.request_connector for details. While the
+        compositor will make a best effort to not send disconnected connectors,
+        no guarantees can be made.
+
+        The compositor must send the drm_fd event before sending connectors.
+        After the drm_fd event it will send all available connectors but may
+        send additional connectors at any time.
+      </description>
+      <arg name="id" type="new_id" interface="wp_drm_lease_connector_v1" />
+    </event>
+
+    <event name="done">
+      <description summary="signals grouping of connectors">
+        The compositor will send this event to indicate that it has sent all
+        currently available connectors after the client binds to the global or
+        when it updates the connector list, for example on hotplug, drm master
+        change or when a leased connector becomes available again. It will
+        similarly send this event to group wp_drm_lease_connector_v1.withdrawn
+        events of connectors of this device.
+      </description>
+    </event>
+
+    <event name="released">
+      <description summary="the compositor has finished using the device">
+        This event is sent in response to the release request and indicates
+        that the compositor is done sending connector events.
+        The compositor will destroy this object immediately after sending the
+        event and it will become invalid. The client should release any
+        resources associated with this device after receiving this event.
+      </description>
+    </event>
+  </interface>
+
+  <interface name="wp_drm_lease_connector_v1" version="1">
+    <description summary="a leasable DRM connector">
+      Represents a DRM connector which is available for lease. These objects are
+      created via wp_drm_lease_device_v1.connector events, and should be passed
+      to lease requests via wp_drm_lease_request_v1.request_connector.
+      Immediately after the wp_drm_lease_connector_v1 object is created the
+      compositor will send a name, a description, a connector_id and a done
+      event. When the description is updated the compositor will send a
+      description event followed by a done event.
+    </description>
+
+    <event name="name">
+      <description summary="name">
+        The compositor sends this event once the connector is created to
+        indicate the name of this connector. This will not change for the
+        duration of the Wayland session, but is not guaranteed to be consistent
+        between sessions.
+      </description>
+      <arg name="name" type="string" summary="connector name" />
+    </event>
+
+    <event name="description">
+      <description summary="description">
+        The compositor sends this event once the connector is created to provide
+        a human-readable description for this connector, which may be presented
+        to the user. The compositor may send this event multiple times over the
+        lifetime of this object to reflect changes in the description.
+      </description>
+      <arg name="description" type="string" summary="connector description" />
+    </event>
+
+    <event name="connector_id">
+      <description summary="connector_id">
+        The compositor sends this event once the connector is created to
+        indicate the DRM object ID which represents the underlying connector
+        that is being offered. Note that the final lease may include additional
+        object IDs, such as CRTCs and planes.
+      </description>
+      <arg name="connector_id" type="uint" summary="DRM connector ID" />
+    </event>
+
+    <event name="done">
+      <description summary="all properties have been sent">
+        This event is sent after all properties of a connector have been sent.
+        This allows changes to the properties to be seen as atomic even if they
+        happen via multiple events.
+      </description>
+    </event>
+
+    <event name="withdrawn">
+      <description summary="lease offer withdrawn">
+        Sent to indicate that the compositor will no longer honor requests for
+        DRM leases which include this connector. The client may still issue a
+        lease request including this connector, but the compositor will send
+        wp_drm_lease_v1.finished without issuing a lease fd. Compositors are
+        encouraged to send this event when they lose access to connector, for
+        example when the connector is hot-unplugged, when the connector gets
+        leased to a client or when the compositor loses DRM master.
+      </description>
+    </event>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy connector">
+        The client may send this request to indicate that it will not use this
+        connector. Clients are encouraged to send this after receiving the
+        "withdrawn" event so that the server can release the resources
+        associated with this connector offer. Neither existing lease requests
+        nor leases will be affected.
+      </description>
+    </request>
+  </interface>
+
+  <interface name="wp_drm_lease_request_v1" version="1">
+    <description summary="DRM lease request">
+      A client that wishes to lease DRM resources will attach the list of
+      connectors advertised with wp_drm_lease_device_v1.connector that they
+      wish to lease, then use wp_drm_lease_request_v1.submit to submit the
+      request.
+    </description>
+
+    <enum name="error">
+      <entry name="wrong_device" value="0"
+             summary="requested a connector from a different lease device"/>
+      <entry name="duplicate_connector" value="1"
+             summary="requested a connector twice"/>
+      <entry name="empty_lease" value="2"
+             summary="requested a lease without requesting a connector"/>
+    </enum>
+
+    <request name="request_connector">
+      <description summary="request a connector for this lease">
+        Indicates that the client would like to lease the given connector.
+        This is only used as a suggestion, the compositor may choose to
+        include any resources in the lease it issues, or change the set of
+        leased resources at any time. Compositors are however encouraged to
+        include the requested connector and other resources necessary
+        to drive the connected output in the lease.
+
+        Requesting a connector that was created from a different lease device
+        than this lease request raises the wrong_device error. Requesting a
+        connector twice will raise the duplicate_connector error.
+      </description>
+      <arg name="connector" type="object"
+           interface="wp_drm_lease_connector_v1" />
+    </request>
+
+    <request name="submit" type="destructor">
+      <description summary="submit the lease request">
+        Submits the lease request and creates a new wp_drm_lease_v1 object.
+        After calling submit the compositor will immediately destroy this
+        object, issuing any more requests will cause a wl_diplay error.
+        The compositor doesn't make any guarantees about the events of the
+        lease object, clients cannot expect an immediate response.
+        Not requesting any connectors before submitting the lease request
+        will raise the empty_lease error.
+      </description>
+      <arg name="id" type="new_id" interface="wp_drm_lease_v1" />
+    </request>
+  </interface>
+
+  <interface name="wp_drm_lease_v1" version="1">
+    <description summary="a DRM lease">
+      A DRM lease object is used to transfer the DRM file descriptor to the
+      client and manage the lifetime of the lease.
+
+      Some time after the wp_drm_lease_v1 object is created, the compositor
+      will reply with the lease request's result. If the lease request is
+      granted, the compositor will send a lease_fd event. If the lease request
+      is denied, the compositor will send a finished event without a lease_fd
+      event.
+    </description>
+
+    <event name="lease_fd">
+      <description summary="shares the DRM file descriptor">
+        This event returns a file descriptor suitable for use with DRM-related
+        ioctls. The client should use drmModeGetLease to enumerate the DRM
+        objects which have been leased to them. The compositor guarantees it
+        will not use the leased DRM objects itself until it sends the finished
+        event. If the compositor cannot or will not grant a lease for the
+        requested connectors, it will not send this event, instead sending the
+        finished event.
+
+        The compositor will send this event at most once during this objects
+        lifetime.
+      </description>
+      <arg name="leased_fd" type="fd" summary="leased DRM file descriptor" />
+    </event>
+
+    <event name="finished">
+      <description summary="sent when the lease has been revoked">
+        The compositor uses this event to either reject a lease request, or if
+        it previously sent a lease_fd, to notify the client that the lease has
+        been revoked. If the client requires a new lease, they should destroy
+        this object and submit a new lease request. The compositor will send
+        no further events for this object after sending the finish event.
+        Compositors should revoke the lease when any of the leased resources
+        become unavailable, namely when a hot-unplug occurs or when the
+        compositor loses DRM master.
+      </description>
+    </event>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroys the lease object">
+        The client should send this to indicate that it no longer wishes to use
+        this lease. The compositor should use drmModeRevokeLease on the
+        appropriate file descriptor, if necessary.
+      </description>
+    </request>
+  </interface>
+</protocol>
diff --git a/freedesktop.org/staging/xdg-activation/README b/freedesktop.org/staging/xdg-activation/README
new file mode 100644
index 0000000..cdd4d96
--- /dev/null
+++ b/freedesktop.org/staging/xdg-activation/README
@@ -0,0 +1,4 @@
+XDG Activation protocol
+
+Maintainers:
+Aleix Pol Gonzalez <aleixpol@kde.org>
diff --git a/freedesktop.org/staging/xdg-activation/x11-interoperation.rst b/freedesktop.org/staging/xdg-activation/x11-interoperation.rst
new file mode 100644
index 0000000..3bd03ee
--- /dev/null
+++ b/freedesktop.org/staging/xdg-activation/x11-interoperation.rst
@@ -0,0 +1,63 @@
+Interoperation with X11
+=======================
+
+*This document is non-normative.*
+
+The former
+`X11 Startup notification protocol <https://cgit.freedesktop.org/startup-notification/tree/doc/startup-notification.txt>`_
+defines the use of the ``DESKTOP_STARTUP_ID`` environment variable to propagate
+startup sequences ("activation tokens" in this protocol) between launcher and
+launchee.
+
+These startup sequence IDs are defined as a globally unique string with a
+``[unique]_TIME[timestamp]`` format, where the ID as a whole is used for startup
+notification and the timestamp is used for focus requests and focus stealing
+prevention.
+
+In order to observe mixed usage scenarios where Wayland and X11 clients might
+be launching each other, it is possible for a compositor to manage a shared
+pool of activation tokens.
+
+Scenario 1. Wayland client spawns X11 client
+--------------------------------------------
+
+1. Wayland client requests token.
+2. Wayland client spawns X11 client, sets ``$DESKTOP_STARTUP_ID`` in its
+   environment with the token string.
+3. X11 client starts.
+4. X11 client sends startup-notification ``remove`` message with the activation
+   ``$DESKTOP_STARTUP_ID`` content.
+5. Compositor receives startup notification message, matches ID with
+   the common pool.
+6. The startup feedback is finished.
+7. X11 client requests focus.
+8. Compositor applies internal policies to allow/deny focus switch.
+
+Scenario 2. X11 client spawns Wayland client
+--------------------------------------------
+
+1. X11 client builds a "globally unique" ID
+2. X11 client sends startup-notification ``new`` message with the ID.
+3. Compositor receives startup notification message, adds the ID to
+   the common pool.
+4. X11 client spawns Wayland client, sets ``$DESKTOP_STARTUP_ID`` in its
+   environment.
+5. Wayland client starts.
+6. Wayland client requests surface activation with the activation token,
+   as received from ``$DESKTOP_STARTUP_ID``.
+7. Compositor receives the request, matches ID with the common pool
+8. The startup feedback is finished.
+9. Compositor applies internal policies to allow/deny focus switch.
+
+Caveats
+-------
+
+- For legacy reasons, the usage of ``$DESKTOP_STARTUP_ID`` (even if as a
+  fallback) should be observed in compositors and clients that are
+  concerned with X11 interoperation.
+
+- Depending on the X11 startup-notification implementation in use by the
+  compositor, the usage of the ``_TIME[timestamp]`` suffix may be mandatory
+  for its correct behavior in the first scenario, the startup-notification
+  reference library is one such implementation. Compositors may work
+  this around by adding a matching suffix to the generated activation tokens.
diff --git a/freedesktop.org/staging/xdg-activation/xdg-activation-v1.xml b/freedesktop.org/staging/xdg-activation/xdg-activation-v1.xml
new file mode 100644
index 0000000..4994298
--- /dev/null
+++ b/freedesktop.org/staging/xdg-activation/xdg-activation-v1.xml
@@ -0,0 +1,200 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<protocol name="xdg_activation_v1">
+
+  <copyright>
+    Copyright © 2020 Aleix Pol Gonzalez &lt;aleixpol@kde.org&gt;
+    Copyright © 2020 Carlos Garnacho &lt;carlosg@gnome.org&gt;
+
+    Permission is hereby granted, free of charge, to any person obtaining a
+    copy of this software and associated documentation files (the "Software"),
+    to deal in the Software without restriction, including without limitation
+    the rights to use, copy, modify, merge, publish, distribute, sublicense,
+    and/or sell copies of the Software, and to permit persons to whom the
+    Software is furnished to do so, subject to the following conditions:
+
+    The above copyright notice and this permission notice (including the next
+    paragraph) shall be included in all copies or substantial portions of the
+    Software.
+
+    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
+    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
+    DEALINGS IN THE SOFTWARE.
+  </copyright>
+
+  <description summary="Protocol for requesting activation of surfaces">
+    The way for a client to pass focus to another toplevel is as follows.
+
+    The client that intends to activate another toplevel uses the
+    xdg_activation_v1.get_activation_token request to get an activation token.
+    This token is then forwarded to the client, which is supposed to activate
+    one of its surfaces, through a separate band of communication.
+
+    One established way of doing this is through the XDG_ACTIVATION_TOKEN
+    environment variable of a newly launched child process. The child process
+    should unset the environment variable again right after reading it out in
+    order to avoid propagating it to other child processes.
+
+    Another established way exists for Applications implementing the D-Bus
+    interface org.freedesktop.Application, which should get their token under
+    XDG_ACTIVATION_TOKEN on their platform_data.
+
+    In general activation tokens may be transferred across clients through
+    means not described in this protocol.
+
+    The client to be activated will then pass the token
+    it received to the xdg_activation_v1.activate request. The compositor can
+    then use this token to decide how to react to the activation request.
+
+    The token the activating client gets may be ineffective either already at
+    the time it receives it, for example if it was not focused, for focus
+    stealing prevention. The activating client will have no way to discover
+    the validity of the token, and may still forward it to the to be activated
+    client.
+
+    The created activation token may optionally get information attached to it
+    that can be used by the compositor to identify the application that we
+    intend to activate. This can for example be used to display a visual hint
+    about what application is being started.
+
+    Warning! The protocol described in this file is currently in the testing
+    phase. Backward compatible changes may be added together with the
+    corresponding interface version bump. Backward incompatible changes can
+    only be done by creating a new major version of the extension.
+  </description>
+
+  <interface name="xdg_activation_v1" version="1">
+    <description summary="interface for activating surfaces">
+      A global interface used for informing the compositor about applications
+      being activated or started, or for applications to request to be
+      activated.
+    </description>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the xdg_activation object">
+        Notify the compositor that the xdg_activation object will no longer be
+        used.
+
+        The child objects created via this interface are unaffected and should
+        be destroyed separately.
+      </description>
+    </request>
+
+    <request name="get_activation_token">
+      <description summary="requests a token">
+        Creates an xdg_activation_token_v1 object that will provide
+        the initiating client with a unique token for this activation. This
+        token should be offered to the clients to be activated.
+      </description>
+
+      <arg name="id" type="new_id" interface="xdg_activation_token_v1"/>
+    </request>
+
+    <request name="activate">
+      <description summary="notify new interaction being available">
+        Requests surface activation. It's up to the compositor to display
+        this information as desired, for example by placing the surface above
+        the rest.
+
+        The compositor may know who requested this by checking the activation
+        token and might decide not to follow through with the activation if it's
+        considered unwanted.
+
+        Compositors can ignore unknown activation tokens when an invalid
+        token is passed.
+      </description>
+      <arg name="token" type="string" summary="the activation token of the initiating client"/>
+      <arg name="surface" type="object" interface="wl_surface"
+	   summary="the wl_surface to activate"/>
+    </request>
+  </interface>
+
+  <interface name="xdg_activation_token_v1" version="1">
+    <description summary="an exported activation handle">
+      An object for setting up a token and receiving a token handle that can
+      be passed as an activation token to another client.
+
+      The object is created using the xdg_activation_v1.get_activation_token
+      request. This object should then be populated with the app_id, surface
+      and serial information and committed. The compositor shall then issue a
+      done event with the token. In case the request's parameters are invalid,
+      the compositor will provide an invalid token.
+    </description>
+
+    <enum name="error">
+      <entry name="already_used" value="0"
+             summary="The token has already been used previously"/>
+    </enum>
+
+    <request name="set_serial">
+      <description summary="specifies the seat and serial of the activating event">
+        Provides information about the seat and serial event that requested the
+        token.
+
+        The serial can come from an input or focus event. For instance, if a
+        click triggers the launch of a third-party client, the launcher client
+        should send a set_serial request with the serial and seat from the
+        wl_pointer.button event.
+
+        Some compositors might refuse to activate toplevels when the token
+        doesn't have a valid and recent enough event serial.
+
+        Must be sent before commit. This information is optional.
+      </description>
+      <arg name="serial" type="uint"
+           summary="the serial of the event that triggered the activation"/>
+      <arg name="seat" type="object" interface="wl_seat"
+           summary="the wl_seat of the event"/>
+    </request>
+
+    <request name="set_app_id">
+      <description summary="specifies the application being activated">
+        The requesting client can specify an app_id to associate the token
+        being created with it.
+
+        Must be sent before commit. This information is optional.
+      </description>
+      <arg name="app_id" type="string"
+           summary="the application id of the client being activated."/>
+    </request>
+
+    <request name="set_surface">
+      <description summary="specifies the surface requesting activation">
+        This request sets the surface requesting the activation. Note, this is
+        different from the surface that will be activated.
+
+        Some compositors might refuse to activate toplevels when the token
+        doesn't have a requesting surface.
+
+        Must be sent before commit. This information is optional.
+      </description>
+      <arg name="surface" type="object" interface="wl_surface"
+	   summary="the requesting surface"/>
+    </request>
+
+    <request name="commit">
+      <description summary="issues the token request">
+        Requests an activation token based on the different parameters that
+        have been offered through set_serial, set_surface and set_app_id.
+      </description>
+    </request>
+
+    <event name="done">
+      <description summary="the exported activation token">
+        The 'done' event contains the unique token of this activation request
+        and notifies that the provider is done.
+      </description>
+      <arg name="token" type="string" summary="the exported activation token"/>
+    </event>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the xdg_activation_token_v1 object">
+        Notify the compositor that the xdg_activation_token_v1 object will no
+        longer be used.
+      </description>
+    </request>
+  </interface>
+</protocol>
diff --git a/freedesktop.org/tests/build-cxx.cc.in b/freedesktop.org/tests/build-cxx.cc.in
new file mode 100644
index 0000000..67aeb2b
--- /dev/null
+++ b/freedesktop.org/tests/build-cxx.cc.in
@@ -0,0 +1,14 @@
+#include "@PROTOCOL_CLIENT_INCLUDE_FILE@"
+#include "@PROTOCOL_SERVER_INCLUDE_FILE@"
+
+/* This is a build-test only */
+
+using namespace std;
+
+int
+main(int argc, char **argv)
+{
+	(void)argc;
+	(void)argv;
+	return 0;
+}
diff --git a/freedesktop.org/tests/build-pedantic.c.in b/freedesktop.org/tests/build-pedantic.c.in
new file mode 100644
index 0000000..39b4127
--- /dev/null
+++ b/freedesktop.org/tests/build-pedantic.c.in
@@ -0,0 +1,12 @@
+#include "@PROTOCOL_CLIENT_INCLUDE_FILE@"
+#include "@PROTOCOL_SERVER_INCLUDE_FILE@"
+
+/* This is a build-test only */
+
+int
+main(int argc, char **argv)
+{
+	(void)argc;
+	(void)argv;
+	return 0;
+}
diff --git a/freedesktop.org/tests/meson.build b/freedesktop.org/tests/meson.build
new file mode 100644
index 0000000..66337e7
--- /dev/null
+++ b/freedesktop.org/tests/meson.build
@@ -0,0 +1,144 @@
+prog_scan_sh = find_program('scan.sh')
+prog_scanner = find_program(dep_scanner.get_pkgconfig_variable('wayland_scanner'))
+
+libwayland = [
+	dependency('wayland-client'),
+	dependency('wayland-server'),
+]
+
+# Check that each protocol passes through the scanner
+foreach protocol_file : protocol_files
+	protocol_path = join_paths(wayland_protocols_srcdir, protocol_file)
+	test_name = 'scan-@0@'.format(protocol_file.underscorify())
+	test(test_name, prog_scan_sh,
+		args: protocol_path,
+		env: [
+			'SCANNER=@0@'.format(prog_scanner.path()),
+		]
+	)
+endforeach
+
+# Check buildability
+
+add_languages('c', 'cpp', native: true)
+replace = find_program('replace.py')
+
+foreach protocol_file : protocol_files
+	xml_file = fs.name(protocol_file)
+	xml_components = xml_file.split('.')
+	protocol_base_file_name = xml_components[0]
+
+	protocol_path = files(join_paths(wayland_protocols_srcdir, protocol_file))
+	client_header_path = '@0@-client.h'.format(protocol_base_file_name)
+	server_header_path = '@0@-server.h'.format(protocol_base_file_name)
+	code_path = '@0@-code.c'.format(protocol_base_file_name)
+	client_header = custom_target(
+		client_header_path,
+		output: client_header_path,
+		input: protocol_path,
+		command: [
+			prog_scanner,
+			'--strict',
+			'client-header',
+			'@INPUT@',
+			'@OUTPUT@',
+		],
+		install: false,
+	)
+	server_header = custom_target(
+		server_header_path,
+		output: server_header_path,
+		input: protocol_path,
+		command: [
+			prog_scanner,
+			'--strict',
+			'server-header',
+			'@INPUT@',
+			'@OUTPUT@',
+		],
+		install: false,
+	)
+	code = custom_target(
+		code_path,
+		output: code_path,
+		input: protocol_path,
+		command: [
+			prog_scanner,
+			'--strict',
+			'private-code',
+			'@INPUT@',
+			'@OUTPUT@',
+		],
+		install: false,
+	)
+
+	replace_command = [
+		replace,
+		'@INPUT@',
+		'@OUTPUT@',
+		'PROTOCOL_CLIENT_INCLUDE_FILE',
+		client_header.full_path(),
+		'PROTOCOL_SERVER_INCLUDE_FILE',
+		server_header.full_path(),
+	]
+
+	# Check that header can be included by a pedantic C99 compiler
+	test_name = 'test-build-pedantic-@0@'.format(protocol_file.underscorify())
+	test_name_source = '@0@.c'.format(test_name)
+	test_source = custom_target(
+		test_name_source,
+		input: 'build-pedantic.c.in',
+		output: test_name_source,
+		command: replace_command,
+	)
+	pedantic_test_executable = executable(
+		test_name,
+		[
+			test_source,
+			client_header,
+			server_header,
+			code
+		],
+		link_args: [
+			'-Wl,--unresolved-symbols=ignore-all',
+		],
+		dependencies: libwayland,
+		c_args: [
+			'-std=c99',
+			'-pedantic',
+			'-Wall',
+			'-Werror' ],
+		install: false,
+		native: true,
+	)
+	test(test_name, pedantic_test_executable)
+
+	# Check that the header
+	if not protocol_file.contains('xdg-foreign-unstable-v1')
+		test_name = 'test-build-cxx-@0@'.format(protocol_file.underscorify())
+		test_name_source = '@0@.cc'.format(test_name)
+		test_source = custom_target(
+			test_name_source,
+			input: 'build-cxx.cc.in',
+			output: test_name_source,
+			command: replace_command,
+		)
+		cxx_test_executable = executable(
+			test_name,
+			[
+				test_source,
+				client_header,
+				server_header,
+			],
+			link_args: [ '-Wl,--unresolved-symbols=ignore-all' ],
+			dependencies: libwayland,
+			cpp_args: [
+				'-Wall',
+				'-Werror',
+			],
+			install: false,
+			native: true,
+		)
+		test(test_name, cxx_test_executable)
+	endif
+endforeach
diff --git a/freedesktop.org/tests/replace.py b/freedesktop.org/tests/replace.py
new file mode 100755
index 0000000..0ab7dfd
--- /dev/null
+++ b/freedesktop.org/tests/replace.py
@@ -0,0 +1,23 @@
+#!/usr/bin/env python3
+
+import sys
+
+execpath, inpath, outpath, *dict_list = sys.argv
+
+dictonary = {}
+while dict_list:
+    key, value, *rest = dict_list
+    dictonary[key] = value
+    dict_list = rest
+
+infile = open(inpath, 'r')
+outfile = open(outpath, 'w')
+
+buf = infile.read()
+infile.close()
+
+for key, value in dictonary.items():
+    buf = buf.replace('@{}@'.format(key), value)
+
+outfile.write(buf)
+outfile.close()
diff --git a/freedesktop.org/unstable/fullscreen-shell/fullscreen-shell-unstable-v1.xml b/freedesktop.org/unstable/fullscreen-shell/fullscreen-shell-unstable-v1.xml
index 634b77d..6a09aa0 100644
--- a/freedesktop.org/unstable/fullscreen-shell/fullscreen-shell-unstable-v1.xml
+++ b/freedesktop.org/unstable/fullscreen-shell/fullscreen-shell-unstable-v1.xml
@@ -147,6 +147,10 @@
 	operation on the surface.  This will override any kind of output
 	scaling, so the buffer_scale property of the surface is effectively
 	ignored.
+
+	This request gives the surface the role of a fullscreen shell surface.
+	If the surface already has another role, it raises a role protocol
+	error.
       </description>
       <arg name="surface" type="object" interface="wl_surface" allow-null="true"/>
       <arg name="method" type="uint" enum="present_method" />
@@ -192,6 +196,10 @@
 	then the compositor may choose a mode that matches either the buffer
 	size or the surface size.  In either case, the surface will fill the
 	output.
+
+	This request gives the surface the role of a fullscreen shell surface.
+	If the surface already has another role, it raises a role protocol
+	error.
       </description>
       <arg name="surface" type="object" interface="wl_surface"/>
       <arg name="output" type="object" interface="wl_output"/>
@@ -204,6 +212,7 @@
 	These errors can be emitted in response to wl_fullscreen_shell requests.
       </description>
       <entry name="invalid_method" value="0" summary="present_method is not known"/>
+      <entry name="role" value="1" summary="given wl_surface has another role"/>
     </enum>
   </interface>
 
diff --git a/freedesktop.org/unstable/linux-dmabuf/linux-dmabuf-unstable-v1.xml b/freedesktop.org/unstable/linux-dmabuf/linux-dmabuf-unstable-v1.xml
index 4b1dd74..afa55ca 100644
--- a/freedesktop.org/unstable/linux-dmabuf/linux-dmabuf-unstable-v1.xml
+++ b/freedesktop.org/unstable/linux-dmabuf/linux-dmabuf-unstable-v1.xml
@@ -55,6 +55,12 @@
         at any time use those fds to import the dmabuf into any kernel
         sub-system that might accept it.
 
+      However, when the underlying graphics stack fails to deliver the
+      promise, because of e.g. a device hot-unplug which raises internal
+      errors, after the wl_buffer has been successfully created the
+      compositor must not raise protocol errors to the client when dmabuf
+      import later fails.
+
       To create a wl_buffer from one or more dmabufs, a client creates a
       zwp_linux_dmabuf_params_v1 object with a zwp_linux_dmabuf_v1.create_params
       request. All planes required by the intended format are added with
@@ -137,6 +143,9 @@
         is as if no explicit modifier is specified. The effective modifier
         will be derived from the dmabuf.
 
+        A compositor that sends valid modifiers and DRM_FORMAT_MOD_INVALID for
+        a given format supports both explicit modifiers and implicit modifiers.
+
         For the definition of the format and modifier codes, see the
         zwp_linux_buffer_params_v1::create and zwp_linux_buffer_params_v1::add
         requests.
diff --git a/freedesktop.org/unstable/pointer-gestures/pointer-gestures-unstable-v1.xml b/freedesktop.org/unstable/pointer-gestures/pointer-gestures-unstable-v1.xml
index 59502ac..3df578b 100644
--- a/freedesktop.org/unstable/pointer-gestures/pointer-gestures-unstable-v1.xml
+++ b/freedesktop.org/unstable/pointer-gestures/pointer-gestures-unstable-v1.xml
@@ -6,7 +6,7 @@
       A global interface to provide semantic touchpad gestures for a given
       pointer.
 
-      Two gestures are currently supported: swipe and zoom/rotate.
+      Two gestures are currently supported: swipe and pinch.
       All gestures follow a three-stage cycle: begin, update, end and
       are identified by a unique id.
 
diff --git a/freedesktop.org/unstable/xdg-foreign/xdg-foreign-unstable-v2.xml b/freedesktop.org/unstable/xdg-foreign/xdg-foreign-unstable-v2.xml
index b9d560e..cc3271d 100644
--- a/freedesktop.org/unstable/xdg-foreign/xdg-foreign-unstable-v2.xml
+++ b/freedesktop.org/unstable/xdg-foreign/xdg-foreign-unstable-v2.xml
@@ -69,6 +69,14 @@
       </description>
     </request>
 
+    <enum name="error">
+      <description summary="error values">
+        These errors can be emitted in response to invalid xdg_exporter
+        requests.
+      </description>
+      <entry name="invalid_surface" value="0" summary="surface is not an xdg_toplevel"/>
+    </enum>
+
     <request name="export_toplevel">
       <description summary="export a toplevel surface">
 	The export_toplevel request exports the passed surface so that it can later be
@@ -78,7 +86,8 @@
 
 	A surface may be exported multiple times, and each exported handle may
 	be used to create an xdg_imported multiple times. Only xdg_toplevel
-	equivalent surfaces may be exported.
+        equivalent surfaces may be exported, otherwise an invalid_surface
+        protocol error is sent.
       </description>
       <arg name="id" type="new_id" interface="zxdg_exported_v2"
 	   summary="the new xdg_exported object"/>
@@ -150,6 +159,14 @@
       relationships between its own surfaces and the imported surface.
     </description>
 
+    <enum name="error">
+      <description summary="error values">
+        These errors can be emitted in response to invalid xdg_imported
+        requests.
+      </description>
+      <entry name="invalid_surface" value="0" summary="surface is not an xdg_toplevel"/>
+    </enum>
+
     <request name="destroy" type="destructor">
       <description summary="destroy the xdg_imported object">
 	Notify the compositor that it will no longer use the xdg_imported
@@ -160,10 +177,11 @@
 
     <request name="set_parent_of">
       <description summary="set as the parent of some surface">
-	Set the imported surface as the parent of some surface of the client.
-	The passed surface must be an xdg_toplevel equivalent. Calling this
-	function sets up a surface to surface relation with the same stacking
-	and positioning semantics as xdg_toplevel.set_parent.
+        Set the imported surface as the parent of some surface of the client.
+        The passed surface must be an xdg_toplevel equivalent, otherwise an
+        invalid_surface protocol error is sent. Calling this function sets up
+        a surface to surface relation with the same stacking and positioning
+        semantics as xdg_toplevel.set_parent.
       </description>
       <arg name="surface" type="object" interface="wl_surface"
 	   summary="the child surface"/>
diff --git a/freedesktop.org/unstable/xdg-output/xdg-output-unstable-v1.xml b/freedesktop.org/unstable/xdg-output/xdg-output-unstable-v1.xml
index fe3a70a..9a5b790 100644
--- a/freedesktop.org/unstable/xdg-output/xdg-output-unstable-v1.xml
+++ b/freedesktop.org/unstable/xdg-output/xdg-output-unstable-v1.xml
@@ -138,7 +138,7 @@
 	  advertise a logical size of 1920×1080,
 
 	- A compositor using a fractional scale of 1.5 will advertise a
-	  logical size to 2560×1620.
+	  logical size of 2560×1440.
 
 	For example, for a wl_output mode 1920×1080 and a 90 degree rotation,
 	the compositor will advertise a logical size of 1080x1920.
diff --git a/freedesktop.org/wayland-protocols.pc.in b/freedesktop.org/wayland-protocols.pc.in
index 379be06..4571fa8 100644
--- a/freedesktop.org/wayland-protocols.pc.in
+++ b/freedesktop.org/wayland-protocols.pc.in
@@ -1,6 +1,6 @@
 prefix=@prefix@
 datarootdir=@datarootdir@
-pkgdatadir=${pc_sysrootdir}@datadir@/@PACKAGE@
+pkgdatadir=${pc_sysrootdir}${datarootdir}/@PACKAGE@
 
 Name: Wayland Protocols
 Description: Wayland protocol files
diff --git a/wayland_protocol_codegen.go b/wayland_protocol_codegen.go
index 2224fce..9b94a82 100644
--- a/wayland_protocol_codegen.go
+++ b/wayland_protocol_codegen.go
@@ -72,7 +72,6 @@ import (
 	"strings"
 
 	"github.com/google/blueprint"
-	"github.com/google/blueprint/bootstrap"
 	"github.com/google/blueprint/proptools"
 
 	"android/soong/android"
@@ -322,7 +321,8 @@ func (g *Module) generateCommonBuildActions(ctx android.ModuleContext) {
 						ctx.ModuleErrorf("host tool %q missing output file", tool)
 						return
 					}
-					if specs := t.TransitivePackagingSpecs(); specs != nil {
+					if specs := android.OtherModuleProviderOrDefault(
+						ctx, t, android.InstallFilesProvider).TransitivePackagingSpecs.ToList(); specs != nil {
 						// If the HostToolProvider has PackgingSpecs, which are definitions of the
 						// required relative locations of the tool and its dependencies, use those
 						// instead.  They will be copied to those relative locations in the sbox
@@ -334,11 +334,6 @@ func (g *Module) generateCommonBuildActions(ctx android.ModuleContext) {
 						tools = append(tools, path.Path())
 						addLocationLabel(tag.label, toolLocation{android.Paths{path.Path()}})
 					}
-				case bootstrap.GoBinaryTool:
-					// A GoBinaryTool provides the install path to a tool, which will be copied.
-					p := android.PathForGoBinary(ctx, t)
-					tools = append(tools, p)
-					addLocationLabel(tag.label, toolLocation{android.Paths{p}})
 				default:
 					ctx.ModuleErrorf("%q is not a host tool provider", tool)
 					return
@@ -589,7 +584,7 @@ func (g *Module) setOutputFiles(ctx android.ModuleContext) {
 
 // Part of android.IDEInfo.
 // Collect information for opening IDE project files in java/jdeps.go.
-func (g *Module) IDEInfo(dpInfo *android.IdeInfo) {
+func (g *Module) IDEInfo(ctx android.BaseModuleContext, dpInfo *android.IdeInfo) {
 	dpInfo.Srcs = append(dpInfo.Srcs, g.Srcs().Strings()...)
 	for _, src := range g.properties.Srcs {
 		if strings.HasPrefix(src, ":") {
@@ -600,6 +595,8 @@ func (g *Module) IDEInfo(dpInfo *android.IdeInfo) {
 	dpInfo.Paths = append(dpInfo.Paths, g.modulePaths...)
 }
 
+var _ android.IDEInfo = (*Module)(nil)
+
 // Ensure Module implements android.ApexModule
 // Note: gensrcs implements it but it's possible we do not actually need to.
 var _ android.ApexModule = (*Module)(nil)
@@ -628,6 +625,8 @@ func generatorFactory(taskGenerator taskFunc, props ...interface{}) *Module {
 type noopImageInterface struct{}
 
 func (x noopImageInterface) ImageMutatorBegin(android.BaseModuleContext)                 {}
+func (x noopImageInterface) VendorVariantNeeded(android.BaseModuleContext) bool          { return false }
+func (x noopImageInterface) ProductVariantNeeded(android.BaseModuleContext) bool         { return false }
 func (x noopImageInterface) CoreVariantNeeded(android.BaseModuleContext) bool            { return false }
 func (x noopImageInterface) RamdiskVariantNeeded(android.BaseModuleContext) bool         { return false }
 func (x noopImageInterface) VendorRamdiskVariantNeeded(android.BaseModuleContext) bool   { return false }
```

