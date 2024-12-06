```diff
diff --git a/client/NetdClient.cpp b/client/NetdClient.cpp
index 56fce2d3..287526c9 100644
--- a/client/NetdClient.cpp
+++ b/client/NetdClient.cpp
@@ -503,14 +503,6 @@ extern "C" int untagSocket(int socketFd) {
     return FwmarkClient().send(&command, socketFd, nullptr);
 }
 
-extern "C" int setCounterSet(uint32_t, uid_t) {
-    return -ENOTSUP;
-}
-
-extern "C" int deleteTagData(uint32_t, uid_t) {
-    return -ENOTSUP;
-}
-
 extern "C" int resNetworkQuery(unsigned netId, const char* dname, int ns_class, int ns_type,
                                uint32_t flags) {
     std::vector<uint8_t> buf(MAX_CMD_SIZE, 0);
diff --git a/server/Android.bp b/server/Android.bp
index b5a013c1..f40b4c6f 100644
--- a/server/Android.bp
+++ b/server/Android.bp
@@ -139,7 +139,6 @@ cc_defaults {
         "NetworkController.cpp",
         "OemNetdListener.cpp",
         "PhysicalNetwork.cpp",
-        "PppController.cpp",
         "Process.cpp",
         "UnreachableNetwork.cpp",
         "VirtualNetwork.cpp",
diff --git a/server/Controllers.h b/server/Controllers.h
index 8b51ddf1..83a1a5c6 100644
--- a/server/Controllers.h
+++ b/server/Controllers.h
@@ -24,7 +24,6 @@
 #include "InterfaceController.h"
 #include "IptablesRestoreController.h"
 #include "NetworkController.h"
-#include "PppController.h"
 #include "StrictController.h"
 #include "TcpSocketMonitor.h"
 #include "TetherController.h"
@@ -41,7 +40,6 @@ class Controllers {
 
     NetworkController netCtrl;
     TetherController tetherCtrl;
-    PppController pppCtrl;
     BandwidthController bandwidthCtrl;
     IdletimerController idletimerCtrl;
     FirewallController firewallCtrl;
diff --git a/server/PppController.cpp b/server/PppController.cpp
deleted file mode 100644
index b80e1a67..00000000
--- a/server/PppController.cpp
+++ /dev/null
@@ -1,155 +0,0 @@
-/*
- * Copyright (C) 2008 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#include <errno.h>
-#include <fcntl.h>
-#include <stdlib.h>
-#include <string.h>
-#include <unistd.h>
-
-#include <sys/socket.h>
-#include <sys/stat.h>
-#include <sys/types.h>
-#include <sys/wait.h>
-
-#include <dirent.h>
-
-#include <netinet/in.h>
-#include <arpa/inet.h>
-
-#define LOG_TAG "PppController"
-#include <log/log.h>
-
-#include "PppController.h"
-
-PppController::PppController() {
-    mTtys = new TtyCollection();
-    mPid = 0;
-}
-
-PppController::~PppController() {
-    TtyCollection::iterator it;
-
-    for (it = mTtys->begin(); it != mTtys->end(); ++it) {
-        free(*it);
-    }
-    mTtys->clear();
-}
-
-int PppController::attachPppd(const char *tty, struct in_addr local,
-                              struct in_addr remote, struct in_addr dns1,
-                              struct in_addr dns2) {
-    pid_t pid;
-
-    if (mPid) {
-        ALOGE("Multiple PPPD instances not currently supported");
-        errno = EBUSY;
-        return -1;
-    }
-
-    TtyCollection::iterator it;
-    for (it = mTtys->begin(); it != mTtys->end(); ++it) {
-        if (!strcmp(tty, *it)) {
-            break;
-        }
-    }
-    if (it == mTtys->end()) {
-        ALOGE("Invalid tty '%s' specified", tty);
-        errno = -EINVAL;
-        return -1;
-    }
-
-    if ((pid = fork()) < 0) {
-        ALOGE("fork failed (%s)", strerror(errno));
-        return -1;
-    }
-
-    if (!pid) {
-        char *l = strdup(inet_ntoa(local));
-        char *r = strdup(inet_ntoa(remote));
-        char *d1 = strdup(inet_ntoa(dns1));
-        char *d2 = strdup(inet_ntoa(dns2));
-        char dev[32];
-        char *lr;
-
-        asprintf(&lr, "%s:%s", l, r);
-        free(l);
-        free(r);
-
-        snprintf(dev, sizeof(dev), "/dev/%s", tty);
-
-        // TODO: Deal with pppd bailing out after 99999 seconds of being started
-        // but not getting a connection
-        if (execl("/system/bin/pppd", "/system/bin/pppd", "-detach", dev, "115200",
-                  lr, "ms-dns", d1, "ms-dns", d2, "lcp-max-configure", "99999", (char *) nullptr)) {
-            ALOGE("execl failed (%s)", strerror(errno));
-        }
-        free(lr);
-        free(d1);
-        free(d2);
-        ALOGE("Should never get here!");
-        return 0;
-    } else {
-        mPid = pid;
-    }
-    return 0;
-}
-
-int PppController::detachPppd(const char *tty) {
-
-    if (mPid == 0) {
-        ALOGE("PPPD already stopped");
-        return 0;
-    }
-
-    ALOGD("Stopping PPPD services on port %s", tty);
-    kill(mPid, SIGTERM);
-    waitpid(mPid, nullptr, 0);
-    mPid = 0;
-    ALOGD("PPPD services on port %s stopped", tty);
-    return 0;
-}
-
-TtyCollection *PppController::getTtyList() {
-    updateTtyList();
-    return mTtys;
-}
-
-int PppController::updateTtyList() {
-    TtyCollection::iterator it;
-
-    for (it = mTtys->begin(); it != mTtys->end(); ++it) {
-        free(*it);
-    }
-    mTtys->clear();
-
-    DIR *d = opendir("/sys/class/tty");
-    if (!d) {
-        ALOGE("Error opening /sys/class/tty (%s)", strerror(errno));
-        return -1;
-    }
-
-    struct dirent *de;
-    while ((de = readdir(d))) {
-        if (de->d_name[0] == '.')
-            continue;
-        if ((!strncmp(de->d_name, "tty", 3)) && (strlen(de->d_name) > 3)) {
-            mTtys->push_back(strdup(de->d_name));
-        }
-    }
-    closedir(d);
-    return 0;
-}
diff --git a/server/PppController.h b/server/PppController.h
deleted file mode 100644
index 7ca54355..00000000
--- a/server/PppController.h
+++ /dev/null
@@ -1,44 +0,0 @@
-/*
- * Copyright (C) 2008 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef _PPP_CONTROLLER_H
-#define _PPP_CONTROLLER_H
-
-#include <linux/in.h>
-
-#include <list>
-
-typedef std::list<char *> TtyCollection;
-
-class PppController {
-    TtyCollection *mTtys;
-    pid_t          mPid; // TODO: Add support for > 1 pppd instance
-
-public:
-    PppController();
-    virtual ~PppController();
-
-    int attachPppd(const char *tty, struct in_addr local,
-                   struct in_addr remote, struct in_addr dns1,
-                   struct in_addr dns2);
-    int detachPppd(const char *tty);
-    TtyCollection *getTtyList();
-
-private:
-    int updateTtyList();
-};
-
-#endif
diff --git a/server/TetherController.cpp b/server/TetherController.cpp
index 03185e71..b159d958 100644
--- a/server/TetherController.cpp
+++ b/server/TetherController.cpp
@@ -232,7 +232,7 @@ int TetherController::startTethering(bool usingLegacyDnsProxy, int num_addrs, ch
     char markStr[UINT32_HEX_STRLEN];
     snprintf(markStr, sizeof(markStr), "0x%x", fwmark.intValue);
 
-    std::vector<const std::string> argVector = {
+    std::vector<std::string> argVector = {
             "/system/bin/dnsmasq",
             "--keep-in-foreground",
             "--no-resolv",
@@ -291,7 +291,7 @@ int TetherController::startTethering(bool usingLegacyDnsProxy, int num_addrs, ch
         return -res;
     }
     const android::base::ScopeGuard attrGuard = [&] { posix_spawnattr_destroy(&attr); };
-    res = posix_spawnattr_setflags(&attr, POSIX_SPAWN_USEVFORK);
+    res = posix_spawnattr_setflags(&attr, POSIX_SPAWN_USEVFORK | POSIX_SPAWN_CLOEXEC_DEFAULT);
     if (res) {
         ALOGE("posix_spawnattr_setflags failed (%s)", strerror(res));
         return -res;
diff --git a/server/corpus/seed-2024-08-29-0 b/server/corpus/seed-2024-08-29-0
new file mode 100644
index 00000000..adcb9217
Binary files /dev/null and b/server/corpus/seed-2024-08-29-0 differ
diff --git a/server/corpus/seed-2024-08-29-1 b/server/corpus/seed-2024-08-29-1
new file mode 100644
index 00000000..12102d92
Binary files /dev/null and b/server/corpus/seed-2024-08-29-1 differ
diff --git a/server/corpus/seed-2024-08-29-10 b/server/corpus/seed-2024-08-29-10
new file mode 100644
index 00000000..b8884149
Binary files /dev/null and b/server/corpus/seed-2024-08-29-10 differ
diff --git a/server/corpus/seed-2024-08-29-11 b/server/corpus/seed-2024-08-29-11
new file mode 100644
index 00000000..cd3f994c
Binary files /dev/null and b/server/corpus/seed-2024-08-29-11 differ
diff --git a/server/corpus/seed-2024-08-29-12 b/server/corpus/seed-2024-08-29-12
new file mode 100644
index 00000000..2881b6e8
Binary files /dev/null and b/server/corpus/seed-2024-08-29-12 differ
diff --git a/server/corpus/seed-2024-08-29-2 b/server/corpus/seed-2024-08-29-2
new file mode 100644
index 00000000..adb40787
Binary files /dev/null and b/server/corpus/seed-2024-08-29-2 differ
diff --git a/server/corpus/seed-2024-08-29-3 b/server/corpus/seed-2024-08-29-3
new file mode 100644
index 00000000..64628891
Binary files /dev/null and b/server/corpus/seed-2024-08-29-3 differ
diff --git a/server/corpus/seed-2024-08-29-4 b/server/corpus/seed-2024-08-29-4
new file mode 100644
index 00000000..5799c78d
Binary files /dev/null and b/server/corpus/seed-2024-08-29-4 differ
diff --git a/server/corpus/seed-2024-08-29-5 b/server/corpus/seed-2024-08-29-5
new file mode 100644
index 00000000..0c3d4479
Binary files /dev/null and b/server/corpus/seed-2024-08-29-5 differ
diff --git a/server/corpus/seed-2024-08-29-6 b/server/corpus/seed-2024-08-29-6
new file mode 100644
index 00000000..747620b7
Binary files /dev/null and b/server/corpus/seed-2024-08-29-6 differ
diff --git a/server/corpus/seed-2024-08-29-7 b/server/corpus/seed-2024-08-29-7
new file mode 100644
index 00000000..0a36272b
Binary files /dev/null and b/server/corpus/seed-2024-08-29-7 differ
diff --git a/server/corpus/seed-2024-08-29-8 b/server/corpus/seed-2024-08-29-8
new file mode 100644
index 00000000..e3e2f4e8
Binary files /dev/null and b/server/corpus/seed-2024-08-29-8 differ
diff --git a/server/corpus/seed-2024-08-29-9 b/server/corpus/seed-2024-08-29-9
new file mode 100644
index 00000000..0ff5b504
Binary files /dev/null and b/server/corpus/seed-2024-08-29-9 differ
diff --git a/tests/kernel_test.cpp b/tests/kernel_test.cpp
index 2a3141f7..c518f579 100644
--- a/tests/kernel_test.cpp
+++ b/tests/kernel_test.cpp
@@ -88,6 +88,13 @@ TEST(KernelTest, TestBpfJitAlwaysOn) {
     ASSERT_TRUE(configVerifier.hasOption("CONFIG_BPF_JIT_ALWAYS_ON"));
 }
 
+TEST(KernelTest, TestHaveEfficientUnalignedAccess) {
+    // Turns out the bpf verifier is stricter if you don't have this option.
+    // At least *some* of our bpf code fails to verify without it.
+    KernelConfigVerifier configVerifier;
+    ASSERT_TRUE(configVerifier.hasOption("CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS"));
+}
+
 /* Android 14/U should only launch on 64-bit kernels
  *   T launches on 5.10/5.15
  *   U launches on 5.15/6.1
```

