```diff
diff --git a/net/test/all_tests.py b/net/test/all_tests.py
index 422005f..84a23c6 100755
--- a/net/test/all_tests.py
+++ b/net/test/all_tests.py
@@ -14,6 +14,7 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+import ctypes
 import importlib
 import os
 import sys
@@ -23,6 +24,16 @@ import gki
 import namespace
 import net_test
 
+# man 2 personality
+personality = ctypes.CDLL(None).personality
+personality.restype = ctypes.c_int
+personality.argtypes = [ctypes.c_ulong]
+
+# From Linux kernel's include/uapi/linux/personality.h
+PER_QUERY = 0xFFFFFFFF
+PER_LINUX = 0
+PER_LINUX32 = 8
+
 all_test_modules = [
     'anycast_test',
     'bpf_test',
@@ -51,8 +62,15 @@ all_test_modules = [
 
 
 def RunTests(modules_to_test):
-  print('Running on %s %s %s %s-%sbit%s%s'
-        % (os.uname()[0], os.uname()[2], net_test.LINUX_VERSION, os.uname()[4],
+  uname = os.uname()
+  linux = uname.sysname
+  kver = uname.release
+  arch = uname.machine
+  p = personality(PER_LINUX)
+  true_arch = os.uname().machine
+  personality(p)
+  print('Running on %s %s %s %s/%s-%sbit%s%s'
+        % (linux, kver, net_test.LINUX_VERSION, true_arch, arch,
            '64' if sys.maxsize > 0x7FFFFFFF else '32',
            ' GKI' if gki.IS_GKI else '', ' GSI' if net_test.IS_GSI else ''),
         file=sys.stderr)
diff --git a/net/test/bpf.py b/net/test/bpf.py
index bc46e95..80acda7 100755
--- a/net/test/bpf.py
+++ b/net/test/bpf.py
@@ -48,11 +48,8 @@ __NR_bpf = {  # pylint: disable=invalid-name
 
 # After ACK merge of 5.10.168 is when support for this was backported from
 # upstream Linux 5.14 and was merged into ACK android{12,13}-5.10 branches.
-#   ACK android12-5.10 was >= 5.10.168 without this support only for ~4.5 hours
-#   ACK android13-4.10 was >= 5.10.168 without this support only for ~25 hours
-# as such we can >= 5.10.168 instead of > 5.10.168
-# Additionally require support to be backported to any 5.10+ non-GKI/GSI kernel.
-HAVE_SO_NETNS_COOKIE = net_test.LINUX_VERSION >= (5, 10, 168) or net_test.NonGXI(5, 10)
+# Require support to be backported to any 5.10+ kernel.
+HAVE_SO_NETNS_COOKIE = net_test.LINUX_VERSION >= (5, 10, 0)
 
 # Note: This is *not* correct for parisc & sparc architectures
 SO_NETNS_COOKIE = 71
diff --git a/net/test/kernel_feature_test.py b/net/test/kernel_feature_test.py
index 2594a82..1f76dd5 100755
--- a/net/test/kernel_feature_test.py
+++ b/net/test/kernel_feature_test.py
@@ -96,15 +96,6 @@ class KernelFeatureTest(net_test.NetworkTest):
   def testIsGKI(self):
     pass
 
-  @unittest.skipUnless(not net_test.IS_GSI and not gki.IS_GKI, "GSI or GKI")
-  def testMinRequiredKernelVersion(self):
-    self.assertTrue(net_test.KernelAtLeast([(4, 19, 236),
-                                            (5, 4, 186),
-                                            (5, 10, 199),
-                                            (5, 15, 136),
-                                            (6, 1, 57)]),
-                    "%s [%s] is too old." % (os.uname()[2], os.uname()[4]))
-
 
 if __name__ == "__main__":
   unittest.main()
diff --git a/net/test/multinetwork_base.py b/net/test/multinetwork_base.py
index 8c5fc26..bc5300f 100644
--- a/net/test/multinetwork_base.py
+++ b/net/test/multinetwork_base.py
@@ -57,6 +57,7 @@ AUTOCONF_TABLE_SYSCTL = "/proc/sys/net/ipv6/conf/default/accept_ra_rt_table"
 IPV4_MARK_REFLECT_SYSCTL = "/proc/sys/net/ipv4/fwmark_reflect"
 IPV6_MARK_REFLECT_SYSCTL = "/proc/sys/net/ipv6/fwmark_reflect"
 RA_HONOR_PIO_LIFE_SYSCTL = "/proc/sys/net/ipv6/conf/default/ra_honor_pio_life"
+RA_HONOR_PIO_PFLAG = "/proc/sys/net/ipv6/conf/default/ra_honor_pio_pflag"
 
 HAVE_ACCEPT_RA_MIN_LFT = (os.path.isfile(ACCEPT_RA_MIN_LFT_SYSCTL) or
                           net_test.NonGXI(5, 10) or
@@ -65,6 +66,14 @@ HAVE_ACCEPT_RA_MIN_LFT = (os.path.isfile(ACCEPT_RA_MIN_LFT_SYSCTL) or
 HAVE_AUTOCONF_TABLE = os.path.isfile(AUTOCONF_TABLE_SYSCTL)
 HAVE_RA_HONOR_PIO_LIFE = (os.path.isfile(RA_HONOR_PIO_LIFE_SYSCTL) or
                           net_test.KernelAtLeast([(6, 7, 0)]))
+HAVE_RA_HONOR_PIO_PFLAG = (os.path.isfile(RA_HONOR_PIO_PFLAG) or
+                           net_test.KernelAtLeast([(6, 12, 0)]))
+
+HAVE_USEROPT_PIO_FIX = net_test.KernelAtLeast([(4, 19, 320), (5, 4, 282),
+                                               (5, 10, 224), (5, 15, 165),
+                                               (6, 1, 104), (6, 6, 45),
+                                               (6, 9, 13), (6, 10, 4),
+                                               (6, 11, 0)])
 
 
 class ConfigurationError(AssertionError):
@@ -244,7 +253,7 @@ class MultiNetworkBaseTest(net_test.NetworkTest):
 
   @classmethod
   def SendRA(cls, netid, retranstimer=None, reachabletime=0, routerlft=RA_VALIDITY,
-             piolft=RA_VALIDITY, m=0, o=0, options=()):
+             piolft=RA_VALIDITY, m=0, o=0, piopflag=0, options=()):
     macaddr = cls.RouterMacAddress(netid)
     lladdr = cls._RouterAddress(netid, 6)
 
@@ -259,6 +268,8 @@ class MultiNetworkBaseTest(net_test.NetworkTest):
     if not HAVE_AUTOCONF_TABLE:
       routerlft = 0
 
+    res1 = 0x10 if piopflag else 0
+
     ra = (scapy.Ether(src=macaddr, dst="33:33:00:00:00:01") /
           scapy.IPv6(src=lladdr, hlim=255) /
           scapy.ICMPv6ND_RA(reachabletime=reachabletime,
@@ -268,7 +279,7 @@ class MultiNetworkBaseTest(net_test.NetworkTest):
           scapy.ICMPv6NDOptSrcLLAddr(lladdr=macaddr) /
           scapy.ICMPv6NDOptPrefixInfo(prefix=cls.OnlinkPrefix(6, netid),
                                       prefixlen=cls.OnlinkPrefixLen(6),
-                                      L=1, A=1,
+                                      L=1, A=1, res1=res1,
                                       validlifetime=piolft,
                                       preferredlifetime=piolft))
     for option in options:
diff --git a/net/test/multinetwork_test.py b/net/test/multinetwork_test.py
index 0696afe..ab9012c 100755
--- a/net/test/multinetwork_test.py
+++ b/net/test/multinetwork_test.py
@@ -599,6 +599,8 @@ class RIOTest(multinetwork_base.MultiNetworkBaseTest):
       self.SetAcceptRaMinLft(0)
     if multinetwork_base.HAVE_RA_HONOR_PIO_LIFE:
       self.SetRaHonorPioLife(0)
+    if multinetwork_base.HAVE_RA_HONOR_PIO_PFLAG:
+      self.SetRaHonorPioPflag(0)
 
   def GetRoutingTable(self):
     if multinetwork_base.HAVE_AUTOCONF_TABLE:
@@ -629,6 +631,10 @@ class RIOTest(multinetwork_base.MultiNetworkBaseTest):
     self.SetSysctl(
         "/proc/sys/net/ipv6/conf/%s/accept_ra_min_lft" % self.IFACE, min_lft)
 
+  def SetRaHonorPioPflag(self, val):
+    self.SetSysctl(
+        "/proc/sys/net/ipv6/conf/%s/ra_honor_pio_pflag" % self.IFACE, val)
+
   def GetAcceptRaMinLft(self):
     return int(self.GetSysctl(
         "/proc/sys/net/ipv6/conf/%s/accept_ra_min_lft" % self.IFACE))
@@ -921,11 +927,41 @@ class RIOTest(multinetwork_base.MultiNetworkBaseTest):
     time.sleep(0.1) # Give the kernel time to notice our RA
     self.assertFalse(self.FindRoutesWithDestination(PREFIX))
 
+  @unittest.skipUnless(multinetwork_base.HAVE_RA_HONOR_PIO_PFLAG,
+                       "needs support for ra_honor_pio_pflag")
+  def testPioPflag(self):
+    self.SetRaHonorPioPflag(1);
+
+    # Test setup has sent an initial RA -- expire it.
+    self.SendRA(self.NETID, routerlft=0, piolft=0)
+    time.sleep(0.1) # Give the kernel time to notice our RA
+    # Check that the prefix route was deleted.
+    prefixroutes = self.FindRoutesWithDestination(self.OnlinkPrefix(6, self.NETID))
+    self.assertEqual([], prefixroutes)
+
+    # Sending a 0-lifetime PIO does not cause the address to be deleted, see
+    # rfc2462#section-5.5.3.
+    address = self.MyAddress(6, self.NETID)
+    self.iproute.DelAddress(address, 64, self.ifindices[self.NETID])
+
+    # PIO with p-flag is ignored
+    self.SendRA(self.NETID, piopflag=1)
+    time.sleep(0.1) # Give the kernel time to notice our RA
+    self.assertIsNone(self.MyAddress(6, self.NETID))
+
+    self.SetRaHonorPioPflag(0);
+    # PIO with p-flag is processed
+    self.SendRA(self.NETID, piopflag=1)
+    time.sleep(0.1) # Give the kernel time to notice our RA
+    self.assertIsNotNone(self.MyAddress(6, self.NETID))
+
 
 class RATest(multinetwork_base.MultiNetworkBaseTest):
 
   ND_ROUTER_ADVERT = 134
+  ND_OPT_PIO = 3
   ND_OPT_PREF64 = 38
+  NDOptHeader = cstruct.Struct("ndopt_header", "!BB", "type length")
   Pref64Option = cstruct.Struct("pref64_option", "!BBH12s",
                                 "type length lft_plc prefix")
 
@@ -1046,26 +1082,56 @@ class RATest(multinetwork_base.MultiNetworkBaseTest):
     # Check that we get an an RTM_NEWNDUSEROPT message on the socket with the
     # expected option.
     csocket.SetSocketTimeout(s.sock, 100)
-    try:
-      data = s._Recv()
-    except IOError as e:
-      self.fail("Should have received an RTM_NEWNDUSEROPT message. "
-                "Please ensure the kernel supports receiving the "
-                "PREF64 RA option. Error: %s" % e)
-    s.close()
 
-    # Check that the message is received correctly.
-    nlmsghdr, data = cstruct.Read(data, netlink.NLMsgHdr)
-    self.assertEqual(iproute.RTM_NEWNDUSEROPT, nlmsghdr.type)
+    needPIO = multinetwork_base.HAVE_USEROPT_PIO_FIX
+    needPref64 = True
 
-    # Check the option contents.
-    ndopthdr, data = cstruct.Read(data, iproute.NdUseroptMsg)
-    self.assertEqual(AF_INET6, ndopthdr.family)
-    self.assertEqual(self.ND_ROUTER_ADVERT, ndopthdr.icmp_type)
-    self.assertEqual(len(opt), ndopthdr.opts_len)
+    while needPIO or needPref64:
+      try:
+        data = s._Recv()
+      except IOError as e:
+        self.fail("Should have received an RTM_NEWNDUSEROPT message. "
+                  "Please ensure the kernel supports receiving the "
+                  "PREF64 RA option. Error: %s" % e)
+      # Check that the message is received correctly.
+      nlmsghdr, data = cstruct.Read(data, netlink.NLMsgHdr)
+      self.assertEqual(iproute.RTM_NEWNDUSEROPT, nlmsghdr.type)
+
+      # print("data=[%s]\n" % data)
+
+      # Check the option contents.
+      ndopthdr, data = cstruct.Read(data, iproute.NdUseroptMsg)
+      self.assertEqual(AF_INET6, ndopthdr.family)
+      self.assertEqual(self.ND_ROUTER_ADVERT, ndopthdr.icmp_type)
+      self.assertEqual(0, ndopthdr.icmp_code)
+
+      self.assertLessEqual(ndopthdr.opts_len, len(data))
+      data, leftover = data[:ndopthdr.opts_len], data[ndopthdr.opts_len:]
+
+      # print("ndopthdr=[%s] data=[%s] leftover=[%s]" % (ndopthdr, data, leftover))
+
+      while data:
+        # print("data2=[%s]\n" % data)
+
+        header_opt = self.NDOptHeader(data)
+        self.assertNotEqual(header_opt.length, 0)
+        self.assertLessEqual(header_opt.length * 8, len(data))
+        payload, data = data[:header_opt.length * 8], data[header_opt.length * 8:]
+
+        # print("type=%d len=%d payload[%s]\n" % (header_opt.type, header_opt.length * 8, payload))
+
+        if header_opt.type == self.ND_OPT_PIO:
+          needPIO = False
+        elif header_opt.type == self.ND_OPT_PREF64:
+          needPref64 = False
+          self.assertEqual(len(opt), len(payload))
+          self.assertEqual(opt, self.Pref64Option(payload))
+        else:
+          # cannot happen: no other options we generate are currently considered user options
+          assert False
 
-    actual_opt = self.Pref64Option(data)
-    self.assertEqual(opt, actual_opt)
+    # we only ever reach here if we find all options we need
+    s.close()
 
   def testRaFlags(self):
     def GetInterfaceIpv6Flags(iface):
diff --git a/net/test/packets.py b/net/test/packets.py
index 2a2ca1e..e9c4777 100644
--- a/net/test/packets.py
+++ b/net/test/packets.py
@@ -87,7 +87,7 @@ def SYN(dport, version, srcaddr, dstaddr, sport=0, seq=-1):
                     seq=seq, ack=0,
                     flags=TCP_SYN, window=TCP_WINDOW))
 
-def RST(version, srcaddr, dstaddr, packet):
+def RST(version, srcaddr, dstaddr, packet, sent_fin=False):
   ip = _GetIpLayer(version)
   original = packet.getlayer("TCP")
   was_syn_or_fin = (original.flags & (TCP_SYN | TCP_FIN)) != 0
@@ -95,7 +95,7 @@ def RST(version, srcaddr, dstaddr, packet):
           ip(src=srcaddr, dst=dstaddr) /
           scapy.TCP(sport=original.dport, dport=original.sport,
                     ack=original.seq + was_syn_or_fin,
-                    seq=original.ack,
+                    seq=original.ack + sent_fin,
                     flags=TCP_RST | TCP_ACK, window=TCP_WINDOW))
 
 def SYNACK(version, srcaddr, dstaddr, packet):
diff --git a/net/test/sock_diag_test.py b/net/test/sock_diag_test.py
index 58e8f01..a668ce0 100755
--- a/net/test/sock_diag_test.py
+++ b/net/test/sock_diag_test.py
@@ -588,6 +588,11 @@ class SockDestroyTcpTest(tcp_test.TcpBaseTest, SockDiagBaseTest):
     super(SockDestroyTcpTest, self).setUp()
     self.netid = random.choice(list(self.tuns.keys()))
 
+  def ExpectRst(self, msg):
+    desc, rst = self.RstPacket()
+    msg = "%s: expecting %s: " % (msg, desc)
+    self.ExpectPacketOn(self.netid, msg, rst)
+
   def CheckRstOnClose(self, sock, req, expect_reset, msg, do_close=True):
     """Closes the socket and checks whether a RST is sent or not."""
     if sock is not None:
@@ -599,9 +604,7 @@ class SockDestroyTcpTest(tcp_test.TcpBaseTest, SockDiagBaseTest):
       self.sock_diag.CloseSocket(req)
 
     if expect_reset:
-      desc, rst = self.RstPacket()
-      msg = "%s: expecting %s: " % (msg, desc)
-      self.ExpectPacketOn(self.netid, msg, rst)
+      self.ExpectRst(msg)
     else:
       msg = "%s: " % msg
       self.ExpectNoPacketsOn(self.netid, msg)
@@ -636,19 +639,31 @@ class SockDestroyTcpTest(tcp_test.TcpBaseTest, SockDiagBaseTest):
       # Close the socket and check that it goes into FIN_WAIT1 and sends a FIN.
       net_test.EnableFinWait(self.accepted)
       self.accepted.close()
-      del self.accepted
+      self.accepted = None
       diag_req.states = 1 << tcp_test.TCP_FIN_WAIT1
       diag_msg, attrs = self.sock_diag.GetSockInfo(diag_req)
       self.assertEqual(tcp_test.TCP_FIN_WAIT1, diag_msg.state)
       desc, fin = self.FinPacket()
-      self.ExpectPacketOn(self.netid, "Closing FIN_WAIT1 socket", fin)
+      msg = "Closing FIN_WAIT1 socket"
+      self.ExpectPacketOn(self.netid, msg, fin)
 
-      # Destroy the socket and expect no RST.
-      self.CheckRstOnClose(None, diag_req, False, "Closing FIN_WAIT1 socket")
-      diag_msg, attrs = self.sock_diag.GetSockInfo(diag_req)
+      # Destroy the socket.
+      self.sock_diag.CloseSocketFromFd(self.s)
+      self.assertRaisesErrno(EINVAL, self.s.accept)
+      try:
+        diag_msg, attrs = self.sock_diag.GetSockInfo(diag_req)
+      except Error as e:
+        # Newer kernels will have closed the socket and sent a RST.
+        self.assertEqual(ENOENT, e.errno)
+        self.ExpectRst(msg)
+        self.CloseSockets()
+        return
 
-      # The socket is still there in FIN_WAIT1: SOCK_DESTROY did nothing
-      # because userspace had already closed it.
+      # Older kernels don't support closing FIN_WAIT1 sockets.
+      # Check that no RST is sent and that the socket is still in FIN_WAIT1, and
+      # advances to FIN_WAIT2 if the FIN is ACked.
+      msg = "%s: " % msg
+      self.ExpectNoPacketsOn(self.netid, msg)
       self.assertEqual(tcp_test.TCP_FIN_WAIT1, diag_msg.state)
 
       # ACK the FIN so we don't trip over retransmits in future tests.
diff --git a/net/test/tcp_test.py b/net/test/tcp_test.py
index f3ee291..b869aa4 100644
--- a/net/test/tcp_test.py
+++ b/net/test/tcp_test.py
@@ -40,13 +40,20 @@ TCP_NOT_YET_ACCEPTED = -1
 
 class TcpBaseTest(multinetwork_base.MultiNetworkBaseTest):
 
+  def __init__(self, *args, **kwargs):
+    super().__init__(*args, **kwargs)
+    self.accepted = None
+    self.s = None
+    self.last_packet = None
+    self.sent_fin = False
+
   def CloseSockets(self):
-    if hasattr(self, "accepted"):
+    if self.accepted:
       self.accepted.close()
-      del self.accepted
-    if hasattr(self, "s"):
+      self.accepted = None
+    if self.s:
       self.s.close()
-      del self.s
+      self.s = None
 
   def tearDown(self):
     self.CloseSockets()
@@ -81,12 +88,15 @@ class TcpBaseTest(multinetwork_base.MultiNetworkBaseTest):
 
   def RstPacket(self):
     return packets.RST(self.version, self.myaddr, self.remoteaddr,
-                       self.last_packet)
+                       self.last_packet, self.sent_fin)
 
   def FinPacket(self):
     return packets.FIN(self.version, self.myaddr, self.remoteaddr,
                        self.last_packet)
 
+  def ExpectPacketOn(self, netid, msg, pkt):
+    self.sent_fin |= (pkt.getlayer("TCP").flags & packets.TCP_FIN) != 0
+    return super(TcpBaseTest, self).ExpectPacketOn(netid, msg, pkt)
 
   def IncomingConnection(self, version, end_state, netid):
     self.s = self.OpenListenSocket(version, netid)
diff --git a/net/test/util.py b/net/test/util.py
index cbcd2d0..ced986e 100644
--- a/net/test/util.py
+++ b/net/test/util.py
@@ -12,6 +12,28 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+"""Utilities for kernel net tests."""
+
+import ctypes
+
+
+def GetSysprop(name):
+  PROP_VALUE_MAX = 92
+  libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
+  name = ctypes.create_string_buffer(name)
+  value = ctypes.create_string_buffer(PROP_VALUE_MAX)
+  libc.__system_property_get(name, value)
+  return value.value
+
+
+def VendorApiLevelIsAtLeast(min_level):
+  try:
+    level = int(GetSysprop(b"ro.vendor.api_level"))
+  except AttributeError:
+    return True
+  return level >= min_level
+
+
 def GetPadLength(block_size, length):
   return (block_size - (length % block_size)) % block_size
 
diff --git a/tools/OWNERS b/tools/OWNERS
new file mode 100644
index 0000000..b3332dc
--- /dev/null
+++ b/tools/OWNERS
@@ -0,0 +1,11 @@
+bettyzhou@google.com
+edliaw@google.com
+elsk@google.com
+hsinyichen@google.com
+joneslee@google.com
+jstultz@google.com
+locc@google.com
+maennich@google.com
+vmartensson@google.com
+willmcvicker@google.com
+
diff --git a/tools/fetch_artifact.sh b/tools/fetch_artifact.sh
new file mode 100755
index 0000000..a29e1af
--- /dev/null
+++ b/tools/fetch_artifact.sh
@@ -0,0 +1,94 @@
+#!/usr/bin/env bash
+# SPDX-License-Identifier: GPL-2.0
+
+# fetch_artifact .sh is a handy tool dedicated to download artifacts from ci.
+# The fetch_artifact binary is needed for this script. Please see more info at:
+#    go/fetch_artifact,
+#    or
+#    https://android.googlesource.com/tools/fetch_artifact/
+# Will use x20 binary: /google/data/ro/projects/android/fetch_artifact by default.
+# Can install fetch_artifact locally with:
+# sudo glinux-add-repo android stable && \
+# sudo apt update && \
+# sudo apt install android-fetch-artifact#
+#
+DEFAULT_FETCH_ARTIFACT=/google/data/ro/projects/android/fetch_artifact
+BOLD="$(tput bold)"
+END="$(tput sgr0)"
+GREEN="$(tput setaf 2)"
+RED="$(tput setaf 198)"
+YELLOW="$(tput setaf 3)"
+BLUE="$(tput setaf 34)"
+
+function print_info() {
+    echo "[$MY_NAME]: ${GREEN}$1${END}"
+}
+
+function print_warn() {
+    echo "[$MY_NAME]: ${YELLOW}$1${END}"
+}
+
+function print_error() {
+    echo -e "[$MY_NAME]: ${RED}$1${END}"
+    exit 1
+}
+
+function binary_checker() {
+    if which fetch_artifact &> /dev/null; then
+        FETCH_CMD="fetch_artifact"
+    elif [ ! -z "${FETCH_ARTIFACT}" ] && [ -f "${FETCH_ARTIFACT}" ]; then
+        FETCH_CMD="${FETCH_ARTIFACT}"
+    elif [ -f "$DEFAULT_FETCH_ARTIFACT" ]; then
+        FETCH_CMD="$DEFAULT_FETCH_ARTIFACT"
+    else
+        print_error "\n${RED} fetch_artifact is not found${END}"
+        echo -e "\n${RED} Please see go/fetch_artifact${END} or
+        https://android.googlesource.com/tools/fetch_artifact/+/refs/heads/main"
+        exit 1
+    fi
+}
+
+
+binary_checker
+
+fetch_cli="$FETCH_CMD"
+
+BUILD_INFO=
+BUILD_FORMAT="ab://<branch>/<build_target>/<build_id>/<file_name>"
+EXTRA_OPTIONS=
+
+MY_NAME="${0##*/}"
+
+for i in "$@"; do
+    case $i in
+        "ab://"*)
+        BUILD_INFO=$i
+        ;;
+        *)
+        EXTRA_OPTIONS+=" $i"
+        ;;
+    esac
+done
+if [ -z "$BUILD_INFO" ]; then
+    print_error "$0 didn't come with the expected $BUILD_FORMAT"
+fi
+
+IFS='/' read -ra array <<< "$BUILD_INFO"
+if [ ${#array[@]} -lt 6 ]; then
+    print_error "Invalid build format: $BUILD_INFO. Needs to be: $BUILD_FORMAT"
+elif [ ${#array[@]} -gt 7 ]; then
+    print_error "Invalid TEST_DIR format: $BUILD_INFO. Needs to be: $BUILD_FORMAT"
+else
+    fetch_cli+=" --branch ${array[2]}"
+    fetch_cli+=" --target ${array[3]}"
+    if [[ "${array[4]}" != latest* ]]; then
+        fetch_cli+=" --bid ${array[4]}"
+    else
+        fetch_cli+=" --latest"
+    fi
+    fetch_cli+="$EXTRA_OPTIONS"
+    fetch_cli+=" '${array[5]}'"
+fi
+
+print_info "Run: $fetch_cli"
+eval "$fetch_cli"
diff --git a/tools/flash_device.sh b/tools/flash_device.sh
new file mode 100755
index 0000000..ba50c13
--- /dev/null
+++ b/tools/flash_device.sh
@@ -0,0 +1,1017 @@
+#!/usr/bin/env bash
+# SPDX-License-Identifier: GPL-2.0
+
+# A handy tool to flash device with local build or remote build.
+
+# Constants
+FETCH_SCRIPT="fetch_artifact.sh"
+# Please see go/cl_flashstation
+FLASH_CLI=/google/bin/releases/android/flashstation/cl_flashstation
+LOCAL_FLASH_CLI=/google/bin/releases/android/flashstation/local_flashstation
+REMOTE_MIX_SCRIPT_PATH="DATA/local/tmp/build_mixed_kernels_ramdisk"
+FETCH_SCRIPT="kernel/tests/tools/fetch_artifact.sh"
+DOWNLOAD_PATH="/tmp/downloaded_images"
+KERNEL_TF_PREBUILT=prebuilts/tradefed/filegroups/tradefed/tradefed.sh
+PLATFORM_TF_PREBUILT=tools/tradefederation/prebuilts/filegroups/tradefed/tradefed.sh
+JDK_PATH=prebuilts/jdk/jdk11/linux-x86
+PLATFORM_JDK_PATH=prebuilts/jdk/jdk21/linux-x86
+LOG_DIR=$PWD/out/test_logs/$(date +%Y%m%d_%H%M%S)
+# Color constants
+BOLD="$(tput bold)"
+END="$(tput sgr0)"
+GREEN="$(tput setaf 2)"
+RED="$(tput setaf 198)"
+YELLOW="$(tput setaf 3)"
+ORANGE="$(tput setaf 208)"
+BLUE=$(tput setaf 4)
+
+SKIP_BUILD=false
+GCOV=false
+DEBUG=false
+KASAN=false
+EXTRA_OPTIONS=()
+LOCAL_REPO=
+DEVICE_VARIANT="userdebug"
+
+function print_help() {
+    echo "Usage: $0 [OPTIONS]"
+    echo ""
+    echo "This script will build images and flash a physical device."
+    echo ""
+    echo "Available options:"
+    echo "  -s <serial_number>, --serial=<serial_number>"
+    echo "                        The serial number for device to be flashed with."
+    echo "  --skip-build          Skip the image build step. Will build by default if in repo."
+    echo "  --gcov                Build gcov enabled kernel"
+    echo "  --debug               Build debug enabled kernel"
+    echo "  --kasan               Build kasan enabled kernel"
+    echo "  -pb <platform_build>, --platform-build=<platform_build>"
+    echo "                        The platform build path. Can be a local path or a remote build"
+    echo "                        as ab://<branch>/<build_target>/<build_id>."
+    echo "                        If not specified, it could use the platform build in the local"
+    echo "                        repo."
+    echo "  -sb <system_build>, --system-build=<system_build>"
+    echo "                        The system build path for GSI testing. Can be a local path or"
+    echo "                        remote build as ab://<branch>/<build_target>/<build_id>."
+    echo "                        If not specified, no system build will be used."
+    echo "  -kb <kernel_build>, --kernel-build=<kernel_build>"
+    echo "                        The kernel build path. Can be a local path or a remote build"
+    echo "                        as ab://<branch>/<build_target>/<build_id>."
+    echo "                        If not specified, it could use the kernel in the local repo."
+    echo "  -vkb <vendor-kernel_build>, --vendor-kernel-build=<kernel_build>"
+    echo "                        The vendor kernel build path. Can be a local path or a remote build"
+    echo "                        as ab://<branch>/<build_target>/<build_id>."
+    echo "                        If not specified, it could use the kernel in the local repo."
+    echo "  --device-variant=<device_variant>"
+    echo "                        Device variant such as userdebug, user, or eng."
+    echo "                        If not specified, will be userdebug by default."
+    echo "  -h, --help            Display this help message and exit"
+    echo ""
+    echo "Examples:"
+    echo "$0"
+    echo "$0 -s 1C141FDEE003FH"
+    echo "$0 -s 1C141FDEE003FH -pb ab://git_main/raven-userdebug/latest"
+    echo "$0 -s 1C141FDEE003FH -pb ~/aosp-main"
+    echo "$0 -s 1C141FDEE003FH -vkb ~/pixel-mainline -pb ab://git_main/raven-trunk_staging-userdebug/latest"
+    echo "$0 -s 1C141FDEE003FH -vkb ab://kernel-android-gs-pixel-mainline/kernel_raviole_kleaf/latest \
+-pb ab://git_trunk_pixel_kernel_61-release/raven-userdebug/latest \
+-kb ab://aosp_kernel-common-android-mainline/kernel_aarch64/latest"
+    echo ""
+    exit 0
+}
+
+function parse_arg() {
+    while test $# -gt 0; do
+        case "$1" in
+            -h|--help)
+                print_help
+                ;;
+            -s)
+                shift
+                if test $# -gt 0; then
+                    SERIAL_NUMBER=$1
+                else
+                    print_error "device serial is not specified"
+                fi
+                shift
+                ;;
+            --serial*)
+                SERIAL_NUMBER=$(echo $1 | sed -e "s/^[^=]*=//g")
+                shift
+                ;;
+            --skip-build)
+                SKIP_BUILD=true
+                shift
+                ;;
+            -pb)
+                shift
+                if test $# -gt 0; then
+                    PLATFORM_BUILD=$1
+                else
+                    print_error "platform build is not specified"
+                fi
+                shift
+                ;;
+            --platform-build=*)
+                PLATFORM_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
+                shift
+                ;;
+            -sb)
+                shift
+                if test $# -gt 0; then
+                    SYSTEM_BUILD=$1
+                else
+                    print_error "system build is not specified"
+                fi
+                shift
+                ;;
+            --system-build=*)
+                SYSTEM_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
+                shift
+                ;;
+            -kb)
+                shift
+                if test $# -gt 0; then
+                    KERNEL_BUILD=$1
+                else
+                    print_error "kernel build path is not specified"
+                fi
+                shift
+                ;;
+            --kernel-build=*)
+                KERNEL_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
+                shift
+                ;;
+            -vkb)
+                shift
+                if test $# -gt 0; then
+                    VENDOR_KERNEL_BUILD=$1
+                else
+                    print_error "vendor kernel build path is not specified"
+                fi
+                shift
+                ;;
+            --vendor-kernel-build=*)
+                VENDOR_KERNEL_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
+                shift
+                ;;
+            --device-variant=*)
+                DEVICE_VARIANT=$(echo $1 | sed -e "s/^[^=]*=//g")
+                shift
+                ;;
+            --gcov)
+                GCOV=true
+                shift
+                ;;
+            --debug)
+                DEBUG=true
+                shift
+                ;;
+            --kasan)
+                KASAN=true
+                shift
+                ;;
+            *)
+                print_error "Unsupported flag: $1" >&2
+                shift
+                ;;
+        esac
+    done
+}
+
+function adb_checker() {
+    if ! which adb &> /dev/null; then
+        print_error "adb not found!"
+    fi
+}
+
+function go_to_repo_root() {
+    current_dir="$1"
+    while [ ! -d ".repo" ] && [ "$current_dir" != "/" ]; do
+        current_dir=$(dirname "$current_dir")  # Go up one directory
+        cd "$current_dir"
+    done
+}
+
+function print_info() {
+    local log_prompt=$MY_NAME
+    if [ ! -z "$2" ]; then
+        log_prompt+=" line $2"
+    fi
+    echo "[$log_prompt]: ${GREEN}$1${END}"
+}
+
+function print_warn() {
+    local log_prompt=$MY_NAME
+    if [ ! -z "$2" ]; then
+        log_prompt+=" line $2"
+    fi
+    echo "[$log_prompt]: ${ORANGE}$1${END}"
+}
+
+function print_error() {
+    local log_prompt=$MY_NAME
+    if [ ! -z "$2" ]; then
+        log_prompt+=" line $2"
+    fi
+    echo -e "[$log_prompt]: ${RED}$1${END}"
+    cd $OLD_PWD
+    exit 1
+}
+
+function set_platform_repo () {
+    print_warn "Build environment target product '${TARGET_PRODUCT}' does not match expected $1. \
+    Reset build environment" "$LINENO"
+    local lunch_cli="source build/envsetup.sh && lunch $1"
+    if [ -f "build/release/release_configs/trunk_staging.textproto" ]; then
+        lunch_cli+="-trunk_staging-$DEVICE_VARIANT"
+    else
+        lunch_cli+="-$DEVICE_VARIANT"
+    fi
+    print_info "Setup build environment with: $lunch_cli" "$LINENO"
+    eval "$lunch_cli"
+    exit_code=$?
+    if [ $exit_code -eq 0 ]; then
+        print_info "$lunch_cli succeeded" "$LINENO"
+    else
+        print_error "$lunch_cli failed" "$LINENO"
+    fi
+}
+
+function find_repo () {
+    manifest_output=$(grep -e "superproject" -e "gs-pixel" -e "private/google-modules/soc/gs" \
+    -e "kernel/common" -e "common-modules/virtual-device" .repo/manifests/default.xml)
+    case "$manifest_output" in
+        *platform/superproject*)
+            PLATFORM_REPO_ROOT="$PWD"
+            PLATFORM_VERSION=$(grep -e "platform/superproject" .repo/manifests/default.xml | \
+            grep -oP 'revision="\K[^"]*')
+            print_info "PLATFORM_REPO_ROOT=$PLATFORM_REPO_ROOT, PLATFORM_VERSION=$PLATFORM_VERSION" "$LINENO"
+            if [ -z "$PLATFORM_BUILD" ]; then
+                PLATFORM_BUILD="$PLATFORM_REPO_ROOT"
+            fi
+            ;;
+        *kernel/superproject*)
+            if [[ "$manifest_output" == *private/google-modules/soc/gs* ]]; then
+                VENDOR_KERNEL_REPO_ROOT="$PWD"
+                VENDOR_KERNEL_VERSION=$(grep -e "default revision" .repo/manifests/default.xml | \
+                grep -oP 'revision="\K[^"]*')
+                print_info "VENDOR_KERNEL_REPO_ROOT=$VENDOR_KERNEL_REPO_ROOT" "$LINENO"
+                print_info "VENDOR_KERNEL_VERSION=$VENDOR_KERNEL_VERSION" "$LINENO"
+                if [ -z "$VENDOR_KERNEL_BUILD" ]; then
+                    VENDOR_KERNEL_BUILD="$VENDOR_KERNEL_REPO_ROOT"
+                fi
+            elif [[ "$manifest_output" == *common-modules/virtual-device* ]]; then
+                KERNEL_REPO_ROOT="$PWD"
+                KERNEL_VERSION=$(grep -e "kernel/superproject" \
+                .repo/manifests/default.xml | grep -oP 'revision="common-\K[^"]*')
+                print_info "KERNEL_REPO_ROOT=$KERNEL_REPO_ROOT, KERNEL_VERSION=$KERNEL_VERSION" "$LINENO"
+                if [ -z "$KERNEL_BUILD" ]; then
+                    KERNEL_BUILD="$KERNEL_REPO_ROOT"
+                fi
+            fi
+            ;;
+        *)
+            print_warn "Unexpected manifest output. Could not determine repository type." "$LINENO"
+            ;;
+    esac
+}
+
+function build_platform () {
+    if [[ "$SKIP_BUILD" = true ]]; then
+        print_warn "--skip-build is set. Do not rebuild platform build" "$LINENO"
+        return
+    fi
+    build_cmd="m -j12 ; make otatools -j12 ; make dist -j12"
+    print_warn "Flag --skip-build is not set. Rebuilt images at $PWD with: $build_cmd" "$LINENO"
+    eval $build_cmd
+    exit_code=$?
+    if [ $exit_code -eq 1 ]; then
+        print_warn "$build_cmd returned exit_code $exit_code" "$LINENO"
+        print_error "$build_cmd failed" "$LINENO"
+    else
+        if [ -f "${ANDROID_PRODUCT_OUT}/system.img" ]; then
+            print_info "${ANDROID_PRODUCT_OUT}/system.img exist" "$LINENO"
+        else
+            print_error "${ANDROID_PRODUCT_OUT}/system.img doesn't exist" "$LINENO"
+        fi
+    fi
+}
+
+function build_slider () {
+    if [[ "$SKIP_BUILD" = true ]]; then
+        print_warn "--skip-build is set. Do not rebuild slider" "$LINENO"
+        return
+    fi
+    local build_cmd=
+    if [ -f "build_slider.sh" ]; then
+        build_cmd="./build_slider.sh"
+    else
+        build_cmd="tools/bazel run --config=fast"
+        build_cmd+=" //private/google-modules/soc/gs:slider_dist"
+    fi
+    if [ "$GCOV" = true ]; then
+        build_cmd+=" --gcov"
+    fi
+    if [ "$DEBUG" = true ]; then
+        build_cmd+=" --debug"
+    fi
+    if [ "$KASAN" = true ]; then
+        build_cmd+=" --kasan"
+    fi
+    eval "$build_cmd"
+    exit_code=$?
+    if [ $exit_code -eq 0 ]; then
+        print_info "Build kernel succeeded" "$LINENO"
+    else
+        print_error "Build kernel failed with exit code $exit_code" "$LINENO"
+    fi
+}
+
+function build_ack () {
+    if [[ "$SKIP_BUILD" = true ]]; then
+        print_warn "--skip-build is set. Do not rebuild kernel" "$LINENO"
+        return
+    fi
+    build_cmd="tools/bazel run --config=fast"
+    if [ "$GCOV" = true ]; then
+        build_cmd+=" --gcov"
+    fi
+    if [ "$DEBUG" = true ]; then
+        build_cmd+=" --debug"
+    fi
+    if [ "$KASAN" = true ]; then
+        build_cmd+=" --kasan"
+    fi
+    build_cmd+=" //common:kernel_aarch64_dist"
+    print_warn "Flag --skip-build is not set. Rebuild the kernel with: $build_cmd." "$LINENO"
+    eval $build_cmd
+    exit_code=$?
+    if [ $exit_code -eq 0 ]; then
+        print_info "$build_cmd succeeded" "$LINENO"
+    else
+        print_error "$build_cmd failed" "$LINENO"
+    fi
+}
+
+function download_platform_build() {
+    print_info "Downloading $1 to $PWD" "$LINENO"
+    local build_info="$1"
+    local file_patterns=("*$PRODUCT-img-*.zip" "bootloader.img" "radio.img" "vendor_ramdisk.img" "misc_info.txt" "otatools.zip")
+
+    for pattern in "${file_patterns[@]}"; do
+        download_file_name="$build_info/$pattern"
+        eval "$FETCH_SCRIPT $download_file_name"
+        exit_code=$?
+        if [ $exit_code -eq 0 ]; then
+            print_info "Download $download_file_name succeeded" "$LINENO"
+        else
+            print_error "Download $download_file_name failed" "$LINENO"
+        fi
+    done
+    echo ""
+}
+
+function download_gki_build() {
+    print_info "Downloading $1 to $PWD" "$LINENO"
+    local build_info="$1"
+    local file_patterns=("Image.lz4" "boot-lz4.img" "system_dlkm_staging_archive.tar.gz" "system_dlkm.flatten.ext4.img" "system_dlkm.flatten.erofs.img")
+
+    for pattern in "${file_patterns[@]}"; do
+        download_file_name="$build_info/$pattern"
+        eval "$FETCH_SCRIPT $download_file_name"
+        exit_code=$?
+        if [ $exit_code -eq 0 ]; then
+            print_info "Download $download_file_name succeeded" "$LINENO"
+        else
+            print_error "Download $download_file_name failed" "$LINENO"
+        fi
+    done
+    echo ""
+}
+
+function download_vendor_kernel_build() {
+    print_info "Downloading $1 to $PWD" "$LINENO"
+    local build_info="$1"
+    local file_patterns=("vendor_dlkm_staging_archive.tar.gz" "Image.lz4" "dtbo.img" \
+    "initramfs.img" "vendor_dlkm.img" "boot.img" "vendor_dlkm.modules.blocklist" "vendor_dlkm.modules.load" )
+
+    if [[ "$VENDOR_KERNEL_VERSION" == *"6.6" ]]; then
+        file_patterns+="*vendor_dev_nodes_fragment.img"
+    fi
+
+    case "$PRODUCT" in
+        oriole | raven | bluejay)
+            file_patterns+=("gs101-a0.dtb" "gs101-b0.dtb")
+            ;;
+        *)
+            ;;
+    esac
+    for pattern in "${file_patterns[@]}"; do
+        download_file_name="$build_info/$pattern"
+        eval "$FETCH_SCRIPT $download_file_name"
+        exit_code=$?
+        if [ $exit_code -eq 0 ]; then
+            print_info "Download $download_file_name succeeded" "$LINENO"
+        else
+            print_error "Download $download_file_name failed" "$LINENO"
+        fi
+    done
+    echo ""
+}
+
+function flash_gki_build() {
+    local boot_image_name
+    local system_dlkm_image_name
+
+    case "$PRODUCT" in
+        oriole | raven | bluejay)
+            boot_image_name="boot-lz4.img"
+            # no system_dlkm partition
+            ;;
+        eos | aurora | full_erd8835 | betty | kirkwood)
+            boot_image_name="boot.img"
+            if [[ "$PRODUCT" == "kirkwood" ]] && [[ ! "$KERNEL_VERSION" =~ ^android13 ]]; then  # Check if NOT android13
+                system_dlkm_image_name="system_dlkm.flatten.erofs.img"
+            # no system_dlkm for android12 & android13
+            elif [[ ! "$KERNEL_VERSION" =~ ^android12 ]] && [[ ! "$KERNEL_VERSION" =~ ^android13 ]]; then  # Check if NOT android12 AND NOT android13
+                system_dlkm_image_name="system_dlkm.flatten.erofs.img"
+            fi
+            ;;
+        k6985v1 | k6989v1)
+            boot_image_name="boot-gz.img"
+            # no system_dlkm for android12 & android13
+            if [[ ! "$KERNEL_VERSION" =~ ^android12 ]] && [[ ! "$KERNEL_VERSION" =~ ^android13 ]]; then  # Check if NOT android12 AND NOT android13
+                system_dlkm_image_name="system_dlkm.flatten.ext4.img"
+            fi
+            ;;
+        *)
+            boot_image_name="boot-lz4.img"
+            # no system_dlkm for android12 & android13
+            if [[ ! "$KERNEL_VERSION" =~ ^android12 ]] && [[ ! "$KERNEL_VERSION" =~ ^android13 ]]; then # Check if NOT android12 AND NOT android13
+                system_dlkm_image_name="system_dlkm.flatten.ext4.img"
+            fi
+            ;;
+    esac
+
+    if [ -z "$TRADEFED" ]; then
+        find_tradefed_bin
+    fi
+    if [ -d "$DOWNLOAD_PATH/tf_gki_kernel_dir" ]; then
+        rm -rf "$DOWNLOAD_PATH/tf_gki_kernel_dir"
+    fi
+    local kernel_dir="$DOWNLOAD_PATH/tf_gki_kernel_dir"
+    mkdir -p "$kernel_dir"
+    cd "$vendor_kernel_dir" || $(print_error "Fail to go to $gki_kernel_dir" "$LINENO")
+    cp "$KERNEL_BUILD/$boot_image_name" "$kernel_dir" || $(print_error "Fail to copy $KERNEL_BUILD/$boot_image_name" "$LINENO")
+    tf_cli="$TRADEFED \
+    run commandAndExit template/local_min --log-level-display VERBOSE \
+    --log-file-path=$LOG_DIR -s $SERIAL_NUMBER --disable-verity \
+    --template:map preparers=template/preparers/gki-device-flash-preparer \
+    --extra-file gki_boot.img=$kernel_dir/$boot_image_name"
+
+    # Check if system_dlkm_image_name is set before adding it to the command
+    if [ ! -z "$system_dlkm_image_name" ]; then
+        cp "$KERNEL_BUILD/$system_dlkm_image_name" "$kernel_dir" || $(print_error "Fail to copy $KERNEL_BUILD/$system_dlkm_image_name" "$LINENO")
+        tf_cli+=" --extra-file system_dlkm.img=$kernel_dir/$system_dlkm_image_name"
+    fi
+    print_info "Run $tf_cli" "$LINENO"
+    eval "$tf_cli" # Quote the variable expansion
+}
+
+function flash_vendor_kernel_build() {
+    if [ -z "$TRADEFED" ]; then
+        find_tradefed_bin
+    fi
+    local tf_cli="$TRADEFED \
+    run commandAndExit template/local_min --log-level-display VERBOSE \
+    --log-file-path=$LOG_DIR -s $SERIAL_NUMBER --disable-verity \
+    --template:map preparers=template/preparers/gki-device-flash-preparer"
+
+    if [ -d "$DOWNLOAD_PATH/tf_vendor_kernel_dir" ]; then
+        rm -rf "$DOWNLOAD_PATH/tf_vendor_kernel_dir"
+    fi
+    local vendor_kernel_dir="$DOWNLOAD_PATH/tf_vendor_kernel_dir"
+    mkdir -p "$vendor_kernel_dir"
+    local file_patterns=("boot.img" "initramfs.img" "dtbo.img" "vendor_dlkm.img")
+    for pattern in "${file_patterns[@]}"; do
+        if [ ! -f "$VENDOR_KERNEL_BUILD/$pattern" ]; then
+            print_error "$VENDOR_KERNEL_BUILD/$pattern doesn't exist" "$LINENO"
+        fi
+        cp "$VENDOR_KERNEL_BUILD/$pattern" "$vendor_kernel_dir"
+        if [[ "$pattern" == "boot.img" ]]; then
+            tf_cli+=" --extra-file gki_boot.img=$vendor_kernel_dir/boot.img"
+        else
+            tf_cli+=" --extra-file $pattern=$vendor_kernel_dir/$pattern"
+        fi
+    done
+    print_info "Run $tf_cli" "$LINENO"
+    eval $tf_cli
+}
+
+function flash_platform_build() {
+    if [[ "$PLATFORM_BUILD" == ab://* ]] && [ -x "$FLASH_CLI" ]; then
+        local flash_cmd="$FLASH_CLI --nointeractive --force_flash_partitions --disable_verity --skip_build_compatibility_check -w -s $SERIAL_NUMBER "
+        IFS='/' read -ra array <<< "$PLATFORM_BUILD"
+        if [ ! -z "${array[3]}" ]; then
+            if [[ "${array[3]}" == *userdebug ]]; then
+                flash_cmd+=" -t userdebug"
+            elif [[ "${array[3]}" == *user ]]; then
+                flash_cmd+=" -t user"
+            fi
+        fi
+        if [ ! -z "${array[4]}" ] && [[ "${array[4]}" != latest* ]]; then
+            echo "Flash $SERIAL_NUMBER with platform build from branch $PLATFORM_BUILD..."
+            flash_cmd+=" --bid ${array[4]}"
+        else
+            echo "Flash $SERIAL_NUMBER with platform build $PLATFORM_BUILD..."
+            flash_cmd+=" -l ${array[2]}"
+        fi
+        print_info "Flash $SERIAL_NUMBER with flash station cli by: $flash_cmd" "$LINENO"
+        eval "$flash_cmd"
+        exit_code=$?
+        if [ $exit_code -eq 0 ]; then
+            echo "Flash platform succeeded"
+            return
+        else
+            echo "Flash platform build failed with exit code $exit_code"
+            exit 1
+        fi
+    fi
+
+    if [ ! -z "$PLATFORM_REPO_ROOT" ] && [[ "$PLATFORM_BUILD" == "$PLATFORM_REPO_ROOT/out/target/product/$PRODUCT" ]] && \
+    [ -x "$PLATFORM_REPO_ROOT/vendor/google/tools/flashall" ]; then
+        cd "$PLATFORM_REPO_ROOT"
+        print_info "Flash with vendor/google/tools/flashall" "$LINENO"
+        if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != *"$PRODUCT" ]]; then
+            if [[ "$PLATFORM_VERSION" == aosp-* ]]; then
+                set_platform_repo "aosp_$PRODUCT"
+            else
+                set_platform_repo "PRODUCT"
+            fi
+        fi
+        eval "vendor/google/tools/flashall  --nointeractive -w -s $SERIAL_NUMBER"
+        return
+    elif [ -x "${ANDROID_HOST_OUT}/bin/local_flashstation" ] || [ -x "$LOCAL_FLASH_CLI" ]; then
+        if [ -z "${TARGET_PRODUCT}" ]; then
+            export TARGET_PRODUCT="$PRODUCT"
+        fi
+        if [ -z "${TARGET_BUILD_VARIANT}" ]; then
+            export TARGET_BUILD_VARIANT="$DEVICE_VARIANT"
+        fi
+        if [ -z "${ANDROID_PRODUCT_OUT}" ] || [[ "${ANDROID_PRODUCT_OUT}" != "$PLATFORM_BUILD" ]] ; then
+            export ANDROID_PRODUCT_OUT="$PLATFORM_BUILD"
+        fi
+        if [ -z "${ANDROID_HOST_OUT}" ]; then
+            export ANDROID_HOST_OUT="$PLATFORM_BUILD"
+        fi
+        if [ ! -f "$PLATFORM_BUILD/system.img" ]; then
+            local device_image=$(find "$PLATFORM_BUILD" -maxdepth 1 -type f -name *-img*.zip)
+            unzip -j "$device_image" -d "$PLATFORM_BUILD"
+        fi
+
+        awk '! /baseband/' "$PLATFORM_BUILD"/android-info.txt > temp && mv temp "$PLATFORM_BUILD"/android-info.txt
+        awk '! /bootloader/' "$PLATFORM_BUILD"/android-info.txt > temp && mv temp "$PLATFORM_BUILD"/android-info.txt
+
+        flash_cmd="$LOCAL_FLASH_CLI"
+
+        if [ ! -x "$LOCAL_FLASH_CLI" ]; then
+            flash_cmd="${ANDROID_HOST_OUT}/bin/local_flashstation"
+        fi
+
+        flash_cmd+=" --nointeractive --force_flash_partitions --skip_build_compatibility_check --disable_verity --disable_verification  -w -s $SERIAL_NUMBER"
+        print_info "Flash device with: $flash_cmd" "$LINENO"
+        eval "$flash_cmd"
+        exit_code=$?
+        if [ $exit_code -eq 0 ]; then
+            echo "Flash platform succeeded"
+            return
+        else
+            echo "Flash platform build failed with exit code $exit_code"
+            exit 1
+        fi
+    fi
+
+}
+
+function get_mix_ramdisk_script() {
+    download_file_name="ab://git_main/aosp_cf_x86_64_only_phone-trunk_staging-userdebug/latest/*-tests-*.zip"
+    eval "$FETCH_SCRIPT $download_file_name"
+    exit_code=$?
+    if [ $exit_code -eq 0 ]; then
+        print_info "Download $download_file_name succeeded" "$LINENO"
+    else
+        print_error "Download $download_file_name failed" "$LINENO" "$LINENO"
+    fi
+    eval "unzip -j *-tests-* DATA/local/tmp/build_mixed_kernels_ramdisk"
+    echo ""
+}
+
+function mixing_build() {
+    if [ ! -z ${PLATFORM_REPO_ROOT_PATH} ] && [ -f "$PLATFORM_REPO_ROOT_PATH/vendor/google/tools/build_mixed_kernels_ramdisk"]; then
+        mix_kernel_cmd="$PLATFORM_REPO_ROOT_PATH/vendor/google/tools/build_mixed_kernels_ramdisk"
+    elif [ -f "$DOWNLOAD_PATH/build_mixed_kernels_ramdisk" ]; then
+        mix_kernel_cmd="$DOWNLOAD_PATH/build_mixed_kernels_ramdisk"
+    else
+        cd "$DOWNLOAD_PATH"
+        get_mix_ramdisk_script
+        mix_kernel_cmd="$PWD/build_mixed_kernels_ramdisk"
+    fi
+    if [ ! -f "$mix_kernel_cmd" ]; then
+        print_error "$mix_kernel_cmd doesn't exist or is not executable" "$LINENO"
+    elif [ ! -x "$mix_kernel_cmd" ]; then
+        print_error "$mix_kernel_cmd is not executable" "$LINENO"
+    fi
+    if [[ "$PLATFORM_BUILD" == ab://* ]]; then
+        print_info "Download platform build $PLATFORM_BUILD" "$LINENO"
+        if [ -d "$DOWNLOAD_PATH/device_dir" ]; then
+            rm -rf "$DOWNLOAD_PATH/device_dir"
+        fi
+        PLATFORM_DIR="$DOWNLOAD_PATH/device_dir"
+        mkdir -p "$PLATFORM_DIR"
+        cd "$PLATFORM_DIR" || $(print_error "Fail to go to $PLATFORM_DIR" "$LINENO")
+        download_platform_build "$PLATFORM_BUILD"
+        PLATFORM_BUILD="$PLATFORM_DIR"
+    elif [ ! -z "$PLATFORM_REPO_ROOT" ] && [[ "$PLATFORM_BUILD" == "$PLATFORM_REPO_ROOT"* ]]; then
+        print_info "Copy platform build $PLATFORM_BUILD to $DOWNLOAD_PATH/device_dir" "$LINENO"
+        PLATFORM_DIR="$DOWNLOAD_PATH/device_dir"
+        mkdir -p "$PLATFORM_DIR"
+        cd "$PLATFORM_DIR" || $(print_error "Fail to go to $PLATFORM_DIR" "$LINENO")
+        local device_image=$(find "$PLATFORM_BUILD" -maxdepth 1 -type f -name *-img.zip)
+        if [ ! -z "device_image" ]; then
+            cp "$device_image $PLATFORM_DIR/$PRODUCT-img-0.zip" "$PLATFORM_DIR"
+        else
+            device_image=$(find "$PLATFORM_BUILD" -maxdepth 1 -type f -name *-img-*.zip)
+            if [ ! -z "device_image" ]; then
+                cp "$device_image $PLATFORM_DIR/$PRODUCT-img-0.zip" "$PLATFORM_DIR"
+            else
+                print_error "Can't find $RPODUCT-img-*.zip in $PLATFORM_BUILD"
+            fi
+        fi
+        local file_patterns=("bootloader.img" "radio.img" "vendor_ramdisk.img" "misc_info.txt" "otatools.zip")
+        for pattern in "${file_patterns[@]}"; do
+            cp "$PLATFORM_BUILD/$pattern" "$PLATFORM_DIR/$pattern"
+            exit_code=$?
+            if [ $exit_code -eq 0 ]; then
+                print_info "Copied $PLATFORM_BUILD/$pattern to $PLATFORM_DIR" "$LINENO"
+            else
+                print_error "Failed to copy $PLATFORM_BUILD/$pattern to $PLATFORM_DIR" "$LINENO"
+            fi
+        done
+        PLATFORM_BUILD="$PLATFORM_DIR"
+    fi
+
+    local new_device_dir="$DOWNLOAD_PATH/new_device_dir"
+    if [ -d "$new_device_dir" ]; then
+        rm -rf "$new_device_dir"
+    fi
+    mkdir -p "$new_device_dir"
+    local mixed_build_cmd="$mix_kernel_cmd"
+    if [ -d "${KERNEL_BUILD}" ]; then
+        mixed_build_cmd+=" --gki_dir $KERNEL_BUILD"
+    fi
+    mixed_build_cmd+=" $PLATFORM_BUILD $VENDOR_KERNEL_BUILD $new_device_dir"
+    print_info "Run: $mixed_build_cmd" "$LINENO"
+    eval $mixed_build_cmd
+    device_image=$(ls $new_device_dir/*$PRODUCT-img*.zip)
+    if [ ! -f "$device_image" ]; then
+        print_error "New device image is not created in $new_device_dir" "$LINENO"
+    fi
+    cp "$PLATFORM_BUILD"/bootloader.img $new_device_dir/.
+    cp "$PLATFORM_BUILD"/radio.img $new_device_dir/.
+    PLATFORM_BUILD="$new_device_dir"
+}
+
+get_kernel_version_from_boot_image() {
+    local boot_image_path="$1"
+    local version_output
+
+    # Check for mainline kernel
+    version_output=$(strings "$boot_image_path" | grep mainline)
+    if [ ! -z "$version_output" ]; then
+        KERNEL_VERSION="android-mainline"
+        return  # Exit the function early if a match is found
+    fi
+
+    # Check for Android 15 6.6 kernel
+    version_output=$(strings "$boot_image_path" | grep "android15" | grep "6.6")
+    if [ ! -z "$version_output" ]; then
+        KERNEL_VERSION="android15-6.6"
+        return
+    fi
+
+    # Check for Android 14 6.1 kernel
+    version_output=$(strings "$boot_image_path" | grep "android14" | grep "6.1")
+    if [ ! -z "$version_output" ]; then
+        KERNEL_VERSION="android14-6.1"
+        return
+    fi
+
+    # Check for Android 14 5.15 kernel
+    version_output=$(strings "$boot_image_path" | grep "android14" | grep "5.15")
+    if [ ! -z "$version_output" ]; then
+        KERNEL_VERSION="android14-5.15"
+        return
+    fi
+
+    # Check for Android 13 5.15 kernel
+    version_output=$(strings "$boot_image_path" | grep "android13" | grep "5.15")
+    if [ ! -z "$version_output" ]; then
+        KERNEL_VERSION="android13-5.15"
+        return
+    fi
+
+    # Check for Android 13 5.10 kernel
+    version_output=$(strings "$boot_image_path" | grep "android13" | grep "5.10")
+    if [ ! -z "$version_output" ]; then
+        KERNEL_VERSION="android13-5.10"
+        return
+    fi
+
+    # Check for Android 12 5.10 kernel
+    version_output=$(strings "$boot_image_path" | grep "android12" | grep "5.10")
+    if [ ! -z "$version_output" ]; then
+        KERNEL_VERSION="android12-5.10"
+        return
+    fi
+}
+
+function gki_build_only_operation {
+    IFS='-' read -ra array <<< "$KERNEL_VERSION"
+    case "$KERNEL_VERSION" in
+        android-mainline | android15-6.6* | android14-6.1* | android14-5.15* )
+            if [[ "$KERNEL_VERSION" == "$DEVICE_KERNEL_VERSION"* ]] && [ ! -z "$SYSTEM_DLKM_VERSION" ]; then
+                print_info "Device $SERIAL_NUMBER is with $KERNEL_VERSION kernel. Flash GKI directly" "$LINENO"
+                flash_gki
+            elif [ -z "$SYSTEM_DLKM_VERSION" ]; then
+                print_warn "Device $SERIAL_NUMBER is $PRODUCT that doesn't have system_dlkm partition. Can't flash GKI directly. \
+Please add vendor kernel build for example by flag -vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
+                print_error "Can not flash GKI to SERIAL_NUMBER without -vkb <vendor_kernel_build> been specified." "$LINENO"
+            elif [[ "$KERNEL_VERSION" != "$DEVICE_KERNEL_VERSION"* ]]; then
+                print_warn "Device $SERIAL_NUMBER is $PRODUCT comes with $DEVICE_KERNEL_STRING kernel. Can't flash GKI directly. \
+Please add a platform build with $KERNEL_VERSION kernel or add vendor kernel build for example by flag \
+-vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
+                print_error "Cannot flash $KERNEL_VERSION GKI to device directly $SERIAL_NUMBER." "$LINENO"
+            fi
+            ;;
+        android13-5.15* | android13-5.10* | android12-5.10* | android12-5.4* )
+            if [[ "$KERNEL_VERSION" == "$EVICE_KERNEL_VERSION"* ]]; then
+                print_info "Device $SERIAL_NUMBER is with android13-5.15 kernel. Flash GKI directly." "$LINENO"
+                flash_gki
+            else
+                print_warn "Device $SERIAL_NUMBER is $PRODUCT comes with $DEVICE_KERNEL_STRING kernel. Can't flash GKI directly. \
+Please add a platform build with $KERNEL_VERSION kernel or add vendor kernel build for example by flag \
+-vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
+                print_error "Cannot flash $KERNEL_VERSION GKI to device directly $SERIAL_NUMBER." "$LINENO"
+            fi
+            ;;
+        *)
+            print_error "Unsupported KERNEL_VERSION: $KERNEL_VERSION" "$LINENO" "$LINENO"
+            ;;
+    esac
+}
+
+function extract_kernel_version() {
+    local kernel_string="$1"
+    # Check if the string contains '-android'
+    if [[ "$kernel_string" == *"-mainline"* ]]; then
+        kernel_version="android-mainline"
+    elif [[ "$kernel_string" == *"-android"* ]]; then
+        # Extract the substring between the first hyphen and the second hyphen
+        local kernel_version=$(echo "$kernel_string" | cut -d '-' -f 2-)
+        kernel_version=$(echo "$kernel_version" | cut -d '-' -f 1)
+    else
+       print_warn "Can not parse $kernel_string into kernel version" "$LINENO"
+    fi
+    print_info "Device kernel version is $kernel_version" "$LINENO"
+}
+
+function get_device_info {
+    BOARD=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.board)
+    ABI=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.cpu.abi)
+    PRODUCT=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.product)
+    BUILD_TYPE=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.type)
+    DEVICE_KERNEL_STRING=$(adb -s "$SERIAL_NUMBER" shell uname -r)
+    DEVICE_KERNEL_VERSION=$(extract_kernel_version "$DEVICE_KERNEL_STRING")
+    SYSTEM_DLKM_VERSION=$(adb -s "$SERIAL_NUMBER" shell getprop ro.system_dlkm.build.version.release)
+    if [ -z "$PRODUCT" ]; then
+        # try get product by fastboot command
+        local output=$(fastboot -s "$SERIAL_NUMBER" getvar product 2>&1)
+        PRODUCT=$(echo "$output" | grep -oP '^product:\s*\K.*' | cut -d' ' -f1)
+    fi
+}
+
+function find_tradefed_bin {
+    cd "$REPO_ROOT_PATH"
+    if [ -f "${ANDROID_HOST_OUT}/bin/tradefed.sh" ] ; then
+        TRADEFED="${ANDROID_HOST_OUT}/bin/tradefed.sh"
+        print_info "Use the tradefed from the local built path $TRADEFED" "$LINENO"
+    elif [ -f "$PLATFORM_TF_PREBUILT" ]; then
+        TRADEFED="JAVA_HOME=$PLATFORM_JDK_PATH PATH=$PLATFORM_JDK_PATH/bin:$PATH $PLATFORM_TF_PREBUILT"
+        print_info "Local Tradefed is not built yet. Use the prebuilt from $PLATFORM_TF_PREBUILT" "$LINENO"
+    elif [ -f "$KERNEL_TF_PREBUILT" ]; then
+        TRADEFED="JAVA_HOME=$JDK_PATH PATH=$JDK_PATH/bin:$PATH $KERNEL_TF_PREBUILT"
+    # No Tradefed found
+    else
+        print_error "Can not find Tradefed binary. Please use flag -tf to specify the binary path." "$LINENO" "$LINENO"
+    fi
+}
+
+adb_checker
+
+LOCAL_REPO=
+
+OLD_PWD=$PWD
+MY_NAME=$0
+
+parse_arg "$@"
+
+if [ -z "$SERIAL_NUMBER" ]; then
+    print_error "Device serial is not provided with flag -s <serial_number>." "$LINENO"
+    exit 1
+fi
+
+get_device_info
+
+FULL_COMMAND_PATH=$(dirname "$PWD/$0")
+REPO_LIST_OUT=$(repo list 2>&1)
+if [[ "$REPO_LIST_OUT" == "error"* ]]; then
+    print_error "Current path $PWD is not in an Android repo. Change path to repo root." "$LINENO"
+    go_to_repo_root "$FULL_COMMAND_PATH"
+    print_info "Changed path to $PWD" "$LINENO"
+else
+    go_to_repo_root "$PWD"
+fi
+
+REPO_ROOT_PATH="$PWD"
+FETCH_SCRIPT="$REPO_ROOT_PATH/$FETCH_SCRIPT"
+
+find_repo
+
+if [ ! -d "$DOWNLOAD_PATH" ]; then
+    mkdir -p "$DOWNLOAD_PATH" || $(print_error "Fail to create directory $DOWNLOAD_PATH" "$LINENO")
+fi
+
+if [ ! -z "$PLATFORM_BUILD" ] && [[ "$PLATFORM_BUILD" != ab://* ]] && [ -d "$PLATFORM_BUILD" ]; then
+    # Check if PLATFORM_BUILD is an Android platform repo
+    cd "$PLATFORM_BUILD"
+    PLATFORM_REPO_LIST_OUT=$(repo list 2>&1)
+    if [[ "$PLATFORM_REPO_LIST_OUT" != "error"* ]]; then
+        go_to_repo_root "$PWD"
+        if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
+            find_repo
+        fi
+        if [ "$SKIP_BUILD" = false ]; then
+            if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != *"$PRODUCT" ]]; then
+                if [[ "$PLATFORM_VERSION" == aosp-* ]]; then
+                    set_platform_repo "aosp_$PRODUCT"
+                else
+                    set_platform_repo "PRODUCT"
+                fi
+            elif [[ "${TARGET_PRODUCT}" == *"$PRODUCT" ]]; then
+                echo "TARGET_PRODUCT=${TARGET_PRODUCT}, ANDROID_PRODUCT_OUT=${ANDROID_PRODUCT_OUT}"
+            fi
+            if [[ "${TARGET_PRODUCT}" == *"$PRODUCT" ]]; then
+                build_platform
+            else
+                print_error "Can not build platform build due to lunch build target failure" "$LINENO"
+            fi
+        fi
+        if [ -d "${PLATFORM_REPO_ROOT}" ] && [ -f "$PLATFORM_REPO_ROOT/out/target/product/$PRODUCT/otatools.zip" ]; then
+            PLATFORM_BUILD=$PLATFORM_REPO_ROOT/out/target/product/$PRODUCT
+        elif [ -d "${ANDROID_PRODUCT_OUT}" ] && [ -f "${ANDROID_PRODUCT_OUT}/otatools.zip" ]; then
+            PLATFORM_BUILD="${ANDROID_PRODUCT_OUT}"
+        else
+            PLATFORM_BUILD=
+        fi
+    fi
+fi
+
+if [[ "$SYSTEM_BUILD" == ab://* ]]; then
+    print_warn "System build is not supoort yet" "$LINENO"
+elif [ ! -z "$SYSTEM_BUILD" ] && [ -d "$SYSTEM_BUILD" ]; then
+    print_warn "System build is not supoort yet" "$LINENO"
+    # Get GSI build
+    cd "$SYSTEM_BUILD"
+    SYSTEM_REPO_LIST_OUT=$(repo list 2>&1)
+    if [[ "$SYSTEM_REPO_LIST_OUT" != "error"* ]]; then
+        go_to_repo_root "$PWD"
+        if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
+            find_repo
+        fi
+        if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != "_arm64" ]]; then
+            set_platform_repo "aosp_arm64"
+            if [ "$SKIP_BUILD" = false ] ; then
+                build_platform
+            fi
+            SYSTEM_BUILD="${ANDROID_PRODUCT_OUT}/system.img"
+        fi
+    fi
+fi
+
+if [[ "$KERNEL_BUILD" == ab://* ]]; then
+    IFS='/' read -ra array <<< "$KERNEL_BUILD"
+    KERNEL_VERSION=$(echo "${array[2]}" | sed "s/aosp_kernel-common-//g")
+    IFS='-' read -ra array <<< "$KERNEL_VERSION"
+    KERNEL_VERSION="${array[0]}-${array[1]}"
+    print_info "$KERNEL_BUILD is KERNEL_VERSION $KERNEL_VERSION"
+    if [[ "$KERNEL_VERSION" != "$DEVICE_KERNEL_VERSION"* ]] && [ -z "$PLATFORM_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then
+        print_warn "Device $SERIAL_NUMBER is $PRODUCT comes with $DEVICE_KERNEL_STRING kernel. Can't flash GKI directly. \
+Please add a platform build with $KERNEL_VERSION kernel or add vendor kernel build for example by flag \
+-vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
+        print_error "Cannot flash $KERNEL_VERSION GKI to device directly $SERIAL_NUMBER." "$LINENO"
+    fi
+    print_info "Download kernel build $KERNEL_BUILD"
+    if [ -d "$DOWNLOAD_PATH/gki_dir" ]; then
+        rm -rf "$DOWNLOAD_PATH/gki_dir"
+    fi
+    GKI_DIR="$DOWNLOAD_PATH/gki_dir"
+    mkdir -p "$GKI_DIR"
+    cd "$GKI_DIR" || $(print_error "Fail to go to $GKI_DIR" "$LINENO")
+    download_gki_build $KERNEL_BUILD
+    KERNEL_BUILD="$GKI_DIR"
+elif [ ! -z "$KERNEL_BUILD" ] && [ -d "$KERNEL_BUILD" ]; then
+    # Check if kernel repo is provided
+    cd "$KERNEL_BUILD"
+    KERNEL_REPO_LIST_OUT=$(repo list 2>&1)
+    if [[ "$KERNEL_REPO_LIST_OUT" != "error"* ]]; then
+        go_to_repo_root "$PWD"
+        if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
+            find_repo
+        fi
+        if [ "$SKIP_BUILD" = false ] ; then
+            if [ ! -f "common/BUILD.bazel" ]; then
+                # TODO: Add build support to android12 and earlier kernels
+                print_error "bazel build is not supported in $PWD" "$LINENO"
+            else
+                build_ack
+            fi
+        fi
+        KERNEL_BUILD="$PWD/out/kernel_aarch64/dist"
+    elif [ -f "$KERNEL_BUILD/boot*.img" ]; then
+        get_kernel_version_from_boot_image "$KERNEL_BUILD/boot*.img"
+    fi
+fi
+
+if [[ "$VENDOR_KERNEL_BUILD" == ab://* ]]; then
+    print_info "Download vendor kernel build $VENDOR_KERNEL_BUILD" "$LINENO"
+    if [ -d "$DOWNLOAD_PATH/vendor_kernel_dir" ]; then
+        rm -rf "$DOWNLOAD_PATH/vendor_kernel_dir"
+    fi
+    VENDOR_KERNEL_DIR="$DOWNLOAD_PATH/vendor_kernel_dir"
+    mkdir -p "$VENDOR_KERNEL_DIR"
+    cd "$VENDOR_KERNEL_DIR" || $(print_error "Fail to go to $VENDOR_KERNEL_DIR" "$LINENO")
+    download_vendor_kernel_build $VENDOR_KERNEL_BUILD
+    VENDOR_KERNEL_BUILD="$VENDOR_KERNEL_DIR"
+elif [ ! -z "$VENDOR_KERNEL_BUILD" ] && [ -d "$VENDOR_KERNEL_BUILD" ]; then
+    # Check if vendor kernel repo is provided
+    cd "$VENDOR_KERNEL_BUILD"
+    VENDOR_KERNEL_REPO_LIST_OUT=$(repo list 2>&1)
+    if [[ "$VENDOR_KERNEL_REPO_LIST_OUT" != "error"* ]]; then
+        go_to_repo_root "$PWD"
+        if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
+            find_repo
+        fi
+        if [ "$SKIP_BUILD" = false ] ; then
+            if [ ! -f "private/google-modules/soc/gs/BUILD.bazel" ]; then
+                # TODO: Add build support to android12 and earlier kernels
+                print_error "bazel build is not supported in $PWD" "$LINENO"
+            else
+                build_slider
+            fi
+        fi
+        VENDOR_KERNEL_BUILD="$PWD/out/slider/dist"
+    fi
+fi
+
+if [ -z "$PLATFORM_BUILD" ]; then  # No platform build provided
+    if [ -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then  # No kernel or vendor kernel build
+        print_info "KERNEL_BUILD=$KERNEL_BUILD VENDOR_KERNEL_BUILD=$VENDOR_KERNEL_BUILD" "$LINENO"
+        print_error "Nothing to flash" "$LINENO"
+    elif [ -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # Only vendor kernel build
+        print_info "Flash kernel from $VENDOR_KERNEL_BUILD" "$LINENO"
+        flash_vendor_kernel_build
+    elif [ ! -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # Both kernel and vendor kernel builds
+        print_error "Mixing only GKI build & vendor kernel build is not supported. \
+Please add platform build for example -pb ab://git_main/$PRODUCT-trunk_staging-userdebug/latest." "$LINENO"
+    elif [ ! -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then  # Only GKI build
+        gki_build_only_operation
+    fi
+else  # Platform build provided
+    if [ -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then  # No kernel or vendor kernel build
+        print_info "Flash platform build only"
+        flash_platform_build
+    elif [ -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # Vendor kernel build and platform build
+        print_info "Mix vendor kernel and platform build"
+        mixing_build
+        flash_platform_build
+    elif [ ! -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then # GKI build and platform build
+        flash_platform_build
+        get_device_info
+        gki_build_only_operation
+    elif [ ! -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # All three builds provided
+        print_info "Mix GKI kernel, vendor kernel and platform build" "$LINENO"
+        mixing_build
+        flash_platform_build
+    fi
+fi
\ No newline at end of file
diff --git a/tools/launch_cvd.sh b/tools/launch_cvd.sh
new file mode 100755
index 0000000..afb893d
--- /dev/null
+++ b/tools/launch_cvd.sh
@@ -0,0 +1,407 @@
+#!/usr/bin/env bash
+# SPDX-License-Identifier: GPL-2.0
+
+# A handy tool to launch CVD with local build or remote build.
+
+# Constants
+ACLOUD_PREBUILT="prebuilts/asuite/acloud/linux-x86/acloud"
+OPT_SKIP_PRERUNCHECK='--skip-pre-run-check'
+PRODUCT='aosp_cf_x86_64_phone'
+# Color constants
+BOLD="$(tput bold)"
+END="$(tput sgr0)"
+GREEN="$(tput setaf 2)"
+RED="$(tput setaf 198)"
+YELLOW="$(tput setaf 3)"
+BLUE="$(tput setaf 34)"
+
+SKIP_BUILD=false
+GCOV=false
+DEBUG=false
+KASAN=false
+EXTRA_OPTIONS=()
+
+function print_help() {
+    echo "Usage: $0 [OPTIONS]"
+    echo ""
+    echo "This script will build images and launch a Cuttlefish device."
+    echo ""
+    echo "Available options:"
+    echo "  --skip-build          Skip the image build step. Will build by default if in repo."
+    echo "  --gcov                Launch CVD with gcov enabled kernel"
+    echo "  --debug               Launch CVD with debug enabled kernel"
+    echo "  --kasan               Launch CVD with kasan enabled kernel"
+    echo "  -pb <platform_build>, --platform-build=<platform_build>"
+    echo "                        The platform build path. Can be a local path or a remote build"
+    echo "                        as ab://<branch>/<build_target>/<build_id>."
+    echo "                        If not specified, it will use the platform build in the local"
+    echo "                        repo, or the default compatible platform build for the kernel."
+    echo "  -sb <system_build>, --system-build=<system_build>"
+    echo "                        The system build path for GSI testing. Can be a local path or"
+    echo "                        remote build as ab://<branch>/<build_target>/<build_id>."
+    echo "                        If not specified, no system build will be used."
+    echo "  -kb <kernel_build>, --kernel-build=<kernel_build>"
+    echo "                        The kernel build path. Can be a local path or a remote build"
+    echo "                        as ab://<branch>/<build_target>/<build_id>."
+    echo "                        If not specified, it will use the kernel in the local repo."
+    echo "  --acloud-bin=<acloud_bin>"
+    echo "                        The alternative alcoud binary path."
+    echo "  --cf-product=<product_type>"
+    echo "                        The alternative cuttlefish product type for local build."
+    echo "                        Will use default aosp_cf_x86_64_phone if not specified."
+    echo "  --acloud-arg=<acloud_arg>"
+    echo "                        Additional acloud command arg. Can be repeated."
+    echo "                        For example --acloud-arg=--local-instance to launch a local cvd."
+    echo "  -h, --help            Display this help message and exit"
+    echo ""
+    echo "Examples:"
+    echo "$0"
+    echo "$0 --acloud-arg=--local-instance"
+    echo "$0 -pb ab://git_main/aosp_cf_x86_64_phone-userdebug/latest"
+    echo "$0 -pb ~/aosp-main/out/target/product/vsoc_x86_64/"
+    echo "$0 -kb ~/android-mainline/out/virtual_device_x86_64/"
+    echo ""
+    exit 0
+}
+
+function parse_arg() {
+    while test $# -gt 0; do
+        case "$1" in
+            -h|--help)
+                print_help
+                ;;
+            --skip-build)
+                SKIP_BUILD=true
+                shift
+                ;;
+            -pb)
+                shift
+                if test $# -gt 0; then
+                    PLATFORM_BUILD=$1
+                else
+                    print_error "platform build is not specified"
+                fi
+                shift
+                ;;
+            --platform-build=*)
+                PLATFORM_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
+                shift
+                ;;
+            -sb)
+                shift
+                if test $# -gt 0; then
+                    SYSTEM_BUILD=$1
+                else
+                    print_error "system build is not specified"
+                fi
+                shift
+                ;;
+            --system-build=*)
+                SYSTEM_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
+                shift
+                ;;
+            -kb)
+                shift
+                if test $# -gt 0; then
+                    KERNEL_BUILD=$1
+                else
+                    print_error "kernel build path is not specified"
+                fi
+                shift
+                ;;
+            --kernel-build=*)
+                KERNEL_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
+                shift
+                ;;
+            --acloud-arg=*)
+                EXTRA_OPTIONS+=($(echo $1 | sed -e "s/^[^=]*=//g")) # Use array append syntax
+                shift
+                ;;
+            --acloud-bin=*)
+                ACLOUD_BIN=$(echo $1 | sed -e "s/^[^=]*=//g")
+                shift
+                ;;
+            --cf-product=*)
+                PRODUCT=$(echo $1 | sed -e "s/^[^=]*=//g")
+                shift
+                ;;
+            --gcov)
+                GCOV=true
+                shift
+                ;;
+            --debug)
+                DEBUG=true
+                shift
+                ;;
+            --kasan)
+                KASAN=true
+                shift
+                ;;
+            *)
+                print_error "Unsupported flag: $1" >&2
+                shift
+                ;;
+        esac
+    done
+}
+
+function adb_checker() {
+    if ! which adb &> /dev/null; then
+        print_error "adb not found!"
+    fi
+}
+
+function go_to_repo_root() {
+    current_dir="$1"
+    while [ ! -d ".repo" ] && [ "$current_dir" != "/" ]; do
+        current_dir=$(dirname "$current_dir")  # Go up one directory
+        cd "$current_dir"
+    done
+}
+
+function print_info() {
+    echo "[$MY_NAME]: ${GREEN}$1${END}"
+}
+
+function print_warn() {
+    echo "[$MY_NAME]: ${YELLOW}$1${END}"
+}
+
+function print_error() {
+    echo -e "[$MY_NAME]: ${RED}$1${END}"
+    cd $OLD_PWD
+    exit 1
+}
+
+function set_platform_repo () {
+    print_warn "Build target product '${TARGET_PRODUCT}' does not match expected '$1'"
+    local lunch_cli="source build/envsetup.sh && lunch $1"
+    if [ -f "build/release/release_configs/trunk_staging.textproto" ]; then
+        lunch_cli+="-trunk_staging-userdebug"
+    else
+        lunch_cli+="-userdebug"
+    fi
+    print_info "Setup build environment with: $lunch_cli"
+    eval "$lunch_cli"
+}
+
+function find_repo () {
+    manifest_output=$(grep -e "superproject" -e "gs-pixel" -e "private/google-modules/soc/gs" \
+    -e "kernel/common" -e "common-modules/virtual-device" .repo/manifests/default.xml)
+    case "$manifest_output" in
+        *platform/superproject*)
+            PLATFORM_REPO_ROOT="$PWD"
+            PLATFORM_VERSION=$(grep -e "platform/superproject" .repo/manifests/default.xml | \
+            grep -oP 'revision="\K[^"]*')
+            print_info "PLATFORM_REPO_ROOT=$PLATFORM_REPO_ROOT, PLATFORM_VERSION=$PLATFORM_VERSION"
+            if [ -z "$PLATFORM_BUILD" ]; then
+                PLATFORM_BUILD="$PLATFORM_REPO_ROOT"
+            fi
+            ;;
+        *kernel/superproject*)
+            if [[ "$manifest_output" == *common-modules/virtual-device* ]]; then
+                CF_KERNEL_REPO_ROOT="$PWD"
+                CF_KERNEL_VERSION=$(grep -e "common-modules/virtual-device" \
+                .repo/manifests/default.xml | grep -oP 'revision="\K[^"]*')
+                print_info "CF_KERNEL_REPO_ROOT=$CF_KERNEL_REPO_ROOT, \
+                CF_KERNEL_VERSION=$CF_KERNEL_VERSION"
+                if [ -z "$KERNEL_BUILD" ]; then
+                    KERNEL_BUILD="$CF_KERNEL_REPO_ROOT"
+                fi
+            fi
+            ;;
+        *)
+            print_warn "Unexpected manifest output. Could not determine repository type."
+            ;;
+    esac
+}
+
+function rebuild_platform () {
+    build_cmd="m -j12"
+    print_warn "Flag --skip-build is not set. Rebuilt images at $PWD with: $build_cmd"
+    eval $build_cmd
+    exit_code=$?
+    if [ $exit_code -eq 0 ]; then
+        if [ -f "${ANDROID_PRODUCT_OUT}/system.img" ]; then
+            print_info "$build_cmd succeeded"
+        else
+            print_error "${ANDROID_PRODUCT_OUT}/system.img doesn't exist"
+        fi
+    else
+        print_warn "$build_cmd returned exit_code $exit_code or ${ANDROID_PRODUCT_OUT}/system.img is not found"
+        print_error "$build_cmd failed"
+    fi
+}
+
+adb_checker
+
+LOCAL_REPO=
+
+OLD_PWD=$PWD
+MY_NAME=$0
+
+parse_arg "$@"
+
+FULL_COMMAND_PATH=$(dirname "$PWD/$0")
+REPO_LIST_OUT=$(repo list 2>&1)
+if [[ "$REPO_LIST_OUT" == "error"* ]]; then
+    print_error "Current path $PWD is not in an Android repo. Change path to repo root."
+    go_to_repo_root "$FULL_COMMAND_PATH"
+    print_info "Changed path to $PWD"
+else
+    go_to_repo_root "$PWD"
+fi
+
+REPO_ROOT_PATH="$PWD"
+
+find_repo
+
+if [ "$SKIP_BUILD" = false ] && [ ! -z "$PLATFORM_BUILD" ] && [[ "$PLATFORM_BUILD" != ab://* ]] \
+&& [ -d "$PLATFORM_BUILD" ]; then
+    # Check if PLATFORM_BUILD is an Android platform repo, if yes rebuild
+    cd "$PLATFORM_BUILD"
+    PLATFORM_REPO_LIST_OUT=$(repo list 2>&1)
+    if [[ "$PLATFORM_REPO_LIST_OUT" != "error"* ]]; then
+        go_to_repo_root "$PWD"
+        if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != "$PRODUCT" ]]; then
+            set_platform_repo $PRODUCT
+            rebuild_platform
+            PLATFORM_BUILD=${ANDROID_PRODUCT_OUT}
+        fi
+    fi
+fi
+
+if [ "$SKIP_BUILD" = false ] && [ ! -z "$SYSTEM_BUILD" ] && [[ "$SYSTEM_BUILD" != ab://* ]] \
+&& [ -d "$SYSTEM_BUILD" ]; then
+    # Get GSI build
+    cd "$SYSTEM_BUILD"
+    SYSTEM_REPO_LIST_OUT=$(repo list 2>&1)
+    if [[ "$SYSTEM_REPO_LIST_OUT" != "error"* ]]; then
+        go_to_repo_root "$PWD"
+        if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != "aosp_x86_64" ]]; then
+            set_platform_repo "aosp_x86_64"
+            rebuild_platform
+            SYSTEM_BUILD="${ANDROID_PRODUCT_OUT}/system.img"
+        fi
+    fi
+fi
+
+if [ "$SKIP_BUILD" = false ] && [ ! -z "$KERNEL_BUILD" ] && [[ "$KERNEL_BUILD" != ab://* ]] \
+&& [ -d "$KERNEL_BUILD" ]; then
+    # Check if kernel repo is provided, if yes rebuild
+    cd "$KERNEL_BUILD"
+    KERNEL_REPO_LIST_OUT=$(repo list 2>&1)
+    if [[ "$KERNEL_REPO_LIST_OUT" != "error"* ]]; then
+        go_to_repo_root "$PWD"
+        if [ ! -f "common-modules/virtual-device/BUILD.bazel" ]; then
+            # TODO: Add build support to android12 and earlier kernels
+            print_error "bazel build common-modules/virtual-device is not supported in this kernel tree"
+        fi
+        KERNEL_VERSION=$(grep -e "common-modules/virtual-device" .repo/manifests/default.xml | grep -oP 'revision="\K[^"]*')
+        # Build a new kernel
+        build_cmd="tools/bazel run --config=fast"
+        if [ "$GCOV" = true ]; then
+            build_cmd+=" --gcov"
+        fi
+        if [ "$DEBUG" = true ]; then
+            build_cmd+=" --debug"
+        fi
+        if [ "$KASAN" = true ]; then
+            build_cmd+=" --kasan"
+        fi
+        build_cmd+=" //common-modules/virtual-device:virtual_device_x86_64_dist"
+        print_warn "Flag --skip-build is not set. Rebuild the kernel with: $build_cmd."
+        eval $build_cmd
+        exit_code=$?
+        if [ $exit_code -eq 0 ]; then
+            print_info "$build_cmd succeeded"
+        else
+            print_error "$build_cmd failed"
+        fi
+        KERNEL_BUILD="$PWD/out/virtual_device_x86_64/dist"
+    fi
+fi
+
+
+if [ -z "$ACLOUD_BIN" ] || ! [ -x "$ACLOUD_BIN" ]; then
+    local output=$(which acloud 2>&1)
+    if [ -z "$output" ]; then
+        print_info "Use acloud binary from $ACLOUD_PREBUILT"
+        ACLOUD_BIN="$ACLOUD_PREBUILT"
+    else
+        print_info "Use acloud binary from $output"
+        ACLOUD_BIN="$output"
+    fi
+
+    # Check if the newly found or prebuilt ACLOUD_BIN is executable
+    if ! [ -x "$ACLOUD_BIN" ]; then
+        print_error "$ACLOUD_BIN is not executable"
+    fi
+fi
+
+acloud_cli="$ACLOUD_BIN create"
+EXTRA_OPTIONS+=("$OPT_SKIP_PRERUNCHECK")
+
+# Add in branch if not specified
+
+if [ -z "$PLATFORM_BUILD" ]; then
+    print_warn "Platform build is not specified, will use the latest aosp-main build."
+    acloud_cli+=' --branch aosp-main'
+elif [[ "$PLATFORM_BUILD" == ab://* ]]; then
+    IFS='/' read -ra array <<< "$PLATFORM_BUILD"
+    acloud_cli+=" --branch ${array[2]}"
+
+    # Check if array[3] exists before using it
+    if [ ${#array[@]} -ge 3 ] && [ ! -z "${array[3]}" ]; then
+        acloud_cli+=" --build-target ${array[3]}"
+
+        # Check if array[4] exists and is not 'latest' before using it
+        if [ ${#array[@]} -ge 4 ] && [ ! -z "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
+            acloud_cli+=" --build-id ${array[4]}"
+        fi
+    fi
+else
+    acloud_cli+=" --local-image $PLATFORM_BUILD"
+fi
+
+if [ -z "$KERNEL_BUILD" ]; then
+    print_warn "Flag --kernel-build is not set, will not launch Cuttlefish with different kernel."
+elif [[ "$KERNEL_BUILD" == ab://* ]]; then
+    IFS='/' read -ra array <<< "$KERNEL_BUILD"
+    acloud_cli+=" --kernel-branch ${array[2]}"
+
+    # Check if array[3] exists before using it
+    if [ ${#array[@]} -ge 3 ] && [ ! -z "${array[3]}" ]; then
+        acloud_cli+=" --kernel-build-target ${array[3]}"
+
+        # Check if array[4] exists and is not 'latest' before using it
+        if [ ${#array[@]} -ge 4 ] && [ ! -z "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
+            acloud_cli+=" --kernel-build-id ${array[4]}"
+        fi
+    fi
+else
+    acloud_cli+=" --local-kernel-image $KERNEL_BUILD"
+fi
+
+if [ -z "$SYSTEM_BUILD" ]; then
+    print_warn "System build is not specified, will not launch Cuttlefish with GSI mixed build."
+elif [[ "$SYSTEM_BUILD" == ab://* ]]; then
+    IFS='/' read -ra array <<< "$SYSTEM_BUILD"
+    acloud_cli+=" --system-branch ${array[2]}"
+
+     # Check if array[3] exists before using it
+    if [ ${#array[@]} -ge 3 ] && [ ! -z "${array[3]}" ]; then
+        acloud_cli+=" --system-build-target ${array[3]}"
+
+        # Check if array[4] exists and is not 'latest' before using it
+        if [ ${#array[@]} -ge 4 ] && [ ! -z "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
+            acloud_cli+=" --system-build-id ${array[4]}"
+        fi
+    fi
+else
+    acloud_cli+=" --local-system-image $SYSTEM_BUILD"
+fi
+
+acloud_cli+=" ${EXTRA_OPTIONS[@]}"
+print_info "Launch CVD with command: $acloud_cli"
+eval "$acloud_cli"
diff --git a/tools/run_test_only.sh b/tools/run_test_only.sh
new file mode 100755
index 0000000..0c2d568
--- /dev/null
+++ b/tools/run_test_only.sh
@@ -0,0 +1,392 @@
+#!/usr/bin/env bash
+# SPDX-License-Identifier: GPL-2.0
+
+#
+# A simple script to run test with Tradefed.
+#
+
+KERNEL_TF_PREBUILT=prebuilts/tradefed/filegroups/tradefed/tradefed.sh
+PLATFORM_TF_PREBUILT=tools/tradefederation/prebuilts/filegroups/tradefed/tradefed.sh
+JDK_PATH=prebuilts/jdk/jdk11/linux-x86
+PLATFORM_JDK_PATH=prebuilts/jdk/jdk21/linux-x86
+DEFAULT_LOG_DIR=$PWD/out/test_logs/$(date +%Y%m%d_%H%M%S)
+DOWNLOAD_PATH="/tmp/downloaded_tests"
+GCOV=false
+FETCH_SCRIPT="kernel/tests/tools/fetch_artifact.sh"
+TRADEFED=
+TEST_ARGS=()
+TEST_DIR=
+TEST_NAMES=()
+
+BOLD="$(tput bold)"
+END="$(tput sgr0)"
+GREEN="$(tput setaf 2)"
+RED="$(tput setaf 198)"
+YELLOW="$(tput setaf 3)"
+BLUE="$(tput setaf 34)"
+
+function adb_checker() {
+    if ! which adb &> /dev/null; then
+        echo -e "\n${RED}Adb not found!${END}"
+    fi
+}
+
+function go_to_repo_root() {
+    current_dir="$1"
+    while [ ! -d ".repo" ] && [ "$current_dir" != "/" ]; do
+        current_dir=$(dirname "$current_dir")  # Go up one directory
+        cd "$current_dir"
+    done
+}
+
+function print_info() {
+    echo "[$MY_NAME]: ${GREEN}$1${END}"
+}
+
+function print_warn() {
+    echo "[$MY_NAME]: ${YELLOW}$1${END}"
+}
+
+function print_error() {
+    echo -e "[$MY_NAME]: ${RED}$1${END}"
+    cd $OLD_PWD
+    exit 1
+}
+
+function print_help() {
+    echo "Usage: $0 [OPTIONS]"
+    echo ""
+    echo "This script will run tests on an Android device."
+    echo ""
+    echo "Available options:"
+    echo "  -s <serial_number>, --serial=<serial_number>"
+    echo "                        The device serial number to run tests with."
+    echo "  -td <test_dir>, --test-dir=<test_dir>"
+    echo "                        The test artifact file name or directory path."
+    echo "                        Can be a local file or directory or a remote file"
+    echo "                        as ab://<branch>/<build_target>/<build_id>/<file_name>."
+    echo "                        If not specified, it will use the tests in the local"
+    echo "                        repo."
+    echo "  -tl <test_log_dir>, --test_log=<test_log_dir>"
+    echo "                        The test log dir. Use default out/test_logs if not specified."
+    echo "  -ta <extra_arg>, --extra-arg=<extra_arg>"
+    echo "                        Additional tradefed command arg. Can be repeated."
+    echo "  -t <test_name>, --test=<test_name>  The test name. Can be repeated."
+    echo "                        If test is not specified, no tests will be run."
+    echo "  -tf <tradefed_binary_path>, --tradefed-bin=<tradefed_binary_path>"
+    echo "                        The alternative tradefed binary to run test with."
+    echo "  --skip-build          Skip the platform build step. Will build by default if in repo."
+    echo "  --gcov                Collect coverage data from the test result"
+    echo "  -h, --help            Display this help message and exit"
+    echo ""
+    echo "Examples:"
+    echo "$0 -s 127.0.0.1:33847 -t selftests"
+    echo "$0 -s 1C141FDEE003FH -t selftests:kselftest_binderfs_binderfs_test"
+    echo "$0 -s 127.0.0.1:33847 -t CtsAccessibilityTestCases -t CtsAccountManagerTestCases"
+    echo "$0 -s 127.0.0.1:33847 -t CtsAccessibilityTestCases -t CtsAccountManagerTestCases \
+-td ab://aosp-main/test_suites_x86_64-trunk_staging/latest/android-cts.zip"
+    echo "$0 -s 1C141FDEE003FH -t CtsAccessibilityTestCases -t CtsAccountManagerTestCases \
+-td ab://git_main/test_suites_arm64-trunk_staging/latest/android-cts.zip"
+    echo "$0 -s 1C141FDEE003FH -t CtsAccessibilityTestCases -td <your_path_to_platform_repo>"
+    echo ""
+    exit 0
+}
+
+function set_platform_repo () {
+    print_warn "Build target product '${TARGET_PRODUCT}' does not match device product '$PRODUCT'"
+    lunch_cli="source build/envsetup.sh && "
+    if [ -f "build/release/release_configs/trunk_staging.textproto" ]; then
+        lunch_cli+="lunch $PRODUCT-trunk_staging-$BUILD_TYPE"
+    else
+        lunch_cli+="lunch $PRODUCT-trunk_staging-$BUILD_TYPE"
+    fi
+    print_info "Setup build environment with: $lunch_cli"
+    eval "$lunch_cli"
+}
+
+function run_test_in_platform_repo () {
+    if [ -z "${TARGET_PRODUCT}" ]; then
+        set_platform_repo
+    elif [[ "${TARGET_PRODUCT}" != *"x86"* && "${PRODUCT}" == *"x86"* ]] || \
+       [[ "${TARGET_PRODUCT}" == *"x86"* && "${PRODUCT}" != *"x86"* ]]; then
+       set_platform_repo
+    fi
+    eval atest " ${TEST_NAMES[@]}" -s "$SERIAL_NUMBER"
+    exit_code=$?
+    cd $OLD_PWD
+    exit $exit_code
+}
+
+OLD_PWD=$PWD
+MY_NAME=$0
+
+while test $# -gt 0; do
+    case "$1" in
+        -h|--help)
+            print_help
+            ;;
+        -s)
+            shift
+            if test $# -gt 0; then
+                SERIAL_NUMBER=$1
+            else
+                print_error "device serial is not specified"
+            fi
+            shift
+            ;;
+        --serial*)
+            SERIAL_NUMBER=$(echo $1 | sed -e "s/^[^=]*=//g")
+            shift
+            ;;
+        -tl)
+            shift
+            if test $# -gt 0; then
+                LOG_DIR=$1
+            else
+                print_error "test log directory is not specified"
+            fi
+            shift
+            ;;
+        --test-log*)
+            LOG_DIR=$(echo $1 | sed -e "s/^[^=]*=//g")
+            shift
+            ;;
+        -td)
+            shift
+            if test $# -gt 0; then
+                TEST_DIR=$1
+            else
+                print_error "test directory is not specified"
+            fi
+            shift
+            ;;
+        --test-dir*)
+            TEST_DIR=$(echo $1 | sed -e "s/^[^=]*=//g")
+            shift
+            ;;
+        -ta)
+            shift
+            if test $# -gt 0; then
+                TEST_ARGS+=$1
+            else
+                print_error "test arg is not specified"
+            fi
+            shift
+            ;;
+        --test-arg*)
+            TEST_ARGS+=$(echo $1 | sed -e "s/^[^=]*=//g")
+            shift
+            ;;
+        -t)
+            shift
+            if test $# -gt 0; then
+                TEST_NAMES+=$1
+            else
+                print_error "test name is not specified"
+            fi
+            shift
+            ;;
+        --test*)
+            TEST_NAMES+=$1
+            shift
+            ;;
+        -tf)
+            shift
+            if test $# -gt 0; then
+                TRADEFED=$1
+            else
+                print_error "tradefed binary is not specified"
+            fi
+            shift
+            ;;
+        --tradefed-bin*)
+            TRADEFED=$(echo $1 | sed -e "s/^[^=]*=//g")
+            shift
+            ;;
+        --gcov)
+            GCOV=true
+            shift
+            ;;
+        *)
+            ;;
+    esac
+done
+
+# Ensure SERIAL_NUMBER is provided
+if [ -z "$SERIAL_NUMBER" ]; then
+    print_error "Device serial is not provided with flag -s <serial_number>."
+fi
+
+# Ensure TEST_NAMES is provided
+if [ -z "$TEST_NAMES" ]; then
+    print_error "No test is specified with flag -t <test_name>."
+fi
+
+FULL_COMMAND_PATH=$(dirname "$PWD/$0")
+REPO_LIST_OUT=$(repo list 2>&1)
+if [[ "$REPO_LIST_OUT" == "error"* ]]; then
+    print_warn "Current path $PWD is not in an Android repo. Change path to repo root."
+    go_to_repo_root "$FULL_COMMAND_PATH"
+    print_info "Changed path to $PWD"
+else
+    go_to_repo_root "$PWD"
+fi
+
+REPO_ROOT_PATH="$PWD"
+FETCH_SCRIPT="$REPO_ROOT_PATH/$FETCH_SCRIPT"
+
+adb_checker
+
+# Set default LOG_DIR if not provided
+if [ -z "$LOG_DIR" ]; then
+    LOG_DIR="$DEFAULT_LOG_DIR"
+fi
+
+BOARD=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.board)
+ABI=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.cpu.abi)
+PRODUCT=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.product)
+BUILD_TYPE=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.type)
+
+if [ -z "$TEST_DIR" ]; then
+    print_warn "Flag -td <test_dir> is not provided. Will use the default test directory"
+    if [[ "$REPO_LIST_OUT" == *"vendor/google/tools"* ]]; then
+        # In the platform repo
+        print_info "Run test with atest"
+        run_test_in_platform_repo
+    elif [[ "$BOARD" == "cutf"* ]] && [[ "$REPO_LIST_OUT" == *"common-modules/virtual-device"* ]]; then
+        # In the android kernel repo
+        if [[ "$ABI" == "arm64"* ]]; then
+            TEST_DIR="$REPO_ROOT_PATH/out/virtual_device_aarch64/dist/tests.zip"
+        elif [[ "$ABI" == "x86_64"* ]]; then
+            TEST_DIR="$REPO_ROOT_PATH/out/virtual_device_x86_64/dist/tests.zip"
+        else
+            print_error "No test builds for $ABI Cuttlefish in $REPO_ROOT_PATH"
+        fi
+    elif [[ "$BOARD" == "raven"* || "$BOARD" == "oriole"* ]] && [[ "$REPO_LIST_OUT" == *"private/google-modules/display"* ]]; then
+        TEST_DIR="$REPO_ROOT_PATH/out/slider/dist/tests.zip"
+    elif [[ "$ABI" == "arm64"* ]] && [[ "$REPO_LIST_OUT" == *"kernel/common"* ]]; then
+        TEST_DIR="$REPO_ROOT_PATH/out/kernel_aarch64/dist/tests.zip"
+    else
+        print_error "No test builds for $ABI $BOARD in $REPO_ROOT_PATH"
+    fi
+fi
+
+TEST_FILTERS=
+for i in "$TEST_NAMES"; do
+    TEST_NAME=$(echo $i | sed "s/:/ /g")
+    TEST_FILTERS+=" --include-filter '$TEST_NAME'"
+done
+
+if [[ "$TEST_DIR" == ab://* ]]; then
+    # Download test_file if it's remote file ab://
+    if [ -d "$DOWNLOAD_PATH" ]; then
+        rm -rf "$DOWNLOAD_PATH"
+    fi
+    mkdir -p "$DOWNLOAD_PATH" || $(print_error "Fail to create directory $DOWNLOAD_PATH")
+    cd $DOWNLOAD_PATH || $(print_error "Fail to go to $DOWNLOAD_PATH")
+    file_name=${TEST_DIR##*/}
+    eval "$FETCH_SCRIPT $TEST_DIR"
+    exit_code=$?
+    if [ $exit_code -eq 0 ]; then
+        print_info "$TEST_DIR is downloaded succeeded"
+    else
+        print_error "Failed to download $TEST_DIR"
+    fi
+
+    file_name=$(ls $file_name)
+    # Check if the download was successful
+    if [ ! -f "${file_name}" ]; then
+        print_error "Failed to download ${file_name}"
+    fi
+    TEST_DIR="$DOWNLOAD_PATH/$file_name"
+elif [ ! -z "$TEST_DIR" ]; then
+    if [ -d $TEST_DIR ]; then
+        test_file_path=$TEST_DIR
+    elif [ -f "$TEST_DIR" ]; then
+        test_file_path=$(dirname "$TEST_DIR")
+    else
+        print_error "$TEST_DIR is neither a directory or file"
+    fi
+    cd "$test_file_path" || $(print_error "Failed to go to $test_file_path")
+    TEST_REPO_LIST_OUT=$(repo list 2>&1)
+    if [[ "$TEST_REPO_LIST_OUT" == "error"* ]]; then
+        print_info "Test path $test_file_path is not in an Android repo. Will use $TEST_DIR directly."
+    elif [[ "$TEST_REPO_LIST_OUT" == *"vendor/google/tools"* ]]; then
+        # Test_dir is from the platform repo
+        print_info "Test_dir $TEST_DIR is from Android platform repo. Run test with atest"
+        go_to_repo_root "$PWD"
+        run_test_in_platform_repo
+    fi
+fi
+
+cd "$REPO_ROOT_PATH"
+if [[ "$TEST_DIR" == *".zip"* ]]; then
+    filename=${TEST_DIR##*/}
+    new_test_dir="$REPO_ROOT_PATH/out/tests"
+    if [ ! -d "$new_test_dir" ]; then
+        mkdir -p "$new_test_dir" || $(print_error "Failed to make directory $new_test_dir")
+    fi
+    unzip -oq "$TEST_DIR" -d "$new_test_dir" || $(print_error "Failed to unzip $TEST_DIR to $new_test_dir")
+    case $filename in
+        "android-vts.zip" | "android-cts.zip")
+        new_test_dir+="/$(echo $filename | sed "s/.zip//g")"
+        ;;
+        *)
+        ;;
+    esac
+    TEST_DIR="$new_test_dir" # Update TEST_DIR to the unzipped directory
+fi
+
+print_info "Will run tests with test artifacts in $TEST_DIR"
+
+if [ -f "${TEST_DIR}/tools/vts-tradefed" ]; then
+    TRADEFED="${TEST_DIR}/tools/vts-tradefed"
+    print_info "Will run tests with vts-tradefed from $TRADEFED"
+    tf_cli="$TRADEFED run commandAndExit \
+    vts --skip-device-info --log-level-display info --log-file-path=$LOG_DIR \
+    $TEST_FILTERS -s $SERIAL_NUMBER"
+elif [ -f "${TEST_DIR}/tools/cts-tradefed" ]; then
+    TRADEFED="${TEST_DIR}/tools/cts-tradefed"
+    print_info "Will run tests with cts-tradefed from $TRADEFED"
+    tf_cli="$TRADEFED run commandAndExit cts --skip-device-info \
+    --log-level-display info --log-file-path=$LOG_DIR \
+    $TEST_FILTERS -s $SERIAL_NUMBER"
+elif [ -f "${ANDROID_HOST_OUT}/bin/tradefed.sh" ] ; then
+    TRADEFED="${ANDROID_HOST_OUT}/bin/tradefed.sh"
+    print_info "Use the tradefed from the local built path $TRADEFED"
+    tf_cli="$TRADEFED run commandAndExit template/local_min \
+    --log-level-display info --log-file-path=$LOG_DIR \
+    --template:map test=suite/test_mapping_suite  --tests-dir=$TEST_DIR\
+    $TEST_FILTERS -s $SERIAL_NUMBER"
+elif [ -f "$PLATFORM_TF_PREBUILT" ]; then
+    TRADEFED="JAVA_HOME=$PLATFORM_JDK_PATH PATH=$PLATFORM_JDK_PATH/bin:$PATH $PLATFORM_TF_PREBUILT"
+    print_info "Local Tradefed is not built yet. Use the prebuilt from $PLATFORM_TF_PREBUILT"
+    tf_cli="$TRADEFED run commandAndExit template/local_min \
+    --log-level-display info --log-file-path=$LOG_DIR \
+    --template:map test=suite/test_mapping_suite  --tests-dir=$TEST_DIR\
+    $TEST_FILTERS -s $SERIAL_NUMBER"
+elif [ -f "$KERNEL_TF_PREBUILT" ]; then
+    TRADEFED="JAVA_HOME=$JDK_PATH PATH=$JDK_PATH/bin:$PATH $KERNEL_TF_PREBUILT"
+    print_info "Use the tradefed prebuilt from $KERNEL_TF_PREBUILT"
+    tf_cli="$TRADEFED run commandAndExit template/local_min \
+    --log-level-display info --log-file-path=$LOG_DIR \
+    --template:map test=suite/test_mapping_suite  --tests-dir=$TEST_DIR\
+    $TEST_FILTERS -s $SERIAL_NUMBER"
+# No Tradefed found
+else
+    print_error "Can not find Tradefed binary. Please use flag -tf to specify the binary path."
+fi
+
+# Construct the TradeFed command
+
+# Add GCOV options if enabled
+if $GCOV; then
+    tf_cli+=" --coverage --coverage-toolchain GCOV_KERNEL --auto-collect GCOV_KERNEL_COVERAGE"
+fi
+
+# Evaluate the TradeFed command with extra arguments
+print_info "Run test with: $tf_cli" "${EXTRA_ARGS[*]}"
+eval "$tf_cli" "${EXTRA_ARGS[*]}"
+exit_code=$?
+cd $OLD_PWD
+exit $exit_code
```

