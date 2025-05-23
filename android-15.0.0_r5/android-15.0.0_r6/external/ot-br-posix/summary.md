```
7f6c3651: support discovering NAT64 prefix from AIL (Handa Wang <handaw@google.com>)
20d05679: Refactor setting infra link state (Handa Wang <handaw@google.com>)
ccc0b1bc: Process the CLI command from AIDL API (Yang Song <yangsongcn@google.com>)
91a377e4: Include NAT64 state and packet counters in telemetry data (Handa Wang <handaw@google.com>)
378125b5: Get network interface index when service is resolved. (Yang Sun <sunytt@google.com>)
918760bc: [test] Add ThreadNetworkIntegrationTests to presubmit (Yang Sun <sunytt@google.com>)
3be5764d: Fix the build error of openthread sync (Handa Wang <handaw@google.com>)
3baf1600: submodule: bump third_party/openthread/repo from `01cb5b0` to `db63932` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
e8ea2d32: submodule: bump third_party/openthread/repo from `e19c775` to `01cb5b0` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
9f867251: [application] simply fdset update (#2469) (Li Cao <irvingcl@google.com>)
b827539a: submodule: bump third_party/openthread/repo from `d60aaab` to `e19c775` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
3874d96d: [posix] add netif TUN Ip6 Sending (#2452) (Li Cao <irvingcl@google.com>)
2a85a7b4: submodule: bump third_party/openthread/repo from `f9349c1` to `d60aaab` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
795f5129: [posix] add netif TUN Ip6Receive (#2455) (Li Cao <irvingcl@google.com>)
22789a04: submodule: bump third_party/openthread/repo from `45c5fe4` to `f9349c1` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
27ad68cc: Make java_sdk_library dependencies explicit (Jihoon Kang <jihoonkang@google.com>)
63584c5e: [telemetry] remove uploading epskc_state and border_agent_state (#2463) (Yang Sun <sunytt@google.com>)
590d028e: submodule: bump third_party/openthread/repo from `706013f` to `45c5fe4` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
180e27b2: [ncp] integrate netif multicast address update (#2460) (Li Cao <irvingcl@google.com>)
5ff6ef7e: submodule: bump third_party/openthread/repo from `abb6934` to `706013f` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
454da7f6: Split the infra link state and configuration (Handa Wang <handaw@google.com>)
9ec7d631: [ncp] integrate netif isUp state update (#2459) (Li Cao <irvingcl@google.com>)
5444cfd0: submodule: bump third_party/openthread/repo from `1c5ad34` to `abb6934` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
3a2110ef: Replace dataset command with detail dataset field command to otdaemon_se... (Tony Zhou <tonyzhou@google.com>)
47869674: Disable telemetry retrieval when Thread stack is disabled. (Tony Zhou <tonyzhou@google.com>)
6ab1a475: [posix] add netif SetState (#2453) (Li Cao <irvingcl@google.com>)
2884b3d8: [cmake] allow overriding TCP and DNS_CLIENT_OVER_TCP features for 1.4 ce... (Suvesh Pratapa <66088488+suveshpratapa@users.nor...)
626b3f58: [posix] add multicast address update in netif module (#2447) (Li Cao <irvingcl@google.com>)
a8f89be6: [telemetry] add support for getting border agent telemetry data (#2439) (Yang Sun <sunytt@google.com>)
544908ee: submodule: bump third_party/openthread/repo from `1a2d5f0` to `1c5ad34` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
ab77091b: [Thread] rename BorderRouterConfiguration ot OtDaemonConfiguration (Kangping Dong <wgtdkp@google.com>)
f2c799d1: submodule: bump third_party/openthread/repo from `24e9306` to `1a2d5f0` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
5f07c07b: submodule: bump third_party/openthread/repo from `afac808` to `24e9306` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
3d663e18: [ncp] use `SendCommand` with no `va_args` requirement to avoid compilati... (Suvesh Pratapa <66088488+suveshpratapa@users.nor...)
1f6390eb: submodule: bump third_party/openthread/repo from `fb7b457` to `afac808` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
95d29752: [ncp] integrate netif unicast address update (#2437) (Li Cao <irvingcl@google.com>)
861ddf20: [controller] add schedule migration API (#2435) (Li Cao <irvingcl@google.com>)
791828cd: [epskc] enable by default for Thread 1.4 (#2429) (Mia Yang <145632982+mia1yang@users.noreply.githu...)
45309ea5: [tests] enhance the ncp mode test script (#2438) (Li Cao <irvingcl@google.com>)
5e7ecc09: submodule: bump third_party/openthread/repo from `e455866` to `fb7b457` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
6fcf269e: submodule: bump third_party/openthread/repo from `5edc367` to `e455866` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
cce147b9: [ncp] update implementation of NcpSpinel DatasetSetActiveTlvs to transpo... (Li Cao <irvingcl@google.com>)
b66cabfa: [posix] add unicast address update in netif module (#2431) (Li Cao <irvingcl@google.com>)
5f72d8b0: submodule: bump third_party/openthread/repo from `509596f` to `5edc367` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
29a20955: submodule: bump third_party/openthread/repo from `df757ba` to `509596f` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
193d5896: [dbus] add dbus Migrate API for NCP (#2427) (Li Cao <irvingcl@google.com>)
67fc25aa: [ot-daemon] change ot-daemon constructor to accommodate fuzzer test (Kangping Dong <wgtdkp@google.com>)
81064521: convert the max power value from `int` to `int16_t` (Zhanglong Xia <zhanglongxia@google.com>)
f93a3b8e: [posix] set addr gen mode to none on linux (#2419) (Li Cao <irvingcl@google.com>)
d89373f8: [epskc] add feature flag list to enable/disble BA ePSKc feature (#2423) (Mia Yang <145632982+mia1yang@users.noreply.githu...)
ef4cbe8e: submodule: bump third_party/openthread/repo from `d034b5c` to `df757ba` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
b15b9dd7: [dbus] add APIs to start/stop ePSKc mode (#2407) (Mia Yang <145632982+mia1yang@users.noreply.githu...)
fa6ab40e: [epskc] add support for multiple ephemeral key callbacks (#2424) (Yang Sun <sunytt@google.com>)
1dc6c81d: [epskc] add support for multiple ephemeral key callbacks (#2424) (Yang Sun <sunytt@google.com>)
4e16cf6e: [Thread] use default Thread radio URL in ot-daemon fuzzer (Kangping Dong <wgtdkp@google.com>)
92ac6cb6: [ncp] update the frame handling of ncp spinel (#2416) (Li Cao <irvingcl@google.com>)
43ce83a0: [version] update 1.4 to 1.4.0 for conformance (#2415) (Rongli Sun <rongli@google.com>)
655edcc6: submodule: bump third_party/openthread/repo from `19dadd9` to `d034b5c` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
442c09d6: create a symbol link script/make-aosp-pretty.sh (Handa Wang <handaw@google.com>)
28fb2d9c: format AIDL and java files (Handa Wang <handaw@google.com>)
f33a3425: make BorderRouterConfiguration @JavaOnlyImmutable (Handa Wang <handaw@google.com>)
f2fcf8b5: submodule: bump third_party/openthread/repo from `c5ad131` to `19dadd9` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
f0afe6e9: [posix] add posix netif module (#2410) (Li Cao <irvingcl@google.com>)
a71358af: [openwrt] disable NAT64 on OpenWRT (#2421) (Handa Wang <7058128+superwhd@users.noreply.githu...)
93b32784: [NAT64] implement otPlatInfraIfDiscoverNat64Prefix (Handa Wang <handaw@google.com>)
9847922e: [ePSKc] runtime enable/disable EphemeralKey feature (#2368) (Mia Yang <145632982+mia1yang@users.noreply.githu...)
17c58396: submodule: bump third_party/openthread/repo from `03113e8` to `c5ad131` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
1532c829: make BorderRouterConfiguration copyable (Handa Wang <handaw@google.com>)
da1f8670: submodule: bump third_party/openthread/repo from `a759a4a` to `03113e8` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
347d7e7b: submodule: bump third_party/openthread/repo from `5493815` to `a759a4a` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
32a34c12: [controller] add join and leave api (#2355) (Li Cao <irvingcl@google.com>)
f59b0f55: [tests] enhance the test script of ncp mode to speed up local developing... (Li Cao <irvingcl@google.com>)
e25258e9: submodule: bump third_party/openthread/repo from `e913c7d` to `5493815` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
87b671d5: [host] add network properties class (#2387) (Li Cao <irvingcl@google.com>)
1f332d4f: submodule: bump third_party/openthread/repo from `7096928` to `e913c7d` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
9698510c: submodule: bump third_party/openthread/repo from `2cc0798` to `7096928` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
6f3dfdc7: submodule: bump third_party/openthread/repo from `af18582` to `2cc0798` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
262c2fb7: [ncp] fix a compilation issue in `ncp_spinel.cpp` (#2395) (Suvesh Pratapa <66088488+suveshpratapa@users.nor...)
d2b70e74: [clang-format] accept different patch versions of `clang-format` (#2402) (Suvesh Pratapa <66088488+suveshpratapa@users.nor...)
4dd1f42d: submodule: bump third_party/openthread/repo from `d0fbfb8` to `af18582` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
2325a356: [dbus] fix `u_int16_t` typo (#2399) (GuoYuchao <yuchao.guo@hoorii.io>)
aea7c7c1: submodule: bump third_party/openthread/repo from `4e3483c` to `d0fbfb8` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
1cbe2cc6: [telemetry] add `peer_br_count` in InfraLinkInfo (#2361) (Jason Zhang <zezhang@google.com>)
43f6bd9c: [Telemetry] add `peer_br_count` in WpanTopoFull (#2383) (Jason Zhang <zezhang@google.com>)
9f69fd08: submodule: bump third_party/openthread/repo from `602167f` to `4e3483c` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
3ab211fa: submodule: bump third_party/openthread/repo from `b73114c` to `602167f` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
ffb879a7: submodule: bump third_party/openthread/repo from `aba7aed` to `b73114c` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
c279dedd: Turn on OTBR_ENABLE_PLATFORM_ANDROID (Handa Wang <handaw@google.com>)
9c5d2541: [continuous-integration] fix the path for uploading artifacts when BR te... (Handa Wang <7058128+superwhd@users.noreply.githu...)
b109ebe8: [github-actions] fix ADVERTISING_PROXY option (#2381) (Li Cao <irvingcl@google.com>)
f85ca4a3: submodule: bump third_party/openthread/repo from `b301a4c` to `aba7aed` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
c87e7311: submodule: bump third_party/openthread/repo from `b0790b3` to `b301a4c` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
b7ebdc36: [github-actions] fix code coverage of ncp mode CI (#2377) (Li Cao <irvingcl@google.com>)
8c7b36b3: submodule: bump third_party/openthread/repo from `78ecafb` to `b0790b3` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
8c539b87: [utils] move VendorServer creation to CreateRcpMode() (#2370) (Yang Sun <sunytt@google.com>)
66fa666a: [utils] move VendorServer creation to CreateRcpMode() (#2370) (Yang Sun <sunytt@google.com>)
05ca8d96: submodule: bump third_party/openthread/repo from `695e7a5` to `78ecafb` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
88403c84: submodule: bump third_party/openthread/repo from `821f241` to `695e7a5` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
e6228ca4: Fix build for ot-sync (Yang Sun <sunytt@google.com>)
31da23b4: submodule: bump third_party/openthread/repo from `4c0d8f2` to `821f241` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
0eada4b3: [github-actions] update the build directory for otbr-agent (#2366) (Li Cao <irvingcl@google.com>)
04a9963a: [tests] use more accurate EXPECT_* in tests (#2362) (Handa Wang <7058128+superwhd@users.noreply.githu...)
30da5c3d: submodule: bump third_party/openthread/repo from `000f5fc` to `4c0d8f2` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
8e4d36bd: submodule: bump third_party/openthread/repo from `6f12c81` to `000f5fc` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
fdeb4173: [tests] enhance expect test framework for ncp_mode (#2353) (Li Cao <irvingcl@google.com>)
8759f8a1: [meshcop] add ThreadRole in state bitmap txt (#2306) (Rongli Sun <rongli@google.com>)
fb76359f: [test] migrate to gtest (#2359) (Yakun Xu <xyk@google.com>)
30af8d9f: [cmake] fix cmake warnings (#2357) (Yakun Xu <xyk@google.com>)
569bb317: [ncp] add ncp spinel and implement GetDeviceRole (#2350) (Li Cao <irvingcl@google.com>)
a994884f: submodule: bump third_party/openthread/repo from `a0ba929` to `6f12c81` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
e3114aca: submodule: bump third_party/openthread/repo from `e10a925` to `a0ba929` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
2c20d833: Add support for forwarding NAT64 packets between Thread and AIL (Handa Wang <handaw@google.com>)
3fc06e4d: submodule: bump third_party/openthread/repo from `cc8f66c` to `e10a925` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
edfb0c4c: [ncp] implement dbus server for NCP mode (#2339) (Li Cao <irvingcl@google.com>)
3a0de316: submodule: bump third_party/openthread/repo from `7d61987` to `cc8f66c` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
3edc59f6: [tests] fix expect test (#2345) (Li Cao <irvingcl@google.com>)
f81a659c: submodule: bump third_party/openthread/repo from `473fbca` to `7d61987` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
9667d8e5: [border-agent] log the RCP version when the otbr-agent starts (#2341) (Zhanglong Xia <zhanglongxia@google.com>)
261a0a1b: submodule: bump third_party/openthread/repo from `89b54dc` to `473fbca` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
41474ce2: submodule: bump third_party/openthread/repo from `215c23f` to `89b54dc` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
d8992429: [dbus] add DBUS API to expose DHCPv6 PD state signal (#2335) (SherySheng <sherysheng@google.com>)
65f03553: submodule: bump third_party/openthread/repo from `4e8f3c0` to `215c23f` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
7b7f3320: [controller] add ncp host (#2329) (Li Cao <irvingcl@google.com>)
88388742: submodule: bump third_party/openthread/repo from `54afce9` to `4e8f3c0` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
5bba00e4: [docker] add ability to set debug-level (#2331) (krbvroc1 <kbass@kenbass.com>)
81813122: submodule: bump third_party/openthread/repo from `8a8a4d8` to `54afce9` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
5008cf3e: [android] use OTBR_PLATFORM_ANDROID for android platform (#2333) (Kangping <wgtdkp@google.com>)
5349ba1a: [controller] rename to ThreadController to ThreadHost (#2332) (Li Cao <irvingcl@google.com>)
299688ad: submodule: bump third_party/openthread/repo from `6bc3b4d` to `8a8a4d8` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
32462a16: submodule: bump third_party/openthread/repo from `cb1220d` to `6bc3b4d` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
b8e743b5: submodule: bump third_party/openthread/repo from `32f462f` to `cb1220d` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
0c034e62: [controller] refactor controller creation (#2309) (Li Cao <irvingcl@google.com>)
20719660: submodule: bump third_party/openthread/repo from `5dbbab1` to `32f462f` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
18ee5956: [meshcop] support non-standard TXT entries at runtime (#2308) (Kangping <wgtdkp@google.com>)
7c77ae87: submodule: bump third_party/openthread/repo from `dd1e5f4` to `5dbbab1` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
32f481b2: submodule: bump third_party/openthread/repo from `cdeb02b` to `dd1e5f4` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
e5890ccd: [controller] update the usage of otPlatformConfig (#2318) (Li Cao <irvingcl@google.com>)
3a3d3363: submodule: bump third_party/openthread/repo from `b5b17ba` to `d6eb56c` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
21d3ba71: submodule: bump third_party/openthread/repo from `59e202c` to `b5b17ba` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
5b1a92a0: [telemetry] refactor the PD processing (#2312) (Handa Wang <7058128+superwhd@users.noreply.githu...)
0ebe955b: submodule: bump third_party/openthread/repo from `330b175` to `59e202c` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
251d34f7: [tests] fix the telemetry test for RLOC16 (#2313) (Handa Wang <7058128+superwhd@users.noreply.githu...)
e2eed3c8: [controller] add Thread controller interface for unified APIs (#2304) (Li Cao <irvingcl@google.com>)
78fa14bd: [telemetry] add external route related telemetry (#2284) (Jason Zhang <zezhang@google.com>)
a05cdc47: [application] refactor constructor to allow flexible initialization (#23... (Li Cao <irvingcl@google.com>)
140247aa: submodule: bump third_party/openthread/repo from `a54f4c4` to `330b175` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
5a7972eb: [script] refactor `script/server` (#2301) (Handa Wang <7058128+superwhd@users.noreply.githu...)
79649131: submodule: bump third_party/openthread/repo from `e7535f7` to `a54f4c4` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
dc226f40: [ncp] rename `ControllerOpenThread` to `RcpHost` (#2294) (Li Cao <irvingcl@google.com>)
91bb24df: submodule: bump third_party/openthread/repo from `a57d927` to `e7535f7` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
2fef6f65: submodule: bump third_party/openthread/repo from `8b04e9c` to `a57d927` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
611cc86d: [mbedtls] stop checking configuration explicitly (#2293) (Łukasz Duda <lukasz.duda@nordicsemi.no>)
25d200df: submodule: bump third_party/openthread/repo from `0ce49fc` to `8b04e9c` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
1045a0b6: [avahi] conditionalize Avahi Service Start and Installation (#2282) (Kevin Anderson <andersonkw2@gmail.com>)
c50fe48e: submodule: bump third_party/openthread/repo from `6444157` to `0ce49fc` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
c5ad8eea: submodule: bump third_party/openthread/repo from `be10913` to `6444157` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
5089108c: submodule: bump third_party/openthread/repo from `848de78` to `be10913` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
a2cfdd3c: submodule: bump third_party/openthread/repo from `02acc48` to `848de78` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
4b545bc9: [border-agent] add `_meshcop-e` service for ePSKc mode (#2259) (Mia Yang <145632982+mia1yang@users.noreply.githu...)
cb427a8d: submodule: bump third_party/openthread/repo from `f12785d` to `02acc48` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
655fb3c0: submodule: bump third_party/openthread/repo from `1fceb22` to `f12785d` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
72ae1f15: [border-agent] config related OpenThread core build flag according to OT... (Mia Yang <145632982+mia1yang@users.noreply.githu...)
e56c0200: submodule: bump third_party/openthread/repo from `74573b5` to `1fceb22` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
1dcdf75e: submodule: bump third_party/openthread/repo from `383d0d2` to `74573b5` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
f8447f93: submodule: bump third_party/openthread/repo from `42ccf28` to `383d0d2` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
6b77887a: submodule: bump third_party/openthread/repo from `ee83d45` to `42ccf28` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
4a8fd139: submodule: bump third_party/openthread/repo from `9e4cbb8` to `ee83d45` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
e4f7be56: submodule: bump third_party/openthread/repo from `9e4cbb8` to `922059c` ... (Jonathan Hui <jonhui@google.com>)
ae8b4a8a: submodule: bump third_party/openthread/repo from `0c6c2fe` to `9e4cbb8` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
35ba9fe2: [bbr] add a flag to enable BBR on init (#2265) (Yang Sun <sunytt@google.com>)
5afa1254: submodule: bump third_party/openthread/repo from `93f3113` to `0c6c2fe` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
619fbc72: [build] fix on macOS (#2269) (Yakun Xu <xyk@google.com>)
61def167: submodule: bump third_party/openthread/repo from `ade9c2b` to `93f3113` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
f7d5b6ed: submodule: bump third_party/openthread/repo from `19dc5ce` to `ade9c2b` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
b006bdc5: submodule: bump third_party/openthread/repo from `9681690` to `19dc5ce` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
45c847a6: submodule: bump third_party/openthread/repo from `4737231` to `9681690` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
e41baa78: submodule: bump third_party/openthread/repo from `4c96151` to `4737231` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
f872bbe9: submodule: bump third_party/openthread/repo from `be7d36e` to `4c96151` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
e41d4d4a: [feature-flag] add feature flag to control link metrics manager (#2251) (Li Cao <irvingcl@google.com>)
06b89cc5: submodule: bump third_party/openthread/repo from `a234add` to `be7d36e` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
99ac957c: submodule: bump third_party/openthread/repo from `43cb7a0` to `a234add` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
2dade2da: submodule: bump third_party/openthread/repo from `d0f6d17` to `43cb7a0` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
c7885ed5: github-actions: bump peaceiris/actions-gh-pages from 3 to 4 (#2253) (dependabot[bot] <49699333+dependabot[bot]@users....)
61383d2f: submodule: bump third_party/openthread/repo from `30aa3e8` to `d0f6d17` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
2533f319: [border-agent] update State Bitmap for ePSKc capability (#2246) (Mia Yang <145632982+mia1yang@users.noreply.githu...)
e438b877: submodule: bump third_party/openthread/repo from `6de5cd8` to `30aa3e8` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
168f20a3: submodule: bump third_party/openthread/repo from `65bc830` to `6de5cd8` ... (dependabot[bot] <49699333+dependabot[bot]@users....)
e9ec5ab6: [telemetry] add `InfraLinkInfo` telemetry data (#2242) (Handa Wang <7058128+superwhd@users.noreply.githu...)
```

