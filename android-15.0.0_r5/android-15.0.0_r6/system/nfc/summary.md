```
1340bbff: Correction of tool analysis warnings for file rw_t4t.cc (Alexandra Ducati-Manas <alexandra.ducati-manas@s...)
5aa44391: Check event pointer in nfc_data_event() (Alexandra Ducati-Manas <alexandra.ducati-manas@s...)
392fe3df: Check nfc_state before processing data to avoid race condition (Alexandra Ducati-Manas <alexandra.ducati-manas@s...)
b0773137: Reset target array when calling NFA_EeGetInfo() (Alexandra Ducati-Manas <alexandra.ducati-manas@s...)
5cd7e6c9: Free allocated buffer if error in NFA_RwLocateTlv() API (Alexandra Ducati-Manas <alexandra.ducati-manas@s...)
986ebacf: Fix nfc_rw_fuzzer for new T5T updates (George Chang <georgekgchang@google.com>)
ee61e241: Add provision to support multiple HCI UICC pipe IDs (suryaprakash.konduru <suryaprakash.konduru@nxp.c...)
2d5dc4e3: Fix for NFC Forum T5T testcase failures (sai.shwethas <sai.shwethas@nxp.com>)
8de633d3: No need to stop discovery when receiving NFC_EE_DISCOVER_REQ_REVT (Alexandra Ducati-Manas <alexandra.ducati-manas@s...)
ede0e2ad: Fix compiler warnigs (Alexandra Ducati-Manas <alexandra.ducati-manas@s...)
df14e050: Extending setControllerAlwaysOn feature with transparent and Card Emulat... (Himanshu Singh Kushwah <himanshusingh.kushwah@nx...)
183442ea: Do not wait on a task that is already dead (Alexandra Ducati-Manas <alexandra.ducati-manas@s...)
3c036f87: Add aconfig flag mfc_read_mad (George Chang <georgekgchang@google.com>)
5ceda2d8: MIFARE tags: added code to read MAD sector (Alexandra Ducati-Manas <alexandra.ducati-manas@s...)
920bbb49: Clear tag activated information when Kovio tag is deactivated (Alexandra Ducati-Manas <alexandra.ducati-manas@s...)
ad1912fe: Allowing transmission of empty raw frames (Alexandra Ducati-Manas <alexandra.ducati-manas@s...)
94aafe23: [DTA] Define new mode and disable NFA API (Celine Finet <celine.finet@st.com>)
464340b1: Clear unused define (George Chang <georgekgchang@google.com>)
17de60f3: Fix unused variables. (Christopher Ferris <cferris@google.com>)
0932383a: Skip unsupported discovery protocols (George Chang <georgekgchang@google.com>)
24eda07d: HAL Request Control Enablement in Android-16 (suryaprakash.konduru <suryaprakash.konduru@nxp.c...)
0ce375ed: Remove the use of the death recipient cookie (Devin Moore <devinmoore@google.com>)
0d4e5e6a: Keep legacy T5T tags readable in the field (Celine Finet <celine.finet@st.com>)
8d21695f: Keep legacy T5T tags readable in the field (Celine Finet <celine.finet@st.com>)
89e666b3: Add new aconfig dependencies (Ted Bauer <tedbauer@google.com>)
8c1ba8ba: Casimir: Remove hard todo!() for NFC-B polling (Henri Chataing <henrichataing@google.com>)
407873a0: switch over to use new storage read api instead of server_configurable_f... (Dennis Shen <dzshen@google.com>)
```
