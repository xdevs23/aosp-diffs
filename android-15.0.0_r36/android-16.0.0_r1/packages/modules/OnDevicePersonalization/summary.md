```
5c6055f7: Revert "Log more error code for task assignment response" (Qiao Li <qiaoli@google.com>)
9a88ce06: Add cts test for setOutputData (Qiao Li <qiaoli@google.com>)
70d4144a: Add new separate tests for constructor API and direclty update existing ... (Qiao Li <qiaoli@google.com>)
20a42b1e: Remove isBuiltByTaskBuilder flag from keras example gen. (Andrew Vuong <akvuong@google.com>)
67f32b26: Log more error code for task assignment response (Qiao Li <qiaoli@google.com>)
3ae71dfd: packages/modules/OnDevicePersonalization: remove usages of Mockito.verif... (Adrian Roos <roosa@google.com>)
dfd98073: Cleanup of unused class members in file downloader. (Parag Kulkarni <paragkulkarni@google.com>)
5b60ee18: SPE migration for FederatedCompute BackgroundKeyFetchJob (Jorge Saldivar <jorgesaldivar@google.com>)
95f7cab5: Create per job flags for SPE FCP migration (Jorge Saldivar <jorgesaldivar@google.com>)
3da561bf: No-op cleanup/fixes to javadocs etc. (Parag Kulkarni <paragkulkarni@google.com>)
245a4815: Updated network type conversion in MddJob (Jorge Saldivar <jorgesaldivar@google.com>)
782c5a42: Add StorageNotLow constraint to  Mdd download job WIFI_CHARGING, CELLULA... (Yanning Jia <yanning@google.com>)
013754a1: Add back CTS tests for hidden APIs (Yanning Jia <yanning@google.com>)
34de0675: [owners] Remove ymu@google.com from OWNERS (Owner Cleanup Bot <swarming-tasks@owners-cleanup...)
bd3be7d8: Add StorageNotLow constraint on training job (Yanning Jia <yanning@google.com>)
1bacd501: Refactor OnDevicePersonalizationMaintenanceJob backoff policy (Jorge Saldivar <jorgesaldivar@google.com>)
2c34b2ed: [owners] Remove xueyiwang@google.com from OWNERS (Owner Cleanup Bot <swarming-tasks@owners-cleanup...)
0c84ffc4: Additional logging to help investigate flakes in MH integration tests. (Parag Kulkarni <paragkulkarni@google.com>)
fe53a8b6: SPE migration for ODP MddJobService (Jorge Saldivar <jorgesaldivar@google.com>)
e84fb999: Potential fix to deflake LocalDataDaoTest. (Parag Kulkarni <paragkulkarni@google.com>)
bee35bd6: Remove storageNotLow constraint from ODP Maintenance job (Yanning Jia <yanning@google.com>)
7e42a65b: Fixes concurrency issue on MddServiceJob (Jorge Saldivar <jorgesaldivar@google.com>)
90c1e7af: Add wait between OdpExampleStoreServiceTests to avoid Concurrent modific... (Yanning Jia <yanning@google.com>)
f3e1b8aa: [owners] Remove ryangu@google.com from OWNERS (Owner Cleanup Bot <swarming-tasks@owners-cleanup...)
22413941: Mock StatsUtils class in OdpExampleStoreServiceTests to reduce flakiness (Yanning Jia <yanning@google.com>)
67376f96: Cleanup to CtsOdpManagerTest and related classes. (Parag Kulkarni <paragkulkarni@google.com>)
222ec785: Eagerly delete any stale files associated with a key during upserts and ... (Parag Kulkarni <paragkulkarni@google.com>)
328c2cd0: Revert "Hide ODP APIs for M-2025-03" (Yanning Jia <yanning@google.com>)
790f867a: Fixes OdpDownloadProcessingJob error prone messages (Jorge Saldivar <jorgesaldivar@google.com>)
4d98061d: SPE migration for ODP OdpDownloadProcessingJobService (Jorge Saldivar <jorgesaldivar@google.com>)
a20a4383: Explicitly keep default constructor in rules without members (Christoffer Adamsen <christofferqa@google.com>)
a3e31bf3: Revert^2 "Fix apex_available value in OnDevicePersonalization" (Colin Cross <ccross@android.com>)
54dacd37: Revert "Fix apex_available value in OnDevicePersonalization" (Chaitanya Cheemala (xWF) <ccheemala@google.com>)
930d3a5c: SPE migration for ODP UserDataCollectionJobService (Jorge Saldivar <jorgesaldivar@google.com>)
729595d0: Fix apex_available value in OnDevicePersonalization (Colin Cross <ccross@android.com>)
60469028: Delete redundant proguard rules (Jared Duke <jdduke@google.com>)
f4c180c8: No-op refactor to fcp service code. (Parag Kulkarni <paragkulkarni@google.com>)
1ea28008: Verify that execute() and LocalData support 30MB blobs. (Karthik Mahesh <karthikmahesh@google.com>)
bb5de65a: 1. explictly delete temp file after run complete 2. add purge job for ca... (Qiao Li <qiaoli@google.com>)
a7bb6968: SPE migration for ODP AggregateErrorDataReportingService (Jorge Saldivar <jorgesaldivar@google.com>)
f2b4318a: Add CTS test for OnDevicePersonalization constructors. (Emily <fumengyao@google.com>)
b7e89e07: SPE migration for ODP ResetDataJobService (Jorge Saldivar <jorgesaldivar@google.com>)
9b80c67c: Adding logging to keep track of reasons for device non-eligibility (Amando Jimenez <amandoj@google.com>)
24540678: Fixes flaky test on OnDevicePersonalizationManagingServiceTest (Jorge Saldivar <jorgesaldivar@google.com>)
dc7f89b4: Add logic to limit error reporting to at most once every interval report... (Parag Kulkarni <paragkulkarni@google.com>)
c6afd3f5: Add @FlaggedApi to unhide OnDevicePersonalizationException class. (Emily <fumengyao@google.com>)
b97343e2: Create per job flags for SPE ODP migration (Jorge Saldivar <jorgesaldivar@google.com>)
1fe5a7ff: Add cts tests for inference input/output (Qiao Li <qiaoli@google.com>)
e5f91856: Fix ODP trace event log constants to match with the atom. (Emily <fumengyao@google.com>)
00b3d79e: Minor cleanup in FederatedComputeWorker class and additional javadocs. (Parag Kulkarni <paragkulkarni@google.com>)
931c867c: Update fileGroupName to include "odp" prefix for easier debugging with s... (Andrew Vuong <akvuong@google.com>)
a745993d: Add flag to unhide OnDevicePersonalizationException. (Emily <fumengyao@google.com>)
a9932a65: Add ProcessWrapper class to facilitate testing (Yanning Jia <yanning@google.com>)
f4e5d59a: Ignore Cts tests behind M05 APIs (Yanning Jia <yanning@google.com>)
ea051dd3: Hide ODP APIs for M-2025-03 (Yanning Jia <yanning@google.com>)
ed48d5df: Refactoring to clean up PhFlags and FlagsConstants (Jorge Saldivar <jorgesaldivar@google.com>)
1d6adaa6: Refactor FCP flag keys to a constant file (Jorge Saldivar <jorgesaldivar@google.com>)
4df34be8: Add CTS tests for queryFeatureAvailability ODP API. (Jonathan Pierce <jonathanpie@google.com>)
feb607da: Remove use of singleton FederatedComputeDbHelper instance in tests. (Parag Kulkarni <paragkulkarni@google.com>)
1de331fb: Add some unknown keys to download json in tests. (Karthik Mahesh <karthikmahesh@google.com>)
63d7a114: Enable test for verifying ODP sandbox process calls (Jorge Saldivar <jorgesaldivar@google.com>)
27f5ab15: Verification for ODP sandbox process calls (Jorge Saldivar <jorgesaldivar@google.com>)
28212fb8: Correctly clear training task dao before tests. (Parag Kulkarni <paragkulkarni@google.com>)
1080f24c: Cleanup owner file (Qiao Li <qiaoli@google.com>)
c0533493: Extract out downloaded json parser and add unit tests. (Karthik Mahesh <karthikmahesh@google.com>)
6e3efbad: No-op fix typo in FederatedTrainingTaskContract class. (Parag Kulkarni <paragkulkarni@google.com>)
3df49547: Explicitly clear tokendao and trainingtaskdao before each test. (Parag Kulkarni <paragkulkarni@google.com>)
e7c859bd: Abort training run if fail to generate KA record (Qiao Li <qiaoli@google.com>)
5183f8a5: Add more logging for key attestation (Qiao Li <qiaoli@google.com>)
562f1a8e: Add more log to investigate test failure (Qiao Li <qiaoli@google.com>)
61536fb1: Restructure assertThat isEmpty checks to be more informative. (Parag Kulkarni <paragkulkarni@google.com>)
4d9bf0fc: Refactor flag keys to a constant file (Qiao Li <qiaoli@google.com>)
f5971529: Clear tokendao before each test to potentially help with flakiness. (Parag Kulkarni <paragkulkarni@google.com>)
e3c167ad: Add some locking for non final members in AuthorizationContext class. (Parag Kulkarni <paragkulkarni@google.com>)
e8d7bd38: Handle unavailable FCService in ODP worker thread (Yanning Jia <yanning@google.com>)
299103f4: Add protodatastore in common/ for use in both ODP and FCP APKs. (Parag Kulkarni <paragkulkarni@google.com>)
96cafc78: Support mnist model used in odp git repo for demo (Qiao Li <qiaoli@google.com>)
afd9c82a: Remove hansson@google.com from federatedcompute/OWNERS (Owner Cleanup Bot <swarming-tasks@owners-cleanup...)
```

