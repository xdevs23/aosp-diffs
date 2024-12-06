```diff
diff --git a/Android.bp b/Android.bp
index 19e9d56..fbbf55d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -128,4 +128,5 @@ cc_test {
     ],
     defaults: ["dittobench_defaults"],
     data: ["example/*"],
+    auto_gen_config: true,
 }
diff --git a/CMakeLists.txt b/CMakeLists.txt
index c279add..e4416f4 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -26,6 +26,7 @@ add_custom_command(
 	COMMAND ${PROJECT_SOURCE_DIR}/ditto2cpp.py
 		-o embedded_benchmarks.cpp
 		-s ${ditto_benchmarks}
+	DEPENDS ${ditto_benchmarks}
 	VERBATIM
 )
 
diff --git a/README.md b/README.md
index 808c675..7c493be 100644
--- a/README.md
+++ b/README.md
@@ -1,14 +1,23 @@
 # Dittosuite
 
-Dittosuite is a work in progress collection of tools that aims at providing
-a high-level language called Dittolang that defines operations.
+Dittosuite is a collection of tools that simplifies writing and running complex
+workloads.
 
-The defined Dittolang operations can be interpreted by Dittosim for simulation
-to provide a simulated performance measurement and quickly identify
-the goodness of a solution.
+These workloads are defined by a set of instructions including, but not limited
+to, CPU load, memory allocations, file system operations, Binder IPC, that can
+be combined to run sequentially or in parallel.
 
-Specularly, Dittobench interprets the Dittolang operations and executes them on
-a real device, tracking the behavior and measuring the performance.
+A new high-level language, Dittolang, defines the workload in the form of a
+textual representation of Protocol Buffers (aka .ditto files).
+
+The operations defined in the .ditto files are interpreted and executed by
+Dittobench on the target device.
+
+## Benchmarking
+
+During the Dittobench execution of the instructions defined in the .ditto file,
+the tool tracks performance metrics such as execution time and I/O bandwidth
+(more in the [Sampling](#sampling) section).
 
 # Doxygen documentation
 
@@ -26,70 +35,110 @@ $ ./dittobench [options] [.ditto file]
 ```
 
 To run a benchmark, a well formed .ditto file must be provided, see section
-[How to write .ditto files](#how-to-write-ditto-files)
+[How to write .ditto files](#writing-ditto-files)
 In addition, these options can be set:
 
-- `--results-output=<int | string>` (default: report). Select the results output format.
-Options: report, csv with 0, 1 respectively.
-- `--log-stream=<int | string>` (default: stdout). Select the output stream for the log messages.
-Options: stdout, logcat with 0, 1 respectively.
-- `--log-level=<int | string>` (default: INFO). Select to output messages which are at or below
-the set level. Options: VERBOSE, DEBUG, INFO, WARNING, ERROR, FATAL with 0, 1, 2, 3, 4 and 5
-respectively.
-- `--parameters=string`. If the benchmark is parametric, all the parameters (separated by commas)
-can be given through this option.
+- `--results-output=<string>` (default: report). Select the results output
+  format. Options: report, csv.
+- `--log-stream=<string>` (default: stdout). Select the output stream for
+  the log messages. Options: stdout, logcat.
+- `--log-level=<string>` (default: INFO). Select to output messages which are
+  at or below the set level. Options: VERBOSE, DEBUG, INFO , WARNING, ERROR,
+  FATAL.
+- `--parameters=string`. If the benchmark takes parameters, they can be passed
+  through this option, separated by commas.
 
-# How to write .ditto files
+# Writing .ditto files {#writing-ditto-files}
+
+## Sections
 
 Every .ditto file should begin with this skeleton:
+
 ```
-main: {
-  ...
-},
-global {
-  ...
-}
+main: {},
+global {}
 ```
 
 Optionally, it can contain `init` and `clean_up` sections:
+
 ```
-init: {
-  ...
-},
-main: {
-  ...
-},
-clean_up: {
-  ...
-},
-global {
-  ...
-}
+main: {},
+init: {},
+clean_up: {},
+global {}
 ```
 
-## `global`
+### `global`
+
+The `global` section contains general benchmark parameters.
+Available options:
 
-Global section should contain general benchmark configuration. Currently available options:
+- (optional) `string absolute_path` (`default = ""`). Specifies the absolute
+  path for files created by benchmarks. This parameter simplifies the
+  definition of paths among different file system `Instruction`s, for example,
+  when different benchmarks should be run in different paths with different
+  file systems.
 
-- (optional) `string absolute_path` (`default = ""`). Specifies the absolute path for the files.
+### `main`
 
-## `init`
+`main` is the entry point for the benchmark.
 
-`init` is optional and can be used to initialize the benchmarking environment. It executes
-instructions similar to `main`, but the results are not collected in the end.
+It contains a single `instruction`.
 
-## `main`
+Having a single instruction does not mean that the tool is limited to one
+instruction. In fact, as will be explained later, multiple instances of the
+same instruction can be executed with the parameter `repeat`, or a series of
+different instructions can be execute using the special instruction
+`instruction_set`.
 
-`main` is the entry point for the benchmark. It can contain a single `instruction` or
-`instruction_set` (also with nested `instruction_set`).
+### `init` (optional)
 
-## `clean_up`
+`init` initializes the benchmarking environment.
 
-`clean_up` is optional and can be used to reset the benchmarking environment to the initial state,
-e.g, delete benchmark files. Similar to `init`, it executes instructions like `main`, but results
-are not collected in the end.
+It executes instructions similar to `main`, but the results are not collected
+at the end of the execution.
 
-## `instruction`
+### `clean_up` (optional)
+
+`clean_up` is optional and can be used to reset the benchmarking environment to
+the initial state, e.g, delete benchmark files. Similar to `init`, it executes
+instructions like `main`, but results are not collected in the end.
+
+## Instructions
+
+Every workload is composed of one or more instructions.
+
+Almost everything in Ditto `main` itself is an instruction!
+
+Here is an example of a .ditto file.
+
+```
+main: {
+  instruction_set: {
+    instructions: [
+      {
+        open_file: {
+          path_name: "newfile2.txt",
+          output_fd: "test_file"
+        }
+      },
+      {
+        close_file: {
+          input_fd: "test_file"
+        }
+      }
+    ]
+  },
+  repeat: 10
+},
+global {
+  absolute_path: "/data/local/tmp/";
+}
+```
+
+See more examples in `example/`.
+
+### `instruction`
 
 ```
 {
@@ -103,10 +152,12 @@ are not collected in the end.
 ```
 
 Currently available options:
-- (optional) `int repeat` (`default = 1`). Specifies how many times the instruction should be
-repeated.
 
-## `instruction_set`
+- (optional) `int repeat` (`default = 1`). Specifies how many times the
+  instruction should be repeated.
+
+### `instruction_set`
+
 ```
 {
   instruction_set: {
@@ -135,21 +186,27 @@ repeated.
 }
 ```
 
-Instruction set is an Instruction container that executes the contained instructions sequentially.
-Instruction set can optionally iterate over a list and execute the provided set of instructions on
-each item from the list. To use it, `iterate_options` should be set with these options:
+Instruction set is an Instruction container that executes the contained
+instructions sequentially.
+
+Instruction set can optionally iterate over a list and execute the provided set
+of instructions on each item from the list. To use it, `iterate_options` should
+be set with these options:
+
 - `string list_name` - Shared variable name pointing to a list of values.
-- `string item_name` - Shared variable name to which a selected value should be stored.
+- `string item_name` - Shared variable name to which a selected value should be
+  stored.
 - (optional) `Order order` (`default = SEQUENTIAL`) - Specifies if
   the elements of the list should be accessed sequentially or randomly. Options:
   `SEQUENTIAL`, `RANDOM`.
-- (optional) `Reseeding reseeding` (`default = ONCE`) - Specifies how often the random number
-generator should be reseeded with the same provided (or generated) seed. Options: `ONCE`,
-`EACH_ROUND_OF_CYCLES`, `EACH_CYCLE`.
-- (optional) `uint32 seed` - Seed for the random number generator. If the seed is not provided,
-current system time is used as the seed.
+- (optional) `Reseeding reseeding` (`default = ONCE`) - Specifies how often the
+  random number generator should be reseeded with the same provided (or
+  generated) seed.  Options: `ONCE`, `EACH_ROUND_OF_CYCLES`, `EACH_CYCLE`.
+- (optional) `uint32 seed` - Seed for the random number generator. If the seed
+  is not provided,
+  current system time is used as the seed.
 
-## `multithreading` and `threads`
+### `multithreading`
 
 ```
 multithreading: {
@@ -163,132 +220,122 @@ multithreading: {
 }
 ```
 
-Multithreading is another instruction container that executes the specified instructions
-(or instruction sets) in different threads. If the optional `spawn` option for a specific
-instruction (or instruction set) is provided, then the provided number of threads will be created
-for it.
+Multithreading is another instruction container that executes the specified
+instructions (or instruction sets) in different threads. If the optional
+`spawn` option for a specific instruction (or instruction set) is provided,
+then the provided number of threads will be created for it.
 
-## Example
+Arguments:
 
-```
-main: {
-  instruction_set: {
-    instructions: [
-      {
-        open_file: {
-          path_name: "newfile2.txt",
-          output_fd: "test_file"
-        }
-      },
-      {
-        close_file: {
-          input_fd: "test_file"
-        }
-      }
-    ]
-  },
-  repeat: 10
-},
-global {
-  absolute_path: "/data/local/tmp/";
-}
-```
-See more examples in `example/`.
+- `Thread threads`: an array of `Thread`s that will be executed in parallel.
+  Each `Thread` specifies:
+  - the `Instruction` to run.
+  - (optional, default 1) `int32 spawn`: number of threads/processes to be
+    created for this instruction.
+  - (optional) `string name`: alias name to be assigned to the thread/process.
+  - (optional) `SchedAttr sched_attr`: scheduling parameters.
+  - (optional, default -1) `int64 sched_affinity`: bitmask that defines what
+    CPUs the thread/process can run on.
+- (optional, default false) `bool fork`: if true, creates processes, otherwise
+  creates threads.
 
-# Predefined list of instructions
+### `open_file`
 
-## `open_file`
+Opens the file specified by the given path or by a shared variable name
+pointing to a file path. If neither of those are provided, a random 9-digit
+name is generated.  Optionally saves the file descriptor which can then be used
+by subsequent instructions. Also, can optionally create the file if it does not
+already exist.
 
-Opens the file with a file path or a shared variable name pointing to a file path. If neither of
-those are provided, a random name consisting of 9 random digits is generated. Optionally saves the
-file descriptor which can then be used by subsequent instructions. Also, can optionally create the
-file if it does not already exist.
+Arguments:
 
-### Arguments:
-- (optional) `string path_name` - Specifies the file path.<br/>
-OR<br/>
-`string input` - Shared variable name pointing to a file path.
-- (optional) `string output_fd` - Shared variable name to which output file descriptor
-should be saved.
-- (optional) `bool create` (`default = true`) - Specifies if the file should be created if it does
-not already exist. If the file exists, nothing happens.
+- (optional) `string path_name` - Specifies the file path.
+- (OR, optional) `string input` - Shared variable name pointing to a file path.
+- (optional) `string output_fd` - Shared variable name to which output file
+  descriptor should be saved.
+- (optional) `bool create` (`default = true`) - Specifies if the file should be
+  created if it does not already exist. If the file exists, nothing happens.
 
-## `delete_file`
+### `delete_file`
 
-Deletes the file with a file path or a shared variable name pointing to a file path.
-Uses `unlink(2)`.
+Deletes the file with a file path or a shared variable name pointing to a file
+path.  Uses `unlink(2)`.
 
-### Arguments:
-- `string path_name` - Specifies the file path.<br/>
-OR<br/>
-`string input` - Shared variable name pointing to a file path.
+Arguments:
 
+- `string path_name` - Specifies the file path.<br/>
+  OR<br/>
+  `string input` - Shared variable name pointing to a file path.
 
-## `close_file`
+### `close_file`
 
 Closes the file with the provided file descriptor.
 Uses `close(2)`.
 
-### Arguments:
+Arguments:
+
 - `string input_fd` - Shared variable name pointing to a file descriptor.
 
-## `resize_file`
+### `resize_file`
 
-Resizes the file with the provided file descriptor and new size. If the provided size is greater
-than the current file size, `fallocate(2)` is used, while `ftruncate(2)` is used if the provided
-size is not greater than the current file size.
+Resizes the file with the provided file descriptor and new size.  If the
+provided size is greater than the current file size, `fallocate(2)` is used,
+otherwise `ftruncate(2)` is used.
+
+Arguments:
 
-### Arguments:
 - `string input_fd` - Shared variable name pointing to a file descriptor.
 - `int64 size` - New file size (in bytes).
 
-## `resize_file_random`
+### `resize_file_random`
+
+Resizes the file with the provided file descriptor and a range for the new
+size. The new file size is randomly generated in the provided range and if the
+generated size is greater than the current file size, `fallocate(2)` is used,
+otherwise `ftruncate(2)` is used.
 
-Resizes the file with the provided file descriptor and a range for new size. New file size is
-randomly generated in the provided range and if the generated size is greater
-than the current file size, `fallocate(2)` is used, while `ftruncate(2)` is used if the generated
-size is not greater than the current file size.
+Arguments:
 
-### Arguments:
 - `string input_fd` - Shared variable name pointing to a file descriptor.
 - `int64 min` - Minimum value (in bytes)
 - `int64 max` - Maximum value (in bytes)
-- (optional) `uint32 seed` - Seed for the random number generator. If the seed is not provided,
-current system time is used as the seed.
-- (optional) `Reseeding reseeding` (`default = ONCE`). How often the random number
-generator should be reseeded with the provided (or generated) seed. Options: `ONCE`,
-`EACH_ROUND_OF_CYCLES`, `EACH_CYCLE`.
-
-## `write_file`
-
-Writes to file with the provided file descriptor. For `SEQUENTIAL`
-access, the blocks of data will be written sequentially and if the end of
-the file is reached, new blocks will start from the beginning of the file. For
-`RANDOM` access, the block offset, to which data should be written, will
-be randomly chosen with uniform distribution. `10101010` byte is used for the
-write operation to fill the memory with alternating ones and zeroes. Uses
+- (optional) `uint32 seed` - Seed for the random number generator. If the seed
+  is not provided, current system time is used as the seed.
+- (optional) `Reseeding reseeding` (`default = ONCE`). How often the random
+  number generator should be reseeded with the provided (or generated) seed.
+  Options: `ONCE`, `EACH_ROUND_OF_CYCLES`, `EACH_CYCLE`.
+
+### `write_file`
+
+Writes to file with the provided file descriptor. For `SEQUENTIAL` access, the
+blocks of data will be written sequentially and if the end of the file is
+reached, new blocks will start from the beginning of the file. For `RANDOM`
+access, the block offset, to which data should be written, will be randomly
+chosen with uniform distribution. `10101010` byte is used for the write
+operation to fill the memory with alternating ones and zeroes. Uses
 `pwrite64(2)`.
 
-### Arguments:
+Arguments:
+
 - `string input_fd` - Shared variable name pointing to a file descriptor.
-- (optional) `int64 size` (`default = -1`) - How much data (in bytes) should be written in total.
-If it is set to `-1`, then file size is used.
-- (optional) `int64 block_size` (`default = 4096`) - How much data (in bytes) should be written at
-once. If it is set to `-1`, then file size is used.
-- (optional) `int64 starting_offset` (`default = 0`) - If `access_order` is
-  set to `SEQUENTIAL`, then the blocks, to which the data should be written,
-  will start from this starting offset (in bytes).
+- (optional) `int64 size` (`default = -1`) - How much data (in bytes) should be
+  written in total.  If it is set to `-1`, then file size is used.
+- (optional) `int64 block_size` (`default = 4096`) - How much data (in bytes)
+  should be written at once. If it is set to `-1`, then file size is used.
+- (optional) `int64 starting_offset` (`default = 0`) - If `access_order` is set
+  to `SEQUENTIAL`, then the blocks, to which the data should be written, will
+  start from this starting offset (in bytes).
 - (optional) `Order access_order` (`default = SEQUENTIAL`) - Order of the
   write. Options: `SEQUENTIAL` and `RANDOM`.
-- (optional) `uint32 seed` - Seed for the random number generator. If the seed is not provided,
-current system time is used as the seed.
-- (optional) `bool fsync` (`default = false`) - If set, `fsync(2)` will be called after the
-execution of all write operations.
-- (optional) `Reseeding reseeding` (`default = ONCE`) - How often the random number
-generator should be reseeded with the provided (or generated) seed. Options: `ONCE`,
-`EACH_ROUND_OF_CYCLES`, `EACH_CYCLE`.
+- (optional) `uint32 seed` - Seed for the random number generator. If the seed
+  is not provided, current system time is used as the seed.
+- (optional) `bool fsync` (`default = false`) - If set, `fsync(2)` will be
+  called after the execution of all write operations.
+- (optional) `Reseeding reseeding` (`default = ONCE`) - How often the random
+  number generator should be reseeded with the provided (or generated) seed.
+  Options: `ONCE`, `EACH_ROUND_OF_CYCLES`, `EACH_CYCLE`.
 
-## `read_file`
+### `read_file`
 
 Reads from file with the provided file descriptor. For `SEQUENTIAL`
 access, the blocks of data will be read sequentially and if the end of
@@ -297,40 +344,47 @@ the file is reached, new blocks will start from the beginning of the file. For
 be randomly chosen with uniform distribution. Calls `posix_fadvise(2)` before
 the read operations. Uses `pread64(2)`.
 
-### Arguments:
+Arguments:
+
 - `string input_fd` - Shared variable name pointing to a file descriptor.
-- (optional) `int64 size` (`default = -1`) - How much data (in bytes) should be read in total.
-If it is set to `-1`, then file size is used.
-- (optional) `int64 block_size` (`default = 4096`) - How much data (in bytes) should be read at
-once. If it is set to `-1`, then file size is used.
-- (optional) `int64 starting_offset` (`default = 0`) - If `access_order` is
-  set to `SEQUENTIAL`, then the blocks, from which the data should be read,
-  will start from this starting offset (in bytes).
-- (optional) `Order access_order` (`default = SEQUENTIAL`) - Order of the
-  read. Options: `SEQUENTIAL` and `RANDOM`.
-- (optional) `uint32 seed` - Seed for the random number generator. If the seed is not provided,
-current system time is used as the seed.
+- (optional) `int64 size` (`default = -1`) - How much data (in bytes) should be
+  read in total.  If it is set to `-1`, then file size is used.
+- (optional) `int64 block_size` (`default = 4096`) - How much data (in bytes)
+  should be read at once. If it is set to `-1`, then file size is used.
+- (optional) `int64 starting_offset` (`default = 0`) - If `access_order` is set
+  to `SEQUENTIAL`, then the blocks, from which the data should be read, will
+  start from this starting offset (in bytes).
+- (optional) `Order access_order` (`default = SEQUENTIAL`) - Order of the read.
+  Options: `SEQUENTIAL` and `RANDOM`.
+- (optional) `uint32 seed` - Seed for the random number generator. If the seed
+  is not provided, current system time is used as the seed.
 - (optional) `ReadFAdvise fadvise` (`default = AUTOMATIC`) - Sets the argument
   for the `posix_fadvise(2)` operation. Options: `AUTOMATIC`, `NORMAL`,
   `SEQUENTIAL` and `RANDOM`. If `AUTOMATIC` is set, then
   `POSIX_FADV_SEQUENTIAL` or `POSIX_FADV_RANDOM` will be used for `SEQUENTIAL`
   and `RANDOM` access order respectively.
-- (optional) `Reseeding reseeding` (`default = ONCE`) - How often the random number
-generator should be reseeded with the provided (or generated) seed. Options: `ONCE`,
-`EACH_ROUND_OF_CYCLES`, `EACH_CYCLE`.
+- (optional) `Reseeding reseeding` (`default = ONCE`) - How often the random
+  number generator should be reseeded with the provided (or generated) seed.
+  Options: `ONCE`, `EACH_ROUND_OF_CYCLES`, `EACH_CYCLE`.
 
-## `read_directory`
+### `read_directory`
 
-Reads file names from a directory and stores them as a list in a shared variable. Uses `readdir(3)`.
+Reads file names from a directory and stores them as a list in a shared
+variable. Uses `readdir(3)`.
+
+Arguments:
 
-### Arguments:
 - `string directory_name` - Name of the directory
 - `string output` - Shared variable name to which files names should be saved.
 
-## `invalidate_cache`
+### `invalidate_cache`
+
+Drops kernel caches, including dentry, inode and page caches. This is done by
+calling `sync()` and then writing `3` to `/proc/sys/vm/drop_caches`.
 
-Drops kernel clean caches, including, dentry, inode and page caches by calling sync() first and
-then writing `3` to `/proc/sys/vm/drop_caches`. No arguments.
+# Sampling {#sampling}
+
+TODO
 
 # Dependencies
 
@@ -383,103 +437,9 @@ lcov -d ./CMakeFiles/ -b . --gcov-tool $PWD/../test/llvm-gcov.sh --capture -o co
 genhtml cov.info -o coverage_html
 ```
 
-> **_NOTE:_**  lcov version 2.* has issues such as `geninfo: ERROR: "XXX:
-function YYY found on line but no corresponding 'line' coverage data point.
-Cannot derive function end line.`. This can be solved by downgrading to version
-1.6. The lcov repository already has a binary, so PATH can be updated with its
-`bin` folder.
-
-
-# Use cases
-
-
-## File operations performance (high priority)
-
-Bandwidth and measurement when dealing with few huge files or many small files.
-Operations are combinations of sequential/random-offset read/write.
-
-Latency in creating/deleting files/folders.
-
-These operations should be able to be triggered in a multiprogrammed fashion.
-
-
-## Display pipeline
-
-A graph of processes that are communicating with each others in a pipeline of
-operations that are parallely contributing to the generation of display frames.
-
-
-## Scheduling (low priority)
-
-Spawning tasks (period, duration, deadline) and verifying their scheduling
-latency and deadline misses count.
-
-
-# Workflow example and implementation nits
-
-In the following scenario, two threads are running.
-
-T1 runs the following operations: Read, Write, Read, sends a request to T2 and
-waits for the reply, then Write, Read.
-T2 waits for a request, then Read, Write, then sends the reply to the requester.
-
-Operations are encoded as primitives expressed with ProtoBuffers.
-The definition of dependencies among threads can be represented as graphs.
-
-
-## Initialization phase
-
-The first graph traversal is performed at initialization time, when all the
-ProtoBuffer configuration files are distributed among all the binaries so that
-they can perform all the heavy initialization duties.
-
-
-## Execution phase
-
-After the initialization phase completes the graph can be traversed again to
-put all the workloads in execution.
-
-
-## Results gathering phase
-
-A final graph traversal can be performed to fetch all the measurements that
-each entity internally stored.
-
-
-## Post processing
-
-All the measurements must be ordered and later processed to provide useful
-information to the user.
-
-T1: INIT   : [ RD WR RD ]  SND               RCV [ WR RD ] : END
-T2:   INIT :                 RCV [ RD WR ] SND             :   END
-
-
-# Scratch notes
-
-critical path [ READ WRITE READ ] [ READ WRITE ]  [ WRITE READ ]
--------------------->
-             >                  <
-Thread1   III-XXXXXX|X-SSSSSS-XX-TTTT
-Thread2               III-XXXX|XXX-TTTT
-                     ^
-
-       >       XXXXXXX    XX<
-                      XXXX
-
-
-READ WRITE READ
-
---->
-
-vector<instr*> {read(), write(), read()};
--> start()
-
-
-RECEIVE READ WRITE READ SEND
---->
-vector<instr*> {receive(), read(), write(), read(), send()};
-start()
-
-lock on receive()
+> **_NOTE:_**: `lcov` version `2.0-1` has issues such as `geninfo: ERROR: "XXX:
+> function YYY found on line but no corresponding 'line' coverage data point.
+> Cannot derive function end line.` This can be solved by downgrading to
+> version 1.6. The lcov repository already has a binary, so `PATH` can be
+> updated with its `bin` folder.
 
diff --git a/example/priority_inversion_fifo.ditto b/example/priority_inversion_fifo.ditto
new file mode 100644
index 0000000..2192ce2
--- /dev/null
+++ b/example/priority_inversion_fifo.ditto
@@ -0,0 +1,101 @@
+main: {
+  multithreading: {
+    threads: [
+      {
+        name: "High"
+        instruction: {
+          instruction_set: {
+            instructions: [
+              {
+                lock: {
+                  mutex { name: "lock1" }
+                }
+              },
+              {
+                cpu_work: {
+                  duration_us: 2000
+                }
+              },
+              {
+                unlock: {
+                  mutex { name: "lock1" }
+                }
+              }
+            ]
+          }
+          repeat: 100
+          period_us: 50000
+          offset_us: 1000
+        }
+        sched_affinity: 1
+        sched_attr: {
+          rt: {
+            policy: FIFO
+            priority: 99
+          }
+        }
+      },
+      {
+        name: "Mid"
+        instruction: {
+          instruction_set: {
+            instructions: [
+              {
+                cpu_work: {
+                  duration_us: 10000
+                }
+              }
+            ]
+          }
+          repeat: 100
+          period_us: 30000
+          offset_us: 1500
+        }
+        sched_affinity: 1
+        sched_attr: {
+          rt: {
+            policy: FIFO
+            priority: 98
+          }
+        }
+      },
+      {
+        name: "Low"
+        instruction: {
+          instruction_set: {
+            instructions: [
+              {
+                lock: {
+                  mutex { name: "lock1" }
+                }
+              },
+              {
+                cpu_work: {
+                  duration_us: 5000
+                }
+              },
+              {
+                unlock: {
+                  mutex { name: "lock1" }
+                }
+              }
+            ]
+          }
+          repeat: 100
+          period_us: 20000
+          offset_us: 0
+        }
+        sched_affinity: 1
+        sched_attr: {
+          rt: {
+            policy: FIFO
+            priority: 97
+          }
+        }
+      }
+    ]
+  }
+}
+global: {
+  mutex { name: "lock1" }
+}
diff --git a/example/priority_inversion_normal.ditto b/example/priority_inversion_normal.ditto
new file mode 100644
index 0000000..bcdae45
--- /dev/null
+++ b/example/priority_inversion_normal.ditto
@@ -0,0 +1,101 @@
+main: {
+  multithreading: {
+    threads: [
+      {
+        name: "High"
+        instruction: {
+          instruction_set: {
+            instructions: [
+              {
+                lock: {
+                  mutex { name: "lock1" }
+                }
+              },
+              {
+                cpu_work: {
+                  duration_us: 2000
+                }
+              },
+              {
+                unlock: {
+                  mutex { name: "lock1" }
+                }
+              }
+            ]
+          }
+          repeat: 100
+          period_us: 50000
+          offset_us: 1000
+        }
+        sched_affinity: 1
+        sched_attr: {
+          other: {
+            policy: OTHER
+            nice: -20
+          }
+        }
+      },
+      {
+        name: "Mid"
+        instruction: {
+          instruction_set: {
+            instructions: [
+              {
+                cpu_work: {
+                  duration_us: 10000
+                }
+              }
+            ]
+          }
+          repeat: 100
+          period_us: 30000
+          offset_us: 1500
+        }
+        sched_affinity: 1
+        sched_attr: {
+          other: {
+            policy: OTHER
+            nice: 0
+          }
+        }
+      },
+      {
+        name: "Low"
+        instruction: {
+          instruction_set: {
+            instructions: [
+              {
+                lock: {
+                  mutex { name: "lock1" }
+                }
+              },
+              {
+                cpu_work: {
+                  duration_us: 5000
+                }
+              },
+              {
+                unlock: {
+                  mutex { name: "lock1" }
+                }
+              }
+            ]
+          }
+          repeat: 100
+          period_us: 20000
+          offset_us: 0
+        }
+        sched_affinity: 1
+        sched_attr: {
+          other: {
+            policy: OTHER
+            nice: 19
+          }
+        }
+      }
+    ]
+  }
+}
+global: {
+  mutex { name: "lock1" }
+}
diff --git a/include/ditto/cpu_work.h b/include/ditto/cpu_work.h
index 79c4931..40356a3 100644
--- a/include/ditto/cpu_work.h
+++ b/include/ditto/cpu_work.h
@@ -40,6 +40,18 @@ class CpuWorkCycles : public CpuWork {
   void RunSingle() override;
 };
 
+class CpuWorkDurationUs : public CpuWork {
+ public:
+  inline static const std::string kName = "cpu_work_duration";
+
+  explicit CpuWorkDurationUs(const Params& params, uint64_t duration_us);
+
+ private:
+  timespec work_time_;
+
+  void RunSingle() override;
+};
+
 class CpuWorkUtilization : public CpuWork {
  public:
   inline static const std::string kName = "cpu_work_utilization";
@@ -47,7 +59,7 @@ class CpuWorkUtilization : public CpuWork {
   explicit CpuWorkUtilization(const Params& params, double utilization);
 
  private:
-  double utilization_;
+  timespec work_time_;
 
   void RunSingle() override;
 };
diff --git a/include/ditto/lock.h b/include/ditto/lock.h
new file mode 100644
index 0000000..29acd8c
--- /dev/null
+++ b/include/ditto/lock.h
@@ -0,0 +1,65 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#pragma once
+
+#include <mutex>
+#include <stack>
+
+#include <ditto/instruction.h>
+
+namespace dittosuite {
+
+class LockInterface : public Instruction {
+ protected:
+  pthread_mutex_t* mutex_;
+
+  LockInterface(const LockInterface&) = delete;
+  LockInterface& operator=(const LockInterface&) = delete;
+
+  LockInterface(const std::string& name, const Params& params, pthread_mutex_t* mutex);
+  virtual ~LockInterface() = default;
+};
+
+class Lock : public LockInterface {
+ public:
+  inline static const std::string kName = "lock";
+
+  Lock(const Lock&) = delete;
+  Lock& operator=(const Lock&) = delete;
+
+  explicit Lock(const Params& params, pthread_mutex_t* mutex);
+  ~Lock() = default;
+
+ private:
+  void SetUpSingle() override;
+  void RunSingle() override;
+};
+
+class Unlock : public LockInterface {
+ public:
+  inline static const std::string kName = "unlock";
+
+  Unlock(const Unlock&) = delete;
+  Unlock& operator=(const Unlock&) = delete;
+
+  explicit Unlock(const Params& params, pthread_mutex_t* mutex);
+  ~Unlock() = default;
+
+ private:
+  void SetUpSingle() override;
+  void RunSingle() override;
+};
+
+}  // namespace dittosuite
diff --git a/include/ditto/shared_variables.h b/include/ditto/shared_variables.h
index a948fc0..21e75c6 100644
--- a/include/ditto/shared_variables.h
+++ b/include/ditto/shared_variables.h
@@ -24,10 +24,12 @@ namespace dittosuite {
 
 class SharedVariables {
  public:
-  typedef std::variant<int, std::string, std::vector<std::string>> Variant;
+  typedef std::variant<int, std::string, pthread_mutex_t, std::vector<std::string>> Variant;
 
+  static bool Exists(const std::list<int>& thread_ids, const std::string& variable_name);
   static int GetKey(const std::list<int>& thread_ids, const std::string& variable_name);
   static Variant Get(int key);
+  static Variant* GetPointer(int key);
   static Variant Get(const std::list<int>& thread_ids, const std::string& variable_name);
   static void Set(int key, const Variant& value);
   static void Set(const std::list<int>& thread_ids, const std::string& variable_name,
diff --git a/include/ditto/syscall.h b/include/ditto/syscall.h
index 6f90483..2a80ef4 100644
--- a/include/ditto/syscall.h
+++ b/include/ditto/syscall.h
@@ -64,6 +64,8 @@ class SyscallInterface {
   virtual void Sync() = 0;
   virtual int Unlink(const std::string& path_name) = 0;
   virtual int64_t Write(int fd, char* buf, int64_t count, int64_t offset) = 0;
+  virtual int LockMutex(pthread_mutex_t* mutex) = 0;
+  virtual int UnlockMutex(pthread_mutex_t* mutex) = 0;
 };
 
 class Syscall : public SyscallInterface {
@@ -91,6 +93,8 @@ class Syscall : public SyscallInterface {
   void Sync() override;
   int Unlink(const std::string& path_name) override;
   int64_t Write(int fd, char* buf, int64_t count, int64_t offset) override;
+  int LockMutex(pthread_mutex_t* mutex) override;
+  int UnlockMutex(pthread_mutex_t* mutex) override;
 
  private:
   Syscall(){};
diff --git a/include/ditto/utils.h b/include/ditto/utils.h
index cd8d907..ffb10b0 100644
--- a/include/ditto/utils.h
+++ b/include/ditto/utils.h
@@ -19,6 +19,8 @@
 
 #include <ditto/syscall.h>
 
+bool operator==(const pthread_mutex_t& a, const pthread_mutex_t& b);
+
 namespace dittosuite {
 
 int64_t GetFileSize(SyscallInterface& syscall, int fd);
diff --git a/schema/benchmark.proto b/schema/benchmark.proto
index 3941360..167f27b 100644
--- a/schema/benchmark.proto
+++ b/schema/benchmark.proto
@@ -35,6 +35,7 @@ message CpuWork {
   oneof type {
     uint64 cycles = 1;
     double utilization = 2;
+    uint64 duration_us = 3;
   }
 }
 
@@ -164,6 +165,18 @@ message ReadDirectory {
   required string output = 2;
 }
 
+message Mutex {
+  optional string name = 1;
+}
+
+message Lock {
+  optional Mutex mutex = 1;
+}
+
+message Unlock {
+  optional Mutex mutex = 1;
+}
+
 message Thread {
   required Instruction instruction = 1;
   optional int32 spawn = 2 [default = 1];
@@ -232,6 +245,8 @@ message Instruction {
     BinderService binder_service = 14;
     CpuWork cpu_work = 16;
     MemoryAllocate mem_alloc = 17;
+    Lock lock = 19;
+    Unlock unlock = 20;
   };
   optional uint64 period_us = 15 [default = 0];
   optional uint64 offset_us = 18 [default = 0];
@@ -252,6 +267,7 @@ message InstructionSetIterate {
 
 message Global {
   optional string absolute_path = 1 [default = ""];
+  optional Mutex mutex = 2;
 }
 
 message Benchmark {
diff --git a/src/cpu_work.cpp b/src/cpu_work.cpp
index 5c34abd..6936b60 100644
--- a/src/cpu_work.cpp
+++ b/src/cpu_work.cpp
@@ -20,19 +20,30 @@ namespace dittosuite {
 
 CpuWork::CpuWork(const std::string& name, const Params& params) : Instruction(name, params) {}
 
+CpuWorkCycles::CpuWorkCycles(const Params& params, uint64_t cycles)
+    : CpuWork(kName, params), cycles_(cycles) {}
+
+void CpuWorkCycles::RunSingle() {
+  volatile int target = -1;
+
+  for (uint64_t counter = 0; counter < cycles_; ++counter) {
+    target = ~target;
+  }
+}
+
 CpuWorkUtilization::CpuWorkUtilization(const Params& params, double utilization)
-    : CpuWork(kName, params), utilization_(utilization) {
+    : CpuWork(kName, params) {
   if (utilization < 0 || utilization > 1) {
     LOGF("Utilization value must be in the range [0,1]");
   }
   if (params.period_us_ <= 0) {
     LOGF("The period of the instruction must be greater than 0");
   }
+  work_time_ = MicrosToTimespec(period_us_ * utilization);
 }
 
-void CpuWorkUtilization::RunSingle() {
-  timespec time_now, time_end, work_time;
-  work_time = MicrosToTimespec(period_us_ * utilization_);
+inline void threadWaitAbsoluteTime(const timespec& work_time) {
+  timespec time_now, time_end;
 
   if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &time_now)) {
     LOGF("Error getting current time");
@@ -47,15 +58,17 @@ void CpuWorkUtilization::RunSingle() {
   } while (time_now < time_end);
 }
 
-CpuWorkCycles::CpuWorkCycles(const Params& params, uint64_t cycles)
-    : CpuWork(kName, params), cycles_(cycles) {}
+void CpuWorkUtilization::RunSingle() {
+  threadWaitAbsoluteTime(work_time_);
+}
 
-void CpuWorkCycles::RunSingle() {
-  volatile int target = -1;
+CpuWorkDurationUs::CpuWorkDurationUs(const Params& params, uint64_t duration_us)
+    : CpuWork(kName, params) {
+  work_time_ = MicrosToTimespec(duration_us);
+}
 
-  for (uint64_t counter = 0; counter < cycles_; ++counter) {
-    target = ~target;
-  }
+void CpuWorkDurationUs::RunSingle() {
+  threadWaitAbsoluteTime(work_time_);
 }
 
 }  // namespace dittosuite
diff --git a/src/instruction_factory.cpp b/src/instruction_factory.cpp
index 6d4a8a1..d10aae6 100644
--- a/src/instruction_factory.cpp
+++ b/src/instruction_factory.cpp
@@ -26,6 +26,7 @@
 #include <ditto/delete_file.h>
 #include <ditto/instruction_set.h>
 #include <ditto/invalidate_cache.h>
+#include <ditto/lock.h>
 #include <ditto/logger.h>
 #include <ditto/memory_allocation.h>
 #include <ditto/multiprocessing.h>
@@ -49,7 +50,7 @@ std::unique_ptr<InstructionSet> InstructionFactory::CreateFromProtoInstructionSe
   std::vector<std::unique_ptr<Instruction>> instructions;
   for (const auto& instruction : proto_instruction_set.instructions()) {
     instructions.push_back(
-        std::move(InstructionFactory::CreateFromProtoInstruction(thread_ids, instruction)));
+        InstructionFactory::CreateFromProtoInstruction(thread_ids, instruction));
   }
 
   if (proto_instruction_set.has_iterate_options()) {
@@ -213,8 +214,8 @@ std::unique_ptr<Instruction> InstructionFactory::CreateFromProtoInstruction(
         for (int i = 0; i < thread.spawn(); i++) {
           auto thread_ids_copy = thread_ids;
           thread_ids_copy.push_back(InstructionFactory::GenerateThreadId());
-          instructions.push_back(std::move(InstructionFactory::CreateFromProtoInstruction(
-              thread_ids_copy, thread.instruction())));
+          instructions.push_back(InstructionFactory::CreateFromProtoInstruction(
+              thread_ids_copy, thread.instruction()));
 
           std::string thread_name;
           if (thread.has_name()) {
@@ -291,6 +292,10 @@ std::unique_ptr<Instruction> InstructionFactory::CreateFromProtoInstruction(
           return std::make_unique<CpuWorkUtilization>(instruction_params, options.utilization());
           break;
         }
+        case CpuWorkType::kDurationUs: {
+          return std::make_unique<CpuWorkDurationUs>(instruction_params, options.duration_us());
+          break;
+        }
         case CpuWorkType::TYPE_NOT_SET: {
           LOGF("No type specified for CpuWorkload");
           break;
@@ -304,6 +309,43 @@ std::unique_ptr<Instruction> InstructionFactory::CreateFromProtoInstruction(
       return std::make_unique<MemoryAllocation>(instruction_params, options.size(), free_policy);
       break;
     }
+    case InstructionType::kLock: {
+      const auto& options = proto_instruction.lock();
+
+      if (!options.has_mutex() || !options.mutex().has_name()) {
+        LOGF("Locking instruction must have a mutex and the mutex must be named");
+      }
+      if (!SharedVariables::Exists(thread_ids, options.mutex().name())) {
+        LOGF(
+            "Could not find mutex declaration. Mutexes must be declared in the global section of "
+            "the .ditto file");
+      }
+
+      auto mux_key = SharedVariables::GetKey(thread_ids, options.mutex().name());
+      auto mux = std::get_if<pthread_mutex_t>(SharedVariables::GetPointer(mux_key));
+
+      return std::make_unique<Lock>(instruction_params, mux);
+      break;
+    }
+    case InstructionType::kUnlock: {
+      const auto& options = proto_instruction.unlock();
+
+      if (!options.has_mutex() || !options.mutex().has_name()) {
+        LOGF("Locking instruction must have a mutex and the mutex must be named");
+      }
+
+      if (!SharedVariables::Exists(thread_ids, options.mutex().name())) {
+        LOGF(
+            "Could not find mutex declaration. Mutexes must be declared in the global section of "
+            "the .ditto file");
+      }
+
+      auto mux_key = SharedVariables::GetKey(thread_ids, options.mutex().name());
+      auto mux = std::get_if<pthread_mutex_t>(SharedVariables::GetPointer(mux_key));
+
+      return std::make_unique<Unlock>(instruction_params, mux);
+      break;
+    }
     case InstructionType::INSTRUCTION_ONEOF_NOT_SET: {
       LOGF("Instruction was not set in .ditto file");
       break;
diff --git a/src/instruction_set.cpp b/src/instruction_set.cpp
index 68997e3..d2a5079 100644
--- a/src/instruction_set.cpp
+++ b/src/instruction_set.cpp
@@ -84,6 +84,10 @@ void InstructionSet::RunSingle() {
                             LOGE("Input for InstructionSet is not iterable.");
                             exit(EXIT_FAILURE);
                           },
+                          [](pthread_mutex_t) {
+                            LOGE("Input for InstructionSet is not iterable.");
+                            exit(EXIT_FAILURE);
+                          },
                           [](const std::string&) {
                             LOGE("Input for InstructionSet is not iterable.");
                             exit(EXIT_FAILURE);
diff --git a/src/lock.cpp b/src/lock.cpp
new file mode 100644
index 0000000..4ee3a0c
--- /dev/null
+++ b/src/lock.cpp
@@ -0,0 +1,51 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include <ditto/logger.h>
+#include <ditto/shared_variables.h>
+#include <ditto/utils.h>
+
+#include <ditto/lock.h>
+
+namespace dittosuite {
+
+LockInterface::LockInterface(const std::string& name, const Params& params, pthread_mutex_t* mutex)
+    : Instruction(name, params), mutex_(mutex) {}
+
+Lock::Lock(const Params& params, pthread_mutex_t* mutex) : LockInterface(kName, params, mutex) {}
+
+void Lock::SetUpSingle() {
+  Instruction::SetUpSingle();
+}
+
+void Lock::RunSingle() {
+  if (syscall_.LockMutex(mutex_)) {
+    PLOGF("Cannot lock mutex");
+  }
+}
+
+Unlock::Unlock(const Params& params, pthread_mutex_t* mutex)
+    : LockInterface(kName, params, mutex) {}
+
+void Unlock::SetUpSingle() {
+  Instruction::SetUpSingle();
+}
+
+void Unlock::RunSingle() {
+  if (syscall_.UnlockMutex(mutex_)) {
+    PLOGF("Cannot unlock mutex");
+  }
+}
+
+}  // namespace dittosuite
diff --git a/src/multithreading.cpp b/src/multithreading.cpp
index 3f685dd..4bc84f0 100644
--- a/src/multithreading.cpp
+++ b/src/multithreading.cpp
@@ -35,7 +35,7 @@ void Multithreading::SetUpSingle() {
 void Multithreading::RunSingle() {
   pthread_barrier_init(&barrier_, NULL, instructions_.size());
   for (size_t i = 0; i < instructions_.size(); ++i) {
-    threads_.push_back(std::move(instructions_[i]->SpawnThread(&barrier_, thread_params_[i])));
+    threads_.push_back(instructions_[i]->SpawnThread(&barrier_, thread_params_[i]));
   }
 }
 
diff --git a/src/parser.cpp b/src/parser.cpp
index f7415fb..ac94b36 100644
--- a/src/parser.cpp
+++ b/src/parser.cpp
@@ -59,6 +59,15 @@ std::unique_ptr<dittosuiteproto::Benchmark> Parser::__Parse(
   SharedVariables::Set(absolute_path_key, benchmark->global().absolute_path());
   Instruction::SetAbsolutePathKey(absolute_path_key);
 
+  if (benchmark->global().has_mutex()) {
+    pthread_mutex_t mux_orig;
+
+    auto mutex_key = SharedVariables::GetKey(thread_ids, benchmark->global().mutex().name());
+    SharedVariables::Set(mutex_key, mux_orig);
+    pthread_mutex_t* mux = std::get_if<pthread_mutex_t>(SharedVariables::GetPointer(mutex_key));
+    pthread_mutex_init(mux, nullptr);
+  }
+
   if (benchmark->has_init()) {
     init_ = InstructionFactory::CreateFromProtoInstruction(thread_ids, benchmark->init());
   }
diff --git a/src/shared_variables.cpp b/src/shared_variables.cpp
index b27c2b6..97dd331 100644
--- a/src/shared_variables.cpp
+++ b/src/shared_variables.cpp
@@ -18,6 +18,16 @@
 
 namespace dittosuite {
 
+bool SharedVariables::Exists(const std::list<int>& thread_ids, const std::string& variable_name) {
+  for (auto it = thread_ids.rbegin(); it != thread_ids.rend(); ++it) {
+    if (keys_.find(*it) == keys_.end() || keys_[*it].find(variable_name) == keys_[*it].end()) {
+      continue;
+    }
+    return true;
+  }
+  return false;
+}
+
 // Matches variable_name to the integer key value.
 //
 // If variable_name already exists in the map for the current thread or parent threads,
@@ -42,6 +52,13 @@ int SharedVariables::GetKey(const std::list<int>& thread_ids, const std::string&
   return key;
 }
 
+SharedVariables::Variant* SharedVariables::GetPointer(int key) {
+  if (key < 0 || static_cast<unsigned int>(key) >= variables_.size()) {
+    LOGF("Shared variable with the provided key does not exist");
+  }
+  return &variables_[key];
+}
+
 SharedVariables::Variant SharedVariables::Get(int key) {
   if (key < 0 || static_cast<unsigned int>(key) >= variables_.size()) {
     LOGF("Shared variable with the provided key does not exist");
diff --git a/src/syscall.cpp b/src/syscall.cpp
index 288e59b..c3e4073 100644
--- a/src/syscall.cpp
+++ b/src/syscall.cpp
@@ -143,6 +143,14 @@ int64_t Syscall::Write(int fd, char* buf, int64_t count, int64_t offset) {
   return pwrite64(fd, buf, count, offset);
 }
 
+int Syscall::LockMutex(pthread_mutex_t* mutex) {
+  return pthread_mutex_lock(mutex);
+}
+
+int Syscall::UnlockMutex(pthread_mutex_t* mutex) {
+  return pthread_mutex_unlock(mutex);
+}
+
 std::string to_string(const SchedAttr__& attr) {
   std::stringstream ss;
   ss << "size: " << attr.size << ", policy: " << attr.sched_policy
diff --git a/src/utils.cpp b/src/utils.cpp
index 4d536c6..7463bbe 100644
--- a/src/utils.cpp
+++ b/src/utils.cpp
@@ -12,12 +12,16 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-#include <ditto/utils.h>
-
+#include <ditto/logger.h>
 #include <sys/param.h>
 #include <sys/stat.h>
+#include <cstring>
 
-#include <ditto/logger.h>
+#include <ditto/utils.h>
+
+bool operator==(const pthread_mutex_t& a, const pthread_mutex_t& b) {
+  return 0 == memcmp(&a, &b, sizeof(pthread_mutex_t));
+}
 
 namespace dittosuite {
 
diff --git a/test/include/mock_syscall.h b/test/include/mock_syscall.h
index 4019197..252c911 100644
--- a/test/include/mock_syscall.h
+++ b/test/include/mock_syscall.h
@@ -73,4 +73,6 @@ class MockSyscall : public dittosuite::SyscallInterface {
   MOCK_METHOD(void, Sync, (), (override));
   MOCK_METHOD(int, Unlink, (const std::string& path_name), (override));
   MOCK_METHOD(int64_t, Write, (int fd, char* buf, int64_t count, int64_t offset), (override));
+  MOCK_METHOD(int, LockMutex, (pthread_mutex_t*), (override));
+  MOCK_METHOD(int, UnlockMutex, (pthread_mutex_t*), (override));
 };
diff --git a/test/open_file_test.cpp b/test/open_file_test.cpp
index 18ec602..4b40133 100644
--- a/test/open_file_test.cpp
+++ b/test/open_file_test.cpp
@@ -48,7 +48,7 @@ TEST_P(OpenFileTest, FileCreatedWithVariable) {
   ASSERT_EQ(access(path.c_str(), F_OK), 0);
 }
 
-INSTANTIATE_TEST_CASE_P(OpenFileTestParametric, OpenFileTest,
-                        ::testing::Values(dittosuite::OpenFile::AccessMode::kReadOnly,
-                                          dittosuite::OpenFile::AccessMode::kWriteOnly,
-                                          dittosuite::OpenFile::AccessMode::kReadWrite));
+INSTANTIATE_TEST_SUITE_P(OpenFileTestParametric, OpenFileTest,
+                         ::testing::Values(dittosuite::OpenFile::AccessMode::kReadOnly,
+                                           dittosuite::OpenFile::AccessMode::kWriteOnly,
+                                           dittosuite::OpenFile::AccessMode::kReadWrite));
diff --git a/test/resize_file_test.cpp b/test/resize_file_test.cpp
index 934c3c3..f895d2d 100644
--- a/test/resize_file_test.cpp
+++ b/test/resize_file_test.cpp
@@ -60,7 +60,7 @@ TEST_P(ResizeFileTest, ResizeFileTestRun) {
   }
 }
 
-INSTANTIATE_TEST_CASE_P(ResizeFileTestParametric, ResizeFileTest,
-                        ::testing::Values(dittosuite::OpenFile::AccessMode::kReadOnly,
-                                          dittosuite::OpenFile::AccessMode::kWriteOnly,
-                                          dittosuite::OpenFile::AccessMode::kReadWrite));
+INSTANTIATE_TEST_SUITE_P(ResizeFileTestParametric, ResizeFileTest,
+                         ::testing::Values(dittosuite::OpenFile::AccessMode::kReadOnly,
+                                           dittosuite::OpenFile::AccessMode::kWriteOnly,
+                                           dittosuite::OpenFile::AccessMode::kReadWrite));
diff --git a/test/shared_variables_test.cpp b/test/shared_variables_test.cpp
index b6c3fb5..fbea76d 100644
--- a/test/shared_variables_test.cpp
+++ b/test/shared_variables_test.cpp
@@ -15,6 +15,7 @@
 #include <gtest/gtest.h>
 
 #include <ditto/shared_variables.h>
+#include <ditto/utils.h>
 
 using dittosuite::SharedVariables;
 
diff --git a/test/timespec_utils_test.cpp b/test/timespec_utils_test.cpp
index cfb22dc..25d05e0 100644
--- a/test/timespec_utils_test.cpp
+++ b/test/timespec_utils_test.cpp
@@ -44,10 +44,10 @@ TEST_P(TimeSpecConversion, MicrosToTimespec) {
   ASSERT_TRUE(MicrosToTimespec(std::get<0>(param)) == std::get<1>(param));
 }
 
-INSTANTIATE_TEST_CASE_P(TimeSpecConversionParametric, TimeSpecConversion,
-                        ::testing::Values(std::make_tuple(0, (timespec){0, 0}),
-                                          std::make_tuple(1e6, (timespec){1, 0}),
-                                          std::make_tuple(1, (timespec){0, 1000})));
+INSTANTIATE_TEST_SUITE_P(TimeSpecConversionParametric, TimeSpecConversion,
+                         ::testing::Values(std::make_tuple(0, (timespec){0, 0}),
+                                           std::make_tuple(1e6, (timespec){1, 0}),
+                                           std::make_tuple(1, (timespec){0, 1000})));
 
 TEST(TimespecUtilsTest, TimespecToNanosInverse) {
   for (const auto& ts0 : tss) {
```

