```diff
diff --git a/gtest_isolated/IsolateMain.cpp b/gtest_isolated/IsolateMain.cpp
index 4cadc34..1cd9c22 100644
--- a/gtest_isolated/IsolateMain.cpp
+++ b/gtest_isolated/IsolateMain.cpp
@@ -186,6 +186,8 @@ int IsolateMain(int argc, char** argv, char**) {
 
     android::gtest_extras::Isolate isolate(options, child_args);
     return_val = isolate.Run();
+  } else {
+    printf("%s\n", options.error().c_str());
   }
 
   for (auto child_arg : child_args) {
diff --git a/gtest_isolated/Options.cpp b/gtest_isolated/Options.cpp
index 0762d0b..1557d5e 100644
--- a/gtest_isolated/Options.cpp
+++ b/gtest_isolated/Options.cpp
@@ -79,30 +79,32 @@ const std::unordered_map<std::string, Options::ArgInfo> Options::kArgs = {
     {"gtest_format", {FLAG_NONE, &Options::SetBool}},
 };
 
-static void PrintError(const std::string& arg, std::string_view msg, bool from_env) {
+static std::string GetError(const std::string& arg, std::string_view msg, bool from_env) {
+  std::string error;
   if (from_env) {
     std::string variable(arg);
     std::transform(variable.begin(), variable.end(), variable.begin(),
                    [](char c) { return std::toupper(c); });
-    printf("env[%s] %s\n", variable.c_str(), msg.data());
+    error = "env[" + variable + "] ";
   } else if (arg[0] == '-') {
-    printf("%s %s\n", arg.c_str(), msg.data());
+    error = arg + " ";
   } else {
-    printf("--%s %s\n", arg.c_str(), msg.data());
+    error = "--" + arg + " ";
   }
+  return error + std::string(msg);
 }
 
 template <typename IntType>
 static bool GetNumeric(const std::string& arg, const std::string& value, IntType* numeric_value,
-                       bool from_env) {
+                       bool from_env, std::string& error) {
   auto result = std::from_chars(value.c_str(), value.c_str() + value.size(), *numeric_value, 10);
   if (result.ec == std::errc::result_out_of_range) {
-    PrintError(arg, std::string("value overflows (") + value + ")", from_env);
+    error = GetError(arg, std::string("value overflows (") + value + ")", from_env);
     return false;
   } else if (result.ec == std::errc::invalid_argument || result.ptr == nullptr ||
              *result.ptr != '\0') {
-    PrintError(arg, std::string("value is not formatted as a numeric value (") + value + ")",
-               from_env);
+    error = GetError(arg, std::string("value is not formatted as a numeric value (") + value + ")",
+                     from_env);
     return false;
   }
   return true;
@@ -117,11 +119,11 @@ bool Options::SetPrintTime(const std::string&, const std::string& value, bool) {
 
 bool Options::SetNumeric(const std::string& arg, const std::string& value, bool from_env) {
   uint64_t* numeric = &numerics_.find(arg)->second;
-  if (!GetNumeric<uint64_t>(arg, value, numeric, from_env)) {
+  if (!GetNumeric<uint64_t>(arg, value, numeric, from_env, error_)) {
     return false;
   }
   if (*numeric == 0) {
-    PrintError(arg, "requires a number greater than zero.", from_env);
+    error_ = GetError(arg, "requires a number greater than zero.", from_env);
     return false;
   }
   return true;
@@ -129,11 +131,11 @@ bool Options::SetNumeric(const std::string& arg, const std::string& value, bool
 
 bool Options::SetNumericEnvOnly(const std::string& arg, const std::string& value, bool from_env) {
   if (!from_env) {
-    PrintError(arg, "is only supported as an environment variable.", false);
+    error_ = GetError(arg, "is only supported as an environment variable.", false);
     return false;
   }
   uint64_t* numeric = &numerics_.find(arg)->second;
-  if (!GetNumeric<uint64_t>(arg, value, numeric, from_env)) {
+  if (!GetNumeric<uint64_t>(arg, value, numeric, from_env, error_)) {
     return false;
   }
   return true;
@@ -145,7 +147,7 @@ bool Options::SetBool(const std::string& arg, const std::string&, bool) {
 }
 
 bool Options::SetIterations(const std::string& arg, const std::string& value, bool from_env) {
-  if (!GetNumeric<int>(arg, value, &num_iterations_, from_env)) {
+  if (!GetNumeric<int>(arg, value, &num_iterations_, from_env, error_)) {
     return false;
   }
   return true;
@@ -158,22 +160,22 @@ bool Options::SetString(const std::string& arg, const std::string& value, bool)
 
 bool Options::SetXmlFile(const std::string& arg, const std::string& value, bool from_env) {
   if (value.substr(0, 4) != "xml:") {
-    PrintError(arg, "only supports an xml output file.", from_env);
+    error_ = GetError(arg, "only supports an xml output file.", from_env);
     return false;
   }
   std::string xml_file(value.substr(4));
   if (xml_file.empty()) {
-    PrintError(arg, "requires a file name after xml:", from_env);
+    error_ = GetError(arg, "requires a file name after xml:", from_env);
     return false;
   }
   // Need an absolute file.
   if (xml_file[0] != '/') {
     char* cwd = getcwd(nullptr, 0);
     if (cwd == nullptr) {
-      PrintError(arg,
-                 std::string("cannot get absolute pathname, getcwd() is failing: ") +
-                     strerror(errno) + '\n',
-                 from_env);
+      error_ = GetError(arg,
+                        std::string("cannot get absolute pathname, getcwd() is failing: ") +
+                            strerror(errno) + '\n',
+                        from_env);
       return false;
     }
     xml_file = std::string(cwd) + '/' + xml_file;
@@ -191,13 +193,13 @@ bool Options::SetXmlFile(const std::string& arg, const std::string& value, bool
 bool Options::HandleArg(const std::string& arg, const std::string& value, const ArgInfo& info,
                         bool from_env) {
   if (info.flags & FLAG_INCOMPATIBLE) {
-    PrintError(arg, "is not compatible with isolation runs.", from_env);
+    error_ = GetError(arg, "is not compatible with isolation runs.", from_env);
     return false;
   }
 
   if (info.flags & FLAG_TAKES_VALUE) {
     if ((info.flags & FLAG_REQUIRES_VALUE) && value.empty()) {
-      PrintError(arg, "requires an argument.", from_env);
+      error_ = GetError(arg, "requires an argument.", from_env);
       return false;
     }
 
@@ -205,7 +207,7 @@ bool Options::HandleArg(const std::string& arg, const std::string& value, const
       return false;
     }
   } else if (!value.empty()) {
-    PrintError(arg, "does not take an argument.", from_env);
+    error_ = GetError(arg, "does not take an argument.", from_env);
     return false;
   } else if (info.func != nullptr) {
     return (this->*(info.func))(arg, value, from_env);
@@ -230,7 +232,7 @@ static bool ReadFileToString(const std::string& file, std::string* contents) {
 bool Options::ProcessFlagfile(const std::string& file, std::vector<char*>* child_args) {
   std::string contents;
   if (!ReadFileToString(file, &contents)) {
-    printf("Unable to read data from file %s\n", file.c_str());
+    error_ = "Unable to read data from file " + file;
     return false;
   }
 
@@ -261,10 +263,10 @@ bool Options::ProcessFlagfile(const std::string& file, std::vector<char*>* child
 bool Options::ProcessSingle(const char* arg, std::vector<char*>* child_args, bool allow_flagfile) {
   if (strncmp("--", arg, 2) != 0) {
     if (arg[0] == '-') {
-      printf("Unknown argument: %s\n", arg);
+      error_ = std::string("Unknown argument: ") + arg;
       return false;
     } else {
-      printf("Unexpected argument '%s'\n", arg);
+      error_ = std::string("Unexpected argument '") + arg + "'";
       return false;
     }
   }
@@ -281,7 +283,7 @@ bool Options::ProcessSingle(const char* arg, std::vector<char*>* child_args, boo
   }
   auto entry = kArgs.find(name);
   if (entry == kArgs.end()) {
-    printf("Unknown argument: %s\n", arg);
+    error_ = std::string("Unknown argument: ") + arg;
     return false;
   }
 
@@ -297,7 +299,7 @@ bool Options::ProcessSingle(const char* arg, std::vector<char*>* child_args, boo
   // file and treat each line as a flag.
   if (name == "gtest_flagfile") {
     if (!allow_flagfile) {
-      printf("Argument: %s is not allowed in flag file.\n", arg);
+      error_ = std::string("Argument: ") + arg + " is not allowed in flag file.";
       return false;
     }
     if (!ProcessFlagfile(value, child_args)) {
@@ -361,13 +363,13 @@ bool Options::Process(const std::vector<const char*>& args, std::vector<char*>*
       if (*value == '\0') {
         // Get the next argument.
         if (i == args.size() - 1) {
-          printf("-j requires an argument.\n");
+          error_ = "-j requires an argument.";
           return false;
         }
         i++;
         value = args[i];
       }
-      if (!GetNumeric<size_t>("-j", value, &job_count_, false)) {
+      if (!GetNumeric<size_t>("-j", value, &job_count_, false, error_)) {
         return false;
       }
     } else {
diff --git a/gtest_isolated/Options.h b/gtest_isolated/Options.h
index ad51e18..0271575 100644
--- a/gtest_isolated/Options.h
+++ b/gtest_isolated/Options.h
@@ -37,6 +37,7 @@ class Options {
   size_t job_count() const { return job_count_; }
   int num_iterations() const { return num_iterations_; }
   bool stop_on_error() const { return stop_on_error_; }
+  const std::string& error() const { return error_; }
 
   uint64_t deadline_threshold_ms() const { return numerics_.at("deadline_threshold_ms"); }
   uint64_t slow_threshold_ms() const { return numerics_.at("slow_threshold_ms"); }
@@ -56,6 +57,7 @@ class Options {
   size_t job_count_;
   int num_iterations_;
   bool stop_on_error_;
+  std::string error_;
 
   std::unordered_map<std::string, bool> bools_;
   std::unordered_map<std::string, std::string> strings_;
diff --git a/gtest_isolated/tests/OptionsTest.cpp b/gtest_isolated/tests/OptionsTest.cpp
index 36f5bef..fcba164 100644
--- a/gtest_isolated/tests/OptionsTest.cpp
+++ b/gtest_isolated/tests/OptionsTest.cpp
@@ -23,7 +23,6 @@
 #include <vector>
 
 #include <android-base/file.h>
-#include <android-base/test_utils.h>
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 
@@ -53,39 +52,30 @@ class OptionsTest : public ::testing::Test {
 };
 
 TEST_F(OptionsTest, unknown_arg) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--unknown_arg"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("Unknown argument: --unknown_arg\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("Unknown argument: --unknown_arg", options.error());
 }
 
 TEST_F(OptionsTest, unknown_arg_single_dash) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "-unknown_arg"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("Unknown argument: -unknown_arg\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("Unknown argument: -unknown_arg", options.error());
 }
 
 TEST_F(OptionsTest, extra_arg) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "extra"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("Unexpected argument 'extra'\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("Unexpected argument 'extra'", options.error());
 }
 
 TEST_F(OptionsTest, check_defaults) {
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_LT(0U, options.job_count());
   EXPECT_EQ(90000ULL, options.deadline_threshold_ms());
   EXPECT_EQ(2000ULL, options.slow_threshold_ms());
@@ -105,25 +95,22 @@ TEST_F(OptionsTest, check_defaults) {
 TEST_F(OptionsTest, gtest_list_tests) {
   std::vector<const char*> cur_args{"ignore", "--gtest_list_tests"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_TRUE(options.list_tests());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 }
 
 TEST_F(OptionsTest, gtest_list_tests_error_argument) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--gtest_list_tests=nothing"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_list_tests does not take an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_list_tests does not take an argument.", options.error());
 }
 
 TEST_F(OptionsTest, job_count_single_arg) {
   std::vector<const char*> cur_args{"ignore", "-j11"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ(11U, options.job_count());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 }
@@ -131,116 +118,89 @@ TEST_F(OptionsTest, job_count_single_arg) {
 TEST_F(OptionsTest, job_count_second_arg) {
   std::vector<const char*> cur_args{"ignore", "-j", "23"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ(23U, options.job_count());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 }
 
 TEST_F(OptionsTest, job_count_error_single_arg) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "-j0bad"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("-j value is not formatted as a numeric value (0bad)\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("-j value is not formatted as a numeric value (0bad)", options.error());
 }
 
 TEST_F(OptionsTest, job_count_error_second_arg) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "-j", "34b"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("-j value is not formatted as a numeric value (34b)\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("-j value is not formatted as a numeric value (34b)", options.error());
 }
 
 TEST_F(OptionsTest, job_count_error_no_arg) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "-j"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("-j requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("-j requires an argument.", options.error());
 }
 
 TEST_F(OptionsTest, deadline_threshold_ms) {
   std::vector<const char*> cur_args{"ignore", "--deadline_threshold_ms=3200"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ(3200ULL, options.deadline_threshold_ms());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 }
 
 TEST_F(OptionsTest, deadline_threshold_ms_error_no_value) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--deadline_threshold_ms"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--deadline_threshold_ms requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--deadline_threshold_ms requires an argument.", options.error());
 }
 
 TEST_F(OptionsTest, deadline_threshold_ms_error_not_a_number) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--deadline_threshold_ms=bad"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--deadline_threshold_ms value is not formatted as a numeric value (bad)\n",
-            capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--deadline_threshold_ms value is not formatted as a numeric value (bad)",
+            options.error());
 }
 
 TEST_F(OptionsTest, deadline_threshold_ms_error_illegal_value) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--deadline_threshold_ms=0"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--deadline_threshold_ms requires a number greater than zero.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--deadline_threshold_ms requires a number greater than zero.", options.error());
 }
 
 TEST_F(OptionsTest, slow_threshold_ms) {
   std::vector<const char*> cur_args{"ignore", "--slow_threshold_ms=4580"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ(4580ULL, options.slow_threshold_ms());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 }
 
 TEST_F(OptionsTest, slow_threshold_ms_error_no_value) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--slow_threshold_ms"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--slow_threshold_ms requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--slow_threshold_ms requires an argument.", options.error());
 }
 
 TEST_F(OptionsTest, slow_threshold_ms_error_not_a_number) {
-  CapturedStdout capture;
   Options options;
   std::vector<const char*> cur_args{"ignore", "--slow_threshold_ms=not"};
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--slow_threshold_ms value is not formatted as a numeric value (not)\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--slow_threshold_ms value is not formatted as a numeric value (not)", options.error());
 }
 
 TEST_F(OptionsTest, slow_threshold_ms_error_illegal_value) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--slow_threshold_ms=0"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--slow_threshold_ms requires a number greater than zero.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--slow_threshold_ms requires a number greater than zero.", options.error());
 }
 
 TEST_F(OptionsTest, shard_index) {
@@ -248,13 +208,13 @@ TEST_F(OptionsTest, shard_index) {
 
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ(100ULL, options.shard_index());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
   ClearChildArgs();
   ASSERT_NE(-1, setenv("GTEST_SHARD_INDEX", "0", 1));
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ(0ULL, options.shard_index());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
@@ -264,13 +224,10 @@ TEST_F(OptionsTest, shard_index) {
 TEST_F(OptionsTest, shard_index_error_no_value) {
   ASSERT_NE(-1, setenv("GTEST_SHARD_INDEX", "", 1));
 
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_SHARD_INDEX] requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_SHARD_INDEX] requires an argument.", options.error());
 
   ASSERT_NE(-1, unsetenv("GTEST_SHARD_INDEX"));
 }
@@ -278,26 +235,20 @@ TEST_F(OptionsTest, shard_index_error_no_value) {
 TEST_F(OptionsTest, shard_index_error_not_a_number) {
   ASSERT_NE(-1, setenv("GTEST_SHARD_INDEX", "bad", 1));
 
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_SHARD_INDEX] value is not formatted as a numeric value (bad)\n",
-            capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_SHARD_INDEX] value is not formatted as a numeric value (bad)",
+            options.error());
 
   ASSERT_NE(-1, unsetenv("GTEST_SHARD_INDEX"));
 }
 
 TEST_F(OptionsTest, shard_index_error_not_from_env) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--gtest_shard_index=100"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_shard_index is only supported as an environment variable.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_shard_index is only supported as an environment variable.", options.error());
 }
 
 TEST_F(OptionsTest, total_shards) {
@@ -305,13 +256,13 @@ TEST_F(OptionsTest, total_shards) {
 
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ(500ULL, options.total_shards());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
   ClearChildArgs();
   ASSERT_NE(-1, setenv("GTEST_TOTAL_SHARDS", "0", 1));
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ(0ULL, options.total_shards());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
@@ -321,13 +272,10 @@ TEST_F(OptionsTest, total_shards) {
 TEST_F(OptionsTest, total_shards_error_no_value) {
   ASSERT_NE(-1, setenv("GTEST_TOTAL_SHARDS", "", 1));
 
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_TOTAL_SHARDS] requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_TOTAL_SHARDS] requires an argument.", options.error());
 
   ASSERT_NE(-1, unsetenv("GTEST_TOTAL_SHARDS"));
 }
@@ -335,141 +283,116 @@ TEST_F(OptionsTest, total_shards_error_no_value) {
 TEST_F(OptionsTest, total_shards_error_not_a_number) {
   ASSERT_NE(-1, setenv("GTEST_TOTAL_SHARDS", "bad", 1));
 
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_TOTAL_SHARDS] value is not formatted as a numeric value (bad)\n",
-            capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_TOTAL_SHARDS] value is not formatted as a numeric value (bad)",
+            options.error());
 
   ASSERT_NE(-1, unsetenv("GTEST_TOTAL_SHARDS"));
 }
 
 TEST_F(OptionsTest, total_shards_error_not_from_env) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--gtest_total_shards=100"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_total_shards is only supported as an environment variable.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_total_shards is only supported as an environment variable.", options.error());
 }
 
 TEST_F(OptionsTest, gtest_color) {
   std::vector<const char*> cur_args{"ignore", "--gtest_color=yes"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ("yes", options.color());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore"), StrEq("--gtest_color=yes")));
 }
 
 TEST_F(OptionsTest, gtest_color_error_no_value) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--gtest_color="};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_color requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_color requires an argument.", options.error());
 }
 
 TEST_F(OptionsTest, gtest_filter) {
   std::vector<const char*> cur_args{"ignore", "--gtest_filter=filter"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ("filter", options.filter());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 }
 
 TEST_F(OptionsTest, gtest_filter_error_no_value) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--gtest_filter"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_filter requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_filter requires an argument.", options.error());
 }
 
 TEST_F(OptionsTest, gtest_also_run_disabled_tests) {
   std::vector<const char*> cur_args{"ignore", "--gtest_also_run_disabled_tests"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_TRUE(options.allow_disabled_tests());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore"), StrEq("--gtest_also_run_disabled_tests")));
 }
 
 TEST_F(OptionsTest, gtest_also_run_disabled_tests_error_argument) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--gtest_also_run_disabled_tests=nothing"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_also_run_disabled_tests does not take an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_also_run_disabled_tests does not take an argument.", options.error());
 }
 
 TEST_F(OptionsTest, gtest_repeat) {
   std::vector<const char*> cur_args{"ignore", "--gtest_repeat=10"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ(10, options.num_iterations());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
   ClearChildArgs();
   cur_args = std::vector<const char*>{"ignore", "--gtest_repeat=-1"};
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ(-1, options.num_iterations());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 }
 
 TEST_F(OptionsTest, gtest_repeat_error_no_value) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--gtest_repeat"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_repeat requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_repeat requires an argument.", options.error());
 }
 
 TEST_F(OptionsTest, gtest_repeat_error_overflow) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--gtest_repeat=2147483747"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_repeat value overflows (2147483747)\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_repeat value overflows (2147483747)", options.error());
 
   ClearChildArgs();
-  capture.Reset();
-  capture.Start();
   cur_args = std::vector<const char*>{"ignore", "--gtest_repeat=-2147483747"};
-  parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_repeat value overflows (-2147483747)\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_repeat value overflows (-2147483747)", options.error());
 }
 
 TEST_F(OptionsTest, gtest_print_time) {
   std::vector<const char*> cur_args{"ignore", "--gtest_print_time"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_TRUE(options.print_time());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
   ClearChildArgs();
   cur_args = std::vector<const char*>{"ignore", "--gtest_print_time=0"};
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_FALSE(options.print_time());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
   ClearChildArgs();
   cur_args = std::vector<const char*>{"ignore", "--gtest_print_time=1"};
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_TRUE(options.print_time());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 }
@@ -477,19 +400,19 @@ TEST_F(OptionsTest, gtest_print_time) {
 TEST_F(OptionsTest, gtest_output) {
   std::vector<const char*> cur_args{"ignore", "--gtest_output=xml:/file.xml"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ("/file.xml", options.xml_file());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
   ClearChildArgs();
   cur_args = std::vector<const char*>{"ignore", "--gtest_output=xml:/directory/"};
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ("/directory/test_details.xml", options.xml_file());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
   ClearChildArgs();
   cur_args = std::vector<const char*>{"ignore", "--gtest_output=xml:cwd.xml"};
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   char* cwd = getcwd(nullptr, 0);
   std::string expected_file(cwd);
   expected_file += "/cwd.xml";
@@ -499,50 +422,37 @@ TEST_F(OptionsTest, gtest_output) {
 }
 
 TEST_F(OptionsTest, gtest_output_error_no_value) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--gtest_output"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_output requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_output requires an argument.", options.error());
 }
 
 TEST_F(OptionsTest, gtest_output_error_no_xml) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--gtest_output=xml:"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_output requires a file name after xml:\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_output requires a file name after xml:", options.error());
 
   ClearChildArgs();
-  capture.Reset();
-  capture.Start();
   cur_args = std::vector<const char*>{"ignore", "--gtest_output=not_xml"};
-  parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_output only supports an xml output file.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_output only supports an xml output file.", options.error());
 }
 
 TEST_F(OptionsTest, gtest_death_test_style) {
   std::vector<const char*> cur_args{"ignore", "--gtest_death_test_style=something"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_THAT(child_args_,
               ElementsAre(StrEq("ignore"), StrEq("--gtest_death_test_style=something")));
 }
 
 TEST_F(OptionsTest, gtest_death_test_style_error_no_value) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--gtest_death_test_style"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("--gtest_death_test_style requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("--gtest_death_test_style requires an argument.", options.error());
 }
 
 TEST_F(OptionsTest, gtest_flagfile) {
@@ -558,7 +468,7 @@ TEST_F(OptionsTest, gtest_flagfile) {
   flag += tf.path;
   std::vector<const char*> cur_args{"ignore", flag.c_str()};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ("no", options.color());
   EXPECT_FALSE(options.print_time());
   EXPECT_EQ(10, options.num_iterations());
@@ -573,7 +483,7 @@ TEST_F(OptionsTest, gtest_flagfile_no_newline) {
   flag += tf.path;
   std::vector<const char*> cur_args{"ignore", flag.c_str()};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ("no", options.color());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore"), StrEq("--gtest_color=no")));
 }
@@ -585,7 +495,7 @@ TEST_F(OptionsTest, gtest_flagfile_empty_file) {
   flag += tf.path;
   std::vector<const char*> cur_args{"ignore", flag.c_str()};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 }
 
@@ -593,71 +503,60 @@ TEST_F(OptionsTest, gtest_flagfile_disallow_j_option) {
   TemporaryFile tf;
   ASSERT_TRUE(android::base::WriteStringToFile("-j1\n", tf.path));
 
-  CapturedStdout capture;
   std::string flag("--gtest_flagfile=");
   flag += tf.path;
   std::vector<const char*> cur_args{"ignore", flag.c_str()};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("Unknown argument: -j1\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("Unknown argument: -j1", options.error());
 }
 
 TEST_F(OptionsTest, gtest_flagfile_disallow_gtest_flagfile_option_in_file) {
   TemporaryFile tf;
   ASSERT_TRUE(android::base::WriteStringToFile("--gtest_flagfile=nothing\n", tf.path));
 
-  CapturedStdout capture;
   std::string flag("--gtest_flagfile=");
   flag += tf.path;
   std::vector<const char*> cur_args{"ignore", flag.c_str()};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("Argument: --gtest_flagfile=nothing is not allowed in flag file.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("Argument: --gtest_flagfile=nothing is not allowed in flag file.", options.error());
 }
 
 TEST_F(OptionsTest, gtest_flagfile_does_not_exist) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", "--gtest_flagfile=/this/does/not/exist"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("Unable to read data from file /this/does/not/exist\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("Unable to read data from file /this/does/not/exist", options.error());
 }
 
 TEST_F(OptionsTest, stop_on_error) {
   std::vector<const char*> cur_args{"ignore", "--gtest_break_on_failure"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_TRUE(options.stop_on_error());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
   ClearChildArgs();
   cur_args = std::vector<const char*>{"ignore", "--gtest_throw_on_failure"};
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_TRUE(options.stop_on_error());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
   ClearChildArgs();
   cur_args =
       std::vector<const char*>{"ignore", "--gtest_break_on_failure", "--gtest_throw_on_failure"};
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_TRUE(options.stop_on_error());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 }
 
 void OptionsTest::CheckIncompatible(const std::string arg) {
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore", arg.c_str()};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly for arg " + arg;
-  EXPECT_EQ(arg + " is not compatible with isolation runs.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_))
+      << "Process did not fail properly for arg " + arg;
+  EXPECT_EQ(arg + " is not compatible with isolation runs.", options.error());
 }
 
 TEST_F(OptionsTest, incompatible) {
@@ -675,7 +574,7 @@ TEST_F(OptionsTest, verify_non_env_variables) {
 
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  EXPECT_TRUE(options.Process(cur_args, &child_args_));
+  EXPECT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_LT(0U, options.job_count());
   EXPECT_EQ(90000ULL, options.deadline_threshold_ms());
   EXPECT_EQ(2000ULL, options.slow_threshold_ms());
@@ -700,7 +599,7 @@ TEST_F(OptionsTest, gtest_filter_from_env) {
 
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  EXPECT_TRUE(options.Process(cur_args, &child_args_));
+  EXPECT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ("filter_value", options.filter());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
@@ -710,13 +609,10 @@ TEST_F(OptionsTest, gtest_filter_from_env) {
 TEST_F(OptionsTest, gtest_filter_error_no_value_from_env) {
   ASSERT_NE(-1, setenv("GTEST_FILTER", "", 1));
 
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_FILTER] requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_FILTER] requires an argument.", options.error());
 
   ASSERT_NE(-1, unsetenv("GTEST_FILTER"));
 }
@@ -726,7 +622,7 @@ TEST_F(OptionsTest, gtest_also_run_disabled_tests_from_env) {
 
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_TRUE(options.allow_disabled_tests());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
@@ -736,13 +632,10 @@ TEST_F(OptionsTest, gtest_also_run_disabled_tests_from_env) {
 TEST_F(OptionsTest, gtest_also_run_disabled_tests_error_argument_from_env) {
   ASSERT_NE(-1, setenv("GTEST_ALSO_RUN_DISABLED_TESTS", "one", 1));
 
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_ALSO_RUN_DISABLED_TESTS] does not take an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_ALSO_RUN_DISABLED_TESTS] does not take an argument.", options.error());
 
   ASSERT_NE(-1, unsetenv("GTEST_ALSO_RUN_DISABLED_TESTS"));
 }
@@ -752,7 +645,7 @@ TEST_F(OptionsTest, gtest_repeat_from_env) {
 
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ(34, options.num_iterations());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
@@ -762,13 +655,10 @@ TEST_F(OptionsTest, gtest_repeat_from_env) {
 TEST_F(OptionsTest, gtest_repeat_error_no_value_from_env) {
   ASSERT_NE(-1, setenv("GTEST_REPEAT", "", 1));
 
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_REPEAT] requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_REPEAT] requires an argument.", options.error());
 
   ASSERT_NE(-1, unsetenv("GTEST_REPEAT"));
 }
@@ -776,23 +666,16 @@ TEST_F(OptionsTest, gtest_repeat_error_no_value_from_env) {
 TEST_F(OptionsTest, gtest_repeat_error_overflow_from_env) {
   ASSERT_NE(-1, setenv("GTEST_REPEAT", "2147483747", 1));
 
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_REPEAT] value overflows (2147483747)\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_REPEAT] value overflows (2147483747)", options.error());
 
   ASSERT_NE(-1, setenv("GTEST_REPEAT", "-2147483747", 1));
 
   ClearChildArgs();
-  capture.Reset();
-  capture.Start();
-  parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_REPEAT] value overflows (-2147483747)\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_REPEAT] value overflows (-2147483747)", options.error());
 
   ASSERT_NE(-1, unsetenv("GTEST_REPEAT"));
 }
@@ -803,7 +686,7 @@ TEST_F(OptionsTest, gtest_color_from_env) {
   std::vector<const char*> cur_args{"ignore"};
   std::vector<const char*> child_args;
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ("yes", options.color());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
@@ -813,12 +696,10 @@ TEST_F(OptionsTest, gtest_color_from_env) {
 TEST_F(OptionsTest, gtest_color_error_no_value_from_env) {
   ASSERT_NE(-1, setenv("GTEST_COLOR", "", 1));
 
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_COLOR] requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_COLOR] requires an argument.", options.error());
 
   ASSERT_NE(-1, unsetenv("GTEST_COLOR"));
 }
@@ -828,7 +709,7 @@ TEST_F(OptionsTest, gtest_print_time_from_env) {
 
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_FALSE(options.print_time());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
@@ -840,7 +721,7 @@ TEST_F(OptionsTest, gtest_print_time_no_value_from_env) {
 
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_TRUE(options.print_time());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
@@ -852,7 +733,7 @@ TEST_F(OptionsTest, gtest_output_from_env) {
 
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_EQ("/file.xml", options.xml_file());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
@@ -862,13 +743,10 @@ TEST_F(OptionsTest, gtest_output_from_env) {
 TEST_F(OptionsTest, gtest_output_error_no_value_from_env) {
   ASSERT_NE(-1, setenv("GTEST_OUTPUT", "", 1));
 
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_OUTPUT] requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_OUTPUT] requires an argument.", options.error());
 
   ASSERT_NE(-1, unsetenv("GTEST_OUTPUT"));
 }
@@ -876,23 +754,16 @@ TEST_F(OptionsTest, gtest_output_error_no_value_from_env) {
 TEST_F(OptionsTest, gtest_output_error_no_xml_from_env) {
   ASSERT_NE(-1, setenv("GTEST_OUTPUT", "xml:", 1));
 
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_OUTPUT] requires a file name after xml:\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_OUTPUT] requires a file name after xml:", options.error());
 
   ASSERT_NE(-1, setenv("GTEST_OUTPUT", "not_xml", 1));
 
   ClearChildArgs();
-  capture.Reset();
-  capture.Start();
-  parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_OUTPUT] only supports an xml output file.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_OUTPUT] only supports an xml output file.", options.error());
 
   ASSERT_NE(-1, unsetenv("GTEST_OUTPUT"));
 }
@@ -902,7 +773,7 @@ TEST_F(OptionsTest, gtest_death_test_style_from_env) {
 
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
   ASSERT_NE(-1, unsetenv("GTEST_DEATH_TEST_STYLE"));
@@ -911,13 +782,10 @@ TEST_F(OptionsTest, gtest_death_test_style_from_env) {
 TEST_F(OptionsTest, gtest_death_test_style_error_no_value_from_env) {
   ASSERT_NE(-1, setenv("GTEST_DEATH_TEST_STYLE", "", 1));
 
-  CapturedStdout capture;
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly.";
-  EXPECT_EQ("env[GTEST_DEATH_TEST_STYLE] requires an argument.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_)) << "Process did not fail properly.";
+  EXPECT_EQ("env[GTEST_DEATH_TEST_STYLE] requires an argument.", options.error());
 
   ASSERT_NE(-1, unsetenv("GTEST_DEATH_TEST_STYLE"));
 }
@@ -927,7 +795,7 @@ TEST_F(OptionsTest, stop_on_error_from_env) {
 
   std::vector<const char*> cur_args{"ignore"};
   Options options;
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_TRUE(options.stop_on_error());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
@@ -936,7 +804,7 @@ TEST_F(OptionsTest, stop_on_error_from_env) {
   ASSERT_NE(-1, setenv("GTEST_THROW_ON_FAILURE", "", 1));
 
   ClearChildArgs();
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_TRUE(options.stop_on_error());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
@@ -946,7 +814,7 @@ TEST_F(OptionsTest, stop_on_error_from_env) {
   ASSERT_NE(-1, setenv("GTEST_THROW_ON_FAILURE", "", 1));
 
   ClearChildArgs();
-  ASSERT_TRUE(options.Process(cur_args, &child_args_));
+  ASSERT_TRUE(options.Process(cur_args, &child_args_)) << options.error();
   EXPECT_TRUE(options.stop_on_error());
   EXPECT_THAT(child_args_, ElementsAre(StrEq("ignore")));
 
@@ -957,23 +825,18 @@ TEST_F(OptionsTest, stop_on_error_from_env) {
 void OptionsTest::CheckIncompatibleFromEnv(const std::string env_var) {
   ASSERT_NE(-1, setenv(env_var.c_str(), "", 1));
 
-  CapturedStdout capture;
   Options options;
   std::vector<const char*> cur_args{"ignore"};
-  bool parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly for env var " + env_var;
-  EXPECT_EQ("env[" + env_var + "] is not compatible with isolation runs.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_))
+      << "Process did not fail properly for env var " + env_var;
+  EXPECT_EQ("env[" + env_var + "] is not compatible with isolation runs.", options.error());
 
   ASSERT_NE(-1, setenv(env_var.c_str(), "not_empty", 1));
 
   ClearChildArgs();
-  capture.Reset();
-  capture.Start();
-  parsed = options.Process(cur_args, &child_args_);
-  capture.Stop();
-  ASSERT_FALSE(parsed) << "Process did not fail properly for env var " + env_var;
-  EXPECT_EQ("env[" + env_var + "] is not compatible with isolation runs.\n", capture.str());
+  ASSERT_FALSE(options.Process(cur_args, &child_args_))
+      << "Process did not fail properly for env var " + env_var;
+  EXPECT_EQ("env[" + env_var + "] is not compatible with isolation runs.", options.error());
 
   ASSERT_NE(-1, unsetenv(env_var.c_str()));
 }
```

