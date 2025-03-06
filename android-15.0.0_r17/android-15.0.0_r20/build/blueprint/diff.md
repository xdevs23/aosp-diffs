```diff
diff --git a/Android.bp b/Android.bp
index 04d75fb..8ab0460 100644
--- a/Android.bp
+++ b/Android.bp
@@ -35,6 +35,7 @@ license {
 bootstrap_go_package {
     name: "blueprint",
     deps: [
+        "blueprint-gobtools",
         "blueprint-metrics",
         "blueprint-parser",
         "blueprint-pathtools",
@@ -151,6 +152,7 @@ bootstrap_go_package {
         "proptools/filter.go",
         "proptools/hash_provider.go",
         "proptools/proptools.go",
+        "proptools/repack.go",
         "proptools/tag.go",
         "proptools/typeequal.go",
         "proptools/unpack.go",
@@ -163,6 +165,7 @@ bootstrap_go_package {
         "proptools/extend_test.go",
         "proptools/filter_test.go",
         "proptools/hash_provider_test.go",
+        "proptools/repack_test.go",
         "proptools/tag_test.go",
         "proptools/typeequal_test.go",
         "proptools/unpack_test.go",
@@ -222,20 +225,11 @@ blueprint_go_binary {
     deps: ["blueprint-parser"],
     srcs: ["bpfmt/bpfmt.go"],
     visibility: [
+        "//development/tools/cargo_embargo",
         "//tools/external_updater",
     ],
 }
 
-blueprint_go_binary {
-    name: "bpmodify",
-    deps: [
-        "blueprint-parser",
-        "blueprint-proptools",
-    ],
-    srcs: ["bpmodify/bpmodify.go"],
-    testSrcs: ["bpmodify/bpmodify_test.go"],
-}
-
 blueprint_go_binary {
     name: "gotestmain",
     srcs: ["gotestmain/gotestmain.go"],
diff --git a/bootstrap/bootstrap.go b/bootstrap/bootstrap.go
index 73c8f8b..223742e 100644
--- a/bootstrap/bootstrap.go
+++ b/bootstrap/bootstrap.go
@@ -17,13 +17,13 @@ package bootstrap
 import (
 	"encoding/json"
 	"fmt"
-	"os"
 	"path/filepath"
 	"runtime"
 	"strings"
 
 	"github.com/google/blueprint"
 	"github.com/google/blueprint/pathtools"
+	"github.com/google/blueprint/proptools"
 )
 
 var (
@@ -104,6 +104,22 @@ var (
 		},
 		"depfile", "generator")
 
+	cat = pctx.StaticRule("Cat",
+		blueprint.RuleParams{
+			Command:     "rm -f $out && cat $in > $out",
+			Description: "concatenate files to $out",
+		})
+
+	// ubuntu 14.04 offcially use dash for /bin/sh, and its builtin echo command
+	// doesn't support -e option. Therefore we force to use /bin/bash when writing out
+	// content to file.
+	writeFile = pctx.StaticRule("writeFile",
+		blueprint.RuleParams{
+			Command:     `rm -f $out && /bin/bash -c 'echo -e -n "$$0" > $out' $content`,
+			Description: "writing file $out",
+		},
+		"content")
+
 	generateBuildNinja = pctx.StaticRule("build.ninja",
 		blueprint.RuleParams{
 			// TODO: it's kinda ugly that some parameters are computed from
@@ -141,6 +157,71 @@ var (
 	})
 )
 
+var (
+	// echoEscaper escapes a string such that passing it to "echo -e" will produce the input value.
+	echoEscaper = strings.NewReplacer(
+		`\`, `\\`, // First escape existing backslashes so they aren't interpreted by `echo -e`.
+		"\n", `\n`, // Then replace newlines with \n
+	)
+)
+
+// shardString takes a string and returns a slice of strings where the length of each one is
+// at most shardSize.
+func shardString(s string, shardSize int) []string {
+	if len(s) == 0 {
+		return nil
+	}
+	ret := make([]string, 0, (len(s)+shardSize-1)/shardSize)
+	for len(s) > shardSize {
+		ret = append(ret, s[0:shardSize])
+		s = s[shardSize:]
+	}
+	if len(s) > 0 {
+		ret = append(ret, s)
+	}
+	return ret
+}
+
+// writeFileRule creates a ninja rule to write contents to a file.  The contents will be
+// escaped so that the file contains exactly the contents passed to the function.
+func writeFileRule(ctx blueprint.ModuleContext, outputFile string, content string) {
+	// This is MAX_ARG_STRLEN subtracted with some safety to account for shell escapes
+	const SHARD_SIZE = 131072 - 10000
+
+	buildWriteFileRule := func(outputFile string, content string) {
+		content = echoEscaper.Replace(content)
+		content = proptools.NinjaEscape(proptools.ShellEscapeIncludingSpaces(content))
+		if content == "" {
+			content = "''"
+		}
+		ctx.Build(pctx, blueprint.BuildParams{
+			Rule:        writeFile,
+			Outputs:     []string{outputFile},
+			Description: "write " + outputFile,
+			Args: map[string]string{
+				"content": content,
+			},
+		})
+	}
+
+	if len(content) > SHARD_SIZE {
+		var chunks []string
+		for i, c := range shardString(content, SHARD_SIZE) {
+			tempPath := fmt.Sprintf("%s.%d", outputFile, i)
+			buildWriteFileRule(tempPath, c)
+			chunks = append(chunks, tempPath)
+		}
+		ctx.Build(pctx, blueprint.BuildParams{
+			Rule:        cat,
+			Inputs:      chunks,
+			Outputs:     []string{outputFile},
+			Description: "Merging to " + outputFile,
+		})
+		return
+	}
+	buildWriteFileRule(outputFile, content)
+}
+
 type pluginDependencyTag struct {
 	blueprint.BaseDependencyTag
 }
@@ -220,34 +301,20 @@ func (g *GoPackage) Properties() []interface{} {
 }
 
 func (g *GoPackage) DynamicDependencies(ctx blueprint.DynamicDependerModuleContext) []string {
-	if ctx.Module() != ctx.PrimaryModule() {
-		return nil
-	}
 	return g.properties.Deps
 }
 
 func (g *GoPackage) bootstrapDeps(ctx blueprint.BottomUpMutatorContext) {
-	if ctx.PrimaryModule() == ctx.Module() {
-		for _, plugin := range g.properties.PluginFor {
-			ctx.AddReverseDependency(ctx.Module(), pluginDepTag, plugin)
-		}
-		blueprint.SetProvider(ctx, DocsPackageProvider, &DocsPackageInfo{
-			PkgPath: g.properties.PkgPath,
-			Srcs:    g.properties.Srcs,
-		})
+	for _, plugin := range g.properties.PluginFor {
+		ctx.AddReverseDependency(ctx.Module(), pluginDepTag, plugin)
 	}
+	blueprint.SetProvider(ctx, DocsPackageProvider, &DocsPackageInfo{
+		PkgPath: g.properties.PkgPath,
+		Srcs:    g.properties.Srcs,
+	})
 }
 
 func (g *GoPackage) GenerateBuildActions(ctx blueprint.ModuleContext) {
-	// Allow the primary builder to create multiple variants.  Any variants after the first
-	// will copy outputs from the first.
-	if ctx.Module() != ctx.PrimaryModule() {
-		if info, ok := blueprint.OtherModuleProvider(ctx, ctx.PrimaryModule(), PackageProvider); ok {
-			blueprint.SetProvider(ctx, PackageProvider, info)
-		}
-		return
-	}
-
 	var (
 		name       = ctx.ModuleName()
 		hasPlugins = false
@@ -356,9 +423,6 @@ func newGoBinaryModuleFactory() func() (blueprint.Module, []interface{}) {
 }
 
 func (g *GoBinary) DynamicDependencies(ctx blueprint.DynamicDependerModuleContext) []string {
-	if ctx.Module() != ctx.PrimaryModule() {
-		return nil
-	}
 	return g.properties.Deps
 }
 
@@ -385,17 +449,6 @@ func (g *GoBinary) Properties() []interface{} {
 }
 
 func (g *GoBinary) GenerateBuildActions(ctx blueprint.ModuleContext) {
-	// Allow the primary builder to create multiple variants.  Any variants after the first
-	// will copy outputs from the first.
-	if ctx.Module() != ctx.PrimaryModule() {
-		if info, ok := blueprint.OtherModuleProvider(ctx, ctx.PrimaryModule(), BinaryProvider); ok {
-			g.installPath = info.InstallPath
-			g.outputFile = info.IntermediatePath
-			blueprint.SetProvider(ctx, BinaryProvider, info)
-		}
-		return
-	}
-
 	var (
 		name            = ctx.ModuleName()
 		objDir          = moduleObjDir(ctx)
@@ -517,13 +570,13 @@ func buildGoPluginLoader(ctx blueprint.ModuleContext, pkgPath, pluginSrc string)
 	return ret
 }
 
-func generateEmbedcfgFile(files []string, srcDir string, embedcfgFile string) {
+func generateEmbedcfgFile(ctx blueprint.ModuleContext, files []string, srcDir string, embedcfgFile string) {
 	embedcfg := struct {
 		Patterns map[string][]string
 		Files    map[string]string
 	}{
-		map[string][]string{},
-		map[string]string{},
+		make(map[string][]string, len(files)),
+		make(map[string]string, len(files)),
 	}
 
 	for _, file := range files {
@@ -533,11 +586,10 @@ func generateEmbedcfgFile(files []string, srcDir string, embedcfgFile string) {
 
 	embedcfgData, err := json.Marshal(&embedcfg)
 	if err != nil {
-		panic(err)
+		ctx.ModuleErrorf("Failed to marshal embedcfg data: %s", err.Error())
 	}
 
-	os.MkdirAll(filepath.Dir(embedcfgFile), os.ModePerm)
-	os.WriteFile(embedcfgFile, []byte(embedcfgData), 0644)
+	writeFileRule(ctx, embedcfgFile, string(embedcfgData))
 }
 
 func buildGoPackage(ctx blueprint.ModuleContext, pkgRoot string,
@@ -568,8 +620,9 @@ func buildGoPackage(ctx blueprint.ModuleContext, pkgRoot string,
 
 	if len(embedSrcs) > 0 {
 		embedcfgFile := archiveFile + ".embedcfg"
-		generateEmbedcfgFile(embedSrcs, srcDir, embedcfgFile)
+		generateEmbedcfgFile(ctx, embedSrcs, srcDir, embedcfgFile)
 		compileArgs["embedFlags"] = "-embedcfg " + embedcfgFile
+		deps = append(deps, embedcfgFile)
 	}
 
 	ctx.Build(pctx, blueprint.BuildParams{
@@ -790,7 +843,7 @@ func (s *singleton) GenerateBuildActions(ctx blueprint.SingletonContext) {
 // modules search for this package via -I arguments.
 func packageRoot(ctx blueprint.ModuleContext) string {
 	toolDir := ctx.Config().(BootstrapConfig).HostToolDir()
-	return filepath.Join(toolDir, "go", ctx.ModuleName(), "pkg")
+	return filepath.Join(toolDir, "go", ctx.ModuleName(), ctx.ModuleSubDir(), "pkg")
 }
 
 // testRoot returns the module-specific package root directory path used for
@@ -798,7 +851,7 @@ func packageRoot(ctx blueprint.ModuleContext) string {
 // packageRoot, plus the test-only code.
 func testRoot(ctx blueprint.ModuleContext) string {
 	toolDir := ctx.Config().(BootstrapConfig).HostToolDir()
-	return filepath.Join(toolDir, "go", ctx.ModuleName(), "test")
+	return filepath.Join(toolDir, "go", ctx.ModuleName(), ctx.ModuleSubDir(), "test")
 }
 
 // moduleSrcDir returns the path of the directory that all source file paths are
@@ -810,11 +863,11 @@ func moduleSrcDir(ctx blueprint.ModuleContext) string {
 // moduleObjDir returns the module-specific object directory path.
 func moduleObjDir(ctx blueprint.ModuleContext) string {
 	toolDir := ctx.Config().(BootstrapConfig).HostToolDir()
-	return filepath.Join(toolDir, "go", ctx.ModuleName(), "obj")
+	return filepath.Join(toolDir, "go", ctx.ModuleName(), ctx.ModuleSubDir(), "obj")
 }
 
 // moduleGenSrcDir returns the module-specific generated sources path.
 func moduleGenSrcDir(ctx blueprint.ModuleContext) string {
 	toolDir := ctx.Config().(BootstrapConfig).HostToolDir()
-	return filepath.Join(toolDir, "go", ctx.ModuleName(), "gen")
+	return filepath.Join(toolDir, "go", ctx.ModuleName(), ctx.ModuleSubDir(), "gen")
 }
diff --git a/bootstrap/command.go b/bootstrap/command.go
index 8ae6e24..8adaf23 100644
--- a/bootstrap/command.go
+++ b/bootstrap/command.go
@@ -108,7 +108,7 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 	}
 	ctx.EndEvent("list_modules")
 
-	ctx.RegisterBottomUpMutator("bootstrap_deps", BootstrapDeps)
+	ctx.RegisterBottomUpMutator("bootstrap_deps", BootstrapDeps).UsesReverseDependencies()
 	ctx.RegisterSingletonType("bootstrap", newSingletonFactory(), false)
 	if !goModuleTypesAreWrapped {
 		RegisterGoModuleTypes(ctx)
@@ -116,14 +116,14 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 
 	ctx.BeginEvent("parse_bp")
 	if blueprintFiles, errs := ctx.ParseFileList(".", filesToParse, config); len(errs) > 0 {
-		return nil, fatalErrors(errs)
+		return nil, colorizeErrs(errs)
 	} else {
 		ctx.EndEvent("parse_bp")
 		ninjaDeps = append(ninjaDeps, blueprintFiles...)
 	}
 
 	if resolvedDeps, errs := ctx.ResolveDependencies(config); len(errs) > 0 {
-		return nil, fatalErrors(errs)
+		return nil, colorizeErrs(errs)
 	} else {
 		ninjaDeps = append(ninjaDeps, resolvedDeps...)
 	}
@@ -134,7 +134,7 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 
 	if ctx.BeforePrepareBuildActionsHook != nil {
 		if err := ctx.BeforePrepareBuildActionsHook(); err != nil {
-			return nil, fatalErrors([]error{err})
+			return nil, colorizeErrs([]error{err})
 		}
 	}
 
@@ -142,12 +142,12 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 		var err error = nil
 		err = ctx.RestoreAllBuildActions(config.(BootstrapConfig).SoongOutDir())
 		if err != nil {
-			return nil, fatalErrors([]error{err})
+			return nil, colorizeErrs([]error{err})
 		}
 	}
 
 	if buildActionsDeps, errs := ctx.PrepareBuildActions(config); len(errs) > 0 {
-		return nil, fatalErrors(errs)
+		return nil, colorizeErrs(errs)
 	} else {
 		ninjaDeps = append(ninjaDeps, buildActionsDeps...)
 	}
@@ -161,13 +161,9 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 	}
 
 	providersValidationChan := make(chan []error, 1)
-	if ctx.GetVerifyProvidersAreUnchanged() {
-		go func() {
-			providersValidationChan <- ctx.VerifyProvidersWereUnchanged()
-		}()
-	} else {
-		providersValidationChan <- nil
-	}
+	go func() {
+		providersValidationChan <- ctx.VerifyProvidersWereUnchanged()
+	}()
 
 	var out blueprint.StringWriterWriter
 	var f *os.File
@@ -230,20 +226,21 @@ func RunBlueprint(args Args, stopBefore StopBefore, ctx *blueprint.Context, conf
 	return ninjaDeps, nil
 }
 
-func fatalErrors(errs []error) error {
+func colorizeErrs(errs []error) error {
 	red := "\x1b[31m"
 	unred := "\x1b[0m"
 
+	var colorizedErrs []error
 	for _, err := range errs {
 		switch err := err.(type) {
 		case *blueprint.BlueprintError,
 			*blueprint.ModuleError,
 			*blueprint.PropertyError:
-			fmt.Printf("%serror:%s %s\n", red, unred, err.Error())
+			colorizedErrs = append(colorizedErrs, fmt.Errorf("%serror:%s %w", red, unred, err))
 		default:
-			fmt.Printf("%sinternal error:%s %s\n", red, unred, err)
+			colorizedErrs = append(colorizedErrs, fmt.Errorf("%sinternal error:%s %s", red, unred, err))
 		}
 	}
 
-	return errors.New("fatal errors encountered")
+	return errors.Join(colorizedErrs...)
 }
diff --git a/bootstrap/writedocs.go b/bootstrap/writedocs.go
index 9b16e50..246fbbc 100644
--- a/bootstrap/writedocs.go
+++ b/bootstrap/writedocs.go
@@ -2,6 +2,7 @@ package bootstrap
 
 import (
 	"fmt"
+	"maps"
 	"path/filepath"
 	"reflect"
 
@@ -45,10 +46,7 @@ func ModuleTypeDocs(ctx *blueprint.Context, factories map[string]reflect.Value)
 		}
 	})
 
-	mergedFactories := make(map[string]reflect.Value)
-	for moduleType, factory := range factories {
-		mergedFactories[moduleType] = factory
-	}
+	mergedFactories := maps.Clone(factories)
 
 	for moduleType, factory := range ctx.ModuleTypeFactories() {
 		if _, exists := mergedFactories[moduleType]; !exists {
diff --git a/bpmodify/Android.bp b/bpmodify/Android.bp
new file mode 100644
index 0000000..9d994e0
--- /dev/null
+++ b/bpmodify/Android.bp
@@ -0,0 +1,17 @@
+bootstrap_go_package {
+    name: "blueprint-bpmodify",
+    pkgPath: "github.com/google/blueprint/bpmodify",
+    deps: [
+        "blueprint-parser",
+    ],
+    srcs: [
+        "bpmodify.go",
+    ],
+    testSrcs: [
+        "bpmodify_test.go",
+    ],
+    visibility: [
+        // used by plugins
+        "//visibility:public",
+    ],
+}
diff --git a/bpmodify/bpmodify.go b/bpmodify/bpmodify.go
index 98b1bee..757c030 100644
--- a/bpmodify/bpmodify.go
+++ b/bpmodify/bpmodify.go
@@ -1,527 +1,475 @@
-// Mostly copied from Go's src/cmd/gofmt:
-// Copyright 2009 The Go Authors. All rights reserved.
-// Use of this source code is governed by a BSD-style
-// license that can be found in the LICENSE file.
-package main
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package bpmodify
 
 import (
 	"bytes"
-	"flag"
+	"errors"
 	"fmt"
-	"io"
-	"io/ioutil"
-	"os"
-	"os/exec"
-	"path/filepath"
+	"slices"
 	"strings"
-	"syscall"
-	"unicode"
 
 	"github.com/google/blueprint/parser"
 )
 
-var (
-	// main operation modes
-	list               = flag.Bool("l", false, "list files that would be modified by bpmodify")
-	write              = flag.Bool("w", false, "write result to (source) file instead of stdout")
-	doDiff             = flag.Bool("d", false, "display diffs instead of rewriting files")
-	sortLists          = flag.Bool("s", false, "sort touched lists, even if they were unsorted")
-	targetedModules    = new(identSet)
-	targetedProperties = new(qualifiedProperties)
-	addIdents          = new(identSet)
-	removeIdents       = new(identSet)
-	removeProperty     = flag.Bool("remove-property", false, "remove the property")
-	moveProperty       = flag.Bool("move-property", false, "moves contents of property into newLocation")
-	newLocation        string
-	setString          *string
-	addLiteral         *string
-	setBool            *string
-	replaceProperty    = new(replacements)
-)
-
-func init() {
-	flag.Var(targetedModules, "m", "comma or whitespace separated list of modules on which to operate")
-	flag.Var(targetedProperties, "parameter", "alias to -property=`name1[,name2[,... […]")
-	flag.StringVar(&newLocation, "new-location", "", " use with moveProperty to move contents of -property into a property with name -new-location ")
-	flag.Var(targetedProperties, "property", "comma-separated list of fully qualified `name`s of properties to modify (default \"deps\")")
-	flag.Var(addIdents, "a", "comma or whitespace separated list of identifiers to add")
-	flag.Var(stringPtrFlag{&addLiteral}, "add-literal", "a literal to add to a list")
-	flag.Var(removeIdents, "r", "comma or whitespace separated list of identifiers to remove")
-	flag.Var(stringPtrFlag{&setString}, "str", "set a string property")
-	flag.Var(replaceProperty, "replace-property", "property names to be replaced, in the form of oldName1=newName1,oldName2=newName2")
-	flag.Var(stringPtrFlag{&setBool}, "set-bool", "a boolean value to set a property with (not a list)")
-	flag.Usage = usage
-}
-
-var (
-	exitCode = 0
-)
+// NewBlueprint returns a Blueprint for the given file contents that allows making modifications.
+func NewBlueprint(filename string, data []byte) (*Blueprint, error) {
+	r := bytes.NewReader(data)
+	file, errs := parser.Parse(filename, r)
+	if len(errs) > 0 {
+		return nil, errors.Join(errs...)
+	}
 
-func report(err error) {
-	fmt.Fprintln(os.Stderr, err)
-	exitCode = 2
+	return &Blueprint{
+		data:   data,
+		bpFile: file,
+	}, nil
 }
 
-func usage() {
-	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] [path ...]\n", os.Args[0])
-	flag.PrintDefaults()
+type Blueprint struct {
+	data     []byte
+	bpFile   *parser.File
+	modified bool
 }
 
-// If in == nil, the source is the contents of the file with the given filename.
-func processFile(filename string, in io.Reader, out io.Writer) error {
-	if in == nil {
-		f, err := os.Open(filename)
+// Bytes returns a copy of the current, possibly modified contents of the Blueprint as a byte slice.
+func (bp *Blueprint) Bytes() ([]byte, error) {
+	if bp.modified {
+		data, err := parser.Print(bp.bpFile)
 		if err != nil {
-			return err
-		}
-		defer f.Close()
-		if *write {
-			syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
+			return nil, err
 		}
-		in = f
+		return data, nil
 	}
-	src, err := ioutil.ReadAll(in)
+	return slices.Clone(bp.data), nil
+}
+
+// String returns the current, possibly modified contents of the Blueprint as a string.
+func (bp *Blueprint) String() string {
+	data, err := bp.Bytes()
 	if err != nil {
-		return err
+		return err.Error()
 	}
-	r := bytes.NewBuffer(src)
-	file, errs := parser.Parse(filename, r)
-	if len(errs) > 0 {
-		for _, err := range errs {
-			fmt.Fprintln(os.Stderr, err)
-		}
-		return fmt.Errorf("%d parsing errors", len(errs))
-	}
-	modified, errs := findModules(file)
-	if len(errs) > 0 {
-		for _, err := range errs {
-			fmt.Fprintln(os.Stderr, err)
-		}
-		fmt.Fprintln(os.Stderr, "continuing...")
+	return string(data)
+}
+
+// Modified returns true if any of the calls on the Blueprint caused the contents to be modified.
+func (bp *Blueprint) Modified() bool {
+	return bp.modified
+}
+
+// ModulesByName returns a ModuleSet that contains all modules with the given list of names.
+// Requesting a module that does not exist is not an error.
+func (bp *Blueprint) ModulesByName(names ...string) *ModuleSet {
+	moduleSet := &ModuleSet{
+		bp: bp,
 	}
-	if modified {
-		res, err := parser.Print(file)
-		if err != nil {
-			return err
-		}
-		if *list {
-			fmt.Fprintln(out, filename)
-		}
-		if *write {
-			err = ioutil.WriteFile(filename, res, 0644)
-			if err != nil {
-				return err
-			}
-		}
-		if *doDiff {
-			data, err := diff(src, res)
-			if err != nil {
-				return fmt.Errorf("computing diff: %s", err)
-			}
-			fmt.Printf("diff %s bpfmt/%s\n", filename, filename)
-			out.Write(data)
-		}
-		if !*list && !*write && !*doDiff {
-			_, err = out.Write(res)
+	for _, def := range bp.bpFile.Defs {
+		module, ok := def.(*parser.Module)
+		if !ok {
+			continue
 		}
-	}
-	return err
-}
-func findModules(file *parser.File) (modified bool, errs []error) {
-	for _, def := range file.Defs {
-		if module, ok := def.(*parser.Module); ok {
-			for _, prop := range module.Properties {
-				if prop.Name == "name" {
-					if stringValue, ok := prop.Value.(*parser.String); ok && targetedModule(stringValue.Value) {
-						for _, p := range targetedProperties.properties {
-							m, newErrs := processModuleProperty(module, prop.Name, file, p)
-							errs = append(errs, newErrs...)
-							modified = modified || m
-						}
-					}
+
+		for _, prop := range module.Properties {
+			if prop.Name == "name" {
+				if stringValue, ok := prop.Value.(*parser.String); ok && slices.Contains(names, stringValue.Value) {
+					moduleSet.modules = append(moduleSet.modules, module)
 				}
 			}
 		}
 	}
-	return modified, errs
+
+	return moduleSet
 }
 
-func processModuleProperty(module *parser.Module, moduleName string,
-	file *parser.File, property qualifiedProperty) (modified bool, errs []error) {
-	prop, parent, err := getRecursiveProperty(module, property.name(), property.prefixes())
-	if err != nil {
-		return false, []error{err}
-	}
-	if prop == nil {
-		if len(addIdents.idents) > 0 || addLiteral != nil {
-			// We are adding something to a non-existing list prop, so we need to create it first.
-			prop, modified, err = createRecursiveProperty(module, property.name(), property.prefixes(), &parser.List{})
-		} else if setString != nil {
-			// We setting a non-existent string property, so we need to create it first.
-			prop, modified, err = createRecursiveProperty(module, property.name(), property.prefixes(), &parser.String{})
-		} else if setBool != nil {
-			// We are setting a non-existent property, so we need to create it first.
-			prop, modified, err = createRecursiveProperty(module, property.name(), property.prefixes(), &parser.Bool{})
-		} else {
-			// We cannot find an existing prop, and we aren't adding anything to the prop,
-			// which means we must be removing something from a non-existing prop,
-			// which means this is a noop.
-			return false, nil
-		}
-		if err != nil {
-			// Here should be unreachable, but still handle it for completeness.
-			return false, []error{err}
+// AllModules returns a ModuleSet that contains all modules in the Blueprint.
+func (bp *Blueprint) AllModules() *ModuleSet {
+	moduleSet := &ModuleSet{
+		bp: bp,
+	}
+	for _, def := range bp.bpFile.Defs {
+		module, ok := def.(*parser.Module)
+		if !ok {
+			continue
 		}
-	} else if *removeProperty {
-		// remove-property is used solely, so return here.
-		return parent.RemoveProperty(prop.Name), nil
-	} else if *moveProperty {
-		return parent.MovePropertyContents(prop.Name, newLocation), nil
-	}
-	m, errs := processParameter(prop.Value, property.String(), moduleName, file)
-	modified = modified || m
-	return modified, errs
-}
-func getRecursiveProperty(module *parser.Module, name string, prefixes []string) (prop *parser.Property, parent *parser.Map, err error) {
-	prop, parent, _, err = getOrCreateRecursiveProperty(module, name, prefixes, nil)
-	return prop, parent, err
+
+		moduleSet.modules = append(moduleSet.modules, module)
+	}
+
+	return moduleSet
 }
-func createRecursiveProperty(module *parser.Module, name string, prefixes []string,
-	empty parser.Expression) (prop *parser.Property, modified bool, err error) {
-	prop, _, modified, err = getOrCreateRecursiveProperty(module, name, prefixes, empty)
-	return prop, modified, err
+
+// A ModuleSet represents a set of modules in a Blueprint, and can be used to make modifications
+// the modules.
+type ModuleSet struct {
+	bp      *Blueprint
+	modules []*parser.Module
 }
-func getOrCreateRecursiveProperty(module *parser.Module, name string, prefixes []string,
-	empty parser.Expression) (prop *parser.Property, parent *parser.Map, modified bool, err error) {
-	m := &module.Map
-	for i, prefix := range prefixes {
-		if prop, found := m.GetProperty(prefix); found {
-			if mm, ok := prop.Value.(*parser.Map); ok {
-				m = mm
-			} else {
-				// We've found a property in the AST and such property is not of type
-				// *parser.Map, which must mean we didn't modify the AST.
-				return nil, nil, false, fmt.Errorf("Expected property %q to be a map, found %s",
-					strings.Join(prefixes[:i+1], "."), prop.Value.Type())
+
+// GetProperty returns a PropertySet that contains all properties with the given list of names
+// in all modules in the ModuleSet.  Requesting properties that do not exist is not an error.
+// It returns an error for a malformed property name, or if the requested property is nested
+// in a property that is not a map.
+func (ms *ModuleSet) GetProperty(properties ...string) (*PropertySet, error) {
+	propertySet := &PropertySet{
+		bp: ms.bp,
+	}
+
+	targetProperties, err := parseQualifiedProperties(properties)
+	if err != nil {
+		return nil, err
+	}
+
+	for _, targetProperty := range targetProperties {
+		for _, module := range ms.modules {
+			prop, _, err := getRecursiveProperty(module, targetProperty)
+			if err != nil {
+				return nil, err
+			} else if prop == nil {
+				continue
 			}
-		} else if empty != nil {
-			mm := &parser.Map{}
-			m.Properties = append(m.Properties, &parser.Property{Name: prefix, Value: mm})
-			m = mm
-			// We've created a new node in the AST. This means the m.GetProperty(name)
-			// check after this for loop must fail, because the node we inserted is an
-			// empty parser.Map, thus this function will return |modified| is true.
-		} else {
-			return nil, nil, false, nil
+			propertySet.properties = append(propertySet.properties, &property{
+				property: prop,
+				module:   module,
+				name:     targetProperty,
+			})
 		}
 	}
-	if prop, found := m.GetProperty(name); found {
-		// We've found a property in the AST, which must mean we didn't modify the AST.
-		return prop, m, false, nil
-	} else if empty != nil {
-		prop = &parser.Property{Name: name, Value: empty}
-		m.Properties = append(m.Properties, prop)
-		return prop, m, true, nil
-	} else {
-		return nil, nil, false, nil
-	}
+
+	return propertySet, nil
 }
-func processParameter(value parser.Expression, paramName, moduleName string,
-	file *parser.File) (modified bool, errs []error) {
-	if _, ok := value.(*parser.Variable); ok {
-		return false, []error{fmt.Errorf("parameter %s in module %s is a variable, unsupported",
-			paramName, moduleName)}
+
+// GetOrCreateProperty returns a PropertySet that contains all properties with the given list of names
+// in all modules in the ModuleSet, creating empty placeholder properties if they don't exist.
+// It returns an error for a malformed property name, or if the requested property is nested
+// in a property that is not a map.
+func (ms *ModuleSet) GetOrCreateProperty(typ Type, properties ...string) (*PropertySet, error) {
+	propertySet := &PropertySet{
+		bp: ms.bp,
 	}
-	if _, ok := value.(*parser.Operator); ok {
-		return false, []error{fmt.Errorf("parameter %s in module %s is an expression, unsupported",
-			paramName, moduleName)}
+
+	targetProperties, err := parseQualifiedProperties(properties)
+	if err != nil {
+		return nil, err
 	}
 
-	if (*replaceProperty).size() != 0 {
-		if list, ok := value.(*parser.List); ok {
-			return parser.ReplaceStringsInList(list, (*replaceProperty).oldNameToNewName), nil
-		} else if str, ok := value.(*parser.String); ok {
-			oldVal := str.Value
-			replacementValue := (*replaceProperty).oldNameToNewName[oldVal]
-			if replacementValue != "" {
-				str.Value = replacementValue
-				return true, nil
+	for _, targetProperty := range targetProperties {
+		for _, module := range ms.modules {
+			prop, _, err := getRecursiveProperty(module, targetProperty)
+			if err != nil {
+				return nil, err
+			} else if prop == nil {
+				prop, err = createRecursiveProperty(module, targetProperty, parser.ZeroExpression(parser.Type(typ)))
+				if err != nil {
+					return nil, err
+				}
+				ms.bp.modified = true
 			} else {
-				return false, nil
+				if prop.Value.Type() != parser.Type(typ) {
+					return nil, fmt.Errorf("unexpected type found in property %q, wanted %s, found %s",
+						targetProperty.String(), typ, prop.Value.Type())
+				}
 			}
+			propertySet.properties = append(propertySet.properties, &property{
+				property: prop,
+				module:   module,
+				name:     targetProperty,
+			})
 		}
-		return false, []error{fmt.Errorf("expected parameter %s in module %s to be a list or string, found %s",
-			paramName, moduleName, value.Type().String())}
 	}
-	if len(addIdents.idents) > 0 || len(removeIdents.idents) > 0 {
-		list, ok := value.(*parser.List)
-		if !ok {
-			return false, []error{fmt.Errorf("expected parameter %s in module %s to be list, found %s",
-				paramName, moduleName, value.Type())}
-		}
-		wasSorted := parser.ListIsSorted(list)
-		for _, a := range addIdents.idents {
-			m := parser.AddStringToList(list, a)
-			modified = modified || m
-		}
-		for _, r := range removeIdents.idents {
-			m := parser.RemoveStringFromList(list, r)
-			modified = modified || m
-		}
-		if (wasSorted || *sortLists) && modified {
-			parser.SortList(file, list)
-		}
-	} else if addLiteral != nil {
-		if *sortLists {
-			return false, []error{fmt.Errorf("sorting not supported when adding a literal")}
-		}
-		list, ok := value.(*parser.List)
-		if !ok {
-			return false, []error{fmt.Errorf("expected parameter %s in module %s to be list, found %s",
-				paramName, moduleName, value.Type().String())}
-		}
-		value, errs := parser.ParseExpression(strings.NewReader(*addLiteral))
-		if errs != nil {
-			return false, errs
-		}
-		list.Values = append(list.Values, value)
-		modified = true
-	} else if setBool != nil {
-		res, ok := value.(*parser.Bool)
-		if !ok {
-			return false, []error{fmt.Errorf("expected parameter %s in module %s to be bool, found %s",
-				paramName, moduleName, value.Type().String())}
-		}
-		if *setBool == "true" {
-			res.Value = true
-		} else if *setBool == "false" {
-			res.Value = false
-		} else {
-			return false, []error{fmt.Errorf("expected parameter %s to be true or false, found %s",
-				paramName, *setBool)}
-		}
-		modified = true
-	} else if setString != nil {
-		str, ok := value.(*parser.String)
-		if !ok {
-			return false, []error{fmt.Errorf("expected parameter %s in module %s to be string, found %s",
-				paramName, moduleName, value.Type().String())}
-		}
-		str.Value = *setString
-		modified = true
-	}
-	return modified, nil
+
+	return propertySet, nil
 }
-func targetedModule(name string) bool {
-	if targetedModules.all {
-		return true
+
+// RemoveProperty removes the given list of properties from all modules in the ModuleSet.
+// It returns an error for a malformed property name, or if the requested property is nested
+// in a property that is not a map.  Removing a property that does not exist is not an error.
+func (ms *ModuleSet) RemoveProperty(properties ...string) error {
+	targetProperties, err := parseQualifiedProperties(properties)
+	if err != nil {
+		return err
 	}
-	for _, m := range targetedModules.idents {
-		if m == name {
-			return true
+
+	for _, targetProperty := range targetProperties {
+		for _, module := range ms.modules {
+			prop, parent, err := getRecursiveProperty(module, targetProperty)
+			if err != nil {
+				return err
+			} else if prop != nil {
+				parent.RemoveProperty(prop.Name)
+				ms.bp.modified = true
+			}
 		}
 	}
-	return false
-}
-func visitFile(path string, f os.FileInfo, err error) error {
-	//TODO(dacek): figure out a better way to target intended .bp files without parsing errors
-	if err == nil && (f.Name() == "Blueprints" || strings.HasSuffix(f.Name(), ".bp")) {
-		err = processFile(path, nil, os.Stdout)
-	}
-	if err != nil {
-		report(err)
-	}
 	return nil
 }
-func walkDir(path string) {
-	filepath.Walk(path, visitFile)
-}
-func main() {
-	defer func() {
-		if err := recover(); err != nil {
-			report(fmt.Errorf("error: %s", err))
-		}
-		os.Exit(exitCode)
-	}()
-	flag.Parse()
 
-	if len(targetedProperties.properties) == 0 && *moveProperty {
-		report(fmt.Errorf("-move-property must specify property"))
-		return
+// MoveProperty moves the given list of properties to a new parent property.
+// It returns an error for a malformed property name, or if the requested property is nested
+// in a property that is not a map.  Moving a property that does not exist is not an error.
+func (ms *ModuleSet) MoveProperty(newParent string, properties ...string) error {
+	targetProperties, err := parseQualifiedProperties(properties)
+	if err != nil {
+		return err
 	}
 
-	if len(targetedProperties.properties) == 0 {
-		targetedProperties.Set("deps")
-	}
-	if flag.NArg() == 0 {
-		if *write {
-			report(fmt.Errorf("error: cannot use -w with standard input"))
-			return
-		}
-		if err := processFile("<standard input>", os.Stdin, os.Stdout); err != nil {
-			report(err)
-		}
-		return
-	}
-	if len(targetedModules.idents) == 0 {
-		report(fmt.Errorf("-m parameter is required"))
-		return
-	}
-
-	if len(addIdents.idents) == 0 && len(removeIdents.idents) == 0 && setString == nil && addLiteral == nil && !*removeProperty && !*moveProperty && (*replaceProperty).size() == 0 && setBool == nil {
-		report(fmt.Errorf("-a, -add-literal, -r, -remove-property, -move-property, replace-property or -str parameter is required"))
-		return
-	}
-	if *removeProperty && (len(addIdents.idents) > 0 || len(removeIdents.idents) > 0 || setString != nil || addLiteral != nil || (*replaceProperty).size() > 0) {
-		report(fmt.Errorf("-remove-property cannot be used with other parameter(s)"))
-		return
-	}
-	if *moveProperty && (len(addIdents.idents) > 0 || len(removeIdents.idents) > 0 || setString != nil || addLiteral != nil || (*replaceProperty).size() > 0) {
-		report(fmt.Errorf("-move-property cannot be used with other parameter(s)"))
-		return
-	}
-	if *moveProperty && newLocation == "" {
-		report(fmt.Errorf("-move-property must specify -new-location"))
-		return
-	}
-	for i := 0; i < flag.NArg(); i++ {
-		path := flag.Arg(i)
-		switch dir, err := os.Stat(path); {
-		case err != nil:
-			report(err)
-		case dir.IsDir():
-			walkDir(path)
-		default:
-			if err := processFile(path, nil, os.Stdout); err != nil {
-				report(err)
+	for _, targetProperty := range targetProperties {
+		for _, module := range ms.modules {
+			prop, parent, err := getRecursiveProperty(module, targetProperty)
+			if err != nil {
+				return err
+			} else if prop != nil {
+				parent.MovePropertyContents(prop.Name, newParent)
+				ms.bp.modified = true
 			}
 		}
 	}
+	return nil
 }
 
-func diff(b1, b2 []byte) (data []byte, err error) {
-	f1, err := ioutil.TempFile("", "bpfmt")
-	if err != nil {
-		return
-	}
-	defer os.Remove(f1.Name())
-	defer f1.Close()
-	f2, err := ioutil.TempFile("", "bpfmt")
-	if err != nil {
-		return
-	}
-	defer os.Remove(f2.Name())
-	defer f2.Close()
-	f1.Write(b1)
-	f2.Write(b2)
-	data, err = exec.Command("diff", "-uw", f1.Name(), f2.Name()).CombinedOutput()
-	if len(data) > 0 {
-		// diff exits with a non-zero status when the files don't match.
-		// Ignore that failure as long as we get output.
-		err = nil
-	}
-	return
+// PropertySet represents a set of properties in a set of modules.
+type PropertySet struct {
+	bp         *Blueprint
+	properties []*property
+	sortLists  bool
 }
 
-type stringPtrFlag struct {
-	s **string
+type property struct {
+	property *parser.Property
+	module   *parser.Module
+	name     *qualifiedProperty
 }
 
-func (f stringPtrFlag) Set(s string) error {
-	*f.s = &s
-	return nil
+// SortListsWhenModifying causes any future modifications to lists in the PropertySet to sort
+// the lists.  Otherwise, lists are only sorted if they appear to be sorted before modification.
+func (ps *PropertySet) SortListsWhenModifying() {
+	ps.sortLists = true
 }
-func (f stringPtrFlag) String() string {
-	if f.s == nil || *f.s == nil {
-		return ""
+
+// SetString sets all properties in the PropertySet to the given string.  It returns an error
+// if any of the properties are not strings.
+func (ps *PropertySet) SetString(s string) error {
+	var errs []error
+	for _, prop := range ps.properties {
+		value := prop.property.Value
+		str, ok := value.(*parser.String)
+		if !ok {
+			errs = append(errs, fmt.Errorf("expected property %s in module %s to be string, found %s",
+				prop.name, prop.module.Name(), value.Type().String()))
+			continue
+		}
+		if str.Value != s {
+			str.Value = s
+			ps.bp.modified = true
+		}
 	}
-	return **f.s
-}
 
-type replacements struct {
-	oldNameToNewName map[string]string
+	return errors.Join(errs...)
 }
 
-func (m *replacements) String() string {
-	ret := ""
-	sep := ""
-	for k, v := range m.oldNameToNewName {
-		ret += sep
-		ret += k
-		ret += ":"
-		ret += v
-		sep = ","
-	}
-	return ret
+// SetBool sets all properties in the PropertySet to the given boolean.  It returns an error
+// if any of the properties are not booleans.
+func (ps *PropertySet) SetBool(b bool) error {
+	var errs []error
+	for _, prop := range ps.properties {
+		value := prop.property.Value
+		res, ok := value.(*parser.Bool)
+		if !ok {
+			errs = append(errs, fmt.Errorf("expected property %s in module %s to be bool, found %s",
+				prop.name, prop.module.Name(), value.Type().String()))
+			continue
+		}
+		if res.Value != b {
+			res.Value = b
+			ps.bp.modified = true
+		}
+	}
+	return errors.Join(errs...)
 }
 
-func (m *replacements) Set(s string) error {
-	usedNames := make(map[string]struct{})
+// AddStringToList adds the given strings to all properties in the PropertySet.  It returns an error
+// if any of the properties are not lists of strings.
+func (ps *PropertySet) AddStringToList(strs ...string) error {
+	var errs []error
+	for _, prop := range ps.properties {
+		value := prop.property.Value
+		list, ok := value.(*parser.List)
+		if !ok {
+			errs = append(errs, fmt.Errorf("expected property %s in module %s to be list, found %s",
+				prop.name, prop.module.Name(), value.Type()))
+			continue
+		}
+		wasSorted := parser.ListIsSorted(list)
+		modified := false
+		for _, s := range strs {
+			m := parser.AddStringToList(list, s)
+			modified = modified || m
+		}
+		if modified {
+			ps.bp.modified = true
+			if wasSorted || ps.sortLists {
+				parser.SortList(ps.bp.bpFile, list)
+			}
+		}
+	}
 
-	pairs := strings.Split(s, ",")
-	length := len(pairs)
-	m.oldNameToNewName = make(map[string]string)
-	for i := 0; i < length; i++ {
+	return errors.Join(errs...)
+}
 
-		pair := strings.SplitN(pairs[i], "=", 2)
-		if len(pair) != 2 {
-			return fmt.Errorf("Invalid replacement pair %s", pairs[i])
+// RemoveStringFromList removes the given strings to all properties in the PropertySet if they are present.
+// It returns an error  if any of the properties are not lists of strings.
+func (ps *PropertySet) RemoveStringFromList(strs ...string) error {
+	var errs []error
+	for _, prop := range ps.properties {
+		value := prop.property.Value
+		list, ok := value.(*parser.List)
+		if !ok {
+			errs = append(errs, fmt.Errorf("expected property %s in module %s to be list, found %s",
+				prop.name, prop.module.Name(), value.Type()))
+			continue
 		}
-		oldName := pair[0]
-		newName := pair[1]
-		if _, seen := usedNames[oldName]; seen {
-			return fmt.Errorf("Duplicated replacement name %s", oldName)
+		wasSorted := parser.ListIsSorted(list)
+		modified := false
+		for _, s := range strs {
+			m := parser.RemoveStringFromList(list, s)
+			modified = modified || m
 		}
-		if _, seen := usedNames[newName]; seen {
-			return fmt.Errorf("Duplicated replacement name %s", newName)
+		if modified {
+			ps.bp.modified = true
+			if wasSorted || ps.sortLists {
+				parser.SortList(ps.bp.bpFile, list)
+			}
 		}
-		usedNames[oldName] = struct{}{}
-		usedNames[newName] = struct{}{}
-		m.oldNameToNewName[oldName] = newName
 	}
-	return nil
-}
 
-func (m *replacements) Get() interface{} {
-	//TODO(dacek): Remove Get() method from interface as it seems unused.
-	return m.oldNameToNewName
+	return errors.Join(errs...)
 }
 
-func (m *replacements) size() (length int) {
-	return len(m.oldNameToNewName)
-}
+// AddLiteral adds the given literal blueprint snippet to all properties in the PropertySet if they are present.
+// It returns an error  if any of the properties are not lists.
+func (ps *PropertySet) AddLiteral(s string) error {
+	var errs []error
+	for _, prop := range ps.properties {
+		value := prop.property.Value
+		if ps.sortLists {
+			return fmt.Errorf("sorting not supported when adding a literal")
+		}
+		list, ok := value.(*parser.List)
+		if !ok {
+			errs = append(errs, fmt.Errorf("expected property %s in module %s to be list, found %s",
+				prop.name, prop.module.Name(), value.Type().String()))
+			continue
+		}
+		value, parseErrs := parser.ParseExpression(strings.NewReader(s))
+		if len(parseErrs) > 0 {
+			errs = append(errs, parseErrs...)
+			continue
+		}
+		list.Values = append(list.Values, value)
+		ps.bp.modified = true
+	}
 
-type identSet struct {
-	idents []string
-	all    bool
+	return errors.Join(errs...)
 }
 
-func (m *identSet) String() string {
-	return strings.Join(m.idents, ",")
+// ReplaceStrings applies replacements to all properties in the PropertySet.  It replaces all instances
+// of the strings in the keys of the given map with their corresponding values.  It returns an error
+// if any of the properties are not lists of strings.
+func (ps *PropertySet) ReplaceStrings(replacements map[string]string) error {
+	var errs []error
+	for _, prop := range ps.properties {
+		value := prop.property.Value
+		if list, ok := value.(*parser.List); ok {
+			modified := parser.ReplaceStringsInList(list, replacements)
+			if modified {
+				ps.bp.modified = true
+			}
+		} else if str, ok := value.(*parser.String); ok {
+			oldVal := str.Value
+			replacementValue := replacements[oldVal]
+			if replacementValue != "" {
+				str.Value = replacementValue
+				ps.bp.modified = true
+			}
+		} else {
+			errs = append(errs, fmt.Errorf("expected property %s in module %s to be a list or string, found %s",
+				prop.name, prop.module.Name(), value.Type().String()))
+		}
+	}
+	return errors.Join(errs...)
 }
-func (m *identSet) Set(s string) error {
-	m.idents = strings.FieldsFunc(s, func(c rune) bool {
-		return unicode.IsSpace(c) || c == ','
-	})
-	if len(m.idents) == 1 && m.idents[0] == "*" {
-		m.all = true
+
+func getRecursiveProperty(module *parser.Module, property *qualifiedProperty) (prop *parser.Property,
+	parent *parser.Map, err error) {
+
+	parent, err = traverseToQualifiedPropertyParent(module, property, false)
+	if err != nil {
+		return nil, nil, err
 	}
-	return nil
+	if parent == nil {
+		return nil, nil, nil
+	}
+	if prop, found := parent.GetProperty(property.name()); found {
+		return prop, parent, nil
+	}
+
+	return nil, nil, nil
 }
-func (m *identSet) Get() interface{} {
-	return m.idents
+
+func createRecursiveProperty(module *parser.Module, property *qualifiedProperty,
+	value parser.Expression) (prop *parser.Property, err error) {
+	parent, err := traverseToQualifiedPropertyParent(module, property, true)
+	if err != nil {
+		return nil, err
+	}
+	if _, found := parent.GetProperty(property.name()); found {
+		return nil, fmt.Errorf("property %q already exists", property.String())
+	}
+
+	prop = &parser.Property{Name: property.name(), Value: value}
+	parent.Properties = append(parent.Properties, prop)
+	return prop, nil
 }
 
-type qualifiedProperties struct {
-	properties []qualifiedProperty
+func traverseToQualifiedPropertyParent(module *parser.Module, property *qualifiedProperty,
+	create bool) (parent *parser.Map, err error) {
+	m := &module.Map
+	for i, prefix := range property.prefixes() {
+		if prop, found := m.GetProperty(prefix); found {
+			if mm, ok := prop.Value.(*parser.Map); ok {
+				m = mm
+			} else {
+				// We've found a property in the AST and such property is not of type *parser.Map
+				return nil, fmt.Errorf("Expected property %q to be a map, found %s",
+					strings.Join(property.prefixes()[:i+1], "."), prop.Value.Type())
+			}
+		} else if create {
+			mm := &parser.Map{}
+			m.Properties = append(m.Properties, &parser.Property{Name: prefix, Value: mm})
+			m = mm
+		} else {
+			return nil, nil
+		}
+	}
+	return m, nil
 }
 
 type qualifiedProperty struct {
 	parts []string
 }
 
-var _ flag.Getter = (*qualifiedProperties)(nil)
-
 func (p *qualifiedProperty) name() string {
 	return p.parts[len(p.parts)-1]
 }
@@ -547,31 +495,32 @@ func parseQualifiedProperty(s string) (*qualifiedProperty, error) {
 
 }
 
-func (p *qualifiedProperties) Set(s string) error {
-	properties := strings.Split(s, ",")
-	if len(properties) == 0 {
-		return fmt.Errorf("%q is not a valid property name", s)
-	}
-
-	p.properties = make([]qualifiedProperty, len(properties))
-	for i := 0; i < len(properties); i++ {
-		tmp, err := parseQualifiedProperty(properties[i])
+func parseQualifiedProperties(properties []string) ([]*qualifiedProperty, error) {
+	var qualifiedProperties []*qualifiedProperty
+	var errs []error
+	for _, property := range properties {
+		qualifiedProperty, err := parseQualifiedProperty(property)
 		if err != nil {
-			return err
+			errs = append(errs, err)
 		}
-		p.properties[i] = *tmp
+		qualifiedProperties = append(qualifiedProperties, qualifiedProperty)
 	}
-	return nil
-}
-
-func (p *qualifiedProperties) String() string {
-	arrayLength := len(p.properties)
-	props := make([]string, arrayLength)
-	for i := 0; i < len(p.properties); i++ {
-		props[i] = p.properties[i].String()
+	if len(errs) > 0 {
+		return nil, errors.Join(errs...)
 	}
-	return strings.Join(props, ",")
+	return qualifiedProperties, nil
 }
-func (p *qualifiedProperties) Get() interface{} {
-	return p.properties
+
+type Type parser.Type
+
+var (
+	List   = Type(parser.ListType)
+	String = Type(parser.StringType)
+	Bool   = Type(parser.BoolType)
+	Int64  = Type(parser.Int64Type)
+	Map    = Type(parser.MapType)
+)
+
+func (t Type) String() string {
+	return parser.Type(t).String()
 }
diff --git a/bpmodify/bpmodify_test.go b/bpmodify/bpmodify_test.go
index 7bd8b57..54b5c38 100644
--- a/bpmodify/bpmodify_test.go
+++ b/bpmodify/bpmodify_test.go
@@ -11,72 +11,90 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
-package main
+
+package bpmodify
 
 import (
 	"strings"
 	"testing"
-
-	"github.com/google/blueprint/parser"
-	"github.com/google/blueprint/proptools"
 )
 
-var testCases = []struct {
-	name            string
-	input           string
-	output          string
-	property        string
-	addSet          string
-	removeSet       string
-	addLiteral      *string
-	setString       *string
-	setBool         *string
-	removeProperty  bool
-	replaceProperty string
-	moveProperty    bool
-	newLocation     string
-}{
-	{
-		name: "add",
-		input: `
-			cc_foo {
-				name: "foo",
-			}
-		`,
-		output: `
+func must(err error) {
+	if err != nil {
+		panic(err)
+	}
+}
+
+func must2[T any](v T, err error) T {
+	if err != nil {
+		panic(err)
+	}
+	return v
+}
+
+func simplifyModuleDefinition(def string) string {
+	var result string
+	for _, line := range strings.Split(def, "\n") {
+		result += strings.TrimSpace(line)
+	}
+	return result
+}
+func TestBpModify(t *testing.T) {
+	var testCases = []struct {
+		name     string
+		input    string
+		output   string
+		err      string
+		modified bool
+		f        func(bp *Blueprint)
+	}{
+		{
+			name: "add",
+			input: `
+			cc_foo {
+				name: "foo",
+			}
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				deps: ["bar"],
 			}
-		`,
-		property: "deps",
-		addSet:   "bar",
-	},
-	{
-		name: "remove",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetOrCreateProperty(List, "deps"))
+				must(props.AddStringToList("bar"))
+			},
+		},
+		{
+			name: "remove",
+			input: `
 			cc_foo {
 				name: "foo",
 				deps: ["bar"],
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				deps: [],
 			}
-		`,
-		property:  "deps",
-		removeSet: "bar",
-	},
-	{
-		name: "nested add",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetProperty("deps"))
+				must(props.RemoveStringFromList("bar"))
+			},
+		},
+		{
+			name: "nested add",
+			input: `
 			cc_foo {
 				name: "foo",
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				arch: {
@@ -87,13 +105,16 @@ var testCases = []struct {
 					},
 				},
 			}
-		`,
-		property: "arch.arm.deps",
-		addSet:   "nested_dep,dep2",
-	},
-	{
-		name: "nested remove",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetOrCreateProperty(List, "arch.arm.deps"))
+				must(props.AddStringToList("nested_dep", "dep2"))
+			},
+		},
+		{
+			name: "nested remove",
+			input: `
 			cc_foo {
 				name: "foo",
 				arch: {
@@ -105,8 +126,8 @@ var testCases = []struct {
 					},
 				},
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				arch: {
@@ -116,13 +137,16 @@ var testCases = []struct {
 					},
 				},
 			}
-		`,
-		property:  "arch.arm.deps",
-		removeSet: "nested_dep,dep2",
-	},
-	{
-		name: "add existing",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetProperty("arch.arm.deps"))
+				must(props.RemoveStringFromList("nested_dep", "dep2"))
+			},
+		},
+		{
+			name: "add existing",
+			input: `
 			cc_foo {
 				name: "foo",
 				arch: {
@@ -134,8 +158,8 @@ var testCases = []struct {
 					},
 				},
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				arch: {
@@ -147,13 +171,16 @@ var testCases = []struct {
 					},
 				},
 			}
-		`,
-		property: "arch.arm.deps",
-		addSet:   "dep2,dep2",
-	},
-	{
-		name: "remove missing",
-		input: `
+			`,
+			modified: false,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetOrCreateProperty(List, "arch.arm.deps"))
+				must(props.AddStringToList("dep2", "dep2"))
+			},
+		},
+		{
+			name: "remove missing",
+			input: `
 			cc_foo {
 				name: "foo",
 				arch: {
@@ -165,8 +192,8 @@ var testCases = []struct {
 					},
 				},
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				arch: {
@@ -178,72 +205,85 @@ var testCases = []struct {
 					},
 				},
 			}
-		`,
-		property:  "arch.arm.deps",
-		removeSet: "dep3,dep4",
-	},
-	{
-		name: "remove non existent",
-		input: `
+			`,
+			modified: false,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetProperty("arch.arm.deps"))
+				must(props.RemoveStringFromList("dep3", "dep4"))
+			},
+		},
+		{
+			name: "remove non existent",
+			input: `
 			cc_foo {
 				name: "foo",
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 			}
-		`,
-		property:  "deps",
-		removeSet: "bar",
-	},
-	{
-		name: "remove non existent nested",
-		input: `
+			`,
+			modified: false,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetProperty("deps"))
+				must(props.RemoveStringFromList("bar"))
+			},
+		},
+		{
+			name: "remove non existent nested",
+			input: `
 			cc_foo {
 				name: "foo",
 				arch: {},
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				arch: {},
 			}
-		`,
-		property:  "arch.arm.deps",
-		removeSet: "dep3,dep4",
-	},
-	{
-		name: "add numeric sorted",
-		input: `
+			`,
+			modified: false,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetProperty("arch.arm.deps"))
+				must(props.RemoveStringFromList("bar"))
+			},
+		},
+		{
+			name: "add numeric sorted",
+			input: `
 			cc_foo {
 				name: "foo",
-				versions: ["1", "2"],
+				versions: ["1", "2", "20"],
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				versions: [
 					"1",
 					"2",
 					"10",
+					"20",
 				],
 			}
-		`,
-		property: "versions",
-		addSet:   "10",
-	},
-	{
-		name: "add mixed sorted",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetProperty("versions"))
+				must(props.AddStringToList("10"))
+			},
+		},
+		{
+			name: "add mixed sorted",
+			input: `
 			cc_foo {
 				name: "foo",
 				deps: ["bar-v1-bar", "bar-v2-bar"],
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				deps: [
@@ -252,154 +292,178 @@ var testCases = []struct {
 					"bar-v10-bar",
 				],
 			}
-		`,
-		property: "deps",
-		addSet:   "bar-v10-bar",
-	},
-	{
-		name:  "add a struct with literal",
-		input: `cc_foo {name: "foo"}`,
-		output: `cc_foo {
-    name: "foo",
-    structs: [
-        {
-            version: "1",
-            imports: [
-                "bar1",
-                "bar2",
-            ],
-        },
-    ],
-}
-`,
-		property:   "structs",
-		addLiteral: proptools.StringPtr(`{version: "1", imports: ["bar1", "bar2"]}`),
-	},
-	{
-		name: "set string",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetProperty("deps"))
+				must(props.AddStringToList("bar-v10-bar"))
+			},
+		},
+		{
+			name:  "add a struct with literal",
+			input: `cc_foo {name: "foo"}`,
+			output: `cc_foo {
+				name: "foo",
+				structs: [
+					{
+						version: "1",
+
+						imports: [
+							"bar1",
+							"bar2",
+						],
+					},
+				],
+			}
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetOrCreateProperty(List, "structs"))
+				must(props.AddLiteral(`{version: "1", imports: ["bar1", "bar2"]}`))
+			},
+		},
+		{
+			name: "set string",
+			input: `
 			cc_foo {
 				name: "foo",
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				foo: "bar",
 			}
-		`,
-		property:  "foo",
-		setString: proptools.StringPtr("bar"),
-	},
-	{
-		name: "set existing string",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetOrCreateProperty(String, "foo"))
+				must(props.SetString("bar"))
+			},
+		},
+		{
+			name: "set existing string",
+			input: `
 			cc_foo {
 				name: "foo",
 				foo: "baz",
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				foo: "bar",
 			}
-		`,
-		property:  "foo",
-		setString: proptools.StringPtr("bar"),
-	},
-	{
-		name: "set bool",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetOrCreateProperty(String, "foo"))
+				must(props.SetString("bar"))
+			},
+		},
+		{
+			name: "set bool",
+			input: `
 			cc_foo {
 				name: "foo",
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				foo: true,
 			}
-		`,
-		property: "foo",
-		setBool:  proptools.StringPtr("true"),
-	},
-	{
-		name: "set existing bool",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetOrCreateProperty(Bool, "foo"))
+				must(props.SetBool(true))
+			},
+		},
+		{
+			name: "set existing bool",
+			input: `
 			cc_foo {
 				name: "foo",
 				foo: true,
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				foo: false,
 			}
-		`,
-		property: "foo",
-		setBool:  proptools.StringPtr("false"),
-	},
-	{
-		name: "remove existing property",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetOrCreateProperty(Bool, "foo"))
+				must(props.SetBool(false))
+			},
+		},
+		{
+			name: "remove existing property",
+			input: `
 			cc_foo {
 				name: "foo",
 				foo: "baz",
 			}
-		`,
-		output: `
+			`,
+			output: `
+			cc_foo {
+				name: "foo",
+			}
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				must(bp.ModulesByName("foo").RemoveProperty("foo"))
+			},
+		}, {
+			name: "remove nested property",
+			input: `
+			cc_foo {
+				name: "foo",
+				foo: {
+					bar: "baz",
+				},
+			}
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
+				foo: {},
 			}
-		`,
-		property:       "foo",
-		removeProperty: true,
-	}, {
-		name: "remove nested property",
-		input: `
-		cc_foo {
-			name: "foo",
-			foo: {
-				bar: "baz",
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				must(bp.ModulesByName("foo").RemoveProperty("foo.bar"))
 			},
-		}
-	`,
-		output: `
-		cc_foo {
-			name: "foo",
-			foo: {},
-		}
-	`,
-		property:       "foo.bar",
-		removeProperty: true,
-	}, {
-		name: "remove non-existing property",
-		input: `
+		}, {
+			name: "remove non-existing property",
+			input: `
 			cc_foo {
 				name: "foo",
 				foo: "baz",
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				foo: "baz",
 			}
-		`,
-		property:       "bar",
-		removeProperty: true,
-	}, {
-		name:     "replace property",
-		property: "deps",
-		input: `
+			`,
+			modified: false,
+			f: func(bp *Blueprint) {
+				must(bp.ModulesByName("foo").RemoveProperty("bar"))
+			},
+		}, {
+			name: "replace property",
+			input: `
 			cc_foo {
 				name: "foo",
 				deps: ["baz", "unchanged"],
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				deps: [
@@ -407,20 +471,23 @@ var testCases = []struct {
                 "unchanged",
 				],
 			}
-		`,
-		replaceProperty: "baz=baz_lib,foobar=foobar_lib",
-	}, {
-		name:     "replace property multiple modules",
-		property: "deps,required",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetProperty("deps"))
+				must(props.ReplaceStrings(map[string]string{"baz": "baz_lib", "foobar": "foobar_lib"}))
+			},
+		}, {
+			name: "replace property multiple modules",
+			input: `
 			cc_foo {
 				name: "foo",
 				deps: ["baz", "unchanged"],
 				unchanged: ["baz"],
 				required: ["foobar"],
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				deps: [
@@ -430,75 +497,86 @@ var testCases = []struct {
 				unchanged: ["baz"],
 				required: ["foobar_lib"],
 			}
-		`,
-		replaceProperty: "baz=baz_lib,foobar=foobar_lib",
-	}, {
-		name:     "replace property string value",
-		property: "name",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetProperty("deps", "required"))
+				must(props.ReplaceStrings(map[string]string{"baz": "baz_lib", "foobar": "foobar_lib"}))
+			},
+		}, {
+			name: "replace property string value",
+			input: `
 			cc_foo {
 				name: "foo",
 				deps: ["baz"],
 				unchanged: ["baz"],
 				required: ["foobar"],
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo_lib",
 				deps: ["baz"],
 				unchanged: ["baz"],
 				required: ["foobar"],
 			}
-		`,
-		replaceProperty: "foo=foo_lib",
-	}, {
-		name:     "replace property string and list values",
-		property: "name,deps",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetProperty("name"))
+				must(props.ReplaceStrings(map[string]string{"foo": "foo_lib"}))
+			},
+		}, {
+			name: "replace property string and list values",
+			input: `
 			cc_foo {
 				name: "foo",
 				deps: ["baz"],
 				unchanged: ["baz"],
 				required: ["foobar"],
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo_lib",
 				deps: ["baz_lib"],
 				unchanged: ["baz"],
 				required: ["foobar"],
 			}
-		`,
-		replaceProperty: "foo=foo_lib,baz=baz_lib",
-	}, {
-		name: "move contents of property into non-existing property",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetProperty("name", "deps"))
+				must(props.ReplaceStrings(map[string]string{"foo": "foo_lib", "baz": "baz_lib"}))
+			},
+		}, {
+			name: "move contents of property into non-existing property",
+			input: `
 			cc_foo {
 				name: "foo",
 				bar: ["barContents"],
 				}
 `,
-		output: `
+			output: `
 			cc_foo {
 				name: "foo",
 				baz: ["barContents"],
 			}
-		`,
-		property:     "bar",
-		moveProperty: true,
-		newLocation:  "baz",
-	}, {
-		name: "move contents of property into existing property",
-		input: `
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				must(bp.ModulesByName("foo").MoveProperty("baz", "bar"))
+			},
+		}, {
+			name: "move contents of property into existing property",
+			input: `
 			cc_foo {
 				name: "foo",
 				baz: ["bazContents"],
 				bar: ["barContents"],
 			}
-		`,
-		output: `
+			`,
+			output: `
 			cc_foo {
 				name: "foo",
 				baz: [
@@ -507,128 +585,82 @@ var testCases = []struct {
 				],
 
 			}
-		`,
-		property:     "bar",
-		moveProperty: true,
-		newLocation:  "baz",
-	}, {
-		name: "replace nested",
-		input: `
-		cc_foo {
-			name: "foo",
-			foo: {
-				bar: "baz",
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				must(bp.ModulesByName("foo").MoveProperty("baz", "bar"))
 			},
-		}
-	`,
-		output: `
-		cc_foo {
-			name: "foo",
-			foo: {
-				bar: "baz2",
+		}, {
+			name: "replace nested",
+			input: `
+			cc_foo {
+				name: "foo",
+				foo: {
+					bar: "baz",
+				},
+			}
+			`,
+			output: `
+			cc_foo {
+				name: "foo",
+				foo: {
+					bar: "baz2",
+				},
+			}
+			`,
+			modified: true,
+			f: func(bp *Blueprint) {
+				props := must2(bp.ModulesByName("foo").GetProperty("foo.bar"))
+				must(props.ReplaceStrings(map[string]string{"baz": "baz2"}))
 			},
-		}
-	`,
-		property:        "foo.bar",
-		replaceProperty: "baz=baz2",
-	},
-}
-
-func simplifyModuleDefinition(def string) string {
-	var result string
-	for _, line := range strings.Split(def, "\n") {
-		result += strings.TrimSpace(line)
+		},
 	}
-	return result
-}
-func TestProcessModule(t *testing.T) {
+
 	for i, testCase := range testCases {
 		t.Run(testCase.name, func(t *testing.T) {
-			targetedProperties.Set(testCase.property)
-			addIdents.Set(testCase.addSet)
-			removeIdents.Set(testCase.removeSet)
-			removeProperty = &testCase.removeProperty
-			moveProperty = &testCase.moveProperty
-			newLocation = testCase.newLocation
-			setString = testCase.setString
-			setBool = testCase.setBool
-			addLiteral = testCase.addLiteral
-			replaceProperty.Set(testCase.replaceProperty)
-
-			inAst, errs := parser.ParseAndEval("", strings.NewReader(testCase.input), parser.NewScope(nil))
-			if len(errs) > 0 {
-				for _, err := range errs {
-					t.Errorf("  %s", err)
-				}
-				t.Errorf("failed to parse:")
-				t.Errorf("%+v", testCase)
-				t.FailNow()
-			}
-			if inModule, ok := inAst.Defs[0].(*parser.Module); !ok {
-				t.Fatalf("  input must only contain a single module definition: %s", testCase.input)
-			} else {
-				for _, p := range targetedProperties.properties {
-					_, errs := processModuleProperty(inModule, "", inAst, p)
-					if len(errs) > 0 {
-						t.Errorf("test case %d:", i)
-						for _, err := range errs {
-							t.Errorf("  %s", err)
+			bp, err := NewBlueprint("", []byte(testCase.input))
+			if err != nil {
+				t.Fatalf("error creating Blueprint: %s", err)
+			}
+			err = nil
+			func() {
+				defer func() {
+					if r := recover(); r != nil {
+						if recoveredErr, ok := r.(error); ok {
+							err = recoveredErr
+						} else {
+							t.Fatalf("unexpected panic: %q", r)
 						}
 					}
-
+				}()
+				testCase.f(bp)
+			}()
+			if err != nil {
+				if testCase.err != "" {
+					if g, w := err.Error(), testCase.err; !strings.Contains(w, g) {
+						t.Errorf("unexpected error, want %q, got %q", g, w)
+					}
+				} else {
+					t.Errorf("unexpected error %q", err.Error())
 				}
-				inModuleText, _ := parser.Print(inAst)
-				inModuleString := string(inModuleText)
-				if simplifyModuleDefinition(inModuleString) != simplifyModuleDefinition(testCase.output) {
-					t.Errorf("test case %d:", i)
-					t.Errorf("expected module definition:")
-					t.Errorf("  %s", testCase.output)
-					t.Errorf("actual module definition:")
-					t.Errorf("  %s", inModuleString)
+			} else {
+				if testCase.err != "" {
+					t.Errorf("missing error, expected %q", testCase.err)
 				}
 			}
-		})
-	}
-}
 
-func TestReplacementsCycleError(t *testing.T) {
-	cycleString := "old1=new1,new1=old1"
-	err := replaceProperty.Set(cycleString)
-
-	if err.Error() != "Duplicated replacement name new1" {
-		t.Errorf("Error message did not match")
-		t.Errorf("Expected ")
-		t.Errorf(" Duplicated replacement name new1")
-		t.Errorf("actual error:")
-		t.Errorf("  %s", err.Error())
-		t.FailNow()
-	}
-}
-
-func TestReplacementsDuplicatedError(t *testing.T) {
-	cycleString := "a=b,a=c"
-	err := replaceProperty.Set(cycleString)
-
-	if err.Error() != "Duplicated replacement name a" {
-		t.Errorf("Error message did not match")
-		t.Errorf("Expected ")
-		t.Errorf(" Duplicated replacement name a")
-		t.Errorf("actual error:")
-		t.Errorf("  %s", err.Error())
-		t.FailNow()
-	}
-}
-
-func TestReplacementsMultipleReplacedToSame(t *testing.T) {
-	cycleString := "a=c,d=c"
-	err := replaceProperty.Set(cycleString)
+			if g, w := bp.Modified(), testCase.modified; g != w {
+				t.Errorf("incorrect bp.Modified() value, want %v, got %v", w, g)
+			}
 
-	if err.Error() != "Duplicated replacement name c" {
-		t.Errorf("Error message did not match")
-		t.Errorf("Expected ")
-		t.Errorf(" Duplicated replacement name c")
-		t.Errorf("actual error:")
-		t.Errorf("  %s", err.Error())
-		t.FailNow()
+			inModuleString := bp.String()
+			if simplifyModuleDefinition(inModuleString) != simplifyModuleDefinition(testCase.output) {
+				t.Errorf("test case %d:", i)
+				t.Errorf("expected module definition:")
+				t.Errorf("  %s", testCase.output)
+				t.Errorf("actual module definition:")
+				t.Errorf("  %s", inModuleString)
+			}
+		})
 	}
 }
diff --git a/bpmodify/cmd/Android.bp b/bpmodify/cmd/Android.bp
new file mode 100644
index 0000000..c0d07c6
--- /dev/null
+++ b/bpmodify/cmd/Android.bp
@@ -0,0 +1,9 @@
+blueprint_go_binary {
+    name: "bpmodify",
+    deps: [
+        "blueprint-bpmodify",
+        "blueprint-proptools",
+    ],
+    srcs: ["main.go"],
+    testSrcs: ["main_test.go"],
+}
diff --git a/bpmodify/cmd/main.go b/bpmodify/cmd/main.go
new file mode 100644
index 0000000..9e98c0b
--- /dev/null
+++ b/bpmodify/cmd/main.go
@@ -0,0 +1,440 @@
+// Mostly copied from Go's src/cmd/gofmt:
+// Copyright 2009 The Go Authors. All rights reserved.
+// Use of this source code is governed by a BSD-style
+// license that can be found in the LICENSE file.
+
+package main
+
+import (
+	"flag"
+	"fmt"
+	"io"
+	"io/ioutil"
+	"os"
+	"os/exec"
+	"path/filepath"
+	"strings"
+	"syscall"
+	"unicode"
+
+	"github.com/google/blueprint/bpmodify"
+)
+
+var (
+	// main operation modes
+	list               = flag.Bool("l", false, "list files that would be modified by bpmodify")
+	write              = flag.Bool("w", false, "write result to (source) file instead of stdout")
+	doDiff             = flag.Bool("d", false, "display diffs instead of rewriting files")
+	sortLists          = flag.Bool("s", false, "sort touched lists, even if they were unsorted")
+	targetedModules    = new(identSet)
+	targetedProperties = new(identSet)
+	addIdents          = new(identSet)
+	removeIdents       = new(identSet)
+	removeProperty     = flag.Bool("remove-property", false, "remove the property")
+	moveProperty       = flag.Bool("move-property", false, "moves contents of property into newLocation")
+	newLocation        string
+	setString          *string
+	addLiteral         *string
+	setBool            *string
+	replaceProperty    = new(replacements)
+)
+
+func init() {
+	flag.Var(targetedModules, "m", "comma or whitespace separated list of modules on which to operate")
+	flag.Var(targetedProperties, "parameter", "alias to -property=`name1[,name2[,... […]")
+	flag.StringVar(&newLocation, "new-location", "", " use with moveProperty to move contents of -property into a property with name -new-location ")
+	flag.Var(targetedProperties, "property", "comma-separated list of fully qualified `name`s of properties to modify (default \"deps\")")
+	flag.Var(addIdents, "a", "comma or whitespace separated list of identifiers to add")
+	flag.Var(stringPtrFlag{&addLiteral}, "add-literal", "a literal to add to a list")
+	flag.Var(removeIdents, "r", "comma or whitespace separated list of identifiers to remove")
+	flag.Var(stringPtrFlag{&setString}, "str", "set a string property")
+	flag.Var(replaceProperty, "replace-property", "property names to be replaced, in the form of oldName1=newName1,oldName2=newName2")
+	flag.Var(stringPtrFlag{&setBool}, "set-bool", "a boolean value to set a property with (not a list)")
+	flag.Usage = usage
+}
+
+var (
+	exitCode = 0
+)
+
+func report(err error) {
+	fmt.Fprintln(os.Stderr, err)
+	exitCode = 2
+}
+
+func usage() {
+	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] [path ...]\n", os.Args[0])
+	flag.PrintDefaults()
+}
+
+func processBp(bp *bpmodify.Blueprint) error {
+	var modules *bpmodify.ModuleSet
+	if targetedModules.all {
+		modules = bp.AllModules()
+	} else {
+		modules = bp.ModulesByName(targetedModules.idents...)
+	}
+
+	if *removeProperty {
+		// remove-property is used solely, so return here.
+		return modules.RemoveProperty(targetedProperties.idents...)
+	} else if *moveProperty {
+		return modules.MoveProperty(newLocation, targetedProperties.idents...)
+	} else if len(addIdents.idents) > 0 {
+		props, err := modules.GetOrCreateProperty(bpmodify.List, targetedProperties.idents...)
+		if err != nil {
+			return err
+		}
+		return props.AddStringToList(addIdents.idents...)
+	} else if addLiteral != nil {
+		props, err := modules.GetOrCreateProperty(bpmodify.List, targetedProperties.idents...)
+		if err != nil {
+			return err
+		}
+		return props.AddLiteral(*addLiteral)
+	} else if setString != nil {
+		props, err := modules.GetOrCreateProperty(bpmodify.String, targetedProperties.idents...)
+		if err != nil {
+			return err
+		}
+		return props.SetString(*setString)
+	} else if setBool != nil {
+		props, err := modules.GetOrCreateProperty(bpmodify.Bool, targetedProperties.idents...)
+		if err != nil {
+			return err
+		}
+		var value bool
+		if *setBool == "true" {
+			value = true
+		} else if *setBool == "false" {
+			value = false
+		} else {
+			return fmt.Errorf("expected parameter to be true or false, found %s", *setBool)
+		}
+		return props.SetBool(value)
+	} else {
+		props, err := modules.GetProperty(targetedProperties.idents...)
+		if err != nil {
+			return err
+		}
+		if len(removeIdents.idents) > 0 {
+			return props.RemoveStringFromList(removeIdents.idents...)
+		} else if replaceProperty.size() != 0 {
+			return props.ReplaceStrings(replaceProperty.oldNameToNewName)
+		}
+	}
+
+	return nil
+}
+
+// If in == nil, the source is the contents of the file with the given filename.
+func processFile(filename string, in io.Reader, out io.Writer) error {
+	if in == nil {
+		f, err := os.Open(filename)
+		if err != nil {
+			return err
+		}
+		defer f.Close()
+		if *write {
+			syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
+		}
+		in = f
+	}
+
+	src, err := io.ReadAll(in)
+	if err != nil {
+		return err
+	}
+
+	bp, err := bpmodify.NewBlueprint(filename, src)
+	if err != nil {
+		return err
+	}
+
+	err = processBp(bp)
+	if err != nil {
+		return err
+	}
+
+	res, err := bp.Bytes()
+	if err != nil {
+		return err
+	}
+	if *list {
+		fmt.Fprintln(out, filename)
+	}
+	if *write {
+		err = os.WriteFile(filename, res, 0644)
+		if err != nil {
+			return err
+		}
+	}
+	if *doDiff {
+		data, err := diff(src, res)
+		if err != nil {
+			return fmt.Errorf("computing diff: %s", err)
+		}
+		fmt.Printf("diff %s bpfmt/%s\n", filename, filename)
+		out.Write(data)
+	}
+	if !*list && !*write && !*doDiff {
+		_, err = out.Write(res)
+	}
+
+	return err
+}
+
+func visitFile(path string, f os.FileInfo, err error) error {
+	//TODO(dacek): figure out a better way to target intended .bp files without parsing errors
+	if err == nil && (f.Name() == "Blueprints" || strings.HasSuffix(f.Name(), ".bp")) {
+		err = processFile(path, nil, os.Stdout)
+	}
+	if err != nil {
+		report(err)
+	}
+	return nil
+}
+
+func walkDir(path string) {
+	filepath.Walk(path, visitFile)
+}
+
+func main() {
+	defer func() {
+		if err := recover(); err != nil {
+			report(fmt.Errorf("error: %s", err))
+		}
+		os.Exit(exitCode)
+	}()
+	flag.Parse()
+
+	if len(targetedProperties.idents) == 0 && *moveProperty {
+		report(fmt.Errorf("-move-property must specify property"))
+		return
+	}
+
+	if len(targetedProperties.idents) == 0 {
+		targetedProperties.Set("deps")
+	}
+	if flag.NArg() == 0 {
+		if *write {
+			report(fmt.Errorf("error: cannot use -w with standard input"))
+			return
+		}
+		if err := processFile("<standard input>", os.Stdin, os.Stdout); err != nil {
+			report(err)
+		}
+		return
+	}
+	if len(targetedModules.idents) == 0 {
+		report(fmt.Errorf("-m parameter is required"))
+		return
+	}
+
+	if len(addIdents.idents) == 0 && len(removeIdents.idents) == 0 && setString == nil && addLiteral == nil && !*removeProperty && !*moveProperty && (*replaceProperty).size() == 0 && setBool == nil {
+		report(fmt.Errorf("-a, -add-literal, -r, -remove-property, -move-property, replace-property or -str parameter is required"))
+		return
+	}
+	if *removeProperty && (len(addIdents.idents) > 0 || len(removeIdents.idents) > 0 || setString != nil || addLiteral != nil || (*replaceProperty).size() > 0) {
+		report(fmt.Errorf("-remove-property cannot be used with other parameter(s)"))
+		return
+	}
+	if *moveProperty && (len(addIdents.idents) > 0 || len(removeIdents.idents) > 0 || setString != nil || addLiteral != nil || (*replaceProperty).size() > 0) {
+		report(fmt.Errorf("-move-property cannot be used with other parameter(s)"))
+		return
+	}
+	if *moveProperty && newLocation == "" {
+		report(fmt.Errorf("-move-property must specify -new-location"))
+		return
+	}
+	for i := 0; i < flag.NArg(); i++ {
+		path := flag.Arg(i)
+		switch dir, err := os.Stat(path); {
+		case err != nil:
+			report(err)
+		case dir.IsDir():
+			walkDir(path)
+		default:
+			if err := processFile(path, nil, os.Stdout); err != nil {
+				report(err)
+			}
+		}
+	}
+}
+
+func diff(b1, b2 []byte) (data []byte, err error) {
+	f1, err := ioutil.TempFile("", "bpfmt")
+	if err != nil {
+		return
+	}
+	defer os.Remove(f1.Name())
+	defer f1.Close()
+	f2, err := ioutil.TempFile("", "bpfmt")
+	if err != nil {
+		return
+	}
+	defer os.Remove(f2.Name())
+	defer f2.Close()
+	f1.Write(b1)
+	f2.Write(b2)
+	data, err = exec.Command("diff", "-uw", f1.Name(), f2.Name()).CombinedOutput()
+	if len(data) > 0 {
+		// diff exits with a non-zero status when the files don't match.
+		// Ignore that failure as long as we get output.
+		err = nil
+	}
+	return
+}
+
+type stringPtrFlag struct {
+	s **string
+}
+
+func (f stringPtrFlag) Set(s string) error {
+	*f.s = &s
+	return nil
+}
+func (f stringPtrFlag) String() string {
+	if f.s == nil || *f.s == nil {
+		return ""
+	}
+	return **f.s
+}
+
+type replacements struct {
+	oldNameToNewName map[string]string
+}
+
+func (m *replacements) String() string {
+	ret := ""
+	sep := ""
+	for k, v := range m.oldNameToNewName {
+		ret += sep
+		ret += k
+		ret += ":"
+		ret += v
+		sep = ","
+	}
+	return ret
+}
+
+func (m *replacements) Set(s string) error {
+	usedNames := make(map[string]struct{})
+
+	pairs := strings.Split(s, ",")
+	length := len(pairs)
+	m.oldNameToNewName = make(map[string]string)
+	for i := 0; i < length; i++ {
+
+		pair := strings.SplitN(pairs[i], "=", 2)
+		if len(pair) != 2 {
+			return fmt.Errorf("Invalid replacement pair %s", pairs[i])
+		}
+		oldName := pair[0]
+		newName := pair[1]
+		if _, seen := usedNames[oldName]; seen {
+			return fmt.Errorf("Duplicated replacement name %s", oldName)
+		}
+		if _, seen := usedNames[newName]; seen {
+			return fmt.Errorf("Duplicated replacement name %s", newName)
+		}
+		usedNames[oldName] = struct{}{}
+		usedNames[newName] = struct{}{}
+		m.oldNameToNewName[oldName] = newName
+	}
+	return nil
+}
+
+func (m *replacements) Get() interface{} {
+	//TODO(dacek): Remove Get() method from interface as it seems unused.
+	return m.oldNameToNewName
+}
+
+func (m *replacements) size() (length int) {
+	return len(m.oldNameToNewName)
+}
+
+type identSet struct {
+	idents []string
+	all    bool
+}
+
+func (m *identSet) String() string {
+	return strings.Join(m.idents, ",")
+}
+func (m *identSet) Set(s string) error {
+	m.idents = strings.FieldsFunc(s, func(c rune) bool {
+		return unicode.IsSpace(c) || c == ','
+	})
+	if len(m.idents) == 1 && m.idents[0] == "*" {
+		m.all = true
+	}
+	return nil
+}
+func (m *identSet) Get() interface{} {
+	return m.idents
+}
+
+type qualifiedProperties struct {
+	properties []qualifiedProperty
+}
+
+type qualifiedProperty struct {
+	parts []string
+}
+
+var _ flag.Getter = (*qualifiedProperties)(nil)
+
+func (p *qualifiedProperty) name() string {
+	return p.parts[len(p.parts)-1]
+}
+func (p *qualifiedProperty) prefixes() []string {
+	return p.parts[:len(p.parts)-1]
+}
+func (p *qualifiedProperty) String() string {
+	return strings.Join(p.parts, ".")
+}
+
+func parseQualifiedProperty(s string) (*qualifiedProperty, error) {
+	parts := strings.Split(s, ".")
+	if len(parts) == 0 {
+		return nil, fmt.Errorf("%q is not a valid property name", s)
+	}
+	for _, part := range parts {
+		if part == "" {
+			return nil, fmt.Errorf("%q is not a valid property name", s)
+		}
+	}
+	prop := qualifiedProperty{parts}
+	return &prop, nil
+
+}
+
+func (p *qualifiedProperties) Set(s string) error {
+	properties := strings.Split(s, ",")
+	if len(properties) == 0 {
+		return fmt.Errorf("%q is not a valid property name", s)
+	}
+
+	p.properties = make([]qualifiedProperty, len(properties))
+	for i := 0; i < len(properties); i++ {
+		tmp, err := parseQualifiedProperty(properties[i])
+		if err != nil {
+			return err
+		}
+		p.properties[i] = *tmp
+	}
+	return nil
+}
+
+func (p *qualifiedProperties) String() string {
+	arrayLength := len(p.properties)
+	props := make([]string, arrayLength)
+	for i := 0; i < len(p.properties); i++ {
+		props[i] = p.properties[i].String()
+	}
+	return strings.Join(props, ",")
+}
+func (p *qualifiedProperties) Get() interface{} {
+	return p.properties
+}
diff --git a/bpmodify/cmd/main_test.go b/bpmodify/cmd/main_test.go
new file mode 100644
index 0000000..24d1a66
--- /dev/null
+++ b/bpmodify/cmd/main_test.go
@@ -0,0 +1,616 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package main
+
+import (
+	"bytes"
+	"strings"
+	"testing"
+
+	"github.com/google/blueprint/proptools"
+)
+
+var testCases = []struct {
+	name            string
+	input           string
+	output          string
+	property        string
+	addSet          string
+	removeSet       string
+	addLiteral      *string
+	setString       *string
+	setBool         *string
+	removeProperty  bool
+	replaceProperty string
+	moveProperty    bool
+	newLocation     string
+}{
+	{
+		name: "add",
+		input: `
+			cc_foo {
+				name: "foo",
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				deps: ["bar"],
+			}
+		`,
+		property: "deps",
+		addSet:   "bar",
+	},
+	{
+		name: "remove",
+		input: `
+			cc_foo {
+				name: "foo",
+				deps: ["bar"],
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				deps: [],
+			}
+		`,
+		property:  "deps",
+		removeSet: "bar",
+	},
+	{
+		name: "nested add",
+		input: `
+			cc_foo {
+				name: "foo",
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				arch: {
+					arm: {
+						deps: [
+							"dep2",
+							"nested_dep",],
+					},
+				},
+			}
+		`,
+		property: "arch.arm.deps",
+		addSet:   "nested_dep,dep2",
+	},
+	{
+		name: "nested remove",
+		input: `
+			cc_foo {
+				name: "foo",
+				arch: {
+					arm: {
+						deps: [
+							"dep2",
+							"nested_dep",
+						],
+					},
+				},
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				arch: {
+					arm: {
+						deps: [
+						],
+					},
+				},
+			}
+		`,
+		property:  "arch.arm.deps",
+		removeSet: "nested_dep,dep2",
+	},
+	{
+		name: "add existing",
+		input: `
+			cc_foo {
+				name: "foo",
+				arch: {
+					arm: {
+						deps: [
+							"nested_dep",
+							"dep2",
+						],
+					},
+				},
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				arch: {
+					arm: {
+						deps: [
+							"nested_dep",
+							"dep2",
+						],
+					},
+				},
+			}
+		`,
+		property: "arch.arm.deps",
+		addSet:   "dep2,dep2",
+	},
+	{
+		name: "remove missing",
+		input: `
+			cc_foo {
+				name: "foo",
+				arch: {
+					arm: {
+						deps: [
+							"nested_dep",
+							"dep2",
+						],
+					},
+				},
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				arch: {
+					arm: {
+						deps: [
+							"nested_dep",
+							"dep2",
+						],
+					},
+				},
+			}
+		`,
+		property:  "arch.arm.deps",
+		removeSet: "dep3,dep4",
+	},
+	{
+		name: "remove non existent",
+		input: `
+			cc_foo {
+				name: "foo",
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+			}
+		`,
+		property:  "deps",
+		removeSet: "bar",
+	},
+	{
+		name: "remove non existent nested",
+		input: `
+			cc_foo {
+				name: "foo",
+				arch: {},
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				arch: {},
+			}
+		`,
+		property:  "arch.arm.deps",
+		removeSet: "dep3,dep4",
+	},
+	{
+		name: "add numeric sorted",
+		input: `
+			cc_foo {
+				name: "foo",
+				versions: ["1", "2"],
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				versions: [
+					"1",
+					"2",
+					"10",
+				],
+			}
+		`,
+		property: "versions",
+		addSet:   "10",
+	},
+	{
+		name: "add mixed sorted",
+		input: `
+			cc_foo {
+				name: "foo",
+				deps: ["bar-v1-bar", "bar-v2-bar"],
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				deps: [
+					"bar-v1-bar",
+					"bar-v2-bar",
+					"bar-v10-bar",
+				],
+			}
+		`,
+		property: "deps",
+		addSet:   "bar-v10-bar",
+	},
+	{
+		name:  "add a struct with literal",
+		input: `cc_foo {name: "foo"}`,
+		output: `cc_foo {
+    name: "foo",
+    structs: [
+        {
+            version: "1",
+            imports: [
+                "bar1",
+                "bar2",
+            ],
+        },
+    ],
+}
+`,
+		property:   "structs",
+		addLiteral: proptools.StringPtr(`{version: "1", imports: ["bar1", "bar2"]}`),
+	},
+	{
+		name: "set string",
+		input: `
+			cc_foo {
+				name: "foo",
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				foo: "bar",
+			}
+		`,
+		property:  "foo",
+		setString: proptools.StringPtr("bar"),
+	},
+	{
+		name: "set existing string",
+		input: `
+			cc_foo {
+				name: "foo",
+				foo: "baz",
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				foo: "bar",
+			}
+		`,
+		property:  "foo",
+		setString: proptools.StringPtr("bar"),
+	},
+	{
+		name: "set bool",
+		input: `
+			cc_foo {
+				name: "foo",
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				foo: true,
+			}
+		`,
+		property: "foo",
+		setBool:  proptools.StringPtr("true"),
+	},
+	{
+		name: "set existing bool",
+		input: `
+			cc_foo {
+				name: "foo",
+				foo: true,
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				foo: false,
+			}
+		`,
+		property: "foo",
+		setBool:  proptools.StringPtr("false"),
+	},
+	{
+		name: "remove existing property",
+		input: `
+			cc_foo {
+				name: "foo",
+				foo: "baz",
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+			}
+		`,
+		property:       "foo",
+		removeProperty: true,
+	}, {
+		name: "remove nested property",
+		input: `
+		cc_foo {
+			name: "foo",
+			foo: {
+				bar: "baz",
+			},
+		}
+	`,
+		output: `
+		cc_foo {
+			name: "foo",
+			foo: {},
+		}
+	`,
+		property:       "foo.bar",
+		removeProperty: true,
+	}, {
+		name: "remove non-existing property",
+		input: `
+			cc_foo {
+				name: "foo",
+				foo: "baz",
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				foo: "baz",
+			}
+		`,
+		property:       "bar",
+		removeProperty: true,
+	}, {
+		name:     "replace property",
+		property: "deps",
+		input: `
+			cc_foo {
+				name: "foo",
+				deps: ["baz", "unchanged"],
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				deps: [
+                "baz_lib",
+                "unchanged",
+				],
+			}
+		`,
+		replaceProperty: "baz=baz_lib,foobar=foobar_lib",
+	}, {
+		name:     "replace property multiple modules",
+		property: "deps,required",
+		input: `
+			cc_foo {
+				name: "foo",
+				deps: ["baz", "unchanged"],
+				unchanged: ["baz"],
+				required: ["foobar"],
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				deps: [
+								"baz_lib",
+								"unchanged",
+				],
+				unchanged: ["baz"],
+				required: ["foobar_lib"],
+			}
+		`,
+		replaceProperty: "baz=baz_lib,foobar=foobar_lib",
+	}, {
+		name:     "replace property string value",
+		property: "name",
+		input: `
+			cc_foo {
+				name: "foo",
+				deps: ["baz"],
+				unchanged: ["baz"],
+				required: ["foobar"],
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo_lib",
+				deps: ["baz"],
+				unchanged: ["baz"],
+				required: ["foobar"],
+			}
+		`,
+		replaceProperty: "foo=foo_lib",
+	}, {
+		name:     "replace property string and list values",
+		property: "name,deps",
+		input: `
+			cc_foo {
+				name: "foo",
+				deps: ["baz"],
+				unchanged: ["baz"],
+				required: ["foobar"],
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo_lib",
+				deps: ["baz_lib"],
+				unchanged: ["baz"],
+				required: ["foobar"],
+			}
+		`,
+		replaceProperty: "foo=foo_lib,baz=baz_lib",
+	}, {
+		name: "move contents of property into non-existing property",
+		input: `
+			cc_foo {
+				name: "foo",
+				bar: ["barContents"],
+				}
+`,
+		output: `
+			cc_foo {
+				name: "foo",
+				baz: ["barContents"],
+			}
+		`,
+		property:     "bar",
+		moveProperty: true,
+		newLocation:  "baz",
+	}, {
+		name: "move contents of property into existing property",
+		input: `
+			cc_foo {
+				name: "foo",
+				baz: ["bazContents"],
+				bar: ["barContents"],
+			}
+		`,
+		output: `
+			cc_foo {
+				name: "foo",
+				baz: [
+					"bazContents",
+					"barContents",
+				],
+
+			}
+		`,
+		property:     "bar",
+		moveProperty: true,
+		newLocation:  "baz",
+	}, {
+		name: "replace nested",
+		input: `
+		cc_foo {
+			name: "foo",
+			foo: {
+				bar: "baz",
+			},
+		}
+	`,
+		output: `
+		cc_foo {
+			name: "foo",
+			foo: {
+				bar: "baz2",
+			},
+		}
+	`,
+		property:        "foo.bar",
+		replaceProperty: "baz=baz2",
+	},
+}
+
+func simplifyModuleDefinition(def string) string {
+	var result string
+	for _, line := range strings.Split(def, "\n") {
+		result += strings.TrimSpace(line)
+	}
+	return result
+}
+func TestProcessModule(t *testing.T) {
+	for _, testCase := range testCases {
+		t.Run(testCase.name, func(t *testing.T) {
+			targetedProperties.Set(testCase.property)
+			addIdents.Set(testCase.addSet)
+			removeIdents.Set(testCase.removeSet)
+			removeProperty = &testCase.removeProperty
+			moveProperty = &testCase.moveProperty
+			newLocation = testCase.newLocation
+			setString = testCase.setString
+			setBool = testCase.setBool
+			addLiteral = testCase.addLiteral
+			replaceProperty.Set(testCase.replaceProperty)
+
+			targetedModules.Set("foo")
+
+			out := &bytes.Buffer{}
+			err := processFile("", strings.NewReader(testCase.input), out)
+			if err != nil {
+				t.Fatalf("unexpected error: %s", err.Error())
+			}
+			if simplifyModuleDefinition(out.String()) != simplifyModuleDefinition(testCase.output) {
+				t.Errorf("expected module definition:")
+				t.Errorf("  %s", testCase.output)
+				t.Errorf("actual module definition:")
+				t.Errorf("  %s", out.String())
+			}
+		})
+	}
+}
+
+func TestReplacementsCycleError(t *testing.T) {
+	cycleString := "old1=new1,new1=old1"
+	err := replaceProperty.Set(cycleString)
+
+	if err.Error() != "Duplicated replacement name new1" {
+		t.Errorf("Error message did not match")
+		t.Errorf("Expected ")
+		t.Errorf(" Duplicated replacement name new1")
+		t.Errorf("actual error:")
+		t.Errorf("  %s", err.Error())
+		t.FailNow()
+	}
+}
+
+func TestReplacementsDuplicatedError(t *testing.T) {
+	cycleString := "a=b,a=c"
+	err := replaceProperty.Set(cycleString)
+
+	if err.Error() != "Duplicated replacement name a" {
+		t.Errorf("Error message did not match")
+		t.Errorf("Expected ")
+		t.Errorf(" Duplicated replacement name a")
+		t.Errorf("actual error:")
+		t.Errorf("  %s", err.Error())
+		t.FailNow()
+	}
+}
+
+func TestReplacementsMultipleReplacedToSame(t *testing.T) {
+	cycleString := "a=c,d=c"
+	err := replaceProperty.Set(cycleString)
+
+	if err.Error() != "Duplicated replacement name c" {
+		t.Errorf("Error message did not match")
+		t.Errorf("Expected ")
+		t.Errorf(" Duplicated replacement name c")
+		t.Errorf("actual error:")
+		t.Errorf("  %s", err.Error())
+		t.FailNow()
+	}
+}
diff --git a/context.go b/context.go
index 33ad4cd..2e0d566 100644
--- a/context.go
+++ b/context.go
@@ -26,6 +26,7 @@ import (
 	"hash/fnv"
 	"io"
 	"io/ioutil"
+	"iter"
 	"maps"
 	"math"
 	"os"
@@ -35,6 +36,7 @@ import (
 	"runtime/pprof"
 	"slices"
 	"sort"
+	"strconv"
 	"strings"
 	"sync"
 	"sync/atomic"
@@ -94,7 +96,6 @@ type Context struct {
 	nameInterface       NameInterface
 	moduleGroups        []*moduleGroup
 	moduleInfo          map[Module]*moduleInfo
-	modulesSorted       []*moduleInfo
 	singletonInfo       []*singletonInfo
 	mutatorInfo         []*mutatorInfo
 	variantMutatorNames []string
@@ -103,7 +104,7 @@ type Context struct {
 
 	transitionMutators []*transitionMutatorImpl
 
-	depsModified uint32 // positive if a mutator modified the dependencies
+	needsUpdateDependencies uint32 // positive if a mutator modified the dependencies
 
 	dependenciesReady bool // set to true on a successful ResolveDependencies
 	buildActionsReady bool // set to true on a successful PrepareBuildActions
@@ -114,8 +115,6 @@ type Context struct {
 	// set by SetAllowMissingDependencies
 	allowMissingDependencies bool
 
-	verifyProvidersAreUnchanged bool
-
 	// set during PrepareBuildActions
 	nameTracker     *nameTracker
 	liveGlobals     *liveTracker
@@ -148,10 +147,8 @@ type Context struct {
 	// not be registered in this Context.
 	providerMutators []*mutatorInfo
 
-	// The currently running mutator
-	startedMutator *mutatorInfo
-	// True for any mutators that have already run over all modules
-	finishedMutators map[*mutatorInfo]bool
+	// True for the index of any mutators that have already run over all modules
+	finishedMutators []bool
 
 	// If true, RunBlueprint will skip cloning modules at the end of RunBlueprint.
 	// Cloning modules intentionally invalidates some Module values after
@@ -244,6 +241,19 @@ func (c *Context) ContainsIncludeTag(name string) bool {
 	return c.includeTags.Contains(name)
 }
 
+// iterateAllVariants returns an iter.Seq that iterates over every variant of every module.
+func (c *Context) iterateAllVariants() iter.Seq[*moduleInfo] {
+	return func(yield func(*moduleInfo) bool) {
+		for _, group := range c.moduleGroups {
+			for _, module := range group.modules {
+				if !yield(module) {
+					return
+				}
+			}
+		}
+	}
+}
+
 // An Error describes a problem that was encountered that is related to a
 // particular location in a Blueprints file.
 type BlueprintError struct {
@@ -283,44 +293,18 @@ type localBuildActions struct {
 	buildDefs []*buildDef
 }
 
-type moduleAlias struct {
-	variant variant
-	target  *moduleInfo
-}
-
-func (m *moduleAlias) alias() *moduleAlias              { return m }
-func (m *moduleAlias) module() *moduleInfo              { return nil }
-func (m *moduleAlias) moduleOrAliasTarget() *moduleInfo { return m.target }
-func (m *moduleAlias) moduleOrAliasVariant() variant    { return m.variant }
-
-func (m *moduleInfo) alias() *moduleAlias              { return nil }
-func (m *moduleInfo) module() *moduleInfo              { return m }
-func (m *moduleInfo) moduleOrAliasTarget() *moduleInfo { return m }
-func (m *moduleInfo) moduleOrAliasVariant() variant    { return m.variant }
-
-type moduleOrAlias interface {
-	alias() *moduleAlias
-	module() *moduleInfo
-	moduleOrAliasTarget() *moduleInfo
-	moduleOrAliasVariant() variant
-}
-
-type modulesOrAliases []moduleOrAlias
+type moduleList []*moduleInfo
 
-func (l modulesOrAliases) firstModule() *moduleInfo {
-	for _, moduleOrAlias := range l {
-		if m := moduleOrAlias.module(); m != nil {
-			return m
-		}
+func (l moduleList) firstModule() *moduleInfo {
+	if len(l) > 0 {
+		return l[0]
 	}
 	panic(fmt.Errorf("no first module!"))
 }
 
-func (l modulesOrAliases) lastModule() *moduleInfo {
-	for i := range l {
-		if m := l[len(l)-1-i].module(); m != nil {
-			return m
-		}
+func (l moduleList) lastModule() *moduleInfo {
+	if len(l) > 0 {
+		return l[len(l)-1]
 	}
 	panic(fmt.Errorf("no last module!"))
 }
@@ -329,24 +313,20 @@ type moduleGroup struct {
 	name      string
 	ninjaName string
 
-	modules modulesOrAliases
+	modules moduleList
 
 	namespace Namespace
 }
 
-func (group *moduleGroup) moduleOrAliasByVariantName(name string) moduleOrAlias {
+func (group *moduleGroup) moduleByVariantName(name string) *moduleInfo {
 	for _, module := range group.modules {
-		if module.moduleOrAliasVariant().name == name {
+		if module.variant.name == name {
 			return module
 		}
 	}
 	return nil
 }
 
-func (group *moduleGroup) moduleByVariantName(name string) *moduleInfo {
-	return group.moduleOrAliasByVariantName(name).module()
-}
-
 type moduleInfo struct {
 	// set during Parse
 	typeName          string
@@ -364,7 +344,7 @@ type moduleInfo struct {
 
 	// set during ResolveDependencies
 	missingDeps   []string
-	newDirectDeps []depInfo
+	newDirectDeps []*moduleInfo
 
 	// set during updateDependencies
 	reverseDeps []*moduleInfo
@@ -375,7 +355,7 @@ type moduleInfo struct {
 	waitingCount int
 
 	// set during each runMutator
-	splitModules           modulesOrAliases
+	splitModules           moduleList
 	obsoletedByNewVariants bool
 
 	// Used by TransitionMutator implementations
@@ -393,8 +373,8 @@ type moduleInfo struct {
 	providers                  []interface{}
 	providerInitialValueHashes []uint64
 
-	startedMutator  *mutatorInfo
-	finishedMutator *mutatorInfo
+	startedMutator  int
+	finishedMutator int
 
 	startedGenerateBuildActions  bool
 	finishedGenerateBuildActions bool
@@ -405,13 +385,12 @@ type moduleInfo struct {
 type incrementalInfo struct {
 	incrementalRestored bool
 	buildActionCacheKey *BuildActionCacheKey
-	orderOnlyStrings    *[]string
+	orderOnlyStrings    []string
 }
 
 type variant struct {
-	name                 string
-	variations           variationMap
-	dependencyVariations variationMap
+	name       string
+	variations variationMap
 }
 
 type depInfo struct {
@@ -560,30 +539,36 @@ type mutatorInfo struct {
 	topDownMutator    TopDownMutator
 	bottomUpMutator   BottomUpMutator
 	name              string
-	parallel          bool
+	index             int
 	transitionMutator *transitionMutatorImpl
+
+	usesRename              bool
+	usesReverseDependencies bool
+	usesReplaceDependencies bool
+	usesCreateModule        bool
+	mutatesDependencies     bool
+	mutatesGlobalState      bool
+	neverFar                bool
 }
 
 func newContext() *Context {
 	eventHandler := metrics.EventHandler{}
 	return &Context{
-		Context:                     context.Background(),
-		EventHandler:                &eventHandler,
-		moduleFactories:             make(map[string]ModuleFactory),
-		nameInterface:               NewSimpleNameInterface(),
-		moduleInfo:                  make(map[Module]*moduleInfo),
-		globs:                       make(map[globKey]pathtools.GlobResult),
-		fs:                          pathtools.OsFs,
-		finishedMutators:            make(map[*mutatorInfo]bool),
-		includeTags:                 &IncludeTags{},
-		sourceRootDirs:              &SourceRootDirs{},
-		outDir:                      nil,
-		requiredNinjaMajor:          1,
-		requiredNinjaMinor:          7,
-		requiredNinjaMicro:          0,
-		verifyProvidersAreUnchanged: true,
-		buildActionsToCache:         make(BuildActionCache),
-		orderOnlyStringsToCache:     make(OrderOnlyStringsCache),
+		Context:                 context.Background(),
+		EventHandler:            &eventHandler,
+		moduleFactories:         make(map[string]ModuleFactory),
+		nameInterface:           NewSimpleNameInterface(),
+		moduleInfo:              make(map[Module]*moduleInfo),
+		globs:                   make(map[globKey]pathtools.GlobResult),
+		fs:                      pathtools.OsFs,
+		includeTags:             &IncludeTags{},
+		sourceRootDirs:          &SourceRootDirs{},
+		outDir:                  nil,
+		requiredNinjaMajor:      1,
+		requiredNinjaMinor:      7,
+		requiredNinjaMicro:      0,
+		buildActionsToCache:     make(BuildActionCache),
+		orderOnlyStringsToCache: make(OrderOnlyStringsCache),
 	}
 }
 
@@ -820,6 +805,7 @@ func (c *Context) RegisterTopDownMutator(name string, mutator TopDownMutator) Mu
 	info := &mutatorInfo{
 		topDownMutator: mutator,
 		name:           name,
+		index:          len(c.mutatorInfo),
 	}
 
 	c.mutatorInfo = append(c.mutatorInfo, info)
@@ -847,6 +833,7 @@ func (c *Context) RegisterBottomUpMutator(name string, mutator BottomUpMutator)
 	info := &mutatorInfo{
 		bottomUpMutator: mutator,
 		name:            name,
+		index:           len(c.mutatorInfo),
 	}
 	c.mutatorInfo = append(c.mutatorInfo, info)
 
@@ -860,24 +847,68 @@ func (c *Context) RegisterBottomUpMutator(name string, mutator BottomUpMutator)
 func (c *Context) HasMutatorFinished(mutatorName string) bool {
 	for _, mutator := range c.mutatorInfo {
 		if mutator.name == mutatorName {
-			finished, ok := c.finishedMutators[mutator]
-			return ok && finished
+			return len(c.finishedMutators) > mutator.index && c.finishedMutators[mutator.index]
 		}
 	}
 	panic(fmt.Sprintf("unknown mutator %q", mutatorName))
 }
 
 type MutatorHandle interface {
-	// Set the mutator to visit modules in parallel while maintaining ordering.  Calling any
-	// method on the mutator context is thread-safe, but the mutator must handle synchronization
-	// for any modifications to global state or any modules outside the one it was invoked on.
-	Parallel() MutatorHandle
+	// UsesRename marks the mutator as using the BottomUpMutatorContext.Rename method, which prevents
+	// coalescing adjacent mutators into a single mutator pass.
+	UsesRename() MutatorHandle
+
+	// UsesReverseDependencies marks the mutator as using the BottomUpMutatorContext.AddReverseDependency
+	// method, which prevents coalescing adjacent mutators into a single mutator pass.
+	UsesReverseDependencies() MutatorHandle
+
+	// UsesReplaceDependencies marks the mutator as using the BottomUpMutatorContext.ReplaceDependencies
+	// method, which prevents coalescing adjacent mutators into a single mutator pass.
+	UsesReplaceDependencies() MutatorHandle
+
+	// UsesCreateModule marks the mutator as using the BottomUpMutatorContext.CreateModule method,
+	// which prevents coalescing adjacent mutators into a single mutator pass.
+	UsesCreateModule() MutatorHandle
+
+	// MutatesDependencies marks the mutator as modifying properties in dependencies, which prevents
+	// coalescing adjacent mutators into a single mutator pass.
+	MutatesDependencies() MutatorHandle
+
+	// MutatesGlobalState marks the mutator as modifying global state, which prevents coalescing
+	// adjacent mutators into a single mutator pass.
+	MutatesGlobalState() MutatorHandle
 
 	setTransitionMutator(impl *transitionMutatorImpl) MutatorHandle
+	setNeverFar() MutatorHandle
+}
+
+func (mutator *mutatorInfo) UsesRename() MutatorHandle {
+	mutator.usesRename = true
+	return mutator
+}
+
+func (mutator *mutatorInfo) UsesReverseDependencies() MutatorHandle {
+	mutator.usesReverseDependencies = true
+	return mutator
+}
+
+func (mutator *mutatorInfo) UsesReplaceDependencies() MutatorHandle {
+	mutator.usesReplaceDependencies = true
+	return mutator
+}
+
+func (mutator *mutatorInfo) UsesCreateModule() MutatorHandle {
+	mutator.usesCreateModule = true
+	return mutator
 }
 
-func (mutator *mutatorInfo) Parallel() MutatorHandle {
-	mutator.parallel = true
+func (mutator *mutatorInfo) MutatesDependencies() MutatorHandle {
+	mutator.mutatesDependencies = true
+	return mutator
+}
+
+func (mutator *mutatorInfo) MutatesGlobalState() MutatorHandle {
+	mutator.mutatesGlobalState = true
 	return mutator
 }
 
@@ -886,6 +917,11 @@ func (mutator *mutatorInfo) setTransitionMutator(impl *transitionMutatorImpl) Mu
 	return mutator
 }
 
+func (mutator *mutatorInfo) setNeverFar() MutatorHandle {
+	mutator.neverFar = true
+	return mutator
+}
+
 // SetIgnoreUnknownModuleTypes sets the behavior of the context in the case
 // where it encounters an unknown module type while parsing Blueprints files. By
 // default, the context will report unknown module types as an error.  If this
@@ -906,18 +942,6 @@ func (c *Context) SetAllowMissingDependencies(allowMissingDependencies bool) {
 	c.allowMissingDependencies = allowMissingDependencies
 }
 
-// SetVerifyProvidersAreUnchanged makes blueprint hash all providers immediately
-// after SetProvider() is called, and then hash them again after the build finished.
-// If the hashes change, it's an error. Providers are supposed to be immutable, but
-// we don't have any more direct way to enforce that in go.
-func (c *Context) SetVerifyProvidersAreUnchanged(verifyProvidersAreUnchanged bool) {
-	c.verifyProvidersAreUnchanged = verifyProvidersAreUnchanged
-}
-
-func (c *Context) GetVerifyProvidersAreUnchanged() bool {
-	return c.verifyProvidersAreUnchanged
-}
-
 func (c *Context) SetModuleListFile(listFile string) {
 	c.moduleListFile = listFile
 }
@@ -1586,8 +1610,7 @@ func (c *Context) cloneLogicModule(origModule *moduleInfo) (Module, []interface{
 	return newLogicModule, newProperties
 }
 
-func newVariant(module *moduleInfo, mutatorName string, variationName string,
-	local bool) variant {
+func newVariant(module *moduleInfo, mutatorName string, variationName string) variant {
 
 	newVariantName := module.variant.name
 	if variationName != "" {
@@ -1601,23 +1624,22 @@ func newVariant(module *moduleInfo, mutatorName string, variationName string,
 	newVariations := module.variant.variations.clone()
 	newVariations.set(mutatorName, variationName)
 
-	newDependencyVariations := module.variant.dependencyVariations.clone()
-	if !local {
-		newDependencyVariations.set(mutatorName, variationName)
-	}
-
-	return variant{newVariantName, newVariations, newDependencyVariations}
+	return variant{newVariantName, newVariations}
 }
 
 func (c *Context) createVariations(origModule *moduleInfo, mutator *mutatorInfo,
-	depChooser depChooser, variationNames []string, local bool) (modulesOrAliases, []error) {
+	depChooser depChooser, variationNames []string) (moduleList, []error) {
+
+	if mutator.transitionMutator == nil {
+		panic(fmt.Errorf("method createVariations called from mutator that was not a TransitionMutator"))
+	}
 
 	if len(variationNames) == 0 {
 		panic(fmt.Errorf("mutator %q passed zero-length variation list for module %q",
 			mutator.name, origModule.Name()))
 	}
 
-	var newModules modulesOrAliases
+	var newModules moduleList
 
 	var errs []error
 
@@ -1640,7 +1662,7 @@ func (c *Context) createVariations(origModule *moduleInfo, mutator *mutatorInfo,
 		newModule.reverseDeps = nil
 		newModule.forwardDeps = nil
 		newModule.logicModule = newLogicModule
-		newModule.variant = newVariant(origModule, mutator.name, variationName, local)
+		newModule.variant = newVariant(origModule, mutator.name, variationName)
 		newModule.properties = newProperties
 		newModule.providers = slices.Clone(origModule.providers)
 		newModule.providerInitialValueHashes = slices.Clone(origModule.providerInitialValueHashes)
@@ -1658,25 +1680,25 @@ func (c *Context) createVariations(origModule *moduleInfo, mutator *mutatorInfo,
 	origModule.obsoletedByNewVariants = true
 	origModule.splitModules = newModules
 
-	atomic.AddUint32(&c.depsModified, 1)
+	atomic.AddUint32(&c.needsUpdateDependencies, 1)
 
 	return newModules, errs
 }
 
 type depChooser func(source *moduleInfo, variationIndex, depIndex int, dep depInfo) (*moduleInfo, string)
 
-func chooseDep(candidates modulesOrAliases, mutatorName, variationName string, defaultVariationName *string) (*moduleInfo, string) {
+func chooseDep(candidates moduleList, mutatorName, variationName string, defaultVariationName *string) (*moduleInfo, string) {
 	for _, m := range candidates {
-		if m.moduleOrAliasVariant().variations.get(mutatorName) == variationName {
-			return m.moduleOrAliasTarget(), ""
+		if m.variant.variations.get(mutatorName) == variationName {
+			return m, ""
 		}
 	}
 
 	if defaultVariationName != nil {
 		// give it a second chance; match with defaultVariationName
 		for _, m := range candidates {
-			if m.moduleOrAliasVariant().variations.get(mutatorName) == *defaultVariationName {
-				return m.moduleOrAliasTarget(), ""
+			if m.variant.variations.get(mutatorName) == *defaultVariationName {
+				return m, ""
 			}
 		}
 	}
@@ -1740,13 +1762,8 @@ func (c *Context) prettyPrintVariant(variations variationMap) string {
 
 func (c *Context) prettyPrintGroupVariants(group *moduleGroup) string {
 	var variants []string
-	for _, moduleOrAlias := range group.modules {
-		if mod := moduleOrAlias.module(); mod != nil {
-			variants = append(variants, c.prettyPrintVariant(mod.variant.variations))
-		} else if alias := moduleOrAlias.alias(); alias != nil {
-			variants = append(variants, c.prettyPrintVariant(alias.variant.variations)+
-				" (alias to "+c.prettyPrintVariant(alias.target.variant.variations)+")")
-		}
+	for _, module := range group.modules {
+		variants = append(variants, c.prettyPrintVariant(module.variant.variations))
 	}
 	return strings.Join(variants, "\n  ")
 }
@@ -1823,7 +1840,7 @@ func (c *Context) addModule(module *moduleInfo) []error {
 
 	group := &moduleGroup{
 		name:    name,
-		modules: modulesOrAliases{module},
+		modules: moduleList{module},
 	}
 	module.group = group
 	namespace, errs := c.nameInterface.NewModule(
@@ -1853,6 +1870,39 @@ func (c *Context) ResolveDependencies(config interface{}) (deps []string, errs [
 	return c.resolveDependencies(c.Context, config)
 }
 
+// coalesceMutators takes the list of mutators and returns a list of lists of mutators,
+// where sublist is a compatible group of mutators that can be run with relaxed
+// intra-mutator ordering.
+func coalesceMutators(mutators []*mutatorInfo) [][]*mutatorInfo {
+	var coalescedMutators [][]*mutatorInfo
+	var last *mutatorInfo
+
+	// Returns true if the mutator can be coalesced with other mutators that
+	// also return true.
+	coalescable := func(m *mutatorInfo) bool {
+		return m.bottomUpMutator != nil &&
+			m.transitionMutator == nil &&
+			!m.usesCreateModule &&
+			!m.usesReplaceDependencies &&
+			!m.usesReverseDependencies &&
+			!m.usesRename &&
+			!m.mutatesGlobalState &&
+			!m.mutatesDependencies
+	}
+
+	for _, mutator := range mutators {
+		if last != nil && coalescable(last) && coalescable(mutator) {
+			lastGroup := &coalescedMutators[len(coalescedMutators)-1]
+			*lastGroup = append(*lastGroup, mutator)
+		} else {
+			coalescedMutators = append(coalescedMutators, []*mutatorInfo{mutator})
+			last = mutator
+		}
+	}
+
+	return coalescedMutators
+}
+
 func (c *Context) resolveDependencies(ctx context.Context, config interface{}) (deps []string, errs []error) {
 	pprof.Do(ctx, pprof.Labels("blueprint", "ResolveDependencies"), func(ctx context.Context) {
 		c.initProviders()
@@ -1862,7 +1912,9 @@ func (c *Context) resolveDependencies(ctx context.Context, config interface{}) (
 			return
 		}
 
-		deps, errs = c.runMutators(ctx, config)
+		mutatorGroups := coalesceMutators(c.mutatorInfo)
+
+		deps, errs = c.runMutators(ctx, config, mutatorGroups)
 		if len(errs) > 0 {
 			return
 		}
@@ -1908,63 +1960,7 @@ func blueprintDepsMutator(ctx BottomUpMutatorContext) {
 	}
 }
 
-// findExactVariantOrSingle searches the moduleGroup for a module with the same variant as module,
-// and returns the matching module, or nil if one is not found.  A group with exactly one module
-// is always considered matching.
-func (c *Context) findExactVariantOrSingle(module *moduleInfo, config any, possible *moduleGroup, reverse bool) *moduleInfo {
-	found, _ := c.findVariant(module, config, possible, nil, false, reverse)
-	if found == nil {
-		for _, moduleOrAlias := range possible.modules {
-			if m := moduleOrAlias.module(); m != nil {
-				if found != nil {
-					// more than one possible match, give up
-					return nil
-				}
-				found = m
-			}
-		}
-	}
-	return found
-}
-
-func (c *Context) addDependency(module *moduleInfo, config any, tag DependencyTag, depName string) (*moduleInfo, []error) {
-	if _, ok := tag.(BaseDependencyTag); ok {
-		panic("BaseDependencyTag is not allowed to be used directly!")
-	}
-
-	if depName == module.Name() {
-		return nil, []error{&BlueprintError{
-			Err: fmt.Errorf("%q depends on itself", depName),
-			Pos: module.pos,
-		}}
-	}
-
-	possibleDeps := c.moduleGroupFromName(depName, module.namespace())
-	if possibleDeps == nil {
-		return nil, c.discoveredMissingDependencies(module, depName, variationMap{})
-	}
-
-	if m := c.findExactVariantOrSingle(module, config, possibleDeps, false); m != nil {
-		module.newDirectDeps = append(module.newDirectDeps, depInfo{m, tag})
-		atomic.AddUint32(&c.depsModified, 1)
-		return m, nil
-	}
-
-	if c.allowMissingDependencies {
-		// Allow missing variants.
-		return nil, c.discoveredMissingDependencies(module, depName, module.variant.dependencyVariations)
-	}
-
-	return nil, []error{&BlueprintError{
-		Err: fmt.Errorf("dependency %q of %q missing variant:\n  %s\navailable variants:\n  %s",
-			depName, module.Name(),
-			c.prettyPrintVariant(module.variant.dependencyVariations),
-			c.prettyPrintGroupVariants(possibleDeps)),
-		Pos: module.pos,
-	}}
-}
-
-func (c *Context) findReverseDependency(module *moduleInfo, config any, destName string) (*moduleInfo, []error) {
+func (c *Context) findReverseDependency(module *moduleInfo, config any, requestedVariations []Variation, destName string) (*moduleInfo, []error) {
 	if destName == module.Name() {
 		return nil, []error{&BlueprintError{
 			Err: fmt.Errorf("%q depends on itself", destName),
@@ -1981,19 +1977,21 @@ func (c *Context) findReverseDependency(module *moduleInfo, config any, destName
 		}}
 	}
 
-	if m := c.findExactVariantOrSingle(module, config, possibleDeps, true); m != nil {
+	if m, _, errs := c.findVariant(module, config, possibleDeps, requestedVariations, false, true); errs != nil {
+		return nil, errs
+	} else if m != nil {
 		return m, nil
 	}
 
 	if c.allowMissingDependencies {
 		// Allow missing variants.
-		return module, c.discoveredMissingDependencies(module, destName, module.variant.dependencyVariations)
+		return nil, c.discoveredMissingDependencies(module, destName, module.variant.variations)
 	}
 
 	return nil, []error{&BlueprintError{
 		Err: fmt.Errorf("reverse dependency %q of %q missing variant:\n  %s\navailable variants:\n  %s",
 			destName, module.Name(),
-			c.prettyPrintVariant(module.variant.dependencyVariations),
+			c.prettyPrintVariant(module.variant.variations),
 			c.prettyPrintGroupVariants(possibleDeps)),
 		Pos: module.pos,
 	}}
@@ -2004,7 +2002,7 @@ func (c *Context) findReverseDependency(module *moduleInfo, config any, destName
 // modify the requested variation.  It finds a variant that existed before the TransitionMutator ran that is
 // a subset of the requested variant to use as the module context for IncomingTransition.
 func (c *Context) applyTransitions(config any, module *moduleInfo, group *moduleGroup, variant variationMap,
-	requestedVariations []Variation) variationMap {
+	requestedVariations []Variation) (variationMap, []error) {
 	for _, transitionMutator := range c.transitionMutators {
 		explicitlyRequested := slices.ContainsFunc(requestedVariations, func(variation Variation) bool {
 			return variation.Mutator == transitionMutator.name
@@ -2020,6 +2018,9 @@ func (c *Context) applyTransitions(config any, module *moduleInfo, group *module
 					depTag: nil, postMutator: true, config: config},
 			}
 			outgoingVariation = transitionMutator.mutator.OutgoingTransition(ctx, sourceVariation)
+			if len(ctx.errs) > 0 {
+				return variationMap{}, ctx.errs
+			}
 		}
 
 		earlierVariantCreatingMutators := c.variantCreatingMutatorOrder[:transitionMutator.variantCreatingMutatorIndex]
@@ -2045,12 +2046,10 @@ func (c *Context) applyTransitions(config any, module *moduleInfo, group *module
 			// the mutator only created a single "" variant when it ran on this module.  Matching against all variants
 			// is slightly worse  than checking the input variants, as the selected variant could have been modified
 			// by a later mutator in a way that affects the results of IncomingTransition.
-			for _, moduleOrAlias := range group.modules {
-				if module := moduleOrAlias.module(); module != nil {
-					if check(module.variant.variations) {
-						matchingInputVariant = module
-						break
-					}
+			for _, module := range group.modules {
+				if check(module.variant.variations) {
+					matchingInputVariant = module
+					break
 				}
 			}
 		}
@@ -2063,6 +2062,9 @@ func (c *Context) applyTransitions(config any, module *moduleInfo, group *module
 			}
 
 			finalVariation := transitionMutator.mutator.IncomingTransition(ctx, outgoingVariation)
+			if len(ctx.errs) > 0 {
+				return variationMap{}, ctx.errs
+			}
 			variant.set(transitionMutator.name, finalVariation)
 		}
 
@@ -2073,24 +2075,23 @@ func (c *Context) applyTransitions(config any, module *moduleInfo, group *module
 		}
 	}
 
-	return variant
+	return variant, nil
 }
 
 func (c *Context) findVariant(module *moduleInfo, config any,
-	possibleDeps *moduleGroup, requestedVariations []Variation, far bool, reverse bool) (*moduleInfo, variationMap) {
+	possibleDeps *moduleGroup, requestedVariations []Variation, far bool, reverse bool) (*moduleInfo, variationMap, []error) {
 
 	// We can't just append variant.Variant to module.dependencyVariant.variantName and
 	// compare the strings because the result won't be in mutator registration order.
 	// Create a new map instead, and then deep compare the maps.
 	var newVariant variationMap
 	if !far {
-		if !reverse {
-			// For forward dependency, ignore local variants by matching against
-			// dependencyVariant which doesn't have the local variants
-			newVariant = module.variant.dependencyVariations.clone()
-		} else {
-			// For reverse dependency, use all the variants
-			newVariant = module.variant.variations.clone()
+		newVariant = module.variant.variations.clone()
+	} else {
+		for _, mutator := range c.mutatorInfo {
+			if mutator.neverFar {
+				newVariant.set(mutator.name, module.variant.variations.get(mutator.name))
+			}
 		}
 	}
 	for _, v := range requestedVariations {
@@ -2098,7 +2099,11 @@ func (c *Context) findVariant(module *moduleInfo, config any,
 	}
 
 	if !reverse {
-		newVariant = c.applyTransitions(config, module, possibleDeps, newVariant, requestedVariations)
+		var errs []error
+		newVariant, errs = c.applyTransitions(config, module, possibleDeps, newVariant, requestedVariations)
+		if len(errs) > 0 {
+			return nil, variationMap{}, errs
+		}
 	}
 
 	// check returns a bool for whether the requested newVariant matches the given variant from possibleDeps, and a
@@ -2121,8 +2126,8 @@ func (c *Context) findVariant(module *moduleInfo, config any,
 	var foundDep *moduleInfo
 	bestDivergence := math.MaxInt
 	for _, m := range possibleDeps.modules {
-		if match, divergence := check(m.moduleOrAliasVariant().variations); match && divergence < bestDivergence {
-			foundDep = m.moduleOrAliasTarget()
+		if match, divergence := check(m.variant.variations); match && divergence < bestDivergence {
+			foundDep = m
 			bestDivergence = divergence
 			if !far {
 				// non-far dependencies use equality, so only the first match needs to be checked.
@@ -2131,10 +2136,10 @@ func (c *Context) findVariant(module *moduleInfo, config any,
 		}
 	}
 
-	return foundDep, newVariant
+	return foundDep, newVariant, nil
 }
 
-func (c *Context) addVariationDependency(module *moduleInfo, config any, variations []Variation,
+func (c *Context) addVariationDependency(module *moduleInfo, mutator *mutatorInfo, config any, variations []Variation,
 	tag DependencyTag, depName string, far bool) (*moduleInfo, []error) {
 	if _, ok := tag.(BaseDependencyTag); ok {
 		panic("BaseDependencyTag is not allowed to be used directly!")
@@ -2145,7 +2150,10 @@ func (c *Context) addVariationDependency(module *moduleInfo, config any, variati
 		return nil, c.discoveredMissingDependencies(module, depName, variationMap{})
 	}
 
-	foundDep, newVariant := c.findVariant(module, config, possibleDeps, variations, far, false)
+	foundDep, newVariant, errs := c.findVariant(module, config, possibleDeps, variations, far, false)
+	if errs != nil {
+		return nil, errs
+	}
 
 	if foundDep == nil {
 		if c.allowMissingDependencies {
@@ -2176,40 +2184,15 @@ func (c *Context) addVariationDependency(module *moduleInfo, config any, variati
 			Pos: module.pos,
 		}}
 	}
-	module.newDirectDeps = append(module.newDirectDeps, depInfo{foundDep, tag})
-	atomic.AddUint32(&c.depsModified, 1)
-	return foundDep, nil
-}
-
-func (c *Context) addInterVariantDependency(origModule *moduleInfo, tag DependencyTag,
-	from, to Module) *moduleInfo {
-	if _, ok := tag.(BaseDependencyTag); ok {
-		panic("BaseDependencyTag is not allowed to be used directly!")
-	}
-
-	var fromInfo, toInfo *moduleInfo
-	for _, moduleOrAlias := range origModule.splitModules {
-		if m := moduleOrAlias.module(); m != nil {
-			if m.logicModule == from {
-				fromInfo = m
-			}
-			if m.logicModule == to {
-				toInfo = m
-				if fromInfo != nil {
-					panic(fmt.Errorf("%q depends on later version of itself", origModule.Name()))
-				}
-			}
-		}
-	}
 
-	if fromInfo == nil || toInfo == nil {
-		panic(fmt.Errorf("AddInterVariantDependency called for module %q on invalid variant",
-			origModule.Name()))
-	}
-
-	fromInfo.newDirectDeps = append(fromInfo.newDirectDeps, depInfo{toInfo, tag})
-	atomic.AddUint32(&c.depsModified, 1)
-	return toInfo
+	// The mutator will pause until the newly added dependency has finished running the current mutator,
+	// so it is safe to add the new dependency directly to directDeps and forwardDeps where it will be visible
+	// to future calls to VisitDirectDeps.  Set newDirectDeps so that at the end of the mutator the reverseDeps
+	// of the dependencies can be updated to point to this module without running a full c.updateDependencies()
+	module.directDeps = append(module.directDeps, depInfo{foundDep, tag})
+	module.forwardDeps = append(module.forwardDeps, foundDep)
+	module.newDirectDeps = append(module.newDirectDeps, foundDep)
+	return foundDep, nil
 }
 
 // findBlueprintDescendants returns a map linking parent Blueprint files to child Blueprints files
@@ -2257,8 +2240,6 @@ type visitOrderer interface {
 	waitCount(module *moduleInfo) int
 	// returns the list of modules that are waiting for this module
 	propagate(module *moduleInfo) []*moduleInfo
-	// visit modules in order
-	visit(modules []*moduleInfo, visit func(*moduleInfo, chan<- pauseSpec) bool)
 }
 
 type unorderedVisitorImpl struct{}
@@ -2271,14 +2252,6 @@ func (unorderedVisitorImpl) propagate(module *moduleInfo) []*moduleInfo {
 	return nil
 }
 
-func (unorderedVisitorImpl) visit(modules []*moduleInfo, visit func(*moduleInfo, chan<- pauseSpec) bool) {
-	for _, module := range modules {
-		if visit(module, nil) {
-			return
-		}
-	}
-}
-
 type bottomUpVisitorImpl struct{}
 
 func (bottomUpVisitorImpl) waitCount(module *moduleInfo) int {
@@ -2289,14 +2262,6 @@ func (bottomUpVisitorImpl) propagate(module *moduleInfo) []*moduleInfo {
 	return module.reverseDeps
 }
 
-func (bottomUpVisitorImpl) visit(modules []*moduleInfo, visit func(*moduleInfo, chan<- pauseSpec) bool) {
-	for _, module := range modules {
-		if visit(module, nil) {
-			return
-		}
-	}
-}
-
 type topDownVisitorImpl struct{}
 
 func (topDownVisitorImpl) waitCount(module *moduleInfo) int {
@@ -2338,7 +2303,7 @@ const parallelVisitLimit = 1000
 // to wait for another dependency to be visited.  If a visit function returns true to cancel
 // while another visitor is paused, the paused visitor will never be resumed and its goroutine
 // will stay paused forever.
-func parallelVisit(modules []*moduleInfo, order visitOrderer, limit int,
+func parallelVisit(moduleIter iter.Seq[*moduleInfo], order visitOrderer, limit int,
 	visit func(module *moduleInfo, pause chan<- pauseSpec) bool) []error {
 
 	doneCh := make(chan *moduleInfo)
@@ -2354,7 +2319,7 @@ func parallelVisit(modules []*moduleInfo, order visitOrderer, limit int,
 
 	pauseMap := make(map[*moduleInfo][]pauseSpec)
 
-	for _, module := range modules {
+	for module := range moduleIter {
 		module.waitingCount = order.waitCount(module)
 	}
 
@@ -2401,10 +2366,11 @@ func parallelVisit(modules []*moduleInfo, order visitOrderer, limit int,
 		}
 	}
 
-	toVisit := len(modules)
+	toVisit := 0
 
 	// Start or backlog any modules that are not waiting for any other modules.
-	for _, module := range modules {
+	for module := range moduleIter {
+		toVisit++
 		if module.waitingCount == 0 {
 			startOrBacklog(module)
 		}
@@ -2517,7 +2483,7 @@ func parallelVisit(modules []*moduleInfo, order visitOrderer, limit int,
 			}
 
 			// Iterate over the modules list instead of pauseMap to provide deterministic ordering.
-			for _, module := range modules {
+			for module := range moduleIter {
 				for _, pauseSpec := range pauseMap[module] {
 					cycle := check(pauseSpec.paused, pauseSpec.until)
 					if len(cycle) > 0 {
@@ -2574,10 +2540,8 @@ func cycleError(cycle []*moduleInfo) (errs []error) {
 // as well as after any mutator pass has called addDependency
 func (c *Context) updateDependencies() (errs []error) {
 	c.cachedDepsModified = true
-	visited := make(map[*moduleInfo]bool)  // modules that were already checked
-	checking := make(map[*moduleInfo]bool) // modules actively being checked
-
-	sorted := make([]*moduleInfo, 0, len(c.moduleInfo))
+	visited := make(map[*moduleInfo]bool, len(c.moduleInfo)) // modules that were already checked
+	checking := make(map[*moduleInfo]bool)                   // modules actively being checked
 
 	var check func(group *moduleInfo) []*moduleInfo
 
@@ -2591,23 +2555,11 @@ func (c *Context) updateDependencies() (errs []error) {
 		module.forwardDeps = module.forwardDeps[:0]
 
 		// Add an implicit dependency ordering on all earlier modules in the same module group
-		for _, dep := range module.group.modules {
-			if dep == module {
-				break
-			}
-			if depModule := dep.module(); depModule != nil {
-				module.forwardDeps = append(module.forwardDeps, depModule)
-			}
-		}
+		selfIndex := slices.Index(module.group.modules, module)
+		module.forwardDeps = slices.Grow(module.forwardDeps, selfIndex+len(module.directDeps))
+		module.forwardDeps = append(module.forwardDeps, module.group.modules[:selfIndex]...)
 
-	outer:
 		for _, dep := range module.directDeps {
-			// use a loop to check for duplicates, average number of directDeps measured to be 9.5.
-			for _, exists := range module.forwardDeps {
-				if dep.module == exists {
-					continue outer
-				}
-			}
 			module.forwardDeps = append(module.forwardDeps, dep.module)
 		}
 
@@ -2640,8 +2592,6 @@ func (c *Context) updateDependencies() (errs []error) {
 			dep.reverseDeps = append(dep.reverseDeps, module)
 		}
 
-		sorted = append(sorted, module)
-
 		return nil
 	}
 
@@ -2657,8 +2607,6 @@ func (c *Context) updateDependencies() (errs []error) {
 		}
 	}
 
-	c.modulesSorted = sorted
-
 	return
 }
 
@@ -2786,7 +2734,7 @@ func getNinjaStrings(nStrs []*ninjaString, nameTracker *nameTracker) []string {
 
 func (c *Context) GetWeightedOutputsFromPredicate(predicate func(*JsonModule) (bool, int)) map[string]int {
 	outputToWeight := make(map[string]int)
-	for _, m := range c.modulesSorted {
+	for m := range c.iterateAllVariants() {
 		jmWithActions := jsonModuleWithActionsFromModuleInfo(m, c.nameTracker)
 		if ok, weight := predicate(jmWithActions); ok {
 			for _, a := range jmWithActions.Module["Actions"].([]JSONAction) {
@@ -2808,7 +2756,7 @@ func (c *Context) GetWeightedOutputsFromPredicate(predicate func(*JsonModule) (b
 func (c *Context) PrintJSONGraphAndActions(wGraph io.Writer, wActions io.Writer) {
 	modulesToGraph := make([]*JsonModule, 0)
 	modulesToActions := make([]*JsonModule, 0)
-	for _, m := range c.modulesSorted {
+	for m := range c.iterateAllVariants() {
 		jm := jsonModuleFromModuleInfo(m)
 		jmWithActions := jsonModuleWithActionsFromModuleInfo(m, c.nameTracker)
 		for _, d := range m.directDeps {
@@ -2948,19 +2896,25 @@ func (c *Context) PrepareBuildActions(config interface{}) (deps []string, errs [
 	return deps, nil
 }
 
-func (c *Context) runMutators(ctx context.Context, config interface{}) (deps []string, errs []error) {
+func (c *Context) runMutators(ctx context.Context, config interface{}, mutatorGroups [][]*mutatorInfo) (deps []string, errs []error) {
+	c.finishedMutators = make([]bool, len(c.mutatorInfo))
+
 	pprof.Do(ctx, pprof.Labels("blueprint", "runMutators"), func(ctx context.Context) {
-		for _, mutator := range c.mutatorInfo {
-			pprof.Do(ctx, pprof.Labels("mutator", mutator.name), func(context.Context) {
-				c.BeginEvent(mutator.name)
-				defer c.EndEvent(mutator.name)
+		for _, mutatorGroup := range mutatorGroups {
+			name := mutatorGroup[0].name
+			if len(mutatorGroup) > 1 {
+				name += "_plus_" + strconv.Itoa(len(mutatorGroup)-1)
+			}
+			pprof.Do(ctx, pprof.Labels("mutator", name), func(context.Context) {
+				c.BeginEvent(name)
+				defer c.EndEvent(name)
 				var newDeps []string
-				if mutator.topDownMutator != nil {
-					newDeps, errs = c.runMutator(config, mutator, topDownMutator)
-				} else if mutator.bottomUpMutator != nil {
-					newDeps, errs = c.runMutator(config, mutator, bottomUpMutator)
+				if mutatorGroup[0].topDownMutator != nil {
+					newDeps, errs = c.runMutator(config, mutatorGroup, topDownMutator)
+				} else if mutatorGroup[0].bottomUpMutator != nil {
+					newDeps, errs = c.runMutator(config, mutatorGroup, bottomUpMutator)
 				} else {
-					panic("no mutator set on " + mutator.name)
+					panic("no mutator set on " + mutatorGroup[0].name)
 				}
 				if len(errs) > 0 {
 					return
@@ -2981,15 +2935,20 @@ func (c *Context) runMutators(ctx context.Context, config interface{}) (deps []s
 }
 
 type mutatorDirection interface {
-	run(mutator *mutatorInfo, ctx *mutatorContext)
+	run(mutator []*mutatorInfo, ctx *mutatorContext)
 	orderer() visitOrderer
 	fmt.Stringer
 }
 
 type bottomUpMutatorImpl struct{}
 
-func (bottomUpMutatorImpl) run(mutator *mutatorInfo, ctx *mutatorContext) {
-	mutator.bottomUpMutator(ctx)
+func (bottomUpMutatorImpl) run(mutatorGroup []*mutatorInfo, ctx *mutatorContext) {
+	for _, mutator := range mutatorGroup {
+		ctx.mutator = mutator
+		ctx.module.startedMutator = mutator.index
+		mutator.bottomUpMutator(ctx)
+		ctx.module.finishedMutator = mutator.index
+	}
 }
 
 func (bottomUpMutatorImpl) orderer() visitOrderer {
@@ -3002,8 +2961,11 @@ func (bottomUpMutatorImpl) String() string {
 
 type topDownMutatorImpl struct{}
 
-func (topDownMutatorImpl) run(mutator *mutatorInfo, ctx *mutatorContext) {
-	mutator.topDownMutator(ctx)
+func (topDownMutatorImpl) run(mutatorGroup []*mutatorInfo, ctx *mutatorContext) {
+	if len(mutatorGroup) > 1 {
+		panic(fmt.Errorf("top down mutator group %s must only have 1 mutator, found %d", mutatorGroup[0].name, len(mutatorGroup)))
+	}
+	mutatorGroup[0].topDownMutator(ctx)
 }
 
 func (topDownMutatorImpl) orderer() visitOrderer {
@@ -3024,13 +2986,10 @@ type reverseDep struct {
 	dep    depInfo
 }
 
-func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
+func (c *Context) runMutator(config interface{}, mutatorGroup []*mutatorInfo,
 	direction mutatorDirection) (deps []string, errs []error) {
 
-	newModuleInfo := make(map[Module]*moduleInfo)
-	for k, v := range c.moduleInfo {
-		newModuleInfo[k] = v
-	}
+	newModuleInfo := maps.Clone(c.moduleInfo)
 
 	type globalStateChange struct {
 		reverse    []reverseDep
@@ -3041,7 +3000,7 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 	}
 
 	type newVariationPair struct {
-		newVariations   modulesOrAliases
+		newVariations   moduleList
 		origLogicModule Module
 	}
 
@@ -3055,7 +3014,7 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 	newVariationsCh := make(chan newVariationPair)
 	done := make(chan bool)
 
-	c.depsModified = 0
+	c.needsUpdateDependencies = 0
 
 	visit := func(module *moduleInfo, pause chan<- pauseSpec) bool {
 		if module.splitModules != nil {
@@ -3068,18 +3027,18 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 				config:  config,
 				module:  module,
 			},
-			mutator: mutator,
+			mutator: mutatorGroup[0],
 			pauseCh: pause,
 		}
 
 		origLogicModule := module.logicModule
 
-		module.startedMutator = mutator
+		module.startedMutator = mutatorGroup[0].index
 
 		func() {
 			defer func() {
 				if r := recover(); r != nil {
-					in := fmt.Sprintf("%s %q for %s", direction, mutator.name, module)
+					in := fmt.Sprintf("%s %q for %s", direction, mutatorGroup[0].name, module)
 					if err, ok := r.(panicError); ok {
 						err.addIn(in)
 						mctx.error(err)
@@ -3088,10 +3047,10 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 					}
 				}
 			}()
-			direction.run(mutator, mctx)
+			direction.run(mutatorGroup, mctx)
 		}()
 
-		module.finishedMutator = mutator
+		module.finishedMutator = mutatorGroup[len(mutatorGroup)-1].index
 
 		if len(mctx.errs) > 0 {
 			errsCh <- mctx.errs
@@ -3133,13 +3092,11 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 				newModules = append(newModules, globalStateChange.newModules...)
 				deps = append(deps, globalStateChange.deps...)
 			case newVariations := <-newVariationsCh:
-				if newVariations.origLogicModule != newVariations.newVariations[0].module().logicModule {
+				if newVariations.origLogicModule != newVariations.newVariations[0].logicModule {
 					obsoleteLogicModules = append(obsoleteLogicModules, newVariations.origLogicModule)
 				}
-				for _, moduleOrAlias := range newVariations.newVariations {
-					if m := moduleOrAlias.module(); m != nil {
-						newModuleInfo[m.logicModule] = m
-					}
+				for _, module := range newVariations.newVariations {
+					newModuleInfo[module.logicModule] = module
 				}
 				createdVariations = true
 			case <-done:
@@ -3148,20 +3105,15 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 		}
 	}()
 
-	c.startedMutator = mutator
-
-	var visitErrs []error
-	if mutator.parallel {
-		visitErrs = parallelVisit(c.modulesSorted, direction.orderer(), parallelVisitLimit, visit)
-	} else {
-		direction.orderer().visit(c.modulesSorted, visit)
-	}
+	visitErrs := parallelVisit(c.iterateAllVariants(), direction.orderer(), parallelVisitLimit, visit)
 
 	if len(visitErrs) > 0 {
 		return nil, visitErrs
 	}
 
-	c.finishedMutators[mutator] = true
+	for _, mutator := range mutatorGroup {
+		c.finishedMutators[mutator.index] = true
+	}
 
 	done <- true
 
@@ -3175,7 +3127,7 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 
 	c.moduleInfo = newModuleInfo
 
-	isTransitionMutator := mutator.transitionMutator != nil
+	isTransitionMutator := mutatorGroup[0].transitionMutator != nil
 
 	var transitionMutatorInputVariants map[*moduleGroup][]*moduleInfo
 	if isTransitionMutator {
@@ -3184,11 +3136,7 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 
 	for _, group := range c.moduleGroups {
 		for i := 0; i < len(group.modules); i++ {
-			module := group.modules[i].module()
-			if module == nil {
-				// Existing alias, skip it
-				continue
-			}
+			module := group.modules[i]
 
 			// Update module group to contain newly split variants
 			if module.splitModules != nil {
@@ -3211,64 +3159,30 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 				module.createdBy = module.createdBy.splitModules.firstModule()
 			}
 
-			// Add in any new direct dependencies that were added by the mutator
-			module.directDeps = append(module.directDeps, module.newDirectDeps...)
-			module.newDirectDeps = nil
-		}
-
-		findAliasTarget := func(oldVariant variant) *moduleInfo {
-			for _, moduleOrAlias := range group.modules {
-				module := moduleOrAlias.moduleOrAliasTarget()
-				if module.splitModules != nil {
-					// Ignore any old aliases that are pointing to modules that were obsoleted.
-					continue
-				}
-				if alias := moduleOrAlias.alias(); alias != nil {
-					if alias.variant.variations.equal(oldVariant.variations) {
-						return alias.target
-					}
-				}
-				if module.variant.variations.equal(oldVariant.variations) {
-					return module
-				}
-			}
-			return nil
-		}
-
-		// Forward or delete any dangling aliases.
-		// Use a manual loop instead of range because len(group.modules) can
-		// change inside the loop
-		for i := 0; i < len(group.modules); i++ {
-			if alias := group.modules[i].alias(); alias != nil {
-				if alias.target.obsoletedByNewVariants {
-					newTarget := findAliasTarget(alias.target.variant)
-					if newTarget != nil {
-						alias.target = newTarget
-					} else {
-						// The alias was left dangling, remove it.
-						group.modules = append(group.modules[:i], group.modules[i+1:]...)
-						i--
-					}
-				}
+			// Add any new forward dependencies to the reverse dependencies of the dependency to avoid
+			// having to call a full c.updateDependencies().
+			for _, m := range module.newDirectDeps {
+				m.reverseDeps = append(m.reverseDeps, module)
 			}
+			module.newDirectDeps = nil
 		}
 	}
 
 	if isTransitionMutator {
-		mutator.transitionMutator.inputVariants = transitionMutatorInputVariants
-		mutator.transitionMutator.variantCreatingMutatorIndex = len(c.variantCreatingMutatorOrder)
-		c.transitionMutators = append(c.transitionMutators, mutator.transitionMutator)
+		mutatorGroup[0].transitionMutator.inputVariants = transitionMutatorInputVariants
+		mutatorGroup[0].transitionMutator.variantCreatingMutatorIndex = len(c.variantCreatingMutatorOrder)
+		c.transitionMutators = append(c.transitionMutators, mutatorGroup[0].transitionMutator)
 	}
 
 	if createdVariations {
-		c.variantCreatingMutatorOrder = append(c.variantCreatingMutatorOrder, mutator.name)
+		c.variantCreatingMutatorOrder = append(c.variantCreatingMutatorOrder, mutatorGroup[0].name)
 	}
 
 	// Add in any new reverse dependencies that were added by the mutator
 	for module, deps := range reverseDeps {
 		sort.Sort(depSorter(deps))
 		module.directDeps = append(module.directDeps, deps...)
-		c.depsModified++
+		c.needsUpdateDependencies++
 	}
 
 	for _, module := range newModules {
@@ -3276,7 +3190,7 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 		if len(errs) > 0 {
 			return nil, errs
 		}
-		atomic.AddUint32(&c.depsModified, 1)
+		c.needsUpdateDependencies++
 	}
 
 	errs = c.handleRenames(rename)
@@ -3289,7 +3203,7 @@ func (c *Context) runMutator(config interface{}, mutator *mutatorInfo,
 		return nil, errs
 	}
 
-	if c.depsModified > 0 {
+	if c.needsUpdateDependencies > 0 {
 		errs = c.updateDependencies()
 		if len(errs) > 0 {
 			return nil, errs
@@ -3318,7 +3232,7 @@ func (c *Context) cloneModules() {
 	ch := make(chan update)
 	doneCh := make(chan bool)
 	go func() {
-		errs := parallelVisit(c.modulesSorted, unorderedVisitorImpl{}, parallelVisitLimit,
+		errs := parallelVisit(c.iterateAllVariants(), unorderedVisitorImpl{}, parallelVisitLimit,
 			func(m *moduleInfo, pause chan<- pauseSpec) bool {
 				origLogicModule := m.logicModule
 				m.logicModule, m.properties = c.cloneLogicModule(m)
@@ -3345,15 +3259,15 @@ func (c *Context) cloneModules() {
 
 // Removes modules[i] from the list and inserts newModules... where it was located, returning
 // the new slice and the index of the last inserted element
-func spliceModules(modules modulesOrAliases, i int, newModules modulesOrAliases) (modulesOrAliases, int) {
+func spliceModules(modules moduleList, i int, newModules moduleList) (moduleList, int) {
 	spliceSize := len(newModules)
 	newLen := len(modules) + spliceSize - 1
-	var dest modulesOrAliases
+	var dest moduleList
 	if cap(modules) >= len(modules)-1+len(newModules) {
 		// We can fit the splice in the existing capacity, do everything in place
 		dest = modules[:newLen]
 	} else {
-		dest = make(modulesOrAliases, newLen)
+		dest = make(moduleList, newLen)
 		copy(dest, modules[:i])
 	}
 
@@ -3393,7 +3307,7 @@ func (c *Context) generateModuleBuildActions(config interface{},
 		}
 	}()
 
-	visitErrs := parallelVisit(c.modulesSorted, bottomUpVisitor, parallelVisitLimit,
+	visitErrs := parallelVisit(c.iterateAllVariants(), bottomUpVisitor, parallelVisitLimit,
 		func(module *moduleInfo, pause chan<- pauseSpec) bool {
 			uniqueName := c.nameInterface.UniqueName(newNamespaceContext(module), module.group.name)
 			sanitizedName := toNinjaName(uniqueName)
@@ -3706,11 +3620,7 @@ func (c *Context) moduleVariantsThatDependOn(name string, dep *moduleInfo) []*mo
 		return nil
 	}
 
-	for _, module := range group.modules {
-		m := module.module()
-		if m == nil {
-			continue
-		}
+	for _, m := range group.modules {
 		for _, moduleDep := range m.directDeps {
 			if moduleDep.module == dep {
 				variants = append(variants, m)
@@ -3754,7 +3664,7 @@ func (c *Context) handleReplacements(replacements []replace) []error {
 	}
 
 	if changedDeps {
-		atomic.AddUint32(&c.depsModified, 1)
+		c.needsUpdateDependencies++
 	}
 	return errs
 }
@@ -3815,10 +3725,8 @@ func (c *Context) visitAllModules(visit func(Module)) {
 	}()
 
 	for _, moduleGroup := range c.sortedModuleGroups() {
-		for _, moduleOrAlias := range moduleGroup.modules {
-			if module = moduleOrAlias.module(); module != nil {
-				visit(module.logicModule)
-			}
+		for _, module := range moduleGroup.modules {
+			visit(module.logicModule)
 		}
 	}
 }
@@ -3836,11 +3744,9 @@ func (c *Context) visitAllModulesIf(pred func(Module) bool,
 	}()
 
 	for _, moduleGroup := range c.sortedModuleGroups() {
-		for _, moduleOrAlias := range moduleGroup.modules {
-			if module = moduleOrAlias.module(); module != nil {
-				if pred(module.logicModule) {
-					visit(module.logicModule)
-				}
+		for _, module := range moduleGroup.modules {
+			if pred(module.logicModule) {
+				visit(module.logicModule)
 			}
 		}
 	}
@@ -3858,10 +3764,8 @@ func (c *Context) visitAllModuleVariants(module *moduleInfo,
 		}
 	}()
 
-	for _, moduleOrAlias := range module.group.modules {
-		if variant = moduleOrAlias.module(); variant != nil {
-			visit(variant.logicModule)
-		}
+	for _, module := range module.group.modules {
+		visit(module.logicModule)
 	}
 }
 
@@ -3876,10 +3780,8 @@ func (c *Context) visitAllModuleInfos(visit func(*moduleInfo)) {
 	}()
 
 	for _, moduleGroup := range c.sortedModuleGroups() {
-		for _, moduleOrAlias := range moduleGroup.modules {
-			if module = moduleOrAlias.module(); module != nil {
-				visit(module)
-			}
+		for _, module := range moduleGroup.modules {
+			visit(module)
 		}
 	}
 }
@@ -4068,11 +3970,7 @@ func (c *Context) ModuleTypePropertyStructs() map[string][]interface{} {
 }
 
 func (c *Context) ModuleTypeFactories() map[string]ModuleFactory {
-	ret := make(map[string]ModuleFactory)
-	for k, v := range c.moduleFactories {
-		ret[k] = v
-	}
-	return ret
+	return maps.Clone(c.moduleFactories)
 }
 
 func (c *Context) ModuleName(logicModule Module) string {
@@ -4108,10 +4006,8 @@ func (c *Context) BlueprintFile(logicModule Module) string {
 	return module.relBlueprintsFile
 }
 
-func (c *Context) ModuleErrorf(logicModule Module, format string,
+func (c *Context) moduleErrorf(module *moduleInfo, format string,
 	args ...interface{}) error {
-
-	module := c.moduleInfo[logicModule]
 	if module == nil {
 		// This can happen if ModuleErrorf is called from a load hook
 		return &BlueprintError{
@@ -4128,6 +4024,11 @@ func (c *Context) ModuleErrorf(logicModule Module, format string,
 	}
 }
 
+func (c *Context) ModuleErrorf(logicModule Module, format string,
+	args ...interface{}) error {
+	return c.moduleErrorf(c.moduleInfo[logicModule], format, args...)
+}
+
 func (c *Context) PropertyErrorf(logicModule Module, property string, format string,
 	args ...interface{}) error {
 
@@ -4252,8 +4153,8 @@ func (c *Context) PrimaryModule(module Module) Module {
 	return c.moduleInfo[module].group.modules.firstModule().logicModule
 }
 
-func (c *Context) FinalModule(module Module) Module {
-	return c.moduleInfo[module].group.modules.lastModule().logicModule
+func (c *Context) IsFinalModule(module Module) bool {
+	return c.moduleInfo[module].group.modules.lastModule().logicModule == module
 }
 
 func (c *Context) VisitAllModuleVariants(module Module,
@@ -4292,7 +4193,7 @@ func (c *Context) VerifyProvidersWereUnchanged() []error {
 	errorCh := make(chan []error)
 	var wg sync.WaitGroup
 	go func() {
-		for _, m := range c.modulesSorted {
+		for m := range c.iterateAllVariants() {
 			toProcess <- m
 		}
 		close(toProcess)
@@ -4678,6 +4579,7 @@ func (c *Context) writeAllModuleActions(nw *ninjaWriter, shardNinja bool, ninjaF
 		modules = append(modules, module)
 	}
 	sort.Sort(moduleSorter{modules, c.nameInterface})
+	sort.Sort(moduleSorter{incrementalModules, c.nameInterface})
 
 	phonys := c.deduplicateOrderOnlyDeps(append(modules, incrementalModules...))
 	if err := orderOnlyForIncremental(c, incrementalModules, phonys); err != nil {
@@ -4739,7 +4641,9 @@ func (c *Context) writeAllModuleActions(nw *ninjaWriter, shardNinja bool, ninjaF
 		}
 
 		if c.GetIncrementalEnabled() {
-			file := fmt.Sprintf("%s.incremental", ninjaFileName)
+			suffix := ".ninja"
+			base := strings.TrimSuffix(ninjaFileName, suffix)
+			file := fmt.Sprintf("%s.incremental%s", base, suffix)
 			wg.Add(1)
 			go func() {
 				defer wg.Done()
@@ -4773,11 +4677,10 @@ func orderOnlyForIncremental(c *Context, modules []*moduleInfo, phonys *localBui
 	for _, mod := range modules {
 		// find the order only strings of the incremental module, it can come from
 		// the cache or from buildDefs depending on if the module was skipped or not.
-		var orderOnlyStrings *[]string
+		var orderOnlyStrings []string
 		if mod.incrementalRestored {
 			orderOnlyStrings = mod.orderOnlyStrings
 		} else {
-			orderOnlyStrings = new([]string)
 			for _, b := range mod.actionDefs.buildDefs {
 				// We do similar check when creating phonys in deduplicateOrderOnlyDeps as well
 				if len(b.OrderOnly) > 0 {
@@ -4785,13 +4688,13 @@ func orderOnlyForIncremental(c *Context, modules []*moduleInfo, phonys *localBui
 				}
 				for _, str := range b.OrderOnlyStrings {
 					if strings.HasPrefix(str, "dedup-") {
-						*orderOnlyStrings = append(*orderOnlyStrings, str)
+						orderOnlyStrings = append(orderOnlyStrings, str)
 					}
 				}
 			}
 		}
 
-		if orderOnlyStrings == nil || len(*orderOnlyStrings) == 0 {
+		if len(orderOnlyStrings) == 0 {
 			continue
 		}
 
@@ -4813,7 +4716,7 @@ func orderOnlyForIncremental(c *Context, modules []*moduleInfo, phonys *localBui
 		// in the phony list anymore, so we need to add it here in order to avoid
 		// writing the ninja statements for the skipped module, otherwise it would
 		// reference a dedup-* phony that no longer exists.
-		for _, dep := range *orderOnlyStrings {
+		for _, dep := range orderOnlyStrings {
 			// nothing changed to this phony, the cached value is still valid
 			if _, ok := c.orderOnlyStringsToCache[dep]; ok {
 				continue
@@ -5065,7 +4968,7 @@ func (c *Context) deduplicateOrderOnlyDeps(modules []*moduleInfo) *localBuildAct
 	defer c.EndEvent("deduplicate_order_only_deps")
 
 	candidates := sync.Map{} //used as map[key]*candidate
-	parallelVisit(modules, unorderedVisitorImpl{}, parallelVisitLimit,
+	parallelVisit(slices.Values(modules), unorderedVisitorImpl{}, parallelVisitLimit,
 		func(m *moduleInfo, pause chan<- pauseSpec) bool {
 			incremental := m.buildActionCacheKey != nil
 			for _, b := range m.actionDefs.buildDefs {
@@ -5158,15 +5061,15 @@ func (c *Context) writeLocalBuildActions(nw *ninjaWriter,
 	return nil
 }
 
-func beforeInModuleList(a, b *moduleInfo, list modulesOrAliases) bool {
+func beforeInModuleList(a, b *moduleInfo, list moduleList) bool {
 	found := false
 	if a == b {
 		return false
 	}
 	for _, l := range list {
-		if l.module() == a {
+		if l == a {
 			found = true
-		} else if l.module() == b {
+		} else if l == b {
 			return found
 		}
 	}
diff --git a/context_test.go b/context_test.go
index bccabc5..1a5f8c0 100644
--- a/context_test.go
+++ b/context_test.go
@@ -21,6 +21,7 @@ import (
 	"hash/fnv"
 	"os"
 	"reflect"
+	"slices"
 	"strconv"
 	"strings"
 	"sync"
@@ -428,7 +429,7 @@ func TestCreateModule(t *testing.T) {
 		`),
 	})
 
-	ctx.RegisterTopDownMutator("create", createTestMutator)
+	ctx.RegisterBottomUpMutator("create", createTestMutator).UsesCreateModule()
 	ctx.RegisterBottomUpMutator("deps", depsMutator)
 
 	ctx.RegisterModuleType("foo_module", newFooModule)
@@ -474,7 +475,7 @@ func TestCreateModule(t *testing.T) {
 	checkDeps(d, "")
 }
 
-func createTestMutator(ctx TopDownMutatorContext) {
+func createTestMutator(ctx BottomUpMutatorContext) {
 	type props struct {
 		Name string
 		Deps []string
@@ -631,12 +632,6 @@ func Test_findVariant(t *testing.T) {
 		variant: variant{
 			name: "normal_local",
 			variations: variationMap{
-				map[string]string{
-					"normal": "normal",
-					"local":  "local",
-				},
-			},
-			dependencyVariations: variationMap{
 				map[string]string{
 					"normal": "normal",
 				},
@@ -649,38 +644,14 @@ func Test_findVariant(t *testing.T) {
 		target  int
 	}
 
-	makeDependencyGroup := func(in ...interface{}) *moduleGroup {
+	makeDependencyGroup := func(in ...*moduleInfo) *moduleGroup {
 		group := &moduleGroup{
 			name: "dep",
 		}
-		for _, x := range in {
-			switch m := x.(type) {
-			case *moduleInfo:
-				m.group = group
-				group.modules = append(group.modules, m)
-			case alias:
-				// aliases may need to target modules that haven't been processed
-				// yet, put an empty alias in for now.
-				group.modules = append(group.modules, nil)
-			default:
-				t.Fatalf("unexpected type %T", x)
-			}
-		}
-
-		for i, x := range in {
-			switch m := x.(type) {
-			case *moduleInfo:
-				// already added in the first pass
-			case alias:
-				group.modules[i] = &moduleAlias{
-					variant: m.variant,
-					target:  group.modules[m.target].moduleOrAliasTarget(),
-				}
-			default:
-				t.Fatalf("unexpected type %T", x)
-			}
+		for _, m := range in {
+			m.group = group
+			group.modules = append(group.modules, m)
 		}
-
 		return group
 	}
 
@@ -712,38 +683,6 @@ func Test_findVariant(t *testing.T) {
 			reverse:    false,
 			want:       "normal",
 		},
-		{
-			name: "AddVariationDependencies(nil) to alias",
-			// A dependency with an alias that matches the non-local variations of the module
-			possibleDeps: makeDependencyGroup(
-				alias{
-					variant: variant{
-						name: "normal",
-						variations: variationMap{
-							map[string]string{
-								"normal": "normal",
-							},
-						},
-					},
-					target: 1,
-				},
-				&moduleInfo{
-					variant: variant{
-						name: "normal_a",
-						variations: variationMap{
-							map[string]string{
-								"normal": "normal",
-								"a":      "a",
-							},
-						},
-					},
-				},
-			),
-			variations: nil,
-			far:        false,
-			reverse:    false,
-			want:       "normal_a",
-		},
 		{
 			name: "AddVariationDependencies(a)",
 			// A dependency with local variations
@@ -791,86 +730,14 @@ func Test_findVariant(t *testing.T) {
 			reverse:    false,
 			want:       "far",
 		},
-		{
-			name: "AddFarVariationDependencies(far) to alias",
-			// A dependency with far variations and aliases
-			possibleDeps: makeDependencyGroup(
-				alias{
-					variant: variant{
-						name: "far",
-						variations: variationMap{
-							map[string]string{
-								"far": "far",
-							},
-						},
-					},
-					target: 2,
-				},
-				&moduleInfo{
-					variant: variant{
-						name: "far_a",
-						variations: variationMap{
-							map[string]string{
-								"far": "far",
-								"a":   "a",
-							},
-						},
-					},
-				},
-				&moduleInfo{
-					variant: variant{
-						name: "far_b",
-						variations: variationMap{
-							map[string]string{
-								"far": "far",
-								"b":   "b",
-							},
-						},
-					},
-				},
-			),
-			variations: []Variation{{"far", "far"}},
-			far:        true,
-			reverse:    false,
-			want:       "far_b",
-		},
-		{
-			name: "AddFarVariationDependencies(far, b) to missing",
-			// A dependency with far variations and aliases
-			possibleDeps: makeDependencyGroup(
-				alias{
-					variant: variant{
-						name: "far",
-						variations: variationMap{
-							map[string]string{
-								"far": "far",
-							},
-						},
-					},
-					target: 1,
-				},
-				&moduleInfo{
-					variant: variant{
-						name: "far_a",
-						variations: variationMap{
-							map[string]string{
-								"far": "far",
-								"a":   "a",
-							},
-						},
-					},
-				},
-			),
-			variations: []Variation{{"far", "far"}, {"a", "b"}},
-			far:        true,
-			reverse:    false,
-			want:       "nil",
-		},
 	}
 	for _, tt := range tests {
 		t.Run(tt.name, func(t *testing.T) {
 			ctx := NewContext()
-			got, _ := ctx.findVariant(module, nil, tt.possibleDeps, tt.variations, tt.far, tt.reverse)
+			got, _, errs := ctx.findVariant(module, nil, tt.possibleDeps, tt.variations, tt.far, tt.reverse)
+			if errs != nil {
+				t.Fatal(errs)
+			}
 			if g, w := got == nil, tt.want == "nil"; g != w {
 				t.Fatalf("findVariant() got = %v, want %v", got, tt.want)
 			}
@@ -896,7 +763,7 @@ func Test_parallelVisit(t *testing.T) {
 				name: name,
 			},
 		}
-		m.group.modules = modulesOrAliases{m}
+		m.group.modules = moduleList{m}
 		return m
 	}
 	moduleA := create("A")
@@ -913,7 +780,7 @@ func Test_parallelVisit(t *testing.T) {
 	addDep(moduleB, moduleC)
 
 	t.Run("no modules", func(t *testing.T) {
-		errs := parallelVisit(nil, bottomUpVisitorImpl{}, 1,
+		errs := parallelVisit(slices.Values([]*moduleInfo(nil)), bottomUpVisitorImpl{}, 1,
 			func(module *moduleInfo, pause chan<- pauseSpec) bool {
 				panic("unexpected call to visitor")
 			})
@@ -923,7 +790,7 @@ func Test_parallelVisit(t *testing.T) {
 	})
 	t.Run("bottom up", func(t *testing.T) {
 		order := ""
-		errs := parallelVisit([]*moduleInfo{moduleA, moduleB, moduleC}, bottomUpVisitorImpl{}, 1,
+		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC}), bottomUpVisitorImpl{}, 1,
 			func(module *moduleInfo, pause chan<- pauseSpec) bool {
 				order += module.group.name
 				return false
@@ -937,7 +804,7 @@ func Test_parallelVisit(t *testing.T) {
 	})
 	t.Run("pause", func(t *testing.T) {
 		order := ""
-		errs := parallelVisit([]*moduleInfo{moduleA, moduleB, moduleC, moduleD}, bottomUpVisitorImpl{}, 1,
+		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC, moduleD}), bottomUpVisitorImpl{}, 1,
 			func(module *moduleInfo, pause chan<- pauseSpec) bool {
 				if module == moduleC {
 					// Pause module C on module D
@@ -957,7 +824,7 @@ func Test_parallelVisit(t *testing.T) {
 	})
 	t.Run("cancel", func(t *testing.T) {
 		order := ""
-		errs := parallelVisit([]*moduleInfo{moduleA, moduleB, moduleC}, bottomUpVisitorImpl{}, 1,
+		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC}), bottomUpVisitorImpl{}, 1,
 			func(module *moduleInfo, pause chan<- pauseSpec) bool {
 				order += module.group.name
 				// Cancel in module B
@@ -972,7 +839,7 @@ func Test_parallelVisit(t *testing.T) {
 	})
 	t.Run("pause and cancel", func(t *testing.T) {
 		order := ""
-		errs := parallelVisit([]*moduleInfo{moduleA, moduleB, moduleC, moduleD}, bottomUpVisitorImpl{}, 1,
+		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC, moduleD}), bottomUpVisitorImpl{}, 1,
 			func(module *moduleInfo, pause chan<- pauseSpec) bool {
 				if module == moduleC {
 					// Pause module C on module D
@@ -993,7 +860,7 @@ func Test_parallelVisit(t *testing.T) {
 	})
 	t.Run("parallel", func(t *testing.T) {
 		order := ""
-		errs := parallelVisit([]*moduleInfo{moduleA, moduleB, moduleC}, bottomUpVisitorImpl{}, 3,
+		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC}), bottomUpVisitorImpl{}, 3,
 			func(module *moduleInfo, pause chan<- pauseSpec) bool {
 				order += module.group.name
 				return false
@@ -1007,7 +874,7 @@ func Test_parallelVisit(t *testing.T) {
 	})
 	t.Run("pause existing", func(t *testing.T) {
 		order := ""
-		errs := parallelVisit([]*moduleInfo{moduleA, moduleB, moduleC}, bottomUpVisitorImpl{}, 3,
+		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC}), bottomUpVisitorImpl{}, 3,
 			func(module *moduleInfo, pause chan<- pauseSpec) bool {
 				if module == moduleA {
 					// Pause module A on module B (an existing dependency)
@@ -1026,7 +893,7 @@ func Test_parallelVisit(t *testing.T) {
 		}
 	})
 	t.Run("cycle", func(t *testing.T) {
-		errs := parallelVisit([]*moduleInfo{moduleA, moduleB, moduleC}, bottomUpVisitorImpl{}, 3,
+		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC}), bottomUpVisitorImpl{}, 3,
 			func(module *moduleInfo, pause chan<- pauseSpec) bool {
 				if module == moduleC {
 					// Pause module C on module A (a dependency cycle)
@@ -1056,7 +923,7 @@ func Test_parallelVisit(t *testing.T) {
 		}
 	})
 	t.Run("pause cycle", func(t *testing.T) {
-		errs := parallelVisit([]*moduleInfo{moduleA, moduleB, moduleC, moduleD}, bottomUpVisitorImpl{}, 3,
+		errs := parallelVisit(slices.Values([]*moduleInfo{moduleA, moduleB, moduleC, moduleD}), bottomUpVisitorImpl{}, 3,
 			func(module *moduleInfo, pause chan<- pauseSpec) bool {
 				if module == moduleC {
 					// Pause module C on module D
@@ -1100,7 +967,7 @@ func Test_parallelVisit(t *testing.T) {
 			moduleD: moduleE,
 			moduleE: moduleF,
 		}
-		errs := parallelVisit([]*moduleInfo{moduleD, moduleE, moduleF, moduleG}, bottomUpVisitorImpl{}, 4,
+		errs := parallelVisit(slices.Values([]*moduleInfo{moduleD, moduleE, moduleF, moduleG}), bottomUpVisitorImpl{}, 4,
 			func(module *moduleInfo, pause chan<- pauseSpec) bool {
 				if dep, ok := pauseDeps[module]; ok {
 					unpause := make(chan struct{})
@@ -1513,7 +1380,7 @@ func TestSourceRootDirs(t *testing.T) {
 			for _, modName := range tc.expectedModuleDefs {
 				allMods := ctx.moduleGroupFromName(modName, nil)
 				if allMods == nil || len(allMods.modules) != 1 {
-					mods := modulesOrAliases{}
+					mods := moduleList{}
 					if allMods != nil {
 						mods = allMods.modules
 					}
@@ -1571,7 +1438,7 @@ func incrementalSetup(t *testing.T) *Context {
 	return ctx
 }
 
-func incrementalSetupForRestore(t *testing.T, orderOnlyStrings *[]string) (*Context, any) {
+func incrementalSetupForRestore(t *testing.T, orderOnlyStrings []string) (*Context, any) {
 	ctx := incrementalSetup(t)
 	incInfo := ctx.moduleGroupFromName("MyIncrementalModule", nil).modules.firstModule()
 	barInfo := ctx.moduleGroupFromName("MyBarModule", nil).modules.firstModule()
@@ -1724,7 +1591,7 @@ func TestSkipNinjaForCacheHit(t *testing.T) {
 		t.Errorf("ninja file doesn't have build statements for MyBarModule: %s", string(content))
 	}
 
-	file, err = ctx.fs.Open("test_ninja_incremental/.-MyIncrementalModule-none-incremental_module.ninja")
+	file, err = ctx.fs.Open("test_incremental_ninja/.-MyIncrementalModule-none-incremental_module.ninja")
 	if !os.IsNotExist(err) {
 		t.Errorf("shouldn't generate ninja file for MyIncrementalModule: %s", err.Error())
 	}
@@ -1758,7 +1625,7 @@ func TestNotSkipNinjaForCacheMiss(t *testing.T) {
 		t.Errorf("ninja file doesn't have build statements for MyBarModule: %s", string(content))
 	}
 
-	file, err = ctx.fs.Open("test_ninja_incremental/.-MyIncrementalModule-none-incremental_module.ninja")
+	file, err = ctx.fs.Open("test_incremental_ninja/.-MyIncrementalModule-none-incremental_module.ninja")
 	if err != nil {
 		t.Errorf("no ninja file for MyIncrementalModule")
 	}
@@ -1798,7 +1665,7 @@ func TestOrderOnlyStringsCaching(t *testing.T) {
 func TestOrderOnlyStringsRestoring(t *testing.T) {
 	phony := "dedup-d479e9a8133ff998"
 	orderOnlyStrings := []string{phony}
-	ctx, _ := incrementalSetupForRestore(t, &orderOnlyStrings)
+	ctx, _ := incrementalSetupForRestore(t, orderOnlyStrings)
 	ctx.orderOnlyStringsFromCache = make(OrderOnlyStringsCache)
 	ctx.orderOnlyStringsFromCache[phony] = []string{"test.lib"}
 	_, errs := ctx.PrepareBuildActions(nil)
@@ -1841,8 +1708,8 @@ func verifyOrderOnlyStringsCache(t *testing.T, ctx *Context, incInfo, barInfo *m
 	if cache == nil {
 		t.Errorf("failed to find cached build actions for the incremental module")
 	}
-	if !listContainsValue(*cache.OrderOnlyStrings, key) {
-		t.Errorf("no order only strings cached for MyIncrementalModule: %v", *cache.OrderOnlyStrings)
+	if !listContainsValue(cache.OrderOnlyStrings, key) {
+		t.Errorf("no order only strings cached for MyIncrementalModule: %v", cache.OrderOnlyStrings)
 	}
 }
 
@@ -1864,3 +1731,118 @@ func mapContainsValue[K comparable, V comparable](m map[K][]V, target V) (bool,
 	var key K
 	return false, key
 }
+
+func TestDisallowedMutatorMethods(t *testing.T) {
+	testCases := []struct {
+		name              string
+		mutatorHandleFunc func(MutatorHandle)
+		mutatorFunc       func(BottomUpMutatorContext)
+		expectedPanic     string
+	}{
+		{
+			name:              "rename",
+			mutatorHandleFunc: func(handle MutatorHandle) { handle.UsesRename() },
+			mutatorFunc:       func(ctx BottomUpMutatorContext) { ctx.Rename("qux") },
+			expectedPanic:     "method Rename called from mutator that was not marked UsesRename",
+		},
+		{
+			name:              "replace_dependencies",
+			mutatorHandleFunc: func(handle MutatorHandle) { handle.UsesReplaceDependencies() },
+			mutatorFunc:       func(ctx BottomUpMutatorContext) { ctx.ReplaceDependencies("bar") },
+			expectedPanic:     "method ReplaceDependenciesIf called from mutator that was not marked UsesReplaceDependencies",
+		},
+		{
+			name:              "replace_dependencies_if",
+			mutatorHandleFunc: func(handle MutatorHandle) { handle.UsesReplaceDependencies() },
+			mutatorFunc: func(ctx BottomUpMutatorContext) {
+				ctx.ReplaceDependenciesIf("bar", func(from Module, tag DependencyTag, to Module) bool { return false })
+			},
+			expectedPanic: "method ReplaceDependenciesIf called from mutator that was not marked UsesReplaceDependencies",
+		},
+		{
+			name:              "reverse_dependencies",
+			mutatorHandleFunc: func(handle MutatorHandle) { handle.UsesReverseDependencies() },
+			mutatorFunc:       func(ctx BottomUpMutatorContext) { ctx.AddReverseDependency(ctx.Module(), nil, "baz") },
+			expectedPanic:     "method AddReverseDependency called from mutator that was not marked UsesReverseDependencies",
+		},
+		{
+			name:              "create_module",
+			mutatorHandleFunc: func(handle MutatorHandle) { handle.UsesCreateModule() },
+			mutatorFunc: func(ctx BottomUpMutatorContext) {
+				ctx.CreateModule(newFooModule, "create_module",
+					&struct{ Name string }{Name: "quz"})
+			},
+			expectedPanic: "method CreateModule called from mutator that was not marked UsesCreateModule",
+		},
+	}
+
+	runTest := func(mutatorHandleFunc func(MutatorHandle), mutatorFunc func(ctx BottomUpMutatorContext), expectedPanic string) {
+		ctx := NewContext()
+
+		ctx.MockFileSystem(map[string][]byte{
+			"Android.bp": []byte(`
+			foo_module {
+				name: "foo",
+			}
+
+			foo_module {
+				name: "bar",
+				deps: ["foo"],
+			}
+
+			foo_module {
+				name: "baz",
+			}
+		`)})
+
+		ctx.RegisterModuleType("foo_module", newFooModule)
+		ctx.RegisterBottomUpMutator("deps", depsMutator)
+		handle := ctx.RegisterBottomUpMutator("mutator", func(ctx BottomUpMutatorContext) {
+			if ctx.ModuleName() == "foo" {
+				mutatorFunc(ctx)
+			}
+		})
+		mutatorHandleFunc(handle)
+
+		_, errs := ctx.ParseBlueprintsFiles("Android.bp", nil)
+		if len(errs) > 0 {
+			t.Errorf("unexpected parse errors:")
+			for _, err := range errs {
+				t.Errorf("  %s", err)
+			}
+			t.FailNow()
+		}
+
+		_, errs = ctx.ResolveDependencies(nil)
+		if expectedPanic != "" {
+			if len(errs) == 0 {
+				t.Errorf("missing expected error %q", expectedPanic)
+			} else if !strings.Contains(errs[0].Error(), expectedPanic) {
+				t.Errorf("missing expected error %q in %q", expectedPanic, errs[0].Error())
+			}
+		} else if len(errs) > 0 {
+			t.Errorf("unexpected dep errors:")
+			for _, err := range errs {
+				t.Errorf("  %s", err)
+			}
+			t.FailNow()
+		}
+	}
+
+	noopMutatorHandleFunc := func(MutatorHandle) {}
+
+	for _, testCase := range testCases {
+		t.Run(testCase.name, func(t *testing.T) {
+			t.Run("allowed", func(t *testing.T) {
+				// Test that the method doesn't panic when the handle function is called.
+				runTest(testCase.mutatorHandleFunc, testCase.mutatorFunc, "")
+			})
+			t.Run("disallowed", func(t *testing.T) {
+				// Test that the method does panic with the expected error when the
+				// handle function is not called.
+				runTest(noopMutatorHandleFunc, testCase.mutatorFunc, testCase.expectedPanic)
+			})
+		})
+	}
+
+}
diff --git a/depset/Android.bp b/depset/Android.bp
new file mode 100644
index 0000000..3f76663
--- /dev/null
+++ b/depset/Android.bp
@@ -0,0 +1,17 @@
+bootstrap_go_package {
+    name: "blueprint-depset",
+    pkgPath: "github.com/google/blueprint/depset",
+    deps: [
+        "blueprint-gobtools",
+    ],
+    srcs: [
+        "depset.go",
+    ],
+    testSrcs: [
+        "depset_test.go",
+    ],
+    visibility: [
+        // used by plugins
+        "//visibility:public",
+    ],
+}
diff --git a/depset/depset.go b/depset/depset.go
new file mode 100644
index 0000000..ff4ad8a
--- /dev/null
+++ b/depset/depset.go
@@ -0,0 +1,315 @@
+// Copyright 2020 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package depset
+
+import (
+	"fmt"
+	"iter"
+	"slices"
+
+	"github.com/google/blueprint/gobtools"
+)
+
+// DepSet is designed to be conceptually compatible with Bazel's depsets:
+// https://docs.bazel.build/versions/master/skylark/depsets.html
+
+type Order int
+
+const (
+	PREORDER Order = iota
+	POSTORDER
+	TOPOLOGICAL
+)
+
+func (o Order) String() string {
+	switch o {
+	case PREORDER:
+		return "PREORDER"
+	case POSTORDER:
+		return "POSTORDER"
+	case TOPOLOGICAL:
+		return "TOPOLOGICAL"
+	default:
+		panic(fmt.Errorf("Invalid Order %d", o))
+	}
+}
+
+type depSettableType comparable
+
+// A DepSet efficiently stores a slice of an arbitrary type from transitive dependencies without
+// copying. It is stored as a DAG of DepSet nodes, each of which has some direct contents and a list
+// of dependency DepSet nodes.
+//
+// A DepSet has an order that will be used to walk the DAG when ToList() is called.  The order
+// can be POSTORDER, PREORDER, or TOPOLOGICAL.  POSTORDER and PREORDER orders return a postordered
+// or preordered left to right flattened list.  TOPOLOGICAL returns a list that guarantees that
+// elements of children are listed after all of their parents (unless there are duplicate direct
+// elements in the DepSet or any of its transitive dependencies, in which case the ordering of the
+// duplicated element is not guaranteed).
+//
+// A DepSet is created by New or NewBuilder.Build from the slice for direct contents
+// and the *DepSets of dependencies. A DepSet is immutable once created.
+type DepSet[T depSettableType] struct {
+	handle *depSet[T]
+}
+
+type depSet[T depSettableType] struct {
+	preorder   bool
+	reverse    bool
+	order      Order
+	direct     []T
+	transitive []DepSet[T]
+}
+
+func (d DepSet[T]) impl() *depSet[T] {
+	return d.handle
+}
+
+func (d DepSet[T]) order() Order {
+	impl := d.impl()
+	return impl.order
+}
+
+type depSetGob[T depSettableType] struct {
+	Preorder   bool
+	Reverse    bool
+	Order      Order
+	Direct     []T
+	Transitive []DepSet[T]
+}
+
+func (d *DepSet[T]) ToGob() *depSetGob[T] {
+	impl := d.impl()
+	return &depSetGob[T]{
+		Preorder:   impl.preorder,
+		Reverse:    impl.reverse,
+		Order:      impl.order,
+		Direct:     impl.direct,
+		Transitive: impl.transitive,
+	}
+}
+
+func (d *DepSet[T]) FromGob(data *depSetGob[T]) {
+	d.handle = &depSet[T]{
+		preorder:   data.Preorder,
+		reverse:    data.Reverse,
+		order:      data.Order,
+		direct:     data.Direct,
+		transitive: data.Transitive,
+	}
+}
+
+func (d DepSet[T]) GobEncode() ([]byte, error) {
+	return gobtools.CustomGobEncode[depSetGob[T]](&d)
+}
+
+func (d *DepSet[T]) GobDecode(data []byte) error {
+	return gobtools.CustomGobDecode[depSetGob[T]](data, d)
+}
+
+// New returns an immutable DepSet with the given order, direct and transitive contents.
+func New[T depSettableType](order Order, direct []T, transitive []DepSet[T]) DepSet[T] {
+	var directCopy []T
+	var transitiveCopy []DepSet[T]
+	nonEmptyTransitiveCount := 0
+	for _, t := range transitive {
+		if t.handle != nil {
+			if t.order() != order {
+				panic(fmt.Errorf("incompatible order, new DepSet is %s but transitive DepSet is %s",
+					order, t.order()))
+			}
+			nonEmptyTransitiveCount++
+		}
+	}
+
+	directCopy = slices.Clone(direct)
+	if nonEmptyTransitiveCount > 0 {
+		transitiveCopy = make([]DepSet[T], 0, nonEmptyTransitiveCount)
+	}
+	var transitiveIter iter.Seq2[int, DepSet[T]]
+	if order == TOPOLOGICAL {
+		// TOPOLOGICAL is implemented as a postorder traversal followed by reversing the output.
+		// Pre-reverse the inputs here so their order is maintained in the output.
+		slices.Reverse(directCopy)
+		transitiveIter = slices.Backward(transitive)
+	} else {
+		transitiveIter = slices.All(transitive)
+	}
+	for _, t := range transitiveIter {
+		if t.handle != nil {
+			transitiveCopy = append(transitiveCopy, t)
+		}
+	}
+
+	if len(directCopy) == 0 && len(transitive) == 0 {
+		return DepSet[T]{nil}
+	}
+
+	depSet := &depSet[T]{
+		preorder:   order == PREORDER,
+		reverse:    order == TOPOLOGICAL,
+		order:      order,
+		direct:     directCopy,
+		transitive: transitiveCopy,
+	}
+
+	return DepSet[T]{depSet}
+}
+
+// Builder is used to create an immutable DepSet.
+type Builder[T depSettableType] struct {
+	order      Order
+	direct     []T
+	transitive []DepSet[T]
+}
+
+// NewBuilder returns a Builder to create an immutable DepSet with the given order and
+// type, represented by a slice of type that will be in the DepSet.
+func NewBuilder[T depSettableType](order Order) *Builder[T] {
+	return &Builder[T]{
+		order: order,
+	}
+}
+
+// DirectSlice adds direct contents to the DepSet being built by a Builder. Newly added direct
+// contents are to the right of any existing direct contents.
+func (b *Builder[T]) DirectSlice(direct []T) *Builder[T] {
+	b.direct = append(b.direct, direct...)
+	return b
+}
+
+// Direct adds direct contents to the DepSet being built by a Builder. Newly added direct
+// contents are to the right of any existing direct contents.
+func (b *Builder[T]) Direct(direct ...T) *Builder[T] {
+	b.direct = append(b.direct, direct...)
+	return b
+}
+
+// Transitive adds transitive contents to the DepSet being built by a Builder. Newly added
+// transitive contents are to the right of any existing transitive contents.
+func (b *Builder[T]) Transitive(transitive ...DepSet[T]) *Builder[T] {
+	for _, t := range transitive {
+		if t.handle != nil && t.order() != b.order {
+			panic(fmt.Errorf("incompatible order, new DepSet is %s but transitive DepSet is %s",
+				b.order, t.order()))
+		}
+	}
+	b.transitive = append(b.transitive, transitive...)
+	return b
+}
+
+// Build returns the DepSet being built by this Builder.  The Builder retains its contents
+// for creating more depSets.
+func (b *Builder[T]) Build() DepSet[T] {
+	return New(b.order, b.direct, b.transitive)
+}
+
+// walk calls the visit method in depth-first order on a DepSet, preordered if d.preorder is set,
+// otherwise postordered.
+func (d DepSet[T]) walk(visit func([]T)) {
+	visited := make(map[DepSet[T]]bool)
+
+	var dfs func(d DepSet[T])
+	dfs = func(d DepSet[T]) {
+		impl := d.impl()
+		visited[d] = true
+		if impl.preorder {
+			visit(impl.direct)
+		}
+		for _, dep := range impl.transitive {
+			if !visited[dep] {
+				dfs(dep)
+			}
+		}
+
+		if !impl.preorder {
+			visit(impl.direct)
+		}
+	}
+
+	dfs(d)
+}
+
+// ToList returns the DepSet flattened to a list.  The order in the list is based on the order
+// of the DepSet.  POSTORDER and PREORDER orders return a postordered or preordered left to right
+// flattened list.  TOPOLOGICAL returns a list that guarantees that elements of children are listed
+// after all of their parents (unless there are duplicate direct elements in the DepSet or any of
+// its transitive dependencies, in which case the ordering of the duplicated element is not
+// guaranteed).
+func (d DepSet[T]) ToList() []T {
+	if d.handle == nil {
+		return nil
+	}
+	impl := d.impl()
+	var list []T
+	d.walk(func(paths []T) {
+		list = append(list, paths...)
+	})
+	list = firstUniqueInPlace(list)
+	if impl.reverse {
+		slices.Reverse(list)
+	}
+	return list
+}
+
+// firstUniqueInPlace returns all unique elements of a slice, keeping the first copy of
+// each.  It modifies the slice contents in place, and returns a subslice of the original
+// slice.
+func firstUniqueInPlace[T comparable](slice []T) []T {
+	// 128 was chosen based on BenchmarkFirstUniqueStrings results.
+	if len(slice) > 128 {
+		return firstUniqueMap(slice)
+	}
+	return firstUniqueList(slice)
+}
+
+// firstUniqueList is an implementation of firstUnique using an O(N^2) list comparison to look for
+// duplicates.
+func firstUniqueList[T any](in []T) []T {
+	writeIndex := 0
+outer:
+	for readIndex := 0; readIndex < len(in); readIndex++ {
+		for compareIndex := 0; compareIndex < writeIndex; compareIndex++ {
+			if interface{}(in[readIndex]) == interface{}(in[compareIndex]) {
+				// The value at readIndex already exists somewhere in the output region
+				// of the slice before writeIndex, skip it.
+				continue outer
+			}
+		}
+		if readIndex != writeIndex {
+			in[writeIndex] = in[readIndex]
+		}
+		writeIndex++
+	}
+	return in[0:writeIndex]
+}
+
+// firstUniqueMap is an implementation of firstUnique using an O(N) hash set lookup to look for
+// duplicates.
+func firstUniqueMap[T comparable](in []T) []T {
+	writeIndex := 0
+	seen := make(map[T]bool, len(in))
+	for readIndex := 0; readIndex < len(in); readIndex++ {
+		if _, exists := seen[in[readIndex]]; exists {
+			continue
+		}
+		seen[in[readIndex]] = true
+		if readIndex != writeIndex {
+			in[writeIndex] = in[readIndex]
+		}
+		writeIndex++
+	}
+	return in[0:writeIndex]
+}
diff --git a/depset/depset_test.go b/depset/depset_test.go
new file mode 100644
index 0000000..91ca9e0
--- /dev/null
+++ b/depset/depset_test.go
@@ -0,0 +1,301 @@
+// Copyright 2020 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package depset
+
+import (
+	"fmt"
+	"reflect"
+	"slices"
+	"strings"
+	"testing"
+)
+
+func ExampleDepSet_ToList_postordered() {
+	a := NewBuilder[string](POSTORDER).Direct("a").Build()
+	b := NewBuilder[string](POSTORDER).Direct("b").Transitive(a).Build()
+	c := NewBuilder[string](POSTORDER).Direct("c").Transitive(a).Build()
+	d := NewBuilder[string](POSTORDER).Direct("d").Transitive(b, c).Build()
+
+	fmt.Println(d.ToList())
+	// Output: [a b c d]
+}
+
+func ExampleDepSet_ToList_preordered() {
+	a := NewBuilder[string](PREORDER).Direct("a").Build()
+	b := NewBuilder[string](PREORDER).Direct("b").Transitive(a).Build()
+	c := NewBuilder[string](PREORDER).Direct("c").Transitive(a).Build()
+	d := NewBuilder[string](PREORDER).Direct("d").Transitive(b, c).Build()
+
+	fmt.Println(d.ToList())
+	// Output: [d b a c]
+}
+
+func ExampleDepSet_ToList_topological() {
+	a := NewBuilder[string](TOPOLOGICAL).Direct("a").Build()
+	b := NewBuilder[string](TOPOLOGICAL).Direct("b").Transitive(a).Build()
+	c := NewBuilder[string](TOPOLOGICAL).Direct("c").Transitive(a).Build()
+	d := NewBuilder[string](TOPOLOGICAL).Direct("d").Transitive(b, c).Build()
+
+	fmt.Println(d.ToList())
+	// Output: [d b c a]
+}
+
+// Tests based on Bazel's ExpanderTestBase.java to ensure compatibility
+// https://github.com/bazelbuild/bazel/blob/master/src/test/java/com/google/devtools/build/lib/collect/nestedset/ExpanderTestBase.java
+func TestDepSet(t *testing.T) {
+	tests := []struct {
+		name                             string
+		depSet                           func(t *testing.T, order Order) DepSet[string]
+		postorder, preorder, topological []string
+	}{
+		{
+			name: "simple",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				return New[string](order, []string{"c", "a", "b"}, nil)
+			},
+			postorder:   []string{"c", "a", "b"},
+			preorder:    []string{"c", "a", "b"},
+			topological: []string{"c", "a", "b"},
+		},
+		{
+			name: "simpleNoDuplicates",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				return New[string](order, []string{"c", "a", "a", "a", "b"}, nil)
+			},
+			postorder:   []string{"c", "a", "b"},
+			preorder:    []string{"c", "a", "b"},
+			topological: []string{"c", "a", "b"},
+		},
+		{
+			name: "nesting",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				subset := New[string](order, []string{"c", "a", "e"}, nil)
+				return New[string](order, []string{"b", "d"}, []DepSet[string]{subset})
+			},
+			postorder:   []string{"c", "a", "e", "b", "d"},
+			preorder:    []string{"b", "d", "c", "a", "e"},
+			topological: []string{"b", "d", "c", "a", "e"},
+		},
+		{
+			name: "builderReuse",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				assertEquals := func(t *testing.T, w, g []string) {
+					t.Helper()
+					if !reflect.DeepEqual(w, g) {
+						t.Errorf("want %q, got %q", w, g)
+					}
+				}
+				builder := NewBuilder[string](order)
+				assertEquals(t, nil, builder.Build().ToList())
+
+				builder.Direct("b")
+				assertEquals(t, []string{"b"}, builder.Build().ToList())
+
+				builder.Direct("d")
+				assertEquals(t, []string{"b", "d"}, builder.Build().ToList())
+
+				child := NewBuilder[string](order).Direct("c", "a", "e").Build()
+				builder.Transitive(child)
+				return builder.Build()
+			},
+			postorder:   []string{"c", "a", "e", "b", "d"},
+			preorder:    []string{"b", "d", "c", "a", "e"},
+			topological: []string{"b", "d", "c", "a", "e"},
+		},
+		{
+			name: "builderChaining",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				return NewBuilder[string](order).Direct("b").Direct("d").
+					Transitive(NewBuilder[string](order).Direct("c", "a", "e").Build()).Build()
+			},
+			postorder:   []string{"c", "a", "e", "b", "d"},
+			preorder:    []string{"b", "d", "c", "a", "e"},
+			topological: []string{"b", "d", "c", "a", "e"},
+		},
+		{
+			name: "transitiveDepsHandledSeparately",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				subset := NewBuilder[string](order).Direct("c", "a", "e").Build()
+				builder := NewBuilder[string](order)
+				// The fact that we add the transitive subset between the Direct(b) and Direct(d)
+				// calls should not change the result.
+				builder.Direct("b")
+				builder.Transitive(subset)
+				builder.Direct("d")
+				return builder.Build()
+			},
+			postorder:   []string{"c", "a", "e", "b", "d"},
+			preorder:    []string{"b", "d", "c", "a", "e"},
+			topological: []string{"b", "d", "c", "a", "e"},
+		},
+		{
+			name: "nestingNoDuplicates",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				subset := NewBuilder[string](order).Direct("c", "a", "e").Build()
+				return NewBuilder[string](order).Direct("b", "d", "e").Transitive(subset).Build()
+			},
+			postorder:   []string{"c", "a", "e", "b", "d"},
+			preorder:    []string{"b", "d", "e", "c", "a"},
+			topological: []string{"b", "d", "c", "a", "e"},
+		},
+		{
+			name: "chain",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				c := NewBuilder[string](order).Direct("c").Build()
+				b := NewBuilder[string](order).Direct("b").Transitive(c).Build()
+				a := NewBuilder[string](order).Direct("a").Transitive(b).Build()
+
+				return a
+			},
+			postorder:   []string{"c", "b", "a"},
+			preorder:    []string{"a", "b", "c"},
+			topological: []string{"a", "b", "c"},
+		},
+		{
+			name: "diamond",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				d := NewBuilder[string](order).Direct("d").Build()
+				c := NewBuilder[string](order).Direct("c").Transitive(d).Build()
+				b := NewBuilder[string](order).Direct("b").Transitive(d).Build()
+				a := NewBuilder[string](order).Direct("a").Transitive(b).Transitive(c).Build()
+
+				return a
+			},
+			postorder:   []string{"d", "b", "c", "a"},
+			preorder:    []string{"a", "b", "d", "c"},
+			topological: []string{"a", "b", "c", "d"},
+		},
+		{
+			name: "extendedDiamond",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				d := NewBuilder[string](order).Direct("d").Build()
+				e := NewBuilder[string](order).Direct("e").Build()
+				b := NewBuilder[string](order).Direct("b").Transitive(d).Transitive(e).Build()
+				c := NewBuilder[string](order).Direct("c").Transitive(e).Transitive(d).Build()
+				a := NewBuilder[string](order).Direct("a").Transitive(b).Transitive(c).Build()
+				return a
+			},
+			postorder:   []string{"d", "e", "b", "c", "a"},
+			preorder:    []string{"a", "b", "d", "e", "c"},
+			topological: []string{"a", "b", "c", "e", "d"},
+		},
+		{
+			name: "extendedDiamondRightArm",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				d := NewBuilder[string](order).Direct("d").Build()
+				e := NewBuilder[string](order).Direct("e").Build()
+				b := NewBuilder[string](order).Direct("b").Transitive(d).Transitive(e).Build()
+				c2 := NewBuilder[string](order).Direct("c2").Transitive(e).Transitive(d).Build()
+				c := NewBuilder[string](order).Direct("c").Transitive(c2).Build()
+				a := NewBuilder[string](order).Direct("a").Transitive(b).Transitive(c).Build()
+				return a
+			},
+			postorder:   []string{"d", "e", "b", "c2", "c", "a"},
+			preorder:    []string{"a", "b", "d", "e", "c", "c2"},
+			topological: []string{"a", "b", "c", "c2", "e", "d"},
+		},
+		{
+			name: "orderConflict",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				child1 := NewBuilder[string](order).Direct("a", "b").Build()
+				child2 := NewBuilder[string](order).Direct("b", "a").Build()
+				parent := NewBuilder[string](order).Transitive(child1).Transitive(child2).Build()
+				return parent
+			},
+			postorder:   []string{"a", "b"},
+			preorder:    []string{"a", "b"},
+			topological: []string{"b", "a"},
+		},
+		{
+			name: "orderConflictNested",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				a := NewBuilder[string](order).Direct("a").Build()
+				b := NewBuilder[string](order).Direct("b").Build()
+				child1 := NewBuilder[string](order).Transitive(a).Transitive(b).Build()
+				child2 := NewBuilder[string](order).Transitive(b).Transitive(a).Build()
+				parent := NewBuilder[string](order).Transitive(child1).Transitive(child2).Build()
+				return parent
+			},
+			postorder:   []string{"a", "b"},
+			preorder:    []string{"a", "b"},
+			topological: []string{"b", "a"},
+		},
+		{
+			name: "zeroDepSet",
+			depSet: func(t *testing.T, order Order) DepSet[string] {
+				a := NewBuilder[string](order).Build()
+				var b DepSet[string]
+				c := NewBuilder[string](order).Direct("c").Transitive(a, b).Build()
+				return c
+			},
+			postorder:   []string{"c"},
+			preorder:    []string{"c"},
+			topological: []string{"c"},
+		},
+	}
+
+	for _, tt := range tests {
+		t.Run(tt.name, func(t *testing.T) {
+			t.Run("postorder", func(t *testing.T) {
+				depSet := tt.depSet(t, POSTORDER)
+				if g, w := depSet.ToList(), tt.postorder; !slices.Equal(g, w) {
+					t.Errorf("expected ToList() = %q, got %q", w, g)
+				}
+			})
+			t.Run("preorder", func(t *testing.T) {
+				depSet := tt.depSet(t, PREORDER)
+				if g, w := depSet.ToList(), tt.preorder; !slices.Equal(g, w) {
+					t.Errorf("expected ToList() = %q, got %q", w, g)
+				}
+			})
+			t.Run("topological", func(t *testing.T) {
+				depSet := tt.depSet(t, TOPOLOGICAL)
+				if g, w := depSet.ToList(), tt.topological; !slices.Equal(g, w) {
+					t.Errorf("expected ToList() = %q, got %q", w, g)
+				}
+			})
+		})
+	}
+}
+
+func TestDepSetInvalidOrder(t *testing.T) {
+	orders := []Order{POSTORDER, PREORDER, TOPOLOGICAL}
+
+	run := func(t *testing.T, order1, order2 Order) {
+		defer func() {
+			if r := recover(); r != nil {
+				if err, ok := r.(error); !ok {
+					t.Fatalf("expected panic error, got %v", err)
+				} else if !strings.Contains(err.Error(), "incompatible order") {
+					t.Fatalf("expected incompatible order error, got %v", err)
+				}
+			}
+		}()
+		New(order1, nil, []DepSet[string]{New[string](order2, []string{"a"}, nil)})
+		t.Fatal("expected panic")
+	}
+
+	for _, order1 := range orders {
+		t.Run(order1.String(), func(t *testing.T) {
+			for _, order2 := range orders {
+				t.Run(order2.String(), func(t *testing.T) {
+					if order1 != order2 {
+						run(t, order1, order2)
+					}
+				})
+			}
+		})
+	}
+}
diff --git a/go.mod b/go.mod
index 9caab2c..902433a 100644
--- a/go.mod
+++ b/go.mod
@@ -1,3 +1,3 @@
 module github.com/google/blueprint
 
-go 1.22
+go 1.23
diff --git a/gobtools/Android.bp b/gobtools/Android.bp
new file mode 100644
index 0000000..de0970a
--- /dev/null
+++ b/gobtools/Android.bp
@@ -0,0 +1,11 @@
+bootstrap_go_package {
+    name: "blueprint-gobtools",
+    pkgPath: "github.com/google/blueprint/gobtools",
+    srcs: [
+        "gob_tools.go",
+    ],
+    visibility: [
+        // used by plugins
+        "//visibility:public",
+    ],
+}
diff --git a/gobtools/gob_tools.go b/gobtools/gob_tools.go
new file mode 100644
index 0000000..f45c364
--- /dev/null
+++ b/gobtools/gob_tools.go
@@ -0,0 +1,49 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package gobtools
+
+import (
+	"bytes"
+	"encoding/gob"
+)
+
+type CustomGob[T any] interface {
+	ToGob() *T
+	FromGob(data *T)
+}
+
+func CustomGobEncode[T any](cg CustomGob[T]) ([]byte, error) {
+	w := new(bytes.Buffer)
+	encoder := gob.NewEncoder(w)
+	err := encoder.Encode(cg.ToGob())
+	if err != nil {
+		return nil, err
+	}
+
+	return w.Bytes(), nil
+}
+
+func CustomGobDecode[T any](data []byte, cg CustomGob[T]) error {
+	r := bytes.NewBuffer(data)
+	var value T
+	decoder := gob.NewDecoder(r)
+	err := decoder.Decode(&value)
+	if err != nil {
+		return err
+	}
+	cg.FromGob(&value)
+
+	return nil
+}
diff --git a/gotestmain/gotestmain.go b/gotestmain/gotestmain.go
index ea381ca..ecfebbb 100644
--- a/gotestmain/gotestmain.go
+++ b/gotestmain/gotestmain.go
@@ -210,6 +210,10 @@ func (matchString) SnapshotCoverage() {
 	panic("shouldn't get here")
 }
 
+func (f matchString) InitRuntimeCoverage() (mode string, tearDown func(string, string) (string, error), snapcov func() float64) {
+	return
+}
+
 type corpusEntry = struct {
 	Parent     string
 	Path       string
diff --git a/incremental.go b/incremental.go
index ca899cb..e4f8c2a 100644
--- a/incremental.go
+++ b/incremental.go
@@ -31,7 +31,7 @@ type CachedProvider struct {
 type BuildActionCachedData struct {
 	Providers        []CachedProvider
 	Pos              *scanner.Position
-	OrderOnlyStrings *[]string
+	OrderOnlyStrings []string
 }
 
 type BuildActionCache = map[BuildActionCacheKey]*BuildActionCachedData
diff --git a/module_ctx.go b/module_ctx.go
index 8c8e81c..22c24a5 100644
--- a/module_ctx.go
+++ b/module_ctx.go
@@ -15,8 +15,10 @@
 package blueprint
 
 import (
+	"errors"
 	"fmt"
 	"path/filepath"
+	"sort"
 	"strings"
 	"sync"
 	"text/scanner"
@@ -106,6 +108,24 @@ type Module interface {
 	GenerateBuildActions(ModuleContext)
 }
 
+type ModuleProxy struct {
+	module Module
+}
+
+func CreateModuleProxy(module Module) ModuleProxy {
+	return ModuleProxy{
+		module: module,
+	}
+}
+
+func (m ModuleProxy) Name() string {
+	return m.module.Name()
+}
+
+func (m ModuleProxy) GenerateBuildActions(context ModuleContext) {
+	m.module.GenerateBuildActions(context)
+}
+
 // A DynamicDependerModule is a Module that may add dependencies that do not
 // appear in its "deps" property.  Any Module that implements this interface
 // will have its DynamicDependencies method called by the Context that created
@@ -129,7 +149,7 @@ type EarlyModuleContext interface {
 	Module() Module
 
 	// ModuleName returns the name of the module.  This is generally the value that was returned by Module.Name() when
-	// the module was created, but may have been modified by calls to BaseMutatorContext.Rename.
+	// the module was created, but may have been modified by calls to BottomUpMutatorContext.Rename.
 	ModuleName() string
 
 	// ModuleDir returns the path to the directory that contains the definition of the module.
@@ -200,6 +220,10 @@ type EarlyModuleContext interface {
 
 	// ModuleFactories returns a map of all of the global ModuleFactories by name.
 	ModuleFactories() map[string]ModuleFactory
+
+	// HasMutatorFinished returns true if the given mutator has finished running.
+	// It will panic if given an invalid mutator name.
+	HasMutatorFinished(mutatorName string) bool
 }
 
 type BaseModuleContext interface {
@@ -222,6 +246,8 @@ type BaseModuleContext interface {
 	// invalidated by future mutators.
 	VisitDirectDeps(visit func(Module))
 
+	VisitDirectDepsProxy(visit func(proxy ModuleProxy))
+
 	// VisitDirectDepsIf calls pred for each direct dependency, and if pred returns true calls visit.  If there are
 	// multiple direct dependencies on the same module pred and visit will be called multiple times on that module and
 	// OtherModuleDependencyTag will return a different tag for each.
@@ -258,6 +284,8 @@ type BaseModuleContext interface {
 	// invalidated by future mutators.
 	WalkDeps(visit func(Module, Module) bool)
 
+	WalkDepsProxy(visit func(ModuleProxy, ModuleProxy) bool)
+
 	// PrimaryModule returns the first variant of the current module.  Variants of a module are always visited in
 	// order by mutators and GenerateBuildActions, so the data created by the current mutator can be read from the
 	// Module returned by PrimaryModule without data races.  This can be used to perform singleton actions that are
@@ -270,12 +298,24 @@ type BaseModuleContext interface {
 	// singleton actions that are only done once for all variants of a module.
 	FinalModule() Module
 
+	// IsFinalModule returns if the current module is the last variant.  Variants of a module are always visited in
+	// order by mutators and GenerateBuildActions, so the data created by the current mutator can be read from all
+	// variants using VisitAllModuleVariants if the current module is the last one.  This can be used to perform
+	// singleton actions that are only done once for all variants of a module.
+	IsFinalModule(module Module) bool
+
 	// VisitAllModuleVariants calls visit for each variant of the current module.  Variants of a module are always
 	// visited in order by mutators and GenerateBuildActions, so the data created by the current mutator can be read
-	// from all variants if the current module == FinalModule().  Otherwise, care must be taken to not access any
+	// from all variants if the current module is the last one.  Otherwise, care must be taken to not access any
 	// data modified by the current mutator.
 	VisitAllModuleVariants(visit func(Module))
 
+	// VisitAllModuleVariantProxies calls visit for each variant of the current module.  Variants of a module are always
+	// visited in order by mutators and GenerateBuildActions, so the data created by the current mutator can be read
+	// from all variants if the current module is the last one.  Otherwise, care must be taken to not access any
+	// data modified by the current mutator.
+	VisitAllModuleVariantProxies(visit func(proxy ModuleProxy))
+
 	// OtherModuleName returns the name of another Module.  See BaseModuleContext.ModuleName for more information.
 	// It is intended for use inside the visit functions of Visit* and WalkDeps.
 	OtherModuleName(m Module) string
@@ -284,11 +324,6 @@ type BaseModuleContext interface {
 	// It is intended for use inside the visit functions of Visit* and WalkDeps.
 	OtherModuleDir(m Module) string
 
-	// OtherModuleSubDir returns the unique subdirectory name of another Module.  See ModuleContext.ModuleSubDir for
-	// more information.
-	// It is intended for use inside the visit functions of Visit* and WalkDeps.
-	OtherModuleSubDir(m Module) string
-
 	// OtherModuleType returns the type of another Module.  See BaseModuleContext.ModuleType for more information.
 	// It is intended for use inside the visit functions of Visit* and WalkDeps.
 	OtherModuleType(m Module) string
@@ -344,6 +379,10 @@ type BaseModuleContext interface {
 	// This method shouldn't be used directly, prefer the type-safe android.OtherModuleProvider instead.
 	OtherModuleProvider(m Module, provider AnyProviderKey) (any, bool)
 
+	// OtherModuleIsAutoGenerated returns true if a module has been generated from another module,
+	// instead of being defined in Android.bp file
+	OtherModuleIsAutoGenerated(m Module) bool
+
 	// Provider returns the value for a provider for the current module.  If the value is
 	// not set it returns nil and false.  It panics if called before the appropriate
 	// mutator or GenerateBuildActions pass for the provider.  The value returned may be a deep
@@ -360,12 +399,10 @@ type BaseModuleContext interface {
 	// This method shouldn't be used directly, prefer the type-safe android.SetProvider instead.
 	SetProvider(provider AnyProviderKey, value any)
 
-	// HasMutatorFinished returns true if the given mutator has finished running.
-	// It will panic if given an invalid mutator name.
-	HasMutatorFinished(mutatorName string) bool
-
 	EarlyGetMissingDependencies() []string
 
+	EqualModules(m1, m2 Module) bool
+
 	base() *baseModuleContext
 }
 
@@ -466,7 +503,7 @@ func (d *baseModuleContext) Errorf(pos scanner.Position,
 func (d *baseModuleContext) ModuleErrorf(format string,
 	args ...interface{}) {
 
-	d.error(d.context.ModuleErrorf(d.module.logicModule, format, args...))
+	d.error(d.context.moduleErrorf(d.module, format, args...))
 }
 
 func (d *baseModuleContext) PropertyErrorf(property, format string,
@@ -511,30 +548,29 @@ type moduleContext struct {
 	handledMissingDeps bool
 }
 
+func (m *baseModuleContext) EqualModules(m1, m2 Module) bool {
+	return getWrappedModule(m1) == getWrappedModule(m2)
+}
+
 func (m *baseModuleContext) OtherModuleName(logicModule Module) string {
-	module := m.context.moduleInfo[logicModule]
+	module := m.context.moduleInfo[getWrappedModule(logicModule)]
 	return module.Name()
 }
 
 func (m *baseModuleContext) OtherModuleDir(logicModule Module) string {
-	module := m.context.moduleInfo[logicModule]
+	module := m.context.moduleInfo[getWrappedModule(logicModule)]
 	return filepath.Dir(module.relBlueprintsFile)
 }
 
-func (m *baseModuleContext) OtherModuleSubDir(logicModule Module) string {
-	module := m.context.moduleInfo[logicModule]
-	return module.variant.name
-}
-
 func (m *baseModuleContext) OtherModuleType(logicModule Module) string {
-	module := m.context.moduleInfo[logicModule]
+	module := m.context.moduleInfo[getWrappedModule(logicModule)]
 	return module.typeName
 }
 
 func (m *baseModuleContext) OtherModuleErrorf(logicModule Module, format string,
 	args ...interface{}) {
 
-	module := m.context.moduleInfo[logicModule]
+	module := m.context.moduleInfo[getWrappedModule(logicModule)]
 	m.errs = append(m.errs, &ModuleError{
 		BlueprintError: BlueprintError{
 			Err: fmt.Errorf(format, args...),
@@ -544,9 +580,16 @@ func (m *baseModuleContext) OtherModuleErrorf(logicModule Module, format string,
 	})
 }
 
+func getWrappedModule(module Module) Module {
+	if mp, isProxy := module.(ModuleProxy); isProxy {
+		return mp.module
+	}
+	return module
+}
+
 func (m *baseModuleContext) OtherModuleDependencyTag(logicModule Module) DependencyTag {
 	// fast path for calling OtherModuleDependencyTag from inside VisitDirectDeps
-	if m.visitingDep.module != nil && logicModule == m.visitingDep.module.logicModule {
+	if m.visitingDep.module != nil && getWrappedModule(logicModule) == m.visitingDep.module.logicModule {
 		return m.visitingDep.tag
 	}
 
@@ -555,7 +598,7 @@ func (m *baseModuleContext) OtherModuleDependencyTag(logicModule Module) Depende
 	}
 
 	for _, dep := range m.visitingParent.directDeps {
-		if dep.module.logicModule == logicModule {
+		if dep.module.logicModule == getWrappedModule(logicModule) {
 			return dep.tag
 		}
 	}
@@ -569,7 +612,7 @@ func (m *baseModuleContext) ModuleFromName(name string) (Module, bool) {
 		if len(moduleGroup.modules) != 1 {
 			panic(fmt.Errorf("Expected exactly one module named %q, but got %d", name, len(moduleGroup.modules)))
 		}
-		moduleInfo := moduleGroup.modules[0].module()
+		moduleInfo := moduleGroup.modules[0]
 		if moduleInfo != nil {
 			return moduleInfo.logicModule, true
 		} else {
@@ -590,7 +633,10 @@ func (m *baseModuleContext) OtherModuleDependencyVariantExists(variations []Vari
 	if possibleDeps == nil {
 		return false
 	}
-	found, _ := m.context.findVariant(m.module, m.config, possibleDeps, variations, false, false)
+	found, _, errs := m.context.findVariant(m.module, m.config, possibleDeps, variations, false, false)
+	if errs != nil {
+		panic(errors.Join(errs...))
+	}
 	return found != nil
 }
 
@@ -599,7 +645,10 @@ func (m *baseModuleContext) OtherModuleFarDependencyVariantExists(variations []V
 	if possibleDeps == nil {
 		return false
 	}
-	found, _ := m.context.findVariant(m.module, m.config, possibleDeps, variations, true, false)
+	found, _, errs := m.context.findVariant(m.module, m.config, possibleDeps, variations, true, false)
+	if errs != nil {
+		panic(errors.Join(errs...))
+	}
 	return found != nil
 }
 
@@ -608,12 +657,15 @@ func (m *baseModuleContext) OtherModuleReverseDependencyVariantExists(name strin
 	if possibleDeps == nil {
 		return false
 	}
-	found, _ := m.context.findVariant(m.module, m.config, possibleDeps, nil, false, true)
+	found, _, errs := m.context.findVariant(m.module, m.config, possibleDeps, nil, false, true)
+	if errs != nil {
+		panic(errors.Join(errs...))
+	}
 	return found != nil
 }
 
 func (m *baseModuleContext) OtherModuleProvider(logicModule Module, provider AnyProviderKey) (any, bool) {
-	module := m.context.moduleInfo[logicModule]
+	module := m.context.moduleInfo[getWrappedModule(logicModule)]
 	return m.context.provider(module, provider.provider())
 }
 
@@ -752,6 +804,25 @@ func (m *baseModuleContext) VisitDirectDeps(visit func(Module)) {
 	m.visitingDep = depInfo{}
 }
 
+func (m *baseModuleContext) VisitDirectDepsProxy(visit func(proxy ModuleProxy)) {
+	defer func() {
+		if r := recover(); r != nil {
+			panic(newPanicErrorf(r, "VisitDirectDeps(%s, %s) for dependency %s",
+				m.module, funcName(visit), m.visitingDep.module))
+		}
+	}()
+
+	m.visitingParent = m.module
+
+	for _, dep := range m.module.directDeps {
+		m.visitingDep = dep
+		visit(ModuleProxy{dep.module.logicModule})
+	}
+
+	m.visitingParent = nil
+	m.visitingDep = depInfo{}
+}
+
 func (m *baseModuleContext) VisitDirectDepsIf(pred func(Module) bool, visit func(Module)) {
 	defer func() {
 		if r := recover(); r != nil {
@@ -824,6 +895,17 @@ func (m *baseModuleContext) WalkDeps(visit func(child, parent Module) bool) {
 	m.visitingDep = depInfo{}
 }
 
+func (m *baseModuleContext) WalkDepsProxy(visit func(child, parent ModuleProxy) bool) {
+	m.context.walkDeps(m.module, true, func(dep depInfo, parent *moduleInfo) bool {
+		m.visitingParent = parent
+		m.visitingDep = dep
+		return visit(ModuleProxy{dep.module.logicModule}, ModuleProxy{parent.logicModule})
+	}, nil)
+
+	m.visitingParent = nil
+	m.visitingDep = depInfo{}
+}
+
 func (m *baseModuleContext) PrimaryModule() Module {
 	return m.module.group.modules.firstModule().logicModule
 }
@@ -832,26 +914,38 @@ func (m *baseModuleContext) FinalModule() Module {
 	return m.module.group.modules.lastModule().logicModule
 }
 
+func (m *baseModuleContext) IsFinalModule(module Module) bool {
+	return m.module.group.modules.lastModule().logicModule == module
+}
+
 func (m *baseModuleContext) VisitAllModuleVariants(visit func(Module)) {
 	m.context.visitAllModuleVariants(m.module, visit)
 }
 
+func (m *baseModuleContext) VisitAllModuleVariantProxies(visit func(proxy ModuleProxy)) {
+	m.context.visitAllModuleVariants(m.module, visitProxyAdaptor(visit))
+}
+
 func (m *baseModuleContext) AddNinjaFileDeps(deps ...string) {
 	m.ninjaFileDeps = append(m.ninjaFileDeps, deps...)
 }
 
 func (m *baseModuleContext) ModuleFactories() map[string]ModuleFactory {
-	ret := make(map[string]ModuleFactory)
-	for k, v := range m.context.moduleFactories {
-		ret[k] = v
-	}
-	return ret
+	return m.context.ModuleTypeFactories()
 }
 
 func (m *baseModuleContext) base() *baseModuleContext {
 	return m
 }
 
+func (m *baseModuleContext) OtherModuleIsAutoGenerated(logicModule Module) bool {
+	module := m.context.moduleInfo[getWrappedModule(logicModule)]
+	if module == nil {
+		panic(fmt.Errorf("Module %s not found in baseModuleContext", logicModule.Name()))
+	}
+	return module.createdBy != nil
+}
+
 func (m *moduleContext) ModuleSubDir() string {
 	return m.module.variant.name
 }
@@ -916,92 +1010,54 @@ type mutatorContext struct {
 	reverseDeps      []reverseDep
 	rename           []rename
 	replace          []replace
-	newVariations    modulesOrAliases // new variants of existing modules
-	newModules       []*moduleInfo    // brand new modules
+	newVariations    moduleList    // new variants of existing modules
+	newModules       []*moduleInfo // brand new modules
 	defaultVariation *string
 	pauseCh          chan<- pauseSpec
 }
 
-type BaseMutatorContext interface {
-	BaseModuleContext
-
-	// Rename all variants of a module.  The new name is not visible to calls to ModuleName,
-	// AddDependency or OtherModuleName until after this mutator pass is complete.
-	Rename(name string)
-
-	// MutatorName returns the name that this mutator was registered with.
-	MutatorName() string
-
-	// CreateModule creates a new module by calling the factory method for the specified moduleType, and applies
-	// the specified property structs to it as if the properties were set in a blueprint file.
-	CreateModule(ModuleFactory, string, ...interface{}) Module
-}
-
 type TopDownMutatorContext interface {
-	BaseMutatorContext
+	BaseModuleContext
 }
 
 type BottomUpMutatorContext interface {
-	BaseMutatorContext
+	BaseModuleContext
 
 	// AddDependency adds a dependency to the given module.  It returns a slice of modules for each
 	// dependency (some entries may be nil).  Does not affect the ordering of the current mutator
 	// pass, but will be ordered correctly for all future mutator passes.
 	//
-	// If the mutator is parallel (see MutatorHandle.Parallel), this method will pause until the
-	// new dependencies have had the current mutator called on them.  If the mutator is not
-	// parallel this method does not affect the ordering of the current mutator pass, but will
-	// be ordered correctly for all future mutator passes.
+	// This method will pause until the new dependencies have had the current mutator called on them.
 	AddDependency(module Module, tag DependencyTag, name ...string) []Module
 
 	// AddReverseDependency adds a dependency from the destination to the given module.
 	// Does not affect the ordering of the current mutator pass, but will be ordered
 	// correctly for all future mutator passes.  All reverse dependencies for a destination module are
 	// collected until the end of the mutator pass, sorted by name, and then appended to the destination
-	// module's dependency list.
+	// module's dependency list.  May only  be called by mutators that were marked with
+	// UsesReverseDependencies during registration.
 	AddReverseDependency(module Module, tag DependencyTag, name string)
 
-	// CreateVariations splits  a module into multiple variants, one for each name in the variationNames
-	// parameter.  It returns a list of new modules in the same order as the variationNames
-	// list.
-	//
-	// If any of the dependencies of the module being operated on were already split
-	// by calling CreateVariations with the same name, the dependency will automatically
-	// be updated to point the matching variant.
-	//
-	// If a module is split, and then a module depending on the first module is not split
-	// when the Mutator is later called on it, the dependency of the depending module will
-	// automatically be updated to point to the first variant.
-	CreateVariations(variationNames ...string) []Module
-
-	// CreateLocalVariations splits a module into multiple variants, one for each name in the variationNames
-	// parameter.  It returns a list of new modules in the same order as the variantNames
-	// list.
-	//
-	// Local variations do not affect automatic dependency resolution - dependencies added
-	// to the split module via deps or DynamicDependerModule must exactly match a variant
-	// that contains all the non-local variations.
-	CreateLocalVariations(variationNames ...string) []Module
-
-	// SetDependencyVariation sets all dangling dependencies on the current module to point to the variation
-	// with given name. This function ignores the default variation set by SetDefaultDependencyVariation.
-	SetDependencyVariation(string)
-
-	// SetDefaultDependencyVariation sets the default variation when a dangling reference is detected
-	// during the subsequent calls on Create*Variations* functions. To reset, set it to nil.
-	SetDefaultDependencyVariation(*string)
-
 	// AddVariationDependencies adds deps as dependencies of the current module, but uses the variations
 	// argument to select which variant of the dependency to use.  It returns a slice of modules for
 	// each dependency (some entries may be nil).  A variant of the dependency must exist that matches
 	// the all of the non-local variations of the current module, plus the variations argument.
 	//
-	// If the mutator is parallel (see MutatorHandle.Parallel), this method will pause until the
-	// new dependencies have had the current mutator called on them.  If the mutator is not
-	// parallel this method does not affect the ordering of the current mutator pass, but will
-	// be ordered correctly for all future mutator passes.
+	//
+	// This method will pause until the new dependencies have had the current mutator called on them.
 	AddVariationDependencies([]Variation, DependencyTag, ...string) []Module
 
+	// AddReverseVariationDependency adds a dependency from the named module to the current
+	// module. The given variations will be added to the current module's varations, and then the
+	// result will be used to find the correct variation of the depending module, which must exist.
+	//
+	// Does not affect the ordering of the current mutator pass, but will be ordered
+	// correctly for all future mutator passes.  All reverse dependencies for a destination module are
+	// collected until the end of the mutator pass, sorted by name, and then appended to the destination
+	// module's dependency list.  May only  be called by mutators that were marked with
+	// UsesReverseDependencies during registration.
+	AddReverseVariationDependency([]Variation, DependencyTag, string)
+
 	// AddFarVariationDependencies adds deps as dependencies of the current module, but uses the
 	// variations argument to select which variant of the dependency to use.  It returns a slice of
 	// modules for each dependency (some entries may be nil).  A variant of the dependency must
@@ -1011,58 +1067,36 @@ type BottomUpMutatorContext interface {
 	// Unlike AddVariationDependencies, the variations of the current module are ignored - the
 	// dependency only needs to match the supplied variations.
 	//
-	// If the mutator is parallel (see MutatorHandle.Parallel), this method will pause until the
-	// new dependencies have had the current mutator called on them.  If the mutator is not
-	// parallel this method does not affect the ordering of the current mutator pass, but will
-	// be ordered correctly for all future mutator passes.
+	//
+	// This method will pause until the new dependencies have had the current mutator called on them.
 	AddFarVariationDependencies([]Variation, DependencyTag, ...string) []Module
 
-	// AddInterVariantDependency adds a dependency between two variants of the same module.  Variants are always
-	// ordered in the same order as they were listed in CreateVariations, and AddInterVariantDependency does not change
-	// that ordering, but it associates a DependencyTag with the dependency and makes it visible to VisitDirectDeps,
-	// WalkDeps, etc.
-	AddInterVariantDependency(tag DependencyTag, from, to Module)
-
 	// ReplaceDependencies finds all the variants of the module with the specified name, then
 	// replaces all dependencies onto those variants with the current variant of this module.
-	// Replacements don't take effect until after the mutator pass is finished.
+	// Replacements don't take effect until after the mutator pass is finished.  May only
+	// be called by mutators that were marked with UsesReplaceDependencies during registration.
 	ReplaceDependencies(string)
 
 	// ReplaceDependenciesIf finds all the variants of the module with the specified name, then
 	// replaces all dependencies onto those variants with the current variant of this module
 	// as long as the supplied predicate returns true.
-	// Replacements don't take effect until after the mutator pass is finished.
+	// Replacements don't take effect until after the mutator pass is finished.  May only
+	// be called by mutators that were marked with UsesReplaceDependencies during registration.
 	ReplaceDependenciesIf(string, ReplaceDependencyPredicate)
 
-	// AliasVariation takes a variationName that was passed to CreateVariations for this module,
-	// and creates an alias from the current variant (before the mutator has run) to the new
-	// variant.  The alias will be valid until the next time a mutator calls CreateVariations or
-	// CreateLocalVariations on this module without also calling AliasVariation.  The alias can
-	// be used to add dependencies on the newly created variant using the variant map from
-	// before CreateVariations was run.
-	AliasVariation(variationName string)
-
-	// CreateAliasVariation takes a toVariationName that was passed to CreateVariations for this
-	// module, and creates an alias from a new fromVariationName variant the toVariationName
-	// variant.  The alias will be valid until the next time a mutator calls CreateVariations or
-	// CreateLocalVariations on this module without also calling AliasVariation.  The alias can
-	// be used to add dependencies on the toVariationName variant using the fromVariationName
-	// variant.
-	CreateAliasVariation(fromVariationName, toVariationName string)
-
-	// SetVariationProvider sets the value for a provider for the given newly created variant of
-	// the current module, i.e. one of the Modules returned by CreateVariations..  It panics if
-	// not called during the appropriate mutator or GenerateBuildActions pass for the provider,
-	// if the value is not of the appropriate type, or if the module is not a newly created
-	// variant of the current module.  The value should not be modified after being passed to
-	// SetVariationProvider.
-	SetVariationProvider(module Module, provider AnyProviderKey, value interface{})
-}
-
-// A Mutator function is called for each Module, and can use
-// MutatorContext.CreateVariations to split a Module into multiple Modules,
-// modifying properties on the new modules to differentiate them.  It is called
-// after parsing all Blueprint files, but before generating any build rules,
+	// Rename all variants of a module.  The new name is not visible to calls to ModuleName,
+	// AddDependency or OtherModuleName until after this mutator pass is complete.  May only be called
+	// by mutators that were marked with UsesRename during registration.
+	Rename(name string)
+
+	// CreateModule creates a new module by calling the factory method for the specified moduleType, and applies
+	// the specified property structs to it as if the properties were set in a blueprint file.  May only
+	// be called by mutators that were marked with UsesCreateModule during registration.
+	CreateModule(ModuleFactory, string, ...interface{}) Module
+}
+
+// A Mutator function is called for each Module, and can modify properties on the modules.
+// It is called after parsing all Blueprint files, but before generating any build rules,
 // and is always called on dependencies before being called on the depending module.
 //
 // The Mutator function should only modify members of properties structs, and not
@@ -1073,8 +1107,7 @@ type BottomUpMutator func(mctx BottomUpMutatorContext)
 
 // DependencyTag is an interface to an arbitrary object that embeds BaseDependencyTag.  It can be
 // used to transfer information on a dependency between the mutator that called AddDependency
-// and the GenerateBuildActions method.  Variants created by CreateVariations have a copy of the
-// interface (pointing to the same concrete object) from their original module.
+// and the GenerateBuildActions method.
 type DependencyTag interface {
 	dependencyTag(DependencyTag)
 }
@@ -1087,43 +1120,19 @@ func (BaseDependencyTag) dependencyTag(DependencyTag) {
 
 var _ DependencyTag = BaseDependencyTag{}
 
-func (mctx *mutatorContext) MutatorName() string {
-	return mctx.mutator.name
-}
-
-func (mctx *mutatorContext) CreateVariations(variationNames ...string) []Module {
-	depChooser := chooseDepInherit(mctx.mutator.name, mctx.defaultVariation)
-	return mctx.createVariations(variationNames, depChooser, false)
-}
-
 func (mctx *mutatorContext) createVariationsWithTransition(variationNames []string, outgoingTransitions [][]string) []Module {
-	return mctx.createVariations(variationNames, chooseDepByIndexes(mctx.mutator.name, outgoingTransitions), false)
-}
-
-func (mctx *mutatorContext) CreateLocalVariations(variationNames ...string) []Module {
-	depChooser := chooseDepInherit(mctx.mutator.name, mctx.defaultVariation)
-	return mctx.createVariations(variationNames, depChooser, true)
-}
-
-func (mctx *mutatorContext) SetVariationProvider(module Module, provider AnyProviderKey, value interface{}) {
-	for _, variant := range mctx.newVariations {
-		if m := variant.module(); m != nil && m.logicModule == module {
-			mctx.context.setProvider(m, provider.provider(), value)
-			return
-		}
-	}
-	panic(fmt.Errorf("module %q is not a newly created variant of %q", module, mctx.module))
+	return mctx.createVariations(variationNames, chooseDepByIndexes(mctx.mutator.name, outgoingTransitions))
 }
 
-func (mctx *mutatorContext) createVariations(variationNames []string, depChooser depChooser, local bool) []Module {
+func (mctx *mutatorContext) createVariations(variationNames []string, depChooser depChooser) []Module {
 	var ret []Module
-	modules, errs := mctx.context.createVariations(mctx.module, mctx.mutator, depChooser, variationNames, local)
+	modules, errs := mctx.context.createVariations(mctx.module, mctx.mutator, depChooser, variationNames)
 	if len(errs) > 0 {
 		mctx.errs = append(mctx.errs, errs...)
 	}
 
 	for _, module := range modules {
-		ret = append(ret, module.module().logicModule)
+		ret = append(ret, module.logicModule)
 	}
 
 	if mctx.newVariations != nil {
@@ -1138,75 +1147,6 @@ func (mctx *mutatorContext) createVariations(variationNames []string, depChooser
 	return ret
 }
 
-func (mctx *mutatorContext) AliasVariation(variationName string) {
-	for _, moduleOrAlias := range mctx.module.splitModules {
-		if alias := moduleOrAlias.alias(); alias != nil {
-			if alias.variant.variations.equal(mctx.module.variant.variations) {
-				panic(fmt.Errorf("AliasVariation already called"))
-			}
-		}
-	}
-
-	for _, variant := range mctx.newVariations {
-		if variant.moduleOrAliasVariant().variations.get(mctx.mutator.name) == variationName {
-			alias := &moduleAlias{
-				variant: mctx.module.variant,
-				target:  variant.moduleOrAliasTarget(),
-			}
-			// Prepend the alias so that AddFarVariationDependencies subset match matches
-			// the alias before matching the first variation.
-			mctx.module.splitModules = append(modulesOrAliases{alias}, mctx.module.splitModules...)
-			return
-		}
-	}
-
-	var foundVariations []string
-	for _, variant := range mctx.newVariations {
-		foundVariations = append(foundVariations, variant.moduleOrAliasVariant().variations.get(mctx.mutator.name))
-	}
-	panic(fmt.Errorf("no %q variation in module variations %q", variationName, foundVariations))
-}
-
-func (mctx *mutatorContext) CreateAliasVariation(aliasVariationName, targetVariationName string) {
-	newVariant := newVariant(mctx.module, mctx.mutator.name, aliasVariationName, false)
-
-	for _, moduleOrAlias := range mctx.module.splitModules {
-		if moduleOrAlias.moduleOrAliasVariant().variations.equal(newVariant.variations) {
-			if alias := moduleOrAlias.alias(); alias != nil {
-				panic(fmt.Errorf("can't alias %q to %q, already aliased to %q", aliasVariationName, targetVariationName, alias.target.variant.name))
-			} else {
-				panic(fmt.Errorf("can't alias %q to %q, there is already a variant with that name", aliasVariationName, targetVariationName))
-			}
-		}
-	}
-
-	for _, variant := range mctx.newVariations {
-		if variant.moduleOrAliasVariant().variations.get(mctx.mutator.name) == targetVariationName {
-			// Append the alias here so that it comes after any aliases created by AliasVariation.
-			mctx.module.splitModules = append(mctx.module.splitModules, &moduleAlias{
-				variant: newVariant,
-				target:  variant.moduleOrAliasTarget(),
-			})
-			return
-		}
-	}
-
-	var foundVariations []string
-	for _, variant := range mctx.newVariations {
-		foundVariations = append(foundVariations, variant.moduleOrAliasVariant().variations.get(mctx.mutator.name))
-	}
-	panic(fmt.Errorf("no %q variation in module variations %q", targetVariationName, foundVariations))
-}
-
-func (mctx *mutatorContext) SetDependencyVariation(variationName string) {
-	mctx.context.convertDepsToVariation(mctx.module, 0, chooseDepExplicit(
-		mctx.mutator.name, variationName, nil))
-}
-
-func (mctx *mutatorContext) SetDefaultDependencyVariation(variationName *string) {
-	mctx.defaultVariation = variationName
-}
-
 func (mctx *mutatorContext) Module() Module {
 	return mctx.module.logicModule
 }
@@ -1215,7 +1155,7 @@ func (mctx *mutatorContext) AddDependency(module Module, tag DependencyTag, deps
 	depInfos := make([]Module, 0, len(deps))
 	for _, dep := range deps {
 		modInfo := mctx.context.moduleInfo[module]
-		depInfo, errs := mctx.context.addDependency(modInfo, mctx.config, tag, dep)
+		depInfo, errs := mctx.context.addVariationDependency(modInfo, mctx.mutator, mctx.config, nil, tag, dep, false)
 		if len(errs) > 0 {
 			mctx.errs = append(mctx.errs, errs...)
 		}
@@ -1229,28 +1169,63 @@ func (mctx *mutatorContext) AddDependency(module Module, tag DependencyTag, deps
 }
 
 func (mctx *mutatorContext) AddReverseDependency(module Module, tag DependencyTag, destName string) {
+	if !mctx.mutator.usesReverseDependencies {
+		panic(fmt.Errorf("method AddReverseDependency called from mutator that was not marked UsesReverseDependencies"))
+	}
+
 	if _, ok := tag.(BaseDependencyTag); ok {
 		panic("BaseDependencyTag is not allowed to be used directly!")
 	}
 
-	destModule, errs := mctx.context.findReverseDependency(mctx.context.moduleInfo[module], mctx.config, destName)
+	destModule, errs := mctx.context.findReverseDependency(mctx.context.moduleInfo[module], mctx.config, nil, destName)
 	if len(errs) > 0 {
 		mctx.errs = append(mctx.errs, errs...)
 		return
 	}
 
+	if destModule == nil {
+		// allowMissingDependencies is true and the module wasn't found
+		return
+	}
+
 	mctx.reverseDeps = append(mctx.reverseDeps, reverseDep{
 		destModule,
 		depInfo{mctx.context.moduleInfo[module], tag},
 	})
 }
 
+func (mctx *mutatorContext) AddReverseVariationDependency(variations []Variation, tag DependencyTag, destName string) {
+	if !mctx.mutator.usesReverseDependencies {
+		panic(fmt.Errorf("method AddReverseVariationDependency called from mutator that was not marked UsesReverseDependencies"))
+	}
+
+	if _, ok := tag.(BaseDependencyTag); ok {
+		panic("BaseDependencyTag is not allowed to be used directly!")
+	}
+
+	destModule, errs := mctx.context.findReverseDependency(mctx.module, mctx.config, variations, destName)
+	if len(errs) > 0 {
+		mctx.errs = append(mctx.errs, errs...)
+		return
+	}
+
+	if destModule == nil {
+		// allowMissingDependencies is true and the module wasn't found
+		return
+	}
+
+	mctx.reverseDeps = append(mctx.reverseDeps, reverseDep{
+		destModule,
+		depInfo{mctx.module, tag},
+	})
+}
+
 func (mctx *mutatorContext) AddVariationDependencies(variations []Variation, tag DependencyTag,
 	deps ...string) []Module {
 
 	depInfos := make([]Module, 0, len(deps))
 	for _, dep := range deps {
-		depInfo, errs := mctx.context.addVariationDependency(mctx.module, mctx.config, variations, tag, dep, false)
+		depInfo, errs := mctx.context.addVariationDependency(mctx.module, mctx.mutator, mctx.config, variations, tag, dep, false)
 		if len(errs) > 0 {
 			mctx.errs = append(mctx.errs, errs...)
 		}
@@ -1268,7 +1243,7 @@ func (mctx *mutatorContext) AddFarVariationDependencies(variations []Variation,
 
 	depInfos := make([]Module, 0, len(deps))
 	for _, dep := range deps {
-		depInfo, errs := mctx.context.addVariationDependency(mctx.module, mctx.config, variations, tag, dep, true)
+		depInfo, errs := mctx.context.addVariationDependency(mctx.module, mctx.mutator, mctx.config, variations, tag, dep, true)
 		if len(errs) > 0 {
 			mctx.errs = append(mctx.errs, errs...)
 		}
@@ -1281,10 +1256,6 @@ func (mctx *mutatorContext) AddFarVariationDependencies(variations []Variation,
 	return depInfos
 }
 
-func (mctx *mutatorContext) AddInterVariantDependency(tag DependencyTag, from, to Module) {
-	mctx.context.addInterVariantDependency(mctx.module, tag, from, to)
-}
-
 func (mctx *mutatorContext) ReplaceDependencies(name string) {
 	mctx.ReplaceDependenciesIf(name, nil)
 }
@@ -1292,6 +1263,10 @@ func (mctx *mutatorContext) ReplaceDependencies(name string) {
 type ReplaceDependencyPredicate func(from Module, tag DependencyTag, to Module) bool
 
 func (mctx *mutatorContext) ReplaceDependenciesIf(name string, predicate ReplaceDependencyPredicate) {
+	if !mctx.mutator.usesReplaceDependencies {
+		panic(fmt.Errorf("method ReplaceDependenciesIf called from mutator that was not marked UsesReplaceDependencies"))
+	}
+
 	targets := mctx.context.moduleVariantsThatDependOn(name, mctx.module)
 
 	if len(targets) == 0 {
@@ -1308,10 +1283,17 @@ func (mctx *mutatorContext) ReplaceDependenciesIf(name string, predicate Replace
 }
 
 func (mctx *mutatorContext) Rename(name string) {
+	if !mctx.mutator.usesRename {
+		panic(fmt.Errorf("method Rename called from mutator that was not marked UsesRename"))
+	}
 	mctx.rename = append(mctx.rename, rename{mctx.module.group, name})
 }
 
 func (mctx *mutatorContext) CreateModule(factory ModuleFactory, typeName string, props ...interface{}) Module {
+	if !mctx.mutator.usesCreateModule {
+		panic(fmt.Errorf("method CreateModule called from mutator that was not marked UsesCreateModule"))
+	}
+
 	module := newModule(factory)
 
 	module.relBlueprintsFile = mctx.module.relBlueprintsFile
@@ -1374,15 +1356,20 @@ type LoadHookContext interface {
 	// the specified property structs to it as if the properties were set in a blueprint file.
 	CreateModule(ModuleFactory, string, ...interface{}) Module
 
+	// CreateModuleInDirectory creates a new module in the specified directory by calling the
+	// factory method for the specified moduleType, and applies the specified property structs
+	// to it as if the properties were set in a blueprint file.
+	CreateModuleInDirectory(ModuleFactory, string, string, ...interface{}) Module
+
 	// RegisterScopedModuleType creates a new module type that is scoped to the current Blueprints
 	// file.
 	RegisterScopedModuleType(name string, factory ModuleFactory)
 }
 
-func (l *loadHookContext) CreateModule(factory ModuleFactory, typeName string, props ...interface{}) Module {
+func (l *loadHookContext) createModule(factory ModuleFactory, typeName, moduleDir string, props ...interface{}) Module {
 	module := newModule(factory)
 
-	module.relBlueprintsFile = l.module.relBlueprintsFile
+	module.relBlueprintsFile = moduleDir
 	module.pos = l.module.pos
 	module.propertyPos = l.module.propertyPos
 	module.createdBy = l.module
@@ -1400,6 +1387,19 @@ func (l *loadHookContext) CreateModule(factory ModuleFactory, typeName string, p
 	return module.logicModule
 }
 
+func (l *loadHookContext) CreateModule(factory ModuleFactory, typeName string, props ...interface{}) Module {
+	return l.createModule(factory, typeName, l.module.relBlueprintsFile, props...)
+}
+
+func (l *loadHookContext) CreateModuleInDirectory(factory ModuleFactory, typeName, moduleDir string, props ...interface{}) Module {
+	if moduleDir != filepath.Clean(moduleDir) {
+		panic(fmt.Errorf("Cannot create a module in %s", moduleDir))
+	}
+
+	filePath := filepath.Join(moduleDir, "Android.bp")
+	return l.createModule(factory, typeName, filePath, props...)
+}
+
 func (l *loadHookContext) RegisterScopedModuleType(name string, factory ModuleFactory) {
 	if _, exists := l.context.moduleFactories[name]; exists {
 		panic(fmt.Errorf("A global module type named %q already exists", name))
@@ -1424,6 +1424,14 @@ type loadHookContext struct {
 
 type LoadHook func(ctx LoadHookContext)
 
+// LoadHookWithPriority is a wrapper around LoadHook and allows hooks to be sorted by priority.
+// hooks with higher value of `priority` run last.
+// hooks with equal value of `priority` run in the order they were registered.
+type LoadHookWithPriority struct {
+	priority int
+	loadHook LoadHook
+}
+
 // Load hooks need to be added by module factories, which don't have any parameter to get to the
 // Context, and only produce a Module interface with no base implementation, so the load hooks
 // must be stored in a global map.  The key is a pointer allocated by the module factory, so there
@@ -1433,21 +1441,32 @@ type LoadHook func(ctx LoadHookContext)
 var pendingHooks sync.Map
 
 func AddLoadHook(module Module, hook LoadHook) {
+	// default priority is 0
+	AddLoadHookWithPriority(module, hook, 0)
+}
+
+// AddLoadhHookWithPriority adds a load hook with a specified priority.
+// Hooks with higher priority run last.
+// Hooks with equal priority run in the order they were registered.
+func AddLoadHookWithPriority(module Module, hook LoadHook, priority int) {
 	// Only one goroutine can be processing a given module, so no additional locking is required
 	// for the slice stored in the sync.Map.
 	v, exists := pendingHooks.Load(module)
 	if !exists {
-		v, _ = pendingHooks.LoadOrStore(module, new([]LoadHook))
+		v, _ = pendingHooks.LoadOrStore(module, new([]LoadHookWithPriority))
 	}
-	hooks := v.(*[]LoadHook)
-	*hooks = append(*hooks, hook)
+	hooks := v.(*[]LoadHookWithPriority)
+	*hooks = append(*hooks, LoadHookWithPriority{priority, hook})
 }
 
 func runAndRemoveLoadHooks(ctx *Context, config interface{}, module *moduleInfo,
 	scopedModuleFactories *map[string]ModuleFactory) (newModules []*moduleInfo, deps []string, errs []error) {
 
 	if v, exists := pendingHooks.Load(module.logicModule); exists {
-		hooks := v.(*[]LoadHook)
+		hooks := v.(*[]LoadHookWithPriority)
+		// Sort the hooks by priority.
+		// Use SliceStable so that hooks with equal priority run in the order they were registered.
+		sort.SliceStable(*hooks, func(i, j int) bool { return (*hooks)[i].priority < (*hooks)[j].priority })
 
 		for _, hook := range *hooks {
 			mctx := &loadHookContext{
@@ -1458,7 +1477,7 @@ func runAndRemoveLoadHooks(ctx *Context, config interface{}, module *moduleInfo,
 				},
 				scopedModuleFactories: scopedModuleFactories,
 			}
-			hook(mctx)
+			hook.loadHook(mctx)
 			newModules = append(newModules, mctx.newModules...)
 			deps = append(deps, mctx.ninjaFileDeps...)
 			errs = append(errs, mctx.errs...)
diff --git a/module_ctx_test.go b/module_ctx_test.go
index b6f7caf..9b7727d 100644
--- a/module_ctx_test.go
+++ b/module_ctx_test.go
@@ -32,42 +32,6 @@ func newModuleCtxTestModule() (Module, []interface{}) {
 func (f *moduleCtxTestModule) GenerateBuildActions(ModuleContext) {
 }
 
-func noAliasMutator(name string) func(ctx BottomUpMutatorContext) {
-	return func(ctx BottomUpMutatorContext) {
-		if ctx.ModuleName() == name {
-			ctx.CreateVariations("a", "b")
-		}
-	}
-}
-
-func aliasMutator(name string) func(ctx BottomUpMutatorContext) {
-	return func(ctx BottomUpMutatorContext) {
-		if ctx.ModuleName() == name {
-			ctx.CreateVariations("a", "b")
-			ctx.AliasVariation("b")
-		}
-	}
-}
-
-func createAliasMutator(name string) func(ctx BottomUpMutatorContext) {
-	return func(ctx BottomUpMutatorContext) {
-		if ctx.ModuleName() == name {
-			ctx.CreateVariations("a", "b")
-			ctx.CreateAliasVariation("c", "a")
-			ctx.CreateAliasVariation("d", "b")
-			ctx.CreateAliasVariation("e", "a")
-		}
-	}
-}
-
-func addVariantDepsMutator(variants []Variation, tag DependencyTag, from, to string) func(ctx BottomUpMutatorContext) {
-	return func(ctx BottomUpMutatorContext) {
-		if ctx.ModuleName() == from {
-			ctx.AddVariationDependencies(variants, tag, to)
-		}
-	}
-}
-
 func addVariantDepsResultMutator(variants []Variation, tag DependencyTag, from, to string, results map[string][]Module) func(ctx BottomUpMutatorContext) {
 	return func(ctx BottomUpMutatorContext) {
 		if ctx.ModuleName() == from {
@@ -77,240 +41,6 @@ func addVariantDepsResultMutator(variants []Variation, tag DependencyTag, from,
 	}
 }
 
-func TestAliasVariation(t *testing.T) {
-	runWithFailures := func(ctx *Context, expectedErr string) {
-		t.Helper()
-		bp := `
-			test {
-				name: "foo",
-			}
-
-			test {
-				name: "bar",
-			}
-		`
-
-		mockFS := map[string][]byte{
-			"Android.bp": []byte(bp),
-		}
-
-		ctx.MockFileSystem(mockFS)
-
-		_, errs := ctx.ParseFileList(".", []string{"Android.bp"}, nil)
-		if len(errs) > 0 {
-			t.Errorf("unexpected parse errors:")
-			for _, err := range errs {
-				t.Errorf("  %s", err)
-			}
-		}
-
-		_, errs = ctx.ResolveDependencies(nil)
-		if len(errs) > 0 {
-			if expectedErr == "" {
-				t.Errorf("unexpected dep errors:")
-				for _, err := range errs {
-					t.Errorf("  %s", err)
-				}
-			} else {
-				for _, err := range errs {
-					if strings.Contains(err.Error(), expectedErr) {
-						continue
-					} else {
-						t.Errorf("unexpected dep error: %s", err)
-					}
-				}
-			}
-		} else if expectedErr != "" {
-			t.Errorf("missing dep error: %s", expectedErr)
-		}
-	}
-
-	run := func(ctx *Context) {
-		t.Helper()
-		runWithFailures(ctx, "")
-	}
-
-	t.Run("simple", func(t *testing.T) {
-		// Creates a module "bar" with variants "a" and "b" and alias "" -> "b".
-		// Tests a dependency from "foo" to "bar" variant "b" through alias "".
-		ctx := NewContext()
-		ctx.RegisterModuleType("test", newModuleCtxTestModule)
-		ctx.RegisterBottomUpMutator("1", aliasMutator("bar"))
-		ctx.RegisterBottomUpMutator("2", addVariantDepsMutator(nil, nil, "foo", "bar"))
-
-		run(ctx)
-
-		foo := ctx.moduleGroupFromName("foo", nil).moduleByVariantName("")
-		barB := ctx.moduleGroupFromName("bar", nil).moduleByVariantName("b")
-
-		if g, w := foo.forwardDeps, []*moduleInfo{barB}; !reflect.DeepEqual(g, w) {
-			t.Fatalf("expected foo deps to be %q, got %q", w, g)
-		}
-	})
-
-	t.Run("chained", func(t *testing.T) {
-		// Creates a module "bar" with variants "a_a", "a_b", "b_a" and "b_b" and aliases "" -> "b_b",
-		// "a" -> "a_b", and "b" -> "b_b".
-		// Tests a dependency from "foo" to "bar" variant "b_b" through alias "".
-		ctx := NewContext()
-		ctx.RegisterModuleType("test", newModuleCtxTestModule)
-		ctx.RegisterBottomUpMutator("1", aliasMutator("bar"))
-		ctx.RegisterBottomUpMutator("2", aliasMutator("bar"))
-		ctx.RegisterBottomUpMutator("3", addVariantDepsMutator(nil, nil, "foo", "bar"))
-
-		run(ctx)
-
-		foo := ctx.moduleGroupFromName("foo", nil).moduleByVariantName("")
-		barBB := ctx.moduleGroupFromName("bar", nil).moduleByVariantName("b_b")
-
-		if g, w := foo.forwardDeps, []*moduleInfo{barBB}; !reflect.DeepEqual(g, w) {
-			t.Fatalf("expected foo deps to be %q, got %q", w, g)
-		}
-	})
-
-	t.Run("chained2", func(t *testing.T) {
-		// Creates a module "bar" with variants "a_a", "a_b", "b_a" and "b_b" and aliases "" -> "b_b",
-		// "a" -> "a_b", and "b" -> "b_b".
-		// Tests a dependency from "foo" to "bar" variant "a_b" through alias "a".
-		ctx := NewContext()
-		ctx.RegisterModuleType("test", newModuleCtxTestModule)
-		ctx.RegisterBottomUpMutator("1", aliasMutator("bar"))
-		ctx.RegisterBottomUpMutator("2", aliasMutator("bar"))
-		ctx.RegisterBottomUpMutator("3", addVariantDepsMutator([]Variation{{"1", "a"}}, nil, "foo", "bar"))
-
-		run(ctx)
-
-		foo := ctx.moduleGroupFromName("foo", nil).moduleByVariantName("")
-		barAB := ctx.moduleGroupFromName("bar", nil).moduleByVariantName("a_b")
-
-		if g, w := foo.forwardDeps, []*moduleInfo{barAB}; !reflect.DeepEqual(g, w) {
-			t.Fatalf("expected foo deps to be %q, got %q", w, g)
-		}
-	})
-
-	t.Run("removed dangling alias", func(t *testing.T) {
-		// Creates a module "bar" with variants "a" and "b" and aliases "" -> "b", then splits the variants into
-		// "a_a", "a_b", "b_a" and "b_b" without creating new aliases.
-		// Tests a dependency from "foo" to removed "bar" alias "" fails.
-		ctx := NewContext()
-		ctx.RegisterModuleType("test", newModuleCtxTestModule)
-		ctx.RegisterBottomUpMutator("1", aliasMutator("bar"))
-		ctx.RegisterBottomUpMutator("2", noAliasMutator("bar"))
-		ctx.RegisterBottomUpMutator("3", addVariantDepsMutator(nil, nil, "foo", "bar"))
-
-		runWithFailures(ctx, `dependency "bar" of "foo" missing variant:`+"\n  <empty variant>\n"+
-			"available variants:"+
-			"\n  1:a,2:a\n  1:a,2:b\n  1:b,2:a\n  1:b,2:b")
-	})
-}
-
-func TestCreateAliasVariations(t *testing.T) {
-	runWithFailures := func(ctx *Context, expectedErr string) {
-		t.Helper()
-		bp := `
-			test {
-				name: "foo",
-			}
-
-			test {
-				name: "bar",
-			}
-		`
-
-		mockFS := map[string][]byte{
-			"Android.bp": []byte(bp),
-		}
-
-		ctx.MockFileSystem(mockFS)
-
-		_, errs := ctx.ParseFileList(".", []string{"Android.bp"}, nil)
-		if len(errs) > 0 {
-			t.Errorf("unexpected parse errors:")
-			for _, err := range errs {
-				t.Errorf("  %s", err)
-			}
-		}
-
-		_, errs = ctx.ResolveDependencies(nil)
-		if len(errs) > 0 {
-			if expectedErr == "" {
-				t.Errorf("unexpected dep errors:")
-				for _, err := range errs {
-					t.Errorf("  %s", err)
-				}
-			} else {
-				for _, err := range errs {
-					if strings.Contains(err.Error(), expectedErr) {
-						continue
-					} else {
-						t.Errorf("unexpected dep error: %s", err)
-					}
-				}
-			}
-		} else if expectedErr != "" {
-			t.Errorf("missing dep error: %s", expectedErr)
-		}
-	}
-
-	run := func(ctx *Context) {
-		t.Helper()
-		runWithFailures(ctx, "")
-	}
-
-	t.Run("simple", func(t *testing.T) {
-		// Creates a module "bar" with variants "a" and "b" and alias "c" -> "a", "d" -> "b", and "e" -> "a".
-		// Tests a dependency from "foo" to "bar" variant "b" through alias "d".
-		ctx := NewContext()
-		ctx.RegisterModuleType("test", newModuleCtxTestModule)
-		ctx.RegisterBottomUpMutator("1", createAliasMutator("bar"))
-		ctx.RegisterBottomUpMutator("2", addVariantDepsMutator([]Variation{{"1", "d"}}, nil, "foo", "bar"))
-
-		run(ctx)
-
-		foo := ctx.moduleGroupFromName("foo", nil).moduleByVariantName("")
-		barB := ctx.moduleGroupFromName("bar", nil).moduleByVariantName("b")
-
-		if g, w := foo.forwardDeps, []*moduleInfo{barB}; !reflect.DeepEqual(g, w) {
-			t.Fatalf("expected foo deps to be %q, got %q", w, g)
-		}
-	})
-
-	t.Run("chained", func(t *testing.T) {
-		// Creates a module "bar" with variants "a_a", "a_b", "b_a" and "b_b" and aliases "c" -> "a_b",
-		// "d" -> "b_b", and "d" -> "a_b".
-		// Tests a dependency from "foo" to "bar" variant "b_b" through alias "d".
-		ctx := NewContext()
-		ctx.RegisterModuleType("test", newModuleCtxTestModule)
-		ctx.RegisterBottomUpMutator("1", createAliasMutator("bar"))
-		ctx.RegisterBottomUpMutator("2", aliasMutator("bar"))
-		ctx.RegisterBottomUpMutator("3", addVariantDepsMutator([]Variation{{"1", "d"}}, nil, "foo", "bar"))
-
-		run(ctx)
-
-		foo := ctx.moduleGroupFromName("foo", nil).moduleByVariantName("")
-		barBB := ctx.moduleGroupFromName("bar", nil).moduleByVariantName("b_b")
-
-		if g, w := foo.forwardDeps, []*moduleInfo{barBB}; !reflect.DeepEqual(g, w) {
-			t.Fatalf("expected foo deps to be %q, got %q", w, g)
-		}
-	})
-
-	t.Run("removed dangling alias", func(t *testing.T) {
-		// Creates a module "bar" with variants "a" and "b" and alias "c" -> "a", "d" -> "b", and "e" -> "a",
-		// then splits the variants into "a_a", "a_b", "b_a" and "b_b" without creating new aliases.
-		// Tests a dependency from "foo" to removed "bar" alias "d" fails.
-		ctx := NewContext()
-		ctx.RegisterModuleType("test", newModuleCtxTestModule)
-		ctx.RegisterBottomUpMutator("1", createAliasMutator("bar"))
-		ctx.RegisterBottomUpMutator("2", noAliasMutator("bar"))
-		ctx.RegisterBottomUpMutator("3", addVariantDepsMutator([]Variation{{"1", "d"}}, nil, "foo", "bar"))
-
-		runWithFailures(ctx, `dependency "bar" of "foo" missing variant:`+"\n  1:d\n"+
-			"available variants:"+
-			"\n  1:a,2:a\n  1:a,2:b\n  1:b,2:a\n  1:b,2:b")
-	})
-}
-
 func expectedErrors(t *testing.T, errs []error, expectedMessages ...string) {
 	t.Helper()
 	if len(errs) != len(expectedMessages) {
@@ -383,7 +113,7 @@ func TestAddVariationDependencies(t *testing.T) {
 		ctx.RegisterModuleType("test", newModuleCtxTestModule)
 		results := make(map[string][]Module)
 		depsMutator := addVariantDepsResultMutator(nil, nil, "foo", "bar", results)
-		ctx.RegisterBottomUpMutator("deps", depsMutator).Parallel()
+		ctx.RegisterBottomUpMutator("deps", depsMutator)
 
 		run(ctx)
 
@@ -399,32 +129,12 @@ func TestAddVariationDependencies(t *testing.T) {
 		}
 	})
 
-	t.Run("non-parallel", func(t *testing.T) {
-		ctx := NewContext()
-		ctx.RegisterModuleType("test", newModuleCtxTestModule)
-		results := make(map[string][]Module)
-		depsMutator := addVariantDepsResultMutator(nil, nil, "foo", "bar", results)
-		ctx.RegisterBottomUpMutator("deps", depsMutator)
-		run(ctx)
-
-		foo := ctx.moduleGroupFromName("foo", nil).moduleByVariantName("")
-		bar := ctx.moduleGroupFromName("bar", nil).moduleByVariantName("")
-
-		if g, w := foo.forwardDeps, []*moduleInfo{bar}; !reflect.DeepEqual(g, w) {
-			t.Fatalf("expected foo deps to be %q, got %q", w, g)
-		}
-
-		if g, w := results["foo"], []Module{nil}; !reflect.DeepEqual(g, w) {
-			t.Fatalf("expected AddVariationDependencies return value to be %q, got %q", w, g)
-		}
-	})
-
 	t.Run("missing", func(t *testing.T) {
 		ctx := NewContext()
 		ctx.RegisterModuleType("test", newModuleCtxTestModule)
 		results := make(map[string][]Module)
 		depsMutator := addVariantDepsResultMutator(nil, nil, "foo", "baz", results)
-		ctx.RegisterBottomUpMutator("deps", depsMutator).Parallel()
+		ctx.RegisterBottomUpMutator("deps", depsMutator)
 		runWithFailures(ctx, `"foo" depends on undefined module "baz"`)
 
 		foo := ctx.moduleGroupFromName("foo", nil).moduleByVariantName("")
@@ -444,7 +154,7 @@ func TestAddVariationDependencies(t *testing.T) {
 		ctx.RegisterModuleType("test", newModuleCtxTestModule)
 		results := make(map[string][]Module)
 		depsMutator := addVariantDepsResultMutator(nil, nil, "foo", "baz", results)
-		ctx.RegisterBottomUpMutator("deps", depsMutator).Parallel()
+		ctx.RegisterBottomUpMutator("deps", depsMutator)
 		run(ctx)
 
 		foo := ctx.moduleGroupFromName("foo", nil).moduleByVariantName("")
diff --git a/parser/ast.go b/parser/ast.go
index 67b6902..19e955b 100644
--- a/parser/ast.go
+++ b/parser/ast.go
@@ -227,6 +227,28 @@ func (t Type) String() string {
 	}
 }
 
+func ZeroExpression(t Type) Expression {
+	switch t {
+	case UnknownType:
+		panic(fmt.Errorf("cannot create zero expression for UnknownType"))
+	case BoolType:
+		return &Bool{}
+	case StringType:
+		return &String{}
+	case Int64Type:
+		return &Int64{}
+	case ListType:
+		return &List{}
+	case MapType:
+		return &Map{}
+	case UnsetType:
+		panic(fmt.Errorf("cannot create zero expression for UnsetType"))
+
+	default:
+		panic(fmt.Errorf("Unknown type %d", t))
+	}
+}
+
 type Operator struct {
 	Args        [2]Expression
 	Operator    rune
diff --git a/parser/parser.go b/parser/parser.go
index 8e5e543..8d36e53 100644
--- a/parser/parser.go
+++ b/parser/parser.go
@@ -607,8 +607,11 @@ func (p *parser) parseSelect() Expression {
 			hasNonUnsetValue = true
 			c.Value = p.parseExpression()
 		}
-		if !p.accept(',') {
-			return nil
+		// allow trailing comma, require it if not seeing a }
+		if p.tok != '}' {
+			if !p.accept(',') {
+				return nil
+			}
 		}
 		result.Cases = append(result.Cases, c)
 	}
diff --git a/parser/parser_test.go b/parser/parser_test.go
index b6a1246..b11c8de 100644
--- a/parser/parser_test.go
+++ b/parser/parser_test.go
@@ -16,6 +16,7 @@ package parser
 
 import (
 	"bytes"
+	"errors"
 	"reflect"
 	"strconv"
 	"strings"
@@ -838,6 +839,25 @@ func TestParseValidInput(t *testing.T) {
 	}
 }
 
+func TestParseSelectWithoutTrailingComma(t *testing.T) {
+	r := bytes.NewBufferString(`
+	m {
+		foo: select(arch(), {
+			"arm64": true,
+			default: false
+		}),
+	}
+	`)
+	file, errs := ParseAndEval("", r, NewScope(nil))
+	if len(errs) != 0 {
+		t.Fatalf("%s", errors.Join(errs...).Error())
+	}
+	_, ok := file.Defs[0].(*Module).Properties[0].Value.(*Select)
+	if !ok {
+		t.Fatalf("did not parse to select")
+	}
+}
+
 func TestParserError(t *testing.T) {
 	testcases := []struct {
 		name  string
diff --git a/parser/printer.go b/parser/printer.go
index 349119f..e32ad72 100644
--- a/parser/printer.go
+++ b/parser/printer.go
@@ -139,16 +139,32 @@ func (p *printer) printExpression(value Expression) {
 }
 
 func (p *printer) printSelect(s *Select) {
+	print_append := func() {
+		if s.Append != nil {
+			p.requestSpace()
+			p.printToken("+", s.RBracePos)
+			p.requestSpace()
+			p.printExpression(s.Append)
+		}
+	}
 	if len(s.Cases) == 0 {
+		print_append()
 		return
 	}
 	if len(s.Cases) == 1 && len(s.Cases[0].Patterns) == 1 {
 		if str, ok := s.Cases[0].Patterns[0].Value.(*String); ok && str.Value == default_select_branch_name {
 			p.printExpression(s.Cases[0].Value)
 			p.pos = s.RBracePos
+			print_append()
 			return
 		}
 	}
+	if len(s.Cases) == 1 && len(s.Cases[0].Patterns) == 0 {
+		p.printExpression(s.Cases[0].Value)
+		p.pos = s.RBracePos
+		print_append()
+		return
+	}
 	p.requestSpace()
 	p.printToken("select(", s.KeywordPos)
 	multilineConditions := false
@@ -217,12 +233,7 @@ func (p *printer) printSelect(s *Select) {
 	p.requestNewline()
 	p.unindent(s.RBracePos)
 	p.printToken("})", s.RBracePos)
-	if s.Append != nil {
-		p.requestSpace()
-		p.printToken("+", s.RBracePos)
-		p.requestSpace()
-		p.printExpression(s.Append)
-	}
+	print_append()
 }
 
 func (p *printer) printSelectPattern(pat SelectPattern) {
diff --git a/parser/printer_test.go b/parser/printer_test.go
index 040c4b5..b838a7b 100644
--- a/parser/printer_test.go
+++ b/parser/printer_test.go
@@ -753,6 +753,36 @@ foo {
         any @ baz: "b" + baz,
     }),
 }
+`,
+	},
+	{
+		name: "Simplify select",
+		input: `
+foo {
+    stuff: select(arch(), {
+        default: "a",
+    }),
+}
+`,
+		output: `
+foo {
+    stuff: "a",
+}
+`,
+	},
+	{
+		name: "Simplify select with append",
+		input: `
+foo {
+    stuff: select(arch(), {
+        default: "a",
+    }) + "foo",
+}
+`,
+		output: `
+foo {
+    stuff: "a" + "foo",
+}
 `,
 	},
 }
diff --git a/proptools/configurable.go b/proptools/configurable.go
index e8cc7b7..a97328d 100644
--- a/proptools/configurable.go
+++ b/proptools/configurable.go
@@ -111,12 +111,24 @@ func (c *ConfigurableCondition) String() string {
 	return sb.String()
 }
 
+func (c *ConfigurableCondition) toParserConfigurableCondition() parser.ConfigurableCondition {
+	var args []parser.String
+	for _, arg := range c.args {
+		args = append(args, parser.String{Value: arg})
+	}
+	return parser.ConfigurableCondition{
+		FunctionName: c.functionName,
+		Args:         args,
+	}
+}
+
 type configurableValueType int
 
 const (
 	configurableValueTypeString configurableValueType = iota
 	configurableValueTypeBool
 	configurableValueTypeUndefined
+	configurableValueTypeStringList
 )
 
 func (v *configurableValueType) patternType() configurablePatternType {
@@ -125,6 +137,8 @@ func (v *configurableValueType) patternType() configurablePatternType {
 		return configurablePatternTypeString
 	case configurableValueTypeBool:
 		return configurablePatternTypeBool
+	case configurableValueTypeStringList:
+		return configurablePatternTypeStringList
 	default:
 		panic("unimplemented")
 	}
@@ -136,6 +150,8 @@ func (v *configurableValueType) String() string {
 		return "string"
 	case configurableValueTypeBool:
 		return "bool"
+	case configurableValueTypeStringList:
+		return "string_list"
 	case configurableValueTypeUndefined:
 		return "undefined"
 	default:
@@ -146,9 +162,10 @@ func (v *configurableValueType) String() string {
 // ConfigurableValue represents the value of a certain condition being selected on.
 // This type mostly exists to act as a sum type between string, bool, and undefined.
 type ConfigurableValue struct {
-	typ         configurableValueType
-	stringValue string
-	boolValue   bool
+	typ             configurableValueType
+	stringValue     string
+	boolValue       bool
+	stringListValue []string
 }
 
 func (c *ConfigurableValue) toExpression() parser.Expression {
@@ -157,6 +174,12 @@ func (c *ConfigurableValue) toExpression() parser.Expression {
 		return &parser.Bool{Value: c.boolValue}
 	case configurableValueTypeString:
 		return &parser.String{Value: c.stringValue}
+	case configurableValueTypeStringList:
+		result := &parser.List{}
+		for _, s := range c.stringListValue {
+			result.Values = append(result.Values, &parser.String{Value: s})
+		}
+		return result
 	default:
 		panic(fmt.Sprintf("Unhandled configurableValueType: %s", c.typ.String()))
 	}
@@ -193,6 +216,13 @@ func ConfigurableValueBool(b bool) ConfigurableValue {
 	}
 }
 
+func ConfigurableValueStringList(l []string) ConfigurableValue {
+	return ConfigurableValue{
+		typ:             configurableValueTypeStringList,
+		stringListValue: slices.Clone(l),
+	}
+}
+
 func ConfigurableValueUndefined() ConfigurableValue {
 	return ConfigurableValue{
 		typ: configurableValueTypeUndefined,
@@ -204,6 +234,7 @@ type configurablePatternType int
 const (
 	configurablePatternTypeString configurablePatternType = iota
 	configurablePatternTypeBool
+	configurablePatternTypeStringList
 	configurablePatternTypeDefault
 	configurablePatternTypeAny
 )
@@ -214,6 +245,8 @@ func (v *configurablePatternType) String() string {
 		return "string"
 	case configurablePatternTypeBool:
 		return "bool"
+	case configurablePatternTypeStringList:
+		return "string_list"
 	case configurablePatternTypeDefault:
 		return "default"
 	case configurablePatternTypeAny:
@@ -240,6 +273,33 @@ type ConfigurablePattern struct {
 	binding     string
 }
 
+func (c ConfigurablePattern) toParserSelectPattern() parser.SelectPattern {
+	switch c.typ {
+	case configurablePatternTypeString:
+		return parser.SelectPattern{
+			Value:   &parser.String{Value: c.stringValue},
+			Binding: parser.Variable{Name: c.binding},
+		}
+	case configurablePatternTypeBool:
+		return parser.SelectPattern{
+			Value:   &parser.Bool{Value: c.boolValue},
+			Binding: parser.Variable{Name: c.binding},
+		}
+	case configurablePatternTypeDefault:
+		return parser.SelectPattern{
+			Value:   &parser.String{Value: "__soong_conditions_default__"},
+			Binding: parser.Variable{Name: c.binding},
+		}
+	case configurablePatternTypeAny:
+		return parser.SelectPattern{
+			Value:   &parser.String{Value: "__soong_conditions_any__"},
+			Binding: parser.Variable{Name: c.binding},
+		}
+	default:
+		panic(fmt.Sprintf("unknown type %d", c.typ))
+	}
+}
+
 func NewStringConfigurablePattern(s string) ConfigurablePattern {
 	return ConfigurablePattern{
 		typ:         configurablePatternTypeString,
@@ -307,6 +367,17 @@ type ConfigurableCase[T ConfigurableElements] struct {
 	value    parser.Expression
 }
 
+func (c *ConfigurableCase[T]) toParserConfigurableCase() *parser.SelectCase {
+	var patterns []parser.SelectPattern
+	for _, p := range c.patterns {
+		patterns = append(patterns, p.toParserSelectPattern())
+	}
+	return &parser.SelectCase{
+		Patterns: patterns,
+		Value:    c.value,
+	}
+}
+
 type configurableCaseReflection interface {
 	initialize(patterns []ConfigurablePattern, value parser.Expression)
 }
@@ -838,6 +909,7 @@ type configurableReflection interface {
 	clone() any
 	isEmpty() bool
 	printfInto(value string) error
+	toExpression() (*parser.Expression, error)
 }
 
 // Same as configurableReflection, but since initialize needs to take a pointer
@@ -886,6 +958,39 @@ func (c Configurable[T]) setAppend(append any, replace bool, prepend bool) {
 	}
 }
 
+func (c Configurable[T]) toExpression() (*parser.Expression, error) {
+	var err error
+	var result *parser.Select
+	var tail *parser.Select
+	for curr := c.inner; curr != nil; curr = curr.next {
+		if curr.replace == true {
+			return nil, fmt.Errorf("Cannot turn a configurable property with replacements into an expression; " +
+				"replacements can only be created via soong code / defaults squashing, not simply in a bp file")
+		}
+		if curr.single.isEmpty() {
+			continue
+		}
+		if result == nil {
+			result, err = curr.single.toExpression()
+			if err != nil {
+				return nil, err
+			}
+			tail = result
+		} else {
+			tail.Append, err = curr.single.toExpression()
+			if err != nil {
+				return nil, err
+			}
+			tail = tail.Append.(*parser.Select)
+		}
+	}
+	if result == nil {
+		return nil, nil
+	}
+	var result2 parser.Expression = result
+	return &result2, nil
+}
+
 func appendPostprocessors[T ConfigurableElements](a, b [][]postProcessor[T], newBase int) [][]postProcessor[T] {
 	var result [][]postProcessor[T]
 	for i := 0; i < len(a); i++ {
@@ -989,6 +1094,25 @@ func (c *singleConfigurable[T]) printfInto(value string) error {
 	return nil
 }
 
+func (c *singleConfigurable[T]) toExpression() (*parser.Select, error) {
+	if c.scope != nil {
+		return nil, fmt.Errorf("Cannot turn a select with a scope back into an expression")
+	}
+	var conditions []parser.ConfigurableCondition
+	for _, cond := range c.conditions {
+		conditions = append(conditions, cond.toParserConfigurableCondition())
+	}
+	var cases []*parser.SelectCase
+	for _, case_ := range c.cases {
+		cases = append(cases, case_.toParserConfigurableCase())
+	}
+	result := &parser.Select{
+		Conditions: conditions,
+		Cases:      cases,
+	}
+	return result, nil
+}
+
 func (c Configurable[T]) clone() any {
 	var newPostProcessors *[][]postProcessor[T]
 	if c.postProcessors != nil {
diff --git a/proptools/repack.go b/proptools/repack.go
new file mode 100644
index 0000000..6775ad5
--- /dev/null
+++ b/proptools/repack.go
@@ -0,0 +1,248 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package proptools
+
+import (
+	"fmt"
+	"reflect"
+	"slices"
+
+	"github.com/google/blueprint/parser"
+)
+
+func RepackProperties(props []interface{}) (*parser.Map, error) {
+
+	var dereferencedProps []reflect.Value
+	for _, rawProp := range props {
+		propStruct := reflect.ValueOf(rawProp)
+		if !isStructPtr(propStruct.Type()) {
+			return nil, fmt.Errorf("properties must be *struct, got %s",
+				propStruct.Type())
+		}
+		propStruct = propStruct.Elem()
+		dereferencedProps = append(dereferencedProps, propStruct)
+	}
+
+	return repackStructs(dereferencedProps)
+}
+
+func repackStructs(props []reflect.Value) (*parser.Map, error) {
+	var allFieldNames []string
+	for _, prop := range props {
+		propType := prop.Type()
+		for i := 0; i < propType.NumField(); i++ {
+			field := propType.Field(i)
+			if !slices.Contains(allFieldNames, field.Name) {
+				allFieldNames = append(allFieldNames, field.Name)
+			}
+		}
+	}
+
+	result := &parser.Map{}
+
+	for _, fieldName := range allFieldNames {
+		var fields []reflect.Value
+		for _, prop := range props {
+			field := prop.FieldByName(fieldName)
+			if field.IsValid() {
+				fields = append(fields, field)
+			}
+		}
+		if err := assertFieldsEquivalent(fields); err != nil {
+			return nil, err
+		}
+
+		var expr parser.Expression
+		var field reflect.Value
+		for _, f := range fields {
+			if !isPropEmpty(f) {
+				field = f
+				break
+			}
+		}
+		if !field.IsValid() {
+			continue
+		}
+		if isStruct(field.Type()) && !isConfigurable(field.Type()) {
+			x, err := repackStructs(fields)
+			if err != nil {
+				return nil, err
+			}
+			if x != nil {
+				expr = x
+			}
+		} else {
+			x, err := fieldToExpr(field)
+			if err != nil {
+				return nil, err
+			}
+			if x != nil {
+				expr = *x
+			}
+		}
+
+		if expr != nil {
+			result.Properties = append(result.Properties, &parser.Property{
+				Name:  PropertyNameForField(fieldName),
+				Value: expr,
+			})
+		}
+	}
+
+	return result, nil
+}
+
+func fieldToExpr(field reflect.Value) (*parser.Expression, error) {
+	if IsConfigurable(field.Type()) {
+		return field.Interface().(configurableReflection).toExpression()
+	}
+	if field.Kind() == reflect.Pointer {
+		if field.IsNil() {
+			return nil, nil
+		}
+		field = field.Elem()
+	}
+	switch field.Kind() {
+	case reflect.String:
+		var result parser.Expression = &parser.String{Value: field.String()}
+		return &result, nil
+	case reflect.Bool:
+		var result parser.Expression = &parser.Bool{Value: field.Bool()}
+		return &result, nil
+	case reflect.Int, reflect.Int64:
+		var result parser.Expression = &parser.Int64{Value: field.Int()}
+		return &result, nil
+	case reflect.Slice:
+		var contents []parser.Expression
+		for i := 0; i < field.Len(); i++ {
+			inner, err := fieldToExpr(field.Index(i))
+			if err != nil {
+				return nil, err
+			}
+			contents = append(contents, *inner)
+		}
+		var result parser.Expression = &parser.List{Values: contents}
+		return &result, nil
+	case reflect.Struct:
+		var properties []*parser.Property
+		typ := field.Type()
+		for i := 0; i < typ.NumField(); i++ {
+			inner, err := fieldToExpr(field.Field(i))
+			if err != nil {
+				return nil, err
+			}
+			properties = append(properties, &parser.Property{
+				Name:  typ.Field(i).Name,
+				Value: *inner,
+			})
+		}
+		var result parser.Expression = &parser.Map{Properties: properties}
+		return &result, nil
+	default:
+		return nil, fmt.Errorf("Unhandled type: %s", field.Kind().String())
+	}
+}
+
+func isPropEmpty(value reflect.Value) bool {
+	switch value.Kind() {
+	case reflect.Pointer:
+		if value.IsNil() {
+			return true
+		}
+		return isPropEmpty(value.Elem())
+	case reflect.Struct:
+		if isConfigurable(value.Type()) {
+			return value.Interface().(configurableReflection).isEmpty()
+		}
+		for i := 0; i < value.NumField(); i++ {
+			if !isPropEmpty(value.Field(i)) {
+				return false
+			}
+		}
+		return true
+	default:
+		return false
+	}
+}
+
+func assertFieldsEquivalent(fields []reflect.Value) error {
+	var firstNonEmpty reflect.Value
+	var firstIndex int
+	for i, f := range fields {
+		if !isPropEmpty(f) {
+			firstNonEmpty = f
+			firstIndex = i
+			break
+		}
+	}
+	if !firstNonEmpty.IsValid() {
+		return nil
+	}
+	for i, f := range fields {
+		if i != firstIndex && !isPropEmpty(f) {
+			if err := assertTwoNonEmptyFieldsEquivalent(firstNonEmpty, f); err != nil {
+				return err
+			}
+		}
+	}
+	return nil
+}
+
+func assertTwoNonEmptyFieldsEquivalent(a, b reflect.Value) error {
+	aType := a.Type()
+	bType := b.Type()
+
+	if aType != bType {
+		return fmt.Errorf("fields must have the same type")
+	}
+
+	switch aType.Kind() {
+	case reflect.Pointer:
+		return assertTwoNonEmptyFieldsEquivalent(a.Elem(), b.Elem())
+	case reflect.String:
+		if a.String() != b.String() {
+			return fmt.Errorf("Conflicting fields in property structs had values %q and %q", a.String(), b.String())
+		}
+	case reflect.Bool:
+		if a.Bool() != b.Bool() {
+			return fmt.Errorf("Conflicting fields in property structs had values %t and %t", a.Bool(), b.Bool())
+		}
+	case reflect.Slice:
+		if a.Len() != b.Len() {
+			return fmt.Errorf("Conflicting fields in property structs had lengths %d and %d", a.Len(), b.Len())
+		}
+		for i := 0; i < a.Len(); i++ {
+			if err := assertTwoNonEmptyFieldsEquivalent(a.Index(i), b.Index(i)); err != nil {
+				return err
+			}
+		}
+	case reflect.Int:
+		if a.Int() != b.Int() {
+			return fmt.Errorf("Conflicting fields in property structs had values %d and %d", a.Int(), b.Int())
+		}
+	case reflect.Struct:
+		if isConfigurable(a.Type()) {
+			// We could properly check that two configurables are equivalent, but that's a lot more
+			// work for a case that I don't think should show up in practice.
+			return fmt.Errorf("Cannot handle two property structs with nonempty configurable properties")
+		}
+		// We don't care about checking if structs are equivalent, we'll check their individual
+		// fields when we recurse down.
+	default:
+		return fmt.Errorf("Unhandled kind: %s", aType.Kind().String())
+	}
+
+	return nil
+}
diff --git a/proptools/repack_test.go b/proptools/repack_test.go
new file mode 100644
index 0000000..2f1c1e1
--- /dev/null
+++ b/proptools/repack_test.go
@@ -0,0 +1,247 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package proptools
+
+import (
+	"regexp"
+	"strings"
+	"testing"
+
+	"github.com/google/blueprint/parser"
+)
+
+type testSymlinkStruct struct {
+	Target string
+	Name   string
+}
+
+type testPropStructNested struct {
+	My_string_ptr *string
+}
+
+type testPropStruct struct {
+	My_string                   string
+	My_configurable_string      Configurable[string]
+	My_configurable_string_list Configurable[[]string]
+	My_string_ptr               *string
+	My_string_list              []string
+	My_struct_list              []testSymlinkStruct
+	My_bool                     bool
+	My_int                      int
+	My_int64                    int64
+	Nested                      testPropStructNested
+}
+
+type testPropStructOnlyConfigurableStringList struct {
+	My_configurable_string_list Configurable[[]string]
+}
+
+func TestRepack(t *testing.T) {
+	testCases := []struct {
+		name        string
+		propStructs []interface{}
+		expectedBp  string
+		expectedErr string
+	}{
+		{
+			name: "Simple prop struct",
+			propStructs: []interface{}{&testPropStruct{
+				My_string:                   "foo",
+				My_configurable_string:      NewSimpleConfigurable("qux"),
+				My_configurable_string_list: NewSimpleConfigurable([]string{"a", "b", "c"}),
+				My_string_ptr:               StringPtr("bar"),
+				My_string_list:              []string{"foo", "bar"},
+				My_struct_list: []testSymlinkStruct{
+					{Name: "foo", Target: "foo_target"},
+					{Name: "bar", Target: "bar_target"},
+				},
+				My_bool:  true,
+				My_int:   5,
+				My_int64: 64,
+				Nested: testPropStructNested{
+					My_string_ptr: StringPtr("baz"),
+				},
+			}},
+			expectedBp: `
+module {
+    my_string: "foo",
+    my_configurable_string: "qux",
+    my_configurable_string_list: [
+        "a",
+        "b",
+        "c",
+    ],
+    my_string_ptr: "bar",
+    my_string_list: [
+        "foo",
+        "bar",
+    ],
+    my_struct_list: [
+        {
+            Target: "foo_target",
+            Name: "foo",
+        },
+        {
+            Target: "bar_target",
+            Name: "bar",
+        },
+    ],
+    my_bool: true,
+    my_int: 5,
+    my_int64: 64,
+    nested: {
+        my_string_ptr: "baz",
+    },
+}`,
+		},
+		{
+			name: "Complicated select",
+			propStructs: []interface{}{&testPropStructOnlyConfigurableStringList{
+				My_configurable_string_list: createComplicatedSelect(),
+			}},
+			expectedBp: `
+module {
+    my_configurable_string_list: ["a"] + select((os(), arch()), {
+        ("android", "x86"): [
+            "android",
+            "x86",
+        ],
+        ("android", "arm64"): [
+            "android",
+            "arm64",
+        ],
+        (default, "x86"): [
+            "default",
+            "x86",
+        ],
+        (default, default): [
+            "default",
+            "default",
+        ],
+    }) + ["b"],
+}`,
+		},
+		{
+			name: "Multiple property structs",
+			propStructs: []interface{}{
+				&testPropStruct{
+					My_string:      "foo",
+					My_string_ptr:  nil,
+					My_string_list: []string{"foo", "bar"},
+					My_bool:        true,
+					My_int:         5,
+				},
+				&testPropStructNested{
+					My_string_ptr: StringPtr("bar"),
+				},
+			},
+			expectedBp: `
+module {
+    my_string: "foo",
+    my_string_ptr: "bar",
+    my_string_list: [
+        "foo",
+        "bar",
+    ],
+    my_struct_list: [],
+    my_bool: true,
+    my_int: 5,
+    my_int64: 0,
+}`,
+		},
+		{
+			name: "Multiple conflicting property structs",
+			propStructs: []interface{}{
+				&testPropStruct{
+					My_string:      "foo",
+					My_string_ptr:  StringPtr("foo"),
+					My_string_list: []string{"foo", "bar"},
+					My_bool:        true,
+					My_int:         5,
+				},
+				&testPropStructNested{
+					My_string_ptr: StringPtr("bar"),
+				},
+			},
+			expectedErr: `Conflicting fields in property structs had values "foo" and "bar"`,
+		},
+	}
+
+	for _, tc := range testCases {
+		t.Run(tc.name, func(t *testing.T) {
+			result, err := RepackProperties(tc.propStructs)
+			if err != nil {
+				if tc.expectedErr != "" {
+					match, err2 := regexp.MatchString(tc.expectedErr, err.Error())
+					if err2 != nil {
+						t.Fatal(err2)
+					}
+					if !match {
+						t.Fatalf("Expected error matching %q, found %q", tc.expectedErr, err.Error())
+					}
+					return
+				} else {
+					t.Fatal(err)
+				}
+			} else if tc.expectedErr != "" {
+				t.Fatalf("Expected error matching %q, but got success", tc.expectedErr)
+			}
+			file := &parser.File{
+				Defs: []parser.Definition{
+					&parser.Module{
+						Type: "module",
+						Map:  *result,
+					},
+				},
+			}
+			bytes, err := parser.Print(file)
+			if err != nil {
+				t.Fatal(err)
+			}
+			expected := strings.TrimSpace(tc.expectedBp)
+			actual := strings.TrimSpace(string(bytes))
+			if expected != actual {
+				t.Fatalf("Expected:\n%s\nBut found:\n%s\n", expected, actual)
+			}
+		})
+	}
+}
+
+func createComplicatedSelect() Configurable[[]string] {
+	result := NewSimpleConfigurable([]string{"a"})
+	result.Append(NewConfigurable([]ConfigurableCondition{
+		NewConfigurableCondition("os", nil),
+		NewConfigurableCondition("arch", nil),
+	}, []ConfigurableCase[[]string]{
+		NewConfigurableCase([]ConfigurablePattern{
+			NewStringConfigurablePattern("android"),
+			NewStringConfigurablePattern("x86"),
+		}, &[]string{"android", "x86"}),
+		NewConfigurableCase([]ConfigurablePattern{
+			NewStringConfigurablePattern("android"),
+			NewStringConfigurablePattern("arm64"),
+		}, &[]string{"android", "arm64"}),
+		NewConfigurableCase([]ConfigurablePattern{
+			NewDefaultConfigurablePattern(),
+			NewStringConfigurablePattern("x86"),
+		}, &[]string{"default", "x86"}),
+		NewConfigurableCase([]ConfigurablePattern{
+			NewDefaultConfigurablePattern(),
+			NewDefaultConfigurablePattern(),
+		}, &[]string{"default", "default"}),
+	}))
+	result.Append(NewSimpleConfigurable([]string{"b"}))
+	return result
+}
diff --git a/provider.go b/provider.go
index 5873d10..8f9120d 100644
--- a/provider.go
+++ b/provider.go
@@ -15,11 +15,10 @@
 package blueprint
 
 import (
-	"bytes"
 	"encoding/gob"
-	"errors"
 	"fmt"
 
+	"github.com/google/blueprint/gobtools"
 	"github.com/google/blueprint/proptools"
 )
 
@@ -56,26 +55,32 @@ type providerKey struct {
 	mutator string
 }
 
-func (m *providerKey) GobEncode() ([]byte, error) {
-	w := new(bytes.Buffer)
-	encoder := gob.NewEncoder(w)
-	err := errors.Join(encoder.Encode(m.id), encoder.Encode(m.typ), encoder.Encode(m.mutator))
-	if err != nil {
-		return nil, err
+type providerKeyGob struct {
+	Id      int
+	Typ     string
+	Mutator string
+}
+
+func (m *providerKey) ToGob() *providerKeyGob {
+	return &providerKeyGob{
+		Id:      m.id,
+		Typ:     m.typ,
+		Mutator: m.mutator,
 	}
+}
 
-	return w.Bytes(), nil
+func (m *providerKey) FromGob(data *providerKeyGob) {
+	m.id = data.Id
+	m.typ = data.Typ
+	m.mutator = data.Mutator
 }
 
-func (m *providerKey) GobDecode(data []byte) error {
-	r := bytes.NewBuffer(data)
-	decoder := gob.NewDecoder(r)
-	err := errors.Join(decoder.Decode(&m.id), decoder.Decode(&m.typ), decoder.Decode(&m.mutator))
-	if err != nil {
-		return err
-	}
+func (m *providerKey) GobEncode() ([]byte, error) {
+	return gobtools.CustomGobEncode[providerKeyGob](m)
+}
 
-	return nil
+func (m *providerKey) GobDecode(data []byte) error {
+	return gobtools.CustomGobDecode[providerKeyGob](data, m)
 }
 
 func (p *providerKey) provider() *providerKey { return p }
@@ -181,16 +186,14 @@ func (c *Context) setProvider(m *moduleInfo, provider *providerKey, value any) {
 
 	m.providers[provider.id] = value
 
-	if c.verifyProvidersAreUnchanged {
-		if m.providerInitialValueHashes == nil {
-			m.providerInitialValueHashes = make([]uint64, len(providerRegistry))
-		}
-		hash, err := proptools.CalculateHash(value)
-		if err != nil {
-			panic(fmt.Sprintf("Can't set value of provider %s: %s", provider.typ, err.Error()))
-		}
-		m.providerInitialValueHashes[provider.id] = hash
+	if m.providerInitialValueHashes == nil {
+		m.providerInitialValueHashes = make([]uint64, len(providerRegistry))
+	}
+	hash, err := proptools.CalculateHash(value)
+	if err != nil {
+		panic(fmt.Sprintf("Can't set value of provider %s: %s", provider.typ, err.Error()))
 	}
+	m.providerInitialValueHashes[provider.id] = hash
 }
 
 // provider returns the value, if any, for a given provider for a module.  Verifies that it is
@@ -223,35 +226,21 @@ func (c *Context) provider(m *moduleInfo, provider *providerKey) (any, bool) {
 }
 
 func (c *Context) mutatorFinishedForModule(mutator *mutatorInfo, m *moduleInfo) bool {
-	if c.finishedMutators[mutator] {
+	if c.finishedMutators[mutator.index] {
 		// mutator pass finished for all modules
 		return true
 	}
 
-	if c.startedMutator == mutator {
-		// mutator pass started, check if it is finished for this module
-		return m.finishedMutator == mutator
-	}
-
-	// mutator pass hasn't started
-	return false
+	return m.finishedMutator >= mutator.index
 }
 
 func (c *Context) mutatorStartedForModule(mutator *mutatorInfo, m *moduleInfo) bool {
-	if c.finishedMutators[mutator] {
+	if c.finishedMutators[mutator.index] {
 		// mutator pass finished for all modules
 		return true
 	}
 
-	if c.startedMutator == mutator {
-		// mutator pass is currently running
-		if m.startedMutator == mutator {
-			// mutator has started for this module
-			return true
-		}
-	}
-
-	return false
+	return m.startedMutator >= mutator.index
 }
 
 // OtherModuleProviderContext is a helper interface that is a subset of ModuleContext, BottomUpMutatorContext, or
diff --git a/singleton_ctx.go b/singleton_ctx.go
index ab44108..91db313 100644
--- a/singleton_ctx.go
+++ b/singleton_ctx.go
@@ -99,6 +99,9 @@ type SingletonContext interface {
 	// VisitAllModules calls visit for each defined variant of each module in an unspecified order.
 	VisitAllModules(visit func(Module))
 
+	// VisitAllModuleProxies calls visit for each defined variant of each module in an unspecified order.
+	VisitAllModuleProxies(visit func(proxy ModuleProxy))
+
 	// VisitAllModules calls pred for each defined variant of each module in an unspecified order, and if pred returns
 	// true calls visit.
 	VisitAllModulesIf(pred func(Module) bool, visit func(Module))
@@ -134,13 +137,16 @@ type SingletonContext interface {
 	// VisitAllModuleVariants calls visit for each variant of the given module.
 	VisitAllModuleVariants(module Module, visit func(Module))
 
+	// VisitAllModuleVariantProxies calls visit for each variant of the given module.
+	VisitAllModuleVariantProxies(module Module, visit func(proxy ModuleProxy))
+
 	// PrimaryModule returns the first variant of the given module.  This can be used to perform
 	//	// singleton actions that are only done once for all variants of a module.
 	PrimaryModule(module Module) Module
 
-	// FinalModule returns the last variant of the given module.  This can be used to perform
+	// IsFinalModule returns if the given module is the last variant. This can be used to perform
 	// singleton actions that are only done once for all variants of a module.
-	FinalModule(module Module) Module
+	IsFinalModule(module Module) bool
 
 	// AddNinjaFileDeps adds dependencies on the specified files to the rule that creates the ninja manifest.  The
 	// primary builder will be rerun whenever the specified files are modified.
@@ -191,23 +197,23 @@ func (s *singletonContext) Name() string {
 }
 
 func (s *singletonContext) ModuleName(logicModule Module) string {
-	return s.context.ModuleName(logicModule)
+	return s.context.ModuleName(getWrappedModule(logicModule))
 }
 
 func (s *singletonContext) ModuleDir(logicModule Module) string {
-	return s.context.ModuleDir(logicModule)
+	return s.context.ModuleDir(getWrappedModule(logicModule))
 }
 
 func (s *singletonContext) ModuleSubDir(logicModule Module) string {
-	return s.context.ModuleSubDir(logicModule)
+	return s.context.ModuleSubDir(getWrappedModule(logicModule))
 }
 
 func (s *singletonContext) ModuleType(logicModule Module) string {
-	return s.context.ModuleType(logicModule)
+	return s.context.ModuleType(getWrappedModule(logicModule))
 }
 
 func (s *singletonContext) ModuleProvider(logicModule Module, provider AnyProviderKey) (any, bool) {
-	return s.context.ModuleProvider(logicModule, provider)
+	return s.context.ModuleProvider(getWrappedModule(logicModule), provider)
 }
 
 func (s *singletonContext) BlueprintFile(logicModule Module) string {
@@ -331,6 +337,10 @@ func (s *singletonContext) VisitAllModules(visit func(Module)) {
 	})
 }
 
+func (s *singletonContext) VisitAllModuleProxies(visit func(proxy ModuleProxy)) {
+	s.VisitAllModules(visitProxyAdaptor(visit))
+}
+
 func (s *singletonContext) VisitAllModulesIf(pred func(Module) bool,
 	visit func(Module)) {
 
@@ -361,14 +371,18 @@ func (s *singletonContext) PrimaryModule(module Module) Module {
 	return s.context.PrimaryModule(module)
 }
 
-func (s *singletonContext) FinalModule(module Module) Module {
-	return s.context.FinalModule(module)
+func (s *singletonContext) IsFinalModule(module Module) bool {
+	return s.context.IsFinalModule(module)
 }
 
 func (s *singletonContext) VisitAllModuleVariants(module Module, visit func(Module)) {
 	s.context.VisitAllModuleVariants(module, visit)
 }
 
+func (s *singletonContext) VisitAllModuleVariantProxies(module Module, visit func(proxy ModuleProxy)) {
+	s.context.VisitAllModuleVariants(module, visitProxyAdaptor(visit))
+}
+
 func (s *singletonContext) AddNinjaFileDeps(deps ...string) {
 	s.ninjaFileDeps = append(s.ninjaFileDeps, deps...)
 }
@@ -396,11 +410,8 @@ func (s *singletonContext) ModuleVariantsFromName(referer Module, name string) [
 		return nil
 	}
 	result := make([]Module, 0, len(moduleGroup.modules))
-	for _, module := range moduleGroup.modules {
-		moduleInfo := module.module()
-		if moduleInfo != nil {
-			result = append(result, moduleInfo.logicModule)
-		}
+	for _, moduleInfo := range moduleGroup.modules {
+		result = append(result, moduleInfo.logicModule)
 	}
 	return result
 }
@@ -408,3 +419,11 @@ func (s *singletonContext) ModuleVariantsFromName(referer Module, name string) [
 func (s *singletonContext) HasMutatorFinished(mutatorName string) bool {
 	return s.context.HasMutatorFinished(mutatorName)
 }
+
+func visitProxyAdaptor(visit func(proxy ModuleProxy)) func(module Module) {
+	return func(module Module) {
+		visit(ModuleProxy{
+			module: module,
+		})
+	}
+}
diff --git a/splice_modules_test.go b/splice_modules_test.go
index 473999a..e48247e 100644
--- a/splice_modules_test.go
+++ b/splice_modules_test.go
@@ -29,82 +29,82 @@ var (
 )
 
 var spliceModulesTestCases = []struct {
-	in         modulesOrAliases
+	in         moduleList
 	at         int
-	with       modulesOrAliases
-	out        modulesOrAliases
+	with       moduleList
+	out        moduleList
 	outAt      int
 	reallocate bool
 }{
 	{
 		// Insert at the beginning
-		in:         modulesOrAliases{testModuleA, testModuleB, testModuleC},
+		in:         moduleList{testModuleA, testModuleB, testModuleC},
 		at:         0,
-		with:       modulesOrAliases{testModuleD, testModuleE},
-		out:        modulesOrAliases{testModuleD, testModuleE, testModuleB, testModuleC},
+		with:       moduleList{testModuleD, testModuleE},
+		out:        moduleList{testModuleD, testModuleE, testModuleB, testModuleC},
 		outAt:      1,
 		reallocate: true,
 	},
 	{
 		// Insert in the middle
-		in:         modulesOrAliases{testModuleA, testModuleB, testModuleC},
+		in:         moduleList{testModuleA, testModuleB, testModuleC},
 		at:         1,
-		with:       modulesOrAliases{testModuleD, testModuleE},
-		out:        modulesOrAliases{testModuleA, testModuleD, testModuleE, testModuleC},
+		with:       moduleList{testModuleD, testModuleE},
+		out:        moduleList{testModuleA, testModuleD, testModuleE, testModuleC},
 		outAt:      2,
 		reallocate: true,
 	},
 	{
 		// Insert at the end
-		in:         modulesOrAliases{testModuleA, testModuleB, testModuleC},
+		in:         moduleList{testModuleA, testModuleB, testModuleC},
 		at:         2,
-		with:       modulesOrAliases{testModuleD, testModuleE},
-		out:        modulesOrAliases{testModuleA, testModuleB, testModuleD, testModuleE},
+		with:       moduleList{testModuleD, testModuleE},
+		out:        moduleList{testModuleA, testModuleB, testModuleD, testModuleE},
 		outAt:      3,
 		reallocate: true,
 	},
 	{
 		// Insert over a single element
-		in:         modulesOrAliases{testModuleA},
+		in:         moduleList{testModuleA},
 		at:         0,
-		with:       modulesOrAliases{testModuleD, testModuleE},
-		out:        modulesOrAliases{testModuleD, testModuleE},
+		with:       moduleList{testModuleD, testModuleE},
+		out:        moduleList{testModuleD, testModuleE},
 		outAt:      1,
 		reallocate: true,
 	},
 	{
 		// Insert at the beginning without reallocating
-		in:         modulesOrAliases{testModuleA, testModuleB, testModuleC, nil}[0:3],
+		in:         moduleList{testModuleA, testModuleB, testModuleC, nil}[0:3],
 		at:         0,
-		with:       modulesOrAliases{testModuleD, testModuleE},
-		out:        modulesOrAliases{testModuleD, testModuleE, testModuleB, testModuleC},
+		with:       moduleList{testModuleD, testModuleE},
+		out:        moduleList{testModuleD, testModuleE, testModuleB, testModuleC},
 		outAt:      1,
 		reallocate: false,
 	},
 	{
 		// Insert in the middle without reallocating
-		in:         modulesOrAliases{testModuleA, testModuleB, testModuleC, nil}[0:3],
+		in:         moduleList{testModuleA, testModuleB, testModuleC, nil}[0:3],
 		at:         1,
-		with:       modulesOrAliases{testModuleD, testModuleE},
-		out:        modulesOrAliases{testModuleA, testModuleD, testModuleE, testModuleC},
+		with:       moduleList{testModuleD, testModuleE},
+		out:        moduleList{testModuleA, testModuleD, testModuleE, testModuleC},
 		outAt:      2,
 		reallocate: false,
 	},
 	{
 		// Insert at the end without reallocating
-		in:         modulesOrAliases{testModuleA, testModuleB, testModuleC, nil}[0:3],
+		in:         moduleList{testModuleA, testModuleB, testModuleC, nil}[0:3],
 		at:         2,
-		with:       modulesOrAliases{testModuleD, testModuleE},
-		out:        modulesOrAliases{testModuleA, testModuleB, testModuleD, testModuleE},
+		with:       moduleList{testModuleD, testModuleE},
+		out:        moduleList{testModuleA, testModuleB, testModuleD, testModuleE},
 		outAt:      3,
 		reallocate: false,
 	},
 	{
 		// Insert over a single element without reallocating
-		in:         modulesOrAliases{testModuleA, nil}[0:1],
+		in:         moduleList{testModuleA, nil}[0:1],
 		at:         0,
-		with:       modulesOrAliases{testModuleD, testModuleE},
-		out:        modulesOrAliases{testModuleD, testModuleE},
+		with:       moduleList{testModuleD, testModuleE},
+		out:        moduleList{testModuleD, testModuleE},
 		outAt:      1,
 		reallocate: false,
 	},
@@ -112,7 +112,7 @@ var spliceModulesTestCases = []struct {
 
 func TestSpliceModules(t *testing.T) {
 	for _, testCase := range spliceModulesTestCases {
-		in := make(modulesOrAliases, len(testCase.in), cap(testCase.in))
+		in := make(moduleList, len(testCase.in), cap(testCase.in))
 		copy(in, testCase.in)
 		origIn := in
 		got, gotAt := spliceModules(in, testCase.at, testCase.with)
@@ -139,6 +139,6 @@ func TestSpliceModules(t *testing.T) {
 	}
 }
 
-func sameArray(a, b modulesOrAliases) bool {
+func sameArray(a, b moduleList) bool {
 	return &a[0:cap(a)][cap(a)-1] == &b[0:cap(b)][cap(b)-1]
 }
diff --git a/transition.go b/transition.go
index 595e9af..afd3661 100644
--- a/transition.go
+++ b/transition.go
@@ -125,6 +125,12 @@ type IncomingTransitionContext interface {
 	// mutator is running.  This should be used sparingly, all uses will have to be removed in order
 	// to support creating variants on demand.
 	IsAddingDependency() bool
+
+	// ModuleErrorf reports an error at the line number of the module type in the module definition.
+	ModuleErrorf(fmt string, args ...interface{})
+
+	// PropertyErrorf reports an error at the line number of a property in the module definition.
+	PropertyErrorf(property, fmt string, args ...interface{})
 }
 
 type OutgoingTransitionContext interface {
@@ -147,6 +153,12 @@ type OutgoingTransitionContext interface {
 	//
 	// This method shouldn't be used directly, prefer the type-safe android.ModuleProvider instead.
 	Provider(provider AnyProviderKey) (any, bool)
+
+	// ModuleErrorf reports an error at the line number of the module type in the module definition.
+	ModuleErrorf(fmt string, args ...interface{})
+
+	// PropertyErrorf reports an error at the line number of a property in the module definition.
+	PropertyErrorf(property, fmt string, args ...interface{})
 }
 
 type transitionMutatorImpl struct {
@@ -219,6 +231,7 @@ type transitionContextImpl struct {
 	depTag      DependencyTag
 	postMutator bool
 	config      interface{}
+	errs        []error
 }
 
 func (c *transitionContextImpl) DepTag() DependencyTag {
@@ -233,6 +246,20 @@ func (c *transitionContextImpl) IsAddingDependency() bool {
 	return c.postMutator
 }
 
+func (c *transitionContextImpl) error(err error) {
+	if err != nil {
+		c.errs = append(c.errs, err)
+	}
+}
+
+func (c *transitionContextImpl) ModuleErrorf(fmt string, args ...interface{}) {
+	c.error(c.context.moduleErrorf(c.dep, fmt, args...))
+}
+
+func (c *transitionContextImpl) PropertyErrorf(property, fmt string, args ...interface{}) {
+	c.error(c.context.PropertyErrorf(c.dep.logicModule, property, fmt, args...))
+}
+
 type outgoingTransitionContextImpl struct {
 	transitionContextImpl
 }
@@ -266,11 +293,19 @@ func (t *transitionMutatorImpl) transition(mctx BaseModuleContext) Transition {
 			depTag:  depTag,
 			config:  mctx.Config(),
 		}
-		outgoingVariation := t.mutator.OutgoingTransition(&outgoingTransitionContextImpl{tc}, sourceVariation)
+		outCtx := &outgoingTransitionContextImpl{tc}
+		outgoingVariation := t.mutator.OutgoingTransition(outCtx, sourceVariation)
+		for _, err := range outCtx.errs {
+			mctx.error(err)
+		}
 		if mctx.Failed() {
 			return outgoingVariation
 		}
-		finalVariation := t.mutator.IncomingTransition(&incomingTransitionContextImpl{tc}, outgoingVariation)
+		inCtx := &incomingTransitionContextImpl{tc}
+		finalVariation := t.mutator.IncomingTransition(inCtx, outgoingVariation)
+		for _, err := range inCtx.errs {
+			mctx.error(err)
+		}
 		return finalVariation
 	}
 }
@@ -306,12 +341,32 @@ func (t *transitionMutatorImpl) mutateMutator(mctx BottomUpMutatorContext) {
 	t.mutator.Mutate(mctx, currentVariation)
 }
 
-func (c *Context) RegisterTransitionMutator(name string, mutator TransitionMutator) {
+type TransitionMutatorHandle interface {
+	// NeverFar causes the variations created by this mutator to never be ignored when adding
+	// far variation dependencies. Normally, far variation dependencies ignore all the variants
+	// of the source module, and only use the variants explicitly requested by the
+	// AddFarVariationDependencies call.
+	NeverFar() TransitionMutatorHandle
+}
+
+type transitionMutatorHandle struct {
+	inner MutatorHandle
+}
+
+var _ TransitionMutatorHandle = (*transitionMutatorHandle)(nil)
+
+func (h *transitionMutatorHandle) NeverFar() TransitionMutatorHandle {
+	h.inner.setNeverFar()
+	return h
+}
+
+func (c *Context) RegisterTransitionMutator(name string, mutator TransitionMutator) TransitionMutatorHandle {
 	impl := &transitionMutatorImpl{name: name, mutator: mutator}
 
-	c.RegisterTopDownMutator(name+"_propagate", impl.topDownMutator).Parallel()
-	c.RegisterBottomUpMutator(name, impl.bottomUpMutator).Parallel().setTransitionMutator(impl)
-	c.RegisterBottomUpMutator(name+"_mutate", impl.mutateMutator).Parallel()
+	c.RegisterTopDownMutator(name+"_propagate", impl.topDownMutator)
+	bottomUpHandle := c.RegisterBottomUpMutator(name, impl.bottomUpMutator).setTransitionMutator(impl)
+	c.RegisterBottomUpMutator(name+"_mutate", impl.mutateMutator)
+	return &transitionMutatorHandle{inner: bottomUpHandle}
 }
 
 // This function is called for every dependency edge to determine which
diff --git a/transition_test.go b/transition_test.go
index e2d0222..c84c288 100644
--- a/transition_test.go
+++ b/transition_test.go
@@ -16,22 +16,31 @@ package blueprint
 
 import (
 	"fmt"
+	"regexp"
 	"slices"
 	"strings"
 	"testing"
 )
 
-func testTransition(bp string) (*Context, []error) {
+func testTransitionCommon(bp string, neverFar bool, ctxHook func(*Context)) (*Context, []error) {
 	ctx := newContext()
 	ctx.MockFileSystem(map[string][]byte{
 		"Android.bp": []byte(bp),
 	})
 
 	ctx.RegisterBottomUpMutator("deps", depsMutator)
-	ctx.RegisterTransitionMutator("transition", transitionTestMutator{})
-	ctx.RegisterBottomUpMutator("post_transition_deps", postTransitionDepsMutator)
+	handle := ctx.RegisterTransitionMutator("transition", transitionTestMutator{})
+	if neverFar {
+		handle.NeverFar()
+	}
+	ctx.RegisterBottomUpMutator("post_transition_deps", postTransitionDepsMutator).UsesReverseDependencies()
 
 	ctx.RegisterModuleType("transition_module", newTransitionModule)
+
+	if ctxHook != nil {
+		ctxHook(ctx)
+	}
+
 	_, errs := ctx.ParseBlueprintsFiles("Android.bp", nil)
 	if len(errs) > 0 {
 		return nil, errs
@@ -45,6 +54,20 @@ func testTransition(bp string) (*Context, []error) {
 	return ctx, nil
 }
 
+func testTransition(bp string) (*Context, []error) {
+	return testTransitionCommon(bp, false, nil)
+}
+
+func testTransitionNeverFar(bp string) (*Context, []error) {
+	return testTransitionCommon(bp, true, nil)
+}
+
+func testTransitionAllowMissingDeps(bp string) (*Context, []error) {
+	return testTransitionCommon(bp, false, func(ctx *Context) {
+		ctx.SetAllowMissingDependencies(true)
+	})
+}
+
 func assertNoErrors(t *testing.T, errs []error) {
 	t.Helper()
 	if len(errs) > 0 {
@@ -56,6 +79,25 @@ func assertNoErrors(t *testing.T, errs []error) {
 	}
 }
 
+func assertOneErrorMatches(t *testing.T, errs []error, re string) {
+	t.Helper()
+	if len(errs) == 0 {
+		t.Fatalf("expected 1 error, but found 0")
+	}
+	if len(errs) > 1 {
+		t.Errorf("expected exactly 1 error, but found:")
+		for _, err := range errs {
+			t.Errorf("  %s", err)
+		}
+		t.FailNow()
+	}
+	if match, err := regexp.MatchString(re, errs[0].Error()); err != nil {
+		t.Fatal(err.Error())
+	} else if !match {
+		t.Fatalf("expected error matching %q, but got: %q", re, errs[0].Error())
+	}
+}
+
 const testTransitionBp = `
 			transition_module {
 			    name: "A",
@@ -104,7 +146,7 @@ const testTransitionBp = `
 
 func getTransitionModule(ctx *Context, name, variant string) *transitionModule {
 	group := ctx.moduleGroupFromName(name, nil)
-	module := group.moduleOrAliasByVariantName(variant).module()
+	module := group.moduleByVariantName(variant)
 	return module.logicModule.(*transitionModule)
 }
 
@@ -112,8 +154,8 @@ func checkTransitionVariants(t *testing.T, ctx *Context, name string, expectedVa
 	t.Helper()
 	group := ctx.moduleGroupFromName(name, nil)
 	var gotVariants []string
-	for _, variant := range group.modules {
-		gotVariants = append(gotVariants, variant.moduleOrAliasVariant().variations.get("transition"))
+	for _, module := range group.modules {
+		gotVariants = append(gotVariants, module.variant.variations.get("transition"))
 	}
 	if !slices.Equal(expectedVariants, gotVariants) {
 		t.Errorf("expected variants of %q to be %q, got %q", name, expectedVariants, gotVariants)
@@ -284,6 +326,156 @@ func TestPostTransitionReverseDeps(t *testing.T) {
 	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "B", "a2"))
 }
 
+func TestPostTransitionReverseVariationDeps(t *testing.T) {
+	ctx, errs := testTransition(`
+		transition_module {
+			name: "A",
+			split: ["a"],
+		}
+
+		transition_module {
+			name: "B",
+			split: ["b"],
+			post_transition_reverse_variation_deps: ["A(a)"],
+		}
+	`)
+	assertNoErrors(t, errs)
+
+	checkTransitionVariants(t, ctx, "A", []string{"a"})
+	checkTransitionVariants(t, ctx, "B", []string{"b"})
+
+	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "A", "a"), "B(b)")
+	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "B", "b"))
+}
+
+func TestFarVariationDep(t *testing.T) {
+	ctx, errs := testTransition(`
+		transition_module {
+			name: "A",
+			split: ["a"],
+			deps: ["B"],
+		}
+		transition_module {
+			name: "B",
+			split: ["", "a"],
+		}
+		transition_module {
+			name: "C",
+			split: ["c"],
+			post_transition_far_deps: ["D"],
+		}
+		transition_module {
+			name: "D",
+			split: ["", "c"],
+		}
+	`)
+	assertNoErrors(t, errs)
+
+	checkTransitionVariants(t, ctx, "A", []string{"a"})
+	checkTransitionVariants(t, ctx, "B", []string{"", "a"})
+	checkTransitionVariants(t, ctx, "C", []string{"c"})
+	checkTransitionVariants(t, ctx, "D", []string{"", "c"})
+
+	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "A", "a"), "B(a)")
+	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "C", "c"), "D()")
+}
+
+func TestNeverFarFarVariationDep(t *testing.T) {
+	ctx, errs := testTransitionNeverFar(`
+		transition_module {
+			name: "A",
+			split: ["a"],
+			deps: ["B"],
+		}
+		transition_module {
+			name: "B",
+			split: ["", "a"],
+		}
+		transition_module {
+			name: "C",
+			split: ["c"],
+			post_transition_far_deps: ["D"],
+		}
+		transition_module {
+			name: "D",
+			split: ["", "c"],
+		}
+	`)
+	assertNoErrors(t, errs)
+
+	checkTransitionVariants(t, ctx, "A", []string{"a"})
+	checkTransitionVariants(t, ctx, "B", []string{"", "a"})
+	checkTransitionVariants(t, ctx, "C", []string{"c"})
+	checkTransitionVariants(t, ctx, "D", []string{"", "c"})
+
+	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "A", "a"), "B(a)")
+	checkTransitionDeps(t, ctx, getTransitionModule(ctx, "C", "c"), "D(c)")
+}
+
+func TestPostTransitionReverseDepsErrorOnMissingDep(t *testing.T) {
+	_, errs := testTransition(`
+		transition_module {
+			name: "A",
+			split: ["a"],
+		}
+
+		transition_module {
+			name: "B",
+			split: ["b"],
+			post_transition_reverse_deps: ["A"],
+		}
+	`)
+	assertOneErrorMatches(t, errs, `reverse dependency "A" of "B" missing variant:\s*transition:b\s*available variants:\s*transition:a`)
+}
+
+func TestErrorInIncomingTransition(t *testing.T) {
+	_, errs := testTransition(`
+		transition_module {
+			name: "A",
+			split: ["a"],
+			deps: ["B"],
+		}
+		transition_module {
+			name: "B",
+			split: ["a"],
+			incoming_transition_error: "my incoming transition error",
+		}
+	`)
+	assertOneErrorMatches(t, errs, "my incoming transition error")
+}
+
+func TestErrorInOutgoingTransition(t *testing.T) {
+	_, errs := testTransition(`
+		transition_module {
+			name: "A",
+			split: ["a"],
+			deps: ["B"],
+			outgoing_transition_error: "my outgoing transition error",
+		}
+		transition_module {
+			name: "B",
+			split: ["a"],
+		}
+	`)
+	assertOneErrorMatches(t, errs, "my outgoing transition error")
+}
+
+func TestPostTransitionReverseDepsAllowMissingDeps(t *testing.T) {
+	_, errs := testTransitionAllowMissingDeps(`
+		transition_module {
+			name: "A",
+			split: ["a"],
+		}
+
+		transition_module {
+			name: "B",
+			split: ["b"],
+			post_transition_reverse_deps: ["A"],
+		}
+	`)
+	assertNoErrors(t, errs)
+}
+
 func TestPostTransitionDepsMissingVariant(t *testing.T) {
 	// TODO: eventually this will create the missing variant on demand
 	_, errs := testTransition(fmt.Sprintf(testTransitionBp,
@@ -339,6 +531,9 @@ func (transitionTestMutator) Split(ctx BaseModuleContext) []string {
 }
 
 func (transitionTestMutator) OutgoingTransition(ctx OutgoingTransitionContext, sourceVariation string) string {
+	if err := ctx.Module().(*transitionModule).properties.Outgoing_transition_error; err != nil {
+		ctx.ModuleErrorf("Error: %s", *err)
+	}
 	if outgoing := ctx.Module().(*transitionModule).properties.Outgoing; outgoing != nil {
 		return *outgoing
 	}
@@ -346,7 +541,9 @@ func (transitionTestMutator) OutgoingTransition(ctx OutgoingTransitionContext, s
 }
 
 func (transitionTestMutator) IncomingTransition(ctx IncomingTransitionContext, incomingVariation string) string {
-
+	if err := ctx.Module().(*transitionModule).properties.Incoming_transition_error; err != nil {
+		ctx.ModuleErrorf("Error: %s", *err)
+	}
 	if ctx.IsAddingDependency() {
 		if incoming := ctx.Module().(*transitionModule).properties.Post_transition_incoming; incoming != nil {
 			return *incoming
@@ -365,13 +562,17 @@ func (transitionTestMutator) Mutate(ctx BottomUpMutatorContext, variation string
 type transitionModule struct {
 	SimpleName
 	properties struct {
-		Deps                         []string
-		Post_transition_deps         []string
-		Post_transition_reverse_deps []string
-		Split                        []string
-		Outgoing                     *string
-		Incoming                     *string
-		Post_transition_incoming     *string
+		Deps                                   []string
+		Post_transition_deps                   []string
+		Post_transition_far_deps               []string
+		Post_transition_reverse_deps           []string
+		Post_transition_reverse_variation_deps []string
+		Split                                  []string
+		Outgoing                               *string
+		Incoming                               *string
+		Post_transition_incoming               *string
+		Outgoing_transition_error              *string
+		Incoming_transition_error              *string
 
 		Mutated string `blueprint:"mutated"`
 	}
@@ -393,6 +594,8 @@ func (f *transitionModule) IgnoreDeps() []string {
 	return nil
 }
 
+var nameAndVariantRegexp = regexp.MustCompile(`([a-zA-Z0-9_]+)\(([a-zA-Z0-9_]+)\)`)
+
 func postTransitionDepsMutator(mctx BottomUpMutatorContext) {
 	if m, ok := mctx.Module().(*transitionModule); ok {
 		for _, dep := range m.properties.Post_transition_deps {
@@ -403,8 +606,20 @@ func postTransitionDepsMutator(mctx BottomUpMutatorContext) {
 			}
 			mctx.AddVariationDependencies(variations, walkerDepsTag{follow: true}, module)
 		}
+		for _, dep := range m.properties.Post_transition_far_deps {
+			mctx.AddFarVariationDependencies(nil, walkerDepsTag{follow: true}, dep)
+		}
 		for _, dep := range m.properties.Post_transition_reverse_deps {
 			mctx.AddReverseDependency(m, walkerDepsTag{follow: true}, dep)
 		}
+		for _, dep := range m.properties.Post_transition_reverse_variation_deps {
+			match := nameAndVariantRegexp.FindStringSubmatch(dep)
+			if len(match) == 0 || match[0] != dep {
+				panic(fmt.Sprintf("Invalid Post_transition_reverse_variation_deps: %q. Expected module_name(variant)", dep))
+			}
+			mctx.AddReverseVariationDependency([]Variation{
+				{Mutator: "transition", Variation: match[2]},
+			}, walkerDepsTag{follow: true}, match[1])
+		}
 	}
 }
```

