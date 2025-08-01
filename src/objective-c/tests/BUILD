# gRPC Bazel BUILD file.
#
# Copyright 2019 gRPC authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@build_bazel_rules_apple//apple:macos.bzl", "macos_unit_test")
load("@build_bazel_rules_apple//apple:resources.bzl", "apple_resource_bundle")
load("@build_bazel_rules_apple//apple:tvos.bzl", "tvos_application", "tvos_unit_test")
load("//bazel:grpc_build_system.bzl", "grpc_sh_test")
load(
    "//src/objective-c:grpc_objc_internal_library.bzl",
    "grpc_objc_ios_unit_test",
    "grpc_objc_testing_library",
    "local_objc_grpc_library",
    "proto_library_objc_wrapper",
)

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

exports_files(["LICENSE"])

proto_library_objc_wrapper(
    name = "messages_proto",
    srcs = ["RemoteTestClient/messages.proto"],
)

proto_library_objc_wrapper(
    name = "test_proto",
    srcs = ["RemoteTestClient/test.proto"],
    use_well_known_protos = True,
    deps = [":messages_proto"],
)

local_objc_grpc_library(
    name = "RemoteTest",
    srcs = ["RemoteTestClient/test.proto"],
    testing = True,
    use_well_known_protos = True,
    deps = [":test_proto"],
)

apple_resource_bundle(
    name = "TestCertificates",
    resources = ["TestCertificates.bundle/test-certificates.pem"],
)

# TestConfigs is added to each grpc_objc_testing_library's deps
grpc_objc_testing_library(
    name = "TestConfigs",
    srcs = glob([
        "Common/**/*.m",
    ]),
    hdrs = glob([
        "Common/**/*.h",
    ]) + ["version.h"],
    data = [":TestCertificates"],
    defines = [
        "DEBUG=1",
        "HOST_PORT_LOCALSSL=localhost:5051",
        "HOST_PORT_LOCAL=localhost:5050",
        "HOST_PORT_REMOTE=grpc-test.sandbox.googleapis.com",
    ],
)

objc_library(
    name = "host-lib",
    srcs = glob(["Hosts/ios-host/*.m"]),
    hdrs = glob(["Hosts/ios-host/*.h"]),
)

tvos_application(
    name = "tvos-host",
    bundle_id = "grpc.objc.tests.tvos-host",
    infoplists = ["Hosts/ios-host/Info.plist"],
    minimum_os_version = "13.0",
    deps = ["host-lib"],
)

grpc_objc_testing_library(
    name = "InteropTests-lib",
    srcs = ["InteropTests/InteropTests.m"],
    hdrs = ["InteropTests/InteropTests.h"],
    deps = [
        ":InteropTestsBlockCallbacks-lib",
    ],
)

grpc_objc_testing_library(
    name = "InteropTestsRemote-lib",
    srcs = ["InteropTests/InteropTestsRemote.m"],
    deps = [":InteropTests-lib"],
)

grpc_objc_testing_library(
    name = "InteropTestsBlockCallbacks-lib",
    srcs = ["InteropTests/InteropTestsBlockCallbacks.m"],
    hdrs = ["InteropTests/InteropTestsBlockCallbacks.h"],
)

grpc_objc_testing_library(
    name = "InteropTestsLocalSSL-lib",
    srcs = ["InteropTests/InteropTestsLocalSSL.m"],
    deps = [":InteropTests-lib"],
)

grpc_objc_testing_library(
    name = "InteropTestsLocalCleartext-lib",
    srcs = ["InteropTests/InteropTestsLocalCleartext.m"],
    deps = [":InteropTests-lib"],
)

grpc_objc_testing_library(
    name = "InteropTestsMultipleChannels-lib",
    srcs = ["InteropTests/InteropTestsMultipleChannels.m"],
    deps = [":InteropTests-lib"],
)

grpc_objc_testing_library(
    name = "RxLibraryUnitTests-lib",
    srcs = ["UnitTests/RxLibraryUnitTests.m"],
)

grpc_objc_testing_library(
    name = "GRPCClientTests-lib",
    srcs = ["UnitTests/GRPCClientTests.m"],
)

grpc_objc_testing_library(
    name = "GRPCBasicUnitTests-lib",
    srcs = ["UnitTests/GRPCCallOptionsTests.m"],
)

grpc_objc_testing_library(
    name = "APIv2Tests-lib",
    srcs = ["UnitTests/APIv2Tests.m"],
)

grpc_objc_testing_library(
    name = "ChannelPoolTest-lib",
    srcs = ["UnitTests/ChannelPoolTest.m"],
)

grpc_objc_testing_library(
    name = "ChannelTests-lib",
    srcs = ["UnitTests/ChannelTests.m"],
)

grpc_objc_testing_library(
    name = "NSErrorUnitTests-lib",
    srcs = ["UnitTests/NSErrorUnitTests.m"],
)

grpc_objc_testing_library(
    name = "MacStressTests-lib",
    srcs = glob([
        "MacTests/*.m",
    ]),
    hdrs = ["MacTests/StressTests.h"],
)

grpc_objc_testing_library(
    name = "UnitTests",
    deps = [
        ":APIv2Tests-lib",
        ":ChannelPoolTest-lib",
        ":ChannelTests-lib",
        ":GRPCBasicUnitTests-lib",
        ":GRPCClientTests-lib",
        ":NSErrorUnitTests-lib",
        ":RxLibraryUnitTests-lib",
    ],
)

grpc_objc_ios_unit_test(
    name = "InteropTestsLocalCleartext",
    deps = [
        ":InteropTestsLocalCleartext-lib",
    ],
)

grpc_objc_ios_unit_test(
    name = "InteropTestsLocalSSL",
    deps = [
        ":InteropTestsLocalSSL-lib",
    ],
)

grpc_objc_ios_unit_test(
    name = "InteropTestsRemote",
    deps = [
        ":InteropTestsRemote-lib",
    ],
)

macos_unit_test(
    name = "MacTests",
    minimum_os_version = "11.0",
    deps = [
        ":APIv2Tests-lib",
        ":InteropTestsLocalCleartext-lib",
        ":InteropTestsLocalSSL-lib",
        ":InteropTestsRemote-lib",
        ":MacStressTests-lib",
        ":NSErrorUnitTests-lib",
        ":RxLibraryUnitTests-lib",
    ],
)

grpc_objc_testing_library(
    name = "CFStreamTests-lib",
    srcs = glob(["CFStreamTests/*.mm"]),
    deps = [
        "//:gpr_platform",
        "//src/core:iomgr_port",
        "//test/core/test_util:grpc_test_util",
    ],
)

grpc_objc_ios_unit_test(
    name = "CFStreamTests",
    deps = [":CFStreamTests-lib"],
)

grpc_objc_testing_library(
    name = "EventEngineClientTests-lib",
    srcs = ["EventEngineTests/CFEventEngineClientTests.mm"],
    deps = [
        "//src/core:cf_event_engine",
        "//test/core/event_engine/test_suite/posix:oracle_event_engine_posix",
        "//test/core/event_engine/test_suite/tests:client",
    ],
)

grpc_objc_testing_library(
    name = "EventEngineServerTests-lib",
    srcs = ["EventEngineTests/CFEventEngineServerTests.mm"],
    deps = [
        "//src/core:cf_event_engine",
        "//test/core/event_engine/test_suite/posix:oracle_event_engine_posix",
        "//test/core/event_engine/test_suite/tests:server",
    ],
)

grpc_objc_testing_library(
    name = "EventEngineUnitTests-lib",
    srcs = ["EventEngineTests/CFEventEngineUnitTests.mm"],
    deps = [
        "//src/core:cf_event_engine",
        "//test/core/event_engine/cf:cf_engine_unit_test_lib",
        "//test/core/event_engine/test_suite/tests:dns",
        "//test/core/event_engine/test_suite/tests:timer",
    ],
)

grpc_objc_ios_unit_test(
    name = "EventEngineClientTests",
    deps = [":EventEngineClientTests-lib"],
)

grpc_objc_ios_unit_test(
    name = "EventEngineServerTests",
    deps = [":EventEngineServerTests-lib"],
)

grpc_objc_ios_unit_test(
    name = "EventEngineUnitTests",
    deps = [":EventEngineUnitTests-lib"],
)

# Note that bazel currently doesn't support running tvos_unit_test
# See https://github.com/bazelbuild/rules_apple/blob/8d841342c238457896cd7596cc29b2d06c9a75f0/apple/testing/default_runner/tvos_test_runner.template.sh
tvos_unit_test(
    name = "TvTests",
    minimum_os_version = "13.0",
    test_host = ":tvos-host",
    deps = [
        ":APIv2Tests-lib",
        ":InteropTestsLocalCleartext-lib",
        ":InteropTestsLocalSSL-lib",
        ":InteropTestsRemote-lib",
        ":NSErrorUnitTests-lib",
        ":RxLibraryUnitTests-lib",
    ],
)

# TvTests is not runnable with bazel, so the best we can do is to test
# that the testsuite builds correctly. This is achieved by having
# a dummy sh_test depend on :TvTests.
grpc_sh_test(
    name = "tvtests_build_test",
    srcs = [
        "tvtests_build_test.sh",
    ],
    data = [
        ":TvTests",
    ],
    uses_polling = False,
)

grpc_sh_test(
    name = "objc_codegen_plugin_test",
    srcs = ["PluginTest/plugin_test.sh"],
    data = [
        "//src/compiler:grpc_objective_c_plugin",
        "@bazel_tools//tools/bash/runfiles",
        "@com_google_protobuf//:protoc",
    ] + glob(["PluginTest/*.proto"]),
    env = {
        "RLOCATIONPATH_PROTOC": "$(rlocationpath @com_google_protobuf//:protoc)",
        "RLOCATIONPATH_PLUGIN": "$(rlocationpath //src/compiler:grpc_objective_c_plugin)",
    },
    uses_polling = False,
)

grpc_sh_test(
    name = "objc_codegen_plugin_option_test",
    srcs = ["PluginTest/plugin_option_test.sh"],
    data = [
        "//src/compiler:grpc_objective_c_plugin",
        "@bazel_tools//tools/bash/runfiles",
        "@com_google_protobuf//:protoc",
        "@com_google_protobuf//:well_known_type_protos",
    ] + glob(["RemoteTestClient/*.proto"]),
    env = {
        "RLOCATIONPATH_PROTOC": "$(rlocationpath @com_google_protobuf//:protoc)",
        "RLOCATIONPATH_PLUGIN": "$(rlocationpath //src/compiler:grpc_objective_c_plugin)",
    },
    uses_polling = False,
)
