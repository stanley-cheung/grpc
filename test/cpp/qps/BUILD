# Copyright 2017 gRPC authors.
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

load("//bazel:custom_exec_properties.bzl", "LARGE_MACHINE")
load("//bazel:grpc_build_system.bzl", "grpc_cc_binary", "grpc_cc_library", "grpc_cc_test", "grpc_package", "grpc_py_binary")
load("//test/cpp/qps:qps_benchmark_script.bzl", "json_run_localhost_batch", "qps_json_driver_batch")

licenses(["notice"])

grpc_package(name = "test/cpp/qps")

grpc_cc_library(
    name = "parse_json",
    srcs = ["parse_json.cc"],
    hdrs = ["parse_json.h"],
    external_deps = [
        "absl/log:check",
        "protobuf",
    ],
    deps = ["//:grpc++"],
)

grpc_cc_library(
    name = "qps_worker_impl",
    srcs = [
        "client_async.cc",
        "client_callback.cc",
        "client_sync.cc",
        "qps_server_builder.cc",
        "qps_worker.cc",
        "server_async.cc",
        "server_callback.cc",
        "server_sync.cc",
    ],
    hdrs = [
        "client.h",
        "qps_server_builder.h",
        "qps_worker.h",
        "server.h",
    ],
    external_deps = ["absl/log:check"],
    deps = [
        ":histogram",
        ":interarrival",
        ":usage_timer",
        "//:grpc",
        "//:grpc++",
        "//:grpcpp_latent_see_service",
        "//src/core:chaotic_good",
        "//src/core:endpoint_transport",
        "//src/proto/grpc/testing:benchmark_service_cc_grpc",
        "//src/proto/grpc/testing:control_cc_proto",
        "//src/proto/grpc/testing:payloads_cc_proto",
        "//src/proto/grpc/testing:worker_service_cc_grpc",
        "//test/core/end2end:ssl_test_data",
        "//test/core/test_util:grpc_test_util",
        "//test/cpp/util:test_config",
        "//test/cpp/util:test_util",
    ],
)

grpc_cc_library(
    name = "driver_impl",
    srcs = [
        "driver.cc",
        "report.cc",
    ],
    hdrs = [
        "driver.h",
        "report.h",
    ],
    external_deps = [
        "absl/log:check",
        "absl/log:log",
    ],
    deps = [
        ":histogram",
        ":parse_json",
        ":qps_worker_impl",
        "//:grpc++",
        "//:grpcpp_latent_see_client",
        "//src/proto/grpc/testing:control_cc_proto",
        "//src/proto/grpc/testing:messages_cc_proto",
        "//src/proto/grpc/testing:report_qps_scenario_service_cc_grpc",
        "//src/proto/grpc/testing:worker_service_cc_grpc",
        "//test/core/test_util:grpc_test_util",
        "//test/cpp/util:test_util",
    ],
)

grpc_cc_library(
    name = "benchmark_config",
    srcs = [
        "benchmark_config.cc",
    ],
    hdrs = [
        "benchmark_config.h",
    ],
    external_deps = [
        "absl/flags:flag",
        "absl/log:check",
    ],
    deps = [
        ":driver_impl",
        ":histogram",
        "//:grpc++",
        "//src/proto/grpc/testing:control_cc_proto",
    ],
)

grpc_cc_library(
    name = "histogram",
    hdrs = [
        "histogram.h",
        "stats.h",
    ],
    deps = [
        "//src/proto/grpc/testing:stats_cc_proto",
        "//test/core/test_util:grpc_test_util",
    ],
)

grpc_cc_binary(
    name = "qps_json_driver",
    srcs = ["qps_json_driver.cc"],
    external_deps = [
        "absl/flags:flag",
        "absl/log:check",
    ],
    deps = [
        ":benchmark_config",
        ":driver_impl",
        "//:grpc++",
        "//test/cpp/util:test_config",
        "//test/cpp/util:test_util",
    ],
)

grpc_cc_test(
    name = "inproc_sync_unary_ping_pong_test",
    srcs = ["inproc_sync_unary_ping_pong_test.cc"],
    deps = [
        ":benchmark_config",
        ":driver_impl",
        "//:grpc++",
        "//test/cpp/util:test_config",
        "//test/cpp/util:test_util",
    ],
)

grpc_cc_library(
    name = "interarrival",
    hdrs = ["interarrival.h"],
    deps = ["//:grpc++"],
)

qps_json_driver_batch()

json_run_localhost_batch()

grpc_cc_test(
    name = "qps_interarrival_test",
    srcs = ["qps_interarrival_test.cc"],
    uses_event_engine = False,
    uses_polling = False,
    deps = [
        ":histogram",
        ":interarrival",
        "//test/core/test_util:grpc_test_util_base",
        "//test/cpp/util:test_config",
    ],
)

grpc_cc_test(
    name = "qps_openloop_test",
    srcs = ["qps_openloop_test.cc"],
    exec_properties = LARGE_MACHINE,
    tags = ["no_windows"],  # LARGE_MACHINE is not configured for windows RBE
    deps = [
        ":benchmark_config",
        ":driver_impl",
        ":qps_worker_impl",
        "//test/cpp/util:test_config",
        "//test/cpp/util:test_util",
    ],
)

grpc_cc_test(
    name = "secure_sync_unary_ping_pong_test",
    srcs = ["secure_sync_unary_ping_pong_test.cc"],
    tags = ["grpc:no-internal-test"],
    deps = [
        ":benchmark_config",
        ":driver_impl",
        "//:grpc++",
        "//test/cpp/util:test_config",
        "//test/cpp/util:test_util",
    ],
)

grpc_cc_library(
    name = "usage_timer",
    srcs = ["usage_timer.cc"],
    hdrs = ["usage_timer.h"],
    deps = ["//:gpr"],
)

grpc_cc_binary(
    name = "qps_worker",
    srcs = ["worker.cc"],
    external_deps = [
        "absl/flags:flag",
    ],
    deps = [
        ":qps_worker_impl",
        "//:grpc++",
        "//test/core/test_util:grpc_test_util",
        "//test/cpp/util:test_config",
        "//test/cpp/util:test_util",
    ],
)

grpc_py_binary(
    name = "scenario_runner",
    testonly = True,
    srcs = ["scenario_runner.py"],
    data = ["scenario_runner_cc"],
    python_version = "PY3",
)

grpc_cc_binary(
    name = "scenario_runner_cc",
    srcs = ["scenario_runner.cc"],
    external_deps = [
        "absl/flags:flag",
    ],
    deps = [
        ":benchmark_config",
        ":driver_impl",
        "//:grpc++",
        "//test/core/test_util:grpc_test_util",
        "//test/cpp/util:test_config",
        "//test/cpp/util:test_util",
    ],
)
