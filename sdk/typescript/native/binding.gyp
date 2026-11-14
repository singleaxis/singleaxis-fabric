# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
#
# For maintainers only (spec 055 §4.4): a local debug build of the Node-API lock module
# with node-gyp, e.g. `npx node-gyp rebuild --directory=native` from sdk/typescript.
# Nothing uses this file at install or startup. The shipped prebuilds are compiled by
# scripts/typescript/prebuild/compile.sh in pinned images, not by node-gyp.
#
# It lives in native/, not at the package root, on purpose: npm runs `node-gyp rebuild`
# on install for any package that has a binding.gyp at its root and no install script.
#
# GYP reads this file as a Python literal, which is why the repository's ruff hooks lint it.
{  # noqa: B018
    "targets": [
        {
            "target_name": "fabric_wire",
            "sources": ["fabric_wire.c", "fabric_wire_core.c"],
            "cflags": ["-std=c11", "-fvisibility=hidden", "-Wall", "-Wextra"],
            "conditions": [
                [
                    "OS=='linux'",
                    {
                        "ldflags": [
                            "-Wl,--version-script=<(module_root_dir)/exports.map",
                            "-Wl,-z,noexecstack",
                            "-Wl,-z,relro",
                            "-Wl,-z,now",
                        ]
                    },
                ],
                [
                    "OS=='mac'",
                    {
                        "xcode_settings": {
                            "MACOSX_DEPLOYMENT_TARGET": "13.0",
                            "GCC_C_LANGUAGE_STANDARD": "c11",
                            "GCC_SYMBOLS_PRIVATE_EXTERN": "YES",
                            "OTHER_LDFLAGS": [
                                "-Wl,-exported_symbols_list,<(module_root_dir)/exports.darwin.txt"
                            ],
                        }
                    },
                ],
            ],
        }
    ]
}
