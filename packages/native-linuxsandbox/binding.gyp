{
  "targets": [
    {
      "target_name": "linuxsandbox",
      "conditions": [
        ["OS=='linux'", {
          "sources": ["src/linuxsandbox.cc"],
          "include_dirs": ["<!@(node -p \"require('node-addon-api').include_dir\")"],
          "defines": ["NAPI_VERSION=8"],
          "cflags_cc": ["-fexceptions", "-std=c++17"],
          "ldflags": ["-Wl,-z,now"]
        }],
        ["OS!='linux'", {
          "sources": []
        }]
      ]
    },
    {
      "target_name": "linuxsandbox_launcher",
      "type": "executable",
      "conditions": [
        ["OS=='linux'", {
          "sources": ["src/launcher.cc"],
          "cflags_cc": ["-std=c++17", "-Wall", "-Wextra"],
          "ldflags": ["-Wl,-z,now"]
        }],
        ["OS!='linux'", {
          "sources": []
        }]
      ]
    }
  ]
}
