{
  "targets": [
    {
      "target_name": "winfs",
      "conditions": [
        ["OS=='win'", {
          "sources": ["src/winfs.cc"],
          "include_dirs": ["<!(node -p \"require('node-addon-api').include_dir\")"],
          "defines": ["NAPI_VERSION=8", "UNICODE", "_UNICODE"],
          "libraries": ["-ladvapi32.lib"],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1
            }
          }
        }],
        ["OS!='win'", {
          "sources": []
        }]
      ]
    }
  ]
}
