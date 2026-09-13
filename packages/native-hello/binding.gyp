{
  "targets": [
    {
      "target_name": "winhello",
      "conditions": [
        ["OS=='win'", {
          "sources": ["src/hello.cc"],
          "include_dirs": ["<!(node -p \"require('node-addon-api').include_dir\")"],
          "defines": ["NAPI_VERSION=8", "UNICODE", "_UNICODE"],
          "libraries": ["-lwindowsapp.lib", "-lruntimeobject.lib", "-lcredui.lib", "-ladvapi32.lib", "-lole32.lib"],
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
