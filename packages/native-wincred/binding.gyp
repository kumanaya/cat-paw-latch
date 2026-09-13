{
  "targets": [
    {
      "target_name": "wincred",
      "conditions": [
        ["OS=='win'", {
          "sources": ["src/wincred.cc"],
          "include_dirs": ["<!(node -p \"require('node-addon-api').include_dir\")"],
          "defines": ["NAPI_VERSION=8", "UNICODE", "_UNICODE"],
          "libraries": ["-lcrypt32.lib", "-ladvapi32.lib"],
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
