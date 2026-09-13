{
  "targets": [
    {
      "target_name": "winsandbox",
      "conditions": [
        ["OS=='win'", {
          "sources": ["src/winsandbox.cc"],
          "include_dirs": ["<!(node -p \"require('node-addon-api').include_dir\")"],
          "defines": ["NAPI_VERSION=8", "UNICODE", "_UNICODE"],
          "libraries": ["-luserenv.lib"],
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
    },
    {
      "target_name": "winsandbox_launcher",
      "type": "executable",
      "conditions": [
        ["OS=='win'", {
          "sources": ["src/launcher.cc"],
          "defines": ["UNICODE", "_UNICODE"],
          "libraries": ["-luserenv.lib", "-ladvapi32.lib", "-laclui.lib", "-lOneCoreUAP.lib"],
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
