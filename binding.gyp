{
  "targets": [
    {
      "target_name": "saturnin",
      "sources": [
        "src/original.cc",
        "src/saturnin.c",
        "src/internal-saturnin.c",
        "src/aead-common.c"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "<!(node -p \"require('node-addon-api').include_dir\")",
        "src"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "cflags": [ "-fPIC" ],
      "cflags_cc": [ "-fPIC", "-std=c++14" ],
      "xcode_settings": {
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "10.7"
      },
      "msvs_settings": {
        "VCCLCompilerTool": { "ExceptionHandling": 1 }
      },
      "defines": [ 
        "NAPI_CPP_EXCEPTIONS"
      ]
    }
  ]
}