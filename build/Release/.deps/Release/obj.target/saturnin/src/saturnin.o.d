cmd_Release/obj.target/saturnin/src/saturnin.o := cc -o Release/obj.target/saturnin/src/saturnin.o ../src/saturnin.c '-DNODE_GYP_MODULE_NAME=saturnin' '-DUSING_UV_SHARED=1' '-DUSING_V8_SHARED=1' '-DV8_DEPRECATION_WARNINGS=1' '-DV8_DEPRECATION_WARNINGS' '-DV8_IMMINENT_DEPRECATION_WARNINGS' '-D_GLIBCXX_USE_CXX11_ABI=1' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DNAPI_CPP_EXCEPTIONS' '-DBUILDING_NODE_EXTENSION' -I/home/sneh/.cache/node-gyp/18.20.4/include/node -I/home/sneh/.cache/node-gyp/18.20.4/src -I/home/sneh/.cache/node-gyp/18.20.4/deps/openssl/config -I/home/sneh/.cache/node-gyp/18.20.4/deps/openssl/openssl/include -I/home/sneh/.cache/node-gyp/18.20.4/deps/uv/include -I/home/sneh/.cache/node-gyp/18.20.4/deps/zlib -I/home/sneh/.cache/node-gyp/18.20.4/deps/v8/include -I/home/sneh/Desktop/post-quantum-communication/Saturnin-node/node_modules/node-addon-api -I../node_modules/node-addon-api -I../src  -fPIC -pthread -Wall -Wextra -Wno-unused-parameter -fPIC -m64 -O3 -fno-omit-frame-pointer  -MMD -MF ./Release/.deps/Release/obj.target/saturnin/src/saturnin.o.d.raw   -c
Release/obj.target/saturnin/src/saturnin.o: ../src/saturnin.c \
 ../src/saturnin.h ../src/aead-common.h ../src/internal-saturnin.h \
 ../src/internal-util.h
../src/saturnin.c:
../src/saturnin.h:
../src/aead-common.h:
../src/internal-saturnin.h:
../src/internal-util.h:
