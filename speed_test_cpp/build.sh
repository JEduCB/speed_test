#cc -g -Iinclude -fPIC -shared src/engine_loader.c -o bin/engine_loader.so
cc -g -Iinclude -fPIC -shared src/speed_test_lib.c -o bin/speed_test_lib.so
#g++ -g -Iinclude src/speed_test.cpp -o bin/speed_test -Wl,-rpath='$ORIGIN' -Lbin -l:speed_test_lib.so -l:engine_loader.so -L/lib/x86_64-linux-gnu -l:libssl.so -l:libcrypto.so
g++ -g -Iinclude src/speed_test.cpp -o bin/speed_test -Wl,-rpath='$ORIGIN' -Lbin -l:speed_test_lib.so -L/lib/x86_64-linux-gnu -l:libssl.so -l:libcrypto.so
