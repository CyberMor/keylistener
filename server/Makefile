OUTFILE = "../binaries/KeyListener.so"

COMMON_FLAGS = -D _GLIBCXX_USE_CXX11_ABI=0 -m32 -O3 -Ofast -fPIC -w -DNDEBUG -fpermissive
COMPILE_FLAGS = $(COMMON_FLAGS) -c -idirafter "../common"
PRELINK_FLAGS = $(COMMON_FLAGS) -shared -static-libgcc -static-libstdc++

all:
	mkdir -p ../binaries
	gcc $(COMPILE_FLAGS) pawn/amx/*.h
	g++ $(COMPILE_FLAGS) -std=c++11 pawn/*.cpp
	g++ $(COMPILE_FLAGS) -std=c++11 raknet/*.cpp
	g++ $(COMPILE_FLAGS) -std=c++17 *.cpp
	g++ $(PRELINK_FLAGS) -o $(OUTFILE) *.o
	rm *.o
	strip -s $(OUTFILE)