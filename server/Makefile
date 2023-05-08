OUTFILE = "KeyListener.so"
# -static-libstdc++
COMPILE_FLAGS = -m32 -fpermissive -c -O3 -w -idirafter "../common"
LINK_FLAGS = -m32 -fpermissive -shared -O3

all:
	gcc $(COMPILE_FLAGS) pawn/amx/*.h
	g++ $(COMPILE_FLAGS) -std=c++17 pawn/*.cpp
	g++ $(COMPILE_FLAGS) -std=c++17 raknet/*.cpp
	g++ $(COMPILE_FLAGS) -std=c++17 *.cpp
	g++ $(LINK_FLAGS) -o $(OUTFILE) *.o
	rm *.o
	strip -s $(OUTFILE)
