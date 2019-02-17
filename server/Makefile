OUTFILE = "KeyListener.so"
# -static-libstdc++
COMPILE_FLAGS = -m32 -fpermissive -c -O3 -w -idirafter "sdk"
LINK_FLAGS = -m32 -fpermissive -shared -O3

all:
	gcc $(COMPILE_FLAGS) sdk/pawn/amx/*.h
	g++ $(COMPILE_FLAGS) -std=c++14 sdk/pawn/*.cpp
	g++ $(COMPILE_FLAGS) -std=c++14 sdk/raknet/*.cpp
	g++ $(COMPILE_FLAGS) -std=c++14 *.cpp
	g++ $(LINK_FLAGS) -o $(OUTFILE) *.o
	rm *.o
	strip -s $(OUTFILE)
