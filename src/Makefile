BOFNAME := self_delete
CC_x64 := x86_64-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip

all:
	$(CC_x64) -Wno-unused-variable -o ../dist/$(BOFNAME).x64.o -c $(BOFNAME).c -masm=intel

clean:
	rm -f ../dist/$(BOFNAME).x64.o
