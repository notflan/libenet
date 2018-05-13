SOURCE:= src/*.c
SOURCE_TEST:= src/test/*.c
INCLUDE:= include
VERSION:=`cat VERSION`
CFLAGS:=  -Wall -pedantic -D__VERSION=$(VERSION)
LFLAGS:= -lcrypto -lenet -lz -lm -lpthread
OBJ:= obj
BUILD:= build
TEST_OUTPUT:= ./test-out

all: clean libenet test

clean:
	rm -f $(OBJ)/*.o
	rm -f $(BUILD)/*
	rm -f $(TEST_OUTPUT)/*

libenet:
	gcc -c $(SOURCE) -I$(INCLUDE)/ $(CFLAGS) -fpic
	mv *.o $(OBJ)/
	gcc -shared -o $(BUILD)/$@-$(VERSION).so $(OBJ)/*.o
	ar rvs $(BUILD)/$@-$(VERSION).a $(OBJ)/*.o
	ln -sf `pwd`/$(BUILD)/$@-$(VERSION).so $(BUILD)/$@.so
	
test:
	gcc $(SOURCE_TEST) -I$(INCLUDE)/ $(CFLAGS) -o $(BUILD)/$@ -L$(BUILD)/ $(LFLAGS)
	LD_LIBRARY_PATH=$(BUILD)/ $(BUILD)/$@
	mv cli_*.txt $(TEST_OUTPUT)/
	mv srv_*.txt $(TEST_OUTPUT)/

install:
	cp $(BUILD)/libenet-$(VERSION).a /usr/local/lib/
	cp $(BUILD)/libenet-$(VERSION).so /usr/local/lib/
	cp $(INCLUDE)/*.h /usr/local/include
	ln -sf /usr/local/lib/libenet-$(VERSION).so /usr/lib/libenet.so
	ln -sf /usr/local/include/enet.h /usr/include/enet.h

uninstall:
	rm -f /usr/local/lib/libenet*
	rm /usr/local/include/enet.h
	
	rm -f /usr/lib/libenet*.so
	rm /usr/include/enet.h
	
