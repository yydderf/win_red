CC=g++
CCFLAGS=-g -std=c++20 -Wall -lws2_32 -lwsock32

target: keylogger.cpp
	$(CC) keylogger.cpp -o keylogger $(CCFLAGS)

clean:
	del /f keylogger