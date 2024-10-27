.PHONY: all clean run

C = gcc
CXXFLAGS = -std=c99 -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

TARGET = server
SRC = ./src/server.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(C) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
