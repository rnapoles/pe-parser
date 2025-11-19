CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LDFLAGS = 

# Detect OS
ifeq ($(OS),Windows_NT)
    TARGET_EXT = .exe
    RM = del /Q
else
    TARGET_EXT = 
    RM = rm -f
endif

TARGET = peparser$(TARGET_EXT)
TEST_TARGET = unit_tests$(TARGET_EXT)
INTEGRATION_TARGET = integration_tests$(TARGET_EXT)

SRCS = main.cpp PeParser.cpp
OBJS = $(SRCS:.cpp=.o)

TEST_SRCS = unit_tests.cpp PeParser.cpp
TEST_OBJS = $(TEST_SRCS:.cpp=.o)

INTEGRATION_SRCS = integration_tests.cpp PeParser.cpp
INTEGRATION_OBJS = $(INTEGRATION_SRCS:.cpp=.o)

.PHONY: all clean test test-integration test-all debug release

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^

$(TEST_TARGET): $(TEST_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^

$(INTEGRATION_TARGET): $(INTEGRATION_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

test-integration: $(INTEGRATION_TARGET)
	./$(INTEGRATION_TARGET)

test-all: test test-integration

clean:
	$(RM) $(TARGET) $(TEST_TARGET) $(INTEGRATION_TARGET) *.o

debug: CXXFLAGS += -g -DDEBUG
debug: all

release: CXXFLAGS += -O2 -DNDEBUG
release: all

