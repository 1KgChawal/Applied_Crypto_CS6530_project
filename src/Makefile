CXX = clang++

CXXFLAGS = \
	-std=c++17 \
	-O3 

LDFLAGS = \
	-lgmp \
	-lgmpxx \
	-lcrypto

LIB_DIR = lib
BUILD_DIR = build

LIB_SOURCES = $(wildcard $(LIB_DIR)/*.cpp)
LIB_OBJECTS = $(patsubst $(LIB_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(LIB_SOURCES))

TARGETS = rsa_test iso_9796_2_test

all: $(TARGETS)
build_lib: $(LIB_OBJECTS)
re_build_lib: clean build_lib
re_build: clean all

$(TARGETS): %: %.cpp $(LIB_OBJECTS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/%.o: $(LIB_DIR)/%.cpp $(LIB_DIR)/%.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(TARGETS) $(BUILD_DIR) *.key *.pem

.PHONY: all clean build_lib re_build_lib re_build