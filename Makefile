# Build flags come from gnustep-config so they work on any GNUstep platform
# (OpenBSD with pkg_add gnustep-make gnustep-base libobjc2, or Linux).
CC      = cc
CFLAGS  = $(shell gnustep-config --objc-flags) -Isrc
LDFLAGS = $(shell gnustep-config --base-libs)

TARGET      = request_validator
SRCS        = src/main.m src/RequestValidator.m

TEST_TARGET = test_validator
TEST_SRCS   = tests/test_validator.m src/RequestValidator.m

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_SRCS)
	$(CC) $(CFLAGS) -o $(TEST_TARGET) $(TEST_SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TEST_TARGET) *.d

install:
	install -m 0755 $(TARGET) /var/www/cgi-bin/request_validator

.PHONY: all test clean install
