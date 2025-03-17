LIBS = -lpcap

TARGET = send_arp
SRCS = main.c
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(SRCS) -o $(TARGET) $(LIBS)

clean:
	rm -f $(OBJS) $(TARGET)