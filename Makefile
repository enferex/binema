APP = binema
CC = gcc
CFLAGS = -g3 -O0 -Wall #-DDEBUG
SOURCES = main.c
OBJS = $(SOURCES:.c=.o)
LIBS = -ldl -lz -lbfd -lopcodes -liberty

%.o: %.c
	$(CC) -c $^ $(CFLAGS)

$(APP): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(EXTRA_CFLAGS) $(LIBS)

.PHONY: test
test: $(APP) test.c
	$(CC) -o $@ test.c -g3 -O0
	./$(APP) ./$@

clean:
	$(RM) $(APP) $(OBJS) test
