APP = binema
CC = gcc
CFLAGS = -g3 -O0 -Wall -DUSE_IGRAPH -ligraph #-DDEBUG 
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
	strip $@
	./$(APP) -f ./$@ -d -s

debug: $(APP)
	gdb --args ./$(APP) -f ./test -d -s

clean:
	$(RM) $(APP) $(OBJS) test
