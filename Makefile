CC_x64 := gcc
OPTIONS := -O3 -I include -w
STRIP := strip
OBJECTS := ptrace.o utils.o

daphne-x64: src/daphne.c $(OBJECTS)
	$(CC_x64) $^ -o dist/$@ $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$@

ptrace.o: src/ptrace.c
	$(CC_x64) -c $< $(OPTIONS)

utils.o: src/utils.c
	$(CC_x64) -c $< $(OPTIONS)

clean:
	rm -f $(OBJECTS) dist/*
