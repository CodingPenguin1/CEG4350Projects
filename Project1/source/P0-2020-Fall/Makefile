#  Makefile for P4: Mounting, Small to Large files;  CEG 433/633 P. Mateti

CURRENT_DIR = P0
PROJECT = P0

CFLAGS = -ggdb -Wall -Wextra -Wpedantic -ansi -pedantic -Wno-write-strings -Wno-parentheses -Wno-unused-parameter -Wno-maybe-uninitialized -std=gnu++11 -lpthread
CC = g++

.SUFFIXES: .cpp .o .C

.C.o:
	$(CC) $(CFLAGS) -c $<

.cpp.o:
	$(CC) $(CFLAGS) -c $<


OBJFILES = simdisk.o bitvector.o directory.o file.o \
  inodes.o volume.o mount.o shell.o

$(PROJECT): $(OBJFILES)
	g++ -o $(PROJECT) $(CFLAGS) $(OBJFILES)

test:   $(PROJECT)
	rm -fr D?.bin
	./$(PROJECT)

$(OBJFILES): fs33types.hpp

indent:
	indent -kr -i2 -pmt *.C *.H *.hpp

tar archive: clean
	(cd ..; tar cvvfj $(PROJECT)-`date +%G%m%d%H%M`.tbz $(CURRENT_DIR))

clean:
	rm -fr core* *.o *~ *.out $(PROJECT) D?.??? lslisa*  *.f33 \\#*


# -eof-
