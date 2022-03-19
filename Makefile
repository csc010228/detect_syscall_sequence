SRC=./src
INC=./include
OBJ=./obj
GRAMMER=./grammer

SOURCE=$(wildcard ${SRC}/*.cpp)
OBJECT=${OBJ}/lex.yy.o ${OBJ}/y.tab.o $(patsubst %.cpp,${OBJ}/%.o,$(notdir ${SOURCE}))
LEX_FILE=${GRAMMER}/sysseq.l
YACC_FILE=${GRAMMER}/sysseq.y

TARGET=dss

CC=g++
CFLAGS=-I${INC}

${TARGET}:${OBJECT}
	$(CC) -std=c++17 -O2 -lm -o $@ ${OBJECT}

${OBJ}/lex.yy.o ${OBJ}/y.tab.o:
	lex -o ${GRAMMER}/lex.yy.c ${LEX_FILE}
	yacc -o ${GRAMMER}/y.tab.c -d ${YACC_FILE}
	cp ${GRAMMER}/lex.yy.c ${GRAMMER}/lex.yy.cpp
	cp ${GRAMMER}/y.tab.c ${GRAMMER}/y.tab.cpp
	mv ${GRAMMER}/y.tab.h ${INC}/y.tab.h
	$(CC) -std=c++17 -O2 -lm $(CFLAGS) -c ${GRAMMER}/lex.yy.cpp ${GRAMMER}/y.tab.cpp
	mv lex.yy.o ${OBJ}/lex.yy.o
	mv y.tab.o ${OBJ}/y.tab.o

${OBJ}/%.o:${SRC}/%.cpp
	$(CC) -std=c++17 -O2 -lm $(CFLAGS) -o $@ -c $<

.PHONY:clean
clean:
	find $(OBJ) -name *.o -exec rm -rf {} \;
	rm -rf $(TARGET)