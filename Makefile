SRC_PATH = src
BUILD_PATH = build
COMPILER = gcc
FILE_TYPE = .c
IS_COS_COMPILATION ?=


ifeq (${IS_COS_COMPILATION}, 1)
	SRC =\
		${SRC_PATH}/main.c\
		${SRC_PATH}/args.c\
		${SRC_PATH}/parse.c\
		${SRC_PATH}/read.c
else
	SRC =\
		${SRC_PATH}/main.c\
		${SRC_PATH}/args.c\
		${SRC_PATH}/read.c\
		${SRC_PATH}/debug.c
endif

INCLUDE =\
	-I./include/\
	-I../include/\

OBJ = ${SRC:${SRC_PATH}/%${FILE_TYPE}=${BUILD_PATH}/%.o}
OBJ_FLAGS = -W -Wall -Wextra -Werror ${INCLUDE} -m64 -mcmodel=large -mlarge-data-threshold=2147483647 -ffreestanding -mno-red-zone -nostdlib -g3 -Wall -Wextra -z noexecstack -z max-page-size=0x1000 -fPIC  -pedantic -pedantic-errors
BIN_FLAGS =
BIN_NAME = winparse
LIB_NAME = libwindowsparser.a

ifeq (${IS_COS_COMPILATION}, 1)
	OBJ_FLAGS += -D IS_COS_COMPILATION=1
endif

all: ${BIN_NAME}
lib: ${LIB_NAME}

debug: OBJ_FLAGS += -DDEBUG -g3
debug: ${BIN_NAME}

${BUILD_PATH}/%.o: ${SRC_PATH}/%${FILE_TYPE}
	mkdir -p ${dir $@}
	${COMPILER} -MD ${OBJ_FLAGS} -c $< -o $@

${BIN_NAME}: ${OBJ}
	${COMPILER} -o ${BIN_NAME} ${OBJ} ${BIN_FLAGS}

${LIB_NAME} : ${OBJ}
	ar rcs ${LIB_NAME} ${OBJ}

clean:
	rm -rf ${BUILD_PATH}

fclean: clean
	rm -rf ${BIN_NAME}
	rm -rf ${LIB_NAME}

-include ${OBJ:%.o=%.d}

.PHONY: all clean fclean
