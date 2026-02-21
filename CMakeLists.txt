set(KERNEL_OUTPUT_DIR "${OUTPUT_DIR}/WindowsParser")

include_directories(include)

add_library(WindowsParser STATIC
        src/parse.c
)

set_target_properties(WindowsParser PROPERTIES LINKER_FLAGS
        rcs
)

install(TARGETS WindowsParser DESTINATION "${KERNEL_OUTPUT_DIR}")
