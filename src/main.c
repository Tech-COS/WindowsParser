////////////////////////
//
//  Created: Fri Jun 21 2024
//  File: main.c
//
////////////////////////

#include <stdlib.h>
#include "args.h"
#include "parse.h"

int main(int argc, char **argv)
{
    if (!check_args(argc, argv))
        return EXIT_FAILURE;
    parse_binary(argv[1]);
    return EXIT_SUCCESS;
}
