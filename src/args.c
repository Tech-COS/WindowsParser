////////////////////////
//
//  Created: Mon Jun 24 2024
//  File: args.c
//
////////////////////////

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>

bool check_args(int argc, char **argv)
{
    if (argc != 2) {
        printf("Invalid number of arguments. Only one argument is required.\n");
        return false;
    }

    if (access(argv[1], F_OK)) {
        printf("%s, file not found\n", argv[1]);
        return false;
    }
    return true;
}
