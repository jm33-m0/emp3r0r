/*
EDB Note: poc-suidbin.c
*/

/*
 * poc-suidbin.c for CVE-2018-14634
 * Copyright (C) 2018 Qualys, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define die()                                                    \
    do {                                                         \
        fprintf(stderr, "died in %s: %u\n", __func__, __LINE__); \
        exit(EXIT_FAILURE);                                      \
    } while (0)

int main(const int argc, const char* const* const argv, const char* const* const envp)
{
    printf("argc %d\n", argc);

    char stack = '\0';
    printf("stack %p < %p < %p < %p < %p\n", &stack, argv, envp, *argv, *envp);

#define LLP "LD_LIBRARY_PATH"
    const char* const llp = getenv(LLP);
    printf("getenv %p %s\n", llp, llp);

    const char* const* env;
    for (env = envp; *env; env++) {
        if (!strncmp(*env, LLP, sizeof(LLP) - 1)) {
            printf("%p %s\n", *env, *env);
        }
    }
    exit(EXIT_SUCCESS);
}

/*
EDB Note: EOF poc-suidbin.c
*/
