#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARGS_COUNT 127
#define MAX_ARG_LENGTH 4095

char **parse_args(const char *command) {
#define STATUS_FIND_BEGIN 1
#define STATUS_FIND_END 2
    char **args = malloc((MAX_ARGS_COUNT + 1) * sizeof(char *));
    int args_index = 0;

    char arg[MAX_ARG_LENGTH + 1] = {'\0'};
    int arg_index = 0;

    int command_length = strlen(command);
    char arg_quote = 0;
    int status = STATUS_FIND_BEGIN;

    int i = 0;
    for (i = 0; i <= command_length; i ++) {
        char c = command[i];
        if (status == STATUS_FIND_BEGIN) {
            if (c != ' ') {
                arg_index = 0;
                if (c == '"' || c == '\'') {
                    arg_quote = c;
                } else {
                    arg_quote = 0;
                    arg[arg_index++] = c;
                }
                status = STATUS_FIND_END;
            }
        } else if (status == STATUS_FIND_END) {
            if (c == '\\') {
                if (i < command_length-1) {
                    switch(command[i+1]) {
                        case '"':
                        case '\'':
                        case '\\':
                        case ' ':
                            if (arg_index < MAX_ARG_LENGTH) {
                                arg[arg_index++] = command[i+1];
                            }
                            i ++;
                            continue;
                        default:
                            goto COPYC;
                    }
                } else {
                    goto COPYC;
                }
            } else if (c == '\0'
                    || (arg_quote != 0 && c == arg_quote)
                    || (arg_quote == 0 && c == ' ')) {
                arg[arg_index] = '\0';
                args[args_index++] = strdup(arg);
                status = STATUS_FIND_BEGIN;
                if (args_index >= MAX_ARGS_COUNT) {
                    goto END;
                }
            } else {
COPYC:
                if (arg_index < MAX_ARG_LENGTH) {
                    arg[arg_index++] = c;
                }
            }
        }
    }

END:
    args[args_index] = NULL;
    return args;
}

void free_args(char **args) {
    if (args == NULL) return;
    char **a = args;
    while(*a) {
        free(*a++);
    }
    free(args);
}

#ifdef ARG_PARSER_TEST

void dump_command(const char *command) {
    printf("--------------\n");
    printf("%s\n", command);
    char **args = parse_args(command);
    char **a = args;
    while (*a) {
        printf("\"%s\"\n", *a++);
    }
    free_args(args);
}

int main(int argc, char **argv) {
    dump_command("ls -lh");
    dump_command("mysql -uroot -pfasdfasd");
    dump_command("mysql -u\"root\" -p\"fasdfasd\"");
    dump_command("mysql \"fasdfasd\"");
    dump_command("mysql \"fas\"dfasd\"");
    dump_command("mysql \"fas\\\"dfasd\"");
    dump_command("mysql \"fas    dfasd\"");
    dump_command("mysql \"fas\\    dfasd\"     ");
    dump_command("\"mysql\" \"fas\\    dfasd\"     -a");
    dump_command("\"mysql\" fas\\ dfasd     -a");
    dump_command("msyql -u'root'");
    dump_command("mysql '-uroot' -p'\"padfs'");
    dump_command("mysql '-uroot''''''");
    return 0;
}

#endif
