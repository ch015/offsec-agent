#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_request(const char *input) {
    char query[256];
    sprintf(query, "SELECT * FROM users WHERE name = '%s'", input);
    execute_query(query);
}

void execute_query(const char *sql) {
    printf("Executing: %s\n", sql);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        handle_request(argv[1]);
    }
    return 0;
}
