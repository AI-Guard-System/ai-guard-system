#include <emscripten.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#define BUFFER_SIZE 2097152 

char OUTPUT[BUFFER_SIZE];
char STACK[1024];
int top = -1;

void push(char c) { if (top < 1023) STACK[++top] = c; }
char pop() { if (top >= 0) return STACK[top--]; return 0; }
char peek() { if (top >= 0) return STACK[top]; return 0; }

EMSCRIPTEN_KEEPALIVE
char* repair_json(char* input) {
    top = -1;
    int out_idx = 0;
    int len = strlen(input);
    bool in_string = false;
    bool escaped = false;

    for (int i = 0; i < len; i++) {
        char c = input[i];
        if (out_idx >= BUFFER_SIZE - 1) break; 

        OUTPUT[out_idx++] = c;

        if (escaped) { escaped = false; continue; }
        if (c == '\\') { escaped = true; continue; }
        if (c == '"') { in_string = !in_string; continue; }

        if (!in_string) {
            if (c == '{') push('}');
            else if (c == '[') push(']');
            else if (c == '}' || c == ']') {
                if (peek() == c) pop();
            }
        }
    }
    
    if (in_string) OUTPUT[out_idx++] = '"';
    while (top >= 0) OUTPUT[out_idx++] = pop();

    OUTPUT[out_idx] = '\0';
    return OUTPUT;
}
