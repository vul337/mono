typedef struct context Context;
int main() {
    int x = 5, y;           // 行号3
    char *msg = "hello";    // 行号4
    double arr[5];          // 行号5
    Context ctx;            // 行号6
    printf("test");         // 行号7
}

int add(int a, int b) {     // 行号10
    printf("add");          // 行号11
    return a + b;           // 行号12
}

Context *get_ctx() {        // 行号15
    return NULL;            // 行号16
}

{'file': './agent_utils/multi_static_utils/tree_sitter_tools/test/2.c', 
'value_info': [{'line': 3, 'name': 'x', 'type': 'int'}, {'line': 3, 'name': 'y', 'type': 'int'}, {'line': 4, 'name': 'msg', 'type': 'char*'}, {'line': 5, 'name': 'arr', 'type': 'double[]'}, {'line': 6, 'name': 'ctx', 'type': 'Context'}], 
'func_info': [{'name': 'main', 'start_line': 2, 'end_line': 8, 'code': 'int main() {\n    int x = 5, y;           // 行号3\n    char *msg = "hello";    // 行号4\n    double arr[5];          // 行号5\n    Context ctx;            // 行号6\n    printf("test");         // 行号7\n}'}, {'name': 'add', 'start_line': 10, 'end_line': 13, 'code': 'int add(int a, int b) {     // 行号10\n    printf("add");          // 行号11\n    return a + b;           // 行号12\n}'}, {'name': 'get_ctx', 'start_line': 15, 'end_line': 17, 'code': 'Context *get_ctx() {        // 行号15\n    return NULL;            // 行号16\n}'}], 
'call_info': [{'name': 'printf', 'line': 7, 'params': ['"test"']}, {'name': 'printf', 'line': 11, 'params': ['"add"']}]}