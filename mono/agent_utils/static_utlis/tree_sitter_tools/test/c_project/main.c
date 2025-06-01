#include <stdio.h>
#include "math_utils.h"
#include "string_utils.h"

void display_result(int value) {  // 库函数 printf
    printf("Result: %d\n", value);
}

int main() {
    int sum = add(3, 4);          
    char name[] = "alice";
    capitalize(name);               
    display_result(sum); 
    printf("I love you");           
    return 0;
}