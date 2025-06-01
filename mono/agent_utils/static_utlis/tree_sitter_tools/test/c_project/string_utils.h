#include <ctype.h>
#include "string_utils.h"

void capitalize(char *str) {
    if (str && *str) {
        str[0] = toupper(str[0]);  // 调用库函数 toupper
    }
}