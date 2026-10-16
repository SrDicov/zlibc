// Gate Ola 9A (string/ctype/wide): exact C string semantics on boot.
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

int main(void) {
    char b[32];
    strcpy(b, "hello");
    if (strcmp(b, "hello") != 0 || strlen(b) != 5)
        return 1;
    strcat(b, " world");
    if (strcmp(b, "hello world") != 0)
        return 1;
    if (!strchr(b, ' ') || strchr(b, 0) != b + 11)
        return 1;
    if (!strstr(b, "lo wo"))
        return 1;
    char *d = strdup(b);
    if (!d || strcmp(d, b) != 0)
        return 1;
    free(d);
    if (strcasecmp("ABC", "abc") != 0 || strncasecmp("ABC", "abd", 3) >= 0)
        return 1;
    if (!isalpha('q') || isalpha('3') || !isdigit('7') || !isspace('\t') || toupper('a') != 'A'
        || tolower('Z') != 'z')
        return 1;
    char t[16];
    strtok(strcpy(t, "a,b;c"), ",;");
    if (strcmp(t, "a") != 0)
        return 1;
    if (strerror(2)[0] != 'N')
        return 1;
    wchar_t w[8];
    wcscpy(w, (wchar_t[]){'h', 'i', 0});
    if (wcslen(w) != 2 || wcscmp(w, (wchar_t[]){'h', 'i', 0}) != 0)
        return 1;
    if (!iswalpha('k') || towupper('m') != 'M')
        return 1;
    printf("string ok\n");
    return 0;
}
