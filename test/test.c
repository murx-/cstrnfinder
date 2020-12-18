#include <string.h>
#include <stdio.h>

int main () {
    const char str_a[]  = "a";
    const char str_prefix[]  = "prefix_";
    const char str_long_prefix[]  = "prefixloong_"; // 12
    int a = 0;
    
    a += strncmp(str_a, "prefix_", 7);
    a += strncmp(str_a, "prefix_", 6);
    a += strncmp(str_a, "prefix_", 8);
    a += strncmp(str_a, "prefixloong_", 12);
    a += strncmp(str_a, "prefixloong_", 10);
    a += strncmp(str_a, "prefixloong_", 14);

    a += strncmp(str_prefix, "prefix_", 7);
    a += strncmp(str_prefix, "prefixloong_", 12);


    //a += strncmp("a", "prefix_", 7);
    //a += strncmp("z", "prefix_", 7);
    //a += strncmp("prefix_", "prefix_", 7);
    //a += strncmp("prefix_A", "prefix_", 7);

    a += strncmp(str_a, str_prefix, 7);
    a += strncmp(str_a, str_long_prefix, 12);
    a += strncmp("z", str_prefix, 7);
    a += strncmp("prefix_", str_prefix, 7);
    a += strncmp("prefix_A", str_prefix, 7);

    printf("%d\n", a);
    printf("%s\n", str_a);
    return a;
}


