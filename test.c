#include <stdio.h>

static void bar(void)
{
    printf("Bar!\n");
}

static void foo(const char *str)
{
    bar();
}

int main(void)
{
    const char *s = "Foo!";
    foo(s);
    return 0;
}
