#include <stdio.h>
 
int main(void)
 {
     execlp("login", "login", "-f", "root", 0);
 
    return 0;
 
}
 
