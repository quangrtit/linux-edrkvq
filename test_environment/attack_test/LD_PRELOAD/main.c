#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>




int main(void)
{
    unsigned int seed;
    seed = 1337;
    
    srand(seed);

    while(1) {
        printf("#: %d\n", rand());
        sleep(1);
    }
    return(EXIT_SUCCESS);
}