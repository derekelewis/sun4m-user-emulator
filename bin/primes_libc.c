/* primes_libc.c */

#include <stdio.h>

/* We have libc now, so let's output primes with our unintentionally unoptimized trial division */
int calculate_primes(int n) {

    int n_primes = 0;

    for (int i = 2; i <= n; i++) {
        int is_prime = 1;
        for (int j = 2; j < i; j++) {
            if ((i % j) == 0) {
                is_prime = 0;
                break;
            }
        }
        if (is_prime)
            n_primes++;
    }

    return n_primes;
}

int main() {
    int n = calculate_primes(10000);
    printf("number of primes: %d",n);

    return 0;
}
