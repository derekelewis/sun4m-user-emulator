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

int kernel_main() {
    int n = calculate_primes(10000);
    return 0;
}
