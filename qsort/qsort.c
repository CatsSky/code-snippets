#include <stdio.h>
#include <stdint.h>

typedef uint32_t U32;

void swap_int(U32* a, U32* b) {
    if (a != b) {
        *a = *a ^ *b;
        *b = *b ^ *a;
        *a = *a ^ *b;
    }
}

// sort [left, right)
void quicksort_impl(U32* left, U32* right) {
    if (left >= right) return;

    U32* pivot = left;
    U32* l_ptr = left;
    U32* r_ptr = right - 1;

    while (1) {
        while (*l_ptr <= *pivot && l_ptr < right) l_ptr++;
        while (*r_ptr >= *pivot && r_ptr > left) r_ptr--;

        if (l_ptr > r_ptr) break;

        swap_int(l_ptr, r_ptr);
    }
    swap_int(pivot, r_ptr);
    
    quicksort_impl(left, r_ptr);
    quicksort_impl(r_ptr + 1, right);
}

void quicksort(U32* arr, int size) {
    quicksort_impl(arr, arr + size);
}

int isSorted(int* lb, int* ub) {
    for(; lb + 1 < ub; ++lb) 
        if(*lb > *(lb + 1))
            return 0;
    return 1;
}

int main(int argc, char* argv[]) {
    U32 arr[] = {6, 4, 8, 1, 9, 0, 4, 6};
    quicksort(arr, sizeof(arr) / sizeof(arr[0]));
    printf("sorted array: ");
    for(size_t i = 0; i < sizeof(arr) / sizeof(arr[0]); i++)
        printf("%d ", arr[i]);
    printf("\n%s", isSorted(arr, arr + sizeof(arr)/ sizeof(arr[0])) ? "is sorted" : "is unsorted");
}
