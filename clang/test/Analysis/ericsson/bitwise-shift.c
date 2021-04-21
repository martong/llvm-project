// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.ericsson.cpp.BitwiseShift -verify %s

/*
    Here I've tested the scenario where the right operand
    value is smaller than the left hand type size, but the shift
    will push out a bit from the signed type capacity.
    Notice that we are in a C file. In the C standard the new int
    has to be representable in the signed type.
*/
int LeftShift()
{
    int left = 1;
    int right = 31;

    /*
     Illegal move in C!
     ( Left new value is not representable in the signed type )
    */
    return left << (right); // expected-warning{{Bit overflow in left shift}}
}

void large_int(){
    __int128 i =  (__int128) 1 << 62 << 1;
    i = (__int128) 1 << 63 << 1; //this used to crash
    (void) i;
}
