#ifndef HELLO_UTILS_H
#define HELLO_UTILS_H


#include <helib/helib.h>

namespace hello{

template <typename T>
T maxEntry(const std::vector<T>& x){
    if (x.size() == 1) 
        return x[0];
    T a = x[0];
    for (std::size_t i = 1; i < x.size(); i++){
        if (a < x[i]){
            a = x[i];
        }
    }
    return a;
}



template <typename T1, typename T2>
long mods(T1 a, T2 p)
{
    if (a >= p/2)
        return a - p;
    else
        return a;
}

template <typename T>
long sign(T a)
{
    if (a >= 0)
        return 1;
    else
        return -1;
}




void print_decrypted_ctxt(const helib::Ctxt & ct, const helib::SecKey& sk, long n = 1);


void ctxt_swap(helib::Ctxt& ct1, helib::Ctxt& ct2);


void printZZX(const NTL::ZZX& poly);

// To compute the sum of slot[beginning..endding] and store the resulting sum to the rth slot, i.e., slot[r]
void new_total_sum(helib::Ctxt& ctr, const helib::Ctxt& ct, const long& begginning, const long& ending, const long& r);

}// namespace hello
#endif // utils.h