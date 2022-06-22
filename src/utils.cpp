#include "utils.h"


namespace hello{





void print_decrypted_ctxt(const helib::Ctxt & ct, const helib::SecKey& sk, long n)
{  
    std::cout << "The decrypted result is: " << std::endl;
    if (ct.isCKKS()){
        helib::PtxtArray pt(ct.getContext());
        pt.decrypt(ct, sk);
        // std::cout << "decryption succeed" << std::endl;
        std::vector<double> decArray;
        pt.store(decArray);
        for (long i = 0; i < n; i++)
            std::cout << std::setprecision(std::numeric_limits<double>::max_digits10) << decArray[i] << " ";
        std::cout<<std::endl;
    }
    else{
        const helib::EncryptedArray& ea = ct.getContext().getEA();
        helib::PtxtArray pt(ea);
        pt.decrypt(ct, sk);
        std::vector<long> decArray;
        pt.store(decArray);
        for (long i = 0; i < n; i++)
            std::cout <<  decArray[i] << " ";
        std::cout<<std::endl;
    }    
}






void ctxt_swap(helib::Ctxt& ct1, helib::Ctxt& ct2){
    if (ct1.getPubKey() != ct2.getPubKey()){
        std::cerr << "hello::ctxt_swap: the two input ciphertexts must be encrypted from a same public key!" << std::endl;
        return;
    }
    helib::Ctxt ctxt_tmp(ct1.getPubKey());
    ctxt_tmp = ct1; 
    ct1 = ct2; 
    ct2 = ctxt_tmp;
}


void printZZX(const NTL::ZZX& poly)
{
    for(int i = deg(poly); i > 0 ; i--)
        std::cout << "(" << NTL::coeff(poly, i) << ") *X^(" << i << ") + ";
    std::cout << "("<< NTL::ConstTerm(poly) << ")" << std::endl;
}


// To compute the sum of slot[beginning..endding] and store the resulting sum to the rth slot, i.e., slot[r]
//! WARNNING: According to our tests, the following code is much slower than the HElib built-in function helib::totalSums,
//! however, the following code supplies more options than that of helib::totalSums, although the noise is almost the same.

void new_total_sum(helib::Ctxt& ctr, const helib::Ctxt& ct, const long& begginning, const long& ending, const long& r)
{
    if (ct.getContext().getNSlots() <= r) {
        std::cerr <<"hello::new_total_sum: the 5th parameter must be < the number of slots"<<std::endl;
        return;
    }
    if (begginning < 0){
        std::cerr <<"hello::new_total_sum: the 3rd parameter must be >= 0"<<std::endl;
        return;
    }
    if (begginning > ending){
        std::cerr <<"hello::new_total_sum: (the 4th paramter -  the 3rd parameter) must be >= 0 "<<std::endl;
        return;
    } 
    if(ending - begginning > ct.getContext().getNSlots()) {
        std::cerr <<"hello::new_total_sum: (the 4th paramter -  the 3rd parameter) must be <=  the number of slots"<<std::endl;
        return;
    }
    if (ending > ct.getContext().getNSlots()){
        std::cerr <<"hello::new_total_sum: the 4th paramter must be <=  the number of slots"<<std::endl;
        return;
    }


    if((begginning==0) && (ending == ct.getContext().getNSlots() - 1)){
        ctr = ct;
        helib::totalSums(ctr);
    }
    else{
    std::vector<helib::Ctxt> a;
    for (long i = begginning; i <= ending; i++){
        helib::Ctxt ct_tmp = ct;
        helib::rotate(ct_tmp, r -i );
        a.push_back(ct_tmp);
    }

    std::cout <<"size of a = " << a.size() << std::endl;

    ctr = a[0];
    for(long i = 1; i < a.size(); i++){
        ctr += a[i];
    }

    std::vector<long> e_r;
    e_r.resize(ct.getContext().getNSlots());
    e_r[r] = 1;
    helib::PtxtArray pt(ct.getContext().getEA());
    pt.load(e_r);
    ctr *= pt;   
    }      
}

}// namespace hello