#include "hello.h"
#include "matrix.h"
#include "utils.h"
#include "BGVNaiveBayesPrediction.h"
#include <helib/NumbTh.h>
#include <helib/debugging.h>
#include <string.h>


int main(int argc, char* argv[])
{
    long p = 2;
    long r = 1;
    long hwt = 120;
    long k = 80;
    long deg = 1; //embedding degree
    long nslots = 1; //lower bound on #slots
    unsigned long nbits = 50;
    unsigned long ndigits = 3;
    long bitsInSpecialPrimes = 58;
    long nthreads = 0; //Default is 0 for number of cpus.
    long m = 0;
    std::string modelDataFilePath;
    std::string testDataFilePath;
    int method = 0;
    hello::PredictionType predictionType = hello::NAIVE;
    // int type = 0;
    he_cmp::CircuitType compare_type = he_cmp::UNI;
    int former_later = 0;
    bool verbose = false;

    helib::ArgMap()
        .required()
        .positional()
            .arg("<input-file1>", modelDataFilePath, "the input model file.", nullptr)
            .arg("<input-file2>", testDataFilePath, "the input test data file.", nullptr)
        .separator(helib::ArgMap::Separator::WHITESPACE)
        .named()
        .optional()
            .arg("-m", m, "the degree of the cyclotomic polynomial")
            .arg("-method", method, "method to predict, '0' for naive, '1' for packed, and '2' for naive_packed")
            // .arg("-t", type, "method to compare, '0' for univariant and '1' for bivariant")
            .arg("-n", nthreads, "the number of cpus")
            .arg("-p", p, "characteristic of plaintext space")
            .arg("-r", r, "exponent of plaintext lifting")
            .arg("-b", nbits, "# bits required for the modulus chain, i.e., a lower bound on the sum of bits of ctxtPrimes and specialPrimes")
            .arg("-c", ndigits, "# digits/columns in the key-switching matrix")
            .arg("-hwt", hwt, "Hamming weight of the secret-key")
            .arg("-bsp", bitsInSpecialPrimes, "bits in special primes")
            .arg("-k", k, "the security parameter if -m is not specified")
            .arg("-s", nslots, "a lower bound on #slots")
            .arg("-d", deg, "the embedding degree")
            .arg("-f", former_later, "argmax returns former or later for equal maximum")
            .arg("-v", verbose, "verbose")
        .parse(argc, argv);


    if (nthreads > 1)
        NTL::SetNumThreads(nthreads);

    if (verbose != false)
        verbose = true;



    if (method == 1)
        predictionType = hello::PACKED;  
    
    if (method == 2)
        predictionType = hello::NAIVE_PACKED;  



    std::vector<hello::matrix<int>> likelihoods;
    std::vector<int> prior;
    std::vector<int> vec;

    readModelData(likelihoods, prior, vec, modelDataFilePath, verbose);
    
    int d = hello::maxEntry(vec); 


    
    if (m == 0)
        m = helib::FindM(k, nbits, ndigits, p, deg, nslots, 0, false);

    std::cout << "Initializing the context object ..." << std::endl;

    //begin HE Bayes
    HELIB_NTIMER_START(iniTimer);
    // init context
    helib::Context context = helib::ContextBuilder<helib::BGV>()
                                .m(m)
                                .p(p)
                                .r(r)
                                .bits(nbits)
                                .c(ndigits)
                                .skHwt(hwt)
                                .bitsInSpecialPrimes(bitsInSpecialPrimes)
                                //.scale(6)
                                .build();

    

    helib::SecKey secretKey(context);
    secretKey.GenSecKey();
    helib::addSome1DMatrices(secretKey);
    if (r > 1)
        helib::addFrbMatrices(secretKey);
    // helib::addAllMatrices(secretKey);
    const helib::PubKey publicKey(secretKey);
    const helib::EncryptedArray& ea = context.getEA();

    

    // print the algebra info
    if (verbose)
        context.printout();
    
    helib::Ctxt ctxt(publicKey);
    double log_q = ctxt.logOfPrimeSet();
    std::cout << "the initial number of bits of q = " << log_q / std::log(2.0) << std::endl;
    helib::IndexSet primes = context.getCtxtPrimes(); //ctxtPrimes | specialPrimes;
    std::cout << "bits of ctxt primes = " << std::ceil(context.logOfProduct(primes) / std::log(2.0)) << std::endl; 
    primes = context.getSpecialPrimes();
    std::cout << "bits of special primes = " << std::ceil(context.logOfProduct(primes) / std::log(2.0)) << std::endl; 

    long nslot = context.getNSlots();
    if (nslot < d && method == 1)
    {
        std::cerr << "\nERROR from main(): the number of slots must be at least " << d << "." << std::endl;
        return EXIT_FAILURE;
    }


    HELIB_NTIMER_STOP(iniTimer);
    const helib::FHEtimer *tp;
    tp = helib::getTimerByName("iniTimer");
    
    if (verbose){
        std::cout <<"Initialization costs " << tp -> getTime()
            << " seconds." << std::endl << std::endl;
    }
    



    std::vector<int> res;

    testEncryptedNaiveBayesPrediction(res, testDataFilePath, likelihoods, prior, vec, context, publicKey, secretKey, former_later, predictionType, verbose);


    return EXIT_SUCCESS;    
}

