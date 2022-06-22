#include <iostream>
#include <fstream>

#include <helib/helib.h>
#include <helib/ArgMap.h>

#include <NTL/BasicThreadPool.h>

#include "matrix.h"
#include "utils.h"
#include "tools.h"
#include "comparator.h"

/* 
 * This example is a naive implementation of the naive Bayes predcition.
 * Entries of a vector are encoded as independent  plaintexts, and encrypted
 * as independent ciphertexts. So, the input data are not packed and hence 
 * SIMD is not used. 
 */

// This is only to test hello::matrix.
template <typename T>
void initMatrix(hello::matrix<T> &A)
{
    std::size_t rows, cols;
    rows = A.getRows();
    cols = A.getCols();
    for (std::size_t i = 0; i < rows; i++)
        for (std::size_t j = 0; j < cols; j++)
            A(i, j) = (T)(i + 2 * j);
}

// input  v = (v_1, ..., v_n) with n attributes and an integer d
// encode v_i as a d-dimensional vector whose v_i-th entry is 1
// and other entries are all 0.
// E.g., input (2, 2, 1, 1) and 3, then the output
//  of encodeFeatureData(2, 2, 1, 1) will be:
//  (0, 1, 0)  --- for v_1 = 2
//  (0, 1, 0)  --- for v_2 = 2
//  (1, 0, 0)  --- for v_3 = 1
//  (1, 0, 0)  --- for v_4 = 1
// Note that integer d is just the maximum of possible values over
//   all attributes. E.g., the last attribute has only 2 possible values,
//   but we append a zero to make the encoded vector is of dimension d.

template <typename T>
hello::matrix<int> encodeFeatureData(const std::vector<T> &v, std::size_t d)
{
    std::size_t n;
    n = v.size();
    hello::matrix<T> M(n, d);
    for (std::size_t i = 0; i < n; i++)
    {
        M(i, v[i] - 1) = 1;
    }
    return M;
}

// the input matrix M includes all information of the naive Bayes model in the following form:
// -16  -14 -13
// -9   -7  -19
//  -9  -14 -6  ------------------- the 1st attribute, it has 3 different values (3 rows above)
//  -3 -4   -7
//  -14 -11 -7 -------------------- the 2nd attribute, it has only 2 different values (2 rows above)
//  -14 -4  -7
//  -3  -11 -7 -------------------- the 3rd attribute, it has only 2 different values (2 rows above)
//  -14 -11 -7
//  -3  -4  -7 -------------------- the 4th attribute, it has only 2 different values (2 rows above)
//  -12 -16 -7 -------------------- the information for the prior probability
//
// the dimension of the vector d is the number of attributes
// d[i]: the number of different values of the i-th attributes
// e.g., for the above matrix,
//      d = [3, 2, 2, 2]
//  so, d_1 + ... + d_last = n - 1, where n is the rows of the input matrix M.
//
//
// The output is a vector, the i-th entry is the i-th likelihood matrix for
//  the i-th attributes.
// rounded + scaled + log likelihood
// The output is A

template <typename T1, typename T2>
void rsLogAllLikelihood(const hello::matrix<T1> &M, const std::vector<T2> &v, std::vector<hello::matrix<T2>> &A)
{
    int s;
    std::size_t r, c, d;
    r = M.getRows();
    c = M.getCols();
    d = v.size();
    hello::sumOfVector(s, v);

    if (r - 1 != s)
        std::cerr << "rsLogAllLikelihood: the rows of the input matrix does not match the input vector" << std::endl;

    A.resize(d);
    int rows = 0;
    for (std::size_t i = 0; i < d; i++)
    {
        hello::matrix<int> tmpA;
        tmpA.resize(v[i], c);
        for (std::size_t k = 0; k < v[i]; k++)
        {
            for (std::size_t j = 0; j < c; j++)
            {
                tmpA(k, j) = M(k + rows, j);
            }
        }
        //A.push_back(tmpA); // A.push_back(tmpA) is to append tmpA to A
        A[i] = tmpA;
        rows += v[i];
    }
}

// input all of model data as a matrix,
// the last row of the matrix is the prior probability
// the output is prior
template <typename T>
void rsLogPrior(const hello::matrix<T> &M, std::vector<T> &prior)
{
    std::size_t n;
    n = M.getRows();
    prior = M.getLastRow();
}

// load all likelihood as vector<vector<vector<helib::PtxtArray>>>
// output is pt_likelihood
// since PtxtArray does not supply a method to set ea,
// we can not use vector<hello::matrix> as the returned type.
// NOTE: PtxtArray is recommended, comparing with PlaintextArray.
template <typename T>
void ptxtArrayLikelihood(std::vector<std::vector<std::vector<helib::PtxtArray>>> &pt_likelihood,
                         const std::vector<hello::matrix<T>> &likelihood,
                         const helib::EncryptedArray &ea)
{
    pt_likelihood.resize(likelihood.size());
    //const helib::EncryptedArray& ea = context.getEA();
    //ea.getPAlgebra().printout();
    for (std::size_t i = 0; i < likelihood.size(); i++)
    {
        pt_likelihood[i].resize(likelihood[i].getRows());
        for (std::size_t j = 0; j < likelihood[i].getRows(); j++)
        {
            for (std::size_t k = 0; k < likelihood[i].getCols(); k++)
            {
                helib::PtxtArray pt_tmp(ea);
                pt_tmp.load(likelihood[i](j, k));
                pt_likelihood[i][j].push_back(pt_tmp);
            }
        }
    }
}

// load rsLogPrior as vector<helib::PtxtArray>
// output is pt_prior
template <typename T>
void ptxtArrayPrior(std::vector<helib::PtxtArray> &pt_prior,
                    const std::vector<T> &prior,
                    const helib::EncryptedArray &ea)
{
    pt_prior.clear();
    for (std::size_t i = 0; i < prior.size(); i++)
    {
        helib::PtxtArray pt_tmp(ea);
        pt_tmp.load(prior[i]);
        pt_prior.push_back(pt_tmp);
        // std::cout << pt_prior[i] << std::endl;
    }
}

// Input the encoded matrix M, publicKey and ea,
// Output the encrypted matrix ctM under publicKey.
template <typename T>
void encryptFeatureMatrix(std::vector<std::vector<helib::Ctxt>> &ctM,
                          const hello::matrix<T> &M,
                          const helib::PubKey &publicKey,
                          const helib::EncryptedArray &ea)
{
    ctM.resize(M.getRows());
    for (std::size_t i = 0; i < M.getRows(); i++)
    {
        for (std::size_t j = 0; j < M.getCols(); j++)
        {
            helib::Ctxt ct_tmp(publicKey);
            helib::PtxtArray pt_tmp(ea);
            pt_tmp.load(M(i, j));
            pt_tmp.encrypt(ct_tmp);
            ctM[i].push_back(ct_tmp);
            // std::cout << ctM[i][j] << "\n" << std::endl;
        }
    }
}

// May not be useful, almost the same with the above encryptFeatureMatrix
template <typename T>
void encryptPackedFeatureMatrix(std::vector<std::vector<helib::Ctxt>> &ctM,
                                const hello::matrix<std::vector<T>> &M,
                                const helib::PubKey &publicKey,
                                const helib::EncryptedArray &ea)
{
    ctM.resize(M.getRows());
    for (std::size_t i = 0; i < M.getRows(); i++)
    {
        for (std::size_t j = 0; j < M.getCols(); j++)
        {
            helib::Ctxt ct_tmp(publicKey);
            helib::PtxtArray pt_tmp(ea);
            pt_tmp.load(M(i, j));
            pt_tmp.encrypt(ct_tmp);
            ctM[i].push_back(ct_tmp);
            // std::cout << ctM[i][j] << "\n" << std::endl;
        }
    }
}

//              1   2   3
// input: ptA = 4   5   6
//              7   8   9
//      and ctxt of a vector, say v = (0, 1, 0)
// output is a ctxt vector v*ptA = ctxt of (4, 5, 6).

void ptMatrixCtVectorMul(const std::vector<std::vector<helib::PtxtArray>> &ptA,
                         const std::vector<helib::Ctxt> &ctx,
                         const helib::PubKey &publicKey,
                         const helib::EncryptedArray &ea,
                         std::vector<helib::Ctxt> &ctr)
{
    ctr.clear();
    std::size_t m, n;
    m = ptA.size();
    n = ptA[0].size();
    for (std::size_t j = 0; j < n; j++)
    {
        helib::PtxtArray pt_tmp(ea);
        helib::Ctxt ct_tmp(publicKey), ct_tmp1(publicKey);
        pt_tmp.load(0);
        pt_tmp.encrypt(ct_tmp);
        for (std::size_t i = 0; i < m; i++)
        {
            ct_tmp1 = ctx[i];
            ct_tmp1 *= ptA[i][j];
            ct_tmp += ct_tmp1;
        }
        ctr.push_back(ct_tmp);
    }
}

void ctxtVectorAdd(const std::vector<helib::Ctxt> &ctx,
                   const std::vector<helib::Ctxt> &cty,
                   const helib::PubKey &publicKey,
                   const helib::EncryptedArray &ea,
                   std::vector<helib::Ctxt> &ctr)
{
    ctr.clear();
    std::size_t d_1 = ctx.size();
    std::size_t d_2 = cty.size();
    if (d_1 != d_2)
        std::cerr << "ctxtVectorAdd: the dimensions of the two input vectors does not match" << std::endl;
    else
    {
        for (std::size_t i = 0; i < d_1; i++)
        {
            helib::PtxtArray pt_tmp(ea);
            helib::Ctxt ct_tmp(publicKey);
            pt_tmp.load(0);
            pt_tmp.encrypt(ct_tmp);
            ct_tmp += ctx[i];
            ct_tmp += cty[i];
            ctr.push_back(ct_tmp);
        }
    }
}

void ptVectorCtVectorAdd(const std::vector<helib::PtxtArray> &x,
                         const std::vector<helib::Ctxt> &cty,
                         const helib::PubKey &publicKey,
                         const helib::EncryptedArray &ea,
                         std::vector<helib::Ctxt> &ctr)
{
    ctr.clear(); // if using vector::push_back, then vector::clear() is necessary.
    std::size_t d_1 = x.size();
    std::size_t d_2 = cty.size();
    if (d_1 != d_2)
        std::cerr << "ptVectorCtVectorAdd: the dimensions of the two input vectors does not match" << std::endl;
    else
    {
        for (std::size_t i = 0; i < d_1; i++)
        {
            helib::PtxtArray pt_tmp(ea);
            helib::Ctxt ct_tmp(publicKey);
            pt_tmp.load(0);
            pt_tmp.encrypt(ct_tmp);
            ct_tmp += x[i];
            // ct_tmp.addConstant(x[i]);
            ctr.push_back(ct_tmp);
        }
    }
}

template <typename T>
void naivePredict(std::vector<helib::Ctxt> &ct_res,
                  const std::vector<hello::matrix<T>> &likelihoods,
                  const std::vector<T> &prior,
                  const std::vector<std::vector<helib::Ctxt>> &ctM,
                  const helib::PubKey &publicKey,
                  const helib::EncryptedArray &ea)
{

    std::vector<std::vector<std::vector<helib::PtxtArray>>> pt_likelihood;
    ptxtArrayLikelihood(pt_likelihood, likelihoods, ea);

    std::vector<helib::PtxtArray> pt_prior;
    ptxtArrayPrior(pt_prior, prior, ea);

    ct_res.clear();
    std::vector<helib::Ctxt> ct_v, ct_z;

    // initializing ct_res as encryption of (0,0,...,0)
    for (std::size_t i = 0; i < pt_prior.size(); i++)
    {
        helib::PtxtArray pt_tmp(ea);
        helib::Ctxt ct_tmp(publicKey);
        pt_tmp.load(0);
        pt_tmp.encrypt(ct_tmp);
        ct_res.push_back(ct_tmp);
        ct_v.push_back(ct_tmp);
        ct_z.push_back(ct_tmp);
    }

    ptVectorCtVectorAdd(pt_prior, ct_v, publicKey, ea, ct_res);

    // std::cout << "I'm here: ptVectorCtVectorAdd" << std::endl;

    for (std::size_t i = 0; i < pt_likelihood.size(); i++)
    {
        // for (std::size_t i = 0; i < 1; i++){
        // for each i do pt_matrix*ct_vector
        ptMatrixCtVectorMul(pt_likelihood[i], ctM[i], publicKey, ea, ct_v);
        // std::cout << "I'm here: ptMatrixCtVectorMul" << std::endl;
        ctxtVectorAdd(ct_res, ct_v, publicKey, ea, ct_z);
        // std::cout << "I'm here: ctxtVectorAdd" << std::endl;
        ct_res = ct_z;
        // std::cout << "I'm here: operator=" << std::endl;
    }
}

// naivePackedPredict for packing test samples

template <typename T>
void naivePackedPredict(std::vector<helib::Ctxt> &ct_res,
                        const std::vector<hello::matrix<T>> &likelihoods,
                        const std::vector<T> &prior,
                        const std::vector<std::vector<helib::Ctxt>> &ctM,
                        const helib::PubKey &publicKey,
                        const helib::EncryptedArray &ea)
{

    std::vector<std::vector<std::vector<helib::PtxtArray>>> pt_likelihood;
    ptxtArrayLikelihood(pt_likelihood, likelihoods, ea);

    std::vector<helib::PtxtArray> pt_prior;
    ptxtArrayPrior(pt_prior, prior, ea);

    ct_res.clear();
    std::vector<helib::Ctxt> ct_v, ct_z;

    // initializing ct_res as encryption of (0,0,...,0)
    for (std::size_t i = 0; i < pt_prior.size(); i++)
    {
        helib::PtxtArray pt_tmp(ea);
        helib::Ctxt ct_tmp(publicKey);
        pt_tmp.load(0);
        pt_tmp.encrypt(ct_tmp);
        ct_res.push_back(ct_tmp);
        ct_v.push_back(ct_tmp);
        ct_z.push_back(ct_tmp);
    }

    ptVectorCtVectorAdd(pt_prior, ct_v, publicKey, ea, ct_res);

    // std::cout << "I'm here: ptVectorCtVectorAdd" << std::endl;

    for (std::size_t i = 0; i < pt_likelihood.size(); i++)
    {
        // for (std::size_t i = 0; i < 1; i++){
        // for each i do pt_matrix*ct_vector
        ptMatrixCtVectorMul(pt_likelihood[i], ctM[i], publicKey, ea, ct_v);
        // std::cout << "I'm here: ptMatrixCtVectorMul" << std::endl;
        ctxtVectorAdd(ct_res, ct_v, publicKey, ea, ct_z);
        // std::cout << "I'm here: ctxtVectorAdd" << std::endl;
        ct_res = ct_z;
        // std::cout << "I'm here: operator=" << std::endl;
    }
}

// Packed Naive Bayes Prediction

template <typename T>
void packPtMatrix(std::vector<helib::PtxtArray> &ptr,
                  const hello::matrix<T> &M,
                  const helib::EncryptedArray &ea)
{
    ptr.clear();
    hello::matrix<T> A = M.transpose();
    std::size_t n = A.getRows();
    for (std::size_t i = 0; i < n; i++)
    {
        std::vector<T> v = A.getRow(i);
        helib::PtxtArray pt_tmp(ea);
        pt_tmp.load(v);
        ptr.push_back(pt_tmp);
    }
}

// E.g., the input feature matrix is
//  (0, 1, 0)  --- for v_1 = 2
//  (0, 1, 0)  --- for v_2 = 2
//  (1, 0, 0)  --- for v_3 = 1
//  (1, 0, 0)  --- for v_4 = 1
// The output is a vector with four entries, where
// the i-th entry is the packed ciphertext of the
// feature vector of v_i.
template <typename T>
void packedEncryptFeatureMatrix(std::vector<helib::Ctxt> &ctM,
                                const hello::matrix<T> &M,
                                const helib::PubKey &publicKey,
                                const helib::EncryptedArray &ea)
{

    int n = M.getRows();
    ctM.clear();
    for (std::size_t i = 0; i < n; i++)
    {
        helib::Ctxt ct_tmp(publicKey);
        helib::PtxtArray pt_tmp(ea);
        std::vector<T> v_tmp = M.getRow(i);
        // std::cout << " I am here ..." << endl;
        //hello::printVector(v_tmp);
        pt_tmp.load(v_tmp);
        pt_tmp.encrypt(ct_tmp);
        ctM.push_back(ct_tmp);
    }
}

// This is not a real vector-matrix multiplication. It just returns
// the resulting vectors of component-wise multiplication.
// E.g., ptr is the column-packed ptxt matrix  (1, 2, 3), (4, 5, 6)
// ctf is the packed ciphertext of a feature vector (1, 0, 0), then
// the output is a ciphertext vector ctr, where
// ctr[0] =  ctxt of (1, 0, 0)
// ctr[1] =  ctxt of (4, 0, 0)
// Since each feature vector is a standard basis vector, we can get
// the vector-matrix multiplication result at a very late step.
void packedPtMatrixPackedCtVectorMul(std::vector<helib::Ctxt> &ctr,
                                     const std::vector<helib::PtxtArray> &ptr, /*packed plaintext matrix as a vector*/
                                     const helib::Ctxt &ctf,                   /*packed ciphertext of a feature vector*/
                                     const helib::PubKey &publicKey,
                                     const helib::EncryptedArray &ea)
{
    ctr.clear();
    int n = ptr.size();
    for (int i = 0; i < n; i++)
    {
        helib::PtxtArray pt_tmp(ea);
        helib::Ctxt ct_tmp(publicKey), ct_tmp1(publicKey);
        pt_tmp.load(0);
        pt_tmp.encrypt(ct_tmp);
        ct_tmp1 = ctf;
        ct_tmp1 *= ptr[i];
        ct_tmp += ct_tmp1;
        ctr.push_back(ct_tmp);
    }
}

// x = (2, 1)
// cty = (cty[0], cty[1]) with cty[0] = ctxt of (1, 0, 0), cty[1] = (4, 0, 0)
// output:
// ctr[0] = ctxt of (1+2, 0, 0), ctr[1] = ctxt of (1+4, 0, 0)
template <typename T>
void packedPtVectorCtVectorAdd(std::vector<helib::Ctxt> &ctr,
                               const std::vector<T> &x,
                               const std::vector<helib::Ctxt> &cty,
                               const helib::PubKey &publicKey,
                               const helib::EncryptedArray &ea)
{
    ctr.clear(); // if using vector::push_back, then vector::clear() is necessary.
    std::size_t d_1 = x.size();
    std::size_t d_2 = cty.size();
    if (d_1 != d_2)
    {
        std::cerr << "packedPtVectorCtVectorAdd: the dimensions of the two input vectors does not match" << std::endl;
        return;
    }

    else
    {
        for (std::size_t i = 0; i < d_1; i++)
        {
            helib::PtxtArray pt_tmp(ea);
            helib::Ctxt ct_tmp(publicKey);
            ct_tmp = cty[i];
            std::vector<T> v;
            v.push_back(x[i]);
            v.push_back(0);
            //hello::printVector(v);
            pt_tmp.load(v);
            ct_tmp += pt_tmp;
            ctr.push_back(ct_tmp);
        }
    }
}

template <typename T>
void packedPredict(std::vector<helib::Ctxt> &ct_res,
                   const std::vector<hello::matrix<T>> &likelihoods,
                   const std::vector<T> &prior,
                   const std::vector<helib::Ctxt> &ctf,
                   const helib::PubKey &publicKey,
                   const helib::EncryptedArray &ea)
{
    ct_res.clear();
    int num_features = likelihoods.size();
    int num_classes = prior.size();

    // ini the result ctxt vector
    std::vector<helib::Ctxt> ctr;
    for (int i = 0; i < num_classes; i++)
    {
        helib::PtxtArray pt_v1(ea);
        helib::Ctxt ct_tmp(publicKey);
        pt_v1.load(0);
        pt_v1.encrypt(ct_tmp);
        ctr.push_back(ct_tmp);
    }

    for (int i = 0; i < num_features; i++)
    {
        std::vector<helib::PtxtArray> ptL;
        packPtMatrix(ptL, likelihoods[i], ea);
        std::vector<helib::Ctxt> ct_tmp, ctv;
        packedPtMatrixPackedCtVectorMul(ct_tmp, ptL, ctf[i], publicKey, ea);
        ctxtVectorAdd(ctr, ct_tmp, publicKey, ea, ctv);
        ctr = ctv;
    }

    // add prior
    std::vector<helib::Ctxt> ctv;
    packedPtVectorCtVectorAdd(ctv, prior, ctr, publicKey, ea);
    ct_res = ctv;
    for (int i = 0; i < ct_res.size(); i++)
        helib::totalSums(ea, ct_res[i]);
}

template <typename T>
void readModelData(std::vector<hello::matrix<T>> &likelihoods,
                   std::vector<T> &prior,
                   std::vector<T> &num_feature_vec,
                   std::string &modelDataFilePath,
                   bool verbose)
{
    std::cout << "reading model data ..." << std::endl;

    std::fstream dataFile(modelDataFilePath);
    if (!dataFile.is_open())
    {
        throw std::runtime_error("Could not open file '" + modelDataFilePath + "'.");
    }
    // Data reading
    std::vector<std::vector<T>> model;
    std::string s;
    while (true)
    {
        std::getline(dataFile, s, '\n');
        std::stringstream iss(s);
        std::istream_iterator<long> issit(iss);
        std::vector<int> vl(issit, {});
        if (dataFile.eof())
        {
            break;
        }
        model.push_back(vl);
    }
    dataFile.close(); // ending of read data

    // This vector indicates the number of different values of each attribute
    // and hence the number of features is the size of this vector.
    num_feature_vec.clear();
    num_feature_vec = model[0]; //
    std::size_t num_features = num_feature_vec.size();

    // the number of classes
    std::size_t num_classes = model[1].size();

    // the data matrix
    hello::matrix<T> A;
    int sum;
    hello::sumOfVector(sum, num_feature_vec);

    if (verbose)
    {
        std::cout << "the number of input model file is " << model.size() << std::endl;
        std::cout << "it should be " << sum + 2 << std::endl;
    }

    if (model.size() != sum + 2)
    {
        std::cerr << "ERROR from readModelData: \nthe number of lines of "
                  << "the input data file does not match the info indicated by the first line of the data." << std::endl;
        return;
    }

    A.resize(sum + 1, num_classes);
    // initMatrix(A);
    for (std::size_t i = 0; i < A.getRows(); i++)
    {
        for (std::size_t j = 0; j < A.getCols(); j++)
        {
            A(i, j) = model[i + 1][j];
        }
    }

    if (verbose)
    {
        std::cout << std::endl
                  << "all the model data are :" << std::endl;
        hello::printMatrix(A);
        std::cout << std::endl
                  << std::endl;
    }

    // std::vector<hello::matrix<T>> likelihoods;
    likelihoods.clear();
    likelihoods.resize(num_features);

    rsLogAllLikelihood(A, num_feature_vec, likelihoods);

    if (verbose)
    {
        std::cout << std::endl
                  << "all likelihood matrices are :" << std::endl;
        for (std::size_t i = 0; i < num_features; i++)
        {
            hello::printMatrix(likelihoods[i]);
            std::cout << std::endl
                      << std::endl;
        }
    }

    // std::vector<int> prior;
    prior.clear();
    rsLogPrior(A, prior);
    if (verbose)
    {
        std::cout << std::endl
                  << "the prior probability is :" << std::endl;
        hello::printVector(prior);
    }
}

template <typename T>
void testEncryptedNaiveBayesPrediction(std::vector<T> &res,
                                       std::string &testDataFilePath,
                                       const std::vector<hello::matrix<T>> &likelihoods,
                                       const std::vector<T> &prior,
                                       const std::vector<T> &num_feature_vec,
                                       const helib::Context &context,
                                       const helib::PubKey &publicKey,
                                       const helib::SecKey &secretKey,
                                       const int former_later,
                                       hello::PredictionType predictionType,
                                       bool verbose)
{
    std::cout << "reading test data ..." << std::endl;

    std::fstream dataFile(testDataFilePath);
    if (!dataFile.is_open())
    {
        throw std::runtime_error("Could not open file '" + testDataFilePath + "'.");
    }
    std::vector<std::vector<T>> test_data;
    std::string s;
    while (true)
    {
        std::getline(dataFile, s, '\n');
        std::stringstream iss(s);
        std::istream_iterator<long> issit(iss);
        std::vector<int> vl(issit, {});
        if (dataFile.eof())
        {
            break;
        }
        test_data.push_back(vl);
    }
    dataFile.close(); // ending of read data

    std::size_t num_tests = test_data.size();
    std::size_t num_features = num_feature_vec.size();
    int d = hello::maxEntry(num_feature_vec);

    if (verbose)
        std::cout << "#features = " << num_features << std::endl;

    const helib::EncryptedArray &ea = context.getEA();
    long p = context.getP();
    const helib::FHEtimer *tp;
    he_cmp::CircuitType compare_type = he_cmp::UNI;

    hello::matrix<T> A;
    A.resize(num_tests, num_features);
    // initMatrix(A);
    for (std::size_t i = 0; i < A.getRows(); i++)
    {
        for (std::size_t j = 0; j < A.getCols(); j++)
        {
            A(i, j) = test_data[i][j];
        }
    }

    if (verbose)
    {
        std::cout << std::endl
                  << "all the test data are :" << std::endl;
        hello::printMatrix(A);
        std::cout << std::endl
                  << std::endl;
    }

    if (predictionType == hello::NAIVE)
    {
        std::cout << "naive predicting ..." << std::endl;
    }

    if (predictionType == hello::PACKED)
    {
        std::cout << "packed predicting ..." << std::endl;
    }

    unsigned long degree = 1;
    unsigned long expansion_len = 1;
    he_cmp::Comparator comparator(context, compare_type, degree, expansion_len, secretKey, verbose);

    std::cout << "m = " << context.getM() << std::endl;
    std::cout << "nslots = " << context.getNSlots() << std::endl;
    std::cout << "ordP = " << context.getOrdP() << std::endl;

    res.clear();

    std::cout << "Predicting the test data ..." << std::endl;

    // 2021/10/14 batching the tests using SIMD

    // The matrix A is the test matrix, each row is a sample, dim(A) = num_tests, num_features
    // If no SIMD for test, each sample is encoded as a num_features * d matrix, where d is the
    // bound on the number of different values of all features.
    // For SIMD, we will use such a num_feature * d matrix to store all information of the test matrix.

    if (predictionType == hello::NAIVE_PACKED)
    {
        std::cout << "#samples is " << num_tests << std::endl;
        std::cout << "packed samples predicting ..." << std::endl;

        std::vector<hello::matrix<T>> V;
        for (int i = 0; i < num_tests; i++)
        {
            std::vector<T> v = A.getRow(i);
            V.push_back(encodeFeatureData(v, d));
        }

        hello::matrix<std::vector<T>> packedA;
        packedA.resize(num_features, d);
        for (int i = 0; i < num_features; i++)
        {
            for (int j = 0; j < d; j++)
            {
                for (int k = 0; k < num_tests; k++)
                {
                    packedA(i, j).push_back(V[k](i, j));
                }
            }
        }

        std::vector<std::vector<helib::Ctxt>> ctV;
        HELIB_NTIMER_START(Encrypt);
        encryptFeatureMatrix(ctV, packedA, publicKey, ea);
        HELIB_NTIMER_STOP(Encrypt);

        

        {   
            std::ofstream encryptedFeatureFile;
            encryptedFeatureFile.open("enc_feature.txt", std::ios::out);
            for(long i=0; i < ctV.size(); i++)
                for (long j = 0; j < ctV[1].size(); j++)
                    ctV[i][j].writeToJSON(encryptedFeatureFile);
            encryptedFeatureFile.close();
        }

        std::vector<helib::Ctxt> ctr;
        HELIB_NTIMER_START(Prediction);
        naivePredict(ctr, likelihoods, prior, ctV, publicKey, ea);
        HELIB_NTIMER_STOP(Prediction);

        if (verbose)
        {
            std::cout << "capacity = " << ctr[0].capacity() << std::endl;
            for (int i = 0; i < ctr.size(); i++)
            {
                hello::print_decrypted_ctxt(ctr[i], secretKey, num_tests);
            }
        }
        HELIB_NTIMER_START(Comparison);
        if (ctr.size() == 2)
        {
            comparator.compare(ctr[0], ctr[0], ctr[1]);
        }
        else
        {
            comparator.argmax(ctr[0], ctr, former_later);
        }

        HELIB_NTIMER_STOP(Comparison);
        // if (verbose)
        std::cout << "capacity = " << ctr[0].capacity() << std::endl;

        helib::PtxtArray pt_vd(ea);

        {   
            std::ofstream resultFile;
            resultFile.open("ctr.txt", std::ios::out);
            ctr[0].writeToJSON(resultFile);
            resultFile.close();
        }


        // std::cout << "memory size of ctr[0] = " << << std::endl;

        HELIB_NTIMER_START(Decrypt);        
        pt_vd.decrypt(ctr[0], secretKey);
        HELIB_NTIMER_STOP(Decrypt);
        // std::vector<long> decArray;
        // pt_vd.store(decArray);
        // hello::printVectorNew(decArray, num_tests, std::cout);
        hello::print_decrypted_ctxt(ctr[0], secretKey, num_tests);
    }
    // end of batching the tests using SIMD

    if (predictionType != hello::NAIVE_PACKED)
    {

        for (std::size_t i = 0; i < num_tests; i++)
        {
            // for (std::size_t i = num_tests - 2; i < num_tests; i++){
            if (verbose)
                std::cout << "Predicting the " << i + 1 << " / " << num_tests << " test data ..." << std::endl;

            std::vector<T> v = A.getRow(i);
            hello::matrix<int> V;
            V = encodeFeatureData(v, d);
            std::vector<helib::Ctxt> ctr;
            if (predictionType == hello::NAIVE)
            {

                std::vector<std::vector<helib::Ctxt>> ctV;
                HELIB_NTIMER_START(Encrypt);
                encryptFeatureMatrix(ctV, V, publicKey, ea);
                HELIB_NTIMER_STOP(Encrypt);

                HELIB_NTIMER_START(Prediction);
                naivePredict(ctr, likelihoods, prior, ctV, publicKey, ea);
                HELIB_NTIMER_STOP(Prediction);
                // if (verbose){
                //     tp = helib::getTimerByName("prediction");
                //     std::cout <<"Naive prediction costs " << tp -> getTime()
                //               << " seconds."  << std::endl << std::endl;
                // }
            }
            else if (predictionType == hello::PACKED)
            {
                // packing the encrypted feature matrix //test packed ciphertexts
                std::vector<helib::Ctxt> packedCtV;
                HELIB_NTIMER_START(Encrypt);
                packedEncryptFeatureMatrix(packedCtV, V, publicKey, ea);
                HELIB_NTIMER_STOP(Encrypt);
                HELIB_NTIMER_START(Prediction);
                packedPredict(ctr, likelihoods, prior, packedCtV, publicKey, ea);
                HELIB_NTIMER_STOP(Prediction);
                // if (verbose){
                //     tp = helib::getTimerByName("packedPrediction");
                //     std::cout <<"Packed prediction costs " << tp -> getTime()
                //               << " seconds." << std::endl << std::endl;
                // }
            }

            std::vector<helib::PtxtArray> ptr;
            for (size_t i = 0; i < ctr.size(); i++)
            {
                helib::PtxtArray pt_tmp(ea);
                pt_tmp.decrypt(ctr[i], secretKey);
                ptr.push_back(pt_tmp);
            }
            if (verbose)
            {
                std::cout << "The decrypted result is: " << std::endl;
                for (size_t j = 0; j < ctr.size(); j++)
                {
                    std::vector<long> decArray;
                    ptr[j].store(decArray);
                    std::cout << hello::mods(decArray[0], p) << " ";
                }
                std::cout << std::endl
                          << std::endl;
                double log_q = ctr[0].logOfPrimeSet() / std::log(2.0);
                NTL::xdouble noise_bnd;
                noise_bnd = ctr[0].totalNoiseBound();

                std::cout << "before comparison:" << std::endl;
                std::cout << "log q = " << log_q << std::endl;
                std::cout << "log_2 of noise bound = " << NTL::log(noise_bnd) / std::log(2.0) << std::endl;
                std::cout << "capacity = " << ctr[0].capacity() << std::endl; // log[2](q/noise_bound)
            }
            HELIB_NTIMER_START(Comparison);
            comparator.compare(ctr[0], ctr[0], ctr[1]);
            HELIB_NTIMER_STOP(Comparison);
            if (verbose || (i == num_tests - 1))
            {
                double log_q = ctr[0].logOfPrimeSet() / std::log(2.0);
                double capacity = ctr[0].bitCapacity(); // log[2](q/noise_bound)
                NTL::xdouble noise_bnd;
                noise_bnd = ctr[0].totalNoiseBound();
                std::cout << "\nafter comparison:" << std::endl;
                std::cout << "log q = " << log_q << std::endl;
                std::cout << "log_2 of noise bound = " << NTL::log(noise_bnd) / std::log(2.0) << std::endl;
                std::cout << "capacity = " << ctr[0].capacity() << std::endl; // log[2](q/noise_bound)
            }

            std::vector<int> dec_vec;
            for (int j = 0; j < ctr.size(); j++)
            {
                helib::PtxtArray pt_vd(ea);
                HELIB_NTIMER_START(Decrypt);
                pt_vd.decrypt(ctr[j], secretKey);
                HELIB_NTIMER_STOP(Decrypt);
                std::vector<long> decArray;
                pt_vd.store(decArray);
                dec_vec.push_back(hello::mods(decArray[0], p));
            }
            res.push_back(dec_vec[0]);
            std::cout << std::endl
                      << "The prediction results are " << std::endl;
            hello::printVector(res);
        }
    } // end if not NAIVE_PACKED

    std::cout << std::endl
              << "The security level is about " << context.securityLevel() << std::endl;

    // double prediction_time, comparison_time;

    // tp = helib::getTimerByName("Prediction");
    // prediction_time = tp -> getTime();
    // std::cout <<"Prediction costs " << prediction_time << " seconds." << std::endl << std::endl;
    // tp = helib::getTimerByName("Comparison");
    // comparison_time =  tp -> getTime();
    // std::cout <<"Comparison costs " << comparison_time << " seconds." << std::endl << std::endl;
    // std::cout <<"All homomorphic computations cost  " << prediction_time + comparison_time << " seconds."  << std::endl;
    helib::printNamedTimer(std::cout, "Encrypt");
    helib::printNamedTimer(std::cout, "Prediction");
    helib::printNamedTimer(std::cout, "Comparison");
    helib::printNamedTimer(std::cout, "Decrypt");
}
