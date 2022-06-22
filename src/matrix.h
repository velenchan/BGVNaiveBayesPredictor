#ifndef HELLO_MATRIX_H
#define HELLO_MATRIX_H

#include <helib/helib.h>
#include <helib/matmul.h>

using namespace helib;

namespace hello{

template<typename T>
class matrix{
    protected:
    std::size_t n, d;
    std::vector<std::vector<T> > M;

    public:

    //matrix();

    // empty matrix
    matrix() : n(0), d(0){}

    //~matrix();

    //  rows * cols, all elements are initialized with the default constructor of T
    matrix(std::size_t rows, std::size_t cols) : n(0), d(0){
        resize(rows, cols);
    }


    void clear() {
        n = d = 0;
        M.clear();
    }

    void resize(std::size_t rows, std::size_t cols){
        std::size_t j;
        n = rows;
        d = cols;
        M.resize(d);
        for (j = 0; j < d; j++){
            M[j].resize(n);
        }
    }// resize


    

    // return the number of rows
    int getRows() const{
        return n;
    }

    // return the number of columns
    int getCols() const{
        return d;
    }

    // a reference to the element (i, j)
    T& operator() (const std::size_t i, const std::size_t j)     {return M[j][i];}

    const T& operator() (const std::size_t i, const std::size_t j) const    {return M[j][i];}


    inline  T& get(const std::size_t i, const std::size_t j)    {return M[j][i];}

    inline  void set(const std::size_t i, const std::size_t j, const T a)                {M[j][i] = a;}

    

    //the transpose of the matrix
    matrix<T> transpose() const {
        matrix<T> B(d, n);
        for (std::size_t i = 0; i < n; i++)
            for (std::size_t j = 0; j < d; j++)
                B(j, i) = M[j][i];
        return B;
    }
    
    // return the i-th row of the matrix; indices start from 0.
    std::vector<T> getRow(std::size_t i) {
        std::vector<T> v;
        v.resize(d);
        for (std::size_t j = 0 ; j < d; j++)
            v[j] = M[j][i];
        
        return v;
    }

     std::vector<T> getRow(std::size_t i) const {
        std::vector<T> v;
        v.resize(d);
        for (std::size_t j = 0 ; j < d; j++)
            v[j] = M[j][i];
        
        return v;
    }

    // return the last row of the matrix
    std::vector<T> getLastRow(){
        return getRow(n-1);
    }

    std::vector<T> getLastRow() const {
        return getRow(n-1);
    }

}; //end of class matrix





template <typename T> 
void transpose(matrix<T> A, const matrix<T>& B);


//              1   2   
// input:   A = 4   5   
//              7   8  
// output: a Ptxt vector ptr with 2 entries
//         the i-th entry of ctr is the ciphertext 
//         of the i-th column of A.



    
// add all entries of V to s
template <typename T> void sumOfVector(T& s, const std::vector<T>& v);


// comput v[j] + ... + v[k-1]
template <typename T>
void partialSumOfVector(T& s, const std::vector<T>& v, const std::size_t& j, const std::size_t& k);


template <typename T>
void printMatrix(matrix<T>& M, std::ostream& out = std::cout);

template <typename T>
void printVector(std::vector<T>& v, std::ostream& out = std::cout);

template <typename type, typename T> // T = int or long
class FullMatrix : public MatMulFull_derived<type>
{
  PA_INJECT(type)
  const EncryptedArray& ea;
  std::vector<std::vector<RX>> data;

public:
  FullMatrix(const EncryptedArray& _ea, const hello::matrix<T>& A) : ea(_ea)
  {
    long n = ea.size(); // n = #slots
    long d = ea.getDegree(); // d = the degree of each slot
    long r = A.getRows();
    long c = A.getCols();

    RBak bak;
    bak.save();
    ea.getContext().getAlMod().restoreContext();
    data.resize(n);
    for (long i : range(n)) {
      data[i].resize(n);
      for (long j : range(n))
        if ((i<r) && (j<c))
            data[i][j] = A(i, j);
        else
            data[i][j] = 0;
    }
  }

  bool get(RX& out, long i, long j) const override
  {
    assertInRange(i, 0l, ea.size(), "Matrix index out of range");
    assertInRange(j, 0l, ea.size(), "Matrix index out of range");
    if (IsZero(data[i][j]))
      return true;
    out = data[i][j];
    return false;
  }

  const EncryptedArray& getEA() const override { return ea; }
};


template<typename T> // T = int or long
MatMulFull* buildFullMatrix(const EncryptedArray& ea, const hello::matrix<T>& A);

template <typename T> 
void transpose(matrix<T> B, const matrix<T>& A)
{
    std::size_t n, d;
    n = A.getRows();
    d = A.getCols();
    B.resize(d, n);
    for (std::size_t i = 0; i < n; i++)
        for (std::size_t j = 0; j < d; j++)
            B(j, i) = A(i, j);
}



template <typename T>
void sumOfVector(T& s, const std::vector<T>& v)
{
    s = 0;
    for (std::size_t i = 0; i < v.size(); i++)
        s += v[i];
}



template <typename T>
void partialSumOfVector(T& s, const std::vector<T>& v, const std::size_t& j, const std::size_t& k)
{
    if ((j > k) || (j < 0) || (k > v.size()-1)){
        std::cerr << "indices j and k must satisfy j < k" << std::endl;
        return;
    }
    s = 0;
    for (std::size_t i = j; i < k; i++)
        s += v[i];
}


template <typename T>
void printMatrix(matrix<T>& M, std::ostream& out )
{
    for (std::size_t i = 0; i < M.getRows(); ++i) {
        for (std::size_t j = 0; j < M.getCols(); ++j)
            out << M(i, j) << " ";
        out << "\n";
    }
}// printmatrix


template <typename T>
void printVector(std::vector<T>& v, std::ostream& out )
{
    
    for (std::size_t j = 0; j < v.size(); ++j)
        out << v[j] << " ";
    out << "\n";
}// printVector










template<typename T> // T = int or long
MatMulFull* buildFullMatrix(const EncryptedArray& ea, const hello::matrix<T>& A)
{
    switch (ea.getTag()) {
        case PA_GF2_tag: {
            return new FullMatrix<PA_GF2, T>(ea, A);
        }
        case PA_zz_p_tag: {
            return new FullMatrix<PA_zz_p, T>(ea, A);
        }
        default:
            return nullptr;
    }
}

}// namespace hello
#endif // matrix.h