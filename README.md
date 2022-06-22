# BGVNaiveBayesPredictor #

BGVNaiveBayesPredictor is an open-source (Mozilla Public License Version 2.0) C++ library for Non-interactive Privacy-Preserving Naive Bayes Classifier based on the homomorphic encryption library [HElib][1].


## How to cite ##

	@incollection{ChenFengLiuWuYang2022,
		author="Chen, Jingwei 	and Feng, Yong and Liu, Yang and Wu, Wenyuan and Yang, Guanci",
		editor="Shi, Wenbo and Chen, Xiaofeng and Choo, Kim-Kwang Raymond",
		title="Non-interactive Privacy-Preserving Na{\"i}ve {B}ayes	Classifier Using Homomorphic Encryption",
		booktitle="Proceedings of the 4th EAI International Conference on Security and Privacy in New Computing Environments (Virtual Event, December 10--11, 2021)",
		year="2022",
		publisher="Springer",
		address="Cham",
		series = {Lecture Notes of the Institute for Computer Sciences, Social Informatics and Telecommunications Engineering},
		volume = "423", 
		pages="192--203",
		note = {\url{https://doi.org/10.1007/978-3-030-96791-8_14}}
	}



## Installation ##

### Dependencies ###

- [HElib][1] 2.1.0 or higher 

### Linux  ###

You should download the source code from github and then run

    mkdir build
    cd build
    cmake ..
    make
    
After these steps, an executable file named "BGVNaiveBayesPredictor" will be produced in the "build" folder.

## How to use ##

Usage: 

./BGVNaiveBayesPredictor [-m <arg>] [-method <arg>] [-n <arg>] [-p <arg>] [-r <arg>] [-b <arg>] [-c <arg>] [-hwt <arg>] [-bsp <arg>] [-k <arg>] [-s <arg>] [-d <arg>] [-f <arg>] [-v <arg>] <input-file1> <input-file2>                                                                                            

* <input-file1> the input model file. 
* <input-file2> the input test data file.                                                                
*  -m           the degree of the cyclotomic polynomial [ default=0 ] 
*  -method      method to predict, '0' for naive, '1' for packed, and '2' for naive_packed [ default=0 ]  
*  -n           the number of cpus [ default=0 ]                                                          
*  -p           characteristic of plaintext space [ default=2 ]                                           
*  -r           exponent of plaintext lifting [ default=1 ]                                               
*  -b           the number of bits required for the modulus chain, i.e., a lower bound on the sum of bits of ctxtPrimes and specialPrimes [ default=50 ]
*  -c           the number of digits/columns in the key-switching matrix [ default=3 ]                                
*  -hwt         Hamming weight of the secret-key [ default=120 ]                                          
*  -bsp         bits in special primes [ default=58 ]                                                     
*  -k           the security parameter if -m is not specified [ default=80 ]
*  -s           a lower bound on #slots [ default=1 ]
*  -d           the embedding degree [ default=1 ] 
*  -f           argmax returns former or later for equal maximum [ default=0 ]                            
*  -v           verbose [ default=0 ]
 

### An example ###
./BGVNaiveBayesPredictor ../data/model_bcw_s0 ../data/test_bcw -p 113 -m 12883 -b 250 -bsp 110 -hwt 0
     
    
[1]: https://github.com/homenc/HElib    "HElib"
