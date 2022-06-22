# only 3 samples of bcw #
	./BGVNaiveBayesPredictor ../data/model_bcw_s0 ../data/test_bcw -p 113 -m 12883 -b 250 -bsp 110 -hwt 0


# all samples of bcw #

## lambda = 101 ##

	./BGVNaiveBayesPredictor ../data/model_bcw_s0 ../data/test_bcw_bak -p 113 -m 12883 -b 250 -bsp 110 -hwt 0 -method 2

## lambda = 76 ##
	./BGVNaiveBayesPredictor ../data/model_bcw_s0 ../data/test_bcw_bak -p 113 -m 12883 -b 310 -bsp 150 -hwt 0 -method 1


## lambda = 161 ##

	./BGVNaiveBayesPredictor ../data/model_bcw_s0 ../data/test_bcw_bak -p 113 -m 18829 -b 250 -bsp 110 -hwt 0 -method 2 -v 1


# all samples of iris #

## lambda = 151 ##
	./BGVNaiveBayesPredictor ../data/model_iris_s0 ../data/test_iris -p 37 -m 21355 -b 270 -bsp 110 -hwt 0 -method 2 -v 1
## lambda = 99 ##
	./BGVNaiveBayesPredictor ../data/model_iris_s0 ../data/test_iris -p 37 -m 14539 -b 270 -bsp 110 -hwt 0 -method 2 -v 1

## lambda = 74 ##
	./BGVNaiveBayesPredictor ../data/model_iris_s0 ../data/test_iris -p 37 -m 14539 -b 330 -bsp 150 -hwt 0 -method 1 -v 1
