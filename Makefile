OPTIONS = -w -std=c++11 -DCURVE_ALT_BN128 -DNO_PROCPS -ggdb
#INCLUDE = -I/home/mls/zksnark/libsnark-usage-example/donator2 -I../libff-n -I../libsnark/src -I../libsnark/third_party -I../libff/src -I../libff/third_party -I../libfqfft/src  -I../zcash_w/src -I../libsnark-n1
#INCLUDE = -I /home/mls/zksnark/libsnark-usage-example/donator2 -I../libsnark/src -I../libsnark/third_party -I../libff/src -I../libff/third_party -I../libfqfft/src  -I../zcash_w/src
INCLUDE = -I libmsk/libff-n -I libmsk/libsnark/src -I libmsk/libsnark/third_party -I libmsk/libff/src -I libmsk/libff/third_party -I libmsk/libfqfft/src  -I libmsk/zcash_w/src
LIBPATH = -L libmsk/libsnark/build/src -L libmsk/libsnark/build/third_party -L libmsk/libff/build/src -L libmsk/zcash_w/build
LIBS    = -lpthread -lssl -lcrypto -lsnark -lff -lzm -lgmp -lstdc++ -lprocps -lgmpxx -lbitcoin_crypto -lbitcoin_util -lbitcoin_common -lbitcoin_zmq -lzcash
GCC		= g++

prac: test.cpp 
	$(GCC) $< -o $@ $(OPTIONS) $(INCLUDE) $(LIBPATH) $(LIBS) 
