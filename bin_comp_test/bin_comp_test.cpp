#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <tuple>
#include <NTL/BasicThreadPool.h>

#include <helib/helib.h>

#include <helib/intraSlot.h>
#include <helib/binaryArith.h>
#include <helib/binaryCompare.h>

#include <helib/debugging.h>


using namespace std;
using namespace helib;


int main(int argc, char* argv[])
{
  // {2, 15004, 15709, 22, 23, 683, 0, 4099, 13663, 0, 22, 31, 0, 25, 3},

  //2, 2304, 4641, 24, 7, 3, 221, 3979, 3095, 3760, 6, 2, -8, 25, 3},
   // { p, phi(m),   m,   d, m1, m2, m3,    g1,   g2,   g3, ord1,ord2,ord3,
      // B,c}
  // Plaintext prime modulus.
  long p = 2;
  // Cyclotomic polynomial - defines phi(m).
  long m =4641;//4095; //4641
  // Hensel lifting (default = 1).
  long r = 1;
  // Number of bits of the modulus chain.
  long bits = 25;//500; //25
  // Number of columns of Key-Switching matrix (typically 2 or 3).
  long c =3;// 2;//3
  // Factorisation of m required for bootstrapping.
  std::vector<long> mvec = {7, 3, 221};//{7, 5, 9, 13}; //7, 3, 221
  // Generating set of Zm* group.
  std::vector<long> gens = {3979, 3095, 3760};//{2341, 3277, 911}; // 3979, 3095, 3760
  // Orders of the previous generators.
  std::vector<long> ords = { 6, 2, -8};//{6, 4, 6};// 6, 2, -8

 helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .gens(gens)
                               .ords(ords)
                               .bits(bits)
                               .c(c)
                               .bootstrappable(true)
                               .mvec(mvec)
                               .build();

  
  const helib::EncryptedArray& ea = context.getEA();

  helib::SecKey secret_key = helib::SecKey(context);
  // Generate the secret key
  secret_key.GenSecKey();
  helib::addSome1DMatrices(secret_key);

  // std::cout << "\nCreating Public Key ...";
  const helib::PubKey& public_key = secret_key;
   // Print the context
  std::cout << std::endl;
  // if (debug)
  //   context.printout();

  // Print the security level
  // Note: This will be negligible to improve performance time.
  //std::cout << "\n***Security Level: " << context.securityLevel()
            //<< " *** Negligible for this example ***" << std::endl;

  // Get the number of slot (phi(m))
  long nslots = ea.size();
  std::cout << "\nNumber of slots: " << nslots << std::endl;

  static std::vector<helib::zzX> unpackSlotEncoding;
  buildUnpackSlotEncoding(unpackSlotEncoding, context.getEA());
  //std::vector<helib::zzX> bin_comp_test::unpackSlotEncoding;

  
  long bitSize = 6;//16

  bool bootstrap = false;
  /*
  vector<long> v {12,32,23,29,26,22,30,24,33};
  long pa = NTL::RandomBits_long(bitSize);
  long pb = NTL::RandomBits_long(bitSize + 1);
  long pMax = std::max(pa, pb);
  long pMin = std::min(pa, pb);
  bool pMu = pa > pb;
  bool pNi = pa < pb;
 
  cout << "pa " << pa <<endl;
  cout << "pb " << pb <<endl;
  // Encrypt the individual bits
  NTL::Vec<helib::Ctxt> eMax, eMin, enca, encb;

  helib::Ctxt mu(secret_key), ni(secret_key);
  resize(enca, bitSize, mu);
  resize(encb, bitSize + 1, ni);
  for (long i = 0; i <= bitSize; i++) {
    if (i < bitSize)
      secret_key.Encrypt(enca[i], NTL::ZZX((pa >> i) & 1));
    secret_key.Encrypt(encb[i], NTL::ZZX((pb >> i) & 1));
    if (bootstrap) { // put them at a lower level
       if (i < bitSize)
         enca[i].bringToSet(context.getCtxtPrimes(5));
       encb[i].bringToSet(context.getCtxtPrimes(5));
     }
  }

    std::vector<long> slotsMin, slotsMax, slotsMu, slotsNi;
  // comparison only
 helib::CtPtrs_VecCt wMin(eMin),
        wMax(eMax); // A wrappers around output vectors
    // comparison with max and min
    compareTwoNumbers(wMax,
                      wMin,
                      mu,
                      ni,
                      helib::CtPtrs_VecCt(enca),
                      helib::CtPtrs_VecCt(encb),
                      false,
                      &unpackSlotEncoding);
    decryptBinaryNums(slotsMax, wMax, secret_key, ea);
    decryptBinaryNums(slotsMin, wMin, secret_key, ea);
   // get rid of the wrapper
  ea.decrypt(mu, secret_key, slotsMu);
  ea.decrypt(ni, secret_key, slotsNi);
  cout<< "slotsMax "<<slotsMax[0] <<endl;
  cout<< "slotsMin " <<slotsMin[0] <<endl;
  cout<< "slotsMu "<<slotsMu[0] <<endl;
  cout<< "slotsNi " <<slotsNi[0] <<endl;
  cout<< "pMu "<<long(pMu) <<endl;
  cout<< "pNi " <<long(pNi) <<endl;
  cout<< "pMax "<<pMax <<endl;
  cout<< "pMin " <<pMin <<endl;*/


 


}





/*const helib::EncryptedArray& ea = context.getEA();

  // Choose two random n-bit integers
  long pa = NTL::RandomBits_long(bitSize);
  long pb = NTL::RandomBits_long(bitSize + 1);
  long pMax = std::max(pa, pb);
  long pMin = std::min(pa, pb);
  bool pMu = pa > pb;
  bool pNi = pa < pb;

  // Encrypt the individual bits
  NTL::Vec<helib::Ctxt> eMax, eMin, enca, encb;

  helib::Ctxt mu(secKey), ni(secKey);
  resize(enca, bitSize, mu);
  resize(encb, bitSize + 1, ni);
  for (long i = 0; i <= bitSize; i++) {
    if (i < bitSize)
      secKey.Encrypt(enca[i], NTL::ZZX((pa >> i) & 1));
    secKey.Encrypt(encb[i], NTL::ZZX((pb >> i) & 1));
    if (bootstrap) { // put them at a lower level
      if (i < bitSize)
        enca[i].bringToSet(context.getCtxtPrimes(5));
      encb[i].bringToSet(context.getCtxtPrimes(5));
    }
  }
#ifdef HELIB_DEBUG
  decryptAndPrint((std::cout << " before comparison: "),
                  encb[0],
                  secKey,
                  ea,
                  0);
#endif

  std::vector<long> slotsMin, slotsMax, slotsMu, slotsNi;
  // comparison only
  compareTwoNumbers(mu,
                    ni,
                    helib::CtPtrs_VecCt(enca),
                    helib::CtPtrs_VecCt(encb),
                    false,
                    &unpackSlotEncoding);
  ea.decrypt(mu, secKey, slotsMu);
  ea.decrypt(ni, secKey, slotsNi);
  EXPECT_EQ(std::make_pair(slotsMu[0], slotsNi[0]),
            std::make_pair((long)pMu, (long)pNi))
      << "Comparison (without min max) error: a=" << pa << ", b=" << pb
      << ", mu=" << slotsMu[0] << ", ni=" << slotsNi[0] << std::endl;
  if (helib_test::verbose) {
    std::cout << "Comparison (without min max) succeeded: ";
    std::cout << '(' << pa << ',' << pb << ")=> mu=" << slotsMu[0]
              << ", ni=" << slotsNi[0] << std::endl;
  }

  {
    helib::CtPtrs_VecCt wMin(eMin),
        wMax(eMax); // A wrappers around output vectors
    // comparison with max and min
    compareTwoNumbers(wMax,
                      wMin,
                      mu,
                      ni,
                      helib::CtPtrs_VecCt(enca),
                      helib::CtPtrs_VecCt(encb),
                      false,
                      &unpackSlotEncoding);
    decryptBinaryNums(slotsMax, wMax, secKey, ea);
    decryptBinaryNums(slotsMin, wMin, secKey, ea);
  } // get rid of the wrapper
  ea.decrypt(mu, secKey, slotsMu);
  ea.decrypt(ni, secKey, slotsNi);

  EXPECT_EQ(std::make_tuple(pMax, pMin, pMu, pNi),
            std::make_tuple(slotsMax[0], slotsMin[0], slotsMu[0], slotsNi[0]))
      << "Comparison (with min max) error: a=" << pa << ", b=" << pb
      << ", but min=" << slotsMin[0] << ", max=" << slotsMax[0]
      << ", mu=" << slotsMu[0] << ", ni=" << slotsNi[0] << std::endl;

  if (helib_test::verbose) {
    std::cout << "Comparison (with min max) succeeded: ";
    std::cout << '(' << pa << ',' << pb << ")=>(" << slotsMin[0] << ','
              << slotsMax[0] << "), mu=" << slotsMu[0] << ", ni=" << slotsNi[0]
              << std::endl;
  }
*/