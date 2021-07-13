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
long calculateLevels(bool bootstrap, long bitSize)
{
  return bootstrap
              ? 900
              : 30 * (7 + NTL::NumBits(bitSize + 2)); // that should be enough
}
int main(int argc, char* argv[])
{
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
  

  bool bootstrap = false;
  long bitSize = 6;
  long seed = 0;
  long nthreads = 1;
  long L = calculateLevels(bootstrap, bitSize);
    std::cout << "---Initialising HE Environment ... ";
  // Initialize context
  // This object will hold information about the algebra used for this scheme.
  std::cout << "\nInitializing the Context ... ";
  HELIB_NTIMER_START(timer_Context);

 helib::Context context = helib::ContextBuilder<helib::BGV>()
                  .m(m)
                  .p(p)
                  .r(1)
                  .gens(gens)
                  .ords(ords)
                  .buildModChain(false)
                  .build();
                             
   context.buildModChain(L, c, /*willBeBootstrappable=*/bootstrap);
  HELIB_NTIMER_STOP(timer_Context);

  // Secret key management. 
  std::cout << "Creating secret key..." << std::endl;
  
  HELIB_NTIMER_START(timer_SecKey);
  // Create a secret key associated with the context.
  helib::SecKey secret_key(context);
  // Generate the secret key.
  secret_key.GenSecKey();
  HELIB_NTIMER_STOP(timer_SecKey);

  // Generate bootstrapping data.
  //  secret_key.genRecryptData();
  HELIB_NTIMER_START(timer_SKM);
  addSome1DMatrices(secret_key); // compute key-switching matrices
  HELIB_NTIMER_STOP(timer_SKM);

  addFrbMatrices(secret_key);

    // Public key management.
  // Set the secret key (upcast: SecKey is a subclass of PubKey).
  std::cout << "\nCreating Public Key ...";
  HELIB_NTIMER_START(timer_PubKey);
  const helib::PubKey& public_key = secret_key;
   HELIB_NTIMER_STOP(timer_PubKey);

  // Get the EncryptedArray of the context.
  const helib::EncryptedArray& ea = context.getEA();

  // Build the unpack slot encoding.
  std::vector<helib::zzX> unpackSlotEncoding;
  buildUnpackSlotEncoding(unpackSlotEncoding, ea);

  // Get the number of slot (phi(m)).
  long nslots = ea.size();
  std::cout << "Number of slots: " << nslots << std::endl;

    helib::printNamedTimer(std::cout << std::endl, "timer_Context");
    helib::printNamedTimer(std::cout, "timer_Chain");
    helib::printNamedTimer(std::cout, "timer_SecKey");
    helib::printNamedTimer(std::cout, "timer_SKM");
    helib::printNamedTimer(std::cout, "timer_PubKey");
    // helib::printNamedTimer(std::cout, "timer_PtxtCountryDB");
    // helib::printNamedTimer(std::cout, "timer_CtxtCountryDB");
  

}