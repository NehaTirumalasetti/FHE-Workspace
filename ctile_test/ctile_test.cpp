#include "helayers/hebase/helib/HelibCkksContext.h"
#include "helayers/hebase/hebase.h"
#include "helayers/hebase/BitwiseEvaluator.h"
#include "helayers/hebase/AlwaysAssert.h"
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <helib/helib.h>

using namespace std;
using namespace helayers;

int main(int argc, char* argv[])
{
    shared_ptr<HeContext> hePtr = HelibContext::create(HELIB_CKKS_8192);

  // The HELIB_CKKS_8192 preset is a configuration where
  // Each ciphertext has 8192 slots, i.e., it can hold 8192 numbers.
  // In CKKS, each number can be a complex number.
  // IMPORTANT: It's
  // always required to test that the resulting security matches your needs.
  // Security levels may vary with different library versions.
  always_assert(hePtr->getSecurityLevel() >= 128);

  // This will print the details of the underlying scheme:
  // name, configuration params, and security level.
  cout << "Using scheme: " << endl;
  hePtr->printSignature();
  vector<double> vals1{0.5};
  HeContext& he = *hePtr;

  // To encrypt it, we need an encoder . . .
  Encoder encoder(he);

  // And a CTile object - this is our ciphertext object.
  CTile c1(he);
  // We'll now encrypt vals1 into c:
  // In HE encryption actually involves two steps: encode, then encrypt.
  // The following method does both.
  encoder.encodeEncrypt(c1, vals1);

  CTile src(he);
  bool b = src.getIsSigned(*c1);

  vector<double> res = encoder.decryptDecodeDouble(c1);
  std::cout << res[0] << endl;
  return 0;
}