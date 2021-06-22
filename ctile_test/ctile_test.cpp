#include "helayers/hebase/helib/HelibCkksContext.h"
#include "helayers/hebase/hebase.h"
#include "helayers/hebase/BitwiseEvaluator.h"
#include "helayers/hebase/AlwaysAssert.h"
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <helib/helib.h>
#include "helayers/hebase/helib/HelibBgvContext.h"

using namespace std;
using namespace helayers;

vector<vector<double>> read_csv(string filename)
{
  vector<vector<double>> dataset;
  ifstream data_file(filename);

  if (!data_file.is_open())
    throw runtime_error(
        "Error: This example failed trying to open the data file: " + filename +
        "\n           Please check this file exists and try again.");

  vector<double> row;
  string line, entry, temp;

  if (data_file.good()) {
    // Read each line of file
    while (getline(data_file, line)) {
      row.clear();

      std::stringstream ss(line);
      while (getline(ss, entry, ',')) 
      {
        row.push_back(stod(entry));
      }
      // Add key value pairs to dataset
      dataset.push_back(row);
    }
  }

  data_file.close();
  return dataset;
}

bool isPowerOf2(int v) { return (v & v - 1) == 0; }

int main(int argc, char* argv[])
{
  // Plaintext prime modulus
  unsigned long p = 127;
  // Cyclotomic polynomial - defines phi(m)
  unsigned long m = 128; // this will give 32 slots
  // Hensel lifting (default = 1)
  unsigned long r = 1;
  // Number of bits of the modulus chain
  unsigned long bits = 1000;
  // Number of columns of Key-Switching matrix (default = 2 or 3)
  unsigned long c = 2;
  // Size of NTL thread pool (default =1)
  unsigned long nthreads = 1;

  HelibConfig conf;
  conf.p = p;
  conf.m = m;
  conf.r = r;
  conf.L = bits;
  conf.c = c;

  HelibBgvContext he;
  he.init(conf);

    //shared_ptr<HeContext> hePtr = HelibContext::create(HELIB_NOT_SECURE_BGV_24);
    
  // The HELIB_CKKS_8192 preset is a configuration where
  // Each ciphertext has 8192 slots, i.e., it can hold 8192 numbers.
  // In CKKS, each number can be a complex number.
  // IMPORTANT: It's
  // always required to test that the resulting security matches your needs.
  // Security levels may vary with different library versions.
  //always_assert(hePtr->getSecurityLevel() >= 128);
  

  // This will print the details of the underlying scheme:
  // name, configuration params, and security level.
  cout << "Using scheme: " << endl;
  //hePtr->printSignature();
  vector<double> vals1{0.5};
  //HeContext& he = *hePtr;

  
  // bool bitwise = he.getTraits().getSupportsBitwiseOperations();
  // std::cout << "pre" << bitwise << endl;
  // he.getTraits().setSupportsBitwiseOperations(true);
  // bool bitwise1 = he.getTraits().getSupportsBitwiseOperations();
  // std::cout << "post" << bitwise1 << endl;

  //BitwiseEvaluator bit = BitwiseEvaluator(he);
    // To encrypt it, we need an encoder . . .
  Encoder encoder(he);

  vector<vector<double>> lookup = read_csv("lookup.csv");

  vector<pair<CTile, CTile>> encrypted_lookup_db;
  for (int i =0;i<lookup.size();i++) {
    // Create a country ciphertext, and encrypt inside
    // the ascii vector representation of each country.
    // For example, Norway is represented
    // (78,111,114,119,97,121,  0,0,0, ...)
    CTile index(he);
    vector<double> vals1;
    vals1.push_back(lookup[i][0]);
    encoder.encodeEncrypt(index, vals1);
    // Similarly encrypt the capital name
    vector<double> vals2;
    vals1.push_back(lookup[i][1]);
    CTile value(he);
    encoder.encodeEncrypt(value, vals2);
    // Add the pair to the database
    encrypted_lookup_db.emplace_back(move(index), move(value));
  }


  vector<CTile> mask;
  mask.reserve(lookup.size());
  NativeFunctionEvaluator eval(he);
  long modulusP = he.getTraits().getArithmeticModulus();

  cout << "DB encrypted mask declared" << endl;

  vector<double> q{-0.48};
  CTile query(he);
  encoder.encodeEncrypt(query, q);
  
  cout << "Entering lookup for loop" <<endl;

  // For every entry in our database we perform the following
  // calculation:
  for (const auto& encrypted_pair : encrypted_lookup_db) {
    //  Copy of database key: a country name

    cout << "Entered lookup for loop" <<endl;
    CTile mask_entry = encrypted_pair.first;
    // Calculate the difference
    // In each slot now we'll have 0 when characters match,
    // or non-zero when there's a mismatch
    mask_entry.sub(query);

    // Fermat's little theorem:
    // Since the underlying plaintext are in modular arithmetic,
    // Raising to the power of modulusP convers all non-zero values
    // to 1.
    eval.powerInPlace(mask_entry, modulusP - 1);

    // Negate the ciphertext
    // Now we'll have 0 for match, -1 for mismatch
    mask_entry.negate();

    // Add +1
    // Now we'll have 1 for match, 0 for mismatch
    mask_entry.addScalar(1);

    // We'll now multiply all slots together, since
    // we want a complete match across all slots.

    // If slot count is a power of 2 there's an efficient way
    // to do it:
    // we'll do a rotate-and-multiply algorithm, similar to
    // a rotate-and-sum one.
    cout << "Power of 2 check" <<endl;
    if (isPowerOf2(he.slotCount())) {
      for (int rot = 1; rot < he.slotCount(); rot *= 2) {
        CTile tmp(mask_entry);
        tmp.rotate(-rot);
        mask_entry.multiply(tmp);
      }
    } else {
      // Otherwise we'll create all possible rotations, and multiply all of
      // them.
      // Note that for non powers of 2 a rotate-and-multiply algorithm
      // can still be used as well, though it's more complicated and
      // beyond the scope of this example.
      vector<CTile> rotated_masks(he.slotCount(), mask_entry);
      for (int i = 1; i < rotated_masks.size(); i++)
        rotated_masks[i].rotate(-i); // Rotate each of the masks
      eval.totalProduct(mask_entry,
                        rotated_masks); // Multiply each of the masks
    }

    // mask_entry is now either all 1s if query==country,
    // or all 0s otherwise.
    // After we multiply by capital name it will be either
    // the capital name, or all 0s.
    mask_entry.multiply(encrypted_pair.second);
    // We collect all our findings.
    mask.push_back(mask_entry);
  }

  CTile value = mask[0];
  for (int i = 1; i < mask.size(); i++)
    value.add(mask[i]);

  vector<double> res = encoder.decryptDecodeDouble(value);
  std::cout << "Value: " << res[0] << endl;


  // And a CTile object - this is our ciphertext object.
  CTile c1(he);
  // We'll now encrypt vals1 into c:
  // In HE encryption actually involves two steps: encode, then encrypt.
  // The following method does both.
  encoder.encodeEncrypt(c1, vals1);

  //CTile src(he);

  //bool b = bit.getIsSigned(c1);
  vector<double> res1 = encoder.decryptDecodeDouble(c1);
  std::cout << res1[0] << endl;
  //std::cout << b << endl;
  
  return 0;
}