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



  // And a CTile object - this is our ciphertext object.
  CTile c1(he);
  // We'll now encrypt vals1 into c:
  // In HE encryption actually involves two steps: encode, then encrypt.
  // The following method does both.
  encoder.encodeEncrypt(c1, vals1);

  //CTile src(he);

  //bool b = bit.getIsSigned(c1);
  vector<double> res = encoder.decryptDecodeDouble(c1);
  std::cout << res[0] << endl;
  //std::cout << b << endl;
  
  return 0;
}