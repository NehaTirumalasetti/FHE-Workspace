#include <iostream>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>
#include "helayers/hebase/hebase.h"
#include <vector>
#include <fstream>
#include <sstream>

using namespace std;
using namespace helayers;
using namespace helib;

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
      // Plaintext prime modulus
  unsigned long p = 131;
  // Cyclotomic polynomial - defines phi(m)
  unsigned long m = 130; // this will give 48 slots
  // Hensel lifting (default = 1)
  unsigned long r = 1;
  // Number of bits of the modulus chain
  unsigned long bits = 1000;
  // Number of columns of Key-Switching matrix (default = 2 or 3)
  unsigned long c = 2;
  // Size of NTL thread pool (default =1)
  unsigned long nthreads = 1;
  // debug output (default no debug output)
  bool debug = false;

  helib::ArgMap amap;
  amap.arg("m", m, "Cyclotomic polynomial ring");
  amap.arg("p", p, "Plaintext prime modulus");
  amap.arg("r", r, "Hensel lifting");
  amap.arg("bits", bits, "# of bits in the modulus chain");
  amap.arg("c", c, "# fo columns of Key-Switching matrix");
  amap.arg("nthreads", nthreads, "Size of NTL thread pool");
  amap.toggle().arg("-debug", debug, "Toggle debug output", "");
  amap.parse(argc, argv);


  helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .bits(bits)
                               .c(c)
                               .build();


  helib::SecKey secret_key = helib::SecKey(context);
  // Generate the secret key
  secret_key.GenSecKey();
  helib::addSome1DMatrices(secret_key);

  std::cout << "\nCreating Public Key ...";
  const helib::PubKey& public_key = secret_key;
  const helib::EncryptedArray& ea = context.getEA();

    // Print the context
  std::cout << std::endl;
  if (debug)
    context.printout();

  // Print the security level
  // Note: This will be negligible to improve performance time.
  std::cout << "\n***Security Level: " << context.securityLevel()
            << " *** Negligible for this example ***" << std::endl;

  // Get the number of slot (phi(m))
  long nslots = ea.size();
  std::cout << "\nNumber of slots: " << nslots << std::endl;

  vector<vector<double>> lookup = read_csv("lookup.csv");
   std::vector<std::pair<helib::Ptxt<helib::BGV>, helib::Ptxt<helib::BGV>>>
      lookup_ptxt;
  for (int i =0;i<lookup.size();i++) {
    // if (debug) {
    //   std::cout << "\t\tname_addr_pair.first size = "
    //             << country_capital_pair.first.size() << " ("
    //             << country_capital_pair.first << ")"
    //             << "\tname_addr_pair.second size = "
    //             << country_capital_pair.second.size() << " ("
    //             << country_capital_pair.second << ")" << std::endl;
    // }
    vector<float> v1;
    v1.push_back(lookup[i][0]);
    helib::Ptxt<helib::BGV> index(context,v1);
    // // std::cout << "\tname size = " << country.size() << std::endl;
    // for (long i = 0; i < country_capital_pair.first.size(); ++i)
    //   country.at(i) = country_capital_pair.first[i];
    
    vector<float> v2;
    v2.push_back(lookup[i][1]);
    helib::Ptxt<helib::BGV> value(context, v2);
    // for (long i = 0; i < country_capital_pair.second.size(); ++i)
    //   capital.at(i) = country_capital_pair.second[i];
    lookup_ptxt.emplace_back(std::move(index), std::move(value));
  }

  std::vector<std::pair<helib::Ctxt, helib::Ctxt>> encrypted_lookup_db;
  for (const auto& lookup_pair : lookup_ptxt) {
    helib::Ctxt encrypted_index(public_key);
    helib::Ctxt encrypted_value(public_key);
    public_key.Encrypt(encrypted_index, lookup_pair.first);
    public_key.Encrypt(encrypted_value, lookup_pair.second);
    encrypted_lookup_db.emplace_back(std::move(encrypted_index),
                                      std::move(encrypted_value));
  }
  vector<float> qu;
  qu.push_back(-0.48);
  helib::Ptxt<helib::BGV> query_ptxt(context,qu);
  cout << query_ptxt[0] << endl;
   
    // Encrypt the query
  helib::Ctxt query(public_key);
  public_key.Encrypt(query, query_ptxt);

  std::vector<helib::Ctxt> mask;
  mask.reserve(lookup.size());
  for (const auto& encrypted_pair : encrypted_lookup_db) {
    helib::Ctxt mask_entry = encrypted_pair.first; // Copy of database key
    mask_entry -= query;                           // Calculate the difference
    mask_entry.power(p - 1);                       // Fermat's little theorem
    mask_entry.negate();                           // Negate the ciphertext
    mask_entry.addConstant(NTL::ZZX(1));           // 1 - mask = 0 or 1
    // Create a vector of copies of the mask
    std::vector<helib::Ctxt> rotated_masks(ea.size(), mask_entry);
    for (int i = 1; i < rotated_masks.size(); i++)
      ea.rotate(rotated_masks[i], i);             // Rotate each of the masks
    totalProduct(mask_entry, rotated_masks);      // Multiply each of the masks
    mask_entry.multiplyBy(encrypted_pair.second); // multiply mask with values
    mask.push_back(mask_entry);
  }

  // Aggregate the results into a single ciphertext
  // Note: This code is for educational purposes and thus we try to refrain
  // from using the STL and do not use std::accumulate
  helib::Ctxt abs_value = mask[0];
  for (int i = 1; i < mask.size(); i++)
    abs_value += mask[i];

  helib::Ptxt<helib::BGV> plaintext_result(context);
  secret_key.Decrypt(plaintext_result, abs_value);

    std::string string_result;
  for (long i = 0; i < plaintext_result.size(); ++i)
    string_result.push_back(static_cast<long>(plaintext_result[i]));
    
//    PtxtArray p3(context);
//    p3.decrypt(abs_value, secret_key);
//    vector<double> v3;
//    p3.store(v3);

//    cout << v3[0] << endl;



   cout << "Test1" << endl;

   cout << string_result << endl;

   cout << "Test2" << endl;

   cout<<plaintext_result[0]<<endl;

   
   cout << "done!" << endl;
   return 0;
}
