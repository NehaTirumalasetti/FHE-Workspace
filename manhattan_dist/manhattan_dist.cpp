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

   helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .bits(bits)
                               .c(c)
                               .build();

  
  const helib::EncryptedArray& ea = context.getEA();

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

Ctxt get_abs_value(Ctxt query,vector<vector<double>> lookup,vector<pair<Ctxt, Ctxt>> encrypted_lookup_db)
{
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
  return abs_value;
}




int main(int argc, char* argv[])
{

  helib::ArgMap amap;
  amap.arg("m", m, "Cyclotomic polynomial ring");
  amap.arg("p", p, "Plaintext prime modulus");
  amap.arg("r", r, "Hensel lifting");
  amap.arg("bits", bits, "# of bits in the modulus chain");
  amap.arg("c", c, "# fo columns of Key-Switching matrix");
  amap.arg("nthreads", nthreads, "Size of NTL thread pool");
  amap.toggle().arg("-debug", debug, "Toggle debug output", "");
  amap.parse(argc, argv);

  helib::SecKey secret_key = helib::SecKey(context);
  // Generate the secret key
  secret_key.GenSecKey();
  helib::addSome1DMatrices(secret_key);

  // std::cout << "\nCreating Public Key ...";
  const helib::PubKey& public_key = secret_key;

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
  std::vector<std::pair<helib::Ptxt<helib::BGV>, helib::Ptxt<helib::BGV>>> lookup_ptxt;
  for (int i =0;i<lookup.size();i++) 
  {
  vector<long> v1;
  v1.push_back(lookup[i][0]);
  helib::Ptxt<helib::BGV> index(context,v1);

  vector<long> v2;
  v2.push_back(lookup[i][1]);
  helib::Ptxt<helib::BGV> value(context, v2);

  lookup_ptxt.emplace_back(std::move(index), std::move(value));
  }

  std::vector<std::pair<helib::Ctxt, helib::Ctxt>> encrypted_lookup_db;
  for (const auto& lookup_pair : lookup_ptxt) 
  {
  helib::Ctxt encrypted_index(public_key);
  helib::Ctxt encrypted_value(public_key);
  public_key.Encrypt(encrypted_index, lookup_pair.first);
  public_key.Encrypt(encrypted_value, lookup_pair.second);
  encrypted_lookup_db.emplace_back(std::move(encrypted_index),
                                    std::move(encrypted_value));
  }





  vector<long> qu;
  qu.push_back(-48);
  helib::Ptxt<helib::BGV> query_ptxt(context,qu);
  cout << query_ptxt[0] << endl;

  // Encrypt the query
  helib::Ctxt query(public_key);
  public_key.Encrypt(query, query_ptxt);

  Ctxt abs_value = get_abs_value(query, lookup,encrypted_lookup_db);

  helib::Ptxt<helib::BGV> plaintext_result(context);
  secret_key.Decrypt(plaintext_result, abs_value);


  cout << "Test2" << endl;

  cout<<plaintext_result[0]<<endl;

  
  cout << "done!" << endl;


 
  vector<vector<double>> interest_vector;
  interest_vector = read_csv("./interest_vector.csv");
  //Context& context = publicKey.getContext();
  vector<vector<Ctxt>> encdb ;
  vector<vector<Ptxt<BGV>>> db_ptxt;

  for(int i =0;i<interest_vector.size();i++)
  {
    vector<Ptxt<BGV>> row;
    for(int j =0;j<interest_vector[i].size();j++)
    {
      vector<long> v;
      v.push_back(interest_vector[i][j]);
      Ptxt<BGV> p (context, v);
      row.push_back(p);
    }
    db_ptxt.emplace_back(row);
  }
  cout << "Ptxt made" << endl;
  cout << db_ptxt[0][0][0]<< endl;

  

  // for(int i=0; i < interest_vector.size(); i++)
  // {
  //   vector<Ctxt> tmp;
  //   for(int j=0; j<=interest_vector[i].size(); j++)
  //   {
  //     if(j<interest_vector[i].size())
  //     {
  //       cout<<"\nIteration " << i << j;
  //       PtxtArray n(context, interest_vector[i][j]);
  //       // vector<long> v1;
  //       // v1.push_back(interest_vector[i][j]);
  //       // Ptxt<BGV> n(context,v1);
  //       Ctxt x(public_key);
  //       cout << "Created ptxt and ctxt" << endl;
  //       n.encrypt(x);
  //       //public_key.Encrypt(x, n);
  //       cout << "Encrypted ctxt" << endl;
  //       tmp.push_back(x);
  //       cout<<"\nIteration " << i << j <<" complete";
  //     }
  //   }
  //   // cout << "\n test after for";
  //   encdb.emplace_back(tmp);
  // }

  // vector<vector<double>> decrp;
  // for(int i = 0;i<encdb.size();i++)
  // {
  //   for(int j = 0 ;j<encdb[i].size();j++)
  //   {
  //       PtxtArray dec_x (public_key.getContext());
  //       dec_x.decrypt(encdb[i][j], secret_key);
  //       vector<double> x_ptxt;
  //       dec_x.store(x_ptxt);
  //       decrp.emplace_back(x_ptxt);
  //   }
  // }

  // cout << decrp[0][0] <<endl;
  return 0;
}