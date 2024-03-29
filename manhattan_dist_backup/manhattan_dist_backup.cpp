#include <iostream>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>
#include "helayers/hebase/hebase.h"
#include <vector>
#include <fstream>
#include <sstream>
#include <helib/binaryArith.h>
#include <helib/binaryCompare.h>
#include <helib/intraSlot.h>
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
        //cout << entry;
        if(!entry.empty())
        {
          row.push_back(stod(entry));
        }
        
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
  //std::cout << "\n***Security Level: " << context.securityLevel()
            //<< " *** Negligible for this example ***" << std::endl;

  // Get the number of slot (phi(m))
  long nslots = ea.size();
  std::cout << "\nNumber of slots: " << nslots << std::endl;
  
//cout << "\nBefore read_csv";
vector<vector<double>> iv = read_csv("interest_vector.csv");
//cout << "\nAfter read_csv";
  std::vector<std::pair<helib::Ptxt<helib::BGV>, helib::Ptxt<helib::BGV>>> iv_ptxt;
 //cout << "\nBefore for";
  for (int i =0;i<iv.size();i++) 
  {
    vector<long> v1;
    v1.push_back(iv[i][0]);
    helib::Ptxt<helib::BGV> index(context,v1);
    //cout << "\nIndex ptxt created ";

    vector<long> v2;
    v2.push_back(iv[i][1]);
    helib::Ptxt<helib::BGV> value(context, v2);
    //cout << "\nValue ptxt created ";

    iv_ptxt.emplace_back(std::move(index), std::move(value));
    //cout << "\nLookup ptxt created ";
  }

  std::vector<std::pair<helib::Ctxt, helib::Ctxt>> enc_ivdb;
  for (const auto& iv_pair : iv_ptxt) 
  {
    helib::Ctxt encrypted_index(public_key);
    helib::Ctxt encrypted_value(public_key);
    //cout << "\nCtxts created ";

    public_key.Encrypt(encrypted_index, iv_pair.first);
    public_key.Encrypt(encrypted_value, iv_pair.second);
    //cout << "\nEncryption complete ";

    enc_ivdb.emplace_back(std::move(encrypted_index),
                                      std::move(encrypted_value));
    //cout << "\nEmplace back completed";
  }



  vector<vector<double>> lookup = read_csv("lookup.csv");
  //vector<vector<double>> lookup = read_csv("./interest_vector.csv");
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




  vector<pair<long, int>> dist_dec;
  vector<Ctxt> distances;
  for (int i=1; i<enc_ivdb.size(); i++)
  {
    Ctxt diff = enc_ivdb[i].first;
    diff -= enc_ivdb[0].first;
    Ctxt abs_val_first = get_abs_value(diff, lookup,encrypted_lookup_db);
    
    helib::Ptxt<helib::BGV> plaintext_result1(context);
    secret_key.Decrypt(plaintext_result1, abs_val_first);
    cout<<"\nAbs val first : "<<plaintext_result1[0]<<endl;
    
    Ctxt diff2 = enc_ivdb[i].second;
    diff2 -= enc_ivdb[0].second;
    Ctxt abs_val_second = get_abs_value(diff2, lookup,encrypted_lookup_db);
    helib::Ptxt<helib::BGV> plaintext_result2(context);
    secret_key.Decrypt(plaintext_result2, abs_val_second);
    cout<<"\nAbs val second : "<<plaintext_result2[0]<<endl;

    Ctxt dist = abs_val_first;
    dist += abs_val_second;
    helib::Ptxt<helib::BGV> plaintext_result3(context);
    secret_key.Decrypt(plaintext_result3, dist);
    cout<<"\nAddition : "<<plaintext_result3[0]<<endl;
    cout << "done!" << endl;

    dist_dec.emplace_back(move(plaintext_result3[0]), move(i));

    distances.emplace_back(move(dist));
  }
  
  //cout << "\nDist Ptxt : " << dist_ptxt[0];
  sort(dist_dec.begin(), dist_dec.end());
  /*
  cout << "\nDistance\tIndex"; 
  for(int i=0; i<dist_dec.size(); i++)
  {
    cout << "\n" << dist_dec[i].first << "\t\t" << dist_dec[i].second;
  }
  */

  cout << "\nTop three recommendations : ";
  for(int i=0; i<3; i++)
  {
    cout << "\nInterest Vector of recommended user : " << iv[dist_dec[i].second];
    cout << "\nDistance : " << dist_dec[i].first ;
  }

  return 0;
}

 /*
 --------------- BACKUP SORT ----------------
  //cout << "\nDist Ptxt : " << dist_ptxt[0];
  sort(dist_dec.begin(), dist_dec.end());

  cout << "\nDistance\tIndex"; 
  for(int i=0; i<dist_dec.size(); i++)
  {
    cout << "\n" << dist_dec[i].first << "\t\t" << dist_dec[i].second;
  }
 */

/*

----- OUTPUT -----

Abs val first : [6]

Abs val second : [6]

Addition : [12]
done!

Abs val first : [24]

Abs val second : [8]

Addition : [32]
done!

Abs val first : [2]

Abs val second : [21]

Addition : [23]
done!

Abs val first : [25]

Abs val second : [4]

Addition : [29]
done!

Abs val first : [20]

Abs val second : [6]

Addition : [26]
done!

Abs val first : [5]

Abs val second : [17]

Addition : [22]
done!

Abs val first : [21]

Abs val second : [9]

Addition : [30]
done!

Abs val first : [9]

Abs val second : [15]

Addition : [24]
done!

Abs val first : [8]

Abs val second : [25]

Addition : [33]
done!

Distance        Index
12              1
22              6
23              3
24              8
26              5
29              4
30              7
32              2


Top three recommendations : 
Interest Vector of recommended user : [18 48]
Distance : 12
Interest Vector of recommended user : [29 37]
Distance : 22
Interest Vector of recommended user : [26 33]
Distance : 23

*/