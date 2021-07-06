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


Ctxt get_abs_value(Ctxt query,vector<vector<double>> lookup,vector<pair<Ctxt, Ctxt>> encrypted_lookup_db, EncryptedArray ea)
{
  long p = 2;
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
  // // {2, 15004, 15709, 22, 23, 683, 0, 4099, 13663, 0, 22, 31, 0, 25, 3},

  // //2, 2304, 4641, 24, 7, 3, 221, 3979, 3095, 3760, 6, 2, -8, 25, 3},
  //  // { p, phi(m),   m,   d, m1, m2, m3,    g1,   g2,   g3, ord1,ord2,ord3,
  //     // B,c}
  // // Plaintext prime modulus.
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


 helib::Context context = helib::ContextBuilder<helib::BGV>()
                  .m(m)
                  .p(p)
                  .r(1)
                  .gens(gens)
                  .ords(ords)
                  .buildModChain(false)
                  .build();
                             
   context.buildModChain(L, c, /*willBeBootstrappable=*/bootstrap);
  // Print the context.
  // context.printout();
  // std::cout << std::endl;
    // const helib::EncryptedArray& ea = context.getEA();
 
 
  // Print the security level.
  // std::cout << "Security: " << context.securityLevel() << std::endl;

  // Secret key management.
  std::cout << "Creating secret key..." << std::endl;
  // Create a secret key associated with the context.
  helib::SecKey secret_key(context);
  // Generate the secret key.
  secret_key.GenSecKey();

  // Generate bootstrapping data.
  //  secret_key.genRecryptData();
  addSome1DMatrices(secret_key); // compute key-switching matrices
  addFrbMatrices(secret_key);

  // Public key management.
  // Set the secret key (upcast: SecKey is a subclass of PubKey).
  const helib::PubKey& public_key = secret_key;

  // Get the EncryptedArray of the context.
  const helib::EncryptedArray& ea = context.getEA();

  // Build the unpack slot encoding.
  std::vector<helib::zzX> unpackSlotEncoding;
  buildUnpackSlotEncoding(unpackSlotEncoding, ea);

  // Get the number of slot (phi(m)).
  long nslots = ea.size();
  std::cout << "Number of slots: " << nslots << std::endl;

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
    Ctxt abs_val_first = get_abs_value(diff, lookup,encrypted_lookup_db,ea);
    
    helib::Ptxt<helib::BGV> plaintext_result1(context);
    secret_key.Decrypt(plaintext_result1, abs_val_first);
    cout<<"\nAbs val first : "<<plaintext_result1[0]<<endl;
    
    Ctxt diff2 = enc_ivdb[i].second;
    diff2 -= enc_ivdb[0].second;
    Ctxt abs_val_second = get_abs_value(diff2, lookup,encrypted_lookup_db, ea);
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


 vector<long> v {12,32,23,29,26,22,30,24,33};
 vector<int> index {1,2,3,4,5,6,7,8,9};
//  cout << v[0] << endl;
//  long v =12;
//  cout << "Created distance vector" << endl;
 vector<vector<Ctxt>> encdb;
//  vector<CtPtrMat_vectorCt> encdbfin;
// cout << "Created vector of vector ctxt" << endl;
 for (int i =0;i<v.size();i++)
 {
  //  cout << "Iteration i " << i << endl;
   Ctxt c(public_key);
    // cout << "Created ctxt c" << endl;
   vector<Ctxt> enc(bitSize, c);
  //  cout << "Created enc vector" << endl;
   for (long j = 0; j <bitSize; j++)
    {
      // cout << "Iteration j " << j << endl;
      secret_key.Encrypt(enc[j], NTL::ZZX((v[i] >> j) & 1));
      // cout << "Encrypted bit" << endl;
      if (bootstrap) 
      { // put them at a lower level
        enc[j].bringToSet(context.getCtxtPrimes(5));
      }
    }
    // cout << "Exited j loop" << endl;
    encdb.emplace_back(enc);
    // cout << "added enc to encdb" << endl;  
 }
  cout<<"\nSorting Distances... "<<endl;
  for(int i =0;i<v.size()-1;i++)
  {
    for(int j =0;j<v.size()-i-1;j++)
    {
      helib::Ctxt mu(secret_key), ni(secret_key);
      resize(encdb[j], bitSize, mu);
      resize(encdb[j+1], bitSize + 1, ni);    
      compareTwoNumbers(mu, //j>j+1 swap
                        ni,
                        helib::CtPtrs_vectorCt(encdb[j]),
                        helib::CtPtrs_vectorCt(encdb[j+1]),
                        false,
                        &unpackSlotEncoding);
      vector<long> slotsMu;
      ea.decrypt(mu, secret_key, slotsMu);
      if(slotsMu[0]==1)//swap
      {
        vector<Ctxt> temp;
        temp = encdb[j];
        encdb[j]=encdb[j+1];
        encdb[j+1]=temp;

        //swap index
        int tmp = index[j];
        index[j] =index[j+1];
        index[j+1] = tmp;
      } 
    }
  }
  // vector<vector<double>> iv = read_csv("interest_vector.csv");

  cout << "\nDistance\tIndex"; 
  for(int i =0;i<v.size();i++)
  {
    CtPtrs_vectorCt c (encdb[i]);
    vector<long> cc;
    decryptBinaryNums(cc, c, secret_key, ea);
    //cout<< cc[0] << endl;
    cout << "\n" << cc[0] << "\t\t" << index[i];

  }
  cout << "\nTop three recommendations : ";
  for(int i =0;i<3;i++)
  {
    CtPtrs_vectorCt c (encdb[i]);
    vector<long> cc;
    decryptBinaryNums(cc, c, secret_key, ea);
    // cout<< cc[0] << endl;
    cout << "\nInterest Vector of recommended user : " << iv[index[i]];
    cout << "\nDistance : " << cc[0] ;
  }
  cout << endl;
 


}

/*--------------OUTPUT----------------
m = 4641, p = 2, phi(m) = 2304
  ord(p) = 24
  normBnd = 2.32522
  polyNormBnd = 65.653
  factors = [3 7 13 17]
  generator 3979 has order (== Z_m^*) of 6
  generator 3095 has order (== Z_m^*) of 2
  generator 3760 has order (!!= Z_m^*) of 8
r = 1
nslots = 96
hwt = 0
ctxtPrimes = [6,7,8,9,10,11]
specialPrimes = [12,13]
number of bits = 448

security level = 0

Security: 0
Creating secret key...
Number of slots: 96
12
Created distance vector
Created vector of vector ctxt
Iteration i 0
Created ctxt c
Created enc vector
Iteration j 0
Encrypted bit
Iteration j 1
Encrypted bit
Iteration j 2
Encrypted bit
Iteration j 3
Encrypted bit
Iteration j 4
Encrypted bit
Iteration j 5
Encrypted bit
Exited j loop
added enc to encdb
Iteration i 1
Created ctxt c
Created enc vector
Iteration j 0
Encrypted bit
Iteration j 1
Encrypted bit
Iteration j 2
Encrypted bit
Iteration j 3
Encrypted bit
Iteration j 4
Encrypted bit
Iteration j 5
Encrypted bit
Exited j loop
added enc to encdb
Iteration i 2
Created ctxt c
Created enc vector
Iteration j 0
Encrypted bit
Iteration j 1
Encrypted bit
Iteration j 2
Encrypted bit
Iteration j 3
Encrypted bit
Iteration j 4
Encrypted bit
Iteration j 5
Encrypted bit
Exited j loop
added enc to encdb
Iteration i 3
Created ctxt c
Created enc vector
Iteration j 0
Encrypted bit
Iteration j 1
Encrypted bit
Iteration j 2
Encrypted bit
Iteration j 3
Encrypted bit
Iteration j 4
Encrypted bit
Iteration j 5
Encrypted bit
Exited j loop
added enc to encdb
Iteration i 4
Created ctxt c
Created enc vector
Iteration j 0
Encrypted bit
Iteration j 1
Encrypted bit
Iteration j 2
Encrypted bit
Iteration j 3
Encrypted bit
Iteration j 4
Encrypted bit
Iteration j 5
Encrypted bit
Exited j loop
added enc to encdb
Iteration i 5
Created ctxt c
Created enc vector
Iteration j 0
Encrypted bit
Iteration j 1
Encrypted bit
Iteration j 2
Encrypted bit
Iteration j 3
Encrypted bit
Iteration j 4
Encrypted bit
Iteration j 5
Encrypted bit
Exited j loop
added enc to encdb
Iteration i 6
Created ctxt c
Created enc vector
Iteration j 0
Encrypted bit
Iteration j 1
Encrypted bit
Iteration j 2
Encrypted bit
Iteration j 3
Encrypted bit
Iteration j 4
Encrypted bit
Iteration j 5
Encrypted bit
Exited j loop
added enc to encdb
Iteration i 7
Created ctxt c
Created enc vector
Iteration j 0
Encrypted bit
Iteration j 1
Encrypted bit
Iteration j 2
Encrypted bit
Iteration j 3
Encrypted bit
Iteration j 4
Encrypted bit
Iteration j 5
Encrypted bit
Exited j loop
added enc to encdb
Iteration i 8
Created ctxt c
Created enc vector
Iteration j 0
Encrypted bit
Iteration j 1
Encrypted bit
Iteration j 2
Encrypted bit
Iteration j 3
Encrypted bit
Iteration j 4
Encrypted bit
Iteration j 5
Encrypted bit
Exited j loop
added enc to encdb
12
22
23
*/

// long bitSize = 6;//16

  // bool bootstrap = true;
  
 /* vector<long> v {12,32,23,29,26,22,30,24,33};
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

 //  .m(m)
                              //  .p(p)
                              //  .r(r)
                              //  .gens(gens)
                              //  .ords(ords)
                              //  .bits(bits)
                              //  .c(c)
                              //  .bootstrappable(true)
                              //  .mvec(mvec)
                              //  .build();


                               //Plaintext prime modulus.
  // long p = 2;
  // // Cyclotomic polynomial - defines phi(m).
  // long m = 4095;
  // // Hensel lifting (default = 1).
  // long r = 1;
  // // Number of bits of the modulus chain.
  // long bits = 500;
  // // Number of columns of Key-Switching matrix (typically 2 or 3).
  // long c = 2;
  // // Factorisation of m required for bootstrapping.
  // std::vector<long> mvec = {7, 5, 9, 13};
  // // Generating set of Zm* group.
  // std::vector<long> gens = {2341, 3277, 911};
  // // Orders of the previous generators.
  // std::vector<long> ords = {6, 4, 6};