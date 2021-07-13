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

  vector<long> v {12,32,23,29,26,22,30,24,33};
 vector<int> index {1,2,3,4,5,6,7,8,9};
//  cout << v[0] << endl;
//  long v =12;
//  cout << "Created distance vector" << endl;
 vector<vector<Ctxt>> encdb;
//  vector<CtPtrMat_vectorCt> encdbfin;
// cout << "Created vector of vector ctxt" << endl;
HELIB_NTIMER_START(timer_enc);
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
 HELIB_NTIMER_STOP(timer_enc);
  cout<<"\nSorting Distances... "<<endl;
  HELIB_NTIMER_START(timer_sorting);
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
  HELIB_NTIMER_STOP(timer_sorting);


  vector<vector<double>> iv = read_csv("interest_vector.csv");

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

    helib::printNamedTimer(std::cout << std::endl, "timer_Context");
    helib::printNamedTimer(std::cout, "timer_Chain");
    helib::printNamedTimer(std::cout, "timer_SecKey");
    helib::printNamedTimer(std::cout, "timer_SKM");
    helib::printNamedTimer(std::cout, "timer_PubKey");
    helib::printNamedTimer(std::cout, "timer_enc");
    helib::printNamedTimer(std::cout, "timer_sorting");
  

}