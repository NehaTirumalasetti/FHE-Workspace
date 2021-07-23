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
//std::vector<zzX>* unpackSlotEncoding = nullptr)


/*void bubbleSort1(vector<CtPtrs_vectorCt> op,vector<CtPtrs_vectorCt> encdb, vector<int> index , EncryptedArray ea , SecKey secret_key)
{//vector<vector<Ctxt>> encdb
   
    cout<<"Entered function" <<endl;
    /*for(int i =0;i<encdb.size()-1;i++)
      {
        cout<<"Entered for loop i" <<endl;
        for(int j =0;j<encdb.size()-i-1;j++)
        {
          // If `a`=`b` then `mu`=`ni`=`0`
          cout<<"Entered for loop j" <<endl;
            helib::Ctxt mu(secret_key), ni(secret_key);
           cout<<"starting compare" <<endl;
            compareTwoNumbers(mu, //j>j+1 swap //a>b
                              ni, //a<b
                              encdb[j],
                              encdb[j+1]);//,
                              // helib::CtPtrs_vectorCt(encdb[j]),
                              // helib::CtPtrs_vectorCt(encdb[j+1]));//,
                              // false,
                              // &unpackSlotEncoding);
            vector<long> slotsMu;
            ea.decrypt(mu, secret_key, slotsMu);
            cout<<"Completed compare" <<endl;
            
            if(slotsMu[0]==1)//j>j+1
            {
              cout<<"Doing swap" <<endl;
              op.emplace_back(encdb[j+1]);
              op.emplace_back(encdb[j]);
              cout<<"completed swap" <<endl;
            }
            else
            {
              op.emplace_back(encdb[j]);
              op.emplace_back(encdb[j+1]);
            }
            cout<<"Completed loop j" <<endl;
        }
      }

       helib::Ctxt mu(secret_key), ni(secret_key);
           cout<<"starting store" <<endl;
           CtPtrs_vectorCt a = encdb[0];
           CtPtrs_vectorCt b = encdb[1];
           cout<<"starting compare" <<endl;
            compareTwoNumbers(mu, //j>j+1 swap //a>b
                              ni, //a<b
                              a,
                              b); // issue with compare causing segmentation fault
      
  // return encdb;
}*/
vector<vector<Ctxt>> bubbleSort(vector<vector<Ctxt>> encdb,  EncryptedArray ea , SecKey secret_key)
{
    cout<<"entered function" <<endl;
    // Context& context = c.getContext();
    for(int i =0;i<encdb.size()-1;i++)
    {
    for(int j =0;j<encdb.size()-i-1;j++)
    {
      cout<<"creating mu and ni"<<endl;
      // If `a`=`b` then `mu`=`ni`=`0`
      // helib::Ctxt mu(secret_key), ni(secret_key);
      helib::Ctxt mu(encdb[0][0].getPubKey()), ni(encdb[0][0].getPubKey());
      cout<<"comparing 2 numbers"<<endl;
      compareTwoNumbers(mu, //j>j+1 swap //a>b
                        ni, //a<b
                        helib::CtPtrs_vectorCt(encdb[j]),
                        helib::CtPtrs_vectorCt(encdb[j+1]));//,
                        // false,
                        // &unpackSlotEncoding);
      cout<<"decrypting mu"<<endl;
      vector<long> slotsMu;
      ea.decrypt(mu, secret_key, slotsMu);
      if(slotsMu[0]==1)//swap
      {
        cout<<"swapping"<<endl;
        vector<Ctxt> temp;
        temp = encdb[j];
        encdb[j]=encdb[j+1];
        encdb[j+1]=temp;
      }
    }
    }
    cout<<"leaving function" <<endl;
    return encdb;
   
}
vector<vector<Ctxt>> insertionSort(vector<vector<Ctxt>> encdb,  EncryptedArray ea , SecKey secret_key)
{
  for(int i = 1;i<encdb.size();i++)
  {
    int j = i-1;
    vector<Ctxt> key = encdb[i];
    while(j>=0)
    {
      helib::Ctxt mu(encdb[0][0].getPubKey()), ni(encdb[0][0].getPubKey());
      cout<<"comparing 2 numbers"<<endl;
      compareTwoNumbers(mu, //j>key swap //a>b
                        ni, //a<b
                        helib::CtPtrs_vectorCt(encdb[j]),
                        helib::CtPtrs_vectorCt(key));
                        // false,
                        // &unpackSlotEncoding);
      cout<<"decrypting mu"<<endl;
      vector<long> slotsMu;
      ea.decrypt(mu, secret_key, slotsMu);
      if(slotsMu[0]==1)//swap
      {
        encdb[j+1]=encdb[j];
        j=j-1;    
      }
      else
        break;
    }
    encdb[j+1] = key;
  }
  return encdb;
}
long testcomp(vector<vector<Ctxt>> encdb, EncryptedArray ea, SecKey secret_key)
{
  cout<<"creating mu and ni"<<endl;
  Ctxt mu(secret_key),ni(secret_key);
  cout<<"comparing 2 numbers"<<endl;
  compareTwoNumbers(mu,ni,CtPtrs_vectorCt(encdb[0]),CtPtrs_vectorCt(encdb[1]));
  cout<<"decrypting mu"<<endl;
  vector<long> slotsMu;
  ea.decrypt(mu, secret_key, slotsMu);  
  cout<<"leaving function" <<endl;
  return(slotsMu[0]);

}
void merge(vector<vector<Ctxt>> array, int left,int mid, int const right, EncryptedArray ea, SecKey secret_key)
{
  int subArr1 = mid-left+1;
  int subArr2 = right - mid;
  vector<vector<Ctxt>> leftArr, rightArr;
  for(int i=0;i<subArr1;i++)
    leftArr[i] = array[left + i];
  for(int i=0;i<subArr1;i++)
    rightArr[i] = array[mid + 1 + i];
  int indexsubarr1 = 0, indexsubarr2 = 0, indexmergearray = left;
    while (indexsubarr1 < subArr1 && indexsubarr2 < subArr2) {

      helib::Ctxt mu(array[0][0].getPubKey()), ni(array[0][0].getPubKey());
      cout<<"comparing 2 numbers"<<endl;
      compareTwoNumbers(mu, //j>key swap //a>b
                        ni, //a<b
                        helib::CtPtrs_vectorCt(rightArr[indexsubarr2]),
                        helib::CtPtrs_vectorCt(leftArr[indexsubarr1]));
                        // false,
                        // &unpackSlotEncoding);
      cout<<"decrypting mu"<<endl;
      vector<long> slotsMu;
      ea.decrypt(mu, secret_key, slotsMu);
      if(slotsMu[0]==1)//swap
      {
        array[indexmergearray] = leftArr[indexsubarr1];
        indexsubarr1++;
      }
      else
      {
        array[indexmergearray] = rightArr[indexsubarr2];
        indexsubarr2++;
      }
      indexmergearray++;
    }
     while (indexsubarr1 < subArr1) {
        array[indexmergearray] = leftArr[indexsubarr1];
        indexsubarr1++;
        indexmergearray++;
    }
    while (indexsubarr2 < subArr2) {
        array[indexmergearray] = rightArr[indexsubarr2];
        indexsubarr2++;
        indexmergearray++;
    }
}
void mergeSort(vector<vector<Ctxt>> array, int begin, int end, EncryptedArray ea, SecKey secret_key)
{
    if (begin >= end)
        return; // Returns recursivly
 
    auto mid = begin + (end - begin) / 2;
    mergeSort(array, begin, mid,ea, secret_key);
    mergeSort(array, mid + 1, end, ea, secret_key);
    merge(array, begin, mid, end, ea, secret_key);
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
//  vector<CtPtrs_vectorCt> bindb;
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
    // bindb.emplace_back(CtPtrs_vectorCt(enc));
    // cout << "added enc to encdb" << endl;  
 }
 HELIB_NTIMER_STOP(timer_enc);
  cout<<"\nSorting... "<<endl;

  HELIB_NTIMER_START(timer_sorting);
  //  vector<vector<Ctxt>> encdb1 = bubbleSort(encdb, ea, secret_key);
  // vector<vector<Ctxt>> encdb1 = insertionSort(encdb, ea, secret_key);
   mergeSort(encdb,0,encdb.size()-1, ea, secret_key);
  HELIB_NTIMER_STOP(timer_sorting);




  cout << "\nSorted values:"; 
  for(int i =0;i<v.size();i++)
  {
     CtPtrs_vectorCt c (encdb[i]);
    vector<long> cc;
    decryptBinaryNums(cc, c, secret_key, ea);
    //cout<< cc[0] << endl;
    cout << "\n" << cc[0];
  }

    helib::printNamedTimer(std::cout << std::endl, "timer_Context");
    helib::printNamedTimer(std::cout, "timer_Chain");
    helib::printNamedTimer(std::cout, "timer_SecKey");
    helib::printNamedTimer(std::cout, "timer_SKM");
    helib::printNamedTimer(std::cout, "timer_PubKey");
    helib::printNamedTimer(std::cout, "timer_enc");
    helib::printNamedTimer(std::cout, "timer_sorting");
  

}

/*  OUTPUT

---Initialising HE Environment ... 
Initializing the Context ... Creating secret key...

Creating Public Key ...Number of slots: 96

Sorting Distances... 

Distance        Index
12              1
22              6
23              3
24              8
26              5
29              4
30              7
32              2
33              9
Top three recommendations : 
Interest Vector of recommended user : [18 48]
Distance : 12
Interest Vector of recommended user : [29 37]
Distance : 22
Interest Vector of recommended user : [26 33]
Distance : 23

  timer_Context: 0.219583 / 1 = 0.219583   [/opt/IBM/FHE-Workspace/sort_test/sort_test.cpp:91]
  timer_SecKey: 0.074141 / 1 = 0.074141   [/opt/IBM/FHE-Workspace/sort_test/sort_test.cpp:108]
  timer_SKM: 0.38515 / 1 = 0.38515   [/opt/IBM/FHE-Workspace/sort_test/sort_test.cpp:117]
  timer_PubKey: 0 / 1 = 0   [/opt/IBM/FHE-Workspace/sort_test/sort_test.cpp:126]
  timer_enc: 0.491515 / 1 = 0.491515   [/opt/IBM/FHE-Workspace/sort_test/sort_test.cpp:149]
  timer_sorting: 59.4951 / 1 = 59.4951   [/opt/IBM/FHE-Workspace/sort_test/sort_test.cpp:173]*/


  // for(int i =0;i<v.size()-1;i++)
  // {
  //   for(int j =0;j<v.size()-i-1;j++)
  //   {
  //     // If `a`=`b` then `mu`=`ni`=`0`
  //     helib::Ctxt mu(encdb[0][0].getPubKey()), ni(encdb[0][0].getPubKey());
  //     // resize(encdb[j], bitSize, mu);
  //     // resize(encdb[j+1], bitSize + 1, ni);    
  //     compareTwoNumbers(mu, //j>j+1 swap //a>b
  //                       ni, //a<b
  //                       helib::CtPtrs_vectorCt(encdb[j]),
  //                       helib::CtPtrs_vectorCt(encdb[j+1]));
  //                       // false,
  //                       // &unpackSlotEncoding);
  //     vector<long> slotsMu;
  //     ea.decrypt(mu, secret_key, slotsMu);
  //     if(slotsMu[0]==1)//swap
  //     {
  //       vector<Ctxt> temp;
  //       temp = encdb[j];
  //       encdb[j]=encdb[j+1];
  //       encdb[j+1]=temp;

  //       //swap index
  //       int tmp = index[j];
  //       index[j] =index[j+1];
  //       index[j+1] = tmp;
  //     } 
  //   }
  // }

   /*
    Sorting Distances... 
terminate called after throwing an instance of 'helib::LogicError'
  what():  Cannot assign Ctxts with different pubKey
Aborted (core dumped) HEIN
    */




