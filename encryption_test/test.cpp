
#include<iostream> 

#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

using namespace std;

int main(int argc, char const *argv[])
{
    /* code */
    cout<<"hello";
    
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
  // input database file name
  std::string db_filename="/opt/IBM/FHE-Workspace/examples/BGV_country_db_lookup/countries_dataset.csv";
  // debug output (default no debug output)
  bool debug = false;


    helib::ArgMap amap;
  amap.arg("m", m, "Cyclotomic polynomial ring");
  amap.arg("p", p, "Plaintext prime modulus");
  amap.arg("r", r, "Hensel lifting");
  amap.arg("bits", bits, "# of bits in the modulus chain");
  amap.arg("c", c, "# fo columns of Key-Switching matrix");
  amap.arg("nthreads", nthreads, "Size of NTL thread pool");
  amap.arg("db_filename", db_filename, "Qualified name for the database filename");
  amap.toggle().arg("-debug", debug, "Toggle debug output", "");
  //amap.parse(argc, argv);

  if (nthreads > 1)
    NTL::SetNumThreads(nthreads);

 std::cout << "---Initialising HE Environment ... ";
  // Initialize context
  std::cout << "\nInitializing the Context ... ";
  HELIB_NTIMER_START(timer_Context);
 // helib::Context context(m, p, r);
   helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .bits(bits)
                               .c(c)
                               .build();
  HELIB_NTIMER_STOP(timer_Context);
  
  // Modify the context, adding primes to the modulus chain
  std::cout << "\nBuilding modulus chain ... ";
  HELIB_NTIMER_START(timer_CHAIN);
  //helib::buildModChain(context, bits, c);
  HELIB_NTIMER_STOP(timer_CHAIN);

// Secret key management
  std::cout << "\nCreating Secret Key ...";
  HELIB_NTIMER_START(timer_SecKey);
  // Create a secret key associated with the context
  helib::SecKey secret_key = helib::SecKey(context);
  // Generate the secret key
  secret_key.GenSecKey();
  HELIB_NTIMER_STOP(timer_SecKey);

  // Compute key-switching matrices that we need
  HELIB_NTIMER_START(timer_SKM);
  helib::addSome1DMatrices(secret_key);
  HELIB_NTIMER_STOP(timer_SKM);

// Public key management
  // Set the secret key (upcast: FHESecKey is a subclass of FHEPubKey)
  std::cout << "\nCreating Public Key ...";
  HELIB_NTIMER_START(timer_PubKey);
  const helib::PubKey& public_key = secret_key;
  HELIB_NTIMER_STOP(timer_PubKey);

  // Get the EncryptedArray of the context
//  const helib::EncryptedArray& ea = *(context.ea);
  const helib::EncryptedArray& ea = context.getEA();

   // Print the context
 // std::cout << std::endl;
  //if (debug)
     // context.zMStar.printout();

// long nslots = ea.size();
//   std::cout << "\nNumber of slots: " << nslots << std::endl;

// //db_filename="abc","xyz";

//  vector< pair <int,int> > db_filename; 
  
//     // initialising 1st and 2nd element of 
//     // pairs with array values 
//     int arr[] = {1,2}; 
//     int arr1[] = {3,4}; 
//     int n = sizeof(arr)/sizeof(arr[0]); 
  
//     // Entering values in vector of pairs 
//     for (int i=0; i<n; i++) 
//         db_filename.push_back( make_pair(arr[i],arr1[i]) ); 

//    /************ Read in the database ************/
//   std::vector<std::pair<std::string, std::string>> country_db = db_filename;

//  std::cout << "Encrypting the database..." << std::endl;
//   HELIB_NTIMER_START(timer_CtxtCountryDB);
//   std::vector<std::pair<helib::Ctxt, helib::Ctxt>> encrypted_country_db;
 
//     helib::Ctxt encrypted_country(public_key);
//     helib::Ctxt encrypted_capital(public_key);
//     public_key.Encrypt(encrypted_country, country_capital_pair.first);
//     public_key.Encrypt(encrypted_capital, country_capital_pair.second);
//     encrypted_country_db.emplace_back(std::move(encrypted_country), std::move(encrypted_capital));
  
    std::string query_string;
  std::cout << "\nPlease enter a string: ";
  // std::cin >> query_string;
  std::getline(std::cin, query_string);
 // std::cout << "Looking for the Capital of " << query_string << std::endl;
  //std::cout << "This may take few minutes ... " << std::endl;

  HELIB_NTIMER_START(timer_TotalQuery);

  HELIB_NTIMER_START(timer_EncryptQuery);
  // Convert query to a numerical vector
  helib::Ptxt<helib::BGV> query_ptxt(context);
  for (long i = 0; i < query_string.size(); ++i)
    query_ptxt[i] = query_string[i];

  // Encrypt the query
  helib::Ctxt query(public_key);
  public_key.Encrypt(query, query_ptxt);
  HELIB_NTIMER_STOP(timer_EncryptQuery);
   //std::cout << "The encrypted string is: " << query_ptxt << std::endl;
  std::cout << "The encrypted string is: " << query << std::endl; 


//std::vector<helib::Ctxt> mask;
std::cout << "starting decryption"<< std::endl;
//mask=query;
  HELIB_NTIMER_START(timer_DecryptQueryResult);
  helib::Ptxt<helib::BGV> plaintext_result(context);
  secret_key.Decrypt(plaintext_result, query);
  HELIB_NTIMER_STOP(timer_DecryptQueryResult);

  // Convert from ASCII to a string
  std::string string_result;
  for (long i = 0; i < plaintext_result.size(); ++i)
    string_result.push_back(static_cast<long>(plaintext_result[i]));


std::cout << "The decrypted string is: " << string_result << std::endl;
  HELIB_NTIMER_STOP(timer_TotalQuery);

return 0;
}