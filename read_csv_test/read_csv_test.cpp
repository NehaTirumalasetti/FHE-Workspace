#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <helib/helib.h>

using namespace std;
using namespace helib;
//using namespace helayers;

// using std::vector;

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
    vector<vector<double>> interest_vector;
    interest_vector = read_csv("./interest_vector.csv");
    for(int i=0; i < interest_vector.size(); i++){
  
        for(int j=0; j< interest_vector[i].size(); j++){
            cout<<interest_vector[i][j]<<"\t";
        }
        cout<<"\n";
    }

     std::vector<std::pair<helib::Ptxt<helib::BGV>, helib::Ptxt<helib::BGV>>>
      country_db_ptxt;

    //   // Plaintext prime modulus
    // unsigned long p = 131;
    // // Cyclotomic polynomial - defines phi(m)
    // unsigned long m = 130; // this will give 48 slots
    // // Hensel lifting (default = 1)
    // unsigned long r = 1;
    // // Number of bits of the modulus chain
    // unsigned long bits = 1000;
    // // Number of columns of Key-Switching matrix (default = 2 or 3)
    // unsigned long c = 2;
    // // Size of NTL thread pool (default =1)
    // unsigned long nthreads = 1;

    //  helib::Context context = helib::ContextBuilder<helib::BGV>()
    //                            .m(m)
    //                            .p(p)
    //                            .r(r)
    //                            .bits(bits)
    //                            .c(c)
    //                            .build();  
       
    Context context =

      // initialize a Context object using the builder pattern
      ContextBuilder<CKKS>()

          .m(16 * 1024)

          .bits(119)
          
          .precision(20)
    
          .c(2)
        
          .build();
     cout << "securityLevel=" << context.securityLevel() << "\n";

    long n = context.getNSlots();

    const helib::EncryptedArray& ea = context.getEA();

    SecKey secretKey(context);

    secretKey.GenSecKey();

    const PubKey& publicKey = secretKey;

    PtxtArray iv(context, interest_vector[0]);
    //cout << iv;
    std::vector<PtxtArray> db_ptxt;
    // , interest_vector);
    for(int i=0; i < interest_vector.size(); i++)
    {
      PtxtArray n (context,interest_vector[i]);
      // PlaintextArray n (ea);
      //n.getData()

      db_ptxt.emplace_back(move(n));
        
    }
    //cout<<db_ptxt;
    std::vector<Ctxt> ctxt_arr;
    // , interest_vector);
    for(int i=0; i < db_ptxt.size(); i++)
    {
      Ctxt c (publicKey);
      db_ptxt[i].encrypt(c);
      ctxt_arr.emplace_back(move(c));        
    }
    cout<<ctxt_arr;


    return 0;
}