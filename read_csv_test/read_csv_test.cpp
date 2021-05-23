#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <helib/helib.h>

using namespace std;
using namespace helib;
using namespace helayers;

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

    SecKey secretKey(context);

    secretKey.GenSecKey();

    const PubKey& publicKey = secretKey;

    // PtxtArray iv(context);//, interest_vector);
    // for(int i=0; i < interest_vector.size(); i++){
  
    //     PtxtArray p0(context, interest_vector[i]);
    //     // for(int j=0; j< interest_vector[i].size(); j++){
            
    //     //     //cout<<interest_vector[i][j]<<"\t";
    //     // }
    //     // cout<<"\n";
    //     iv.load(p0);
    // }
    // cout<<iv;




    return 0;
}