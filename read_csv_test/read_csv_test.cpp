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

void storeinfile(string filename, vector<Ctxt> cp)
{
     ofstream file;
    file.open(filename , ios::out);
    if (file.is_open())
    {
      file<<cp;
    }
    else cout << "Unable to open file";
}

void storeinfileptxt(string filename, vector<vector<double>> cp)
{
     ofstream file;
    file.open(filename , ios::out);
    if (file.is_open())
    {
      file<<cp;
    }
    else cout << "Unable to open file";
}


void sqroot(EncryptedArray ea, PubKey publicKey, SecKey secretKey)
{
  int xint = 0.5;
  int d = 4;
  PtxtArray one(ea, 1);
  PtxtArray negone(ea, -1);
  PtxtArray three(ea, 3);
  long half = 0.5;
  long quarter = 0.25;

  PtxtArray x(ea, xint);
  Ctxt xc(publicKey);
  
  x.encrypt(xc);

  Ctxt a0 = xc;
  Ctxt a1(publicKey);
  Ctxt b0 = xc;
  Ctxt b1(publicKey);
  
  b0 -= one;

  for(int i=0; i<d; i++)
  {
    Ctxt temp1 = b0;
    temp1.multByConstant(half);
    temp1 -= one;
    temp1.multByConstant(negone);
    a0 *= temp1;
    a1 = a0;

    Ctxt temp2 = b0;
    temp2 -= three;
    temp2.multByConstant(quarter);
    b0 *= b0;
    b0 *= temp2;
    b1 = b0;

    //a0 = a1;
    //b0 = b1;
  }
   PtxtArray dec_x (ea);
  dec_x.decrypt(a1, secretKey);

  cout << "Decrypted sqroot : " << dec_x;
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

    //  std::vector<std::pair<helib::Ptxt<helib::BGV>, helib::Ptxt<helib::BGV>>>
    //   country_db_ptxt;

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
      vector<double> v1 = interest_vector[i];
      for(int j =6; j<n;j++)
      {
        v1.push_back(0);
      }
      PtxtArray n (context,v1);
      // PtxtArray n (context,interest_vector[i]);
      // PlaintextArray n (ea);
      //n.getData()

      db_ptxt.emplace_back(n);
        
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
    // cout<<ctxt_arr;

    ctxt_arr[1] -= ctxt_arr[0];

    storeinfile("op.txt", ctxt_arr);

  //Decryption
  vector<vector<double>> decrytxt;
  for(int i =0;i<ctxt_arr.size();i++)
  {
    PtxtArray pp (context);
    pp.decrypt(ctxt_arr[i],secretKey);
    vector<double> v;
    pp.store(v);
    decrytxt.push_back(v);
  }
  //cout<<decrytxt;
  storeinfileptxt("dec.txt", decrytxt);

  double x = 0.24;
  PtxtArray k(context, x);
  Ctxt xc(publicKey);
  
  k.encrypt(xc);

  //long r = 1;
  vector<Ctxt> bits;
  //xc.extractBits(bits, r);
  //storeinfile("bits.txt", bits);

  /*
  vector<vector<double>> bits_decrypt;
  for(int i =0;i<bits.size();i++)
  {
    PtxtArray pp (context);
    pp.decrypt(bits[i],secretKey);
    vector<double> v;
    pp.store(v);
    bits_decrypt.push_back(v);
  }
  */
  //cout<<decrytxt;
  //storeinfileptxt("bits_dec.txt", bits_decrypt);

  sqroot(ea, publicKey, secretKey);

    return 0;
}

