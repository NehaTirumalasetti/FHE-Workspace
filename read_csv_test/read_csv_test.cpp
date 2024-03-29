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
    else std::cout << "Unable to open file";
}

void storeinfileptxt(string filename, vector<vector<double>> cp)
{
     ofstream file;
    file.open(filename , ios::out);
    if (file.is_open())
    {
      file<<cp;
    }
    else std::cout << "Unable to open file";
}

void storeinfilePtxtArray(string filename, vector<double> cp)
{
     ofstream file;
    file.open(filename , ios::out);
    if (file.is_open())
    {
      file<<cp;
    }
    else std::cout << "Unable to open file";
}

void debugtxtfile(string filename, Ctxt c, string var, int i ,SecKey secretKey)
{
  PtxtArray dec_x (c.getContext());
  dec_x.decrypt(c, secretKey);
  vector<double> x_ptxt;
  dec_x.store(x_ptxt);
  bool flag = false;

    ofstream file;
    file.open(filename , ios::out);
    if (file.is_open())
    {
      file << "Iteration " << i << " " << var <<" = "<< x_ptxt[0] << "\n" ;
      file<<"\n";
      flag = true;
    }
    else std::cout << "Unable to open file";
    if(flag == true){
    std::cout << var <<"\n";
    }
}


void debugtxtprint(Ctxt c, string var, int i ,SecKey secretKey)
{
  PtxtArray dec_x (c.getContext());
  dec_x.decrypt(c, secretKey);
  vector<double> x_ptxt;
  dec_x.store(x_ptxt);
  bool flag = false;

  std::cout<< "Iteration " << i << " " << var <<" = "<< x_ptxt[0] << "\n" ;
  
}

void decryptDBinfile(string filename, vector<vector<Ctxt>> encdb, PubKey publicKey , SecKey secretKey)
{
  vector<vector<double>> decrp;
  for(int i = 0;i<encdb.size();i++)
  {
    for(int j = 0 ;j<encdb[i].size();j++)
    {
        PtxtArray dec_x (publicKey.getContext());
        dec_x.decrypt(encdb[i][j], secretKey);
        vector<double> x_ptxt;
        dec_x.store(x_ptxt);
        decrp.emplace_back(x_ptxt);
    }
  }
  storeinfileptxt(filename,decrp);
}

void sqroot(EncryptedArray ea, PubKey publicKey, SecKey secretKey, Ctxt xc)
{
  //int xint = 0.5;
  //vector<double> xint;
  //xint.push_back(0.0603);
  int d = 3;
  std::cout << "test1";
  vector<double> k;
  k.push_back(1);
  PtxtArray one(publicKey.getContext(), k);
  std::cout << "test one";
  vector<double> u;
  u.push_back(-1);
  PtxtArray negone(publicKey.getContext(), u);
  std::cout << "test negone";
  vector<double> f;
  f.push_back(3);
  PtxtArray three(publicKey.getContext(), f);
  std::cout << "test three";
  long half = 0.5;
  long quarter = 0.25;

  //PtxtArray x(publicKey.getContext(), xint);
  std::cout << "test x";
  //Ctxt xc(publicKey);
  
  //x.encrypt(xc);

  Ctxt a0 = xc;
  //Ctxt a1 = xc;
  Ctxt b0 = xc;
  //Ctxt b1 = xc;
  
  b0 -= one;

  // std::cout << "\na0 c : " << a0.capacity() << "\n";
  // std::cout << "a0 e : " << a0.errorBound() << "\n";
  // std::cout << "b0 c : " << b0.capacity() << "\n";
  // std::cout << "b0 e : " << b0.errorBound() << "\n";

  for(int i=0; i<d; i++)
  {
    std::cout << "Iteration : " << i;
    Ctxt temp1 = b0;
    //temp1.multByConstant(half);
    temp1 *= 0.5;
    //temp1.divideBy2();
    temp1 -= one;
    //temp1.multByConstant(negone);
    temp1 *= -1.0;
    a0 *= temp1;
    //a1 = a0;
    debugtxtprint(a0,"After a0 calc : a0 ",i, secretKey);
    debugtxtprint(b0,"After a0 calc : b0 ",i, secretKey);

    Ctxt temp2 = b0;
    temp2 -= three;
    //temp2.multByConstant(quarter);
    temp2 *= 0.25;
    debugtxtprint(temp2,"During b0 calc : temp2 ",i, secretKey);
    //b0 *= b0;
    b0.square();
    debugtxtprint(b0,"During b0 calc : b0 square ",i, secretKey);
    b0 *= temp2;
    //b1 = b0;

    debugtxtprint(a0,"After b0 calc : a0 ",i, secretKey);
    debugtxtprint(b0,"After b0 calc : b0 ",i, secretKey);

    // std::cout << "a0 c : " << a0.capacity() << "\n";
    // std::cout << "a0 e : " << a0.errorBound() << "\n";
    // std::cout << "b0 c : " << b0.capacity() << "\n";
    // std::cout << "b0 e : " << b0.errorBound() << "\n";
    //a0 = a1;
    //b0 = b1;
  }
  int i=0;
  debugtxtfile("debug_sqrt.txt",a0,"Square root : ",i,secretKey);
}



void encryptDb (PubKey publicKey, SecKey secretKey, EncryptedArray ea)
{
  vector<vector<double>> interest_vector;
  interest_vector = read_csv("./interest_vector.csv");
  //Context& context = publicKey.getContext();
  vector<vector<Ctxt>> encdb ;
  
  cout<<"\ntest 1";
  for(int i=0; i < interest_vector.size(); i++){
          vector<Ctxt> tmp;
        for(int j=0; j< interest_vector[i].size(); j++)
        {
          cout<<"\nIteration " << i << j;
          PtxtArray n(publicKey.getContext(), interest_vector[i][j]);
          Ctxt x (publicKey);
          n.encrypt(x);
          tmp.push_back(x);
        }
        cout << "\n test after for";
        encdb.emplace_back(tmp);
    }


  for(int i = 0; i<encdb.size()-1;i++)
 {
   for(int j =0;j<6;j++)
   {
    //Ctxt tmp = v[i][j];

     encdb[i][j]-=encdb[i+1][j];
     encdb[i][j].square();
     cout << "\nIteration " << i << j;
     //v[i][j]*=v[i][j];
   }
 }

 vector<Ctxt> tmp_add;
 Ctxt sum(publicKey);
 for(int k=0; k<6; k++)
 {
   sum += encdb[0][k];
 }
 tmp_add.push_back(sum);

 int x=0;
 debugtxtfile("sq_add_dbtest_new.txt",tmp_add[0],"addition",x,secretKey);
 decryptDBinfile("subsqdbtest.txt",encdb, publicKey, secretKey);

 sqroot(ea, publicKey, secretKey, tmp_add[0]);
  //return encdb;
}



/*
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
    //temp1.multByConstant(half);
    temp1.divideBy2();
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

  std::cout << "Decrypted sqroot : " << dec_x;
}

*/


int main(int argc, char* argv[])
{
    vector<vector<double>> interest_vector;
    interest_vector = read_csv("./interest_vector.csv");
    for(int i=0; i < interest_vector.size(); i++){
  
        for(int j=0; j< interest_vector[i].size(); j++){
            std::cout<<interest_vector[i][j]<<"\t";
        }
        std::cout<<"\n";
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
          
          .precision(32)
    
          .c(2)
        
          .build();
     std::cout << "securityLevel=" << context.securityLevel() << "\n";

    long n = context.getNSlots();

    const helib::EncryptedArray& ea = context.getEA();

    SecKey secretKey(context);

    secretKey.GenSecKey();

    const PubKey& publicKey = secretKey;

    std::cout << "test pubkey";
    /*
    PtxtArray iv(context, interest_vector[0]);
    //std::cout << iv;
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
    //std::cout<<db_ptxt;
    std::vector<Ctxt> ctxt_arr;
    // , interest_vector);
    for(int i=0; i < db_ptxt.size(); i++)
    {
      Ctxt c (publicKey);
      db_ptxt[i].encrypt(c);
      ctxt_arr.emplace_back(move(c));        
    }
    // std::cout<<ctxt_arr;

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
  //std::cout<<decrytxt;
  storeinfileptxt("dec.txt", decrytxt);

  double x = 0.24;
  PtxtArray k(context, x);
  Ctxt xc(publicKey);
  
  k.encrypt(xc);

  //long r = 1;
  vector<Ctxt> bits;
  //xc.extractBits(bits, r);
  //storeinfile("bits.txt", bits);
*/
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
  //std::cout<<decrytxt;
  //storeinfileptxt("bits_dec.txt", bits_decrypt);


  //sqroot(ea, publicKey, secretKey);
/* SQUARE ROOT CODE : -------------------------------------------
  //int xint = 0.5;
  vector<double> xint;
  xint.push_back(0.0603);
  int d = 3;
  std::cout << "test1";
  vector<double> k;
  k.push_back(1);
  PtxtArray one(context, k);
  std::cout << "test one";
  vector<double> u;
  u.push_back(-1);
  PtxtArray negone(context, u);
  std::cout << "test negone";
  vector<double> f;
  f.push_back(3);
  PtxtArray three(context, f);
  std::cout << "test three";
  long half = 0.5;
  long quarter = 0.25;

  PtxtArray x(context, xint);
  std::cout << "test x";
  Ctxt xc(publicKey);
  
  x.encrypt(xc);

  Ctxt a0 = xc;
  //Ctxt a1 = xc;
  Ctxt b0 = xc;
  //Ctxt b1 = xc;
  
  b0 -= one;

  // std::cout << "\na0 c : " << a0.capacity() << "\n";
  // std::cout << "a0 e : " << a0.errorBound() << "\n";
  // std::cout << "b0 c : " << b0.capacity() << "\n";
  // std::cout << "b0 e : " << b0.errorBound() << "\n";

  for(int i=0; i<d; i++)
  {
    std::cout << "Iteration : " << i;
    Ctxt temp1 = b0;
    //temp1.multByConstant(half);
    temp1 *= 0.5;
    //temp1.divideBy2();
    temp1 -= one;
    //temp1.multByConstant(negone);
    temp1 *= -1.0;
    a0 *= temp1;
    //a1 = a0;
    debugtxtprint("debug.txt",a0,"After a0 calc : a0 ",i, secretKey);
    debugtxtprint("debug.txt",b0,"After a0 calc : b0 ",i, secretKey);

    Ctxt temp2 = b0;
    temp2 -= three;
    //temp2.multByConstant(quarter);
    temp2 *= 0.25;
    debugtxtprint("debug.txt",temp2,"During b0 calc : temp2 ",i, secretKey);
    //b0 *= b0;
    b0.square();
    debugtxtprint("debug.txt",b0,"During b0 calc : b0 square ",i, secretKey);
    b0 *= temp2;
    //b1 = b0;

    debugtxtprint("debug.txt",a0,"After b0 calc : a0 ",i, secretKey);
    debugtxtprint("debug.txt",b0,"After b0 calc : b0 ",i, secretKey);

    // std::cout << "a0 c : " << a0.capacity() << "\n";
    // std::cout << "a0 e : " << a0.errorBound() << "\n";
    // std::cout << "b0 c : " << b0.capacity() << "\n";
    // std::cout << "b0 e : " << b0.errorBound() << "\n";
    //a0 = a1;
    //b0 = b1;
  }*/
  //PtxtArray dec_x (context);
  //dec_x.decrypt(a0, secretKey);

  //std::cout << "Decrypted sqroot : " << dec_x;
  //vector<double> x_ptxt;
  //dec_x.store(x_ptxt);

  //storeinfilePtxtArray("sqroot_ptxt.txt", x_ptxt); 

 /*vector<vector<Ctxt>> v = encryptDb( publicKey);


  cout<<"\ntest 1";
 for(int i = 0; i<v.size()-1;i++)
 {
   for(int j =0;j<6;j++)
   {
    //Ctxt tmp = v[i][j];

     v[i][j]-=v[i+1][j];
     v[i][j].square();
     cout << "\nIteration " << i << j;
     //v[i][j]*=v[i][j];
   }
 }

 decryptDBinfile("subsqdbtest.txt",v, publicKey, secretKey);*/

/*
 PtxtArray p1 (context, 0.24);
 PtxtArray p2 (context, 0.18);
 Ctxt c1 (publicKey);
 p1.encrypt(c1);
 Ctxt c2 (publicKey);
 p2.encrypt(c2);
  
 cout << "\ntest 1";
 c1-=c2;
 cout << "\ntest 2";
 c1.square();
 int i=0;
 cout << "\ntest 3";
 debugtxtprint(c1, "square",i,secretKey);
*/
 //vector<Ctxt> bits;
 //cout << "\ntest 4";
 //Ctxt bits (publicKey);
 //c1.extractBits(bits,5);
 //cout << "\ntest 5";
// PtxtArray dec_x (context);
// dec_x.decrypt(bits[0], secretKey);
// vector<double> x_ptxt;
// dec_x.store(x_ptxt);
// cout << x_ptxt[0] <<endl;

encryptDb(publicKey, secretKey, ea);
  return 0;
}

/*

./read_csv_test
0.24    0.54    0.17    0.26    0.31    0.25
0.18    0.48    0.13    0.18    0.2     0.19
securityLevel=129.741
test pubkeytest1test onetest negonetest threetest xIteration : 0Iteration 0 After a0 calc : a0  = 0.500001
Iteration 0 After a0 calc : b0  = -0.5
Iteration 0 After b0 calc : a0  = 0.500001
Iteration 0 After b0 calc : b0  = 99.0279
Iteration : 1Iteration 1 After a0 calc : a0  = 0.499999
Iteration 1 After a0 calc : b0  = 99.0279
Iteration 1 After b0 calc : a0  = 0.499999
Iteration 1 After b0 calc : b0  = 99.0279
Iteration : 2Iteration 2 After a0 calc : a0  = 0.500002
Iteration 2 After a0 calc : b0  = 99.0279
Iteration 2 After b0 calc : a0  = 0.500002
Iteration 2 After b0 calc : b0  = 99.0279
Iteration : 3Iteration 3 After a0 calc : a0  = 0.500002
Iteration 3 After a0 calc : b0  = 99.0279
Iteration 3 After b0 calc : a0  = 0.500002
Iteration 3 After b0 calc : b0  = 99.0279


 vector<double> v1 {0.24,0.54,0.17,0.26,0.31,0.25};
  vector<double> v2 {0.18,0.48,0.13,0.18,0.2,0.19};
  PtxtArray x1(context, v1);
  PtxtArray x2(context, v2);
  Ctxt e1 (publicKey);
  x1.encrypt(e1);
  Ctxt e2 (publicKey);
  x2.encrypt(e2);

  e1-=e2;
  e1.square();
  cout << e1[0] << endl;
  
  vector<vector<Ctxt>> db ;
  

  PtxtArray dec_x (context);
  dec_x.decrypt(e1, secretKey);
  vector<double> x_ptxt;
  dec_x.store(x_ptxt);
  storeinfilePtxtArray("subsqptxt.txt", x_ptxt);

*/