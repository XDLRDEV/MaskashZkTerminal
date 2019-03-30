#include <boost/lexical_cast.hpp>

#include "libmsk/donator2/libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libmsk/donator2/interface.hpp"

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

#include <iostream>
#include <string>
#include <stdio.h>
#include <ostream>
#include <fstream>

using namespace std;

int main(){

    ppT::init_public_params();
    //using FieldT = ppT::Fp_type;
    inhibit_profiling_info = true;
    inhibit_profiling_counters = true;

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");

    uint64_t v_1=5;
    uint64_t v_2=3;
    uint64_t v_3=0;

    uint256 old_r=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");

    uint256 new_r1=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");
    uint256 new_r2=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    //transferZero tr= makeTransferZero<FieldT>( apk_r, new_r1,new_r2,v_1,ask_s,old_r,v_2);


    // mskTxMaker(uint256 _Rpk, uint256 _pr1, uint256 _pr2, uint64_t _vr, uint256 _Ssk, uint256 _ps, uint64_t _vs)
    mskTxMaker zeroTx = mskTxMaker(apk_r, new_r1,new_r2,v_1,ask_s,old_r,v_2 );
    //std::cout<<"----------"<<endl<<zeroTx.mskTxS<<endl<<"-----------"<<endl;
    std::string tmpstr = demoMaker(zeroTx.mskTxS);
    mskVerifier mskV = mskVerifier(zeroTx.mskTxS);
    mskVerifier mskV2 = mskVerifier(zeroTx.mskTxS);


    std::fstream fileD; // 定义fstream对象
    fileD.open("./sendDemo.js", std::ios::out); // 打开文件，并绑定到ios::out对象
    std::streambuf *stream_buffer_cout9 = std::cout.rdbuf();
    std::streambuf *stream_buffer_file9 = fileD.rdbuf();
    std::cout.rdbuf(stream_buffer_file9);
    std::cout<<tmpstr;
    std::cout.rdbuf(stream_buffer_cout9);
    fileD.close(); // 关闭文件

/*
    std::string tmpProofS = "\"";
    tmpProofS += proofToString(tr.pi);
    tmpProofS += "\",";
    std::cout<<"tmpProofS:\n----------\n";
    std::cout<<tmpProofS<<"\n-----------\n";

    tmpProofS = tmpProofS.substr(1, tmpProofS.length()-3);

    r1cs_ppzksnark_proof<ppT> tmpProof = stringToProof(tmpProofS);


    std::string tmpVkS = "\"";
    tmpVkS += verifyKeyToString(tr.vk);
    tmpVkS += "\",";
    tmpVkS = tmpVkS.substr(1, tmpVkS.length()-3);
    //std::cout<<"tmpVkS:\n----------\n";
    //std::cout<<tmpVkS<<"\n-----------\n";
    r1cs_ppzksnark_verification_key<ppT> tmpVk = stringToVerifyKey(tmpVkS);
    //std::cout<<"tmpVk:\n----------\n";
    //std::cout<<tmpVk<<"\n-----------\n";

*/
/*
//---------------------------------------------------
    fstream file; // 定义fstream对象
    file.open("./cout.txt", ios::out); // 打开文件，并绑定到ios::out对象
    //string line;
  
    // 先获取cout、cin的buffer指针
    streambuf *stream_buffer_cout = cout.rdbuf();
    streambuf *stream_buffer_cin = cin.rdbuf();
  
    // 获取文件的buffer指针
    streambuf *stream_buffer_file = file.rdbuf();
  
    // cout重定向到文件
    cout.rdbuf(stream_buffer_file);
  
    cout<<zeroTx.mskTxS;

    //cout<<tr.pi<<endl;
  
    // cout重定向到cout，即输出到屏幕
    cout.rdbuf(stream_buffer_cout);
  
    file.close(); // 关闭文件
//-------------------------------------------------------
*/
    //bool t=transferZeroVerify<FieldT>(tr.SNold, tr.krnew, tr.ksnew, tr.data,\
                                     tr.pi, tr.vk, tr.c_rt, tr.s_rt, tr.r_rt);

    return 0;

 }