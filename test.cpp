#include <boost/lexical_cast.hpp>

#include "libmsk/donator2/libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libmsk/donator2/interface.hpp"

#include <iostream>
#include <string>
#include <stdio.h>
#include <ostream>
#include <fstream>

using namespace std;
using namespace libsnark;
using namespace libff;

using ppT = default_r1cs_ppzksnark_pp; 
using FieldT = ppT::Fp_type;

class mskMsgMaker {
public:
    mskMsgMaker(uint256 _Usk, uint256 _p, int64_t _v) {
        this->mintReq = makeMintRequest(_Usk, _p, _v);
    }

    void toString() {
        std::string msgType = "MintRequest";
        std::string UpkS = this->mintReq.Upk.ToString();
        std::string kmintS = this->mintReq.kmint.ToString();
        char tmp[10];
        sprintf(tmp, "%lu", this->mintReq.v);
        std::string vS = tmp;
        std::string pS = this->mintReq.p.ToString();
        
        this->mintReqS = msgType+"|||"+UpkS+"|||"+kmintS+"|||"+vS+"|||"+pS;     // 使用"|||"作为分隔符
        std::cout<<mintReqS<<endl;
    }

private:
    msgMintRequest mintReq;
    std::string mintReqS;
};

class mskTxMaker {
public:
    mskTxMaker(uint256 _kmint, int64_t _v, uint256 _upk) {
        this->txType="txMint";
        this->m_msgMint = makeMsgMint(_kmint, _v, _upk);
    }

    mskTxMaker(uint256 _Rpk, uint256 _pr1, uint256 _pr2, uint64_t _vr, uint256 _Ssk, uint256 _ps, uint64_t _vs) {
        this->txType="txTransferZero";
        this->m_transferZero = makeTransferZero<FieldT>(_Rpk, _pr1, _pr2, _vr, _Ssk, _ps, _vs);
    }

    mskTxMaker(uint256 _Rpk, uint256 _ps, uint256 _pr, uint64_t _vr, uint256 _Ssk) {
        this->txType="txTransferOne";
        this->m_transferOne =  makeTransferOne<FieldT>(_Rpk, _ps, _pr, _vr, _Ssk);
    }

    void toString() {
        if(this->txType=="txMint") {        // 发币交易到字符串的转换 
            std::string kmintS = this->m_msgMint.kmint.ToString();
            std::string dataS(this->m_msgMint.data);
            for(int i=0; i<192; i++) {
                int tmp = boost::lexical_cast<int>(usgnCharToInt(m_msgMint.data[i]));
                dataS += boost::lexical_cast<std::string>(tmp);
            }
            std::string SigpubS = this->m_msgMint.Sigpub;

            this->mskTxS = txType+"|||"+kmintS+"|||"+dataS+"|||"+SigpubS;
        } 
        else if (this->txType=="txTransferZero") {
            std::string SNoldS = this->m_transferZero.SNold.ToString();
            std::string krnewS = this->m_transferZero.krnew.ToString();
            std::string ksnewS = this->m_transferZero.ksnew.ToString();
            std::string proofS = proofToString(this->m_transferZero.pi);
            std::string dataS(this->m_transferZero.data);
            for(int i=0; i<192; i++) {
                int tmp = boost::lexical_cast<int>(usgnCharToInt(m_transferZero.data[i]));
                dataS += boost::lexical_cast<std::string>(tmp);
            }
            std::string vkS = verifyKeyToString(this->m_transferZero.vk);
            std::string c_rtS = this->m_transferZero.c_rt.ToString();
            std::string s_rtS = this->m_transferZero.s_rt.ToString();
            std::string r_rtS = this->m_transferZero.r_rt.ToString();

            this->mskTxS = txType+"|||"+SNoldS+"|||"+krnewS +"|||"+ksnewS +"|||"+proofS +"|||"+dataS +"|||"+\
                           vkS +"|||"+c_rtS +"|||"+s_rtS+"|||"+r_rtS;
        } 
        else if (this->txType=="txTransferOne") {
            std::string SNoldS = this->m_transferOne.SNold.ToString();
            std::string krnewS = this->m_transferOne.krnew.ToString();
            std::string proofS = proofToString(this->m_transferOne.pi);
            std::string dataS(this->m_transferOne.data);
            for(int i=0; i<192; i++) {
                int tmp = boost::lexical_cast<int>(usgnCharToInt(m_transferZero.data[i]));
                dataS += boost::lexical_cast<std::string>(tmp);
            }
            std::string vkS = verifyKeyToString(this->m_transferOne.vk);
            std::string c_rtS = this->m_transferOne.c_rt.ToString();
            std::string s_rtS = this->m_transferOne.s_rt.ToString();
            std::string r_rtS = this->m_transferOne.r_rt.ToString();

            this->mskTxS = txType+"|||"+SNoldS+"|||"+krnewS +"|||"+proofS +"|||"+dataS +"|||"+\
                           vkS +"|||"+c_rtS +"|||"+s_rtS+"|||"+r_rtS;
        }
    }

    // char: -128 ~ 127
    // usgn char: 0 ~ 255
    int usgnCharToInt(unsigned char _uc) {
        int tmp = _uc;
        return tmp;
    }

    unsigned char intToUsgnChar(int _int) {
        unsigned char tmp;
        tmp = _int;
        return tmp;
    }

    std::string proofToString(r1cs_ppzksnark_proof<ppT> proof) {
        stringstream ss("");
        string proof_str;
        ss<<proof;            // 把一个什么东西流进ss
        proof_str=ss.str();   // ss.str()的值便成为了流进ss的这堆东西
        return proof_str;
    }

    r1cs_ppzksnark_proof<ppT> stringToProof(std::string proofS) {
        r1cs_ppzksnark_proof<ppT> tmpProof;
        stringstream ss("");
        ss<<proofS;
        ss>>tmpProof;
        return tmpProof;
    }

    std::string verifyKeyToString(r1cs_ppzksnark_verification_key<ppT> vk) {
        stringstream ss("");
        string vk_str;
        ss<<vk;            // 把一个什么东西流进ss
        vk_str=ss.str();   // ss.str()的值便成为了流进ss的这堆东西
        return vk_str;
    }

    r1cs_ppzksnark_verification_key<ppT> stringToVerifyKey(std::string vkS) {
        r1cs_ppzksnark_verification_key<ppT> tmpVk;
        stringstream ss("");
        ss<<vkS;
        ss>>tmpVk;
        return tmpVk;
    }

private:
    std::string txType;

    msgMint m_msgMint;
    transferZero m_transferZero;
    transferOne m_transferOne;

    std::string mskTxS;
};

class mskVerifier {
public:
    mskVerifier(std::string _mskTxS) {

    }
    
private:

};




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

    transferZero tr= makeTransferZero<FieldT>( apk_r, new_r1,new_r2,v_1,ask_s,old_r,v_2);

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
  
    cout<<tr.pi<<endl;
  
    // cout重定向到cout，即输出到屏幕
    cout.rdbuf(stream_buffer_cout);
  
    file.close(); // 关闭文件
//---------
    fstream file2; // 定义fstream对象
    file2.open("./cout.txt", ios::in); // 打开文件，并绑定到ios::in对象
    //string line;
  
    // 先获取cout、cin的buffer指针
    //streambuf *stream_buffer_cout = cout.rdbuf();
    //streambuf *stream_buffer_cin = cin.rdbuf();
  
    // 获取文件的buffer指针
    //streambuf *stream_buffer_file = file.rdbuf();
  
    // cin重定向到文件
    cin.rdbuf(stream_buffer_file);
  
    r1cs_ppzksnark_proof<ppT> pi2;

    cin>>pi2;
  
    // cout重定向到cout，即输出到屏幕
    cin.rdbuf(stream_buffer_cin);
  
    file2.close(); // 关闭文件
    std::cout<<"tr.pi2: \n"<<pi2;
//-------------------------------------------------------
*/
    bool t=transferZeroVerify<FieldT>(tr.SNold, tr.krnew, tr.ksnew, tr.data, tmpProof, tmpVk, tr.c_rt, tr.s_rt, tr.r_rt);

    return 0;

 } 
   
