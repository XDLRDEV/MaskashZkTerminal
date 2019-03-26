#include "libmsk/donator2/libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libmsk/donator2/interface.hpp"

#include <iostream>
#include <string>
#include <stdio.h>

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
        
        this->mintReqS = msgType+","+UpkS+","+kmintS+","+vS+","+pS;
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
        this->m_transferZero = makeTransferZero<FieldT>(uint256 _Rpk, uint256 _pr1, uint256 _pr2, uint64_t _vr, uint256 _Ssk, uint256 _ps, uint64_t _vs);
    }

    mskTxMaker(uint256 _Rpk, uint256 _ps, uint256 _pr, uint64_t _vr, uint256 _Ssk) {
        this->txType="txTransferOne";
        this->m_transferOne =  makeTransferOne<FieldT>(uint256 _Rpk, uint256 _ps, uint256 _pr, uint64_t _vr, uint256 _Ssk);
    }



private:
    std::string txType;

    msgMint m_msgMint;
    transferZero m_transferZero;
    transferOne m_transferOne;

    std::string mskTxS;
};

class mskMsgVerifier {
public:

private:

};

class mskTxVerifier {
public:

private:

};

int main(){
    mskMsgMaker tmp(uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0"), uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0"), 18446744073709551610);
    tmp.toString();
/*
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
    bool t=transferZeroVerify<FieldT>(tr.SNold ,tr.krnew,tr.ksnew, tr.data, tr.pi,tr.vk,tr.c_rt,tr.s_rt,tr.r_rt);
    cout<<t<<endl;
    return 0;
*/
 } 
   
