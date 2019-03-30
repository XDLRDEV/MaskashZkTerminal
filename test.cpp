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
//using namespace libsnark;
//using namespace libff;

//using ppT = default_r1cs_ppzksnark_pp; 
//using FieldT = ppT::Fp_type;

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
        
        this->mintReqS = msgType+"||"+UpkS+"||"+kmintS+"||"+vS+"||"+pS;     // 使用"|||"作为分隔符
        std::cout<<mintReqS<<endl;
    }

private:
    msgMintRequest mintReq;
    std::string mintReqS;
};


/**
 * M = Mint
 * Z = whole coin
 * O = div coin
*/
class mskTxMaker {
public:
    mskTxMaker(uint256 _kmint, int64_t _v, uint256 _upk) {
        this->txType="M";
        this->m_msgMint = makeMsgMint(_kmint, _v, _upk);
        this->toString();
    }

    mskTxMaker(uint256 _Rpk, uint256 _pr1, uint256 _pr2, uint64_t _vr, uint256 _Ssk, uint256 _ps, uint64_t _vs) {
        this->txType="Z";
        this->m_transferZero = makeTransferZero<libsnark::default_r1cs_ppzksnark_pp::Fp_type>(_Rpk, _pr1, _pr2, _vr, _Ssk, _ps, _vs);
        this->toString();
    }

    mskTxMaker(uint256 _Rpk, uint256 _ps, uint256 _pr, uint64_t _vr, uint256 _Ssk) {
        this->txType="O";
        this->m_transferOne =  makeTransferOne<libsnark::default_r1cs_ppzksnark_pp::Fp_type>(_Rpk, _ps, _pr, _vr, _Ssk);
        this->toString();
    }

    bool Base64Encode( const string & input, string * output ) {
        typedef boost::archive::iterators::base64_from_binary<boost::archive::iterators::transform_width<string::const_iterator, 6, 8>> Base64EncodeIterator;
        stringstream result;
        try {
            copy( Base64EncodeIterator( input.begin() ), Base64EncodeIterator( input.end() ), ostream_iterator<char>( result ) );
        } catch ( ... ) {
            return false;
        }
        size_t equal_count = (3 - input.length() % 3) % 3;
        for ( size_t i = 0; i < equal_count; i++ ) {
            result.put( '=' );
        }
        *output = result.str();
        return output->empty() == false;
    }

    void toString() {
        if(this->txType=="M") {        // 发币交易到字符串的转换 
            std::string kmintS = this->m_msgMint.kmint.ToString();
            std::string dataS;
            for(int i=0; i<192; i++) {
                int tmp = boost::lexical_cast<int>(usgnCharToInt(m_msgMint.data[i]));
                dataS += boost::lexical_cast<std::string>(tmp);
            }
            std::string SigpubS = this->m_msgMint.Sigpub;

            std::string tmpMskTxS = txType+"||"+kmintS+"||"+dataS+"||"+SigpubS;

            this->Base64Encode(tmpMskTxS, &this->mskTxS);
            
            // this->mskTxS = txType+"||"+kmintS+"||"+dataS+"||"+SigpubS;
        } 
        else if (this->txType=="Z") {
            std::string SNoldS = this->m_transferZero.SNold.ToString();
            std::string krnewS = this->m_transferZero.krnew.ToString();
            std::string ksnewS = this->m_transferZero.ksnew.ToString();
            std::string proofS = proofToString(this->m_transferZero.pi);
            std::string dataS;
            for(int i=0; i<192; i++) {
                int tmp = boost::lexical_cast<int>(usgnCharToInt(m_transferZero.data[i]));
                dataS += boost::lexical_cast<std::string>(tmp);
            }
            std::string vkS = verifyKeyToString(this->m_transferZero.vk);
            std::string c_rtS = this->m_transferZero.c_rt.ToString();
            std::string s_rtS = this->m_transferZero.s_rt.ToString();
            std::string r_rtS = this->m_transferZero.r_rt.ToString();
            std::string tmpMskTxS = txType+"||"+SNoldS+"||"+krnewS +"||"+ksnewS +"||"+proofS +"||"+dataS +"||"+\
                                    vkS +"||"+c_rtS +"||"+s_rtS+"||"+r_rtS;

            this->Base64Encode(tmpMskTxS, &this->mskTxS);
            //std::cout<<"Encoded:\n"<<this->mskTxS<<std::endl;
        } 
        else if (this->txType=="O") {
            std::string SNoldS = this->m_transferOne.SNold.ToString();
            std::string krnewS = this->m_transferOne.krnew.ToString();
            std::string proofS = proofToString(this->m_transferOne.pi);
            std::string dataS;
            for(int i=0; i<192; i++) {
                int tmp = boost::lexical_cast<int>(usgnCharToInt(m_transferOne.data[i]));
                dataS += boost::lexical_cast<std::string>(tmp);
            }
            std::string vkS = verifyKeyToString(this->m_transferOne.vk);
            std::string c_rtS = this->m_transferOne.c_rt.ToString();
            std::string s_rtS = this->m_transferOne.s_rt.ToString();
            std::string r_rtS = this->m_transferOne.r_rt.ToString();

            std::string tmpMskTxS = txType+"||"+SNoldS+"||"+krnewS +"||"+proofS +"||"+dataS +"||"+\
                                    vkS +"||"+c_rtS +"||"+s_rtS+"||"+r_rtS;

            this->Base64Encode(tmpMskTxS, &this->mskTxS);
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

    std::string proofToString(r1cs_ppzksnark_proof<libsnark::default_r1cs_ppzksnark_pp> proof) {
        std::stringstream ss("");
        string proof_str;
        ss<<proof;
        proof_str=ss.str();
        return proof_str;
    }

    libsnark::r1cs_ppzksnark_proof<libsnark::default_r1cs_ppzksnark_pp> stringToProof(std::string proofS) {
        libsnark::r1cs_ppzksnark_proof<libsnark::default_r1cs_ppzksnark_pp> tmpProof;
        std::stringstream ss("");
        ss<<proofS;
        ss>>tmpProof;
        return tmpProof;
    }

    std::string verifyKeyToString(r1cs_ppzksnark_verification_key<libsnark::default_r1cs_ppzksnark_pp> vk) {
        std::stringstream ss("");
        string vk_str;
        ss<<vk;
        vk_str=ss.str();
        return vk_str;
    }

    libsnark::r1cs_ppzksnark_verification_key<libsnark::default_r1cs_ppzksnark_pp> stringToVerifyKey(std::string vkS) {
        libsnark::r1cs_ppzksnark_verification_key<libsnark::default_r1cs_ppzksnark_pp> tmpVk;
        std::stringstream ss("");
        ss<<vkS;
        ss>>tmpVk;
        return tmpVk;
    }

//private:
    std::string txType;

    msgMint m_msgMint;
    transferZero m_transferZero;
    transferOne m_transferOne;

    std::string mskTxS;
};


/**
 * M = Mint
 * Z = whole coin
 * O = div coin
*/
class mskVerifier {
public:
    mskVerifier() {}

    mskVerifier(std::string _mskTxS) {
        std::string mskTxS;
        Base64Decode(_mskTxS, &mskTxS);
        //std::cout<<"Decode Status:"<<Base64Decode(_mskTxS, &mskTxS)<<"\n"<<"Decoded:\n"<<mskTxS<<std::endl;
        strTxToStructTx(mskTxS);
    }

    bool Base64Decode( const std::string & input, std::string * output ) {
        typedef boost::archive::iterators::transform_width<boost::archive::iterators::binary_from_base64<std::string::const_iterator>, 8, 6> Base64DecodeIterator;
        stringstream result;
        try {
            copy( Base64DecodeIterator( input.begin() ), Base64DecodeIterator( input.end() ), std::ostream_iterator<char>( result ) );
        } catch ( ... ) {
            return false;
        }
        *output = result.str();
        return output->empty() == false;
    }

    void strTxToStructTx(std::string mskTxS) {
        if(mskTxS[0]=='M') {       // txType+||+kmintS+||+dataS+||+SigpubS
            mskTxS = mskTxS.substr(3);
            std::string kmintS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string dataS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string SigpubS = mskTxS.substr(0, mskTxS.length());
            this->m_msgMint.kmint = uint256S(kmintS);
            for(int i=0; i<192; i++) {
                int tmp = boost::lexical_cast<int>(dataS[i]);
                m_msgMint.data[i] = intToUsgnChar(tmp);
            }
            this->m_msgMint.Sigpub = SigpubS;
            
        } else if(mskTxS[0]=='Z') { // txType+||+SNoldS+||+krnewS +||+ksnewS +||+proofS +||+dataS +||+\
                                        vkS +||+c_rtS +||+s_rtS+||+r_rtS;
            mskTxS = mskTxS.substr(3);
            std::string SNoldS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string krnewS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string ksnewS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string proofS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string dataS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string vkS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string c_rtS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string s_rtS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string r_rtS = mskTxS.substr(0, mskTxS.length());

            this->m_transferZero.SNold = uint256S(SNoldS);
            std::cout<<endl<<"FL2"<<endl;
            this->m_transferZero.krnew = uint256S(krnewS);
            std::cout<<endl<<"FL3"<<endl;
            this->m_transferZero.ksnew = uint256S(ksnewS);
            std::cout<<endl<<"FL4"<<endl;
            this->m_transferZero.pi = stringToProof(proofS);
            std::cout<<endl<<"FL5"<<endl;
            for(int i=0; i<192; i++) {
                int tmp = boost::lexical_cast<int>(dataS[i]);
                m_transferZero.data[i] = intToUsgnChar(tmp);
            }
            std::cout<<endl<<"FL5.5"<<endl;
            this->m_transferZero.vk = stringToVerifyKey(vkS);
            std::cout<<endl<<"FL6"<<endl;
            this->m_transferZero.c_rt = uint256S(c_rtS);
            std::cout<<endl<<"FL7"<<endl;
            this->m_transferZero.s_rt = uint256S(s_rtS);
            std::cout<<endl<<"FL8"<<endl;
            this->m_transferZero.r_rt = uint256S(r_rtS);
            std::cout<<endl<<"BEGIN VERIFY"<<endl;
            transferZeroVerify<libsnark::default_r1cs_ppzksnark_pp::Fp_type>(this->m_transferZero.SNold, this->m_transferZero.krnew,\
                                       this->m_transferZero.ksnew, this->m_transferZero.data,\
                                       this->m_transferZero.pi, this->m_transferZero.vk, \
                                       this->m_transferZero.c_rt, this->m_transferZero.s_rt, this->m_transferZero.r_rt);

        } else if(mskTxS[0]=='O') { //txType+||+SNoldS+||+krnewS +||+proofS +||+dataS +||+\
                                       vkS +||+c_rtS +||+s_rtS+||+r_rtS;
            mskTxS = mskTxS.substr(3);
            std::string SNoldS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string krnewS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string proofS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string dataS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string vkS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string c_rtS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string s_rtS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string r_rtS = mskTxS.substr(0, mskTxS.length());

            this->m_transferOne.SNold = uint256S(SNoldS);
            this->m_transferOne.krnew = uint256S(krnewS);
            this->m_transferOne.pi = stringToProof(proofS);
            for(int i=0; i<192; i++) {
                int tmp = boost::lexical_cast<int>(dataS[i]);
                m_transferOne.data[i] = intToUsgnChar(tmp);
            }
            this->m_transferOne.vk = stringToVerifyKey(vkS);
            this->m_transferOne.c_rt = uint256S(c_rtS);
            this->m_transferOne.s_rt = uint256S(s_rtS);
            this->m_transferOne.r_rt = uint256S(r_rtS);
        } else {
            std::cout<<"\n FAILED!!  strTxToStructTx and Verify \n";
        }
    }

    int usgnCharToInt(unsigned char _uc) {
        int tmp = _uc;
        return tmp;
    }

    unsigned char intToUsgnChar(int _int) {
        unsigned char tmp;
        tmp = _int;
        return tmp;
    }

    libsnark::r1cs_ppzksnark_proof<libsnark::default_r1cs_ppzksnark_pp> stringToProof(std::string proofS) {
        libsnark::r1cs_ppzksnark_proof<libsnark::default_r1cs_ppzksnark_pp> tmpProof;
        std::stringstream ss("");
        ss<<proofS;
        ss>>tmpProof;
        return tmpProof;
    }

    libsnark::r1cs_ppzksnark_verification_key<libsnark::default_r1cs_ppzksnark_pp> stringToVerifyKey(std::string vkS) {
        libsnark::r1cs_ppzksnark_verification_key<libsnark::default_r1cs_ppzksnark_pp> tmpVk;
        std::stringstream ss("");
        ss<<vkS;
        ss>>tmpVk;
        return tmpVk;
    }

private:
    msgMint m_msgMint;
    transferZero m_transferZero;
    transferOne m_transferOne;
};

std::string demoMaker(std::string _mskTxS) {
    std::string tmpstr;
    tmpstr="eth.sendTransaction({from:\"0x62808DEDC60186480096d0517bbb174A875E39D9\",to: \"0xCed054D472CC39CC8386041AE87B9b2684E122A3\", value: \"12\",maskashMsg: \""+_mskTxS+"\"})";
    return tmpstr;
}


void makeDemoTxFile() {
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
}

int main(){
    

    return 0;

 }