//
//  libzerocoin.hpp
//  nixwallet
//
//  Created by Matthew T on 1/4/19.
//  Copyright © 2019 Nix Platform. All rights reserved.
//

#ifndef libzerocoin_hpp
#define libzerocoin_hpp

#define BOOST_THREAD_PROVIDES_FUTURE

#include <stdio.h>
#include <vector>
#include <bitset>
#include <string>
#include <math.h>
#include <queue>
#include <vector>
#include <list>
#include <algorithm>
#include <functional>
#include <openssl/rand.h>
#include <string>
#include <iostream>
#include <fstream>
#include <exception>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/future.hpp>
#include <boost/chrono.hpp>
#include <stdexcept>

#include "../loafwallet-core/secp256k1/include/secp256k1.h"
#include "../loafwallet-core/secp256k1/include/secp256k1_recovery.h"
#include "../loafwallet-core/secp256k1/include/secp256k1_ecdh.h"

#include "ripemd160.h"
#include "bitcoin_bignum/uint256.h"
#include "bitcoin_bignum/serialize.h"
#include "bitcoin_bignum/version.h"
#include "bitcoin_bignum/clientversion.h"
#include "bitcoin_bignum/netbase.h"
#include "bitcoin_bignum/bignum.h"
#include "bitcoin_bignum/allocators.h"
#include "bitcoin_bignum/hash.h"
#include "bitcoin_bignum/compat.h"

#define ZEROCOIN_DEFAULT_SECURITYLEVEL      80
#define ZEROCOIN_MIN_SECURITY_LEVEL         80
#define ZEROCOIN_MAX_SECURITY_LEVEL         80
#define ACCPROOF_KPRIME                     160
#define ACCPROOF_KDPRIME                    128
#define MAX_COINMINT_ATTEMPTS               10000
#define ZEROCOIN_MINT_PRIME_PARAM            20
#define ZEROCOIN_VERSION_STRING             "0.11"
#define ZEROCOIN_VERSION_INT                11
#define ZEROCOIN_PROTOCOL_VERSION           "1"
#define HASH_OUTPUT_BITS                    256
#define ZEROCOIN_COMMITMENT_EQUALITY_PROOF  "COMMITMENT_EQUALITY_PROOF"
#define ZEROCOIN_ACCUMULATOR_PROOF          "ACCUMULATOR_PROOF"
#define ZEROCOIN_SERIALNUMBER_PROOF         "SERIALNUMBER_PROOF"
#define ZEROCOIN_PUBLICKEY_TO_SERIALNUMBER  "PUBLICKEY_TO_SERIALNUMBER"

// Allocate version control for future upgrades
#define ZEROCOIN_VERSION_1               1

// Activate multithreaded mode for proof verification
#define ZEROCOIN_THREADING 1

// Uses a fast technique for coin generation. Could be more vulnerable
// to timing attacks. Turn off if an attacker can measure coin minting time.
#define    ZEROCOIN_FAST_MINT 1

// We use a SHA256 hash for our PoK challenges. Update the following
// if we ever change hash functions.
#define COMMITMENT_EQUALITY_CHALLENGE_SIZE  256

// A 512-bit security parameter for the statistical ZK PoK.
#define COMMITMENT_EQUALITY_SECMARGIN       512

// Errors thrown by the Zerocoin library

class ZerocoinException : public std::runtime_error
{
public:
    explicit ZerocoinException(const std::string& str) : std::runtime_error(str) {}
};

using namespace std;

int64_t COIN = 1000000000;

namespace libzerocoin {

    class Params;
    class AccumulatorProofOfKnowledge;
    class IntegerGroupParams;
    class AccumulatorWitness;
    class Accumulator;
    class Commitment;
    // Defined in coin.cpp
    extern secp256k1_context* ctx;
    
    class IntegerGroupParams {
    public:
        /** @brief Integer group class, default constructor
         *
         * Allocates an empty (uninitialized) set of parameters.
         **/
        IntegerGroupParams();
        
        /**
         * Generates a random group element
         * @return a random element in the group.
         */
        CBigNum randomElement() const;
        bool initialized;
        
        /**
         * A generator for the group.
         */
        CBigNum g;
        
        /**
         * A second generator for the group.
         * Note log_g(h) and log_h(g) must
         * be unknown.
         */
        CBigNum h;
        
        /**
         * The modulus for the group.
         */
        CBigNum modulus;
        
        /**
         * The order of the group
         */
        CBigNum groupOrder;
        
        IMPLEMENT_SERIALIZE (
                             READWRITE(initialized);
                             READWRITE(g);
                             READWRITE(h);
                             READWRITE(modulus);
                             READWRITE(groupOrder);
                             )
        
    };
    
    class AccumulatorAndProofParams {
    public:
        /** @brief Construct a set of Zerocoin parameters from a modulus "N".
         * @param N                A trusted RSA modulus
         * @param securityLevel    A security level expressed in symmetric bits (default 80)
         *
         * Allocates and derives a set of Zerocoin parameters from
         * a trustworthy RSA modulus "N". This routine calculates all
         * of the remaining parameters (group descriptions etc.) from N
         * using a verifiable, deterministic procedure.
         *
         * Note: this constructor makes the fundamental assumption that "N"
         * encodes a valid RSA-style modulus of the form "e1 * e2" where
         * "e1" and "e2" are safe primes. The factors "e1", "e2" MUST NOT
         * be known to any party, or the security of Zerocoin is
         * compromised. The integer "N" must be a MINIMUM of 1024
         * in length. 3072 bits is strongly recommended.
         **/
        AccumulatorAndProofParams();
        
        //AccumulatorAndProofParams(Bignum accumulatorModulus);
        
        bool initialized;
        
        /**
         * Modulus used for the accumulator.
         * Product of two safe primes who's factorization is unknown.
         */
        CBigNum accumulatorModulus;
        
        /**
         * The initial value for the accumulator
         * A random Quadratic residue mod n thats not 1
         */
        CBigNum accumulatorBase;
        
        /**
         * Lower bound on the value for committed coin.
         * Required by the accumulator proof.
         */
        CBigNum minCoinValue;
        
        /**
         * Upper bound on the value for a comitted coin.
         * Required by the accumulator proof.
         */
        CBigNum maxCoinValue;
        
        /**
         * The second of two groups used to form a commitment to
         * a coin (which it self is a commitment to a serial number).
         * This one differs from serialNumberSokCommitment due to
         * restrictions from Camenisch and Lysyanskaya's paper.
         */
        IntegerGroupParams accumulatorPoKCommitmentGroup;
        
        /**
         * Hidden order quadratic residue group mod N.
         * Used in the accumulator proof.
         */
        IntegerGroupParams accumulatorQRNCommitmentGroup;
        
        /**
         * Security parameter.
         * Bit length of the challenges used in the accumulator proof.
         */
        uint32_t k_prime;
        
        /**
         * Security parameter.
         * The statistical zero-knowledgeness of the accumulator proof.
         */
        uint32_t k_dprime;
        
        IMPLEMENT_SERIALIZE (
                             READWRITE(initialized);
                             READWRITE(accumulatorModulus);
                             READWRITE(accumulatorBase);
                             READWRITE(accumulatorPoKCommitmentGroup);
                             READWRITE(accumulatorQRNCommitmentGroup);
                             READWRITE(minCoinValue);
                             READWRITE(maxCoinValue);
                             READWRITE(k_prime);
                             READWRITE(k_dprime);
                             )
    };
    
    class Params {
    public:
        /** @brief Construct a set of Zerocoin parameters from a modulus "N".
         * @param N                A trusted RSA modulus
         * @param securityLevel    A security level expressed in symmetric bits (default 80)
         *
         * Allocates and derives a set of Zerocoin parameters from
         * a trustworthy RSA modulus "N". This routine calculates all
         * of the remaining parameters (group descriptions etc.) from N
         * using a verifiable, deterministic procedure.
         *
         * Note: this constructor makes the fundamental assumption that "N"
         * encodes a valid RSA-style modulus of the form "e1 * e2" where
         * "e1" and "e2" are safe primes. The factors "e1", "e2" MUST NOT
         * be known to any party, or the security of Zerocoin is
         * compromised. The integer "N" must be a MINIMUM of 1024
         * in length. 3072 bits is strongly recommended.
         **/
        Params(CBigNum accumulatorModulus, CBigNum Nseed, uint32_t securityLevel = ZEROCOIN_DEFAULT_SECURITYLEVEL);
        
        bool initialized;
        
        AccumulatorAndProofParams accumulatorParams;
        
        /**
         * The Quadratic Residue group from which we form
         * a coin as a commitment  to a serial number.
         */
        IntegerGroupParams coinCommitmentGroup;
        
        /**
         * One of two groups used to form a commitment to
         * a coin (which it self is a commitment to a serial number).
         * This is the one used in the serial number poof.
         * It's order must be equal to the modulus of coinCommitmentGroup.
         */
        IntegerGroupParams serialNumberSoKCommitmentGroup;
        
        /**
         * The number of iterations to use in the serial
         * number proof.
         */
        uint32_t zkp_iterations;
        
        /**
         * The amount of the hash function we use for
         * proofs.
         */
        uint32_t zkp_hash_len;
        
        IMPLEMENT_SERIALIZE (
                             READWRITE(initialized);
                             READWRITE(accumulatorParams);
                             READWRITE(coinCommitmentGroup);
                             READWRITE(serialNumberSoKCommitmentGroup);
                             READWRITE(zkp_iterations);
                             READWRITE(zkp_hash_len);
                             )
        
    };
    
    enum  CoinDenomination {
        ZQ_ERROR = 0,
        ZQ_ONE = 1,
        ZQ_FIVE = 5,
        ZQ_TEN = 10,
        ZQ_FIFTY = 50,
        ZQ_ONE_HUNDRED = 100,
        ZQ_FIVE_HUNDRED = 500,
        ZQ_ONE_THOUSAND = 1000,
        ZQ_FIVE_THOUSAND = 5000
    };
    
    // Order is with the Smallest Denomination first and is important for a particular routine that this order is maintained
    const std::vector<CoinDenomination> denominationList = {ZQ_ONE, ZQ_FIVE, ZQ_TEN, ZQ_FIFTY, ZQ_ONE_HUNDRED, ZQ_FIVE_HUNDRED, ZQ_ONE_THOUSAND, ZQ_FIVE_THOUSAND};
    // These are the max number you'd need at any one Denomination before moving to the higher denomination. Last number is 4, since it's the max number of
    // possible spends at the moment    /
    const std::vector<int> maxCoinsPerDenom   = {4, 1, 4, 1, 4, 1, 4, 4};
    
    int64_t ZerocoinDenominationToInt(const CoinDenomination& denomination);
    int64_t ZerocoinDenominationToAmount(const CoinDenomination& denomination);
    CoinDenomination IntToZerocoinDenomination(int64_t amount);
    CoinDenomination AmountToZerocoinDenomination(int64_t amount);
    CoinDenomination AmountToClosestDenomination(int64_t nAmount, int64_t& nRemaining);
    CoinDenomination get_denomination(std::string denomAmount);
    int64_t get_amount(std::string denomAmount);
    
    /** A Public coin is the part of a coin that
     * is published to the network and what is handled
     * by other clients. It contains only the value
     * of commitment to a serial number and the
     * denomination of the coin.
     */
    class PublicCoin {
    public:
        template<typename Stream>
        PublicCoin(const Params* p, Stream& strm): params(p) {
            strm >> *this;
        }
        
        PublicCoin(const Params* p);
        
        /**Generates a public coin
         *
         * @param p cryptographic paramters
         * @param coin the value of the commitment.
         * @param denomination The denomination of the coin. Defaults to ZQ_LOVELACE
         */
        PublicCoin(const Params* p, const Bignum& coin, const CoinDenomination d = ZQ_ONE);
        const Bignum& getValue() const;
        CoinDenomination getDenomination() const;
        bool operator==(const PublicCoin& rhs) const;
        bool operator!=(const PublicCoin& rhs) const;
        /** Checks that a coin prime
         *  and in the appropriate range
         *  given the parameters
         * @return true if valid
         */
        bool validate() const;
        IMPLEMENT_SERIALIZE(
                            READWRITE(value);
                            READWRITE(denomination);
                            )
        //    IMPLEMENT_SERIALIZE
        //    (
        //        READWRITE(value);
        //        READWRITE(denomination);
        //    )
        // Denomination is stored as an INT because storing
        // and enum raises amigiuities in the serialize code //FIXME if possible
        int denomination;
    private:
        const Params* params;
        Bignum value;
    };
    
    /**
     * A private coin. As the name implies, the content
     * of this should stay private except PublicCoin.
     *
     * Contains a coin's serial number, a commitment to it,
     * and opening randomness for the commitment.
     *
     * @warning Failure to keep this secret(or safe),
     * @warning will result in the theft of your coins
     * @warning and a TOTAL loss of anonymity.
     */
    class PrivateCoin {
    public:
        template<typename Stream>
        PrivateCoin(const Params* p, Stream& strm): params(p), publicCoin(p) {
            strm >> *this;
        }
        PrivateCoin(const Params* p, CoinDenomination denomination = ZQ_ONE, int version = ZEROCOIN_VERSION_1);
        const PublicCoin& getPublicCoin() const;
        const Bignum& getSerialNumber() const;
        const Bignum& getRandomness() const;
        const unsigned char* getEcdsaSeckey() const;
        unsigned int getVersion() const;
        static const Bignum serialNumberFromSerializedPublicKey(secp256k1_context *ctx, secp256k1_pubkey *pubkey, uint160& pubHash);
        
        void setPublicCoin(PublicCoin p){
            publicCoin = p;
        }
        
        void setRandomness(Bignum n){
            randomness = n;
        }
        
        void setSerialNumber(Bignum n){
            serialNumber = n;
        }
        
        void setVersion(unsigned int nVersion){
            version = nVersion;
        };
        
        void setEcdsaSeckey(const vector<unsigned char> &seckey) {
            if (seckey.size() == sizeof(ecdsaSeckey))
                std::copy(seckey.cbegin(), seckey.cend(), &ecdsaSeckey[0]);
        }
        
        IMPLEMENT_SERIALIZE(
                            READWRITE(publicCoin);
                            READWRITE(randomness);
                            READWRITE(serialNumber);
                            READWRITE(version);
        //READWRITE(ecdsaSeckey);
        )
        
        /**
         * @brief Mint a new coin.
         * @param denomination the denomination of the coin to mint
         * @throws ZerocoinException if the process takes too long
         *
         * Generates a new Zerocoin by (a) selecting a random serial
         * number, (b) committing to this serial number and repeating until
         * the resulting commitment is prime. Stores the
         * resulting commitment (coin) and randomness (trapdoor).
         **/
        void mintCoin(const CoinDenomination denomination);
        
        /**
         * @brief Mint a new coin using a faster process.
         * @param denomination the denomination of the coin to mint
         * @throws ZerocoinException if the process takes too long
         *
         * Generates a new Zerocoin by (a) selecting a random serial
         * number, (b) committing to this serial number and repeating until
         * the resulting commitment is prime. Stores the
         * resulting commitment (coin) and randomness (trapdoor).
         * This routine is substantially faster than the
         * mintCoin() routine, but could be more vulnerable
         * to timing attacks. Don't use it if you think someone
         * could be timing your coin minting.
         **/
        void mintCoinFast(const CoinDenomination denomination);
        
        PublicCoin publicCoin;
        uint160 pubHash;
        
    private:
        const Params* params;
        Bignum randomness;
        Bignum serialNumber;
        unsigned int version = 0;
        unsigned char ecdsaSeckey[32];
        
    };
    
    class AccumulatorProofOfKnowledge {
    public:
        AccumulatorProofOfKnowledge(const AccumulatorAndProofParams* p);
        
        /** Generates a proof that a commitment to a coin c was accumulated
         * @param p  Cryptographic parameters
         * @param commitmentToCoin commitment containing the coin we want to prove is accumulated
         * @param witness The witness to the accumulation of the coin
         * @param a
         */
        AccumulatorProofOfKnowledge(const AccumulatorAndProofParams* p, const Commitment& commitmentToCoin, const AccumulatorWitness& witness, Accumulator& a);
        /** Verifies that  a commitment c is accumulated in accumulated a
         */
        bool Verify(const Accumulator& a,const Bignum& valueOfCommitmentToCoin) const;
        
        IMPLEMENT_SERIALIZE(
                            READWRITE(C_e);
                            READWRITE(C_u);
                            READWRITE(C_r);
                            READWRITE(st_1);
                            READWRITE(st_2);
                            READWRITE(st_3);
                            READWRITE(t_1);
                            READWRITE(t_2);
                            READWRITE(t_3);
                            READWRITE(t_4);
                            READWRITE(s_alpha);
                            READWRITE(s_beta);
                            READWRITE(s_zeta);
                            READWRITE(s_sigma);
                            READWRITE(s_eta);
                            READWRITE(s_epsilon);
                            READWRITE(s_delta);
                            READWRITE(s_xi);
                            READWRITE(s_phi);
                            READWRITE(s_gamma);
                            READWRITE(s_psi);
                            )
    private:
        const AccumulatorAndProofParams* params;
        
        /* Return values for proof */
        Bignum C_e;
        Bignum C_u;
        Bignum C_r;
        
        Bignum st_1;
        Bignum st_2;
        Bignum st_3;
        
        Bignum t_1;
        Bignum t_2;
        Bignum t_3;
        Bignum t_4;
        
        Bignum s_alpha;
        Bignum s_beta;
        Bignum s_zeta;
        Bignum s_sigma;
        Bignum s_eta;
        Bignum s_epsilon;
        Bignum s_delta;
        Bignum s_xi;
        Bignum s_phi;
        Bignum s_gamma;
        Bignum s_psi;
    };
    
    class Commitment {
    public:
        /**Generates a Pedersen commitment to the given value.
         *
         * @param p the group parameters for the coin
         * @param value the value to commit to
         */
        Commitment(const IntegerGroupParams* p, const Bignum& value);
        const Bignum& getCommitmentValue() const;
        const Bignum& getRandomness() const;
        const Bignum& getContents() const;
    private:
        const IntegerGroupParams *params;
        Bignum commitmentValue;
        Bignum randomness;
        const Bignum contents;
        
        IMPLEMENT_SERIALIZE(
                            READWRITE(commitmentValue);
                            READWRITE(randomness);
                            READWRITE(contents);
                            )
    };
    
    /**Proof that two commitments open to the same value.
     *
     */
    class CommitmentProofOfKnowledge {
    public:
        CommitmentProofOfKnowledge(const IntegerGroupParams* ap, const IntegerGroupParams* bp);
        /** Generates a proof that two commitments, a and b, open to the same value.
         *
         * @param ap the IntegerGroup for commitment a
         * @param bp the IntegerGroup for commitment b
         * @param a the first commitment
         * @param b the second commitment
         */
        CommitmentProofOfKnowledge(const IntegerGroupParams* aParams, const IntegerGroupParams* bParams, const Commitment& a, const Commitment& b);
        //FIXME: is it best practice that this is here?
        template<typename Stream>
        CommitmentProofOfKnowledge(const IntegerGroupParams* aParams,
                                   const IntegerGroupParams* bParams, Stream& strm): ap(aParams), bp(bParams)
        {
            strm >> *this;
        }
        
        const Bignum calculateChallenge(const Bignum& a, const Bignum& b, const Bignum &commitOne, const Bignum &commitTwo) const;
        
        /**Verifies the proof
         *
         * @return true if the proof is valid.
         */
        /**Verifies the proof of equality of the two commitments
         *
         * @param A value of commitment one
         * @param B value of commitment two
         * @return
         */
        bool Verify(const Bignum& A, const Bignum& B) const;
        
        IMPLEMENT_SERIALIZE(
                            READWRITE(S1);
                            READWRITE(S2);
                            READWRITE(S3);
                            READWRITE(challenge);
                            )
        //    IMPLEMENT_SERIALIZE
        //    (
        //        READWRITE(S1);
        //        READWRITE(S2);
        //        READWRITE(S3);
        //        READWRITE(challenge);
        //    )
    private:
        const IntegerGroupParams *ap, *bp;
        
        Bignum S1, S2, S3, challenge;
    };
    
    class SpendMetaData {
    public:
        /**
         * Creates meta data associated with a coin spend
         * @param accumulatorId hash of block containing accumulator
         * @param txHash hash of transaction
         */
        SpendMetaData(uint256 accumulatorId, uint256 txHash);
        
        /**
         * The hash of the block containing the accumulator CoinSpend
         * proves membership in.
         */
        uint256 accumulatorId; // The block the accumulator is in
        /**Contains the hash of the rest of transaction
         * spending a zerocoin (excluding the coinspend proof)
         */
        uint256 txHash; // The Hash of the rest of the transaction the spend proof is n.
        
        IMPLEMENT_SERIALIZE(
                            READWRITE(accumulatorId);
                            READWRITE(txHash);
                            )
    };
    
    class Accumulator {
    public:
        
        /**
         * @brief      Construct an Accumulator from a stream.
         * @param p    An AccumulatorAndProofParams object containing global parameters
         * @param d    the denomination of coins we are accumulating
         * @throw      Zerocoin exception in case of invalid parameters
         **/
        template<typename Stream>
        Accumulator(const AccumulatorAndProofParams* p, Stream& strm): params(p) {
            strm >> *this;
        }
        
        template<typename Stream>
        Accumulator(const Params* p, Stream& strm) {
            strm >> *this;
            this->params = &(p->accumulatorParams);
        }
        
        /**
         * @brief      Construct an Accumulator from a Params object.
         * @param p    A Params object containing global parameters
         * @param d    the denomination of coins we are accumulating
         * @param v    accumulator value
         * @throw      Zerocoin exception in case of invalid parameters
         **/
        Accumulator(const AccumulatorAndProofParams* p, const Bignum &v, const CoinDenomination d = ZQ_ONE);
        Accumulator(const AccumulatorAndProofParams* p, const CoinDenomination d = ZQ_ONE);
        
        Accumulator(const Params* p, const Bignum &v, const CoinDenomination d = ZQ_ONE);
        Accumulator(const Params* p, const CoinDenomination d = ZQ_ONE);
        
        /**
         * Accumulate a coin into the accumulator. Validates
         * the coin prior to accumulation.
         *
         * @param coin    A PublicCoin to accumulate.
         *
         * @throw        Zerocoin exception if the coin is not valid.
         *
         **/
        void accumulate(const PublicCoin &coin, bool validateCoin=false);
        
        CoinDenomination getDenomination() const;
        /** Get the accumulator result
         *
         * @return a Bignum containing the result.
         */
        const Bignum& getValue() const;
        
        
        // /**
        //  * Used to set the accumulator value
        //  *
        //  * Use this to handle accumulator checkpoints
        //  * @param b the value to set the accumulator to.
        //  * @throw  A ZerocoinException if the accumulator value is invalid.
        //  */
        // void setValue(Bignum &b); // shouldn't this be a constructor?
        
        /** Used to accumulate a coin
         *
         * @param c the coin to accumulate
         * @return a refrence to the updated accumulator.
         */
        Accumulator& operator +=(const PublicCoin& c);
        bool operator==(const Accumulator rhs) const;
        
        IMPLEMENT_SERIALIZE(
                            READWRITE(value);
                            READWRITE(denomination);
                            )
    private:
        const AccumulatorAndProofParams* params;
        Bignum value;
        // Denomination is stored as an INT because storing
        // and enum raises amigiuities in the serialize code //FIXME if possible
        int denomination;
    };
    
    /**A witness that a PublicCoin is in the accumulation of a set of coins
     *
     */
    class AccumulatorWitness {
    public:
        template<typename Stream>
        AccumulatorWitness(const Params* p, Stream& strm): params(p) {
            strm >> *this;
        }
        
        /**  Construct's a witness.  You must add all elements after the witness
         * @param p pointer to params
         * @param checkpoint the last known accumulator value before the element was added
         * @param coin the coin we want a witness to
         */
        AccumulatorWitness(const Params* p, const Accumulator& checkpoint, const PublicCoin coin);
        
        /** Adds element to the set whose's accumulation we are proving coin is a member of
         *
         * @param c the coin to add
         */
        void AddElement(const PublicCoin& c);
        
        /**
         *
         * @return the value of the witness
         */
        const Bignum& getValue() const;
        
        /** Checks that this is a witness to the accumulation of coin
         * @param a             the accumulator we are checking against.
         * @param publicCoin    the coin we're providing a witness for
         * @return True if the witness computation validates
         */
        bool VerifyWitness(const Accumulator& a, const PublicCoin &publicCoin) const;
        
        /**
         * Adds rhs to the set whose's accumulation ware proving coin is a member of
         * @param rhs the PublicCoin to add
         * @return
         */
        AccumulatorWitness& operator +=(const PublicCoin& rhs);
    private:
        const Params* params;
        Accumulator witness;
        const PublicCoin element;
    };

    
    class SerialNumberSignatureOfKnowledge {
    public:
        SerialNumberSignatureOfKnowledge(const Params* p);
        /** Creates a Signature of knowledge object that a commitment to a coin contains a coin with serial number x
         *
         * @param p params
         * @param coin the coin we are going to prove the serial number of.
         * @param commitmentToCoin the commitment to the coin
         * @param msghash hash of meta data to create a signature of knowledge on.
         */
        SerialNumberSignatureOfKnowledge(const Params* p, const PrivateCoin& coin, const Commitment& commitmentToCoin, uint256 msghash);
        
        /** Verifies the Signature of knowledge.
         *
         * @param msghash hash of meta data to create a signature of knowledge on.
         * @return
         */
        bool Verify(const Bignum& coinSerialNumber, const Bignum& valueOfCommitmentToCoin,const uint256 msghash) const;
        
        IMPLEMENT_SERIALIZE(
                            READWRITE(s_notprime);
                            READWRITE(sprime);
                            READWRITE(hash);
                            )
    private:
        const Params* params;
        // challenge hash
        uint256 hash; //TODO For efficiency, should this be a bitset where Templates define params?
        
        // challenge response values
        // this is s_notprime instead of s
        // because the serialization macros
        // define something named s and it conflicts
        vector<Bignum> s_notprime;
        vector<Bignum> sprime;
        inline Bignum challengeCalculation(const Bignum& a_exp, const Bignum& b_exp,
                                           const Bignum& h_exp) const;
    };
    
    class ParallelTasks {
    private:
        vector<boost::future<void>> tasks;
        
    public:
        ParallelTasks(int n=0);
        
        // add new task
        void Add(std::function<void()> task);
        
        // wait for everything added so far
        void Wait();
        
        // clear all the tasks from the waiting list
        void Reset();
        
        // helper class to put thread interruption on pause
        class DoNotDisturb {
        private:
            boost::this_thread::disable_interruption dnd;
        public:
            DoNotDisturb() {}
        };
    };
    
    void CalculateParams(Params &params, Bignum N, Bignum Nseed, std::string aux, uint32_t securityLevel);
    void calculateGroupParamLengths(uint32_t maxPLen, uint32_t securityLevel,
                                    uint32_t *pLen, uint32_t *qLen);
    
    // Constants
#define STRING_COMMIT_GROUP         "COIN_COMMITMENT_GROUP"
#define STRING_AVC_GROUP            "ACCUMULATED_VALUE_COMMITMENT_GROUP"
#define STRING_AVC_ORDER            "ACCUMULATED_VALUE_COMMITMENT_ORDER"
#define STRING_AIC_GROUP            "ACCUMULATOR_INTERNAL_COMMITMENT_GROUP"
#define STRING_QRNCOMMIT_GROUPG     "ACCUMULATOR_QRN_COMMITMENT_GROUPG"
#define STRING_QRNCOMMIT_GROUPH     "ACCUMULATOR_QRN_COMMITMENT_GROUPH"
#define ACCUMULATOR_BASE_CONSTANT   31
#define MAX_PRIMEGEN_ATTEMPTS       10000
#define MAX_ACCUMGEN_ATTEMPTS       10000
#define MAX_GENERATOR_ATTEMPTS      10000
#define NUM_SCHNORRGEN_ATTEMPTS     10000
    
    // Prototypes
    bool primalityTestByTrialDivision(uint32_t candidate);
    uint256 calculateSeed(Bignum modulus, std::string auxString, uint32_t securityLevel, std::string groupName);
    uint256 calculateGeneratorSeed(uint256 seed, uint256 pSeed, uint256 qSeed, std::string label, uint32_t index, uint32_t count);
    uint256 calculateHash(uint256 input);
    IntegerGroupParams  deriveIntegerGroupParams(uint256 seed, uint32_t pLen, uint32_t qLen);
    IntegerGroupParams  deriveIntegerGroupFromOrder(Bignum &groupOrder);
    void calculateGroupModulusAndOrder(uint256 seed, uint32_t pLen, uint32_t qLen, Bignum &resultModulus, Bignum &resultGroupOrder, uint256 *resultPseed, uint256 *resultQseed);
    Bignum calculateGroupGenerator(uint256 seed, uint256 pSeed, uint256 qSeed, Bignum modulus, Bignum groupOrder, uint32_t index);
    Bignum generateRandomPrime(uint32_t primeBitLen, uint256 in_seed, uint256 *out_seed, uint32_t *prime_gen_counter);
    Bignum generateIntegerFromSeed(uint32_t numBits, uint256 seed, uint32_t *numIterations);
    bool primalityTestByTrialDivision(uint32_t candidate);
    
    class CoinSpend {
    private:
        template <typename Stream>
        auto is_eof_helper(Stream &s, bool) -> decltype(s.eof()) {
            return s.eof();
        }
        
        template <typename Stream>
        bool is_eof_helper(Stream &s, int) {
            return false;
        }
        
        template<typename Stream>
        bool is_eof(Stream &s) {
            return is_eof_helper(s, true);
        }
        
    public:
        template<typename Stream>
        CoinSpend(const Params* p,  Stream& strm):
        params(p),
        denomination(ZQ_ONE),
        accumulatorPoK(&p->accumulatorParams),
        serialNumberSoK(p),
        commitmentPoK(&p->serialNumberSoKCommitmentGroup, &p->accumulatorParams.accumulatorPoKCommitmentGroup) {
            strm >> *this;
        }
        /**Generates a proof spending a zerocoin.
         *
         * To use this, provide an unspent PrivateCoin, the latest Accumulator
         * (e.g from the most recent Bitcoin block) containing the public part
         * of the coin, a witness to that, and whatever medeta data is needed.
         *
         * Once constructed, this proof can be serialized and sent.
         * It is validated simply be calling validate.
         * @warning Validation only checks that the proof is correct
         * @warning for the specified values in this class. These values must be validated
         *  Clients ought to check that
         * 1) params is the right params
         * 2) the accumulator actually is in some block
         * 3) that the serial number is unspent
         * 4) that the transaction
         *
         * @param p cryptographic parameters
         * @param coin The coin to be spend
         * @param a The current accumulator containing the coin
         * @param witness The witness showing that the accumulator contains the coin
         * @param m arbitrary meta data related to the spend that might be needed by Bitcoin
         *             (i.e. the transaction hash)
         * @throw ZerocoinException if the process fails
         */
        CoinSpend(const Params* p, const PrivateCoin& coin, Accumulator& a, const AccumulatorWitness& witness,
                  const SpendMetaData& m, uint256 _accumulatorBlockHash=uint256());
        
        /** Returns the serial number of the coin spend by this proof.
         *
         * @return the coin's serial number
         */
        const Bignum& getCoinSerialNumber();
        
        /**Gets the denomination of the coin spent in this proof.
         *
         * @return the denomination
         */
        CoinDenomination getDenomination() const;
        
        void setVersion(unsigned int nVersion){
            version = nVersion;
        }
        
        int getVersion() const {
            return version;
        }
        
        uint256 getAccumulatorBlockHash() const {
            return accumulatorBlockHash;
        }
        
        bool HasValidSerial() const;
        bool Verify(const Accumulator& a, const SpendMetaData &metaData) const;
        
        IMPLEMENT_SERIALIZE(
                            READWRITE(denomination);
                            READWRITE(accCommitmentToCoinValue);
                            READWRITE(serialCommitmentToCoinValue);
                            READWRITE(coinSerialNumber);
                            READWRITE(accumulatorPoK);
                            READWRITE(serialNumberSoK);
                            READWRITE(commitmentPoK);
                            READWRITE(version);
                            READWRITE(ecdsaPubkey);
                            READWRITE(ecdsaSignature);
                            READWRITE(accumulatorBlockHash);
                            )
        
    private:
        const Params *params;
        const uint256 signatureHash(const SpendMetaData &m) const;
        // Denomination is stored as an INT because storing
        // and enum raises amigiuities in the serialize code //FIXME if possible
        int denomination;
        unsigned int version = 0;
        Bignum accCommitmentToCoinValue;
        Bignum serialCommitmentToCoinValue;
        Bignum coinSerialNumber;
        std::vector<unsigned char> ecdsaSignature;
        std::vector<unsigned char> ecdsaPubkey;
        AccumulatorProofOfKnowledge accumulatorPoK;
        SerialNumberSignatureOfKnowledge serialNumberSoK;
        CommitmentProofOfKnowledge commitmentPoK;
        uint256 accumulatorBlockHash;
    };
    
}

/* namespace libzerocoin */
#endif /* libzerocoin_h */
