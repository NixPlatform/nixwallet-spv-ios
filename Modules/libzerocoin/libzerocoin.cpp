//
//  libzerocoin.cpp
//  nixwallet
//
//  Created by Matthew T on 1/4/19.
//  Copyright © 2019 Nix Platform. All rights reserved.
//

#include "libzerocoin.h"


namespace libzerocoin {
    
    Params::Params(CBigNum N, CBigNum Nseed, uint32_t securityLevel) {
        this->zkp_hash_len = securityLevel;
        this->zkp_iterations = securityLevel;
        
        this->accumulatorParams.k_prime = ACCPROOF_KPRIME;
        this->accumulatorParams.k_dprime = ACCPROOF_KDPRIME;
        
        // Generate the parameters
        CalculateParams(*this, N, Nseed, ZEROCOIN_PROTOCOL_VERSION, securityLevel);
        
        this->accumulatorParams.initialized = true;
        this->initialized = true;
    }
    
    AccumulatorAndProofParams::AccumulatorAndProofParams() {
        this->initialized = false;
    }
    
    IntegerGroupParams::IntegerGroupParams() {
        this->initialized = false;
    }
    
    Bignum IntegerGroupParams::randomElement() const {
        // The generator of the group raised
        // to a random number less than the order of the group
        // provides us with a uniformly distributed random number.
        return this->g.pow_mod(Bignum::randBignum(this->groupOrder),this->modulus);
    }

    CoinSpend::CoinSpend(const Params* p, const PrivateCoin& coin,
                         Accumulator& a, const AccumulatorWitness& witness, const SpendMetaData& m,
                         uint256 _accumulatorBlockHash):
    params(p),
    denomination(coin.getPublicCoin().getDenomination()),
    coinSerialNumber((coin.getSerialNumber())),
    ecdsaSignature(64, 0),
    ecdsaPubkey(33, 0),
    accumulatorPoK(&p->accumulatorParams),
    serialNumberSoK(p),
    commitmentPoK(&p->serialNumberSoKCommitmentGroup, &p->accumulatorParams.accumulatorPoKCommitmentGroup),
    accumulatorBlockHash(_accumulatorBlockHash)
    {
        
        // Sanity check: let's verify that the Witness is valid with respect to
        // the coin and Accumulator provided.
        if (!(witness.VerifyWitness(a, coin.getPublicCoin()))) {
            throw ZerocoinException("Accumulator witness does not verify");
        }
        
        if (!HasValidSerial()) {
            throw ZerocoinException("Invalid serial # range");
        }
        
        // 1: Generate two separate commitments to the public coin (C), each under
        // a different set of public parameters. We do this because the RSA accumulator
        // has specific requirements for the commitment parameters that are not
        // compatible with the group we use for the serial number proof.
        // Specifically, our serial number proof requires the order of the commitment group
        // to be the same as the modulus of the upper group. The Accumulator proof requires a
        // group with a significantly larger order.
        const Commitment fullCommitmentToCoinUnderSerialParams(&p->serialNumberSoKCommitmentGroup, coin.getPublicCoin().getValue());
        this->serialCommitmentToCoinValue = fullCommitmentToCoinUnderSerialParams.getCommitmentValue();
        
        const Commitment fullCommitmentToCoinUnderAccParams(&p->accumulatorParams.accumulatorPoKCommitmentGroup, coin.getPublicCoin().getValue());
        this->accCommitmentToCoinValue = fullCommitmentToCoinUnderAccParams.getCommitmentValue();
        
        // 2. Generate a ZK proof that the two commitments contain the same public coin.
        this->commitmentPoK = CommitmentProofOfKnowledge(&p->serialNumberSoKCommitmentGroup, &p->accumulatorParams.accumulatorPoKCommitmentGroup, fullCommitmentToCoinUnderSerialParams, fullCommitmentToCoinUnderAccParams);
        
        // Now generate the two core ZK proofs:
        // 3. Proves that the committed public coin is in the Accumulator (PoK of "witness")
        this->accumulatorPoK = AccumulatorProofOfKnowledge(&p->accumulatorParams, fullCommitmentToCoinUnderAccParams, witness, a);
        
        // 4. Proves that the coin is correct w.r.t. serial number and hidden coin secret
        // (This proof is bound to the coin 'metadata', i.e., transaction hash)
        uint256 metahash = signatureHash(m);
        this->serialNumberSoK = SerialNumberSignatureOfKnowledge(p, coin, fullCommitmentToCoinUnderSerialParams, coin.getVersion()==ZEROCOIN_VERSION_1 ? metahash : uint256());
        
        if(coin.getVersion() == 1){
            // 5. Sign the transaction under the public key associate with the serial number.
            secp256k1_pubkey pubkey;
            size_t len = 33;
            secp256k1_ecdsa_signature sig;
            
            // TODO timing channel, since secp256k1_ec_pubkey_serialize does not expect its output to be secret.
            // See main_impl.h of ecdh module on secp256k1
            if (!secp256k1_ec_pubkey_create(ctx, &pubkey, coin.getEcdsaSeckey())) {
                throw ZerocoinException("Invalid secret key");
            }
            secp256k1_ec_pubkey_serialize(ctx, &this->ecdsaPubkey[0], &len, &pubkey, SECP256K1_EC_COMPRESSED);
            
            secp256k1_ecdsa_sign(ctx, &sig, metahash.begin(), coin.getEcdsaSeckey(), NULL, NULL);
            secp256k1_ecdsa_signature_serialize_compact(ctx, &this->ecdsaSignature[0], &sig);
        }
    }
    
    const Bignum&CoinSpend::getCoinSerialNumber() {
        return this->coinSerialNumber;
    }
    
    CoinDenomination CoinSpend::getDenomination() const {
        return static_cast<CoinDenomination>(this->denomination);
    }
    
    bool CoinSpend::Verify(const Accumulator& a, const SpendMetaData &m) const {
        if (!HasValidSerial())
            return false;
        
        uint256 metahash = signatureHash(m);
        // Verify both of the sub-proofs using the given meta-data
        int ret = (a.getDenomination() == this->denomination)
        && commitmentPoK.Verify(serialCommitmentToCoinValue, accCommitmentToCoinValue)
        && accumulatorPoK.Verify(a, accCommitmentToCoinValue)
        && serialNumberSoK.Verify(coinSerialNumber, serialCommitmentToCoinValue, this->version == ZEROCOIN_VERSION_1 ? metahash : uint256());
        if (!ret) {
            return false;
        }
        
        
        if (this->version != 1) {
            return ret;
        }
        else {
            // Check if this is a coin that requires a signatures
            if (coinSerialNumber.bitSize() > 160)
                return false;
            
            // Check sizes
            if (this->ecdsaPubkey.size() != 33 || this->ecdsaSignature.size() != 64) {
                return false;
            }
            
            // Verify signature
            secp256k1_pubkey pubkey;
            secp256k1_ecdsa_signature signature;
            
            if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, ecdsaPubkey.data(), 33)) {
                return false;
            }
            
            uint160 pubHash;
            // Recompute and compare hash of public key
            if (coinSerialNumber != PrivateCoin::serialNumberFromSerializedPublicKey(ctx, &pubkey, pubHash)) {
                return false;
            }
            
            secp256k1_ecdsa_signature_parse_compact(ctx, &signature, ecdsaSignature.data());
            if (!secp256k1_ecdsa_verify(ctx, &signature, metahash.begin(), &pubkey)) {
                return false;
            }
            
            return true;
        }
        
    }
    
    bool CoinSpend::HasValidSerial() const {
        return coinSerialNumber > 0 && coinSerialNumber < params->coinCommitmentGroup.groupOrder;
    }
    
    const uint256 CoinSpend::signatureHash(const SpendMetaData &m) const {
        CHashWriter h(0,0);
        h << m << serialCommitmentToCoinValue << accCommitmentToCoinValue << commitmentPoK << accumulatorPoK;
        return h.GetHash();
    }

    
    void CalculateParams(Params &params, Bignum N, Bignum Nseed, string aux, uint32_t securityLevel) {
        params.initialized = false;
        params.accumulatorParams.initialized = false;
        
        // Verify that |N| is > 1023 bits.
        uint32_t NLen = N.bitSize();
        if (NLen < 1023) {
            throw ZerocoinException("Modulus must be at least 1023 bits");
        }
        
        // Verify that "securityLevel" is  at least 80 bits (minimum).
        if (securityLevel < 80) {
            throw ZerocoinException("Security level must be at least 80 bits.");
        }
        
        // Set the accumulator modulus to "N".
        params.accumulatorParams.accumulatorModulus = N;
        
        // Calculate the required size of the field "F_p" into which
        // we're embedding the coin commitment group. This may throw an
        // exception if the securityLevel is too large to be supported
        // by the current modulus.
        uint32_t pLen = 0;
        uint32_t qLen = 0;
        calculateGroupParamLengths(NLen - 2, securityLevel, &pLen, &qLen);
        
        // Calculate candidate parameters ("p", "q") for the coin commitment group
        // using a deterministic process based on "N", the "aux" string, and
        // the dedicated string "COMMITMENTGROUP".
        params.coinCommitmentGroup = deriveIntegerGroupParams(calculateSeed(Nseed, aux, securityLevel, STRING_COMMIT_GROUP),
                                                              pLen, qLen);
        
        // Next, we derive parameters for a second Accumulated Value commitment group.
        // This is a Schnorr group with the specific property that the order of the group
        // must be exactly equal to "q" from the commitment group. We set
        // the modulus of the new group equal to "2q+1" and test to see if this is prime.
        params.serialNumberSoKCommitmentGroup = deriveIntegerGroupFromOrder(params.coinCommitmentGroup.modulus);
        
        // Calculate the parameters for the internal commitment
        // using the same process.
        params.accumulatorParams.accumulatorPoKCommitmentGroup = deriveIntegerGroupParams(
                                                                                          calculateSeed(Nseed, aux, securityLevel, STRING_AIC_GROUP),
                                                                                          qLen + 300, qLen + 1);
        
        // Calculate the parameters for the accumulator QRN commitment generators. This isn't really
        // a whole group, just a pair of random generators in QR_N.
        uint32_t resultCtr;
        params.accumulatorParams.accumulatorQRNCommitmentGroup.g = generateIntegerFromSeed(NLen - 1,
                                                                                           calculateSeed(N, aux,
                                                                                                         securityLevel,
                                                                                                         STRING_QRNCOMMIT_GROUPG),
                                                                                           &resultCtr).pow_mod(
                                                                                                               Bignum(2), N);
        params.accumulatorParams.accumulatorQRNCommitmentGroup.h = generateIntegerFromSeed(NLen - 1,
                                                                                           calculateSeed(N, aux,
                                                                                                         securityLevel,
                                                                                                         STRING_QRNCOMMIT_GROUPH),
                                                                                           &resultCtr).pow_mod(
                                                                                                               Bignum(2), N);
        
        // Calculate the accumulator base, which we calculate as "u = C**2 mod N"
        // where C is an arbitrary value. In the unlikely case that "u = 1" we increment
        // "C" and repeat.
        Bignum constant(ACCUMULATOR_BASE_CONSTANT);
        params.accumulatorParams.accumulatorBase = Bignum(1);
        for (uint32_t count = 0;
             count < MAX_ACCUMGEN_ATTEMPTS && params.accumulatorParams.accumulatorBase.isOne(); count++) {
            params.accumulatorParams.accumulatorBase = constant.pow_mod(Bignum(2),
                                                                        params.accumulatorParams.accumulatorModulus);
        }
        
        // Compute the accumulator range. The upper range is the largest possible coin commitment value.
        // The lower range is sqrt(upper range) + 1. Since OpenSSL doesn't have
        // a square root function we use a slightly higher approximation.
        params.accumulatorParams.maxCoinValue = params.coinCommitmentGroup.modulus;
        params.accumulatorParams.minCoinValue = Bignum(2).pow((params.coinCommitmentGroup.modulus.bitSize() / 2) + 3);
        
        // If all went well, mark params as successfully initialized.
        params.accumulatorParams.initialized = true;
        
        // If all went well, mark params as successfully initialized.
        params.initialized = true;
    }
    
    /// \brief Format a seed string by hashing several values.
    /// \param N                A Bignum
    /// \param aux              An auxiliary string
    /// \param securityLevel    The security level in bits
    /// \param groupName        A group description string
    /// \throws         ZerocoinException if the process fails
    ///
    /// Returns the hash of the value.
    
    uint256 calculateGeneratorSeed(uint256 seed, uint256 pSeed, uint256 qSeed, string label, uint32_t index, uint32_t count) {
        CHashWriter hasher(0, 0);
        uint256 hash;
        
        // Compute the hash of:
        // <modulus>||<securitylevel>||<auxString>||groupName
        hasher << seed;
        hasher << string("||");
        hasher << pSeed;
        hasher << string("||");
        hasher << qSeed;
        hasher << string("||");
        hasher << label;
        hasher << string("||");
        hasher << index;
        hasher << string("||");
        hasher << count;
        
        return hasher.GetHash();
    }
    
    /// \brief Format a seed string by hashing several values.
    /// \param N                A Bignum
    /// \param aux              An auxiliary string
    /// \param securityLevel    The security level in bits
    /// \param groupName        A group description string
    /// \throws         ZerocoinException if the process fails
    ///
    /// Returns the hash of the value.
    
    uint256 calculateSeed(Bignum modulus, string auxString, uint32_t securityLevel, string groupName) {
        CHashWriter hasher(0, 0);
        uint256 hash;
        
        // Compute the hash of:
        // <modulus>||<securitylevel>||<auxString>||groupName
        hasher << modulus;
        hasher << string("||");
        hasher << securityLevel;
        hasher << string("||");
        hasher << auxString;
        hasher << string("||");
        hasher << groupName;
        
        uint256 hx = (hasher.GetHash());
        return hx;
    }
    
    uint256 calculateHash(uint256 input) {
        CHashWriter hasher(0, 0);
        
        // Compute the hash of "input"
        hasher << input;
        uint256 hx = (hasher.GetHash());
        return hx;
    }
    
    /// \brief Calculate field/group parameter sizes based on a security level.
    /// \param maxPLen          Maximum size of the field (modulus "p") in bits.
    /// \param securityLevel    Required security level in bits (at least 80)
    /// \param pLen             Result: length of "p" in bits
    /// \param qLen             Result: length of "q" in bits
    /// \throws                 ZerocoinException if the process fails
    ///
    /// Calculates the appropriate sizes of "p" and "q" for a prime-order
    /// subgroup of order "q" embedded within a field "F_p". The sizes
    /// are based on a 'securityLevel' provided in symmetric-equivalent
    /// bits. Our choices slightly exceed the specs in FIPS 186-3:
    ///
    /// securityLevel = 80:     pLen = 1024, qLen = 256
    /// securityLevel = 112:    pLen = 2048, qLen = 256
    /// securityLevel = 128:    qLen = 3072, qLen = 320
    ///
    /// If the length of "p" exceeds the length provided in "maxPLen", or
    /// if "securityLevel < 80" this routine throws an exception.
    
    void calculateGroupParamLengths(uint32_t maxPLen, uint32_t securityLevel,
                                    uint32_t *pLen, uint32_t *qLen) {
        *pLen = *qLen = 0;
        
        if (securityLevel < 80) {
            throw ZerocoinException("Security level must be at least 80 bits.");
        } else if (securityLevel == 80) {
            *qLen = 256;
            *pLen = 1024;
        } else if (securityLevel <= 112) {
            *qLen = 256;
            *pLen = 2048;
        } else if (securityLevel <= 128) {
            *qLen = 320;
            *pLen = 3072;
        } else {
            throw ZerocoinException("Security level not supported.");
        }
        
        if (*pLen > maxPLen) {
            throw ZerocoinException("Modulus size is too small for this security level.");
        }
    }
    
    /// \brief Deterministically compute a set of group parameters using NIST procedures.
    /// \param seedStr  A byte string seeding the process.
    /// \param pLen     The desired length of the modulus "p" in bits
    /// \param qLen     The desired length of the order "q" in bits
    /// \return         An IntegerGroupParams object
    ///
    /// Calculates the description of a group G of prime order "q" embedded within
    /// a field "F_p". The input to this routine is in arbitrary seed. It uses the
    /// algorithms described in FIPS 186-3 Appendix A.1.2 to calculate
    /// primes "p" and "q". It uses the procedure in Appendix A.2.3 to
    /// derive two generators "g", "h".
    
    IntegerGroupParams deriveIntegerGroupParams(uint256 seed, uint32_t pLen, uint32_t qLen) {
        IntegerGroupParams result;
        Bignum p;
        Bignum q;
        uint256 pSeed, qSeed;
        
        // Calculate "p" and "q" and "domain_parameter_seed" from the
        // "seed" buffer above, using the procedure described in NIST
        // FIPS 186-3, Appendix A.1.2.
        calculateGroupModulusAndOrder(seed, pLen, qLen, result.modulus,
                                      result.groupOrder, &pSeed, &qSeed);
        
        // Calculate the generators "g", "h" using the process described in
        // NIST FIPS 186-3, Appendix A.2.3. This algorithm takes ("p", "q",
        // "domain_parameter_seed", "index"). We use "index" value 1
        // to generate "g" and "index" value 2 to generate "h".
        result.g = calculateGroupGenerator(seed, pSeed, qSeed, result.modulus, result.groupOrder, 1);
        result.h = calculateGroupGenerator(seed, pSeed, qSeed, result.modulus, result.groupOrder, 2);
        
        // Perform some basic tests to make sure we have good parameters
        if ((uint32_t)(result.modulus.bitSize()) < pLen ||          // modulus is pLen bits long
            (uint32_t)(result.groupOrder.bitSize()) < qLen ||       // order is qLen bits long
            !(result.modulus.isPrime()) ||                          // modulus is prime
            !(result.groupOrder.isPrime()) ||                       // order is prime
            !((result.g.pow_mod(result.groupOrder, result.modulus)).isOne()) || // g^order mod modulus = 1
            !((result.h.pow_mod(result.groupOrder, result.modulus)).isOne()) || // h^order mod modulus = 1
            ((result.g.pow_mod(Bignum(100), result.modulus)).isOne()) ||        // g^100 mod modulus != 1
            ((result.h.pow_mod(Bignum(100), result.modulus)).isOne()) ||        // h^100 mod modulus != 1
            result.g == result.h ||                                 // g != h
            result.g.isOne()) {                                     // g != 1
            // If any of the above tests fail, throw an exception
            throw ZerocoinException("Group parameters are not valid");
        }
        
        return result;
    }
    
    /// \brief Deterministically compute a  set of group parameters with a specified order.
    /// \param groupOrder   The order of the group
    /// \return         An IntegerGroupParams object
    ///
    /// Given "q" calculates the description of a group G of prime order "q" embedded within
    /// a field "F_p".
    
    IntegerGroupParams
    deriveIntegerGroupFromOrder(Bignum &groupOrder) {
        IntegerGroupParams result;
        
        // Set the order to "groupOrder"
        result.groupOrder = groupOrder;
        
        // Try possible values for "modulus" of the form "groupOrder * 2 * i" where
        // "p" is prime and i is a counter starting at 1.
        for (uint32_t i = 1; i < NUM_SCHNORRGEN_ATTEMPTS; i++) {
            // Set modulus equal to "groupOrder * 2 * i"
            result.modulus = (result.groupOrder * Bignum(i * 2)) + Bignum(1);
            
            // Test the result for primality
            // TODO: This is a probabilistic routine and thus not the right choice
            if (result.modulus.isPrime(256)) {
                
                // Success.
                //
                // Calculate the generators "g", "h" using the process described in
                // NIST FIPS 186-3, Appendix A.2.3. This algorithm takes ("p", "q",
                // "domain_parameter_seed", "index"). We use "index" value 1
                // to generate "g" and "index" value 2 to generate "h".
                uint256 seed = calculateSeed(groupOrder, "", 128, "");
                uint256 pSeed = calculateHash(seed);
                uint256 qSeed = calculateHash(pSeed);
                result.g = calculateGroupGenerator(seed, pSeed, qSeed, result.modulus, result.groupOrder, 1);
                result.h = calculateGroupGenerator(seed, pSeed, qSeed, result.modulus, result.groupOrder, 2);
                
                // Perform some basic tests to make sure we have good parameters
                if (!(result.modulus.isPrime()) ||                          // modulus is prime
                    !(result.groupOrder.isPrime()) ||                       // order is prime
                    !((result.g.pow_mod(result.groupOrder, result.modulus)).isOne()) || // g^order mod modulus = 1
                    !((result.h.pow_mod(result.groupOrder, result.modulus)).isOne()) || // h^order mod modulus = 1
                    ((result.g.pow_mod(Bignum(100), result.modulus)).isOne()) ||        // g^100 mod modulus != 1
                    ((result.h.pow_mod(Bignum(100), result.modulus)).isOne()) ||        // h^100 mod modulus != 1
                    result.g == result.h ||                                 // g != h
                    result.g.isOne()) {                                     // g != 1
                    // If any of the above tests fail, throw an exception
                    throw ZerocoinException("Group parameters are not valid");
                }
                
                return result;
            }
        }
        
        // If we reached this point group generation has failed. Throw an exception.
        throw ZerocoinException("Too many attempts to generate Schnorr group.");
    }
    
    /// \brief Deterministically compute a group description using NIST procedures.
    /// \param seed                         A byte string seeding the process.
    /// \param pLen                         The desired length of the modulus "p" in bits
    /// \param qLen                         The desired length of the order "q" in bits
    /// \param resultModulus                A value "p" describing a finite field "F_p"
    /// \param resultGroupOrder             A value "q" describing the order of a subgroup
    /// \param resultDomainParameterSeed    A resulting seed for use in later calculations.
    ///
    /// Calculates the description of a group G of prime order "q" embedded within
    /// a field "F_p". The input to this routine is in arbitrary seed. It uses the
    /// algorithms described in FIPS 186-3 Appendix A.1.2 to calculate
    /// primes "p" and "q".
    
    void calculateGroupModulusAndOrder(uint256 seed, uint32_t pLen, uint32_t qLen,
                                       Bignum &resultModulus, Bignum &resultGroupOrder,
                                       uint256 *resultPseed, uint256 *resultQseed) {
        // Verify that the seed length is >= qLen
        if (qLen > (sizeof(seed)) * 8) {
            // TODO: The use of 256-bit seeds limits us to 256-bit group orders. We should probably change this.
            // throw ZerocoinException("Seed is too short to support the required security level.");
        }
        
#ifdef ZEROCOIN_DEBUG
        cout << "calculateGroupModulusAndOrder: pLen = " << pLen << endl;
#endif
        
        // Generate a random prime for the group order.
        // This may throw an exception, which we'll pass upwards.
        // Result is the value "resultGroupOrder", "qseed" and "qgen_counter".
        uint256 qseed;
        uint32_t qgen_counter;
        resultGroupOrder = generateRandomPrime(qLen, seed, &qseed, &qgen_counter);
        
        // Using ⎡pLen / 2 + 1⎤ as the length and qseed as the input_seed, use the random prime
        // routine to obtain p0 , pseed, and pgen_counter. We pass exceptions upward.
        uint32_t p0len = ceil((pLen / 2.0) + 1);
        uint256 pseed;
        uint32_t pgen_counter;
        Bignum p0 = generateRandomPrime(p0len, qseed, &pseed, &pgen_counter);
        
        // Set x = 0, old_counter = pgen_counter
        uint32_t old_counter = pgen_counter;
        
        // Generate a random integer "x" of pLen bits
        uint32_t iterations;
        Bignum x = generateIntegerFromSeed(pLen, pseed, &iterations);
        pseed += (iterations + 1);
        
        // Set x = 2^{pLen−1} + (x mod 2^{pLen–1}).
        Bignum powerOfTwo = Bignum(2).pow(pLen - 1);
        x = powerOfTwo + (x % powerOfTwo);
        
        // t = ⎡x / (2 * resultGroupOrder * p0)⎤.
        // TODO: we don't have a ceiling function
        Bignum t = x / (Bignum(2) * resultGroupOrder * p0);
        
        // Now loop until we find a valid prime "p" or we fail due to
        // pgen_counter exceeding ((4*pLen) + old_counter).
        for (; pgen_counter <= ((4 * pLen) + old_counter); pgen_counter++) {
            // If (2 * t * resultGroupOrder * p0 + 1) > 2^{pLen}, then
            // t = ⎡2^{pLen−1} / (2 * resultGroupOrder * p0)⎤.
            powerOfTwo = Bignum(2).pow(pLen);
            Bignum prod = (Bignum(2) * t * resultGroupOrder * p0) + Bignum(1);
            if (prod > powerOfTwo) {
                // TODO: implement a ceil function
                t = Bignum(2).pow(pLen - 1) / (Bignum(2) * resultGroupOrder * p0);
            }
            
            // Compute a candidate prime resultModulus = 2tqp0 + 1.
            resultModulus = (Bignum(2) * t * resultGroupOrder * p0) + Bignum(1);
            
            // Verify that resultModulus is prime. First generate a pseudorandom integer "a".
            Bignum a = generateIntegerFromSeed(pLen, pseed, &iterations);
            pseed += iterations + 1;
            
            // Set a = 2 + (a mod (resultModulus–3)).
            a = Bignum(2) + (a % (resultModulus - Bignum(3)));
            
            // Set z = a^{2 * t * resultGroupOrder} mod resultModulus
            Bignum z = a.pow_mod(Bignum(2) * t * resultGroupOrder, resultModulus);
            
            // If GCD(z–1, resultModulus) == 1 AND (z^{p0} mod resultModulus == 1)
            // then we have found our result. Return.
            if ((resultModulus.gcd(z - Bignum(1))).isOne() &&
                (z.pow_mod(p0, resultModulus)).isOne()) {
                // Success! Return the seeds and primes.
                *resultPseed = pseed;
                *resultQseed = qseed;
                return;
            }
            
            // This prime did not work out. Increment "t" and try again.
            t = t + Bignum(1);
        } // loop continues until pgen_counter exceeds a limit
        
        // We reach this point only if we exceeded our maximum iteration count.
        // Throw an exception.
        throw ZerocoinException("Unable to generate a prime modulus for the group");
    }
    
    /// \brief Deterministically compute a generator for a given group.
    /// \param seed                         A first seed for the process.
    /// \param pSeed                        A second seed for the process.
    /// \param qSeed                        A third seed for the process.
    /// \param modulus                      Proposed prime modulus for the field.
    /// \param groupOrder                   Proposed order of the group.
    /// \param index                        Index value, selects which generator you're building.
    /// \return                             The resulting generator.
    /// \throws                             A ZerocoinException if error.
    ///
    /// Generates a random group generator deterministically as a function of (seed,pSeed,qSeed)
    /// Uses the algorithm described in FIPS 186-3 Appendix A.2.3.
    
    Bignum calculateGroupGenerator(uint256 seed, uint256 pSeed, uint256 qSeed, Bignum modulus,
                                   Bignum groupOrder, uint32_t index) {
        Bignum result;
        
        // Verify that 0 <= index < 256
        if (index > 255) {
            throw ZerocoinException("Invalid index for group generation");
        }
        
        // Compute e = (modulus - 1) / groupOrder
        Bignum e = (modulus - Bignum(1)) / groupOrder;
        
        // Loop until we find a generator
        for (uint32_t count = 1; count < MAX_GENERATOR_ATTEMPTS; count++) {
            // hash = Hash(seed || pSeed || qSeed || “ggen” || index || count
            uint256 hash = calculateGeneratorSeed(seed, pSeed, qSeed, "ggen", index, count);
            Bignum W(hash);
            
            // Compute result = W^e mod p
            result = W.pow_mod(e, modulus);
            
            // If result > 1, we have a generator
            if (result > 1) {
                return result;
            }
        }
        
        // We only get here if we failed to find a generator
        throw ZerocoinException("Unable to find a generator, too many attempts");
    }
    
    /// \brief Deterministically compute a random prime number.
    /// \param primeBitLen                  Desired bit length of the prime.
    /// \param in_seed                      Input seed for the process.
    /// \param out_seed                     Result: output seed from the process.
    /// \param prime_gen_counter            Result: number of iterations required.
    /// \return                             The resulting prime number.
    /// \throws                             A ZerocoinException if error.
    ///
    /// Generates a random prime number of primeBitLen bits from a given input
    /// seed. Uses the Shawe-Taylor algorithm as described in FIPS 186-3
    /// Appendix C.6. This is a recursive function.
    
    Bignum generateRandomPrime(uint32_t primeBitLen, uint256 in_seed, uint256 *out_seed,
                               uint32_t *prime_gen_counter) {
        // Verify that primeBitLen is not too small
        if (primeBitLen < 2) {
            throw ZerocoinException("Prime length is too short");
        }
        
        // If primeBitLen < 33 bits, perform the base case.
        if (primeBitLen < 33) {
            Bignum result(0);
            
            // Set prime_seed = in_seed, prime_gen_counter = 0.
            uint256 prime_seed = in_seed;
            (*prime_gen_counter) = 0;
            
            // Loop up to "4 * primeBitLen" iterations.
            while ((*prime_gen_counter) < (4 * primeBitLen)) {
                
                // Generate a pseudorandom integer "c" of length primeBitLength bits
                uint32_t iteration_count;
                Bignum c = generateIntegerFromSeed(primeBitLen, prime_seed, &iteration_count);
#ifdef ZEROCOIN_DEBUG
                cout << "generateRandomPrime: primeBitLen = " << primeBitLen << endl;
                cout << "Generated c = " << c << endl;
#endif
                
                prime_seed += (iteration_count + 1);
                (*prime_gen_counter)++;
                
                // Set "intc" to be the least odd integer >= "c" we just generated
                uint32_t intc = c.getulong();
                intc = (2 * floor(intc / 2.0)) + 1;
#ifdef ZEROCOIN_DEBUG
                cout << "Should be odd. c = " << intc << endl;
                cout << "The big num is: c = " << c << endl;
#endif
                
                // Perform trial division on this (relatively small) integer to determine if "intc"
                // is prime. If so, return success.
                if (primalityTestByTrialDivision(intc)) {
                    // Return "intc" converted back into a Bignum and "prime_seed". We also updated
                    // the variable "prime_gen_counter" in previous statements.
                    result = intc;
                    *out_seed = prime_seed;
                    
                    // Success
                    return result;
                }
            } // while()
            
            // If we reached this point there was an error finding a candidate prime
            // so throw an exception.
            throw ZerocoinException("Unable to find prime in Shawe-Taylor algorithm");
            
            // END OF BASE CASE
        }
        // If primeBitLen >= 33 bits, perform the recursive case.
        else {
            // Recurse to find a new random prime of roughly half the size
            uint32_t newLength = ceil((double) primeBitLen / 2.0) + 1;
            Bignum c0 = generateRandomPrime(newLength, in_seed, out_seed, prime_gen_counter);
            
            // Generate a random integer "x" of primeBitLen bits using the output
            // of the previous call.
            uint32_t numIterations;
            Bignum x = generateIntegerFromSeed(primeBitLen, *out_seed, &numIterations);
            (*out_seed) += numIterations + 1;
            
            // Compute "t" = ⎡x / (2 * c0⎤
            // TODO no Ceiling call
            Bignum t = x / (Bignum(2) * c0);
            
            // Repeat the following procedure until we find a prime (or time out)
            for (uint32_t testNum = 0; testNum < MAX_PRIMEGEN_ATTEMPTS; testNum++) {
                
                // If ((2 * t * c0) + 1 > 2^{primeBitLen}),
                // then t = ⎡2^{primeBitLen} – 1 / (2 * c0)⎤.
                if ((Bignum(2) * t * c0) > (Bignum(2).pow(Bignum(primeBitLen)))) {
                    t = ((Bignum(2).pow(Bignum(primeBitLen))) - Bignum(1)) / (Bignum(2) * c0);
                }
                
                // Set c = (2 * t * c0) + 1
                Bignum c = (Bignum(2) * t * c0) + Bignum(1);
                
                // Increment prime_gen_counter
                (*prime_gen_counter)++;
                
                // Test "c" for primality as follows:
                // 1. First pick an integer "a" in between 2 and (c - 2)
                Bignum a = generateIntegerFromSeed(c.bitSize(), (*out_seed), &numIterations);
                a = Bignum(2) + (a % (c - Bignum(3)));
                (*out_seed) += (numIterations + 1);
                
                // 2. Compute "z" = a^{2*t} mod c
                Bignum z = a.pow_mod(Bignum(2) * t, c);
                
                // 3. Check if "c" is prime.
                //    Specifically, verify that gcd((z-1), c) == 1 AND (z^c0 mod c) == 1
                // If so we return "c" as our result.
                if (c.gcd(z - Bignum(1)).isOne() && z.pow_mod(c0, c).isOne()) {
                    // Return "c", out_seed and prime_gen_counter
                    // (the latter two of which were already updated)
                    return c;
                }
                
                // 4. If the test did not succeed, increment "t" and loop
                t = t + Bignum(1);
            } // end of test loop
        }
        
        // We only reach this point if the test loop has iterated MAX_PRIMEGEN_ATTEMPTS
        // and failed to identify a valid prime. Throw an exception.
        throw ZerocoinException("Unable to generate random prime (too many tests)");
    }
    
    Bignum generateIntegerFromSeed(uint32_t numBits, uint256 seed, uint32_t *numIterations) {
        Bignum result(0);
        uint32_t iterations = ceil((double) numBits / (double) HASH_OUTPUT_BITS);
        
#ifdef ZEROCOIN_DEBUG
        cout << "numBits = " << numBits << endl;
        cout << "iterations = " << iterations << endl;
#endif
        
        // Loop "iterations" times filling up the value "result" with random bits
        for (uint32_t count = 0; count < iterations; count++) {
            // result += ( H(pseed + count) * 2^{count * p0len} )
            result += Bignum(calculateHash(seed + count)) * Bignum(2).pow(count * HASH_OUTPUT_BITS);
        }
        
        result = Bignum(2).pow(numBits - 1) + (result % (Bignum(2).pow(numBits - 1)));
        
        // Return the number of iterations and the result
        *numIterations = iterations;
        return result;
    }
    
    /// \brief Determines whether a uint32_t is a prime through trial division.
    /// \param candidate       Candidate to test.
    /// \return                true if the value is prime, false otherwise
    ///
    /// Performs trial division to determine whether a uint32_t is prime.
    
    bool
    primalityTestByTrialDivision(uint32_t candidate) {
        // TODO: HACK HACK WRONG WRONG
        Bignum canBignum(candidate);
        
        return canBignum.isPrime();
    }

    
    SerialNumberSignatureOfKnowledge::SerialNumberSignatureOfKnowledge(const Params* p): params(p) { }
    
    SerialNumberSignatureOfKnowledge::SerialNumberSignatureOfKnowledge(const Params* p, const PrivateCoin& coin, const Commitment& commitmentToCoin, uint256 msghash)
    :params(p), s_notprime(p->zkp_iterations), sprime(p->zkp_iterations) {
        
        ParallelTasks::DoNotDisturb dnd;
        
        // Sanity check: verify that the order of the "accumulatedValueCommitmentGroup" is
        // equal to the modulus of "coinCommitmentGroup". Otherwise we will produce invalid
        // proofs.
        if (params->coinCommitmentGroup.modulus != params->serialNumberSoKCommitmentGroup.groupOrder) {
            throw ZerocoinException("Groups are not structured correctly.");
        }
        
        Bignum a = params->coinCommitmentGroup.g;
        Bignum b = params->coinCommitmentGroup.h;
        Bignum g = params->serialNumberSoKCommitmentGroup.g;
        Bignum h = params->serialNumberSoKCommitmentGroup.h;
        
        CHashWriter hasher(0,0);
        hasher << *params << commitmentToCoin.getCommitmentValue() << coin.getSerialNumber() << msghash;
        
        vector<Bignum> r(params->zkp_iterations);
        vector<Bignum> v(params->zkp_iterations);
        vector<Bignum> c(params->zkp_iterations);
        
        
        for(uint32_t i=0; i < params->zkp_iterations; i++) {
            //FIXME we really ought to use one BN_CTX for all of these
            // operations for performance reasons, not the one that
            // is created individually  by the wrapper
            r[i] = Bignum::randBignum(params->coinCommitmentGroup.groupOrder);
            v[i] = Bignum::randBignum(params->serialNumberSoKCommitmentGroup.groupOrder);
        }
        
        // Openssl's rng is not thread safe, so we don't call it in a parallel loop,
        // instead we generate the random values beforehand and run the calculations
        // based on those values in parallel.
        
        ParallelTasks challenges(params->zkp_iterations);
        
        for(uint32_t i=0; i < params->zkp_iterations; i++) {
            // compute g^{ {a^x b^r} h^v} mod p2
            challenges.Add([this, i, &coin, &c, &r, &v] {
                c[i] = challengeCalculation(coin.getSerialNumber(), r[i], v[i]);
            });
        }
        challenges.Wait();
        
        // We can't hash data in parallel either
        // because OPENMP cannot not guarantee loops
        // execute in order.
        for(uint32_t i=0; i < params->zkp_iterations; i++) {
            hasher << c[i];
        }
        this->hash = hasher.GetHash();
        unsigned char *hashbytes =  (unsigned char*) &hash;
        
        challenges.Reset();
        for(uint32_t i = 0; i < params->zkp_iterations; i++) {
            int bit = i % 8;
            int byte = i / 8;
            
            bool challenge_bit = ((hashbytes[byte] >> bit) & 0x01);
            if (challenge_bit) {
                s_notprime[i]       = r[i];
                sprime[i]           = v[i];
            } else {
                challenges.Add([this, i, &r, &v, &b, &commitmentToCoin, &coin] {
                    s_notprime[i]   = r[i] - coin.getRandomness();
                    sprime[i]       = v[i] - (commitmentToCoin.getRandomness() *
                                              b.pow_mod(r[i] - coin.getRandomness(), params->serialNumberSoKCommitmentGroup.groupOrder));
                });
            }
        }
        challenges.Wait();
    }
    
    inline Bignum SerialNumberSignatureOfKnowledge::challengeCalculation(const Bignum& a_exp,const Bignum& b_exp,
                                                                         const Bignum& h_exp) const {
        
        Bignum a = params->coinCommitmentGroup.g;
        Bignum b = params->coinCommitmentGroup.h;
        Bignum g = params->serialNumberSoKCommitmentGroup.g;
        Bignum h = params->serialNumberSoKCommitmentGroup.h;
        
        Bignum exponent = (a.pow_mod(a_exp, params->serialNumberSoKCommitmentGroup.groupOrder)
                           * b.pow_mod(b_exp, params->serialNumberSoKCommitmentGroup.groupOrder)) % params->serialNumberSoKCommitmentGroup.groupOrder;
        
        return (g.pow_mod(exponent, params->serialNumberSoKCommitmentGroup.modulus) * h.pow_mod(h_exp, params->serialNumberSoKCommitmentGroup.modulus)) % params->serialNumberSoKCommitmentGroup.modulus;
    }
    
    bool SerialNumberSignatureOfKnowledge::Verify(const Bignum& coinSerialNumber, const Bignum& valueOfCommitmentToCoin,
                                                  const uint256 msghash) const {
        
        ParallelTasks::DoNotDisturb dnd;
        
        Bignum a = params->coinCommitmentGroup.g;
        Bignum b = params->coinCommitmentGroup.h;
        Bignum g = params->serialNumberSoKCommitmentGroup.g;
        Bignum h = params->serialNumberSoKCommitmentGroup.h;
        
        // Make sure that the serial number has a unique representation
        if (coinSerialNumber < 0 || coinSerialNumber >= params->coinCommitmentGroup.groupOrder){
            return false;
        }
        
        
        CHashWriter hasher(0,0);
        hasher << *params << valueOfCommitmentToCoin <<coinSerialNumber << msghash;
        
        vector<CBigNum> tprime(params->zkp_iterations);
        unsigned char *hashbytes = (unsigned char*) &this->hash;
        
        ParallelTasks challenges(params->zkp_iterations);
        
        for(uint32_t i = 0; i < params->zkp_iterations; i++) {
            challenges.Add([this, i, hashbytes, &b, &h, &tprime, &coinSerialNumber, &valueOfCommitmentToCoin] {
                int bit = i % 8;
                int byte = i / 8;
                bool challenge_bit = ((hashbytes[byte] >> bit) & 0x01);
                if(challenge_bit) {
                    tprime[i] = challengeCalculation(coinSerialNumber, s_notprime[i], sprime[i]);
                } else {
                    Bignum exp = b.pow_mod(s_notprime[i], params->serialNumberSoKCommitmentGroup.groupOrder);
                    tprime[i] = ((valueOfCommitmentToCoin.pow_mod(exp, params->serialNumberSoKCommitmentGroup.modulus) % params->serialNumberSoKCommitmentGroup.modulus) *
                                 (h.pow_mod(sprime[i], params->serialNumberSoKCommitmentGroup.modulus) % params->serialNumberSoKCommitmentGroup.modulus)) %
                    params->serialNumberSoKCommitmentGroup.modulus;
                }
            });
        }
        challenges.Wait();
        
        for(uint32_t i = 0; i < params->zkp_iterations; i++) {
            hasher << tprime[i];
        }
        return hasher.GetHash() == hash;
    }
    
    //Commitment class
    Commitment::Commitment::Commitment(const IntegerGroupParams* p,
                                       const Bignum& value): params(p), contents(value) {
        this->randomness = Bignum::randBignum(params->groupOrder);
        this->commitmentValue = (params->g.pow_mod(this->contents, params->modulus).mul_mod(
                                                                                            params->h.pow_mod(this->randomness, params->modulus), params->modulus));
    }
    
    const Bignum& Commitment::getCommitmentValue() const {
        return this->commitmentValue;
    }
    
    const Bignum& Commitment::getRandomness() const {
        return this->randomness;
    }
    
    const Bignum& Commitment::getContents() const {
        return this->contents;
    }
    
    //CommitmentProofOfKnowledge class
    CommitmentProofOfKnowledge::CommitmentProofOfKnowledge(const IntegerGroupParams* ap, const IntegerGroupParams* bp): ap(ap), bp(bp) {}
    
    // TODO: get parameters from the commitment group
    CommitmentProofOfKnowledge::CommitmentProofOfKnowledge(const IntegerGroupParams* aParams,
                                                           const IntegerGroupParams* bParams, const Commitment& a, const Commitment& b):
    ap(aParams),bp(bParams)
    {
        Bignum r1, r2, r3;
        
        // First: make sure that the two commitments have the
        // same contents.
        if (a.getContents() != b.getContents()) {
            throw ZerocoinException("Both commitments must contain the same value");
        }
        
        // Select three random values "r1, r2, r3" in the range 0 to (2^l)-1 where l is:
        // length of challenge value + max(modulus 1, modulus 2, order 1, order 2) + margin.
        // We set "margin" to be a relatively generous  security parameter.
        //
        // We choose these large values to ensure statistical zero knowledge.
        uint32_t randomSize = COMMITMENT_EQUALITY_CHALLENGE_SIZE + COMMITMENT_EQUALITY_SECMARGIN +
        std::max(std::max(this->ap->modulus.bitSize(), this->bp->modulus.bitSize()),
                 std::max(this->ap->groupOrder.bitSize(), this->bp->groupOrder.bitSize()));
        Bignum maxRange = (Bignum(2).pow(randomSize) - Bignum(1));
        
        r1 = Bignum::randBignum(maxRange);
        r2 = Bignum::randBignum(maxRange);
        r3 = Bignum::randBignum(maxRange);
        
        // Generate two random, ephemeral commitments "T1, T2"
        // of the form:
        // T1 = g1^r1 * h1^r2 mod p1
        // T2 = g2^r1 * h2^r3 mod p2
        //
        // Where (g1, h1, p1) are from "aParams" and (g2, h2, p2) are from "bParams".
        Bignum T1 = this->ap->g.pow_mod(r1, this->ap->modulus).mul_mod((this->ap->h.pow_mod(r2, this->ap->modulus)), this->ap->modulus);
        Bignum T2 = this->bp->g.pow_mod(r1, this->bp->modulus).mul_mod((this->bp->h.pow_mod(r3, this->bp->modulus)), this->bp->modulus);
        
        // Now hash commitment "A" with commitment "B" as well as the
        // parameters and the two ephemeral commitments "T1, T2" we just generated
        this->challenge = calculateChallenge(a.getCommitmentValue(), b.getCommitmentValue(), T1, T2);
        
        // Let "m" be the contents of the commitments "A, B". We have:
        // A =  g1^m  * h1^x  mod p1
        // B =  g2^m  * h2^y  mod p2
        // T1 = g1^r1 * h1^r2 mod p1
        // T2 = g2^r1 * h2^r3 mod p2
        //
        // Now compute:
        //  S1 = r1 + (m * challenge)   -- note, not modular arithmetic
        //  S2 = r2 + (x * challenge)   -- note, not modular arithmetic
        //  S3 = r3 + (y * challenge)   -- note, not modular arithmetic
        this->S1 = r1 + (a.getContents() * this->challenge);
        this->S2 = r2 + (a.getRandomness() * this->challenge);
        this->S3 = r3 + (b.getRandomness() * this->challenge);
        
        // We're done. The proof is S1, S2, S3 and "challenge", all of which
        // are stored in member variables.
    }
    
    bool CommitmentProofOfKnowledge::Verify(const Bignum& A, const Bignum& B) const
    {
        // Compute the maximum range of S1, S2, S3 and verify that the given values are
        // in a correct range. This might be an unnecessary check.
        uint32_t maxSize = 64 * (COMMITMENT_EQUALITY_CHALLENGE_SIZE + COMMITMENT_EQUALITY_SECMARGIN +
                                 std::max(std::max(this->ap->modulus.bitSize(), this->bp->modulus.bitSize()),
                                          std::max(this->ap->groupOrder.bitSize(), this->bp->groupOrder.bitSize())));
        
        if ((uint32_t)this->S1.bitSize() > maxSize ||
            (uint32_t)this->S2.bitSize() > maxSize ||
            (uint32_t)this->S3.bitSize() > maxSize ||
            this->S1 < Bignum(0) ||
            this->S2 < Bignum(0) ||
            this->S3 < Bignum(0) ||
            this->challenge < Bignum(0) ||
            this->challenge > (Bignum(2).pow(COMMITMENT_EQUALITY_CHALLENGE_SIZE) - Bignum(1))) {
            // Invalid inputs. Reject.
            return false;
        }
        
        // Compute T1 = g1^S1 * h1^S2 * inverse(A^{challenge}) mod p1
        Bignum T1 = A.pow_mod(this->challenge, ap->modulus).inverse(ap->modulus).mul_mod(
                                                                                         (ap->g.pow_mod(S1, ap->modulus).mul_mod(ap->h.pow_mod(S2, ap->modulus), ap->modulus)),
                                                                                         ap->modulus);
        
        // Compute T2 = g2^S1 * h2^S3 * inverse(B^{challenge}) mod p2
        Bignum T2 = B.pow_mod(this->challenge, bp->modulus).inverse(bp->modulus).mul_mod(
                                                                                         (bp->g.pow_mod(S1, bp->modulus).mul_mod(bp->h.pow_mod(S3, bp->modulus), bp->modulus)),
                                                                                         bp->modulus);
        
        // Hash T1 and T2 along with all of the public parameters
        Bignum computedChallenge = calculateChallenge(A, B, T1, T2);
        
        // Return success if the computed challenge matches the incoming challenge
        if(computedChallenge == this->challenge) {
            return true;
        }
        
        // Otherwise return failure
        return false;
    }
    
    const Bignum CommitmentProofOfKnowledge::calculateChallenge(const Bignum& a, const Bignum& b, const Bignum &commitOne, const Bignum &commitTwo) const {
        CHashWriter hasher(0,0);
        
        // Hash together the following elements:
        // * A string identifying the proof
        // * Commitment A
        // * Commitment B
        // * Ephemeral commitment T1
        // * Ephemeral commitment T2
        // * A serialized instance of the commitment A parameters
        // * A serialized instance of the commitment B parameters
        
        hasher << std::string(ZEROCOIN_COMMITMENT_EQUALITY_PROOF);
        hasher << commitOne;
        hasher << std::string("||");
        hasher << commitTwo;
        hasher << std::string("||");
        hasher << a;
        hasher << std::string("||");
        hasher << b;
        hasher << std::string("||");
        hasher << *(this->ap);
        hasher << std::string("||");
        hasher << *(this->bp);
        
        // Convert the SHA256 result into a Bignum
        // Note that if we ever change the size of the hash function we will have
        // to update COMMITMENT_EQUALITY_CHALLENGE_SIZE appropriately!
        return Bignum(hasher.GetHash());
    }
    
    //Accumulator class
    Accumulator::Accumulator(const AccumulatorAndProofParams* p, const Bignum &v, const CoinDenomination d): params(p), value(v), denomination(d) {
        if (!(params->initialized)) {
            throw ZerocoinException("Invalid parameters for accumulator");
        }
        
        this->value = v;
    }
    
    Accumulator::Accumulator(const AccumulatorAndProofParams* p, const CoinDenomination d): Accumulator(p, p->accumulatorBase, d) {}
    
    
    Accumulator::Accumulator(const Params* p, const Bignum &v, const CoinDenomination d) {
        this->params = &(p->accumulatorParams);
        this->denomination = d;
        
        if (!(params->initialized)) {
            throw ZerocoinException("Invalid parameters for accumulator");
        }
        
        this->value = v;
    }
    
    Accumulator::Accumulator(const Params* p, const CoinDenomination d) :Accumulator(p, p->accumulatorParams.accumulatorBase, d) {}
    
    void Accumulator::accumulate(const PublicCoin& coin, bool validateCoin) {
        // Make sure we're initialized
        if(!(this->value)) {
            throw ZerocoinException("Accumulator is not initialized");
        }
        
        if(this->denomination != coin.getDenomination()) {
            //std::stringstream msg;
            std::string msg;
            msg = "Wrong denomination for coin. Expected coins of denomination: ";
            msg += this->denomination;
            msg += ". Instead, got a coin of denomination: ";
            msg += coin.getDenomination();
            throw ZerocoinException(msg);
        }
        
        if(!validateCoin || coin.validate()) {
            // Compute new accumulator = "old accumulator"^{element} mod N
            this->value = this->value.pow_mod(coin.getValue(), this->params->accumulatorModulus);
        } else {
            throw ZerocoinException("Coin is not valid");
        }
    }
    
    CoinDenomination Accumulator::getDenomination() const {
        return static_cast<CoinDenomination> (this->denomination);
    }
    
    const Bignum& Accumulator::getValue() const{
        return this->value;
    }
    
    Accumulator& Accumulator::operator += (const PublicCoin& c) {
        this->accumulate(c, false);
        return *this;
    }
    
    bool Accumulator::operator == (const Accumulator rhs) const {
        return this->value == rhs.value;
    }
    
    //AccumulatorWitness class
    AccumulatorWitness::AccumulatorWitness(const Params* p,
                                           const Accumulator& checkpoint, const PublicCoin coin): params(p), witness(checkpoint), element(coin) {
    }
    
    void AccumulatorWitness::AddElement(const PublicCoin& c) {
        if(element != c) {
            witness += c;
        }
    }
    
    const Bignum& AccumulatorWitness::getValue() const {
        return this->witness.getValue();
    }
    
    bool AccumulatorWitness::VerifyWitness(const Accumulator& a, const PublicCoin &publicCoin) const {
        Accumulator temp(witness);
        temp += element;
        return (temp == a && this->element == publicCoin);
    }
    
    AccumulatorWitness& AccumulatorWitness::operator +=(const PublicCoin& rhs) {
        this->AddElement(rhs);
        return *this;
    }
    
    secp256k1_context* init_ctx() {
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        unsigned char seed[32];
        if (RAND_bytes(seed, sizeof(seed)) != 1) {
            throw ZerocoinException("Unable to generate randomness for context");
        }
        if (secp256k1_context_randomize(ctx, seed) != 1) {
            throw ZerocoinException("Unable to randomize context");
        };
        return ctx;
    }
    // global context
    secp256k1_context* ctx = init_ctx();
    
    //PublicCoin class
    PublicCoin::PublicCoin(const Params* p):
    params(p), denomination(ZQ_ONE) {
        if (this->params->initialized == false) {
            throw ZerocoinException("Params are not initialized");
        }
    };
    
    PublicCoin::PublicCoin(const Params* p, const Bignum& coin, const CoinDenomination d):
    params(p), value(coin), denomination(d) {
        if (this->params->initialized == false) {
            throw ZerocoinException("Params are not initialized");
        }
    };
    
    bool PublicCoin::operator==(const PublicCoin& rhs) const {
        return this->value == rhs.value; // FIXME check param equality
    }
    
    bool PublicCoin::operator!=(const PublicCoin& rhs) const {
        return !(*this == rhs);
    }
    
    const Bignum& PublicCoin::getValue() const {
        return this->value;
    }
    
    CoinDenomination PublicCoin::getDenomination() const {
        return static_cast<CoinDenomination>(this->denomination);
    }
    
    bool PublicCoin::validate() const{
        return (this->params->accumulatorParams.minCoinValue < value) && (value < this->params->accumulatorParams.maxCoinValue) && value.isPrime(params->zkp_iterations);
    }
    
    //PrivateCoin class
    PrivateCoin::PrivateCoin(const Params* p, CoinDenomination denomination, int version): params(p), publicCoin(p) {
        this->version = version;
        // Verify that the parameters are valid
        if(this->params->initialized == false) {
            throw ZerocoinException("Params are not initialized");
        }
        
#ifdef ZEROCOIN_FAST_MINT
        // Mint a new coin with a random serial number using the fast process.
        // This is more vulnerable to timing attacks so don't mint coins when
        // somebody could be timing you.
        this->mintCoinFast(denomination);
#else
        // Mint a new coin with a random serial number using the standard process.
        this->mintCoin(denomination);
#endif
        
    }
    
    /**
     *
     * @return the coins serial number
     */
    const Bignum& PrivateCoin::getSerialNumber() const {
        return this->serialNumber;
    }
    
    const Bignum& PrivateCoin::getRandomness() const {
        return this->randomness;
    }
    
    const unsigned char* PrivateCoin::getEcdsaSeckey() const {
        return this->ecdsaSeckey;
    }
    
    unsigned int PrivateCoin::getVersion() const {
        return this->version;
    }
    
    void PrivateCoin::mintCoin(const CoinDenomination denomination) {
        
        Bignum s;
        
        // Repeat this process up to MAX_COINMINT_ATTEMPTS times until
        // we obtain a prime number
        for (uint32_t attempt = 0; attempt < MAX_COINMINT_ATTEMPTS; attempt++) {
            if (this->version == 1) {
                
                // Create a key pair
                secp256k1_pubkey pubkey;
                do {
                    if (RAND_bytes(this->ecdsaSeckey, sizeof(this->ecdsaSeckey))
                        != 1) {
                        throw ZerocoinException("Unable to generate randomness");
                    }
                } while (!secp256k1_ec_pubkey_create(ctx, &pubkey,
                                                     this->ecdsaSeckey));
                
                // Hash the public key in the group to obtain a serial number
                s = serialNumberFromSerializedPublicKey(ctx, &pubkey, this->pubHash);
            } else {
                // Generate a random serial number in the range 0...{q-1} where
                // "q" is the order of the commitment group.
                s = Bignum::randBignum(
                                       this->params->coinCommitmentGroup.groupOrder);
            }
            
            // Generate a Pedersen commitment to the serial number "s"
            Commitment coin(&params->coinCommitmentGroup, s);
            
            // Now verify that the commitment is a prime number
            // in the appropriate range. If not, we'll throw this coin
            // away and generate a new one.
            if (coin.getCommitmentValue().isPrime(ZEROCOIN_MINT_PRIME_PARAM)
                && coin.getCommitmentValue()
                >= params->accumulatorParams.minCoinValue
                && coin.getCommitmentValue()
                <= params->accumulatorParams.maxCoinValue && coin.getCommitmentValue().bitSize() > params->coinCommitmentGroup.modulus.bitSize()-8) {
                // Found a valid coin. Store it.
                this->serialNumber = s;
                this->randomness = coin.getRandomness();
                this->publicCoin = PublicCoin(params, coin.getCommitmentValue(),
                                              denomination);
                
                // Success! We're done.
                return;
            }
        }
        
        // We only get here if we did not find a coin within
        // MAX_COINMINT_ATTEMPTS. Throw an exception.
        throw ZerocoinException(
                                "Unable to mint a new Zerocoin (too many attempts)");
    }
    
    void PrivateCoin::mintCoinFast(const CoinDenomination denomination) {
        Bignum s;
        
        if(this->version == 1) {
            
            // Create a key pair
            secp256k1_pubkey pubkey;
            do {
                if (RAND_bytes(this->ecdsaSeckey, sizeof(this->ecdsaSeckey)) != 1) {
                    throw ZerocoinException("Unable to generate randomness");
                }
            }while (!secp256k1_ec_pubkey_create(ctx, &pubkey, this->ecdsaSeckey));
            
            // Hash the public key in the group to obtain a serial number
            s = serialNumberFromSerializedPublicKey(ctx, &pubkey, this->pubHash);
        } else {
            // Generate a random serial number in the range 0...{q-1} where
            // "q" is the order of the commitment group.
            s = Bignum::randBignum(this->params->coinCommitmentGroup.groupOrder);
        }
        
        // Generate a random number "r" in the range 0...{q-1}
        Bignum r = Bignum::randBignum(this->params->coinCommitmentGroup.groupOrder);
        
        // Manually compute a Pedersen commitment to the serial number "s" under randomness "r"
        // C = g^s * h^r mod p
        Bignum commitmentValue = this->params->coinCommitmentGroup.g.pow_mod(s, this->params->coinCommitmentGroup.modulus).mul_mod(this->params->coinCommitmentGroup.h.pow_mod(r, this->params->coinCommitmentGroup.modulus), this->params->coinCommitmentGroup.modulus);
        
        // Repeat this process up to MAX_COINMINT_ATTEMPTS times until
        // we obtain a prime number
        for (uint32_t attempt = 0; attempt < MAX_COINMINT_ATTEMPTS; attempt++) {
            // First verify that the commitment is a prime number
            // in the appropriate range. If not, we'll throw this coin
            // away and generate a new one.
            if (commitmentValue.isPrime(ZEROCOIN_MINT_PRIME_PARAM) &&
                commitmentValue >= params->accumulatorParams.minCoinValue &&
                commitmentValue <= params->accumulatorParams.maxCoinValue && commitmentValue.bitSize() > params->coinCommitmentGroup.modulus.bitSize()-8) {
                // Found a valid coin. Store it.
                this->serialNumber = s;
                this->randomness = r;
                this->publicCoin = PublicCoin(params, commitmentValue, denomination);
                
                // Success! We're done.
                return;
            }
            
            // Generate a new random "r_delta" in 0...{q-1}
            Bignum r_delta = Bignum::randBignum(this->params->coinCommitmentGroup.groupOrder);
            
            // The commitment was not prime. Increment "r" and recalculate "C":
            // r = r + r_delta mod q
            // C = C * h mod p
            r = (r + r_delta) % this->params->coinCommitmentGroup.groupOrder;
            commitmentValue = commitmentValue.mul_mod(this->params->coinCommitmentGroup.h.pow_mod(r_delta, this->params->coinCommitmentGroup.modulus), this->params->coinCommitmentGroup.modulus);
        }
        
        // We only get here if we did not find a coin within
        // MAX_COINMINT_ATTEMPTS. Throw an exception.
        throw ZerocoinException("Unable to mint a new Zerocoin (too many attempts)");
    }
    
    const PublicCoin& PrivateCoin::getPublicCoin() const {
        return this->publicCoin;
    }
    
    
    const Bignum PrivateCoin::serialNumberFromSerializedPublicKey(secp256k1_context *context, secp256k1_pubkey *pubkey, uint160& pubHash)  {
        std::vector<unsigned char> pubkey_hash(32, 0);
        
        static const unsigned char one[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        };
        
        // We use secp256k1_ecdh instead of secp256k1_serialize_pubkey to avoid a timing channel.
        secp256k1_ecdh(context, pubkey_hash.data(), pubkey, &one[0]);
        
        std::string zpts(ZEROCOIN_PUBLICKEY_TO_SERIALNUMBER);
        std::vector<unsigned char> pre(zpts.begin(), zpts.end());
        std::copy(pubkey_hash.begin(), pubkey_hash.end(), std::back_inserter(pre));
        
        uint160 hash;
        CRIPEMD160().Write(pre.data(), pre.size()).Finalize(hash.begin());
        pubHash = hash;
        // Use 160 bits of hash as coin serial. Bignum constuctor expects little-endian sequence of bytes,
        // last zero byte is used to set sign bit to 0
        std::vector<unsigned char> hash_vch(hash.begin(), hash.end());
        hash_vch.push_back(0);
        return Bignum(hash_vch);
    }
    
    
    CoinDenomination IntToZerocoinDenomination(int64_t amount)
    {
        CoinDenomination denomination;
        switch (amount) {
            case 1:        denomination = CoinDenomination::ZQ_ONE; break;
            case 5:    denomination = CoinDenomination::ZQ_FIVE; break;
            case 10:    denomination = CoinDenomination::ZQ_TEN; break;
            case 50:    denomination = CoinDenomination::ZQ_FIFTY; break;
            case 100: denomination = CoinDenomination::ZQ_ONE_HUNDRED; break;
            case 500: denomination = CoinDenomination::ZQ_FIVE_HUNDRED; break;
            case 1000: denomination = CoinDenomination::ZQ_ONE_THOUSAND; break;
            case 5000: denomination = CoinDenomination::ZQ_FIVE_THOUSAND; break;
            default:
                //not a valid denomination
                denomination = CoinDenomination::ZQ_ERROR; break;
        }
        
        return denomination;
    }
    
    int64_t ZerocoinDenominationToInt(const CoinDenomination& denomination)
    {
        int64_t Value = 0;
        switch (denomination) {
            case CoinDenomination::ZQ_ONE: Value = 1; break;
            case CoinDenomination::ZQ_FIVE: Value = 5; break;
            case CoinDenomination::ZQ_TEN: Value = 10; break;
            case CoinDenomination::ZQ_FIFTY : Value = 50; break;
            case CoinDenomination::ZQ_ONE_HUNDRED: Value = 100; break;
            case CoinDenomination::ZQ_FIVE_HUNDRED: Value = 500; break;
            case CoinDenomination::ZQ_ONE_THOUSAND: Value = 1000; break;
            case CoinDenomination::ZQ_FIVE_THOUSAND: Value = 5000; break;
            default:
                // Error Case
                Value = 0; break;
        }
        return Value;
    }
    
    
    
    CoinDenomination AmountToZerocoinDenomination(int64_t amount)
    {
        // Check to make sure amount is an exact integer number of COINS
        int64_t residual_amount = amount - COIN * (amount / COIN);
        if (residual_amount == 0) {
            return IntToZerocoinDenomination(amount/COIN);
        } else {
            return CoinDenomination::ZQ_ERROR;
        }
    }
    
    // return the highest denomination that is less than or equal to the amount given
    // use case: converting coins without user worrying about denomination math themselves
    CoinDenomination AmountToClosestDenomination(int64_t nAmount, int64_t& nRemaining)
    {
        if (nAmount < 1 * COIN)
            return ZQ_ERROR;
        
        int64_t nConvert = nAmount / COIN;
        CoinDenomination denomination = ZQ_ERROR;
        for (unsigned int i = 0; i < denominationList.size(); i++) {
            denomination = denominationList[i];
            
            //exact match
            if (nConvert == denomination) {
                nRemaining = 0;
                return denomination;
            }
            
            //we are beyond the value, use previous denomination
            if (denomination > nConvert && i) {
                CoinDenomination d = denominationList[i - 1];
                nRemaining = nConvert - d;
                return d;
            }
        }
        //last denomination, the highest value possible
        nRemaining = nConvert - denomination;
        return denomination;
    }
    
    int64_t ZerocoinDenominationToAmount(const CoinDenomination& denomination)
    {
        int64_t nValue = COIN * ZerocoinDenominationToInt(denomination);
        return nValue;
    }
    
    
    CoinDenomination get_denomination(std::string denomAmount) {
        int64_t val = std::stoi(denomAmount);
        return IntToZerocoinDenomination(val);
    }
    
    
    int64_t get_amount(std::string denomAmount) {
        int64_t nAmount = 0;
        CoinDenomination denom = get_denomination(denomAmount);
        if (denom == ZQ_ERROR) {
            nAmount = 0;
        } else {
            nAmount = ZerocoinDenominationToAmount(denom);
        }
        return nAmount;
    }

    
#ifdef ZEROCOIN_THREADING
    
    // Number of seconds before thread shuts down if idle
    constexpr static int secondsBeforeThreadShutdown = 10;
    
    // Simple thread pool class for using multiple cores effeciently
    
    static class ParallelOpThreadPool {
    private:
        std::list<boost::thread>                  threads;
        std::queue<boost::packaged_task<void>>    taskQueue;
        boost::mutex                              taskQueueMutex;
        boost::condition_variable                 taskQueueCondition;
        
        bool                                      shutdown;
        size_t                                    numberOfThreads;
        
        void ThreadProc() {
            for (;;) {
                boost::packaged_task<void> job;
                {
                    boost::unique_lock<boost::mutex> lock(taskQueueMutex);
                    
                    taskQueueCondition.wait_for(lock, boost::chrono::seconds(secondsBeforeThreadShutdown),
                                                [this] { return !taskQueue.empty() || shutdown; });
                    if (taskQueue.empty()) {
                        // Either timeout or shutdown. If it's a timeout we need to delete ourself from the thread list and detach the thread
                        // In case of shutdown thread list will be empty and destructor will wait for this thread completion
                        boost::thread::id currentId = boost::this_thread::get_id();
                        auto pThread = find_if(threads.begin(), threads.end(), [=](const boost::thread &t) { return t.get_id() == currentId; });
                        if (pThread != threads.end()) {
                            pThread->detach();
                            threads.erase(pThread);
                        }
                        break;
                    }
                    job = std::move(taskQueue.front());
                    taskQueue.pop();
                }
                job();
            }
        }
        
        void StartThreads() {
            // should be called with mutex aquired
            // start missing threads
            while(threads.size() < numberOfThreads)
                threads.emplace_back(std::bind(&ParallelOpThreadPool::ThreadProc, this));
        }
        
    public:
        ParallelOpThreadPool() : shutdown(false), numberOfThreads(boost::thread::hardware_concurrency()) {}
        
        ~ParallelOpThreadPool() {
            std::list<boost::thread> threadsToJoin;
            
            taskQueueMutex.lock();
            
            shutdown = true;
            taskQueueCondition.notify_all();
            
            // move the list to separate variable to wait for the shutdown process to complete
            threadsToJoin.swap(threads);
            
            taskQueueMutex.unlock();
            
            // wait for all the threads
            for (boost::thread &t: threadsToJoin)
                t.join();
        }
        
        // Post a task to the thread pool and return a future to wait for its completion
        boost::future<void> PostTask(function<void()> task) {
            boost::packaged_task<void> packagedTask(std::move(task));
            boost::future<void> ret = packagedTask.get_future();
            
            taskQueueMutex.lock();
            
            // lazy start threads on first request or after shutdown
            if (threads.size() < numberOfThreads)
                StartThreads();
            
            taskQueue.emplace(std::move(packagedTask));
            taskQueueCondition.notify_one();
            
            taskQueueMutex.unlock();
            
            return ret;
        }
        
    } s_parallelOpThreadPool;
    
#else
    
    static class ParallelOpThreadPool {
    public:
        boost::future<void> PostTask(function<void()> task) {
            task();
            boost::promise<void> promise;
            promise.set_value();
            return promise.get_future();
        }
    } s_parallelOpThreadPool;
    
#endif
    
    // High level API to create number of parallel tasks and wait for completion
    
    ParallelTasks::ParallelTasks(int n) {
        tasks.reserve(n);
    }
    
    void ParallelTasks::Add(function<void()> task) {
        tasks.push_back(s_parallelOpThreadPool.PostTask(std::move(task)));
    }
    
    void ParallelTasks::Wait() {
        for (boost::future<void> &f: tasks)
            f.get();
    }
    
    void ParallelTasks::Reset() {
        tasks.clear();
    }
    
    SpendMetaData::SpendMetaData(uint256 accumulatorId, uint256 txHash): accumulatorId(accumulatorId), txHash(txHash) {}
    
    AccumulatorProofOfKnowledge::AccumulatorProofOfKnowledge(const AccumulatorAndProofParams *p) : params(p) {}
    
    AccumulatorProofOfKnowledge::AccumulatorProofOfKnowledge(const AccumulatorAndProofParams *p,
                                                             const Commitment &commitmentToCoin,
                                                             const AccumulatorWitness &witness,
                                                             Accumulator &a) : params(p) {
        
        Bignum sg = params->accumulatorPoKCommitmentGroup.g;
        Bignum sh = params->accumulatorPoKCommitmentGroup.h;
        
        Bignum g_n = params->accumulatorQRNCommitmentGroup.g;
        Bignum h_n = params->accumulatorQRNCommitmentGroup.h;
        
        Bignum e = commitmentToCoin.getContents();
        Bignum r = commitmentToCoin.getRandomness();
        
        Bignum r_1 = Bignum::randBignum(params->accumulatorModulus / 4);
        Bignum r_2 = Bignum::randBignum(params->accumulatorModulus / 4);
        Bignum r_3 = Bignum::randBignum(params->accumulatorModulus / 4);
        
        this->C_e = g_n.pow_mod(e, params->accumulatorModulus) * h_n.pow_mod(r_1, params->accumulatorModulus);
        this->C_u = witness.getValue() * h_n.pow_mod(r_2, params->accumulatorModulus);
        this->C_r = g_n.pow_mod(r_2, params->accumulatorModulus) * h_n.pow_mod(r_3, params->accumulatorModulus);
        
        Bignum r_alpha = Bignum::randBignum(params->maxCoinValue * Bignum(2).pow(params->k_prime + params->k_dprime));
        if (!(Bignum::randBignum(Bignum(3)) % 2)) {
            r_alpha = 0 - r_alpha;
        }
        
        Bignum r_gamma = Bignum::randBignum(params->accumulatorPoKCommitmentGroup.modulus);
        Bignum r_phi = Bignum::randBignum(params->accumulatorPoKCommitmentGroup.modulus);
        Bignum r_psi = Bignum::randBignum(params->accumulatorPoKCommitmentGroup.modulus);
        Bignum r_sigma = Bignum::randBignum(params->accumulatorPoKCommitmentGroup.modulus);
        Bignum r_xi = Bignum::randBignum(params->accumulatorPoKCommitmentGroup.modulus);
        
        Bignum r_epsilon = Bignum::randBignum(
                                              (params->accumulatorModulus / 4) * Bignum(2).pow(params->k_prime + params->k_dprime));
        if (!(Bignum::randBignum(Bignum(3)) % 2)) {
            r_epsilon = 0 - r_epsilon;
        }
        Bignum r_eta = Bignum::randBignum(
                                          (params->accumulatorModulus / 4) * Bignum(2).pow(params->k_prime + params->k_dprime));
        if (!(Bignum::randBignum(Bignum(3)) % 2)) {
            r_eta = 0 - r_eta;
        }
        Bignum r_zeta = Bignum::randBignum(
                                           (params->accumulatorModulus / 4) * Bignum(2).pow(params->k_prime + params->k_dprime));
        if (!(Bignum::randBignum(Bignum(3)) % 2)) {
            r_zeta = 0 - r_zeta;
        }
        
        Bignum r_beta = Bignum::randBignum(
                                           (params->accumulatorModulus / 4) * params->accumulatorPoKCommitmentGroup.modulus *
                                           Bignum(2).pow(params->k_prime + params->k_dprime));
        if (!(Bignum::randBignum(Bignum(3)) % 2)) {
            r_beta = 0 - r_beta;
        }
        Bignum r_delta = Bignum::randBignum(
                                            (params->accumulatorModulus / 4) * params->accumulatorPoKCommitmentGroup.modulus *
                                            Bignum(2).pow(params->k_prime + params->k_dprime));
        if (!(Bignum::randBignum(Bignum(3)) % 2)) {
            r_delta = 0 - r_delta;
        }
        
        this->st_1 = (sg.pow_mod(r_alpha, params->accumulatorPoKCommitmentGroup.modulus) *
                      sh.pow_mod(r_phi, params->accumulatorPoKCommitmentGroup.modulus)) %
        params->accumulatorPoKCommitmentGroup.modulus;
        this->st_2 = (((commitmentToCoin.getCommitmentValue() *
                        sg.inverse(params->accumulatorPoKCommitmentGroup.modulus)).pow_mod(r_gamma,
                                                                                           params->accumulatorPoKCommitmentGroup.modulus)) *
                      sh.pow_mod(r_psi, params->accumulatorPoKCommitmentGroup.modulus)) %
        params->accumulatorPoKCommitmentGroup.modulus;
        this->st_3 = ((sg * commitmentToCoin.getCommitmentValue()).pow_mod(r_sigma,
                                                                           params->accumulatorPoKCommitmentGroup.modulus) *
                      sh.pow_mod(r_xi, params->accumulatorPoKCommitmentGroup.modulus)) %
        params->accumulatorPoKCommitmentGroup.modulus;
        
        this->t_1 =
        (h_n.pow_mod(r_zeta, params->accumulatorModulus) * g_n.pow_mod(r_epsilon, params->accumulatorModulus)) %
        params->accumulatorModulus;
        this->t_2 =
        (h_n.pow_mod(r_eta, params->accumulatorModulus) * g_n.pow_mod(r_alpha, params->accumulatorModulus)) %
        params->accumulatorModulus;
        this->t_3 = (C_u.pow_mod(r_alpha, params->accumulatorModulus) *
                     ((h_n.inverse(params->accumulatorModulus)).pow_mod(r_beta, params->accumulatorModulus))) %
        params->accumulatorModulus;
        this->t_4 = (C_r.pow_mod(r_alpha, params->accumulatorModulus) *
                     ((h_n.inverse(params->accumulatorModulus)).pow_mod(r_delta, params->accumulatorModulus)) *
                     ((g_n.inverse(params->accumulatorModulus)).pow_mod(r_beta, params->accumulatorModulus))) %
        params->accumulatorModulus;
        
        CHashWriter hasher(0, 0);
        hasher << *params << sg << sh << g_n << h_n << commitmentToCoin.getCommitmentValue() << C_e << C_u << C_r
        << st_1 << st_2 << st_3 << t_1 << t_2 << t_3 << t_4;
        
        //According to the proof, this hash should be of length k_prime bits.  It is currently greater than that, which should not be a problem, but we should check this.
        Bignum c = Bignum(hasher.GetHash());
        
        this->s_alpha = r_alpha - c * e;
        this->s_beta = r_beta - c * r_2 * e;
        this->s_zeta = r_zeta - c * r_3;
        this->s_sigma = r_sigma - c * ((e + 1).inverse(params->accumulatorPoKCommitmentGroup.groupOrder));
        this->s_eta = r_eta - c * r_1;
        this->s_epsilon = r_epsilon - c * r_2;
        this->s_delta = r_delta - c * r_3 * e;
        this->s_xi = r_xi + c * r * ((e + 1).inverse(params->accumulatorPoKCommitmentGroup.groupOrder));
        this->s_phi = (r_phi - c * r) % params->accumulatorPoKCommitmentGroup.groupOrder;
        this->s_gamma = r_gamma - c * ((e - 1).inverse(params->accumulatorPoKCommitmentGroup.groupOrder));
        this->s_psi = r_psi + c * r * ((e - 1).inverse(params->accumulatorPoKCommitmentGroup.groupOrder));
    }
    
    /** Verifies that a commitment c is accumulated in accumulator a
     */
    bool AccumulatorProofOfKnowledge::Verify(const Accumulator &a, const Bignum &valueOfCommitmentToCoin) const {
        //        printf("AccumulatorProofOfKnowledge::Verify\n");
        Bignum sg = params->accumulatorPoKCommitmentGroup.g;
        Bignum sh = params->accumulatorPoKCommitmentGroup.h;
        
        Bignum g_n = params->accumulatorQRNCommitmentGroup.g;
        Bignum h_n = params->accumulatorQRNCommitmentGroup.h;
        
        
        
        //According to the proof, this hash should be of length k_prime bits.  It is currently greater than that, which should not be a problem, but we should check this.
        CHashWriter hasher(0, 0);
        hasher << *params << sg << sh << g_n << h_n << valueOfCommitmentToCoin << C_e << C_u << C_r << st_1 << st_2
        << st_3 << t_1 << t_2 << t_3 << t_4;
        
        Bignum c = Bignum(hasher.GetHash()); //this hash should be of length k_prime bits
        
        Bignum st_1_prime = (valueOfCommitmentToCoin.pow_mod(c, params->accumulatorPoKCommitmentGroup.modulus) *
                             sg.pow_mod(s_alpha, params->accumulatorPoKCommitmentGroup.modulus) *
                             sh.pow_mod(s_phi, params->accumulatorPoKCommitmentGroup.modulus)) %
        params->accumulatorPoKCommitmentGroup.modulus;
        Bignum st_2_prime = (sg.pow_mod(c, params->accumulatorPoKCommitmentGroup.modulus) * ((valueOfCommitmentToCoin *
                                                                                              sg.inverse(
                                                                                                         params->accumulatorPoKCommitmentGroup.modulus)).pow_mod(
                                                                                                                                                                 s_gamma, params->accumulatorPoKCommitmentGroup.modulus)) *
                             sh.pow_mod(s_psi, params->accumulatorPoKCommitmentGroup.modulus)) %
        params->accumulatorPoKCommitmentGroup.modulus;
        Bignum st_3_prime = (sg.pow_mod(c, params->accumulatorPoKCommitmentGroup.modulus) *
                             (sg * valueOfCommitmentToCoin).pow_mod(s_sigma,
                                                                    params->accumulatorPoKCommitmentGroup.modulus) *
                             sh.pow_mod(s_xi, params->accumulatorPoKCommitmentGroup.modulus)) %
        params->accumulatorPoKCommitmentGroup.modulus;
        
        Bignum t_1_prime =
        (C_r.pow_mod(c, params->accumulatorModulus) * h_n.pow_mod(s_zeta, params->accumulatorModulus) *
         g_n.pow_mod(s_epsilon, params->accumulatorModulus)) % params->accumulatorModulus;
        Bignum t_2_prime =
        (C_e.pow_mod(c, params->accumulatorModulus) * h_n.pow_mod(s_eta, params->accumulatorModulus) *
         g_n.pow_mod(s_alpha, params->accumulatorModulus)) % params->accumulatorModulus;
        
        Bignum t_3_prime = ((a.getValue()).pow_mod(c, params->accumulatorModulus) *
                            C_u.pow_mod(s_alpha, params->accumulatorModulus) *
                            ((h_n.inverse(params->accumulatorModulus)).pow_mod(s_beta, params->accumulatorModulus))) %
        params->accumulatorModulus;
        
        Bignum t_4_prime = (C_r.pow_mod(s_alpha, params->accumulatorModulus) *
                            ((h_n.inverse(params->accumulatorModulus)).pow_mod(s_delta, params->accumulatorModulus)) *
                            ((g_n.inverse(params->accumulatorModulus)).pow_mod(s_beta, params->accumulatorModulus))) %
        params->accumulatorModulus;
        
        bool result = false;
        
        bool result_st1 = (st_1 == st_1_prime);
        bool result_st2 = (st_2 == st_2_prime);
        bool result_st3 = (st_3 == st_3_prime);
        
        bool result_t1 = (t_1 == t_1_prime);
        bool result_t2 = (t_2 == t_2_prime);
        bool result_t3 = (t_3 == t_3_prime);
        bool result_t4 = (t_4 == t_4_prime);
      
        bool result_range = (
                             (s_alpha >= -(params->maxCoinValue * Bignum(2).pow(params->k_prime + params->k_dprime + 1))) &&
                             (s_alpha <= (params->maxCoinValue * Bignum(2).pow(params->k_prime + params->k_dprime + 1))));
        //        printf("result_range=%d\n", result_range);
        
        result = result_st1 && result_st2 && result_st3 && result_t1 && result_t2 && result_t3 && result_t4 &&
        result_range;
        
        return result;
    }
    
} /* namespace libzerocoin */
