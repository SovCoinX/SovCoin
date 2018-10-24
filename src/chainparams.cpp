// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The SOV Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "uint256.h"
#include "arith_uint256.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>
#include <boost/assign/list_of.hpp>
#include <limits>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1522190273, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "SOV Coin";
    const CScript genesisOutputScript = CScript() << ParseHex("04174c0933f7ed53fc996de0c252cd6bbf9e9b8161dcda7615c2503dbd5d48f02bdb72bd216af26b6815e0b2f50381100916a7eb7b1a88aeb8debb0803250d8401") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));


class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 518400; // Note: actual number of blocks per calendar year with DGW v3 is ~200700 (for example 449750 - 249050)
        consensus.nMasternodePaymentsStartBlock = 2000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 9999999999; // deactivated on initial launch
        consensus.nMasternodePaymentsIncreasePeriod = 9999999999; // deactivated on initial launch
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 9999999999; // Disabled
        consensus.nBudgetPaymentsCycleBlocks = 9999999999; // Disabled
        consensus.nBudgetPaymentsWindowBlocks = 9999999999; // Disabled
        consensus.nBudgetProposalEstablishingTime = 60*20*9999999999; // Disabled
        consensus.nSuperblockStartBlock = 99999999999; // Disabled
        consensus.nSuperblockCycle = 9999999999; // Disabled
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x000007d91d1254d60e2dd1ae580383070a4ddffa4c64c2eeb4a2f9ecc0414343");
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.nZawyLwmaAveragingWindow = 65;
        consensus.nZawyLwmaAjustedWeight = 3927;

        consensus.nPowTargetTimespan = 1 * 60; // SOV: 1 hour
        consensus.nPowTargetSpacing = 1 * 60; // SOV: 1 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.useDarkGravityWave = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1486252800; // Feb 5th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517788800; // Feb 5th, 2018

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 1508025600; // Oct 15th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 1539561600; // Oct 15th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 3226; // 80% of 4032

        // The best chain should have at least this much work.
        //consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000100a308553b4863b755"); // 782700

        // By default assume that the signatures in ancestors of this block are valid.
        //consensus.defaultAssumeValid = uint256S("0x000000000000001c172f518793c3b9e83f202284615592f87fe3506ce964dcd4"); // 782700

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xae;
        pchMessageStart[1] = 0x7e;
        pchMessageStart[2] = 0x5d;
        pchMessageStart[3] = 0x74;
        vAlertPubKey = ParseHex("048c4ef0c2c635687f6077a742be01a05748370a24a6d5209283d727e7825bf5b259256169f638e7f845c923abe6f3b3f64177f8dd354c447fbe2ad933f457febe");
        nDefaultPort = 11888;
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in sov
        nDelayGetHeadersTime = 24 * 60 * 60;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1530264182, 3765700, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
   /*
	 //////////////
        //////////////
                // calculate Genesis Block
                // Reset genesis
                consensus.hashGenesisBlock = uint256S("0x");
                std::cout << std::string("Begin calculating Mainnet Genesis Block:\n");
                if (true && (genesis.GetHash() != consensus.hashGenesisBlock)) {
                    LogPrintf("Calculating Mainnet Genesis Block:\n");
                    arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
                    uint256 hash;
                    genesis.nNonce = 0;
                    // This will figure out a valid hash and Nonce if you're
                    // creating a different genesis block:
                    // uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
                    // hashTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow).getuint256();
                    // while (genesis.GetHash() > hashTarget)
                    while (UintToArith256(genesis.GetHash()) > hashTarget)
                    {
                        ++genesis.nNonce;
                        if (genesis.nNonce == 0)
                        {
                            LogPrintf("NONCE WRAPPED, incrementing time");
                            std::cout << std::string("NONCE WRAPPED, incrementing time:\n");
                            ++genesis.nTime;
                        }
                        if (genesis.nNonce % 10000 == 0)
                        {
                            LogPrintf("Mainnet: nonce %08u: hash = %s \n", genesis.nNonce, genesis.GetHash().ToString().c_str());
                            // std::cout << strNetworkID << " nonce: " << genesis.nNonce << " time: " << genesis.nTime << " hash: " << genesis.GetHash().ToString().c_str() << "\n";
                        }
                    }
                    std::cout << "Mainnet ---\n";
                    std::cout << "  nonce: " << genesis.nNonce <<  "\n";
                    std::cout << "   time: " << genesis.nTime << "\n";
                    std::cout << "   hash: " << genesis.GetHash().ToString().c_str() << "\n";
                    std::cout << "   merklehash: "  << genesis.hashMerkleRoot.ToString().c_str() << "\n";
                    // Mainnet --- nonce: 296277 time: 1390095618 hash: 000000bdd771b14e5a031806292305e563956ce2584278de414d9965f6ab54b0
                }
                std::cout << std::string("Finished calculating Mainnet Genesis Block:\n");
     */
        assert(consensus.hashGenesisBlock == uint256S("0000093e6f9d658353d8def21d98a5a5126a388a7c5987bce7cac4ccf5299dd0"));
        assert(genesis.hashMerkleRoot == uint256S("999ad67d669569e6168d11f92cd4ee8a056a2a5754253164ec8fb9593f923267"));

        vSeeds.push_back(CDNSSeedData("217.69.13.119", "217.69.13.119"));
        vSeeds.push_back(CDNSSeedData("45.76.189.173", "45.76.189.173"));
        vSeeds.push_back(CDNSSeedData("207.148.80.120", "207.148.80.120"));
        vSeeds.push_back(CDNSSeedData("202.182.114.244", "202.182.114.244"));
        vSeeds.push_back(CDNSSeedData("80.240.31.33", "80.240.31.33"));
        vSeeds.push_back(CDNSSeedData("45.32.26.177", "45.32.26.177"));
        // vFixedSeeds.clear();
        // vSeeds.clear();

        // SOV addresses start with 'S'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63);
        // SOV script addresses start with '8'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,18);
        // SOV private keys start with 't'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128+63);
        // SOV BIP32 pubkeys start with 'xpub' (SOV defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // SOV BIP32 prvkeys start with 'xprv' (SOV defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        // SOV BIP44 coin type is '5'
        nExtCoinType = 5;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour
        strSporkPubKey = "0406d43be70bd276010ad0ca49c6ad33564a9b8bc7f5461f97182e2f14cd0608f71e31b45112f98ff2ddca58ab9855be5bcf17fb7c71aca006cec7280da1379415";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (  0, uint256S("0000093e6f9d658353d8def21d98a5a5126a388a7c5987bce7cac4ccf5299dd0")),
            1530264182, // * UNIX timestamp of last checkpoint block
            0,    // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            500        // * estimated number of transactions per day after checkpoint
        };
    }
};

static CMainParams mainParams;



/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 21600;
        consensus.nMasternodePaymentsStartBlock = 2000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 9999;
        consensus.nMasternodePaymentsIncreasePeriod = 9999;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 9999999999; // Disabled
        consensus.nBudgetPaymentsCycleBlocks = 9999999999; // Disabled
        consensus.nBudgetPaymentsWindowBlocks = 9999999999; // Disabled
        consensus.nBudgetProposalEstablishingTime = 60*20*9999999999; // Disabled
        consensus.nSuperblockStartBlock = 99999999999; // Disabled
        consensus.nSuperblockCycle = 9999999999; // Disabled
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x0000047d24635e347be3aaaeb66c26be94901a2f962feccd4f95090191f208c1");
        consensus.powLimit = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");

        consensus.nZawyLwmaAveragingWindow = 65;
        consensus.nZawyLwmaAjustedWeight = 3927;

        consensus.nPowTargetTimespan = 30 * 60 * 2; // SOV: 1 hour
        consensus.nPowTargetSpacing = 2 * 60; // SOV: 2 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.useDarkGravityWave = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1506556800; // September 28th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1538092800; // September 28th, 2018

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 1505692800; // Sep 18th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 1537228800; // Sep 18th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 50; // 50% of 100

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xa1;
        pchMessageStart[1] = 0xbb;
        pchMessageStart[2] = 0xca;
        pchMessageStart[3] = 0x45;
        vAlertPubKey = ParseHex("046e05270f6d736f006cb682c9e15998e3505e6185475f7e1a9bc5a4965984b6933ed8988336006ad07d0b5ae408bf5805183c5a94ab376d0e50f0c51ab30f6662");
        nDefaultPort = 17979;
        nMaxTipAge = 0x7fffffff; // allow mining on top of old blocks for testnet
        nDelayGetHeadersTime = 24 * 60 * 60;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1525413615UL, 1507179UL, 0x1e0ffff0, 1, 150000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
       // assert(consensus.hashGenesisBlock == uint256S("0x00000ba049e5c1f95474ea3fc62d5f1b1632a294c20c22fea701134a43cf3068"));
        //assert(genesis.hashMerkleRoot == uint256S("0xd5dec0980d7b84cc1c048eb8706afe68bbbdb07fdefab76de8d176dfcb858ae8"));

        vSeeds.push_back(CDNSSeedData("testnet.sovproject.org", "testnet.seed.sovproject.org"));
        vSeeds.push_back(CDNSSeedData("fixed-seeds.sovproject.org", "testnet.fixed-seeds.sovproject.org"));
        // vFixedSeeds.clear();
        // vSeeds.clear();

        // Testnet SOV addresses start with 'm'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,110);
        // Testnet SOV script addresses start with '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,21);
        // Testnet private keys start with '9' or 'c' (SOV defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Testnet SOV BIP32 pubkeys start with 'tpub' (SOV defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet SOV BIP32 prvkeys start with 'tprv' (SOV defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        // Testnet SOV BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        strSporkPubKey = "04f148c649d452178b270f996ae71b22ec80dfd5e09a1920694587f9cd26fdb6528d20041346089d085e499ac9e5bcea91ce7b0f5b8a80338f1426cc4eb4786774";

        // checkpointData = (CCheckpointData) {
        //     boost::assign::map_list_of
        //     (  0, uint256S("0x00000ba049e5c1f95474ea3fc62d5f1b1632a294c20c22fea701134a43cf3068"))
        //     ( 22520, uint256S("00000002c95eb91831bb7cb51ba6f5f39311b76280720f3aa02f8fafbeda0993")),
        //     1525413615, // * UNIX timestamp of last checkpoint block
        //     22520,       // * total number of transactions between genesis and last checkpoint
        //                 //   (the tx=... number in the SetBestChain debug.log lines)
        //     250         // * estimated number of transactions per day after checkpoint
        // };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMasternodePaymentsStartBlock = 2;
        consensus.nMasternodePaymentsIncreaseBlock = 999;
        consensus.nMasternodePaymentsIncreasePeriod = 999;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nBudgetProposalEstablishingTime = 60*20;
        consensus.nSuperblockStartBlock = 1500;
        consensus.nSuperblockCycle = 10;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 100;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.nZawyLwmaAveragingWindow = 65;
        consensus.nZawyLwmaAjustedWeight = 3927;

        consensus.nPowTargetTimespan = 30 * 60 * 2; // SOV: 1 hour
        consensus.nPowTargetSpacing = 2 * 60; // SOV: 2 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.useDarkGravityWave = false;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xf4;
        pchMessageStart[1] = 0xaf;
        pchMessageStart[2] = 0xbf;
        pchMessageStart[3] = 0xf5;
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in sov
        nDelayGetHeadersTime = 0; // never delay GETHEADERS in regtests
        nDefaultPort = 17978;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1522201627, 1282268, 0x1e0ffff0, 1, 150000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
       // assert(consensus.hashGenesisBlock == uint256S("0x000005ec6d48ac579d697448a82e93127b94403770629399cf561caa216a694b"));
        //assert(genesis.hashMerkleRoot == uint256S("0xd5dec0980d7b84cc1c048eb8706afe68bbbdb07fdefab76de8d176dfcb858ae8"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x000005ec6d48ac579d697448a82e93127b94403770629399cf561caa216a694b")),
            1522201627,
            0,
            0
        };
        // Regtest SOV addresses start with 'o'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,115);
        // Regtest SOV script addresses start with 'a'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,83);
        // Regtest private keys start with '9' or 'c' (SOV defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Regtest SOV BIP32 pubkeys start with 'tpub' (SOV defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Regtest SOV BIP32 prvkeys start with 'tprv' (SOV defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        // Regtest SOV BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;
   }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}
