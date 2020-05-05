// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

#include <mutex>
#include "metrics.h"
#include "crypto/equihash.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'Vcoin' + blake2s(b'TODO').hexdigest()
 *
 * CBlock(hash=00052461, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=94c7ae, nTime=1516980000, nBits=1f07ffff, nNonce=6796, vtx=1)
 *   CTransaction(hash=94c7ae, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 94c7ae
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "VCoin0b42a68c2115102b4f5bbb03ac82872da8c567b67dad6c232a440ba4420b11e5";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
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
        strCurrencyUnits = "VCC";
	bip44CoinType = 19167;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 5000;
        consensus.nSubsidyHalvingInterval = 655350; // 2.5 years
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32; // 32% adjustment down
        consensus.nDigishieldMaxAdjustUp = 16; // 16% adjustment up
	consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.nPowTargetSpacing = 2 * 60;

        consensus.vUpgrades[Consensus::BASE].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight = 125000;

	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight = 125100;

	consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight = 250000;		// Approx January 12th

    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = 372500;  // Approx July 2nd - Zel Team Boulder Meetup 

	consensus.nZawyLWMAAveragingWindow = 60;
	consensus.eh_epoch_fade_length = 11;

	eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_3 = zelHash;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xe1;
        pchMessageStart[2] = 0xd0;
        pchMessageStart[3] = 0xf4;
        vAlertPubKey = ParseHex("04025b2cf3a116782a69bb68cb4ae5ba3b7f05069f7139b75573dd28e48f8992d95c118122b618d4943456ad64e7356b0b45b2ef179cbe3d9767a2426662d13d32"); //Zel Technologies GmbH
        nDefaultPort = 16425;
        nPruneAfterHeight = 100000;


        genesis = CreateGenesisBlock(
            1588582424,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000446"),
            ParseHex("0032ab83050a4f468f7d334f21333bee00bb9af5f60dd2a738158b0e1aec9e74c851ef7155eeb21df1503e0a56c549cfef833b8d97337bede15bbd2b5e65054b072b9a0fd90ff39a870a36e6692f42fee11dc34704a6cdba6e4c99490019d237afa256eac9eab83f1f2ba19fcf7a323087a69515de19e368c71f74d9e0b10c74365ed58323df95abd326fde92f6e91643c2e3324df4ee8d826fae9941db28636ad8019060e8f15350090c421c6132949d1f06099c752e2799820b8fbf460179d69119d28a3fe96f9ad6beb4b428d5616ca1c13d7233d754f26b7a0f0d9518bcc0396ff189f4c2e1917e15a8adc16b7a25008a262df37d2375ff383d20314a7a0e7ddd38b750232848cddee3f6bd3bba66710569970eb868f811adf82cfd9205b66cd005eeebf09a04e83a9736bf7af09f4447a4102eda5a3dea4175b67264ae15a16e5973427ec0160cad29a9e7da2040240d3c21e85875efa606475f65c3e598608b19a0406ba596dea4a30dd3786d3968b9fae65a8b65b778c2f3cfc77c58cc1419c7527595760a1ea866db8bcc8331ca72c7ed033f5499043996cbfede56c5b55324508e9a59802341a69edcc640970d2ff616c833cb67710a255a56cd9b0070587e3c313fc49521925b747dc12a6637336d9d6eff1a4352787332e371f241f139f43c1de7f3fe4a9936365c4a269b3740a4be534f2b2034bf77d0922e867de62925d1ea70cf644ff1fb3f355e6de34a19d5597b1e56590e6eedc86695adb644b1c65d9cd2f8c5783ac1af3ec57bcbee685843de4121f2e74262f0ce8acf3e6c372c84446c315f85cd1611f7a961c4f88823ab19794506363d4cd2576cc08ff7bf39dc087746a15db0ba87ac651ef424093befc022af7a22430e56b35e3c602d11818cdf0f450f423f72e6eae21d550db9af2f1d4f64dc1b9bdb8519bc9bc00eced23540c55aa6e76414273e937e0bd5a6cd2f202203a470921d8bb43a637dbc578be0a257dbabbda1759347707d737f12cf6c2d66e177de65651bfd9a13575275874ebb62d7a4a73ae61aa321d38d9f382eb1b1b52d1985cc6819a0bd528b07dcf76af01fafec12ad8a430ee341599dcc2545228db9825f3f3db726f1e178b86b46a8b379f2c46aefb387ca6701e768d651ef2ba1db62fc6e5a91584439970446e7807f8d13706943a727fcbb73701dd3553be4064656e55fcaafb171955b99db461abfa59526aae9f9d75ffc69f2ede147ea90d72a7ee5f705ae5b802c602639c9c3d4e6c3a4722df0f2b1ed5d31b8a0dc558d772c477db126f18e38fdce349b67184279194cc942fc265631d1a6335d19620285d60870e34146349f1277a5a417d960f1d35f1a6d04d1cbc9afe36fb54cbb71282ea575caa35e32a12865b798161cbf9beb6e8523ee8fbb798f4079d04121423257d24b2d0d584aeecb93ffbad9bf6158ff733ed1eaec368a7430e96bfeeb5b67270e6350a7c37c11dce931792b5a7cc38466b4a6e21176c7a25ba9efde81e664d3c8e02715fcf79d1634db66de70ac252e89c69a59f99bfa1d5a2cc8051cd857ca8b221a57dc108168a2722a40440c23df5a518437097e80e33c443b05d0c5b59a211aebd3abadd97f54f9dfb2f0ed1ce15de9f6fb7b5a48ba6e9e709feee3c8b6107c1a9dd49d20115f803a5aad86df885c1a9f409da11dc0d2264b46689adb101ba1c285c9c87bfe5765c16a9b9f4e92f693390d21435066de5dd1e201ad09f2b47f66248fcb695eb3502d4e346153552afb7c6fb09ee48c3141dc99d6f6773bf8ad0575ddbdf92c4df3c8f4a51be1c2b3d8b4b13ea20b45f9e080472101a239a7555bd8cb1c0f520dc2985726ae36a06bf9f2f3390ac1b241d4a6af6ac75886d6d68c17663b5d44d"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        printf("%s\n", consensus.hashGenesisBlock.ToString().c_str());
	printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x000321c4d661333010a92b08e45c11d6b62cce263df04ba97b10883c61ba1583"));
        assert(genesis.hashMerkleRoot == uint256S("0x72f07fb325a78bd0cfb3874d328f0004bd17ea84a33948e7521f29c813028b6f"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("vps.zel.network", "singapore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vpsone.zel.network", "bangalore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vpstwo.zel.network", "frankfurt.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vpsthree.zel.network", "newyork.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vps.vcoin.online", "dnsseed.vcoin.online")); // TheTrunk

        // guarantees the first 2 characters, when base58 encoded, are "V1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x0F,0xC5};
        // guarantees the first 2 characters, when base58 encoded, are "V3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x0F,0xC9};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "za";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewa";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivka";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        strSporkKey = "04f5382d5868ae49aedfd67efce7c0f56a66a9405a2cc13f8ef236aabb3f0f1d00031f9b9ca67edc93044918a1cf265655108bab531e94c7d48918e40a94a34f77";
        nStartZelnodePayments = 1550748576; //Thu, 21 Feb 2019 11:29:36 UTC // Not being used, but could be in the future
        networkID = CBaseChainParams::Network::MAIN;
        strZelnodeTestingDummyAddress= "t1Ub8iNuaoCAKTaiVyCh8d3iZ31QJFxnGzU";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock), //Halep won French Open 2018
            1588582424,     // * UNIX timestamp of last checkpoint block
            0,              // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            1               // * estimated number of transactions per day
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        // nSproutValuePoolCheckpointHeight = 520633;
        // nSproutValuePoolCheckpointBalance = 22145062442933;
        // fZIP209Enabled = true;
        // hashSproutValuePoolCheckpointBlock = uint256S("0000000000c7b46b6bc04b4cbf87d8bb08722aebd51232619b214f7273f8460e");
    }
};
static CMainParams mainParams;

/**
 * testnet-kamiooka
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TESTVCC";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 5000;
        consensus.nSubsidyHalvingInterval = 655350; // 2.5 years
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32; // 32% adjustment down
        consensus.nDigishieldMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 299187;
        consensus.nPowTargetSpacing = 2 * 60;

        consensus.vUpgrades[Consensus::BASE].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE].nActivationHeight =
        Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
        Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
	    consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight = 70;

	    consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
	    consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight = 100;

        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight = 120;

	    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = 720;


        consensus.nZawyLWMAAveragingWindow = 60;
	    consensus.eh_epoch_fade_length = 10;

	    //eh_epoch_1 = eh96_5;
    eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_3 = zelHash;


        pchMessageStart[0] = 0x69;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0x28;
        pchMessageStart[3] = 0xdc;
        vAlertPubKey = ParseHex("044b5cb8fd1db34e2d89a93e7becf3fb35dd08a81bb3080484365e567136403fd4a6682a43d8819522ae35394704afa83de1ef069a3104763fd0ebdbdd505a1386"); //Zel Technologies GmbH

        nDefaultPort = 26425;

        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1588586264,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000026"),
            ParseHex("00261517d1851526da828829c251b922c6553f613606c40504d6c77e3ace3e04fd4bb4342e5fdfb635b716a435277b6004c72b5d42007d999054abb9a7abf65693c7ed69ee97cb7fba1615b4d8de3dc0d49c3b380533ad4d0a66d283d7a875d3704e89c5f44851e90418311bcf91dbd3efddf163a61a22133b5aba5f41ec1f3a6a0f8c4dd2f8b8f534f1c13e4ce734d09a7dc920355d0861af57a183e492e3cd714239e97f38ff8207f2a848ac882775b2e214295bc538ee3bd7b5dddb4de97b9ef17e70a7fb9b261831587a52991d3f65be2ab9f5c99e555003f06888c3d4c846c66c1c14622d4f158714b4247173a0a79879e05100c7ca485f823a18a4b3657edd15910d2bc1dc3457ddf08e11a5adf03d86bac71453fe44fc16e5fe2a7b61128cc096bff51d210624c6cd1f2b13bc64227555e649a00abf433b2b520e69e2cf59ca8fcdb2c719fbff2190eab65d9c073579ef7fd2ef8d8893209da0afd01963114bf412165f039ea411217fcff4a36a70e137690d5eefa9000ab6628674525b076349d22473c06c34c0ad49079a50a7ef34f9d8719ec4b9061b39528f8236ac75b4be092d5c77fb26148df529c11956cf09d53475b1270d2629dc38da536074a45a0500a4d6ecf2e1fd3de3ad09a4d1f8f3d566a34dba545e005fd39160e191db430dd954796ee3dfcf6d03d10e9cfafa9532909ee8e607cbb78c8e43bdc79ae8d5bfa140b2c723dd5d1344103460dfb718d567b2212371faa1c488eeb9b11dc70b46065018c7bdfa6e33a3689dbc122d797fb1a200324fc29d6d4df6d8e2a2d932046dea327c47da46570a2acbc6fb77ba05f4191688c1b5cd49a68216c50d3af3af4a0314556388be4ae80aecd46f78307bc6df35c376c1a4353de5f74de5cedbd7a839e2b63c81843d47acc5a599c3a782fed6b12576b3d6163b7ffc160286d637b648493d9b31d0f051177315d363b885c64b2a86551614dde3c9e7a764584df1a27a1e75b34818c5c1866ae3bcc9b372f3b9a2b1873de8b4127c383a72bed779539e5f75d95c4075eaf0471df87b0138063ff705994a6ae2540e80f8367da9a2ce9a37f4001023b31af24adae5245634b609f303ca542cfb469408e28edfabd83425f13d23607faf9f5950b3345a062564f7255ee403a120b993970fcc8475df401aa36502f52cd0b704e64a584c342339f20909dac2379f4d10d78137fe06b776aa4f28dfcad407b6ea09df199210e2f4d0b06e2e81e69e513369b675b2e87ebc26ed32a8aed0a89684fb6d9564e8d4b9ae7af40cdca3f50a19257b0083308d2277458a38efbe099ca8d23f87363256bb2bd985593e6733f307d771ce1db09183b7210bed6b3d520c3f4ca5f3ddb7c8c52b847a7faf8229f5bc24feaabb8d96f19336e3f1a8ed7075ee3d8a0754c88de50785a4955c62291c4b8c859e1670e6f932678e7440674ba7493c58458668834f91db7ea390096343817739a335cfa32a7970f42ac7269efafbba1402daf85e5f486b43411144b6cc7b6564c094505810ed33a512858fff683af48eb5d2ebfaf913dbb32731886700b8dda191d155b4e02967692583757754cc1dd8a4b0e6cb5a3bcd21f1e8e2386c26e18fdac7bb2c908a2f512cda01b25fe37ef9dfc4695159cb48dd0ad99f3e0a53108b15fb742e2ce0535a616c3da0825aeacd1676f3fc25c7e8178bc878065249577ddd6123eedb6ca10b5a11249e6421bb265acd4917b8b29932a99bd5489bfb8bf1d38348da9c55013d30b58225102aec2bad5bcfd3eb4f073c2ddf3dc9fca27426b85cf5f65739f030d5ee9da5f63cb78551d37b9dd5321173f6ea65e07b4b75127838245e0dfe2509da4bff3ac4944d49569df2cd2fc603c644bfe1b06d794616"),
            0x2007ffff, 4, 0);
        
        consensus.hashGenesisBlock = genesis.GetHash();
        printf("%s\n", consensus.hashGenesisBlock.ToString().c_str());
	printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x07cfcf0caa00c60f9a59df77d7923d7f89bde918b510f871e1d528570f76945c"));
        assert(genesis.hashMerkleRoot == uint256S("0x72f07fb325a78bd0cfb3874d328f0004bd17ea84a33948e7521f29c813028b6f"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("test.vps.zel.network", "test.singapore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpsone.zel.network", "test.bangalore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpstwo.zel.network", "test.frankfurt.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpsthree.zel.network", "test.newyork.zel.network")); // MilesManley
        //vSeeds.push_back(CDNSSeedData("vps.testnet.vcoin.online", "dnsseedtestnet.vcoin.online")); // TheTrunk


        // guarantees the first 2 characters, when base58 encoded, are "v1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0xD8};
        // guarantees the first 2 characters, when base58 encoded, are "v2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1D,0xDA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestacadia";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestacadia";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestacadia";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;
        strSporkKey = "0408c6a3a6cacb673fc38f27c75d79c865e1550441ea8b5295abf21116972379a1b49416da07b7d9b40fb9daf8124f309c608dfc79756a5d3c2a957435642f7f1a";
        nStartZelnodePayments = 1550748576; //Thu, 21 Feb 2019 11:29:36 UTC // Currently not being used.
        networkID = CBaseChainParams::Network::TESTNET;
        strZelnodeTestingDummyAddress= "tmXxZqbmvrxeSFQsXmm4N9CKyME767r47fS";




        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1588586264,  // * UNIX timestamp of last checkpoint block
            0,           // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            1            // * estimated number of transactions per day after checkpoint 720 newly mined +30 for txs that users are doing
                         //   total number of tx / (checkpoint block height / (24 * 24))
        };

    // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        //nSproutValuePoolCheckpointHeight = 440329;
        //nSproutValuePoolCheckpointBalance = 40000029096803;
        //fZIP209Enabled = true;
        //hashSproutValuePoolCheckpointBlock = uint256S("000a95d08ba5dcbabe881fc6471d11807bcca7df5f1795c99f3ec4580db4279b");

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
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nDigishieldMaxAdjustUp = 0; // Turn off adjustment up

        consensus.nPowTargetSpacing = 2 * 60;
	consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;

        consensus.vUpgrades[Consensus::BASE].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight =
	    Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

    consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170006;
    consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

	consensus.nZawyLWMAAveragingWindow = 60;
	consensus.eh_epoch_fade_length = 11;

	eh_epoch_1 = eh48_5;
        eh_epoch_2 = eh48_5;

        pchMessageStart[0] = 0xab;
        pchMessageStart[1] = 0xe3;
        pchMessageStart[2] = 0x2f;
        pchMessageStart[3] = 0x4f;
        nDefaultPort = 26426;
        nPruneAfterHeight = 1000;


        genesis = CreateGenesisBlock(
            1588587054,
            uint256S("000000000000000000000000000000000000000000000000000000000000001a"),
            ParseHex("0764027dd26755f3a20c6ca21da292c5a1c83fb19796a4034911b06b7b6b3b76c4f2f5e8"),
            0x200f0f0f, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        printf("%s\n", consensus.hashGenesisBlock.ToString().c_str());
	printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x04b9cfb0bfeaf23545cca161535e863513bfe0f49bfe05d8ae62a02595202705"));
        assert(genesis.hashMerkleRoot == uint256S("0x72f07fb325a78bd0cfb3874d328f0004bd17ea84a33948e7521f29c813028b6f"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        networkID = CBaseChainParams::Network::REGTEST;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("72f07fb325a78bd0cfb3874d328f0004bd17ea84a33948e7521f29c813028b6f")),
            0,
            0,
            0
        };
        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0xD8};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1D,0xDA};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }

    void SetRegTestZIP209Enabled() {
        fZIP209Enabled = true;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }

    // When a developer is debugging turnstile violations in regtest mode, enable ZIP209
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-developersetpoolsizezero")) {
        regTestParams.SetRegTestZIP209Enabled();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}


// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}
std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

int validEHparameterList(EHparameters *ehparams, unsigned long blockheight, const CChainParams& params){
    //if in overlap period, there will be two valid solutions, else 1.
    //The upcoming version of EH is preferred so will always be first element
    //returns number of elements in list

    int current_height = (int)blockheight;
    if (current_height < 0)
        current_height = 0;

    // When checking to see if the activation height is above the fade length, we subtract the fade length from the
    // current height and run it through the NetworkUpgradeActive method
    int modified_height = (int)(current_height - params.GetConsensus().eh_epoch_fade_length);
    if (modified_height < 0)
        modified_height = 0;

    // check to see if the block height is greater then the overlap period ( height - fade depth >= Upgrade Height)
    if (NetworkUpgradeActive(modified_height, Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA)) {
        ehparams[0]=params.eh_epoch_3_params();
        return 1;
    }

    // check to see if the block height is in the overlap period.
    // The above if statement shows us that we are already below the upgrade height + the fade depth, so now we check
    // to see if we are above just the upgrade height
    if (NetworkUpgradeActive(current_height, Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA)) {
        ehparams[0]=params.eh_epoch_3_params();
        ehparams[1]=params.eh_epoch_2_params();
        return 2;
    }

    // check to see if the block height is greater then the overlap period (height - fade depth >= Upgrade Height)
    if (NetworkUpgradeActive(modified_height, Params().GetConsensus(), Consensus::UPGRADE_EQUI144_5)) {
        ehparams[0]=params.eh_epoch_2_params();
        return 1;
    }

    // check to see if the block height is in the overlap period
    // The above if statement shows us that we are already below the upgrade height + the fade depth, so now we check
    // to see if we are above just the upgrade height
    if (NetworkUpgradeActive(current_height, Params().GetConsensus(), Consensus::UPGRADE_EQUI144_5)) {
        ehparams[0]=params.eh_epoch_2_params();
        ehparams[1]=params.eh_epoch_1_params();
        return 2;
    }

    // return the block height is less than the upgrade height params
    ehparams[0]=params.eh_epoch_1_params();
    return 1;
}
