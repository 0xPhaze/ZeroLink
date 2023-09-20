// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2 as console} from "forge-std/Test.sol";

import {NoirTestBase} from "./utils/NoirTestBase.sol";

import {BaseUltraVerifier} from "../circuits/contract/ZeroLink/plonk_vk.sol";
import {MerkleLib, DEPTH} from "../src/utils/MerkleLib.sol";
import {NoirUtils} from "../src/utils/NoirUtils.sol";
import {ZeroLink} from "../src/ZeroLink.sol";

/// @notice Exposes helper functions on `ZeroLink`
contract MockZeroLink is ZeroLink {
    function verifyProof(address receiver, uint256 nullifier, uint256 root_, bytes calldata proof) public view {
        _verifyProof(receiver, nullifier, root_, proof);
    }
}

/// @notice ZeroLink tests
contract ZeroLinkTest is NoirTestBase {
    MockZeroLink zerolink = new MockZeroLink();

    address bob = address(0xb0b);
    address alice = address(0xa11ce);

    uint256 key;
    uint256 secret;
    uint256 leaf;
    uint256 nullifier;
    uint256[DEPTH] nodes;
    uint256 root;
    bytes proof;

    function setUp() public {
        deal(bob, 100 ether);
        deal(alice, 100 ether);

        // Initialize proof data for first deposit.
        key = 0;
        secret = 0x1337;
        leaf = MerkleLib.hash(secret + 1);
        nullifier = MerkleLib.hash(secret + 2);

        // Initialize inner nodes of empty tree.
        (root, nodes) = MerkleLib.getEmptyTree();
    }

    function setUpProofAlice() internal {
        key = 0;
        secret = 0x1337;
        leaf = MerkleLib.hash(secret + 1);
        nullifier = MerkleLib.hash(secret + 2);
        // Note: These nodes are used to compute the nodes and root following
        //       the next deposit. THEY ARE NOT USED FOR PROVING THE CURRENT DEPOSIT.
        (root, nodes) = MerkleLib.appendLeaf(key, leaf, nodes);
        proof =
            hex"24f0a876de857e1f3a8961005059c0f02fbc89b2014762c9cbbaa67cbbc906f51e2d064ba36ce904c8ce16044ec040760ae0213c3694dfd31d920da2fca37931236dc34fe83bc94cabd605bba2de1dbde68ce3e52ce803afc9af75448054931712f8ffdcfe5c9cbc05708d54dfda0ba46be775b18d1d7dc125110138f5ad2e610913110cd971f1ec59831a45a5624efa1062185aef5a06cde320e2a64f1dedfd24d087e835e06cfaa3cdfb5d8f62a6ab7af7f29ef2ce342d46783a6cd71009f91f6a4b737f819143a19b70ed3430b087ecaf248492910677610d38ea9a4cb5cf0150ce913a06f8853fca0b85a362c9cbf55d800e7bd9ede7633c5b277f8fbec4237bb20a496482d92586cf03bb65a6977cce8f656880479b4053d6aed24fe83403d99b2699114a8a6d10569675edc35d1f13d49fde63751977ff0b145ba7028414234efe28ba06b34b958b464cd0ec9bd84f9805133e089e2ec16ca10d0a0e0601d5e2dae41eb73c13b6fcf4f9f39e2ca55033dcbcd092a9fac907e50d84a8b812f5af73b65e81d37672bcf5536ab84bff0b63f573cef78866621150eba78ee9280dd5b502f27e3efe57a92bc5517b35ad78f1a8f75b2676c0dd0563d9ae09cc090f6ccd11215c24d9ee6628c3ba4bc7c76920b0ca7a5eef82a3ac0ecdaf52e01c2c694bc49b5bf4224f9d0cbeba9ed4ea53018ce0c46cb44f628925346f198c04ec9070dccaca46e3d21c53d58c91b8217feac5f9a7859fb4bc9c4802f1370d1b7be69f3061942eecb488476e37422372fab8419ffc3dfa15ef484cb3cb7612240f42c856ee4f2b91690b272a50d7684637c71c5f93bb88bd6b2230301e52580f096306895b39a986635ec0926a56603d5ff313ba389214f51745f0adb8d4b82228c0e410b91e8057c2f5e3897a84e0e6fa1b380589958ac2158ce6f7158f9b015eefdd1391bb28185e73b58837bf869fd0cd19d52fef759933bf0f1ed88f45109f6496d2bfe4798d534b86c5e9e71a1cb51d9ef7bf3a9fa29ed5cf8db7951c141b948c097091b498f195dbbfd217db98cbb480cf727ebbf5289aa16b15a5280a405e73a55552312bdff14d23c6b14d2650129e43849703f2273e8cdcfefc8e1c09243c2f26d67463095666598e88e6e0ec016d47ce6ad47c22dbaa9c06ef1b24ac4c7d92aabc6620ec798c2cea4f3f320ae5ebae6cc8d5945d78d1e3072dca0648861087c665d0093b95f6d6a760992185cda32388ac0ae4a96b671156dde72b7e8b389d01a052e920ffbc77a8b7ec8bfd64ab708da51dcbf8e38ec0434ebb0906f87f9dd56c562c119886f145d38cf4c31490e1fa84cf13006ec0b6c053692b0964bc612c460b4a7932a8efceb8f5a381187fe2711d0b5d07f6b10b8c5205047e8e0f6dfcb5edf6a5efb001893a43f6aa7d1710eca6191845d5cf857d63461ee3fafb5de478565044f8f35c4bb9d86de7a193539bc343397b8829fb64df8e19f7a0bf1664655ed2c8e8b42d58da42259ed4a544e98f3fcc8570d8f18ca1071b1aeaa7ac6a39782440e8e5fc7da240fcf4a5af905088d58ffb0d205587f1d31ff4092a421118002b3eb5efe2b044cc5e01a3dbdc1e77332c5609ca2e4f151322676a469630b71a0fa0f2ac4686f26e756dcb51570bb3ca18c07b37712d45de2e55f8790cd6b4817867756d0a7196c4a4db725cfd69a4e4d6394c3ef9174f550317a93010a07dbb7822ae89c2fcdd60e44e250266f4d4dec69698075da81f411a7b457631a287de7be4584579d0147d663d6d9b9b4c8d97d0fa4286665cb3f92be30e2810a5e710a22891774aa6bdf93f8e4872736b901e01b39610d7614e6c2217f353b01c8f344aabf781a281b60c6a3133e2097f459ed78c46fb19c0f72127a157265ebac9f61ca984ae507b283e62341faa1fbd52dba13243de0db30e780d63a783da975082e839ac3037161b53b39b5ade2d7e15f52f151ac006c9bf1b1289a6adbf92b9e6a0452b037122ba4d1b41f5cc10c2b68063545c1c5b5a8f0817afa5d7a48e234a5850a9d6ab2f594682e890b9f407570b97939d78afeb5ef51cd5a50189898cae105c28a9e53bf83fea8f2ba7d74bf796cbd2ded5047c2ee2083da859f59be71f302e2d5cfd097c5a4bf4bff04a397569fad5d963b238ef2e05221b1ab68a1e6d10216590c83035b898acc38c29eb83200821e7951d9012d2241ed0a2f313da9a13313dd6e4bc7fb6e36c1906d23be4e5fefc1fec3e9ff3af0c6001889ba7c51a07b95d29c290c802969772173ba07f160625848156e59d391d36d921506511d660d4cfeb5e617e4608e8d6dc303f698d500d29fbd67d87d01aaed04152cfd141e33e74d2e9b561652419991793d0849dcd0a496a58513b8221c367200f027c697d21991c0c666b49ddf2ee9f88bcc3903f71794691035c951880eba6fedd8f3ffb0078a0667944827f7d25efb8385c8b39fc28d2f49b8ca5271b6d3b6258e247beece7438ef782d8d2a1c0ce1b410916025501046dfaef46165c4e3b7a2b6be425eb7eeffd3b83877ccc7f4b1c9fd2b8e84a88922494aa172125ef1b1c71b2993c75c8b8ef6660480de240bb0042aa67756e49300f00d4ed193871b208abbfdda0720875cc90df9ce888a4ed256aaaf799b482cf5b48f9e02d9324193e1ca147e69234f81de3368a632fcb995fb33c3631c4f284f6ffce192d570b3c70858c0a6a6d08e84040b3b8d2c4c93572dd6283f04287990cea749b2d1af25fa2ee76ccee47dcd8629e30e74259c6d1860788d1aec01cad22d51b1d2cded982d557618f7222b0c884fbae15b1eec46d9931af1f6d3db1c138bfc19f0bcf913fb070eac2df3006683fe14d0bfedd9f9fc1870ecd60b588289caf4562035e3e2354f492a08b4a9b61ac14e7346ab29f9cd69dfb2e867efa0bae4cae350d9e4003fbd2827ff9253434d0f69698440256887c3417d2ecd7098a9fe8ebd806ad719a8c4a814ee666eec04f72ffd4ff5da803550adcbca12afe9f527685ae";
    }

    function logNodes() internal view {
        console.log();
        for (uint256 i; i < DEPTH; i++) {
            console.log(i, vm.toString(nodes[i]));
        }
        console.log("root", vm.toString(root));
    }

    /// Can successfully generate proofs.
    function test_generateProof() public {
        setUpProofAlice();

        // Set up proof nodes.
        (, uint256[DEPTH] memory proofNodes) = MerkleLib.getEmptyTree();

        // Regenerate proof for alice's withdrawal.
        // Note: proof generation seems to be non-deterministic
        //       and depending on prover file path.
        // proof = generateProof(alice, key, nullifier, secret, proofNodes, root, ".tmp.toml");

        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(leaf);

        assertEq(root, zerolink.root());

        vm.prank(alice);
        zerolink.withdraw(alice, nullifier, root, proof);

        uint256 leaf_1 = leaf;

        // Set up bob's proof data.
        key = 1;
        secret = 0x1234;
        leaf = MerkleLib.hash(secret + 1);
        nullifier = MerkleLib.hash(secret + 2);
        (root, nodes) = MerkleLib.appendLeaf(key, leaf, nodes);

        // Set up proof nodes.
        (, proofNodes) = MerkleLib.getEmptyTree();
        proofNodes[0] = leaf_1;

        assertEq(MerkleLib.computeRoot(key, leaf, proofNodes), root);

        // proof = generateProof(bob, key, nullifier, secret, proofNodes, root, ".tmp.toml");
        proof =
            hex"054319834f7d1622f066b4091a72cc8e25fc051c6fe2d99da3f3132a2c46c57c2342b747e846e4fccd2186816fe7f0f9d172949c0496b11eceac3da0d946941f0fa3c54fae5cf47e27c4a88ed5e619d4b3464e02a38648920426cf3d7166af04148c86049c9a36af589dba0e6da26b74b74788ccd7b7e9c987bfc9e34bcbbd9d149579af96b1c8f090b71c200ac2903f9ca7971a2cdc9cbdbbbd6ece6054b80e2efc50ddeca3af628a68ab76c474f3071330beb808e308961a3118e1de118560058ad5dff5e008125247fb27ee80f717922738abcda520343b3c2bc797a11e7011f154fe8dca61ed776b9eacfdedace4575a8026e16448ae1f820f674f9a06a82965e4e69533891b908d2b34b7fe6b7d17be96cae3bc098917847053dc4a53e919cc43552f1c81b2503cf4f26078a09d8243ed8ed7bbae3ce40c38cca2854fa925685526d595c5e999f667a515afc8a4ac750004b66332d599a8a249fb4912802851a71296d7eff244dc7a1a6d0e1aa1f45279341ec5d79fa5cee291db526ea800ca286043ad61c051940b51739e607ce0258f4d079f01320dbf2d127bc3af2c251c675bfcf512f8ba4eddb56e3ad1f4653d9f1eedaa4f7222e2b2cb879c8f3c2ca3b9f67c9c34bd1caa8ea6bac3e58f1733970955e1856a2b4c9b65db22b7a415cd85faeffb2077601f1bd7ee740598f7762744e78517ad894caa864652ac511defca9987f16e9f9518744a05a4d75bd69921278cae39b8b4f0575a53ea69730284b6fdb8594c59b87fbb841408c69ea037ebb327a244f54f4d9ab38d63dce21d814a2896a75c9f3db20f3f0b28f203624cb076237bdba36d5ee9ed75f897f624ce0001818b9aa87266c504baf14a1da31059af27d349ef0e93eda04aaec67b154e049ac4c7a6a9763f294a316359a4bdf4e089c27e0b5bede549c091b15d00205d40c38ca8d5050f619506c0aa377a068e316de975ba9ff3083abce070af642269c586a1a526475d55a292496f6537016ecbf4344206a2aa8f7b1eb84a3a0508d0a65ff12d0aa562f8c80d2784ac22d549c4667498e961afbc9b792f00d2a01aab1f1b3892ec0f3712a5d6c6fec86f2b52f1f1fef836d1c1b6489476df757a069c69bc4b35367f4c7c581cb1293ff4de34a92ca96c1427d666f33258dc94ac11a33ab2a448e729ccdb4d4eceb8c7233f974c1794895d51f528ae0fb865b4e92c09cd00b1bd7c9c8b98b337c32a996d95dab2ec9e02dfc6a1cd3f2e0b0c6a9b0bfdbf8fadf7e75fee0310c68733532fe0af3ce08c359ef24b2aa8fb6abde2aa1dc785cdf65362575c48ddf8c4a63ba497fe80cc0b7a245fabaec948b5d310372a4bb3aeca06736c740731cfd8934f22bf02cf8fb8006543260ea56c90c831960116f45dc79df6adde502312e31f7d6a9356d6ac2838c36cc40cfbaec5ff04a4207736237af70325b9ad986b0527bef7d8e605c182cb15b826f0976e8c29441d2127dd26714868fb7bb2d0eb596f09aeecaa74477ca9ba5534f9f9cb3991045e00180f9b9ee7c49e0722ee1d62c3ee069c0a3abcebc5483efb9b2a022e5ca7e31efab1d485af20a0b342934a8d89613f79dc8d8d58b94d8f8d9b5460439f59942916f6cf5e8cf71e0eb019afb868db6a49eb9742887607677a687eca428683261880a9fbc7d9b4a3ba5c41c546faf245313f147e0753e84b9877e85bda3de62b25fa956a2c8b2530f8069175881720d35c18bc2a5c14a957d4f05531999a1c302d5752287d1bd8691397aa18618cca2d313984b3bbaad75146f44ce143d184ce1a64d362c33075da14593758280b3b4abc69679ce38f8059c9f6e877d04523391c18ecd2d280995939a810911d76cff5c79ec6d05c7a149c62402e09e1ce3c952259fae0c274ce22d80488e8f2059266ca8ec3b22ed58cea80933816607c93f4108a1dd414bc6621bb0aeb1f88ce25928998233a8bdcbadf09ff3949285288391e040942796dd6aef8b53acfc9ea5420b471cae6e09d7beb4677a61ee7aebe3e2b7df4b0de1f473c365f8a800b0682aedf4b7293355e3cf782f012f4a70af443089391ac619f179fbbb99479caa158dfe1f131f710658d727b868a3676672a4703103265b00af5947d609b6f47b1f7045ebe7b8e371bf9d2cd86cc7368f652342fd6eb5ed126c90bdc929743cb42f9a9ad3ff33922b9acc549d0120028f156ce128610d2388b34fb5531ed906495b22b66674774d0c65326d3bcbedfba34e7bc206ef5e1648e330b4dbd7bdff02a39f34208e85ffd00ccf15322a0d0c07bb367029c1bfc0b1ce0073828bc66ec303c6b681d67178ec83f1c3289627d4ab644c90ec9c76d9aa858ae117f2e1e0e390d23b5ae6f20ccf091d29f64972c2fd42e022973d8ad114c271e60cf4ac0119cd972810294064b90e6079ca0ce30af63e7da2f68d4e890c123122de0bf012ac5412abaa6acdaeb3727b8ac6c0e0daf63295110f7a233580ed46ccd6fb36e4762dbad106ed38b811f3754fe6377e1cbc288230782672b1db65f8efd198cb6a14a5dc90d25d8e87ee68edd87466e175bf792d00deb9e57b3380e2b9dc06b1c35ba200b61ae8b97ac67ef3b6fc887a5402b89db1edd84e2df3e6f86898c622cc9cccaf89efa6e9ffe61366d5431a460801a45640d1ddabf9feaa26855ffa5ba20785988ac1bf0120b049dea1516f77d7d2d8a452a7030129b45cd5eb3591c34196329dfbc91e0e87d9bd767a91cb0b3939c0076175e36f2b56f582b58624cf790cca1d9a4d3e9767679a053f9407455ba0a76a6044c3dd2cf98e2f7fd6b7dbb083619d38d15f2046f576940496437f7e078ecd6229a4d7dc3ed5551ea690e7c0a735991634a34c622ffe1af3b47eef690f63f4e2f70e73b0ef8d0819d26922821583005b10050325e1067ad5d575d6aa89bf0e4219133e0403195111eb35e67c525ee17e065fbdb4fb203745462acc72e33834b17cb0c38770de614e9d32f052fb135c69d4bedbcaaa1be4a83cbebbdfd33b045";
        // console.logBytes(proof);

        // zerolink.verifyProof(bob, nullifier, root, proof);

        // Make sure bob can deposit and withdraw,
        vm.prank(bob);
        zerolink.deposit{value: 1 ether}(leaf);

        assertEq(root, zerolink.root());

        vm.prank(bob);
        zerolink.withdraw(bob, nullifier, root, proof);
    }

    /* ------------- deposit ------------- */

    /// Can successfully deposit.
    function test_deposit() public {
        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(0x1234);

        vm.prank(bob);
        zerolink.deposit{value: 1 ether}(0x4567);

        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(0x7890);
    }

    /// Deposit failure.
    function test_deposit_revert_LeafAlreadyCommitted() public {
        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(leaf);

        vm.prank(bob);
        vm.expectRevert(ZeroLink.LeafAlreadyCommitted.selector);
        zerolink.deposit{value: 1 ether}(leaf);
    }

    /* ------------- withdraw ------------- */

    /// Can successfully withdraw.
    function test_withdraw() public {
        setUpProofAlice();

        // Able to deposit.
        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(leaf);

        // Read new `root`.
        root = zerolink.root();

        // Can withdraw funds.
        vm.prank(alice);
        zerolink.withdraw(alice, nullifier, root, proof);

        // Receiver gets funds back.
        assertEq(alice.balance, 100 ether);
    }

    /// Can successfully withdraw with old root.
    function test_withdraw_old_root() public {
        setUpProofAlice();

        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(leaf);

        vm.prank(bob);
        zerolink.deposit{value: 1 ether}(0x1234);

        // Alice's proof is still valid.
        vm.prank(alice);
        zerolink.withdraw(alice, nullifier, root, proof);
    }

    /// Can't withdraw with a valid proof but invalid root.
    function test_withdraw_revert_InvalidRoot() public {
        setUpProofAlice();

        // `root` corresponds to valid proof, but it was never committed.
        vm.prank(alice);
        vm.expectRevert(ZeroLink.InvalidRoot.selector);
        zerolink.withdraw(alice, nullifier, root, proof);
    }

    /// The same `nullifier` cannot be used twice.
    function test_withdraw_revert_NullifierUsed() public {
        setUpProofAlice();

        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(leaf);

        vm.prank(alice);
        zerolink.withdraw(alice, nullifier, root, proof);

        vm.prank(alice);
        vm.expectRevert(ZeroLink.NullifierUsed.selector);
        zerolink.withdraw(alice, nullifier, root, proof);
    }

    /// The call to `verifyProof` cannot be front-run.
    function test_verify_revert_PROOF_FAILURE_invalidSender(address sender) public {
        vm.assume(sender != alice);

        // Alice deposits.
        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(leaf);

        // Alice generates withdrawal proof,
        setUpProofAlice();

        // Alice is front-run by `sender` who uses the same data.
        vm.prank(sender);
        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.withdraw(sender, nullifier, root, proof);
    }

    /// Cannot modify `nullifier` in proof.
    function test_verify_revert_PROOF_FAILURE_invalid_nullifier(uint256 nullifier_) public {
        nullifier_ = NoirUtils.asField(nullifier_);

        vm.assume(nullifier != nullifier_);

        setUpProofAlice();

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.verifyProof(alice, nullifier_, root, proof);
    }

    /// Cannot modify `root` in proof.
    function test_verify_revert_PROOF_FAILURE_invalid_root(uint256 root_) public {
        root_ = NoirUtils.asField(root_);

        vm.assume(root != root_);

        setUpProofAlice();

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.verifyProof(alice, nullifier, root_, proof);
    }

    /// Cannot modify `proof`.
    function test_verify_revert_invalidProof(bytes calldata proof_) public {
        vm.assume(keccak256(proof) != keccak256(proof_));

        setUpProofAlice();

        vm.expectRevert();
        zerolink.verifyProof(alice, nullifier, root, proof_);
    }

    /// Cannot modify any proof inputs.
    function test_verify_revert_invalidInputs(address sender, bytes calldata proof_, uint256 nullifier_, uint256 root_)
        public
    {
        bool validProof;
        validProof = validProof && root == root_;
        validProof = validProof && sender == alice;
        validProof = validProof && nullifier == nullifier_;
        validProof = validProof && keccak256(proof) == keccak256(proof_);
        vm.assume(!validProof);

        vm.expectRevert();
        zerolink.verifyProof(sender, nullifier_, root_, proof_);
    }
}
