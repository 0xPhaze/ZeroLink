// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2 as console} from "forge-std/Test.sol";

import {ZeroLink} from "../src/ZeroLink.sol";
import {MerkleLib, DEPTH} from "../src/MerkleLib.sol";
import {BaseUltraVerifier} from "../circuits/contract/ZeroLink/plonk_vk.sol";

import {NoirTestBase} from "./utils/NoirTestBase.sol";

/// @notice Exposes helper functions on `ZeroLink`
contract MockZeroLink is ZeroLink {
    function verifyProof(address receiver, bytes32 nullifier, bytes32 root_, bytes calldata proof) public view {
        _verifyProof(receiver, nullifier, root_, proof);
    }
}

/// @notice ZeroLink tests
contract ZeroLinkTest is NoirTestBase {
    MockZeroLink zerolink = new MockZeroLink();

    address bob = address(0xb0b);
    address alice = address(0xa11ce);

    // Proof data for alice's deposit on an empty tree
    uint256 key;
    bytes32 nullifier = hex"222244448888";
    bytes32 secret = hex"1337";
    bytes32 nullifierSecretHash = MerkleLib.hash(nullifier, secret);
    bytes32[DEPTH] nodes;
    bytes32 root;
    bytes proof;

    function setUp() public {
        deal(bob, 100 ether);
        deal(alice, 100 ether);

        // Initialize inner nodes of empty tree.
        (root, nodes) = MerkleLib.getEmptyTree();
    }

    function setUpProofAlice() internal {
        key = 0;
        nullifier = hex"222244448888";
        secret = hex"1337";
        nullifierSecretHash = MerkleLib.hash(nullifier, secret);
        // Note: These nodes are used to compute the nodes and root following
        //       the next deposit. THEY ARE NOT USED FOR PROVING THE CURRENT DEPOSIT.
        (root, nodes) = MerkleLib.appendLeaf(key, nullifierSecretHash, nodes);
        proof =
            hex"0199e0a6c4fb6c29181056e20e835581975df8b4f16073ce4cee26e68f0139272ddd8e7eb08f6a7a92dd2f2387b8fd3eeef78284c85f30dae6ccae44dd4c61082823fc1a0d642127fee54b54cf8f9d27ff6d5732e1af700815738a16473ab3fe2e32515e09fc7f023ae6f5f90ced4e6e32bcb904d38622796cb08e2a7064e45f125ac94e3681b96f4040ccaa1a3472f7377487158a5197a1f7d2cc956f2b29b026e8d6888398c156827444299895c22a29052a54f0932ed340d09e0bfb45f76700de2deca6422fae1fa923fb2260d6dd59513729cd06714847d44e702c920a302eec5ad18d69044de2d9c92f5fc4e828d20733999348e2a69767a60c48837f3f0b9802533c36d5c893b398bb87c8cf4d20dc6b14b4809838e8a3ae2eeaab1878079d55b111b4ca93ce628f1fae41972d4ff2c5d47c0a2862a21e411ef930111a11295f398cb3620b9d71473bce21e0ca8d09e69207fa23714eb8c939983a09d12c4f045b12b5cfe2bfb579f015edd95166f449ee2351f34adecaaa96f98a48402eaecff7b35eb02291e94f2eb0c55d7b58bd66ad3c431691297241b47773c17b25c4b5d5d33e55364d593851b399f1bd516c92ad3135103e42dd63e057321c970a5ef7f2c895f9ba1576fc7d88c5746febf19895c0d061a41e7fb2c601fc5d1a2f70f8270ed281c53e45429e012dd1ef8634fba15dffb24776b51277684c9dc92728872d6ac147b76c9c31af7b1c790290a8cae2ea9faec664a1cfcefeba7d0e0683c70b21297b9ccebc139d7157f6832e074a1c7cc289b03a8d9baa405a85bc07af269ff7dbfa4397633a11fe555ab3f3359512b3969f4de450d4565e176d1023b592dd7d5c357c9a340bc2289042946bbceec2efef5fd88aec095c879772230c0188ecb892e3fd1f7dc77d0c1f472e720c2e74048e8753cc23b80b6c4bc7bd1027bf352b7537c5023d13da41fa6c0a754b99b93fc0d99e085c3b4243dae8b5197f4426ca7949fa48f1b87a385aeb7e8affb2ba0f3c0435863108ba12f4edbc1bf32eac4e7ea276be10020141be66eae8c6d8d7fa51d8e6f3942bb6c29a67962ec3363c2a5ffb4f9ee270b9f3a4c50a69646cd7020d8287f5a7e23d9cee953d0d17325183118f627a3059847145dac96b884f1fb034bc639e12bf690d02629d1f555ccb8fcddb1582bce19bbc95416122b30eeb56a9fa4e9c50d161fe6f118a23dd20555bbe8596f61390fadde0af71fa262deb8416c43507e73b426d0392410289dc81393094969a1011d8d206c5b81537c3e8251b5f0202c7bd77010bc1dc2e09cbd28ed4f7c0597ee3f1eea3c5b2c44a2db58813a5e1bc8e5072aebbdea0224ada9bdc2e2467ca3fb05bd180d7d3f76dcd72b59dbde7263cd5210c5312161d18ee1a63850845db139da082cc561f6d1e3c6263a6dcaa4e8d2d5cc7de3f3b1795c70bdac1c4fa4bd29749c5128fb08afffc168c9765f4f78052afb1db9ccb26317dc30babee06d936c42642980a513098ba93ad809cd1020247157748400a02da3af14eb70c1e905ef960b0c65c3fecc27e5d998a525f38b30e2fd416a45e273cf9005b03b45b3301097b53b410db3cb2627460aa76f216357b3447a0a879001169aa88bb7be036dcb08db2a2a5baab781ceedd5944b8b1456f4d51dea04c077d4f1a34550db55467318a889836b16d07d3667e1b1824584b633fd296f23d13134ce14fbedd7d6a4b9bdeed70894b9e8602103563c20fc685fa2ee66ed4440978b09723363362492a9e458db9398003466da024b2e0c58b485907c8afee362ebce0aab79dc5c03d96a7f9e2e1b507c1091ba293652eb36b60256c93b9142111f22fc638a056293855dbcfc01afcc112cab8a264714d074a8bae175723c2ce0d6c0db3337995608759eedc894d2a730ee7a68fe875ee5f2dbaf906b28c6af312d467809ee4662d8458616cc2a6dc452e91c23c9188a33bd8122d27262e66d022c32f6a3da4b87636621b2c7aba7f0d80956f6e591e0ae096dafab120c718c7025bf0f73c201b45e72d4c4c4a01fde6a54dbe4501fd2f82f8e33941264897f1119592470b5c08d0eac0831e0c8072565b0b30d19479dd3bb2d052ae234356c30b27c361fe705224dc276dccbda576e9438771facfdc7bb27b1f50c553dd511705cfa220bd3034e46592a0a0a017b88b600a9966ee11599e2fcdc335a83cb41b1a208af45e5a8ef4c7881e58d204735ffd44a071d2814d28efd0103e5a4053cf1baed5bb582abe369e9690f5e3d7b5ad99020fd5bd754780c8d433fe8a8b45030229cd7674ea575737a7f1ee817fb36b04df2f4ac57acdaeb094d9800f4604480101ace275a077d884d698b6c8f0872c3a4a79e3b6f41475e6e3331fefd881a3012f8a65b8f68d069216fe2263dc2cb037b4f144151c3a41f9ca0d0ef7ff8446220b2f1d35acf2c49e492efe995ed223c1f6c1409e2538fcdf7a9c11fbf5045a247d75a4dd90f5f90c74eb9c824beddb3a51c42ef7a03bf71f7f1c8b22a29a3d1aa3e558314b00846a9cc15f38b183ec5aa67badc0b794048048a4c985c256f102eedd257b3b882da176b9556179acefb88aaa32bcc7e7bc1940fbd0400f4e17075e82b9053074180517768244b283282db15a507b8b993b1702028ecb9f43ab2b52777df18d54806ae30ae8bb7254c9f72ca978011130a9d70702ab5661f2430416205d8b728f389152fef5a07fb88e234fed8402ffd8fc1e922ec11d6d53492f7bc3dacc8445708cfdea04f1da5d852b911f3a173d49c6835a9ca0102ef67b26e83b015428166cf05ae8f879b80e96897308e13fa89cbd27b923fe74af234c10ca1d7923ea3650e07b7b8dfa1bf08e6395294de68ad8fb00516028a0099beb0415d7611a1193a4c47deddb013bd06eb42a497f9ac7e452a5a38d694103d95e04ef1e13b796ec04bf8f0b50d8c5608ec26deb1c07815c5dfd1dcc0558de81182514b0c15fb459349b3fd3b51138d01e236196cd41e562927a67e010dd83a721";
    }

    function logNodes() internal view {
        // console.log(toStringUint8Array(abi.encode(nodes)));
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
        (, bytes32[DEPTH] memory proofNodes) = MerkleLib.getEmptyTree();

        // Note: There seems to be a problem where the proof bytes that are read
        //       conflict is `generateProof` is called multiple times in a test.

        // // Regenerate proof for alice's withdrawal.
        // // Note: proof generation seems to be non-deterministic
        // //       and depending on prover file path.
        // proof = generateProof(alice, key, nullifier, secret, proofNodes, root, ".tmp.toml");

        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        assertEq(root, zerolink.root());

        vm.prank(alice);
        zerolink.withdraw(nullifier, root, proof);

        bytes32 leaf_1 = nullifierSecretHash;

        // Set up bob's proof data.
        key = 1;
        nullifier = hex"abcd";
        secret = hex"1234";
        nullifierSecretHash = MerkleLib.hash(nullifier, secret);
        (root, nodes) = MerkleLib.appendLeaf(key, nullifierSecretHash, nodes);

        // Set up proof nodes.
        (, proofNodes) = MerkleLib.getEmptyTree();
        proofNodes[0] = leaf_1;

        assertEq(MerkleLib.computeRoot(key, nullifierSecretHash, proofNodes), root);

        // proof = generateProof(bob, key, nullifier, secret, proofNodes, root, ".tmp.toml");
        proof =
            hex"2e3e111d23619fe9c8eed472e71e7e600b01e8e618f5101932de01ac389b98c12bceb490742ba76cdfe652525386e0b7ca7597da9ed37cc716ae1933d292216d1d98e0f97abb8e60cc01f4c539ab89ba2eaee7c870d3e1ccd637260eef9911ca1c0dce6633ef3dfb7114f4d0e93dbb12a5d3ba48639cedde7fcfee60dc3f3d792d899eee54ae8d2e13df176efe10fc36624aafc2e975fba49dfe9b39ce0b39ca2f410e4de4201e98d74ee86158451178e6a8f49cd648b07036c810c878f9ca0b25384a1e0a3d6014196c0178b5c9aa3cc6d657424fdd6949796b4b9f1e251e9212411e2d2111b05c98a0c00174f81fac07f1eb5849e12ea4d4b1a3e503b80de11763569e66e09e54d737e9bcfd7208f7b96807cdea7624b879b69f53331425d721cc6a4e0a96813b382c3fbfef9bd3c0931611c14aff2b238e5d74545d3a48f30abc80a595ce262a7db18181900ecb47234e43b8705a51d3a2aff352276e5d711f26a59b2f6261fb7f0f89645012518de73b2de400f089afa4984aad3dd547d8252f64fd6bfd99d1e1dea62612b4ebbf83ca03152dc75105492cb22946eb77c025b6c2e87907b0ac1b3152a3d520ae8f75446c1fd4e7cc7e4d871b8129bf54521ec16bac2a1c70ab40dc5c023ad592c0fd8415810591f5c7f56df65291b656c707a565f72698e86dce6508f60526bfffed7f9730e6d7bb1cdb9c92f1cd34795808d2bb36c100ae182c953b5bca8bbc679f794e9750f7468dcc0f5bac6a6244dd09763e880d5314005d28a00e0c5cdb4ecb8873f534f6ad0889460025388f503f1c11cedd03a03ebf603070469f7cfd6784cb593f6d8f52d15d79687134df0d882ee249584d1ef1d2998a582bf24bc78820f621c9a33022cab66b13b09a88f2261adf6adc5c8fa943c9a9d0f6c21cb7a9e8b21f2cb61035775743bb6cf522e0f11b841781e6d343cb3e09beba5e481b3ebbbd27f5a68e97469f72937d85891ffe03172d7000d6db44ee6e332370daa0c1a753c3ef58fc11b2db7184d89c019d2b224c2e734150a84237a5b0c61d0e8aa10755692e0f5a075ca54d46b07c04b0e8082472ae4c17a9a13bb6394e2c22e918283bdc761e43bcaf84a5fdccfd773d7f06f1f1dedbf8164e9d26cfc8df53b4cb18d6397b5cd359f32b2bb6cbc302be3a0ad326cc43dde481a6a79eaeeaf933d8464437c8ab228f6236cc1eed61bbdd592ad8baa1a192fe94561c5c0efd3f29ae7fa57fccbf060a735559235881c20acf2eff98c49fb43be6b1b3e105f0da44e67c6335eab9b5598a50404d0885880c2f18a43b4920105825cfd26856bce72478a11f6a9b8a3722aa774b24942ab7f8fc116d5d0370a3afe17a1e32f8c11c9d3d2baeb6ab6a2d423d0843e3bfa3404e912624f91178eef99960c1ca837e61e5a1ef3c6e438333f37a38a9b1321ee358ba29dde12eb272082d078e72118ca584467517180e6c77831d8c3e14ab8b312d2f18778eef75d39742e7d38c7ff5cc431cd7ef94127fd8c769820b71ef3cd551c1270a755aa0c7a5d90db3a99a80b86ee595b86067036bed889fd5516f4b97355416443c84b356b201ba2ec9e95f9a7b9b4f8f68391e00f2532b08b583ad5888bf056403412c3a41f78a01aedf075d137b8a4aa509f6546258ffab8bf814fd3d880822f6188f6ae84f3f70300ce30ca5bbdd171cb299d37227490ee6d8a16663f32eadc03bc0480cea479ea47fd2c7fce04dd046542609649ca26af863c355529d02b354539d34e93ae22ec758511884d440c6657d641597400592ae4c9ed0c1f51a2f46ddfc38920a9f124941750e7072d08ca1d5d0fc9f0e911b19b40d7699b22d507b88e1282aa92c37908715b50df2bbdd9564f0b9cb7b9a2aa9247705ce4309d771a6aeda4bbc52331f663ed4534f6cf02b9227ca1b715a5af737a01533422707618c5ade6b5ba9855edce677cce0a11c65dbd5eb107e73436fd60c8605f116c2d3afdd8871ce6a30042ec7f69ba75c82e2f24aa5acecf898f4e0470c5ec010aece48d57666d9fe68102be6c84ddd5a944d4efb48cb97f53c38611c6b270311924f3ecd56a92f2adf9b7da3727ba7a5df95973569718a17883b68ce5eae4c11ab09eefd289998bbe16c2f56f7c1d4cf986ccbc67d3dd9d441f7e44e2c2c541030b2343753ff47efd9d35a5f80d329157128b7ac043ca8279b7312ed4c9c102b2f156f11b2492c2a9713553b6256e02630f688c56339c5672685b73fd9112913f7a93e192f2583255ef4969833f73c9f536e837c1d7c8633394dc695f3f5d32526f43a862467b9808b8ce21d7812e5c3d8614ac3ec089f013f59caa762b03a10d33a5d532142481c7dbac53db11eb4d8136fbc774ab1a16458af148a3cc80709dfd4d43be0d95214bf01589b7899e831524380410e70815abe0986eee49d82225212a9fd5c413ad82b8e3a699a293a74e50d131b061e41fe3865cb804bf7cb233d753f4d6dcab007725a98da00e8c5222c33790ae6a1a3bc2d4fde645cbeba054263226693be5d46bfedb86b0ca70c7a9d3461589bf450950f5bc10a8eef6e2e10a2cb2458144fdef1d99f0999b56e4583f58eda9bd384f1462693cdb809fe211dd2f8155e6f5076ecda3a2cdaacd05e5c3b954a7d526b40b7315d1e0d2d7b2043e60f4a4d31bc49b0cd3933d6bac12fca1a0323a5171af74b0cbd2f872fc815b99348d23086c73b9026c6c632a1706ee8a99ac3e2f9e7c1b899d4f76aa24b19441e3f20df1918b9716be0054d787a38d410cef6f757f97cf42c18f1cd9e0a08115b85ae0d369ef09041a0869ebb11606070d7ebb448017a6b2c2e6e1036511597e5d3ad25b444f9c8f18c236e2ecfb94596ad42b6a09093d54806c8dcb30c2cf4a9494c4a1709335b1dd9567d48f9d8f53e2a5db1cfd10b42273e56d20dce04291cb318d49650e526579a5bbb7eb454357a65015d62ceba199d98bbf28ba80f5ce894cdf07f5d7a874920bf2a5beea772e8cacc831ef82a27ba8090b836cb";

        zerolink.verifyProof(bob, nullifier, root, proof);

        // Make sure bob can deposit and withdraw.
        vm.prank(bob);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        assertEq(root, zerolink.root());

        vm.prank(bob);
        zerolink.withdraw(nullifier, root, proof);
    }

    /* ------------- deposit ------------- */

    /// Can successfully deposit.
    function test_deposit() public {
        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(hex"1234");

        vm.prank(bob);
        zerolink.deposit{value: 1 ether}(hex"4567");

        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(hex"7890");
    }

    /// Deposit failure.
    function test_deposit_revert_LeafAlreadyCommitted() public {
        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        vm.prank(bob);
        vm.expectRevert(ZeroLink.LeafAlreadyCommitted.selector);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);
    }

    /* ------------- withdraw ------------- */

    /// Can successfully withdraw.
    function test_withdraw() public {
        setUpProofAlice();

        // Able to deposit.
        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        // Read new `root`.
        root = zerolink.root();

        // Can withdraw funds.
        vm.prank(alice);
        zerolink.withdraw(nullifier, root, proof);

        // Receiver gets funds back.
        assertEq(alice.balance, 100 ether);
    }

    /// Can successfully withdraw with old root.
    function test_withdraw_old_root() public {
        setUpProofAlice();

        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        vm.prank(bob);
        zerolink.deposit{value: 1 ether}(hex"1234");

        // Alice's proof is still valid.
        vm.prank(alice);
        zerolink.withdraw(nullifier, root, proof);
    }

    /// Can't withdraw with a valid proof but invalid root.
    function test_withdraw_revert_InvalidRoot() public {
        setUpProofAlice();

        // `root` corresponds to valid proof, but it was never committed.
        vm.prank(alice);
        vm.expectRevert(ZeroLink.InvalidRoot.selector);
        zerolink.withdraw(nullifier, root, proof);
    }

    /// The same `nullifier` cannot be used twice.
    function test_withdraw_revert_NullifierUsed() public {
        setUpProofAlice();

        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        vm.prank(alice);
        zerolink.withdraw(nullifier, root, proof);

        vm.prank(alice);
        vm.expectRevert(ZeroLink.NullifierUsed.selector);
        zerolink.withdraw(nullifier, root, proof);
    }

    /// The call to `verifyProof` cannot be front-run.
    function test_verify_revert_PROOF_FAILURE_invalidSender(address sender) public {
        vm.assume(sender != alice);

        // Alice deposits.
        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        // Alice generates withdrawal proof,
        setUpProofAlice();

        // Alice is front-run by `sender` who uses the same data.
        vm.prank(sender);
        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.withdraw(nullifier, root, proof);
    }

    /// Cannot modify `nullifier` in proof.
    function test_verify_revert_PROOF_FAILURE_invalid_nullifier(bytes32 nullifier_) public {
        nullifier_ = asField(nullifier_);

        vm.assume(nullifier != nullifier_);

        setUpProofAlice();

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.verifyProof(alice, nullifier_, root, proof);
    }

    /// Cannot modify `root` in proof.
    function test_verify_revert_PROOF_FAILURE_invalid_root(bytes32 root_) public {
        root_ = asField(root_);

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
    function test_verify_revert_invalidInputs(address sender, bytes calldata proof_, bytes32 nullifier_, bytes32 root_)
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
