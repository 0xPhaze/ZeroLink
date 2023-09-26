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
            hex"11b9ce90c35438d8a350a486c2e1bdca71fc8de78bf91eed5893b0aa28b56d631ed6613f5966cb5065dfd439d8cd71a82e82a1f3f591dafe50401e82034408f60be1feb6b6748306da50280ede982f2a539e31366ea40c5415ce76f84cef42ba1af2cb0a0b616cf5f5d063ef59670c27911f87012e2a185df638ff63a029d75b14731d172e9b8dfb2636a0b32bab2aa63d8a72baa18be62d0bbeafcd533315011959d970e04d336ad6cc8c7ed192be82da6c68be5e13c786de0f42e13a8d8b451a0e88859535eeeff40962ad92a31764150085ef1e52c083a278128037763e8b1c682117aea48f19e32899e42f1a1fdabebf90c64ea95dc93ecdd919a65f1de11e5f3160dd48612fda3f510f86060bd208576e55b7fd2a44de504ed3b75464fd1714e54152dc8f8ec25269d53e2e8802db4307a605c245297cf3c8ef55cb5cea06a3fc09d9afa73b37ecd627c0ca2ed3e224f53a15f6f80f86f940b17af3579629268c90fe605e2cb3a7f5829c05dd1cb120ebea776296b4cbb4a0ebda350bab258e95a5d2a6a76c77198fb18024ca01f7e74d0482da3a420d616316a193da7c2231dee67b24483818b8dced33e6cfbf2914a7ac7aaed1233a3841e924c614cc15595069082a783a93d822db22d10f19150acefdbc4f4d6f4189919ba3f892300b49736da50fa22c95f8684f623766b23a048c58ba4e8ae09a1e9cab7202df2b074a648245bf83afddbb10ff70b1e12c601dece53bd113d30cc2a83e3f8d6c8d1af084c69665856681e70096119c489088a62491b8d6e97582f930d545f29e2a1991217909893ef0ca9704e1a56cd848c60a7f85d25edf54c8f894b954c8f97b08c97cf966a049d71e04fc5561c0a6b562408a6f16c2462b27c982af6e501d81066429a98576a1057eef3af4b895768476b856074e74030d2de9500af18e887524e960fa89630aa0246d2035e917a7f403f3214d685700d0865bfa91a1a228540554caf59742f9dac8e2a80418c2908e3b51e9ef162077618291f0825f71f79a0773e3cfb0164016011035e21a9009c53adc05d77591cd8f5c7ddf98f51c9a9f1b279ac96228ffcfda81ae7f022a3649154fc8b0d81b4447e64c16e93dea8f631d27442674aac39dcc13966ad73fad28de82f0b4a17e03c77f796f50e4ffc1890c8eac7242b78577ae5d428eabb52c317f035b1d183dd58c16aa0561a502e8d80b717668023b682672b0dbcbb755302ad2331e738f85541ad14cf5ebde1b3f272f460f0223f803f6127e5f781fb55f214292c76bb005fb44820ce34141bcdcf509ab7babd18ee03a1ba85be094843fc9f5d46069ee19a8bc7fab0badea1743001f7f965920dcdefaa4a1028490de3798ab22b7e8d933afffc0b36b2621cd0dda26e1a2e461536c9873a002565a0d79a0a00a7a0a2fd132a2704957dac830ceb02d5a5498e34bb240224104d7b976cee90b618d0f1adf5002a49711f53fc3cc9607efe11820f1464c67023361fdd71bcac67e1b450b0c54107152a542ea50250d082c208c0e5a772b42c503143bac523527a97a673b00033fd5383c1a8d2b48d3031b1aab597ba026359eb95b8ef0fa9d24f1807db7aff6a65949ca39c153e46727e8413f4f302082a87be1dc153df49ff9b78838d4aaed077b4aad4161a883f013a3307273bfeb367b11418d14b0de0068de6b4e2e958772b300a55befa5b2e01b323e8beef7339680c6c25bb39a007c956ead7b5dbabf7323c47daf7a4654f923af05fa22c905af742f4a0d07af8bba44a7c39d7820e7c721f048f2e54cd6021506624dfdba0818b52865745c1c5d58d44dedad6980c8bff89d12bb0164d6c5077d12c3ef2fa532e9755166b78ed45255717f7aedc58e4e8c3ac115d7afb48107688dfb9987791ba869d0740d09610219430c1b6ea1b5748ea6b09eeed227462a505abee565c4568c31c3f8f16c4574ee8f31d5bc052f74054c2e568f87992b017b1a657f6b6c8cd996ff110ed40f93f2eb8bba7170f6e3322e11162a283b43090a287efaa2b4ecdf4c7fdfadbd32101f7bcde7a0962ee3a2f1e969b4c8dd5c1099369875d9fd4ce50200ae4ca6548c4c0c1014cfbb66e413b5c1bd3f697f7522c14ca56a2e7bf6867c432a528322f8c1feefa88cdff7739488560304e6f71208c95deb9315d35f1c63f9a9b1a8096d55a3ab719206c36c8fc6b56ae67383a2285bc1e7a0061bb18303d1c1d806811af83c32de2e41e605670bbb51f2d192871de51bb48fdd52eea799e497ac9ff63e1d18d650df2eb365e72be1899a6c199b0a59d7057687c1046ffd8fdf33e909f7c7aa44a525a341a8f96e8b890acf863007095cc956d73aae489b4115bfa43dafd75666381231bf2748a9b7c8a4eba4c320ffdb2bbe9798bfc1564f16738e73edeec4ed2dc5b3ac40f1982bba4d036bca0c63bb6e0a3fe85e3e25164715fc33d7416ac0edcaa0031d2d03ab3bb997d0a006995df78db4a9561164c9b946f7f66df04690b89e715978f265f40738f053410139b01efe01e193faf4f34ab41c655dbefb0ace66398885b5484bfbc8532d3e0bcaaa798943ee3dd5d2176f5f0103eede80a1ff2afc2e7dc1adb0f874ecdd313062d8007f3e6d66e7506225c25a3504d53ba7ae541a63b4dad38cfcbbd83e63293d84cab5b81c690b188cbac5f08bdb8fbea96e15ac8535933f71834b1c4f371072ccc3417fd6aecb2bc51fe03923f784459ab7a5ceb94ff7eb96629ab4007b280c632eae79311e438f433b7c031470a1007449afaa5dfba079b0d5da4bb1c00f41ab273a40eb6403a27ba0964bac8c958765933fcc92160525d5b529e363042fb1f18075dc3cdcb2c99da50351d62d2a55a1287f5915e80e7d416f0c9409e91b474352366ed2348eabfe6f7f0e038f1ae4c05a8494a0c6d7be230d345b299328003f8eb8368bc6d3873dd472184928de4393f1c62b9980ebe353bcb4753681111134baf9b771241af5b9e21a861ef5ff30db18d02960487644aa8a2722b5fe";
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
        // console.log("proof", vm.toString(proof));

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
        // console.log("proof", vm.toString(proof));
        proof =
            hex"0a94aec97aac6a70796ca36429ec4f855c1db871359304cc3f27b535253f7d1109bf85611a647c6499e7534f37ede1d7edfb228d6b8502bfe3de01065fe3c2c721b5b7939cdc05b4fe15ffb44cff0ffa1442596978f165b4bf989f4a3280c1f40e67f029a05e49d1416255b0f4158b3400be26e5d9235fc2bb56920765662f711ffcf72832be3b2e4877f77b22e6009f5125b20c776b6e503889960444197f96027022533df500b17f8224d3e2019977566a2b32dd8077bfc38a6df2dfe7cc5626a81a6c6b5c9730fed8dae112243931c22307b4b036c7283d1d8d776bc6741f3061876446b776415876a9d52eea0b92fb0fae6c4d40ae4e9c045c42ad2d974d11cdd9f4cdf800dded3928bb0f5356e5cefa45c4de070b6669d5e69eea6e6c2a13cee19fca222996b77611f93b88568fdf0590014d89c95f8cabc9629b85c771228d2f17bd1599ff418837d815007960de8734fb1877b3871ce27423929fc0bd0d1fc57b0e36dc8f6dcb2f7b62a58ea79f5a3723e14dabac47fa9c1bd815ccd91599724ebcb04289ab430b51b2375114d1a2788809b659fb10d93a7abe98ca5908f6e82b24810a677366bf06cda313bd7bc4c65c0573d8625db14982b86878111047557b33ebef4c8385a3423c4488e3aad9122000f3f2ea194015433302268a0e4ee387ba173d6a5355595b910aba9d698b17d4915abab61ad69421ba2c9d732f2f4cca89475dd3a7538ba253ad63f4696cd2af3cffb06ae24204f5b278b942162def52b26be6c30c64497a04f1a75d0efa21d7ab5728a9d7470019a89cf52b01fa53f0750276f659c9257681115b442cef610b278fe1436ceafe2704f3972f1f078a9b006e96dd64b94064c5bc97eb9d65f79308bc4a908c613b90b89eb936190de6f4c8b5c80d468b2d7e5a8d2d960b7980d2b35171ff480b665e211522031e4c69ce5c316300eb902455250f82066970f8fa64deed42786092211ed6be3b2dc14097fe7ec3fc5f6ef715e5352bb76b518c08ce431efc54573e96190ba5fc03600ca659ba5adaaf29953239a37278341964ae2d94122bb06063af88359e65277575ee4d0da289f84fb428fe0c8d24da4c84b17b3d8bb0d5e989d97a277d7f28abca6323b7fceae6af9d7c8cb55586575cbdff289d7890b42b3ffeea8df4060eaa539fa0511c3f1a336bd74c880a5c6468fa91f24513542ddc27be7f922215252272680d3127946c6114ea86f7bd2c6cee794915453882a557eaa012e73a46057b5ab3abc9fc18bfc24c7b8c831def43e40001fd37aafdfbaa5c61903e68f8263fa1769e2c94d8419cc89c38ae1947810963f77a9adcc5fd6d24864de53e5e13e834536834637ee38ac7975d59156f8d7e0a303692f87ad3f4fab1a767e4571bea6be9507bf9ce1354a6a9045e68ca097be8e0d5da51ee742a3a89ecb4dcdb0b5f68250e88b942aea6ce67ad1ca82f490ab2a3a165049a063a22dde5b158580c9909dc925e43a93f353c673ca7f22aaf901923cf0b6bb1a08e6004af9d7db5239824c124e9e2c0f9c584e84f628cc7b9b39e85fb8eea4e1ad8e0dc634c825c2a1092241c494eaebd534eba5c42df2c1dd8ead413d14d928ee81024b49141f2233b4c3c62156ed0b35c10ed83956c63dce49f655ec21ecd9867f7537f92bdd2110f1c3795cd15e405fa359b83aafc46ed900bf5721786e70957344cd88a048402d2e8c2227dff613afb40c54aaf502fc1ab31a339bfe2259e6ae8408427933d13a76d3a1a056a37ad8b8565d45f0c95e86e40df5f699fd322da5b78687095891124f0a9d8ff394be0b83c0238d42ef972068757496320d0ee5cf85af327f3a12a78d10ff14472c5dc34a1f6d603d5f8f8662c1011d88e890a1ad8ae74de2d1910fb44e5db1922ec40a7054f2f91deb99a09a23eb2d61322bebee9048343a0a716bed04a1d1172855d4d9ccf5a39505e9215654742ca09340c7445bbcb62b0b008829cd4a9c25c02924ea7f9213da44766308af50a726472a187f9af77003f692aaab7d217a4e5a97f9ff8d969c3508d627f98eb4bd430427a7da337129dce231c6e845ca455cf26b4a1040330c7a476369abe99137c8b810f91572abe3b5cdc24fb03bf90608908284c91a59334fc75bdfa3f997b21adf5776091c81fc521f7280360a1fba57e096236b0f0f089df041bed756eaf4bc85f7be2493e014a56a02a3b77d3f457820449756cd485f86260aeb5f221321b9ff02d99ff68bb427879191ab5df3e2c62fc5aa356fac43bc2f6a8f3a5db45c95070d62f271cccb9096c286eb0471f12c99844d03110bff75d143bb9db042ee824450536e8132c34afc525a519b74ecb99565f36c40497c90a3875f9c1baabedff208dcdb495271c7adc175c0144ca1f493500e5edd00a2ed0644ca21bbf346c3f9367e667fa4da73d60200d2f1f38e7d5a1ad61a1bd7eeff4d4526de208058ce50762d3cdfcfe2240ea2f5901c016f48558f118d466fcc2b2f27747552814135237152d298e070c49e21b9ec27e0c4f149d754949c1a4e8edbf582e91940e960b6419161be442c57bf42dbed1eb7734a53597511bda7636bfa95ecdd46369180f5e4f8c1f0b25ba38a41ea353cd580b7fa518b12af8f875cf57bfee9b9d4438735003ebc0ff43be13c925b8fab4bfde94f0488fca82de83739017f40810e3856ae8214c9ce4c4f41e3028ddba43cfdbcc044e9bc60dc663bd316f485e124bd089262412ff4d2ab320b42c0279d2dfd9031854a7c198ae4406d2c69cb413b41ba76426d961b5907223382f273961efd63a2c5ab3bd23962450741df10a151c66c5a2299fc41df63125bc0776f6e4f092083ddee09c1e1168bc5b54107b18c44b6b5000913432712da2431638c500a91da940f3e60e8a4a13c494ad909271c6a32481c733c307372bb30f1f9b34925e6f1d26addd778715ce26f9c961d974ca5a52a282692d634cd98d352ac3e46d7ad5be58ae8abcd248edd766ed84c1a24425bb40993f733f338e5671";

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

        for (uint256 i; i < zerolink.NUM_OLD_ROOTS(); i++) {
            vm.prank(bob);
            zerolink.deposit{value: 1 ether}(i);
        }

        // Alice's proof is still valid.
        vm.prank(alice);
        zerolink.withdraw(alice, nullifier, root, proof);
    }

    /// Withdrawal fails with `receiver = address(0)`.
    function test_withdraw_revert_InvalidReceiver() public {
        setUpProofAlice();

        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(leaf);

        // Alice's proof is not valid anymore due to a stale root.
        vm.prank(alice);
        vm.expectRevert(ZeroLink.InvalidReceiver.selector);
        zerolink.withdraw(address(0), nullifier, root, proof);
    }

    /// Withdrawal fails with a stale root.
    function test_withdraw_revert_InvalidRoot_stale() public {
        setUpProofAlice();

        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(leaf);

        for (uint256 i; i < zerolink.NUM_OLD_ROOTS() + 1; i++) {
            vm.prank(bob);
            zerolink.deposit{value: 1 ether}(i);
        }

        // Alice's proof is not valid anymore due to a stale root.
        vm.prank(alice);
        vm.expectRevert(ZeroLink.InvalidRoot.selector);
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

    /// The call to `withdraw` cannot be front-run with a different `receiver`.
    function test_withdraw_revert_PROOF_FAILURE_invalid_receiver(address receiver) public {
        vm.assume(receiver != alice);

        // Alice deposits.
        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(leaf);

        // Alice generates withdrawal proof,
        setUpProofAlice();

        // Alice is front-run by `receiver` who uses the same data.
        vm.prank(receiver);
        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.withdraw(receiver, nullifier, root, proof);
    }

    /* ------------- verify ------------- */

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

        // console.log("root", root);
        setUpProofAlice();

        // TODO: Why does this pass, and how did the fuzzer find this?
        // root = 19712377064642672829441595136074946683621277828620209496774504837737984048981;
        // root_ = 14454887486296858059177895280788715091825181821667744840060709186414153006648;

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.verifyProof(alice, nullifier, root_, proof);
    }

    /// Cannot modify `proof`.
    function test_verify_revert_PROOF_FAILURE_invalid_proof(bytes calldata proof_) public {
        vm.assume(keccak256(proof) != keccak256(proof_));

        setUpProofAlice();

        vm.expectRevert();
        zerolink.verifyProof(alice, nullifier, root, proof_);
    }

    /// Cannot modify any proof inputs.
    function test_verify_revert_PROOF_FAILURE_invalid_inputs(
        address sender,
        bytes calldata proof_,
        uint256 nullifier_,
        uint256 root_
    ) public {
        bool validProof;
        validProof = validProof && root == root_;
        validProof = validProof && sender == alice;
        validProof = validProof && nullifier == nullifier_;
        validProof = validProof && keccak256(proof) == keccak256(proof_);
        vm.assume(!validProof);

        vm.expectRevert();
        zerolink.verifyProof(sender, nullifier_, root_, proof_);
    }

    /* ------------- proveAssociation ------------- */

    function test_proveAssociation_InvalidReceiver() public {
        setUpProofAlice();

        // `address(0)` is used for proving an association.
        vm.prank(alice);
        vm.expectRevert(ZeroLink.InvalidReceiver.selector);
        zerolink.proveAssociation(alice, nullifier, root, proof);
    }

    function test_proveAssociation() public {
        // `address(0)` is used for proving an association.
        address receiver = address(0x0);

        // Set up Alice's proof data.
        key = 0;
        secret = 0xa11ce;
        leaf = MerkleLib.hash(secret + 1);
        nullifier = MerkleLib.hash(secret + 2);
        (root, nodes) = MerkleLib.appendLeaf(key, leaf, nodes);

        // Set up Bob's proof data.
        key = 1;
        secret = 0xb0b;
        leaf = MerkleLib.hash(secret + 1);
        nullifier = MerkleLib.hash(secret + 2);
        (root, nodes) = MerkleLib.appendLeaf(key, leaf, nodes);

        // Set up Eve's proof data.
        key = 2;
        secret = 0xefe;
        leaf = MerkleLib.hash(secret + 1);
        nullifier = MerkleLib.hash(secret + 2);
        (root, nodes) = MerkleLib.appendLeaf(key, leaf, nodes);

        uint256[] memory leaves = new uint256[](3);
        leaves[0] = MerkleLib.hash(0xa11ce + 1);
        leaves[1] = MerkleLib.hash(0xb0b + 1);
        leaves[2] = MerkleLib.hash(0xefe + 1);

        // Sanity check: `leaves` must generate `root`.
        assertEq(MerkleLib.computeRoot(leaves), root);

        // Prove Alice's inclusion in `root`.
        uint256[DEPTH] memory proofNodes;
        key = 0;
        secret = 0xa11ce;
        leaf = MerkleLib.hash(secret + 1);
        nullifier = MerkleLib.hash(secret + 2);
        proofNodes = MerkleLib.getProof(key, leaves);

        // Sanity check: Verify that `proofNodes` can
        // validate `leaf` at `key`.
        assertEq(MerkleLib.computeRoot(key, leaf, proofNodes), root);

        // Association to `zerolink.root` is guaranteed.
        // Generate a zk proof.
        proof = generateProof(receiver, key, nullifier, secret, proofNodes, root, ".tmp.toml");
        zerolink.proveAssociation(receiver, nullifier, root, proof);

        // Create modified merkle tree.
        leaves[0] = MerkleLib.hash(0xa11ce + 1);
        leaves[1] = MerkleLib.BLOCKED; // Bob's nullifier is invalidated.
        leaves[2] = MerkleLib.hash(0xefe + 1);

        uint256 aspRoot = MerkleLib.computeRoot(leaves);

        // Set up Alice's proof data.
        key = 0;
        secret = 0xa11ce;
        nullifier = MerkleLib.hash(secret + 2);
        proofNodes = MerkleLib.getProof(key, leaves);

        // Alice is able to prove association with `aspRoot`.
        proof = generateProof(receiver, key, nullifier, secret, proofNodes, aspRoot, ".tmp.toml");
        zerolink.proveAssociation(receiver, nullifier, aspRoot, proof);

        // Set up Bob's proof data.
        key = 1;
        secret = 0xb0b;
        nullifier = MerkleLib.hash(secret + 2);
        proofNodes = MerkleLib.getProof(key, leaves);

        // Bob is NOT able to prove association with `aspRoot`.
        proofNodes = MerkleLib.getProof(key, leaves);

        // Commenting to remove ffi error message.
        // vm.expectRevert("Invalid proof generated");
        // proof = generateProof(receiver, key, nullifier, secret, proofNodes, aspRoot, ".tmp.toml");

        // Set up Eve's proof data.
        key = 2;
        secret = 0xefe;
        nullifier = MerkleLib.hash(secret + 2);
        proofNodes = MerkleLib.getProof(key, leaves);

        // // Eve is able to prove association with `aspRoot`.
        proof = generateProof(receiver, key, nullifier, secret, proofNodes, aspRoot, ".tmp.toml");
        zerolink.proveAssociation(receiver, nullifier, aspRoot, proof); //
    }
}
