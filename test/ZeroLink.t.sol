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
            hex"1b757a6c8662847371f6dfa798a7ac28b3d9464ee9cf5efdb8a8054b78d92faa21c11a3e73f41d49d80438f4af10ba8198c8836ca617c6db5e5b7c626e26d65613c60a8016f9149cd6ab15293b5d11e106cc1dd702e004d2f0a6d04ebc6a63352d15591ba3802b64711385c8049ce97b63d95a74654fa2c2aa1fd9e801773617015a7c91c551664948c9812294accfb6ed1bac1397e8c8267b6527987796ec45169bdfe94fb831d03b7ac1e777f663da52d5fc99874051471a12da7d3dfc0f522b8f60c0c7b7ae3924f8eb5fd76192e66a008badb63779adf2b60b522bb494d22b2f3aa65bfdac825a02dc6a0e2af6f1cb04b185f317b34102747affab0fac11052ff486e7f0e0a7ea7b19de6fbcdd3e51109b608fd797919e6924c8307eb15d1c0900305a269c99c497f5d9f55a7342bfaa78668ad493d39ca2642dd71caa1b280564c5fc61997db2abbdb1421b84662f91a1b61b4378d6e36ecb2f10fb95002d1b36c5a6aa8fd13090e9240ec983ddbdcd6ac5a6ab2f5f60a475bbd0d3b6581e447544bdad79d01391f4a5b9f470e0c9b332da01a91785a0feff621e98669c16544a37dd19d5a6387c89a2411ab9174c6bca2e18a3370b817da5dd0dbe42bb2a3f03670a3fe6ebbcb1ecd2a8646b0431402d8077d9b8ee270cb3e5b3f914330b8dce50af11089c5d53f40d91ec7b927d97cb9ff47819c89168926e21f7bce51eac0984a439abd3d0260eed95002e15cb66bd071f8ce26d7e579d7a29566535094013a056f2d7ced41223d999c1246c4228737b91e0837d947852c47c10483815f87363d6dc9422df179a40c144ae7c5a14afc22e3d5a61faa0953ce33d46102849670d578d8da3e090a24d1dd51b959f5d80e00b34b5e9b8f09133c00505512abd028feb4e02951969dde262b270d72a0a904da4a81b78fdca9e7acdb997d31de39f20e0828586ec433e605e243b63eb85ff4a862cbab5ccdac2442edce67727451297db76d94dd2343c9dab04114aac1b87231b7bb71d4b88905511eb711c29379e92757e0e513d1c84c60c8373749fc6d798a64237b9c90ec637ecdd8ff22eb5a6e576d8064f75ca30fb8810ccf4a0ea94cc05d7165ecd5502f1589ebe3d0b0bfce3025d8bd5178ed9161d0796a33b72967ad26710941d9d871c899a473f0652433e36abc722611cbb25dbe741fef08eeade29a44de5d2cd16c19f5c404b1e2c32d45fe971bd8543583305f5276428700136d74b600f2237f581a3551d2d2199018eb2caef4a87e7d4b639e756e84c62f36267d711b82372cec88b020d6711d7d3a0efdf03198bd316c18a7ba1f618708fda6953e946230a2023e98641102d3c54d44da1a7c75407b83481351bb05a32cc1b5c7f67b5123c059198dd404310481b9e2aed9a1479c5304e049b0ffec9cf15e6cf037bd5f0b814cbb741c51a2cbc53b685bb70d0cda06d7f505664a7d2a9347c5bc3bb0e9de73f50d84364f12bd6728be9eb9c4c2b7b64829d19d4bca7dc6b2f9ac98a70882b09ee5cf3742c0a0ad021e8a5937ddcd358123c0a8b775305ccf6c03950713739534217a1a5912f7e0417bc0c87800c9bc954968f5c620ae6940cc7d716a5d5ec0ba37251664c0b4176807bc84b9759daf6f33ef1d8829b585db2ab4b88d78ea7b42d3059dbeb2ae856585800592458488163b7c0eacd27e3da964cc8e04d4ae9e42f4c6517691a2ae7bd5306c6879e65c61daf0ea4ba8c3b6f31748cc731c34a1e9d787052e6192e809931303c44d24706b438ec401f36cd29eb49d37252e1bd3e1c2691efea251eef95511604ad7b7e9ba73fc7a2c4801b47d5b1478e7b5ad20ffbd3680f012c9cdb4630fd1e7c91298ade5be40e39569693f3ac5d7e5ed10db3714c52beb9048b2cfb7e6c1d15e18168f4ba75a9dffa19050e57fc572e156f8f659003ca28291458fa2a454177e2f095481f2b70f27d1e80b03dce058bf7ec890dc086c9e11856ea5f254baedb290dda0216792adfe176154b6591ec70704cc37bec92055e07997bc420521c3e6f2b1ebc0dc6e4cd45cda9e68d55d354e8acfdea189d40db27405b9bfc8a29cb6d98a92c8695f717d25926ca2ed32acaa4ef2dec34a87c59096d79224e0d33eae4830ad7a65c5ea7f09303cc9c50ae163baa590ba47b8e63072aa93cf37beb9a0122bb9f44f46b33e77a2abf8956435e71dc676d9d38df012ba2b34ef317a40e7a16529f2a3e58ab2122988cde10d21a630abb01457cfbae219c44e6b1fdf8ab523419369dd359f2a27afc4933f3db6b4915165d6090686524b6d77715ff9c30f218f7fda71109e549b881ca8ef4a7d5279e90c0ddffbbb11fb3b1790a398582c07fce4583170a1a35d45eb5a22b56d8102203ec19ab893d2af8049651128e25d740a2d3f1005b0feeef53a86f61a224f5a75f7426c8321f19c9f9343a59dead362c8a2c6bdb7ff33fa1beed5daf6b3117a5a2606573c2ef2f526efec2fb8d016118581a50d3f188918157e23b2ed154cff53a55d5eade5f2a0db7f71f6e49ce58a2b6d014e90ac8c901e10108f7ec71280b161385817c54011b2733ea3e1fc98639a0fd9d87f4e3121be6f623d936df6376f40eadc62bc80cba7e57a541ebbc033a75194d6a819a20be8b4e29b60bb6a099026162459f8218bc49af553d2bf3bdce1ed39610413241a4352503a16626ad7a445aa16036381acbfa7df1acef9d62f4a16537e6f14bc71c8ee819442ea9e699ca0cd97d90121cdbab4c8e1cb347081b23f6d9bda1654c94e8ab2ee6f72d1fb94fbf119ae9ec1eeb5c1b2a8c76f0ad41a6887b94517ed20d426e4489bfb058d8d57149b843c602f1abe8470e7127502f3298bcf40e47a37c46c6f164f8623297a80a2bb66b48044e77990e460cb6511824b33e26ab515b45b240e317305d571629bfe53ab6890dd8d73674a9ef2362996bf058ae409977bfafc39b13202612564dc0df745b682993a0c6637c38d9c624372ef5e2bb5df65e3ebd3ebe358970d623ffa4b611a9";
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
            hex"21e2b74381efe506d5387fd0ae8e35856fea3ecb600b6822dac3186c728b86931ae3535331d1d446fa7f7108984dcaf2cb6139e59783d197be81b7f2543b3bb115c9f938d5fb6df2aa4aac95141b30c0a0da9a4222474fa93b0c6a91509067b928f7c17c0956300cac2653f93dbbf9a5058a93d4aa34e654ae3d19da62b80f39251c372ee0029d4c23364c5abcd38f95da8425c718e78409fc848d0badb1d70c193776ed9c0ac30c4db4320016fc5f60d93b2c0bc318bf5ad6d9cebbb18e3dc90b3d1028342089f1e2d5ee890d98ec14bc3a504743bca2cffaa03855db3b7521053217d66e75f6567431a87dc0f1d99f78dfc0527932da819d53118c53f06f7c13a0dc096fde085301099214a9167e32872dd7f30d9ecf3da111e6c4c123fcd028ddbd33e81eddf0aa3c2168d67b01218885131c23f2aa5e6f8994033492ff860529e4b9dd6491963c7e5466563c8fdc5e32d64e803ece18b08c9a06433fe6b02148743521915afffb5a7e4da91d802305b2d3cd298b85240f9a74b4cb716fa019ccbdd9734825089e647355945d2b666ccf4ebb25ff7b8fb7961151182c8fef23045f6dbd6edb9f57c740ec7b3dad83a1ecc9433adbfa771bf9f2529aca5ffd07fa8627353264252f7940b24cbafb8a1381a087e379ae705f9fffbc0d5ec5a222c4b181c43eff12021888f2d911357abc616392e22f4f01122e24323057acc6035869752e3dc4b1b63744abb316181ad947c097bb1bc06f099f08d82ccc57741fc8854f2332efa11db14874ecef79d79294a114001fb29f152a6714b0493a762727ed3dae232b915f702f002cedcbe6605f65ab8cf90f25d8392b23699eb17e1edba5a53cbffca45365df032af4b82f8cd407d48de8469044417e7a4b4439301b33d38b74ec337e23ff4e3ab435c62dc2a13accaaae8e304d9975f104eb4c1b213a2d170f89c590c96ffa54f8e54c39406b2a441aad719099592b022e11a7e5240c88f2b1c56d71a790bcf2a172dc36734182368b2b8dae1eb5d2e9ec6a286e060d447bb44f09bc1e9c840ddec24271b6ec8a9d379d4215bc454a780b688fe3209c2de7a4516bea9d3aa3de5904dba28834a7d838fe23b583f3daa4bb52bcc310fd026abf485ad4a36c6a92f1abf9455baa369a24e4769a3f079236b620e2bc1eec0fe112a8d5bdf149a55a534e33d4603552ea7ba6047bb8d83899e24871f0247f54e63ed7eca688ab34727afba115bf5b65c2620acf747df7cc52419d3cad01368c47bc3c9e777ddacdcd56cdfcfcfc3f9319a6c03ff3a4eebc938bbfb4e02362ad6e1ccc953b7603979600b512ab6c60c51cf81b06e2766ce1cfb1772ad5111545976bd680c9b061ff398885c44c74578ba1c0448b37a82471671c60a8542c4ac6eba3274251e3d92302898a13e9bac95e22d81d7f9499f64881bbf8f603096275c6e1c6eacfd41ac0fb50858ab1b0cbe7845aecd7471aecdfc1ac396de528f7c299b93751d9f7355afc9f5423cd7cbf2b9bd1b79def19d863aa373bc266250bcb53efaf2e935ff04ff6041a4f35d1d9ea5e3c841763edbd742cf033cce10847a75d3dd2e6bbad6dccd23b7983790d78a68b6803928891e6b4d1d68d92d20c8347b3d7b3e3bfc579014f16076397966534b0793bc9b423e67face5a1e7dc2645d7e3c343304c9a5044543988fc391d4bcf6ac53ffb334a544a6c7a5624d80fa419a0cda0dcafb6d741a2db893c7d7bfe81dc978abc212ce01f981f0a61d3106e4d57d07e3673345cb7d4d33218b2cef04f4f9a5614b6361b75c907934ee80b7c007dd7bb3d2bf5386cd1c61898c275c262d639b02c1fcc452f13fd1da23309961f894c62180acbc830f1b5f6252073cb2f7a83b8fd51edb5f496dcf9ddb1129b27730f0775292230c423813c942b1e12c8e68874fd7f5a37511d0c59470b12c4eb8dc38dd59fa83581f6a10b15636197cf08b5d9ae8e35d9bf835872dbca2c877bbdaf1d222c7d0cc4fbc48cae04e87e69c301dde00d5c478a42ed2718c615e5bd7ab97ace8f9993c24a668cee4947311c34d428a0fb3ed35f6e91db55c12fa84daaa50a1b1c6e6b054f8a0e86eace17b6ef202cd27a65412a2e268f92bd2966a9d0b930293c8bae84a7ff0ad51f02e51c96e38eeda0534dea57b3be9ecf08e60437753938dd7ce16748956f60ffd9d56084ff2d1743dcecec7d469c2647131350f89bf656d54c14f5eaffea303efbc09b73321520d54599b99680b41398167d32248a79537869ff6da55cf29b2e47dd36e9b8201955447dce4edd346d3d228a52b7324f3ba8068ddd65141810a71f0ea054f6bdbf25ec8aa314f3a8595f0fc4c6d06574832c9f6e1be6dfafbb900ba9281c14742f26690615a481c579b313b5a4c47b7956bc4eafd237e42f2f2aaf49193a3ac1f104f7551e8f52645f43288b13613e86dd1a60ac913df9eb5195421106e49c4d6f6ba52ef97c2ee631f922007f0c95b0f09fe032f2d3e54c2415e42f21b6a622abc037c21b3b3027eeaf0cdf023e6e0d3ca70798c08d340353b152cab6662733e219d6dbdf56ae8c35c9051af5898d7b22f71159268cae5fdc55d7ebf828813892b01113b217b8dd82c82fd2c335dcf5d89df5a2a9c4095d277b1aa48327da181c6743aadc70ef247a711f28ffd165d7d23798a9064eeb3ab6fe91fe242afcbf846103c228c1ea88ae00017ee0d642de0e4b152c43067dd40b55ae060c5395fe845d96d1086f7369672a1439104e0115ea8849ffc57491eeb809f241dcc4a8f6f4eb6dc1ddb0ec4a205526f33fc5bf4dc6c57ed347e2a60964be367dad35bbef657944b2b2f2652ad98015aab116dd613d04014763dc42148c6d2e09b8e78adfad703b6426272494e2942e8159b341e50819346f26028756e96757df071d6fcccdc924668d6d99b1d1a0083a7073ab983bc5dff3b9a9d23c5504209439f47a3e3bc4b3a5f1a8aca20b3d28218fff78ff33eea1a95ac429b88f660e5ae7f1470e1cfae7e15b0570350bf0";

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
