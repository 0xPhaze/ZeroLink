// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2 as console} from "forge-std/Test.sol";

import {NoirTestBase} from "./utils/NoirTestBase.sol";

import {BaseUltraVerifier} from "../circuits/contract/ZeroLink/plonk_vk.sol";
import {MerkleLib, DEPTH} from "../src/utils/MerkleLib.sol";
import {NoirUtils} from "../src/utils/NoirUtils.sol";
import {ZeroLink} from "../src/ZeroLink.sol";

/// @notice ZeroLink tests
contract ZeroLinkTest is NoirTestBase {
    ZeroLink zerolink = new ZeroLink();

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
            hex"1b94b0fdbb0d801b6bac7e2de2c4383fa336a1eaac4f2a787d18d4adb48c77160852dcc46028500ddc623867669145a6273f69929dc8f4d801a5c7785df31f0a02ae72520b2cb0a03cdbf43b484a008cbb651cbdb2cc8a348d9bd586010474462b4b2f62442a6755b3176c725a09de48a3f23cb892c41f230463df6189ecc28b11d16694c20e0b5147ad4909bed6ee9a3342adcacbae6b9a31bd6c76e187334620928f63574c28b98a0f3b292d7b9505b98ea6731728dd87371536fd743ab84623dd17e2c1b918299c3f5a3419fa22b80b8c2ee8c5562a6b842a586f2e8d08e417cd32f397987efe34fc372cca66745dab48439d0fd2bef7a085343ba45bba5605c1a9d1c0876ca2b44fd81c5142e6a82856eb4b57a5dc7a9ae3d488249612982d9f192d42b4485cf37368d3667d49c6a7736c206a964d05fa238f4f3041a55d2a6d141c29ed71a3515fb203b2fe53db61dfd308639276c3915dbfc3cfcfed7a276e2a9f7ead3bb11e134ba83642bbabe39fcdf8406307295aaae8636049732405615a9e39118f3c8e4547697be290bbf62d8dfce6674a60f1470ee07e9d2af005bb39ce820c1dfffaf682b75db2456ccf166defc9b4a138e516fa99048d5ada0036541dd1d7b78d693fe9baa362e121640d5f2b1f60ade79ddecf5357b695eb092b647ab03089a9cd1184e6e65ede9eb07c27d9d4d226272de7b99a369a78760f96e3ada27760fe16e2e2a8ca3ac056e2e8e3b3e6e4cc9bd5cb10e233b8d4f7280ea29864470e2b422dd123cc74028829c257b222a898efc955ff8abc7b5bdd12026f8977bebafaa82be0590a670dc42b70bcf9f9f1324d4ea066c6917209d30b20e2e6e317c720503963a8624e2179b63356be9dadf1ff16535d54e5207c2018257d01dfd2964e36ed5a815859c104cf72cdd7c3a1e4bfa805e635f3e2f8762f52d9cfe2b9be8c1c1f3798e47941100622d295152e6ce805eded2a95775ac62f32550606656970eb1642675fb0ebc7969126b72403233fe23336cce7dd9d6a03ce59261fd5ac046cafac1aa8d29f9472932aa727bf935e1f4efb2ef1307cff04f3d143d344571a1eab6f065c6c101af32d9707ec14e69f46c0e6d52ad879340f68b001384d3de1303beb055c645bb84ef3fd7383cea52d40d126b6915675360af489a8e24d055bcaf507ac3f2292a0bacedbb507e6b3f9fb31eeadadfd0c9010d632440b290671bd839543071007a83d6042af54bae1b93eff432ad25e436412bf53fe93e33c1fcc1bcf60805a32d4134f14da07be7b611297decc5c2a822d141be7d4e09c6ce0ef97ce63a0fcb0e088eba35d568f4e0f33de5b0ab5fd96a21643a5a595574a8b02f929575172bd76dfa876c3e881570eaf43d18a0b7705c20911b643fdc691811652a8d94a66ea4d94d712d6cc2fc842b91d31eb5f3b83eb1bc9a9e92bda3c4434b88cddbe92e034deec80fe5d5be39acf50a9bd2e60950518421442b28f262e67cf1fa2dbbc2799483be08fa43e7c7e184ce89c37389e4b1272a34fe2ae07a8c70b64aeff6655d0bb7deb71d8d1c2de8d8dfdd3016dc2f9118c0e7951dc49464b23c82520e7d84860dc19d5ff4dc91bd025db2be47bb3a404ca0394f9ac903f20c08d58a7c2f00863c366782b5439c2e72a3e999dd61c06117c57a4512e8a5172ecb0715d1ba420ba48cd594f2d1d1f950803d1cd90df871e2eabb3a8b08463c518d38a1274583910ce343a7306007c42e5c909fd4ba308293b4960bd29a95cc37427a5e15f552a0ab6d3e1d3e1cf8abdf7878409e36ada15dd7ecb596417b0963d6eaeeef509d7ca046c2ba189443fa91d1dc5857236d627c057804a2d089023b542b10f3b6925e0ea25445d2ba4e01aeca0260184f0e22dc7414d91d52dcaf64218236c14be25f9b99617d71f0357247d8eca8b58d6ad072f055f7682d85eb120d404fba4680c95a519b440fe56a45abf5de66cc12a0913e1596ece04d271034cf71db0fd1c24ec2a809564d73a01089d231e9c7bed8a2093ad7e2586cc8355791a366655d03d42afe77688b01d5db67ae856cc36b10b2d46018d7d08c695a7a53d4f1bae845599354e57ac8900ba6458ad8efbf1748c2ae0ffc300327e761744f6a2c7cd0c5167539b1b96dee3d8f0c38e422d0666892b1bb634faef16b60177fbc66ecc7aa12b0ea95a8e3d1b40ace996f30d11bbd82f30ef90da60d88a197a20eb66b15405ff0ccac739db8223497f51f2c1dc1992070f371c1500d26fbe26c377f2f8d4963c8adb291dd4abc69c577cf40d9df6d907c8aaafac85da6eb9fe4968c08c8858157dfcfc9f1846f4cb247509873e610b09cbef830b6f5e272a0466d343ec89c988b848141a8c06aac271744bd76c609a2bc11db3372075b6c508c6348aa6b192a1df999d5330ce1b3d8f9a6c47b03a0f0693e7be29de57ca009fdd03b11f9d2fd06a974b6361fa1e583582e36bea99cb29890630a11aafc053624ecb2a46296b54e2e4aa98c675f8e740d9f9ed549aaa000849c9fbe45e3e6c76fb1bda3ee3a4e16ea054a9475e13f525d9dca08187d91eda0b354cad6e1883fffc6a97fb3ae2629955580001ba4a672e8a9f7d24fbe0044e73b6ed0dbef42ad5d5db753205cb9b4814c334d35707b0fb9e6ff20ee8ce126a96bd72e04e008c7abffc912f9f9840bf34734a31d079ef33dd5f1d08c6bc13f378a291c85480982fa5519d48ece4f0cf237ce5b5f72ec322da7c5f742ca1157c5a87b0b05b00a3e48aa6a9623a31a0df1286813a1de39711d799a1df928617053c6ccf986180af996ffbb57b877e50ef01901cbe44986b00d4b6e44af86b240e20ccb2ed26ffc138d6b440779117a2741354b3c8c7d256c2acf43ed2235d240b8248c4d570a2ed1e41048599728c1862f9839d95f762f8a39b4ca0a5c4f60b69227ae4974258fc1a84ad8319c1a1bbbf36f309de1a80cd3531540c33ed8123e2449f54774f939521463dfee1ee7d43f9ac112555de131856f88ec9ddd857";
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
            hex"2fcd0901459e870ba9e381f2dbc28668523761a58f2a24c2efae2e88683976fb072348787a9bcfbd8a72eb8fa59808cac0abed2212177214b8c3e78e17d994b01a37a4c921b5c7f416a662ed1887ace3e60a5c66f49334f78c818176a5cb46d10857bf059fb5aec597d4b6cbdecd8f09342505bbcf7295a1e564f731066abcb1185879285a4f3416d48326412db0935e5a66e8a358594f3dccb9024829c077d62ded124dfccd4622e29d1762a9c09cd4ffa32d2c3dce70f097e90cba39dbca122cdab7bd71488f4f9065c9a9d4cec0de723f7f68372de0a8e67138fa3009f00203163a76b18cd82bb0e8dcb991c81837a378992bf960892fd29341ba857ffc6f0b125d999db55a0f025c99292b06ef3a754074c7a3443476f0828e4f521c72bd25bf1297edb2a9c5d2d64a101e86e322130942e8d9dd29989cc62c8f855946af2c6c02aef411500c7e6857d10fc61ebd3c389ae87ee2b5799064738df2cffd4007f57638e80adc9c350ccab18a63ee236f86b0b7928d253011406be7c3741f1f0fd97e95e89cabdacf52fde1ae6f512fbc0e44c199ac4e201379ab4ab9c8ced00b5effa41fa8427a4ce9c2278616ce60d817748e1571ff7d7d26fcdddbe3fcdc20833a3d99f8c9a10f9bd34b2696c366debffa65030005876f01b5d2e7178da72d5853c75d50ab4255764ad89887035b70dcac879ca94f79c752e13404108b981a746234d2bf8e788fdb4b3f535184ec2f3ef67288c997b7031e1e30a61245b70d3590731ba53a4148fd19fab32158bfd0e2897c4436939db71840438eb967da00733e36707a74cc3b8b36f35b05fa1d4100fa7cb0c0b9aac20b79bcc4ac00582b3a61b0dd5d2264912d6fd4a8d1f5a5c50d2cc24d7280d845375ddf32fb1ba522d668c1c54e0acb0471535716e714604e9531ba087fbc946c8a6e0f658f77780af01bcfdc914fe35d87adefe890009c04bfdf543ad3e6f9ea24bf94c6b63d5619fc6282f04349cb7cf017c71668e4afac4f459ac380fdc8307eee68fa7a2af3039197a48ea908b5a942ba036435d8bf8c679203b37d5cb305eb9d4b5ebb3381229ab10f13895b8ffaee215f5dff84cea42a30f8faf741b2d02cb4264d00411321c7f5fd5c09aab093fc6892a8d250362d992be3cff3821ee5a54a966e2c9e140f2ae5f83d5f44e843f4e893ac5fc0e2e9f4c810610d0cc30ddaa9dadb94a4b80885a6e959ef49424577bf7395c38636275b0b42e8c8f07bafdfc52254d07e3a2eb95534b8fb18c975b6423a85f5a03baca5f7608bbae853fb7d410189b3e1a108b382c73f2de9c56c89f9bd5e42210f653b2c864ae1e5ad6ae9029ec26e422d23154ccf40e4efee1a01a399798b8be36e3eadf3fcda2f1da2f2aa75d18ebdbd2faf1d137f0634007882101bb355d43abc97187164ed8cae4471159df460c5a40af2c5fa207d27709df581c96832cf08f16aa83e2db81ba14f176f107ecc012c1f4658b37965f7e4cd0cf963216a9871089cc88e6760e74a4f0e8ceaac3dc33103d85df184a0e1713deb3f91c102ed526b5f0ea573ab0f04a83af64427ab171e21b05e494261def2dde161ee550fa0d26e4ed04d6aab73d24a819882854d734f2edbe6ef6c1d4a074d7cdb863699f99f5cb0d08338c66fe296b5e2789e6556e6106c28f730bbbb28ecf042ae1c4c368d6a1ffc5d44942971f6a32698be3201c22260b971d68bcc7444b3ef8c837fcbd89fc3107fca1b53929a72604ccdfeac9f2980be6eec1b5f67acf746e995c3091f9bdf1f21a162e0de3e48317ed469a0f91f179e7bbf86c2ed0ffe7c0b4faaa162f2ba40e085a4097688ff8a1a0db8b75402c5205b7e2a9e22268d3ea6fb787a5edfa9553ff770ad369879ac44901631111587fff98a7cb3b3e5df045d156221e0a712deee93f45e9324abef033ca40be615e58bf440fa4ee13beb0392d0659e11e2d5507c5b7037429e2ede20fd98025827da1c6ee6ca602c93aeb0713799335d1878649ee0f7616341fe17d50d64ad35096a5e76ab68d14e332217991d4b704b25e79078ecc51af2a1eb5bf52d3158111b5eeef15138e2998ae5c477847f05965b8aa49b724c451345ba95a93cfe02ee03f0fb799b2a3d95e42756b4693208c6ad323c59d5e90d21fa5fa46cedcb577b1adcd48a5c90c9b2a8da353c9ff81e236ebef0045dd7cb6d74c95f720deb31d01500a38ef28b1ee29acf462dfe5c498e36a5ae60b06ee3ac7b63b5eeb9831825071fbc1a452ea1677b657dbeac5a4d59ae270b195c2255b18187ab522f41e14f0d2b99562eb552540cde1bb887bc04287006a7909af555f2899137c0edf02409109886672702802fe33f1668c5bd25de14b8fe8351c1adacd50a6c4e652260d0291bda890b73d75a9ddb19f876f9648c480df516af84dfe79ac49f0f8eb37a8b0129b38b27e2085efbad9ea2f4b2527bfbb387dca255579059a63325cf7596bc1e23f080e06422de10c57fdb1025549048b3212d4426371d5800d2cc7e0c670b1312495c1dbd5d7a25f56f8591c4ff0c33ef4ef5d8ce7618a0f72e0becffe99415d241cb434ba4a42f8ac164c1af89c79a59bc9a2d8579d5598522b756e6263b211d26aeb2db69ba32459e938e2955a05ef0188bbfc0074fd0e332db1e3d796e17a98b2440e363444bd813e62d7f6a51aca3a08c12d04929e12ea03e013eb0c125bb6a5953ed68e9c03e26fc51aa5e9a6fbe3d5488255611af95aafd7d593f7c0368fb1b85c5ce657c53f45bf453fa860aa4f1d483c0f2683a1ac0290973ce36117ada5098cfd40af0ba0772187eeececdbf8e9cf915ff500881cae8858e5cf11ff566f32b7f0640544d08f0a3d9eef2fd0b58ce128f6e4d3679ea64a6cf4d6829e56dc781368e4f7199ef6e7e48449a5fd514391f4fd170434f8d80d7c59a8e2ecf46bedd7bcbd3276c724ff4db9ea8114619f54e74963b2f4914e58520aaa01fd65c8fc065a487cab8a64025c44799cb39be942fecf9cbe1e8a53f93e13917";

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
        zerolink.proveAssociation(nullifier, root, proof);

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
        zerolink.proveAssociation(nullifier, aspRoot, proof);

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
        zerolink.proveAssociation(nullifier, aspRoot, proof); //
    }
}
