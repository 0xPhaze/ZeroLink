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
            hex"0012b049d3a96abf0aa11baf08c301a55ecf3fa3950a68d39668bd325e2e96cf253352873c24e3bb2bc24689341f06cecc23f44eda1747a722ac1eb744f0330c058ab0d1c3ac51544e4fe664e71b649d75fb909fe8c9e1f58d3e7f0667e865d022db2c4f49238aaabe3284d32d11adcb3616abd93666f7ead67ec5d2f439b3381bcdb8a523ce02c8533db903576efc458202a5312d1052763e1a061a9cd8a84407f3c3f1625fca6c36b416abc8c5a4ff925d3f45f593dd51d92deb4cb7f88a87096d044c26e696fa5a30d317522b97771e1328f4e00a7c46c2d3c6dcbb3694e81dfdf166f78ad138fc4693a4e7b4611a7aa8361418bb6697e2002228cec3b9f81727ca27dc7cf98bb6b0fe45ea3e2fc414fa5601e40a0071baff60faee8983b81e359eb2e149e569abef8736299c5d14b9eb131730b0b79cffe1d6d022cd12e604feaabc35f2dd7c27dc2372dd18ad613e52e934d30ed61ba390e888e64bf75b0b9a3c8571de198781e02bd641ad9677590891c9d65c82588b793b2e2ee687a3220083f20ba82b1143d2f98e51bf7189b9dd0a241d08611d6b4e89236ba3064e07a9a3dfdf08b667e3c79acd05d8c4cda09c8c67c5a8221d8970038865e888740e4c48f6e4ccf398687cde90e8518eefaab4ceb3f842c7220c2a82e8913065b62a92874b3c754ec8ab7b3e801a2455c3be81fa38f986d1c02e6b5787e2437aaf046a07ff2ac1632766cd2dcbb77ff9bfd192fe63ba21e8fed7e7aed3e4e4fec32835bb942da46476650c6c3dcbf6fc1f619a1e2bb1263b9ecb17bb9296c0d2e1021eeb72fc792fdbf71e63f10695044bedbd5f005983c674baacc41ad92e61cf0cdde43b3c5469801feeb52574ef7e78972c01d27602d98e6be5c05a992aa1a11a1ec8364dbbfcb8935d0651a7a7f1b047a420b96d4386e47af6358f15b1fe941ff644b2dfea81d4d4368b0eaff260474368bad38b1ab70f262ca96555bf7ccf2f97553fac4c056eac2760eb8d5e94bcff44612ee782bf04c5aa9e8d4a19be58159b014b0251511ecd3e0b09f28c35cf038c728cc27d159cacea507e05b6568105298978d7393894fa4e34f3051131cf577aa1dca7773817882ca07132ff2fd31c804f9d218814f95ae07070ab3324719785bebf4b287859f643538d56c15e422949f98493d5d08a79b4aa422f8476fa191fbd5687b49745207458b2451a5bdb0a3f922a4228445cce2c9a88381433739905f0ca9450edcd9c3a8805a0df418c21108338e786b7dbe2fbd261d1cb90ab95ec94ebb8b130b5bdd3e5f16f13ebf91fa72b68b501ad3faaa49f01789d287f18cff0b7c3d96bc6c691b57d61c6909413a728396f5cc6f230a801b389476157fab9a7b2072f6da8e0c9dd266e6ff5d6005558adeccce91283f01424f70ae6778bd31c8b32ee0e35c6a150d968c09bb92dd48411f0d506319f226fd20da49dfdc41b03b96b11ead1b3e06c4466bf19d60b1486ea00b7c4bb3e807d6412de8353da6fd91e64fda195c72f06e771e26765118ed1c74be9e690a5a25b8ecea890613003a756bf42e0e7ffed0a3e3463055d262c8b17a52c634e469aa134947d98877aec91b7dd782a63fc12e84a0e80bb722821810fa582aa9165664282176160b089a8554605f2c9f28224d20bbd180fe918fe256780d09469e6a46f490c399a42f01904bfa55506606b538017a71f682f2686021ac12bac0d293a5240d50769b4690ae38fb64ecac44d728c02445bc91816e1f7af2c68d5e8b2d94e279c17894d1b8da8c86b724801e7dcff4356bda7d90175a03cd55cafa35be4a143fbf16ff0f465846b75c346277a909d13b111f8781ea55132e0b0629496949d0a935c285af9bc8c767a35c1727b3b1265da67dde827f92019118e0e011a8202f6c2f56e9472687669cb7576cda455a8e1e41d7ade07a9b25f0ef35fd3c51e62e394086f258bcdb6ffce060fef5496a52763b125d1122465cb3f0ec8ba203c70869e519b240e81b4001f67b039a66930b611fa25ef17b0452531b2365afef5ef6998449410ec645f71fe3080f0cc366a699887a36b136a2a1914b9842a5fa17c553960d066d10173d8fdb1c50911354576165c4e3c2a3fa4eca17b9fb80ce16999b9c304a55f686f42b45f7cac1cefdab7e615c33913264f1f07216ed2b5e9cde4fd1d8534c256673c0aad507633e835bec049de901a2923f5a48d70534b193882ae3e42d2119b63893fc1808718f381ab301371be0244de225b9d343620457e1b75d84710b3bbb31b2ec9d06127040926f4395b2d1f15141de7ac8de3d847bb64b0d9e23c53b7834fd08448006b66f388431b8d4f0923562666c752bc8a02d1854784f954a860eba7ac2646c3b0df2569380e5dea00beed7cb2541e41b8ba6a8d0aa8f9d0f2d7980843d03097c0a63cd121fa445d07ffb76405e5b513e17fdb6490e407b0863439d34470d57d4b9d5c5b4db4ff8030063b92478e6df7776d14ec0c2f910a1ffc32ec6325d5c2b3108a9b28599bc127370c0e512aa90ce61c9f4dc616d80bdcf2b63dfffdf7662fa83abfd7e4eaeb248a51c020f6b239913a904d185da464c95c8b3d44fdc84f18b1b47002e02e5f103db7c836174cc8fd2a3516c3547f03e15f9c40d07ff118fff5e4fa3d00b3b01ce9f393e0426df9422fdbe085023323e3a24ab07b496660fc4695a0c94801422e0277dd40c1f7fdb6ef4fc134a467b80fdb440f906a548f15c4e49f29118f6c1f9203793617abb9e6307d57a853288c8bf5ec7e7fa451304faed495dac8d9ab2b9e17802a228e2963da052cb61aa7f98b2782aee736fc5ff8d8882f33fa80cd2142cc2ae88b3305301cba80399947d8e8183342130a661708fe4999955d119b129f35c81fd5f30008f60b974b4f02efddbd4040aea1cf661ba1ac5e26e1e51025f8ee93c9ba2618552e50e22d44613c201f1030da366c7bc5edac401752521b0c680b774b234e2ffeac629ebfad67ff65bba27adc82470820a1d2606be4afc2";
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

        // Regenerate proof for alice's withdrawal.
        // Note: proof generation seems to be non-deterministic
        //       and depending on prover file path.
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
            hex"0df801ba32102eb20b60f51115fb0f219a4b8a0558cc9d2ecc25a06e486b3a270e1749ca3ffb60a71c8b2fdfee5806a0efbc4ef21c77518ccb251bf40eefcdab2d0301aeee254eeeefd18b600611e56b8485fb6e88b736d2310c41514883efc81d5d51e5db6c54bfd7ebe1114da13472580113906f9c052da5fee30b371d562208261c32601b61d6ccfe7110de9758db05e939b3468a5ae681dd1083c0df7ca4163f806e1be1512fee882808f41662f5545d1282638fafaabe8be7f722f1a15002113d24a48e6c7f87d0bbe4143d73e9f071aacb0f85524c1d777eebb1ea9a4504cbad878a02d79824cb124bc228ae4d7ca70c0b7ff6d03b88dc3892409d7ab30b351a38d79976db5877488b8384034857f16a5c7431fcbdc5ffa9d0485025630578fb55ba9e2bef1a1a8120c02a1530df269197c559e0810119017aa0285f640e748877c147dd484e562d769630fcd67bd54352e5c6a8d0585976e4b8a651d905d7c5a33d076c03346ce19f1c1e64b6634ade7b51b6960b1ac3de78e29b8d4707fade4534852338b3bf795854352de879936bc40388c407a6ec43a7f1757501269d749690b7af97175612e97f54e817079b597fe9d7dd03d0f7c3b1e23129e91ed041b32e7f00c78f75310c779076fae218a8fa765b81c5df81c94b98b56b9204792df9c87b3d84d6d170107bd3a9802bede13363b313358248c51b0d9d85f41725681c44c2307430aff911b6bd03abfad1489d222e4ee5517ebd0b4aa6682c205dd38fb3cd4f9571bb2e2051562be4bfb24f4caafb1668d3cda8c55af425632bddb6ae9413667e14871ed09599b5e26f287add2b75a30ef88934326fc23c052ebfdf15221839d8cdbdb5581058f13400cf58df9d6a04c6f8cd1e3c86a365781180741ce059e73862421666f26f90b81d3cf0d0753ca3dfca4312e858b5c671157bb822e0f683087f8d2109c60dc5ba61c60fec7012030d143089e5c4397c7e219d590ab47da885b43dec7be054feaaeb4e11ca4764c0bab8879c3da83a01fc0434a0acf3f1e281d5a93eba7e7331e3e6f5890118d919912a1ae3e6710b6190150b31faac98dbe3f534e402148272a799889d192b6f84c568cc7ad03b5afcfa17e4ad472ee1bea943ca7bd0439db8b6d8f906dcd376dc0349be8a563216420f1df8604c80d71597f2789db4b93c22a10a92dd28f3430f9a8c01e9e4971a10870ea5458a5ff25626962a590bcaba9267b006394b3bd135ab3b011a00e17b6922051fb6fc101634274a6ff1be78b9442bea2b960847d9aeaeabc18b0f438b1e8d0d121ffbba155aa35b411a7982e25ef657866b385c14dd7599cd34d7a497907d0136cb08c3d2f1f87d06ea7aff09a2fbac7fca14eb0f58c401436211ce9abd64187eb0ae4537fb455f29badb7b6834ad5531029e51b75321210cc2c47a2d82901621c38a73b541acb0ea7745b625e06b2ff79f6932b84d0df355b908a3f1749521764a7601f9862dfb58e5248bb219d6ff3e8dad770e9e0f3168f7aab76ad6dd14a1236be9ec1a6452432767ac3b025731a8834dd328f7da5bde394d8101e03d1da0fcf142ac0b28441a046e163d7ce77da6cc6ffb8ec6463b8f6586559d4c9d2381dbf97d6c01f74fe73fd751e7c78240670f68c8e8ab7ffe9a6982a4bbf7a21404640d81b50eaa11b102982ae395cd03ad56c212244235fe0456dd1d6a5ffa265f33fc6967f0591834c4c977446e91117c91619210c46c69c1eb4370af154f2f82e7e4e1140f5cbbf0fa2779b2c3211e1bb47ae0bbb52f45db54c60771b24c0fc2028d9faf3b4c15bb039d1fe45fe23db6bebe797bf36aa135027102454e140d6b161258f616b44969c91f2ef7e22782020925f4141d7b28c6cda7e691e6f92e2edf7fc027085b9db9ab5695743c014570f60b9bc679acc9daa5d162d035580333120e650c5303a1f12d98ccadc8f8e6d92b60421133099262cdf8da60df8221579e685c802df1e9732f8d2c2aa777cc5089438ed9cdf4a4d6681ff64a4915225f335230b9282b668fb83552882e58d261a9c629bd9187f172596b1c7db5f406d90843ffe4003210f5352209a04f400a0dc9c157dc9204144bf70ea3071c1f2276cea2c70caa4a22448795a022157b5adf12a672927b840597f559195438e91a6f485c0472d4e5abf336850eb0596dfeb146e473475b6533a5becdbc9ff252136d26be91056919419c5417616830399c5a050a658f17e80743cf6eb3cc1dc90a6575393035fd7b0577af2978a16dcf04047e29a18238bca6c68c6fabc446451e64c692c5bec584c4db454825b0de93781117a6ad8e5d4abab4358d8fcb7e5a07921e2c5feeb3c8ff5120b8a9801d8e3b4a19f8888211296a1c58454ac36dd91310737d18eb003f962c2848a6b396e0f339108d4267e1656cd7b706ffc3507b0ffde49cdaa6a6d15004b11ef24f8bb89fcb49f530b86a9c352df0e163540898152f546f15375355e08aeab7281935faacbe4001080f4d35e6db534ce560087c1f8a1916b7b6dcf4982528baf16545c6de14fb24ada5c1604e39ca982f6f14911a7f7bc5fcf6a7516b279050bbafd81972e235981e9051ab78811c7a3381ec2c0b05c2e66b47d6151aa77d9c351ebee439f2002b93bb56f926fb386dcc46b4c510925d0f4b1aeed5466fa4dfe8a4b3496e78c1b6ddf42f710bdbd48e6e00ab870240fff98c6137b4b40152a2d3f070d0a514367f94591b1f306dd1ebe82de81c0c42199fa6edd1ec117c21cf6b2c6c138833e98853db52e9077daffbd832ee930279c29862296284edc621b44871bece5c3b27ebc792de89f603085dd6ce778d0151102f7463d2a33d22e0e1253c443601a62657caffe6bfb1d15f2d5d895daa0ba3dd1290e98bc730028fd878f1b2b805bba781258e25b6265f228c1f783caa09a0fa05fc6aae8ec77daf253c7b870846fed54a977398729172561f713a5ced2773415c781a7f8f603420636bcefbece69e550f29183d4b7dc94af7640952e4";

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
