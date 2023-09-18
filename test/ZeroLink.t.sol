// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2 as console} from "forge-std/Test.sol";

import {ZeroLink} from "../src/ZeroLink.sol";
import {NoirUtils} from "../src/NoirUtils.sol";
import {MerkleLib, DEPTH} from "../src/MerkleLib.sol";
import {BaseUltraVerifier} from "../circuits/contract/ZeroLink/plonk_vk.sol";

import {NoirTestBase} from "./utils/NoirTestBase.sol";
import {NoirUtils} from "../src/NoirUtils.sol";

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
            hex"09011fdb50192f4ea6f2a85f43ff882d14fc478ebfcfeb2e861e1461b5a4659e12bd92686e48f07da7f0bf73bd3dde83515ed1281dcd01d405814658d17aea2200a0551ac0ac7e5c9a410693f78265c113b816ffe882c1a4c5525b7fa5b30cbc0c47ce769b63fe3d3cf7bb1af6eb3b27bafdebe699df3d9c1d7507139d5a94081e18beda14954d8b6bcc3b49e24cdd3c8146295cfd61c5d266cb858bb618944e139442a901dabf6d15c7f18131c4b6b1f8b804cb242121d2ea9dca710924512a15552042b1026edd6377b8bb4061a3ede33d7828ae89dbd7b70895d77cc6cf88106f1a826298a025aabe46662a9aed0edf0b3a2d70f4aac0897300515dd22d691b63cf22b278740a636d7e48cd8acc343fb05c0f54b5ffe8fcfed21247cff17400402aebd59335cc041722413197ff9dc69a54839946bdf1e4c82044b254d6e712570f3d8d19325ca666ce638b79eae4770c434d71900616518293edd16effe41b581bacb2580b6ee951d125a2acd6e6c9277fc47d558839d213fdb81a146edf2ac10928be35aeb59fd64ad8f8d8be0f49838319fab58b991b1a904c1c4680b607ef63d2faf73efa58f01aa59aa53f1a1e4fbe7147cfd14209ff4c6850b6a5c80929995033d499cdcdae2ae4d3550d3f5ad4e1fb8f915f907ab7f392f6fa9cd112cd09a4cc7bbabd41a8c31c3a01bee78c9e0a14bdd15ccdba5d958bb55cfab81147c04e67c298109624bc34760da198665c7ef0bbe1a7790d4416c786b6d03121033b2085db79377cf3b29eeb6d4647abc939c2d0a29776e79055fce5de07ad2a2ca68e105083d617d7199c96258373944d488b2db94306b95684a7a1ccfff92de899d15f7f735f0f9d50ae795cbe1a89abb90133bd84ed714a88e058bcced8220ff0ecebde0349777f00cd4fababba3f3ef750bffa3763df0ad38447b5704901bbfa89957c6567f04c729c8cc05c790f6c1e8338fa4da4d814e1d6ae7acfc722f0be500485edff1b8bf8536927c27cf13873f172137ac795338799d9f3f7b30901904569231127d08d9faf453d7d06aa4f4048e2c35ebcbbab4e0ca7caff6b0d67007a6a29a0d80b422c40e99b8266f3b39410c69875496b11965591003d272aa9b43790c80eda98bd70b2d55feec1304a0c247f9b4988c5aa66b190888c0107f6fc541a23002e7c7b3ab7e25334836b37624ef98a331389ccfeb83c0028bb24098e318d7d3ddd6a6b0470cb0814abad96a6a007caf053dd5a09accbdc79e5217a564fd3882ee438b70efa3e4b4a5c97c4e344ed2054d06ce68640a5c5e09d1b1bc2e3f012fe17f18d60f130536ce5092b42d770ca23c86916950754499af90747d4bd707253759c444bbb7669e0bc5c0d867ae39d6fd51749dd73c12b072d08149037e183777694fc0a89bc84695928e3d209dd0ebad8c6fcefc701208afb1feeca91955d88f22c238bc59b2d826ffb7f8dedb129cf21d0507b012376c90227c7111b3b2fcacfa0d325be9394035749f5d4f81806d9dfd32156130e94e6f42186c658c8d0eda86163cd78539d4a59384e2b757e49148d6a10afe72bc99fc007580a4552ba541f44861d2cb85c34ae53c05912d911f6fcc7e43ba50ec8abc90e79afa5fa89ef2c7a8a8e20163605d085ea8cd1e344d102e5e53a5a4ce0199d2fe62fda600c4d6b423551a868c443a7f93f54e489beb6b2b878b881b5322d8304d4587fc26a441491404de82bca810825a0aeee5836e8a7174ed76df5c5f9ad05c8159e30a1714329df916dabf13dd820d86beab25ed756d50a64a242676f441b47dfeabd39d6dd9e1604fb0f7d8902a4b5494ebedb644c65284abc92201e9111d99ccf627a8f80e8b696f8db20714ac02d8f7b73e49eebfc88f4d8432818ad152a64227b9c43ee11daaee9dd04c63c7414078a38ab686da7468bac4cb563190f7946b0498971ba9ff6d1d4b4d9ac82cecb3392e89a2db25cbf006e56ed920314cbbdc88d19088da75213caf9614240236075e530cbd037ff7714ee87815e2e1a1e34e0d0a89f60aead55c13de8d7fd77f5b83778fd72bda22f296eb8152a591f70abf914383633b60897b782706dbacc8afa89c12f154344e73deee8a8f6840a26cf9805f9dae7989b8fde705216c57a35f140a0688b2cba06ebee2659c5d8194d4248d3ff687a8f60bd58151feaa01267c1353d9d5e498c9e03983e45f6842b6fef3a7e10fcd522c8735daa1b3337394cc558f850e01374964319ac9dded71ab81eb332b6eafbcc8afa2bf3537b447b667f9931f263b1d899062e32735ee72b8dc0f5e5d8d6ff6b3275c2b66510fd54478456b38e0bbe3c1cb39cdac81c20122414cdd7b3c23317535eeaf76804cd06e61790dc41b766e7b5acc2336a1b6926c7bad0880ffdc222d26d0b0f4b623a7f55fae1cd28ec97e14c12c1fd602c0e084e2600b0449a9a4aeef866482b4dd2acc9845d9b9c20f19012a060ba0f262907635feb36a3b4c35b253db0d31e0a4e1687006dc1e1c8b208c1d57f41d980161dad0e8d44ea008c7299a91df8600615e31cbb8ab68c9eb34c362d118574554e13b7641a45c48fb8562748a52cb417b0485f35f9920fb6ad57bf80808be030011b22c85700214d5c049e66402f6ca4bb705aa1a5266347ed21a3ed5e1809902f0ee344dc59987df451cb5498d5e7f69299f52f21608ebadfba05fc6d09cb5ece183197ac86982324f75451eea7fb8483ad7cef1ae78edd353f817a641d46fc0a217fea7cb397c8559cdd4f447a0f1274c104af146e8eff8ac4fcf85b30c299462ace3d4ce0976d8642664c9a4c22a065d48c6f0df58f21e04a787652443e3682087920b0778577b7d688335e6c71870b84d8b43d390c7535b35ba6a23a9dc7450d406d1039ee3108d99e08c4fd88c9209cc117a3c4cc39db914f594d4e12986e15d8cfa7cb179650b645306c8475be2ce73ded42065398cf4839aaea8860f2481c7d15a5603824d2bc3ca0a1bffae6352e8aed6d1870323fb266dd5e9b1351f4";
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

        // Regenerate proof for alice's withdrawal.
        // Note: proof generation seems to be non-deterministic
        //       and depending on prover file path.
        // proof = generateProof(alice, key, nullifier, secret, proofNodes, root, ".tmp.toml");
        proof =
            hex"0a050c4cb133b3e3ec9d48b4bc5bcb6a1179d2b8b60db6f0f1abdc410356815207d0d47cadb33bce4b1c3edb3273d529b667eeda5deba92ecb9e006b54c2d2da1d92f2855ef4744f961dba4f368701b4d306842e71c6defe36786700fa88201c124e9a841171e5a1dbc0445361164da6e51b90b8c74bb84454e61b5262f696b808f240a86d663a0eeb2fca0ce65edd6e0561d000df53c7dd28d26de30ea10a642235d444278fdddedea0b752ed25e34edf1132cdc25ac59d51bf2455ab9504532b2b5b679f94d3f07b628c6118bd2983c4d67b92ddd610bb4dcb4830a8987f930444f1d621cdf5320a8359cb9662e63cdda520ca2cc4dbef5ec4bc1f1d4d553c0462fb16cb65e6df063b1ad0ec21af4d0de97d601f85f98325170091a3ea11ec0a8ea215859d70b9a74caf34fa9f3ff1d9d77bbe9c4e34a53e8683f02f5cf48922a2d181001e0b71d9b6663cb349519a35ad2627c107c913c736f0b132575499057e39bb48d3a4f76b181e9b4384c810761875892a05cfa64345b24995910df00894d42f4981328cf8263ef903466b725bb34f3b12c7384292b3158bb1a9c8160ce2330f3832bcba4127455c342e40fb777d6e67d35ce3eb2b3b0f10b1cb7cb51bd8ee4a2533646964fa5d1fc1a992662d69f4afe836ba069e802128991788080fa05a9408e66608b28b75ccd473e6604844b8d947863f4872d72dede497c71f1ff037ca58a165a30b24c6cda6a1e29727089bb251e91ee4cf992848b7644e0f0226b5e68a7437644196c92737f55d17f1d616163962982d6115d9846d320f470521afe73cdeb1755479de411b9dd12d8f28670f553c584a6efc39817834af370c1968d9ec3c1b6bc98fb59ed136dabe2f1af5c28bebe1e682deb2d3aeb58176190de318b0bdb9543693791db0b208d16b0427f18754253b6121a83977582b1e077f04030df8cbe1b6c354ed2f6b32bea2efe58bc816b8ef3032c0ec0789e7390dde5c5fc39588a0959b8eb93c1507387356845f5ca60811fd3d68e0075d11b30cae23c7d7850c54be182cb5fe9dfa47d2829bdc222ce797542676dd1f0e1bdd1a4fa33265b71ca81d08b25969b2eaf22c6c5823eefa021a48278dc654b3abe8283a0ce05f2aee02f337a890194a4ffbae312133f0e27ea7d139c9d0aa4790582f43049aff137427d0c789470a105b305ba01ef2f3907e628ba9e4c19b2a682f06f4c958ed6823c3309e8c29c7925c4541abf93f0b9a74dcc85f41d91a182fbe076b44b793fe111bb8043a80f8243875e2ad88a2b41dab38b327fcd6e3d2fd6726584f4b857eece39bf355efa54937dcb6b66ad59b6acafb956562d88cda796d0b185236ef4dd311d0bdb2cb2bc13c7845a0235de006f1a280f349cc785815940531b18d9d94a76112f0457d735b64c1a48e65ba0bfb8ac9b799d6ef1756375a13f3c327fcc873e83ebce6900a2496c2f0e5d7b84a0a1727e4965a5b7b148b7b2f921428e529f6f0b00dbb7406bec24312ad725215cae9f18370dbf7582d14352e91d46f4b22efa2c13d9f290081f6fa8e168a41da93e764a35f490230fda95405b8a581737f770bb790c230bde45ac050668fdd2878e25304eaa0235c766a4710705d0e016ac7dbc1ecfd7ff062c4e81e296cd83b87637d2903f1879427c7e905bb7d828a93ddc781f336fcce7635f5d53ecf7032326a7334f08cbf409ed1382140efed4ff8c12dbde58045663cfb44e6d467887b662697d24febedcd223dcd2350c97769addc174eb64922ce687a8682c19b97c85c21685436b1b76688965e07de15a148ea7c2ae024bf62a83f3f10f23e74076bec6804c0eb8ca3ea8f45de039e08937711c37657226250c1b892640d80ab26c733654284da2da4ab5a9b89191cd56427781f6fa7d7102219695e880287505b37ce24d9888af61f9fe0cb7827e7864ff990e7d07d79cd2014492d85e1cbaf7094142e4fc92cb4b6f62916f61308aa47ddc42b0d011bd0b22a8e9a77cb2d5f40638e79e322aa1e5192ac838a2e8e1cb2a3290e733d0e19fac2555fc6dcc2f758acc23607c0097d801f2ff01f19af40aa875c51afc0b01d8cd89accb8c624a7287c3c819b1986e71abbb35cb30c6213e5342c046a418783d77c826836d03617584ae0722b2bcd558869a5aa6114fcbbbca02d99272d3a84f6aee15f1323eaf1cceb1250a5845f679ced5c2a4e18e4713b3f649d7842d4e5e50f7bbe5f39d53c77c08c11f1711e3e12a8360db5150d8a7340a0304caefca9c45bcaec0e286b8f60fb791b66ff195817d31e3b3c2bf95f339f578032ad8a7228c9c6241018261ad37a76e1ba03cf6165eb30e69f099887da9b6db75605070ad2771d83f9172f38a1cde1927203e99acc589c31b60874efb202d7db1c1dfc08a76333b121dac635a15af18f4a50713a59f884b17e12316d2cd380b595476d1f083bb6892c472a5df4092d3aaf3f2a15739c7365210d44508bf32aaad3ba0dcd33fc1dd83314ff1e888ecfd17d70627dfd60040acd15e49424690c5896d699c911d7ab97a4480df84d2abf1d7da551ed68507808d52dcf32cd0db587a36de52f74646922f34bb2f90da80b10501db27326cbc99c990643c01cccd060b9d3d791cef98cc71d7be8c30cb40bfc12fff9d0bda16dcf53221d48baa5e694fc69a5e9d762d31daacfc05a3493a150d02fc8dfe588f880a520ecb2eb4ba0540df86d0cda204498c69db6b9084074a38018c6c8c1ab0d36081fbc1d1bf15a131f87342fdcddb613e26bad17dbed47f63001c4b19dcd21eb6b1e8b874c9713d23115fb52df9b278efe39a376af9a1b48dfeac29a79ef36a0ce1d725f4dcaf90633687e1d3eebc90c6cb6dda3bea495a85550deb116cc986496034ed277efce788eef61fcac7ecdab3d0e0022f9def54c456ac6577a6ea4311d2d2c9905be154a01450cedb315afe6bf6e6f3319b570d628f92f521fa860f1ad03a2c792aafbcb95bbb83e2b6e98d2038bde614173fb738007bc0957b94ce393";

        vm.prank(alice);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        assertEq(root, zerolink.root());

        vm.prank(alice);
        zerolink.withdraw(nullifier, root, proof);

        bytes32 leaf_1 = nullifierSecretHash;

        // Set up bob's proof data.
        key = 1;
        nullifier = hex"00abcd";
        secret = hex"1234";
        nullifierSecretHash = MerkleLib.hash(nullifier, secret);
        (root, nodes) = MerkleLib.appendLeaf(key, nullifierSecretHash, nodes);

        // Set up proof nodes.
        (, proofNodes) = MerkleLib.getEmptyTree();
        proofNodes[0] = leaf_1;

        assertEq(MerkleLib.computeRoot(key, nullifierSecretHash, proofNodes), root);

        // proof = generateProof(bob, key, nullifier, secret, proofNodes, root, ".tmp.toml");
        proof =
            hex"068e204d21521eba70753c5704e2fef7ccfa65e9e5e2dce18dadc3156323e1bf2224ef2737607c4377e317bc049e62c94e1a5092fda17a240958f906a872e67309c1182966b4816507765b65ee9744893335edd5bcca63df368e8c5997b1c0bc0be8303e5184423323ea95249272a5a81034ad03889af82d4d7e13c94d83662c2a790291d24288f312028434489a2f9c0467739b571a473216dfc07e11824b87012abe73ec0dbad3c7b197811339b31c925185d8880663ebb04faa7460101eaa05f49e6667d807f71dd1bde06ee853f1755243cda5f32039cc4db1b302177d94217e8904b2d5bccb255f3dc454e878232ff5a30343ca1f2dbbd699669c111e4b1588fc27ed1d72892576e1f90b18df930c78a88a29063ff7713b259a20e298b02139b70a9b1aca7e6c574c11b3cc24a16d5366faab8fd4c12f29640eaa51214d1e2c1d1eb2ed82630d3b22edfadd7403c44730ebfd72bd5dde40718203d56afc2ad0fb2102c6a1d4243bdbd2e63438fc770ca2e8ff60a2ee7ac944b63eee20c10d8897a28c6eeab1ca08c743702f360bb53218035f01114295dca2651a6937412ce2b616675d1c11f6c084d4d831a86497964837a66921c1651c4fbcc146ec451f906cf633919654c197019b7e9b37d780f63faa2bc5bec0e18cce495c084fe50651e8d095c6a64f7323d586d755133a1a9db98dccdfb1159e8baa4073d9808522a4ff08e6e004963e822dde394b67404c69e3de45108b676ff65790a79398c41eb20eeed5496203f134052f2152ae6d805c5b2065c73adfd639ed28e1df5ab6267c2575d08d2ea1b051f486738f8fddc858f61672a42e4536b0073039bc6f021b39f0234add856209b1826cbc449b5f5e2c71d0ec1dc068848c7516ee208cd8149bad40cb12d01e02382406d231ccd8f0e53d0fbc052c7a63c2f8d4b377540b19853dd9f73c3a2bed1ea53f1615e6e996898e044063863736429a55a2251bba1856b655ef846cceb1e2e3299406d33b6df33f59e63a79356e3b75376772659e175da56263ff3bd8f1beceff512e61f2d3a32ee0e3aa69a74836e718e797706329e62c4a5f53c94bb43b3af2eae5cc40377861892412ae860c3922a30a20f393146054f109723441dd64689da258f8c2a2065f112ac3e1260ac29524a881350e1a79c2bc3cb5ed27ac499684f279f170744554f2a82f5658f1a15170c475aeec176195677fe6f7590f75fb1ea8950eb7373333e4accc84793ccc73afe216bb0818a1b66ac3bb1c380f998fdf604e7b3fdb54031d17aab7135b35503ab8756ae90f6cdcdf78b6953f708af2e3c9fa6969afd3cab8fbcb6eae8059881ca002783626c9b7633b9da9db4dbfd4cdc437e308810feefcbf40a2c1b9107d74c21c7eef26dfde9ba6982d66daeb275c69e42759e217849a887a0f3bf287fa3f4ac9c2cd2075e00ed4a3b5d1c77c5b15c5709cc61c72427b2ef82c82c27e2dadd76b0eb5303c2e524c1f7620ff77327878b9bc034241c6b4ac66c27362dc2308a073257f04c8e45c7de509b351cd3ea8cbf37cc7d87af0d7f476d668f984af8c1ebea33a030155eb87ebb93321f0623bf60c97d6f50f99b01e84aea0c80efb1b041ed964237b2116d243415d4bef3ed04192b7861915cbc3041ec38f4d76bf13b68e27eb187ea8dcce5cc0a5cf1265c567683efa96916f9489978a7b81cc49bacb20960f05b57c5081348ede9429a76dc78faced0735312f7f398448aaf0568dcc5d18821f7afedf9990fe007cc8c9b0cd4003e448cbd542541618ff21b60ea77927000305e3699290f55d0ee628a6a4575f1089478c07112117e7aeacbcc608f8acf2c32c7388cecc26650ea5fa5cf02e979c98c47bc8af00511b37d4579fa644ba57b427c01e670a7bbc37c1b344c762464842e8ca302618ec8809e9b9a97cbc3d0a98108771aac815cb79d6a87075095fe12f10b09cade436e874411a65c7bed61d692e2293915c1f39dc540ff7d3eb08a77ea9884691539252d2ae20682eb0129fdd1b5967050ef708151927397c4b3015711a2c082c49344c9fd7447501b14f225008903a78c1ced64dde3e7b24ab5783638acfc9c73ed6466d006881d4b28ba4c323509e37153dfd4111912ecca938733ca00cdb12ee94eea717f658f4bd999af615638022bb05694e6f04a8962806df1528bbc1e50c0d66b24ab92299b1e00cb51b5c7144a38e2fb3ffa0b66510f010a661d8d323ed034681dfbe5fbde21ca88615df99c74885f038e30d1f26917c2a5e6bb5fbec7580b0cd9041d7f7ddb8cf63211d38f4c0190d9749b065a318b1bef5482c9dd1d46e1a9723b2f37bf39bcc2a08d3f18441dbb069e4b4f8d178b1cd1824abda8e665f1e88a816b4f906a8fe870273dad19525f13677729b05849a77804c9c7e801e45b8448c30ead63c2fa712185ed88840cd89bac8981a487f30c6156fd9b78df13e3d44713161f4ec04fd0b1c41b40c55950c7d81ab2c7b5e27053d7f6f19bad4f1e6ba4ce46e26235ae3120e484bbb80ecc00160727b593988f1da7e01f6aaacb3d3501b5bfe0f481917a1174a7b8b780d91167b787837e3eb23f5a1eb35e1e3afc9c4ea37f1280b7429771b515e0421ea86955501a3f44767223f5710ada549355f55d660c0f5d476d4d00becd9e484adde57c0ea4504c57daba8a54864617204d993ab2644bb86ad749c0ceb41623a6706346653201a809d79f6b30e6cbee62febb54ebeca75d1e693a90de9a8dff0202e110bbbfb303bbd4844c0d4751c5a5afdd6f25750301d1fb2b60ee8105da5d955edb124d645f6dd1692ce9a7d79ce860ff895efd5ea6858d1c30ef4661b23ed14fda0b9becb12157a33998ef901cb2ed9ef231c84e2b766c0940375889bcee2272b8a056f643171338185b17e4da22f556192b8eecc478f3fd212ff6202e6107979c6d370c16ec31780b0cbac3ac98d54597f654640db6a46390dfefeefa4a6953d33f41468332778a82ddeb17d970eca0576d4e83d960fdcd4";

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
        nullifier_ = NoirUtils.asField(nullifier_);

        vm.assume(nullifier != nullifier_);

        setUpProofAlice();

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.verifyProof(alice, nullifier_, root, proof);
    }

    /// Cannot modify `root` in proof.
    function test_verify_revert_PROOF_FAILURE_invalid_root(bytes32 root_) public {
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
