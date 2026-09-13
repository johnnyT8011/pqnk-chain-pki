pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PQNKRegistryV3} from "../src/PQNKRegistryV3.sol";

contract PQNKRegistryV3Test is Test {
    PQNKRegistryV3 registry;

    address server = address(0xA11CE);
    address other = address(0xB0B);
    address attacker = address(0xBAD);

    bytes32 constant PK_V1 = keccak256("pk_static_v1");
    bytes32 constant PK_V2 = keccak256("pk_static_v2");
    bytes32 constant PK_V3 = keccak256("pk_static_v3");

    function setUp() public {
        registry = new PQNKRegistryV3();
    }

    // --- 基本路徑 ---

    function test_FirstPublish() public {
        vm.prank(server);
        registry.publish(PK_V1);

        assertEq(registry.getPkHash(server), PK_V1);
        assertTrue(registry.exists(server));
    }

    /// 輪替：新值覆蓋舊值。合約不保留歷史 —— 那是 event log 的職責。
    function test_RotationOverwrites() public {
        vm.startPrank(server);
        registry.publish(PK_V1);
        registry.publish(PK_V2);
        registry.publish(PK_V3);
        vm.stopPrank();

        assertEq(registry.getPkHash(server), PK_V3);
    }

    /// 每個 address 的 commitment 彼此獨立。
    function test_IsolatedPerAddress() public {
        vm.prank(server);
        registry.publish(PK_V1);

        vm.prank(other);
        registry.publish(PK_V2);

        assertEq(registry.getPkHash(server), PK_V1);
        assertEq(registry.getPkHash(other), PK_V2);
    }

    // --- 事件 ---

    /// 事件必須帶上前一版的摘要，監測者才能把零散的事件串成輪替鏈。
    function test_EventCarriesPreviousHash() public {
        vm.prank(server);
        vm.expectEmit(true, false, false, true);
        emit PQNKRegistryV3.CommitmentUpdated(server, PK_V1, bytes32(0));
        registry.publish(PK_V1);

        vm.prank(server);
        vm.expectEmit(true, false, false, true);
        emit PQNKRegistryV3.CommitmentUpdated(server, PK_V2, PK_V1);
        registry.publish(PK_V2);
    }

    // --- 邊界與拒絕條件 ---

    /// 全零被保留作為「未發布」的標記，不可寫入。
    function test_RevertOnZeroHash() public {
        vm.prank(server);
        vm.expectRevert(PQNKRegistryV3.ZeroHash.selector);
        registry.publish(bytes32(0));
    }

    /// 重複寫入相同的值不改變狀態，卻要付 gas 並污染事件紀錄。
    function test_RevertOnUnchanged() public {
        vm.startPrank(server);
        registry.publish(PK_V1);

        vm.expectRevert(PQNKRegistryV3.UnchangedCommitment.selector);
        registry.publish(PK_V1);
        vm.stopPrank();
    }

    /// 輪替回舊值是允許的：對合約而言那只是另一個不同的值。
    /// 是否該接受某個摘要，由 client 的 pk_auth 驗證決定，不是合約的職責。
    function test_CanRotateBackToPreviousValue() public {
        vm.startPrank(server);
        registry.publish(PK_V1);
        registry.publish(PK_V2);
        registry.publish(PK_V1);
        vm.stopPrank();

        assertEq(registry.getPkHash(server), PK_V1);
    }

    /// 查詢未發布的 address 必須 revert，不能回傳零值 ——
    /// 否則 client 會把「查無此人」誤判成「摘要是 0x00...」。
    function test_RevertOnNoCommitment() public {
        vm.expectRevert(
            abi.encodeWithSelector(PQNKRegistryV3.NoCommitment.selector, server)
        );
        registry.getPkHash(server);

        // exists 是例外：回傳 false 本身就是明確的答案
        assertFalse(registry.exists(server));
    }

    // --- 威脅模型 ---

    /// 在古典簽章鏈上，對手可偽造交易以 server 的身分寫入。
    ///
    /// 合約擋不住，也不該擋 —— 授權由 client 端的 pk_auth 驗證提供。
    /// 本測試確認的是：合約的行為是可預測的，偽造的寫入會成為當前值，
    /// 而 client 會在驗簽時拒絕它。
    function test_ForgedWriteBecomesCurrentValue() public {
        vm.prank(server);
        registry.publish(PK_V1);

        // 對手偽造 ECDSA 簽章，以 server 的 address 寫入
        vm.prank(server);
        registry.publish(keccak256("forged_pk"));

        // 合約誠實記錄了它 —— client 驗 pk_auth 簽章時才會拒絕
        assertEq(registry.getPkHash(server), keccak256("forged_pk"));
    }

    /// 對手無法寫入「別人的」commitment —— msg.sender 決定寫入哪一格。
    /// 這是合約唯一提供的隔離，且它只在對手無法偽造交易簽章時成立。
    function test_CannotWriteToAnotherAddress() public {
        vm.prank(server);
        registry.publish(PK_V1);

        vm.prank(attacker);
        registry.publish(PK_V2);

        assertEq(registry.getPkHash(server), PK_V1);
        assertEq(registry.getPkHash(attacker), PK_V2);
    }

    // --- 成本 ---

    /// 首次發布與後續輪替的 gas 差異來自 EVM 的儲存規則：
    /// 寫入從零變非零的槽收 20000，修改既有的非零槽只收 2900。
    function test_GasCost() public {
        vm.startPrank(server);

        uint256 before = gasleft();
        registry.publish(PK_V1);
        emit log_named_uint("first publish gas", before - gasleft());

        before = gasleft();
        registry.publish(PK_V2);
        emit log_named_uint("rotation gas ", before - gasleft());

        vm.stopPrank();
    }

    // --- 模糊測試 ---

    /// 任意非零摘要皆應能寫入並正確讀回。
    function testFuzz_PublishAndRead(address who, bytes32 h) public {
        vm.assume(h != bytes32(0));

        vm.prank(who);
        registry.publish(h);

        assertEq(registry.getPkHash(who), h);
    }
}
