// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PQNKRegistryV3
/// @notice pqNK server 靜態 KEM 公鑰的鏈上 commitment。
///
/// 前提：底層鏈使用古典簽章（如目前的以太坊），因此 msg.sender「不」
/// 構成可信的授權來源 —— 量子對手可偽造交易簽章，以任意 address 的
/// 身分寫入。
///
/// 授權完全由 client 端的 ML-DSA 簽章驗證提供：server 以 sk_auth 簽署
/// (serverAddr ‖ pkHash)，簽章不上鏈，而是在 client 需要時由 server
/// 直接傳送。client 以帶外取得的 pk_auth 驗證。
///
/// 因此本合約只承擔一件事：記錄「這個 address 宣稱的公鑰摘要是什麼」。
/// 它不驗證任何簽章、不做任何授權判斷，也不需要。
///
/// 鏈提供的性質（皆不依賴交易簽章的強度）：
///   - 不可竄改：寫入後無法抹除或修改
///   - 全域一致：所有觀察者讀到同一份狀態
///   - 可稽核：偽造的寫入永久留下公開證據
///
/// 若底層鏈的交易與共識簽章皆完成後量子遷移，client 端的 ML-DSA 驗證
/// 即可移除，此合約不需任何改動。
contract PQNKRegistryV3 {
    /// @notice server address => 當前的公鑰摘要。
    ///
    /// 採覆寫而非 append-only：對手雖能偽造交易寫入，但寫入的值過不了
    /// client 的 pk_auth 驗證，保留歷史沒有意義。歷史由 event log 承擔。
    ///
    /// 未發布時為 bytes32(0)。真實摘要恰為全零的機率是 2^-256，可忽略，
    /// 故不需額外的 exists 旗標。
    mapping(address => bytes32) private _pkHash;

    /// @notice 每次更新都發出事件，讓監測者能重建完整的輪替歷史。
    ///
    /// 帶上 previousPkHash 是為了讓零散的事件能串成一條鏈：若某筆事件
    /// 宣稱前一版是 X，而另一筆事件的 pkHash 正是 X，即可確認兩者相鄰、
    /// 中間沒有遺漏 —— 這在 log 被節點修剪、或只抓到部分區塊範圍時特別
    /// 有用。
    ///
    /// 區塊高度與時間戳由 log 本身的 metadata 提供，不需另存。
    event CommitmentUpdated(
        address indexed server,
        bytes32 pkHash,
        bytes32 previousPkHash
    );

    error NoCommitment(address server);
    error ZeroHash();
    error UnchangedCommitment();

    /// @notice 發布或更新自己的公鑰摘要。
    function publish(bytes32 pkHash) external {
        // 全零被保留作為「未發布」的標記，不可作為有效摘要
        if (pkHash == bytes32(0)) revert ZeroHash();

        bytes32 previous = _pkHash[msg.sender];

        // 重複寫入同一個值不改變狀態，卻要付 gas 並在 log 留下無意義的
        // 紀錄 —— 後者會干擾以事件重建歷史的監測者
        if (previous == pkHash) revert UnchangedCommitment();

        _pkHash[msg.sender] = pkHash;
        emit CommitmentUpdated(msg.sender, pkHash, previous);
    }

    /// @notice 取得某個 server 當前的公鑰摘要。
    /// @dev    查無紀錄時 revert 而非回傳零值 —— 否則 client 無法分辨
    ///         「未發布」與「摘要恰為全零」。
    function getPkHash(address server) external view returns (bytes32) {
        bytes32 h = _pkHash[server];
        if (h == bytes32(0)) revert NoCommitment(server);
        return h;
    }

    /// @notice 查詢是否已發布，不會 revert。
    function exists(address server) external view returns (bool) {
        return _pkHash[server] != bytes32(0);
    }
}