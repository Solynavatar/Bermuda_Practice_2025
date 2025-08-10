#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <algorithm>
#include <sstream>
#include <functional>

// SM3 算法
class SM3 {
private:
    static const uint32_t IV[8];
    static const uint32_t T[64];

    static inline uint32_t ROTL(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    static inline uint32_t P0(uint32_t x) {
        return x ^ ROTL(x, 9) ^ ROTL(x, 17);
    }

    static inline uint32_t P1(uint32_t x) {
        return x ^ ROTL(x, 15) ^ ROTL(x, 23);
    }

    static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
    }

    static std::vector<uint8_t> pad(const uint8_t* data, size_t len) {
        size_t bitLen = len * 8;
        size_t k = (448 - (bitLen + 1) % 512 + 512) % 512;
        size_t paddedLen = len + (k + 1 + 64) / 8;

        std::vector<uint8_t> res(paddedLen, 0);
        memcpy(res.data(), data, len);
        res[len] = 0x80;

        for (int i = 0; i < 8; ++i) {
            res[paddedLen - 1 - i] = (bitLen >> (8 * i)) & 0xFF;
        }
        return res;
    }

public:
    static void hash(const uint8_t* data, size_t len, uint8_t digest[32]) {
        uint32_t V[8];
        memcpy(V, IV, sizeof(V));

        std::vector<uint8_t> msg = pad(data, len);
        size_t blocks = msg.size() / 64;

        for (size_t i = 0; i < blocks; ++i) {
            uint32_t W[68], W1[64];
            const uint8_t* B = msg.data() + i * 64;

            // 消息扩展合并
            for (int j = 0; j < 16; ++j) {
                W[j] = (uint32_t(B[j*4]) << 24) | (uint32_t(B[j*4+1]) << 16) | (uint32_t(B[j*4+2]) << 8) | uint32_t(B[j*4+3]);
            }
            for (int j = 16; j < 68; ++j) {
                W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j-13],7) ^ W[j-6];
            }
            for (int j = 0; j < 64; ++j) {
                W1[j] = W[j] ^ W[j+4];
            }

            uint32_t A=V[0], B_=V[1], C=V[2], D=V[3];
            uint32_t E=V[4], F=V[5], G=V[6], H=V[7];

            // 循环展开，每次处理8轮
            for (int j = 0; j < 64; j+=8) {
                for (int k = 0; k < 8; ++k) {
                    uint32_t SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j+k], j+k)) & 0xFFFFFFFF, 7);
                    uint32_t SS2 = SS1 ^ ROTL(A,12);
                    uint32_t TT1 = (FF(A,B_,C,j+k) + D + SS2 + W1[j+k]) & 0xFFFFFFFF;
                    uint32_t TT2 = (GG(E,F,G,j+k) + H + SS1 + W[j+k]) & 0xFFFFFFFF;
                    D=C; C=ROTL(B_,9); B_=A; A=TT1;
                    H=G; G=ROTL(F,19); F=E; E=P0(TT2);
                }
            }

            V[0]^=A; V[1]^=B_; V[2]^=C; V[3]^=D;
            V[4]^=E; V[5]^=F; V[6]^=G; V[7]^=H;
        }

        for (int i=0;i<8;i++) {
            digest[i*4]=(V[i]>>24)&0xFF;
            digest[i*4+1]=(V[i]>>16)&0xFF;
            digest[i*4+2]=(V[i]>>8)&0xFF;
            digest[i*4+3]=V[i]&0xFF;
        }
    }
};

const uint32_t SM3::IV[8] = {
    0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
    0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
};

const uint32_t SM3::T[64] = {
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
};

// 辅助：字节向量与 hex

using Bytes = std::vector<uint8_t>;

std::string toHex(const Bytes &b) {
    std::ostringstream oss;
    oss<<std::hex<<std::setfill('0');
    for (auto x: b) oss<<std::setw(2)<<(int)x;
    oss<<std::dec;
    return oss.str();
}

Bytes sm3_hash_bytes(const Bytes &input) {
    uint8_t out[32];
    if (input.empty()) {
        SM3::hash(nullptr, 0, out);
    } else {
        SM3::hash(input.data(), input.size(), out);
    }
    return Bytes(out, out+32);
}

// RFC6962 风格的 Merkle 树 & 证明函数

class MerkleTreeRFC6962 {
public:
    // leaves: 原始叶子数据（任意字节串）。注意：RFC6962 把 leaf hash 定义为 Hash(0x00 || data)
    MerkleTreeRFC6962(const std::vector<Bytes> &leaves) : leaves_(leaves) {
        n_ = leaves_.size();
        // 如果需要基于某种排序（例如按值排序）来支持非存在证明，
        // 应在构造时对 leaves 做排序并记住原始下标；这里我们默认 leaves 已按“某一顺序”排列。
        // 此处，我们不会改变输入顺序（可以根据需要排序）。
    }

    // 计算并返回树根（使用缓存以避免重复计算）
    Bytes root() {
        memo_.clear();
        return mth(0, n_);
    }

    // 生成包含证明（audit path）
    // 返回：vector<Bytes> 审计路径（每项为 32 字节哈希），按 RFC6962 定义
    std::vector<Bytes> get_audit_path(size_t m) {
        if (m >= n_) return {};
        memo_.clear();
        std::vector<Bytes> path;
        build_path(m, 0, n_, path);
        return path;
    }

    // 非存在证明：
    //  - 对一个 target 字节串（需要以和叶子同样的比较方式比较），
    //    找到它在 leaves 中的插入位置 idx（0..n）
    //  - 返回前驱 (idx-1) 和 后继 (idx) 的包含证明（若存在）
    struct NonExistProof {
        bool has_predecessor;
        size_t pred_index;
        std::vector<Bytes> pred_path; // proof for predecessor
        bool has_successor;
        size_t succ_index;
        std::vector<Bytes> succ_path; // proof for successor
    };

    // 这里采用字典序比较（lexicographical）来定位 target 在 leaves 中的位置
    NonExistProof get_non_membership_proof(const Bytes &target) {
        // 首先构造 vector of leaves for comparison
        std::vector<Bytes> leaf_data = leaves_; // shallow copy
        // 计算 leaf hashes for comparison, because the "meaningful" content maybe leaf-hash
        // We consider comparing raw leaf bytes lexicographically here.
        auto cmp = [](const Bytes &a, const Bytes &b){
            return a < b;
        };

        // 找到插入位置
        size_t idx = std::lower_bound(leaf_data.begin(), leaf_data.end(), target, cmp) - leaf_data.begin();

        NonExistProof proof;
        proof.has_predecessor = (idx > 0);
        proof.has_successor = (idx < n_);

        if (proof.has_predecessor) {
            proof.pred_index = idx - 1;
            proof.pred_path = get_audit_path(proof.pred_index);
        }
        if (proof.has_successor) {
            proof.succ_index = idx;
            proof.succ_path = get_audit_path(proof.succ_index);
        }
        return proof;
    }

    // 验证审计路径（外部函数）：给定 leafData, index m, tree_size n, 和 path（sibling nodes list），验证是否能构造出 root
    // 按 RFC6962 的验证逻辑：从 leafHash 开始，不断结合 path 中的元素（需要知道在每一步上 sibling 应放左还是右）
    // 这里实现的 path 结构是 RFC6962 的 PATH(m, D[n])：验证逻辑按 RFC6962 定义的分割 k 来决定合并方向。
    // 为简化验证逻辑，这里实现一个验证函数：给定 leafData 和 m、n 和 path，逐步使用 RFC 的分割规则重建 root。
   static Bytes compute_root_from_path(const Bytes &leafData, size_t m, size_t n, const std::vector<Bytes> &path) {
    // 将原始叶子数据转换为叶子哈希
    Bytes cur = leaf_hash(leafData);
    size_t idx = m;
    size_t path_pos = 0;
    // 定义递归辅助函数：计算区间 [l, r) 对应的 MTH(D[l:r])，
    // 如果遇到目标叶子则直接返回当前已知哈希，否则从 path 中取出对应的哈希。
    std::function<Bytes(size_t,size_t)> helper = [&](size_t l, size_t r)->Bytes{
        if (r - l == 1) {
            // 单个叶子
            if (l == m) return cur; // 如果是目标叶子，返回当前哈希
            // 否则说明该叶子不在当前验证分支，需要从 path 中取哈希
            if (path_pos >= path.size()) return Bytes(); // 路径数据不足
            return path[path_pos++]; // 消耗一个路径哈希
        }
        // 处理多叶子区间
        size_t len = r - l;
        // 找到小于区间长度的最大 2 的幂
        size_t k = 1;
        while (2*k < len) k <<= 1;
        if (m < l + k) {
            // 目标叶子在左子树
            Bytes left = helper(l, l + k);
            if (path_pos >= path.size()) return Bytes(); // 路径不足
            Bytes right = path[path_pos++]; // 右子树哈希来自 path
            return node_hash(left, right);
        } else {
            // 目标叶子在右子树
            Bytes right = helper(l + k, r);
            if (path_pos >= path.size()) return Bytes();
            Bytes left = path[path_pos++]; // 左子树哈希来自 path
            return node_hash(left, right);
        }
    };

    // 计算整棵树的根哈希
    Bytes root = helper(0, n);
    return root;
}

private:
    std::vector<Bytes> leaves_;
    size_t n_;
    // 记忆化缓存表，键值为 ((uint64_t)l<<32) | r，用于存储已计算过的区间哈希值
    std::unordered_map<uint64_t, Bytes> memo_;

    // 按 RFC6962 定义计算叶子节点哈希
    static Bytes leaf_hash(const Bytes &data) {
        Bytes in;
        in.reserve(1 + data.size());
        in.push_back(0x00); // 叶子节点前缀 0x00
        in.insert(in.end(), data.begin(), data.end());
        return sm3_hash_bytes(in);
    }

    // 按 RFC6962 定义计算内部节点哈希
    static Bytes node_hash(const Bytes &left, const Bytes &right) {
        Bytes in;
        in.reserve(1 + left.size() + right.size());
        in.push_back(0x01); // 内部节点前缀 0x01
        in.insert(in.end(), left.begin(), left.end());
        in.insert(in.end(), right.begin(), right.end());
        return sm3_hash_bytes(in);
    }

    // 递归计算 MTH(D[l:r])，带记忆化缓存
    Bytes mth(size_t l, size_t r) {
        if (l >= r) {
            // 空区间：按 RFC6962 定义，返回空字符串的哈希
            uint8_t z[32];
            SM3::hash(nullptr, 0, z);
            return Bytes(z, z+32);
        }
        if (r == l + 1) {
            // 区间仅包含一个叶子节点，返回叶子节点哈希
            return leaf_hash(leaves_[l]);
        }
        uint64_t key = (uint64_t(l) << 32) | uint64_t(r);
        auto it = memo_.find(key);
        if (it != memo_.end()) return it->second;

        size_t len = r - l;
        // 找到小于 len 的最大 2 的幂 k
        size_t k = 1;
        while (2*k < len) k <<= 1;
        Bytes left = mth(l, l + k);
        Bytes right = mth(l + k, r);
        Bytes node = node_hash(left, right);
        memo_.emplace(key, node);
        return node;
    }

    // 构建指定叶子 m 的认证路径 PATH(m, D[l:r])，并将路径节点依次追加到 out 中
    void build_path(size_t m, size_t l, size_t r, std::vector<Bytes> &out) {
        if (r == l + 1) {
            // 区间内只有一个叶子节点，认证路径为空
            return;
        }
        size_t len = r - l;
        size_t k = 1;
        while (2*k < len) k <<= 1;
        if (m < l + k) {
            // 叶子位于左子树：先递归构建左子树的路径
            build_path(m, l, l + k, out);
            // 追加右子树的哈希（右子树作为兄弟节点）
            Bytes right = mth(l + k, r);
            out.push_back(right);
        } else {
            // 叶子位于右子树：先递归构建右子树的路径
            build_path(m, l + k, r, out);
            // 追加左子树的哈希（左子树作为兄弟节点）
            Bytes left = mth(l, l + k);
            out.push_back(left);
        }
    }

}; // end class


// main() 函数，程序主体

void printHex(const Bytes &b) {
    std::cout<<toHex(b)<<"\n";
}

int main() {
    // 构建 100000 个叶子
    const size_t LEAVES = 100000; // 10万叶子
    std::vector<Bytes> leaves;
    leaves.reserve(LEAVES);
    for (size_t i = 0; i < LEAVES; ++i) {
        std::string s = "leaf-" + std::to_string(i); // 可替换为真实数据
        leaves.push_back(Bytes(s.begin(), s.end()));
    }

    MerkleTreeRFC6962 tree(leaves);

    std::cout<<"构建 100000 叶子的 Merkle Tree（RFC6962）...\n";
    auto t0 = std::chrono::high_resolution_clock::now();
    Bytes root = tree.root();
    auto t1 = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double>(t1 - t0).count() * 1000.0;
    std::cout<<"构建完成，耗时: "<<ms<<" ms\n";
    std::cout<<"Merkle Root: ";
    printHex(root);

    // 示例：存在性证明（leaf index = 50000）
    size_t idx = 50000;
    std::cout<<"\n=== 生成存在性证明：leaf index = "<<idx<<" ===\n";
    auto t2 = std::chrono::high_resolution_clock::now();
    auto path = tree.get_audit_path(idx);
    auto t3 = std::chrono::high_resolution_clock::now();
    std::cout<<"审计路径长度: "<<path.size()<<"\n";
    for (size_t i=0;i<path.size();++i) {
        std::cout<<"path["<<i<<"] = "<<toHex(path[i])<<"\n";
    }
    std::cout<<"生成存在性证明耗时: "<<std::chrono::duration<double>(t3-t2).count()*1000<<" ms\n";

    // 验证示例：用 compute_root_from_path 验证
    Bytes computed_root = MerkleTreeRFC6962::compute_root_from_path(leaves[idx], idx, LEAVES, path);
    std::cout<<"\n验证由 proof 重建的 root 是否与实际 root 相等？\n";
    std::cout<<"重建 root: "<<toHex(computed_root)<<"\n";
    std::cout<<"实际 root: "<<toHex(root)<<"\n";
    std::cout<<(computed_root == root ? "验证成功：包含证明有效\n" : "验证失败：证明无效\n");

    // 非存在证明示例：证明 "leaf-100000000" 不存在
    std::string target_str = "leaf-100000000";
    Bytes target(target_str.begin(), target_str.end());
    std::cout<<"\n=== 生成非存在证明：target = '"<<target_str<<"' ===\n";
    auto ne = tree.get_non_membership_proof(target);
    if (ne.has_predecessor) {
        std::cout<<"前驱索引: "<<ne.pred_index<<"\n";
        std::cout<<"前驱包含证明长度: "<<ne.pred_path.size()<<"\n";
        Bytes pred_root = MerkleTreeRFC6962::compute_root_from_path(leaves[ne.pred_index], ne.pred_index, LEAVES, ne.pred_path);
        std::cout<<"前驱 leaf value: "<<std::string(leaves[ne.pred_index].begin(), leaves[ne.pred_index].end())<<"\n";
        std::cout<<"重建 root equals actual? "<<(pred_root == root ? "Yes":"No")<<"\n";
    } else {
        std::cout<<"无前驱 (target 应插入在 0)\n";
    }
    if (ne.has_successor) {
        std::cout<<"后继索引: "<<ne.succ_index<<"\n";
        std::cout<<"后继包含证明长度: "<<ne.succ_path.size()<<"\n";
        Bytes succ_root = MerkleTreeRFC6962::compute_root_from_path(leaves[ne.succ_index], ne.succ_index, LEAVES, ne.succ_path);
        std::cout<<"后继 leaf value: "<<std::string(leaves[ne.succ_index].begin(), leaves[ne.succ_index].end())<<"\n";
        std::cout<<"重建 root equals actual? "<<(succ_root == root ? "Yes":"No")<<"\n";
    } else {
        std::cout<<"无后继 (target 应插入在末尾)\n";
    }

    std::cout<<"\n说明：若前驱或后继的包含证明都能被验证为真实（即能重建 root）且它们的值都 != target，那么 target 可被证明不在树内。\n";

    return 0;
}
