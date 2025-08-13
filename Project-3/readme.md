# Project 3

本项目的主要文件结构如下：
```
Project-3
├── exp250709.zip   # 从 Ubuntu 22.04 虚拟机中迁移过来的实验文件压缩包。
├── input.json   # 用于生成 witness 的输入文件。
├── package.json
├── package-lock.json
├── poseidon2_0000.zkey   # 初始化的证明密钥
├── poseidon2_0001.zkey   # 最终的证明密钥
├── poseidon2.circom   # poseidon2 算法的 circom 实现
├── poseidon2_js   # witness 生成的相关 js 脚本和 wasm 模块
│   ├── generate_witness.js
│   ├── poseidon2.wasm
│   ├── verification_key.js
│   └── witness_calculator.js
├── poseidon2.json   # 导出的 poseidon2 算法的 js 文件
├── poseidon2.r1cs   # 导出的 poseidon2 算法的 r1cs 文件
├── poseidon2.sym   # 导出的 poseidon2 算法的 sym 文件
├── pot12_0000.ptau
├── pot12_0001.ptau
├── pot12_final.ptau
├── proof.json   # 生成的零知识文件
├── public.json   # 含有公共的输入和输出的文件
├── verification_key.json
├── witness.json   # 由 witness.wtns 导出的 json 文件。
└── witness.wtns   # 生成的 witness 文件。
```

其中，编写的 poseidon2.circom 代码如下：
```javascript
pragma circom 2.0.0;

// Poseidon2 模板
template Poseidon2() {
    signal input in[3];
    signal output out;

    // 总共需要保存每一轮的状态：初始+5轮=6个状态
    signal state[6][3];

    // S-box 的中间结果数组：每一轮一个
    signal new_state0[5];
    signal new_state1[5];
    signal new_state2[5];

    // MDS 层的中间变量数组
    signal tmp0[5];
    signal tmp1[5];
    signal tmp2[5];

    // 初始化 state[0]
    state[0][0] <== in[0];
    state[0][1] <== in[1];
    state[0][2] <== in[2];

    // 5 轮循环
    for (var i = 0; i < 5; i++) {
        // S-box 层：平方
        new_state0[i] <== state[i][0] * state[i][0];
        new_state1[i] <== state[i][1] * state[i][1];
        new_state2[i] <== state[i][2] * state[i][2];

        // MDS 层：简单线性组合
        tmp0[i] <== new_state0[i] + new_state1[i];
        tmp1[i] <== new_state1[i] + new_state2[i];
        tmp2[i] <== new_state2[i] + new_state0[i];

        // 得到下一轮状态
        state[i+1][0] <== tmp0[i];
        state[i+1][1] <== tmp1[i];
        state[i+1][2] <== tmp2[i];
    }

    // 输出最后一轮的第一个状态
    out <== state[5][0];
}

// Main 模板
template Main() {
    signal input preimage[3]; // 隐私输入
    signal input hash;        // 公开输入

    component poseidon2Circuit = Poseidon2();

    // 连接输入
    for (var i = 0; i < 3; i++) {
        poseidon2Circuit.in[i] <== preimage[i];
    }

    // 强制输出等于公开输入
    hash === poseidon2Circuit.out;
}

// 主电路
component main = Main();
```
用于辅助 input.json 的哈希值计算的 Python 代码如下：
```Python
# poseidon2_hash.py

def poseidon2_hash(preimage):
    """
    根据 Circom 里简化版 Poseidon2 电路逻辑计算哈希值
    输入: preimage 是长度为3的整数列表
    返回: 最终 state[0]，作为哈希值
    """
    if len(preimage) != 3:
        raise ValueError("输入必须是长度为3的列表")

    # 初始化 state
    state = [preimage[0], preimage[1], preimage[2]]

    # 5轮
    for i in range(5):
        # 所有元素平方
        state = [x * x for x in state]

        # 计算 tmp
        tmp0 = state[0] + state[1]
        tmp1 = state[1] + state[2]
        tmp2 = state[2] + state[0]

        # 更新 state
        state = [tmp0, tmp1, tmp2]

    # 输出 state[0]
    return state[0]


if __name__ == "__main__":
    # 示例输入
    preimage = [1, 2, 3]
    hash_value = poseidon2_hash(preimage)
    print("真实 hash 值:", hash_value)
```

首先，需要配置好 rust，node.js，circom 和 snarkjs 。

依次运行如下bash命令：
```bash
circom poseidon2.circom --r1cs --sym --wasm
# 编译 Circom 电路：
# - poseidon2.r1cs：电路约束系统
# - poseidon2.sym：调试符号
# - poseidon2_js/poseidon2.wasm：生成 witness 的 wasm 文件

snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
# 创建新的 trusted setup 第一阶段文件（power=12）

snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="BermudaWarehouse" -v
# 对第一阶段 ptau 文件贡献随机数
# 会提示输入随机字符串（Entropy）

snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v
# 生成可供 Groth16 使用的 pot12_final.ptau

snarkjs groth16 setup poseidon2.r1cs pot12_final.ptau poseidon2_0000.zkey
# Groth16 trusted setup 第二阶段，生成初始 proving key

snarkjs zkey contribute poseidon2_0000.zkey poseidon2_0001.zkey --name="Test" -v
# 提高安全性，再次输入随机字符串（Entropy）

snarkjs zkey export verificationkey poseidon2_0001.zkey verification_key.json
# 用于验证证明的公钥

gedit input.json
# 编写 input.json 用于后续计算电路

node poseidon2_js/generate_witness.js poseidon2_js/poseidon2.wasm input.json witness.wtns
# 根据 input.json 计算电路 witness

snarkjs wtns export json witness.wtns witness.json
# 方便查看所有信号值，非必须

snarkjs groth16 prove poseidon2_0001.zkey witness.wtns proof.json public.json
# proof.json：证明文件
# public.json：公开输入（如电路中的 hash）

snarkjs zkey verify poseidon2.r1cs pot12_final.ptau poseidon2_0000.zkey
# 确保 proving key 是从正确的电路和 ptau 文件生成的

snarkjs groth16 verify verification_key.json public.json proof.json
# 使用 verification_key.json 和 public.json 验证 proof.json

```

最终的结果如下：
![项目3测试结果](../images/proj3test.png)