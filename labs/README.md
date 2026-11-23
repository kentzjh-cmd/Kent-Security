# labs

可复现的小实验、PoC 草稿与辅助脚本。

## 规则

- 只针对**自有资产**或**已获书面授权**的目标。
- 仓库默认只保留最小可复现的验证片段，完整利用链放在本地，并通过 `.gitignore` 排除。
- 依赖版本锁定在 `requirements.txt` / `package.json` 中，确保别人能跑起来。
- 脚本默认**只读**。任何写操作必须显式加开关参数，例如 `--i-understand-the-risk`。
- 真实目标地址、内网域名一律用占位符（`<target>`、`example.internal`）替换。

## 结构

```
labs/
└── <topic>/
    ├── README.md      # 目的、环境、预期结果 vs 实际结果
    ├── exploit.py     # 或 script.sh
    └── notes.md       # 踩坑记录与调参过程
```

每个实验的 README 必须写清楚**预期结果**和**实际结果**。两者不一致的地方，往往才是真正的发现。
