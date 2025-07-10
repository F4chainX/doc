

# **架构最优MPC钱包：面向机构级安全的深度防御蓝图**

## **执行摘要**

在数字资产管理领域，对安全、可扩展且具备操作灵活性的托管解决方案的需求已达到前所未有的高度。多方计算（Multi-Party Computation, MPC）钱包，特别是基于门限签名方案（Threshold Signature Schemes, TSS）的钱包，已成为机构级应用的首选范式。然而，实现真正稳健的安全性并非依赖单一技术，而是需要构建一个深度防御（Defense-in-Depth）体系。本报告旨在提供一个全面的架构蓝图，用于设计和部署一个最优的机构级MPC钱包系统。

本报告的核心论点是，安全性的顶峰并非通过选择某一种技术（如MPC本身）就能达到，而是源于多种先进技术的协同整合。这包括：先进的密码学协议（如采用分布式密钥生成（DKG）的MPC-TSS）、硬件强制隔离（结合硬件安全模块HSM和可信执行环境TEE）、零信任网络架构，以及严格的、由密码学强制执行的运营治理。

我们提出的最优解决方案是一个精心设计的混合模型。该模型旨在利用不同技术在防御堆栈各个层面的独特优势，并根据机构特定的风险偏好和运营需求进行定制。具体而言，该方案主张将在线（“热”）签名节点的密钥分片置于跨越多个云服务商和硬件供应商的可信执行环境（TEE）中，以实现高可用性和硬件供应链的风险分散。同时，将最关键的离线（“冷”）密钥分片存储于物理隔离（Air-Gapped）的、经过FIPS 140-3认证的硬件安全模块（HSM）中，作为最终的安全保障。

此外，本报告强调，一个强大的治理框架，即交易授权策略（Transaction Authorization Policy, TAP）引擎，是防止内部欺诈和外部攻击的关键。该引擎必须与签名层分离，并在安全硬件内强制执行策略。最后，报告还勾勒了全面的密钥生命周期管理流程，包括主动密钥轮换（密钥更新）和经过严格测试的灾难恢复计划，并展望了向后量子密码学（PQC）过渡的前瞻性路径。

本蓝图旨在为金融机构、加密原生公司及Web3企业的首席技术官、首席安全官和首席架构师提供一个清晰、可行的指南，以构建一个不仅能抵御当前威胁，还能适应未来挑战的安全MPC钱包基础设施。

---

## **第1节：MPC钱包安全的基础原则**

本节旨在奠定后续所有架构决策的密码学基础。我们将阐明为何MPC，特别是采用门限签名方案（TSS）的技术，已成为机构级钱包的主流范式，同时也将坦诚地揭示其固有的复杂性和风险。

### **1.1 MPC-TSS范式：消除单点故障**

多方计算（MPC）是一个密码学分支，它允许多个互不信任的参与方在不泄露各自私有输入的前提下，协同计算一个共同的函数 1。在加密货币钱包的应用场景中，这个“函数”就是生成一笔交易的数字签名。

* **密钥分片 (Key Sharding)**：与传统钱包不同，MPC钱包的核心思想是私钥从不以一个完整的实体形式存在。取而代之的是，通过密码学算法将一个逻辑上的私钥分割成多个加密的“分片”（shares）或“碎片”（shards）2。  
* **门限签名方案 (Threshold Signature Schemes, TSS)**：这是MPC钱包实现其功能所依赖的具体密码学协议 4。TSS将密钥的生成和签名过程分布在多个参与方之间 7。系统会预设一个门限值，例如  
  t-of-n（如2-of-3或3-of-5），这意味着需要至少 t 个分片持有者协同参与，才能共同生成一个单一且有效的数字签名 7。最关键的一点是，在整个签名过程中，完整的私钥  
  **永远不会**在任何单一设备或服务器上被重构 3。  
* **分布式密钥生成 (Distributed Key Generation, DKG)**：这是现代MPC钱包安全性的基石。在DKG过程中，所有参与方通过一个交互式协议共同生成各自的密钥分片，而无需一个可信的“分发者”（dealer）或中央方来首先生成完整私钥再进行分割 10。这一点至关重要，它将现代MPC与老旧的秘密共享方案（如Shamir秘密共享，SSS）区分开来。在SSS中，密钥首先被完整创建，然后再分割，这在密钥创生之初就引入了一个致命的单点故障 11。任何声称采用MPC但其密钥生成依赖于“分发者”模式的解决方案，在根本上都比采用真正DKG协议的方案更不安全。因此，在评估任何MPC提供商时，对其密钥生成仪式的确切性质进行探究是至关重要的尽职调查环节。

### **1.2 核心安全保证与固有风险**

MPC-TSS架构提供了强大的安全保证，但也伴随着一系列必须正视的风险。

* **核心保证**：  
  * **消除单点故障**：最主要的安全保证是消除了与传统单一私钥相关的单点故障 1。攻击者无法通过攻破单个持有分片的设备或服务器来窃取资金。  
  * **正确性与隐私性**：MPC协议的两个基本属性是正确性（Correctness）和隐私性（Privacy）。正确性确保协议的输出结果是正确的，而隐私性则保证任何参与方的秘密输入（即密钥分片）不会泄露给其他参与方 10。  
* **固有风险与漏洞**：  
  * **节点妥协与共谋 (Node Compromise & Collusion)**：如果攻击者成功控制了达到门限数量（t 个或更多）的计算节点，他们就能够伪造签名并窃取资产 4。这其中也包括了恶意内部人员共谋的风险 4。整个系统的安全性都建立在一个核心假设之上：对手无法在同一时间控制达到门限数量的参与者 14。  
  * **实现与密码学漏洞 (Implementation & Cryptographic Vulnerabilities)**：MPC协议的极端复杂性意味着，代码实现中的错误（bug）或底层密码学算法的缺陷都可能导致灾难性后果，包括完整的私钥被提取 4。现实世界中已发现的漏洞，如BitForge和TSSHOCK，明确地揭示了这一风险 9。  
  * **通信信道攻击 (Communication Channel Attacks)**：MPC协议的交互性要求参与方之间必须进行安全通信。攻击者可以利用中间人攻击（Man-in-the-Middle, MITM）来窃听或篡改协议消息，从而破坏其安全性 4。  
  * **侧信道攻击 (Side-Channel Attacks)**：攻击者可能通过分析计算节点的物理特性，如计算时间、功耗或网络流量模式，来推断出与密钥分片相关的敏感信息，从而削弱系统的安全性 4。  
  * **依赖性风险 (Dependency Risks)**：许多MPC解决方案严重依赖于第三方服务提供商或特定的云基础设施（如AWS、Google Cloud）。这不仅引入了系统性风险，还可能形成新的中心化节点，与去中心化的初衷相悖 4。  
  * **EOA撤销问题 (The EOA Revocation Problem)**：当MPC钱包用于控制标准的外部拥有账户（Externally Owned Accounts, EOA）时，存在一个根本性的弱点：链上没有机制可以撤销一个已经泄露的密钥分片。即使执行了密钥“更新”（resharing）操作以生成新的分片，理论上，如果攻击者收集到足够数量的**旧**分片，他们仍然可以构造出有效的签名。这构成了一个持久性的安全威胁，与能够通过智能合约在链上撤销密钥的钱包形成鲜明对比 4。

### **1.3 权威对比：MPC vs. 链上多重签名**

为了充分理解为何MPC成为机构首选，有必要将其与另一种主流的多方授权技术——链上多重签名（On-Chain Multi-Signature）进行深入比较。

| 特性 | MPC钱包 (MPC-TSS) | 链上多重签名钱包 (On-Chain Multi-sig) |
| :---- | :---- | :---- |
| **工作机制** | 使用一个分片的私钥，通过TSS协议在**链下**协作生成**一个**有效的数字签名 3。 | 使用多个独立的完整私钥，在**链上**提交**多个**独立的数字签名以满足智能合约或协议的要求 6。 |
| **隐私性** | **高**。签名仪式在链下进行，最终上链的交易与单签交易无异。这隐藏了钱包的安全策略（如门限值）和签名者的身份 1。 | **低**。多签钱包的地址结构和签名要求（如2-of-3）在区块链上是公开可见的，暴露了其安全配置 9。 |
| **交易成本** | **低**。由于链上只有一个签名，其数据大小与单签交易相同，因此网络费用（Gas费）也与单签交易持平 6。 | **高**。需要为每个签名支付额外的链上数据空间，导致交易费用显著高于单签或MPC交易 6。 |
| **灵活性与兼容性** | **高**。MPC是密码学层面的技术，与区块链无关。只要目标链支持标准的签名算法（如ECDSA、EdDSA），MPC钱包就可以无缝支持 13。 | **有限**。多重签名依赖于特定区块链协议或智能合约的原生支持。并非所有区块链都提供原生、稳健的多签功能 9。 |
| **密钥与策略管理** | **灵活**。可以通过密钥“更新”（resharing）协议来更改签名者或调整门限值，而无需更改钱包地址，也无需进行链上交易 6。 | **僵化**。更改签名者或门限值通常需要创建一个全新的多签钱包，并将所有资产从旧地址转移到新地址，这是一个繁琐且昂贵的链上过程 6。 |

这种对比揭示了一个深刻的权衡：信任模型的转变。链上多重签名的信任根植于区块链协议或智能合约的开放、可审计和不可变的代码。其安全性是透明且可由任何人验证的。相比之下，MPC的信任则从链上协议转移到了链下、通常是专有的MPC提供商的软件实现上。对于区块链而言，MPC的签名过程是一个“黑箱” 18。这意味着，虽然MPC在隐私、成本和灵活性方面具有显著优势，但它也要求机构对MPC提供商进行极为严格的尽职调查。评估的重点必须包括其密码学团队的专业水平（例如，Coinbase聘请了密码学权威Yehuda Lindell 22）、安全审计的质量和频率 23、核心库的开放性 25 以及其运营日志的完整性和可审计性 12。最终，机构面临的选择是在“协议级信任”（多签）和“提供商级信任”（MPC）之间做出决策。对于追求运营效率和隐私的现代机构而言，MPC通常是更优越的选择，但这要求它们承担起审查和监督提供商的责任。

---

## **第2节：基石 \- 密钥分片的安全存储**

密钥分片是MPC系统中最核心、最敏感的资产。本节将详细阐述存储这些分片的物理和虚拟环境，并提出一个结合了多种技术的深度防御混合模型作为最优解决方案。

### **2.1 硬件安全模块 (HSM)：物理堡垒**

硬件安全模块（HSM）是一种专门设计的、具备防篡改能力的物理设备，用于安全地生成、存储和管理密码学密钥 26。它们提供了一个可信执行环境（TEE），被公认为保护根信任材料的黄金标准 29。

* **核心功能与认证**：HSM旨在确保密钥永远不会离开其安全边界。所有密码学操作都在模块内部完成。评估HSM时，必须关注其是否通过了国际公认的安全认证，如FIPS 140-2或更高级别的FIPS 140-3。这些认证为设备的安全性设计和实现提供了独立的第三方保证 27。  
* **部署模型**：  
  * **本地部署HSM (On-Premise HSMs)**：提供对设备的完全物理控制和所有权，是实现物理隔离（air-gapped）环境和满足具有严格物理安全策略的组织的理想选择 31。其缺点是前期资本支出（CapEx）高昂，且需要持续的维护和管理开销 27。  
  * **云HSM (Cloud HSMs)**：由AWS、Google Cloud等云服务商提供，以“即服务”的模式交付。这大大降低了前期投资，简化了管理，但同时也引入了对云服务商的依赖，并削弱了直接的物理控制权 27。  
* **在MPC架构中的角色**：HSM最适合用于存储最关键、最不常使用的密钥分片。这包括用于冷存储金库的分片，或仅在灾难恢复场景下才会动用的备份和恢复分片 26。行业领导者Anchorage Digital的整个托管模型就是围绕其专有的HSM构建的，这体现了HSM在最高安全级别场景中的核心地位 33。

### **2.2 可信执行环境 (TEE)：虚拟保险箱**

可信执行环境（TEE）是在主处理器内部创建的一个安全、隔离的区域，它能保证在其中执行的代码和数据的机密性和完整性 35。TEE能够有效抵御来自宿主操作系统（即使已被攻破）或拥有特权的系统管理员的攻击。

* **主流技术**：  
  * **AWS Nitro Enclaves**：这是一种创建完全隔离的虚拟机的技术。这些虚拟机没有持久化存储、没有交互式访问权限，也没有外部网络连接。与宿主实例的通信通过一个安全的本地通道进行。其关键特性是“密码学证明”（Cryptographic Attestation），它能向外部服务（如AWS KMS）证明，该隔离区内运行的是且仅是经过授权的代码 37。这使其成为部署云原生MPC节点的绝佳选择 5。  
  * **Intel Software Guard Extensions (SGX)**：与保护整个虚拟机不同，SGX保护的是内存中的特定部分，即“应用飞地”（application enclaves）40。这为受保护的应用提供了更小的攻击面，但实现起来可能更为复杂。Fireblocks在其架构中广泛采用了Intel SGX技术 42。  
  * **AMD Secure Encrypted Virtualization (SEV)**：SEV技术通过为每个虚拟机分配一个唯一的密钥来加密其内存，从而保护虚拟机免受来自Hypervisor（虚拟机监控程序）的窥探 40。其最新版本SEV-SNP（Secure Nested Paging）进一步增加了强大的完整性保护，以抵御基于软件的攻击 40。  
* **在MPC架构中的角色**：TEE是保护需要在线并保持响应能力的“热”或“温”签名节点上密钥分片的理想选择。它们提供了一种软件定义的、可扩展且成本效益高的方案，来保护分片在活跃的计算过程中的安全 35。

### **2.3 架构决策：深度防御的混合模型**

最优的架构并非在HSM和TEE之间做出“二选一”的抉择，而是将两者进行协同组合，形成一个深度防御体系 28。

* **蓝图规划**：  
  * **热/温签名节点**：将用于日常交易的MPC签名节点部署在TEE（如AWS Nitro Enclaves）中。为了实现高可用性和风险分散，这些节点应分布在多个不同的云服务商和地理区域。  
  * **冷/恢复分片**：将一部分密钥分片（例如，在一个3-of-5方案中的最后一个分片）存储在本地部署的、物理隔离的、经过FIPS 140-3认证的HSM中。这个分片作为最终的安全屏障，仅在处理超高价值交易或执行灾难恢复程序时才会被激活。  
  * **行业实践**：Fireblocks通过在其活跃节点上使用Intel SGX，同时支持客户集成自有HSM进行分层保护，为这种混合模型提供了现实世界的范例 42。

这种架构设计体现了一个重要的安全思想：TEE虽然能有效隔离来自宿主操作系统的威胁，但它也引入了一个新的信任边界和攻击面，即对硬件制造商（Intel、AMD）和云提供商（AWS）的依赖。历史上针对SGX的Foreshadow/L1TF等漏洞表明，TEE本身也可能成为攻击目标。因此，一个稳健的架构绝不能单独依赖TEE。这进一步强化了混合模型的必要性——即使TEE层被攻破，整个系统的安全也不会被完全摧毁，因为还有基于HSM的离线分片作为最后的防线。

更进一步，最高级的安全态势不仅要求跨云服务商进行多样化部署，还应跨TEE供应商进行多样化。例如，有文献明确建议将MPC端点同时部署在Intel SGX和AMD SEV上 36。这是一个深刻的架构策略。如果Intel的SGX实现中发现了严重漏洞，运行在AMD SEV上的MPC节点将保持安全，从而防止攻击者达到共谋门限。这种策略分散了硬件供应链的风险，这是大多数纯软件或单一云解决方案未能考虑到的威胁。因此，最优的架构蓝图应推荐一个

t-of-n方案，其中密钥分片分布在至少两种不同的TEE供应商环境（例如，基于Graviton/AMD的AWS Nitro实例和基于Intel的SGX实例）以及一个HSM之上。

### **2.4 MPC分片的冷存储与物理隔离策略**

传统观念认为，MPC需要各参与方之间进行在线的、交互式的通信，这似乎与真正的物理隔离（Air-Gapped）冷存储概念背道而驰 45。

* **Fireblocks MPC-CMP的创新**：Fireblocks声称其开发的特定协议MPC-CMP，实现了一种真正意义上的、可物理隔离的MPC冷存储解决方案 46。虽然其公开白皮书未详述完整的密码学机制 42，但其核心创新在于能够预先计算大量的“一次性签名组件”。这使得物理隔离的设备能够在不进行实时、多轮交互的情况下，参与签名过程。这极大地扩展了MPC的应用场景，使得一个完全离线的设备也能成为MPC签名网络的一部分，这是一个重大的技术突破 46。  
* **常规隔离策略**：对于其他密钥分片，实现隔离的方法包括：  
  * **物理隔离 (Physical Air Gap)**：将分片存储在一台没有任何网络接口（有线或无线）的机器上，并将其放置在安全的物理位置（如保险库）。数据传输必须通过可移动介质（如加密U盘）手动进行，并实施严格的物理访问控制 48。  
  * **逻辑/操作隔离 (Logical/Operational Air Gap)**：利用防火墙和网络分段技术，创建单向或基于时间的通信连接。例如，防火墙可以被编程为仅在MPC协议执行所需的短暂、预定的通信窗口期间允许流量通过，然后在其他时间完全阻断连接 50。这被称为“操作性物理隔离”。

### **2.5 表1：密钥分片存储技术 \- 对比分析**

为了给决策者提供一个清晰的参考，下表对各种安全存储技术进行了多维度比较。

| 技术 | 安全模型 | 隔离粒度 | 证明机制 | 主要用例 | 关键漏洞/风险 | 成本模型 |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| **本地HSM** | 物理防篡改硬件 | 设备级 | FIPS 140-2/3 认证 | 根信任、冷存储、离线恢复分片 | 物理盗窃、内部人员滥用、高维护成本 | 高资本支出 (CapEx)，低运营支出 (OpEx) |
| **云HSM** | 云服务商管理的专用硬件 | 设备级（租户隔离） | FIPS 140-2/3 认证 | 云原生应用的根信任、合规性要求 | 云服务商风险、配置错误、供应商锁定 | 低/零CapEx，基于使用的OpEx |
| **AWS Nitro Enclave** | Hypervisor强制隔离的虚拟机 | 虚拟机级 | 密码学证明 (Attestation) | 热/温签名节点、云原生MPC计算 | Hypervisor漏洞、云平台风险、侧信道攻击 | 作为EC2实例的一部分，无额外费用 |
| **Intel SGX** | CPU强制隔离的应用内存 | 应用级（飞地） | 远程证明 (Remote Attestation) | 热/温签名节点、保护特定敏感计算 | CPU微码漏洞（如Foreshadow）、侧信道攻击 | 依赖支持SGX的CPU |
| **AMD SEV** | CPU强制加密的虚拟机内存 | 虚拟机级 | 内存内容证明 (Attestation) | 热/温签名节点、保护整个VM工作负载 | Hypervisor攻击、CPU微码漏洞、侧信道攻击 | 依赖支持SEV的CPU |

此表清晰地展示了不同技术之间的权衡，帮助架构师根据具体需求（如隔离粒度、风险承受能力和成本预算）做出明智的技术选型决策。

---

## **第3节：堡垒 \- 配置签名环境**

本节提供了一份可操作的指南，用于加固构成MPC签名基础设施的机器和网络，直接回应了用户对签名机器配置的核心关切。

### **3.1 签名节点的操作系统（OS）加固**

安全始于一个干净、最小化的操作系统环境。

* **最小功能原则 (Principle of Least Functionality)**：应从一个经过加固的、最小化的OS镜像开始，例如使用CIS加固镜像（CIS Hardened Images）53。移除所有不必要的应用程序、服务、库和设备驱动程序，以最大限度地减少攻击面 54。  
* **访问控制 (Access Control)**：实施严格的基于角色的访问控制（RBAC）和最小权限原则。任何用户或进程都不应拥有超出其完成任务所必需的权限。管理员访问权限应受到严格限制、监控，并使用多因素认证。所有默认账户（如root, administrator）必须被禁用或重命名 54。  
* **应用控制 (Application Control)**：采用应用白名单策略，确保只有经过批准和密码学验证（例如，通过哈希或发布者证书验证）的可执行文件才能运行。默认阻止所有其他应用的执行 54。  
* **系统完整性与监控**：  
  * 启用全面、集中的日志记录，捕获所有系统活动，包括用户登录、文件访问和进程执行，并将日志发送到安全的、隔离的日志服务器 54。  
  * 使用文件完整性监控（FIM）工具，实时检测对关键系统文件和配置的未经授权的更改。  
  * 定期进行漏洞扫描和渗透测试，以主动发现并修复安全弱点 54。  
* **补丁管理 (Patch Management)**：建立一个自动化的、严格的补丁管理流程，确保安全更新能够及时、可靠地应用到所有签名节点 54。  
* **内存安全语言 (Memory-Safe Languages)**：在技术选型时，应优先考虑使用内存安全语言（如Rust、Go）编写的MPC软件。这可以从根本上消除如缓冲区溢出等一整类的内存安全漏洞 56。例如，Coinbase的开源库虽然使用C++17，但明确建议使用特定的现代编译器并开启所有安全检查 25。

一个重要的观点是，加固工作必须延伸到构建管道（Build Pipeline）。仅仅保护运行时环境是不够的，因为攻击者可能在软件部署之前就已将其攻破。一个安全的构建流程应包括：验证基础OS镜像的完整性、扫描所有软件依赖项以查找漏洞 57、使用版本控制的基础设施即代码（Infrastructure-as-Code）工具来管理配置 55，并确保最终的部署包经过密码学签名和验证。

### **3.2 网络架构与隔离：零信任方法**

MPC签名节点必须运行在一个与外界严格隔离的网络环境中，遵循零信任原则。

* **网络分段 (Network Segmentation)**：将MPC签名节点放置在一个独立的、高度分段的网络中（例如，专用的VPC或VLAN）。默认情况下，防火墙应拒绝所有流量，仅在特定端口上明确允许来自其他MPC节点特定IP地址的通信 52。  
* **物理隔离 (Air-Gapping)**：  
  * **物理隔离**：对于最安全的“冷”节点（如基于HSM的节点），这意味着完全没有任何物理网络连接 48。  
  * **逻辑/操作隔离**：对于其他节点，可以通过编程方式控制防火墙规则，仅在MPC协议执行所需的短暂、预定的通信窗口期间打开连接，然后在其他时间关闭。这是一种“操作性物理隔离” 50。  
* **安全通信信道 (Secure Communication Channels)**：所有MPC节点之间的通信都必须通过强大的、相互认证的加密协议（如带有相互证书验证的TLS 1.3）进行。这可以有效防止中间人攻击，避免对手窃听或篡改MPC协议消息 4。  
* **禁用不安全协议**：必须禁用所有不安全的管理协议，如Telnet、FTP和HTTP。所有远程管理都应通过SSH等经过加密和认证的协议进行 55。

在MPC的语境下，网络本身不仅仅是一个传输数据的管道，它实际上是计算过程的一部分。MPC协议通常包含多个交互“轮次” 59。这意味着对网络的攻击就是对算法的攻击。例如，在签名过程中对网络发起拒绝服务（DoS）攻击可能导致协议中止；而复杂的中间人攻击则可能尝试重放或修改消息以提取敏感信息。因此，网络加固不仅是IT运营的最佳实践，更是一项密码学安全要求。网络的设计必须秉持与MPC协议本身相同的对抗性思维，假设它随时可能受到攻击。这也解释了为何需要采取逻辑/操作隔离和相互认证TLS等极端措施。

### **3.3 本地组件的物理安全控制**

此部分适用于任何本地部署的HSM或签名节点。

* **安全位置**：设备必须存放在具有严格物理访问控制的安全数据中心或保险库中。  
* **访问控制**：采用多因素认证机制（如生物识别、门禁卡）来控制进入。所有物理访问都必须被详细记录和审计。  
* **监控**：实施全天候的视频监控。  
* **防篡改**：对设备使用防篡改封条和机箱。HSM本身被设计为防篡改的，一旦检测到物理入侵，会自动擦除其中存储的密钥材料 29。

---

## **第4节：规则手册 \- 机构治理与生命周期管理**

本节将讨论从纯技术转向管理其使用的策略和流程。对于机构而言，这通常是防止内部欺诈和外部攻击的最关键层面。

### **4.1 设计稳健的交易授权策略（TAP）引擎**

一个精心设计的TAP引擎是机构级MPC钱包的核心。

* **关注点分离 (Separation of Concerns)**：最佳架构将策略执行层与密码学签名层完全分离 12。MPC协议负责保护密钥本身的安全；而TAP引擎则决定在何种条件下  
  **允许**使用该密钥。  
* **密码学强制执行的策略 (Cryptographically Enforced Policies)**：策略不应仅仅是数据库中的记录，因为这很容易被篡改。相反，策略本身应该是一个经过管理员群体（quorum）密码学签名的对象。理想情况下，策略的执行应在TEE（如Fireblocks使用SGX 42）或HSM（如Anchorage Digital的模型 33）内部进行，使其不可篡改。  
* **精细化的规则集 (Granular Rule-Set)**：TAP引擎必须支持一套丰富的、可配置的规则，以满足机构复杂的合规和风控需求。这包括：  
  * **基于角色的群体审批 (Role-Based Quorums)**：定义不同的用户角色（如交易发起人、审批人、管理员），并要求特定角色的特定组合（quorum）才能授权一笔交易 47。  
  * **交易限额 (Transaction Limits)**：强制执行基于价值（例如，单笔不超过100万美元）、频率（例如，每小时不超过5笔）和时间窗口内总额（例如，每日总额不超过1000万美元）的限制 60。  
  * **地址管理 (Address Management)**：实施严格的目的地址白名单制度。默认情况下，向非白名单地址的交易应被阻止。对白名单的任何修改都应需要一个高级别的、多角色的群体审批 60。  
  * **智能合约交互控制 (Smart Contract Interaction Control)**：建立已审计的智能合约地址和函数调用的白名单。这可以防止用户与恶意的或未经审查的dApp进行交互，从而避免资产被盗 47。  
  * **交易模拟与解析 (Transaction Simulation & Enrichment)**：在请求用户签名之前，TAP引擎应模拟该交易的链上后果，并以人类可读的格式清晰地展示其影响（例如，“您正在向Uniswap V3路由器发送100 ETH，预计将收到约180,000 USDC”）。这可以有效防止“盲签”（blind signing）带来的风险 64。

### **4.2 表2：机构交易授权策略（TAP）引擎规则集模板**

下表提供了一个具体的、可操作的TAP规则集模板。

| 规则类别 | 具体规则 | 旨在缓解的威胁 | 实施示例 |
| :---- | :---- | :---- | :---- |
| **用户角色与群体审批** | 任何超过100万美元的交易需要至少1名“交易员”发起，并由1名“合规官”和1名“高管”共同批准。 | 内部欺诈、单人操作失误、权限滥用 | 设置一个3人审批流，每个角色来自不同部门。 |
|  | 修改策略（如限额、白名单）需要至少2名“管理员”批准。 | 策略被恶意篡改、单点管理风险 | 策略更改操作需要一个2-of-N的管理员群体签名。 |
| **交易限额** | 单个用户每日交易总额不得超过500万美元。 | 个人账户被盗后的大规模资金损失 | 在策略引擎中为每个用户ID设置每日累计交易额上限。 |
|  | 每小时提现到新白名单地址的次数不得超过1次。 | 快速、自动化的盗窃攻击 | 实施基于时间的速率限制策略。 |
| **地址管理** | 所有提现地址必须预先加入白名单。 | 钓鱼攻击、地址投毒攻击、内部人员将资金转至个人地址 | 默认拒绝所有向未知地址的转账请求。 |
|  | 向白名单添加新地址需要24小时的冷却期才能生效。 | 攻击者快速添加恶意地址并提现 | 实施时间锁（timelock）策略，在冷却期内可由管理员撤销。 |
| **合约交互** | 仅允许与经过审计的DeFi协议（如Uniswap, Aave）的特定路由器或池合约进行交互。 | 与恶意或有漏洞的智能合约交互导致资产损失 | 维护一个合约地址和函数签名（function signature）的白名单。 |
|  | 禁止调用任何合约的approve()函数，除非目标地址在批准的合约列表中。 | 无限授权（unlimited approval）漏洞被利用 | 对approve等高风险函数调用进行特殊检查和限制。 |
| **时间基准控制** | 禁止在非工作时间（如午夜至凌晨6点）进行任何资金转移操作。 | 在监控较弱的时段发生未经授权的活动 | 实施基于时间窗口的策略规则。 |

### **4.3 全面的密钥生命周期管理**

必须将源自传统公钥基础设施（PKI）标准的严格生命周期管理框架 66，应用于MPC的密钥分片。

* **生成 (Generation)**：如第1节所述，必须使用安全的、经过审计的DKG协议。  
* **存储 (Storage)**：采用第2节中详述的HSM/TEE混合模型。  
* **分发与安装 (Distribution & Installation)**：将分片安全地安装到经过加固的节点上。  
* **使用 (Usage)**：由TAP引擎严格管控。  
* **轮换/更新 (Rotation/Resharing)**：定期更新密钥分片（详见4.4节）。  
* **备份与恢复 (Backup & Recovery)**：实施并定期测试灾难恢复计划（详见4.5节）。  
* **撤销/销毁 (Revocation/Destruction)**：当一个密钥不再需要时，必须在所有节点上安全地删除其所有分片，且此过程必须可审计。

### **4.4 主动安全：密钥更新与主动秘密共享（PSS）**

密钥更新（Key Resharing）是主动秘密共享（Proactive Secret Sharing, PSS）的一种形式，是MPC架构中一项至关重要的主动防御机制。

* **目的**：密钥更新是一个协议，它允许现有分片持有者共同计算出一套**全新**的、随机化的分片，用于代表**同一个**私钥。此过程完成后，旧的分片将完全失效 68。钱包的公钥和链上地址保持不变。  
* **协议高级步骤**：  
  1. 一个达到门限的现有分片持有者群体（t of n）发起更新会话。  
  2. 每个参与者生成一个新的、常数项为零的随机多项式（t-1次）。他们将这个“零洞”多项式的分片分发给所有其他参与者。  
  3. 每个参与者将自己持有的原始分片与从其他参与者那里收到的新分片相加。这个过程有效地对原始秘密的分片进行了重新随机化。  
  4. 最终结果是一套全新的、对原始秘密有效的分片。旧分片与新分片互不兼容，因此失效。（基于 69 的原理）。  
* **关键用例**：  
  * **撤销泄露的分片**：当员工离职或设备丢失时，立即执行密钥更新会话可以使其持有的旧分片失效，从而有效缓解第1节中提到的EOA撤销问题 4。  
  * **抵御“移动的对手”**：保护系统免受缓慢、渐进式的攻击。在这种攻击中，对手可能在很长一段时间内逐个攻破节点。定期的密钥更新可以确保即使对手成功窃取了一个分片，该分片也会在下一次更新后失效，使其无法集齐门限数量的分片 68。  
  * **更改门限或成员**：密钥更新协议也可以用来灵活地调整群体审批的策略（例如，从2-of-3升级到3-of-5）或增删成员，而无需创建新钱包和转移资产 69。

### **4.5 灾难恢复（DR）与业务连续性**

一个正式的、文档化的、并经过反复测试的灾难恢复计划是任何机构级部署的必要条件 72。

* **软恢复 (Soft Recovery)**：用于恢复单个丢失的分片或设备。  
  * **流程**：此过程需要剩余的、达到门限数量的分片持有者在线。用户通过强身份验证（如生物识别、密码），然后系统为一个新设备生成一个新的分片。紧接着，必须强制执行一次密钥更新会话，以使丢失的旧分片永久失效 73。  
  * **考量**：用于恢复的凭证（如恢复密码）必须与设备本身分开、安全地存储 73。Zengo的安全审计案例 74 深刻地揭示了恢复/设备注册流程是系统的攻击关键点，必须用最高级别的身份验证来保护。  
* **硬恢复 (Hard Recovery)**：用于应对灾难性故障，例如，在线的、活跃的分片丢失数量超过了门限，导致无法正常签名。  
  * **流程**：这是最后的手段，涉及从高度安全的离线备份中重构主私钥种子 73。  
  * **考量**：此过程会暂时性地重新引入单点故障 73。因此，它必须在一个物理安全的、物理隔离的环境（“洁净室”）中执行，并有多名高级别利益相关者在场监督（形成一个“仪式”）。重构出的密钥必须立即用于为新钱包生成一套全新的MPC分片，并将资产转移过去。之后，重构出的完整密钥必须被彻底、可验证地销毁。  
* **测试**：灾难恢复计划必须定期（至少每年一次）在模拟环境中进行演练，以确保其有效性，并确保所有相关人员都清楚地了解自己的职责和操作流程 73。

一个深刻的结论是，治理是抵御共谋的现实手段。MPC的密码学安全性是基于“不超过 t-1 个参与者是恶意的”这一数学假设 14。然而，在现实世界中，是什么阻止

t 个参与者进行共谋呢？仅靠密码学是无法做到的。这时，治理就显得至关重要。通过实施“任何单个管理员都不能批准对地址白名单的更改”或“一笔高价值交易需要来自合规团队、财务团队的成员以及一个自动化风险引擎三方批准”等规则，TAP引擎使得实际操作中的共谋变得极其困难。它在组织层面强制执行了职责分离，这与密钥分片的密码学分离形成了镜像。

另一个关键点是，恢复过程是系统最脆弱的状态。一个MPC系统在正常运行 时最为安全，而在恢复，特别是硬恢复期间，则最为脆弱。攻击者最有可能的策略不是正面硬撼MPC密码学，而是攻击其恢复流程。他们可能会尝试通过社会工程学手段来通过软恢复流程，或者在硬恢复期间攻击“洁净室”环境。因此，一个机构在保护其恢复流程上所投入的精力，应不亚于其日常交易工作流。备份组件的安全性和恢复仪式的严谨性是至关重要的。

---

## **第5节：业界蓝图 \- 领先托管解决方案分析**

本节将对用户查询中提到的行业领导者进行基准分析，从它们的成功实践和已披露的安全事件中提取关键的架构模式和经验教训。

### **5.1 Coinbase：可扩展、用户中心化的模型**

* **架构**：Coinbase的WaaS（Wallet as a Service）主要采用2-of-2的MPC模型。其中一个分片存储在用户的设备上，另一个分片由Coinbase的服务器管理 22。这种设计极大地简化了用户体验，使其感觉更接近传统的Web2应用。  
* **恢复机制**：其特色是“Coinbase辅助备份”（Coinbase-aided backup）。用户的分片经过加密后，会备份到他们自己的个人云存储（如iCloud或Google Drive）。当用户丢失设备时，他们只需通过向Coinbase进行身份验证，即可恢复访问权限，这模仿了传统的“密码重置”流程，优先考虑了易用性 22。  
* **安全模型**：这种架构下，Coinbase无法单方面动用用户资金，因为它只持有一个分片。同时，即使用户的设备被攻破，攻击者也无法轻易盗取资金，因为他们还需要获取Coinbase持有的分片，并通过Coinbase的身份验证和风险控制系统 22。  
* **开放性**：Coinbase已将其核心的MPC密码学库开源 25，这不仅展示了其技术实力，也允许公众对其进行审查，增加了透明度。

### **5.2 Fireblocks：多层次、深度防御模型**

* **架构**：Fireblocks采用了一种多层次的深度防御系统，其核心是专有的MPC-CMP协议、硬件隔离技术（Intel SGX）和多云部署策略的结合 42。  
* **关键差异化**：  
  * **MPC-CMP协议**：一种经过优化的MPC协议，据称可将签名速度提高8倍，并实现了一种独特的、可物理隔离的冷存储解决方案 46。  
  * **硬件隔离**：广泛使用Intel SGX技术为密钥分片存储和策略引擎的执行创建安全飞地，从而保护它们免受来自底层操作系统的攻击 42。  
  * **策略引擎**：一个功能强大、粒度精细的策略引擎是其产品的核心，并且该引擎的执行同样在SGX飞地内受到保护，使其难以被篡改 42。

### **5.3 Anchorage Digital：银行级、HSM中心化模型**

* **架构**：Anchorage Digital采取了一种与前两者截然不同的方法，其整个安全模型都建立在专有的、经过FIPS 140-2认证的HSM之上。值得注意的是，它是美国唯一一家获得联邦特许的加密银行 34。  
* **关键差异化**：  
  * **硬件强制执行的策略**：其交易授权逻辑和策略引擎被直接构建在HSM的固件中。这意味着策略检查与密钥本身在同一个安全边界内进行，这是一种独特且极其强大的安全设计 30。  
  * **生物识别认证**：将生物识别因素（如声音和视频）整合到其基于群体的审批工作流中，增加了额外的身份验证层 33。  
  * **合格托管人**：作为一家受监管的银行，它能提供纯技术提供商无法比拟的监管合规性和破产隔离保护 33。

### **5.4 Zengo：来自面向消费者的MPC钱包审计的教训**

* **架构**：一个2-of-2的MPC钱包，一个分片在用户的移动设备上，另一个在Zengo的服务器上 78。  
* **恢复机制**：依赖于一个三因素认证系统（3FA）：电子邮件、云恢复文件和3D生物面部扫描（FaceLock）23。  
* **审计洞见（CertiK）**：审计发现了一个严重漏洞：用户可以在**没有**进行3D FaceLock验证的情况下，注册一个新的设备密钥。这意味着，一个在用户设备上获得特权访问的攻击者，可以利用这个漏洞注册自己的设备，从而接管整个账户 74。  
* **关键教训**：这个真实的审计案例提供了一个至关重要的教训——MPC系统的安全性取决于其最薄弱的环节。即使核心的MPC密码学是安全的，其周边流程（如设备注册或恢复）中的一个缺陷也可能摧毁整个系统。这再次强调了实施全面、整体安全措施的必要性，必须对所有能改变安全状态的操作（state-changing operations）应用最高级别的身份验证。

通过对这些行业领导者的分析，我们可以看到机构级托管领域存在三种不同的架构哲学：

1. **软件定义与可扩展（以Coinbase为代表）**：侧重于易用性和无缝的开发者/用户体验，充分利用云技术和强大的运营安全。其信任模型建立在对提供商软件和运营能力的信任之上。  
2. **多层次防御（以Fireblocks为代表）**：一种“集最优者于一身”的方法，将先进的MPC密码学与商用硬件（TEE）和多云基础设施相结合。其信任模型建立在各层防御机制的协同作用之上。  
3. **硬件根植与受监管（以Anchorage Digital为代表）**：一种垂直整合的“数字银行”模型，其信任根植于专有的、经过认证的硬件和严格的监管监督。

机构在选择提供商时，不仅仅是在选择一种技术，更是在选择一种与其自身风险模型和合规要求相匹配的安全哲学。此外，这些案例也揭示了“安全性”与“可恢复性”之间的核心设计权衡。Anchorage的HSM模型在密钥存储方面可能最安全，但灵活性稍逊；Coinbase的云备份恢复体验极佳，但将大量信任置于云服务商的安全性上；而Zengo的漏洞恰恰出现在安全与恢复的交汇点。这表明，恢复机制的设计是衡量一个提供商优先级的最重要指标。架构师必须在这个问题上做出明确决策：我们是在优化以抵御攻击下的损失，还是在优化以确保运营故障后的访问？这个问题的答案将决定整个架构的方向。

### **5.5 表3：机构托管提供商安全模型 \- 对比概览**

| 提供商 | 核心架构哲学 | 关键技术栈 | 恢复模型 | 关键差异化/优势 | 主要风险/信任假设 |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **Coinbase WaaS** | 软件定义与可扩展 | 2-of-2 MPC, 云基础设施 | Coinbase辅助备份 (用户云存储 \+ Coinbase验证) | 卓越的用户体验和开发者API，快速上手 | 信任Coinbase的运营安全和用户个人云账户的安全 |
| **Fireblocks** | 多层次深度防御 | MPC-CMP, Intel SGX (TEE), 多云部署 | 软恢复/硬恢复，支持第三方灾难恢复服务 | 专有MPC-CMP协议（支持物理隔离冷存储），硬件隔离的策略引擎 | 信任多层防御的协同效应，信任Intel SGX的安全性 |
| **Anchorage Digital** | 硬件根植与受监管 | 专有HSM, 生物识别认证 | 基于HSM的、有策略控制的恢复流程 | 联邦特许银行身份，策略在HSM固件内强制执行 | 信任其专有硬件和作为受监管实体的运营 |

---

## **第6节：最优解决方案 \- 综合架构蓝图**

本节将综合前述所有分析，提出一个具体的、规范性的最优机构级MPC钱包架构蓝图。

### **6.1 组件选型与理由**

* **MPC协议**：选择一个经过同行评审的、开源的TSS协议（例如，基于GG18/GG20或更新的研究成果），该协议需经过广泛的公开审查。避免使用专有的、闭源的、“以隐晦为安全”的实现。协议必须原生支持密钥更新（resharing）功能。  
* **密钥分片存储**：  
  * **热/温节点（在线签名）**：使用AWS Nitro Enclaves，因其强大的隔离性、成熟的证明模型以及与AWS生态的无缝集成。为实现硬件多样化，节点应分布在至少两种不同的CPU架构上（例如，AWS Graviton/AMD和Intel）\[基于第2节的分析\]。  
  * **冷节点（群体审批的最终保障/高价值交易）**：使用本地部署的、经过FIPS 140-3认证的HSM，并进行物理隔离。  
* **策略引擎**：实现一个独立的、由密码学强制执行的TAP引擎，与签名逻辑分离。策略本身应是一个签名的对象，其执行应在专用的TEE内部进行。  
* **网络**：采用零信任、分段的网络架构，并对所有节点实施逻辑/操作隔离。

### **6.2 综合架构：一个3-of-5的混合模型**

我们推荐一个3-of-5的MPC门限方案，这是一个在安全性、可用性和操作复杂性之间取得良好平衡的配置。其分片分布如下：

* **分片1**：托管于AWS区域A（例如，美东-1）的、基于**Intel** CPU的Nitro Enclave实例中。  
* **分片2**：托管于AWS区域B（例如，欧洲-西-1）的、基于**AMD或Graviton** CPU的Nitro Enclave实例中（实现硬件供应商多样化）。  
* **分片3**：托管于**另一个顶级云服务商**（如Google Cloud或Microsoft Azure）的TEE环境中，位于区域C（实现云服务商多样化）。  
* **分片4**：用户的操作分片，存储在经过严格加固的公司设备上（如专用的工作站或移动设备），用于发起交易请求并提供第一个签名。  
* **分片5**：**冷分片**，存储在本地部署的、物理隔离的HSM中。此分片默认离线，仅在处理超过预设极高价值阈值的交易，或在执行灾难恢复程序时，才通过一个安全的、受控的流程被激活并参与签名。

**工作流示例**：

* **标准交易**：一笔标准价值的交易需要3-of-5的群体批准，通常会使用分片1、2和4。这提供了高可用性和快速的签名体验。  
* **高价值交易**：TAP引擎中的策略可以规定，任何超过1000万美元的交易，其审批群体必须包括分片5。这将强制启动激活冷分片的流程，为高价值操作增加一道极强的安全屏障。

### **6.3 实施路线图与运营最佳实践**

* **阶段一：基础与冷存储**：采购、配置并部署本地HSM。建立安全的网络基础设施和操作系统加固模板。  
* **阶段二：MPC部署**：在多云环境中部署基于TEE的签名节点和TAP引擎。通过一次安全的多方参与的DKG仪式，生成初始的3-of-5密钥分片。  
* **阶段三：策略与治理**：根据第4节的模板，定义并实施完整的TAP策略集。对首批用户和管理员进行培训和上线。  
* **阶段四：运营与维护**：制度化地执行定期的灾难恢复演练、密钥更新计划（例如，每季度一次，或在任何人员变动后立即执行），并实施持续的安全监控。

### **6.4 面向未来：为后量子（PQC）威胁做准备**

一个真正最优的架构必须具备前瞻性，能够应对未来的威胁，其中最紧迫的就是来自量子计算的威胁。

* **威胁：“先采集，后解密” (Harvest Now, Decrypt Later)**：对手正在大规模地记录和存储当前的区块链交易数据。一旦具备足够计算能力的量子计算机问世，他们就可以利用Shor算法，通过这些交易中暴露的公钥来破解ECDSA私钥，从而窃取资金 81。即使是冷存储也无法幸免，因为其公钥在第一次交易时同样会被暴露在链上 81。  
* **解决方案：集成PQC**：架构必须具备“密码学敏捷性”（crypto-agility），能够平滑地过渡到抗量子算法。  
  * **混合签名 (Hybrid Signatures)**：近期的解决方案是转向混合签名方案。每笔交易都需要由两个签名共同验证：一个是由当前MPC协议生成的传统签名（如ECDSA），另一个是由抗量子算法（如NIST推荐的CRYSTALS-Dilithium）生成的PQC签名。  
  * **硬件中的PQC**：PQC的密钥材料也应在同样的安全环境（HSM/TEE）中受到保护。市场上已经开始出现专为此目的设计的新硬件，如SEALSQ的QS7001芯片 81。  
  * **架构影响**：TAP引擎和签名工作流必须进行升级，以支持生成和验证这第二种类型的签名。这代表了一条重要但必要的未来升级路径，以确保钱包的长期安全。

## **结论**

本报告详细阐述了构建一个最优机构级MPC钱包的全面蓝图。其核心结论是，最先进的MPC安全不是一个单一的产品，而是一个动态的、多层次的系统。它将先进的密码学、硬件强制隔离、零信任网络和严格可审计的治理无缝地编织在一起。

我们提出的3-of-5混合模型，将其密钥分片战略性地分布在多个云服务商、多种硬件供应商以及一个物理隔离的HSM之间，代表了这一理念的顶峰。这种架构不仅为抵御当前复杂的外部攻击和内部威胁提供了强大的深度防御，还通过对密钥更新、灾难恢复和后量子密码学的规划，为未来的挑战提供了一条清晰、可行的演进路径。对于任何寻求在数字资产生态系统中安全运营的机构而言，采纳这种整体性的、以防御为中心的方法，将是确保其资产长期安全与业务连续性的关键。

#### **引用的著作**

1. What is an MPC Wallet? A Comprehensive Guide to Enhanced Crypto Security \- CPAY, 访问时间为 七月 9, 2025， [https://cpay.world/blog/what-is-mpc-wallet-a-comprehensive-guide](https://cpay.world/blog/what-is-mpc-wallet-a-comprehensive-guide)  
2. The Beginner's Guide to MPC Wallets \- CoinsDo, 访问时间为 七月 9, 2025， [https://www.coinsdo.com/en/blog/the-beginner-guide-to-mpc-wallets](https://www.coinsdo.com/en/blog/the-beginner-guide-to-mpc-wallets)  
3. What is a Multi-Party Computation (MPC) wallet? \- Coinbase, 访问时间为 七月 9, 2025， [https://www.coinbase.com/learn/wallet/what-is-a-multi-party-computation-mpc-wallet](https://www.coinbase.com/learn/wallet/what-is-a-multi-party-computation-mpc-wallet)  
4. A Complete Guide to the Differences Between MPC Wallets and Multisig Wallets \- Gate.com, 访问时间为 七月 9, 2025， [https://www.gate.com/learn/articles/a-complete-guide-to-the-differences-between-mpc-wallets-and-multisig-wallets/7124](https://www.gate.com/learn/articles/a-complete-guide-to-the-differences-between-mpc-wallets-and-multisig-wallets/7124)  
5. Build secure multi-party computation (MPC) wallets using AWS Nitro Enclaves, 访问时间为 七月 9, 2025， [https://aws.amazon.com/blogs/web3/build-secure-multi-party-computation-mpc-wallets-using-aws-nitro-enclaves/](https://aws.amazon.com/blogs/web3/build-secure-multi-party-computation-mpc-wallets-using-aws-nitro-enclaves/)  
6. An overview of Multi-Signature and Multi-Party Computation \- Dynamic.xyz, 访问时间为 七月 9, 2025， [https://www.dynamic.xyz/blog/the-evolution-of-multi-signature-and-multi-party-computation](https://www.dynamic.xyz/blog/the-evolution-of-multi-signature-and-multi-party-computation)  
7. What is the Threshold Signature Scheme? \- Gate.com, 访问时间为 七月 9, 2025， [https://www.gate.com/learn/articles/threshold-signature-scheme/1950](https://www.gate.com/learn/articles/threshold-signature-scheme/1950)  
8. What Is the Threshold Signature Scheme? \- Crypto APIs, 访问时间为 七月 9, 2025， [https://cryptoapis.io/blog/78-what-is-the-threshold-signature-scheme](https://cryptoapis.io/blog/78-what-is-the-threshold-signature-scheme)  
9. Multisig vs. Shamir's vs. MPC: Institutional-grade bitcoin custody, 访问时间为 七月 9, 2025， [https://www.unchained.com/features/mpc-vs-multisig-vs-sss](https://www.unchained.com/features/mpc-vs-multisig-vs-sss)  
10. Threshold Signature: How it Works And Advantages? \- TotalSig, 访问时间为 七月 9, 2025， [https://www.totalsig.com/blog/threshold-signature-how-it-works-and-advantages](https://www.totalsig.com/blog/threshold-signature-how-it-works-and-advantages)  
11. Threshold Signatures Explained \- Binance Academy, 访问时间为 七月 9, 2025， [https://academy.binance.com/en/articles/threshold-signatures-explained](https://academy.binance.com/en/articles/threshold-signatures-explained)  
12. How MPC Wallets Work: A Complete Guide for All Levels, 访问时间为 七月 9, 2025， [https://cordialsystems.com/post/how-mpc-wallets-work-a-complete-guide-for-all-levels](https://cordialsystems.com/post/how-mpc-wallets-work-a-complete-guide-for-all-levels)  
13. Multi-Sig vs MPC Wallets: A Guide for Institutions (2024) \- Utila, 访问时间为 七月 9, 2025， [https://utila.io/blog/multi-sig-vs-mpc-wallets-a-guide-for-institutions/](https://utila.io/blog/multi-sig-vs-mpc-wallets-a-guide-for-institutions/)  
14. Secure multi-party computation \- Wikipedia, 访问时间为 七月 9, 2025， [https://en.wikipedia.org/wiki/Secure\_multi-party\_computation](https://en.wikipedia.org/wiki/Secure_multi-party_computation)  
15. Multi-Party Computation (MPC): Secure, Private Collaboration \- Cyfrin, 访问时间为 七月 9, 2025， [https://www.cyfrin.io/blog/multi-party-computation-secure-private-collaboration](https://www.cyfrin.io/blog/multi-party-computation-secure-private-collaboration)  
16. Masking-Friendly Post-Quantum Signatures in the Threshold-Computation-in-the-Head Framework \- Cryptology ePrint Archive, 访问时间为 七月 9, 2025， [https://eprint.iacr.org/2025/520](https://eprint.iacr.org/2025/520)  
17. Threshold Implementations Against Side-Channel Attacks and Glitches \- ResearchGate, 访问时间为 七月 9, 2025， [https://www.researchgate.net/publication/220739435\_Threshold\_Implementations\_Against\_Side-Channel\_Attacks\_and\_Glitches](https://www.researchgate.net/publication/220739435_Threshold_Implementations_Against_Side-Channel_Attacks_and_Glitches)  
18. Multisig vs MPC \- Squads Blog, 访问时间为 七月 9, 2025， [https://squads.so/blog/mpc-wallets-risks-vs-multisig](https://squads.so/blog/mpc-wallets-risks-vs-multisig)  
19. MPC vs. Multi-sig Wallets: An Overview \- Kaleido, 访问时间为 七月 9, 2025， [https://www.kaleido.io/blockchain-blog/mpc-vs-multi-sig-wallets-an-overview](https://www.kaleido.io/blockchain-blog/mpc-vs-multi-sig-wallets-an-overview)  
20. MPC vs Multi-Sig Wallets: Which One is Better for Your Crypto? \- OneSafe Blog, 访问时间为 七月 9, 2025， [https://www.onesafe.io/blog/mpc-vs-multi-sig-wallets-digital-asset-security](https://www.onesafe.io/blog/mpc-vs-multi-sig-wallets-digital-asset-security)  
21. Key Differences Between HSM, MPC, and Multi-Sig Wallets Explained \- Liminal Custody, 访问时间为 七月 9, 2025， [https://www.liminalcustody.com/blog/key-differences-between-hsm-mpc-and-multi-sig-wallets-explained/](https://www.liminalcustody.com/blog/key-differences-between-hsm-mpc-and-multi-sig-wallets-explained/)  
22. Digital Asset Management with MPC (Whitepaper) \- Coinbase, 访问时间为 七月 9, 2025， [https://www.coinbase.com/blog/digital-asset-management-with-mpc-whitepaper](https://www.coinbase.com/blog/digital-asset-management-with-mpc-whitepaper)  
23. The Most Secure Crypto Wallet \- Zengo, 访问时间为 七月 9, 2025， [https://zengo.com/security/](https://zengo.com/security/)  
24. CertiK Analyzes ZenGo's Secure Wallet To Uncover a Privileged User Vulnerability, 访问时间为 七月 9, 2025， [https://www.globenewswire.com/news-release/2023/04/05/2641839/0/en/CertiK-Analyzes-ZenGo-s-Secure-Wallet-To-Uncover-a-Privileged-User-Vulnerability.html](https://www.globenewswire.com/news-release/2023/04/05/2641839/0/en/CertiK-Analyzes-ZenGo-s-Secure-Wallet-To-Uncover-a-Privileged-User-Vulnerability.html)  
25. coinbase/cb-mpc \- GitHub, 访问时间为 七月 9, 2025， [https://github.com/coinbase/cb-mpc](https://github.com/coinbase/cb-mpc)  
26. The Difference Between MPC and HSM Wallets with Joanie Xie \- YouTube, 访问时间为 七月 9, 2025， [https://www.youtube.com/watch?v=5NLAmEM8igo](https://www.youtube.com/watch?v=5NLAmEM8igo)  
27. Cloud-Based VS On-Premises HSMs \- Encryption Consulting, 访问时间为 七月 9, 2025， [https://www.encryptionconsulting.com/cloud-based-versus-on-premise-hsm/](https://www.encryptionconsulting.com/cloud-based-versus-on-premise-hsm/)  
28. Securing digital assets: What is HSM and MPC technology? \- Tangany, 访问时间为 七月 9, 2025， [https://tangany.com/blog/securing-digital-assets-what-is-hsm-and-mpc-technology](https://tangany.com/blog/securing-digital-assets-what-is-hsm-and-mpc-technology)  
29. What should a bank choose between HSM and MPC for digital asset custody? \- Taurus SA, 访问时间为 七月 9, 2025， [https://www.taurushq.com/blog/what-should-a-bank-choose-between-tss-mpc-and-hsm-for-digital-asset-custody/](https://www.taurushq.com/blog/what-should-a-bank-choose-between-tss-mpc-and-hsm-for-digital-asset-custody/)  
30. Porto | Self-custody wallet for institutions \- Anchorage Digital, 访问时间为 七月 9, 2025， [https://www.anchorage.com/platform/self-custody](https://www.anchorage.com/platform/self-custody)  
31. Cloud HSM vs On-Premises HSMs: Choosing the Right Encryption Solution \- SignMyCode, 访问时间为 七月 9, 2025， [https://signmycode.com/blog/cloud-hsm-vs-on-premises-hsms-choosing-the-right-encryption-solution](https://signmycode.com/blog/cloud-hsm-vs-on-premises-hsms-choosing-the-right-encryption-solution)  
32. Multi-Sig vs. MPC-CMP vs. HSM Pros and Cons \- Rakkar Digital, 访问时间为 七月 9, 2025， [https://www.rakkardigital.com/post/multi-sig-vs-mpc-cmp-vs-hsm-pros-and-cons](https://www.rakkardigital.com/post/multi-sig-vs-mpc-cmp-vs-hsm-pros-and-cons)  
33. Finding end-to-end security in crypto custody \- Anchorage Digital, 访问时间为 七月 9, 2025， [https://learn.anchorage.com/Finding-End-to-End-Security-in-Crypto-Custody.pdf](https://learn.anchorage.com/Finding-End-to-End-Security-in-Crypto-Custody.pdf)  
34. Solana Projects \> Anchorage Digital, 访问时间为 七月 9, 2025， [https://solanacompass.com/projects/anchorage-digital](https://solanacompass.com/projects/anchorage-digital)  
35. Enclave MPC API \- Portal, 访问时间为 七月 9, 2025， [https://www.portalhq.io/platform/enclave-mpc-api](https://www.portalhq.io/platform/enclave-mpc-api)  
36. Next-level security for digital assets | Edgeless Systems, 访问时间为 七月 9, 2025， [https://www.edgeless.systems/blog/next-level-security-for-digital-assets-how-confidential-computing](https://www.edgeless.systems/blog/next-level-security-for-digital-assets-how-confidential-computing)  
37. AWS Nitro Enclaves, 访问时间为 七月 9, 2025， [https://aws.amazon.com/ec2/nitro/nitro-enclaves/](https://aws.amazon.com/ec2/nitro/nitro-enclaves/)  
38. Build secure multi-party computation (MPC) wallets using AWS Nitro Enclaves, 访问时间为 七月 9, 2025， [https://aws-news.com/article/019428d4-f433-d6ec-e3b9-1313a0a77b2a](https://aws-news.com/article/019428d4-f433-d6ec-e3b9-1313a0a77b2a)  
39. Exploring AWS Nitro Enclaves for Practical Web3 Use-Cases | by Dheeban SG | Medium, 访问时间为 七月 9, 2025， [https://medium.com/@sgdheeban/exploring-aws-nitro-enclaves-for-practical-web3-use-cases-59aab1084a5d](https://medium.com/@sgdheeban/exploring-aws-nitro-enclaves-for-practical-web3-use-cases-59aab1084a5d)  
40. Confidential Kubernetes: Use Confidential Virtual Machines and Enclaves to improve your cluster security, 访问时间为 七月 9, 2025， [https://kubernetes.io/blog/2023/07/06/confidential-kubernetes/](https://kubernetes.io/blog/2023/07/06/confidential-kubernetes/)  
41. Deployment models in confidential computing \- Learn Microsoft, 访问时间为 七月 9, 2025， [https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-computing-deployment-models](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-computing-deployment-models)  
42. Fireblocks' Multi-Layer Digital Asset Security | Fireblocks, 访问时间为 七月 9, 2025， [https://www.fireblocks.com/report/fireblocks-multi-layer-digital-asset-security/](https://www.fireblocks.com/report/fireblocks-multi-layer-digital-asset-security/)  
43. An introduction to confidential computing \- Smals Research, 访问时间为 七月 9, 2025， [https://www.smalsresearch.be/download/presentations/Webinar-An-introduction-to-confidential-computing.pdf](https://www.smalsresearch.be/download/presentations/Webinar-An-introduction-to-confidential-computing.pdf)  
44. Crypto Enterprise-Grade Security Platform \- Fireblocks, 访问时间为 七月 9, 2025， [https://www.fireblocks.com/platforms/security/](https://www.fireblocks.com/platforms/security/)  
45. What Is a Threshold Signature Wallet: Advantages and Disadvantages \- TotalSig, 访问时间为 七月 9, 2025， [https://www.totalsig.com/blog/what-is-a-threshold-signature-wallet](https://www.totalsig.com/blog/what-is-a-threshold-signature-wallet)  
46. How Fireblocks Is Innovating MPC Wallet Technology \- SecuritySenses, 访问时间为 七月 9, 2025， [https://securitysenses.com/videos/how-fireblocks-innovating-mpc-wallet-technology](https://securitysenses.com/videos/how-fireblocks-innovating-mpc-wallet-technology)  
47. Secure Institutional Crypto Wallet Solutions \- Blockdaemon, 访问时间为 七月 9, 2025， [https://www.blockdaemon.com/mpc-wallets-and-vaults/institutional-vault](https://www.blockdaemon.com/mpc-wallets-and-vaults/institutional-vault)  
48. Air gap (networking) \- Wikipedia, 访问时间为 七月 9, 2025， [https://en.wikipedia.org/wiki/Air\_gap\_(networking)](https://en.wikipedia.org/wiki/Air_gap_\(networking\))  
49. What Is an Air-Gapped Backup and How to Use It? \- NAKIVO, 访问时间为 七月 9, 2025， [https://www.nakivo.com/blog/air-gap-backup/](https://www.nakivo.com/blog/air-gap-backup/)  
50. The Role of Air Gaps in Cyber Resilience | DataCore Software, 访问时间为 七月 9, 2025， [https://www.datacore.com/blog/the-role-of-air-gaps-in-cyber-resilience/](https://www.datacore.com/blog/the-role-of-air-gaps-in-cyber-resilience/)  
51. What Are Air Gaps and Are They Effective Data Security Strategies? \- Pure Storage Blog, 访问时间为 七月 9, 2025， [https://blog.purestorage.com/perspectives/what-are-air-gaps-and-are-they-effective-data-security-strategies/](https://blog.purestorage.com/perspectives/what-are-air-gaps-and-are-they-effective-data-security-strategies/)  
52. Data Isolation and Air Gapping \- Commvault Documentation, 访问时间为 七月 9, 2025， [https://documentation.commvault.com/11.20/data\_isolation\_and\_air\_gapping\_01.html](https://documentation.commvault.com/11.20/data_isolation_and_air_gapping_01.html)  
53. 5 Tips to Harden Your OS On-Prem or in the Cloud \- CIS Center for Internet Security, 访问时间为 七月 9, 2025， [https://www.cisecurity.org/insights/blog/5-tips-for-securing-systems-on-prem-or-in-the-cloud](https://www.cisecurity.org/insights/blog/5-tips-for-securing-systems-on-prem-or-in-the-cloud)  
54. OS Hardening: 15 Best Practices \- Perception Point, 访问时间为 七月 9, 2025， [https://perception-point.io/guides/os-isolation/os-hardening-10-best-practices/](https://perception-point.io/guides/os-isolation/os-hardening-10-best-practices/)  
55. Operating System Hardening 20 Best Practices \- CalCom Software, 访问时间为 七月 9, 2025， [https://calcomsoftware.com/os-hardening-20-best-practices/](https://calcomsoftware.com/os-hardening-20-best-practices/)  
56. Guidelines for system hardening | Cyber.gov.au, 访问时间为 七月 9, 2025， [https://www.cyber.gov.au/resources-business-and-government/essential-cybersecurity/ism/cybersecurity-guidelines/guidelines-system-hardening](https://www.cyber.gov.au/resources-business-and-government/essential-cybersecurity/ism/cybersecurity-guidelines/guidelines-system-hardening)  
57. Applications Beyond Key Management \- Turnkey Whitepaper, 访问时间为 七月 9, 2025， [https://whitepaper.turnkey.com/applications](https://whitepaper.turnkey.com/applications)  
58. Secure MPC-based Path-Following for UAS in Adverse Network Environment | Request PDF, 访问时间为 七月 9, 2025， [https://www.researchgate.net/publication/368407481\_Secure\_MPC-based\_Path-Following\_for\_UAS\_in\_Adverse\_Network\_Environment](https://www.researchgate.net/publication/368407481_Secure_MPC-based_Path-Following_for_UAS_in_Adverse_Network_Environment)  
59. Exploring the Efficiency of MPC Algorithms in Crypto Wallets \- CertiK, 访问时间为 七月 9, 2025， [https://www.certik.com/resources/blog/exploring-the-efficiency-of-mpc-algorithms-in-crypto-wallets](https://www.certik.com/resources/blog/exploring-the-efficiency-of-mpc-algorithms-in-crypto-wallets)  
60. MPC Bitcoin Security: Complete Guide for 2025 | Xapo Bank, 访问时间为 七月 9, 2025， [https://www.xapobank.com/en/blog/mpc-bitcoin-security-guide](https://www.xapobank.com/en/blog/mpc-bitcoin-security-guide)  
61. Pricing \- MPC Vault, 访问时间为 七月 9, 2025， [https://mpcvault.com/pricing](https://mpcvault.com/pricing)  
62. Introduction \- Developer Hub \- Cobo Wallet, 访问时间为 七月 9, 2025， [https://www.cobo.com/developers/v1/overview/mpc-wallet/mpc-introduction](https://www.cobo.com/developers/v1/overview/mpc-wallet/mpc-introduction)  
63. Whitelist an address \- Liminal overview, 访问时间为 七月 9, 2025， [https://docs.lmnl.app/v2/docs/add-whitelist-address-1](https://docs.lmnl.app/v2/docs/add-whitelist-address-1)  
64. FORDEFI \- Institutional MPC Wallet, 访问时间为 七月 9, 2025， [https://fordefi.com/](https://fordefi.com/)  
65. MPCVault | MPC-Multisig crypto wallet for teams, 访问时间为 七月 9, 2025， [https://mpcvault.com/](https://mpcvault.com/)  
66. What is the Encryption Key Management Lifecycle? \- Thales CPL, 访问时间为 七月 9, 2025， [https://cpl.thalesgroup.com/faq/key-secrets-management/what-encryption-key-management-lifecycle](https://cpl.thalesgroup.com/faq/key-secrets-management/what-encryption-key-management-lifecycle)  
67. Key Management Lifecycle \- NIST Computer Security Resource Center, 访问时间为 七月 9, 2025， [https://csrc.nist.gov/csrc/media/events/key-management-workshop-2001/documents/lifecycle-slides.pdf](https://csrc.nist.gov/csrc/media/events/key-management-workshop-2001/documents/lifecycle-slides.pdf)  
68. What is proactive secret sharing scheme? \- Cryptography Stack Exchange, 访问时间为 七月 9, 2025， [https://crypto.stackexchange.com/questions/50904/what-is-proactive-secret-sharing-scheme](https://crypto.stackexchange.com/questions/50904/what-is-proactive-secret-sharing-scheme)  
69. Resharing Shamir Secret Shares to Change the Threshold \- Conduition, 访问时间为 七月 9, 2025， [https://conduition.io/cryptography/shamir-resharing/](https://conduition.io/cryptography/shamir-resharing/)  
70. Key Re-sharing \- HackMD, 访问时间为 七月 9, 2025， [https://hackmd.io/@matan/key-resharing](https://hackmd.io/@matan/key-resharing)  
71. Key Lifecycle Management \- Builder Vault TSM \- Blockdaemon, 访问时间为 七月 9, 2025， [https://builder-vault-tsm.docs.blockdaemon.com/docs/key-lifecycle-management](https://builder-vault-tsm.docs.blockdaemon.com/docs/key-lifecycle-management)  
72. Disaster Recovery Services: A New Standard for Digital Asset Security \- Fireblocks, 访问时间为 七月 9, 2025， [https://www.fireblocks.com/blog/disaster-recovery-services-new-standard-digital-asset-security/](https://www.fireblocks.com/blog/disaster-recovery-services-new-standard-digital-asset-security/)  
73. Digital Asset Custody and Transaction Processing Leading ..., 访问时间为 七月 9, 2025， [https://www.fireblocks.com/report/digital-asset-custody-and-transaction-processing-leading-practices-using-fireblocks-mpc-solution/](https://www.fireblocks.com/report/digital-asset-custody-and-transaction-processing-leading-practices-using-fireblocks-mpc-solution/)  
74. ZenGo Slides with CertiK \- Finalized for PDF, 访问时间为 七月 9, 2025， [https://zengo.com/wp-content/uploads/Zengo-Certik-Audit-2023-.pdf](https://zengo.com/wp-content/uploads/Zengo-Certik-Audit-2023-.pdf)  
75. Ledger Key Recovery: Understanding the Principles of MPC Wallets | by Numen Cyber Labs, 访问时间为 七月 9, 2025， [https://medium.com/numen-cyber-labs/ledger-key-recovery-understanding-the-principles-of-mpc-wallets-dc2eacfd39f3](https://medium.com/numen-cyber-labs/ledger-key-recovery-understanding-the-principles-of-mpc-wallets-dc2eacfd39f3)  
76. Building user-focused web3 wallets at Coinbase, 访问时间为 七月 9, 2025， [https://www.coinbase.com/blog/building-user-focused-web3-wallets-at-coinbase](https://www.coinbase.com/blog/building-user-focused-web3-wallets-at-coinbase)  
77. Crypto Custody for Institutions \- Anchorage Digital, 访问时间为 七月 9, 2025， [https://www.anchorage.com/platform/custody](https://www.anchorage.com/platform/custody)  
78. How Zengo Security Model Works, 访问时间为 七月 9, 2025， [http://help.zengo.com/en/articles/2603678-how-zengo-security-model-works](http://help.zengo.com/en/articles/2603678-how-zengo-security-model-works)  
79. Crypto & Bitcoin Wallet: Signature Security Standards \- Zengo, 访问时间为 七月 9, 2025， [https://zengo.com/security-in-depth/](https://zengo.com/security-in-depth/)  
80. Fortifying ZenGo: Unearthing and Defending Against Privileged User Attacks \- CertiK, 访问时间为 七月 9, 2025， [https://www.certik.com/resources/blog/fortifying-zengo-unearthing-and-defending-against-privileged-user-attacks](https://www.certik.com/resources/blog/fortifying-zengo-unearthing-and-defending-against-privileged-user-attacks)  
81. SEALSQ Post-Quantum Secure Chip Safeguards Crypto Wallets ..., 访问时间为 七月 9, 2025， [https://www.sealsq.com/investors/news-releases/sealsq-post-quantum-secure-chip-safeguards-crypto-wallets-against-emerging-quantum-threats](https://www.sealsq.com/investors/news-releases/sealsq-post-quantum-secure-chip-safeguards-crypto-wallets-against-emerging-quantum-threats)  
82. Cryptocurrencies and Quantum Computers \- Coinbase, 访问时间为 七月 9, 2025， [https://www.coinbase.com/blog/cryptocurrencies-and-quantum-computers](https://www.coinbase.com/blog/cryptocurrencies-and-quantum-computers)