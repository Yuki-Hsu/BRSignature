# BRSignature
📝📝📝A so called blind ring signature

## 笔记

### 编写步骤

#### 安装 Miracl

> https://github.com/miracl/MIRACL

1. 解压所有文件至同一个文件夹

2. 运行`mingw.bat`，电脑提前配置好 gcc

3. 得到`miracl.a`静态链接库，和定制化的`mirdef.h`

#### 编码

1. 拷贝`miracl.a`，`miracl.h`，`mirdef.h`至编码目录

2. 根据需求包含相关的头文件
```
#include "miracl.h"
#include "mirdef.h"    // not always necessary
```

### 使用说明

1. 拷贝相关文件至工作目录

2. 编译`g++ -O2 BRSign.cpp ss2_pair.cpp ec2.cpp gf2m4x.cpp gf2m.cpp big.cpp miracl.a`

3. 参考
> https://github.com/miracl/MIRACL/blob/master/source/curve/pairing/sk_1.cpp
https://en.wikipedia.org/wiki/Sakai%E2%80%93Kasahara_scheme
https://en.bitcoin.it/wiki/Secp256k1
http://www.sikoba.com/docs/SKOR_SV_Pairing_Based_Crypto.pdf
https://groups.google.com/forum/#!topic/pbc-devel/DvDvziTTwFk
