# Intermediate Representation(中间语言)

## Compilers and Static Analyzers
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220119223655.png)

1. Source Code -> Lexical Analysis(词法分析) -> Tokens
2. Tokens -> Syntax Analysis(语法分析) -> AST  
3. AST -> Semantic Analysis(语义分析) -> Decorated AST
4. Decorated AST -> Translator(翻译) -> IR
5. IR -> Static Analysis(静态分析) -> Code Generator -> Machine Code
## AST vs. IR
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220119225105.png)

### AST
- high-level and closed to grammar structure (高级并更接近于语法结构)
- usually language dependent (通常存在语言依赖，即每种语言的AST结构不同)
- suitable for fast type checking(更适合于快速类型检查)
- lack of control flow information(缺少控制流信息)
### IR
- low-level and closed to machine code (低级并更接近于机器语言)
- usually language independent (通常没有语言依赖，即每种语言的IR结构大致相同)
- compact and uniform (紧凑而且整齐)
- contains control flow information (包含控制流信息)
- usually considered as the basis for static analysis (通常用于静态分析的基础)

## IR: Three-Address Code (3AC)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220119225257.png)

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220120130244.png)

### 特征
1. 在右侧最多有一个操作符
2. 通常是比较简单的语句(?个人理解)
3. 最多包含三个address(?个人理解为对象)

## 3AC in Real Static Analyzer: Soot
Soot是最流行的java静态代码分析工具，它的IR是Jimple(typed 3AC)



## Static Single Assignment (SSA)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220120131323.png)
All assignments in SSA are to variables with distinct names(在SSA中的所有赋值都指向一个新的名字)

### Every variable has exactly one definition(每个变量都有且仅有一个确切的定义?)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220120131647.png)
当有条件语句时例外，需要引入phi-function这个标记用于合并多个节点的值

### Why SSA
- Flow information is indirectly incorporated into the unique variable names(流信息间接并入了独立的变量名中) May help deliver some simpler analyses, e.g., flow-insensitive analysis gains partial precision of flow-sensitive analysis via SSA(可能可以帮助程序更简单地进行分析，，比如通过SSA，流信息不敏感的分析获得了流信息敏感分析的部分精度)
- Define-and-Use pairs are explicit (定义和使用对更加明确) Enable more effective data facts storage and propagation in some on-demand tasks (在一些按需任务中允许更有效的数据的存储和传播) Some optimization tasks perform better on SSA (e.g., conditional constant propagation, global value numbering) (一些优化项目在SSA上完成得更好)
### Why not SSA
- SSA may introduce too many variables and phi-functions(SSA可能会引入太多的变量和phi-function)
- May introduce inefficiency problem when translating to machine code (due to copy operations) (可能会在翻译成机器码时导致效率低下的问题(由于复制操作) )

## Basic Blocks (BB)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220120145651.png)
Basic blocks (BB) are maximal sequences of consecutive three-address instructions with the properties that: (基础块 (BB) 是三地址码(3AC)的连续最大序列，它具有以下的性质)
- It can be entered only at the beginning, i.e., the first instruction in the block (有且只有一个入口，是块的第一个3AC)
- It can be exited only at the end, i.e., the last instruction in the block (有且只有一个出口，是块的最后一个AC)

**划分Basic blocks的关键是goto(跳转指令)**，具体划分方法如下:
1. 我们把BB中的第一个3AC称为leader，划分BB转为寻找所有的leader
2. 第一个3AC为leader
3. 寻找所有goto，其目标3AC即为leader
4. 寻找所有goto，其下一个3AC也是leader
5. 去重之后找到所有的leader，从一个leader到下一个leader之前即为一个BB

## Control Flow Graphs (CFG)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220120195140.png)

- The nodes of CFG are basic blocks(CFG的最小节点是BB)
- There is an edge from block A to block B if and only if(从块A到块B的跳转方式只有if)
    - There is a conditional or unconditional jump from the end of A to the beginning of B(从块A到块B的跳转方式只有有条件的或无条件的jump)
    - B immediately follows A in the original order of instructions and A does not end in an unconditional jump(块B按照顺序紧跟在块A之后且A不是以一个无条件的跳转作为结尾)

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220120195503.png)
我们称块A为块B的前趋，块B为块A的后继

**最终目的: 将一段3AC转为CFG**
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220120195537.png)
