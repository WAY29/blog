# Data Flow Analysis - Applications

## overview
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125100124.png)

## Overview of Data Flow Analysis
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125100445.png)
Over- and under-approximations are both for safety of analysis (这两种近似都是对于分析来说都是safety的)
### may analysis / over-approximation
outputs information that may be true, it works for most static analyses (输出的信息可能是正确的，它适用于绝大多数的静态分析)

### must analysis / under-approximation
outputs information that must be true (输出的信息必须是正确的)


### for example
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125101744.png)
different data-flow analysis applications have different data abstraction and different flow safe-approximation strategies, i.e., different transfer functions and control-flow handlings (不同的数据流分析有不同的数据抽象，不同的flow safe-approximation，不同的转换函数和不同的控制流处理)

以第一节课的符号静态分析为例(即分析变量的符号为正，负，零，未知，还是未定义)
1. 这里的application-specific Data为我们关注的符号
2. 这里的transfer function为符号运算规则(如正正得正，正负得负)
3. 这里的control-flow handling为将这些符号合并起来，得到符号可能的结果

### three key points
1. Abstract application-specific Data(抽象出我们关注的数据)
2. Describe transfer function(描述转换函数)
3. Control-flow handling(处理控制流)

## Preliminaries of Data Flow Analysis
### Input and Output States
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125103337.png)

- Each execution of an IR statement transforms an input state to a new output state(每个语句的执行都会将一个input状态转换为一个新的output状态)
- The input (output) state is associated with the program point before (after) the statement (Input/output状态是与语句执行前/后的程序点相关联的)

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125104337.png)

- In each data-flow analysis application, we associate with every program point a data-flow value that represents an abstraction of the set of all possible program states that can be observed for that point.(在每个数据流分析应用程序中，我们将每个程序点与一个数据流值关联起来，这个数据流值表示可以观察到的所有可能的程序状态集的抽象)
- The set of possible dataflow values is the domain for this application(可能的数据流值集是此应用程序的域)
- Data-flow analysis is to find a solution to a set of safe-approximationdirected constraints on the IN[s]’s and OUT[s]’s, for all statements.(数据流分析就是为所有语句的IN和OUT找到一组safe-approximationdirected的约束的解决方案)
    - constraints based on semantics of statements (transfer functions) (约束基于语句语义)
    - constraints based on the flows of control (约束基于控制流)

还是以第一节课的符号静态分析为例:
- 我们关注的是符号，所以此应用程序的域就为这几个符号
- 在每次语句执行后，我们关注此程序点的变量(x,y)的所有可能符号

### Notations for Transfer Function’s Constraints
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125105519.png)

1. Forward Analysis(正向分析)
2. Backward Analysis(反向分析)

### Notations for Control Flow’s Constraints
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125110254.png)

The meet operator ^ is used to summarize the contributions from different paths at the confluence of those paths (交运算符 ^ 是用于汇总不同路径在汇合处的结果)

## Reaching Definitions
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125110449.png)

> A definition d at program point p reaches a point q if there is a path from p to q such that d is not “killed” along that path(可达定义分析就是指一个定义d在程序点p能否到达程序点q，即是否存在一条从p到q且在途中d没被杀死的路径)
- A definition of a variable v is a statement that assigns a value to v(变量 v 的定义是一个给v赋值的语句)
- Translated as: definition of variable v at program point p reaches point q if there is a path from p to q such that no new definition of v appears on that path(换句话说: 如果存在从 p 到 q 的路径，使得在这条路径上不会出现新的 v 的定义，则定义d可从p抵达q)
- Reaching definitions can be used to detect possible undefined variables. e.g., introduce a dummy definition for each variable v at the entry of CFG, and if the dummy definition of v reaches a point p where v is used, then v may be used before definition (as undefined reaches v) (可以使用可达定义分析可能的未定义变量。例如，在 CFG 的入口处为每个变量 v 引入一个虚拟定义，如果 v 的虚拟定义达到一个点 p，那么v可能在定义之前使用)

### Understanding Reaching Definitions
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125111301.png)

我们需要对我们关注的数据进行抽象，在这里我们关注的是所有变量的定义，我们可以使用比特流来表示，比如D1，D2，D3，D4，...，D100，我们可以使用一个100位的比特流来表示，从左数第i个Bit代表第i个定义是否可到达(0为不可达，1为可达)

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125111809.png)

以一个我们关注的，简单的定义语句为例，这条定义语句D定义了变量v并且杀死了在程序中其他定义v的语句，所以我们可以写出:
- transfer function: `OUT[B] = genB U (IN[B] - killB)`

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125112539.png)
这里是一个简单的例子，用于理解transfer function

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125113210.png)
A definition reaches a program point as long as there exists at least one path along which the definition reaches.(只要存在至少一条定义到达的路径，定义就到达了程序点)

### Algorithm of Reaching Definitions Analysis
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125113511.png)

#### for example
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125114110.png)

经过三轮的迭代之后最后到达一个稳态，所有的IN和OUT都不再变化，此时为最终结果

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125114513.png)

### Why this iterative algorithm can finally stop?
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125142920.png)

1. 首先gen和kill是常量，是不可变的
2. 当"more facts"流入IN时，"more facts"要么被杀死，要么流向OUT，我们称为survivor
3. 当"fact"流入OUT时，无论它是生成的(gen)还是存活的(survivor)，它都将永远留在OUT中
4. 直到OUT永远不变(0->1, 1->1)
5. 由于fact集是有限的(例如: 程序中的所有定义) ，因此必然存在一个迭代过程，在此过程中没有向任何 OUT 添加任何内容，然后算法终止

### Safe to terminate by this condition?
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220125144340.png)

1. 当OUT不改变时IN不会改变
2. 当IN不改变时OUT不会改变
3. 他们最终会到达一个不动点(这也与单调性有关)  
