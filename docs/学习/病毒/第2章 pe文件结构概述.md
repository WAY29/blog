# pe文件结构概述
## pe文件结构
### 总体结构
![](https://gitee.com/guuest/images/raw/master/img/20210616101909.png)

![](https://gitee.com/guuest/images/raw/master/img/20210616102130.png)

![](https://gitee.com/guuest/images/raw/master/img/20210616102607.png)

![](https://gitee.com/guuest/images/raw/master/img/20210616102803.png)
### MS DOS 文件头

![](https://gitee.com/guuest/images/raw/master/img/20210616103407.png)
### PE签名
这一字段占`0x004`字节，为固定子字串”PE\0\0”，即`50 45 00 00`，标志着PE文件头的开始

![](https://gitee.com/guuest/images/raw/master/img/20210616125125.png)

### 映像文件头
```
typedef struct _IMAGE_FILE_HEADER
{
    WORD  Machine;                         //每个CPU都拥有唯一的machine码
    WORD  NumberOfSections;                //节区数量，当定义节区数与实际不同时会发生错误
    DWORD  TimeDateStamp;
    DWORD  PointerToSymbolTable;
    DWORD  NumberOfSymbols;
    WORD  SizeOfOptionalHeader;            //可选映像头的大小，固定的
    WORD  Characteristics;                 //文件属性，0x0002h为可执行文件，0x2000h为DLL文件
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEAD
```
![](https://gitee.com/guuest/images/raw/master/img/20210616124852.png)
-   `offset 0xB6-0xB7`：该字段为NumberOfSections，定义了节区的数量，在这里的值为`0x0003`，说明该程序含有三个节区
-   `offset 0xC4-0xC5`：该字段为SizeOfOptionalHeader，定义了可选映像头（OptionalHeader）的大小，在这里的值为`0x00E0`
### 可选映像文件头
```
typedef struct _IMAGE_OPTIONAL_HEADER {
WORD    Magic;            //标志字(32位时0x10Bh)
BYTE    MajorLinkerVersion;        //连接器主版本号
BYTE    MinorLinkerVersion;        //连接器次版本号
DWORD   SizeOfCode;            //代码段大小
DWORD   SizeOfInitializedData;    //已初始化数据块大小
DWORD   SizeOfUninitializedData;    //未初始化数据块大小
DWORD   AddressOfEntryPoint;     //EP的RVA值，程序最先执行代码的地址
DWORD   BaseOfCode;            //代码段起始RVA
DWORD   BaseOfData;            //数据段起始RVA
DWORD   ImageBase;            //PE文件的装载地址
DWORD   SectionAlignment;        //块对齐，节区在内存中最小单位
DWORD   FileAlignment;        //文件块对齐，节区在文件中的最小单位
WORD    MajorOperatingSystemVersion;//所需操作系统版本号
WORD    MinorOperatingSystemVersion;//
WORD    MajorImageVersion;        //用户自定义主版本号
WORD    MinorImageVersion;        //用户自定义次版本号
WORD    MajorSubsystemVersion;    //win32子系统版本。若PE文件是专门为Win32设计的
WORD    MinorSubsystemVersion;    //该子系统版本必定是4.0否则对话框不会有3维立体感
DWORD   Win32VersionValue;        //保留
DWORD   SizeOfImage;            //内存中整个PE映像体的尺寸
DWORD   SizeOfHeaders;        //所有头+节表的大小，即整个PE头的大小
DWORD   CheckSum;            //校验和
WORD    Subsystem;            //NT用来识别PE文件属于哪个子系统（系统驱动、GUI、CUI）
WORD    DllCharacteristics;        
DWORD   SizeOfStackReserve;        
DWORD   SizeOfStackCommit;        
DWORD   SizeOfHeapReserve;        
DWORD   SizeOfHeapCommit;        
DWORD   LoaderFlags;            
DWORD   NumberOfRvaAndSizes;    //指定DataDirectory数组的个数
IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];//IMAGE_DATA_DIRECTORY 结构数组。每个结构给出一个重要数据结构的RVA，比如引入地址表等
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```
![](https://gitee.com/guuest/images/raw/master/img/20210616130351.png)
-   `offset 0xD8-0xDB`：该字段为AddressOfEntryPoint，定义了文件开始执行位置的相对虚拟地址（RVA），在这里的值为`0x00001000`
-   `offset 0xE4-0xE7`：该字段为ImageBase，定义了可执行文件默认装入的内存地址，在这里的值为`0x00400000`
-   `offset 0x124-0x127`：该字段为NumberOfRvaAndSizes，指示了数据目录项（DataDirectory）的项数，在这里的值为`0x00000010`，即16项
-   `offset 0x128-0x1A7`：该字段为DataDirectory，是一个IMAGE\_DATA\_DIRECTORY数组，里面存放的是可执行文件的一些重要部分的起始RVA和尺寸，目的是使可执行文件更快地进行装载
### DataDirectory
第0个元素是 导出表的地址和大小，第1个元素是导⼊表的地址和大小
每个元素的前4个字节是地址RVA，后4个字节是表的大小
### 节表
紧接着PE文件头的是节表。节表实际上是一个结构数组，每个结构包含了一个节的具体信息（每个结构占用`0x28`字节），该结构的内容如下：
```
#define IMAGE_SIZEOF_SHORT_NAME 8
typedef struct _IMAGE_SECTION_HEADER{ 
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME]; // 8个字节的节区名称  
    union {  
        DWORD PhysicalAddress;         
        DWORD VirtualSize;            //内存中节区的大小
    } Misc; 
    DWORD VirtualAddress;         // 内存中节区的起始地址（RVA）  
    DWORD SizeOfRawData;            // 磁盘中文件中节区所占大小
    DWORD PointerToRawData;        // 磁盘中文件的起始位置  
    DWORD PointerToRelocations;     // 在OBJ文件中使用，重定位的偏移  
    DWORD PointerToLinenumbers;   // 行号表的偏移（供调试使用地）  
    WORD NumberOfRelocations;      // 在OBJ文件中使用，重定位项数目  
    WORD NumberOfLinenumbers;    // 行号表中行号的数目  
    DWORD Characteristics;       // 节属性如可读，可写，可执行等  
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```
###  .text节表

其中比较重要的几个字段：

-   `offset 0x1A8-0x1AF`：该字段为Name，可以从ASCII码值看出该节表对应的节为.text节
-   `offset 0x1B0-0x1B3`：该字段在exe文件中为Virtual-Size，表示节的实际字节数，这里的值为`0x00000046`字节
-   `offset 0x1B4-0x1B7`：该字段为VirtualAddress，表示本节起始的相对虚拟地址（RVA），这里的值为`0x00001000`
-   `offset 0x1BC-0x1BF`：该字段为PointerToRawData，表示本节在磁盘中对齐后的位置，这里的值为`0x00000400`
-   `offset 0x1CC-0x1CF`：该字段为Characteristic，表示该节的属性，这里的值为`0x60000020 = 0x40000000 + 0x20000000 + 0x20`，表示的意义是该节包含代码，并且可读可执行

### .rdata节表

其中比较重要的几个字段：

-   `offset 0x1D0-0x1D7`：该字段为Name，可以从ASCII码值看出该节表对应的节为.rdata节
-   `offset 0x1D8-0x1DB`：该字段在exe文件中为Virtual-Size，表示节的实际字节数，这里的值为`0x000000A6`字节
-   `offset 0x1DC-0x1DF`：该字段为VirtualAddress，表示本节起始的相对虚拟地址（RVA），这里的值为`0x00002000`
-   `offset 0x1E4-0x1E7`：该字段为PointerToRawData，表示本节在磁盘中对齐后的位置，这里的值为`0x00000600`
-   `offset 0x1F0-0x1F7`：该字段为Characteristic，表示该节的属性，这里的值为`0x40000040 = 0x40000000 + 0x40`，表示的意义是该节包含已初始化的数据，并且可读

### .data节表

-   `offset 0x1F8-0x1FF`：该字段为Name，可以从ASCII码值看出该节表对应的节为.data节
-   `offset 0x200-0x203`：该字段在exe文件中为Virtual-Size，表示节的实际字节数，这里的值为`0x0000008E`字节
-   `offset 0x204-0x207`：该字段为VirtualAddress，表示本节起始的相对虚拟地址（RVA），这里的值为`0x00003000`
-   `offset 0x20C-0x20F`：该字段为PointerToRawData，表示本节在磁盘中对齐后的位置，这里的值为`0x00000800`
-   `offset 0x21C-0x21F`：该字段为Characteristic，表示该节的属性，这里的值为`0xC0000040 = 0x80000000 + 0x40000000 + 0x30`，表示的意义是该节包含已初始化的数据，并且可读可写

### .text节
这一节含有程序的可执行代码，根据节表中的值，可以确定.text节在文件中的地址为`0x00000400`，实际长度为`0x46`字节，具体代码如下：
![](https://gitee.com/guuest/images/raw/master/img/20210616132646.png)
### .rdata节
这一节称为引入函数节，包含有从其他DLL中引入的函数，根据IMAGE\_DATA\_DIRECTORY中引入函数表地址为`0x00002014`，且根据节表，该表在内存中的偏移为`0x00002000`，即RVA为`0x0`。根据节表，该节从文件偏移`0x600`处开始，那么.rdata表在文件中的偏移就为`0x614`。大小为`0xA6`字节。
###  .data节
.data节称为已初始化的数据节，其中存放的是在编译时刻已经确定的数据。可以从节表中知道，该节从文件偏移`0x800`处开始，实际大小为`0x8E`字节。