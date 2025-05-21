
### 研读代码
**第一题需要实现**：UseAfterFree释放后使用、HeapBufferOverflow内存访问越界、DoubleFree无效释放的捕获，输出日志包括调用栈、内存大小、内存地址、当前的进程名称  
**Kfence机制**：  
1. Slab内存分配机制： [知乎参考网页](https://zhuanlan.zhihu.com/p/358891862#:~:text=slab%20%E5%88%86%E9%85%8D%E5%99%A8%E4%B8%93%E4%B8%BA%E5%B0%8F%E5%86%85%E5%AD%98%E5%88%86%E9%85%8D%E8%80%8C%E7%94%9F%EF%BC%8C%E7%94%B1Sun%E5%85%AC%E5%8F%B8%E7%9A%84%E4%B8%80%E4%B8%AA%E9%9B%87%E5%91%98%20Jeff%20Bonwick%20%E5%9C%A8%20Solaris%202.4%20%E4%B8%AD%E8%AE%BE%E8%AE%A1%E5%B9%B6%E5%AE%9E%E7%8E%B0%E3%80%82,Buddy%20%E5%88%86%E9%85%8D%E5%99%A8%E4%B8%AD%E7%94%B3%E8%AF%B7%E5%86%85%E5%AD%98%EF%BC%8C%E4%B9%8B%E5%90%8E%E8%87%AA%E5%B7%B1%E5%AF%B9%E7%94%B3%E8%AF%B7%E6%9D%A5%E7%9A%84%E5%86%85%E5%AD%98%E7%BB%86%E5%88%86%E7%AE%A1%E7%90%86%E3%80%82%20%E9%99%A4%E4%BA%86%E6%8F%90%E4%BE%9B%E5%B0%8F%E5%86%85%E5%AD%98%E5%A4%96%EF%BC%8Cslab%20%E5%88%86%E9%85%8D%E5%99%A8%E7%9A%84%E7%AC%AC%E4%BA%8C%E4%B8%AA%E4%BB%BB%E5%8A%A1%E6%98%AF%E7%BB%B4%E6%8A%A4%E5%B8%B8%E7%94%A8%E5%AF%B9%E8%B1%A1%E7%9A%84%E7%BC%93%E5%AD%98%E3%80%82%20%E5%AF%B9%E4%BA%8E%E5%86%85%E6%A0%B8%E4%B8%AD%E4%BD%BF%E7%94%A8%E7%9A%84%E8%AE%B8%E5%A4%9A%E7%BB%93%E6%9E%84%EF%BC%8C%E5%88%9D%E5%A7%8B%E5%8C%96%E5%AF%B9%E8%B1%A1%E6%89%80%E9%9C%80%E7%9A%84%E6%97%B6%E9%97%B4%E5%8F%AF%E7%AD%89%E4%BA%8E%E6%88%96%E8%B6%85%E8%BF%87%E4%B8%BA%E5%85%B6%E5%88%86%E9%85%8D%E7%A9%BA%E9%97%B4%E7%9A%84%E6%88%90%E6%9C%AC%E3%80%82%20%E5%BD%93%E5%88%9B%E5%BB%BA%E4%B8%80%E4%B8%AA%E6%96%B0%E7%9A%84slab%20%E6%97%B6%EF%BC%8C%E8%AE%B8%E5%A4%9A%E5%AF%B9%E8%B1%A1%E5%B0%86%E8%A2%AB%E6%89%93%E5%8C%85%E5%88%B0%E5%85%B6%E4%B8%AD%E5%B9%B6%E4%BD%BF%E7%94%A8%E6%9E%84%E9%80%A0%E5%87%BD%E6%95%B0%EF%BC%88%E5%A6%82%E6%9E%9C%E6%9C%89%EF%BC%89%E8%BF%9B%E8%A1%8C%E5%88%9D%E5%A7%8B%E5%8C%96%E3%80%82%20%E9%87%8A%E6%94%BE%E5%AF%B9%E8%B1%A1%E5%90%8E%EF%BC%8C%E5%AE%83%E4%BC%9A%E4%BF%9D%E6%8C%81%E5%85%B6%E5%88%9D%E5%A7%8B%E5%8C%96%E7%8A%B6%E6%80%81%EF%BC%8C%E8%BF%99%E6%A0%B7%E5%8F%AF%E4%BB%A5%E5%BF%AB%E9%80%9F%E5%88%86%E9%85%8D%E5%AF%B9%E8%B1%A1%E3%80%82)。  
   1. Buddy 分配器以页为单位管理和分配内存，但内核却要求以字节为单位（在内核中面临频繁的结构体内存分配问题，分配一页非常浪费）。假如需要一个内核结构体(20B)，就需要slab分配器来**分配小内存**。slab 分配器仍然从 Buddy 分配器中申请内存，之后自己对申请来的内存细分管理。  
   2. **维护常用对象的缓存**。小内存的对象初始化所需的时间可等于或超过为其分配空间的成本。当创建一个新的slab 时，许多对象将被打包到其中并使用构造函数（如果有）进行初始化。释放对象后，它会保持其初始化状态，这样可以快速分配对象。  
   3. **提高CPU硬件缓存的利用率(着色)**。![着色原因](https://github.com/user-attachments/assets/12549a55-a116-4408-b40a-5cf18c362cd2)![着色原理](https://github.com/user-attachments/assets/b1c78cf1-134b-488b-a2ce-fdf77fab7443)


   4. slab 分配器的实现源码：
      - include/linux/slab_def.h
      - include/linux/slab.h
      - mm/slab.c   
   5. 提供的API：与 libc 提供的内存申请 API （malloc 和 free ）类似，Slab 分配器提供的 API 为 kmalloc()和 kfree()。
2. Kfence机制![kfence机制](https://github.com/user-attachments/assets/6946e5f2-0989-4500-83c7-d49ef01ab12a)

   1. 初始化过程中，KFENCE向[Memblock](https://www.l2h.site/p/20210923linuxmm4.html)申请一段内存，作为KFENCE内存池。![初始化机制](https://github.com/user-attachments/assets/192b3d1d-4664-42e7-86dd-a86307e192fc)

   2. 分配。kfence_alloc_gate值为0时，使用kmem_cache_alloc所作的内存分配从KFENCE内存池中分配，并增加kfence_alloc_gate的值。kfence_alloc_gate值大于等于1时，直接从SLUB中分配。由此可以看出，kfence是基于采样的内存检测。每次通过KFENCE进行内存分配时，都会从KFENCE内存池分配一个内存页和一个Guard Page，并在实际使用内存的两端内存填充Canary数据。*大于一个Page(4K)的分配不会从KFENCE Pool中分配，如果KFENCE内存池中没有可用内存，则直接从SLAB中分配。*
   3. 释放时，检查Canary数据，将所用内存放回KFENCE内存池。![free](https://github.com/user-attachments/assets/56260855-93c7-4639-acb6-bfc658d2402e)

   4. 在以下情况，会检测报错：  
       - 释放时发现Canary数据不对（页内越界访问mem-corruption）。![canary](https://github.com/user-attachments/assets/909ffee8-ac9a-4a32-abf9-6e2dc6b01641)

       - 页外越界访问out-of-bounds，利用 MMU 的特性把 fence page 设置成不可访问。如果对 data page 的访问越过了 page 边界， 即访问page fence，就会立刻触发异常，这种就称为data page页外访问越界。
       - 无效释放：当一段KFENCE内存没有被标记分配，但对齐释放时，会有相应报错提示。
       - use-after-free
   5. 异常如何触发&日志打印
       - use-after-free：KFENCE_ERROR_UAF类型的内存错误  
       当某个模块的代码中触发了use-after-free，会走kernel原生的流程，调用kfence的kfence_handle_page_fault函数，进行错误日志的收集与打印。
       - ut-of-bounds(页外访问越界)：KFENCE_ERROR_OOB类型的内存错误，同上
       - out-of-bounds(页内访问越界)：KFENCE_ERROR_CORRUPTION类型的内存错误  
        在kfence allock阶段初始化canary区域（详见3.4），kfence free阶段去检测canary区域是否被访问过或破坏，如果被破坏，传入KFENCE_ERROR_CORRUPTION类型的参数，调用kfence_report_error函数，打印错误日志信息。
       - invalid-free：KFENCE_ERROR_INVALID_FREE类型的内存错误  
        kfence free阶段去检测本次内存释放是否为invalid-free，调用kfence_report_error函数，传入KFENCE_ERROR_INVALID_FREE类型的参数，打印错误日志信息。  

### 开发
#### 5.19

bugs 
问题：宏定义了，包含了头文件，但是显示没有定义？？？
然后发现Kconfig没有加入mm的Kconfig，加了之后就是如下问题：

```
'm/Kconfig:368:warning: ignoring unsupported character '
'm/kfence/Kconfig:6:warning: ignoring unsupported character '
'm/kfence/Kconfig:7:warning: ignoring unsupported character '
'm/kfence/Kconfig:8:warning: ignoring unsupported character '
'm/kfence/Kconfig:9:warning: ignoring unsupported character '
'm/kfence/Kconfig:9:warning: ignoring unsupported character '
'm/kfence/Kconfig:15:warning: ignoring unsupported character '
'm/kfence/Kconfig:15:warning: ignoring unsupported character '
'm/kfence/Kconfig:17:warning: ignoring unsupported character '
'm/kfence/Kconfig:18:warning: ignoring unsupported character '
'm/kfence/Kconfig:19:warning: ignoring unsupported character '
'm/kfence/Kconfig:20:warning: ignoring unsupported character '
'm/kfence/Kconfig:21:warning: ignoring unsupported character '
'm/kfence/Kconfig:21:warning: ignoring unsupported character '
'm/kfence/Kconfig:29:warning: ignoring unsupported character '
'm/kfence/Kconfig:30:warning: ignoring unsupported character '
'm/kfence/Kconfig:31:warning: ignoring unsupported character '
'm/kfence/Kconfig:32:warning: ignoring unsupported character '
'm/kfence/Kconfig:33:warning: ignoring unsupported character '
'm/kfence/Kconfig:33:warning: ignoring unsupported character '
'm/kfence/Kconfig:39:warning: ignoring unsupported character '
'm/kfence/Kconfig:40:warning: ignoring unsupported character '
'm/kfence/Kconfig:41:warning: ignoring unsupported character '
'm/kfence/Kconfig:42:warning: ignoring unsupported character '
'm/kfence/Kconfig:42:warning: ignoring unsupported character '
'm/kfence/Kconfig:48:warning: ignoring unsupported character '
'm/kfence/Kconfig:49:warning: ignoring unsupported character '
'm/kfence/Kconfig:50:warning: ignoring unsupported character '
'm/kfence/Kconfig:51:warning: ignoring unsupported character '
'm/kfence/Kconfig:51:warning: ignoring unsupported character '
'm/kfence/Kconfig:56:warning: ignoring unsupported character '
'm/kfence/Kconfig:57:warning: ignoring unsupported character '
'm/kfence/Kconfig:58:warning: ignoring unsupported character '
'm/kfence/Kconfig:59:warning: ignoring unsupported character '
'm/kfence/Kconfig:60:warning: ignoring unsupported character '
'm/kfence/Kconfig:61:warning: ignoring unsupported character '
'm/kfence/Kconfig:61:warning: ignoring unsupported character '
'm/kfence/Kconfig:66:warning: ignoring unsupported character '
'm/kfence/Kconfig:67:warning: ignoring unsupported character '
'm/kfence/Kconfig:68:warning: ignoring unsupported character '
'm/kfence/Kconfig:69:warning: ignoring unsupported character '
'm/kfence/Kconfig:69:warning: ignoring unsupported character '
'm/kfence/Kconfig:74:warning: ignoring unsupported character '
'm/kfence/Kconfig:75:warning: ignoring unsupported character '
'm/kfence/Kconfig:76:warning: ignoring unsupported character '
'm/kfence/Kconfig:77:warning: ignoring unsupported character '
'm/kfence/Kconfig:78:warning: ignoring unsupported character '
'm/kfence/Kconfig:79:warning: ignoring unsupported character '
'm/kfence/Kconfig:79:warning: ignoring unsupported character '
'm/kfence/Kconfig:85:warning: ignoring unsupported character '
'm/kfence/Kconfig:86:warning: ignoring unsupported character '
'm/kfence/Kconfig:87:warning: ignoring unsupported character '
'm/kfence/Kconfig:88:warning: ignoring unsupported character '
'm/kfence/Kconfig:88:warning: ignoring unsupported character '
'm/kfence/Kconfig:93:warning: ignoring unsupported character '
'm/kfence/Kconfig:94:warning: ignoring unsupported character '
'm/kfence/Kconfig:95:warning: ignoring unsupported character '
'm/kfence/Kconfig:96:warning: ignoring unsupported character '
'm/kfence/Kconfig:96:warning: ignoring unsupported character '
'm/kfence/Kconfig:101:warning: ignoring unsupported character '
'm/kfence/Kconfig:102:warning: ignoring unsupported character '
'm/kfence/Kconfig:103:warning: ignoring unsupported character '
'm/kfence/Kconfig:104:warning: ignoring unsupported character '
'm/kfence/Kconfig:104:warning: ignoring unsupported character '
'm/kfence/Kconfig:109:warning: ignoring unsupported character '
'm/kfence/Kconfig:110:warning: ignoring unsupported character '
'm/kfence/Kconfig:111:warning: ignoring unsupported character '
'm/kfence/Kconfig:112:warning: ignoring unsupported character '
'm/kfence/Kconfig:112:warning: ignoring unsupported character '
'm/kfence/Kconfig:117:warning: ignoring unsupported character '
'm/kfence/Kconfig:118:warning: ignoring unsupported character '
'm/kfence/Kconfig:119:warning: ignoring unsupported character '
'm/kfence/Kconfig:120:warning: ignoring unsupported character '
'm/kfence/Kconfig:120:warning: ignoring unsupported character '
'm/kfence/Kconfig:125:warning: ignoring unsupported character '
'm/kfence/Kconfig:126:warning: ignoring unsupported character '
'm/kfence/Kconfig:127:warning: ignoring unsupported character '
'm/kfence/Kconfig:128:warning: ignoring unsupported character '
'm/kfence/Kconfig:128:warning: ignoring unsupported character '
mm/kfence/Kconfig:134: 'endif' in different file than 'if'
mm/kfence/Kconfig:17: location of the 'if'
Kconfig:2755: 'endmenu' in different file than 'menu'
mm/kfence/Kconfig:17: location of the 'menu'
```

1. 买个板子试一下
2. 栈安全和堆安全不太一样
