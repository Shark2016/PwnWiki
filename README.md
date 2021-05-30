
# PwnWiki

## 基础

- [汇编基础与调用约定](汇编基础与调用约定.md)
- [ELF格式与动态链接](ELF格式与动态链接.md)
- 漏洞类型与缓解措施
- 漏洞调试环境搭建

## 常见漏洞类型介绍

- 整数溢出(Integer Overflow)
- 有符号无符号比较与运算
- 越界访问(读/写)(Out Of Boundary Access, OOB)
- 栈溢出(Stack Overflow)
- 堆溢出(Heap Overflow)
- Double Free
- UAF(Use After Free)
- 格式化字符串(Format String)
- Double Fetchs
- 空指针(Null Pointer)
- 竞争条件(Race Condition)
- TOCTOU
- 逻辑错误
- scanf误用
- system()命令注入

## 缓解技术与绕过介绍
- Canary
- NX/DEP
- RELRO
- ASLR/PIE

## 常见利用技术汇总
- GOT覆写
- 函数指针覆写
- ret2shellcode/jmp esp/call esp
- rop/ret2libc/ret2text/ret2csu
- stack pivot
- leak libc
- gadget/one-gadget
- malloc_hook/relloc_hook覆写
- fastbin attack攻击
- unlink
- tcache
- overlap
- mmap
- house of系列
