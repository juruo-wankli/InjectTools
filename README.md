# InjectTools

一款从Ring0和3以及APC注入,远程线程劫持的提权工具。 //开源无🐎🐎,relax!!

## Usage:  

### APC注入 
Example:  

InjectTools.exe 你要注入的程序 DLL完整路径  

InjectTools.exe lsass.exe C:\Users\ASUS\Desktop\artifact_x64.dll

![APCInject](https://github.com/whoami-juruo/InjectTools/blob/main/img/APCInject.png)

### DLL注入 

example:  

InjectTools.exe 你要注入的程序 DLL完整路径  

InjectTools.exe lsass.exe C:\Users\ASUS\Desktop\artifact_x64.dll

![DLLInject](https://github.com/whoami-juruo/InjectTools/blob/main/img/DLLInject.png)

### 远程线程劫持
example:  

InjectTools.exe 你要注入的程序 BIN完整路径 

InjectTools.exe lsass.exe C:\Users\ASUS\Desktop\artifact_x64.bin

![RemoteThreadHiJacking](https://github.com/whoami-juruo/InjectTools/blob/main/img/RemoteThreadHiJacking.png)

### 映射注入

此功能以本进程进行,一旦关闭此进程即可掉线 ！！ //第二个参数随便写

example:

InjectTools.exe  WhateverYouWant   C:\Users\ASUS\Desktop\artifact_x64.bin

![MappingInject](https://github.com/whoami-juruo/InjectTools/blob/main/img/MappingInject.png)

<!-- Blank -->
<!-- Blank -->

### Anti-Virus

## SandBox

微步
![ThreatBook](https://github.com/whoami-juruo/InjectTools/blob/main/img/ThreatBook.png)

VT
![VT](https://github.com/whoami-juruo/InjectTools/blob/main/img/VT.png)

奇安信
![奇安信沙箱](https://github.com/whoami-juruo/InjectTools/blob/main/img/奇安信沙箱.png)

## AV

火绒
![火绒](https://github.com/whoami-juruo/InjectTools/blob/main/img/火绒.png)

Windows Defender
![WindowsDefender](https://github.com/whoami-juruo/InjectTools/blob/main/img/WindowsDefender.png)

360全家桶
![360全家桶](https://github.com/whoami-juruo/InjectTools/blob/main/img/360全家桶.png)

麦咖啡
![McAfee](https://github.com/whoami-juruo/InjectTools/blob/main/img/McAfee.png)

ESET
![ESET](https://github.com/whoami-juruo/InjectTools/blob/main/img/ESET.png)

卡巴斯基
![Kaspersky](https://github.com/whoami-juruo/InjectTools/blob/main/img/Kaspersky.png)

赛门铁克
![Symantec](https://github.com/whoami-juruo/InjectTools/blob/main/img/Symantec.png)

## TODO 

- [√] 普通动态调用静态过大部分杀软
- [ ] 实现文件加解密操作
- [ ] 反沙箱
- [ ] NT动态调用
- [ ] PEB寻址
- [ ] 新的模块功能引入
- [ ] 签名,信息
- [ ] ....


