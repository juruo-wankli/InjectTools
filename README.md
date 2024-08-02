# InjectTools

一款集成了DLL-Session0注入，APC注入，映射注入，线程劫持，函数踩踏自提权的工具。 //开源无🐎🐎,relax!!

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

### 远程线程劫持
example:   //这里建议RuntimeBroker

InjectTools.exe 你要注入的程序 BIN完整路径 

InjectTools.exe  RuntimeBroker.exe  C:\Users\users\Desktop\artifact_x64.bin

![RemoteThreadHiJacking](https://github.com/whoami-juruo/InjectTools/blob/main/img/RemoteThreadHiJacking.png)

### 映射注入

example:

InjectTools.exe  你要注入的程序   BIN完整路径

InjectTools.exe  OneDrive.exe  C:\Users\users\Desktop\artifact_x64.bin

![MappingInject](https://github.com/whoami-juruo/InjectTools/blob/main/img/MappingInject.png)

### 函数踩踏

InjectTools.exe  目标程序   BIN完整路径
目标程序加载的DLL  要踩踏的函数

InjectTools.exe  Notepad.exe   C:\Users\users\Desktop\artifact_x64.bin
User32.dll  GetFocus 

![FunctionStomping](https://github.com/whoami-juruo/InjectTools/blob/main/img/FunctionStomping.png)
<!-- Blank -->
<!-- Blank -->

### Anti-Virus

## SandBox (2024.8.2)

VT
![VT](https://github.com/whoami-juruo/InjectTools/blob/main/img/VT.png)

微步
![ThreatBook](https://github.com/whoami-juruo/InjectTools/blob/main/img/ThreatBook.png)

360沙箱
![360沙箱](https://github.com/whoami-juruo/InjectTools/blob/main/img/360沙箱.png)

## EDR (2024.8.2)
McAfee EDR + FireEye Combined !!
![McAFeeEDR](https://github.com/whoami-juruo/InjectTools/blob/main/img/McAFeeEDR.png)

## AV  (2024.7.30)

火绒
![火绒](https://github.com/whoami-juruo/InjectTools/blob/main/img/火绒.png)

Windows Defender  实体机&&虚拟机
![WindowsDefender](https://github.com/whoami-juruo/InjectTools/blob/main/img/WindowsDefender.png)

360全家桶  || 现在QVM杀疯了 , 不白加黑基本上不可能 , Failed  ：（ 
![360全家桶](https://github.com/whoami-juruo/InjectTools/blob/main/img/360全家桶.png)

ESET
![ESET](https://github.com/whoami-juruo/InjectTools/blob/main/img/ESET.png)

卡巴斯基
![Kaspersky](https://github.com/whoami-juruo/InjectTools/blob/main/img/Kaspersky.png)

赛门铁克
![Symantec](https://github.com/whoami-juruo/InjectTools/blob/main/img/Symantec.png)

## TODO 

- [√] 普通动态调用静态过大部分杀软
- [√] ICON(360),详细信息,签名
- [√] 简单反沙箱
- [√] 新的模块功能引入
- [ ] 实现文件加解密操作
- [ ] NT动态调用
- [ ] PEB寻址
- [ ] ....


