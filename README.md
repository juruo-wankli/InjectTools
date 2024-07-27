# InjectTools

一款从Ring0和3以及APC注入的提权注入工具。 //开源无🐎🐎,relax!!

## Usage:   For InjectTools.exe 

### APC注入 
Example:  

InjectTools.exe 你要注入的程序 DLL路径  

InjectTools.exe lsass.exe C:\Users\ASUS\Desktop\artifact_x64.dll

![Win11_APC](https://github.com/whoami-juruo/InjectTools/raw/main/img/Win11_APC.png)
![Win10_APC](https://github.com/whoami-juruo/InjectTools/raw/main/img/Win10_APC.png)

### DLL注入 

example:  

InjectTools.exe 你要注入的程序 DLL路径  

InjectTools.exe lsass.exe C:\Users\ASUS\Desktop\artifact_x64.dll

![Win10_DLL](https://github.com/whoami-juruo/InjectTools/raw/main/img/Win10_DLL.png)
![Win11_DLL](https://github.com/whoami-juruo/InjectTools/raw/main/img/Win11_DLL.png)

## Usage:   For InjectTools_SandBox.exe

### Tips:    Assisted on-line

这个反沙箱的其中一个原理就是检测同文件夹下是否有cs.dll(你也可以改成你喜欢的名字)，你还可以直接创建一个假的cs.dll在同目录下(然后注入自己其他路径的DLL) (APC同理!!)
 
example:

InjectTools_SandBox.exe 你要注入的进程 你的DLL(或者同目录下的CS上线DLL)

InjectTools_SandBox.exe lsass.exe C:\Users\ASUS\Desktop\cs.dll

![Command](https://github.com/whoami-juruo/InjectTools/raw/main/img/AntiSanbox_Command.png)
![Usage](https://github.com/whoami-juruo/InjectTools/raw/main/img/AntiSanbox_Usaeg.png)


## Anti-Virus?


<!-- Blank -->
<!-- Blank -->
##  InjectTools_SandBox.exe

赛门铁克
![Symantec](https://github.com/whoami-juruo/InjectTools/raw/main/img/Symantec.png)

VT
![VT](https://github.com/whoami-juruo/InjectTools/raw/main/img/AntiSanbox_VT.png)

ThreadBook
![ThreadBook](https://github.com/whoami-juruo/InjectTools/raw/main/img/AntiSanbox_ThreadBook.png)

<!-- Blank -->
<!-- Blank -->

##  InjectTools.exe 
### 沙箱扫描 (SandBox)
ThreadBook  
![ThreadBook](https://github.com/whoami-juruo/InjectTools/raw/main/img/ThreadBook.png)

VT  
![VT](https://github.com/whoami-juruo/InjectTools/raw/main/img/VT.png)

<!-- 加两个空行 -->
<!-- 加两个空行 -->

### AV检测 (静态查杀 Static Detect)

Windows Defender  
![Defender](https://github.com/whoami-juruo/InjectTools/raw/main/img/WindowsDefender.png)

火绒  
![火绒](https://github.com/whoami-juruo/InjectTools/raw/main/img/火绒.png)

卡巴斯基  
![Kaspersky](https://github.com/whoami-juruo/InjectTools/raw/main/img/Kaspersky.png)

360Family  
![360Family](https://github.com/whoami-juruo/InjectTools/raw/main/img/360Family.png)
