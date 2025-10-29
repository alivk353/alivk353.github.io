
# adb

adb shell pm list packages -[option] 

adb shell dumpsys package <package_name>  //获取全部信息
adb shell dumpsys package <package_name> | grep XXX //获取XXX信息

查看进程

```shell
frida adb shell ps | grep sdnx
u0_a194       6447   802 2125392 278588 0                   0 S com.sdnxs.mall
u0_a194       6579   802 1137472 113724 0                   0 S com.sdnxs.mall:pushcore
```


# Magisk

magisk hide 和 frida 都用了 ptrace,所以会有冲突,可以把 firda 的动态库直接嵌入程序
这样就不会用到 ptrace.
本质上 ptrace 只是为了注入




## riru简单实用

对于反frida调试的不能对目标进程attach的加固方案 可以尝试通过riru注入gadget解决

在migisk中安装riru_25.x版本
下载附件中的gadget.json执行adb push gadget.json /data/local/tmp
执行 adb shell su -c "setprop frida.target packagename"
启动目标app
执行frida -H ip:27004 -l ./myscript.js Gadget

端口27042在gadget.json指定 Gadget为固定值；

frida使用14.2.14版本，实测15.0.8之前的都不能用，不知道frida后面有没有修复；

目前listen模式中，on_load仅支持resume. wait模式还有些问题


```json
//两种gadget.json的写法
{
  "interaction": {
    "type": "script",
    "path": "/data/local/tmp/test.js"
  }
}

{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_load": "resume"
  }
}

```

## Xposed

Xposed 在 Android Pie 之后已停更,EdXposed 是 Xposed 的正统接任者

在Magisk安装EdXposed v0.5.2.2时,需要降级riru至v25.4.4版本,才可以正常安装

# frida

## 输出所有类方法名

```js
    var hook = Java.use(instance);
    var ret = hook.class.getDeclaredMethods();
    ret.forEach(function(s) {
        console.log(s);
    })
```


## 在任何位置获取conntext对象

```js
var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
var context = currentApplication.getApplicationContext();
var t = Java.use("com.cebbank.cebUtils.CebTransferParam").$new();
```  


## cli

frida-ps -U 

frida -U -f com.shinhan.global.cn.bank -l /Users/nana/sec/Android/frida_env/xinhan/hook.js

objection -g com.shinhan.global.cn.bank explore

## objection

开启 frida-server
使用 -P 参数带着插件启动 objection
objection -g com.xx.xx explore -P ~/Documents/android/objection/plugins

指定文件 txt 运行 比如文件上写了， 批量需要hook的函数

- objection -g com.xx.xx explore -c ~/xxx.txt
- objection -g com.xx.xx explore -c ~/xxx.txt

### root

- 尝试关闭app的root检测 android root disable

- 尝试模拟root环境 android root simulate

### ui
- 截图 android ui screenshot image_name

- 设置FLAG_SECURE权限 android ui FLAG_SECURE false

### Memory 指令
memory list modules //枚举当前进程模块
memory list exports [lib_name] //查看指定模块的导出函数
memory list exports libart.so --json /root/libart.json //将结果保存到json文件中
memory search --string --offsets-only //搜索内存

### android heap

堆内存中搜索指定类的实例, 可以获取该类的实例id
- search instances com.xx.xx.class

直接调用指定实例下的方法
- android heap execute [ins_id] [func_name]

自定义frida脚本, 执行实例的方法
- android heap execute [ins_id]

### 内存漫游
列出内存中所有的类
- android hooking list classes

在内存中所有已加载的类中搜索包含特定关键词的类
- android hooking search classes [search_name] 


在内存中所有已加载的方法中搜索包含特定关键词的方法
- android hooking search methods [search_name] 

直接生成hook代码
- android hooking generate simple [class_name]

### hook 方式

android hooking watch class_method com.csii.aesencryption.PEJniLib.aesNativeDecrypt


hook指定方法, 如果有重载会hook所有重载,如果有疑问可以看
- --dump-args : 打印参数
- --dump-backtrace : 打印调用栈
- --dump-return : 打印返回值

- android hooking watch class_method com.xxx.xxx.methodName --dump-args --dump-backtrace --dump-return

hook指定类, 会打印该类下的所以调用
- android hooking watch class com.xxx.xxx

设置返回值(只支持bool类型)
- android hooking set return_value com.xxx.xxx.methodName false

### spawn 方式 hook

- objection -g packageName explore --startup-command '[obejection_command]'

### activity 和 service

枚举activity

- android hooking list activities

启动activity
- android intent launch_activity [activity_class]

枚举services
- android hooking list services

启动services
- android intent launch_service [services_class]
任务管理
查看任务列表
- jobs list

关闭任务
- jobs kill [task_id]
关闭app的ssl校验
- android sslpinning disable


## r0capture


Spawn 模式：

$ python3 r0capture.py -U -f com.qiyi.video -v

Attach 模式，抓包内容保存成pcap文件供后续分析：

$ python3 r0capture.py -U com.qiyi.video -v -p iqiyi.pcap

京口北固亭怀古

千古江山 英雄无觅孙仲谋处 
舞榭歌台 风流总被雨打风吹去
斜阳草树 寻常巷陌 人道寄奴曾住
想当年 金戈铁马 气吞万里如虎
