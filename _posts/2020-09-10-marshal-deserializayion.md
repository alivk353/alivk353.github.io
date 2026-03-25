---
title: Java Marshal Sec
date: 2020-09-10 12:30:00 +0800
categories: [record]
tags: [all]
---


# marshal sec

一些常用点 笔记用

### java.beans.EventHandler

- 动态代理利用 实现InvocationHandler接口
- 有`private Object target;`实现调用任意方法

### javax.imageio.spi.FilterIterator

- 外层`FilterIterator`的 `next()` 方法会从内层迭代器获取元素 如:`TemplatesImpl`
- 然后调用 `filter.filter(element)` 进行过滤，从而触发恶意方法
- 通常搭配`javax.imageio.ImageIO$ContainsFilter`

### javax.imageio.ImageIO$ContainsFilter

- 常被用于文件操作相关的利用链
- 其filter方法会通过反射调用指定的method 如`getOutputProperties` 并将传入的对象作为目标
- 许配合:`javax.imageio.spi.FilterIterator`触发


### jdk.nashorn.internal.objects.NativeString

- 触发NativeString.value.toString()
- 声明:`private final CharSequence value`

`NativeString.hashCode() ` -> `NativeString.getStringValue() ` -> `NativeString.value.toString()`

### sun.rmi.server.UnicastRef

- RMI相关的反序列化利用链组件

### org.springframework.context.support.ClassPathXmlApplicationContext

- 构造方法只有1个String 加载xml文件 方便利用
- Bean实例化：读取XML中的`<bean>`定义 反射创建对象
- 支持SPEL表达式解析
- 参数xml路径支持通配符
    - 尝试引用本地tmp下的临时文件 
    - 如tomcat在出文件上传mutil请求时 会将文件块存储到临时tmp目录下
    - 且tomcat有自己的命名规则
    - 出自`https://www.leavesongs.com/PENETRATION/springboot-xml-beans-exploit-without-network.html`

```xml
<bean id="pwn" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
        <list>
            <value>calc.exe</value> 
            <value>#{T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"})}</value> 
        </list>
    </constructor-arg>
</bean>
```

### com.sun.xml.internal.ws.util.ServiceFinder$LazyIterator

com.sun.xml.internal.ws.util.ServiceFinder.LazyIterator#next存在如下调用:

```java
ServiceName sn = this.names[this.index++];
String cn = sn.className;
URL currentConfig = sn.config;
return this.service.cast(Class.forName(cn, true, this.loader).newInstance());
```

xstream控制loader为`org.apache.bcel.util.ClassLoader`实例

当classname以$$BCEL$$开头的 根据classname的值去defineClass，这就是任意载入字节码的地方

在构造XStream的BcelClassLoader对象时 为了避免报错删除ignored_packages和deferTo属性

后续在BcelClassLoader.classes加入字节码的依赖即可

```
jdk.nashorn.internal.objects.NativeString#hashCode
-> com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data#toString
-> javax.crypto.CipherInputStream#read
-> Javax.crypto.Cipher#chooseFirstProvider
-> com.sun.xml.internal.ws.util.ServiceFinder$LazyIterator#next
-> Java.lang.Class#forName
-> com.sun.org.apache.bcel.internal.util.ClassLoader#loadClass
```


### javax.swing.UIDefaults

### SwingLazyValue


## 读写文件

### sun.rmi.server.MarshalOutputStream

