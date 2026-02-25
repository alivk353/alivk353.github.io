# PHP 反序列化

PHP中序列化一个对象需要调用serialize()方法，之后会调用__sleep()方法执行自定义操作后，序列化数据生成，而JAVA的wrireObject()是可以重写的。反序列化后会调用__wakeup()方法。

PHP中的魔术方法__sleep(),__wakeup()是在序列化操作的前后执行而不是序列化时。

PHP反序列化漏洞的利用点是在序列化时将一些属性修改成我们想要的数据 ，从而在之后的执行流程中进行危险操作，而不是在__wakeup()中，因为根本不可控，除非__wakeup()本身写的很危险

# Python 反序列化

Python反序列化和Java、PHP有个显著的区别，就是Python的反序列化过程实际上是在执行一个基于栈的虚拟机。

我们可以向栈上增、删对象，也可以执行一些指令，比如函数的执行等，甚至可以用这个虚拟机执行一个完整的应用程序。

# Java 反序列化

Java的反序列化和PHP的反序列化其实有些类似，都是将一个对象中的属性按照某种特定的格式生成一段数据流。
在反序列化的时候再按照这个格式将属性取出，再赋值给新的对象。

在序列化是会调用writeObject()，参数是ObjectOutSteam类型。

我们可以将任何数据写入这个对象输出流，在反序列化是调用重写好的readObject()来读取前面写入的内容，比PHP序列化操作更自定义


## 起

### java.util.HashSet

- 底层采用HashMap实现,利用哈希冲突实现唯一值.
- `readObject()`中调用内置`map.put(unsafeObject, XXX)`,进而调用`unsafeObject.hashCode()`


### java.util.HashMap

- `hashMap.put(k,v)`-> `hashMap.putVal(hash(k), k, v)`触发 `k.hashCode()`和`k.equals(k2)`
- `readObject()`会计算key的哈希值去重,`readObject()`->`hash(key)`->`key.hashCode()`

- 哈希碰撞 `hash(key) == hash(anotherKey)`
    - `Objects.hashCode("zZ") = 3872`
    - `Objects.hashCode("yy") = 3872`
    - 触发元素`key.equals(anotherKey)`

- 特殊hash碰撞类:`org.springframework.aop.target.HotSwappableTargetSource`
 - 重写hashCode():`{return HotSwappableTargetSource.class.hashCode();}`
 - 有:`hash(HotSwappableTargetSource) == hash(HotSwappableTargetSource)`
 - 触发元素`HotSwappableTargetSource.equals(HotSwappableTargetSource)`
 - 触发equals()内部逻辑

- `HashMap.hashCode()`逻辑：
    - 调用父类`AbstractMap.hasCode()`
    - 依次调用`Node.hashCode()`
    - `java.util.Objects#hashCode`分别计算Node中key，value的哈希





### java.util.Hashtable

- `readObejct()`中调用`key.hashCode()`
- 哈希冲突,触发`key.equals(key2)`
- 通常后接`TiedMapEntry`触发CC.
- Hashtable存两个HashMap->触发`euqals`->hashMap父类`AbstractMap`的`equals(key)`->`key.get()`
- readObject简单逻辑
    - 首先从对象流读取len等信息 初始化内置table
    - 从流读取第一对key value，调用`reconstitutionPut(table,key,value)`
    - `reconstitutionPut`中，先计算`key.hashCode()`，确定在table的index
    - 此时table无元素，不进行eauals直接放进`table[index]`
    - 第二次读取KV，调用`reconstitutionPut(table,key2,value2)`
    - 此时table有元素，遍历table避免哈希冲突
    - 当`key.hashCode()==key2.hashCode()`时,触发`key.equals(key2)`
    - ysoserial

### java.util.AbstractMap

- `equals()`->`LazyMap.get()`

### javax.swing.UIDefaults.TextAndMnemonicHashMap

- `HashMap`子类，重写`get(key)`方法，内调用`key.toString()`

### javax.management.BadAttributeValueExpException

- 属性`val`是Object类型,`BadAttributeValueExpException#readObject`中调用`val.toString()`
- 限制`System.getSecurityManager() == null`,利用条件`java.lang.SecurityManager`没有实例

### java.util.PriorityQueue

- 存在`java.util.Comparator`成员变量,序列化可控. 反序列化时读取对象到数组后`Comparator`排序
- `readObject()`->`heapify()`->`siftDown()`->`siftDownUsingComparator()`->`comparator.compare()`

###  sun.reflect.annotation.AnnotationInvocationHandler

- 有成员变量`Class`类型`type` jdk8u71和jdk8u202之后 修改类型为泛型`Class<? extends Annotation>`并在readObject方法中限制为注解类型
- 成员变量`Map<String, Object>`类型`memberValues` 
- 8u71前，自身`readObject()`会调用实例map属性的内部类MapEntry的`setValue()`->`checkSetValue()`->`transform()`，调用默认defaultReadObject()，map可控，通常后接TransformedMap
- `invoke(Object proxy, Method method, Object[] args)`的逻辑
    - 当`method.getName()`不是`toString equals hashCode annotationType`时 
    - 用方法名作为key 在`memberValues`中取verlue并返回任意对象
    - `return this.memberValues.get(method.getName())`
    - 低版本中可以利用次特性控制返回值
    - 高版本中`readObject`限制`memberValues`的可以和value必须是`this.type`注解的成员参数 无法利用

- 作为Proxy的handle，invoke()内调用实例map属性的`get()`，通常后接LazyMap
- 作为Proxy的handle，invoke()内调用`equalsImpl()`,反射执行可控方法

- 
### org.apache.commons.collections.bag.TreeBag

- 存在`java.util.Comparator`成员变量,序列化可控.`readObject()`中作为`TreeMap`构造函数的参数.
- `org.apache.commons.collections.bag.AbstractMapBag#doReadObject`->`TreeMap.put(unsafeObject,XXX)`->`comparator.compare()`
- 通常后接`org.apache.commons.collections.comparators.TransformingComparator`触发CC执行链


## 承

### java.util.TreeMap

- 红黑树实现,存在`java.util.Comparator`类的成员变量,根节点为`null`时触发`TreeMap.put(key,value)`->`compare(key, key)`->`comparator.compare(key,key)`

### org.apache.commons.collections.map.TransformedMap

- apache CC3&4类接Transform执行链,`setValue()`->`checkSetValue()`->`transform()`
- Common Collections 3.2.2 FunctorUtils.checkUnsafeSerialization() 需要enableUnsafeSerialization=true

### org.apache.commons.collections.map.LazyMap

- 有`org.apache.commons.collections.Transformer`类型成员变量`factory`
- `LazyMap.get(key)`->`transform(key)` CC3&4类接Transform执行链

- 有`java.util.Map`类型成员变量`map`
- `LazyMap.get(key)`->`this.map.put(key,transform(key))` 
- `ConstantTransformer`可控制value


### org.apache.commons.collections4.comparators.TransformingComparator

- cc4版本实现序列化接口
- compare方法会调用`org.apache.commons.collections4.Transformer#transform`
- 可代替LazyMap触发transform

### org.apache.commons.collections.map.DefaultedMap

- 与LazyMap类似
- CC3&4类接Transform执行链,`map.get()`->`transform()`

### org.apache.commons.collections.keyvalue.TiedMapEntry

- `Map.Entry`的实现类 可作为`hashMap`的`table`上的节点

- 存在`java.util.Map`成员变量map和`String`类型变量`key`
- `TiedMapEntry.getValue()`内调用`map.get(this.key)`
- `hashCode()`->`getValue()`->`map.get(this.key)`,通常后接LazyMap.get()
- `toString()`->`getValue()`->`map.get(this.key)`,通常后接LazyMap.get()

### org.apache.commons.collections4.bidimap.DualHashBidiMap

- `DualHashBidiMap.readObject()`

### com.alibaba.fastjson.JSONObject
### com.alibaba.fastjson.JSONArray

- 实现了`Serializable`接口
- `JSONObject.toString()`会调用成员的所有getter方法 如`TemplatesImpl`的getter
- `JSONObject`对应的处理器为`MapSerializer`
- `TypeUtils.fnv1a_64(className)`计算哈希值
- 并在`com.alibaba.fastjson.serializer.SerializeConfig.createJavaBeanSerializer()`的`denyClasses` 1.2.83版本只有2个hashCode 无效过滤

> com.alibaba.fastjson.JSONObject还实现InvocationHandler接口 可作为代理handle

- invoke逻辑如下
- 仅代理调用getter setter toString equal hashCode isXXX方法 其他方法会抛异常
- getter 条件返回值void 参数length=0 method以get开始 method名长度最短=4
    - 根据`getAbc()`取`abc`在属性map取值`obj` -> `Object obj = this.map.get('abc')`
    - Class clazz=`getAbc()`返回值类型 调用`TypeUtils.cast(Object obj, Class<T> clazz, ParserConfig config)`
        - `clazz==obj.getClass()` 返回obj
        - `obj instanceof Map` 返回 obj
        - `clazz.isArray()`且`obj instanceof Collection` 调用collection.iterator()迭代器系列method 
        - `clazz == byte[].class` Base64解码String 返回
        - `clazz.isAssignableFrom(obj.getClass())` 是子类时 返回obj
        - `clazz == String.class` 调用`obj.toString()`返回


### org.springframework.aop.target.HotSwappableTargetSource

- 重写hashCode():`{return HotSwappableTargetSource.class.hashCode();}`
- 重写equals(): `HotSwappableTargetSource.target.equals(((HotSwappableTargetSource)other).target)`
- 触发特殊哈希碰撞 有`HotSwappableTargetSource.equals(HotSwappableTargetSource)`
- 触发`target.equals()`

### org.apache.xpath.objects.XString

- 存在`Object`类型成员变量`m_obj`
- `XString.equals(Object obj2)` 触发`obj2.toString()`


### com.fasterxml.jackson.databind.node.POJONode

- 低版本如2.6.3，`POJONode`类的父类`BaseJsonNode`没有实现`Serializable`
- 构造函数Object类型参数，赋值属性`_value`
- `POJONode.toString()`->`BaseJsonNode.toString()`->`InternalNodeMapper.nodeToString(this)`->`com.fasterxml.jackson.databind.ObjectWriter#writeValueAsString`
- 将依次调用属性`_value`的getter方法
- 

### com.fr.json.JSONArray

- `com.fr.json.JSONArray#toString`->`com.fr.json.revise.EmbedJson#encode`
- `MAPPER.writeValueAsString`,进入序列化触发getter


### javax.swing.event.EventListenerList

- readObject()字符串拼接，调用toString()
## 转

### org.apache.commons.collections.functors.ChainedTransformer

- `Transformer`的循环调用,第一次调用的返回值作为下次循环的参数

### org.apache.commons.collections.functors.InvokerTransformer

- `iMethodName``iParamTypes``iArgs`反射执行任意方法
- CC3.2.1版本 增加重写`readObject()`添加反序列化验证` FunctorUtils.checkUnsafeSerialization`开启`enableUnsafeSerialization`
- CC4.3版本 删除实现`Serializable`接口
- 可构造 `Runtime.getRuntime().exec()` 

### org.apache.commons.collections.functors.InstantiateTransformer

- `transformer()`方法实现调用任意构造方法
- CC3.2.1版本 增加重写`readObject()`添加反序列化验证
- CC4.3版本 删除实现`Serializable`接口
- 可构造`TrAXFilter`

### org.apache.commons.collections.functors.ConstantTransformer

- `transformer()`实现返回对象变量`iConstant`
- 可控制`transform()`任意返回值 

### org.apache.commons.collections.functors.MapTransformer

- 有实例属性`iMap` 反序列化可控
- `transformer(input)`返回`iMap.get(input)`

### org.apache.commons.collections.functors.FactoryTransformer

- 有实例属性`org.apache.commons.collections.Factory`
- `transformer()`实现调用`factory.create()`
- `Factory`实现类`org.apache.commons.collections.functors.InstantiateFactory` 
- `InstantiateFactory.create()`实现任意构造方法调用
- 可结合`TrAXFilter<init>`使用

### org.apache.xalan.xsltc.trax.TrAXFilter
### com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter

- 构造方法存在`javax.xml.transform.Templates`类型参数 直接调用`templates.newTransformer()`


### org.apache.commons.beanutils.BeanComparator

- `BeanComparator#compare`比较对象时,会调用参数对象成员属性的getter方法
- `java.util.PriorityQueue`可构造触发compare
- `TemplatesImpl`的`getOutputProperties()`符合条件

### org.springframework.aop.framework.JdkDynamicAopProxy

- 实现`java.lang.reflect.InvocationHandler` 只支持接口动态代理
- 有`AdvisedSupport`类型变量`advised`
- `advised.targetSource`属性类型控制为`org.springframework.aop.target.SingletonTargetSource`
- invoke() 利用方式1 使用`MethodInvokeTypeProvider`导致版本限制
    - 条件:需要通过调用`newTransformer`来触发`JdkDynamicAopProxy`的`invoke()`
    - 触发`AopUtils.invokeJoinpointUsingReflection(target, method, args);`
    - target可控 `target = SingletonTargetSource.getTarget();`
    - 使target为`TemplatesImpl`实例 method则为代理调用方法`newTransformer`
    - 可使用`MethodInvokeTypeProvider.readObject()`触发反射调用`newTransformer`方法
    - 利用`AnnotationInvocationHandler`控制`MethodInvokeTypeProvider.TypeProvider.getType()`返回`JdkDynamicAopProxy`代理对象
    - 代理对象代理接口`Type.class`和`Templates.class`
    - 触发`JdkDynamicAopProxy.invoke()`->`AopUtils.invokeJoinpointUsingReflection(target, method, args)`
- invoke() 利用方式2
    - 有调用`this.advised.getInterceptorsAndDynamicInterceptionAdvice`获取Interceptor链
    - `org.springframework.aop.aspectj.AspectJAfterAdvice`->`invokeAdviceMethod`存在反射调用
    - `aspectJAdviceMethod`方法名反序列化可控
    - `this.aspectInstanceFactory.getAspectInstance()`实例可控 类`SingletonAspectInstanceFactory`
    - 参数存在类型限制,不可控 执行`newTransformer`足够
    - `new AspectJAfterAdvice(newTransformerMethod, pointcut, new SingletonAspectInstanceFactory(templatesObject));`

### org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler

- 实现`java.lang.reflect.InvocationHandler` 只支持接口动态代理
- 有`org.springframework.beans.factory.ObjectFactory`类型成员变量`objectFactory`
- `invoke(Object proxy, Method method, Object[] args)`逻辑:
- `method.invoke(this.objectFactory.getObject(), args);` 可动态代理`ObjectFactory`接口 实现返回任意对象
- 当method为`toString()`时 调用`this.objectFactory.toString()`

### org.springframework.core.SerializableTypeWrapper.MethodInvokeTypeProvider

- `spring-core:4.1.4.RELEASE`, `spring-beans:4.1.4.RELEASE`后 检查methodName方法的返回值类型
- `SerializableTypeWrapper`的内部类 继承`TypeProvider`接口 可序列化 
- 有`TypeProvider`类型的变量`provider`
- `readObject()`有反射逻辑 `this.methodName`可控制为`TemplatesImpl`的`getOutputProperties()`或`newTransformer()`
- `ReflectionUtils.findMethod(this.provider.getType().getClass(), this.methodName)` 
- `ReflectionUtils.invokeMethod(method, this.provider.getType())`
- 要调用`newTransformer`需要控制`provider.getType()`返回值是TemplatesImpl对象 
- `TypeProvider.getType()`返回值类型是`java.lang.reflect.Type` 
    - 1.构造代理对象 同时代理`Type.class`和`TemplatesImpl.class` 来避免调用是的类型转换异常
    - 2.构造`ObjectFactory`接口代理对象 使其getObject()返回TemplatesImpl实例
    - 3.构造handle使用`AutowireUtils$ObjectFactoryDelegatingInvocationHandler` 属性objectFactory为代理对象
    - 4.用`AnnotationInvocationHandler`代理`TypeProvider`接口 控制`getType()`返回代理对象 接口`Type.class`和`TemplatesImpl.class`
    - 构造的结果
    - `@java.lang.Override(getType=@java.lang.Override(getObject=com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl))`
    

### org.apache.tomcat.dbcp.dbcp2.BasicDataSource

- 无法java序列化，fastjson等库可用
- getter方法：`getConnection()`->`createDataSource()`->`createConnectionFactory()`
- `createConnectionFactory`中，有调用`Class.forName(driverClassName, true, driverClassLoader)`
-  
## 合

### org.apache.xalan.xsltc.trax.TemplatesImpl
### com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl

- 重写`defineClass()` 类加载代码执行
- `getOutputProperties()`和`newTransformer()`


### java.beans.XMLDecoder

- `readObject()`可构造调用链 命令执行

    ```xml
    <java>
        <object class=\"bsh.Interpreter\">
            <void method=\"eval\">
                <string><![CDATA[new java.io.FileOutputStream(\"%swebapps/nc_web/Client/%s\").write(\"%s\".getBytes(\"UTF-8\"));]]]></string>
            </void>
        </object>
    </java>
    ```

### bsh.Interpreter

- BeanShell执行上下文解释器
- `Interpreter.eval()`执行java代码.定义方法 变量赋值表达式 调用方法
- `bsh.This`上下文的引用
- `bsh.This#invokeMethod(java.lang.String, java.lang.Object[])` 执行`Interpreter`注册的方法

### bsh.XThis

- 对`bsh.Interpreter`的拓展 持有`Interpreter`上下文引用

- 内部类`Handler`提供通用接口代理机制的支持.

- 用`bsh.XThis.Handler`为handle代理的接口 `invoke()`会回调`bsh.Interpreter`中注册的方法
- `bsh.XThis.Handler`在2.b6不再实现序列化接口

- 如`ysoserial`的`beanshell1`:
    - 构造Proxy对象,代理`java.util.Comparator`接口 handle传`bsh.XThis.Handler`实例
    - `bsh.Interpreter`中注册`compare(Object o1,Object o2){eval code}`
    - 用`PriorityQueue`触发`compare()` 执行任意代码

### org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap

- `put(fileName,fileContent)`触发写文件 路径由属性`folder`拼接 反序列化可控
- 通过`readObject()`触发时 需要key和value同时可控
- HashSet可控只有key

### java.security.SignedObject

- 二次反序列化 可用于绕过第一次黑名单
- 属性`content`为加密后的反序列化数据
- `getObject()`触发解密和反序列化


### org.springframework.transaction.jta.JtaTransactionManager

- readObject触发jndi lookup
- JtaTransactionManager.readObject()

### com.sun.rowset.JdbcRowSetImpl

当程序调用 setAutoCommit()、execute() 或 prepare() 等方法时，类内部会尝试建立数据库连接 后触发`javax.naming.InitialContext.lookup(dataSourceName)`:

- JdbcRowSetImpl.execute()->JdbcRowSetImpl.prepare()->JdbcRowSetImpl.connect()->lookup()

## JDK间的区别

### jdk7

- JDK开始引入JS引擎 采用Rhino实现
- 不支持Java.type等获取Java类型的操作

### jdk8

- JS引擎默认采用Nashorn实现

### jdk9

- 引入模块机制
- 类隔离

### jdk11

- Unsafe.defineClass方法被移除
- 默认禁止跨包之间反射调用非公有方法

### jdk12

- Reflection类下fieldFilterMap增加过滤 反射操作被大大限制

fieldFilterMap 是 JDK 内部的一个映射表，用于过滤掉某些不应该通过反射访问的字段

### jdk15

- JS引擎被正式移出JDK

#### 常见利用

> org.apache.commons.dbcp.BasicDataSource

`BasicDataSource.toString()`方法会遍历这个类的所有getter并执行，于是通过`getConnection()`->`createDataSource()`->`createConnectionFactory()`的调用关系 调用到了`createConnectionFactory()`：

```java
protected ConnectionFactory createConnectionFactory() throws SQLException {
        Class driverFromCCL = null;
        Throwable t;
        String user;
        if (this.driverClassName != null) {
            try {
                try {
                    if (this.driverClassLoader == null) {
                        Class.forName(this.driverClassName);
                    } else {
                        Class.forName(this.driverClassName, true, this.driverClassLoader);
                    }
                } catch (ClassNotFoundException var6) {
                    driverFromCCL = Thread.currentThread().getContextClassLoader().loadClass(this.driverClassName);
                }
            } catch (Throwable var7) {
                t = var7;
                user = "Cannot load JDBC driver class '" + this.driverClassName + "'";
                this.logWriter.println(user);
                t.printStackTrace(this.logWriter);
                throw new SQLNestedException(user, t);
            }
        }
```



代码`Class.forName(this.driverClassName, true, this.driverClassLoader);` 通过指定ClassLoader加载class，设置2参数initial为true，执行static{}代码块，


## Java内置的反序列化调用

![path](https://qi353.github.io/image/unser_1.png)

我们重写的readObject方式是通过反射调用的

整个调用顺序:`readObject()`->`readObejct0()`->`readOrdinaryObject()`->`readSerialData()`

### resolveClass和resolveProxyClass

这两个方法都是在类`java.io.ObjectInputStream`中,可以在这两个方法中通过classdesc获取类名和代理类的相关接口进行防御方序列化


在调用到readOrdinaryObject()方法时,在new序列化对象之前会调用readClassDesc()获取ObjectStreamClass对象

```java
//调用在调用到readOrdinaryObject()
        depth++;
        totalObjectRefs++;
        try {
            switch (tc) {
                case TC_NULL:
                    return readNull();

                case TC_REFERENCE:
                    // check the type of the existing object
                    return type.cast(readHandle(unshared));

                case TC_CLASS:
                    if (type == String.class) {
                        throw new ClassCastException("Cannot cast a class to java.lang.String");
                    }
                    return readClass(unshared);

                case TC_CLASSDESC:
                case TC_PROXYCLASSDESC:
                    if (type == String.class) {
                        throw new ClassCastException("Cannot cast a class to java.lang.String");
                    }
                    return readClassDesc(unshared);

                case TC_STRING:
                case TC_LONGSTRING:
                    return checkResolve(readString(unshared));

                case TC_ARRAY:
                    if (type == String.class) {
                        throw new ClassCastException("Cannot cast an array to java.lang.String");
                    }
                    return checkResolve(readArray(unshared));

                case TC_ENUM:
                    if (type == String.class) {
                        throw new ClassCastException("Cannot cast an enum to java.lang.String");
                    }
                    return checkResolve(readEnum(unshared));

                case TC_OBJECT:
                    if (type == String.class) {
                        throw new ClassCastException("Cannot cast an object to java.lang.String");
                    }
                    return checkResolve(readOrdinaryObject(unshared));

                case TC_EXCEPTION:
                    if (type == String.class) {
                        throw new ClassCastException("Cannot cast an exception to java.lang.String");
                    }
                    IOException ex = readFatalException();
                    throw new WriteAbortedException("writing aborted", ex);

                case TC_BLOCKDATA:
                case TC_BLOCKDATALONG:
                    if (oldMode) {
                        bin.setBlockDataMode(true);
                        bin.peek();             // force header read
                        throw new OptionalDataException(
                            bin.currentBlockRemaining());
                    } else {
                        throw new StreamCorruptedException(
                            "unexpected block data");
                    }

                case TC_ENDBLOCKDATA:
                    if (oldMode) {
                        throw new OptionalDataException(true);
                    } else {
                        throw new StreamCorruptedException(
                            "unexpected end of block data");
                    }

                default:
                    throw new StreamCorruptedException(
                        String.format("invalid type code: %02X", tc));
            }
```

在这个过程中就调用了`readClassDesc()`->`readNonProxyDesc()`->`resolveCLass()`

```java
    /**
     * Reads in and returns (possibly null) class descriptor.  Sets passHandle
     * to class descriptor's assigned handle.  If class descriptor cannot be
     * resolved to a class in the local VM, a ClassNotFoundException is
     * associated with the class descriptor's handle.
     */
    private ObjectStreamClass readClassDesc(boolean unshared)
        throws IOException
    {
        byte tc = bin.peekByte();
        ObjectStreamClass descriptor;
        switch (tc) {
            case TC_NULL:
                descriptor = (ObjectStreamClass) readNull();
                break;
            case TC_REFERENCE:
                descriptor = (ObjectStreamClass) readHandle(unshared);
                // Should only reference initialized class descriptors
                descriptor.checkInitialized();
                break;
            case TC_PROXYCLASSDESC:
                descriptor = readProxyDesc(unshared);
                break;
            case TC_CLASSDESC:
                descriptor = readNonProxyDesc(unshared);
                break;
            default:
                throw new StreamCorruptedException(
                    String.format("invalid type code: %02X", tc));
        }
        if (descriptor != null) {
            validateDescriptor(descriptor);
        }
        return descriptor;
    }
```

### readSerialData()

在获取带反序列化的实例后,会通过`slotDesc.hasReadObjectMethod()`判断该类是否重写readObject()

是则反射调用我们重写的readObject()方法,执行自定义逻辑

```java
    private void readSerialData(Object obj, ObjectStreamClass desc)
        throws IOException
    {
        ObjectStreamClass.ClassDataSlot[] slots = desc.getClassDataLayout();
        for (int i = 0; i < slots.length; i++) {
            ObjectStreamClass slotDesc = slots[i].desc;

            if (slots[i].hasData) {
                if (obj == null || handles.lookupException(passHandle) != null) {
                    defaultReadFields(null, slotDesc); // skip field values
                } else if (slotDesc.hasReadObjectMethod()) {
                    ThreadDeath t = null;
                    boolean reset = false;
                    SerialCallbackContext oldContext = curContext;
                    if (oldContext != null)
                        oldContext.check();
                    try {
                        curContext = new SerialCallbackContext(obj, slotDesc);

                        bin.setBlockDataMode(true);
                        slotDesc.invokeReadObject(obj, this);
                    } catch (ClassNotFoundException ex) {
                        /*
                         * In most cases, the handle table has already
                         * propagated a CNFException to passHandle at this
                         * point; this mark call is included to address cases
                         * where the custom readObject method has cons'ed and
                         * thrown a new CNFException of its own.
                         */
                        handles.markException(passHandle, ex);
                    } finally {
                        do {
                            try {
                                curContext.setUsed();
                                if (oldContext!= null)
                                    oldContext.check();
                                curContext = oldContext;
                                reset = true;
                            } catch (ThreadDeath x) {
                                t = x;  // defer until reset is true
                            }
                        } while (!reset);
                        if (t != null)
                            throw t;
                    }

                    /*
                     * defaultDataEnd may have been set indirectly by custom
                     * readObject() method when calling defaultReadObject() or
                     * readFields(); clear it to restore normal read behavior.
                     */
                    defaultDataEnd = false;
                } else {
                    defaultReadFields(obj, slotDesc);
                    }

                if (slotDesc.hasWriteObjectData()) {
                    skipCustomData();
                } else {
                    bin.setBlockDataMode(false);
                }
            } else {
                if (obj != null &&
                    slotDesc.hasReadObjectNoDataMethod() &&
                    handles.lookupException(passHandle) == null)
                {
                    slotDesc.invokeReadObjectNoData(obj);
                }
            }
        }
            }

```

### readResolve()

readObject()返回->invokeReadResolve()->readResolve()

