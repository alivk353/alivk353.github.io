# CommonsCollections2&CommonsCollections4

cc2和cc4是针对commons-collections4库的利用链,4版本是3.2.1版本的分支,apache官方对旧版进行了架构上的升级,所以4版本和3版本在maven仓库中有不同id,可以同时存在一个项目中.

## CommonsCollections2

### PriorityQueue利⽤链

首先是ysoserial的cc2的godget:

```text
/*
	Gadget chain:
		ObjectInputStream.readObject()
			PriorityQueue.readObject()
				...
					TransformingComparator.compare()
						InvokerTransformer.transform()
							Method.invoke()
								Runtime.exec()
 */
```

PriorityQueue字面意思是优先级队列,所以才会在插入数据时进行比较并把数据放到合适的位置,同样他也是可序列化对象,那么在反序列PriorityQueue时就会对队列内的数据进行恢复

在readObject()内对数据结构进行复原时,会调用到TransformingComparator.compare(),从而触发命令执行

在创建PriorityQueue对象时传入构造好的TransformingComparator实例

#### TransformingComparator

`TransformingComparator`是实现`java.util.Comparator`的针对数据结构的功能类,实现了compare方法用于比较数据,方法内部


```java
   public int compare(final I obj1, final I obj2) {
        final O value1 = this.transformer.transform(obj1);
        final O value2 = this.transformer.transform(obj2);
        return this.decorated.compare(value1, value2);
    }
```

compare方法中的this.transformer是在构造对象时传入的参数,当然是传入可以执行命令的`InvokerTransformer`

#### 用到了TemplatesImpl

在构建InvokerTransformer时传入要执行的方法是`newTransformer`:

```java
final InvokerTransformer transformer = new InvokerTransformer("newTransformer", new Class[0], new Object[0]);
```

再将构建好的TemplatesImpl类作为队列的数据添加,这样反序列化PriorityQueue对象时会触发命令执行.

## CommonsCollections4

### 使用InstantiateTransformer替代InvokerTransformer.


至于CC4的godget和CC2的区别在于使用InstantiateTransformer替换背过滤的InvokerTransformer

InstantiateTransformer类的tranformer方法

```java

    public InstantiateTransformer(final Class<?>[] paramTypes, final Object[] args) {
        super();
        iParamTypes = paramTypes != null ? paramTypes.clone() : null;
        iArgs = args != null ? args.clone() : null;
    }

    /**
     * Transforms the input Class object to a result by instantiation.
     *
     * @param input  the input object to transform
     * @return the transformed result
     */
    public T transform(final Class<? extends T> input) {
        try {
            if (input == null) {
                throw new FunctorException(
                    "InstantiateTransformer: Input object was not an instanceof Class, it was a null object");
            }
            final Constructor<? extends T> con = input.getConstructor(iParamTypes);
            return con.newInstance(iArgs);
        } catch (final NoSuchMethodException ex) {
            throw new FunctorException("InstantiateTransformer: The constructor must exist and be public ");
        } catch (final InstantiationException ex) {
            throw new FunctorException("InstantiateTransformer: InstantiationException", ex);
        } catch (final IllegalAccessException ex) {
            throw new FunctorException("InstantiateTransformer: Constructor must be public", ex);
        } catch (final InvocationTargetException ex) {
            throw new FunctorException("InstantiateTransformer: Constructor threw an exception", ex);
        }
    }

}
```

后续和CC3基本上一致的,将构建好的chainTranformers作为参数传给PriorityQueue的构造函数即可.
