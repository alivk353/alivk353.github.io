
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