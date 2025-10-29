## memo

- com.thoughtworks.xstream.core.TreeUnmarshaller
    - com.thoughtworks.xstream.core.AbstractReferenceUnmarshaller
        - com.thoughtworks.xstream.core.ReferenceByXPathUnmarshaller

#### 解析标签名对应的class 层层mapper结构 执行逻辑类Filter
`<map class="x.x.Xxx"或resolves-to="x.x.Xxx" reference="">` 
从标签中解析classType属性 属性key`resolves-to`和class
CachingMapper解析 根据标签明map先查缓存 后检查预制标签名 对应class后附
DynamicProxyMapper解析 标签名=dynamic-proxy 代理会被解析为`com.thoughtworks.xstream.mapper.DynamicProxyMapper.DynamicProxy `
最后DefaultMapper返回`Class.forName("x.x.Xxx", initialize, classLoader)` 当为class是数组时，initialize=true


##### com.thoughtworks.xstream.mapper.SecurityMapper

维护`com.thoughtworks.xstream.mapper.SecurityMapper#permissions` 维护白名单 

研发一般会设置com.thoughtworks.xstream.security.AnyTypePermission 允许所有

#### 转化器

创建Converters实例`new XStream()`内call`com.thoughtworks.xstream.XStream#setupConverters`





class为接口 预置对应的实现类 比如：

`"interface java.util.Map" -> "class java.util.HashMap"`
`"interface java.util.SortedSet" -> "class java.util.TreeSet"`

`DefaultConverterLookup#lookupConverterForType` 迭代查找class对应的转换器Converter


- 对特定class的转换处理 如时间日期相关类 UUID格式 
- 字符串处理StringBuilder Enum相关类 Pattern正则 StackTrace异常堆栈类 Throwable 
- 反射相关Field Method Class类
- 代理相关DynamicProxyConverter DynamicProxy
- 文件类FileConverter File
- 字节数组处理EncodedByteArrayConverter byte array
- 集合类SingletonCollectionConverter list set
- 处理去重CollectionConverter set集合类
- 处理Map键值对集合 MapConverter Treemap hashtable hashmap linkmap
- 实现java序列化接口 SerializableConverter 
    - 必须设置`serialization="custom"` 
- ReflectionConverter 不在上述预制cover `Converter.canConvert`默认返回true
    - 存在 `AbstractReflectionConverter#canAccess` 

均实现接口方法`marshal`和`unmarshal `实际序列化操作

`AbstractReferenceUnmarshaller#convert` 调用具体Coverter的`marshal`和`unmarshal`方法

`<map class="x.x.Xxx"或resolves-to="x.x.Xxx" reference="">` 

维护`AbstractReferenceUnmarshaller#parentStack` 存储已处理标签 索引reference属性值决定 默认标签名
维护`AbstractReferenceUnmarshaller#values` 存储已经实例化对象 key=reference属性值

#### 实例化

以第一个map标签为例 进入MapConverter逻辑
- 直接调用class.newInstance() 无参构造
- HierarchicalStreams 解析《entry》标签
- 解析map第一个entry的key对象 按标签名查class
- 例子使用`jdk.nashorn.internal.objects.NativeString` key去重回调`hashCode()`->`toString()`
- 按照Mapper逻辑 由DefaultMapper处理 class
- 对应Coverter ReflectionConverter 处理
- call `MapConverter#putCurrentEntryIntoMap` 依次解析key和value
    - call `ReflectionConverter#unmarshal` 创建一般class实例
    - call  `SerializableConverter` 创建序列化实例
    - 最后call HashMap.put(key,value)
    - 进而调用key.hashCode()

##### AbstractReflectionConverter 

ReflectionConverter和SerializableConverter是AbstractReflectionConverter的子类

负责实例化标签名class，在XStream实例化过程中调用`XStream.setupConverters`注册Coverter

注册Coverter会附带优先级属性int priority xstream反序列化时按优先级顺序 条件是符合Converter.canConver

ReflectionConverter优先级-20 SerializableConverte优先级-10

##### XStream.reflectionProvider属性

用于在ReflectionConverter和SerializableConverter中创建标签实例，XStream不同版本有差异

- 早期版本1.3.x PureJavaReflectionProvider
    - 先调用无参构造
    - 无默认构造函数 实现序列化接口则构建通用序列化data 调用readObject()获得实例
    - 构建通用序列化data只有基础结构 成功与否视目标类实现readObject()复杂程度
    - 既无无参构造也非序列化，报错
- 1.4.x PureJavaReflectionProvider SunLimitedUnsafeReflectionProvider
    - unsafe模块 实例化


```java
Caused by: com.thoughtworks.xstream.converters.reflection.ObjectAccessException: 
    Cannot construct jdk.nashorn.internal.objects.NativeString as it does not have a no-args constructor
	at com.thoughtworks.xstream.converters.reflection.PureJavaReflectionProvider.newInstance(PureJavaReflectionProvider.java:71)
	at com.thoughtworks.xstream.converters.reflection.AbstractReflectionConverter.instantiateNewInstance(AbstractReflectionConverter.java:308)
	at com.thoughtworks.xstream.converters.reflection.AbstractReflectionConverter.unmarshal(AbstractReflectionConverter.java:161)
	at com.thoughtworks.xstream.core.TreeUnmarshaller.convert(TreeUnmarshaller.java:82)
```

##### 一般实例化 v1.4.11 AbstractReflectionConverter#instantiateNewInstance

可以由resolves-to指定具体class
call `SunLimitedUnsafeReflectionProvider#newInstance` 具体实例化
call `unsasun.misc.Unsafe#.allocateInstance(type)` 分配内存空间

> 早期版本默认call无参构造函数，没有则抛异常中断

##### 填充属性

迭代`<jdk.nashorn.internal.objects.NativeString>`标签的子标签

- 根据标签名获取声明属性 `PureJavaReflectionProvider#getFieldOrNull`
- 获取属性class对用的转换器Coverter 后实例化属性 迭代循环处理
- `ReflectionProvider#writeField` call unfase接口赋值
- 标签包含属性`serialization="custom"` 反射调用`readObject()` 
    - 自定义对象输入流`com.thoughtworks.xstream.core.util.CustomObjectInputStream`

### 利用

- jdk.nashorn.internal.objects.NativeString.hashCode()->NativeString.value.toString()
- com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data.toString() -> Base64Data.get()
- Base64Data.get() -> Base64Data.dataHandler.getDataSource()
- com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource.getInputStream() -> java.io.SequenceInputStream.nextStream()
- SequenceInputStream.nextStream() -> javax.swing.MultiUIDefaults.MultiUIDefaultsEnumerator.nextElement()
- javax.swing.MultiUIDefaults.MultiUIDefaultsEnumerator.nextElement() -> MultiUIDefaultsEnumerator.iterator.next()
- javax.imageio.spi.FilterIterator.next() -> FilterIterator.advance() -> FilterIterator.filter.filter()
- javax.imageio.ImageIO$ContainsFilter.filter() -> ImageIO$ContainsFilter.method.invoke()


```json
"empty-list" -> "java.util.Collections$EmptyList"
"awt-text-attribute" -> "java.awt.font.TextAttribute"
"year" -> "java.time.Year"
"chrono-unit" -> "java.time.temporal.ChronoUnit"
"number" -> "java.lang.Number"
"enum-map" -> "java.util.EnumMap"
"path" -> "java.nio.file.Path"
"hashtable" -> "java.util.Hashtable"
"enum-set" -> "java.util.EnumSet"
"iso-field" -> "java.time.temporal.IsoFields$Field"
"local-time" -> "java.time.LocalTime"
"serialized-lambda" -> "java.lang.invoke.SerializedLambda"
"tree-map" -> "java.util.TreeMap"
"offset-date-time" -> "java.time.OffsetDateTime"
"period" -> "java.time.Period"
"thai-buddhist-era" -> "java.time.chrono.ThaiBuddhistEra"
"temporal-value-range" -> "java.time.temporal.ValueRange"
"method" -> "java.lang.reflect.Method"
"sql-timestamp" -> "java.sql.Timestamp"
"double" -> "java.lang.Double"
"byte" -> "java.lang.Byte"
"local-date-time" -> "java.time.LocalDateTime"
"iso-unit" -> "java.time.temporal.IsoFields$Unit"
"auth-subject" -> "javax.security.auth.Subject"
"concurrent-hash-map" -> "java.util.concurrent.ConcurrentHashMap"
"big-decimal" -> "java.math.BigDecimal"
"field" -> "java.lang.reflect.Field"
"local-date" -> "java.time.LocalDate"
"tree-set" -> "java.util.TreeSet"
"object" -> "java.lang.Object"
"charset" -> "java.nio.charset.Charset"
"awt-font" -> "java.awt.Font"
"long" -> "java.lang.Long"
"instant" -> "java.time.Instant"
"file" -> "java.io.File"
"day-of-week" -> "java.time.DayOfWeek"
"japanese-date" -> "java.time.chrono.JapaneseDate"
"week-fields" -> "java.time.temporal.WeekFields"
"vector" -> "java.util.Vector"
"currency" -> "java.util.Currency"
"map" -> "java.util.Map"
"sorted-set" -> "java.util.SortedSet"
"set" -> "java.util.Set"
"xml-duration" -> "javax.xml.datatype.Duration"
"bit-set" -> "java.util.BitSet"
"hijrah-date" -> "java.time.chrono.HijrahDate"
"uri" -> "java.net.URI"
"gregorian-calendar" -> "java.util.Calendar"
"url" -> "java.net.URL"
"char" -> "java.lang.Character"
"activation-data-flavor" -> "javax.activation.ActivationDataFlavor"
"chrono-field" -> "java.time.temporal.ChronoField"
"year-month" -> "java.time.YearMonth"
"date" -> "java.util.Date"
"singleton-set" -> "java.util.Collections$SingletonSet"
"zone-id" -> "java.time.ZoneId"
"string-builder" -> "java.lang.StringBuilder"
"japanese-era" -> "java.time.chrono.JapaneseEra"
"offset-time" -> "java.time.OffsetTime"
"chronology" -> "java.time.chrono.Chronology"
"awt-color" -> "java.awt.Color"
"float" -> "java.lang.Float"
"uuid" -> "java.util.UUID"
"offset-clock" -> "java.time.Clock$OffsetClock"
"linked-list" -> "java.util.LinkedList"
"empty-map" -> "java.util.Collections$EmptyMap"
"linked-hash-map" -> "java.util.LinkedHashMap"
"julian-field" -> "java.time.temporal.JulianFields$Field"
"linked-hash-set" -> "java.util.LinkedHashSet"
"minguo-era" -> "java.time.chrono.MinguoEra"
"constructor" -> "java.lang.reflect.Constructor"
"empty-set" -> "java.util.Collections$EmptySet"
"list" -> "java.util.List"
"sql-time" -> "java.sql.Time"
"entry" -> "java.util.Map$Entry"
"big-int" -> "java.math.BigInteger"
"null" -> "com.thoughtworks.xstream.mapper.Mapper$Null"
"month" -> "java.time.Month"
"thai-buddhist-date" -> "java.time.chrono.ThaiBuddhistDate"
"singleton-map" -> "java.util.Collections$SingletonMap"
"month-day" -> "java.time.MonthDay"
"java-class" -> "java.lang.Class"
"minguo-date" -> "java.time.chrono.MinguoDate"
"system-clock" -> "java.time.Clock$SystemClock"
"string" -> "java.lang.String"
"tick-clock" -> "java.time.Clock$TickClock"
"locale" -> "java.util.Locale"
"duration" -> "java.time.Duration"
"singleton-list" -> "java.util.Collections$SingletonList"
"trace" -> "java.lang.StackTraceElement"
"string-buffer" -> "java.lang.StringBuffer"
"int" -> "java.lang.Integer"
"zoned-date-time" -> "java.time.ZonedDateTime"
"boolean" -> "java.lang.Boolean"
"sql-date" -> "java.sql.Date"
"hijrah-era" -> "java.time.chrono.HijrahEra"
"short" -> "java.lang.Short"
"fixed-clock" -> "java.time.Clock$FixedClock"
"properties" -> "java.util.Properties"

```