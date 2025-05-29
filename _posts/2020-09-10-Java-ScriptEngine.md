# javax.script.AbstractScriptEngine

`javax.script.AbstractScriptEngine`提供java中调用JS代码的接口，jdk8的`NashornScriptEngine`和Bsh的`bsh.engine.BshScriptEngine`

```
ScriptEngineManager factory = new ScriptEngineManager();
ScriptEngine engine = factory.getEngineByName(engineName);
```
获取JVM中实现的ScriptEngine，标准是实现`javax.script.ScriptEngine`和`javax.script.ScriptEngineFactory`接口

继承`javax.script.AbstractScriptEngine`类

## NashornScriptEngine

`getEngineByName(name)` 参数可以是nashorn Nashorn js JS JavaScript javascript ECMAScript ecmascript

#### 执行一段JS code

```java
ScriptEngineManager manager = new ScriptEngineManager();
ScriptEngine engine = manager.getEngineByName("nashorn");
// evaluate JavaScript code
engine.eval("print('Hello, World')");
engine.eval(new java.io.FileReader("script.js"));
```

#### 导出java对象到engine的全局变量

```java
ScriptEngineManager manager = new ScriptEngineManager();
ScriptEngine engine = manager.getEngineByName("nashorn");
// create File object
File f = new File("test.txt");
// expose File object as a global variable to the engine
engine.put("file", f);
// evaluate JavaScript code and access the variable
engine.eval("print(file.getAbsolutePath())");
```

#### 定义JS函数和对象 由java接口调用



`javax.script.Invocable`接口 

`invokeFunction(String name, Object... args)` 可以调用engine定义过的函数

```java
ScriptEngineManager manager = new ScriptEngineManager();
 ScriptEngine engine = manager.getEngineByName("nashorn");
 // evaluate JavaScript code that defines a function with one parameter
 engine.eval("function hello(name) { print('Hello, ' + name) }");
 // create an Invocable object by casting the script engine object
 Invocable inv = (Invocable) engine;
 // invoke the function named "hello" with "Scripting!" as the argument
 inv.invokeFunction("hello", "Scripting!");
```


`invokeMethod(Object thiz, String name, Object... args)` 可以调用执行过程中对象的方法

```java
ScriptEngineManager manager = new ScriptEngineManager();
 ScriptEngine engine = manager.getEngineByName("nashorn");
 // evaluate JavaScript code that defines an object with one method
 engine.eval("var obj = new Object()");
 engine.eval("obj.hello = function(name) { print('Hello, ' + name) }");
 // expose object defined in the script to the Java application
 Object obj = engine.get("obj");
 // create an Invocable object by casting the script engine object
 Invocable inv = (Invocable) engine;
 // invoke the method named "hello" on the object defined in the script
 // with "Script Method!" as the argument
 inv.invokeMethod(obj, "hello", "Script Method!");
```