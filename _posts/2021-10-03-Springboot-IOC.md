# tittle

## 几个注解

### @Component

标记一个组件 

### import 

向容器中导入组件,使用在程序中某个组件类上,导入的参数是类数组,根据类数组中类的不同分三种情况:

当@import引入的类是不同的组件时,会调用指定类的默认无参构造方法并注入容器

当@import引入的类实现了ImportSelector接口或是实现了ImportSelector接口的类的子类时,会调用类的`selectImports`方法实现复杂情况的配置导入

当import的是 `ImportBeanDefinitionRegistrar` 接口的实现时,初始化Registrar类后调用registerBeanDefinitions方法.

### @Conditional

满足Conditional条件的情况下才会注入到容器中

例如当前JVM中存在某组件的依赖时,会执行这种组件的autoconfig

### @ConfigurationProperties

springboot项目中的`application.properties`文件中,提供所有组件的配置参数

@ConfigurationProperties作用与已经导入容器的组件上将`application.properties`文件中的配置绑定到当前类的属性上

```java
@Component
@ConfigurationProperties(prefix = "test")
```

将`application.properties`文件汇总test开头的配置项绑定到类属性上

## 自动装配

### 组件的自动配置流程

@SpringBootApplication注解用于整个web程序的入口main方法的application类上

它整合了如下三个注解:

```java
@SpringBootConfiguration //标记当前的application类是一个配置类
@EnableAutoConfiguration //开启自动配置流程
@ComponentScan( // 指定扫描的包的范围 默认为当前application类的所在包
    excludeFilters = {@Filter(
    type = FilterType.CUSTOM,
    classes = {TypeExcludeFilter.class}
), @Filter(
    type = FilterType.CUSTOM,
    classes = {AutoConfigurationExcludeFilter.class}
)}
)
public @interface SpringBootApplication {}


```

#### @EnableAutoConfiguration

整合了`@AutoConfigurationPackage`和`@Import`两个注解

```java
@AutoConfigurationPackage
@Import({AutoConfigurationImportSelector.class})
public @interface EnableAutoConfiguration {}
```

##### 接着是`@AutoConfigurationPackage`

```java
@Import({Registrar.class})
public @interface AutoConfigurationPackage {
```

可以看出Registrar类是`ImportBeanDefinitionRegistrar`的实现:

```java
static class Registrar implements ImportBeanDefinitionRegistrar, DeterminableImports {
        Registrar() {
        }

        public void registerBeanDefinitions(AnnotationMetadata metadata, BeanDefinitionRegistry registry) {
            AutoConfigurationPackages.register(registry, (String[])(new AutoConfigurationPackages.PackageImports(metadata)).getPackageNames().toArray(new String[0]));
        }

        public Set<Object> determineImports(AnnotationMetadata metadata) {
            return Collections.singleton(new AutoConfigurationPackages.PackageImports(metadata));
        }
    }
```

这里会调用registerBeanDefinitions方法,参数metadata是注解的元信息:

![path](https://nanazeven.github.io/image/2021-11-02-15-32-37.png)

执行的结果是将当前包路径`com.q`注册到`AutoConfigurationPackages`类中,为的是将这个包的所有组件导入进来

##### 接着的注解是`@Import({AutoConfigurationImportSelector.class})`

import注解导入类是`ImportSelector`接口的实现类,会掉用selectImports方法:


```java
    public String[] selectImports(AnnotationMetadata annotationMetadata) {
        if (!this.isEnabled(annotationMetadata)) {
            return NO_IMPORTS;
        } else {
            AutoConfigurationImportSelector.AutoConfigurationEntry autoConfigurationEntry = this.getAutoConfigurationEntry(annotationMetadata);
            return StringUtils.toStringArray(autoConfigurationEntry.getConfigurations());
        }
    }
```

返回值是一个String数组,规定了具体要导入那些组件,调用`this.getAutoConfigurationEntry`字面意思为获取自动配置集合:

```java
protected AutoConfigurationImportSelector.AutoConfigurationEntry getAutoConfigurationEntry(AnnotationMetadata annotationMetadata) {
        if (!this.isEnabled(annotationMetadata)) {
            return EMPTY_ENTRY;
        } else {
            AnnotationAttributes attributes = this.getAttributes(annotationMetadata);
            List<String> configurations = this.getCandidateConfigurations(annotationMetadata, attributes);
            configurations = this.removeDuplicates(configurations);
            Set<String> exclusions = this.getExclusions(annotationMetadata, attributes);
            this.checkExcludedClasses(configurations, exclusions);
            configurations.removeAll(exclusions);
            configurations = this.getConfigurationClassFilter().filter(configurations);
            this.fireAutoConfigurationImportEvents(configurations, exclusions);
            return new AutoConfigurationImportSelector.AutoConfigurationEntry(configurations, exclusions);
        }
    }

```

通过调用`this.getCandidateConfigurations`获取当前引入依赖的Jar包的`spring-boot-autoconfigure-2.5.4.jar!/META-INF/spring.factories`文件内所包括的spring支持的全部场景的自动配置类:

![path](https://nanazeven.github.io/image/2021-11-02-15-55-11.png)

根据spring.factories写死的全类名配置类去一一加载,过程中通过@Conditional注解按需加载.

整个流程的调用栈为:

![path](https://nanazeven.github.io/image/2021-11-02-16-05-31.png)

