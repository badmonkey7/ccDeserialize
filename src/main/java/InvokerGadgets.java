import org.apache.commons.collections.functors.InvokerTransformer;

import java.util.Scanner;

public class InvokerGadgets {

    public static void main(String[] args) {
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"whoami"});

        Process process = (Process) invokerTransformer.transform(Runtime.getRuntime());
        Scanner scanner = new Scanner(process.getInputStream());
        String res  = scanner.hasNext()?scanner.next():"";
        System.out.println(res);
    }
}

