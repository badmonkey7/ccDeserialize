import java.io.FileInputStream;
import java.io.ObjectInputStream;

public class ServerDemo {
    public static void main(String[] args) {
        try(
                FileInputStream fis = new FileInputStream("payload.txt");
                ObjectInputStream ois = new ObjectInputStream(fis);
        ){
            Object  object= ois.readObject();
//            System.out.println(object);
//            Transformer transformer = (Transformer) ois.readObject();
//            Process process = (Process) transformer.transform(null);
//            Scanner
        }catch (Exception e){
            e.printStackTrace();
        }

    }
}
