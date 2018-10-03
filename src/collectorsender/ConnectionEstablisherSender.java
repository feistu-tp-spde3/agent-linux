

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;


public class ConnectionEstablisherSender {
    private String fileName;
    FilesReader reader = new FilesReader();
    DataOutputStream output = null;
    DataInputStream input = null;
    
    int establishAndSend(String file, Collector collector){
        CollectorSender sender = new CollectorSender(collector);
        Socket socket = null;
        
        System.out.println("Pripajanie na Collector " + sender.getIpAddress() + ":" + sender.getPort());
        try {
            socket = new Socket(sender.getIpAddress(), sender.getPort());
            input = new DataInputStream(socket.getInputStream());
            output = new DataOutputStream(socket.getOutputStream());
        } catch (IOException ex) {
            Logger.getLogger(ConnectionEstablisherSender.class.getName()).log(Level.SEVERE, null, ex);
            return 1;
        }
        
        try {
            System.out.println("Zasielam data na Collector.");
            sender.setData(reader.readFile(file));
            sender.sendToCollector(output, input);
            //reader.deleteFile(file);
            System.out.println("Ukoncuje sa spojenie s Collectorom " + sender.getIpAddress() + ":" + sender.getPort());
            socket.close();
            return 0;
        } catch (IOException ex) {
            Logger.getLogger(ConnectionEstablisherSender.class.getName()).log(Level.SEVERE, null, ex);
            return 1;
        }
    }
}
