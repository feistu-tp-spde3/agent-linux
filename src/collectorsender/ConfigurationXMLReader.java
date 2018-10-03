

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.ArrayList;

/**
 * Created by Juraj on 31-May-16.
 */
public class ConfigurationXMLReader {

    private ArrayList<Collector> collectors = new ArrayList<>();

    public int readXML(String fileName)
    {
        File file = new File(fileName);
        DocumentBuilderFactory documentBuilderFactory;
        DocumentBuilder documentBuilder;
        Document document;
        String port, value, address;
        NodeList settingsNodes, childList, collectorAddressNodes;
        Node child;
        Collector collector = null;

        documentBuilderFactory = DocumentBuilderFactory.newInstance();

        try {
            documentBuilder = documentBuilderFactory.newDocumentBuilder();
            document = documentBuilder.parse(file);
        }
        catch(Exception e){
            e.printStackTrace();
            return -1;
        }

        settingsNodes = document.getElementsByTagName("Settings");

        if (settingsNodes.getLength() == 0) {
            return -1;
        }

        childList = settingsNodes.item(0).getChildNodes();
        collector = new Collector();

        for(int i = 0; i< childList.getLength(); i++){
            child = childList.item(i);
            switch (child.getNodeName()){
                case "Event":
                    value = child.getTextContent();
                    collector.setEvent(Integer.parseInt(value));
                    break;
                case "Protocol":
                    value = child.getTextContent();
                    collector.setProtocol(Integer.parseInt(value));
                    break;
                case "Source":
                    value = child.getTextContent();
                    collector.setSource(value);
                    break;
                case "Tags":
                    value = child.getTextContent();
                    collector.setTags(value);
                    break;
                case "StreamName":
                    value = child.getTextContent();
                    collector.setStreamName(value);
                    break;
                case "Debugging":
                    value = child.getTextContent();
                    collector.setDebugging(value);
                    break;
                case "RecordEndOffsets":
                    value = child.getTextContent();
                    collector.setRecordEndOffsets(Integer.parseInt(value));
                    break;
                case "FinalDirectory":
                    value = child.getTextContent();
                    collector.setFinalDirectoryPath(value);
                    break;
           }


        }

        collectorAddressNodes = document.getElementsByTagName("Collector"); // get addresses of collectr
        if(collectorAddressNodes.getLength() == 0){
            return -1;
        }

        for(int i = 0; i < collectorAddressNodes.getLength(); i++){
            value = collectorAddressNodes.item(i).getTextContent();
            address = value.substring(0, value.indexOf(':'));
            collector.setAddress(address);
            port = value.substring(value.indexOf(':') + 1, value.length());
            collector.setPort(Integer.parseInt(port));
            this.collectors.add(new Collector(collector)); // add as many collectors as many addresses are defined
        }


        return 0;
    }

    public ArrayList<Collector> getCollectors() {
        return collectors;
    }
}
