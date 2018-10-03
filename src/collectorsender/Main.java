

import java.util.ArrayList;
/*
* prvy argument cesta k priecinku final
* druhy argument cesta ku XML
*
*/

public class Main {
    
    public static void main(String args[]){
        FilesReader fileReader = new FilesReader();
        ArrayList<String> filePaths = null;
        ConnectionEstablisherSender establisher = new ConnectionEstablisherSender();
        ConfigurationXMLReader configXML = new ConfigurationXMLReader();
        ArrayList<Collector> collectors;
        int result;
        Collector collector;
        
        System.out.println("Start zasielania suborov.");

        if( configXML.readXML(args[0]) != 0 ){
            System.out.println("Chyba. skontrolujte XML subor.");
            System.exit(1);
        }

        filePaths = fileReader.scanFolder(configXML.getCollectors().get(0).getFinalDirectoryPath());
        if (filePaths.size() == 0){
            System.out.println("Nie su subory na zaslanie.");
            System.exit(-1);
        }

            collectors = configXML.getCollectors();
            for(int collectorNum = 0 ; collectorNum < collectors.size(); collectorNum++) {
                collector = collectors.get(collectorNum);
                result = 0;
                for (int i = 0; i < filePaths.size(); i++) {
                    //ak sa subor odosle spravne na kollektor, vrati sa nula
                    if(filePaths.get(i).endsWith("xml"))
                        collector.setDataType("NetworkMetrics");
                    if (filePaths.get(i).endsWith("txt"))
                        collector.setDataType("NetworkData");

                    result += establisher.establishAndSend(filePaths.get(i), collector );

                }

                if(result == 0) // ak sa vsetky subory odoslali korektne na nejaky kollektor - koncime
                {
                    for (int i = 0; i < filePaths.size(); i++)
                        fileReader.deleteFile(filePaths.get(i)); // zmazene vsetky subory

                    filePaths.clear();
                    System.out.println("Koniec zasielania suborov.");
                    System.exit(0);
                }
            }
            filePaths.clear();
            System.out.println("Nebolo mozne sa odoslat data na ziadny z Collectorov.");
            System.exit(1);
        }
    

        

    }
    

