

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;


public class FilesReader {
    private String path;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }
    
    public ArrayList<String> scanFolder(String path){
        
        File folder = new File(path);
        File[] listOfFiles = folder.listFiles();
        ArrayList<String> listOfPaths = new ArrayList<>();
        
            for (File file : listOfFiles) {
                if (file.isFile()) {
                
                    if (file.length() != 0){
                        listOfPaths.add(file.getAbsolutePath());
                    }
                    else{
                        deleteFile(file.getAbsolutePath());
                    }
                
                }
            }



        return listOfPaths;
    }
    
    public byte[] readFile(String path) throws IOException{
        byte[] data;
        Path pathToFile = Paths.get(path);
        
        data = Files.readAllBytes(pathToFile);
        
        return data;
    }
    
    public void deleteFile(String path){
        File file = new File(path);
        
        if(file.delete()){
            System.out.println(file.getName() + " vymazany.s");
            
        }
    }
}
