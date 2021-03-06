

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public final class CollectorSender {
      private String ipAddress = "";
      private int port = 0;
      private int protocol = 1;
      private int event = 0;
      private String source = "";
      private String streamName = "";
      private String dataType = "";
      private String tags = "";
      private byte[] data = null;
      private String debuggingInfo = "";
      private long seqId;
      private int recordEndOffsets;

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }
    
    public int getProtocol(){
        return protocol;
    }
    
    public void setProtocol(int protocol){
        this.protocol = protocol;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getStreamName() {
        return streamName;
    }

    public void setStreamName(String streamName) {
        this.streamName = streamName;
    }

    public String getDataType() {
        return dataType;
    }

    public void setDataType(String dataType) {
        this.dataType = dataType;
    }

    public String getTags() {
        return tags;
    }

    public void setTags(String tags) {
        this.tags = tags;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public String getDebuggingInfo() {
        return debuggingInfo;
    }

    public void setDebugging(String debuggingInfo) {
        this.debuggingInfo = debuggingInfo;
    }

    public long getSeqId() {
        return seqId;
    }

    public void setSeqId(long seqId) {
        this.seqId = seqId;
    }

    public int getRecordEndOffsets() {
        return recordEndOffsets;
    }

    public void setRecordEndOffsets(int recordEndOffsets) {
        this.recordEndOffsets = recordEndOffsets;
    }

    public int getEvent() {
        return event;
    }

    public void setEvent(int event) {
        this.event = event;
    }
    
    public String getHttpHeader(long size){
        StringBuilder strBuild = new StringBuilder();
        
        strBuild.append("POST http://" + ipAddress + ":" + Integer.toString(port) + "/chukwa HTTP/1.1\r\n");
        strBuild.append("User-Agent: Jakarta Commons-HttpClient/3.0.1\r\n");
        strBuild.append("Host: " + ipAddress + ":" + Integer.toString(port) + "\r\n");
        strBuild.append("Content-Length: ");
        strBuild.append(size);
        strBuild.append("\r\n");
        strBuild.append("Content-Type: application/octet-stream\r\n");
        strBuild.append("\r\n");
        
        return strBuild.toString();
    }
    
    public long getSize(byte[] data){
        long size = 0;
        
        size += (getDataType().length() + getDebuggingInfo().length() + getSource().length() + 
                getStreamName().length() + getTags().length());
        
        size += data.length;
        size += 36;
        
        return size;
    }
    
    public void sendToCollector(DataOutputStream out, DataInputStream in) throws IOException{
        
        out.writeBytes(getHttpHeader(getSize(data)));
        out.writeInt(getEvent()); //predstavuje kolko paketov pride 
        out.writeInt(getProtocol());
        out.writeLong(data.length);
        out.writeUTF(getSource());
        out.writeUTF(getTags());
        out.writeUTF(getStreamName());
        out.writeUTF(getDataType());
        out.writeUTF(getDebuggingInfo());
        out.writeInt(getRecordEndOffsets());
        out.writeInt(data.length-1);
        out.write(data, 0, data.length);
        
        /*String responseLine;
                while ((responseLine = in.readLine()) != null) {
                    System.out.println("Server: " + responseLine);
                    if (responseLine.indexOf("Ok") != -1) {
                      break;
                    }
                }*/
       
       out.flush();
    }
    
    /*CollectorSender(String ipAddress, int port){
        /*this.ipAddress = ipAddress;
        this.port = port;
        this.setEvent(1);
        this.setProtocol(1);
        this.setSeqId(2);
        this.setSource("hadoopmaster-virutal-machine");
        this.setTags("cluster=\"agent\"");
        this.setSource("agent");
        this.setStreamName("skuska");
        this.setDataType("logs");
        this.setDebugging("none");
        this.setRecordEndOffsets(1);*/

    CollectorSender (Collector collector){
        this.ipAddress = collector.getAddress();
        this.port = collector.getPort();
        this.event = collector.getEvent();
        this.protocol = collector.getProtocol();
        this.seqId = collector.getSeqID();
        this.source = collector.getSource();
        this.tags = collector.getTags();
        this.streamName = collector.getStreamName();
        this.dataType = collector.getDataType();
        this.debuggingInfo = collector.getDebugging();
        this.recordEndOffsets = collector.getRecordEndOffsets();
    }

}
