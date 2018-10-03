

/**
 * Created by Juraj on 31-May-16.
 */
public class Collector{
    private String address;
    private int port;
    private int event;
    private int protocol;
    private int seqID;
    private String source;
    private String tags;
    private String streamName;
    private String dataType;
    private String debugging;
    private int recordEndOffsets;
    private String finalDirectoryPath;

    public Collector(String address, int port, int event, int protocol, int seqID, String source, String tags, String streamName, String dataType, String debugging, int recordEndOffsets, String finalDirectoryPath) {
        this.address = address;
        this.port = port;
        this.event = event;
        this.protocol = protocol;
        this.seqID = seqID;
        this.source = source;
        this.tags = tags;
        this.streamName = streamName;
        this.dataType = dataType;
        this.debugging = debugging;
        this.recordEndOffsets = recordEndOffsets;
        this.finalDirectoryPath = finalDirectoryPath;
    }

    public Collector(Collector collector) {
        this.address = collector.address;
        this.port = collector.port;
        this.event = collector.event;
        this.protocol = collector.protocol;
        this.seqID = collector.seqID;
        this.source = collector.source;
        this.tags = collector.tags;
        this.streamName = collector.streamName;
        this.dataType = collector.dataType;
        this.debugging = collector.debugging;
        this.recordEndOffsets = collector.recordEndOffsets;
        this.finalDirectoryPath = collector.finalDirectoryPath;
    }

    public Collector() {

    }

    public void setAddress(String address) {
        this.address = address;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setEvent(int event) {
        this.event = event;
    }

    public void setProtocol(int protocol) {
        this.protocol = protocol;
    }

    public void setSeqID(int seqID) {
        this.seqID = seqID;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public void setTags(String tags) {
        this.tags = tags;
    }

    public void setStreamName(String streamName) {
        this.streamName = streamName;
    }

    public void setDataType(String dataType) {
        this.dataType = dataType;
    }

    public void setDebugging(String debugging) {
        this.debugging = debugging;
    }

    public void setRecordEndOffsets(int recordEndOffsets) {
        this.recordEndOffsets = recordEndOffsets;
    }

    public String getAddress() {
        return address;
    }

    public int getPort() {
        return port;
    }

    public int getEvent() {
        return event;
    }

    public int getProtocol() {
        return protocol;
    }

    public int getSeqID() {
        return seqID;
    }

    public String getSource() {
        return source;
    }

    public String getTags() {
        return tags;
    }

    public String getStreamName() {
        return streamName;
    }

    public String getDataType() {
        return dataType;
    }

    public String getDebugging() {
        return debugging;
    }

    public int getRecordEndOffsets() {
        return recordEndOffsets;
    }

    public String getFinalDirectoryPath() {
        return finalDirectoryPath;
    }

    public void setFinalDirectoryPath(String finalDirectoryPath) {
        this.finalDirectoryPath = finalDirectoryPath;
    }
}
