/** Cross-language deserialization fixture — Java. */

public class DeserEndpoint {

    public void handleRequest() {
        String data = System.getProperty("user.data");  // $ source=deserialization
        try {
            java.io.ObjectInputStream ois = new java.io.ObjectInputStream(
                new java.io.ByteArrayInputStream(data.getBytes())
            );
            Object obj = ois.readObject();  // $ sink=deserialization
        } catch (Exception e) {}
    }

    public void handleJackson() {
        String json = System.getProperty("user.json");  // $ source=deserialization
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper =
                new com.fasterxml.jackson.databind.ObjectMapper();
            Object obj = mapper.readValue(json, Object.class);  // $ sink=deserialization
        } catch (Exception e) {}
    }
}
