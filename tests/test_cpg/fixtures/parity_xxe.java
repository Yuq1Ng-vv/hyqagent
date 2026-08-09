/** Cross-language XXE fixture — Java. */

public class XxeEndpoint {

    public void parse() {
        String xml = System.getProperty("user.xml");  // $ source=xxe
        try {
            javax.xml.parsers.DocumentBuilderFactory factory =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(  // $ sink=xxe
                new java.io.ByteArrayInputStream(xml.getBytes())
            );
        } catch (Exception e) {}
    }
}
