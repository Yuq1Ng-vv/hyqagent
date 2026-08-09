/** Cross-language SSTI fixture — Java (FreeMarker). */

public class SstiEndpoint {

    public void render() {
        String template = System.getProperty("user.template");  // $ source=ssti
        try {
            freemarker.template.Configuration cfg =
                new freemarker.template.Configuration();
            freemarker.template.Template t = cfg.getTemplate(template);  // $ sink=ssti
            java.io.StringWriter out = new java.io.StringWriter();
            t.process(null, out);
        } catch (Exception e) {}
    }
}
