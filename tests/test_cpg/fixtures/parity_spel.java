/** Cross-language SpEL injection fixture — Java. */

public class SpelEndpoint {

    public void evaluate() {
        String expr = System.getProperty("user.expr");  // $ source=code_injection
        org.springframework.expression.ExpressionParser parser =
            new org.springframework.expression.spel.standard.SpelExpressionParser();
        org.springframework.expression.Expression exp =
            parser.parseExpression(expr);  // $ sink=code_injection
        Object value = exp.getValue();
    }
}
