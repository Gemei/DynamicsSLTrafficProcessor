package com.bdocyber.helpers;

/**
 * Rule that pauses relay traffic when request/response body matches text.
 */
public class InterceptRule {
    private boolean enabled = true;
    /** REQUEST (C→S), RESPONSE (S→C), or BOTH */
    private String target = "BOTH";
    private String match = "";
    private boolean regex = false;
    private String encoding = "UTF16LE";
    private String comment = "";

    public InterceptRule() {
    }

    public InterceptRule(boolean enabled, String target, String match, boolean regex,
                         String encoding, String comment) {
        this.enabled = enabled;
        this.target = target;
        this.match = match;
        this.regex = regex;
        this.encoding = encoding;
        this.comment = comment;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public String getMatch() {
        return match;
    }

    public void setMatch(String match) {
        this.match = match;
    }

    public boolean isRegex() {
        return regex;
    }

    public void setRegex(boolean regex) {
        this.regex = regex;
    }

    public String getEncoding() {
        return encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public boolean appliesToClientToServer() {
        String t = target == null ? "BOTH" : target.toUpperCase();
        return "REQUEST".equals(t) || "BOTH".equals(t) || "C2S".equals(t) || "CLIENT".equals(t);
    }

    public boolean appliesToServerToClient() {
        String t = target == null ? "BOTH" : target.toUpperCase();
        return "RESPONSE".equals(t) || "BOTH".equals(t) || "S2C".equals(t) || "SERVER".equals(t);
    }

    public InterceptRule copy() {
        return new InterceptRule(enabled, target, match, regex, encoding, comment);
    }
}
