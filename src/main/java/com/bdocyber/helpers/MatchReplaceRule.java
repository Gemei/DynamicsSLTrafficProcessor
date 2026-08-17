package com.bdocyber.helpers;

/**
 * A single automatic match/replace rule for TDS (TCP relay / Proxy).
 */
public class MatchReplaceRule {
    private boolean enabled = true;
    /** REQUEST, RESPONSE, or BOTH */
    private String target = "BOTH";
    private String match = "";
    private String replace = "";
    private boolean regex = false;
    /**
     * How to apply the match string to binary TDS bodies:
     * RAW = Latin-1/byte string as typed;
     * UTF16LE = encode match/replace as UTF-16LE (typical for SQL text);
     * BOTH = try UTF16LE then RAW.
     */
    private String encoding = "BOTH";
    private String comment = "";

    public MatchReplaceRule() {
    }

    public MatchReplaceRule(boolean enabled, String target, String match, String replace,
                            boolean regex, String encoding, String comment) {
        this.enabled = enabled;
        this.target = target;
        this.match = match;
        this.replace = replace;
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

    public String getReplace() {
        return replace;
    }

    public void setReplace(String replace) {
        this.replace = replace;
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

    public boolean appliesToRequest() {
        String t = target == null ? "BOTH" : target.toUpperCase();
        return "REQUEST".equals(t) || "BOTH".equals(t) || "CLIENT".equals(t);
    }

    public boolean appliesToResponse() {
        String t = target == null ? "BOTH" : target.toUpperCase();
        return "RESPONSE".equals(t) || "BOTH".equals(t) || "SERVER".equals(t);
    }

    public MatchReplaceRule copy() {
        return new MatchReplaceRule(enabled, target, match, replace, regex, encoding, comment);
    }
}
