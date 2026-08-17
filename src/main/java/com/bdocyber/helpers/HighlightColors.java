package com.bdocyber.helpers;

import java.awt.Color;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Named highlight colors for TCP streams / frames (Burp-like palette).
 */
public final class HighlightColors {

    public static final String NONE = "";

    private static final Map<String, Color> COLORS = new LinkedHashMap<>();

    static {
        COLORS.put("red", new Color(255, 180, 180));
        COLORS.put("orange", new Color(255, 210, 160));
        COLORS.put("yellow", new Color(255, 255, 160));
        COLORS.put("green", new Color(180, 240, 180));
        COLORS.put("cyan", new Color(170, 235, 245));
        COLORS.put("blue", new Color(180, 200, 255));
        COLORS.put("pink", new Color(255, 190, 220));
        COLORS.put("magenta", new Color(235, 180, 255));
        COLORS.put("gray", new Color(210, 210, 210));
    }

    private HighlightColors() {
    }

    public static String[] names() {
        return COLORS.keySet().toArray(new String[0]);
    }

    public static String normalize(String name) {
        if (name == null || name.isBlank() || "none".equalsIgnoreCase(name.trim())
                || "clear".equalsIgnoreCase(name.trim()) || "-".equals(name.trim())) {
            return NONE;
        }
        String key = name.trim().toLowerCase(Locale.ROOT);
        return COLORS.containsKey(key) ? key : NONE;
    }

    public static boolean hasHighlight(String name) {
        return !normalize(name).isEmpty();
    }

    public static Color background(String name) {
        String key = normalize(name);
        if (key.isEmpty()) {
            return null;
        }
        return COLORS.get(key);
    }

    /** Short marker for list labels, e.g. "[red] ". */
    public static String labelPrefix(String name) {
        String key = normalize(name);
        if (key.isEmpty()) {
            return "";
        }
        return "[" + key + "] ";
    }

    public static String displayName(String name) {
        String key = normalize(name);
        if (key.isEmpty()) {
            return "None";
        }
        return Character.toUpperCase(key.charAt(0)) + key.substring(1);
    }
}
