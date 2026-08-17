package com.bdocyber.views;

import com.bdocyber.helpers.MatchReplaceEngine;
import com.bdocyber.helpers.MatchReplaceRule;
import com.bdocyber.helpers.UndoSupport;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.util.ArrayList;
import java.util.EventObject;
import java.util.List;
import java.util.function.Consumer;

/**
 * Suite UI for automatic request/response match &amp; replace rules.
 * Rules and the master On switch sync to the engine live (no Apply button).
 */
public class MatchReplacePanel extends JPanel {

    public static final String[] TARGET_OPTIONS = {"REQUEST", "RESPONSE", "BOTH"};
    public static final String[] ENCODING_OPTIONS = {
            "UTF16LE",
            "RAW",
            "BOTH"
    };

    private final MatchReplaceEngine engine;
    private final RuleTableModel tableModel;
    private final JTable table;
    private final JCheckBox enabledBox;
    private final JLabel statusLabel;
    private boolean suppressSync;
    private Consumer<Void> changeListener;

    public MatchReplacePanel(MatchReplaceEngine engine) {
        super(new BorderLayout(8, 8));
        this.engine = engine;
        this.tableModel = new RuleTableModel();
        this.table = new JTable(tableModel) {
            @Override
            public boolean editCellAt(int row, int column, EventObject e) {
                boolean started = super.editCellAt(row, column, e);
                if (started) {
                    Component editor = getEditorComponent();
                    if (editor instanceof JComboBox) {
                        final JComboBox<?> combo = (JComboBox<?>) editor;
                        SwingUtilities.invokeLater(combo::showPopup);
                    }
                }
                return started;
            }
        };
        this.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        this.table.setFillsViewportHeight(true);
        this.table.setRowHeight(24);
        this.table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        this.table.setSurrendersFocusOnKeystroke(true);

        this.table.getColumnModel().getColumn(0).setPreferredWidth(45);
        this.table.getColumnModel().getColumn(1).setPreferredWidth(100);
        this.table.getColumnModel().getColumn(2).setPreferredWidth(160);
        this.table.getColumnModel().getColumn(3).setPreferredWidth(160);
        this.table.getColumnModel().getColumn(4).setPreferredWidth(50);
        this.table.getColumnModel().getColumn(5).setPreferredWidth(100);
        this.table.getColumnModel().getColumn(6).setPreferredWidth(140);

        installDropdownColumn(1, TARGET_OPTIONS);
        installDropdownColumn(5, ENCODING_OPTIONS);
        // Free-text: Match, Replace, Comment
        this.table.getColumnModel().getColumn(2).setCellEditor(UndoSupport.textCellEditor());
        this.table.getColumnModel().getColumn(3).setCellEditor(UndoSupport.textCellEditor());
        this.table.getColumnModel().getColumn(6).setCellEditor(UndoSupport.textCellEditor());

        // Live sync table → engine
        this.tableModel.addTableModelListener(e -> {
            if (suppressSync) {
                return;
            }
            // Defer so cell editor can finish writing setValueAt
            if (e.getType() == TableModelEvent.UPDATE && e.getFirstRow() == TableModelEvent.HEADER_ROW) {
                return;
            }
            SwingUtilities.invokeLater(this::pushToEngine);
        });

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        // Master switch: turns auto match/replace on/off for the whole engine
        enabledBox = new JCheckBox("On", engine.isEnabled());
        enabledBox.setToolTipText(
                "Master switch. When checked, enabled rules apply live on relay/Proxy traffic.");
        enabledBox.addActionListener(e -> {
            stopEditing();
            pushToEngine();
        });
        top.add(enabledBox);

        statusLabel = new JLabel(" ");
        top.add(Box.createHorizontalStrut(12));
        top.add(statusLabel);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton add = new JButton("Add rule");
        add.addActionListener(e -> {
            stopEditing();
            tableModel.addRule(new MatchReplaceRule(true, "BOTH", "", "", false, "UTF16LE", ""));
        });
        JButton remove = new JButton("Remove selected");
        remove.addActionListener(e -> {
            stopEditing();
            int row = table.getSelectedRow();
            if (row >= 0) {
                tableModel.removeRule(row);
            }
        });
        buttons.add(add);
        buttons.add(remove);

        JPanel north = new JPanel(new BorderLayout());
        north.add(top, BorderLayout.NORTH);
        north.add(buttons, BorderLayout.CENTER);

        add(north, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);

        suppressSync = true;
        if (engine.getRules().isEmpty()) {
            // Example only when nothing was restored from the project
            tableModel.addRule(new MatchReplaceRule(
                    false, "REQUEST", "APPAPMANAGER1", "APPAPMANAGER1",
                    false, "UTF16LE", "example: enable + change Replace (UTF16LE)"));
        } else {
            tableModel.setRules(engine.getRules());
        }
        enabledBox.setSelected(engine.isEnabled());
        suppressSync = false;
        pushToEngine();
    }

    public void setChangeListener(Consumer<Void> listener) {
        this.changeListener = listener;
    }

    /** Refresh table from engine (after project load). */
    public void reloadFromEngine() {
        suppressSync = true;
        tableModel.setRules(engine.getRules());
        enabledBox.setSelected(engine.isEnabled());
        suppressSync = false;
        updateStatus();
    }

    private void notifyChanged() {
        if (changeListener != null) {
            try {
                changeListener.accept(null);
            } catch (Exception ignored) {
            }
        }
    }

    private void stopEditing() {
        if (table.isEditing()) {
            table.getCellEditor().stopCellEditing();
        }
    }

    private void installDropdownColumn(int columnIndex, String[] options) {
        TableColumn column = table.getColumnModel().getColumn(columnIndex);

        JComboBox<String> editorCombo = new JComboBox<>(options);
        editorCombo.setEditable(false);
        DefaultCellEditor editor = new DefaultCellEditor(editorCombo) {
            @Override
            public boolean isCellEditable(EventObject e) {
                if (e instanceof java.awt.event.MouseEvent) {
                    return ((java.awt.event.MouseEvent) e).getClickCount() >= 1;
                }
                return super.isCellEditable(e);
            }
        };
        editor.setClickCountToStart(1);
        column.setCellEditor(editor);
        column.setCellRenderer(new ComboBoxCellRenderer(options));
    }

    private static class ComboBoxCellRenderer implements TableCellRenderer {
        private final JComboBox<String> combo;

        ComboBoxCellRenderer(String[] options) {
            this.combo = new JComboBox<>(options);
            this.combo.setEditable(false);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            if (value != null) {
                combo.setSelectedItem(value.toString());
            }
            combo.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
            combo.setForeground(isSelected ? table.getSelectionForeground() : table.getForeground());
            combo.setEnabled(table.isEnabled());
            return combo;
        }
    }

    private void pushToEngine() {
        stopEditing();
        engine.setRules(tableModel.getRules());
        engine.setEnabled(enabledBox.isSelected());
        updateStatus();
        if (!suppressSync) {
            notifyChanged();
        }
    }

    private void updateStatus() {
        statusLabel.setText(statusSummary());
    }

    private String statusSummary() {
        return (engine.isEnabled() ? "ON" : "OFF")
                + " · " + engine.enabledRuleCount() + " active rule(s)"
                + " · " + engine.getRules().size() + " total";
    }

    private static class RuleTableModel extends AbstractTableModel {
        private final String[] cols = {
                "On", "Target", "Match", "Replace", "Regex", "Encoding", "Comment"
        };
        private final List<MatchReplaceRule> rules = new ArrayList<>();

        public void setRules(List<MatchReplaceRule> list) {
            rules.clear();
            for (MatchReplaceRule r : list) {
                rules.add(r.copy());
            }
            fireTableDataChanged();
        }

        public List<MatchReplaceRule> getRules() {
            List<MatchReplaceRule> out = new ArrayList<>();
            for (MatchReplaceRule r : rules) {
                out.add(r.copy());
            }
            return out;
        }

        public void addRule(MatchReplaceRule r) {
            rules.add(r);
            fireTableRowsInserted(rules.size() - 1, rules.size() - 1);
        }

        public void removeRule(int row) {
            rules.remove(row);
            fireTableRowsDeleted(row, row);
        }

        @Override
        public int getRowCount() {
            return rules.size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public String getColumnName(int column) {
            return cols[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0 || columnIndex == 4) {
                return Boolean.class;
            }
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return true;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            MatchReplaceRule r = rules.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> r.isEnabled();
                case 1 -> normalizeTarget(r.getTarget());
                case 2 -> r.getMatch();
                case 3 -> r.getReplace();
                case 4 -> r.isRegex();
                case 5 -> normalizeEncoding(r.getEncoding());
                case 6 -> r.getComment();
                default -> "";
            };
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            MatchReplaceRule r = rules.get(rowIndex);
            switch (columnIndex) {
                case 0 -> r.setEnabled(Boolean.TRUE.equals(aValue));
                case 1 -> r.setTarget(normalizeTarget(String.valueOf(aValue)));
                case 2 -> r.setMatch(aValue == null ? "" : String.valueOf(aValue));
                case 3 -> r.setReplace(aValue == null ? "" : String.valueOf(aValue));
                case 4 -> r.setRegex(Boolean.TRUE.equals(aValue));
                case 5 -> r.setEncoding(normalizeEncoding(String.valueOf(aValue)));
                case 6 -> r.setComment(aValue == null ? "" : String.valueOf(aValue));
                default -> {
                }
            }
            fireTableCellUpdated(rowIndex, columnIndex);
        }

        private static String normalizeTarget(String t) {
            if (t == null) {
                return "BOTH";
            }
            String u = t.trim().toUpperCase();
            if ("CLIENT".equals(u)) {
                return "REQUEST";
            }
            if ("SERVER".equals(u)) {
                return "RESPONSE";
            }
            for (String opt : TARGET_OPTIONS) {
                if (opt.equals(u)) {
                    return opt;
                }
            }
            return "BOTH";
        }

        private static String normalizeEncoding(String e) {
            if (e == null) {
                return "UTF16LE";
            }
            String u = e.trim().toUpperCase().replace("-", "").replace("_", "");
            if ("UTF16LE".equals(u) || "UTF16".equals(u) || "UNICODE".equals(u)) {
                return "UTF16LE";
            }
            if ("RAW".equals(u) || "LATIN1".equals(u) || "ASCII".equals(u)) {
                return "RAW";
            }
            if ("BOTH".equals(u) || "ALL".equals(u)) {
                return "BOTH";
            }
            return "UTF16LE";
        }
    }
}
