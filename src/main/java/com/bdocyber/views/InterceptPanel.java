package com.bdocyber.views;

import burp.api.montoya.logging.Logging;
import com.bdocyber.helpers.InterceptEngine;
import com.bdocyber.helpers.InterceptRule;
import com.bdocyber.helpers.TdsHelper;
import com.bdocyber.helpers.TdsSimpleView;
import com.bdocyber.helpers.UndoSupport;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.TableModelEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Configure body-match intercept rules and resolve held relay frames.
 */
public class InterceptPanel extends JPanel {

    public static final String[] TARGET_OPTIONS = {"REQUEST", "RESPONSE", "BOTH"};
    public static final String[] ENCODING_OPTIONS = {"UTF16LE", "RAW", "BOTH"};

    private final InterceptEngine engine;
    private final Logging logging;
    private final TdsHelper tdsHelper;
    private final RuleTableModel ruleModel = new RuleTableModel();
    private final DefaultListModel<String> pendingListModel = new DefaultListModel<>();
    private final JList<String> pendingList;
    private final List<InterceptEngine.PendingIntercept> pendingItems = new ArrayList<>();
    private final JTextArea detailArea;
    private final JCheckBox enabledBox;
    private final JSpinner timeoutSpin;
    private final JLabel statusLabel;
    private final JRadioButton detailSimple = new JRadioButton("Simple", true);
    private final JRadioButton detailFull = new JRadioButton("Full", false);
    private boolean suppressSync;
    private Consumer<Void> changeListener;

    public InterceptPanel(Logging logging, InterceptEngine engine) {
        super(new BorderLayout(8, 8));
        setBorder(new EmptyBorder(8, 8, 8, 8));
        this.logging = logging;
        this.engine = engine;
        this.tdsHelper = new TdsHelper();

        enabledBox = new JCheckBox("Enable intercept (pauses matching relay frames)", engine.isEnabled());
        timeoutSpin = new JSpinner(new SpinnerNumberModel(
                (int) Math.min(Integer.MAX_VALUE, Math.max(0, engine.getTimeoutSeconds())),
                0, 3600, 5));
        statusLabel = new JLabel(" ");

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(enabledBox);
        top.add(new JLabel("Timeout (sec, 0=forever):"));
        top.add(timeoutSpin);
        top.add(statusLabel);
        enabledBox.addActionListener(e -> {
            engine.setEnabled(enabledBox.isSelected());
            updateStatus();
            notifyChanged();
        });
        timeoutSpin.addChangeListener(e -> {
            engine.setTimeoutSeconds(((Number) timeoutSpin.getValue()).longValue());
            notifyChanged();
        });

        JTable ruleTable = new JTable(ruleModel);
        ruleTable.setRowHeight(24);
        installDropdown(ruleTable, 1, TARGET_OPTIONS);
        installDropdown(ruleTable, 4, ENCODING_OPTIONS);
        // Free-text columns: Match, Comment
        ruleTable.getColumnModel().getColumn(2).setCellEditor(UndoSupport.textCellEditor());
        ruleTable.getColumnModel().getColumn(5).setCellEditor(UndoSupport.textCellEditor());
        ruleModel.addTableModelListener(e -> {
            if (!suppressSync && e.getType() != TableModelEvent.HEADER_ROW) {
                SwingUtilities.invokeLater(this::pushRules);
            }
        });

        JPanel ruleButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton add = new JButton("Add rule");
        add.addActionListener(e -> {
            ruleModel.addRule(new InterceptRule(true, "REQUEST", "", false, "UTF16LE", ""));
            pushRules();
        });
        JButton remove = new JButton("Remove selected");
        remove.addActionListener(e -> {
            int row = ruleTable.getSelectedRow();
            if (row >= 0) {
                ruleModel.removeRule(row);
                pushRules();
            }
        });
        ruleButtons.add(add);
        ruleButtons.add(remove);

        JPanel rulesPanel = new JPanel(new BorderLayout());
        rulesPanel.setBorder(new TitledBorder("Match rules (body contains text)"));
        rulesPanel.add(new JScrollPane(ruleTable), BorderLayout.CENTER);
        rulesPanel.add(ruleButtons, BorderLayout.SOUTH);

        pendingList = new JList<>(pendingListModel);
        pendingList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        pendingList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelected();
            }
        });
        detailArea = new JTextArea();
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setEditable(true);
        ButtonGroup dg = new ButtonGroup();
        dg.add(detailSimple);
        dg.add(detailFull);
        detailSimple.addActionListener(e -> showSelected());
        detailFull.addActionListener(e -> showSelected());

        JPanel actionButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton forward = new JButton("Forward");
        forward.addActionListener(e -> actForward(false));
        JButton forwardEdited = new JButton("Forward edited");
        forwardEdited.addActionListener(e -> actForward(true));
        JButton drop = new JButton("Drop");
        drop.addActionListener(e -> actDrop());
        JButton forwardAll = new JButton("Forward all");
        forwardAll.addActionListener(e -> {
            engine.forwardAll();
            refreshPending();
        });
        JButton dropAll = new JButton("Drop all");
        dropAll.addActionListener(e -> {
            engine.dropAll();
            refreshPending();
        });
        actionButtons.add(forward);
        actionButtons.add(forwardEdited);
        actionButtons.add(drop);
        actionButtons.add(forwardAll);
        actionButtons.add(dropAll);

        JPanel pendingPanel = new JPanel(new BorderLayout());
        pendingPanel.setBorder(new TitledBorder("Held frames (relay waits until Forward/Drop)"));
        JPanel detailNorth = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detailNorth.add(new JLabel("Detail:"));
        detailNorth.add(detailSimple);
        detailNorth.add(detailFull);
        JPanel detailWrap = new JPanel(new BorderLayout());
        detailWrap.add(detailNorth, BorderLayout.NORTH);
        detailWrap.add(new JScrollPane(detailArea), BorderLayout.CENTER);
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(pendingList), detailWrap);
        split.setResizeWeight(0.28);
        pendingPanel.add(split, BorderLayout.CENTER);
        pendingPanel.add(actionButtons, BorderLayout.SOUTH);

        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT, rulesPanel, pendingPanel);
        main.setResizeWeight(0.35);

        add(top, BorderLayout.NORTH);
        add(main, BorderLayout.CENTER);

        suppressSync = true;
        if (engine.getRules().isEmpty()) {
            ruleModel.addRule(new InterceptRule(false, "REQUEST", "Select", false, "UTF16LE",
                    "example: pause SQL batches containing Select"));
        } else {
            ruleModel.setRules(engine.getRules());
        }
        enabledBox.setSelected(engine.isEnabled());
        timeoutSpin.setValue((int) Math.min(Integer.MAX_VALUE, Math.max(0, engine.getTimeoutSeconds())));
        suppressSync = false;
        pushRules();
        UndoSupport.enable(detailArea);

        engine.addListener(p -> SwingUtilities.invokeLater(() -> {
            refreshPending();
            // auto-select newest
            if (pendingListModel.size() > 0) {
                pendingList.setSelectedIndex(pendingListModel.size() - 1);
            }
            // ask parent to show this tab
            firePropertyChange("dsl.showIntercept", false, true);
        }));
        refreshPending();
    }

    public void setChangeListener(Consumer<Void> listener) {
        this.changeListener = listener;
    }

    public void reloadFromEngine() {
        suppressSync = true;
        ruleModel.setRules(engine.getRules());
        enabledBox.setSelected(engine.isEnabled());
        timeoutSpin.setValue((int) Math.min(Integer.MAX_VALUE, Math.max(0, engine.getTimeoutSeconds())));
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

    private void installDropdown(JTable table, int col, String[] options) {
        TableColumn column = table.getColumnModel().getColumn(col);
        JComboBox<String> combo = new JComboBox<>(options);
        DefaultCellEditor editor = new DefaultCellEditor(combo);
        editor.setClickCountToStart(1);
        column.setCellEditor(editor);
    }

    private void pushRules() {
        if (tableIsEditing()) {
            // best effort
        }
        engine.setRules(ruleModel.getRules());
        engine.setEnabled(enabledBox.isSelected());
        engine.setTimeoutSeconds(((Number) timeoutSpin.getValue()).longValue());
        updateStatus();
        if (!suppressSync) {
            notifyChanged();
        }
    }

    private boolean tableIsEditing() {
        return false;
    }

    private void updateStatus() {
        statusLabel.setText((engine.isEnabled() ? "ON" : "OFF")
                + " · " + engine.activeRuleCount() + " rule(s)"
                + " · " + engine.getPending().size() + " held");
    }

    private void refreshPending() {
        int sel = pendingList.getSelectedIndex();
        pendingItems.clear();
        pendingListModel.clear();
        for (InterceptEngine.PendingIntercept p : engine.getPending()) {
            pendingItems.add(p);
            String match = p.getMatchedRule() != null ? p.getMatchedRule().getMatch() : "?";
            pendingListModel.addElement("#" + p.getId() + " "
                    + p.getDirection().shortLabel() + " "
                    + p.getPeer() + "  match=\"" + match + "\"  "
                    + p.getOriginalBody().length + " B");
        }
        if (sel >= 0 && sel < pendingListModel.size()) {
            pendingList.setSelectedIndex(sel);
        }
        updateStatus();
    }

    private void showSelected() {
        int i = pendingList.getSelectedIndex();
        if (i < 0 || i >= pendingItems.size()) {
            detailArea.setText("");
            return;
        }
        InterceptEngine.PendingIntercept p = pendingItems.get(i);
        try {
            JSONObject meta = new JSONObject();
            meta.put("id", p.getId());
            meta.put("peer", p.getPeer());
            meta.put("direction", p.getDirection().legacyName());
            meta.put("matchedRule", p.getMatchedRule() != null ? p.getMatchedRule().getMatch() : "");
            detailArea.setText(TdsSimpleView.format(p.getOriginalBody(), meta, detailSimple.isSelected()));
            detailArea.setCaretPosition(0);
        } catch (Exception e) {
            detailArea.setText("hex=" + TdsHelper.toHex(p.getOriginalBody()));
        }
    }

    private void actForward(boolean edited) {
        int i = pendingList.getSelectedIndex();
        if (i < 0 || i >= pendingItems.size()) {
            return;
        }
        InterceptEngine.PendingIntercept p = pendingItems.get(i);
        if (edited) {
            byte[] body = parseEditedBody(detailArea.getText(), p.getOriginalBody());
            engine.forwardEdited(p.getId(), body);
        } else {
            engine.forward(p.getId());
        }
        refreshPending();
    }

    private void actDrop() {
        int i = pendingList.getSelectedIndex();
        if (i < 0 || i >= pendingItems.size()) {
            return;
        }
        engine.drop(pendingItems.get(i).getId());
        refreshPending();
    }

    /**
     * Re-pack from Simple/Full JSON when possible; else payloadHex / original.
     */
    private byte[] parseEditedBody(String text, byte[] original) {
        if (text == null) {
            return original;
        }
        try {
            String trimmed = text.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                // Prefer re-pack so sql/param edits apply (Simple or Full)
                try {
                    return TdsSimpleView.packEditor(trimmed, original, tdsHelper);
                } catch (Exception packEx) {
                    logging.logToError("[-] Intercept re-pack: " + packEx.getMessage());
                    JSONObject o = new JSONObject(trimmed);
                    if (o.has("payloadHex")) {
                        return TdsHelper.fromHex(o.getString("payloadHex"));
                    }
                }
            }
            String hex = trimmed.replaceAll("\\s+", "");
            if (hex.matches("(?i)[0-9a-f]+") && hex.length() >= 16 && hex.length() % 2 == 0) {
                return TdsHelper.fromHex(hex);
            }
        } catch (Exception e) {
            logging.logToError("[-] Intercept edit parse: " + e.getMessage());
        }
        return original;
    }

    private static class RuleTableModel extends AbstractTableModel {
        private final String[] cols = {"On", "Target", "Match", "Regex", "Encoding", "Comment"};
        private final List<InterceptRule> rules = new ArrayList<>();

        void setRules(List<InterceptRule> list) {
            rules.clear();
            for (InterceptRule r : list) {
                rules.add(r.copy());
            }
            fireTableDataChanged();
        }

        List<InterceptRule> getRules() {
            List<InterceptRule> out = new ArrayList<>();
            for (InterceptRule r : rules) {
                out.add(r.copy());
            }
            return out;
        }

        void addRule(InterceptRule r) {
            rules.add(r);
            fireTableRowsInserted(rules.size() - 1, rules.size() - 1);
        }

        void removeRule(int row) {
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
            if (columnIndex == 0 || columnIndex == 3) {
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
            InterceptRule r = rules.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> r.isEnabled();
                case 1 -> r.getTarget();
                case 2 -> r.getMatch();
                case 3 -> r.isRegex();
                case 4 -> r.getEncoding();
                case 5 -> r.getComment();
                default -> "";
            };
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            InterceptRule r = rules.get(rowIndex);
            switch (columnIndex) {
                case 0 -> r.setEnabled(Boolean.TRUE.equals(aValue));
                case 1 -> r.setTarget(String.valueOf(aValue));
                case 2 -> r.setMatch(aValue == null ? "" : String.valueOf(aValue));
                case 3 -> r.setRegex(Boolean.TRUE.equals(aValue));
                case 4 -> r.setEncoding(String.valueOf(aValue));
                case 5 -> r.setComment(aValue == null ? "" : String.valueOf(aValue));
                default -> {
                }
            }
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }
}
