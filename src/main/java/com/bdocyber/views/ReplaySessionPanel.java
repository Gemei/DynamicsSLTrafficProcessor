package com.bdocyber.views;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import com.bdocyber.helpers.TdsHelper;
import com.bdocyber.helpers.TdsSimpleView;
import com.bdocyber.helpers.TcpStreamStore;
import com.bdocyber.helpers.UndoSupport;
import com.bdocyber.models.StreamStep;
import com.bdocyber.models.TcpStream;
import com.bdocyber.models.TcpStreamFrame;
import com.bdocyber.relay.ActiveRelaySession;
import com.bdocyber.relay.TcpRelayService;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * One Stream Replay session (steps table + editor + log) — content of a Repeater-style tab.
 */
public class ReplaySessionPanel extends JPanel {

    private final MontoyaApi montoya;
    private final Logging logging;
    private final StreamTableModel tableModel;
    private final JTable table;
    private final JTextArea logArea;
    private final JTextArea editorArea;
    private final JLabel editorLabel;
    private final JCheckBox clientsOnlyBox;
    /** Fixed response wait after each C→S (no UI spinner). */
    private static final int DEFAULT_RESPONSE_WAIT_MS = 5_000;
    private final JComboBox<String> connectionModeBox;
    private final JComboBox<ActiveRelaySession> liveSessionBox;
    private final JLabel liveSessionLabel;
    private final JTextField findField = new JTextField(14);
    private final JTextField replaceField = new JTextField(14);
    private final JCheckBox utf16Box = new JCheckBox("UTF-16LE", true);
    private final JCheckBox rawBox = new JCheckBox("RAW", false);
    private final JRadioButton editorSimple = new JRadioButton("Simple", true);
    private final JRadioButton editorFull = new JRadioButton("Full", false);
    private final AtomicBoolean replaying = new AtomicBoolean(false);
    private final TdsHelper tdsHelper = new TdsHelper();
    private TcpRelayService relayService;
    private TcpStreamStore streamStore;
    private JButton replayButton;
    private JButton stopButton;
    private int editingRow = -1;
    private Consumer<Void> changeListener;

    public ReplaySessionPanel(MontoyaApi api) {
        super(new BorderLayout(8, 8));
        this.montoya = api;
        this.logging = api.logging();
        this.tableModel = new StreamTableModel();
        this.table = new JTable(tableModel);
        this.table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        this.table.setFillsViewportHeight(true);
        this.table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                loadSelectedIntoEditor();
            }
        });

        this.logArea = new JTextArea(6, 60);
        this.logArea.setEditable(false);
        this.logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        this.editorArea = new JTextArea();
        this.editorArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        this.editorLabel = new JLabel("Select a step to edit");

        // --- Compact toolbar ---
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        clientsOnlyBox = new JCheckBox("C→S only", true);
        clientsOnlyBox.setToolTipText("Skip S→C steps when replaying");

        connectionModeBox = new JComboBox<>(new String[]{
                "Live session",
                "New TCP"
        });
        connectionModeBox.setToolTipText(
                "Live session: inject into open relay bridge (keeps login). "
                        + "New TCP: fresh socket (no session).");
        liveSessionBox = new JComboBox<>();
        liveSessionBox.setPreferredSize(new Dimension(160, liveSessionBox.getPreferredSize().height));
        liveSessionBox.setToolTipText(
                "Live relay bridge by TCP Stream # (and name). Auto = match step stream / peer. "
                        + "Hover for connection endpoint.");
        liveSessionBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value == null) {
                    setText("Auto");
                    setToolTipText("Match step stream / peer automatically");
                } else if (value instanceof ActiveRelaySession s) {
                    setText(formatLiveSessionLabel(s));
                    setToolTipText(s.getStreamKey() + (s.isOpen() ? " [live]" : " [closed]"));
                }
                return this;
            }
        });
        liveSessionLabel = new JLabel("Session");
        JButton refreshLive = new JButton("↻");
        refreshLive.setToolTipText("Refresh live sessions");
        refreshLive.setMargin(new Insets(2, 6, 2, 6));
        refreshLive.addActionListener(e -> refreshLiveSessions());
        connectionModeBox.addActionListener(e -> updateLiveSessionUi());

        replayButton = new JButton("Replay");
        replayButton.setToolTipText("Replay all included steps");
        replayButton.addActionListener(e -> startReplay(false));
        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> replaying.set(false));
        JButton replaySelected = new JButton("Replay Selected");
        replaySelected.setToolTipText("Replay selected steps only");
        replaySelected.addActionListener(e -> startReplay(true));

        controls.add(connectionModeBox);
        controls.add(liveSessionLabel);
        controls.add(liveSessionBox);
        controls.add(refreshLive);
        controls.add(clientsOnlyBox);
        controls.add(replayButton);
        controls.add(replaySelected);
        controls.add(stopButton);

        // Thin find/replace (no titled border)
        JPanel replaceBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        findField.setColumns(10);
        replaceField.setColumns(10);
        replaceBar.add(new JLabel("Find"));
        replaceBar.add(findField);
        replaceBar.add(new JLabel("Replace"));
        replaceBar.add(replaceField);
        replaceBar.add(utf16Box);
        replaceBar.add(rawBox);
        JButton replaceAllBtn = new JButton("All");
        replaceAllBtn.setToolTipText("Replace in all steps");
        replaceAllBtn.addActionListener(e -> bulkReplace(false));
        JButton replaceSelBtn = new JButton("Selected");
        replaceSelBtn.setToolTipText("Replace in selected steps");
        replaceSelBtn.addActionListener(e -> bulkReplace(true));
        replaceBar.add(replaceAllBtn);
        replaceBar.add(replaceSelBtn);

        JPanel north = new JPanel(new BorderLayout(0, 0));
        north.add(controls, BorderLayout.NORTH);
        north.add(replaceBar, BorderLayout.SOUTH);

        // Table context menu: remove / clear / reorder
        table.setComponentPopupMenu(buildStepContextMenu());
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                maybeSelectOnPopup(e);
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                maybeSelectOnPopup(e);
            }

            private void maybeSelectOnPopup(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0 && !table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                }
            }
        });

        // Compact editor chrome
        JPanel editorPanel = new JPanel(new BorderLayout(2, 2));
        editorPanel.setBorder(new TitledBorder("Step editor"));
        JPanel editorTop = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        editorTop.add(editorLabel);
        ButtonGroup eg = new ButtonGroup();
        eg.add(editorSimple);
        eg.add(editorFull);
        editorTop.add(editorSimple);
        editorTop.add(editorFull);
        editorSimple.addActionListener(e -> loadSelectedIntoEditor());
        editorFull.addActionListener(e -> loadSelectedIntoEditor());
        JButton applyEdit = new JButton("Apply");
        applyEdit.setToolTipText("Apply editor text to selected step");
        applyEdit.addActionListener(e -> applyEditorToStep());
        JButton reloadEdit = new JButton("Reload");
        reloadEdit.setToolTipText("Reload step into editor");
        reloadEdit.addActionListener(e -> loadSelectedIntoEditor());
        editorTop.add(applyEdit);
        editorTop.add(reloadEdit);
        editorPanel.add(editorTop, BorderLayout.NORTH);
        editorPanel.add(new JScrollPane(editorArea), BorderLayout.CENTER);

        JSplitPane tableAndEditor = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), editorPanel);
        tableAndEditor.setResizeWeight(0.55);
        tableAndEditor.setBorder(null);

        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(new TitledBorder("Log"));
        logPanel.add(new JScrollPane(logArea), BorderLayout.CENTER);
        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableAndEditor, logPanel);
        main.setResizeWeight(0.72);
        main.setBorder(null);

        add(north, BorderLayout.NORTH);
        add(main, BorderLayout.CENTER);

        UndoSupport.enable(findField);
        UndoSupport.enable(replaceField);
        UndoSupport.enable(editorArea);
        updateLiveSessionUi();
        refreshLiveSessions();
    }

    private JPopupMenu buildStepContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem replaySel = new JMenuItem("Replay selected");
        replaySel.addActionListener(e -> startReplay(true));
        menu.add(replaySel);
        menu.addSeparator();
        JMenuItem up = new JMenuItem("Move up");
        up.addActionListener(e -> moveSelected(-1));
        menu.add(up);
        JMenuItem down = new JMenuItem("Move down");
        down.addActionListener(e -> moveSelected(1));
        menu.add(down);
        menu.addSeparator();
        JMenuItem remove = new JMenuItem("Remove selected");
        remove.addActionListener(e -> removeSelectedSteps());
        menu.add(remove);
        JMenuItem clear = new JMenuItem("Clear all steps");
        clear.addActionListener(e -> clearAllSteps());
        menu.add(clear);
        return menu;
    }

    private void removeSelectedSteps() {
        tableModel.removeRows(table.getSelectedRows());
        editingRow = -1;
        editorArea.setText("");
        editorLabel.setText("Select a step to edit");
        notifyChanged();
    }

    private void clearAllSteps() {
        int n = tableModel.getRowCount();
        if (n == 0) {
            return;
        }
        int r = JOptionPane.showConfirmDialog(this,
                "Clear all " + n + " step(s) from this tab?",
                "Clear steps",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (r != JOptionPane.OK_OPTION) {
            return;
        }
        tableModel.clear();
        logArea.setText("");
        editingRow = -1;
        editorArea.setText("");
        editorLabel.setText("Select a step to edit");
        notifyChanged();
    }

    private void moveSelected(int delta) {
        int row = table.getSelectedRow();
        if (row < 0) {
            return;
        }
        int target = row + delta;
        if (target < 0 || target >= tableModel.getRowCount()) {
            return;
        }
        tableModel.move(row, target);
        table.setRowSelectionInterval(target, target);
        notifyChanged();
    }

    /** Wire relay + capture store so live inject and response wait work. */
    public void setRelayContext(TcpRelayService relay, TcpStreamStore store) {
        this.relayService = relay;
        this.streamStore = store;
        refreshLiveSessions();
        if (relay != null) {
            relay.addStatusListener(r -> SwingUtilities.invokeLater(this::refreshLiveSessions));
        }
        if (store != null) {
            store.addListener(st -> SwingUtilities.invokeLater(() -> {
                refreshLiveSessions();
                table.repaint(); // Stream column uses store # / name
            }));
        }
    }

    /**
     * Label for a captured TCP Stream: {@code #N} plus optional user name (not the connection string).
     * Matches the # column in the TCP Streams list (1-based store order).
     */
    private String formatStreamLabel(String streamKey, String peerFallback) {
        if (streamStore != null && streamKey != null && !streamKey.isEmpty()) {
            List<TcpStream> streams = streamStore.getStreams();
            for (int i = 0; i < streams.size(); i++) {
                TcpStream s = streams.get(i);
                if (streamKey.equals(s.getStreamKey())) {
                    String name = s.getUserName();
                    if (name != null && !name.isEmpty()) {
                        return "#" + (i + 1) + " " + name;
                    }
                    return "#" + (i + 1);
                }
            }
        }
        if (peerFallback != null && !peerFallback.isEmpty()) {
            return peerFallback;
        }
        return streamKey != null ? streamKey : "";
    }

    private String formatLiveSessionLabel(ActiveRelaySession s) {
        if (s == null) {
            return "Auto";
        }
        String base = formatStreamLabel(s.getStreamKey(), null);
        if (base.isEmpty()) {
            base = s.getStreamKey();
        }
        if (!s.isOpen()) {
            return base + " [closed]";
        }
        return base;
    }

    private String formatStepStreamLabel(StreamStep step) {
        if (step == null) {
            return "";
        }
        return formatStreamLabel(step.getStreamKey(), step.getPeer());
    }

    private void updateLiveSessionUi() {
        boolean live = connectionModeBox.getSelectedIndex() == 0;
        liveSessionBox.setEnabled(live);
        liveSessionLabel.setEnabled(live);
    }

    private void refreshLiveSessions() {
        Object selected = liveSessionBox.getSelectedItem();
        liveSessionBox.removeAllItems();
        liveSessionBox.addItem(null); // Auto
        if (relayService != null) {
            for (ActiveRelaySession s : relayService.listLiveSessions()) {
                liveSessionBox.addItem(s);
            }
        }
        if (selected instanceof ActiveRelaySession prev) {
            for (int i = 0; i < liveSessionBox.getItemCount(); i++) {
                ActiveRelaySession it = liveSessionBox.getItemAt(i);
                if (it != null && prev.getStreamKey().equals(it.getStreamKey())) {
                    liveSessionBox.setSelectedIndex(i);
                    return;
                }
            }
        }
        liveSessionBox.setSelectedIndex(0);
    }

    public void setChangeListener(Consumer<Void> listener) {
        this.changeListener = listener;
    }

    private void notifyChanged() {
        if (changeListener != null) {
            try {
                changeListener.accept(null);
            } catch (Exception ignored) {
            }
        }
    }

    public List<StreamStep> getAllSteps() {
        return tableModel.getAllSteps();
    }

    public void setSteps(List<StreamStep> steps) {
        SwingUtilities.invokeLater(() -> {
            tableModel.clear();
            if (steps != null) {
                for (StreamStep s : steps) {
                    if (s != null) {
                        tableModel.addStep(s);
                    }
                }
            }
            editingRow = -1;
            editorArea.setText("");
            editorLabel.setText("Select a step to edit");
            int n = tableModel.getRowCount();
            if (n > 0) {
                int withBody = 0;
                for (StreamStep s : tableModel.getAllSteps()) {
                    if (s != null && s.getBodyLength() > 0) {
                        withBody++;
                    }
                }
                appendLog("Restored " + n + " stream replay step(s) from project"
                        + " (" + withBody + " with body).");
                // Auto-open first step so SQL/body is visible after reload
                table.setRowSelectionInterval(0, 0);
                loadSelectedIntoEditor();
            }
        });
    }

    public void addRequest(HttpRequest request) {
        if (request == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            tableModel.addStep(new StreamStep(request));
            appendLog("Added HTTP step #" + tableModel.getRowCount() + " " + request.path());
            notifyChanged();
        });
    }

    public void addRequests(List<HttpRequest> requests) {
        if (requests == null) {
            return;
        }
        for (HttpRequest r : requests) {
            addRequest(r);
        }
    }

    public void addTcpFrames(List<TcpStreamFrame> frames) {
        if (frames == null || frames.isEmpty()) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            for (TcpStreamFrame f : frames) {
                tableModel.addStep(new StreamStep(f));
            }
            appendLog("Added " + frames.size() + " TCP frame(s) from stream (total steps="
                    + tableModel.getRowCount() + ")");
            if (tableModel.getRowCount() > 0) {
                table.setRowSelectionInterval(0, 0);
            }
            notifyChanged();
        });
    }

    private void loadSelectedIntoEditor() {
        int row = table.getSelectedRow();
        if (row < 0) {
            editingRow = -1;
            editorArea.setText("");
            editorLabel.setText("Select a step to edit");
            return;
        }
        StreamStep step = tableModel.getStep(row);
        if (step == null) {
            return;
        }
        editingRow = row;
        editorLabel.setText("Editing step #" + (row + 1) + "  " + step.getMode()
                + "  " + step.getDirection() + "  " + step.getPeer()
                + "  (" + step.getBodyLength() + " B)");
        try {
            JSONObject meta = new JSONObject();
            meta.put("step", row + 1);
            meta.put("mode", step.getMode().name());
            meta.put("direction", step.getDirection());
            meta.put("peer", step.getPeer());
            meta.put("summary", step.getSummary());
            editorArea.setText(TdsSimpleView.format(step.getRawBody(), meta, editorSimple.isSelected()));
            editorArea.setCaretPosition(0);
        } catch (Exception e) {
            editorArea.setText("payloadHex=" + TdsHelper.toHex(step.getRawBody()));
        }
    }

    private void applyEditorToStep() {
        if (editingRow < 0 || editingRow >= tableModel.getRowCount()) {
            appendLog("No step selected to apply.");
            return;
        }
        StreamStep step = tableModel.getStep(editingRow);
        if (step == null) {
            return;
        }
        try {
            String editorText = editorArea.getText();
            int caret = editorArea.getCaretPosition();
            byte[] original = step.getRawBody();
            byte[] body = TdsSimpleView.packEditor(editorText, original, tdsHelper);
            boolean changed = !java.util.Arrays.equals(original, body);
            step.setRawBody(body);
            tableModel.fireStepUpdated(editingRow);
            if (!changed) {
                appendLog("Apply edit to step #" + (editingRow + 1)
                        + ": body unchanged (same bytes). Check that SQL was modified under SQL Batch / RPC.");
            } else {
                appendLog("Applied edit to step #" + (editingRow + 1)
                        + " (" + original.length + " → " + body.length + " B) — " + step.getSummary());
            }
            // Reload from packed body so Simple view matches wire form; restore caret approx.
            loadSelectedIntoEditor();
            try {
                editorArea.setCaretPosition(Math.min(caret, editorArea.getDocument().getLength()));
            } catch (Exception ignored) {
            }
            notifyChanged();
        } catch (Exception e) {
            appendLog("Apply edit failed: " + e.getMessage());
            logging.logToError("[-] Replay edit: " + e.getMessage());
            // Do NOT reload editor — keep user's in-progress text
            JOptionPane.showMessageDialog(this, "Could not apply edit:\n" + e.getMessage(),
                    "Stream Replay", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void bulkReplace(boolean selectedOnly) {
        String find = findField.getText();
        String repl = replaceField.getText();
        if (find == null || find.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Find string is empty.", "Stream Replay",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (repl == null) {
            repl = "";
        }
        boolean utf = utf16Box.isSelected();
        boolean raw = rawBox.isSelected();
        if (!utf && !raw) {
            utf = true;
        }

        int[] rows;
        if (selectedOnly) {
            rows = table.getSelectedRows();
            if (rows.length == 0) {
                JOptionPane.showMessageDialog(this, "No steps selected.", "Stream Replay",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
        } else {
            rows = new int[tableModel.getRowCount()];
            for (int i = 0; i < rows.length; i++) {
                rows[i] = i;
            }
        }

        int changed = 0;
        for (int row : rows) {
            StreamStep step = tableModel.getStep(row);
            if (step == null) {
                continue;
            }
            if (step.replaceString(find, repl, utf, raw)) {
                changed++;
                tableModel.fireStepUpdated(row);
            }
        }
        appendLog("Bulk replace \"" + find + "\" → \"" + repl + "\": "
                + changed + " step(s) updated (utf16=" + utf + ", raw=" + raw + ")");
        if (editingRow >= 0) {
            loadSelectedIntoEditor();
        }
        if (changed > 0) {
            notifyChanged();
        }
        if (changed == 0) {
            JOptionPane.showMessageDialog(this, "No occurrences found in selected steps.",
                    "Stream Replay", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void startReplay(boolean selectedOnly) {
        if (!replaying.compareAndSet(false, true)) {
            appendLog("Replay already running.");
            return;
        }
        List<StreamStep> steps = selectedOnly
                ? tableModel.getSteps(table.getSelectedRows())
                : tableModel.getIncludedSteps();
        if (steps.isEmpty()) {
            replaying.set(false);
            appendLog("No steps to replay.");
            return;
        }
        boolean clientsOnly = clientsOnlyBox.isSelected();
        final int respTimeout = DEFAULT_RESPONSE_WAIT_MS;
        final boolean preferLive = connectionModeBox.getSelectedIndex() == 0;
        final ActiveRelaySession forcedSession = preferLive
                ? (ActiveRelaySession) liveSessionBox.getSelectedItem()
                : null;

        replayButton.setEnabled(false);
        stopButton.setEnabled(true);
        appendLog("--- Replay start (" + steps.size() + " steps, mode="
                + (preferLive ? "live-session" : "new-tcp") + ") ---");
        if (preferLive) {
            appendLog("Live inject: C→S bytes go into the existing relay bridge (auth state preserved).");
            if (relayService == null || relayService.listLiveSessions().isEmpty()) {
                appendLog("WARN: no live relay sessions right now — will fall back to new TCP if inject fails.");
            }
        } else {
            appendLog("New TCP: one socket per peer until error (login/SSPI state is NOT carried over).");
        }
        new Thread(() -> {
            Socket rawSocket = null;
            OutputStream rawOut = null;
            InputStream rawIn = null;
            String openPeer = null;
            try {
                int n = 0;
                for (StreamStep step : steps) {
                    if (!replaying.get()) {
                        appendLog("Stopped by user.");
                        break;
                    }
                    if (clientsOnly && !step.isClientRequest()) {
                        appendLog("Skip " + step.getDirection() + " " + step.getPeer());
                        continue;
                    }
                    n++;
                    try {
                        byte[] body = step.getRawBody();
                        appendLog("[" + n + "] " + step.getMode() + " " + step.getDirection()
                                + " " + step.getBodyLength() + " B — " + step.getSummary());
                        if (step.getMode() == StreamStep.Mode.HTTP) {
                            HttpRequestResponse rr = montoya.http().sendRequest(step.getRequest());
                            int status = rr.response() != null ? rr.response().statusCode() : -1;
                            appendLog("    -> HTTP " + status);
                            if (rr.response() != null && rr.response().body() != null) {
                                byte[] respBody = rr.response().body().getBytes();
                                logServerResponse(respBody, step.getPeer(), "HTTP body");
                            }
                        } else {
                            byte[] toSend = prepareBodyToSend(body);
                            String peer = step.getPeer();
                            String streamKey = step.getStreamKey();
                            boolean sentLive = false;

                            if (preferLive && relayService != null) {
                                try {
                                    long seqBefore = streamStore != null ? streamStore.getCurrentSeq() : 0;
                                    ActiveRelaySession used = injectViaRelay(
                                            streamKey, peer, toSend, forcedSession);
                                    sentLive = true;
                                    appendLog("    -> live inject " + toSend.length + " B on "
                                            + used.getStreamKey());
                                    if (respTimeout > 0 && step.isClientRequest()) {
                                        waitLiveServerResponse(used.getStreamKey(), seqBefore, respTimeout, peer);
                                    }
                                } catch (Exception liveEx) {
                                    appendLog("    live inject failed: " + liveEx.getMessage());
                                    appendLog("    falling back to new TCP…");
                                }
                            }

                            if (!sentLive) {
                                if (peer == null || !peer.contains(":")) {
                                    appendLog("    ERROR: invalid peer " + peer);
                                    continue;
                                }
                                if (rawSocket == null || rawOut == null || !peer.equals(openPeer)) {
                                    if (openPeer != null) {
                                        appendLog("    !! Opening NEW TCP connection (previous closed). "
                                                + "Login/session state is LOST.");
                                    }
                                    closeQuietly(rawSocket);
                                    String host = peer.substring(0, peer.lastIndexOf(':'));
                                    int port = Integer.parseInt(peer.substring(peer.lastIndexOf(':') + 1));
                                    rawSocket = new Socket();
                                    rawSocket.connect(new InetSocketAddress(host, port), 10_000);
                                    rawSocket.setTcpNoDelay(true);
                                    rawOut = rawSocket.getOutputStream();
                                    rawIn = rawSocket.getInputStream();
                                    openPeer = peer;
                                    appendLog("    opened TCP " + peer + " (same socket for following steps)");
                                }
                                rawOut.write(toSend);
                                rawOut.flush();
                                appendLog("    -> wrote " + toSend.length + " bytes (new TCP)"
                                        + (toSend.length != body.length
                                        ? " (from " + body.length + " B step body)" : ""));

                                if (respTimeout > 0 && step.isClientRequest() && rawIn != null) {
                                    byte[] response = readSocketResponse(rawSocket, rawIn, respTimeout);
                                    if (response.length == 0) {
                                        appendLog("    <- (no response within " + respTimeout + " ms)");
                                    } else {
                                        logServerResponse(response, peer, "TCP");
                                    }
                                }
                            }
                        }
                    } catch (Exception ex) {
                        String msg = ex.getMessage() != null ? ex.getMessage() : ex.toString();
                        appendLog("    ERROR: " + msg);
                        if (msg.toLowerCase().contains("abort") || msg.toLowerCase().contains("reset")
                                || msg.toLowerCase().contains("forcibly")) {
                            appendLog("    !! Connection aborted — next C→S may open a NEW TCP connection (session lost).");
                        }
                        logging.logToError("[-] Stream replay: " + msg);
                        closeQuietly(rawSocket);
                        rawSocket = null;
                        rawOut = null;
                        rawIn = null;
                        openPeer = null;
                    }
                }
                appendLog("--- Replay finished ---");
            } finally {
                closeQuietly(rawSocket);
                replaying.set(false);
                SwingUtilities.invokeLater(() -> {
                    replayButton.setEnabled(true);
                    stopButton.setEnabled(false);
                    refreshLiveSessions();
                });
            }
        }, "dsl-stream-replay").start();
    }

    private byte[] prepareBodyToSend(byte[] body) {
        TdsHelper.PduFraming framing = TdsHelper.analyzePduFraming(body);
        byte[] toSend = body;
        if (framing.hasWarning()) {
            appendLog("    WARN: " + framing.warning);
        }
        if (framing.startsLikeTds && framing.completeBytes > 0
                && framing.completeBytes < body.length) {
            toSend = TdsHelper.preferCompletePdus(body);
            appendLog("    preferred " + framing.completePacketCount
                    + " complete PDU(s) (" + toSend.length + " B); dropped trailing "
                    + framing.trailingIncompleteBytes + " B incomplete");
        } else if (framing.startsLikeTds && framing.completePacketCount == 0) {
            appendLog("    WARN: sending incomplete PDU as-is (may confuse SQL Server)");
        }
        return toSend != null ? toSend : new byte[0];
    }

    /**
     * Inject via relay service (captures frame). If forced session set, require that streamKey.
     */
    private ActiveRelaySession injectViaRelay(String streamKey, String peer, byte[] toSend,
                                              ActiveRelaySession forced) throws Exception {
        if (relayService == null) {
            throw new IllegalStateException("relay not wired");
        }
        if (forced != null) {
            if (!forced.isOpen()) {
                throw new IOException("selected live session is closed");
            }
            return relayService.injectClientToServer(forced.getStreamKey(), forced.getPeer(), toSend);
        }
        return relayService.injectClientToServer(streamKey, peer, toSend);
    }

    /**
     * After live inject, S→C is consumed by the relay pump — poll TCP Streams capture for new frames.
     */
    private void waitLiveServerResponse(String streamKey, long seqBefore, int timeoutMs, String peer) {
        if (streamStore == null || timeoutMs <= 0) {
            return;
        }
        long deadline = System.currentTimeMillis() + timeoutMs;
        List<TcpStreamFrame> got = new ArrayList<>();
        while (System.currentTimeMillis() < deadline && replaying.get()) {
            got = streamStore.getServerFramesAfter(streamKey, seqBefore);
            if (!got.isEmpty()) {
                // brief settle for multi-packet replies
                try {
                    Thread.sleep(200);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
                got = streamStore.getServerFramesAfter(streamKey, seqBefore);
                break;
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        if (got.isEmpty()) {
            appendLog("    <- (no S→C frames on stream within " + timeoutMs + " ms)");
            return;
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (TcpStreamFrame f : got) {
            try {
                bos.write(f.getBody());
            } catch (Exception ignored) {
            }
        }
        appendLog("    <- live capture " + got.size() + " S→C frame(s), " + bos.size() + " B");
        logServerResponse(bos.toByteArray(), peer, "live stream");
    }

    /**
     * Read server data: wait up to timeoutMs for first byte, then keep reading
     * while more data arrives (TDS multi-packet). Prefer completing TDS length fields.
     */
    private static byte[] readSocketResponse(Socket socket, InputStream in, int timeoutMs) throws Exception {
        if (timeoutMs <= 0 || in == null) {
            return new byte[0];
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[16_384];
        long deadline = System.currentTimeMillis() + timeoutMs;
        // After first data, idle window to gather remaining TDS packets (longer than before)
        int idleMs = Math.min(1500, Math.max(300, timeoutMs / 5));
        boolean gotAny = false;

        while (System.currentTimeMillis() < deadline && !Thread.currentThread().isInterrupted()) {
            int remaining = (int) Math.max(1, deadline - System.currentTimeMillis());
            int soTimeout = gotAny ? Math.min(idleMs, remaining) : remaining;
            socket.setSoTimeout(soTimeout);
            try {
                int n = in.read(buf);
                if (n < 0) {
                    break;
                }
                if (n > 0) {
                    bos.write(buf, 0, n);
                    gotAny = true;
                    // If we have complete TDS packet(s) and idle would be next, try short extra read
                    if (tdsResponseLooksComplete(bos.toByteArray())) {
                        // one more short poll for trailing packets
                        socket.setSoTimeout(Math.min(200, remaining));
                        try {
                            int n2 = in.read(buf);
                            if (n2 > 0) {
                                bos.write(buf, 0, n2);
                            } else if (n2 < 0) {
                                break;
                            }
                        } catch (SocketTimeoutException ignore) {
                            break;
                        }
                    }
                }
            } catch (SocketTimeoutException ste) {
                break; // first-byte timeout or idle after data
            }
        }
        return bos.toByteArray();
    }

    /** True if buffer is one or more complete TDS packets ending on a boundary. */
    private static boolean tdsResponseLooksComplete(byte[] data) {
        if (data == null || data.length < 8) {
            return false;
        }
        int off = 0;
        boolean any = false;
        while (off + 8 <= data.length) {
            int type = data[off] & 0xFF;
            if (type == 0 || type > 0x12) {
                return false;
            }
            int len = ((data[off + 2] & 0xFF) << 8) | (data[off + 3] & 0xFF);
            if (len < 8 || off + len > data.length) {
                return false;
            }
            any = true;
            off += len;
        }
        return any && off == data.length;
    }

    private void logServerResponse(byte[] response, String peer, String channel) {
        appendLog("    <- " + channel + " response " + response.length + " B"
                + (peer != null && !peer.isEmpty() ? " from " + peer : ""));
        try {
            String summary = com.bdocyber.helpers.TdsTextFormatter.oneLineSummary(response, 120);
            appendLog("       summary: " + summary);
            JSONObject meta = new JSONObject();
            meta.put("direction", "SERVER_RESPONSE");
            if (peer != null) {
                meta.put("peer", peer);
            }
            String simple = TdsSimpleView.format(response, meta, true);
            for (String line : simple.split("\n", -1)) {
                appendLog("       " + line);
            }
        } catch (Exception e) {
            appendLog("       (decode failed: " + e.getMessage() + ")");
            appendLog("       hex=" + TdsHelper.toHex(
                    response.length > 64 ? java.util.Arrays.copyOf(response, 64) : response)
                    + (response.length > 64 ? "…" : ""));
        }
    }

    private static void closeQuietly(Socket s) {
        if (s != null) {
            try {
                s.close();
            } catch (Exception ignored) {
            }
        }
    }

    private void appendLog(String line) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(line + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    private class StreamTableModel extends AbstractTableModel {
        private final String[] cols = {"#", "Include", "Mode", "Direction", "Stream", "Bytes", "Summary"};
        private final List<StreamStep> steps = new ArrayList<>();

        public void addStep(StreamStep step) {
            steps.add(step);
            fireTableRowsInserted(steps.size() - 1, steps.size() - 1);
        }

        public StreamStep getStep(int row) {
            if (row < 0 || row >= steps.size()) {
                return null;
            }
            return steps.get(row);
        }

        public void fireStepUpdated(int row) {
            if (row >= 0 && row < steps.size()) {
                fireTableRowsUpdated(row, row);
            }
        }

        public void clear() {
            steps.clear();
            fireTableDataChanged();
        }

        public void removeRows(int[] rows) {
            if (rows == null || rows.length == 0) {
                return;
            }
            java.util.Arrays.sort(rows);
            for (int i = rows.length - 1; i >= 0; i--) {
                if (rows[i] >= 0 && rows[i] < steps.size()) {
                    steps.remove(rows[i]);
                }
            }
            fireTableDataChanged();
        }

        public void move(int from, int to) {
            StreamStep s = steps.remove(from);
            steps.add(to, s);
            fireTableDataChanged();
        }

        public List<StreamStep> getIncludedSteps() {
            List<StreamStep> out = new ArrayList<>();
            for (StreamStep s : steps) {
                if (s.isInclude()) {
                    out.add(s);
                }
            }
            return out;
        }

        public List<StreamStep> getSteps(int[] rows) {
            List<StreamStep> out = new ArrayList<>();
            if (rows == null) {
                return out;
            }
            java.util.Arrays.sort(rows);
            for (int r : rows) {
                if (r >= 0 && r < steps.size() && steps.get(r).isInclude()) {
                    out.add(steps.get(r));
                }
            }
            return out;
        }

        public List<StreamStep> getAllSteps() {
            return new ArrayList<>(steps);
        }

        @Override
        public int getRowCount() {
            return steps.size();
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
            if (columnIndex == 1) {
                return Boolean.class;
            }
            if (columnIndex == 0 || columnIndex == 5) {
                return Integer.class;
            }
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 1;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            StreamStep s = steps.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> rowIndex + 1;
                case 1 -> s.isInclude();
                case 2 -> s.getMode().name();
                case 3 -> s.getDirection();
                case 4 -> formatStepStreamLabel(s);
                case 5 -> s.getBodyLength();
                case 6 -> s.getSummary();
                default -> "";
            };
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex == 1) {
                steps.get(rowIndex).setInclude(Boolean.TRUE.equals(aValue));
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }
}
