package com.bdocyber.views;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.bdocyber.helpers.FollowStreamBuilder;
import com.bdocyber.helpers.HighlightColors;
import com.bdocyber.helpers.TdsHelper;
import com.bdocyber.helpers.TdsMessageAssembler;
import com.bdocyber.helpers.TdsSimpleView;
import com.bdocyber.helpers.TcpStreamStore;
import com.bdocyber.helpers.UndoSupport;
import com.bdocyber.models.TcpStream;
import com.bdocyber.models.TcpStreamFrame;
import com.bdocyber.relay.TcpRelayService;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * TCP Streams + Frames list + Follow Stream for one conversation.
 * User highlight colors on streams/frames; last-updated and live relay streams auto-tint.
 */
public class TcpStreamsPanel extends JPanel {

    /** Soft green for live relay sessions (not a user highlight color). */
    private static final Color LIVE_STREAM_BG = new Color(185, 240, 195);
    /** Soft amber for the stream that most recently received frames. */
    private static final Color LAST_UPDATED_STREAM_BG = new Color(255, 235, 160);
    /** Follow Stream search-hit highlight. */
    private static final Color FOLLOW_SEARCH_HIT_BG = new Color(255, 235, 100);
    private static final Highlighter.HighlightPainter FOLLOW_SEARCH_PAINTER =
            new DefaultHighlighter.DefaultHighlightPainter(FOLLOW_SEARCH_HIT_BG);

    /** Stream list: full date+time UTC. */
    private static final DateTimeFormatter STREAM_UTC_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm:ss a 'UTC'", Locale.US)
                    .withZone(ZoneOffset.UTC);
    /** Frame date column (UTC). */
    private static final DateTimeFormatter DATE_UTC_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd", Locale.US).withZone(ZoneOffset.UTC);
    /** Frame time column: 12-hour UTC with millis. */
    private static final DateTimeFormatter TIME_UTC_12_FMT =
            DateTimeFormatter.ofPattern("h:mm:ss.SSS a", Locale.US).withZone(ZoneOffset.UTC);

    private final Logging logging;
    private final TcpStreamStore store;
    private volatile TcpRelayService relayService;

    private final StreamTableModel streamModel = new StreamTableModel();
    private final JTable streamTable;
    private final FrameTableModel frameModel = new FrameTableModel();
    private final JTable frameTable;
    private final JTextArea detailArea;
    private final JTextArea followArea;
    /**
     * Last full Follow Stream dump (source of truth for Copy). JTextArea can leave a
     * selection from Find navigation; we never copy selection-only.
     */
    private volatile String lastFollowDump = "";
    /** Keeps clipboard data alive until replaced (ClipboardOwner). */
    private Transferable followClipboardTransferable;
    private final JComboBox<String> followMode = new JComboBox<>(new String[]{
            "TDS decode (best for server)", "UTF-16 text (strings only)", "Hex dump", "Raw ASCII"
    });
    private final JCheckBox followBoth = new JCheckBox("Both directions", true);
    /** On by default — keep stream list scrolled to the latest TCP Stream. */
    private final JCheckBox autoScrollStreams = new JCheckBox("Auto-scroll", true);
    /** On by default — keep Frames table scrolled to the latest frame. */
    private final JCheckBox autoScrollFrames = new JCheckBox("Auto-scroll", true);
    /** On by default — keep Follow Stream text scrolled to the end (latest traffic). */
    private final JCheckBox autoScrollFollow = new JCheckBox("Auto-scroll", true);
    private final JTextField searchField = new JTextField(24);
    private final JCheckBox searchUtf16 = new JCheckBox("UTF-16LE", true);
    private final JCheckBox searchRaw = new JCheckBox("RAW", false);
    private final JCheckBox searchAllStreams = new JCheckBox("All streams", true);
    private final JCheckBox highlightedOnly = new JCheckBox("Highlighted only", false);
    private final JCheckBox modifiedOnly = new JCheckBox("Modified only", false);
    private final JCheckBox hideHandshakeAuth = new JCheckBox("Hide handshake/auth", false);
    private final JLabel searchStatus = new JLabel(" ");
    /** Active stream-list filter text (from Search when All streams is on). */
    private String streamFilterQuery = "";
    /**
     * Stream keys that matched the last async content search ({@code null} = no active content filter).
     * Live UI refreshes use this set instead of re-scanning every frame body on the EDT.
     */
    private volatile java.util.Set<String> searchMatchedStreamKeys;
    private final AtomicInteger searchGen = new AtomicInteger(0);
    private final JLabel followStatus = new JLabel(" ");
    /** Dedicated Follow Stream text search (independent of capture Search above). */
    private final JTextField followTextSearchField = new JTextField(18);
    private final JButton followSearchPrev = new JButton("▲");
    private final JButton followSearchNext = new JButton("▼");
    private final JLabel followSearchHitLabel = new JLabel(" ");
    /** Document offsets of Follow Stream search hits (start index of each match). */
    private final List<Integer> followSearchHits = new ArrayList<>();
    private int followSearchHitIndex = -1;
    private final JRadioButton detailSimple = new JRadioButton("Simple", true);
    private final JRadioButton detailFull = new JRadioButton("Full technical", false);
    private List<TcpStreamFrame> currentFrames = List.of();
    private final List<String> streamKeys = new ArrayList<>();
    private final AtomicBoolean uiRefreshPending = new AtomicBoolean(false);
    private final AtomicInteger followGen = new AtomicInteger(0);
    private final ExecutorService uiWorker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "dsl-tcp-streams-ui");
        t.setDaemon(true);
        return t;
    });
    private volatile boolean suppressSelectionEvents;
    /** Ignore scrollbar events while we programmatically scroll the stream list. */
    private boolean suppressAutoScrollToggle;
    /**
     * User unchecked Auto-scroll while already at the bottom — stay off until they leave the bottom
     * (then normal scroll-to-bottom re-enable applies).
     */
    private boolean holdAutoScrollOffUntilLeaveBottom;
    private boolean suppressFrameAutoScrollToggle;
    private boolean holdFrameAutoScrollOffUntilLeaveBottom;
    private boolean suppressFollowAutoScrollToggle;
    private boolean holdFollowAutoScrollOffUntilLeaveBottom;
    private JScrollPane streamScroll;
    private JScrollPane frameScroll;
    private JScrollPane followScroll;

    public TcpStreamsPanel(MontoyaApi api, TcpStreamStore store) {
        super(new BorderLayout(8, 8));
        setBorder(new EmptyBorder(8, 8, 8, 8));
        this.logging = api.logging();
        this.store = store;

        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchBar.add(new JLabel("Search:"));
        searchBar.add(searchField);
        searchBar.add(searchUtf16);
        searchBar.add(searchRaw);
        searchBar.add(searchAllStreams);
        searchBar.add(highlightedOnly);
        searchBar.add(modifiedOnly);
        searchBar.add(hideHandshakeAuth);
        searchAllStreams.setToolTipText(
                "When checked, filter the TCP Streams list to streams that match (name, endpoint, or frame content). "
                        + "Also filter frames in the selected stream.");
        searchField.setToolTipText(
                "Find text in stream names / endpoints / frame SQL & bodies (UTF-16LE and/or RAW).");
        highlightedOnly.setToolTipText("Show only frames (and streams) with a user highlight color.");
        modifiedOnly.setToolTipText("Show only frames altered by match/replace (★ / Mod column).");
        hideHandshakeAuth.setToolTipText(
                "Hide PRELOGIN, LOGIN7, SSPI and other handshake/auth PDUs from Frames and Follow Stream.");
        JButton searchBtn = new JButton("Search");
        searchBtn.addActionListener(e -> runSearch());
        JButton clearSearch = new JButton("Clear");
        clearSearch.addActionListener(e -> {
            searchField.setText("");
            highlightedOnly.setSelected(false);
            modifiedOnly.setSelected(false);
            streamFilterQuery = "";
            searchMatchedStreamKeys = null;
            runSearch();
        });
        searchBar.add(searchBtn);
        searchBar.add(clearSearch);
        searchBar.add(searchStatus);
        searchField.addActionListener(e -> runSearch());
        highlightedOnly.addActionListener(e -> runSearch());
        modifiedOnly.addActionListener(e -> runSearch());
        searchAllStreams.addActionListener(e -> runSearch());
        hideHandshakeAuth.addActionListener(e -> {
            applySearch(true);
            rebuildFollowStreamAsync();
        });

        streamTable = new JTable(streamModel);
        streamTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        streamTable.setFillsViewportHeight(true);
        streamTable.setRowHeight(22);
        streamTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        // # | Name | Frames | Time (UTC)
        streamTable.getColumnModel().getColumn(0).setPreferredWidth(36);
        streamTable.getColumnModel().getColumn(1).setPreferredWidth(100);
        streamTable.getColumnModel().getColumn(2).setPreferredWidth(52);
        streamTable.getColumnModel().getColumn(3).setPreferredWidth(160);
        streamTable.setDefaultRenderer(Object.class, new StreamRowRenderer());
        streamTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting() || suppressSelectionEvents) {
                return;
            }
            refreshFrames(true);
        });
        streamTable.setComponentPopupMenu(buildStreamContextMenu());
        streamTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                maybeSelectStreamOnPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                maybeSelectStreamOnPopup(e);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && !e.isPopupTrigger()) {
                    int row = streamTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        streamTable.setRowSelectionInterval(row, row);
                        renameSelectedStream();
                    }
                }
            }

            private void maybeSelectStreamOnPopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = streamTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        streamTable.setRowSelectionInterval(row, row);
                    }
                }
            }
        });

        frameTable = new JTable(frameModel);
        frameTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        frameTable.setFillsViewportHeight(true);
        frameTable.setRowHeight(22);
        // # Dir Date Time Bytes Mod HL Summary
        frameTable.getColumnModel().getColumn(0).setPreferredWidth(48);
        frameTable.getColumnModel().getColumn(1).setPreferredWidth(40);
        frameTable.getColumnModel().getColumn(2).setPreferredWidth(90);
        frameTable.getColumnModel().getColumn(3).setPreferredWidth(110);
        frameTable.getColumnModel().getColumn(4).setPreferredWidth(50);
        frameTable.getColumnModel().getColumn(5).setPreferredWidth(36);
        frameTable.getColumnModel().getColumn(6).setPreferredWidth(48);
        frameTable.getColumnModel().getColumn(7).setPreferredWidth(360);
        frameTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedDetail();
            }
        });
        frameTable.setDefaultRenderer(Object.class, new FrameRowRenderer());
        frameTable.setComponentPopupMenu(buildFrameContextMenu());
        frameTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                maybeSelectRowOnPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                maybeSelectRowOnPopup(e);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && !e.isPopupTrigger()) {
                    int row = frameTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        frameTable.setRowSelectionInterval(row, row);
                        renameSelectedFrame();
                    }
                }
            }

            private void maybeSelectRowOnPopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = frameTable.rowAtPoint(e.getPoint());
                    if (row >= 0 && !frameTable.isRowSelected(row)) {
                        frameTable.setRowSelectionInterval(row, row);
                    }
                }
            }
        });

        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        followArea = new JTextArea();
        followArea.setEditable(false);
        followArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel followControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        followControls.add(new JLabel("View:"));
        followControls.add(followMode);
        followControls.add(followBoth);
        autoScrollFollow.setToolTipText(
                "When checked, keep Follow Stream scrolled to the end (latest traffic). "
                        + "Scroll up to pause; scroll back to the bottom to resume.");
        autoScrollFollow.addActionListener(e -> {
            if (suppressFollowAutoScrollToggle) {
                return;
            }
            if (autoScrollFollow.isSelected()) {
                holdFollowAutoScrollOffUntilLeaveBottom = false;
                scrollFollowToBottom();
            } else {
                holdFollowAutoScrollOffUntilLeaveBottom = isFollowAtBottom();
            }
        });
        followControls.add(autoScrollFollow);
        JButton copyFollow = new JButton("Copy follow text");
        copyFollow.setToolTipText(
                "Copy the entire Follow Stream dump to the clipboard (full tables, not just the selection).");
        copyFollow.addActionListener(e -> copyFollowTextToClipboard());
        followControls.add(copyFollow);
        JButton saveFollow = new JButton("Save to file");
        saveFollow.setToolTipText(
                "Save the full Follow Stream dump to a UTF-8 text file (complete table cells, no truncation).");
        saveFollow.addActionListener(e -> saveFollowTextToFile());
        followControls.add(saveFollow);
        followControls.add(followStatus);
        followMode.addActionListener(e -> rebuildFollowStreamAsync());
        followBoth.addActionListener(e -> rebuildFollowStreamAsync());

        JPanel followPanel = new JPanel(new BorderLayout());
        followPanel.setBorder(new TitledBorder("Follow TCP Stream (continuous conversation)"));
        followPanel.add(followControls, BorderLayout.NORTH);
        followScroll = new JScrollPane(followArea);
        followScroll.getVerticalScrollBar().addAdjustmentListener(e -> syncFollowAutoScrollFromViewport());
        followPanel.add(followScroll, BorderLayout.CENTER);

        JPanel framesPanel = new JPanel(new BorderLayout());
        framesPanel.setBorder(new TitledBorder("Frames"));
        autoScrollFrames.setToolTipText(
                "When checked, keep Frames scrolled to the latest frame. "
                        + "Scroll up to pause; scroll back to the bottom to resume.");
        autoScrollFrames.addActionListener(e -> {
            if (suppressFrameAutoScrollToggle) {
                return;
            }
            if (autoScrollFrames.isSelected()) {
                holdFrameAutoScrollOffUntilLeaveBottom = false;
                scrollFrameListToBottom();
            } else {
                holdFrameAutoScrollOffUntilLeaveBottom = isFrameListAtBottom();
            }
        });
        JPanel framesNorth = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        framesNorth.add(autoScrollFrames);
        framesPanel.add(framesNorth, BorderLayout.NORTH);
        ButtonGroup detailGroup = new ButtonGroup();
        detailGroup.add(detailSimple);
        detailGroup.add(detailFull);
        JPanel detailBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        detailBar.add(new JLabel("Detail:"));
        detailBar.add(detailSimple);
        detailBar.add(detailFull);
        detailSimple.addActionListener(e -> showSelectedDetail());
        detailFull.addActionListener(e -> showSelectedDetail());
        JPanel detailWrap = new JPanel(new BorderLayout());
        detailWrap.add(detailBar, BorderLayout.NORTH);
        detailWrap.add(new JScrollPane(detailArea), BorderLayout.CENTER);
        frameScroll = new JScrollPane(frameTable);
        frameScroll.getVerticalScrollBar().addAdjustmentListener(e -> syncFrameAutoScrollFromViewport());
        JSplitPane framesSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, frameScroll, detailWrap);
        framesSplit.setResizeWeight(0.55);
        framesPanel.add(framesSplit, BorderLayout.CENTER);

        JTabbedPane rightTabs = new JTabbedPane();
        rightTabs.addTab("Frames", framesPanel);
        rightTabs.addTab("Follow Stream", followPanel);

        JPanel streamSide = new JPanel(new BorderLayout(4, 4));
        streamSide.setBorder(new TitledBorder("TCP Streams"));
        autoScrollStreams.setToolTipText(
                "When checked, keep the list scrolled to the latest TCP Stream. "
                        + "Scroll up to pause; scroll back to the bottom to resume.");
        autoScrollStreams.addActionListener(e -> {
            if (suppressAutoScrollToggle) {
                return;
            }
            if (autoScrollStreams.isSelected()) {
                holdAutoScrollOffUntilLeaveBottom = false;
                scrollStreamListToBottom();
            } else {
                // Stay off if unchecked while already at bottom until the user scrolls away
                holdAutoScrollOffUntilLeaveBottom = isStreamListAtBottom();
            }
        });
        JPanel streamNorth = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        streamNorth.add(autoScrollStreams);
        streamSide.add(streamNorth, BorderLayout.NORTH);
        streamScroll = new JScrollPane(streamTable);
        streamScroll.getVerticalScrollBar().addAdjustmentListener(e -> syncAutoScrollFromViewport());
        streamSide.add(streamScroll, BorderLayout.CENTER);

        JSplitPane mid = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, streamSide, rightTabs);
        mid.setResizeWeight(0.28);
        mid.setDividerLocation(340);

        // Bottom bar: Follow Stream text search + stream store actions
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        followTextSearchField.setToolTipText(
                "Search text inside the Follow Stream dump (highlight + ▲/▼). Independent of capture Search above.");
        followSearchPrev.setToolTipText("Previous match in Follow Stream");
        followSearchNext.setToolTipText("Next match in Follow Stream");
        followSearchPrev.setMargin(new Insets(1, 6, 1, 6));
        followSearchNext.setMargin(new Insets(1, 6, 1, 6));
        followSearchPrev.setEnabled(false);
        followSearchNext.setEnabled(false);
        followSearchPrev.addActionListener(e -> goToFollowSearchHit(-1));
        followSearchNext.addActionListener(e -> goToFollowSearchHit(1));
        JButton followFindBtn = new JButton("Find");
        followFindBtn.addActionListener(e -> runFollowTextSearch());
        JButton followFindClear = new JButton("Clear find");
        followFindClear.addActionListener(e -> {
            followTextSearchField.setText("");
            runFollowTextSearch();
        });
        followTextSearchField.addActionListener(e -> runFollowTextSearch());
        buttons.add(new JLabel("Follow find:"));
        buttons.add(followTextSearchField);
        buttons.add(followFindBtn);
        buttons.add(followSearchPrev);
        buttons.add(followSearchNext);
        buttons.add(followSearchHitLabel);
        buttons.add(Box.createHorizontalStrut(12));
        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(e -> refreshStreams(true));
        JButton clearStream = new JButton("Clear stream");
        clearStream.setToolTipText("Remove the selected TCP Stream from capture (right-click for more actions)");
        clearStream.addActionListener(e -> confirmClearSelectedStream());
        JButton clearAll = new JButton("Clear all");
        clearAll.setToolTipText("Remove all TCP Streams from capture");
        clearAll.addActionListener(e -> confirmClearAllStreams());
        buttons.add(refresh);
        buttons.add(clearStream);
        buttons.add(clearAll);

        add(searchBar, BorderLayout.NORTH);
        add(mid, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        store.addListener(s -> scheduleUiRefresh());
        UndoSupport.enable(searchField);
        UndoSupport.enable(followTextSearchField);
        refreshStreams(true);
    }

    private void runFollowTextSearch() {
        String q = followTextSearchField.getText() != null ? followTextSearchField.getText().trim() : "";
        int hits = applyFollowSearchHighlight(q);
        if (q.isEmpty()) {
            followStatus.setText(statusBaseFollow() + " · find cleared");
        } else if (hits > 0) {
            followStatus.setText(statusBaseFollow() + " · " + hits + " find hit(s)");
        } else {
            followStatus.setText(statusBaseFollow() + " · no find hits");
        }
    }

    private String statusBaseFollow() {
        int n = currentFrames != null ? currentFrames.size() : 0;
        int chars = lastFollowDump != null ? lastFollowDump.length() : 0;
        return n + " frame(s) in follow"
                + (hideHandshakeAuth.isSelected() ? " (handshake hidden)" : "")
                + (chars > 0 ? " · " + chars + " chars" : "");
    }

    /** Wire relay so live TCP Streams can be auto-highlighted. */
    public void setRelayService(TcpRelayService relay) {
        this.relayService = relay;
        if (relay != null) {
            relay.addStatusListener(r -> SwingUtilities.invokeLater(() -> {
                streamTable.repaint();
                // refresh labels for [live] without full follow rebuild
                refreshStreams(false);
            }));
        }
        SwingUtilities.invokeLater(() -> refreshStreams(false));
    }

    private boolean isStreamLive(String streamKey) {
        TcpRelayService r = relayService;
        return r != null && streamKey != null && r.getLiveSession(streamKey) != null;
    }

    /**
     * Coalesce store notifications: at most one UI rebuild scheduled on the EDT.
     */
    private void scheduleUiRefresh() {
        if (!uiRefreshPending.compareAndSet(false, true)) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            uiRefreshPending.set(false);
            refreshStreams(false);
        });
    }

    private JPopupMenu buildStreamContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem rename = new JMenuItem("Rename TCP Stream…");
        rename.addActionListener(e -> renameSelectedStream());
        menu.add(rename);
        JMenuItem clearName = new JMenuItem("Clear stream name");
        clearName.addActionListener(e -> {
            String key = selectedStreamKey();
            if (key != null) {
                store.setStreamUserName(key, "");
            }
        });
        menu.add(clearName);
        menu.addSeparator();
        menu.add(buildHighlightSubmenu("Highlight TCP Stream", this::highlightSelectedStream));
        menu.addSeparator();
        JMenuItem sendStream = new JMenuItem("Send TCP Stream to Replay");
        sendStream.addActionListener(e -> sendToReplay(false));
        menu.add(sendStream);
        JMenuItem clearStream = new JMenuItem("Clear this TCP Stream");
        clearStream.addActionListener(e -> confirmClearSelectedStream());
        menu.add(clearStream);
        return menu;
    }

    private void confirmClearSelectedStream() {
        String key = selectedStreamKey();
        if (key == null) {
            JOptionPane.showMessageDialog(this, "Select a TCP Stream first.",
                    "Clear stream", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        TcpStream s = store.getStream(key);
        String label = s != null ? s.getDisplayLabel() : key;
        int n = s != null ? s.getFrameCount() : 0;
        int r = JOptionPane.showConfirmDialog(this,
                "Clear TCP Stream and remove " + n + " frame(s) from capture?\n\n" + label,
                "Clear stream",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (r == JOptionPane.OK_OPTION) {
            store.clearPeer(key);
            refreshStreams(true);
        }
    }

    private void confirmClearAllStreams() {
        int streams = store.streamCount();
        int frames = store.frameCount();
        if (streams == 0) {
            return;
        }
        int r = JOptionPane.showConfirmDialog(this,
                "Clear all TCP Streams from capture?\n\n"
                        + streams + " stream(s), " + frames + " frame(s) will be removed.\n"
                        + "This cannot be undone.",
                "Clear all",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (r == JOptionPane.OK_OPTION) {
            store.clearAll();
            refreshStreams(true);
        }
    }

    private JPopupMenu buildFrameContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem rename = new JMenuItem("Rename Frame…");
        rename.addActionListener(e -> renameSelectedFrame());
        menu.add(rename);
        JMenuItem clearName = new JMenuItem("Clear frame name");
        clearName.addActionListener(e -> {
            String key = selectedStreamKey();
            int[] rows = frameTable.getSelectedRows();
            if (key != null) {
                for (int row : rows) {
                    TcpStreamFrame f = frameModel.getFrame(row);
                    if (f != null) {
                        store.setFrameUserName(key, f.getSeq(), "");
                    }
                }
            }
        });
        menu.add(clearName);
        menu.addSeparator();
        menu.add(buildHighlightSubmenu("Highlight selected Frames", this::highlightSelectedFrames));
        menu.addSeparator();
        JMenuItem sendSel = new JMenuItem("Send selected Frames to Replay");
        sendSel.addActionListener(e -> sendToReplay(true));
        menu.add(sendSel);
        JMenuItem sendStream = new JMenuItem("Send TCP Stream to Replay");
        sendStream.addActionListener(e -> sendToReplay(false));
        menu.add(sendStream);
        JMenuItem toConvert = new JMenuItem("Send Frame body to Convert");
        toConvert.addActionListener(e -> sendSelectedToConvert());
        menu.add(toConvert);
        return menu;
    }

    private JMenu buildHighlightSubmenu(String title, Consumer<String> onPick) {
        JMenu hl = new JMenu(title);
        JMenuItem none = new JMenuItem("None (clear)");
        none.addActionListener(e -> onPick.accept(HighlightColors.NONE));
        hl.add(none);
        hl.addSeparator();
        for (String name : HighlightColors.names()) {
            JMenuItem mi = new JMenuItem(HighlightColors.displayName(name));
            Color bg = HighlightColors.background(name);
            if (bg != null) {
                mi.setBackground(bg);
                mi.setOpaque(true);
            }
            mi.addActionListener(e -> onPick.accept(name));
            hl.add(mi);
        }
        return hl;
    }

    private void renameSelectedStream() {
        String key = selectedStreamKey();
        if (key == null) {
            return;
        }
        TcpStream stream = store.getStream(key);
        if (stream == null) {
            return;
        }
        String current = stream.getUserName();
        String conn = stream.getConnectionLabel();
        Object result = JOptionPane.showInputDialog(
                this,
                "Name for this TCP Stream (finding note).\nConnection: " + conn + "\n\nLeave empty to clear.",
                "Rename TCP Stream",
                JOptionPane.PLAIN_MESSAGE,
                null,
                null,
                current != null ? current : "");
        if (result == null) {
            return; // cancelled
        }
        store.setStreamUserName(key, String.valueOf(result));
    }

    private void renameSelectedFrame() {
        String key = selectedStreamKey();
        if (key == null) {
            return;
        }
        int row = frameTable.getSelectedRow();
        TcpStreamFrame frame = frameModel.getFrame(row);
        if (frame == null) {
            // multi-select: rename first selected only, or batch with same name
            int[] rows = frameTable.getSelectedRows();
            if (rows.length == 0) {
                return;
            }
            frame = frameModel.getFrame(rows[0]);
            if (frame == null) {
                return;
            }
        }
        String current = frame.getUserName();
        String auto = frame.getSummary();
        Object result = JOptionPane.showInputDialog(
                this,
                "Name for Frame #" + frame.getSeq()
                        + " (finding note).\nAuto summary: " + auto
                        + "\n\nLeave empty to clear and show auto summary again.",
                "Rename Frame",
                JOptionPane.PLAIN_MESSAGE,
                null,
                null,
                current != null ? current : "");
        if (result == null) {
            return;
        }
        String name = String.valueOf(result);
        int[] rows = frameTable.getSelectedRows();
        if (rows.length <= 1) {
            store.setFrameUserName(key, frame.getSeq(), name);
        } else {
            // Same note on all selected frames
            for (int r : rows) {
                TcpStreamFrame f = frameModel.getFrame(r);
                if (f != null) {
                    store.setFrameUserName(key, f.getSeq(), name);
                }
            }
        }
    }

    private void highlightSelectedStream(String color) {
        String key = selectedStreamKey();
        if (key == null) {
            return;
        }
        store.setStreamHighlight(key, HighlightColors.normalize(color));
        // store listener refreshes UI
    }

    private void highlightSelectedFrames(String color) {
        String key = selectedStreamKey();
        if (key == null) {
            return;
        }
        int[] rows = frameTable.getSelectedRows();
        if (rows.length == 0) {
            return;
        }
        long[] seqs = new long[rows.length];
        int n = 0;
        for (int row : rows) {
            TcpStreamFrame f = frameModel.getFrame(row);
            if (f != null) {
                seqs[n++] = f.getSeq();
            }
        }
        if (n == 0) {
            return;
        }
        if (n < seqs.length) {
            long[] trimmed = new long[n];
            System.arraycopy(seqs, 0, trimmed, 0, n);
            seqs = trimmed;
        }
        store.setFrameHighlights(key, seqs, HighlightColors.normalize(color));
    }

    /**
     * @param fullFollow if true (user selected a stream), rebuild follow when auto or first open
     */
    private void refreshStreams(boolean fullFollow) {
        String selectedKey = selectedStreamKey();
        int prevIndex = streamTable.getSelectedRow();
        List<TcpStream> all = store.getStreams();
        List<TcpStream> streams = filterStreams(all);

        suppressSelectionEvents = true;
        try {
            streamKeys.clear();
            for (TcpStream s : streams) {
                streamKeys.add(s.getStreamKey());
            }
            streamModel.setStreams(streams);
            if (selectedKey != null) {
                int idx = streamKeys.indexOf(selectedKey);
                if (idx >= 0 && prevIndex != idx) {
                    streamTable.setRowSelectionInterval(idx, idx);
                } else if (idx >= 0 && prevIndex == idx) {
                    // keep selection
                    streamTable.getSelectionModel().setSelectionInterval(idx, idx);
                } else if (!streams.isEmpty()) {
                    // selected stream filtered out — jump to first match
                    streamTable.setRowSelectionInterval(0, 0);
                }
            } else if (streamModel.getRowCount() > 0 && streamTable.getSelectedRow() < 0) {
                streamTable.setRowSelectionInterval(0, 0);
            }
        } finally {
            suppressSelectionEvents = false;
        }

        if (autoScrollStreams.isSelected() && streamFilterQuery.isEmpty()) {
            scrollStreamListToBottom();
        }

        refreshFrames(true);
        streamTable.repaint();
    }

    /**
     * Run stream + frame search off the EDT. Does not rebuild Follow Stream (full dump is expensive);
     * only re-highlights the existing follow text.
     */
    private void runSearch() {
        final String q = searchField.getText() != null ? searchField.getText().trim() : "";
        final boolean allStreams = searchAllStreams.isSelected();
        final boolean onlyHl = highlightedOnly.isSelected();
        final boolean onlyMod = modifiedOnly.isSelected();
        final boolean hideHs = hideHandshakeAuth.isSelected();
        boolean utf = searchUtf16.isSelected();
        boolean raw = searchRaw.isSelected();
        if (!utf && !raw) {
            utf = true;
        }
        final boolean utfF = utf;
        final boolean rawF = raw;

        if (allStreams && !q.isEmpty()) {
            streamFilterQuery = q;
        } else if (allStreams && (onlyHl || onlyMod)) {
            streamFilterQuery = "";
        } else {
            streamFilterQuery = "";
        }

        if (q.isEmpty() && !onlyHl && !onlyMod) {
            searchMatchedStreamKeys = null;
            streamFilterQuery = "";
            refreshStreams(false);
            applySearch(true);
            return;
        }

        final int gen = searchGen.incrementAndGet();
        searchStatus.setText("Searching…");
        final String selectedKey = selectedStreamKey();
        final List<TcpStream> allStreamsSnapshot = store.getStreams();
        final long[] selectedSeqs = captureSelectedFrameSeqs();

        uiWorker.execute(() -> {
            try {
                java.util.Set<String> matchedKeys = null;
                List<TcpStream> matchedStreams = allStreamsSnapshot;
                if (allStreams && (!q.isEmpty() || onlyHl || onlyMod)) {
                    matchedKeys = new java.util.LinkedHashSet<>();
                    matchedStreams = new ArrayList<>();
                    String qLower = q.toLowerCase(Locale.ROOT);
                    for (TcpStream s : allStreamsSnapshot) {
                        if (gen != searchGen.get()) {
                            return;
                        }
                        if (streamMatchesFast(s, q, qLower, utfF, rawF, onlyHl, onlyMod, hideHs)) {
                            matchedKeys.add(s.getStreamKey());
                            matchedStreams.add(s);
                        }
                    }
                }

                String keyForFrames = selectedKey;
                if (matchedKeys != null && keyForFrames != null && !matchedKeys.contains(keyForFrames)) {
                    keyForFrames = matchedStreams.isEmpty() ? null : matchedStreams.get(0).getStreamKey();
                }
                if (keyForFrames == null && !matchedStreams.isEmpty()) {
                    keyForFrames = matchedStreams.get(0).getStreamKey();
                }
                List<TcpStreamFrame> fullFrames = List.of();
                if (keyForFrames != null) {
                    TcpStream st = store.getStream(keyForFrames);
                    if (st != null) {
                        fullFrames = st.getFrames();
                    }
                }
                List<TcpStreamFrame> filteredFrames = filterFrameList(fullFrames, q, utfF, rawF,
                        onlyHl, onlyMod, hideHs, gen);

                final java.util.Set<String> keysOut = matchedKeys;
                final List<TcpStream> streamsOut = matchedStreams;
                final List<TcpStreamFrame> framesOut = filteredFrames;
                final List<TcpStreamFrame> fullOut = fullFrames;
                final String keyOut = keyForFrames;
                final int streamN = streamsOut.size();
                final int frameN = framesOut.size();
                final int fullN = fullOut.size();

                SwingUtilities.invokeLater(() -> {
                    if (gen != searchGen.get()) {
                        return;
                    }
                    searchMatchedStreamKeys = keysOut;
                    suppressSelectionEvents = true;
                    try {
                        streamKeys.clear();
                        for (TcpStream s : streamsOut) {
                            streamKeys.add(s.getStreamKey());
                        }
                        streamModel.setStreams(streamsOut);
                        if (keyOut != null) {
                            int idx = streamKeys.indexOf(keyOut);
                            if (idx >= 0) {
                                streamTable.setRowSelectionInterval(idx, idx);
                            }
                        }
                    } finally {
                        suppressSelectionEvents = false;
                    }
                    currentFrames = fullOut;
                    frameModel.setFrames(framesOut, fullOut);
                    restoreFrameSelection(selectedSeqs);
                    afterFrameTableUpdate(selectedSeqs);

                    String status = streamN + " stream(s) · " + frameN + " / " + fullN + " frame(s)";
                    searchStatus.setText(status);
                    rebuildFollowStreamAsync();
                    streamTable.repaint();
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    if (gen == searchGen.get()) {
                        searchStatus.setText("Search error: " + ex.getMessage());
                    }
                });
            }
        });
    }

    private List<TcpStreamFrame> filterFrameList(List<TcpStreamFrame> source, String q,
                                                 boolean utf, boolean raw,
                                                 boolean onlyHl, boolean onlyMod, boolean hideHs,
                                                 int gen) {
        if (source == null || source.isEmpty()) {
            return List.of();
        }
        boolean need = onlyHl || onlyMod || hideHs || (q != null && !q.isEmpty());
        if (!need) {
            return source;
        }
        List<TcpStreamFrame> out = new ArrayList<>();
        for (TcpStreamFrame f : source) {
            if (gen >= 0 && gen != searchGen.get()) {
                return out;
            }
            if (hideHs && isHandshakeOrAuthFrame(f)) {
                continue;
            }
            if (onlyHl && !HighlightColors.hasHighlight(f.getHighlight())) {
                continue;
            }
            if (onlyMod && !f.isMatchReplaced()) {
                continue;
            }
            if (q != null && !q.isEmpty() && !frameContains(f, q, utf, raw)) {
                continue;
            }
            out.add(f);
        }
        return out;
    }

    /** PRELOGIN / LOGIN / SSPI / fedauth handshake PDUs (and related summaries). */
    private static boolean isHandshakeOrAuthFrame(TcpStreamFrame f) {
        if (f == null) {
            return false;
        }
        byte[] body = f.bodyRef();
        if (body != null && body.length >= 1) {
            int type = body[0] & 0xFF;
            // MS-TDS packet types commonly used for session setup / auth
            if (type == 0x02 || type == 0x10 || type == 0x11 || type == 0x12 || type == 0x08) {
                return true; // PRE_TDS7_LOGIN, LOGIN7, SSPI, PRELOGIN, FEDAUTH
            }
        }
        String s = f.getCachedSummary();
        if (s == null || s.isEmpty()) {
            return false;
        }
        String low = s.toLowerCase(Locale.ROOT);
        return low.contains("prelogin") || low.contains("login7") || low.contains("sspi")
                || low.contains("ntlm") || low.contains("kerberos") || low.contains("spnego")
                || low.contains("negotiate") || low.contains("fedauth")
                || low.startsWith("pre-login") || low.contains("authentication");
    }

    /**
     * Cheap filter for live refresh: use last search result keys, never re-scan bodies on EDT.
     */
    private List<TcpStream> filterStreams(List<TcpStream> all) {
        if (all == null || all.isEmpty()) {
            return List.of();
        }
        if (!searchAllStreams.isSelected()) {
            return all;
        }
        java.util.Set<String> matched = searchMatchedStreamKeys;
        if (matched == null) {
            // No active content filter (or search not finished)
            if (streamFilterQuery == null || streamFilterQuery.isEmpty()) {
                return all;
            }
            // Query set but results not ready — show all until async completes
            return all;
        }
        List<TcpStream> out = new ArrayList<>(matched.size());
        for (TcpStream s : all) {
            if (matched.contains(s.getStreamKey())) {
                out.add(s);
            }
        }
        return out;
    }

    /**
     * Stream match for search worker. Avoids TDS summary decode (uses cached summary only).
     */
    private static boolean streamMatchesFast(TcpStream s, String q, String qLower, boolean utf,
                                             boolean raw, boolean onlyHl, boolean onlyMod,
                                             boolean hideHs) {
        if (s == null) {
            return false;
        }
        if (q == null || q.isEmpty()) {
            if (!onlyHl && !onlyMod) {
                return false;
            }
            if (onlyHl && HighlightColors.hasHighlight(s.getHighlight())) {
                return true;
            }
            for (TcpStreamFrame f : s.getFrames()) {
                if (hideHs && isHandshakeOrAuthFrame(f)) {
                    continue;
                }
                if (onlyHl && HighlightColors.hasHighlight(f.getHighlight())) {
                    return true;
                }
                if (onlyMod && f.isMatchReplaced()) {
                    return true;
                }
            }
            return false;
        }
        String name = s.getUserName();
        if (name != null && !name.isEmpty() && name.toLowerCase(Locale.ROOT).contains(qLower)) {
            return true;
        }
        String conn = s.getConnectionLabel();
        if (conn != null && conn.toLowerCase(Locale.ROOT).contains(qLower)) {
            return true;
        }
        String key = s.getStreamKey();
        if (key != null && key.toLowerCase(Locale.ROOT).contains(qLower)) {
            return true;
        }
        for (TcpStreamFrame f : s.getFrames()) {
            if (hideHs && isHandshakeOrAuthFrame(f)) {
                continue;
            }
            if (onlyHl && !HighlightColors.hasHighlight(f.getHighlight())) {
                continue;
            }
            if (onlyMod && !f.isMatchReplaced()) {
                continue;
            }
            if (frameContains(f, q, utf, raw)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isScrollPaneAtBottom(JScrollPane scroll) {
        if (scroll == null) {
            return true;
        }
        JScrollBar bar = scroll.getVerticalScrollBar();
        int extent = bar.getVisibleAmount();
        int max = bar.getMaximum();
        int value = bar.getValue();
        // Not scrollable (all rows fit) counts as "at bottom"
        if (max <= extent) {
            return true;
        }
        // A few pixels of tolerance for layout jitter / last-row paint
        return value >= max - extent - 6;
    }

    private boolean isStreamListAtBottom() {
        return isScrollPaneAtBottom(streamScroll);
    }

    private boolean isFrameListAtBottom() {
        return isScrollPaneAtBottom(frameScroll);
    }

    private void scrollStreamListToBottom() {
        scrollTableToBottom(streamTable, streamScroll, () -> suppressAutoScrollToggle = true,
                () -> SwingUtilities.invokeLater(() -> suppressAutoScrollToggle = false));
    }

    private void scrollFrameListToBottom() {
        scrollTableToBottom(frameTable, frameScroll, () -> suppressFrameAutoScrollToggle = true,
                () -> SwingUtilities.invokeLater(() -> suppressFrameAutoScrollToggle = false));
    }

    private boolean isFollowAtBottom() {
        return isScrollPaneAtBottom(followScroll);
    }

    private void scrollFollowToBottom() {
        if (followScroll == null || followArea == null) {
            return;
        }
        suppressFollowAutoScrollToggle = true;
        try {
            javax.swing.text.Document doc = followArea.getDocument();
            int len = doc.getLength();
            if (len > 0) {
                followArea.setCaretPosition(len);
            }
            JScrollBar bar = followScroll.getVerticalScrollBar();
            bar.setValue(bar.getMaximum());
        } finally {
            SwingUtilities.invokeLater(() -> {
                // Second pass after layout finishes computing scrollbar max
                try {
                    JScrollBar bar = followScroll.getVerticalScrollBar();
                    bar.setValue(bar.getMaximum());
                    int len = followArea.getDocument().getLength();
                    if (len > 0 && autoScrollFollow.isSelected()) {
                        followArea.setCaretPosition(len);
                    }
                } catch (Exception ignored) {
                }
                suppressFollowAutoScrollToggle = false;
            });
        }
    }

    private void syncFollowAutoScrollFromViewport() {
        syncAutoScrollCheckbox(suppressFollowAutoScrollToggle, isFollowAtBottom(), autoScrollFollow,
                hold -> holdFollowAutoScrollOffUntilLeaveBottom = hold,
                () -> holdFollowAutoScrollOffUntilLeaveBottom,
                v -> suppressFollowAutoScrollToggle = v);
    }

    private void maybeScrollFollowToBottom() {
        if (autoScrollFollow.isSelected()) {
            scrollFollowToBottom();
        }
    }

    private static void scrollTableToBottom(JTable table, JScrollPane scroll,
                                            Runnable beginSuppress, Runnable endSuppressLater) {
        int rows = table.getRowCount();
        if (rows <= 0 || scroll == null) {
            return;
        }
        beginSuppress.run();
        try {
            int last = rows - 1;
            table.scrollRectToVisible(table.getCellRect(last, 0, true));
            JScrollBar bar = scroll.getVerticalScrollBar();
            bar.setValue(bar.getMaximum());
        } finally {
            endSuppressLater.run();
        }
    }

    /**
     * Scroll up → uncheck Auto-scroll; scroll fully to the latest stream → re-check.
     */
    private void syncAutoScrollFromViewport() {
        syncAutoScrollCheckbox(suppressAutoScrollToggle, isStreamListAtBottom(), autoScrollStreams,
                hold -> holdAutoScrollOffUntilLeaveBottom = hold,
                () -> holdAutoScrollOffUntilLeaveBottom,
                v -> suppressAutoScrollToggle = v);
    }

    private void syncFrameAutoScrollFromViewport() {
        syncAutoScrollCheckbox(suppressFrameAutoScrollToggle, isFrameListAtBottom(), autoScrollFrames,
                hold -> holdFrameAutoScrollOffUntilLeaveBottom = hold,
                () -> holdFrameAutoScrollOffUntilLeaveBottom,
                v -> suppressFrameAutoScrollToggle = v);
    }

    private static void syncAutoScrollCheckbox(boolean suppress, boolean atBottom, JCheckBox box,
                                               java.util.function.Consumer<Boolean> setHold,
                                               java.util.function.BooleanSupplier getHold,
                                               java.util.function.Consumer<Boolean> setSuppress) {
        if (suppress) {
            return;
        }
        if (!atBottom) {
            setHold.accept(false);
            if (box.isSelected()) {
                setSuppress.accept(true);
                try {
                    box.setSelected(false);
                } finally {
                    setSuppress.accept(false);
                }
            }
            return;
        }
        if (getHold.getAsBoolean()) {
            return;
        }
        if (!box.isSelected()) {
            setSuppress.accept(true);
            try {
                box.setSelected(true);
            } finally {
                setSuppress.accept(false);
            }
        }
    }

    private void maybeScrollFramesToBottom() {
        if (autoScrollFrames.isSelected()) {
            scrollFrameListToBottom();
        }
    }

    private String selectedStreamKey() {
        int i = streamTable.getSelectedRow();
        if (i < 0 || i >= streamKeys.size()) {
            return null;
        }
        return streamKeys.get(i);
    }

    private static String formatUtcInstant(Instant instant) {
        if (instant == null) {
            return "";
        }
        return STREAM_UTC_FMT.format(instant);
    }

    /**
     * @param rebuildFollow whether to rebuild follow stream (async) after updating the table
     */
    private void refreshFrames(boolean rebuildFollow) {
        String key = selectedStreamKey();
        if (key == null) {
            currentFrames = List.of();
            updateFrameTable(List.of());
            detailArea.setText("");
            searchStatus.setText(" ");
            followArea.setText("");
            lastFollowDump = "";
            followStatus.setText(" ");
            return;
        }
        TcpStream stream = store.getStream(key);
        currentFrames = stream != null ? stream.getFrames() : List.of();
        // Follow always auto-updates with the full stream
        applySearch(rebuildFollow);
    }

    private FollowStreamBuilder.ViewMode currentFollowMode() {
        return switch (followMode.getSelectedIndex()) {
            case 1 -> FollowStreamBuilder.ViewMode.UTF16_TEXT;
            case 2 -> FollowStreamBuilder.ViewMode.HEX;
            case 3 -> FollowStreamBuilder.ViewMode.RAW_ASCII;
            default -> FollowStreamBuilder.ViewMode.TDS_DECODE;
        };
    }

    /**
     * Full-fidelity Follow dump (unlimited table cells). Safe to call off the EDT.
     */
    private String buildFullFollowDump(List<TcpStreamFrame> use, FollowStreamBuilder.ViewMode mode,
                                       boolean both) {
        List<TcpStreamFrame> frames = use;
        if (hideHandshakeAuth.isSelected() && frames != null) {
            List<TcpStreamFrame> filtered = new ArrayList<>();
            for (TcpStreamFrame f : frames) {
                if (!isHandshakeOrAuthFrame(f)) {
                    filtered.add(f);
                }
            }
            frames = filtered;
        }
        TdsSimpleView.setMaxCellWidth(0);
        try {
            String text;
            if (frames.size() > 8_000) {
                List<TcpStreamFrame> tail = frames.subList(Math.max(0, frames.size() - 4_000), frames.size());
                text = "# Follow export: last 4000 of " + frames.size() + " frames (complete cells)\n\n"
                        + FollowStreamBuilder.build(tail, mode, both);
            } else {
                text = FollowStreamBuilder.build(frames, mode, both);
            }
            if (text != null && text.indexOf('\0') >= 0) {
                text = text.replace("\0", "");
            }
            return text != null ? text : "";
        } finally {
            TdsSimpleView.resetMaxCellWidth();
        }
    }

    private static int countLines(String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        int lines = 1;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == '\n') {
                lines++;
            }
        }
        return lines;
    }

    /**
     * Rebuild a full-fidelity Follow dump (no table cell truncation) and copy it.
     * Also writes a UTF-8 temp file so nothing is lost if the OS clipboard truncates large text.
     */
    private void copyFollowTextToClipboard() {
        final List<TcpStreamFrame> use = currentFrames != null ? List.copyOf(currentFrames) : List.of();
        final FollowStreamBuilder.ViewMode mode = currentFollowMode();
        final boolean both = followBoth.isSelected();
        followStatus.setText("Building full dump for copy (complete tables, no truncation)…");
        uiWorker.execute(() -> {
            String text;
            try {
                text = buildFullFollowDump(use, mode, both);
            } catch (Exception ex) {
                final String msg = ex.getMessage();
                SwingUtilities.invokeLater(() -> {
                    followStatus.setText("Copy build failed: " + msg);
                    logging.logToError("[-] Copy follow text build: " + msg);
                });
                return;
            }

            final String payload = text;
            String fileNote = "";
            try {
                java.nio.file.Path out = java.nio.file.Files.createTempFile("dsl-follow-stream-", ".txt");
                java.nio.file.Files.writeString(out, payload, java.nio.charset.StandardCharsets.UTF_8);
                fileNote = " · also " + out.toAbsolutePath();
            } catch (Exception fileEx) {
                fileNote = " · temp file failed: " + fileEx.getMessage();
            }
            final String fileNoteFinal = fileNote;
            final int chars = payload.length();
            final int lines = countLines(payload);

            SwingUtilities.invokeLater(() -> {
                lastFollowDump = payload;
                try {
                    int len = followArea.getDocument().getLength();
                    if (len > 0) {
                        followArea.setCaretPosition(0);
                        followArea.moveCaretPosition(0);
                    }
                    Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();
                    followClipboardTransferable = new StringSelection(payload);
                    clip.setContents(followClipboardTransferable, (clipboard, contents) -> {
                        if (followClipboardTransferable == contents) {
                            followClipboardTransferable = null;
                        }
                    });
                    try {
                        Transferable got = clip.getContents(null);
                        if (got != null && got.isDataFlavorSupported(
                                java.awt.datatransfer.DataFlavor.stringFlavor)) {
                            Object data = got.getTransferData(
                                    java.awt.datatransfer.DataFlavor.stringFlavor);
                            if (data instanceof String s && s.length() != chars) {
                                followStatus.setText("Clipboard truncated (" + s.length()
                                        + "/" + chars + " chars)" + fileNoteFinal
                                        + " — use Save to file for the full dump");
                                logging.logToError("[-] Clipboard truncated follow dump: "
                                        + s.length() + " vs " + chars);
                                return;
                            }
                        }
                    } catch (Exception ignored) {
                    }
                    followStatus.setText("Copied full follow dump (" + lines + " lines, "
                            + chars + " chars)" + fileNoteFinal);
                } catch (Exception ex) {
                    followStatus.setText("Clipboard failed (" + chars + " chars)"
                            + fileNoteFinal + " — use Save to file");
                    logging.logToError("[-] Copy follow text clipboard: " + ex.getMessage());
                }
            });
        });
    }

    /** Prompt for a path, then write a full-fidelity Follow dump (UTF-8). */
    private void saveFollowTextToFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Follow Stream dump");
        chooser.setSelectedFile(new java.io.File("follow-stream.txt"));
        javax.swing.filechooser.FileNameExtensionFilter txtFilter =
                new javax.swing.filechooser.FileNameExtensionFilter("Text files (*.txt)", "txt");
        chooser.setFileFilter(txtFilter);
        chooser.addChoosableFileFilter(txtFilter);
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File file = chooser.getSelectedFile();
        if (file == null) {
            return;
        }
        String name = file.getName();
        if (!name.contains(".")) {
            file = new java.io.File(file.getParentFile(), name + ".txt");
        }
        final java.io.File target = file;
        if (target.exists()) {
            int overwrite = JOptionPane.showConfirmDialog(this,
                    "Overwrite existing file?\n" + target.getAbsolutePath(),
                    "Save Follow Stream",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);
            if (overwrite != JOptionPane.YES_OPTION) {
                return;
            }
        }

        final List<TcpStreamFrame> use = currentFrames != null ? List.copyOf(currentFrames) : List.of();
        final FollowStreamBuilder.ViewMode mode = currentFollowMode();
        final boolean both = followBoth.isSelected();
        followStatus.setText("Building full dump for save…");
        uiWorker.execute(() -> {
            try {
                String payload = buildFullFollowDump(use, mode, both);
                java.nio.file.Files.writeString(target.toPath(), payload,
                        java.nio.charset.StandardCharsets.UTF_8);
                lastFollowDump = payload;
                final int chars = payload.length();
                final int lines = countLines(payload);
                SwingUtilities.invokeLater(() ->
                        followStatus.setText("Saved follow dump (" + lines + " lines, "
                                + chars + " chars) → " + target.getAbsolutePath()));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    followStatus.setText("Save failed: " + ex.getMessage());
                    logging.logToError("[-] Save follow text: " + ex.getMessage());
                    JOptionPane.showMessageDialog(TcpStreamsPanel.this,
                            "Could not save Follow Stream:\n" + ex.getMessage(),
                            "Save Follow Stream",
                            JOptionPane.ERROR_MESSAGE);
                });
            }
        });
    }

    /** Rebuild Follow Stream from the selected stream (always on; optional handshake filter). */
    private void rebuildFollowStreamAsync() {
        final int gen = followGen.incrementAndGet();
        List<TcpStreamFrame> base = currentFrames != null ? currentFrames : List.of();
        if (hideHandshakeAuth.isSelected()) {
            List<TcpStreamFrame> filtered = new ArrayList<>();
            for (TcpStreamFrame f : base) {
                if (!isHandshakeOrAuthFrame(f)) {
                    filtered.add(f);
                }
            }
            base = filtered;
        }
        final List<TcpStreamFrame> use = base;
        final String highlightQuery = followTextSearchField.getText() != null
                ? followTextSearchField.getText().trim() : "";
        final FollowStreamBuilder.ViewMode mode = switch (followMode.getSelectedIndex()) {
            case 1 -> FollowStreamBuilder.ViewMode.UTF16_TEXT;
            case 2 -> FollowStreamBuilder.ViewMode.HEX;
            case 3 -> FollowStreamBuilder.ViewMode.RAW_ASCII;
            default -> FollowStreamBuilder.ViewMode.TDS_DECODE;
        };
        final boolean both = followBoth.isSelected();
        final int n = use.size();
        final boolean hidHs = hideHandshakeAuth.isSelected();
        followStatus.setText("Building follow (" + n + " frames"
                + (hidHs ? ", handshake hidden" : "") + ")…");
        uiWorker.execute(() -> {
            try {
                String text;
                if (use.size() > 8_000) {
                    List<TcpStreamFrame> tail = use.subList(Math.max(0, use.size() - 4_000), use.size());
                    text = "# Follow truncated: showing last 4000 of " + use.size() + " frames\n\n"
                            + FollowStreamBuilder.build(tail, mode, both);
                } else {
                    text = FollowStreamBuilder.build(use, mode, both);
                }
                final String out = text;
                final int frameN = use.size();
                SwingUtilities.invokeLater(() -> {
                    if (gen != followGen.get()) {
                        return;
                    }
                    lastFollowDump = out != null ? out : "";
                    followArea.setText(lastFollowDump);
                    try {
                        int docLen = followArea.getDocument().getLength();
                        if (docLen != lastFollowDump.length()) {
                            javax.swing.text.PlainDocument doc = new javax.swing.text.PlainDocument();
                            doc.insertString(0, lastFollowDump, null);
                            followArea.setDocument(doc);
                        }
                    } catch (Exception ignored) {
                    }
                    int hits = applyFollowSearchHighlight(highlightQuery);
                    String sizeNote = " · " + lastFollowDump.length() + " chars";
                    String hs = hidHs ? " (handshake hidden)" : "";
                    if (hits > 0) {
                        followStatus.setText(frameN + " frame(s) in follow" + hs + " · "
                                + hits + " find hit(s)" + sizeNote);
                        // Find navigation owns scroll position
                    } else if (!highlightQuery.isEmpty()) {
                        followStatus.setText(frameN + " frame(s) in follow" + hs
                                + " · no find hits" + sizeNote);
                        maybeScrollFollowToBottom();
                    } else {
                        followStatus.setText(frameN + " frame(s) in follow" + hs + sizeNote);
                        maybeScrollFollowToBottom();
                    }
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    if (gen != followGen.get()) {
                        return;
                    }
                    followStatus.setText("Follow build error: " + ex.getMessage());
                });
            }
        });
    }

    /**
     * Highlight all case-insensitive occurrences of {@code query} in Follow Stream text.
     * Returns hit count. Populates prev/next navigation and scrolls to the first match.
     */
    private int applyFollowSearchHighlight(String query) {
        Highlighter hl = followArea.getHighlighter();
        hl.removeAllHighlights();
        followSearchHits.clear();
        followSearchHitIndex = -1;
        updateFollowSearchNavUi();
        if (query == null || query.isEmpty()) {
            return 0;
        }
        String text = followArea.getText();
        if (text == null || text.isEmpty()) {
            return 0;
        }
        String hay = text.toLowerCase(Locale.ROOT);
        String needle = query.toLowerCase(Locale.ROOT);
        int from = 0;
        int count = 0;
        while (from < hay.length()) {
            int at = hay.indexOf(needle, from);
            if (at < 0) {
                break;
            }
            try {
                hl.addHighlight(at, at + needle.length(), FOLLOW_SEARCH_PAINTER);
                followSearchHits.add(at);
                count++;
            } catch (BadLocationException ignored) {
                break;
            }
            from = at + Math.max(1, needle.length());
            // Safety: huge dumps with many hits
            if (count >= 50_000) {
                break;
            }
        }
        if (!followSearchHits.isEmpty()) {
            followSearchHitIndex = 0;
            scrollFollowToHit(followSearchHits.get(0));
        }
        updateFollowSearchNavUi();
        return count;
    }

    private void goToFollowSearchHit(int delta) {
        if (followSearchHits.isEmpty()) {
            return;
        }
        int n = followSearchHits.size();
        followSearchHitIndex = Math.floorMod(followSearchHitIndex + delta, n);
        scrollFollowToHit(followSearchHits.get(followSearchHitIndex));
        updateFollowSearchNavUi();
    }

    private void scrollFollowToHit(int offset) {
        if (offset < 0) {
            return;
        }
        String text = followArea.getText();
        if (text == null || offset > text.length()) {
            return;
        }
        followArea.setCaretPosition(offset);
        followArea.getCaret().setSelectionVisible(true);
        // Briefly select the hit for visibility
        String q = followTextSearchField.getText() != null ? followTextSearchField.getText().trim() : "";
        if (!q.isEmpty() && offset + q.length() <= text.length()) {
            followArea.select(offset, offset + q.length());
        }
        try {
            Rectangle r = followArea.modelToView2D(offset).getBounds();
            if (r != null) {
                // Pad so the hit is not glued to the top edge
                r.grow(0, 40);
                followArea.scrollRectToVisible(r);
            }
        } catch (Exception ignored) {
            try {
                @SuppressWarnings("deprecation")
                Rectangle r = followArea.modelToView(offset);
                if (r != null) {
                    r.grow(0, 40);
                    followArea.scrollRectToVisible(r);
                }
            } catch (Exception ignored2) {
            }
        }
        followArea.requestFocusInWindow();
    }

    private void updateFollowSearchNavUi() {
        boolean has = !followSearchHits.isEmpty();
        followSearchPrev.setEnabled(has);
        followSearchNext.setEnabled(has);
        if (!has) {
            followSearchHitLabel.setText(" ");
        } else {
            followSearchHitLabel.setText((followSearchHitIndex + 1) + " / " + followSearchHits.size());
        }
    }

    private void applySearch(boolean rebuildFollow) {
        String q = searchField.getText() != null ? searchField.getText().trim() : "";
        boolean onlyHl = highlightedOnly.isSelected();
        boolean onlyMod = modifiedOnly.isSelected();
        boolean hideHs = hideHandshakeAuth.isSelected();
        boolean utf = searchUtf16.isSelected();
        boolean raw = searchRaw.isSelected();
        if (!utf && !raw) {
            utf = true;
        }
        final boolean needFilter = onlyHl || onlyMod || hideHs || !q.isEmpty();
        final List<TcpStreamFrame> source = currentFrames;
        final boolean utfF = utf;
        final boolean rawF = raw;

        if (!needFilter) {
            updateFrameTable(source);
            String streamNote = searchMatchedStreamKeys != null
                    ? streamKeys.size() + " stream(s) · "
                    : "";
            searchStatus.setText(streamNote + source.size() + " frame(s)");
            if (rebuildFollow) {
                rebuildFollowStreamAsync();
            }
            return;
        }

        searchStatus.setText("Filtering…");
        final int gen = searchGen.incrementAndGet();
        final long[] selectedSeqs = captureSelectedFrameSeqs();
        final int streamMatchN = streamKeys.size();
        final boolean onlyHlF = onlyHl;
        final boolean onlyModF = onlyMod;
        final boolean hideHsF = hideHs;
        uiWorker.execute(() -> {
            List<TcpStreamFrame> filtered = filterFrameList(source, q, utfF, rawF,
                    onlyHlF, onlyModF, hideHsF, gen);
            if (gen != searchGen.get()) {
                return;
            }
            SwingUtilities.invokeLater(() -> {
                if (gen != searchGen.get()) {
                    return;
                }
                frameModel.setFrames(filtered, source);
                restoreFrameSelection(selectedSeqs);
                String prefix = searchAllStreams.isSelected() && !q.isEmpty()
                        ? streamMatchN + " stream(s) · "
                        : "";
                searchStatus.setText(prefix + filtered.size() + " / " + source.size() + " frame(s)");
                afterFrameTableUpdate(selectedSeqs);
                if (rebuildFollow) {
                    rebuildFollowStreamAsync();
                }
            });
        });
    }

    /** Capture selected frame global seqs (stable across table rebuilds). */
    private long[] captureSelectedFrameSeqs() {
        int[] rows = frameTable.getSelectedRows();
        if (rows == null || rows.length == 0) {
            return new long[0];
        }
        long[] seqs = new long[rows.length];
        int n = 0;
        for (int row : rows) {
            TcpStreamFrame f = frameModel.getFrame(row);
            if (f != null) {
                seqs[n++] = f.getSeq();
            }
        }
        if (n == seqs.length) {
            return seqs;
        }
        long[] trimmed = new long[n];
        System.arraycopy(seqs, 0, trimmed, 0, n);
        return trimmed;
    }

    private void restoreFrameSelection(long[] seqs) {
        if (seqs == null || seqs.length == 0) {
            return;
        }
        ListSelectionModel sm = frameTable.getSelectionModel();
        sm.setValueIsAdjusting(true);
        try {
            sm.clearSelection();
            for (int i = 0; i < frameModel.getRowCount(); i++) {
                TcpStreamFrame f = frameModel.getFrame(i);
                if (f == null) {
                    continue;
                }
                long seq = f.getSeq();
                for (long s : seqs) {
                    if (s == seq) {
                        sm.addSelectionInterval(i, i);
                        break;
                    }
                }
            }
        } finally {
            sm.setValueIsAdjusting(false);
        }
    }

    private void updateFrameTable(List<TcpStreamFrame> display) {
        long[] selectedSeqs = captureSelectedFrameSeqs();
        frameModel.setFrames(display, currentFrames);
        restoreFrameSelection(selectedSeqs);
        afterFrameTableUpdate(selectedSeqs);
    }

    /**
     * Auto-scroll to latest only when nothing was selected or the selection included the last row
     * (so mid-stream inspection is not yanked away). Otherwise keep selection visible.
     */
    private void afterFrameTableUpdate(long[] previousSelectedSeqs) {
        int rows = frameModel.getRowCount();
        if (rows <= 0) {
            return;
        }
        boolean hadSelection = previousSelectedSeqs != null && previousSelectedSeqs.length > 0;
        boolean selectionStillVisible = frameTable.getSelectedRowCount() > 0;
        boolean lastWasSelected = false;
        if (hadSelection) {
            TcpStreamFrame last = frameModel.getFrame(rows - 1);
            if (last != null) {
                long lastSeq = last.getSeq();
                for (long s : previousSelectedSeqs) {
                    if (s == lastSeq) {
                        lastWasSelected = true;
                        break;
                    }
                }
            }
        }
        if (autoScrollFrames.isSelected() && (!hadSelection || lastWasSelected || !selectionStillVisible)) {
            maybeScrollFramesToBottom();
        } else if (selectionStillVisible) {
            int first = frameTable.getSelectedRow();
            if (first >= 0) {
                frameTable.scrollRectToVisible(frameTable.getCellRect(first, 0, true));
            }
        }
    }

    /**
     * Fast content match. Does <b>not</b> call {@link TcpStreamFrame#getSummary()} (that would
     * force a full TDS unpack on every uncached frame and freeze the UI).
     */
    private static boolean frameContains(TcpStreamFrame f, String q, boolean utf16, boolean raw) {
        if (f == null || q == null || q.isEmpty()) {
            return false;
        }
        String qLower = q.toLowerCase(Locale.ROOT);
        // Cached summary only — never trigger lazy TDS oneLineSummary during search
        String cached = f.getCachedSummary();
        if (cached != null && !cached.isEmpty()
                && cached.toLowerCase(Locale.ROOT).contains(qLower)) {
            return true;
        }
        String uname = f.getUserName();
        if (uname != null && !uname.isEmpty() && uname.toLowerCase(Locale.ROOT).contains(qLower)) {
            return true;
        }
        byte[] body = f.bodyRef();
        if (body == null || body.length == 0) {
            return false;
        }
        // Cap body scan — SQL text almost always sits near the start of TDS PDUs
        final int maxScan = Math.min(body.length, 256 * 1024);
        if (utf16) {
            byte[] needle = q.getBytes(java.nio.charset.StandardCharsets.UTF_16LE);
            if (indexOfBytes(body, maxScan, needle) >= 0) {
                return true;
            }
            // Also try lowercase / uppercase ASCII variants for UTF-16LE SQL
            if (!q.equals(qLower)) {
                byte[] needleLo = qLower.getBytes(java.nio.charset.StandardCharsets.UTF_16LE);
                if (indexOfBytes(body, maxScan, needleLo) >= 0) {
                    return true;
                }
            }
            String qUp = q.toUpperCase(Locale.ROOT);
            if (!q.equals(qUp) && !qLower.equals(qUp)) {
                byte[] needleUp = qUp.getBytes(java.nio.charset.StandardCharsets.UTF_16LE);
                if (indexOfBytes(body, maxScan, needleUp) >= 0) {
                    return true;
                }
            }
        }
        if (raw) {
            byte[] needle = q.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
            if (indexOfBytes(body, maxScan, needle) >= 0) {
                return true;
            }
            if (!q.equals(qLower)) {
                byte[] needleLo = qLower.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
                if (indexOfBytes(body, maxScan, needleLo) >= 0) {
                    return true;
                }
            }
        }
        return false;
    }

    /** First-byte-filtered byte search over hay[0..scanLen). */
    private static int indexOfBytes(byte[] hay, int scanLen, byte[] needle) {
        if (needle == null || needle.length == 0 || hay == null) {
            return -1;
        }
        int limit = Math.min(scanLen, hay.length);
        if (limit < needle.length) {
            return -1;
        }
        byte first = needle[0];
        int last = limit - needle.length;
        outer:
        for (int i = 0; i <= last; i++) {
            if (hay[i] != first) {
                continue;
            }
            for (int j = 1; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private void showSelectedDetail() {
        int row = frameTable.getSelectedRow();
        TcpStreamFrame frame = frameModel.getFrame(row);
        if (frame == null) {
            detailArea.setText("");
            return;
        }
        try {
            // Merge multi-PDU TDS messages (COLMETADATA + ROW often span frames).
            // Use full stream order (not search-filtered list) so siblings are present.
            String sk = frame.getStreamKey();
            TcpStream stream = sk != null ? store.getStream(sk) : null;
            List<TcpStreamFrame> context = stream != null ? stream.getFrames() : currentFrames;
            if (context == null || context.isEmpty()) {
                context = List.of(frame);
            }
            byte[] body = TdsMessageAssembler.assembleMessageContaining(context, frame);
            JSONObject meta = new JSONObject();
            meta.put("seq", frame.getSeq());
            meta.put("streamKey", frame.getStreamKey());
            meta.put("peer", frame.getPeer());
            meta.put("direction", frame.getDirection().legacyName());
            meta.put("matchReplaced", frame.isMatchReplaced());
            meta.put("highlight", frame.getHighlight());
            meta.put("userName", frame.getUserName());
            meta.put("source", frame.getSource());
            if (body.length != frame.getBodyLength()) {
                meta.put("assembledBytes", body.length);
                meta.put("note", "Multi-packet TDS message assembled for decode ("
                        + frame.getBodyLength() + " B frame → " + body.length + " B message)");
            }
            boolean simple = detailSimple.isSelected();
            detailArea.setText(TdsSimpleView.format(body, meta, simple));
            detailArea.setCaretPosition(0);
        } catch (Exception e) {
            detailArea.setText("Decode error: " + e.getMessage() + "\nhex=" + TdsHelper.toHex(frame.getBody()));
            logging.logToError("[-] Stream detail: " + e.getMessage());
        }
    }

    private void sendSelectedToConvert() {
        int row = frameTable.getSelectedRow();
        TcpStreamFrame frame = frameModel.getFrame(row);
        if (frame == null) {
            return;
        }
        firePropertyChange("dsl.sendToConvert", null, frame.getBody());
    }

    private void sendToReplay(boolean selectionOnly) {
        List<TcpStreamFrame> frames = new ArrayList<>();
        if (selectionOnly) {
            for (int r : frameTable.getSelectedRows()) {
                TcpStreamFrame f = frameModel.getFrame(r);
                if (f != null) {
                    frames.add(f);
                }
            }
        } else {
            frames.addAll(frameModel.getAllFrames());
        }
        if (frames.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No frames to send.", "TCP Streams",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        firePropertyChange("dsl.sendToReplay", null, frames);
    }

    private class StreamRowRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (row >= 0 && row < streamKeys.size()) {
                String key = streamKeys.get(row);
                TcpStream s = store.getStream(key);
                String lastKey = store.getLastUpdatedStreamKey();
                boolean lastUpdated = lastKey != null && lastKey.equals(key);
                if (s != null && c instanceof JComponent jc) {
                    String tip = s.getConnectionLabel();
                    if (lastUpdated) {
                        tip = tip + "  · last updated";
                    }
                    jc.setToolTipText(tip);
                }
                if (!isSelected) {
                    Color userHl = s != null ? HighlightColors.background(s.getHighlight()) : null;
                    if (userHl != null) {
                        c.setBackground(userHl);
                    } else if (lastUpdated) {
                        c.setBackground(LAST_UPDATED_STREAM_BG);
                    } else if (isStreamLive(key)) {
                        c.setBackground(LIVE_STREAM_BG);
                    } else {
                        c.setBackground(table.getBackground());
                    }
                }
            }
            return c;
        }
    }

    private class StreamTableModel extends AbstractTableModel {
        /** # · Name · Frames · Time (UTC) — connection endpoint via tooltip / rename dialog */
        private final String[] cols = {"#", "Name", "Frames", "Time (UTC)"};
        private List<TcpStream> streams = List.of();

        void setStreams(List<TcpStream> list) {
            streams = list != null ? list : List.of();
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return streams.size();
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
            return switch (columnIndex) {
                case 0, 2 -> Integer.class;
                default -> String.class;
            };
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            TcpStream s = streams.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> rowIndex + 1; // sequential ID in current list order
                case 1 -> {
                    // User-assigned label only (right-click → Rename). Empty until set.
                    String n = s.getUserName();
                    yield n.isEmpty() ? "" : n;
                }
                case 2 -> s.getFrameCount();
                case 3 -> formatUtcInstant(s.getFirstTimestamp());
                default -> "";
            };
        }
    }

    private static class FrameTableModel extends AbstractTableModel {
        private final String[] cols = {"#", "Dir", "Date", "Time (UTC)", "Bytes", "Mod", "HL", "Summary"};
        private List<TcpStreamFrame> frames = new ArrayList<>();
        /** Per-stream 1-based index by global seq (not capture-global numbering). */
        private java.util.Map<Long, Integer> localBySeq = java.util.Map.of();

        void setFrames(List<TcpStreamFrame> display, List<TcpStreamFrame> streamOrder) {
            frames = display != null ? display : List.of();
            java.util.HashMap<Long, Integer> map = new java.util.HashMap<>();
            List<TcpStreamFrame> order = streamOrder != null && !streamOrder.isEmpty()
                    ? streamOrder : frames;
            for (int i = 0; i < order.size(); i++) {
                TcpStreamFrame f = order.get(i);
                if (f != null) {
                    map.put(f.getSeq(), i + 1);
                }
            }
            localBySeq = map;
            fireTableDataChanged();
        }

        TcpStreamFrame getFrame(int row) {
            if (row < 0 || row >= frames.size()) {
                return null;
            }
            return frames.get(row);
        }

        List<TcpStreamFrame> getAllFrames() {
            return frames;
        }

        @Override
        public int getRowCount() {
            return frames.size();
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
        public Object getValueAt(int rowIndex, int columnIndex) {
            TcpStreamFrame f = frames.get(rowIndex);
            Instant ts = f.getTimestamp();
            return switch (columnIndex) {
                case 0 -> localBySeq.getOrDefault(f.getSeq(), rowIndex + 1);
                case 1 -> f.getDirection().shortLabel();
                case 2 -> ts != null ? DATE_UTC_FMT.format(ts) : "";
                case 3 -> ts != null ? TIME_UTC_12_FMT.format(ts) : "";
                case 4 -> f.getBodyLength();
                case 5 -> f.isMatchReplaced() ? "★" : "";
                case 6 -> HighlightColors.hasHighlight(f.getHighlight())
                        ? HighlightColors.displayName(f.getHighlight()) : "";
                case 7 -> f.getListSummary();
                default -> "";
            };
        }
    }

    private static class FrameRowRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component comp = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected && table.getModel() instanceof FrameTableModel) {
                TcpStreamFrame f = ((FrameTableModel) table.getModel()).getFrame(row);
                Color userHl = f != null ? HighlightColors.background(f.getHighlight()) : null;
                if (userHl != null) {
                    comp.setBackground(userHl);
                } else if (f != null && f.isMatchReplaced()) {
                    comp.setBackground(new Color(255, 200, 230));
                } else if (f != null && f.getDirection() == TcpStreamFrame.Direction.CLIENT_TO_SERVER) {
                    comp.setBackground(new Color(220, 245, 255));
                } else {
                    comp.setBackground(new Color(235, 255, 235));
                }
            }
            return comp;
        }
    }
}
