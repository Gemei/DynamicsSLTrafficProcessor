package com.bdocyber.views;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.RawEditor;
import com.bdocyber.helpers.DslProjectPersistence;
import com.bdocyber.helpers.InterceptEngine;
import com.bdocyber.helpers.MatchReplaceEngine;
import com.bdocyber.helpers.TdsHelper;
import com.bdocyber.helpers.TdsSimpleView;
import com.bdocyber.helpers.TcpStreamStore;
import com.bdocyber.models.TcpStreamFrame;
import com.bdocyber.relay.TcpRelayService;
import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Suite tab: Relay, Intercept, TCP Streams, Stream Replay, Match/Replace, Convert.
 */
public class DSLView extends JComponent {

    private final Logging logging;
    private final TdsHelper tdsHelper;
    private final JTabbedPane tabs;
    private final StreamReplayPanel streamPanel;
    private final TcpStreamsPanel tcpStreamsPanel;
    private final InterceptPanel interceptPanel;
    private final MatchReplacePanel matchReplacePanel;
    private final RelayPanel relayPanel;
    private final MatchReplaceEngine matchReplaceEngine;
    private final InterceptEngine interceptEngine;
    private final TcpStreamStore streamStore;

    private RawEditor editor;
    private RawEditor results;
    private JComboBox<String> dropDownMenu;
    private JCheckBox convertSimple = new JCheckBox("Simple view", true);

    private static final int DESERIALIZE_IDX = 0;
    /** Tab order: Relay, Intercept, TCP Streams, Stream Replay, Match/Replace, Convert */
    private static final int TAB_INTERCEPT = 1;
    private static final int TAB_REPLAY = 3;
    private static final int TAB_CONVERT = 5;

    public DSLView(MontoyaApi montoyaApi, MatchReplaceEngine matchReplaceEngine,
                   InterceptEngine interceptEngine,
                   TcpStreamStore streamStore, TcpRelayService relayService,
                   DslProjectPersistence projectPersistence,
                   DslProjectPersistence.Snapshot loaded) {
        setLayout(new BorderLayout(10, 10));
        this.logging = montoyaApi.logging();
        this.tdsHelper = new TdsHelper(montoyaApi);
        this.matchReplaceEngine = matchReplaceEngine;
        this.interceptEngine = interceptEngine;
        this.streamStore = streamStore;
        this.tabs = new JTabbedPane();
        this.streamPanel = new StreamReplayPanel(montoyaApi);
        this.streamPanel.setRelayContext(relayService, streamStore);
        this.tcpStreamsPanel = new TcpStreamsPanel(montoyaApi, streamStore);
        this.tcpStreamsPanel.setRelayService(relayService);
        this.interceptPanel = new InterceptPanel(this.logging, interceptEngine);
        this.matchReplacePanel = new MatchReplacePanel(matchReplaceEngine);
        this.relayPanel = new RelayPanel(this.logging, relayService);

        tabs.addTab("Relay", relayPanel);
        tabs.addTab("Intercept", interceptPanel);
        tabs.addTab("TCP Streams", tcpStreamsPanel);
        tabs.addTab("Stream Replay", streamPanel);
        tabs.addTab("Match / Replace", matchReplacePanel);
        tabs.addTab("Convert", buildConvertPanel(montoyaApi));
        add(tabs, BorderLayout.CENTER);

        if (loaded != null && loaded.relayLoaded) {
            relayPanel.applySettings(loaded.listenHost, loaded.listenPort,
                    loaded.targetHost, loaded.targetPort);
        }
        if (loaded != null && loaded.loaded) {
            if (loaded.replayTabs != null && !loaded.replayTabs.isEmpty()) {
                streamPanel.setTabs(loaded.replayTabs, loaded.replaySelectedTab);
            } else if (loaded.replaySteps != null && !loaded.replaySteps.isEmpty()) {
                streamPanel.setSteps(loaded.replaySteps);
            }
        }

        tcpStreamsPanel.addPropertyChangeListener("dsl.sendToConvert", evt -> {
            Object v = evt.getNewValue();
            if (v instanceof byte[]) {
                setEditorText(ByteArray.byteArray((byte[]) v));
            }
        });
        tcpStreamsPanel.addPropertyChangeListener("dsl.sendToReplay", evt -> {
            Object v = evt.getNewValue();
            if (v instanceof List<?> list) {
                @SuppressWarnings("unchecked")
                List<TcpStreamFrame> frames = (List<TcpStreamFrame>) list;
                streamPanel.addTcpFrames(frames);
                tabs.setSelectedIndex(TAB_REPLAY);
            }
        });
        interceptPanel.addPropertyChangeListener("dsl.showIntercept", evt ->
                tabs.setSelectedIndex(TAB_INTERCEPT));

        if (projectPersistence != null) {
            projectPersistence.setSnapshotSupplier(this::buildSnapshot);
            Runnable save = projectPersistence::scheduleSave;
            relayPanel.addChangeListener(v -> save.run());
            interceptPanel.setChangeListener(v -> save.run());
            matchReplacePanel.setChangeListener(v -> save.run());
            streamPanel.setChangeListener(v -> save.run());
            streamStore.addListener(s -> projectPersistence.scheduleSave());
        }
    }

    public DslProjectPersistence.Snapshot buildSnapshot() {
        DslProjectPersistence.Snapshot s = new DslProjectPersistence.Snapshot();
        s.matchReplaceEnabled = matchReplaceEngine.isEnabled();
        s.matchReplaceRules = matchReplaceEngine.getRules();
        s.interceptEnabled = interceptEngine.isEnabled();
        s.interceptTimeoutSec = interceptEngine.getTimeoutSeconds();
        s.interceptRules = interceptEngine.getRules();
        s.listenHost = relayPanel.getListenHost();
        s.listenPort = relayPanel.getListenPort();
        s.targetHost = relayPanel.getTargetHost();
        s.targetPort = relayPanel.getTargetPort();
        s.relayLoaded = true;
        s.streamFrames = streamStore.getAllFrames();
        s.streamHighlights = streamStore.getStreamHighlights();
        s.streamNames = streamStore.getStreamNames();
        s.replayTabs = streamPanel.getTabsSnapshot();
        s.replaySelectedTab = streamPanel.getSelectedTabIndex();
        s.replaySteps = streamPanel.getAllSteps();
        s.loaded = true;
        return s;
    }

    private JPanel buildConvertPanel(MontoyaApi api) {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        JPanel mainView = new JPanel(new GridLayout(1, 2));
        JPanel buttonView = new JPanel(new FlowLayout(FlowLayout.LEFT));

        this.editor = api.userInterface().createRawEditor();
        this.results = api.userInterface().createRawEditor();
        mainView.add(this.editor.uiComponent());
        mainView.add(this.results.uiComponent());

        JButton convertButton = new JButton("Deserialize");
        convertButton.addActionListener(e -> handleButtonClick());
        buttonView.add(convertButton);

        this.dropDownMenu = new JComboBox<>(new String[]{"TDS->JSON", "JSON->TDS"});
        this.dropDownMenu.addActionListener(e -> {
            int idx = this.dropDownMenu.getSelectedIndex();
            convertButton.setText(idx == DESERIALIZE_IDX ? "Deserialize" : "Serialize");
            convertSimple.setEnabled(idx == DESERIALIZE_IDX);
        });
        buttonView.add(this.dropDownMenu);
        buttonView.add(convertSimple);
        convertSimple.setToolTipText("Off = full technical tokens/collations; On = sql/params/rows only");

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            this.editor.setContents(ByteArray.byteArray(""));
            this.results.setContents(ByteArray.byteArray(""));
        });
        buttonView.add(clearButton);

        panel.add(buttonView, BorderLayout.NORTH);
        panel.add(mainView, BorderLayout.CENTER);
        return panel;
    }

    public void setEditorText(ByteArray text) {
        if (this.editor != null) {
            this.editor.setContents(text);
        }
        this.tabs.setSelectedIndex(TAB_CONVERT);
    }

    public void addToStream(HttpRequest request) {
        this.streamPanel.addRequest(request);
        this.tabs.setSelectedIndex(TAB_REPLAY);
    }

    public void addToStream(List<HttpRequest> requests) {
        this.streamPanel.addRequests(requests);
        this.tabs.setSelectedIndex(TAB_REPLAY);
    }

    private void handleButtonClick() {
        try {
            byte[] input = this.editor.getContents().getBytes();
            if (input == null || input.length == 0) {
                return;
            }
            int mode = this.dropDownMenu.getSelectedIndex();
            if (mode == DESERIALIZE_IDX) {
                byte[] body = extractBody(input);
                String pretty = TdsSimpleView.format(body, null, convertSimple.isSelected());
                this.results.setContents(ByteArray.byteArray(
                        pretty.getBytes(StandardCharsets.UTF_8)));
            } else {
                String text = new String(input, StandardCharsets.UTF_8).trim();
                byte[] body = TdsSimpleView.packEditor(text, extractBody(input), this.tdsHelper);
                String out = "length=" + body.length + "\nhex=" + TdsHelper.toHex(body) + "\n";
                this.results.setContents(ByteArray.byteArray(out.getBytes(StandardCharsets.UTF_8)));
            }
        } catch (Exception e) {
            this.logging.logToError("[-] DSL suite convert: " + e.getMessage());
            this.results.setContents(ByteArray.byteArray(
                    ("Error: " + e.getMessage()).getBytes(StandardCharsets.UTF_8)));
        }
    }

    private byte[] extractBody(byte[] input) {
        String asLatin = new String(input, StandardCharsets.ISO_8859_1);
        int idx = asLatin.indexOf("\r\n\r\n");
        if (idx >= 0 && (asLatin.startsWith("POST ") || asLatin.startsWith("HTTP/"))) {
            return java.util.Arrays.copyOfRange(input, idx + 4, input.length);
        }
        String asUtf = new String(input, StandardCharsets.UTF_8).trim();
        if (asUtf.matches("(?is)^[0-9a-f\\s]+$")
                && asUtf.replaceAll("\\s", "").length() % 2 == 0
                && asUtf.replaceAll("\\s", "").length() >= 16) {
            try {
                return TdsHelper.fromHex(asUtf);
            } catch (Exception ignored) {
            }
        }
        return input;
    }
}
