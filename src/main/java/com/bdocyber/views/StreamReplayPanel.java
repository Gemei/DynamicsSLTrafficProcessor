package com.bdocyber.views;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bdocyber.helpers.HighlightColors;
import com.bdocyber.helpers.TcpStreamStore;
import com.bdocyber.models.StreamStep;
import com.bdocyber.models.TcpStreamFrame;
import com.bdocyber.relay.TcpRelayService;

import javax.swing.*;
import javax.swing.plaf.basic.BasicButtonUI;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Stream Replay with Burp Repeater-style tabs: sequential numbers, rename, highlight.
 * Each tab holds an independent step list / live-session inject UI.
 */
public class StreamReplayPanel extends JPanel {

    private final MontoyaApi montoya;
    private final JTabbedPane tabbedPane;
    private final List<TabMeta> tabs = new ArrayList<>();
    private int nextNumber = 1;
    private Consumer<Void> changeListener;
    private TcpRelayService relayService;
    private TcpStreamStore streamStore;

    public StreamReplayPanel(MontoyaApi api) {
        super(new BorderLayout(4, 4));
        this.montoya = api;
        this.tabbedPane = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);
        tabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);

        JButton newTab = new JButton("+");
        newTab.setToolTipText("New tab. Double-click a tab to rename; right-click for highlight/close.");
        newTab.setMargin(new Insets(1, 8, 1, 8));
        newTab.addActionListener(e -> {
            addTab(null, "", HighlightColors.NONE, List.of(), true);
            notifyChanged();
        });
        JPanel tabBar = new JPanel(new BorderLayout(2, 0));
        tabBar.add(newTab, BorderLayout.WEST);
        tabBar.add(tabbedPane, BorderLayout.CENTER);
        add(tabBar, BorderLayout.CENTER);

        addTab(null, "", HighlightColors.NONE, List.of(), false);
    }

    public void setRelayContext(TcpRelayService relay, TcpStreamStore store) {
        this.relayService = relay;
        this.streamStore = store;
        for (TabMeta t : tabs) {
            t.session.setRelayContext(relay, store);
        }
    }

    public void setChangeListener(Consumer<Void> listener) {
        this.changeListener = listener;
        for (TabMeta t : tabs) {
            t.session.setChangeListener(v -> notifyChanged());
        }
    }

    private void notifyChanged() {
        if (changeListener != null) {
            try {
                changeListener.accept(null);
            } catch (Exception ignored) {
            }
        }
    }

    /** Flatten all steps across tabs (legacy single-list consumers). Prefer {@link #getTabsSnapshot()}. */
    public List<StreamStep> getAllSteps() {
        List<StreamStep> all = new ArrayList<>();
        for (TabMeta t : tabs) {
            all.addAll(t.session.getAllSteps());
        }
        return all;
    }

    public List<TabSnapshot> getTabsSnapshot() {
        List<TabSnapshot> out = new ArrayList<>();
        for (TabMeta t : tabs) {
            TabSnapshot s = new TabSnapshot();
            s.number = t.number;
            s.title = t.title != null ? t.title : "";
            s.highlight = t.highlight != null ? t.highlight : "";
            s.steps = t.session.getAllSteps();
            out.add(s);
        }
        return out;
    }

    public int getSelectedTabIndex() {
        return tabbedPane.getSelectedIndex();
    }

    /** Restore multi-tab project state (or empty). */
    public void setTabs(List<TabSnapshot> snapshots, int selectedIndex) {
        SwingUtilities.invokeLater(() -> {
            tabbedPane.removeAll();
            tabs.clear();
            nextNumber = 1;
            if (snapshots == null || snapshots.isEmpty()) {
                addTab(null, "", HighlightColors.NONE, List.of(), false);
            } else {
                int maxNum = 0;
                for (TabSnapshot snap : snapshots) {
                    if (snap == null) {
                        continue;
                    }
                    int num = snap.number > 0 ? snap.number : nextNumber;
                    maxNum = Math.max(maxNum, num);
                    addTab(num, snap.title, snap.highlight, snap.steps, false);
                }
                nextNumber = maxNum + 1;
                if (tabs.isEmpty()) {
                    addTab(null, "", HighlightColors.NONE, List.of(), false);
                }
            }
            if (selectedIndex >= 0 && selectedIndex < tabbedPane.getTabCount()) {
                tabbedPane.setSelectedIndex(selectedIndex);
            }
        });
    }

    /** Legacy: load steps into tab 1 (or create it). */
    public void setSteps(List<StreamStep> steps) {
        SwingUtilities.invokeLater(() -> {
            if (tabs.isEmpty()) {
                addTab(1, "", HighlightColors.NONE, steps, false);
                nextNumber = 2;
            } else {
                // Put restored steps into first tab; clear other empty tabs except keep one
                TabMeta first = tabs.get(0);
                first.session.setSteps(steps);
                // If only legacy single list, leave other tabs alone if multi already loaded
            }
        });
    }

    public void addRequest(HttpRequest request) {
        ensureActiveTab().addRequest(request);
        notifyChanged();
    }

    public void addRequests(List<HttpRequest> requests) {
        ensureActiveTab().addRequests(requests);
        notifyChanged();
    }

    public void addTcpFrames(List<TcpStreamFrame> frames) {
        // New content from TCP Streams → new tab (Repeater-like)
        String title = "";
        if (frames != null && !frames.isEmpty()) {
            String peer = frames.get(0).getPeer();
            if (peer != null && !peer.isEmpty()) {
                title = peer;
            }
        }
        addTab(null, title, HighlightColors.NONE, List.of(), true);
        TabMeta t = tabs.get(tabs.size() - 1);
        t.session.addTcpFrames(frames);
        notifyChanged();
    }

    private ReplaySessionPanel ensureActiveTab() {
        if (tabs.isEmpty()) {
            addTab(null, "", HighlightColors.NONE, List.of(), false);
        }
        int i = tabbedPane.getSelectedIndex();
        if (i < 0) {
            i = 0;
            tabbedPane.setSelectedIndex(0);
        }
        return tabs.get(i).session;
    }

    /**
     * @param number fixed number or null for next sequential
     */
    private void addTab(Integer number, String title, String highlight, List<StreamStep> steps, boolean select) {
        int num = number != null ? number : nextNumber++;
        if (number != null) {
            nextNumber = Math.max(nextNumber, number + 1);
        }
        ReplaySessionPanel session = new ReplaySessionPanel(montoya);
        session.setRelayContext(relayService, streamStore);
        session.setChangeListener(v -> notifyChanged());
        if (steps != null && !steps.isEmpty()) {
            session.setSteps(steps);
        }
        TabMeta meta = new TabMeta(num, title != null ? title : "", HighlightColors.normalize(highlight), session);
        tabs.add(meta);
        tabbedPane.addTab(meta.displayTitle(), session);
        int idx = tabbedPane.getTabCount() - 1;
        tabbedPane.setTabComponentAt(idx, createTabComponent(meta));
        if (select) {
            tabbedPane.setSelectedIndex(idx);
        }
    }

    private JPanel createTabComponent(TabMeta meta) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        p.setOpaque(true);
        applyTabColor(p, meta.highlight);
        JLabel label = new JLabel(meta.displayTitle());
        label.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        p.add(label);
        meta.tabLabel = label;
        meta.tabComponent = p;

        JButton close = new JButton("×");
        close.setFont(close.getFont().deriveFont(Font.BOLD, 12f));
        close.setMargin(new Insets(0, 4, 0, 4));
        close.setBorderPainted(false);
        close.setContentAreaFilled(false);
        close.setFocusable(false);
        close.setToolTipText("Close tab");
        close.setUI(new BasicButtonUI());
        close.addActionListener(e -> closeTab(meta));
        p.add(close);

        MouseAdapter ma = new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                selectTab(meta);
                if (e.isPopupTrigger()) {
                    showTabMenu(meta, e);
                }
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    selectTab(meta);
                    showTabMenu(meta, e);
                }
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                selectTab(meta);
                if (e.getClickCount() == 2 && !e.isPopupTrigger()) {
                    renameTab(meta);
                }
            }
        };
        p.addMouseListener(ma);
        label.addMouseListener(ma);
        return p;
    }

    private void selectTab(TabMeta meta) {
        int idx = tabs.indexOf(meta);
        if (idx >= 0) {
            tabbedPane.setSelectedIndex(idx);
        }
    }

    private void showTabMenu(TabMeta meta, MouseEvent e) {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem rename = new JMenuItem("Rename tab…");
        rename.addActionListener(ev -> renameTab(meta));
        menu.add(rename);
        JMenuItem clearName = new JMenuItem("Clear custom name");
        clearName.addActionListener(ev -> {
            meta.title = "";
            refreshTabTitle(meta);
            notifyChanged();
        });
        menu.add(clearName);
        menu.addSeparator();
        JMenu hl = new JMenu("Highlight tab");
        JMenuItem none = new JMenuItem("None (clear)");
        none.addActionListener(ev -> {
            meta.highlight = HighlightColors.NONE;
            refreshTabTitle(meta);
            notifyChanged();
        });
        hl.add(none);
        hl.addSeparator();
        for (String name : HighlightColors.names()) {
            JMenuItem mi = new JMenuItem(HighlightColors.displayName(name));
            Color bg = HighlightColors.background(name);
            if (bg != null) {
                mi.setBackground(bg);
                mi.setOpaque(true);
            }
            mi.addActionListener(ev -> {
                meta.highlight = name;
                refreshTabTitle(meta);
                notifyChanged();
            });
            hl.add(mi);
        }
        menu.add(hl);
        menu.addSeparator();
        JMenuItem close = new JMenuItem("Close tab");
        close.addActionListener(ev -> closeTab(meta));
        menu.add(close);
        JMenuItem closeOthers = new JMenuItem("Close other tabs");
        closeOthers.addActionListener(ev -> closeOtherTabs(meta));
        menu.add(closeOthers);
        JMenuItem closeAll = new JMenuItem("Close all tabs");
        closeAll.addActionListener(ev -> {
            tabbedPane.removeAll();
            tabs.clear();
            nextNumber = 1;
            addTab(null, "", HighlightColors.NONE, List.of(), false);
            notifyChanged();
        });
        menu.add(closeAll);
        menu.addSeparator();
        JMenuItem newTab = new JMenuItem("New tab");
        newTab.addActionListener(ev -> {
            addTab(null, "", HighlightColors.NONE, List.of(), true);
            notifyChanged();
        });
        menu.add(newTab);
        menu.show(e.getComponent(), e.getX(), e.getY());
    }

    private void renameTab(TabMeta meta) {
        Object result = JOptionPane.showInputDialog(
                this,
                "Name for tab " + meta.number + " (optional).\nLeave empty to show only the number.",
                "Rename Stream Replay tab",
                JOptionPane.PLAIN_MESSAGE,
                null,
                null,
                meta.title != null ? meta.title : "");
        if (result == null) {
            return;
        }
        meta.title = String.valueOf(result).trim();
        refreshTabTitle(meta);
        notifyChanged();
    }

    private void refreshTabTitle(TabMeta meta) {
        if (meta.tabLabel != null) {
            meta.tabLabel.setText(meta.displayTitle());
        }
        if (meta.tabComponent != null) {
            applyTabColor(meta.tabComponent, meta.highlight);
            meta.tabComponent.revalidate();
            meta.tabComponent.repaint();
        }
        int idx = tabs.indexOf(meta);
        if (idx >= 0) {
            tabbedPane.setTitleAt(idx, meta.displayTitle());
        }
    }

    private static void applyTabColor(JComponent comp, String highlight) {
        Color bg = HighlightColors.background(highlight);
        if (bg != null) {
            comp.setBackground(bg);
            comp.setOpaque(true);
        } else {
            comp.setOpaque(false);
            comp.setBackground(null);
        }
    }

    private void closeTab(TabMeta meta) {
        int idx = tabs.indexOf(meta);
        if (idx < 0) {
            return;
        }
        if (tabs.size() == 1) {
            // Keep at least one tab; clear its content
            meta.session.setSteps(List.of());
            meta.title = "";
            meta.highlight = HighlightColors.NONE;
            refreshTabTitle(meta);
            notifyChanged();
            return;
        }
        tabs.remove(idx);
        tabbedPane.remove(idx);
        notifyChanged();
    }

    private void closeOtherTabs(TabMeta keep) {
        List<TabMeta> toClose = new ArrayList<>();
        for (TabMeta t : tabs) {
            if (t != keep) {
                toClose.add(t);
            }
        }
        for (TabMeta t : toClose) {
            int idx = tabs.indexOf(t);
            if (idx >= 0) {
                tabs.remove(idx);
                tabbedPane.remove(idx);
            }
        }
        notifyChanged();
    }

    private static final class TabMeta {
        final int number;
        String title;
        String highlight;
        final ReplaySessionPanel session;
        JLabel tabLabel;
        JPanel tabComponent;

        TabMeta(int number, String title, String highlight, ReplaySessionPanel session) {
            this.number = number;
            this.title = title != null ? title : "";
            this.highlight = highlight != null ? highlight : "";
            this.session = session;
        }

        String displayTitle() {
            if (title == null || title.isEmpty()) {
                return String.valueOf(number);
            }
            return number + ": " + title;
        }
    }

    /** Serializable tab for project persistence. */
    public static final class TabSnapshot {
        public int number;
        public String title = "";
        public String highlight = "";
        public List<StreamStep> steps = new ArrayList<>();
    }
}
