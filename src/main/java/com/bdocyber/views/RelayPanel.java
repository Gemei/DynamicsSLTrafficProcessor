package com.bdocyber.views;

import burp.api.montoya.logging.Logging;
import com.bdocyber.helpers.UndoSupport;
import com.bdocyber.relay.TcpRelayService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Dedicated suite tab: start/stop the built-in TCP relay and hosts-file instructions.
 */
public class RelayPanel extends JPanel {

    private final Logging logging;
    private final TcpRelayService relay;
    private final List<Consumer<Void>> changeListeners = new ArrayList<>();

    private final JTextField listenHostField = new JTextField("0.0.0.0", 12);
    private final JTextField listenPortField = new JTextField("1433", 6);
    private final JTextField targetHostField = new JTextField("192.0.2.1", 14);
    private final JTextField targetPortField = new JTextField("1433", 6);
    private final JButton startRelayBtn = new JButton("Start relay");
    private final JButton stopRelayBtn = new JButton("Stop relay");
    private final JLabel relayStatus = new JLabel(" ");

    public RelayPanel(Logging logging, TcpRelayService relay) {
        super(new BorderLayout(12, 12));
        setBorder(new EmptyBorder(12, 12, 12, 12));
        this.logging = logging;
        this.relay = relay;

        listenPortField.setToolTipText("Local listen port (no commas). Desktop apps usually need 1433.");
        targetPortField.setToolTipText("Real SQL Server port (no commas), e.g. 1433");

        JTextArea hostsNote = new JTextArea(
                "IMPORTANT — update your hosts file\n"
                        + "\n"
                        + "Desktop apps almost always connect to a SQL hostname on a fixed port (1433).\n"
                        + "They will not use a different listen port. You must trick the app so that\n"
                        + "hostname resolves to this machine (127.0.0.1), while the relay forwards to\n"
                        + "the real server IP.\n"
                        + "\n"
                        + "1. Edit (as Administrator):\n"
                        + "     C:\\Windows\\System32\\drivers\\etc\\hosts\n"
                        + "\n"
                        + "2. Add a line (use the hostname from the app / connection string, NOT the real IP):\n"
                        + "     127.0.0.1    your-sql-hostname\n"
                        + "\n"
                        + "3. Relay settings below are typically:\n"
                        + "     Listen  0.0.0.0 : 1433\n"
                        + "     Target  <real-sql-ip> : 1433\n"
                        + "\n"
                        + "4. Free local port 1433 if something else (e.g. local SQL Server) already owns it.\n"
                        + "\n"
                        + "5. Start relay, then launch Dynamics. Traffic: App → 127.0.0.1:1433 → extension → real IP:1433.\n"
                        + "\n"
                        + "Do NOT set Target to 127.0.0.1 when Listen port is also 1433 (that loops onto the relay).\n"
                        + "View captured frames under the TCP Streams tab. Extender → Output shows [DSL relay] logs."
        );
        hostsNote.setEditable(false);
        hostsNote.setOpaque(true);
        hostsNote.setBackground(new Color(255, 248, 220));
        hostsNote.setBorder(BorderFactory.createCompoundBorder(
                new TitledBorder("Hosts file (required for desktop apps)"),
                new EmptyBorder(8, 8, 8, 8)));
        hostsNote.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        hostsNote.setLineWrap(true);
        hostsNote.setWrapStyleWord(true);

        JPanel controls = new JPanel(new GridBagLayout());
        controls.setBorder(new TitledBorder("TCP relay"));
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(4, 6, 4, 6);
        gc.anchor = GridBagConstraints.WEST;
        gc.gridy = 0;

        gc.gridx = 0;
        controls.add(new JLabel("Listen"), gc);
        gc.gridx = 1;
        controls.add(listenHostField, gc);
        gc.gridx = 2;
        controls.add(new JLabel(":"), gc);
        gc.gridx = 3;
        controls.add(listenPortField, gc);

        gc.gridx = 4;
        controls.add(new JLabel("  →  Target"), gc);
        gc.gridx = 5;
        controls.add(targetHostField, gc);
        gc.gridx = 6;
        controls.add(new JLabel(":"), gc);
        gc.gridx = 7;
        controls.add(targetPortField, gc);

        gc.gridx = 8;
        controls.add(startRelayBtn, gc);
        gc.gridx = 9;
        controls.add(stopRelayBtn, gc);
        stopRelayBtn.setEnabled(false);

        gc.gridy = 1;
        gc.gridx = 0;
        gc.gridwidth = 10;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.weightx = 1;
        relayStatus.setText("Relay stopped.");
        controls.add(relayStatus, gc);

        JPanel center = new JPanel(new BorderLayout(8, 8));
        center.add(controls, BorderLayout.NORTH);

        add(new JScrollPane(hostsNote), BorderLayout.CENTER);
        add(center, BorderLayout.SOUTH);

        startRelayBtn.addActionListener(e -> startRelay());
        stopRelayBtn.addActionListener(e -> stopRelay());
        relay.addStatusListener(r -> {
            if (SwingUtilities.isEventDispatchThread()) {
                updateRelayStatus();
            } else {
                SwingUtilities.invokeLater(this::updateRelayStatus);
            }
        });
        updateRelayStatus();
        UndoSupport.enable(listenHostField);
        UndoSupport.enable(listenPortField);
        UndoSupport.enable(targetHostField);
        UndoSupport.enable(targetPortField);
        DocumentListener dl = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                fireChanged();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                fireChanged();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                fireChanged();
            }
        };
        listenHostField.getDocument().addDocumentListener(dl);
        listenPortField.getDocument().addDocumentListener(dl);
        targetHostField.getDocument().addDocumentListener(dl);
        targetPortField.getDocument().addDocumentListener(dl);
    }

    public void addChangeListener(Consumer<Void> listener) {
        if (listener != null) {
            changeListeners.add(listener);
        }
    }

    private void fireChanged() {
        for (Consumer<Void> l : changeListeners) {
            try {
                l.accept(null);
            } catch (Exception ignored) {
            }
        }
    }

    public void applySettings(String listenHost, int listenPort, String targetHost, int targetPort) {
        if (relay.isRunning()) {
            return;
        }
        if (listenHost != null && !listenHost.isBlank()) {
            listenHostField.setText(listenHost.trim());
        }
        listenPortField.setText(String.valueOf(listenPort > 0 ? listenPort : 1433));
        if (targetHost != null) {
            targetHostField.setText(targetHost.trim());
        }
        targetPortField.setText(String.valueOf(targetPort > 0 ? targetPort : 1433));
    }

    public String getListenHost() {
        return listenHostField.getText().trim();
    }

    public int getListenPort() {
        try {
            return parsePort(listenPortField.getText(), "Listen port");
        } catch (Exception e) {
            return 1433;
        }
    }

    public String getTargetHost() {
        return targetHostField.getText().trim();
    }

    public int getTargetPort() {
        try {
            return parsePort(targetPortField.getText(), "Target port");
        } catch (Exception e) {
            return 1433;
        }
    }

    private void startRelay() {
        try {
            int listenPort = parsePort(listenPortField.getText(), "Listen port");
            int targetPort = parsePort(targetPortField.getText(), "Target port");
            relay.configure(
                    listenHostField.getText().trim(),
                    listenPort,
                    targetHostField.getText().trim(),
                    targetPort);
            relay.start();
            startRelayBtn.setEnabled(false);
            stopRelayBtn.setEnabled(true);
            setRelayFieldsEnabled(false);
            updateRelayStatus();

            String hostsHint = (listenPort == targetPort)
                    ? "Same-port mode: ensure hosts maps the app SQL hostname to 127.0.0.1\n"
                    + "and Target is the real SQL IP (" + targetHostField.getText().trim() + ").\n\n"
                    : "Client must use this machine on port " + listenPort + ".\n\n";

            JOptionPane.showMessageDialog(this,
                    "Relay started (fast transparent mode unless Match/Replace rules are ON).\n\n"
                            + "Listen " + listenHostField.getText().trim() + ":" + listenPort + "\n"
                            + "→ Target " + targetHostField.getText().trim() + ":" + targetPort + "\n\n"
                            + hostsHint
                            + "Hosts file: 127.0.0.1  <sql-hostname-from-app>\n"
                            + "TCP Streams shows captured TDS frames.",
                    "DSL Relay",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            logging.logToError("[-] Start relay: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "Failed to start relay:\n" + ex.getMessage(),
                    "DSL Relay", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void stopRelay() {
        relay.stop();
        startRelayBtn.setEnabled(true);
        stopRelayBtn.setEnabled(false);
        setRelayFieldsEnabled(true);
        updateRelayStatus();
    }

    private void setRelayFieldsEnabled(boolean on) {
        listenHostField.setEnabled(on);
        listenPortField.setEnabled(on);
        targetHostField.setEnabled(on);
        targetPortField.setEnabled(on);
    }

    private void updateRelayStatus() {
        if (relay.isRunning()) {
            String samePort = relay.getListenPort() == relay.getTargetPort()
                    ? "  |  same-port: hosts → 127.0.0.1, Target = real IP"
                    : "  |  client port " + relay.getListenPort();
            relayStatus.setText(String.format(
                    "Relay RUNNING  %s:%d → %s:%d  |  conns=%d  frames=%d  C→S=%d B  S→C=%d B%s",
                    relay.getListenHost(), relay.getListenPort(),
                    relay.getTargetHost(), relay.getTargetPort(),
                    relay.getActiveConnections(), relay.getFramesForwarded(),
                    relay.getBytesClientToServer(), relay.getBytesServerToClient(),
                    samePort));
        } else {
            relayStatus.setText(
                    "Relay stopped. Update hosts (hostname → 127.0.0.1), then Listen 0.0.0.0:1433 → real-sql-ip:1433.");
        }
    }

    static int parsePort(String text, String label) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException(label + " is empty");
        }
        String cleaned = text.trim().replace(",", "").replace(" ", "");
        try {
            int p = Integer.parseInt(cleaned);
            if (p < 1 || p > 65535) {
                throw new IllegalArgumentException(label + " must be 1–65535 (got " + p + ")");
            }
            return p;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(label + " must be a number (got \"" + text + "\")");
        }
    }
}
