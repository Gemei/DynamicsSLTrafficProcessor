package com.bdocyber.helpers;

import javax.swing.*;
import javax.swing.event.UndoableEditEvent;
import javax.swing.event.UndoableEditListener;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;
import javax.swing.undo.CannotRedoException;
import javax.swing.undo.CannotUndoException;
import javax.swing.undo.UndoManager;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

/**
 * Installs Ctrl+Z / Ctrl+Y (and Ctrl+Shift+Z) undo/redo on Swing text components.
 */
public final class UndoSupport {

    private static final String UNDO_KEY = "dsl-undo";
    private static final String REDO_KEY = "dsl-redo";
    private static final Object MANAGER_KEY = new Object();

    private UndoSupport() {
    }

    /**
     * Enable undo/redo on a single text field or area.
     */
    public static void enable(JTextComponent text) {
        if (text == null) {
            return;
        }
        // Avoid double-install
        if (text.getClientProperty(MANAGER_KEY) instanceof UndoManager) {
            return;
        }

        UndoManager manager = new UndoManager();
        manager.setLimit(200);
        text.putClientProperty(MANAGER_KEY, manager);

        Document doc = text.getDocument();
        doc.addUndoableEditListener(new UndoableEditListener() {
            @Override
            public void undoableEditHappened(UndoableEditEvent e) {
                manager.addEdit(e.getEdit());
            }
        });

        InputMap im = text.getInputMap(JComponent.WHEN_FOCUSED);
        ActionMap am = text.getActionMap();

        int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();

        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, menuMask), UNDO_KEY);
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Y, menuMask), REDO_KEY);
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, menuMask | InputEvent.SHIFT_DOWN_MASK), REDO_KEY);

        am.put(UNDO_KEY, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    if (manager.canUndo()) {
                        manager.undo();
                    }
                } catch (CannotUndoException ignored) {
                }
            }
        });
        am.put(REDO_KEY, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    if (manager.canRedo()) {
                        manager.redo();
                    }
                } catch (CannotRedoException ignored) {
                }
            }
        });
    }

    /**
     * Recursively enable undo on all {@link JTextComponent}s under a container
     * (skips non-editable components by default).
     */
    public static void enableTree(Container root) {
        enableTree(root, false);
    }

    /**
     * @param includeReadOnly if true, also attach to non-editable areas (usually unnecessary)
     */
    public static void enableTree(Container root, boolean includeReadOnly) {
        if (root == null) {
            return;
        }
        if (root instanceof JTextComponent text) {
            if (includeReadOnly || text.isEditable()) {
                enable(text);
            }
        }
        for (Component child : root.getComponents()) {
            if (child instanceof Container c) {
                enableTree(c, includeReadOnly);
            }
        }
    }

    /**
     * Table cell editor with Ctrl+Z support for free-text columns.
     */
    public static DefaultCellEditor textCellEditor() {
        JTextField field = new JTextField();
        enable(field);
        DefaultCellEditor editor = new DefaultCellEditor(field);
        editor.setClickCountToStart(1);
        return editor;
    }
}
