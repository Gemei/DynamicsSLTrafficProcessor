package com.bdocyber.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.bdocyber.helpers.DSLConstants;
import com.bdocyber.views.DSLView;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class DSLContextMenuItemsProvider implements ContextMenuItemsProvider {

    private final MontoyaApi montoya;
    private final DSLView dslView;

    public DSLContextMenuItemsProvider(MontoyaApi api, DSLView view) {
        this.montoya = api;
        this.dslView = view;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        JMenuItem sendToDsl = new JMenuItem(DSLConstants.SEND_TO_DSL_CAPTION);
        sendToDsl.addActionListener(e -> {
            try {
                HttpRequestResponse rr = firstRequestResponse(event);
                if (rr != null && rr.request() != null) {
                    byte[] body = rr.request().body().getBytes();
                    this.dslView.setEditorText(ByteArray.byteArray(body));
                }
            } catch (Exception ex) {
                this.montoya.logging().logToError("[-] Send to DSL: " + ex.getMessage());
            }
        });
        items.add(sendToDsl);

        JMenuItem sendToStream = new JMenuItem(DSLConstants.SEND_TO_STREAM_CAPTION);
        sendToStream.addActionListener(e -> {
            try {
                List<HttpRequest> requests = collectRequests(event);
                if (!requests.isEmpty()) {
                    this.dslView.addToStream(requests);
                }
            } catch (Exception ex) {
                this.montoya.logging().logToError("[-] Send to stream: " + ex.getMessage());
            }
        });
        items.add(sendToStream);

        return items;
    }

    private HttpRequestResponse firstRequestResponse(ContextMenuEvent event) {
        if (event.selectedRequestResponses() != null && !event.selectedRequestResponses().isEmpty()) {
            return event.selectedRequestResponses().get(0);
        }
        if (event.messageEditorRequestResponse().isPresent()) {
            return event.messageEditorRequestResponse().get().requestResponse();
        }
        return null;
    }

    private List<HttpRequest> collectRequests(ContextMenuEvent event) {
        List<HttpRequest> out = new ArrayList<>();
        if (event.selectedRequestResponses() != null) {
            for (HttpRequestResponse rr : event.selectedRequestResponses()) {
                if (rr != null && rr.request() != null) {
                    out.add(rr.request());
                }
            }
        }
        if (out.isEmpty() && event.messageEditorRequestResponse().isPresent()) {
            HttpRequestResponse rr = event.messageEditorRequestResponse().get().requestResponse();
            if (rr != null && rr.request() != null) {
                out.add(rr.request());
            }
        }
        return out;
    }
}
