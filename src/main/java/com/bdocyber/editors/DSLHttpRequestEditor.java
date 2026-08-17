package com.bdocyber.editors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.bdocyber.helpers.DSLConstants;
import com.bdocyber.helpers.TdsHelper;
import com.bdocyber.helpers.TdsSimpleView;
import org.json.JSONException;
import org.json.JSONObject;

import java.awt.*;
import java.nio.charset.StandardCharsets;

/**
 * Request editor tab: TDS binary body ↔ JSON (simple pentester view by default).
 */
public class DSLHttpRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private final RawEditor editor;
    private final TdsHelper tdsHelper;
    private final Logging logging;
    private HttpRequestResponse reqResp;
    private byte[] originalBody = new byte[0];

    public DSLHttpRequestEditor(MontoyaApi api, EditorMode editorMode) {
        this.editor = api.userInterface().createRawEditor();
        this.tdsHelper = new TdsHelper(api);
        this.logging = api.logging();
    }

    @Override
    public HttpRequest getRequest() {
        if (!this.editor.isModified()) {
            return this.reqResp.request();
        }
        try {
            String text = new String(this.editor.getContents().getBytes(), StandardCharsets.UTF_8).trim();
            byte[] newBody = TdsSimpleView.packEditor(text, originalBody, this.tdsHelper);
            return this.reqResp.request().withBody(ByteArray.byteArray(newBody));
        } catch (JSONException e) {
            this.logging.logToError("[-] DSL getRequest JSON error: " + e.getMessage());
            return this.reqResp.request();
        } catch (Exception e) {
            this.logging.logToError("[-] DSL getRequest pack error: " + e.getMessage());
            return this.reqResp.request();
        }
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.reqResp = requestResponse;
        byte[] body = requestResponse.request().body().getBytes();
        this.originalBody = body != null ? body : new byte[0];
        try {
            JSONObject meta = new JSONObject();
            meta.put("direction", "CLIENT_REQUEST");
            meta.put("peer", TdsHelper.extractPeer(requestResponse.request().path()));
            // Default simple — pentesters edit sql/params; put "view":"full" hint via _hint
            String pretty = TdsSimpleView.format(this.originalBody, meta, true);
            this.editor.setContents(ByteArray.byteArray(pretty.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            this.logging.logToError("[-] DSL setRequestResponse: " + e.getMessage());
            this.editor.setContents(ByteArray.byteArray(body));
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            return false;
        }
        HttpRequest request = requestResponse.request();
        byte[] body = request.body() != null ? request.body().getBytes() : new byte[0];
        return this.tdsHelper.looksLikeTds(body);
    }

    @Override
    public String caption() {
        return DSLConstants.CAPTION;
    }

    @Override
    public Component uiComponent() {
        return this.editor.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return this.editor.selection().isPresent() ? this.editor.selection().get() : null;
    }

    @Override
    public boolean isModified() {
        return this.editor.isModified();
    }
}
