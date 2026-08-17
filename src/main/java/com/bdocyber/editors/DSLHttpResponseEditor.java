package com.bdocyber.editors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import com.bdocyber.helpers.DSLConstants;
import com.bdocyber.helpers.TdsHelper;
import com.bdocyber.helpers.TdsSimpleView;
import org.json.JSONObject;

import java.awt.*;
import java.nio.charset.StandardCharsets;

/**
 * Optional HTTP response editor tab when the body looks like TDS.
 */
public class DSLHttpResponseEditor implements ExtensionProvidedHttpResponseEditor {

    private final RawEditor editor;
    private final TdsHelper tdsHelper;
    private final Logging logging;
    private HttpRequestResponse reqResp;
    private byte[] originalBody = new byte[0];

    public DSLHttpResponseEditor(MontoyaApi api, EditorMode editorMode) {
        this.editor = api.userInterface().createRawEditor();
        this.tdsHelper = new TdsHelper(api);
        this.logging = api.logging();
    }

    @Override
    public HttpResponse getResponse() {
        if (!this.editor.isModified() || this.reqResp.response() == null) {
            return this.reqResp.response();
        }
        try {
            String text = new String(this.editor.getContents().getBytes(), StandardCharsets.UTF_8).trim();
            byte[] newBody = TdsSimpleView.packEditor(text, originalBody, this.tdsHelper);
            return this.reqResp.response().withBody(ByteArray.byteArray(newBody));
        } catch (Exception e) {
            this.logging.logToError("[-] DSL getResponse: " + e.getMessage());
            return this.reqResp.response();
        }
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.reqResp = requestResponse;
        if (requestResponse.response() == null) {
            this.editor.setContents(ByteArray.byteArray(""));
            this.originalBody = new byte[0];
            return;
        }
        byte[] body = requestResponse.response().body().getBytes();
        this.originalBody = body != null ? body : new byte[0];
        try {
            JSONObject meta = new JSONObject();
            meta.put("direction", "HTTP_RESPONSE");
            String pretty = TdsSimpleView.format(this.originalBody, meta, true);
            this.editor.setContents(ByteArray.byteArray(pretty.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            this.logging.logToError("[-] DSL setResponse: " + e.getMessage());
            this.editor.setContents(ByteArray.byteArray(body));
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.response() == null) {
            return false;
        }
        byte[] body = requestResponse.response().body() != null
                ? requestResponse.response().body().getBytes()
                : new byte[0];
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
