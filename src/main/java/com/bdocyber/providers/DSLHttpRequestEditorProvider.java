package com.bdocyber.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import com.bdocyber.editors.DSLHttpRequestEditor;

public class DSLHttpRequestEditorProvider implements HttpRequestEditorProvider {

    private final MontoyaApi montoya;

    public DSLHttpRequestEditorProvider(MontoyaApi api) {
        this.montoya = api;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorContext) {
        return new DSLHttpRequestEditor(this.montoya, editorContext.editorMode());
    }
}
