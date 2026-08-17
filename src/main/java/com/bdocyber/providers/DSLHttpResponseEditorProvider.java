package com.bdocyber.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import com.bdocyber.editors.DSLHttpResponseEditor;

public class DSLHttpResponseEditorProvider implements HttpResponseEditorProvider {

    private final MontoyaApi montoya;

    public DSLHttpResponseEditorProvider(MontoyaApi api) {
        this.montoya = api;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorContext) {
        return new DSLHttpResponseEditor(this.montoya, editorContext.editorMode());
    }
}
