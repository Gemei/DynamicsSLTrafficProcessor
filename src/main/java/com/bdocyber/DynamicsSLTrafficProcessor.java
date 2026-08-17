package com.bdocyber;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;
import com.bdocyber.handlers.DSLHttpRequestHandler;
import com.bdocyber.handlers.DSLHttpResponseHandler;
import com.bdocyber.helpers.DSLConstants;
import com.bdocyber.helpers.DslProjectPersistence;
import com.bdocyber.helpers.InterceptEngine;
import com.bdocyber.helpers.MatchReplaceEngine;
import com.bdocyber.helpers.TcpStreamStore;
import com.bdocyber.providers.DSLContextMenuItemsProvider;
import com.bdocyber.providers.DSLHttpRequestEditorProvider;
import com.bdocyber.providers.DSLHttpResponseEditorProvider;
import com.bdocyber.relay.TcpRelayService;
import com.bdocyber.views.DSLView;

/**
 * Burp extension for Microsoft Dynamics SL / TDS traffic.
 * Primary capture path: built-in TCP relay for Dynamics SL TDS traffic.
 * Project state (rules, relay config, streams, replay) is stored via
 * {@link burp.api.montoya.persistence.Persistence#extensionData()}.
 */
public class DynamicsSLTrafficProcessor implements BurpExtension, ExtensionUnloadingHandler {

    private MontoyaApi montoya;
    private Logging logging;
    private MatchReplaceEngine matchReplaceEngine;
    private InterceptEngine interceptEngine;
    private TcpStreamStore streamStore;
    private TcpRelayService relayService;
    private DslProjectPersistence projectPersistence;
    private DSLView suiteTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.montoya = api;
        this.montoya.extension().setName(DSLConstants.EXTENSION_NAME);
        this.logging = this.montoya.logging();
        this.matchReplaceEngine = new MatchReplaceEngine();
        this.interceptEngine = new InterceptEngine();
        this.streamStore = new TcpStreamStore();
        this.projectPersistence = new DslProjectPersistence(
                this.montoya.persistence(), this.logging);

        // Load project-scoped state before UI so panels pick up restored rules
        DslProjectPersistence.Snapshot loaded = this.projectPersistence.load();
        this.projectPersistence.applyToEngines(
                loaded, this.matchReplaceEngine, this.interceptEngine, this.streamStore);

        this.relayService = new TcpRelayService(
                this.matchReplaceEngine,
                this.interceptEngine,
                this.streamStore,
                new TcpRelayService.LogSink() {
                    @Override
                    public void info(String msg) {
                        safeLogOutput(msg);
                    }

                    @Override
                    public void error(String msg) {
                        safeLogError(msg);
                    }
                });

        DSLHttpRequestEditorProvider requestEditorProvider = new DSLHttpRequestEditorProvider(this.montoya);
        DSLHttpResponseEditorProvider responseEditorProvider = new DSLHttpResponseEditorProvider(this.montoya);
        this.montoya.userInterface().registerHttpRequestEditorProvider(requestEditorProvider);
        this.montoya.userInterface().registerHttpResponseEditorProvider(responseEditorProvider);

        DSLHttpRequestHandler requestHandler = new DSLHttpRequestHandler(
                this.montoya, this.matchReplaceEngine, this.streamStore);
        DSLHttpResponseHandler responseHandler = new DSLHttpResponseHandler(this.montoya, this.matchReplaceEngine);
        this.montoya.proxy().registerRequestHandler(requestHandler);
        this.montoya.proxy().registerResponseHandler(responseHandler);

        this.suiteTab = new DSLView(
                this.montoya, this.matchReplaceEngine, this.interceptEngine,
                this.streamStore, this.relayService, this.projectPersistence, loaded);
        this.montoya.userInterface().registerSuiteTab(DSLConstants.CAPTION, this.suiteTab);

        DSLContextMenuItemsProvider menuItemsProvider = new DSLContextMenuItemsProvider(this.montoya, this.suiteTab);
        this.montoya.userInterface().registerContextMenuItemsProvider(menuItemsProvider);

        this.montoya.extension().registerUnloadingHandler(this);
        this.logging.logToOutput(DSLConstants.LOADED_LOG_MSG);
        this.logging.logToOutput("[*] Primary: DSL → Relay (hosts → 127.0.0.1, :1433 → real SQL).");
        this.logging.logToOutput("[*] Tabs: Relay | Intercept | TCP Streams | Stream Replay | Match/Replace | Convert");
        this.logging.logToOutput("[*] Project persistence: rules, relay settings, TCP streams, stream replay (Burp project file).");
    }

    @Override
    public void extensionUnloaded() {
        try {
            if (this.projectPersistence != null) {
                this.projectPersistence.saveNow();
            }
        } catch (Throwable ignored) {
        }
        try {
            if (this.relayService != null) {
                this.relayService.stop();
            }
        } catch (Throwable ignored) {
        }
        safeLogOutput(DSLConstants.UNLOADED_LOG_MSG);
    }

    private void safeLogOutput(String msg) {
        try {
            if (logging != null && msg != null) {
                logging.logToOutput(msg);
            }
        } catch (Throwable ignored) {
            // Burp Logging can be null/torn down during unload
        }
    }

    private void safeLogError(String msg) {
        try {
            if (logging != null && msg != null) {
                logging.logToError(msg);
            }
        } catch (Throwable ignored) {
            // Burp Logging can be null/torn down during unload
        }
    }
}
