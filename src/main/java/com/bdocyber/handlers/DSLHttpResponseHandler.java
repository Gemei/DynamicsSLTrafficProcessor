package com.bdocyber.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import com.bdocyber.helpers.MatchReplaceEngine;

import java.util.Arrays;

/**
 * Optional Proxy HTTP response path: match/replace on response bodies.
 * Primary capture is the built-in TCP relay.
 */
public class DSLHttpResponseHandler implements ProxyResponseHandler {

    private final Logging logging;
    private final MatchReplaceEngine matchReplace;

    public DSLHttpResponseHandler(MontoyaApi montoyaApi, MatchReplaceEngine matchReplace) {
        this.logging = montoyaApi.logging();
        this.matchReplace = matchReplace;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        try {
            HttpResponse updated = transform(interceptedResponse);
            if (updated == null) {
                return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }
            return ProxyResponseReceivedAction.continueWith(updated, interceptedResponse.annotations());
        } catch (Exception e) {
            logging.logToError("[-] DSL response handler: " + e.getMessage());
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        try {
            HttpResponse updated = transform(interceptedResponse);
            if (updated == null) {
                return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
            }
            return ProxyResponseToBeSentAction.continueWith(updated, interceptedResponse.annotations());
        } catch (Exception e) {
            logging.logToError("[-] DSL response to-be-sent: " + e.getMessage());
            return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
        }
    }

    private HttpResponse transform(InterceptedResponse interceptedResponse) {
        if (!matchReplace.isEnabled() || matchReplace.enabledRuleCount() == 0) {
            return null;
        }
        byte[] body = interceptedResponse.body() != null
                ? interceptedResponse.body().getBytes()
                : new byte[0];
        if (body.length == 0) {
            return null;
        }
        byte[] modified = matchReplace.apply(body, MatchReplaceEngine.Direction.RESPONSE);
        if (Arrays.equals(body, modified)) {
            return null;
        }
        return interceptedResponse.withBody(ByteArray.byteArray(modified));
    }
}
