package com.bdocyber.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import com.bdocyber.helpers.MatchReplaceEngine;
import com.bdocyber.helpers.TdsHelper;

import java.util.Arrays;

/**
 * Optional Proxy HTTP request path: match/replace and highlight TDS-looking bodies.
 * Primary capture is the built-in TCP relay (not HTTP).
 */
public class DSLHttpRequestHandler implements ProxyRequestHandler {

    private final TdsHelper tdsHelper;
    private final Logging logging;
    private final MatchReplaceEngine matchReplace;

    public DSLHttpRequestHandler(MontoyaApi montoyaApi, MatchReplaceEngine matchReplace,
                                 com.bdocyber.helpers.TcpStreamStore streamStore) {
        // streamStore retained in constructor for binary compatibility with DynamicsSLTrafficProcessor
        this.tdsHelper = new TdsHelper(montoyaApi);
        this.logging = montoyaApi.logging();
        this.matchReplace = matchReplace;
        this.matchReplace.setApplyListener((rule, direction, before, after, mode) ->
                this.logging.logToOutput("[DSL match/replace] mode=" + mode + " "
                        + direction + " match=\"" + rule.getMatch() + "\" → \""
                        + (rule.getReplace() == null ? "" : rule.getReplace())
                        + "\" encoding=" + rule.getEncoding()
                        + " body " + before + "→" + after + " bytes"));
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        try {
            Result result = transform(interceptedRequest);
            if (result.modifiedRequest() != null) {
                return ProxyRequestReceivedAction.continueWith(
                        result.modifiedRequest(), interceptedRequest.annotations());
            }
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        } catch (Exception e) {
            this.logging.logToError("[-] DSL request handler: " + e.getMessage());
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        try {
            Result result = transform(interceptedRequest);
            if (result.modifiedRequest() != null) {
                return ProxyRequestToBeSentAction.continueWith(
                        result.modifiedRequest(), interceptedRequest.annotations());
            }
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        } catch (Exception e) {
            this.logging.logToError("[-] DSL request to-be-sent: " + e.getMessage());
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }
    }

    private Result transform(InterceptedRequest interceptedRequest) {
        byte[] body = interceptedRequest.body() != null
                ? interceptedRequest.body().getBytes()
                : new byte[0];

        boolean alreadyMagenta = isHighlight(interceptedRequest, HighlightColor.MAGENTA);
        boolean decodable = body.length > 0 && this.tdsHelper.isSuccessfullyDecoded(body);

        byte[] finalBody = body;
        boolean changed = false;

        if (matchReplace.isEnabled() && matchReplace.enabledRuleCount() > 0 && body.length > 0) {
            byte[] modified = matchReplace.apply(body, MatchReplaceEngine.Direction.REQUEST);
            if (!Arrays.equals(body, modified)) {
                finalBody = modified;
                changed = true;
            }
        }

        if (changed || alreadyMagenta) {
            interceptedRequest.annotations().setHighlightColor(HighlightColor.MAGENTA);
        } else if (decodable) {
            interceptedRequest.annotations().setHighlightColor(HighlightColor.CYAN);
        }

        if (!changed) {
            return new Result(null);
        }
        return new Result(interceptedRequest.withBody(ByteArray.byteArray(finalBody)));
    }

    private static boolean isHighlight(InterceptedRequest req, HighlightColor color) {
        try {
            return req.annotations().highlightColor() == color;
        } catch (Exception e) {
            return false;
        }
    }

    private record Result(HttpRequest modifiedRequest) {
    }
}
