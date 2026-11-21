package com.sessionshare.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.RequestAction;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import com.sessionshare.follower.TokenInjector;
import com.sessionshare.follower.TokenPoller;
import com.sessionshare.leader.TokenCaptureHandler;
import com.sessionshare.model.TokenStore;
import com.sessionshare.session.SessionHttpHandler;
import com.sessionshare.session.SessionManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@Isolated("Temporarily supplies Montoya's static request action factory")
class ForwardingOnlyTest {
    @Test void nativeForwardingLeavesTheOriginalRequestUntouchedInAllThreeHandlers() {
        MontoyaApi api = UpstreamProxyRulesTest.emptyProjectApi();
        UpstreamProxyRules.apply(api, "*", "laptop.test", 8080);
        TokenStore store = new TokenStore();
        List<HttpHandler> handlers = List.of(
                new TokenCaptureHandler(api, store),
                new TokenInjector(api, store, new TokenPoller(api, store)),
                new SessionHttpHandler(api, store, new SessionManager(api, store)));

        HttpRequestToBeSent original = (HttpRequestToBeSent) Proxy.newProxyInstance(
                HttpRequestToBeSent.class.getClassLoader(), new Class<?>[]{HttpRequestToBeSent.class},
                (proxy, method, args) -> { throw new AssertionError("Forwarding handler called " + method); });
        MontoyaObjectFactory previous = ObjectFactoryLocator.FACTORY;
        try {
            ObjectFactoryLocator.FACTORY = (MontoyaObjectFactory) Proxy.newProxyInstance(
                    MontoyaObjectFactory.class.getClassLoader(), new Class<?>[]{MontoyaObjectFactory.class},
                    (proxy, method, args) -> {
                        if (!method.getName().equals("requestResult") || args.length != 1) {
                            throw new AssertionError("Unexpected Montoya factory call: " + method);
                        }
                        HttpRequest forwarded = (HttpRequest) args[0];
                        return new RequestToBeSentAction() {
                            @Override public HttpRequest request() { return forwarded; }
                            @Override public Annotations annotations() { return null; }
                        };
                    });
            for (HttpHandler handler : handlers) {
                RequestToBeSentAction result = handler.handleHttpRequestToBeSent(original);
                assertSame(original, result.request());
                assertEquals(RequestAction.CONTINUE, result.action());
            }
        } finally {
            ObjectFactoryLocator.FACTORY = previous;
        }
    }
}
