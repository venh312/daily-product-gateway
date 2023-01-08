package com.daily.product.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.util.List;
import java.util.Objects;

@Slf4j
@Component
public class ClientAuthFilter extends AbstractGatewayFilterFactory {

    @Value("${global.clientKey}")
    private String clientKey;

    @Override
    public GatewayFilter apply(Object config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            log.info("[Gateway] ClientAuthFilter : request uri => {}", request.getURI());

            if (!request.getHeaders().containsKey("CLIENT-KEY")) {
                return handleUnAuthorized(exchange); // 401 Error
            }

            List<String> clientKey = request.getHeaders().get("CLIENT-KEY");
            String clientKeyString = Objects.requireNonNull(clientKey).get(0);

            if (!clientKey.equals(clientKeyString)) {
                return handleUnAuthorized(exchange); // 토큰이 일치하지 않을 때
            }

            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                log.info("[Gateway] ClientAuthFilter : response code -> {}", response.getStatusCode());
            }));
        });
    }

    private Mono<Void> handleUnAuthorized(ServerWebExchange exchange) {
        log.info("[Gateway] ClientAuthFilter : response code -> {}", "401 Unauthorized");
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }
}