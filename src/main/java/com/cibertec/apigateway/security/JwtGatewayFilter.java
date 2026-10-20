package com.cibertec.apigateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class JwtGatewayFilter implements GlobalFilter, Ordered {
    @Value("${jwt.secret}") private String secret;
    private SecretKey key;

    @PostConstruct
    void init() {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if(bytes.length < 32) throw new IllegalStateException("jwt.secret debe tener 32 bytes como minimo");
        key = Keys.hmacShaKeyFor(bytes);
    }

    @Override public int getOrder() { return -100; }
    @Override public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path=exchange.getRequest().getPath().value();
        if (exchange.getRequest().getMethod() == org.springframework.http.HttpMethod.OPTIONS) return chain.filter(exchange);
        if (path.equals("/api/auth/login")) return chain.filter(exchange);
        String header=exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if(header==null || !header.startsWith("Bearer ")) return reject(exchange,HttpStatus.UNAUTHORIZED);
        try {
            Claims claims=Jwts.parser().verifyWith(key).build().parseSignedClaims(header.substring(7)).getPayload();
            String rol=claims.get("rol",String.class);
            if(claims.getSubject()==null || claims.getSubject().isBlank() || !("ADMINISTRADOR".equals(rol)||"OPERADOR_CAJA".equals(rol)))
                return reject(exchange,HttpStatus.UNAUTHORIZED);
            if(path.startsWith("/api/usuarios")
              && !(exchange.getRequest().getMethod().name().equals("GET")
                && path.matches("/api/usuarios/[0-9]+"))
              && !"ADMINISTRADOR".equals(rol))
                return reject(exchange,HttpStatus.FORBIDDEN);
            return chain.filter(exchange);
        } catch(RuntimeException e) {
            return reject(exchange,HttpStatus.UNAUTHORIZED);
        }
    }
    private Mono<Void> reject(ServerWebExchange exchange,HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }
}
