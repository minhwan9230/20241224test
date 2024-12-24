package com.springjwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {
    private SecretKey secretKey;

    public JwtUtil(@Value("${jwt.admin.secret.key}") String secret) {
        this.secretKey=new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
        //secret.getBytes(StandardCharsets.UTF_8) : 문자열을 **바이트 배열(byte array)**로 변환, 암호화 또는 서명 알고리즘에서 바이트 배열이 필요
        //JWT 서명 알고리즘(HS256)에 필요한 SecretKey 객체를 생성
    }
    public String getUsername(String token) {
        return Jwts.parser().verifyWith(this.secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
        //Jwts.parser(): 파싱을 위한 빌더 객체 생성
        //verifyWith(this.secretKey):서명을 검증할때 사용할 비밀키를 설정
        //build(): 설정된 키와 함께 최종파서를 생성
        //parseSignedClaims(token) : 토큰을 파싱하고 서명을 검증
        //getPayload(): payload 추출
    }
    public String getRole(String token) {
        return Jwts.parser().verifyWith(this.secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String getCategory(String token) {
        return Jwts.parser().verifyWith(this.secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
    }

    public String CreateJwt(String category, String username, String role, Long expiredMs){
        return Jwts.builder()
                .claim("category",category)
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) //밀리초 값을 받아 해당 시간에 대응하는 Date 객체를 생성
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }




}
