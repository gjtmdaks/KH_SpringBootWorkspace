package com.kh.menu.security.controller;

import static com.kh.menu.security.utils.CookieUtil.ACCESS_COOKIE;
import static com.kh.menu.security.utils.CookieUtil.REFRESH_COOKI;
import static com.kh.menu.security.utils.CookieUtil.ROLE_COOKIE;
import static com.kh.menu.security.utils.CookieUtil.createTokenCookie;

import java.util.stream.Collectors;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kh.menu.security.model.dto.AuthDto.AuthResult;
import com.kh.menu.security.model.dto.AuthDto.LoginRequest;
import com.kh.menu.security.model.provider.JWTProvider;
import com.kh.menu.security.model.service.AuthService;
import com.kh.menu.security.model.service.KakaoService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
@Slf4j
public class AuthController {
	private final AuthService service;
	private final KakaoService kakaoService;
	private final JWTProvider jwt;

	@PostMapping("/login")
	public ResponseEntity<AuthResult> login(@RequestBody LoginRequest req){
		/*
		 * 로그인
		 *  - 현재 db에 존재하지 않는 이메일이면 404에러 반환
		 *  - 프런트에서는 응답상태가 404인 경우 회원가입할지, 재로그인할지 처리
		 *  - 이메일은 존재하나 비밀번호가 틀린경우 401상태(미인증) 반환 => 재로그인
		 *  - 모두 성공시 유저정보와 JWT토큰 반환
		 */
		// 1) 사용자가 존재하는지 확인
		boolean exists = service.existsByEmail(req.getEmail());
		
		if(!exists) {
			// 2) 사용자가 존재하지 않는 경우 404상태 반환
			return ResponseEntity.notFound().build();
		}
		
		// 3) 사용자가 존재한다면 인증처리하고, 인증정보 반환
		try {
			AuthResult result = service.login(req.getEmail(), req.getPassword());
			
			// 인증성공시 accessToken, refreshToken생성하여 클라이언트의 쿠키로 전달.
			return makeResponse(result);
			
		}catch(BadCredentialsException e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		}
	}
	
	private ResponseEntity<AuthResult> makeResponse(AuthResult result){
		// AccessToken을 쿠키에 담아서 전달
		ResponseCookie accessCookie = 
				createTokenCookie(ACCESS_COOKIE, result.getAccessToken(), 30);
		
		ResponseCookie refreshCookie = 
				createTokenCookie(REFRESH_COOKI, result.getRefreshToken(), 7);
		
		String roles = result.getUser().getRoles()
							.stream().collect(Collectors.joining("|"));
		ResponseCookie roleCookie = 
				createTokenCookie(ROLE_COOKIE, roles, 30);
		
		return ResponseEntity
					.ok()
					.header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
					.header(HttpHeaders.SET_COOKIE, accessCookie.toString())
					.header(HttpHeaders.SET_COOKIE, roleCookie.toString())
					.body(result);
	}
	
	/*
	 * 자동 회원가입
	 */
	@PostMapping("/signup")
	public ResponseEntity<AuthResult> signup(
			@RequestBody LoginRequest req
			){
		
		AuthResult result = service.signup(req);
		return makeResponse(result);
	}
}
