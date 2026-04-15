package com.kh.menu;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/*
 * @SpringBootApplication
 *  - 여러 어노테이션을 합쳐놓은 스프링부트 프로젝트에 한개만 작성해야하는
 *    어노테이션
 *  
 *  1. SpringBootConfiguration
 *   - springboot 설정파일임을 의미하는 어노테이션
 *  2. EnableAutoConfiguration
 *   - 자동설정활성화
 *  3. CompoentScan
 *   - 현재 실행된 클래스를 기준으로 "하위패키지"를 모두 검사하여
 *     bean객체로 등록해주는 어노테이션
 */
@SpringBootApplication
public class MenuApplication {

	public static void main(String[] args) {
		SpringApplication.run(MenuApplication.class, args);
	}

}
