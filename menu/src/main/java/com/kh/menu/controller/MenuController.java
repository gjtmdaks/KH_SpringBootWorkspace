package com.kh.menu.controller;

import java.net.URI;
import java.util.HashMap;
import java.util.List;

import org.apache.ibatis.javassist.NotFoundException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.kh.menu.model.dto.MenuDto.MenuPost;
import com.kh.menu.model.dto.MenuDto.MenuPut;
import com.kh.menu.model.service.MenuService;
import com.kh.menu.model.vo.Menu;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@RestController // @Controller + @ResponseBody
@Tag(name="Menu API", description = "메뉴 관리 API")
public class MenuController {
	/*
	 * #1. REST(Representaional State Transfer)
	 *  - 자원의 현재 상태(state)를 어떤 형식으로 전달하는 규칙, 방법
	 *    자원
	 *     - 서버에 존재하는 모든 데이터(문서, 이미지, 사용자 정보등)을 의미한다
	 *  - REST는 모든 자원에 대한 유니크한 URI을 설계하는 것이 원칙이다.
	 *    ex) 1번 게시글 -> /board?bno=1 (x) , /board/1(o)
	 *  - http메서드의 전송방식에 따라 같은 URI여도 서로 다른 자원을 가리킨다.
	 *    전송방식
	 *    GET - 자원 조회
	 *    POST - 자원 생성
	 *    PUT/PATCH - 자원 (전체)수정
	 *    DELETE - 자원 삭제
	 *    
	 *  형식(Represetaion)
	 *   - 자원의 상태를 표현하는 형식
	 *   - 클라이언트의 요청에 따라 /board/1과 같은 자원은 "xml, json, html"
	 *     등 다양한 형식으로 표현될 수 있다.
	 *   - 자원의 형식은 content-type, request-header에 의해 선택된다
	 *   - REST방식을 사용하면 URI와 HTTP메서드만 확인시 어떤 기능을 하는지
	 *     쉽게 알 수 있다.
	 *     
	 * #2. Rest API
	 *  - REST아키텍쳐 스타일에 따라 요청한 자원에 대한 CRUD를 수행하는 서버
	 *  - REST설계원칙을 잘 준수할 수록 RESTful한 API서버라고 부른다.
	 *  - 일반 MVC컨트롤러는 HTML페이지를 반환하나, REST API는 JSON을
	 *    반환한다.
	 */
	
	private final MenuService menuService;
	
	// 메뉴조회 서비스
	/*
	 * #3. REST API 설계원칙
	 * 1) 명사를 사용하여 자원을 작성한다.
	 *  - /getMenus => /menus (복수형작성)
	 * 2) 일관된 응답상태 관리
	 * 3) 새로운 API 생성을 지양한다.
	 *  - 필터용 데이터는 URI가 아닌 쿼리스트링으로 전달한다.
	 */
	@GetMapping("/menus")
	@Operation(summary = "메뉴 목록 조회", description = "메뉴목록 조회. type과 taste로 필터링 가능")
	@ApiResponse(responseCode = "200", description = "메뉴 목록 조회 성공",
			content = @Content(
					mediaType = "application/json",
					array = @ArraySchema(schema = @Schema(implementation = Menu.class))
					)
			)
	public ResponseEntity<List<Menu>> menus(
			@Parameter(description = "검색필터(type, taste)")
			@RequestParam HashMap<String, Object> param
			){
		List<Menu> list = menuService.selectMenus(param);
		
		log.debug("list {} ", list);
		
		return ResponseEntity.ok(list);
	}
	
	/*
	 * 메뉴등록
	 * 
	 * 4) 행위를 URI에 포함시키지 않는다.
	 *  - /menus/insert (x) => POST + /menus
	 */
	@PostMapping("/menus")
	public ResponseEntity<Void> insertMenu(
			@RequestBody MenuPost menu
			){
		int result = menuService.insertMenu(menu);
		
		if(result > 0) {
			// POST요청의 경우 응답데이터의 header에 이동할 URI에 대한 정보를
			// 적어준다.
			URI location = URI.create("/menus/"+menu.getId());
			
			// 201 Created
			return ResponseEntity.created(location).build();
		}else {
			// 400 bad request
			return ResponseEntity.badRequest().build();
		}
	}
	
	/*
     * 실습문제 1.) 메뉴 조회 기능
     * 요구사항
     *  1. REST한 방식으로 URI구성
     *  2. 응답데이터는 위 메서드들을 확인화여 일관된 방식으로 구성
     *  3. 조회 성공시 200응답상태와 조회결과 dto를 반환.
     *   - menu테이블의 모든 칼럼 조회.
     *  4. 조회결과가 존재하지 않을시 404에러상태 반환
     */
	@GetMapping("/menus/{id}")
	public ResponseEntity<Menu> menuDetail(
			@PathVariable long id
			){
		Menu menu = menuService.menuDetail(id);
		
		if(menu == null) {
			return ResponseEntity.notFound().build();
		}
		return ResponseEntity.ok(menu);
	}
	
	// 메뉴 수정
	@PutMapping("/menus/{id}")
	public ResponseEntity<Void> updateMenu(
			@RequestBody MenuPut menu,
			@PathVariable long id
			){
		menu.setId(id);
		int result = menuService.updateMenu(menu);
		
		if(result > 0) {
			// 204 -> PUT / PATCH / DELETE 시 사용하는 응답상태
			return ResponseEntity.noContent().build();
		}
		return ResponseEntity.notFound().build();
	}
	
	/*
     * 실습문제 2) 메뉴 삭제
     * 요구사항
     *  1. REST한 방식으로 URI구성
     *  2. 응답데이터는 위 메서드들을 확인화여 일관된 방식으로 구성
     *  3. 수정 성공시 204상태값(no content) 반환.
     *  4. 삭제 실패시 404에러상태 반환
     */
	@DeleteMapping("/menus/{id}")
	public ResponseEntity<Void> deleteMenu(
			@PathVariable long id
			) throws NotFoundException{
		menuService.deleteMenu(id);
		
		return ResponseEntity.noContent().build();
	}
}
