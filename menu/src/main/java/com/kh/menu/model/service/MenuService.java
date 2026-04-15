package com.kh.menu.model.service;

import java.util.HashMap;
import java.util.List;

import org.apache.ibatis.javassist.NotFoundException;
import org.springframework.stereotype.Service;

import com.kh.menu.model.dao.MenuDao;
import com.kh.menu.model.dto.MenuDto.MenuPost;
import com.kh.menu.model.dto.MenuDto.MenuPut;
import com.kh.menu.model.vo.Menu;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class MenuService {
	private final MenuDao dao;

	public List<Menu> selectMenus(HashMap<String, Object> param) {
		return dao.selectMenus(param);
	}

	public int insertMenu(MenuPost menu) {
		return dao.insertMenu(menu);
	}

	public Menu menuDetail(long id) {
		return dao.menuDetail(id);
	}

	public int updateMenu(MenuPut menu) {
		return dao.updateMenu(menu);
	}

	public void deleteMenu(long id) throws NotFoundException {
		int result = dao.deleteMenu(id);
		
		if(result == 0) throw new NotFoundException("삭제할 메뉴가 존재하지 않습니다.");
	}

}
