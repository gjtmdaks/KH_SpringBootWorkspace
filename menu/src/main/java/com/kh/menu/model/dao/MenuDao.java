package com.kh.menu.model.dao;

import java.util.HashMap;
import java.util.List;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.stereotype.Repository;

import com.kh.menu.model.dto.MenuDto.MenuPost;
import com.kh.menu.model.dto.MenuDto.MenuPut;
import com.kh.menu.model.vo.Menu;

import lombok.RequiredArgsConstructor;

@Repository
@RequiredArgsConstructor
public class MenuDao {
	private final SqlSessionTemplate session;

	public List<Menu> selectMenus(HashMap<String, Object> param) {
		List<Menu> list = session.selectList("menumapper.selectMenus", param);
		
		return list;
	}

	public int insertMenu(MenuPost menu) {
		return session.insert("menumapper.insertMenu", menu);
	}

	public Menu menuDetail(long id) {
		return session.selectOne("menumapper.menuDetail", id);
	}

	public int updateMenu(MenuPut menu) {
		return session.update("menumapper.updateMenu", menu);
	}

	public int deleteMenu(long id) {
		return session.delete("menumapper.deleteMenu", id);
	}

}
