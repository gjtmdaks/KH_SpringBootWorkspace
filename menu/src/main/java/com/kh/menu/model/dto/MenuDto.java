package com.kh.menu.model.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

public class MenuDto {
	
	@Data
	@NoArgsConstructor
	public static class MenuPost{
		private long id;
		private String restaurant;
		private String name;
		private int price;
		private String type;
		private String taste;
	}
	
	@Data
	@NoArgsConstructor
	public static class MenuPut{
		private long id;
		private String restaurant;
		private String name;
		private int price;
		private String type;
		private String taste;
	}
}
