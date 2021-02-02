package org.yf.enums;

/**
 * 密文分组模式
 * @author yfqlzlx
 * @date 2021/2/2 15:18
 */
public enum Sm4Mode {
    CBC("CBC"),
    ECB("ECB");

    private String name;

    Sm4Mode(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
