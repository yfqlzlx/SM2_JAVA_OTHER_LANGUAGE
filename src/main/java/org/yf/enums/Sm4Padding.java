package org.yf.enums;

/**
 * SM4填充模式
 * @author yfqlzlx
 * @date 2021/2/2 15:17
 */
public enum Sm4Padding {
    /**
     * NoPadding模式，需要用户保证数据是块长度的倍数
     */
    PADDING_NO("NoPadding"),
    PADDING_PKCS5("PKCS5Padding"),
    PADDING_PKCS7("PKCS7Padding");

    private String name;

    Sm4Padding(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
