package org.yf.util;

import org.junit.Test;
import org.yf.enums.Sm4Mode;
import org.yf.enums.Sm4Padding;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

/**
 * @author yfqlzlx
 * @date 2021/2/2 15:49
 */
public class Sm4Tester {
    @Test
    public void testSm4() throws Exception{
        String source = "Source1N123111111asbc我不是张三123";
        byte[] iv = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        String sm4Key = UUID.randomUUID().toString().replaceAll("-", "").substring(0, 16);
        System.out.println("sm4Key:\t" + sm4Key);
        byte[] encrypt = Sm4Util.encrypt(Sm4Mode.CBC, Sm4Padding.PADDING_PKCS5, iv, sm4Key.getBytes(StandardCharsets.UTF_8), source.getBytes(StandardCharsets.UTF_8));
        String base64Str = new String(Base64.getEncoder().encode(encrypt));
        System.out.println("base64Str:" + base64Str);
        byte[] decode = Base64.getDecoder().decode(base64Str.getBytes(StandardCharsets.UTF_8));
        byte[] decrypt = Sm4Util.decrypt(Sm4Mode.CBC, Sm4Padding.PADDING_PKCS5, iv, sm4Key.getBytes(StandardCharsets.UTF_8), decode);
        System.out.println("解密后:" + new String(decrypt, StandardCharsets.UTF_8));
    }
}

