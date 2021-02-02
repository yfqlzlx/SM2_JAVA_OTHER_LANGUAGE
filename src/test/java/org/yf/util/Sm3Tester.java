package org.yf.util;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * @author yfqlzlx
 * @date 2021/2/2 15:46
 */
public class Sm3Tester {

    @Test
    public void testSm3() throws Exception{
        // source的Sm3 base64后的结果
        String target = "MzE3YmQ1Zjg0ODdhYmIxZTg3ZGVkMzE0Y2IyYjAyNjBiN2Q5MTU3MDdhNTJlODA4MTAxNjc2MzNmZTdmMDdlYw==";
        String source = "abcdefc我是123waz11";
        String digestHex = Sm3Util.digestHex(source.getBytes(StandardCharsets.UTF_8));
        System.out.println("sm3摘要：" + digestHex);
        String sm3Str = new String(Base64.getEncoder().encode(digestHex.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        System.out.println("结果对比： " + target.equals(sm3Str));
    }
}
