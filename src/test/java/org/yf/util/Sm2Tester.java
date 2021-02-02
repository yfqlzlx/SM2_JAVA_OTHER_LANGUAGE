package org.yf.util;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.Test;
import org.yf.enums.Sm2Struct;

import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

/**
 * @author yfqlzlx
 * @date 2021/2/2 15:19
 */
public class Sm2Tester {

    @Test
    public void testSm2() throws Exception {
        // 加密
        String sm4Key = UUID.randomUUID().toString().replaceAll("-", "").substring(0, 16);
        System.out.println("原始sm4Key：" + sm4Key);

        BCECPublicKey publicKey = Sm2Util.convertX509ToPublicKey(new InputStreamReader(Thread.currentThread().getContextClassLoader().getResourceAsStream("sm2PubKey.pem")));
        // 以C1C3C2编码的ASN1输出
        byte[] encrypt = Sm2Util.encrypt(Sm2Struct.C1C3C2, sm4Key.getBytes(StandardCharsets.UTF_8), publicKey.getQ());

        String base64Encrypt = new String(Base64.getEncoder().encode(encrypt));
        System.out.println("base64 sm4Key:" + base64Encrypt);

        // 解密
        BCECPrivateKey privateKey = Sm2Util.convertPkcs8ToPrivateKey(new InputStreamReader(Thread.currentThread().getContextClassLoader().getResourceAsStream("sm2PrivateKey.pem")));
        byte[] source = Base64.getDecoder().decode(base64Encrypt.getBytes(StandardCharsets.UTF_8));
        String decrypt = Sm2Util.decrypt(Sm2Struct.C1C3C2, privateKey, source);
        System.out.println("解密后sm4Key：" + decrypt);
	}
}
