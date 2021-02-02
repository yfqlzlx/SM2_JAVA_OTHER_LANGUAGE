package org.yf;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.Security;
import java.util.Base64;

public class Sm4Util {
    /**
     * SM4算法目前只支持128位（即密钥16字节）
     */
    public static final int DEFAULT_KEY_SIZE = 128;
    private static final String ALGORITHM_NAME = "SM4";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] encrypt(Sm4Mode mode, Sm4Padding padding, byte[] iv, byte[] key, byte[] content) throws GeneralSecurityException {
        Cipher cipher;
        if(Sm4Mode.CBC.equals(mode)){
            if(iv == null || iv.length == 0){
                throw new IllegalArgumentException("CBC模式下, iv不能为空");
            }
            cipher = generateCbcCipher(getAlgorithmName(mode, padding), Cipher.ENCRYPT_MODE, key, iv);
        }else{
            cipher = generateEcbCipher(getAlgorithmName(mode, padding), Cipher.ENCRYPT_MODE, key);
        }
        return cipher.doFinal(content);
    }


    public static byte[] decrypt(Sm4Mode mode, Sm4Padding padding, byte[] iv, byte[] key, byte[] content) throws GeneralSecurityException {
        Cipher cipher;
        if(Sm4Mode.CBC.equals(mode)){
            if(iv == null || iv.length == 0){
                throw new IllegalArgumentException("CBC模式下, iv不能为空");
            }
            cipher = generateCbcCipher(getAlgorithmName(mode, padding), Cipher.DECRYPT_MODE, key, iv);
        }else{
            cipher = generateEcbCipher(getAlgorithmName(mode, padding), Cipher.DECRYPT_MODE, key);
        }
        return cipher.doFinal(content);
    }

    private static String getAlgorithmName(Sm4Mode mode, Sm4Padding padding){
        return ALGORITHM_NAME + "/" + mode.getName() + "/" + padding.getName();
    }

    private static Cipher generateEcbCipher(String algorithmName, int mode, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        cipher.init(mode, sm4Key);
        return cipher;
    }

    private static Cipher generateCbcCipher(String algorithmName, int mode, byte[] key, byte[] iv) throws GeneralSecurityException{
        Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(mode, sm4Key, ivParameterSpec);
        return cipher;
    }

    public static enum Sm4Mode{
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

    public static enum Sm4Padding{
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


    public static void main(String[] args) throws Exception{
//        String source = "Source1N123111111asbc我不是张三123";
        byte[] iv = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
//        String sm4Key = UUID.randomUUID().toString().replaceAll("-", "").substring(0, 16);
//        System.out.println("sm4Key:\t" + sm4Key);
//        byte[] encrypt = Sm4Util.encrypt(Sm4Mode.CBC, Sm4Padding.PADDING_PKCS5, iv, sm4Key.getBytes(StandardCharsets.UTF_8), source.getBytes(StandardCharsets.UTF_8));
//        String base64Str = new String(Base64.getEncoder().encode(encrypt));
//        System.out.println("base64Str:" + base64Str);
//        System.out.println("==================================");
//
//        byte[] decode = Base64.getDecoder().decode(base64Str.getBytes(StandardCharsets.UTF_8));
//        byte[] decrypt = Sm4Util.decrypt(Sm4Mode.CBC, Sm4Padding.PADDING_PKCS5, iv, sm4Key.getBytes(StandardCharsets.UTF_8), decode);
//        System.out.println("解密后： \t" + new String(decrypt, StandardCharsets.UTF_8));

        String base64Str = "9o0pC1Be32veSQiUHDo+7rTpIWdQ05DkFSQpdglqyog=";
        String key = "b8677db2e72240f6";
        byte[] decrypt = Sm4Util.decrypt(Sm4Mode.CBC, Sm4Padding.PADDING_PKCS5, iv, key.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(base64Str.getBytes(StandardCharsets.UTF_8)));
        System.out.println(new String(decrypt, StandardCharsets.UTF_8));
    }
}
