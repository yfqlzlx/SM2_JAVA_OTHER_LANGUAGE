package org.yf.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.yf.enums.Sm4Mode;
import org.yf.enums.Sm4Padding;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.Security;

public class Sm4Util {
    private static final String ALGORITHM_NAME = "SM4";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 加密
     * @param mode 分组模式
     * @param padding 填充类型
     * @param iv 偏移向量
     * @param key 对称密钥
     * @param content 明文
     * @return 加密后的
     * @throws GeneralSecurityException 加密模式或填充错误
     */
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
}
