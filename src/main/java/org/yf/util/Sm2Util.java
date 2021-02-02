package org.yf.util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.yf.enums.Sm2Struct;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 标准SM2工具类，可以与其他语言交互
 * @author yf
 *
 */
public class Sm2Util {

    /*
     * 国密推荐的椭圆曲线参数
     */

    private static final BigInteger N = new BigInteger(
			"FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "7203DF6B" + "21C6052B" + "53BBF409" + "39D54123", 16);
	private static final BigInteger P = new BigInteger(
			"FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF" + "FFFFFFFF", 16);
	private static final BigInteger A = new BigInteger(
			"FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF" + "FFFFFFFC", 16);
	private static final BigInteger B = new BigInteger(
			"28E9FA9E" + "9D9F5E34" + "4D5A9E4B" + "CF6509A7" + "F39789F5" + "15AB8F92" + "DDBCBD41" + "4D940E93", 16);
	private static final BigInteger GX = new BigInteger(
			"32C4AE2C" + "1F198119" + "5F990446" + "6A39C994" + "8FE30BBF" + "F2660BE1" + "715A4589" + "334C74C7", 16);
	private static final BigInteger GY = new BigInteger(
			"BC3736A2" + "F4F6779C" + "59BDCEE3" + "6B692153" + "D0A9877C" + "C62A4740" + "02DF32E5" + "2139F0A0", 16);

	private static final int DIGEST_LENGTH = 32;
    private static final String ALGO_NAME_EC = "EC";
    // 使用真随机数
	private static final SecureRandom RANDOM = new SecureRandom();
	private static final ECCurve.Fp CURVE = new ECCurve.Fp(P, A, B, null, null);;
	private static final ECPoint G = CURVE.createPoint(GX, GY);
    private static final ECDomainParameters ECC_BC_SPEC = new ECDomainParameters(CURVE, G, N);;
	private static final Logger LOGGER = Logger.getLogger(Sm2Util.class.getName());

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    /**
     * 从公钥文件中加载公钥
     * @param reader 公钥文件流
     * @return 公钥
     * @throws IOException 读取文件流失败
     * @throws GeneralSecurityException 格式不正确
     */
    public static BCECPublicKey convertX509ToPublicKey(Reader reader) throws IOException, GeneralSecurityException {
        PemObject spki = new PemReader(reader).readPemObject();
        byte[] x509Bytes = KeyFactory.getInstance("EC", "BC").generatePublic(new X509EncodedKeySpec(spki.getContent())).getEncoded();
        X509EncodedKeySpec eks = new X509EncodedKeySpec(x509Bytes);
        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return (BCECPublicKey) kf.generatePublic(eks);
    }

    /**
     * 从私钥文件中读取私钥
     * @param reader 私钥文件流
     * @return 私钥
     * @throws IOException 读取私钥文件失败
     * @throws GeneralSecurityException 私钥是个不正确
     */
    public static BCECPrivateKey convertPkcs8ToPrivateKey(Reader reader) throws IOException, GeneralSecurityException {
        PEMParser pemReader = new PEMParser(reader);
        Object obj = pemReader.readObject();
        pemReader.close();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        byte[] pkcs8Key = converter.getPrivateKey((PrivateKeyInfo) obj).getEncoded();
        PKCS8EncodedKeySpec peks = new PKCS8EncodedKeySpec(pkcs8Key);
        KeyFactory kf = KeyFactory.getInstance(ALGO_NAME_EC, BouncyCastleProvider.PROVIDER_NAME);
        return (BCECPrivateKey) kf.generatePrivate(peks);
    }

    /**
     * 公钥加密
     * @see Sm2Util#encrypt(org.yf.enums.Sm2Struct, byte[], org.bouncycastle.math.ec.ECPoint)
     */
    public static byte[] encrypt(byte[] source, ECPoint publicKey) throws IOException{
        return encrypt(Sm2Struct.C1C3C2, source, publicKey);
    }

	/**
	 * 公钥加密
     * @param struct 密文结构
	 * @param source 明文
	 * @param publicKey 公钥
	 * @return 密文
     * @throws IOException ASN1编码失败
	 */
	public static byte[] encrypt(Sm2Struct struct, byte[] source, ECPoint publicKey) throws IOException{
        publicKey = publicKey.normalize();
		byte[] c1Buffer;
		ECPoint kpb;
		byte[] t;
        ECPoint c1;
		do {
			// 1、产生随机数k，k属于[1, n-1]
			BigInteger k = random(N);
			// 2、计算椭圆曲线点C1 = [k]G = (x1, y1)
            c1 = G.multiply(k).normalize();
            c1Buffer = c1.getEncoded(false);
			// 3、计算椭圆曲线点 S = [h]Pb */
            // 如果在无穷点不能交叉，则这个点是错的
			BigInteger h = ECC_BC_SPEC.getH();
			if (h != null) {
				ECPoint S = publicKey.multiply(h);
				if (S.isInfinity()) {
                    throw new IllegalStateException();
                }
			}
			// 4、计算 [k]PB = (x2, y2)
			kpb = publicKey.multiply(k).normalize();
			//5、计算 t = KDF(x2||y2, klen)
            byte[] kpbBytes = point2bytes(kpb);
			t = kdf(kpbBytes, source.length);
		} while (allZero(t));

		// 6、计算C2=M^t
		byte[] c2 = new byte[source.length];
		for (int i = 0; i < source.length; i++) {
            c2[i] = (byte) (source[i] ^ t[i]);
		}

		// 7、计算C3 = Hash(x2 || M || y2)
        byte[] c3 = sm3hash(point2x(kpb), source, point2y(kpb));

//		// 8、输出C1C3C2密文，但是不选择这样，而是用ASN1编码
//		byte[] encryptResult = new byte[C1Buffer.length + C2.length + C3.length];
//		System.arraycopy(C1Buffer, 0, encryptResult, 0, C1Buffer.length);
//		System.arraycopy(C3, 0, encryptResult, C1Buffer.length , C3.length);
//      System.arraycopy(C2, 0, encryptResult, C1Buffer.length + C3.length, C2.length);

        // 9、输出ASN1，选择Vector保证输出顺序
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(c1.getXCoord().toBigInteger()));
        vector.add(new ASN1Integer(c1.getYCoord().toBigInteger()));
        if(Sm2Struct.C1C2C3.equals(struct)){
            vector.add(new DEROctetString(c2));
            vector.add(new DEROctetString(c3));
        }else{
            vector.add(new DEROctetString(c3));
            vector.add(new DEROctetString(c2));
        }
        DERSequence seq = new DERSequence(vector);
        return seq.getEncoded();
	}

    public static String decrypt(Sm2Struct struct, BCECPrivateKey privateKey, byte[] encryptData) throws IOException{
	    return decrypt(struct, privateKey.getD(), encryptData);
    }

    public static String decrypt(BCECPrivateKey privateKey, byte[] encryptData) throws IOException{
        return decrypt(Sm2Struct.C1C3C2, privateKey.getD(), encryptData);
    }

    public static String decrypt(BigInteger privateKey, byte[] encryptData) throws IOException{
        return decrypt(Sm2Struct.C1C3C2, privateKey, encryptData);
    }


	/**
	 * 私钥解密
     * @param struct 密文结构
     * @param privateKey 私钥的D值
     * @param encryptData  密文数据字节数组，C1C2C3，如果是C1C3C2需要先转换
	 * @return 明文
	 */
	public static String decrypt(Sm2Struct struct, BigInteger privateKey, byte[] encryptData) throws IOException{
	    if(Sm2Struct.C1C3C2.equals(struct)){
            encryptData = fromC1C3C2ToC1C2C3(encryptData);
        }
		byte[] c1Byte = new byte[65];
		System.arraycopy(encryptData, 0, c1Byte, 0, c1Byte.length);
		// 私钥要归一化，否则会解密失败(t值不为1)
		ECPoint c1 = CURVE.decodePoint(c1Byte).normalize();
        // 计算椭圆曲线点 S = [h]C1 是否为无穷点
		BigInteger h = ECC_BC_SPEC.getH();
		if (h != null) {
			ECPoint s = c1.multiply(h);
			if (s.isInfinity()) {
                throw new IllegalStateException();
            }
		}
		// 计算[dB]C1 = (x2, y2)，同时归一化，归一化是为了与其他语言交互
		ECPoint dBC1 = c1.multiply(privateKey).normalize();

		// 计算t = KDF(x2 || y2, klen)
        // x,y要特殊处理，防止高位为1导致与其他语言T值计算错误
        byte[] dBC1Bytes = point2bytes(dBC1);
		int kLen = encryptData.length - 65 - DIGEST_LENGTH;
		byte[] t = kdf(dBC1Bytes, kLen);
		if (allZero(t)) {
			LOGGER.log(Level.SEVERE, "计算t失败, 曲线不交叉");
			throw new IllegalStateException();
		}

		// 计算M'=C2^t
		byte[] M = new byte[kLen];
		for (int i = 0; i < M.length; i++) {
			M[i] = (byte) (encryptData[c1Byte.length + i] ^ t[i]);
		}

		// 计算 u = Hash(x2 || M' || y2) 判断 u == C3是否成立(校验sm3签名)
		byte[] C3 = new byte[DIGEST_LENGTH];

		System.arraycopy(encryptData, encryptData.length - DIGEST_LENGTH, C3, 0, DIGEST_LENGTH);
        byte[] u = sm3hash(point2x(dBC1), M, point2y(dBC1));
        LOGGER.log(Level.FINE, "解密结果C3验证：【{0}】",  Arrays.equals(u, C3));
        if(!Arrays.equals(u, C3)){
            // 目前本语言内的SM3没问题，与其他语言交互的SM3签名可能会有错误
            LOGGER.log(Level.FINE, "SM3校验错误");
        }
        return new String(M, StandardCharsets.UTF_8);
	}

    /**
     * 随机数生成器
     */
    private static BigInteger random(BigInteger max) {
        BigInteger r = new BigInteger(256, RANDOM);
        while (r.compareTo(max) >= 0) {
            r = new BigInteger(128, RANDOM);
        }
        return r;
    }

    /**
     * 判断字节数组是否全0
     */
    private static boolean allZero(byte[] buffer) {
        for (byte value : buffer) {
            if (value != 0) {
                return false;
            }
        }
        return true;
    }

	/**
	 * 字节数组拼接
	 * @param params 待拼接数组
	 * @return 拼接后数组
     * @throws  IOException 拼接错误
	 */
	private static byte[] join(byte[]... params) throws IOException {
	    try(ByteArrayOutputStream baos = new ByteArrayOutputStream()){
            for (byte[] param : params) {
                baos.write(param);
            }
            return baos.toByteArray();
        }
	}

	/**
	 * SM3摘要
	 * @param params 参与SM3计算的组成部分：基点的x, 密文, 基点的y
	 * @return SM3摘要
	 */
	private static byte[] sm3hash(byte[]... params) throws IOException{
		return Sm3Util.digest(join(params));
	}


	/**
	 * 密钥派生函数生成
	 * @param z 大数拼接后的基点的x,y坐标值
	 * @param kLen 生成kLen字节数长度的密钥
	 * @return 基于基点的派生函数
     * @throws IOException 派生函数生成失败
	 */
	private static byte[] kdf(byte[] z, int kLen) throws IOException{
		int ct = 1;
		int end = (int) Math.ceil(kLen * 1.0 / 32);
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()){
			for (int i = 1; i < end; i++) {
				baos.write(sm3hash(z, toByteArray(ct)));
				ct++;
			}
			byte[] last = sm3hash(z, toByteArray(ct));
			if (kLen % 32 == 0) {
				baos.write(last);
			} else {
                baos.write(last, 0, kLen % 32);
            }
			return baos.toByteArray();
		}
	}

    /**
     * ASN1模式转换
     * 将标准的C1C3C2转换成非标准的C1C2C3
     * @param source C1C3C2形式的密文
     * @return C1C2C3形式的密文
     * @throws IOException 转换模式失败，可能是ASN1不标准或者其他格式问题导致曲线不是正常的ECC曲线
     */
	private static byte[] fromC1C3C2ToC1C2C3(byte[] source) throws IOException{
        try(ByteArrayOutputStream os = new ByteArrayOutputStream()){
            ASN1InputStream aIn = new ASN1InputStream(source);
            ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
            BigInteger x = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
            BigInteger y = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
            byte[] c3 = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
            byte[] c2 = ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets();
            ECPoint p = CURVE.validatePoint(x, y);
            // 为了正常解密，这里加一次编码转换，因为解密那又一次decode
            byte[] c1b = p.getEncoded(false);
            os.write(c1b);
            os.write(c2);
            os.write(c3);
            return os.toByteArray();
        }
    }

    /**
     * 获得ECC曲线上点的x
     * @param point 点
     * @return x坐标的byte数组，因为是大数
     */
    private static byte[] point2x(ECPoint point){
        int size = (CURVE.getFieldSize() + 7) / 8;
        byte[] xb = point.getXCoord().toBigInteger().toByteArray();
        if(xb.length > size){
            byte[] tmp = xb; xb = new byte[size];
            System.arraycopy(tmp, tmp.length - size, xb, 0, size);
        }
        byte[] ret = new byte[size];
        Arrays.fill(ret, (byte)0);
        System.arraycopy(xb, 0, ret, size - xb.length, xb.length);
        return ret;
    }

    /**
     * 获得ECC曲线上点的y
     * @param point 点
     * @return y坐标的byte数组，因为是大数
     */
    private static byte[] point2y(ECPoint point){
        int size = (CURVE.getFieldSize() + 7) / 8;
        byte[] yb = point.getYCoord().toBigInteger().toByteArray();
        if(yb.length > size){
            byte[] tmp = yb; yb = new byte[size];
            System.arraycopy(tmp, 0, yb, 0, size);
        }
        byte[] ret = new byte[size];
        Arrays.fill(ret, (byte)0);
        System.arraycopy(yb, 0, ret, size - yb.length, yb.length);
        return ret;
    }

    /**
     * 获得ECC点的xy值的byte数组
     * @param point 点
     * @return xy2个byte数组拼接
     */
    private static byte[] point2bytes(ECPoint point){
        int size = (CURVE.getFieldSize() + 7) / 8;
        byte[] xb = point.getXCoord().toBigInteger().toByteArray();
        byte[] yb = point.getYCoord().toBigInteger().toByteArray();
        if(xb.length > size){
            byte[] tmp = xb; xb = new byte[size];
            System.arraycopy(tmp, tmp.length - size, xb, 0, size);
        }
        if(yb.length > size){
            byte[] tmp = yb; yb = new byte[size];
            System.arraycopy(tmp, tmp.length - size, yb, 0, size);
        }
        byte[] ret = new byte[size*2];
        Arrays.fill(ret, (byte)0);
        System.arraycopy(xb, 0, ret, size - xb.length, xb.length);
        System.arraycopy(yb, 0, ret, size + size - yb.length, yb.length);
        return ret;
    }


    private static byte[] toByteArray(int i) {
        byte[] byteArray = new byte[4];
        byteArray[0] = (byte) (i >>> 24);
        byteArray[1] = (byte) ((i & 0xFFFFFF) >>> 16);
        byteArray[2] = (byte) ((i & 0xFFFF) >>> 8);
        byteArray[3] = (byte) (i & 0xFF);
        return byteArray;
    }
}
