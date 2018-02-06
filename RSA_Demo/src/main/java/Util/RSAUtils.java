/*
 * 文件名：RSAUtil.java
 * 版权：Copyright by www.xxx.com
 * 描述：
 * 修改人：Lucius Chen
 * 修改时间：2018-02-01
 * 跟踪单号：
 * 修改单号：
 * 修改内容：
 */
package Util;


import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;


/**
 * RSA 工具类
 *
 * @author Lucius Chen
 * @version 2018-02-01
 * @see RSAUtils
 */
public class RSAUtils {
    /**
     * 非对称加密密钥算法
     */
    private static final String RSA = "RSA";

    /**
     * 秘钥默认长度
     */
    public static final int DEFAULT_KEY_SIZE = 1024;

    /**
     * 加密的最大字节数
     */
    private static final int DEFAULT_ENCRYPT_SIZE = (DEFAULT_KEY_SIZE / 8) - 11;

    /**
     * 解密的最大字节数
     */
    private static final int DEFAULT_DECRYPT_SIZE = (DEFAULT_KEY_SIZE / 8);

    /**
     * 标识位
     */
    private static final byte[] DEFAULT_SPLIT = "#PATH#".getBytes();

    /**
     * 加密填充方式
     */
    private static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";

    /**
     * 随机生成RSA密钥对
     *
     * @param keyLength 密钥长度，范围：512～2048；一般为1024
     * @return 密钥对儿（包含公钥和私钥）
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
            kpg.initialize(keyLength);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       已加密数据
     * @param privateKey 私钥(BASE64编码)
     * @return String
     * @throws Exception 签名相关的一些异常
     */
    public static String sign(byte[] data, PrivateKey privateKey)
            throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return Base64.encodeBase64String(signature.sign());
    }

    /**
     * <p>
     * 校验数字签名
     * </p>
     *
     * @param data      已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @param sign      数字签名
     * @return boolean
     * @throws Exception 签名出现的一些异常
     */
    public static boolean verify(byte[] data, PublicKey publicKey, String sign)
            throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(Base64.decodeBase64(sign));
    }

    /**
     * 从文件中加载 Key
     *
     * @param path 路径
     * @return String
     * @throws Exception IOException NullPointerException
     */
    public static String loadKeyByFile(String path)
            throws Exception {
        try {
            BufferedReader br = new BufferedReader(new FileReader(path));
            String readLine;
            StringBuilder sb = new StringBuilder();
            while ((readLine = br.readLine()) != null) {
                sb.append(readLine);
            }
            br.close();
            return sb.toString();
        } catch (IOException e) {
            throw new Exception("公钥数据流读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥输入流为空");
        }
    }

    /**
     * 从字符串中加载公钥
     *
     * @param publicKeyStr 公钥数据字符串
     * @return RSAPublicKey
     * @throws Exception NoSuchAlgorithmException InvalidKeySpecException NullPointerException
     */
    public static RSAPublicKey loadPublicKeyByStr(String publicKeyStr)
            throws Exception {
        try {
            byte[] buffer = Base64.decodeBase64(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("公钥非法");
        } catch (NullPointerException e) {
            throw new Exception("公钥数据为空");
        }
    }

    /**
     * 从字符串中加载私钥
     *
     * @param privateKeyStr 私钥数据字符串
     * @return RSAPrivateKey
     * @throws Exception NoSuchAlgorithmException InvalidKeySpecException NullPointerException
     */
    public static RSAPrivateKey loadPrivateKeyByStr(String privateKeyStr)
            throws Exception {
        try {
            byte[] buffer = Base64.decodeBase64(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("私钥非法");
        } catch (NullPointerException e) {
            throw new Exception("私钥数据为空");
        }
    }

    /**
     * 公钥加密方法
     *
     * @param source    源数据
     * @param publicKey 公钥
     * @return byte[]
     * @throws Exception NoSuchPaddingException InvalidKeyException
     */
    public static byte[] encrypt(String source, RSAPublicKey publicKey)
            throws Exception {
        // 得到 Cipher 对象来实现对源数据的RSA加密
        // 移植到 Android 需要将 RSA 换成 RSA/ECB/PKCS1Padding 或者 RSA/None/NoPadding
        // Android 的 JDK 和 Java 的 JDK 实现不一样
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] sourceData = source.getBytes();
        // 执行分组加密操作
        return Base64.encodeBase64(DataProcessing(sourceData, cipher, DEFAULT_ENCRYPT_SIZE));
    }

    /**
     * 使用私钥解密算法
     *
     * @param cryptoSrc  已加密的数据
     * @param privateKey 私钥
     * @return byte[]
     * @throws Exception NoSuchPaddingException InvalidKeyException
     */
    public static byte[] decrypt(String cryptoSrc, RSAPrivateKey privateKey)
            throws Exception {
        // 得到 Cipher 对象对已用公钥加密的数据进行RSA解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedData = Base64.decodeBase64(cryptoSrc);
        // 执行解密操作
        return DataProcessing(encryptedData, cipher, DEFAULT_DECRYPT_SIZE);
    }

    /**
     * 数据处理
     *
     * @param data   需要处理的数据
     * @param cipher Cipher
     * @param size   size
     * @return byte[]
     * @throws Exception IllegalBlockSizeException
     */
    private static byte[] DataProcessing(byte[] data, Cipher cipher, int size)
            throws Exception {
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > size) {
                cache = cipher.doFinal(data, offSet, size);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * size;
        }

        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    //
    // =================================================================================================================
    //  以上是通过确定的最小加密长度（117）以及最大解密长度（即明文长度加上 padding，padding 参与加密）来实现加密解密（包括分段）的；
    //  以下是假设不知加密后长度的前提下，通过标识位的方式实现分段加密解密的。
    // =================================================================================================================
    //

    /**
     * 使用公钥加密
     *
     * @param data      待加密数据
     * @param publicKey 公钥
     * @return byte[]       加密数据
     * @throws Exception exception
     */
    private static byte[] encryptByPublicKey(byte[] data, byte[] publicKey)
            throws Exception {
        // 得到公钥
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        PublicKey keyPublic = kf.generatePublic(keySpec);
        // 加密数据
        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
        cp.init(Cipher.ENCRYPT_MODE, keyPublic);
        return cp.doFinal(data);
    }

    /**
     * 使用私钥进行解密
     *
     * @param encrypted  待解密数据
     * @param privateKey 私钥
     * @return byte[]       解密数据
     * @throws Exception exception
     */
    private static byte[] decryptByPrivateKey(byte[] encrypted, byte[] privateKey)
            throws Exception {
        // 得到私钥
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        PrivateKey keyPrivate = kf.generatePrivate(keySpec);

        // 解密数据
        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
        cp.init(Cipher.DECRYPT_MODE, keyPrivate);
        return cp.doFinal(encrypted);
    }

    /**
     * 用公钥对字符串进行分段加密
     *
     * @param data      待加密数据
     * @param publicKey 公钥
     * @return byte[]
     * @throws Exception exception
     */
    private static byte[] encryptByPublicKeyForSpilt(byte[] data, byte[] publicKey)
            throws Exception {
        int dataLen = data.length;
        // 如果数据的长度不超过密钥支持的最大值，就直接进行加密操作
        if (dataLen <= DEFAULT_ENCRYPT_SIZE) {
            return encryptByPublicKey(data, publicKey);
        }
        // 否则进行分段加密，allBytes是分段加密后数据的载体

        return dataSplit(data, publicKey, dataLen, true);
    }

    /**
     * 用私钥对字符串进行分段解密
     *
     * @param encrypted  待解密的数据
     * @param privateKey 私钥
     */
    public static byte[] decryptByPrivateKeyForSpilt(byte[] encrypted, byte[] privateKey)
            throws Exception {
        int splitLen = DEFAULT_SPLIT.length;
        // 如果分块解密的标识的长度为0，就直接进行加密操作，换句话说：如果没有分块解密的标识，直接进行解密
        if (splitLen <= 0) {
            return decryptByPrivateKey(encrypted, privateKey);
        }
        // 否则进行分块解密
        return dataSplit(encrypted, privateKey, splitLen, false);
    }

    /**
     * 分割数据
     *
     * @param encrypted encrypted
     * @param key       key
     * @param splitLen  splitLen
     * @param flag      flag
     * @return byte[]
     * @throws Exception exception
     */
    private static byte[] dataSplit(byte[] encrypted, byte[] key, int splitLen, boolean flag)
            throws Exception {
        int dataLen = encrypted.length;
        // 解密后数据的载体
        List<Byte> allBytes = new ArrayList<>(DEFAULT_KEY_SIZE);
        int latestStartIndex = 0;
        for (int i = 0; i < dataLen; i++) {
            byte bt = encrypted[i];
            boolean isMatchSplit = false;

            if (bt == DEFAULT_SPLIT[0]) {
                // 如果找到以split[0]开头字节，就开始判断其是否为分组标识，如果是就将isMatchSplit改为true
                if (splitLen > 1) {
                    if (i + splitLen < dataLen) {
                        // 没有超出data的范围
                        for (int j = 1; j < splitLen; j++) {
                            if (DEFAULT_SPLIT[j] != encrypted[i + j]) {
                                break;
                            }
                            if (j == splitLen - 1) {
                                // 验证到split的最后一位，都没有break，则表明已经确认是split段（即：是分组标识）
                                isMatchSplit = true;
                            }
                        }
                    }
                } else {
                    // split只有一位，则已经匹配了
                    isMatchSplit = true;
                }
            }
            // 如果isMatchSplit为true，则就进行分割数据串，然后解密后放入allBytes（或者已经是最后一段数据直接加密）
            if (isMatchSplit || i == dataLen - 1) {
                byte[] part = new byte[i - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0, part.length);
                byte[] decryptPart;

                if (flag) {
                    decryptPart = encryptByPublicKey(part, key);
                } else {
                    decryptPart = decryptByPrivateKey(part, key);
                }

                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            }
        }
        // 返回解密后数据
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b;
            }
        }
        return bytes;
    }

}
