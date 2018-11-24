<?php

namespace Id0612\Crypt;

include_once __DIR__ . '/Pkcs7.php';

/**
 * 提供加解密接口
 * @author Anran <id0612@qq.com>
 */
final class Prpcrypt {

    /**
     * 对明文进行加密
     * @param string $text 需要加密的明文
     * @param string $encoding_aes_key EncodingAESKey
     * @return array [0, '加密后的密文'] 或 [1, '错误消息']
     */
    public static function encrypt($text, $encoding_aes_key) {
        try {
            // 获得Key
            $key = base64_decode($encoding_aes_key);

            // 获得16位随机字符串，填充到明文之前
            $random = self::get_rand_str();
            $text = $random . pack('N', strlen($text)) . $text;

            // 网络字节序
            $iv = substr($key, 0, 16);

            // 使用自定义的填充方式对明文进行补位填充
            $text = PKCS7::encode($text);

            // 加密
            $encrypted = openssl_encrypt($text, 'AES-256-CBC', substr($key, 0, 32), OPENSSL_ZERO_PADDING, $iv);

            return array(0, $encrypted);
        } catch (\Exception $e) {
            return array(1, $e->getMessage());
        }
    }

    /**
     * 对密文进行解密
     * @param string $encrypted 需要解密的密文
     * @param string $encoding_aes_key EncodingAESKey
     * @return array [0, '解密得到的明文'] 或 [1, '错误消息']
     */
    public static function decrypt($encrypted, $encoding_aes_key) {
        try {
            // 获得Key
            $key = base64_decode($encoding_aes_key);

            // 网络字节序
            $iv = substr($key, 0, 16);

            // 解密
            $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', substr($key, 0, 32), OPENSSL_ZERO_PADDING, $iv);
        } catch (\Exception $e) {
            return array(1, $e->getMessage());
        }

        try {
            // 去除补位字符
            $result = PKCS7::decode($decrypted);

            // 去除16位随机字符串,网络字节序
            $len = strlen($result);
            if ($len < 16) {
                return array(1, '解密错误');
            }
            $content = substr($result, 16, $len);
            $len_list = unpack('N', substr($content, 0, 4));
            $xml_len = $len_list[1];
            $xml_content = substr($content, 4, $xml_len);
            unset($len, $xml_len, $len_list);
        } catch (\Exception $e) {
            return array(1, $e->getMessage());
        }

        return array(0, $xml_content);
    }

    /**
     * 随机生成16位字符串
     * @return string 生成的字符串
     */
    private static function get_rand_str() {
        $str = '';
        $str_pol = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz';
        $max = strlen($str_pol) - 1;
        for ($i = 0; $i < 16; ++$i) {
            $str .= $str_pol[mt_rand(0, $max)];
        }
        unset($str_pol);

        return $str;
    }

}
