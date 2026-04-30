using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ItdlpWordAddin
{
    /// <summary>
    /// AES-256-GCM 加密 + .itdlp 文件格式封装。
    /// 与 Python 端 common/crypto_utils.py 完全兼容。
    /// </summary>
    public static class CryptoHelper
    {
        // Python 端 MAGIC = b"ITDLPENC2"
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("ITDLPENC2");
        private const int NonceSize = 12;  // GCM nonce
        private const int TagSize = 16;    // GCM authentication tag
        private const int KeySize = 32;    // AES-256

        /// <summary>
        /// 将明文加密为 IT-DLP .itdlp 格式的字节数组。
        ///
        /// .itdlp 格式: MAGIC(8B) + header_len(4B, big-endian) + header_json(UTF-8) + nonce(12B) + ciphertext+tag
        /// </summary>
        /// <param name="plaintext">文档明文内容</param>
        /// <param name="key">AES-256 密钥（32 字节）</param>
        /// <param name="header">文件头元数据（不含 nonce）</param>
        /// <param name="originalFileName">另存为的原始文件名</param>
        /// <returns>完整 .itdlp 文件内容</returns>
        public static byte[] EncryptItdlp(byte[] plaintext, byte[] key,
            Dictionary<string, string> header, string originalFileName)
        {
            if (key == null || key.Length != KeySize)
                throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));

            // 构建 header（不含 nonce，与 Python 端一致）
            var hdr = new Dictionary<string, string>(header);
            hdr["original_name"] = originalFileName;
            hdr["updated_at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();

            string headerJson = JsonSerializer.Serialize(hdr, new JsonSerializerOptions
            {
                WriteIndented = false,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
            byte[] headerBytes = Encoding.UTF8.GetBytes(headerJson);

            // AES-256-GCM 加密
            byte[] nonce = new byte[NonceSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonce);
            }

            // AAD = header JSON (与 Python 端一致: sort_keys=True)
            var aadHdr = new SortedDictionary<string, string>(hdr);
            string aadJson = JsonSerializer.Serialize(aadHdr, new JsonSerializerOptions
            {
                WriteIndented = false,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
            byte[] aad = Encoding.UTF8.GetBytes(aadJson);

            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[TagSize];

            using (var aesGcm = new AesGcm(key, TagSize))
            {
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            }

            // 组装 .itdlp 文件
            // MAGIC(8) + header_len(4, big-endian) + header_json + nonce(12) + ciphertext + tag
            using (var ms = new MemoryStream())
            {
                ms.Write(Magic, 0, Magic.Length);

                // header_len as big-endian uint32
                byte[] lenBytes = new byte[4];
                lenBytes[0] = (byte)((headerBytes.Length >> 24) & 0xFF);
                lenBytes[1] = (byte)((headerBytes.Length >> 16) & 0xFF);
                lenBytes[2] = (byte)((headerBytes.Length >> 8) & 0xFF);
                lenBytes[3] = (byte)(headerBytes.Length & 0xFF);
                ms.Write(lenBytes, 0, 4);

                ms.Write(headerBytes, 0, headerBytes.Length);
                ms.Write(nonce, 0, nonce.Length);
                ms.Write(ciphertext, 0, ciphertext.Length);
                ms.Write(tag, 0, tag.Length);

                return ms.ToArray();
            }
        }

        /// <summary>
        /// 用于 AAD 计算的排序字典。Python 端使用 sort_keys=True。
        /// </summary>
        private class SortedDictionary<TKey, TValue> : SortedDictionary<TKey, TValue>
        {
            public SortedDictionary(IDictionary<TKey, TValue> dictionary)
                : base(dictionary, Comparer<TKey>.Default) { }
        }
    }
}
