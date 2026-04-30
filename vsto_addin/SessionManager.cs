using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace ItdlpWordAddin
{
    /// <summary>
    /// DLP 会话信息 — 由 Python Agent 在启动 Office 前写入 %TEMP%\itdlp_session.json，
    /// VSTO 加载项读取此文件获取加密密钥和临时文件路径。
    /// </summary>
    public class DlpSession
    {
        /// <summary>Python Agent 解密的临时文件绝对路径</summary>
        public string TempFilePath { get; set; } = "";

        /// <summary>AES-256 密钥（Base64 URL-safe 编码，由 Python encode_key 生成）</summary>
        public string KeyBase64 { get; set; } = "";

        /// <summary>加密文件头元数据</summary>
        public Dictionary<string, string> Header { get; set; } = new();

        /// <summary>Python Agent 进程 PID（用于检测会话是否仍然有效）</summary>
        public int AgentPid { get; set; }

        // ── 派生属性 ──────────────────────────────────────

        /// <summary>原始 AES-256 密钥字节（32 bytes）</summary>
        public byte[] Key => string.IsNullOrEmpty(KeyBase64)
            ? throw new InvalidOperationException("KeyBase64 is empty")
            : DecodeUrlSafeBase64(KeyBase64);

        /// <summary>会话是否有效（Python Agent 进程仍在运行）</summary>
        public bool IsValid
        {
            get
            {
                if (AgentPid <= 0) return false;
                try
                {
                    var proc = System.Diagnostics.Process.GetProcessById(AgentPid);
                    return !proc.HasExited;
                }
                catch
                {
                    return false;
                }
            }
        }

        private static byte[] DecodeUrlSafeBase64(string s)
        {
            // URL-safe Base64 → standard Base64
            string b64 = s.Replace('-', '+').Replace('_', '/');
            switch (b64.Length % 4)
            {
                case 2: b64 += "=="; break;
                case 3: b64 += "="; break;
            }
            return Convert.FromBase64String(b64);
        }
    }

    /// <summary>
    /// 管理 DLP 会话文件的加载与清理。
    /// </summary>
    public static class SessionManager
    {
        private static readonly string SessionFilePath =
            Path.Combine(Path.GetTempPath(), "itdlp_session.json");

        /// <summary>当前活跃的会话（null 表示非 DLP 场景）</summary>
        public static DlpSession Current { get; private set; }

        /// <summary>
        /// 从 %TEMP%\itdlp_session.json 加载会话。
        /// 写入方为 Python Agent（agent/core.py）。
        /// </summary>
        public static void LoadSession()
        {
            Current = null;
            try
            {
                if (!File.Exists(SessionFilePath)) return;

                string json = File.ReadAllText(SessionFilePath, System.Text.Encoding.UTF8);
                var session = JsonSerializer.Deserialize<DlpSession>(json,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (session == null) return;

                // 检查会话是否仍然有效
                if (!session.IsValid)
                {
                    // Agent 已退出，清理残留会话文件
                    try { File.Delete(SessionFilePath); } catch { }
                    return;
                }

                if (string.IsNullOrEmpty(session.KeyBase64)) return;
                if (string.IsNullOrEmpty(session.TempFilePath)) return;

                Current = session;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[IT-DLP] 加载会话文件失败: {ex.Message}");
                Current = null;
            }
        }

        /// <summary>
        /// 清理会话文件（由 Python Agent 在进程退出后调用，或 VSTO 自行清理）。
        /// </summary>
        public static void ClearSession()
        {
            Current = null;
            try
            {
                if (File.Exists(SessionFilePath))
                    File.Delete(SessionFilePath);
            }
            catch { }
        }
    }
}
