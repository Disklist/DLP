using System;
using System.IO;
using System.Windows.Forms;
using Word = Microsoft.Office.Interop.Word;

namespace ItDlpWordAddIn
{
    public partial class ThisAddIn
    {
        private bool _isIntercepting = false;

        private void ThisAddIn_Startup(object sender, System.EventArgs e)
        {
            // 确保事件成功绑定！
            this.Application.DocumentBeforeSave += Application_DocumentBeforeSave;
        }

        private void Application_DocumentBeforeSave(Word.Document Doc, ref bool SaveAsUI, ref bool Cancel)
        {
            // 如果已经在拦截处理中，防止死循环
            if (_isIntercepting) return;

            try
            {
                _isIntercepting = true;

                // 【暴力测试点】只要触发，第一时间弹窗。如果连这个都没弹，说明插件没加载！
                MessageBox.Show($"进入拦截器！\n当前是另存为吗？ SaveAsUI = {SaveAsUI}", "调试信息");

                if (SaveAsUI || string.IsNullOrEmpty(Doc.Path))
                {
                    // 强制弹窗我们自己的另存为
                    using (SaveFileDialog sfd = new SaveFileDialog())
                    {
                        sfd.Filter = "IT-DLP 加密文档 (*.itdlp)|*.itdlp";
                        sfd.Title = "IT-DLP 强制安全保存 (测试版)";
                        sfd.FileName = Path.GetFileNameWithoutExtension(Doc.Name) + ".itdlp";

                        if (sfd.ShowDialog() == DialogResult.OK)
                        {
                            // 模拟加密写盘
                            File.WriteAllText(sfd.FileName, "这是一段被 IT-DLP 模拟加密的内容。");
                            MessageBox.Show($"接管成功！已伪造加密文件至:\n{sfd.FileName}", "成功");
                            
                            // 骗过 Word 把它标记为已保存
                            Doc.Saved = true;
                        }
                    }

                    // 【核心】杀掉 Word 的原生保存动作！
                    Cancel = true; 
                }
                else
                {
                    // 常规 Ctrl+S 
                    MessageBox.Show("常规保存被拦截！", "调试信息");
                    Cancel = true; // 同样杀掉原生保存
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("发生错误: " + ex.Message);
                Cancel = true; 
            }
            finally
            {
                _isIntercepting = false;
            }
        }

        private void ThisAddIn_Shutdown(object sender, System.EventArgs e)
        {
            this.Application.DocumentBeforeSave -= Application_DocumentBeforeSave;
        }

        #region VSTO generated code
        private void InternalStartup()
        {
            this.Startup += new System.EventHandler(ThisAddIn_Startup);
            this.Shutdown += new System.EventHandler(ThisAddIn_Shutdown);
        }
        #endregion
    }
}