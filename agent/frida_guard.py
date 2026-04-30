import frida

class FridaGuard:
    def __init__(self, pid):
        self.pid = pid
        self.session = None

    def start(self):
        try:
            # 附加到刚才启动的目标进程 (如 notepad.exe)
            self.session = frida.attach(self.pid)
            print(f"\n[FridaGuard] 成功附加到进程 PID: {self.pid}")
            
            # 注入底层 API 拦截逻辑 (JavaScript)
            js_code = """
            // 找到 Windows 底层写文件 API 的内存地址
            var WriteFilePtr = Module.findExportByName("kernel32.dll", "WriteFile");
            if (WriteFilePtr) {
                Interceptor.attach(WriteFilePtr, {
                    onEnter: function (args) {
                        var bytesToWrite = args[2].toInt32();
                        // 将拦截到的动作发送回 Python 端
                        send({
                            type: 'write_attempt',
                            bytes: bytesToWrite
                        });
                        
                        // 【进阶防御】如果你想直接干掉另存为，可以在这里抛出异常或修改缓冲区
                        // args[2] = ptr("0"); // 强制写入 0 字节
                    }
                });
                console.log("[FridaGuard] kernel32!WriteFile 拦截已生效！");
            } else {
                console.log("[FridaGuard] 未找到 WriteFile API。");
            }
            """
            script = self.session.create_script(js_code)
            script.on('message', self.on_message)
            script.load()
        except Exception as e:
            print(f"\n[FridaGuard] 注入失败 (如果报无权限，请尝试管理员身份运行): {e}")

    def on_message(self, message, data):
        if message['type'] == 'send':
            payload = message['payload']
            if payload.get('type') == 'write_attempt':
                print(f"[API Hooking 警告] 检测到目标进程正在尝试写入/另存为文件，大小: {payload['bytes']} 字节")

    def stop(self):
        if self.session:
            try:
                self.session.detach()
                print("[FridaGuard] 进程结束，已断开 Hook。")
            except:
                pass