# -*- coding: utf-8 -*-

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController
from javax.swing import JPanel, JLabel, JTextField, JButton, JTabbedPane, BoxLayout, JScrollPane
from javax.swing import JSplitPane, JEditorPane, JComboBox, JCheckBox, SwingConstants, JMenuItem, JPasswordField, JDialog, JOptionPane
from java.awt import Component, BorderLayout, FlowLayout, Font, Color, Dimension, Insets
from java.util import ArrayList, Date, Set
from java.text import SimpleDateFormat
from javax.swing.border import EmptyBorder
from threading import Thread
import time
from java.awt.event import WindowAdapter
from java.net import URL
from java.io import DataOutputStream, BufferedReader, InputStreamReader, IOException
from javax.net.ssl import SSLContext, TrustManager, X509TrustManager
import json

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("AI HTTP Analyzer")
        
        self._initUI()
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        
        self.analysisHistory = {}
        self.MAX_HISTORY = 100
        
        # 添加AI设置
        self.ai_settings = {
            'api_type': 'burp',  # 默认使用burp ai
            'api_url': '',
            'api_key': '',
            'model': 'gpt-3.5-turbo'  # 默认模型
        }
        
        # 加载保存的设置
        self._loadSettings()
        
        # 注册AI功能
        try:
            # 尝试注册AI功能
            callbacks.registerExtensionProvidedAuthenticationHandler(None)
        except:
            callbacks.printError("Failed to register AI capabilities")
        
        callbacks.printOutput("AI HTTP Analyzer loaded successfully!")

    def _initUI(self):
        self._mainPanel = JPanel(BorderLayout())
        self._mainPanel.setBorder(EmptyBorder(5,5,5,5))
        self._tabbedPane = JTabbedPane()
        self._createNewTab(u"\u9ed8\u8ba4")  # "默认"
        self._mainPanel.add(self._tabbedPane, BorderLayout.CENTER)

    def _createNewTab(self, title, requestResponse=None):
        verticalSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        horizontalSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        self._requestEditor = self._callbacks.createMessageEditor(self, True)
        self._responseEditor = self._callbacks.createMessageEditor(self, False)
        
        if requestResponse:
            self._requestEditor.setMessage(requestResponse.getRequest(), True)
            self._responseEditor.setMessage(requestResponse.getResponse(), False)
            
        horizontalSplit.setLeftComponent(self._requestEditor.getComponent())
        horizontalSplit.setRightComponent(self._responseEditor.getComponent())
        horizontalSplit.setResizeWeight(0.5)
        
        self._aiResponseArea = JEditorPane()
        self._aiResponseArea.setContentType("text/html")
        self._aiResponseArea.setEditable(False)
        aiScrollPane = JScrollPane(self._aiResponseArea)
        
        bottomPanel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 10))
        
        self._includeReqResp = JCheckBox(u"\u5305\u542b\u8bf7\u6c42\u548c\u54cd\u5e94")  # "包含请求和响应"
        self._includeReqResp.setSelected(True)
        
        self._customInput = JTextField(20)
        self._customInput.setPreferredSize(Dimension(200, 35))
        self._customInput.putClientProperty("JTextField.placeholderText", 
            u"\u5728\u6b64\u8f93\u5165\u81ea\u5b9a\u4e49\u5206\u6790\u63d0\u793a...")  # "在此输入自定义分析提示..."
        
        analyzeButton = JButton(u"\u5f00\u59cb AI \u5206\u6790")  # "开始 AI 分析"
        analyzeButton.setBackground(Color(0, 120, 212))
        analyzeButton.setForeground(Color.WHITE)
        analyzeButton.setFont(Font("Microsoft YaHei", Font.PLAIN, 13))
        analyzeButton.setFocusPainted(False)
        analyzeButton.setBorderPainted(False)
        analyzeButton.setPreferredSize(Dimension(120, 35))
        analyzeButton.addActionListener(self._onAnalyzeClick)
        
        self._historyCombo = JComboBox()
        self._historyCombo.setPreferredSize(Dimension(150, 35))
        self._historyCombo.addItem(u"--- \u5206\u6790\u5386\u53f2 ---")  # "--- 分析历史 ---"
        self._historyCombo.addActionListener(self._onHistorySelect)
        
        settingsButton = JButton(u"AI设置")
        settingsButton.addActionListener(self._showSettingsDialog)
        
        bottomPanel.add(self._includeReqResp)
        bottomPanel.add(self._customInput)
        bottomPanel.add(analyzeButton)
        bottomPanel.add(self._historyCombo)
        bottomPanel.add(settingsButton)
        
        verticalSplit.setTopComponent(horizontalSplit)
        verticalSplit.setBottomComponent(aiScrollPane)
        verticalSplit.setResizeWeight(0.7)
        
        # 添加请求预览区域
        previewPanel = JPanel(BorderLayout())
        previewLabel = JLabel(u"当前分析的请求：")
        previewArea = JEditorPane()
        previewArea.setContentType("text/plain; charset=utf-8")
        previewArea.setEditable(False)
        previewScroll = JScrollPane(previewArea)
        previewScroll.setPreferredSize(Dimension(0, 100))
        
        if requestResponse:
            request = self._helpers.bytesToString(requestResponse.getRequest())
            preview = request.split('\r\n\r\n')[0] if '\r\n\r\n' in request else request
            previewArea.setText(preview)
        else:
            previewArea.setText(u"未加载请求")
        
        previewPanel.add(previewLabel, BorderLayout.NORTH)
        previewPanel.add(previewScroll, BorderLayout.CENTER)
        
        # 修改布局
        mainPanel = JPanel(BorderLayout())
        mainPanel.add(verticalSplit, BorderLayout.CENTER)
        mainPanel.add(previewPanel, BorderLayout.NORTH)
        mainPanel.add(bottomPanel, BorderLayout.SOUTH)
        
        self._tabbedPane.addTab(title, mainPanel)
        self._tabbedPane.setSelectedIndex(self._tabbedPane.getTabCount()-1)

    def _onAnalyzeClick(self, event):
        Thread(target=self._analyzeRequest).start()

    def _analyzeRequest(self):
        try:
            # 更新UI状态
            self._aiResponseArea.setContentType("text/html; charset=utf-8")
            self._aiResponseArea.setText(u"正在准备分析请求...")
            
            request = self._requestEditor.getMessage()
            response = self._responseEditor.getMessage()
            customInput = self._customInput.getText()
            includeReqResp = self._includeReqResp.isSelected()
            
            if not (request or customInput):
                self._aiResponseArea.setText(u"错误：请提供HTTP请求或自定义提示")
                return
            
            self._aiResponseArea.setText(u"正在连接AI服务...")
            
            try:
                promptText = self._buildPromptText(includeReqResp, customInput, request, response)
                
                if self.ai_settings['api_type'] == 'burp':
                    self._aiResponseArea.setText(u"正在使用Burp AI分析...")
                    aiResponse = self._callbacks.ai().prompt().execute([
                        {"role": "system", "content": SYSTEM_MESSAGE},
                        {"role": "user", "content": promptText}
                    ])
                    content = aiResponse.content()
                else:
                    self._aiResponseArea.setText(u"正在使用OpenAI兼容API分析...")
                    headers = {
                        "Authorization": "Bearer " + self.ai_settings['api_key'],
                        "Content-Type": "application/json"
                    }
                    data = {
                        "model": self.ai_settings['model'],
                        "messages": [
                            {"role": "system", "content": SYSTEM_MESSAGE},
                            {"role": "user", "content": promptText}
                        ]
                    }
                    
                    # 添加详细的错误处理
                    try:
                        response = self._http_request(
                            self.ai_settings['api_url'],
                            headers,
                            data
                        )
                        content = response['choices'][0]['message']['content']
                    except Exception as e:
                        self._callbacks.printError(u"API请求失败: " + str(e))
                        if "401" in str(e):
                            raise Exception(u"API认证失败，请检查API Key")
                        elif "404" in str(e):
                            raise Exception(u"API地址错误，请检查URL")
                        else:
                            raise Exception(u"API请求失败: " + str(e))
                
                self._saveToHistory(promptText, content)
                
                # 格式化输出
                if content:
                    formatted_content = """
<html>
<head>
<meta charset="utf-8">
<style>
body { font-family: "Microsoft YaHei", Arial, sans-serif; margin: 20px; }
h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
.risk { color: #e74c3c; font-weight: bold; }
.high { color: #c0392b; }
.medium { color: #e67e22; }
.low { color: #f1c40f; }
.details { margin-left: 20px; }
.payload { background-color: #f8f9fa; padding: 10px; border-left: 3px solid #3498db; margin: 10px 0; }
</style>
</head>
<body>
""" + content + """
</body>
</html>
"""
                    self._aiResponseArea.setText(formatted_content)
                else:
                    self._aiResponseArea.setText("未获得有效响应")
                
            except Exception as e:
                error_msg = str(e)
                self._callbacks.printError(error_msg)
                self._aiResponseArea.setText(u"分析失败: " + error_msg + 
                    u"\n\n请检查:\n1. AI服务配置是否正确\n2. 网络连接是否正常\n3. API密钥是否有效")
                
        except Exception as e:
            self._callbacks.printError(u"未知错误: " + str(e))
            self._aiResponseArea.setText(u"发生错误: " + str(e))

    def _buildPromptText(self, includeReqResp, customInput, request, response):
        promptText = []
        
        if includeReqResp and request:
            promptText.append(u"分析以下HTTP请求的安全问题:\n")
            promptText.append(u"请求:\n" + self._helpers.bytesToString(request))
            
            if response:
                promptText.append(u"\n响应:\n" + self._helpers.bytesToString(response))
                
        if customInput:
            promptText.append("\n" + customInput)
            
        return "\n".join(promptText)

    def _saveToHistory(self, prompt, response):
        timestamp = SimpleDateFormat("HH:mm:ss").format(Date())
        key = timestamp + " - " + (prompt[:27] + "..." if len(prompt) > 30 else prompt)
        
        self.analysisHistory[key] = response
        self._historyCombo.addItem(key)
        
        # 限制历史记录数量
        if len(self.analysisHistory) > self.MAX_HISTORY:
            oldestKey = next(iter(self.analysisHistory))
            del self.analysisHistory[oldestKey]
            self._historyCombo.removeItem(oldestKey)

    def _onHistorySelect(self, event):
        selected = self._historyCombo.getSelectedItem()
        if selected and selected != u"--- \u5206\u6790\u5386\u53f2 ---":
            self._aiResponseArea.setText(self.analysisHistory[selected])

    # ITab implementation
    def getTabCaption(self):
        return u"AI \u5206\u6790\u5668"  # "AI 分析器"
        
    def getUiComponent(self):
        return self._mainPanel

    # IContextMenuFactory implementation  
    def createMenuItems(self, event):
        menuItems = ArrayList()
        menuItems.add(JMenuItem(u"\u53d1\u9001\u5230 AI HTTP \u5206\u6790\u5668",  # "发送到 AI HTTP 分析器"
            actionPerformed=lambda x: self._sendToTab(event)))
        return menuItems

    def _sendToTab(self, event):
        self._createNewTab(u"\u5206\u6790 " + str(self._tabbedPane.getTabCount()),  # "分析 "
            event.getSelectedMessages()[0])

    # IScannerInsertionPointProvider implementation
    def getInsertionPoints(self, baseRequestResponse):
        return None

    def _showSettingsDialog(self, event):
        dialog = JDialog(None, u"AI\u8bbe\u7f6e", True)  # "AI设置"
        panel = JPanel(BorderLayout(10, 10))
        
        # API类型选择
        apiTypePanel = JPanel(FlowLayout(FlowLayout.LEFT))
        apiTypePanel.add(JLabel(u"API\u7c7b\u578b: "))  # "API类型: "
        apiTypeCombo = JComboBox([u"Burp AI", u"OpenAI\u517c\u5bb9"])  # "Burp AI", "OpenAI兼容"
        apiTypeCombo.setSelectedItem(u"Burp AI" if self.ai_settings['api_type'] == 'burp' else u"OpenAI\u517c\u5bb9")
        apiTypePanel.add(apiTypeCombo)
        
        # API URL输入
        urlPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        urlPanel.add(JLabel(u"API URL: "))
        urlField = JTextField(self.ai_settings['api_url'], 30)
        urlPanel.add(urlField)
        
        # API Key输入
        keyPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        keyPanel.add(JLabel(u"API Key: "))
        keyField = JPasswordField(self.ai_settings['api_key'], 30)
        keyPanel.add(keyField)
        
        # 模型选择
        modelPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        modelPanel.add(JLabel(u"\u6a21\u578b: "))  # "模型: "
        modelField = JTextField(self.ai_settings['model'], 20)
        modelPanel.add(modelField)
        
        # 保存按钮
        saveButton = JButton(u"\u4fdd\u5b58")  # "保存"
        def saveSettings(evt):
            self.ai_settings.update({
                'api_type': 'burp' if apiTypeCombo.getSelectedItem() == u"Burp AI" else 'openai',
                'api_url': urlField.getText(),
                'api_key': ''.join(keyField.getPassword()),
                'model': modelField.getText()
            })
            self._saveSettings()
            dialog.dispose()
            JOptionPane.showMessageDialog(None, u"\u8bbe\u7f6e\u5df2\u4fdd\u5b58")  # "设置已保存"
            
        saveButton.addActionListener(saveSettings)
        
        # 组装面板
        inputPanel = JPanel()
        inputPanel.setLayout(BoxLayout(inputPanel, BoxLayout.Y_AXIS))
        inputPanel.add(apiTypePanel)
        inputPanel.add(urlPanel)
        inputPanel.add(keyPanel)
        inputPanel.add(modelPanel)
        
        panel.add(inputPanel, BorderLayout.CENTER)
        panel.add(saveButton, BorderLayout.SOUTH)
        
        dialog.add(panel)
        dialog.pack()
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)

    def _loadSettings(self):
        try:
            settings = self._callbacks.loadExtensionSetting("ai_settings")
            if settings:
                import json
                self.ai_settings.update(json.loads(settings))
        except:
            pass

    def _saveSettings(self):
        try:
            import json
            self._callbacks.saveExtensionSetting("ai_settings", 
                json.dumps(self.ai_settings))
        except:
            pass

    # 添加一个简单的TrustManager来处理HTTPS
    class TrustAllCerts(X509TrustManager):
        def checkClientTrusted(self, chain, auth):
            pass
        
        def checkServerTrusted(self, chain, auth):
            pass
        
        def getAcceptedIssuers(self):
            return None

    # 在BurpExtender类中添加HTTP请求方法
    def _http_request(self, url, headers, data):
        # 设置信任所有证书
        trust_all_certs = [self.TrustAllCerts()]
        sc = SSLContext.getInstance("SSL")
        sc.init(None, trust_all_certs, None)
        
        # 创建连接
        url = URL(url)
        conn = url.openConnection()
        conn.setSSLSocketFactory(sc.getSocketFactory())
        
        # 设置超时
        conn.setConnectTimeout(10000)  # 10秒连接超时
        conn.setReadTimeout(30000)     # 30秒读取超时
        
        try:
            # 设置请求方法和headers
            conn.setRequestMethod("POST")
            for key, value in headers.items():
                conn.setRequestProperty(key, value)
            
            # 发送数据
            conn.setDoOutput(True)
            output = None
            input_stream = None
            reader = None
            
            try:
                output = DataOutputStream(conn.getOutputStream())
                output.writeBytes(json.dumps(data))
                output.flush()
                
                # 读取响应
                response = ""
                input_stream = conn.getInputStream()
                reader = BufferedReader(InputStreamReader(input_stream, "UTF-8"))
                
                line = reader.readLine()
                while line is not None:
                    response += line
                    line = reader.readLine()
                
                return json.loads(response)
                
            except IOException as e:
                # 获取错误流
                error_stream = conn.getErrorStream()
                if error_stream:
                    error_reader = BufferedReader(InputStreamReader(error_stream))
                    error_response = ""
                    line = error_reader.readLine()
                    while line is not None:
                        error_response += line
                        line = error_reader.readLine()
                    raise Exception("API错误: " + error_response)
                else:
                    raise Exception("连接错误: " + str(e))
                
            finally:
                if output: output.close()
                if reader: reader.close()
                if input_stream: input_stream.close()
                
        except Exception as e:
            raise Exception("请求失败: " + str(e))

# System prompt message
SYSTEM_MESSAGE = u"""你是 AI HTTP 分析器，一个集成到 Burp Suite 中的高级安全分析助手。
分析HTTP请求和响应时，请使用以下HTML格式输出：

<h2>安全风险概述</h2>
{高/中/低风险项的总结}

<h2>详细分析</h2>
<div class="risk high">高风险</div>
<div class="details">
- 具体问题描述
- 影响
- 利用方法
</div>

<h2>漏洞利用</h2>
<div class="payload">
具体的Payload或PoC代码
</div>

<h2>修复建议</h2>
- 具体的修复方案
- 配置建议
- 最佳实践

请保持专业性和可操作性，避免冗长的理论讨论。
所有输出使用中文，并严格按照上述HTML格式。""" 
