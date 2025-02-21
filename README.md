# AI HTTP Analyzer for Burp Suite

AI HTTP Analyzer 是一个 Burp Suite 插件，它利用 AI 能力来分析 HTTP 请求和响应，帮助安全测试人员快速识别潜在的安全问题。

## 功能特点

- 支持多种 AI 引擎
  - Burp Suite 内置 AI（需要 Burp Suite Professional 2024.1+ 版本）
  - OpenAI 兼容 API（支持 OpenAI、Azure OpenAI、自部署模型等）
- 智能分析 HTTP 请求/响应
  - 自动识别常见安全漏洞
  - 提供详细的漏洞分析报告
  - 生成可直接使用的 PoC
- 友好的用户界面
  - 请求预览功能
  - 分析历史记录
  - 自定义分析提示
  - 美观的 HTML 格式输出

## 安装要求

- Burp Suite Professional 2024.1 或更高版本
- Jython 2.7+
- 如果使用 Burp AI，需要有足够的 AI Credits
- 如果使用 OpenAI 兼容 API，需要有相应的 API 访问权限

## 安装步骤

1. 在 Burp Suite 中打开 Extensions 标签页
2. 点击 Add 按钮
3. 在 Extension Type 中选择 Python
4. 选择 BurpChinesePlugin.py 文件
5. 点击 Next 完成安装

## 使用方法

### 基本使用
1. 在 Burp Suite 中截获或选择要分析的请求
2. 右键点击请求，选择"发送到 AI HTTP 分析器"
3. 在分析器标签页中查看分析结果

### AI 设置
1. 点击"AI设置"按钮
2. 选择 AI 类型：
   - Burp AI：使用 Burp Suite 内置 AI
   - OpenAI 兼容：使用其他 AI API
3. 如果选择 OpenAI 兼容，需要配置：
   - API URL
   - API Key
   - 模型名称

### 自定义分析
1. 在文本框中输入自定义分析提示
2. 选择是否包含请求和响应内容
3. 点击"开始 AI 分析"按钮

## 分析报告格式

分析报告包含以下部分：
- 安全风险概述
- 详细分析（按风险等级分类）
- 漏洞利用方法和 PoC
- 修复建议

## 注意事项

1. 使用 Burp AI 需要：
   - Burp Suite Professional 许可证
   - 足够的 AI Credits
   - 在 Suite > AI 设置中启用 AI 功能

2. 使用 OpenAI 兼容 API 需要：
   - 有效的 API 访问地址
   - 正确的 API Key
   - 支持的模型名称
## 运行截图

![AI HTTP Analyzer 运行界面](<img width="1568" alt="image" src="https://github.com/user-attachments/assets/51adb8f7-af3b-4e59-910d-2bb2b05ca076" />
)

## 常见问题

Q: 为什么看不到"Use AI"选项？  
A: 确保使用的是 Burp Suite Professional 2024.1+ 版本，并且已启用 AI 功能。

Q: 如何获取 AI Credits？  
A: 访问 PortSwigger 网站的账户页面购买或激活 AI Credits。

Q: 支持哪些 OpenAI 兼容 API？  
A: 支持任何兼容 OpenAI API 格式的服务，包括：
- OpenAI API
- Azure OpenAI
- 自部署的兼容模型（如 LMStudio）

## 贡献指南

欢迎提交 Issue 和 Pull Request 来改进这个项目。

## 许可证

[MIT License](LICENSE)
