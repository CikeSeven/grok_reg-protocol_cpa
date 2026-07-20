@echo off

:: 检测PowerShell是否可用
powershell -Command "Write-Host 'PowerShell available'" >nul 2>&1
if %errorlevel% equ 0 (
    :: PowerShell可用，使用PowerShell运行
    echo 正在启动PowerShell终端...
    powershell -ExecutionPolicy Bypass -File "%~dp0Start-TurnstileSolver.ps1"
) else (
    :: PowerShell不可用，使用CMD运行
    echo PowerShell不可用，使用CMD运行...
    
    :: 强制使用UTF-8编码
    chcp 65001 >nul
    
    :: 延迟启动，防止闪退
    timeout /t 1 /nobreak >nul
    
    echo ============================================================
    echo Turnstile Solver - 验证码解决服务
    echo ============================================================
    echo.
    echo 启动配置选项：
    echo 1. Chromium (默认) - 通用浏览器，兼容性好
    echo 2. Chrome - 官方Chrome浏览器
    echo 3. Edge - Microsoft Edge浏览器
    echo 4. Camoufox - 浏览器指纹伪装
    echo.
    echo 请选择浏览器类型 (1-4, 默认1):
    set /p browser_choice=
    
    if "%browser_choice%"=="" set browser_choice=1
    
    set "browser_type=chromium"
    if "%browser_choice%"=="2" set "browser_type=chrome"
    if "%browser_choice%"=="3" set "browser_type=msedge"
    if "%browser_choice%"=="4" set "browser_type=camoufox"
    
    echo.
    echo 请输入线程数 (默认5, 建议5-10):
    set /p thread_count=
    
    if "%thread_count%"=="" set thread_count=5
    
    echo.
    echo ============================================================
    echo 系统检查...
    echo ============================================================
    
    :: 创建错误日志文件
    echo [%date% %time%] 启动Turnstile Solver > solver_log.txt
    
    :: 检查Python是否安装
    echo 检查Python是否安装...
    python --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo 错误: 未找到Python，请先安装Python 3.8+
        echo 请访问 https://www.python.org/downloads/ 下载安装
        echo 错误: 未找到Python >> solver_log.txt
        echo.
        pause
        exit /b 1
    )
    echo Python已安装
    echo Python已安装 >> solver_log.txt
    
    :: 检查Python版本
    echo 检查Python版本...
    for /f "tokens=2 delims=." %%i in ('python --version 2^>^&1') do set python_major=%%i
    echo Python主版本: %python_major% >> solver_log.txt
    
    if %python_major% lss 8 (
        echo 错误: Python版本过低，需要Python 3.8+
        echo 当前版本: %python_version%
        echo 错误: Python版本过低 >> solver_log.txt
        echo.
        pause
        exit /b 1
    )
    echo Python版本检查通过
    echo Python版本检查通过 >> solver_log.txt
    
    :: 检查依赖是否安装
    echo 检查依赖包...
    python -c "import quart, playwright, camoufox" >nul 2>&1
    if %errorlevel% neq 0 (
        echo 警告: 缺少依赖包，正在安装...
        echo 警告: 缺少依赖包，正在安装... >> solver_log.txt
        pip install -r requirements.txt >nul 2>&1
        if %errorlevel% neq 0 (
            echo 错误: 依赖包安装失败
            echo 请手动运行: pip install -r requirements.txt
            echo 错误: 依赖包安装失败 >> solver_log.txt
            echo.
            pause
            exit /b 1
        )
        echo 依赖包安装成功
        echo 依赖包安装成功 >> solver_log.txt
    ) else (
        echo 依赖包检查通过
        echo 依赖包检查通过 >> solver_log.txt
    )
    
    :: 检查playwright浏览器是否安装
    echo 检查Playwright浏览器...
    python -m playwright install chromium >nul 2>&1
    if %errorlevel% neq 0 (
        echo 警告: Playwright浏览器安装失败
        echo 请手动运行: python -m playwright install
        echo 警告: Playwright浏览器安装失败 >> solver_log.txt
        echo.
    )
    echo Playwright浏览器检查完成
    echo Playwright浏览器检查完成 >> solver_log.txt
    
    echo.
    echo ============================================================
    echo 启动 Turnstile Solver
    echo ============================================================
    echo 浏览器类型: %browser_type%
    echo 线程数: %thread_count%
    echo 监听地址: http://127.0.0.1:5072
    echo.
    echo 提示:
    echo - 请保持此窗口运行，不要关闭！
    echo - 启动成功后，在另一个窗口运行注册程序
    echo - 如需停止，请按 Ctrl+C
    echo ============================================================
    echo.
    echo 正在启动服务...
    echo 正在启动服务: browser_type=%browser_type%, thread=%thread_count% >> solver_log.txt
    echo.
    
    :: 启动Turnstile Solver
    python api_solver.py --browser_type %browser_type% --thread %thread_count%
    
    if %errorlevel% neq 0 (
        echo.
    echo ============================================================
    echo 启动失败！
    echo ============================================================
    echo.
    echo 可能的原因：
    echo 1. 端口 5072 已被占用
    echo 2. 浏览器类型不支持
    echo 3. 系统资源不足
    echo 4. 网络连接问题
    echo.
    echo 解决方法：
    echo 1. 检查是否有其他Turnstile Solver实例在运行
    echo 2. 尝试选择不同的浏览器类型
    echo 3. 减少线程数
    echo 4. 检查网络连接
    echo.
    echo 详细错误信息已记录到 solver_log.txt
    echo 错误代码: %errorlevel% >> solver_log.txt
    pause
    exit /b 1
    )
)
