@echo off
setlocal
cd /d "%~dp0"

echo Building DynamicsSLTrafficProcessor...
echo.

if not exist "gradlew.bat" (
    echo ERROR: gradlew.bat not found in %CD%
    exit /b 1
)

call gradlew.bat jar %*
if errorlevel 1 (
    echo.
    echo BUILD FAILED
    exit /b 1
)

echo.
echo BUILD SUCCESSFUL
echo.
echo JAR:
dir /b "build\libs\DynamicsSLTrafficProcessor-*.jar" 2>nul
if exist "build\libs\DynamicsSLTrafficProcessor-1.0.jar" (
    echo.
    echo Full path:
    echo   %CD%\build\libs\DynamicsSLTrafficProcessor-1.0.jar
)

endlocal
exit /b 0
