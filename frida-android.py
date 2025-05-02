import time
import queue
import threading
import frida
from mcp.server.fastmcp import FastMCP, Context
from typing import Dict, Any

mcp = FastMCP("FridaAndroid")

_usb_device = None

@mcp.tool()
def get_usb_device() -> Any:
    """frida와 USB로 연결된 장치를 찾고 저장하여 다른 도구에서도 사용할 수 있도록 한다. 
    
    Returns:
        device
    """
    global _usb_device
    if _usb_device is None:
        device = frida.get_usb_device()
        _usb_device = device
    return _usb_device

@mcp.tool()
def hook_apk(package: str, hook_script: str, duration: float = 1.0) -> Dict[str, Any]:
    """켜져있지 않은 앱을 후킹하고 스크립트를 삽입하여 처음부터 실행시킨다

    Args:
        package: 후킹할 패키지 이름
        hook_script: Frida Javascript 코드
        duration: 후킹 결과 수집 기간 (기본값 1.0 s)
        
    Returns:
        {
            "pid":     pid,
            "messages": msgs
        }
    """

    script_ext = """
    var _log = console.log;

    console.log = function() {
        var msg = Array.prototype.slice.call(arguments).join(' ');
        send({ type: 'log', payload: msg });
        _log.apply(console, arguments);
    };
    """
    msgs  = []
    try:
        pid = _usb_device.spawn([package])
        session = _usb_device.attach(pid)
        script = session.create_script(script_ext + hook_script)

        ### need fix
        def on_message(message, data):
            msgs.append(message.get("payload"))
        script.on("message", on_message)

        script.load()
        _usb_device.resume(pid)
        time.sleep(duration)

    except Exception as e:
        return {"error": f"HOOK ERROR: {e}"}

    return {
        "pid":     pid,
        "messages": msgs
    }

@mcp.tool()
def kill_process(package: str) -> bool:
    """패키지 이름으로 앱 검색 후 켜져있다면 종료시킨다.
    Args:
        package: 종료할 패키지 이름

    Returns:
        앱이 켜져있어서 정상 종료됐다면 True, 프로세스가 검색되지 않았다면 False 리턴
    """

    ret = False
    processes = _usb_device.enumerate_processes()
    for proc in processes:
        if proc.name == package:
            _usb_device.kill(proc.pid)
            ret = True

    return ret