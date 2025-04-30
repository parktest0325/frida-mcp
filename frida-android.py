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
    """frida 와 USB로 연결된 장치의 ID를 찾고 저장한다
    
    Returns:
        device ID
    """
    global _usb_device
    if _usb_device is None:
        device = frida.get_usb_device()
        _usb_device = device
    return _usb_device

@mcp.tool()
def hook_apk(package: str, hook_script: str, duration: float = 1.0) -> Dict[str, Any]:
    """지정한 앱을 후킹하여 스크립트를 삽입하고 처음부터 실행시킨다

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
    msg_queue = queue.Queue()
    try:
        pid = _usb_device.spawn([package])
        session = _usb_device.attach(pid)
        script = session.create_script(hook_script)

        ### need fix
        def on_message(message, data):
            msg_queue.put(message.get("payload"))
        script.on("message", on_message)

        script.load()
        _usb_device.resume(pid)

        
        time.sleep(duration)
        msgs = []
        while not msg_queue.empty():
            msgs.append(msg_queue.get_nowait())

    except Exception as e:
        return {"error": f"HOOK ERROR: {e}"}

    return {
        "pid":     pid,
        "messages": msgs
    }
