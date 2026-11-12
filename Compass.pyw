#!pythonw
"""Compass launcher (no console window).

Double-click the "Compass" shortcut that "Install Compass.bat" creates, or
this file directly. It starts the Compass server and opens it in your browser.
Because it runs through Windows' own signed pythonw.exe, Smart App Control does
not block it. Messages and errors go to data\\compass.log.
"""
import os
import socket
import sys
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

PORT = int(os.environ.get("COMPASS_PORT", "8765"))


def _already_running():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", PORT))
        return True
    except Exception:
        return False
    finally:
        s.close()


if _already_running():
    # Compass is already up on this PC; just bring the browser to it.
    webbrowser.open("http://127.0.0.1:%d" % PORT)
    sys.exit(0)

import server
server.main()
