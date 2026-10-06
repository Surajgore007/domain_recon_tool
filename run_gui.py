#!/usr/bin/env python3
"""
Launcher script for OSINT Recon Web Dashboard
"""
import sys
import webbrowser
import threading
import time

def open_browser(url: str, delay: float = 1.2):
    time.sleep(delay)
    try:
        webbrowser.open(url)
    except Exception:
        pass

if __name__ == "__main__":
    url = "http://127.0.0.1:8000"
    threading.Thread(target=open_browser, args=(url,), daemon=True).start()
    
    import uvicorn
    from app import app
    print(f"\n========================================================")
    print(f"  OSINT Recon Web Platform running at: {url}")
    print(f"  Press Ctrl+C to stop the server")
    print(f"========================================================\n")
    uvicorn.run(app, host="127.0.0.1", port=8000)
