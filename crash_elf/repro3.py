import faulthandler, os, sys
sys.path.insert(0, r"C:\Users\WYH\Desktop\pwn宝\pwn宝")
faulthandler.enable()
os.environ.pop("QT_QPA_PLATFORM", None)
# 不安装 sys.excepthook：PyQt5 对未捕获 slot 异常会 qFatal(abort) = 用户闪退
# traceback 会先打到 stderr，我们抓它。

from PyQt5.QtCore import QCoreApplication, Qt, QTimer
QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
from PyQt5.QtWidgets import QApplication

app = QApplication([])

from pwnbao.gui.main_window import MainWindow
w = MainWindow()
w.show()
app.processEvents()
print("== window up ==", flush=True)

from PyQt5.QtCore import QPoint, QMimeData as MD, QUrl
from PyQt5.QtGui import QDragEnterEvent, QDropEvent

mime = MD()
mime.setUrls([QUrl.fromLocalFile(r"C:\Users\WYH\Desktop\pwn宝\crash_elf\pwn")])

def do_drop(widget, pos):
    widget.event(QDragEnterEvent(pos, Qt.CopyAction, mime, Qt.LeftButton, Qt.NoModifier))
    widget.event(QDropEvent(pos, Qt.CopyAction, mime, Qt.LeftButton, Qt.NoModifier))
    app.processEvents()

print("== drop main window ==", flush=True)
do_drop(w, QPoint(800, 400))
print("== drop import page ==", flush=True)
do_drop(w.import_page, QPoint(100, 100))
if hasattr(w, "monaco_editor"):
    print("== drop monaco view ==", flush=True)
    do_drop(w.monaco_editor.view, QPoint(100, 100))
print("== pumping 45s for workflow+pwndbg ==", flush=True)

def finish():
    print("== SURVIVED ==", flush=True)
    app.quit()

QTimer.singleShot(45000, finish)
while True:
    app.processEvents()
    import time as _t
    _t.sleep(0.05)
