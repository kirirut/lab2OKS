import sys
import threading
import struct
from dataclasses import dataclass
from typing import Optional, List
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton,
    QComboBox, QHBoxLayout, QVBoxLayout, QPlainTextEdit, QLineEdit, QMessageBox
)
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon
import serial
import serial.tools.list_ports


# ---------------- Frame structure / constants ----------------
FRAME_DELIMITER_BYTE = 22  # 0b00010110
FRAME_DELIMITER_BITS = '00010110'
FLAG_VALUE = FRAME_DELIMITER_BYTE
MAX_PAYLOAD_SIZE = 65535


# ---------------- bit/byte helper functions ----------------
def bytes_to_bits(b: bytes) -> str:
    return ''.join(f"{byte:08b}" for byte in b)


def bits_to_bytes(bits: str) -> bytes:
    if len(bits) % 8:
        bits += '0' * (8 - (len(bits) % 8))
    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(int(bits[i:i + 8], 2))
    return bytes(out)


def bytes_to_binary(b: bytes) -> str:
    return ' '.join(f"{byte:08b}" for byte in b)


def group_bits_str(bits: str) -> str:
    return ' '.join(bits[i:i + 8] for i in range(0, len(bits), 8))


def bin_str(val: int, bits: int = 8) -> str:
    return bin(val)[2:].zfill(bits)


def checksum16(data: bytes) -> int:
    return sum(data) & 0xFFFF


# ---------------- bit-stuffing (CORRECTED) ----------------
# ---------------- bit-stuffing (FIXED) ----------------
def bit_stuff(bits: str, pattern_to_avoid: str = FRAME_DELIMITER_BITS) -> str:
    """
    Вставляем complement(last_bit) сразу после того, как в выходе
    оказался prefix + last_bit. Никаких lookahead-скипов входных битов.
    """
    prefix = pattern_to_avoid[:-1]
    last_bit = pattern_to_avoid[-1]
    # вставляем противоположный бит к последнему биту шаблона
    stuff_bit = '1' if last_bit == '0' else '0'

    result = []
    for b in bits:
        result.append(b)
        # если только что в выход ушёл prefix + last_bit — вставляем stuff_bit
        if len(result) >= len(prefix) + 1 and ''.join(result[-(len(prefix) + 1):]) == prefix + last_bit:
            result.append(stuff_bit)
    return ''.join(result)


def bit_unstuff(bits: str, pattern_to_avoid: str = FRAME_DELIMITER_BITS) -> str:
    """
    Удаляем stuff_bit, если он следует сразу после prefix + last_bit.
    Симметрично исправлённой bit_stuff.
    """
    prefix = pattern_to_avoid[:-1]
    last_bit = pattern_to_avoid[-1]
    stuff_bit = '1' if last_bit == '0' else '0'

    result = []
    i = 0
    while i < len(bits):
        result.append(bits[i])
        # если в выходе уже prefix + last_bit и следующий входной бит — stuff_bit,
        # пропускаем этот следующий (удаляем его)
        if (len(result) >= len(prefix) + 1
            and ''.join(result[-(len(prefix) + 1):]) == prefix + last_bit
            and i + 1 < len(bits)
            and bits[i + 1] == stuff_bit):
            i += 1  # пропустить stuff_bit во входе (не добавлять в result)
        i += 1
    return ''.join(result)



# ---------------- Frame dataclass ----------------
@dataclass
class Frame:
    flag: int
    src: int
    dst: int
    payload: bytes

    def to_bytes(self, do_bit_stuff: bool = True) -> bytes:
        length = len(self.payload)
        header = struct.pack('!BBBH', self.flag & 0xFF, self.src & 0xFF, self.dst & 0xFF, length)
        data_to_checksum = header + self.payload
        chk = checksum16(data_to_checksum)
        data_with_chk = data_to_checksum + struct.pack('!H', chk)

        if do_bit_stuff:
            bits = bytes_to_bits(data_with_chk)
            stuffed = bit_stuff(bits, FRAME_DELIMITER_BITS)
            stuffed_bytes = bits_to_bytes(stuffed)
            return bytes([FRAME_DELIMITER_BYTE]) + stuffed_bytes + bytes([FRAME_DELIMITER_BYTE])
        else:
            return bytes([FRAME_DELIMITER_BYTE]) + data_with_chk + bytes([FRAME_DELIMITER_BYTE])

    @staticmethod
    def from_bytes(data: bytes, do_bit_unstuff: bool = True) -> Optional['Frame']:
        try:
            if len(data) < 2 or data[0] != FRAME_DELIMITER_BYTE or data[-1] != FRAME_DELIMITER_BYTE:
                return None
            inner = data[1:-1]
            if do_bit_unstuff:
                bits = bytes_to_bits(inner)
                unstuffed = bit_unstuff(bits, FRAME_DELIMITER_BITS)
                inner = bits_to_bytes(unstuffed)
            if len(inner) < 7:
                return None
            flag, src, dst, length = struct.unpack('!BBBH', inner[:5])
            expected = 5 + length + 2
            if len(inner) < expected:
                return None
            payload = inner[5:5 + length]
            chk_recv, = struct.unpack('!H', inner[5 + length:5 + length + 2])
            chk_calc = checksum16(inner[:5 + length])
            if chk_recv != chk_calc:
                return None
            return Frame(flag=flag, src=src, dst=dst, payload=payload)
        except Exception:
            return None


# ---------------- SerialWorker ----------------
class SerialWorker(QThread):
    data_received = pyqtSignal(bytes)
    error = pyqtSignal(str)
    state = pyqtSignal(str)

    def __init__(self, port, baud=9600, bytesize=serial.EIGHTBITS,
                 parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                 timeout=0.1):
        super().__init__()
        self.port = port
        self.baud = baud
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits = stopbits
        self.timeout = timeout
        self._running = False
        self._lock = threading.Lock()
        self.ser = None
        self._buffer = bytearray()

    def run(self):
        try:
            self.ser = serial.Serial(
                port=self.port,
                baudrate=self.baud,
                bytesize=self.bytesize,
                parity=self.parity,
                stopbits=self.stopbits,
                timeout=self.timeout
            )
            self._running = True
            self.state.emit(f"Opened {self.port}")
        except Exception as e:
            self.error.emit(f"Open error: {e}")
            return

        try:
            while self._running:
                try:
                    if self.ser.in_waiting:
                        data = self.ser.read(self.ser.in_waiting)
                        if data:
                            self._buffer.extend(data)
                            self._process_buffer()
                except Exception as e:
                    self.error.emit(f"Read error: {e}")
                    break
                self.msleep(20)
        finally:
            if self.ser and self.ser.is_open:
                try:
                    self.ser.close()
                except Exception:
                    pass
            self.state.emit("Closed")

    def _process_buffer(self):
        while True:
            start = self._buffer.find(bytes([FRAME_DELIMITER_BYTE]))
            if start == -1:
                break
            if start > 0:
                del self._buffer[:start]
                start = 0
            end = self._buffer.find(bytes([FRAME_DELIMITER_BYTE]), start + 1)
            if end == -1:
                break
            frame = bytes(self._buffer[:end + 1])
            self.data_received.emit(frame)
            del self._buffer[:end + 1]

    def write(self, data: bytes) -> bool:
        with self._lock:
            if self.ser and self.ser.is_open:
                try:
                    self.ser.write(data)
                    return True
                except Exception as e:
                    self.error.emit(f"Write error: {e}")
                    return False
            else:
                self.error.emit("Port not open")
                return False

    def stop(self):
        self._running = False
        self.wait(1000)


# ---------------- Main Window ----------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("COM Messenger (frames + bit-stuffing + fragmentation)")
        self.resize(960, 560)
        self.worker_send = None
        self.worker_receive = None

        # UI elements
        self.port_send_cb = QComboBox()
        self.port_receive_cb = QComboBox()
        self.refresh_ports_btn = QPushButton("Refresh COM")
        self.refresh_ports_btn.setIcon(QIcon.fromTheme("view-refresh"))
        self.connect_btn = QPushButton("Open ports")
        self.connect_btn.setIcon(QIcon.fromTheme("network-connect"))
        self.bytes_cb = QComboBox()

        self.send_input = QLineEdit()
        self.send_input.setMaxLength(2147483647)
        self.send_btn = QPushButton("Send")
        self.send_btn.setIcon(QIcon.fromTheme("mail-send"))

        self.sent_area = QPlainTextEdit()
        self.sent_area.setReadOnly(True)
        self.recv_area = QPlainTextEdit()
        self.recv_area.setReadOnly(True)
        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)

        self._recv_fragments: List[bytes] = []

        self._build_ui()
        self._populate_defaults()
        self._connect_signals()
        self._apply_styles()

    def _build_ui(self):
        main_w = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)

        row1 = QHBoxLayout()
        row1.setSpacing(8)
        row1.addWidget(QLabel("TX Port:"))
        row1.addWidget(self.port_send_cb)
        row1.addWidget(QLabel("RX Port:"))
        row1.addWidget(self.port_receive_cb)
        row1.addWidget(self.refresh_ports_btn)
        row1.addWidget(QLabel("Data bits:"))
        row1.addWidget(self.bytes_cb)
        row1.addWidget(self.connect_btn)
        main_layout.addLayout(row1)

        msg_row = QHBoxLayout()
        msg_row.setSpacing(8)
        msg_row.addWidget(QLabel("Message:"))
        msg_row.addWidget(self.send_input)
        msg_row.addWidget(self.send_btn)
        main_layout.addLayout(msg_row)

        split_row = QHBoxLayout()
        split_row.setSpacing(10)

        v1 = QVBoxLayout()
        v1.addWidget(QLabel("Sent frames:"))
        v1.addWidget(self.sent_area)
        split_row.addLayout(v1)

        v2 = QVBoxLayout()
        v2.addWidget(QLabel("Received messages:"))
        v2.addWidget(self.recv_area)
        split_row.addLayout(v2)

        v3 = QVBoxLayout()
        v3.addWidget(QLabel("Application logs:"))
        v3.addWidget(self.log_area)
        split_row.addLayout(v3)

        main_layout.addLayout(split_row)
        main_w.setLayout(main_layout)
        self.setCentralWidget(main_w)

    def _apply_styles(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #f0f0f5; font-family: 'Segoe UI', Arial, sans-serif; }
            QLabel { font-size: 14px; color: #333; }
            QComboBox { padding: 5px; border: 1px solid #ccc; border-radius: 4px; background-color: #fff; font-size: 14px; color: #000000; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView { color: #000000; background-color: #fff; }
            QPushButton { padding: 8px 16px; border: none; border-radius: 4px; background-color: #0078d4; color: white; font-size: 14px; }
            QPushButton:hover { background-color: #005ea2; }
            QPushButton:pressed { background-color: #004080; }
            QLineEdit { padding: 5px; border: 1px solid #ccc; border-radius: 4px; background-color: #fff; font-size: 14px; color: #000000; }
            QPlainTextEdit { border: 1px solid #ccc; border-radius: 4px; background-color: #fff; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; color: #000000; }
            QMessageBox { background-color: #f0f0f5; }
        """)
        self.setFont(QFont("Segoe UI", 10))

    def _populate_defaults(self):
        self._refresh_ports()
        self.bytes_cb.addItems(["5", "6", "7", "8"])
        self.bytes_cb.setCurrentText("8")

    def _connect_signals(self):
        self.refresh_ports_btn.clicked.connect(self._refresh_ports)
        self.connect_btn.clicked.connect(self._on_connect_clicked)
        self.send_btn.clicked.connect(self._on_send_clicked)
        self.send_input.returnPressed.connect(self._on_send_clicked)

    def _refresh_ports(self):
        self.port_send_cb.clear()
        self.port_receive_cb.clear()
        self.port_send_cb.addItem("Select port", "")
        self.port_receive_cb.addItem("Select port", "")
        ports = serial.tools.list_ports.comports()
        for p in ports:
            self.port_send_cb.addItem(p.device, p.device)
            self.port_receive_cb.addItem(p.device, p.device)
        if self.port_send_cb.count() == 1:
            self.port_send_cb.addItem("No COM", "")
            self.port_receive_cb.addItem("No COM", "")
        self.port_send_cb.setCurrentIndex(0)
        self.port_receive_cb.setCurrentIndex(0)

    def _on_connect_clicked(self):
        if self.worker_send is None and self.worker_receive is None:
            send_port = self.port_send_cb.currentData()
            recv_port = self.port_receive_cb.currentData()
            if (not send_port or not recv_port or send_port == recv_port or send_port == "" or recv_port == ""):
                QMessageBox.warning(self, "Error", "Select different valid COM ports for TX and RX.")
                return

            bytesize_map = {"5": serial.FIVEBITS, "6": serial.SIXBITS, "7": serial.SEVENBITS, "8": serial.EIGHTBITS}
            bs = bytesize_map.get(self.bytes_cb.currentText(), serial.EIGHTBITS)

            self.worker_send = SerialWorker(send_port, bytesize=bs)
            self.worker_send.error.connect(self._on_error)
            self.worker_send.state.connect(self._on_state)
            self.worker_send.start()

            self.worker_receive = SerialWorker(recv_port, bytesize=bs)
            self.worker_receive.data_received.connect(self._on_data_received)
            self.worker_receive.error.connect(self._on_error)
            self.worker_receive.state.connect(self._on_state)
            self.worker_receive.start()

            self.log(f"Threads started: send={send_port}, recv={recv_port}")
            self.connect_btn.setText("Close ports")
            self.connect_btn.setIcon(QIcon.fromTheme("network-disconnect"))
        else:
            self.log("Stopping threads...")
            if self.worker_send:
                self.worker_send.stop()
            if self.worker_receive:
                self.worker_receive.stop()
            self.worker_send = None
            self.worker_receive = None
            self.connect_btn.setText("Open ports")
            self.connect_btn.setIcon(QIcon.fromTheme("network-connect"))
            self.log("Ports closed")

    def _format_frame_dump(self, frm: Frame, fragment_num: int, total_fragments: int) -> str:
        length = len(frm.payload)
        header = struct.pack('!BBBH', frm.flag, frm.src, frm.dst, length)
        chk = checksum16(header + frm.payload)
        data_with_chk = header + frm.payload + struct.pack('!H', chk)
        bits = bytes_to_bits(data_with_chk)
        stuffed = bit_stuff(bits, FRAME_DELIMITER_BITS)
        # Показываем БИТЫ без паддинга
        stuffed_bits_grouped = group_bits_str(stuffed)

        return f"""flag: {bin_str(frm.flag)}
tx: {bin_str(frm.src)}
rx: {bin_str(frm.dst)}
data_length: {bin_str(length, 16)}
data: {bytes_to_binary(frm.payload)}
checksum: {bin_str(chk, 16)}
--- Stuffed Frame Data ---
{stuffed_bits_grouped}
[Fragment {fragment_num}/{total_fragments}]
"""

    def _on_send_clicked(self):
        if self.worker_send is None:
            QMessageBox.warning(self, "Error", "Send port not open")
            return
        text = self.send_input.text().strip()
        if not text:
            return

        payload = text.encode("utf-8")
        chunks = [payload[i:i + MAX_PAYLOAD_SIZE] for i in range(0, len(payload), MAX_PAYLOAD_SIZE)]
        total_fragments = len(chunks)

        self.log(f"Splitting message into {total_fragments} fragment(s)")

        for i, chunk in enumerate(chunks):
            frm = Frame(flag=FLAG_VALUE, src=1, dst=2, payload=chunk)
            tx = frm.to_bytes(do_bit_stuff=True)

            dump_text = self._format_frame_dump(frm, i + 1, total_fragments)
            self.sent_area.appendPlainText(dump_text)

            if not self.worker_send.write(tx):
                self.log("Send failed")
                return
            self.log(f"Fragment {i+1}/{total_fragments} sent ({len(tx)} bytes)")

        self.send_input.clear()

    def _on_data_received(self, data: bytes):
        frm = Frame.from_bytes(data, do_bit_unstuff=True)
        if not frm:
            self.log("Invalid or corrupted frame.")
            return

        if not self._recv_fragments:
            self._recv_fragments = [frm.payload]
            self.log(f"Started reassembling (fragment 1, {len(frm.payload)} bytes)")
        else:
            self._recv_fragments.append(frm.payload)
            self.log(f"Received fragment {len(self._recv_fragments)}")

        if len(frm.payload) < MAX_PAYLOAD_SIZE:
            full_payload = b''.join(self._recv_fragments)
            try:
                msg = full_payload.decode("utf-8")
                self.recv_area.appendPlainText(msg)
                self.log(f"Message reassembled: {len(full_payload)} bytes in {len(self._recv_fragments)} fragments")
            except Exception:
                self.recv_area.appendPlainText(f"[binary] {full_payload.hex(' ')}")
                self.log("Binary data received")
            self._recv_fragments = []
        else:
            self.log("Waiting for more fragments...")

    def _on_error(self, text: str):
        self.log(f"ERROR: {text}")

    def _on_state(self, text: str):
        self.log(f"STATE: {text}")

    def log(self, text: str):
        self.log_area.appendPlainText(text)

    def closeEvent(self, event):
        if self.worker_send or self.worker_receive:
            try:
                if self.worker_send:
                    self.worker_send.stop()
                if self.worker_receive:
                    self.worker_receive.stop()
            except Exception:
                pass
            self.worker_send = None
            self.worker_receive = None
        event.accept()


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()