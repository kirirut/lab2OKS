import sys
import threading
import math
import re  # Добавлен для извлечения адреса из имени порта
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton,
    QComboBox, QHBoxLayout, QVBoxLayout, QPlainTextEdit, QLineEdit, QMessageBox,
    QDialog
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont, QIcon
import serial
import serial.tools.list_ports


# ---------------- Frame Processor Logic ----------------
# Логика кадрирования и декадрирования, вынесенная для удобства.
class FrameProcessor:
    FLAG = "00010110"  # 8 бит

    @staticmethod
    def _bin_to_bytes(binary_string: str) -> bytes:
        """Конвертирует двоичную строку в байты для передачи."""
        # Дополняем нулями до кратного 8
        padding_needed = (8 - (len(binary_string) % 8)) % 8
        binary_string += '0' * padding_needed

        byte_list = []
        for i in range(0, len(binary_string), 8):
            byte_str = binary_string[i:i + 8]
            byte_val = int(byte_str, 2)
            byte_list.append(byte_val)
        return bytes(byte_list)

    @staticmethod
    def _bytes_to_bin(data_bytes: bytes) -> str:
        """Конвертирует байты, полученные по COM-порту, обратно в двоичную строку."""
        return ''.join(f'{b:08b}' for b in data_bytes)

    @staticmethod
    def bit_stuffing(bit_string: str) -> str:
        """
        ВОССТАНОВЛЕННЫЙ АЛГОРИТМ: Вставляет '1' после '0001011' ПЕРЕД следующим '0'.
        Превращает 00010110 в 000101110.
        """
        stuffed_result = ""
        prefix = "0001011"
        prefix_len = len(prefix)
        i = 0
        while i < len(bit_string):

            # 1. Проверяем наличие 7-битного префикса
            if i + prefix_len <= len(bit_string) and bit_string[i:i + prefix_len] == prefix:

                # Копируем 7-битный префикс
                stuffed_result += prefix
                i += prefix_len

                # 2. Проверяем следующий бит
                if i < len(bit_string):
                    next_bit = bit_string[i]

                    # 3. Если следующий бит '0', завершая FLAG, вставляем '1' ПЕРЕД '0'
                    if next_bit == '0':
                        stuffed_result += '1'  # Вставленный '1'
                        stuffed_result += next_bit  # Добавляем оригинальный '0'
                        i += 1  # Сдвигаем индекс на один шаг вперед (пропустили оригинальный '0')
                    else:
                        # Если следующий бит '1', стаффинг не нужен
                        stuffed_result += next_bit
                        i += 1

            else:
                # Префикс не найден, копируем один бит
                stuffed_result += bit_string[i]
                i += 1

        return stuffed_result

    @staticmethod
    def de_bit_stuffing(stuffed_bit_string: str) -> str:
        """ДЕКАДРИРОВАНИЕ: '0001011' + '1' (stuffed) + '0' -> удалить '1'."""
        de_stuffed_result = ""
        prefix = "0001011"
        i = 0
        while i < len(stuffed_bit_string):

            # 1. Проверяем паттерн "0001011"
            if stuffed_bit_string[i:i + len(prefix)] == prefix:
                de_stuffed_result += prefix
                i += len(prefix)

                # 2. Проверяем, есть ли следующий бит
                if i < len(stuffed_bit_string):

                    # 3. Проверяем стаффинговую последовательность "10"
                    if stuffed_bit_string[i] == '1' and i + 1 < len(stuffed_bit_string) and stuffed_bit_string[
                        i + 1] == '0':
                        # Если это вставленный "10", добавляем только "0" и пропускаем оба бита
                        de_stuffed_result += '0'
                        i += 2
                    else:
                        # Это оригинальный бит (может быть '1' или '0' в конце строки)
                        de_stuffed_result += stuffed_bit_string[i]
                        i += 1
            else:
                de_stuffed_result += stuffed_bit_string[i]
                i += 1
        return de_stuffed_result

    @staticmethod
    def build_frame(tx: int, rx: int, data: bytes) -> tuple:
        """Собирает и кадрирует кадр, возвращает данные и бит-строку."""
        tx_bin = bin(tx)[2:].zfill(8)
        rx_bin = bin(rx)[2:].zfill(8)
        data_length_bin = bin(len(data))[2:].zfill(8)
        data_bin = ''.join(f'{b:08b}' for b in data)

        # Тело кадра: TX (8) + RX (8) + Length (8) + Data (N*8)
        frame_data_body = tx_bin + rx_bin + data_length_bin + data_bin

        # Бит-стаффинг
        stuffed_data_body = FrameProcessor.bit_stuffing(frame_data_body)

        # Конечный кадр: FLAG + Stuffed Body + FLAG
        final_frame_bin = FrameProcessor.FLAG + stuffed_data_body + FrameProcessor.FLAG

        return {
            "tx_bin": tx_bin,
            "rx_bin": rx_bin,
            "data_length_bin": data_length_bin,
            "data_bin": data_bin,
            "stuffed_body": stuffed_data_body,
            "final_frame_bin": final_frame_bin
        }

    @staticmethod
    def parse_frame(received_frame_bin: str) -> dict:
        """Разбирает и декадрирует принятый бит-кадр."""

        # 1. Проверка флагов
        flag_len = len(FrameProcessor.FLAG)
        if not received_frame_bin.startswith(FrameProcessor.FLAG) or \
                not received_frame_bin.endswith(FrameProcessor.FLAG):
            return {"error": "Invalid frame: Missing or corrupted flags at ends."}

        stuffed_body = received_frame_bin[flag_len:-flag_len]

        # 2. Декадрирование
        de_stuffed_body = FrameProcessor.de_bit_stuffing(stuffed_body)

        # Минимальная длина: TX(8) + RX(8) + Length(8) = 24 бита
        if len(de_stuffed_body) < 24:
            return {"error": "Invalid frame: Body too short after de-stuffing (Min 24 bits required)."}

        # 3. Парсинг полей (TX, RX, Length - 8 бит каждое)
        tx_bin = de_stuffed_body[:8]
        rx_bin = de_stuffed_body[8:16]
        length_bin = de_stuffed_body[16:24]
        data_bin = de_stuffed_body[24:]  # Data идет до конца

        try:
            length_val = int(length_bin, 2)
        except ValueError:
            return {"error": "Invalid frame: Cannot parse data length field."}

        # Проверка длины данных
        if len(data_bin) != length_val * 8:
            return {
                "error": f"Invalid frame: Data length mismatch (Expected: {length_val * 8} bits, Found: {len(data_bin)} bits)"}

        return {
            "status": "OK",
            "tx_bin": tx_bin,
            "rx_bin": rx_bin,
            "length_bin": length_bin,
            "data_bin": data_bin,
            "de_stuffed_body": de_stuffed_body
        }


# ---------------- Frame Window (Log) ----------------
class FrameWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sent Frame History")
        self.resize(700, 500)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        self.log_display = QPlainTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Consolas", 10))
        self.log_display.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(QLabel("History of Sent Frame Structures:"))
        main_layout.addWidget(self.log_display)
        self._apply_styles()

    def _apply_styles(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #f0f0f5;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QLabel {
                font-size: 14px;
                color: #333;
                font-weight: bold;
            }
            QLineEdit, QPlainTextEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #fff;
                font-size: 13px;
                color: #000000;
            }
        """)

    def log_frame_data(self, frame_info: dict, original_text: str):
        """Логирует информацию о фрейме в QPlainTextEdit."""

        log_text = f"--- SENT FRAME: {original_text!r} ---\n"

        # Фиксированное выравнивание
        log_text += f"Flag:             {FrameProcessor.FLAG}\n"
        log_text += f"TX:               {frame_info['tx_bin']} ({int(frame_info['tx_bin'], 2)})\n"
        log_text += f"RX:               {frame_info['rx_bin']} ({int(frame_info['rx_bin'], 2)})\n"

        length_output = f"{frame_info['data_length_bin']} ({int(frame_info['data_length_bin'], 2)} bytes)"
        log_text += f"Data Length:      {length_output}\n"

        log_text += f"Data:             {frame_info['data_bin']}\n"

        original_body = frame_info['tx_bin'] + frame_info['rx_bin'] + frame_info['data_length_bin'] + frame_info[
            'data_bin']

        # Расчет ожидаемой длины тела, если стаффинг не произошел
        data_len_bytes = int(frame_info['data_length_bin'], 2)
        expected_unstuffed_len = 24 + (data_len_bytes * 8)  # 3 поля (24 бит) + Биты данных

        if original_body != frame_info['stuffed_body']:
            log_text += f"Stuffed Body:     {frame_info['stuffed_body']} (Len: {len(frame_info['stuffed_body'])} bits)\n"
        else:
            # Если стаффинг не произошел, длина тела должна быть равна ожидаемой длине
            log_text += f"Stuffed Body:     (No stuffing occurred - Body length: {expected_unstuffed_len} bits)\n"

        log_text += f"Full Stuffed Frame:\n"

        # Форматирование полной бинарной строки по байтам
        formatted_frame = ' '.join(
            frame_info['final_frame_bin'][i:i + 8] for i in range(0, len(frame_info['final_frame_bin']), 8))
        log_text += f"{formatted_frame}\n"
        log_text += "\n"  # Добавляем пустую строку для разделения

        self.log_display.appendPlainText(log_text)
        self.log_display.ensureCursorVisible()


# ---------------- Serial Worker ----------------
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
                            self.data_received.emit(data)
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

    def write(self, data: bytes) -> bool:
        with self._lock:
            if self.ser and self.ser.is_open:
                try:
                    # Отправляем байты, представляющие бит-кадрированный кадр
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
        self.setWindowTitle("COM Messenger")
        self.resize(900, 520)
        self.worker_send = None
        self.worker_receive = None
        self.frame_window = FrameWindow(self)  # Окно истории фреймов

        # Логические адреса фрейма (TX/RX) теперь будут извлекаться из имен портов.
        # Константы self.tx_addr и self.rx_addr удалены.

        # UI elements
        self.port_send_cb = QComboBox()
        self.port_receive_cb = QComboBox()
        self.refresh_ports_btn = QPushButton("Refresh COM")
        self.refresh_ports_btn.setIcon(QIcon.fromTheme("view-refresh"))
        self.connect_btn = QPushButton("Open ports")
        self.connect_btn.setIcon(QIcon.fromTheme("network-connect"))
        self.bytes_cb = QComboBox()

        self.show_frame_btn = QPushButton("Show Sent History")
        self.show_frame_btn.setIcon(QIcon.fromTheme("dialog-information"))

        # Message input / send
        self.send_input = QLineEdit()
        self.send_btn = QPushButton("Send")
        self.send_btn.setIcon(QIcon.fromTheme("mail-send"))

        # Received / logs
        self.recv_area = QPlainTextEdit()
        self.recv_area.setReadOnly(True)
        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)

        self._build_ui()
        self._populate_defaults()
        self._connect_signals()
        self._apply_styles()

    def _build_ui(self):
        main_w = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Top row: ports + controls
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

        # Message row
        msg_row = QHBoxLayout()
        msg_row.setSpacing(8)
        msg_row.addWidget(QLabel("Message:"))
        msg_row.addWidget(self.send_input)
        msg_row.addWidget(self.send_btn)
        msg_row.addWidget(self.show_frame_btn)  # Добавляем кнопку
        main_layout.addLayout(msg_row)

        # Split row: Received / Logs
        split_row = QHBoxLayout()
        split_row.setSpacing(10)
        v1 = QVBoxLayout()
        v1.addWidget(QLabel("Received messages:"))
        v1.addWidget(self.recv_area)
        split_row.addLayout(v1)

        v2 = QVBoxLayout()
        v2.addWidget(QLabel("Application logs:"))
        v2.addWidget(self.log_area)
        split_row.addLayout(v2)

        main_layout.addLayout(split_row)
        main_w.setLayout(main_layout)
        self.setCentralWidget(main_w)

    def _apply_styles(self):
        # Modern stylesheet
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #f0f0f5;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QLabel {
                font-size: 14px;
                color: #333;
            }
            QComboBox {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #fff;
                font-size: 14px;
                color: #000000;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                color: #000000;
                background-color: #fff;
            }
            QPushButton {
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                background-color: #0078d4;
                color: white;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #005ea2;
            }
            QPushButton:pressed {
                background-color: #004080;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #fff;
                font-size: 14px;
                color: #000000; /* Set text color to black for input */
            }
            QPlainTextEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #fff;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 13px;
                color: #000000; /* Ensure text is black */
            }
            QMessageBox {
                background-color: #f0f0f5;
            }
        """)
        # Set consistent font for all widgets
        font = QFont("Segoe UI", 10)
        self.setFont(font)

    def _populate_defaults(self):
        self._refresh_ports()
        self.bytes_cb.addItems(["5", "6", "7", "8"])
        self.bytes_cb.setCurrentText("8")

    def _connect_signals(self):
        self.refresh_ports_btn.clicked.connect(self._refresh_ports)
        self.connect_btn.clicked.connect(self._on_connect_clicked)
        self.send_btn.clicked.connect(self._on_send_clicked)
        self.send_input.returnPressed.connect(self._on_send_clicked)
        self.show_frame_btn.clicked.connect(self._on_show_frame_clicked)  # Сигнал для новой кнопки

    def _refresh_ports(self):
        self.port_send_cb.clear()
        self.port_receive_cb.clear()

        # Добавляем placeholder
        self.port_send_cb.addItem("Select port", "")
        self.port_receive_cb.addItem("Select port", "")

        # Заполняем список портов
        ports = serial.tools.list_ports.comports()
        for p in ports:
            self.port_send_cb.addItem(p.device, p.device)
            self.port_receive_cb.addItem(p.device, p.device)

        # Если нет портов, оставляем только placeholder
        if self.port_send_cb.count() == 1:  # Только "Select port"
            self.port_send_cb.addItem("No COM", "")
            self.port_receive_cb.addItem("No COM", "")

        # Устанавливаем placeholder как текущий элемент
        self.port_send_cb.setCurrentIndex(0)  # "Select port"
        self.port_receive_cb.setCurrentIndex(0)  # "Select port"

    def _on_connect_clicked(self):
        if self.worker_send is None and self.worker_receive is None:
            send_port = self.port_send_cb.currentData()
            receive_port = self.port_receive_cb.currentData()

            # Проверяем, что порты выбраны и не совпадают (если это не loopback)
            if not send_port or not receive_port or send_port == "" or receive_port == "":
                QMessageBox.warning(self, "Error", "Please select valid COM ports.")
                return

            # Разрешаем отправку и прием через один и тот же порт (loopback test)
            if send_port == receive_port:
                # В случае loopback, нужен только один SerialWorker
                bytesize_map = {"5": serial.FIVEBITS, "6": serial.SIXBITS,
                                "7": serial.SEVENBITS, "8": serial.EIGHTBITS}
                bytesize = bytesize_map.get(self.bytes_cb.currentText(), serial.EIGHTBITS)

                # Создаем один worker для отправки и приема на одном порту
                self.worker_send = SerialWorker(send_port, bytesize=bytesize)
                self.worker_send.error.connect(self._on_error)
                self.worker_send.state.connect(self._on_state)
                self.worker_send.data_received.connect(self._on_data_received)  # Прием данных
                self.worker_send.start()
                self.worker_receive = self.worker_send  # Используем один и тот же объект

                self.log(f"Thread started for loopback on {send_port}")
            else:
                # Два разных порта
                bytesize_map = {"5": serial.FIVEBITS, "6": serial.SIXBITS,
                                "7": serial.SEVENBITS, "8": serial.EIGHTBITS}
                bytesize = bytesize_map.get(self.bytes_cb.currentText(), serial.EIGHTBITS)

                self.worker_send = SerialWorker(send_port, bytesize=bytesize)
                self.worker_send.error.connect(self._on_error)
                self.worker_send.state.connect(self._on_state)
                self.worker_send.start()

                self.worker_receive = SerialWorker(receive_port, bytesize=bytesize)
                self.worker_receive.data_received.connect(self._on_data_received)
                self.worker_receive.error.connect(self._on_error)
                self.worker_receive.state.connect(self._on_state)
                self.worker_receive.start()

                self.log(f"Threads started: send={send_port}, recv={receive_port}")

            self.connect_btn.setText("Close ports")
            self.connect_btn.setIcon(QIcon.fromTheme("network-disconnect"))
        else:
            # Логика закрытия портов
            self.log("Stopping threads...")
            try:
                if self.worker_send:
                    self.worker_send.stop()
                if self.worker_receive and self.worker_receive != self.worker_send:
                    self.worker_receive.stop()
            except Exception:
                pass
            self.worker_send = None
            self.worker_receive = None
            self.connect_btn.setText("Open ports")
            self.connect_btn.setIcon(QIcon.fromTheme("network-connect"))
            self.log("Ports closed")

    def _get_addr_from_port_name(self, port_name: str) -> int | None:
        """Извлекает числовой адрес из имени COM-порта (например, COM1 -> 1)."""
        # Находим все числа в конце строки (например, 'COM12' -> 12, '/dev/ttyS1' -> 1)
        match = re.search(r'(\d+)$', port_name)
        if match:
            try:
                addr = int(match.group(1))
                if 0 <= addr <= 255:  # Адрес должен быть 8-битным
                    return addr
            except ValueError:
                pass
        return None

    def _on_send_clicked(self):
        if self.worker_send is None:
            QMessageBox.warning(self, "Error", "Send port not open")
            self.log("Send failed: port not open")
            return

        tx_port_name = self.port_send_cb.currentText()
        rx_port_name = self.port_receive_cb.currentText()

        # --- 1. Извлечение адресов из имен портов ---
        tx_addr = self._get_addr_from_port_name(tx_port_name)
        rx_addr = self._get_addr_from_port_name(rx_port_name)

        if tx_addr is None or rx_addr is None:
            QMessageBox.warning(self, "Error",
                                f"Could not determine 8-bit TX/RX address from port names: "
                                f"TX='{tx_port_name}', RX='{rx_port_name}'. "
                                f"Ensure port names end with a number (0-255).")
            self.log(f"Send failed: Invalid TX/RX addresses derived from ports.")
            return

        text = self.send_input.text()
        if text == "":
            return

        # ------------------- ОБРАБОТКА ДАННЫХ ДЛЯ ОТПРАВКИ -------------------
        # Специальный тест битстаффинга
        if text.upper() == "TESTSTUFF":
            flag_value_decimal = 22
            data = bytes([flag_value_decimal])
            self.log("--- Bit Stuffing TEST Forced: Sending flag byte (22) ---")
            original_text_log = "[TESTSTUFF: Data=0x16]"
        else:
            try:
                data = text.encode("utf-8")
                original_text_log = text
            except Exception as e:
                self.log(f"Encoding error: {e}")
                return

        # ------------------- НОВАЯ ПРОВЕРКА ДЛИНЫ -------------------
        # Максимальная длина данных, которую может хранить 8-битное поле Length (2^8 - 1)
        MAX_PAYLOAD_SIZE = 255

        if len(data) > MAX_PAYLOAD_SIZE:
            error_msg = (
                f"Message size ({len(data)} bytes) exceeds the protocol's "
                f"maximum payload limit of {MAX_PAYLOAD_SIZE} bytes. "
                "The 'Data Length' field is restricted to 8 bits."
            )
            QMessageBox.critical(self, "Protocol Limit Exceeded", error_msg)
            self.log(f"Send failed: {error_msg}")
            return
        # ------------------- КОНЕЦ НОВОЙ ПРОВЕРКИ -------------------

        # 2. Сборка и кадрирование фрейма с ДИНАМИЧЕСКИМИ адресами
        frame_info = FrameProcessor.build_frame(tx_addr, rx_addr, data)

        # 3. Преобразование бит-строки в байты для передачи
        bytes_to_send = FrameProcessor._bin_to_bytes(frame_info['final_frame_bin'])

        # 4. Логирование отправленного кадра (для истории)
        self.frame_window.log_frame_data(frame_info, original_text_log)

        # 5. Отправляем данные
        ok = self.worker_send.write(bytes_to_send)
        if ok:
            self.log(
                f"Sent (TX={tx_addr}, RX={rx_addr}): {original_text_log!r} (Data: {len(data)} bytes, Frame: {len(bytes_to_send)} bytes)")
        else:
            self.log("Send failed")

    def _on_show_frame_clicked(self):
        # При нажатии кнопки показываем окно истории отправленных кадров
        self.frame_window.show()

    def _on_data_received(self, data: bytes):
        # 1. Преобразование принятых байтов в бит-строку (включая мусор)
        raw_received_bin = FrameProcessor._bytes_to_bin(data)

        FLAG = FrameProcessor.FLAG

        # 2. Поиск первого флага (Start Flag)
        start_index = raw_received_bin.find(FLAG)

        if start_index == -1:
            self.recv_area.appendPlainText("ERROR PARSING: Start flag not found in received data.")
            self.log("Received data parse error: Start flag not found.")
            return

        # Удаление ведущего мусора
        if start_index > 0:
            self.log(f"Warning: Removed {start_index} leading garbage bits.")

        # 3. Поиск конечного флага (End Flag)
        body_and_end = raw_received_bin[start_index + len(FLAG):]
        # Используем rfind для поиска последнего возможного флага
        end_flag_start_index_in_body_section = body_and_end.rfind(FLAG)

        if end_flag_start_index_in_body_section == -1:
            self.recv_area.appendPlainText("ERROR PARSING: End flag not found after start flag.")
            self.log("Received data parse error: End flag not found.")
            return

        # 4. Извлечение полного кадра (Start FLAG + Stuffed Body + End FLAG)
        # Длина от начала Start FLAG до конца End FLAG
        total_frame_length = (len(FLAG) +
                              end_flag_start_index_in_body_section + len(FLAG))

        # Обрезанный кадр, начинающийся с первого флага
        stuffed_frame_bin = raw_received_bin[start_index:start_index + total_frame_length]

        # 5. Разбор и декадрирование кадра
        frame_parse_result = FrameProcessor.parse_frame(stuffed_frame_bin)

        # 6. Вывод структуры декадрированного кадра

        if "error" in frame_parse_result:
            self.recv_area.appendPlainText(f"--- DE-BIT-STUFFED STRUCTURE ---")
            self.recv_area.appendPlainText(f"ERROR PARSING FRAME: {frame_parse_result['error']}")
            self.log(f"Received data parse error: {frame_parse_result['error']}")
        else:
            data_bin = frame_parse_result['data_bin']
            de_stuffed_body = frame_parse_result['de_stuffed_body']

            # Конвертация Data в байты и затем в текст
            data_bytes = FrameProcessor._bin_to_bytes(data_bin)
            try:
                decoded_text = data_bytes.decode("utf-8", errors="replace")
            except Exception:
                decoded_text = repr(data_bytes)

            # 1. Построение и форматирование ПОЛНОГО декадрированного кадра (FLAG + Body + FLAG)
            full_de_stuffed_frame = FLAG + de_stuffed_body + FLAG
            formatted_full_de_stuffed_frame = ' '.join(
                full_de_stuffed_frame[i:i + 8] for i in range(0, len(full_de_stuffed_frame), 8))

            # --- Вывод структуры декадрированного кадра с ВЫРАВНИВАНИЕМ ---

            self.recv_area.appendPlainText(f"\n--- DE-BIT-STUFFED FRAME STRUCTURE ---")

            # Выравнивание полей
            self.recv_area.appendPlainText(f"FLAG:             {FLAG}")
            self.recv_area.appendPlainText(
                f"TX:               {frame_parse_result['tx_bin']} ({int(frame_parse_result['tx_bin'], 2)})")
            self.recv_area.appendPlainText(
                f"RX:               {frame_parse_result['rx_bin']} ({int(frame_parse_result['rx_bin'], 2)})")

            length_output = f"{frame_parse_result['length_bin']} ({len(data_bytes)} bytes)"
            self.recv_area.appendPlainText(
                f"Data Length:      {length_output}")

            # Поле данных
            self.recv_area.appendPlainText(f"Data:             {data_bin}")

            # ПОЛНЫЙ КАДР, ВКЛЮЧАЯ ФЛАГИ
            self.recv_area.appendPlainText(f"De-stuffed Frame: {formatted_full_de_stuffed_frame}")

            self.recv_area.appendPlainText(f"Received Message: {decoded_text!r}")
            self.recv_area.appendPlainText("------------------------------------\n")

            self.log(f"Received message: {decoded_text!r} (Parsed OK)")

    def _on_error(self, text: str):
        self.log(f"ERROR: {text}")

    def _on_state(self, text: str):
        self.log(f"STATE: {text}")

    def log(self, text: str):
        self.log_area.appendPlainText(text)

    def closeEvent(self, event):
        # Закрываем все рабочие потоки при закрытии главного окна
        if self.worker_send or self.worker_receive:
            try:
                if self.worker_send:
                    self.worker_send.stop()
                if self.worker_receive and self.worker_receive != self.worker_send:
                    self.worker_receive.stop()
            except Exception:
                pass
            self.worker_send = None
            self.worker_receive = None

        # Закрываем окно фрейма
        if self.frame_window:
            self.frame_window.close()

        event.accept()


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()