#!/usr/bin/env python3
# ai_traffic_grid_smooth.py
"""
Optimized AI Traffic Density — Multi-Camera Grid with Arduino LED control
Smooth real-time UI with asynchronous YOLO detection.

Dependencies:
    pip install ultralytics opencv-python pillow numpy customtkinter pyserial torch
"""
import os
import cv2
import threading
import time
import numpy as np
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from datetime import datetime
from collections import deque
import itertools
import platform
import subprocess
import sys
import math

# try torch to detect cuda
try:
    import torch
except Exception:
    torch = None

# Serial (pyserial)
try:
    import serial
except Exception:
    serial = None

# ---------------- Arduino configuration ----------------
ARDUINO_PORT = "COM4"        # change if needed
ARDUINO_BAUD = 9600
ARD_PIN_GREEN = 5            # pin for GREEN LED
ARD_PIN_YELLOW = 6           # pin for YELLOW LED
ARD_PIN_RED = 7              # pin for RED LED
ARDUINO_CMD_FORMAT = "pinset"  # "pinset" uses "5:1;6:0;7:0\n" format; "letter" uses "G\n","Y\n","R\n"

# ----------------- USER CONFIG: modify this list to add cameras -----------------
# Put indices or IP camera URLs here
CAMERA_SOURCES = [2,5,4,7]

# MODEL OPTIONS (set file names or paths for YOLO weights)
MODEL_OPTIONS = {
    # --- YOLOv8 Series ---
    "yolov8n (fast)": "yolov8n.pt",
    "yolov8s (balance)": "yolov8s.pt",
    "yolov8m (more acc)": "yolov8m.pt",
    "yolov8l (highest acc)": "yolov8l.pt",
    "yolov8x (maximum acc)": "yolov8x.pt",
    "yolov11n (ultra-fast)": "yolo11n.pt",
    "yolov11s (improved balance)": "yolo11s.pt",
    "yolov11m (better accuracy)": "yolo11m.pt",
    "yolov11l (highest acc/eff)": "yolo11l.pt",
    "yolov11x (maximum accuracy)": "yolo11x.pt",
    "yolov12n (fast)": "yolo12n.pt",
    "yolov12s (balance)": "yolo12s.pt",
    "yolov12m (more acc)": "yolo12m.pt",
    "yolov12l (highest acc)": "yolo12l.pt",
    "yolov12x (maximum acc)": "yolo12x.pt"
}
DEFAULT_MODEL_KEY = "yolov11s (improved balance)"

# UI / behavior defaults
DEFAULT_IMG_SZ = 640
DEFAULT_CONF = 0.45
DEFAULT_SKIP = 5               # starting skip for detection (adaptive)
MIN_SKIP = 1
MAX_SKIP = 12
MAX_CONCURRENT_INFERENCES = 2

# Detection classes (COCO indices) and vehicle weights
DETECTION_CLASSES = [2, 3, 5, 7]  # car, motorcycle, bus, truck
VEHICLE_WEIGHTS = {2: 1, 3: 0.5, 5: 2, 7: 3}

# thresholds & timers (ms)
THRESHOLDS = {'light': 4, 'moderate': 9, 'heavy': 16, 'jammed': 25}
BASE_TRAFFIC = {'GREEN': 8000, 'YELLOW': 2000, 'RED': 8000}
MIN_GREEN_DUR = 4000
MAX_GREEN_MULTIPLIER = 2.0
ALL_RED_DURATION_MS = 1000

# panel display
PANEL_W = 380
PANEL_H = 285
SHOW_FPS = True
SHOW_TIMESTAMP = True
DENSITY_WINDOW_S = 3.0
FPS_WINDOW_S = 1.0

# appearance
ctk.set_default_color_theme("blue")

# -------------------- Global State --------------------
_model_lock = threading.Lock()
model = None
current_model_key = DEFAULT_MODEL_KEY
inference_semaphore = threading.Semaphore(MAX_CONCURRENT_INFERENCES)

# Scheduler globals (kept unchanged)
_global_light_control_lock = threading.Lock()
_active_green_worker_idx = None
_worker_iterator = None
_last_phase_ended_time = 0.0
SCHEDULER_DEBUG = False

# Arduino globals
_arduino_lock = threading.Lock()
_arduino = None
_last_sent_arduino_state = None
_arduino_connecting = False

# device string for model (auto-detect)
DEVICE_STR = "cpu"
if torch is not None and torch.cuda.is_available():
    DEVICE_STR = "cuda:0"

# helper: best backend flag
def _get_capture_backend_flag():
    if platform.system() == 'Windows':
        # CAP_DSHOW tends to reduce lag on Windows
        try:
            return cv2.CAP_DSHOW
        except Exception:
            return cv2.CAP_ANY
    return cv2.CAP_ANY

# -------------------- Arduino Helpers --------------------
def arduino_try_connect():
    global _arduino, _arduino_connecting
    if serial is None:
        return None
    with _arduino_lock:
        if _arduino is not None and getattr(_arduino, 'is_open', False):
            return _arduino
        if _arduino_connecting:
            return None
        _arduino_connecting = True
        try:
            _arduino = serial.Serial(ARDUINO_PORT, ARDUINO_BAUD, timeout=1)
            time.sleep(2.0)
            print(f"[Arduino] Connected on {ARDUINO_PORT} @ {ARDUINO_BAUD}")
            return _arduino
        except Exception as e:
            print(f"[Arduino] Connection failed: {e}")
            _arduino = None
            return None
        finally:
            _arduino_connecting = False

def _format_pinset_message(state):
    if state == 'GREEN':
        return f"{ARD_PIN_GREEN}:1;{ARD_PIN_YELLOW}:0;{ARD_PIN_RED}:0\n"
    elif state == 'YELLOW':
        return f"{ARD_PIN_GREEN}:0;{ARD_PIN_YELLOW}:1;{ARD_PIN_RED}:0\n"
    elif state == 'RED' or state == 'ALL_RED':
        return f"{ARD_PIN_GREEN}:0;{ARD_PIN_YELLOW}:0;{ARD_PIN_RED}:1\n"
    else:
        return f"{ARD_PIN_GREEN}:0;{ARD_PIN_YELLOW}:0;{ARD_PIN_RED}:0\n"

def _format_letter_message(state):
    if state == 'GREEN':
        return "G\n"
    if state == 'YELLOW':
        return "Y\n"
    if state == 'RED':
        return "R\n"
    if state == 'ALL_RED':
        return "A\n"
    return "X\n"

def arduino_set_light(state):
    global _arduino, _last_sent_arduino_state
    if serial is None:
        return
    if state not in ('GREEN', 'YELLOW', 'RED', 'ALL_RED'):
        state = 'RED'
    with _arduino_lock:
        try:
            if _arduino is None or not getattr(_arduino, 'is_open', False):
                arduino_try_connect()
            if _arduino is None:
                return
            if _last_sent_arduino_state == state:
                return
            if ARDUINO_CMD_FORMAT == "pinset":
                msg = _format_pinset_message(state)
            else:
                msg = _format_letter_message(state)
            _arduino.write(msg.encode())
            _arduino.flush()
            _last_sent_arduino_state = state
            if SCHEDULER_DEBUG:
                print(f"[Arduino] Sent: {msg.strip()}")
        except Exception as e:
            print(f"[Arduino] Write error: {e}")
            try:
                _arduino.close()
            except Exception:
                pass
            _arduino = None
            _last_sent_arduino_state = None

# start Arduino connect in background
try:
    threading.Thread(target=arduino_try_connect, daemon=True).start()
except Exception:
    pass

# -------------------- Model loader (GPU-aware) --------------------
def load_model(model_key):
    global model, current_model_key, DEVICE_STR
    try:
        from ultralytics import YOLO
    except Exception as e:
        if SCHEDULER_DEBUG:
            print("[Model] ultralytics not available; detection disabled.", e)
        return None
    with _model_lock:
        if current_model_key == model_key and model is not None:
            return model
        try:
            path = MODEL_OPTIONS.get(model_key, model_key)
            if SCHEDULER_DEBUG:
                print(f"[Model] Loading: {model_key} -> {path} on {DEVICE_STR}")
            m = YOLO(path)
            # try to move to CUDA if available
            try:
                if DEVICE_STR.startswith('cuda'):
                    # ultralytics models sometimes accept .to('cuda')
                    try:
                        m.to(DEVICE_STR)
                    except Exception:
                        # if .to not available, rely on internal device handling
                        pass
                # small fuse/opt attempt
                try:
                    m.fuse()
                except Exception:
                    pass
            except Exception:
                pass
            model = m
            current_model_key = model_key
            if SCHEDULER_DEBUG:
                print(f"[Model] Loaded: {model_key}")
            return model
        except Exception as e:
            print(f"[Model] Load failed for {model_key}: {e}")
            model = None
            return None

# preload default model in background (non-blocking)
try:
    threading.Thread(target=load_model, args=(DEFAULT_MODEL_KEY,), daemon=True).start()
except Exception:
    pass

# -------------------- Scheduler logic (unchanged w/ minor logging) --------------------
def synchronized_light_scheduler(workers):
    global _active_green_worker_idx, _worker_iterator, _last_phase_ended_time
    try:
        now = time.time()
        running_idxs = [i for i, w in enumerate(workers) if getattr(w, 'running', False)]
        if not running_idxs:
            _active_green_worker_idx = None
            return

        if _worker_iterator is None:
            _worker_iterator = itertools.cycle(range(len(workers)))

        def compute_green_ms(w):
            base_green = BASE_TRAFFIC.get('GREEN', 8000)
            density_bonus_factor = max(0, getattr(w, 'weighted_count', 0.0) - THRESHOLDS['light']) / (THRESHOLDS['heavy'] * 2.0)
            density_bonus = density_bonus_factor * base_green
            green = base_green + density_bonus
            green = max(MIN_GREEN_DUR, min(base_green * MAX_GREEN_MULTIPLIER, green))
            return green

        if _active_green_worker_idx is None:
            if now - _last_phase_ended_time < (ALL_RED_DURATION_MS / 1000.0):
                return

            best_idx, best_score = None, -1.0
            for i in running_idxs:
                w = workers[i]
                weight = getattr(w, 'weighted_count', 0.0)
                last_green = getattr(w, '_last_green_time', getattr(w, 'last_light_change', 0.0))
                wait = now - last_green
                wait_boost = min(3.0, wait / 10.0)
                score = weight * (1.0 + wait_boost) + 0.001 * wait
                if score > best_score:
                    best_idx, best_score = i, score

            if best_idx is None:
                for _ in range(len(workers)):
                    cand = next(_worker_iterator)
                    if cand in running_idxs:
                        best_idx = cand
                        break

            if best_idx is not None:
                for i, w in enumerate(workers):
                    w.light_state = 'GREEN' if i == best_idx else 'RED'
                    if i == best_idx:
                        w.last_light_change = now
                        w._last_green_time = now
                _active_green_worker_idx = best_idx
                if SCHEDULER_DEBUG:
                    print(f"[Scheduler] Lane {best_idx} GREEN (score {best_score:.2f})")

        if _active_green_worker_idx not in range(len(workers)) or not getattr(workers[_active_green_worker_idx], 'running', False):
            if SCHEDULER_DEBUG:
                print("[Scheduler] Active lane lost/reset")
            _active_green_worker_idx = None
            _last_phase_ended_time = now
            return

        w = workers[_active_green_worker_idx]
        elapsed_ms = (now - w.last_light_change) * 1000.0
        green_ms = compute_green_ms(w)
        yellow_ms = BASE_TRAFFIC.get('YELLOW', 2000)

        other_max = max((getattr(workers[i], 'weighted_count', 0.0) for i in running_idxs if i != _active_green_worker_idx), default=0.0)

        if w.light_state == 'GREEN':
            if (elapsed_ms >= MIN_GREEN_DUR and other_max > max(THRESHOLDS['heavy'], w.weighted_count * 1.8)) or elapsed_ms >= green_ms:
                w.light_state = 'YELLOW'
                w.last_light_change = now
                if SCHEDULER_DEBUG:
                    print(f"[Scheduler] Lane {_active_green_worker_idx} -> YELLOW")

        elif w.light_state == 'YELLOW':
            if elapsed_ms >= yellow_ms:
                w.light_state = 'RED'
                w.last_light_change = now
                _active_green_worker_idx = None
                _last_phase_ended_time = now
                try:
                    next(_worker_iterator)
                except Exception:
                    pass
                if SCHEDULER_DEBUG:
                    print(f"[Scheduler] Lane {w.idx} -> RED. All-red starts.")
                return

        else:
            _active_green_worker_idx = None
            _last_phase_ended_time = now
            if SCHEDULER_DEBUG:
                print("[Scheduler] Unexpected state reset")

    except Exception as e:
        print(f"[Scheduler] Exception: {e}")

# -------------------- Camera Worker (smooth display + async detection) --------------------
class CameraWorker:
    def __init__(self, source, parent_frame, idx, app_state):
        self.source = source
        self.idx = idx
        self.app_state = app_state
        self.cap = None
        self.running = False
        self.last_frame = None          # raw BGR frame (numpy)
        self.frame_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.new_frame_event = threading.Event()   # set when a new frame is available
        self.detections = []            # last finished detections (list)
        self.detect_lock = threading.Lock()
        self.car_count = 0
        self.weighted_count = 0.0
        self.density = 'Light'
        self.light_state = 'RED'
        self.last_light_change = time.time()
        self.density_history = deque()
        self.fps = 0.0
        self.fps_history = deque()
        self._skip_counter = 0
        self._adaptive_skip = DEFAULT_SKIP
        self.panel = self._make_panel(parent_frame)
        self.parent_app = None
        self.fullscreen_win = None
        self.fullscreen_label = None
        self._backend_flag = _get_capture_backend_flag()
        # cache last ImageTk.PhotoImage to avoid GC churn
        self._cached_photoimage = None
        self._display_size = (PANEL_W, PANEL_H)
        self.inference_time_history = deque(maxlen=10)

    def _make_panel(self, parent):
        frame = ctk.CTkFrame(parent, border_width=2, corner_radius=8, fg_color="#2b313a")
        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill=tk.X, padx=6, pady=6)

        self.title_var = tk.StringVar(value=f"Lane {self.idx} - {self.source}")
        title = ctk.CTkLabel(top, textvariable=self.title_var, width=220, anchor='w')
        title.pack(side=tk.LEFT)

        btn_frame = ctk.CTkFrame(top, fg_color='transparent')
        btn_frame.pack(side=tk.RIGHT)

        ctk.CTkButton(btn_frame, text='Start', width=60, command=self.start).pack(side=tk.LEFT, padx=4)
        ctk.CTkButton(btn_frame, text='Stop', width=60, command=self.stop).pack(side=tk.LEFT, padx=4)
        ctk.CTkButton(btn_frame, text='FS', width=40, command=self.open_fullscreen).pack(side=tk.LEFT, padx=4)
        ctk.CTkButton(btn_frame, text='⚙', width=36, command=self.open_settings).pack(side=tk.LEFT, padx=4)

        video_label = tk.Label(frame, text='', width=PANEL_W, height=PANEL_H, bg='black', fg='white')
        video_label.pack(padx=6, pady=(0,6), fill=None)

        info_label = ctk.CTkLabel(frame, text='Init | FPS: 0.0', anchor='w')
        info_label.pack(fill=tk.X, padx=6, pady=(0,8))

        frame.video_label = video_label
        frame.info_label = info_label
        return frame

    def open_settings(self):
        win = tk.Toplevel()
        win.title(f"Settings - Lane {self.idx}")
        win.geometry("420x160")
        wrap = ctk.CTkFrame(win)
        wrap.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        ctk.CTkLabel(wrap, text="Rename lane:").pack(padx=10, pady=(6,4), anchor='w')
        name_var = tk.StringVar(value=self.title_var.get())
        name_entry = ctk.CTkEntry(wrap, textvariable=name_var, width=360)
        name_entry.pack(padx=10, pady=(0,8))

        ctk.CTkLabel(wrap, text="Detection skip (adaptive):").pack(padx=10, pady=(4,2), anchor='w')
        skip_var = tk.IntVar(value=self._adaptive_skip)
        def on_skip_change(val):
            try:
                v = int(val)
                self._adaptive_skip = max(MIN_SKIP, min(MAX_SKIP, v))
                skip_var.set(self._adaptive_skip)
            except Exception:
                pass
        skip_entry = ctk.CTkEntry(wrap, textvariable=skip_var, width=120)
        skip_entry.pack(padx=10, pady=(0,6), anchor='w')

        def do_rename():
            val = name_var.get().strip()
            if val:
                self.title_var.set(val)
                win.destroy()

        ctk.CTkButton(wrap, text="Rename", command=do_rename).pack(side='left', padx=12, pady=6)

        def do_remove():
            if messagebox.askyesno("Remove", f"Remove lane {self.idx}?"):
                try:
                    self.parent_app.remove_camera(self.idx)
                except Exception as e:
                    print("Remove failed:", e)
                win.destroy()

        ctk.CTkButton(wrap, text="Remove", fg_color="#EA4335", hover_color="#c8382d", command=do_remove).pack(side='right', padx=12, pady=6)

    def open_fullscreen(self):
        """Open fullscreen window showing this camera feed (smooth updates)."""
        if self.fullscreen_win and self.fullscreen_win.winfo_exists():
            try:
                self.fullscreen_win.focus_set()
            except Exception:
                pass
            return

        self.fullscreen_win = tk.Toplevel()
        self.fullscreen_win.title(f"Fullscreen - Lane {self.idx}")
        # fullscreen attribute works differently across platforms; set window size as fallback
        try:
            self.fullscreen_win.attributes('-fullscreen', True)
        except Exception:
            self.fullscreen_win.geometry(f"{self.winfo_screenwidth()}x{self.winfo_screenheight()}")

        self.fullscreen_label = tk.Label(self.fullscreen_win, bg='black')
        self.fullscreen_label.pack(fill=tk.BOTH, expand=True)

        def exit_fullscreen(event=None):
            try:
                self.fullscreen_win.destroy()
            except Exception:
                pass
            self.fullscreen_win = None

        self.fullscreen_win.bind('<Escape>', exit_fullscreen)

        def update_fullscreen():
            if not self.fullscreen_win or not self.fullscreen_win.winfo_exists():
                return
            # build overlayed frame quickly
            img = self._build_display_image(scale_to=None)  # give original size
            if img is not None:
                try:
                    imgtk = ImageTk.PhotoImage(image=img)
                    self.fullscreen_label.configure(image=imgtk)
                    self.fullscreen_label.imgtk = imgtk
                except Exception:
                    pass
            self.fullscreen_win.after(30, update_fullscreen)

        update_fullscreen()

    def start(self):
        if self.running:
            return
        self.stop_event.clear()
        src = self.source
        try:
            src_int = int(self.source) if isinstance(self.source, str) and self.source.isdigit() else None
            if src_int is not None:
                src = src_int
        except Exception:
            pass
        try:
            self.cap = cv2.VideoCapture(src, self._backend_flag)
        except Exception:
            self.cap = cv2.VideoCapture(src)
        if not self.cap or not self.cap.isOpened():
            messagebox.showwarning("Camera Error", f"Camera {self.idx} failed to open: {self.source}")
            return
        # try to reduce internal buffer
        try:
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        except Exception:
            pass
        self.running = True
        self._skip_counter = 0
        # read loop (grabs frames continuously)
        threading.Thread(target=self._read_loop, daemon=True, name=f"Reader-{self.idx}").start()
        # detection loop (background, uses last_frame snapshot)
        threading.Thread(target=self._detect_loop, daemon=True, name=f"Detector-{self.idx}").start()
        # worker UI updater: this will respond to new_frame_event and update label
        threading.Thread(target=self._ui_update_worker_loop, daemon=True, name=f"UIUpdater-{self.idx}").start()

    def stop(self):
        self.running = False
        self.stop_event.set()
        try:
            if self.cap:
                self.cap.release()
        except Exception:
            pass
        if self.fullscreen_win:
            try:
                self.fullscreen_win.destroy()
            except Exception:
                pass
            self.fullscreen_win = None
        # clear cached image
        self._cached_photoimage = None
        self.new_frame_event.clear()

    def _read_loop(self):
        """Continuously read frames and update last_frame; event-driven UI updates."""
        while self.running and not self.stop_event.is_set():
            if not self.cap or not self.cap.isOpened():
                time.sleep(0.2)
                continue
            ok = self.cap.grab()
            if not ok:
                ret, frame = self.cap.read()
            else:
                ret, frame = self.cap.retrieve()
            if not ret or frame is None:
                time.sleep(0.01)
                continue

            now = time.time()
            self.fps_history.append((now, 1))
            while self.fps_history and now - self.fps_history[0][0] > FPS_WINDOW_S:
                self.fps_history.popleft()
            total_frames = sum(v for _, v in self.fps_history)
            total_time = (now - self.fps_history[0][0]) if self.fps_history else 1.0
            if total_time > 0:
                self.fps = total_frames / total_time

            with self.frame_lock:
                self.last_frame = frame
            # flag a new frame for UI thread
            self.new_frame_event.set()
            # tiny sleep to yield
            time.sleep(0.001)

    def _detect_loop(self):
        """Runs inference on snapshots asynchronously; updates self.detections when done."""
        while self.running and not self.stop_event.is_set():
            # adaptive skip (we only attempt inference every _adaptive_skip frames)
            self._skip_counter = (self._skip_counter + 1) % max(1, self._adaptive_skip)
            if self._skip_counter != 0:
                time.sleep(0.005)
                continue

            # snapshot frame for inference
            with self.frame_lock:
                frame = None if self.last_frame is None else self.last_frame.copy()
            if frame is None:
                time.sleep(0.02)
                continue

            # try to acquire a semaphore slot for inference (limits concurrent)
            acquired = inference_semaphore.acquire(timeout=0.5)
            if not acquired:
                time.sleep(0.02)
                continue

            start_inf = time.time()
            try:
                model_key = self.app_state.get('model_key', DEFAULT_MODEL_KEY)
                imgsz = int(self.app_state.get('imgsz', DEFAULT_IMG_SZ))
                conf = float(self.app_state.get('confidence', DEFAULT_CONF))

                loaded = load_model(model_key)
                if loaded is None:
                    # No model — reset and continue
                    with self.detect_lock:
                        self.detections = []
                    self.car_count = 0
                    self.weighted_count = 0.0
                    self._update_density()
                    time.sleep(0.2)
                    continue

                h, w = frame.shape[:2]
                # resize for model input while preserving aspect ratio
                if w != imgsz:
                    small = cv2.resize(frame, (imgsz, int(h * (imgsz / w))), interpolation=cv2.INTER_LINEAR)
                else:
                    small = frame

                # run inference (ultralytics returns an iterable of results)
                try:
                    results = loaded(small, classes=DETECTION_CLASSES, conf=conf, verbose=False)
                except Exception as e:
                    # fallback single-call style
                    try:
                        results = loaded.predict(small, classes=DETECTION_CLASSES, conf=conf)
                    except Exception as ex:
                        print(f"[Infer] Inference failed: {e} / {ex}")
                        results = []

                detections = []
                weighted_count = 0.0
                scale_x = w / small.shape[1]
                scale_y = h / small.shape[0]

                for r in results:
                    boxes = getattr(r, 'boxes', [])
                    for box in boxes:
                        try:
                            coords = box.xyxy[0].tolist()
                        except Exception:
                            # older versions may use box.xyxy
                            try:
                                coords = box.xyxy.tolist()[0]
                            except Exception:
                                continue
                        x1, y1, x2, y2 = map(int, coords)
                        # conf and cls extraction compatibility
                        try:
                            conf_score = float(box.conf[0]) if hasattr(box.conf, '__len__') else float(box.conf)
                        except Exception:
                            conf_score = 0.0
                        try:
                            cls_id = int(box.cls[0]) if hasattr(box.cls, '__len__') else int(box.cls)
                        except Exception:
                            cls_id = int(getattr(box, 'cls', 0))

                        label = loaded.names.get(cls_id, str(cls_id)) if hasattr(loaded, 'names') else str(cls_id)

                        # rescale to original
                        x1 = int(x1 * scale_x)
                        x2 = int(x2 * scale_x)
                        y1 = int(y1 * scale_y)
                        y2 = int(y2 * scale_y)

                        detections.append((x1, y1, x2, y2, conf_score, cls_id, label))
                        weighted_count += VEHICLE_WEIGHTS.get(cls_id, 1.0)

                # update detection results
                with self.detect_lock:
                    self.detections = detections
                self.car_count = len(detections)
                self.weighted_count = weighted_count
                self._update_density()

            except Exception as e:
                print(f"Error in detection loop {self.idx}: {e}")
            finally:
                inf_time = (time.time() - start_inf)
                try:
                    self.inference_time_history.append(inf_time)
                except Exception:
                    pass
                # adapt skip based on measured inference time
                try:
                    avg_inf = sum(self.inference_time_history) / max(1, len(self.inference_time_history))
                    # target detection rate depends on device: faster -> smaller skip
                    # desired detection interval (s) ~ clamp(avg_inf * factor, 0.12, 1.5)
                    factor = 2.0
                    desired_interval = max(0.12, min(1.5, avg_inf * factor))
                    # capture fps estimate:
                    cap_fps = max(1.0, self.fps)
                    desired_skip = int(max(1, round(desired_interval * cap_fps)))
                    self._adaptive_skip = max(MIN_SKIP, min(MAX_SKIP, desired_skip))
                except Exception:
                    pass
                inference_semaphore.release()

            # tiny gap
            time.sleep(0.005)

    def _update_density(self):
        now = time.time()
        self.density_history.append((now, self.weighted_count))
        while self.density_history and now - self.density_history[0][0] > DENSITY_WINDOW_S:
            self.density_history.popleft()
        if not self.density_history:
            self.density = 'Light'
            return
        avg = sum(c for _, c in self.density_history) / len(self.density_history)
        if avg <= THRESHOLDS['light']:
            self.density = 'Light'
        elif avg <= THRESHOLDS['moderate']:
            self.density = 'Moderate'
        elif avg <= THRESHOLDS['heavy']:
            self.density = 'Heavy'
        else:
            self.density = 'Jammed'

    def _build_display_image(self, scale_to=None):
        """Return a PIL.Image for display: builds from last_frame + last detections (fast)."""
        with self.frame_lock:
            frame = None if self.last_frame is None else self.last_frame.copy()
        if frame is None:
            # make a blank PIL image
            blank = np.zeros((PANEL_H, PANEL_W, 3), np.uint8)
            cv2.putText(blank, 'No Feed', (PANEL_W // 2 - 40, PANEL_H // 2), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (120, 120, 120), 2)
            img = Image.fromarray(cv2.cvtColor(blank, cv2.COLOR_BGR2RGBA))
            return img

        # optionally scale to requested size
        if scale_to is None:
            target_w, target_h = frame.shape[1], frame.shape[0]
        else:
            target_w, target_h = scale_to

        # resize once to target
        disp = cv2.resize(frame, (min(target_w, frame.shape[1]), min(target_h, frame.shape[0])), interpolation=cv2.INTER_AREA)
        # overlay detections quickly using last known detections
        with self.detect_lock:
            dets = list(self.detections)

        # draw boxes on disp (scale accordingly)
        # compute scale factors
        fx = disp.shape[1] / frame.shape[1]
        fy = disp.shape[0] / frame.shape[0]

        for (x1, y1, x2, y2, conf_score, cls_id, label) in dets:
            sx1, sy1 = int(x1 * fx), int(y1 * fy)
            sx2, sy2 = int(x2 * fx), int(y2 * fy)
            cv2.rectangle(disp, (sx1, sy1), (sx2, sy2), (50, 200, 50), 2)
            text = f"{label} {conf_score:.2f}"
            cv2.putText(disp, text, (sx1, max(16, sy1 - 6)), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 255, 255), 1, cv2.LINE_AA)

        # put overlays like counts, density, time
        count_text = f"Vehicles: {self.car_count} (W:{self.weighted_count:.1f})"
        cv2.putText(disp, count_text, (6, 20), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1, cv2.LINE_AA)
        density_color = (0, 255, 0) if self.density == 'Light' else (0, 255, 255) if self.density == 'Moderate' else (0, 165, 255) if self.density == 'Heavy' else (0, 0, 255)
        cv2.putText(disp, f"Density: {self.density}", (6, 42), cv2.FONT_HERSHEY_SIMPLEX, 0.5, density_color, 1, cv2.LINE_AA)
        light_color = (0, 255, 0) if self.light_state == 'GREEN' else (0, 255, 255) if self.light_state == 'YELLOW' else (0, 0, 255)
        cv2.putText(disp, f"Light: {self.light_state}", (6, 62), cv2.FONT_HERSHEY_SIMPLEX, 0.5, light_color, 1, cv2.LINE_AA)

        time_text = 'Waiting'
        if self.light_state in ('GREEN', 'YELLOW'):
            base_green = BASE_TRAFFIC['GREEN']
            density_bonus_factor = max(0, self.weighted_count - THRESHOLDS['light']) / (THRESHOLDS['heavy'] * 2.0)
            density_bonus = density_bonus_factor * base_green
            green_dur = base_green + density_bonus
            green_dur = max(MIN_GREEN_DUR, min(base_green * MAX_GREEN_MULTIPLIER, green_dur))
            duration_ms = green_dur if self.light_state == 'GREEN' else BASE_TRAFFIC['YELLOW']
            time_left_s = max(0, duration_ms / 1000 - (time.time() - self.last_light_change))
            time_text = f"T-L: {time_left_s:.1f}s"
        else:
            if _active_green_worker_idx is None:
                time_since_phase_end = time.time() - _last_phase_ended_time
                if time_since_phase_end * 1000 < ALL_RED_DURATION_MS:
                    all_red_left = (ALL_RED_DURATION_MS / 1000) - time_since_phase_end
                    time_text = f"ALL RED: {max(0, all_red_left):.1f}s"

        cv2.putText(disp, time_text, (6, 82), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (240, 240, 240), 1, cv2.LINE_AA)

        if SHOW_FPS:
            cv2.putText(disp, f"CAP FPS:{self.fps:.1f}", (disp.shape[1] - 110, 20), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 0), 1, cv2.LINE_AA)

        if SHOW_TIMESTAMP:
            cv2.putText(disp, datetime.now().strftime('%H:%M:%S'), (disp.shape[1] - 120, 40), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (200, 200, 200), 1, cv2.LINE_AA)

        # circle indicator
        cv2.circle(disp, (disp.shape[1] - 20, disp.shape[0] - 20), 10, light_color, -1)

        # convert BGR->RGBA for PIL
        try:
            disp_rgba = cv2.cvtColor(disp, cv2.COLOR_BGR2RGBA)
        except Exception:
            disp_rgba = cv2.cvtColor(disp, cv2.COLOR_BGR2RGB)
        try:
            return Image.fromarray(disp_rgba)
        except Exception:
            # fallback to convert BGR to RGB then PIL
            return Image.fromarray(cv2.cvtColor(disp, cv2.COLOR_BGR2RGB))

    def _ui_update_worker_loop(self):
        """Update the panel when a new frame is available. Avoids redundant periodic updates."""
        last_update = 0.0
        while self.running and not self.stop_event.is_set():
            got = self.new_frame_event.wait(timeout=1.0)
            if not got:
                continue
            self.new_frame_event.clear()
            if not self.panel or not self.panel.winfo_exists():
                continue

            # Build display image scaled to panel
            img = self._build_display_image(scale_to=self._display_size)
            if img is None:
                continue
            try:
                imgtk = ImageTk.PhotoImage(image=img)
                self._cached_photoimage = imgtk
                try:
                    self.panel.video_label.configure(image=imgtk, text='')
                    self.panel.video_label.imgtk = imgtk
                except Exception:
                    pass
            except Exception as e:
                print(f"[UIUpdate] PhotoImage creation failed for worker {self.idx}: {e}")

            # update info label (use CTk label update)
            try:
                # approximate inference rate display
                avg_inf = (sum(self.inference_time_history) / len(self.inference_time_history)) if self.inference_time_history else 0.0
                inf_ms = avg_inf * 1000.0 if avg_inf else 0.0
                self.panel.info_label.configure(text=(f"W:{self.weighted_count:.1f} | D:{self.density} | L:{self.light_state} | "
                                                      f"CAP FPS:{self.fps:.1f} | INF:{inf_ms:.0f}ms | SKIP:{self._adaptive_skip}"))
            except Exception:
                pass

# -------------------- Application (enhanced add-camera UI + optimizations) --------------------
class AITrafficGridApp(ctk.CTk):
    def __init__(self, camera_sources):
        super().__init__()
        self.title('AI Traffic Density — Smooth Multi-Lane Control')
        self.geometry('1280x900')
        self.camera_sources = list(camera_sources)
        self.workers = []
        self.app_state = {'model_key': DEFAULT_MODEL_KEY, 'imgsz': DEFAULT_IMG_SZ, 'confidence': DEFAULT_CONF, 'skip_frames': DEFAULT_SKIP}
        self.detected_cameras = []
        self._build_ui()
        threading.Thread(target=self._detect_system_cameras, daemon=True).start()
        self.create_workers()
        self.protocol('WM_DELETE_WINDOW', self.on_close)
        self.after(200, self.light_scheduler_loop)
        self.after(500, self.ui_update_loop)

    def _build_ui(self):
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        topbar = ctk.CTkFrame(self, fg_color='#1d232c')
        topbar.grid(row=0, column=0, sticky='ew', padx=10, pady=(10, 5))

        ctk.CTkLabel(topbar, text='Model:').pack(side=tk.LEFT, padx=(10, 4))
        self.model_combo = ctk.CTkComboBox(topbar, values=list(MODEL_OPTIONS.keys()), width=180, command=self.on_model_change)
        self.model_combo.set(DEFAULT_MODEL_KEY)
        self.model_combo.pack(side=tk.LEFT)

        ctk.CTkLabel(topbar, text='Confidence:').pack(side=tk.LEFT, padx=(15, 4))
        self.conf_slider = ctk.CTkSlider(topbar, from_=0.2, to=0.8, number_of_steps=60, width=120, command=self.on_confidence_change)
        self.conf_slider.set(DEFAULT_CONF)
        self.conf_slider.pack(side=tk.LEFT)

        ctk.CTkLabel(topbar, text='ImgSz:').pack(side=tk.LEFT, padx=(15, 4))
        self.imgsz_var = tk.StringVar(value=str(DEFAULT_IMG_SZ))
        self.imgsz_entry = ctk.CTkComboBox(topbar, values=['320', '480', '640', '800', '960', '1280'], variable=self.imgsz_var, width=80, command=self.on_imgsz_change)
        self.imgsz_entry.pack(side=tk.LEFT)

        ctk.CTkLabel(topbar, text='SkipFrames:').pack(side=tk.LEFT, padx=(15, 4))
        self.skip_spin = ctk.CTkComboBox(topbar, values=[str(i) for i in range(1, 13)], width=60, command=self.on_skip_change)
        self.skip_spin.set(str(DEFAULT_SKIP))
        self.skip_spin.pack(side=tk.LEFT)

        ctk.CTkButton(topbar, text='Start All', command=self.start_all, fg_color='#34A853').pack(side=tk.RIGHT, padx=10)
        ctk.CTkButton(topbar, text='Stop All', command=self.stop_all, fg_color='#EA4335').pack(side=tk.RIGHT)
        ctk.CTkButton(topbar, text='Add Camera', command=self.prompt_add_camera, fg_color='#4285F4').pack(side=tk.RIGHT, padx=(10, 6))
        self.debug_var = tk.BooleanVar(value=SCHEDULER_DEBUG)
        ctk.CTkCheckBox(topbar, text='Scheduler Debug', variable=self.debug_var, command=self.toggle_debug).pack(side=tk.RIGHT, padx=(6, 6))

        self.grid_frame = ctk.CTkFrame(self, fg_color='transparent')
        self.grid_frame.grid(row=1, column=0, sticky='nsew', padx=10, pady=(5, 10))

        self.status_bar = ctk.CTkLabel(self, text='Ready', fg_color='#1d232c', anchor='w')
        self.status_bar.grid(row=2, column=0, sticky='ew', padx=0, pady=0, ipady=5)

    def toggle_debug(self):
        global SCHEDULER_DEBUG
        SCHEDULER_DEBUG = bool(self.debug_var.get())

    def create_workers(self):
        # create CameraWorker for each configured source
        for i, src in enumerate(self.camera_sources):
            w = CameraWorker(src, self.grid_frame, i, self.app_state)
            w.parent_app = self
            self.workers.append(w)
        self.arrange_grid()

    def arrange_grid(self):
        count = len(self.workers)
        if count == 0:
            return
        cols = max(1, int(np.ceil(np.sqrt(count))))
        rows = int(np.ceil(count / cols))
        for r in range(rows):
            self.grid_frame.grid_rowconfigure(r, weight=1, uniform='row')
        for c in range(cols):
            self.grid_frame.grid_columnconfigure(c, weight=1, uniform='col')
        for idx, w in enumerate(self.workers):
            row, col = divmod(idx, cols)
            w.panel.grid(row=row, column=col, padx=8, pady=8, sticky='nsew')
            w.idx = idx
            if w.title_var.get().startswith("Lane "):
                w.title_var.set(f"Lane {idx} - {w.source}")

    def on_model_change(self, selected):
        if selected not in MODEL_OPTIONS:
            messagebox.showerror('Model Error', 'Unknown model selected.')
            return
        self.status_bar.configure(text=f'Loading model: {selected}...')
        def loader():
            if load_model(selected):
                self.app_state['model_key'] = selected
                self.status_bar.configure(text=f"Model '{selected}' loaded. Ready.")
            else:
                self.status_bar.configure(text=f"Model loading failed: {selected}")
        threading.Thread(target=loader, daemon=True).start()

    def on_confidence_change(self, val):
        try:
            self.app_state['confidence'] = float(val)
        except Exception:
            pass

    def on_imgsz_change(self, val):
        try:
            self.app_state['imgsz'] = int(val)
        except Exception:
            pass

    def on_skip_change(self, val):
        try:
            v = int(val)
            # set all worker adaptive skips to this (manual override)
            for w in self.workers:
                w._adaptive_skip = max(MIN_SKIP, min(MAX_SKIP, v))
            self.app_state['skip_frames'] = v
        except Exception:
            pass

    def start_all(self):
        global _active_green_worker_idx, _worker_iterator, _last_phase_ended_time
        _active_green_worker_idx = None
        _last_phase_ended_time = time.time()
        _worker_iterator = itertools.cycle(range(len(self.workers)))
        for w in self.workers:
            w.light_state = 'RED'
            w.last_light_change = time.time()
            w.start()
        self.status_bar.configure(text='All camera feeds started.')

    def stop_all(self):
        for w in self.workers:
            w.stop()
        # hardware safety
        arduino_set_light('ALL_RED')
        self.status_bar.configure(text='All camera feeds stopped.')

    def light_scheduler_loop(self):
        if any(w.running for w in self.workers):
            with _global_light_control_lock:
                synchronized_light_scheduler(self.workers)
            self._update_light_indicators()
        self.after(200, self.light_scheduler_loop)

    def _update_light_indicators(self):
        # Determine global state priority: GREEN > YELLOW > RED
        global_state = 'RED'
        for i, w in enumerate(self.workers):
            if w.light_state == 'GREEN':
                global_state = 'GREEN'
                break
            if w.light_state == 'YELLOW' and global_state != 'GREEN':
                global_state = 'YELLOW'

        for i, w in enumerate(self.workers):
            if w.light_state == 'GREEN':
                w.panel.configure(border_width=2, fg_color="#223322")
            elif w.light_state == 'YELLOW':
                w.panel.configure(border_width=2, fg_color="#333322")
            else:
                w.panel.configure(border_width=2, fg_color="#2b313a")

        try:
            threading.Thread(target=arduino_set_light, args=(global_state,), daemon=True).start()
        except Exception:
            arduino_set_light(global_state)

    def ui_update_loop(self):
        # keep status summary updated periodically
        total_vehicles = 0
        fps_list = []
        active_workers = 0
        for w in self.workers:
            try:
                if not w.panel.winfo_exists():
                    continue
            except Exception:
                continue
            if w.running:
                active_workers += 1
                total_vehicles += w.car_count
                fps_list.append(w.fps)
        avg_fps = sum(fps_list) / len(fps_list) if fps_list else 0.0
        if active_workers > 0:
            try:
                running_infers = MAX_CONCURRENT_INFERENCES - inference_semaphore._value
            except Exception:
                running_infers = 0
            self.status_bar.configure(text=(f"Active Lanes: {active_workers} | Total Vehicles: {total_vehicles} "
                                           f"| Avg CAP FPS: {avg_fps:.1f} | Model: {self.app_state['model_key']} "
                                           f"| Inferences Running: {running_infers}"))
        else:
            self.status_bar.configure(text="All systems idle. Press 'Start All' to begin monitoring.")
        self.after(500, self.ui_update_loop)

    def add_camera(self, src):
        idx = len(self.workers)
        self.camera_sources.append(src)
        w = CameraWorker(src, self.grid_frame, idx, self.app_state)
        w.parent_app = self
        self.workers.append(w)
        self.arrange_grid()
        self.status_bar.configure(text=f"Camera {idx} added: {src}")

    def prompt_add_camera(self):
        top = tk.Toplevel()
        top.title("Add Camera")
        top.geometry("520x280")
        wrap = ctk.CTkFrame(top)
        wrap.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        ctk.CTkLabel(wrap, text="Detected cameras (select to add):").pack(padx=8, pady=(6,4), anchor='w')

        values = [f"{name}  ({src})" for name, src in self.detected_cameras]
        self.add_cam_combo = ctk.CTkComboBox(wrap, values=values, width=440)
        if values:
            self.add_cam_combo.set(values[0])
        self.add_cam_combo.pack(padx=8, pady=(0,6))

        ctk.CTkLabel(wrap, text="Or enter camera source (index or URL):").pack(padx=8, pady=(4,2), anchor='w')
        entry_var = tk.StringVar()
        entry = ctk.CTkEntry(wrap, textvariable=entry_var, width=440)
        entry.pack(padx=8, pady=(0,8))

        def on_add():
            sel = self.add_cam_combo.get()
            val = entry_var.get().strip()
            src = None
            if val:
                try:
                    src = int(val) if val.isdigit() else val
                except Exception:
                    src = val
            elif sel:
                idx = self.add_cam_combo.get()
                for name, s in self.detected_cameras:
                    display = f"{name}  ({s})"
                    if display == idx:
                        src = s
                        break
            if src is None:
                messagebox.showwarning("Input", "Please select or enter a camera source.")
                return
            self.add_camera(src)
            top.destroy()

        btn = ctk.CTkButton(wrap, text="Add", command=on_add, width=100)
        btn.pack(side=tk.RIGHT, padx=12, pady=8)
        cancel = ctk.CTkButton(wrap, text="Cancel", command=lambda: top.destroy(), width=100)
        cancel.pack(side=tk.RIGHT, padx=(0,6), pady=8)

    def remove_camera(self, idx):
        if idx < 0 or idx >= len(self.workers):
            return
        w = self.workers[idx]
        try:
            w.stop()
        except Exception:
            pass
        try:
            w.panel.destroy()
        except Exception:
            pass
        del self.workers[idx]
        try:
            del self.camera_sources[idx]
        except Exception:
            pass
        self.arrange_grid()
        self.status_bar.configure(text=f"Removed camera {idx}. {len(self.workers)} remaining.")

    def on_close(self):
        self.stop_all()
        time.sleep(0.5)
        arduino_set_light('ALL_RED')
        self.destroy()

    # ---------------- Camera enumeration helpers ----------------
    def _detect_system_cameras(self):
        detected = []
        try:
            if platform.system() == 'Windows':
                proc = subprocess.run(['ffmpeg', '-list_devices', 'true', '-f', 'dshow', '-i', 'dummy'],
                                      stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True, timeout=5)
                out = proc.stderr + proc.stdout
                import re
                names = re.findall(r'\"([^\"]+)\"', out)
                if names:
                    uniq = []
                    for n in names:
                        if n not in uniq:
                            uniq.append(n)
                    for i in range(0, 12):
                        cap = cv2.VideoCapture(i, _get_capture_backend_flag())
                        ok = cap.isOpened()
                        cap.release()
                        if ok:
                            name = uniq.pop(0) if uniq else f"Camera {i}"
                            detected.append((name, i))
        except Exception:
            detected = []

        if not detected:
            max_probe = 10
            for i in range(max_probe):
                try:
                    cap = cv2.VideoCapture(i, _get_capture_backend_flag())
                    if cap is None:
                        continue
                    ok, _ = cap.read()
                    if cap.isOpened():
                        detected.append((f"Camera {i}", i))
                    cap.release()
                except Exception:
                    try:
                        cap.release()
                    except Exception:
                        pass
            for s in list(self.camera_sources):
                if isinstance(s, str) and s not in [str(src) for _, src in detected]:
                    detected.append((f"Configured {s}", s))

        if not detected:
            detected.append(("No cameras found", ""))
        self.detected_cameras = detected

# -------------------- Run --------------------
if __name__ == '__main__':
    missing = []
    try:
        import customtkinter as _ct
    except Exception:
        missing.append('customtkinter')
    try:
        import numpy as _n
    except Exception:
        missing.append('numpy')
    try:
        import cv2 as _cv
    except Exception:
        missing.append('opencv-python')
    try:
        from ultralytics import YOLO as _y
    except Exception:
        # model optional — continue
        pass
    try:
        from PIL import Image as _Image
    except Exception:
        missing.append('Pillow')

    if missing:
        msg = "Missing packages: " + ", ".join(missing) + ". Install with pip before running."
        print(msg)
        try:
            r = tk.Tk(); r.withdraw(); messagebox.showerror('Missing Packages', msg); r.destroy()
        except Exception:
            pass

    # Try connect Arduino early (non-blocking)
    try:
        threading.Thread(target=arduino_try_connect, daemon=True).start()
    except Exception:
        pass

    app = AITrafficGridApp(CAMERA_SOURCES)
    app.mainloop()
