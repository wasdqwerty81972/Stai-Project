    def update_metrics(self):
        try:
            uptime = int(time.time() - self.start_time)
            mins, secs = divmod(uptime, 60)
            hours, mins = divmod(mins, 60)
            self.lbl_uptime.setText('Uptime: %02d:%02d:%02d' % (hours, mins, secs))
            try:
                import psutil
                mem_mb = psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
                self.lbl_mem.setText('Mem: %.1f MB' % mem_mb)
            except Exception:
                pass
            ratio = self.passed / self.dropped if self.dropped > 0 else (float(self.passed) if self.passed > 0 else 0.0)
            if self.passed == 0 and self.dropped == 0:
                ratio_str = '0.00'
            else:
                ratio_str = '%.2f' % ratio
            self.lbl_ratio.setText('Pass/Drop Ratio: ' + ratio_str)
            self.lbl_passed.setText('Passed: ' + str(self.passed))
            self.lbl_dropped.setText('Dropped: ' + str(self.dropped))
            self.lbl_total.setText('Total Processed: ' + str(self.total_processed))
        except Exception:
            pass

    def log_event(self, msg, color):
        try:
            ts = time.strftime('%H:%M:%S.') + ('%03d' % (int((time.time() % 1) * 1000)))
            line = ts + ' ' + msg
            self.log_buffer.append((line, color))
            if len(self.log_buffer) > self.log_max:
                self.log_buffer = self.log_buffer[-self.log_max:]
            self.log_view.clear()
            for l, c in self.log_buffer:
                self.log_view.appendPlainText(l)
            self.log_view.ensureCursorVisible()
        except Exception:
            pass

    def _apply_style(self):
        try:
            style = ("QMainWindow{background-color:" + SLATE_900 + ";} " +
                     "QSplitter::handle{background-color:" + SLATE_700 + ";} " +
                     "QPushButton{background-color:" + SLATE_800 + ";color:" + SLATE_400 + ";border:1px solid " + SLATE_700 + ";padding:6px;} " +
                     "QPushButton:disabled{background-color:" + SLATE_900 + ";color:" + SLATE_700 + ";} " +
                     "QPushButton:hover{background-color:" + BLUE_500 + ";} " +
                     "QPlainTextEdit{background-color:" + SLATE_900 + ";color:" + SLATE_400 + ";border:1px solid " + SLATE_700 + ";font-family:monospace;}")
            self.setStyleSheet(style)
        except Exception:
            pass
