from ui.process_entropy import executable_entropy


def test_executable_entropy_is_shannon_bits_per_byte(tmp_path):
    sample = tmp_path / "uniform.bin"
    sample.write_bytes(bytes(range(256)) * 1024)

    assert executable_entropy(sample) == 8.0


def test_low_entropy_executable_sample_is_not_overstated(tmp_path):
    sample = tmp_path / "repeated.bin"
    sample.write_bytes(b"A" * (256 * 1024))

    assert executable_entropy(sample) == 0.0


def test_entropy_sampling_is_bounded_to_configured_sample_size(tmp_path, monkeypatch):
    from pathlib import Path

    sample = tmp_path / "large.bin"
    sample.write_bytes((bytes(range(256)) * 1024) + (b"Z" * (8 * 1024 * 1024)))
    bytes_read = 0
    real_open = Path.open

    class CountingReader:
        def __init__(self, source):
            self.source = source

        def __enter__(self):
            self.source.__enter__()
            return self

        def __exit__(self, *args):
            return self.source.__exit__(*args)

        def seek(self, offset):
            return self.source.seek(offset)

        def read(self, count):
            nonlocal bytes_read
            result = self.source.read(count)
            bytes_read += len(result)
            return result

    monkeypatch.setattr(Path, "open", lambda path, *args, **kwargs: CountingReader(real_open(path, *args, **kwargs)))

    score = executable_entropy(sample, sample_bytes=256 * 1024)

    assert 0.0 < score < 8.0
    assert bytes_read <= 256 * 1024
