from src.ai.text_extraction import extract_text_preview


def test_plain_text_extracted():
    result = extract_text_preview("note.txt", b"hello world")
    assert result.supported is True
    assert "hello world" in result.text


def test_unsupported_binary_extension():
    result = extract_text_preview("archive.zip", b"\x50\x4b\x03\x04random bytes")
    assert result.supported is False


def test_invalid_utf8_text_file_rejected():
    result = extract_text_preview("broken.txt", b"\xff\xfe\x00bad")
    assert result.supported is False
