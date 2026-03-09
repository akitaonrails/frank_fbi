require "test_helper"

class ScreenshotCapturerTest < ActiveSupport::TestCase
  test "returns empty hash for empty URL list" do
    capturer = ScreenshotCapturer.new([])
    assert_equal({}, capturer.capture)
  end

  test "returns empty hash for nil input" do
    capturer = ScreenshotCapturer.new(nil)
    assert_equal({}, capturer.capture)
  end

  test "limits to MAX_URLS" do
    urls = 8.times.map { |i| "https://example#{i}.com" }
    capturer = ScreenshotCapturer.new(urls)
    assert_equal 5, capturer.instance_variable_get(:@urls).size
  end

  test "deduplicates URLs" do
    urls = ["https://example.com", "https://example.com", "https://other.com"]
    capturer = ScreenshotCapturer.new(urls)
    assert_equal 2, capturer.instance_variable_get(:@urls).size
  end

  test "preserves URL order after dedup" do
    urls = ["https://z.com", "https://a.com", "https://z.com"]
    capturer = ScreenshotCapturer.new(urls)
    assert_equal ["https://z.com", "https://a.com"], capturer.instance_variable_get(:@urls)
  end

  test "handles browser creation failure gracefully" do
    capturer = StubCapturerBrowserFails.new(["https://example.com"])
    result = capturer.capture
    assert_equal({}, result)
  end

  test "captures URLs using browser and returns hash keyed by URL" do
    capturer = StubCapturerSuccess.new(["https://example.com", "https://other.com"])
    result = capturer.capture

    assert_equal 2, result.size
    assert result.key?("https://example.com")
    assert result.key?("https://other.com")
    result.each_value { |v| assert_equal "fake_base64", v }
  end

  test "skips failed URLs and continues with remaining" do
    capturer = StubCapturerPartialFail.new(["https://bad.com", "https://good.com"])
    result = capturer.capture

    assert_equal 1, result.size
    refute result.key?("https://bad.com")
    assert result.key?("https://good.com")
  end

  private

  # Test double that simulates browser failure on create
  class StubCapturerBrowserFails < ScreenshotCapturer
    private

    def create_browser
      raise Ferrum::BrowserError, "Chrome not found"
    end
  end

  # Test double that returns fake data for all URLs
  class StubCapturerSuccess < ScreenshotCapturer
    private

    def create_browser
      FakeBrowser.new
    end

    def capture_url(_browser, _url, _timeout)
      "fake_base64"
    end
  end

  # Test double that fails on specific URLs
  class StubCapturerPartialFail < ScreenshotCapturer
    private

    def create_browser
      FakeBrowser.new
    end

    def capture_url(_browser, url, _timeout)
      raise Ferrum::TimeoutError, "timeout" if url.include?("bad.com")
      "fake_base64"
    end
  end

  class FakeBrowser
    def command(*); end
    def quit; end
  end
end
