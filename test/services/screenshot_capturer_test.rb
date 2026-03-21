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

  # --- SSRF protection tests (Issue 3: private IP blocking) ---

  # Helper: create a capturer subclass that stubs DNS resolution
  def capturer_with_resolved_ip(ip)
    klass = Class.new(ScreenshotCapturer) do
      define_method(:resolve_host) { |_host| ip }
    end
    klass.new([])
  end

  test "blocks localhost URL" do
    capturer = capturer_with_resolved_ip("127.0.0.1")
    refute capturer.send(:safe_url?, "http://localhost:8080/admin")
  end

  test "blocks RFC 1918 10.x.x.x URL" do
    capturer = capturer_with_resolved_ip("10.0.0.1")
    refute capturer.send(:safe_url?, "https://internal.corp.local")
  end

  test "blocks RFC 1918 172.16.x.x URL" do
    capturer = capturer_with_resolved_ip("172.16.0.50")
    refute capturer.send(:safe_url?, "https://docker-service.local")
  end

  test "blocks RFC 1918 192.168.x.x URL" do
    capturer = capturer_with_resolved_ip("192.168.1.1")
    refute capturer.send(:safe_url?, "https://router.local")
  end

  test "blocks IPv6 loopback URL" do
    capturer = capturer_with_resolved_ip("::1")
    refute capturer.send(:safe_url?, "http://[::1]:3000")
  end

  test "allows public IP URL" do
    capturer = capturer_with_resolved_ip("93.184.216.34")
    assert capturer.send(:safe_url?, "https://example.com")
  end

  test "blocks non-http scheme" do
    capturer = capturer_with_resolved_ip("93.184.216.34")
    refute capturer.send(:safe_url?, "file:///etc/passwd")
    refute capturer.send(:safe_url?, "ftp://internal/data")
    refute capturer.send(:safe_url?, "javascript:alert(1)")
  end

  test "blocks URL with unresolvable host" do
    klass = Class.new(ScreenshotCapturer) do
      define_method(:resolve_host) { |_host| raise Resolv::ResolvError, "no address" }
    end
    capturer = klass.new([])
    refute capturer.send(:safe_url?, "https://nonexistent.invalid")
  end

  test "blocks 0.0.0.0 URL" do
    capturer = capturer_with_resolved_ip("0.0.0.0")
    refute capturer.send(:safe_url?, "http://0.0.0.0:8080")
  end

  test "SSRF blocked URLs are skipped during capture" do
    capturer = StubCapturerSSRF.new(["http://localhost:8080", "https://safe.com"])
    result = capturer.capture

    assert_equal 1, result.size
    refute result.key?("http://localhost:8080")
    assert result.key?("https://safe.com")
  end

  # Test double that stubs safe_url? to simulate SSRF blocking during capture
  class StubCapturerSSRF < ScreenshotCapturer
    private

    def create_browser
      FakeBrowser.new
    end

    def safe_url?(url)
      !url.include?("localhost")
    end

    def capture_url(browser, url, timeout)
      return nil unless safe_url?(url)
      "fake_base64"
    end
  end
end
