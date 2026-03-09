class ScreenshotCapturer
  MAX_URLS = 5
  PER_URL_TIMEOUT = 15 # seconds
  TOTAL_TIMEOUT = 90 # seconds
  RESIZE_WIDTH = 560
  JPEG_QUALITY = 60

  USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

  STEALTH_JS = <<~JS
    // Override navigator.webdriver
    Object.defineProperty(navigator, 'webdriver', { get: () => false });

    // Set window.chrome
    window.chrome = { runtime: {}, loadTimes: function(){}, csi: function(){} };

    // Override permissions query
    const originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = (parameters) =>
      parameters.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission })
        : originalQuery(parameters);

    // Override plugins
    Object.defineProperty(navigator, 'plugins', {
      get: () => [1, 2, 3, 4, 5]
    });

    // Override languages
    Object.defineProperty(navigator, 'languages', {
      get: () => ['en-US', 'en']
    });
  JS

  def initialize(urls)
    @urls = Array(urls).uniq.first(MAX_URLS)
  end

  def capture
    return {} if @urls.empty?

    screenshots = {}
    browser = nil
    deadline = Time.current + TOTAL_TIMEOUT

    begin
      browser = create_browser
      browser.command("Page.addScriptToEvaluateOnNewDocument", source: STEALTH_JS)

      @urls.each do |url|
        break if Time.current >= deadline

        begin
          remaining = [deadline - Time.current, PER_URL_TIMEOUT].min
          screenshot_data = capture_url(browser, url, remaining)
          screenshots[url] = screenshot_data if screenshot_data
        rescue => e
          Rails.logger.warn("Screenshot failed for #{url}: #{e.message}")
        end
      end
    rescue => e
      Rails.logger.warn("Screenshot browser error: #{e.message}")
    ensure
      browser&.quit
    end

    screenshots
  end

  private

  def create_browser
    chrome_path = ENV.fetch("CHROME_BIN", find_chrome_binary)

    options = Ferrum::Browser.new(
      browser_path: chrome_path,
      headless: "new",
      timeout: PER_URL_TIMEOUT,
      window_size: [1280, 900],
      browser_options: {
        "no-sandbox" => nil,
        "disable-gpu" => nil,
        "disable-dev-shm-usage" => nil,
        "disable-blink-features" => "AutomationControlled",
        "user-agent" => USER_AGENT
      }
    )

    options
  end

  def find_chrome_binary
    %w[chromium chromium-browser google-chrome google-chrome-stable].each do |name|
      path = `which #{name} 2>/dev/null`.strip
      return path if path.present?
    end
    "chromium"
  end

  def capture_url(browser, url, timeout)
    page = browser.create_page
    page.go_to(url)

    # Wait for network idle or timeout
    begin
      page.network.wait_for_idle(timeout: [timeout, 3].min)
    rescue Ferrum::TimeoutError
      # Page loaded enough, continue with screenshot
    end

    # Capture full-width screenshot as PNG bytes
    png_data = page.screenshot(format: "png", full: false)

    # Resize and convert to JPEG via vips
    resize_to_jpeg(png_data)
  rescue Ferrum::TimeoutError, Ferrum::StatusError, Ferrum::NodeNotFoundError => e
    Rails.logger.warn("Screenshot navigation failed for #{url}: #{e.message}")
    nil
  ensure
    page&.close
  end

  def resize_to_jpeg(png_data)
    image = Vips::Image.new_from_buffer(png_data, "")

    if image.width > RESIZE_WIDTH
      scale = RESIZE_WIDTH.to_f / image.width
      image = image.resize(scale)
    end

    jpeg_buffer = image.write_to_buffer(".jpg", Q: JPEG_QUALITY)
    Base64.strict_encode64(jpeg_buffer)
  end
end
