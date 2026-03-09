ENV["RAILS_ENV"] ||= "test"

require "simplecov"
SimpleCov.start "rails" do
  add_filter "/test/"
  add_filter "/config/"
end

require_relative "../config/environment"
require "rails/test_help"
require "webmock/minitest"
require "factory_bot_rails"

# Disable all external network connections in tests
WebMock.disable_net_connect!(allow_localhost: true)

module ActiveSupport
  class TestCase
    include FactoryBot::Syntax::Methods

    # Run tests in parallel with specified workers
    parallelize(workers: :number_of_processors)

    # Setup all fixtures in test/fixtures/*.yml for all tests in alphabetical order.
    fixtures :all

    # Helper to read sample .eml files
    def read_eml(filename)
      File.read(Rails.root.join("suspects", filename))
    end

    # Swap cache to memory_store for rate limit tests, restore after block
    def with_memory_cache
      original_cache = Rails.cache
      Rails.cache = ActiveSupport::Cache::MemoryStore.new
      yield
    ensure
      Rails.cache = original_cache
    end

    # Helper to create a parsed email record from an .eml file
    def create_email_from_eml(filename, submitter: "test@example.com")
      raw = read_eml(filename)
      parser = EmailParser.new(raw)
      parsed = parser.parse

      Email.create!(
        message_id: parsed[:message_id] || SecureRandom.uuid,
        submitter_email: submitter,
        subject: parsed[:subject],
        from_address: parsed[:from_address],
        from_name: parsed[:from_name],
        reply_to_address: parsed[:reply_to_address],
        sender_domain: parsed[:sender_domain],
        body_text: parsed[:body_text],
        body_html: parsed[:body_html],
        raw_headers: parsed[:raw_headers],
        raw_source: raw,
        extracted_urls: parsed[:extracted_urls],
        extracted_emails: parsed[:extracted_emails],
        attachments_info: parsed[:attachments_info],
        received_at: parsed[:received_at],
        status: "analyzing"
      )
    end
  end
end
