require "test_helper"

class CommunityReporting::SpamcopForwarderTest < ActiveSupport::TestCase
  setup do
    ENV["SPAMCOP_SUBMISSION_ADDRESS"] = "submit.test@spam.spamcop.net"
    ENV["GMAIL_USERNAME"] = "frank@example.com"
    @forwarder = CommunityReporting::SpamcopForwarder.new
    @email = create(:email, :spam,
      status: "completed",
      final_score: 92,
      verdict: "fraudulent"
    )

    Mail.defaults do
      delivery_method :test
    end
    Mail::TestMailer.deliveries.clear
  end

  teardown do
    ENV["SPAMCOP_SUBMISSION_ADDRESS"] = ""
    Mail::TestMailer.deliveries.clear
  end

  test "returns nil when submission address is blank" do
    ENV["SPAMCOP_SUBMISSION_ADDRESS"] = ""
    forwarder = CommunityReporting::SpamcopForwarder.new

    assert_nil forwarder.forward(@email)
  end

  test "returns nil when raw_source is blank" do
    @email.update_columns(raw_source: nil)

    assert_nil @forwarder.forward(@email)
  end

  test "forwards email as attachment to SpamCop" do
    result = @forwarder.forward(@email)

    assert_not_nil result
    assert_equal "submit.test@spam.spamcop.net", result[:forwarded_to]
    assert_equal @email.message_id, result[:message_id]
  end

  test "attaches original email as message/rfc822" do
    @forwarder.forward(@email)

    delivered = Mail::TestMailer.deliveries.last
    assert_not_nil delivered
    assert_equal ["submit.test@spam.spamcop.net"], delivered.to
    assert delivered.attachments.any? { |a| a.filename == "original.eml" }
  end
end
