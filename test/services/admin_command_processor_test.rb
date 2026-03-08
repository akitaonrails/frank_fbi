require "test_helper"

class AdminCommandProcessorTest < ActiveSupport::TestCase
  setup do
    @admin = "admin@example.com"
  end

  test "add command creates allowed senders" do
    result = AdminCommandProcessor.new(
      subject: "add senders",
      body: "alice@example.com\nbob@example.com",
      admin_email: @admin
    ).process

    assert result.success
    assert_equal "add", result.command
    assert_equal 2, AllowedSender.active.count
    assert AllowedSender.authorized?("alice@example.com")
    assert AllowedSender.authorized?("bob@example.com")
  end

  test "add command reactivates inactive sender" do
    create(:allowed_sender, email_address: "inactive@example.com", active: false)

    result = AdminCommandProcessor.new(
      subject: "add",
      body: "inactive@example.com",
      admin_email: @admin
    ).process

    assert result.success
    assert AllowedSender.authorized?("inactive@example.com")
  end

  test "add command reports already existing senders" do
    create(:allowed_sender, email_address: "existing@example.com")

    result = AdminCommandProcessor.new(
      subject: "add",
      body: "existing@example.com",
      admin_email: @admin
    ).process

    assert result.success
    assert_includes result.body_text, "Already existed"
  end

  test "add command with no emails returns error" do
    result = AdminCommandProcessor.new(
      subject: "add",
      body: "no emails here",
      admin_email: @admin
    ).process

    assert_not result.success
    assert_includes result.body_text, "No email addresses found"
  end

  test "remove command deactivates sender" do
    create(:allowed_sender, email_address: "remove-me@example.com")

    result = AdminCommandProcessor.new(
      subject: "remove",
      body: "remove-me@example.com",
      admin_email: @admin
    ).process

    assert result.success
    assert_not AllowedSender.authorized?("remove-me@example.com")
  end

  test "remove command handles not-found gracefully" do
    result = AdminCommandProcessor.new(
      subject: "remove",
      body: "nonexistent@example.com",
      admin_email: @admin
    ).process

    assert result.success
    assert_includes result.body_text, "Not found"
  end

  test "list command returns all active senders" do
    create(:allowed_sender, email_address: "a@example.com")
    create(:allowed_sender, email_address: "b@example.com")
    create(:allowed_sender, :inactive, email_address: "c@example.com")

    result = AdminCommandProcessor.new(
      subject: "list",
      body: "",
      admin_email: @admin
    ).process

    assert result.success
    assert_equal "list", result.command
    assert_includes result.body_text, "a@example.com"
    assert_includes result.body_text, "b@example.com"
    assert_not_includes result.body_text, "c@example.com"
  end

  test "list command with no senders" do
    result = AdminCommandProcessor.new(
      subject: "list",
      body: "",
      admin_email: @admin
    ).process

    assert result.success
    assert_includes result.body_text, "No allowed senders"
  end

  test "stats command returns system stats" do
    create(:email, :completed)

    result = AdminCommandProcessor.new(
      subject: "stats",
      body: "",
      admin_email: @admin
    ).process

    assert result.success
    assert_equal "stats", result.command
    assert_includes result.body_text, "Frank FBI System Stats"
    assert_includes result.body_text, "Completed: 1"
  end

  test "add command rejects admin email address" do
    ENV["ADMIN_EMAIL"] = @admin

    result = AdminCommandProcessor.new(
      subject: "add",
      body: "admin@example.com\nvalid@example.com",
      admin_email: @admin
    ).process

    assert result.success
    # valid@example.com should be added, admin@example.com should be rejected
    assert AllowedSender.authorized?("valid@example.com")
    assert_not AllowedSender.find_by(email_address: "admin@example.com")
    assert_includes result.body_text, "Rejected"
  end

  test "unknown command returns help message" do
    result = AdminCommandProcessor.new(
      subject: "foobar",
      body: "",
      admin_email: @admin
    ).process

    assert_not result.success
    assert_equal "unknown", result.command
    assert_includes result.body_text, "Available commands"
  end
end
