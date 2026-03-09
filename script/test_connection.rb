require "net/imap"
require "net/smtp"

puts "=== IMAP Test ==="
begin
  host = ENV.fetch("GMAIL_IMAP_HOST", "imap.gmail.com")
  user = ENV.fetch("GMAIL_USERNAME")
  pass = ENV.fetch("GMAIL_PASSWORD")

  imap = Net::IMAP.new(host, port: 993, ssl: true)
  imap.login(user, pass)
  imap.select("INBOX")
  count = imap.search(["ALL"]).size
  unseen = imap.search(["UNSEEN"]).size
  puts "Connected to: #{user}"
  puts "Inbox: #{count} total, #{unseen} unread"
  imap.logout
  imap.disconnect
  puts "IMAP: OK"
rescue => e
  puts "IMAP FAILED: #{e.class} - #{e.message}"
end

puts
puts "=== SMTP Test ==="
begin
  host = ENV.fetch("GMAIL_SMTP_HOST", "smtp.gmail.com")
  user = ENV.fetch("GMAIL_USERNAME")
  pass = ENV.fetch("GMAIL_PASSWORD")

  smtp = Net::SMTP.new(host, 587)
  smtp.enable_starttls
  smtp.start("localhost", user, pass, :plain)
  puts "Connected to SMTP: #{host}"
  smtp.finish
  puts "SMTP: OK"
rescue => e
  puts "SMTP FAILED: #{e.class} - #{e.message}"
end

puts
puts "=== Action Mailbox Ingress Password ==="
pwd = ENV["RAILS_INBOUND_EMAIL_PASSWORD"].to_s
if pwd.length > 10
  puts "Set (#{pwd.length} chars): OK"
else
  puts "Missing or too short"
end
