FactoryBot.define do
  factory :email do
    sequence(:message_id) { |n| "msg-#{n}@example.com" }
    submitter_email { "submitter@example.com" }
    subject { "Test email subject" }
    from_address { "sender@example.com" }
    from_name { "Test Sender" }
    sender_domain { "example.com" }
    body_text { "This is a test email body" }
    raw_headers { "From: sender@example.com\nTo: recipient@example.com\nSubject: Test" }
    raw_source { "From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email body" }
    status { "analyzing" }
    received_at { Time.current }

    trait :pending do
      status { "pending" }
    end

    trait :completed do
      status { "completed" }
      final_score { 75 }
      verdict { "suspicious_likely_fraud" }
    end

    trait :spam do
      subject { "YOUR ATM CARD COMPENSATION PAYMENT !!!!" }
      from_address { "info@asume.gov" }
      from_name { "FBI" }
      reply_to_address { "lawyergeraddave00@hotmail.com" }
      sender_domain { "asume.gov" }
      body_text { "Dear beneficiary, You have been approved for ATM CARD COMPENSATION PAYMENT worth $2.5 million USD. Contact us immediately." }
      raw_headers do
        <<~HEADERS
          Authentication-Results: mx.google.com; spf=pass smtp.mailfrom="bounces+SRS=02623=AQ@asume.pr.gov"; dkim=none (message not signed); dmarc=none action=none header.from=asume.gov
          Reply-To: <lawyergeraddave00@hotmail.com>
          From: FBI <info@asume.gov>
          Subject: YOUR ATM CARD COMPENSATION PAYMENT !!!!
        HEADERS
      end
    end

    trait :legitimate do
      subject { "Fale Conosco - Gabriel Delfiol" }
      from_address { "contact@codeminer42.com" }
      sender_domain { "codeminer42.com" }
      body_text { "Hello, I would like to discuss a potential project collaboration." }
      raw_headers do
        <<~HEADERS
          Authentication-Results: mx.google.com; spf=pass; dkim=pass header.i=@mailgun.codeminer42.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=codeminer42.com
          From: Gabriel Delfiol <contact@codeminer42.com>
          Subject: Fale Conosco - Gabriel Delfiol
        HEADERS
      end
    end
  end
end
