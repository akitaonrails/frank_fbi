class KnownSender < ApplicationRecord
  belongs_to :known_domain, optional: true

  validates :email_address, presence: true, uniqueness: true

  def fraud_ratio
    return 0.0 if emails_analyzed.zero?
    fraud_count.to_f / emails_analyzed
  end

  def record_analysis(verdict)
    increment!(:emails_analyzed)
    case verdict
    when "fraudulent", "suspicious_likely_fraud"
      increment!(:fraud_count)
    when "legitimate", "suspicious_likely_ok"
      increment!(:legit_count)
    end
  end
end
