class KnownSender < ApplicationRecord
  belongs_to :known_domain, optional: true

  validates :email_address, presence: true, uniqueness: true

  def fraud_ratio
    return 0.0 if emails_analyzed.zero?
    fraud_count.to_f / emails_analyzed
  end

  def record_analysis(verdict)
    counters = { emails_analyzed: 1 }
    case verdict
    when "fraudulent", "suspicious_likely_fraud"
      counters[:fraud_count] = 1
    when "legitimate", "suspicious_likely_ok"
      counters[:legit_count] = 1
    end
    self.class.update_counters(id, **counters)
  end
end
