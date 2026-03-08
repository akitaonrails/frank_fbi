class LlmVerdict < ApplicationRecord
  PROVIDERS = %w[anthropic openai xai].freeze

  belongs_to :email

  validates :provider, presence: true, inclusion: { in: PROVIDERS },
            uniqueness: { scope: :email_id }
  validates :score, numericality: {
    only_integer: true, greater_than_or_equal_to: 0,
    less_than_or_equal_to: 100
  }, allow_nil: true
  validates :verdict, inclusion: {
    in: %w[legitimate suspicious_likely_ok suspicious_likely_fraud fraudulent],
    allow_nil: true
  }
  validates :confidence, numericality: {
    greater_than_or_equal_to: 0, less_than_or_equal_to: 1
  }, allow_nil: true
end
