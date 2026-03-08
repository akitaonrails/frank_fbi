module Analysis
  class ScoreAggregator
    VERDICT_THRESHOLDS = {
      (0..25) => "legitimate",
      (26..50) => "suspicious_likely_ok",
      (51..75) => "suspicious_likely_fraud",
      (76..100) => "fraudulent"
    }.freeze

    def initialize(email)
      @email = email
    end

    def aggregate
      layers = @email.analysis_layers.where(status: "completed")
      return nil if layers.empty?

      final_score = calculate_weighted_score(layers)
      verdict = score_to_verdict(final_score)

      @email.update!(
        final_score: final_score,
        verdict: verdict,
        verdict_explanation: build_verdict_explanation(layers, final_score, verdict),
        analyzed_at: Time.current
      )

      # Update known domain and sender records with verdict
      update_reputation_records(verdict)

      # Apply conditional encryption for legitimate emails
      encrypt_if_legitimate(verdict)

      { score: final_score, verdict: verdict }
    end

    private

    def calculate_weighted_score(layers)
      weighted_sum = 0.0
      weight_sum = 0.0

      layers.each do |layer|
        # Layers that scored near 0 ("found nothing") provide weak evidence of
        # legitimacy — absence of evidence is not evidence of absence. Dampen
        # their influence so they don't drown out layers that found real problems.
        dampening = [[layer.score / 50.0, 1.0].min, 0.1].max
        effective_weight = layer.weight * layer.confidence * dampening
        weighted_sum += layer.score * effective_weight
        weight_sum += effective_weight
      end

      return 50 if weight_sum.zero?
      (weighted_sum / weight_sum).round
    end

    def score_to_verdict(score)
      VERDICT_THRESHOLDS.each do |range, verdict|
        return verdict if range.include?(score)
      end
      "suspicious_likely_fraud"
    end

    def build_verdict_explanation(layers, score, verdict)
      lines = ["Pontuação Final: #{score}/100 — #{verdict.humanize}"]
      lines << ""

      layers.order(:layer_name).each do |layer|
        lines << "#{layer.layer_name.titleize}: #{layer.score}/100 (weight: #{layer.weight}, confidence: #{layer.confidence})"
        lines << "  #{layer.explanation}"
        lines << ""
      end

      lines.join("\n")
    end

    def update_reputation_records(verdict)
      if @email.sender_domain
        domain = KnownDomain.find_by(domain: @email.sender_domain)
        domain&.record_analysis(verdict)
      end

      if @email.from_address
        sender = KnownSender.find_by(email_address: @email.from_address)
        sender&.record_analysis(verdict)
      end
    end

    def encrypt_if_legitimate(verdict)
      return unless verdict == "legitimate"

      # For legitimate emails, encrypt the body content to protect privacy
      # We re-save with encryption applied
      @email.class.encrypts :body_text
      @email.class.encrypts :body_html
      @email.save!
    rescue => e
      Rails.logger.warn("ScoreAggregator: Failed to encrypt legitimate email body: #{e.message}")
    end
  end
end
