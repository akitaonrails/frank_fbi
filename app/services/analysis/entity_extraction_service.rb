module Analysis
  class EntityExtractionService
    GENERIC_PREFIXES = %w[
      noreply no-reply info support contact admin webmaster
      mailer-daemon postmaster help feedback notifications
      donotreply do-not-reply sales billing newsletter
    ].freeze

    FREEMAIL_DOMAINS = %w[
      gmail.com yahoo.com hotmail.com outlook.com aol.com
      icloud.com mail.com protonmail.com zoho.com yandex.com
      live.com msn.com gmx.com fastmail.com tutanota.com
    ].freeze

    GOVERNMENT_PATTERNS = [
      /\b(FBI|CIA|NSA|IRS|Federal\s+Bureau)\b/,
      /\b(United\s+Nations|UN\s+Office|World\s+Bank|IMF)\b/i,
      /\b(Department\s+of\s+(State|Treasury|Justice|Homeland|Defense))\b/i,
      /\b(Interpol|Scotland\s+Yard|Secret\s+Service)\b/i,
      /\b(Securities?\s+and\s+Exchange\s+Commission|SEC)\b/,
      /\b(Federal\s+Reserve|Central\s+Bank)\b/i,
      /\b(Pol[íi]cia\s+Federal|Pol[íi]cia\s+Civil)\b/i,
      /\b(Receita\s+Federal)\b/i,
      /\b(Banco\s+Central\s+do\s+Brasil)\b/i,
      /\b(Minist[ée]rio\s+P[úu]blico)\b/i,
      /\b(Tribunal\s+de\s+Justi[çc]a)\b/i
    ].freeze

    CORPORATE_PATTERNS = [
      /\b([A-Z][a-zA-Z&\s]+(?:Inc|Corp|LLC|Ltd|PLC|GmbH|SA|AG|NV|BV|Pty|Co)\.?)\b/,
      /\b([A-Z][a-zA-Z&\s]+(?:Bank|Insurance|Holdings|Group|Foundation|Association|Institute))\b/
    ].freeze

    TITLED_PERSON_PATTERNS = [
      /\b(?:Dr|Prof|Director|CEO|CFO|CTO|Agent|Special\s+Agent|Officer|Inspector|Commissioner|Ambassador|Minister|Secretary|Barrister|Attorney|General|Colonel|Major|Captain)\b\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})/,
      /\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\s*,\s*(?:Ph\.?D|MD|Esq|Jr|Sr|FBI|CIA|Director|CEO|Agent)/
    ].freeze

    def initialize(email, prior_layers: nil)
      @email = email
      @prior_layers = prior_layers
    end

    def extract
      {
        sender: extract_sender_info,
        claimed_entities: extract_claimed_entities,
        mentioned_contacts: extract_mentioned_contacts,
        skip_person_research: generic_sender?,
        freemail: freemail_sender?
      }
    end

    private

    def extract_sender_info
      {
        name: @email.from_name,
        email: @email.from_address,
        domain: @email.sender_domain,
        reply_to: @email.reply_to_address
      }
    end

    def extract_claimed_entities
      text = combined_text
      entities = { organizations: [], people: [], authority_claims: [] }

      # Extract authority/government claims
      GOVERNMENT_PATTERNS.each do |pattern|
        text.scan(pattern).flatten.each do |match|
          entities[:authority_claims] << match.strip unless match.blank?
        end
      end

      # Use content_analysis layer's authority_matches if available
      content_layer = find_content_layer
      if content_layer&.details&.dig("authority_matches").to_i > 0
        entities[:authority_claims] << "authority_impersonation_detected"
      end

      # Extract corporate names
      CORPORATE_PATTERNS.each do |pattern|
        text.scan(pattern).flatten.each do |match|
          name = match.strip
          entities[:organizations] << name if name.length > 3 && name.length < 100
        end
      end

      # Extract titled persons
      TITLED_PERSON_PATTERNS.each do |pattern|
        text.scan(pattern).flatten.each do |match|
          name = match.strip
          entities[:people] << name if name.length > 3 && name.length < 60
        end
      end

      # Add sender name if it looks like a person
      if @email.from_name.present? && @email.from_name.match?(/\A[A-Z][a-z]+(\s+[A-Z][a-z]+)+\z/)
        entities[:people] << @email.from_name unless entities[:people].include?(@email.from_name)
      end

      entities[:organizations].uniq!
      entities[:people].uniq!
      entities[:authority_claims].uniq!
      entities
    end

    def extract_mentioned_contacts
      {
        urls: (@email.extracted_urls || []).first(10),
        emails: (@email.extracted_emails || []).first(10)
      }
    end

    def generic_sender?
      return true if @email.from_address.blank?

      local_part = @email.from_address.split("@").first&.downcase
      GENERIC_PREFIXES.include?(local_part)
    end

    def freemail_sender?
      return false if @email.sender_domain.blank?

      FREEMAIL_DOMAINS.include?(@email.sender_domain.downcase)
    end

    def combined_text
      [@email.subject, @email.body_text, @email.from_name].compact.join(" ")
    end

    def find_content_layer
      if @prior_layers
        @prior_layers.find { |l| l.layer_name == "content_analysis" }
      else
        @email.analysis_layers.find_by(layer_name: "content_analysis")
      end
    end
  end
end
