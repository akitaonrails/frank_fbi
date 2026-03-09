require "json"

module Analysis
  class EntityVerificationAnalyzer
    LAYER_NAME = "entity_verification"
    WEIGHT = AnalysisLayer::WEIGHTS[LAYER_NAME]
    MODEL = "anthropic/claude-sonnet-4.6"

    def initialize(email)
      @email = email
    end

    def analyze
      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(weight: WEIGHT, status: "running")

      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      # Extract entities from email and prior layers
      prior_layers = @email.analysis_layers.where(status: "completed").where.not(layer_name: LAYER_NAME)
      entities = EntityExtractionService.new(@email, prior_layers: prior_layers).extract

      # Build prompt
      prompt = Prompts::EntityVerificationPrompt.new(@email, entities).build

      # Call LLM with tool use
      chat = build_chat
      response = chat.ask(prompt)

      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time

      # Parse response
      parsed = parse_response(response.content)

      layer.update!(
        score: parsed[:score],
        weight: WEIGHT,
        confidence: parsed[:confidence],
        details: {
          extracted_entities: entities,
          verdict_summary: parsed[:verdict_summary],
          sender_verified: parsed[:sender_verified],
          domain_verified: parsed[:domain_verified],
          entity_mismatches: parsed[:entity_mismatches],
          key_findings: parsed[:key_findings],
          search_summary: parsed[:search_summary],
          model: MODEL,
          response_time_seconds: elapsed.round(2),
          input_tokens: response.input_tokens,
          output_tokens: response.output_tokens
        },
        explanation: parsed[:verdict_summary] || "Verificação de entidade concluída",
        status: "completed"
      )

      layer
    rescue => e
      Rails.logger.error("EntityVerificationAnalyzer: #{e.message}")
      handle_failure(e)
    end

    private

    def build_chat
      chat = RubyLLM.chat(model: MODEL)
      chat.with_tool(BraveWebSearch)
      chat
    end

    def parse_response(content)
      data = extract_json(content.to_s)

      {
        score: data["score"]&.to_i&.clamp(0, 100) || 50,
        confidence: data["confidence"]&.to_f&.clamp(0.0, 1.0) || 0.5,
        verdict_summary: data["verdict_summary"].to_s,
        sender_verified: data["sender_verified"],
        domain_verified: data["domain_verified"],
        entity_mismatches: Array(data["entity_mismatches"]).map(&:to_s).first(10),
        key_findings: Array(data["key_findings"]).map(&:to_s).first(10),
        search_summary: data["search_summary"].to_s
      }
    rescue JSON::ParserError => e
      Rails.logger.warn("EntityVerificationAnalyzer: JSON parse failed: #{e.message}")
      {
        score: 50,
        confidence: 0.2,
        verdict_summary: "Falha ao interpretar resposta da verificação de entidade",
        sender_verified: nil,
        domain_verified: nil,
        entity_mismatches: [],
        key_findings: ["Falha na interpretação da resposta"],
        search_summary: "Parse error: #{content.to_s[0..200]}"
      }
    end

    def extract_json(text)
      # Try to find JSON inside ```json ... ``` blocks first
      if text =~ /```json\s*(.*?)```/mi
        return JSON.parse($1.strip)
      end

      # Find the first { and match to the last }
      start_idx = text.index("{")
      end_idx = text.rindex("}")
      if start_idx && end_idx && end_idx > start_idx
        return JSON.parse(text[start_idx..end_idx])
      end

      # Last resort: try parsing the whole thing
      JSON.parse(text.strip)
    end

    def handle_failure(error)
      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(
        score: 50,
        weight: WEIGHT,
        confidence: 0.2,
        details: { error: error.message },
        explanation: "Verificação de entidade falhou: #{error.message}",
        status: "completed"
      )
      layer
    end
  end
end
