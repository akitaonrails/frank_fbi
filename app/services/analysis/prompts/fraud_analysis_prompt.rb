module Analysis
  module Prompts
    class FraudAnalysisPrompt
      def initialize(email, layer_results)
        @email = email
        @layer_results = layer_results
      end

      def build
        <<~PROMPT
          Você é um analista especialista em fraude de e-mail. Analise o e-mail a seguir e os resultados preliminares da análise para determinar se é fraudulento, suspeito ou legítimo.

          ## Metadados do E-mail
          - **De**: #{@email.from_name} <#{@email.from_address}>
          - **Reply-To**: #{@email.reply_to_address || 'mesmo que De'}
          - **Assunto**: #{@email.subject}
          - **Domínio do Remetente**: #{@email.sender_domain}
          - **Data**: #{@email.received_at}

          ## Corpo do E-mail (texto)
          **Nota**: Este e-mail foi encaminhado por um usuário para análise. O corpo abaixo contém apenas o conteúdo do remetente suspeito, sem a assinatura de quem encaminhou.
          ```
          #{truncate_text(suspect_text, 2000)}
          ```

          ## URLs Extraídas (#{(@email.extracted_urls || []).size} no total)
          #{format_urls}

          ## Anexos
          #{format_attachments}

          ## Resultados da Análise Preliminar

          #{format_layer_results}

          ## REGRAS OBRIGATÓRIAS
          - Cada item em key_findings DEVE ser sustentado por dados das camadas acima. NUNCA invente dados.
          - Se sender_reputation mostra 0 hits em listas negras, NUNCA afirme que o domínio está em blacklists.
          - Se external_api mostra 0 URLs maliciosas, NUNCA afirme que URLs foram detectadas como maliciosas.
          - Se external_api mostra 0 anexos maliciosos, NUNCA afirme que anexos foram detectados como maliciosos.
          - Se estiver incerto, diga "não confirmado" — NUNCA fabrique números, contagens ou nomes de blacklists.
          - Cada item em key_findings deve começar com [Nome da Camada] indicando a fonte dos dados.
          - O campo reasoning deve citar APENAS fatos presentes nos resultados acima.

          ## Sua Tarefa
          Com base em TODAS as informações acima, forneça sua análise de fraude como um objeto JSON com exatamente estes campos:
          - **score**: inteiro 0-100 (0 = certamente legítimo, 100 = certamente fraudulento)
          - **verdict**: um de "legitimate", "suspicious_likely_ok", "suspicious_likely_fraud", "fraudulent"
          - **confidence**: float 0.0-1.0 (quão confiante você está no seu veredito)
          - **reasoning**: uma conclusão curta e direta justificando seu veredito (1-3 frases, sem enrolação)
          - **key_findings**: array de strings, as 3-5 descobertas mais importantes que sustentam seu veredito. CADA item deve começar com "[Nome da Camada]" indicando a fonte dos dados. NÃO inclua descobertas sem evidência nas camadas.
          - **content_patterns**: objeto com contagens de padrões detectados no corpo do e-mail:
            - **urgency**: inteiro >= 0, frases de urgência/pressão (ex: "aja agora", "prazo", "suspensão de conta")
            - **financial_fraud**: inteiro >= 0, indicadores de fraude financeira (ex: loteria, herança, transferência bancária, criptomoeda)
            - **pii_request**: inteiro >= 0, solicitações de dados pessoais/sensíveis (ex: CPF, senha, cartão de crédito, SSN)
            - **authority_impersonation**: inteiro >= 0, alegações de autoridade/governo (ex: FBI, Receita Federal, Tribunal, Polícia)
            - **phishing**: inteiro >= 0, frases/técnicas de phishing (ex: "clique aqui para verificar", "conta suspensa")

          Responda em português brasileiro. Responda APENAS com o objeto JSON, nenhum outro texto.
        PROMPT
      end

      private

      def suspect_text
        ForwardedContentExtractor.new(@email.body_text).extract[:suspect_text]
      end

      def truncate_text(text, max_length)
        return "Nenhum conteúdo de texto disponível" if text.blank?

        if text.length > max_length
          text[0...max_length] + "\n... [truncado]"
        else
          text
        end
      end

      def format_urls
        urls = (@email.extracted_urls || []).first(15)
        return "Nenhuma URL encontrada" if urls.empty?

        urls.map { |u| "- #{u}" }.join("\n")
      end

      def format_attachments
        attachments = @email.attachments_info || []
        return "Sem anexos" if attachments.empty?

        attachments.map { |a| "- #{a['filename']} (#{a['content_type']}, #{a['size']} bytes)" }.join("\n")
      end

      def format_layer_results
        @layer_results.map do |layer|
          details_section = format_layer_details(layer)
          <<~LAYER
            ### #{layer.layer_name.titleize} (Pontuação: #{layer.score}/100, Confiança: #{layer.confidence})
            #{layer.explanation}
            #{details_section}
          LAYER
        end.join("\n")
      end

      def format_layer_details(layer)
        return "" unless layer.details.is_a?(Hash)

        case layer.layer_name
        when "sender_reputation"
          format_sender_reputation_details(layer.details)
        when "external_api"
          format_external_api_details(layer.details)
        when "header_auth"
          format_header_auth_details(layer.details)
        else
          ""
        end
      end

      def format_sender_reputation_details(details)
        lines = ["**Dados estruturados:**"]
        lines << "- Hits em listas negras (blacklist_hits): #{details['blacklist_hits'] || details[:blacklist_hits] || 0}"

        age = details["domain_age_days"] || details[:domain_age_days]
        lines << "- Idade do domínio: #{age ? "#{age} dias" : 'desconhecida'}"

        freemail = details["freemail"] || details[:freemail]
        lines << "- Freemail: #{freemail ? 'sim' : 'não'}" unless freemail.nil?

        lines.join("\n")
      end

      def format_external_api_details(details)
        lines = ["**Dados estruturados:**"]
        lines << "- URLs maliciosas VirusTotal (virustotal_malicious_count): #{details['virustotal_malicious_count'] || details[:virustotal_malicious_count] || 0}"
        lines << "- URLs maliciosas URLhaus (urlhaus_malicious_count): #{details['urlhaus_malicious_count'] || details[:urlhaus_malicious_count] || 0}"
        lines << "- Anexos maliciosos (attachments_malicious_count): #{details['attachments_malicious_count'] || details[:attachments_malicious_count] || 0}"

        urls_scanned = details["urls_scanned"] || details[:urls_scanned] || 0
        lines << "- URLs verificadas: #{urls_scanned}"

        lines.join("\n")
      end

      def format_header_auth_details(details)
        lines = ["**Dados estruturados:**"]

        spf = details["spf_result"] || details[:spf_result]
        dkim = details["dkim_result"] || details[:dkim_result]
        dmarc = details["dmarc_result"] || details[:dmarc_result]

        lines << "- SPF: #{spf || 'não verificado'}"
        lines << "- DKIM: #{dkim || 'não verificado'}"
        lines << "- DMARC: #{dmarc || 'não verificado'}"

        reply_to_mismatch = details["reply_to_mismatch"] || details[:reply_to_mismatch]
        lines << "- Reply-To divergente: #{reply_to_mismatch ? 'sim' : 'não'}" unless reply_to_mismatch.nil?

        lines.join("\n")
      end
    end
  end
end
