module Analysis
  module Prompts
    class FraudAnalysisPrompt
      def initialize(email, layer_results)
        @email = email
        @layer_results = layer_results
      end

      def build
        <<~PROMPT
          You are an expert email fraud analyst. Analyze the following email and its preliminary analysis results to determine if it is fraudulent, suspicious, or legitimate.

          ## Email Metadata
          - **From**: #{@email.from_name} <#{@email.from_address}>
          - **Reply-To**: #{@email.reply_to_address || 'same as From'}
          - **Subject**: #{@email.subject}
          - **Sender Domain**: #{@email.sender_domain}
          - **Date**: #{@email.received_at}

          ## Email Body (text)
          ```
          #{truncate_text(@email.body_text, 2000)}
          ```

          ## Extracted URLs (#{(@email.extracted_urls || []).size} total)
          #{format_urls}

          ## Attachments
          #{format_attachments}

          ## Preliminary Analysis Results

          #{format_layer_results}

          ## Your Task
          Based on ALL the information above, provide your fraud analysis as a JSON object with exactly these fields:
          - **score**: integer 0-100 (0 = certainly legitimate, 100 = certainly fraudulent)
          - **verdict**: one of "legitimate", "suspicious_likely_ok", "suspicious_likely_fraud", "fraudulent"
          - **confidence**: float 0.0-1.0 (how confident you are in your verdict)
          - **reasoning**: a 2-3 sentence explanation of your verdict
          - **key_findings**: array of strings, the top 3-5 most important findings that support your verdict

          Respond ONLY with the JSON object, no other text.
        PROMPT
      end

      private

      def truncate_text(text, max_length)
        return "No text content available" if text.blank?

        if text.length > max_length
          text[0...max_length] + "\n... [truncated]"
        else
          text
        end
      end

      def format_urls
        urls = (@email.extracted_urls || []).first(15)
        return "No URLs found" if urls.empty?

        urls.map { |u| "- #{u}" }.join("\n")
      end

      def format_attachments
        attachments = @email.attachments_info || []
        return "No attachments" if attachments.empty?

        attachments.map { |a| "- #{a['filename']} (#{a['content_type']}, #{a['size']} bytes)" }.join("\n")
      end

      def format_layer_results
        @layer_results.map do |layer|
          <<~LAYER
            ### #{layer.layer_name.titleize} (Score: #{layer.score}/100, Confidence: #{layer.confidence})
            #{layer.explanation}
          LAYER
        end.join("\n")
      end
    end
  end
end
