class BraveWebSearch < RubyLLM::Tool
  description "Search the web using Brave Search to verify entities, people, organizations, and domains mentioned in emails."

  param :query, desc: "The search query to look up"

  def execute(query:)
    result = BraveSearchClient.new.search(query)

    unless result
      return "Busca falhou ou chave da API não configurada. Não foi possível verificar esta consulta."
    end

    results = result[:results]
    if results.empty?
      return "Nenhum resultado encontrado para: #{query}"
    end

    lines = ["Resultados da busca para: #{query}\n"]
    results.each_with_index do |r, i|
      lines << "#{i + 1}. #{r[:title] || r["title"]}"
      lines << "   URL: #{r[:url] || r["url"]}"
      desc = r[:description] || r["description"]
      lines << "   #{desc}" if desc.present?
      age = r[:age] || r["age"]
      lines << "   Age: #{age}" if age.present?
      lines << ""
    end

    lines.join("\n")
  end
end
